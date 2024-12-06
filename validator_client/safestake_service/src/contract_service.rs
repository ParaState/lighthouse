use crate::config::Config;
use account_utils::operator_committee_definitions::OperatorCommitteeDefinition;
use account_utils::default_operator_committee_definition_path;
use alloy_primitives::{Address, Bytes};
use alloy_provider::{Provider, ProviderBuilder, RootProvider};
use alloy_rpc_types::{Filter, Log};
use alloy_sol_macro::sol;
use alloy_sol_types::SolEvent;
use alloy_transport_http::{Client, Http};
use eth2_keystore::KeystoreBuilder;
use eth2_keystore_share::KeystoreShare;
use parking_lot::RwLock;
use safestake_crypto::elgamal::{Ciphertext, Elgamal};
use safestake_crypto::secp::PublicKey as SecpPublicKey;
use safestake_database::SafeStakeDatabase;
use safestake_database::models::{Operator, Validator, ValidatorOperation};
use safestake_operator::THRESHOLD_MAP;
use serde::{Deserialize, Serialize};
use slog::{error, info, warn, Logger};
use slot_clock::SlotClock;
use std::fs::{remove_dir_all, remove_file, File};
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use std::{collections::HashMap, sync::Arc};
use task_executor::TaskExecutor;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use types::EthSpec;
use types::Address as H160;
use types::{Keypair, PublicKey, SecretKey};
use validator_dir::insecure_keys::{insecure_kdf, INSECURE_PASSWORD};
use validator_dir::ShareBuilder;
use validator_store::ValidatorStore;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    contract SafeStakeRegistry {
        struct Operator {
            string name;
            bytes publicKey;
            address ownerAddress;
            uint32 indexInOwner;
            uint32 validatorCount;
            bool active;
            bool fromParaStateDao;
            bool verified;
        }
        mapping(uint32 => Operator) public _operators;
    }
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    contract SafeStakeNetwork {
        struct ValidatorData {
            uint256 startBlockNumber;
            uint256 endBlockNumber;
            uint256 lastOperatorFee;
            uint256 balance;
            uint32[] operatorIds;
            bool enable;
        }
        event ValidatorRegistration(address indexed,bytes,uint32[],bytes[],bytes[],uint256);
        event ValidatorRemoval(address indexed,bytes);
        mapping(bytes => ValidatorData) public _validatorDatas;
    }
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    contract SafeStakeConfig {
        event FeeRecipientAddressChanged(address,address);
    }
);

type T = Http<Client>;
type P = RootProvider<T>;
type SafeStakeRegistryContract = SafeStakeRegistry::SafeStakeRegistryInstance<T, P>;
type SafeStakeNetworkContract = SafeStakeNetwork::SafeStakeNetworkInstance<T, P>;

const VALIDATOR_REGISTRATION_TOPIC: alloy_primitives::FixedBytes<32> =
    SafeStakeNetwork::ValidatorRegistration::SIGNATURE_HASH;
const VALIDATOR_REMOVAL_TOPIC: alloy_primitives::FixedBytes<32> =
    SafeStakeNetwork::ValidatorRemoval::SIGNATURE_HASH;
const FEE_RECIPIENT_TOPIC: alloy_primitives::FixedBytes<32> =
    SafeStakeConfig::FeeRecipientAddressChanged::SIGNATURE_HASH;

impl SafeStakeRegistryContract {
    async fn query_operator(&self, operator_id: u32) -> Result<Operator, String> {
        let SafeStakeRegistry::_operatorsReturn { _0, _1, _2, .. } = self
            ._operators(operator_id)
            .call()
            .await
            .map_err(|e| e.to_string())?;
        let public_key_slice: [u8; 33] = _1
            .as_ref()
            .try_into()
            .map_err(|_| "failed to parse node public key".to_string())?;
        let operator = Operator {
            id: operator_id,
            name: _0,
            owner: _2,
            public_key: SecpPublicKey(public_key_slice),
        };
        Ok(operator)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct BlockRecord {
    pub block_num: u64,
}

impl BlockRecord {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let file = File::options()
            .read(true)
            .open(path)
            .map_err(|e| format!("failed to open file {:?}", e))?;
        serde_yaml::from_reader(file).map_err(|e| format!("failed to deserialize file {:?}", e))
    }

    fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), String>
    where
        Self: Serialize,
    {
        let file = File::options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|e| format!("failed to open file {:?}", e))?;
        serde_yaml::to_writer(file, self)
            .map_err(|e| format!("failed to serialize to file {:?}", e))
    }
}

pub struct ContractService {}

impl ContractService {
    pub async fn check_operator(config: &Config) -> Result<(), String> {
        let provider: P = ProviderBuilder::new().on_http(
            config
                .rpc_url
                .parse::<reqwest::Url>()
                .map_err(|e| e.to_string())?,
        );

        let registry_contract = SafeStakeRegistryContract::new(
            config
                .registry_contract
                .parse::<Address>()
                .map_err(|e| e.to_string())?,
            provider.clone(),
        );

        let SafeStakeRegistry::_operatorsReturn { _0, _1, _2, .. } = registry_contract
            ._operators(config.operator_id as u32)
            .call()
            .await
            .map_err(|e| e.to_string())?;

        if config.node_secret.name.0 != _1.as_ref() {
            return Err(format!("operator id {} and its public key are not consistent with smart contract! Please make sure operator id is right", config.operator_id));
        }

        Ok(())
    }

    pub async fn spawn_pull_logs<T: SlotClock + 'static, E: EthSpec>(
        logger: Logger,
        config: Config,
        validator_store: Arc<ValidatorStore<T, E>>,
        db: SafeStakeDatabase,
        executor: &TaskExecutor,
        keypairs: Arc<RwLock<HashMap<PublicKey, Keypair>>>,
        sender: mpsc::Sender<(SecpPublicKey, oneshot::Sender<Option<SocketAddr>>)>,
    ) {
        let provider: P =
            ProviderBuilder::new().on_http(config.rpc_url.parse::<reqwest::Url>().unwrap());
        let mut record = match BlockRecord::from_file(&config.contract_record_path) {
            Ok(r) => r,
            Err(_) => {
                let current_block = provider.get_block_number().await.unwrap();

                BlockRecord {
                    block_num: current_block,
                }
            }
        };
        info!(
            logger,
            "pull event logs";
            "record block" => record.block_num
        );
        let registry_address = config.registry_contract.parse::<Address>().unwrap();
        let network_address = config.network_contract.parse::<Address>().unwrap();
        let config_address = config.config_contract.parse::<Address>().unwrap();
        let cluster_address = config.cluster_contract.parse::<Address>().unwrap();
        let mut query_interval = tokio::time::interval(Duration::from_secs(60));
        executor.spawn(async move {
            loop {
                query_interval.tick().await;
                match provider.get_block_number().await {
                    Ok(current_block) => {
                        let filter = Filter::new()
                            .from_block(record.block_num)
                            .to_block(std::cmp::min(current_block, record.block_num + 1024))
                            .address(vec![registry_address, network_address, config_address, cluster_address])
                            .event_signature(vec![VALIDATOR_REGISTRATION_TOPIC, VALIDATOR_REMOVAL_TOPIC, FEE_RECIPIENT_TOPIC]);
                        match provider.get_logs(&filter).await {
                            Ok(logs) => {
                                if logs.len() == 0 {
                                    record.block_num = std::cmp::min(current_block, record.block_num + 1024 + 1);
                                    continue;
                                }
                                for log in logs {
                                    
                                    if let Err(e) = 
                                        handle_events(
                                            &log,
                                            &logger,
                                            &config,
                                            validator_store.clone(),
                                            &db,
                                            keypairs.clone(),
                                            &sender
                                        ).await
                                    {
                                        warn!(logger, "process events"; "error reason" => e);
                                        continue;
                                    }
                                    record.block_num = log.block_number.unwrap() + 1;
                                }
                                let _ = record.to_file(&config.contract_record_path);
                            },
                            Err(e) => {
                                warn!(logger, "contract service"; "rpc error" => e.to_string());
                            }
                        }
                    },
                    Err(e) => {
                        warn!(logger, "contract service"; "rpc error" => e.to_string());
                    }
                }
            }
        }, "pull_events");
    }

    pub fn spawn_validator_monitor<T: SlotClock + 'static, E: EthSpec>(
        logger: Logger,
        config: Config,
        validator_store: Arc<ValidatorStore<T, E>>,
        db: SafeStakeDatabase,
        executor: &TaskExecutor,
    ) {
        let provider: P =
            ProviderBuilder::new().on_http(config.rpc_url.parse::<reqwest::Url>().unwrap());
        let network_contract = SafeStakeNetworkContract::new(
            config.network_contract.parse::<Address>().unwrap(),
            provider.clone(),
        );
        let mut query_interval = tokio::time::interval(Duration::from_secs(60 * 3));
        executor.spawn(async move {
            loop {
                query_interval.tick().await;
                let current_block = provider.get_block_number().await.unwrap();
                match db.with_transaction(|tx| {
                    db.query_all_validators(tx)
                }) {
                    Ok(validator_public_keys) => {
                        for validator_public_key in validator_public_keys {
                            match network_contract._validatorDatas(Bytes::from(validator_public_key.serialize())).call().await.map_err(|e| e.to_string()) {
                                Ok(SafeStakeNetwork::_validatorDatasReturn {_0, _1 , ..}) => {
                                    let paid_block: u64 = _1.try_into().unwrap();
                                    info!(
                                        logger,
                                        "validator monitor";
                                        "validator public key" => %validator_public_key,
                                        "current block" => current_block,
                                        "paid block" => paid_block,
                                    );
                                    if current_block > paid_block {
                                        // validator fee is used up
                                        match validator_store.is_enabled(&validator_public_key) {
                                            Some(t) => {
                                                if t {
                                                    if let Err(e) = db.with_transaction(|tx| {
                                                        db.insert_validator_operation(tx, &validator_public_key, ValidatorOperation::Disable)
                                                    }) {
                                                        error!(
                                                            logger,
                                                            "validator operation: disable";
                                                            "error" => %e
                                                        );
                                                    }
                                                }
                                            }
                                            None => {}
                                        }
                                    } else {
                                        match validator_store.is_enabled(&validator_public_key) {
                                            Some(t) => {
                                                if !t {
                                                    if let Err(e) = db.with_transaction(|tx| {
                                                        db.insert_validator_operation(tx, &validator_public_key, ValidatorOperation::Enable)
                                                    }) {
                                                        error!(
                                                            logger,
                                                            "validator operation: enable";
                                                            "error" => %e
                                                        );
                                                    }
                                                }
                                            }
                                            None => {}
                                        }
                                    }
                                    
                                },
                                Err(e) => {
                                    error!(
                                        logger,
                                        "validator monitor";
                                        "err" => %e
                                    )
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!(
                            logger,
                            "validator monitor";
                            "err" => %e
                        )
                    }
                }
            }
        }, "validator_monitor");
    }
}

async fn handle_events<T: SlotClock + 'static, E: EthSpec>(
    log: &Log,
    logger: &Logger,
    config: &Config,
    validator_store: Arc<ValidatorStore<T, E>>,
    db: &SafeStakeDatabase,
    keypairs: Arc<RwLock<HashMap<PublicKey, Keypair>>>,
    sender: &mpsc::Sender<(SecpPublicKey, oneshot::Sender<Option<SocketAddr>>)>,
) -> Result<(), String> {
    match log.topic0() {
        Some(&VALIDATOR_REGISTRATION_TOPIC) => {
            handle_validator_registration(
                log,
                logger,
                config,
                db,
                keypairs,
                sender,
            )
            .await?;
        }
        Some(&VALIDATOR_REMOVAL_TOPIC) => {
            handle_validator_removal(log, logger, config, db, keypairs).await?;
        }
        Some(&FEE_RECIPIENT_TOPIC) => {
            handle_fee_recipient_set(log, logger, validator_store, db).await?;
        }
        _ => {}
    };
    Ok(())
}

async fn handle_validator_registration(
    log: &Log,
    logger: &Logger,
    config: &Config,
    db: &SafeStakeDatabase,
    keypairs: Arc<RwLock<HashMap<PublicKey, Keypair>>>,
    sender: &mpsc::Sender<(SecpPublicKey, oneshot::Sender<Option<SocketAddr>>)>,
) -> Result<(), String> {
    let SafeStakeNetwork::ValidatorRegistration {
        _0,
        _1,
        _2,
        _3,
        _4,
        _5,
    } = log.log_decode().map_err(|e| e.to_string())?.inner.data;
    let owner = _0;
    let validator_public_key = PublicKey::deserialize(_1.as_ref())
        .map_err(|_| format!("failed to deserialize validator public key"))?;
    let operator_ids = _2;
    info!(
        logger,
        "validator registration";
        "owner" => %owner,
        "public key" => %validator_public_key,
        "operatrs" => format!("{:?}", operator_ids),
    );
    let self_operator_id = config.operator_id;
    let provider: P = ProviderBuilder::new().on_http(
        config
            .rpc_url
            .parse::<reqwest::Url>()
            .map_err(|e| e.to_string())?,
    );
    let registry_contract = SafeStakeRegistryContract::new(
        config
            .registry_contract
            .parse::<Address>()
            .map_err(|e| e.to_string())?,
        provider.clone(),
    );
    let secret = config.node_secret.clone();

    if operator_ids.contains(&self_operator_id) {
        let mut operator_public_keys = vec![];
        for operator_id in &operator_ids {
            let operator = registry_contract.query_operator(*operator_id).await?;
            db.with_transaction(|t| db.insert_operator(t, &operator))
                .map_err(|e| format!("failed to insert operator {}", e.to_string()))?;
            operator_public_keys.push(operator.public_key);
        }
        let shared_public_keys: Vec<Result<PublicKey, String>> = _3
            .iter()
            .map(|shared_public_key| {
                PublicKey::deserialize(shared_public_key.as_ref()).map_err(|e: bls::Error| {
                    error!(logger, "failed to deserialize shared public key");
                    format!("{:?}", e)
                })
            })
            .collect();
        if shared_public_keys.iter().any(|x| !x.is_ok()) {
            return Err(format!(
                "failed to deserialize shared public key, validator: {}",
                validator_public_key
            ));
        }
        let shared_public_keys: Vec<PublicKey> =
            shared_public_keys.into_iter().map(|x| x.unwrap()).collect();

        let self_index = operator_ids
            .iter()
            .position(|x| *x == self_operator_id)
            .unwrap();

        // decrypt
        let key_pair = {
            let rng = rand::thread_rng();
            let mut elgamal = Elgamal::new(rng);
            let ciphertext = Ciphertext::from_bytes(&_4[self_index]);
            let plain_shared_key = elgamal
                .decrypt(&ciphertext, &secret.secret)
                .map_err(|e| e.to_string())?;
            let shared_secret_key = SecretKey::deserialize(&plain_shared_key)
                .map_err(|e| format!("failed to deserialize decrypted key: {:?}", e))?;
            let shared_public_key = shared_secret_key.public_key();
            Keypair::from_components(shared_public_key, shared_secret_key)
        };

        let keystore = KeystoreBuilder::new(&key_pair, INSECURE_PASSWORD, "".into())
            .map_err(|e| format!("{:?}", e))?
            .kdf(insecure_kdf())
            .build()
            .map_err(|e| format!("{:?}", e))?;

        let keystore_share =
            KeystoreShare::new(keystore, validator_public_key.clone(), self_operator_id);
        ShareBuilder::new(config.validator_dir.clone())
            .password_dir(config.secrets_dir.clone())
            .voting_keystore_share(keystore_share.clone(), INSECURE_PASSWORD)
            .build()
            .map_err(|e| format!("{:?}", e))?;

        let mut socket_addresses = vec![];
        for public_key in &operator_public_keys {
            let (tx, rx) = oneshot::channel();
            sender.send((public_key.clone(), tx)).await.unwrap();
            let addr = rx.await.unwrap();
            socket_addresses.push(addr);
        }

        let def = OperatorCommitteeDefinition {
            total: operator_ids.len() as u64,
            threshold: *THRESHOLD_MAP
                .get(&(operator_ids.len() as u64))
                .ok_or(format!("unkown number of operator committees"))?,
            validator_id: convert_validator_public_key_to_id(&validator_public_key.serialize()),
            validator_public_key: validator_public_key.clone(),
            operator_ids: operator_ids.clone(),
            operator_public_keys: shared_public_keys,
            node_public_keys: operator_public_keys,
            base_socket_addresses: socket_addresses,
        };

        let committee_def_path = default_operator_committee_definition_path(
            &validator_public_key,
            config.validator_dir.clone(),
        );
        def.to_file(committee_def_path.clone())
            .map_err(|e| format!("failed to save committee definition: {:?}", e))?;

        if let Err(e) = db.with_transaction(|tx| {
            db.insert_validator_operation(tx, &validator_public_key, ValidatorOperation::Add)
        }) {
            error!(
                logger,
                "validator operation: add";
                "error" => %e
            );
        }

        let validator = Validator {
            owner,
            public_key: validator_public_key.clone(),
            releated_operators: operator_ids.clone(),
            active: true,
            registration_timestamp: log.block_timestamp.unwrap(),
        };
        db.with_transaction(|t| db.insert_validator(t, &validator))
            .map_err(|e| format!("failed to insert validator {}", e.to_string()))?;
        keypairs.write().insert(validator_public_key, key_pair);
    }
    Ok(())
}

async fn handle_validator_removal(
    log: &Log,
    logger: &Logger,
    config: &Config,
    db: &SafeStakeDatabase,
    keypairs: Arc<RwLock<HashMap<PublicKey, Keypair>>>,
) -> Result<(), String> {
    let SafeStakeNetwork::ValidatorRemoval { _0, _1 } =
        log.log_decode().map_err(|e| e.to_string())?.inner.data;
    let validator_public_key = PublicKey::deserialize(_1.as_ref()).map_err(|e: bls::Error| {
        error!(logger, "failed to deserialize shared public key");
        format!("{:?}", e)
    })?;
    db.with_transaction(|t| db.delete_validator(t, &validator_public_key))
        .map_err(|e| format!("failed to delete validator {}", e.to_string()))?;

    // delete validator dir
    let deleted_validator_dir = config
        .validator_dir
        .join(validator_public_key.as_hex_string());
    if deleted_validator_dir.exists() {
        let _ = remove_dir_all(&deleted_validator_dir);
    }
    // delete password file
    let password_file = config
        .secrets_dir
        .join(format!("{}_{}", validator_public_key, config.operator_id));
    if password_file.exists() {
        let _ = remove_file(password_file);
    }

    if let Err(e) = db.with_transaction(|tx| {
        db.insert_validator_operation(tx, &validator_public_key, ValidatorOperation::Remove)
    }) {
        error!(
            logger,
            "validator operation: remove";
            "error" => %e
        );
    }

    keypairs.write().remove(&validator_public_key);
    info!(
        logger,
        "validator removal";
        "validator public key" => %validator_public_key,
    );
    Ok(())
}

async fn handle_fee_recipient_set<T: SlotClock + 'static, E: EthSpec>(
    log: &Log,
    logger: &Logger,
    validator_store: Arc<ValidatorStore<T, E>>,
    db: &SafeStakeDatabase,
) -> Result<(), String> {
    let SafeStakeConfig::FeeRecipientAddressChanged { _0, _1 } =
        log.log_decode().map_err(|e| e.to_string())?.inner.data;
    let owner = _0;
    let fee_recipient = _1;
    let validator_public_keys = db
        .with_transaction(|t| {
            db.upsert_owner_fee_recipient(t, owner.clone(), fee_recipient.clone())?;
            db.query_validator_public_keys_by_owner(t, owner)
        })
        .map_err(|e| format!("failed to delete validator {}", e.to_string()))?;

    for validator_public_key in validator_public_keys {
        validator_store
            .set_validator_fee_recipient(
                &validator_public_key,
                H160::from_slice(fee_recipient.as_slice()),
            );

        db.with_transaction(|t| {
            db.update_validator_registration_timestamp(
                t,
                &validator_public_key,
                log.block_timestamp.unwrap(),
            )
        })
        .map_err(|e| {
            format!(
                "failed to update validator registration timestamp {}",
                e.to_string()
            )
        })?;

        info!(
            logger,
            "setting fee recipient";
            "validator public key" => %validator_public_key,
            "fee recipient address" => %fee_recipient
        );
    }
    Ok(())
}

pub fn convert_validator_public_key_to_id(public_key: &[u8]) -> u64 {
    let mut little_endian: [u8; 8] = [0; 8];
    let mut i = 0;
    for elem in little_endian.iter_mut() {
        *elem = public_key[i];
        i = i + 1;
    }
    let id = u64::from_le_bytes(little_endian);
    id
}

#[tokio::test]
async fn test_rpc_parse() {
    use alloy_primitives::{address};
    use safestake_crypto::secret::{Secret, Export};
    let rpc_url = "https://ethereum-holesky-rpc.publicnode.com".parse::<reqwest::Url>().unwrap();
    let provider: P = ProviderBuilder::new().on_http(rpc_url);
    let registry_address = address!("997dB01eD539e06D59aA3e79F7D2Edb2Ad3aD8AA");
    let network_address = address!("34637C3bE556BD8fD6A6a741669a501B79A79e3B");
    let config_address = address!("1EFB8c90381695584CcB117388Bba897b71e0635");
    let cluster_address = address!("1EFB8c90381695584CcB117388Bba897b71e0635");
    let filter = Filter::new()
        .from_block(2390031)
        .to_block(2390031 + 5000)
        .address(vec![registry_address, network_address, config_address, cluster_address])
        .event_signature(vec![VALIDATOR_REGISTRATION_TOPIC, VALIDATOR_REMOVAL_TOPIC, FEE_RECIPIENT_TOPIC]);
    let logs = provider.get_logs(&filter).await.unwrap();
    let operator_id = 1;
    let registry_contract = SafeStakeRegistryContract::new(
        registry_address,
        provider.clone(),
    );
    
    
    for log in logs {
        let SafeStakeNetwork::ValidatorRegistration {
            _0,
            _1,
            _2,
            _3,
            _4,
            _5,
        } = log.log_decode().map_err(|e| e.to_string()).unwrap().inner.data;
        let node_secret_path = dirs::home_dir().unwrap().join(".lighthouse/v1/holesky/node_key.json");
        let validator_dir = dirs::home_dir().unwrap().join(".lighthouse/v1/holesky/validators");
        let secrets_dir = dirs::home_dir().unwrap().join(".lighthouse/v1/holesky/secrets");
        if _2.contains(&operator_id) {
            let secret = if node_secret_path.exists() {
                let secret = Secret::read(&node_secret_path).unwrap();
                secret
            } else {
                panic!()
            };
            let validator_public_key = PublicKey::deserialize(_1.as_ref()).unwrap();
            let mut operator_public_keys = vec![];
            for operator_id in &_2 {
                let operator = registry_contract.query_operator(*operator_id).await.unwrap();
                operator_public_keys.push(operator.public_key);
            }
            let shared_public_keys: Vec<PublicKey> = _3
                .iter()
                .map(|shared_public_key| {
                    PublicKey::deserialize(shared_public_key.as_ref()).unwrap()
                })
                .collect();

            let self_index = _2
                .iter()
                .position(|x| *x == operator_id)
                .unwrap();

            // decrypt
            let key_pair = {
                let rng = rand::thread_rng();
                let mut elgamal = Elgamal::new(rng);
                let ciphertext = Ciphertext::from_bytes(&_4[self_index]);
                let plain_shared_key = elgamal
                    .decrypt(&ciphertext, &secret.secret)
                    .unwrap();
                let shared_secret_key = SecretKey::deserialize(&plain_shared_key).unwrap();
                let shared_public_key = shared_secret_key.public_key();
                Keypair::from_components(shared_public_key, shared_secret_key)
            };

            let keystore = KeystoreBuilder::new(&key_pair, INSECURE_PASSWORD, "".into()).unwrap()
                .kdf(insecure_kdf())
                .build()
                .unwrap();

            let keystore_share =
                KeystoreShare::new(keystore, validator_public_key.clone(), operator_id);
            println!("{:?}", keystore_share);
            ShareBuilder::new(validator_dir.clone())
                .password_dir(secrets_dir.clone())
                .voting_keystore_share(keystore_share.clone(), INSECURE_PASSWORD)
                .build()
                .unwrap();

            break;
        }
        
    }

    
}   
