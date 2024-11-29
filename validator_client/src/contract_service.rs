
use types::EthSpec;
use crate::validator_store::ValidatorStore;
use crate::Config;
use alloy_provider::{Provider, ProviderBuilder, RootProvider};
use alloy_rpc_types::{Filter, Log};
use alloy_sol_macro::sol;
use alloy_sol_types::SolEvent;
use alloy_primitives::{b256, keccak256, Address, FixedBytes};
use alloy_transport_http::{Http, Client};
use std::{collections::HashMap, sync::Arc};
use serde::{Serialize, Deserialize};
use bls::{PublicKey, SecretKey, Keypair};
use std::fs::File;
use std::path::Path;
use slog::{Logger, warn, info, log, error};
use std::time::Duration;
use crate::operator::database::SafeStakeDatabase;
use crate::operator::models::{Operator, Validator};
use safestake_crypto::secp::PublicKey as SecpPublicKey;
use safestake_crypto::secret::Secret;
use safestake_crypto::elgamal::{Ciphertext, Elgamal};
use eth2_keystore::KeystoreBuilder;
use validator_dir::insecure_keys::{INSECURE_PASSWORD, insecure_kdf};
use validator_dir::{ShareBuilder, default_keystore_share_path};
use std::path::PathBuf;
use crate::operator::operator_committee::DvfOperatorCommittee;
use account_utils::operator_committee_definitions::OperatorCommitteeDefinition;
use account_utils::{
    default_keystore_share_password_path,
    default_operator_committee_definition_path,
};
use eth2_keystore_share::KeystoreShare;
use crate::operator::THRESHOLD_MAP;

const VALIDATOR_REGISTRATION: &str = "ValidatorRegistration(address,bytes,uint32[],bytes[],bytes[],uint256)";
const VALIDATOR_REMOVAL: &str = "ValidatorRemoval(address,bytes)";
const FEE_RECIPIENT_SET: &str = "FeeRecipientAddressChanged(address,address)";

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
        event ValidatorRegistration(address,bytes,uint32[],bytes[],bytes[],uint256);
        event ValidatorRemoval(address,bytes);
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

impl SafeStakeRegistryContract {
    async fn query_operator(&self, operator_id: u32) -> Result<Operator, String> {
        let SafeStakeRegistry::_operatorsReturn {_0, _1 , _2, ..} = self._operators(operator_id).call().await.map_err(|e| e.to_string())?;
        let public_key_slice: [u8; 33] = _1.as_ref().try_into().map_err(|_| "failed to parse node public key".to_string())?;
        let operator = Operator {
            id: operator_id,
            name: _0,
            owner: _2,
            public_key: SecpPublicKey(public_key_slice)
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
        serde_yaml::to_writer(file, self).map_err(|e| format!("failed to serialize to file {:?}", e))
    }
}

pub struct ContractService {
}

impl ContractService {
    pub async fn spawn<T, E: EthSpec>(config: &Config, log: Logger, validator_store: Arc<ValidatorStore<T, E>>, db: SafeStakeDatabase) -> Result<(), String> {
        let provider: P = ProviderBuilder::new().on_http(config.rpc_url.parse::<reqwest::Url>().map_err(|e| {
            e.to_string()
        })?);

        let registry_contract = SafeStakeRegistryContract::new(config.registry_contract.parse::<Address>().map_err(|e| e.to_string())?, provider.clone());

        let SafeStakeRegistry::_operatorsReturn {_0, _1 , _2, ..} = registry_contract._operators(config.operator_id as u32).call().await.map_err(|e| e.to_string())?;
        
        if config.node_secret.name.0 != _1.as_ref() {
            return Err(format!("operator id {} and its public key are not consistent with smart contract! Please make sure operator id is right", config.operator_id));
        }

        let filter = Filter::new();
        Ok(())
    }

    pub async fn spawn_pull_logs<T, E: EthSpec>(config: &Config, provider: RootProvider<Http<Client>>, log: Logger, validator_store: Arc<ValidatorStore<T, E>>, db: SafeStakeDatabase) -> Result<(), String> {
        let mut record = match BlockRecord::from_file(&config.contract_record_path) {
            Ok(r) => r,
            Err(e) => {
                let current_block = provider.get_block_number().await.map_err(|e| e.to_string())?;
                warn!(
                    log, 
                    "contract service"; 
                    "file error" => e, 
                    "current block" => current_block
                );
                BlockRecord { block_num: current_block }
            }
        };
        let registry_address = config.registry_contract.parse::<Address>().map_err(|e| e.to_string())?;
        let network_address = config.network_contract.parse::<Address>().map_err(|e| e.to_string())?;
        let config_address = config.config_contract.parse::<Address>().map_err(|e| e.to_string())?;
        let cluster_address = config.cluster_contract.parse::<Address>().map_err(|e| e.to_string())?;
        
        // let handlers: HashMap<FixedBytes<32>, Handler<T, E>> = HashMap::new();
        // handlers.insert(validator_registration_topic, process_validator_registration);
        tokio::spawn(async move {
            let mut query_interval =
                tokio::time::interval(Duration::from_secs(60));
            loop {
                query_interval.tick().await;
                match provider.get_block_number().await {
                    Ok(current_block) => {
                        let filter = Filter::new()
                            .from_block(record.block_num)
                            .to_block(std::cmp::min(current_block, record.block_num + 1024))
                            .address(vec![registry_address, network_address, config_address, cluster_address])
                            .events(vec![VALIDATOR_REGISTRATION, VALIDATOR_REMOVAL, FEE_RECIPIENT_SET]);
                        match provider.get_logs(&filter).await {
                            Ok(logs) => {
                                if logs.len() == 0 {
                                    record.block_num = std::cmp::min(current_block, record.block_num + 1024 + 1);
                                    continue;
                                }
                                for log in logs {


                                    record.block_num = log.block_number.unwrap() + 1;
                                }
                            },
                            Err(e) => {
                                warn!(log, "contract service"; "rpc error" => e.to_string());
                            }
                        }
                    },
                    Err(e) => {
                        warn!(log, "contract service"; "rpc error" => e.to_string());
                    }
                }
            }
        });

        Ok(())
    }
}

async fn process_events<T, E: EthSpec>(
    logger: &Logger, 
    self_operator_id: u32, 
    validator_store: Arc<ValidatorStore<T, E>>, 
    db: SafeStakeDatabase, 
    log: Log, 
    registry_contract: SafeStakeRegistryContract, 
    secret: &Secret,
    validator_dir: PathBuf,
    secret_dir: PathBuf
) -> Result<(), String> {
    match log.topic0() {
        Some(&SafeStakeNetwork::ValidatorRegistration::SIGNATURE_HASH) => {
            let SafeStakeNetwork::ValidatorRegistration {
                _0, 
                _1,
                _2,
                _3,
                _4,
                _5
            } = log.log_decode().map_err(|e| e.to_string())?.inner.data;
            let owner = _0;
            let validator_public_key = PublicKey::deserialize(_1.as_ref()).map_err(|_| format!("failed to deserialize validator public key"))?;
            let operator_ids = _2;
            info!(
                logger, 
                "validator registration";
                "owner" => owner.to_string(),
                "public key" => validator_public_key.as_hex_string(),
                "operatrs" => format!("{:?}", operator_ids),
            );

            if operator_ids.contains(&self_operator_id) {
                let mut operator_public_keys = vec![];
                for operator_id in &operator_ids {
                    let operator = registry_contract.query_operator(*operator_id).await?;
                    db.with_transaction(|t| {
                        db.insert_operator(t, &operator)
                    }).map_err(|e| {
                        format!("failed to insert operator {}", e.to_string())
                    })?;
                    operator_public_keys.push(operator.public_key);
                }
                let shared_public_keys: Vec<Result<PublicKey, String>> = _3.iter().map(|shared_public_key| {
                    PublicKey::deserialize(shared_public_key.as_ref()).map_err(|e: bls::Error| {
                        error!(
                            logger,
                            "failed to deserialize shared public key"
                        );
                        format!("{:?}", e)
                    })
                }).collect();
                if shared_public_keys.iter().any(|x| !x.is_ok()) {
                    return Err(format!("failed to deserialize shared public key, validator: {}", validator_public_key));
                }
                let shared_public_keys: Vec<PublicKey> = shared_public_keys.into_iter().map(|x| x.unwrap()).collect();

                let self_index = operator_ids.iter().position(|x| *x == self_operator_id).unwrap();

                // decrypt 
                let key_pair = {
                    let rng = rand::thread_rng();
                    let mut elgamal = Elgamal::new(rng);
                    let ciphertext = Ciphertext::from_bytes(&_4[self_index]);
                    let plain_shared_key = elgamal.decrypt(&ciphertext, &secret.secret).map_err(|e| e.to_string())?;
                    let shared_secret_key = SecretKey::deserialize(&plain_shared_key).map_err(|e| format!("failed to deserialize decrypted key: {:?}", e))?;
                    let shared_public_key = shared_secret_key.public_key();
                    Keypair::from_components(shared_public_key, shared_secret_key)
                };

                let keystore = KeystoreBuilder::new(&key_pair, INSECURE_PASSWORD, "".into()).map_err(|e| format!("{:?}", e))?.kdf(insecure_kdf()).build().map_err(|e| {
                    format!("{:?}", e)
                })?;

                let keystore_share = KeystoreShare::new(
                    keystore,
                    validator_public_key.clone(),
                    self_operator_id
                );
                ShareBuilder::new(validator_dir.clone())
                    .password_dir(secret_dir.clone())
                    .voting_keystore_share(keystore_share.clone(), INSECURE_PASSWORD)
                    .build()
                    .map_err(|e| {format!("{:?}", e)})?;

                let def = OperatorCommitteeDefinition {
                    total: operator_ids.len() as u64,
                    threshold: *THRESHOLD_MAP.get(&(operator_ids.len() as u64)).ok_or(format!("unkown number of operator committees"))?,
                    validator_id: convert_validator_public_key_to_id(&validator_public_key.serialize()),
                    validator_public_key: validator_public_key.clone(),
                    operator_ids: operator_ids.clone(),
                    operator_public_keys: shared_public_keys,
                    node_public_keys: operator_public_keys,
                    base_socket_addresses: vec![],
                };

                let committee_def_path = default_operator_committee_definition_path(&validator_public_key, validator_dir.clone());
                def.to_file(committee_def_path.clone()).map_err(|e| format!("failed to save committee definition: {:?}", e))?;
                let voting_keystore_share_path = default_keystore_share_path(&keystore_share, validator_dir.clone());
                let voting_keystore_share_password_path = default_keystore_share_password_path(&keystore_share, secret_dir.clone());

                // validator_store.

                let validator = Validator {
                    owner: _0,
                    public_key: validator_public_key,
                    releated_operators: operator_ids.clone(),
                    active: true,
                    registration_timestamp: log.block_timestamp.unwrap()
                };
                db.with_transaction(|t| {
                    db.insert_validator(t, &validator)
                }).map_err(|e| {
                    format!("failed to insert validator {}", e.to_string())
                })?;
                
            }


        },
        Some(&SafeStakeNetwork::ValidatorRemoval::SIGNATURE_HASH) => {

        },
        Some(&SafeStakeConfig::FeeRecipientAddressChanged::SIGNATURE_HASH) => {

        },
        _ => {

        }
    };
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