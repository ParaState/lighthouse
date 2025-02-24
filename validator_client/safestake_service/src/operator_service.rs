use bls::SecretKey;
use dvf_utils::VERSION;
use safestake_crypto::secp::{Digest, Signature};
use safestake_database::SafeStakeDatabase;
use safestake_operator::proto::safestake_server::Safestake;
use safestake_operator::proto::safestake_server::SafestakeServer;
use safestake_operator::proto::{
    AttestRequest, AttestResponse, CheckLivenessRequest, CheckLivenessResponse,
    GetSignatureRequest, GetSignatureResponse, ProposeBlindedBlockRequest,
    ProposeBlindedBlockResponse, ProposeFullBlockRequest, ProposeFullBlockResponse,
};
use signing_method::SignableMessage;
use slashing_protection::{NotSafe, Safe, SlashingDatabase};
use slog::{error, info, Logger};
use tonic::transport::Channel;
use tonic::transport::Endpoint;
use std::sync::Arc;
use store::{database::leveldb_impl::LevelDB, DBColumn};
use task_executor::TaskExecutor;
use tokio::sync::mpsc::Receiver;
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use types::{
    AbstractExecPayload, AttestationData, BeaconBlock, BlindedPayload, EthSpec, ExecPayload,
    FullPayload, Hash256,
};
use types::{PublicKey, Signature as BlsSignature};
use parking_lot::RwLock;
use account_utils::validator_definitions::{ValidatorDefinitions, SigningDefinition};
use std::collections::HashMap;
use eth2_keystore_share::KeystoreShare;
use validator_dir::insecure_keys::INSECURE_PASSWORD;
use account_utils::default_operator_committee_definition_path;
use account_utils::operator_committee_definitions::OperatorCommitteeDefinition;
use crate::config::Config;
use safestake_operator::CHANNEL_SIZE;

pub struct SafestakeService<E: EthSpec> {
    logger: Logger,
    store: Arc<LevelDB<E>>,
    slashing_database: SlashingDatabase,
    safestake_database: SafeStakeDatabase,
    validator_keys: Arc<RwLock<HashMap<PublicKey, SecretKey>>>
}

impl<E: EthSpec> SafestakeService<E> {
    pub fn serving(base_port: u16, executor: &TaskExecutor, operator_service: SafestakeService<E>) {
        let addr = format!("0.0.0.0:{}", base_port).parse().unwrap();
        executor.spawn(
            async move {
                Server::builder()
                    .add_service(SafestakeServer::new(operator_service))
                    .serve(addr)
                    .await
                    .unwrap()
            },
            "safestake_server",
        );
    }

    pub fn new(
        logger: Logger,
        store: Arc<LevelDB<E>>,
        slashing_database: SlashingDatabase,
        safestake_database: SafeStakeDatabase,
        mut rx: Receiver<(Hash256, BlsSignature, PublicKey)>,
        executor: &TaskExecutor,
        validator_keys: Arc<RwLock<HashMap<PublicKey, SecretKey>>>
    ) -> Self {
        let log = logger.clone();
        let safestake_service = Self {
            logger,
            store: store.clone(),
            slashing_database,
            safestake_database: safestake_database.clone(),
            validator_keys
        };
        let store_fut = async move {
            loop {
                if let Some((msg, signature, _validator_public_key)) = rx.recv().await {
                    info!(log, "local sign"; "signing root" => %hex::encode(msg));
                    let _ = store.put_bytes(
                        DBColumn::SafeStake,
                        // &validator_public_key.as_hex_string(),
                        &msg.0,
                        &signature.serialize(),
                    );
                }
            }
        };
        executor.spawn(store_fut, "signature_store");
        safestake_service
    }

    async fn check_version_and_validator_public_key(
        &self,
        version: u64,
        validator_public_key: &[u8],
    ) -> Result<PublicKey, Status> {
        if version != VERSION {
            return Err(Status::internal(format!(
                "version mismatch, expected {}, got {}",
                VERSION, version
            )));
        }

        let validator_public_key = PublicKey::deserialize(validator_public_key).map_err(|e| {
            Status::internal(format!(
                "failed to deserialize validator public key {:?}",
                e
            ))
        })?;
        // if self.validator_client.get_lighthouse_validators_pubkey(&validator_public_key.compress()).await.map_err(|_| {
        //     Status::internal(format!(
        //         "validator is not enabled on this operator {}",
        //         &validator_public_key
        //     ))
        // })?.is_none() {
        //     return Err(Status::internal(format!(
        //         "validator is not enabled on this operator {}",
        //         &validator_public_key
        //     )));
        // }
        if !self.validator_keys.read().contains_key(&validator_public_key) {
            return Err(Status::internal(format!(
                "validator is not enabled on this operator {}",
                &validator_public_key
            )));
        }

        Ok(validator_public_key)
    }

    fn  check_operator_domain_hash_signature(
        &self,
        domain_hash: &Hash256,
        signature: &[u8],
        operator_id: u32,
    ) -> Result<(), Status> {
        let signature = Signature::from_bytes(signature)
            .map_err(|e| Status::internal(format!("failed to deserialize signature {:?}", e)))?;
        let operator_public_key = self
            .safestake_database
            .with_transaction(|tx| {
                self.safestake_database
                    .query_operator_public_key(tx, operator_id)
            })
            .map_err(|e| Status::internal(format!("failed to find operator's public key {:?}", e)))?;

        signature
            .verify(&Digest(domain_hash.0), &operator_public_key)
            .map_err(|_| Status::internal(format!("failed to verify operator's signature")))?;

        Ok(())
    }

    async fn sign_msg(
        &self,
        validator_public_key: &PublicKey,
        msg: Hash256,
    ) -> Result<BlsSignature, Status> {
        // self.validator_client
        //     .post_keypair_sign(&validator_public_key.compress(), msg)
        //     .await
        //     .map_err(|_| {
        //         Status::internal(format!(
        //             "unkown validator public key {}",
        //             validator_public_key
        //         ))
        //     })?
        //     .ok_or(Status::internal(format!(
        //         "unkown validator public key {}",
        //         validator_public_key
        //     )))
        Ok(self.validator_keys.read().get(validator_public_key).ok_or(Status::internal(format!(
            "unkown validator public key {}", validator_public_key
        )))?.sign(msg))
    }

    async fn sign_block<Payload: AbstractExecPayload<E>>(
        &self,
        block: BeaconBlock<E, Payload>,
        domain_hash: Hash256,
        validator_public_key: &PublicKey,
    ) -> Result<String, Status> {
        Ok(
            match self.slashing_database.check_and_insert_block_proposal(
                &validator_public_key.compress(),
                &block.block_header(),
                domain_hash,
            ) {
                Ok(Safe::Valid) => {
                    let signable_msg = SignableMessage::BeaconBlock(&block);
                    let signing_root = signable_msg.signing_root(domain_hash);
                    info!(
                        self.logger,
                        "safestake operator sign block";
                        "signing root" => format!("{:?}", signing_root)
                    );
                    let sig = self.sign_msg(&validator_public_key, signing_root).await?;
                    let serialized_signature = sig.serialize();

                    self.store
                        .put_bytes(
                            DBColumn::SafeStake,
                            // &validator_public_key.as_hex_string(),
                            &signing_root.0,
                            &serialized_signature,
                        )
                        .map_err(|e| {
                            Status::internal(format!("failed to save signature {:?}", e))
                        })?;
                    format!("successfully consensus block on {}", &signing_root)
                }
                Ok(Safe::SameData) => {
                    format!("skipping signing of previously signed block")
                }
                Err(e) => {
                    format!(
                        "do not sign slashable proposal {}: {:?}",
                        validator_public_key, e
                    )
                }
            },
        )
    }
}

#[tonic::async_trait]
impl<E: EthSpec> Safestake for SafestakeService<E> {
    async fn check_liveness(
        &self,
        request: Request<CheckLivenessRequest>,
    ) -> Result<Response<CheckLivenessResponse>, Status> {
        let req = request.into_inner();
        let _ = self
            .check_version_and_validator_public_key(req.version, &req.validator_public_key)
            .await?;
        if req.msg.len() != 32 {
            return Err(Status::internal(format!("invalid message length")));
        }
        // let msg: [u8; 32] = req.msg.try_into().unwrap();
        // let sig = Signature::new(&Digest::from(&msg), &self.secret.secret)
        //     .map_err(|e| Status::internal(format!("failed to sign message {:?}", e)))?;
        Ok(Response::new(CheckLivenessResponse {
            // signature: bincode::serialize(&sig).unwrap(),
            signature: vec![]
        }))
    }

    async fn get_signature(
        &self,
        request: Request<GetSignatureRequest>,
    ) -> Result<Response<GetSignatureResponse>, Status> {
        let req = request.into_inner();
        let _ = self
            .check_version_and_validator_public_key(req.version, &req.validator_public_key)
            .await?;
        let signature = self
            .store
            .get_bytes(
                DBColumn::SafeStake,
                // &format!("0x{}", hex::encode(&req.validator_public_key)), 
                &req.msg)
            .map_err(|e| Status::internal(format!("failed to read signature {:?}", e)))?;
        if let Some(signature) = signature {
            Ok(Response::new(GetSignatureResponse { signature }))
        } else {
            Err(Status::internal(format!(
                "failed to find message's signature"
            )))
        }
    }

    async fn attest_data(
        &self,
        request: Request<AttestRequest>,
    ) -> Result<Response<AttestResponse>, Status> {
        let req = request.into_inner();
        let validator_public_key = self
            .check_version_and_validator_public_key(req.version, &req.validator_public_key)
            .await?;

        let domain_hash = Hash256::from(&req.domain_hash.try_into().unwrap());
        self.check_operator_domain_hash_signature(
            &domain_hash,
            &req.domian_hash_signature,
            req.operator_id,
        )?;

        let attestation_data: AttestationData = match serde_json::from_slice(&req.attestation_data)
        {
            Ok(a) => a,
            Err(e) => {
                error!(self.logger, "deserialize attestation data"; "error" => %e);
                return Err(Status::internal(format!(
                    "failed to deserialize attestation data"
                )));
            }
        };

        let output = match self.slashing_database.check_and_insert_attestation(
            &validator_public_key.compress(),
            &attestation_data,
            domain_hash,
        ) {
            Ok(Safe::Valid) => {
                let signable_msg =
                    SignableMessage::<E, BlindedPayload<E>>::AttestationData(&attestation_data);
                let signing_root = signable_msg.signing_root(domain_hash);
                info!(self.logger, "opeartor service attestation"; "signing root" => %signing_root);
                let sig = self.sign_msg(&validator_public_key, signing_root).await?;
                let serialized_signature = sig.serialize();
                self.store
                    .put_bytes(
                        // &format!("0x{}", hex::encode(req.validator_public_key)),
                        DBColumn::SafeStake,
                        &signing_root.0,
                        &serialized_signature,
                    )
                    .map_err(|e| Status::internal(format!("failed to save signature {:?}", e)))?;
                format!("successfully consensus attestation on {}", &signing_root)
            }
            Ok(Safe::SameData) => {
                format!("skipping signing of previously signed attestation")
            }
            Err(NotSafe::UnregisteredValidator(validator_public_key)) => {
                format!(
                    "do not signing attestation for unregistered validator public_key {}",
                    validator_public_key
                )
            }
            Err(e) => {
                format!(
                    "do not sign slashable attestation {}: {:?}",
                    validator_public_key, e
                )
            }
        };

        Ok(Response::new(AttestResponse { msg: output }))
    }

    async fn propose_full_block(
        &self,
        request: Request<ProposeFullBlockRequest>,
    ) -> Result<Response<ProposeFullBlockResponse>, Status> {
        let req = request.into_inner();
        let validator_public_key = self
            .check_version_and_validator_public_key(req.version, &req.validator_public_key)
            .await?;
        let domain_hash = Hash256::from(&req.domain_hash.try_into().unwrap());
        self.check_operator_domain_hash_signature(
            &domain_hash,
            &req.domian_hash_signature,
            req.operator_id,
        )?;

        let block: BeaconBlock<E, FullPayload<E>> =
            match serde_json::from_slice(&req.full_block_data) {
                Ok(b) => b,
                Err(e) => {
                    error!(self.logger, "deserialize full block"; "error" => %e);
                    return Err(Status::internal(format!(
                        "failed to deserialize propose full block data"
                    )));
                }
            };

        let fee_recipient = self
            .safestake_database
            .with_transaction(|tx| {
                self.safestake_database
                    .query_validator_fee_recipient(tx, &validator_public_key)
            })
            .map_err(|e| {
                Status::internal(format!("failed to query validator fee recipient {:?}", e))
            })?;

        let block_fee_recipient = block.body().execution_payload().unwrap().fee_recipient();

        if fee_recipient.as_slice() != &block_fee_recipient.0 {
            return Err(Status::internal(format!(
                "fee recipient mismatch, local fee recipient {:?}, block fee recipient {:?}",
                fee_recipient, block_fee_recipient
            )));
        }

        info!(
            self.logger,
            "propose full block";
            "validator public key" => %validator_public_key,
            "fee recipient address" => %fee_recipient
        );

        let output = self
            .sign_block(block, domain_hash, &validator_public_key)
            .await?;

        Ok(Response::new(ProposeFullBlockResponse { msg: output }))
    }

    async fn propose_blinded_block(
        &self,
        request: Request<ProposeBlindedBlockRequest>,
    ) -> Result<Response<ProposeBlindedBlockResponse>, Status> {
        let req = request.into_inner();
        let validator_public_key = self
            .check_version_and_validator_public_key(req.version, &req.validator_public_key)
            .await?;
        let domain_hash = Hash256::from(&req.domain_hash.try_into().unwrap());
        self.check_operator_domain_hash_signature(
            &domain_hash,
            &req.domian_hash_signature,
            req.operator_id,
        )?;

        let block: BeaconBlock<E, BlindedPayload<E>> =
            match serde_json::from_slice(&req.blinded_block_data) {
                Ok(b) => b,
                Err(e) => {
                    error!(self.logger, "deserialize blinded block"; "error" => %e);
                    return Err(Status::internal(format!(
                        "failed to deserialize propose blinded block data"
                    )));
                }
            };

        info!(
            self.logger,
            "propose blinded block";
            "validator public key" => %validator_public_key,
        );

        let output = self
            .sign_block(block, domain_hash, &validator_public_key)
            .await?;

        Ok(Response::new(ProposeBlindedBlockResponse { msg: output }))
    }
}

#[tokio::test]
async fn test_query_validator() {
    use eth2::lighthouse_vc::http_client::ValidatorClientHttpClient;
    use crate::SensitiveUrl;
    use validator_http_api::ApiSecret;
    use std::path::Path;
    let api_secret = ApiSecret::create_or_open(&Path::new("/home/jiangyi/.lighthouse/v1/holesky/validators")).unwrap();
    let url = SensitiveUrl::parse(&format!("http://127.0.0.1:{}", 5062)).unwrap();
    let api_pubkey = api_secret.api_token();
    let client = ValidatorClientHttpClient::new(url.clone(), api_pubkey).unwrap();
    let pk = PublicKey::deserialize(&hex::decode("81d214246ae4ea96f18b8f0dd4a56ed0fef87f0c79a6652ce3743b029b4f0b88e2b58e471652914af756e49f8cb17182").unwrap()).unwrap();
    println!("{:?}", client.get_lighthouse_validators_pubkey(&pk.compress()).await.map_err(|_| {
        Status::internal(format!(
            "validator is not enabled on this operator {}",
            &pk
        ))
    }).unwrap());
}

pub fn get_validator_keys(validator_defs: &ValidatorDefinitions) -> Result<HashMap<PublicKey, SecretKey>, String> {
    let mut validator_secretkey = HashMap::new();

    for validator_def in validator_defs.as_slice() {
        let voting_key = validator_def.voting_public_key.clone();
        match &validator_def.signing_definition {
            SigningDefinition::DistributedKeystore { voting_keystore_share_path, .. } => {
                let keystore = std::fs::File::options()
                    .read(true)
                    .create(false)
                    .open(voting_keystore_share_path)
                    .map_err(|e| format!("{:?}", e))
                    .and_then(|file| {
                        KeystoreShare::from_json_reader(file).map_err(|e| format!("{:?}", e))
                    })?;
                let sk = keystore.keystore.decrypt_keypair(INSECURE_PASSWORD).unwrap().sk;
                validator_secretkey.insert(voting_key, sk);
            },
            _ => {}
        }
    }
    Ok(validator_secretkey)
}

pub fn get_channels(validator_defs: &ValidatorDefinitions, config: &Config) -> Result<HashMap<u32, Vec<Channel>>, String> {
    let mut channels = HashMap::new();
    for validator_def in validator_defs.as_slice() {
        let operator_committee_definition_path = default_operator_committee_definition_path(
            &validator_def.voting_public_key,
            &config.validator_dir,
        );
        let def = OperatorCommitteeDefinition::from_file(operator_committee_definition_path).map_err(|e| {
            format!("failed to parse operator committee def {:?}", e)
        })?;
        
        for i in 0..def.total as usize {
            if def.operator_ids[i] != config.operator_id {
                if !channels.contains_key(&def.operator_ids[i]) {
                    if let Some(addr) = def.base_socket_addresses[i] {
                        let mut c = vec![];
                        for _i in 0..CHANNEL_SIZE {
                            c.push(Endpoint::from_shared(format!("http://{}", addr.to_string()))
                            .unwrap()
                            .connect_lazy());
                        }
                        channels.insert(def.operator_ids[i], c);
                    }
                }
            }   
        }
    }
    Ok(channels)
}