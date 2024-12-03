use dvf_utils::VERSION;
use parking_lot::RwLock;
use safestake_crypto::secp::{Digest, Signature};
use safestake_crypto::secret::Secret;
use safestake_operator::database::SafeStakeDatabase;
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
use std::collections::HashMap;
use std::sync::Arc;
use store::{KeyValueStore, LevelDB};
use task_executor::TaskExecutor;
use tokio::sync::mpsc::Receiver;
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use types::{
    AbstractExecPayload, AttestationData, BeaconBlock, BlindedPayload, EthSpec, ExecPayload,
    FullPayload, Hash256,
};
use types::{Keypair, PublicKey, Signature as BlsSignature};
pub struct SafestakeService<E: EthSpec> {
    logger: Logger,
    secret: Secret,
    store: Arc<LevelDB<E>>,
    slashing_database: SlashingDatabase,
    safestake_database: SafeStakeDatabase,
    keypairs: Arc<RwLock<HashMap<PublicKey, Keypair>>>,
}

impl<E: EthSpec> SafestakeService<E> {
    pub fn serving(base_port: u16, executor: &TaskExecutor, operator_service: SafestakeService<E>) {
        let addr = format!("[::1]:{}", base_port).parse().unwrap();
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
        secret: Secret,
        store: Arc<LevelDB<E>>,
        slashing_database: SlashingDatabase,
        safestake_database: SafeStakeDatabase,
        keypairs: Arc<RwLock<HashMap<PublicKey, Keypair>>>,
        mut rx: Receiver<(Hash256, BlsSignature, PublicKey)>,
        executor: &TaskExecutor,
    ) -> Self {
        let safestake_service = Self {
            logger,
            secret,
            store: store.clone(),
            slashing_database,
            safestake_database: safestake_database.clone(),
            keypairs,
        };
        let store_fut = async move {
            loop {
                if let Some((msg, signature, validator_public_key)) = rx.recv().await {
                    let _ = store.put_bytes(
                        &validator_public_key.as_hex_string(),
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
        if !self.keypairs.read().contains_key(&validator_public_key) {
            return Err(Status::internal(format!(
                "unkown validators {}",
                validator_public_key
            )));
        }
        Ok(validator_public_key)
    }

    fn check_operator_domain_hash_signature(
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
            .map_err(|e| Status::internal(format!("failed to find operator's public key {:?}", e)))?
            .ok_or(Status::internal(format!(
                "failed to find operator's public key"
            )))?;

        signature
            .verify(&Digest(domain_hash.0), &operator_public_key)
            .map_err(|_| Status::internal(format!("failed to verify operator's signature")))?;

        Ok(())
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
                    let keypairs = self.keypairs.read();
                    let keypair =
                        keypairs
                            .get(validator_public_key)
                            .ok_or(Status::internal(format!(
                                "unkown validator public key {}",
                                validator_public_key
                            )))?;

                    let sig = keypair.sk.sign(signing_root);
                    let serialized_signature = bincode::serialize(&sig).unwrap();

                    self.store
                        .put_bytes(
                            &validator_public_key.as_hex_string(),
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
        let msg: [u8; 32] = req.msg.try_into().unwrap();
        let sig = Signature::new(&Digest::from(&msg), &self.secret.secret)
            .map_err(|e| Status::internal(format!("failed to sign message {:?}", e)))?;
        Ok(Response::new(CheckLivenessResponse {
            signature: bincode::serialize(&sig).unwrap(),
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
            .get_bytes(&hex::encode(&req.validator_public_key), &req.msg)
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
                let keypairs = self.keypairs.read();
                let keypair =
                    keypairs
                        .get(&validator_public_key)
                        .ok_or(Status::internal(format!(
                            "unkown validator public key {}",
                            validator_public_key
                        )))?;
                let sig = keypair.sk.sign(signing_root);
                let serialized_signature = bincode::serialize(&sig).unwrap();
                self.store
                    .put_bytes(
                        &hex::encode(&req.validator_public_key),
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
