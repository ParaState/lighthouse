use bls::SecretKey;
use dvf_utils::SOFTWARE_VERSION;
use dvf_utils::VERSION;
use safestake_crypto::secp::{Digest, Signature};
use safestake_database::SafeStakeDatabase;
use safestake_operator::proto::safestake_server::Safestake;
use safestake_operator::proto::safestake_server::SafestakeServer;
use safestake_operator::proto::*;
use slashing_protection::{NotSafe, Safe, SlashingDatabase};
use tracing::{error, info, warn};
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
    FullPayload, Hash256, Attestation, SignedAggregateAndProof, SyncCommitteeMessage, ChainSpec, SignedBeaconBlock, SignedRoot, Slot, KzgProofs, BlobsList
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
use beacon_node_fallback::{ApiTopic, BeaconNodeFallback};
use slot_clock::SlotClock;
use either::Either;
use eth2::types::PublishBlockRequest;
pub struct SafestakeService<T: SlotClock + 'static, E: EthSpec> {
    store: Arc<LevelDB<E>>,
    slashing_database: SlashingDatabase,
    safestake_database: SafeStakeDatabase,
    validator_keys: Arc<RwLock<HashMap<PublicKey, SecretKey>>>,
    beacon_nodes: Arc<BeaconNodeFallback<T>>,
    spec: Arc<ChainSpec>
}

impl<T: SlotClock + 'static, E: EthSpec> SafestakeService<T, E> {
    pub fn serving(base_port: u16, executor: &TaskExecutor, operator_service: SafestakeService<T, E>) {
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
        store: Arc<LevelDB<E>>,
        slashing_database: SlashingDatabase,
        safestake_database: SafeStakeDatabase,
        mut rx: Receiver<(Hash256, BlsSignature, PublicKey)>,
        executor: &TaskExecutor,
        validator_keys: Arc<RwLock<HashMap<PublicKey, SecretKey>>>,
        spec: Arc<ChainSpec>,
        beacon_nodes: Arc<BeaconNodeFallback<T>>,
    ) -> Self {
        let safestake_service = Self {
            store: store.clone(),
            slashing_database,
            safestake_database: safestake_database.clone(),
            validator_keys,
            spec: spec.clone(),
            beacon_nodes: beacon_nodes.clone(),
        };
        let store_fut = async move {
            loop {
                if let Some((msg, signature, validator_public_key)) = rx.recv().await {
                    info!(info="local sign", signing_root= %hex::encode(msg));
                    let mut key = msg.0.to_vec();
                    key.extend_from_slice(&validator_public_key.serialize());
                    let _ = store.put_bytes(
                        DBColumn::SafeStake,
                        // &validator_public_key.as_hex_string(),
                        &key,
                        &signature.serialize(),
                    );
                    // Compatible with old versions, need to be deleted later
                    if store.get_bytes(DBColumn::SafeStake,&msg.0).unwrap().is_none() {
                        let _ = store.put_bytes(
                            DBColumn::SafeStake,
                            // &validator_public_key.as_hex_string(),
                            &msg.0,
                            &signature.serialize(),
                        );
                    }
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
                    let signing_root = block.signing_root(domain_hash);
                    info!(
                        info="safestake operator sign block",
                        signing_root=format!("{:?}", signing_root)
                    );
                    let sig = self.sign_msg(&validator_public_key, signing_root).await?;
                    let serialized_signature = sig.serialize();

                    self.store
                        .put_bytes(
                            DBColumn::SafeStake,
                            &signing_root.0,
                            &serialized_signature,
                        )
                        .map_err(|e| {
                            Status::internal(format!("failed to save signature {:?}", e))
                        })?;

                    let mut key = signing_root.0.to_vec();
                    key.extend_from_slice(&validator_public_key.serialize());
                    self.store
                        .put_bytes(
                            DBColumn::SafeStake,
                            &key,
                            &serialized_signature,
                        )
                        .map_err(|e| Status::internal(format!("failed to save signature {:?}", e)))?;
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

    fn check_msg_signed(
        &self,
        signing_root: &[u8],
        validator_public_key: &[u8],
    ) -> Result<(), Status> {
        let mut key = signing_root.to_vec();
        key.extend_from_slice(validator_public_key);
        let signature = self
            .store
            .get_bytes(
                DBColumn::SafeStake,
                &key)
            .map_err(|e| {
                Status::internal(format!("failed to read signature {:?}", e))
            })?;
        if signature.is_none() {
            error!(
                error="can't find signature when checking",
                signing_root=hex::encode(signing_root),
            );
            return Err(Status::internal(format!("failed to find signature for {:?}", hex::encode(signing_root))));
        }
        Ok(())
    }

}

#[tonic::async_trait]
impl<T: SlotClock + 'static, E: EthSpec> Safestake for SafestakeService<T, E> {
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
            signature: vec![],
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
        let signature = self.store
            .get_bytes(
                DBColumn::SafeStake,
                &req.msg)
            .map_err(|e| Status::internal(format!("failed to read signature {:?}", e)))?;
        if let Some(signature) = signature {
            return Ok(Response::new(GetSignatureResponse { signature }));
        }
        Err(Status::internal(format!(
            "failed to find message's signature"
        )))
    }

    async fn get_signature_v2(
        &self,
        request: Request<GetSignatureRequest>,
    ) -> Result<Response<GetSignatureResponse>, Status> {
        let req = request.into_inner();
        let _ = self
            .check_version_and_validator_public_key(req.version, &req.validator_public_key)
            .await?;
        let mut key = req.msg.clone();
        key.extend_from_slice(&req.validator_public_key);
        let signature = self
            .store
            .get_bytes(
                DBColumn::SafeStake,
                &key)
            .map_err(|e| Status::internal(format!("failed to read signature {:?}", e)))?;
        if let Some(signature) = signature {
            return Ok(Response::new(GetSignatureResponse { signature }));
        }
        Err(Status::internal(format!(
            "failed to find message's signature"
        )))
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

        let attest_bytes = match safestake_operator::decompress_data(&req.attestation_data) {
            Ok(d) => d,
            Err(_) => req.attestation_data
        };
        let attestation_data: AttestationData = match serde_json::from_slice(&attest_bytes)
        {
            Ok(a) => a,
            Err(_) => {
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
                let signing_root = attestation_data.signing_root(domain_hash);
                info!(info="opeartor service attestation",signing_root=%signing_root);
                let sig = self.sign_msg(&validator_public_key, signing_root).await?;
                let serialized_signature = sig.serialize();
                self.store
                    .put_bytes(
                        DBColumn::SafeStake,
                        &signing_root.0,
                        &serialized_signature,
                    )
                    .map_err(|e| Status::internal(format!("failed to save signature {:?}", e)))?;
                let mut key = signing_root.0.to_vec();
                key.extend_from_slice(&req.validator_public_key);
                self.store
                    .put_bytes(
                        DBColumn::SafeStake,
                        &key,
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
        let block_bytes = match safestake_operator::decompress_data(&req.full_block_data) {
            Ok(d) => d,
            Err(_) => req.full_block_data
        };

        let block: BeaconBlock<E, FullPayload<E>> =
            match serde_json::from_slice(&block_bytes) {
                Ok(b) => b,
                Err(_) => {
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
            info="propose full block",
            validator_public_key=%validator_public_key,
            fee_recipient= %fee_recipient
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
        let block_bytes = match safestake_operator::decompress_data(&req.blinded_block_data) {
            Ok(d) => d,
            Err(_) => req.blinded_block_data
        };
        let block: BeaconBlock<E, BlindedPayload<E>> =
            match serde_json::from_slice(&block_bytes) {
                Ok(b) => b,
                Err(_) => {
                    return Err(Status::internal(format!(
                        "failed to deserialize propose blinded block data"
                    )));
                }
            };

        info!(
            info="propose blinded block",
            validator_public_key=%validator_public_key,
        );

        let output = self
            .sign_block(block, domain_hash, &validator_public_key)
            .await?;

        Ok(Response::new(ProposeBlindedBlockResponse { msg: output }))
    }

    async fn get_software_version(
        &self,
        _: Request<GetSoftwareVersionRequest>
    ) -> Result<Response<GetSoftwareVersionResponse>, Status> {

        Ok(Response::new(GetSoftwareVersionResponse { software_vresion: SOFTWARE_VERSION }))
    }

    async fn broadcast_attestation(
        &self,
        request: Request<BroadcastAttestationRequest>,
    ) -> Result<Response<EmptyResponse>, Status> {
        let req = request.into_inner();
        let domain_hash = Hash256::from(&req.domain_hash.try_into().unwrap());
        self.check_operator_domain_hash_signature(
            &domain_hash,
            &req.domain_hash_signature,
            req.operator_id,
        )?;
        
        let attestation_bytes = safestake_operator::decompress_data(&req.attestation).unwrap();
        let attestation: Attestation<E> = match serde_json::from_slice(&attestation_bytes) {
            Ok(a) => a,
            Err(_) => {
                return Err(Status::internal(format!(
                    "failed to deserialize attestation data"
                )));
            }
        };

        let signing_root = attestation.data().signing_root(domain_hash);
        self.check_msg_signed(&signing_root.0, &req.validator_public_key)?;
        info!(
            info="received broadcast attestation",
            validator_public_key=hex::encode(&req.validator_public_key),
        );
        // lighthouse/validator_client/validator_services/src/attestation_service.rs:468
        let slot = attestation.data().slot;
        let committee_index = attestation.data().index;
        let fork_name = self.spec.fork_name_at_slot::<E>(slot);
        // Post the attestations to the BN.
        match self
            .beacon_nodes
            .request(ApiTopic::Attestations, |beacon_node| {
                let a = attestation.clone();
                async move {
                    
                    let single_attestations = match a
                        .to_single_attestation_with_attester_index(req.validator_index)
                        {
                            Ok(s) => s,
                            Err(_) => {
                                return Ok(())
                            }
                        };
                    
                    beacon_node
                    .post_beacon_pool_attestations_v2::<E>(
                        vec![single_attestations],
                        fork_name,
                    )
                    .await
                }
            })
            .await
        {
            Ok(()) => info!(
                info="Successfully published attestations by leader",
                validator_index=req.validator_index,
                committee_index=committee_index,
                slot=slot.as_u64(),
                type="unaggregated",
            ),
            Err(e) => error!(
                error=%e,
                committee_index=committee_index,
                slot=slot.as_u64(),
                type="unaggregated",
                "Unable to publish attestations",
            ),
        }
        Ok(Response::new(EmptyResponse { }))
    }

    async fn broadcast_aggregate_and_proof(
        &self,
        request: Request<BroadcastAggregateAndProofRequest>,
    ) -> Result<Response<EmptyResponse>, Status> {
        let req = request.into_inner();
        let domain_hash = Hash256::from(&req.domain_hash.try_into().unwrap());
        self.check_operator_domain_hash_signature(
            &domain_hash,
            &req.domain_hash_signature,
            req.operator_id,
        )?;
        let aggregate_data = safestake_operator::decompress_data(&req.aggregate_and_proof).unwrap();
        let aggregate_and_proof: SignedAggregateAndProof<E> = match serde_json::from_slice(&aggregate_data) {
            Ok(a) => a,
            Err(_) => {
                return Err(Status::internal(format!(
                    "failed to deserialize aggregate and proof data"
                )));
            }
        };
        let signing_root = aggregate_and_proof.message().signing_root(domain_hash);
        
        self.check_msg_signed(&signing_root.0, &req.validator_public_key)?;
        info!(
            info="received broadcast aggregate and proof",
            validator_public_key = hex::encode(req.validator_public_key),
        );

        let fork_name = self.spec.fork_name_at_slot::<E>(aggregate_and_proof.message().aggregate().data().slot);
        match self.beacon_nodes.first_success(|beacon_node| {
            let aggregate_and_proof = aggregate_and_proof.clone();
            async move {
                if fork_name.electra_enabled() {
                    beacon_node
                        .post_validator_aggregate_and_proof_v2(
                            &vec![aggregate_and_proof],
                            fork_name,
                        )
                        .await
                } else {
                    beacon_node
                        .post_validator_aggregate_and_proof_v1(
                            &vec![aggregate_and_proof],
                        )
                        .await
                }
            }
        }).await
        {
            Ok(()) => {
                let attestation = aggregate_and_proof.message().aggregate();
                info!(
                    info="Successfully published attestation by leader",
                    aggregator=aggregate_and_proof.message().aggregator_index(),
                    head_block=format!("{:?}", attestation.data().beacon_block_root),
                    committee_index=attestation.committee_index(),
                    slot=attestation.data().slot.as_u64(),
                    type="aggregated",
                );
                
            }
            Err(e) => {
                let attestation = &aggregate_and_proof.message().aggregate();
                warn!(
                    error=%e,
                    aggregator=aggregate_and_proof.message().aggregator_index(),
                    head_block=format!("{:?}", attestation.data().beacon_block_root),
                    committee_index=attestation.committee_index(),
                    slot=attestation.data().slot.as_u64(),
                    "Failed to publish attestation by leader",
                );
                
            }
        }
        Ok(Response::new(EmptyResponse { }))
    }

    async fn simple_duty(
        &self,
        request: Request<SimpleDutyRequest>,
    ) -> Result<Response<EmptyResponse>, Status> {
        let req = request.into_inner();
        let validator_public_key = self
            .check_version_and_validator_public_key(req.version, &req.validator_public_key)
            .await?;
        let signing_root = Hash256::from(&req.signing_root.try_into().unwrap());
        self.check_operator_domain_hash_signature(
            &signing_root,
            &req.signing_root_signature,
            req.operator_id,
        )?;

        let sig = self.sign_msg(&validator_public_key, signing_root).await?;
        let serialized_signature = sig.serialize();
        let mut key = signing_root.0.to_vec();
        key.extend_from_slice(&req.validator_public_key);
        self.store
            .put_bytes(
                DBColumn::SafeStake,
                &key,
                &serialized_signature,
            )
            .map_err(|e| Status::internal(format!("failed to save signature {:?}", e)))?;
        Ok(Response::new(EmptyResponse {}))
    }

    async fn broadcast_sync_committee_message(
        &self,
        request: Request<BroadcastSyncCommitteeMessageRequest>,
    ) -> Result<Response<EmptyResponse>, Status> {
        let req = request.into_inner();
        let domain_hash = Hash256::from(&req.domain_hash.try_into().unwrap());
        self.check_operator_domain_hash_signature(
            &domain_hash,
            &req.domain_hash_signature,
            req.operator_id,
        )?;
        
        let sync_committee_message_bytes = safestake_operator::decompress_data(&req.sync_committee_message).unwrap();
        let sync_committee_message: SyncCommitteeMessage = match serde_json::from_slice(&sync_committee_message_bytes) {
            Ok(a) => a,
            Err(_) => {
                return Err(Status::internal(format!(
                    "failed to deserialize sync committee message data"
                )));
            }
        };

        let signing_root = sync_committee_message.beacon_block_root.signing_root(domain_hash);
        self.check_msg_signed(&signing_root.0, &req.validator_public_key)?;
        info!(
            info="received broadcast sync committee message",
            validator_public_key=hex::encode(req.validator_public_key),
        );

        // lighthouse/validator_client/validator_services/src/sync_committee_service.rs:303
        let slot = sync_committee_message.slot;
        let beacon_block_root = sync_committee_message.beacon_block_root;
        self.beacon_nodes
            .request(ApiTopic::SyncCommittee, |beacon_node| {
                let sync_committee_message = sync_committee_message.clone();
                async move {
                    beacon_node
                        .post_beacon_pool_sync_committee_signatures(&vec![sync_committee_message])
                        .await
                }})
                .await
                .map_err(|_| {
                    Status::internal(format!(
                        "Unable to publish sync committee messages by leader"
                    ))
                })?;
        info!(
            info="Successfully published sync committee messages by leader",
            beacon_block_roo=?beacon_block_root,
            slot=?slot,
        );
        Ok(Response::new(EmptyResponse { }))
    }

    async fn broadcast_full_block(
        &self,
        request: Request<BroadcastFullBlockRequest>,
    ) -> Result<Response<EmptyResponse>, Status> {
        let req = request.into_inner();
        let domain_hash = Hash256::from(&req.domain_hash.try_into().unwrap());
        self.check_operator_domain_hash_signature(
            &domain_hash,
            &req.domain_hash_signature,
            req.operator_id,
        )?;

        let block_bytes = safestake_operator::decompress_data(&req.block_data).unwrap();
        let signed_block: SignedBeaconBlock<E, FullPayload<E>> =
        match serde_json::from_slice(&block_bytes) {
            Ok(b) => b,
            Err(_) => {
                return Err(Status::internal(format!(
                    "failed to deserialize propose full block data"
                )));
            }
        };
        let signing_root = signed_block.message().signing_root(domain_hash);
        let slot = signed_block.slot();
        self.check_msg_signed(&signing_root.0, &req.validator_public_key)?;
        info!(
            info="received broadcast full block",
            slot=slot.as_u64(),
            validator_public_key=hex::encode(&req.validator_public_key),
        );
        self.beacon_nodes.request(ApiTopic::Blocks, |beacon_node| {
            let signed_block = signed_block.clone();
            let blobs = req.blobs.clone();
            async move {
                let blobs_bytes = safestake_operator::decompress_data(&blobs).unwrap();
                let maybe_blobs: Option<(KzgProofs<E>, BlobsList<E>)> = serde_json::from_slice(&blobs_bytes).unwrap();
                let request = PublishBlockRequest::new(Arc::new(signed_block), maybe_blobs);
                beacon_node
                    .post_beacon_blocks_v2_ssz(&request, None)
                    .await
                    .or_else(|e| handle_block_post_error(e, slot))
            }   
        }).await.map_err(|_| {
            Status::internal(format!(
                "Unable to publish block by leader"
            ))
        })?;
        info!(
            info="Successfully published full block by leader",
            validator_public_key=hex::encode(&req.validator_public_key),
            slot= signed_block.slot().as_u64(),
        );
        Ok(Response::new(EmptyResponse { }))
    }

    async fn broadcast_blinded_block(
        &self,
        request: Request<BroadcastBlindedBlockRequest>,
    ) -> Result<Response<EmptyResponse>, Status> {
        let req = request.into_inner();
        let domain_hash = Hash256::from(&req.domain_hash.try_into().unwrap());
        self.check_operator_domain_hash_signature(
            &domain_hash,
            &req.domain_hash_signature,
            req.operator_id,
        )?;

        let block_bytes = safestake_operator::decompress_data(&req.block_data).unwrap();
        let signed_block: SignedBeaconBlock<E, BlindedPayload<E>> =
        match serde_json::from_slice(&block_bytes) {
            Ok(b) => b,
            Err(_) => {
                return Err(Status::internal(format!(
                    "failed to deserialize propose full block data"
                )));
            }
        };
        let signing_root = signed_block.message().signing_root(domain_hash);
        let slot = signed_block.slot();
        self.check_msg_signed(&signing_root.0, &req.validator_public_key)?;
        info!(
            info="received broadcast blinded block",
            slot= slot.as_u64(),
            validator_public_key=hex::encode(&req.validator_public_key),
        );
        self.beacon_nodes.request(ApiTopic::Blocks, |beacon_node| {
            let signed_block = signed_block.clone();
            async move {
                beacon_node
                    .post_beacon_blinded_blocks_v2_ssz(&signed_block, None)
                    .await
                    .or_else(|e| handle_block_post_error(e, slot))
            }   
        }).await.map_err(|_| {
            Status::internal(format!(
                "Unable to publish block by leader"
            ))
        })?;
        info!(
            info="Successfully published blinded block by leader",
            validator_public_key=hex::encode(&req.validator_public_key),
            slot=signed_block.slot().as_u64(),
        );
        Ok(Response::new(EmptyResponse { }))
    }
}

fn handle_block_post_error(err: eth2::Error, slot: Slot) -> Result<(), Status> {
    // Handle non-200 success codes.
    if let Some(status) = err.status() {
        if status == eth2::StatusCode::ACCEPTED {
            info!(
                info="Block is already known to BN or might be invalid",
                slot=slot.as_u64(),
                status_code=status.as_u16(),
            );
            return Ok(());
        } else if status.is_success() {
            warn!(
                info="Block published with non-standard success code",
                slot=slot.as_u64(),
                status_code=status.as_u16(),
            );
            return Ok(());
        }
    }
    Err(Status::internal(format!(
        "Error from beacon node when publishing block: {err:?}",
    )))
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