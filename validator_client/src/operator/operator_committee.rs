use std::collections::HashMap;
use crate::operator::TOperator;
use crate::operator::generic_operator_committee::TOperatorCommittee;
use types::{AttestationData, Hash256, PublicKey, Signature};
use crate::operator::RemoteOperator;
use dvf_utils::{DvfError, invalid_addr};
use async_trait::async_trait;
use futures::future::join_all;
use slog::Logger;
use safestake_crypto::{ThresholdSignature, secp::SecretKey};
use account_utils::operator_committee_definitions::OperatorCommitteeDefinition;
use chrono::prelude::{DateTime, Utc};
use crate::operator::report::{DvfPerformanceRequest, request_to_api, SignDigest};
use task_executor::TaskExecutor;
pub struct DvfOperatorCommittee {
    pub node_secret_key: SecretKey,
    pub operator_id: u32,
    pub validator_public_key: PublicKey,
    threshold: usize,
    operators: HashMap<u32, Box<dyn TOperator>>,
    pub log: Logger,
    pub safestake_api: String
}

#[async_trait]
impl TOperatorCommittee for DvfOperatorCommittee {
    fn new(
        node_secret_key: SecretKey,
        operator_id: u32,
        validator_public_key: PublicKey,
        t: usize,
        log: Logger,
        safestake_api: String
    ) -> Self {
        Self {
            node_secret_key,
            operator_id,
            validator_public_key,
            threshold: t,
            operators: <_>::default(),
            log,
            safestake_api
        }
    }

    fn add_operator(&mut self, operator_id: u32, operator: Box<dyn TOperator>) {
        self.operators.insert(operator_id, operator);
    }

    async fn sign(&self, msg: Hash256, local_signature: Signature, executor: &TaskExecutor) -> Result<(Signature, Vec<u64>), DvfError> {
        let signing_futures = self.operators.iter().map(|(op_id, op)| async move {
            op.sign(msg).await.map(|sig| {
                (*op_id, op.shared_public_key(), sig)
            })
        });
        let results = join_all(signing_futures)
            .await
            .into_iter()
            .flatten()
            .collect::<Vec<(u32, PublicKey, Signature)>>();
        let ids = results.iter().map(|x| x.0 as u64).collect::<Vec<u64>>();
        let pks = results.iter().map(|x| x.1.clone()).collect::<Vec<PublicKey>>();
        let sigs = results.iter().map(|x| {
            if x.2 == Signature::empty() {
                local_signature.clone()
            } else {
                x.2.clone()
            }   
        }).collect::<Vec<Signature>>();
        let ids_res = ids.clone();
        let threshold_sig = ThresholdSignature::new(self.threshold);
        let sig = executor.spawn_blocking_handle(
            move || threshold_sig.threshold_aggregate(&sigs, &pks, &ids, msg), "threshold_aggregate"
        ).ok_or(DvfError::ShuttingDown)?.await.map_err(|e| DvfError::TokioJoin(e.to_string()))??;
        Ok((sig, ids_res))
    }

    async fn check_liveness(&self, operator_id: u32) -> bool {
        self.operators.get(&operator_id).unwrap().is_active().await
    }
    async fn attest(&self, attest_data: &AttestationData, domain_hash: Hash256) {
        let attest_futures = self.operators.iter().map(|(_, op)| async move {
            op.attest(attest_data, domain_hash).await
        });
        join_all(attest_futures).await;

    }
    async fn propose_full_block(&self, full_block: &[u8], domain_hash: Hash256) { 
        let propose_futures = self.operators.iter().map(|(_, op)| async move {
            op.propose_full_block(full_block, domain_hash).await
        });
        join_all(propose_futures).await;
    }
    async fn propose_blinded_block(&self, blinded_block: &[u8], domain_hash: Hash256) { 
        let propose_futures = self.operators.iter().map(|(_, op)| async move {
            op.propose_blinded_block(blinded_block, domain_hash).await
        });
        join_all(propose_futures).await;
    }

    fn get_leader_id(&self, nonce: u64) -> u32 {
        let index = nonce % self.operators.len() as u64;
        let mut ids: Vec<u32> = self.operators.keys().map(|k| *k).collect();
        ids.sort();
        ids[index as usize]
    }

    fn get_backup_id(&self, nonce: u64) -> u32 {
        let index = (nonce + 1) % self.operators.len() as u64;
        let mut ids: Vec<u32> = self.operators.keys().map(|k| *k).collect();
        ids.sort();
        ids[index as usize]
    }
}

impl DvfOperatorCommittee {
    pub fn is_leader(&self, nonce: u64) -> bool {
        self.get_leader_id(nonce) == self.operator_id
    }

    pub fn is_backup(&self, nonce: u64) -> bool {
        self.get_backup_id(nonce) == self.operator_id
    }

    pub fn from_definition(node_secret_key: SecretKey, operator_id: u32, def: OperatorCommitteeDefinition, log: Logger, api: String) -> Self {
        let mut committee = Self::new(
            node_secret_key.clone(),
            operator_id,
            def.validator_public_key.clone(),
            def.threshold as usize,
            log.clone(),
            api
        );
        for i in 0..(def.total as usize) {
            let addr = def.base_socket_addresses[i].unwrap_or(invalid_addr());
            let operator = RemoteOperator {
                self_operator_secretkey: node_secret_key.clone(), 
                self_operator_id: operator_id,
                operator_id: def.operator_ids[i],
                base_address: addr,
                validator_public_key: def.validator_public_key.clone(),
                operator_node_pk: def.node_public_keys[i].clone(),
                shared_public_key: def.operator_public_keys[i].clone(),
                logger: log.clone()
            };
            committee
                .add_operator(def.operator_ids[i], Box::new(operator));
        }
        committee
    }

    pub async fn send_performance_report(&self, epoch: u64, slot: u64, duty: &str, validator_pk: String, operator_id: u32, ids: Vec<u64>, start_time: DateTime<Utc>) -> Result<(), String> {
        if duty == "ATTESTER" || duty == "PROPOSER" {
            let mut request_body = DvfPerformanceRequest {
                validator_pk,
                operator_id,
                operators: ids,
                slot: slot,
                epoch: epoch,
                duty: duty.to_string(),
                time: Utc::now().signed_duration_since(start_time).num_milliseconds(),
                sign_hex: None,
            };
            request_body.sign_hex = Some(
                request_body
                    .sign_digest(&self.node_secret_key)?,
            );
            let url_str = format!("{}{}", self.safestake_api, "collect_performance");
            tokio::spawn(async move {
                _ = request_to_api(request_body, &url_str)
                    .await;
            });
        }

        Ok(())
    }
}