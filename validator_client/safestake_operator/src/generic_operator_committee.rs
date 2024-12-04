use crate::TOperator;
use async_trait::async_trait;
use dvf_utils::DvfError;
use safestake_crypto::secp::SecretKey;
use slog::Logger;
use task_executor::TaskExecutor;
use types::{AttestationData, Hash256, PublicKey, Signature};
#[async_trait]
pub trait TOperatorCommittee: Send {
    fn new(
        node_secret_key: SecretKey,
        operator_id: u32,
        validator_public_key: PublicKey,
        t: usize,
        log: Logger,
    ) -> Self;
    fn add_operator(&mut self, operator_id: u32, operator: Box<dyn TOperator>);
    async fn sign(
        &self,
        msg: Hash256,
        local_signature: Signature,
        executor: &TaskExecutor,
    ) -> Result<(Signature, Vec<u64>), DvfError>;
    async fn check_liveness(&self, operator_id: u32) -> bool;
    async fn attest(&self, attest_data: &AttestationData, domain_hash: Hash256);
    async fn propose_full_block(&self, full_block: &[u8], domain_hash: Hash256);
    async fn propose_blinded_block(&self, blinded_block: &[u8], domain_hash: Hash256);
    fn get_leader_id(&self, nonce: u64) -> u32;
    fn get_backup_id(&self, nonce: u64) -> u32;
}
