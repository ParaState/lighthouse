pub mod generic_operator_committee;
pub mod operator_committee;
pub mod report;
pub mod database;
pub mod models;
use bls::Error as BlsError;
use std::net::SocketAddr;
use types::{AttestationData, BeaconBlock, BlindedPayload, EthSpec, FullPayload, PublicKey};
use async_trait::async_trait;
use types::{Hash256, Keypair, Signature};
use safestake_crypto::secp::PublicKey as SecpPublicKey;
use tokio::sync::OnceCell;
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::collections::HashSet;

pub static OPERATOR_ID: OnceCell<u64> = OnceCell::const_new();

lazy_static! {
    pub static ref THRESHOLD_MAP: HashMap<u64, u64> = {
        let mut threshold_map = HashMap::new();
        threshold_map.insert(4, 3);
        threshold_map.insert(7, 5);
        threshold_map
    };
}

#[derive(Clone, Debug, PartialEq)]
pub enum DvfError {
    BlsError(BlsError),
    /// Key generation failed.
    KeyGenError(String),
    /// Threshold signature aggregation failed due to insufficient valid signatures.
    InsufficientSignatures {
        got: usize,
        expected: usize,
    },
    /// Invalid signature from operator {id}
    InvalidSignatureShare {
        id: u64,
    },
    /// Size mis match
    SizeMisMatch {
        x: usize,
        y: usize,
    },
    /// Should not call the function specified by the string
    UnexpectedCall(String),
    /// Error propogated from Store
    StoreError(String),
    /// Vss share verification
    VssShareVerificationFailed,
    /// Dispute claim
    InvalidDkgShare(Vec<(u64, u64)>),
    /// Commitment
    CommitmentVerificationFailed,
    /// Zero knowledge proof
    ZKProofInvalidInput,
    /// Zero knowledge proof verification
    ZKVerificationFailed,
    InsufficientValidPks,
}


#[async_trait]
pub trait TOperator: Sync + Send {
    fn id(&self) -> u32;
    async fn sign(&self, msg: Hash256) -> Result<Signature, DvfError>;
    async fn is_active(&self) -> bool;
    async fn attest(&self, attest_data: &AttestationData);
    async fn propose_full_block(&self, full_block: &[u8]);
    async fn propose_blinded_block(&self, blinded_block: &[u8]);
    fn shared_public_key(&self) -> PublicKey;
}

pub struct LocalOperator {
    pub operator_id: u32,
    pub operator_keypair: Keypair,
}

#[async_trait]
impl TOperator for LocalOperator {
    async fn sign(&self, msg: Hash256) -> Result<Signature, DvfError> {
        Ok(self.operator_keypair.sk.sign(msg))
    }

    async fn is_active(&self) -> bool {
        true
    }

    async fn attest(&self, attest_data: &AttestationData) { }

    async fn propose_full_block(&self, full_block: &[u8]) { }

    async fn propose_blinded_block(&self, blinded_block: &[u8]) { }

    fn id(&self) -> u32 {
        self.operator_id
    }

    fn shared_public_key(&self) -> PublicKey {
        self.operator_keypair.pk.clone()
    }
}

pub struct RemoteOperator {
    pub operator_id: u32,
    pub base_address: SocketAddr,
    pub operator_node_pk: SecpPublicKey,
    pub shared_public_key: PublicKey
}

#[async_trait]
impl TOperator for RemoteOperator {
    async fn sign(&self, msg: Hash256) -> Result<Signature, DvfError> {
        todo!()
    }

    async fn is_active(&self) -> bool {
        true
    }

    async fn attest(&self, attest_data: &AttestationData) { }

    async fn propose_full_block(&self, full_block: &[u8]) { }

    async fn propose_blinded_block(&self, blinded_block: &[u8]) { }

    fn id(&self) -> u32 {
        self.operator_id
    }

    fn shared_public_key(&self) -> PublicKey {
        self.shared_public_key.clone()
    }
}