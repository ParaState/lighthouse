use bls::Error as BlsError;
use std::net::{SocketAddr, IpAddr, Ipv4Addr};

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

/// Up to 1 million
/// !NOTE: Don't change this unless you know want you are doing. We relate this to the database storage path of dvf.
/// Changing this might essentially have the effect of cleaning all data.
pub const ROOT_VERSION: u64 = 1;
/// Up to 1 million
pub const MAJOR_VERSION: u64 = 3;
/// Up to 1 million
pub const MINOR_VERSION: u64 = 4;

pub static VERSION: u64 = ROOT_VERSION * 1_000_000_000_000 + MAJOR_VERSION * 1_000_000 + MINOR_VERSION;

pub const SOFTWARE_MINOR_VERSION: u64 = 5;
pub static SOFTWARE_VERSION: u64 = ROOT_VERSION * 1_000_000_000_000 + MAJOR_VERSION * 1_000_000 + SOFTWARE_MINOR_VERSION;

pub static DVF_STORE_PATH: &str = "dvf_store";
pub static DVF_NODE_SECRET_PATH: &str = "node_key.json";
pub static DVF_NODE_SECRET_HEX_PATH: &str = "node_key_hex.json";
pub static DVF_CONTRACT_BLOCK_PATH: &str = "contract_record.yml";
pub fn invalid_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0)
}