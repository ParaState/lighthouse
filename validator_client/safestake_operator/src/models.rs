use alloy_primitives::Address;
use bls::PublicKey;
use safestake_crypto::secp::PublicKey as SecpPublicKey;
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug)]
pub struct Operator {
    pub id: u32,
    pub name: String,
    pub owner: Address,
    pub public_key: SecpPublicKey,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Validator {
    pub owner: Address,
    pub public_key: PublicKey,
    pub releated_operators: Vec<u32>,
    pub active: bool,
    pub registration_timestamp: u64,
}
