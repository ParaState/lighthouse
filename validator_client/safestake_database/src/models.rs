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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ValidatorOperation {
    Add = 0,
    Remove,
    Disable,
    Enable,
    Restart,
    Unkown
} 

impl TryFrom<u32> for ValidatorOperation {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ValidatorOperation::Add),
            1 => Ok(ValidatorOperation::Remove),
            2 => Ok(ValidatorOperation::Disable),
            3 => Ok(ValidatorOperation::Enable),
            4 => Ok(ValidatorOperation::Restart),
            _ => Ok(ValidatorOperation::Unkown),
        }
    }
}