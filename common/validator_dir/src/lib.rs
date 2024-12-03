//! Provides:
//!
//! - `ValidatorDir`: manages a directory containing validator keypairs, deposit info and other
//!   things.
//!
//! This crate is intended to be used by the account manager to create validators and the validator
//! client to load those validators.

mod builder;
pub mod insecure_keys;
mod share_builder;
mod validator_dir;

pub use crate::validator_dir::{
    unlock_keypair_from_password_path, Error, Eth1DepositData, ValidatorDir,
    ETH1_DEPOSIT_TX_HASH_FILE,
};
pub use builder::{
    keystore_password_path, write_password_to_file, Builder, Error as BuilderError,
    ETH1_DEPOSIT_DATA_FILE, VOTING_KEYSTORE_FILE, WITHDRAWAL_KEYSTORE_FILE,
};
pub use share_builder::default_keystore_share_path;
pub use share_builder::ShareBuilder;
pub use share_builder::VOTING_KEYSTORE_SHARE_FILE;
