//! Provides a file format for defining validators that should be initialized by this validator.
//!
//! Serves as the source-of-truth of which validators this validator client should attempt (or not
//! attempt) to load into the `crate::intialized_validators::InitializedValidators` struct.

use crate::validator_definitions::Error;
use crate::write_file_via_temporary;
use safestake_crypto::secp::PublicKey as SecpPublicKey;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::net::SocketAddr;
use std::path::Path;
use types::PublicKey;
/// The file name for the serialized `OperatorCommitteeDefinition` struct.
pub const OPERATOR_COMMITTEE_DEFINITION_FILENAME: &str = "operator_committee_definition.yml";

/// The temporary file name for the serialized `OperatorCommitteeDefinition` struct.
///
/// This is used to achieve an atomic update of the contents on disk, without truncation.
/// See: https://github.com/sigp/lighthouse/issues/2159
pub const OPERATOR_COMMITTEE_DEFINITION_TEMP_FILENAME: &str =
    ".operator_committee_definition.yml.tmp";

/// A validator that may be initialized by this validator client.
///
/// Presently there is only a single variant, however we expect more variants to arise (e.g.,
/// remote signing).
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct OperatorCommitteeDefinition {
    pub total: u64,
    pub threshold: u64,
    pub validator_id: u64,
    pub validator_public_key: PublicKey,
    pub operator_ids: Vec<u64>,
    pub operator_public_keys: Vec<PublicKey>,
    pub node_public_keys: Vec<SecpPublicKey>,
    pub base_socket_addresses: Vec<Option<SocketAddr>>,
}

impl OperatorCommitteeDefinition {
    /// Instantiates `self` by reading a file at `path`.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let file = File::options()
            .read(true)
            .write(false)
            .create(false)
            .open(path)
            .map_err(Error::UnableToOpenFile)?;
        serde_yaml::from_reader(file).map_err(Error::UnableToParseFile)
    }

    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        let file = File::options()
            .write(true)
            .read(true)
            .create_new(true)
            .open(path)
            .map_err(Error::UnableToOpenFile)?;
        serde_yaml::to_writer(file, self).map_err(Error::UnableToEncodeFile)
    }

    /// Encodes `self` as a YAML string and atomically writes it out to disk.
    ///
    /// Will create a new file if it does not exist or overwrite any existing file.
    pub fn save<P: AsRef<Path>>(&self, committee_def_dir: P) -> Result<(), Error> {
        let config_path = committee_def_dir
            .as_ref()
            .join(OPERATOR_COMMITTEE_DEFINITION_FILENAME);
        let temp_path = committee_def_dir
            .as_ref()
            .join(OPERATOR_COMMITTEE_DEFINITION_TEMP_FILENAME);
        let bytes = serde_yaml::to_string(self).map_err(Error::UnableToEncodeFile)?;

        write_file_via_temporary(&config_path, &temp_path, bytes.as_bytes())
            .map_err(Error::UnableToWriteFile)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_committee_checks() {
        let oc_str = r#"---
            total: 4
            threshold: 3
            validator_id: 6161405031639792275
            validator_public_key: "0x93ba31543bb58155f379970aeaffd0211c25668caea7c2bed4582fe5a84caa45d9406136be574a7e64477998eb5cfbf3"
            operator_ids:
            - 1
            - 3
            - 4
            - 5
            operator_public_keys:
            - "0x931ce1e9e9e14b80a198a5eeb8539f1a173d03a9c5d38524810111af0f4101258298245f2d9213b956679a177f44a899"
            - "0x9463f2ef44b76036bf5f55b55cac896f4bc88164e7c9a04c58adbf6f3647863ce3c4c670b2c71a9da4ff460c705828f6"
            - "0xb0c9c7483ec4deca7dbea0279e6a98516707ab303165085fd7fb3d40257f246e487f32412daa94073b14c8f3f33961b7"
            - "0x898064041ca0d0ae43342ddf8d7d02eca5953ffd5f7ac9d7b0da305d569fe03099a2b48ef8faa0f383ee6689b7a09d3a"
            node_public_keys:
            - AgrzJyU1v8vG+KTphzaWmlFnh395S0GofSoj51gp6z4k
            - A5DTEz2MFETa1ZJpuQ0ZeLLnMy7Bp92kLak+ORWtyNZV
            - AzoBJv47MBMEIk9ICWwZ6NpogLKuaPvTzfAfgn+lpNC1
            - A3JgIvGBKbS3gmHT39RfJq0A6B1zO1bEaeWFSHdfQnZl
            base_socket_addresses:
            - "127.0.0.1:26000"
            - "18.136.181.226:26000"
            - "13.215.100.234:26000"
            - "18.143.137.23:26000"
        "#;
        let def: OperatorCommitteeDefinition = serde_yaml::from_str(oc_str).unwrap();
        assert_eq!(def.total, 4);
        assert_eq!(def.threshold, 3);
    }
}
