use directory::{
    DEFAULT_HARDCODED_NETWORK, DEFAULT_ROOT_DIR, DEFAULT_SECRET_DIR, DEFAULT_VALIDATOR_DIR,
};
use dvf_utils::{DEFAULT_BASE_PORT, DVF_CONTRACT_BLOCK_PATH, DVF_STORE_PATH, ROOT_VERSION};
use safestake_crypto::secret::Secret;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

/// Stores the core configuration for this validator instance.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub operator_id: u32,
    pub safestake_api: String,
    pub node_secret: Secret,
    pub store_path: PathBuf,
    pub contract_record_path: PathBuf,
    pub network_contract: String,
    pub registry_contract: String,
    pub config_contract: String,
    pub cluster_contract: String,
    pub rpc_url: String,
    pub ip: IpAddr,
    pub base_port: u16,
    pub validator_dir: PathBuf,
    pub secrets_dir: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        let base_dir = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(DEFAULT_ROOT_DIR)
            .join(format!("v{}", ROOT_VERSION))
            .join(DEFAULT_HARDCODED_NETWORK);
        let validator_dir = base_dir.join(DEFAULT_VALIDATOR_DIR);
        let secrets_dir = base_dir.join(DEFAULT_SECRET_DIR);
        let store_path = base_dir.join(DVF_STORE_PATH);
        let contract_record_path = base_dir.join(DVF_CONTRACT_BLOCK_PATH);
        Config {
            operator_id: 0,
            safestake_api: String::new(),
            node_secret: Secret::new(),
            store_path,
            contract_record_path,
            network_contract: String::new(),
            registry_contract: String::new(),
            config_contract: String::new(),
            cluster_contract: String::new(),
            rpc_url: String::new(),
            ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            base_port: DEFAULT_BASE_PORT,
            validator_dir: validator_dir,
            secrets_dir: secrets_dir,
        }
    }
}
