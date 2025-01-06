use crate::config::Config;
use account_utils::{
    default_operator_committee_definition_path,
    operator_committee_definitions::OperatorCommitteeDefinition,
};
use bls::PublicKey;
use dvf_utils::VERSION;
use dvf_utils::{BOOT_ENRS_CONFIG_FILE, DEFAULT_BASE_PORT};
use eth2::lighthouse_vc::http_client::ValidatorClientHttpClient;
use lighthouse_network::discv5::{
    enr::{CombinedKey, Enr, EnrPublicKey, NodeId},
    ConfigBuilder, Discv5, Event, ListenConfig,
};
use rand::RngCore;
use safestake_database::SafeStakeDatabase;
use safestake_operator::proto::bootnode_client::BootnodeClient;
use safestake_operator::proto::QueryNodeAddressRequest;
use safestake_operator::CHANNEL_SIZE;
use sensitive_url::SensitiveUrl;
use slog::{error, info, Logger};
use std::fs::File;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;
use task_executor::TaskExecutor;
use tokio::sync::{mpsc, oneshot};
use validator_http_api::ApiSecret;
use tonic::transport::Endpoint;
use safestake_operator::proto::CheckLivenessRequest;
use safestake_operator::proto::safestake_client::SafestakeClient;
use types::Hash256;
use tokio::time::timeout;
use safestake_crypto::secp::{
    Digest, PublicKey as SecpPublicKey, Signature as SecpSignature,
};
use std::sync::Arc;
use std::collections::HashMap;
use parking_lot::RwLock;
use tonic::transport::Channel;

#[derive(Clone)]
pub struct LivenessService {}

impl LivenessService {
    pub async fn spawn(
        logger: Logger,
        config: Config,
        operator_channels: Arc<RwLock<HashMap<u32, Vec<Channel>>>>,
        operator_liveness: Arc<RwLock<HashMap<u32, bool>>>,
        executor: &TaskExecutor,
    ) -> Result<mpsc::Sender<(u32, oneshot::Sender<bool>)>, String> {
        let (query_tx, mut query_rx) =
            mpsc::channel::<(u32, oneshot::Sender<bool>)>(1000);
        let liveness_fut = async move {
            loop {
                tokio::select! {
                    Some((operator_id, notification)) = query_rx.recv() => {
                        notification.send(*operator_liveness.read().get(&operator_id).unwrap()).unwrap();
                    }
                }
            }
        };
        executor.spawn(liveness_fut, "operator liveness");
        Ok(query_tx)
    }
}

pub async fn spawn_operator_liveness(
    operator_channels: Arc<RwLock<HashMap<u32, Vec<Channel>>>>,
    executor: &TaskExecutor
) -> Result<RwLock<HashMap<u32, bool>>, String> {
    let channels = operator_channels.read();
    let mut operator_liveness = HashMap::new();

       


    Err(String::new())
}