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

pub const DISCOVERY_PORT_OFFSET: u16 = 4;

#[derive(Clone)]
pub struct DiscoveryService {}

impl DiscoveryService {
    pub async fn spawn(
        logger: Logger,
        config: Config,
        db: SafeStakeDatabase,
        executor: &TaskExecutor,
    ) -> Result<mpsc::Sender<(SecpPublicKey, oneshot::Sender<Option<SocketAddr>>)>, String> {
        let seq =
            match db.with_transaction(|tx| db.query_operator_seq(tx, &config.node_secret.name)) {
                Ok(seq) => seq + 1,
                Err(_) => 1,
            };
        db.with_transaction(|tx| {
            db.upsert_operator_socket_address(
                tx,
                &config.node_secret.name,
                &SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), config.base_port),
                seq,
            )
        })
        .map_err(|e| e.to_string())?;

        let discovery_port = config.base_port.checked_add(DISCOVERY_PORT_OFFSET).unwrap();
        let mut secret_key = config.node_secret.secret.0.to_vec();
        let enr_key = CombinedKey::secp256k1_from_bytes(&mut secret_key[..]).unwrap();

        let local_enr = {
            let mut builder = Enr::builder();
            builder.ip(config.ip);
            if config.base_port != DEFAULT_BASE_PORT {
                builder.udp4(discovery_port);
            }
            builder.seq(seq);
            builder.build(&enr_key).unwrap()
        };

        info!(
            logger,
            "discovery service";
            "ip" => %config.ip,
            "base_port" => config.base_port,
            "public key" => %config.node_secret.name,
            "enr" => local_enr.to_base64()
        );

        let discv_config = ConfigBuilder::new(ListenConfig::Ipv4 {
            ip: "0.0.0.0".parse().unwrap(),
            port: discovery_port,
        })
        .build();

        let mut discv5: Discv5 = Discv5::new(local_enr.clone(), enr_key, discv_config).unwrap();

        let file = File::options()
            .read(true)
            .write(false)
            .create(false)
            .open(BOOT_ENRS_CONFIG_FILE)
            .map_err(|e| {
                format!(
                    "Unable to open the boot enrs config file: {} {:?}",
                    BOOT_ENRS_CONFIG_FILE, e
                )
            })?;
        let boot_enrs: Vec<Enr<CombinedKey>> =
            serde_yaml::from_reader(file).expect("Unable to parse boot enr");
        let mut boot_nodes = vec![];
        boot_enrs.iter().for_each(|enr| {
            discv5.add_enr(enr.clone()).unwrap();
            info!(
                logger,
                "discovery service";
                "boot enr" => enr.to_base64()
            );
            let socketaddr = SocketAddr::new(
                IpAddr::V4(enr.ip4().expect("boot enr ip should not be empty")),
                enr.udp4().expect("boot enr port should not be empty"),
            );
            boot_nodes.push(socketaddr);
        });

        let (query_tx, mut query_rx) =
            mpsc::channel::<(SecpPublicKey, oneshot::Sender<Option<SocketAddr>>)>(1000);

        let self_public_key = config.node_secret.name.clone();
        let discv5_fut = async move {
            let _ = discv5.start().await;
            let mut event_stream = discv5.event_stream().await.unwrap();
            let random_node_id = NodeId::random();
            discv5
                .find_node(random_node_id)
                .await
                .unwrap()
                .into_iter()
                .for_each(|enr| handle_enr(&self_public_key, &db, enr));
            loop {
                tokio::select! {
                    Some((node_public_key, notification)) = query_rx.recv() => {
                        let boot_idx = rand::random::<usize>() % boot_nodes.len();
                        let addr = boot_nodes[boot_idx];
                        let mut client = match BootnodeClient::connect(format!("http://{}", addr)).await {
                            Ok(c) => c,
                            Err(e) => {
                                error!(
                                    logger,
                                    "query_boot";
                                    "error" => %e
                                );
                                notification.send(None).unwrap();
                                continue;
                            }
                        };
                        let request = tonic::Request::new(QueryNodeAddressRequest {
                            version: VERSION,
                            operator_public_key: node_public_key.0.to_vec(),
                        });
                        match client.query_node_address(request).await {
                            Ok(response) => {
                                let res = response.into_inner();
                                let addr = bincode::deserialize::<SocketAddr>(&res.address).unwrap();
                                let _ = db.with_transaction(|tx| {
                                    db.upsert_operator_socket_address(tx, &node_public_key, &addr, res.seq)
                                });
                                notification.send(Some(addr)).unwrap()
                            },
                            Err(e) => {
                                error!(
                                    logger,
                                    "query boot node";
                                    "error" => %e
                                );
                                notification.send(None).unwrap()
                            }
                        }
                    }
                    Some(event) = event_stream.recv() => {
                        match event {
                            Event::Discovered(_) => {
                                // handle_enr(&self_public_key, &db, enr);
                            }
                            Event::SessionEstablished(enr, _) => {
                                handle_enr(&self_public_key, &db, enr);
                            },
                            Event::SocketUpdated(addr) => {
                                info!(
                                    logger,
                                    "socket address updated";
                                    "address" => %addr
                                );
                            }
                            Event::NodeInserted { .. }
                            | Event::TalkRequest(_) => {},
                            Event::UnverifiableEnr { .. } => { },
                            _ => {}// Ignore all other discv5 server events
                        }
                    }
                }
            }
        };
        executor.spawn(discv5_fut, "discv5");

        Ok(query_tx)
    }

    pub fn spawn_operator_monitor(
        logger: Logger,
        validator_dir: PathBuf,
        db: SafeStakeDatabase,
        sender: mpsc::Sender<(SecpPublicKey, oneshot::Sender<Option<SocketAddr>>)>,
        executor: &TaskExecutor,
        self_operator_id: u32, 
        http_port: u16,
        operator_channels: Arc<RwLock<HashMap<u32, Vec<Channel>>>>
    ) {
        let mut query_interval = tokio::time::interval(Duration::from_secs(60 * 30));
        executor.spawn(
            async move {
                let api_secret = ApiSecret::create_or_open(&validator_dir.join("api-token.txt")).unwrap();
                let url = SensitiveUrl::parse(&format!("http://127.0.0.1:{}", http_port)).unwrap();
                let api_pubkey = api_secret.api_token();
                let client = ValidatorClientHttpClient::new(url.clone(), api_pubkey).unwrap();
                loop {
                    query_interval.tick().await;

                    let validator_public_keys = db
                        .with_transaction(|tx| db.query_all_validators(tx))
                        .unwrap();

                    for validator_public_key in &validator_public_keys {
                        let committee_def_path = default_operator_committee_definition_path(
                            validator_public_key,
                            validator_dir.clone(),
                        );
                        let mut committee_def =
                            match OperatorCommitteeDefinition::from_file(&committee_def_path) {
                                Ok(def) => def,
                                Err(_) => continue
                            };
                        let mut restart = false;
                        for i in 0..committee_def.total as usize {
                            if committee_def.operator_ids[i] == self_operator_id {
                                continue;
                            }
                            if !remote_op_is_active(&logger, committee_def.operator_ids[i], &committee_def.base_socket_addresses[i], &committee_def.node_public_keys[i], &committee_def.validator_public_key, &operator_channels).await {
                                let (tx, rx) = oneshot::channel();
                                sender.send((committee_def.node_public_keys[i].clone(), tx))
                                .await
                                .unwrap();

                                let queried_addr = rx.await.unwrap();
                                if queried_addr.is_none() {
                                    continue;
                                }
                                if committee_def.base_socket_addresses[i] != queried_addr {
                                    info!(
                                        logger,
                                        "opertor ip changed";
                                        "current" => format!("{:?}", committee_def.base_socket_addresses[i]),
                                        "queried" => queried_addr
                                    );
                                    committee_def.base_socket_addresses[i] = queried_addr;
                                    restart = true;
                                    if let Some(addr) = queried_addr {
                                        let mut c = vec![];
                                        for _i in 0..CHANNEL_SIZE {
                                            c.push(Endpoint::from_shared(format!("http://{}", addr.to_string()))
                                            .unwrap()
                                            .connect_lazy());
                                        }
                                        operator_channels.write().insert(committee_def.operator_ids[i], c);
                                    }
                                }
                            }
                        }
                        if restart {
                            let _ = committee_def.save(committee_def_path.parent().unwrap());
                            // restart validator
                            match client
                                .post_validators_disable(&validator_public_key.compress())
                                .await
                            {
                                Ok(()) => {}
                                Err(e) => {
                                    error!(
                                        logger,
                                        "failed to disable validator";
                                        "validator public key" => %validator_public_key,
                                        "error" => %e
                                    )
                                }
                            }
                            tokio::time::sleep(Duration::from_secs(3)).await;
                            match client
                                .post_validators_enable(&validator_public_key.compress())
                                .await
                            {
                                Ok(()) => {}
                                Err(e) => {
                                    error!(
                                        logger,
                                        "failed to enable validator";
                                        "validator public key" => %validator_public_key,
                                        "error" => %e
                                    )
                                }
                            }
                        }
                    }
                }
            },
            "operator_address_monitor",
        );
    }
}

pub fn handle_enr(self_public_key: &SecpPublicKey, db: &SafeStakeDatabase, enr: Enr<CombinedKey>) {
    let node_public_key: [u8; 33] = enr.public_key().encode().try_into().unwrap();
    let public_key = SecpPublicKey(node_public_key);
    if public_key == *self_public_key {
        // ignore self operator, the address of self operator in database is always 127.0.0.1:26000
        return;
    }
    let seq = match db.with_transaction(|txn| db.query_operator_seq(txn, &public_key)) {
        Ok(seq) => seq,
        Err(_) => 0,
    };
    if enr.seq() > seq {
        let _ = db.with_transaction(|tx| {
            if let Some(ip) = enr.ip4() {
                let port = match enr.udp4() {
                    Some(port) => port.checked_sub(DISCOVERY_PORT_OFFSET).unwrap(),
                    None => DEFAULT_BASE_PORT,
                };
                let socket_address = SocketAddr::new(IpAddr::V4(ip), port);
                db.upsert_operator_socket_address(tx, &public_key, &socket_address, enr.seq())
            } else {
                Ok(())
            }
        });
    }
}

async fn remote_op_is_active(logger: &Logger, operator_id: u32, addr: &Option<SocketAddr>, node_public_key: &SecpPublicKey, validator_public_key: &PublicKey, operator_channels: &Arc<RwLock<HashMap<u32, Vec<Channel>>>>) -> bool {
    if addr.is_none() {
        return false;
    }
    let channel = match operator_channels.read().get(&operator_id) {
        None => Endpoint::from_shared(format!("http://{}", addr.unwrap().to_string())).unwrap()
        .connect_lazy(),
        Some(c) => {
            let mut rng = rand::thread_rng();
            let random_index  = rng.next_u64() as usize % CHANNEL_SIZE;
            c[random_index].clone()
        }
    };
    let mut client = SafestakeClient::new(channel);
    let random_hash = Hash256::random();
    let request = tonic::Request::new(CheckLivenessRequest {
        version: VERSION,
        msg: random_hash.0.to_vec(),
        validator_public_key: validator_public_key.serialize().to_vec(),
    });
    match timeout(std::time::Duration::from_millis(800), client.check_liveness(request)).await {
        Ok(Ok(response)) => {
            match bincode::deserialize::<SecpSignature>(&response.into_inner().signature) {
                Ok(sig) => {
                    match sig.verify(&Digest::from(&random_hash.0), &node_public_key) {
                        Ok(_) => {
                            info!(
                                logger,
                                "discovery operator liveness";
                                "operator" => operator_id
                            );
                            return true;
                        }
                        Err(_) => {}
                    }
                }
                Err(_) => {}
            }
        }
        Ok(Err(e)) => {
            error!(
                logger,
                "discovery operator liveness error";
                "error" => %e
            );
        }
        Err(_) => {
            error!(
                logger,
                "discovery operator liveness timeout";
                "operator" => operator_id,
                "socket address" => addr
            );
        }
    }
    false
}

#[tokio::test]
async fn test_query_boot() {
    use base64::prelude::*;
    let request = tonic::Request::new(QueryNodeAddressRequest {
        version: VERSION,
        operator_public_key: BASE64_STANDARD.decode("A5DTEz2MFETa1ZJpuQ0ZeLLnMy7Bp92kLak+ORWtyNZV").unwrap(),
    });
    let mut client = BootnodeClient::connect(format!("http://18.141.189.105:9005")).await.unwrap();
    match client.query_node_address(request).await {
        Ok(response) => {
            let res = response.into_inner();
            let addr = bincode::deserialize::<SocketAddr>(&res.address).unwrap();
            
            println!("{:?}", addr);
        },
        Err(e) => {
            panic!("{}", e);
        }
    }
}

#[tokio::test]
async fn test_parse_enr() { 
    use base64::prelude::*;
    let enr = "enr:-IS4QCQaienDvEyWvFY9-wkj55spRowzzp-so55JRefrrTAeAbQ3Lr7fl9_k5ScRQBxeozZ1qZRLJkQpZGOLLNd3q6QBgmlkgnY0gmlwhBKNvWmJc2VjcDI1NmsxoQL4ns4R7bHwiMB7LId7Kc7KCbScmVhDxcROOxpUHVnz8oN1ZHCCIy0";

    let boot_enrs: Enr<CombinedKey> = serde_yaml::from_str(enr).unwrap();
    println!("{:?} {:?} {:?} ",boot_enrs.ip4(), boot_enrs.tcp4(), BASE64_STANDARD.encode(boot_enrs.public_key().encode()));
}