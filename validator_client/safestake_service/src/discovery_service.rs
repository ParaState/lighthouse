use crate::config::Config;
use account_utils::{
    default_operator_committee_definition_path,
    operator_committee_definitions::OperatorCommitteeDefinition,
};
use dvf_utils::VERSION;
use dvf_utils::{BOOT_ENRS_CONFIG_FILE, DEFAULT_BASE_PORT};
use lighthouse_network::discv5::{
    enr::{CombinedKey, Enr, EnrPublicKey, NodeId},
    ConfigBuilder, Discv5, Event, ListenConfig,
};
use safestake_crypto::secp::PublicKey as SecpPublicKey;
use safestake_database::{SafeStakeDatabase, models::ValidatorOperation};
use safestake_operator::proto::bootnode_client::BootnodeClient;
use safestake_operator::proto::QueryNodeAddressRequest;
use slog::{error, info, Logger};
use std::collections::HashMap;
use std::fs::File;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;
use task_executor::TaskExecutor;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Interval;

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
            let mut heartbeats: HashMap<SecpPublicKey, Interval> = HashMap::new();
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
                        if !heartbeats.contains_key(&node_public_key) {
                            let mut ht = tokio::time::interval(Duration::from_secs(60 * 10));
                            ht.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                            heartbeats.insert(node_public_key.clone(), ht);
                        }
                        let heartbeat = heartbeats.get_mut(&node_public_key).unwrap();
                        let ready = std::future::ready(());
                        tokio::select! {
                            biased; // Poll from top to bottom
                            _ = heartbeat.tick() => {
                                let node_id = NodeId::parse(&keccak_hash::keccak(&node_public_key).0).unwrap();
                                // discover
                                match discv5.find_node(node_id).await {
                                    Ok(v) => v.into_iter().for_each(|enr| handle_enr(&self_public_key, &db, enr)),
                                    Err(e) => {
                                        error!(
                                            logger,
                                            "discovery service";
                                            "err" => %e
                                        );
                                    }
                                }
                                // query from boot
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
                            _ = ready => {
                                let addr = match db.with_transaction(|txn| {
                                    db.query_operator_socket_address(txn, &node_public_key)
                                }) {
                                    Ok(s) => Some(s),
                                    Err(_) => None
                                };
                                notification.send(addr).unwrap()
                            }
                        };
                    }
                    Some(event) = event_stream.recv() => {
                        match event {
                            Event::Discovered(enr) => {
                                handle_enr(&self_public_key, &db, enr);
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
                            _ => todo!() // Ignore all other discv5 server events
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
    ) {
        let mut query_interval = tokio::time::interval(Duration::from_secs(60 * 30));
        executor.spawn(async move {
            loop {
                query_interval.tick().await;

                let validator_public_keys = db.with_transaction(|tx| {
                    db.query_all_validators(tx)
                }).unwrap();

                for validator_public_key in &validator_public_keys {
                    let committee_def_path = default_operator_committee_definition_path(validator_public_key, validator_dir.clone());
                    let mut committee_def = OperatorCommitteeDefinition::from_file(&committee_def_path).unwrap();
                    let mut restart = false;
                    for i in 0..committee_def.total as usize {
                        let (tx, rx) = oneshot::channel();
                        sender.send((committee_def.node_public_keys[i].clone(), tx)).await.unwrap();
                        if let Some(addr) = rx.await.unwrap() {
                            if let Some(current) = committee_def.base_socket_addresses[i].as_mut() {
                                if *current != addr {
                                   info!(
                                        logger,
                                        "opertor_ip_changed";
                                        "local" => %current,
                                        "queried" => addr
                                   );
                                   *current = addr;
                                   restart = true;
                                }
                            } else {
                                committee_def.base_socket_addresses[i] = Some(addr);
                                restart = true;
                            }
                        }
                    }
                    if restart {
                        let _ = committee_def.save(committee_def_path.parent().unwrap());
                        // restart validator
                        if let Err(e) = db.with_transaction(|tx| {
                            db.insert_validator_operation(tx, &validator_public_key, ValidatorOperation::Restart)
                        }) {
                            error!(
                                logger,
                                "validator operation: remove";
                                "error" => %e
                            );
                        }
                    }

                }
            }
        }, "operator_address_monitor");
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
            let ip = enr.ip4().unwrap();
            let port = match enr.udp4() {
                Some(port) => port.checked_sub(DISCOVERY_PORT_OFFSET).unwrap(),
                None => DEFAULT_BASE_PORT,
            };
            let socket_address = SocketAddr::new(IpAddr::V4(ip), port);
            db.upsert_operator_socket_address(tx, &public_key, &socket_address, enr.seq())
        });
    }
}
