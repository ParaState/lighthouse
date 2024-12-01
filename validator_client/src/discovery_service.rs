
use crate::Config;
use crate::operator::database::SafeStakeDatabase;
use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use lighthouse_network::discv5::{
    enr::{CombinedKey, Enr, EnrPublicKey, NodeId}, ConfigBuilder, Discv5, Event, ListenConfig
};
use slog::{info, error, Logger};
use dvf_utils::{DEFAULT_BASE_PORT, BOOT_ENRS_CONFIG_FILE};
use std::fs::File;
use std::time::Duration;
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Interval;
use safestake_crypto::secp::PublicKey as SecpPublicKey;
use crate::operator::proto::bootnode_client::BootnodeClient;
use crate::operator::proto::QueryNodeAddressRequest;
use dvf_utils::VERSION;

pub const DISCOVERY_PORT_OFFSET: u16 = 4;
pub const DISCOVER_HEARTBEAT_INTERVAL: u64 = 60 * 5;

#[derive(Clone)]
pub struct DiscoveryService {
    sender: mpsc::Sender<(NodeId, oneshot::Sender<()>)>,
    heartbeats: Arc<RwLock<HashMap<SecpPublicKey, Interval>>>,
    db: SafeStakeDatabase,
    boot_nodes: Vec<SocketAddr>,
    logger: Logger
}

impl DiscoveryService {
    pub async fn new_and_spawn(
        logger: Logger,
        config: Config,
        db: SafeStakeDatabase,
    ) -> Result<Self, String> {
        let seq = match db.with_transaction(|tx| {
            db.query_operator_seq(tx, &config.node_secret.name)
        }) {
            Ok(seq) => {
                seq + 1
            },
            Err(_) => {
                1
            }
        };
        db.with_transaction(|tx| {
            db.upsert_operator_socket_address(tx, &config.node_secret.name, &SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), config.base_port), seq)
        }).map_err(|e| {
            e.to_string()
        })?;
        
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
            .map_err(|e|
                format!(
                    "Unable to open the boot enrs config file: {} {:?}",
                    BOOT_ENRS_CONFIG_FILE, e
                )
            )?;
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
                IpAddr::V4(
                    enr.ip4().expect("boot enr ip should not be empty"),
                ),
                enr.udp4().expect("boot enr port should not be empty"),
            );
            boot_nodes.push(socketaddr);
        });

        let (tx, mut rx) = mpsc::channel::<(NodeId, oneshot::Sender<()>)>(1000);

        let discovery = Self {
            sender: tx,
            heartbeats: <_>::default(),
            db: db.clone(),
            boot_nodes,
            logger: logger.clone()
        };  

        tokio::spawn(async move {
            let _ = discv5.start().await;
            let mut event_stream = discv5.event_stream().await.unwrap();

            loop {
                tokio::select! {
                    Some((node_id, notification)) = rx.recv() => {
                        match discv5.find_node(node_id).await {
                            Ok(v) => {
                                for enr in v {
                                    handle_enr(&db, enr).await;
                                }
                            },
                            Err(e) => {
                                error!(
                                    logger,
                                    "discovery service";
                                    "err" => %e
                                );
                            }
                        }
                        let _ = notification.send(());
                    }
                    Some(event) = event_stream.recv() => {
                        match event {
                            Event::Discovered(enr) => {
                                handle_enr(&db, enr).await;
                            }
                            Event::SessionEstablished(enr, _) => {
                                handle_enr(&db, enr).await;
                            },
                            Event::SocketUpdated(addr) => {
                                info!(
                                    logger, 
                                    "socket address updated";
                                    "address" => %addr
                                );
                            }
                            Event::EnrAdded { .. }
                            | Event::NodeInserted { .. }
                            | Event::TalkRequest(_) => {}, // Ignore all other discv5 server events
                        }
                    }
                }
            }

        });
        // immediately initiate a discover request to annouce ourself
        let random_node_id = NodeId::random();
        discovery.discover(random_node_id).await;

        Ok(discovery)
    }

    async fn discover(&self, node_id: NodeId) {
        let (sender, receiver) = oneshot::channel();
        let _ = self.sender.send((node_id, sender)).await;
        let _ = receiver.await;
    }

    pub async fn query_addrs(&self, pks: &Vec<SecpPublicKey>) -> Vec<Option<SocketAddr>> {
        let mut socket_address: Vec<Option<SocketAddr>> = Default::default();
        for pk in pks {
            socket_address.push(self.query_addr(&pk).await);
        }
        socket_address
    }

    pub async fn query_addr(&self, pk: &SecpPublicKey) -> Option<SocketAddr> {
        let mut heartbeats = self.heartbeats.write().await;
        if !heartbeats.contains_key(&pk) {
            let mut ht = tokio::time::interval(Duration::from_secs(DISCOVER_HEARTBEAT_INTERVAL));
            ht.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            heartbeats.insert(pk.clone(), ht);
        }

        let heartbeat = heartbeats.get_mut(pk).unwrap();
        let ready = std::future::ready(());
        tokio::select! {
            biased; // Poll from top to bottom
            _ = heartbeat.tick() => {
                // Updating IP takes time, so we can release the hashmap lock here.
                drop(heartbeats);
                // only update when heartbeat is ready
                self.update_addr(pk).await
            }
            _ = ready => {
                match self.db.with_transaction(|txn| {
                    self.db.query_operator_socket_address(txn, pk)
                }) {
                    Ok(s) => Some(s),
                    Err(_) => None 
                }
            }
        }
    }

    async fn update_addr(&self, pk: &SecpPublicKey) -> Option<SocketAddr> {
        let node_id = NodeId::parse(&keccak_hash::keccak(pk).0).unwrap();
        self.discover(node_id).await;
        // Randomly pick a boot node
        let boot_idx = rand::random::<usize>() % self.boot_nodes.len();
        self.query_addr_from_boot(boot_idx, pk).await.ok()
    }

    async fn query_addr_from_boot(&self, boot_idx: usize, pk: &SecpPublicKey) -> Result<SocketAddr, String> {
        let addr = self.boot_nodes[boot_idx];
        let mut client = BootnodeClient::connect(format!("http://{}", addr)).await.map_err(|e| e.to_string())?;
        let request = tonic::Request::new(QueryNodeAddressRequest {
            version: VERSION,
            operator_public_key: pk.0.to_vec(),
        });
        match client.query_node_address(request).await {
            Ok(response) => {
                let data: Vec<u8> = response.into_inner().address;
                let addr = bincode::deserialize::<SocketAddr>(&data).unwrap();
                Ok(addr)
            },
            Err(e) => {
                error!(
                    self.logger,
                    "query boot node";
                    "error" => %e
                );
                Err(e.to_string())
            }
        }
    }
}

pub async fn handle_enr(
    db: &SafeStakeDatabase,
    enr: Enr<CombinedKey> 
) {
    let node_public_key: [u8; 33] = enr.public_key().encode().try_into().unwrap();
    let public_key = SecpPublicKey(node_public_key);
    let seq = match db.with_transaction(|txn| {
        db.query_operator_seq(txn, &public_key)
    }) {
        Ok(seq) => seq,
        Err(_) => 0
    };
    if enr.seq() > seq {
        let _ = db.with_transaction(|tx| {
            let ip = enr.ip4().unwrap();
            let port = match enr.udp4() {
                Some(port) => {
                    port.checked_sub(DISCOVERY_PORT_OFFSET).unwrap()
                },
                None => DEFAULT_BASE_PORT
            };
            let socket_address = SocketAddr::new(
                IpAddr::V4(ip), port
            );
            db.upsert_operator_socket_address(tx, &public_key, &socket_address, enr.seq())
        });
    }
    
}