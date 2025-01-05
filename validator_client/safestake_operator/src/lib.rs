pub mod generic_operator_committee;
pub mod operator_committee;
pub mod proto;
pub mod report;

use crate::proto::safestake_client::SafestakeClient;
use crate::proto::*;
use async_trait::async_trait;
use bls::Error as BlsError;
use dvf_utils::VERSION;
use lazy_static::lazy_static;
use safestake_crypto::secp::{
    Digest, PublicKey as SecpPublicKey, SecretKey as SecpSecretKey, Signature as SecpSignature,
};
use slog::{error, info, Logger};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::thread::sleep;
use std::time::Duration;
use tokio::sync::OnceCell;
use tokio::time::timeout;
use tonic::transport::Channel;
use types::{graffiti::GraffitiString, AttestationData, PublicKey};
use types::{Hash256, Signature};

pub const CHANNEL_SIZE: usize = 32;

lazy_static! {
    pub static ref THRESHOLD_MAP: HashMap<u64, u64> = {
        let mut threshold_map = HashMap::new();
        threshold_map.insert(4, 3);
        threshold_map.insert(7, 5);
        threshold_map
    };
    pub static ref SafeStakeGraffiti: GraffitiString =
        GraffitiString::from_str("SafeStake Operator").unwrap();
}

pub static NODE_SECRET: OnceCell<SecpSecretKey> = OnceCell::const_new();
pub static SAFESTAKE_API: OnceCell<String> = OnceCell::const_new();
pub static RPC_REQUEST_TIMEOUT: Duration = Duration::from_millis(1200);
#[derive(Clone, Debug, PartialEq)]
pub enum DvfError {
    SignatureNotFound(String),
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

#[async_trait]
pub trait TOperator: Sync + Send {
    fn id(&self) -> u32;
    async fn sign(&self, msg: Hash256) -> Result<Signature, DvfError>;
    async fn is_active(&self) -> bool;
    async fn attest(&self, attest_data: &AttestationData, domain_hash: Hash256);
    async fn propose_full_block(&self, full_block: &[u8], domain_hash: Hash256);
    async fn propose_blinded_block(&self, blinded_block: &[u8], domain_hash: Hash256);
    fn shared_public_key(&self) -> PublicKey;
}

pub struct LocalOperator {
    pub operator_id: u32,
    pub share_public_key: PublicKey,
}

#[async_trait]
impl TOperator for LocalOperator {
    async fn sign(&self, _msg: Hash256) -> Result<Signature, DvfError> {
        Ok(Signature::empty())
    }

    async fn is_active(&self) -> bool {
        true
    }

    async fn attest(&self, _: &AttestationData, _: Hash256) {}

    async fn propose_full_block(&self, _: &[u8], _: Hash256) {}

    async fn propose_blinded_block(&self, _: &[u8], _: Hash256) {}

    fn id(&self) -> u32 {
        self.operator_id
    }

    fn shared_public_key(&self) -> PublicKey {
        self.share_public_key.clone()
    }
}

pub struct RemoteOperator {
    pub self_operator_id: u32,
    pub self_operator_secretkey: SecpSecretKey,
    pub operator_id: u32,
    pub base_address: SocketAddr,
    pub validator_public_key: PublicKey,
    pub operator_node_pk: SecpPublicKey,
    pub shared_public_key: PublicKey,
    pub logger: Logger,
    pub channel: Channel,
}

#[async_trait]
impl TOperator for RemoteOperator {
    async fn sign(&self, msg: Hash256) -> Result<Signature, DvfError> {
        let mut client = SafestakeClient::new(self.channel.clone());
        
        for _ in 0..3 {
            let request = tonic::Request::new(GetSignatureRequest {
                version: VERSION,
                msg: msg.0.to_vec(),
                validator_public_key: self.validator_public_key.serialize().to_vec(),
            });
            match timeout(RPC_REQUEST_TIMEOUT.clone(), client.get_signature(request)).await {
                Ok(Ok(response)) => {
                    return Ok(Signature::deserialize(&response.into_inner().signature).unwrap());
                },
                _ => {
                    sleep(Duration::from_millis(200));
                    continue;
                },
            }
        }
        Err(DvfError::SignatureNotFound(format!("{} not found", msg)))
    }

    async fn is_active(&self) -> bool {
        let mut client = SafestakeClient::new(self.channel.clone());
        let random_hash = Hash256::random();
        let request = tonic::Request::new(CheckLivenessRequest {
            version: VERSION,
            msg: random_hash.0.to_vec(),
            validator_public_key: self.validator_public_key.serialize().to_vec(),
        });
        match timeout(RPC_REQUEST_TIMEOUT.clone(), client.check_liveness(request)).await {
            Ok(Ok(_)) => {
                // match bincode::deserialize::<SecpSignature>(&response.into_inner().signature) {
                //             Ok(_) => {
                //                 info!(
                //                     self.logger,
                //                     "operator liveness";
                //                     "operator" => self.operator_id
                //                 );
                //                 return true;
                //             }
                //             Err(_) => {}
                //         }
                //     }
                //     Err(_) => {}
                // }
                info!(
                    self.logger,
                    "operator liveness";
                    "operator" => self.operator_id
                );
            }
            Ok(Err(e)) => {
                error!(
                    self.logger,
                    "operator liveness error";
                    "error" => %e
                );
            }
            Err(_) => {
                error!(
                    self.logger,
                    "operator liveness timeout";
                    "operator" => self.operator_id,
                    "socket address" => self.base_address
                );
            }
        }
        false
    }

    async fn attest(&self, attest_data: &AttestationData, domain_hash: Hash256) {
        let mut client = SafestakeClient::new(self.channel.clone());
        let data = serde_json::to_string(attest_data).unwrap();
        let sig = SecpSignature::new(&Digest::from(&domain_hash.0), &self.self_operator_secretkey)
            .unwrap();

        let request = tonic::Request::new(AttestRequest {
            version: VERSION,
            operator_id: self.self_operator_id,
            domain_hash: domain_hash.0.to_vec(),
            domian_hash_signature: sig.flatten().to_vec(),
            attestation_data: data.as_bytes().to_vec(),
            validator_public_key: self.validator_public_key.serialize().to_vec(),
        });

        match timeout(RPC_REQUEST_TIMEOUT.clone(), client.attest_data(request)).await {
            Ok(Ok(resp)) => {
                info!(
                    self.logger,
                    "remote attestation";
                    "response" => %resp.into_inner().msg
                );
            }
            Ok(Err(e)) => {
                error!(
                    self.logger,
                    "remote attestation error";
                    "error" => %e
                );
            }
            Err(_) => {
                error!(
                    self.logger,
                    "remote attestation timeout";
                    "operator" => self.operator_id,
                    "socket address" => self.base_address
                );
            }
        }
    }

    async fn propose_full_block(&self, full_block: &[u8], domain_hash: Hash256) {
        let mut client = SafestakeClient::new(self.channel.clone());
        let sig = SecpSignature::new(&Digest::from(&domain_hash.0), &self.self_operator_secretkey)
            .unwrap();
        let request = tonic::Request::new(ProposeFullBlockRequest {
            version: VERSION,
            operator_id: self.self_operator_id,
            domain_hash: domain_hash.0.to_vec(),
            domian_hash_signature: sig.flatten().to_vec(),
            full_block_data: full_block.to_vec(),
            validator_public_key: self.validator_public_key.serialize().to_vec(),
        });

        match timeout(RPC_REQUEST_TIMEOUT.clone(), client.propose_full_block(request)).await {
            Ok(r) => {
                match r {
                    Ok(_) => {
                        info!(
                            self.logger,
                            "remote proposal full block";
                            "signing root" => %domain_hash
                        );
                    },
                    Err(e) => {
                        error!(
                            self.logger,
                            "remote proposal full block error";
                            "error" => %e
                        );
                    } 
                }
                
            }
            Err(_) => {
                error!(
                    self.logger,
                    "remote proposal full block timeout";
                    "operator" => self.operator_id,
                    "socket address" => self.base_address
                );
            }
        }
    }

    async fn propose_blinded_block(&self, blinded_block: &[u8], domain_hash: Hash256) {
        let mut client = SafestakeClient::new(self.channel.clone());
        let sig = SecpSignature::new(&Digest::from(&domain_hash.0), &self.self_operator_secretkey)
            .unwrap();
        let request = tonic::Request::new(ProposeBlindedBlockRequest {
            version: VERSION,
            operator_id: self.self_operator_id,
            domain_hash: domain_hash.0.to_vec(),
            domian_hash_signature: sig.flatten().to_vec(),
            blinded_block_data: blinded_block.to_vec(),
            validator_public_key: self.validator_public_key.serialize().to_vec(),
        });

        match timeout(RPC_REQUEST_TIMEOUT.clone(), client.propose_blinded_block(request)).await {
            Ok(r) => {
                match r {
                    Ok(_) => {
                        info!(
                            self.logger,
                            "remote proposal blinded block";
                            "signing root" => %domain_hash
                        );
                    },
                    Err(e) => {
                        error!(
                            self.logger,
                            "remote proposal blinded block error";
                            "error" => %e
                        );
                    } 
                }
                
            }
            Err(_) => {
                error!(
                    self.logger,
                    "remote proposal blinded block timeout";
                    "operator" => self.operator_id,
                    "socket address" => self.base_address
                );
            }
        }
    }

    fn id(&self) -> u32 {
        self.operator_id
    }

    fn shared_public_key(&self) -> PublicKey {
        self.shared_public_key.clone()
    }
}

#[tokio::test]
pub async fn test_rpc_client() {
    use tonic::transport::Endpoint;
    use types::test_utils::TestRandom;
    let channel = Endpoint::from_static("http://54.151.182.45:26000").timeout(Duration::from_secs(2)).connect_lazy();
    
    let mut client = SafestakeClient::new(channel);
    let random_hash = Hash256::random();
    let mut rng = rand::thread_rng();
    let mut req = tonic::Request::new(CheckLivenessRequest {
        version: VERSION,
        msg: random_hash.0.to_vec(),
        validator_public_key: PublicKey::random_for_test(&mut rng).serialize().to_vec(),
    });
    req.set_timeout(Duration::from_secs(2));
    match tokio::time::timeout(Duration::from_secs(2), client
        .check_liveness(req))
        .await
    {
        Ok(Ok(r)) => {
            println!("{:?}", r);
        }
        Ok(Err(e)) => {
            println!("{:?}", e);
        }
        Err(e) => {
            println!("{:?}", e);
        }
    }
}

#[tokio::test]
async fn test_liveness() {
    use std::net::{Ipv4Addr, IpAddr};
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(3, 1, 157, 181)), 26000);
    let addr_str = format!("http://{}", addr.to_string());

    let mut client = SafestakeClient::connect(addr_str).await.unwrap();
    let random_hash = Hash256::random();
    let request = tonic::Request::new(CheckLivenessRequest {
        version: VERSION,
        msg: random_hash.0.to_vec(),
        validator_public_key: hex::decode("a025fd6f9806c4af7fde3a73cd71aa92dea92fe232c95cc8393a8974755e9719128e654006b46d106fd372d968da6114").unwrap(),
    });

    println!("{:?}, ", client.check_liveness(request).await.unwrap());
}

#[tokio::test]
async fn test_signature() {
    use store::LevelDB;
    use std::net::{Ipv4Addr, IpAddr};
    use types::MainnetEthSpec;
    use std::path::Path;
    let store = 
        LevelDB::<MainnetEthSpec>::open(Path::new("/tmp/test_store"))
            .map_err(|e| format!("{:?}", e)).unwrap();
    let testleaon = "18.143.137.23";
    let addr_str = format!("http://{}:26000", testleaon);
    
    let mut client = SafestakeClient::connect(addr_str).await.unwrap();
    let msg = hex::decode("b60913bd42c14342ac7af9a5e7e69a50184086d25410a6fc9d57773152b03486").unwrap();
    let request = tonic::Request::new(GetSignatureRequest {
        version: VERSION,
        msg,
        validator_public_key: hex::decode("857c755885305bcb010114eed5c93fafd6c7afba9c2132849aadf0bb821916c3f06f160674dd6f9d3ace0a486b08ad09").unwrap(),
    });
    let resp = client.get_signature(request).await.unwrap();
    Signature::deserialize(&resp.into_inner().signature).unwrap();

}
