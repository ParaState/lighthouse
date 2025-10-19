pub mod generic_operator_committee;
pub mod operator_committee;
pub mod proto;
pub mod report;

use crate::proto::safestake_client::SafestakeClient;
use crate::proto::*;
use async_trait::async_trait;
use bls::Error as BlsError;
use dvf_utils::{OUTDATE_SOFTWARE_VERSION, VERSION};
use lazy_static::lazy_static;
use safestake_crypto::secp::{
    Digest, PublicKey as SecpPublicKey, SecretKey as SecpSecretKey, Signature as SecpSignature,
};
use tracing::{error, info, warn};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use tokio::time::sleep;
use std::time::Duration;
use tokio::sync::OnceCell;
use tonic::transport::Channel;
use types::{graffiti::GraffitiString, AttestationData, PublicKey};
use types::{Hash256, Signature};
use flate2::{write::GzEncoder, read::GzDecoder};
use flate2::Compression;
use std::io::{Write, Read};
use tonic::Code;
use rand::random;

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

fn compress_data(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    let compressed_data = encoder.finish()?;
    Ok(compressed_data)
}

pub fn decompress_data(data: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut decoder = GzDecoder::new(data);
    let mut decompressed_data = Vec::new();
    decoder.read_to_end(&mut decompressed_data)?;
    Ok(decompressed_data)
}

pub static NODE_SECRET: OnceCell<SecpSecretKey> = OnceCell::const_new();
pub static SAFESTAKE_API: OnceCell<String> = OnceCell::const_new();
pub static RPC_REQUEST_TIMEOUT: Duration = Duration::from_millis(800);
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
    async fn simple_duty(&self, signing_root: Hash256);
    async fn propose_full_block(&self, full_block: &[u8], domain_hash: Hash256);
    async fn propose_blinded_block(&self, blinded_block: &[u8], domain_hash: Hash256);
    async fn broadcast_attestation(&self, attestation: &[u8], validator_index: u64, domain_hash: Hash256);
    async fn broadcast_aggregate_and_proof(&self, aggregate_and_proof: &[u8], domain_hash: Hash256);
    async fn broadcast_sync_committee_message(&self, _: &[u8], _: Hash256) {}
    fn shared_public_key(&self) -> PublicKey;
    async fn broadcast_full_block(&self, _: &[u8], _: Hash256, _: &[u8]) {}
    async fn broadcast_blinded_block(&self, _: &[u8], _: Hash256) {}
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

    async fn broadcast_attestation(&self, _: &[u8], _: u64, _: Hash256) {}

    async fn broadcast_aggregate_and_proof(&self, _: &[u8], _: Hash256) {}
    
    async fn simple_duty(&self, _: Hash256) {}

    async fn broadcast_sync_committee_message(&self, _: &[u8], _: Hash256) {}

    async fn broadcast_full_block(&self, _: &[u8], _: Hash256, _: &[u8]) {}

    async fn broadcast_blinded_block(&self, _: &[u8], _: Hash256) {}
}

pub struct RemoteOperator {
    pub self_operator_id: u32,
    pub self_operator_secretkey: SecpSecretKey,
    pub operator_id: u32,
    pub base_address: SocketAddr,
    pub validator_public_key: PublicKey,
    pub operator_node_pk: SecpPublicKey,
    pub shared_public_key: PublicKey,
    pub channel: Channel,
    pub software_version: u64
}

#[async_trait]
impl TOperator for RemoteOperator {
    async fn sign(&self, msg: Hash256) -> Result<Signature, DvfError> {
        let mut client = SafestakeClient::new(self.channel.clone());
        
        for i in 0..3 {
            let request = tonic::Request::new(GetSignatureRequest {
                version: VERSION,
                msg: msg.0.to_vec(),
                validator_public_key: self.validator_public_key.serialize().to_vec(),
            });
            tokio::select! {
                result = client.get_signature_v2(request) => {
                    match result {
                        Ok(response) => return Ok(Signature::deserialize(&response.into_inner().signature).unwrap()),
                        Err(e) => {
                            match e.code() {
                                Code::Unimplemented => { break; }
                                _ => {
                                    warn!(
                                        info="failed to get remote operator's signature",
                                        retry=?i
                                    );
                                    sleep(Duration::from_millis(200)).await;
                                }
                            }
                        },
                    }
                },
                _ = sleep(RPC_REQUEST_TIMEOUT) => {
                    error!(
                        msg = "operator get signature timeout",
                        operator=?self.operator_id,
                        socket_address=?self.base_address
                    );
                }
            }
        }

        for _ in 0..3 {
            let request = tonic::Request::new(GetSignatureRequest {
                version: VERSION,
                msg: msg.0.to_vec(),
                validator_public_key: self.validator_public_key.serialize().to_vec(),
            });
            tokio::select! {
                result = client.get_signature(request) => {
                    match result {
                        Ok(response) => return Ok(Signature::deserialize(&response.into_inner().signature).unwrap()),
                        Err(_) => {
                            sleep(Duration::from_millis(200)).await;
                        },
                    }
                },
                _ = sleep(RPC_REQUEST_TIMEOUT) => {
                    error!(
                        msg="operator get signature timeout",
                        operator=self.operator_id,
                        socket_address=?self.base_address
                    );
                }
            }
        }

        error!(
            msg="remote operator signature not found",
            operator=self.operator_id,
        );
        Err(DvfError::SignatureNotFound(format!("{} not found", msg)))
    }

    async fn is_active(&self) -> bool {
        let mut client = SafestakeClient::new(self.channel.clone());
        let bytes: [u8; 32] = random();
        let random_hash = Hash256::new(bytes);
        let request = tonic::Request::new(CheckLivenessRequest {
            version: VERSION,
            msg: random_hash.0.to_vec(),
            validator_public_key: self.validator_public_key.serialize().to_vec(),
        });

        tokio::select! {
            result = client.check_liveness(request) => {
                match result {
                    Ok(_) => {
                        info!(
                            info="operator liveness",
                            operator=?self.operator_id
                        );
                        return true;
                    },
                    Err(_) => {
                        return false;
                    },
                }
            },
            _ = sleep(RPC_REQUEST_TIMEOUT) => {
                error!(
                    msg="operator liveness timeout",
                    operator=?self.operator_id,
                    socket_address=?self.base_address
                );
                return false;
            }
        }
    }

    async fn attest(&self, attest_data: &AttestationData, domain_hash: Hash256) {
        let mut client = SafestakeClient::new(self.channel.clone());
        let data = serde_json::to_vec(attest_data).unwrap();
        let sig = SecpSignature::new(&Digest::from(&domain_hash.0), &self.self_operator_secretkey)
            .unwrap();

        let sent_data = if self.software_version > OUTDATE_SOFTWARE_VERSION {
            compress_data(&data).unwrap()
        } else {
            data
        };

        let request = tonic::Request::new(AttestRequest {
            version: VERSION,
            operator_id: self.self_operator_id,
            domain_hash: domain_hash.0.to_vec(),
            domian_hash_signature: sig.flatten().to_vec(),
            attestation_data: sent_data,
            validator_public_key: self.validator_public_key.serialize().to_vec(),
        });

        tokio::select! {
            result = client.attest_data(request) => {
                match result {
                    Ok(resp) => {
                        info!(
                            info="remote attestation",
                            response=?resp.into_inner().msg
                        );
                    },
                    Err(e) => {
                        error!(
                            error=?e,
                            "remote attestation error",
                        );
                    },
                }
            },
            _ = sleep(RPC_REQUEST_TIMEOUT) => {
                error!(
                    msg="remote attestation timeout",
                    operator=?self.operator_id,
                    socket_addres=?self.base_address
                );
            }
        }
    }

    async fn broadcast_attestation(&self, attestation: &[u8], validator_index: u64, domain_hash: Hash256) {
        let mut client = SafestakeClient::new(self.channel.clone());
        let sent_data = compress_data(attestation).unwrap();
        let sig = SecpSignature::new(&Digest::from(&domain_hash.0), &self.self_operator_secretkey).unwrap();
        let request = tonic::Request::new(BroadcastAttestationRequest {
            version: VERSION,
            operator_id: self.self_operator_id,
            domain_hash: domain_hash.0.to_vec(),
            domain_hash_signature: sig.flatten().to_vec(),
            attestation: sent_data,
            validator_index: validator_index,
            validator_public_key: self.validator_public_key.serialize().to_vec()
        });
        tokio::spawn(async move {
            let _ = client.broadcast_attestation(request).await;
        });
    }

    async fn broadcast_aggregate_and_proof(&self, aggregate_and_proof: &[u8], domain_hash: Hash256) {
        let mut client = SafestakeClient::new(self.channel.clone());
        let sent_data = compress_data(aggregate_and_proof).unwrap();
        let sig = SecpSignature::new(&Digest::from(&domain_hash.0), &self.self_operator_secretkey).unwrap();
        let request = tonic::Request::new(BroadcastAggregateAndProofRequest {
            version: VERSION,
            operator_id: self.self_operator_id,
            domain_hash: domain_hash.0.to_vec(),
            domain_hash_signature: sig.flatten().to_vec(),
            aggregate_and_proof: sent_data,
            validator_public_key: self.validator_public_key.serialize().to_vec()
        });
        tokio::spawn(async move {
            let _ = client.broadcast_aggregate_and_proof(request).await;
        });
    }

    async fn broadcast_full_block(&self, full_block: &[u8], domain_hash: Hash256, blobs: &[u8]) {
        let mut client = SafestakeClient::new(self.channel.clone());
        let sent_data = compress_data(full_block).unwrap();
        let sig = SecpSignature::new(&Digest::from(&domain_hash.0), &self.self_operator_secretkey).unwrap();
        let request = tonic::Request::new(BroadcastFullBlockRequest {
            version: VERSION,
            operator_id: self.self_operator_id,
            domain_hash: domain_hash.0.to_vec(),
            domain_hash_signature: sig.flatten().to_vec(),
            block_data: sent_data,
            blobs: compress_data(blobs).unwrap(),
            validator_public_key: self.validator_public_key.serialize().to_vec()
        });
        tokio::spawn(async move {
            let _ = client.broadcast_full_block(request).await;
        });
    }

    async fn broadcast_blinded_block(&self, blinded_block: &[u8], domain_hash: Hash256) {
        let mut client = SafestakeClient::new(self.channel.clone());
        let sent_data = compress_data(blinded_block).unwrap();
        let sig = SecpSignature::new(&Digest::from(&domain_hash.0), &self.self_operator_secretkey).unwrap();
        let request = tonic::Request::new(BroadcastBlindedBlockRequest {
            version: VERSION,
            operator_id: self.self_operator_id,
            domain_hash: domain_hash.0.to_vec(),
            domain_hash_signature: sig.flatten().to_vec(),
            block_data: sent_data,
            validator_public_key: self.validator_public_key.serialize().to_vec()
        });
        tokio::spawn(async move {
            let _ = client.broadcast_blinded_block(request).await;
        });
    }

    async fn propose_full_block(&self, full_block: &[u8], domain_hash: Hash256) {
        let mut client = SafestakeClient::new(self.channel.clone());
        let sig = SecpSignature::new(&Digest::from(&domain_hash.0), &self.self_operator_secretkey)
            .unwrap();

        let sent_data = if self.software_version > OUTDATE_SOFTWARE_VERSION {
            compress_data(full_block).unwrap()
        } else {
            full_block.to_vec()
        };
        let request = tonic::Request::new(ProposeFullBlockRequest {
            version: VERSION,
            operator_id: self.self_operator_id,
            domain_hash: domain_hash.0.to_vec(),
            domian_hash_signature: sig.flatten().to_vec(),
            full_block_data: sent_data,
            validator_public_key: self.validator_public_key.serialize().to_vec(),
        });

        tokio::select! {
            result = client.propose_full_block(request) => {
                match result {
                    Ok(_) => {
                        info!(
                            info="remote proposal full block",
                            signing_root=%domain_hash
                        );
                    },
                    Err(e) => {
                        error!(
                            error=?e,
                            "remote proposal full block error"
                        );
                    },
                }
            },
            _ = sleep(RPC_REQUEST_TIMEOUT) => {
                error!(
                    msg="remote proposal full block timeout",
                    operator=%self.operator_id,
                    socket_address=%self.base_address
                );
            }
        }
    }

    async fn propose_blinded_block(&self, blinded_block: &[u8], domain_hash: Hash256) {
        let mut client = SafestakeClient::new(self.channel.clone());
        let sig = SecpSignature::new(&Digest::from(&domain_hash.0), &self.self_operator_secretkey)
            .unwrap();
        let sent_data = if self.software_version > OUTDATE_SOFTWARE_VERSION {
            compress_data(blinded_block).unwrap()
        } else {
            blinded_block.to_vec()
        };
        let request = tonic::Request::new(ProposeBlindedBlockRequest {
            version: VERSION,
            operator_id: self.self_operator_id,
            domain_hash: domain_hash.0.to_vec(),
            domian_hash_signature: sig.flatten().to_vec(),
            blinded_block_data: sent_data,
            validator_public_key: self.validator_public_key.serialize().to_vec(),
        });
        
        tokio::select! {
            result = client.propose_blinded_block(request) => {
                match result {
                    Ok(_) => {
                        info!(
                            info="remote proposal blinded block",
                            signing_root=%domain_hash
                        );
                    },
                    Err(e) => {
                        error!(
                            error=%e,
                            "remote proposal blinded block error"
                        );
                    }
                }
            },
            _ = sleep(RPC_REQUEST_TIMEOUT) => {
                error!(
                    msg="remote proposal full block timeout",
                    operator=%self.operator_id,
                    socket_address=%self.base_address
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

    async fn simple_duty(&self, signing_root: Hash256) {
        let mut client = SafestakeClient::new(self.channel.clone());
        let sig = SecpSignature::new(&Digest::from(&signing_root.0), &self.self_operator_secretkey).unwrap();
        let request = tonic::Request::new(SimpleDutyRequest {
            version: VERSION,
            operator_id: self.self_operator_id,
            signing_root: signing_root.0.to_vec(),
            signing_root_signature: sig.flatten().to_vec(),
            validator_public_key: self.validator_public_key.serialize().to_vec(),
        });

        tokio::select! {
            result = client.simple_duty(request) => {
                match result {
                    Ok(_) => {
                        info!(
                            info="simple duty",
                        );
                    },
                    Err(e) => {
                        error!(
                            error=%e,
                            "simple duty error"
                        );
                    }
                }
            },
            _ = sleep(RPC_REQUEST_TIMEOUT) => {
                error!(
                    msg="simple duty timeout",
                    operator=%self.operator_id,
                    socket_address=%self.base_address
                );
            }
        }
    }

    async fn broadcast_sync_committee_message(&self, sync_committee_message: &[u8], domain_hash: Hash256) {
        let mut client = SafestakeClient::new(self.channel.clone());
        let sig = SecpSignature::new(&Digest::from(&domain_hash.0), &self.self_operator_secretkey).unwrap();
        let request = tonic::Request::new(BroadcastSyncCommitteeMessageRequest {
            version: VERSION,
            operator_id: self.self_operator_id,
            domain_hash: domain_hash.0.to_vec(),
            domain_hash_signature: sig.flatten().to_vec(),
            sync_committee_message: sync_committee_message.to_vec(),
            validator_public_key: self.validator_public_key.serialize().to_vec(),
        });
        tokio::spawn(async move {
            let _ = client.broadcast_sync_committee_message(request).await;
        });
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
async fn test_compress() {
    use rand::RngCore;
    use types::*;
    let mut rng = rand::thread_rng();
    
    let attest_data = AttestationData {
        slot: Slot::new(0),
        index: 0,
        beacon_block_root: Hash256::zero(),
        target: Checkpoint {
            root: Hash256::zero(),
            epoch: Epoch::new(0),
        },
        source: Checkpoint {
            root: Hash256::zero(),
            epoch: Epoch::new(0),
        },
    };
    let data = serde_json::to_string(&attest_data).unwrap();
    println!("data : {}", data);
    let compressed = compress_data(data.as_bytes()).unwrap();

    println!("origin length {}, compressed length {}", data.len(), compressed.len());

    let decompressed = decompress_data(&compressed).unwrap();

    assert_eq!(data.as_bytes(), &decompressed);
}

#[tokio::test]
async fn test_compress_block() {
    use rand::RngCore;
    use types::*;

    let data = "{\"message\":{\"slot\":\"3038281899734347327\",\"proposer_index\":\"3038287259853529439\",\"parent_root\":\"0x86a2712af7d20a5150212a51252a2a2a74d8e88d543e728aebae528a86c652f1\",\"state_root\":\"0xa08bb23a3c9229210445133eb6d21259bfbd53f71b69869a2a24193e3dc651f1\",\"body\":{\"randao_reveal\":\"0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\",\"eth1_data\":{\"deposit_root\":\"0xed23859b374fe23235052dc5835332ba63951a08a0f8a1282c54088545a18ead\",\"deposit_count\":\"6242018213914445850\",\"block_hash\":\"0xb28dce914792924937605c2428fd7972c84d3f97c2f5e24a7179788d4b455530\"},\"graffiti\":\"0x841f695d0ebd780081ff854e079460d43024e0c1cf61b5042fefad65318fbdb5\",\"proposer_slashings\":[{\"signed_header_1\":{\"message\":{\"slot\":\"15021203085507186803\",\"proposer_index\":\"1956234481814458790\",\"parent_root\":\"0x3a1096832ecac4e311517534a22de30044fac733a8d397f6b2e9f46833576371\",\"state_root\":\"0x81967a7d1500383579c64efaccccff91ec8e9838421955cd9f73a441cb4e522e\",\"body_root\":\"0x034a41d200c6bbb7e363e1d5824b7969fc05b0b10c5e52d89ec0720689bef4a5\"},\"signature\":\"0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"},\"signed_header_2\":{\"message\":{\"slot\":\"16046992427396550702\",\"proposer_index\":\"5644413697793459183\",\"parent_root\":\"0x1e8ecd0cf62fc7407a1762aec0983d474753e027d270215eab6546e0fb1a164b\",\"state_root\":\"0xb502496e4e48bb3baf1903e896073913eef3433530345bd475816524d837bbff\",\"body_root\":\"0x42774dd56f23bad8247fdcd01097fff6ea19b648c8ea1e4190980872d6c64578\"},\"signature\":\"0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"}},{\"signed_header_1\":{\"message\":{\"slot\":\"3907447753550395773\",\"proposer_index\":\"6261653780291443016\",\"parent_root\":\"0x40c84df15d87c9177516c511e14abf695e802ff6a90287add2dfc894e867b307\",\"state_root\":\"0x303a148d71f31318ee89f7ca7f3be756294e0e7a62b201fdd5eccf8b10029ce4\",\"body_root\":\"0xac67ebecf14a891cf1a4d4e879b75cec597b3d5b0d6cb50d66b20b406122e549\"},\"signature\":\"0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"},\"signed_header_2\":{\"message\":{\"slot\":\"6899991305971204023\",\"proposer_index\":\"2509196135399465108\",\"parent_root\":\"0xbdf8f748da4de81a130ecf7df1bb08ccdd80cd3be39c136304b9a9661351f7ef\",\"state_root\":\"0x58ef6bb83288604743782a6c1cc300394bfaf6debfd8949d2e4343a2596c649d\",\"body_root\":\"0x1cf929f4069643cff3e6a177fa4a19c9dcab437234f063a1950c8dd9c4c3c0da\"},\"signature\":\"0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"}}],\"attester_slashings\":[{\"attestation_1\":{\"attesting_indices\":[\"7400624632945338005\"],\"data\":{\"slot\":\"4437459872398136559\",\"index\":\"17296625070497484247\",\"beacon_block_root\":\"0x1e36040d7665359852f3835e4a4393e1a02d0bcda2ff26fe579a7ebfe1178cc4\",\"source\":{\"epoch\":\"11055346147395519741\",\"root\":\"0xe7e78bd248d11c76da2ae7d47b0ba42e97659da33d769b336e3bc7de1e0c36d0\"},\"target\":{\"epoch\":\"8074353698011052626\",\"root\":\"0xcc84f697d03cc0f790d53e1462a8c20a129d31295802e1df61de913d09e00f22\"}},\"signature\":\"0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"},\"attestation_2\":{\"attesting_indices\":[\"16394984587976446243\",\"11545956531142136911\",\"11394412340436646247\"],\"data\":{\"slot\":\"18148326900572429376\",\"index\":\"5197767471137331124\",\"beacon_block_root\":\"0xa193418007a6c6a53c0059bfcbbf4de638e41d6ae2817bfa7126548df7636c06\",\"source\":{\"epoch\":\"11927658472840461094\",\"root\":\"0x4053cc8955eadaeca3b0fec4e5a8915d44a62cb6967a9f8d2eb8d5bcd1f9d36c\"},\"target\":{\"epoch\":\"14493703138850008201\",\"root\":\"0xf43f26d85048c82b8413fe6707a7dab157f7ea58d2be093144e9fca603807ac2\"}},\"signature\":\"0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"}}],\"attestations\":[],\"deposits\":[],\"voluntary_exits\":[{\"message\":{\"epoch\":\"559570677015632420\",\"validator_index\":\"18267714871076196171\"},\"signature\":\"0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"}]}},\"signature\":\"0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\"}";
    let compressed = compress_data(data.as_bytes()).unwrap();

    println!("origin length {}, compressed length {}", data.len(), compressed.len());

    let decompressed = decompress_data(&compressed).unwrap();

    assert_eq!(data.as_bytes(), &decompressed);
}

#[tokio::test]
async fn test_signature() {
    use store::database::leveldb_impl::LevelDB;
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
