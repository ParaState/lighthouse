pub mod database;
pub mod generic_operator_committee;
pub mod models;
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
use tokio::sync::OnceCell;
use tonic::transport::Channel;
use types::{AttestationData, PublicKey};
use types::{Hash256, Keypair, Signature};

lazy_static! {
    pub static ref THRESHOLD_MAP: HashMap<u64, u64> = {
        let mut threshold_map = HashMap::new();
        threshold_map.insert(4, 3);
        threshold_map.insert(7, 5);
        threshold_map
    };
}

pub static NODE_SECRET: OnceCell<SecpSecretKey> = OnceCell::const_new();
pub static SAFESTAKE_API: OnceCell<String> = OnceCell::const_new();

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
    pub operator_keypair: Keypair,
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
        self.operator_keypair.pk.clone()
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
        let request = tonic::Request::new(GetSignatureRequest {
            version: VERSION,
            msg: msg.0.to_vec(),
            validator_public_key: self.validator_public_key.serialize().to_vec(),
        });
        match client.get_signature(request).await {
            Ok(response) => Ok(Signature::deserialize(&response.into_inner().signature).unwrap()),
            Err(e) => Err(DvfError::SignatureNotFound(e.to_string())),
        }
    }

    async fn is_active(&self) -> bool {
        let mut client = SafestakeClient::new(self.channel.clone());
        let random_hash = Hash256::random();
        let request = tonic::Request::new(CheckLivenessRequest {
            version: VERSION,
            msg: random_hash.0.to_vec(),
            validator_public_key: self.validator_public_key.serialize().to_vec(),
        });

        match client.check_liveness(request).await {
            Ok(response) => {
                match bincode::deserialize::<SecpSignature>(&response.into_inner().signature) {
                    Ok(sig) => {
                        match sig.verify(&Digest::from(&random_hash.0), &self.operator_node_pk) {
                            Ok(_) => {
                                info!(
                                    self.logger,
                                    "operator liveness";
                                    "operator" => self.operator_id
                                );
                                return true;
                            }
                            Err(_) => {}
                        }
                    }
                    Err(_) => {}
                }
            }
            Err(e) => {
                error!(
                    self.logger,
                    "remote operator liveness";
                    "error" => %e
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

        match client.attest_data(request).await {
            Ok(_) => {
                info!(
                    self.logger,
                    "remote attestation";
                    "signing root" => %domain_hash
                );
            }
            Err(e) => {
                error!(
                    self.logger,
                    "remote attestation";
                    "error" => %e
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

        match client.propose_full_block(request).await {
            Ok(_) => {
                info!(
                    self.logger,
                    "remote proposal full block";
                    "signing root" => %domain_hash
                );
            }
            Err(e) => {
                error!(
                    self.logger,
                    "remote proposal full block";
                    "error" => %e
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

        match client.propose_blinded_block(request).await {
            Ok(_) => {
                info!(
                    self.logger,
                    "remote proposal blinded block";
                    "signing root" => %domain_hash
                );
            }
            Err(e) => {
                error!(
                    self.logger,
                    "remote proposal blinded block";
                    "error" => %e
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
    let channel = Endpoint::from_static("http://[::1]:50051").connect_lazy();
    let mut client = SafestakeClient::new(channel);
    let random_hash = Hash256::random();
    let mut rng = rand::thread_rng();
    match client
        .check_liveness(tonic::Request::new(CheckLivenessRequest {
            version: VERSION,
            msg: random_hash.0.to_vec(),
            validator_public_key: PublicKey::random_for_test(&mut rng).serialize().to_vec(),
        }))
        .await
    {
        Ok(r) => {
            println!("{:?}", r);
        }
        Err(e) => {
            println!("{:?}", e);
        }
    }
}
