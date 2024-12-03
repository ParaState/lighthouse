//! Provides methods for obtaining validator signatures, including:
//!
//! - Via a local `Keypair`.
//! - Via a remote signer (Web3Signer)

use crate::http_metrics::metrics;
use eth2_keystore::Keystore;
use eth2_keystore_share::KeystoreShare;
use lockfile::Lockfile;
use parking_lot::Mutex;
use reqwest::{header::ACCEPT, Client};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use task_executor::TaskExecutor;
use types::*;
use url::Url;
use web3signer::{ForkInfo, SigningRequest, SigningResponse};
use crate::operator::operator_committee::DvfOperatorCommittee;
use crate::operator::generic_operator_committee::TOperatorCommittee;
pub use web3signer::Web3SignerObject;
use slog::info;
use tokio::time::sleep;
use chrono::prelude::{DateTime, Utc};
use tokio::sync::mpsc::Sender;
mod web3signer;

#[derive(Debug, PartialEq)]
pub enum Error {
    InconsistentDomains {
        message_type_domain: Domain,
        domain: Domain,
    },
    Web3SignerRequestFailed(String),
    Web3SignerJsonParsingFailed(String),
    ShuttingDown,
    TokioJoin(String),
    MergeForkNotSupported,
    GenesisForkVersionRequired,
    NotLeader,
    CommitteeSignFailed(String)
}

/// Enumerates all messages that can be signed by a validator.
pub enum SignableMessage<'a, E: EthSpec, Payload: AbstractExecPayload<E> = FullPayload<E>> {
    RandaoReveal(Epoch),
    BeaconBlock(&'a BeaconBlock<E, Payload>),
    AttestationData(&'a AttestationData),
    SignedAggregateAndProof(AggregateAndProofRef<'a, E>),
    SelectionProof(Slot),
    SyncSelectionProof(&'a SyncAggregatorSelectionData),
    SyncCommitteeSignature {
        beacon_block_root: Hash256,
        slot: Slot,
    },
    SignedContributionAndProof(&'a ContributionAndProof<E>),
    ValidatorRegistration(&'a ValidatorRegistrationData),
    VoluntaryExit(&'a VoluntaryExit),
}

impl<'a, E: EthSpec, Payload: AbstractExecPayload<E>> SignableMessage<'a, E, Payload> {
    /// Returns the `SignedRoot` for the contained message.
    ///
    /// The actual `SignedRoot` trait is not used since it also requires a `TreeHash` impl, which is
    /// not required here.
    pub fn signing_root(&self, domain: Hash256) -> Hash256 {
        match self {
            SignableMessage::RandaoReveal(epoch) => epoch.signing_root(domain),
            SignableMessage::BeaconBlock(b) => b.signing_root(domain),
            SignableMessage::AttestationData(a) => a.signing_root(domain),
            SignableMessage::SignedAggregateAndProof(a) => a.signing_root(domain),
            SignableMessage::SelectionProof(slot) => slot.signing_root(domain),
            SignableMessage::SyncSelectionProof(s) => s.signing_root(domain),
            SignableMessage::SyncCommitteeSignature {
                beacon_block_root, ..
            } => beacon_block_root.signing_root(domain),
            SignableMessage::SignedContributionAndProof(c) => c.signing_root(domain),
            SignableMessage::ValidatorRegistration(v) => v.signing_root(domain),
            SignableMessage::VoluntaryExit(exit) => exit.signing_root(domain),
        }
    }
}

/// A method used by a validator to sign messages.
///
/// Presently there is only a single variant, however we expect more variants to arise (e.g.,
/// remote signing).
pub enum SigningMethod {
    /// A validator that is defined by an EIP-2335 keystore on the local filesystem.
    LocalKeystore {
        voting_keystore_path: PathBuf,
        voting_keystore_lockfile: Mutex<Option<Lockfile>>,
        voting_keystore: Keystore,
        voting_keypair: Arc<Keypair>,
    },
    /// A validator that defers to a Web3Signer server for signing.
    ///
    /// See: https://docs.web3signer.consensys.net/en/latest/
    Web3Signer {
        signing_url: Url,
        http_client: Client,
        voting_public_key: PublicKey,
    },
    /// A validator whose key is distributed among a set of operators.
    DistributedKeystore {
        voting_keystore_share_path: PathBuf,
        voting_keystore_share_lockfile: Mutex<Option<Lockfile>>,
        voting_keystore_share: KeystoreShare,
        voting_public_key: PublicKey,
        operator_committee: DvfOperatorCommittee,
        keypair: Keypair,
        store_sender: Sender<(Hash256, Signature, PublicKey)>,
    },
}

/// The additional information used to construct a signature. Mostly used for protection from replay
/// attacks.
pub struct SigningContext {
    pub domain: Domain,
    pub epoch: Epoch,
    pub fork: Fork,
    pub genesis_validators_root: Hash256,
}

impl SigningContext {
    /// Returns the `Hash256` to be mixed-in with the signature.
    pub fn domain_hash(&self, spec: &ChainSpec) -> Hash256 {
        spec.get_domain(
            self.epoch,
            self.domain,
            &self.fork,
            self.genesis_validators_root,
        )
    }
}

impl SigningMethod {
    pub async fn responsible(&self, epoch: Epoch) -> bool {
        let nonce = epoch.as_u64();
        match self {
            SigningMethod::DistributedKeystore { operator_committee, .. } => {
                let leader = operator_committee.get_leader_id(nonce);
                // if leader is active, check whether self is leader
                if operator_committee.check_liveness(leader).await {
                    operator_committee.is_leader(nonce)
                } else {
                    operator_committee.is_backup(nonce)
                }
            }
            _ => true,
        }
    }

    pub async fn distributed_attest(
        &self,
        domain_hash: Hash256,
        attestation_data: &AttestationData,
    ) {
        match self {
            SigningMethod::DistributedKeystore { operator_committee, .. } => {
                operator_committee.attest(attestation_data, domain_hash).await;
            }
            _ => {}
        }
    }

    pub async fn distributed_propose_block<T: EthSpec, Payload: AbstractExecPayload<T>>(
        &self,
        domain_hash: Hash256,
        block: &BeaconBlock<T, Payload>,
    ) {
        match self {
            SigningMethod::DistributedKeystore { operator_committee, .. } => {
                let data = serde_json::to_vec(block).unwrap();
                let block_type = Payload::block_type();
                match block_type {
                    BlockType::Blinded => {
                        operator_committee.propose_blinded_block(&data, domain_hash).await;
                    },
                    BlockType::Full => {
                        operator_committee.propose_full_block(&data, domain_hash).await;
                    }
                };
            }
            _ => {}
        }
    }

    /// Return whether this signing method requires local slashing protection.
    pub fn requires_local_slashing_protection(
        &self,
        enable_web3signer_slashing_protection: bool,
    ) -> bool {
        match self {
            // Slashing protection is ALWAYS required for local keys. DO NOT TURN THIS OFF.
            SigningMethod::LocalKeystore { .. } => true,
            // Slashing protection is only required for remote signer keys when the configuration
            // dictates that it is desired.
            SigningMethod::Web3Signer { .. } => enable_web3signer_slashing_protection,
            SigningMethod::DistributedKeystore { .. } => true,
        }
    }

    /// Return the signature of `signable_message`, with respect to the `signing_context`.
    pub async fn get_signature<E: EthSpec, Payload: AbstractExecPayload<E>>(
        &self,
        signable_message: SignableMessage<'_, E, Payload>,
        signing_context: SigningContext,
        spec: &ChainSpec,
        executor: &TaskExecutor,
    ) -> Result<Signature, Error> {
        let domain_hash = signing_context.domain_hash(spec);
        let SigningContext {
            fork,
            genesis_validators_root,
            ..
        } = signing_context;

        let signing_root = signable_message.signing_root(domain_hash);

        let fork_info = Some(ForkInfo {
            fork,
            genesis_validators_root,
        });

        self.get_signature_from_root(signable_message, signing_root, executor, fork_info)
            .await
    }

    pub async fn get_signature_from_root<E: EthSpec, Payload: AbstractExecPayload<E>>(
        &self,
        signable_message: SignableMessage<'_, E, Payload>,
        signing_root: Hash256,
        executor: &TaskExecutor,
        fork_info: Option<ForkInfo>,
    ) -> Result<Signature, Error> {
        match self {
            SigningMethod::LocalKeystore { voting_keypair, .. } => {
                let _timer =
                    metrics::start_timer_vec(&metrics::SIGNING_TIMES, &[metrics::LOCAL_KEYSTORE]);

                let voting_keypair = voting_keypair.clone();
                // Spawn a blocking task to produce the signature. This avoids blocking the core
                // tokio executor.
                let signature = executor
                    .spawn_blocking_handle(
                        move || voting_keypair.sk.sign(signing_root),
                        "local_keystore_signer",
                    )
                    .ok_or(Error::ShuttingDown)?
                    .await
                    .map_err(|e| Error::TokioJoin(e.to_string()))?;
                Ok(signature)
            }
            SigningMethod::Web3Signer {
                signing_url,
                http_client,
                ..
            } => {
                let _timer =
                    metrics::start_timer_vec(&metrics::SIGNING_TIMES, &[metrics::WEB3SIGNER]);

                // Map the message into a Web3Signer type.
                let object = match signable_message {
                    SignableMessage::RandaoReveal(epoch) => {
                        Web3SignerObject::RandaoReveal { epoch }
                    }
                    SignableMessage::BeaconBlock(block) => Web3SignerObject::beacon_block(block)?,
                    SignableMessage::AttestationData(a) => Web3SignerObject::Attestation(a),
                    SignableMessage::SignedAggregateAndProof(a) => {
                        Web3SignerObject::AggregateAndProof(a)
                    }
                    SignableMessage::SelectionProof(slot) => {
                        Web3SignerObject::AggregationSlot { slot }
                    }
                    SignableMessage::SyncSelectionProof(s) => {
                        Web3SignerObject::SyncAggregatorSelectionData(s)
                    }
                    SignableMessage::SyncCommitteeSignature {
                        beacon_block_root,
                        slot,
                    } => Web3SignerObject::SyncCommitteeMessage {
                        beacon_block_root,
                        slot,
                    },
                    SignableMessage::SignedContributionAndProof(c) => {
                        Web3SignerObject::ContributionAndProof(c)
                    }
                    SignableMessage::ValidatorRegistration(v) => {
                        Web3SignerObject::ValidatorRegistration(v)
                    }
                    SignableMessage::VoluntaryExit(e) => Web3SignerObject::VoluntaryExit(e),
                };

                // Determine the Web3Signer message type.
                let message_type = object.message_type();

                if matches!(
                    object,
                    Web3SignerObject::Deposit { .. } | Web3SignerObject::ValidatorRegistration(_)
                ) && fork_info.is_some()
                {
                    return Err(Error::GenesisForkVersionRequired);
                }

                let request = SigningRequest {
                    message_type,
                    fork_info,
                    signing_root,
                    object,
                };

                // Request a signature from the Web3Signer instance via HTTP(S).
                let response: SigningResponse = http_client
                    .post(signing_url.clone())
                    .header(ACCEPT, "application/json")
                    .json(&request)
                    .send()
                    .await
                    .map_err(|e| Error::Web3SignerRequestFailed(e.to_string()))?
                    .error_for_status()
                    .map_err(|e| Error::Web3SignerRequestFailed(e.to_string()))?
                    .json()
                    .await
                    .map_err(|e| Error::Web3SignerJsonParsingFailed(e.to_string()))?;

                Ok(response.signature)
            }
            SigningMethod::DistributedKeystore { 
                operator_committee, 
                keypair, 
                store_sender,
                .. } => {
                let _timer = metrics::start_timer_vec(
                    &metrics::SIGNING_TIMES,
                    &[metrics::DISTRIBUTED_KEYSTORE],
                );
                let (epoch, slot, duty, only_aggregator) = match signable_message {
                    SignableMessage::RandaoReveal(e) => {
                        // Every operator should be able to get randao signature,
                        // otherwise if, e.g, only 2 out of 4 gets the randao signature,
                        // then the committee wouldn't be able to get enough partial signatuers for
                        // aggregation, because the other 2 operations who don't get the randao
                        // will NOT enter the next phase of signing block.
                        (e, e.start_slot(E::slots_per_epoch()),  "RANDAO", false)
                    }
                    SignableMessage::AttestationData(a) => (a.slot.epoch(E::slots_per_epoch()), a.slot, "ATTESTER", true),
                    SignableMessage::BeaconBlock(b) => (b.slot().epoch(E::slots_per_epoch()), b.slot(), "PROPOSER", true),
                    SignableMessage::SignedAggregateAndProof(x) => {
                        (x.aggregate().data().slot.epoch(E::slots_per_epoch()), x.aggregate().data().slot, "AGGREGATE", true)
                    }
                    SignableMessage::SelectionProof(s) => {
                        // Every operator should be able to get selection proof signature,
                        // otherwise operators who don't get selection proof signature will
                        // NOT be able to insert the ATTESTER duties into their local cache,
                        // hence will NOT enter the corresponding phase of signing attestation.
                        (s.epoch(E::slots_per_epoch()), s, "SELECT", false)
                    }
                    SignableMessage::SyncSelectionProof(s) => (s.slot.epoch(E::slots_per_epoch()), s.slot, "SYNC_SELECT", false),
                    SignableMessage::SyncCommitteeSignature {
                        beacon_block_root: _,
                        slot,
                    } => (slot.epoch(E::slots_per_epoch()), slot, "SYNC_COMMITTEE", true),
                    SignableMessage::SignedContributionAndProof(c) => {
                        (c.contribution.slot.epoch(E::slots_per_epoch()), c.contribution.slot, "CONTRIB", true)
                    }
                    SignableMessage::ValidatorRegistration(_) => (
                        Epoch::new(0),
                        Slot::new(0),
                        "VA_REG",
                        false,
                    ),
                    SignableMessage::VoluntaryExit(e) => {
                        (e.epoch, e.epoch.start_slot(E::slots_per_epoch()), "VA_EXIT", true)
                    }
                };

                let is_aggregator = operator_committee.is_leader(epoch.as_u64()) || operator_committee.is_backup(epoch.as_u64());

                info!(
                    operator_committee.log,
                    "Distributed Signing Method";
                    "Validator" => format!("{:?}", operator_committee.validator_public_key),
                    "Epoch" => epoch.as_u64(),
                    "Slot" => slot.as_u64(),
                    "Duty" => duty,
                    "Root" => format!("{:?}", signing_root),
                    "Is aggregator" => is_aggregator
                );
                
                let keypair = keypair.clone();
                let local_signature = executor
                    .spawn_blocking_handle(
                        move || keypair.sk.sign(signing_root),
                        "local_keystore_signer",
                    )
                    .ok_or(Error::ShuttingDown)?
                    .await
                    .map_err(|e| Error::TokioJoin(e.to_string()))?;
                store_sender.send((signing_root, local_signature.clone(), operator_committee.validator_public_key.clone())).await.unwrap();
                if !only_aggregator || (only_aggregator && is_aggregator) {
                    let task_timeout = Duration::from_secs(E::default_spec().seconds_per_slot * 2 / 3);
                    let timeout = sleep(task_timeout);
                    let work = operator_committee.sign(signing_root, local_signature, &executor);
                    let start_time: DateTime<Utc> = Utc::now();
                    tokio::select! {
                        result = work => {
                            match result {
                                Ok((signature, ids)) => {
                                    operator_committee.send_performance_report(epoch.as_u64(), slot.as_u64(), duty, operator_committee.validator_public_key.as_hex_string(), operator_committee.operator_id, ids, start_time).await.map_err(|e| {
                                        Error::CommitteeSignFailed(e)
                                    })?;
                                    Ok(signature)
                                },
                                Err(e) => {
                                    Err(Error::CommitteeSignFailed(format!("{:?}", e)))
                                }
                            }
                        }
                        _ = timeout => {
                            Err(Error::CommitteeSignFailed(format!("Timeout")))
                        }
                    }
                } else {
                    Err(Error::NotLeader)
                }
            }
        }
    }
}
