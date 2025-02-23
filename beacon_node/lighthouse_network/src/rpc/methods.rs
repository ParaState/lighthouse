//! Available RPC methods types and ids.

use crate::types::{EnrAttestationBitfield, EnrSyncCommitteeBitfield};
use regex::bytes::Regex;
use serde::Serialize;
use ssz::Encode;
use ssz_derive::{Decode, Encode};
use ssz_types::{typenum::U256, VariableList};
use std::collections::BTreeMap;
use std::fmt::Display;
use std::marker::PhantomData;
use std::ops::Deref;
use std::sync::Arc;
use strum::IntoStaticStr;
use superstruct::superstruct;
use types::blob_sidecar::BlobIdentifier;
use types::light_client_update::MAX_REQUEST_LIGHT_CLIENT_UPDATES;
use types::{
    blob_sidecar::BlobSidecar, ChainSpec, ColumnIndex, DataColumnIdentifier, DataColumnSidecar,
    Epoch, EthSpec, Hash256, LightClientBootstrap, LightClientFinalityUpdate,
    LightClientOptimisticUpdate, LightClientUpdate, RuntimeVariableList, SignedBeaconBlock, Slot,
};

/// Maximum length of error message.
pub type MaxErrorLen = U256;
pub const MAX_ERROR_LEN: u64 = 256;

/// Wrapper over SSZ List to represent error message in rpc responses.
#[derive(Debug, Clone)]
pub struct ErrorType(pub VariableList<u8, MaxErrorLen>);

impl From<String> for ErrorType {
    fn from(s: String) -> Self {
        Self(VariableList::from(s.as_bytes().to_vec()))
    }
}

impl From<&str> for ErrorType {
    fn from(s: &str) -> Self {
        Self(VariableList::from(s.as_bytes().to_vec()))
    }
}

impl Deref for ErrorType {
    type Target = VariableList<u8, MaxErrorLen>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Display for ErrorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[allow(clippy::invalid_regex)]
        let re = Regex::new("\\p{C}").expect("Regex is valid");
        let error_type_str =
            String::from_utf8_lossy(&re.replace_all(self.0.deref(), &b""[..])).to_string();
        write!(f, "{}", error_type_str)
    }
}

/* Request/Response data structures for RPC methods */

/* Requests */

/// The STATUS request/response handshake message.
#[derive(Encode, Decode, Clone, Debug, PartialEq)]
pub struct StatusMessage {
    /// The fork version of the chain we are broadcasting.
    pub fork_digest: [u8; 4],

    /// Latest finalized root.
    pub finalized_root: Hash256,

    /// Latest finalized epoch.
    pub finalized_epoch: Epoch,

    /// The latest block root.
    pub head_root: Hash256,

    /// The slot associated with the latest block root.
    pub head_slot: Slot,
}

/// The PING request/response message.
#[derive(Encode, Decode, Copy, Clone, Debug, PartialEq)]
pub struct Ping {
    /// The metadata sequence number.
    pub data: u64,
}

/// The METADATA request structure.
#[superstruct(
    variants(V1, V2, V3),
    variant_attributes(derive(Clone, Debug, PartialEq, Serialize),)
)]
#[derive(Clone, Debug, PartialEq)]
pub struct MetadataRequest<E: EthSpec> {
    _phantom_data: PhantomData<E>,
}

impl<E: EthSpec> MetadataRequest<E> {
    pub fn new_v1() -> Self {
        Self::V1(MetadataRequestV1 {
            _phantom_data: PhantomData,
        })
    }

    pub fn new_v2() -> Self {
        Self::V2(MetadataRequestV2 {
            _phantom_data: PhantomData,
        })
    }

    pub fn new_v3() -> Self {
        Self::V3(MetadataRequestV3 {
            _phantom_data: PhantomData,
        })
    }
}

/// The METADATA response structure.
#[superstruct(
    variants(V1, V2, V3),
    variant_attributes(
        derive(Encode, Decode, Clone, Debug, PartialEq, Serialize),
        serde(bound = "E: EthSpec", deny_unknown_fields),
    )
)]
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(bound = "E: EthSpec")]
pub struct MetaData<E: EthSpec> {
    /// A sequential counter indicating when data gets modified.
    pub seq_number: u64,
    /// The persistent attestation subnet bitfield.
    pub attnets: EnrAttestationBitfield<E>,
    /// The persistent sync committee bitfield.
    #[superstruct(only(V2, V3))]
    pub syncnets: EnrSyncCommitteeBitfield<E>,
    #[superstruct(only(V3))]
    pub custody_subnet_count: u64,
}

impl<E: EthSpec> MetaData<E> {
    /// Returns a V1 MetaData response from self.
    pub fn metadata_v1(&self) -> Self {
        match self {
            md @ MetaData::V1(_) => md.clone(),
            MetaData::V2(metadata) => MetaData::V1(MetaDataV1 {
                seq_number: metadata.seq_number,
                attnets: metadata.attnets.clone(),
            }),
            MetaData::V3(metadata) => MetaData::V1(MetaDataV1 {
                seq_number: metadata.seq_number,
                attnets: metadata.attnets.clone(),
            }),
        }
    }

    /// Returns a V2 MetaData response from self by filling unavailable fields with default.
    pub fn metadata_v2(&self) -> Self {
        match self {
            MetaData::V1(metadata) => MetaData::V2(MetaDataV2 {
                seq_number: metadata.seq_number,
                attnets: metadata.attnets.clone(),
                syncnets: Default::default(),
            }),
            md @ MetaData::V2(_) => md.clone(),
            MetaData::V3(metadata) => MetaData::V2(MetaDataV2 {
                seq_number: metadata.seq_number,
                attnets: metadata.attnets.clone(),
                syncnets: metadata.syncnets.clone(),
            }),
        }
    }

    /// Returns a V3 MetaData response from self by filling unavailable fields with default.
    pub fn metadata_v3(&self, spec: &ChainSpec) -> Self {
        match self {
            MetaData::V1(metadata) => MetaData::V3(MetaDataV3 {
                seq_number: metadata.seq_number,
                attnets: metadata.attnets.clone(),
                syncnets: Default::default(),
                custody_subnet_count: spec.custody_requirement,
            }),
            MetaData::V2(metadata) => MetaData::V3(MetaDataV3 {
                seq_number: metadata.seq_number,
                attnets: metadata.attnets.clone(),
                syncnets: metadata.syncnets.clone(),
                custody_subnet_count: spec.custody_requirement,
            }),
            md @ MetaData::V3(_) => md.clone(),
        }
    }

    pub fn as_ssz_bytes(&self) -> Vec<u8> {
        match self {
            MetaData::V1(md) => md.as_ssz_bytes(),
            MetaData::V2(md) => md.as_ssz_bytes(),
            MetaData::V3(md) => md.as_ssz_bytes(),
        }
    }
}

/// The reason given for a `Goodbye` message.
///
/// Note: any unknown `u64::into(n)` will resolve to `Goodbye::Unknown` for any unknown `n`,
/// however `GoodbyeReason::Unknown.into()` will go into `0_u64`. Therefore de-serializing then
/// re-serializing may not return the same bytes.
#[derive(Debug, Clone, PartialEq)]
pub enum GoodbyeReason {
    /// This node has shutdown.
    ClientShutdown = 1,

    /// Incompatible networks.
    IrrelevantNetwork = 2,

    /// Error/fault in the RPC.
    Fault = 3,

    /// Teku uses this code for not being able to verify a network.
    UnableToVerifyNetwork = 128,

    /// The node has too many connected peers.
    TooManyPeers = 129,

    /// Scored poorly.
    BadScore = 250,

    /// The peer is banned
    Banned = 251,

    /// The IP address the peer is using is banned.
    BannedIP = 252,

    /// Unknown reason.
    Unknown = 0,
}

impl From<u64> for GoodbyeReason {
    fn from(id: u64) -> GoodbyeReason {
        match id {
            1 => GoodbyeReason::ClientShutdown,
            2 => GoodbyeReason::IrrelevantNetwork,
            3 => GoodbyeReason::Fault,
            128 => GoodbyeReason::UnableToVerifyNetwork,
            129 => GoodbyeReason::TooManyPeers,
            250 => GoodbyeReason::BadScore,
            251 => GoodbyeReason::Banned,
            252 => GoodbyeReason::BannedIP,
            _ => GoodbyeReason::Unknown,
        }
    }
}

impl From<GoodbyeReason> for u64 {
    fn from(reason: GoodbyeReason) -> u64 {
        reason as u64
    }
}

impl ssz::Encode for GoodbyeReason {
    fn is_ssz_fixed_len() -> bool {
        <u64 as ssz::Encode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <u64 as ssz::Encode>::ssz_fixed_len()
    }

    fn ssz_bytes_len(&self) -> usize {
        0_u64.ssz_bytes_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let conv: u64 = self.clone().into();
        conv.ssz_append(buf)
    }
}

impl ssz::Decode for GoodbyeReason {
    fn is_ssz_fixed_len() -> bool {
        <u64 as ssz::Decode>::is_ssz_fixed_len()
    }

    fn ssz_fixed_len() -> usize {
        <u64 as ssz::Decode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        u64::from_ssz_bytes(bytes).map(|n| n.into())
    }
}

/// Request a number of beacon block roots from a peer.
#[superstruct(
    variants(V1, V2),
    variant_attributes(derive(Encode, Decode, Clone, Debug, PartialEq))
)]
#[derive(Clone, Debug, PartialEq)]
pub struct BlocksByRangeRequest {
    /// The starting slot to request blocks.
    pub start_slot: u64,

    /// The number of blocks from the start slot.
    pub count: u64,
}

impl BlocksByRangeRequest {
    /// The default request is V2
    pub fn new(start_slot: u64, count: u64) -> Self {
        Self::V2(BlocksByRangeRequestV2 { start_slot, count })
    }

    pub fn new_v1(start_slot: u64, count: u64) -> Self {
        Self::V1(BlocksByRangeRequestV1 { start_slot, count })
    }
}

/// Request a number of beacon blobs from a peer.
#[derive(Encode, Decode, Clone, Debug, PartialEq)]
pub struct BlobsByRangeRequest {
    /// The starting slot to request blobs.
    pub start_slot: u64,

    /// The number of slots from the start slot.
    pub count: u64,
}

impl BlobsByRangeRequest {
    pub fn max_blobs_requested<E: EthSpec>(&self) -> u64 {
        self.count.saturating_mul(E::max_blobs_per_block() as u64)
    }
}

/// Request a number of beacon data columns from a peer.
#[derive(Encode, Decode, Clone, Debug, PartialEq)]
pub struct DataColumnsByRangeRequest {
    /// The starting slot to request data columns.
    pub start_slot: u64,
    /// The number of slots from the start slot.
    pub count: u64,
    /// The list column indices being requested.
    pub columns: Vec<ColumnIndex>,
}

impl DataColumnsByRangeRequest {
    pub fn max_requested<E: EthSpec>(&self) -> u64 {
        self.count.saturating_mul(self.columns.len() as u64)
    }

    pub fn ssz_min_len() -> usize {
        DataColumnsByRangeRequest {
            start_slot: 0,
            count: 0,
            columns: vec![0],
        }
        .as_ssz_bytes()
        .len()
    }

    pub fn ssz_max_len(spec: &ChainSpec) -> usize {
        DataColumnsByRangeRequest {
            start_slot: 0,
            count: 0,
            columns: vec![0; spec.number_of_columns],
        }
        .as_ssz_bytes()
        .len()
    }
}

/// Request a number of beacon block roots from a peer.
#[superstruct(
    variants(V1, V2),
    variant_attributes(derive(Encode, Decode, Clone, Debug, PartialEq))
)]
#[derive(Clone, Debug, PartialEq)]
pub struct OldBlocksByRangeRequest {
    /// The starting slot to request blocks.
    pub start_slot: u64,

    /// The number of blocks from the start slot.
    pub count: u64,

    /// The step increment to receive blocks.
    ///
    /// A value of 1 returns every block.
    /// A value of 2 returns every second block.
    /// A value of 3 returns every third block and so on.
    pub step: u64,
}

impl OldBlocksByRangeRequest {
    /// The default request is V2
    pub fn new(start_slot: u64, count: u64, step: u64) -> Self {
        Self::V2(OldBlocksByRangeRequestV2 {
            start_slot,
            count,
            step,
        })
    }

    pub fn new_v1(start_slot: u64, count: u64, step: u64) -> Self {
        Self::V1(OldBlocksByRangeRequestV1 {
            start_slot,
            count,
            step,
        })
    }
}

/// Request a number of beacon block bodies from a peer.
#[superstruct(variants(V1, V2), variant_attributes(derive(Clone, Debug, PartialEq)))]
#[derive(Clone, Debug, PartialEq)]
pub struct BlocksByRootRequest {
    /// The list of beacon block bodies being requested.
    pub block_roots: RuntimeVariableList<Hash256>,
}

impl BlocksByRootRequest {
    pub fn new(block_roots: Vec<Hash256>, spec: &ChainSpec) -> Self {
        let block_roots =
            RuntimeVariableList::from_vec(block_roots, spec.max_request_blocks as usize);
        Self::V2(BlocksByRootRequestV2 { block_roots })
    }

    pub fn new_v1(block_roots: Vec<Hash256>, spec: &ChainSpec) -> Self {
        let block_roots =
            RuntimeVariableList::from_vec(block_roots, spec.max_request_blocks as usize);
        Self::V1(BlocksByRootRequestV1 { block_roots })
    }
}

/// Request a number of beacon blocks and blobs from a peer.
#[derive(Clone, Debug, PartialEq)]
pub struct BlobsByRootRequest {
    /// The list of beacon block roots being requested.
    pub blob_ids: RuntimeVariableList<BlobIdentifier>,
}

impl BlobsByRootRequest {
    pub fn new(blob_ids: Vec<BlobIdentifier>, spec: &ChainSpec) -> Self {
        let blob_ids =
            RuntimeVariableList::from_vec(blob_ids, spec.max_request_blob_sidecars as usize);
        Self { blob_ids }
    }
}

/// Request a number of data columns from a peer.
#[derive(Clone, Debug, PartialEq)]
pub struct DataColumnsByRootRequest {
    /// The list of beacon block roots and column indices being requested.
    pub data_column_ids: RuntimeVariableList<DataColumnIdentifier>,
}

impl DataColumnsByRootRequest {
    pub fn new(data_column_ids: Vec<DataColumnIdentifier>, spec: &ChainSpec) -> Self {
        let data_column_ids = RuntimeVariableList::from_vec(
            data_column_ids,
            spec.max_request_data_column_sidecars as usize,
        );
        Self { data_column_ids }
    }

    pub fn new_single(block_root: Hash256, index: ColumnIndex, spec: &ChainSpec) -> Self {
        Self::new(vec![DataColumnIdentifier { block_root, index }], spec)
    }

    pub fn group_by_ordered_block_root(&self) -> Vec<(Hash256, Vec<ColumnIndex>)> {
        let mut column_indexes_by_block = BTreeMap::<Hash256, Vec<ColumnIndex>>::new();
        for request_id in self.data_column_ids.as_slice() {
            column_indexes_by_block
                .entry(request_id.block_root)
                .or_default()
                .push(request_id.index);
        }
        column_indexes_by_block.into_iter().collect()
    }
}

/// Request a number of beacon data columns from a peer.
#[derive(Encode, Decode, Clone, Debug, PartialEq)]
pub struct LightClientUpdatesByRangeRequest {
    /// The starting period to request light client updates.
    pub start_period: u64,
    /// The number of periods from `start_period`.
    pub count: u64,
}

impl LightClientUpdatesByRangeRequest {
    pub fn max_requested(&self) -> u64 {
        MAX_REQUEST_LIGHT_CLIENT_UPDATES
    }

    pub fn ssz_min_len() -> usize {
        LightClientUpdatesByRangeRequest {
            start_period: 0,
            count: 0,
        }
        .as_ssz_bytes()
        .len()
    }

    pub fn ssz_max_len() -> usize {
        Self::ssz_min_len()
    }
}

/* RPC Handling and Grouping */
// Collection of enums and structs used by the Codecs to encode/decode RPC messages

#[derive(Debug, Clone, PartialEq)]
pub enum RpcSuccessResponse<E: EthSpec> {
    /// A HELLO message.
    Status(StatusMessage),

    /// A response to a get BLOCKS_BY_RANGE request. A None response signifies the end of the
    /// batch.
    BlocksByRange(Arc<SignedBeaconBlock<E>>),

    /// A response to a get BLOCKS_BY_ROOT request.
    BlocksByRoot(Arc<SignedBeaconBlock<E>>),

    /// A response to a get BLOBS_BY_RANGE request
    BlobsByRange(Arc<BlobSidecar<E>>),

    /// A response to a get LIGHT_CLIENT_BOOTSTRAP request.
    LightClientBootstrap(Arc<LightClientBootstrap<E>>),

    /// A response to a get LIGHT_CLIENT_OPTIMISTIC_UPDATE request.
    LightClientOptimisticUpdate(Arc<LightClientOptimisticUpdate<E>>),

    /// A response to a get LIGHT_CLIENT_FINALITY_UPDATE request.
    LightClientFinalityUpdate(Arc<LightClientFinalityUpdate<E>>),

    /// A response to a get LIGHT_CLIENT_UPDATES_BY_RANGE request.
    LightClientUpdatesByRange(Arc<LightClientUpdate<E>>),

    /// A response to a get BLOBS_BY_ROOT request.
    BlobsByRoot(Arc<BlobSidecar<E>>),

    /// A response to a get DATA_COLUMN_SIDECARS_BY_ROOT request.
    DataColumnsByRoot(Arc<DataColumnSidecar<E>>),

    /// A response to a get DATA_COLUMN_SIDECARS_BY_RANGE request.
    DataColumnsByRange(Arc<DataColumnSidecar<E>>),

    /// A PONG response to a PING request.
    Pong(Ping),

    /// A response to a META_DATA request.
    MetaData(MetaData<E>),
}

/// Indicates which response is being terminated by a stream termination response.
#[derive(Debug, Clone)]
pub enum ResponseTermination {
    /// Blocks by range stream termination.
    BlocksByRange,

    /// Blocks by root stream termination.
    BlocksByRoot,

    /// Blobs by range stream termination.
    BlobsByRange,

    /// Blobs by root stream termination.
    BlobsByRoot,

    /// Data column sidecars by root stream termination.
    DataColumnsByRoot,

    /// Data column sidecars by range stream termination.
    DataColumnsByRange,

    /// Light client updates by range stream termination.
    LightClientUpdatesByRange,
}

/// The structured response containing a result/code indicating success or failure
/// and the contents of the response
#[derive(Debug, Clone)]
pub enum RpcResponse<E: EthSpec> {
    /// The response is a successful.
    Success(RpcSuccessResponse<E>),

    Error(RpcErrorResponse, ErrorType),

    /// Received a stream termination indicating which response is being terminated.
    StreamTermination(ResponseTermination),
}

/// Request a light_client_bootstrap for light_clients peers.
#[derive(Encode, Decode, Clone, Debug, PartialEq)]
pub struct LightClientBootstrapRequest {
    pub root: Hash256,
}

/// The code assigned to an erroneous `RPCResponse`.
#[derive(Debug, Clone, Copy, PartialEq, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum RpcErrorResponse {
    RateLimited,
    BlobsNotFoundForBlock,
    InvalidRequest,
    ServerError,
    /// Error spec'd to indicate that a peer does not have blocks on a requested range.
    ResourceUnavailable,
    Unknown,
}

impl<E: EthSpec> RpcResponse<E> {
    /// Used to encode the response in the codec.
    pub fn as_u8(&self) -> Option<u8> {
        match self {
            RpcResponse::Success(_) => Some(0),
            RpcResponse::Error(code, _) => Some(code.as_u8()),
            RpcResponse::StreamTermination(_) => None,
        }
    }

    /// Tells the codec whether to decode as an RPCResponse or an error.
    pub fn is_response(response_code: u8) -> bool {
        matches!(response_code, 0)
    }

    /// Builds an RPCCodedResponse from a response code and an ErrorMessage
    pub fn from_error(response_code: u8, err: ErrorType) -> Self {
        let code = match response_code {
            1 => RpcErrorResponse::InvalidRequest,
            2 => RpcErrorResponse::ServerError,
            3 => RpcErrorResponse::ResourceUnavailable,
            139 => RpcErrorResponse::RateLimited,
            140 => RpcErrorResponse::BlobsNotFoundForBlock,
            _ => RpcErrorResponse::Unknown,
        };
        RpcResponse::Error(code, err)
    }

    /// Returns true if this response always terminates the stream.
    pub fn close_after(&self) -> bool {
        !matches!(self, RpcResponse::Success(_))
    }
}

impl RpcErrorResponse {
    fn as_u8(&self) -> u8 {
        match self {
            RpcErrorResponse::InvalidRequest => 1,
            RpcErrorResponse::ServerError => 2,
            RpcErrorResponse::ResourceUnavailable => 3,
            RpcErrorResponse::Unknown => 255,
            RpcErrorResponse::RateLimited => 139,
            RpcErrorResponse::BlobsNotFoundForBlock => 140,
        }
    }
}

use super::Protocol;
impl<E: EthSpec> RpcSuccessResponse<E> {
    pub fn protocol(&self) -> Protocol {
        match self {
            RpcSuccessResponse::Status(_) => Protocol::Status,
            RpcSuccessResponse::BlocksByRange(_) => Protocol::BlocksByRange,
            RpcSuccessResponse::BlocksByRoot(_) => Protocol::BlocksByRoot,
            RpcSuccessResponse::BlobsByRange(_) => Protocol::BlobsByRange,
            RpcSuccessResponse::BlobsByRoot(_) => Protocol::BlobsByRoot,
            RpcSuccessResponse::DataColumnsByRoot(_) => Protocol::DataColumnsByRoot,
            RpcSuccessResponse::DataColumnsByRange(_) => Protocol::DataColumnsByRange,
            RpcSuccessResponse::Pong(_) => Protocol::Ping,
            RpcSuccessResponse::MetaData(_) => Protocol::MetaData,
            RpcSuccessResponse::LightClientBootstrap(_) => Protocol::LightClientBootstrap,
            RpcSuccessResponse::LightClientOptimisticUpdate(_) => {
                Protocol::LightClientOptimisticUpdate
            }
            RpcSuccessResponse::LightClientFinalityUpdate(_) => Protocol::LightClientFinalityUpdate,
            RpcSuccessResponse::LightClientUpdatesByRange(_) => Protocol::LightClientUpdatesByRange,
        }
    }
}

impl std::fmt::Display for RpcErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let repr = match self {
            RpcErrorResponse::InvalidRequest => "The request was invalid",
            RpcErrorResponse::ResourceUnavailable => "Resource unavailable",
            RpcErrorResponse::ServerError => "Server error occurred",
            RpcErrorResponse::Unknown => "Unknown error occurred",
            RpcErrorResponse::RateLimited => "Rate limited",
            RpcErrorResponse::BlobsNotFoundForBlock => "No blobs for the given root",
        };
        f.write_str(repr)
    }
}

impl std::fmt::Display for StatusMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Status Message: Fork Digest: {:?}, Finalized Root: {}, Finalized Epoch: {}, Head Root: {}, Head Slot: {}", self.fork_digest, self.finalized_root, self.finalized_epoch, self.head_root, self.head_slot)
    }
}

impl<E: EthSpec> std::fmt::Display for RpcSuccessResponse<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcSuccessResponse::Status(status) => write!(f, "{}", status),
            RpcSuccessResponse::BlocksByRange(block) => {
                write!(f, "BlocksByRange: Block slot: {}", block.slot())
            }
            RpcSuccessResponse::BlocksByRoot(block) => {
                write!(f, "BlocksByRoot: Block slot: {}", block.slot())
            }
            RpcSuccessResponse::BlobsByRange(blob) => {
                write!(f, "BlobsByRange: Blob slot: {}", blob.slot())
            }
            RpcSuccessResponse::BlobsByRoot(sidecar) => {
                write!(f, "BlobsByRoot: Blob slot: {}", sidecar.slot())
            }
            RpcSuccessResponse::DataColumnsByRoot(sidecar) => {
                write!(f, "DataColumnsByRoot: Data column slot: {}", sidecar.slot())
            }
            RpcSuccessResponse::DataColumnsByRange(sidecar) => {
                write!(
                    f,
                    "DataColumnsByRange: Data column slot: {}",
                    sidecar.slot()
                )
            }
            RpcSuccessResponse::Pong(ping) => write!(f, "Pong: {}", ping.data),
            RpcSuccessResponse::MetaData(metadata) => {
                write!(f, "Metadata: {}", metadata.seq_number())
            }
            RpcSuccessResponse::LightClientBootstrap(bootstrap) => {
                write!(f, "LightClientBootstrap Slot: {}", bootstrap.get_slot())
            }
            RpcSuccessResponse::LightClientOptimisticUpdate(update) => {
                write!(
                    f,
                    "LightClientOptimisticUpdate Slot: {}",
                    update.signature_slot()
                )
            }
            RpcSuccessResponse::LightClientFinalityUpdate(update) => {
                write!(
                    f,
                    "LightClientFinalityUpdate Slot: {}",
                    update.signature_slot()
                )
            }
            RpcSuccessResponse::LightClientUpdatesByRange(update) => {
                write!(
                    f,
                    "LightClientUpdatesByRange Slot: {}",
                    update.signature_slot(),
                )
            }
        }
    }
}

impl<E: EthSpec> std::fmt::Display for RpcResponse<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcResponse::Success(res) => write!(f, "{}", res),
            RpcResponse::Error(code, err) => write!(f, "{}: {}", code, err),
            RpcResponse::StreamTermination(_) => write!(f, "Stream Termination"),
        }
    }
}

impl std::fmt::Display for GoodbyeReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GoodbyeReason::ClientShutdown => write!(f, "Client Shutdown"),
            GoodbyeReason::IrrelevantNetwork => write!(f, "Irrelevant Network"),
            GoodbyeReason::Fault => write!(f, "Fault"),
            GoodbyeReason::UnableToVerifyNetwork => write!(f, "Unable to verify network"),
            GoodbyeReason::TooManyPeers => write!(f, "Too many peers"),
            GoodbyeReason::BadScore => write!(f, "Bad Score"),
            GoodbyeReason::Banned => write!(f, "Banned"),
            GoodbyeReason::BannedIP => write!(f, "BannedIP"),
            GoodbyeReason::Unknown => write!(f, "Unknown Reason"),
        }
    }
}

impl std::fmt::Display for BlocksByRangeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Start Slot: {}, Count: {}",
            self.start_slot(),
            self.count()
        )
    }
}

impl std::fmt::Display for OldBlocksByRangeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Start Slot: {}, Count: {}, Step: {}",
            self.start_slot(),
            self.count(),
            self.step()
        )
    }
}

impl std::fmt::Display for BlobsByRootRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Request: BlobsByRoot: Number of Requested Roots: {}",
            self.blob_ids.len()
        )
    }
}

impl std::fmt::Display for BlobsByRangeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Request: BlobsByRange: Start Slot: {}, Count: {}",
            self.start_slot, self.count
        )
    }
}

impl std::fmt::Display for DataColumnsByRootRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Request: DataColumnsByRoot: Number of Requested Data Column Ids: {}",
            self.data_column_ids.len()
        )
    }
}

impl slog::KV for StatusMessage {
    fn serialize(
        &self,
        record: &slog::Record,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        use slog::Value;
        serializer.emit_arguments("fork_digest", &format_args!("{:?}", self.fork_digest))?;
        Value::serialize(&self.finalized_epoch, record, "finalized_epoch", serializer)?;
        serializer.emit_arguments("finalized_root", &format_args!("{}", self.finalized_root))?;
        Value::serialize(&self.head_slot, record, "head_slot", serializer)?;
        serializer.emit_arguments("head_root", &format_args!("{}", self.head_root))?;
        slog::Result::Ok(())
    }
}
