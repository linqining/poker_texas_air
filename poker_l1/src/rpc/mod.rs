//! RPC server（Task 31 — SubTask 31.1 / 31.2 / 31.3）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）：
//! - **SubTask 31.1**：JSON-RPC 方法
//!   - `get_block(hash | height)` / `get_object(id)` / `get_tx(hash)`
//!   - `submit_tx(tx_bytes)` / `get_account(address | pubkey)` / `get_dag_vertex(hash)`
//!   - `get_native_balance` / `get_native_coins` / `select_native_coins`
//! - **SubTask 31.2**：WebSocket 订阅事件（block / vertex / tx）
//! - **SubTask 31.3**：crypto verify RPC
//!   - `secp256k1_aggregate_verify(pubkeys, msg_hashes, sigs)`
//!   - `bls_verify(pubkey_g2, signature_g1, msg)`
//!   - `zk_verify(scheme_id, proof, public_io)`
//!
//! 实现说明：
//! - 本模块定义 RPC 请求/响应类型、[`RpcBackend`] trait、[`RpcHandler`] 派发器
//! - 不绑定具体传输层（HTTP / WebSocket）；由上层 node 二进制集成 axum / tungstenite
//! - 纯库代码，可单元测试；集成测试见 `tests/phase6_integration.rs`

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::account::{Account, AccountStore, derive_address};
use crate::block::Block;
use crate::block::validator::{validate_tx_chain_id, validate_tx_nonce, validate_tx_signature};
use crate::consensus::DagVertex;
use crate::crypto_precompiles::native_api::{
    bls_verify as native_bls_verify,
    secp256k1_aggregate_verify as native_secp256k1_aggregate_verify,
};
use crate::economics::{
    OwnedNativeCoin, list_owned_native_coins, select_native_coins_from_candidates,
    sum_native_coin_balance,
};
use crate::error::{PokerL1Error, PokerL1Result};
use crate::indexer::{BlockFilter, IndexedBlock, IndexedTransaction, IndexerEvent, TxFilter};
use crate::object_model::{Object, ObjectID};
use crate::offline::zk_verifier::{SchemeId, ZkPublicIo, ZkVerifierRegistry, ZkVerifyResult};
use crate::signature::TaggedPubkey;
use crate::storage::{BlockStore, DagVertexStore, ObjectDb};
use crate::transaction::{Transaction, TxLane, validate_tx_limits};
use crate::{Address, BlockHeight, ChainId, Hash};

/// Bound indexed-query response construction independently of the wire-level JSON size limit.
const MAX_INDEX_QUERY_RESULTS: usize = 1_000;

/// JSON-RPC 2.0 请求（spec：https://www.jsonrpc.org/specification）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// 协议版本（固定 "2.0"）。
    pub jsonrpc: String,
    /// 方法名。
    pub method: String,
    /// 参数（位置参数）。
    pub params: serde_json::Value,
    /// 请求 ID（由客户端提供，原样回传）。
    pub id: serde_json::Value,
}

/// JSON-RPC 2.0 响应。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// 协议版本。
    pub jsonrpc: String,
    /// 结果（成功时）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// 错误（失败时）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    /// 请求 ID（原样回传）。
    pub id: serde_json::Value,
}

/// JSON-RPC 错误对象。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// 错误码（标准 JSON-RPC 错误码或自定义 -32xxx）。
    pub code: i32,
    /// 错误消息。
    pub message: String,
    /// 额外数据（可选）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl JsonRpcError {
    /// 解析错误（-32700）。
    pub const PARSE_ERROR: i32 = -32700;
    /// 无效请求（-32600）。
    pub const INVALID_REQUEST: i32 = -32600;
    /// 方法未找到（-32601）。
    pub const METHOD_NOT_FOUND: i32 = -32601;
    /// 无效参数（-32602）。
    pub const INVALID_PARAMS: i32 = -32602;
    /// 内部错误（-32603）。
    pub const INTERNAL_ERROR: i32 = -32603;

    /// 构造错误对象。
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// 构造带额外数据的错误对象。
    pub fn with_data(code: i32, message: impl Into<String>, data: serde_json::Value) -> Self {
        Self {
            code,
            message: message.into(),
            data: Some(data),
        }
    }
}

impl JsonRpcResponse {
    /// 成功响应。
    pub fn success(result: serde_json::Value, id: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    /// 错误响应。
    pub fn error(err: JsonRpcError, id: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(err),
            id,
        }
    }
}

// ===== SubTask 31.1: JSON-RPC 方法参数与返回类型 =====

/// `get_block` 参数（按 hash 或 height 查询）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GetBlockParams {
    /// 按 block_hash 查询。
    ByHash {
        /// block hash。
        hash: Hash,
    },
    /// 按 height 查询。
    ByHeight {
        /// block height。
        height: BlockHeight,
    },
}

/// `get_object` 参数。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetObjectParams {
    /// 对象 ID。
    pub id: ObjectID,
}

/// `get_tx` 参数。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetTxParams {
    /// tx hash。
    pub tx_hash: Hash,
}

/// `submit_tx` 参数。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitTxParams {
    /// BCS 编码的 tx 字节。
    pub tx_bytes: Vec<u8>,
}

/// `submit_tx` 返回。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitTxResult {
    /// 计算出的 tx hash。
    pub tx_hash: Hash,
}

/// `get_account` 参数（按 address 或 tagged pubkey 查询）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GetAccountParams {
    /// 按 20 字节 address 查询。
    ByAddress {
        /// 账户地址。
        address: Address,
    },
    /// 按 tagged pubkey 查询（库内部派生 address）。
    ByPubkey {
        /// 账户绑定的 tagged pubkey。
        tagged_pubkey: TaggedPubkey,
    },
}

/// `get_dag_vertex` 参数。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetDagVertexParams {
    /// vertex hash。
    pub vertex_hash: Hash,
}

/// `get_native_balance` / `get_native_coins` parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GetNativeCoinsParams {
    /// Query by the 20-byte owner address.
    ByAddress {
        /// Native-coin owner.
        address: Address,
    },
    /// Query by tagged public key; the node derives the owner address.
    ByPubkey {
        /// Wallet tagged public key.
        tagged_pubkey: TaggedPubkey,
    },
}

/// `select_native_coins` parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SelectNativeCoinsParams {
    /// Select coins by owner address.
    ByAddress {
        /// Native-coin owner.
        address: Address,
        /// Required amount in indivisible ZCN base units.
        required: u64,
    },
    /// Select coins by tagged public key.
    ByPubkey {
        /// Wallet tagged public key.
        tagged_pubkey: TaggedPubkey,
        /// Required amount in indivisible ZCN base units.
        required: u64,
    },
}

/// Aggregated native-coin balance returned to wallets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeBalanceResult {
    /// Owner address used for the query.
    pub owner: Address,
    /// Sum of all live native-coin outputs owned by the address.
    pub balance: u64,
    /// Number of live native-coin outputs hidden behind the aggregated balance.
    pub coin_count: u64,
}

/// Advisory deterministic coin selection returned to wallets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectNativeCoinsResult {
    /// Owner address used for selection.
    pub owner: Address,
    /// Coin object IDs to place in the signed transaction's `inputs` field.
    pub input_ids: Vec<ObjectID>,
    /// Sum of selected inputs.
    pub total: u64,
    /// Deterministic change amount that execution will return to the owner.
    pub change: u64,
}

// ===== SubTask 31.3: crypto verify RPC 参数与返回类型 =====

/// `secp256k1_aggregate_verify` 参数。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Secp256k1AggregateVerifyParams {
    /// N 个 tagged pubkey。
    pub pubkeys: Vec<TaggedPubkey>,
    /// N 个消息哈希（每个 32 字节）。
    pub msg_hashes: Vec<Hash>,
    /// N 个签名字节。
    pub sigs: Vec<Vec<u8>>,
}

/// `secp256k1_aggregate_verify` 返回。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Secp256k1AggregateVerifyResult {
    /// 全部签名验证通过返回 true，任一失败返回 false。
    pub verified: bool,
}

/// `bls_verify` 参数。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlsVerifyParams {
    /// 签名者公钥（G2 compressed，96 字节）。
    pub pubkey_g2: Vec<u8>,
    /// 签名（G1 compressed，48 字节）。
    pub signature_g1: Vec<u8>,
    /// 被签名的消息。
    pub msg: Vec<u8>,
}

/// `bls_verify` 返回。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlsVerifyResult {
    /// 验证结果。
    pub verified: bool,
}

/// `zk_verify` 参数。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkVerifyParams {
    /// ZK 证明 scheme_id（1=Stwo / 2=Groth16 / 3=IPA）。
    pub scheme_id: SchemeId,
    /// proof 字节。
    pub proof: Vec<u8>,
    /// public_io（序列化为 BCS 字节）。
    pub public_io_bytes: Vec<u8>,
    /// max_skip_segments 上限。
    pub max_skip_segments: u32,
    /// max_ack_chain_length 上限。
    pub max_ack_chain_length: u32,
}

/// `zk_verify` 返回。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkVerifyRpcResult {
    /// 验证结果。
    pub verified: bool,
    /// 当前 verifier_status（Stub / Production）。
    pub verifier_status: String,
    /// scheme_id。
    pub scheme_id: SchemeId,
}

// ===== SubTask 31.2: WebSocket 订阅 =====

/// WebSocket 订阅事件类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventType {
    /// 新 block 事件。
    Block,
    /// 新 DAG vertex 事件。
    Vertex,
    /// 新 tx 事件。
    Transaction,
}

/// WebSocket 订阅请求。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscribeRequest {
    /// 订阅的事件类型列表。
    pub event_types: Vec<EventType>,
    /// Optional transaction filter, applied only to transaction events.
    #[serde(default)]
    pub tx_filter: Option<TxFilter>,
}

/// WebSocket 订阅响应。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscribeResponse {
    /// 订阅 ID（用于后续取消订阅）。
    pub subscription_id: u64,
}

/// WebSocket 取消订阅请求。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsubscribeRequest {
    /// 订阅 ID。
    pub subscription_id: u64,
}

/// Pull all currently queued events for one subscription.  This works over the existing TCP
/// JSON-RPC transport; a future WebSocket adapter can use the same backend subscription IDs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PollSubscriptionRequest {
    /// Subscription ID returned by `subscribe`.
    pub subscription_id: u64,
}

/// Parameters for querying indexed output objects by their initial address owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryObjectsByOwnerRequest {
    /// Address that owned the object at creation time.
    pub owner: Address,
}

/// Parameters for querying indexed output objects by their type string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryObjectsByTypeRequest {
    /// Canonical object type.
    pub object_type: String,
}

/// WebSocket 推送的事件消息。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventMessage {
    /// 订阅 ID。
    pub subscription_id: u64,
    /// 事件类型。
    pub event_type: EventType,
    /// 事件载荷（BCS 字节，客户端按 event_type 反序列化）。
    pub payload: Vec<u8>,
}

// ===== H-1 修复：RPC 认证与限流 =====

/// RPC 方法类别（用于差异化限流）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RpcMethodCategory {
    /// 读请求（get_block / get_object / get_tx / get_account / get_dag_vertex）。
    Read,
    /// 写请求（submit_tx）。
    Write,
    /// 加密验证请求（secp256k1_aggregate_verify / bls_verify / zk_verify）。
    Crypto,
}

impl RpcMethodCategory {
    /// 根据方法名推断类别。
    pub fn from_method(method: &str) -> Self {
        match method {
            "submit_tx" => Self::Write,
            "secp256k1_aggregate_verify" | "bls_verify" | "zk_verify" => Self::Crypto,
            _ => Self::Read,
        }
    }
}

/// RPC 限流配置（H-1 修复）。
///
/// 使用滑动窗口算法，按客户端独立计数。
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// 读请求：每秒最大请求数。
    pub read_rps: u32,
    /// 写请求：每秒最大请求数。
    pub write_rps: u32,
    /// 加密验证请求：每秒最大请求数。
    pub crypto_rps: u32,
    /// 滑动窗口大小。
    pub window: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            read_rps: 100,
            write_rps: 10,
            crypto_rps: 5,
            window: Duration::from_secs(1),
        }
    }
}

/// RPC 认证配置（H-1 修复）。
#[derive(Debug, Clone, Default)]
pub struct AuthConfig {
    /// 是否要求 write 端点认证。
    pub require_auth_for_write: bool,
    /// 是否要求 crypto 端点认证。
    pub require_auth_for_crypto: bool,
    /// 允许的 API key 集合。
    pub allowed_api_keys: HashSet<String>,
}

/// RPC 客户端身份信息（H-1 修复 — 用于认证与限流）。
///
/// 由传输层（HTTP server / WebSocket）提取并传入。
#[derive(Debug, Clone, Default)]
pub struct RpcClientInfo {
    /// 客户端标识（IP 地址或连接 ID，用于限流）。
    pub client_id: Option<String>,
    /// API key（由请求头 `X-API-Key` 提供）。
    pub api_key: Option<String>,
}

/// 滑动窗口内记录的请求时间戳。
struct SlidingWindow {
    timestamps: VecDeque<Instant>,
}

/// RPC 安全守卫（H-1 修复 — 限流 + 认证）。
///
/// 由 `RpcHandler` 持有，在 `handle_with_client` 中对每个请求执行：
/// 1. 认证检查（write/crypto 端点可能要求 API key）
/// 2. 限流检查（按 client_id + 方法类别独立计数）
pub struct RpcGuard {
    /// 限流配置。
    rate_limit_config: RateLimitConfig,
    /// 认证配置。
    auth_config: AuthConfig,
    /// per-client per-category 滑动窗口。
    windows: Mutex<HashMap<(String, RpcMethodCategory), SlidingWindow>>,
}

impl std::fmt::Debug for RpcGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RpcGuard")
            .field("rate_limit_config", &self.rate_limit_config)
            .field("auth_config", &self.auth_config)
            .finish_non_exhaustive()
    }
}

/// RPC 守卫检查结果错误。
#[derive(Debug)]
pub enum RpcGuardError {
    /// 认证失败。
    Auth(String),
    /// 限流超限。
    RateLimited(String),
}

impl RpcGuard {
    /// 创建守卫。
    pub fn new(rate_limit_config: RateLimitConfig, auth_config: AuthConfig) -> Self {
        Self {
            rate_limit_config,
            auth_config,
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// 创建无需认证的守卫（仅限流）。
    pub fn rate_limit_only(config: RateLimitConfig) -> Self {
        Self::new(config, AuthConfig::default())
    }

    /// 创建默认配置的守卫。
    pub fn default_config() -> Self {
        Self::new(RateLimitConfig::default(), AuthConfig::default())
    }

    /// 检查请求是否通过认证与限流。
    ///
    /// 返回 `Ok(())` 表示通过，`Err(RpcGuardError)` 表示被拒绝。
    pub fn check(&self, method: &str, client: &RpcClientInfo) -> Result<(), RpcGuardError> {
        let category = RpcMethodCategory::from_method(method);

        // 1. 认证检查
        self.check_auth(category, client)?;

        // 2. 限流检查
        self.check_rate_limit(category, client)?;

        Ok(())
    }

    /// 认证检查。
    fn check_auth(
        &self,
        category: RpcMethodCategory,
        client: &RpcClientInfo,
    ) -> Result<(), RpcGuardError> {
        let need_auth = match category {
            RpcMethodCategory::Write => self.auth_config.require_auth_for_write,
            RpcMethodCategory::Crypto => self.auth_config.require_auth_for_crypto,
            RpcMethodCategory::Read => false,
        };

        if need_auth {
            let api_key = client
                .api_key
                .as_ref()
                .ok_or_else(|| RpcGuardError::Auth("此端点要求 API key 认证".to_string()))?;

            if !self.auth_config.allowed_api_keys.contains(api_key) {
                return Err(RpcGuardError::Auth("无效的 API key".to_string()));
            }
        }

        Ok(())
    }

    /// 限流检查（滑动窗口）。
    fn check_rate_limit(
        &self,
        category: RpcMethodCategory,
        client: &RpcClientInfo,
    ) -> Result<(), RpcGuardError> {
        let client_id = client.client_id.as_deref().unwrap_or("anonymous");
        let max_rps = match category {
            RpcMethodCategory::Read => self.rate_limit_config.read_rps,
            RpcMethodCategory::Write => self.rate_limit_config.write_rps,
            RpcMethodCategory::Crypto => self.rate_limit_config.crypto_rps,
        };

        let key = (client_id.to_string(), category);
        let now = Instant::now();
        let window = self.rate_limit_config.window;

        let mut windows = self.windows.lock().unwrap_or_else(|e| e.into_inner());
        let entry = windows.entry(key).or_insert_with(|| SlidingWindow {
            timestamps: VecDeque::with_capacity(max_rps as usize + 1),
        });

        // 淘汰窗口外的旧时间戳
        while entry
            .timestamps
            .front()
            .is_some_and(|&t| now.duration_since(t) > window)
        {
            entry.timestamps.pop_front();
        }

        if entry.timestamps.len() >= max_rps as usize {
            return Err(RpcGuardError::RateLimited(format!(
                "请求频率超限：{category:?} 上限 {max_rps} req/{window:?}"
            )));
        }

        entry.timestamps.push_back(now);
        Ok(())
    }
}

/// 限流拒绝错误码（JSON-RPC 自定义错误码 -32001）。
pub const RATE_LIMIT_EXCEEDED: i32 = -32001;
/// 认证失败错误码（JSON-RPC 自定义错误码 -32002）。
pub const AUTH_FAILED: i32 = -32002;

/// JSON-RPC 请求 params 最大字节数（L-4 修复 — 防止非 tx 方法的超大 payload DoS）。
pub const MAX_RPC_PARAMS_SIZE: usize = 256 * 1024;

// ===== M-5 修复：RPC 错误脱敏 =====

/// RPC handler 处理错误（M-5 修复 — 区分客户端错误与内部错误以使用正确错误码）。
///
/// - `Client`：客户端可见错误（无效参数 / 签名失败 / nonce 不匹配等），
///   映射到 JSON-RPC `INVALID_PARAMS` (-32602)
/// - `Internal`：内部错误（存储 / 序列化 / VM 执行等），已脱敏，
///   映射到 JSON-RPC `INTERNAL_ERROR` (-32603)，详细原因通过 tracing 记录
#[derive(Debug)]
pub enum RpcHandlerError {
    /// 客户端错误 — 消息可直接返回给客户端。
    Client(String),
    /// 内部错误 — 消息已脱敏，实际错误已通过 tracing 记录。
    Internal(String),
}

impl RpcHandlerError {
    /// 从 `PokerL1Error` 构造，自动判断客户端/内部错误并脱敏。
    pub fn from_poker_error(e: PokerL1Error) -> Self {
        match &e {
            // 内部错误 — 脱敏，仅返回通用消息，详细原因记录到日志
            PokerL1Error::Rocksdb(_)
            | PokerL1Error::Serialization(_)
            | PokerL1Error::Other(_)
            | PokerL1Error::Secp256k1(_)
            | PokerL1Error::NetworkTransport(_)
            | PokerL1Error::SyncError(_)
            | PokerL1Error::ContractExecutionFailed(_)
            | PokerL1Error::SyscallPanic(_) => {
                tracing::warn!(error = %e, "RPC internal error (sanitized)");
                Self::Internal("internal server error".to_string())
            }
            // 客户端可见错误 — 保留具体消息（不泄漏实现细节）
            _ => Self::Client(e.to_string()),
        }
    }

    /// 从 `serde_json::Error` 构造 — 脱敏为 "invalid params"。
    pub fn from_serde_error(e: serde_json::Error) -> Self {
        tracing::warn!(error = %e, "RPC params deserialization failed (sanitized)");
        Self::Client("invalid params".to_string())
    }
}

impl From<String> for RpcHandlerError {
    fn from(s: String) -> Self {
        Self::Client(s)
    }
}

// ===== RpcBackend trait =====

/// RPC 后端 trait — 提供存储与状态访问抽象。
///
/// 实现方（节点二进制）组合 BlockStore / ObjectDb / DagVertexStore / AccountStore
/// 实现此 trait，并传给 [`RpcHandler`] 派发请求。
pub trait RpcBackend: Send + Sync {
    /// 按 hash 查询 block。
    fn get_block_by_hash(&self, hash: &Hash) -> PokerL1Result<Option<Block>>;
    /// 按 height 查询 block。
    fn get_block_by_height(&self, height: BlockHeight) -> PokerL1Result<Option<Block>>;
    /// 查询对象。
    fn get_object(&self, id: &ObjectID) -> PokerL1Result<Option<Object>>;
    /// 按 hash 查询 tx（遍历 block 查找；archive node 才支持）。
    fn get_tx(&self, tx_hash: &Hash) -> PokerL1Result<Option<Transaction>>;
    /// 提交 tx（验证后放入待装 vertex 缓冲）。
    fn submit_tx(&self, tx: Transaction) -> PokerL1Result<Hash>;
    /// 按 address 查询 account。
    fn get_account(&self, address: &Address) -> PokerL1Result<Option<Account>>;
    /// 按 hash 查询 DAG vertex。
    fn get_dag_vertex(&self, vertex_hash: &Hash) -> PokerL1Result<Option<DagVertex>>;
    /// List live native coins owned by an address.
    ///
    /// The default keeps existing external backend implementations source-compatible. Production
    /// nodes should override it before exposing the native-coin wallet RPC methods.
    fn get_native_coins(&self, _owner: &Address) -> PokerL1Result<Vec<OwnedNativeCoin>> {
        Err(PokerL1Error::Other(
            "native coin queries are not supported by this RPC backend".into(),
        ))
    }
    /// Query finalized transaction metadata through the durable index.
    fn query_indexed_txs(&self, _filter: &TxFilter) -> PokerL1Result<Vec<IndexedTransaction>> {
        Err(PokerL1Error::Other(
            "indexed transaction queries are not supported by this RPC backend".into(),
        ))
    }
    /// Query finalized block metadata through the durable index.
    fn query_indexed_blocks(&self, _filter: &BlockFilter) -> PokerL1Result<Vec<IndexedBlock>> {
        Err(PokerL1Error::Other(
            "indexed block queries are not supported by this RPC backend".into(),
        ))
    }
    /// Query output object IDs indexed by initial address ownership.
    fn query_indexed_objects_by_owner(&self, _owner: Address) -> PokerL1Result<Vec<ObjectID>> {
        Err(PokerL1Error::Other(
            "indexed object queries are not supported by this RPC backend".into(),
        ))
    }
    /// Query output object IDs indexed by type.
    fn query_indexed_objects_by_type(&self, _object_type: &str) -> PokerL1Result<Vec<ObjectID>> {
        Err(PokerL1Error::Other(
            "indexed object queries are not supported by this RPC backend".into(),
        ))
    }
    /// Create an in-process finalized-event subscription.
    fn subscribe_indexed_events(
        &self,
        _request: &SubscribeRequest,
    ) -> PokerL1Result<SubscribeResponse> {
        Err(PokerL1Error::Other(
            "event subscriptions are not supported by this RPC backend".into(),
        ))
    }
    /// Remove a finalized-event subscription.
    fn unsubscribe_indexed_events(&self, _subscription_id: u64) -> PokerL1Result<bool> {
        Err(PokerL1Error::Other(
            "event subscriptions are not supported by this RPC backend".into(),
        ))
    }
    /// Consume queued finalized events for a subscription.
    fn poll_indexed_events(
        &self,
        _subscription_id: u64,
    ) -> PokerL1Result<Option<Vec<IndexerEvent>>> {
        Err(PokerL1Error::Other(
            "event subscriptions are not supported by this RPC backend".into(),
        ))
    }
    /// 当前 chain_id。
    fn chain_id(&self) -> ChainId;
    /// ZK verifier registry（用于 zk_verify RPC）。
    fn zk_verifier_registry(&self) -> Option<&ZkVerifierRegistry>;
    /// 导出 Prometheus 格式指标文本（缺口 #7；默认空实现，NodeRpcBackend 覆写）。
    fn export_metrics(&self) -> String {
        String::new()
    }
}

// ===== RpcHandler =====

/// JSON-RPC 请求派发器。
///
/// 持有 [`RpcBackend`] 引用，将 JSON-RPC 请求派发到后端方法。
/// 方法名匹配 spec SubTask 31.1 / 31.3。
///
/// H-1 修复：可选持有 [`RpcGuard`] 执行认证与限流。
pub struct RpcHandler<'a, B: RpcBackend> {
    /// 后端。
    backend: &'a B,
    /// 安全守卫（H-1 修复 — 认证 + 限流）。
    guard: Option<Arc<RpcGuard>>,
}

fn normalize_index_query_limit(limit: &mut Option<usize>) -> Result<(), RpcHandlerError> {
    match limit {
        Some(value) if *value == 0 || *value > MAX_INDEX_QUERY_RESULTS => {
            Err(RpcHandlerError::Client(format!(
                "index query limit must be in 1..={MAX_INDEX_QUERY_RESULTS}"
            )))
        }
        Some(_) => Ok(()),
        None => {
            *limit = Some(MAX_INDEX_QUERY_RESULTS);
            Ok(())
        }
    }
}

impl<'a, B: RpcBackend> RpcHandler<'a, B> {
    /// 创建 handler（无守卫 — 向后兼容）。
    pub const fn new(backend: &'a B) -> Self {
        Self {
            backend,
            guard: None,
        }
    }

    /// 创建带安全守卫的 handler（H-1 修复）。
    ///
    /// guard 以 `Arc` 共享，使多连接共享同一限流窗口与认证配置。
    pub fn with_guard(backend: &'a B, guard: Arc<RpcGuard>) -> Self {
        Self {
            backend,
            guard: Some(guard),
        }
    }

    /// 处理 JSON-RPC 请求（无客户端信息 — 向后兼容）。
    ///
    /// 等价于 `handle_with_client(req, &RpcClientInfo::default())`。
    pub fn handle(&self, req: &JsonRpcRequest) -> JsonRpcResponse {
        self.handle_with_client(req, &RpcClientInfo::default())
    }

    /// 处理 JSON-RPC 请求，携带客户端身份信息（H-1 修复）。
    ///
    /// 若设置了 [`RpcGuard`]，先执行认证 + 限流检查，被拒绝时返回对应错误码：
    /// - 认证失败 → `-32002` (AUTH_FAILED)
    /// - 限流超限 → `-32001` (RATE_LIMIT_EXCEEDED)
    pub fn handle_with_client(
        &self,
        req: &JsonRpcRequest,
        client: &RpcClientInfo,
    ) -> JsonRpcResponse {
        // L-4 修复：params 序列化大小校验（防止超大 JSON payload DoS）
        // submit_tx 有独立的 MAX_TX_SIZE 检查，此处跳过
        if req.method != "submit_tx" {
            if let Ok(params_str) = serde_json::to_string(&req.params) {
                if params_str.len() > MAX_RPC_PARAMS_SIZE {
                    return JsonRpcResponse::error(
                        JsonRpcError::new(
                            JsonRpcError::INVALID_PARAMS,
                            format!(
                                "params too large: {} > {}",
                                params_str.len(),
                                MAX_RPC_PARAMS_SIZE
                            ),
                        ),
                        req.id.clone(),
                    );
                }
            }
        }

        // H-1 修复：认证 + 限流检查
        if let Some(guard) = &self.guard
            && let Err(err) = guard.check(&req.method, client)
        {
            let (code, msg) = match err {
                RpcGuardError::Auth(m) => (AUTH_FAILED, m),
                RpcGuardError::RateLimited(m) => (RATE_LIMIT_EXCEEDED, m),
            };
            return JsonRpcResponse::error(JsonRpcError::new(code, msg), req.id.clone());
        }

        // 解析 params 为 serde_json::Value，方法内部再反序列化为具体类型
        let result = match req.method.as_str() {
            "get_block" => self.handle_get_block(&req.params),
            "get_object" => self.handle_get_object(&req.params),
            "get_tx" => self.handle_get_tx(&req.params),
            "submit_tx" => self.handle_submit_tx(&req.params),
            "get_account" => self.handle_get_account(&req.params),
            "get_dag_vertex" => self.handle_get_dag_vertex(&req.params),
            "get_native_balance" => self.handle_get_native_balance(&req.params),
            "get_native_coins" => self.handle_get_native_coins(&req.params),
            "select_native_coins" => self.handle_select_native_coins(&req.params),
            "query_txs" => self.handle_query_txs(&req.params),
            "query_blocks" => self.handle_query_blocks(&req.params),
            "query_objects_by_owner" => self.handle_query_objects_by_owner(&req.params),
            "query_objects_by_type" => self.handle_query_objects_by_type(&req.params),
            "subscribe" => self.handle_subscribe(&req.params),
            "unsubscribe" => self.handle_unsubscribe(&req.params),
            "poll_events" => self.handle_poll_events(&req.params),
            "secp256k1_aggregate_verify" => self.handle_secp256k1_aggregate_verify(&req.params),
            "bls_verify" => self.handle_bls_verify(&req.params),
            "zk_verify" => self.handle_zk_verify(&req.params),
            "get_metrics" => self.handle_get_metrics(),
            _ => {
                return JsonRpcResponse::error(
                    JsonRpcError::new(
                        JsonRpcError::METHOD_NOT_FOUND,
                        format!("method not found: {}", req.method),
                    ),
                    req.id.clone(),
                );
            }
        };

        match result {
            Ok(value) => JsonRpcResponse::success(value, req.id.clone()),
            // M-5 修复：区分客户端错误与内部错误，使用正确错误码
            Err(RpcHandlerError::Client(msg)) => JsonRpcResponse::error(
                JsonRpcError::new(JsonRpcError::INVALID_PARAMS, msg),
                req.id.clone(),
            ),
            Err(RpcHandlerError::Internal(msg)) => JsonRpcResponse::error(
                JsonRpcError::new(JsonRpcError::INTERNAL_ERROR, msg),
                req.id.clone(),
            ),
        }
    }

    // ===== SubTask 31.1: JSON-RPC 方法 =====
    // M-5 修复：所有 handler 返回 RpcHandlerError 以区分客户端/内部错误

    fn handle_get_block(
        &self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, RpcHandlerError> {
        let p: GetBlockParams =
            serde_json::from_value(params.clone()).map_err(RpcHandlerError::from_serde_error)?;
        let block = match p {
            GetBlockParams::ByHash { hash } => self.backend.get_block_by_hash(&hash),
            GetBlockParams::ByHeight { height } => self.backend.get_block_by_height(height),
        }
        .map_err(RpcHandlerError::from_poker_error)?;
        serde_json::to_value(block).map_err(RpcHandlerError::from_serde_error)
    }

    fn handle_get_object(
        &self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, RpcHandlerError> {
        let p: GetObjectParams =
            serde_json::from_value(params.clone()).map_err(RpcHandlerError::from_serde_error)?;
        let obj = self
            .backend
            .get_object(&p.id)
            .map_err(RpcHandlerError::from_poker_error)?;
        serde_json::to_value(obj).map_err(RpcHandlerError::from_serde_error)
    }

    fn handle_get_tx(
        &self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, RpcHandlerError> {
        let p: GetTxParams =
            serde_json::from_value(params.clone()).map_err(RpcHandlerError::from_serde_error)?;
        let tx = self
            .backend
            .get_tx(&p.tx_hash)
            .map_err(RpcHandlerError::from_poker_error)?;
        serde_json::to_value(tx).map_err(RpcHandlerError::from_serde_error)
    }

    fn handle_query_txs(
        &self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, RpcHandlerError> {
        let mut filter: TxFilter =
            serde_json::from_value(params.clone()).map_err(RpcHandlerError::from_serde_error)?;
        normalize_index_query_limit(&mut filter.limit)?;
        let transactions = self
            .backend
            .query_indexed_txs(&filter)
            .map_err(RpcHandlerError::from_poker_error)?;
        serde_json::to_value(transactions).map_err(RpcHandlerError::from_serde_error)
    }

    fn handle_query_blocks(
        &self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, RpcHandlerError> {
        let mut filter: BlockFilter =
            serde_json::from_value(params.clone()).map_err(RpcHandlerError::from_serde_error)?;
        normalize_index_query_limit(&mut filter.limit)?;
        let blocks = self
            .backend
            .query_indexed_blocks(&filter)
            .map_err(RpcHandlerError::from_poker_error)?;
        serde_json::to_value(blocks).map_err(RpcHandlerError::from_serde_error)
    }

    fn handle_query_objects_by_owner(
        &self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, RpcHandlerError> {
        let request: QueryObjectsByOwnerRequest =
            serde_json::from_value(params.clone()).map_err(RpcHandlerError::from_serde_error)?;
        let objects = self
            .backend
            .query_indexed_objects_by_owner(request.owner)
            .map_err(RpcHandlerError::from_poker_error)?;
        serde_json::to_value(objects).map_err(RpcHandlerError::from_serde_error)
    }

    fn handle_query_objects_by_type(
        &self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, RpcHandlerError> {
        let request: QueryObjectsByTypeRequest =
            serde_json::from_value(params.clone()).map_err(RpcHandlerError::from_serde_error)?;
        if request.object_type.is_empty() || request.object_type.len() > 256 {
            return Err(RpcHandlerError::Client(
                "object_type must contain 1..=256 bytes".into(),
            ));
        }
        let objects = self
            .backend
            .query_indexed_objects_by_type(&request.object_type)
            .map_err(RpcHandlerError::from_poker_error)?;
        serde_json::to_value(objects).map_err(RpcHandlerError::from_serde_error)
    }

    fn handle_subscribe(
        &self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, RpcHandlerError> {
        let request: SubscribeRequest =
            serde_json::from_value(params.clone()).map_err(RpcHandlerError::from_serde_error)?;
        let response = self
            .backend
            .subscribe_indexed_events(&request)
            .map_err(RpcHandlerError::from_poker_error)?;
        serde_json::to_value(response).map_err(RpcHandlerError::from_serde_error)
    }

    fn handle_unsubscribe(
        &self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, RpcHandlerError> {
        let request: UnsubscribeRequest =
            serde_json::from_value(params.clone()).map_err(RpcHandlerError::from_serde_error)?;
        let removed = self
            .backend
            .unsubscribe_indexed_events(request.subscription_id)
            .map_err(RpcHandlerError::from_poker_error)?;
        serde_json::to_value(removed).map_err(RpcHandlerError::from_serde_error)
    }

    fn handle_poll_events(
        &self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, RpcHandlerError> {
        let request: PollSubscriptionRequest =
            serde_json::from_value(params.clone()).map_err(RpcHandlerError::from_serde_error)?;
        let events = self
            .backend
            .poll_indexed_events(request.subscription_id)
            .map_err(RpcHandlerError::from_poker_error)?
            .ok_or_else(|| RpcHandlerError::Client("subscription not found".into()))?;
        serde_json::to_value(events).map_err(RpcHandlerError::from_serde_error)
    }

    fn handle_submit_tx(
        &self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, RpcHandlerError> {
        let p: SubmitTxParams =
            serde_json::from_value(params.clone()).map_err(RpcHandlerError::from_serde_error)?;
        // tx_bytes 边界校验（SubTask 30.6：tx <= 128KB）
        const MAX_TX_SIZE: usize = 128 * 1024;
        if p.tx_bytes.len() > MAX_TX_SIZE {
            return Err(RpcHandlerError::Client(
                PokerL1Error::TxTooLarge {
                    actual: p.tx_bytes.len(),
                    limit: MAX_TX_SIZE,
                }
                .to_string(),
            ));
        }
        let tx = Transaction::from_bcs(&p.tx_bytes).map_err(RpcHandlerError::from_poker_error)?;

        // C-1 安全修复：反序列化后立即执行完整验证
        // 1. 每字段边界校验（MAX_INPUTS/MAX_OUTPUTS/MAX_SIG_LEN/MAX_ARGS_LEN）
        validate_tx_limits(&tx).map_err(RpcHandlerError::from_poker_error)?;
        // 2. chain_id 校验（SEC-L4：防跨链重放）
        validate_tx_chain_id(&tx, self.backend.chain_id())
            .map_err(RpcHandlerError::from_poker_error)?;
        // 3. 签名验证（常数时间，IMPL-SEC-1）
        validate_tx_signature(&tx).map_err(RpcHandlerError::from_poker_error)?;
        // 4. nonce 校验（Public/ForceSync/CheckpointAnchor 通道）
        //    GameTurn 通道的 game_player_nonce 需游戏状态，RPC 层无法获取，
        //    留待 block 验证时检查（跳过 nonce 校验，避免误拒合法 GameTurn tx）
        if tx.lane_hint != TxLane::GameTurn {
            let caller_address = derive_address(&tx.tagged_pubkey);
            let account_nonce = self
                .backend
                .get_account(&caller_address)
                .map_err(RpcHandlerError::from_poker_error)?
                .map(|a| a.nonce)
                .unwrap_or(0);
            validate_tx_nonce(&tx, account_nonce, None)
                .map_err(RpcHandlerError::from_poker_error)?;
        }

        let tx_hash = self
            .backend
            .submit_tx(tx)
            .map_err(RpcHandlerError::from_poker_error)?;
        serde_json::to_value(SubmitTxResult { tx_hash }).map_err(RpcHandlerError::from_serde_error)
    }

    fn handle_get_account(
        &self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, RpcHandlerError> {
        let p: GetAccountParams =
            serde_json::from_value(params.clone()).map_err(RpcHandlerError::from_serde_error)?;
        let address = match p {
            GetAccountParams::ByAddress { address } => address,
            GetAccountParams::ByPubkey { tagged_pubkey } => {
                crate::account::derive_address(&tagged_pubkey)
            }
        };
        let account = self
            .backend
            .get_account(&address)
            .map_err(RpcHandlerError::from_poker_error)?;
        serde_json::to_value(account).map_err(RpcHandlerError::from_serde_error)
    }

    fn handle_get_dag_vertex(
        &self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, RpcHandlerError> {
        let p: GetDagVertexParams =
            serde_json::from_value(params.clone()).map_err(RpcHandlerError::from_serde_error)?;
        let vertex = self
            .backend
            .get_dag_vertex(&p.vertex_hash)
            .map_err(RpcHandlerError::from_poker_error)?;
        serde_json::to_value(vertex).map_err(RpcHandlerError::from_serde_error)
    }

    fn native_coin_owner(params: GetNativeCoinsParams) -> Address {
        match params {
            GetNativeCoinsParams::ByAddress { address } => address,
            GetNativeCoinsParams::ByPubkey { tagged_pubkey } => derive_address(&tagged_pubkey),
        }
    }

    fn handle_get_native_balance(
        &self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, RpcHandlerError> {
        let params: GetNativeCoinsParams =
            serde_json::from_value(params.clone()).map_err(RpcHandlerError::from_serde_error)?;
        let owner = Self::native_coin_owner(params);
        let coins = self
            .backend
            .get_native_coins(&owner)
            .map_err(RpcHandlerError::from_poker_error)?;
        let balance = sum_native_coin_balance(&coins).map_err(RpcHandlerError::from_poker_error)?;
        let coin_count = u64::try_from(coins.len()).map_err(|_| {
            RpcHandlerError::Internal("native coin count exceeds RPC representation".into())
        })?;
        serde_json::to_value(NativeBalanceResult {
            owner,
            balance,
            coin_count,
        })
        .map_err(RpcHandlerError::from_serde_error)
    }

    fn handle_get_native_coins(
        &self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, RpcHandlerError> {
        let params: GetNativeCoinsParams =
            serde_json::from_value(params.clone()).map_err(RpcHandlerError::from_serde_error)?;
        let owner = Self::native_coin_owner(params);
        let coins = self
            .backend
            .get_native_coins(&owner)
            .map_err(RpcHandlerError::from_poker_error)?;
        serde_json::to_value(coins).map_err(RpcHandlerError::from_serde_error)
    }

    fn handle_select_native_coins(
        &self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, RpcHandlerError> {
        let params: SelectNativeCoinsParams =
            serde_json::from_value(params.clone()).map_err(RpcHandlerError::from_serde_error)?;
        let (owner, required) = match params {
            SelectNativeCoinsParams::ByAddress { address, required } => (address, required),
            SelectNativeCoinsParams::ByPubkey {
                tagged_pubkey,
                required,
            } => (derive_address(&tagged_pubkey), required),
        };
        if required == 0 {
            return Err(RpcHandlerError::Client(
                "required amount must be greater than zero".into(),
            ));
        }
        let coins = self
            .backend
            .get_native_coins(&owner)
            .map_err(RpcHandlerError::from_poker_error)?;
        let selection = select_native_coins_from_candidates(&coins, required)
            .map_err(RpcHandlerError::from_poker_error)?;
        serde_json::to_value(SelectNativeCoinsResult {
            owner,
            input_ids: selection.input_ids,
            total: selection.total,
            change: selection.total - required,
        })
        .map_err(RpcHandlerError::from_serde_error)
    }

    // ===== SubTask 31.3: crypto verify RPC =====

    fn handle_secp256k1_aggregate_verify(
        &self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, RpcHandlerError> {
        let p: Secp256k1AggregateVerifyParams =
            serde_json::from_value(params.clone()).map_err(RpcHandlerError::from_serde_error)?;
        if p.pubkeys.len() != p.msg_hashes.len() || p.pubkeys.len() != p.sigs.len() {
            return Err(RpcHandlerError::Client(
                "pubkeys / msg_hashes / sigs length mismatch".to_string(),
            ));
        }
        let msg_refs: Vec<&[u8; 32]> = p.msg_hashes.iter().collect();
        let sig_refs: Vec<&[u8]> = p.sigs.iter().map(|s| s.as_slice()).collect();
        let verified = native_secp256k1_aggregate_verify(&p.pubkeys, &msg_refs, &sig_refs)
            .map_err(RpcHandlerError::from_poker_error)?;
        serde_json::to_value(Secp256k1AggregateVerifyResult { verified })
            .map_err(RpcHandlerError::from_serde_error)
    }

    fn handle_bls_verify(
        &self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, RpcHandlerError> {
        let p: BlsVerifyParams =
            serde_json::from_value(params.clone()).map_err(RpcHandlerError::from_serde_error)?;
        let verified = native_bls_verify(&p.pubkey_g2, &p.signature_g1, &p.msg)
            .map_err(RpcHandlerError::from_poker_error)?;
        serde_json::to_value(BlsVerifyResult { verified })
            .map_err(RpcHandlerError::from_serde_error)
    }

    fn handle_zk_verify(
        &self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, RpcHandlerError> {
        let p: ZkVerifyParams =
            serde_json::from_value(params.clone()).map_err(RpcHandlerError::from_serde_error)?;
        let registry = self.backend.zk_verifier_registry().ok_or_else(|| {
            RpcHandlerError::Client("zk verifier registry not available".to_string())
        })?;
        // 反序列化 public_io（ZkPublicIo::from_bytes 内部固定布局）
        let public_io = ZkPublicIo::from_bytes(&p.public_io_bytes).ok_or_else(|| {
            RpcHandlerError::Client("public_io deserialization failed".to_string())
        })?;
        let result: ZkVerifyResult = registry
            .zk_verify(
                self.backend.chain_id(),
                p.scheme_id,
                &p.proof,
                &public_io,
                p.max_skip_segments,
                p.max_ack_chain_length,
            )
            .map_err(RpcHandlerError::from_poker_error)?;
        serde_json::to_value(ZkVerifyRpcResult {
            verified: result.verified,
            verifier_status: format!("{:?}", result.verifier_status),
            scheme_id: result.scheme_id,
        })
        .map_err(RpcHandlerError::from_serde_error)
    }

    /// `get_metrics` —— 导出 Prometheus 格式指标文本（缺口 #7）。
    ///
    /// 无参数，返回 `{"metrics": "<prometheus text>"}`。
    fn handle_get_metrics(&self) -> Result<serde_json::Value, RpcHandlerError> {
        let text = self.backend.export_metrics();
        Ok(serde_json::json!({ "metrics": text }))
    }
}

// ===== MemoryBackend（用于测试） =====

/// tx_cache 最大条目数（C-2 修复 — 防止内存 DoS）。
const MAX_RPC_TX_CACHE_SIZE: usize = 10_000;

/// pending_tx 最大条目数（C-2 修复 — 防止内存 DoS）。
const MAX_RPC_PENDING_TX_SIZE: usize = 10_000;

/// RPC 层 tx 缓存状态（M-6 修复 — 合并 cache + order 到单个 Mutex 避免多锁死锁）。
struct RpcTxCacheState {
    /// tx_hash → tx 映射。
    cache: HashMap<Hash, Transaction>,
    /// 插入顺序（FIFO 淘汰追踪）。
    order: VecDeque<Hash>,
}

impl RpcTxCacheState {
    fn new() -> Self {
        Self {
            cache: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn insert(&mut self, tx_hash: Hash, tx: Transaction, max_size: usize) {
        if !self.cache.contains_key(&tx_hash) {
            self.order.push_back(tx_hash);
        }
        self.cache.insert(tx_hash, tx);
        while self.cache.len() > max_size {
            if let Some(old_hash) = self.order.pop_front() {
                self.cache.remove(&old_hash);
            } else {
                break;
            }
        }
    }

    fn get(&self, tx_hash: &Hash) -> Option<&Transaction> {
        self.cache.get(tx_hash)
    }
}

/// 内存后端 — 用于单元测试与集成测试。
///
/// 组合 BlockStore / ObjectDb / DagVertexStore / AccountStore 的内存实例。
pub struct MemoryBackend {
    /// BlockStore。
    block_store: BlockStore,
    /// ObjectDb。
    object_db: std::sync::Mutex<ObjectDb>,
    /// DagVertexStore。
    vertex_store: DagVertexStore,
    /// AccountStore。
    account_store: std::sync::Mutex<AccountStore>,
    /// chain_id。
    chain_id: ChainId,
    /// 已提交的 tx 缓存（M-6 修复 — cache + order 合并到单个 Mutex）。
    tx_cache: std::sync::Mutex<RpcTxCacheState>,
    /// 待装 vertex 的 tx 缓冲（submit_tx 写入）。
    pending_tx: std::sync::Mutex<std::collections::VecDeque<Transaction>>,
    /// ZK verifier registry（可选）。
    zk_registry: Option<ZkVerifierRegistry>,
}

impl MemoryBackend {
    /// 创建空内存后端。
    pub fn new(chain_id: ChainId) -> PokerL1Result<Self> {
        Ok(Self {
            block_store: BlockStore::open_inmemory()?,
            object_db: std::sync::Mutex::new(ObjectDb::open_inmemory()?),
            vertex_store: DagVertexStore::open_inmemory()?,
            account_store: std::sync::Mutex::new(AccountStore::new()),
            chain_id,
            tx_cache: std::sync::Mutex::new(RpcTxCacheState::new()),
            pending_tx: std::sync::Mutex::new(std::collections::VecDeque::new()),
            zk_registry: None,
        })
    }

    /// 设置 ZK verifier registry。
    pub fn set_zk_registry(&mut self, registry: ZkVerifierRegistry) {
        self.zk_registry = Some(registry);
    }

    /// 注入 block（测试辅助）。
    pub fn insert_block(&self, block: Block) -> PokerL1Result<Hash> {
        self.block_store.put(&block, self.chain_id)
    }

    /// 注入对象（测试辅助）。
    pub fn insert_object(&self, object: Object) -> PokerL1Result<()> {
        self.object_db
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .create(object)
    }

    /// 注入 DAG vertex（测试辅助）。
    pub fn insert_vertex(&self, vertex: &DagVertex) -> PokerL1Result<Hash> {
        self.vertex_store.put(vertex)
    }

    /// 注入 account（测试辅助）。
    pub fn insert_account(&self, account: Account) -> PokerL1Result<()> {
        self.account_store
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .create(account)
    }

    /// 取出待装 vertex 的 tx（测试辅助）。
    pub fn drain_pending_tx(&self) -> Vec<Transaction> {
        self.pending_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain(..)
            .collect()
    }
}

impl RpcBackend for MemoryBackend {
    fn get_block_by_hash(&self, hash: &Hash) -> PokerL1Result<Option<Block>> {
        match self.block_store.get_by_hash(hash) {
            Ok(block) => Ok(Some(block)),
            Err(PokerL1Error::BlockNotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn get_block_by_height(&self, height: BlockHeight) -> PokerL1Result<Option<Block>> {
        match self.block_store.get_by_height(height) {
            Ok(block) => Ok(Some(block)),
            Err(PokerL1Error::BlockNotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn get_object(&self, id: &ObjectID) -> PokerL1Result<Option<Object>> {
        let result = self
            .object_db
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .read(id);
        match result {
            Ok(obj) => Ok(Some(obj)),
            Err(PokerL1Error::ObjectNotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn get_tx(&self, tx_hash: &Hash) -> PokerL1Result<Option<Transaction>> {
        Ok(self
            .tx_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(tx_hash)
            .cloned())
    }

    fn submit_tx(&self, tx: Transaction) -> PokerL1Result<Hash> {
        let tx_hash = tx.tx_hash();

        // M-6 修复：单次 lock 完成 cache + order 操作
        {
            let mut cache = self.tx_cache.lock().unwrap_or_else(|e| e.into_inner());
            cache.insert(tx_hash, tx.clone(), MAX_RPC_TX_CACHE_SIZE);
        }

        let mut pending = self.pending_tx.lock().unwrap_or_else(|e| e.into_inner());
        pending.push_back(tx);
        while pending.len() > MAX_RPC_PENDING_TX_SIZE {
            pending.pop_front();
        }
        Ok(tx_hash)
    }

    fn get_account(&self, address: &Address) -> PokerL1Result<Option<Account>> {
        Ok(self
            .account_store
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(address)
            .cloned())
    }

    fn get_dag_vertex(&self, vertex_hash: &Hash) -> PokerL1Result<Option<DagVertex>> {
        match self.vertex_store.get_by_hash(vertex_hash) {
            Ok(vertex) => Ok(Some(vertex)),
            Err(PokerL1Error::DagVertexNotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn get_native_coins(&self, owner: &Address) -> PokerL1Result<Vec<OwnedNativeCoin>> {
        let object_db = self.object_db.lock().unwrap_or_else(|e| e.into_inner());
        list_owned_native_coins(&object_db, *owner)
    }

    fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    fn zk_verifier_registry(&self) -> Option<&ZkVerifierRegistry> {
        self.zk_registry.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DEFAULT_CHAIN_ID;
    use crate::account::Account;
    use crate::block::{Block, BlockHeader};
    use crate::consensus::DagVertex;
    use crate::economics::native_coin_object;
    use crate::object_model::{Object, ObjectID, Ownership};
    use crate::signature::tagged_pubkey::{CURRENT_VERSION, SignatureScheme, encode_tag};
    use crate::transaction::{Gas, RouteHint, Transaction, TxLane};
    use secp256k1::rand::rngs::OsRng;
    use secp256k1::{Message, Secp256k1};

    fn dummy_tagged_pubkey() -> TaggedPubkey {
        TaggedPubkey {
            tag: encode_tag(SignatureScheme::Secp256k1, 1),
            raw: vec![0x02u8; 33],
        }
    }

    /// 生成真实 secp256k1 签名的 dummy tx（nonce=0，适配新账户）。
    fn signed_dummy_tx() -> Transaction {
        let secp = Secp256k1::new();
        let mut rng = OsRng;
        let (secret, public) = secp.generate_keypair(&mut rng);
        let compressed = public.serialize();
        let tagged = TaggedPubkey::new(
            SignatureScheme::Secp256k1,
            CURRENT_VERSION,
            compressed.to_vec(),
        )
        .expect("构造 tagged pubkey 不应失败");

        let mut tx = Transaction {
            inputs: vec![ObjectID::new([0u8; 20], 1)],
            outputs: vec![dummy_object(1)],
            contract_call: None,
            tagged_pubkey: tagged,
            signature: vec![0u8; 65],
            gas: Gas::new(1000, 1),
            lane_hint: TxLane::Public,
            route_hint: RouteHint::AnyValidator,
            chain_id: DEFAULT_CHAIN_ID,
            nonce: 0,
            gameturn_nonce: None,
            is_fallback: false,
        };
        let signing_hash = tx.signing_hash();
        let msg = Message::from_digest_slice(&signing_hash).expect("signing_hash 32 bytes");
        let sig = secp.sign_ecdsa_recoverable(&msg, &secret);
        let (recovery_id, compact) = sig.serialize_compact();
        let mut sig_bytes = compact.to_vec();
        sig_bytes.push(recovery_id.to_i32() as u8);
        tx.signature = sig_bytes;
        tx
    }

    fn dummy_object(id_byte: u8) -> Object {
        Object::new(
            ObjectID::new([id_byte; 20], 0),
            Ownership::Shared,
            "TestType",
            b"test_data".to_vec(),
            None,
        )
    }

    fn dummy_commit_certificate() -> crate::consensus::DagCommitCertificate {
        crate::consensus::DagCommitCertificate {
            epoch: 0,
            commit_round: 0,
            prev_commit_hash: [0u8; 32],
            epoch_transition: None,
            vertex_hash_list: vec![],
            round_attendance_bitmap: vec![],
            state_root: [0u8; 32],
            account_root: [0u8; 32],
            public_tx_root: [0u8; 32],
            gameturn_tx_root: [0u8; 32],
            signature_list: vec![],
            signer_bitmap: vec![],
        }
    }

    fn dummy_block(height: u64) -> Block {
        Block::new(
            BlockHeader {
                height,
                timestamp_ms: height * 1000,
                prev_hash: [0u8; 32],
                state_root: [0u8; 32],
                account_root: [0u8; 32],
                public_tx_root: [0u8; 32],
                gameturn_tx_root: [0u8; 32],
                dag_commit_certificate: dummy_commit_certificate(),
            },
            vec![],
            vec![],
        )
    }

    #[test]
    fn jsonrpc_response_success_serialization() {
        let resp = JsonRpcResponse::success(serde_json::json!({"ok": true}), serde_json::json!(1));
        let s = serde_json::to_string(&resp).unwrap();
        assert!(s.contains("\"result\""));
        assert!(!s.contains("\"error\""));
    }

    #[test]
    fn jsonrpc_response_error_serialization() {
        let resp = JsonRpcResponse::error(
            JsonRpcError::new(JsonRpcError::METHOD_NOT_FOUND, "no method"),
            serde_json::json!(1),
        );
        let s = serde_json::to_string(&resp).unwrap();
        assert!(s.contains("\"error\""));
        assert!(!s.contains("\"result\""));
    }

    #[test]
    fn get_block_by_height_success() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let block = dummy_block(10);
        let hash = backend.insert_block(block).unwrap();

        let handler = RpcHandler::new(&backend);
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "get_block".to_string(),
            params: serde_json::json!({"height": 10}),
            id: serde_json::json!(1),
        };
        let resp = handler.handle(&req);
        assert!(resp.error.is_none(), "get_block 应成功");
        let block_resp: Block = serde_json::from_value(resp.result.unwrap()).unwrap();
        assert_eq!(block_resp.header.height, 10);
        // hash 一致
        assert_eq!(block_resp.block_hash(DEFAULT_CHAIN_ID), hash);
    }

    #[test]
    fn get_block_by_hash_not_found() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let handler = RpcHandler::new(&backend);
        let zero_hash: Hash = [0u8; 32];
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "get_block".to_string(),
            params: serde_json::json!({"hash": zero_hash}),
            id: serde_json::json!(1),
        };
        let resp = handler.handle(&req);
        assert!(resp.result.is_some(), "not found 应返回 result: null");
        assert!(resp.result.unwrap().is_null());
    }

    #[test]
    fn get_object_success() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let obj = dummy_object(0xAA);
        let id = obj.id;
        backend.insert_object(obj).unwrap();

        let handler = RpcHandler::new(&backend);
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "get_object".to_string(),
            params: serde_json::json!({"id": id}),
            id: serde_json::json!(1),
        };
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let obj_resp: Object = serde_json::from_value(resp.result.unwrap()).unwrap();
        assert_eq!(obj_resp.id, id);
    }

    #[test]
    fn native_coin_rpc_aggregates_lists_and_selects_without_exposing_fragmentation_by_default() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let owner = [0x44; 20];
        let first = native_coin_object(owner, 40, 2).unwrap();
        let second = native_coin_object(owner, 70, 1).unwrap();
        backend.insert_object(first.clone()).unwrap();
        backend.insert_object(second.clone()).unwrap();

        let handler = RpcHandler::new(&backend);
        let balance = handler.handle(&JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "get_native_balance".to_string(),
            params: serde_json::json!({"address": owner}),
            id: serde_json::json!(1),
        });
        assert!(balance.error.is_none());
        let balance: NativeBalanceResult = serde_json::from_value(balance.result.unwrap()).unwrap();
        assert_eq!(balance.balance, 110);
        assert_eq!(balance.coin_count, 2);

        let coins = handler.handle(&JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "get_native_coins".to_string(),
            params: serde_json::json!({"address": owner}),
            id: serde_json::json!(2),
        });
        assert!(coins.error.is_none());
        let coins: Vec<OwnedNativeCoin> = serde_json::from_value(coins.result.unwrap()).unwrap();
        assert_eq!(coins[0].id, second.id);
        assert_eq!(coins[1].id, first.id);

        let selection = handler.handle(&JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "select_native_coins".to_string(),
            params: serde_json::json!({"address": owner, "required": 100}),
            id: serde_json::json!(3),
        });
        assert!(selection.error.is_none());
        let selection: SelectNativeCoinsResult =
            serde_json::from_value(selection.result.unwrap()).unwrap();
        assert_eq!(selection.input_ids, vec![second.id, first.id]);
        assert_eq!(selection.total, 110);
        assert_eq!(selection.change, 10);
    }

    #[test]
    fn native_coin_selection_rpc_reports_insufficient_balance_as_client_error() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let owner = [0x55; 20];
        backend
            .insert_object(native_coin_object(owner, 25, 1).unwrap())
            .unwrap();

        let response = RpcHandler::new(&backend).handle(&JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "select_native_coins".to_string(),
            params: serde_json::json!({"address": owner, "required": 30}),
            id: serde_json::json!(1),
        });
        assert_eq!(response.error.unwrap().code, JsonRpcError::INVALID_PARAMS);
    }

    #[test]
    fn submit_tx_returns_tx_hash() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let tx = signed_dummy_tx();
        let expected_hash = tx.tx_hash();
        let tx_bytes = tx.to_bcs().unwrap();

        let handler = RpcHandler::new(&backend);
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "submit_tx".to_string(),
            params: serde_json::json!({"tx_bytes": tx_bytes}),
            id: serde_json::json!(1),
        };
        let resp = handler.handle(&req);
        assert!(resp.error.is_none(), "submit_tx 应成功");
        let result: SubmitTxResult = serde_json::from_value(resp.result.unwrap()).unwrap();
        assert_eq!(result.tx_hash, expected_hash);

        // pending_tx 应有一笔
        let pending = backend.drain_pending_tx();
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn submit_tx_too_large_rejected() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let handler = RpcHandler::new(&backend);
        // 构造超大 tx_bytes（128KB + 1）
        let big_bytes = vec![0u8; 128 * 1024 + 1];
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "submit_tx".to_string(),
            params: serde_json::json!({"tx_bytes": big_bytes}),
            id: serde_json::json!(1),
        };
        let resp = handler.handle(&req);
        assert!(resp.error.is_some(), "超大 tx 应被拒绝");
        assert_eq!(resp.error.unwrap().code, JsonRpcError::INVALID_PARAMS);
    }

    #[test]
    fn get_account_by_address() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let tagged = dummy_tagged_pubkey();
        let account = Account::new(tagged, 1000);
        let address = account.address;
        backend.insert_account(account).unwrap();

        let handler = RpcHandler::new(&backend);
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "get_account".to_string(),
            params: serde_json::json!({"address": address}),
            id: serde_json::json!(1),
        };
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let account_resp: Account = serde_json::from_value(resp.result.unwrap()).unwrap();
        assert_eq!(account_resp.address, address);
        assert_eq!(account_resp.balance, 1000);
    }

    #[test]
    fn get_account_by_pubkey() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let tagged = dummy_tagged_pubkey();
        let account = Account::new(tagged.clone(), 500);
        backend.insert_account(account).unwrap();

        let handler = RpcHandler::new(&backend);
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "get_account".to_string(),
            params: serde_json::json!({"tagged_pubkey": tagged}),
            id: serde_json::json!(1),
        };
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let account_resp: Account = serde_json::from_value(resp.result.unwrap()).unwrap();
        assert_eq!(account_resp.balance, 500);
    }

    #[test]
    fn get_dag_vertex_success() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let vertex = DagVertex {
            epoch: 1,
            round: 5,
            author_pubkey: dummy_tagged_pubkey(),
            tx_list: vec![],
            parent_hashes: vec![],
            author_sig: vec![0u8; 65],
        };
        let hash = backend.insert_vertex(&vertex).unwrap();

        let handler = RpcHandler::new(&backend);
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "get_dag_vertex".to_string(),
            params: serde_json::json!({"vertex_hash": hash}),
            id: serde_json::json!(1),
        };
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        let v_resp: DagVertex = serde_json::from_value(resp.result.unwrap()).unwrap();
        assert_eq!(v_resp.epoch, 1);
        assert_eq!(v_resp.round, 5);
    }

    #[test]
    fn method_not_found() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let handler = RpcHandler::new(&backend);
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "nonexistent_method".to_string(),
            params: serde_json::json!({}),
            id: serde_json::json!(1),
        };
        let resp = handler.handle(&req);
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, JsonRpcError::METHOD_NOT_FOUND);
    }

    #[test]
    fn secp256k1_aggregate_verify_length_mismatch() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let handler = RpcHandler::new(&backend);
        let msg1: Hash = [0u8; 32];
        let msg2: Hash = [0u8; 32];
        let sig: Vec<u8> = vec![0u8; 65];
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "secp256k1_aggregate_verify".to_string(),
            params: serde_json::json!({
                "pubkeys": [dummy_tagged_pubkey()],
                "msg_hashes": [msg1, msg2],
                "sigs": [sig]
            }),
            id: serde_json::json!(1),
        };
        let resp = handler.handle(&req);
        assert!(resp.error.is_some(), "长度不匹配应返回错误");
    }

    #[test]
    fn bls_verify_invalid_pubkey_length() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let handler = RpcHandler::new(&backend);
        let bad_pubkey: Vec<u8> = vec![0u8; 95];
        let sig: Vec<u8> = vec![0u8; 48];
        let msg: Vec<u8> = vec![0u8; 32];
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "bls_verify".to_string(),
            params: serde_json::json!({
                "pubkey_g2": bad_pubkey,
                "signature_g1": sig,
                "msg": msg
            }),
            id: serde_json::json!(1),
        };
        let resp = handler.handle(&req);
        assert!(resp.error.is_some(), "错误 pubkey 长度应返回错误");
    }

    #[test]
    fn zk_verify_no_registry_returns_error() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let handler = RpcHandler::new(&backend);
        let proof: Vec<u8> = vec![0u8; 16];
        let public_io: Vec<u8> = vec![0u8; 16];
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "zk_verify".to_string(),
            params: serde_json::json!({
                "scheme_id": 1u32,
                "proof": proof,
                "public_io_bytes": public_io,
                "max_skip_segments": 3u32,
                "max_ack_chain_length": 1000u32
            }),
            id: serde_json::json!(1),
        };
        let resp = handler.handle(&req);
        assert!(resp.error.is_some(), "无 registry 应返回错误");
    }

    #[test]
    fn websocket_event_types_serialize() {
        let types = vec![EventType::Block, EventType::Vertex, EventType::Transaction];
        let s = serde_json::to_string(&types).unwrap();
        assert!(s.contains("Block"));
        assert!(s.contains("Vertex"));
        assert!(s.contains("Transaction"));
        let de: Vec<EventType> = serde_json::from_str(&s).unwrap();
        assert_eq!(de.len(), 3);
    }

    #[test]
    fn subscribe_request_roundtrip() {
        let req = SubscribeRequest {
            event_types: vec![EventType::Block, EventType::Transaction],
            tx_filter: None,
        };
        let s = serde_json::to_string(&req).unwrap();
        let de: SubscribeRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(de.event_types.len(), 2);
    }

    #[test]
    fn event_message_roundtrip() {
        let msg = EventMessage {
            subscription_id: 42,
            event_type: EventType::Block,
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let s = serde_json::to_string(&msg).unwrap();
        let de: EventMessage = serde_json::from_str(&s).unwrap();
        assert_eq!(de.subscription_id, 42);
        assert_eq!(de.payload, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn get_tx_returns_none_for_unknown() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let handler = RpcHandler::new(&backend);
        let zero_hash: Hash = [0u8; 32];
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "get_tx".to_string(),
            params: serde_json::json!({"tx_hash": zero_hash}),
            id: serde_json::json!(1),
        };
        let resp = handler.handle(&req);
        assert!(resp.error.is_none());
        assert!(resp.result.unwrap().is_null());
    }

    #[test]
    fn get_tx_returns_tx_after_submit() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let tx = signed_dummy_tx();
        let tx_hash = tx.tx_hash();
        let tx_bytes = tx.to_bcs().unwrap();

        // submit_tx
        let handler = RpcHandler::new(&backend);
        let submit_req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "submit_tx".to_string(),
            params: serde_json::json!({"tx_bytes": tx_bytes}),
            id: serde_json::json!(1),
        };
        let _ = handler.handle(&submit_req);

        // get_tx
        let get_req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "get_tx".to_string(),
            params: serde_json::json!({"tx_hash": tx_hash}),
            id: serde_json::json!(2),
        };
        let resp = handler.handle(&get_req);
        assert!(resp.error.is_none());
        let tx_resp: Transaction = serde_json::from_value(resp.result.unwrap()).unwrap();
        assert_eq!(tx_resp.tx_hash(), tx_hash);
    }

    // ===== H-1 修复测试：RPC 认证与限流 =====

    #[test]
    fn h1_rate_limit_rejects_excessive_write_requests() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let config = RateLimitConfig {
            write_rps: 2,
            ..Default::default()
        };
        let guard = RpcGuard::rate_limit_only(config);
        let handler = RpcHandler::with_guard(&backend, Arc::new(guard));

        let client = RpcClientInfo {
            client_id: Some("test-client".to_string()),
            ..Default::default()
        };

        // 前两次请求应通过
        for _ in 0..2 {
            let req = JsonRpcRequest {
                jsonrpc: "2.0".to_string(),
                method: "get_block".to_string(), // Read 请求不受 write_rps 限制
                params: serde_json::json!({"height": 0u64}),
                id: serde_json::json!(1),
            };
            let resp = handler.handle_with_client(&req, &client);
            // get_block height=0 不存在，返回 result: null（非错误）
            assert!(resp.error.is_none(), "read 请求不应被 write 限流拒绝");
        }

        // write 请求（submit_tx）超过 write_rps=2 后应被限流
        let tx = signed_dummy_tx();
        let tx_bytes = tx.to_bcs().unwrap();
        for i in 0..3 {
            let req = JsonRpcRequest {
                jsonrpc: "2.0".to_string(),
                method: "submit_tx".to_string(),
                params: serde_json::json!({"tx_bytes": tx_bytes.clone()}),
                id: serde_json::json!(i),
            };
            let resp = handler.handle_with_client(&req, &client);
            if i < 2 {
                // nonce 检查可能拒绝第 2 次（相同 nonce），但不应是限流错误
                if let Some(err) = &resp.error {
                    assert_ne!(err.code, RATE_LIMIT_EXCEEDED, "前 {i} 次请求不应被限流");
                }
            } else {
                // 第 3 次应被限流
                assert!(resp.error.is_some(), "第 {i} 次 write 请求应被限流");
                assert_eq!(resp.error.unwrap().code, RATE_LIMIT_EXCEEDED);
            }
        }
    }

    #[test]
    fn h1_auth_rejects_missing_api_key() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let auth_config = AuthConfig {
            require_auth_for_write: true,
            allowed_api_keys: HashSet::from(["secret-key".to_string()]),
            ..Default::default()
        };
        let guard = RpcGuard::new(RateLimitConfig::default(), auth_config);
        let handler = RpcHandler::with_guard(&backend, Arc::new(guard));

        let client = RpcClientInfo::default(); // 无 API key
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "submit_tx".to_string(),
            params: serde_json::json!({"tx_bytes": vec![0u8; 32]}),
            id: serde_json::json!(1),
        };
        let resp = handler.handle_with_client(&req, &client);
        assert!(resp.error.is_some(), "无 API key 应被拒绝");
        assert_eq!(resp.error.unwrap().code, AUTH_FAILED);
    }

    #[test]
    fn h1_auth_rejects_invalid_api_key() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let auth_config = AuthConfig {
            require_auth_for_write: true,
            allowed_api_keys: HashSet::from(["secret-key".to_string()]),
            ..Default::default()
        };
        let guard = RpcGuard::new(RateLimitConfig::default(), auth_config);
        let handler = RpcHandler::with_guard(&backend, Arc::new(guard));

        let client = RpcClientInfo {
            api_key: Some("wrong-key".to_string()),
            ..Default::default()
        };
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "submit_tx".to_string(),
            params: serde_json::json!({"tx_bytes": vec![0u8; 32]}),
            id: serde_json::json!(1),
        };
        let resp = handler.handle_with_client(&req, &client);
        assert!(resp.error.is_some(), "错误 API key 应被拒绝");
        assert_eq!(resp.error.unwrap().code, AUTH_FAILED);
    }

    #[test]
    fn h1_auth_allows_valid_api_key() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let auth_config = AuthConfig {
            require_auth_for_write: true,
            allowed_api_keys: HashSet::from(["secret-key".to_string()]),
            ..Default::default()
        };
        let guard = RpcGuard::new(RateLimitConfig::default(), auth_config);
        let handler = RpcHandler::with_guard(&backend, Arc::new(guard));

        let tx = signed_dummy_tx();
        let tx_bytes = tx.to_bcs().unwrap();
        let client = RpcClientInfo {
            api_key: Some("secret-key".to_string()),
            client_id: Some("test-client".to_string()),
        };
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "submit_tx".to_string(),
            params: serde_json::json!({"tx_bytes": tx_bytes}),
            id: serde_json::json!(1),
        };
        let resp = handler.handle_with_client(&req, &client);
        assert!(resp.error.is_none(), "正确 API key 应通过认证");
    }

    #[test]
    fn h1_read_endpoints_no_auth_required() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let auth_config = AuthConfig {
            require_auth_for_write: true,
            require_auth_for_crypto: true,
            allowed_api_keys: HashSet::from(["secret-key".to_string()]),
        };
        let guard = RpcGuard::new(RateLimitConfig::default(), auth_config);
        let handler = RpcHandler::with_guard(&backend, Arc::new(guard));

        // Read 请求不需要认证
        let client = RpcClientInfo::default();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "get_block".to_string(),
            params: serde_json::json!({"height": 0u64}),
            id: serde_json::json!(1),
        };
        let resp = handler.handle_with_client(&req, &client);
        assert!(resp.error.is_none(), "read 请求不应要求认证");
    }

    #[test]
    fn h1_rate_limit_independent_per_client() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let config = RateLimitConfig {
            read_rps: 2,
            ..Default::default()
        };
        let guard = RpcGuard::rate_limit_only(config);
        let handler = RpcHandler::with_guard(&backend, Arc::new(guard));

        // client_a 用尽 read 配额
        let client_a = RpcClientInfo {
            client_id: Some("client-a".to_string()),
            ..Default::default()
        };
        for _ in 0..2 {
            let req = JsonRpcRequest {
                jsonrpc: "2.0".to_string(),
                method: "get_block".to_string(),
                params: serde_json::json!({"height": 0u64}),
                id: serde_json::json!(1),
            };
            let _ = handler.handle_with_client(&req, &client_a);
        }
        // client_a 第 3 次应被限流
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "get_block".to_string(),
            params: serde_json::json!({"height": 0u64}),
            id: serde_json::json!(1),
        };
        let resp = handler.handle_with_client(&req, &client_a);
        assert_eq!(
            resp.error.as_ref().unwrap().code,
            RATE_LIMIT_EXCEEDED,
            "client_a 应被限流"
        );

        // client_b 不受 client_a 影响
        let client_b = RpcClientInfo {
            client_id: Some("client-b".to_string()),
            ..Default::default()
        };
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "get_block".to_string(),
            params: serde_json::json!({"height": 0u64}),
            id: serde_json::json!(1),
        };
        let resp = handler.handle_with_client(&req, &client_b);
        assert!(resp.error.is_none(), "client_b 不应被 client_a 的限流影响");
    }

    #[test]
    fn h1_handler_without_guard_backward_compatible() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let handler = RpcHandler::new(&backend); // 无 guard

        let client = RpcClientInfo::default();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "get_block".to_string(),
            params: serde_json::json!({"height": 0u64}),
            id: serde_json::json!(1),
        };
        // handle() 和 handle_with_client() 都应正常工作
        let resp1 = handler.handle(&req);
        let resp2 = handler.handle_with_client(&req, &client);
        assert!(resp1.error.is_none());
        assert!(resp2.error.is_none());
    }

    // ===== M-5 修复测试：RPC 错误脱敏 =====

    #[test]
    fn m5_internal_error_sanitized_to_generic_message() {
        // Rocksdb 错误应被脱敏为 "internal server error"
        let err = RpcHandlerError::from_poker_error(PokerL1Error::Rocksdb(
            "disk I/O failure at /var/data/db".to_string(),
        ));
        match err {
            RpcHandlerError::Internal(msg) => {
                assert_eq!(msg, "internal server error");
                // 确保不泄漏原始路径
                assert!(!msg.contains("/var/data"));
                assert!(!msg.contains("disk I/O"));
            }
            RpcHandlerError::Client(_) => panic!("Rocksdb 错误应被分类为 Internal"),
        }
    }

    #[test]
    fn m5_serialization_error_sanitized() {
        let err = RpcHandlerError::from_poker_error(PokerL1Error::Serialization(
            "bcs: invalid field 'secret_key' at offset 42".to_string(),
        ));
        match err {
            RpcHandlerError::Internal(msg) => {
                assert_eq!(msg, "internal server error");
                assert!(!msg.contains("secret_key"));
                assert!(!msg.contains("offset 42"));
            }
            RpcHandlerError::Client(_) => panic!("Serialization 错误应被分类为 Internal"),
        }
    }

    #[test]
    fn m5_other_error_sanitized() {
        let err = RpcHandlerError::from_poker_error(PokerL1Error::Other(
            "internal state corruption in module xyz".to_string(),
        ));
        match err {
            RpcHandlerError::Internal(msg) => {
                assert_eq!(msg, "internal server error");
                assert!(!msg.contains("corruption"));
                assert!(!msg.contains("xyz"));
            }
            RpcHandlerError::Client(_) => panic!("Other 错误应被分类为 Internal"),
        }
    }

    #[test]
    fn m5_client_error_preserves_specific_message() {
        // TxTooLarge 是客户端错误，应保留具体消息
        let err = RpcHandlerError::from_poker_error(PokerL1Error::TxTooLarge {
            actual: 200_000,
            limit: 131_072,
        });
        match err {
            RpcHandlerError::Client(msg) => {
                assert!(msg.contains("200000"));
                assert!(msg.contains("131072"));
            }
            RpcHandlerError::Internal(_) => panic!("TxTooLarge 应被分类为 Client"),
        }
    }

    #[test]
    fn m5_signature_error_preserves_specific_message() {
        let err = RpcHandlerError::from_poker_error(PokerL1Error::InvalidSignature);
        match err {
            RpcHandlerError::Client(msg) => {
                assert!(msg.contains("signature verification failed"));
            }
            RpcHandlerError::Internal(_) => panic!("InvalidSignature 应被分类为 Client"),
        }
    }

    #[test]
    fn m5_invalid_params_uses_correct_error_code() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let handler = RpcHandler::new(&backend);

        // 提交无效 JSON 参数 → 应返回 INVALID_PARAMS 而非 INTERNAL_ERROR
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "get_block".to_string(),
            params: serde_json::json!("not an object"), // 无效参数类型
            id: serde_json::json!(1),
        };
        let resp = handler.handle(&req);
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, JsonRpcError::INVALID_PARAMS);
    }

    #[test]
    fn m5_tx_too_large_uses_invalid_params_code() {
        let backend = MemoryBackend::new(DEFAULT_CHAIN_ID).unwrap();
        let handler = RpcHandler::new(&backend);

        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: "submit_tx".to_string(),
            params: serde_json::json!({"tx_bytes": vec![0u8; 200_000]}), // 超过 128KB
            id: serde_json::json!(1),
        };
        let resp = handler.handle(&req);
        assert!(resp.error.is_some());
        let err = resp.error.unwrap();
        // TxTooLarge 是客户端错误 → INVALID_PARAMS
        assert_eq!(err.code, JsonRpcError::INVALID_PARAMS);
        // 消息应包含具体限制信息（客户端可见）
        assert!(err.message.contains("131072"));
    }
}
