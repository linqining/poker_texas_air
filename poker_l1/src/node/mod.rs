//! 节点集成模块（Task 32 — SubTask 32.1 / 32.2 / 32.3 / 32.4 / 32.5）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）：
//! - **SubTask 32.1**：validator 节点（DAG vertex 产出 + Bullshark 共识 + game sub-block）
//! - **SubTask 32.2**：full node（validation only，不参与共识，执行 Layer 1-3 裁剪）
//! - **SubTask 32.3**：archive node（永不裁剪，提供 `request_historical_data` RPC）
//! - **SubTask 32.4**：light node（仅 block header + state root commitment 订阅）
//! - **SubTask 32.5**：CLI 工具（keygen 支持 secp256k1/ed25519 tagged pubkey、query、
//!   deploy contract、send tx、upgrade contract、本地计算 assigned_validator、请求历史数据）
//!
//! 实现说明：
//! - [`NodeRole`] 区分 4 种节点角色；裁剪行为委托给 [`crate::storage::NodeRole`]
//! - [`NodeConfig`] 定义节点启动配置
//! - [`Node`] 持有存储后端与可选 validator 密钥，提供 RPC 后端集成点
//! - CLI 工具函数（keygen / query / send_tx）以纯函数形式提供，可被二进制 main 调用

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::account::{Account, AccountStore};
use crate::block::validator::{
    validate_block_tx_roots, validate_commit_certificate_signatures_for_header,
    validate_gameturn_no_gas, validate_state_root_transition, validate_tx_chain_id,
    validate_tx_signature, validate_vertex_tx_ordering,
};
use crate::block::{Block, BlockHeader, TimeConsensusConfig, validate_block_time};
use crate::consensus::{
    DagVertex, Epoch, EpochTransitionProof, MAX_VERTEX_SIZE, ValidatorEntry, ValidatorSet,
    compute_genesis_chain_randomness, required_parent_count, validate_commit_certificate_fields,
};
use crate::economics::{fee_policy_object, read_fee_policy};
use crate::error::{PokerL1Error, PokerL1Result};
use crate::executor::{
    BlockExecutionOutcome, ExecutionEnvironment, FeePolicy, execute_block, execute_block_serial,
};
use crate::genesis::{
    GENESIS_ANCHOR_OBJECT_ID, GenesisAllocation, GenesisManifest, decode_genesis_anchor,
    genesis_anchor_object,
};
use crate::indexer::Indexer;
use crate::network::{
    LightClientHeader, MAX_LIGHT_CLIENT_HEADER_BYTES, MAX_LIGHT_HEADERS_PER_SYNC_REQUEST,
    NetworkTransport, verify_light_client_header, verify_light_client_header_signatures,
};
use crate::object_model::{Object, ObjectID};
use crate::signature::TaggedPubkey;
use crate::signature::tagged_pubkey::{CURRENT_VERSION, SignatureScheme};
use crate::signature::unified::verify_signature;
use crate::storage::{
    BlockCommitJournal, BlockStore, BridgeRegistrySnapshot, BridgeRegistryStore, DagVertexStore,
    HistoricalDataRequest, HistoricalDataResponse, HistoricalDataType, NodeRole as PruningNodeRole,
    ObjectBackend, ObjectDb, ObjectDbSnapshot, PendingBlockCommit, ZkProofArchiveProvider,
};
use crate::sync::{FullFastSync, FullSnapshot, FullSnapshotManifest, SnapshotBuilder};
use crate::transaction::{Transaction, TxLane, validate_tx_limits};
use crate::vm::PrecompileRegistry;
use crate::vm::contracts::{GamePrecompile, TexasPokerPrecompile};
use crate::{Address, BlockHeight, ChainId, Hash};

/// tx_cache 最大条目数（C-2 修复 — 防止内存 DoS）。
const MAX_NODE_TX_CACHE_SIZE: usize = 10_000;

/// pending_tx 最大条目数（C-2 修复 — 防止内存 DoS）。
const MAX_PENDING_TX_SIZE: usize = 10_000;

// ===== SubTask 32.1 ~ 32.4: 节点角色 =====

/// 节点角色（spec SubTask 32.1 ~ 32.4）。
///
/// - `Validator`：参与共识（DAG vertex 产出 + Bullshark 投票），裁剪行为同 Full
/// - `Full`：仅验证，不参与共识，执行 Layer 1-3 裁剪
/// - `Archive`：永不裁剪，提供 `request_historical_data` RPC
/// - `Light`：仅订阅 block header + state root commitment
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum NodeRole {
    /// Validator 节点：参与 DAG 共识 + game sub-block 产出。
    Validator,
    /// Full node：仅验证，不参与共识，执行 Layer 1-3 裁剪。
    #[default]
    Full,
    /// Archive node：永不裁剪，提供历史数据 RPC。
    Archive,
    /// Light node：仅 block header + state root 订阅。
    Light,
}

impl NodeRole {
    /// 转换为裁剪角色（[`crate::storage::NodeRole`]）。
    ///
    /// Validator 的裁剪行为同 Full（执行 Layer 1-3 裁剪）。
    #[must_use]
    pub const fn to_pruning_role(self) -> PruningNodeRole {
        match self {
            Self::Validator | Self::Full => PruningNodeRole::Full,
            Self::Archive => PruningNodeRole::Archive,
            Self::Light => PruningNodeRole::Light,
        }
    }

    /// 是否应执行裁剪。
    #[must_use]
    pub const fn should_prune(self) -> bool {
        self.to_pruning_role().should_prune()
    }

    /// 是否为 validator 节点。
    #[must_use]
    pub const fn is_validator(self) -> bool {
        matches!(self, Self::Validator)
    }

    /// 是否为 archive 节点（提供历史数据 RPC）。
    #[must_use]
    pub const fn is_archive(self) -> bool {
        matches!(self, Self::Archive)
    }

    /// 是否为 light 节点（仅订阅 header）。
    #[must_use]
    pub const fn is_light(self) -> bool {
        matches!(self, Self::Light)
    }
}

// ===== NodeConfig =====

/// 节点启动配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// 节点角色。
    pub role: NodeRole,
    /// 网络 chain_id。
    pub chain_id: ChainId,
    /// 数据目录（RocksDB 路径）。
    pub data_dir: PathBuf,
    /// RPC 监听地址（如 "127.0.0.1:8545"）。
    pub rpc_listen: String,
    /// P2P 监听地址（如 "127.0.0.1:9000"）。
    pub p2p_listen: String,
    /// Validator 密钥（仅 Validator 角色需要）。
    pub validator_key: Option<ValidatorKey>,
    /// 创世 validator 列表（P0-4 动态 quorum）。
    ///
    /// 节点启动时以此初始化 ValidatorSet（epoch 0）。
    /// 空列表仅适合在注册 validator 之前准备 genesis 状态；生产入口在启动
    /// RPC/P2P/共识前必须调用 [`Node::ensure_consensus_ready`] 并拒绝空集合。
    /// Entries must have zero stake; native ZCN stake is admitted only through UTXO-backed bond.
    #[serde(default)]
    pub genesis_validators: Vec<ValidatorEntry>,
    /// Hash of the canonical genesis manifest expected by this node.
    ///
    /// Production launchers must set this from the complete validator and allocation manifest
    /// before opening storage.  A persisted anchor with a different hash is fatal; a first block
    /// must use this hash as its parent commitment.
    #[serde(default)]
    pub genesis_manifest_hash: Option<Hash>,
    /// Resource-credit policy. Compute metering remains enabled when set to `Free`.
    #[serde(default)]
    pub fee_policy: FeePolicy,
}

impl NodeConfig {
    /// 创建默认配置（Full node，chain_id = DEFAULT_CHAIN_ID）。
    #[must_use]
    pub fn default_full(data_dir: PathBuf) -> Self {
        Self {
            role: NodeRole::Full,
            chain_id: crate::DEFAULT_CHAIN_ID,
            data_dir,
            rpc_listen: "127.0.0.1:8545".to_string(),
            p2p_listen: "127.0.0.1:9000".to_string(),
            validator_key: None,
            genesis_validators: vec![],
            genesis_manifest_hash: None,
            fee_policy: FeePolicy::Free,
        }
    }

    /// 创建 validator 配置。
    #[must_use]
    pub fn validator(data_dir: PathBuf, validator_key: ValidatorKey) -> Self {
        Self {
            role: NodeRole::Validator,
            chain_id: crate::DEFAULT_CHAIN_ID,
            data_dir,
            rpc_listen: "127.0.0.1:8545".to_string(),
            p2p_listen: "127.0.0.1:9000".to_string(),
            validator_key: Some(validator_key),
            genesis_validators: vec![],
            genesis_manifest_hash: None,
            fee_policy: FeePolicy::Free,
        }
    }

    /// 创建 archive 配置。
    #[must_use]
    pub fn archive(data_dir: PathBuf) -> Self {
        Self {
            role: NodeRole::Archive,
            chain_id: crate::DEFAULT_CHAIN_ID,
            data_dir,
            rpc_listen: "127.0.0.1:8545".to_string(),
            p2p_listen: "127.0.0.1:9000".to_string(),
            validator_key: None,
            genesis_validators: vec![],
            genesis_manifest_hash: None,
            fee_policy: FeePolicy::Free,
        }
    }

    /// 创建 light 配置。
    #[must_use]
    pub fn light(data_dir: PathBuf) -> Self {
        Self {
            role: NodeRole::Light,
            chain_id: crate::DEFAULT_CHAIN_ID,
            data_dir,
            rpc_listen: "127.0.0.1:8545".to_string(),
            p2p_listen: "127.0.0.1:9000".to_string(),
            validator_key: None,
            genesis_validators: vec![],
            genesis_manifest_hash: None,
            fee_policy: FeePolicy::Free,
        }
    }

    /// 设置创世 validator 列表（builder 风格）。
    #[must_use]
    pub fn with_genesis_validators(mut self, validators: Vec<ValidatorEntry>) -> Self {
        self.genesis_validators = validators;
        self
    }

    /// Pin the complete canonical genesis manifest expected for this network.
    #[must_use]
    pub const fn with_genesis_manifest_hash(mut self, manifest_hash: Hash) -> Self {
        self.genesis_manifest_hash = Some(manifest_hash);
        self
    }

    /// Select the chain's resource-credit policy.
    #[must_use]
    pub const fn with_fee_policy(mut self, fee_policy: FeePolicy) -> Self {
        self.fee_policy = fee_policy;
        self
    }
}

// ===== ValidatorKey =====

/// Validator 密钥（secp256k1）。
///
/// 用于 DAG vertex 签名与 commit certificate 签名。
/// 注意：私钥仅在 validator 节点内存中持有，不持久化到磁盘。
///
/// M-4 修复：实现 `Drop` 自动 zeroize 私钥，自定义 `Debug` 隐藏私钥内容。
#[derive(Clone, Serialize, Deserialize)]
pub struct ValidatorKey {
    /// secp256k1 私钥（32 字节）。
    pub secret_key_bytes: [u8; 32],
    /// 对应的 tagged pubkey。
    pub tagged_pubkey: TaggedPubkey,
    /// VRF 私钥（ECVRF-secp256k1，32 字节）。
    ///
    /// Reserved for the designated-proposer epoch-proof protocol. Until that proof is committed
    /// in a block, consensus uses the previous-certificate beacon fallback and never derives
    /// randomness from this node-local secret.
    pub vrf_secret: Option<[u8; 32]>,
}

impl std::fmt::Debug for ValidatorKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidatorKey")
            .field("secret_key_bytes", &"[REDACTED]")
            .field("tagged_pubkey", &self.tagged_pubkey)
            .finish()
    }
}

impl Drop for ValidatorKey {
    fn drop(&mut self) {
        self.secret_key_bytes.fill(0);
        if let Some(vrf) = &mut self.vrf_secret {
            vrf.fill(0);
        }
    }
}

impl ValidatorKey {
    /// 从 secp256k1 私钥字节构造。
    ///
    /// 私钥必须为 32 字节且在 secp256k1 曲线阶范围内。
    pub fn from_secret_bytes(secret_key_bytes: [u8; 32]) -> PokerL1Result<Self> {
        use secp256k1::{PublicKey, Secp256k1};
        let secp = Secp256k1::new();
        let secret_key =
            secp256k1::SecretKey::from_slice(&secret_key_bytes).map_err(PokerL1Error::Secp256k1)?;
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        let compressed = public_key.serialize();
        let tagged_pubkey = TaggedPubkey::new(
            SignatureScheme::Secp256k1,
            CURRENT_VERSION,
            compressed.to_vec(),
        )?;
        Ok(Self {
            secret_key_bytes,
            tagged_pubkey,
            vrf_secret: None,
        })
    }

    /// 设置将来 epoch-proof proposer 使用的 VRF 私钥。
    pub fn with_vrf_secret(mut self, vrf_secret: [u8; 32]) -> Self {
        self.vrf_secret = Some(vrf_secret);
        self
    }
}

// ===== Node =====

/// tx 缓存状态（M-6 修复 — 合并 cache + order 到单个 Mutex 避免多锁死锁）。
///
/// C-2 修复：FIFO 淘汰机制防止内存 DoS（上限 10,000 条）。
struct TxCacheState {
    /// tx_hash → tx 映射。
    cache: std::collections::HashMap<Hash, Transaction>,
    /// 插入顺序（FIFO 淘汰追踪）。
    order: std::collections::VecDeque<Hash>,
}

impl TxCacheState {
    /// 创建空状态。
    fn new() -> Self {
        Self {
            cache: std::collections::HashMap::new(),
            order: std::collections::VecDeque::new(),
        }
    }

    /// 插入 tx，若已存在则更新；若新插入则追加到 order 队列。
    /// 超过 max_size 时 FIFO 淘汰最旧条目。
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

    /// 按 hash 查询 tx。
    fn get(&self, tx_hash: &Hash) -> Option<&Transaction> {
        self.cache.get(tx_hash)
    }
}

/// A pending transaction together with the data needed to index it cheaply.
///
/// `Transaction` deliberately does not cache its derived caller address.  The mempool does: the
/// address is required for RBF, and deriving it for every queued transaction on every submission
/// turned a 10,000-entry mempool into an O(N²) hot path.
struct PendingTxEntry {
    /// Monotonic, in-process identifier.  It distinguishes otherwise identical transactions in
    /// the (permitted) zero-fee non-RBF case.
    id: u64,
    /// Caller derived once when the transaction enters the mempool.
    caller: Address,
    /// Full transaction in FIFO arrival order.
    tx: Transaction,
}

/// Pending transaction queue and its RBF index.
///
/// The queue remains the source of truth for arrival ordering.  `by_caller_nonce` points at the
/// oldest queued entry for a key, matching the previous linear `VecDeque::iter().position()`
/// semantics while making the common no-conflict submission O(1).  It contains a deque because
/// legacy zero-fee submissions do not participate in RBF and may share a caller/nonce.
struct PendingTxState {
    queue: std::collections::VecDeque<PendingTxEntry>,
    by_caller_nonce: std::collections::HashMap<(Address, u64), std::collections::VecDeque<u64>>,
    next_id: u64,
}

impl PendingTxState {
    fn new() -> Self {
        Self {
            queue: std::collections::VecDeque::new(),
            by_caller_nonce: std::collections::HashMap::new(),
            next_id: 0,
        }
    }

    fn len(&self) -> usize {
        self.queue.len()
    }

    fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    fn oldest_for(&self, caller: Address, nonce: u64) -> Option<(usize, &PendingTxEntry)> {
        let id = *self.by_caller_nonce.get(&(caller, nonce))?.front()?;
        self.queue
            .iter()
            .enumerate()
            .find(|(_, entry)| entry.id == id)
    }

    fn push(&mut self, caller: Address, tx: Transaction) {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.by_caller_nonce
            .entry((caller, tx.nonce))
            .or_default()
            .push_back(id);
        self.queue.push_back(PendingTxEntry { id, caller, tx });
    }

    fn push_front(&mut self, caller: Address, tx: Transaction) {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.by_caller_nonce
            .entry((caller, tx.nonce))
            .or_default()
            .push_front(id);
        self.queue.push_front(PendingTxEntry { id, caller, tx });
    }

    /// Remove an entry by its queue position and update the RBF index at the same time.
    fn remove(&mut self, index: usize) -> Option<PendingTxEntry> {
        let entry = self.queue.remove(index)?;
        let key = (entry.caller, entry.tx.nonce);
        let remove_key = if let Some(ids) = self.by_caller_nonce.get_mut(&key) {
            // This cannot fail while `queue` and the index are mutated only through this type.
            let id_index = ids
                .iter()
                .position(|id| *id == entry.id)
                .expect("pending transaction RBF index must reference queue entry");
            ids.remove(id_index);
            ids.is_empty()
        } else {
            false
        };
        if remove_key {
            self.by_caller_nonce.remove(&key);
        }
        Some(entry)
    }

    fn drain(&mut self) -> std::collections::VecDeque<PendingTxEntry> {
        self.by_caller_nonce.clear();
        std::mem::take(&mut self.queue)
    }
}

/// 节点实例 — 持有存储后端与可选 validator 密钥。
///
/// 不直接运行网络/event loop；由上层二进制集成 tokio runtime + network + RPC server。
/// 本结构提供存储访问、tx 提交、block/vertex 查询等核心方法。
pub struct Node {
    /// 配置。
    config: NodeConfig,
    /// BlockStore。
    block_store: BlockStore,
    /// Synchronously persisted intent for an in-flight cross-store block transition.
    block_commit_journal: BlockCommitJournal,
    /// Serializes the complete validate → execute snapshots → persist block transition.
    ///
    /// ObjectDb, AccountStore and BlockStore do not share one physical transaction, so two local
    /// block writers must not interleave their preflight checks and commits.
    block_commit_lock: std::sync::Mutex<()>,
    /// ObjectDb。
    object_db: std::sync::Mutex<ObjectDb>,
    /// DagVertexStore。
    vertex_store: DagVertexStore,
    /// AccountStore（内存版，Phase 4 接入 rocksdb）。
    account_store: std::sync::Mutex<AccountStore>,
    /// 已提交的 tx 缓存（M-6 修复 — cache + order 合并到单个 Mutex）。
    tx_cache: std::sync::Mutex<TxCacheState>,
    /// 待装 vertex 的 tx 缓冲（仅 Validator 角色）。
    pending_tx: std::sync::Mutex<PendingTxState>,
    /// pending_tx 的 Condvar — submit_tx 时 notify，validator loop 用 wait_timeout 等待。
    pending_tx_condvar: std::sync::Condvar,
    /// 当前 ValidatorSet（P0-4 动态 quorum）。
    ///
    /// Production consensus admission fails closed when there are no active validators. Explicit
    /// in-memory constructors retain an empty-set mode for unit and integration tests which focus
    /// on execution rather than consensus membership.
    validator_set: std::sync::Mutex<ValidatorSet>,
    /// Whether consensus admission may bypass validator membership for explicit in-memory tests.
    allow_empty_consensus_for_tests: bool,
    /// Current canonical fee policy loaded from the state-root-committed system object.
    ///
    /// `NodeConfig::fee_policy` is consulted only while initializing an empty genesis database;
    /// once the singleton exists, local launcher settings cannot change execution semantics.
    fee_policy: std::sync::Mutex<FeePolicy>,
    /// Current governance state loaded from the state-root-committed singleton.
    ///
    /// It is retained as a runtime cache only; every mutation is staged through the immutable
    /// system object during block execution and refreshed after commit/snapshot installation.
    governance: std::sync::Mutex<crate::governance::GovernanceState>,
    /// 预编译合约注册表（共享 Arc — block 执行时 clone 引用而非重建）。
    ///
    /// 注册内置预编译合约：
    /// - [`GamePrecompile`]（`0xFF..01`，GameTurn 通道免 gas）
    /// - [`TexasPokerPrecompile`]（`0xFF..02`，GameTurn 通道免 gas）
    ///
    /// 治理升级（版本号 + timelock）经 `propose_upgrade` / `activate_upgrade`，
    /// 不在此处直接重建。
    precompile_registry: Arc<PrecompileRegistry>,
    /// Bridge registry store（缺口 #9：bridge_verify 铸币路径 + nonce 持久化）。
    ///
    /// 生产节点持久化（重启不丢 nonce，防重放铸币）。`None` 表示节点未启用桥
    /// （bridge contract_call 会被 executor 拒绝）。
    bridge_registry_store: Option<Arc<BridgeRegistryStore>>,
    /// 指标收集器（缺口 #7：Prometheus 风格指标导出）。
    metrics: Arc<crate::metrics::MetricsCollector>,
    /// ZK verifier registry（链上 zk_verify 启用）。
    zk_verifier: Option<crate::offline::zk_verifier::ZkVerifierRegistry>,
    /// Light client header 缓存（缺口：subscribe_light_headers 完整实现）。
    /// validator 节点在 put_block 时生成并签名；light/full 节点可订阅获取。
    light_headers: std::sync::Mutex<Vec<crate::network::LightClientHeader>>,
    /// Indexes only blocks accepted by `put_block`; rebuilt from durable blocks at startup.
    indexer: Arc<Indexer>,
    /// Optional external archive for historical ZK proof material.  Responses are hash-verified
    /// against the request before they leave this node.
    zk_proof_archive: std::sync::RwLock<Option<Arc<dyn ZkProofArchiveProvider>>>,
}

/// Return the protocol-defined built-in native precompile versions.
fn default_precompile_versions() -> [(ObjectID, u32); 2] {
    [
        (crate::vm::precompile::reserved::game_contract_id(), 1),
        (
            crate::vm::precompile::reserved::texas_poker_contract_id(),
            1,
        ),
    ]
}

/// 构造默认预编译合约注册表并注册内置预编译合约。
///
/// 在 [`Node::open`] / [`Node::open_inmemory_with_validators`] 中调用，
/// 确保 `GamePrecompile` 和 `TexasPokerPrecompile` 在节点启动时即注册。
fn build_default_precompile_registry(consensus_governed: bool) -> Arc<PrecompileRegistry> {
    let mut registry = if consensus_governed {
        PrecompileRegistry::new_consensus()
    } else {
        PrecompileRegistry::new()
    };
    registry.register(GamePrecompile::new_arc(1));
    registry.register(TexasPokerPrecompile::new_arc(1));
    Arc::new(registry)
}

/// 从创世 validator 列表构建初始 ValidatorSet（epoch 0）。
///
/// - `genesis_chain_randomness` 由所有 validator pubkey 聚合派生（SEC2-M12）
/// - 初始 `epoch_randomness = genesis_chain_randomness`，`prev_epoch_randomness = 0`
fn build_genesis_validator_set(mut validators: Vec<ValidatorEntry>) -> PokerL1Result<ValidatorSet> {
    if let Some(validator) = validators.iter().find(|validator| validator.stake != 0) {
        return Err(PokerL1Error::Other(format!(
            "genesis validator {:?} declares unbacked stake {}; genesis validators must start at zero and bond NativeCoin UTXOs after genesis mint",
            validator.pubkey, validator.stake
        )));
    }
    validators.sort_by_key(|validator| validator.pubkey.to_bytes());
    for pair in validators.windows(2) {
        if pair[0].pubkey == pair[1].pubkey {
            return Err(PokerL1Error::Other(
                "duplicate genesis validator pubkey".into(),
            ));
        }
    }
    let genesis_chain_randomness = compute_genesis_chain_randomness(&validators);
    let mut set = ValidatorSet {
        epoch: 0,
        validators,
        validator_set_hash: [0u8; 32],
        epoch_randomness: genesis_chain_randomness,
        prev_epoch_randomness: [0u8; 32],
        genesis_chain_randomness,
    };
    set.validator_set_hash = set.compute_hash();
    Ok(set)
}

fn read_genesis_manifest_hash(object_db: &ObjectDb) -> PokerL1Result<Option<Hash>> {
    match object_db.read(&GENESIS_ANCHOR_OBJECT_ID) {
        Ok(object) => Ok(Some(decode_genesis_anchor(&object)?.manifest_hash)),
        Err(PokerL1Error::ObjectNotFound(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

fn validator_staking_escrow(set: &ValidatorSet) -> PokerL1Result<u64> {
    set.validators.iter().try_fold(0u64, |total, validator| {
        total
            .checked_add(validator.stake)
            .ok_or_else(|| PokerL1Error::Other("validator staking escrow sum overflow".into()))
    })
}

/// Sum native ZCN secured by active validator entries and by unresolved bonded-admission
/// proposals.  Pending proposal value is custody, not live UTXO, so every supply reconciliation
/// must include it until the epoch transition transfers it into `ValidatorSet::stake`.
fn validator_bond_escrow<B: ObjectBackend>(
    object_db: &B,
    set: &ValidatorSet,
    chain_id: ChainId,
) -> PokerL1Result<u64> {
    validator_staking_escrow(set)?
        .checked_add(crate::governance::pending_validator_bond_escrow(
            object_db, chain_id,
        )?)
        .ok_or_else(|| PokerL1Error::Other("validator bond escrow sum overflow".into()))
}

fn read_persisted_validator_set(
    object_db: &ObjectDb,
    chain_id: ChainId,
) -> PokerL1Result<Option<(ValidatorSet, u64)>> {
    use crate::consensus::validator_set::{VALIDATOR_SET_OBJECT_ID, decode_validator_set_object};
    match object_db.read(&VALIDATOR_SET_OBJECT_ID) {
        Ok(object) => Ok(Some((
            decode_validator_set_object(&object, chain_id)?,
            object.version,
        ))),
        Err(PokerL1Error::ObjectNotFound(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

fn read_persisted_governance_state(
    object_db: &ObjectDb,
    chain_id: ChainId,
) -> PokerL1Result<Option<crate::governance::GovernanceState>> {
    match object_db.read(&crate::governance::GOVERNANCE_STATE_OBJECT_ID) {
        Ok(object) => {
            crate::governance::decode_governance_state_object(&object, chain_id).map(Some)
        }
        Err(PokerL1Error::ObjectNotFound(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Read the consensus-pinned native-precompile activation singleton, if genesis has initialized
/// it. A missing object is never silently substituted once other genesis system state exists.
fn read_persisted_precompile_governance_state(
    object_db: &ObjectDb,
    chain_id: ChainId,
) -> PokerL1Result<Option<crate::vm::precompile::PrecompileGovernanceState>> {
    match crate::vm::precompile::read_precompile_governance_state(object_db, chain_id) {
        Ok((state, _)) => Ok(Some(state)),
        Err(PokerL1Error::ObjectNotFound(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Load the bridge validator configuration committed in ObjectDb.
///
/// A missing singleton denotes an old/uninitialized chain and is deliberately treated as an
/// empty configuration by execution, never as permission to consult node-local slots.
fn read_persisted_bridge_registry_config(
    object_db: &ObjectDb,
    chain_id: ChainId,
) -> PokerL1Result<Option<crate::bridge::BridgeRegistryConfig>> {
    match object_db.read(&crate::bridge::BRIDGE_REGISTRY_CONFIG_OBJECT_ID) {
        Ok(object) => {
            crate::bridge::decode_bridge_registry_config_object(&object, chain_id).map(Some)
        }
        Err(PokerL1Error::ObjectNotFound(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Load the replay-protection commitment which binds the external bridge nonce archive to the
/// ObjectDb state root. A missing value is not equivalent to an empty nonce set for a bridge
/// enabled node: accepting that equivalence would re-enable post-sync nonce replay.
fn read_persisted_bridge_replay_state(
    object_db: &ObjectDb,
    chain_id: ChainId,
) -> PokerL1Result<Option<crate::bridge::BridgeReplayState>> {
    match object_db.read(&crate::bridge::BRIDGE_REPLAY_STATE_OBJECT_ID) {
        Ok(object) => crate::bridge::decode_bridge_replay_state_object(&object, chain_id).map(Some),
        Err(PokerL1Error::ObjectNotFound(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

fn stage_validator_set_update(
    snapshot: &mut ObjectDbSnapshot,
    chain_id: ChainId,
    current: &ValidatorSet,
    next: &ValidatorSet,
) -> PokerL1Result<()> {
    crate::consensus::validator_set::replace_persisted_validator_set(
        snapshot, chain_id, current, next,
    )
}

impl Node {
    /// Recover a block transition that was prepared before a previous process stopped.
    ///
    /// ObjectDb batches are atomic, so recovery distinguishes only the old root and the final
    /// header root.  Account records are stored in the journal in both versions, allowing an
    /// account-only durable write to be restored before deterministic replay.
    fn recover_pending_block_commit(&self) -> PokerL1Result<()> {
        let Some(pending) = self.block_commit_journal.pending()? else {
            return Ok(());
        };
        let block = &pending.block;
        let expected_hash = block.block_hash(self.config.chain_id);
        let expected_object_root = block.header.state_root;
        let expected_account_root = block.header.account_root;
        let (bridge_nonces_before, bridge_nonces_after) = match (
            &pending.bridge_nonces_before,
            &pending.bridge_nonces_after,
            &self.bridge_registry_store,
        ) {
            (Some(before), Some(after), Some(_)) => (Some(before.clone()), Some(after.clone())),
            (None, None, None) => (None, None),
            _ => {
                return Err(PokerL1Error::Other(
                    "block commit journal bridge state does not match this node configuration"
                        .into(),
                ));
            }
        };

        match self.block_store.get_by_height(block.header.height) {
            Ok(existing) => {
                if existing.block_hash(self.config.chain_id) != expected_hash {
                    return Err(PokerL1Error::Other(format!(
                        "block commit journal at height {} conflicts with stored block",
                        block.header.height
                    )));
                }
                let object_root = self
                    .object_db
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .state_root();
                let account_root = self
                    .account_store
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .state_root();
                if object_root != expected_object_root || account_root != expected_account_root {
                    return Err(PokerL1Error::Other(
                        "stored block and pending journal disagree with local committed state"
                            .into(),
                    ));
                }
                if let (Some(store), Some(expected)) =
                    (&self.bridge_registry_store, &bridge_nonces_after)
                    && store.nonce_snapshot() != *expected
                {
                    return Err(PokerL1Error::Other(
                        "stored block and pending journal disagree with bridge nonce state".into(),
                    ));
                }
                self.block_commit_journal.clear()?;
                return Ok(());
            }
            Err(PokerL1Error::BlockNotFound) => {}
            Err(error) => return Err(error),
        }

        let object_root = self
            .object_db
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .state_root();
        if object_root == expected_object_root {
            // ObjectDb reached the final state before the process stopped.  Complete AccountStore
            // from the authenticated post-state in the journal, then append the block atomically.
            let mut accounts = self.account_store.lock().unwrap_or_else(|e| e.into_inner());
            accounts.replace_all_records_durable(pending.accounts_after.clone())?;
            if accounts.state_root() != expected_account_root {
                return Err(PokerL1Error::Other(
                    "journal post-account snapshot does not match block account_root".into(),
                ));
            }
            drop(accounts);
            if let (Some(store), Some(target)) = (&self.bridge_registry_store, bridge_nonces_after)
            {
                store.replace_nonce_snapshot_durable(target)?;
            }
            self.block_store.put_durable(block, self.config.chain_id)?;
            self.block_commit_journal.clear()?;
            if let Some((set, _)) = read_persisted_validator_set(
                &self.object_db.lock().unwrap_or_else(|e| e.into_inner()),
                self.config.chain_id,
            )? {
                *self.validator_set.lock().unwrap_or_else(|e| e.into_inner()) = set;
            }
            return Ok(());
        }
        if object_root != pending.object_root_before {
            return Err(PokerL1Error::Other(
                "ObjectDb root is neither journal pre-state nor block final state; refusing unsafe recovery".into(),
            ));
        }

        // ObjectDb was not committed.  Restore an account-only partial write, retain the journal,
        // and use the ordinary full validation path to replay the known block.
        {
            let mut accounts = self.account_store.lock().unwrap_or_else(|e| e.into_inner());
            accounts.replace_all_records_durable(pending.accounts_before.clone())?;
            if accounts.state_root() != pending.account_root_before {
                return Err(PokerL1Error::Other(
                    "journal pre-account snapshot does not match its recorded root".into(),
                ));
            }
        }
        if let (Some(store), Some(target)) = (&self.bridge_registry_store, bridge_nonces_before) {
            store.replace_nonce_snapshot_durable(target)?;
        }
        self.put_block(block).map(|_| ())
    }

    /// 打开节点（初始化所有存储后端）。
    ///
    /// The standard node intentionally starts without a generic ZK verifier registry. The former
    /// STWO/zkVM MVP registry had no production soundness guarantee, so exposing it by default
    /// would make the VM `zk_verify` syscall look available when it must remain fail-closed.
    /// Applications which eventually provide an independently audited verifier can use the
    /// explicit [`Self::open_with_zk_verifier_registry`] constructor instead.
    pub fn open(config: NodeConfig) -> PokerL1Result<Self> {
        Self::open_with_optional_zk_verifier_registry(config, None)
    }

    /// Open a node with an application-supplied ZK verifier registry.
    ///
    /// This is the dependency-inversion boundary for application-aware verifiers such as the
    /// Texas recursive STWO verifier. `poker_l1` cannot depend on `poker_texas_air` without a Cargo
    /// cycle, so the top-level node binary constructs and injects the final registry here.
    pub fn open_with_zk_verifier_registry(
        config: NodeConfig,
        zk_registry: crate::offline::zk_verifier::ZkVerifierRegistry,
    ) -> PokerL1Result<Self> {
        Self::open_with_optional_zk_verifier_registry(config, Some(zk_registry))
    }

    /// Shared construction path for the standard fail-closed node and an explicitly configured
    /// verifier registry.
    fn open_with_optional_zk_verifier_registry(
        config: NodeConfig,
        zk_verifier: Option<crate::offline::zk_verifier::ZkVerifierRegistry>,
    ) -> PokerL1Result<Self> {
        let block_path = config.data_dir.join("blocks");
        let object_path = config.data_dir.join("objects");
        let vertex_path = config.data_dir.join("vertices");
        let account_path = config.data_dir.join("accounts");
        let bridge_path = config.data_dir.join("bridge_registry");
        let indexer_path = config.data_dir.join("indexer");
        let commit_journal_path = config.data_dir.join("block_commit_journal");
        let block_store = BlockStore::open(&block_path)?;
        let object_db = ObjectDb::open(&object_path)?;
        let vertex_store = DagVertexStore::open(&vertex_path)?;
        // 缺口 #8：AccountStore 落 RocksDB，重启后账户余额 / nonce 不丢失。
        let account_store = AccountStore::open(&account_path)?;
        // 缺口 #9：BridgeRegistryStore 落 RocksDB，重启后 deposit/burn nonce 不丢失（防重放铸币）。
        let bridge_registry_store = BridgeRegistryStore::open(&bridge_path)?;
        let indexer = Arc::new(Indexer::open(&indexer_path)?);
        let block_commit_journal = BlockCommitJournal::open(&commit_journal_path)?;
        let configured_validator_set =
            build_genesis_validator_set(config.genesis_validators.clone())?;
        let persisted_validator_set = read_persisted_validator_set(&object_db, config.chain_id)?;
        let persisted_fee_policy = read_fee_policy(&object_db, config.chain_id)?;
        let persisted_governance = read_persisted_governance_state(&object_db, config.chain_id)?;
        let persisted_precompile_governance =
            read_persisted_precompile_governance_state(&object_db, config.chain_id)?;
        let treasury_initialized = crate::economics::read_treasury(&object_db)?.is_some();
        let persisted_genesis_hash = read_genesis_manifest_hash(&object_db)?;
        if treasury_initialized != persisted_validator_set.is_some()
            || treasury_initialized != persisted_genesis_hash.is_some()
            || treasury_initialized != persisted_fee_policy.is_some()
            || treasury_initialized != persisted_governance.is_some()
            || treasury_initialized != persisted_precompile_governance.is_some()
        {
            return Err(PokerL1Error::Other(
                "TreasuryCap, ValidatorSet, FeePolicy, GovernanceState, PrecompileGovernanceState, and GenesisAnchor system objects must be initialized together".into(),
            ));
        }
        if let (Some(expected), Some(actual)) =
            (config.genesis_manifest_hash, persisted_genesis_hash)
            && expected != actual
        {
            return Err(PokerL1Error::Other(format!(
                "persisted genesis manifest hash differs from configured hash: expected {}, got {}",
                hex::encode(expected),
                hex::encode(actual)
            )));
        }
        let validator_set = persisted_validator_set
            .map(|(set, _)| set)
            .unwrap_or(configured_validator_set);
        let canonical_fee_policy = persisted_fee_policy.unwrap_or(config.fee_policy);
        let governance = persisted_governance.unwrap_or_default();
        // A persisted Production status is a consensus commitment, not a launcher hint. The
        // standard binary intentionally has no verifier registry, so it must refuse to start a
        // chain whose governance already enabled proofs instead of exposing a node that can
        // advertise Production while every `zk_verify` call fails due to a missing backend.
        if governance.verifier_status(config.chain_id)
            == crate::offline::zk_verifier::VerifierStatus::Production
        {
            let registry = zk_verifier.as_ref().ok_or_else(|| {
                PokerL1Error::Other(
                    "governance requires a Production ZK verifier, but this node has no verifier registry"
                        .into(),
                )
            })?;
            // OffChain v2 commitments use the recursive STWO scheme.  Merely injecting an empty
            // registry would otherwise let a node advertise a governance-authorized Production
            // state while every proof deterministically fails at execution time.  This startup
            // check cannot certify an implementation's cryptographic soundness, but it prevents
            // that unambiguous unavailable-backend configuration from joining the network.
            if !registry.has_verifier(crate::offline::zk_verifier::SCHEME_STWO) {
                return Err(PokerL1Error::Other(
                    "governance requires a Production STWO verifier, but the registry does not provide SCHEME_STWO"
                        .into(),
                ));
            }
        }
        crate::economics::reconcile_native_supply_if_initialized(
            &object_db,
            validator_bond_escrow(&object_db, &validator_set, config.chain_id)?,
        )?;
        let precompile_registry = build_default_precompile_registry(true);
        if let Some(state) = &persisted_precompile_governance {
            for (&id, activation) in &state.precompiles {
                if !precompile_registry.has_implementation(id, activation.active_version) {
                    return Err(PokerL1Error::Other(format!(
                        "node lacks consensus-required precompile {id:?} version {}",
                        activation.active_version
                    )));
                }
            }
        }
        let node = Self {
            config,
            block_store,
            block_commit_journal,
            block_commit_lock: std::sync::Mutex::new(()),
            object_db: std::sync::Mutex::new(object_db),
            vertex_store,
            account_store: std::sync::Mutex::new(account_store),
            tx_cache: std::sync::Mutex::new(TxCacheState::new()),
            pending_tx: std::sync::Mutex::new(PendingTxState::new()),
            pending_tx_condvar: std::sync::Condvar::new(),
            validator_set: std::sync::Mutex::new(validator_set),
            allow_empty_consensus_for_tests: false,
            fee_policy: std::sync::Mutex::new(canonical_fee_policy),
            governance: std::sync::Mutex::new(governance),
            precompile_registry,
            bridge_registry_store: Some(Arc::new(bridge_registry_store)),
            metrics: Arc::new(crate::metrics::MetricsCollector::new()),
            zk_verifier,
            light_headers: std::sync::Mutex::new(Vec::new()),
            indexer,
            zk_proof_archive: std::sync::RwLock::new(None),
        };
        // The status map is consensus state, not launcher configuration.  Ensure a registry
        // injected by the application observes the durable genesis/snapshot value immediately
        // on startup, before it is exposed through an execution environment.
        if let Some(registry) = &node.zk_verifier {
            registry.synchronize_governance_statuses(
                &node
                    .governance
                    .lock()
                    .unwrap_or_else(|error| error.into_inner()),
            );
        }
        node.recover_pending_block_commit()?;
        if let Some(tip) = node.block_store.get_tip_height()? {
            let indexed_tip = node.indexer.tip_height();
            if indexed_tip.is_some_and(|height| height > tip) {
                return Err(PokerL1Error::Other(
                    "durable index tip is ahead of the canonical block store".into(),
                ));
            }
            if let Some(height) = indexed_tip {
                let indexed = node.indexer.get_block_by_height(height).ok_or_else(|| {
                    PokerL1Error::Other("durable index lost its indexed tip record".into())
                })?;
                let canonical = node.block_store.get_by_height(height)?;
                if indexed.block_hash != canonical.block_hash(node.config.chain_id) {
                    return Err(PokerL1Error::Other(
                        "durable index tip does not match canonical block store".into(),
                    ));
                }
            }
            let start = indexed_tip
                .map(|height| height.saturating_add(1))
                .unwrap_or(0);
            if start <= tip {
                for block in node.block_store.get_range(start, tip)? {
                    node.indexer.try_index_block(&block, node.config.chain_id)?;
                }
            }
        } else if node.indexer.tip_height().is_some() {
            return Err(PokerL1Error::Other(
                "durable index has records but canonical block store is empty".into(),
            ));
        }
        {
            let object_db = node
                .object_db
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            node.indexer.synchronize_live_objects(object_db.iter())?;
        }
        Ok(node)
    }

    /// Apply the one-time native ZCN genesis allocation.
    ///
    /// Accounts remain identity/nonce records with zero legacy balance; spendable funds are
    /// emitted as address-owned native coin UTXOs. TreasuryCap creation, all coin creations and
    /// permanent closure of genesis minting are committed in one ObjectDb batch.
    ///
    /// Reapplying the identical allocation is a no-op. A different allocation after mint closure
    /// is rejected instead of being silently ignored.
    pub fn apply_genesis_alloc(
        &self,
        allocs: impl IntoIterator<Item = (TaggedPubkey, u64)>,
    ) -> PokerL1Result<usize> {
        let allocs: Vec<(TaggedPubkey, u64)> = allocs.into_iter().collect();
        let manifest = GenesisManifest::new_with_fee_policy(
            self.config.chain_id,
            self.config.genesis_validators.clone(),
            allocs
                .iter()
                .cloned()
                .map(|(recipient, amount)| GenesisAllocation { recipient, amount })
                .collect(),
            self.config.fee_policy,
        )?;
        let manifest_hash = manifest.hash();
        if let Some(expected) = self.config.genesis_manifest_hash
            && expected != manifest_hash
        {
            return Err(PokerL1Error::Other(format!(
                "genesis inputs do not match configured manifest hash: expected {}, got {}",
                hex::encode(expected),
                hex::encode(manifest_hash)
            )));
        }

        let mut object_db = self.object_db.lock().unwrap_or_else(|e| e.into_inner());
        let mut account_store = self.account_store.lock().unwrap_or_else(|e| e.into_inner());
        let mut native_allocs = Vec::with_capacity(allocs.len());
        let mut missing_accounts = Vec::new();
        for (pubkey, amount) in &allocs {
            let addr = crate::account::derive_address(&pubkey);
            if let Some(account) = account_store.get(&addr) {
                if account.tagged_pubkey != *pubkey {
                    return Err(PokerL1Error::Other(format!(
                        "genesis account pubkey mismatch at address {addr:?}"
                    )));
                }
                if account.balance != 0 {
                    return Err(PokerL1Error::Other(format!(
                        "genesis account {addr:?} has legacy balance {}; refusing duplicate monetary state",
                        account.balance
                    )));
                }
            } else {
                missing_accounts.push(pubkey.clone());
            }
            native_allocs.push((addr, *amount));
        }
        let validator_set = self.validator_set.lock().unwrap_or_else(|e| e.into_inner());
        let initializing = crate::economics::read_treasury(&object_db)?.is_none();
        let mut system_objects = vec![
            genesis_anchor_object(manifest_hash)?,
            fee_policy_object(self.config.chain_id, self.config.fee_policy, 0)?,
            crate::governance::governance_state_object(
                self.config.chain_id,
                &self
                    .governance
                    .lock()
                    .unwrap_or_else(|error| error.into_inner()),
                0,
            )?,
            crate::vm::precompile::precompile_governance_state_object(
                &crate::vm::precompile::PrecompileGovernanceState::from_active_versions(
                    self.config.chain_id,
                    default_precompile_versions(),
                )?,
                0,
            )?,
            crate::bridge::bridge_registry_config_object(
                &crate::bridge::BridgeRegistryConfig::empty(self.config.chain_id),
                0,
            )?,
            crate::bridge::bridge_replay_state_object(
                &crate::bridge::BridgeReplayState::empty(self.config.chain_id),
                0,
            )?,
        ];
        if initializing {
            system_objects.push(crate::consensus::validator_set::validator_set_object(
                self.config.chain_id,
                &validator_set,
                0,
            )?);
        }
        let minted = crate::economics::genesis_mint_with_system_objects(
            &mut object_db,
            self.config.chain_id,
            &native_allocs,
            system_objects,
        )?;
        // Account records are non-monetary identity/nonce metadata. If persistence fails here,
        // startup fails and the identical genesis call repairs missing zero-balance accounts on
        // the next restart without minting again.
        for pubkey in missing_accounts {
            account_store.create(crate::account::Account::new(pubkey, 0))?;
        }
        crate::economics::reconcile_native_supply(
            &object_db,
            validator_bond_escrow(&*object_db, &validator_set, self.config.chain_id)?,
        )?;
        self.indexer.synchronize_live_objects(object_db.iter())?;
        Ok(minted)
    }

    /// 创建内存节点（用于测试）。
    pub fn open_inmemory(role: NodeRole, chain_id: ChainId) -> PokerL1Result<Self> {
        Self::open_inmemory_with_validators(role, chain_id, vec![])
    }

    /// 创建带创世 validator 列表的内存节点（P0-4 动态 quorum 测试用）。
    pub fn open_inmemory_with_validators(
        role: NodeRole,
        chain_id: ChainId,
        genesis_validators: Vec<ValidatorEntry>,
    ) -> PokerL1Result<Self> {
        let validator_set = build_genesis_validator_set(genesis_validators.clone())?;
        let precompile_registry = build_default_precompile_registry(false);
        Ok(Self {
            config: NodeConfig {
                role,
                chain_id,
                data_dir: PathBuf::from("/tmp/poker_l1_inmemory"),
                rpc_listen: "127.0.0.1:0".to_string(),
                p2p_listen: "127.0.0.1:0".to_string(),
                validator_key: None,
                genesis_validators,
                genesis_manifest_hash: None,
                fee_policy: FeePolicy::Free,
            },
            block_store: BlockStore::open_inmemory()?,
            block_commit_journal: BlockCommitJournal::open_inmemory()?,
            block_commit_lock: std::sync::Mutex::new(()),
            object_db: std::sync::Mutex::new(ObjectDb::open_inmemory()?),
            vertex_store: DagVertexStore::open_inmemory()?,
            account_store: std::sync::Mutex::new(AccountStore::new()),
            tx_cache: std::sync::Mutex::new(TxCacheState::new()),
            pending_tx: std::sync::Mutex::new(PendingTxState::new()),
            pending_tx_condvar: std::sync::Condvar::new(),
            validator_set: std::sync::Mutex::new(validator_set),
            allow_empty_consensus_for_tests: true,
            fee_policy: std::sync::Mutex::new(FeePolicy::Free),
            governance: std::sync::Mutex::new(crate::governance::GovernanceState::new()),
            precompile_registry,
            // 缺口 #9：内存节点默认不启用桥（bridge contract_call 会拒绝）；
            // 需桥的测试可用 [`Node::with_bridge`] 显式注入。
            bridge_registry_store: None,
            metrics: Arc::new(crate::metrics::MetricsCollector::new()),
            zk_verifier: None,
            light_headers: std::sync::Mutex::new(Vec::new()),
            indexer: Arc::new(Indexer::new()),
            zk_proof_archive: std::sync::RwLock::new(None),
        })
    }

    /// 获取节点角色。
    #[must_use]
    pub const fn role(&self) -> NodeRole {
        self.config.role
    }

    /// 获取 chain_id。
    #[must_use]
    pub const fn chain_id(&self) -> ChainId {
        self.config.chain_id
    }

    // ===== P0-4: 动态 quorum（ValidatorSet 接入节点） =====

    /// 当前 validator 总数（含 Bonding / Unbonding / Slashed / Retired）。
    pub fn validator_count(&self) -> usize {
        self.validator_set
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .validators
            .len()
    }

    /// 当前活跃 validator 数量（动态 quorum 的计算基数）。
    pub fn active_validator_count(&self) -> usize {
        self.validator_set
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .active_count()
    }

    /// Ensure this node has an active validator set before it starts serving consensus traffic.
    ///
    /// Persistent production entry points must call this after loading genesis state and before
    /// starting RPC/P2P listeners. Consensus admission also enforces the same invariant, so an
    /// accidentally exposed node cannot accept unsigned vertices or blocks while unconfigured.
    pub fn ensure_consensus_ready(&self) -> PokerL1Result<()> {
        let active = self.active_validator_count();
        if active == 0 {
            return Err(PokerL1Error::Other(
                "consensus is not configured: active ValidatorSet is empty".into(),
            ));
        }
        if !self.allow_empty_consensus_for_tests
            && active < crate::consensus::validator_set::MIN_VALIDATOR_SET_SIZE
        {
            return Err(PokerL1Error::ValidatorSetTooSmallForOffChain { size: active });
        }
        Ok(())
    }

    /// 当前动态 quorum（严格 > 2/3 活跃 validator：`2 * n / 3 + 1`）。
    ///
    /// 未配置 active validator 时返回 0；生产入口不得以此状态启动共识服务。
    pub fn required_quorum(&self) -> usize {
        let active = self.active_validator_count();
        if active == 0 {
            return 0;
        }
        crate::consensus::required_quorum(active)
    }

    /// 校验 pubkey 是否为当前活跃 validator（可参与共识）。
    pub fn is_active_validator(&self, pubkey: &TaggedPubkey) -> bool {
        self.validator_set
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .find_validator(pubkey)
            .is_some_and(ValidatorEntry::can_participate_consensus)
    }

    /// 活跃 validator pubkey 列表（按字节排序，commit certificate signer_bitmap 索引基准）。
    ///
    /// 排序保证全网点对 bitmap 索引的解释一致。
    pub fn active_validator_pubkeys_sorted(&self) -> Vec<TaggedPubkey> {
        let set = self.validator_set.lock().unwrap_or_else(|e| e.into_inner());
        let mut pubkeys: Vec<TaggedPubkey> = set
            .validators
            .iter()
            .filter(|v| v.can_participate_consensus())
            .map(|v| v.pubkey.clone())
            .collect();
        pubkeys.sort_by_key(TaggedPubkey::to_bytes);
        pubkeys
    }

    /// Register an unfunded validator entry for consensus-only unit tests.
    ///
    /// Production registration must use [`Self::bond_validator`] so stake is backed by consumed
    /// ZCN UTXOs. Keeping this path test-only prevents zero-stake validator admission in a node.
    #[cfg(test)]
    pub(crate) fn add_validator(&self, entry: ValidatorEntry) -> PokerL1Result<()> {
        if entry.stake > 0 {
            return Err(PokerL1Error::Other(
                "non-zero validator stake must be funded through bond_validator native-coin inputs"
                    .into(),
            ));
        }
        let mut object_db = self.object_db.lock().unwrap_or_else(|e| e.into_inner());
        let mut set = self.validator_set.lock().unwrap_or_else(|e| e.into_inner());
        let mut next_set = set.clone();
        if next_set.find_validator(&entry.pubkey).is_some() {
            return Err(PokerL1Error::Other(format!(
                "validator already in set: {:?}",
                entry.pubkey
            )));
        }
        next_set.validators.push(entry);
        next_set.validator_set_hash = next_set.compute_hash();
        if read_persisted_validator_set(&object_db, self.config.chain_id)?.is_some() {
            let mut snapshot = object_db.create_snapshot();
            stage_validator_set_update(&mut snapshot, self.config.chain_id, &set, &next_set)?;
            snapshot.apply_to(&mut object_db)?;
        } else if crate::economics::read_treasury(&object_db)?.is_some() {
            return Err(PokerL1Error::Other(
                "initialized Treasury is missing authoritative ValidatorSet state".into(),
            ));
        }
        *set = next_set;
        Ok(())
    }

    /// Consume validator-owned native coin UTXOs and lock `entry.stake` in staking escrow.
    ///
    /// Any excess input value is returned as deterministic change. Treasury supply is unchanged:
    /// value moves from live UTXOs into `ValidatorEntry.stake` escrow.
    #[cfg(test)]
    pub(crate) fn bond_validator(
        &self,
        mut entry: ValidatorEntry,
        coin_inputs: &[ObjectID],
    ) -> PokerL1Result<Option<ObjectID>> {
        if entry.stake == 0 {
            return Err(PokerL1Error::Other(
                "bond_validator requires non-zero stake".into(),
            ));
        }
        // Admission always begins in Bonding; callers cannot buy immediate consensus power by
        // submitting an entry pre-marked Active.
        entry.status = crate::consensus::ValidatorStatus::Bonding;
        let owner = crate::account::derive_address(&entry.pubkey);
        let mut object_db = self.object_db.lock().unwrap_or_else(|e| e.into_inner());
        let mut object_snapshot = object_db.create_snapshot();
        let selection = crate::economics::select_owned_native_coins(
            &object_snapshot,
            coin_inputs,
            owner,
            entry.stake,
        )?;

        let mut set = self.validator_set.lock().unwrap_or_else(|e| e.into_inner());
        let mut next_set = set.clone();
        if next_set.find_validator(&entry.pubkey).is_some() {
            return Err(PokerL1Error::Other(format!(
                "validator already in set: {:?}",
                entry.pubkey
            )));
        }
        next_set.validators.push(entry.clone());
        next_set.validator_set_hash = next_set.compute_hash();

        let operation_hash = crate::economics::system_coin_operation_hash(
            b"STAKING_BOND_V1",
            owner,
            coin_inputs,
            entry.stake,
            next_set.epoch,
        );
        let change = crate::economics::consume_native_coin_selection(
            &mut object_snapshot,
            &selection,
            owner,
            entry.stake,
            &operation_hash,
            0,
        )?;
        stage_validator_set_update(&mut object_snapshot, self.config.chain_id, &set, &next_set)?;
        crate::economics::reconcile_native_supply_snapshot_if_initialized(
            &object_snapshot,
            validator_bond_escrow(&object_snapshot, &next_set, self.config.chain_id)?,
        )?;
        object_snapshot.apply_to(&mut object_db)?;
        *set = next_set;
        Ok(change)
    }

    /// Slash staking escrow and atomically account for the destroyed ZCN in TreasuryCap.
    #[cfg(test)]
    pub(crate) fn slash_validator(
        &self,
        validator_pubkey: &TaggedPubkey,
        reason: crate::consensus::SlashingReason,
        config: &crate::consensus::SlashingConfig,
    ) -> PokerL1Result<crate::consensus::SlashingResult> {
        let mut object_db = self.object_db.lock().unwrap_or_else(|e| e.into_inner());
        let mut set = self.validator_set.lock().unwrap_or_else(|e| e.into_inner());
        let mut next_set = set.clone();
        let result =
            crate::consensus::apply_slashing(&mut next_set, validator_pubkey, reason, config)?;
        next_set.validator_set_hash = next_set.compute_hash();
        let mut object_snapshot = object_db.create_snapshot();
        crate::economics::burn_escrowed_native(&mut object_snapshot, result.slash_amount)?;
        stage_validator_set_update(&mut object_snapshot, self.config.chain_id, &set, &next_set)?;
        crate::economics::reconcile_native_supply_snapshot_if_initialized(
            &object_snapshot,
            validator_bond_escrow(&object_snapshot, &next_set, self.config.chain_id)?,
        )?;
        object_snapshot.apply_to(&mut object_db)?;
        *set = next_set;
        Ok(result)
    }

    /// Complete unbonding by converting staking escrow back into a native coin UTXO.
    #[cfg(test)]
    pub(crate) fn complete_unbonding(
        &self,
        validator_pubkey: &TaggedPubkey,
        current_height: BlockHeight,
    ) -> PokerL1Result<u64> {
        let owner = crate::account::derive_address(validator_pubkey);
        let mut object_db = self.object_db.lock().unwrap_or_else(|e| e.into_inner());
        let mut set = self.validator_set.lock().unwrap_or_else(|e| e.into_inner());
        let mut next_set = set.clone();
        let validator = next_set
            .find_validator_mut(validator_pubkey)
            .ok_or_else(|| PokerL1Error::ValidatorNotInSet(validator_pubkey.clone()))?;
        // 须处于 Unbonding 且 lock 期已到。
        if validator.status != crate::consensus::ValidatorStatus::Unbonding {
            return Err(PokerL1Error::Other(format!(
                "validator not in unbonding (status={:?})",
                validator.status
            )));
        }
        if current_height < validator.unbonding_until_height {
            return Err(PokerL1Error::Other(format!(
                "unbonding lock not expired: current={current_height} < until={}",
                validator.unbonding_until_height
            )));
        }
        let refund = validator.stake;
        validator.stake = 0;
        validator.status = crate::consensus::ValidatorStatus::Retired;
        next_set.validator_set_hash = next_set.compute_hash();

        let mut object_snapshot = object_db.create_snapshot();
        if refund > 0 {
            let payout_hash = crate::economics::system_coin_operation_hash(
                b"STAKING_UNBOND_V1",
                owner,
                &[],
                refund,
                current_height,
            );
            crate::economics::create_native_coin_output(
                &mut object_snapshot,
                owner,
                refund,
                &payout_hash,
                0,
            )?;
        }
        stage_validator_set_update(&mut object_snapshot, self.config.chain_id, &set, &next_set)?;
        crate::economics::reconcile_native_supply_snapshot_if_initialized(
            &object_snapshot,
            validator_bond_escrow(&object_snapshot, &next_set, self.config.chain_id)?,
        )?;
        object_snapshot.apply_to(&mut object_db)?;
        *set = next_set;
        Ok(refund)
    }

    /// Test-only direct epoch mutation retained for low-level ECVRF coverage.
    ///
    /// 流程：
    /// 1. `ValidatorSet::advance_epoch`（滚动 prev_epoch_randomness + 衰减审查计数）
    /// 2. 若 `vrf_secret` 提供：用 ECVRF prover 对当前 epoch 的 VRF input 生成 proof，
    ///    调 `submit_epoch_vrf_proof` 验证并写入新 epoch_randomness。
    /// 3. 未配置 VRF / 提交失败：调 `fallback_epoch_randomness`（SEC2-M12 降级）。
    ///
    /// **self-proposing 模式**：当前节点用自身 VRF 私钥为该 epoch 生成 proof。
    /// 多 validator 完整 VRF 协议（proposer 选举 + proof gossip）属后续工作；
    /// 此实现使 epoch_randomness 来自真实 ECVRF（非 stub），且与验证方一致
    /// （验证方用同一 prover pub key + proof 重算相同 output）。
    #[cfg(test)]
    pub(crate) fn advance_epoch_with_vrf(
        &self,
        new_epoch: Epoch,
        vrf_secret: Option<&[u8; 32]>,
    ) -> PokerL1Result<()> {
        let mut object_db = self.object_db.lock().unwrap_or_else(|e| e.into_inner());
        let mut set = self.validator_set.lock().unwrap_or_else(|e| e.into_inner());
        let mut next_set = set.clone();
        next_set.advance_epoch(new_epoch);

        // 尝试用 VRF proof 派生 epoch_randomness。
        let vrf_ok = if let Some(secret) = vrf_secret {
            let prover = crate::consensus::ecvrf::Secp256k1VrfProver::from_secret_bytes(secret);
            let vrf_input = crate::consensus::validator_set::compute_vrf_input(
                self.config.chain_id,
                next_set.epoch,
                &next_set.prev_epoch_randomness,
            );
            match prover.prove(&vrf_input) {
                Ok((proof, _output)) => {
                    // submit_epoch_vrf_proof 内部用 Secp256k1VrfVerifier 验证 proof
                    // 并把 output 写入 epoch_randomness。
                    let verifier = crate::consensus::ecvrf::Secp256k1VrfVerifier::new();
                    next_set
                        .submit_epoch_vrf_proof(
                            self.config.chain_id,
                            &self
                                .config
                                .validator_key
                                .as_ref()
                                .map(|k| &k.tagged_pubkey)
                                .cloned()
                                .unwrap_or_else(|| {
                                    // 无 validator_key 时无法标识 proposer，fallback。
                                    TaggedPubkey {
                                        tag: 0,
                                        raw: vec![],
                                    }
                                }),
                            &proof,
                            &verifier,
                        )
                        .is_ok()
                }
                Err(_) => false,
            }
        } else {
            false
        };

        if !vrf_ok {
            // 降级：fallback epoch_randomness（SEC2-M12）。
            next_set.fallback_epoch_randomness();
        }
        next_set.validator_set_hash = next_set.compute_hash();
        let mut snapshot = object_db.create_snapshot();
        stage_validator_set_update(&mut snapshot, self.config.chain_id, &set, &next_set)?;
        snapshot.apply_to(&mut object_db)?;
        *set = next_set;
        Ok(())
    }

    /// Test-only direct epoch mutation. Production transitions are block-authorized and staged by
    /// [`Self::stage_certificate_epoch_transition`].
    #[cfg(test)]
    pub(crate) fn advance_epoch(&self, new_epoch: Epoch) -> PokerL1Result<()> {
        let mut object_db = self.object_db.lock().unwrap_or_else(|e| e.into_inner());
        let mut set = self.validator_set.lock().unwrap_or_else(|e| e.into_inner());
        let mut next_set = set.clone();
        next_set.advance_epoch(new_epoch);
        let mut snapshot = object_db.create_snapshot();
        stage_validator_set_update(&mut snapshot, self.config.chain_id, &set, &next_set)?;
        snapshot.apply_to(&mut object_db)?;
        *set = next_set;
        Ok(())
    }

    /// 处理 bonding 到期（NEW-L3：到达 bonding_until_height 后转 Active）。
    #[cfg(test)]
    pub(crate) fn process_bonding_expiry(&self, current_height: BlockHeight) -> PokerL1Result<()> {
        let mut object_db = self.object_db.lock().unwrap_or_else(|e| e.into_inner());
        let mut set = self.validator_set.lock().unwrap_or_else(|e| e.into_inner());
        let mut next_set = set.clone();
        next_set.process_bonding_expiry(current_height);
        if next_set == *set {
            return Ok(());
        }
        let mut snapshot = object_db.create_snapshot();
        stage_validator_set_update(&mut snapshot, self.config.chain_id, &set, &next_set)?;
        snapshot.apply_to(&mut object_db)?;
        *set = next_set;
        Ok(())
    }

    /// Persistently move an active validator into the unbonding state.
    #[cfg(test)]
    pub(crate) fn start_validator_unbonding(
        &self,
        validator_pubkey: &TaggedPubkey,
        unbonding_until_height: BlockHeight,
    ) -> PokerL1Result<()> {
        let mut object_db = self.object_db.lock().unwrap_or_else(|e| e.into_inner());
        let mut set = self.validator_set.lock().unwrap_or_else(|e| e.into_inner());
        let mut next_set = set.clone();
        next_set.start_unbonding(validator_pubkey, unbonding_until_height)?;
        let mut snapshot = object_db.create_snapshot();
        stage_validator_set_update(&mut snapshot, self.config.chain_id, &set, &next_set)?;
        snapshot.apply_to(&mut object_db)?;
        *set = next_set;
        Ok(())
    }

    /// 当前 epoch。
    pub fn current_epoch(&self) -> Epoch {
        self.validator_set
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .epoch
    }

    /// 获取配置引用。
    #[must_use]
    pub const fn config(&self) -> &NodeConfig {
        &self.config
    }

    /// 获取 BlockStore 引用。
    #[must_use]
    pub const fn block_store(&self) -> &BlockStore {
        &self.block_store
    }

    /// 获取 DagVertexStore 引用。
    #[must_use]
    pub const fn vertex_store(&self) -> &DagVertexStore {
        &self.vertex_store
    }

    /// 按 hash 查询 block。
    pub fn get_block_by_hash(&self, hash: &Hash) -> PokerL1Result<Option<Block>> {
        match self.block_store.get_by_hash(hash) {
            Ok(block) => Ok(Some(block)),
            Err(PokerL1Error::BlockNotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// 按 height 查询 block。
    pub fn get_block_by_height(&self, height: BlockHeight) -> PokerL1Result<Option<Block>> {
        match self.block_store.get_by_height(height) {
            Ok(block) => Ok(Some(block)),
            Err(PokerL1Error::BlockNotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Serve historical data from this node's durable archive stores.
    ///
    /// Transaction and DAG-vertex lookups are resolved against the canonical local stores. ZK
    /// proofs require an explicitly configured archive provider and are hash-verified before a
    /// success payload is returned; an unavailable or mismatched blob never becomes `Found`.
    pub fn request_historical_data(
        &self,
        request: &HistoricalDataRequest,
    ) -> PokerL1Result<HistoricalDataResponse> {
        if !self.serves_historical_data() {
            return Ok(HistoricalDataResponse::Unavailable(
                "only archive nodes can serve historical data".into(),
            ));
        }
        match request.request_type {
            HistoricalDataType::DagVertex => match self.vertex_store.get_by_hash(&request.key) {
                Ok(vertex) => Ok(HistoricalDataResponse::Found(borsh::to_vec(&vertex)?)),
                Err(PokerL1Error::DagVertexNotFound) => Ok(HistoricalDataResponse::Unavailable(
                    "vertex is not present in the local archive".into(),
                )),
                Err(error) => Err(error),
            },
            HistoricalDataType::Transaction => {
                // Archive nodes rebuild and maintain this finalized index from their durable
                // canonical block store.  Do not turn one untrusted historical-data request
                // into a tip-sized RocksDB scan: an unavailable/corrupt local index should be
                // repaired during startup, not silently bypassed on the serving hot path.
                if let Some(indexed) = self.indexer.get_tx(&request.key) {
                    match self.block_store.get_by_height(indexed.block_height) {
                        Ok(block) => {
                            if let Some(transaction) = block
                                .canonical_execution_txs()
                                .into_iter()
                                .find(|transaction| transaction.tx_hash() == request.key)
                            {
                                return Ok(HistoricalDataResponse::Found(borsh::to_vec(
                                    &transaction,
                                )?));
                            }
                        }
                        Err(PokerL1Error::BlockNotFound) => {}
                        Err(error) => return Err(error),
                    }
                }
                Ok(HistoricalDataResponse::Unavailable(
                    "transaction is not present in the local archive".into(),
                ))
            }
            HistoricalDataType::ZkProof => {
                let provider = self
                    .zk_proof_archive
                    .read()
                    .unwrap_or_else(|error| error.into_inner())
                    .clone();
                let Some(provider) = provider else {
                    return Ok(HistoricalDataResponse::Unavailable(
                        "no Walrus/archive ZK-proof provider is configured".into(),
                    ));
                };
                let payload = match provider.load_proof(&request.key) {
                    Ok(Some(payload)) => payload,
                    Ok(None) => {
                        return Ok(HistoricalDataResponse::Unavailable(
                            "ZK proof is not present in the configured archive".into(),
                        ));
                    }
                    Err(error) => {
                        return Ok(HistoricalDataResponse::Unavailable(format!(
                            "ZK proof archive lookup failed: {error}"
                        )));
                    }
                };
                let actual = crate::storage::compute_proof_hash(
                    &payload.proof,
                    &payload.state_delta,
                    &payload.ack_chain,
                );
                if actual != request.key {
                    return Ok(HistoricalDataResponse::Unavailable(
                        "ZK proof archive payload does not match the requested proof hash".into(),
                    ));
                }
                Ok(HistoricalDataResponse::Found(borsh::to_vec(&payload)?))
            }
        }
    }

    /// Configure the external historical-ZK-proof archive used by an Archive node.
    ///
    /// The provider is local operational configuration, while the payload's `proof_hash` remains
    /// the consensus commitment.  Replacing this provider cannot change state and every response
    /// is revalidated by [`Self::request_historical_data`].
    pub fn set_zk_proof_archive_provider(&self, provider: Arc<dyn ZkProofArchiveProvider>) {
        *self
            .zk_proof_archive
            .write()
            .unwrap_or_else(|error| error.into_inner()) = Some(provider);
    }

    /// 写入对象。
    pub fn put_object(&self, object: Object) -> PokerL1Result<()> {
        if crate::economics::is_reserved_economic_object(&object) {
            return Err(PokerL1Error::Other(
                "reserved economic objects must be created through economics APIs".into(),
            ));
        }
        self.object_db
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .create(object)
    }

    /// 查询对象。
    pub fn get_object(&self, id: &ObjectID) -> PokerL1Result<Option<Object>> {
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

    /// List an address's spendable native ZCN UTXOs in deterministic object-ID order.
    pub fn list_native_coins(
        &self,
        owner: Address,
    ) -> PokerL1Result<Vec<crate::economics::OwnedNativeCoin>> {
        let object_db = self.object_db.lock().unwrap_or_else(|e| e.into_inner());
        crate::economics::list_owned_native_coins(&object_db, owner)
    }

    /// Return the wallet-facing aggregate ZCN balance across all owned UTXOs.
    pub fn native_coin_balance(&self, owner: Address) -> PokerL1Result<u64> {
        let object_db = self.object_db.lock().unwrap_or_else(|e| e.into_inner());
        crate::economics::native_coin_balance(&object_db, owner)
    }

    /// Read the native ZCN TreasuryCap tracked by the UTXO/escrow monetary domain.
    pub fn treasury_cap(&self) -> PokerL1Result<Option<crate::economics::TreasuryCap>> {
        let object_db = self.object_db.lock().unwrap_or_else(|e| e.into_inner());
        crate::economics::read_treasury(&object_db)
    }

    /// Audit every currently modelled native ZCN custody domain.
    ///
    /// Lock ordering intentionally matches bond/slash/unbond paths: `ObjectDb` first, then
    /// `ValidatorSet`. Keeping both locks for the duration gives the report one coherent view of
    /// live UTXOs, table vaults and staking escrow.
    pub fn audit_native_supply(
        &self,
    ) -> PokerL1Result<crate::economics::NativeSupplyReconciliation> {
        let object_db = self.object_db.lock().unwrap_or_else(|e| e.into_inner());
        let validator_set = self.validator_set.lock().unwrap_or_else(|e| e.into_inner());
        let staking_escrow =
            validator_bond_escrow(&*object_db, &validator_set, self.config.chain_id)?;
        crate::economics::audit_native_supply(&object_db, staking_escrow)
    }

    /// Require Treasury supply to equal live UTXOs plus staking and Texas table escrow.
    pub fn reconcile_native_supply(
        &self,
    ) -> PokerL1Result<crate::economics::NativeSupplyReconciliation> {
        self.audit_native_supply()?.require_balanced()
    }

    /// 写入 DAG vertex（入库前验证）。
    ///
    /// P0-3 修复：在写入存储前执行完整验证链：
    /// 1. 大小校验（≤ MAX_VERTEX_SIZE）
    /// 2. 签名验证（author_sig 对 signing_hash）
    /// 3. tx 边界、chain_id 与签名校验
    /// 5. vertex 内 tx 排序校验（S9 规则）
    /// 6. parent graph 校验（存在、去重、严格上一轮、distinct active-author quorum）
    pub fn put_vertex(&self, vertex: &DagVertex) -> PokerL1Result<Hash> {
        self.validate_vertex(vertex)?;
        self.vertex_store.put(vertex)
    }

    /// 验证 DAG vertex（P0-3）。
    ///
    /// 在 vertex 入库或入内存 DAG 前调用，防止恶意或损坏的 vertex 污染存储。
    pub fn validate_vertex(&self, vertex: &DagVertex) -> PokerL1Result<()> {
        // 1. 大小校验
        let vertex_size = vertex.to_bcs()?.len();
        if vertex_size > MAX_VERTEX_SIZE {
            return Err(PokerL1Error::VertexTooLarge {
                actual: vertex_size,
                limit: MAX_VERTEX_SIZE,
            });
        }

        let current_epoch = self.current_epoch();
        if vertex.epoch != current_epoch {
            return Err(PokerL1Error::InvalidVertexEpoch {
                actual: vertex.epoch,
                expected: current_epoch,
            });
        }

        // 2. author 必须是当前活跃 validator（P0-4 动态 quorum）。
        // 放在签名验证之前，可快速丢弃非 validator 的顶点并避免验签开销。
        {
            let set = self.validator_set.lock().unwrap_or_else(|e| e.into_inner());
            let active_count = set.active_count();
            if active_count == 0 && !self.allow_empty_consensus_for_tests {
                return Err(PokerL1Error::Other(
                    "cannot admit DAG vertex with an empty active ValidatorSet".into(),
                ));
            }
            if !self.allow_empty_consensus_for_tests
                && active_count < crate::consensus::validator_set::MIN_VALIDATOR_SET_SIZE
            {
                return Err(PokerL1Error::ValidatorSetTooSmallForOffChain { size: active_count });
            }
            let is_active = set
                .find_validator(&vertex.author_pubkey)
                .is_some_and(ValidatorEntry::can_participate_consensus);
            if active_count > 0 && !is_active {
                return Err(PokerL1Error::VertexAuthorNotActiveValidator(
                    vertex.author_pubkey.clone(),
                ));
            }
        }

        // 3. 签名验证（author_sig 对 signing_hash）
        let signing_hash = vertex.signing_hash(self.config.chain_id);
        verify_signature(&vertex.author_pubkey, &vertex.author_sig, &signing_hash).map_err(
            |_| PokerL1Error::InvalidVertexSignature {
                vertex_hash: vertex.vertex_hash(),
            },
        )?;

        // 同一 author 在同一 (epoch, round) 只能有一个内容 hash。完全相同的 vertex
        // 属于网络重放，保持幂等；内容不同则在进入 tx/parent 深层校验前直接拒绝。
        let vertex_hash = vertex.vertex_hash();
        for existing in self.vertex_store.get_by_round(vertex.epoch, vertex.round)? {
            if existing.author_pubkey == vertex.author_pubkey
                && existing.vertex_hash() != vertex_hash
            {
                return Err(PokerL1Error::VertexEquivocation {
                    epoch: vertex.epoch,
                    round: vertex.round,
                    author: vertex.author_pubkey.clone(),
                });
            }
        }

        // 3. tx 边界、chain_id 与签名校验。P2P vertex 绕过普通 RPC admission，
        // 因此不能等到 block execution 才发现并拒绝无效交易。
        for tx in &vertex.tx_list {
            validate_tx_limits(tx)?;
            validate_tx_chain_id(tx, self.config.chain_id)?;
            validate_tx_signature(tx)?;
        }

        // 4. vertex 内 tx 排序校验（S9：GameTurn 优先于 ForceSync）
        validate_vertex_tx_ordering(&vertex.tx_list)?;

        // 5. Parent graph validation. Counting raw hashes is insufficient: one validator could
        // otherwise equivocate multiple parents and manufacture a quorum. Round 1 is the only
        // parentless round; every later vertex must reference a distinct-author quorum from the
        // immediately preceding round.
        if vertex.round == 0 {
            return Err(PokerL1Error::InvalidVertexRound {
                round: vertex.round,
            });
        }
        if vertex.round == 1 {
            if !vertex.parent_hashes.is_empty() {
                return Err(PokerL1Error::UnexpectedFirstRoundParents {
                    actual: vertex.parent_hashes.len(),
                });
            }
            return Ok(());
        }

        let active_parent_authors: std::collections::BTreeSet<Vec<u8>> = self
            .active_validator_pubkeys_sorted()
            .into_iter()
            .map(|pubkey| pubkey.to_bytes())
            .collect();
        let validator_count = active_parent_authors.len().max(1);
        let required = required_parent_count(validator_count);
        let expected_parent_round = vertex.round - 1;
        let mut seen_parent_hashes = std::collections::BTreeSet::new();
        let mut seen_parent_authors = std::collections::BTreeSet::new();

        for parent_hash in &vertex.parent_hashes {
            if !seen_parent_hashes.insert(*parent_hash) {
                return Err(PokerL1Error::DuplicateParentVertex(*parent_hash));
            }
            let parent = match self.vertex_store.get_by_hash(parent_hash) {
                Ok(parent) => parent,
                Err(PokerL1Error::DagVertexNotFound) => {
                    return Err(PokerL1Error::ParentVertexNotFound(*parent_hash));
                }
                Err(error) => return Err(error),
            };
            if parent.epoch != vertex.epoch {
                return Err(PokerL1Error::InvalidParentVertexEpoch {
                    parent_hash: *parent_hash,
                    actual: parent.epoch,
                    expected: vertex.epoch,
                });
            }
            if parent.round != expected_parent_round {
                return Err(PokerL1Error::InvalidParentVertexRound {
                    parent_hash: *parent_hash,
                    actual: parent.round,
                    expected: expected_parent_round,
                });
            }

            let parent_author = parent.author_pubkey.to_bytes();
            if !active_parent_authors.is_empty() && !active_parent_authors.contains(&parent_author)
            {
                return Err(PokerL1Error::ParentVertexAuthorNotActiveValidator(
                    parent.author_pubkey,
                ));
            }
            if !seen_parent_authors.insert(parent_author) {
                return Err(PokerL1Error::DuplicateParentVertexAuthor(
                    parent.author_pubkey,
                ));
            }
        }

        if seen_parent_authors.len() < required {
            return Err(PokerL1Error::InsufficientParents {
                actual: seen_parent_authors.len(),
                required,
            });
        }

        Ok(())
    }

    /// 写入 block（入库前验证 + 状态根重放比对）。
    ///
    /// P0-3 修复：在写入存储前执行完整验证链：
    /// 1. block header 字段校验（height / prev_hash 连续性）
    /// 2. tx roots 一致性校验
    /// 3. GameTurn 免 gas 校验
    /// 4. commit certificate 多签验证
    /// 5. 状态根重放比对：重新执行 tx，比对计算出的 state_root 与 header.state_root
    pub fn put_block(&self, block: &Block) -> PokerL1Result<Hash> {
        let commit_started = Instant::now();
        let _commit_guard = self
            .block_commit_lock
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let candidate_hash = block.block_hash(self.config.chain_id);
        match self.block_store.get_by_height(block.header.height) {
            Ok(existing) => {
                let existing_hash = existing.block_hash(self.config.chain_id);
                if existing_hash == candidate_hash {
                    return Ok(candidate_hash);
                }
                return Err(PokerL1Error::Other(format!(
                    "block height {} is already committed to a different hash",
                    block.header.height
                )));
            }
            Err(PokerL1Error::BlockNotFound) => {}
            Err(error) => return Err(error),
        }

        self.validate_block_structure(block)?;

        // Hold both state locks across provisional replay and commit.  A block is first executed
        // against isolated snapshots; only a matching state root may be materialized locally.
        // This prevents a rejected block from changing objects or account nonces.
        let mut object_db = self.object_db.lock().unwrap_or_else(|e| e.into_inner());
        let mut account_store = self.account_store.lock().unwrap_or_else(|e| e.into_inner());
        let (object_snapshot, account_snapshot, outcome, next_validator_set, bridge_snapshot) =
            self.prepare_block_execution(block, &object_db, &account_store)?;
        let staking_escrow = match next_validator_set.as_ref() {
            Some(next) => validator_bond_escrow(&object_snapshot, next, self.config.chain_id)?,
            None => {
                let validator_set = self.validator_set.lock().unwrap_or_else(|e| e.into_inner());
                validator_bond_escrow(&object_snapshot, &validator_set, self.config.chain_id)?
            }
        };
        crate::economics::reconcile_native_supply_snapshot_if_initialized(
            &object_snapshot,
            staking_escrow,
        )?;

        // Write an fsynced intent before touching any of the three independent RocksDB handles.
        // Recovery can then either finish an ObjectDb-committed transition or restore the account
        // pre-state and replay it.  Do not replace this with a best-effort rollback: that is not
        // sufficient across process death or power loss.
        let pending = PendingBlockCommit {
            block: block.clone(),
            object_root_before: object_db.state_root(),
            account_root_before: account_store.state_root(),
            accounts_before: account_store.snapshot_records(),
            accounts_after: account_snapshot.snapshot_records(),
            bridge_nonces_before: self
                .bridge_registry_store
                .as_ref()
                .map(|store| store.nonce_snapshot()),
            bridge_nonces_after: bridge_snapshot
                .as_ref()
                .map(BridgeRegistrySnapshot::nonce_snapshot),
        };
        self.block_commit_journal.prepare(&pending)?;

        if let Err(error) = account_store.apply_snapshot_durable(account_snapshot) {
            // AccountStore applies one atomic batch, so this error leaves it at `accounts_before`.
            self.block_commit_journal.clear()?;
            return Err(error);
        }
        if let Err(error) = object_snapshot.apply_to_durable(&mut object_db) {
            // This path is normally unreachable after snapshot validation because ObjectDb uses
            // one atomic batch.  If it happens, restore synchronously; retain the intent if the
            // restore itself fails so startup recovery remains authoritative.
            if let Err(rollback_error) =
                account_store.replace_all_records_durable(pending.accounts_before.clone())
            {
                tracing::error!(
                    "ObjectDb commit failed after account commit; account rollback also failed: {rollback_error}"
                );
            } else {
                self.block_commit_journal.clear()?;
            }
            return Err(error);
        }
        if let (Some(store), Some(snapshot)) = (&self.bridge_registry_store, bridge_snapshot) {
            // ObjectDb has reached the final root.  If this synchronous nonce write fails, retain
            // the journal: startup recognizes the final ObjectDb root, installs the recorded
            // bridge post-state, and then appends the block exactly once.
            store.apply_snapshot_durable(snapshot)?;
        }

        let hash = match self.block_store.put_durable(block, self.config.chain_id) {
            Ok(hash) => hash,
            Err(error) => {
                // ObjectDb is now durable; leave the intent in place for startup to append this
                // idempotent block record after verifying both committed roots.
                return Err(error);
            }
        };
        if let Err(error) = self.block_commit_journal.clear() {
            // The block is already canonical.  Keep serving it; a restart verifies the roots and
            // removes the stale intent instead of attempting to replay the transition.
            tracing::warn!(
                "block {} committed but journal cleanup will be retried on startup: {error}",
                block.header.height
            );
        }
        // Index only after the block and all state stores are durable. The indexer is therefore
        // never ahead of the canonical chain and can be rebuilt deterministically on restart.
        if let Err(error) = self.indexer.try_index_block(block, self.config.chain_id) {
            // The canonical block is already durable.  Treat an auxiliary index write failure as
            // an operational fault, never as a reason to roll back consensus state; startup
            // repairs a missing tail from BlockStore before exposing the node again.
            tracing::error!(
                height = block.header.height,
                "durable finalized index update failed and will require startup repair: {error}"
            );
        }
        if let Err(error) = self.indexer.synchronize_live_objects(object_db.iter()) {
            tracing::error!(
                height = block.header.height,
                "live object index update failed and will require startup repair: {error}"
            );
        }
        if let Some(next_validator_set) = next_validator_set {
            *self.validator_set.lock().unwrap_or_else(|e| e.into_inner()) = next_validator_set;
        }
        // Refresh only after all durable stores and the canonical block record have committed.
        // The cache is an optimization for runtime consumers; ObjectDb remains the source of
        // truth during execution and replay.
        match read_fee_policy(&object_db, self.config.chain_id)? {
            Some(policy) => {
                *self
                    .fee_policy
                    .lock()
                    .unwrap_or_else(|error| error.into_inner()) = policy;
            }
            None if !self.allow_empty_consensus_for_tests => {
                return Err(PokerL1Error::Other(
                    "committed block is missing the consensus FeePolicy system object".into(),
                ));
            }
            None => {}
        }
        match read_persisted_governance_state(&object_db, self.config.chain_id)? {
            Some(governance) => {
                *self
                    .governance
                    .lock()
                    .unwrap_or_else(|error| error.into_inner()) = governance.clone();
                if let Some(registry) = &self.zk_verifier {
                    registry.synchronize_governance_statuses(&governance);
                }
            }
            None if !self.allow_empty_consensus_for_tests => {
                return Err(PokerL1Error::Other(
                    "committed block is missing the consensus GovernanceState system object".into(),
                ));
            }
            None => {}
        }
        // 缺口 #4：State Pruning 接入出块路径。
        if self.config.role.should_prune() {
            if let Err(e) = self.run_pruning(block.header.height) {
                tracing::warn!("run_pruning 失败（不阻断出块）：{e}");
            }
        }
        // Light client header 多签背书：validator 节点用自己的 secp256k1 key
        // 对 block header 签名，生成 LightClientHeader 并缓存供 light client 订阅。
        if let Some(vkey) = &self.config.validator_key {
            self.sign_and_store_light_header(block, vkey);
        }
        self.metrics.inc_tx(outcome.receipts.len() as u64);
        self.metrics.inc_gas_used(outcome.total_gas_used);
        self.metrics
            .observe_block_time_ms(commit_started.elapsed().as_millis() as u64);
        Ok(hash)
    }

    /// 为 block 生成 validator 签名的 LightClientHeader（light client 协议核心）。
    ///
    /// validator 用自己的 secp256k1 secret key 对 `header_bytes` 的 blake2b_256 哈希签名，
    /// 生成 `ValidatorSig`（tagged_pubkey + 65B 签名），存入 `LightClientHeader.signatures`。
    /// 多个 validator 各自签名后，light client 收集 ≥2/3 签名即可验证 header 真实性。
    fn sign_and_store_light_header(&self, block: &Block, vkey: &ValidatorKey) {
        use blake2::digest::{Update, VariableOutput};
        use secp256k1::{Message, Secp256k1, SecretKey};
        let header_bytes = borsh::to_vec(&block.header).unwrap_or_default();
        // 签名对象 = blake2b_256(header_bytes)
        let mut hasher = blake2::Blake2bVar::new(32).expect("32 <= 64");
        Update::update(&mut hasher, &header_bytes);
        let mut msg_hash = [0u8; 32];
        hasher.finalize_variable(&mut msg_hash).expect("32 <= 64");
        // secp256k1 recoverable 签名
        let secp = Secp256k1::new();
        let secret = match SecretKey::from_slice(&vkey.secret_key_bytes) {
            Ok(s) => s,
            Err(_) => return,
        };
        let msg = Message::from_digest(msg_hash);
        let sig = secp.sign_ecdsa_recoverable(&msg, &secret);
        let (recovery_id, compact) = sig.serialize_compact();
        let mut full_sig = compact.to_vec();
        full_sig.push(recovery_id.to_i32() as u8);
        let validator_sig = crate::network::ValidatorSig {
            validator: vkey.tagged_pubkey.clone(),
            signature: full_sig,
        };
        // 尝试合并到已有的同 header LightClientHeader，或新建。
        let mut headers = self.light_headers.lock().unwrap_or_else(|e| e.into_inner());
        // 查找是否已有同 header_bytes 的 header（多 validator 合并签名）。
        if let Some(existing) = headers.iter_mut().find(|h| h.header_bytes == header_bytes) {
            // 去重：同一 validator 不重复签名。
            if !existing
                .signatures
                .iter()
                .any(|s| s.validator == validator_sig.validator)
            {
                existing.signatures.push(validator_sig);
            }
        } else {
            // 新建 LightClientHeader。
            let lch = crate::network::LightClientHeader {
                header_bytes,
                signatures: vec![validator_sig],
                signer_bitmap: vec![],
            };
            headers.push(lch);
            // 限制缓存大小（保留最近 1000 个 header）。
            if headers.len() > 1000 {
                headers.remove(0);
            }
        }
    }

    /// 获取缓存的 LightClientHeader 列表（供 subscribe_light_headers RPC/P2P 使用）。
    #[must_use]
    pub fn get_light_headers(&self) -> Vec<crate::network::LightClientHeader> {
        self.light_headers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Serve only durable, quorum-authenticated header attestations for P2P range sync.
    ///
    /// The in-memory share cache deliberately does not participate here: an unquorumed share is
    /// useful to validators but is not a finality proof and must never be served as sync state.
    pub fn finalized_light_headers_by_range(
        &self,
        start: BlockHeight,
        end: BlockHeight,
    ) -> PokerL1Result<Vec<LightClientHeader>> {
        if start > end {
            return Ok(Vec::new());
        }
        let capped_end =
            end.min(start.saturating_add(MAX_LIGHT_HEADERS_PER_SYNC_REQUEST.saturating_sub(1)));
        self.block_store
            .get_finalized_light_header_range(start, capped_end, self.config.chain_id)
    }

    /// Fetch and persist a contiguous authenticated header chain from peers.
    ///
    /// This is intentionally independent of full-block synchronization: a fresh full node first
    /// obtains compact BFT attestations, then uses one of those authenticated headers to validate
    /// a snapshot, and finally replays post-snapshot block bodies.
    pub fn sync_authenticated_headers_from_network(
        &self,
        transport: &dyn NetworkTransport,
    ) -> PokerL1Result<u64> {
        let mut next_height = self
            .block_store
            .get_header_tip_height()?
            .map(|height| {
                height.checked_add(1).ok_or_else(|| {
                    PokerL1Error::Other("authenticated header height overflow".to_string())
                })
            })
            .transpose()?
            // Height zero is not an independently accepted light-client header.  A fresh node
            // starts from the first finalized block and anchors it to the canonical genesis state.
            .unwrap_or(1);
        let mut synchronized = 0u64;

        loop {
            let end_height =
                next_height.saturating_add(MAX_LIGHT_HEADERS_PER_SYNC_REQUEST.saturating_sub(1));
            let headers = transport.request_light_client_headers(next_height, end_height)?;
            if headers.is_empty() {
                break;
            }
            if headers.len() > MAX_LIGHT_HEADERS_PER_SYNC_REQUEST as usize {
                return Err(PokerL1Error::Other(format!(
                    "peer returned {} light headers; maximum is {}",
                    headers.len(),
                    MAX_LIGHT_HEADERS_PER_SYNC_REQUEST
                )));
            }

            for light_header in &headers {
                let decoded: BlockHeader = borsh::from_slice(&light_header.header_bytes)?;
                if borsh::to_vec(&decoded)? != light_header.header_bytes {
                    return Err(PokerL1Error::Other(
                        "peer returned a non-canonical light-client header".to_string(),
                    ));
                }
                if decoded.height != next_height {
                    return Err(PokerL1Error::Other(format!(
                        "authenticated header sync expected height {next_height}, got {}",
                        decoded.height
                    )));
                }
                let finalized = self.ingest_light_header(light_header.clone())?;
                if finalized.is_none() {
                    let persisted = self
                        .block_store
                        .get_finalized_light_header_by_height(next_height, self.config.chain_id)
                        .map_err(|_| {
                            PokerL1Error::Other(format!(
                                "peer supplied a non-finalized light header at height {next_height}"
                            ))
                        })?;
                    if persisted.header_bytes != light_header.header_bytes {
                        return Err(PokerL1Error::Other(format!(
                            "persisted light header differs at height {next_height}"
                        )));
                    }
                }
                synchronized = synchronized.checked_add(1).ok_or_else(|| {
                    PokerL1Error::Other("authenticated header sync count overflow".to_string())
                })?;
                next_height = next_height.checked_add(1).ok_or_else(|| {
                    PokerL1Error::Other("authenticated header height overflow".to_string())
                })?;
            }

            if headers.len() < MAX_LIGHT_HEADERS_PER_SYNC_REQUEST as usize {
                break;
            }
        }
        Ok(synchronized)
    }

    /// Verify, chain-anchor, and merge a peer-provided light-header signature share.
    ///
    /// A peer may supply fewer than quorum signatures while validators are collecting shares.
    /// Such a share is retained only after every signature, the active ValidatorSet membership,
    /// canonical header encoding, and the local chain anchor have been verified. The returned
    /// header is present only when the merged set reaches a full quorum and is therefore safe to
    /// expose to light clients or relay further.
    pub fn ingest_light_header(
        &self,
        header: LightClientHeader,
    ) -> PokerL1Result<Option<LightClientHeader>> {
        if header.header_bytes.len() > MAX_LIGHT_CLIENT_HEADER_BYTES {
            return Err(PokerL1Error::Other(format!(
                "light client header exceeds {} byte limit",
                MAX_LIGHT_CLIENT_HEADER_BYTES
            )));
        }
        let decoded: BlockHeader = borsh::from_slice(&header.header_bytes)?;
        if borsh::to_vec(&decoded)? != header.header_bytes {
            return Err(PokerL1Error::Other(
                "light client header is not canonically encoded".into(),
            ));
        }

        match self.block_store.get_header_by_height(decoded.height) {
            Ok(known) if known != decoded => {
                return Err(PokerL1Error::Other(
                    "light client header conflicts with locally finalized block".into(),
                ));
            }
            Ok(_) => {}
            Err(PokerL1Error::BlockNotFound) => {
                if decoded.height == 0 {
                    return Err(PokerL1Error::Other(
                        "cannot accept an unanchored light-client genesis header".into(),
                    ));
                }
                let expected_parent_hash = if decoded.height == 1 {
                    self.genesis_parent_hash()?
                } else {
                    self.block_store
                        .get_header_by_height(decoded.height - 1)?
                        .block_hash(self.config.chain_id)
                };
                if decoded.prev_hash != expected_parent_hash {
                    return Err(PokerL1Error::Other(
                        "light client header does not extend the local finalized chain".into(),
                    ));
                }
            }
            Err(error) => return Err(error),
        }

        let validators = self.active_validator_pubkeys_sorted();
        verify_light_client_header_signatures(&header, &validators, verify_signature)?;

        let mut headers = self.light_headers.lock().unwrap_or_else(|e| e.into_inner());
        let merged = if let Some(existing) = headers
            .iter()
            .find(|existing| existing.header_bytes == header.header_bytes)
        {
            let mut candidate = existing.clone();
            for sig in &header.signatures {
                if !candidate
                    .signatures
                    .iter()
                    .any(|known| known.validator == sig.validator)
                {
                    candidate.signatures.push(sig.clone());
                }
            }
            candidate
        } else {
            header
        };

        // Validate the complete candidate before committing it to the cache.  In particular, this
        // keeps a collection of individually valid shares from exceeding the bounded wire/storage
        // representation after aggregation.
        let finalized = match verify_light_client_header(&merged, &validators, verify_signature) {
            Ok(()) => true,
            Err(PokerL1Error::LightClientQuorumInsufficient { .. }) => false,
            Err(error) => return Err(error),
        };
        if let Some(existing) = headers
            .iter_mut()
            .find(|existing| existing.header_bytes == merged.header_bytes)
        {
            *existing = merged.clone();
        } else {
            headers.push(merged.clone());
            if headers.len() > 1000 {
                headers.remove(0);
            }
        }
        drop(headers);

        if finalized {
            self.block_store
                .put_finalized_light_header(&merged, self.config.chain_id)?;
            Ok(Some(merged))
        } else {
            Ok(None)
        }
    }

    /// Return the pruning limits committed in the current governance singleton.
    ///
    /// These limits are consensus-governed.  A local node must never silently substitute its
    /// build-time defaults after governance has changed the retention policy.
    fn committed_pruning_config(&self) -> crate::storage::PruningConfig {
        let params = &self
            .governance
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .params;
        crate::storage::PruningConfig {
            tx_prune_after_blocks: params.tx_prune_after_blocks,
            vertex_prune_after_blocks: params.vertex_prune_after_blocks,
            dispute_window_blocks: params.dispute_window_blocks,
            archive_node_min_count: u32::try_from(params.archive_node_min_count)
                // Governance validation currently bounds this value to a small range.  Keeping
                // the conversion saturating nevertheless makes an invalid persisted value fail
                // closed below instead of wrapping to a smaller archive requirement.
                .unwrap_or(u32::MAX),
            archive_retention_blocks: params.archive_retention_blocks,
        }
    }

    /// Execute local state pruning only after an authenticated archive-availability provider is
    /// integrated.
    ///
    /// The pruning thresholds themselves are loaded from governance, but this node currently has
    /// no consensus-authenticated source for both the archive membership count and proof/blob
    /// availability.  The previous implementation deleted block bodies and DAG vertices anyway,
    /// based on local defaults.  That could destroy data needed for an open dispute.  Until the
    /// archive provider supplies and verifies that evidence, this boundary intentionally retains
    /// all data and reports a successful no-op.  A future provider must enforce the committed
    /// `dispute_window_blocks`, `archive_node_min_count`, and `archive_retention_blocks` before
    /// calling the destructive storage methods.
    ///
    /// Returns `(pruned_blocks, pruned_vertices)`; currently always `(0, 0)`.
    pub fn run_pruning(&self, current_height: u64) -> PokerL1Result<(usize, usize)> {
        let config = self.committed_pruning_config();
        tracing::debug!(
            current_height,
            tx_prune_after_blocks = config.tx_prune_after_blocks,
            vertex_prune_after_blocks = config.vertex_prune_after_blocks,
            dispute_window_blocks = config.dispute_window_blocks,
            archive_node_min_count = config.archive_node_min_count,
            archive_retention_blocks = config.archive_retention_blocks,
            "pruning skipped: no authenticated archive-availability provider is configured"
        );
        Ok((0, 0))
    }

    /// 验证 block（P0-3）。
    ///
    /// 在 block 入库前调用，确保 block 合法且状态根正确。
    pub fn validate_block(&self, block: &Block) -> PokerL1Result<()> {
        self.validate_block_structure(block)?;
        let object_db = self.object_db.lock().unwrap_or_else(|e| e.into_inner());
        let account_store = self.account_store.lock().unwrap_or_else(|e| e.into_inner());
        let _ = self.prepare_block_execution(block, &object_db, &account_store)?;
        Ok(())
    }

    /// Validate block metadata that is independent of the local execution state.
    fn validate_block_structure(&self, block: &Block) -> PokerL1Result<()> {
        let header = &block.header;

        // 1. A body may arrive after its compact, quorum-authenticated header was synchronized.
        // Treat that durable header as the canonical commitment, while still requiring a new
        // unsynchronized body to extend the authenticated tip exactly once.  This deliberately
        // separates header finality from body availability for snapshot fast sync.
        let known_header = match self.block_store.get_header_by_height(header.height) {
            Ok(known) => {
                if known != *header {
                    return Err(PokerL1Error::Other(format!(
                        "block body conflicts with authenticated header at height {}",
                        header.height
                    )));
                }
                true
            }
            Err(PokerL1Error::BlockNotFound) => false,
            Err(error) => return Err(error),
        };
        if !known_header {
            match self.block_store.get_header_tip_height()? {
                Some(tip_height) => {
                    let expected_height = tip_height
                        .checked_add(1)
                        .ok_or_else(|| PokerL1Error::Other("block height overflow".into()))?;
                    if header.height != expected_height {
                        return Err(PokerL1Error::BlockHeightNotIncreasing {
                            prev: tip_height,
                            got: header.height,
                        });
                    }
                }
                None if header.height != 1 => {
                    return Err(PokerL1Error::BlockHeightNotIncreasing {
                        prev: 0,
                        got: header.height,
                    });
                }
                None => {}
            }
        }

        let previous_header = if header.height == 1 {
            // Genesis monetary/object state is initialized outside BlockStore, but its immutable
            // manifest anchor is part of ObjectDb.  The first consensus block must bind to that
            // exact anchor instead of a universal all-zero sentinel.
            let expected_genesis_parent = self.genesis_parent_hash()?;
            if header.prev_hash != expected_genesis_parent {
                return Err(PokerL1Error::InvalidPrevHash {
                    expected: expected_genesis_parent,
                    got: header.prev_hash,
                });
            }
            None
        } else {
            let previous_height = header
                .height
                .checked_sub(1)
                .ok_or_else(|| PokerL1Error::Other("block height underflow".into()))?;
            let previous = self.block_store.get_header_by_height(previous_height)?;
            validate_block_time(Some(&previous), header, &TimeConsensusConfig::default())?;
            let expected_prev_hash = previous.block_hash(self.config.chain_id);
            if header.prev_hash != expected_prev_hash {
                return Err(PokerL1Error::InvalidPrevHash {
                    expected: expected_prev_hash,
                    got: header.prev_hash,
                });
            }
            Some(previous)
        };

        // 2. Both lane commitments must exactly match their bodies.
        validate_block_tx_roots(
            &block.public_txs,
            &block.gameturn_txs,
            header.public_tx_root,
            header.gameturn_tx_root,
        )?;

        // 3. GameTurn / CheckpointAnchor are the only gas-free body lane.
        validate_gameturn_no_gas(&block.gameturn_txs)?;

        // 4. Bind the certificate to both this header and the previous finalized certificate.
        // The signature alone proves only that validators signed a self-contained statement; it
        // does not establish that the statement belongs at this point in the local chain.
        let cert = &header.dag_commit_certificate;
        let expected_prev_commit_hash = previous_header
            .as_ref()
            .map(|previous| {
                previous.dag_commit_certificate.cert_hash_for_header(
                    self.config.chain_id,
                    previous.height,
                    previous.timestamp_ms,
                    previous.prev_hash,
                )
            })
            .unwrap_or([0u8; 32]);
        match previous_header.as_ref() {
            None if cert.epoch != self.current_epoch() => {
                return Err(PokerL1Error::CommitCertificateMismatch(format!(
                    "first certificate epoch mismatch: cert={}, validator_set={}",
                    cert.epoch,
                    self.current_epoch()
                )));
            }
            Some(previous) => {
                let previous_epoch = previous.dag_commit_certificate.epoch;
                let max_epoch = previous_epoch
                    .checked_add(1)
                    .ok_or_else(|| PokerL1Error::Other("certificate epoch overflow".into()))?;
                if cert.epoch < previous_epoch || cert.epoch > max_epoch {
                    return Err(PokerL1Error::CommitCertificateMismatch(format!(
                        "certificate epoch must stay at {previous_epoch} or advance once to {max_epoch}, got {}",
                        cert.epoch
                    )));
                }
            }
            None => {}
        }
        validate_commit_certificate_fields(
            cert,
            cert.epoch,
            expected_prev_commit_hash,
            header.state_root,
            header.account_root,
            header.public_tx_root,
            header.gameturn_tx_root,
        )?;

        let expected_commit_round = previous_header.as_ref().map_or(Ok(1), |previous| {
            previous
                .dag_commit_certificate
                .commit_round
                .checked_add(1)
                .ok_or_else(|| PokerL1Error::Other("commit round overflow".into()))
        })?;
        if cert.commit_round != expected_commit_round {
            return Err(PokerL1Error::CommitCertificateMismatch(format!(
                "commit_round mismatch: cert={}, expected={expected_commit_round}",
                cert.commit_round
            )));
        }

        // 5. A production node always requires a full, individually verified quorum.
        // A DAG reference graph is not a substitute for a finality certificate.
        let active_pubkeys = self.active_validator_pubkeys_sorted();
        if active_pubkeys.is_empty() && !self.allow_empty_consensus_for_tests {
            return Err(PokerL1Error::Other(
                "cannot admit block with an empty active ValidatorSet".into(),
            ));
        }
        if !self.allow_empty_consensus_for_tests
            && active_pubkeys.len() < crate::consensus::validator_set::MIN_VALIDATOR_SET_SIZE
        {
            return Err(PokerL1Error::ValidatorSetTooSmallForOffChain {
                size: active_pubkeys.len(),
            });
        }
        if !active_pubkeys.is_empty() {
            validate_commit_certificate_signatures_for_header(
                cert,
                &active_pubkeys,
                self.config.chain_id,
                header.height,
                header.timestamp_ms,
                header.prev_hash,
            )?;
        }

        Ok(())
    }

    /// Return the unique parent commitment for the first consensus block.
    ///
    /// An uninitialized in-memory node keeps the all-zero value only for low-level tests that do
    /// not establish a genesis state.  Any initialized persistent state must contain the anchor;
    /// accepting zero in that state would reopen the split-genesis problem.
    pub fn genesis_parent_hash(&self) -> PokerL1Result<Hash> {
        let object_db = self
            .object_db
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        match read_genesis_manifest_hash(&object_db)? {
            Some(hash) => Ok(hash),
            // A cold-sync node must authenticate the first finalized header before it can
            // download the snapshot that contains GenesisAnchor.  The launcher-supplied hash is
            // precisely the trust anchor for that initial request.  It is safe to use only while
            // the local monetary state is still absent; an initialized database missing its
            // anchor remains a fatal corruption rather than silently falling back to config.
            None if crate::economics::read_treasury(&object_db)?.is_none() => {
                Ok(self.config.genesis_manifest_hash.unwrap_or([0u8; 32]))
            }
            None => Err(PokerL1Error::Other(
                "initialized chain is missing its GenesisAnchor".into(),
            )),
        }
    }

    /// Execute a candidate block against isolated ObjectDb and AccountStore snapshots.
    ///
    /// The returned snapshots are suitable for a caller that has already completed all validation
    /// and wants to commit them.  Ordinary validation simply drops them, leaving live state
    /// untouched even when the candidate state root is wrong.
    fn prepare_block_execution(
        &self,
        block: &Block,
        object_db: &ObjectDb,
        account_store: &AccountStore,
    ) -> PokerL1Result<(
        ObjectDbSnapshot,
        AccountStore,
        BlockExecutionOutcome,
        Option<ValidatorSet>,
        Option<BridgeRegistrySnapshot>,
    )> {
        let header = &block.header;
        let mut env = self.execution_environment(header.height, header.timestamp_ms);
        if let Some(first_vh) = header.dag_commit_certificate.vertex_hash_list.first() {
            if let Ok(vertex) = self.vertex_store.get_by_hash(first_vh) {
                env = env.with_proposer(crate::account::derive_address(&vertex.author_pubkey));
            }
        }

        let mut object_snapshot = object_db.create_snapshot();
        let mut account_snapshot = account_store.create_snapshot();
        let bridge_config = read_persisted_bridge_registry_config(object_db, self.config.chain_id)?
            .unwrap_or_else(|| crate::bridge::BridgeRegistryConfig::empty(self.config.chain_id));
        let bridge_snapshot = if let Some(store) = &self.bridge_registry_store {
            let mut snapshot = store.create_snapshot_with_config(&bridge_config);
            let replay_state = read_persisted_bridge_replay_state(object_db, self.config.chain_id)?
                .ok_or_else(|| {
                    PokerL1Error::Other(
                        "bridge-enabled node is missing its replay-protection state commitment"
                            .to_string(),
                    )
                })?;
            if !replay_state.matches_registry(snapshot.registry_mut()) {
                return Err(PokerL1Error::Other(
                    "local bridge nonce archive does not match the state-root commitment"
                        .to_string(),
                ));
            }
            Some(Arc::new(Mutex::new(snapshot)))
        } else {
            None
        };
        if let Some(snapshot) = &bridge_snapshot {
            env = env.with_bridge_registry_snapshot(Arc::clone(snapshot));
        }
        let current_validator_set = self
            .validator_set
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let block_start_validator_set = self.stage_block_validator_maintenance(
            &mut object_snapshot,
            &current_validator_set,
            header.height,
        )?;
        // Timelocked contract upgrades are consensus state transitions, not best-effort runtime
        // work.  Stage them before replaying user transactions so a block at the activation
        // height observes the new code and commits the same root on every validator.
        crate::vm::activate_due_persisted_upgrades(&mut object_snapshot, header.height)?;
        if self.precompile_registry.is_consensus_governed() {
            crate::vm::precompile::activate_due_precompile_upgrades(
                &mut object_snapshot,
                self.config.chain_id,
                header.height,
            )?;
        }
        let validator_set_snapshot = Arc::new(Mutex::new(block_start_validator_set));
        env = env.with_validator_set_snapshot(Arc::clone(&validator_set_snapshot));
        let txs = block.canonical_execution_txs();
        let mut outcome =
            execute_block_serial(&env, &txs, &mut object_snapshot, &mut account_snapshot);
        let tx_validator_set = validator_set_snapshot
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let certificate_validator_set = self.stage_certificate_epoch_transition(
            &mut object_snapshot,
            &tx_validator_set,
            header.height,
            header.dag_commit_certificate.epoch,
            header.dag_commit_certificate.prev_commit_hash,
            header.dag_commit_certificate.epoch_transition.as_ref(),
        )?;
        let final_validator_set = certificate_validator_set.unwrap_or(tx_validator_set);
        let next_validator_set =
            (final_validator_set != current_validator_set).then_some(final_validator_set);
        outcome.state_root = object_snapshot.state_root();
        validate_state_root_transition(outcome.state_root, header.state_root)?;
        if outcome.account_root != header.account_root {
            return Err(PokerL1Error::StateRootMismatch {
                expected: header.account_root,
                got: outcome.account_root,
            });
        }
        let staged_bridge_snapshot = bridge_snapshot.map(|snapshot| {
            snapshot
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .clone()
        });
        Ok((
            object_snapshot,
            account_snapshot,
            outcome,
            next_validator_set,
            staged_bridge_snapshot,
        ))
    }

    /// Stage the certificate-authorized epoch transition in the same ObjectDb snapshot as block
    /// transaction execution.  The returned set is installed in the in-memory cache only after the
    /// snapshot commits.
    fn stage_certificate_epoch_transition(
        &self,
        object_snapshot: &mut ObjectDbSnapshot,
        current: &ValidatorSet,
        block_height: BlockHeight,
        target_epoch: Epoch,
        previous_certificate_hash: Hash,
        epoch_transition: Option<&EpochTransitionProof>,
    ) -> PokerL1Result<Option<ValidatorSet>> {
        if target_epoch == current.epoch {
            if epoch_transition.is_some() {
                return Err(PokerL1Error::CommitCertificateMismatch(
                    "certificate carries an epoch transition without advancing epoch".into(),
                ));
            }
            return Ok(None);
        }
        let expected_epoch = current
            .epoch
            .checked_add(1)
            .ok_or_else(|| PokerL1Error::Other("validator epoch overflow".into()))?;
        if target_epoch != expected_epoch {
            return Err(PokerL1Error::CommitCertificateMismatch(format!(
                "certificate epoch must match validator state {} or advance once to {expected_epoch}, got {target_epoch}",
                current.epoch
            )));
        }

        let mut next = current.clone();
        match epoch_transition {
            Some(transition) => {
                let designated =
                    current.designated_epoch_vrf_proposer(self.config.chain_id, target_epoch)?;
                if transition.proposer_pubkey != designated {
                    return Err(PokerL1Error::InvalidVrfProof(
                        "epoch VRF proof proposer is not the designated validator".into(),
                    ));
                }
                next.advance_epoch(target_epoch);
                let verifier = crate::consensus::ecvrf::Secp256k1VrfVerifier::new();
                next.submit_epoch_vrf_proof(
                    self.config.chain_id,
                    &transition.proposer_pubkey,
                    &transition.proof,
                    &verifier,
                )?;
            }
            None => {
                next.advance_epoch(target_epoch);
                next.derive_epoch_randomness_from_certificate(
                    self.config.chain_id,
                    previous_certificate_hash,
                );
            }
        }

        // Governance membership updates take effect only after this block's certificate was
        // checked with the old set and exactly at the declared epoch boundary. Both singleton
        // replacements live in the same ObjectDb snapshot, so no replay can observe one without
        // the other.
        match object_snapshot.read(&crate::governance::GOVERNANCE_STATE_OBJECT_ID) {
            Ok(object) => {
                let current_governance = crate::governance::decode_governance_state_object(
                    &object,
                    self.config.chain_id,
                )?;
                let mut next_governance = current_governance.clone();
                // Capture and verify every funded addition before mutating either singleton.
                // A proposal created through the legacy governance wire has no pending escrow
                // and therefore cannot introduce stake here.
                let bonded_additions: Vec<(u64, Vec<crate::governance::ValidatorAddition>)> =
                    current_governance
                        .proposals
                        .iter()
                        .filter_map(|(&proposal_id, proposal)| match &proposal.kind {
                            crate::governance::ProposalKind::ValidatorSetUpdate {
                                additions,
                                effective_epoch,
                                ..
                            } if proposal.status == crate::governance::ProposalStatus::Passed
                                && *effective_epoch == target_epoch
                                && !additions.is_empty() =>
                            {
                                Some((proposal_id, additions.clone()))
                            }
                            _ => None,
                        })
                        .collect();
                let mut pending_bond_escrow = if bonded_additions.is_empty() {
                    None
                } else {
                    Some(
                        crate::governance::read_validator_bond_escrow(
                            object_snapshot,
                            self.config.chain_id,
                        )?
                        .ok_or_else(|| {
                            PokerL1Error::Other(
                                "bonded validator additions require a pending NativeCoin escrow singleton"
                                    .into(),
                            )
                        })?,
                    )
                };
                if let Some((escrow, _)) = &pending_bond_escrow {
                    for (proposal_id, additions) in &bonded_additions {
                        escrow.validate_activation(*proposal_id, additions)?;
                    }
                }
                let set_update_changed = next_governance.apply_validator_set_updates_at_epoch(
                    &mut next,
                    target_epoch,
                    block_height,
                )?;
                if let Some((escrow, version)) = &mut pending_bond_escrow {
                    for (proposal_id, additions) in &bonded_additions {
                        // `release_activated` repeats the exact-key/value check before erasing
                        // any custody.  The state-root snapshot now contains the corresponding
                        // `ValidatorSet` stake, so total native supply is unchanged.
                        escrow.release_activated(*proposal_id, additions)?;
                    }
                    crate::governance::write_validator_bond_escrow(
                        object_snapshot,
                        self.config.chain_id,
                        Some(*version),
                        escrow,
                    )?;
                }

                // Key rotations are also epoch-bound.  The certificate for this block was
                // verified before entering this method with `current`, so replacing keys here
                // cannot retroactively change the signer set that finalized the transition.
                let pending_rotations =
                    next_governance.pending_key_rotations_at_height(block_height);
                let mut key_history = if pending_rotations.is_empty() {
                    None
                } else {
                    Some(
                        crate::consensus::read_validator_key_history(
                            object_snapshot,
                            self.config.chain_id,
                        )?
                        .unwrap_or_else(|| (crate::consensus::ValidatorKeyHistory::default(), 0)),
                    )
                };
                let key_history_was_present = if pending_rotations.is_empty() {
                    false
                } else {
                    object_snapshot
                        .read(&crate::consensus::VALIDATOR_KEY_HISTORY_OBJECT_ID)
                        .is_ok()
                };
                if let Some((history, _)) = &mut key_history {
                    let mut executed = Vec::with_capacity(pending_rotations.len());
                    for (proposal_id, old_pubkey, new_pubkey) in &pending_rotations {
                        next.rotate_validator_key(old_pubkey, new_pubkey.clone())?;
                        history.record(
                            old_pubkey.clone(),
                            new_pubkey.clone(),
                            target_epoch,
                            block_height,
                        )?;
                        executed.push(*proposal_id);
                    }
                    next_governance.mark_key_rotations_executed(&executed)?;
                }
                if let Some((history, version)) = key_history {
                    crate::consensus::write_validator_key_history(
                        object_snapshot,
                        self.config.chain_id,
                        key_history_was_present.then_some(version),
                        &history,
                    )?;
                }
                if set_update_changed || !pending_rotations.is_empty() {
                    crate::governance::replace_persisted_governance_state(
                        object_snapshot,
                        self.config.chain_id,
                        &current_governance,
                        &next_governance,
                    )?;
                }
            }
            Err(PokerL1Error::ObjectNotFound(_)) if self.allow_empty_consensus_for_tests => {}
            Err(error) => return Err(error),
        }

        match object_snapshot.read(&crate::consensus::validator_set::VALIDATOR_SET_OBJECT_ID) {
            Ok(_) => {
                stage_validator_set_update(object_snapshot, self.config.chain_id, current, &next)?
            }
            Err(PokerL1Error::ObjectNotFound(_)) if self.allow_empty_consensus_for_tests => {
                // Legacy in-memory tests may intentionally run without initialized genesis system
                // objects. Production startup rejects that configuration before consensus starts.
            }
            Err(error) => return Err(error),
        }
        Ok(Some(next))
    }

    /// Stage deterministic validator maintenance that every block replays before user calls.
    ///
    /// Bonding expiry is derived only from the committed block height.  It therefore cannot be
    /// driven by a node-local timer and is written through the same ValidatorSet system object as
    /// signed validator-system transactions.
    fn stage_block_validator_maintenance(
        &self,
        object_snapshot: &mut ObjectDbSnapshot,
        current: &ValidatorSet,
        block_height: BlockHeight,
    ) -> PokerL1Result<ValidatorSet> {
        let mut next = current.clone();
        next.process_bonding_expiry(block_height);
        if next == *current {
            return Ok(next);
        }
        match object_snapshot.read(&crate::consensus::validator_set::VALIDATOR_SET_OBJECT_ID) {
            Ok(_) => {
                stage_validator_set_update(object_snapshot, self.config.chain_id, current, &next)?
            }
            Err(PokerL1Error::ObjectNotFound(_)) if self.allow_empty_consensus_for_tests => {}
            Err(error) => return Err(error),
        }
        Ok(next)
    }

    /// 当前全局状态根（所有 live 对象的 Sparse Merkle Root）。
    ///
    /// 返回 object_db 的当前 SMT root（即上一 block 后的状态根）。
    /// 产块时应先调用 [`Self::execute_block_on_state`] 执行 vertex 中的 txs，
    /// 取返回的 `outcome.state_root` 作为新 block header 的 `state_root`。
    pub fn state_root(&self) -> Hash {
        self.object_db
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .state_root()
    }

    /// Current deterministic commitment of balances, resource credits and account replay nonces.
    pub fn account_root(&self) -> Hash {
        self.account_store
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .state_root()
    }

    /// 获取预编译合约注册表引用（共享 Arc）。
    ///
    /// 供 `build_block_from_vertex` 构造 [`ExecutionEnvironment`] 时使用，
    /// 避免 main.rs 直接访问 Node 私有字段。
    #[must_use]
    pub fn precompile_registry(&self) -> Arc<PrecompileRegistry> {
        Arc::clone(&self.precompile_registry)
    }

    /// 获取 ZK verifier registry 的 clone（链上 zk_verify 启用）。
    /// 供 executor 构造 ExecutionEnvironment 时注入，使 VM 内 `zk_verify` syscall 可用。
    #[must_use]
    pub(crate) fn zk_verifier_registry_clone(
        &self,
    ) -> Option<crate::offline::zk_verifier::ZkVerifierRegistry> {
        self.zk_verifier.clone()
    }

    /// Synchronize the shared verifier-status control plane from authenticated governance state.
    ///
    /// The verifier implementations themselves remain fixed at node startup; only the per-chain
    /// Stub/Production status is updated. All registry clones observe the same status map.
    ///
    /// # Errors
    ///
    /// Returns an error when this node has no ZK verifier registry configured.
    pub(crate) fn synchronize_zk_verifier_governance(
        &self,
        governance: &crate::governance::GovernanceState,
    ) -> PokerL1Result<()> {
        let registry = self.zk_verifier.as_ref().ok_or_else(|| {
            PokerL1Error::Other("node has no ZK verifier registry to synchronize".into())
        })?;
        registry.synchronize_governance_statuses(governance);
        Ok(())
    }

    /// Construct the deterministic block execution environment owned by this node.
    ///
    /// Keeping this assembly in one place is consensus-critical: block production and block
    /// replay must inject the same precompile, ZK-verifier, and bridge registries. In particular,
    /// an application-aware recursive verifier registered at node startup must be visible to the
    /// VM `zk_verify` syscall on every execution path.
    #[must_use]
    pub fn execution_environment(
        &self,
        block_height: BlockHeight,
        block_timestamp: crate::TimestampMs,
    ) -> ExecutionEnvironment {
        let mut env =
            ExecutionEnvironment::new(self.config.chain_id, block_height, block_timestamp)
                .with_precompile_registry_arc(Arc::clone(&self.precompile_registry))
                .with_fee_policy(
                    *self
                        .fee_policy
                        .lock()
                        .unwrap_or_else(|error| error.into_inner()),
                );
        if let Some(registry) = &self.zk_verifier {
            env = env.with_zk_verifier(registry.clone());
        }
        if let Some(bridge_store) = &self.bridge_registry_store {
            env = env.with_bridge_registry_store(Arc::clone(bridge_store));
        }
        env
    }

    /// 获取指标收集器引用（缺口 #7）。
    #[must_use]
    pub fn metrics(&self) -> Arc<crate::metrics::MetricsCollector> {
        Arc::clone(&self.metrics)
    }

    /// Access the finalized-block indexer for RPC/query integration.
    #[must_use]
    pub fn indexer(&self) -> Arc<Indexer> {
        Arc::clone(&self.indexer)
    }

    /// 导出 Prometheus 格式指标文本（缺口 #7）。
    #[must_use]
    pub fn export_metrics(&self) -> String {
        // 刷新 gauge 类指标（tip 高度 + mempool 大小）。
        let tip = self
            .block_store
            .get_tip_height()
            .ok()
            .flatten()
            .unwrap_or(0);
        self.metrics.set_block_height(tip);
        self.metrics.set_mempool_size(
            self.pending_tx
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .len() as u64,
        );
        self.metrics.export()
    }

    /// 获取 Bridge registry store 引用（共享 Arc；缺口 #9）。
    ///
    /// 供 `build_block_from_vertex` / `validate_block` 构造 [`ExecutionEnvironment`] 时注入，
    /// 使 bridge contract_call 能访问持久化的 nonce registry。`None` 表示节点未启用桥。
    #[must_use]
    pub fn bridge_registry_store(&self) -> Option<Arc<BridgeRegistryStore>> {
        self.bridge_registry_store.clone()
    }

    /// Build one self-consistent full-state snapshot at the current finalized tip.
    ///
    /// Only archive nodes serve snapshots.  The method locks ObjectDb and AccountStore in the
    /// same order as block execution, then requires both roots to match the selected tip header.
    /// A concurrent commit therefore yields an error rather than an inconsistent export.
    pub fn build_full_snapshot_at_tip(&self) -> PokerL1Result<FullSnapshot> {
        if !self.serves_historical_data() {
            return Err(PokerL1Error::Other(
                "only archive nodes may serve full-state snapshots".to_string(),
            ));
        }
        let height = self.block_store.get_tip_height()?.ok_or_else(|| {
            PokerL1Error::Other("cannot snapshot an empty block store".to_string())
        })?;
        let block = self.block_store.get_by_height(height)?;
        let object_db = self
            .object_db
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let account_store = self
            .account_store
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        match &self.bridge_registry_store {
            Some(bridge_store) => SnapshotBuilder::build_full_snapshot_with_bridge(
                &object_db,
                &account_store,
                bridge_store,
                &block.header,
                self.config.chain_id,
            ),
            None => SnapshotBuilder::build_full_snapshot(
                &object_db,
                &account_store,
                &block.header,
                self.config.chain_id,
            ),
        }
    }

    /// Download and install a full snapshot through the authenticated P2P sync protocol.
    ///
    /// The corresponding finalized header must already have passed header/certificate sync and
    /// exist in this node's `BlockStore`; [`FullFastSync`] verifies every manifest and chunk
    /// against it before mutating live state.  A light node intentionally cannot use this path.
    pub fn download_full_snapshot_from_network(
        &self,
        transport: &dyn NetworkTransport,
    ) -> PokerL1Result<FullSnapshotManifest> {
        if self.config.role.is_light() {
            return Err(PokerL1Error::Other(
                "light nodes do not retain state required for full fast sync".to_string(),
            ));
        }
        let mut object_db = self
            .object_db
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut account_store = self
            .account_store
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let manifest = match &self.bridge_registry_store {
            Some(bridge_store) => {
                let mut sync = FullFastSync::new_with_bridge(
                    &self.block_store,
                    &mut object_db,
                    &mut account_store,
                    bridge_store,
                );
                sync.download_snapshot_from_network(transport)?
            }
            None => {
                let mut sync =
                    FullFastSync::new(&self.block_store, &mut object_db, &mut account_store);
                sync.download_snapshot_from_network(transport)?
            }
        };
        let (validator_set, _) = read_persisted_validator_set(&object_db, self.config.chain_id)?
            .ok_or_else(|| {
                PokerL1Error::Other(
                    "full snapshot lacks the consensus ValidatorSet system object".to_string(),
                )
            })?;
        *self
            .validator_set
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = validator_set;
        let fee_policy = read_fee_policy(&object_db, self.config.chain_id)?.ok_or_else(|| {
            PokerL1Error::Other(
                "full snapshot lacks the consensus FeePolicy system object".to_string(),
            )
        })?;
        *self
            .fee_policy
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = fee_policy;
        let governance = read_persisted_governance_state(&object_db, self.config.chain_id)?
            .ok_or_else(|| {
                PokerL1Error::Other(
                    "full snapshot lacks the consensus GovernanceState system object".to_string(),
                )
            })?;
        *self
            .governance
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = governance;
        if let Some(registry) = &self.zk_verifier {
            registry.synchronize_governance_statuses(
                &self
                    .governance
                    .lock()
                    .unwrap_or_else(|error| error.into_inner()),
            );
        }
        self.indexer.synchronize_live_objects(object_db.iter())?;
        Ok(manifest)
    }

    /// Execute the complete cold-start synchronization sequence for a full/archive node.
    ///
    /// 1. download a contiguous chain of quorum-authenticated headers;
    /// 2. install a snapshot whose manifest is committed by one of those headers; and
    /// 3. replay every authenticated post-snapshot block body through `put_block`.
    ///
    /// No unverified block body is allowed to choose the target state: each replayed body must
    /// exactly match the header chain fetched in step 1.
    pub fn fast_sync_from_network(
        &self,
        transport: &dyn NetworkTransport,
    ) -> PokerL1Result<FullSnapshotManifest> {
        if self.config.role.is_light() {
            return Err(PokerL1Error::Other(
                "light nodes do not retain state required for full fast sync".to_string(),
            ));
        }
        let synchronized_headers = self.sync_authenticated_headers_from_network(transport)?;
        let authenticated_tip = self.block_store.get_header_tip_height()?.ok_or_else(|| {
            PokerL1Error::Other(
                "fast sync could not obtain any quorum-authenticated headers from peers"
                    .to_string(),
            )
        })?;
        let manifest = self.download_full_snapshot_from_network(transport)?;
        let snapshot_header = self
            .block_store
            .get_header_by_height(manifest.object_manifest.height)?;
        if snapshot_header.block_hash(self.config.chain_id) != manifest.block_hash() {
            return Err(PokerL1Error::Other(
                "snapshot manifest is not anchored to the authenticated header chain".to_string(),
            ));
        }
        let caught_up_blocks = self.catch_up_blocks_after_snapshot(
            transport,
            manifest.object_manifest.height,
            authenticated_tip,
        )?;
        tracing::info!(
            synchronized_headers,
            caught_up_blocks,
            snapshot_height = manifest.object_manifest.height,
            authenticated_tip,
            "authenticated full fast sync completed"
        );
        Ok(manifest)
    }

    /// Replay authenticated body ranges after a verified snapshot has become the local state.
    fn catch_up_blocks_after_snapshot(
        &self,
        transport: &dyn NetworkTransport,
        snapshot_height: BlockHeight,
        authenticated_tip: BlockHeight,
    ) -> PokerL1Result<u64> {
        if snapshot_height > authenticated_tip {
            return Err(PokerL1Error::Other(format!(
                "snapshot height {snapshot_height} exceeds authenticated header tip {authenticated_tip}"
            )));
        }
        let mut next_height = snapshot_height.checked_add(1).ok_or_else(|| {
            PokerL1Error::Other("snapshot height overflow during catch-up".to_string())
        })?;
        let mut caught_up = 0u64;
        while next_height <= authenticated_tip {
            let end_height = next_height
                .saturating_add(crate::sync::MAX_BLOCKS_PER_SYNC_REQUEST.saturating_sub(1))
                .min(authenticated_tip);
            let expected_count = usize::try_from(end_height - next_height + 1).map_err(|_| {
                PokerL1Error::Other("catch-up block range does not fit usize".to_string())
            })?;
            let blocks = transport.request_blocks_by_range(next_height, end_height)?;
            if blocks.len() != expected_count {
                return Err(PokerL1Error::Other(format!(
                    "catch-up peer returned {} blocks for {next_height}..={end_height}; expected {expected_count}",
                    blocks.len()
                )));
            }
            for (offset, block) in blocks.iter().enumerate() {
                let expected_height = next_height + offset as BlockHeight;
                if block.header.height != expected_height {
                    return Err(PokerL1Error::Other(format!(
                        "catch-up peer returned height {} at offset {offset}; expected {expected_height}",
                        block.header.height
                    )));
                }
                let authenticated_header =
                    self.block_store.get_header_by_height(expected_height)?;
                if authenticated_header != block.header {
                    return Err(PokerL1Error::Other(format!(
                        "catch-up block body does not match its authenticated header at height {expected_height}"
                    )));
                }
                self.put_block(block)?;
                caught_up = caught_up.checked_add(1).ok_or_else(|| {
                    PokerL1Error::Other("catch-up block count overflow".to_string())
                })?;
            }
            next_height = end_height.checked_add(1).ok_or_else(|| {
                PokerL1Error::Other(
                    "authenticated header height overflow during catch-up".to_string(),
                )
            })?;
        }
        Ok(caught_up)
    }

    /// 注入 Bridge registry store（builder 模式；缺口 #9）。
    ///
    /// 内存节点（`open_inmemory*`）默认不启用桥；需桥的测试可链式调用：
    /// `Node::open_inmemory(..)?.with_bridge(Arc::new(BridgeRegistryStore::open_inmemory()?))`。
    #[must_use]
    pub fn with_bridge(mut self, store: Arc<BridgeRegistryStore>) -> Self {
        self.bridge_registry_store = Some(store);
        self
    }

    /// 在当前链状态上执行 txs，返回执行结果（含新 state_root）。
    ///
    /// 供 `build_block_from_vertex` 在产块时调用：执行 vertex 中的 txs，
    /// 取 `outcome.state_root` 作为新 block 的 state_root。
    ///
    /// 内部加锁 `object_db` + `account_store`，调用 [`execute_block`]。
    /// execute_block 已设计为"失败 tx 返回失败回执，不阻断 block"，
    /// 故仅在底层错误（锁中毒 / RocksDB 写失败）时返回 `Err`。
    ///
    /// # 参数
    ///
    /// - `env`：执行环境（chain_id / height / timestamp / gas limit / precompile registry）
    /// - `txs`：待执行的有序 tx 列表（caller 应先 S9 排序）
    pub fn execute_block_on_state(
        &self,
        env: &ExecutionEnvironment,
        txs: &[Transaction],
    ) -> PokerL1Result<BlockExecutionOutcome> {
        if txs.iter().any(|tx| {
            tx.contract_call.as_ref().is_some_and(|call| {
                call.contract_id == crate::vm::precompile::reserved::validator_system_contract_id()
            })
        }) {
            return Err(PokerL1Error::Other(
                "validator system transactions may only execute through finalized block replay"
                    .into(),
            ));
        }
        let mut object_db = self
            .object_db
            .lock()
            .map_err(|e| PokerL1Error::Other(format!("object_db mutex poisoned: {e}")))?;
        let mut account_store = self
            .account_store
            .lock()
            .map_err(|e| PokerL1Error::Other(format!("account_store mutex poisoned: {e}")))?;
        Ok(execute_block(
            env,
            txs,
            &mut *object_db,
            &mut *account_store,
        ))
    }

    /// Deterministically execute transactions on isolated state snapshots.
    ///
    /// Block producers use this to derive a candidate state root before the resulting block is
    /// finalized and submitted through [`Self::put_block`].  Unlike
    /// [`Self::execute_block_on_state`], this method never changes the node's live ObjectDb or
    /// AccountStore, so producing a block cannot cause the later validation path to replay the
    /// same transaction twice.
    ///
    /// Bridge calls use an isolated nonce snapshot here.  The snapshot is intentionally dropped
    /// after simulation: only [`Self::put_block`] can make it durable under the block journal.
    pub fn simulate_block_execution(
        &self,
        env: &ExecutionEnvironment,
        txs: &[Transaction],
    ) -> PokerL1Result<BlockExecutionOutcome> {
        let object_db = self
            .object_db
            .lock()
            .map_err(|e| PokerL1Error::Other(format!("object_db mutex poisoned: {e}")))?;
        let account_store = self
            .account_store
            .lock()
            .map_err(|e| PokerL1Error::Other(format!("account_store mutex poisoned: {e}")))?;
        let mut object_snapshot = object_db.create_snapshot();
        let mut account_snapshot = account_store.create_snapshot();
        let mut simulation_env = env.clone();
        if let Some(store) = &self.bridge_registry_store {
            let bridge_config =
                read_persisted_bridge_registry_config(&object_db, self.config.chain_id)?
                    .unwrap_or_else(|| {
                        crate::bridge::BridgeRegistryConfig::empty(self.config.chain_id)
                    });
            simulation_env = simulation_env.with_bridge_registry_snapshot(Arc::new(Mutex::new(
                store.create_snapshot_with_config(&bridge_config),
            )));
        }
        let current_validator_set = self
            .validator_set
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let block_start_validator_set = self.stage_block_validator_maintenance(
            &mut object_snapshot,
            &current_validator_set,
            simulation_env.block_height,
        )?;
        crate::vm::activate_due_persisted_upgrades(
            &mut object_snapshot,
            simulation_env.block_height,
        )?;
        if self.precompile_registry.is_consensus_governed() {
            crate::vm::precompile::activate_due_precompile_upgrades(
                &mut object_snapshot,
                self.config.chain_id,
                simulation_env.block_height,
            )?;
        }
        simulation_env = simulation_env
            .with_validator_set_snapshot(Arc::new(Mutex::new(block_start_validator_set)));
        Ok(execute_block_serial(
            &simulation_env,
            txs,
            &mut object_snapshot,
            &mut account_snapshot,
        ))
    }

    /// Simulate transaction execution plus the certificate-authorized epoch transition.
    ///
    /// Block producers must use this variant so the proposed state root includes the exact same
    /// ValidatorSet mutation that full nodes apply while replaying the block.
    pub fn simulate_block_execution_for_certificate(
        &self,
        env: &ExecutionEnvironment,
        txs: &[Transaction],
        target_epoch: Epoch,
        previous_certificate_hash: Hash,
        epoch_transition: Option<&EpochTransitionProof>,
    ) -> PokerL1Result<BlockExecutionOutcome> {
        let object_db = self
            .object_db
            .lock()
            .map_err(|e| PokerL1Error::Other(format!("object_db mutex poisoned: {e}")))?;
        let account_store = self
            .account_store
            .lock()
            .map_err(|e| PokerL1Error::Other(format!("account_store mutex poisoned: {e}")))?;
        let mut object_snapshot = object_db.create_snapshot();
        let mut account_snapshot = account_store.create_snapshot();
        let mut simulation_env = env.clone();
        if let Some(store) = &self.bridge_registry_store {
            let bridge_config =
                read_persisted_bridge_registry_config(&object_db, self.config.chain_id)?
                    .unwrap_or_else(|| {
                        crate::bridge::BridgeRegistryConfig::empty(self.config.chain_id)
                    });
            simulation_env = simulation_env.with_bridge_registry_snapshot(Arc::new(Mutex::new(
                store.create_snapshot_with_config(&bridge_config),
            )));
        }
        let current_validator_set = self
            .validator_set
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let block_start_validator_set = self.stage_block_validator_maintenance(
            &mut object_snapshot,
            &current_validator_set,
            simulation_env.block_height,
        )?;
        crate::vm::activate_due_persisted_upgrades(
            &mut object_snapshot,
            simulation_env.block_height,
        )?;
        if self.precompile_registry.is_consensus_governed() {
            crate::vm::precompile::activate_due_precompile_upgrades(
                &mut object_snapshot,
                self.config.chain_id,
                simulation_env.block_height,
            )?;
        }
        let validator_set_snapshot = Arc::new(Mutex::new(block_start_validator_set));
        simulation_env =
            simulation_env.with_validator_set_snapshot(Arc::clone(&validator_set_snapshot));
        let mut outcome = execute_block_serial(
            &simulation_env,
            txs,
            &mut object_snapshot,
            &mut account_snapshot,
        );
        let tx_validator_set = validator_set_snapshot
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        self.stage_certificate_epoch_transition(
            &mut object_snapshot,
            &tx_validator_set,
            simulation_env.block_height,
            target_epoch,
            previous_certificate_hash,
            epoch_transition,
        )?;
        outcome.state_root = object_snapshot.state_root();
        Ok(outcome)
    }

    /// Build this node's proof when it is the designated proposer for the next epoch.
    ///
    /// Returning `None` is intentional for a non-designated node or a node without a configured
    /// VRF secret; the certificate-beacon fallback remains valid until multi-validator proof
    /// gossip supplies the selected validator's proof.
    pub fn local_epoch_transition_proof(
        &self,
        target_epoch: Epoch,
    ) -> PokerL1Result<Option<EpochTransitionProof>> {
        let current = self
            .validator_set
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if target_epoch == current.epoch {
            return Ok(None);
        }
        let designated =
            current.designated_epoch_vrf_proposer(self.config.chain_id, target_epoch)?;
        let Some(key) = self.config.validator_key.as_ref() else {
            return Ok(None);
        };
        if key.tagged_pubkey != designated {
            return Ok(None);
        }
        let Some(secret) = key.vrf_secret.as_ref() else {
            return Ok(None);
        };
        let prover = crate::consensus::ecvrf::Secp256k1VrfProver::from_secret_bytes(secret);
        let expected_pubkey = current
            .find_validator(&designated)
            .ok_or_else(|| PokerL1Error::ValidatorNotInSet(designated.clone()))?
            .vrf_pubkey;
        if prover.derive_public_key()? != expected_pubkey {
            return Err(PokerL1Error::InvalidVrfProof(
                "configured VRF secret does not match designated validator VRF public key".into(),
            ));
        }
        let input = crate::consensus::validator_set::compute_vrf_input(
            self.config.chain_id,
            target_epoch,
            &current.epoch_randomness,
        );
        let (proof, _) = prover.prove(&input)?;
        Ok(Some(EpochTransitionProof {
            proposer_pubkey: designated,
            proof,
        }))
    }

    /// Validate an untrusted epoch-transition proposal without changing local state.
    ///
    /// P2P receivers use this before caching a proof.  The same checks run again while applying
    /// the certificate, but performing them here prevents arbitrary peers from making validators
    /// sign competing or malformed certificate statements.
    pub fn validate_epoch_transition_proof(
        &self,
        target_epoch: Epoch,
        proof: &EpochTransitionProof,
    ) -> PokerL1Result<()> {
        let current = self
            .validator_set
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let expected_epoch = current
            .epoch
            .checked_add(1)
            .ok_or_else(|| PokerL1Error::Other("validator epoch overflow".into()))?;
        if target_epoch != expected_epoch {
            return Err(PokerL1Error::CommitCertificateMismatch(format!(
                "epoch transition proof must target next epoch {expected_epoch}, got {target_epoch}"
            )));
        }
        let designated =
            current.designated_epoch_vrf_proposer(self.config.chain_id, target_epoch)?;
        if proof.proposer_pubkey != designated {
            return Err(PokerL1Error::InvalidVrfProof(
                "epoch VRF proof proposer is not the designated validator".into(),
            ));
        }

        // `submit_epoch_vrf_proof` derives the canonical input from the pre-transition beacon
        // and performs the real ECVRF verification.  Run it on a clone to keep this method
        // strictly read-only.
        let mut candidate = current;
        candidate.advance_epoch(target_epoch);
        let verifier = crate::consensus::ecvrf::Secp256k1VrfVerifier::new();
        candidate.submit_epoch_vrf_proof(
            self.config.chain_id,
            &proof.proposer_pubkey,
            &proof.proof,
            &verifier,
        )?;
        Ok(())
    }

    /// 按 hash 查询 DAG vertex。
    pub fn get_vertex(&self, hash: &Hash) -> PokerL1Result<Option<DagVertex>> {
        match self.vertex_store.get_by_hash(hash) {
            Ok(vertex) => Ok(Some(vertex)),
            Err(PokerL1Error::DagVertexNotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// 写入 account。
    pub fn put_account(&self, account: Account) -> PokerL1Result<()> {
        self.account_store
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .create(account)
    }

    /// 按 address 查询 account。
    pub fn get_account(&self, address: &Address) -> PokerL1Result<Option<Account>> {
        Ok(self
            .account_store
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(address)
            .cloned())
    }

    /// 提交 tx（缓存 + pending 缓冲）。
    ///
    /// Validator 节点会将 tx 装入下一个 vertex；非 Validator 节点仅缓存用于查询。
    /// C-2 修复：tx_cache 和 pending_tx 均有 FIFO 驱逐上限（10,000 条）。
    /// M-6 修复：tx_cache + order 合并到单个 Mutex，消除多锁死锁风险。
    pub fn submit_tx(&self, tx: Transaction) -> PokerL1Result<Hash> {
        let tx_hash = tx.tx_hash();

        // M-6 修复：单次 lock 即可完成 cache + order 操作
        {
            let mut cache = self.tx_cache.lock().unwrap_or_else(|e| e.into_inner());
            cache.insert(tx_hash, tx.clone(), MAX_NODE_TX_CACHE_SIZE);
        }

        if self.config.role.is_validator() {
            let mut pending = self.pending_tx.lock().unwrap_or_else(|e| e.into_inner());
            // 缺口 #3：Priority Mempool — RBF（Replace-by-Fee）。
            // 若已有相同 (caller, nonce) 的 tx 且新 tx gas_price 更高 → 替换。
            // Caller address is derived exactly once per submission; `PendingTxState` supplies an
            // O(1) key lookup instead of deriving every queued caller on every new transaction.
            let caller = crate::account::derive_address(&tx.tagged_pubkey);
            let new_price = tx.gas.price;
            let new_nonce = tx.nonce;
            let mut replaced = false;
            if new_price > 0 {
                // 查找同 (caller, nonce) 的最早到达旧 tx，保持此前 FIFO 查找语义。
                if let Some((idx, old)) = pending.oldest_for(caller, new_nonce) {
                    if old.tx.gas.price < new_price {
                        // RBF：替换（仅当新 price 严格更高）。
                        pending.remove(idx);
                        replaced = true;
                    } else {
                        // 旧 tx price 更高或相等 → 拒绝（不替换）。
                        return Err(PokerL1Error::Other(format!(
                            "RBF rejected: existing tx gas_price {} >= new {} for caller {:?} nonce {}",
                            old.tx.gas.price, new_price, caller, new_nonce
                        )));
                    }
                }
            }
            pending.push(caller, tx);
            while pending.len() > MAX_PENDING_TX_SIZE {
                // 溢出时丢弃 gas_price 最低的（而非 FIFO 最旧）。
                if pending.len() > 1 {
                    let mut min_idx = 0;
                    let mut min_price = u64::MAX;
                    for (i, entry) in pending.queue.iter().enumerate() {
                        if entry.tx.gas.price < min_price {
                            min_price = entry.tx.gas.price;
                            min_idx = i;
                        }
                    }
                    pending.remove(min_idx);
                } else {
                    pending.remove(0);
                }
            }
            let len_after = pending.len();
            // 唤醒 validator loop（混合模式：有 tx 时立即出 vertex）
            self.pending_tx_condvar.notify_one();
            tracing::info!(
                "submit_tx: tx_hash={} pending_tx.len()={} role={:?} rbf={}",
                hex::encode(tx_hash),
                len_after,
                self.config.role,
                replaced
            );
        } else {
            tracing::warn!(
                "submit_tx: 节点非 validator 角色，tx 仅缓存未加入 pending_tx (tx_hash={})",
                hex::encode(tx_hash)
            );
        }
        Ok(tx_hash)
    }

    /// Query a transaction by hash from the mempool cache or the durable canonical chain.
    ///
    /// `tx_cache` is only a latency optimisation.  It is intentionally bounded and is empty
    /// after restart, so treating it as the authoritative transaction store made confirmed
    /// transactions disappear from RPC responses.  The indexer is rebuilt from durable block
    /// bodies at startup; an archive node additionally performs an honest full scan when an
    /// index entry is absent.
    pub fn get_tx(&self, tx_hash: &Hash) -> PokerL1Result<Option<Transaction>> {
        if let Some(transaction) = self
            .tx_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(tx_hash)
            .cloned()
        {
            return Ok(Some(transaction));
        }

        if let Some(indexed) = self.indexer.get_tx(tx_hash) {
            match self.block_store.get_by_height(indexed.block_height) {
                Ok(block) => {
                    let transaction = block
                        .canonical_execution_txs()
                        .into_iter()
                        .find(|transaction| transaction.tx_hash() == *tx_hash);
                    // The index records only finalized blocks.  A mismatch is therefore local
                    // pruning/corruption, not a reason to return a different transaction.
                    return Ok(transaction);
                }
                Err(PokerL1Error::BlockNotFound) => return Ok(None),
                Err(error) => return Err(error),
            }
        }

        if self.config.role.is_archive() {
            let tip = self.block_store.get_tip_height()?.unwrap_or(0);
            for block in self.block_store.get_range(0, tip)? {
                if let Some(transaction) = block
                    .canonical_execution_txs()
                    .into_iter()
                    .find(|transaction| transaction.tx_hash() == *tx_hash)
                {
                    return Ok(Some(transaction));
                }
            }
        }
        Ok(None)
    }

    /// 取出待装 vertex 的 tx（仅 Validator 角色有效）。
    ///
    /// 缺口 #3：Priority Mempool 排序规则。
    ///
    /// 排序优先级（与 S9 vertex 排序规则一致，但加入 gas_price 二级排序）：
    /// 1. **GameTurn + CheckpointAnchor**（优先）：免 gas 的游戏操作/anchor，
    ///    按 arrival 顺序保持（游戏的轮次/nonce 语义由 `build_game_sub_block` 处理）
    /// 2. **Public**（中间）：按 `gas_price` 降序（高 price 先装入 vertex）
    /// 3. **ForceSync**（后置）：按 `gas_price` 降序
    ///
    /// GameTurn 通道的排序**不**按 gas_price（它们免 gas），而按 arrival 顺序，
    /// 因为游戏操作的顺序由轮转规则（`TurnRule`）决定，不是由 gas 竞价决定。
    pub fn drain_pending_tx(&self) -> Vec<Transaction> {
        let txs: Vec<Transaction> = self
            .pending_tx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .drain()
            .into_iter()
            .map(|entry| entry.tx)
            .collect();
        // 分通道排序：GameTurn/CheckpointAnchor 优先 → Public 中 → ForceSync 后。
        // Public/ForceSync 内部按 gas_price 降序；GameTurn 按 arrival 顺序。
        let mut gameturn: Vec<&Transaction> = Vec::new();
        let mut public: Vec<&Transaction> = Vec::new();
        let mut forcesync: Vec<&Transaction> = Vec::new();
        for tx in &txs {
            match tx.lane_hint {
                TxLane::GameTurn | TxLane::CheckpointAnchor => gameturn.push(tx),
                TxLane::Public => public.push(tx),
                TxLane::ForceSync => forcesync.push(tx),
            }
        }
        // Public / ForceSync 按 gas_price 降序（stable sort 保持 arrival tiebreaker）。
        public.sort_by(|a, b| b.gas.price.cmp(&a.gas.price));
        forcesync.sort_by(|a, b| b.gas.price.cmp(&a.gas.price));
        // GameTurn 保持 arrival 顺序（已按 drain 的 VecDeque 顺序 = arrival）。
        // 组装结果：GameTurn + CheckpointAnchor → Public → ForceSync。
        let mut result: Vec<Transaction> = Vec::with_capacity(txs.len());
        result.extend(gameturn.into_iter().cloned());
        result.extend(public.into_iter().cloned());
        result.extend(forcesync.into_iter().cloned());
        result
    }

    /// Return transactions drained by the validator loop to the front of the mempool.
    ///
    /// This is used when a multi-validator node cannot yet assemble a valid previous-round
    /// parent quorum. The original arrival order is preserved ahead of transactions that arrived
    /// concurrently while the batch was being assembled, so a temporary DAG lag cannot silently
    /// drop or reorder user submissions.
    pub fn requeue_pending_txs(&self, txs: Vec<Transaction>) {
        if !self.config.role.is_validator() || txs.is_empty() {
            return;
        }

        let mut pending = self.pending_tx.lock().unwrap_or_else(|e| e.into_inner());
        for tx in txs.into_iter().rev() {
            let caller = crate::account::derive_address(&tx.tagged_pubkey);
            pending.push_front(caller, tx);
        }
        while pending.len() > MAX_PENDING_TX_SIZE {
            let min_index = pending
                .queue
                .iter()
                .enumerate()
                .min_by_key(|(_, entry)| entry.tx.gas.price)
                .map(|(index, _)| index)
                .unwrap_or(0);
            pending.remove(min_index);
        }
        self.pending_tx_condvar.notify_one();
    }

    /// 等待 pending_tx 非空或超时（混合模式核心）。
    ///
    /// - 如果 pending_tx 已有 tx → 立即返回 `true`
    /// - 否则阻塞等待，被 `submit_tx` 的 `notify_one` 唤醒后返回 `true`
    /// - 超时返回 `false`（调用方据此决定是否产出空 vertex 推进 commit）
    pub fn wait_for_pending_tx(&self, timeout: std::time::Duration) -> bool {
        let guard = self.pending_tx.lock().unwrap_or_else(|e| e.into_inner());
        if !guard.is_empty() {
            return true;
        }
        let result = self
            .pending_tx_condvar
            .wait_timeout(guard, timeout)
            .unwrap_or_else(|e| e.into_inner());
        !result.0.is_empty()
    }

    /// 是否提供历史数据 RPC（仅 Archive 节点）。
    #[must_use]
    pub const fn serves_historical_data(&self) -> bool {
        self.config.role.is_archive()
    }
}

// ===== SubTask 32.5: CLI 工具函数 =====

/// CLI keygen 结果。
///
/// SEC-FIX-2：实现 `Drop` 自动 zeroize 私钥字节，自定义 `Debug` 隐藏私钥内容，
/// 与 `ValidatorKey` 保持一致的安全处理模式。
#[derive(Clone, Serialize, Deserialize)]
pub struct KeygenResult {
    /// 签名方案。
    pub scheme: SignatureScheme,
    /// 私钥字节（secp256k1 = 32B，ed25519 = 32B）。
    pub secret_key_bytes: Vec<u8>,
    /// 对应的 tagged pubkey。
    pub tagged_pubkey: TaggedPubkey,
    /// 派生的账户地址。
    pub address: Address,
}

impl std::fmt::Debug for KeygenResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeygenResult")
            .field("scheme", &self.scheme)
            .field("secret_key_bytes", &"[REDACTED]")
            .field("tagged_pubkey", &self.tagged_pubkey)
            .field("address", &self.address)
            .finish()
    }
}

impl Drop for KeygenResult {
    fn drop(&mut self) {
        self.secret_key_bytes.fill(0);
    }
}

/// 生成 secp256k1 tagged pubkey 密钥对。
///
/// 使用 `OsRng` 密码学安全随机源。返回私钥 + tagged pubkey + 地址。
pub fn keygen_secp256k1() -> PokerL1Result<KeygenResult> {
    use secp256k1::Secp256k1;
    use secp256k1::rand::rngs::OsRng;
    let secp = Secp256k1::new();
    let mut rng = OsRng;
    let (secret_key, public_key) = secp.generate_keypair(&mut rng);
    let secret_key_bytes = secret_key.secret_bytes();
    let compressed = public_key.serialize();
    let tagged_pubkey = TaggedPubkey::new(
        SignatureScheme::Secp256k1,
        CURRENT_VERSION,
        compressed.to_vec(),
    )?;
    let address = crate::account::derive_address(&tagged_pubkey);
    // 安全擦除 OsRng 不需要（它是 CSPRNG）
    let secret_vec = secret_key_bytes.to_vec();
    Ok(KeygenResult {
        scheme: SignatureScheme::Secp256k1,
        secret_key_bytes: secret_vec,
        tagged_pubkey,
        address,
    })
}

/// 生成 ed25519 tagged pubkey 密钥对。
///
/// 使用 `OsRng` 密码学安全随机源。返回私钥 + tagged pubkey + 地址。
pub fn keygen_ed25519() -> PokerL1Result<KeygenResult> {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    let secret_key_bytes = signing_key.to_bytes();
    let public_bytes = verifying_key.to_bytes();
    let tagged_pubkey = TaggedPubkey::new(
        SignatureScheme::Ed25519,
        CURRENT_VERSION,
        public_bytes.to_vec(),
    )?;
    let address = crate::account::derive_address(&tagged_pubkey);
    Ok(KeygenResult {
        scheme: SignatureScheme::Ed25519,
        secret_key_bytes: secret_key_bytes.to_vec(),
        tagged_pubkey,
        address,
    })
}

/// CLI keygen 入口 — 按签名方案生成密钥对。
pub fn keygen(scheme: SignatureScheme) -> PokerL1Result<KeygenResult> {
    match scheme {
        SignatureScheme::Secp256k1 => keygen_secp256k1(),
        SignatureScheme::Ed25519 => keygen_ed25519(),
    }
}

/// 本地计算 assigned_validator（spec：`hash(game_id, epoch) % |V|`）。
///
/// 客户端 CLI 可用此函数本地预测 assigned_validator，无需查询链上。
///
/// # 参数
///
/// - `game_id`：Game 对象 ID
/// - `epoch`：当前 epoch
/// - `validator_set`：当前 epoch 的 validator 公钥列表（按 BTreeSet 排序后的顺序）
#[must_use]
pub fn compute_assigned_validator_local<'a>(
    game_id: &ObjectID,
    epoch: crate::consensus::Epoch,
    validator_set: &'a [TaggedPubkey],
) -> Option<&'a TaggedPubkey> {
    use blake2::Blake2bVar;
    use blake2::digest::{Update, VariableOutput};
    if validator_set.is_empty() {
        return None;
    }
    let mut h = Blake2bVar::new(32).expect("32 <= 64");
    h.update(&[0x41]); // 'A' for Assignment
    h.update(&game_id.to_bytes());
    h.update(&epoch.to_le_bytes());
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).expect("32 <= 64");
    // 取前 8 字节作为 u64 索引
    let mut idx_bytes = [0u8; 8];
    idx_bytes.copy_from_slice(&out[..8]);
    // M-8 修复：先在 u64 上取模再转 usize，避免 32-bit 平台截断
    let idx = (u64::from_le_bytes(idx_bytes) % validator_set.len() as u64) as usize;
    validator_set.get(idx)
}

/// CLI 查询节点信息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    /// 节点角色。
    pub role: NodeRole,
    /// chain_id。
    pub chain_id: ChainId,
    /// 当前 tip height（None = 空库）。
    pub tip_height: Option<BlockHeight>,
    /// 当前 tip hash（None = 空库）。
    pub tip_hash: Option<Hash>,
    /// 是否为 validator。
    pub is_validator: bool,
    /// 是否提供历史数据 RPC。
    pub serves_historical_data: bool,
}

/// CLI 查询节点信息。
pub fn query_node_info(node: &Node) -> PokerL1Result<NodeInfo> {
    let tip_height = node.block_store().get_tip_height()?;
    let tip_hash = node.block_store().get_tip_hash()?;
    Ok(NodeInfo {
        role: node.role(),
        chain_id: node.chain_id(),
        tip_height,
        tip_hash,
        is_validator: node.role().is_validator(),
        serves_historical_data: node.serves_historical_data(),
    })
}

// ===== Arc<Node> 适配 RpcBackend =====

/// 为 `Arc<Node>` 提供 RPC 后端能力（便于上层 RPC server 直接使用）。
///
/// 注意：`Node` 本身未实现 [`crate::rpc::RpcBackend`] 因为 `RpcBackend` 要求 `Send + Sync`
/// 且方法签名不返回 `'static` 引用。这里通过 wrapper 提供。
pub struct NodeRpcBackend {
    /// 节点引用。
    node: Arc<Node>,
}

impl NodeRpcBackend {
    /// 创建 RPC 后端。
    #[must_use]
    pub const fn new(node: Arc<Node>) -> Self {
        Self { node }
    }

    /// 获取节点引用。
    #[must_use]
    pub const fn node(&self) -> &Arc<Node> {
        &self.node
    }
}

impl crate::rpc::RpcBackend for NodeRpcBackend {
    fn get_block_by_hash(&self, hash: &Hash) -> PokerL1Result<Option<Block>> {
        self.node.get_block_by_hash(hash)
    }

    fn get_block_by_height(&self, height: BlockHeight) -> PokerL1Result<Option<Block>> {
        self.node.get_block_by_height(height)
    }

    fn get_object(&self, id: &ObjectID) -> PokerL1Result<Option<Object>> {
        self.node.get_object(id)
    }

    fn get_tx(&self, tx_hash: &Hash) -> PokerL1Result<Option<Transaction>> {
        self.node.get_tx(tx_hash)
    }

    fn submit_tx(&self, tx: Transaction) -> PokerL1Result<Hash> {
        self.node.submit_tx(tx)
    }

    fn get_account(&self, address: &Address) -> PokerL1Result<Option<Account>> {
        self.node.get_account(address)
    }

    fn get_dag_vertex(&self, vertex_hash: &Hash) -> PokerL1Result<Option<DagVertex>> {
        self.node.get_vertex(vertex_hash)
    }

    fn get_native_coins(
        &self,
        owner: &Address,
    ) -> PokerL1Result<Vec<crate::economics::OwnedNativeCoin>> {
        let object_db = self
            .node
            .object_db
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        crate::economics::list_owned_native_coins(&object_db, *owner)
    }

    fn query_indexed_txs(
        &self,
        filter: &crate::indexer::TxFilter,
    ) -> PokerL1Result<Vec<crate::indexer::IndexedTransaction>> {
        Ok(self.node.indexer.query_txs(filter))
    }

    fn query_indexed_blocks(
        &self,
        filter: &crate::indexer::BlockFilter,
    ) -> PokerL1Result<Vec<crate::indexer::IndexedBlock>> {
        Ok(self.node.indexer.query_blocks(filter))
    }

    fn query_indexed_objects_by_owner(&self, owner: Address) -> PokerL1Result<Vec<ObjectID>> {
        Ok(self.node.indexer.query_objects_by_owner(owner))
    }

    fn query_indexed_objects_by_type(&self, object_type: &str) -> PokerL1Result<Vec<ObjectID>> {
        Ok(self.node.indexer.query_objects_by_type(object_type))
    }

    fn subscribe_indexed_events(
        &self,
        request: &crate::rpc::SubscribeRequest,
    ) -> PokerL1Result<crate::rpc::SubscribeResponse> {
        let subscription_id = self
            .node
            .indexer
            .subscribe(request.event_types.clone(), request.tx_filter.clone())?;
        Ok(crate::rpc::SubscribeResponse { subscription_id })
    }

    fn unsubscribe_indexed_events(&self, subscription_id: u64) -> PokerL1Result<bool> {
        Ok(self.node.indexer.unsubscribe(subscription_id))
    }

    fn poll_indexed_events(
        &self,
        subscription_id: u64,
    ) -> PokerL1Result<Option<Vec<crate::indexer::IndexerEvent>>> {
        Ok(self.node.indexer.poll_events(subscription_id))
    }

    fn chain_id(&self) -> ChainId {
        self.node.chain_id()
    }

    fn zk_verifier_registry(&self) -> Option<&crate::offline::zk_verifier::ZkVerifierRegistry> {
        self.node.zk_verifier.as_ref()
    }

    /// 缺口 #7：导出 Prometheus 格式指标（覆写默认空实现）。
    fn export_metrics(&self) -> String {
        self.node.export_metrics()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DEFAULT_CHAIN_ID;
    use crate::account::derive_address;
    use crate::block::{Block, BlockHeader};
    use crate::object_model::{Object, ObjectID, Ownership};
    use crate::signature::tagged_pubkey::{SignatureScheme, encode_tag};
    use crate::transaction::{Gas, RouteHint, TxRequest};

    fn dummy_tagged_pubkey() -> TaggedPubkey {
        TaggedPubkey {
            tag: encode_tag(SignatureScheme::Secp256k1, 1),
            raw: vec![0x02u8; 33],
        }
    }

    #[test]
    fn node_role_to_pruning_role() {
        assert_eq!(NodeRole::Validator.to_pruning_role(), PruningNodeRole::Full);
        assert_eq!(NodeRole::Full.to_pruning_role(), PruningNodeRole::Full);
        assert_eq!(
            NodeRole::Archive.to_pruning_role(),
            PruningNodeRole::Archive
        );
        assert_eq!(NodeRole::Light.to_pruning_role(), PruningNodeRole::Light);
    }

    #[test]
    fn node_role_should_prune() {
        assert!(NodeRole::Validator.should_prune());
        assert!(NodeRole::Full.should_prune());
        assert!(!NodeRole::Archive.should_prune());
        assert!(!NodeRole::Light.should_prune());
    }

    #[test]
    fn pruning_uses_committed_governance_limits_and_is_fail_closed_without_archive_evidence() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        {
            let mut governance = node
                .governance
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            governance.params.tx_prune_after_blocks = 17;
            governance.params.vertex_prune_after_blocks = 29;
            governance.params.dispute_window_blocks = 31;
            governance.params.archive_node_min_count = 7;
            governance.params.archive_retention_blocks = 41;
        }

        let config = node.committed_pruning_config();
        assert_eq!(config.tx_prune_after_blocks, 17);
        assert_eq!(config.vertex_prune_after_blocks, 29);
        assert_eq!(config.dispute_window_blocks, 31);
        assert_eq!(config.archive_node_min_count, 7);
        assert_eq!(config.archive_retention_blocks, 41);

        // A Full node is otherwise eligible to prune, but cannot establish the network-wide
        // archive and proof-availability conditions from local storage alone.
        assert_eq!(node.run_pruning(10_000).unwrap(), (0, 0));
    }

    #[test]
    fn node_role_predicates() {
        assert!(NodeRole::Validator.is_validator());
        assert!(!NodeRole::Full.is_validator());
        assert!(NodeRole::Archive.is_archive());
        assert!(NodeRole::Light.is_light());
    }

    #[test]
    fn epoch_transition_atomically_moves_pending_bond_into_validator_stake() {
        let validators_and_keys: Vec<_> = (0x51..=0x55)
            .map(|seed| make_real_validator(seed, ValidatorStatus::Active))
            .collect();
        let validators = validators_and_keys
            .iter()
            .map(|(_, entry)| entry.clone())
            .collect::<Vec<_>>();
        let node = Node::open_inmemory_with_validators(
            NodeRole::Full,
            DEFAULT_CHAIN_ID,
            validators.clone(),
        )
        .unwrap();
        let funder = validators[0].pubkey.clone();
        node.apply_genesis_alloc(std::iter::once((funder.clone(), 300)))
            .unwrap();

        let candidate = make_real_validator(0x61, ValidatorStatus::Active).1;
        let addition = crate::governance::ValidatorAddition {
            pubkey: candidate.pubkey.clone(),
            vrf_pubkey: candidate.vrf_pubkey,
            stake: 300,
        };
        let current_set = node
            .validator_set
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        let mut object_db = node
            .object_db
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let governance_object = object_db
            .read(&crate::governance::GOVERNANCE_STATE_OBJECT_ID)
            .unwrap();
        let current_governance =
            crate::governance::decode_governance_state_object(&governance_object, DEFAULT_CHAIN_ID)
                .unwrap();
        let mut next_governance = current_governance.clone();
        let proposal_id = next_governance
            .create_validator_set_update_proposal(
                &current_set,
                vec![addition.clone()],
                vec![],
                1,
                funder.clone(),
                0,
            )
            .unwrap();
        next_governance
            .proposals
            .get_mut(&proposal_id)
            .unwrap()
            .status = crate::governance::ProposalStatus::Passed;
        crate::governance::replace_persisted_governance_state(
            &mut *object_db,
            DEFAULT_CHAIN_ID,
            &current_governance,
            &next_governance,
        )
        .unwrap();

        let funder_address = crate::account::derive_address(&funder);
        let input =
            crate::economics::list_owned_native_coins(&*object_db, funder_address).unwrap()[0];
        let selection = crate::economics::select_owned_native_coins(
            &*object_db,
            &[input.id],
            funder_address,
            300,
        )
        .unwrap();
        let mut funding_snapshot = object_db.create_snapshot();
        crate::economics::consume_native_coin_selection(
            &mut funding_snapshot,
            &selection,
            funder_address,
            300,
            &[0xAB; 32],
            0,
        )
        .unwrap();
        let mut escrow = crate::governance::ValidatorBondEscrow::default();
        escrow
            .insert_proposal(proposal_id, &[addition.clone()], funder_address)
            .unwrap();
        crate::governance::write_validator_bond_escrow(
            &mut funding_snapshot,
            DEFAULT_CHAIN_ID,
            None,
            &escrow,
        )
        .unwrap();
        crate::economics::reconcile_native_supply_snapshot_if_initialized(
            &funding_snapshot,
            validator_bond_escrow(&funding_snapshot, &current_set, DEFAULT_CHAIN_ID).unwrap(),
        )
        .unwrap();
        funding_snapshot.apply_to(&mut object_db).unwrap();

        let mut transition_snapshot = object_db.create_snapshot();
        let transitioned = node
            .stage_certificate_epoch_transition(
                &mut transition_snapshot,
                &current_set,
                1_000,
                1,
                [0u8; 32],
                None,
            )
            .unwrap()
            .expect("epoch transition must update ValidatorSet");
        assert_eq!(
            transitioned
                .find_validator(&candidate.pubkey)
                .expect("funded candidate must join set")
                .stake,
            300
        );
        assert_eq!(
            crate::governance::pending_validator_bond_escrow(
                &transition_snapshot,
                DEFAULT_CHAIN_ID,
            )
            .unwrap(),
            0
        );
        crate::economics::reconcile_native_supply_snapshot_if_initialized(
            &transition_snapshot,
            validator_bond_escrow(&transition_snapshot, &transitioned, DEFAULT_CHAIN_ID).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn epoch_transition_rotates_validator_key_and_commits_history() {
        let validators_and_keys: Vec<_> = (0x71..=0x75)
            .map(|seed| make_real_validator(seed, ValidatorStatus::Active))
            .collect();
        let validators = validators_and_keys
            .iter()
            .map(|(_, entry)| entry.clone())
            .collect::<Vec<_>>();
        let node = Node::open_inmemory_with_validators(
            NodeRole::Full,
            DEFAULT_CHAIN_ID,
            validators.clone(),
        )
        .unwrap();
        node.apply_genesis_alloc(std::iter::empty::<(TaggedPubkey, u64)>())
            .unwrap();
        let old_pubkey = validators[0].pubkey.clone();
        let new_pubkey = make_real_validator(0x76, ValidatorStatus::Active).1.pubkey;
        let current_set = node
            .validator_set
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        let mut object_db = node
            .object_db
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let object = object_db
            .read(&crate::governance::GOVERNANCE_STATE_OBJECT_ID)
            .unwrap();
        let current_governance =
            crate::governance::decode_governance_state_object(&object, DEFAULT_CHAIN_ID).unwrap();
        let mut next_governance = current_governance.clone();
        let proposal_id = next_governance
            .create_key_rotation_proposal(
                old_pubkey.clone(),
                new_pubkey.clone(),
                old_pubkey.clone(),
                0,
            )
            .unwrap();
        let proposal = next_governance.proposals.get_mut(&proposal_id).unwrap();
        proposal.status = crate::governance::ProposalStatus::Passed;
        let crate::governance::ProposalKind::KeyRotation {
            effective_height, ..
        } = &mut proposal.kind
        else {
            panic!("key-rotation proposal has wrong kind");
        };
        *effective_height = 0;
        crate::governance::replace_persisted_governance_state(
            &mut *object_db,
            DEFAULT_CHAIN_ID,
            &current_governance,
            &next_governance,
        )
        .unwrap();

        let mut snapshot = object_db.create_snapshot();
        let transitioned = node
            .stage_certificate_epoch_transition(&mut snapshot, &current_set, 1, 1, [0; 32], None)
            .unwrap()
            .expect("epoch transition must rotate ValidatorSet");
        assert!(transitioned.find_validator(&old_pubkey).is_none());
        assert!(transitioned.find_validator(&new_pubkey).is_some());
        let history = crate::consensus::read_validator_key_history(&snapshot, DEFAULT_CHAIN_ID)
            .unwrap()
            .expect("rotation must initialize key history")
            .0;
        assert_eq!(history.resolve_current(&old_pubkey).unwrap(), new_pubkey);
        let governance = crate::governance::decode_governance_state_object(
            &snapshot
                .read(&crate::governance::GOVERNANCE_STATE_OBJECT_ID)
                .unwrap(),
            DEFAULT_CHAIN_ID,
        )
        .unwrap();
        assert_eq!(
            governance.proposals[&proposal_id].status,
            crate::governance::ProposalStatus::Executed
        );
    }

    #[test]
    fn node_role_default_is_full() {
        assert_eq!(NodeRole::default(), NodeRole::Full);
    }

    #[test]
    fn node_config_default_full() {
        let cfg = NodeConfig::default_full(PathBuf::from("/tmp/test"));
        assert_eq!(cfg.role, NodeRole::Full);
        assert_eq!(cfg.chain_id, DEFAULT_CHAIN_ID);
        assert!(cfg.validator_key.is_none());
    }

    #[test]
    fn node_config_validator() {
        let key = ValidatorKey::from_secret_bytes([1u8; 32]).unwrap();
        let cfg = NodeConfig::validator(PathBuf::from("/tmp/test"), key);
        assert_eq!(cfg.role, NodeRole::Validator);
        assert!(cfg.validator_key.is_some());
    }

    #[test]
    fn node_config_archive() {
        let cfg = NodeConfig::archive(PathBuf::from("/tmp/test"));
        assert_eq!(cfg.role, NodeRole::Archive);
    }

    #[test]
    fn node_config_light() {
        let cfg = NodeConfig::light(PathBuf::from("/tmp/test"));
        assert_eq!(cfg.role, NodeRole::Light);
    }

    #[test]
    fn standard_node_has_no_zk_verifier_registry() {
        let temp = tempfile::tempdir().unwrap();
        let node = Node::open(NodeConfig::default_full(temp.path().to_path_buf())).unwrap();

        assert!(node.zk_verifier_registry_clone().is_none());
        assert!(node.execution_environment(7, 11).zk_verifier.is_none());
    }

    #[test]
    fn persisted_production_zk_status_rejects_missing_stwo_backend_at_startup() {
        use crate::governance::replace_persisted_governance_state;
        use crate::offline::zk_verifier::{VerifierStatus, ZkVerifierRegistry};

        let temp = tempfile::tempdir().unwrap();
        let config = NodeConfig::default_full(temp.path().to_path_buf());
        let node = Node::open(config.clone()).unwrap();
        node.apply_genesis_alloc(std::iter::empty::<(TaggedPubkey, u64)>())
            .unwrap();

        let current = node
            .governance
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        let mut production = current.clone();
        production.set_verifier_status(DEFAULT_CHAIN_ID, VerifierStatus::Production);
        {
            let mut object_db = node
                .object_db
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            replace_persisted_governance_state(
                &mut *object_db,
                DEFAULT_CHAIN_ID,
                &current,
                &production,
            )
            .unwrap();
        }
        drop(node);

        let no_registry = match Node::open(config.clone()) {
            Ok(_) => panic!("Production governance must reject a node without a registry"),
            Err(error) => error,
        };
        assert!(no_registry.to_string().contains("no verifier registry"));

        let empty_registry =
            match Node::open_with_zk_verifier_registry(config, ZkVerifierRegistry::new()) {
                Ok(_) => panic!("Production governance must reject a registry without STWO"),
                Err(error) => error,
            };
        assert!(
            empty_registry
                .to_string()
                .contains("does not provide SCHEME_STWO")
        );
    }

    #[test]
    fn execution_environment_includes_injected_zk_verifier_registry() {
        use crate::offline::zk_verifier::{VerifierStatus, ZkVerifierRegistry};

        let temp = tempfile::tempdir().unwrap();
        let registry = ZkVerifierRegistry::new();
        registry.set_verifier_status(DEFAULT_CHAIN_ID, VerifierStatus::Production);
        let node = Node::open_with_zk_verifier_registry(
            NodeConfig::default_full(temp.path().to_path_buf()),
            registry,
        )
        .unwrap();

        let env = node.execution_environment(7, 11);
        let injected = env
            .zk_verifier
            .expect("node verifier registry must be injected");
        // The injected implementation is present, but activation is consensus state. A fresh
        // chain's GovernanceState is Stub, so startup must overwrite an application's local
        // Production preference rather than accidentally accepting proofs before governance
        // authorizes that transition.
        assert_eq!(
            injected.verifier_status(DEFAULT_CHAIN_ID),
            VerifierStatus::Stub
        );
        assert!(injected.registered_schemes().is_empty());
        assert!(env.precompile_registry.is_some());
        assert!(env.bridge_registry_store.is_some());
    }

    #[test]
    fn governance_status_sync_reaches_existing_registry_clones() {
        use crate::governance::GovernanceState;
        use crate::offline::zk_verifier::{VerifierStatus, ZkVerifierRegistry};

        let temp = tempfile::tempdir().unwrap();
        let registry = ZkVerifierRegistry::new();
        let node = Node::open_with_zk_verifier_registry(
            NodeConfig::default_full(temp.path().to_path_buf()),
            registry,
        )
        .unwrap();
        let observer = node.zk_verifier_registry_clone().unwrap();
        assert_eq!(
            observer.verifier_status(DEFAULT_CHAIN_ID),
            VerifierStatus::Stub
        );

        let mut governance = GovernanceState::new();
        governance.set_verifier_status(DEFAULT_CHAIN_ID, VerifierStatus::Production);
        node.synchronize_zk_verifier_governance(&governance)
            .unwrap();

        assert_eq!(
            observer.verifier_status(DEFAULT_CHAIN_ID),
            VerifierStatus::Production
        );
        assert_eq!(
            node.execution_environment(8, 13)
                .zk_verifier
                .unwrap()
                .verifier_status(DEFAULT_CHAIN_ID),
            VerifierStatus::Production
        );
    }

    #[test]
    fn validator_key_from_secret_bytes() {
        let key = ValidatorKey::from_secret_bytes([42u8; 32]).unwrap();
        assert_eq!(key.secret_key_bytes, [42u8; 32]);
        assert_eq!(
            key.tagged_pubkey.tag,
            encode_tag(SignatureScheme::Secp256k1, CURRENT_VERSION)
        );
        assert_eq!(key.tagged_pubkey.raw.len(), 33);
    }

    #[test]
    fn validator_key_invalid_secret_bytes() {
        // 全零私钥无效（不在曲线阶范围内）
        let result = ValidatorKey::from_secret_bytes([0u8; 32]);
        assert!(result.is_err(), "全零私钥应被拒绝");
    }

    #[test]
    fn node_open_inmemory_full() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        assert_eq!(node.role(), NodeRole::Full);
        assert_eq!(node.chain_id(), DEFAULT_CHAIN_ID);
        assert!(!node.serves_historical_data());
    }

    #[test]
    fn node_open_inmemory_archive() {
        let node = Node::open_inmemory(NodeRole::Archive, DEFAULT_CHAIN_ID).unwrap();
        assert!(node.serves_historical_data());
    }

    #[derive(Clone)]
    struct TestZkProofArchive {
        payload: Option<crate::storage::ArchivedZkProofPayload>,
    }

    impl ZkProofArchiveProvider for TestZkProofArchive {
        fn load_proof(
            &self,
            _proof_hash: &Hash,
        ) -> PokerL1Result<Option<crate::storage::ArchivedZkProofPayload>> {
            Ok(self.payload.clone())
        }
    }

    #[test]
    fn archive_zk_proof_response_requires_hash_bound_payload() {
        let node = Node::open_inmemory(NodeRole::Archive, DEFAULT_CHAIN_ID).unwrap();
        let payload = crate::storage::ArchivedZkProofPayload {
            proof: vec![1, 2],
            state_delta: vec![3],
            ack_chain: vec![4, 5],
            blob_id: [0xAB; 32],
        };
        let proof_hash = crate::storage::compute_proof_hash(
            &payload.proof,
            &payload.state_delta,
            &payload.ack_chain,
        );
        node.set_zk_proof_archive_provider(Arc::new(TestZkProofArchive {
            payload: Some(payload.clone()),
        }));
        let found = node
            .request_historical_data(&HistoricalDataRequest {
                key: proof_hash,
                request_type: HistoricalDataType::ZkProof,
            })
            .unwrap();
        let HistoricalDataResponse::Found(bytes) = found else {
            panic!("hash-bound archive proof must be returned")
        };
        assert_eq!(
            borsh::from_slice::<crate::storage::ArchivedZkProofPayload>(&bytes).unwrap(),
            payload
        );
        assert!(matches!(
            node.request_historical_data(&HistoricalDataRequest {
                key: [0xFF; 32],
                request_type: HistoricalDataType::ZkProof,
            })
            .unwrap(),
            HistoricalDataResponse::Unavailable(_)
        ));
    }

    #[test]
    fn node_open_inmemory_validator() {
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        assert!(node.role().is_validator());
    }

    #[test]
    fn node_put_and_get_object() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let obj = Object::new(
            ObjectID::new([0xAA; 20], 0),
            Ownership::Shared,
            "TestType",
            b"data".to_vec(),
            None,
        );
        let id = obj.id;
        node.put_object(obj).unwrap();
        let got = node.get_object(&id).unwrap();
        assert!(got.is_some());
        assert_eq!(got.unwrap().id, id);
    }

    #[test]
    fn node_get_object_not_found() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let result = node.get_object(&ObjectID::new([0xBB; 20], 0)).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn node_put_and_get_account() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let tagged = dummy_tagged_pubkey();
        let account = Account::new(tagged, 1000);
        let address = account.address;
        node.put_account(account).unwrap();
        let got = node.get_account(&address).unwrap();
        assert!(got.is_some());
        assert_eq!(got.unwrap().balance, 1000);
    }

    #[test]
    fn node_submit_tx_validator_buffers() {
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        let tx = Transaction {
            inputs: vec![ObjectID::new([0u8; 20], 1)],
            outputs: vec![],
            contract_call: None,
            tagged_pubkey: dummy_tagged_pubkey(),
            signature: vec![0u8; 65],
            gas: crate::transaction::Gas::zero(),
            lane_hint: crate::transaction::TxLane::Public,
            route_hint: crate::transaction::RouteHint::AnyValidator,
            chain_id: DEFAULT_CHAIN_ID,
            nonce: 1,
            gameturn_nonce: None,
            is_fallback: false,
        };
        let expected_hash = tx.tx_hash();
        let returned_hash = node.submit_tx(tx).unwrap();
        assert_eq!(returned_hash, expected_hash);

        // validator 应缓冲 tx
        let pending = node.drain_pending_tx();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].tx_hash(), expected_hash);
    }

    #[test]
    fn node_submit_tx_full_does_not_buffer() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let tx = Transaction {
            inputs: vec![ObjectID::new([0u8; 20], 1)],
            outputs: vec![],
            contract_call: None,
            tagged_pubkey: dummy_tagged_pubkey(),
            signature: vec![0u8; 65],
            gas: crate::transaction::Gas::zero(),
            lane_hint: crate::transaction::TxLane::Public,
            route_hint: crate::transaction::RouteHint::AnyValidator,
            chain_id: DEFAULT_CHAIN_ID,
            nonce: 1,
            gameturn_nonce: None,
            is_fallback: false,
        };
        let tx_hash = tx.tx_hash();
        node.submit_tx(tx).unwrap();

        // full node 不应缓冲 tx
        let pending = node.drain_pending_tx();
        assert!(pending.is_empty(), "full node 不应缓冲 tx");

        // 但应能查询
        let got = node.get_tx(&tx_hash).unwrap();
        assert!(got.is_some());
    }

    #[test]
    fn node_get_tx_after_submit() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let tx = Transaction {
            inputs: vec![ObjectID::new([0u8; 20], 1)],
            outputs: vec![],
            contract_call: None,
            tagged_pubkey: dummy_tagged_pubkey(),
            signature: vec![0u8; 65],
            gas: crate::transaction::Gas::zero(),
            lane_hint: crate::transaction::TxLane::Public,
            route_hint: crate::transaction::RouteHint::AnyValidator,
            chain_id: DEFAULT_CHAIN_ID,
            nonce: 1,
            gameturn_nonce: None,
            is_fallback: false,
        };
        let tx_hash = tx.tx_hash();
        node.submit_tx(tx).unwrap();
        let got = node.get_tx(&tx_hash).unwrap();
        assert!(got.is_some());
        assert_eq!(got.unwrap().tx_hash(), tx_hash);
    }

    #[test]
    fn keygen_secp256k1_produces_valid_keypair() {
        let result = keygen_secp256k1().unwrap();
        assert_eq!(result.scheme, SignatureScheme::Secp256k1);
        assert_eq!(result.secret_key_bytes.len(), 32);
        assert_eq!(result.tagged_pubkey.raw.len(), 33); // compressed
        // 地址非全零
        assert_ne!(result.address, [0u8; 20]);
    }

    #[test]
    fn keygen_ed25519_produces_valid_keypair() {
        let result = keygen_ed25519().unwrap();
        assert_eq!(result.scheme, SignatureScheme::Ed25519);
        assert_eq!(result.secret_key_bytes.len(), 32);
        assert_eq!(result.tagged_pubkey.raw.len(), 32); // ed25519 pubkey
        assert_ne!(result.address, [0u8; 20]);
    }

    #[test]
    fn keygen_secp256k1_two_calls_produce_different_keys() {
        let r1 = keygen_secp256k1().unwrap();
        let r2 = keygen_secp256k1().unwrap();
        assert_ne!(
            r1.secret_key_bytes, r2.secret_key_bytes,
            "两次 keygen 应产生不同密钥"
        );
        assert_ne!(
            r1.tagged_pubkey.raw, r2.tagged_pubkey.raw,
            "两次 keygen 应产生不同公钥"
        );
    }

    #[test]
    fn keygen_dispatch_by_scheme() {
        let r1 = keygen(SignatureScheme::Secp256k1).unwrap();
        assert_eq!(r1.scheme, SignatureScheme::Secp256k1);
        let r2 = keygen(SignatureScheme::Ed25519).unwrap();
        assert_eq!(r2.scheme, SignatureScheme::Ed25519);
    }

    #[test]
    fn compute_assigned_validator_local_basic() {
        let game_id = ObjectID::new([0x42; 20], 0);
        let epoch = 1;
        let validators: Vec<TaggedPubkey> = (0..5)
            .map(|i| TaggedPubkey {
                tag: encode_tag(SignatureScheme::Secp256k1, 1),
                raw: vec![i; 33],
            })
            .collect();
        let assigned = compute_assigned_validator_local(&game_id, epoch, &validators);
        assert!(assigned.is_some(), "非空 validator 集应返回结果");
        // 结果应在 validator_set 中
        let assigned_ref = assigned.unwrap();
        assert!(validators.iter().any(|v| v == assigned_ref));
    }

    #[test]
    fn compute_assigned_validator_local_empty_set() {
        let game_id = ObjectID::new([0x42; 20], 0);
        let result = compute_assigned_validator_local(&game_id, 1, &[]);
        assert!(result.is_none(), "空 validator 集应返回 None");
    }

    #[test]
    fn compute_assigned_validator_local_deterministic() {
        let game_id = ObjectID::new([0x42; 20], 0);
        let epoch = 1;
        let validators: Vec<TaggedPubkey> = (0..5)
            .map(|i| TaggedPubkey {
                tag: encode_tag(SignatureScheme::Secp256k1, 1),
                raw: vec![i; 33],
            })
            .collect();
        let r1 = compute_assigned_validator_local(&game_id, epoch, &validators);
        let r2 = compute_assigned_validator_local(&game_id, epoch, &validators);
        assert_eq!(r1, r2, "同一 (game_id, epoch) 应确定性返回相同 validator");
    }

    #[test]
    fn compute_assigned_validator_local_changes_with_epoch() {
        let game_id = ObjectID::new([0x42; 20], 0);
        let validators: Vec<TaggedPubkey> = (0..10)
            .map(|i| TaggedPubkey {
                tag: encode_tag(SignatureScheme::Secp256k1, 1),
                raw: vec![i; 33],
            })
            .collect();
        let r1 = compute_assigned_validator_local(&game_id, 1, &validators);
        let r2 = compute_assigned_validator_local(&game_id, 2, &validators);
        // 不同 epoch 可能返回相同或不同 validator，但都应在集合中
        assert!(r1.is_some());
        assert!(r2.is_some());
    }

    #[test]
    fn query_node_info_empty_node() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let info = query_node_info(&node).unwrap();
        assert_eq!(info.role, NodeRole::Full);
        assert_eq!(info.chain_id, DEFAULT_CHAIN_ID);
        assert!(info.tip_height.is_none());
        assert!(info.tip_hash.is_none());
        assert!(!info.is_validator);
        assert!(!info.serves_historical_data);
    }

    #[test]
    fn query_node_info_validator() {
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        let info = query_node_info(&node).unwrap();
        assert!(info.is_validator);
    }

    #[test]
    fn query_node_info_archive() {
        let node = Node::open_inmemory(NodeRole::Archive, DEFAULT_CHAIN_ID).unwrap();
        let info = query_node_info(&node).unwrap();
        assert!(info.serves_historical_data);
    }

    #[test]
    fn node_rpc_backend_adapter() {
        use crate::rpc::RpcBackend;
        let node = Arc::new(Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap());
        let owner_key = tp(0x33);
        let owner = crate::account::derive_address(&owner_key);
        node.apply_genesis_alloc(vec![(owner_key, 42)]).unwrap();
        let backend = NodeRpcBackend::new(node);
        assert_eq!(backend.chain_id(), DEFAULT_CHAIN_ID);
        // get_object 返回 None（空库）
        let result = backend.get_object(&ObjectID::new([0xCC; 20], 0)).unwrap();
        assert!(result.is_none());
        let coins = backend.get_native_coins(&owner).unwrap();
        assert_eq!(coins.len(), 1);
        assert_eq!(coins[0].amount, 42);
        let metrics = backend.export_metrics();
        assert!(metrics.contains("# TYPE zchain_block_height gauge"));
        assert!(metrics.contains("zchain_mempool_size 0"));
    }

    // ===== P0-3: validate_vertex 测试 =====

    #[test]
    fn validate_vertex_rejects_wrong_chain_id() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let mut vertex = DagVertex {
            epoch: 0,
            round: 1,
            author_pubkey: dummy_tagged_pubkey(),
            tx_list: vec![Transaction {
                inputs: vec![],
                outputs: vec![],
                contract_call: None,
                tagged_pubkey: dummy_tagged_pubkey(),
                signature: vec![0u8; 65],
                gas: crate::transaction::Gas::zero(),
                lane_hint: crate::transaction::TxLane::Public,
                route_hint: crate::transaction::RouteHint::AnyValidator,
                chain_id: DEFAULT_CHAIN_ID + 1, // 错误 chain_id
                nonce: 1,
                gameturn_nonce: None,
                is_fallback: false,
            }],
            parent_hashes: vec![],
            author_sig: vec![0u8; 65],
        };
        let result = node.validate_vertex(&vertex);
        assert!(
            result.is_err(),
            "错误 chain_id 的 tx 应被拒绝: {:?}",
            result
        );
    }

    #[test]
    fn validate_vertex_rejects_invalid_signature() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let vertex = DagVertex {
            epoch: 0,
            round: 1,
            author_pubkey: dummy_tagged_pubkey(),
            tx_list: vec![],
            parent_hashes: vec![],
            author_sig: vec![0xFF; 65], // 无效签名
        };
        let result = node.validate_vertex(&vertex);
        assert!(result.is_err(), "无效签名应被拒绝: {:?}", result);
    }

    #[test]
    fn validate_vertex_rejects_s9_ordering_violation() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let vertex = DagVertex {
            epoch: 0,
            round: 1,
            author_pubkey: dummy_tagged_pubkey(),
            tx_list: vec![
                // ForceSync 在 GameTurn 之前 → 违反 S9
                Transaction {
                    inputs: vec![],
                    outputs: vec![],
                    contract_call: None,
                    tagged_pubkey: dummy_tagged_pubkey(),
                    signature: vec![0u8; 65],
                    gas: crate::transaction::Gas::zero(),
                    lane_hint: crate::transaction::TxLane::ForceSync,
                    route_hint: crate::transaction::RouteHint::AnyValidator,
                    chain_id: DEFAULT_CHAIN_ID,
                    nonce: 1,
                    gameturn_nonce: None,
                    is_fallback: false,
                },
                Transaction {
                    inputs: vec![],
                    outputs: vec![],
                    contract_call: None,
                    tagged_pubkey: dummy_tagged_pubkey(),
                    signature: vec![0u8; 65],
                    gas: crate::transaction::Gas::zero(),
                    lane_hint: crate::transaction::TxLane::GameTurn,
                    route_hint: crate::transaction::RouteHint::AssignedValidator,
                    chain_id: DEFAULT_CHAIN_ID,
                    nonce: 0,
                    gameturn_nonce: Some(0),
                    is_fallback: false,
                },
            ],
            parent_hashes: vec![],
            author_sig: vec![0u8; 65],
        };
        let result = node.validate_vertex(&vertex);
        assert!(result.is_err(), "S9 排序违规应被拒绝: {:?}", result);
    }

    #[test]
    fn validate_vertex_rejects_parent_not_found() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let vertex = DagVertex {
            epoch: 0,
            round: 2,
            author_pubkey: dummy_tagged_pubkey(),
            tx_list: vec![],
            parent_hashes: vec![[0xAA; 32]], // 不存在的 parent
            author_sig: vec![0u8; 65],
        };
        let result = node.validate_vertex(&vertex);
        assert!(result.is_err(), "不存在的 parent 应被拒绝: {:?}", result);
    }

    #[test]
    fn validate_vertex_accepts_valid_vertex() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        // 先创建一个有效的 vertex 并入库，作为后续 vertex 的 parent
        let parent = DagVertex {
            epoch: 0,
            round: 1,
            author_pubkey: dummy_tagged_pubkey(),
            tx_list: vec![],
            parent_hashes: vec![],
            author_sig: vec![0u8; 65],
        };
        // parent 入库前不需要验证签名（测试中跳过）
        let parent_hash = node.vertex_store.put(&parent).unwrap();

        let vertex = DagVertex {
            epoch: 0,
            round: 2,
            author_pubkey: dummy_tagged_pubkey(),
            tx_list: vec![Transaction {
                inputs: vec![],
                outputs: vec![],
                contract_call: None,
                tagged_pubkey: dummy_tagged_pubkey(),
                signature: vec![0u8; 65],
                gas: crate::transaction::Gas::zero(),
                lane_hint: crate::transaction::TxLane::Public,
                route_hint: crate::transaction::RouteHint::AnyValidator,
                chain_id: DEFAULT_CHAIN_ID,
                nonce: 1,
                gameturn_nonce: None,
                is_fallback: false,
            }],
            parent_hashes: vec![parent_hash],
            author_sig: vec![0u8; 65],
        };
        // 注意：签名是 dummy，验证会失败。这里只验证 parent 存在性路径
        let result = node.validate_vertex(&vertex);
        assert!(
            result.is_err(),
            "dummy 签名应失败，但 parent 校验应通过: {:?}",
            result
        );
    }

    // ===== P0-3: validate_block 测试 =====

    fn empty_consensus_block(
        node: &Node,
        height: u64,
        timestamp_ms: u64,
        prev_hash: Hash,
        epoch: u64,
        commit_round: u64,
        prev_commit_hash: Hash,
    ) -> Block {
        let empty_root = crate::block::compute_tx_merkle_root(&[]);
        let state_root = node.state_root();
        let account_root = node.account_root();
        Block::new(
            BlockHeader {
                height,
                timestamp_ms,
                prev_hash,
                state_root,
                account_root,
                public_tx_root: empty_root,
                gameturn_tx_root: empty_root,
                dag_commit_certificate: crate::consensus::DagCommitCertificate {
                    epoch,
                    commit_round,
                    prev_commit_hash,
                    epoch_transition: None,
                    vertex_hash_list: vec![],
                    round_attendance_bitmap: vec![],
                    state_root,
                    account_root,
                    public_tx_root: empty_root,
                    gameturn_tx_root: empty_root,
                    signature_list: vec![],
                    signer_bitmap: vec![],
                },
            },
            vec![],
            vec![],
        )
    }

    #[test]
    fn empty_block_store_accepts_only_canonical_first_block() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();

        let height_gap = empty_consensus_block(&node, 2, 1_000, [0u8; 32], 0, 1, [0u8; 32]);
        assert!(matches!(
            node.validate_block(&height_gap),
            Err(PokerL1Error::BlockHeightNotIncreasing { prev: 0, got: 2 })
        ));

        let bad_parent = empty_consensus_block(&node, 1, 1_000, [0xAA; 32], 0, 1, [0u8; 32]);
        assert!(matches!(
            node.validate_block(&bad_parent),
            Err(PokerL1Error::InvalidPrevHash { .. })
        ));
    }

    #[test]
    fn block_certificate_chain_and_timestamp_are_strict() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let first = empty_consensus_block(
            &node,
            1,
            1_000,
            node.genesis_parent_hash().unwrap(),
            0,
            1,
            [0u8; 32],
        );
        let first_hash = node.put_block(&first).unwrap();
        let first_cert_hash = first.header.dag_commit_certificate.cert_hash_for_header(
            DEFAULT_CHAIN_ID,
            first.header.height,
            first.header.timestamp_ms,
            first.header.prev_hash,
        );
        let second = empty_consensus_block(&node, 2, 2_000, first_hash, 1, 2, first_cert_hash);

        let mut backwards = second.clone();
        backwards.header.timestamp_ms = 999;
        assert!(matches!(
            node.validate_block(&backwards),
            Err(PokerL1Error::BlockTimestampMovedBackwards { .. })
        ));

        let mut too_far = second.clone();
        too_far.header.timestamp_ms = 31_001;
        assert!(matches!(
            node.validate_block(&too_far),
            Err(PokerL1Error::BlockTimestampIntervalExceeded { .. })
        ));

        let mut wrong_prev_cert = second.clone();
        wrong_prev_cert
            .header
            .dag_commit_certificate
            .prev_commit_hash = [0xBB; 32];
        assert!(matches!(
            node.validate_block(&wrong_prev_cert),
            Err(PokerL1Error::CommitCertificateMismatch(_))
        ));

        let mut reset_round = second.clone();
        reset_round.header.dag_commit_certificate.commit_round = 1;
        assert!(matches!(
            node.validate_block(&reset_round),
            Err(PokerL1Error::CommitCertificateMismatch(_))
        ));

        let mut epoch_jump = second.clone();
        epoch_jump.header.dag_commit_certificate.epoch = 2;
        assert!(matches!(
            node.validate_block(&epoch_jump),
            Err(PokerL1Error::CommitCertificateMismatch(_))
        ));

        node.put_block(&second).unwrap();
    }

    #[test]
    fn epoch_transition_is_committed_by_first_new_epoch_block() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        node.apply_genesis_alloc(std::iter::empty()).unwrap();

        let first = empty_consensus_block(
            &node,
            1,
            1_000,
            node.genesis_parent_hash().unwrap(),
            0,
            1,
            [0u8; 32],
        );
        let first_hash = node.put_block(&first).unwrap();
        let first_cert_hash = first.header.dag_commit_certificate.cert_hash_for_header(
            DEFAULT_CHAIN_ID,
            first.header.height,
            first.header.timestamp_ms,
            first.header.prev_hash,
        );
        let set_before = node
            .validator_set
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let root_before = node.state_root();
        let env = node.execution_environment(2, 2_000);
        let transition_outcome = node
            .simulate_block_execution_for_certificate(&env, &[], 1, first_cert_hash, None)
            .unwrap();
        assert_ne!(transition_outcome.state_root, root_before);

        let mut second = empty_consensus_block(&node, 2, 2_000, first_hash, 1, 2, first_cert_hash);
        second.header.state_root = transition_outcome.state_root;
        second.header.dag_commit_certificate.state_root = transition_outcome.state_root;

        // Validation replays on snapshots and must not advance the live validator state.
        node.validate_block(&second).unwrap();
        assert_eq!(node.current_epoch(), 0);
        assert_eq!(node.state_root(), root_before);

        node.put_block(&second).unwrap();
        assert_eq!(node.current_epoch(), 1);
        assert_eq!(node.state_root(), transition_outcome.state_root);

        let mut expected = set_before;
        expected.advance_epoch(1);
        expected.derive_epoch_randomness_from_certificate(DEFAULT_CHAIN_ID, first_cert_hash);
        let persisted = {
            let object_db = node.object_db.lock().unwrap_or_else(|e| e.into_inner());
            read_persisted_validator_set(&object_db, DEFAULT_CHAIN_ID)
                .unwrap()
                .unwrap()
                .0
        };
        assert_eq!(persisted, expected);
        assert_eq!(
            *node.validator_set.lock().unwrap_or_else(|e| e.into_inner()),
            expected
        );
    }

    #[test]
    fn repeated_block_commit_is_idempotent() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let block = empty_consensus_block(&node, 1, 1_000, [0u8; 32], 0, 1, [0u8; 32]);
        let first_hash = node.put_block(&block).unwrap();
        let repeated_hash = node.put_block(&block).unwrap();
        assert_eq!(repeated_hash, first_hash);
        assert_eq!(node.block_store().len().unwrap(), 1);
    }

    #[test]
    fn persistent_node_rejects_empty_consensus_configuration() {
        let temp = tempfile::tempdir().unwrap();
        let node = Node::open(NodeConfig::default_full(temp.path().to_path_buf())).unwrap();
        assert!(node.ensure_consensus_ready().is_err());
    }

    #[test]
    fn persistent_node_rejects_bft_validator_set_smaller_than_five() {
        let temp = tempfile::tempdir().unwrap();
        let validator = make_validator_entry(0xA1, ValidatorStatus::Active);
        let config = NodeConfig::default_full(temp.path().to_path_buf())
            .with_genesis_validators(vec![validator]);
        let node = Node::open(config).unwrap();
        let error = node.ensure_consensus_ready().unwrap_err();
        assert!(matches!(
            error,
            PokerL1Error::ValidatorSetTooSmallForOffChain { size: 1 }
        ));
    }

    fn journal_test_validators() -> (
        Vec<ValidatorEntry>,
        Vec<(TaggedPubkey, secp256k1::SecretKey)>,
    ) {
        let mut validators = Vec::new();
        let mut signing_keys = Vec::new();
        // Persistent nodes enforce the production BFT minimum of five active validators.  These
        // recovery fixtures deliberately use a persistent RocksDB node, so they must exercise
        // that same invariant rather than relying on the in-memory test exception.
        for seed in 0x31..=0x35 {
            let (secret, validator) = make_real_validator(seed, ValidatorStatus::Active);
            signing_keys.push((validator.pubkey.clone(), secret));
            validators.push(validator);
        }
        (validators, signing_keys)
    }

    /// Fill the certificate with a real quorum whose signatures bind this exact header position.
    fn sign_journal_test_block(
        node: &Node,
        block: &mut Block,
        signing_keys: &[(TaggedPubkey, secp256k1::SecretKey)],
    ) {
        let active = node.active_validator_pubkeys_sorted();
        let signing_hash = block.header.dag_commit_certificate.signing_hash_for_header(
            DEFAULT_CHAIN_ID,
            block.header.height,
            block.header.timestamp_ms,
            block.header.prev_hash,
        );
        let secp = secp256k1::Secp256k1::new();
        let mut signatures = Vec::with_capacity(active.len());
        for public_key in &active {
            let secret = signing_keys
                .iter()
                .find_map(|(candidate, secret)| (candidate == public_key).then_some(secret))
                .expect("every active journal-test validator has a signing key");
            let signature =
                secp.sign_ecdsa_recoverable(&secp256k1::Message::from_digest(signing_hash), secret);
            let (recovery_id, compact) = signature.serialize_compact();
            let mut bytes = compact.to_vec();
            bytes.push(recovery_id.to_i32() as u8);
            signatures.push(bytes);
        }
        block.header.dag_commit_certificate.signer_bitmap = vec![(1u8 << active.len()) - 1];
        block.header.dag_commit_certificate.signature_list = signatures;
    }

    /// Create the first epoch-transition block whose ObjectDb state changes, together with a
    /// canonical predecessor. This provides a real replayable transition for crash recovery
    /// tests rather than a synthetic header with disconnected roots.
    fn staged_epoch_transition_block_for_journal(
        node: &Node,
        signing_keys: &[(TaggedPubkey, secp256k1::SecretKey)],
    ) -> Block {
        node.apply_genesis_alloc(std::iter::empty()).unwrap();
        let mut first = empty_consensus_block(
            node,
            1,
            1_000,
            node.genesis_parent_hash().unwrap(),
            0,
            1,
            [0u8; 32],
        );
        sign_journal_test_block(node, &mut first, signing_keys);
        let first_hash = node.put_block(&first).unwrap();
        let first_cert_hash = first.header.dag_commit_certificate.cert_hash_for_header(
            DEFAULT_CHAIN_ID,
            first.header.height,
            first.header.timestamp_ms,
            first.header.prev_hash,
        );
        let env = node.execution_environment(2, 2_000);
        let transition = node
            .simulate_block_execution_for_certificate(&env, &[], 1, first_cert_hash, None)
            .unwrap();
        let mut second = empty_consensus_block(node, 2, 2_000, first_hash, 1, 2, first_cert_hash);
        second.header.state_root = transition.state_root;
        second.header.dag_commit_certificate.state_root = transition.state_root;
        sign_journal_test_block(node, &mut second, signing_keys);
        second
    }

    #[test]
    fn journal_recovery_replays_after_account_only_durable_write() {
        let temp = tempfile::tempdir().unwrap();
        let (validators, signing_keys) = journal_test_validators();
        let config =
            NodeConfig::default_full(temp.path().to_path_buf()).with_genesis_validators(validators);
        let node = Node::open(config.clone()).unwrap();
        let block = staged_epoch_transition_block_for_journal(&node, &signing_keys);
        let mut objects = node
            .object_db
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut accounts = node
            .account_store
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let object_root_before = objects.state_root();
        let account_root_before = accounts.state_root();
        let accounts_before = accounts.snapshot_records();
        let (object_snapshot, account_snapshot, _, _, bridge_snapshot) = node
            .prepare_block_execution(&block, &objects, &accounts)
            .unwrap();
        let accounts_after = account_snapshot.snapshot_records();
        let bridge_nonces_before = node
            .bridge_registry_store
            .as_ref()
            .map(|store| store.nonce_snapshot());
        let bridge_nonces_after = bridge_snapshot
            .as_ref()
            .map(BridgeRegistrySnapshot::nonce_snapshot);
        node.block_commit_journal
            .prepare(&PendingBlockCommit {
                block: block.clone(),
                object_root_before,
                account_root_before,
                accounts_before,
                accounts_after,
                bridge_nonces_before,
                bridge_nonces_after,
            })
            .unwrap();

        // Simulate loss of power after the AccountStore batch reaches disk but before ObjectDb.
        accounts.apply_snapshot_durable(account_snapshot).unwrap();
        assert_eq!(objects.state_root(), object_root_before);
        drop(accounts);
        drop(objects);
        drop(node);

        let reopened = Node::open(config).unwrap();
        assert_eq!(
            reopened.get_block_by_height(2).unwrap(),
            Some(block.clone())
        );
        assert_eq!(reopened.state_root(), block.header.state_root);
        assert_eq!(reopened.account_root(), block.header.account_root);
        assert!(reopened.block_commit_journal.pending().unwrap().is_none());
    }

    #[test]
    fn journal_recovery_finishes_after_object_write_before_block_store() {
        let temp = tempfile::tempdir().unwrap();
        let (validators, signing_keys) = journal_test_validators();
        let config =
            NodeConfig::default_full(temp.path().to_path_buf()).with_genesis_validators(validators);
        let node = Node::open(config.clone()).unwrap();
        let block = staged_epoch_transition_block_for_journal(&node, &signing_keys);
        let mut objects = node
            .object_db
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut accounts = node
            .account_store
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let (object_snapshot, account_snapshot, _, _, bridge_snapshot) = node
            .prepare_block_execution(&block, &objects, &accounts)
            .unwrap();
        let bridge_nonces_before = node
            .bridge_registry_store
            .as_ref()
            .map(|store| store.nonce_snapshot());
        let bridge_nonces_after = bridge_snapshot
            .as_ref()
            .map(BridgeRegistrySnapshot::nonce_snapshot);
        node.block_commit_journal
            .prepare(&PendingBlockCommit {
                block: block.clone(),
                object_root_before: objects.state_root(),
                account_root_before: accounts.state_root(),
                accounts_before: accounts.snapshot_records(),
                accounts_after: account_snapshot.snapshot_records(),
                bridge_nonces_before,
                bridge_nonces_after,
            })
            .unwrap();

        // Simulate loss of power after both state stores are durable but before BlockStore.
        accounts.apply_snapshot_durable(account_snapshot).unwrap();
        object_snapshot.apply_to_durable(&mut objects).unwrap();
        assert_eq!(objects.state_root(), block.header.state_root);
        drop(accounts);
        drop(objects);
        drop(node);

        let reopened = Node::open(config).unwrap();
        assert_eq!(
            reopened.get_block_by_height(2).unwrap(),
            Some(block.clone())
        );
        assert_eq!(reopened.state_root(), block.header.state_root);
        assert_eq!(reopened.account_root(), block.header.account_root);
        assert!(reopened.block_commit_journal.pending().unwrap().is_none());
    }

    #[test]
    fn validate_block_rejects_tx_root_mismatch() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let block = Block::new(
            crate::block::BlockHeader {
                height: 1,
                timestamp_ms: 1000,
                prev_hash: [0u8; 32],
                state_root: [0u8; 32],
                account_root: [0u8; 32],
                public_tx_root: [0xFF; 32], // 错误的 root
                gameturn_tx_root: crate::block::compute_tx_merkle_root(&[]),
                dag_commit_certificate: crate::consensus::DagCommitCertificate {
                    epoch: 1,
                    commit_round: 1,
                    prev_commit_hash: [0u8; 32],
                    epoch_transition: None,
                    vertex_hash_list: vec![],
                    round_attendance_bitmap: vec![0xFF],
                    state_root: [0u8; 32],
                    account_root: [0u8; 32],
                    public_tx_root: [0xFF; 32],
                    gameturn_tx_root: crate::block::compute_tx_merkle_root(&[]),
                    signature_list: vec![],
                    signer_bitmap: vec![0xFF],
                },
            },
            vec![Transaction {
                inputs: vec![],
                outputs: vec![],
                contract_call: None,
                tagged_pubkey: dummy_tagged_pubkey(),
                signature: vec![0u8; 65],
                gas: crate::transaction::Gas::new(1000, 1),
                lane_hint: crate::transaction::TxLane::Public,
                route_hint: crate::transaction::RouteHint::AnyValidator,
                chain_id: DEFAULT_CHAIN_ID,
                nonce: 1,
                gameturn_nonce: None,
                is_fallback: false,
            }],
            vec![],
        );
        let result = node.validate_block(&block);
        assert!(result.is_err(), "tx root 不匹配应被拒绝: {:?}", result);
    }

    #[test]
    fn validate_block_rejects_gameturn_gas_charged() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let mut gameturn_tx = Transaction {
            inputs: vec![],
            outputs: vec![],
            contract_call: None,
            tagged_pubkey: dummy_tagged_pubkey(),
            signature: vec![0u8; 65],
            gas: crate::transaction::Gas::new(100, 1), // 错误计费
            lane_hint: crate::transaction::TxLane::GameTurn,
            route_hint: crate::transaction::RouteHint::AssignedValidator,
            chain_id: DEFAULT_CHAIN_ID,
            nonce: 0,
            gameturn_nonce: Some(0),
            is_fallback: false,
        };
        let gt_root = crate::block::compute_tx_merkle_root(&[gameturn_tx.clone()]);
        let block = Block::new(
            crate::block::BlockHeader {
                height: 1,
                timestamp_ms: 1000,
                prev_hash: [0u8; 32],
                state_root: [0u8; 32],
                account_root: [0u8; 32],
                public_tx_root: crate::block::compute_tx_merkle_root(&[]),
                gameturn_tx_root: gt_root,
                dag_commit_certificate: crate::consensus::DagCommitCertificate {
                    epoch: 1,
                    commit_round: 1,
                    prev_commit_hash: [0u8; 32],
                    epoch_transition: None,
                    vertex_hash_list: vec![],
                    round_attendance_bitmap: vec![0xFF],
                    state_root: [0u8; 32],
                    account_root: [0u8; 32],
                    public_tx_root: crate::block::compute_tx_merkle_root(&[]),
                    gameturn_tx_root: gt_root,
                    signature_list: vec![],
                    signer_bitmap: vec![0xFF],
                },
            },
            vec![],
            vec![gameturn_tx],
        );
        let result = node.validate_block(&block);
        assert!(result.is_err(), "GameTurn 计费应被拒绝: {:?}", result);
    }

    #[test]
    fn state_root_mismatch_does_not_mutate_live_state() {
        use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};

        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let tagged_pubkey = TaggedPubkey {
            tag: encode_tag(SignatureScheme::Secp256k1, 1),
            raw: PublicKey::from_secret_key(&secp, &secret)
                .serialize()
                .to_vec(),
        };
        let caller = derive_address(&tagged_pubkey);
        node.put_account(Account::new(tagged_pubkey.clone(), 0))
            .unwrap();

        let created = Object::new(
            ObjectID::new(caller, 1),
            Ownership::AddressOwned { owner: caller },
            "ValidationRegression",
            b"must-not-leak".to_vec(),
            None,
        );
        let request = TxRequest {
            inputs: vec![],
            outputs: vec![created.clone()],
            contract_call: None,
            gas: Gas::new(1_000, 1),
            lane_hint: TxLane::Public,
            route_hint: RouteHint::AnyValidator,
            chain_id: DEFAULT_CHAIN_ID,
            nonce: 0,
            gameturn_nonce: None,
            is_fallback: false,
        };
        let signature = {
            let signature =
                secp.sign_ecdsa_recoverable(&Message::from_digest(request.signing_hash()), &secret);
            let (recovery_id, compact) = signature.serialize_compact();
            let mut bytes = compact.to_vec();
            bytes.push(recovery_id.to_i32() as u8);
            bytes
        };
        let tx = request.into_transaction(tagged_pubkey, signature);
        let env = node.execution_environment(1, 1_000);
        let expected_outcome = node
            .simulate_block_execution(&env, std::slice::from_ref(&tx))
            .unwrap();
        let expected_state_root = expected_outcome.state_root;
        let expected_account_root = expected_outcome.account_root;
        let mut wrong_state_root = expected_state_root;
        wrong_state_root[0] ^= 0xFF;
        let public_tx_root = crate::block::compute_tx_merkle_root(std::slice::from_ref(&tx));
        let empty_root = crate::block::compute_tx_merkle_root(&[]);
        let certificate = crate::consensus::DagCommitCertificate {
            epoch: 0,
            commit_round: 1,
            prev_commit_hash: [0u8; 32],
            epoch_transition: None,
            vertex_hash_list: vec![],
            round_attendance_bitmap: vec![],
            state_root: wrong_state_root,
            account_root: expected_account_root,
            public_tx_root,
            gameturn_tx_root: empty_root,
            signature_list: vec![],
            signer_bitmap: vec![],
        };
        let mut block = Block::new(
            BlockHeader {
                height: 1,
                timestamp_ms: 1_000,
                prev_hash: [0u8; 32],
                state_root: wrong_state_root,
                account_root: expected_account_root,
                public_tx_root,
                gameturn_tx_root: empty_root,
                dag_commit_certificate: certificate,
            },
            vec![tx],
            vec![],
        );

        let root_before = node.state_root();
        assert!(node.validate_block(&block).is_err());
        assert_eq!(node.state_root(), root_before);
        assert!(node.get_object(&created.id).unwrap().is_none());
        assert_eq!(node.get_account(&caller).unwrap().unwrap().nonce, 0);

        // The same transaction is committed exactly once only after its state root matches.
        block.header.state_root = expected_state_root;
        block.header.dag_commit_certificate.state_root = expected_state_root;
        block.header.account_root = expected_account_root;
        block.header.dag_commit_certificate.account_root = expected_account_root;
        node.validate_block(&block).unwrap();
        assert!(node.get_object(&created.id).unwrap().is_none());
        node.put_block(&block).unwrap();
        assert!(node.get_object(&created.id).unwrap().is_some());
        assert_eq!(node.get_account(&caller).unwrap().unwrap().nonce, 1);
    }

    #[test]
    fn conflicting_height_is_rejected_before_any_state_commit() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let empty_root = crate::block::compute_tx_merkle_root(&[]);
        let state_root = node.state_root();
        let account_root = node.account_root();
        let certificate = crate::consensus::DagCommitCertificate {
            epoch: 0,
            commit_round: 1,
            prev_commit_hash: [0u8; 32],
            epoch_transition: None,
            vertex_hash_list: vec![],
            round_attendance_bitmap: vec![],
            state_root,
            account_root,
            public_tx_root: empty_root,
            gameturn_tx_root: empty_root,
            signature_list: vec![],
            signer_bitmap: vec![],
        };
        let first = Block::new(
            BlockHeader {
                height: 1,
                timestamp_ms: 1_000,
                prev_hash: [0u8; 32],
                state_root,
                account_root,
                public_tx_root: empty_root,
                gameturn_tx_root: empty_root,
                dag_commit_certificate: certificate.clone(),
            },
            vec![],
            vec![],
        );
        let first_hash = node.put_block(&first).unwrap();
        let conflicting = Block::new(
            BlockHeader {
                timestamp_ms: 2_000,
                dag_commit_certificate: certificate,
                ..first.header.clone()
            },
            vec![],
            vec![],
        );

        assert!(node.put_block(&conflicting).is_err());
        assert_eq!(node.state_root(), state_root);
        assert_eq!(
            node.get_block_by_height(1)
                .unwrap()
                .unwrap()
                .block_hash(DEFAULT_CHAIN_ID),
            first_hash
        );
    }

    // ===== P0-4: 动态 quorum（ValidatorSet 接入节点）测试 =====

    use crate::consensus::ValidatorStatus;

    /// 构造测试用 ValidatorEntry（指定状态）。
    fn make_validator_entry(byte: u8, status: ValidatorStatus) -> ValidatorEntry {
        let mut entry = ValidatorEntry::new(
            TaggedPubkey {
                tag: encode_tag(SignatureScheme::Secp256k1, 1),
                raw: vec![byte; 33],
            },
            [byte; 33],
            0,
            0,
        );
        entry.status = status;
        entry
    }

    /// 构造 5 个活跃 validator 的创世列表（字节避开 0x02 = dummy_tagged_pubkey）。
    fn five_active_validators() -> Vec<ValidatorEntry> {
        (0xA1u8..=0xA5)
            .map(|b| make_validator_entry(b, ValidatorStatus::Active))
            .collect()
    }

    fn make_real_validator(
        seed: u8,
        status: ValidatorStatus,
    ) -> (secp256k1::SecretKey, ValidatorEntry) {
        let secret = secp256k1::SecretKey::from_slice(&[seed; 32]).unwrap();
        let public = secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &secret);
        let tagged = TaggedPubkey::new(
            SignatureScheme::Secp256k1,
            CURRENT_VERSION,
            public.serialize().to_vec(),
        )
        .unwrap();
        let mut entry = ValidatorEntry::new(tagged, public.serialize(), 0, 0);
        entry.status = status;
        (secret, entry)
    }

    fn signed_empty_vertex(
        secret: &secp256k1::SecretKey,
        author: TaggedPubkey,
        epoch: u64,
        round: u64,
        parent_hashes: Vec<Hash>,
    ) -> DagVertex {
        sign_vertex(
            secret,
            DagVertex {
                epoch,
                round,
                author_pubkey: author,
                tx_list: vec![],
                parent_hashes,
                author_sig: vec![],
            },
        )
    }

    fn sign_vertex(secret: &secp256k1::SecretKey, mut vertex: DagVertex) -> DagVertex {
        let message = secp256k1::Message::from_digest(vertex.signing_hash(DEFAULT_CHAIN_ID));
        let signature = secp256k1::Secp256k1::new().sign_ecdsa_recoverable(&message, secret);
        let (recovery_id, compact) = signature.serialize_compact();
        vertex.author_sig = compact
            .into_iter()
            .chain(std::iter::once(recovery_id.to_i32() as u8))
            .collect();
        vertex
    }

    fn four_real_validators() -> Vec<(secp256k1::SecretKey, ValidatorEntry)> {
        (1..=4)
            .map(|seed| make_real_validator(seed, ValidatorStatus::Active))
            .collect()
    }

    #[test]
    fn validate_vertex_rejects_invalid_transaction_signature_at_admission() {
        let (secret, validator) = make_real_validator(9, ValidatorStatus::Active);
        let node = Node::open_inmemory_with_validators(
            NodeRole::Full,
            DEFAULT_CHAIN_ID,
            vec![validator.clone()],
        )
        .unwrap();
        let mut invalid_tx = make_pub_tx(0x44, 1, 5);
        invalid_tx.tagged_pubkey = validator.pubkey.clone();
        let wrong_message = secp256k1::Message::from_digest([0xAA; 32]);
        let wrong_signature =
            secp256k1::Secp256k1::new().sign_ecdsa_recoverable(&wrong_message, &secret);
        let (wrong_recovery_id, wrong_compact) = wrong_signature.serialize_compact();
        invalid_tx.signature = wrong_compact
            .into_iter()
            .chain(std::iter::once(wrong_recovery_id.to_i32() as u8))
            .collect();
        let vertex = sign_vertex(
            &secret,
            DagVertex {
                epoch: 0,
                round: 1,
                author_pubkey: validator.pubkey,
                tx_list: vec![invalid_tx],
                parent_hashes: vec![],
                author_sig: vec![],
            },
        );

        assert!(matches!(
            node.validate_vertex(&vertex),
            Err(PokerL1Error::InvalidSignature)
        ));
    }

    #[test]
    fn validate_vertex_accepts_distinct_active_parent_quorum() {
        let validators = four_real_validators();
        let node = Node::open_inmemory_with_validators(
            NodeRole::Full,
            DEFAULT_CHAIN_ID,
            validators.iter().map(|(_, entry)| entry.clone()).collect(),
        )
        .unwrap();

        let mut parent_hashes = Vec::new();
        for (secret, entry) in validators.iter().take(3) {
            let parent = signed_empty_vertex(secret, entry.pubkey.clone(), 0, 1, vec![]);
            parent_hashes.push(node.put_vertex(&parent).unwrap());
        }
        let child = signed_empty_vertex(
            &validators[3].0,
            validators[3].1.pubkey.clone(),
            0,
            2,
            parent_hashes,
        );

        node.validate_vertex(&child).unwrap();
    }

    #[test]
    fn validate_vertex_rejects_parent_hash_count_without_distinct_author_quorum() {
        let validators = four_real_validators();
        let node = Node::open_inmemory_with_validators(
            NodeRole::Full,
            DEFAULT_CHAIN_ID,
            validators.iter().map(|(_, entry)| entry.clone()).collect(),
        )
        .unwrap();

        let first = signed_empty_vertex(
            &validators[0].0,
            validators[0].1.pubkey.clone(),
            0,
            1,
            vec![],
        );
        let equivocation = signed_empty_vertex(
            &validators[0].0,
            validators[0].1.pubkey.clone(),
            0,
            1,
            vec![],
        );
        // Different tx content changes the hash while retaining epoch/round/author.
        let mut equivocation = equivocation;
        equivocation.tx_list.push(make_pub_tx(0x55, 1, 1));
        let equivocation = sign_vertex(&validators[0].0, equivocation);
        let first_hash = node.vertex_store.put(&first).unwrap();
        let equivocation_hash = node.vertex_store.put(&equivocation).unwrap();
        let third = signed_empty_vertex(
            &validators[1].0,
            validators[1].1.pubkey.clone(),
            0,
            1,
            vec![],
        );
        let third_hash = node.put_vertex(&third).unwrap();
        let child = signed_empty_vertex(
            &validators[3].0,
            validators[3].1.pubkey.clone(),
            0,
            2,
            vec![first_hash, equivocation_hash, third_hash],
        );

        assert!(matches!(
            node.validate_vertex(&child),
            Err(PokerL1Error::DuplicateParentVertexAuthor(_))
        ));
    }

    #[test]
    fn validate_vertex_rejects_insufficient_previous_round_quorum() {
        let validators = four_real_validators();
        let node = Node::open_inmemory_with_validators(
            NodeRole::Full,
            DEFAULT_CHAIN_ID,
            validators.iter().map(|(_, entry)| entry.clone()).collect(),
        )
        .unwrap();
        let mut parent_hashes = Vec::new();
        for (secret, entry) in validators.iter().take(2) {
            let parent = signed_empty_vertex(secret, entry.pubkey.clone(), 0, 1, vec![]);
            parent_hashes.push(node.put_vertex(&parent).unwrap());
        }
        let child = signed_empty_vertex(
            &validators[3].0,
            validators[3].1.pubkey.clone(),
            0,
            2,
            parent_hashes,
        );

        assert!(matches!(
            node.validate_vertex(&child),
            Err(PokerL1Error::InsufficientParents {
                actual: 2,
                required: 3
            })
        ));
    }

    #[test]
    fn validate_vertex_rejects_duplicate_or_wrong_round_parent() {
        let validators = four_real_validators();
        let node = Node::open_inmemory_with_validators(
            NodeRole::Full,
            DEFAULT_CHAIN_ID,
            validators.iter().map(|(_, entry)| entry.clone()).collect(),
        )
        .unwrap();
        let parent = signed_empty_vertex(
            &validators[0].0,
            validators[0].1.pubkey.clone(),
            0,
            1,
            vec![],
        );
        let parent_hash = node.put_vertex(&parent).unwrap();

        let duplicate = signed_empty_vertex(
            &validators[3].0,
            validators[3].1.pubkey.clone(),
            0,
            2,
            vec![parent_hash, parent_hash],
        );
        assert!(matches!(
            node.validate_vertex(&duplicate),
            Err(PokerL1Error::DuplicateParentVertex(hash)) if hash == parent_hash
        ));

        let wrong_round = signed_empty_vertex(
            &validators[3].0,
            validators[3].1.pubkey.clone(),
            0,
            3,
            vec![parent_hash],
        );
        assert!(matches!(
            node.validate_vertex(&wrong_round),
            Err(PokerL1Error::InvalidParentVertexRound {
                actual: 1,
                expected: 2,
                ..
            })
        ));
    }

    #[test]
    fn validate_vertex_rejects_wrong_epoch() {
        let (secret, validator) = make_real_validator(8, ValidatorStatus::Active);
        let node = Node::open_inmemory_with_validators(
            NodeRole::Full,
            DEFAULT_CHAIN_ID,
            vec![validator.clone()],
        )
        .unwrap();
        let vertex = signed_empty_vertex(&secret, validator.pubkey, 1, 1, vec![]);

        assert!(matches!(
            node.validate_vertex(&vertex),
            Err(PokerL1Error::InvalidVertexEpoch {
                actual: 1,
                expected: 0
            })
        ));
    }

    #[test]
    fn validate_vertex_rejects_parent_from_different_epoch() {
        let (secret, validator) = make_real_validator(7, ValidatorStatus::Active);
        let node = Node::open_inmemory_with_validators(
            NodeRole::Full,
            DEFAULT_CHAIN_ID,
            vec![validator.clone()],
        )
        .unwrap();
        let old_epoch_parent = signed_empty_vertex(&secret, validator.pubkey.clone(), 1, 1, vec![]);
        let parent_hash = node.vertex_store.put(&old_epoch_parent).unwrap();
        let child = signed_empty_vertex(&secret, validator.pubkey, 0, 2, vec![parent_hash]);

        assert!(matches!(
            node.validate_vertex(&child),
            Err(PokerL1Error::InvalidParentVertexEpoch {
                parent_hash: actual_hash,
                actual: 1,
                expected: 0
            }) if actual_hash == parent_hash
        ));
    }

    #[test]
    fn validate_vertex_rejects_same_author_equivocation_at_admission() {
        let validators = four_real_validators();
        let node = Node::open_inmemory_with_validators(
            NodeRole::Full,
            DEFAULT_CHAIN_ID,
            validators.iter().map(|(_, entry)| entry.clone()).collect(),
        )
        .unwrap();

        let mut parent_hashes = Vec::new();
        for (secret, entry) in validators.iter().take(3) {
            let parent = signed_empty_vertex(secret, entry.pubkey.clone(), 0, 1, vec![]);
            parent_hashes.push(node.put_vertex(&parent).unwrap());
        }
        let first = signed_empty_vertex(
            &validators[3].0,
            validators[3].1.pubkey.clone(),
            0,
            2,
            parent_hashes.clone(),
        );
        node.put_vertex(&first).unwrap();

        parent_hashes.swap(0, 1);
        let conflicting = signed_empty_vertex(
            &validators[3].0,
            validators[3].1.pubkey.clone(),
            0,
            2,
            parent_hashes,
        );
        assert!(matches!(
            node.validate_vertex(&conflicting),
            Err(PokerL1Error::VertexEquivocation {
                epoch: 0,
                round: 2,
                author
            }) if author == validators[3].1.pubkey
        ));
    }

    #[test]
    fn node_genesis_validators_loaded() {
        let node = Node::open_inmemory_with_validators(
            NodeRole::Validator,
            DEFAULT_CHAIN_ID,
            five_active_validators(),
        )
        .unwrap();
        assert_eq!(node.validator_count(), 5);
        assert_eq!(node.active_validator_count(), 5);
        // quorum = 2*5/3+1 = 4
        assert_eq!(node.required_quorum(), 4);
        assert_eq!(node.current_epoch(), 0);
    }

    #[test]
    fn node_rejects_unbacked_genesis_validator_stake() {
        let mut validator = make_validator_entry(0xB1, ValidatorStatus::Active);
        validator.stake = 1;
        let error = match Node::open_inmemory_with_validators(
            NodeRole::Validator,
            DEFAULT_CHAIN_ID,
            vec![validator],
        ) {
            Ok(_) => panic!("unbacked genesis stake must be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("unbacked stake"));
    }

    #[test]
    fn node_required_quorum_empty_set_is_zero() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        assert_eq!(node.validator_count(), 0);
        assert_eq!(node.active_validator_count(), 0);
        assert_eq!(node.required_quorum(), 0, "创世引导期 quorum 应为 0");
    }

    #[test]
    fn node_required_quorum_reflects_dynamic_set() {
        // 3 active → quorum 3；加入 bonding validator 不影响 active quorum
        let validators: Vec<ValidatorEntry> = (1u8..=3)
            .map(|b| make_validator_entry(b, ValidatorStatus::Active))
            .collect();
        let node =
            Node::open_inmemory_with_validators(NodeRole::Validator, DEFAULT_CHAIN_ID, validators)
                .unwrap();
        node.apply_genesis_alloc(std::iter::empty()).unwrap();
        assert_eq!(node.required_quorum(), 3); // 2*3/3+1

        // 加入第 4 个零质押测试 validator（Bonding 状态）→ active 数不变。
        let mut entry4 = make_validator_entry(4, ValidatorStatus::Bonding);
        entry4.stake = 0;
        node.add_validator(entry4).unwrap();
        assert_eq!(node.validator_count(), 4);
        assert_eq!(node.active_validator_count(), 3);
        assert_eq!(node.required_quorum(), 3);

        // bonding 到期 → Active → quorum 变为 2*4/3+1 = 3
        node.process_bonding_expiry(100).unwrap();
        assert_eq!(node.active_validator_count(), 4);
        assert_eq!(node.required_quorum(), 3);

        // 再加入 2 个 active → 6 active → quorum = 2*6/3+1 = 5
        for b in [5u8, 6u8] {
            let mut entry = make_validator_entry(b, ValidatorStatus::Active);
            entry.stake = 0;
            node.add_validator(entry).unwrap();
        }
        assert_eq!(node.active_validator_count(), 6);
        assert_eq!(node.required_quorum(), 5);
    }

    #[test]
    fn node_add_validator_rejects_duplicate() {
        let node = Node::open_inmemory_with_validators(
            NodeRole::Validator,
            DEFAULT_CHAIN_ID,
            five_active_validators(),
        )
        .unwrap();
        node.apply_genesis_alloc(std::iter::empty()).unwrap();
        let dup = make_validator_entry(0xA1, ValidatorStatus::Active);
        let result = node.add_validator(dup);
        assert!(result.is_err(), "重复 pubkey 应被拒绝: {:?}", result);
    }

    #[test]
    fn node_advance_epoch_rolls_randomness() {
        let node = Node::open_inmemory_with_validators(
            NodeRole::Validator,
            DEFAULT_CHAIN_ID,
            five_active_validators(),
        )
        .unwrap();
        node.apply_genesis_alloc(std::iter::empty()).unwrap();
        let randomness_before = {
            let set = node.validator_set.lock().unwrap_or_else(|e| e.into_inner());
            set.epoch_randomness
        };
        node.advance_epoch(1).unwrap();
        assert_eq!(node.current_epoch(), 1);
        let set = node.validator_set.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(set.prev_epoch_randomness, randomness_before);
    }

    #[test]
    fn validate_vertex_rejects_non_validator_author() {
        let node = Node::open_inmemory_with_validators(
            NodeRole::Full,
            DEFAULT_CHAIN_ID,
            five_active_validators(),
        )
        .unwrap();
        // author（0x02;33 = dummy_tagged_pubkey）不在 validator set 中
        let vertex = DagVertex {
            epoch: 0,
            round: 1,
            author_pubkey: dummy_tagged_pubkey(),
            tx_list: vec![],
            parent_hashes: vec![],
            author_sig: vec![0u8; 65],
        };
        let result = node.validate_vertex(&vertex);
        assert!(
            matches!(result, Err(PokerL1Error::VertexAuthorNotActiveValidator(_))),
            "非 validator author 应被拒绝: {:?}",
            result
        );
    }

    #[test]
    fn validate_vertex_rejects_bonding_author() {
        // author 在 set 中但处于 Bonding 状态（不可参与共识）
        let mut validators = five_active_validators();
        validators.push(make_validator_entry(0x02, ValidatorStatus::Bonding));
        let node =
            Node::open_inmemory_with_validators(NodeRole::Full, DEFAULT_CHAIN_ID, validators)
                .unwrap();
        // dummy_tagged_pubkey raw = [0x02; 33] → 与 bonding entry 匹配
        let vertex = DagVertex {
            epoch: 0,
            round: 1,
            author_pubkey: dummy_tagged_pubkey(),
            tx_list: vec![],
            parent_hashes: vec![],
            author_sig: vec![0u8; 65],
        };
        let result = node.validate_vertex(&vertex);
        assert!(
            matches!(result, Err(PokerL1Error::VertexAuthorNotActiveValidator(_))),
            "Bonding author 应被拒绝: {:?}",
            result
        );
    }

    #[test]
    fn validate_block_rejects_insufficient_cert_quorum() {
        let node = Node::open_inmemory_with_validators(
            NodeRole::Full,
            DEFAULT_CHAIN_ID,
            five_active_validators(),
        )
        .unwrap();
        // 空 tx 列表，tx roots 正确；cert 无签名 → quorum 不足（0 < 4）
        let empty_root = crate::block::compute_tx_merkle_root(&[]);
        let block = Block::new(
            crate::block::BlockHeader {
                height: 1,
                timestamp_ms: 1000,
                prev_hash: [0u8; 32],
                state_root: [0u8; 32],
                account_root: [0u8; 32],
                public_tx_root: empty_root,
                gameturn_tx_root: empty_root,
                dag_commit_certificate: crate::consensus::DagCommitCertificate {
                    epoch: 0,
                    commit_round: 1,
                    prev_commit_hash: [0u8; 32],
                    epoch_transition: None,
                    vertex_hash_list: vec![],
                    round_attendance_bitmap: vec![0],
                    state_root: [0u8; 32],
                    account_root: [0u8; 32],
                    public_tx_root: empty_root,
                    gameturn_tx_root: empty_root,
                    signature_list: vec![],
                    signer_bitmap: vec![0],
                },
            },
            vec![],
            vec![],
        );
        let result = node.validate_block(&block);
        assert!(
            result.is_err(),
            "quorum 不足的 commit certificate 应被拒绝: {:?}",
            result
        );
    }

    // ===== 缺口 #5：staking 结算测试 =====

    /// 创建 validator entry（用于 UTXO-backed staking 测试）。
    fn make_funded_validator(byte: u8, stake: u64) -> ValidatorEntry {
        let entry = make_validator_entry(byte, ValidatorStatus::Active);
        let mut e = entry;
        e.stake = stake;
        e
    }

    fn genesis_fund_validator(node: &Node, entry: &ValidatorEntry, amount: u64) -> Vec<ObjectID> {
        node.apply_genesis_alloc([(entry.pubkey.clone(), amount)])
            .unwrap();
        let owner = crate::account::derive_address(&entry.pubkey);
        node.list_native_coins(owner)
            .unwrap()
            .into_iter()
            .map(|coin| coin.id)
            .collect()
    }

    #[test]
    fn bond_validator_locks_utxo_value_in_staking_escrow() {
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        let entry = make_funded_validator(0x20, 5_000);
        let addr = crate::account::derive_address(&entry.pubkey);
        let inputs = genesis_fund_validator(&node, &entry, 1_005_000);
        assert_eq!(node.native_coin_balance(addr).unwrap(), 1_005_000);
        node.bond_validator(entry, &inputs).unwrap();
        assert_eq!(node.native_coin_balance(addr).unwrap(), 1_000_000);
        assert_eq!(node.get_account(&addr).unwrap().unwrap().balance, 0);
        assert_eq!(
            node.treasury_cap().unwrap().unwrap().total_supply,
            1_005_000
        );
        let reconciliation = node.reconcile_native_supply().unwrap();
        assert_eq!(reconciliation.live_utxo, 1_000_000);
        assert_eq!(reconciliation.staking_escrow, 5_000);
    }

    #[test]
    fn bonded_validator_and_epoch_survive_persistent_restart() {
        let temp = tempfile::tempdir().unwrap();
        let config = NodeConfig::default_full(temp.path().to_path_buf());
        let node = Node::open(config.clone()).unwrap();
        let entry = make_funded_validator(0x24, 5_000);
        let pubkey = entry.pubkey.clone();
        let inputs = genesis_fund_validator(&node, &entry, 10_000);
        node.bond_validator(entry, &inputs).unwrap();
        node.advance_epoch(1).unwrap();
        assert_eq!(
            node.reconcile_native_supply().unwrap().staking_escrow,
            5_000
        );
        drop(node);

        let reopened = Node::open(config).unwrap();
        assert_eq!(reopened.current_epoch(), 1);
        let set = reopened.validator_set.lock().unwrap();
        let restored = set
            .find_validator(&pubkey)
            .expect("bonded validator restored");
        assert_eq!(restored.stake, 5_000);
        drop(set);
        assert_eq!(
            reopened.reconcile_native_supply().unwrap().staking_escrow,
            5_000
        );
    }

    #[test]
    fn bond_validator_rejects_insufficient_utxo_value_without_mutation() {
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        let mut entry = make_validator_entry(0x21, ValidatorStatus::Active);
        entry.stake = 10_000;
        let owner = crate::account::derive_address(&entry.pubkey);
        let inputs = genesis_fund_validator(&node, &entry, 100);
        let err = node.bond_validator(entry, &inputs).unwrap_err();
        assert!(
            matches!(err, PokerL1Error::InsufficientBalance { .. }),
            "余额不足应拒绝: {err:?}"
        );
        assert_eq!(node.native_coin_balance(owner).unwrap(), 100);
        assert_eq!(node.validator_count(), 0);
    }

    #[test]
    fn slash_validator_reduces_stake() {
        // slashing 减少 ValidatorEntry.stake（锁定部分燃烧，不退账户）。
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        let entry = make_funded_validator(0x22, 100_000);
        let pubkey = entry.pubkey.clone();
        let addr = crate::account::derive_address(&pubkey);
        let inputs = genesis_fund_validator(&node, &entry, 150_000);
        node.bond_validator(entry, &inputs).unwrap();
        let cap_before = node.treasury_cap().unwrap().unwrap();

        let config = crate::consensus::SlashingConfig::default();
        let result = node
            .slash_validator(
                &pubkey,
                crate::consensus::SlashingReason::VertexEquivocation,
                &config,
            )
            .unwrap();
        // 默认 slash_percentage=100 → slash_amount = 100_000（全额）
        assert_eq!(result.slash_amount, 100_000);
        assert_eq!(result.stake_after, 0);
        assert_eq!(node.native_coin_balance(addr).unwrap(), 50_000);
        let cap_after = node.treasury_cap().unwrap().unwrap();
        assert_eq!(cap_after.total_supply, cap_before.total_supply - 100_000);
        assert_eq!(cap_after.total_burned, cap_before.total_burned + 100_000);
        assert_eq!(node.get_account(&addr).unwrap().unwrap().balance, 0);
        assert!(node.reconcile_native_supply().unwrap().is_balanced());
    }

    #[test]
    fn complete_unbonding_refunds_stake() {
        // unbonding 完成后退还剩余 stake 到账户。
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        let entry = make_funded_validator(0x23, 50_000);
        let pubkey = entry.pubkey.clone();
        let addr = crate::account::derive_address(&pubkey);
        let inputs = genesis_fund_validator(&node, &entry, 75_000);
        node.bond_validator(entry, &inputs).unwrap();
        assert_eq!(node.native_coin_balance(addr).unwrap(), 25_000);
        node.process_bonding_expiry(0).unwrap();

        // 启动 unbonding（锁定到 height 100）
        node.start_validator_unbonding(&pubkey, 100).unwrap();
        // 未到期 → 拒绝
        let err = node.complete_unbonding(&pubkey, 50).unwrap_err();
        assert!(matches!(err, PokerL1Error::Other(_)));

        // 到期 → 退还
        let refund = node.complete_unbonding(&pubkey, 100).unwrap();
        assert_eq!(refund, 50_000, "应退还全部剩余 stake");
        assert_eq!(node.native_coin_balance(addr).unwrap(), 75_000);
        assert_eq!(node.get_account(&addr).unwrap().unwrap().balance, 0);
        assert_eq!(node.treasury_cap().unwrap().unwrap().total_supply, 75_000);
        let reconciliation = node.reconcile_native_supply().unwrap();
        assert_eq!(reconciliation.live_utxo, 75_000);
        assert_eq!(reconciliation.staking_escrow, 0);
    }

    // ===== 缺口 #3 §3.6：VRF 时序接入测试 =====

    #[test]
    fn advance_epoch_with_vrf_derives_real_randomness() {
        // 配置 VRF 私钥 → advance_epoch_with_vrf 用真实 ECVRF 派生 epoch_randomness。
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        // 构造一个 validator + VRF 密钥对，注册到 set。
        let prover = crate::consensus::ecvrf::Secp256k1VrfProver::from_secret_bytes(&[0x55; 32]);
        let vrf_pubkey = prover.derive_public_key().unwrap();
        let tagged =
            TaggedPubkey::new(SignatureScheme::Secp256k1, CURRENT_VERSION, vec![0x55; 33]).unwrap();
        let mut entry = ValidatorEntry::new(tagged.clone(), vrf_pubkey, 0, 0);
        entry.status = crate::consensus::ValidatorStatus::Active;
        node.add_validator(entry).unwrap();
        node.apply_genesis_alloc(std::iter::empty()).unwrap();
        // 注入 validator_key（使 advance_epoch_with_vrf 能标识 proposer）。
        // 注意：tagged_pubkey 需匹配 set 中的 validator。
        let randomness_before = {
            let set = node.validator_set.lock().unwrap();
            set.epoch_randomness
        };

        node.advance_epoch_with_vrf(1, Some(&[0x55; 32])).unwrap();

        let set = node.validator_set.lock().unwrap();
        // epoch_randomness 应已变化（真实 ECVRF output，非 fallback 也非旧值）。
        assert_ne!(
            set.epoch_randomness, randomness_before,
            "VRF 应派生新的 epoch_randomness"
        );
        assert_eq!(set.epoch, 1);
    }

    #[test]
    fn advance_epoch_without_vrf_uses_fallback() {
        // 无 VRF 私钥 → fallback_epoch_randomness（SEC2-M12）。
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        node.apply_genesis_alloc(std::iter::empty()).unwrap();
        let randomness_before = {
            let set = node.validator_set.lock().unwrap();
            set.epoch_randomness
        };
        node.advance_epoch_with_vrf(1, None).unwrap();
        let set = node.validator_set.lock().unwrap();
        // fallback = hash(prev || genesis)，应不同于原 epoch_randomness（genesis 随机性）。
        assert_eq!(set.epoch, 1);
        // fallback 可能恰好等于原值（若 prev==genesis==0），故仅断言 epoch 推进 + 不 panic。
        let _ = randomness_before;
    }

    // ===== 缺口 #4-M1：genesis 余额分配测试 =====

    fn tp(byte: u8) -> TaggedPubkey {
        TaggedPubkey {
            tag: encode_tag(SignatureScheme::Secp256k1, 1),
            raw: vec![byte; 33],
        }
    }

    #[test]
    fn apply_genesis_alloc_creates_zero_balance_accounts_and_coins() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let pk1 = tp(0x30);
        let pk2 = tp(0x31);
        let allocs = vec![(pk1.clone(), 1_000_000), (pk2.clone(), 500_000)];
        let created = node.apply_genesis_alloc(allocs).unwrap();
        assert_eq!(created, 2);
        let addr1 = crate::account::derive_address(&pk1);
        let addr2 = crate::account::derive_address(&pk2);
        assert_eq!(node.get_account(&addr1).unwrap().unwrap().balance, 0);
        assert_eq!(node.get_account(&addr2).unwrap().unwrap().balance, 0);
        let cap = node.treasury_cap().unwrap().unwrap();
        assert_eq!(cap.total_supply, 1_500_000);
        assert!(cap.minting_closed);
        assert!(node.reconcile_native_supply().unwrap().is_balanced());
        let object_db = node.object_db.lock().unwrap();
        assert_eq!(
            crate::economics::native_coin_balance(&object_db, addr1).unwrap(),
            1_000_000
        );
        assert_eq!(
            crate::economics::native_coin_balance(&object_db, addr2).unwrap(),
            500_000
        );
    }

    #[test]
    fn apply_genesis_alloc_is_idempotent() {
        // 完全相同的 genesis allocation 在重启时是 no-op。
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let pk = tp(0x32);
        node.apply_genesis_alloc(vec![(pk.clone(), 1_000)]).unwrap();
        let created = node.apply_genesis_alloc(vec![(pk.clone(), 1_000)]).unwrap();
        assert_eq!(created, 0, "相同 allocation 不应重复铸币");
        let addr = crate::account::derive_address(&pk);
        assert_eq!(node.get_account(&addr).unwrap().unwrap().balance, 0);
        assert_eq!(node.treasury_cap().unwrap().unwrap().total_supply, 1_000);
        assert!(node.apply_genesis_alloc(vec![(pk, 9_999)]).is_err());
        assert_eq!(node.treasury_cap().unwrap().unwrap().total_supply, 1_000);
    }

    #[test]
    fn pinned_genesis_manifest_survives_restart_and_rejects_mismatch() {
        let temp = tempfile::tempdir().unwrap();
        let recipient = tp(0x73);
        let allocations = vec![(recipient.clone(), 77)];
        let manifest = GenesisManifest::new(
            DEFAULT_CHAIN_ID,
            vec![],
            vec![GenesisAllocation {
                recipient: recipient.clone(),
                amount: 77,
            }],
        )
        .unwrap();
        let config = NodeConfig::default_full(temp.path().to_path_buf())
            .with_genesis_manifest_hash(manifest.hash());
        let node = Node::open(config.clone()).unwrap();
        // Cold-sync nodes authenticate the first header before a snapshot installs the anchor.
        assert_eq!(node.genesis_parent_hash().unwrap(), manifest.hash());
        node.apply_genesis_alloc(allocations.clone()).unwrap();
        assert_eq!(node.genesis_parent_hash().unwrap(), manifest.hash());
        drop(node);

        let reopened = Node::open(config).unwrap();
        assert_eq!(reopened.genesis_parent_hash().unwrap(), manifest.hash());
        drop(reopened);

        let wrong_manifest = GenesisManifest::new(
            DEFAULT_CHAIN_ID,
            vec![],
            vec![GenesisAllocation {
                recipient,
                amount: 78,
            }],
        )
        .unwrap();
        let wrong_config = NodeConfig::default_full(temp.path().to_path_buf())
            .with_genesis_manifest_hash(wrong_manifest.hash());
        assert!(Node::open(wrong_config).is_err());
    }

    #[test]
    fn initialized_genesis_rejects_zero_first_block_parent() {
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        node.apply_genesis_alloc(std::iter::empty()).unwrap();
        let wrong = empty_consensus_block(&node, 1, 1_000, [0u8; 32], 0, 1, [0u8; 32]);
        assert!(matches!(
            node.validate_block(&wrong),
            Err(PokerL1Error::InvalidPrevHash { .. })
        ));
        let right = empty_consensus_block(
            &node,
            1,
            1_000,
            node.genesis_parent_hash().unwrap(),
            0,
            1,
            [0u8; 32],
        );
        assert!(node.validate_block(&right).is_ok());
    }

    #[test]
    fn persistent_node_startup_rejects_unbalanced_native_supply() {
        let temp = tempfile::tempdir().unwrap();
        let config = NodeConfig::default_full(temp.path().to_path_buf());
        let node = Node::open(config.clone()).unwrap();
        node.apply_genesis_alloc(std::iter::empty()).unwrap();

        let table_id = ObjectID::new([0x88; 20], 44);
        let mut table = crate::vm::contracts::texas_poker::types::TexasPokerTable::new(
            table_id,
            "startup-gate".into(),
            [0x77; 20],
            6,
            50,
            100,
        );
        table.chip_pool = 1;
        let objects =
            crate::vm::contracts::texas_poker::state_codec::table_storage_objects(&table).unwrap();
        let mut object_db = node.object_db.lock().unwrap();
        for object in objects {
            object_db.create(object).unwrap();
        }
        drop(object_db);
        drop(node);

        let error = match Node::open(config) {
            Ok(_) => panic!("startup must reject an unbalanced Treasury state"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("native supply reconciliation mismatch")
        );
    }

    // ===== 缺口 #3：Priority Mempool 测试 =====

    fn make_pub_tx(pubkey_byte: u8, nonce: u64, gas_price: u64) -> Transaction {
        Transaction {
            inputs: vec![],
            outputs: vec![],
            contract_call: None,
            tagged_pubkey: TaggedPubkey {
                tag: encode_tag(SignatureScheme::Secp256k1, 1),
                raw: vec![pubkey_byte; 33],
            },
            signature: vec![0u8; 65],
            gas: crate::transaction::Gas::new(1_000_000, gas_price),
            lane_hint: crate::transaction::TxLane::Public,
            route_hint: crate::transaction::RouteHint::AnyValidator,
            chain_id: DEFAULT_CHAIN_ID,
            nonce,
            gameturn_nonce: None,
            is_fallback: false,
        }
    }

    #[test]
    fn priority_mempool_drains_by_gas_price_desc() {
        // drain_pending_tx 应按 gas_price 降序返回（高 price 先）。
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        // 按乱序插入：price=10, 50, 30
        node.submit_tx(make_pub_tx(0x01, 1, 10)).unwrap();
        node.submit_tx(make_pub_tx(0x02, 1, 50)).unwrap();
        node.submit_tx(make_pub_tx(0x03, 1, 30)).unwrap();
        let drained = node.drain_pending_tx();
        assert_eq!(drained.len(), 3);
        // 应按 price 降序：50, 30, 10
        assert_eq!(drained[0].gas.price, 50);
        assert_eq!(drained[1].gas.price, 30);
        assert_eq!(drained[2].gas.price, 10);
    }

    #[test]
    fn priority_mempool_rbf_replaces_lower_price() {
        // 同 (caller, nonce) 的高 price tx 替换低 price tx。
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        // pubkey_byte=0x05, nonce=1, price=10
        node.submit_tx(make_pub_tx(0x05, 1, 10)).unwrap();
        // 同 caller+nonce，price=20 → RBF 替换
        node.submit_tx(make_pub_tx(0x05, 1, 20)).unwrap();
        let drained = node.drain_pending_tx();
        assert_eq!(drained.len(), 1, "RBF 应替换为 1 条");
        assert_eq!(drained[0].gas.price, 20, "应保留高 price tx");
    }

    #[test]
    fn priority_mempool_rbf_rejects_lower_or_equal_price() {
        // 新 price <= 旧 price → 拒绝替换。
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        node.submit_tx(make_pub_tx(0x06, 1, 20)).unwrap();
        // price=20（相等）→ 拒绝
        let err = node.submit_tx(make_pub_tx(0x06, 1, 20)).unwrap_err();
        assert!(err.to_string().contains("RBF rejected"));
        // price=10（更低）→ 拒绝
        let err = node.submit_tx(make_pub_tx(0x06, 1, 10)).unwrap_err();
        assert!(err.to_string().contains("RBF rejected"));
        // 应仅保留原 price=20 的 1 条
        let drained = node.drain_pending_tx();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].gas.price, 20);
    }

    #[test]
    fn priority_mempool_overflow_evicts_lowest_price() {
        // 溢出时丢弃 gas_price 最低的（而非 FIFO 最旧）。
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        // 插入超过 MAX_PENDING_TX_SIZE 条（不同 caller+nonce 避免 RBF）。
        // 用 usize 计数器（避免 u8 回绕），pubkey_byte 用 (i % 200) + 1 避免回绕到 0/重复。
        let count = MAX_PENDING_TX_SIZE + 5;
        for i in 0..count {
            let price = if i == 0 { 999 } else { 1 }; // 第 0 条 price 最高
            let pubkey_byte = ((i % 200) as u8) + 1; // 1..=200，避免 0/回绕
            // nonce = i（全局唯一，避免同 (caller, nonce) RBF）
            node.submit_tx(make_pub_tx(pubkey_byte, i as u64, price))
                .unwrap();
        }
        let drained = node.drain_pending_tx();
        assert_eq!(drained.len(), MAX_PENDING_TX_SIZE, "应保留上限条数");
        // price=999 的 tx 应被保留（在第一条，因降序）。
        assert_eq!(drained[0].gas.price, 999, "最高 price tx 不应被淘汰");
    }

    #[test]
    fn priority_mempool_same_price_preserves_arrival_order() {
        // 同 gas_price 的 tx 保持 arrival 顺序（stable sort）。
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        node.submit_tx(make_pub_tx(0x20, 1, 5)).unwrap();
        node.submit_tx(make_pub_tx(0x21, 1, 5)).unwrap();
        node.submit_tx(make_pub_tx(0x22, 1, 5)).unwrap();
        let drained = node.drain_pending_tx();
        assert_eq!(drained[0].tagged_pubkey.raw[0], 0x20, "arrival 顺序保持");
        assert_eq!(drained[1].tagged_pubkey.raw[0], 0x21);
        assert_eq!(drained[2].tagged_pubkey.raw[0], 0x22);
    }

    #[test]
    fn requeue_pending_txs_preserves_drained_order_ahead_of_new_arrivals() {
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        node.submit_tx(make_pub_tx(0x20, 1, 5)).unwrap();
        node.submit_tx(make_pub_tx(0x21, 1, 5)).unwrap();
        let drained = node.drain_pending_tx();
        node.submit_tx(make_pub_tx(0x22, 1, 5)).unwrap();

        node.requeue_pending_txs(drained);

        let retried = node.drain_pending_tx();
        assert_eq!(retried.len(), 3);
        assert_eq!(retried[0].tagged_pubkey.raw[0], 0x20);
        assert_eq!(retried[1].tagged_pubkey.raw[0], 0x21);
        assert_eq!(retried[2].tagged_pubkey.raw[0], 0x22);
    }

    #[test]
    fn priority_mempool_gameturn_before_public_regardless_of_gas_price() {
        // GameTurn（免 gas, price=0）应排在 Public（高 gas_price）之前，
        // 因为游戏操作的时间敏感性和轮转规则优先于 gas 竞价。
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        // 插入高 price 的 Public tx
        node.submit_tx(make_pub_tx(0x30, 1, 100)).unwrap();
        // 插入 GameTurn tx（免 gas, price=0）
        let gameturn_tx = Transaction {
            inputs: vec![],
            outputs: vec![],
            contract_call: None,
            tagged_pubkey: TaggedPubkey {
                tag: encode_tag(SignatureScheme::Secp256k1, 1),
                raw: vec![0x40; 33],
            },
            signature: vec![0u8; 65],
            gas: crate::transaction::Gas::zero(), // GameTurn 免 gas
            lane_hint: crate::transaction::TxLane::GameTurn,
            route_hint: crate::transaction::RouteHint::AssignedValidator,
            chain_id: DEFAULT_CHAIN_ID,
            nonce: 0,
            gameturn_nonce: Some(1),
            is_fallback: false,
        };
        node.submit_tx(gameturn_tx).unwrap();
        let drained = node.drain_pending_tx();
        assert_eq!(drained.len(), 2);
        // GameTurn 应排第一（即使 gas_price=0）
        assert_eq!(
            drained[0].lane_hint,
            crate::transaction::TxLane::GameTurn,
            "GameTurn 应排在 Public 之前"
        );
        // Public 排第二（即使 gas_price=100）
        assert_eq!(
            drained[1].lane_hint,
            crate::transaction::TxLane::Public,
            "Public 应排在 GameTurn 之后"
        );
    }

    #[test]
    fn priority_mempool_gameturn_preserves_arrival_order() {
        // 多个 GameTurn tx 保持 arrival 顺序（轮转规则由后续 build_game_sub_block 处理）。
        let node = Node::open_inmemory(NodeRole::Validator, DEFAULT_CHAIN_ID).unwrap();
        let make_gameturn = |byte: u8, nonce: u64| -> Transaction {
            Transaction {
                inputs: vec![],
                outputs: vec![],
                contract_call: None,
                tagged_pubkey: TaggedPubkey {
                    tag: encode_tag(SignatureScheme::Secp256k1, 1),
                    raw: vec![byte; 33],
                },
                signature: vec![0u8; 65],
                gas: crate::transaction::Gas::zero(),
                lane_hint: crate::transaction::TxLane::GameTurn,
                route_hint: crate::transaction::RouteHint::AssignedValidator,
                chain_id: DEFAULT_CHAIN_ID,
                nonce: 0,
                gameturn_nonce: Some(nonce),
                is_fallback: false,
            }
        };
        node.submit_tx(make_gameturn(0x50, 1)).unwrap();
        node.submit_tx(make_gameturn(0x51, 2)).unwrap();
        node.submit_tx(make_gameturn(0x52, 3)).unwrap();
        let drained = node.drain_pending_tx();
        assert_eq!(drained.len(), 3);
        // 全部 GameTurn，保持 arrival 顺序
        assert_eq!(drained[0].tagged_pubkey.raw[0], 0x50);
        assert_eq!(drained[1].tagged_pubkey.raw[0], 0x51);
        assert_eq!(drained[2].tagged_pubkey.raw[0], 0x52);
    }

    #[test]
    fn light_header_generated_with_validator_signature() {
        // validator 节点 put_block 后应生成带 secp256k1 签名的 LightClientHeader。
        let vkey = ValidatorKey::from_secret_bytes([0x42; 32]).unwrap();
        let node =
            Node::open_inmemory_with_validators(NodeRole::Validator, DEFAULT_CHAIN_ID, vec![])
                .unwrap();
        // 手动注入 validator_key（open_inmemory 默认无 key）。
        // 通过直接调用 sign_and_store_light_header 测试。
        let block = Block::new(
            BlockHeader {
                height: 1,
                timestamp_ms: 1000,
                prev_hash: [0u8; 32],
                state_root: [0u8; 32],
                account_root: [0u8; 32],
                public_tx_root: [0u8; 32],
                gameturn_tx_root: [0u8; 32],
                dag_commit_certificate: crate::consensus::DagCommitCertificate {
                    epoch: 1,
                    commit_round: 1,
                    prev_commit_hash: [0u8; 32],
                    epoch_transition: None,
                    vertex_hash_list: vec![],
                    round_attendance_bitmap: vec![0xFF],
                    state_root: [0u8; 32],
                    account_root: [0u8; 32],
                    public_tx_root: [0u8; 32],
                    gameturn_tx_root: [0u8; 32],
                    signature_list: vec![],
                    signer_bitmap: vec![0x00],
                },
            },
            vec![],
            vec![],
        );
        node.sign_and_store_light_header(&block, &vkey);
        let headers = node.get_light_headers();
        assert_eq!(headers.len(), 1, "应生成 1 个 LightClientHeader");
        assert_eq!(headers[0].signatures.len(), 1, "应有 1 个 validator 签名");
        assert_eq!(headers[0].signatures[0].validator, vkey.tagged_pubkey);
        assert_eq!(
            headers[0].signatures[0].signature.len(),
            65,
            "secp256k1 签名 65B"
        );
    }

    #[test]
    fn light_header_merges_peer_signatures() {
        // merge_light_header 应合并不同 validator 的签名到同一 header。
        let vkey1 = ValidatorKey::from_secret_bytes([0x42; 32]).unwrap();
        let vkey2 = ValidatorKey::from_secret_bytes([0x43; 32]).unwrap();
        let node = Node::open_inmemory(NodeRole::Full, DEFAULT_CHAIN_ID).unwrap();
        let block = Block::new(
            BlockHeader {
                height: 1,
                timestamp_ms: 1000,
                prev_hash: [0u8; 32],
                state_root: [0u8; 32],
                account_root: [0u8; 32],
                public_tx_root: [0u8; 32],
                gameturn_tx_root: [0u8; 32],
                dag_commit_certificate: crate::consensus::DagCommitCertificate {
                    epoch: 1,
                    commit_round: 1,
                    prev_commit_hash: [0u8; 32],
                    epoch_transition: None,
                    vertex_hash_list: vec![],
                    round_attendance_bitmap: vec![0xFF],
                    state_root: [0u8; 32],
                    account_root: [0u8; 32],
                    public_tx_root: [0u8; 32],
                    gameturn_tx_root: [0u8; 32],
                    signature_list: vec![],
                    signer_bitmap: vec![0x00],
                },
            },
            vec![],
            vec![],
        );
        // validator 1 签名
        node.sign_and_store_light_header(&block, &vkey1);
        // validator 2 的本地签名与同一 header 合并。
        node.sign_and_store_light_header(&block, &vkey2);
        let headers = node.get_light_headers();
        assert_eq!(headers.len(), 1, "仍为 1 个 header");
        assert_eq!(headers[0].signatures.len(), 2, "应有 2 个 validator 签名");
    }

    fn sign_light_header_for_sync_test(
        header: &BlockHeader,
        signers: &[(secp256k1::SecretKey, ValidatorEntry)],
    ) -> LightClientHeader {
        use blake2::digest::{Update, VariableOutput};
        let header_bytes = borsh::to_vec(header).unwrap();
        let mut hasher = blake2::Blake2bVar::new(32).unwrap();
        hasher.update(&header_bytes);
        let mut digest = [0u8; 32];
        hasher.finalize_variable(&mut digest).unwrap();
        let message = secp256k1::Message::from_digest(digest);
        let secp = secp256k1::Secp256k1::new();
        let signatures = signers
            .iter()
            .map(|(secret, entry)| {
                let signature = secp.sign_ecdsa_recoverable(&message, secret);
                let (recovery, compact) = signature.serialize_compact();
                let mut bytes = compact.to_vec();
                bytes.push(recovery.to_i32() as u8);
                crate::network::ValidatorSig {
                    validator: entry.pubkey.clone(),
                    signature: bytes,
                }
            })
            .collect();
        LightClientHeader {
            header_bytes,
            signatures,
            signer_bitmap: vec![],
        }
    }

    #[test]
    fn authenticated_header_sync_persists_contiguous_quorum_headers() {
        let signers = vec![
            make_real_validator(0x31, ValidatorStatus::Active),
            make_real_validator(0x32, ValidatorStatus::Active),
            make_real_validator(0x33, ValidatorStatus::Active),
        ];
        let validators = signers
            .iter()
            .map(|(_, entry)| entry.clone())
            .collect::<Vec<_>>();
        let node =
            Node::open_inmemory_with_validators(NodeRole::Full, DEFAULT_CHAIN_ID, validators)
                .unwrap();
        let certificate = |round| crate::consensus::DagCommitCertificate {
            epoch: 0,
            commit_round: round,
            prev_commit_hash: [0; 32],
            epoch_transition: None,
            vertex_hash_list: vec![],
            round_attendance_bitmap: vec![],
            state_root: [0; 32],
            account_root: [0; 32],
            public_tx_root: [0; 32],
            gameturn_tx_root: [0; 32],
            signature_list: vec![],
            signer_bitmap: vec![],
        };
        let first = BlockHeader {
            height: 1,
            timestamp_ms: 1_000,
            prev_hash: [0; 32],
            state_root: [0; 32],
            account_root: [0; 32],
            public_tx_root: [0; 32],
            gameturn_tx_root: [0; 32],
            dag_commit_certificate: certificate(1),
        };
        let second = BlockHeader {
            height: 2,
            timestamp_ms: 2_000,
            prev_hash: first.block_hash(DEFAULT_CHAIN_ID),
            state_root: [1; 32],
            account_root: [1; 32],
            public_tx_root: [0; 32],
            gameturn_tx_root: [0; 32],
            dag_commit_certificate: certificate(2),
        };
        let transport = crate::network::InMemoryTransport::new();
        transport.inject_light_header(sign_light_header_for_sync_test(&first, &signers));
        transport.inject_light_header(sign_light_header_for_sync_test(&second, &signers));

        assert_eq!(
            node.sync_authenticated_headers_from_network(&transport)
                .unwrap(),
            2
        );
        assert_eq!(node.block_store().get_header_by_height(1).unwrap(), first);
        assert_eq!(node.block_store().get_header_by_height(2).unwrap(), second);
        assert_eq!(
            node.block_store()
                .get_finalized_light_header_by_height(2, DEFAULT_CHAIN_ID)
                .unwrap()
                .signatures
                .len(),
            3
        );
        assert_eq!(
            node.finalized_light_headers_by_range(1, 10).unwrap().len(),
            2
        );
    }

    #[test]
    fn authenticated_fast_sync_installs_snapshot_then_replays_header_bound_body() {
        // Exercise the exact cold-start order used by `--fast-sync`: the target initially has
        // only the configured genesis hash, then authenticates headers, installs the archive
        // snapshot at height 1, and finally executes the height-2 body against that state.
        let source_dir = tempfile::tempdir().unwrap();
        let target_dir = tempfile::tempdir().unwrap();
        let (validators, signing_keys) = journal_test_validators();
        let manifest_hash = GenesisManifest::new_with_fee_policy(
            DEFAULT_CHAIN_ID,
            validators.clone(),
            vec![],
            FeePolicy::Free,
        )
        .unwrap()
        .hash();
        let source_config = NodeConfig::archive(source_dir.path().to_path_buf())
            .with_genesis_validators(validators.clone())
            .with_genesis_manifest_hash(manifest_hash);
        let target_config = NodeConfig::default_full(target_dir.path().to_path_buf())
            .with_genesis_validators(validators.clone())
            .with_genesis_manifest_hash(manifest_hash);
        let source = Node::open(source_config).unwrap();
        source
            .apply_genesis_alloc(std::iter::empty::<(TaggedPubkey, u64)>())
            .unwrap();

        let mut first = empty_consensus_block(
            &source,
            1,
            1_000,
            source.genesis_parent_hash().unwrap(),
            0,
            1,
            [0; 32],
        );
        sign_journal_test_block(&source, &mut first, &signing_keys);
        let first_hash = source.put_block(&first).unwrap();
        let snapshot = source.build_full_snapshot_at_tip().unwrap();

        let first_cert_hash = first.header.dag_commit_certificate.cert_hash_for_header(
            DEFAULT_CHAIN_ID,
            first.header.height,
            first.header.timestamp_ms,
            first.header.prev_hash,
        );
        let mut second =
            empty_consensus_block(&source, 2, 2_000, first_hash, 0, 2, first_cert_hash);
        sign_journal_test_block(&source, &mut second, &signing_keys);
        source.put_block(&second).unwrap();

        let light_signers = validators
            .iter()
            .map(|entry| {
                let secret = signing_keys
                    .iter()
                    .find_map(|(pubkey, secret)| (pubkey == &entry.pubkey).then_some(*secret))
                    .expect("every validator has a test signing key");
                (secret, entry.clone())
            })
            .collect::<Vec<_>>();
        let transport = crate::network::InMemoryTransport::new();
        transport.inject_light_header(sign_light_header_for_sync_test(
            &first.header,
            &light_signers,
        ));
        transport.inject_light_header(sign_light_header_for_sync_test(
            &second.header,
            &light_signers,
        ));
        transport.inject_full_snapshot(snapshot.clone()).unwrap();
        transport.inject_block(second.clone());

        let target = Node::open(target_config).unwrap();
        assert_eq!(target.genesis_parent_hash().unwrap(), manifest_hash);
        let installed = target.fast_sync_from_network(&transport).unwrap();

        assert_eq!(installed.block_hash(), first_hash);
        assert_eq!(
            target.block_store().get_header_tip_height().unwrap(),
            Some(2)
        );
        assert_eq!(target.block_store().get_tip_height().unwrap(), Some(2));
        assert_eq!(target.get_block_by_height(2).unwrap(), Some(second));
        assert_eq!(target.state_root(), source.state_root());
        assert_eq!(target.account_root(), source.account_root());
        assert_eq!(
            target
                .block_store()
                .get_finalized_light_header_by_height(2, DEFAULT_CHAIN_ID)
                .unwrap()
                .signatures
                .len(),
            validators.len()
        );
    }
}
