//! 状态裁剪与存储管理（Task 29 — SubTask 29.1~29.8）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）+ tasks.md Task 29：
//! - **SubTask 29.1**：Game 结算 + dispute_window 过期 → 裁剪中间版本，
//!   保留最终版本 + state root commitment
//! - **SubTask 29.2**：block 距 finality 过 `tx_prune_after_blocks`（默认 1000）
//!   + block 内所有 Game 结算 + dispute 过期 → tx 压缩为
//!     `(tx_hash, tx_type, merkle_proof)`；block header 的 `tx_merkle_root` 永久保留
//! - **SubTask 29.3**：vertex 距 finality 过 `vertex_prune_after_blocks`
//!   （默认 10000，NEW-M13）→ 丢弃 `tx_list` + `parent_hashes` 详情，
//!   保留 `(round, author, vertex_hash, tx_count, parent_count, author_sig)`
//! - **SubTask 29.4**：ZK proof 归档到 Walrus DA 层；链上仅保留
//!   `(proof_hash, verification_result, walrus_blob_id)`；
//!   archive node < `archive_node_min_count`（默认 3）时不得裁剪
//! - **SubTask 29.5**：永久保留项清单（block header / ValidatorSet 变更 /
//!   治理参数变更 / Game 最终结算 / slashing 证据等）
//! - **SubTask 29.6**：节点角色分层（archive / full / light）
//! - **SubTask 29.7**：数据可恢复性（`request_historical_data` RPC）
//! - **SubTask 29.8**：Compact Block Relay 协同
//!
//! # 安全约束
//!
//! - **SEC-M7 修复**：Walrus blob 多副本续费 + 失败处理（replica_count >= 3）
//! - **SEC-M8 修复**：永久保留项清单补全（force_checkpoint evidence /
//!   challenge_delta 证据 / request_revert 证据 / ZK proof hash 链等）
//! - **SEC2-M5 修复**：archive node 勾结检测（PoSt 存储证明）

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};
use rocksdb::{DB, Options};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Mutex;

use crate::Hash;
use crate::consensus::{DagVertex, Epoch, Round};
use crate::error::{PokerL1Error, PokerL1Result};
use crate::signature::TaggedPubkey;
use crate::transaction::{Transaction, TxLane};

// ===== 常量 =====

/// 历史 tx 裁剪窗口（SubTask 29.2，默认 1000 block）。
///
/// block 距 finality 过此窗口 + block 内所有 Game 结算 + dispute 过期 →
/// tx 内容压缩为 `(tx_hash, tx_type, merkle_proof)`。
pub const DEFAULT_TX_PRUNE_AFTER_BLOCKS: u64 = 1000;

/// DAG vertex 裁剪窗口（SubTask 29.3，NEW-M13：默认 10000 block）。
///
/// vertex 所在 round 距 finality 过此窗口 → 丢弃 `tx_list` + `parent_hashes` 详情，
/// 保留 `(round, author, vertex_hash, tx_count, parent_count, author_sig)`。
pub const DEFAULT_VERTEX_PRUNE_AFTER_BLOCKS: u64 = 10_000;

/// archive node 最少数量（SubTask 29.4，默认 3）。
///
/// archive node 数量 < 此值时不得裁剪（R5-M7）。
pub const DEFAULT_ARCHIVE_NODE_MIN_COUNT: u32 = 3;

/// archive 保留窗口（SubTask 29.4，SEC-M7：Walrus blob 续费覆盖期）。
///
/// da_storage_fee 覆盖 `dispute_window_blocks + archive_retention_blocks`。
pub const DEFAULT_ARCHIVE_RETENTION_BLOCKS: u64 = 100_000;

/// ZK proof Walrus 副本数下限（SEC-M7：replica_count >= 3）。
pub const MIN_ZK_PROOF_REPLICA_COUNT: u32 = 3;

// ===== NodeRole（SubTask 29.6）=====

/// 节点角色分层（SubTask 29.6）。
///
/// - [`NodeRole::Archive`]：永不裁剪，提供 `request_historical_data` RPC
/// - [`NodeRole::Full`]：Layer 1-3 裁剪（tx / vertex / ZK proof）
/// - [`NodeRole::Light`]：仅 block header + state root commitment
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeRole {
    /// Archive node：永不裁剪，保留全数据，提供历史数据 RPC。
    Archive,
    /// Full node：Layer 1-3 裁剪（tx / vertex / ZK proof）。
    Full,
    /// Light node：仅 block header + state root commitment 订阅。
    Light,
}

impl NodeRole {
    /// 是否应执行裁剪（SubTask 29.6）。
    ///
    /// Archive node 永不裁剪；Full node 执行 Layer 1-3 裁剪；Light node 无完整数据可裁剪。
    #[must_use]
    pub const fn should_prune(self) -> bool {
        matches!(self, Self::Full)
    }

    /// 是否保留全数据（SubTask 29.6）。
    #[must_use]
    pub const fn retains_full_data(self) -> bool {
        matches!(self, Self::Archive)
    }

    /// 是否仅保留 block header（SubTask 29.6）。
    #[must_use]
    pub const fn is_light(self) -> bool {
        matches!(self, Self::Light)
    }

    /// 是否可响应 `request_historical_data` RPC（SubTask 29.7）。
    #[must_use]
    pub const fn can_serve_historical_data(self) -> bool {
        matches!(self, Self::Archive)
    }
}

// ===== PruningConfig =====

/// 裁剪可治理参数（SubTask 29.1~29.4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PruningConfig {
    /// 历史 tx 裁剪窗口（默认 1000）。
    pub tx_prune_after_blocks: u64,
    /// DAG vertex 裁剪窗口（默认 10000，NEW-M13）。
    pub vertex_prune_after_blocks: u64,
    /// 争议窗口（block 数，dispute 过期判定）。
    pub dispute_window_blocks: u64,
    /// archive node 最少数量（默认 3）。
    pub archive_node_min_count: u32,
    /// archive 保留窗口（默认 100000）。
    pub archive_retention_blocks: u64,
}

impl Default for PruningConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl PruningConfig {
    /// 创建默认配置。
    #[must_use]
    pub const fn new() -> Self {
        Self {
            tx_prune_after_blocks: DEFAULT_TX_PRUNE_AFTER_BLOCKS,
            vertex_prune_after_blocks: DEFAULT_VERTEX_PRUNE_AFTER_BLOCKS,
            dispute_window_blocks: 200, // 与 TimeConsensusConfig 默认一致
            archive_node_min_count: DEFAULT_ARCHIVE_NODE_MIN_COUNT,
            archive_retention_blocks: DEFAULT_ARCHIVE_RETENTION_BLOCKS,
        }
    }
}

// ===== PrunedTx（SubTask 29.2）=====

/// 压缩后的 tx commitment（SubTask 29.2）。
///
/// block 距 finality 过 `tx_prune_after_blocks` + 所有 Game 结算 + dispute 过期 →
/// 丢弃完整 tx 内容，仅保留此结构。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrunedTx {
    /// 交易哈希（永久保留，用于检索与验证）。
    pub tx_hash: Hash,
    /// 交易通道类型（Public / GameTurn / CheckpointAnchor / ForceSync）。
    pub tx_type: TxLane,
    /// Merkle 证明（证明 tx 在 block 的 tx_merkle_tree 中）。
    pub merkle_proof: Vec<u8>,
}

// ===== PrunedVertex（SubTask 29.3）=====

/// 压缩后的 vertex commitment（SubTask 29.3）。
///
/// vertex 距 finality 过 `vertex_prune_after_blocks` →
/// 丢弃 `tx_list` + `parent_hashes` 详情，保留此结构。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrunedVertex {
    /// DAG round（全局递增）。
    pub round: Round,
    /// 当前 epoch（SEC-C1：绑定 epoch）。
    pub epoch: Epoch,
    /// 作者 validator 的 tagged pubkey。
    pub author_pubkey: TaggedPubkey,
    /// vertex 内容哈希（永久保留，用于 DAG 引用验证）。
    pub vertex_hash: Hash,
    /// 原始 tx_list 长度。
    pub tx_count: u32,
    /// 原始 parent_hashes 长度。
    pub parent_count: u32,
    /// 作者 validator 的 secp256k1 签名（slashing 证据用）。
    pub author_sig: Vec<u8>,
}

// ===== ArchivedZkProof（SubTask 29.4）=====

/// 归档到 Walrus DA 层的 ZK proof 摘要（SubTask 29.4）。
///
/// checkin 的 (π, Δ, ack_chain) 所在 Game 结算 + dispute 过期 →
/// π 移到 Walrus DA 层，链上仅保留此结构。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchivedZkProof {
    /// proof_hash = blake2b(π || Δ || ack_chain)（永久保留，R5-M7）。
    pub proof_hash: Hash,
    /// ZK 验证结果（永久保留，即使 blob 过期也保留）。
    pub verification_result: bool,
    /// Walrus blob ID（用于检索完整 proof）。
    pub walrus_blob_id: [u8; 32],
    /// blob 是否已过期（SEC-M7：续费失败后标记）。
    pub blob_expired: bool,
}

// ===== PruningEligibility =====

/// 裁剪资格判定结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PruningEligibility {
    /// 可裁剪。
    CanPrune,
    /// 不可裁剪（含原因）。
    CannotPrune(&'static str),
}

impl PruningEligibility {
    /// 是否可裁剪。
    #[must_use]
    pub const fn can_prune(self) -> bool {
        matches!(self, Self::CanPrune)
    }
}

// ===== 资格判定函数 =====

/// 判定 Game 对象中间版本是否可裁剪（SubTask 29.1）。
///
/// # 条件
/// 1. Game 已结算（`game_settled = true`）
/// 2. dispute_window 已过期（`dispute_window_passed = true`）
///
/// # 参数
/// - `game_settled`：Game 是否已结算
/// - `dispute_window_passed`：dispute_window 是否已过
#[must_use]
pub const fn check_game_pruning_eligibility(
    game_settled: bool,
    dispute_window_passed: bool,
) -> PruningEligibility {
    if !game_settled {
        return PruningEligibility::CannotPrune("game not settled");
    }
    if !dispute_window_passed {
        return PruningEligibility::CannotPrune("dispute window not expired");
    }
    PruningEligibility::CanPrune
}

/// 判定 block 内 tx 是否可裁剪（SubTask 29.2）。
///
/// # 条件
/// 1. block 距 finality 已过 `tx_prune_after_blocks`
/// 2. block 内所有 Game 已结算
/// 3. block 内所有 dispute 已过期
///
/// # 参数
/// - `block_finality_age`：block 距 finality 的 block 数
/// - `tx_prune_after_blocks`：tx 裁剪窗口（默认 1000）
/// - `all_games_settled`：block 内所有 Game 是否已结算
/// - `all_disputes_expired`：block 内所有 dispute 是否已过期
#[must_use]
pub const fn check_tx_pruning_eligibility(
    block_finality_age: u64,
    tx_prune_after_blocks: u64,
    all_games_settled: bool,
    all_disputes_expired: bool,
) -> PruningEligibility {
    if block_finality_age < tx_prune_after_blocks {
        return PruningEligibility::CannotPrune("tx_prune_after_blocks not reached");
    }
    if !all_games_settled {
        return PruningEligibility::CannotPrune("block has unsettled games");
    }
    if !all_disputes_expired {
        return PruningEligibility::CannotPrune("block has active disputes");
    }
    PruningEligibility::CanPrune
}

/// 判定 DAG vertex 是否可裁剪（SubTask 29.3）。
///
/// # 条件
/// 1. vertex 所在 round 距 finality 已过 `vertex_prune_after_blocks`
///
/// # 参数
/// - `vertex_finality_age`：vertex 距 finality 的 block 数
/// - `vertex_prune_after_blocks`：vertex 裁剪窗口（默认 10000，NEW-M13）
#[must_use]
pub const fn check_vertex_pruning_eligibility(
    vertex_finality_age: u64,
    vertex_prune_after_blocks: u64,
) -> PruningEligibility {
    if vertex_finality_age < vertex_prune_after_blocks {
        return PruningEligibility::CannotPrune("vertex_prune_after_blocks not reached");
    }
    PruningEligibility::CanPrune
}

/// 判定 ZK proof 是否可归档到 DA 层（SubTask 29.4）。
///
/// # 条件
/// 1. Game 已结算
/// 2. dispute_window 已过期
/// 3. archive node 数量 >= `archive_node_min_count`
///
/// # 参数
/// - `game_settled`：Game 是否已结算
/// - `dispute_window_passed`：dispute_window 是否已过
/// - `archive_node_count`：当前 archive node 数量
/// - `archive_node_min_count`：archive node 最少数量（默认 3）
#[must_use]
pub const fn check_zk_proof_pruning_eligibility(
    game_settled: bool,
    dispute_window_passed: bool,
    archive_node_count: u32,
    archive_node_min_count: u32,
) -> PruningEligibility {
    if !game_settled {
        return PruningEligibility::CannotPrune("game not settled");
    }
    if !dispute_window_passed {
        return PruningEligibility::CannotPrune("dispute window not expired");
    }
    if archive_node_count < archive_node_min_count {
        return PruningEligibility::CannotPrune("archive node count < min");
    }
    PruningEligibility::CanPrune
}

/// 判定 archive node 数量是否充足（SubTask 29.4）。
#[must_use]
pub const fn is_archive_node_sufficient(
    archive_node_count: u32,
    archive_node_min_count: u32,
) -> bool {
    archive_node_count >= archive_node_min_count
}

// ===== 裁剪转换函数 =====

/// 将完整 tx 压缩为 PrunedTx（SubTask 29.2）。
///
/// 丢弃完整 tx 内容，仅保留 `(tx_hash, tx_type, merkle_proof)`。
///
/// # 参数
/// - `tx`：完整交易
/// - `merkle_proof`：tx 在 block 的 tx_merkle_tree 中的 Merkle 证明
#[must_use]
pub fn prune_tx(tx: &Transaction, merkle_proof: Vec<u8>) -> PrunedTx {
    PrunedTx {
        tx_hash: tx.tx_hash(),
        tx_type: tx.lane_hint,
        merkle_proof,
    }
}

/// 将完整 vertex 压缩为 PrunedVertex（SubTask 29.3）。
///
/// 丢弃 `tx_list` + `parent_hashes` 详情，
/// 保留 `(round, epoch, author_pubkey, vertex_hash, tx_count, parent_count, author_sig)`。
#[must_use]
pub fn prune_vertex(vertex: &DagVertex) -> PrunedVertex {
    PrunedVertex {
        round: vertex.round,
        epoch: vertex.epoch,
        author_pubkey: vertex.author_pubkey.clone(),
        vertex_hash: vertex.vertex_hash(),
        tx_count: u32::try_from(vertex.tx_list.len()).unwrap_or(u32::MAX),
        parent_count: u32::try_from(vertex.parent_hashes.len()).unwrap_or(u32::MAX),
        author_sig: vertex.author_sig.clone(),
    }
}

/// 计算 ZK proof 的 proof_hash（SubTask 29.4 / R5-M7）。
///
/// `proof_hash = blake2b_256(π || Δ || ack_chain)`
#[must_use]
pub fn compute_proof_hash(proof: &[u8], state_delta: &[u8], ack_chain: &[u8]) -> Hash {
    let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32) 初始化不应失败");
    hasher.update(proof);
    hasher.update(state_delta);
    hasher.update(ack_chain);
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("Blake2bVar finalize 不应失败");
    out
}

/// 归档 ZK proof 到 DA 层（SubTask 29.4）。
///
/// 链上仅保留 `(proof_hash, verification_result, walrus_blob_id)`。
///
/// # 参数
/// - `proof`：ZK proof 字节
/// - `state_delta`：状态增量 Δ
/// - `ack_chain`：ACK 链
/// - `verification_result`：ZK 验证结果
/// - `walrus_blob_id`：Walrus DA 层返回的 blob ID
#[must_use]
pub fn archive_zk_proof(
    proof: &[u8],
    state_delta: &[u8],
    ack_chain: &[u8],
    verification_result: bool,
    walrus_blob_id: [u8; 32],
) -> ArchivedZkProof {
    ArchivedZkProof {
        proof_hash: compute_proof_hash(proof, state_delta, ack_chain),
        verification_result,
        walrus_blob_id,
        blob_expired: false,
    }
}

// ===== 永久保留项（SubTask 29.5 / SEC-M8）=====

/// 永久保留项类型（SubTask 29.5 / SEC-M8）。
///
/// 这些项写入 archive node 永不裁剪，full node 可仅保留最近 N=10000 block 的详情。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PermanentRetentionItem {
    /// block header（永久保留）。
    BlockHeader,
    /// ValidatorSet 变更记录（含 slashing 证据 + 罚没金额）。
    ValidatorSetChange,
    /// 治理参数变更记录（参数名 / 旧值 / 新值 / 生效 height）。
    GovernanceParamChange,
    /// Game 最终结算版本 + 台费分配。
    GameFinalSettlement,
    /// Slashing 证据（vertex equivocation / 停机 / 恶意 refuse_ack 累计）。
    SlashingEvidence,
    /// force_checkpoint evidence 全量（SEC-M8）。
    ForceCheckpointEvidence,
    /// challenge_delta 争议证据（SEC-M8）。
    ChallengeDeltaEvidence,
    /// request_revert 回退证据（SEC-M8）。
    RequestRevertEvidence,
    /// ZK proof 的 proof_hash + verification_result + walrus_blob_id（SEC-M8）。
    ZkProofHashChain,
    /// partial_checkin 锚点记录（SEC-M8）。
    PartialCheckinAnchor,
    /// rotate_validator_key tx 完整记录（SEC-M8）。
    RotateValidatorKeyRecord,
    /// UpgradeCap 升级 tx 记录（SEC-M8）。
    UpgradeCapRecord,
    /// verifier_status 切换记录（SEC-M8）。
    VerifierStatusSwitch,
    /// validator under_investigation_count 累积记录（SEC-M8）。
    UnderInvestigationRecord,
    /// 桥操作 burn_on_source + mint_on_target 凭证（SEC-M8）。
    BridgeOperation,
}

impl PermanentRetentionItem {
    /// 该项是否永久保留（所有 PermanentRetentionItem 均为永久保留）。
    #[must_use]
    pub const fn is_permanent(self) -> bool {
        true
    }

    /// full node 保留最近 N 个 block 的详情（SubTask 29.5）。
    pub const FULL_NODE_RECENT_BLOCKS: u64 = 10_000;
}

/// 判定给定项是否为永久保留项（SubTask 29.5）。
///
/// 永久保留项不可裁剪，即使 archive node 数量充足。
#[must_use]
pub const fn is_permanently_retained(item: PermanentRetentionItem) -> bool {
    item.is_permanent()
}

// ===== request_historical_data RPC（SubTask 29.7）=====

/// 历史数据检索请求（SubTask 29.7）。
///
/// `request_historical_data(tx_hash | vertex_hash | proof_hash)` RPC。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoricalDataRequest {
    /// 检索键（tx_hash / vertex_hash / proof_hash）。
    pub key: Hash,
    /// 检索类型。
    pub request_type: HistoricalDataType,
}

/// 历史数据检索类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HistoricalDataType {
    /// 按 tx_hash 检索完整 tx 内容。
    Transaction,
    /// 按 vertex_hash 检索完整 vertex 内容。
    DagVertex,
    /// 按 proof_hash 检索 ZK proof（从 Walrus DA 层）。
    ZkProof,
}

/// 历史数据检索结果（SubTask 29.7）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HistoricalDataResponse {
    /// 检索成功（返回数据）。
    Found(Vec<u8>),
    /// 数据不可用（Walrus blob 过期 / archive node 不足 / 裁剪后无法检索，R5-M7）。
    Unavailable(String),
}

/// Complete proof material recovered from an external archive provider.
///
/// Returning all three commitment components lets the node recompute the permanent
/// `proof_hash = H(proof || state_delta || ack_chain)` before exposing the payload to a client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ArchivedZkProofPayload {
    /// Recursive/underlying ZK proof bytes.
    pub proof: Vec<u8>,
    /// State-delta bytes bound into the proof commitment.
    pub state_delta: Vec<u8>,
    /// Acknowledgement chain bytes bound into the proof commitment.
    pub ack_chain: Vec<u8>,
    /// Provider-specific immutable blob ID used for diagnostics and caching.
    pub blob_id: [u8; 32],
}

/// Maximum encoded payload accepted by the built-in local archive.
///
/// A proof itself remains bounded by [`crate::offline::zk_verifier::MAX_ZK_PROOF_BYTES`]. The
/// wider envelope leaves room for the state-delta and acknowledgement-chain material that is
/// bound into the permanent proof hash, while keeping one archive/RPC record bounded.
pub const MAX_ARCHIVED_ZK_PROOF_PAYLOAD_BYTES: usize = 1024 * 1024;

/// Durable, content-addressed local implementation of [`ZkProofArchiveProvider`].
///
/// This is suitable for an Archive node's local replica or as the storage layer beneath a Walrus
/// adapter. It does not claim that a local disk is a consensus-authenticated archive quorum;
/// pruning remains disabled until that separate availability proof exists. Both writes and reads
/// verify the content hash so a corrupted record is never served as the requested proof.
pub struct RocksDbZkProofArchive {
    db: DB,
    /// RocksDB serializes a database path across processes. This lock also makes the
    /// read-then-write conflict check atomic among threads sharing this archive instance.
    write_lock: Mutex<()>,
}

impl RocksDbZkProofArchive {
    /// Open (or create) one durable proof archive at `path`.
    pub fn open(path: impl AsRef<Path>) -> PokerL1Result<Self> {
        let mut options = Options::default();
        options.create_if_missing(true);
        let db =
            DB::open(&options, path).map_err(|error| PokerL1Error::Rocksdb(error.to_string()))?;
        Ok(Self {
            db,
            write_lock: Mutex::new(()),
        })
    }

    /// Store one immutable content-addressed proof payload and return its permanent proof hash.
    ///
    /// Re-storing the exact same bytes is idempotent. A conflicting record for an existing hash
    /// is rejected instead of allowing provider metadata or payload bytes to be overwritten.
    pub fn store_proof(&self, payload: ArchivedZkProofPayload) -> PokerL1Result<Hash> {
        let proof_hash = validate_archived_zk_proof_payload(&payload)?;
        let _write_guard = self
            .write_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(existing) = self
            .db
            .get(proof_hash)
            .map_err(|error| PokerL1Error::Rocksdb(error.to_string()))?
        {
            let existing = decode_archived_zk_proof_payload(&existing, &proof_hash)?;
            if existing != payload {
                return Err(PokerL1Error::Other(
                    "conflicting payload already exists for this proof hash".into(),
                ));
            }
            return Ok(proof_hash);
        }
        self.db
            .put(proof_hash, borsh::to_vec(&payload)?)
            .map_err(|error| PokerL1Error::Rocksdb(error.to_string()))?;
        Ok(proof_hash)
    }
}

impl ZkProofArchiveProvider for RocksDbZkProofArchive {
    fn load_proof(&self, proof_hash: &Hash) -> PokerL1Result<Option<ArchivedZkProofPayload>> {
        let Some(encoded) = self
            .db
            .get(proof_hash)
            .map_err(|error| PokerL1Error::Rocksdb(error.to_string()))?
        else {
            return Ok(None);
        };
        Ok(Some(decode_archived_zk_proof_payload(
            &encoded, proof_hash,
        )?))
    }
}

fn decode_archived_zk_proof_payload(
    encoded: &[u8],
    expected_hash: &Hash,
) -> PokerL1Result<ArchivedZkProofPayload> {
    if encoded.len() > MAX_ARCHIVED_ZK_PROOF_PAYLOAD_BYTES {
        return Err(PokerL1Error::Other(format!(
            "local ZK proof archive record is {} bytes; limit is {}",
            encoded.len(),
            MAX_ARCHIVED_ZK_PROOF_PAYLOAD_BYTES,
        )));
    }
    let payload: ArchivedZkProofPayload = borsh::from_slice(encoded)?;
    if validate_archived_zk_proof_payload(&payload)? != *expected_hash {
        return Err(PokerL1Error::Other(
            "local ZK proof archive record does not match its content-addressed key".into(),
        ));
    }
    Ok(payload)
}

fn validate_archived_zk_proof_payload(payload: &ArchivedZkProofPayload) -> PokerL1Result<Hash> {
    if payload.proof.is_empty()
        || payload.proof.len() > crate::offline::zk_verifier::MAX_ZK_PROOF_BYTES
    {
        return Err(PokerL1Error::InvalidZkProofFormat(format!(
            "archived proof length {} is outside 1..={}",
            payload.proof.len(),
            crate::offline::zk_verifier::MAX_ZK_PROOF_BYTES,
        )));
    }
    let encoded = borsh::to_vec(payload)?;
    if encoded.len() > MAX_ARCHIVED_ZK_PROOF_PAYLOAD_BYTES {
        return Err(PokerL1Error::Other(format!(
            "archived proof payload is {} bytes; limit is {}",
            encoded.len(),
            MAX_ARCHIVED_ZK_PROOF_PAYLOAD_BYTES,
        )));
    }
    Ok(compute_proof_hash(
        &payload.proof,
        &payload.state_delta,
        &payload.ack_chain,
    ))
}

/// External, content-addressed archive for historical ZK proof material.
///
/// Implementations may wrap Walrus, a replicated archive network, or a local integration test
/// store.  They are intentionally outside consensus: callers must still hash-bind every returned
/// payload to the request key before serving it.
pub trait ZkProofArchiveProvider: Send + Sync {
    /// Load proof material for its permanent proof-hash commitment.
    fn load_proof(&self, proof_hash: &Hash) -> PokerL1Result<Option<ArchivedZkProofPayload>>;
}

/// 处理历史数据检索请求（SubTask 29.7）。
///
/// Archive node 响应延迟应 < 5s（SubTask 29.7）。
///
/// # 参数
/// - `request`：检索请求
/// - `is_archive_node`：当前节点是否为 archive node
/// - `load`：由 archive 存储/Walrus 客户端提供实际字节的加载器
///
/// # 返回
/// - `Found(data)`：检索成功
/// - `Unavailable(reason)`：数据不可用
#[must_use]
pub fn handle_historical_data_request<F>(
    request: &HistoricalDataRequest,
    is_archive_node: bool,
    load: F,
) -> HistoricalDataResponse
where
    F: FnOnce(&HistoricalDataRequest) -> Result<Option<Vec<u8>>, String>,
{
    if !is_archive_node {
        return HistoricalDataResponse::Unavailable(
            "only archive node can serve historical data".to_string(),
        );
    }
    match load(request) {
        Ok(Some(bytes)) if !bytes.is_empty() => HistoricalDataResponse::Found(bytes),
        Ok(Some(_)) => HistoricalDataResponse::Unavailable(
            "archive loader returned an empty historical payload".to_string(),
        ),
        Ok(None) => {
            HistoricalDataResponse::Unavailable("data pruned or Walrus blob expired".to_string())
        }
        Err(error) => HistoricalDataResponse::Unavailable(format!(
            "historical archive lookup failed: {error}"
        )),
    }
}

/// 标记 Walrus blob 已过期（SEC-M7：续费失败处理）。
///
/// blob 确认过期 → 链上状态标记 `blob_expired = true`，
/// `request_historical_data` 返回 `HistoricalDataUnavailable`，
/// 但 `proof_hash` 与 `verification_result` 仍永久保留。
pub const fn mark_blob_expired(archived: &mut ArchivedZkProof) {
    archived.blob_expired = true;
}

/// 校验裁剪操作是否被允许（综合检查 archive node 数量）。
///
/// # 参数
/// - `archive_node_count`：当前 archive node 数量
/// - `config`：裁剪配置
///
/// # 返回
/// - `Ok(())`：允许裁剪
/// - `Err(PruningRejectedArchiveInsufficient)`：archive node 不足
pub const fn check_pruning_allowed(
    archive_node_count: u32,
    config: &PruningConfig,
) -> Result<(), PokerL1Error> {
    if archive_node_count < config.archive_node_min_count {
        return Err(PokerL1Error::PruningRejectedArchiveInsufficient {
            actual: archive_node_count,
            limit: config.archive_node_min_count,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::{CURRENT_VERSION, SignatureScheme, TaggedPubkey};
    use crate::transaction::{Gas, RouteHint};

    fn make_tagged_pubkey(byte: u8) -> TaggedPubkey {
        let mut raw = vec![byte];
        raw.extend_from_slice(&[0x02u8; 32]);
        TaggedPubkey::new(SignatureScheme::Secp256k1, CURRENT_VERSION, raw)
            .expect("构造 tagged pubkey 不应失败")
    }

    // ===== 常量测试 =====

    #[test]
    fn test_constants() {
        assert_eq!(
            DEFAULT_TX_PRUNE_AFTER_BLOCKS, 1000,
            "SubTask 29.2: tx 裁剪窗口默认 1000"
        );
        assert_eq!(
            DEFAULT_VERTEX_PRUNE_AFTER_BLOCKS, 10_000,
            "SubTask 29.3 / NEW-M13: vertex 裁剪窗口默认 10000"
        );
        assert_eq!(
            DEFAULT_ARCHIVE_NODE_MIN_COUNT, 3,
            "SubTask 29.4: archive node 最少 3"
        );
        assert_eq!(
            MIN_ZK_PROOF_REPLICA_COUNT, 3,
            "SEC-M7: ZK proof Walrus 副本数 >= 3"
        );
    }

    #[test]
    fn test_pruning_config_default() {
        let config = PruningConfig::default();
        assert_eq!(config.tx_prune_after_blocks, 1000);
        assert_eq!(config.vertex_prune_after_blocks, 10_000);
        assert_eq!(config.archive_node_min_count, 3);
        assert_eq!(config.archive_retention_blocks, 100_000);
    }

    // ===== NodeRole 测试（SubTask 29.6）=====

    #[test]
    fn test_node_role_archive_never_prunes() {
        assert!(!NodeRole::Archive.should_prune(), "Archive node 永不裁剪");
        assert!(NodeRole::Archive.retains_full_data());
        assert!(NodeRole::Archive.can_serve_historical_data());
    }

    #[test]
    fn test_node_role_full_prunes() {
        assert!(
            NodeRole::Full.should_prune(),
            "Full node 执行 Layer 1-3 裁剪"
        );
        assert!(!NodeRole::Full.retains_full_data());
        assert!(!NodeRole::Full.can_serve_historical_data());
    }

    #[test]
    fn test_node_role_light_only_headers() {
        assert!(!NodeRole::Light.should_prune());
        assert!(NodeRole::Light.is_light());
        assert!(!NodeRole::Light.retains_full_data());
        assert!(!NodeRole::Light.can_serve_historical_data());
    }

    // ===== check_game_pruning_eligibility 测试（SubTask 29.1）=====

    #[test]
    fn test_game_pruning_eligible() {
        let result = check_game_pruning_eligibility(true, true);
        assert!(result.can_prune());
    }

    #[test]
    fn test_game_pruning_not_settled() {
        let result = check_game_pruning_eligibility(false, true);
        assert!(!result.can_prune());
    }

    #[test]
    fn test_game_pruning_dispute_active() {
        let result = check_game_pruning_eligibility(true, false);
        assert!(!result.can_prune());
    }

    #[test]
    fn test_game_pruning_both_fail() {
        let result = check_game_pruning_eligibility(false, false);
        assert!(!result.can_prune());
    }

    // ===== check_tx_pruning_eligibility 测试（SubTask 29.2）=====

    #[test]
    fn test_tx_pruning_eligible() {
        let result = check_tx_pruning_eligibility(1500, 1000, true, true);
        assert!(result.can_prune());
    }

    #[test]
    fn test_tx_pruning_window_not_reached() {
        let result = check_tx_pruning_eligibility(500, 1000, true, true);
        assert!(!result.can_prune());
    }

    #[test]
    fn test_tx_pruning_boundary() {
        // SEC2-L6: >= 边界判定（距 finality >= tx_prune_after_blocks）
        let result = check_tx_pruning_eligibility(1000, 1000, true, true);
        assert!(result.can_prune(), "boundary 1000 == 1000 应可裁剪");
    }

    #[test]
    fn test_tx_pruning_unsettled_game() {
        let result = check_tx_pruning_eligibility(1500, 1000, false, true);
        assert!(!result.can_prune());
    }

    #[test]
    fn test_tx_pruning_active_dispute() {
        let result = check_tx_pruning_eligibility(1500, 1000, true, false);
        assert!(!result.can_prune());
    }

    // ===== check_vertex_pruning_eligibility 测试（SubTask 29.3）=====

    #[test]
    fn test_vertex_pruning_eligible() {
        let result = check_vertex_pruning_eligibility(15_000, 10_000);
        assert!(result.can_prune());
    }

    #[test]
    fn test_vertex_pruning_window_not_reached() {
        let result = check_vertex_pruning_eligibility(5_000, 10_000);
        assert!(!result.can_prune());
    }

    #[test]
    fn test_vertex_pruning_boundary() {
        // SEC2-L6: >= 边界判定
        let result = check_vertex_pruning_eligibility(10_000, 10_000);
        assert!(result.can_prune(), "boundary 10000 == 10000 应可裁剪");
    }

    // ===== check_zk_proof_pruning_eligibility 测试（SubTask 29.4）=====

    #[test]
    fn test_zk_proof_pruning_eligible() {
        let result = check_zk_proof_pruning_eligibility(true, true, 5, 3);
        assert!(result.can_prune());
    }

    #[test]
    fn test_zk_proof_pruning_not_settled() {
        let result = check_zk_proof_pruning_eligibility(false, true, 5, 3);
        assert!(!result.can_prune());
    }

    #[test]
    fn test_zk_proof_pruning_dispute_active() {
        let result = check_zk_proof_pruning_eligibility(true, false, 5, 3);
        assert!(!result.can_prune());
    }

    #[test]
    fn test_zk_proof_pruning_archive_insufficient() {
        let result = check_zk_proof_pruning_eligibility(true, true, 2, 3);
        assert!(!result.can_prune(), "archive node < min 不得裁剪");
    }

    #[test]
    fn test_zk_proof_pruning_archive_boundary() {
        // archive_node_count == min → 可裁剪
        let result = check_zk_proof_pruning_eligibility(true, true, 3, 3);
        assert!(result.can_prune());
    }

    // ===== is_archive_node_sufficient 测试 =====

    #[test]
    fn test_archive_node_sufficient() {
        assert!(is_archive_node_sufficient(5, 3));
        assert!(is_archive_node_sufficient(3, 3), "boundary: == min");
        assert!(!is_archive_node_sufficient(2, 3));
        assert!(!is_archive_node_sufficient(0, 3));
    }

    // ===== check_pruning_allowed 测试 =====

    #[test]
    fn test_check_pruning_allowed_ok() {
        let config = PruningConfig::new();
        assert!(check_pruning_allowed(5, &config).is_ok());
        assert!(
            check_pruning_allowed(3, &config).is_ok(),
            "boundary: == min"
        );
    }

    #[test]
    fn test_check_pruning_allowed_rejected() {
        let config = PruningConfig::new();
        let result = check_pruning_allowed(2, &config);
        assert!(matches!(
            result,
            Err(PokerL1Error::PruningRejectedArchiveInsufficient {
                actual: 2,
                limit: 3
            })
        ));
    }

    // ===== prune_tx 测试（SubTask 29.2）=====

    fn make_tx() -> Transaction {
        Transaction {
            inputs: vec![],
            outputs: vec![],
            contract_call: None,
            tagged_pubkey: make_tagged_pubkey(0x01),
            signature: vec![0xAA; 65],
            gas: Gas::zero(),
            lane_hint: TxLane::Public,
            route_hint: RouteHint::AnyValidator,
            chain_id: 1,
            nonce: 1,
            gameturn_nonce: None,
            is_fallback: false,
        }
    }

    #[test]
    fn test_prune_tx_preserves_hash_and_type() {
        let tx = make_tx();
        let tx_hash = tx.tx_hash();
        let proof = vec![0xBB; 64];

        let pruned = prune_tx(&tx, proof.clone());

        assert_eq!(pruned.tx_hash, tx_hash, "tx_hash 永久保留");
        assert_eq!(pruned.tx_type, TxLane::Public);
        assert_eq!(pruned.merkle_proof, proof);
    }

    #[test]
    fn test_prune_tx_different_lanes() {
        let mut tx = make_tx();
        tx.lane_hint = TxLane::GameTurn;
        let pruned = prune_tx(&tx, vec![]);
        assert_eq!(pruned.tx_type, TxLane::GameTurn);

        let mut tx2 = make_tx();
        tx2.lane_hint = TxLane::ForceSync;
        let pruned2 = prune_tx(&tx2, vec![]);
        assert_eq!(pruned2.tx_type, TxLane::ForceSync);
    }

    // ===== prune_vertex 测试（SubTask 29.3）=====

    fn make_vertex() -> DagVertex {
        DagVertex {
            epoch: 1,
            round: 10,
            author_pubkey: make_tagged_pubkey(0xFF),
            tx_list: vec![make_tx(), make_tx(), make_tx()],
            parent_hashes: vec![[0x11; 32], [0x22; 32]],
            author_sig: vec![0xCC; 65],
        }
    }

    #[test]
    fn test_prune_vertex_preserves_commitment() {
        let vertex = make_vertex();
        let vertex_hash = vertex.vertex_hash();

        let pruned = prune_vertex(&vertex);

        assert_eq!(pruned.round, 10);
        assert_eq!(pruned.epoch, 1);
        assert_eq!(pruned.vertex_hash, vertex_hash, "vertex_hash 永久保留");
        assert_eq!(pruned.tx_count, 3, "tx_list 长度保留");
        assert_eq!(pruned.parent_count, 2, "parent_hashes 长度保留");
        assert_eq!(
            pruned.author_sig,
            vec![0xCC; 65],
            "author_sig 保留（slashing 证据）"
        );
    }

    #[test]
    fn test_prune_vertex_drops_tx_list_and_parents() {
        let vertex = make_vertex();
        let pruned = prune_vertex(&vertex);

        // PrunedVertex 不含 tx_list / parent_hashes 详情
        // 仅保留计数
        assert_eq!(pruned.tx_count, 3);
        assert_eq!(pruned.parent_count, 2);
    }

    #[test]
    fn test_prune_vertex_empty_tx_list() {
        let mut vertex = make_vertex();
        vertex.tx_list = vec![];
        vertex.parent_hashes = vec![];

        let pruned = prune_vertex(&vertex);
        assert_eq!(pruned.tx_count, 0);
        assert_eq!(pruned.parent_count, 0);
    }

    // ===== compute_proof_hash 测试（SubTask 29.4 / R5-M7）=====

    #[test]
    fn test_compute_proof_hash_deterministic() {
        let proof = vec![0xAA];
        let delta = vec![0xBB];
        let ack = vec![0xCC];

        let h1 = compute_proof_hash(&proof, &delta, &ack);
        let h2 = compute_proof_hash(&proof, &delta, &ack);
        assert_eq!(h1, h2, "相同输入应产生相同 proof_hash");
    }

    #[test]
    fn test_compute_proof_hash_different_inputs() {
        let h1 = compute_proof_hash(&[0xAA], &[0xBB], &[0xCC]);
        let h2 = compute_proof_hash(&[0xAA], &[0xBB], &[0xDD]);
        assert_ne!(h1, h2, "不同 ack_chain 应产生不同 proof_hash");
    }

    // ===== archive_zk_proof 测试（SubTask 29.4）=====

    #[test]
    fn test_archive_zk_proof_basic() {
        let blob_id = [0xDD; 32];
        let archived = archive_zk_proof(&[0xAA], &[0xBB], &[0xCC], true, blob_id);

        assert!(archived.verification_result);
        assert_eq!(archived.walrus_blob_id, blob_id);
        assert!(!archived.blob_expired, "新归档的 blob 未过期");
        // proof_hash 应与手动计算一致
        assert_eq!(
            archived.proof_hash,
            compute_proof_hash(&[0xAA], &[0xBB], &[0xCC])
        );
    }

    #[test]
    fn test_archive_zk_proof_verification_failed() {
        let archived = archive_zk_proof(&[0xAA], &[0xBB], &[0xCC], false, [0; 32]);
        assert!(!archived.verification_result, "验证失败记录为 false");
    }

    #[test]
    fn rocksdb_zk_proof_archive_is_content_addressed_and_survives_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let payload = ArchivedZkProofPayload {
            proof: vec![0xAA; 32],
            state_delta: vec![0xBB; 8],
            ack_chain: vec![0xCC; 4],
            blob_id: [0xDD; 32],
        };
        let proof_hash;
        {
            let archive = RocksDbZkProofArchive::open(directory.path()).unwrap();
            proof_hash = archive.store_proof(payload.clone()).unwrap();
            assert_eq!(
                archive.load_proof(&proof_hash).unwrap(),
                Some(payload.clone())
            );
            assert_eq!(archive.store_proof(payload.clone()).unwrap(), proof_hash);
        }
        let reopened = RocksDbZkProofArchive::open(directory.path()).unwrap();
        assert_eq!(reopened.load_proof(&proof_hash).unwrap(), Some(payload));
    }

    #[test]
    fn rocksdb_zk_proof_archive_rejects_invalid_or_conflicting_payloads() {
        let directory = tempfile::tempdir().unwrap();
        let archive = RocksDbZkProofArchive::open(directory.path()).unwrap();
        assert!(
            archive
                .store_proof(ArchivedZkProofPayload {
                    proof: Vec::new(),
                    state_delta: vec![],
                    ack_chain: vec![],
                    blob_id: [0; 32],
                })
                .is_err()
        );

        let payload = ArchivedZkProofPayload {
            proof: vec![1],
            state_delta: vec![2],
            ack_chain: vec![3],
            blob_id: [4; 32],
        };
        let hash = archive.store_proof(payload.clone()).unwrap();
        let mut conflicting = payload;
        conflicting.blob_id[0] ^= 1;
        assert_eq!(
            compute_proof_hash(
                &conflicting.proof,
                &conflicting.state_delta,
                &conflicting.ack_chain,
            ),
            hash,
        );
        assert!(archive.store_proof(conflicting).is_err());
    }

    #[test]
    fn rocksdb_zk_proof_archive_fails_closed_for_corrupt_records() {
        let directory = tempfile::tempdir().unwrap();
        let payload = ArchivedZkProofPayload {
            proof: vec![1],
            state_delta: vec![2],
            ack_chain: vec![3],
            blob_id: [4; 32],
        };
        let archive = RocksDbZkProofArchive::open(directory.path()).unwrap();
        let hash = archive.store_proof(payload).unwrap();
        drop(archive);

        let mut options = Options::default();
        options.create_if_missing(false);
        let database = DB::open(&options, directory.path()).unwrap();
        database
            .put(hash, vec![0; MAX_ARCHIVED_ZK_PROOF_PAYLOAD_BYTES + 1])
            .unwrap();
        drop(database);

        let archive = RocksDbZkProofArchive::open(directory.path()).unwrap();
        assert!(archive.load_proof(&hash).is_err());
    }

    // ===== mark_blob_expired 测试（SEC-M7）=====

    #[test]
    fn test_mark_blob_expired() {
        let mut archived = archive_zk_proof(&[0xAA], &[0xBB], &[0xCC], true, [0xDD; 32]);
        assert!(!archived.blob_expired);

        mark_blob_expired(&mut archived);
        assert!(archived.blob_expired, "SEC-M7: blob 过期后标记 true");
        // proof_hash 与 verification_result 仍永久保留
        assert_eq!(
            archived.proof_hash,
            compute_proof_hash(&[0xAA], &[0xBB], &[0xCC])
        );
        assert!(archived.verification_result);
    }

    // ===== PermanentRetentionItem 测试（SubTask 29.5 / SEC-M8）=====

    #[test]
    fn test_all_permanent_items_retained() {
        // SEC-M8：所有 PermanentRetentionItem 均为永久保留
        let items = [
            PermanentRetentionItem::BlockHeader,
            PermanentRetentionItem::ValidatorSetChange,
            PermanentRetentionItem::GovernanceParamChange,
            PermanentRetentionItem::GameFinalSettlement,
            PermanentRetentionItem::SlashingEvidence,
            PermanentRetentionItem::ForceCheckpointEvidence,
            PermanentRetentionItem::ChallengeDeltaEvidence,
            PermanentRetentionItem::RequestRevertEvidence,
            PermanentRetentionItem::ZkProofHashChain,
            PermanentRetentionItem::PartialCheckinAnchor,
            PermanentRetentionItem::RotateValidatorKeyRecord,
            PermanentRetentionItem::UpgradeCapRecord,
            PermanentRetentionItem::VerifierStatusSwitch,
            PermanentRetentionItem::UnderInvestigationRecord,
            PermanentRetentionItem::BridgeOperation,
        ];
        for item in items {
            assert!(
                is_permanently_retained(item),
                "所有 PermanentRetentionItem 应永久保留"
            );
        }
    }

    #[test]
    fn test_full_node_recent_blocks_limit() {
        assert_eq!(PermanentRetentionItem::FULL_NODE_RECENT_BLOCKS, 10_000);
    }

    // ===== HistoricalDataRequest 测试（SubTask 29.7）=====

    #[test]
    fn test_handle_historical_data_archive_node_available() {
        let request = HistoricalDataRequest {
            key: [0xAA; 32],
            request_type: HistoricalDataType::Transaction,
        };
        let response = handle_historical_data_request(&request, true, |_| Ok(Some(vec![1, 2])));
        assert_eq!(response, HistoricalDataResponse::Found(vec![1, 2]));
    }

    #[test]
    fn test_handle_historical_data_non_archive_node() {
        let request = HistoricalDataRequest {
            key: [0xAA; 32],
            request_type: HistoricalDataType::Transaction,
        };
        let response = handle_historical_data_request(&request, false, |_| Ok(Some(vec![1])));
        assert!(matches!(response, HistoricalDataResponse::Unavailable(_)));
    }

    #[test]
    fn test_handle_historical_data_unavailable() {
        let request = HistoricalDataRequest {
            key: [0xAA; 32],
            request_type: HistoricalDataType::ZkProof,
        };
        let response = handle_historical_data_request(&request, true, |_| Ok(None));
        assert!(matches!(response, HistoricalDataResponse::Unavailable(_)));
    }

    #[test]
    fn test_historical_data_request_types() {
        let req_tx = HistoricalDataRequest {
            key: [0x01; 32],
            request_type: HistoricalDataType::Transaction,
        };
        let req_vertex = HistoricalDataRequest {
            key: [0x02; 32],
            request_type: HistoricalDataType::DagVertex,
        };
        let req_proof = HistoricalDataRequest {
            key: [0x03; 32],
            request_type: HistoricalDataType::ZkProof,
        };
        assert_eq!(req_tx.request_type, HistoricalDataType::Transaction);
        assert_eq!(req_vertex.request_type, HistoricalDataType::DagVertex);
        assert_eq!(req_proof.request_type, HistoricalDataType::ZkProof);
    }
}
