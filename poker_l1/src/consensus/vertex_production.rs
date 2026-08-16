//! DAG vertex 产出与 game sub-block 嵌入（Task 8 — SubTask 8.1~8.9）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）：
//! - **SubTask 8.1**：validator 收到 tx 后装入本地待出 vertex 缓冲（默认 100ms 内必出 vertex）
//!   — 网络层时间相关，本模块仅提供 `VertexBuilder` 数据结构与组装函数，
//!   实际 100ms 触发由 Phase 6 网络层实现
//! - **SubTask 8.2**：vertex 组装（tx_list + ≥2/3 parent_hashes + secp256k1 签名）
//!   — [`crate::consensus::DagVertex`] 数据结构已实现，本模块提供 builder
//! - **SubTask 8.3**：vertex 大小上限 `max_vertex_size`（默认 256KB）
//!   — [`crate::consensus::MAX_VERTEX_SIZE`] 已定义，本模块提供校验函数
//! - **SubTask 8.4**：assigned_validator 把自己负责 game 的 GameTurn tx 分组为 game sub-block
//!   — 本模块实现 [`GameSubBlock`] + [`build_game_sub_block`]
//! - **SubTask 8.5**：GameTurn 通道游戏操作 tx 免 gas，仅校验轮转约束 + 买入锁仓
//!   — 本模块实现 [`validate_game_turn_tx`]（买入锁仓属 Phase 3 合约层）
//! - **SubTask 8.6**：**Block 内排序（S9 修复）** + **R4-M4 commit 级排序** + **SEC-H6 跨 commit 抢跑防护**
//!   - S9：同一 vertex 内 GameTurn tx 先于 ForceSync tx 执行
//!   - R4-M4：同一 Bullshark commit 内所有 vertex 的 GameTurn tx 先于所有 ForceSync tx
//!   - SEC-H6：跨 commit 的 force_advance 判定需校验前一 commit 是否有该 Game 的 GameTurn tx
//! - **SubTask 8.7**：活跃 Game 上限（S8 修复）— 已在 [`crate::consensus::validate_active_games_limit`] 实现
//! - **SubTask 8.8**：vertex 通过 gossipsub 广播 — Phase 6 网络层实现，本模块不涉及
//! - **SubTask 8.9**：**GameTurn tx 超时后 fallback 接受（NEW-H2 + R3-H4/R3-H5 + SEC-H7）**
//!   - assigned_validator 超时 → 客户端可向任意非 assigned_validator 提交该 tx（附 timeout_proof）
//!   - timeout_proof 含 ≥3 个副本 validator secp256k1 签名见证（R4-H6 阈值公式）
//!   - fallback tx 走 Public 通道正常计费 gas，但执行排序仍按 GameTurn 通道语义（R3-H5）
//!   - fallback tx 显式标记 `is_fallback = true`（SEC-H7）
//!   - 正常 GameTurn tx 不得设 `is_fallback = true`（validator 拒绝）
//!
//! ## 设计决策
//!
//! - `VertexBuilder` 不做签名（签名由 [`crate::signature`] 模块在外层完成），
//!   仅组装 `tx_list` / `parent_hashes` / 元数据，调用方在外层完成签名后填入 `author_sig`
//! - S9 / R4-M4 排序使用 stable partition，保持同通道内 tx 的相对顺序（arrival 顺序）
//! - SEC-H6 跨 commit 抢跑防护为校验函数，实际跨 commit state 跟踪由 Phase 9 状态机维护
//! - fallback tx 的 timeout_proof 校验为密码学操作（无状态），实际 witness 收集由 Phase 6 网络层完成
//! - `required_witness_count` 阈值公式按 R4-H6 修正：`max(3, floor(checkpoint_multi_replica_count * 2 / 3))`

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::BlockHeight;
use crate::consensus::routing::{GameStatus, TurnRule};
use crate::consensus::{DagVertex, Epoch, GamePhase, MAX_VERTEX_SIZE, Round};
use crate::error::{PokerL1Error, PokerL1Result};
use crate::signature::TaggedPubkey;
use crate::transaction::{Gas, RouteHint, Transaction, TxLane};

/// 默认 checkpoint 多副本见证数（spec：3-of-5）。
pub const DEFAULT_CHECKPOINT_MULTI_REPLICA_COUNT: usize = 5;

/// 计算多副本见证签名阈值（R4-H6 修正）。
///
/// spec：`required_witness_count = max(3, floor(checkpoint_multi_replica_count * 2 / 3))`
///
/// 默认 5 副本 → `max(3, floor(10/3)) = max(3, 3) = 3`（3-of-5）。
pub const fn required_witness_count(checkpoint_multi_replica_count: usize) -> usize {
    let computed = checkpoint_multi_replica_count * 2 / 3;
    if computed > 3 { computed } else { 3 }
}

/// 计算某轮 vertex 引用 parent 所需的最小 quorum（≥2/3 validator）。
///
/// spec SubTask 8.2：vertex 须引用 ≥2/3 validator 的上一轮 vertex hash。
///
/// 参数：
/// - `validator_count`：当前 ValidatorSet 规模 |V|
///
/// 返回严格 >2/3 的最小整数（C-3 修复）。
pub const fn required_parent_count(validator_count: usize) -> usize {
    2 * validator_count / 3 + 1
}

/// 计算某轮 commit certificate 所需的最小签名 quorum（≥2/3 validator）。
///
/// spec SubTask 9.1 / 10.7：commit certificate 须含 ≥2/3 validator 签名。
pub const fn required_quorum(validator_count: usize) -> usize {
    required_parent_count(validator_count)
}

/// Vertex 构造器（SubTask 8.1 / 8.2 / 8.3）。
///
/// validator 收到 tx 后装入本地缓冲，组装为 vertex。
/// 签名（`author_sig`）由外层调用方在 [`Self::build`] 后填充。
#[derive(Debug, Clone)]
pub struct VertexBuilder {
    /// 当前 epoch。
    pub epoch: Epoch,
    /// DAG round。
    pub round: Round,
    /// 作者 validator 的 tagged pubkey。
    pub author_pubkey: TaggedPubkey,
    /// 待出 tx 列表（按 arrival 顺序）。
    pub tx_list: Vec<Transaction>,
    /// 引用的上一轮 vertex hash 列表。
    pub parent_hashes: Vec<crate::Hash>,
}

impl VertexBuilder {
    /// 创建空的 vertex builder。
    pub const fn new(epoch: Epoch, round: Round, author_pubkey: TaggedPubkey) -> Self {
        Self {
            epoch,
            round,
            author_pubkey,
            tx_list: Vec::new(),
            parent_hashes: Vec::new(),
        }
    }

    /// 追加一条 tx 到待出缓冲。
    pub fn push_tx(&mut self, tx: Transaction) -> &mut Self {
        self.tx_list.push(tx);
        self
    }

    /// 设置 parent_hashes（须 ≥2/3 validator 的上一轮 vertex hash）。
    pub fn with_parents(mut self, parent_hashes: Vec<crate::Hash>) -> Self {
        self.parent_hashes = parent_hashes;
        self
    }

    /// 校验 vertex 大小是否超限（SubTask 8.3）。
    ///
    /// spec：`max_vertex_size` 默认 256KB，超出应分多个 vertex。
    /// 本函数估算 vertex 序列化后大小（不含 author_sig），实际生产中应序列化后精确校验。
    pub fn validate_size(&self) -> PokerL1Result<()> {
        let estimated = self.estimate_size();
        if estimated > MAX_VERTEX_SIZE {
            return Err(PokerL1Error::VertexTooLarge {
                actual: estimated,
                limit: MAX_VERTEX_SIZE,
            });
        }
        Ok(())
    }

    /// 估算 vertex 序列化后大小（粗略，用于提前拒绝）。
    ///
    /// 实际生产中应序列化后精确校验。此处用 tx_list 各 tx 的 signature + inputs + outputs
    /// 长度粗略累加，避免重复序列化。
    fn estimate_size(&self) -> usize {
        let mut size = 8 + 8; // epoch + round
        size += 1 + self.author_pubkey.raw.len(); // tag + raw
        size += 8; // tx_list len prefix
        for tx in &self.tx_list {
            size += 8; // inputs len
            size += tx.inputs.iter().map(|i| i.to_bytes().len()).sum::<usize>();
            size += 8; // outputs len
            size += tx
                .outputs
                .iter()
                .map(|o| o.content_hash().len())
                .sum::<usize>();
            size += 1 + tx.signature.len();
            size += 8 + 8; // gas budget + price
        }
        size += 8; // parent_hashes len
        // M-11 修复：saturating_mul 防止 parent_hashes.len() * 32 溢出绕过 MAX_VERTEX_SIZE 检查
        size = size.saturating_add(self.parent_hashes.len().saturating_mul(32));
        // L-3 修复：预留 author_sig 空间（secp256k1 = 65B + BCS len prefix）
        size = size.saturating_add(8 + 65);
        size
    }

    /// 校验 parent_hashes 数量是否 ≥2/3 validator（SubTask 8.2）。
    ///
    /// 参数：
    /// - `validator_count`：当前 ValidatorSet 规模 |V|
    pub const fn validate_parents(&self, validator_count: usize) -> PokerL1Result<()> {
        let required = required_parent_count(validator_count);
        if self.parent_hashes.len() < required {
            return Err(PokerL1Error::InsufficientParents {
                actual: self.parent_hashes.len(),
                required,
            });
        }
        Ok(())
    }

    /// 组装 vertex（不含签名，调用方在外层签名后填入 `author_sig`）。
    ///
    /// 调用前应先调用 [`Self::validate_size`] 与 [`Self::validate_parents`]。
    pub fn build(self, author_sig: Vec<u8>) -> DagVertex {
        DagVertex {
            epoch: self.epoch,
            round: self.round,
            author_pubkey: self.author_pubkey,
            tx_list: self.tx_list,
            parent_hashes: self.parent_hashes,
            author_sig,
        }
    }
}

/// Game sub-block（SubTask 8.4）。
///
/// assigned_validator 把自己负责 game 的 GameTurn tx 分组为 game sub-block（每 game 一个）。
/// sub-block 内按 `(current_turn, arrival)` 排序：当前轮次玩家优先，同玩家按 arrival 顺序。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct GameSubBlock {
    /// Game 对象 ID。
    pub game_id: crate::object_model::ObjectID,
    /// sub-block 内的 GameTurn tx 列表（已排序）。
    pub txs: Vec<Transaction>,
    /// 排序前的 arrival 序号（用于审计追溯）。
    pub arrival_order: Vec<u64>,
}

/// 构造 game sub-block（SubTask 8.4 / Phase 5 Task 9）。
///
/// assigned_validator 把自己负责 game 的 GameTurn tx 分组为 game sub-block，
/// sub-block 内排序键根据 [`GameStatus::phase`] 选择：
/// 1. [`GamePhase::Betting`]：按 `(current_turn 优先, arrival)` 排序
///    — 当前轮次玩家的 tx 优先，同玩家按 arrival 顺序（既有行为，保持兼容）
/// 2. [`GamePhase::MultiPlayerSubmit`]：按 `(phase_kind, arrival)` 排序
///    — 多玩家阶段无单一 current_turn，按到达顺序稳定排序
///    （同一 game 的 phase_kind 恒定，等价于 arrival 顺序）
///
/// 参数：
/// - `txs`：待分组的 GameTurn tx 列表（按 arrival 顺序，索引即 arrival 序号）
/// - `game`：Game 状态
/// - `turn_rule`：轮转规则
///
/// 返回排序后的 sub-block。非 GameTurn 通道 tx 会被过滤并忽略（不应传入）。
pub fn build_game_sub_block(
    txs: Vec<Transaction>,
    game: &GameStatus,
    turn_rule: &dyn TurnRule,
) -> PokerL1Result<GameSubBlock> {
    let game_id = game.id;

    // 过滤仅保留 GameTurn 通道 tx，记录原始 arrival 序号
    let mut filtered: Vec<(u64, Transaction)> = txs
        .into_iter()
        .enumerate()
        .filter(|(_, tx)| tx.lane_hint == TxLane::GameTurn)
        .map(|(idx, tx)| (idx as u64, tx))
        .collect();

    // 按 game.phase 选择排序键
    match game.phase {
        GamePhase::Betting { .. } => {
            // 下注阶段：按 (current_turn 优先, arrival 顺序) 排序
            let current_turn = turn_rule.current_turn(game);
            filtered.sort_by(|(arr_a, tx_a), (arr_b, tx_b)| {
                let a_is_current = current_turn
                    .map(|ct| derive_actor_address(tx_a) == ct)
                    .unwrap_or(false);
                let b_is_current = current_turn
                    .map(|ct| derive_actor_address(tx_b) == ct)
                    .unwrap_or(false);
                match (a_is_current, b_is_current) {
                    (true, false) => std::cmp::Ordering::Less,
                    (false, true) => std::cmp::Ordering::Greater,
                    _ => arr_a.cmp(arr_b),
                }
            });
        }
        GamePhase::MultiPlayerSubmit { .. } => {
            // 多玩家阶段：按 (phase_kind, arrival) 排序
            // 同一 game 的 phase_kind 恒定，等价于按 arrival 顺序稳定排序
            // （多玩家阶段 current_turn 返回 None，不使用 current_turn 优先级）
            filtered.sort_by_key(|(arr, _)| *arr);
        }
    }

    let arrival_order: Vec<u64> = filtered.iter().map(|(arr, _)| *arr).collect();
    let sorted_txs: Vec<Transaction> = filtered.into_iter().map(|(_, tx)| tx).collect();

    Ok(GameSubBlock {
        game_id,
        txs: sorted_txs,
        arrival_order,
    })
}

/// 综合校验 GameTurn 通道 tx（SubTask 8.5 / SEC-H7）。
///
/// 校验项：
/// 1. tx 通道与路由提示一致（`validate_lane_route`）
/// 2. GameTurn 通道免 gas（`gas == Gas::zero()`）
/// 3. 正常 GameTurn tx 不得设 `is_fallback = true`（SEC-H7）
/// 4. 阶段感知轮转约束（`validate_game_turn_phase_aware`）：
///    - Betting 阶段：`current_turn_player` 匹配
///    - MultiPlayerSubmit 阶段：`pending_submitters` 校验
///
/// 买入锁仓校验属 Phase 3 合约层，本函数不涉及。
///
/// 参数：
/// - `tx`：待校验交易
/// - `game`：Game 状态（`&mut` 用于多玩家阶段更新 pending_submitters）
/// - `actor`：tx 签名者派生地址
/// - `turn_rule`：轮转规则
pub fn validate_game_turn_tx(
    tx: &Transaction,
    game: &mut GameStatus,
    actor: crate::Address,
    turn_rule: &dyn TurnRule,
) -> PokerL1Result<()> {
    // 1. lane_route 一致性
    crate::consensus::validate_lane_route(tx)?;

    // 2. GameTurn 通道免 gas
    validate_gameturn_gas_free(tx)?;

    // 3. SEC-H7：GameTurn 通道 tx 不得设置 is_fallback = true
    //    fallback tx 必须走 Public 通道（详见 validate_fallback_tx）
    //    若 GameTurn 通道 tx 设置 is_fallback = true → 视为构造错误，拒绝
    if tx.lane_hint == TxLane::GameTurn && tx.is_fallback {
        return Err(PokerL1Error::InvalidFallbackFlag);
    }

    // 4. 阶段感知轮转约束（Betting: current_turn 匹配；MultiPlayerSubmit: pending_submitters 校验）
    crate::consensus::validate_game_turn_phase_aware(tx, game, actor, turn_rule)?;

    Ok(())
}

/// 校验 GameTurn 通道 tx 是否免 gas（SubTask 8.5）。
///
/// spec：GameTurn 通道游戏操作 tx 免 gas，`gas == Gas::zero()`。
/// fallback tx 走 Public 通道正常计费，本函数不校验 fallback tx。
pub fn validate_gameturn_gas_free(tx: &Transaction) -> PokerL1Result<()> {
    if tx.lane_hint == TxLane::GameTurn && tx.gas != Gas::zero() {
        return Err(PokerL1Error::InsufficientBalance {
            needed: tx.gas.budget,
            has: 0,
        });
    }
    Ok(())
}

/// S9 排序：同一 vertex 内 GameTurn tx 先于 ForceSync tx（SubTask 8.6）。
///
/// spec S9 修复：
/// - GameTurn 通道 tx（含 CheckpointAnchor）先执行
/// - ForceSync 通道 tx 后执行
/// - Public 通道 tx 在中间
/// - 同通道内保持 arrival 顺序（stable partition）
///
/// 参数：
/// - `txs`：vertex 内 tx 列表（按 arrival 顺序）
///
/// 返回排序后的 tx 列表。
pub fn sort_vertex_txs_s9(txs: Vec<Transaction>) -> Vec<Transaction> {
    let mut result: Vec<Transaction> = Vec::with_capacity(txs.len());
    // 1. GameTurn + CheckpointAnchor 优先
    result.extend(
        txs.iter()
            .filter(|tx| matches!(tx.lane_hint, TxLane::GameTurn | TxLane::CheckpointAnchor))
            .cloned(),
    );
    // 2. Public 中间
    result.extend(
        txs.iter()
            .filter(|tx| tx.lane_hint == TxLane::Public)
            .cloned(),
    );
    // 3. ForceSync 后置
    result.extend(
        txs.iter()
            .filter(|tx| tx.lane_hint == TxLane::ForceSync)
            .cloned(),
    );
    result
}

/// R4-M4 排序：同一 Bullshark commit 内所有 vertex 的 GameTurn tx 先于所有 ForceSync tx（SubTask 8.6）。
///
/// spec R4-M4 修正：跨 vertex 排序规则 — 同一 Bullshark commit（round）内所有 vertex 的
/// GameTurn tx 先于所有 ForceSync/force_advance tx 执行。
///
/// 参数：
/// - `commit_vertex_txs`：commit 内各 vertex 的 tx 列表（按 Bullshark 排序顺序）
///
/// 返回聚合后按 R4-M4 规则排序的 tx 列表。
pub fn sort_commit_txs_r4m4(commit_vertex_txs: Vec<Vec<Transaction>>) -> Vec<Transaction> {
    // 先按 Bullshark 顺序聚合（保持 vertex 间顺序）
    let mut aggregated: Vec<Transaction> = Vec::new();
    for vertex_txs in commit_vertex_txs {
        aggregated.extend(vertex_txs);
    }
    // 再按 S9 规则排序（GameTurn 优先，ForceSync 后置）
    // R4-M4 等价于聚合后做 S9 排序（跨 vertex 的 GameTurn 全先于 ForceSync）
    sort_vertex_txs_s9(aggregated)
}

/// SEC-H6 跨 commit force_advance 抢跑防护校验（SubTask 8.6 / Phase 5 Task 10）。
///
/// spec SEC-H6 修复：跨 commit（不同 block）的 force_advance 判定需额外校验 —
/// force_advance 所在 commit 的前一个 commit 内是否有该 Game 的 GameTurn tx，
/// 若有则 `last_action_height` 视为已更新，force_advance 判定为 false 被拒绝。
///
/// **Phase 5 Task 10 扩展**：覆盖 [`GamePhase::MultiPlayerSubmit`] 阶段 —
/// 多玩家阶段（Shuffle / RevealToken / Reconstruct / LeaveProof）的 GameTurn tx
/// 同样视为更新 `last_action_height`，前一 commit 有此类 tx 时 force_advance 被拒绝。
///
/// 参数：
/// - `prev_commit_game_turns`：前一个 commit 内该 Game 的 GameTurn tx 列表
///   （空表示前一 commit 无该 Game 的 GameTurn tx）
/// - `force_advance_game_id`：force_advance tx 涉及的 Game ID
/// - `game_id`：待校验的 Game ID（应与 force_advance_game_id 一致）
/// - `game_phase`：当前 Game 阶段（Betting 或 MultiPlayerSubmit）
///
/// 返回 `Ok(())` 表示 force_advance 可执行；`Err` 表示被 SEC-H6 拒绝。
pub fn check_sech6_cross_commit_force_advance(
    prev_commit_game_turns: &[Transaction],
    force_advance_game_id: &crate::object_model::ObjectID,
    game_id: &crate::object_model::ObjectID,
    game_phase: &GamePhase,
) -> PokerL1Result<()> {
    // Game ID 一致性校验
    if force_advance_game_id != game_id {
        return Err(PokerL1Error::GameNotFound(*force_advance_game_id));
    }
    // SEC-H6：前一 commit 有该 Game 的 GameTurn tx → last_action_height 视为已更新
    // 覆盖 Betting 与 MultiPlayerSubmit 阶段：多玩家阶段的提交 tx 同样更新 last_action_height
    if !prev_commit_game_turns.is_empty() {
        return Err(PokerL1Error::Other(format!(
            "SEC-H6: force_advance rejected — prev commit has GameTurn txs for game {:?} (phase={:?})",
            game_id, game_phase
        )));
    }
    Ok(())
}

/// Fallback tx 的 timeout proof（SubTask 8.9 / NEW-H2 / R3-H4）。
///
/// assigned_validator 在 `game_validator_timeout_blocks` 内未装入 GameTurn tx →
/// 客户端可向任意非 assigned_validator 提交该 tx（附本 proof）。
///
/// proof 含：
/// - 原始 GameTurn tx（被超时的）
/// - 提交时对应的 block height（SEC-M5：以 height 为权威）
/// - 多副本 validator secp256k1 签名见证（≥ `required_witness_count` 个）
/// - round 范围非包含证明（复用 C6 sparse Merkle 非包含证明格式）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct TimeoutProof {
    /// 原始被超时的 GameTurn tx。
    pub original_tx: Transaction,
    /// 提交时对应的 block height（SEC-M5：以 height 为权威，非 timestamp_ms）。
    pub submit_height: BlockHeight,
    /// 见证 validator 的 tagged pubkeys（与 witness_signatures 一一对应）。
    pub witness_pubkeys: Vec<TaggedPubkey>,
    /// 见证 validator 的 secp256k1 签名（签名对象 = `hash(chain_id || game_id || original_tx_hash || submit_height)`）。
    pub witness_signatures: Vec<Vec<u8>>,
    /// round 范围非包含证明（C6 sparse Merkle 非包含证明格式）。
    ///
    /// 证明 assigned_validator 在 `[submit_height - game_validator_timeout_blocks, submit_height]`
    /// 范围内未装入同 `gameturn_nonce` 的 GameTurn tx。
    /// Phase 2 仅定义字段，实际证明生成与验证由 Phase 9 状态机实现。
    pub non_inclusion_proof: Vec<u8>,
}

impl TimeoutProof {
    /// 校验 witness 数量是否达到阈值（R4-H6）。
    ///
    /// 参数：
    /// - `checkpoint_multi_replica_count`：多副本配置（默认 5）
    pub fn validate_witness_count(
        &self,
        checkpoint_multi_replica_count: usize,
    ) -> PokerL1Result<()> {
        let required = required_witness_count(checkpoint_multi_replica_count);
        if self.witness_signatures.len() < required {
            return Err(PokerL1Error::InvalidTimeoutProof(format!(
                "witness count {} < required {}",
                self.witness_signatures.len(),
                required
            )));
        }
        if self.witness_pubkeys.len() != self.witness_signatures.len() {
            return Err(PokerL1Error::InvalidTimeoutProof(
                "witness_pubkeys and witness_signatures length mismatch".to_string(),
            ));
        }
        Ok(())
    }

    /// 校验 witness_pubkeys 是否都不等于 assigned_validator（R3-H4：多副本独立性）。
    ///
    /// spec：见证 validator 须为非 assigned_validator 的其他 validator，
    /// 防 assigned_validator 自签伪造 timeout_proof。
    pub fn validate_witness_independence(
        &self,
        assigned_validator: &TaggedPubkey,
    ) -> PokerL1Result<()> {
        for pk in &self.witness_pubkeys {
            if pk == assigned_validator {
                return Err(PokerL1Error::InvalidTimeoutProof(
                    "witness includes assigned_validator (independence violated)".to_string(),
                ));
            }
        }
        Ok(())
    }
}

/// 校验 fallback tx（SubTask 8.9 / NEW-H2 / R3-H4 / R3-H5 / SEC-H7）。
///
/// 校验项：
/// 1. tx 通道为 Public（fallback tx 走 Public 通道正常计费，R3-H5）
/// 2. tx 显式标记 `is_fallback = true`（SEC-H7）
/// 3. tx 使用 `gameturn_nonce`（NEW-M9）
/// 4. timeout_proof witness 数量达标（R4-H6）
/// 5. timeout_proof witness 独立性（非 assigned_validator，R3-H4）
/// 6. timeout_proof.original_tx 与 fallback tx 的 gameturn_nonce 一致
///
/// 参数：
/// - `fallback_tx`：待校验的 fallback tx
/// - `timeout_proof`：附带的 timeout proof
/// - `assigned_validator`：Game 的 assigned_validator
/// - `checkpoint_multi_replica_count`：多副本配置（默认 5）
pub fn validate_fallback_tx(
    fallback_tx: &Transaction,
    timeout_proof: &TimeoutProof,
    assigned_validator: &TaggedPubkey,
    checkpoint_multi_replica_count: usize,
) -> PokerL1Result<()> {
    // 1. fallback tx 走 Public 通道正常计费（R3-H5）
    if fallback_tx.lane_hint != TxLane::Public {
        return Err(PokerL1Error::WrongLane {
            lane: fallback_tx.lane_hint,
            route: fallback_tx.route_hint,
        });
    }
    if fallback_tx.route_hint != RouteHint::AnyValidator {
        return Err(PokerL1Error::WrongLane {
            lane: fallback_tx.lane_hint,
            route: fallback_tx.route_hint,
        });
    }

    // 2. SEC-H7：fallback tx 显式标记 is_fallback = true
    if !fallback_tx.is_fallback {
        return Err(PokerL1Error::InvalidFallbackFlag);
    }

    // 3. NEW-M9：fallback tx 使用 gameturn_nonce
    if fallback_tx.gameturn_nonce.is_none() {
        return Err(PokerL1Error::GameTurnNonceMismatch { tx: 0, game: 0 });
    }

    // 4. R4-H6：witness 数量达标
    timeout_proof.validate_witness_count(checkpoint_multi_replica_count)?;

    // 5. R3-H4：witness 独立性
    timeout_proof.validate_witness_independence(assigned_validator)?;

    // 6. gameturn_nonce 一致性：fallback_tx 与 original_tx 须同 gameturn_nonce
    let fallback_nonce = fallback_tx.gameturn_nonce.unwrap();
    let original_nonce = timeout_proof.original_tx.gameturn_nonce;
    if original_nonce != Some(fallback_nonce) {
        return Err(PokerL1Error::GameTurnNonceMismatch {
            tx: fallback_nonce,
            game: original_nonce.unwrap_or(0),
        });
    }

    Ok(())
}

/// 从 tx 派生签名者地址（`blake2b_256(tagged_pubkey)[0..20]`）。
fn derive_actor_address(tx: &Transaction) -> crate::Address {
    crate::account::derive_address(&tx.tagged_pubkey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::routing::{ExecutionMode, SimpleTurnRule};
    use crate::object_model::{Object, ObjectID, Ownership};
    use crate::signature::tagged_pubkey::{SignatureScheme, encode_tag};
    use crate::transaction::{Gas, RouteHint, Transaction, TxLane};
    use std::collections::{BTreeMap, BTreeSet};

    fn make_tagged_pubkey(byte: u8, scheme: SignatureScheme) -> TaggedPubkey {
        let raw_len = scheme.raw_pubkey_len();
        TaggedPubkey {
            tag: encode_tag(scheme, 1),
            raw: vec![byte; raw_len],
        }
    }

    fn make_game(
        assigned_byte: u8,
        current_turn_byte: u8,
        participants: &[u8],
    ) -> (GameStatus, TaggedPubkey) {
        let assigned_tp = make_tagged_pubkey(assigned_byte, SignatureScheme::Secp256k1);
        let mut active = BTreeSet::new();
        for &b in participants {
            active.insert([b; 20]);
        }
        let game = GameStatus {
            id: ObjectID::new([0xAA; 20], 1),
            assigned_validator: assigned_tp.clone(),
            current_turn_player: [current_turn_byte; 20],
            active_participants: active,
            player_nonce: BTreeMap::new(),
            last_action_height: 100,
            hand_start_height: 90,
            execution_mode: ExecutionMode::OnChain,
            is_finalized: false,
            phase: crate::consensus::GamePhase::default_phase(),
            pending_submitters: BTreeSet::new(),
            phase_started_height: 0,
            completed_submitters: BTreeSet::new(),
        };
        (game, assigned_tp)
    }

    fn make_gameturn_tx(actor_byte: u8, gameturn_nonce: u64, is_fallback: bool) -> Transaction {
        Transaction {
            inputs: vec![],
            outputs: vec![],
            contract_call: None,
            tagged_pubkey: make_tagged_pubkey(actor_byte, SignatureScheme::Secp256k1),
            signature: vec![0; 65],
            gas: if is_fallback {
                Gas::new(1_000_000, 1)
            } else {
                Gas::zero()
            },
            lane_hint: if is_fallback {
                TxLane::Public
            } else {
                TxLane::GameTurn
            },
            route_hint: if is_fallback {
                RouteHint::AnyValidator
            } else {
                RouteHint::AssignedValidator
            },
            chain_id: crate::DEFAULT_CHAIN_ID,
            nonce: 0,
            gameturn_nonce: Some(gameturn_nonce),
            is_fallback,
        }
    }

    fn make_public_tx(nonce: u64) -> Transaction {
        Transaction {
            inputs: vec![],
            outputs: vec![],
            contract_call: None,
            tagged_pubkey: make_tagged_pubkey(0x02, SignatureScheme::Secp256k1),
            signature: vec![0; 65],
            gas: Gas::new(1_000_000, 1),
            lane_hint: TxLane::Public,
            route_hint: RouteHint::AnyValidator,
            chain_id: crate::DEFAULT_CHAIN_ID,
            nonce,
            gameturn_nonce: None,
            is_fallback: false,
        }
    }

    fn make_force_sync_tx(nonce: u64) -> Transaction {
        Transaction {
            inputs: vec![],
            outputs: vec![],
            contract_call: None,
            tagged_pubkey: make_tagged_pubkey(0x02, SignatureScheme::Secp256k1),
            signature: vec![0; 65],
            gas: Gas::new(1_000_000, 1),
            lane_hint: TxLane::ForceSync,
            route_hint: RouteHint::AnyValidator,
            chain_id: crate::DEFAULT_CHAIN_ID,
            nonce,
            gameturn_nonce: None,
            is_fallback: false,
        }
    }

    fn make_checkpoint_anchor_tx() -> Transaction {
        Transaction {
            inputs: vec![],
            outputs: vec![],
            contract_call: None,
            tagged_pubkey: make_tagged_pubkey(0x02, SignatureScheme::Secp256k1),
            signature: vec![0; 65],
            gas: Gas::zero(),
            lane_hint: TxLane::CheckpointAnchor,
            route_hint: RouteHint::AssignedValidator,
            chain_id: crate::DEFAULT_CHAIN_ID,
            nonce: 0,
            gameturn_nonce: None,
            is_fallback: false,
        }
    }

    // ===== required_witness_count / required_parent_count 测试 =====

    #[test]
    fn required_witness_count_default_3_of_5() {
        // R4-H6：max(3, floor(5*2/3)) = max(3, 3) = 3
        assert_eq!(required_witness_count(5), 3);
    }

    #[test]
    fn required_witness_count_floor_3_for_small_set() {
        assert_eq!(required_witness_count(1), 3);
        assert_eq!(required_witness_count(2), 3);
        assert_eq!(required_witness_count(4), 3);
    }

    #[test]
    fn required_witness_count_grows_for_large_set() {
        // 9 副本 → max(3, floor(18/3)) = max(3, 6) = 6
        assert_eq!(required_witness_count(9), 6);
    }

    #[test]
    fn required_parent_count_two_thirds_quorum() {
        // 严格 >2/3（C-3 修复）
        assert_eq!(required_parent_count(3), 3); // 2*3/3+1 = 3
        assert_eq!(required_parent_count(5), 4); // 2*5/3+1 = 4
        assert_eq!(required_parent_count(6), 5); // 2*6/3+1 = 5
        assert_eq!(required_parent_count(7), 5); // 2*7/3+1 = 5
        assert_eq!(required_parent_count(9), 7); // 2*9/3+1 = 7
    }

    #[test]
    fn required_quorum_equals_required_parent() {
        // quorum 与 parent 阈值相同（均为 2/3）
        assert_eq!(required_quorum(5), required_parent_count(5));
        assert_eq!(required_quorum(9), required_parent_count(9));
    }

    // ===== VertexBuilder 测试 =====

    #[test]
    fn vertex_builder_builds_valid_vertex() {
        let author = make_tagged_pubkey(0x01, SignatureScheme::Secp256k1);
        let mut builder = VertexBuilder::new(1, 10, author.clone());
        builder.push_tx(make_public_tx(1));
        builder.push_tx(make_public_tx(2));
        let vertex = builder
            .with_parents(vec![[0u8; 32], [1u8; 32]])
            .build(vec![0u8; 65]);
        assert_eq!(vertex.epoch, 1);
        assert_eq!(vertex.round, 10);
        assert_eq!(vertex.author_pubkey, author);
        assert_eq!(vertex.tx_list.len(), 2);
        assert_eq!(vertex.parent_hashes.len(), 2);
    }

    #[test]
    fn vertex_builder_validate_parents_rejects_insufficient() {
        let author = make_tagged_pubkey(0x01, SignatureScheme::Secp256k1);
        let builder = VertexBuilder::new(1, 10, author).with_parents(vec![[0u8; 32]]); // 仅 1 个 parent
        // 5 validator → 需要 4 个 parent
        let err = builder.validate_parents(5).unwrap_err();
        assert!(matches!(
            err,
            PokerL1Error::InsufficientParents {
                actual: 1,
                required: 4
            }
        ));
    }

    #[test]
    fn vertex_builder_validate_parents_ok_with_quorum() {
        let author = make_tagged_pubkey(0x01, SignatureScheme::Secp256k1);
        let builder = VertexBuilder::new(1, 10, author)
            .with_parents(vec![[0u8; 32], [1u8; 32], [2u8; 32], [3u8; 32]]);
        // 5 validator → 需要 4 个 parent，正好 4 个
        builder
            .validate_parents(5)
            .expect("4 个 parent 应满足 5 validator quorum");
    }

    #[test]
    fn vertex_builder_validate_size_ok_for_small_vertex() {
        let author = make_tagged_pubkey(0x01, SignatureScheme::Secp256k1);
        let builder = VertexBuilder::new(1, 10, author).with_parents(vec![[0u8; 32]]);
        builder.validate_size().expect("小 vertex 不应超限");
    }

    // ===== GameSubBlock + build_game_sub_block 测试 =====

    #[test]
    fn build_game_sub_block_prioritizes_current_turn_player() {
        // current_turn_player 必须等于某 tx 的 derive_actor_address（blake2b 派生地址）
        let tx_player_10 = make_gameturn_tx(0x10, 2, false);
        let tx_player_20 = make_gameturn_tx(0x20, 1, false);
        let actor_10 = derive_actor_address(&tx_player_10);
        let actor_20 = derive_actor_address(&tx_player_20);

        let assigned_tp = make_tagged_pubkey(0x01, SignatureScheme::Secp256k1);
        let mut active = BTreeSet::new();
        active.insert(actor_10);
        active.insert(actor_20);
        let game = GameStatus {
            id: ObjectID::new([0xAA; 20], 1),
            assigned_validator: assigned_tp,
            current_turn_player: actor_10, // current_turn = actor_10
            active_participants: active,
            player_nonce: BTreeMap::new(),
            last_action_height: 100,
            hand_start_height: 90,
            execution_mode: ExecutionMode::OnChain,
            is_finalized: false,
            phase: crate::consensus::GamePhase::default_phase(),
            pending_submitters: BTreeSet::new(),
            phase_started_height: 0,
            completed_submitters: BTreeSet::new(),
        };
        let rule = SimpleTurnRule;
        // arrival 顺序：0x20 先到（nonce=1），0x10 后到（nonce=2）
        let txs = vec![tx_player_20, tx_player_10];
        let sub = build_game_sub_block(txs, &game, &rule).expect("构造 sub-block");
        // current_turn=actor_10 的 tx 应排前（nonce=2），其他玩家排后（nonce=1）
        assert_eq!(sub.txs[0].gameturn_nonce, Some(2));
        assert_eq!(sub.txs[1].gameturn_nonce, Some(1));
    }

    #[test]
    fn build_game_sub_block_preserves_arrival_for_same_player() {
        let (game, _) = make_game(0x01, 0x10, &[0x10, 0x20]);
        let rule = SimpleTurnRule;
        let txs = vec![
            make_gameturn_tx(0x10, 1, false),
            make_gameturn_tx(0x10, 2, false),
            make_gameturn_tx(0x10, 3, false),
        ];
        let sub = build_game_sub_block(txs, &game, &rule).expect("构造 sub-block");
        // 同玩家按 arrival 顺序
        assert_eq!(sub.txs.len(), 3);
        assert_eq!(sub.txs[0].gameturn_nonce, Some(1));
        assert_eq!(sub.txs[1].gameturn_nonce, Some(2));
        assert_eq!(sub.txs[2].gameturn_nonce, Some(3));
    }

    #[test]
    fn build_game_sub_block_filters_non_gameturn_txs() {
        let (game, _) = make_game(0x01, 0x10, &[0x10, 0x20]);
        let rule = SimpleTurnRule;
        let txs = vec![
            make_gameturn_tx(0x10, 1, false),
            make_public_tx(1),     // 非 GameTurn，应被过滤
            make_force_sync_tx(2), // 非 GameTurn，应被过滤
        ];
        let sub = build_game_sub_block(txs, &game, &rule).expect("构造 sub-block");
        assert_eq!(sub.txs.len(), 1, "仅保留 GameTurn 通道 tx");
    }

    #[test]
    fn build_game_sub_block_multi_player_submit_sorts_by_arrival() {
        // 多玩家阶段：不使用 current_turn 优先级，按 arrival 顺序排序
        let (mut game, _) = make_game(0x01, 0x10, &[0x10, 0x20]);
        game.phase = crate::consensus::GamePhase::MultiPlayerSubmit {
            kind: crate::consensus::SubmitPhaseKind::Shuffle,
        };
        let rule = SimpleTurnRule;
        // arrival 顺序：0x20 先到（nonce=1），0x10 后到（nonce=2）
        // current_turn_player=0x10，但多玩家阶段不应优先
        let txs = vec![
            make_gameturn_tx(0x20, 1, false),
            make_gameturn_tx(0x10, 2, false),
        ];
        let sub = build_game_sub_block(txs, &game, &rule).expect("构造 sub-block");
        // 多玩家阶段按 arrival 顺序：0x20（nonce=1）在前，0x10（nonce=2）在后
        assert_eq!(sub.txs[0].gameturn_nonce, Some(1));
        assert_eq!(sub.txs[1].gameturn_nonce, Some(2));
    }

    // ===== validate_game_turn_tx / validate_gameturn_gas_free 测试 =====

    #[test]
    fn validate_gameturn_gas_free_ok_for_zero_gas() {
        let tx = make_gameturn_tx(0x10, 1, false);
        validate_gameturn_gas_free(&tx).expect("GameTurn 免 gas 应通过");
    }

    #[test]
    fn validate_gameturn_gas_free_rejects_nonzero_gas() {
        let mut tx = make_gameturn_tx(0x10, 1, false);
        tx.gas = Gas::new(100, 1); // 非零 gas
        let err = validate_gameturn_gas_free(&tx).unwrap_err();
        assert!(matches!(err, PokerL1Error::InsufficientBalance { .. }));
    }

    #[test]
    fn validate_gameturn_gas_free_skips_public_channel() {
        let tx = make_public_tx(1);
        validate_gameturn_gas_free(&tx).expect("Public 通道不校验免 gas");
    }

    #[test]
    fn validate_game_turn_tx_ok_for_current_player() {
        let (mut game, _) = make_game(0x01, 0x10, &[0x10, 0x20]);
        let rule = SimpleTurnRule;
        let tx = make_gameturn_tx(0x10, 1, false);
        validate_game_turn_tx(&tx, &mut game, [0x10; 20], &rule)
            .expect("当前轮次玩家 GameTurn tx 应通过");
    }

    #[test]
    fn validate_game_turn_tx_rejects_wrong_player() {
        let (mut game, _) = make_game(0x01, 0x10, &[0x10, 0x20]);
        let rule = SimpleTurnRule;
        let tx = make_gameturn_tx(0x20, 1, false);
        let err = validate_game_turn_tx(&tx, &mut game, [0x20; 20], &rule).unwrap_err();
        assert!(matches!(err, PokerL1Error::NotYourTurn { .. }));
    }

    #[test]
    fn validate_game_turn_tx_rejects_gameturn_lane_with_fallback_flag() {
        // SEC-H7：GameTurn 通道 tx 不得设置 is_fallback = true
        let (mut game, _) = make_game(0x01, 0x10, &[0x10, 0x20]);
        let rule = SimpleTurnRule;
        let mut tx = make_gameturn_tx(0x10, 1, false);
        tx.is_fallback = true; // 错误：GameTurn 通道不应设置 fallback 标识
        let err = validate_game_turn_tx(&tx, &mut game, [0x10; 20], &rule).unwrap_err();
        assert!(matches!(err, PokerL1Error::InvalidFallbackFlag));
    }

    // ===== S9 排序测试 =====

    #[test]
    fn sort_vertex_txs_s9_gameturn_before_forcesync() {
        let txs = vec![
            make_force_sync_tx(1),
            make_public_tx(2),
            make_gameturn_tx(0x10, 3, false),
            make_checkpoint_anchor_tx(),
            make_force_sync_tx(4),
        ];
        let sorted = sort_vertex_txs_s9(txs);
        // 期望顺序：GameTurn + CheckpointAnchor（先）→ Public（中）→ ForceSync（后）
        assert_eq!(sorted[0].lane_hint, TxLane::GameTurn);
        assert_eq!(sorted[1].lane_hint, TxLane::CheckpointAnchor);
        assert_eq!(sorted[2].lane_hint, TxLane::Public);
        assert_eq!(sorted[3].lane_hint, TxLane::ForceSync);
        assert_eq!(sorted[4].lane_hint, TxLane::ForceSync);
    }

    #[test]
    fn sort_vertex_txs_s9_preserves_intra_channel_order() {
        let txs = vec![
            make_gameturn_tx(0x10, 1, false),
            make_gameturn_tx(0x10, 2, false),
            make_force_sync_tx(3),
            make_force_sync_tx(4),
        ];
        let sorted = sort_vertex_txs_s9(txs);
        // GameTurn 通道内保持 arrival 顺序
        assert_eq!(sorted[0].gameturn_nonce, Some(1));
        assert_eq!(sorted[1].gameturn_nonce, Some(2));
        // ForceSync 通道内保持 arrival 顺序
        assert_eq!(sorted[2].nonce, 3);
        assert_eq!(sorted[3].nonce, 4);
    }

    // ===== R4-M4 排序测试 =====

    #[test]
    fn sort_commit_txs_r4m4_aggregates_then_s9() {
        // vertex 1: [ForceSync, GameTurn]
        // vertex 2: [GameTurn, ForceSync]
        let commit = vec![
            vec![make_force_sync_tx(1), make_gameturn_tx(0x10, 2, false)],
            vec![make_gameturn_tx(0x20, 3, false), make_force_sync_tx(4)],
        ];
        let sorted = sort_commit_txs_r4m4(commit);
        // 聚合后按 S9 排序：所有 GameTurn 先于所有 ForceSync
        assert_eq!(sorted.len(), 4);
        assert_eq!(sorted[0].lane_hint, TxLane::GameTurn);
        assert_eq!(sorted[1].lane_hint, TxLane::GameTurn);
        assert_eq!(sorted[2].lane_hint, TxLane::ForceSync);
        assert_eq!(sorted[3].lane_hint, TxLane::ForceSync);
    }

    #[test]
    fn sort_commit_txs_r4m4_empty_commit() {
        let sorted = sort_commit_txs_r4m4(vec![]);
        assert!(sorted.is_empty());
    }

    #[test]
    fn sort_commit_txs_r4m4_single_vertex() {
        let commit = vec![vec![
            make_force_sync_tx(1),
            make_gameturn_tx(0x10, 2, false),
        ]];
        let sorted = sort_commit_txs_r4m4(commit);
        assert_eq!(sorted[0].lane_hint, TxLane::GameTurn);
        assert_eq!(sorted[1].lane_hint, TxLane::ForceSync);
    }

    // ===== SEC-H6 跨 commit 抢跑防护测试 =====

    #[test]
    fn check_sech6_ok_when_prev_commit_has_no_gameturn() {
        let game_id = ObjectID::new([0xAA; 20], 1);
        let prev_turns: Vec<Transaction> = vec![];
        let phase = crate::consensus::GamePhase::default_phase();
        check_sech6_cross_commit_force_advance(&prev_turns, &game_id, &game_id, &phase)
            .expect("前一 commit 无 GameTurn → force_advance 可执行");
    }

    #[test]
    fn check_sech6_rejects_when_prev_commit_has_gameturn() {
        let game_id = ObjectID::new([0xAA; 20], 1);
        let prev_turns = vec![make_gameturn_tx(0x10, 1, false)];
        let phase = crate::consensus::GamePhase::default_phase();
        let err = check_sech6_cross_commit_force_advance(&prev_turns, &game_id, &game_id, &phase)
            .unwrap_err();
        assert!(matches!(err, PokerL1Error::Other(_)));
    }

    #[test]
    fn check_sech6_rejects_game_id_mismatch() {
        let game_id_a = ObjectID::new([0xAA; 20], 1);
        let game_id_b = ObjectID::new([0xBB; 20], 1);
        let prev_turns: Vec<Transaction> = vec![];
        let phase = crate::consensus::GamePhase::default_phase();
        let err =
            check_sech6_cross_commit_force_advance(&prev_turns, &game_id_a, &game_id_b, &phase)
                .unwrap_err();
        assert!(matches!(err, PokerL1Error::GameNotFound(_)));
    }

    #[test]
    fn check_sech6_rejects_multi_player_submit_with_prev_gameturn() {
        // Phase 5 Task 10：多玩家阶段前一 commit 有 GameTurn tx → force_advance 被拒绝
        let game_id = ObjectID::new([0xAA; 20], 1);
        let prev_turns = vec![make_gameturn_tx(0x10, 1, false)];
        let phase = crate::consensus::GamePhase::MultiPlayerSubmit {
            kind: crate::consensus::SubmitPhaseKind::Shuffle,
        };
        let err = check_sech6_cross_commit_force_advance(&prev_turns, &game_id, &game_id, &phase)
            .unwrap_err();
        assert!(matches!(err, PokerL1Error::Other(_)));
    }

    #[test]
    fn check_sech6_ok_for_multi_player_submit_without_prev_gameturn() {
        // 多玩家阶段前一 commit 无 GameTurn tx → force_advance 可执行
        let game_id = ObjectID::new([0xAA; 20], 1);
        let prev_turns: Vec<Transaction> = vec![];
        let phase = crate::consensus::GamePhase::MultiPlayerSubmit {
            kind: crate::consensus::SubmitPhaseKind::RevealToken,
        };
        check_sech6_cross_commit_force_advance(&prev_turns, &game_id, &game_id, &phase)
            .expect("多玩家阶段前一 commit 无 GameTurn → force_advance 可执行");
    }

    // ===== TimeoutProof + validate_fallback_tx 测试 =====

    fn make_timeout_proof(
        original_tx: Transaction,
        witness_count: usize,
        include_assigned: bool,
        assigned_byte: u8,
    ) -> TimeoutProof {
        let mut pubkeys = Vec::new();
        let mut sigs = Vec::new();
        for i in 0..witness_count {
            let byte = if include_assigned && i == 0 {
                assigned_byte
            } else {
                0x50 + i as u8
            };
            pubkeys.push(make_tagged_pubkey(byte, SignatureScheme::Secp256k1));
            sigs.push(vec![0u8; 65]);
        }
        TimeoutProof {
            original_tx,
            submit_height: 200,
            witness_pubkeys: pubkeys,
            witness_signatures: sigs,
            non_inclusion_proof: vec![0u8; 64],
        }
    }

    #[test]
    fn timeout_proof_validate_witness_count_ok() {
        let original = make_gameturn_tx(0x10, 1, false);
        let proof = make_timeout_proof(original, 3, false, 0x01);
        proof.validate_witness_count(5).expect("3 >= 3 应通过");
    }

    #[test]
    fn timeout_proof_validate_witness_count_rejects_below_threshold() {
        let original = make_gameturn_tx(0x10, 1, false);
        let proof = make_timeout_proof(original, 2, false, 0x01);
        let err = proof.validate_witness_count(5).unwrap_err();
        assert!(matches!(err, PokerL1Error::InvalidTimeoutProof(_)));
    }

    #[test]
    fn timeout_proof_validate_witness_independence_ok() {
        let original = make_gameturn_tx(0x10, 1, false);
        let proof = make_timeout_proof(original, 3, false, 0x01);
        let assigned = make_tagged_pubkey(0x01, SignatureScheme::Secp256k1);
        proof
            .validate_witness_independence(&assigned)
            .expect("无 assigned_validator 应通过");
    }

    #[test]
    fn timeout_proof_validate_witness_independence_rejects_assigned() {
        let original = make_gameturn_tx(0x10, 1, false);
        // witness 包含 assigned_validator（byte=0x01）
        let proof = make_timeout_proof(original, 3, true, 0x01);
        let assigned = make_tagged_pubkey(0x01, SignatureScheme::Secp256k1);
        let err = proof.validate_witness_independence(&assigned).unwrap_err();
        assert!(matches!(err, PokerL1Error::InvalidTimeoutProof(_)));
    }

    #[test]
    fn validate_fallback_tx_ok_with_valid_proof() {
        let assigned = make_tagged_pubkey(0x01, SignatureScheme::Secp256k1);
        let original = make_gameturn_tx(0x10, 5, false);
        let proof = make_timeout_proof(original, 3, false, 0x01);
        let fallback = make_gameturn_tx(0x10, 5, true);
        validate_fallback_tx(&fallback, &proof, &assigned, 5).expect("合法 fallback tx 应通过");
    }

    #[test]
    fn validate_fallback_tx_rejects_non_public_lane() {
        let assigned = make_tagged_pubkey(0x01, SignatureScheme::Secp256k1);
        let original = make_gameturn_tx(0x10, 5, false);
        let proof = make_timeout_proof(original, 3, false, 0x01);
        // fallback tx 走 GameTurn 通道（错误，应走 Public）
        let mut fallback = make_gameturn_tx(0x10, 5, true);
        fallback.lane_hint = TxLane::GameTurn;
        fallback.route_hint = RouteHint::AssignedValidator;
        fallback.gas = Gas::zero();
        let err = validate_fallback_tx(&fallback, &proof, &assigned, 5).unwrap_err();
        assert!(matches!(err, PokerL1Error::WrongLane { .. }));
    }

    #[test]
    fn validate_fallback_tx_rejects_missing_fallback_flag() {
        let assigned = make_tagged_pubkey(0x01, SignatureScheme::Secp256k1);
        let original = make_gameturn_tx(0x10, 5, false);
        let proof = make_timeout_proof(original, 3, false, 0x01);
        // fallback tx 未标记 is_fallback=true（SEC-H7 违规）
        let mut fallback = make_gameturn_tx(0x10, 5, true);
        fallback.is_fallback = false;
        let err = validate_fallback_tx(&fallback, &proof, &assigned, 5).unwrap_err();
        assert!(matches!(err, PokerL1Error::InvalidFallbackFlag));
    }

    #[test]
    fn validate_fallback_tx_rejects_missing_gameturn_nonce() {
        let assigned = make_tagged_pubkey(0x01, SignatureScheme::Secp256k1);
        let original = make_gameturn_tx(0x10, 5, false);
        let proof = make_timeout_proof(original, 3, false, 0x01);
        let mut fallback = make_gameturn_tx(0x10, 5, true);
        fallback.gameturn_nonce = None;
        let err = validate_fallback_tx(&fallback, &proof, &assigned, 5).unwrap_err();
        assert!(matches!(err, PokerL1Error::GameTurnNonceMismatch { .. }));
    }

    #[test]
    fn validate_fallback_tx_rejects_nonce_mismatch() {
        let assigned = make_tagged_pubkey(0x01, SignatureScheme::Secp256k1);
        let original = make_gameturn_tx(0x10, 5, false); // original nonce=5
        let proof = make_timeout_proof(original, 3, false, 0x01);
        let fallback = make_gameturn_tx(0x10, 6, true); // fallback nonce=6 不匹配
        let err = validate_fallback_tx(&fallback, &proof, &assigned, 5).unwrap_err();
        assert!(matches!(err, PokerL1Error::GameTurnNonceMismatch { .. }));
    }

    #[test]
    fn validate_fallback_tx_rejects_insufficient_witness() {
        let assigned = make_tagged_pubkey(0x01, SignatureScheme::Secp256k1);
        let original = make_gameturn_tx(0x10, 5, false);
        // 仅 2 个 witness（< 3 阈值）
        let proof = make_timeout_proof(original, 2, false, 0x01);
        let fallback = make_gameturn_tx(0x10, 5, true);
        let err = validate_fallback_tx(&fallback, &proof, &assigned, 5).unwrap_err();
        assert!(matches!(err, PokerL1Error::InvalidTimeoutProof(_)));
    }

    #[test]
    fn validate_fallback_tx_rejects_witness_includes_assigned() {
        let assigned = make_tagged_pubkey(0x01, SignatureScheme::Secp256k1);
        let original = make_gameturn_tx(0x10, 5, false);
        // witness 包含 assigned_validator
        let proof = make_timeout_proof(original, 3, true, 0x01);
        let fallback = make_gameturn_tx(0x10, 5, true);
        let err = validate_fallback_tx(&fallback, &proof, &assigned, 5).unwrap_err();
        assert!(matches!(err, PokerL1Error::InvalidTimeoutProof(_)));
    }

    // ===== 序列化往返测试 =====

    #[test]
    fn game_sub_block_bcs_roundtrip() {
        let (game, _) = make_game(0x01, 0x10, &[0x10, 0x20]);
        let rule = SimpleTurnRule;
        let txs = vec![
            make_gameturn_tx(0x10, 1, false),
            make_gameturn_tx(0x10, 2, false),
        ];
        let sub = build_game_sub_block(txs, &game, &rule).expect("构造 sub-block");
        let bytes = borsh::to_vec(&sub).unwrap();
        let recovered: GameSubBlock = borsh::from_slice(&bytes).unwrap();
        assert_eq!(sub, recovered);
    }

    #[test]
    fn timeout_proof_bcs_roundtrip() {
        let original = make_gameturn_tx(0x10, 5, false);
        let proof = make_timeout_proof(original, 3, false, 0x01);
        let bytes = borsh::to_vec(&proof).unwrap();
        let recovered: TimeoutProof = borsh::from_slice(&bytes).unwrap();
        assert_eq!(proof, recovered);
    }

    // ===== 防误用：ObjectID / Ownership import 仍可用 =====

    #[test]
    fn object_id_and_ownership_still_importable() {
        let id = ObjectID::new([1u8; 20], 0);
        let _ = Ownership::Shared;
        let _ = Object::new(id, Ownership::Shared, "T", b"d".to_vec(), None);
    }
}
