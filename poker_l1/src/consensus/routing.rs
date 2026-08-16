//! tx 双通道分类与客户端路由（Task 7 — SubTask 7.1~7.5）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）：
//! - **SubTask 7.1**：`TxLane` 枚举（Public / GameTurn / CheckpointAnchor / ForceSync）
//!   — 已在 [`crate::transaction`] 模块定义，本模块仅消费
//! - **SubTask 7.2**：tx 路由规则
//!   - `GameTurn` + `CheckpointAnchor` → `assigned_validator`
//!   - `ForceSync` + `Public` → 任意 validator（客户端多副本广播）
//! - **SubTask 7.3**：`TurnRule` — 给定 Game 状态，计算 `current_turn` 玩家地址
//! - **SubTask 7.4**：assigned_validator 校验轮转约束，非当前轮次玩家提交 GameTurn tx
//!   返回 [`PokerL1Error::NotYourTurn`]；允许 read-only 查询
//! - **SubTask 7.5**：非 assigned_validator 收到 GameTurn / CheckpointAnchor tx 时
//!   返回 [`PokerL1Error::NotAssignedValidator`]（实际转发逻辑由 Phase 6 网络层实现）
//!
//! ## Phase 2 最小化 Game 状态
//!
//! 完整 poker 游戏逻辑（bet / call / raise / fold 状态机）在 Phase 3 合约层实现。
//! Phase 2 仅需 routing 所需字段：`id` / `assigned_validator` / `current_turn_player` /
//! `active_participants` / `last_action_height` / `player_nonce`（SEC-L3 gameturn_nonce 存储）。
//!
//! ## 设计决策
//!
//! - `TurnRule` 为 trait，允许不同扑克变体（Texas Hold'em / Omaha / ...）实现不同轮转规则；
//!   Phase 2 提供默认实现 [`SimpleTurnRule`]（按 `active_participants` 顺序轮转）。
//! - `GameStatus` 不含完整牌局状态（手牌 / 公共牌 / 底池），那些字段由 Phase 3 合约对象承载；
//!   Phase 2 routing 仅消费 routing 相关字段。
//! - 客户端"多副本广播"与"转发到 assigned_validator"为网络层（Phase 6）职责，
//!   本模块仅提供校验函数供 validator 在装入 vertex 前调用。

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::error::{PokerL1Error, PokerL1Result};
use crate::signature::TaggedPubkey;
use crate::transaction::{RouteHint, Transaction, TxLane};
use crate::{Address, BlockHeight};

/// Game 状态最小化结构（Phase 2 routing 用）。
///
/// 完整 Game 对象（含牌局状态 / 买入锁仓 / 台费分配）由 Phase 3 合约层实现，
/// 此处仅定义 routing / DAG sub-block / fallback / slashing 所需字段。
///
/// 字段说明：
/// - `id`：Game 对象 ID（全局唯一）
/// - `assigned_validator`：当前 epoch 的 assigned_validator（spec：`hash(G.id, epoch) % |V|`）
/// - `current_turn_player`：当前轮次玩家地址（由 [`TurnRule`] 计算）
/// - `active_participants`：当前在座玩家（未 fold / 未 sit-out）地址集合
/// - `player_nonce`：per-game per-player 计数器（SEC-L3 / NEW-M9：GameTurn tx 重放保护）
/// - `last_action_height`：最后一次 GameTurn / checkpoint_anchor 的 block height
///   （NEW-C2 修复：字段统一为 `last_action_height`，force_advance 判定依据）
/// - `execution_mode`：OnChain / OffChain（影响 Phase 5 流程，Phase 2 仅记录）
/// - `is_finalized`：结算后冻结为 true（spec：结算后 Game 对象变 Immutable）
/// - `phase`：当前游戏阶段（Betting 或 MultiPlayerSubmit），默认 `Betting { Preflop }`
/// - `pending_submitters`：多玩家阶段待提交者集合（下注阶段为空）
/// - `phase_started_height`：当前阶段开始的 block height（用于超时判定）
/// - `completed_submitters`：多玩家阶段已提交者集合（用于进度追踪）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct GameStatus {
    /// Game 对象 ID。
    pub id: crate::object_model::ObjectID,
    /// 当前 epoch 的 assigned_validator（spec SubTask 12.1：`hash(G.id, current_epoch) % |V|`）。
    pub assigned_validator: TaggedPubkey,
    /// 当前轮次玩家地址（由 [`TurnRule::current_turn`] 计算）。
    pub current_turn_player: Address,
    /// 当前在座玩家地址集合（未 fold / 未 sit-out）。
    /// NEW-M11：fold 事件时动态收缩（fold tx 上链作为证据）。
    pub active_participants: BTreeSet<Address>,
    /// per-game per-player GameTurn nonce（SEC-L3 / NEW-M9）。
    /// 玩家首次 join 时初始化为 0；冷启动（无记录）按 0 处理。
    pub player_nonce: BTreeMap<Address, u64>,
    /// 最后一次 GameTurn / checkpoint_anchor 的 block height（NEW-C2）。
    pub last_action_height: BlockHeight,
    /// 当前手牌起始 block height（SubTask 11.4：判定 hand_max_duration 超时）。
    ///
    /// 每次 `force_advance` / 新手牌开始时更新。
    /// SEC-M5：超时判定以 `block.height` 为权威，禁止以 `timestamp_ms` 触发。
    pub hand_start_height: BlockHeight,
    /// 执行模式（OnChain / OffChain）。
    pub execution_mode: ExecutionMode,
    /// 是否已结算（结算后 Game 对象冻结为 Immutable）。
    pub is_finalized: bool,
    /// 当前游戏阶段（Betting 或 MultiPlayerSubmit）。
    /// 默认 `Betting { round: Preflop }`，向后兼容既有 GameStatus。
    pub phase: GamePhase,
    /// 多玩家阶段待提交者集合（下注阶段为空）。
    /// 阶段切换时重置为该阶段的合法提交者集合；玩家成功提交后从此集合移除。
    pub pending_submitters: BTreeSet<Address>,
    /// 当前阶段开始的 block height（用于超时判定）。
    /// 阶段切换时更新为 `last_action_height + 1`。
    pub phase_started_height: BlockHeight,
    /// 多玩家阶段已提交者集合（用于进度追踪）。
    /// 阶段切换时清空；玩家成功提交后插入此集合。
    pub completed_submitters: BTreeSet<Address>,
}

/// Game 执行模式（spec：合约可选 OnChain 默认 / OffChain 可选）。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum ExecutionMode {
    /// 全链上执行（默认）。
    OnChain,
    /// 链下执行 + ZK 证明（Phase 5）。
    OffChain,
}

/// 下注轮次（Texas Hold'em 四轮下注 + 摊牌）。
///
/// 用于 [`GamePhase::Betting`] 标记当前下注轮次。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum BettingRound {
    /// Preflop：翻牌前下注轮（盲注后、翻牌前）。
    Preflop,
    /// Flop：翻牌后下注轮（前三张公共牌发出后）。
    Flop,
    /// Turn：转牌下注轮（第四张公共牌发出后）。
    Turn,
    /// River：河牌下注轮（第五张公共牌发出后）。
    River,
    /// Showdown：摊牌阶段（所有下注结束，比较手牌）。
    Showdown,
}

/// 多玩家提交阶段的子类型（spec：4 种并行/顺序提交阶段）。
///
/// 用于 [`GamePhase::MultiPlayerSubmit`] 标记当前多玩家提交子阶段。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum SubmitPhaseKind {
    /// 洗牌提交：活跃玩家依次提交 shuffle proof（顺序）。
    Shuffle,
    /// Reveal Token 提交：每张牌的密钥持有者并行提交 reveal token。
    RevealToken,
    /// Reconstruct Deck 提交：所有活跃玩家并行提交重建牌组。
    Reconstruct,
    /// Leave Proof 提交：任意活跃玩家可随时提交离开证明（非阶段绑定，被动行为）。
    LeaveProof,
}

/// Game 阶段枚举（spec：区分下注阶段与多玩家提交阶段）。
///
/// - [`GamePhase::Betting`]：单玩家轮转（Preflop / Flop / Turn / River / Showdown betting），
///   使用 `current_turn_player` 与 [`TurnRule::current_turn`] 校验
/// - [`GamePhase::MultiPlayerSubmit`]：一组玩家并行/顺序提交（shuffle / reveal / reconstruct / leave），
///   使用 `pending_submitters` 与 [`TurnRule::current_submitters`] 校验
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum GamePhase {
    /// 下注阶段：单玩家轮转。
    Betting {
        /// 当前下注轮次。
        round: BettingRound,
    },
    /// 多玩家提交阶段：一组玩家并行/顺序提交。
    MultiPlayerSubmit {
        /// 子阶段类型。
        kind: SubmitPhaseKind,
    },
}

impl GamePhase {
    /// 默认阶段：Betting { round: Preflop }（向后兼容）。
    pub const fn default_phase() -> Self {
        Self::Betting {
            round: BettingRound::Preflop,
        }
    }

    /// 判定是否为下注阶段。
    pub const fn is_betting(&self) -> bool {
        matches!(self, Self::Betting { .. })
    }

    /// 判定是否为多玩家提交阶段。
    pub const fn is_multi_player_submit(&self) -> bool {
        matches!(self, Self::MultiPlayerSubmit { .. })
    }
}

impl Default for GamePhase {
    fn default() -> Self {
        Self::default_phase()
    }
}

/// 轮转规则 trait（SubTask 7.3）。
///
/// 给定 Game 状态，计算 `current_turn` 玩家地址。
/// 不同扑克变体（Texas Hold'em / Omaha / Stud / ...）可实现不同轮转规则。
///
/// Phase 2 提供默认实现 [`SimpleTurnRule`]：按 `active_participants` BTreeSet 顺序轮转。
///
/// # 多玩家阶段扩展
///
/// `current_turn()` 在 [`GamePhase::MultiPlayerSubmit`] 阶段返回 `None`（无单一当前轮次玩家）；
/// 此时应使用 [`Self::current_submitters`] 获取合法提交者集合，
/// [`Self::is_submission_complete`] 判定是否所有提交者已完成，
/// [`Self::advance_phase`] 推进到下一阶段。
pub trait TurnRule: Send + Sync {
    /// 计算当前轮次玩家地址。
    ///
    /// 返回 `None` 表示无活跃玩家（Game 已结束或异常状态），
    /// 或当前处于 [`GamePhase::MultiPlayerSubmit`] 阶段（多玩家阶段无单一 current_turn）。
    fn current_turn(&self, game: &GameStatus) -> Option<Address>;

    /// 推进到下一轮次玩家。
    ///
    /// 调用方负责在 GameTurn tx 执行成功后调用此方法更新 `game.current_turn_player`。
    /// 返回新的当前轮次玩家地址；返回 `None` 表示无下一玩家（Game 结束）。
    ///
    /// 仅 [`GamePhase::Betting`] 阶段有效；多玩家阶段调用为 no-op 返回 `None`。
    fn advance_turn(&self, game: &mut GameStatus) -> Option<Address>;

    /// 返回当前阶段合法提交者集合（多玩家阶段）。
    ///
    /// - [`GamePhase::Betting`] 阶段：返回空集合（下注阶段使用 `current_turn()` 校验）
    /// - [`GamePhase::MultiPlayerSubmit`] 阶段：返回该子阶段的合法提交者集合
    ///   - `Shuffle` / `Reconstruct` / `LeaveProof`：返回 `active_participants` 副本
    ///   - `RevealToken`：返回 `pending_submitters` 副本（密钥持有者已在 pending 中）
    fn current_submitters(&self, game: &GameStatus) -> BTreeSet<Address>;

    /// 判定多玩家阶段是否所有提交者已完成。
    ///
    /// - [`GamePhase::Betting`] 阶段：返回 `true`（下注阶段不使用此判定）
    /// - [`GamePhase::MultiPlayerSubmit`] 阶段：返回 `pending_submitters.is_empty()`
    fn is_submission_complete(&self, game: &GameStatus) -> bool;

    /// 推进到下一阶段（多玩家 → 下阶段 / 回到 Betting）。
    ///
    /// 推进时重置 `pending_submitters` / `completed_submitters` / `phase_started_height`
    /// （设为 `last_action_height + 1`）。
    ///
    /// 返回新的 [`GamePhase`]；失败返回 [`PhaseTransitionError`]。
    fn advance_phase(&self, game: &mut GameStatus) -> Result<GamePhase, PhaseTransitionError>;
}

/// 阶段切换错误（[`TurnRule::advance_phase`] 返回）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PhaseTransitionError {
    /// 待提交者集合非空，不可推进阶段（须先完成所有提交或超时 kick）。
    #[error("pending submitters not empty: count={0}")]
    PendingSubmittersNotEmpty(usize),
    /// 非法的阶段转换（如 Betting 阶段调用 advance_phase，或 Unsupported 转换路径）。
    #[error("invalid phase transition from {0:?}")]
    InvalidPhaseTransition(GamePhase),
}

/// 默认轮转规则：按 `active_participants` BTreeSet 顺序循环轮转。
///
/// 适用于大多数扑克变体（Texas Hold'em / Omaha 等）的简化版本次。
/// 完整扑克规则（含盲注 / button 移动 / side pot）由 Phase 3 合约层实现。
#[derive(Debug, Clone, Copy, Default)]
pub struct SimpleTurnRule;

impl TurnRule for SimpleTurnRule {
    fn current_turn(&self, game: &GameStatus) -> Option<Address> {
        // 多玩家阶段无单一 current_turn
        if game.phase.is_multi_player_submit() {
            return None;
        }
        if game.is_finalized || game.active_participants.is_empty() {
            return None;
        }
        // 校验 current_turn_player 仍在 active_participants 中
        if game.active_participants.contains(&game.current_turn_player) {
            Some(game.current_turn_player)
        } else {
            // current_turn_player 已 fold / sit-out，返回首个活跃玩家
            game.active_participants.iter().next().copied()
        }
    }

    fn advance_turn(&self, game: &mut GameStatus) -> Option<Address> {
        // 多玩家阶段不推进 current_turn
        if game.phase.is_multi_player_submit() {
            return None;
        }
        if game.is_finalized || game.active_participants.is_empty() {
            return None;
        }
        let participants: Vec<Address> = game.active_participants.iter().copied().collect();
        let current_idx = participants
            .iter()
            .position(|p| *p == game.current_turn_player)
            .unwrap_or(0);
        let next_idx = (current_idx + 1) % participants.len();
        game.current_turn_player = participants[next_idx];
        Some(game.current_turn_player)
    }

    fn current_submitters(&self, game: &GameStatus) -> BTreeSet<Address> {
        // SimpleTurnRule 仅支持下注阶段：返回空集合
        let _ = game;
        BTreeSet::new()
    }

    fn is_submission_complete(&self, game: &GameStatus) -> bool {
        // SimpleTurnRule 仅支持下注阶段：视为已完成
        let _ = game;
        true
    }

    fn advance_phase(&self, game: &mut GameStatus) -> Result<GamePhase, PhaseTransitionError> {
        // SimpleTurnRule 不处理多玩家阶段：Betting 阶段调用返回 InvalidPhaseTransition
        Err(PhaseTransitionError::InvalidPhaseTransition(game.phase))
    }
}

/// 校验 tx 通道与路由提示一致性（SubTask 7.2）。
///
/// spec：
/// - `GameTurn` + `CheckpointAnchor` → `RouteHint::AssignedValidator`
/// - `Public` + `ForceSync` → `RouteHint::AnyValidator`
///
/// 不一致返回 [`PokerL1Error::WrongLane`]。
pub const fn validate_lane_route(tx: &Transaction) -> PokerL1Result<()> {
    match (tx.lane_hint, tx.route_hint) {
        (TxLane::GameTurn | TxLane::CheckpointAnchor, RouteHint::AssignedValidator) => Ok(()),
        (TxLane::Public | TxLane::ForceSync, RouteHint::AnyValidator) => Ok(()),
        _ => Err(PokerL1Error::WrongLane {
            lane: tx.lane_hint,
            route: tx.route_hint,
        }),
    }
}

/// 校验接收 validator 是否为 Game 的 assigned_validator（SubTask 7.5）。
///
/// spec：
/// - `GameTurn` + `CheckpointAnchor` 通道 tx 必须提交给 assigned_validator
/// - 非 assigned_validator 收到此类 tx 时应返回 [`PokerL1Error::NotAssignedValidator`]
///   （网络层可由客户端多副本广播避免；本函数仅做 validator 端校验）
/// - `Public` + `ForceSync` 通道 tx 任意 validator 可接收，跳过此校验
///
/// 参数：
/// - `tx`：待校验交易
/// - `game`：Game 状态（含 assigned_validator）
/// - `receiver`：当前接收 tx 的 validator 的 tagged pubkey
pub fn validate_assigned_validator(
    tx: &Transaction,
    game: &GameStatus,
    receiver: &TaggedPubkey,
) -> PokerL1Result<()> {
    // 仅 GameTurn / CheckpointAnchor 通道需要 assigned_validator 校验
    if !matches!(tx.lane_hint, TxLane::GameTurn | TxLane::CheckpointAnchor) {
        return Ok(());
    }
    if &game.assigned_validator != receiver {
        return Err(PokerL1Error::NotAssignedValidator {
            game_id: game.id,
            assigned: game.assigned_validator.clone(),
            receiver: receiver.clone(),
        });
    }
    Ok(())
}

/// 校验 GameTurn tx 提交者是否为当前轮次玩家（SubTask 7.4）。
///
/// spec：
/// - assigned_validator 校验轮转约束，非当前轮次玩家提交 GameTurn tx
///   返回 [`PokerL1Error::NotYourTurn`]
/// - 允许 read-only 查询（非 tx 提交，本函数不校验）
/// - `Public` / `ForceSync` / `CheckpointAnchor` 通道 tx 不走轮转约束，跳过此校验
///
/// 参数：
/// - `tx`：待校验交易
/// - `game`：Game 状态（含 current_turn_player）
/// - `actor`：tx 签名者派生地址（`blake2b_256(tagged_pubkey)[0..20]`）
/// - `turn_rule`：轮转规则实现
///
/// 注意：fallback tx（`is_fallback = true`）虽走 GameTurn 通道语义，
/// 但由非 assigned_validator 接受，本函数仍校验轮转约束（SEC-H7：fallback tx
/// 使用 gameturn_nonce，排序仍按 GameTurn 通道 current_turn）。
pub fn validate_turn_order(
    tx: &Transaction,
    game: &GameStatus,
    actor: Address,
    turn_rule: &dyn TurnRule,
) -> PokerL1Result<()> {
    // 仅 GameTurn 通道（含 fallback）走轮转约束
    if tx.lane_hint != TxLane::GameTurn {
        return Ok(());
    }
    let current = turn_rule
        .current_turn(game)
        .ok_or(PokerL1Error::GameNotFound(game.id))?;
    if current != actor {
        return Err(PokerL1Error::NotYourTurn {
            game_id: game.id,
            phase: game.phase,
            current_turn: current,
            actor,
        });
    }
    Ok(())
}

/// 阶段感知的 GameTurn tx 校验（spec：多玩家并行提交阶段扩展）。
///
/// 根据 [`GameStatus::phase`] 分支校验：
/// - 非 GameTurn 通道：跳过校验
/// - [`GamePhase::Betting`]：保持原 `current_turn_player` 匹配逻辑（调用 [`validate_turn_order`]）
/// - [`GamePhase::MultiPlayerSubmit`]（除 LeaveProof）：校验 `actor` 在 `pending_submitters` 中，
///   否则返回 [`PokerL1Error::NotEligibleSubmitter`]
/// - [`SubmitPhaseKind::LeaveProof`]：校验 `actor` 在 `active_participants` 中
///   （不要求在 `pending_submitters` 中）
///
/// 成功后更新追踪集合：
/// - 非 LeaveProof 多玩家阶段：从 `pending_submitters` 移除 actor，插入 `completed_submitters`
/// - LeaveProof 阶段：从 `pending_submitters` 移除 actor（若在），插入 `completed_submitters`，
///   并从 `active_participants` 移除 actor
///
/// 参数：
/// - `tx`：待校验交易
/// - `game`：Game 状态（`&mut` 用于更新 pending_submitters / completed_submitters / active_participants）
/// - `actor`：tx 签名者派生地址
/// - `turn_rule`：轮转规则实现
pub fn validate_game_turn_phase_aware(
    tx: &Transaction,
    game: &mut GameStatus,
    actor: Address,
    turn_rule: &dyn TurnRule,
) -> PokerL1Result<()> {
    // 非 GameTurn 通道跳过
    if tx.lane_hint != TxLane::GameTurn {
        return Ok(());
    }

    match game.phase {
        GamePhase::Betting { .. } => {
            // 下注阶段：保持原 current_turn_player 匹配逻辑
            validate_turn_order(tx, game, actor, turn_rule)
        }
        GamePhase::MultiPlayerSubmit { kind } => match kind {
            SubmitPhaseKind::LeaveProof => {
                // LeaveProof：校验 actor 在 active_participants 中（不要求在 pending_submitters）
                if !game.active_participants.contains(&actor) {
                    return Err(PokerL1Error::NotEligibleSubmitter {
                        game_id: game.id,
                        phase: game.phase,
                        pending: game.pending_submitters.clone(),
                        actor,
                    });
                }
                // 成功：从 active_participants 移除，从 pending_submitters 移除（若在），插入 completed
                game.active_participants.remove(&actor);
                game.pending_submitters.remove(&actor);
                game.completed_submitters.insert(actor);
                Ok(())
            }
            _ => {
                // Shuffle / RevealToken / Reconstruct：校验 actor 在 pending_submitters 中
                if !game.pending_submitters.contains(&actor) {
                    return Err(PokerL1Error::NotEligibleSubmitter {
                        game_id: game.id,
                        phase: game.phase,
                        pending: game.pending_submitters.clone(),
                        actor,
                    });
                }
                // 成功：从 pending_submitters 移除，插入 completed_submitters
                game.pending_submitters.remove(&actor);
                game.completed_submitters.insert(actor);
                Ok(())
            }
        },
    }
}

/// 校验玩家活跃 Game 数量是否超限（SubTask 8.7：S8 修复）。
///
/// spec：join 时校验玩家活跃 Game 数 <= `max_active_games_per_player`（默认 10），
/// 超出返回 [`PokerL1Error::TooManyActiveGames`]。
pub const fn validate_active_games_limit(
    player: Address,
    active_count: u32,
    limit: u32,
) -> PokerL1Result<()> {
    if active_count > limit {
        return Err(PokerL1Error::TooManyActiveGames {
            player,
            active: active_count,
            limit,
        });
    }
    Ok(())
}

/// 默认 `max_active_games_per_player`（spec SubTask 8.7：默认 10）。
pub const DEFAULT_MAX_ACTIVE_GAMES_PER_PLAYER: u32 = 10;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object_model::{ObjectID, Ownership};
    use crate::signature::tagged_pubkey::{SignatureScheme, encode_tag};
    use crate::transaction::{Gas, Transaction};

    /// 构造测试用 tagged pubkey（不验证签名，仅用于地址派生与比对）。
    fn make_tagged_pubkey(byte: u8, scheme: SignatureScheme) -> TaggedPubkey {
        let raw_len = scheme.raw_pubkey_len();
        TaggedPubkey {
            tag: encode_tag(scheme, 1),
            raw: vec![byte; raw_len],
        }
    }

    /// 构造测试用 Game 状态。
    fn make_game(
        assigned_byte: u8,
        current_turn_byte: u8,
        participants: &[u8],
    ) -> (GameStatus, TaggedPubkey, Address, Vec<Address>) {
        let assigned_tp = make_tagged_pubkey(assigned_byte, SignatureScheme::Secp256k1);
        let assigned_addr = crate::account::derive_address(&assigned_tp);
        let mut active = BTreeSet::new();
        let mut addrs = Vec::new();
        for &b in participants {
            let a = [b; 20];
            active.insert(a);
            addrs.push(a);
        }
        let current_turn = [current_turn_byte; 20];
        let game = GameStatus {
            id: ObjectID::new([0xAA; 20], 1),
            assigned_validator: assigned_tp.clone(),
            current_turn_player: current_turn,
            active_participants: active,
            player_nonce: BTreeMap::new(),
            last_action_height: 100,
            hand_start_height: 90,
            execution_mode: ExecutionMode::OnChain,
            is_finalized: false,
            phase: GamePhase::default_phase(),
            pending_submitters: BTreeSet::new(),
            phase_started_height: 0,
            completed_submitters: BTreeSet::new(),
        };
        (game, assigned_tp, assigned_addr, addrs)
    }

    /// 构造最小化 Transaction（仅 lane / route 字段有效，其他字段为零值）。
    fn make_tx(lane: TxLane, route: RouteHint, is_fallback: bool) -> Transaction {
        let gas = match lane {
            TxLane::GameTurn | TxLane::CheckpointAnchor => Gas::zero(),
            TxLane::Public | TxLane::ForceSync => Gas::new(1_000_000, 1),
        };
        Transaction {
            inputs: vec![],
            outputs: vec![],
            contract_call: None,
            tagged_pubkey: make_tagged_pubkey(0x02, SignatureScheme::Secp256k1),
            signature: vec![0; 65],
            gas,
            lane_hint: lane,
            route_hint: route,
            chain_id: crate::DEFAULT_CHAIN_ID,
            nonce: 0,
            gameturn_nonce: if lane == TxLane::GameTurn {
                Some(0)
            } else {
                None
            },
            is_fallback,
        }
    }

    // ===== SubTask 7.2: validate_lane_route 测试 =====

    #[test]
    fn validate_lane_route_ok_for_public() {
        let tx = make_tx(TxLane::Public, RouteHint::AnyValidator, false);
        validate_lane_route(&tx).expect("Public + AnyValidator 应通过");
    }

    #[test]
    fn validate_lane_route_ok_for_gameturn() {
        let tx = make_tx(TxLane::GameTurn, RouteHint::AssignedValidator, false);
        validate_lane_route(&tx).expect("GameTurn + AssignedValidator 应通过");
    }

    #[test]
    fn validate_lane_route_ok_for_checkpoint_anchor() {
        let tx = make_tx(
            TxLane::CheckpointAnchor,
            RouteHint::AssignedValidator,
            false,
        );
        validate_lane_route(&tx).expect("CheckpointAnchor + AssignedValidator 应通过");
    }

    #[test]
    fn validate_lane_route_ok_for_force_sync() {
        let tx = make_tx(TxLane::ForceSync, RouteHint::AnyValidator, false);
        validate_lane_route(&tx).expect("ForceSync + AnyValidator 应通过");
    }

    #[test]
    fn validate_lane_route_rejects_gameturn_with_any_validator() {
        let tx = make_tx(TxLane::GameTurn, RouteHint::AnyValidator, false);
        let err = validate_lane_route(&tx).unwrap_err();
        assert!(matches!(err, PokerL1Error::WrongLane { .. }));
    }

    #[test]
    fn validate_lane_route_rejects_public_with_assigned_validator() {
        let tx = make_tx(TxLane::Public, RouteHint::AssignedValidator, false);
        let err = validate_lane_route(&tx).unwrap_err();
        assert!(matches!(err, PokerL1Error::WrongLane { .. }));
    }

    // ===== SubTask 7.5: validate_assigned_validator 测试 =====

    #[test]
    fn validate_assigned_validator_ok_for_gameturn_to_assigned() {
        let (game, assigned_tp, _, _) = make_game(0x01, 0x10, &[0x10, 0x20, 0x30]);
        let tx = make_tx(TxLane::GameTurn, RouteHint::AssignedValidator, false);
        validate_assigned_validator(&tx, &game, &assigned_tp)
            .expect("GameTurn 提交给 assigned_validator 应通过");
    }

    #[test]
    fn validate_assigned_validator_rejects_gameturn_to_non_assigned() {
        let (game, assigned_tp, _, _) = make_game(0x01, 0x10, &[0x10, 0x20, 0x30]);
        let other_tp = make_tagged_pubkey(0x99, SignatureScheme::Secp256k1);
        let tx = make_tx(TxLane::GameTurn, RouteHint::AssignedValidator, false);
        let err = validate_assigned_validator(&tx, &game, &other_tp).unwrap_err();
        assert!(matches!(err, PokerL1Error::NotAssignedValidator { .. }));
        // assigned_tp 应能通过（对照）
        validate_assigned_validator(&tx, &game, &assigned_tp).expect("assigned_validator 应通过");
    }

    #[test]
    fn validate_assigned_validator_skips_public_channel() {
        let (game, _assigned_tp, _, _) = make_game(0x01, 0x10, &[0x10, 0x20, 0x30]);
        let other_tp = make_tagged_pubkey(0x99, SignatureScheme::Secp256k1);
        // Public / ForceSync 通道任意 validator 都能接收
        let tx_pub = make_tx(TxLane::Public, RouteHint::AnyValidator, false);
        validate_assigned_validator(&tx_pub, &game, &other_tp)
            .expect("Public 通道任意 validator 应通过");
        let tx_force = make_tx(TxLane::ForceSync, RouteHint::AnyValidator, false);
        validate_assigned_validator(&tx_force, &game, &other_tp)
            .expect("ForceSync 通道任意 validator 应通过");
    }

    #[test]
    fn validate_assigned_validator_ok_for_checkpoint_anchor() {
        let (game, assigned_tp, _, _) = make_game(0x01, 0x10, &[0x10, 0x20, 0x30]);
        let tx = make_tx(
            TxLane::CheckpointAnchor,
            RouteHint::AssignedValidator,
            false,
        );
        validate_assigned_validator(&tx, &game, &assigned_tp)
            .expect("CheckpointAnchor 提交给 assigned_validator 应通过");
    }

    // ===== SubTask 7.3 / 7.4: TurnRule + validate_turn_order 测试 =====

    #[test]
    fn simple_turn_rule_current_turn_returns_player_in_active() {
        let (game, _, _, _) = make_game(0x01, 0x10, &[0x10, 0x20, 0x30]);
        let rule = SimpleTurnRule;
        assert_eq!(rule.current_turn(&game), Some([0x10; 20]));
    }

    #[test]
    fn simple_turn_rule_current_turn_returns_none_when_finalized() {
        let (mut game, _, _, _) = make_game(0x01, 0x10, &[0x10, 0x20, 0x30]);
        game.is_finalized = true;
        let rule = SimpleTurnRule;
        assert_eq!(rule.current_turn(&game), None);
    }

    #[test]
    fn simple_turn_rule_current_turn_returns_none_when_empty() {
        let (mut game, _, _, _) = make_game(0x01, 0x10, &[0x10]);
        game.active_participants.clear();
        let rule = SimpleTurnRule;
        assert_eq!(rule.current_turn(&game), None);
    }

    #[test]
    fn simple_turn_rule_current_turn_fallback_when_current_player_folded() {
        // current_turn_player 已 fold（不在 active_participants）
        let (game, _, _, _) = make_game(0x01, 0x99, &[0x10, 0x20, 0x30]);
        // current_turn=0x99 不在 active 中，应返回首个活跃玩家 0x10
        let rule = SimpleTurnRule;
        assert_eq!(rule.current_turn(&game), Some([0x10; 20]));
    }

    #[test]
    fn simple_turn_rule_advance_rotates_in_order() {
        let (mut game, _, _, _) = make_game(0x01, 0x10, &[0x10, 0x20, 0x30]);
        let rule = SimpleTurnRule;
        assert_eq!(rule.current_turn(&game), Some([0x10; 20]));
        assert_eq!(rule.advance_turn(&mut game), Some([0x20; 20]));
        assert_eq!(rule.advance_turn(&mut game), Some([0x30; 20]));
        // 循环回到首个
        assert_eq!(rule.advance_turn(&mut game), Some([0x10; 20]));
    }

    #[test]
    fn validate_turn_order_ok_for_current_player() {
        let (game, _, _, _) = make_game(0x01, 0x10, &[0x10, 0x20, 0x30]);
        let tx = make_tx(TxLane::GameTurn, RouteHint::AssignedValidator, false);
        let rule = SimpleTurnRule;
        validate_turn_order(&tx, &game, [0x10; 20], &rule).expect("当前轮次玩家应通过");
    }

    #[test]
    fn validate_turn_order_rejects_wrong_player() {
        let (game, _, _, _) = make_game(0x01, 0x10, &[0x10, 0x20, 0x30]);
        let tx = make_tx(TxLane::GameTurn, RouteHint::AssignedValidator, false);
        let rule = SimpleTurnRule;
        let err = validate_turn_order(&tx, &game, [0x20; 20], &rule).unwrap_err();
        assert!(matches!(err, PokerL1Error::NotYourTurn { .. }));
    }

    #[test]
    fn validate_turn_order_skips_non_gameturn_channel() {
        let (game, _, _, _) = make_game(0x01, 0x10, &[0x10, 0x20, 0x30]);
        let rule = SimpleTurnRule;
        // Public / ForceSync / CheckpointAnchor 通道不走轮转约束
        let tx_pub = make_tx(TxLane::Public, RouteHint::AnyValidator, false);
        validate_turn_order(&tx_pub, &game, [0x99; 20], &rule).expect("Public 通道不走轮转约束");
        let tx_ca = make_tx(
            TxLane::CheckpointAnchor,
            RouteHint::AssignedValidator,
            false,
        );
        validate_turn_order(&tx_ca, &game, [0x99; 20], &rule)
            .expect("CheckpointAnchor 通道不走轮转约束");
    }

    #[test]
    fn validate_turn_order_rejects_when_game_finalized() {
        let (mut game, _, _, _) = make_game(0x01, 0x10, &[0x10, 0x20, 0x30]);
        game.is_finalized = true;
        let tx = make_tx(TxLane::GameTurn, RouteHint::AssignedValidator, false);
        let rule = SimpleTurnRule;
        let err = validate_turn_order(&tx, &game, [0x10; 20], &rule).unwrap_err();
        assert!(matches!(err, PokerL1Error::GameNotFound(_)));
    }

    #[test]
    fn validate_turn_order_allows_fallback_tx_with_current_player() {
        // fallback tx 仍按 GameTurn 通道语义校验轮转（SEC-H7）
        let (game, _, _, _) = make_game(0x01, 0x10, &[0x10, 0x20, 0x30]);
        let tx = make_tx(TxLane::GameTurn, RouteHint::AssignedValidator, true);
        let rule = SimpleTurnRule;
        validate_turn_order(&tx, &game, [0x10; 20], &rule).expect("fallback tx 当前轮次玩家应通过");
    }

    // ===== SubTask 8.7: validate_active_games_limit 测试 =====

    #[test]
    fn validate_active_games_limit_ok_when_within_limit() {
        validate_active_games_limit([0x01; 20], 5, 10).expect("5 <= 10 应通过");
    }

    #[test]
    fn validate_active_games_limit_rejects_when_exceeded() {
        let err = validate_active_games_limit([0x01; 20], 11, 10).unwrap_err();
        assert!(matches!(err, PokerL1Error::TooManyActiveGames { .. }));
    }

    #[test]
    fn validate_active_games_limit_default_is_10() {
        assert_eq!(DEFAULT_MAX_ACTIVE_GAMES_PER_PLAYER, 10);
    }

    // ===== GameStatus 序列化往返测试 =====

    #[test]
    fn game_status_bcs_roundtrip() {
        let (game, _, _, _) = make_game(0x01, 0x10, &[0x10, 0x20, 0x30]);
        let bytes = borsh::to_vec(&game).unwrap();
        let recovered: GameStatus = borsh::from_slice(&bytes).unwrap();
        assert_eq!(game, recovered);
    }

    #[test]
    fn game_status_json_roundtrip() {
        let (game, _, _, _) = make_game(0x01, 0x10, &[0x10, 0x20, 0x30]);
        let json = serde_json::to_string(&game).unwrap();
        let recovered: GameStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(game, recovered);
    }

    // ===== 防误用：ObjectID / Ownership import 仍可用（验证模块间依赖） =====

    #[test]
    fn object_id_and_ownership_still_importable() {
        let id = ObjectID::new([1u8; 20], 0);
        let _ = Ownership::Shared;
        assert_eq!(id.creation_nonce, 0);
    }

    // ===== Phase 1 Task 1: GamePhase / BettingRound / SubmitPhaseKind 测试 =====

    #[test]
    fn betting_round_bcs_roundtrip() {
        for round in [
            BettingRound::Preflop,
            BettingRound::Flop,
            BettingRound::Turn,
            BettingRound::River,
            BettingRound::Showdown,
        ] {
            let bytes = borsh::to_vec(&round).unwrap();
            let recovered: BettingRound = borsh::from_slice(&bytes).unwrap();
            assert_eq!(round, recovered);
        }
    }

    #[test]
    fn submit_phase_kind_bcs_roundtrip() {
        for kind in [
            SubmitPhaseKind::Shuffle,
            SubmitPhaseKind::RevealToken,
            SubmitPhaseKind::Reconstruct,
            SubmitPhaseKind::LeaveProof,
        ] {
            let bytes = borsh::to_vec(&kind).unwrap();
            let recovered: SubmitPhaseKind = borsh::from_slice(&bytes).unwrap();
            assert_eq!(kind, recovered);
        }
    }

    #[test]
    fn game_phase_bcs_roundtrip_all_variants() {
        let phases = vec![
            GamePhase::Betting {
                round: BettingRound::Preflop,
            },
            GamePhase::Betting {
                round: BettingRound::Flop,
            },
            GamePhase::Betting {
                round: BettingRound::Turn,
            },
            GamePhase::Betting {
                round: BettingRound::River,
            },
            GamePhase::Betting {
                round: BettingRound::Showdown,
            },
            GamePhase::MultiPlayerSubmit {
                kind: SubmitPhaseKind::Shuffle,
            },
            GamePhase::MultiPlayerSubmit {
                kind: SubmitPhaseKind::RevealToken,
            },
            GamePhase::MultiPlayerSubmit {
                kind: SubmitPhaseKind::Reconstruct,
            },
            GamePhase::MultiPlayerSubmit {
                kind: SubmitPhaseKind::LeaveProof,
            },
        ];
        for phase in &phases {
            let bytes = borsh::to_vec(phase).unwrap();
            let recovered: GamePhase = borsh::from_slice(&bytes).unwrap();
            assert_eq!(*phase, recovered);
        }
    }

    #[test]
    fn game_phase_json_roundtrip_all_variants() {
        let phases = vec![
            GamePhase::Betting {
                round: BettingRound::Preflop,
            },
            GamePhase::MultiPlayerSubmit {
                kind: SubmitPhaseKind::Shuffle,
            },
            GamePhase::MultiPlayerSubmit {
                kind: SubmitPhaseKind::LeaveProof,
            },
        ];
        for phase in &phases {
            let json = serde_json::to_string(phase).unwrap();
            let recovered: GamePhase = serde_json::from_str(&json).unwrap();
            assert_eq!(*phase, recovered);
        }
    }

    #[test]
    fn game_phase_default_is_betting_preflop() {
        let phase = GamePhase::default_phase();
        assert_eq!(
            phase,
            GamePhase::Betting {
                round: BettingRound::Preflop
            }
        );
        assert!(phase.is_betting());
        assert!(!phase.is_multi_player_submit());
    }

    #[test]
    fn game_phase_is_helpers_correct() {
        let betting = GamePhase::Betting {
            round: BettingRound::Flop,
        };
        assert!(betting.is_betting());
        assert!(!betting.is_multi_player_submit());

        let multi = GamePhase::MultiPlayerSubmit {
            kind: SubmitPhaseKind::Shuffle,
        };
        assert!(!multi.is_betting());
        assert!(multi.is_multi_player_submit());
    }

    #[test]
    fn game_phase_copy_semantics() {
        // GamePhase 派生 Copy，赋值后修改不影响原值
        let phase1 = GamePhase::Betting {
            round: BettingRound::Preflop,
        };
        let phase2 = phase1;
        // 编译期保证 Copy：phase1 仍可用
        assert_eq!(phase1, phase2);
    }

    // ===== Phase 1 Task 2: GameStatus 新字段默认值与阶段切换测试 =====

    #[test]
    fn game_status_new_fields_have_correct_defaults() {
        let (game, _, _, _) = make_game(0x01, 0x10, &[0x10, 0x20, 0x30]);
        assert_eq!(
            game.phase,
            GamePhase::Betting {
                round: BettingRound::Preflop
            }
        );
        assert!(game.pending_submitters.is_empty());
        assert_eq!(game.phase_started_height, 0);
        assert!(game.completed_submitters.is_empty());
    }

    #[test]
    fn game_status_phase_switch_resets_tracking_fields() {
        let (mut game, _, _, _) = make_game(0x01, 0x10, &[0x10, 0x20, 0x30]);
        // 模拟多玩家阶段填充
        game.phase = GamePhase::MultiPlayerSubmit {
            kind: SubmitPhaseKind::Shuffle,
        };
        game.pending_submitters.insert([0x10; 20]);
        game.pending_submitters.insert([0x20; 20]);
        game.completed_submitters.insert([0x10; 20]);
        game.phase_started_height = 50;
        // 阶段切换：重置追踪集合
        game.phase = GamePhase::Betting {
            round: BettingRound::Flop,
        };
        game.pending_submitters.clear();
        game.completed_submitters.clear();
        game.phase_started_height = 0;
        assert!(game.pending_submitters.is_empty());
        assert!(game.completed_submitters.is_empty());
        assert_eq!(game.phase_started_height, 0);
        assert_eq!(
            game.phase,
            GamePhase::Betting {
                round: BettingRound::Flop
            }
        );
    }

    #[test]
    fn game_status_with_multi_player_phase_bcs_roundtrip() {
        let (mut game, _, _, _) = make_game(0x01, 0x10, &[0x10, 0x20, 0x30]);
        game.phase = GamePhase::MultiPlayerSubmit {
            kind: SubmitPhaseKind::Shuffle,
        };
        game.pending_submitters.insert([0x10; 20]);
        game.pending_submitters.insert([0x20; 20]);
        game.completed_submitters.insert([0x10; 20]);
        game.phase_started_height = 100;
        let bytes = borsh::to_vec(&game).unwrap();
        let recovered: GameStatus = borsh::from_slice(&bytes).unwrap();
        assert_eq!(game, recovered);
    }

    #[test]
    fn game_status_with_multi_player_phase_json_roundtrip() {
        let (mut game, _, _, _) = make_game(0x01, 0x10, &[0x10, 0x20, 0x30]);
        game.phase = GamePhase::MultiPlayerSubmit {
            kind: SubmitPhaseKind::RevealToken,
        };
        game.pending_submitters.insert([0x10; 20]);
        game.phase_started_height = 100;
        let json = serde_json::to_string(&game).unwrap();
        let recovered: GameStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(game, recovered);
    }

    // ===== Phase 2 Task 3: TurnRule trait 扩展 + SimpleTurnRule 新方法测试 =====

    #[test]
    fn simple_turn_rule_current_submitters_returns_empty_for_betting() {
        let (game, _, _, _) = make_game(0x01, 0x10, &[0x10, 0x20, 0x30]);
        let rule = SimpleTurnRule;
        assert!(rule.current_submitters(&game).is_empty());
    }

    #[test]
    fn simple_turn_rule_is_submission_complete_returns_true_for_betting() {
        let (game, _, _, _) = make_game(0x01, 0x10, &[0x10, 0x20, 0x30]);
        let rule = SimpleTurnRule;
        assert!(rule.is_submission_complete(&game));
    }

    #[test]
    fn simple_turn_rule_advance_phase_returns_invalid_for_betting() {
        let (game, _, _, _) = make_game(0x01, 0x10, &[0x10, 0x20, 0x30]);
        let expected_phase = game.phase;
        let mut g = game;
        let rule = SimpleTurnRule;
        let err = rule.advance_phase(&mut g).unwrap_err();
        assert_eq!(
            err,
            PhaseTransitionError::InvalidPhaseTransition(expected_phase)
        );
    }

    #[test]
    fn simple_turn_rule_current_turn_returns_none_in_multi_player_phase() {
        let (mut game, _, _, _) = make_game(0x01, 0x10, &[0x10, 0x20, 0x30]);
        game.phase = GamePhase::MultiPlayerSubmit {
            kind: SubmitPhaseKind::Shuffle,
        };
        let rule = SimpleTurnRule;
        // 多玩家阶段 current_turn 返回 None
        assert_eq!(rule.current_turn(&game), None);
    }

    #[test]
    fn simple_turn_rule_advance_turn_returns_none_in_multi_player_phase() {
        let (mut game, _, _, _) = make_game(0x01, 0x10, &[0x10, 0x20, 0x30]);
        game.phase = GamePhase::MultiPlayerSubmit {
            kind: SubmitPhaseKind::Shuffle,
        };
        let rule = SimpleTurnRule;
        // 多玩家阶段 advance_turn 返回 None（no-op）
        assert_eq!(rule.advance_turn(&mut game), None);
        // current_turn_player 不变
        assert_eq!(game.current_turn_player, [0x10; 20]);
    }

    #[test]
    fn phase_transition_error_pending_submitters_not_empty_display() {
        let err = PhaseTransitionError::PendingSubmittersNotEmpty(3);
        let msg = format!("{}", err);
        assert!(msg.contains("3"));
    }

    #[test]
    fn phase_transition_error_invalid_phase_transition_display() {
        let err = PhaseTransitionError::InvalidPhaseTransition(GamePhase::Betting {
            round: BettingRound::Preflop,
        });
        let msg = format!("{}", err);
        assert!(msg.contains("Betting"));
    }

    // ===== Phase 3 Task 5: validate_game_turn_phase_aware 测试 =====

    #[test]
    fn validate_game_turn_phase_aware_betting_ok() {
        // 下注阶段：current_turn_player 提交 → 通过
        let (mut game, _, _, _) = make_game(0x01, 0x10, &[0x10, 0x20]);
        let rule = SimpleTurnRule;
        let tx = make_tx(TxLane::GameTurn, RouteHint::AssignedValidator, false);
        // game.phase 默认为 Betting { Preflop }
        validate_game_turn_phase_aware(&tx, &mut game, [0x10; 20], &rule)
            .expect("下注阶段 current_turn_player 提交应通过");
    }

    #[test]
    fn validate_game_turn_phase_aware_betting_rejects_wrong_player() {
        // 下注阶段：非 current_turn_player 提交 → NotYourTurn
        let (mut game, _, _, _) = make_game(0x01, 0x10, &[0x10, 0x20]);
        let rule = SimpleTurnRule;
        let tx = make_tx(TxLane::GameTurn, RouteHint::AssignedValidator, false);
        let err = validate_game_turn_phase_aware(&tx, &mut game, [0x20; 20], &rule).unwrap_err();
        assert!(matches!(err, PokerL1Error::NotYourTurn { .. }));
    }

    #[test]
    fn validate_game_turn_phase_aware_multi_player_submit_ok() {
        // 多玩家阶段（Shuffle）：pending_submitter 提交 → 通过，pending 移除、completed 插入
        let (mut game, _, _, _) = make_game(0x01, 0x10, &[0x10, 0x20, 0x30]);
        game.phase = GamePhase::MultiPlayerSubmit {
            kind: SubmitPhaseKind::Shuffle,
        };
        game.pending_submitters.insert([0x10; 20]);
        game.pending_submitters.insert([0x20; 20]);
        let rule = SimpleTurnRule;
        let tx = make_tx(TxLane::GameTurn, RouteHint::AssignedValidator, false);
        validate_game_turn_phase_aware(&tx, &mut game, [0x10; 20], &rule)
            .expect("多玩家阶段 pending_submitter 提交应通过");
        // 校验追踪集合更新：0x10 从 pending 移除，插入 completed
        assert!(!game.pending_submitters.contains(&[0x10; 20]));
        assert!(game.completed_submitters.contains(&[0x10; 20]));
        // 另一提交者 0x20 仍在 pending
        assert!(game.pending_submitters.contains(&[0x20; 20]));
    }

    #[test]
    fn validate_game_turn_phase_aware_multi_player_submit_rejects_non_pending() {
        // 多玩家阶段（Shuffle）：非 pending_submitter 提交 → NotEligibleSubmitter
        let (mut game, _, _, _) = make_game(0x01, 0x10, &[0x10, 0x20, 0x30]);
        game.phase = GamePhase::MultiPlayerSubmit {
            kind: SubmitPhaseKind::Shuffle,
        };
        game.pending_submitters.insert([0x10; 20]);
        let rule = SimpleTurnRule;
        let tx = make_tx(TxLane::GameTurn, RouteHint::AssignedValidator, false);
        // 0x20 在 active_participants 但不在 pending_submitters
        let err = validate_game_turn_phase_aware(&tx, &mut game, [0x20; 20], &rule).unwrap_err();
        assert!(matches!(err, PokerL1Error::NotEligibleSubmitter { .. }));
    }

    #[test]
    fn validate_game_turn_phase_aware_leave_proof_ok() {
        // LeaveProof 阶段：active_participant 提交 → 通过，从 active/pending 移除
        let (mut game, _, _, _) = make_game(0x01, 0x10, &[0x10, 0x20, 0x30]);
        game.phase = GamePhase::MultiPlayerSubmit {
            kind: SubmitPhaseKind::LeaveProof,
        };
        game.pending_submitters.insert([0x10; 20]);
        let rule = SimpleTurnRule;
        let tx = make_tx(TxLane::GameTurn, RouteHint::AssignedValidator, false);
        validate_game_turn_phase_aware(&tx, &mut game, [0x20; 20], &rule)
            .expect("LeaveProof 阶段 active_participant 提交应通过");
        // 0x20 从 active_participants 移除
        assert!(!game.active_participants.contains(&[0x20; 20]));
        // 0x20 插入 completed_submitters
        assert!(game.completed_submitters.contains(&[0x20; 20]));
        // 0x10 仍在 active_participants
        assert!(game.active_participants.contains(&[0x10; 20]));
    }

    #[test]
    fn validate_game_turn_phase_aware_leave_proof_rejects_non_active() {
        // LeaveProof 阶段：非 active_participant 提交 → NotEligibleSubmitter
        let (mut game, _, _, _) = make_game(0x01, 0x10, &[0x10, 0x20]);
        game.phase = GamePhase::MultiPlayerSubmit {
            kind: SubmitPhaseKind::LeaveProof,
        };
        let rule = SimpleTurnRule;
        let tx = make_tx(TxLane::GameTurn, RouteHint::AssignedValidator, false);
        // 0x30 不在 active_participants
        let err = validate_game_turn_phase_aware(&tx, &mut game, [0x30; 20], &rule).unwrap_err();
        assert!(matches!(err, PokerL1Error::NotEligibleSubmitter { .. }));
    }

    #[test]
    fn validate_game_turn_phase_aware_skips_non_gameturn_lane() {
        // 非 GameTurn 通道 → 跳过校验
        let (mut game, _, _, _) = make_game(0x01, 0x10, &[0x10, 0x20]);
        let rule = SimpleTurnRule;
        let tx = make_tx(TxLane::Public, RouteHint::AnyValidator, false);
        validate_game_turn_phase_aware(&tx, &mut game, [0x99; 20], &rule)
            .expect("非 GameTurn 通道应跳过校验");
    }
}
