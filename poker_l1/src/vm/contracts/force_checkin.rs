//! force_checkin 故障恢复 + H4 forfeit 边界判定（Task 27 — SubTask 27.5 / 27.5e）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）：
//! - **SubTask 27.5 — force_checkin 可行性条件**：覆盖两种场景：
//!   (1) 操作方已广播 checkpoint state 但拒绝 checkin（恶意扣留）；
//!   (2) 操作方机器故障导致无法提交 checkin（机器故障）。
//!   两种场景下其他参与者均可基于已广播 checkpoint state 自行计算 (π', Δ')。
//!   纯扣留（无 checkpoint 广播）走 `request_revert`。
//!
//! - **H4 修复 — forfeit 边界判定**（NEW-C2 修复：字段统一为 `last_action_height`）：
//!   基于 `last_checkpoint_age = block.height - Game.last_action_height`
//!   （纯 timer 驱动，不要求故障证据）：
//!   - `last_checkpoint_age <= turn_timeout_blocks` → 恶意扣留 → forfeit
//!   - `last_checkpoint_age > turn_timeout_blocks` → 机器故障 → 不 forfeit（可重折叠）
//!   - 判定与 `request_revert` 的 reason 字段语义兼容
//!
//! - **NEW-M4 修复 — designated operator 场景**（R3-M1 + R3-M7 修正）：
//!   若操作方为 designated operator（非当前轮次玩家），forfeit 边界加倍为
//!   `last_checkpoint_age <= turn_timeout_blocks * 2`；force_advance 时**无条件豁免
//!   当前轮次玩家**（改为 check 而非 fold）。
//!   - **R3-M1 修正**：不需"证明短暂网络抖动"，与纯 timer 驱动一致；豁免对象是
//!     当前轮次玩家而非 designated operator
//!   - **R3-M7 修正**：Game 维护 `designated_operator_check_exemptions` 计数器，
//!     达上限（默认 2）后恢复 fold 语义，防恶意 designated operator 循环停发无限拖延
//!   - **反规避**：停发 checkpoint_anchor 超 turn_timeout_blocks 先触发 force_advance
//!     （fold 损失筹码）
//!
//! - **SubTask 27.5e — 操作方故障恢复流程（3 阶段时间窗口，不要求故障证据）**：
//!   - 阶段 1 `turn_timeout_blocks`（操作方可恢复，force_advance 可触发，无 forfeit）
//!   - 阶段 2 `da_window_blocks + recovery_window_blocks`（request_da + 参与者重折叠
//!     force_checkin，窗口内无 forfeit）
//!   - 阶段 3 forfeit + force_revert（窗口过期 + 无 force_checkin + 操作方未恢复 →
//!     forfeit 保证金 + 回退到最后 ACKed checkpoint）
//!   - **不要求故障证据**（任何证据可伪造，时间窗口不可伪造）

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::Hash;
use crate::error::PokerL1Error;
use crate::object_model::ObjectID;

use super::types::{GameContract, GamePhase};

// ===== 常量 =====

/// 阶段 2 恢复窗口默认值（SubTask 27.5e）。
///
/// 阶段 2 总窗口 = `da_window_blocks + recovery_window_blocks`。
pub const DEFAULT_RECOVERY_WINDOW_BLOCKS: u64 = 100;
/// designated operator check 豁免次数上限（NEW-M4 / R3-M7：默认 2）。
pub const DEFAULT_DESIGNATED_OPERATOR_CHECK_EXEMPTION_LIMIT: u32 = 2;

// ===== ForfeitReason / ForfeitDecision =====

/// forfeit 边界判定原因（H4 修复）。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum ForfeitReason {
    /// 恶意扣留：`last_checkpoint_age <= boundary`（H4：操作方有能力提交但拒绝）。
    MaliciousWithholding,
    /// 机器故障：`last_checkpoint_age > boundary`（H4：操作方无法提交）。
    MachineFailure,
}

/// forfeit 边界判定结果（H4 修复 + NEW-M4）。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct ForfeitDecision {
    /// 是否应触发 forfeit。
    pub should_forfeit: bool,
    /// 判定原因。
    pub reason: ForfeitReason,
    /// `block.height - game.last_action_height`（已过的 block 数）。
    pub last_checkpoint_age: u64,
    /// forfeit 边界（turn_timeout_blocks 或 * 2 for designated operator）。
    pub boundary: u64,
    /// 是否为 designated operator 场景（影响 boundary）。
    pub is_designated_operator: bool,
}

impl ForfeitDecision {
    /// 计算 forfeit 边界判定（H4 修复 + NEW-M4）。
    ///
    /// # 参数
    /// - `game`：当前 GameContract 状态
    /// - `current_block_height`：当前 block height
    /// - `turn_timeout_blocks`：turn 超时阈值（来自 TimeConsensusConfig）
    /// - `is_designated_operator`：操作方是否为 designated operator
    ///
    /// # 返回
    /// [`ForfeitDecision`]，caller 据此决定是否触发 forfeit 流程。
    ///
    /// # Panics
    /// 不会 panic；`current_block_height < game.last_action_height` 时 age = 0
    /// （视为刚活动过，无超时）。
    #[must_use]
    pub const fn compute(
        game: &GameContract,
        current_block_height: u64,
        turn_timeout_blocks: u64,
        is_designated_operator: bool,
    ) -> Self {
        // last_checkpoint_age = block.height - game.last_action_height
        // 防下溢：current < last_action_height 时 age = 0
        let last_checkpoint_age = current_block_height.saturating_sub(game.last_action_height);

        // NEW-M4: designated operator 边界加倍
        let boundary = if is_designated_operator {
            turn_timeout_blocks.saturating_mul(2)
        } else {
            turn_timeout_blocks
        };

        // H4: last_checkpoint_age <= boundary → MaliciousWithholding (forfeit)
        //     last_checkpoint_age > boundary  → MachineFailure (no forfeit)
        let (should_forfeit, reason) = if last_checkpoint_age <= boundary {
            (true, ForfeitReason::MaliciousWithholding)
        } else {
            (false, ForfeitReason::MachineFailure)
        };

        Self {
            should_forfeit,
            reason,
            last_checkpoint_age,
            boundary,
            is_designated_operator,
        }
    }
}

// ===== RecoveryStage（SubTask 27.5e — 3 阶段时间窗口） =====

/// 操作方故障恢复阶段（SubTask 27.5e）。
///
/// 3 阶段时间窗口（不要求故障证据，纯 timer 驱动）：
/// - [`RecoveryStage::Stage1`]：`turn_timeout_blocks` 内，操作方可恢复，
///   force_advance 可触发，无 forfeit
/// - [`RecoveryStage::Stage2`]：`turn_timeout_blocks` 之后 `da_window_blocks +
///   recovery_window_blocks` 内，request_da + 参与者重折叠 force_checkin，无 forfeit
/// - [`RecoveryStage::Stage3`]：阶段 2 窗口过期 + 无 force_checkin + 操作方未恢复 →
///   forfeit 保证金 + force_revert
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum RecoveryStage {
    /// 阶段 1：操作方可恢复（`elapsed <= turn_timeout_blocks`）。
    Stage1 {
        /// 自 last_action_height 起经过的 block 数。
        elapsed: u64,
        /// 阶段 1 总长度（= turn_timeout_blocks）。
        window_end: u64,
    },
    /// 阶段 2：request_da + 重折叠窗口（`turn_timeout_blocks < elapsed <=
    /// turn_timeout_blocks + da_window_blocks + recovery_window_blocks`）。
    Stage2 {
        /// 自 last_action_height 起经过的 block 数。
        elapsed: u64,
        /// 阶段 2 结束相对 last_action_height 的偏移。
        window_end: u64,
    },
    /// 阶段 3：forfeit + force_revert（阶段 2 窗口过期）。
    Stage3 {
        /// 自 last_action_height 起经过的 block 数。
        elapsed: u64,
        /// 阶段 3 起始相对 last_action_height 的偏移。
        window_start: u64,
    },
}

impl RecoveryStage {
    /// 计算当前所处的故障恢复阶段（SubTask 27.5e）。
    ///
    /// # 参数
    /// - `game`：当前 GameContract 状态
    /// - `current_block_height`：当前 block height
    /// - `turn_timeout_blocks`：阶段 1 长度（来自 TimeConsensusConfig）
    /// - `da_window_blocks`：DA 窗口（来自 TimeConsensusConfig）
    /// - `recovery_window_blocks`：恢复窗口（默认 100）
    ///
    /// # 返回
    /// [`RecoveryStage`]，caller 据此决定允许的操作（force_advance / request_da /
    /// force_checkin / forfeit + force_revert）。
    ///
    /// # 阶段边界（SEC2-L6：`<=` 边界判定）
    /// - `elapsed <= turn_timeout_blocks` → Stage1
    /// - `elapsed <= turn_timeout_blocks + da_window_blocks + recovery_window_blocks` → Stage2
    /// - 否则 → Stage3
    #[must_use]
    pub const fn compute(
        game: &GameContract,
        current_block_height: u64,
        turn_timeout_blocks: u64,
        da_window_blocks: u64,
        recovery_window_blocks: u64,
    ) -> Self {
        let elapsed = current_block_height.saturating_sub(game.last_action_height);

        // 阶段 1: elapsed <= turn_timeout_blocks (SEC2-L6: <= 边界)
        let stage1_end = turn_timeout_blocks;
        if elapsed <= stage1_end {
            return Self::Stage1 {
                elapsed,
                window_end: stage1_end,
            };
        }

        // 阶段 2: elapsed <= turn_timeout_blocks + da_window_blocks + recovery_window_blocks
        let stage2_end = turn_timeout_blocks
            .saturating_add(da_window_blocks)
            .saturating_add(recovery_window_blocks);
        if elapsed <= stage2_end {
            return Self::Stage2 {
                elapsed,
                window_end: stage2_end,
            };
        }

        // 阶段 3: 窗口过期
        Self::Stage3 {
            elapsed,
            window_start: stage2_end,
        }
    }

    /// 是否允许 force_advance（阶段 1 内允许）。
    #[must_use]
    pub const fn allows_force_advance(&self) -> bool {
        matches!(self, Self::Stage1 { .. })
    }

    /// 是否允许 force_checkin（阶段 2 内允许）。
    #[must_use]
    pub const fn allows_force_checkin(&self) -> bool {
        matches!(self, Self::Stage2 { .. })
    }

    /// 是否应触发 forfeit + force_revert（阶段 3）。
    #[must_use]
    pub const fn requires_forfeit_and_revert(&self) -> bool {
        matches!(self, Self::Stage3 { .. })
    }
}

// ===== Designated Operator Check 豁免（NEW-M4 / R3-M1 / R3-M7） =====

/// 判定 force_advance 时当前轮次玩家是否应豁免（改为 check 而非 fold）。
///
/// **NEW-M4 修复 + R3-M1 + R3-M7 修正**：
/// - 豁免对象是**当前轮次玩家**（若为 designated operator）而非 designated
///   operator 本身
/// - 不需"证明短暂网络抖动"，与纯 timer 驱动一致
/// - Game 维护 `designated_operator_check_exemptions` 计数器，达上限（默认 2）后
///   恢复 fold 语义
///
/// # 参数
/// - `game`：当前 GameContract 状态
/// - `is_current_turn_designated_operator`：当前轮次玩家是否为 designated operator
/// - `exemption_limit`：豁免次数上限（默认 2）
///
/// # 返回
/// - `true`：应豁免（check）
/// - `false`：不应豁免（fold）
#[must_use]
pub const fn should_exempt_current_turn_player(
    game: &GameContract,
    is_current_turn_designated_operator: bool,
    exemption_limit: u32,
) -> bool {
    is_current_turn_designated_operator
        && game.designated_operator_check_exemptions < exemption_limit
}

/// 应用 designated operator check 豁免（递增 `designated_operator_check_exemptions`）。
///
/// 仅在 force_advance 实际触发 check 豁免时调用（即
/// [`should_exempt_current_turn_player`] 返回 `true` 且 force_advance 决定为 check）。
///
/// # 参数
/// - `game`：可变的 GameContract 引用
///
/// # 返回
/// - `Ok(())`：豁免计数已递增
/// - `Err(Other)`：豁免计数溢出（saturating 后仍达上限）
pub const fn apply_designated_operator_check_exemption(
    game: &mut GameContract,
) -> Result<(), PokerL1Error> {
    game.designated_operator_check_exemptions =
        game.designated_operator_check_exemptions.saturating_add(1);
    game.version = game.version.saturating_add(1);
    Ok(())
}

/// 判定是否已耗尽 designated operator check 豁免次数（恢复 fold 语义）。
///
/// R3-M7：达上限后恢复 fold 语义，防恶意 designated operator 循环停发无限拖延。
#[must_use]
pub const fn is_designated_operator_exemption_exhausted(
    game: &GameContract,
    exemption_limit: u32,
) -> bool {
    game.designated_operator_check_exemptions >= exemption_limit
}

// ===== force_checkin 可行性条件（SubTask 27.5） =====

/// force_checkin 可行性条件（SubTask 27.5）。
///
/// 覆盖两种场景：
/// - (1) 操作方已广播 checkpoint state 但拒绝 checkin（恶意扣留）
/// - (2) 操作方机器故障导致无法提交 checkin（机器故障）
///
/// 两种场景下其他参与者均可基于已广播 checkpoint state 自行计算 (π', Δ')。
/// 纯扣留（无 checkpoint 广播）走 `request_revert`。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum ForceCheckinScenario {
    /// 场景 1：操作方已广播 checkpoint state 但拒绝 checkin（恶意扣留）。
    /// `last_checkpoint_state_hash` 存在 + forfeit 边界判定为 MaliciousWithholding。
    MaliciousWithholding,
    /// 场景 2：操作方机器故障导致无法提交 checkin。
    /// `last_checkpoint_state_hash` 存在 + forfeit 边界判定为 MachineFailure。
    MachineFailure,
    /// 不可行：纯扣留（无 checkpoint 广播）→ 走 `request_revert`。
    NotFeasibleRequiresRevert,
}

/// 判定 force_checkin 可行性与场景（SubTask 27.5）。
///
/// # 参数
/// - `game`：当前 GameContract 状态
/// - `current_block_height`：当前 block height
/// - `turn_timeout_blocks`：turn 超时阈值
/// - `is_designated_operator`：操作方是否为 designated operator
///
/// # 返回
/// [`ForceCheckinScenario`]，caller 据此决定走 force_checkin 还是 request_revert。
///
/// # 判定逻辑
/// - `game.last_checkpoint_state_hash` 为 None（无 checkpoint 广播）→
///   [`ForceCheckinScenario::NotFeasibleRequiresRevert`]（纯扣留走 request_revert）
/// - 有 checkpoint 广播 + H4 判定为 MaliciousWithholding →
///   [`ForceCheckinScenario::MaliciousWithholding`]
/// - 有 checkpoint 广播 + H4 判定为 MachineFailure →
///   [`ForceCheckinScenario::MachineFailure`]
#[must_use]
pub const fn determine_force_checkin_scenario(
    game: &GameContract,
    current_block_height: u64,
    turn_timeout_blocks: u64,
    is_designated_operator: bool,
) -> ForceCheckinScenario {
    // 纯扣留（无 checkpoint 广播）→ 走 request_revert
    if game.last_checkpoint_state_hash.is_none() {
        return ForceCheckinScenario::NotFeasibleRequiresRevert;
    }

    // 有 checkpoint 广播 → 根据 H4 forfeit 边界判定场景
    let decision = ForfeitDecision::compute(
        game,
        current_block_height,
        turn_timeout_blocks,
        is_designated_operator,
    );

    match decision.reason {
        ForfeitReason::MaliciousWithholding => ForceCheckinScenario::MaliciousWithholding,
        ForfeitReason::MachineFailure => ForceCheckinScenario::MachineFailure,
    }
}

/// 校验 force_checkin tx 的 game_id 一致性。
///
/// 通用辅助函数，确保 tx 携带的 game_id 与链上 Game 对象匹配。
pub fn validate_force_checkin_game_id(
    game: &GameContract,
    tx_game_id: &ObjectID,
) -> Result<(), PokerL1Error> {
    if &game.id != tx_game_id {
        return Err(PokerL1Error::GameNotFound(*tx_game_id));
    }
    Ok(())
}

// ===== apply_force_checkin（SubTask 28.3） =====

/// force_checkin 输入参数（SubTask 28.3）。
///
/// 由任意参与者构造（非操作方），基于已广播的 checkpoint state 自行计算 (π', Δ')。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ForceCheckinInput {
    /// 当前 block height（用于 forfeit 边界判定）。
    pub current_block_height: u64,
    /// 操作方是否为 designated operator（影响 boundary：turn_timeout_blocks * 2）。
    pub is_designated_operator: bool,
    /// turn_timeout_blocks（来自 TimeConsensusConfig）。
    pub turn_timeout_blocks: u64,
    /// 参与者自行计算的 new_commitment（结算后状态）。
    ///
    /// spec.md L665-669：checkin tx 携带 `(π, Δ, new_commitment, ack_chain)`。
    pub new_commitment: Hash,
    /// 参与者自行计算的状态增量 Δ'。
    pub state_delta: Vec<u8>,
}

impl ForceCheckinInput {
    /// 创建 force_checkin 输入。
    #[must_use]
    pub const fn new(
        current_block_height: u64,
        is_designated_operator: bool,
        turn_timeout_blocks: u64,
        new_commitment: Hash,
        state_delta: Vec<u8>,
    ) -> Self {
        Self {
            current_block_height,
            is_designated_operator,
            turn_timeout_blocks,
            new_commitment,
            state_delta,
        }
    }
}

/// force_checkin 应用结果（SubTask 28.3）。
///
/// 调用方据 `should_forfeit` 决定是否触发 forfeit 保证金扣除流程。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct ForceCheckinOutcome {
    /// 判定的场景（MaliciousWithholding / MachineFailure）。
    pub scenario: ForceCheckinScenario,
    /// 是否应触发 forfeit（H4 边界判定）。
    pub should_forfeit: bool,
    /// forfeit 原因（与 `request_revert` reason 字段语义兼容）。
    pub reason: ForfeitReason,
    /// `block.height - game.last_action_height`（已过的 block 数，BEFORE mutation）。
    pub last_checkpoint_age: u64,
    /// forfeit 边界（turn_timeout_blocks 或 * 2 for designated operator）。
    pub boundary: u64,
}

/// 应用 force_checkin 到 GameContract（SubTask 28.3）。
///
/// spec.md L697-699 + tasks.md SubTask 28.3：
/// 1. 判定场景（MaliciousWithholding / MachineFailure / NotFeasible）
/// 2. NotFeasible（无 checkpoint 广播）→ 拒绝，caller 须改走 `request_revert`
/// 3. 可行 → 应用 Δ' 结算手牌（标记 phase = Settled）
/// 4. 清除 `last_commitment`（checkin 完成 checkout cycle，SubTask 28.1）
/// 5. 清除 `last_checkpoint_state_hash`（已消费）
/// 6. 更新 `last_action_height = current_block_height`（force_checkin 是活动事件）
/// 7. 递增 `version`
///
/// **H4 修复 — forfeit 边界判定**：
/// - `last_checkpoint_age <= turn_timeout_blocks` → MaliciousWithholding →
///   返回 `should_forfeit = true`，caller 据此扣除 forfeit_deposit
/// - `last_checkpoint_age > turn_timeout_blocks` → MachineFailure →
///   返回 `should_forfeit = false`（参与者重折叠，无 forfeit）
///
/// **NEW-M4 修复**：designated operator 场景下 boundary 加倍为
/// `turn_timeout_blocks * 2`，由 `is_designated_operator` 控制。
///
/// # 参数
/// - `game`：可变的 GameContract 引用
/// - `input`：force_checkin 输入
///
/// # 返回
/// [`ForceCheckinOutcome`]，caller 据此决定是否触发 forfeit 流程。
///
/// # 错误
/// - [`PokerL1Error::Other`]：场景为 NotFeasibleRequiresRevert（无 checkpoint 广播，
///   caller 须改走 `request_revert`）
pub fn apply_force_checkin(
    game: &mut GameContract,
    input: &ForceCheckinInput,
) -> Result<ForceCheckinOutcome, PokerL1Error> {
    // 1. 判定场景（BEFORE mutation，基于当前 last_action_height）
    let scenario = determine_force_checkin_scenario(
        game,
        input.current_block_height,
        input.turn_timeout_blocks,
        input.is_designated_operator,
    );

    // 2. NotFeasible → 拒绝（caller 须改走 request_revert）
    if matches!(scenario, ForceCheckinScenario::NotFeasibleRequiresRevert) {
        return Err(PokerL1Error::Other(
            "force_checkin not feasible: no checkpoint broadcast, use request_revert".to_string(),
        ));
    }

    // 3. 计算 forfeit decision（BEFORE mutation，基于当前 last_action_height）
    let decision = ForfeitDecision::compute(
        game,
        input.current_block_height,
        input.turn_timeout_blocks,
        input.is_designated_operator,
    );

    // 4. 校验 last_checkpoint_state_hash 存在（与 NotFeasible 检查一致，防御性）
    if game.last_checkpoint_state_hash.is_none() {
        return Err(PokerL1Error::Other(
            "last_checkpoint_state_hash missing despite scenario != NotFeasible".to_string(),
        ));
    }

    // 5. 应用 Δ'：标记当前手牌结算
    if let Some(hand) = game.current_hand.as_mut() {
        hand.phase = GamePhase::Settled;
        hand.last_action_height = input.current_block_height;
    }

    // 6. 更新 game.last_action_height（force_checkin 是活动事件）
    game.last_action_height = input.current_block_height;

    // 7. 清除 last_commitment（checkin 完成 checkout cycle，SubTask 28.1）
    game.last_commitment = None;

    // 8. 清除 last_checkpoint_state_hash（已消费）
    game.last_checkpoint_state_hash = None;

    // 9. 递增 version
    game.version = game.version.saturating_add(1);

    Ok(ForceCheckinOutcome {
        scenario,
        should_forfeit: decision.should_forfeit,
        reason: decision.reason,
        last_checkpoint_age: decision.last_checkpoint_age,
        boundary: decision.boundary,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Address;
    use crate::signature::{CURRENT_VERSION, SignatureScheme, TaggedPubkey};
    use crate::vm::contracts::types::{ExecutionMode, RakeConfigRef};

    fn make_addr(byte: u8) -> Address {
        [byte; 20]
    }

    fn make_game_id() -> ObjectID {
        ObjectID::new(make_addr(0x01), 1)
    }

    fn make_tagged_pubkey(byte: u8) -> TaggedPubkey {
        let mut raw = vec![byte];
        raw.extend_from_slice(&[0x02u8; 32]);
        TaggedPubkey::new(SignatureScheme::Secp256k1, CURRENT_VERSION, raw)
            .expect("构造 tagged pubkey 不应失败")
    }

    fn make_game(last_action_height: u64) -> GameContract {
        let mut game = GameContract::new(
            make_game_id(),
            make_addr(0x01),
            make_tagged_pubkey(0xFF),
            ExecutionMode::OffChain,
            RakeConfigRef {
                rake_rate_bps: 0,
                rake_cap: 0,
                rake_recipient: make_addr(0x00),
            },
            10,
        );
        game.last_action_height = last_action_height;
        game
    }

    fn make_game_with_checkpoint(last_action_height: u64, state_byte: u8) -> GameContract {
        let mut game = make_game(last_action_height);
        game.last_checkpoint_state_hash = Some([state_byte; 32]);
        game
    }

    // ===== ForfeitDecision 测试 =====

    #[test]
    fn test_forfeit_decision_malicious_withholding() {
        // last_action_height = 100, current = 120, turn_timeout = 30
        // age = 20 <= 30 → MaliciousWithholding (forfeit)
        let game = make_game(100);
        let decision = ForfeitDecision::compute(&game, 120, 30, false);
        assert!(decision.should_forfeit, "age 20 <= 30 应 forfeit");
        assert_eq!(decision.reason, ForfeitReason::MaliciousWithholding);
        assert_eq!(decision.last_checkpoint_age, 20);
        assert_eq!(decision.boundary, 30);
        assert!(!decision.is_designated_operator);
    }

    #[test]
    fn test_forfeit_decision_machine_failure() {
        // last_action_height = 100, current = 200, turn_timeout = 30
        // age = 100 > 30 → MachineFailure (no forfeit)
        let game = make_game(100);
        let decision = ForfeitDecision::compute(&game, 200, 30, false);
        assert!(!decision.should_forfeit, "age 100 > 30 应不 forfeit");
        assert_eq!(decision.reason, ForfeitReason::MachineFailure);
        assert_eq!(decision.last_checkpoint_age, 100);
        assert_eq!(decision.boundary, 30);
    }

    #[test]
    fn test_forfeit_decision_boundary_inclusive() {
        // SEC2-L6: <= 边界判定
        // last_action_height = 100, current = 130, turn_timeout = 30
        // age = 30 == 30 → MaliciousWithholding (<= 边界)
        let game = make_game(100);
        let decision = ForfeitDecision::compute(&game, 130, 30, false);
        assert!(
            decision.should_forfeit,
            "age 30 == boundary 30 应 forfeit (<= 边界)"
        );
        assert_eq!(decision.reason, ForfeitReason::MaliciousWithholding);
    }

    #[test]
    fn test_forfeit_decision_just_after_boundary() {
        // age = 31 > 30 → MachineFailure
        let game = make_game(100);
        let decision = ForfeitDecision::compute(&game, 131, 30, false);
        assert!(!decision.should_forfeit, "age 31 > 30 应不 forfeit");
        assert_eq!(decision.reason, ForfeitReason::MachineFailure);
    }

    #[test]
    fn test_forfeit_decision_designated_operator_boundary_doubled() {
        // NEW-M4: designated operator → boundary = 30 * 2 = 60
        // last_action_height = 100, current = 150, age = 50 <= 60 → MaliciousWithholding
        let game = make_game(100);
        let decision = ForfeitDecision::compute(&game, 150, 30, true);
        assert!(
            decision.should_forfeit,
            "designated operator: age 50 <= 60 应 forfeit"
        );
        assert_eq!(decision.reason, ForfeitReason::MaliciousWithholding);
        assert_eq!(
            decision.boundary, 60,
            "NEW-M4: boundary = turn_timeout * 2 = 60"
        );
        assert!(decision.is_designated_operator);
    }

    #[test]
    fn test_forfeit_decision_designated_operator_machine_failure() {
        // NEW-M4: designated operator → boundary = 60
        // age = 70 > 60 → MachineFailure
        let game = make_game(100);
        let decision = ForfeitDecision::compute(&game, 170, 30, true);
        assert!(
            !decision.should_forfeit,
            "designated operator: age 70 > 60 应不 forfeit"
        );
        assert_eq!(decision.reason, ForfeitReason::MachineFailure);
        assert_eq!(decision.boundary, 60);
    }

    #[test]
    fn test_forfeit_decision_current_before_last_action() {
        // 防下溢：current < last_action_height → age = 0
        let game = make_game(200);
        let decision = ForfeitDecision::compute(&game, 150, 30, false);
        assert_eq!(decision.last_checkpoint_age, 0, "防下溢 age = 0");
        assert!(decision.should_forfeit, "age 0 <= 30 应 forfeit (刚活动过)");
        assert_eq!(decision.reason, ForfeitReason::MaliciousWithholding);
    }

    // ===== RecoveryStage 测试 =====

    #[test]
    fn test_recovery_stage_stage1() {
        // last_action_height = 100, current = 120, turn_timeout = 30
        // elapsed = 20 <= 30 → Stage1
        let game = make_game(100);
        let stage = RecoveryStage::compute(&game, 120, 30, 500, 100);
        assert!(matches!(
            stage,
            RecoveryStage::Stage1 {
                elapsed: 20,
                window_end: 30
            }
        ));
        assert!(stage.allows_force_advance());
        assert!(!stage.allows_force_checkin());
        assert!(!stage.requires_forfeit_and_revert());
    }

    #[test]
    fn test_recovery_stage_stage1_boundary_inclusive() {
        // SEC2-L6: <= 边界判定
        // elapsed = 30 == turn_timeout → Stage1
        let game = make_game(100);
        let stage = RecoveryStage::compute(&game, 130, 30, 500, 100);
        assert!(matches!(
            stage,
            RecoveryStage::Stage1 {
                elapsed: 30,
                window_end: 30
            }
        ));
        assert!(stage.allows_force_advance());
    }

    #[test]
    fn test_recovery_stage_stage2() {
        // last_action_height = 100, current = 200, turn_timeout = 30,
        // da_window = 500, recovery_window = 100
        // elapsed = 100, stage2_end = 30 + 500 + 100 = 630, 100 <= 630 → Stage2
        let game = make_game(100);
        let stage = RecoveryStage::compute(&game, 200, 30, 500, 100);
        assert!(matches!(
            stage,
            RecoveryStage::Stage2 {
                elapsed: 100,
                window_end: 630
            }
        ));
        assert!(!stage.allows_force_advance());
        assert!(stage.allows_force_checkin());
        assert!(!stage.requires_forfeit_and_revert());
    }

    #[test]
    fn test_recovery_stage_stage2_boundary_inclusive() {
        // SEC2-L6: <= 边界判定
        // elapsed = 630 == stage2_end → Stage2
        let game = make_game(100);
        let stage = RecoveryStage::compute(&game, 730, 30, 500, 100);
        assert!(matches!(
            stage,
            RecoveryStage::Stage2 {
                elapsed: 630,
                window_end: 630
            }
        ));
        assert!(stage.allows_force_checkin());
    }

    #[test]
    fn test_recovery_stage_stage3() {
        // elapsed = 631 > 630 → Stage3
        let game = make_game(100);
        let stage = RecoveryStage::compute(&game, 731, 30, 500, 100);
        assert!(matches!(
            stage,
            RecoveryStage::Stage3 {
                elapsed: 631,
                window_start: 630
            }
        ));
        assert!(!stage.allows_force_advance());
        assert!(!stage.allows_force_checkin());
        assert!(stage.requires_forfeit_and_revert());
    }

    #[test]
    fn test_recovery_stage_just_after_stage1() {
        // elapsed = 31 > 30 → Stage2 (just entered)
        let game = make_game(100);
        let stage = RecoveryStage::compute(&game, 131, 30, 500, 100);
        assert!(matches!(
            stage,
            RecoveryStage::Stage2 {
                elapsed: 31,
                window_end: 630
            }
        ));
    }

    // ===== Designated Operator Check 豁免测试 =====

    #[test]
    fn test_should_exempt_current_turn_player_yes() {
        // is_designated_operator = true, exemptions = 0 < 2 → 豁免
        let game = make_game(100);
        assert!(should_exempt_current_turn_player(&game, true, 2));
    }

    #[test]
    fn test_should_exempt_current_turn_player_no_not_designated() {
        // is_designated_operator = false → 不豁免
        let game = make_game(100);
        assert!(!should_exempt_current_turn_player(&game, false, 2));
    }

    #[test]
    fn test_should_exempt_current_turn_player_no_exhausted() {
        // exemptions = 2 >= 2 → 不豁免（R3-M7：达上限恢复 fold 语义）
        let mut game = make_game(100);
        game.designated_operator_check_exemptions = 2;
        assert!(!should_exempt_current_turn_player(&game, true, 2));
    }

    #[test]
    fn test_should_exempt_current_turn_player_one_left() {
        // exemptions = 1 < 2 → 豁免
        let mut game = make_game(100);
        game.designated_operator_check_exemptions = 1;
        assert!(should_exempt_current_turn_player(&game, true, 2));
    }

    #[test]
    fn test_apply_designated_operator_check_exemption_increments() {
        let mut game = make_game(100);
        assert_eq!(game.designated_operator_check_exemptions, 0);
        apply_designated_operator_check_exemption(&mut game).expect("应成功");
        assert_eq!(game.designated_operator_check_exemptions, 1);
        apply_designated_operator_check_exemption(&mut game).expect("应成功");
        assert_eq!(game.designated_operator_check_exemptions, 2);
        // saturating_add：超过上限不溢出
        apply_designated_operator_check_exemption(&mut game).expect("应成功");
        assert_eq!(game.designated_operator_check_exemptions, 3);
    }

    #[test]
    fn test_is_designated_operator_exemption_exhausted() {
        let mut game = make_game(100);
        assert!(!is_designated_operator_exemption_exhausted(&game, 2));
        game.designated_operator_check_exemptions = 2;
        assert!(is_designated_operator_exemption_exhausted(&game, 2));
        game.designated_operator_check_exemptions = 3;
        assert!(is_designated_operator_exemption_exhausted(&game, 2));
    }

    // ===== determine_force_checkin_scenario 测试 =====

    #[test]
    fn test_determine_scenario_not_feasible_no_checkpoint() {
        // 无 checkpoint 广播 → NotFeasibleRequiresRevert
        let game = make_game(100); // last_checkpoint_state_hash = None
        let scenario = determine_force_checkin_scenario(&game, 120, 30, false);
        assert_eq!(scenario, ForceCheckinScenario::NotFeasibleRequiresRevert);
    }

    #[test]
    fn test_determine_scenario_malicious_withholding() {
        // 有 checkpoint + age 20 <= 30 → MaliciousWithholding
        let game = make_game_with_checkpoint(100, 0xAB);
        let scenario = determine_force_checkin_scenario(&game, 120, 30, false);
        assert_eq!(scenario, ForceCheckinScenario::MaliciousWithholding);
    }

    #[test]
    fn test_determine_scenario_machine_failure() {
        // 有 checkpoint + age 100 > 30 → MachineFailure
        let game = make_game_with_checkpoint(100, 0xAB);
        let scenario = determine_force_checkin_scenario(&game, 200, 30, false);
        assert_eq!(scenario, ForceCheckinScenario::MachineFailure);
    }

    #[test]
    fn test_determine_scenario_designated_operator_boundary_doubled() {
        // NEW-M4: designated operator → boundary = 60
        // age = 50 <= 60 → MaliciousWithholding
        let game = make_game_with_checkpoint(100, 0xAB);
        let scenario = determine_force_checkin_scenario(&game, 150, 30, true);
        assert_eq!(scenario, ForceCheckinScenario::MaliciousWithholding);
    }

    #[test]
    fn test_determine_scenario_designated_operator_machine_failure() {
        // NEW-M4: designated operator → boundary = 60
        // age = 70 > 60 → MachineFailure
        let game = make_game_with_checkpoint(100, 0xAB);
        let scenario = determine_force_checkin_scenario(&game, 170, 30, true);
        assert_eq!(scenario, ForceCheckinScenario::MachineFailure);
    }

    // ===== validate_force_checkin_game_id 测试 =====

    #[test]
    fn test_validate_game_id_match() {
        let game = make_game(100);
        assert!(validate_force_checkin_game_id(&game, &make_game_id()).is_ok());
    }

    #[test]
    fn test_validate_game_id_mismatch() {
        let game = make_game(100);
        let wrong_id = ObjectID::new([0xFF; 20], 999);
        let result = validate_force_checkin_game_id(&game, &wrong_id);
        assert!(
            matches!(result, Err(PokerL1Error::GameNotFound(_))),
            "game_id 不匹配应返回 GameNotFound"
        );
    }

    // ===== 常量测试 =====

    #[test]
    fn test_constants() {
        assert_eq!(
            DEFAULT_RECOVERY_WINDOW_BLOCKS, 100,
            "SubTask 27.5e: 阶段 2 恢复窗口默认 100"
        );
        assert_eq!(
            DEFAULT_DESIGNATED_OPERATOR_CHECK_EXEMPTION_LIMIT, 2,
            "NEW-M4 / R3-M7: designated operator check 豁免上限默认 2"
        );
    }

    // ===== apply_force_checkin 测试（SubTask 28.3）=====

    fn make_force_checkin_input(
        current_block_height: u64,
        is_designated_operator: bool,
        turn_timeout_blocks: u64,
    ) -> ForceCheckinInput {
        ForceCheckinInput::new(
            current_block_height,
            is_designated_operator,
            turn_timeout_blocks,
            [0xAB; 32],
            vec![0xCD; 16],
        )
    }

    #[test]
    fn test_apply_force_checkin_malicious_withholding_forfeits() {
        // last_action_height = 100, current = 120, turn_timeout = 30
        // age = 20 <= 30 → MaliciousWithholding → should_forfeit = true
        let mut game = make_game_with_checkpoint(100, 0xAB);
        game.last_commitment = Some([0x11; 32]);
        let input = make_force_checkin_input(120, false, 30);

        let outcome = apply_force_checkin(&mut game, &input).expect("应成功");
        assert_eq!(outcome.scenario, ForceCheckinScenario::MaliciousWithholding);
        assert!(outcome.should_forfeit, "age 20 <= 30 应 forfeit");
        assert_eq!(outcome.reason, ForfeitReason::MaliciousWithholding);
        assert_eq!(outcome.last_checkpoint_age, 20);
        assert_eq!(outcome.boundary, 30);
        // 状态变更
        assert_eq!(game.last_action_height, 120);
        assert!(
            game.last_commitment.is_none(),
            "checkin 完成 → last_commitment 清除"
        );
        assert!(game.last_checkpoint_state_hash.is_none(), "已消费");
        assert!(game.version > 0);
    }

    #[test]
    fn test_apply_force_checkin_machine_failure_no_forfeit() {
        // last_action_height = 100, current = 200, turn_timeout = 30
        // age = 100 > 30 → MachineFailure → should_forfeit = false
        let mut game = make_game_with_checkpoint(100, 0xAB);
        game.last_commitment = Some([0x11; 32]);
        let input = make_force_checkin_input(200, false, 30);

        let outcome = apply_force_checkin(&mut game, &input).expect("应成功");
        assert_eq!(outcome.scenario, ForceCheckinScenario::MachineFailure);
        assert!(!outcome.should_forfeit, "age 100 > 30 应不 forfeit");
        assert_eq!(outcome.reason, ForfeitReason::MachineFailure);
    }

    #[test]
    fn test_apply_force_checkin_designated_operator_boundary_doubled() {
        // NEW-M4: designated operator → boundary = 30 * 2 = 60
        // last_action_height = 100, current = 150, age = 50 <= 60 → MaliciousWithholding
        let mut game = make_game_with_checkpoint(100, 0xAB);
        game.last_commitment = Some([0x11; 32]);
        let input = make_force_checkin_input(150, true, 30);

        let outcome = apply_force_checkin(&mut game, &input).expect("应成功");
        assert!(
            outcome.should_forfeit,
            "designated operator: age 50 <= 60 应 forfeit"
        );
        assert_eq!(outcome.boundary, 60);
    }

    #[test]
    fn test_apply_force_checkin_designated_operator_machine_failure() {
        // NEW-M4: designated operator → boundary = 60
        // age = 70 > 60 → MachineFailure
        let mut game = make_game_with_checkpoint(100, 0xAB);
        let input = make_force_checkin_input(170, true, 30);

        let outcome = apply_force_checkin(&mut game, &input).expect("应成功");
        assert!(
            !outcome.should_forfeit,
            "designated operator: age 70 > 60 应不 forfeit"
        );
        assert_eq!(outcome.boundary, 60);
    }

    #[test]
    fn test_apply_force_checkin_not_feasible_no_checkpoint() {
        // 无 checkpoint 广播 → NotFeasibleRequiresRevert → 拒绝
        let mut game = make_game(100); // last_checkpoint_state_hash = None
        let input = make_force_checkin_input(120, false, 30);

        let result = apply_force_checkin(&mut game, &input);
        assert!(result.is_err(), "无 checkpoint 广播应拒绝");
        // 状态不变（mutation 未发生）
        assert_eq!(game.last_action_height, 100);
    }

    #[test]
    fn test_apply_force_checkin_clears_last_commitment() {
        // SubTask 28.1：checkin 完成 checkout cycle → last_commitment 清除
        let mut game = make_game_with_checkpoint(100, 0xAB);
        game.last_commitment = Some([0x22; 32]);
        let input = make_force_checkin_input(120, false, 30);

        apply_force_checkin(&mut game, &input).expect("应成功");
        assert!(
            game.last_commitment.is_none(),
            "force_checkin 后 last_commitment 必须清除"
        );
    }

    #[test]
    fn test_apply_force_checkin_updates_last_action_height() {
        let mut game = make_game_with_checkpoint(100, 0xAB);
        let input = make_force_checkin_input(150, false, 30);

        apply_force_checkin(&mut game, &input).expect("应成功");
        assert_eq!(
            game.last_action_height, 150,
            "force_checkin 是活动事件，须更新 last_action_height"
        );
    }

    #[test]
    fn test_apply_force_checkin_clears_last_checkpoint_state_hash() {
        let mut game = make_game_with_checkpoint(100, 0xAB);
        let input = make_force_checkin_input(120, false, 30);

        apply_force_checkin(&mut game, &input).expect("应成功");
        assert!(
            game.last_checkpoint_state_hash.is_none(),
            "force_checkin 后 last_checkpoint_state_hash 必须清除（已消费）"
        );
    }

    #[test]
    fn test_apply_force_checkin_increments_version() {
        let mut game = make_game_with_checkpoint(100, 0xAB);
        let prev_version = game.version;
        let input = make_force_checkin_input(120, false, 30);

        apply_force_checkin(&mut game, &input).expect("应成功");
        assert_eq!(
            game.version,
            prev_version.saturating_add(1),
            "version 须递增 1"
        );
    }

    #[test]
    fn test_apply_force_checkin_boundary_inclusive() {
        // SEC2-L6: <= 边界判定
        // last_action_height = 100, current = 130, age = 30 == 30 → MaliciousWithholding
        let mut game = make_game_with_checkpoint(100, 0xAB);
        let input = make_force_checkin_input(130, false, 30);

        let outcome = apply_force_checkin(&mut game, &input).expect("应成功");
        assert!(
            outcome.should_forfeit,
            "age 30 == boundary 30 应 forfeit (<= 边界)"
        );
        assert_eq!(outcome.reason, ForfeitReason::MaliciousWithholding);
    }

    #[test]
    fn test_apply_force_checkin_just_after_boundary() {
        // age = 31 > 30 → MachineFailure
        let mut game = make_game_with_checkpoint(100, 0xAB);
        let input = make_force_checkin_input(131, false, 30);

        let outcome = apply_force_checkin(&mut game, &input).expect("应成功");
        assert!(!outcome.should_forfeit, "age 31 > 30 应不 forfeit");
        assert_eq!(outcome.reason, ForfeitReason::MachineFailure);
    }

    #[test]
    fn test_apply_force_checkin_zero_state_delta_allowed() {
        // state_delta 可为空（Δ' = 空表示无状态变更，仅结算）
        let mut game = make_game_with_checkpoint(100, 0xAB);
        let input = ForceCheckinInput::new(120, false, 30, [0xAB; 32], Vec::new());

        let outcome = apply_force_checkin(&mut game, &input).expect("应成功");
        assert!(outcome.should_forfeit);
    }
}
