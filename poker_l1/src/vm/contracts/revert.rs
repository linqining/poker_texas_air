//! request_revert / force_revert tx（SubTask 28.4）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）+ tasks.md SubTask 28.4：
//! - tx 内容：`(game_id, last_acked_checkpoint, reason)`
//! - `reason` 枚举：`technical_interrupt` / `malicious_withholding` / `data_unavailable`
//! - **`reason=technical_interrupt`** → 回退到最后 ACKed checkpoint_state，操作方不 forfeit
//!   （技术中断豁免；阶段 1-2 内允许；**R7-M6：阶段 3 内被拒**）
//! - **`reason=malicious_withholding` 或 `data_unavailable`** → 回退 + 按 forfeit 规则处置
//! - **与故障恢复流程兼容**：
//!   - 阶段 1-2 内 technical_interrupt 无 forfeit
//!   - 阶段 3 内 technical_interrupt 仍无 forfeit（reason 优先于阶段判定），但被 R7-M6 拒绝
//!   - 恶意滥用由参与者在阶段 3 提交 `force_revert(reason=malicious_withholding)` 触发 forfeit
//!
//! # request_revert vs force_revert 的区别
//!
//! 两者结构相同，区别在于典型提交者和语义：
//! - `request_revert`：典型由**操作方本人**提交，声明 `reason=technical_interrupt`
//!   （技术中断豁免，无 forfeit）
//! - `force_revert`：典型由**任意参与者**提交，声明 `reason=malicious_withholding`
//!   或 `data_unavailable`（触发 forfeit）
//!
//! 协议层不强制提交者身份，但应用层可附加签名校验。

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::error::PokerL1Error;
use crate::object_model::ObjectID;
use crate::{Address, Hash};

use super::force_checkin::{ForfeitDecision, ForfeitReason, RecoveryStage};
use super::types::GameContract;

/// request_revert / force_revert 的 reason 枚举（SubTask 28.4）。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum RevertReason {
    /// 技术中断（操作方特权，无 forfeit；阶段 3 内被 R7-M6 拒绝）。
    TechnicalInterrupt,
    /// 恶意扣留（触发 forfeit）。
    MaliciousWithholding,
    /// 数据不可用（触发 forfeit）。
    DataUnavailable,
}

impl RevertReason {
    /// 是否触发 forfeit（technical_interrupt 不触发，其余两个触发）。
    #[must_use]
    pub const fn triggers_forfeit(&self) -> bool {
        matches!(self, Self::MaliciousWithholding | Self::DataUnavailable)
    }

    /// 是否为技术中断（操作方特权）。
    #[must_use]
    pub const fn is_technical_interrupt(&self) -> bool {
        matches!(self, Self::TechnicalInterrupt)
    }
}

/// request_revert tx（SubTask 28.4，典型由操作方提交）。
///
/// 内容：`(game_id, last_acked_checkpoint, reason, submitter)`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct RequestRevertTx {
    /// Game 对象 ID。
    pub game_id: ObjectID,
    /// 最后 ACKed checkpoint state hash（回退锚点）。
    pub last_acked_checkpoint: Hash,
    /// 回退原因。
    pub reason: RevertReason,
    /// 提交者地址。
    pub submitter: Address,
}

/// force_revert tx（SubTask 28.4，任意参与者提交）。
///
/// 内容：`(game_id, last_acked_checkpoint, reason, submitter)` +
/// 阶段判定所需的 block height 参数。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ForceRevertTx {
    /// Game 对象 ID。
    pub game_id: ObjectID,
    /// 最后 ACKed checkpoint state hash（回退锚点）。
    pub last_acked_checkpoint: Hash,
    /// 回退原因。
    pub reason: RevertReason,
    /// 提交者地址（任意参与者）。
    pub submitter: Address,
    /// 当前 block height（用于阶段判定 + forfeit 边界）。
    pub current_block_height: u64,
    /// turn_timeout_blocks（来自 TimeConsensusConfig）。
    pub turn_timeout_blocks: u64,
    /// da_window_blocks（来自 TimeConsensusConfig）。
    pub da_window_blocks: u64,
    /// recovery_window_blocks（默认 100，SubTask 27.5e）。
    pub recovery_window_blocks: u64,
    /// 是否为 designated operator（影响 boundary：turn_timeout_blocks * 2）。
    pub is_designated_operator: bool,
}

/// request_revert / force_revert 应用结果（SubTask 28.4）。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct RevertOutcome {
    /// 是否触发了 forfeit。
    pub should_forfeit: bool,
    /// forfeit 原因（仅当 `should_forfeit=true` 时有意义）。
    pub reason: Option<ForfeitReason>,
    /// `block.height - game.last_action_height`（BEFORE mutation）。
    pub last_checkpoint_age: u64,
    /// forfeit 边界（`turn_timeout_blocks` 或 `* 2` for designated operator）。
    pub boundary: u64,
    /// 回退前 `game.last_action_height`（用于审计/回滚）。
    pub previous_last_action_height: u64,
}

/// 内部共享的回退应用逻辑（SubTask 28.4）。
///
/// 已通过外部校验（game_id / submitter / R7-M6）后调用。
const fn apply_revert_internal(
    game: &mut GameContract,
    reason: RevertReason,
    decision: ForfeitDecision,
    current_block_height: u64,
) -> RevertOutcome {
    let prev_last_action_height = game.last_action_height;

    // 判定是否触发 forfeit（reason 优先于阶段判定）
    let (should_forfeit, forfeit_reason) = if reason.triggers_forfeit() {
        // malicious_withholding / data_unavailable → 触发 forfeit
        // H4 边界判定：age <= boundary → MaliciousWithholding；age > boundary → MachineFailure
        // 但 reason=malicious_withholding 优先：即使 age > boundary，仍标记为 MaliciousWithholding
        let fr = if decision.should_forfeit {
            decision.reason
        } else {
            // age > boundary 但 reason 显式声明恶意 → 标记为 MaliciousWithholding
            ForfeitReason::MaliciousWithholding
        };
        (true, Some(fr))
    } else {
        // technical_interrupt → 无 forfeit
        (false, None)
    };

    // 应用回退：清除 checkout/checkpoint 锚点
    game.last_commitment = None;
    game.last_checkpoint_state_hash = None;
    game.last_action_height = current_block_height;
    game.version = game.version.saturating_add(1);

    RevertOutcome {
        should_forfeit,
        reason: forfeit_reason,
        last_checkpoint_age: decision.last_checkpoint_age,
        boundary: decision.boundary,
        previous_last_action_height: prev_last_action_height,
    }
}

/// 应用 request_revert（SubTask 28.4，典型由操作方提交）。
///
/// # 校验
/// 1. `tx.game_id == game.id`
/// 2. `tx.submitter == game.owner`（典型场景；应用层可放宽）
/// 3. R7-M6：阶段 3 内 `reason=technical_interrupt` 被拒
///
/// # 状态变更
/// 1. 清除 `last_commitment`（回退到 last_acked_checkpoint）
/// 2. 清除 `last_checkpoint_state_hash`
/// 3. 更新 `last_action_height = current_block_height`
/// 4. 递增 `version`
///
/// # 参数
/// - `game`：可变的 GameContract 引用
/// - `tx`：request_revert tx
/// - `current_block_height`：当前 block height
/// - `turn_timeout_blocks`：turn 超时阈值
/// - `da_window_blocks`：DA 窗口
/// - `recovery_window_blocks`：恢复窗口（默认 100）
///
/// # 错误
/// - [`PokerL1Error::GameNotFound`]：game_id 不匹配
/// - [`PokerL1Error::NotOwner`]：submitter 非 game.owner
/// - [`PokerL1Error::OperatorCannotClaimTechnicalInterrupt`]：阶段 3 + technical_interrupt
#[allow(clippy::too_many_arguments)] // 6 参数均为 spec 要求的安全校验参数
pub fn apply_request_revert(
    game: &mut GameContract,
    tx: &RequestRevertTx,
    current_block_height: u64,
    turn_timeout_blocks: u64,
    da_window_blocks: u64,
    recovery_window_blocks: u64,
) -> Result<RevertOutcome, PokerL1Error> {
    // 校验 game_id 一致
    if tx.game_id != game.id {
        return Err(PokerL1Error::GameNotFound(tx.game_id));
    }

    // 校验 submitter 是操作方 owner（典型场景）
    if tx.submitter != game.owner {
        return Err(PokerL1Error::NotOwner(game.id));
    }

    // R7-M6: 阶段 3 内 technical_interrupt 被拒
    if tx.reason.is_technical_interrupt() {
        let stage = RecoveryStage::compute(
            game,
            current_block_height,
            turn_timeout_blocks,
            da_window_blocks,
            recovery_window_blocks,
        );
        if stage.requires_forfeit_and_revert() {
            return Err(PokerL1Error::OperatorCannotClaimTechnicalInterrupt(game.id));
        }
    }

    // 计算 forfeit decision（BEFORE mutation）
    let decision = ForfeitDecision::compute(
        game,
        current_block_height,
        turn_timeout_blocks,
        false, // request_revert 不区分 designated operator（操作方特权）
    );

    Ok(apply_revert_internal(
        game,
        tx.reason,
        decision,
        current_block_height,
    ))
}

/// 应用 force_revert（SubTask 28.4，任意参与者提交）。
///
/// # 校验
/// 1. `tx.game_id == game.id`
/// 2. R7-M6：阶段 3 内 `reason=technical_interrupt` 被拒
///
/// # 状态变更
/// 同 [`apply_request_revert`]。
///
/// # 参数
/// - `game`：可变的 GameContract 引用
/// - `tx`：force_revert tx（含 block height 参数）
///
/// # 错误
/// - [`PokerL1Error::GameNotFound`]：game_id 不匹配
/// - [`PokerL1Error::OperatorCannotClaimTechnicalInterrupt`]：阶段 3 + technical_interrupt
pub fn apply_force_revert(
    game: &mut GameContract,
    tx: &ForceRevertTx,
) -> Result<RevertOutcome, PokerL1Error> {
    // 校验 game_id 一致
    if tx.game_id != game.id {
        return Err(PokerL1Error::GameNotFound(tx.game_id));
    }

    // R7-M6: 阶段 3 内 technical_interrupt 被拒（force_revert 也适用）
    if tx.reason.is_technical_interrupt() {
        let stage = RecoveryStage::compute(
            game,
            tx.current_block_height,
            tx.turn_timeout_blocks,
            tx.da_window_blocks,
            tx.recovery_window_blocks,
        );
        if stage.requires_forfeit_and_revert() {
            return Err(PokerL1Error::OperatorCannotClaimTechnicalInterrupt(game.id));
        }
    }

    // 计算 forfeit decision（BEFORE mutation）
    let decision = ForfeitDecision::compute(
        game,
        tx.current_block_height,
        tx.turn_timeout_blocks,
        tx.is_designated_operator,
    );

    Ok(apply_revert_internal(
        game,
        tx.reason,
        decision,
        tx.current_block_height,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
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
            make_addr(0x01), // owner
            make_tagged_pubkey(0xFF),
            ExecutionMode::OffChain,
            RakeConfigRef {
                rake_rate_bps: 0,
                rake_cap: 0,
                rake_recipient: make_addr(0x00),
            },
            10, // turn_timeout_blocks
        );
        game.last_action_height = last_action_height;
        game.last_commitment = Some([0x11; 32]);
        game.last_checkpoint_state_hash = Some([0xAB; 32]);
        game
    }

    fn make_request_revert_tx(reason: RevertReason) -> RequestRevertTx {
        RequestRevertTx {
            game_id: make_game_id(),
            last_acked_checkpoint: [0xAB; 32],
            reason,
            submitter: make_addr(0x01), // owner
        }
    }

    fn make_force_revert_tx(
        reason: RevertReason,
        current_block_height: u64,
        is_designated_operator: bool,
    ) -> ForceRevertTx {
        ForceRevertTx {
            game_id: make_game_id(),
            last_acked_checkpoint: [0xAB; 32],
            reason,
            submitter: make_addr(0x02), // 任意参与者
            current_block_height,
            turn_timeout_blocks: 30,
            da_window_blocks: 500,
            recovery_window_blocks: 100,
            is_designated_operator,
        }
    }

    // ===== RevertReason 测试 =====

    #[test]
    fn test_revert_reason_triggers_forfeit() {
        assert!(!RevertReason::TechnicalInterrupt.triggers_forfeit());
        assert!(RevertReason::MaliciousWithholding.triggers_forfeit());
        assert!(RevertReason::DataUnavailable.triggers_forfeit());
    }

    #[test]
    fn test_revert_reason_is_technical_interrupt() {
        assert!(RevertReason::TechnicalInterrupt.is_technical_interrupt());
        assert!(!RevertReason::MaliciousWithholding.is_technical_interrupt());
        assert!(!RevertReason::DataUnavailable.is_technical_interrupt());
    }

    // ===== apply_request_revert 测试 =====

    #[test]
    fn test_apply_request_revert_technical_interrupt_no_forfeit() {
        // 阶段 1 内 technical_interrupt → 无 forfeit
        // last_action_height = 100, current = 120, turn_timeout = 30, age = 20 <= 30 → Stage1
        let mut game = make_game(100);
        let tx = make_request_revert_tx(RevertReason::TechnicalInterrupt);

        let outcome = apply_request_revert(&mut game, &tx, 120, 30, 500, 100).expect("应成功");
        assert!(!outcome.should_forfeit, "technical_interrupt 无 forfeit");
        assert!(outcome.reason.is_none());
        // 状态变更
        assert_eq!(game.last_action_height, 120);
        assert!(game.last_commitment.is_none());
        assert!(game.last_checkpoint_state_hash.is_none());
        assert_eq!(outcome.previous_last_action_height, 100);
    }

    #[test]
    fn test_apply_request_revert_malicious_withholding_forfeits() {
        // reason=malicious_withholding + age <= boundary → MaliciousWithholding forfeit
        // last_action_height = 100, current = 120, age = 20 <= 30
        let mut game = make_game(100);
        let tx = make_request_revert_tx(RevertReason::MaliciousWithholding);

        let outcome = apply_request_revert(&mut game, &tx, 120, 30, 500, 100).expect("应成功");
        assert!(
            outcome.should_forfeit,
            "malicious_withholding 应触发 forfeit"
        );
        assert_eq!(outcome.reason, Some(ForfeitReason::MaliciousWithholding));
    }

    #[test]
    fn test_apply_request_revert_data_unavailable_forfeits() {
        let mut game = make_game(100);
        let tx = make_request_revert_tx(RevertReason::DataUnavailable);

        let outcome = apply_request_revert(&mut game, &tx, 120, 30, 500, 100).expect("应成功");
        assert!(outcome.should_forfeit, "data_unavailable 应触发 forfeit");
    }

    #[test]
    fn test_apply_request_revert_malicious_withholding_age_over_boundary_still_forfeits() {
        // reason 优先：即使 age > boundary（MachineFailure），reason=malicious_withholding 仍触发 forfeit
        // last_action_height = 100, current = 200, age = 100 > 30 → MachineFailure
        // 但 reason=malicious_withholding → 仍 forfeit，标记为 MaliciousWithholding（reason 优先）
        let mut game = make_game(100);
        let tx = make_request_revert_tx(RevertReason::MaliciousWithholding);

        let outcome = apply_request_revert(&mut game, &tx, 200, 30, 500, 100).expect("应成功");
        assert!(
            outcome.should_forfeit,
            "reason=malicious_withholding 即使 age 超边界仍 forfeit"
        );
        assert_eq!(
            outcome.reason,
            Some(ForfeitReason::MaliciousWithholding),
            "reason 优先：标记为 MaliciousWithholding 而非 MachineFailure"
        );
    }

    #[test]
    fn test_apply_request_revert_technical_interrupt_rejected_in_stage3() {
        // R7-M6: 阶段 3 内 technical_interrupt 被拒
        // last_action_height = 100, current = 800, age = 700 > 630 (stage2_end) → Stage3
        let mut game = make_game(100);
        let tx = make_request_revert_tx(RevertReason::TechnicalInterrupt);

        let result = apply_request_revert(&mut game, &tx, 800, 30, 500, 100);
        assert!(
            matches!(
                result,
                Err(PokerL1Error::OperatorCannotClaimTechnicalInterrupt(_))
            ),
            "阶段 3 + technical_interrupt 应被 R7-M6 拒绝"
        );
        // 状态不变
        assert_eq!(game.last_action_height, 100);
        assert!(game.last_commitment.is_some());
    }

    #[test]
    fn test_apply_request_revert_wrong_submitter_rejected() {
        let mut game = make_game(100);
        let mut tx = make_request_revert_tx(RevertReason::TechnicalInterrupt);
        tx.submitter = make_addr(0x99); // 非 owner

        let result = apply_request_revert(&mut game, &tx, 120, 30, 500, 100);
        assert!(
            matches!(result, Err(PokerL1Error::NotOwner(_))),
            "request_revert submitter 非 owner 应被拒"
        );
    }

    #[test]
    fn test_apply_request_revert_wrong_game_id_rejected() {
        let mut game = make_game(100);
        let mut tx = make_request_revert_tx(RevertReason::TechnicalInterrupt);
        tx.game_id = ObjectID::new([0xFF; 20], 999);

        let result = apply_request_revert(&mut game, &tx, 120, 30, 500, 100);
        assert!(matches!(result, Err(PokerL1Error::GameNotFound(_))));
    }

    #[test]
    fn test_apply_request_revert_clears_last_commitment() {
        let mut game = make_game(100);
        let tx = make_request_revert_tx(RevertReason::TechnicalInterrupt);

        apply_request_revert(&mut game, &tx, 120, 30, 500, 100).expect("应成功");
        assert!(
            game.last_commitment.is_none(),
            "回退后 last_commitment 清除"
        );
    }

    #[test]
    fn test_apply_request_revert_clears_last_checkpoint_state_hash() {
        let mut game = make_game(100);
        let tx = make_request_revert_tx(RevertReason::TechnicalInterrupt);

        apply_request_revert(&mut game, &tx, 120, 30, 500, 100).expect("应成功");
        assert!(
            game.last_checkpoint_state_hash.is_none(),
            "回退后 last_checkpoint_state_hash 清除"
        );
    }

    #[test]
    fn test_apply_request_revert_increments_version() {
        let mut game = make_game(100);
        let prev_version = game.version;
        let tx = make_request_revert_tx(RevertReason::TechnicalInterrupt);

        apply_request_revert(&mut game, &tx, 120, 30, 500, 100).expect("应成功");
        assert_eq!(game.version, prev_version.saturating_add(1));
    }

    // ===== apply_force_revert 测试 =====

    #[test]
    fn test_apply_force_revert_malicious_withholding_forfeits() {
        // 任意参与者提交 force_revert(reason=malicious_withholding)
        // last_action_height = 100, current = 800, age = 700 > 630 → Stage3
        let mut game = make_game(100);
        let tx = make_force_revert_tx(RevertReason::MaliciousWithholding, 800, false);

        let outcome = apply_force_revert(&mut game, &tx).expect("应成功");
        assert!(
            outcome.should_forfeit,
            "force_revert malicious_withholding 应 forfeit"
        );
        assert_eq!(outcome.reason, Some(ForfeitReason::MaliciousWithholding));
    }

    #[test]
    fn test_apply_force_revert_data_unavailable_forfeits() {
        let mut game = make_game(100);
        let tx = make_force_revert_tx(RevertReason::DataUnavailable, 800, false);

        let outcome = apply_force_revert(&mut game, &tx).expect("应成功");
        assert!(
            outcome.should_forfeit,
            "force_revert data_unavailable 应 forfeit"
        );
    }

    #[test]
    fn test_apply_force_revert_designated_operator_boundary_doubled() {
        // NEW-M4: designated operator → boundary = 30 * 2 = 60
        // last_action_height = 100, current = 150, age = 50 <= 60 → MaliciousWithholding
        let mut game = make_game(100);
        let tx = make_force_revert_tx(RevertReason::MaliciousWithholding, 150, true);

        let outcome = apply_force_revert(&mut game, &tx).expect("应成功");
        assert!(outcome.should_forfeit);
        assert_eq!(outcome.boundary, 60, "designated operator boundary 加倍");
        assert_eq!(outcome.reason, Some(ForfeitReason::MaliciousWithholding));
    }

    #[test]
    fn test_apply_force_revert_designated_operator_machine_failure_still_forfeits() {
        // NEW-M4: designated operator → boundary = 60
        // age = 70 > 60 → MachineFailure（H4 判定）
        // 但 reason=malicious_withholding → reason 优先，仍 forfeit，标记为 MaliciousWithholding
        let mut game = make_game(100);
        let tx = make_force_revert_tx(RevertReason::MaliciousWithholding, 170, true);

        let outcome = apply_force_revert(&mut game, &tx).expect("应成功");
        assert!(
            outcome.should_forfeit,
            "reason 优先：即使 age > boundary 仍 forfeit"
        );
        assert_eq!(
            outcome.reason,
            Some(ForfeitReason::MaliciousWithholding),
            "reason=malicious_withholding 优先，标记为 MaliciousWithholding 而非 MachineFailure"
        );
    }

    #[test]
    fn test_apply_force_revert_technical_interrupt_rejected_in_stage3() {
        // R7-M6: 阶段 3 内 technical_interrupt 被拒（force_revert 也适用）
        let mut game = make_game(100);
        let tx = make_force_revert_tx(RevertReason::TechnicalInterrupt, 800, false);

        let result = apply_force_revert(&mut game, &tx);
        assert!(
            matches!(
                result,
                Err(PokerL1Error::OperatorCannotClaimTechnicalInterrupt(_))
            ),
            "force_revert 阶段 3 + technical_interrupt 应被 R7-M6 拒绝"
        );
    }

    #[test]
    fn test_apply_force_revert_technical_interrupt_allowed_in_stage1() {
        // 阶段 1 内 technical_interrupt 允许（无 forfeit）
        // 虽然典型由操作方提交，但协议层不强制
        let mut game = make_game(100);
        let tx = make_force_revert_tx(RevertReason::TechnicalInterrupt, 120, false);

        let outcome = apply_force_revert(&mut game, &tx).expect("应成功");
        assert!(
            !outcome.should_forfeit,
            "阶段 1 内 technical_interrupt 无 forfeit"
        );
        assert!(outcome.reason.is_none());
    }

    #[test]
    fn test_apply_force_revert_wrong_game_id_rejected() {
        let mut game = make_game(100);
        let mut tx = make_force_revert_tx(RevertReason::MaliciousWithholding, 800, false);
        tx.game_id = ObjectID::new([0xFF; 20], 999);

        let result = apply_force_revert(&mut game, &tx);
        assert!(matches!(result, Err(PokerL1Error::GameNotFound(_))));
    }

    #[test]
    fn test_apply_force_revert_clears_anchors() {
        let mut game = make_game(100);
        let tx = make_force_revert_tx(RevertReason::MaliciousWithholding, 800, false);

        apply_force_revert(&mut game, &tx).expect("应成功");
        assert!(game.last_commitment.is_none());
        assert!(game.last_checkpoint_state_hash.is_none());
        assert_eq!(game.last_action_height, 800);
    }

    #[test]
    fn test_apply_force_revert_increments_version() {
        let mut game = make_game(100);
        let prev_version = game.version;
        let tx = make_force_revert_tx(RevertReason::MaliciousWithholding, 800, false);

        apply_force_revert(&mut game, &tx).expect("应成功");
        assert_eq!(game.version, prev_version.saturating_add(1));
    }
}
