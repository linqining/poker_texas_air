//! request_da tx（SubTask 28.6 — 操作方故障恢复阶段 2 入口）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）+ tasks.md SubTask 28.6：
//! - request_da tx（任意 validator）：要求操作方在 `da_window_blocks` 内发布状态
//! - 进入操作方故障恢复流程阶段 2
//! - `da_window_blocks + recovery_window_blocks` 过期且无 force_checkin 且操作方未恢复 →
//!   触发 `force_revert`
//!
//! # 阶段定义（SubTask 27.5e）
//!
//! - **Stage 1**（`elapsed <= turn_timeout_blocks`）：操作方可恢复，force_advance 可触发，无 forfeit
//! - **Stage 2**（`turn_timeout_blocks < elapsed <= turn_timeout_blocks + da_window_blocks +
//!   recovery_window_blocks`）：request_da + 参与者重折叠 force_checkin，无 forfeit
//! - **Stage 3**（窗口过期）：forfeit + force_revert
//!
//! # request_da 的语义
//!
//! request_da 是一个**信号 tx**，由任意参与者提交，声明"操作方未在 turn_timeout_blocks
//! 内活动，要求其在 da_window_blocks 内发布状态"。
//!
//! - 提交时机：Stage 1 已过（elapsed > turn_timeout_blocks），即 Stage 2 开始
//! - 提交后：操作方有 `da_window_blocks + recovery_window_blocks` 时间恢复
//!   （提交 checkpoint_anchor / checkin / force_checkin）
//! - 窗口过期：参与者可提交 `force_revert(reason=malicious_withholding)` 触发 forfeit
//!
//! 协议层不强制 request_da 必须提交才能进入 Stage 2（Stage 由 block height 自动判定），
//! 但 request_da 作为链上事件记录，便于审计和争议解决。

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::Address;
use crate::error::PokerL1Error;
use crate::object_model::ObjectID;

use super::force_checkin::RecoveryStage;
use super::types::GameContract;

/// request_da tx（SubTask 28.6）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct RequestDaTx {
    /// Game 对象 ID。
    pub game_id: ObjectID,
    /// 提交者地址（任意参与者）。
    pub submitter: Address,
    /// 当前 block height。
    pub current_block_height: u64,
    /// turn_timeout_blocks（来自 TimeConsensusConfig）。
    pub turn_timeout_blocks: u64,
    /// da_window_blocks（来自 TimeConsensusConfig）。
    pub da_window_blocks: u64,
    /// recovery_window_blocks（默认 100，SubTask 27.5e）。
    pub recovery_window_blocks: u64,
}

/// request_da 应用结果（SubTask 28.6）。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct RequestDaOutcome {
    /// 当前所处的故障恢复阶段。
    pub stage: RecoveryStage,
    /// DA 截止 height（`last_action_height + turn_timeout_blocks + da_window_blocks`）。
    ///
    /// 操作方须在此 height 前发布状态（checkpoint_anchor / checkin）。
    pub da_deadline: u64,
    /// 恢复截止 height（`da_deadline + recovery_window_blocks`）。
    ///
    /// 参与者须在此 height 前提交 force_checkin，否则可触发 force_revert。
    pub recovery_deadline: u64,
    /// 是否应立即触发 force_revert（已进入 Stage 3）。
    pub triggers_force_revert: bool,
    /// 自 last_action_height 起经过的 block 数。
    pub elapsed: u64,
}

/// 应用 request_da 到 GameContract（SubTask 28.6）。
///
/// # 流程
/// 1. 校验 `tx.game_id == game.id`
/// 2. 计算当前故障恢复阶段（RecoveryStage）
/// 3. 计算 DA 截止 + 恢复截止 height
/// 4. 判定是否应触发 force_revert（Stage 3）
/// 5. 递增 version（request_da 是链上事件）
///
/// # 参数
/// - `game`：可变的 GameContract 引用
/// - `tx`：request_da tx
///
/// # 返回
/// [`RequestDaOutcome`]，caller 据此决定是否触发 force_revert。
///
/// # 错误
/// - [`PokerL1Error::GameNotFound`]：game_id 不匹配
pub fn apply_request_da(
    game: &mut GameContract,
    tx: &RequestDaTx,
) -> Result<RequestDaOutcome, PokerL1Error> {
    // 1. 校验 game_id 一致
    if tx.game_id != game.id {
        return Err(PokerL1Error::GameNotFound(tx.game_id));
    }

    // 2. 计算当前阶段
    let stage = RecoveryStage::compute(
        game,
        tx.current_block_height,
        tx.turn_timeout_blocks,
        tx.da_window_blocks,
        tx.recovery_window_blocks,
    );

    // 3. 计算 DA 截止 + 恢复截止 height
    // Stage 2 起点 = last_action_height + turn_timeout_blocks
    // DA 截止 = Stage 2 起点 + da_window_blocks
    // 恢复截止 = DA 截止 + recovery_window_blocks
    let stage2_start = game
        .last_action_height
        .saturating_add(tx.turn_timeout_blocks);
    let da_deadline = stage2_start.saturating_add(tx.da_window_blocks);
    let recovery_deadline = da_deadline.saturating_add(tx.recovery_window_blocks);

    // 4. 计算已过 block 数
    let elapsed = tx
        .current_block_height
        .saturating_sub(game.last_action_height);

    // 5. 判定是否触发 force_revert（Stage 3）
    let triggers_force_revert = stage.requires_forfeit_and_revert();

    // 6. 递增 version（request_da 是链上事件）
    game.version = game.version.saturating_add(1);

    Ok(RequestDaOutcome {
        stage,
        da_deadline,
        recovery_deadline,
        triggers_force_revert,
        elapsed,
    })
}

/// 判定 request_da 是否可提交（SubTask 28.6）。
///
/// 协议层允许任意时刻提交，但典型场景为 Stage 1 已过（elapsed > turn_timeout_blocks）。
/// 此辅助函数供 caller 决定是否拒绝过早提交（防 spam）。
#[must_use]
pub const fn is_request_da_appropriate(
    game: &GameContract,
    current_block_height: u64,
    turn_timeout_blocks: u64,
) -> bool {
    let elapsed = current_block_height.saturating_sub(game.last_action_height);
    elapsed > turn_timeout_blocks
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

    fn make_request_da_tx(current_block_height: u64) -> RequestDaTx {
        RequestDaTx {
            game_id: make_game_id(),
            submitter: make_addr(0x02),
            current_block_height,
            turn_timeout_blocks: 30,
            da_window_blocks: 500,
            recovery_window_blocks: 100,
        }
    }

    // ===== apply_request_da 测试 =====

    #[test]
    fn test_apply_request_da_stage2_returns_deadlines() {
        // last_action_height = 100, current = 200, turn_timeout = 30
        // elapsed = 100, stage2_end = 30 + 500 + 100 = 630, 100 <= 630 → Stage2
        let mut game = make_game(100);
        let tx = make_request_da_tx(200);
        let prev_version = game.version;

        let outcome = apply_request_da(&mut game, &tx).expect("应成功");
        assert!(matches!(outcome.stage, RecoveryStage::Stage2 { .. }));
        // DA 截止 = 100 + 30 + 500 = 630
        assert_eq!(outcome.da_deadline, 630);
        // 恢复截止 = 630 + 100 = 730
        assert_eq!(outcome.recovery_deadline, 730);
        assert_eq!(outcome.elapsed, 100);
        assert!(!outcome.triggers_force_revert);
        assert_eq!(game.version, prev_version.saturating_add(1));
    }

    #[test]
    fn test_apply_request_da_stage1_still_allowed() {
        // 阶段 1 内提交 request_da：协议层允许，但典型场景为 Stage 2
        // last_action_height = 100, current = 120, elapsed = 20 <= 30 → Stage1
        let mut game = make_game(100);
        let tx = make_request_da_tx(120);

        let outcome = apply_request_da(&mut game, &tx).expect("应成功");
        assert!(matches!(outcome.stage, RecoveryStage::Stage1 { .. }));
        assert!(!outcome.triggers_force_revert);
        // DA 截止仍按 last_action_height + turn_timeout + da_window 计算
        assert_eq!(outcome.da_deadline, 630);
    }

    #[test]
    fn test_apply_request_da_stage3_triggers_force_revert() {
        // last_action_height = 100, current = 800, elapsed = 700 > 630 → Stage3
        let mut game = make_game(100);
        let tx = make_request_da_tx(800);

        let outcome = apply_request_da(&mut game, &tx).expect("应成功");
        assert!(matches!(outcome.stage, RecoveryStage::Stage3 { .. }));
        assert!(outcome.triggers_force_revert, "Stage 3 应触发 force_revert");
    }

    #[test]
    fn test_apply_request_da_wrong_game_id_rejected() {
        let mut game = make_game(100);
        let mut tx = make_request_da_tx(200);
        tx.game_id = ObjectID::new([0xFF; 20], 999);

        let result = apply_request_da(&mut game, &tx);
        assert!(matches!(result, Err(PokerL1Error::GameNotFound(_))));
    }

    #[test]
    fn test_apply_request_da_increments_version() {
        let mut game = make_game(100);
        let prev_version = game.version;
        let tx = make_request_da_tx(200);

        apply_request_da(&mut game, &tx).expect("应成功");
        assert_eq!(game.version, prev_version.saturating_add(1));
    }

    #[test]
    fn test_apply_request_da_does_not_modify_last_action_height() {
        // request_da 不更新 last_action_height（非操作方活动）
        let mut game = make_game(100);
        let tx = make_request_da_tx(200);

        apply_request_da(&mut game, &tx).expect("应成功");
        assert_eq!(
            game.last_action_height, 100,
            "request_da 不更新 last_action_height"
        );
    }

    #[test]
    fn test_apply_request_da_stage2_boundary_inclusive() {
        // SEC2-L6: <= 边界判定
        // elapsed = 630 == stage2_end (630) → Stage2
        let mut game = make_game(100);
        let tx = make_request_da_tx(730); // 730 - 100 = 630 == stage2_end

        let outcome = apply_request_da(&mut game, &tx).expect("应成功");
        assert!(matches!(outcome.stage, RecoveryStage::Stage2 { .. }));
        assert!(!outcome.triggers_force_revert);
    }

    #[test]
    fn test_apply_request_da_just_past_stage2_boundary() {
        // elapsed = 631 > 630 → Stage3
        let mut game = make_game(100);
        let tx = make_request_da_tx(731);

        let outcome = apply_request_da(&mut game, &tx).expect("应成功");
        assert!(matches!(outcome.stage, RecoveryStage::Stage3 { .. }));
        assert!(outcome.triggers_force_revert);
    }

    // ===== is_request_da_appropriate 测试 =====

    #[test]
    fn test_is_request_da_appropriate_in_stage1() {
        // elapsed = 20 <= 30 → Stage1，request_da 不适当（过早）
        let game = make_game(100);
        assert!(!is_request_da_appropriate(&game, 120, 30));
    }

    #[test]
    fn test_is_request_da_appropriate_just_past_stage1() {
        // elapsed = 31 > 30 → Stage2，request_da 适当
        let game = make_game(100);
        assert!(is_request_da_appropriate(&game, 131, 30));
    }

    #[test]
    fn test_is_request_da_appropriate_at_stage1_boundary() {
        // elapsed = 30 == 30 → Stage1（<= 边界），request_da 不适当
        let game = make_game(100);
        assert!(!is_request_da_appropriate(&game, 130, 30));
    }

    #[test]
    fn test_is_request_da_appropriate_in_stage3() {
        // elapsed = 700 > 630 → Stage3，request_da 仍适当（可触发 force_revert）
        let game = make_game(100);
        assert!(is_request_da_appropriate(&game, 800, 30));
    }
}
