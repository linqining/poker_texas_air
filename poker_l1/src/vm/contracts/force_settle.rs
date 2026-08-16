//! force_settle tx（SubTask 28.7 — 整局超时兜底结算）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）+ tasks.md SubTask 28.7：
//! - force_settle tx（任意 validator）：整局超时兜底结算
//!
//! # 触发条件
//!
//! 当 Game 进入 Stage 3（故障恢复窗口完全过期）且仍未结算时，任意参与者可提交
//! force_settle tx 强制结算当前手牌。
//!
//! Stage 3 触发条件（SubTask 27.5e）：
//! `elapsed > turn_timeout_blocks + da_window_blocks + recovery_window_blocks`
//!
//! # 结算规则
//!
//! 复用 [`super::settle::settle_hand`] 逻辑：
//! 1. 确定胜者（最后一个未 fold 的玩家）
//! 2. 计算台费 `rake = min(rake_rate × pot, rake_cap)`
//! 3. 胜者分得 `pot - rake`
//! 4. 台费转入 `rake_recipient`
//!
//! 若所有玩家已 fold（无胜者），底池按 buy_in 比例退还（caller 负责）。
//!
//! # 状态变更
//!
//! 1. 标记当前手牌 `phase = Settled`
//! 2. 更新 `last_action_height = current_block_height`
//! 3. 清除 `last_commitment` / `last_checkpoint_state_hash`
//! 4. 递增 `version`

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::Address;
use crate::error::PokerL1Error;
use crate::object_model::ObjectID;

use super::force_checkin::RecoveryStage;
use super::settle::{RakeConfig, SettleResult, settle_hand};
use super::types::{GameContract, GamePhase};

/// force_settle tx（SubTask 28.7）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ForceSettleTx {
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

/// force_settle 应用结果（SubTask 28.7）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ForceSettleOutcome {
    /// settle 结果（胜者 + 台费 + 分配）。
    pub settle_result: SettleResult,
    /// 结算前 `game.last_action_height`（用于审计）。
    pub previous_last_action_height: u64,
}

/// 应用 force_settle 到 GameContract（SubTask 28.7）。
///
/// # 流程
/// 1. 校验 `tx.game_id == game.id`
/// 2. 校验当前阶段为 Stage 3（故障恢复窗口完全过期）
/// 3. 校验当前手牌未结算
/// 4. 调用 `settle_hand` 执行结算
/// 5. 标记手牌 `phase = Settled`
/// 6. 更新 `last_action_height = current_block_height`
/// 7. 清除 `last_commitment` / `last_checkpoint_state_hash`
/// 8. 递增 `version`
///
/// # 参数
/// - `game`：可变的 GameContract 引用
/// - `tx`：force_settle tx
/// - `rake_config`：台费配置（来自 game.rake_config 转 RakeConfig）
///
/// # 返回
/// [`ForceSettleOutcome`]，含 settle 结果。
///
/// # 错误
/// - [`PokerL1Error::GameNotFound`]：game_id 不匹配
/// - [`PokerL1Error::Other`]：未进入 Stage 3（窗口未过期）
/// - [`PokerL1Error::Other`]：手牌已结算
/// - [`PokerL1Error::Other`]：无当前手牌
/// - [`PokerL1Error::Other`]：settle 失败（无胜者等）
pub fn apply_force_settle(
    game: &mut GameContract,
    tx: &ForceSettleTx,
    rake_config: &RakeConfig,
) -> Result<ForceSettleOutcome, PokerL1Error> {
    // 1. 校验 game_id 一致
    if tx.game_id != game.id {
        return Err(PokerL1Error::GameNotFound(tx.game_id));
    }

    // 2. 校验当前阶段为 Stage 3
    let stage = RecoveryStage::compute(
        game,
        tx.current_block_height,
        tx.turn_timeout_blocks,
        tx.da_window_blocks,
        tx.recovery_window_blocks,
    );
    if !stage.requires_forfeit_and_revert() {
        return Err(PokerL1Error::Other(format!(
            "force_settle not allowed: stage not yet Stage3 (elapsed={:?})",
            stage
        )));
    }

    // 3. 校验当前手牌未结算
    let hand = game
        .current_hand
        .as_mut()
        .ok_or_else(|| PokerL1Error::Other("force_settle: no current hand".to_string()))?;
    if hand.phase.is_settled() {
        return Err(PokerL1Error::Other(
            "force_settle: hand already settled".to_string(),
        ));
    }

    // 4. 调用 settle_hand 执行结算（clone hand 避免借用冲突）
    let hand_snapshot = hand.clone();
    let settle_result = settle_hand(&hand_snapshot, rake_config)
        .map_err(|e| PokerL1Error::Other(format!("force_settle settle failed: {e}")))?;

    let prev_last_action_height = game.last_action_height;

    // 5. 标记手牌 Settled
    hand.phase = GamePhase::Settled;
    hand.last_action_height = tx.current_block_height;

    // 6. 更新 game.last_action_height
    game.last_action_height = tx.current_block_height;

    // 7. 清除 last_commitment / last_checkpoint_state_hash
    game.last_commitment = None;
    game.last_checkpoint_state_hash = None;

    // 8. 递增 version
    game.version = game.version.saturating_add(1);

    Ok(ForceSettleOutcome {
        settle_result,
        previous_last_action_height: prev_last_action_height,
    })
}

/// 判定 force_settle 是否可提交（SubTask 28.7）。
///
/// 仅当 Stage 3（故障恢复窗口完全过期）时允许。
#[must_use]
pub const fn is_force_settle_allowed(
    game: &GameContract,
    current_block_height: u64,
    turn_timeout_blocks: u64,
    da_window_blocks: u64,
    recovery_window_blocks: u64,
) -> bool {
    let stage = RecoveryStage::compute(
        game,
        current_block_height,
        turn_timeout_blocks,
        da_window_blocks,
        recovery_window_blocks,
    );
    stage.requires_forfeit_and_revert()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::{CURRENT_VERSION, SignatureScheme, TaggedPubkey};
    use crate::vm::contracts::types::{
        ExecutionMode, GamePhase, HandState, PlayerStack, RakeConfigRef,
    };

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

    fn make_rake_config() -> RakeConfig {
        RakeConfig {
            rake_rate_bps: 0,
            rake_cap: 0,
            rake_recipient: make_addr(0x00),
        }
    }

    fn make_game_with_hand(last_action_height: u64) -> GameContract {
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
        // 设置一个未 fold 的玩家手牌
        let p1 = PlayerStack::new(make_addr(0x10));
        let p2 = PlayerStack::new(make_addr(0x20));
        let hand = HandState {
            phase: GamePhase::Preflop,
            pot: 100,
            current_bet: 0,
            big_blind_amount: 20,
            small_blind_amount: 10,
            raise_count: 0,
            bet_count: 0,
            current_turn: p1.address,
            players: vec![p1, p2],
            last_action_height,
            hand_start_height: 90,
        };
        game.current_hand = Some(hand);
        game.last_action_height = last_action_height;
        game.last_commitment = Some([0x11; 32]);
        game.last_checkpoint_state_hash = Some([0xAB; 32]);
        game
    }

    fn make_force_settle_tx(current_block_height: u64) -> ForceSettleTx {
        ForceSettleTx {
            game_id: make_game_id(),
            submitter: make_addr(0x02),
            current_block_height,
            turn_timeout_blocks: 30,
            da_window_blocks: 500,
            recovery_window_blocks: 100,
        }
    }

    // ===== apply_force_settle 测试 =====

    #[test]
    fn test_apply_force_settle_succeeds_in_stage3() {
        // last_action_height = 100, current = 800, elapsed = 700 > 630 → Stage3
        let mut game = make_game_with_hand(100);
        let tx = make_force_settle_tx(800);
        let prev_version = game.version;

        let outcome = apply_force_settle(&mut game, &tx, &make_rake_config()).expect("应成功");
        // settle 结果：胜者为第一个未 fold 玩家
        assert_eq!(outcome.settle_result.winner, make_addr(0x10));
        assert_eq!(outcome.settle_result.pot, 100);
        assert_eq!(outcome.previous_last_action_height, 100);
        // 状态变更
        assert_eq!(game.last_action_height, 800);
        assert!(matches!(
            game.current_hand.as_ref().unwrap().phase,
            GamePhase::Settled
        ));
        assert!(game.last_commitment.is_none());
        assert!(game.last_checkpoint_state_hash.is_none());
        assert_eq!(game.version, prev_version.saturating_add(1));
    }

    #[test]
    fn test_apply_force_settle_rejected_in_stage2() {
        // last_action_height = 100, current = 200, elapsed = 100 <= 630 → Stage2
        let mut game = make_game_with_hand(100);
        let tx = make_force_settle_tx(200);

        let result = apply_force_settle(&mut game, &tx, &make_rake_config());
        assert!(result.is_err(), "Stage 2 内 force_settle 应被拒");
        // 状态不变
        assert_eq!(game.last_action_height, 100);
        assert!(matches!(
            game.current_hand.as_ref().unwrap().phase,
            GamePhase::Preflop
        ));
    }

    #[test]
    fn test_apply_force_settle_rejected_in_stage1() {
        // last_action_height = 100, current = 120, elapsed = 20 <= 30 → Stage1
        let mut game = make_game_with_hand(100);
        let tx = make_force_settle_tx(120);

        let result = apply_force_settle(&mut game, &tx, &make_rake_config());
        assert!(result.is_err(), "Stage 1 内 force_settle 应被拒");
    }

    #[test]
    fn test_apply_force_settle_wrong_game_id_rejected() {
        let mut game = make_game_with_hand(100);
        let mut tx = make_force_settle_tx(800);
        tx.game_id = ObjectID::new([0xFF; 20], 999);

        let result = apply_force_settle(&mut game, &tx, &make_rake_config());
        assert!(matches!(result, Err(PokerL1Error::GameNotFound(_))));
    }

    #[test]
    fn test_apply_force_settle_no_hand_rejected() {
        // 无当前手牌
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
        game.last_action_height = 100;
        let tx = make_force_settle_tx(800);

        let result = apply_force_settle(&mut game, &tx, &make_rake_config());
        assert!(result.is_err(), "无当前手牌应被拒");
    }

    #[test]
    fn test_apply_force_settle_already_settled_rejected() {
        let mut game = make_game_with_hand(100);
        // 标记手牌已结算
        if let Some(hand) = game.current_hand.as_mut() {
            hand.phase = GamePhase::Settled;
        }
        let tx = make_force_settle_tx(800);

        let result = apply_force_settle(&mut game, &tx, &make_rake_config());
        assert!(result.is_err(), "已结算手牌应被拒");
    }

    #[test]
    fn test_apply_force_settle_clears_anchors() {
        let mut game = make_game_with_hand(100);
        let tx = make_force_settle_tx(800);

        apply_force_settle(&mut game, &tx, &make_rake_config()).expect("应成功");
        assert!(game.last_commitment.is_none());
        assert!(game.last_checkpoint_state_hash.is_none());
    }

    #[test]
    fn test_apply_force_settle_stage3_boundary_exclusive() {
        // SEC2-L6: <= 边界判定（Stage 2 边界包含）
        // elapsed = 630 == stage2_end → Stage2（仍在窗口内）
        let mut game = make_game_with_hand(100);
        let tx = make_force_settle_tx(730); // 730 - 100 = 630 == stage2_end

        let result = apply_force_settle(&mut game, &tx, &make_rake_config());
        assert!(
            result.is_err(),
            "elapsed == stage2_end 仍为 Stage2，force_settle 被拒"
        );
    }

    #[test]
    fn test_apply_force_settle_just_past_stage2_boundary() {
        // elapsed = 631 > 630 → Stage3
        let mut game = make_game_with_hand(100);
        let tx = make_force_settle_tx(731);

        let outcome = apply_force_settle(&mut game, &tx, &make_rake_config());
        assert!(
            outcome.is_ok(),
            "elapsed = 631 > 630 → Stage3，force_settle 应成功"
        );
    }

    // ===== is_force_settle_allowed 测试 =====

    #[test]
    fn test_is_force_settle_allowed_stage3() {
        let game = make_game_with_hand(100);
        assert!(is_force_settle_allowed(&game, 800, 30, 500, 100));
    }

    #[test]
    fn test_is_force_settle_not_allowed_stage2() {
        let game = make_game_with_hand(100);
        assert!(!is_force_settle_allowed(&game, 200, 30, 500, 100));
    }

    #[test]
    fn test_is_force_settle_not_allowed_stage1() {
        let game = make_game_with_hand(100);
        assert!(!is_force_settle_allowed(&game, 120, 30, 500, 100));
    }
}
