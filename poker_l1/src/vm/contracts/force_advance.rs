//! force_advance fold/check 规则（Task 16 — SubTask 16.6）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）第 683-693 行：
//! - **第 683-687 行（轮次超时强制推进）**：当前轮次玩家在 `turn_timeout_blocks` 内
//!   未提交 GameTurn tx（OnChain）或未提交 checkpoint_anchor（OffChain）时，
//!   任何参与者可提交 `force_advance` tx（路由到任意 validator）；超时玩家按 fold
//!   处理（弃牌失去本轮投入），除非当前轮次无人下注且该玩家在大盲位（按 check 处理）（M6 修复）。
//! - **第 689-693 行（force_advance 的 fold/check 规则）**：
//!   - 默认超时 = fold（玩家弃牌，失去本轮已投入筹码）
//!   - 例外：当前下注轮无人加注（current_bet == 0 且无 raise）且超时玩家是大盲位，
//!     则超时 = check（过牌，不丢失筹码）
//!   - **SEC2-L5 修复 — fold/check 规则边界修正**：
//!     1. **preflop 阶段**：当前下注轮无人 raise（即 `current_bet == big_blind_amount`
//!        且 `raise_count == 0`）且超时玩家是大盲位 → check
//!     2. **postflop 阶段**：当前下注轮无人下注（`current_bet == 0` 且 `bet_count == 0`）→
//!        任何超时玩家 check（不仅限大盲位）
//!     3. 规则由协议层定义，合约可覆盖
//!
//! # 判定流程
//!
//! ```text
//! force_advance(timeout_player) → Action:
//!   1. if betting_round == Preflop:
//!        if current_bet == big_blind_amount AND raise_count == 0
//!           AND timeout_player == big_blind_player:
//!          → Check
//!        else:
//!          → Fold
//!   2. if betting_round == Postflop:
//!        if current_bet == 0 AND bet_count == 0:
//!          → Check  (任意超时玩家)
//!        else:
//!          → Fold
//! ```

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::Address;

use super::types::{BettingRound, GameAction, GameContract, HandState};

/// force_advance 输入参数。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ForceAdvanceInput {
    /// 超时玩家地址。
    pub timeout_player: Address,
    /// 当前 block height（用于判定是否真的超时）。
    pub current_block_height: u64,
}

impl ForceAdvanceInput {
    /// 创建 force_advance 输入。
    #[must_use]
    pub const fn new(timeout_player: Address, current_block_height: u64) -> Self {
        Self {
            timeout_player,
            current_block_height,
        }
    }
}

/// force_advance 错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ForceAdvanceError {
    /// 超时玩家不在游戏中。
    #[error("timeout player {0:?} not in game")]
    PlayerNotInGame(Address),
    /// 超时玩家已 fold。
    #[error("timeout player {0:?} already folded")]
    PlayerAlreadyFolded(Address),
    /// 尚未超时（current_block_height - last_action_height < turn_timeout_blocks）。
    #[error("not timed out yet: elapsed={elapsed}, timeout={timeout}")]
    NotTimedOut {
        /// 已经过的 block 数。
        elapsed: u64,
        /// 超时阈值。
        timeout: u64,
    },
    /// 手牌已结算。
    #[error("hand already settled")]
    HandAlreadySettled,
}

/// 判定 force_advance 的动作（fold / check）。
///
/// 严格遵循 spec.md 第 689-693 行 SEC2-L5 修复后的规则。
///
/// # 参数
///
/// - `hand`：当前手牌状态
/// - `input`：force_advance 输入（超时玩家 + 当前 block height）
///
/// # 返回
///
/// - [`GameAction::Check`]：超时玩家可过牌（不丢失筹码）
/// - [`GameAction::Fold`]：超时玩家弃牌（失去本轮已投入筹码）
///
/// # 错误
///
/// - [`ForceAdvanceError::PlayerNotInGame`]：超时玩家不在游戏中
/// - [`ForceAdvanceError::PlayerAlreadyFolded`]：超时玩家已 fold
/// - [`ForceAdvanceError::NotTimedOut`]：尚未超时
/// - [`ForceAdvanceError::HandAlreadySettled`]：手牌已结算
pub fn force_advance_action(
    hand: &HandState,
    input: &ForceAdvanceInput,
    turn_timeout_blocks: u64,
) -> Result<GameAction, ForceAdvanceError> {
    // 校验手牌未结算
    if hand.phase.is_settled() {
        return Err(ForceAdvanceError::HandAlreadySettled);
    }

    // 校验超时玩家在游戏中
    let player_idx = hand
        .find_player(&input.timeout_player)
        .ok_or(ForceAdvanceError::PlayerNotInGame(input.timeout_player))?;

    // 校验超时玩家未 fold
    if hand.players[player_idx].folded {
        return Err(ForceAdvanceError::PlayerAlreadyFolded(input.timeout_player));
    }

    // 校验确实超时（current_block_height - last_action_height >= turn_timeout_blocks）
    let elapsed = input
        .current_block_height
        .saturating_sub(hand.last_action_height);
    if elapsed < turn_timeout_blocks {
        return Err(ForceAdvanceError::NotTimedOut {
            elapsed,
            timeout: turn_timeout_blocks,
        });
    }

    // 按 betting_round 分支判定 fold / check（SEC2-L5 修复）
    let action = match hand.betting_round() {
        BettingRound::Preflop => {
            // preflop：current_bet == big_blind_amount AND raise_count == 0
            //          AND 超时玩家是大盲位 → check
            //          否则 → fold
            let is_big_blind = hand.players[player_idx].is_big_blind;
            if hand.current_bet == hand.big_blind_amount && hand.raise_count == 0 && is_big_blind {
                GameAction::Check
            } else {
                GameAction::Fold
            }
        }
        BettingRound::Postflop => {
            // postflop：current_bet == 0 AND bet_count == 0 → check（任意玩家）
            //          否则 → fold
            if hand.current_bet == 0 && hand.bet_count == 0 {
                GameAction::Check
            } else {
                GameAction::Fold
            }
        }
    };

    Ok(action)
}

/// 应用 force_advance 到 GameContract（SubTask 28.2）。
///
/// 状态更新：
/// 1. 调用 `force_advance_action` 判定动作（fold / check）
/// 2. Fold → 标记超时玩家 `folded = true`
/// 3. Check → 玩家筹码不变，仅推进轮次
/// 4. **R5-L1 修正**：更新 `last_action_height = block_height`（hand 级 + game 级），
///    实现自然频率限制（每 `turn_timeout_blocks` 最多 1 次 force_advance）
/// 5. 推进 `current_turn` 到下一个未 fold 玩家
/// 6. 递增 `game.version`
///
/// # 参数
/// - `game`：可变的 GameContract 引用
/// - `input`：force_advance 输入（超时玩家 + 当前 block height）
///
/// # 返回
/// 应用的动作（Fold / Check），供调用方记录日志
///
/// # 错误
/// - [`ForceAdvanceError::HandAlreadySettled`]：手牌已结算
/// - [`ForceAdvanceError::PlayerNotInGame`]：超时玩家不在游戏中
/// - [`ForceAdvanceError::PlayerAlreadyFolded`]：超时玩家已 fold
/// - [`ForceAdvanceError::NotTimedOut`]：尚未超时
pub fn apply_force_advance(
    game: &mut GameContract,
    input: &ForceAdvanceInput,
) -> Result<GameAction, ForceAdvanceError> {
    let hand = game
        .current_hand
        .as_mut()
        .ok_or(ForceAdvanceError::HandAlreadySettled)?;

    // 判定动作（复用已有逻辑）
    let action = force_advance_action(hand, input, game.turn_timeout_blocks)?;

    let player_idx = hand
        .find_player(&input.timeout_player)
        .expect("force_advance_action 已校验玩家存在");

    // 应用动作
    match action {
        GameAction::Fold => {
            hand.players[player_idx].folded = true;
        }
        GameAction::Check => {
            // check：筹码不变，仅推进轮次
        }
        GameAction::Call | GameAction::Raise { .. } | GameAction::Bet { .. } => {
            // force_advance 不会产生这些动作
            return Err(ForceAdvanceError::HandAlreadySettled);
        }
    }

    // R5-L1：更新 last_action_height（hand 级 + game 级）
    hand.last_action_height = input.current_block_height;
    game.last_action_height = input.current_block_height;

    // 推进 current_turn 到下一个未 fold 玩家
    advance_to_next_active_player(hand, player_idx);

    game.version = game.version.saturating_add(1);

    Ok(action)
}

/// 推进 `current_turn` 到下一个未 fold 玩家。
///
/// 从 `from_idx` 的下一个位置开始扫描，找到第一个未 fold 玩家。
/// 若所有其他玩家都已 fold，则 `current_turn` 保持不变（仅剩一人，即将结算）。
fn advance_to_next_active_player(hand: &mut HandState, from_idx: usize) {
    let n = hand.players.len();
    if n <= 1 {
        return;
    }
    for offset in 1..=n {
        let idx = (from_idx + offset) % n;
        if !hand.players[idx].folded {
            hand.current_turn = hand.players[idx].address;
            return;
        }
    }
    // 所有玩家都已 fold（不应发生，但防御性处理）
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object_model::ObjectID;
    use crate::vm::contracts::types::{ExecutionMode, GamePhase, PlayerStack, RakeConfigRef};

    fn make_addr(byte: u8) -> Address {
        [byte; 20]
    }

    /// 创建测试用手牌状态。
    ///
    /// `players` 为 (address, is_big_blind, folded) 元组列表。
    fn make_hand(
        phase: GamePhase,
        current_bet: u64,
        raise_count: u32,
        bet_count: u32,
        last_action_height: u64,
        players: &[(Address, bool, bool)],
    ) -> HandState {
        let players: Vec<PlayerStack> = players
            .iter()
            .map(|(addr, is_bb, folded)| {
                let mut p = PlayerStack::new(*addr);
                p.is_big_blind = *is_bb;
                p.folded = *folded;
                p
            })
            .collect();
        HandState {
            phase,
            pot: 100,
            current_bet,
            big_blind_amount: 20,
            small_blind_amount: 10,
            raise_count,
            bet_count,
            current_turn: players[0].address,
            players,
            last_action_height,
            hand_start_height: 90,
        }
    }

    const DEFAULT_TIMEOUT_BLOCKS: u64 = 10;

    // ===== preflop 分支测试（SEC2-L5 修复 1）=====

    #[test]
    fn test_force_advance_preflop_bb_check_no_raise() {
        // preflop, current_bet == big_blind_amount, raise_count == 0, 超时玩家 == BB → check
        let bb = make_addr(0x01);
        let hand = make_hand(
            GamePhase::Preflop,
            20, // == big_blind_amount
            0,
            0,
            100,
            &[(bb, true, false)],
        );
        let input = ForceAdvanceInput::new(bb, 110); // elapsed = 10 == timeout

        let action = force_advance_action(&hand, &input, DEFAULT_TIMEOUT_BLOCKS).unwrap();
        assert_eq!(action, GameAction::Check, "BB preflop 无人 raise 应 check");
    }

    #[test]
    fn test_force_advance_preflop_bb_fold_when_raised() {
        // preflop, current_bet > big_blind_amount (有人 raise) → fold
        let bb = make_addr(0x01);
        let hand = make_hand(
            GamePhase::Preflop,
            40, // > big_blind_amount
            1,  // raise_count > 0
            0,
            100,
            &[(bb, true, false)],
        );
        let input = ForceAdvanceInput::new(bb, 110);

        let action = force_advance_action(&hand, &input, DEFAULT_TIMEOUT_BLOCKS).unwrap();
        assert_eq!(action, GameAction::Fold, "preflop 有人 raise 应 fold");
    }

    #[test]
    fn test_force_advance_preflop_non_bb_fold_no_raise() {
        // preflop, 无人 raise，但超时玩家不是 BB → fold
        let bb = make_addr(0x01);
        let other = make_addr(0x02);
        let hand = make_hand(
            GamePhase::Preflop,
            20, // == big_blind_amount
            0,
            0,
            100,
            &[(bb, true, false), (other, false, false)],
        );
        let input = ForceAdvanceInput::new(other, 110); // 超时玩家不是 BB

        let action = force_advance_action(&hand, &input, DEFAULT_TIMEOUT_BLOCKS).unwrap();
        assert_eq!(action, GameAction::Fold, "非 BB 超时 应 fold");
    }

    #[test]
    fn test_force_advance_preflop_bb_fold_when_raise_count_positive() {
        // preflop, current_bet == big_blind_amount 但 raise_count > 0 → fold
        // （理论上 raise 后 current_bet 应增加，此处测试边界条件防御）
        let bb = make_addr(0x01);
        let hand = make_hand(
            GamePhase::Preflop,
            20, // == big_blind_amount
            1,  // raise_count > 0
            0,
            100,
            &[(bb, true, false)],
        );
        let input = ForceAdvanceInput::new(bb, 110);

        let action = force_advance_action(&hand, &input, DEFAULT_TIMEOUT_BLOCKS).unwrap();
        assert_eq!(action, GameAction::Fold, "raise_count > 0 应 fold");
    }

    // ===== postflop 分支测试（SEC2-L5 修复 2）=====

    #[test]
    fn test_force_advance_postflop_check_no_bet() {
        // postflop, current_bet == 0, bet_count == 0 → check（任意玩家）
        let p1 = make_addr(0x01);
        let hand = make_hand(
            GamePhase::Flop,
            0, // current_bet == 0
            0,
            0, // bet_count == 0
            100,
            &[(p1, false, false)],
        );
        let input = ForceAdvanceInput::new(p1, 110);

        let action = force_advance_action(&hand, &input, DEFAULT_TIMEOUT_BLOCKS).unwrap();
        assert_eq!(action, GameAction::Check, "postflop 无人下注应 check");
    }

    #[test]
    fn test_force_advance_postflop_check_any_player() {
        // postflop, 无人下注，任意超时玩家（不仅限 BB）→ check
        let p1 = make_addr(0x01);
        let p2 = make_addr(0x02);
        let hand = make_hand(
            GamePhase::Turn,
            0,
            0,
            0,
            100,
            &[(p1, true, false), (p2, false, false)],
        );
        let input = ForceAdvanceInput::new(p2, 110); // p2 不是 BB

        let action = force_advance_action(&hand, &input, DEFAULT_TIMEOUT_BLOCKS).unwrap();
        assert_eq!(
            action,
            GameAction::Check,
            "postflop 无人下注，任意玩家超时应 check"
        );
    }

    #[test]
    fn test_force_advance_postflop_fold_when_bet() {
        // postflop, current_bet > 0 → fold
        let p1 = make_addr(0x01);
        let hand = make_hand(
            GamePhase::Flop,
            50, // current_bet > 0
            0,
            1, // bet_count > 0
            100,
            &[(p1, false, false)],
        );
        let input = ForceAdvanceInput::new(p1, 110);

        let action = force_advance_action(&hand, &input, DEFAULT_TIMEOUT_BLOCKS).unwrap();
        assert_eq!(action, GameAction::Fold, "postflop 有人下注应 fold");
    }

    #[test]
    fn test_force_advance_postflop_fold_when_bet_count_positive() {
        // postflop, current_bet == 0 但 bet_count > 0 → fold（防御边界）
        let p1 = make_addr(0x01);
        let hand = make_hand(
            GamePhase::Flop,
            0,
            0,
            1, // bet_count > 0
            100,
            &[(p1, false, false)],
        );
        let input = ForceAdvanceInput::new(p1, 110);

        let action = force_advance_action(&hand, &input, DEFAULT_TIMEOUT_BLOCKS).unwrap();
        assert_eq!(action, GameAction::Fold, "bet_count > 0 应 fold");
    }

    #[test]
    fn test_force_advance_river_postflop_check() {
        // River 阶段也属于 postflop
        let p1 = make_addr(0x01);
        let hand = make_hand(GamePhase::River, 0, 0, 0, 100, &[(p1, false, false)]);
        let input = ForceAdvanceInput::new(p1, 110);

        let action = force_advance_action(&hand, &input, DEFAULT_TIMEOUT_BLOCKS).unwrap();
        assert_eq!(action, GameAction::Check, "River 无人下注应 check");
    }

    // ===== 错误场景测试 =====

    #[test]
    fn test_force_advance_player_not_in_game() {
        let p1 = make_addr(0x01);
        let hand = make_hand(GamePhase::Preflop, 20, 0, 0, 100, &[(p1, true, false)]);
        let unknown = make_addr(0xff);
        let input = ForceAdvanceInput::new(unknown, 110);

        let result = force_advance_action(&hand, &input, DEFAULT_TIMEOUT_BLOCKS);
        assert!(matches!(result, Err(ForceAdvanceError::PlayerNotInGame(_))));
    }

    #[test]
    fn test_force_advance_player_already_folded() {
        let p1 = make_addr(0x01);
        let hand = make_hand(
            GamePhase::Preflop,
            20,
            0,
            0,
            100,
            &[(p1, true, true)], // 已 fold
        );
        let input = ForceAdvanceInput::new(p1, 110);

        let result = force_advance_action(&hand, &input, DEFAULT_TIMEOUT_BLOCKS);
        assert!(matches!(
            result,
            Err(ForceAdvanceError::PlayerAlreadyFolded(_))
        ));
    }

    #[test]
    fn test_force_advance_not_timed_out() {
        let p1 = make_addr(0x01);
        let hand = make_hand(GamePhase::Preflop, 20, 0, 0, 100, &[(p1, true, false)]);
        // elapsed = 105 - 100 = 5 < 10 → 未超时
        let input = ForceAdvanceInput::new(p1, 105);

        let result = force_advance_action(&hand, &input, DEFAULT_TIMEOUT_BLOCKS);
        assert!(matches!(
            result,
            Err(ForceAdvanceError::NotTimedOut {
                elapsed: 5,
                timeout: 10
            })
        ));
    }

    #[test]
    fn test_force_advance_hand_already_settled() {
        let p1 = make_addr(0x01);
        let hand = make_hand(GamePhase::Settled, 0, 0, 0, 100, &[(p1, true, false)]);
        let input = ForceAdvanceInput::new(p1, 110);

        let result = force_advance_action(&hand, &input, DEFAULT_TIMEOUT_BLOCKS);
        assert!(matches!(result, Err(ForceAdvanceError::HandAlreadySettled)));
    }

    // ===== 边界条件测试 =====

    #[test]
    fn test_force_advance_exact_timeout_boundary() {
        // elapsed == timeout_blocks（边界，恰好超时）
        let bb = make_addr(0x01);
        let hand = make_hand(GamePhase::Preflop, 20, 0, 0, 100, &[(bb, true, false)]);
        let input = ForceAdvanceInput::new(bb, 110); // elapsed = 10 == timeout

        let result = force_advance_action(&hand, &input, DEFAULT_TIMEOUT_BLOCKS);
        assert!(result.is_ok(), "恰好超时应允许 force_advance");
    }

    #[test]
    fn test_force_advance_one_block_past_timeout() {
        // elapsed = timeout + 1（超过超时阈值）
        let bb = make_addr(0x01);
        let hand = make_hand(GamePhase::Preflop, 20, 0, 0, 100, &[(bb, true, false)]);
        let input = ForceAdvanceInput::new(bb, 111); // elapsed = 11 > 10

        let result = force_advance_action(&hand, &input, DEFAULT_TIMEOUT_BLOCKS);
        assert!(result.is_ok());
    }

    #[test]
    fn test_force_advance_one_block_before_timeout() {
        // elapsed = timeout - 1（未到超时阈值）
        let bb = make_addr(0x01);
        let hand = make_hand(GamePhase::Preflop, 20, 0, 0, 100, &[(bb, true, false)]);
        let input = ForceAdvanceInput::new(bb, 109); // elapsed = 9 < 10

        let result = force_advance_action(&hand, &input, DEFAULT_TIMEOUT_BLOCKS);
        assert!(matches!(result, Err(ForceAdvanceError::NotTimedOut { .. })));
    }

    #[test]
    fn test_force_advance_zero_timeout_blocks() {
        // turn_timeout_blocks = 0（立即超时）
        let bb = make_addr(0x01);
        let hand = make_hand(GamePhase::Preflop, 20, 0, 0, 100, &[(bb, true, false)]);
        let input = ForceAdvanceInput::new(bb, 100); // elapsed = 0

        let result = force_advance_action(&hand, &input, 0);
        assert!(result.is_ok(), "timeout=0 时立即超时");
    }

    // ===== apply_force_advance 测试（SubTask 28.2）=====

    fn make_game_with_hand(
        phase: GamePhase,
        current_bet: u64,
        raise_count: u32,
        bet_count: u32,
        last_action_height: u64,
        players: &[(Address, bool, bool)],
    ) -> GameContract {
        let hand = make_hand(
            phase,
            current_bet,
            raise_count,
            bet_count,
            last_action_height,
            players,
        );
        let mut game = GameContract::new(
            ObjectID::new([0x42; 20], 1),
            make_addr(0x01),
            crate::signature::TaggedPubkey {
                tag: 0x01,
                raw: vec![0xFF; 33],
            },
            ExecutionMode::OffChain,
            RakeConfigRef {
                rake_rate_bps: 0,
                rake_cap: 0,
                rake_recipient: make_addr(0x00),
            },
            DEFAULT_TIMEOUT_BLOCKS,
        );
        game.last_action_height = last_action_height;
        game.current_hand = Some(hand);
        game
    }

    #[test]
    fn test_apply_force_advance_fold_marks_player_folded() {
        // preflop 有人 raise → fold → 玩家被标记 folded
        let bb = make_addr(0x01);
        let other = make_addr(0x02);
        let mut game = make_game_with_hand(
            GamePhase::Preflop,
            40, // > big_blind_amount
            1,  // raise_count > 0
            0,
            100,
            &[(bb, true, false), (other, false, false)],
        );
        let input = ForceAdvanceInput::new(bb, 110);

        let action = apply_force_advance(&mut game, &input).expect("应成功");
        assert_eq!(action, GameAction::Fold);

        let hand = game.current_hand.as_ref().expect("手牌应存在");
        let bb_idx = hand.find_player(&bb).expect("BB 应存在");
        assert!(hand.players[bb_idx].folded, "BB 应被标记 folded");
    }

    #[test]
    fn test_apply_force_advance_check_no_chip_change() {
        // postflop 无人下注 → check → 玩家筹码不变
        let p1 = make_addr(0x01);
        let mut game = make_game_with_hand(GamePhase::Flop, 0, 0, 0, 100, &[(p1, false, false)]);
        let input = ForceAdvanceInput::new(p1, 110);

        let action = apply_force_advance(&mut game, &input).expect("应成功");
        assert_eq!(action, GameAction::Check);

        let hand = game.current_hand.as_ref().expect("手牌应存在");
        let p1_idx = hand.find_player(&p1).expect("p1 应存在");
        assert!(!hand.players[p1_idx].folded, "check 不应 fold");
    }

    #[test]
    fn test_apply_force_advance_updates_last_action_height() {
        // R5-L1：last_action_height 更新（hand 级 + game 级）
        let bb = make_addr(0x01);
        let mut game = make_game_with_hand(GamePhase::Preflop, 20, 0, 0, 100, &[(bb, true, false)]);
        let input = ForceAdvanceInput::new(bb, 120);

        apply_force_advance(&mut game, &input).expect("应成功");

        assert_eq!(
            game.last_action_height, 120,
            "game.last_action_height 应更新"
        );
        let hand = game.current_hand.as_ref().expect("手牌应存在");
        assert_eq!(
            hand.last_action_height, 120,
            "hand.last_action_height 应更新"
        );
    }

    #[test]
    fn test_apply_force_advance_advances_current_turn() {
        // fold 后 current_turn 推进到下一个未 fold 玩家
        let p1 = make_addr(0x01);
        let p2 = make_addr(0x02);
        let mut game = make_game_with_hand(
            GamePhase::Preflop,
            40,
            1,
            0,
            100,
            &[(p1, true, false), (p2, false, false)],
        );
        let input = ForceAdvanceInput::new(p1, 110);

        apply_force_advance(&mut game, &input).expect("应成功");

        let hand = game.current_hand.as_ref().expect("手牌应存在");
        assert_eq!(hand.current_turn, p2, "current_turn 应推进到 p2");
    }

    #[test]
    fn test_apply_force_advance_increments_version() {
        let bb = make_addr(0x01);
        let mut game = make_game_with_hand(GamePhase::Preflop, 20, 0, 0, 100, &[(bb, true, false)]);
        let old_version = game.version;
        let input = ForceAdvanceInput::new(bb, 110);

        apply_force_advance(&mut game, &input).expect("应成功");
        assert_eq!(game.version, old_version + 1, "version 应递增");
    }

    #[test]
    fn test_apply_force_advance_natural_frequency_limit() {
        // R5-L1：第一次 force_advance 后 last_action_height 更新，
        // 第二次须再等 turn_timeout_blocks 个 block
        let bb = make_addr(0x01);
        let mut game = make_game_with_hand(GamePhase::Preflop, 20, 0, 0, 100, &[(bb, true, false)]);

        // 第一次：block 110，elapsed = 10 == timeout → 成功
        let input1 = ForceAdvanceInput::new(bb, 110);
        apply_force_advance(&mut game, &input1).expect("第一次应成功");
        assert_eq!(game.last_action_height, 110);

        // 恢复玩家 fold 状态（模拟下一轮）
        if let Some(hand) = game.current_hand.as_mut()
            && let Some(idx) = hand.find_player(&bb)
        {
            hand.players[idx].folded = false;
        }

        // 第二次：block 115，elapsed = 5 < 10 → 未超时，应失败
        let input2 = ForceAdvanceInput::new(bb, 115);
        let result = apply_force_advance(&mut game, &input2);
        assert!(
            matches!(result, Err(ForceAdvanceError::NotTimedOut { .. })),
            "R5-L1：第二次须等 turn_timeout_blocks 后才可触发"
        );

        // 第三次：block 120，elapsed = 10 == timeout → 成功
        let input3 = ForceAdvanceInput::new(bb, 120);
        apply_force_advance(&mut game, &input3).expect("第三次应成功");
    }

    #[test]
    fn test_apply_force_advance_no_hand_returns_error() {
        // current_hand = None → HandAlreadySettled
        let mut game = GameContract::new(
            ObjectID::new([0x42; 20], 1),
            make_addr(0x01),
            crate::signature::TaggedPubkey {
                tag: 0x01,
                raw: vec![0xFF; 33],
            },
            ExecutionMode::OffChain,
            RakeConfigRef {
                rake_rate_bps: 0,
                rake_cap: 0,
                rake_recipient: make_addr(0x00),
            },
            DEFAULT_TIMEOUT_BLOCKS,
        );
        let input = ForceAdvanceInput::new(make_addr(0x01), 110);

        let result = apply_force_advance(&mut game, &input);
        assert!(matches!(result, Err(ForceAdvanceError::HandAlreadySettled)));
    }
}
