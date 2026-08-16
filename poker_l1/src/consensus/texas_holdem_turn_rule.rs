//! Texas Hold'em 完整轮转规则（Phase 2 Task 4）。
//!
//! 实现完整扑克协议的 [`TurnRule`]，覆盖下注阶段（Betting）与多玩家提交阶段
//! （Shuffle / RevealToken / Reconstruct / LeaveProof）。
//!
//! ## 阶段状态机
//!
//! ```text
//! Betting ──(advance_phase: Err)──X
//!
//! Shuffle ──(advance_phase)──→ RevealToken ──(advance_phase)──→ Betting { Preflop }
//!
//! Reconstruct ──(advance_phase)──→ Betting { Preflop }（继续游戏）
//!
//! LeaveProof ──(advance_phase)──→ LeaveProof（保持当前阶段，leave 是被动行为）
//! ```
//!
//! ## 提交者集合规则
//!
//! | 子阶段 | current_submitters() |
//! |--------|---------------------|
//! | Betting | 空集合 |
//! | Shuffle | active_participants |
//! | RevealToken | pending_submitters（密钥持有者） |
//! | Reconstruct | active_participants |
//! | LeaveProof | active_participants |
//!
//! ## 设计决策
//!
//! - `current_turn()` 在 Betting 阶段复用 [`SimpleTurnRule`] 逻辑（按 active_participants 顺序轮转）；
//!   MultiPlayerSubmit 阶段返回 `None`
//! - `advance_phase()` 默认路径：Shuffle → RevealToken → Betting；
//!   Reconstruct → Betting；LeaveProof 保持不变
//! - 阶段切换时重置 `pending_submitters`（设为新阶段的合法提交者集合）、
//!   `completed_submitters`（清空）、`phase_started_height`（设为 `last_action_height + 1`）
//! - RevealToken 阶段的 `pending_submitters` 默认设为 `active_participants`，
//!   合约层可在进入阶段后收缩为实际密钥持有者集合

use std::collections::BTreeSet;

use crate::Address;
use crate::consensus::routing::{
    BettingRound, GamePhase, GameStatus, PhaseTransitionError, SimpleTurnRule, SubmitPhaseKind,
    TurnRule,
};

/// Texas Hold'em 完整轮转规则。
///
/// 覆盖下注阶段与多玩家提交阶段的完整状态机。
/// 下注阶段行为复用 [`SimpleTurnRule`]，多玩家阶段按子阶段类型计算提交者集合。
#[derive(Debug, Clone, Copy, Default)]
pub struct TexasHoldemTurnRule;

impl TexasHoldemTurnRule {
    /// 创建新的 Texas Hold'em 轮转规则。
    pub const fn new() -> Self {
        Self
    }

    /// 计算指定阶段的合法提交者集合（内部辅助方法）。
    ///
    /// 用于 `advance_phase` 切换到新阶段时重置 `pending_submitters`。
    fn compute_submitters_for_phase(phase: GamePhase, game: &GameStatus) -> BTreeSet<Address> {
        match phase {
            GamePhase::Betting { .. } => BTreeSet::new(),
            GamePhase::MultiPlayerSubmit { kind } => match kind {
                SubmitPhaseKind::Shuffle
                | SubmitPhaseKind::Reconstruct
                | SubmitPhaseKind::LeaveProof => game.active_participants.clone(),
                // RevealToken：默认使用 active_participants，合约层可后续收缩为密钥持有者
                SubmitPhaseKind::RevealToken => game.active_participants.clone(),
            },
        }
    }
}

impl TurnRule for TexasHoldemTurnRule {
    fn current_turn(&self, game: &GameStatus) -> Option<Address> {
        // 多玩家阶段无单一 current_turn
        if game.phase.is_multi_player_submit() {
            return None;
        }
        // Betting 阶段复用 SimpleTurnRule 逻辑
        SimpleTurnRule.current_turn(game)
    }

    fn advance_turn(&self, game: &mut GameStatus) -> Option<Address> {
        // 多玩家阶段不推进 current_turn
        if game.phase.is_multi_player_submit() {
            return None;
        }
        // Betting 阶段复用 SimpleTurnRule 逻辑
        SimpleTurnRule.advance_turn(game)
    }

    fn current_submitters(&self, game: &GameStatus) -> BTreeSet<Address> {
        match game.phase {
            GamePhase::Betting { .. } => BTreeSet::new(),
            GamePhase::MultiPlayerSubmit { kind } => match kind {
                SubmitPhaseKind::Shuffle
                | SubmitPhaseKind::Reconstruct
                | SubmitPhaseKind::LeaveProof => game.active_participants.clone(),
                // RevealToken：返回 pending_submitters 副本（密钥持有者已在 pending 中）
                SubmitPhaseKind::RevealToken => game.pending_submitters.clone(),
            },
        }
    }

    fn is_submission_complete(&self, game: &GameStatus) -> bool {
        match game.phase {
            GamePhase::Betting { .. } => true,
            GamePhase::MultiPlayerSubmit { .. } => game.pending_submitters.is_empty(),
        }
    }

    fn advance_phase(&self, game: &mut GameStatus) -> Result<GamePhase, PhaseTransitionError> {
        let current_phase = game.phase;

        // Betting 阶段不允许 advance_phase（应使用 advance_turn）
        if current_phase.is_betting() {
            return Err(PhaseTransitionError::InvalidPhaseTransition(current_phase));
        }

        // LeaveProof 保持当前阶段（leave 是被动行为，不触发阶段切换）
        if current_phase
            == (GamePhase::MultiPlayerSubmit {
                kind: SubmitPhaseKind::LeaveProof,
            })
        {
            return Ok(current_phase);
        }

        // 多玩家阶段切换前，pending_submitters 必须为空（所有提交者已完成）
        if !game.pending_submitters.is_empty() {
            return Err(PhaseTransitionError::PendingSubmittersNotEmpty(
                game.pending_submitters.len(),
            ));
        }

        // 计算下一阶段
        let new_phase = match current_phase {
            GamePhase::MultiPlayerSubmit {
                kind: SubmitPhaseKind::Shuffle,
            } => {
                // Shuffle → RevealToken（默认：有牌待揭）
                GamePhase::MultiPlayerSubmit {
                    kind: SubmitPhaseKind::RevealToken,
                }
            }
            GamePhase::MultiPlayerSubmit {
                kind: SubmitPhaseKind::RevealToken,
            } => {
                // RevealToken → Betting { Preflop }
                GamePhase::Betting {
                    round: BettingRound::Preflop,
                }
            }
            GamePhase::MultiPlayerSubmit {
                kind: SubmitPhaseKind::Reconstruct,
            } => {
                // Reconstruct → Betting { Preflop }（继续游戏）
                GamePhase::Betting {
                    round: BettingRound::Preflop,
                }
            }
            // LeaveProof 已在上面处理
            GamePhase::Betting { .. } | GamePhase::MultiPlayerSubmit { .. } => {
                return Err(PhaseTransitionError::InvalidPhaseTransition(current_phase));
            }
        };

        // 切换阶段并重置追踪字段
        game.phase = new_phase;
        game.completed_submitters.clear();
        game.phase_started_height = game.last_action_height + 1;
        // 重置 pending_submitters 为新阶段的合法提交者集合
        game.pending_submitters = Self::compute_submitters_for_phase(new_phase, game);

        Ok(new_phase)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::routing::{ExecutionMode, GameStatus};
    use crate::object_model::ObjectID;
    use crate::signature::TaggedPubkey;
    use crate::signature::tagged_pubkey::{SignatureScheme, encode_tag};
    use std::collections::{BTreeMap, BTreeSet};

    /// 构造测试用 tagged pubkey。
    fn make_tagged_pubkey(byte: u8) -> TaggedPubkey {
        TaggedPubkey {
            tag: encode_tag(SignatureScheme::Secp256k1, 1),
            raw: vec![byte; 33],
        }
    }

    /// 构造测试用 Game 状态，可选指定 phase。
    fn make_game(
        participants: &[u8],
        phase: GamePhase,
        pending: &[u8],
    ) -> (GameStatus, Vec<Address>) {
        let assigned_tp = make_tagged_pubkey(0x01);
        let mut active = BTreeSet::new();
        let mut addrs = Vec::new();
        for &b in participants {
            let a = [b; 20];
            active.insert(a);
            addrs.push(a);
        }
        let mut pending_set = BTreeSet::new();
        for &b in pending {
            pending_set.insert([b; 20]);
        }
        let game = GameStatus {
            id: ObjectID::new([0xAA; 20], 1),
            assigned_validator: assigned_tp,
            current_turn_player: [participants[0]; 20],
            active_participants: active,
            player_nonce: BTreeMap::new(),
            last_action_height: 100,
            hand_start_height: 90,
            execution_mode: ExecutionMode::OnChain,
            is_finalized: false,
            phase,
            pending_submitters: pending_set,
            phase_started_height: 0,
            completed_submitters: BTreeSet::new(),
        };
        (game, addrs)
    }

    // ===== current_turn 测试 =====

    #[test]
    fn current_turn_returns_player_in_betting_phase() {
        let (game, addrs) = make_game(
            &[0x10, 0x20, 0x30],
            GamePhase::Betting {
                round: BettingRound::Preflop,
            },
            &[],
        );
        let rule = TexasHoldemTurnRule::new();
        assert_eq!(rule.current_turn(&game), Some(addrs[0]));
    }

    #[test]
    fn current_turn_returns_none_in_shuffle_phase() {
        let (game, _) = make_game(
            &[0x10, 0x20, 0x30],
            GamePhase::MultiPlayerSubmit {
                kind: SubmitPhaseKind::Shuffle,
            },
            &[],
        );
        let rule = TexasHoldemTurnRule::new();
        assert_eq!(rule.current_turn(&game), None);
    }

    #[test]
    fn current_turn_returns_none_in_reveal_token_phase() {
        let (game, _) = make_game(
            &[0x10, 0x20],
            GamePhase::MultiPlayerSubmit {
                kind: SubmitPhaseKind::RevealToken,
            },
            &[0x10],
        );
        let rule = TexasHoldemTurnRule::new();
        assert_eq!(rule.current_turn(&game), None);
    }

    // ===== advance_turn 测试 =====

    #[test]
    fn advance_turn_rotates_in_betting_phase() {
        let (mut game, addrs) = make_game(
            &[0x10, 0x20, 0x30],
            GamePhase::Betting {
                round: BettingRound::Preflop,
            },
            &[],
        );
        let rule = TexasHoldemTurnRule::new();
        assert_eq!(rule.advance_turn(&mut game), Some(addrs[1]));
        assert_eq!(rule.advance_turn(&mut game), Some(addrs[2]));
        assert_eq!(rule.advance_turn(&mut game), Some(addrs[0]));
    }

    #[test]
    fn advance_turn_returns_none_in_multi_player_phase() {
        let (mut game, _) = make_game(
            &[0x10, 0x20],
            GamePhase::MultiPlayerSubmit {
                kind: SubmitPhaseKind::Shuffle,
            },
            &[0x10, 0x20],
        );
        let rule = TexasHoldemTurnRule::new();
        assert_eq!(rule.advance_turn(&mut game), None);
    }

    // ===== current_submitters 测试 =====

    #[test]
    fn current_submitters_empty_in_betting_phase() {
        let (game, _) = make_game(
            &[0x10, 0x20, 0x30],
            GamePhase::Betting {
                round: BettingRound::Preflop,
            },
            &[],
        );
        let rule = TexasHoldemTurnRule::new();
        assert!(rule.current_submitters(&game).is_empty());
    }

    #[test]
    fn current_submitters_returns_active_in_shuffle_phase() {
        let (game, _) = make_game(
            &[0x10, 0x20, 0x30],
            GamePhase::MultiPlayerSubmit {
                kind: SubmitPhaseKind::Shuffle,
            },
            &[],
        );
        let rule = TexasHoldemTurnRule::new();
        let submitters = rule.current_submitters(&game);
        assert_eq!(submitters.len(), 3);
        assert!(submitters.contains(&[0x10; 20]));
        assert!(submitters.contains(&[0x20; 20]));
        assert!(submitters.contains(&[0x30; 20]));
    }

    #[test]
    fn current_submitters_returns_pending_in_reveal_token_phase() {
        let (game, _) = make_game(
            &[0x10, 0x20, 0x30],
            GamePhase::MultiPlayerSubmit {
                kind: SubmitPhaseKind::RevealToken,
            },
            &[0x10, 0x20], // pending = 密钥持有者
        );
        let rule = TexasHoldemTurnRule::new();
        let submitters = rule.current_submitters(&game);
        assert_eq!(submitters.len(), 2);
        assert!(submitters.contains(&[0x10; 20]));
        assert!(submitters.contains(&[0x20; 20]));
        assert!(!submitters.contains(&[0x30; 20]));
    }

    #[test]
    fn current_submitters_returns_active_in_reconstruct_phase() {
        let (game, _) = make_game(
            &[0x10, 0x20],
            GamePhase::MultiPlayerSubmit {
                kind: SubmitPhaseKind::Reconstruct,
            },
            &[],
        );
        let rule = TexasHoldemTurnRule::new();
        let submitters = rule.current_submitters(&game);
        assert_eq!(submitters.len(), 2);
    }

    #[test]
    fn current_submitters_returns_active_in_leave_proof_phase() {
        let (game, _) = make_game(
            &[0x10, 0x20, 0x30],
            GamePhase::MultiPlayerSubmit {
                kind: SubmitPhaseKind::LeaveProof,
            },
            &[],
        );
        let rule = TexasHoldemTurnRule::new();
        let submitters = rule.current_submitters(&game);
        assert_eq!(submitters.len(), 3);
    }

    // ===== is_submission_complete 测试 =====

    #[test]
    fn is_submission_complete_true_in_betting_phase() {
        let (game, _) = make_game(
            &[0x10, 0x20],
            GamePhase::Betting {
                round: BettingRound::Preflop,
            },
            &[],
        );
        let rule = TexasHoldemTurnRule::new();
        assert!(rule.is_submission_complete(&game));
    }

    #[test]
    fn is_submission_complete_false_when_pending_non_empty() {
        let (game, _) = make_game(
            &[0x10, 0x20],
            GamePhase::MultiPlayerSubmit {
                kind: SubmitPhaseKind::Shuffle,
            },
            &[0x10], // pending 非空
        );
        let rule = TexasHoldemTurnRule::new();
        assert!(!rule.is_submission_complete(&game));
    }

    #[test]
    fn is_submission_complete_true_when_pending_empty() {
        let (game, _) = make_game(
            &[0x10, 0x20],
            GamePhase::MultiPlayerSubmit {
                kind: SubmitPhaseKind::Shuffle,
            },
            &[], // pending 为空
        );
        let rule = TexasHoldemTurnRule::new();
        assert!(rule.is_submission_complete(&game));
    }

    // ===== advance_phase 状态机测试 =====

    #[test]
    fn advance_phase_rejects_betting_phase() {
        let (mut game, _) = make_game(
            &[0x10, 0x20],
            GamePhase::Betting {
                round: BettingRound::Preflop,
            },
            &[],
        );
        let rule = TexasHoldemTurnRule::new();
        let err = rule.advance_phase(&mut game).unwrap_err();
        assert_eq!(
            err,
            PhaseTransitionError::InvalidPhaseTransition(GamePhase::Betting {
                round: BettingRound::Preflop
            })
        );
    }

    #[test]
    fn advance_phase_rejects_when_pending_non_empty() {
        let (mut game, _) = make_game(
            &[0x10, 0x20],
            GamePhase::MultiPlayerSubmit {
                kind: SubmitPhaseKind::Shuffle,
            },
            &[0x10], // pending 非空
        );
        let rule = TexasHoldemTurnRule::new();
        let err = rule.advance_phase(&mut game).unwrap_err();
        assert_eq!(err, PhaseTransitionError::PendingSubmittersNotEmpty(1));
    }

    #[test]
    fn advance_phase_shuffle_to_reveal_token() {
        let (mut game, _) = make_game(
            &[0x10, 0x20, 0x30],
            GamePhase::MultiPlayerSubmit {
                kind: SubmitPhaseKind::Shuffle,
            },
            &[], // pending 为空
        );
        let rule = TexasHoldemTurnRule::new();
        let new_phase = rule.advance_phase(&mut game).unwrap();
        assert_eq!(
            new_phase,
            GamePhase::MultiPlayerSubmit {
                kind: SubmitPhaseKind::RevealToken
            }
        );
        assert_eq!(game.phase, new_phase);
        // pending_submitters 重置为 active_participants
        assert_eq!(game.pending_submitters.len(), 3);
        // completed_submitters 清空
        assert!(game.completed_submitters.is_empty());
        // phase_started_height = last_action_height + 1
        assert_eq!(game.phase_started_height, 101);
    }

    #[test]
    fn advance_phase_reveal_token_to_betting() {
        let (mut game, _) = make_game(
            &[0x10, 0x20],
            GamePhase::MultiPlayerSubmit {
                kind: SubmitPhaseKind::RevealToken,
            },
            &[], // pending 为空
        );
        let rule = TexasHoldemTurnRule::new();
        let new_phase = rule.advance_phase(&mut game).unwrap();
        assert_eq!(
            new_phase,
            GamePhase::Betting {
                round: BettingRound::Preflop
            }
        );
        assert_eq!(game.phase, new_phase);
        // Betting 阶段 pending_submitters 为空
        assert!(game.pending_submitters.is_empty());
        assert!(game.completed_submitters.is_empty());
        assert_eq!(game.phase_started_height, 101);
    }

    #[test]
    fn advance_phase_reconstruct_to_betting() {
        let (mut game, _) = make_game(
            &[0x10, 0x20],
            GamePhase::MultiPlayerSubmit {
                kind: SubmitPhaseKind::Reconstruct,
            },
            &[], // pending 为空
        );
        let rule = TexasHoldemTurnRule::new();
        let new_phase = rule.advance_phase(&mut game).unwrap();
        assert_eq!(
            new_phase,
            GamePhase::Betting {
                round: BettingRound::Preflop
            }
        );
        assert_eq!(game.phase, new_phase);
        assert!(game.pending_submitters.is_empty());
    }

    #[test]
    fn advance_phase_leave_proof_keeps_current_phase() {
        let (mut game, _) = make_game(
            &[0x10, 0x20],
            GamePhase::MultiPlayerSubmit {
                kind: SubmitPhaseKind::LeaveProof,
            },
            &[0x10], // pending 非空，但 LeaveProof 不检查
        );
        let rule = TexasHoldemTurnRule::new();
        let result = rule.advance_phase(&mut game).unwrap();
        // LeaveProof 保持当前阶段
        assert_eq!(
            result,
            GamePhase::MultiPlayerSubmit {
                kind: SubmitPhaseKind::LeaveProof
            }
        );
        assert_eq!(game.phase, result);
        // 字段不变
        assert_eq!(game.pending_submitters.len(), 1);
    }

    // ===== 完整状态机流程测试 =====

    #[test]
    fn full_state_machine_shuffle_reveal_betting() {
        let (mut game, _) = make_game(
            &[0x10, 0x20],
            GamePhase::MultiPlayerSubmit {
                kind: SubmitPhaseKind::Shuffle,
            },
            &[], // pending 为空（所有玩家已完成 shuffle）
        );
        let rule = TexasHoldemTurnRule::new();

        // Shuffle → RevealToken
        let p1 = rule.advance_phase(&mut game).unwrap();
        assert_eq!(
            p1,
            GamePhase::MultiPlayerSubmit {
                kind: SubmitPhaseKind::RevealToken
            }
        );
        // 模拟所有 reveal token 提交完成
        game.pending_submitters.clear();

        // RevealToken → Betting { Preflop }
        let p2 = rule.advance_phase(&mut game).unwrap();
        assert_eq!(
            p2,
            GamePhase::Betting {
                round: BettingRound::Preflop
            }
        );
        // Betting 阶段可用 current_turn / advance_turn
        assert!(rule.current_turn(&game).is_some());
    }
}
