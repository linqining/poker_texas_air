//! Phase 6 端到端集成测试（Task 11 — SubTask 11.1~11.4）
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）+ tasks.md Task 11：
//! - **SubTask 11.1**：完整一手牌流程（Betting → Shuffle → RevealToken → Betting）
//! - **SubTask 11.2**：多玩家阶段超时恢复（Shuffle 超时 → kick → 继续 / finalize）
//! - **SubTask 11.3**：LeaveProof 随时提交（Betting 阶段 + MultiPlayerSubmit 阶段）
//! - **SubTask 11.4**：跨 commit 排序（build_game_sub_block + check_sech6_cross_commit_force_advance）
//!
//! 集成测试使用 `poker_l1` crate 公共 API（`use poker_l1::...`），不修改 lib 内部代码。
//! 覆盖 spec Phase 1-5 实现的端到端协作流程。

use std::collections::{BTreeMap, BTreeSet};

use poker_l1::account::derive_address;
use poker_l1::block::{TimeConsensusConfig, is_submit_phase_timed_out};
use poker_l1::consensus::{
    BettingRound, ExecutionMode, GamePhase, GameStatus, PhaseTransitionError, SimpleTurnRule,
    SubmitPhaseKind, TexasHoldemTurnRule, TurnRule, build_game_sub_block,
    check_sech6_cross_commit_force_advance, handle_submit_phase_timeout,
    validate_game_turn_phase_aware,
};
use poker_l1::error::PokerL1Error;
use poker_l1::object_model::ObjectID;
use poker_l1::signature::TaggedPubkey;
use poker_l1::signature::tagged_pubkey::{SignatureScheme, encode_tag};
use poker_l1::transaction::{Gas, RouteHint, Transaction, TxLane};
use poker_l1::{Address, BlockHeight, DEFAULT_CHAIN_ID};

// ===== 测试辅助函数 =====

/// 构造测试用 tagged pubkey（secp256k1 v1，raw 用单字节填充）。
fn make_tagged_pubkey(byte: u8) -> TaggedPubkey {
    TaggedPubkey {
        tag: encode_tag(SignatureScheme::Secp256k1, 1),
        raw: vec![byte; 33],
    }
}

/// 用单字节生成 20 字节地址（测试用，便于可读性）。
fn addr(b: u8) -> Address {
    [b; 20]
}

/// 构造测试用 GameStatus，可指定 phase / pending_submitters / active_participants。
fn make_game(
    participants: &[u8],
    phase: GamePhase,
    pending: &[u8],
    phase_started_height: BlockHeight,
) -> GameStatus {
    let assigned_tp = make_tagged_pubkey(0x01);
    let mut active = BTreeSet::new();
    for &b in participants {
        active.insert(addr(b));
    }
    let mut pending_set = BTreeSet::new();
    for &b in pending {
        pending_set.insert(addr(b));
    }
    let current_turn = participants.first().copied().unwrap_or(0x10);
    GameStatus {
        id: ObjectID::new([0xAA; 20], 1),
        assigned_validator: assigned_tp,
        current_turn_player: addr(current_turn),
        active_participants: active,
        player_nonce: BTreeMap::new(),
        last_action_height: 100,
        hand_start_height: 90,
        execution_mode: ExecutionMode::OnChain,
        is_finalized: false,
        phase,
        pending_submitters: pending_set,
        phase_started_height,
        completed_submitters: BTreeSet::new(),
    }
}

/// 构造 GameTurn 通道 tx（免 gas，AssignedValidator 路由）。
/// `actor_byte` 用于填充 tagged_pubkey.raw[0]，便于通过 derive_address 派生地址。
fn make_gameturn_tx(actor_byte: u8, gameturn_nonce: u64) -> Transaction {
    Transaction {
        inputs: vec![],
        outputs: vec![],
        contract_call: None,
        tagged_pubkey: make_tagged_pubkey(actor_byte),
        signature: vec![0u8; 65],
        gas: Gas::zero(),
        lane_hint: TxLane::GameTurn,
        route_hint: RouteHint::AssignedValidator,
        chain_id: DEFAULT_CHAIN_ID,
        nonce: 0,
        gameturn_nonce: Some(gameturn_nonce),
        is_fallback: false,
    }
}

/// 构造 Public 通道 tx（非零 gas，AnyValidator 路由）。
fn make_public_tx(nonce: u64) -> Transaction {
    Transaction {
        inputs: vec![],
        outputs: vec![],
        contract_call: None,
        tagged_pubkey: make_tagged_pubkey(0x02),
        signature: vec![0u8; 65],
        gas: Gas::new(1_000_000, 1),
        lane_hint: TxLane::Public,
        route_hint: RouteHint::AnyValidator,
        chain_id: DEFAULT_CHAIN_ID,
        nonce,
        gameturn_nonce: None,
        is_fallback: false,
    }
}

/// 构造 ForceSync 通道 tx（非零 gas，AnyValidator 路由）。
fn make_force_sync_tx(nonce: u64) -> Transaction {
    Transaction {
        inputs: vec![],
        outputs: vec![],
        contract_call: None,
        tagged_pubkey: make_tagged_pubkey(0x02),
        signature: vec![0u8; 65],
        gas: Gas::new(1_000_000, 1),
        lane_hint: TxLane::ForceSync,
        route_hint: RouteHint::AnyValidator,
        chain_id: DEFAULT_CHAIN_ID,
        nonce,
        gameturn_nonce: None,
        is_fallback: false,
    }
}

// ===== SubTask 11.1: 完整一手牌流程测试 =====
//
// 场景：3 玩家 A(0x10)/B(0x20)/C(0x30)，验证完整状态机：
// Betting{Preflop} → MultiPlayerSubmit{Shuffle} → MultiPlayerSubmit{RevealToken}
// → Betting{Preflop}（新手牌）→ ... → Betting{Showdown}

/// 完整一手牌流程：Betting → Shuffle → RevealToken → Betting。
/// 验证 TexasHoldemTurnRule 状态机端到端协作，含阶段切换与追踪字段重置。
#[test]
fn full_hand_flow_betting_shuffle_reveal_betting() {
    let rule = TexasHoldemTurnRule::new();
    // 初始：3 玩家，Betting{Preflop}，A(0x10) 当前轮次
    let mut game = make_game(
        &[0x10, 0x20, 0x30],
        GamePhase::Betting {
            round: BettingRound::Preflop,
        },
        &[],
        0,
    );

    // ===== Betting{Preflop} 阶段：单玩家轮转 =====
    // A 当前轮次
    assert_eq!(rule.current_turn(&game), Some(addr(0x10)));
    // A 下注 → advance_turn → B
    assert_eq!(rule.advance_turn(&mut game), Some(addr(0x20)));
    // B 跟注 → advance_turn → C
    assert_eq!(rule.advance_turn(&mut game), Some(addr(0x30)));
    // C 跟注 → advance_turn → A（循环）
    assert_eq!(rule.advance_turn(&mut game), Some(addr(0x10)));

    // 下注阶段调用 advance_phase 应返回 InvalidPhaseTransition
    let err = rule.advance_phase(&mut game).unwrap_err();
    assert_eq!(
        err,
        PhaseTransitionError::InvalidPhaseTransition(GamePhase::Betting {
            round: BettingRound::Preflop
        })
    );

    // ===== 切换到 MultiPlayerSubmit{Shuffle} 阶段 =====
    // 模拟合约层发起 shuffle：手动设置 phase + pending_submitters = active_participants
    game.phase = GamePhase::MultiPlayerSubmit {
        kind: SubmitPhaseKind::Shuffle,
    };
    game.pending_submitters = game.active_participants.clone();
    game.completed_submitters.clear();
    game.phase_started_height = game.last_action_height + 1;

    // 多玩家阶段 current_turn 返回 None
    assert_eq!(rule.current_turn(&game), None);
    // current_submitters 返回 active_participants
    let submitters = rule.current_submitters(&game);
    assert_eq!(submitters.len(), 3);
    // is_submission_complete = pending 非空 → false
    assert!(!rule.is_submission_complete(&game));

    // ===== A 提交 shuffle proof =====
    let tx_a = make_gameturn_tx(0x10, 1);
    validate_game_turn_phase_aware(&tx_a, &mut game, addr(0x10), &rule)
        .expect("A 在 pending_submitters 中，应通过");
    // A 从 pending 移除，插入 completed
    assert!(!game.pending_submitters.contains(&addr(0x10)));
    assert!(game.completed_submitters.contains(&addr(0x10)));
    // B/C 仍在 pending
    assert!(game.pending_submitters.contains(&addr(0x20)));
    assert!(game.pending_submitters.contains(&addr(0x30)));
    // 仍 incomplete
    assert!(!rule.is_submission_complete(&game));

    // ===== B 提交 shuffle proof =====
    let tx_b = make_gameturn_tx(0x20, 1);
    validate_game_turn_phase_aware(&tx_b, &mut game, addr(0x20), &rule)
        .expect("B 在 pending_submitters 中，应通过");
    assert!(!game.pending_submitters.contains(&addr(0x20)));
    assert!(game.completed_submitters.contains(&addr(0x20)));

    // ===== C 提交 shuffle proof =====
    let tx_c = make_gameturn_tx(0x30, 1);
    validate_game_turn_phase_aware(&tx_c, &mut game, addr(0x30), &rule)
        .expect("C 在 pending_submitters 中，应通过");
    // pending 清空 → is_submission_complete = true
    assert!(game.pending_submitters.is_empty());
    assert!(rule.is_submission_complete(&game));

    // ===== advance_phase: Shuffle → RevealToken =====
    let new_phase = rule
        .advance_phase(&mut game)
        .expect("Shuffle → RevealToken");
    assert_eq!(
        new_phase,
        GamePhase::MultiPlayerSubmit {
            kind: SubmitPhaseKind::RevealToken
        }
    );
    // 追踪字段重置：pending_submitters = active_participants（3 玩家）
    assert_eq!(game.pending_submitters.len(), 3);
    // completed_submitters 清空
    assert!(game.completed_submitters.is_empty());
    // phase_started_height = last_action_height + 1
    assert_eq!(game.phase_started_height, game.last_action_height + 1);

    // ===== RevealToken 阶段：所有玩家并行提交 reveal token =====
    assert_eq!(rule.current_turn(&game), None);
    // RevealToken 的 current_submitters 返回 pending_submitters
    assert_eq!(rule.current_submitters(&game).len(), 3);

    // A/B/C 依次提交 reveal token
    for byte in [0x10, 0x20, 0x30] {
        let tx = make_gameturn_tx(byte, 2);
        validate_game_turn_phase_aware(&tx, &mut game, addr(byte), &rule)
            .expect("RevealToken 阶段玩家应通过校验");
    }
    assert!(game.pending_submitters.is_empty());
    assert!(rule.is_submission_complete(&game));

    // ===== advance_phase: RevealToken → Betting{Preflop} =====
    let new_phase = rule
        .advance_phase(&mut game)
        .expect("RevealToken → Betting{Preflop}");
    assert_eq!(
        new_phase,
        GamePhase::Betting {
            round: BettingRound::Preflop
        }
    );
    // Betting 阶段 pending_submitters 为空
    assert!(game.pending_submitters.is_empty());
    assert!(game.completed_submitters.is_empty());
    // 回到下注阶段后 current_turn 可用
    assert!(rule.current_turn(&game).is_some());
    // 下注阶段 current_submitters 返回空集合
    assert!(rule.current_submitters(&game).is_empty());
    // 下注阶段 is_submission_complete 返回 true
    assert!(rule.is_submission_complete(&game));
}

/// 完整状态机：覆盖 Reconstruct → Betting 与 LeaveProof 保持当前阶段路径。
#[test]
fn full_hand_flow_reconstruct_and_leave_proof_phase_transitions() {
    let rule = TexasHoldemTurnRule::new();

    // ===== Reconstruct → Betting{Preflop} =====
    let mut game = make_game(
        &[0x10, 0x20],
        GamePhase::MultiPlayerSubmit {
            kind: SubmitPhaseKind::Reconstruct,
        },
        &[], // pending 已空
        500,
    );
    let new_phase = rule
        .advance_phase(&mut game)
        .expect("Reconstruct → Betting{Preflop}");
    assert_eq!(
        new_phase,
        GamePhase::Betting {
            round: BettingRound::Preflop
        }
    );
    assert!(game.pending_submitters.is_empty());
    assert_eq!(game.phase_started_height, game.last_action_height + 1);

    // ===== LeaveProof 保持当前阶段（不触发阶段切换） =====
    let mut game_lp = make_game(
        &[0x10, 0x20],
        GamePhase::MultiPlayerSubmit {
            kind: SubmitPhaseKind::LeaveProof,
        },
        &[0x10], // pending 非空，但 LeaveProof 不检查
        600,
    );
    let result = rule
        .advance_phase(&mut game_lp)
        .expect("LeaveProof 保持当前阶段");
    assert_eq!(
        result,
        GamePhase::MultiPlayerSubmit {
            kind: SubmitPhaseKind::LeaveProof
        }
    );
    // 字段不变
    assert_eq!(game_lp.pending_submitters.len(), 1);
}

/// 验证 advance_phase 在 pending 非空时拒绝切换。
#[test]
fn full_hand_flow_advance_phase_rejects_pending_non_empty() {
    let rule = TexasHoldemTurnRule::new();
    let mut game = make_game(
        &[0x10, 0x20, 0x30],
        GamePhase::MultiPlayerSubmit {
            kind: SubmitPhaseKind::Shuffle,
        },
        &[0x10, 0x20], // pending 非空
        0,
    );
    let err = rule.advance_phase(&mut game).unwrap_err();
    assert_eq!(err, PhaseTransitionError::PendingSubmittersNotEmpty(2));
}

// ===== SubTask 11.2: 多玩家阶段超时恢复测试 =====
//
// 场景：多玩家提交阶段超时 → handle_submit_phase_timeout kick pending_submitters
// → 若剩余 < 2 人则 finalize；若剩余 ≥ 2 人则游戏继续

/// 超时恢复：Shuffle 阶段超时，B/C 被 kick，仅剩 A → is_finalized=true。
#[test]
fn timeout_recovery_shuffle_kick_all_finalizes() {
    let config = TimeConsensusConfig::default();
    // 3 玩家，Shuffle 阶段，phase_started_height=1000
    // pending = {B, C}（A 已提交，不在 pending）
    let mut game = make_game(
        &[0x10, 0x20, 0x30],
        GamePhase::MultiPlayerSubmit {
            kind: SubmitPhaseKind::Shuffle,
        },
        &[0x20, 0x30],
        1000,
    );
    // A 在 completed 中（已提交）
    game.completed_submitters.insert(addr(0x10));

    // 边界：current=1100 不超时（shuffle_timeout_blocks=100，1000+100=1100，`>` 严格大于）
    assert_eq!(is_submit_phase_timed_out(&game, 1100, &config), None);
    // current=1101 超时
    assert_eq!(
        is_submit_phase_timed_out(&game, 1101, &config),
        Some(SubmitPhaseKind::Shuffle)
    );

    // 执行超时惩罚：kick pending 中的 B/C
    let results =
        handle_submit_phase_timeout(&mut game, SubmitPhaseKind::Shuffle, 1101, |player| {
            // 退款金额 = 玩家 total_bet（此处用地址首字节模拟）
            (player[0] as u64) * 10
        });

    // 2 个 KickResult（B=0x20, C=0x30，按 BTreeSet 升序）
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].player, addr(0x20));
    assert_eq!(results[0].refund_amount, 0x20 * 10); // 320
    assert_eq!(results[1].player, addr(0x30));
    assert_eq!(results[1].refund_amount, 0x30 * 10); // 480

    // B/C 从 active / pending / completed / player_nonce 移除
    assert!(!game.active_participants.contains(&addr(0x20)));
    assert!(!game.active_participants.contains(&addr(0x30)));
    assert!(game.pending_submitters.is_empty());
    // A 仍在 active（A 在 completed 中，未被 kick）
    assert!(game.active_participants.contains(&addr(0x10)));
    assert_eq!(game.active_participants.len(), 1);
    // 剩余 1 < 2 → finalize
    assert!(game.is_finalized);
}

/// 超时恢复：RevealToken 阶段超时，仅 kick 1 玩家，剩余 ≥ 2 人继续游戏。
#[test]
fn timeout_recovery_reveal_token_partial_kick_continues() {
    let config = TimeConsensusConfig::default();
    // 3 玩家，RevealToken 阶段，phase_started_height=2000
    // pending = {C}（A/B 已提交）
    let mut game = make_game(
        &[0x10, 0x20, 0x30],
        GamePhase::MultiPlayerSubmit {
            kind: SubmitPhaseKind::RevealToken,
        },
        &[0x30],
        2000,
    );
    game.completed_submitters.insert(addr(0x10));
    game.completed_submitters.insert(addr(0x20));

    // RevealToken 超时阈值 = 50：current > 2000+50=2050 → 超时
    assert_eq!(is_submit_phase_timed_out(&game, 2050, &config), None);
    assert_eq!(
        is_submit_phase_timed_out(&game, 2051, &config),
        Some(SubmitPhaseKind::RevealToken)
    );

    // 执行超时惩罚：仅 kick C
    let results =
        handle_submit_phase_timeout(&mut game, SubmitPhaseKind::RevealToken, 2051, |_| 1000);

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].player, addr(0x30));
    assert_eq!(results[0].refund_amount, 1000);

    // A/B 保留，C 移除
    assert!(game.active_participants.contains(&addr(0x10)));
    assert!(game.active_participants.contains(&addr(0x20)));
    assert!(!game.active_participants.contains(&addr(0x30)));
    assert_eq!(game.active_participants.len(), 2);
    // 剩余 2 >= 2 → 不 finalize，游戏继续
    assert!(!game.is_finalized);
    // pending 清空（可推进阶段）
    assert!(game.pending_submitters.is_empty());

    // 游戏继续：advance_phase RevealToken → Betting{Preflop}
    let rule = TexasHoldemTurnRule::new();
    let new_phase = rule
        .advance_phase(&mut game)
        .expect("RevealToken → Betting{Preflop}（剩余 2 人继续）");
    assert_eq!(
        new_phase,
        GamePhase::Betting {
            round: BettingRound::Preflop
        }
    );
}

/// 超时检测：LeaveProof 阶段永不超时；Betting 阶段不走此超时。
#[test]
fn timeout_detection_leave_proof_and_betting_never_timeout() {
    let config = TimeConsensusConfig::default();

    // LeaveProof 永不超时
    let game_lp = make_game(
        &[0x10, 0x20],
        GamePhase::MultiPlayerSubmit {
            kind: SubmitPhaseKind::LeaveProof,
        },
        &[0x10],
        1000,
    );
    assert_eq!(is_submit_phase_timed_out(&game_lp, 1000, &config), None);
    assert_eq!(is_submit_phase_timed_out(&game_lp, 100_000, &config), None);

    // Betting 阶段不走此超时
    let game_bet = make_game(
        &[0x10, 0x20],
        GamePhase::Betting {
            round: BettingRound::Preflop,
        },
        &[],
        1000,
    );
    assert_eq!(is_submit_phase_timed_out(&game_bet, 100_000, &config), None);
}

/// 超时检测：Reconstruct 阶段超时边界（threshold=100）。
#[test]
fn timeout_detection_reconstruct_boundary() {
    let config = TimeConsensusConfig::default();
    let game = make_game(
        &[0x10, 0x20],
        GamePhase::MultiPlayerSubmit {
            kind: SubmitPhaseKind::Reconstruct,
        },
        &[0x10],
        3000,
    );
    // 3000 + 100 = 3100，边界不超时
    assert_eq!(is_submit_phase_timed_out(&game, 3100, &config), None);
    // 3101 超时
    assert_eq!(
        is_submit_phase_timed_out(&game, 3101, &config),
        Some(SubmitPhaseKind::Reconstruct)
    );
}

/// 超时恢复：pending 为空时 no-op，不改变状态。
#[test]
fn timeout_recovery_empty_pending_no_op() {
    let mut game = make_game(
        &[0x10, 0x20, 0x30],
        GamePhase::MultiPlayerSubmit {
            kind: SubmitPhaseKind::Shuffle,
        },
        &[], // pending 为空
        1000,
    );
    let results = handle_submit_phase_timeout(&mut game, SubmitPhaseKind::Shuffle, 1101, |_| 100);
    // 无 KickResult
    assert!(results.is_empty());
    // active 不变
    assert_eq!(game.active_participants.len(), 3);
    // 3 >= 2 → 不 finalize
    assert!(!game.is_finalized);
}

// ===== SubTask 11.3: LeaveProof 随时提交测试 =====
//
// 场景：LeaveProof 可在任意阶段提交（Betting / MultiPlayerSubmit），
// 提交后玩家从 active_participants 移除，从 pending_submitters 移除（若在）

/// LeaveProof 在 Betting 阶段提交：玩家从 active_participants 移除。
/// 注意：Betting 阶段提交 LeaveProof 需先切换到 MultiPlayerSubmit{LeaveProof} 阶段
/// （spec：LeaveProof 是 MultiPlayerSubmit 的子阶段）。
#[test]
fn leave_proof_submission_removes_player_from_active() {
    let rule = TexasHoldemTurnRule::new();
    // 3 玩家，LeaveProof 阶段
    let mut game = make_game(
        &[0x10, 0x20, 0x30],
        GamePhase::MultiPlayerSubmit {
            kind: SubmitPhaseKind::LeaveProof,
        },
        &[0x10, 0x20, 0x30], // pending = active（LeaveProof 阶段所有 active 玩家可提交）
        0,
    );

    // B(0x20) 提交 LeaveProof（B 在 active_participants 中）
    let tx_b = make_gameturn_tx(0x20, 1);
    validate_game_turn_phase_aware(&tx_b, &mut game, addr(0x20), &rule)
        .expect("LeaveProof 阶段 active_participant 提交应通过");
    // B 从 active_participants 移除
    assert!(!game.active_participants.contains(&addr(0x20)));
    // B 从 pending_submitters 移除（若在）
    assert!(!game.pending_submitters.contains(&addr(0x20)));
    // B 插入 completed_submitters
    assert!(game.completed_submitters.contains(&addr(0x20)));
    // A/C 仍在 active
    assert!(game.active_participants.contains(&addr(0x10)));
    assert!(game.active_participants.contains(&addr(0x30)));
    assert_eq!(game.active_participants.len(), 2);

    // C(0x30) 提交 LeaveProof
    let tx_c = make_gameturn_tx(0x30, 1);
    validate_game_turn_phase_aware(&tx_c, &mut game, addr(0x30), &rule)
        .expect("C 提交 LeaveProof 应通过");
    assert!(!game.active_participants.contains(&addr(0x30)));
    assert_eq!(game.active_participants.len(), 1);
    // 剩余 1 人，但 LeaveProof 不自动 finalize（finalize 由 handle_submit_phase_timeout 或合约层触发）
    // 此处仅验证 active_participants 更新，不验证 is_finalized
}

/// LeaveProof 提交：玩家不在 pending_submitters 中但仍可提交（spec：不要求在 pending）。
#[test]
fn leave_proof_submission_player_not_in_pending() {
    let rule = TexasHoldemTurnRule::new();
    // 3 玩家，LeaveProof 阶段，pending 仅含 A/B（C 不在 pending）
    let mut game = make_game(
        &[0x10, 0x20, 0x30],
        GamePhase::MultiPlayerSubmit {
            kind: SubmitPhaseKind::LeaveProof,
        },
        &[0x10, 0x20], // pending 仅 A/B，C 不在 pending
        0,
    );

    // C(0x30) 不在 pending 但在 active → 仍可提交 LeaveProof
    let tx_c = make_gameturn_tx(0x30, 1);
    validate_game_turn_phase_aware(&tx_c, &mut game, addr(0x30), &rule)
        .expect("LeaveProof 不要求在 pending_submitters 中，active 即可");
    // C 从 active 移除，插入 completed
    assert!(!game.active_participants.contains(&addr(0x30)));
    assert!(game.completed_submitters.contains(&addr(0x30)));
}

/// LeaveProof 提交：非 active_participant 被拒绝（NotEligibleSubmitter）。
#[test]
fn leave_proof_submission_rejects_non_active_player() {
    let rule = TexasHoldemTurnRule::new();
    // 2 玩家 A/B，LeaveProof 阶段
    let mut game = make_game(
        &[0x10, 0x20],
        GamePhase::MultiPlayerSubmit {
            kind: SubmitPhaseKind::LeaveProof,
        },
        &[],
        0,
    );

    // C(0x30) 不在 active_participants → 拒绝
    let tx_c = make_gameturn_tx(0x30, 1);
    let err = validate_game_turn_phase_aware(&tx_c, &mut game, addr(0x30), &rule).unwrap_err();
    assert!(matches!(err, PokerL1Error::NotEligibleSubmitter { .. }));
}

/// LeaveProof 与其他多玩家阶段交错：Shuffle 阶段中玩家可切换到 LeaveProof 提交。
#[test]
fn leave_proof_interleaved_with_shuffle_phase() {
    let rule = TexasHoldemTurnRule::new();
    // 3 玩家，Shuffle 阶段，pending = {A, B, C}
    let mut game = make_game(
        &[0x10, 0x20, 0x30],
        GamePhase::MultiPlayerSubmit {
            kind: SubmitPhaseKind::Shuffle,
        },
        &[0x10, 0x20, 0x30],
        0,
    );

    // A 正常提交 shuffle proof
    let tx_a = make_gameturn_tx(0x10, 1);
    validate_game_turn_phase_aware(&tx_a, &mut game, addr(0x10), &rule)
        .expect("A 在 pending 中，Shuffle 提交应通过");
    assert!(game.completed_submitters.contains(&addr(0x10)));

    // B 想离开：须先切换到 LeaveProof 阶段（合约层负责切换，此处模拟）
    game.phase = GamePhase::MultiPlayerSubmit {
        kind: SubmitPhaseKind::LeaveProof,
    };
    // B 提交 LeaveProof
    let tx_b = make_gameturn_tx(0x20, 1);
    validate_game_turn_phase_aware(&tx_b, &mut game, addr(0x20), &rule)
        .expect("B 在 active 中，LeaveProof 提交应通过");
    // B 从 active 与 pending 同时移除
    assert!(!game.active_participants.contains(&addr(0x20)));
    assert!(!game.pending_submitters.contains(&addr(0x20)));
    // A 仍保留（A 已 completed shuffle，未被 LeaveProof 影响）
    assert!(game.active_participants.contains(&addr(0x10)));
    // C 仍在 active 与 pending
    assert!(game.active_participants.contains(&addr(0x30)));
    assert!(game.pending_submitters.contains(&addr(0x30)));
}

// ===== SubTask 11.4: 跨 commit 排序测试 =====
//
// 测试 build_game_sub_block（Phase 5 Task 9）与 check_sech6_cross_commit_force_advance（Phase 5 Task 10）

// ----- build_game_sub_block 测试 -----

/// Betting 阶段：current_turn 玩家优先，同玩家按 arrival 顺序。
#[test]
fn build_sub_block_betting_prioritizes_current_turn() {
    let rule = SimpleTurnRule;
    // current_turn = A(0x10)（需通过 derive_address 匹配 tx 的 tagged_pubkey）
    let tx_a = make_gameturn_tx(0x10, 2);
    let tx_b = make_gameturn_tx(0x20, 1);
    let actor_a = derive_address(&tx_a.tagged_pubkey);
    let actor_b = derive_address(&tx_b.tagged_pubkey);

    let mut game = make_game(
        &[0x10, 0x20],
        GamePhase::Betting {
            round: BettingRound::Preflop,
        },
        &[],
        0,
    );
    // 设置 current_turn_player 为 actor_a（派生地址），使 A 的 tx 优先
    game.current_turn_player = actor_a;
    game.active_participants = BTreeSet::from([actor_a, actor_b]);

    // arrival 顺序：B 先到（nonce=1），A 后到（nonce=2）
    let txs = vec![tx_b, tx_a];
    let sub = build_game_sub_block(txs, &game, &rule).expect("构造 sub-block");
    // current_turn=actor_a 的 tx 排前（nonce=2），B 排后（nonce=1）
    assert_eq!(sub.txs.len(), 2);
    assert_eq!(sub.txs[0].gameturn_nonce, Some(2)); // A
    assert_eq!(sub.txs[1].gameturn_nonce, Some(1)); // B
    // arrival_order 记录排序后的原始序号：A 原序号=1，B 原序号=0
    assert_eq!(sub.arrival_order, vec![1, 0]);
}

/// MultiPlayerSubmit 阶段：按 arrival 顺序稳定排序（不使用 current_turn 优先级）。
#[test]
fn build_sub_block_multi_player_submit_arrival_order() {
    let rule = SimpleTurnRule;
    let game = make_game(
        &[0x10, 0x20],
        GamePhase::MultiPlayerSubmit {
            kind: SubmitPhaseKind::Shuffle,
        },
        &[0x10, 0x20],
        0,
    );
    // arrival 顺序：B 先到（nonce=1），A 后到（nonce=2）
    // current_turn_player=0x10，但多玩家阶段不应优先
    let txs = vec![make_gameturn_tx(0x20, 1), make_gameturn_tx(0x10, 2)];
    let sub = build_game_sub_block(txs, &game, &rule).expect("构造 sub-block");
    // 多玩家阶段按 arrival 顺序：B（nonce=1）在前，A（nonce=2）在后
    assert_eq!(sub.txs.len(), 2);
    assert_eq!(sub.txs[0].gameturn_nonce, Some(1)); // B
    assert_eq!(sub.txs[1].gameturn_nonce, Some(2)); // A
    assert_eq!(sub.arrival_order, vec![0, 1]);
}

/// 过滤非 GameTurn 通道 tx（Public / ForceSync 被忽略）。
#[test]
fn build_sub_block_filters_non_gameturn_txs() {
    let rule = SimpleTurnRule;
    let game = make_game(
        &[0x10, 0x20],
        GamePhase::Betting {
            round: BettingRound::Preflop,
        },
        &[],
        0,
    );
    let txs = vec![
        make_gameturn_tx(0x10, 1),
        make_public_tx(1),     // 非 GameTurn，应被过滤
        make_force_sync_tx(2), // 非 GameTurn，应被过滤
        make_gameturn_tx(0x10, 2),
    ];
    let sub = build_game_sub_block(txs, &game, &rule).expect("构造 sub-block");
    assert_eq!(sub.txs.len(), 2, "仅保留 GameTurn 通道 tx");
    assert_eq!(sub.txs[0].gameturn_nonce, Some(1));
    assert_eq!(sub.txs[1].gameturn_nonce, Some(2));
}

/// 同玩家多笔 tx 按 arrival 顺序保持稳定。
#[test]
fn build_sub_block_preserves_arrival_same_player() {
    let rule = SimpleTurnRule;
    let game = make_game(
        &[0x10, 0x20],
        GamePhase::Betting {
            round: BettingRound::Preflop,
        },
        &[],
        0,
    );
    let txs = vec![
        make_gameturn_tx(0x10, 1),
        make_gameturn_tx(0x10, 2),
        make_gameturn_tx(0x10, 3),
    ];
    let sub = build_game_sub_block(txs, &game, &rule).expect("构造 sub-block");
    assert_eq!(sub.txs.len(), 3);
    assert_eq!(sub.txs[0].gameturn_nonce, Some(1));
    assert_eq!(sub.txs[1].gameturn_nonce, Some(2));
    assert_eq!(sub.txs[2].gameturn_nonce, Some(3));
    assert_eq!(sub.arrival_order, vec![0, 1, 2]);
}

/// 多玩家阶段不同 SubmitPhaseKind 的排序行为一致（均按 arrival）。
#[test]
fn build_sub_block_all_multi_player_kinds_arrival_order() {
    let rule = SimpleTurnRule;
    for kind in [
        SubmitPhaseKind::Shuffle,
        SubmitPhaseKind::RevealToken,
        SubmitPhaseKind::Reconstruct,
        SubmitPhaseKind::LeaveProof,
    ] {
        let game = make_game(
            &[0x10, 0x20],
            GamePhase::MultiPlayerSubmit { kind },
            &[0x10, 0x20],
            0,
        );
        // arrival 顺序：0x20 先到，0x10 后到
        let txs = vec![make_gameturn_tx(0x20, 1), make_gameturn_tx(0x10, 2)];
        let sub = build_game_sub_block(txs, &game, &rule).expect("构造 sub-block");
        assert_eq!(
            sub.txs[0].gameturn_nonce,
            Some(1),
            "kind={kind:?} 应按 arrival 排序"
        );
        assert_eq!(
            sub.txs[1].gameturn_nonce,
            Some(2),
            "kind={kind:?} 应按 arrival 排序"
        );
    }
}

// ----- check_sech6_cross_commit_force_advance 测试 -----

/// SEC-H6：前一 commit 无 GameTurn tx → force_advance 可执行（Betting 阶段）。
#[test]
fn check_sech6_ok_no_prev_gameturn_betting() {
    let game_id = ObjectID::new([0xAA; 20], 1);
    let prev_turns: Vec<Transaction> = vec![];
    let phase = GamePhase::Betting {
        round: BettingRound::Preflop,
    };
    check_sech6_cross_commit_force_advance(&prev_turns, &game_id, &game_id, &phase)
        .expect("前一 commit 无 GameTurn → force_advance 可执行");
}

/// SEC-H6：前一 commit 有 GameTurn tx → force_advance 被拒绝（Betting 阶段）。
#[test]
fn check_sech6_rejects_prev_gameturn_betting() {
    let game_id = ObjectID::new([0xAA; 20], 1);
    let prev_turns = vec![make_gameturn_tx(0x10, 1)];
    let phase = GamePhase::Betting {
        round: BettingRound::Preflop,
    };
    let err = check_sech6_cross_commit_force_advance(&prev_turns, &game_id, &game_id, &phase)
        .unwrap_err();
    assert!(matches!(err, PokerL1Error::Other(_)));
}

/// SEC-H6：game_id 不匹配 → GameNotFound。
#[test]
fn check_sech6_rejects_game_id_mismatch() {
    let game_id_a = ObjectID::new([0xAA; 20], 1);
    let game_id_b = ObjectID::new([0xBB; 20], 1);
    let prev_turns: Vec<Transaction> = vec![];
    let phase = GamePhase::Betting {
        round: BettingRound::Preflop,
    };
    let err = check_sech6_cross_commit_force_advance(&prev_turns, &game_id_a, &game_id_b, &phase)
        .unwrap_err();
    assert!(matches!(err, PokerL1Error::GameNotFound(_)));
}

/// SEC-H6：多玩家阶段（Shuffle）前一 commit 有 GameTurn tx → force_advance 被拒绝。
#[test]
fn check_sech6_rejects_multi_player_shuffle_with_prev_gameturn() {
    let game_id = ObjectID::new([0xAA; 20], 1);
    let prev_turns = vec![make_gameturn_tx(0x10, 1)];
    let phase = GamePhase::MultiPlayerSubmit {
        kind: SubmitPhaseKind::Shuffle,
    };
    let err = check_sech6_cross_commit_force_advance(&prev_turns, &game_id, &game_id, &phase)
        .unwrap_err();
    assert!(matches!(err, PokerL1Error::Other(_)));
}

/// SEC-H6：多玩家阶段（RevealToken）前一 commit 无 GameTurn tx → force_advance 可执行。
#[test]
fn check_sech6_ok_multi_player_reveal_token_no_prev_gameturn() {
    let game_id = ObjectID::new([0xAA; 20], 1);
    let prev_turns: Vec<Transaction> = vec![];
    let phase = GamePhase::MultiPlayerSubmit {
        kind: SubmitPhaseKind::RevealToken,
    };
    check_sech6_cross_commit_force_advance(&prev_turns, &game_id, &game_id, &phase)
        .expect("多玩家阶段前一 commit 无 GameTurn → force_advance 可执行");
}

/// SEC-H6：覆盖所有多玩家阶段类型，前一 commit 有 GameTurn 均被拒绝。
#[test]
fn check_sech6_all_multi_player_kinds_reject_prev_gameturn() {
    let game_id = ObjectID::new([0xAA; 20], 1);
    let prev_turns = vec![make_gameturn_tx(0x10, 1)];
    for kind in [
        SubmitPhaseKind::Shuffle,
        SubmitPhaseKind::RevealToken,
        SubmitPhaseKind::Reconstruct,
        SubmitPhaseKind::LeaveProof,
    ] {
        let phase = GamePhase::MultiPlayerSubmit { kind };
        let err = check_sech6_cross_commit_force_advance(&prev_turns, &game_id, &game_id, &phase)
            .unwrap_err();
        assert!(
            matches!(err, PokerL1Error::Other(_)),
            "kind={kind:?} 前一 commit 有 GameTurn 应被拒绝"
        );
    }
}

/// SEC-H6：前一 commit 多笔 GameTurn tx → 仍被拒绝。
#[test]
fn check_sech6_rejects_multiple_prev_gameturns() {
    let game_id = ObjectID::new([0xAA; 20], 1);
    let prev_turns = vec![
        make_gameturn_tx(0x10, 1),
        make_gameturn_tx(0x20, 1),
        make_gameturn_tx(0x30, 1),
    ];
    let phase = GamePhase::Betting {
        round: BettingRound::Flop,
    };
    let err = check_sech6_cross_commit_force_advance(&prev_turns, &game_id, &game_id, &phase)
        .unwrap_err();
    assert!(matches!(err, PokerL1Error::Other(_)));
}

// ===== 端到端综合场景：超时恢复后剩余玩家继续游戏 =====

/// 综合场景：Shuffle 阶段 1 玩家超时被 kick，剩余 2 人推进到 RevealToken → Betting。
#[test]
fn e2e_timeout_then_continue_with_remaining_players() {
    let rule = TexasHoldemTurnRule::new();
    let config = TimeConsensusConfig::default();

    // 3 玩家，Shuffle 阶段，pending = {B}（A/C 已提交）
    let mut game = make_game(
        &[0x10, 0x20, 0x30],
        GamePhase::MultiPlayerSubmit {
            kind: SubmitPhaseKind::Shuffle,
        },
        &[0x20], // 仅 B 未提交
        1000,
    );
    game.completed_submitters.insert(addr(0x10));
    game.completed_submitters.insert(addr(0x30));

    // 检测超时
    let timed_out = is_submit_phase_timed_out(&game, 1101, &config);
    assert_eq!(timed_out, Some(SubmitPhaseKind::Shuffle));

    // 执行 kick：仅 B
    let results = handle_submit_phase_timeout(&mut game, SubmitPhaseKind::Shuffle, 1101, |_| 500);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].player, addr(0x20));
    assert_eq!(results[0].refund_amount, 500);

    // 剩余 A/C（2 人），不 finalize
    assert_eq!(game.active_participants.len(), 2);
    assert!(!game.is_finalized);
    assert!(game.pending_submitters.is_empty());

    // 推进阶段：Shuffle → RevealToken
    let new_phase = rule
        .advance_phase(&mut game)
        .expect("Shuffle → RevealToken");
    assert_eq!(
        new_phase,
        GamePhase::MultiPlayerSubmit {
            kind: SubmitPhaseKind::RevealToken
        }
    );
    // pending 重置为剩余 active（A/C）
    assert_eq!(game.pending_submitters.len(), 2);
    assert!(game.pending_submitters.contains(&addr(0x10)));
    assert!(game.pending_submitters.contains(&addr(0x30)));

    // A/C 提交 reveal token
    for byte in [0x10, 0x30] {
        let tx = make_gameturn_tx(byte, 2);
        validate_game_turn_phase_aware(&tx, &mut game, addr(byte), &rule)
            .expect("剩余玩家提交 reveal token 应通过");
    }
    assert!(game.pending_submitters.is_empty());

    // 推进：RevealToken → Betting{Preflop}
    let new_phase = rule
        .advance_phase(&mut game)
        .expect("RevealToken → Betting");
    assert_eq!(
        new_phase,
        GamePhase::Betting {
            round: BettingRound::Preflop
        }
    );
    // 回到下注阶段，current_turn 可用
    assert!(rule.current_turn(&game).is_some());
}
