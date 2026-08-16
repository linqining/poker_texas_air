//! Phase 5c 集成测试（Task 42c — SubTask 42.8 / 42.9 / 42.10 / 42.11）
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）+ tasks.md Task 42c：
//! - **SubTask 42.8**：强制同步单元测试 — force_advance（默认 fold / 大盲位 check）+
//!   force_checkin（H4 修复 — forfeit 边界判定基于 last_checkpoint_age）+
//!   request_revert / force_revert（forfeit 仅阶段 3 / reason 优先）+
//!   challenge_delta（从 π public_io 重派生 Δ'）+ request_da + force_settle +
//!   forfeit 保证金（扣除 / 分配 / 退还）
//! - **SubTask 42.9**：状态裁剪集成测试 — Game 结算 + dispute 过期裁剪 / tx 压缩 /
//!   vertex 压缩 / ZK proof 归档 / archive node 不足不得裁剪
//! - **SubTask 42.10**：节点角色分层集成测试 — archive / full / light +
//!   request_historical_data RPC
//! - **SubTask 42.11**：模糊测试 — 10000 个随机输入覆盖强制同步 / 裁剪 / 保证金安全路径

use poker_l1::consensus::DagVertex;
use poker_l1::error::PokerL1Error;
use poker_l1::object_model::ObjectID;
use poker_l1::signature::{CURRENT_VERSION, SignatureScheme, TaggedPubkey};
use poker_l1::storage::pruning::{
    DEFAULT_ARCHIVE_NODE_MIN_COUNT, DEFAULT_TX_PRUNE_AFTER_BLOCKS,
    DEFAULT_VERTEX_PRUNE_AFTER_BLOCKS, HistoricalDataRequest, HistoricalDataResponse,
    HistoricalDataType, NodeRole, PermanentRetentionItem, PruningConfig, archive_zk_proof,
    check_game_pruning_eligibility, check_pruning_allowed, check_tx_pruning_eligibility,
    check_vertex_pruning_eligibility, check_zk_proof_pruning_eligibility, compute_proof_hash,
    handle_historical_data_request, is_archive_node_sufficient, is_permanently_retained,
    mark_blob_expired, prune_tx, prune_vertex,
};
use poker_l1::transaction::{Gas, RouteHint, Transaction, TxLane};
use poker_l1::vm::contracts::challenge_delta::{
    ChallengeDeltaTx, DEFAULT_CHALLENGE_DEPOSIT_RATIO, DEFAULT_CHALLENGE_REWARD_RATIO,
    apply_challenge_delta, compute_challenge_delta_outcome, compute_challenger_deposit,
    compute_challenger_reward, hash_state_delta, validate_challenge_deposit_ratio,
    validate_challenge_reward_ratio,
};
use poker_l1::vm::contracts::force_advance::{
    ForceAdvanceError, ForceAdvanceInput, apply_force_advance,
};
use poker_l1::vm::contracts::force_checkin::{
    ForceCheckinInput, ForceCheckinScenario, ForfeitDecision, ForfeitReason, RecoveryStage,
    apply_force_checkin, determine_force_checkin_scenario,
};
use poker_l1::vm::contracts::force_settle::{
    ForceSettleTx, apply_force_settle, is_force_settle_allowed,
};
use poker_l1::vm::contracts::forfeit::{
    DEFAULT_FORFEIT_DEPOSIT_RATIO, apply_forfeit, apply_forfeit_refund,
    compute_designated_operator_bond, compute_forfeit_deposit, compute_forfeit_distribution,
    validate_designated_operator_bond, validate_forfeit_deposit_ratio,
};
use poker_l1::vm::contracts::request_da::{
    RequestDaTx, apply_request_da, is_request_da_appropriate,
};
use poker_l1::vm::contracts::revert::{
    ForceRevertTx, RequestRevertTx, RevertReason, apply_force_revert, apply_request_revert,
};
use poker_l1::vm::contracts::settle::RakeConfig;
use poker_l1::vm::contracts::types::{
    ExecutionMode, GameContract, GamePhase, HandState, PlayerStack, RakeConfigRef,
};

// ===== 辅助函数 =====

fn make_tagged_pubkey(byte: u8) -> TaggedPubkey {
    let mut raw = vec![byte];
    raw.extend_from_slice(&[0x02u8; 32]);
    TaggedPubkey::new(SignatureScheme::Secp256k1, CURRENT_VERSION, raw)
        .expect("构造 tagged pubkey 不应失败")
}

fn make_addr(byte: u8) -> poker_l1::Address {
    [byte; 20]
}

fn make_game_id() -> ObjectID {
    ObjectID::new(make_addr(0x01), 1)
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
        30, // turn_timeout_blocks
    );
    game.last_action_height = last_action_height;
    game
}

fn make_game_with_checkpoint(last_action_height: u64) -> GameContract {
    let mut game = make_game(last_action_height);
    game.last_checkpoint_state_hash = Some([0xAB; 32]);
    game.last_commitment = Some([0x11; 32]);
    game
}

fn make_game_with_forfeit_deposit(last_action_height: u64, forfeit_deposit: u64) -> GameContract {
    let mut game = make_game_with_checkpoint(last_action_height);
    game.forfeit_deposit = forfeit_deposit;
    game
}

/// 构造含 2 个未 fold 玩家的 Game（用于 force_advance / force_settle 测试）。
fn make_game_with_hand(last_action_height: u64) -> GameContract {
    let mut game = make_game_with_checkpoint(last_action_height);
    let hand = HandState {
        phase: GamePhase::Preflop,
        pot: 100,
        current_bet: 20,
        big_blind_amount: 20,
        small_blind_amount: 10,
        raise_count: 0,
        bet_count: 0,
        current_turn: make_addr(0x10),
        players: vec![
            PlayerStack {
                address: make_addr(0x10),
                contributed: 20,
                folded: false,
                is_big_blind: true,
                is_small_blind: false,
                is_button: false,
            },
            PlayerStack {
                address: make_addr(0x20),
                contributed: 10,
                folded: false,
                is_big_blind: false,
                is_small_blind: true,
                is_button: true,
            },
        ],
        last_action_height,
        hand_start_height: last_action_height,
    };
    game.current_hand = Some(hand);
    game
}

fn make_force_advance_input(
    timeout_player: poker_l1::Address,
    current_block_height: u64,
) -> ForceAdvanceInput {
    ForceAdvanceInput::new(timeout_player, current_block_height)
}

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

fn make_request_revert_tx(reason: RevertReason) -> RequestRevertTx {
    RequestRevertTx {
        game_id: make_game_id(),
        last_acked_checkpoint: [0xAB; 32],
        reason,
        submitter: make_addr(0x01), // == owner
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
        submitter: make_addr(0x02),
        current_block_height,
        turn_timeout_blocks: 30,
        da_window_blocks: 500,
        recovery_window_blocks: 100,
        is_designated_operator,
    }
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

fn make_challenge_delta_tx(claimed_delta: Vec<u8>, challenger_deposit: u64) -> ChallengeDeltaTx {
    ChallengeDeltaTx {
        game_id: make_game_id(),
        challenger: make_addr(0x02),
        claimed_state_delta: claimed_delta,
        challenger_deposit,
    }
}

fn make_rake_config() -> RakeConfig {
    RakeConfig {
        rake_rate_bps: 0,
        rake_cap: 0,
        rake_recipient: make_addr(0x00),
    }
}

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

// ===== SubTask 42.8: 强制同步单元测试 =====

mod subtask_42_8_force_sync {
    use super::*;

    // ----- force_advance -----

    #[test]
    fn test_force_advance_default_fold_preflop() {
        // Preflop + 有 raise → 超时 fold
        let mut game = make_game_with_hand(100);
        game.current_hand.as_mut().unwrap().raise_count = 1;
        game.current_hand.as_mut().unwrap().current_bet = 40;

        let input = make_force_advance_input(make_addr(0x10), 131); // elapsed=31 > 30
        let action = apply_force_advance(&mut game, &input).expect("force_advance 应成功");
        assert!(action.is_fold(), "Preflop 有 raise 超时应 fold");
        assert_eq!(game.last_action_height, 131, "last_action_height 应更新");
    }

    #[test]
    fn test_force_advance_big_blind_check_preflop() {
        // Preflop + 无人 raise + 超时玩家是大盲位 → check（SEC2-L5）
        let mut game = make_game_with_hand(100);
        // current_bet == big_blind_amount == 20, raise_count == 0
        let input = make_force_advance_input(make_addr(0x10), 131); // 大盲位
        let action = apply_force_advance(&mut game, &input).expect("force_advance 应成功");
        assert!(action.is_check(), "大盲位 preflop 无人 raise 超时应 check");
    }

    #[test]
    fn test_force_advance_postflop_no_betting_check() {
        // Postflop + 无人下注 → 任意超时玩家 check
        let mut game = make_game_with_hand(100);
        game.current_hand.as_mut().unwrap().phase = GamePhase::Flop;
        game.current_hand.as_mut().unwrap().current_bet = 0;
        game.current_hand.as_mut().unwrap().bet_count = 0;

        let input = make_force_advance_input(make_addr(0x20), 131); // 非大盲位
        let action = apply_force_advance(&mut game, &input).expect("force_advance 应成功");
        assert!(action.is_check(), "Postflop 无人下注超时应 check");
    }

    #[test]
    fn test_force_advance_postflop_with_bet_fold() {
        // Postflop + 有人下注 → fold
        let mut game = make_game_with_hand(100);
        game.current_hand.as_mut().unwrap().phase = GamePhase::Flop;
        game.current_hand.as_mut().unwrap().current_bet = 50;
        game.current_hand.as_mut().unwrap().bet_count = 1;

        let input = make_force_advance_input(make_addr(0x10), 131);
        let action = apply_force_advance(&mut game, &input).expect("force_advance 应成功");
        assert!(action.is_fold(), "Postflop 有人下注超时应 fold");
    }

    #[test]
    fn test_force_advance_not_timed_out() {
        let mut game = make_game_with_hand(100);
        let input = make_force_advance_input(make_addr(0x10), 105); // elapsed=5 < 30
        let result = apply_force_advance(&mut game, &input);
        assert!(matches!(result, Err(ForceAdvanceError::NotTimedOut { .. })));
    }

    #[test]
    fn test_force_advance_boundary_equal() {
        // SEC2-L6: <= 边界判定 — elapsed == turn_timeout_blocks 视为超时
        let mut game = make_game_with_hand(100);
        let input = make_force_advance_input(make_addr(0x10), 130); // elapsed=30 == 30
        let result = apply_force_advance(&mut game, &input);
        assert!(result.is_ok(), "elapsed == timeout 边界应触发超时");
    }

    #[test]
    fn test_force_advance_player_not_in_game() {
        let mut game = make_game_with_hand(100);
        let input = make_force_advance_input(make_addr(0x99), 131);
        let result = apply_force_advance(&mut game, &input);
        assert!(matches!(result, Err(ForceAdvanceError::PlayerNotInGame(_))));
    }

    #[test]
    fn test_force_advance_player_already_folded() {
        let mut game = make_game_with_hand(100);
        game.current_hand.as_mut().unwrap().players[0].folded = true;
        let input = make_force_advance_input(make_addr(0x10), 131);
        let result = apply_force_advance(&mut game, &input);
        assert!(matches!(
            result,
            Err(ForceAdvanceError::PlayerAlreadyFolded(_))
        ));
    }

    // ----- force_checkin（H4 修复 — forfeit 边界判定基于 last_checkpoint_age）-----

    #[test]
    fn test_force_checkin_malicious_withholding_forfeit() {
        // H4: last_checkpoint_age <= turn_timeout_blocks → 恶意扣留 → forfeit
        let mut game = make_game_with_forfeit_deposit(100, 5000);
        let input = make_force_checkin_input(130, false, 30); // age=30 <= 30
        let outcome = apply_force_checkin(&mut game, &input).expect("force_checkin 应成功");
        assert!(
            outcome.should_forfeit,
            "age <= timeout 应 forfeit（恶意扣留）"
        );
        assert_eq!(outcome.reason, ForfeitReason::MaliciousWithholding);
        assert_eq!(outcome.scenario, ForceCheckinScenario::MaliciousWithholding);
    }

    #[test]
    fn test_force_checkin_machine_failure_no_forfeit() {
        // H4: last_checkpoint_age > turn_timeout_blocks → 机器故障 → 不 forfeit
        let mut game = make_game_with_forfeit_deposit(100, 5000);
        let input = make_force_checkin_input(131, false, 30); // age=31 > 30
        let outcome = apply_force_checkin(&mut game, &input).expect("force_checkin 应成功");
        assert!(
            !outcome.should_forfeit,
            "age > timeout 不应 forfeit（机器故障）"
        );
        assert_eq!(outcome.reason, ForfeitReason::MachineFailure);
        assert_eq!(outcome.scenario, ForceCheckinScenario::MachineFailure);
    }

    #[test]
    fn test_force_checkin_designated_operator_doubled_boundary() {
        // NEW-M4: designated operator forfeit 边界加倍 = turn_timeout_blocks * 2
        let mut game = make_game_with_forfeit_deposit(100, 5000);
        // age=40 <= 60 (30*2) → 恶意扣留
        let input = make_force_checkin_input(140, true, 30);
        let outcome = apply_force_checkin(&mut game, &input).expect("force_checkin 应成功");
        assert!(
            outcome.should_forfeit,
            "designated operator age <= 2*timeout 应 forfeit"
        );
        assert_eq!(outcome.boundary, 60, "designated operator 边界应加倍");
    }

    #[test]
    fn test_force_checkin_designated_operator_above_doubled_boundary() {
        let mut game = make_game_with_forfeit_deposit(100, 5000);
        // age=61 > 60 → 机器故障
        let input = make_force_checkin_input(161, true, 30);
        let outcome = apply_force_checkin(&mut game, &input).expect("force_checkin 应成功");
        assert!(
            !outcome.should_forfeit,
            "designated operator age > 2*timeout 不应 forfeit"
        );
    }

    #[test]
    fn test_force_checkin_not_feasible_requires_revert() {
        // 无 checkpoint state → NotFeasibleRequiresRevert
        let mut game = make_game(100);
        game.last_checkpoint_state_hash = None;
        let input = make_force_checkin_input(200, false, 30);
        let result = apply_force_checkin(&mut game, &input);
        assert!(result.is_err(), "无 checkpoint state 应返回错误");
    }

    #[test]
    fn test_force_checkin_updates_last_action_height() {
        let mut game = make_game_with_forfeit_deposit(100, 5000);
        let input = make_force_checkin_input(131, false, 30);
        let _ = apply_force_checkin(&mut game, &input).expect("force_checkin 应成功");
        assert_eq!(game.last_action_height, 131, "last_action_height 应更新");
        assert!(game.last_commitment.is_none(), "last_commitment 应清除");
    }

    #[test]
    fn test_determine_force_checkin_scenario_malicious() {
        let game = make_game_with_checkpoint(100);
        let scenario = determine_force_checkin_scenario(&game, 130, 30, false);
        assert_eq!(scenario, ForceCheckinScenario::MaliciousWithholding);
    }

    #[test]
    fn test_determine_force_checkin_scenario_machine_failure() {
        let game = make_game_with_checkpoint(100);
        let scenario = determine_force_checkin_scenario(&game, 131, 30, false);
        assert_eq!(scenario, ForceCheckinScenario::MachineFailure);
    }

    #[test]
    fn test_forfeit_decision_boundary_equal() {
        // SEC2-L6: <= 边界 — age == boundary → MaliciousWithholding
        let game = make_game_with_checkpoint(100);
        let decision = ForfeitDecision::compute(&game, 130, 30, false); // age=30 == 30
        assert!(decision.should_forfeit, "age == boundary 应 forfeit");
        assert_eq!(decision.reason, ForfeitReason::MaliciousWithholding);
    }

    // ----- request_revert / force_revert -----

    #[test]
    fn test_request_revert_technical_interrupt_no_forfeit() {
        let mut game = make_game_with_forfeit_deposit(100, 5000);
        let tx = make_request_revert_tx(RevertReason::TechnicalInterrupt);
        let outcome =
            apply_request_revert(&mut game, &tx, 150, 30, 500, 100).expect("request_revert 应成功");
        assert!(!outcome.should_forfeit, "TechnicalInterrupt 不应 forfeit");
    }

    #[test]
    fn test_request_revert_malicious_withholding_forfeit() {
        let mut game = make_game_with_forfeit_deposit(100, 5000);
        let tx = make_request_revert_tx(RevertReason::MaliciousWithholding);
        let outcome =
            apply_request_revert(&mut game, &tx, 150, 30, 500, 100).expect("request_revert 应成功");
        assert!(outcome.should_forfeit, "MaliciousWithholding 应 forfeit");
    }

    #[test]
    fn test_request_revert_data_unavailable_forfeit() {
        let mut game = make_game_with_forfeit_deposit(100, 5000);
        let tx = make_request_revert_tx(RevertReason::DataUnavailable);
        let outcome =
            apply_request_revert(&mut game, &tx, 150, 30, 500, 100).expect("request_revert 应成功");
        assert!(outcome.should_forfeit, "DataUnavailable 应 forfeit");
    }

    #[test]
    fn test_request_revert_wrong_submitter() {
        let mut game = make_game_with_forfeit_deposit(100, 5000);
        let mut tx = make_request_revert_tx(RevertReason::TechnicalInterrupt);
        tx.submitter = make_addr(0x99); // 非 owner
        let result = apply_request_revert(&mut game, &tx, 150, 30, 500, 100);
        assert!(matches!(result, Err(PokerL1Error::NotOwner(_))));
    }

    #[test]
    fn test_force_revert_malicious_withholding_forfeit() {
        let mut game = make_game_with_forfeit_deposit(100, 5000);
        let tx = make_force_revert_tx(RevertReason::MaliciousWithholding, 700, false);
        let outcome = apply_force_revert(&mut game, &tx).expect("force_revert 应成功");
        assert!(outcome.should_forfeit, "MaliciousWithholding 应 forfeit");
    }

    #[test]
    fn test_force_revert_reason_overrides_stage() {
        // reason=malicious_withholding 即使 age 超边界仍 forfeit（reason 优先）
        let mut game = make_game_with_forfeit_deposit(100, 5000);
        // current_block_height=1000 → age=900 远超 boundary
        let tx = make_force_revert_tx(RevertReason::MaliciousWithholding, 1000, false);
        let outcome = apply_force_revert(&mut game, &tx).expect("force_revert 应成功");
        assert!(
            outcome.should_forfeit,
            "reason 优先 — MaliciousWithholding 即使超边界仍 forfeit"
        );
        assert_eq!(outcome.reason, Some(ForfeitReason::MaliciousWithholding));
    }

    #[test]
    fn test_revert_reason_triggers_forfeit() {
        assert!(!RevertReason::TechnicalInterrupt.triggers_forfeit());
        assert!(RevertReason::MaliciousWithholding.triggers_forfeit());
        assert!(RevertReason::DataUnavailable.triggers_forfeit());
    }

    // ----- challenge_delta -----

    #[test]
    fn test_challenge_delta_succeeded() {
        // 提交的 Δ 与 on_chain_state_delta_hash 不一致 → 挑战成立
        let mut game = make_game_with_forfeit_deposit(100, 5000);
        let tx = make_challenge_delta_tx(vec![0xAA], 1000);
        let on_chain_hash = hash_state_delta(&[0xBB]); // 不同的 delta
        let result = apply_challenge_delta(
            &mut game,
            &tx,
            on_chain_hash,
            DEFAULT_CHALLENGE_REWARD_RATIO,
        );
        assert!(matches!(result, Err(PokerL1Error::ChallengeSucceeded)));
        assert_eq!(game.forfeit_deposit, 0, "挑战成立后 forfeit_deposit 清零");
    }

    #[test]
    fn test_challenge_delta_failed() {
        // 提交的 Δ 与 on_chain_state_delta_hash 一致 → 挑战失败
        let mut game = make_game_with_forfeit_deposit(100, 5000);
        let claimed_delta = vec![0xAA];
        let on_chain_hash = hash_state_delta(&claimed_delta); // 一致
        let tx = make_challenge_delta_tx(claimed_delta, 1000);
        let result = apply_challenge_delta(
            &mut game,
            &tx,
            on_chain_hash,
            DEFAULT_CHALLENGE_REWARD_RATIO,
        );
        assert!(matches!(result, Err(PokerL1Error::ChallengeFailed)));
        assert_eq!(
            game.forfeit_deposit, 6000,
            "挑战失败后 forfeit_deposit += challenger_deposit"
        );
    }

    #[test]
    fn test_challenge_delta_outcome_computation() {
        let game = make_game_with_forfeit_deposit(100, 5000);
        let tx = make_challenge_delta_tx(vec![0xAA], 1000);
        let on_chain_hash = hash_state_delta(&[0xBB]);
        let outcome = compute_challenge_delta_outcome(
            &game,
            &tx,
            on_chain_hash,
            DEFAULT_CHALLENGE_REWARD_RATIO,
        );
        assert!(outcome.succeeded, "Δ 不一致 → 挑战成立");
        assert_eq!(outcome.operator_forfeit_amount, 5000);
        assert_eq!(outcome.challenger_reward, 5000); // 100% reward ratio
    }

    #[test]
    fn test_challenge_deposit_computation() {
        // SEC-C4: challenge_deposit = buy_in * ratio / 100
        assert_eq!(compute_challenger_deposit(1000, 50), 500);
        assert_eq!(
            compute_challenger_deposit(1000, DEFAULT_CHALLENGE_DEPOSIT_RATIO),
            500
        );
    }

    #[test]
    fn test_challenge_reward_computation() {
        // SEC-C4: challenge_reward = forfeit_deposit * ratio / 100
        assert_eq!(compute_challenger_reward(5000, 100), 5000);
        assert_eq!(
            compute_challenger_reward(5000, DEFAULT_CHALLENGE_REWARD_RATIO),
            5000
        );
    }

    #[test]
    fn test_challenge_ratio_validation() {
        assert!(validate_challenge_deposit_ratio(50));
        assert!(validate_challenge_deposit_ratio(1));
        assert!(validate_challenge_deposit_ratio(100));
        assert!(!validate_challenge_deposit_ratio(0));
        assert!(!validate_challenge_deposit_ratio(101));

        assert!(validate_challenge_reward_ratio(100));
        assert!(validate_challenge_reward_ratio(10));
        assert!(!validate_challenge_reward_ratio(9));
        assert!(!validate_challenge_reward_ratio(101));
    }

    // ----- request_da -----

    #[test]
    fn test_request_da_stage2() {
        let mut game = make_game_with_checkpoint(100);
        let tx = make_request_da_tx(150); // elapsed=50 > 30 → Stage2
        let outcome = apply_request_da(&mut game, &tx).expect("request_da 应成功");
        assert!(matches!(outcome.stage, RecoveryStage::Stage2 { .. }));
        assert!(!outcome.triggers_force_revert, "Stage2 不触发 force_revert");
        assert_eq!(
            game.last_action_height, 100,
            "request_da 不更新 last_action_height"
        );
    }

    #[test]
    fn test_request_da_stage3_triggers_force_revert() {
        let mut game = make_game_with_checkpoint(100);
        // elapsed > turn_timeout + da_window + recovery_window = 30+500+100=630
        let tx = make_request_da_tx(800);
        let outcome = apply_request_da(&mut game, &tx).expect("request_da 应成功");
        assert!(matches!(outcome.stage, RecoveryStage::Stage3 { .. }));
        assert!(outcome.triggers_force_revert, "Stage3 应触发 force_revert");
    }

    #[test]
    fn test_is_request_da_appropriate() {
        let game = make_game_with_checkpoint(100);
        assert!(
            !is_request_da_appropriate(&game, 105, 30),
            "elapsed=5 <= 30 不应 request_da"
        );
        assert!(
            is_request_da_appropriate(&game, 131, 30),
            "elapsed=31 > 30 应 request_da"
        );
    }

    // ----- force_settle -----

    #[test]
    fn test_force_settle_rejected_in_stage2() {
        let mut game = make_game_with_hand(100);
        let tx = make_force_settle_tx(150); // Stage2
        let result = apply_force_settle(&mut game, &tx, &make_rake_config());
        assert!(result.is_err(), "Stage2 不允许 force_settle");
    }

    #[test]
    fn test_force_settle_allowed_in_stage3() {
        let mut game = make_game_with_hand(100);
        let tx = make_force_settle_tx(800); // Stage3
        let outcome =
            apply_force_settle(&mut game, &tx, &make_rake_config()).expect("force_settle 应成功");
        assert_eq!(outcome.settle_result.pot, 100, "底池应正确结算");
        assert!(game.is_hand_settled(), "手牌应标记为 Settled");
    }

    #[test]
    fn test_is_force_settle_allowed_stage_check() {
        let game = make_game_with_hand(100);
        assert!(
            !is_force_settle_allowed(&game, 150, 30, 500, 100),
            "Stage2 不允许"
        );
        assert!(
            is_force_settle_allowed(&game, 800, 30, 500, 100),
            "Stage3 允许"
        );
    }

    // ----- forfeit 保证金（SubTask 28.9）-----

    #[test]
    fn test_compute_forfeit_deposit_default_ratio() {
        // SEC-C4: forfeit_deposit = total_table_buy_in * ratio / 100，默认 ratio=100
        assert_eq!(compute_forfeit_deposit(5000, 100), 5000);
        assert_eq!(
            compute_forfeit_deposit(5000, DEFAULT_FORFEIT_DEPOSIT_RATIO),
            5000
        );
    }

    #[test]
    fn test_compute_forfeit_deposit_ratio_bounds() {
        assert!(validate_forfeit_deposit_ratio(100));
        assert!(validate_forfeit_deposit_ratio(10));
        assert!(validate_forfeit_deposit_ratio(200));
        assert!(!validate_forfeit_deposit_ratio(9));
        assert!(!validate_forfeit_deposit_ratio(201));
    }

    #[test]
    fn test_designated_operator_bond_median() {
        // SEC-L8: designated_operator_bond = median(buy_ins)
        assert_eq!(compute_designated_operator_bond(&[100, 200, 300]), 200);
        assert_eq!(compute_designated_operator_bond(&[100, 200, 300, 400]), 250); // 偶数取中间两个平均
        assert_eq!(compute_designated_operator_bond(&[500]), 500);
        assert_eq!(compute_designated_operator_bond(&[]), 0);
    }

    #[test]
    fn test_validate_designated_operator_bond_ok() {
        // bond == governed && bond >= total_buy_in
        assert!(validate_designated_operator_bond(5000, 5000, 3000).is_ok());
    }

    #[test]
    fn test_validate_designated_operator_bond_mismatch() {
        // SEC2-M7: bond != governed → InvalidBondAmount
        let result = validate_designated_operator_bond(4000, 5000, 3000);
        assert!(matches!(
            result,
            Err(PokerL1Error::InvalidBondAmount {
                expected: 5000,
                got: 4000
            })
        ));
    }

    #[test]
    fn test_validate_designated_operator_bond_insufficient() {
        // SEC2-M7: bond < total_buy_in → InsufficientOperatorBond
        let result = validate_designated_operator_bond(5000, 5000, 6000);
        assert!(matches!(
            result,
            Err(PokerL1Error::InsufficientOperatorBond {
                bond: 5000,
                required: 6000
            })
        ));
    }

    #[test]
    fn test_apply_forfeit_deducts_deposit() {
        let mut game = make_game_with_forfeit_deposit(100, 5000);
        let victims = vec![(make_addr(0x10), 1000), (make_addr(0x20), 2000)];
        let outcome = apply_forfeit(
            &mut game,
            Some(&make_game_id()),
            ForfeitReason::MaliciousWithholding,
            Some(make_addr(0x02)),
            5000, // challenger_reward = 100%
            &victims,
        )
        .expect("apply_forfeit 应成功");
        assert!(outcome.forfeited);
        assert_eq!(outcome.forfeit_amount, 5000);
        assert_eq!(game.forfeit_deposit, 0, "forfeit_deposit 应清零");
        assert_eq!(outcome.distribution.challenger_reward, 5000);
    }

    #[test]
    fn test_apply_forfeit_refund() {
        let mut game = make_game_with_forfeit_deposit(100, 5000);
        let outcome = apply_forfeit_refund(&mut game, make_addr(0x01));
        assert!(outcome.refunded);
        assert_eq!(outcome.refund_amount, 5000);
        assert_eq!(game.forfeit_deposit, 0, "退还后 forfeit_deposit 清零");
    }

    #[test]
    fn test_forfeit_distribution_proportional() {
        // SEC-C4: 挑战方得 challenge_reward_ratio%，剩余按 buy-in 比例分配
        let victims = vec![(make_addr(0x10), 1000), (make_addr(0x20), 3000)]; // total=4000
        let dist = compute_forfeit_distribution(5000, Some(make_addr(0x02)), 2500, &victims);
        // challenger_reward = min(2500, 5000) = 2500
        assert_eq!(dist.challenger_reward, 2500);
        // remaining = 5000 - 2500 = 2500
        // victim 1: 2500 * 1000/4000 = 625
        // victim 2: 2500 * 3000/4000 = 1875 → remaining - 625 = 1875
        assert_eq!(dist.victim_distributions.len(), 2);
        assert_eq!(dist.total_distributed, 5000, "总额应等于 forfeit_amount");
    }
}

// ===== SubTask 42.9: 状态裁剪集成测试 =====

mod subtask_42_9_pruning {
    use super::*;

    #[test]
    fn test_game_pruning_after_settle_and_dispute_expiry() {
        // (a) Game 结算 + dispute 过期 → 可裁剪
        assert!(check_game_pruning_eligibility(true, true).can_prune());
        assert!(
            !check_game_pruning_eligibility(false, true).can_prune(),
            "未结算不可裁剪"
        );
        assert!(
            !check_game_pruning_eligibility(true, false).can_prune(),
            "dispute 未过期不可裁剪"
        );
    }

    #[test]
    fn test_tx_pruning_after_window() {
        // (b) block 过 tx_prune_after_blocks → tx 压缩
        assert!(check_tx_pruning_eligibility(1500, 1000, true, true).can_prune());
        assert!(
            !check_tx_pruning_eligibility(500, 1000, true, true).can_prune(),
            "窗口未过不可裁剪"
        );
        // SEC2-L6: >= 边界
        assert!(
            check_tx_pruning_eligibility(1000, 1000, true, true).can_prune(),
            "边界 == 应可裁剪"
        );
    }

    #[test]
    fn test_tx_pruning_blocked_by_unsettled_game() {
        assert!(!check_tx_pruning_eligibility(1500, 1000, false, true).can_prune());
    }

    #[test]
    fn test_tx_pruning_blocked_by_active_dispute() {
        assert!(!check_tx_pruning_eligibility(1500, 1000, true, false).can_prune());
    }

    #[test]
    fn test_vertex_pruning_after_window() {
        // (c) vertex 过 vertex_prune_after_blocks → 压缩
        assert!(check_vertex_pruning_eligibility(15_000, 10_000).can_prune());
        assert!(!check_vertex_pruning_eligibility(5_000, 10_000).can_prune());
        // SEC2-L6: >= 边界
        assert!(check_vertex_pruning_eligibility(10_000, 10_000).can_prune());
    }

    #[test]
    fn test_prune_tx_compresses_to_commitment() {
        let tx = make_tx();
        let tx_hash = tx.tx_hash();
        let proof = vec![0xBB; 64];
        let pruned = prune_tx(&tx, proof.clone());
        assert_eq!(pruned.tx_hash, tx_hash, "tx_hash 永久保留");
        assert_eq!(pruned.tx_type, TxLane::Public);
        assert_eq!(pruned.merkle_proof, proof);
    }

    #[test]
    fn test_prune_vertex_drops_details() {
        let vertex = make_vertex();
        let vertex_hash = vertex.vertex_hash();
        let pruned = prune_vertex(&vertex);
        assert_eq!(pruned.round, 10);
        assert_eq!(pruned.epoch, 1);
        assert_eq!(pruned.vertex_hash, vertex_hash, "vertex_hash 永久保留");
        assert_eq!(pruned.tx_count, 3);
        assert_eq!(pruned.parent_count, 2);
        assert_eq!(pruned.author_sig, vec![0xCC; 65], "author_sig 保留");
    }

    #[test]
    fn test_zk_proof_archive_to_walrus() {
        // (d) ZK proof 归档到 Walrus DA 层
        let blob_id = [0xDD; 32];
        let archived = archive_zk_proof(&[0xAA], &[0xBB], &[0xCC], true, blob_id);
        assert_eq!(
            archived.proof_hash,
            compute_proof_hash(&[0xAA], &[0xBB], &[0xCC])
        );
        assert!(archived.verification_result);
        assert_eq!(archived.walrus_blob_id, blob_id);
        assert!(!archived.blob_expired);
    }

    #[test]
    fn test_zk_proof_pruning_requires_archive_nodes() {
        // (e) archive node < archive_node_min_count 时不得裁剪
        assert!(
            !check_zk_proof_pruning_eligibility(true, true, 2, 3).can_prune(),
            "archive 不足不可裁剪"
        );
        assert!(
            check_zk_proof_pruning_eligibility(true, true, 3, 3).can_prune(),
            "boundary == min 可裁剪"
        );
        assert!(check_zk_proof_pruning_eligibility(true, true, 5, 3).can_prune());
    }

    #[test]
    fn test_check_pruning_allowed_rejects_insufficient_archive() {
        let config = PruningConfig::new();
        let result = check_pruning_allowed(2, &config);
        assert!(matches!(
            result,
            Err(PokerL1Error::PruningRejectedArchiveInsufficient {
                actual: 2,
                limit: 3
            })
        ));
        assert!(check_pruning_allowed(3, &config).is_ok());
    }

    #[test]
    fn test_mark_blob_expired_preserves_proof_hash() {
        // SEC-M7: blob 过期后标记，但 proof_hash + verification_result 永久保留
        let mut archived = archive_zk_proof(&[0xAA], &[0xBB], &[0xCC], true, [0xDD; 32]);
        let original_hash = archived.proof_hash;
        mark_blob_expired(&mut archived);
        assert!(archived.blob_expired);
        assert_eq!(archived.proof_hash, original_hash, "proof_hash 永久保留");
        assert!(archived.verification_result, "verification_result 永久保留");
    }

    #[test]
    fn test_permanent_retention_all_items() {
        // SEC-M8: 所有 PermanentRetentionItem 均永久保留
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
    fn test_pruning_config_defaults() {
        let config = PruningConfig::new();
        assert_eq!(config.tx_prune_after_blocks, DEFAULT_TX_PRUNE_AFTER_BLOCKS);
        assert_eq!(
            config.vertex_prune_after_blocks,
            DEFAULT_VERTEX_PRUNE_AFTER_BLOCKS
        );
        assert_eq!(
            config.archive_node_min_count,
            DEFAULT_ARCHIVE_NODE_MIN_COUNT
        );
    }
}

// ===== SubTask 42.10: 节点角色分层集成测试 =====

mod subtask_42_10_node_roles {
    use super::*;

    #[test]
    fn test_archive_node_never_prunes() {
        assert!(!NodeRole::Archive.should_prune(), "Archive node 永不裁剪");
        assert!(NodeRole::Archive.retains_full_data());
        assert!(NodeRole::Archive.can_serve_historical_data());
    }

    #[test]
    fn test_full_node_prunes() {
        assert!(
            NodeRole::Full.should_prune(),
            "Full node 执行 Layer 1-3 裁剪"
        );
        assert!(!NodeRole::Full.retains_full_data());
        assert!(!NodeRole::Full.can_serve_historical_data());
    }

    #[test]
    fn test_light_node_only_headers() {
        assert!(!NodeRole::Light.should_prune());
        assert!(NodeRole::Light.is_light());
        assert!(!NodeRole::Light.retains_full_data());
    }

    #[test]
    fn test_request_historical_data_archive_available() {
        let request = HistoricalDataRequest {
            key: [0xAA; 32],
            request_type: HistoricalDataType::Transaction,
        };
        let response = handle_historical_data_request(&request, true, |_| Ok(Some(vec![1])));
        assert_eq!(response, HistoricalDataResponse::Found(vec![1]));
    }

    #[test]
    fn test_request_historical_data_non_archive_rejected() {
        let request = HistoricalDataRequest {
            key: [0xAA; 32],
            request_type: HistoricalDataType::Transaction,
        };
        let response = handle_historical_data_request(&request, false, |_| Ok(Some(vec![1])));
        assert!(matches!(response, HistoricalDataResponse::Unavailable(_)));
    }

    #[test]
    fn test_request_historical_data_unavailable() {
        let request = HistoricalDataRequest {
            key: [0xAA; 32],
            request_type: HistoricalDataType::ZkProof,
        };
        let response = handle_historical_data_request(&request, true, |_| Ok(None));
        assert!(matches!(response, HistoricalDataResponse::Unavailable(_)));
    }

    #[test]
    fn test_archive_node_sufficient_check() {
        assert!(is_archive_node_sufficient(5, 3));
        assert!(is_archive_node_sufficient(3, 3), "boundary == min");
        assert!(!is_archive_node_sufficient(2, 3));
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

// ===== SubTask 42.11: 模糊测试（>= 10000 随机输入）=====

mod subtask_42_11_fuzz {
    use super::*;

    /// 简单 LCG 伪随机数生成器（确定性，无外部依赖）。
    fn lcg_next(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *state
    }

    #[test]
    fn test_fuzz_force_advance_timeout_boundary() {
        // 模糊测试 force_advance 超时边界判定
        let mut state = 0x5C5C_DEAD_BEEF_u64;
        let turn_timeout = 30u64;
        let mut tested = 0u64;

        for _ in 0..10_000 {
            let last_action_height = 100 + (lcg_next(&mut state) % 500);
            let current_height = last_action_height + (lcg_next(&mut state) % 100);
            let mut game = make_game_with_hand(last_action_height);
            let player_addr = if lcg_next(&mut state).is_multiple_of(2) {
                make_addr(0x10)
            } else {
                make_addr(0x20)
            };
            let input = make_force_advance_input(player_addr, current_height);

            let elapsed = current_height - last_action_height;
            let result = apply_force_advance(&mut game, &input);

            if elapsed < turn_timeout {
                // 未超时 → 应返回 NotTimedOut（除非玩家已 fold 或不在游戏）
                if player_addr == make_addr(0x10) || player_addr == make_addr(0x20) {
                    assert!(
                        matches!(result, Err(ForceAdvanceError::NotTimedOut { .. })),
                        "elapsed={} < {} 应 NotTimedOut",
                        elapsed,
                        turn_timeout
                    );
                }
            } else {
                // 已超时（elapsed >= turn_timeout，SEC2-L6 <= 边界）→ 应成功
                if player_addr == make_addr(0x10) || player_addr == make_addr(0x20) {
                    assert!(
                        result.is_ok(),
                        "elapsed={} >= {} 应成功",
                        elapsed,
                        turn_timeout
                    );
                }
            }
            tested += 1;
        }
        assert!(tested >= 10_000, "模糊测试应覆盖 >= 10000 输入");
    }

    #[test]
    fn test_fuzz_force_checkin_forfeit_boundary() {
        // 模糊测试 H4 forfeit 边界判定
        let mut state = 0xF15C_CAFE_BABE_u64;
        let turn_timeout = 30u64;
        let mut tested = 0u64;

        for _ in 0..10_000 {
            let last_action_height = 100 + (lcg_next(&mut state) % 500);
            let current_height = last_action_height + (lcg_next(&mut state) % 200);
            let is_designated = lcg_next(&mut state).is_multiple_of(2);
            let mut game = make_game_with_forfeit_deposit(last_action_height, 5000);

            let input = make_force_checkin_input(current_height, is_designated, turn_timeout);
            let age = current_height - last_action_height;
            let boundary = if is_designated {
                turn_timeout * 2
            } else {
                turn_timeout
            };

            let result = apply_force_checkin(&mut game, &input);
            if let Ok(outcome) = result {
                if age <= boundary {
                    assert!(
                        outcome.should_forfeit,
                        "age={} <= boundary={} 应 forfeit",
                        age, boundary
                    );
                } else {
                    assert!(
                        !outcome.should_forfeit,
                        "age={} > boundary={} 不应 forfeit",
                        age, boundary
                    );
                }
            }
            tested += 1;
        }
        assert!(tested >= 10_000);
    }

    #[test]
    fn test_fuzz_challenge_delta_hash_comparison() {
        // 模糊测试 challenge_delta 哈希比对
        let mut state = 0xA55C_1234_5678_u64;
        let mut tested = 0u64;

        for _ in 0..10_000 {
            let delta_len = (lcg_next(&mut state) % 64) as usize;
            let claimed_delta: Vec<u8> = (0..delta_len)
                .map(|_| (lcg_next(&mut state) & 0xFF) as u8)
                .collect();
            let on_chain_delta: Vec<u8> = (0..delta_len)
                .map(|_| (lcg_next(&mut state) & 0xFF) as u8)
                .collect();

            let claimed_hash = hash_state_delta(&claimed_delta);
            let on_chain_hash = hash_state_delta(&on_chain_delta);

            let mut game = make_game_with_forfeit_deposit(100, 5000);
            let tx = make_challenge_delta_tx(claimed_delta, 1000);
            let result = apply_challenge_delta(
                &mut game,
                &tx,
                on_chain_hash,
                DEFAULT_CHALLENGE_REWARD_RATIO,
            );

            if claimed_hash == on_chain_hash {
                assert!(
                    matches!(result, Err(PokerL1Error::ChallengeFailed)),
                    "哈希一致 → 挑战失败"
                );
            } else {
                assert!(
                    matches!(result, Err(PokerL1Error::ChallengeSucceeded)),
                    "哈希不一致 → 挑战成立"
                );
            }
            tested += 1;
        }
        assert!(tested >= 10_000);
    }

    #[test]
    fn test_fuzz_pruning_eligibility() {
        // 模糊测试裁剪资格判定
        let mut state = 0x5CF1_2001_0001_u64;
        let mut tested = 0u64;

        for _ in 0..10_000 {
            let block_age = lcg_next(&mut state) % 20_000;
            let tx_window = 1000;
            let vertex_window = 10_000;
            let all_settled = lcg_next(&mut state).is_multiple_of(2);
            let dispute_expired = lcg_next(&mut state).is_multiple_of(2);
            let archive_count = (lcg_next(&mut state) % 10) as u32;

            // tx 裁剪
            let tx_result =
                check_tx_pruning_eligibility(block_age, tx_window, all_settled, dispute_expired);
            if block_age >= tx_window && all_settled && dispute_expired {
                assert!(tx_result.can_prune(), "满足全部条件应可裁剪 tx");
            } else {
                assert!(!tx_result.can_prune(), "条件不满足不可裁剪 tx");
            }

            // vertex 裁剪
            let vertex_result = check_vertex_pruning_eligibility(block_age, vertex_window);
            if block_age >= vertex_window {
                assert!(vertex_result.can_prune());
            } else {
                assert!(!vertex_result.can_prune());
            }

            // zk proof 裁剪
            let zk_result =
                check_zk_proof_pruning_eligibility(all_settled, dispute_expired, archive_count, 3);
            if all_settled && dispute_expired && archive_count >= 3 {
                assert!(zk_result.can_prune());
            } else {
                assert!(!zk_result.can_prune());
            }

            tested += 1;
        }
        assert!(tested >= 10_000);
    }

    #[test]
    fn test_fuzz_forfeit_distribution_invariants() {
        // 模糊测试 forfeit 分配不变量：total_distributed == forfeit_amount
        let mut state = 0x5CD1_5801_1001_u64;
        let mut tested = 0u64;

        for _ in 0..10_000 {
            let forfeit_amount = 1 + (lcg_next(&mut state) % 10_000);
            let has_challenger = lcg_next(&mut state).is_multiple_of(2);
            let challenger = if has_challenger {
                Some(make_addr(0x02))
            } else {
                None
            };
            let challenger_reward = lcg_next(&mut state) % (forfeit_amount + 1);
            let victim_count = 1 + (lcg_next(&mut state) % 5) as usize;
            let victims: Vec<(poker_l1::Address, u64)> = (0..victim_count)
                .map(|i| {
                    let buy_in = 1 + (lcg_next(&mut state) % 1000);
                    (make_addr(0x10 + i as u8), buy_in)
                })
                .collect();

            let dist = compute_forfeit_distribution(
                forfeit_amount,
                challenger,
                challenger_reward,
                &victims,
            );

            // 不变量：分配总额 == forfeit_amount（舍入余额归最后一个 victim）
            assert_eq!(
                dist.total_distributed, forfeit_amount,
                "分配总额必须等于 forfeit_amount，tested={}",
                tested
            );
            // challenger_reward 不超过 forfeit_amount
            assert!(dist.challenger_reward <= forfeit_amount);
            tested += 1;
        }
        assert!(tested >= 10_000);
    }

    #[test]
    fn test_fuzz_designated_operator_bond_validation() {
        // 模糊测试 designated_operator_bond 校验
        let mut state = 0x5C80_D001_0001_u64;
        let mut tested = 0u64;

        for _ in 0..10_000 {
            let governed = 1 + (lcg_next(&mut state) % 10_000);
            let bond = lcg_next(&mut state) % (governed + 5_000); // 可能 != governed 或 < total_buy_in
            let total_buy_in = 1 + (lcg_next(&mut state) % 5_000);

            let result = validate_designated_operator_bond(bond, governed, total_buy_in);

            if bond != governed {
                assert!(
                    matches!(result, Err(PokerL1Error::InvalidBondAmount { .. })),
                    "bond != governed 应 InvalidBondAmount"
                );
            } else if bond < total_buy_in {
                assert!(
                    matches!(result, Err(PokerL1Error::InsufficientOperatorBond { .. })),
                    "bond < total_buy_in 应 InsufficientOperatorBond"
                );
            } else {
                assert!(
                    result.is_ok(),
                    "bond == governed && bond >= total_buy_in 应通过"
                );
            }
            tested += 1;
        }
        assert!(tested >= 10_000);
    }

    #[test]
    fn test_fuzz_proof_hash_deterministic() {
        // 模糊测试 proof_hash 确定性
        let mut state = 0x5CA5_5001_0001_u64;
        let mut tested = 0u64;

        for _ in 0..10_000 {
            let proof_len = (lcg_next(&mut state) % 128) as usize;
            let delta_len = (lcg_next(&mut state) % 128) as usize;
            let ack_len = (lcg_next(&mut state) % 128) as usize;
            let proof: Vec<u8> = (0..proof_len)
                .map(|_| (lcg_next(&mut state) & 0xFF) as u8)
                .collect();
            let delta: Vec<u8> = (0..delta_len)
                .map(|_| (lcg_next(&mut state) & 0xFF) as u8)
                .collect();
            let ack: Vec<u8> = (0..ack_len)
                .map(|_| (lcg_next(&mut state) & 0xFF) as u8)
                .collect();

            let h1 = compute_proof_hash(&proof, &delta, &ack);
            let h2 = compute_proof_hash(&proof, &delta, &ack);
            assert_eq!(h1, h2, "相同输入应产生相同 proof_hash");
            tested += 1;
        }
        assert!(tested >= 10_000);
    }
}
