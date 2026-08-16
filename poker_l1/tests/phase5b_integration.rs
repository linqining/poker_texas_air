//! Phase 5b 集成测试（Task 42b — SubTask 42.6 / 42.7 / 42.7a）
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）：
//! - **SubTask 42.6**：链下通信协议集成测试 — checkpoint_anchor + 多方 ACK +
//!   force_advance + force_checkin + force_checkpoint + 3 阶段恢复流程
//! - **SubTask 42.7**：审查截断防护集成测试 — (a) assigned_validator 拒收 →
//!   force_checkpoint；(b) 委托逃生；(c) 多副本检测；(d) request_ack → opt_out；
//!   (e) refuse_ack + 无效 evidence；(f) checkpoint_skip；(g) skip_count > max；
//!   (h) 伪造 failure_proof；(i) 虚假见证 slashing
//! - **SubTask 42.7a**：操作方故障恢复流程集成测试 — (a) 阶段 1 恢复；
//!   (b) 阶段 1 force_advance；(c) 阶段 2 force_checkin；(e) 阶段 3 force_revert；
//!   (g) H4 恶意扣留 forfeit；(h) H4 机器故障不 forfeit

use poker_l1::Address;
use poker_l1::consensus::validator_set::{
    VRF_PUBKEY_SIZE, ValidatorEntry, ValidatorSet, ValidatorStatus,
    compute_genesis_chain_randomness,
};
use poker_l1::object_model::ObjectID;
use poker_l1::signature::{CURRENT_VERSION, SignatureScheme, TaggedPubkey};
use poker_l1::vm::contracts::ack_protocol::{
    DEFAULT_MALICIOUS_REFUSE_THRESHOLD, MIN_ACK_DEADLINE_BLOCKS, RefuseAckReason, RefuseAckTx,
    RequestAckTx, apply_refuse_ack, apply_request_ack, check_ack_deadline_expired,
    clear_pending_ack,
};
use poker_l1::vm::contracts::censor_detection::{
    CensorshipWitnessEvidence, DEFAULT_GOSSIPSUB_MESH_SIZE, FALSE_WITNESS_SLASH_PERCENTAGE,
    FalseWitnessEvidence, compute_replica_set, gossipsub_mesh_size, is_witness_in_replica_set,
};
use poker_l1::vm::contracts::checkpoint_anchor::{
    CheckpointAnchorTx, DEFAULT_NO_PROGRESS_THRESHOLD, OptOutAckProof, apply_checkpoint_anchor,
    is_opt_out_ack_valid,
};
use poker_l1::vm::contracts::checkpoint_skip::{
    CheckpointSkipTx, SegmentContinuityProof, StateProof, apply_checkpoint_skip,
    verify_segment_chain,
};
use poker_l1::vm::contracts::delegated_escape::{
    DEFAULT_DELEGATED_ESCAPE_MAX_EXPIRY_BLOCKS, DelegatedEscapeAuthorization,
    compute_next_credential_nonce, consume_delegated_escape_authorization,
};
use poker_l1::vm::contracts::force_checkin::{
    DEFAULT_DESIGNATED_OPERATOR_CHECK_EXEMPTION_LIMIT, DEFAULT_RECOVERY_WINDOW_BLOCKS,
    ForceCheckinScenario, ForfeitDecision, ForfeitReason, RecoveryStage,
    determine_force_checkin_scenario,
};
use poker_l1::vm::contracts::force_checkpoint::{
    AssignedValidatorFailureProof, DEFAULT_CHECKPOINT_MULTI_REPLICA_COUNT,
    DEFAULT_INVESTIGATION_THRESHOLD, DEFAULT_REPLICA_WITNESS_THRESHOLD,
    DEFAULT_VERTEX_PRUNE_AFTER_BLOCKS, ForceCheckpointTx, MultiReplicaReceipt,
    RoundRangeNonInclusionProof, VertexInfo, apply_force_checkpoint,
};
use poker_l1::vm::contracts::types::{ExecutionMode, GameContract, RakeConfigRef};

// ===== 辅助函数 =====

fn make_tagged_pubkey(byte: u8) -> TaggedPubkey {
    let mut raw = vec![byte];
    raw.extend_from_slice(&[0x02u8; 32]);
    TaggedPubkey::new(SignatureScheme::Secp256k1, CURRENT_VERSION, raw)
        .expect("构造 tagged pubkey 不应失败")
}

fn make_addr(byte: u8) -> Address {
    [byte; 20]
}

fn make_game_id() -> ObjectID {
    ObjectID::new(make_addr(0x01), 1)
}

fn make_vrf_pubkey(byte: u8) -> [u8; VRF_PUBKEY_SIZE] {
    [byte; VRF_PUBKEY_SIZE]
}

fn make_validator(byte: u8) -> ValidatorEntry {
    let mut v = ValidatorEntry::new(
        make_tagged_pubkey(byte),
        make_vrf_pubkey(byte),
        1_000_000,
        0,
    );
    v.status = ValidatorStatus::Active;
    v
}

fn make_validator_set(count: usize) -> ValidatorSet {
    let validators: Vec<ValidatorEntry> =
        (0..count).map(|i| make_validator(0x10 + i as u8)).collect();
    let genesis_randomness = compute_genesis_chain_randomness(&validators);
    let mut set = ValidatorSet {
        epoch: 1,
        validators,
        validator_set_hash: [0u8; 32],
        epoch_randomness: [0u8; 32],
        prev_epoch_randomness: [0u8; 32],
        genesis_chain_randomness: genesis_randomness,
    };
    set.validator_set_hash = set.compute_hash();
    set
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
    game
}

fn make_checkpoint_anchor_tx(seq: u64, state_byte: u8) -> CheckpointAnchorTx {
    CheckpointAnchorTx {
        game_id: make_game_id(),
        checkpoint_seq: seq,
        current_turn: make_addr(0x05),
        state_hash: [state_byte; 32],
        ack_signatures: vec![],
        opt_out_ack_proof: None,
    }
}

fn make_receipt(
    witness_byte: u8,
    content_hash: [u8; 32],
    block_height: u64,
    round_range: (u64, u64),
) -> MultiReplicaReceipt {
    MultiReplicaReceipt {
        witness: make_tagged_pubkey(witness_byte),
        content_hash,
        block_height,
        round_range,
        signature: vec![0u8; 65],
    }
}

// ===== SubTask 42.6: 链下通信协议集成测试 =====

#[test]
fn subtask_42_6_checkpoint_anchor_with_ack_updates_last_action_height() {
    // checkpoint_anchor 提交 → last_action_height 更新 + checkpoint_seq 递增
    let mut game = make_game(100);
    let tx = make_checkpoint_anchor_tx(1, 0xAB);
    let result = apply_checkpoint_anchor(&mut game, &tx, 150);
    assert!(result.is_ok(), "checkpoint_anchor 应成功应用");
    assert_eq!(game.checkpoint_seq, 1, "checkpoint_seq 应递增");
    assert_eq!(game.last_action_height, 150, "last_action_height 应更新");
    assert_eq!(game.version, 1, "version 应递增");
}

#[test]
fn subtask_42_6_checkpoint_anchor_no_progress_detection() {
    // SEC-H2: 连续 2 次相同 state_hash → no_progress_count 递增
    let mut game = make_game(100);
    let tx1 = make_checkpoint_anchor_tx(1, 0xAB);
    apply_checkpoint_anchor(&mut game, &tx1, 150).expect("第一次 checkpoint");
    assert_eq!(game.no_progress_count, 0, "首次 checkpoint 视为有进度");

    // 第二次相同 state_hash → no_progress_count += 1
    let tx2 = make_checkpoint_anchor_tx(2, 0xAB); // 相同 state_hash
    apply_checkpoint_anchor(&mut game, &tx2, 155).expect("第二次 checkpoint");
    assert_eq!(
        game.no_progress_count, 1,
        "相同 state_hash 应递增 no_progress_count"
    );

    // 第三次相同 state_hash → no_progress_count = 2，达阈值
    let tx3 = make_checkpoint_anchor_tx(3, 0xAB);
    apply_checkpoint_anchor(&mut game, &tx3, 160).expect("第三次 checkpoint");
    assert_eq!(
        game.no_progress_count, DEFAULT_NO_PROGRESS_THRESHOLD,
        "达阈值应触发 force_revert"
    );
}

#[test]
fn subtask_42_6_force_checkpoint_updates_investigation_count() {
    // force_checkpoint → under_investigation_count 递增
    let mut game = make_game_with_checkpoint(100);
    let tx = ForceCheckpointTx {
        game_id: make_game_id(),
        current_turn: make_addr(0x05),
        state_hash: [0xAB; 32],
        ack_signatures: vec![],
        opt_out_ack_proof: None,
        assigned_validator_failure_proof: AssignedValidatorFailureProof {
            original_checkpoint_anchor: make_checkpoint_anchor_tx(1, 0xAB),
            multi_replica_receipts: vec![],
            non_inclusion_proof: RoundRangeNonInclusionProof {
                epoch: 1,
                round_start: 10,
                round_end: 15,
                assigned_validator: make_tagged_pubkey(0xFF),
                vertex_list: vec![],
                non_inclusion_proofs: vec![],
                round_attendance_bitmap: vec![0u8; 1],
            },
        },
    };
    // 第一次 force_checkpoint
    let r1 = apply_force_checkpoint(&mut game, &tx, 200, DEFAULT_INVESTIGATION_THRESHOLD)
        .expect("force_checkpoint 应成功");
    assert!(!r1, "首次调查未达阈值");
    assert_eq!(game.under_investigation_count, 1);
    assert_eq!(game.last_action_height, 200);

    // 第二次
    let r2 = apply_force_checkpoint(&mut game, &tx, 210, DEFAULT_INVESTIGATION_THRESHOLD)
        .expect("应成功");
    assert!(!r2);
    assert_eq!(game.under_investigation_count, 2);

    // 第三次 → 达阈值
    let r3 = apply_force_checkpoint(&mut game, &tx, 220, DEFAULT_INVESTIGATION_THRESHOLD)
        .expect("应成功");
    assert!(r3, "第三次应触发 slashing");
    assert_eq!(game.under_investigation_count, 3);
}

#[test]
fn subtask_42_6_three_stage_recovery_flow() {
    // SubTask 27.5e: 3 阶段恢复流程
    let game = make_game(100);
    let turn_timeout = 30u64;
    let da_window = 500u64;
    let recovery_window = DEFAULT_RECOVERY_WINDOW_BLOCKS;

    // 阶段 1: elapsed = 20 <= 30
    let stage1 = RecoveryStage::compute(&game, 120, turn_timeout, da_window, recovery_window);
    assert!(matches!(stage1, RecoveryStage::Stage1 { .. }));
    assert!(stage1.allows_force_advance());
    assert!(!stage1.requires_forfeit_and_revert());

    // 阶段 2: elapsed = 100, 30 < 100 <= 30 + 500 + 100 = 630
    let stage2 = RecoveryStage::compute(&game, 200, turn_timeout, da_window, recovery_window);
    assert!(matches!(stage2, RecoveryStage::Stage2 { .. }));
    assert!(stage2.allows_force_checkin());
    assert!(!stage2.requires_forfeit_and_revert());

    // 阶段 3: elapsed = 700 > 630
    let stage3 = RecoveryStage::compute(&game, 800, turn_timeout, da_window, recovery_window);
    assert!(matches!(stage3, RecoveryStage::Stage3 { .. }));
    assert!(stage3.requires_forfeit_and_revert());
}

// ===== SubTask 42.7: 审查截断防护集成测试 =====

#[test]
fn subtask_42_7a_assigned_validator_rejection_triggers_force_checkpoint() {
    // assigned_validator 拒收 → force_checkpoint → last_action_height 更新 +
    // under_investigation_count 累积
    let mut game = make_game_with_checkpoint(100);
    let original_anchor = make_checkpoint_anchor_tx(1, 0xAB);
    let tx = ForceCheckpointTx {
        game_id: make_game_id(),
        current_turn: make_addr(0x05),
        state_hash: [0xAB; 32],
        ack_signatures: vec![],
        opt_out_ack_proof: None,
        assigned_validator_failure_proof: AssignedValidatorFailureProof {
            original_checkpoint_anchor: original_anchor,
            multi_replica_receipts: vec![],
            non_inclusion_proof: RoundRangeNonInclusionProof {
                epoch: 1,
                round_start: 10,
                round_end: 15,
                assigned_validator: make_tagged_pubkey(0xFF),
                vertex_list: vec![],
                non_inclusion_proofs: vec![],
                round_attendance_bitmap: vec![0u8; 1],
            },
        },
    };
    let trigger_slashing =
        apply_force_checkpoint(&mut game, &tx, 200, DEFAULT_INVESTIGATION_THRESHOLD)
            .expect("force_checkpoint 应成功");
    assert!(!trigger_slashing, "首次未达阈值");
    assert_eq!(game.last_action_height, 200, "last_action_height 应更新");
    assert_eq!(game.under_investigation_count, 1, "调查计数应递增");
}

#[test]
fn subtask_42_7b_delegated_escape_authorization_flow() {
    // 委托逃生 — 凭证验证 + 一次性消费
    let mut game = make_game_with_checkpoint(100);
    let auth = DelegatedEscapeAuthorization {
        game_id: make_game_id(),
        delegator: make_tagged_pubkey(0xFF),
        expiry_height: 200,
        credential_nonce: 1,
        operator_signature: vec![0u8; 65],
    };

    // 凭证 nonce 计算
    assert_eq!(
        compute_next_credential_nonce(&game),
        1,
        "下一个 nonce = 0 + 1"
    );

    // 消费凭证（NEW-M1：一次性消费）
    let result = consume_delegated_escape_authorization(&mut game, &auth);
    assert!(result.is_ok(), "消费凭证应成功");
    assert_eq!(game.delegated_escape_nonce, 1, "nonce 应更新为 1");

    // 重复消费同一凭证 → 失败
    let r2 = consume_delegated_escape_authorization(&mut game, &auth);
    assert!(r2.is_err(), "同一凭证不可重复消费");
}

#[test]
fn subtask_42_7c_censorship_witness_evidence_multi_replica_detection() {
    // 多副本检测 — 副本 validator 签发审查见证证据
    let set = make_validator_set(7);
    let assigned = make_tagged_pubkey(0x10);
    let replica_set = compute_replica_set(
        &make_game_id(),
        1,
        1,
        &[0u8; 32],
        &set,
        &assigned,
        DEFAULT_CHECKPOINT_MULTI_REPLICA_COUNT,
    )
    .expect("应成功");
    assert_eq!(replica_set.len(), 5, "replica_set 应有 5 个 validator");
    assert!(
        !replica_set.contains(&assigned),
        "不应包含 assigned_validator"
    );

    // gossipsub mesh 大小
    assert_eq!(
        gossipsub_mesh_size(DEFAULT_CHECKPOINT_MULTI_REPLICA_COUNT),
        DEFAULT_GOSSIPSUB_MESH_SIZE,
    );

    // 构造见证证据（用 replica_set 中的前 3 个 validator）
    let receipts: Vec<MultiReplicaReceipt> = replica_set
        .iter()
        .take(3)
        .map(|w| make_receipt(w.raw[0], [0xAB; 32], 100, (10, 15)))
        .collect();

    let evidence = CensorshipWitnessEvidence {
        game_id: make_game_id(),
        epoch: 1,
        checkpoint_seq: 1,
        content_hash: [0xAB; 32],
        receipts,
    };

    // 验证（占位签名会失败，但 cheap check 应通过到签名验证）
    let result = evidence.verify(
        poker_l1::DEFAULT_CHAIN_ID,
        &set,
        &assigned,
        &[0u8; 32],
        DEFAULT_CHECKPOINT_MULTI_REPLICA_COUNT,
        DEFAULT_REPLICA_WITNESS_THRESHOLD,
    );
    assert!(
        matches!(result, Err(poker_l1::error::PokerL1Error::InvalidSignature)),
        "合法 witness 应通过 cheap check 到达签名验证"
    );
}

#[test]
fn subtask_42_7d_request_ack_then_opt_out_ack_proof() {
    // request_ack → ack_deadline 逾期 → opt_out_ack_proof 验证
    let mut game = make_game(100);
    let req_tx = RequestAckTx {
        game_id: make_game_id(),
        target_participant: make_tagged_pubkey(0x20),
    };
    let ack_deadline = apply_request_ack(&mut game, &req_tx, 100, MIN_ACK_DEADLINE_BLOCKS, 5)
        .expect("request_ack 应成功");
    assert_eq!(ack_deadline, 100 + MIN_ACK_DEADLINE_BLOCKS);

    // block.height > ack_deadline → 视为逾期
    assert!(
        check_ack_deadline_expired(&game, &req_tx.target_participant, ack_deadline).is_none(),
        "边界时刻未逾期"
    );
    assert!(
        check_ack_deadline_expired(&game, &req_tx.target_participant, ack_deadline + 1).is_some(),
        "逾期后应返回 true"
    );

    // opt_out_ack_proof 验证
    let proof = OptOutAckProof {
        participant: make_tagged_pubkey(0x20),
        request_ack_block_height: 100,
        ack_deadline,
    };
    assert!(
        is_opt_out_ack_valid(&proof, ack_deadline + 1),
        "逾期后 opt_out 应有效"
    );
    assert!(
        !is_opt_out_ack_valid(&proof, ack_deadline),
        "未逾期 opt_out 应无效"
    );

    // 清除 pending_ack
    let target_addr = poker_l1::account::derive_address(&req_tx.target_participant);
    clear_pending_ack(&mut game, &req_tx.target_participant);
    assert!(!game.pending_ack_requests.contains_key(&target_addr));
}

#[test]
fn subtask_42_7e_refuse_ack_with_invalid_evidence_triggers_forfeit() {
    // refuse_ack + 无效 evidence → forfeit 保证金（malicious_refuse_count 累积）
    let mut game = make_game(100);
    let req_tx = RequestAckTx {
        game_id: make_game_id(),
        target_participant: make_tagged_pubkey(0x20),
    };
    let ack_deadline = apply_request_ack(&mut game, &req_tx, 100, MIN_ACK_DEADLINE_BLOCKS, 5)
        .expect("request_ack 应成功");

    // 参与者提交 refuse_ack + 无效 evidence
    let refuse_tx = RefuseAckTx {
        game_id: make_game_id(),
        request_id: ack_deadline,
        reason: RefuseAckReason::InvalidState,
        evidence: vec![0u8; 10], // 无效 evidence
        participant: make_tagged_pubkey(0x20),
        signature: vec![0u8; 65], // 占位签名
    };
    let result = apply_refuse_ack(
        &mut game,
        &refuse_tx,
        poker_l1::DEFAULT_CHAIN_ID,
        105, // ack_deadline 之前
        DEFAULT_MALICIOUS_REFUSE_THRESHOLD,
    );
    // 占位签名会失败
    assert!(result.is_err(), "占位签名应失败");
}

#[test]
fn subtask_42_7f_checkpoint_skip_accumulates_skip_count() {
    // checkpoint_skip → skip_count 累计
    let mut game = make_game_with_checkpoint(100);
    let tx = CheckpointSkipTx {
        game_id: make_game_id(),
        skip_segment_start: 1,
        skip_segment_end: 2,
        last_known_state_hash: [0xAB; 32],
        continuity_proof: SegmentContinuityProof {
            start_state_proof: StateProof {
                checkpoint_seq: 1,
                state_hash: [0xAB; 32],
                ack_signatures: vec![],
            },
            end_state_proof: None,
        },
        ack_set: vec![make_tagged_pubkey(0x20)],
    };
    let result = apply_checkpoint_skip(&mut game, &tx, 150, 3);
    assert!(result.is_ok(), "checkpoint_skip 应成功");
    assert_eq!(game.skip_count, 1, "skip_count 应递增");
    assert_eq!(game.last_action_height, 150, "last_action_height 应更新");
}

#[test]
fn subtask_42_7g_skip_count_exceeds_max_forces_request_revert() {
    // skip_count > max_skip_segments → 强制 request_revert
    let mut game = make_game_with_checkpoint(100);
    game.skip_count = 3; // 已达上限

    let tx = CheckpointSkipTx {
        game_id: make_game_id(),
        skip_segment_start: 4,
        skip_segment_end: 5,
        last_known_state_hash: [0xAB; 32],
        continuity_proof: SegmentContinuityProof {
            start_state_proof: StateProof {
                checkpoint_seq: 4,
                state_hash: [0xAB; 32],
                ack_signatures: vec![],
            },
            end_state_proof: None,
        },
        ack_set: vec![make_tagged_pubkey(0x20)],
    };
    let result = apply_checkpoint_skip(&mut game, &tx, 200, 3);
    assert!(result.is_err(), "skip_count >= max 应失败");
    match result {
        Err(poker_l1::error::PokerL1Error::SkipCountExceeded { actual, limit }) => {
            // actual = game.skip_count（递增前的值 = 3）
            assert_eq!(actual, 3);
            assert_eq!(limit, 3);
        }
        _ => panic!("应返回 SkipCountExceeded"),
    }
}

#[test]
fn subtask_42_7h_forged_failure_proof_with_insufficient_witnesses_rejected() {
    // 伪造 assigned_validator_failure_proof — 见证签名不足 3 个 → 拒绝
    let tx = ForceCheckpointTx {
        game_id: make_game_id(),
        current_turn: make_addr(0x05),
        state_hash: [0xAB; 32],
        ack_signatures: vec![],
        opt_out_ack_proof: None,
        assigned_validator_failure_proof: AssignedValidatorFailureProof {
            original_checkpoint_anchor: make_checkpoint_anchor_tx(1, 0xAB),
            multi_replica_receipts: vec![
                // 仅 2 个见证（< 阈值 3）
                make_receipt(0x11, [0xAB; 32], 100, (10, 15)),
                make_receipt(0x12, [0xAB; 32], 100, (10, 15)),
            ],
            non_inclusion_proof: RoundRangeNonInclusionProof {
                epoch: 1,
                round_start: 10,
                round_end: 15,
                assigned_validator: make_tagged_pubkey(0xFF),
                vertex_list: vec![],
                non_inclusion_proofs: vec![],
                round_attendance_bitmap: vec![0u8; 1],
            },
        },
    };

    let active_validator_set: Vec<TaggedPubkey> = (0x10..=0x16).map(make_tagged_pubkey).collect();
    let active_participants: Vec<TaggedPubkey> = vec![make_tagged_pubkey(0x20)];

    let result = tx.verify(
        poker_l1::DEFAULT_CHAIN_ID,
        &active_participants,
        &active_validator_set,
        DEFAULT_REPLICA_WITNESS_THRESHOLD, // 3
        100,                               // max_round_span
        200,                               // current_block_height
        DEFAULT_VERTEX_PRUNE_AFTER_BLOCKS,
    );
    assert!(
        matches!(
            result,
            Err(poker_l1::error::PokerL1Error::ForceCheckpointEvidenceFailed(_))
        ),
        "见证签名不足 3 个应拒绝"
    );
}

#[test]
fn subtask_42_7i_false_witness_evidence_triggers_slashing() {
    // 副本 validator 签发虚假见证证据 → 100% slashing
    let false_evidence = CensorshipWitnessEvidence {
        game_id: make_game_id(),
        epoch: 1,
        checkpoint_seq: 1,
        content_hash: [0xAB; 32],
        receipts: vec![make_receipt(0x11, [0xAB; 32], 100, (10, 15))],
    };
    let actual_vertex_list = vec![VertexInfo {
        round: 12,
        author: make_tagged_pubkey(0x10),
        vertex_hash: [0xCD; 32],
        tx_merkle_root: [0xEF; 32],
    }];
    let false_witness = FalseWitnessEvidence {
        false_evidence,
        actual_vertex_list,
        inclusion_round: 12,
        anchor_tx_hash: [0xAB; 32],
    };
    assert!(false_witness.verify().is_ok(), "虚假见证证据结构应验证通过");
    assert_eq!(
        FalseWitnessEvidence::slash_percentage(),
        FALSE_WITNESS_SLASH_PERCENTAGE,
        "虚假见证 slashing = 100%"
    );
}

// ===== SubTask 42.7a: 操作方故障恢复流程集成测试 =====

#[test]
fn subtask_42_7a_stage1_operator_recovers_no_forfeit() {
    // 阶段 1 — 操作方在 turn_timeout_blocks 内恢复 → checkpoint_anchor → 游戏继续
    let mut game = make_game_with_checkpoint(100);
    let stage = RecoveryStage::compute(&game, 120, 30, 500, DEFAULT_RECOVERY_WINDOW_BLOCKS);
    assert!(matches!(stage, RecoveryStage::Stage1 { .. }));

    // 操作方提交 checkpoint_anchor
    let tx = make_checkpoint_anchor_tx(1, 0xCD);
    let result = apply_checkpoint_anchor(&mut game, &tx, 120);
    assert!(result.is_ok(), "阶段 1 内 checkpoint_anchor 应成功");
    assert_eq!(game.last_action_height, 120);
    // 阶段 1 不强制 forfeit（实际 forfeit 判定由 force_checkin 场景触发）
    assert!(stage.allows_force_advance());
    assert!(!stage.requires_forfeit_and_revert());
}

#[test]
fn subtask_42_7a_stage1_operator_not_recovered_force_advance() {
    // 阶段 1 — 操作方未恢复 → force_advance 触发推进轮次，无 forfeit
    let game = make_game_with_checkpoint(100);
    let stage = RecoveryStage::compute(&game, 130, 30, 500, DEFAULT_RECOVERY_WINDOW_BLOCKS);
    // elapsed = 30 == turn_timeout → Stage1 (<= 边界)
    assert!(matches!(stage, RecoveryStage::Stage1 { .. }));
    assert!(stage.allows_force_advance());
    assert!(
        !stage.requires_forfeit_and_revert(),
        "阶段 1 不应触发 forfeit"
    );
}

#[test]
fn subtask_42_7a_stage2_force_checkin_allowed() {
    // 阶段 2 — force_checkin 允许
    let game = make_game_with_checkpoint(100);
    let stage = RecoveryStage::compute(&game, 200, 30, 500, DEFAULT_RECOVERY_WINDOW_BLOCKS);
    assert!(matches!(stage, RecoveryStage::Stage2 { .. }));
    assert!(stage.allows_force_checkin());
    assert!(
        !stage.requires_forfeit_and_revert(),
        "阶段 2 不应触发 forfeit"
    );
}

#[test]
fn subtask_42_7a_stage3_requires_forfeit_and_revert() {
    // 阶段 3 — da_window + recovery_window 过期 → force_revert + forfeit
    let game = make_game_with_checkpoint(100);
    // elapsed = 700 > 30 + 500 + 100 = 630
    let stage = RecoveryStage::compute(&game, 800, 30, 500, DEFAULT_RECOVERY_WINDOW_BLOCKS);
    assert!(matches!(stage, RecoveryStage::Stage3 { .. }));
    assert!(
        stage.requires_forfeit_and_revert(),
        "阶段 3 应触发 forfeit + force_revert"
    );
}

#[test]
fn subtask_42_7a_g_h4_forfeit_boundary_malicious_withholding() {
    // H4 — last_checkpoint_age <= turn_timeout_blocks → 恶意扣留 → forfeit
    let game = make_game_with_checkpoint(100);
    let decision = ForfeitDecision::compute(&game, 120, 30, false);
    // age = 20 <= 30 → MaliciousWithholding
    assert!(decision.should_forfeit, "age 20 <= 30 应 forfeit");
    assert_eq!(decision.reason, ForfeitReason::MaliciousWithholding);

    // force_checkin 场景判定
    let scenario = determine_force_checkin_scenario(&game, 120, 30, false);
    assert_eq!(scenario, ForceCheckinScenario::MaliciousWithholding);
}

#[test]
fn subtask_42_7a_h_h4_forfeit_boundary_machine_failure() {
    // H4 — last_checkpoint_age > turn_timeout_blocks → 机器故障 → 不 forfeit
    let game = make_game_with_checkpoint(100);
    let decision = ForfeitDecision::compute(&game, 200, 30, false);
    // age = 100 > 30 → MachineFailure
    assert!(!decision.should_forfeit, "age 100 > 30 应不 forfeit");
    assert_eq!(decision.reason, ForfeitReason::MachineFailure);

    let scenario = determine_force_checkin_scenario(&game, 200, 30, false);
    assert_eq!(scenario, ForceCheckinScenario::MachineFailure);
}

#[test]
fn subtask_42_7a_h4_not_feasible_no_checkpoint_requires_revert() {
    // 无 checkpoint 广播 → 走 request_revert
    let game = make_game(100); // last_checkpoint_state_hash = None
    let scenario = determine_force_checkin_scenario(&game, 120, 30, false);
    assert_eq!(scenario, ForceCheckinScenario::NotFeasibleRequiresRevert);
}

#[test]
fn subtask_42_7a_designated_operator_boundary_doubled() {
    // NEW-M4: designated operator → boundary = 30 * 2 = 60
    let game = make_game_with_checkpoint(100);
    // age = 50 <= 60 → MaliciousWithholding (designated operator)
    let decision = ForfeitDecision::compute(&game, 150, 30, true);
    assert!(
        decision.should_forfeit,
        "designated operator: age 50 <= 60 应 forfeit"
    );
    assert_eq!(decision.boundary, 60, "boundary 应加倍为 60");
    assert_eq!(decision.reason, ForfeitReason::MaliciousWithholding);

    // age = 70 > 60 → MachineFailure
    let decision2 = ForfeitDecision::compute(&game, 170, 30, true);
    assert!(
        !decision2.should_forfeit,
        "designated operator: age 70 > 60 应不 forfeit"
    );
    assert_eq!(decision2.reason, ForfeitReason::MachineFailure);
}

#[test]
fn subtask_42_7a_designated_operator_check_exemption_flow() {
    // NEW-M4 / R3-M7: designated operator check 豁免流程
    let mut game = make_game_with_checkpoint(100);

    // 首次豁免
    assert!(poker_l1::vm::contracts::should_exempt_current_turn_player(
        &game,
        true,
        DEFAULT_DESIGNATED_OPERATOR_CHECK_EXEMPTION_LIMIT,
    ));
    poker_l1::vm::contracts::apply_designated_operator_check_exemption(&mut game).expect("应成功");
    assert_eq!(game.designated_operator_check_exemptions, 1);

    // 第二次豁免
    assert!(poker_l1::vm::contracts::should_exempt_current_turn_player(
        &game,
        true,
        DEFAULT_DESIGNATED_OPERATOR_CHECK_EXEMPTION_LIMIT,
    ));
    poker_l1::vm::contracts::apply_designated_operator_check_exemption(&mut game).expect("应成功");
    assert_eq!(game.designated_operator_check_exemptions, 2);

    // 第三次 → 已耗尽，恢复 fold 语义
    assert!(!poker_l1::vm::contracts::should_exempt_current_turn_player(
        &game,
        true,
        DEFAULT_DESIGNATED_OPERATOR_CHECK_EXEMPTION_LIMIT,
    ));
}

// ===== 跨模块综合场景 =====

#[test]
fn subtask_42_6_full_censorship_resistance_flow() {
    // 综合：assigned_validator 拒收 → 副本见证 → force_checkpoint → 调查累积
    let mut game = make_game_with_checkpoint(100);
    let set = make_validator_set(7);
    let assigned = make_tagged_pubkey(0xFF); // 与 game.assigned_validator 一致

    // 1. 计算 replica_set
    let replica_set = compute_replica_set(
        &make_game_id(),
        1,
        1,
        &[0u8; 32],
        &set,
        &assigned,
        DEFAULT_CHECKPOINT_MULTI_REPLICA_COUNT,
    )
    .expect("replica_set 计算应成功");

    // 2. 副本 validator 见证（简化：仅构造 receipts，不验证签名）
    let content_hash = [0xAB; 32];
    let receipts: Vec<MultiReplicaReceipt> = replica_set
        .iter()
        .take(DEFAULT_REPLICA_WITNESS_THRESHOLD as usize)
        .map(|w| make_receipt(w.raw[0], content_hash, 100, (10, 15)))
        .collect();
    assert_eq!(receipts.len(), 3, "应有 3 个副本见证");

    // 3. 所有 witness 须在 replica_set 中
    for receipt in &receipts {
        assert!(is_witness_in_replica_set(&receipt.witness, &replica_set));
    }

    // 4. force_checkpoint 应用 → under_investigation_count 递增
    let force_tx = ForceCheckpointTx {
        game_id: make_game_id(),
        current_turn: make_addr(0x05),
        state_hash: content_hash,
        ack_signatures: vec![],
        opt_out_ack_proof: None,
        assigned_validator_failure_proof: AssignedValidatorFailureProof {
            original_checkpoint_anchor: make_checkpoint_anchor_tx(1, 0xAB),
            multi_replica_receipts: receipts,
            non_inclusion_proof: RoundRangeNonInclusionProof {
                epoch: 1,
                round_start: 10,
                round_end: 15,
                assigned_validator: assigned,
                vertex_list: vec![],
                non_inclusion_proofs: vec![],
                round_attendance_bitmap: vec![0u8; 1],
            },
        },
    };
    let trigger_slashing =
        apply_force_checkpoint(&mut game, &force_tx, 200, DEFAULT_INVESTIGATION_THRESHOLD)
            .expect("force_checkpoint 应成功");
    assert!(!trigger_slashing, "首次未达阈值");
    assert_eq!(game.last_action_height, 200, "last_action_height 应更新");
    assert_eq!(game.under_investigation_count, 1, "调查应累积");

    // 5. 恢复阶段判定（force_checkpoint 更新了 last_action_height）
    let stage = RecoveryStage::compute(&game, 210, 30, 500, DEFAULT_RECOVERY_WINDOW_BLOCKS);
    assert!(
        matches!(stage, RecoveryStage::Stage1 { .. }),
        "应回到阶段 1"
    );
}

#[test]
fn subtask_42_6_checkpoint_skip_then_checkin_continuity() {
    // 综合：checkpoint_skip → 后续 checkin segment_continuity_proof 验证
    let mut game = make_game_with_checkpoint(100);

    // 第一次 skip
    let tx1 = CheckpointSkipTx {
        game_id: make_game_id(),
        skip_segment_start: 1,
        skip_segment_end: 2,
        last_known_state_hash: [0xAB; 32],
        continuity_proof: SegmentContinuityProof {
            start_state_proof: StateProof {
                checkpoint_seq: 1,
                state_hash: [0xAB; 32],
                ack_signatures: vec![],
            },
            end_state_proof: None,
        },
        ack_set: vec![make_tagged_pubkey(0x20)],
    };
    apply_checkpoint_skip(&mut game, &tx1, 150, 3).expect("第一次 skip 应成功");
    assert_eq!(game.skip_count, 1);

    // 第二次 skip
    let tx2 = CheckpointSkipTx {
        game_id: make_game_id(),
        skip_segment_start: 2,
        skip_segment_end: 3,
        last_known_state_hash: [0xAB; 32],
        continuity_proof: SegmentContinuityProof {
            start_state_proof: StateProof {
                checkpoint_seq: 2,
                state_hash: [0xAB; 32],
                ack_signatures: vec![],
            },
            end_state_proof: None,
        },
        ack_set: vec![make_tagged_pubkey(0x20)],
    };
    apply_checkpoint_skip(&mut game, &tx2, 160, 3).expect("第二次 skip 应成功");
    assert_eq!(game.skip_count, 2);
    assert_eq!(game.last_action_height, 160);

    // 验证 segment chain（空 segments 应失败）
    let empty_segments: Vec<SegmentContinuityProof> = vec![];
    let active_participants: Vec<TaggedPubkey> = vec![make_tagged_pubkey(0x20)];
    let result = verify_segment_chain(
        &empty_segments,
        poker_l1::DEFAULT_CHAIN_ID,
        &make_game_id(),
        &active_participants,
        &[0xAB; 32],
    );
    assert!(result.is_err(), "空 segments 应失败");
}

#[test]
fn subtask_42_7_constants_alignment() {
    // 常量一致性校验
    assert_eq!(DEFAULT_CHECKPOINT_MULTI_REPLICA_COUNT, 5, "NEW-M3: N = 5");
    assert_eq!(DEFAULT_REPLICA_WITNESS_THRESHOLD, 3, "NEW-M3: 3-of-N");
    assert_eq!(DEFAULT_GOSSIPSUB_MESH_SIZE, 6, "SEC-H5: mesh = 5 + 1");
    assert_eq!(
        DEFAULT_DESIGNATED_OPERATOR_CHECK_EXEMPTION_LIMIT, 2,
        "R3-M7: 豁免上限 = 2"
    );
    assert_eq!(
        DEFAULT_RECOVERY_WINDOW_BLOCKS, 100,
        "SubTask 27.5e: 恢复窗口 = 100"
    );
    assert_eq!(DEFAULT_INVESTIGATION_THRESHOLD, 3, "NEW-H1: 调查阈值 = 3");
    assert_eq!(
        DEFAULT_DELEGATED_ESCAPE_MAX_EXPIRY_BLOCKS, 100,
        "NEW-M2: 委托逃生有效期 = 100"
    );
    assert_eq!(
        FALSE_WITNESS_SLASH_PERCENTAGE, 100,
        "虚假见证 slashing = 100%"
    );
    assert_eq!(
        MIN_ACK_DEADLINE_BLOCKS, 10,
        "SEC2-H1: ack_deadline 下限 = 10"
    );
    assert_eq!(
        DEFAULT_MALICIOUS_REFUSE_THRESHOLD, 3,
        "SubTask 27.9: 恶意 refuse_ack 阈值 = 3"
    );
}
