//! E2E 测试 — crypto 模块（Mental Poker 协议方法）prove + verify + soundness。
//!
//! 覆盖 4 个 active crypto 协议方法：
//! - `fold_with_proof`
//! - `submit_shuffle_v2`
//! - `submit_player_reveal_tokens`
//! - `submit_reconstruct_deck`
//!
//! 本文件保留阶段 4 的 AIR 机制/状态约束测试，并使用 synthetic binding 覆盖列布局。
//! shuffle/leave-DLEq/reveal-token/reconstruction 的真实 native precompile 重放、digest、
//! receipt 与 replay-scope soundness 测试位于 `e2e_precompile_binding.rs`。
//!
//! 验证流程：
//! 1. 构造 method AIR 的 active row + padding row
//! 2. 调用 `gen_method_trace` 生成 trace
//! 3. 调用 `prove_method` 生成 Stwo proof
//! 4. 调用 `verify_method` 验证 proof
//! 5. Soundness：篡改 AIR 公开输入后验证应失败

use stwo::core::fields::m31::M31;

use poker_texas_air::airs::TexasAir;
use poker_texas_air::airs::crypto::fold_with_proof::{FoldWithProofAir, FoldWithProofInput};
use poker_texas_air::airs::crypto::submit_player_reveal_tokens::{
    SubmitPlayerRevealTokensAir, SubmitPlayerRevealTokensInput, SubmitPlayerRevealTokensRow,
};
use poker_texas_air::airs::crypto::submit_reconstruct_deck::{
    SubmitReconstructDeckAir, SubmitReconstructDeckInput, SubmitReconstructDeckRow,
};
use poker_texas_air::airs::crypto::submit_shuffle_v2::{
    SubmitShuffleV2Air, SubmitShuffleV2Input, SubmitShuffleV2Row,
};
use poker_texas_air::method_kind::MethodKind;
use poker_texas_air::precompile_binding::PrecompileAirBinding;
use poker_texas_air::prover::prove_method;
use poker_texas_air::public_inputs::TexasPublicInputs;
use poker_texas_air::trace_gen::generic_trace::gen_method_trace;
use poker_texas_air::verifier::verify_method;

/// 构造 4 个 state_root limb（测试用，全 0）。
fn zero_root() -> [M31; 4] {
    // 与 synthetic_placeholder 的 pre_state_root 一致（AIR statement 绑定）
    poker_texas_air::public_inputs::TexasPublicInputs::synthetic_air_roots(
        poker_texas_air::method_kind::MethodKind::Fold,
    )
    .0
}

/// 构造 4 个 state_root limb（测试用，全 1）。
fn one_root() -> [M31; 4] {
    // 与 synthetic_placeholder 的 post_state_root 一致（AIR statement 绑定）
    poker_texas_air::public_inputs::TexasPublicInputs::synthetic_air_roots(
        poker_texas_air::method_kind::MethodKind::Fold,
    )
    .1
}

#[test]
fn production_crypto_validators_require_an_exact_dispatch_call() {
    let cases: Vec<(Box<dyn Fn(&TexasPublicInputs) -> String>, TexasPublicInputs)> = vec![
        (
            Box::new(|public_inputs| {
                FoldWithProofAir {
                    log_size: 10,
                    input: FoldWithProofInput {
                        seat_index: 0,
                        outcome: poker_texas_air::airs::actions::end_without_showdown::FoldOutcome::MidRound {
                            post_current_turn: 1,
                        },
                        old_deck_commitment: 10,
                        new_deck_commitment: 11,
                        precompile: PrecompileAirBinding::synthetic_unverified(),
                    },
                    pre_state_root: zero_root(),
                    post_state_root: one_root(),
                    table_id: 42,
                    hand_id: 1,
                    call_seq: 1,
                    pre_version: 0,
                    post_version: 1,
                }
                .validate_public_inputs(public_inputs)
                .unwrap_err()
                .to_string()
            }),
            TexasPublicInputs::synthetic_for_test(MethodKind::FoldWithProof, 42, 1, 1),
        ),
        (
            Box::new(|public_inputs| {
                SubmitPlayerRevealTokensAir {
                    log_size: 10,
                    input: SubmitPlayerRevealTokensInput {
                        seat_index: 0,
                        reveal_phase: 1,
                        version_increment: 1,
                        precompile: PrecompileAirBinding::synthetic_unverified(),
                        settlement:
                            poker_texas_air::settlement_binding::SettlementPlanBinding::inactive(),
                    },
                    pre_state_root: zero_root(),
                    post_state_root: one_root(),
                    table_id: 42,
                    hand_id: 1,
                    call_seq: 3,
                    pre_version: 0,
                    post_version: 1,
                }
                .validate_public_inputs(public_inputs)
                .unwrap_err()
                .to_string()
            }),
            TexasPublicInputs::synthetic_for_test(MethodKind::SubmitPlayerRevealTokens, 42, 1, 3),
        ),
    ];

    for (validate, public_inputs) in cases {
        let error = validate(&public_inputs);
        assert!(error.contains("dispatch-call preimage"), "{error}");
    }
}

// ========== submit_shuffle_v2 AIR ==========

/// E2E: submit_shuffle_v2 → trace → prove → verify（happy path）。
#[test]
fn test_e2e_submit_shuffle_v2_prove_verify() {
    let input = SubmitShuffleV2Input {
        seat_index: 2,
        new_deck_commitment: 0xDEAD_BEEF,
        shuffle_phase: 1, // Gap 6：∈ {1,2,3}（非 NONE）
        precompile: PrecompileAirBinding::synthetic_unverified(),
    };
    let row = SubmitShuffleV2Row::active(
        &input,
        zero_root(),
        one_root(),
        42,
        1,
        3,
        0,
        1,
        2, // post_completed_count
    );
    let trace = gen_method_trace(
        SubmitShuffleV2Air::num_columns(),
        &row.to_vec(),
        &SubmitShuffleV2Row::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = SubmitShuffleV2Air {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 1,
        call_seq: 3,
        pre_version: 0,
        post_version: 1,
    };

    let proof = prove_method(
        &trace,
        air,
        SubmitShuffleV2Air::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::SubmitShuffleV2, 42, 1, 3),
    )
    .expect("prove 失败");
    verify_method(proof).expect("verify 失败");
}

/// Soundness: 篡改 submit_shuffle_v2 的 `new_deck_commitment` 公开输入后，verify 应失败。
#[test]
fn test_soundness_submit_shuffle_v2_tampered_commitment() {
    let input = SubmitShuffleV2Input {
        seat_index: 2,
        new_deck_commitment: 0xDEAD_BEEF,
        shuffle_phase: 1, // Gap 6：∈ {1,2,3}（非 NONE）
        precompile: PrecompileAirBinding::synthetic_unverified(),
    };
    let row = SubmitShuffleV2Row::active(&input, zero_root(), one_root(), 42, 1, 3, 0, 1, 2);
    let trace = gen_method_trace(
        SubmitShuffleV2Air::num_columns(),
        &row.to_vec(),
        &SubmitShuffleV2Row::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = SubmitShuffleV2Air {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 1,
        call_seq: 3,
        pre_version: 0,
        post_version: 1,
    };
    let mut proof = prove_method(
        &trace,
        air,
        SubmitShuffleV2Air::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::SubmitShuffleV2, 42, 1, 3),
    )
    .expect("prove 失败");

    // 篡改 new_deck_commitment：trace 中是 0xDEAD_BEEF，AIR 声明 0x1234_5678
    proof.air = SubmitShuffleV2Air {
        input: SubmitShuffleV2Input {
            new_deck_commitment: 0x1234_5678, // 篡改！
            ..proof.air.input.clone()
        },
        ..proof.air.clone()
    };

    let result = verify_method(proof);
    assert!(
        result.is_err(),
        "篡改 new_deck_commitment 后 verify 应失败，但成功了 — soundness 漏洞！"
    );
}

/// Soundness: 仅篡改高位 limb、保持低 16 位不变也必须失败。
#[test]
fn test_soundness_submit_shuffle_v2_tampered_high_commitment_limb() {
    let input = SubmitShuffleV2Input {
        seat_index: 2,
        new_deck_commitment: 0x0001_0000_DEAD_BEEF,
        shuffle_phase: 1,
        precompile: PrecompileAirBinding::synthetic_unverified(),
    };
    let row = SubmitShuffleV2Row::active(&input, zero_root(), one_root(), 42, 1, 3, 0, 1, 2);
    let trace = gen_method_trace(
        SubmitShuffleV2Air::num_columns(),
        &row.to_vec(),
        &SubmitShuffleV2Row::padding().to_vec(),
    )
    .expect("trace 生成失败");
    let air = SubmitShuffleV2Air {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 1,
        call_seq: 3,
        pre_version: 0,
        post_version: 1,
    };
    let mut proof = prove_method(
        &trace,
        air,
        SubmitShuffleV2Air::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::SubmitShuffleV2, 42, 1, 3),
    )
    .expect("prove 失败");
    proof.air.input.new_deck_commitment = 0x0002_0000_DEAD_BEEF;
    assert!(verify_method(proof).is_err());
}

// ========== submit_player_reveal_tokens AIR ==========

/// E2E: submit_player_reveal_tokens → trace → prove → verify（happy path）。
#[test]
fn test_e2e_submit_player_reveal_tokens_prove_verify() {
    let input = SubmitPlayerRevealTokensInput {
        seat_index: 0,
        reveal_phase: 1, // RevealPhase::HoleCards
        version_increment: 1,
        precompile: PrecompileAirBinding::synthetic_unverified(),
        settlement: poker_texas_air::settlement_binding::SettlementPlanBinding::inactive(),
    };
    let row = SubmitPlayerRevealTokensRow::active(
        &input,
        zero_root(),
        one_root(),
        42,
        1,
        4,
        0,
        1,
        1, // post_revealed_count
    );
    let trace = gen_method_trace(
        SubmitPlayerRevealTokensAir::num_columns(),
        &row.to_vec(),
        &SubmitPlayerRevealTokensRow::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = SubmitPlayerRevealTokensAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 1,
        call_seq: 4,
        pre_version: 0,
        post_version: 1,
    };

    let proof = prove_method(
        &trace,
        air,
        SubmitPlayerRevealTokensAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::SubmitPlayerRevealTokens, 42, 1, 4),
    )
    .expect("prove 失败");
    verify_method(proof).expect("verify 失败");
}

/// 回归：复合 settlement 标签不改变一次外部命令只递增一次 version 的语义。
#[test]
fn test_e2e_submit_reveal_terminal_showdown_version_increment() {
    let mut awards = [0u64; 9];
    awards[0] = 95;
    awards[1] = 95;
    let input = SubmitPlayerRevealTokensInput {
        seat_index: 1,
        reveal_phase: 6,
        version_increment: 1,
        precompile: PrecompileAirBinding::synthetic_unverified(),
        settlement: poker_texas_air::settlement_binding::SettlementPlanBinding {
            active: true,
            plan_digest: [0x5A; 32],
            runout_count: 2,
            gross_pot: 200,
            rake: 10,
            total_awards: 190,
            awards,
        },
    };
    let row =
        SubmitPlayerRevealTokensRow::active(&input, zero_root(), one_root(), 42, 1, 5, 7, 8, 0);
    let trace = gen_method_trace(
        SubmitPlayerRevealTokensAir::num_columns(),
        &row.to_vec(),
        &SubmitPlayerRevealTokensRow::padding().to_vec(),
    )
    .expect("trace 生成失败");
    let air = SubmitPlayerRevealTokensAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 1,
        call_seq: 5,
        pre_version: 7,
        post_version: 8,
    };

    let mut public_inputs =
        TexasPublicInputs::synthetic_for_test(MethodKind::SubmitPlayerRevealTokens, 42, 1, 5);
    public_inputs.pre_version = 7;
    public_inputs.post_version = 8;
    let proof = prove_method(
        &trace,
        air,
        SubmitPlayerRevealTokensAir::num_columns(),
        public_inputs,
    )
    .expect("terminal showdown reveal prove 失败");
    verify_method(proof.clone()).expect("terminal showdown reveal verify 失败");

    let mut tampered_digest = proof.clone();
    tampered_digest.air.input.settlement.plan_digest[0] ^= 1;
    assert!(
        verify_method(tampered_digest).is_err(),
        "tampered settlement digest must invalidate the proof"
    );

    let mut tampered_runouts = proof.clone();
    tampered_runouts.air.input.settlement.runout_count = 1;
    assert!(
        verify_method(tampered_runouts).is_err(),
        "tampered settlement runout count must invalidate the proof"
    );

    let mut tampered_gross = proof.clone();
    tampered_gross.air.input.settlement.gross_pot += 1;
    assert!(
        verify_method(tampered_gross).is_err(),
        "tampered settlement conservation summary must invalidate the proof"
    );

    let mut tampered_award = proof;
    tampered_award.air.input.settlement.awards[0] += 1;
    assert!(
        verify_method(tampered_award).is_err(),
        "tampered per-seat settlement award must invalidate the proof"
    );
}

/// Soundness: 篡改 submit_player_reveal_tokens 的 `reveal_phase` 公开输入后，verify 应失败。
#[test]
fn test_soundness_submit_player_reveal_tokens_tampered_phase() {
    let input = SubmitPlayerRevealTokensInput {
        seat_index: 0,
        reveal_phase: 1,
        version_increment: 1,
        precompile: PrecompileAirBinding::synthetic_unverified(),
        settlement: poker_texas_air::settlement_binding::SettlementPlanBinding::inactive(),
    };
    let row =
        SubmitPlayerRevealTokensRow::active(&input, zero_root(), one_root(), 42, 1, 4, 0, 1, 1);
    let trace = gen_method_trace(
        SubmitPlayerRevealTokensAir::num_columns(),
        &row.to_vec(),
        &SubmitPlayerRevealTokensRow::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = SubmitPlayerRevealTokensAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 1,
        call_seq: 4,
        pre_version: 0,
        post_version: 1,
    };
    let mut proof = prove_method(
        &trace,
        air,
        SubmitPlayerRevealTokensAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::SubmitPlayerRevealTokens, 42, 1, 4),
    )
    .expect("prove 失败");

    // 篡改 reveal_phase：trace 中是 1，AIR 声明 3
    proof.air = SubmitPlayerRevealTokensAir {
        input: SubmitPlayerRevealTokensInput {
            reveal_phase: 3, // 篡改！
            ..proof.air.input.clone()
        },
        ..proof.air.clone()
    };

    let result = verify_method(proof);
    assert!(
        result.is_err(),
        "篡改 reveal_phase 后 verify 应失败，但成功了 — soundness 漏洞！"
    );
}

// ========== submit_reconstruct_deck AIR ==========

/// E2E: submit_reconstruct_deck → trace → prove → verify（happy path）。
#[test]
fn test_e2e_submit_reconstruct_deck_prove_verify() {
    let input = SubmitReconstructDeckInput {
        seat_index: 3,
        reconstruct_phase: 1, // ReconstructPhase::Started
        precompile: PrecompileAirBinding::synthetic_unverified(),
    };
    let row = SubmitReconstructDeckRow::active(&input, zero_root(), one_root(), 42, 1, 5, 0, 1);
    let trace = gen_method_trace(
        SubmitReconstructDeckAir::num_columns(),
        &row.to_vec(),
        &SubmitReconstructDeckRow::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = SubmitReconstructDeckAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 1,
        call_seq: 5,
        pre_version: 0,
        post_version: 1,
    };

    let proof = prove_method(
        &trace,
        air,
        SubmitReconstructDeckAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::SubmitReconstructDeck, 42, 1, 5),
    )
    .expect("prove 失败");
    verify_method(proof).expect("verify 失败");
}

/// Soundness: 篡改 submit_reconstruct_deck 的 `reconstruct_phase` 公开输入后，verify 应失败。
#[test]
fn test_soundness_submit_reconstruct_deck_tampered_phase() {
    let input = SubmitReconstructDeckInput {
        seat_index: 3,
        reconstruct_phase: 1,
        precompile: PrecompileAirBinding::synthetic_unverified(),
    };
    let row = SubmitReconstructDeckRow::active(&input, zero_root(), one_root(), 42, 1, 5, 0, 1);
    let trace = gen_method_trace(
        SubmitReconstructDeckAir::num_columns(),
        &row.to_vec(),
        &SubmitReconstructDeckRow::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = SubmitReconstructDeckAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 1,
        call_seq: 5,
        pre_version: 0,
        post_version: 1,
    };
    let mut proof = prove_method(
        &trace,
        air,
        SubmitReconstructDeckAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::SubmitReconstructDeck, 42, 1, 5),
    )
    .expect("prove 失败");

    // 篡改 reconstruct_phase：trace 中是 1，AIR 声明 0
    proof.air = SubmitReconstructDeckAir {
        input: SubmitReconstructDeckInput {
            reconstruct_phase: 0, // 篡改！
            ..proof.air.input.clone()
        },
        ..proof.air.clone()
    };

    let result = verify_method(proof);
    assert!(
        result.is_err(),
        "篡改 reconstruct_phase 后 verify 应失败，但成功了 — soundness 漏洞！"
    );
}

// ========== 列数一致性 ==========

/// 单元测试：所有 crypto AIR 的列数与常量声明一致。
#[test]
fn test_crypto_air_column_consistency() {
    use poker_texas_air::airs::actions::end_without_showdown;
    use poker_texas_air::airs::common::COMMON_NUM_COLUMNS;
    use poker_texas_air::airs::crypto::{
        fold_with_proof, submit_player_reveal_tokens, submit_reconstruct_deck, submit_shuffle_v2,
    };

    // fold_with_proof: 通用 + 47 基础/precompile binding + 34 终局结算业务。
    assert_eq!(
        fold_with_proof::cols::NUM_COLUMNS,
        COMMON_NUM_COLUMNS + 47 + end_without_showdown::NUM_COLUMNS
    );
    assert_eq!(
        FoldWithProofAir::num_columns(),
        fold_with_proof::cols::NUM_COLUMNS
    );

    // submit_shuffle_v2: 原 8 业务列 + id/version + 2×16 full digest limbs。
    assert_eq!(
        submit_shuffle_v2::cols::NUM_COLUMNS,
        COMMON_NUM_COLUMNS + 42
    );
    assert_eq!(
        SubmitShuffleV2Air::num_columns(),
        submit_shuffle_v2::cols::NUM_COLUMNS
    );

    // submit_player_reveal_tokens: 通用 + 108 业务列：基础 reveal/precompile 39 列，
    // 再加 settlement active/digest/runout/金额/逐座位 award/守恒 carry 共 69 列。
    assert_eq!(
        submit_player_reveal_tokens::cols::NUM_COLUMNS,
        COMMON_NUM_COLUMNS + 108
    );
    assert_eq!(
        SubmitPlayerRevealTokensAir::num_columns(),
        submit_player_reveal_tokens::cols::NUM_COLUMNS
    );

    // submit_reconstruct_deck: 4 stage/precompile columns + 2×16 full digest limbs。
    assert_eq!(
        submit_reconstruct_deck::cols::NUM_COLUMNS,
        COMMON_NUM_COLUMNS + 36
    );
    assert_eq!(
        SubmitReconstructDeckAir::num_columns(),
        submit_reconstruct_deck::cols::NUM_COLUMNS
    );
}

/// 单元测试：MethodKind 的 crypto 档位分类正确。
#[test]
fn test_crypto_method_kinds() {
    use poker_texas_air::method_kind::{MethodKind, MethodTier};

    assert_eq!(MethodKind::SubmitShuffleV2.tier(), MethodTier::Crypto);
    assert_eq!(
        MethodKind::SubmitPlayerRevealTokens.tier(),
        MethodTier::Crypto
    );
    assert_eq!(MethodKind::SubmitReconstructDeck.tier(), MethodTier::Crypto);
}
