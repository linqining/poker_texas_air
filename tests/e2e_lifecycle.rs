//! E2E 测试 — lifecycle 模块（join_table/leave_table/start_hand/advance_deadline）
//! prove + verify + soundness。
//!
//! 验证流程：
//! 1. 构造 method AIR 的 active row + padding row
//! 2. 调用 `gen_method_trace` 生成 trace
//! 3. 调用 `prove_method` 生成 Stwo proof
//! 4. 调用 `verify_method` 验证 proof
//! 5. Soundness：篡改 AIR 公开输入后验证应失败

use stwo::core::fields::m31::M31;

use poker_texas_air::airs::common::MAX_TOTAL_BET;
use poker_texas_air::airs::lifecycle::advance_deadline::{
    AdvanceDeadlineAir as TickAir, AdvanceDeadlineInput as TickInput, AdvanceDeadlineRow as TickRow,
};
use poker_texas_air::airs::lifecycle::join_table::{JoinTableAir, JoinTableInput, JoinTableRow};
use poker_texas_air::airs::lifecycle::leave_table::{
    LeaveTableAir, LeaveTableInput, LeaveTableRow,
};
use poker_texas_air::airs::lifecycle::start_hand::{StartHandAir, StartHandInput, StartHandRow};
use poker_texas_air::authorization_binding::AdminAuthorizationAirBinding;
use poker_texas_air::method_kind::MethodKind;
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

fn synthetic_admin_authorization() -> AdminAuthorizationAirBinding {
    AdminAuthorizationAirBinding::synthetic_unverified()
}

// ========== join_table AIR ==========

/// E2E: join_table → trace → prove → verify（happy path）。
#[test]
fn test_e2e_join_table_prove_verify() {
    let input = JoinTableInput {
        seat_index: 2,
        buy_in: 1_000,
        player_addr: [0u8; 20],
    };
    let row = JoinTableRow::active(
        &input,
        zero_root(),
        one_root(),
        42, // table_id
        0,  // hand_id
        1,  // call_seq
        0,  // pre_version
        1,  // post_version
        10, // big_blind
        0,  // pre_chip_pool
    );
    let trace = gen_method_trace(
        JoinTableAir::num_columns(),
        &row.to_vec(),
        &JoinTableRow::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = JoinTableAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 0,
        call_seq: 1,
        pre_version: 0,
        post_version: 1,
    };

    let proof = prove_method(
        &trace,
        air,
        JoinTableAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::JoinTable, 42, 0, 1),
    )
    .expect("prove 失败");
    verify_method(proof).expect("verify 失败");
}

/// 资金语义回归：`chip_pool + buy_in` 跨 16-bit limb 时必须由 ripple carry 正确证明。
#[test]
fn test_e2e_join_table_cross_limb_carry() {
    let buy_in = 65_536;
    let pre_chip_pool = MAX_TOTAL_BET - buy_in;
    let input = JoinTableInput {
        seat_index: 2,
        buy_in,
        player_addr: [0x42; 20],
    };
    let row = JoinTableRow::active(
        &input,
        zero_root(),
        one_root(),
        42,
        0,
        1,
        0,
        1,
        10,
        pre_chip_pool,
    );
    let trace = gen_method_trace(
        JoinTableAir::num_columns(),
        &row.to_vec(),
        &JoinTableRow::padding().to_vec(),
    )
    .expect("trace 生成失败");
    let air = JoinTableAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 0,
        call_seq: 1,
        pre_version: 0,
        post_version: 1,
    };
    let proof = prove_method(
        &trace,
        air,
        JoinTableAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::JoinTable, 42, 0, 1),
    )
    .expect("跨 limb join prove 失败");
    verify_method(proof).expect("跨 limb join verify 失败");
}

/// Soundness: 篡改 join_table 的 `seat_index` 公开输入后，verify 应失败。
#[test]
fn test_soundness_join_table_tampered_seat() {
    let input = JoinTableInput {
        seat_index: 2,
        buy_in: 1_000,
        player_addr: [0u8; 20],
    };
    let row = JoinTableRow::active(&input, zero_root(), one_root(), 42, 0, 1, 0, 1, 10, 0);
    let trace = gen_method_trace(
        JoinTableAir::num_columns(),
        &row.to_vec(),
        &JoinTableRow::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = JoinTableAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 0,
        call_seq: 1,
        pre_version: 0,
        post_version: 1,
    };
    let mut proof = prove_method(
        &trace,
        air,
        JoinTableAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::JoinTable, 42, 0, 1),
    )
    .expect("prove 失败");

    // 篡改 seat_index：trace 中是 2，AIR 声明 7
    proof.air = JoinTableAir {
        input: JoinTableInput {
            seat_index: 7, // 篡改！
            ..proof.air.input.clone()
        },
        ..proof.air.clone()
    };

    let result = verify_method(proof);
    assert!(
        result.is_err(),
        "篡改 seat_index 后 verify 应失败，但成功了 — soundness 漏洞！"
    );
}

// ========== leave_table AIR ==========

/// E2E: leave_table → trace → prove → verify（happy path）。
#[test]
fn test_e2e_leave_table_prove_verify() {
    let input = LeaveTableInput { seat_index: 3 };
    let row = LeaveTableRow::active(
        &input,
        zero_root(),
        one_root(),
        42,
        0,
        2,
        0,
        1,
        1000,
        0,
        5000,
        4000,
    );
    let trace = gen_method_trace(
        LeaveTableAir::num_columns(),
        &row.to_vec(),
        &LeaveTableRow::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = LeaveTableAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 0,
        call_seq: 2,
        pre_version: 0,
        post_version: 1,
    };

    let proof = prove_method(
        &trace,
        air,
        LeaveTableAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::LeaveTable, 42, 0, 2),
    )
    .expect("prove 失败");
    verify_method(proof).expect("verify 失败");
}

/// Soundness: 篡改 leave_table 的 `seat_index` 公开输入后，verify 应失败。
#[test]
fn test_soundness_leave_table_tampered_seat() {
    let input = LeaveTableInput { seat_index: 3 };
    let row = LeaveTableRow::active(
        &input,
        zero_root(),
        one_root(),
        42,
        0,
        2,
        0,
        1,
        1000,
        0,
        5000,
        4000,
    );
    let trace = gen_method_trace(
        LeaveTableAir::num_columns(),
        &row.to_vec(),
        &LeaveTableRow::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = LeaveTableAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 0,
        call_seq: 2,
        pre_version: 0,
        post_version: 1,
    };
    let mut proof = prove_method(
        &trace,
        air,
        LeaveTableAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::LeaveTable, 42, 0, 2),
    )
    .expect("prove 失败");

    // 篡改 seat_index：trace 中是 3，AIR 声明 8
    proof.air = LeaveTableAir {
        input: LeaveTableInput { seat_index: 8 }, // 篡改！
        ..proof.air.clone()
    };

    let result = verify_method(proof);
    assert!(
        result.is_err(),
        "篡改 seat_index 后 verify 应失败，但成功了 — soundness 漏洞！"
    );
}

/// E2E: 退款加法和资金池减法均接受跨 16-bit limb carry/borrow。
#[test]
fn test_e2e_leave_table_funds_ripple_carry() {
    let input = LeaveTableInput { seat_index: 0 };
    let row = LeaveTableRow::active(
        &input,
        zero_root(),
        one_root(),
        42,
        0,
        2,
        0,
        1,
        65_535,
        1,
        65_536,
        0,
    );
    let trace = gen_method_trace(
        LeaveTableAir::num_columns(),
        &row.to_vec(),
        &LeaveTableRow::padding().to_vec(),
    )
    .expect("trace 生成失败");
    let air = LeaveTableAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 0,
        call_seq: 2,
        pre_version: 0,
        post_version: 1,
    };
    let proof = prove_method(
        &trace,
        air,
        LeaveTableAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::LeaveTable, 42, 0, 2),
    )
    .expect("跨 limb leave_table prove 失败");
    verify_method(proof).expect("跨 limb leave_table verify 失败");
}

/// Soundness: refund/chip_pool 任一资金 witness 被篡改时 prove 必须失败。
#[test]
fn test_soundness_leave_table_tampered_funds_rejected() {
    use poker_texas_air::airs::lifecycle::leave_table::cols;

    let input = LeaveTableInput { seat_index: 0 };
    let row = LeaveTableRow::active(
        &input,
        zero_root(),
        one_root(),
        42,
        0,
        2,
        0,
        1,
        65_535,
        1,
        65_536,
        0,
    );
    for (name, column) in [
        ("refund", cols::OUTPUT_REFUND_BASE),
        ("chip_pool", cols::OUTPUT_POST_CHIP_POOL_BASE),
    ] {
        let mut trace_row = row.to_vec();
        trace_row[column] += M31::from(1u32);
        let trace = gen_method_trace(
            LeaveTableAir::num_columns(),
            &trace_row,
            &LeaveTableRow::padding().to_vec(),
        )
        .expect("trace 生成失败");
        let air = LeaveTableAir {
            log_size: trace.log_size,
            input: input.clone(),
            pre_state_root: zero_root(),
            post_state_root: one_root(),
            table_id: 42,
            hand_id: 0,
            call_seq: 2,
            pre_version: 0,
            post_version: 1,
        };
        let result = prove_method(
            &trace,
            air,
            LeaveTableAir::num_columns(),
            TexasPublicInputs::synthetic_for_test(MethodKind::LeaveTable, 42, 0, 2),
        );
        assert!(result.is_err(), "篡改 {name} witness 时 prove 应失败");
    }
}

/// 计算 active_count*(active_count-1) 在 M31 域内的乘法逆元（Gap 4 witness）。
fn active_count_inv(active_count: u8) -> M31 {
    let c = M31::from(u32::from(active_count));
    (c * (c - M31::from(1u32))).inverse()
}

/// 计算 active_count*(active_count-1)（Gap 4 witness 中间列）。
fn active_count_prod(active_count: u8) -> M31 {
    let c = M31::from(u32::from(active_count));
    c * (c - M31::from(1u32))
}

// ========== start_hand AIR ==========

/// E2E: start_hand → trace → prove → verify（happy path）。
#[test]
fn test_e2e_start_hand_prove_verify() {
    let input = StartHandInput {
        active_count: 4,
        new_button: 2,
        ante_mode: 0,
        ante_amount: 0,
        ante_collected: 0,
        pre_pot: 0,
        post_pot: 0,
        authorization: synthetic_admin_authorization(),
    };
    let row = StartHandRow::active(
        &input,
        active_count_inv(4),
        active_count_prod(4),
        zero_root(),
        one_root(),
        42,
        0,
        3,
        0,
        1,
    );
    let trace = gen_method_trace(
        StartHandAir::num_columns(),
        &row.to_vec(),
        &StartHandRow::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = StartHandAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 0,
        call_seq: 3,
        pre_version: 0,
        post_version: 1,
    };

    let proof = prove_method(
        &trace,
        air,
        StartHandAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::StartHand, 42, 0, 3),
    )
    .expect("prove 失败");
    verify_method(proof).expect("verify 失败");
}

/// Soundness: 篡改 start_hand 的 `active_count` 公开输入后，verify 应失败。
#[test]
fn test_soundness_start_hand_tampered_count() {
    let input = StartHandInput {
        active_count: 4,
        new_button: 2,
        ante_mode: 0,
        ante_amount: 0,
        ante_collected: 0,
        pre_pot: 0,
        post_pot: 0,
        authorization: synthetic_admin_authorization(),
    };
    let row = StartHandRow::active(
        &input,
        active_count_inv(4),
        active_count_prod(4),
        zero_root(),
        one_root(),
        42,
        0,
        3,
        0,
        1,
    );
    let trace = gen_method_trace(
        StartHandAir::num_columns(),
        &row.to_vec(),
        &StartHandRow::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = StartHandAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 0,
        call_seq: 3,
        pre_version: 0,
        post_version: 1,
    };
    let mut proof = prove_method(
        &trace,
        air,
        StartHandAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::StartHand, 42, 0, 3),
    )
    .expect("prove 失败");

    // 篡改 active_count：trace 中是 4，AIR 声明 9
    proof.air = StartHandAir {
        input: StartHandInput {
            active_count: 9,
            ..proof.air.input.clone()
        }, // 篡改！
        ..proof.air.clone()
    };

    let result = verify_method(proof);
    assert!(
        result.is_err(),
        "篡改 active_count 后 verify 应失败，但成功了 — soundness 漏洞！"
    );
}

/// Soundness: 篡改 start_hand 的 `ante_mode` 公开输入后，verify 应失败。
#[test]
fn test_soundness_start_hand_tampered_ante_mode() {
    let input = StartHandInput {
        active_count: 4,
        new_button: 2,
        ante_mode: 1,
        ante_amount: 10,
        ante_collected: 40,
        pre_pot: 0,
        post_pot: 40,
        authorization: synthetic_admin_authorization(),
    };
    let row = StartHandRow::active(
        &input,
        active_count_inv(4),
        active_count_prod(4),
        zero_root(),
        one_root(),
        42,
        0,
        3,
        0,
        1,
    );
    let trace = gen_method_trace(
        StartHandAir::num_columns(),
        &row.to_vec(),
        &StartHandRow::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = StartHandAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 0,
        call_seq: 3,
        pre_version: 0,
        post_version: 1,
    };
    let mut proof = prove_method(
        &trace,
        air,
        StartHandAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::StartHand, 42, 0, 3),
    )
    .expect("prove 失败");

    // 篡改 ante_mode：trace 中是 1 (NORMAL)，AIR 声明 2 (BBA)
    proof.air = StartHandAir {
        input: StartHandInput {
            ante_mode: 2,
            ..proof.air.input.clone()
        },
        ..proof.air.clone()
    };

    let result = verify_method(proof);
    assert!(
        result.is_err(),
        "篡改 ante_mode 后 verify 应失败，但成功了 — soundness 漏洞！"
    );
}

/// Soundness: creator authorization receipt digests are constrained by the
/// start_hand AIR rather than trusted as host-only metadata.
#[test]
fn test_soundness_start_hand_tampered_authorization_digest() {
    let input = StartHandInput {
        active_count: 4,
        new_button: 2,
        ante_mode: 0,
        ante_amount: 0,
        ante_collected: 0,
        pre_pot: 0,
        post_pot: 0,
        authorization: synthetic_admin_authorization(),
    };
    let mut row = StartHandRow::active(
        &input,
        active_count_inv(4),
        active_count_prod(4),
        zero_root(),
        one_root(),
        42,
        0,
        3,
        0,
        1,
    );
    row.authorization.receipt_digest[7] = M31::from(1u32);
    let trace = gen_method_trace(
        StartHandAir::num_columns(),
        &row.to_vec(),
        &StartHandRow::padding().to_vec(),
    )
    .expect("trace generation failed");

    let result = prove_method(
        &trace,
        StartHandAir {
            log_size: trace.log_size,
            input,
            pre_state_root: zero_root(),
            post_state_root: one_root(),
            table_id: 42,
            hand_id: 0,
            call_seq: 3,
            pre_version: 0,
            post_version: 1,
        },
        StartHandAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::StartHand, 42, 0, 3),
    );
    assert!(
        result.is_err(),
        "tampered start_hand authorization receipt must not prove"
    );
}

/// Soundness: ante high limbs are constrained, not truncated to limb 0.
#[test]
fn test_soundness_start_hand_rejects_high_limb_ante_substitution() {
    let input = StartHandInput {
        active_count: 2,
        new_button: 1,
        ante_mode: 2,
        ante_amount: 0,
        ante_collected: 0,
        pre_pot: 0,
        post_pot: 0,
        authorization: synthetic_admin_authorization(),
    };
    let mut row = StartHandRow::active(
        &input,
        active_count_inv(2),
        active_count_prod(2),
        zero_root(),
        one_root(),
        42,
        0,
        3,
        0,
        1,
    );
    row.output_ante_amount[1] = M31::from(1u32);
    row.output_ante_collected[1] = M31::from(1u32);
    let trace = gen_method_trace(
        StartHandAir::num_columns(),
        &row.to_vec(),
        &StartHandRow::padding().to_vec(),
    )
    .unwrap();
    let result = prove_method(
        &trace,
        StartHandAir {
            log_size: trace.log_size,
            input,
            pre_state_root: zero_root(),
            post_state_root: one_root(),
            table_id: 42,
            hand_id: 0,
            call_seq: 3,
            pre_version: 0,
            post_version: 1,
        },
        StartHandAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::StartHand, 42, 0, 3),
    );
    assert!(result.is_err(), "high-limb ante substitution must fail");
}

/// `start_hand` proves the full checked-u64 pot update, including a carry from
/// limb 0 into limb 1.
#[test]
fn test_e2e_start_hand_ante_pot_ripple_carry() {
    let input = StartHandInput {
        active_count: 2,
        new_button: 1,
        ante_mode: 2,
        ante_amount: 1,
        ante_collected: 1,
        pre_pot: 65_535,
        post_pot: 65_536,
        authorization: synthetic_admin_authorization(),
    };
    let row = StartHandRow::active(
        &input,
        active_count_inv(2),
        active_count_prod(2),
        zero_root(),
        one_root(),
        42,
        0,
        3,
        0,
        1,
    );
    assert_eq!(row.ante_pot_add_carry[0], M31::from(1u32));
    let trace = gen_method_trace(
        StartHandAir::num_columns(),
        &row.to_vec(),
        &StartHandRow::padding().to_vec(),
    )
    .expect("trace generation failed");
    let air = StartHandAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 0,
        call_seq: 3,
        pre_version: 0,
        post_version: 1,
    };
    let proof = prove_method(
        &trace,
        air,
        StartHandAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::StartHand, 42, 0, 3),
    )
    .expect("prove failed");
    verify_method(proof).expect("verify failed");
}

// ========== tick AIR ==========

/// E2E: tick → trace → prove → verify（happy path）。
#[test]
fn test_e2e_tick_prove_verify() {
    let input = TickInput {
        current_time: 1_700_000_000,
        timeout_kind: 1, // Gap 5：tick 需 timeout_kind > 0（reveal timeout，inverse 存在）
        time_bank_consumed: 0,
        time_bank_post: 30_000,
        rake_mode: 0,
        rake_amount: 0,
        ..TickInput::default()
    };
    let row = TickRow::active(
        &input,
        zero_root(),
        one_root(),
        42,
        0,
        4,
        0,
        1,
        1, // pre = SHUFFLE
        2, // post = DEAL_HOLE_CARDS
    );
    let trace = gen_method_trace(
        TickAir::num_columns(),
        &row.to_vec(),
        &TickRow::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = TickAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 0,
        call_seq: 4,
        pre_version: 0,
        post_version: 1,
    };

    let proof = prove_method(
        &trace,
        air,
        TickAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::AdvanceDeadline, 42, 0, 4),
    )
    .expect("prove 失败");
    verify_method(proof).expect("verify 失败");
}

/// Soundness: 篡改 tick 的 `timeout_kind` 公开输入后，verify 应失败。
#[test]
fn test_soundness_tick_tampered_kind() {
    let input = TickInput {
        current_time: 1_700_000_000,
        timeout_kind: 1, // Gap 5：tick 需 timeout_kind > 0（reveal timeout）
        time_bank_consumed: 0,
        time_bank_post: 30_000,
        rake_mode: 0,
        rake_amount: 0,
        ..TickInput::default()
    };
    let row = TickRow::active(&input, zero_root(), one_root(), 42, 0, 4, 0, 1, 1, 2);
    let trace = gen_method_trace(
        TickAir::num_columns(),
        &row.to_vec(),
        &TickRow::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = TickAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 0,
        call_seq: 4,
        pre_version: 0,
        post_version: 1,
    };
    let mut proof = prove_method(
        &trace,
        air,
        TickAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::AdvanceDeadline, 42, 0, 4),
    )
    .expect("prove 失败");

    // 篡改 timeout_kind：trace 中是 1，AIR 声明 3
    proof.air = TickAir {
        input: TickInput {
            timeout_kind: 3, // 篡改！
            ..proof.air.input.clone()
        },
        ..proof.air.clone()
    };

    let result = verify_method(proof);
    assert!(
        result.is_err(),
        "篡改 timeout_kind 后 verify 应失败，但成功了 — soundness 漏洞！"
    );
}

/// Soundness: the verifier-issued Tick lifecycle receipt is constrained by
/// the method AIR even when all four business components are inactive.
#[test]
fn test_soundness_tick_tampered_lifecycle_receipt() {
    let input = TickInput {
        current_time: 1_700_000_000,
        timeout_kind: 1,
        time_bank_consumed: 0,
        time_bank_post: 30_000,
        rake_mode: 0,
        rake_amount: 0,
        ..TickInput::default()
    };
    let mut row = TickRow::active(&input, zero_root(), one_root(), 42, 0, 4, 0, 1, 1, 2);
    row.lifecycle.receipt_digest[7] = M31::from(1u32);
    let trace = gen_method_trace(
        TickAir::num_columns(),
        &row.to_vec(),
        &TickRow::padding().to_vec(),
    )
    .expect("trace generation failed");

    let result = prove_method(
        &trace,
        TickAir {
            log_size: trace.log_size,
            input,
            pre_state_root: zero_root(),
            post_state_root: one_root(),
            table_id: 42,
            hand_id: 0,
            call_seq: 4,
            pre_version: 0,
            post_version: 1,
        },
        TickAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::AdvanceDeadline, 42, 0, 4),
    );
    assert!(
        result.is_err(),
        "tampered Tick lifecycle receipt must not prove"
    );
}

/// The full 64-bit consensus timestamp is part of the tick statement.  A
/// change outside limb 0 must invalidate the proof just as a low-limb change
/// does.
#[test]
fn test_soundness_tick_tampered_high_limb_time() {
    let input = TickInput {
        current_time: 1_700_000_000,
        timeout_kind: 1,
        time_bank_consumed: 0,
        time_bank_post: 30_000,
        rake_mode: 0,
        rake_amount: 0,
        ..TickInput::default()
    };
    let row = TickRow::active(&input, zero_root(), one_root(), 42, 0, 4, 0, 1, 1, 2);
    let trace = gen_method_trace(
        TickAir::num_columns(),
        &row.to_vec(),
        &TickRow::padding().to_vec(),
    )
    .expect("trace 生成失败");
    let air = TickAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 0,
        call_seq: 4,
        pre_version: 0,
        post_version: 1,
    };
    let mut proof = prove_method(
        &trace,
        air,
        TickAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::AdvanceDeadline, 42, 0, 4),
    )
    .expect("prove 失败");

    proof.air = TickAir {
        input: TickInput {
            current_time: 1_700_000_000 + (1_u64 << 32),
            ..proof.air.input.clone()
        },
        ..proof.air.clone()
    };
    assert!(
        verify_method(proof).is_err(),
        "篡改 tick timestamp 的高 limb 后 verify 必须失败"
    );
}

/// Soundness: 篡改 tick 的 `time_bank_consumed` 公开输入后，verify 应失败。
#[test]
fn test_soundness_tick_tampered_time_bank() {
    let input = TickInput {
        current_time: 1_700_000_000,
        timeout_kind: 3, // betting timeout
        time_bank_consumed: 10_000,
        time_bank_post: 20_000,
        rake_mode: 0,
        rake_amount: 0,
        ..TickInput::default()
    };
    let row = TickRow::active(&input, zero_root(), one_root(), 42, 0, 4, 0, 1, 5, 5);
    let trace = gen_method_trace(
        TickAir::num_columns(),
        &row.to_vec(),
        &TickRow::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = TickAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 0,
        call_seq: 4,
        pre_version: 0,
        post_version: 1,
    };
    let mut proof = prove_method(
        &trace,
        air,
        TickAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::AdvanceDeadline, 42, 0, 4),
    )
    .expect("prove 失败");

    // 篡改 time_bank_consumed：trace 中是 10_000，AIR 声明 99_999
    proof.air = TickAir {
        input: TickInput {
            time_bank_consumed: 99_999, // 篡改！
            ..proof.air.input.clone()
        },
        ..proof.air.clone()
    };

    let result = verify_method(proof);
    assert!(
        result.is_err(),
        "篡改 time_bank_consumed 后 verify 应失败，但成功了 — soundness 漏洞！"
    );
}

/// Soundness: 篡改 tick 的 `rake_amount` 公开输入后，verify 应失败。
#[test]
fn test_soundness_tick_tampered_rake() {
    let input = TickInput {
        current_time: 1_700_000_000,
        timeout_kind: 1, // reveal timeout (triggers settlement)
        time_bank_consumed: 0,
        time_bank_post: 30_000,
        rake_mode: 1,    // PERCENTAGE
        rake_amount: 50, // 5% of 1000
        ..TickInput::default()
    };
    let row = TickRow::active(&input, zero_root(), one_root(), 42, 0, 4, 0, 1, 8, 8);
    let trace = gen_method_trace(
        TickAir::num_columns(),
        &row.to_vec(),
        &TickRow::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = TickAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 42,
        hand_id: 0,
        call_seq: 4,
        pre_version: 0,
        post_version: 1,
    };
    let mut proof = prove_method(
        &trace,
        air,
        TickAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::AdvanceDeadline, 42, 0, 4),
    )
    .expect("prove 失败");

    // 篡改 rake_amount：trace 中是 50，AIR 声明 999
    proof.air = TickAir {
        input: TickInput {
            rake_amount: 999, // 篡改！
            ..proof.air.input.clone()
        },
        ..proof.air.clone()
    };

    let result = verify_method(proof);
    assert!(
        result.is_err(),
        "篡改 rake_amount 后 verify 应失败，但成功了 — soundness 漏洞！"
    );
}

// ========== 列数一致性 ==========

/// 单元测试：所有 lifecycle AIR 的列数与常量声明一致。
#[test]
fn test_lifecycle_air_column_consistency() {
    use poker_texas_air::airs::common::COMMON_NUM_COLUMNS;
    use poker_texas_air::airs::lifecycle::{
        advance_deadline as tick, join_table, leave_table, start_hand,
    };

    // join_table: 通用 + 46 业务
    //   原始 14 列（seat_index + buy_in 4 + player_addr 4 + seat_stack 4 + seat_empty 1）
    //   + 12 列（big_blind 4 + pre_chip_pool 4 + post_chip_pool 4）用于 buy_in >= big_blind 和 chip_pool 守恒
    //   + 10 列（bound_diff 4 + carry_lo 3 + carry_hi 3）用于全局上界 range check
    //   + 7 列（阶段 3 新增：ge_diff 4 + ge_borrow 3）用于 buy_in >= big_blind
    //   + 3 列 chip_pool ripple carry
    assert_eq!(join_table::cols::NUM_COLUMNS, COMMON_NUM_COLUMNS + 46);
    assert_eq!(JoinTableAir::num_columns(), join_table::cols::NUM_COLUMNS);

    // leave_table: 通用 + 28 业务
    //   原始 6 列（seat_index + refund 4 + seat_occupied 1）
    //   + 16 新列（seat_stack 4 + pending_addon 4 + pre_chip_pool 4 + post_chip_pool 4）
    //   + 6 carry bit（退款加法、chip_pool 减法各 3）
    assert_eq!(leave_table::cols::NUM_COLUMNS, COMMON_NUM_COLUMNS + 28);
    assert_eq!(LeaveTableAir::num_columns(), leave_table::cols::NUM_COLUMNS);

    // start_hand: 通用 + 17 业务（完整 ante 金额、active_count witnesses、pot add carries）
    assert_eq!(start_hand::cols::NUM_COLUMNS, COMMON_NUM_COLUMNS + 51);
    assert_eq!(StartHandAir::num_columns(), start_hand::cols::NUM_COLUMNS);

    // tick: 通用 + 87 个业务列：53 列完整 64-bit Time Bank / Rake / deadline witness，
    // 再加 lifecycle ABI/branch 两列和完整 request/receipt digest 各 16 列。
    assert_eq!(tick::cols::NUM_COLUMNS, COMMON_NUM_COLUMNS + 87);
    assert_eq!(TickAir::num_columns(), tick::cols::NUM_COLUMNS);
}

/// 单元测试：MethodKind 的 lifecycle 档位分类正确。
#[test]
fn test_lifecycle_method_kinds() {
    use poker_texas_air::method_kind::{MethodKind, MethodTier};

    assert_eq!(MethodKind::CreateTable.tier(), MethodTier::Lifecycle);
    assert_eq!(MethodKind::JoinTable.tier(), MethodTier::Lifecycle);
    assert_eq!(MethodKind::LeaveTable.tier(), MethodTier::Lifecycle);
    assert_eq!(MethodKind::StartHand.tier(), MethodTier::Lifecycle);
    assert_eq!(MethodKind::AdvanceDeadline.tier(), MethodTier::Lifecycle);
}
