//! E2E 测试 — funds 模块（addon/rebuy）prove + verify + soundness。
//!
//! 验证流程：
//! 1. 构造 method AIR 的 active row + padding row
//! 2. 调用 `gen_method_trace` 生成 trace
//! 3. 调用 `prove_method` 生成 Stwo proof
//! 4. 调用 `verify_method` 验证 proof
//! 5. Soundness：篡改 AIR 公开输入后验证应失败
//!
//! ## addon vs rebuy 的核心差异
//!
//! - `addon`：约束 `post_pending_addon == pre_pending_addon + amount`（不动 stack）
//! - `rebuy`：约束 `post_stack == pre_stack + amount`（立即改 stack）
//!
//! Soundness 测试通过篡改 `amount` 验证：
//! - addon：篡改后 `post_pending_addon` 与 `pre + tampered_amount` 不匹配
//! - rebuy：篡改后 `post_stack` 与 `pre + tampered_amount` 不匹配

use stwo::core::fields::m31::M31;

use poker_texas_air::airs::funds::addon::{AddonAir, AddonInput, AddonRow};
use poker_texas_air::airs::funds::rebuy::{RebuyAir, RebuyInput, RebuyRow};
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

// ========== addon AIR ==========

/// E2E: addon → trace → prove → verify（happy path）。
///
/// 场景：seat 3 当前 pending_addon = 100，addon 200，结果 pending = 300。
#[test]
fn test_e2e_addon_prove_verify() {
    let input = AddonInput {
        seat_index: 3,
        amount: 200,
    };
    let pre_pending = 100; // 已有 100 pending
    let row = AddonRow::active(
        &input,
        pre_pending,
        0,   // pre_chip_pool
        200, // post_chip_pool
        zero_root(),
        one_root(),
        42, // table_id
        0,  // hand_id
        1,  // call_seq
        0,  // pre_version
        1,  // post_version
        0,  // pre_round_state (WAITING)
        0,  // post_round_state (WAITING)
    );
    let trace = gen_method_trace(
        AddonAir::num_columns(),
        &row.to_vec(),
        &AddonRow::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = AddonAir {
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
        AddonAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::Addon, 42, 0, 1),
    )
    .expect("prove 失败");
    verify_method(proof).expect("verify 失败");
}

/// E2E: addon 从 pre_pending = 0 开始（最常见场景）。
#[test]
fn test_e2e_addon_from_zero_pending() {
    let input = AddonInput {
        seat_index: 0,
        amount: 500,
    };
    let row = AddonRow::active(
        &input,
        0,   // pre_pending = 0
        0,   // pre_chip_pool
        500, // post_chip_pool
        zero_root(),
        one_root(),
        1,
        0,
        0,
        0,
        1,
        0,
        0,
    );
    let trace = gen_method_trace(
        AddonAir::num_columns(),
        &row.to_vec(),
        &AddonRow::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = AddonAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 1,
        hand_id: 0,
        call_seq: 0,
        pre_version: 0,
        post_version: 1,
    };

    let proof = prove_method(
        &trace,
        air,
        AddonAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::Addon, 1, 0, 0),
    )
    .expect("prove 失败");
    verify_method(proof).expect("verify 失败");
}

/// 回归：amount 的低 limb 为 0 时仍应接受合法的非零 u64 金额。
#[test]
fn test_e2e_addon_high_limb_amount() {
    let input = AddonInput {
        seat_index: 0,
        amount: 65_536,
    };
    let row = AddonRow::active(
        &input,
        0,
        0,
        65_536,
        zero_root(),
        one_root(),
        1,
        0,
        0,
        0,
        1,
        0,
        0,
    );
    let trace = gen_method_trace(
        AddonAir::num_columns(),
        &row.to_vec(),
        &AddonRow::padding().to_vec(),
    )
    .expect("trace 生成失败");
    let air = AddonAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 1,
        hand_id: 0,
        call_seq: 0,
        pre_version: 0,
        post_version: 1,
    };
    let proof = prove_method(
        &trace,
        air,
        AddonAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::Addon, 1, 0, 0),
    )
    .expect("高 limb addon 应可证明");
    verify_method(proof).expect("高 limb addon 应可验证");
}

/// 回归：pending_addon 跨过 16-bit limb 边界时仍可证明。
#[test]
fn test_e2e_addon_ripple_carry() {
    let input = AddonInput {
        seat_index: 0,
        amount: 1,
    };
    let row = AddonRow::active(
        &input,
        65_535,
        0,
        1,
        zero_root(),
        one_root(),
        1,
        0,
        0,
        0,
        1,
        0,
        0,
    );
    let trace = gen_method_trace(
        AddonAir::num_columns(),
        &row.to_vec(),
        &AddonRow::padding().to_vec(),
    )
    .expect("trace 生成失败");
    let air = AddonAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 1,
        hand_id: 0,
        call_seq: 0,
        pre_version: 0,
        post_version: 1,
    };
    let proof = prove_method(
        &trace,
        air,
        AddonAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::Addon, 1, 0, 0),
    )
    .expect("跨 limb addon 应可证明");
    verify_method(proof).expect("跨 limb addon 应可验证");
}

/// Soundness: 篡改 addon 的 `amount` 公开输入后，verify 应失败。
///
/// 流程：用正确 AIR 生成 proof → 篡改 proof.air.input.amount → verify 应失败。
/// 原因：trace 中 `post_pending_addon = pre + 正确 amount`，
/// 但 AIR 公开输入变为 `篡改 amount`，约束 `post == pre + 篡改 amount` 不成立。
#[test]
fn test_soundness_addon_tampered_amount() {
    let input = AddonInput {
        seat_index: 3,
        amount: 200,
    };
    let pre_pending = 100;
    let row = AddonRow::active(
        &input,
        pre_pending,
        0,   // pre_chip_pool
        200, // post_chip_pool
        zero_root(),
        one_root(),
        42,
        0,
        1,
        0,
        1,
        0,
        0,
    );
    let trace = gen_method_trace(
        AddonAir::num_columns(),
        &row.to_vec(),
        &AddonRow::padding().to_vec(),
    )
    .expect("trace 生成失败");

    // 用正确的 AIR 生成 proof（trace 与 AIR 一致）
    let air = AddonAir {
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
        AddonAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::Addon, 42, 0, 1),
    )
    .expect("prove 失败");

    // 篡改 proof.air.input.amount：trace 中是 200，但 AIR 声明 999
    proof.air = AddonAir {
        input: AddonInput {
            amount: 999, // 篡改！
            ..proof.air.input.clone()
        },
        ..proof.air.clone()
    };

    // verify 应失败（约束 post_pending_0 != pre_pending_0 + 999）
    let result = verify_method(proof);
    assert!(
        result.is_err(),
        "篡改 amount 后 verify 应失败，但成功了 — soundness 漏洞！"
    );
}

/// Soundness: 篡改 addon 的 `seat_index` 公开输入后，verify 应失败。
#[test]
fn test_soundness_addon_tampered_seat() {
    let input = AddonInput {
        seat_index: 3,
        amount: 200,
    };
    let row = AddonRow::active(
        &input,
        100,
        0,   // pre_chip_pool
        200, // post_chip_pool
        zero_root(),
        one_root(),
        42,
        0,
        1,
        0,
        1,
        0,
        0,
    );
    let trace = gen_method_trace(
        AddonAir::num_columns(),
        &row.to_vec(),
        &AddonRow::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = AddonAir {
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
        AddonAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::Addon, 42, 0, 1),
    )
    .expect("prove 失败");

    // 篡改 seat_index
    proof.air = AddonAir {
        input: AddonInput {
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

/// Soundness：只篡改 amount 的高 limb 也必须失败。
#[test]
fn test_soundness_addon_tampered_high_amount_limb() {
    let input = AddonInput {
        seat_index: 0,
        amount: 200,
    };
    let row = AddonRow::active(
        &input,
        0,
        0,
        200,
        zero_root(),
        one_root(),
        1,
        0,
        0,
        0,
        1,
        0,
        0,
    );
    let trace = gen_method_trace(
        AddonAir::num_columns(),
        &row.to_vec(),
        &AddonRow::padding().to_vec(),
    )
    .expect("trace 生成失败");
    let air = AddonAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 1,
        hand_id: 0,
        call_seq: 0,
        pre_version: 0,
        post_version: 1,
    };
    let mut proof = prove_method(
        &trace,
        air,
        AddonAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::Addon, 1, 0, 0),
    )
    .expect("prove 失败");
    proof.air.input.amount += 65_536;
    assert!(verify_method(proof).is_err(), "高 limb amount 篡改必须失败");
}

/// Soundness：post chip_pool 必须等于 pre chip_pool + amount。
#[test]
fn test_soundness_addon_tampered_post_chip_pool() {
    use poker_texas_air::airs::funds::addon::cols;
    let input = AddonInput {
        seat_index: 0,
        amount: 200,
    };
    let row = AddonRow::active(
        &input,
        0,
        0,
        200,
        zero_root(),
        one_root(),
        1,
        0,
        0,
        0,
        1,
        0,
        0,
    );
    let mut trace_vec = row.to_vec();
    trace_vec[cols::OUTPUT_POST_CHIP_POOL_BASE] = M31::from(199u32);
    let trace = gen_method_trace(
        AddonAir::num_columns(),
        &trace_vec,
        &AddonRow::padding().to_vec(),
    )
    .expect("trace 生成失败");
    let air = AddonAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 1,
        hand_id: 0,
        call_seq: 0,
        pre_version: 0,
        post_version: 1,
    };
    assert!(
        prove_method(
            &trace,
            air,
            AddonAir::num_columns(),
            TexasPublicInputs::synthetic_for_test(MethodKind::Addon, 1, 0, 0),
        )
        .is_err(),
        "篡改 addon post chip_pool 时 prove 必须失败"
    );
}

// ========== rebuy AIR ==========

/// E2E: rebuy → trace → prove → verify（happy path）。
///
/// 场景：seat 2 当前 stack = 1000，rebuy 500，结果 stack = 1500。
#[test]
fn test_e2e_rebuy_prove_verify() {
    let input = RebuyInput {
        seat_index: 2,
        amount: 500,
    };
    let pre_stack = 1000;
    let row = RebuyRow::active(
        &input,
        pre_stack,
        0,   // pre_chip_pool
        500, // post_chip_pool
        zero_root(),
        one_root(),
        42, // table_id
        0,  // hand_id
        3,  // call_seq
        0,  // pre_version
        1,  // post_version
        0,  // pre_round_state
        0,  // post_round_state
    );
    let trace = gen_method_trace(
        RebuyAir::num_columns(),
        &row.to_vec(),
        &RebuyRow::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = RebuyAir {
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
        RebuyAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::Rebuy, 42, 0, 3),
    )
    .expect("prove 失败");
    verify_method(proof).expect("verify 失败");
}

/// 回归：stack 跨过 16-bit limb 边界时仍可证明。
#[test]
fn test_e2e_rebuy_ripple_carry() {
    let input = RebuyInput {
        seat_index: 0,
        amount: 1,
    };
    let row = RebuyRow::active(
        &input,
        65_535,
        0,
        1,
        zero_root(),
        one_root(),
        1,
        0,
        0,
        0,
        1,
        0,
        0,
    );
    let trace = gen_method_trace(
        RebuyAir::num_columns(),
        &row.to_vec(),
        &RebuyRow::padding().to_vec(),
    )
    .expect("trace 生成失败");
    let air = RebuyAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 1,
        hand_id: 0,
        call_seq: 0,
        pre_version: 0,
        post_version: 1,
    };
    let proof = prove_method(
        &trace,
        air,
        RebuyAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::Rebuy, 1, 0, 0),
    )
    .expect("跨 limb rebuy 应可证明");
    verify_method(proof).expect("跨 limb rebuy 应可验证");
}

/// Soundness: 篡改 rebuy 的 `amount` 公开输入后，verify 应失败。
///
/// 原因：trace 中 `post_stack = pre_stack + 正确 amount`，
/// 篡改后约束 `post_stack == pre_stack + 篡改 amount` 不成立。
#[test]
fn test_soundness_rebuy_tampered_amount() {
    let input = RebuyInput {
        seat_index: 2,
        amount: 500,
    };
    let pre_stack = 1000;
    let row = RebuyRow::active(
        &input,
        pre_stack,
        0,   // pre_chip_pool
        500, // post_chip_pool
        zero_root(),
        one_root(),
        42,
        0,
        3,
        0,
        1,
        0,
        0,
    );
    let trace = gen_method_trace(
        RebuyAir::num_columns(),
        &row.to_vec(),
        &RebuyRow::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = RebuyAir {
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
        RebuyAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::Rebuy, 42, 0, 3),
    )
    .expect("prove 失败");

    // 篡改 amount：trace 中是 500，但 AIR 声明 777
    proof.air = RebuyAir {
        input: RebuyInput {
            amount: 777, // 篡改！
            ..proof.air.input.clone()
        },
        ..proof.air.clone()
    };

    let result = verify_method(proof);
    assert!(
        result.is_err(),
        "篡改 amount 后 verify 应失败，但成功了 — soundness 漏洞！"
    );
}

/// Soundness（阶段 3 range-check）：rebuy 的 input_amount limb 若 ≥ 2^16，
/// range16 约束应使 prove 失败（验证 range-check 真实生效，非摆设）。
#[test]
fn test_soundness_rebuy_range_violation() {
    use poker_texas_air::airs::common::COMMON_NUM_COLUMNS;
    let input = RebuyInput {
        seat_index: 2,
        amount: 500,
    };
    let row = RebuyRow::active(
        &input,
        1000, // pre_stack
        0,    // pre_chip_pool
        500,  // post_chip_pool
        zero_root(),
        one_root(),
        42,
        0,
        3,
        0,
        1,
        0,
        0,
    );
    let mut trace_vec = row.to_vec();
    // 篡改 input_amount limb 0：设为 70000（≥ 65536，超出 16-bit 范围）。
    // input_amount 起始列 = COMMON_NUM_COLUMNS + 1（见 rebuy::cols::INPUT_AMOUNT_BASE）。
    trace_vec[COMMON_NUM_COLUMNS + 1] = M31::from(70000u32);
    let trace = gen_method_trace(
        RebuyAir::num_columns(),
        &trace_vec,
        &RebuyRow::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = RebuyAir {
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
    // prove 应失败：range16 约束（amount_limb0 = 70000，bit 分解无法重建）不满足。
    let result = prove_method(
        &trace,
        air,
        RebuyAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::Rebuy, 42, 0, 3),
    );
    assert!(
        result.is_err(),
        "amount limb ≥ 2^16 时 prove 应失败（range16 约束生效），但成功了 — range-check 漏洞！"
    );
}

/// Soundness: 篡改 rebuy 的 `seat_index` 公开输入后，verify 应失败。
#[test]
fn test_soundness_rebuy_tampered_seat() {
    let input = RebuyInput {
        seat_index: 2,
        amount: 500,
    };
    let row = RebuyRow::active(
        &input,
        1000,
        0,   // pre_chip_pool
        500, // post_chip_pool
        zero_root(),
        one_root(),
        42,
        0,
        3,
        0,
        1,
        0,
        0,
    );
    let trace = gen_method_trace(
        RebuyAir::num_columns(),
        &row.to_vec(),
        &RebuyRow::padding().to_vec(),
    )
    .expect("trace 生成失败");

    let air = RebuyAir {
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
        RebuyAir::num_columns(),
        TexasPublicInputs::synthetic_for_test(MethodKind::Rebuy, 42, 0, 3),
    )
    .expect("prove 失败");

    proof.air = RebuyAir {
        input: RebuyInput {
            seat_index: 5, // 篡改！
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

/// Soundness：rebuy post chip_pool 必须等于 pre chip_pool + amount。
#[test]
fn test_soundness_rebuy_tampered_post_chip_pool() {
    use poker_texas_air::airs::funds::rebuy::cols;
    let input = RebuyInput {
        seat_index: 0,
        amount: 500,
    };
    let row = RebuyRow::active(
        &input,
        1_000,
        0,
        500,
        zero_root(),
        one_root(),
        1,
        0,
        0,
        0,
        1,
        0,
        0,
    );
    let mut trace_vec = row.to_vec();
    trace_vec[cols::OUTPUT_POST_CHIP_POOL_BASE] = M31::from(499u32);
    let trace = gen_method_trace(
        RebuyAir::num_columns(),
        &trace_vec,
        &RebuyRow::padding().to_vec(),
    )
    .expect("trace 生成失败");
    let air = RebuyAir {
        log_size: trace.log_size,
        input,
        pre_state_root: zero_root(),
        post_state_root: one_root(),
        table_id: 1,
        hand_id: 0,
        call_seq: 0,
        pre_version: 0,
        post_version: 1,
    };
    assert!(
        prove_method(
            &trace,
            air,
            RebuyAir::num_columns(),
            TexasPublicInputs::synthetic_for_test(MethodKind::Rebuy, 1, 0, 0),
        )
        .is_err(),
        "篡改 rebuy post chip_pool 时 prove 必须失败"
    );
}

// ========== 列数一致性测试 ==========

/// 验证 funds AIR 的列数与 cols::NUM_COLUMNS 一致。
#[test]
fn test_funds_air_column_consistency() {
    use poker_texas_air::airs::common::COMMON_NUM_COLUMNS;
    use poker_texas_air::airs::funds::addon;
    use poker_texas_air::airs::funds::rebuy;

    // addon: 通用 + 39 业务（pending addon 与 chip-pool 两条 checked-u64 加法）
    assert_eq!(addon::cols::NUM_COLUMNS, COMMON_NUM_COLUMNS + 39);
    assert_eq!(AddonAir::num_columns(), addon::cols::NUM_COLUMNS);

    // rebuy: 通用 + 103 业务（stack/chip_pool 两条 checked-u64 加法 + amount range bits）
    assert_eq!(rebuy::cols::NUM_COLUMNS, COMMON_NUM_COLUMNS + 103);
    assert_eq!(RebuyAir::num_columns(), rebuy::cols::NUM_COLUMNS);
}

/// 验证 funds method kinds 分类正确。
#[test]
fn test_funds_method_kinds() {
    use poker_texas_air::method_kind::{MethodKind, MethodTier};

    assert_eq!(MethodKind::Addon as u8, 13);
    assert_eq!(MethodKind::Rebuy as u8, 14);
    assert_eq!(MethodKind::Addon.tier(), MethodTier::Funds);
    assert_eq!(MethodKind::Rebuy.tier(), MethodTier::Funds);
    assert_eq!(MethodKind::Addon.method_name(), "addon");
    assert_eq!(MethodKind::Rebuy.method_name(), "rebuy");
}
