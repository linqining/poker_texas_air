//! E2E 测试 — `create_table` 单方法 prove + verify + soundness。
//!
//! 验证流程：
//! 1. 构造 pre/post `TexasPokerTable`
//! 2. 调用 `gen_create_table_trace` 生成 trace
//! 3. 调用 `prove_create_table` 生成 Stwo proof
//! 4. 调用 `verify_create_table` 验证 proof
//! 5. Soundness：篡改 AIR 公开输入后验证应失败

use poker_l1::object_model::ObjectID;
use poker_l1::vm::contracts::texas_poker::types::{EMPTY_PLAYER, TexasPokerTable};
use stwo::core::fields::m31::M31;

use poker_texas_air::airs::lifecycle::create_table::{CreateTableAir, CreateTableInput};
use poker_texas_air::method_kind::MethodKind;
use poker_texas_air::prover::prove_create_table;
use poker_texas_air::public_inputs::TexasPublicInputs;
use poker_texas_air::trace_gen::create_table_trace::gen_create_table_trace;
use poker_texas_air::verifier::verify_create_table;

/// 构造测试用 `TexasPokerTable`（pre-state，placeholder）。
fn make_pre_table() -> TexasPokerTable {
    TexasPokerTable::new(
        ObjectID::new([0xAA; 20], 42),
        String::new(),
        EMPTY_PLAYER,
        2,
        1,
        1,
    )
}

/// 构造测试用 `TexasPokerTable`（post-state，真实新建桌台）。
fn make_post_table() -> TexasPokerTable {
    let mut t = TexasPokerTable::new(
        ObjectID::new([0xAA; 20], 42),
        "test_table".to_string(),
        [0xCC; 20],
        6,
        10,
        20,
    );
    // create_table 语义：post call_seq = pre call_seq(0) + 1 = 1。
    t.call_seq = 1;
    t
}

/// E2E: create_table → trace → prove → verify（happy path）。
#[test]
fn test_e2e_create_table_prove_verify() {
    // 1. 构造 pre/post state
    let pre_table = make_pre_table();
    let post_table = make_post_table();

    // 2. 构造输入
    let input = CreateTableInput {
        name: "test_table".to_string(),
        max_players: 6,
        small_blind: 10,
        big_blind: 20,
    };

    // 3. 生成 trace
    let trace = gen_create_table_trace(
        input,
        &pre_table,
        &post_table,
        42, // table_id
        0,  // hand_id
        1,  // call_seq
    )
    .expect("trace 生成失败");

    // 4. 生成 proof
    let proof = prove_create_table(
        &trace,
        TexasPublicInputs::from_tables(&pre_table, &post_table, MethodKind::CreateTable, 42, 0, 1)
            .expect("PI 构造失败"),
    )
    .expect("prove 失败");

    // 5. 验证 proof
    verify_create_table(proof).expect("verify 失败");
}

/// Historical synthetic placeholders are no longer admitted even as proof fixtures.  Only the
/// exact ObjectDb-absence placeholder maps to the distinguished zero root.
#[test]
fn production_verifier_rejects_noncanonical_create_placeholder() {
    let pre_table = TexasPokerTable::new(
        ObjectID::new([0xAA; 20], 42),
        "legacy-placeholder".into(),
        EMPTY_PLAYER,
        2,
        1,
        2,
    );
    let post_table = make_post_table();
    let error =
        TexasPublicInputs::from_tables(&pre_table, &post_table, MethodKind::CreateTable, 42, 0, 1)
            .expect_err("noncanonical create placeholder must not produce public inputs");
    assert!(error.to_string().contains("governance creator is empty"));
}

/// Soundness: 篡改 AIR 的 `max_players` 公开输入后，verify 应失败。
///
/// Prover 用 max_players=6 生成 trace，但 verifier 用 max_players=9 构造 AIR，
/// 约束 `is_active * (input_max_players - expected_max_players) = 0` 应不满足。
#[test]
fn test_soundness_tampered_max_players() {
    let pre_table = make_pre_table();
    let post_table = make_post_table();

    let input = CreateTableInput {
        name: "test_table".to_string(),
        max_players: 6,
        small_blind: 10,
        big_blind: 20,
    };

    let trace =
        gen_create_table_trace(input, &pre_table, &post_table, 42, 0, 1).expect("trace 生成失败");

    // 用正确的 trace 生成 proof
    let mut proof = prove_create_table(
        &trace,
        TexasPublicInputs::from_tables(&pre_table, &post_table, MethodKind::CreateTable, 42, 0, 1)
            .expect("PI 构造失败"),
    )
    .expect("prove 失败");

    // 篡改 AIR 的 max_players（6 → 9）
    proof.air = CreateTableAir {
        input: CreateTableInput {
            name: "test_table".to_string(),
            max_players: 9, // 篡改！
            small_blind: 10,
            big_blind: 20,
        },
        ..proof.air.clone()
    };

    // 验证应失败（约束不满足）
    let result = verify_create_table(proof);
    assert!(
        result.is_err(),
        "篡改 max_players 后 verify 应失败，但成功了 — soundness 漏洞！"
    );
}

/// Soundness: 篡改 `big_blind` 为 0 后，约束 `big_blind > 0` 应不满足。
#[test]
fn test_soundness_zero_big_blind() {
    let pre_table = make_pre_table();
    let post_table = make_post_table();

    let input = CreateTableInput {
        name: "test_table".to_string(),
        max_players: 6,
        small_blind: 10,
        big_blind: 20,
    };

    let trace =
        gen_create_table_trace(input, &pre_table, &post_table, 42, 0, 1).expect("trace 生成失败");

    let mut proof = prove_create_table(
        &trace,
        TexasPublicInputs::from_tables(&pre_table, &post_table, MethodKind::CreateTable, 42, 0, 1)
            .expect("PI 构造失败"),
    )
    .expect("prove 失败");

    // 篡改 big_blind（20 → 0），违反 `big_blind > 0` 约束
    proof.air = CreateTableAir {
        input: CreateTableInput {
            name: "test_table".to_string(),
            max_players: 6,
            small_blind: 10,
            big_blind: 0, // 篡改！
        },
        ..proof.air.clone()
    };

    let result = verify_create_table(proof);
    assert!(
        result.is_err(),
        "篡改 big_blind=0 后 verify 应失败，但成功了 — soundness 漏洞！"
    );
}

/// Soundness: 仅篡改大盲高位 limb、保持低 16 位不变也必须失败。
#[test]
fn test_soundness_tampered_big_blind_high_limb() {
    let pre_table = make_pre_table();
    let post_table = make_post_table();
    let input = CreateTableInput {
        name: "test_table".to_string(),
        max_players: 6,
        small_blind: 10,
        big_blind: 20,
    };
    let trace =
        gen_create_table_trace(input, &pre_table, &post_table, 42, 0, 1).expect("trace 生成失败");
    let mut proof = prove_create_table(
        &trace,
        TexasPublicInputs::from_tables(&pre_table, &post_table, MethodKind::CreateTable, 42, 0, 1)
            .expect("PI 构造失败"),
    )
    .expect("prove 失败");
    proof.air.input.big_blind = 20 + (1u64 << 32);
    assert!(verify_create_table(proof).is_err());
}

fn invalid_statement_cannot_prove(input: CreateTableInput) {
    let pre_table = make_pre_table();
    let post_table = make_post_table();
    let trace = gen_create_table_trace(input, &pre_table, &post_table, 42, 0, 1)
        .expect("invalid statement trace construction should remain deterministic");
    let result = prove_create_table(
        &trace,
        TexasPublicInputs::from_tables(&pre_table, &post_table, MethodKind::CreateTable, 42, 0, 1)
            .expect("PI 构造失败"),
    );
    assert!(
        result.is_err(),
        "invalid create_table statement unexpectedly proved"
    );
}

#[test]
fn test_air_rejects_out_of_range_max_players_without_host_validation() {
    invalid_statement_cannot_prove(CreateTableInput {
        name: "invalid-max".into(),
        max_players: 1,
        small_blind: 10,
        big_blind: 20,
    });
}

#[test]
fn test_air_rejects_zero_big_blind_without_host_validation() {
    invalid_statement_cannot_prove(CreateTableInput {
        name: "zero-big".into(),
        max_players: 6,
        small_blind: 0,
        big_blind: 0,
    });
}

#[test]
fn test_air_rejects_inverted_blinds_without_host_validation() {
    invalid_statement_cannot_prove(CreateTableInput {
        name: "inverted".into(),
        max_players: 6,
        small_blind: 21,
        big_blind: 20,
    });
}

/// 单元测试：验证 `CreateTableAir::num_columns()` 与 `cols::NUM_COLUMNS` 一致。
#[test]
fn test_num_columns_consistency() {
    use poker_texas_air::airs::lifecycle::create_table::cols;
    assert_eq!(
        cols::NUM_COLUMNS,
        poker_texas_air::airs::common::COMMON_NUM_COLUMNS + 19
    );
}

/// 单元测试：验证 `ZERO` 常量等于 `M31::from(0u32)`。
#[test]
fn test_zero_constant() {
    use poker_texas_air::airs::common::ZERO;
    assert_eq!(ZERO, M31::from(0u32));
}
