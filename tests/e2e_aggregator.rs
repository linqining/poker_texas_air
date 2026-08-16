//! 机制测试 — descriptor-only Aggregator AIR；不验证子 proof，生产入口 fail-closed。
//!
//! 验证流程：
//! 1. 构造 N 个 `ChildDescriptor`（按 `call_seq` 升序、state_root 链式衔接）
//! 2. 调用 `prove_aggregator` 生成聚合 Stwo proof
//! 3. 调用 `verify_aggregator` 验证 proof
//! 4. Soundness：
//!    - 链式连续性破坏 → `prove_aggregator` 应返回 `RecursionError`
//!    - call_seq 顺序错误 → `prove_aggregator` 应返回 `RecursionError`
//!    - 篡改 proof.air 的 left/right 描述符 → `verify_aggregator` 应失败
//!
//! ## 简化策略
//!
//! 阶段 4 PoC：Aggregator AIR 只验证状态链式连续性（state_root 衔接）+
//! 方法种类/call_seq 一致性。完整递归（嵌入 Layer 1 Verifier AIR）留待阶段 5。

use stwo::core::fields::m31::M31;

use poker_texas_air::aggregator_air::{ChildDescriptor, build_binary_tree};
use poker_texas_air::aggregator_prover::{
    HostAttestation, prove_aggregator, prove_aggregator_host_attested,
    prove_aggregator_unchecked_for_tests,
};
use poker_texas_air::aggregator_verifier::{
    verify_aggregator, verify_aggregator_host_attested, verify_aggregator_unchecked_for_tests,
};
use poker_texas_air::airs::common::ZERO;
use poker_texas_air::error::TexasAirError;
use poker_texas_air::method_kind::MethodKind;

/// 构造 state_root limb（4 个相同值）。
fn root_of(v: u32) -> [M31; 4] {
    [M31::from(v); 4]
}

/// 构造一个 ChildDescriptor。
///
/// # 参数
/// - `seq`: call_seq
/// - `kind`: method_kind
/// - `pre`: pre_state_root 值
/// - `post`: post_state_root 值
fn make_child(seq: u32, kind: MethodKind, pre: u32, post: u32) -> ChildDescriptor {
    ChildDescriptor {
        pre_state_root: root_of(pre),
        post_state_root: root_of(post),
        call_seq: seq,
        method_kind: kind,
    }
}

/// 构造链式衔接的 N 个子节点（state_root 链式）。
///
/// state_root 序列：`r0 → r0 → r1 → r1 → r2 → r2 → ...`
/// 即 child[i].pre == child[i-1].post。
fn make_chain(seqs: &[u32], kinds: &[MethodKind], roots: &[u32]) -> Vec<ChildDescriptor> {
    assert_eq!(seqs.len(), kinds.len());
    assert_eq!(seqs.len(), roots.len());
    seqs.iter()
        .enumerate()
        .map(|(i, &seq)| {
            let pre = roots[i];
            let post = if i + 1 < roots.len() {
                roots[i + 1]
            } else {
                roots[i]
            };
            make_child(seq, kinds[i], pre, post)
        })
        .collect()
}

// ========== E2E happy path ==========

/// Production entry points fail closed because descriptor-only aggregation does not verify children.
#[test]
fn test_production_aggregator_entry_points_reject_untrusted_poc() {
    let children = make_chain(
        &[0, 1],
        &[MethodKind::CreateTable, MethodKind::JoinTable],
        &[10, 20],
    );

    assert!(matches!(
        prove_aggregator(children.clone()),
        Err(TexasAirError::UntrustedAggregationDisabled)
    ));

    let poc_proof = prove_aggregator_unchecked_for_tests(children.clone())
        .expect("test-only PoC prove should work");
    assert!(matches!(
        verify_aggregator(poc_proof.clone()),
        Err(TexasAirError::UntrustedAggregationDisabled)
    ));

    let attestation = HostAttestation {
        verified_count: children.len(),
        anchor_state_root: poker_texas_air::state_root::StateRoot::zero(),
        final_state_root: poker_texas_air::state_root::StateRoot::zero(),
    };
    assert!(matches!(
        prove_aggregator_host_attested(children, &attestation),
        Err(TexasAirError::UntrustedAggregationDisabled)
    ));
    assert!(matches!(
        verify_aggregator_host_attested(poc_proof),
        Err(TexasAirError::UntrustedAggregationDisabled)
    ));
}

#[test]
fn test_soundness_aggregator_rejects_call_seq_gap() {
    let children = vec![
        make_child(10, MethodKind::CreateTable, 10, 20),
        make_child(12, MethodKind::JoinTable, 20, 30),
    ];
    assert!(matches!(
        prove_aggregator_unchecked_for_tests(children),
        Err(TexasAirError::RecursionError(_))
    ));
}

#[test]
fn test_soundness_aggregator_rejects_tampered_endpoints_and_metadata() {
    let children = make_chain(
        &[0, 1],
        &[MethodKind::CreateTable, MethodKind::JoinTable],
        &[10, 20],
    );
    let proof = prove_aggregator_unchecked_for_tests(children).expect("fixture proof");

    let mut changed_endpoint = proof.clone();
    changed_endpoint.air.agg_post_state_root = root_of(999);
    assert!(verify_aggregator_unchecked_for_tests(changed_endpoint).is_err());

    let mut changed_count = proof.clone();
    changed_count.num_children += 1;
    assert!(verify_aggregator_unchecked_for_tests(changed_count).is_err());

    let mut changed_levels = proof;
    changed_levels.num_levels += 1;
    assert!(verify_aggregator_unchecked_for_tests(changed_levels).is_err());
}

/// E2E: 聚合 2 个 method proof → prove → verify（happy path，单层聚合）。
#[test]
fn test_e2e_aggregate_two_children() {
    let children = make_chain(
        &[0, 1],
        &[MethodKind::CreateTable, MethodKind::JoinTable],
        &[10, 20],
    );

    let proof = prove_aggregator_unchecked_for_tests(children).expect("prove 失败");
    assert_eq!(proof.num_children, 2);
    assert_eq!(proof.num_levels, 1);
    verify_aggregator_unchecked_for_tests(proof).expect("verify 失败");
}

/// E2E: 聚合 4 个 method proof → prove → verify（双层聚合）。
#[test]
fn test_e2e_aggregate_four_children() {
    let children = make_chain(
        &[0, 1, 2, 3],
        &[
            MethodKind::CreateTable,
            MethodKind::JoinTable,
            MethodKind::StartHand,
            MethodKind::Fold,
        ],
        &[10, 20, 30, 40],
    );

    let proof = prove_aggregator_unchecked_for_tests(children).expect("prove 失败");
    assert_eq!(proof.num_children, 4);
    assert_eq!(proof.num_levels, 2);
    verify_aggregator_unchecked_for_tests(proof).expect("verify 失败");
}

/// E2E: 聚合 8 个 method proof → prove → verify（三层聚合）。
#[test]
fn test_e2e_aggregate_eight_children() {
    let kinds = [
        MethodKind::CreateTable,
        MethodKind::JoinTable,
        MethodKind::StartHand,
        MethodKind::Fold,
        MethodKind::Check,
        MethodKind::Call,
        MethodKind::Raise,
        MethodKind::Bet,
    ];
    let roots: Vec<u32> = (0..8).map(|i| 10 * (i + 1)).collect();
    let seqs: Vec<u32> = (0..8).collect();
    let children = make_chain(&seqs, &kinds, &roots);

    let proof = prove_aggregator_unchecked_for_tests(children).expect("prove 失败");
    assert_eq!(proof.num_children, 8);
    assert_eq!(proof.num_levels, 3);
    verify_aggregator_unchecked_for_tests(proof).expect("verify 失败");
}

/// E2E: 聚合 3 个 method proof（奇数节点，含晋升）→ prove → verify。
#[test]
fn test_e2e_aggregate_three_children_odd() {
    let children = make_chain(
        &[0, 1, 2],
        &[
            MethodKind::CreateTable,
            MethodKind::JoinTable,
            MethodKind::StartHand,
        ],
        &[10, 20, 30],
    );

    let proof = prove_aggregator_unchecked_for_tests(children).expect("prove 失败");
    assert_eq!(proof.num_children, 3);
    // 3 节点：底层 1 个聚合行（pair 0+1），顶层 1 个聚合行（pair 上层结果 + 2）
    assert_eq!(proof.num_levels, 2);
    verify_aggregator_unchecked_for_tests(proof).expect("verify 失败");
}

// ========== Soundness: build_binary_tree 错误检测 ==========

/// Soundness: 链式连续性破坏 → prove_aggregator 应返回 RecursionError。
#[test]
fn test_soundness_aggregator_chain_break() {
    // child[0].post = 20, child[1].pre = 99 → 链式破坏
    let children = vec![
        make_child(0, MethodKind::CreateTable, 10, 20),
        make_child(1, MethodKind::JoinTable, 99, 30), // pre ≠ 上一个 post
    ];

    let result = prove_aggregator_unchecked_for_tests(children);
    assert!(
        matches!(result, Err(TexasAirError::RecursionError(_))),
        "链式连续性破坏应返回 RecursionError，实际：{result:?}"
    );
}

/// Soundness: call_seq 顺序错误 → prove_aggregator 应返回 RecursionError。
#[test]
fn test_soundness_aggregator_seq_reversed() {
    // call_seq 反向：child[0].seq=5, child[1].seq=0
    let children = vec![
        make_child(5, MethodKind::CreateTable, 10, 20),
        make_child(0, MethodKind::JoinTable, 20, 30), // seq 反向
    ];

    let result = prove_aggregator_unchecked_for_tests(children);
    assert!(
        matches!(result, Err(TexasAirError::RecursionError(_))),
        "call_seq 反向应返回 RecursionError，实际：{result:?}"
    );
}

/// Soundness: 单子节点 → prove_aggregator 应返回 RecursionError（无需聚合）。
#[test]
fn test_soundness_aggregator_single_child_no_agg() {
    let children = vec![make_child(0, MethodKind::CreateTable, 10, 20)];

    let result = prove_aggregator_unchecked_for_tests(children);
    assert!(
        matches!(result, Err(TexasAirError::RecursionError(_))),
        "单子节点应返回 RecursionError（levels 为空），实际：{result:?}"
    );
}

/// Soundness: 空子节点列表 → prove_aggregator 应返回 RecursionError。
#[test]
fn test_soundness_aggregator_empty_children() {
    let result = prove_aggregator_unchecked_for_tests(vec![]);
    assert!(
        matches!(result, Err(TexasAirError::RecursionError(_))),
        "空子节点列表应返回 RecursionError，实际：{result:?}"
    );
}

// ========== Soundness: 篡改 proof.air 后 verify 失败 ==========

/// Soundness: 篡改 proof.air.left.call_seq 后 verify 应失败。
///
/// 流程：用正确 children 生成 proof → 篡改 proof.air.left 的 call_seq → verify 应失败。
#[test]
fn test_soundness_aggregator_tampered_left_seq() {
    let children = make_chain(
        &[0, 1],
        &[MethodKind::CreateTable, MethodKind::JoinTable],
        &[10, 20],
    );

    let mut proof = prove_aggregator_unchecked_for_tests(children).expect("prove 失败");

    // 篡改 left.call_seq：trace 中是 0，AIR 声明 99
    proof.air.left.call_seq = 99;

    let result = verify_aggregator_unchecked_for_tests(proof);
    assert!(
        result.is_err(),
        "篡改 left.call_seq 后 verify 应失败，但成功了 — soundness 漏洞！"
    );
}

/// Soundness: 篡改 proof.air.right.method_kind 后 verify 应失败。
#[test]
fn test_soundness_aggregator_tampered_right_kind() {
    let children = make_chain(
        &[0, 1],
        &[MethodKind::CreateTable, MethodKind::JoinTable],
        &[10, 20],
    );

    let mut proof = prove_aggregator_unchecked_for_tests(children).expect("prove 失败");

    // 篡改 right.method_kind：trace 中是 JoinTable (1)，AIR 声明 Fold (6)
    proof.air.right.method_kind = MethodKind::Fold;

    let result = verify_aggregator_unchecked_for_tests(proof);
    assert!(
        result.is_err(),
        "篡改 right.method_kind 后 verify 应失败，但成功了 — soundness 漏洞！"
    );
}

/// Soundness: 篡改 proof.air.left.method_kind 后 verify 应失败。
#[test]
fn test_soundness_aggregator_tampered_left_kind() {
    let children = make_chain(
        &[0, 1],
        &[MethodKind::CreateTable, MethodKind::JoinTable],
        &[10, 20],
    );

    let mut proof = prove_aggregator_unchecked_for_tests(children).expect("prove 失败");

    // 篡改 left.method_kind：trace 中是 CreateTable (0)，AIR 声明 Tick (4)
    proof.air.left.method_kind = MethodKind::AdvanceDeadline;

    let result = verify_aggregator_unchecked_for_tests(proof);
    assert!(
        result.is_err(),
        "篡改 left.method_kind 后 verify 应失败，但成功了 — soundness 漏洞！"
    );
}

/// Soundness: 篡改 proof.air.right.call_seq 后 verify 应失败。
#[test]
fn test_soundness_aggregator_tampered_right_seq() {
    let children = make_chain(
        &[0, 1],
        &[MethodKind::CreateTable, MethodKind::JoinTable],
        &[10, 20],
    );

    let mut proof = prove_aggregator_unchecked_for_tests(children).expect("prove 失败");

    // 篡改 right.call_seq：trace 中是 1，AIR 声明 99
    proof.air.right.call_seq = 99;

    let result = verify_aggregator_unchecked_for_tests(proof);
    assert!(
        result.is_err(),
        "篡改 right.call_seq 后 verify 应失败，但成功了 — soundness 漏洞！"
    );
}

// ========== build_binary_tree 直接单元测试（覆盖更多边界）==========

/// 单元测试：build_binary_tree 的链式连续性破坏检测。
#[test]
fn test_build_binary_tree_chain_break_direct() {
    let children = vec![
        make_child(0, MethodKind::CreateTable, 10, 20),
        make_child(1, MethodKind::JoinTable, 99, 30), // pre ≠ 上一 post
    ];
    let result = build_binary_tree(children);
    assert!(
        matches!(result, Err(TexasAirError::RecursionError(_))),
        "链式破坏应返回 RecursionError"
    );
}

/// 单元测试：build_binary_tree 的 call_seq 顺序错误检测。
#[test]
fn test_build_binary_tree_seq_break_direct() {
    let children = vec![
        make_child(5, MethodKind::CreateTable, 10, 20),
        make_child(0, MethodKind::JoinTable, 20, 30), // seq 反向
    ];
    let result = build_binary_tree(children);
    assert!(
        matches!(result, Err(TexasAirError::RecursionError(_))),
        "seq 反向应返回 RecursionError"
    );
}

/// 单元测试：build_binary_tree 空列表错误。
#[test]
fn test_build_binary_tree_empty() {
    let result = build_binary_tree(vec![]);
    assert!(
        matches!(result, Err(TexasAirError::RecursionError(_))),
        "空列表应返回 RecursionError"
    );
}

/// 单元测试：ChildDescriptor 的字段构造正确性。
#[test]
fn test_child_descriptor_construction() {
    let c = make_child(42, MethodKind::Call, 100, 200);
    assert_eq!(c.call_seq, 42);
    assert_eq!(c.method_kind, MethodKind::Call);
    assert_eq!(c.pre_state_root, root_of(100));
    assert_eq!(c.post_state_root, root_of(200));
}

/// 单元测试：AggregatorAIR 列数常量正确。
#[test]
fn test_aggregator_air_num_columns() {
    use poker_texas_air::aggregator_air::{AggregatorAir, cols};
    // 23 列：2 通用 + 4*4 state_root + 2 call_seq + 2 method_kind + 1 is_top_level
    assert_eq!(cols::NUM_COLUMNS, 23);
    assert_eq!(AggregatorAir::num_columns(), 23);
}

/// 单元测试：u64_to_limbs 辅助函数正确。
#[test]
fn test_u64_to_limbs_helper() {
    use poker_texas_air::aggregator_air::u64_to_limbs;
    let limbs = u64_to_limbs(0xFFFF_FFFF_FFFF_FFFF);
    assert_eq!(limbs.len(), 4);
    // 每个 limb 应为 0xFFFF (16 bit)
    for l in &limbs {
        assert_eq!(*l, M31::from(0xFFFFu32));
    }
}

/// 单元测试：padding 行的 IS_PADDING=1 且其余为 0。
#[test]
fn test_aggregator_row_padding() {
    use poker_texas_air::aggregator_air::AggregatorRow;
    let pad = AggregatorRow::padding();
    let v = pad.to_vec();
    assert_eq!(v[0], ZERO); // IS_ACTIVE = 0
    assert_eq!(v[1], M31::from(1u32)); // IS_PADDING = 1
    // 其余列应为 0（含 IS_TOP_LEVEL）
    for &val in &v[2..] {
        assert_eq!(val, ZERO, "padding 行的非通用列应为 0");
    }
}

/// 单元测试：active 行的字段正确写入（is_top_level=true）。
#[test]
fn test_aggregator_row_active_top_level() {
    use poker_texas_air::aggregator_air::{AggregatorRow, cols};
    let left = make_child(0, MethodKind::CreateTable, 10, 20);
    let right = make_child(1, MethodKind::JoinTable, 20, 30);
    let row = AggregatorRow::active(&left, &right, true);
    let v = row.to_vec();

    assert_eq!(v[cols::IS_ACTIVE], M31::from(1u32));
    assert_eq!(v[cols::IS_PADDING], ZERO);
    assert_eq!(v[cols::IS_TOP_LEVEL], M31::from(1u32));
    assert_eq!(v[cols::LEFT_CALL_SEQ], M31::from(0u32));
    assert_eq!(v[cols::RIGHT_CALL_SEQ], M31::from(1u32));
    assert_eq!(
        v[cols::LEFT_METHOD_KIND],
        M31::from(MethodKind::CreateTable as u32)
    );
    assert_eq!(
        v[cols::RIGHT_METHOD_KIND],
        M31::from(MethodKind::JoinTable as u32)
    );
}

/// 单元测试：active 行的字段正确写入（is_top_level=false，底层行）。
#[test]
fn test_aggregator_row_active_non_top_level() {
    use poker_texas_air::aggregator_air::{AggregatorRow, cols};
    let left = make_child(0, MethodKind::CreateTable, 10, 20);
    let right = make_child(1, MethodKind::JoinTable, 20, 30);
    let row = AggregatorRow::active(&left, &right, false);
    let v = row.to_vec();

    assert_eq!(v[cols::IS_ACTIVE], M31::from(1u32));
    assert_eq!(v[cols::IS_PADDING], ZERO);
    assert_eq!(v[cols::IS_TOP_LEVEL], ZERO); // 底层行 is_top_level = 0
}
