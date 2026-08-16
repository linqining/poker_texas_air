//! Aggregator Prover — 生成二叉树聚合的 Stwo proof。
//!
//! ## 流程
//!
//! 1. 调用 [`crate::aggregator_air::build_binary_tree`] 构造二叉树聚合层级
//! 2. 把每层的聚合行（[`crate::aggregator_air::AggregatorRow`]）写入 trace
//! 3. 调用 Stwo prover 生成 proof
//! 4. 返回 `AggregatorProof`（含 stark_proof + AggregatorAir 公开输入）
//!
//! ## 简化策略
//!
//! 阶段 4 PoC：把所有聚合层展平为单 trace（一行 = 一个聚合节点），且不验证
//! 任何子 proof。生产入口默认拒绝；显式测试入口仅用于机制测试。

use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::poseidon252_merkle::Poseidon252MerkleHasher;

#[cfg(any(test, feature = "test-helpers"))]
use stwo::core::channel::Poseidon252Channel;
#[cfg(any(test, feature = "test-helpers"))]
use stwo::core::vcs_lifted::poseidon252_merkle::Poseidon252MerkleChannel;
#[cfg(any(test, feature = "test-helpers"))]
use stwo::prover::backend::simd::SimdBackend;
#[cfg(any(test, feature = "test-helpers"))]
use stwo::prover::pcs::CommitmentSchemeProver;
#[cfg(any(test, feature = "test-helpers"))]
use stwo::prover::{ProvingError, prove};
#[cfg(any(test, feature = "test-helpers"))]
use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};

use crate::aggregator_air::{AggregatorAir, ChildDescriptor};
#[cfg(any(test, feature = "test-helpers"))]
use crate::aggregator_air::{AggregatorRow, build_binary_tree, cols, mix_children_into_channel};
use crate::error::{TexasAirError, TexasAirResult};
#[cfg(any(test, feature = "test-helpers"))]
use crate::trace_gen::MethodTrace;

/// Aggregator proof（含 StarkProof + AIR 公开输入）。
#[derive(Debug, Clone)]
pub struct AggregatorProof {
    /// Stwo 内部 proof。
    pub stark_proof: StarkProof<Poseidon252MerkleHasher>,
    /// AIR 公开输入。
    pub air: AggregatorAir,
    /// trace log_size。
    pub log_size: u32,
    /// 聚合的子节点数。
    pub num_children: usize,
    /// 聚合层级数。
    pub num_levels: usize,
    /// 聚合的子节点描述符（state_root 链式绑定用；阶段 2 soundness 修复）。
    /// verifier 用相同的 children 重新 mix 进 channel，确保聚合 proof 绑定到声明的链。
    pub children: Vec<crate::aggregator_air::ChildDescriptor>,
}

/// Produce a succinct recursive aggregation proof.
///
/// This entry is intentionally unavailable until the Texas-owned verifier AIR
/// validates every child proof and binds their statements.  A descriptor chain
/// alone cannot establish child-proof validity.
///
/// # Errors
///
/// Always returns [`TexasAirError::UntrustedAggregationDisabled`].
pub fn prove_aggregator(_children: Vec<ChildDescriptor>) -> TexasAirResult<AggregatorProof> {
    Err(TexasAirError::UntrustedAggregationDisabled)
}

/// Host-attested 聚合证明（非 recursive）。
///
/// 调用方须显式提供 [`HostAttestation`]，声明所有子 proof 已在宿主上通过
/// `verify_method_against` 原生验证（O(N) host-verify）。此函数在此基础上生成
/// descriptor chain 的单一 STARK 证明（聚合 state_root 连续性约束），使验证方
/// 只需验证一个 proof 而非逐个子 proof。
///
/// **信任边界**：此 proof 证明 descriptor chain 的连续性（Fiat-Shamir 绑定），
/// 但**不证明**子 proof 的密码学有效性——后者由 host-verify 回执保证。
/// 这不是 succinct recursive proof；完整闭环需要 Texas 自有递归 verifier AIR。
///
/// # 参数
/// - `children`：子节点描述符链（须有连续的 state_root / call_seq）
/// - `attestation`：宿主证明（声明 N 个子 proof 已验证通过）
///
/// # Errors
/// - `TexasAirError::RecursionError` — 链式连续性破坏
/// - `TexasAirError::StwoProverError` — Stwo prover 内部错误
pub fn prove_aggregator_host_attested(
    _children: Vec<ChildDescriptor>,
    _attestation: &HostAttestation,
) -> TexasAirResult<AggregatorProof> {
    // `HostAttestation` is caller-constructible data, not an unforgeable verifier
    // receipt. A count/endpoints check cannot turn descriptor-only aggregation
    // into proof of child validity. The safe O(N) transition path is
    // `outer_aggregate`, which actually re-verifies every child package.
    Err(TexasAirError::UntrustedAggregationDisabled)
}

/// Legacy host-attestation descriptor retained for source compatibility.
///
/// This structure is ordinary caller-constructible data and therefore cannot
/// authorize aggregation. [`prove_aggregator_host_attested`] always fails
/// closed. Use [`crate::outer_aggregate`] for the explicit O(N) host-verified
/// path while the Texas-owned recursive verifier is unfinished.
#[derive(Debug, Clone)]
pub struct HostAttestation {
    /// 已验证的子 proof 数量。
    pub verified_count: usize,
    /// 宿主验证的起始 state_root（链锚点）。
    pub anchor_state_root: crate::state_root::StateRoot,
    /// 宿主验证的结束 state_root（链尾）。
    pub final_state_root: crate::state_root::StateRoot,
}

/// 运行不验证子 proof 的 Aggregator PoC，仅供测试与审计复现。
///
/// 调用者必须明确接受：返回的 STARK 只证明 descriptor trace 的局部约束，不能证明
/// descriptor 来自任何有效 method proof，也不是递归压缩证明。
///
/// # Errors
///
/// - `TexasAirError::RecursionError` — 子节点链式连续性破坏 / call_seq 不连续
/// - `TexasAirError::StwoProverError` — Stwo prover 内部错误（约束不满足）
#[cfg(any(test, feature = "test-helpers"))]
pub fn prove_aggregator_unchecked_for_tests(
    children: Vec<ChildDescriptor>,
) -> TexasAirResult<AggregatorProof> {
    prove_aggregator_unchecked(children)
}

#[cfg(any(test, feature = "test-helpers"))]
fn prove_aggregator_unchecked(children: Vec<ChildDescriptor>) -> TexasAirResult<AggregatorProof> {
    // 1. 构造二叉树聚合
    let num_children = children.len();
    let children_for_mix = children.clone();
    let (root, levels) = build_binary_tree(children)?;

    if levels.is_empty() {
        return Err(TexasAirError::RecursionError(
            "prove_aggregator: 单子节点无需聚合（levels 为空）".into(),
        ));
    }

    // 2. 把所有聚合行展平到单 trace
    let mut all_rows: Vec<AggregatorRow> = Vec::new();
    for level in &levels {
        all_rows.extend(level.iter().cloned());
    }

    // 3. 选择 log_size（≥10，Stwo SIMD 对齐）
    let num_rows = all_rows.len();
    let mut log_size: u32 = 10; // 最小 1024
    while (1usize << log_size) < num_rows {
        log_size += 1;
    }

    // 4. 构造 trace
    let mut trace = MethodTrace::new(log_size, cols::NUM_COLUMNS);
    for (i, row) in all_rows.iter().enumerate() {
        trace.write_row(i, &row.to_vec())?;
    }
    // padding 行（剩余）
    let padding_row = AggregatorRow::padding();
    for i in num_rows..(1usize << log_size) {
        trace.write_row(i, &padding_row.to_vec())?;
    }

    // 5. 构造 AIR 公开输入
    //    注意：阶段 4 PoC 只用顶层（root）的 left/right 描述符作为 AIR 公开输入
    //    完整版应每层一个 AIR 实例，递归聚合
    let top_level = levels.last().expect("levels 非空");
    let top_row = top_level
        .first()
        .ok_or_else(|| TexasAirError::RecursionError("顶层无聚合行".into()))?;

    // 从顶层行还原 left/right ChildDescriptor（用于 AIR 公开输入）
    let left_desc = ChildDescriptor {
        pre_state_root: top_row.left_pre_state_root,
        post_state_root: top_row.left_post_state_root,
        call_seq: top_row.left_call_seq.0,
        method_kind: crate::method_kind::MethodKind::from_u8(top_row.left_method_kind.0 as u8)
            .unwrap_or(crate::method_kind::MethodKind::CreateTable),
    };
    let right_desc = ChildDescriptor {
        pre_state_root: top_row.right_pre_state_root,
        post_state_root: top_row.right_post_state_root,
        call_seq: top_row.right_call_seq.0,
        method_kind: crate::method_kind::MethodKind::from_u8(top_row.right_method_kind.0 as u8)
            .unwrap_or(crate::method_kind::MethodKind::CreateTable),
    };

    let air = AggregatorAir {
        log_size,
        left: left_desc,
        right: right_desc,
        agg_pre_state_root: root.pre_state_root,
        agg_post_state_root: root.post_state_root,
    };

    // 6. PCS 配置 + twiddles
    let config = crate::prover_context::protocol_pcs_config();
    let blowup_log = config.fri_config.log_blowup_factor;
    let twiddles = crate::prover_context::simd_twiddles(log_size + blowup_log);

    // 7. Channel + CommitmentSchemeProver
    let mut channel = Poseidon252Channel::default();
    // soundness 关键：把所有子节点描述符（state_root 链）mix 进 channel，
    // 使聚合 proof 绑定到声明的链（否则 AIR struct 的 left/right 可被替换）。
    mix_children_into_channel(&mut channel, &children_for_mix);
    let mut commitment_scheme =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::with_memory_pool(
            config,
            &twiddles,
            crate::prover_context::simd_base_column_pool(),
        );

    // 8. 提交空 preprocessed trace（tree 0）
    {
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(vec![]);
        tree_builder.commit(&mut channel);
    }

    // 9. 提交 original trace（tree 1）
    {
        let columns = trace.to_evaluations();
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(columns);
        tree_builder.commit(&mut channel);
    }

    // 10. 构建 AIR component
    let mut allocator = TraceLocationAllocator::default();
    let component = FrameworkComponent::new(
        &mut allocator,
        air.clone(),
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    // 11. 生成 proof
    let stark_proof = prove(&[&component], &mut channel, commitment_scheme)
        .map_err(|e: ProvingError| TexasAirError::StwoProverError(e.to_string()))?;

    Ok(AggregatorProof {
        stark_proof,
        air,
        log_size,
        num_children,
        num_levels: levels.len(),
        children: children_for_mix,
    })
}
