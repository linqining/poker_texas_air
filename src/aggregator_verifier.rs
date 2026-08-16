//! Aggregator Verifier — descriptor-only Aggregator PoC 的保护性入口。
//!
//! ## 流程
//!
//! 1. 从 `AggregatorProof` 读取 AIR 公开输入 + StarkProof
//! 2. 构造 Channel + CommitmentSchemeVerifier
//! 3. 从 proof 读取 preprocessed + trace commitments
//! 4. 构建 AIR component（与 prover 端使用相同 AIR 实例）
//! 5. 调用 `stwo::core::verifier::verify` 验证 proof
//!
//! ## 简化策略
//!
//! 当前实现不验证子 proof；生产入口默认拒绝，显式测试入口只检查 PoC STARK。

#[cfg(any(test, feature = "test-helpers"))]
use stwo::core::channel::Poseidon252Channel;
#[cfg(any(test, feature = "test-helpers"))]
use stwo::core::pcs::CommitmentSchemeVerifier;
#[cfg(any(test, feature = "test-helpers"))]
use stwo::core::vcs_lifted::poseidon252_merkle::Poseidon252MerkleChannel;
#[cfg(any(test, feature = "test-helpers"))]
use stwo::core::verifier::{VerificationError, verify};
#[cfg(any(test, feature = "test-helpers"))]
use stwo_constraint_framework::{FrameworkComponent, TraceLocationAllocator};

#[cfg(any(test, feature = "test-helpers"))]
use crate::aggregator_air::cols;
use crate::aggregator_prover::AggregatorProof;
use crate::error::{TexasAirError, TexasAirResult};

/// 拒绝 descriptor-only Aggregator proof 的生产验证。
///
/// # 参数
/// - `proof`: 由 [`crate::aggregator_prover::prove_aggregator`] 生成的 proof
///
/// # 返回
/// 当前 Aggregator AIR 没有验证子 proof，因此即使内部 STARK 有效，也不能把它解释为
/// 一条已验证的 method-proof 链。该入口在可信递归 verifier 接入前始终 fail closed。
///
/// # Errors
///
/// 始终返回 [`TexasAirError::UntrustedAggregationDisabled`]。
pub fn verify_aggregator(_proof: AggregatorProof) -> TexasAirResult<()> {
    Err(TexasAirError::UntrustedAggregationDisabled)
}

/// 验证 host-attested 聚合证明（非 recursive）。
///
/// 验证 STARK 内部约束 + descriptor chain 连续性（Fiat-Shamir 绑定）。
/// 成功只证明 descriptor chain 的 state_root 连续性满足 AIR 约束，
/// **不证明**子 proof 的密码学有效性——后者由 host-verify 回执保证。
///
/// **信任边界**：验证方须信任 orchestrator 的 host-verify 回执（O(N) 原生验证）。
/// 这不是 succinct recursive proof。
///
/// # Errors
/// - `TexasAirError::ConstraintUnsatisfied` — AIR 约束不满足
/// - `TexasAirError::StwoProverError` — Stwo verifier 内部错误
pub fn verify_aggregator_host_attested(proof: AggregatorProof) -> TexasAirResult<()> {
    let _ = proof;
    Err(TexasAirError::UntrustedAggregationDisabled)
}

/// 验证 descriptor-only Aggregator PoC，仅供测试与审计复现。
///
/// 成功只说明摘要 trace 满足当前 Aggregator AIR，不说明任何子 proof 有效。
///
/// # Errors
///
/// - `TexasAirError::ConstraintUnsatisfied` — AIR 约束不满足
/// - `TexasAirError::StwoProverError` — Stwo verifier 内部错误
#[cfg(any(test, feature = "test-helpers"))]
pub fn verify_aggregator_unchecked_for_tests(proof: AggregatorProof) -> TexasAirResult<()> {
    verify_aggregator_unchecked(proof)
}

#[cfg(any(test, feature = "test-helpers"))]
fn verify_aggregator_unchecked(proof: AggregatorProof) -> TexasAirResult<()> {
    validate_proof_metadata(&proof)?;
    let config = crate::prover_context::protocol_pcs_config();
    let log_size = proof.log_size;
    let stark_proof = proof.stark_proof.clone();

    // 1. Channel + CommitmentSchemeVerifier
    let mut channel = Poseidon252Channel::default();
    // soundness 关键：与 prover 对称地 mix 子节点描述符（state_root 链）。
    crate::aggregator_air::mix_children_into_channel(&mut channel, &proof.children);
    let mut commitment_scheme = CommitmentSchemeVerifier::<Poseidon252MerkleChannel>::new(config);

    // 2. 从 proof 读取 preprocessed commitment（tree 0）
    let preprocessed_commitment = *stark_proof.commitments.get(0).ok_or_else(|| {
        TexasAirError::StwoProverError(format!(
            "proof.commitments 长度不足：期望 ≥1，实际 {}",
            stark_proof.commitments.len()
        ))
    })?;
    commitment_scheme.commit(preprocessed_commitment, &[], &mut channel);

    // 3. 从 proof 读取 trace commitment（tree 1，cols::NUM_COLUMNS 列）
    let trace_commitment = *stark_proof.commitments.get(1).ok_or_else(|| {
        TexasAirError::StwoProverError(format!(
            "proof.commitments 长度不足：期望 ≥2，实际 {}",
            stark_proof.commitments.len()
        ))
    })?;
    let trace_log_sizes = vec![log_size; cols::NUM_COLUMNS];
    commitment_scheme.commit(trace_commitment, &trace_log_sizes, &mut channel);

    // 4. 构建 AIR component（与 prover 端使用相同的 AIR 实例）
    let air = proof.air.clone();
    let mut allocator = TraceLocationAllocator::default();
    let component = FrameworkComponent::new(
        &mut allocator,
        air,
        stwo::core::fields::qm31::SecureField::from(0u32),
    );

    // 5. 验证（verify 内部处理 composition poly commitment = proof.commitments.last()）
    verify(
        &[&component],
        &mut channel,
        &mut commitment_scheme,
        stark_proof,
    )
    .map_err(|e: VerificationError| TexasAirError::ConstraintUnsatisfied(e.to_string()))?;

    Ok(())
}

/// Reconstruct every verifier-controlled Aggregator statement field from the
/// transcript-bound leaf descriptors. Proof-carried AIR metadata is never an
/// independent source of truth.
#[cfg(any(test, feature = "test-helpers"))]
fn validate_proof_metadata(proof: &AggregatorProof) -> TexasAirResult<()> {
    if proof.num_children != proof.children.len() {
        return Err(TexasAirError::RecursionError(format!(
            "aggregator num_children {} != descriptor count {}",
            proof.num_children,
            proof.children.len()
        )));
    }

    let (root, levels) = crate::aggregator_air::build_binary_tree(proof.children.clone())?;
    if levels.is_empty() {
        return Err(TexasAirError::RecursionError(
            "aggregator proof must contain at least two children".into(),
        ));
    }
    if proof.num_levels != levels.len() {
        return Err(TexasAirError::RecursionError(format!(
            "aggregator num_levels {} != reconstructed level count {}",
            proof.num_levels,
            levels.len()
        )));
    }

    let row_count: usize = levels.iter().map(Vec::len).sum();
    let mut expected_log_size = 10u32;
    while (1usize << expected_log_size) < row_count {
        expected_log_size += 1;
    }
    if proof.log_size != expected_log_size || proof.air.log_size != expected_log_size {
        return Err(TexasAirError::RecursionError(format!(
            "aggregator log_size mismatch: proof={}, air={}, expected={expected_log_size}",
            proof.log_size, proof.air.log_size
        )));
    }

    let top_row = levels
        .last()
        .and_then(|level| level.first())
        .ok_or_else(|| TexasAirError::RecursionError("aggregator top row missing".into()))?;
    let left_kind = crate::method_kind::MethodKind::from_u8(
        u8::try_from(top_row.left_method_kind.0).map_err(|_| {
            TexasAirError::RecursionError("aggregator left method kind exceeds u8".into())
        })?,
    )
    .ok_or_else(|| TexasAirError::RecursionError("aggregator left method kind invalid".into()))?;
    let right_kind = crate::method_kind::MethodKind::from_u8(
        u8::try_from(top_row.right_method_kind.0).map_err(|_| {
            TexasAirError::RecursionError("aggregator right method kind exceeds u8".into())
        })?,
    )
    .ok_or_else(|| TexasAirError::RecursionError("aggregator right method kind invalid".into()))?;
    let expected_air = crate::aggregator_air::AggregatorAir {
        log_size: expected_log_size,
        left: crate::aggregator_air::ChildDescriptor {
            pre_state_root: top_row.left_pre_state_root,
            post_state_root: top_row.left_post_state_root,
            call_seq: top_row.left_call_seq.0,
            method_kind: left_kind,
        },
        right: crate::aggregator_air::ChildDescriptor {
            pre_state_root: top_row.right_pre_state_root,
            post_state_root: top_row.right_post_state_root,
            call_seq: top_row.right_call_seq.0,
            method_kind: right_kind,
        },
        agg_pre_state_root: root.pre_state_root,
        agg_post_state_root: root.post_state_root,
    };
    if proof.air != expected_air {
        return Err(TexasAirError::RecursionError(
            "aggregator AIR metadata does not match transcript-bound descriptors".into(),
        ));
    }
    Ok(())
}
