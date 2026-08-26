//! # poker_texas_air — Texas Poker method AIR + host verification
//!
//! VM 与 AIR 当前统一保留 19 个 active MethodKind；退休 discriminant 5/10/15/16 均 fail-closed。批量
//! Aggregator 仍是 descriptor-only PoC，不能作为递归压缩证明使用。
//!
//! ## 架构分层
//!
//! - **Layer 0**: Method AIRs（19 个 active stable discriminant）
//! - **Layer 1**: Host verification receipts（legacy replay-backed）与
//!   `texas_tagged` direct state-transition AIR（mid-round, fail-closed）
//! - **Layer 2**: Host-verified outer precompile（O(N) child replay + final digest AIR）
//! - **Layer 3**: Texas 自有递归协议（尚未实现，生产验证入口保持关闭）
//!
//! ## 设计文档
//!
//! 详见 `.trae/documents/poker_texas_air_custom_circuit_plan.md`。
//!
//! ## 复用率 ~85%
//!
//! - state root 在可信 host 端从 canonical Borsh preimage 重算，并与完整公开输入一起
//!   混入 Fiat–Shamir；当前 method AIR 内没有嵌入 Poseidon verifier 组件
//! - 直接复用 `poker_l1::vm::contracts::texas_poker::types::TexasPokerTable`（业务类型）

#![cfg_attr(texas_release_tests, allow(unexpected_cfgs))]
#![deny(unsafe_code)]
#![deny(missing_docs)]

// Integration tests use this feature to exercise deliberately untrusted PoC
// entry points. Refuse release artifacts that accidentally enable it through
// `--all-features`; checked production APIs remain available without it.
// `cfg(test)` exempts the release *test harness* (`cargo test --release --lib`),
// and the custom `texas_release_tests` cfg — set explicitly via
// `RUSTFLAGS='--cfg=texas_release_tests'` — exempts deliberate release
// integration-test runs. Both are test artifacts, not shippable builds.
#[cfg(all(feature = "test-helpers", not(debug_assertions), not(test)))]
#[cfg(not(texas_release_tests))]
compile_error!("poker_texas_air/test-helpers must not be enabled in release builds");

// ===== Layer 0: Method AIRs =====
pub mod airs;
pub mod trace_gen;

// ===== 公共基础设施 =====
pub mod deck_commitment;
pub mod dual_proof;
pub mod error;
pub mod merkle_tree;
pub mod method_kind;
pub mod outer_aggregate;
pub mod outer_precompile;
pub mod precompile_binding;
pub mod proof_archive;
pub mod prove_timing;
mod prover_context;
pub mod public_inputs;
pub mod settlement_binding;
/// Strict Cairo ABI calldata builder for the verified outer aggregate
/// settlement path on Starknet Sepolia.
pub mod starknet_settlement;
pub mod state_root;
/// Flock-proven state-root binding replacing host hash recomputation.
pub mod state_root_binding;
pub mod tagged_method;
/// Fixed-width canonical state and selector ABI for the complete Texas VM surface.
pub mod texas_canonical;
/// Direct AIR and archive format for complete canonical Texas transitions.
pub mod texas_canonical_air;
/// Finalized state-kernel receipt binding for direct Texas proofs.
pub mod texas_receipt;
/// No-replay canonical heterogeneous Texas transition proving path.
pub mod texas_tagged;
pub mod verified_chain;

// ===== Post-commit Prover =====
// 证明任务（数据契约）+ Orchestrator（异步消费任务生成/聚合 proof）。
// 详见 orchestrator.rs 的架构说明。
pub mod orchestrator;
pub mod prove_task;

// ===== Layer 2: Aggregator AIR =====
// 阶段 4 PoC：Aggregator AIR 不再 feature-gated。
// descriptor-only prove/verify 生产入口默认拒绝，只保留显式测试入口。
pub mod aggregator_air;
pub mod aggregator_prover;
pub mod aggregator_verifier;
pub mod authorization_binding;
/// Lookup-backed Blake2b compression scheduler and fixed-value SMT path proof.
pub mod blake2b_lookup_compression;
/// Lookup-backed Blake2b G component for the host-zero compression path.
pub mod blake2b_lookup_g;
/// Stwo 2.3 LogUp byte-XOR foundation for the lookup-optimized Blake2b port.
pub mod blake2b_lookup_xor;
/// Sequential in-AIR Blake2b-256 compression for the fixed SMT ABI.
pub mod blake2b_smt_air;
/// Fixed-width Blake2b SMT compression witness ABI for the host-zero route.
pub mod blake2b_smt_witness;
/// Binary-field BLAKE3 (flock) hash-proving backend.
pub mod blake3_flock;
/// Blake2b authentication of the canonical table-rules preimage and the
/// fixed-width rake opening consumed by raked settlement terminals.
pub mod canonical_rake_opening;
/// No-replay scope binding for canonical Reconstruction V3 AIR requests.
pub mod canonical_reconstruction_binding;
pub mod canonical_reveal_opening;
/// Fixed-width, lookup-authenticated reveal-assignment ledger opening.
pub mod canonical_settlement_air;
pub mod canonical_settlement_air_plan;
/// Lookup-backed authentication of canonical state-image byte preimages.
pub mod canonical_state_hash;
/// Public-proof composition that binds canonical Texas transitions to L1
/// fixed-width Blake2b state-object openings.
pub mod canonical_state_opening;
/// Backend-agnostic Blake2b statement proving seam shared by the M31 lookup
/// stack and the binary-field flock backend.
pub mod hash_prover;
/// Bounded, non-terminal reveal-timeout kick cascade scope.
pub mod reveal_timeout_cascade;
#[cfg(test)]
mod ristretto_degree_util;
/// Composed host-zero extended-Edwards point-addition proofs.
pub mod ristretto_edwards_add_air;
/// Canonical Ristretto255 modular-addition AIR.
pub mod ristretto_fp_add_air;
/// Canonical Ristretto255 field-element limb AIR.
pub mod ristretto_fp_air;
/// Composed Ristretto255 multiplicative-inverse proofs.
pub mod ristretto_fp_inv_air;
/// Canonical Ristretto255 modular-multiplication AIR.
pub mod ristretto_fp_mul_air;
/// Single-STARK canonical Ristretto255 field-program AIR.
pub mod ristretto_fp_program_air;
/// Composed Ristretto255 `sqrt_ratio_i` proofs.
pub mod ristretto_fp_sqrt_ratio_air;
/// Composed Ristretto255 modular-subtraction proofs.
pub mod ristretto_fp_sub_air;
/// Variable-base Ristretto255 multi-scalar multiplication over batched STARKs.
pub mod ristretto_msm_air;
/// RistrettoAirV2 player sigma proofs: ownership, reveal tokens, deck
/// remasking, and fold/leave transitions.
pub mod ristretto_player_proofs_air;
/// Composed host-zero Ristretto255 point-decode proofs.
pub mod ristretto_point_decode_air;
/// Composed host-zero Ristretto255 point-encode proofs.
pub mod ristretto_point_encode_air;
/// Folded Ristretto group-addition binding for reconstruction accumulators.
pub mod ristretto_reconstruction_accumulator_air;
/// Partial request-scoped composition of implemented Reconstruction V3 relations.
pub mod ristretto_reconstruction_composition;
/// Versioned public wire envelope for Ristretto Reconstruction V3 proofs.
pub mod ristretto_reconstruction_proof_wire;
/// Ristretto Reconstruction V3 cross-key equation composition.
pub mod ristretto_reconstruction_relation_air;
/// Ristretto Reconstruction V3 slot-membership OR composition.
pub mod ristretto_reconstruction_slot_or_air;
/// Canonical Poseidon252 transcript absorption schedule for Reconstruction V3.
pub mod ristretto_reconstruction_transcript;
/// RistrettoAirV2 native reconstruction: complete low-latency relation set.
pub mod ristretto_reconstruction_v2_air;
/// Canonical Ristretto255 scalar addition modulo the group order.
pub mod ristretto_scalar_add_air;
/// Canonical Ristretto255 group-scalar limb AIR.
pub mod ristretto_scalar_air;
/// Canonical Ristretto255 scalar 4-bit window AIR.
pub mod ristretto_scalar_windows_air;
/// RistrettoAirV2 complete 52-card shuffle: Bayer--Groth argument with a
/// Flock-BLAKE3 Fiat--Shamir transcript.
pub mod ristretto_shuffle_air;
/// Statement-level projection of L1 sparse-Merkle openings onto the shared
/// hash-prover seam.
pub mod smt_statements;

/// Canonical tagged-seat fixture operations, available only to tests and debug test helpers.
#[cfg(any(test, feature = "test-helpers"))]
pub mod test_support;

// P05-H-source：从已认证共识材料构造 ExpectedChainAnchor。
pub mod consensus_anchor;

// ===== Prover / Verifier 入口 =====
pub mod prover;
pub mod verifier;
