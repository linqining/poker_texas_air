//! Canonical Ristretto255 scalar 4-bit window AIR.
//!
//! This is the input ABI for fixed-window scalar multiplication and MSM.  It
//! proves that 64 committed windows are exactly the little-endian 4-bit
//! decomposition of a canonical public scalar.

use bincode::Options;
use borsh::{BorshDeserialize, BorshSerialize};
use stwo::core::channel::Channel;
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::SecureField;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::poseidon252_merkle::Poseidon252MerkleChannel;
use stwo::core::vcs_lifted::poseidon252_merkle::Poseidon252MerkleHasher;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::pcs::CommitmentSchemeProver;
use stwo::prover::prove;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
};

use crate::error::{TexasAirError, TexasAirResult};
use crate::ristretto_scalar_air::{
    ArchivedRistrettoScalarCanonicalProof, prove_ristretto_scalar_canonical,
    verify_ristretto_scalar_canonical,
};
use crate::trace_gen::MethodTrace;

const LIMBS: usize = 32;
const WINDOWS: usize = 64;
const LOG_SIZE: u32 = 1;
const LIMB_OFFSET: usize = 0;
const LIMB_BITS_OFFSET: usize = LIMB_OFFSET + LIMBS;
const WINDOW_OFFSET: usize = LIMB_BITS_OFFSET + LIMBS * 8;
const WINDOW_BITS_OFFSET: usize = WINDOW_OFFSET + WINDOWS;
const NUM_COLUMNS: usize = WINDOW_BITS_OFFSET + WINDOWS * 4;
const PREPROCESSED_COLUMNS: usize = LIMBS;

/// Public scalar and its verified 4-bit windows.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoScalarWindowsProof {
    /// Canonical little-endian scalar bytes.
    pub scalar: [u8; LIMBS],
    /// Sixty-four little-endian 4-bit windows.
    pub windows: [u8; WINDOWS],
    /// Independent strict `scalar < l` proof.
    pub canonical: ArchivedRistrettoScalarCanonicalProof,
    /// Proof that the windows reconstruct the scalar.
    pub stark_proof_bytes: Vec<u8>,
}

fn options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(16 * 1024 * 1024)
}

fn windows(scalar: &[u8; LIMBS]) -> [u8; WINDOWS] {
    let mut out = [0u8; WINDOWS];
    for (limb_index, limb) in scalar.iter().enumerate() {
        out[limb_index * 2] = limb & 0x0f;
        out[limb_index * 2 + 1] = limb >> 4;
    }
    out
}

fn trace_columns(scalar: &[u8; LIMBS]) -> MethodTrace {
    let scalar_windows = windows(scalar);
    let mut row = Vec::with_capacity(NUM_COLUMNS);
    row.extend(scalar.iter().map(|limb| M31::from(u32::from(*limb))));
    for limb in scalar {
        for bit in 0..8 {
            row.push(M31::from(u32::from((limb >> bit) & 1)));
        }
    }
    row.extend(
        scalar_windows
            .iter()
            .map(|window| M31::from(u32::from(*window))),
    );
    for window in scalar_windows {
        for bit in 0..4 {
            row.push(M31::from(u32::from((window >> bit) & 1)));
        }
    }

    let mut trace = MethodTrace::new(LOG_SIZE, NUM_COLUMNS);
    trace.write_row(0, &row).expect("fixed scalar-window width");
    trace.write_row(1, &row).expect("fixed scalar-window width");
    trace
}

fn scope_columns(scalar: &[u8; LIMBS]) -> MethodTrace {
    let mut trace = MethodTrace::new(LOG_SIZE, PREPROCESSED_COLUMNS);
    let row = scalar
        .iter()
        .map(|limb| M31::from(u32::from(*limb)))
        .collect::<Vec<_>>();
    trace.write_row(0, &row).expect("fixed scalar scope width");
    trace.write_row(1, &row).expect("fixed scalar scope width");
    trace
}

fn preprocessed_ids() -> Vec<PreProcessedColumnId> {
    (0..LIMBS)
        .map(|limb| PreProcessedColumnId {
            id: format!("ristretto.scalar.windows.v1.{limb}").into(),
        })
        .collect()
}

#[derive(Clone, Copy)]
struct ScalarWindowsAir {
    log_size: u32,
}

impl FrameworkEval for ScalarWindowsAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let one: E::F = M31::from(1u32).into();
        let ids = preprocessed_ids();

        let mut limbs = Vec::with_capacity(LIMBS);
        for _ in 0..LIMBS {
            limbs.push(eval.next_trace_mask());
        }
        let mut limb_bits = Vec::with_capacity(LIMBS * 8);
        for _ in 0..LIMBS * 8 {
            let bit = eval.next_trace_mask();
            eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
            limb_bits.push(bit);
        }
        let mut committed_windows = Vec::with_capacity(WINDOWS);
        for _ in 0..WINDOWS {
            committed_windows.push(eval.next_trace_mask());
        }
        let mut window_bits = Vec::with_capacity(WINDOWS * 4);
        for _ in 0..WINDOWS * 4 {
            let bit = eval.next_trace_mask();
            eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
            window_bits.push(bit);
        }

        for limb_index in 0..LIMBS {
            let mut reconstructed: E::F = M31::from(0u32).into();
            for bit_index in 0..8 {
                let global_bit = limb_index * 8 + bit_index;
                reconstructed +=
                    limb_bits[global_bit].clone() * E::F::from(M31::from(1u32 << bit_index));
            }
            eval.add_constraint(limbs[limb_index].clone() - reconstructed);
        }

        for window_index in 0..WINDOWS {
            let mut reconstructed_window: E::F = M31::from(0u32).into();
            let mut reconstructed_scalar_bits: E::F = M31::from(0u32).into();
            for bit_index in 0..4 {
                let window_bit = window_index * 4 + bit_index;
                reconstructed_window +=
                    window_bits[window_bit].clone() * E::F::from(M31::from(1u32 << bit_index));
                reconstructed_scalar_bits +=
                    limb_bits[window_bit].clone() * E::F::from(M31::from(1u32 << bit_index));
            }
            eval.add_constraint(committed_windows[window_index].clone() - reconstructed_window);
            eval.add_constraint(
                committed_windows[window_index].clone() - reconstructed_scalar_bits,
            );
        }

        for (limb_index, limb) in limbs.into_iter().enumerate() {
            let scope = eval.get_preprocessed_column(ids[limb_index].clone());
            eval.add_constraint(limb - scope);
        }
        eval
    }
}

fn mix_scope(channel: &mut impl Channel, scalar: &[u8; LIMBS], windows: &[u8; WINDOWS]) {
    channel.mix_u32s(
        &scalar
            .iter()
            .map(|limb| u32::from(*limb))
            .collect::<Vec<_>>(),
    );
    channel.mix_u32s(
        &windows
            .iter()
            .map(|window| u32::from(*window))
            .collect::<Vec<_>>(),
    );
}

/// Prove the canonical scalar and its exact 4-bit window decomposition.
pub fn prove_ristretto_scalar_windows(
    scalar: &[u8; LIMBS],
) -> TexasAirResult<ArchivedRistrettoScalarWindowsProof> {
    let canonical = prove_ristretto_scalar_canonical(scalar)?;
    let scalar_windows = windows(scalar);
    let trace = trace_columns(scalar);
    let scope = scope_columns(scalar);
    let config = crate::prover_context::protocol_pcs_config();
    let twiddles =
        crate::prover_context::simd_twiddles(LOG_SIZE + config.fri_config.log_blowup_factor);
    let mut channel = stwo::core::channel::Poseidon252Channel::default();
    mix_scope(&mut channel, scalar, &scalar_windows);
    let mut scheme =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::with_memory_pool(
            config,
            &twiddles,
            crate::prover_context::simd_base_column_pool(),
        );
    {
        let mut tree = scheme.tree_builder();
        tree.extend_evals(scope.to_evaluations());
        tree.commit(&mut channel);
    }
    {
        let mut tree = scheme.tree_builder();
        tree.extend_evals(trace.to_evaluations());
        tree.commit(&mut channel);
    }
    let ids = preprocessed_ids();
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
    let component = FrameworkComponent::new(
        &mut allocator,
        ScalarWindowsAir { log_size: LOG_SIZE },
        SecureField::from(0u32),
    );
    let proof = prove(&[&component], &mut channel, scheme)
        .map_err(|error| TexasAirError::StwoProverError(error.to_string()))?;
    let stark_proof_bytes = options()
        .serialize(&proof)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
    Ok(ArchivedRistrettoScalarWindowsProof {
        scalar: *scalar,
        windows: scalar_windows,
        canonical,
        stark_proof_bytes,
    })
}

/// Verify the scalar/window decomposition without trusting a host decomposition.
pub fn verify_ristretto_scalar_windows(
    archive: &ArchivedRistrettoScalarWindowsProof,
) -> TexasAirResult<()> {
    verify_ristretto_scalar_canonical(&archive.canonical)?;
    if archive.canonical.value != archive.scalar {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Ristretto scalar-window canonical proof is detached".into(),
        ));
    }
    type Proof = StarkProof<Poseidon252MerkleHasher>;
    let proof: Proof = options()
        .deserialize(&archive.stark_proof_bytes)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
    let trace = trace_columns(&archive.scalar);
    let scope = scope_columns(&archive.scalar);
    let config = crate::prover_context::protocol_pcs_config();
    let twiddles =
        crate::prover_context::simd_twiddles(LOG_SIZE + config.fri_config.log_blowup_factor);
    let mut trusted =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::with_memory_pool(
            config,
            &twiddles,
            crate::prover_context::simd_base_column_pool(),
        );
    let mut scope_channel = stwo::core::channel::Poseidon252Channel::default();
    {
        let mut tree = trusted.tree_builder();
        tree.extend_evals(scope.to_evaluations());
        tree.commit(&mut scope_channel);
    }
    if proof.commitments.first().copied() != trusted.roots().first().copied() {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Ristretto scalar-window scope commitment mismatch".into(),
        ));
    }
    let mut trace_channel = stwo::core::channel::Poseidon252Channel::default();
    {
        let mut tree = trusted.tree_builder();
        tree.extend_evals(trace.to_evaluations());
        tree.commit(&mut trace_channel);
    }
    if proof.commitments.get(1).copied() != trusted.roots().get(1).copied() {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Ristretto scalar-window trace commitment mismatch".into(),
        ));
    }

    let mut channel = stwo::core::channel::Poseidon252Channel::default();
    mix_scope(&mut channel, &archive.scalar, &archive.windows);
    let mut scheme =
        stwo::core::pcs::CommitmentSchemeVerifier::<Poseidon252MerkleChannel>::new(config);
    scheme.commit(
        proof.commitments[0],
        &vec![LOG_SIZE; PREPROCESSED_COLUMNS],
        &mut channel,
    );
    scheme.commit(
        proof.commitments[1],
        &vec![LOG_SIZE; NUM_COLUMNS],
        &mut channel,
    );
    let ids = preprocessed_ids();
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
    let component = FrameworkComponent::new(
        &mut allocator,
        ScalarWindowsAir { log_size: LOG_SIZE },
        SecureField::from(0u32),
    );
    stwo::core::verifier::verify(&[&component], &mut channel, &mut scheme, proof)
        .map_err(|error| TexasAirError::ConstraintUnsatisfied(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ristretto_scalar_air::prove_ristretto_scalar_canonical;

    #[test]
    fn proves_boundary_scalar_windows() {
        let mut scalar = crate::ristretto_scalar_air::GROUP_ORDER_BYTES;
        scalar[0] -= 1;
        let archive = prove_ristretto_scalar_windows(&scalar).unwrap();
        assert_eq!(archive.windows[0], scalar[0] & 0x0f);
        assert_eq!(archive.windows[1], scalar[0] >> 4);
        verify_ristretto_scalar_windows(&archive).unwrap();
    }

    #[test]
    fn verifier_rejects_spliced_scalar_or_window() {
        let mut scalar = crate::ristretto_scalar_air::GROUP_ORDER_BYTES;
        scalar[0] -= 1;
        let mut archive = prove_ristretto_scalar_windows(&scalar).unwrap();
        archive.scalar[0] ^= 1;
        assert!(verify_ristretto_scalar_windows(&archive).is_err());

        let mut archive = prove_ristretto_scalar_windows(&scalar).unwrap();
        archive.windows[0] ^= 1;
        assert!(verify_ristretto_scalar_windows(&archive).is_err());
    }

    #[test]
    fn scalar_must_be_canonical() {
        let mut scalar = crate::ristretto_scalar_air::GROUP_ORDER_BYTES;
        scalar[0] += 1;
        assert!(prove_ristretto_scalar_windows(&scalar).is_err());
        assert!(prove_ristretto_scalar_canonical(&scalar).is_err());
    }
}
