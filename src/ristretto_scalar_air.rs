//! Canonical Ristretto255 group-scalar limb AIR.
//!
//! A public 32-byte scalar is constrained to canonical 8-bit limbs and to be
//! strictly below the prime-order group order `l`.  The bound is checked by an
//! AIR subtraction witness, not by a native host comparison.

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
use crate::trace_gen::MethodTrace;

const LIMBS: usize = 32;
const BASE: u32 = 256;
const LOG_SIZE: u32 = 1;
const NUM_VALUE_BITS: usize = LIMBS * 8;
const VALUE_OFFSET: usize = 0;
const VALUE_BITS_OFFSET: usize = VALUE_OFFSET + LIMBS;
const DIFF_OFFSET: usize = VALUE_BITS_OFFSET + NUM_VALUE_BITS;
const DIFF_BITS_OFFSET: usize = DIFF_OFFSET + LIMBS;
const CARRY_OFFSET: usize = DIFF_BITS_OFFSET + NUM_VALUE_BITS;
const NONZERO_OFFSET: usize = CARRY_OFFSET + LIMBS;
const INVERSE_OFFSET: usize = NONZERO_OFFSET + LIMBS;
const NUM_COLUMNS: usize = INVERSE_OFFSET + LIMBS + 1;
const PREPROCESSED_COLUMNS: usize = LIMBS;

/// Little-endian bytes of the Ristretto255 group order.
const GROUP_ORDER_BYTES: [u8; LIMBS] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

/// A public Ristretto255 scalar and its canonical-range STARK.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoScalarCanonicalProof {
    /// Little-endian public scalar bytes.
    pub value: [u8; LIMBS],
    /// Serialized proof binding the scalar to the canonical range relation.
    pub stark_proof_bytes: Vec<u8>,
}

fn options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(16 * 1024 * 1024)
}

fn order_minus_value(value: &[u8; LIMBS]) -> TexasAirResult<([u8; LIMBS], [u8; LIMBS])> {
    let mut difference = [0u8; LIMBS];
    let mut borrows = [0u8; LIMBS];
    let mut borrow = false;
    for index in 0..LIMBS {
        let mut order_limb = u16::from(GROUP_ORDER_BYTES[index]);
        if borrow {
            order_limb = order_limb.saturating_sub(1);
        }
        let value_limb = u16::from(value[index]);
        if order_limb >= value_limb {
            difference[index] = u8::try_from(order_limb - value_limb)
                .expect("canonical scalar subtraction fits in a byte");
            borrow = false;
        } else {
            difference[index] = u8::try_from(order_limb + 256u16 - value_limb)
                .expect("canonical scalar subtraction fits in a byte");
            borrow = true;
        }
        borrows[index] = u8::from(borrow);
    }
    if borrow {
        return Err(TexasAirError::SpecViolation(
            "Ristretto scalar is not below the group order".into(),
        ));
    }
    if difference == [0u8; LIMBS] {
        return Err(TexasAirError::SpecViolation(
            "Ristretto scalar must be strictly below the group order".into(),
        ));
    }
    Ok((difference, borrows))
}

fn append_limb(row: &mut Vec<M31>, limb: u8) {
    row.push(M31::from(u32::from(limb)));
    for bit in 0..8 {
        row.push(M31::from(u32::from((limb >> bit) & 1)));
    }
}

fn m31_inverse(value: u8) -> M31 {
    if value == 0 {
        return M31::from(0u32);
    }
    M31::from(u32::from(value)).inverse()
}

fn trace_columns(value: &[u8; LIMBS]) -> TexasAirResult<MethodTrace> {
    let (difference, borrows) = order_minus_value(value)?;
    let mut row = Vec::with_capacity(NUM_COLUMNS);
    for limb in value {
        append_limb(&mut row, *limb);
    }
    for limb in difference {
        append_limb(&mut row, limb);
    }
    // Addition carry into limb i is subtraction borrow out of limb i-1.
    row.push(M31::from(0u32));
    for borrow in borrows[..LIMBS - 1].iter() {
        row.push(M31::from(u32::from(*borrow)));
    }
    let mut nonzero_count = 0u32;
    for limb in difference {
        nonzero_count += u32::from(limb != 0);
        row.push(M31::from(u32::from(limb != 0)));
        row.push(m31_inverse(limb));
    }
    row.push(M31::from(nonzero_count).inverse());
    debug_assert_eq!(row.len(), NUM_COLUMNS);
    let mut trace = MethodTrace::new(LOG_SIZE, NUM_COLUMNS);
    trace.write_row(0, &row)?;
    trace.write_row(1, &row)?;
    Ok(trace)
}

fn scope_columns(value: &[u8; LIMBS]) -> MethodTrace {
    let mut trace = MethodTrace::new(LOG_SIZE, PREPROCESSED_COLUMNS);
    let row = value
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
            id: format!("ristretto.scalar.canonical.v1.{limb}").into(),
        })
        .collect()
}

#[derive(Clone, Copy)]
struct CanonicalScalarAir {
    log_size: u32,
}

impl FrameworkEval for CanonicalScalarAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let one: E::F = M31::from(1u32).into();
        let base: E::F = M31::from(BASE).into();
        let ids = preprocessed_ids();

        let mut value = Vec::with_capacity(LIMBS);
        let mut difference = Vec::with_capacity(LIMBS);
        for _ in 0..(2 * LIMBS) {
            let limb = eval.next_trace_mask();
            let mut bits = Vec::with_capacity(8);
            for _ in 0..8 {
                bits.push(eval.next_trace_mask());
            }
            let mut reconstructed: E::F = M31::from(0u32).into();
            for (bit_index, bit) in bits.iter().enumerate() {
                eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
                reconstructed += bit.clone() * E::F::from(M31::from(1u32 << bit_index));
            }
            eval.add_constraint(limb.clone() - reconstructed);
            if value.len() < LIMBS {
                value.push(limb);
            } else {
                difference.push(limb);
            }
        }

        let mut carries = Vec::with_capacity(LIMBS);
        for _ in 0..LIMBS {
            let carry = eval.next_trace_mask();
            eval.add_constraint(carry.clone() * (carry.clone() - one.clone()));
            carries.push(carry);
        }
        eval.add_constraint(carries[0].clone());
        let mut nonzero_count: E::F = M31::from(0u32).into();
        for index in 0..LIMBS {
            let carry_out = if index + 1 == LIMBS {
                M31::from(0u32).into()
            } else {
                carries[index + 1].clone()
            };
            eval.add_constraint(
                value[index].clone() + difference[index].clone() + carries[index].clone()
                    - E::F::from(M31::from(u32::from(GROUP_ORDER_BYTES[index])))
                    - base.clone() * carry_out,
            );
        }

        for index in 0..LIMBS {
            let nonzero = eval.next_trace_mask();
            let inverse = eval.next_trace_mask();
            eval.add_constraint(nonzero.clone() * (nonzero.clone() - one.clone()));
            nonzero_count += nonzero.clone();
            eval.add_constraint(difference[index].clone() * inverse - nonzero);
        }
        let nonzero_inverse = eval.next_trace_mask();
        eval.add_constraint(nonzero_count.clone() * nonzero_inverse - one);

        for (index, limb) in value.into_iter().enumerate() {
            let scope = eval.get_preprocessed_column(ids[index].clone());
            eval.add_constraint(limb - scope);
        }
        eval
    }
}

/// Prove that a public little-endian Ristretto scalar is canonical.
pub fn prove_ristretto_scalar_canonical(
    value: &[u8; LIMBS],
) -> TexasAirResult<ArchivedRistrettoScalarCanonicalProof> {
    let trace = trace_columns(value)?;
    let scope = scope_columns(value);
    let config = crate::prover_context::protocol_pcs_config();
    let twiddles =
        crate::prover_context::simd_twiddles(LOG_SIZE + config.fri_config.log_blowup_factor);
    let mut channel = stwo::core::channel::Poseidon252Channel::default();
    channel.mix_u32s(
        &value
            .iter()
            .map(|limb| u32::from(*limb))
            .collect::<Vec<_>>(),
    );
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
        CanonicalScalarAir { log_size: LOG_SIZE },
        SecureField::from(0u32),
    );
    let proof = prove(&[&component], &mut channel, scheme)
        .map_err(|error| TexasAirError::StwoProverError(error.to_string()))?;
    let stark_proof_bytes = options()
        .serialize(&proof)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
    Ok(ArchivedRistrettoScalarCanonicalProof {
        value: *value,
        stark_proof_bytes,
    })
}

/// Verify the scalar canonical-range statement without a host comparison.
pub fn verify_ristretto_scalar_canonical(
    archive: &ArchivedRistrettoScalarCanonicalProof,
) -> TexasAirResult<()> {
    type Proof = StarkProof<Poseidon252MerkleHasher>;
    let proof: Proof = options()
        .deserialize(&archive.stark_proof_bytes)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
    let scope = scope_columns(&archive.value);
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
            "Ristretto scalar public scope commitment mismatch".into(),
        ));
    }

    let mut channel = stwo::core::channel::Poseidon252Channel::default();
    channel.mix_u32s(
        &archive
            .value
            .iter()
            .map(|limb| u32::from(*limb))
            .collect::<Vec<_>>(),
    );
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
        CanonicalScalarAir { log_size: LOG_SIZE },
        SecureField::from(0u32),
    );
    stwo::core::verifier::verify(&[&component], &mut channel, &mut scheme, proof)
        .map_err(|error| TexasAirError::ConstraintUnsatisfied(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prove_and_verify_accept_boundary_scalars() {
        let mut order_minus_one = GROUP_ORDER_BYTES;
        order_minus_one[0] -= 1;
        for value in [order_minus_one, {
            let mut value = order_minus_one;
            value[0] -= 1;
            value
        }] {
            let archive = prove_ristretto_scalar_canonical(&value).unwrap();
            verify_ristretto_scalar_canonical(&archive).unwrap();
        }
    }

    #[test]
    fn witness_rows_satisfy_the_direct_scalar_constraints() {
        let value = {
            let mut value = GROUP_ORDER_BYTES;
            value[0] -= 1;
            value
        };
        let trace = trace_columns(&value).unwrap();
        let scope = scope_columns(&value);
        let evals = stwo::core::pcs::TreeVec::new(vec![
            scope.cols.iter().collect(),
            trace.cols.iter().collect(),
        ]);
        stwo_constraint_framework::assert_constraints_on_trace(
            &evals,
            LOG_SIZE,
            |eval| {
                CanonicalScalarAir { log_size: LOG_SIZE }.evaluate(eval);
            },
            SecureField::from(0u32),
        );
    }

    #[test]
    fn noncanonical_scalar_rejects_before_proving() {
        assert!(prove_ristretto_scalar_canonical(&GROUP_ORDER_BYTES).is_err());

        let mut value = GROUP_ORDER_BYTES;
        value[0] += 1;
        assert!(prove_ristretto_scalar_canonical(&value).is_err());
    }

    #[test]
    fn direct_constraints_reject_a_forged_noncanonical_scalar_limb() {
        let value = {
            let mut value = GROUP_ORDER_BYTES;
            value[0] -= 1;
            value
        };
        let mut trace = trace_columns(&value).unwrap();
        trace.cols[VALUE_OFFSET][0] += M31::from(1u32);
        let scope = scope_columns(&value);
        let evals = stwo::core::pcs::TreeVec::new(vec![
            scope.cols.iter().collect(),
            trace.cols.iter().collect(),
        ]);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                stwo_constraint_framework::assert_constraints_on_trace(
                    &evals,
                    LOG_SIZE,
                    |eval| {
                        CanonicalScalarAir { log_size: LOG_SIZE }.evaluate(eval);
                    },
                    SecureField::from(0u32),
                );
            }))
            .is_err()
        );
    }

    #[test]
    fn verifier_rejects_public_scope_splice() {
        let mut canonical = GROUP_ORDER_BYTES;
        canonical[0] -= 1;
        let archive = prove_ristretto_scalar_canonical(&canonical).unwrap();
        let mut forged = archive;
        forged.value[0] ^= 1;
        assert!(verify_ristretto_scalar_canonical(&forged).is_err());
    }
}
