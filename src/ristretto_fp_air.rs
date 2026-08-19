//! Canonical Ristretto255 field-element limb AIR.
//!
//! This is the first production-oriented primitive for the Ristretto migration:
//! a public 32-byte value is constrained to use canonical 8-bit limbs and lie
//! strictly below `2^255 - 19`.  The subtraction witness is committed, so the
//! inequality is an AIR relation rather than a host comparison.  Later decode,
//! encode, DLEQ, and MSM components will compose this limb representation.

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

/// Little-endian bytes of the Ristretto255 prime `2^255 - 19`.
const P_BYTES: [u8; LIMBS] = {
    let mut bytes = [0xffu8; LIMBS];
    bytes[0] = 0xed;
    bytes[31] = 0x7f;
    bytes
};

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
/// A public Ristretto255 field element and its canonical-limb STARK.
pub struct ArchivedRistrettoFpCanonicalProof {
    /// Little-endian public field-element bytes.
    pub value: [u8; LIMBS],
    /// Serialized Stwo proof binding the bytes to the canonical range relation.
    pub stark_proof_bytes: Vec<u8>,
}

fn options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(16 * 1024 * 1024)
}

fn canonical_subtraction(value: &[u8; LIMBS]) -> TexasAirResult<([u8; LIMBS], [u8; LIMBS])> {
    let mut difference = [0u8; LIMBS];
    let mut carries = [0u8; LIMBS];
    let mut borrow = false;
    for index in 0..LIMBS {
        let prime_limb = u16::from(P_BYTES[index]);
        let value_limb = u16::from(value[index]);
        let mut left = prime_limb;
        if borrow {
            left = left.saturating_sub(1);
        }
        if left >= value_limb {
            difference[index] =
                u8::try_from(left - value_limb).expect("canonical limb subtraction fits in u8");
            borrow = false;
        } else {
            difference[index] = u8::try_from(left + 256u16 - value_limb)
                .expect("canonical limb subtraction fits in u8");
            borrow = true;
        }
        carries[index] = u8::from(borrow);
    }
    if borrow {
        return Err(TexasAirError::SpecViolation(
            "Ristretto255 field element is not below the prime".into(),
        ));
    }
    if difference == [0u8; LIMBS] {
        return Err(TexasAirError::SpecViolation(
            "Ristretto255 field element must be strictly below the prime".into(),
        ));
    }
    Ok((difference, carries))
}

fn append_limb_witness(row: &mut Vec<M31>, limb: u8) {
    row.push(M31::from(u32::from(limb)));
    for bit in 0..8 {
        row.push(M31::from(u32::from((limb >> bit) & 1)));
    }
}

fn m31_inverse(value: u8) -> M31 {
    if value == 0 {
        M31::from(0u32)
    } else {
        M31::from(u32::from(value)).inverse()
    }
}

fn trace_columns(value: &[u8; LIMBS]) -> TexasAirResult<MethodTrace> {
    let (difference, _subtraction_borrows) = canonical_subtraction(value)?;
    let mut row = Vec::with_capacity(NUM_COLUMNS);
    for limb in value {
        append_limb_witness(&mut row, *limb);
    }
    for limb in difference {
        append_limb_witness(&mut row, limb);
    }
    let mut addition_carries = [0u8; LIMBS];
    let mut addition_carry = 0u16;
    for index in 0..LIMBS {
        let sum = u16::from(value[index]) + u16::from(difference[index]) + addition_carry;
        addition_carries[index] = u8::from(sum >= BASE as u16);
        addition_carry = sum >> 8;
    }
    for carry in addition_carries {
        row.push(M31::from(u32::from(carry)));
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
    trace.write_row(0, &row).expect("fixed scope width");
    trace.write_row(1, &row).expect("fixed scope width");
    trace
}

fn preprocessed_ids() -> Vec<PreProcessedColumnId> {
    (0..LIMBS)
        .map(|limb| PreProcessedColumnId {
            id: format!("ristretto.fp.value.v1.{limb}").into(),
        })
        .collect()
}

#[derive(Clone, Copy)]
struct CanonicalFpAir {
    log_size: u32,
}

impl FrameworkEval for CanonicalFpAir {
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
        for _ in 0..LIMBS {
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
            value.push(limb);
        }
        for _ in 0..LIMBS {
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
            difference.push(limb);
        }
        let mut carries = Vec::with_capacity(LIMBS);
        for _ in 0..LIMBS {
            let carry = eval.next_trace_mask();
            eval.add_constraint(carry.clone() * (carry.clone() - one.clone()));
            carries.push(carry);
        }
        eval.add_constraint(carries[LIMBS - 1].clone());
        let mut nonzero_count: E::F = M31::from(0u32).into();
        for index in 0..LIMBS {
            let carry_in = if index == 0 {
                M31::from(0u32).into()
            } else {
                carries[index - 1].clone()
            };
            let carry_out = if index + 1 == LIMBS {
                M31::from(0u32).into()
            } else {
                carries[index].clone()
            };
            eval.add_constraint(
                value[index].clone() + difference[index].clone() + carry_in
                    - E::F::from(M31::from(u32::from(P_BYTES[index])))
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

/// Prove that a public little-endian Ristretto255 field element is canonical.
///
/// The host constructs witness columns but does not provide a trusted comparison result.
/// Verification reconstructs only public scope and invokes STARK verification.
pub fn prove_ristretto_fp_canonical(
    value: &[u8; LIMBS],
) -> TexasAirResult<ArchivedRistrettoFpCanonicalProof> {
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
        CanonicalFpAir { log_size: LOG_SIZE },
        SecureField::from(0u32),
    );
    let proof = prove(&[&component], &mut channel, scheme)
        .map_err(|error| TexasAirError::StwoProverError(error.to_string()))?;
    let stark_proof_bytes = options()
        .serialize(&proof)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
    Ok(ArchivedRistrettoFpCanonicalProof {
        value: *value,
        stark_proof_bytes,
    })
}

/// Verify the AIR canonical-range statement without a native big-integer comparison.
pub fn verify_ristretto_fp_canonical(
    archive: &ArchivedRistrettoFpCanonicalProof,
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
            "Ristretto Fp public scope commitment mismatch".into(),
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
        CanonicalFpAir { log_size: LOG_SIZE },
        SecureField::from(0u32),
    );
    stwo::core::verifier::verify(&[&component], &mut channel, &mut scheme, proof)
        .map_err(|error| TexasAirError::ConstraintUnsatisfied(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prove_and_verify_accept_boundary_field_elements() {
        let mut prime_minus_one = P_BYTES;
        prime_minus_one[0] -= 1;
        let mut small = [0u8; LIMBS];
        small[0] = 3;
        let mut inverse_four_squared = [0xffu8; LIMBS];
        inverse_four_squared[0] = 0xf2;
        inverse_four_squared[31] = 0x5f;
        for value in [
            prime_minus_one,
            {
                let mut value = prime_minus_one;
                value[0] -= 1;
                value
            },
            small,
            inverse_four_squared,
        ] {
            let archive = prove_ristretto_fp_canonical(&value)
                .expect("canonical Ristretto field element proof");
            verify_ristretto_fp_canonical(&archive).expect("canonical verification");
        }
    }

    #[test]
    fn witness_rows_satisfy_the_direct_fp_constraints() {
        let value = {
            let mut value = P_BYTES;
            value[0] -= 1;
            value
        };
        let mut inverse_four_squared = [0xffu8; LIMBS];
        inverse_four_squared[0] = 0xf2;
        inverse_four_squared[31] = 0x5f;
        for value in [value, inverse_four_squared] {
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
                    CanonicalFpAir { log_size: LOG_SIZE }.evaluate(eval);
                },
                SecureField::from(0u32),
            );
        }
    }

    #[test]
    fn noncanonical_field_element_rejects_before_proving() {
        assert!(prove_ristretto_fp_canonical(&P_BYTES).is_err());

        let mut value = P_BYTES;
        value[0] += 1;
        assert!(prove_ristretto_fp_canonical(&value).is_err());
    }

    #[test]
    fn direct_constraints_reject_a_forged_noncanonical_limb() {
        let value = {
            let mut value = P_BYTES;
            value[0] -= 1;
            value
        };
        let mut trace = trace_columns(&value).unwrap();
        // Bypass the prover-side canonical check and modify only the low limb.
        // The committed prime-subtraction equation must reject p + 1.
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
                        CanonicalFpAir { log_size: LOG_SIZE }.evaluate(eval);
                    },
                    SecureField::from(0u32),
                );
            }))
            .is_err()
        );
    }

    #[test]
    fn verifier_rejects_public_scope_splice() {
        let mut canonical = P_BYTES;
        canonical[0] -= 1;
        let archive = prove_ristretto_fp_canonical(&canonical).unwrap();
        let mut forged = archive;
        forged.value[0] ^= 1;
        assert!(verify_ristretto_fp_canonical(&forged).is_err());
    }
}
