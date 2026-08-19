//! Canonical Ristretto255 field-element modular multiplication AIR.
//!
//! The relation proves `a * b = c + q * p` limb by limb.  All four values are
//! independently canonical-range proofs; signed school-multiplication carries
//! are committed, sign/range constrained, and never trusted from the host.

use bincode::Options;
use borsh::{BorshDeserialize, BorshSerialize};
use num_bigint::BigUint;
use num_traits::One;
use stwo::core::channel::{Channel, Poseidon252Channel};
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::SecureField;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::poseidon252_merkle::Poseidon252MerkleChannel;
use stwo::core::vcs_lifted::poseidon252_merkle::Poseidon252MerkleHasher;
use stwo::core::verifier::verify;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::pcs::CommitmentSchemeProver;
use stwo::prover::prove;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
};

use crate::error::{TexasAirError, TexasAirResult};
use crate::ristretto_fp_air::{
    ArchivedRistrettoFpCanonicalProof, prove_ristretto_fp_canonical, verify_ristretto_fp_canonical,
};
use crate::trace_gen::MethodTrace;

const LIMBS: usize = 32;
const PRODUCT_LIMBS: usize = 2 * LIMBS;
const LOG_SIZE: u32 = 1;
const BASE: u32 = 256;
const A_OFFSET: usize = 0;
const B_OFFSET: usize = A_OFFSET + LIMBS;
const C_OFFSET: usize = B_OFFSET + LIMBS;
const Q_OFFSET: usize = C_OFFSET + LIMBS;
const CARRY_OFFSET: usize = Q_OFFSET + LIMBS;
const CARRY_WITNESS_WIDTH: usize = 1 + 1 + 16;
const NUM_COLUMNS: usize = CARRY_OFFSET + (PRODUCT_LIMBS - 1) * CARRY_WITNESS_WIDTH;
const PREPROCESSED_COLUMNS: usize = Q_OFFSET + LIMBS;

/// Little-endian bytes of the Ristretto255 prime `2^255 - 19`.
const P_BYTES: [u8; LIMBS] = {
    let mut bytes = [0xffu8; LIMBS];
    bytes[0] = 0xed;
    bytes[31] = 0x7f;
    bytes
};

/// Serialized limbwise modular-multiplication STARK.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoFpMulProof {
    stark_proof_bytes: Vec<u8>,
}

/// Public `a*b=c mod p` statement and all independently verified range proofs.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoFpMultiplicationProof {
    /// Canonical left input.
    pub a: [u8; LIMBS],
    /// Canonical right input.
    pub b: [u8; LIMBS],
    /// Canonical product modulo `p`.
    pub c: [u8; LIMBS],
    /// Canonical quotient `floor(a*b/p)`.
    pub q: [u8; LIMBS],
    /// Range proofs for `a`, `b`, `c`, and `q`.
    pub canonical: [ArchivedRistrettoFpCanonicalProof; 4],
    /// Limbwise multiplication relation.
    pub multiplication: ArchivedRistrettoFpMulProof,
}

#[derive(Clone, Copy)]
struct SignedCarry {
    negative: bool,
    magnitude: u16,
}

impl SignedCarry {
    fn new(value: i64) -> Self {
        let magnitude =
            u16::try_from(value.unsigned_abs()).expect("Ristretto carry magnitude fits in u16");
        Self {
            negative: value < 0,
            magnitude,
        }
    }
}

fn options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(32 * 1024 * 1024)
}

fn modulus() -> BigUint {
    (BigUint::one() << 255u32) - BigUint::from(19u32)
}

fn big_uint(value: &[u8; LIMBS]) -> BigUint {
    BigUint::from_bytes_le(value)
}

fn limbs(value: &BigUint) -> [u8; LIMBS] {
    let mut out = [0u8; LIMBS];
    let bytes = value.to_bytes_le();
    let length = bytes.len().min(LIMBS);
    out[..length].copy_from_slice(&bytes[..length]);
    out
}

fn convolution(left: &[u8; LIMBS], right: &[u8; LIMBS]) -> Vec<i64> {
    let mut out = vec![0i64; PRODUCT_LIMBS];
    for (left_index, left_limb) in left.iter().enumerate() {
        for (right_index, right_limb) in right.iter().enumerate() {
            out[left_index + right_index] += i64::from(*left_limb) * i64::from(*right_limb);
        }
    }
    out
}

fn multiplication_witness(
    a: &[u8; LIMBS],
    b: &[u8; LIMBS],
) -> TexasAirResult<([u8; LIMBS], [u8; LIMBS], Vec<SignedCarry>)> {
    let p = modulus();
    let a_value = big_uint(a);
    let b_value = big_uint(b);
    if a_value >= p || b_value >= p {
        return Err(TexasAirError::SpecViolation(
            "Ristretto modular multiplication inputs must be canonical".into(),
        ));
    }
    let product = &a_value * &b_value;
    let quotient = &product / &p;
    let remainder = &product % &p;
    let c = limbs(&remainder);
    let q = limbs(&quotient);

    let product_limbs = convolution(a, b);
    let quotient_prime_limbs = convolution(&q, &P_BYTES);
    let mut carries = Vec::with_capacity(PRODUCT_LIMBS - 1);
    let mut carry_in = 0i64;
    for limb_index in 0..PRODUCT_LIMBS {
        let output_limb = if limb_index < LIMBS {
            i64::from(c[limb_index])
        } else {
            0
        };
        let difference =
            product_limbs[limb_index] - quotient_prime_limbs[limb_index] - output_limb + carry_in;
        if difference % i64::from(BASE) != 0 {
            return Err(TexasAirError::SpecViolation(
                "Ristretto multiplication carry witness is invalid".into(),
            ));
        }
        let carry_out = difference / i64::from(BASE);
        if limb_index + 1 == PRODUCT_LIMBS {
            if carry_out != 0 {
                return Err(TexasAirError::SpecViolation(
                    "Ristretto multiplication final carry is nonzero".into(),
                ));
            }
        } else {
            carries.push(SignedCarry::new(carry_out));
            carry_in = carry_out;
        }
    }
    Ok((c, q, carries))
}

fn append_signed_carry(row: &mut Vec<M31>, carry: SignedCarry) {
    row.push(M31::from(u32::from(carry.negative)));
    row.push(M31::from(u32::from(carry.magnitude)));
    for bit in 0..16 {
        row.push(M31::from(u32::from((carry.magnitude >> bit) & 1)));
    }
}

fn trace_columns(
    a: &[u8; LIMBS],
    b: &[u8; LIMBS],
) -> TexasAirResult<(MethodTrace, [u8; LIMBS], [u8; LIMBS])> {
    let (c, q, carries) = multiplication_witness(a, b)?;
    let mut row = Vec::with_capacity(NUM_COLUMNS);
    row.extend(a.iter().map(|limb| M31::from(u32::from(*limb))));
    row.extend(b.iter().map(|limb| M31::from(u32::from(*limb))));
    row.extend(c.iter().map(|limb| M31::from(u32::from(*limb))));
    row.extend(q.iter().map(|limb| M31::from(u32::from(*limb))));
    for carry in carries {
        append_signed_carry(&mut row, carry);
    }
    debug_assert_eq!(row.len(), NUM_COLUMNS);
    let mut trace = MethodTrace::new(LOG_SIZE, NUM_COLUMNS);
    trace.write_row(0, &row)?;
    trace.write_row(1, &row)?;
    Ok((trace, c, q))
}

fn scope_columns(
    a: &[u8; LIMBS],
    b: &[u8; LIMBS],
    c: &[u8; LIMBS],
    q: &[u8; LIMBS],
) -> MethodTrace {
    let mut trace = MethodTrace::new(LOG_SIZE, PREPROCESSED_COLUMNS);
    let mut row = Vec::with_capacity(PREPROCESSED_COLUMNS);
    row.extend(a.iter().map(|limb| M31::from(u32::from(*limb))));
    row.extend(b.iter().map(|limb| M31::from(u32::from(*limb))));
    row.extend(c.iter().map(|limb| M31::from(u32::from(*limb))));
    row.extend(q.iter().map(|limb| M31::from(u32::from(*limb))));
    trace.write_row(0, &row).expect("fixed scope width");
    trace.write_row(1, &row).expect("fixed scope width");
    trace
}

fn preprocessed_ids() -> Vec<PreProcessedColumnId> {
    (0..PREPROCESSED_COLUMNS)
        .map(|column| PreProcessedColumnId {
            id: format!("ristretto.fp.mul.v1.{column}").into(),
        })
        .collect()
}

#[derive(Clone, Copy)]
struct FpMulAir {
    log_size: u32,
}

impl FrameworkEval for FpMulAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let one: E::F = M31::from(1u32).into();
        let a: Vec<_> = (0..LIMBS).map(|_| eval.next_trace_mask()).collect();
        let b: Vec<_> = (0..LIMBS).map(|_| eval.next_trace_mask()).collect();
        let c: Vec<_> = (0..LIMBS).map(|_| eval.next_trace_mask()).collect();
        let q: Vec<_> = (0..LIMBS).map(|_| eval.next_trace_mask()).collect();

        let mut negative_flags = Vec::with_capacity(PRODUCT_LIMBS - 1);
        let mut magnitudes = Vec::with_capacity(PRODUCT_LIMBS - 1);
        for _ in 0..(PRODUCT_LIMBS - 1) {
            let negative = eval.next_trace_mask();
            let magnitude = eval.next_trace_mask();
            let mut bits = Vec::with_capacity(16);
            for _ in 0..16 {
                bits.push(eval.next_trace_mask());
            }
            eval.add_constraint(negative.clone() * (negative.clone() - one.clone()));
            let mut reconstructed: E::F = M31::from(0u32).into();
            for (bit_index, bit) in bits.iter().enumerate() {
                eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
                reconstructed += bit.clone() * E::F::from(M31::from(1u32 << bit_index));
            }
            eval.add_constraint(magnitude.clone() - reconstructed);
            negative_flags.push(negative);
            magnitudes.push(magnitude);
        }

        for limb_index in 0..PRODUCT_LIMBS {
            let mut relation: E::F = M31::from(0u32).into();
            let start = limb_index.saturating_sub(LIMBS - 1);
            let end = limb_index.min(LIMBS - 1);
            for left_index in start..=end {
                let right_index = limb_index - left_index;
                relation += a[left_index].clone() * b[right_index].clone();
                relation = relation
                    - q[left_index].clone()
                        * E::F::from(M31::from(u32::from(P_BYTES[right_index])));
            }
            if limb_index < LIMBS {
                relation = relation - c[limb_index].clone();
            }
            if limb_index > 0 {
                let previous = limb_index - 1;
                let negative = negative_flags[previous].clone();
                let positive = one.clone() - negative.clone();
                relation += positive * magnitudes[previous].clone();
                relation = relation - negative * magnitudes[previous].clone();
            }
            if limb_index + 1 < PRODUCT_LIMBS {
                let negative = negative_flags[limb_index].clone();
                let positive = one.clone() - negative.clone();
                let signed_carry_out = positive - negative;
                relation = relation
                    - E::F::from(M31::from(BASE))
                        * signed_carry_out
                        * magnitudes[limb_index].clone();
            }
            eval.add_constraint(relation);
        }

        let ids = preprocessed_ids();
        for (index, value) in a
            .iter()
            .chain(b.iter())
            .chain(c.iter())
            .chain(q.iter())
            .enumerate()
        {
            let scope = eval.get_preprocessed_column(ids[index].clone());
            eval.add_constraint(value.clone() - scope);
        }
        eval
    }
}

fn mix_scope(
    channel: &mut Poseidon252Channel,
    a: &[u8; LIMBS],
    b: &[u8; LIMBS],
    c: &[u8; LIMBS],
    q: &[u8; LIMBS],
) {
    let mut values = Vec::with_capacity(PREPROCESSED_COLUMNS);
    values.extend(a.iter().map(|limb| u32::from(*limb)));
    values.extend(b.iter().map(|limb| u32::from(*limb)));
    values.extend(c.iter().map(|limb| u32::from(*limb)));
    values.extend(q.iter().map(|limb| u32::from(*limb)));
    channel.mix_u32s(&values);
}

/// Prove `a * b = c mod p`, including range proofs and committed quotient.
pub fn prove_ristretto_fp_multiplication(
    a: &[u8; LIMBS],
    b: &[u8; LIMBS],
) -> TexasAirResult<ArchivedRistrettoFpMultiplicationProof> {
    let (trace, c, q) = trace_columns(a, b)?;
    let scope = scope_columns(a, b, &c, &q);
    let config = crate::prover_context::protocol_pcs_config();
    let twiddles =
        crate::prover_context::simd_twiddles(LOG_SIZE + config.fri_config.log_blowup_factor);
    let mut channel = Poseidon252Channel::default();
    mix_scope(&mut channel, a, b, &c, &q);
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
        FpMulAir { log_size: LOG_SIZE },
        SecureField::from(0u32),
    );
    let stark_proof = prove(&[&component], &mut channel, scheme)
        .map_err(|error| TexasAirError::StwoProverError(error.to_string()))?;
    let stark_proof_bytes = options()
        .serialize(&stark_proof)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
    Ok(ArchivedRistrettoFpMultiplicationProof {
        a: *a,
        b: *b,
        c,
        q,
        canonical: [
            prove_ristretto_fp_canonical(a)?,
            prove_ristretto_fp_canonical(b)?,
            prove_ristretto_fp_canonical(&c)?,
            prove_ristretto_fp_canonical(&q)?,
        ],
        multiplication: ArchivedRistrettoFpMulProof { stark_proof_bytes },
    })
}

/// Verify all range proofs and the limbwise multiplication STARK.
pub fn verify_ristretto_fp_multiplication(
    archive: &ArchivedRistrettoFpMultiplicationProof,
) -> TexasAirResult<()> {
    let [canonical_a, canonical_b, canonical_c, canonical_q] = &archive.canonical;
    verify_ristretto_fp_canonical(canonical_a)?;
    verify_ristretto_fp_canonical(canonical_b)?;
    verify_ristretto_fp_canonical(canonical_c)?;
    verify_ristretto_fp_canonical(canonical_q)?;
    if canonical_a.value != archive.a
        || canonical_b.value != archive.b
        || canonical_c.value != archive.c
        || canonical_q.value != archive.q
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Ristretto multiplication range proof is detached from public operands".into(),
        ));
    }

    let proof: StarkProof<Poseidon252MerkleHasher> = options()
        .deserialize(&archive.multiplication.stark_proof_bytes)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
    let scope = scope_columns(&archive.a, &archive.b, &archive.c, &archive.q);
    let config = crate::prover_context::protocol_pcs_config();
    let twiddles =
        crate::prover_context::simd_twiddles(LOG_SIZE + config.fri_config.log_blowup_factor);
    let mut trusted =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::with_memory_pool(
            config,
            &twiddles,
            crate::prover_context::simd_base_column_pool(),
        );
    let mut scope_channel = Poseidon252Channel::default();
    {
        let mut tree = trusted.tree_builder();
        tree.extend_evals(scope.to_evaluations());
        tree.commit(&mut scope_channel);
    }
    if proof.commitments.first().copied() != trusted.roots().first().copied() {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Ristretto multiplication public scope commitment mismatch".into(),
        ));
    }
    let mut channel = Poseidon252Channel::default();
    mix_scope(&mut channel, &archive.a, &archive.b, &archive.c, &archive.q);
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
        FpMulAir { log_size: LOG_SIZE },
        SecureField::from(0u32),
    );
    verify(&[&component], &mut channel, &mut scheme, proof)
        .map_err(|error| TexasAirError::ConstraintUnsatisfied(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small(value: u8) -> [u8; LIMBS] {
        let mut out = [0u8; LIMBS];
        out[0] = value;
        out
    }

    #[test]
    fn witness_rows_satisfy_the_direct_fp_mul_constraints() {
        let (trace, c, q) = trace_columns(&small(2), &small(3)).unwrap();
        let scope = scope_columns(&small(2), &small(3), &c, &q);
        let evals = stwo::core::pcs::TreeVec::new(vec![
            scope.cols.iter().collect(),
            trace.cols.iter().collect(),
        ]);
        stwo_constraint_framework::assert_constraints_on_trace(
            &evals,
            LOG_SIZE,
            |eval| {
                FpMulAir { log_size: LOG_SIZE }.evaluate(eval);
            },
            SecureField::from(0u32),
        );
    }

    #[test]
    fn witness_rows_satisfy_a_large_quotient_multiplication() {
        let mut inverse_two = [0xffu8; LIMBS];
        inverse_two[0] = 0xf7;
        inverse_two[31] = 0x3f;
        let (trace, c, q) = trace_columns(&small(2), &inverse_two).unwrap();
        assert_eq!(c, small(1));
        assert_eq!(q, small(1));
        let scope = scope_columns(&small(2), &inverse_two, &c, &q);
        let evals = stwo::core::pcs::TreeVec::new(vec![
            scope.cols.iter().collect(),
            trace.cols.iter().collect(),
        ]);
        stwo_constraint_framework::assert_constraints_on_trace(
            &evals,
            LOG_SIZE,
            |eval| {
                FpMulAir { log_size: LOG_SIZE }.evaluate(eval);
            },
            SecureField::from(0u32),
        );
    }

    #[test]
    fn witness_rows_satisfy_the_sqrt_ratio_inverse_four_multiplication() {
        let mut a = [0xffu8; LIMBS];
        a[0] = 0xf2;
        a[31] = 0x5f;
        let mut b = [0u8; LIMBS];
        b[0] = 4;
        let (trace, c, q) = trace_columns(&a, &b).unwrap();
        assert_eq!(c, small(1));
        assert_eq!(q, small(3));
        let scope = scope_columns(&a, &b, &c, &q);
        let evals = stwo::core::pcs::TreeVec::new(vec![
            scope.cols.iter().collect(),
            trace.cols.iter().collect(),
        ]);
        stwo_constraint_framework::assert_constraints_on_trace(
            &evals,
            LOG_SIZE,
            |eval| {
                FpMulAir { log_size: LOG_SIZE }.evaluate(eval);
            },
            SecureField::from(0u32),
        );
    }

    #[test]
    fn fp_mul_declares_the_maximum_expression_degree() {
        let mut evaluator = crate::ristretto_degree_util::DegreeEvaluator { max: 0 };
        evaluator = FpMulAir { log_size: LOG_SIZE }.evaluate(evaluator);
        assert_eq!(evaluator.max, 2);
    }

    #[test]
    fn proves_identity_zero_and_boundary_multiplications() {
        let archive = prove_ristretto_fp_multiplication(&small(0), &small(7)).unwrap();
        assert_eq!(archive.c, small(0));
        verify_ristretto_fp_multiplication(&archive).unwrap();

        let archive = prove_ristretto_fp_multiplication(&small(1), &small(1)).unwrap();
        assert_eq!(archive.c, small(1));
        assert_eq!(archive.q, small(0));
        verify_ristretto_fp_multiplication(&archive).unwrap();

        let mut p_minus_one = P_BYTES;
        p_minus_one[0] -= 1;
        let archive = prove_ristretto_fp_multiplication(&p_minus_one, &p_minus_one).unwrap();
        assert_eq!(archive.c, small(1));
        let mut expected_quotient = p_minus_one;
        expected_quotient[0] -= 1;
        assert_eq!(archive.q, expected_quotient);
        verify_ristretto_fp_multiplication(&archive).unwrap();
    }

    #[test]
    fn verifier_rejects_public_operand_splice() {
        let archive = prove_ristretto_fp_multiplication(&small(2), &small(3)).unwrap();
        let mut forged = archive;
        forged.a[0] ^= 1;
        assert!(verify_ristretto_fp_multiplication(&forged).is_err());
    }

    #[test]
    fn direct_constraints_reject_a_forged_output_limb() {
        let (mut trace, c, q) = trace_columns(&small(2), &small(3)).unwrap();
        trace.cols[C_OFFSET][0] += M31::from(1u32);
        let scope = scope_columns(&small(2), &small(3), &c, &q);
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
                        FpMulAir { log_size: LOG_SIZE }.evaluate(eval);
                    },
                    SecureField::from(0u32),
                );
            }))
            .is_err()
        );
    }
}
