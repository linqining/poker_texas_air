//! Canonical Ristretto255 field-element modular addition AIR.
//!
//! This composes three canonical-limb range proofs with a limbwise addition
//! relation.  The reduction selector `k` proves that at most one multiple of
//! `p = 2^255 - 19` was removed, which is sufficient because both inputs are
//! independently proven below `p`.

use bincode::Options;
use borsh::{BorshDeserialize, BorshSerialize};
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
const LOG_SIZE: u32 = 1;
const BASE: u32 = 256;
const A_OFFSET: usize = 0;
const B_OFFSET: usize = A_OFFSET + LIMBS;
const C_OFFSET: usize = B_OFFSET + LIMBS;
const K_OFFSET: usize = C_OFFSET + LIMBS;
const CARRY_OFFSET: usize = K_OFFSET + 1;
const NUM_COLUMNS: usize = CARRY_OFFSET + LIMBS * 2;
const PREPROCESSED_COLUMNS: usize = K_OFFSET + 1;

/// Little-endian bytes of the Ristretto255 prime `2^255 - 19`.
const P_BYTES: [u8; LIMBS] = {
    let mut bytes = [0xffu8; LIMBS];
    bytes[0] = 0xed;
    bytes[31] = 0x7f;
    bytes
};

/// Serialized limbwise modular-addition STARK.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoFpAddProof {
    stark_proof_bytes: Vec<u8>,
}

/// Public inputs and independently verified canonical-range proofs for `a+b=c`.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoFpAdditionProof {
    /// Canonical left input.
    pub a: [u8; LIMBS],
    /// Canonical right input.
    pub b: [u8; LIMBS],
    /// Canonical canonical sum modulo the Ristretto prime.
    pub c: [u8; LIMBS],
    /// One iff `a + b >= p`, therefore exactly one prime was removed.
    pub reduced: bool,
    /// Range proofs for a, b, and c.
    pub canonical: [ArchivedRistrettoFpCanonicalProof; 3],
    /// Limbwise arithmetic relation.
    pub addition: ArchivedRistrettoFpAddProof,
}

fn options() -> impl bincode::Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(16 * 1024 * 1024)
}

fn raw_sum(a: &[u8; LIMBS], b: &[u8; LIMBS]) -> [u8; LIMBS + 1] {
    let mut out = [0u8; LIMBS + 1];
    let mut carry = 0u16;
    for index in 0..LIMBS {
        let sum = u16::from(a[index]) + u16::from(b[index]) + carry;
        out[index] = u8::try_from(sum & 0xff).expect("raw sum limb fits in u8");
        carry = sum >> 8;
    }
    out[LIMBS] = u8::try_from(carry).expect("raw-sum carry fits in u8");
    out
}

fn raw_at_least_prime(value: &[u8; LIMBS + 1]) -> bool {
    if value[LIMBS] != 0 {
        return true;
    }
    for index in (0..LIMBS).rev() {
        let limb = u16::from(value[index]);
        let prime_limb = u16::from(P_BYTES[index]);
        if limb != prime_limb {
            return limb > prime_limb;
        }
    }
    true
}

fn subtract_prime(value: &[u8; LIMBS + 1]) -> [u8; LIMBS + 1] {
    let mut out = *value;
    let mut borrow = false;
    for index in 0..LIMBS {
        let mut prime_limb = u16::from(P_BYTES[index]);
        if borrow {
            prime_limb = prime_limb.saturating_add(1);
        }
        let current = u16::from(out[index]);
        if current >= prime_limb {
            out[index] =
                u8::try_from(current - prime_limb).expect("prime subtraction limb fits in u8");
            borrow = false;
        } else {
            out[index] = u8::try_from(current + 256u16 - prime_limb)
                .expect("prime subtraction limb fits in u8");
            borrow = true;
        }
    }
    debug_assert!(!borrow);
    out[LIMBS] = 0;
    out
}

fn addition_witness(a: &[u8; LIMBS], b: &[u8; LIMBS]) -> TexasAirResult<([u8; LIMBS], bool)> {
    if raw_at_least_prime(&{
        let mut value = [0u8; LIMBS + 1];
        value[..LIMBS].copy_from_slice(a);
        value
    }) || raw_at_least_prime(&{
        let mut value = [0u8; LIMBS + 1];
        value[..LIMBS].copy_from_slice(b);
        value
    }) {
        return Err(TexasAirError::SpecViolation(
            "Ristretto modular addition inputs must be canonical".into(),
        ));
    }
    let sum = raw_sum(a, b);
    let reduced = raw_at_least_prime(&sum);
    let c_value = if reduced { subtract_prime(&sum) } else { sum };
    let mut c = [0u8; LIMBS];
    c.copy_from_slice(&c_value[..LIMBS]);
    Ok((c, reduced))
}

fn calculate_carry(a: &[u8; LIMBS], b: &[u8; LIMBS], c: &[u8; LIMBS], k: u8) -> [i8; LIMBS] {
    let mut carry = [0i8; LIMBS];
    let mut carry_in: i64 = 0;
    for index in 0..LIMBS {
        let total = i64::from(a[index]) + i64::from(b[index]) + carry_in;
        let rhs = i64::from(P_BYTES[index]) * i64::from(k);
        let difference = total - i64::from(c[index]) - rhs;
        carry_in = difference.div_euclid(i64::from(BASE));
        if !(-1..=1).contains(&carry_in) {
            panic!("modular-addition carry must be -1, 0, or 1");
        }
        carry[index] = i8::try_from(carry_in).expect("signed carry magnitude is one bit");
    }
    carry
}

fn trace_columns(
    a: &[u8; LIMBS],
    b: &[u8; LIMBS],
) -> TexasAirResult<(MethodTrace, [u8; LIMBS], bool)> {
    let (c, reduced) = addition_witness(a, b)?;
    let k = u8::from(reduced);
    let carry = calculate_carry(a, b, &c, k);
    let mut row = Vec::with_capacity(NUM_COLUMNS);
    row.extend(a.iter().map(|limb| M31::from(u32::from(*limb))));
    row.extend(b.iter().map(|limb| M31::from(u32::from(*limb))));
    row.extend(c.iter().map(|limb| M31::from(u32::from(*limb))));
    row.push(M31::from(u32::from(k)));
    for signed_carry in carry {
        row.push(M31::from(u32::from(signed_carry < 0)));
        row.push(M31::from(u32::from(signed_carry != 0)));
    }
    debug_assert_eq!(row.len(), NUM_COLUMNS);
    let mut trace = MethodTrace::new(LOG_SIZE, NUM_COLUMNS);
    trace.write_row(0, &row)?;
    trace.write_row(1, &row)?;
    Ok((trace, c, reduced))
}

fn scope_columns(a: &[u8; LIMBS], b: &[u8; LIMBS], c: &[u8; LIMBS], k: u8) -> MethodTrace {
    let mut trace = MethodTrace::new(LOG_SIZE, PREPROCESSED_COLUMNS);
    let mut row = Vec::with_capacity(PREPROCESSED_COLUMNS);
    row.extend(a.iter().map(|limb| M31::from(u32::from(*limb))));
    row.extend(b.iter().map(|limb| M31::from(u32::from(*limb))));
    row.extend(c.iter().map(|limb| M31::from(u32::from(*limb))));
    row.push(M31::from(u32::from(k)));
    trace.write_row(0, &row).expect("fixed scope width");
    trace.write_row(1, &row).expect("fixed scope width");
    trace
}

fn preprocessed_ids() -> &'static [PreProcessedColumnId] {
    static IDS: std::sync::OnceLock<Vec<PreProcessedColumnId>> = std::sync::OnceLock::new();
    IDS.get_or_init(|| {
        (0..PREPROCESSED_COLUMNS)
            .map(|column| PreProcessedColumnId {
                id: format!("ristretto.fp.add.v1.{column}").into(),
            })
            .collect()
    })
    .as_slice()
}

#[derive(Clone, Copy)]
struct FpAddAir {
    log_size: u32,
}

impl FrameworkEval for FpAddAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let one: E::F = M31::from(1u32).into();
        let base: E::F = M31::from(BASE).into();
        let a: Vec<_> = (0..LIMBS).map(|_| eval.next_trace_mask()).collect();
        let b: Vec<_> = (0..LIMBS).map(|_| eval.next_trace_mask()).collect();
        let c: Vec<_> = (0..LIMBS).map(|_| eval.next_trace_mask()).collect();
        let k = eval.next_trace_mask();
        let mut carries = Vec::with_capacity(LIMBS);
        for _ in 0..LIMBS {
            let negative = eval.next_trace_mask();
            let magnitude = eval.next_trace_mask();
            eval.add_constraint(negative.clone() * (negative.clone() - one.clone()));
            eval.add_constraint(magnitude.clone() * (magnitude.clone() - one.clone()));
            let positive = one.clone() - negative.clone();
            carries.push(positive * magnitude.clone() - negative * magnitude);
        }

        eval.add_constraint(k.clone() * (k.clone() - one.clone()));
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
                a[index].clone() + b[index].clone() + carry_in
                    - c[index].clone()
                    - k.clone() * E::F::from(M31::from(u32::from(P_BYTES[index])))
                    - base.clone() * carry_out,
            );
        }

        let ids = preprocessed_ids();
        for (index, value) in a.iter().chain(b.iter()).chain(c.iter()).enumerate() {
            let scope = eval.get_preprocessed_column(ids[index].clone());
            eval.add_constraint(value.clone() - scope);
        }
        let k_scope = eval.get_preprocessed_column(ids[K_OFFSET].clone());
        eval.add_constraint(k - k_scope);
        eval
    }
}

fn mix_scope(
    channel: &mut Poseidon252Channel,
    a: &[u8; LIMBS],
    b: &[u8; LIMBS],
    c: &[u8; LIMBS],
    reduced: bool,
) {
    let mut values = Vec::with_capacity(PREPROCESSED_COLUMNS);
    values.extend(a.iter().map(|limb| u32::from(*limb)));
    values.extend(b.iter().map(|limb| u32::from(*limb)));
    values.extend(c.iter().map(|limb| u32::from(*limb)));
    values.push(u32::from(reduced));
    channel.mix_u32s(&values);
}

/// Prove `a + b = c mod p`, including canonical-range proofs for all operands.
pub fn prove_ristretto_fp_addition(
    a: &[u8; LIMBS],
    b: &[u8; LIMBS],
) -> TexasAirResult<ArchivedRistrettoFpAdditionProof> {
    let (trace, c, reduced) = trace_columns(a, b)?;
    let scope = scope_columns(a, b, &c, u8::from(reduced));
    let config = crate::prover_context::protocol_pcs_config();
    let twiddles =
        crate::prover_context::simd_twiddles(LOG_SIZE + config.fri_config.log_blowup_factor);
    let mut channel = Poseidon252Channel::default();
    mix_scope(&mut channel, a, b, &c, reduced);
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
        FpAddAir { log_size: LOG_SIZE },
        SecureField::from(0u32),
    );
    let stark_proof = prove(&[&component], &mut channel, scheme)
        .map_err(|error| TexasAirError::StwoProverError(error.to_string()))?;
    let stark_proof_bytes = options()
        .serialize(&stark_proof)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
    Ok(ArchivedRistrettoFpAdditionProof {
        a: *a,
        b: *b,
        c,
        reduced,
        canonical: [
            prove_ristretto_fp_canonical(a)?,
            prove_ristretto_fp_canonical(b)?,
            prove_ristretto_fp_canonical(&c)?,
        ],
        addition: ArchivedRistrettoFpAddProof { stark_proof_bytes },
    })
}

/// Verify the canonical operand proofs and the limbwise modular-addition STARK.
pub fn verify_ristretto_fp_addition(
    archive: &ArchivedRistrettoFpAdditionProof,
) -> TexasAirResult<()> {
    let [canonical_a, canonical_b, canonical_c] = &archive.canonical;
    verify_ristretto_fp_canonical(canonical_a)?;
    verify_ristretto_fp_canonical(canonical_b)?;
    verify_ristretto_fp_canonical(canonical_c)?;
    if canonical_a.value != archive.a
        || canonical_b.value != archive.b
        || canonical_c.value != archive.c
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Ristretto addition range proof is detached from public operands".into(),
        ));
    }

    let proof: StarkProof<Poseidon252MerkleHasher> = options()
        .deserialize(&archive.addition.stark_proof_bytes)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
    let scope = scope_columns(
        &archive.a,
        &archive.b,
        &archive.c,
        u8::from(archive.reduced),
    );
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
            "Ristretto addition public scope commitment mismatch".into(),
        ));
    }
    let mut channel = Poseidon252Channel::default();
    mix_scope(
        &mut channel,
        &archive.a,
        &archive.b,
        &archive.c,
        archive.reduced,
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
        FpAddAir { log_size: LOG_SIZE },
        SecureField::from(0u32),
    );
    verify(&[&component], &mut channel, &mut scheme, proof)
        .map_err(|error| TexasAirError::ConstraintUnsatisfied(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;

    fn one() -> [u8; LIMBS] {
        let mut value = [0u8; LIMBS];
        value[0] = 1;
        value
    }

    #[test]
    fn proves_unreduced_and_reduced_additions() {
        let archive = prove_ristretto_fp_addition(&one(), &one()).unwrap();
        assert!(!archive.reduced);
        let mut two = [0u8; LIMBS];
        two[0] = 2;
        assert_eq!(archive.c, two);
        verify_ristretto_fp_addition(&archive).unwrap();

        let mut p_minus_one = P_BYTES;
        p_minus_one[0] -= 1;
        let archive = prove_ristretto_fp_addition(&p_minus_one, &one()).unwrap();
        assert!(archive.reduced);
        assert_eq!(archive.c, [0u8; LIMBS]);
        verify_ristretto_fp_addition(&archive).unwrap();
    }

    #[test]
    fn proves_a_large_reduced_addition_with_signed_borrow_carries() {
        let basepoint = [
            0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71, 0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00,
            0x51, 0x5f, 0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d, 0xb6, 0xa6, 0x59, 0x45,
            0xe0, 0x8d, 0x2d, 0x76,
        ];
        let (trace, expected_c, reduced) = trace_columns(&basepoint, &basepoint).unwrap();
        assert!(reduced);
        let scope = scope_columns(&basepoint, &basepoint, &expected_c, u8::from(reduced));
        let evals = stwo::core::pcs::TreeVec::new(vec![
            scope.cols.iter().collect(),
            trace.cols.iter().collect(),
        ]);
        stwo_constraint_framework::assert_constraints_on_trace(
            &evals,
            LOG_SIZE,
            |eval| {
                FpAddAir { log_size: LOG_SIZE }.evaluate(eval);
            },
            SecureField::from(0u32),
        );

        let archive = prove_ristretto_fp_addition(&basepoint, &basepoint).unwrap();
        assert!(archive.reduced);
        verify_ristretto_fp_addition(&archive).unwrap();
    }

    #[test]
    fn direct_constraints_accept_the_decode_v_addition() {
        let hex_field = |value: &str| {
            let integer = BigUint::parse_bytes(value.as_bytes(), 16)
                .expect("test field is valid hexadecimal");
            let mut out = [0u8; LIMBS];
            let bytes = integer.to_bytes_le();
            out[..bytes.len()].copy_from_slice(&bytes);
            out
        };
        let a = hex_field("4267ce3d248704a8907783d7d9ec8a5b7cebfc62adcc6255a0f57a06954eeb13");
        let b = hex_field("5eaecdeee27cab34adc7a0b9235d48e2bbf095ae14b2edf87e94e1fec82b7d5c");
        let (trace, c, reduced) = trace_columns(&a, &b).unwrap();
        assert!(reduced);
        let scope = scope_columns(&a, &b, &c, u8::from(reduced));
        let evals = stwo::core::pcs::TreeVec::new(vec![
            scope.cols.iter().collect(),
            trace.cols.iter().collect(),
        ]);
        stwo_constraint_framework::assert_constraints_on_trace(
            &evals,
            LOG_SIZE,
            |eval| {
                FpAddAir { log_size: LOG_SIZE }.evaluate(eval);
            },
            SecureField::from(0u32),
        );
    }

    #[test]
    fn verifier_rejects_public_operand_splice() {
        let archive = prove_ristretto_fp_addition(&one(), &one()).unwrap();
        let mut forged = archive;
        forged.a[0] ^= 1;
        assert!(verify_ristretto_fp_addition(&forged).is_err());
    }

    #[test]
    fn direct_constraints_reject_a_forged_output_limb() {
        let (mut trace, c, reduced) = trace_columns(&one(), &one()).unwrap();
        trace.cols[C_OFFSET][0] += M31::from(1u32);
        let scope = scope_columns(&one(), &one(), &c, u8::from(reduced));
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
                        FpAddAir { log_size: LOG_SIZE }.evaluate(eval);
                    },
                    SecureField::from(0u32),
                );
            }))
            .is_err()
        );
    }
}
