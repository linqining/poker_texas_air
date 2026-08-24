//! Canonical Ristretto255 scalar addition modulo the group order `l`.
//!
//! This is deliberately separate from the Ristretto base-field (`p`) addition
//! AIR.  Sigma challenge shares and responses are scalars modulo the prime
//! order `l`, not field elements modulo `2^255 - 19`.

#![allow(missing_docs)]

use bincode::Options;
use borsh::{BorshDeserialize, BorshSerialize};
use stwo::core::channel::{Channel, Poseidon252Channel};
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::SecureField;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::poseidon252_merkle::{
    Poseidon252MerkleChannel, Poseidon252MerkleHasher,
};
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::pcs::CommitmentSchemeProver;
use stwo::prover::prove;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
};

use crate::error::{TexasAirError, TexasAirResult};
use crate::ristretto_scalar_air::{
    GROUP_ORDER_BYTES, prove_ristretto_scalar_canonical, verify_ristretto_scalar_canonical,
};
use crate::trace_gen::MethodTrace;

const LIMBS: usize = 32;
const BASE: u32 = 256;
const LOG_SIZE: u32 = 1;
const A_OFFSET: usize = 0;
const B_OFFSET: usize = A_OFFSET + LIMBS;
const C_OFFSET: usize = B_OFFSET + LIMBS;
const K_OFFSET: usize = C_OFFSET + LIMBS;
const CARRY_OFFSET: usize = K_OFFSET + 1;
const NUM_COLUMNS: usize = CARRY_OFFSET + LIMBS * 2;
const PREPROCESSED_COLUMNS: usize = K_OFFSET + 1;

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoScalarAdditionProof {
    pub a: [u8; LIMBS],
    pub b: [u8; LIMBS],
    pub c: [u8; LIMBS],
    pub reduced: bool,
    pub canonical: [crate::ristretto_scalar_air::ArchivedRistrettoScalarCanonicalProof; 3],
    pub stark_proof_bytes: Vec<u8>,
}

fn options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(16 * 1024 * 1024)
}

fn add_witness(
    a: &[u8; LIMBS],
    b: &[u8; LIMBS],
) -> TexasAirResult<([u8; LIMBS], bool, [i8; LIMBS])> {
    let mut c = [0u8; LIMBS];
    let mut carry = 0u16;
    let mut raw = [0u16; LIMBS + 1];
    for i in 0..LIMBS {
        let sum = u16::from(a[i]) + u16::from(b[i]) + carry;
        raw[i] = sum & 0xff;
        carry = sum >> 8;
    }
    raw[LIMBS] = carry;
    let reduced = if raw[LIMBS] != 0 {
        true
    } else {
        raw[..LIMBS]
            .iter()
            .zip(GROUP_ORDER_BYTES.iter())
            .rev()
            .find_map(|(x, modulus)| {
                (*x != u16::from(*modulus)).then_some(*x > u16::from(*modulus))
            })
            .unwrap_or(true)
    };
    let mut borrow = false;
    if reduced {
        for i in 0..LIMBS {
            let mut modulus = u16::from(GROUP_ORDER_BYTES[i]);
            if borrow {
                modulus += 1;
            }
            let value = raw[i];
            if value >= modulus {
                c[i] = u8::try_from(value - modulus).expect("scalar reduction limb fits");
                borrow = false;
            } else {
                c[i] = u8::try_from(value + 256 - modulus).expect("scalar reduction limb fits");
                borrow = true;
            }
        }
        if borrow || raw[LIMBS] != 0 {
            // The final borrow is expected to be consumed by the high carry.
            // A two-limb subtraction is represented by the same modular result.
        }
    } else {
        for i in 0..LIMBS {
            c[i] = u8::try_from(raw[i]).expect("scalar raw limb fits");
        }
    }

    let k = u8::from(reduced);
    let mut signed = [0i8; LIMBS];
    let mut carry_in: i64 = 0;
    for i in 0..LIMBS {
        let value = i64::from(a[i]) + i64::from(b[i]) + carry_in
            - i64::from(c[i])
            - i64::from(GROUP_ORDER_BYTES[i]) * i64::from(k);
        carry_in = value.div_euclid(i64::from(BASE));
        if !(-1..=1).contains(&carry_in) {
            return Err(TexasAirError::SpecViolation(
                "scalar-addition carry is outside signed one-bit range".into(),
            ));
        }
        signed[i] = i8::try_from(carry_in).expect("signed scalar carry fits");
    }
    if carry_in != 0 {
        return Err(TexasAirError::SpecViolation(
            "scalar-addition final carry does not close".into(),
        ));
    }
    Ok((c, reduced, signed))
}

fn trace_columns(
    a: &[u8; LIMBS],
    b: &[u8; LIMBS],
) -> TexasAirResult<(MethodTrace, [u8; LIMBS], bool)> {
    let (c, reduced, carries) = add_witness(a, b)?;
    let mut row = Vec::with_capacity(NUM_COLUMNS);
    row.extend(a.iter().map(|v| M31::from(u32::from(*v))));
    row.extend(b.iter().map(|v| M31::from(u32::from(*v))));
    row.extend(c.iter().map(|v| M31::from(u32::from(*v))));
    row.push(M31::from(u32::from(reduced)));
    for carry in carries {
        row.push(M31::from(u32::from(carry < 0)));
        row.push(M31::from(u32::from(carry != 0)));
    }
    let mut trace = MethodTrace::new(LOG_SIZE, NUM_COLUMNS);
    trace.write_row(0, &row)?;
    trace.write_row(1, &row)?;
    Ok((trace, c, reduced))
}

fn scope_columns(a: &[u8; LIMBS], b: &[u8; LIMBS], c: &[u8; LIMBS], reduced: bool) -> MethodTrace {
    let mut trace = MethodTrace::new(LOG_SIZE, PREPROCESSED_COLUMNS);
    let mut row = Vec::with_capacity(PREPROCESSED_COLUMNS);
    row.extend(a.iter().map(|v| M31::from(u32::from(*v))));
    row.extend(b.iter().map(|v| M31::from(u32::from(*v))));
    row.extend(c.iter().map(|v| M31::from(u32::from(*v))));
    row.push(M31::from(u32::from(reduced)));
    trace
        .write_row(0, &row)
        .expect("fixed scalar-add scope width");
    trace
        .write_row(1, &row)
        .expect("fixed scalar-add scope width");
    trace
}

fn preprocessed_ids() -> Vec<PreProcessedColumnId> {
    (0..PREPROCESSED_COLUMNS)
        .map(|i| PreProcessedColumnId {
            id: format!("ristretto.scalar.add.v1.{i}").into(),
        })
        .collect()
}

#[derive(Clone, Copy)]
struct ScalarAddAir {
    log_size: u32,
}

impl FrameworkEval for ScalarAddAir {
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
        eval.add_constraint(k.clone() * (k.clone() - one.clone()));
        let mut carries = Vec::with_capacity(LIMBS);
        for _ in 0..LIMBS {
            let negative = eval.next_trace_mask();
            let magnitude = eval.next_trace_mask();
            eval.add_constraint(negative.clone() * (negative.clone() - one.clone()));
            eval.add_constraint(magnitude.clone() * (magnitude.clone() - one.clone()));
            carries
                .push((one.clone() - negative.clone()) * magnitude.clone() - negative * magnitude);
        }
        for i in 0..LIMBS {
            let carry_in = if i == 0 {
                M31::from(0u32).into()
            } else {
                carries[i - 1].clone()
            };
            let carry_out = if i + 1 == LIMBS {
                M31::from(0u32).into()
            } else {
                carries[i].clone()
            };
            eval.add_constraint(
                a[i].clone() + b[i].clone() + carry_in
                    - c[i].clone()
                    - k.clone() * E::F::from(M31::from(u32::from(GROUP_ORDER_BYTES[i])))
                    - base.clone() * carry_out,
            );
        }
        let ids = preprocessed_ids();
        for (i, value) in a.iter().chain(b.iter()).chain(c.iter()).enumerate() {
            let scope = eval.get_preprocessed_column(ids[i].clone());
            eval.add_constraint(value.clone() - scope);
        }
        let k_scope = eval.get_preprocessed_column(ids[K_OFFSET].clone());
        eval.add_constraint(k - k_scope);
        eval
    }
}

fn mix_scope(
    channel: &mut impl Channel,
    a: &[u8; LIMBS],
    b: &[u8; LIMBS],
    c: &[u8; LIMBS],
    reduced: bool,
) {
    channel.mix_u32s(
        &a.iter()
            .chain(b)
            .chain(c)
            .map(|v| u32::from(*v))
            .collect::<Vec<_>>(),
    );
    channel.mix_u32s(&[u32::from(reduced)]);
}

pub fn prove_ristretto_scalar_addition(
    a: &[u8; LIMBS],
    b: &[u8; LIMBS],
) -> TexasAirResult<ArchivedRistrettoScalarAdditionProof> {
    let (trace, c, reduced) = trace_columns(a, b)?;
    let scope = scope_columns(a, b, &c, reduced);
    let canonical = [
        prove_ristretto_scalar_canonical(a)?,
        prove_ristretto_scalar_canonical(b)?,
        prove_ristretto_scalar_canonical(&c)?,
    ];
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
        ScalarAddAir { log_size: LOG_SIZE },
        SecureField::from(0u32),
    );
    let proof = prove(&[&component], &mut channel, scheme)
        .map_err(|e| TexasAirError::StwoProverError(e.to_string()))?;
    let stark_proof_bytes = options()
        .serialize(&proof)
        .map_err(|e| TexasAirError::SerializationError(e.to_string()))?;
    Ok(ArchivedRistrettoScalarAdditionProof {
        a: *a,
        b: *b,
        c,
        reduced,
        canonical,
        stark_proof_bytes,
    })
}

pub fn verify_ristretto_scalar_addition(
    archive: &ArchivedRistrettoScalarAdditionProof,
) -> TexasAirResult<()> {    for (proof, expected) in archive
        .canonical
        .iter()
        .zip([archive.a, archive.b, archive.c])
    {
        verify_ristretto_scalar_canonical(proof)?;
        if proof.value != expected {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "scalar-add canonical proof detached".into(),
            ));
        }
    }
    type Proof = StarkProof<Poseidon252MerkleHasher>;
    let proof: Proof = options()
        .deserialize(&archive.stark_proof_bytes)
        .map_err(|e| TexasAirError::SerializationError(e.to_string()))?;
    let scope = scope_columns(&archive.a, &archive.b, &archive.c, archive.reduced);
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
            "scalar-add scope commitment mismatch".into(),
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
        ScalarAddAir { log_size: LOG_SIZE },
        SecureField::from(0u32),
    );
    stwo::core::verifier::verify(&[&component], &mut channel, &mut scheme, proof)
        .map_err(|e| TexasAirError::ConstraintUnsatisfied(e.to_string()))
}

/// One row of a batched scalar-addition archive.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoScalarAdditionRow {
    pub a: [u8; LIMBS],
    pub b: [u8; LIMBS],
    pub c: [u8; LIMBS],
    pub reduced: bool,
    /// Independent strict `value < l` proof for each operand and the sum.
    pub canonical: [crate::ristretto_scalar_air::ArchivedRistrettoScalarCanonicalProof; 3],
}

/// Many scalar additions proven as rows of one STARK.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoScalarAdditionBatchProof {
    /// Public `(a, b, c, reduced)` triples in canonical row order.
    pub rows: Vec<ArchivedRistrettoScalarAdditionRow>,
    /// Serialized Stwo proof for the complete batch.
    pub stark_proof_bytes: Vec<u8>,
}

fn batch_log_size(row_count: usize) -> u32 {
    row_count.max(2).next_power_of_two().ilog2()
}

fn trace_columns_batch(inputs: &[([u8; LIMBS], [u8; LIMBS])]) -> TexasAirResult<MethodTrace> {
    let log_size = batch_log_size(inputs.len());
    let rows = 1usize << log_size;
    let mut trace = MethodTrace::new(log_size, NUM_COLUMNS);
    for row_index in 0..rows {
        let source = row_index.min(inputs.len() - 1);
        let (a, b) = inputs[source];
        let (c, reduced, carries) = add_witness(&a, &b)?;
        let mut row = Vec::with_capacity(NUM_COLUMNS);
        row.extend(a.iter().map(|v| M31::from(u32::from(*v))));
        row.extend(b.iter().map(|v| M31::from(u32::from(*v))));
        row.extend(c.iter().map(|v| M31::from(u32::from(*v))));
        row.push(M31::from(u32::from(reduced)));
        for carry in carries {
            row.push(M31::from(u32::from(carry < 0)));
            row.push(M31::from(u32::from(carry != 0)));
        }
        trace.write_row(row_index, &row)?;
    }
    Ok(trace)
}

fn scope_columns_batch(rows: &[ArchivedRistrettoScalarAdditionRow]) -> MethodTrace {
    let log_size = batch_log_size(rows.len());
    let domain_rows = 1usize << log_size;
    let mut trace = MethodTrace::new(log_size, PREPROCESSED_COLUMNS);
    for row_index in 0..domain_rows {
        let source = &rows[row_index.min(rows.len() - 1)];
        let mut row = Vec::with_capacity(PREPROCESSED_COLUMNS);
        row.extend(source.a.iter().map(|v| M31::from(u32::from(*v))));
        row.extend(source.b.iter().map(|v| M31::from(u32::from(*v))));
        row.extend(source.c.iter().map(|v| M31::from(u32::from(*v))));
        row.push(M31::from(u32::from(source.reduced)));
        trace
            .write_row(row_index, &row)
            .expect("fixed scalar-add scope width");
    }
    trace
}

fn mix_scope_batch(
    channel: &mut impl Channel,
    rows: &[ArchivedRistrettoScalarAdditionRow],
) {
    channel.mix_u64(0x7363_616c_6164_6462);
    channel.mix_u64(rows.len() as u64);
    for row in rows {
        mix_scope(channel, &row.a, &row.b, &row.c, row.reduced);
    }
}

/// Prove many scalar additions as rows of one STARK.
pub fn prove_ristretto_scalar_addition_batch(
    inputs: &[([u8; LIMBS], [u8; LIMBS])],
) -> TexasAirResult<ArchivedRistrettoScalarAdditionBatchProof> {
    if inputs.is_empty() {
        return Err(TexasAirError::SpecViolation(
            "scalar-addition batch cannot be empty".into(),
        ));
    }
    let log_size = batch_log_size(inputs.len());
    let trace = trace_columns_batch(inputs)?;
    let rows = inputs
        .iter()
        .map(|(a, b)| {
            let (c, reduced, _) = add_witness(a, b)?;
            let canonical = [
                prove_ristretto_scalar_canonical(a)?,
                prove_ristretto_scalar_canonical(b)?,
                prove_ristretto_scalar_canonical(&c)?,
            ];
            Ok(ArchivedRistrettoScalarAdditionRow {
                a: *a,
                b: *b,
                c,
                reduced,
                canonical,
            })
        })
        .collect::<TexasAirResult<Vec<_>>>()?;
    let scope = scope_columns_batch(&rows);
    let config = crate::prover_context::protocol_pcs_config();
    let twiddles =
        crate::prover_context::simd_twiddles(log_size + config.fri_config.log_blowup_factor);
    let mut channel = Poseidon252Channel::default();
    mix_scope_batch(&mut channel, &rows);
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
        ScalarAddAir { log_size },
        SecureField::from(0u32),
    );
    let proof = prove(&[&component], &mut channel, scheme)
        .map_err(|e| TexasAirError::StwoProverError(e.to_string()))?;
    let stark_proof_bytes = options()
        .serialize(&proof)
        .map_err(|e| TexasAirError::SerializationError(e.to_string()))?;
    Ok(ArchivedRistrettoScalarAdditionBatchProof {
        rows,
        stark_proof_bytes,
    })
}

/// Verify a batched scalar-addition archive.
pub fn verify_ristretto_scalar_addition_batch(
    archive: &ArchivedRistrettoScalarAdditionBatchProof,
) -> TexasAirResult<()> {
    if archive.rows.is_empty() {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "scalar-addition batch cannot be empty".into(),
        ));
    }
    for row in &archive.rows {
        for (proof, expected) in row.canonical.iter().zip([row.a, row.b, row.c]) {
            verify_ristretto_scalar_canonical(proof)?;
            if proof.value != expected {
                return Err(TexasAirError::ConstraintUnsatisfied(
                    "scalar-add canonical proof detached".into(),
                ));
            }
        }
    }
    type Proof = StarkProof<Poseidon252MerkleHasher>;
    let proof: Proof = options()
        .deserialize(&archive.stark_proof_bytes)
        .map_err(|e| TexasAirError::SerializationError(e.to_string()))?;
    let log_size = batch_log_size(archive.rows.len());
    let scope = scope_columns_batch(&archive.rows);
    let config = crate::prover_context::protocol_pcs_config();
    let twiddles =
        crate::prover_context::simd_twiddles(log_size + config.fri_config.log_blowup_factor);
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
            "scalar-addition batch scope commitment mismatch".into(),
        ));
    }
    let mut channel = Poseidon252Channel::default();
    mix_scope_batch(&mut channel, &archive.rows);
    let mut scheme =
        stwo::core::pcs::CommitmentSchemeVerifier::<Poseidon252MerkleChannel>::new(config);
    scheme.commit(
        proof.commitments[0],
        &vec![log_size; PREPROCESSED_COLUMNS],
        &mut channel,
    );
    scheme.commit(proof.commitments[1], &vec![log_size; NUM_COLUMNS], &mut channel);
    let ids = preprocessed_ids();
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
    let component = FrameworkComponent::new(
        &mut allocator,
        ScalarAddAir { log_size },
        SecureField::from(0u32),
    );
    stwo::core::verifier::verify(&[&component], &mut channel, &mut scheme, proof)
        .map_err(|e| TexasAirError::ConstraintUnsatisfied(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn proves_reduced_and_unreduced_scalar_addition() {
        let mut one = [0u8; LIMBS];
        one[0] = 1;
        let archive = prove_ristretto_scalar_addition(&one, &one).unwrap();
        assert!(!archive.reduced);
        assert_eq!(archive.c[0], 2);
        verify_ristretto_scalar_addition(&archive).unwrap();
        let mut max = GROUP_ORDER_BYTES;
        max[0] -= 1;
        let archive = prove_ristretto_scalar_addition(&max, &one).unwrap();
        assert!(archive.reduced);
        assert_eq!(archive.c, [0; LIMBS]);
        verify_ristretto_scalar_addition(&archive).unwrap();
    }

    #[test]
    fn batch_proves_and_rejects_row_splices() {
        let mut one = [0u8; LIMBS];
        one[0] = 1;
        let mut two = [0u8; LIMBS];
        two[0] = 2;
        let mut max = GROUP_ORDER_BYTES;
        max[0] -= 1;
        let archive =
            prove_ristretto_scalar_addition_batch(&[(one, one), (max, one), (two, max)]).unwrap();
        assert_eq!(archive.rows.len(), 3);
        assert!(!archive.rows[0].reduced);
        assert!(archive.rows[1].reduced);
        verify_ristretto_scalar_addition_batch(&archive).unwrap();

        let mut spliced = archive.clone();
        spliced.rows[2].c = [0u8; LIMBS];
        assert!(verify_ristretto_scalar_addition_batch(&spliced).is_err());
    }
}
