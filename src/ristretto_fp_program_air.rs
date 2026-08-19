//! Single-STARK Ristretto255 field-arithmetic program AIR.
//!
//! A program commits all canonical Fp values and a fixed list of add/sub/mul
//! operations.  Unlike composing one STARK per field operation, this module
//! places every canonical-limb witness and arithmetic relation in one trace and
//! creates one proof.  It is the folding substrate for the production point
//! codec, Edwards arithmetic, scalar multiplication, and later DLEQ/MSM AIRs.

use bincode::Options;
use borsh::{BorshDeserialize, BorshSerialize};
use num_bigint::BigUint;
use num_traits::{One, Zero};
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
const PRODUCT_LIMBS: usize = 2 * LIMBS;
const BASE: u32 = 256;
const LOG_SIZE: u32 = 1;
const MAX_VALUES: usize = 512;
const MAX_OPS: usize = 512;
const MAX_OUTPUTS: usize = 64;

const P_BYTES: [u8; LIMBS] = {
    let mut bytes = [0xffu8; LIMBS];
    bytes[0] = 0xed;
    bytes[31] = 0x7f;
    bytes
};

const ONE_BYTES: [u8; LIMBS] = {
    let mut bytes = [0u8; LIMBS];
    bytes[0] = 1;
    bytes
};

const ZERO_BYTES: [u8; LIMBS] = [0u8; LIMBS];

/// Edwards `d` as a positive decimal residue; the curve constant is negative.
const EDWARDS_D_BYTES: [u8; LIMBS] = [
    0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x09,
    0x8e, 0x87, 0x97, 0x77, 0x94, 0x0c, 0x78, 0xc7, 0x3f, 0xe6, 0xf2, 0xbe, 0xe6, 0xc0, 0x35, 0x2a,
];

/// Nonnegative `sqrt(-1)` in the Ristretto255 field.
const SQRT_M1_BYTES: [u8; LIMBS] = [
    0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4, 0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
    0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b, 0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b,
];

/// One field operation in the public program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum RistrettoFpProgramOp {
    /// `values[a] + values[b] = values[out]`.
    Add {
        /// Left value index.
        a: u16,
        /// Right value index.
        b: u16,
        /// Output value index.
        out: u16,
    },
    /// `values[a] - values[b] = values[out]`.
    Subtract {
        /// Left value index.
        a: u16,
        /// Right value index.
        b: u16,
        /// Output value index.
        out: u16,
    },
    /// `values[a] * values[b] = values[out] + values[q] * p`.
    Multiply {
        /// Left value index.
        a: u16,
        /// Right value index.
        b: u16,
        /// Output value index.
        out: u16,
        /// Quotient value index.
        q: u16,
    },
}

/// Public canonical values, operations, and declared outputs.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RistrettoFpProgram {
    /// All canonical little-endian field values in column order.
    pub values: Vec<[u8; LIMBS]>,
    /// Arithmetic operations.
    pub ops: Vec<RistrettoFpProgramOp>,
    /// Public output value indices.
    pub outputs: Vec<u16>,
}

/// Serialized single-STARK field-program proof.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoFpProgramProof {
    /// Authenticated program statement.
    pub program: RistrettoFpProgram,
    /// Serialized Stwo proof.
    pub stark_proof_bytes: Vec<u8>,
}

/// Public `sqrt_ratio_i` statement proven by one field-program STARK.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoFpProgramSqrtRatioProof {
    /// Canonical numerator.
    pub u: [u8; LIMBS],
    /// Canonical denominator.
    pub v: [u8; LIMBS],
    /// Canonical nonnegative root.
    pub r: [u8; LIMBS],
    /// Verified `r*r*v`.
    pub check: [u8; LIMBS],
    /// Verified `sqrt(-1)*u`.
    pub i_times_u: [u8; LIMBS],
    /// True iff the result is `sqrt(u/v)`.
    pub was_square: bool,
    /// One-STARK field-program proof.
    pub program: ArchivedRistrettoFpProgramProof,
}

/// Public Ristretto point-decode statement proven by one field-program STARK.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoFpProgramPointDecodeProof {
    /// Canonical nonnegative 32-byte encoding.
    pub encoding: [u8; LIMBS],
    /// Authenticated nonnegative inverse-square-root witness.
    pub inverse_sqrt: [u8; LIMBS],
    /// Nonnegative selected extended coordinate `X`.
    pub x: [u8; LIMBS],
    /// Nonzero extended coordinate `Y`.
    pub y: [u8; LIMBS],
    /// Nonnegative extended coordinate `T`.
    pub t: [u8; LIMBS],
    /// One-STARK decode program.
    pub program: ArchivedRistrettoFpProgramProof,
}

/// Incremental host-side program builder.
#[derive(Debug, Default)]
pub struct RistrettoFpProgramBuilder {
    values: Vec<[u8; LIMBS]>,
    ops: Vec<RistrettoFpProgramOp>,
}

impl RistrettoFpProgramBuilder {
    /// Create a program from canonical public input values.
    #[must_use]
    pub fn new(inputs: &[[u8; LIMBS]]) -> Self {
        Self {
            values: inputs.to_vec(),
            ops: Vec::new(),
        }
    }

    /// Append a canonical constant and return its index.
    pub fn constant(&mut self, value: &[u8; LIMBS]) -> TexasAirResult<u16> {
        self.push_value(*value)
    }

    /// Append `a+b`.
    pub fn add(&mut self, a: u16, b: u16) -> TexasAirResult<u16> {
        let out_value = add_big(&big_uint(&self.value(a)?), &big_uint(&self.value(b)?));
        let out = self.push_value(limbs(&out_value))?;
        self.ops.push(RistrettoFpProgramOp::Add { a, b, out });
        Ok(out)
    }

    /// Append `a-b`.
    pub fn subtract(&mut self, a: u16, b: u16) -> TexasAirResult<u16> {
        let out_value = subtract_big(&big_uint(&self.value(a)?), &big_uint(&self.value(b)?));
        let out = self.push_value(limbs(&out_value))?;
        self.ops.push(RistrettoFpProgramOp::Subtract { a, b, out });
        Ok(out)
    }

    /// Append `a*b`, including the committed quotient value.
    pub fn multiply(&mut self, a: u16, b: u16) -> TexasAirResult<u16> {
        let product = big_uint(&self.value(a)?) * big_uint(&self.value(b)?);
        let quotient = &product / modulus();
        let remainder = &product % modulus();
        let q = self.push_value(limbs(&quotient))?;
        let out = self.push_value(limbs(&remainder))?;
        self.ops
            .push(RistrettoFpProgramOp::Multiply { a, b, out, q });
        Ok(out)
    }

    /// Finalize with public output indices.
    pub fn finish(self, outputs: &[u16]) -> TexasAirResult<RistrettoFpProgram> {
        validate_indices(self.values.len(), self.ops.len(), outputs)?;
        Ok(RistrettoFpProgram {
            values: self.values,
            ops: self.ops,
            outputs: outputs.to_vec(),
        })
    }

    fn value(&self, index: u16) -> TexasAirResult<[u8; LIMBS]> {
        self.values
            .get(usize::from(index))
            .copied()
            .ok_or_else(|| TexasAirError::SpecViolation("Fp program index is out of bounds".into()))
    }

    fn push_value(&mut self, value: [u8; LIMBS]) -> TexasAirResult<u16> {
        if self.values.len() >= MAX_VALUES {
            return Err(TexasAirError::SpecViolation(
                "Fp program exceeds its maximum value count".into(),
            ));
        }
        if big_uint(&value) >= modulus() {
            return Err(TexasAirError::SpecViolation(
                "Fp program value is noncanonical".into(),
            ));
        }
        self.values.push(value);
        Ok(u16::try_from(self.values.len() - 1).expect("MAX_VALUES fits in u16"))
    }
}

#[derive(Clone, Copy)]
struct SignedMagnitude {
    negative: bool,
    magnitude: u16,
}

#[derive(Clone)]
enum OpWitness {
    Add {
        subtract: bool,
        k: SignedMagnitude,
        carries: Vec<SignedMagnitude>,
    },
    Multiply {
        carries: Vec<SignedMagnitude>,
    },
}

#[derive(Clone)]
struct ProgramWitness {
    differences: Vec<[u8; LIMBS]>,
    op_witnesses: Vec<OpWitness>,
}

#[derive(Clone)]
struct FpProgramAir {
    log_size: u32,
    program: RistrettoFpProgram,
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

fn add_big(left: &BigUint, right: &BigUint) -> BigUint {
    (left + right) % modulus()
}

fn subtract_big(left: &BigUint, right: &BigUint) -> BigUint {
    if left >= right {
        left - right
    } else {
        left + modulus() - right
    }
}

fn multiply_big(left: &BigUint, right: &BigUint) -> BigUint {
    left * right % modulus()
}

fn options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(64 * 1024 * 1024)
}

fn validate_indices(value_count: usize, op_count: usize, outputs: &[u16]) -> TexasAirResult<()> {
    if value_count == 0
        || value_count > MAX_VALUES
        || op_count > MAX_OPS
        || outputs.is_empty()
        || outputs.len() > MAX_OUTPUTS
    {
        return Err(TexasAirError::SpecViolation(
            "Fp program size is outside its committed limits".into(),
        ));
    }
    if outputs
        .iter()
        .any(|index| usize::from(*index) >= value_count)
    {
        return Err(TexasAirError::SpecViolation(
            "Fp program output index is out of bounds".into(),
        ));
    }
    Ok(())
}

fn prime_minus(value: &[u8; LIMBS]) -> TexasAirResult<[u8; LIMBS]> {
    Ok(limbs(&(&modulus() - big_uint(value))))
}

fn program_witness(program: &RistrettoFpProgram) -> TexasAirResult<ProgramWitness> {
    validate_indices(program.values.len(), program.ops.len(), &program.outputs)?;
    let mut differences = Vec::with_capacity(program.values.len());
    for value in &program.values {
        if big_uint(value) >= modulus() {
            return Err(TexasAirError::SpecViolation(
                "Fp program value is noncanonical".into(),
            ));
        }
        differences.push(prime_minus(value)?);
    }

    let mut op_witnesses = Vec::with_capacity(program.ops.len());
    for op in &program.ops {
        match *op {
            RistrettoFpProgramOp::Add { a, b, out }
            | RistrettoFpProgramOp::Subtract { a, b, out } => {
                let subtract = matches!(op, RistrettoFpProgramOp::Subtract { .. });
                let a_value = program.values.get(usize::from(a)).ok_or_else(|| {
                    TexasAirError::SpecViolation("Fp program operand is out of bounds".into())
                })?;
                let b_value = program.values.get(usize::from(b)).ok_or_else(|| {
                    TexasAirError::SpecViolation("Fp program operand is out of bounds".into())
                })?;
                let out_value = program.values.get(usize::from(out)).ok_or_else(|| {
                    TexasAirError::SpecViolation("Fp program output is out of bounds".into())
                })?;
                let expected = if subtract {
                    subtract_big(&big_uint(a_value), &big_uint(b_value))
                } else {
                    add_big(&big_uint(a_value), &big_uint(b_value))
                };
                if limbs(&expected) != *out_value {
                    return Err(TexasAirError::SpecViolation(
                        "Fp program addition/subtraction relation is invalid".into(),
                    ));
                }

                let a_int = big_uint(a_value);
                let b_int = big_uint(b_value);
                let (k_negative, k_magnitude) = if subtract {
                    (a_int < b_int, a_int < b_int)
                } else {
                    (false, a_int + b_int >= modulus())
                };
                let mut carry_in: i64 = 0;
                let mut carries = Vec::with_capacity(LIMBS);
                for index in 0..LIMBS {
                    let signed_b = if subtract {
                        -i64::from(b_value[index])
                    } else {
                        i64::from(b_value[index])
                    };
                    let signed_k = if k_negative && k_magnitude {
                        -1i64
                    } else if !k_negative && k_magnitude {
                        1
                    } else {
                        0
                    };
                    let difference = i64::from(a_value[index]) + signed_b + carry_in
                        - i64::from(out_value[index])
                        - signed_k * i64::from(P_BYTES[index]);
                    let carry_out = difference.div_euclid(i64::from(BASE));
                    if !(-1..=1).contains(&carry_out) {
                        return Err(TexasAirError::SpecViolation(
                            "Fp program carry witness is outside {-1,0,1}".into(),
                        ));
                    }
                    carries.push(SignedMagnitude {
                        negative: carry_out < 0,
                        magnitude: u16::try_from(carry_out.unsigned_abs())
                            .expect("program carry magnitude is boolean"),
                    });
                    carry_in = carry_out;
                }
                if carry_in != 0 {
                    return Err(TexasAirError::SpecViolation(
                        "Fp program carry chain is nonterminal".into(),
                    ));
                }
                op_witnesses.push(OpWitness::Add {
                    subtract,
                    k: SignedMagnitude {
                        negative: k_negative,
                        magnitude: u16::from(k_magnitude),
                    },
                    carries,
                });
            }
            RistrettoFpProgramOp::Multiply { a, b, out, q } => {
                let a_value = program.values.get(usize::from(a)).ok_or_else(|| {
                    TexasAirError::SpecViolation("Fp program operand is out of bounds".into())
                })?;
                let b_value = program.values.get(usize::from(b)).ok_or_else(|| {
                    TexasAirError::SpecViolation("Fp program operand is out of bounds".into())
                })?;
                let out_value = program.values.get(usize::from(out)).ok_or_else(|| {
                    TexasAirError::SpecViolation("Fp program output is out of bounds".into())
                })?;
                let q_value = program.values.get(usize::from(q)).ok_or_else(|| {
                    TexasAirError::SpecViolation("Fp program quotient is out of bounds".into())
                })?;
                let product = &big_uint(a_value) * &big_uint(b_value);
                let expected_q = &product / modulus();
                let expected_out = &product % modulus();
                if limbs(&expected_q) != *q_value || limbs(&expected_out) != *out_value {
                    return Err(TexasAirError::SpecViolation(
                        "Fp program multiplication relation is invalid".into(),
                    ));
                }

                let product_limbs = convolution(a_value, b_value);
                let quotient_prime_limbs = convolution(q_value, &P_BYTES);
                let mut carry_in: i64 = 0;
                let mut carries = Vec::with_capacity(PRODUCT_LIMBS - 1);
                for limb_index in 0..PRODUCT_LIMBS {
                    let output_limb = if limb_index < LIMBS {
                        i64::from(out_value[limb_index])
                    } else {
                        0
                    };
                    let difference =
                        product_limbs[limb_index] - quotient_prime_limbs[limb_index] - output_limb
                            + carry_in;
                    let carry_out = difference.div_euclid(i64::from(BASE));
                    if limb_index + 1 == PRODUCT_LIMBS {
                        if carry_out != 0 {
                            return Err(TexasAirError::SpecViolation(
                                "Fp multiplication final carry is nonzero".into(),
                            ));
                        }
                    } else {
                        if carry_out.unsigned_abs() > u16::MAX as u64 {
                            return Err(TexasAirError::SpecViolation(
                                "Fp multiplication carry does not fit in 16 bits".into(),
                            ));
                        }
                        carries.push(SignedMagnitude {
                            negative: carry_out < 0,
                            magnitude: carry_out.unsigned_abs() as u16,
                        });
                        carry_in = carry_out;
                    }
                }
                op_witnesses.push(OpWitness::Multiply { carries });
            }
        }
    }
    Ok(ProgramWitness {
        differences,
        op_witnesses,
    })
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

fn sqrt_m1() -> BigUint {
    BigUint::from(2u32).modpow(&((&modulus() - BigUint::one()) >> 2u32), &modulus())
}

fn nonnegative_sqrt(value: &BigUint) -> Option<BigUint> {
    if value.is_zero() {
        return Some(BigUint::from(0u32));
    }
    let p = modulus();
    let mut root = value.modpow(&((&p + BigUint::from(3u32)) >> 3u32), &p);
    if multiply_big(&root, &root) != *value {
        root = multiply_big(&root, &sqrt_m1());
    }
    if multiply_big(&root, &root) != *value {
        return None;
    }
    Some(if (&root & BigUint::one()) == BigUint::one() {
        &p - root
    } else {
        root
    })
}

fn append_signed_magnitude(row: &mut Vec<M31>, value: SignedMagnitude) {
    row.push(M31::from(u32::from(value.negative)));
    row.push(M31::from(u32::from(value.magnitude)));
    for bit in 0..16 {
        row.push(M31::from(u32::from((value.magnitude >> bit) & 1)));
    }
}

fn append_limb(row: &mut Vec<M31>, limb: u8) {
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

fn trace_columns(program: &RistrettoFpProgram) -> TexasAirResult<MethodTrace> {
    let witness = program_witness(program)?;
    let mut row = Vec::new();
    for (value, difference) in program.values.iter().zip(&witness.differences) {
        for limb in value {
            append_limb(&mut row, *limb);
        }
        for limb in difference {
            append_limb(&mut row, *limb);
        }
        let mut carries = [0u8; LIMBS];
        let mut carry_in = 0u16;
        for index in 0..LIMBS {
            let sum = u16::from(value[index]) + u16::from(difference[index]) + carry_in;
            carries[index] = u8::from(sum >= BASE as u16);
            carry_in = sum >> 8;
        }
        row.push(M31::from(0u32));
        row.extend(
            carries[..LIMBS - 1]
                .iter()
                .map(|carry| M31::from(u32::from(*carry))),
        );
        let mut nonzero_count = 0u32;
        for limb in difference {
            nonzero_count += u32::from(*limb != 0);
            row.push(M31::from(u32::from(*limb != 0)));
            row.push(m31_inverse(*limb));
        }
        row.push(M31::from(nonzero_count).inverse());
    }

    for op_witness in &witness.op_witnesses {
        match op_witness {
            OpWitness::Add {
                subtract,
                k,
                carries,
            } => {
                row.push(M31::from(u32::from(*subtract)));
                row.push(M31::from(u32::from(k.negative)));
                row.push(M31::from(u32::from(k.magnitude)));
                for carry in carries {
                    // Add/sub carries only need sign and one magnitude bit.
                    row.push(M31::from(u32::from(carry.negative)));
                    row.push(M31::from(u32::from(carry.magnitude)));
                }
            }
            OpWitness::Multiply { carries } => {
                for carry in carries {
                    append_signed_magnitude(&mut row, *carry);
                }
            }
        }
    }

    let mut trace = MethodTrace::new(LOG_SIZE, row.len());
    trace.write_row(0, &row)?;
    trace.write_row(1, &row)?;
    Ok(trace)
}

fn scope_columns(program: &RistrettoFpProgram) -> MethodTrace {
    let mut trace = MethodTrace::new(LOG_SIZE, program.values.len() * LIMBS);
    let mut row = Vec::with_capacity(program.values.len() * LIMBS);
    for value in &program.values {
        row.extend(value.iter().map(|limb| M31::from(u32::from(*limb))));
    }
    trace.write_row(0, &row).expect("fixed program scope width");
    trace.write_row(1, &row).expect("fixed program scope width");
    trace
}

fn preprocessed_ids(program: &RistrettoFpProgram) -> Vec<PreProcessedColumnId> {
    (0..program.values.len() * LIMBS)
        .map(|column| PreProcessedColumnId {
            id: format!("ristretto.fp.program.scope.v1.{column}").into(),
        })
        .collect()
}

impl FrameworkEval for FpProgramAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let one: E::F = M31::from(1u32).into();
        let base: E::F = M31::from(BASE).into();
        let ids = preprocessed_ids(&self.program);
        let mut value_limbs = Vec::with_capacity(self.program.values.len());

        for value_index in 0..self.program.values.len() {
            let mut value = Vec::with_capacity(LIMBS);
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
                difference.push(limb);
            }

            let mut carries = Vec::with_capacity(LIMBS);
            for _ in 0..LIMBS {
                let carry = eval.next_trace_mask();
                eval.add_constraint(carry.clone() * (carry.clone() - one.clone()));
                carries.push(carry);
            }
            eval.add_constraint(carries[0].clone());
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

            let mut nonzero_count: E::F = M31::from(0u32).into();
            for index in 0..LIMBS {
                let nonzero = eval.next_trace_mask();
                let inverse = eval.next_trace_mask();
                eval.add_constraint(nonzero.clone() * (nonzero.clone() - one.clone()));
                nonzero_count += nonzero.clone();
                eval.add_constraint(difference[index].clone() * inverse - nonzero);
            }
            let nonzero_inverse = eval.next_trace_mask();
            eval.add_constraint(nonzero_count * nonzero_inverse - one.clone());

            for (limb_index, limb) in value.iter().enumerate() {
                let scope_index = value_index * LIMBS + limb_index;
                let scope = eval.get_preprocessed_column(ids[scope_index].clone());
                eval.add_constraint(limb.clone() - scope);
            }
            value_limbs.push(value);
        }

        for op in &self.program.ops {
            match *op {
                RistrettoFpProgramOp::Add { a, b, out }
                | RistrettoFpProgramOp::Subtract { a, b, out } => {
                    let subtract = eval.next_trace_mask();
                    eval.add_constraint(subtract.clone() * (subtract.clone() - one.clone()));
                    let k_negative = eval.next_trace_mask();
                    let k_magnitude = eval.next_trace_mask();
                    eval.add_constraint(k_negative.clone() * (k_negative.clone() - one.clone()));
                    eval.add_constraint(k_magnitude.clone() * (k_magnitude.clone() - one.clone()));
                    let positive = one.clone() - k_negative.clone();
                    let signed_k = positive * k_magnitude.clone() - k_negative * k_magnitude;

                    let mut signed_carries = Vec::with_capacity(LIMBS);
                    for _ in 0..LIMBS {
                        let negative = eval.next_trace_mask();
                        let magnitude = eval.next_trace_mask();
                        eval.add_constraint(negative.clone() * (negative.clone() - one.clone()));
                        eval.add_constraint(magnitude.clone() * (magnitude.clone() - one.clone()));
                        let positive = one.clone() - negative.clone();
                        signed_carries.push(positive * magnitude.clone() - negative * magnitude);
                    }
                    eval.add_constraint(signed_carries[0].clone());
                    for index in 0..LIMBS {
                        let carry_in = if index == 0 {
                            M31::from(0u32).into()
                        } else {
                            signed_carries[index - 1].clone()
                        };
                        let carry_out = if index + 1 == LIMBS {
                            M31::from(0u32).into()
                        } else {
                            signed_carries[index].clone()
                        };
                        let signed_b = value_limbs[usize::from(b)][index].clone()
                            * (one.clone() - subtract.clone() - subtract.clone());
                        eval.add_constraint(
                            value_limbs[usize::from(a)][index].clone() + signed_b + carry_in
                                - value_limbs[usize::from(out)][index].clone()
                                - signed_k.clone()
                                    * E::F::from(M31::from(u32::from(P_BYTES[index])))
                                - base.clone() * carry_out,
                        );
                    }
                }
                RistrettoFpProgramOp::Multiply { a, b, out, q } => {
                    let mut signed_carries = Vec::with_capacity(PRODUCT_LIMBS - 1);
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
                        let positive = one.clone() - negative.clone();
                        signed_carries.push(positive * magnitude.clone() - negative * magnitude);
                    }

                    for limb_index in 0..PRODUCT_LIMBS {
                        let start = limb_index.saturating_sub(LIMBS - 1);
                        let end = limb_index.min(LIMBS - 1);
                        let mut relation: E::F = M31::from(0u32).into();
                        for left_index in start..=end {
                            let right_index = limb_index - left_index;
                            relation += value_limbs[usize::from(a)][left_index].clone()
                                * value_limbs[usize::from(b)][right_index].clone();
                            relation = relation
                                - value_limbs[usize::from(q)][left_index].clone()
                                    * E::F::from(M31::from(u32::from(P_BYTES[right_index])));
                        }
                        if limb_index < LIMBS {
                            relation = relation - value_limbs[usize::from(out)][limb_index].clone();
                        }
                        if limb_index > 0 {
                            relation += signed_carries[limb_index - 1].clone();
                        }
                        if limb_index + 1 < PRODUCT_LIMBS {
                            relation = relation - base.clone() * signed_carries[limb_index].clone();
                        }
                        eval.add_constraint(relation);
                    }
                }
            }
        }
        eval
    }
}

fn mix_program(channel: &mut impl Channel, program: &RistrettoFpProgram) {
    let mut values = Vec::with_capacity(program.values.len() * LIMBS);
    for value in &program.values {
        values.extend(value.iter().map(|limb| u32::from(*limb)));
    }
    channel.mix_u32s(&values);
    channel.mix_u64(program.ops.len() as u64);
    for op in &program.ops {
        let (selector, indices) = match *op {
            RistrettoFpProgramOp::Add { a, b, out } => (0u64, [a, b, out, 0]),
            RistrettoFpProgramOp::Subtract { a, b, out } => (1u64, [a, b, out, 0]),
            RistrettoFpProgramOp::Multiply { a, b, out, q } => (2u64, [a, b, out, q]),
        };
        channel.mix_u64(selector);
        for index in indices {
            channel.mix_u64(u64::from(index));
        }
    }
    channel.mix_u64(program.outputs.len() as u64);
    for output in &program.outputs {
        channel.mix_u64(u64::from(*output));
    }
}

/// Prove all canonical values and field operations in one STARK.
pub fn prove_ristretto_fp_program(
    program: &RistrettoFpProgram,
) -> TexasAirResult<ArchivedRistrettoFpProgramProof> {
    let trace = trace_columns(program)?;
    let scope = scope_columns(program);
    let config = crate::prover_context::protocol_pcs_config();
    let twiddles =
        crate::prover_context::simd_twiddles(LOG_SIZE + config.fri_config.log_blowup_factor);
    let mut channel = stwo::core::channel::Poseidon252Channel::default();
    mix_program(&mut channel, program);
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
    let ids = preprocessed_ids(program);
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
    let component = FrameworkComponent::new(
        &mut allocator,
        FpProgramAir {
            log_size: LOG_SIZE,
            program: program.clone(),
        },
        SecureField::from(0u32),
    );
    let proof = prove(&[&component], &mut channel, scheme)
        .map_err(|error| TexasAirError::StwoProverError(error.to_string()))?;
    let stark_proof_bytes = options()
        .serialize(&proof)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
    Ok(ArchivedRistrettoFpProgramProof {
        program: program.clone(),
        stark_proof_bytes,
    })
}

/// Verify the fixed public Fp program in one STARK.
pub fn verify_ristretto_fp_program(
    archive: &ArchivedRistrettoFpProgramProof,
) -> TexasAirResult<()> {
    type Proof = StarkProof<Poseidon252MerkleHasher>;
    let proof: Proof = options()
        .deserialize(&archive.stark_proof_bytes)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
    let trace = trace_columns(&archive.program)?;
    let scope = scope_columns(&archive.program);
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
            "Fp program public scope commitment mismatch".into(),
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
            "Fp program trace commitment mismatch".into(),
        ));
    }

    let mut channel = stwo::core::channel::Poseidon252Channel::default();
    mix_program(&mut channel, &archive.program);
    let mut scheme =
        stwo::core::pcs::CommitmentSchemeVerifier::<Poseidon252MerkleChannel>::new(config);
    scheme.commit(
        proof.commitments[0],
        &vec![LOG_SIZE; archive.program.values.len() * LIMBS],
        &mut channel,
    );
    scheme.commit(
        proof.commitments[1],
        &vec![LOG_SIZE; trace.cols.len()],
        &mut channel,
    );
    let ids = preprocessed_ids(&archive.program);
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
    let component = FrameworkComponent::new(
        &mut allocator,
        FpProgramAir {
            log_size: LOG_SIZE,
            program: archive.program.clone(),
        },
        SecureField::from(0u32),
    );
    stwo::core::verifier::verify(&[&component], &mut channel, &mut scheme, proof)
        .map_err(|error| TexasAirError::ConstraintUnsatisfied(error.to_string()))
}

/// Prove the exact field semantics of `sqrt_ratio_i` in one program STARK.
///
/// This replaces three independently proven multiplications with one folded
/// field-program proof while preserving the same public square/nonsquare
/// classification and zero-denominator behavior.
pub fn prove_ristretto_fp_program_sqrt_ratio(
    u: &[u8; LIMBS],
    v: &[u8; LIMBS],
) -> TexasAirResult<ArchivedRistrettoFpProgramSqrtRatioProof> {
    let p = modulus();
    let u_value = big_uint(u);
    let v_value = big_uint(v);
    if u_value >= p || v_value >= p {
        return Err(TexasAirError::SpecViolation(
            "Ristretto sqrt_ratio program inputs must be canonical".into(),
        ));
    }

    let (was_square, r_value) = if u_value.is_zero() {
        (true, BigUint::from(0u32))
    } else if v_value.is_zero() {
        (false, BigUint::from(0u32))
    } else {
        let ratio = multiply_big(&u_value, &v_value.modpow(&(&p - BigUint::from(2u32)), &p));
        if let Some(root) = nonnegative_sqrt(&ratio) {
            (true, root)
        } else {
            let target = multiply_big(&sqrt_m1(), &ratio);
            let root = nonnegative_sqrt(&target).ok_or_else(|| {
                TexasAirError::SpecViolation(
                    "Ristretto sqrt_ratio witness is neither square nor i-square".into(),
                )
            })?;
            (false, root)
        }
    };
    let r = limbs(&r_value);

    let mut builder = RistrettoFpProgramBuilder::new(&[*u, *v, r]);
    let r_squared = builder.multiply(2, 2)?;
    let check = builder.multiply(r_squared, 1)?;
    let sqrt_m1_index = builder.constant(&SQRT_M1_BYTES)?;
    let i_times_u = builder.multiply(sqrt_m1_index, 0)?;
    let program = builder.finish(&[check, i_times_u])?;
    let proof = prove_ristretto_fp_program(&program)?;
    Ok(ArchivedRistrettoFpProgramSqrtRatioProof {
        u: *u,
        v: *v,
        r,
        check: program.values[usize::from(check)],
        i_times_u: program.values[usize::from(i_times_u)],
        was_square,
        program: proof,
    })
}

/// Verify the folded `sqrt_ratio_i` program and its fixed public DAG.
pub fn verify_ristretto_fp_program_sqrt_ratio(
    archive: &ArchivedRistrettoFpProgramSqrtRatioProof,
) -> TexasAirResult<()> {
    let program = &archive.program.program;
    let fixed_shape = program.values.len() == 10
        && program.ops.len() == 3
        && program.outputs == [6, 9]
        && program.ops
            == [
                RistrettoFpProgramOp::Multiply {
                    a: 2,
                    b: 2,
                    out: 4,
                    q: 3,
                },
                RistrettoFpProgramOp::Multiply {
                    a: 4,
                    b: 1,
                    out: 6,
                    q: 5,
                },
                RistrettoFpProgramOp::Multiply {
                    a: 7,
                    b: 0,
                    out: 9,
                    q: 8,
                },
            ];
    if !fixed_shape
        || program.values[0] != archive.u
        || program.values[1] != archive.v
        || program.values[2] != archive.r
        || program.values[7] != SQRT_M1_BYTES
        || program.values[6] != archive.check
        || program.values[9] != archive.i_times_u
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Ristretto sqrt_ratio program shape is detached".into(),
        ));
    }

    verify_ristretto_fp_program(&archive.program)?;
    let zero = [0u8; LIMBS];
    if archive.r[0] & 1 == 1 {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Ristretto sqrt_ratio root must be nonnegative".into(),
        ));
    }
    if archive.u == zero {
        if !archive.was_square || archive.r != zero || archive.check != zero {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "Ristretto sqrt_ratio(0,v) must return zero".into(),
            ));
        }
        return Ok(());
    }
    if archive.v == zero {
        if archive.was_square || archive.r != zero || archive.check != zero {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "Ristretto sqrt_ratio(u,0) must return false and zero".into(),
            ));
        }
        return Ok(());
    }
    let expected_check = if archive.was_square {
        archive.u
    } else {
        archive.i_times_u
    };
    if archive.check != expected_check {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Ristretto sqrt_ratio classification is inconsistent".into(),
        ));
    }
    Ok(())
}

fn negative_edwards_d() -> [u8; LIMBS] {
    limbs(&subtract_big(&modulus(), &big_uint(&EDWARDS_D_BYTES)))
}

fn expected_decode_ops(x_index: u16) -> Vec<RistrettoFpProgramOp> {
    vec![
        RistrettoFpProgramOp::Multiply {
            a: 0,
            b: 0,
            out: 5,
            q: 4,
        },
        RistrettoFpProgramOp::Subtract { a: 2, b: 5, out: 6 },
        RistrettoFpProgramOp::Add { a: 2, b: 5, out: 7 },
        RistrettoFpProgramOp::Multiply {
            a: 7,
            b: 7,
            out: 9,
            q: 8,
        },
        RistrettoFpProgramOp::Multiply {
            a: 6,
            b: 6,
            out: 11,
            q: 10,
        },
        RistrettoFpProgramOp::Multiply {
            a: 3,
            b: 11,
            out: 13,
            q: 12,
        },
        RistrettoFpProgramOp::Subtract {
            a: 13,
            b: 9,
            out: 14,
        },
        RistrettoFpProgramOp::Multiply {
            a: 14,
            b: 9,
            out: 16,
            q: 15,
        },
        RistrettoFpProgramOp::Multiply {
            a: 1,
            b: 1,
            out: 18,
            q: 17,
        },
        RistrettoFpProgramOp::Multiply {
            a: 18,
            b: 16,
            out: 20,
            q: 19,
        },
        RistrettoFpProgramOp::Multiply {
            a: 1,
            b: 7,
            out: 22,
            q: 21,
        },
        RistrettoFpProgramOp::Multiply {
            a: 22,
            b: 14,
            out: 24,
            q: 23,
        },
        RistrettoFpProgramOp::Multiply {
            a: 1,
            b: 24,
            out: 26,
            q: 25,
        },
        RistrettoFpProgramOp::Add {
            a: 0,
            b: 0,
            out: 27,
        },
        RistrettoFpProgramOp::Multiply {
            a: 27,
            b: 22,
            out: 29,
            q: 28,
        },
        RistrettoFpProgramOp::Subtract {
            a: 30,
            b: 29,
            out: 31,
        },
        RistrettoFpProgramOp::Multiply {
            a: 6,
            b: 26,
            out: 33,
            q: 32,
        },
        RistrettoFpProgramOp::Multiply {
            a: x_index,
            b: 33,
            out: 35,
            q: 34,
        },
    ]
}

/// Prove canonical Ristretto point decoding in one field-program STARK.
pub fn prove_ristretto_fp_program_point_decode(
    encoding: &[u8; LIMBS],
) -> TexasAirResult<ArchivedRistrettoFpProgramPointDecodeProof> {
    let p = modulus();
    let s = big_uint(encoding);
    if s >= p {
        return Err(TexasAirError::SpecViolation(
            "Ristretto point encoding is noncanonical".into(),
        ));
    }
    if (s.clone() & BigUint::one()) == BigUint::one() {
        return Err(TexasAirError::SpecViolation(
            "Ristretto point encoding is negative".into(),
        ));
    }

    let one = BigUint::one();
    let ss = multiply_big(&s, &s);
    let u1 = subtract_big(&one, &ss);
    let u2 = add_big(&one, &ss);
    let u2sq = multiply_big(&u2, &u2);
    let u1sq = multiply_big(&u1, &u1);
    let negative_d = subtract_big(&p, &big_uint(&EDWARDS_D_BYTES));
    let neg_d_u1sq = multiply_big(&negative_d, &u1sq);
    let v = subtract_big(&neg_d_u1sq, &u2sq);
    let target = multiply_big(&v, &u2sq);
    #[cfg(test)]
    eprintln!(
        "decode target legendre-one={} d_len={} target_len={} target={:?} negative_d={:?}",
        target.modpow(&((&modulus() - BigUint::one()) >> 1u32), &modulus()) == BigUint::one(),
        big_uint(&EDWARDS_D_BYTES).to_bytes_le().len(),
        target.to_bytes_le().len(),
        limbs(&target),
        negative_edwards_d()
    );
    let root = nonnegative_sqrt(&target).ok_or_else(|| {
        TexasAirError::SpecViolation("Ristretto decode inverse square root does not exist".into())
    })?;
    let mut inverse_sqrt = root.modpow(&(&p - BigUint::from(2u32)), &p);
    if (&inverse_sqrt & BigUint::one()) == BigUint::one() {
        inverse_sqrt = &p - inverse_sqrt;
    }

    let inverse_sqrt_bytes = limbs(&inverse_sqrt);
    let mut builder = RistrettoFpProgramBuilder::new(&[*encoding, inverse_sqrt_bytes]);
    builder.constant(&ONE_BYTES)?;
    builder.constant(&negative_edwards_d())?;
    let ss_index = builder.multiply(0, 0)?;
    let u1_index = builder.subtract(2, ss_index)?;
    let u2_index = builder.add(2, ss_index)?;
    let u2sq_index = builder.multiply(u2_index, u2_index)?;
    let u1sq_index = builder.multiply(u1_index, u1_index)?;
    let neg_d_u1sq_index = builder.multiply(3, u1sq_index)?;
    let v_index = builder.subtract(neg_d_u1sq_index, u2sq_index)?;
    let target_index = builder.multiply(v_index, u2sq_index)?;
    let inverse_sqrt_sq_index = builder.multiply(1, 1)?;
    let identity_index = builder.multiply(inverse_sqrt_sq_index, target_index)?;
    if builder_values(&builder, identity_index)? != ONE_BYTES {
        return Err(TexasAirError::SpecViolation(
            "Ristretto decode inverse-square-root relation is invalid".into(),
        ));
    }
    let dx_index = builder.multiply(1, u2_index)?;
    let dxv_index = builder.multiply(dx_index, v_index)?;
    let dy_index = builder.multiply(1, dxv_index)?;
    let two_s_index = builder.add(0, 0)?;
    let x_raw_index = builder.multiply(two_s_index, dx_index)?;
    builder.constant(&ZERO_BYTES)?;
    let x_negative_index = builder.subtract(30, x_raw_index)?;
    let y_index = builder.multiply(u1_index, dy_index)?;

    let x_raw = builder_values(&builder, x_raw_index)?;
    let x_index = if x_raw[0] & 1 == 0 {
        x_raw_index
    } else {
        x_negative_index
    };
    let t_index = builder.multiply(x_index, y_index)?;
    let x = builder_values(&builder, x_index)?;
    let y = builder_values(&builder, y_index)?;
    let t = builder_values(&builder, t_index)?;
    if y == ZERO_BYTES {
        return Err(TexasAirError::SpecViolation(
            "Ristretto decode produced Y = 0".into(),
        ));
    }
    if t[0] & 1 == 1 {
        return Err(TexasAirError::SpecViolation(
            "Ristretto decode produced negative T".into(),
        ));
    }

    let program = builder.finish(&[identity_index, x_index, y_index, t_index])?;
    let proof = prove_ristretto_fp_program(&program)?;
    Ok(ArchivedRistrettoFpProgramPointDecodeProof {
        encoding: *encoding,
        inverse_sqrt: inverse_sqrt_bytes,
        x,
        y,
        t,
        program: proof,
    })
}

fn builder_values(builder: &RistrettoFpProgramBuilder, index: u16) -> TexasAirResult<[u8; LIMBS]> {
    builder
        .values
        .get(usize::from(index))
        .copied()
        .ok_or_else(|| TexasAirError::SpecViolation("Fp program index is out of bounds".into()))
}

/// Verify the fixed one-STARK canonical decode program and its branches.
pub fn verify_ristretto_fp_program_point_decode(
    archive: &ArchivedRistrettoFpProgramPointDecodeProof,
) -> TexasAirResult<()> {
    let program = &archive.program.program;
    let x_index = if program
        .values
        .get(29)
        .copied()
        .is_some_and(|x| x[0] & 1 == 0)
    {
        29
    } else {
        31
    };
    let fixed_shape = program.values.len() == 36
        && program.ops.len() == 19
        && program.outputs == [20, x_index, 33, 35]
        && program.ops == expected_decode_ops(x_index)
        && program.values[0] == archive.encoding
        && program.values[1] == archive.inverse_sqrt
        && program.values[2] == ONE_BYTES
        && program.values[3] == negative_edwards_d()
        && program.values[20] == ONE_BYTES
        && program.values[30] == ZERO_BYTES
        && program.values[usize::from(x_index)] == archive.x
        && program.values[33] == archive.y
        && program.values[35] == archive.t;
    if !fixed_shape {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Ristretto decode program shape is detached".into(),
        ));
    }

    verify_ristretto_fp_program(&archive.program)?;
    let expected_x = if program.values[29][0] & 1 == 0 {
        program.values[29]
    } else {
        program.values[31]
    };
    if archive.encoding[0] & 1 == 1
        || archive.inverse_sqrt[0] & 1 == 1
        || archive.x != expected_x
        || archive.x[0] & 1 == 1
        || archive.y == ZERO_BYTES
        || archive.t[0] & 1 == 1
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Ristretto decode canonical branch is invalid".into(),
        ));
    }
    Ok(())
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
    fn proves_add_subtract_and_multiply_in_one_stark() {
        let mut builder = RistrettoFpProgramBuilder::new(&[small(2), small(3), small(5)]);
        let sum = builder.add(0, 1).unwrap();
        let product = builder.multiply(sum, 2).unwrap();
        let difference = builder.subtract(product, 0).unwrap();
        let program = builder.finish(&[sum, product, difference]).unwrap();
        assert_eq!(program.values[usize::from(sum)], small(5));
        assert_eq!(program.values[usize::from(product)], small(25));
        assert_eq!(program.values[usize::from(difference)], small(23));

        let archive = prove_ristretto_fp_program(&program).unwrap();
        verify_ristretto_fp_program(&archive).unwrap();
    }

    #[test]
    fn witness_rows_satisfy_direct_program_constraints() {
        let mut builder = RistrettoFpProgramBuilder::new(&[small(7), small(6)]);
        let difference = builder.subtract(0, 1).unwrap();
        let program = builder.finish(&[difference]).unwrap();
        let trace = trace_columns(&program).unwrap();
        let scope = scope_columns(&program);
        let evals = stwo::core::pcs::TreeVec::new(vec![
            scope.cols.iter().collect(),
            trace.cols.iter().collect(),
        ]);
        stwo_constraint_framework::assert_constraints_on_trace(
            &evals,
            LOG_SIZE,
            |eval| {
                FpProgramAir {
                    log_size: LOG_SIZE,
                    program: program.clone(),
                }
                .evaluate(eval);
            },
            SecureField::from(0u32),
        );
    }

    #[test]
    fn program_air_declares_quadratic_degree() {
        let mut builder = RistrettoFpProgramBuilder::new(&[small(2), small(3)]);
        let out = builder.multiply(0, 1).unwrap();
        let program = builder.finish(&[out]).unwrap();
        let mut evaluator = crate::ristretto_degree_util::DegreeEvaluator { max: 0 };
        evaluator = FpProgramAir {
            log_size: LOG_SIZE,
            program,
        }
        .evaluate(evaluator);
        assert_eq!(evaluator.max, 2);
    }

    #[test]
    fn verifier_rejects_spliced_public_values() {
        let mut builder = RistrettoFpProgramBuilder::new(&[small(2), small(3)]);
        let out = builder.add(0, 1).unwrap();
        let program = builder.finish(&[out]).unwrap();
        let mut archive = prove_ristretto_fp_program(&program).unwrap();
        archive.program.values[0][0] ^= 1;
        assert!(verify_ristretto_fp_program(&archive).is_err());
    }

    #[test]
    fn folded_sqrt_ratio_handles_square_nonsquare_and_zero_edges() {
        let square = prove_ristretto_fp_program_sqrt_ratio(&small(4), &small(1)).unwrap();
        assert!(square.was_square);
        assert_eq!(square.r, small(2));
        verify_ristretto_fp_program_sqrt_ratio(&square).unwrap();

        let nonsquare = prove_ristretto_fp_program_sqrt_ratio(&small(2), &small(1)).unwrap();
        assert!(!nonsquare.was_square);
        verify_ristretto_fp_program_sqrt_ratio(&nonsquare).unwrap();

        let zero_over_zero = prove_ristretto_fp_program_sqrt_ratio(&small(0), &small(0)).unwrap();
        assert!(zero_over_zero.was_square);
        verify_ristretto_fp_program_sqrt_ratio(&zero_over_zero).unwrap();

        let nonzero_over_zero =
            prove_ristretto_fp_program_sqrt_ratio(&small(1), &small(0)).unwrap();
        assert!(!nonzero_over_zero.was_square);
        verify_ristretto_fp_program_sqrt_ratio(&nonzero_over_zero).unwrap();
    }

    #[test]
    fn folded_sqrt_ratio_verifier_rejects_flipped_and_spliced_statements() {
        let mut flipped = prove_ristretto_fp_program_sqrt_ratio(&small(4), &small(1)).unwrap();
        flipped.was_square = false;
        assert!(verify_ristretto_fp_program_sqrt_ratio(&flipped).is_err());

        let mut spliced = prove_ristretto_fp_program_sqrt_ratio(&small(4), &small(1)).unwrap();
        spliced.r[0] ^= 2;
        assert!(verify_ristretto_fp_program_sqrt_ratio(&spliced).is_err());
    }

    fn basepoint() -> [u8; LIMBS] {
        [
            0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71, 0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00,
            0x51, 0x5f, 0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d, 0xb6, 0xa6, 0x59, 0x45,
            0xe0, 0x8d, 0x2d, 0x76,
        ]
    }

    #[test]
    fn folded_point_decode_handles_identity_and_basepoint() {
        let identity = prove_ristretto_fp_program_point_decode(&ZERO_BYTES).unwrap();
        assert_eq!(identity.x, ZERO_BYTES);
        assert_eq!(identity.y, ONE_BYTES);
        assert_eq!(identity.t, ZERO_BYTES);
        verify_ristretto_fp_program_point_decode(&identity).unwrap();

        let base = prove_ristretto_fp_program_point_decode(&basepoint()).unwrap();
        assert_ne!(base.x, ZERO_BYTES);
        assert_ne!(base.y, ZERO_BYTES);
        verify_ristretto_fp_program_point_decode(&base).unwrap();
    }

    #[test]
    fn folded_point_decode_rejects_invalid_encodings_before_proving() {
        let mut negative = ZERO_BYTES;
        negative[0] = 1;
        assert!(prove_ristretto_fp_program_point_decode(&negative).is_err());

        let mut noncanonical = [0xffu8; LIMBS];
        noncanonical[31] = 0x7f;
        assert!(prove_ristretto_fp_program_point_decode(&noncanonical).is_err());
    }

    #[test]
    fn folded_point_decode_verifier_rejects_spliced_coordinates() {
        let mut archive = prove_ristretto_fp_program_point_decode(&basepoint()).unwrap();
        archive.x[0] ^= 2;
        assert!(verify_ristretto_fp_program_point_decode(&archive).is_err());
    }

    #[test]
    fn noncanonical_or_invalid_program_rejects_before_proving() {
        let mut program = RistrettoFpProgramBuilder::new(&[small(1), small(2)])
            .finish(&[0])
            .unwrap();
        program.values[0] = P_BYTES;
        assert!(prove_ristretto_fp_program(&program).is_err());

        let mut invalid = RistrettoFpProgramBuilder::new(&[small(2), small(3)])
            .finish(&[0])
            .unwrap();
        invalid
            .ops
            .push(RistrettoFpProgramOp::Add { a: 0, b: 1, out: 0 });
        assert!(prove_ristretto_fp_program(&invalid).is_err());
    }
}
