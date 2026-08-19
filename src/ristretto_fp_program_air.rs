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
use crate::ristretto_scalar_windows_air::{
    ArchivedRistrettoScalarWindowsProof, verify_ristretto_scalar_windows,
};
use crate::trace_gen::MethodTrace;

const LIMBS: usize = 32;
const PRODUCT_LIMBS: usize = 2 * LIMBS;
const BASE: u32 = 256;
const LOG_SIZE: u32 = 1;
const MAX_VALUES: usize = 512;
const MAX_OPS: usize = 512;
const MAX_OUTPUTS: usize = 64;
const FIXED_WINDOW_COUNT: usize = 64;
const FIXED_WINDOW_TABLE_COORDINATES: usize = 4;
const PROJECTIVE_ADDITIONS_PER_WINDOW: usize = 5;
const PROJECTIVE_ADDITION_OPS: usize = 18;
const PROJECTIVE_ADDITION_VALUES: usize = 28;
const FIXED_WINDOW_ADDITION_COUNT: usize = FIXED_WINDOW_COUNT * PROJECTIVE_ADDITIONS_PER_WINDOW;
const FIXED_WINDOW_PROGRAM_OPS: usize = FIXED_WINDOW_ADDITION_COUNT * PROJECTIVE_ADDITION_OPS;
const FIXED_WINDOW_PROGRAM_VALUES: usize = 6
    + FIXED_WINDOW_COUNT * FIXED_WINDOW_TABLE_COORDINATES
    + FIXED_WINDOW_ADDITION_COUNT * PROJECTIVE_ADDITION_VALUES;

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

const TWO_BYTES: [u8; LIMBS] = {
    let mut bytes = [0u8; LIMBS];
    bytes[0] = 2;
    bytes
};

/// `2*d mod p` for the unified Edwards addition formula.
const EDWARDS_TWO_D_BYTES: [u8; LIMBS] = [
    0x59, 0xf1, 0xb2, 0x26, 0x94, 0x9b, 0xd6, 0xeb, 0x56, 0xb1, 0x83, 0x82, 0x9a, 0x14, 0xe0, 0x00,
    0x30, 0xd1, 0xf3, 0xee, 0xf2, 0x80, 0x8e, 0x19, 0xe7, 0xfc, 0xdf, 0x56, 0xdc, 0xd9, 0x06, 0x24,
];

/// Edwards `d` as a positive decimal residue; the curve constant is negative.
const EDWARDS_D_BYTES: [u8; LIMBS] = [
    0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
    0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c, 0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52,
];

/// Nonnegative `sqrt(-1)` in the Ristretto255 field.
const SQRT_M1_BYTES: [u8; LIMBS] = [
    0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4, 0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
    0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b, 0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b,
];

/// `1/sqrt(a-d)` for the Ristretto compression branch.
const INVSQRT_A_MINUS_D_BYTES: [u8; LIMBS] = [
    0xea, 0x40, 0x5d, 0x80, 0xaa, 0xfd, 0xc8, 0x99, 0xbe, 0x72, 0x41, 0x5a, 0x17, 0x16, 0x2f, 0x9d,
    0x40, 0xd8, 0x01, 0xfe, 0x91, 0x7b, 0xc2, 0x16, 0xa2, 0xfc, 0xaf, 0xcf, 0x05, 0x89, 0x6c, 0x78,
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

/// Public Ristretto point-encode statement proven by one field-program STARK.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoFpProgramPointEncodeProof {
    /// Authenticated decoded input point.
    pub point: ArchivedRistrettoFpProgramPointDecodeProof,
    /// Canonical nonnegative output encoding.
    pub encoding: [u8; LIMBS],
    /// One-STARK encode program.
    pub program: ArchivedRistrettoFpProgramProof,
}

/// Public extended-Edwards addition statement proven by one program STARK.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoFpProgramEdwardsAdditionProof {
    /// Authenticated decoded left summand.
    pub left: ArchivedRistrettoFpProgramPointDecodeProof,
    /// Authenticated decoded right summand.
    pub right: ArchivedRistrettoFpProgramPointDecodeProof,
    /// Output extended coordinate `X`.
    pub x: [u8; LIMBS],
    /// Output extended coordinate `Y`.
    pub y: [u8; LIMBS],
    /// Output extended coordinate `Z`.
    pub z: [u8; LIMBS],
    /// Output extended coordinate `T`.
    pub t: [u8; LIMBS],
    /// One-STARK addition program.
    pub program: ArchivedRistrettoFpProgramProof,
}

/// An authenticated projective point usable as the input to another point AIR.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoFpProgramProjectivePoint {
    /// Extended coordinate `X`.
    pub x: [u8; LIMBS],
    /// Extended coordinate `Y`.
    pub y: [u8; LIMBS],
    /// Nonzero extended coordinate `Z`.
    pub z: [u8; LIMBS],
    /// Extended coordinate `T`.
    pub t: [u8; LIMBS],
    /// Proof that these coordinates represent a valid point.
    pub source: ArchivedRistrettoFpProgramProjectivePointSource,
}

/// Provenance of an authenticated projective point.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum ArchivedRistrettoFpProgramProjectivePointSource {
    /// The point came from canonical 32-byte decoding.
    Decode(ArchivedRistrettoFpProgramPointDecodeProof),
    /// The point came from a verified projective addition.
    Addition(Box<ArchivedRistrettoFpProgramProjectiveAdditionProof>),
    /// The point was selected from a verified 16-entry point table.
    Selector(Box<ArchivedRistrettoFpProgramPointSelectorProof>),
    /// The point is entry `index` of a verified `0..15` multiples table.
    Table {
        /// The common multiples-table proof.
        table: Box<ArchivedRistrettoFpProgramPointTableProof>,
        /// Entry index in `0..15`.
        index: u8,
    },
}

/// Public general projective Edwards addition statement.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoFpProgramProjectiveAdditionProof {
    /// Authenticated left summand.
    pub left: ArchivedRistrettoFpProgramProjectivePoint,
    /// Authenticated right summand.
    pub right: ArchivedRistrettoFpProgramProjectivePoint,
    /// Output extended coordinate `X`.
    pub x: [u8; LIMBS],
    /// Output extended coordinate `Y`.
    pub y: [u8; LIMBS],
    /// Output extended coordinate `Z`.
    pub z: [u8; LIMBS],
    /// Output extended coordinate `T`.
    pub t: [u8; LIMBS],
    /// One-STARK general addition program.
    pub program: ArchivedRistrettoFpProgramProof,
}

/// Public `0P..15P` table derived in one program STARK.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoFpProgramPointTableProof {
    /// Authenticated base point.
    pub base: ArchivedRistrettoFpProgramProjectivePoint,
    /// Sixteen projective coordinate tuples.
    pub coordinates: [[u8; LIMBS]; 64],
    /// One-STARK table program.
    pub program: ArchivedRistrettoFpProgramProof,
}

/// Public 16-entry table selection statement.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoFpProgramPointSelectorProof {
    /// Authenticated table entries `0..15`.
    pub table: [ArchivedRistrettoFpProgramProjectivePoint; 16],
    /// Four-bit table index.
    pub selector: u8,
    /// Selected extended coordinate `X`.
    pub x: [u8; LIMBS],
    /// Selected extended coordinate `Y`.
    pub y: [u8; LIMBS],
    /// Selected extended coordinate `Z`.
    pub z: [u8; LIMBS],
    /// Selected extended coordinate `T`.
    pub t: [u8; LIMBS],
}

/// Fixed-window scalar multiplication statement for a folded Fp program.
///
/// The program uses Horner evaluation from the most significant 4-bit window:
/// four projective doublings followed by addition of the authenticated table
/// entry for each window.  The scalar-window proof and the table are both part
/// of the statement, so the verifier does not trust a host-side decomposition
/// or selected point.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoFpProgramFixedWindowScalarMulProof {
    /// Canonical scalar and its authenticated 4-bit windows.
    pub scalar_windows: ArchivedRistrettoScalarWindowsProof,
    /// Authenticated `0P..15P` table.
    pub table: ArchivedRistrettoFpProgramPointTableProof,
    /// Output extended coordinate `X`.
    pub x: [u8; LIMBS],
    /// Output extended coordinate `Y`.
    pub y: [u8; LIMBS],
    /// Output extended coordinate `Z`.
    pub z: [u8; LIMBS],
    /// Output extended coordinate `T`.
    pub t: [u8; LIMBS],
    /// One folded scalar-multiplication program.
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
    differences: Vec<Option<[u8; LIMBS]>>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValueCanonicity {
    /// A root/constant or multiplication result carrying its own strict witness.
    Witnessed,
    /// Canonicality follows from an add/sub output or multiplication quotient.
    Derived,
}

fn program_canonicity(program: &RistrettoFpProgram) -> TexasAirResult<Vec<ValueCanonicity>> {
    let mut canonicity = vec![ValueCanonicity::Witnessed; program.values.len()];
    for op in &program.ops {
        let (operands, derived, multiplication_output) = match *op {
            RistrettoFpProgramOp::Add { a, b, out }
            | RistrettoFpProgramOp::Subtract { a, b, out } => (&[a, b][..], out, false),
            RistrettoFpProgramOp::Multiply { a, b, out: _, q } => (&[a, b][..], q, true),
        };
        for index in operands.iter().chain(std::iter::once(&derived)) {
            if usize::from(*index) >= program.values.len() {
                return Err(TexasAirError::SpecViolation(
                    "Fp program operation index is out of bounds".into(),
                ));
            }
        }
        if usize::from(multiplication_output) >= program.values.len() {
            return Err(TexasAirError::SpecViolation(
                "Fp program multiplication output is out of bounds".into(),
            ));
        }
        if operands.iter().any(|operand| *operand >= derived) {
            return Err(TexasAirError::SpecViolation(
                "Fp program operation consumes a later value".into(),
            ));
        }
        if canonicity[usize::from(derived)] != ValueCanonicity::Witnessed {
            return Err(TexasAirError::SpecViolation(
                "Fp program defines a value more than once".into(),
            ));
        }
        canonicity[usize::from(derived)] = ValueCanonicity::Derived;

        if multiplication_output {
            let out = match op {
                RistrettoFpProgramOp::Multiply { out, .. } => *out,
                _ => unreachable!("multiplication output is only set for Multiply"),
            };
            if canonicity[usize::from(out)] != ValueCanonicity::Witnessed {
                return Err(TexasAirError::SpecViolation(
                    "Fp program defines a value more than once".into(),
                ));
            }
            // The multiplication output retains a direct `< p` witness.  Its
            // quotient is canonical because a*b < p^2 and the exact convolution
            // equation proves a*b = out + q*p.
            canonicity[usize::from(out)] = ValueCanonicity::Witnessed;
        }
    }
    Ok(canonicity)
}

fn program_witness(program: &RistrettoFpProgram) -> TexasAirResult<ProgramWitness> {
    validate_indices(program.values.len(), program.ops.len(), &program.outputs)?;
    let canonicity = program_canonicity(program)?;
    let mut differences = Vec::with_capacity(program.values.len());
    for (value_index, value) in program.values.iter().enumerate() {
        if big_uint(value) >= modulus() {
            return Err(TexasAirError::SpecViolation(
                "Fp program value is noncanonical".into(),
            ));
        }
        differences.push(if canonicity[value_index] == ValueCanonicity::Witnessed {
            Some(prime_minus(value)?)
        } else {
            None
        });
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
    let canonicity = program_canonicity(program)?;
    let mut row = Vec::new();
    for (value_index, value) in program.values.iter().enumerate() {
        for limb in value {
            append_limb(&mut row, *limb);
        }
        if canonicity[value_index] == ValueCanonicity::Witnessed {
            let difference = witness.differences[value_index]
                .expect("witnessed values carry a prime-difference witness");
            for limb in difference {
                append_limb(&mut row, limb);
            }
            let mut carries = [0u8; LIMBS];
            let mut carry_in = 0u16;
            for index in 0..LIMBS {
                let sum = u16::from(value[index]) + u16::from(difference[index]) + carry_in;
                carries[index] = u8::from(sum >= BASE as u16);
                carry_in = sum >> 8;
            }
            row.extend(carries.iter().map(|carry| M31::from(u32::from(*carry))));
            let mut nonzero_count = 0u32;
            for limb in difference {
                nonzero_count += u32::from(limb != 0);
                row.push(M31::from(u32::from(limb != 0)));
                row.push(m31_inverse(limb));
            }
            row.push(M31::from(nonzero_count).inverse());
        }
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
            id: format!("ristretto.fp.program.scope.v2.{column}").into(),
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
        let canonicity =
            program_canonicity(&self.program).expect("program was validated before proving");
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
            if canonicity[value_index] == ValueCanonicity::Witnessed {
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
                eval.add_constraint(carries[LIMBS - 1].clone());
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
            }

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
                    let expected_subtract = matches!(op, RistrettoFpProgramOp::Subtract { .. });
                    let subtract = eval.next_trace_mask();
                    eval.add_constraint(subtract.clone() * (subtract.clone() - one.clone()));
                    eval.add_constraint(
                        subtract.clone() - E::F::from(M31::from(u32::from(expected_subtract))),
                    );
                    let k_negative = eval.next_trace_mask();
                    let k_magnitude = eval.next_trace_mask();
                    eval.add_constraint(k_negative.clone() * (k_negative.clone() - one.clone()));
                    eval.add_constraint(k_magnitude.clone() * (k_magnitude.clone() - one.clone()));
                    if expected_subtract {
                        eval.add_constraint(k_negative.clone() - k_magnitude.clone());
                    } else {
                        eval.add_constraint(k_negative.clone());
                    }
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
                    eval.add_constraint(signed_carries[LIMBS - 1].clone());
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
        && program.ops.len() == 18
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

fn expected_encode_ops(
    selected_x: u16,
    selected_y: u16,
    selected_denominator: u16,
    final_y: u16,
) -> Vec<RistrettoFpProgramOp> {
    vec![
        RistrettoFpProgramOp::Add { a: 4, b: 1, out: 7 },
        RistrettoFpProgramOp::Subtract { a: 4, b: 1, out: 8 },
        RistrettoFpProgramOp::Multiply {
            a: 7,
            b: 8,
            out: 10,
            q: 9,
        },
        RistrettoFpProgramOp::Multiply {
            a: 0,
            b: 1,
            out: 12,
            q: 11,
        },
        RistrettoFpProgramOp::Multiply {
            a: 12,
            b: 12,
            out: 14,
            q: 13,
        },
        RistrettoFpProgramOp::Multiply {
            a: 10,
            b: 14,
            out: 16,
            q: 15,
        },
        RistrettoFpProgramOp::Multiply {
            a: 3,
            b: 3,
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
            a: 3,
            b: 10,
            out: 22,
            q: 21,
        },
        RistrettoFpProgramOp::Multiply {
            a: 3,
            b: 12,
            out: 24,
            q: 23,
        },
        RistrettoFpProgramOp::Multiply {
            a: 24,
            b: 2,
            out: 26,
            q: 25,
        },
        RistrettoFpProgramOp::Multiply {
            a: 22,
            b: 26,
            out: 28,
            q: 27,
        },
        RistrettoFpProgramOp::Multiply {
            a: 2,
            b: 28,
            out: 30,
            q: 29,
        },
        RistrettoFpProgramOp::Multiply {
            a: 0,
            b: 5,
            out: 32,
            q: 31,
        },
        RistrettoFpProgramOp::Multiply {
            a: 1,
            b: 5,
            out: 34,
            q: 33,
        },
        RistrettoFpProgramOp::Multiply {
            a: 22,
            b: 6,
            out: 36,
            q: 35,
        },
        RistrettoFpProgramOp::Subtract {
            a: 37,
            b: selected_y,
            out: 38,
        },
        RistrettoFpProgramOp::Multiply {
            a: selected_x,
            b: 28,
            out: 40,
            q: 39,
        },
        RistrettoFpProgramOp::Subtract {
            a: 4,
            b: final_y,
            out: 41,
        },
        RistrettoFpProgramOp::Multiply {
            a: selected_denominator,
            b: 41,
            out: 43,
            q: 42,
        },
        RistrettoFpProgramOp::Subtract {
            a: 37,
            b: 43,
            out: 44,
        },
    ]
}

/// Prove canonical Ristretto encoding of a folded decoded point in one STARK.
pub fn prove_ristretto_fp_program_point_encode(
    point: ArchivedRistrettoFpProgramPointDecodeProof,
) -> TexasAirResult<ArchivedRistrettoFpProgramPointEncodeProof> {
    verify_ristretto_fp_program_point_decode(&point)?;
    let x_value = big_uint(&point.x);
    let y_value = big_uint(&point.y);
    let one = BigUint::one();

    let z_plus_y = add_big(&one, &y_value);
    let z_minus_y = subtract_big(&one, &y_value);
    let u1 = multiply_big(&z_plus_y, &z_minus_y);
    let u2 = multiply_big(&x_value, &y_value);
    let u2_squared = multiply_big(&u2, &u2);
    let v = multiply_big(&u1, &u2_squared);
    let mut inverse_sqrt = if v.is_zero() {
        BigUint::from(0u32)
    } else {
        let root = nonnegative_sqrt(&v).ok_or_else(|| {
            TexasAirError::SpecViolation("Ristretto encode square root does not exist".into())
        })?;
        let inverse = root.modpow(&(modulus() - BigUint::from(2u32)), &modulus());
        if (&inverse & BigUint::one()) == BigUint::one() {
            modulus() - inverse
        } else {
            inverse
        }
    };
    inverse_sqrt = if (&inverse_sqrt & BigUint::one()) == BigUint::one() {
        modulus() - inverse_sqrt
    } else {
        inverse_sqrt
    };

    let mut builder =
        RistrettoFpProgramBuilder::new(&[point.x, point.y, point.t, limbs(&inverse_sqrt)]);
    builder.constant(&ONE_BYTES)?;
    builder.constant(&SQRT_M1_BYTES)?;
    builder.constant(&INVSQRT_A_MINUS_D_BYTES)?;
    let z_plus_y_index = builder.add(4, 1)?;
    let z_minus_y_index = builder.subtract(4, 1)?;
    let u1_index = builder.multiply(z_plus_y_index, z_minus_y_index)?;
    let u2_index = builder.multiply(0, 1)?;
    let u2_squared_index = builder.multiply(u2_index, u2_index)?;
    let v_index = builder.multiply(u1_index, u2_squared_index)?;
    let inverse_sqrt_squared = builder.multiply(3, 3)?;
    let inverse_check = builder.multiply(inverse_sqrt_squared, v_index)?;
    let i1 = builder.multiply(3, u1_index)?;
    let i2 = builder.multiply(3, u2_index)?;
    let i2_times_t = builder.multiply(i2, 2)?;
    let z_inverse = builder.multiply(i1, i2_times_t)?;
    let t_times_z_inverse = builder.multiply(2, z_inverse)?;
    let i_x = builder.multiply(0, 5)?;
    let i_y = builder.multiply(1, 5)?;
    let enchanted_denominator = builder.multiply(i1, 6)?;
    builder.constant(&ZERO_BYTES)?;

    let t_z_inv = builder_values(&builder, t_times_z_inverse)?;
    let rotate = t_z_inv[0] & 1 == 1;
    let selected_x_index = if rotate { i_y } else { 0 };
    let selected_y_index = if rotate { i_x } else { 1 };
    let selected_denominator = if rotate { enchanted_denominator } else { i2 };
    let negative_selected_y = builder.subtract(37, selected_y_index)?;
    let x_times_z_inverse = builder.multiply(selected_x_index, z_inverse)?;
    let x_z_inv = builder_values(&builder, x_times_z_inverse)?;
    let negate_y = x_z_inv[0] & 1 == 1;
    let final_y_index = if negate_y {
        negative_selected_y
    } else {
        selected_y_index
    };
    let z_minus_final_y = builder.subtract(4, final_y_index)?;
    let s_raw = builder.multiply(selected_denominator, z_minus_final_y)?;
    let negative_s_raw = builder.subtract(37, s_raw)?;
    let s_raw_bytes = builder_values(&builder, s_raw)?;
    let encoding_index = if s_raw_bytes[0] & 1 == 1 {
        negative_s_raw
    } else {
        s_raw
    };
    let encoding = builder_values(&builder, encoding_index)?;
    if encoding[0] & 1 == 1 {
        return Err(TexasAirError::SpecViolation(
            "Ristretto encode output is negative".into(),
        ));
    }

    let program = builder.finish(&[inverse_check, encoding_index])?;
    let proof = prove_ristretto_fp_program(&program)?;
    Ok(ArchivedRistrettoFpProgramPointEncodeProof {
        point,
        encoding,
        program: proof,
    })
}

/// Verify the fixed one-STARK canonical encode program and its branches.
pub fn verify_ristretto_fp_program_point_encode(
    archive: &ArchivedRistrettoFpProgramPointEncodeProof,
) -> TexasAirResult<()> {
    verify_ristretto_fp_program_point_decode(&archive.point)?;
    let program = &archive.program.program;
    let rotate = program.values[30][0] & 1 == 1;
    let selected_x = if rotate { 34 } else { 0 };
    let selected_y = if rotate { 32 } else { 1 };
    let selected_denominator = if rotate { 36 } else { 24 };
    let negate_y = program.values[40][0] & 1 == 1;
    let final_y = if negate_y { 38 } else { selected_y };
    let expected_ops = expected_encode_ops(selected_x, selected_y, selected_denominator, final_y);
    let encoding_index = if program.values[43][0] & 1 == 1 {
        44
    } else {
        43
    };
    let fixed_shape = program.values.len() == 45
        && program.ops.len() == 21
        && program.outputs == [20, encoding_index]
        && program.ops == expected_ops
        && program.values[0] == archive.point.x
        && program.values[1] == archive.point.y
        && program.values[2] == archive.point.t
        && program.values[4] == ONE_BYTES
        && program.values[5] == SQRT_M1_BYTES
        && program.values[6] == INVSQRT_A_MINUS_D_BYTES
        && program.values[37] == ZERO_BYTES
        && program.values[usize::from(encoding_index)] == archive.encoding;
    if !fixed_shape {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Ristretto encode program shape is detached".into(),
        ));
    }
    verify_ristretto_fp_program(&archive.program)?;

    let identity = archive.point.x == ZERO_BYTES
        && archive.point.y == ONE_BYTES
        && archive.point.t == ZERO_BYTES;
    if identity {
        if archive.encoding != ZERO_BYTES || program.values[20] != ZERO_BYTES {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "Ristretto identity encode is invalid".into(),
            ));
        }
        return Ok(());
    }
    if program.values[20] != ONE_BYTES
        || program.values[3][0] & 1 == 1
        || archive.encoding[0] & 1 == 1
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Ristretto encode inverse-root or output branch is invalid".into(),
        ));
    }
    Ok(())
}

fn expected_edwards_addition_ops() -> [RistrettoFpProgramOp; 16] {
    [
        RistrettoFpProgramOp::Subtract { a: 1, b: 0, out: 8 },
        RistrettoFpProgramOp::Subtract { a: 4, b: 3, out: 9 },
        RistrettoFpProgramOp::Add {
            a: 1,
            b: 0,
            out: 10,
        },
        RistrettoFpProgramOp::Add {
            a: 4,
            b: 3,
            out: 11,
        },
        RistrettoFpProgramOp::Multiply {
            a: 8,
            b: 9,
            out: 13,
            q: 12,
        },
        RistrettoFpProgramOp::Multiply {
            a: 10,
            b: 11,
            out: 15,
            q: 14,
        },
        RistrettoFpProgramOp::Multiply {
            a: 2,
            b: 5,
            out: 17,
            q: 16,
        },
        RistrettoFpProgramOp::Multiply {
            a: 7,
            b: 17,
            out: 19,
            q: 18,
        },
        RistrettoFpProgramOp::Subtract {
            a: 15,
            b: 13,
            out: 20,
        },
        RistrettoFpProgramOp::Subtract {
            a: 6,
            b: 19,
            out: 21,
        },
        RistrettoFpProgramOp::Add {
            a: 6,
            b: 19,
            out: 22,
        },
        RistrettoFpProgramOp::Add {
            a: 13,
            b: 15,
            out: 23,
        },
        RistrettoFpProgramOp::Multiply {
            a: 20,
            b: 21,
            out: 25,
            q: 24,
        },
        RistrettoFpProgramOp::Multiply {
            a: 22,
            b: 23,
            out: 27,
            q: 26,
        },
        RistrettoFpProgramOp::Multiply {
            a: 21,
            b: 22,
            out: 29,
            q: 28,
        },
        RistrettoFpProgramOp::Multiply {
            a: 20,
            b: 23,
            out: 31,
            q: 30,
        },
    ]
}

/// Prove unified extended-Edwards addition in one program STARK.
pub fn prove_ristretto_fp_program_edwards_addition(
    left: ArchivedRistrettoFpProgramPointDecodeProof,
    right: ArchivedRistrettoFpProgramPointDecodeProof,
) -> TexasAirResult<ArchivedRistrettoFpProgramEdwardsAdditionProof> {
    verify_ristretto_fp_program_point_decode(&left)?;
    verify_ristretto_fp_program_point_decode(&right)?;
    let mut builder =
        RistrettoFpProgramBuilder::new(&[left.x, left.y, left.t, right.x, right.y, right.t]);
    builder.constant(&TWO_BYTES)?;
    builder.constant(&EDWARDS_TWO_D_BYTES)?;

    let left_y_minus_x = builder.subtract(1, 0)?;
    let right_y_minus_x = builder.subtract(4, 3)?;
    let left_y_plus_x = builder.add(1, 0)?;
    let right_y_plus_x = builder.add(4, 3)?;
    let a = builder.multiply(left_y_minus_x, right_y_minus_x)?;
    let b = builder.multiply(left_y_plus_x, right_y_plus_x)?;
    let t_product = builder.multiply(2, 5)?;
    let c = builder.multiply(7, t_product)?;
    let e = builder.subtract(b, a)?;
    let f = builder.subtract(6, c)?;
    let g = builder.add(6, c)?;
    let h = builder.add(a, b)?;
    let x = builder.multiply(e, f)?;
    let y = builder.multiply(g, h)?;
    let z = builder.multiply(f, g)?;
    let t = builder.multiply(e, h)?;

    let x_bytes = builder_values(&builder, x)?;
    let y_bytes = builder_values(&builder, y)?;
    let z_bytes = builder_values(&builder, z)?;
    let t_bytes = builder_values(&builder, t)?;
    if z_bytes == ZERO_BYTES {
        return Err(TexasAirError::SpecViolation(
            "Edwards addition produced Z = 0".into(),
        ));
    }
    let program = builder.finish(&[x, y, z, t])?;
    let proof = prove_ristretto_fp_program(&program)?;
    Ok(ArchivedRistrettoFpProgramEdwardsAdditionProof {
        left,
        right,
        x: x_bytes,
        y: y_bytes,
        z: z_bytes,
        t: t_bytes,
        program: proof,
    })
}

/// Verify the fixed one-STARK Edwards addition program.
pub fn verify_ristretto_fp_program_edwards_addition(
    archive: &ArchivedRistrettoFpProgramEdwardsAdditionProof,
) -> TexasAirResult<()> {
    verify_ristretto_fp_program_point_decode(&archive.left)?;
    verify_ristretto_fp_program_point_decode(&archive.right)?;
    let program = &archive.program.program;
    let fixed_shape = program.values.len() == 32
        && program.ops.len() == 16
        && program.outputs == [25, 27, 29, 31]
        && program.ops == expected_edwards_addition_ops()
        && program.values[0] == archive.left.x
        && program.values[1] == archive.left.y
        && program.values[2] == archive.left.t
        && program.values[3] == archive.right.x
        && program.values[4] == archive.right.y
        && program.values[5] == archive.right.t
        && program.values[6] == TWO_BYTES
        && program.values[7] == EDWARDS_TWO_D_BYTES
        && program.values[25] == archive.x
        && program.values[27] == archive.y
        && program.values[29] == archive.z
        && program.values[31] == archive.t
        && archive.z != ZERO_BYTES;
    if !fixed_shape {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Ristretto Edwards addition program shape is detached".into(),
        ));
    }
    verify_ristretto_fp_program(&archive.program)
}

fn expected_projective_edwards_addition_ops() -> [RistrettoFpProgramOp; 18] {
    [
        RistrettoFpProgramOp::Subtract {
            a: 1,
            b: 0,
            out: 10,
        },
        RistrettoFpProgramOp::Subtract {
            a: 5,
            b: 4,
            out: 11,
        },
        RistrettoFpProgramOp::Add {
            a: 1,
            b: 0,
            out: 12,
        },
        RistrettoFpProgramOp::Add {
            a: 5,
            b: 4,
            out: 13,
        },
        RistrettoFpProgramOp::Multiply {
            a: 10,
            b: 11,
            out: 15,
            q: 14,
        },
        RistrettoFpProgramOp::Multiply {
            a: 12,
            b: 13,
            out: 17,
            q: 16,
        },
        RistrettoFpProgramOp::Multiply {
            a: 9,
            b: 3,
            out: 19,
            q: 18,
        },
        RistrettoFpProgramOp::Multiply {
            a: 19,
            b: 7,
            out: 21,
            q: 20,
        },
        RistrettoFpProgramOp::Multiply {
            a: 8,
            b: 2,
            out: 23,
            q: 22,
        },
        RistrettoFpProgramOp::Multiply {
            a: 23,
            b: 6,
            out: 25,
            q: 24,
        },
        RistrettoFpProgramOp::Subtract {
            a: 17,
            b: 15,
            out: 26,
        },
        RistrettoFpProgramOp::Subtract {
            a: 25,
            b: 21,
            out: 27,
        },
        RistrettoFpProgramOp::Add {
            a: 25,
            b: 21,
            out: 28,
        },
        RistrettoFpProgramOp::Add {
            a: 15,
            b: 17,
            out: 29,
        },
        RistrettoFpProgramOp::Multiply {
            a: 26,
            b: 27,
            out: 31,
            q: 30,
        },
        RistrettoFpProgramOp::Multiply {
            a: 28,
            b: 29,
            out: 33,
            q: 32,
        },
        RistrettoFpProgramOp::Multiply {
            a: 27,
            b: 28,
            out: 35,
            q: 34,
        },
        RistrettoFpProgramOp::Multiply {
            a: 26,
            b: 29,
            out: 37,
            q: 36,
        },
    ]
}

/// Wrap a verified decoded affine point as a general projective point.
pub fn ristretto_fp_program_projective_point_from_decode(
    point: ArchivedRistrettoFpProgramPointDecodeProof,
) -> TexasAirResult<ArchivedRistrettoFpProgramProjectivePoint> {
    verify_ristretto_fp_program_point_decode(&point)?;
    Ok(ArchivedRistrettoFpProgramProjectivePoint {
        x: point.x,
        y: point.y,
        z: ONE_BYTES,
        t: point.t,
        source: ArchivedRistrettoFpProgramProjectivePointSource::Decode(point),
    })
}

/// Verify the provenance and coordinates of a projective point.
pub fn verify_ristretto_fp_program_projective_point(
    point: &ArchivedRistrettoFpProgramProjectivePoint,
) -> TexasAirResult<()> {
    if point.z == ZERO_BYTES {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Ristretto projective point has Z = 0".into(),
        ));
    }
    match &point.source {
        ArchivedRistrettoFpProgramProjectivePointSource::Decode(decode) => {
            verify_ristretto_fp_program_point_decode(decode)?;
            if decode.x != point.x
                || decode.y != point.y
                || decode.t != point.t
                || point.z != ONE_BYTES
            {
                return Err(TexasAirError::ConstraintUnsatisfied(
                    "Ristretto decoded projective point is detached".into(),
                ));
            }
            Ok(())
        }
        ArchivedRistrettoFpProgramProjectivePointSource::Addition(addition) => {
            verify_ristretto_fp_program_projective_addition(addition)?;
            if addition.x != point.x
                || addition.y != point.y
                || addition.z != point.z
                || addition.t != point.t
            {
                return Err(TexasAirError::ConstraintUnsatisfied(
                    "Ristretto addition projective point is detached".into(),
                ));
            }
            Ok(())
        }
        ArchivedRistrettoFpProgramProjectivePointSource::Selector(selector) => {
            verify_ristretto_fp_program_point_selector(selector)?;
            if selector.x != point.x
                || selector.y != point.y
                || selector.z != point.z
                || selector.t != point.t
            {
                return Err(TexasAirError::ConstraintUnsatisfied(
                    "Ristretto selected projective point is detached".into(),
                ));
            }
            Ok(())
        }
        ArchivedRistrettoFpProgramProjectivePointSource::Table { table, index } => {
            verify_ristretto_fp_program_point_table(table)?;
            if *index >= 16 {
                return Err(TexasAirError::ConstraintUnsatisfied(
                    "Ristretto table point index is outside 0..15".into(),
                ));
            }
            let start = usize::from(*index) * 4;
            if table.coordinates[start] != point.x
                || table.coordinates[start + 1] != point.y
                || table.coordinates[start + 2] != point.z
                || table.coordinates[start + 3] != point.t
            {
                return Err(TexasAirError::ConstraintUnsatisfied(
                    "Ristretto table projective point is detached".into(),
                ));
            }
            Ok(())
        }
    }
}

/// Prove general projective extended-Edwards addition in one program STARK.
pub fn prove_ristretto_fp_program_projective_addition(
    left: ArchivedRistrettoFpProgramProjectivePoint,
    right: ArchivedRistrettoFpProgramProjectivePoint,
) -> TexasAirResult<ArchivedRistrettoFpProgramProjectiveAdditionProof> {
    verify_ristretto_fp_program_projective_point(&left)?;
    verify_ristretto_fp_program_projective_point(&right)?;
    let mut builder = RistrettoFpProgramBuilder::new(&[
        left.x, left.y, left.z, left.t, right.x, right.y, right.z, right.t,
    ]);
    builder.constant(&TWO_BYTES)?;
    builder.constant(&EDWARDS_TWO_D_BYTES)?;

    let left_y_minus_x = builder.subtract(1, 0)?;
    let right_y_minus_x = builder.subtract(5, 4)?;
    let left_y_plus_x = builder.add(1, 0)?;
    let right_y_plus_x = builder.add(5, 4)?;
    let a = builder.multiply(left_y_minus_x, right_y_minus_x)?;
    let b = builder.multiply(left_y_plus_x, right_y_plus_x)?;
    let two_d_left_t = builder.multiply(9, 3)?;
    let c = builder.multiply(two_d_left_t, 7)?;
    let two_left_z = builder.multiply(8, 2)?;
    let d = builder.multiply(two_left_z, 6)?;
    let e = builder.subtract(b, a)?;
    let f = builder.subtract(d, c)?;
    let g = builder.add(d, c)?;
    let h = builder.add(a, b)?;
    let x = builder.multiply(e, f)?;
    let y = builder.multiply(g, h)?;
    let z = builder.multiply(f, g)?;
    let t = builder.multiply(e, h)?;

    let x_bytes = builder_values(&builder, x)?;
    let y_bytes = builder_values(&builder, y)?;
    let z_bytes = builder_values(&builder, z)?;
    let t_bytes = builder_values(&builder, t)?;
    if z_bytes == ZERO_BYTES {
        return Err(TexasAirError::SpecViolation(
            "projective Edwards addition produced Z = 0".into(),
        ));
    }
    let program = builder.finish(&[x, y, z, t])?;
    let proof = prove_ristretto_fp_program(&program)?;
    Ok(ArchivedRistrettoFpProgramProjectiveAdditionProof {
        left,
        right,
        x: x_bytes,
        y: y_bytes,
        z: z_bytes,
        t: t_bytes,
        program: proof,
    })
}

/// Verify the fixed general projective Edwards addition program.
pub fn verify_ristretto_fp_program_projective_addition(
    archive: &ArchivedRistrettoFpProgramProjectiveAdditionProof,
) -> TexasAirResult<()> {
    verify_ristretto_fp_program_projective_point(&archive.left)?;
    verify_ristretto_fp_program_projective_point(&archive.right)?;
    let program = &archive.program.program;
    let fixed_shape = program.values.len() == 38
        && program.ops.len() == 18
        && program.outputs == [31, 33, 35, 37]
        && program.ops == expected_projective_edwards_addition_ops()
        && program.values[0] == archive.left.x
        && program.values[1] == archive.left.y
        && program.values[2] == archive.left.z
        && program.values[3] == archive.left.t
        && program.values[4] == archive.right.x
        && program.values[5] == archive.right.y
        && program.values[6] == archive.right.z
        && program.values[7] == archive.right.t
        && program.values[8] == TWO_BYTES
        && program.values[9] == EDWARDS_TWO_D_BYTES
        && program.values[31] == archive.x
        && program.values[33] == archive.y
        && program.values[35] == archive.z
        && program.values[37] == archive.t
        && archive.z != ZERO_BYTES;
    if !fixed_shape {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Ristretto projective addition program shape is detached".into(),
        ));
    }
    verify_ristretto_fp_program(&archive.program)
}

fn expected_point_table_layout() -> (Vec<RistrettoFpProgramOp>, Vec<u16>, usize) {
    let mut ops = Vec::new();
    let mut coordinates = (0..8u16).collect::<Vec<_>>();
    let mut next_value = 10u16;

    let base_y_minus_x = next_value;
    ops.push(RistrettoFpProgramOp::Subtract {
        a: 5,
        b: 4,
        out: base_y_minus_x,
    });
    next_value += 1;
    let base_y_plus_x = next_value;
    ops.push(RistrettoFpProgramOp::Add {
        a: 5,
        b: 4,
        out: base_y_plus_x,
    });
    next_value += 1;
    let mut previous = [4u16, 5, 6, 7];

    for multiple in 2..16u16 {
        let left_y_minus_x = next_value;
        ops.push(RistrettoFpProgramOp::Subtract {
            a: previous[1],
            b: previous[0],
            out: left_y_minus_x,
        });
        next_value += 1;
        let left_y_plus_x = next_value;
        ops.push(RistrettoFpProgramOp::Add {
            a: previous[1],
            b: previous[0],
            out: left_y_plus_x,
        });
        next_value += 1;

        let a_quotient = next_value;
        let a = a_quotient + 1;
        ops.push(RistrettoFpProgramOp::Multiply {
            a: left_y_minus_x,
            b: base_y_minus_x,
            out: a,
            q: a_quotient,
        });
        next_value = a + 1;

        let b_quotient = next_value;
        let b = b_quotient + 1;
        ops.push(RistrettoFpProgramOp::Multiply {
            a: left_y_plus_x,
            b: base_y_plus_x,
            out: b,
            q: b_quotient,
        });
        next_value = b + 1;

        let c_first_quotient = next_value;
        let c_first = c_first_quotient + 1;
        ops.push(RistrettoFpProgramOp::Multiply {
            a: 9,
            b: previous[3],
            out: c_first,
            q: c_first_quotient,
        });
        next_value = c_first + 1;
        let c_quotient = next_value;
        let c = c_quotient + 1;
        ops.push(RistrettoFpProgramOp::Multiply {
            a: c_first,
            b: 7,
            out: c,
            q: c_quotient,
        });
        next_value = c + 1;

        let d_first_quotient = next_value;
        let d_first = d_first_quotient + 1;
        ops.push(RistrettoFpProgramOp::Multiply {
            a: 8,
            b: previous[2],
            out: d_first,
            q: d_first_quotient,
        });
        next_value = d_first + 1;
        let d_quotient = next_value;
        let d = d_quotient + 1;
        ops.push(RistrettoFpProgramOp::Multiply {
            a: d_first,
            b: 6,
            out: d,
            q: d_quotient,
        });
        next_value = d + 1;

        let e = next_value;
        ops.push(RistrettoFpProgramOp::Subtract { a: b, b: a, out: e });
        next_value += 1;
        let f = next_value;
        ops.push(RistrettoFpProgramOp::Subtract { a: d, b: c, out: f });
        next_value += 1;
        let g = next_value;
        ops.push(RistrettoFpProgramOp::Add { a: d, b: c, out: g });
        next_value += 1;
        let h = next_value;
        ops.push(RistrettoFpProgramOp::Add { a: a, b: b, out: h });
        next_value += 1;

        let x_quotient = next_value;
        let x = x_quotient + 1;
        ops.push(RistrettoFpProgramOp::Multiply {
            a: e,
            b: f,
            out: x,
            q: x_quotient,
        });
        next_value = x + 1;
        let y_quotient = next_value;
        let y = y_quotient + 1;
        ops.push(RistrettoFpProgramOp::Multiply {
            a: g,
            b: h,
            out: y,
            q: y_quotient,
        });
        next_value = y + 1;
        let z_quotient = next_value;
        let z = z_quotient + 1;
        ops.push(RistrettoFpProgramOp::Multiply {
            a: f,
            b: g,
            out: z,
            q: z_quotient,
        });
        next_value = z + 1;
        let t_quotient = next_value;
        let t = t_quotient + 1;
        ops.push(RistrettoFpProgramOp::Multiply {
            a: e,
            b: h,
            out: t,
            q: t_quotient,
        });
        next_value = t + 1;

        let output = [x, y, z, t];
        coordinates.extend(output);
        previous = output;
        debug_assert_eq!(coordinates.len(), usize::from(multiple + 1) * 4);
    }

    let value_count = usize::from(next_value);
    (ops, coordinates, value_count)
}

/// Derive and prove a `0P..15P` table in one program STARK.
pub fn prove_ristretto_fp_program_point_table(
    base: ArchivedRistrettoFpProgramProjectivePoint,
) -> TexasAirResult<ArchivedRistrettoFpProgramPointTableProof> {
    verify_ristretto_fp_program_projective_point(&base)?;
    let mut builder = RistrettoFpProgramBuilder::new(&[
        ZERO_BYTES, ONE_BYTES, ONE_BYTES, ZERO_BYTES, base.x, base.y, base.z, base.t,
    ]);
    builder.constant(&TWO_BYTES)?;
    builder.constant(&EDWARDS_TWO_D_BYTES)?;

    let base_y_minus_x = builder.subtract(5, 4)?;
    let base_y_plus_x = builder.add(5, 4)?;
    let mut previous = [4u16, 5, 6, 7];
    let mut coordinates = Vec::with_capacity(64);
    coordinates.extend([0u16, 1, 2, 3, 4, 5, 6, 7]);

    for multiple in 2..16u16 {
        let left_y_minus_x = builder.subtract(previous[1], previous[0])?;
        let left_y_plus_x = builder.add(previous[1], previous[0])?;
        let a = builder.multiply(left_y_minus_x, base_y_minus_x)?;
        let b = builder.multiply(left_y_plus_x, base_y_plus_x)?;
        let c_first = builder.multiply(9, previous[3])?;
        let c = builder.multiply(c_first, 7)?;
        let d_first = builder.multiply(8, previous[2])?;
        let d = builder.multiply(d_first, 6)?;
        let e = builder.subtract(b, a)?;
        let f = builder.subtract(d, c)?;
        let g = builder.add(d, c)?;
        let h = builder.add(a, b)?;
        let x = builder.multiply(e, f)?;
        let y = builder.multiply(g, h)?;
        let z = builder.multiply(f, g)?;
        let t = builder.multiply(e, h)?;

        if builder_values(&builder, z)? == ZERO_BYTES {
            return Err(TexasAirError::SpecViolation(format!(
                "Ristretto table entry {multiple} produced Z = 0"
            )));
        }
        coordinates.extend([x, y, z, t]);
        previous = [x, y, z, t];
    }

    let (expected_ops, expected_coordinates, value_count) = expected_point_table_layout();
    let mut coordinate_values = [ZERO_BYTES; 64];
    for (index, coordinate) in expected_coordinates.iter().enumerate() {
        coordinate_values[index] = builder_values(&builder, *coordinate)?;
    }

    let program = builder.finish(&expected_coordinates)?;
    if program.values.len() != value_count
        || program.ops != expected_ops
        || program.outputs != expected_coordinates
    {
        return Err(TexasAirError::SpecViolation(
            "Ristretto point-table witness layout diverged".into(),
        ));
    }
    let proof = prove_ristretto_fp_program(&program)?;
    Ok(ArchivedRistrettoFpProgramPointTableProof {
        base,
        coordinates: coordinate_values,
        program: proof,
    })
}

/// Verify the fixed `0P..15P` table program and its public coordinates.
pub fn verify_ristretto_fp_program_point_table(
    archive: &ArchivedRistrettoFpProgramPointTableProof,
) -> TexasAirResult<()> {
    verify_ristretto_fp_program_projective_point(&archive.base)?;
    let (expected_ops, expected_coordinates, value_count) = expected_point_table_layout();
    let program = &archive.program.program;
    let fixed_shape = program.values.len() == value_count
        && program.ops == expected_ops
        && program.outputs == expected_coordinates
        && program.values[0] == ZERO_BYTES
        && program.values[1] == ONE_BYTES
        && program.values[2] == ONE_BYTES
        && program.values[3] == ZERO_BYTES
        && program.values[4] == archive.base.x
        && program.values[5] == archive.base.y
        && program.values[6] == archive.base.z
        && program.values[7] == archive.base.t
        && program.values[8] == TWO_BYTES
        && program.values[9] == EDWARDS_TWO_D_BYTES;
    if !fixed_shape {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Ristretto point-table program shape is detached".into(),
        ));
    }

    for (index, coordinate) in expected_coordinates.iter().enumerate() {
        if program.values[usize::from(*coordinate)] != archive.coordinates[index] {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "Ristretto point-table coordinate is detached".into(),
            ));
        }
    }
    for entry in 0..16 {
        if archive.coordinates[entry * 4 + 2] == ZERO_BYTES {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "Ristretto point-table entry has Z = 0".into(),
            ));
        }
    }
    verify_ristretto_fp_program(&archive.program)
}

/// Return an authenticated point from a verified `0..15` multiples table.
pub fn ristretto_fp_program_point_table_entry(
    table: ArchivedRistrettoFpProgramPointTableProof,
    index: u8,
) -> TexasAirResult<ArchivedRistrettoFpProgramProjectivePoint> {
    if index >= 16 {
        return Err(TexasAirError::SpecViolation(
            "Ristretto table index must fit in four bits".into(),
        ));
    }
    verify_ristretto_fp_program_point_table(&table)?;
    let start = usize::from(index) * 4;
    Ok(ArchivedRistrettoFpProgramProjectivePoint {
        x: table.coordinates[start],
        y: table.coordinates[start + 1],
        z: table.coordinates[start + 2],
        t: table.coordinates[start + 3],
        source: ArchivedRistrettoFpProgramProjectivePointSource::Table {
            table: Box::new(table),
            index,
        },
    })
}

/// Prove selection of one projective point from a 16-entry table.
pub fn prove_ristretto_fp_program_point_selector(
    table: [ArchivedRistrettoFpProgramProjectivePoint; 16],
    selector: u8,
) -> TexasAirResult<ArchivedRistrettoFpProgramPointSelectorProof> {
    if selector >= 16 {
        return Err(TexasAirError::SpecViolation(
            "Ristretto point-table selector must fit in four bits".into(),
        ));
    }
    let mut verified_points = std::collections::HashSet::new();
    for point in &table {
        let key = borsh::to_vec(point)
            .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
        if verified_points.insert(key) {
            verify_ristretto_fp_program_projective_point(point)?;
        }
    }

    let selected = table[usize::from(selector)].clone();
    Ok(ArchivedRistrettoFpProgramPointSelectorProof {
        table,
        selector,
        x: selected.x,
        y: selected.y,
        z: selected.z,
        t: selected.t,
    })
}

/// Verify a fixed 16-entry point-table selector program.
pub fn verify_ristretto_fp_program_point_selector(
    archive: &ArchivedRistrettoFpProgramPointSelectorProof,
) -> TexasAirResult<()> {
    if archive.selector >= 16 {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Ristretto point-table selector is outside 0..15".into(),
        ));
    }
    let mut verified_points = std::collections::HashSet::new();
    for point in &archive.table {
        let key = borsh::to_vec(point)
            .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
        if verified_points.insert(key) {
            verify_ristretto_fp_program_projective_point(point)?;
        }
    }

    let selected = &archive.table[usize::from(archive.selector)];
    if archive.x != selected.x
        || archive.y != selected.y
        || archive.z != selected.z
        || archive.t != selected.t
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Ristretto point-table output is detached".into(),
        ));
    }
    Ok(())
}

/// Append one unified projective Edwards addition to `builder`.
fn append_projective_addition(
    builder: &mut RistrettoFpProgramBuilder,
    left: [u16; 4],
    right: [u16; 4],
    two: u16,
    curve_d: u16,
) -> TexasAirResult<[u16; 4]> {
    let left_y_minus_x = builder.subtract(left[1], left[0])?;
    let right_y_minus_x = builder.subtract(right[1], right[0])?;
    let left_y_plus_x = builder.add(left[1], left[0])?;
    let right_y_plus_x = builder.add(right[1], right[0])?;
    let a = builder.multiply(left_y_minus_x, right_y_minus_x)?;
    let b = builder.multiply(left_y_plus_x, right_y_plus_x)?;
    let two_d_left_t = builder.multiply(two, left[3])?;
    let c = builder.multiply(two_d_left_t, curve_d)?;
    let two_left_z = builder.multiply(two, left[2])?;
    let d = builder.multiply(two_left_z, right[2])?;
    let e = builder.subtract(b, a)?;
    let f = builder.subtract(d, c)?;
    let g = builder.add(d, c)?;
    let h = builder.add(a, b)?;
    let x = builder.multiply(e, f)?;
    let y = builder.multiply(g, h)?;
    let z = builder.multiply(f, g)?;
    let t = builder.multiply(e, h)?;
    Ok([x, y, z, t])
}

fn fixed_window_program_shape() -> (usize, usize) {
    (FIXED_WINDOW_PROGRAM_VALUES, FIXED_WINDOW_PROGRAM_OPS)
}

fn ensure_fixed_window_program_supported() -> TexasAirResult<()> {
    let (value_count, op_count) = fixed_window_program_shape();
    if value_count > MAX_VALUES || op_count > MAX_OPS {
        return Err(TexasAirError::SpecViolation(format!(
            "generic fixed-window Fp program requires {value_count} values and {op_count} ops, exceeding the committed limits ({MAX_VALUES} values, {MAX_OPS} ops); use a dedicated scalar-multiplication AIR"
        )));
    }
    Ok(())
}

fn build_fixed_window_scalar_mul_program(
    windows: &[u8; 64],
    table: &ArchivedRistrettoFpProgramPointTableProof,
) -> TexasAirResult<(RistrettoFpProgram, [u16; 4])> {
    ensure_fixed_window_program_supported()?;
    let mut builder =
        RistrettoFpProgramBuilder::new(&[ZERO_BYTES, ONE_BYTES, ONE_BYTES, ZERO_BYTES]);
    let two = builder.constant(&TWO_BYTES)?;
    let curve_d = builder.constant(&EDWARDS_TWO_D_BYTES)?;
    let mut accumulator = [0u16, 1, 2, 3];

    // Horner evaluation: acc <- 16*acc + window*P, from the most significant
    // window to the least significant one.  Four doublings are deliberately
    // kept in the generic program until a dedicated doubling AIR is available.
    for window in windows.iter().rev() {
        for _ in 0..4 {
            accumulator =
                append_projective_addition(&mut builder, accumulator, accumulator, two, curve_d)?;
        }
        let start = usize::from(*window) * 4;
        let selected = [
            builder.constant(&table.coordinates[start])?,
            builder.constant(&table.coordinates[start + 1])?,
            builder.constant(&table.coordinates[start + 2])?,
            builder.constant(&table.coordinates[start + 3])?,
        ];
        accumulator =
            append_projective_addition(&mut builder, accumulator, selected, two, curve_d)?;
    }
    let program = builder.finish(&accumulator)?;
    Ok((program, accumulator))
}

/// Attempt to prove fixed-window scalar multiplication with one folded program STARK.
///
/// The generic backend currently returns a bounded-resource error for the full
/// 64-window shape; a dedicated scalar-multiplication AIR is required to prove
/// this statement.
pub fn prove_ristretto_fp_program_fixed_window_scalar_mul(
    scalar_windows: ArchivedRistrettoScalarWindowsProof,
    table: ArchivedRistrettoFpProgramPointTableProof,
) -> TexasAirResult<ArchivedRistrettoFpProgramFixedWindowScalarMulProof> {
    ensure_fixed_window_program_supported()?;
    verify_ristretto_scalar_windows(&scalar_windows)?;
    verify_ristretto_fp_program_point_table(&table)?;
    let (program, outputs) =
        build_fixed_window_scalar_mul_program(&scalar_windows.windows, &table)?;
    let x = program.values[usize::from(outputs[0])];
    let y = program.values[usize::from(outputs[1])];
    let z = program.values[usize::from(outputs[2])];
    let t = program.values[usize::from(outputs[3])];
    if z == ZERO_BYTES {
        return Err(TexasAirError::SpecViolation(
            "Ristretto fixed-window multiplication produced Z = 0".into(),
        ));
    }
    let proof = prove_ristretto_fp_program(&program)?;
    Ok(ArchivedRistrettoFpProgramFixedWindowScalarMulProof {
        scalar_windows,
        table,
        x,
        y,
        z,
        t,
        program: proof,
    })
}

/// Verify the fixed-window scalar multiplication statement and its full DAG.
///
/// This currently fails closed for the full shape until the dedicated AIR is
/// available, so no oversized generic proof can be admitted accidentally.
pub fn verify_ristretto_fp_program_fixed_window_scalar_mul(
    archive: &ArchivedRistrettoFpProgramFixedWindowScalarMulProof,
) -> TexasAirResult<()> {
    ensure_fixed_window_program_supported()?;
    verify_ristretto_scalar_windows(&archive.scalar_windows)?;
    verify_ristretto_fp_program_point_table(&archive.table)?;
    let (expected, outputs) =
        build_fixed_window_scalar_mul_program(&archive.scalar_windows.windows, &archive.table)?;
    if archive.program.program != expected
        || archive.x != expected.values[usize::from(outputs[0])]
        || archive.y != expected.values[usize::from(outputs[1])]
        || archive.z != expected.values[usize::from(outputs[2])]
        || archive.t != expected.values[usize::from(outputs[3])]
        || archive.z == ZERO_BYTES
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Ristretto fixed-window scalar multiplication program is detached".into(),
        ));
    }
    verify_ristretto_fp_program(&archive.program)
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
    fn program_canonicity_reuses_only_derived_values() {
        let mut builder = RistrettoFpProgramBuilder::new(&[small(2), small(3)]);
        let sum = builder.add(0, 1).unwrap();
        let product = builder.multiply(0, 1).unwrap();
        let difference = builder.subtract(0, 1).unwrap();
        let program = builder.finish(&[sum, product, difference]).unwrap();

        let canonicity = program_canonicity(&program).unwrap();
        assert_eq!(canonicity[0], ValueCanonicity::Witnessed);
        assert_eq!(canonicity[1], ValueCanonicity::Witnessed);
        assert_eq!(canonicity[2], ValueCanonicity::Derived);
        assert_eq!(canonicity[3], ValueCanonicity::Derived);
        assert_eq!(canonicity[4], ValueCanonicity::Witnessed);
        assert_eq!(canonicity[5], ValueCanonicity::Derived);
    }

    #[test]
    fn program_canonicity_rejects_non_dataflow_programs() {
        let forward_operand = RistrettoFpProgram {
            values: vec![small(0), small(0), small(0)],
            ops: vec![RistrettoFpProgramOp::Add { a: 2, b: 0, out: 1 }],
            outputs: vec![1],
        };
        assert!(program_canonicity(&forward_operand).is_err());

        let duplicate_output = RistrettoFpProgram {
            values: vec![small(0), small(0), small(0)],
            ops: vec![
                RistrettoFpProgramOp::Add { a: 0, b: 1, out: 2 },
                RistrettoFpProgramOp::Subtract { a: 0, b: 1, out: 2 },
            ],
            outputs: vec![2],
        };
        assert!(program_canonicity(&duplicate_output).is_err());
    }

    #[test]
    fn point_table_witness_plan_shares_derived_canonicality() {
        let (ops, outputs, value_count) = expected_point_table_layout();
        let program = RistrettoFpProgram {
            values: vec![ZERO_BYTES; value_count],
            ops: ops.clone(),
            outputs: outputs.clone(),
        };
        let canonicity = program_canonicity(&program).unwrap();

        assert_eq!(ops.len(), 226);
        assert_eq!(value_count, 376);
        assert_eq!(
            canonicity
                .iter()
                .filter(|kind| **kind == ValueCanonicity::Derived)
                .count(),
            226
        );
        assert_eq!(
            canonicity
                .iter()
                .filter(|kind| **kind == ValueCanonicity::Witnessed)
                .count(),
            150
        );
    }

    #[test]
    fn fixed_window_shape_is_explicitly_bounded() {
        assert_eq!(FIXED_WINDOW_COUNT, 64);
        assert_eq!(PROJECTIVE_ADDITIONS_PER_WINDOW, 5);
        assert_eq!(FIXED_WINDOW_ADDITION_COUNT, 320);
        assert_eq!(FIXED_WINDOW_PROGRAM_OPS, 5_760);
        assert_eq!(FIXED_WINDOW_PROGRAM_VALUES, 9_222);

        let (value_count, op_count) = fixed_window_program_shape();
        assert_eq!(value_count, 9_222);
        assert_eq!(op_count, 5_760);
        assert!(value_count > MAX_VALUES);
        assert!(op_count > MAX_OPS);
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
        assert_program_trace(&program, &trace);
    }

    fn assert_program_trace(program: &RistrettoFpProgram, trace: &MethodTrace) {
        let scope = scope_columns(program);
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
    #[should_panic]
    fn add_program_rejects_a_flipped_public_subtract_selector() {
        let mut builder = RistrettoFpProgramBuilder::new(&[small(2), small(3)]);
        let sum = builder.add(0, 1).unwrap();
        let program = builder.finish(&[sum]).unwrap();
        let mut trace = trace_columns(&program).unwrap();
        let strict_values = program_canonicity(&program)
            .unwrap()
            .into_iter()
            .filter(|kind| *kind == ValueCanonicity::Witnessed)
            .count();
        let op_witness_start = program.values.len() * LIMBS * 9 + strict_values * 385;
        assert_program_trace(&program, &trace);
        assert!(trace.cols.len() > op_witness_start);
        trace.cols[op_witness_start][0] = M31::from(1u32);
        assert_program_trace(&program, &trace);
    }

    #[test]
    #[should_panic]
    fn subtract_program_rejects_a_positive_reduction_sign() {
        let mut builder = RistrettoFpProgramBuilder::new(&[small(7), small(6)]);
        let difference = builder.subtract(0, 1).unwrap();
        let program = builder.finish(&[difference]).unwrap();
        let mut trace = trace_columns(&program).unwrap();
        let strict_values = program_canonicity(&program)
            .unwrap()
            .into_iter()
            .filter(|kind| *kind == ValueCanonicity::Witnessed)
            .count();
        let op_witness_start = program.values.len() * LIMBS * 9 + strict_values * 385;
        assert_program_trace(&program, &trace);
        assert!(trace.cols.len() > op_witness_start + 2);
        trace.cols[op_witness_start + 2][0] = M31::from(1u32);
        assert_program_trace(&program, &trace);
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
    fn folded_point_encode_restores_identity_and_basepoint() {
        let identity_decode = prove_ristretto_fp_program_point_decode(&ZERO_BYTES).unwrap();
        let identity = prove_ristretto_fp_program_point_encode(identity_decode).unwrap();
        assert_eq!(identity.encoding, ZERO_BYTES);
        verify_ristretto_fp_program_point_encode(&identity).unwrap();

        let base_decode = prove_ristretto_fp_program_point_decode(&basepoint()).unwrap();
        let base = prove_ristretto_fp_program_point_encode(base_decode).unwrap();
        assert_eq!(base.encoding, basepoint());
        verify_ristretto_fp_program_point_encode(&base).unwrap();
    }

    #[test]
    fn folded_point_encode_verifier_rejects_spliced_encoding() {
        let decode = prove_ristretto_fp_program_point_decode(&basepoint()).unwrap();
        let mut archive = prove_ristretto_fp_program_point_encode(decode).unwrap();
        archive.encoding[0] ^= 2;
        assert!(verify_ristretto_fp_program_point_encode(&archive).is_err());
    }

    #[test]
    fn folded_edwards_addition_proves_basepoint_doubling() {
        let left = prove_ristretto_fp_program_point_decode(&basepoint()).unwrap();
        let right = prove_ristretto_fp_program_point_decode(&basepoint()).unwrap();
        let archive = prove_ristretto_fp_program_edwards_addition(left, right).unwrap();
        assert_ne!(archive.x, ZERO_BYTES);
        assert_ne!(archive.z, ZERO_BYTES);
        verify_ristretto_fp_program_edwards_addition(&archive).unwrap();
    }

    #[test]
    fn folded_edwards_addition_verifier_rejects_spliced_output() {
        let left = prove_ristretto_fp_program_point_decode(&basepoint()).unwrap();
        let right = prove_ristretto_fp_program_point_decode(&basepoint()).unwrap();
        let mut archive = prove_ristretto_fp_program_edwards_addition(left, right).unwrap();
        archive.x[0] ^= 2;
        assert!(verify_ristretto_fp_program_edwards_addition(&archive).is_err());
    }

    #[test]
    fn folded_projective_addition_accepts_addition_outputs() {
        let left = ristretto_fp_program_projective_point_from_decode(
            prove_ristretto_fp_program_point_decode(&basepoint()).unwrap(),
        )
        .unwrap();
        let right = ristretto_fp_program_projective_point_from_decode(
            prove_ristretto_fp_program_point_decode(&basepoint()).unwrap(),
        )
        .unwrap();
        let doubled = prove_ristretto_fp_program_projective_addition(left, right).unwrap();
        verify_ristretto_fp_program_projective_addition(&doubled).unwrap();
        assert_ne!(doubled.z, ONE_BYTES);

        let doubled_point = ArchivedRistrettoFpProgramProjectivePoint {
            x: doubled.x,
            y: doubled.y,
            z: doubled.z,
            t: doubled.t,
            source: ArchivedRistrettoFpProgramProjectivePointSource::Addition(Box::new(doubled)),
        };
        let base = ristretto_fp_program_projective_point_from_decode(
            prove_ristretto_fp_program_point_decode(&basepoint()).unwrap(),
        )
        .unwrap();
        let triple = prove_ristretto_fp_program_projective_addition(doubled_point, base).unwrap();
        verify_ristretto_fp_program_projective_addition(&triple).unwrap();
    }

    #[test]
    fn folded_projective_addition_verifier_rejects_spliced_output() {
        let left = ristretto_fp_program_projective_point_from_decode(
            prove_ristretto_fp_program_point_decode(&basepoint()).unwrap(),
        )
        .unwrap();
        let right = ristretto_fp_program_projective_point_from_decode(
            prove_ristretto_fp_program_point_decode(&basepoint()).unwrap(),
        )
        .unwrap();
        let mut archive = prove_ristretto_fp_program_projective_addition(left, right).unwrap();
        archive.x[0] ^= 2;
        assert!(verify_ristretto_fp_program_projective_addition(&archive).is_err());
    }

    #[test]
    fn folded_point_selector_chooses_an_authenticated_table_entry() {
        let identity = ristretto_fp_program_projective_point_from_decode(
            prove_ristretto_fp_program_point_decode(&ZERO_BYTES).unwrap(),
        )
        .unwrap();
        let base = ristretto_fp_program_projective_point_from_decode(
            prove_ristretto_fp_program_point_decode(&basepoint()).unwrap(),
        )
        .unwrap();
        let mut table = std::array::from_fn(|_| identity.clone());
        table[1] = base;

        let archive = prove_ristretto_fp_program_point_selector(table.clone(), 1).unwrap();
        assert_eq!(archive.x, table[1].x);
        assert_eq!(archive.y, table[1].y);
        assert_eq!(archive.z, table[1].z);
        assert_eq!(archive.t, table[1].t);
        verify_ristretto_fp_program_point_selector(&archive).unwrap();

        let selected_point = ArchivedRistrettoFpProgramProjectivePoint {
            x: archive.x,
            y: archive.y,
            z: archive.z,
            t: archive.t,
            source: ArchivedRistrettoFpProgramProjectivePointSource::Selector(Box::new(archive)),
        };
        verify_ristretto_fp_program_projective_point(&selected_point).unwrap();
    }

    #[test]
    fn folded_point_selector_rejects_spliced_selector_and_output() {
        let identity = ristretto_fp_program_projective_point_from_decode(
            prove_ristretto_fp_program_point_decode(&ZERO_BYTES).unwrap(),
        )
        .unwrap();
        let base = ristretto_fp_program_projective_point_from_decode(
            prove_ristretto_fp_program_point_decode(&basepoint()).unwrap(),
        )
        .unwrap();
        let mut table = std::array::from_fn(|_| identity.clone());
        table[1] = base;

        let mut archive = prove_ristretto_fp_program_point_selector(table.clone(), 1).unwrap();
        archive.selector = 0;
        assert!(verify_ristretto_fp_program_point_selector(&archive).is_err());

        let mut archive = prove_ristretto_fp_program_point_selector(table, 1).unwrap();
        archive.x[0] ^= 2;
        assert!(verify_ristretto_fp_program_point_selector(&archive).is_err());
    }

    #[test]
    fn folded_point_table_derives_authenticated_multiples() {
        let base = ristretto_fp_program_projective_point_from_decode(
            prove_ristretto_fp_program_point_decode(&basepoint()).unwrap(),
        )
        .unwrap();
        let archive = prove_ristretto_fp_program_point_table(base).unwrap();
        verify_ristretto_fp_program_point_table(&archive).unwrap();

        assert_eq!(archive.coordinates[0], ZERO_BYTES);
        assert_eq!(archive.coordinates[1], ONE_BYTES);
        assert_eq!(archive.coordinates[2], ONE_BYTES);
        assert_eq!(archive.coordinates[3], ZERO_BYTES);
        assert_eq!(archive.coordinates[4], archive.base.x);
        assert_eq!(archive.coordinates[5], archive.base.y);
        assert_eq!(archive.coordinates[6], archive.base.z);
        assert_eq!(archive.coordinates[7], archive.base.t);

        let double = ristretto_fp_program_point_table_entry(archive, 2).unwrap();
        verify_ristretto_fp_program_projective_point(&double).unwrap();
    }

    #[test]
    fn folded_point_table_verifier_rejects_spliced_base_or_coordinate() {
        let base = ristretto_fp_program_projective_point_from_decode(
            prove_ristretto_fp_program_point_decode(&basepoint()).unwrap(),
        )
        .unwrap();
        let mut archive = prove_ristretto_fp_program_point_table(base).unwrap();
        archive.base.x[0] ^= 2;
        assert!(verify_ristretto_fp_program_point_table(&archive).is_err());

        archive.base.x[0] ^= 2;
        verify_ristretto_fp_program_point_table(&archive).unwrap();
        archive.coordinates[8][0] ^= 2;
        assert!(verify_ristretto_fp_program_point_table(&archive).is_err());
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
