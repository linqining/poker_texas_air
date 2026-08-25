//! Single-STARK Ristretto255 field-arithmetic program AIR.
//!
//! A program commits all canonical Fp values and a fixed list of add/sub/mul
//! operations.  Unlike composing one STARK per field operation, this module
//! places every canonical-limb witness and arithmetic relation in one trace and
//! creates one proof.  It is the folding substrate for the production point
//! codec, Edwards arithmetic, scalar multiplication, and later DLEQ/MSM AIRs.

#![allow(missing_docs)]

use bincode::Options;
use borsh::{BorshDeserialize, BorshSerialize};
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, Zero};
use rayon::prelude::*;
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
    EvalAtRow, FrameworkComponent, FrameworkEval, LogupTraceGenerator, Relation, RelationEntry,
    TraceLocationAllocator, relation,
};

use crate::error::{TexasAirError, TexasAirResult};
use crate::ristretto_scalar_windows_air::{
    ArchivedRistrettoScalarWindowsProof, verify_ristretto_scalar_windows,
};
use crate::trace_gen::MethodTrace;

const LIMBS: usize = 32;
/// Internal witness radix: each canonical value is proven as twenty-four
/// 11-bit limbs (`LIMB_COUNT * LIMB_BITS = 264 ≥ 256` bits).
const LIMB_COUNT: usize = 24;
const LIMB_BITS: u32 = 11;
const BASE: u32 = 1 << LIMB_BITS;
const PRODUCT_LIMBS: usize = 2 * LIMB_COUNT;
/// Domain floor for every program STARK.  The LogUp interaction generator
/// needs one SIMD vector row (`LOG_N_LANES = 4`) and the 2048-entry range
/// table stripes across `2048 >> log_size` column pairs below log 11, so
/// small domains are structurally supported.  The floor is pinned at 128 rows
/// for FRI soundness: with `log_blowup = 1`, 30 queries only carry their
/// nominal weight while the LDE domain comfortably exceeds the query count
/// (domain 256 → ~28 distinct positions vs ~29 at the old 256-row trace
/// floor); a 16-row floor would cap effective FRI security near 30 bits.
const LOG_SIZE: u32 = 7;
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

/// `2^256 − p` little-endian: `value + C < 2^256 ⟺ value < p`, proven by a
/// carry-chain adder with no per-limb nonzero/inverse flags.
const CANONICITY_COMPLEMENT_BYTES: [u8; LIMBS] = {
    let mut bytes = [0u8; LIMBS];
    bytes[0] = 0x13;
    bytes[31] = 0x80;
    bytes
};

/// Split a 32-byte little-endian value into `LIMB_COUNT` 11-bit limbs.
const fn base_limbs(bytes: &[u8; LIMBS]) -> [u16; LIMB_COUNT] {
    let mut out = [0u16; LIMB_COUNT];
    let mut limb_index = 0usize;
    while limb_index < LIMB_COUNT {
        let mut limb = 0u16;
        let mut bit = 0u32;
        while bit < LIMB_BITS {
            let global_bit = limb_index * LIMB_BITS as usize + bit as usize;
            let byte = global_bit / 8;
            if byte < LIMBS && (bytes[byte] >> (global_bit % 8)) & 1 == 1 {
                limb |= 1 << bit;
            }
            bit += 1;
        }
        out[limb_index] = limb;
        limb_index += 1;
    }
    out
}

fn to_limbs(value: &[u8; LIMBS]) -> [u16; LIMB_COUNT] {
    base_limbs(value)
}

/// `p = 2^255 − 19` as twenty-four 11-bit limbs.
const P_BASE_LIMBS: [u16; LIMB_COUNT] = base_limbs(&P_BYTES);
/// `2^256 − p` as twenty-four 11-bit limbs.
const CANONICITY_COMPLEMENT_LIMBS: [u16; LIMB_COUNT] =
    base_limbs(&CANONICITY_COMPLEMENT_BYTES);
/// Bound on a multiplication carry magnitude: `|carry| ≤ (2·L·(2^11−1)² +
/// terms) / 2^11 < 2^17`, so every magnitude splits into two range-checked
/// 11-bit limbs and every relation stays far below the M31 wraparound bound.
const MAX_MUL_CARRY_MAGNITUDE: u32 = 1 << 17;

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
    /// Public claimed sum of the shared range LogUp (4 M31 coordinates).
    pub range_claimed_sum: [u32; 4],
}

/// Multiple equal-shape field programs proven as rows of one STARK.
///
/// The in-memory representation intentionally keeps the existing `programs`
/// field so downstream statement checks remain explicit. Its Borsh wire format
/// is compact: the shared operation/output layout is serialized once, followed
/// by each row's values. The versioned format prevents old archives from being
/// silently interpreted as the compact representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchivedRistrettoFpProgramBatchProof {
    /// Public programs in canonical row order. All operation/output layouts
    /// are identical; only field values differ between rows.
    pub programs: Vec<RistrettoFpProgram>,
    /// Serialized Stwo proof for the complete batch.
    pub stark_proof_bytes: Vec<u8>,
    /// Public claimed sum of the shared range LogUp (4 M31 coordinates).
    pub range_claimed_sum: [u32; 4],
}

const FP_PROGRAM_BATCH_ARCHIVE_MAGIC: [u8; 4] = *b"RFPB";
const FP_PROGRAM_BATCH_ARCHIVE_VERSION: u8 = 1;

impl BorshSerialize for ArchivedRistrettoFpProgramBatchProof {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&FP_PROGRAM_BATCH_ARCHIVE_MAGIC)?;
        FP_PROGRAM_BATCH_ARCHIVE_VERSION.serialize(writer)?;
        let (ops, outputs) = self
            .programs
            .first()
            .map(|program| (program.ops.clone(), program.outputs.clone()))
            .unwrap_or_default();
        ops.serialize(writer)?;
        outputs.serialize(writer)?;
        let values: Vec<&Vec<[u8; LIMBS]>> = self
            .programs
            .iter()
            .map(|program| &program.values)
            .collect();
        values.serialize(writer)?;
        self.stark_proof_bytes.serialize(writer)?;
        self.range_claimed_sum.serialize(writer)
    }
}

impl BorshDeserialize for ArchivedRistrettoFpProgramBatchProof {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if magic != FP_PROGRAM_BATCH_ARCHIVE_MAGIC {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unsupported Ristretto Fp program batch archive format",
            ));
        }
        let version = u8::deserialize_reader(reader)?;
        if version != FP_PROGRAM_BATCH_ARCHIVE_VERSION {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unsupported Ristretto Fp program batch archive version {version}"),
            ));
        }
        let ops = Vec::<RistrettoFpProgramOp>::deserialize_reader(reader)?;
        let outputs = Vec::<u16>::deserialize_reader(reader)?;
        let values = Vec::<Vec<[u8; LIMBS]>>::deserialize_reader(reader)?;
        let stark_proof_bytes = Vec::<u8>::deserialize_reader(reader)?;
        let range_claimed_sum = <[u32; 4]>::deserialize_reader(reader)?;
        let programs = values
            .into_iter()
            .map(|values| RistrettoFpProgram {
                values,
                ops: ops.clone(),
                outputs: outputs.clone(),
            })
            .collect();
        Ok(Self {
            programs,
            stark_proof_bytes,
            range_claimed_sum,
        })
    }
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

/// Public canonical encoding of an authenticated projective Ristretto point.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoFpProgramProjectivePointEncodeProof {
    /// Authenticated projective input point.
    pub point: ArchivedRistrettoFpProgramProjectivePoint,
    /// Canonical nonnegative output encoding.
    pub encoding: [u8; LIMBS],
    /// One-STARK projective encode program.
    pub program: ArchivedRistrettoFpProgramProof,
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

/// One fixed-shape projective addition row without provenance recursion.
pub type RistrettoProjectiveCoordinates = [[u8; LIMBS]; 4];

/// Batch proof for projective Edwards additions whose input/output coordinates
/// are authenticated by the single equal-shape Fp-program batch.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoFpProgramProjectiveAdditionBatchProof {
    /// Public left projective coordinates in row order.
    pub left: Vec<RistrettoProjectiveCoordinates>,
    /// Public right projective coordinates in row order.
    pub right: Vec<RistrettoProjectiveCoordinates>,
    /// Public output projective coordinates in row order.
    pub output: Vec<RistrettoProjectiveCoordinates>,
    /// Equal-shape Fp-program batch proving every row.
    pub additions: ArchivedRistrettoFpProgramBatchProof,
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
    /// Canonical scalar (proof of its window decomposition owned by caller).
    pub scalar: [u8; LIMBS],
    /// Four-bit decomposition of `scalar`.
    pub windows: [u8; FIXED_WINDOW_COUNT],
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

/// Compressed-point fixed-window scalar multiplication in one equal-shape
/// addition batch.
///
/// Fifteen rows derive `1P..15P` from the canonical compressed identity, then
/// 320 rows perform 64 Horner windows with four doublings and one selected
/// table addition per window.  This avoids the oversized 5,760-operation
/// monolithic generic program while retaining one batch STARK.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoFpProgramCompressedFixedWindowScalarMulProof {
    /// Canonical scalar and its four-bit decomposition (proof owned by caller).
    pub scalar: [u8; LIMBS],
    /// Four-bit decomposition of `scalar`.
    pub windows: [u8; FIXED_WINDOW_COUNT],
    /// Canonical compressed base point, including the Ristretto identity.
    pub base: [u8; LIMBS],
    /// Canonical compressed scalar-multiplication output.
    pub output: [u8; LIMBS],
    /// Exactly 335 equal-shape compressed-point addition rows.
    pub additions: ArchivedRistrettoFpProgramBatchProof,
}

/// One public compressed scalar-multiplication statement inside a shared batch.
///
/// The four-bit decomposition is carried as statement data only: its proof is
/// owned by the caller (a per-scalar `ArchivedRistrettoScalarWindowsProof` or
/// one shared batched window proof), so batches need not embed one small
/// STARK per scalar.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RistrettoCompressedFixedWindowScalarMulStatement {
    /// Canonical scalar.
    pub scalar: [u8; LIMBS],
    /// Four-bit decomposition of `scalar`.
    pub windows: [u8; FIXED_WINDOW_COUNT],
    /// Canonical compressed base point, including the Ristretto identity.
    pub base: [u8; LIMBS],
    /// Canonical compressed output point.
    pub output: [u8; LIMBS],
}

/// Multiple compressed scalar multiplications sharing one point-addition STARK.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoFpProgramCompressedFixedWindowScalarMulBatchProof {
    /// Public statements in canonical caller-defined order.
    pub statements: Vec<RistrettoCompressedFixedWindowScalarMulStatement>,
    /// Concatenated 335-row schedules for all statements.
    pub additions: ArchivedRistrettoFpProgramBatchProof,
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
        let (quotient, remainder) = product.div_rem(modulus());
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
        if big_uint(&value) >= *modulus() {
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

/// A multiplication carry: boolean sign plus a magnitude below
/// `MAX_MUL_CARRY_MAGNITUDE`, witnessed as two 11-bit limbs.
#[derive(Clone, Copy)]
struct SignedLimbCarry {
    negative: bool,
    magnitude: u32,
}

#[derive(Clone)]
enum OpWitness {
    Add {
        subtract: bool,
        k: SignedMagnitude,
        carries: Vec<SignedMagnitude>,
    },
    Multiply {
        carries: Vec<SignedLimbCarry>,
    },
}

#[derive(Clone)]
struct ProgramWitness {
    /// Per witnessed value: the 11-bit limbs of `value + (2^256 − p)` and
    /// their boolean carries, all `< 2^256` exactly when `value < p`.
    canonicity: Vec<Option<([u16; LIMB_COUNT], [u16; LIMB_COUNT])>>,
    /// The per-value canonicity classification already derived while
    /// building this witness, so callers do not recompute it.
    value_canonicity: Vec<ValueCanonicity>,
    /// The per-value 11-bit limb decomposition, reused by trace generation.
    value_limbs: Vec<[u16; LIMB_COUNT]>,
    op_witnesses: Vec<OpWitness>,
}

/// Shared single-limb (11-bit) range table LogUp relation for Fp program
/// limbs: each entry ranges one limb column over the 2048 radix values,
/// keeping one interaction entry per limb.
relation!(FpRange11, 1);

/// Paired (lo, hi) 11-bit-limb LogUp relation for multiplication carries:
/// every magnitude below `2^17` splits as `lo + 2048·hi` with `lo < 2048`
/// and `hi < 64`, so one arity-2 entry ranges the full carry against a
/// 131,072-entry striped pair table.
relation!(FpCarry17, 2);

#[derive(Clone)]
struct FpProgramAir {
    log_size: u32,
    program: RistrettoFpProgram,
    range: FpRange11,
    carry: FpCarry17,
    /// Precomputed preprocessed scope-column identifiers (built once instead
    /// of one `format!` allocation per value per evaluate pass).
    scope_ids: Vec<PreProcessedColumnId>,
    /// Precomputed value canonicity classes.
    canonicity: Vec<ValueCanonicity>,
}

impl FpProgramAir {
    /// Build the AIR, precomputing the preprocessed-column identifiers and
    /// the canonicity classification shared by every evaluate call.
    fn new(
        log_size: u32,
        program: RistrettoFpProgram,
        range: FpRange11,
        carry: FpCarry17,
    ) -> Self {
        let scope_ids = preprocessed_ids(&program);
        let canonicity = program_canonicity(&program)
            .expect("program was validated before proving or verifying");
        Self {
            log_size,
            program,
            range,
            carry,
            scope_ids,
            canonicity,
        }
    }

    /// Number of table stripes: the 2048-entry limb range table is striped
    /// across `2048 >> log_size` stripes, one entry per row per stripe
    /// (`t * 2^log_size + row`), each stripe holding one multiplicity and
    /// one limb value column, with inert values (and zero multiplicity)
    /// beyond 2047.
    fn table_stripes(&self) -> usize {
        range_table_stripes(self.log_size)
    }

    /// Number of pair-table stripes: the 131,072-entry carry table is striped
    /// across `131072 >> log_size` stripes, each holding one multiplicity and
    /// one `(lo, hi)` value-column pair.
    fn carry_table_stripes(&self) -> usize {
        carry_table_stripes(self.log_size)
    }
}

/// Number of `(multiplicity, value)` table stripes for an 11-bit limb range
/// table over a `2^log_size` row domain.
fn range_table_stripes(log_size: u32) -> usize {
    (2048usize >> log_size.min(11)).max(1)
}

/// Number of `(multiplicity, lo, hi)` table stripes for the 17-bit carry
/// pair table over a `2^log_size` row domain.
fn carry_table_stripes(log_size: u32) -> usize {
    (131_072usize >> log_size.min(17)).max(1)
}

static MODULUS: std::sync::OnceLock<BigUint> = std::sync::OnceLock::new();

fn modulus() -> &'static BigUint {
    MODULUS.get_or_init(|| (BigUint::one() << 255u32) - BigUint::from(19u32))
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

/// Production `prove_*` entry points default to emitting archives without a
/// trailing full self-verification: admission always verifies independently,
/// and the belt-and-braces check roughly doubles proving latency.  Set
/// `TEXAS_RISTRETTO_SELF_VERIFY=1` to restore it (CI / debugging).
pub(crate) fn ristretto_self_verify_enabled() -> bool {
    std::env::var("TEXAS_RISTRETTO_SELF_VERIFY").as_deref() == Ok("1")
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

/// Limb-wise witness that `value < p`: the sum limbs and boolean carries of
/// `value + (2^256 − p)`, which stays below `2^256` exactly when `value < p`.
fn canonicity_witness(
    value: &[u16; LIMB_COUNT],
) -> ([u16; LIMB_COUNT], [u16; LIMB_COUNT]) {
    let mut sum = [0u16; LIMB_COUNT];
    let mut carries = [0u16; LIMB_COUNT];
    let mut carry_in = 0u16;
    for index in 0..LIMB_COUNT {
        let total = value[index] + CANONICITY_COMPLEMENT_LIMBS[index] + carry_in;
        sum[index] = total % BASE as u16;
        carry_in = total / BASE as u16;
        carries[index] = carry_in;
    }
    debug_assert_eq!(carry_in, 0, "value < p plus its complement stays below 2^256");
    (sum, carries)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValueCanonicity {
    /// A root/constant or arithmetic result carrying its own strict witness.
    Witnessed,
    /// Canonicality follows from a multiplication quotient relation.
    Derived,
}

fn program_canonicity(program: &RistrettoFpProgram) -> TexasAirResult<Vec<ValueCanonicity>> {
    let mut produced = vec![false; program.values.len()];
    for op in &program.ops {
        let (a, b, first_output, second_output) = match *op {
            RistrettoFpProgramOp::Add { a, b, out }
            | RistrettoFpProgramOp::Subtract { a, b, out } => (a, b, out, None),
            RistrettoFpProgramOp::Multiply { a, b, out, q } => {
                if q >= out {
                    return Err(TexasAirError::SpecViolation(
                        "Fp program multiplication values are not in quotient/output order".into(),
                    ));
                }
                (a, b, q, Some(out))
            }
        };
        for index in [a, b, first_output].into_iter().chain(second_output) {
            if usize::from(index) >= program.values.len() {
                return Err(TexasAirError::SpecViolation(
                    "Fp program operation index is out of bounds".into(),
                ));
            }
        }
        if a >= first_output
            || b >= first_output
            || second_output.is_some_and(|output| a >= output || b >= output)
        {
            return Err(TexasAirError::SpecViolation(
                "Fp program operation consumes a non-earlier value".into(),
            ));
        }
        for output in std::iter::once(first_output).chain(second_output) {
            if std::mem::replace(&mut produced[usize::from(output)], true) {
                return Err(TexasAirError::SpecViolation(
                    "Fp program defines a value more than once".into(),
                ));
            }
        }
    }

    let mut canonicity = vec![ValueCanonicity::Witnessed; program.values.len()];
    let mut available = produced
        .iter()
        .map(|is_output| !is_output)
        .collect::<Vec<_>>();
    for op in &program.ops {
        let (a, b) = match *op {
            RistrettoFpProgramOp::Add { a, b, .. }
            | RistrettoFpProgramOp::Subtract { a, b, .. }
            | RistrettoFpProgramOp::Multiply { a, b, .. } => (a, b),
        };
        if !available[usize::from(a)] || !available[usize::from(b)] {
            return Err(TexasAirError::SpecViolation(
                "Fp program operation consumes a value produced by a later operation".into(),
            ));
        }
        match *op {
            RistrettoFpProgramOp::Add { out, .. } | RistrettoFpProgramOp::Subtract { out, .. } => {
                // The modular relation alone does not determine whether the
                // prover chose the reduced representative, so add/sub outputs
                // retain their direct `< p` witness.
                available[usize::from(out)] = true;
            }
            RistrettoFpProgramOp::Multiply { out, q, .. } => {
                // The multiplication output retains a direct `< p` witness.
                // Since a,b,out < p and a*b = out + q*p exactly, a*b < p^2
                // implies q < p without a second strict witness.
                canonicity[usize::from(q)] = ValueCanonicity::Derived;
                available[usize::from(q)] = true;
                available[usize::from(out)] = true;
            }
        }
    }
    Ok(canonicity)
}

fn program_witness(program: &RistrettoFpProgram) -> TexasAirResult<ProgramWitness> {
    validate_indices(program.values.len(), program.ops.len(), &program.outputs)?;
    let canonicity = program_canonicity(program)?;
    let value_limbs = program
        .values
        .iter()
        .map(|value| to_limbs(value))
        .collect::<Vec<_>>();
    let mut canonicity_witnesses = Vec::with_capacity(program.values.len());
    // One BigUint conversion per value up front: the op loop below used to
    // re-convert operands (and re-derive products the builder already
    // computed) on every operation.
    let value_ints = program
        .values
        .iter()
        .map(|value| big_uint(value))
        .collect::<Vec<_>>();
    for value_index in 0..program.values.len() {
        if value_ints[value_index] >= *modulus() {
            return Err(TexasAirError::SpecViolation(
                "Fp program value is noncanonical".into(),
            ));
        }
        canonicity_witnesses.push(if canonicity[value_index] == ValueCanonicity::Witnessed {
            Some(canonicity_witness(&value_limbs[value_index]))
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
                // Indices were already validated by `validate_indices`.
                let (a, b, out) = (usize::from(a), usize::from(b), usize::from(out));
                // The builder already guarantees the modular relation, so the
                // independent BigUint re-derivation only runs in debug builds.
                #[cfg(debug_assertions)]
                {
                    let expected = if subtract {
                        subtract_big(&value_ints[a], &value_ints[b])
                    } else {
                        add_big(&value_ints[a], &value_ints[b])
                    };
                    if limbs(&expected) != program.values[out] {
                        return Err(TexasAirError::SpecViolation(
                            "Fp program addition/subtraction relation is invalid".into(),
                        ));
                    }
                }

                let a_limbs = &value_limbs[a];
                let b_limbs = &value_limbs[b];
                let out_limbs = &value_limbs[out];
                let a_int = &value_ints[a];
                let b_int = &value_ints[b];
                let (k_negative, k_magnitude) = if subtract {
                    (a_int < b_int, a_int < b_int)
                } else {
                    (false, a_int + b_int >= *modulus())
                };
                let mut carry_in: i64 = 0;
                let mut carries = Vec::with_capacity(LIMB_COUNT);
                for index in 0..LIMB_COUNT {
                    let signed_b = if subtract {
                        -i64::from(b_limbs[index])
                    } else {
                        i64::from(b_limbs[index])
                    };
                    let signed_k = if k_negative && k_magnitude {
                        -1i64
                    } else if !k_negative && k_magnitude {
                        1
                    } else {
                        0
                    };
                    let difference = i64::from(a_limbs[index]) + signed_b + carry_in
                        - i64::from(out_limbs[index])
                        - signed_k * i64::from(P_BASE_LIMBS[index]);
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
                // Indices were already validated by `validate_indices`.
                let (a, b, out, q) = (
                    usize::from(a),
                    usize::from(b),
                    usize::from(out),
                    usize::from(q),
                );
                // The builder already derived the product and quotient, so the
                // BigUint `div_rem` cross-check only runs in debug builds.
                #[cfg(debug_assertions)]
                {
                    let product = &value_ints[a] * &value_ints[b];
                    let (expected_q, expected_out) = product.div_rem(modulus());
                    if limbs(&expected_q) != program.values[q]
                        || limbs(&expected_out) != program.values[out]
                    {
                        return Err(TexasAirError::SpecViolation(
                            "Fp program multiplication relation is invalid".into(),
                        ));
                    }
                }

                let product_limbs = convolution(&value_limbs[a], &value_limbs[b]);
                let quotient_prime_limbs = convolution(&value_limbs[q], &P_BASE_LIMBS);
                let out_limbs = &value_limbs[out];
                let mut carry_in: i64 = 0;
                let mut carries = Vec::with_capacity(PRODUCT_LIMBS - 1);
                for limb_index in 0..PRODUCT_LIMBS {
                    let output_limb = if limb_index < LIMB_COUNT {
                        i64::from(out_limbs[limb_index])
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
                        if carry_out.unsigned_abs() > u64::from(MAX_MUL_CARRY_MAGNITUDE) {
                            return Err(TexasAirError::SpecViolation(
                                "Fp multiplication carry exceeds its 17-bit bound".into(),
                            ));
                        }
                        carries.push(SignedLimbCarry {
                            negative: carry_out < 0,
                            magnitude: carry_out.unsigned_abs() as u32,
                        });
                        carry_in = carry_out;
                    }
                }
                op_witnesses.push(OpWitness::Multiply { carries });
            }
        }
    }
    Ok(ProgramWitness {
        canonicity: canonicity_witnesses,
        value_canonicity: canonicity,
        value_limbs,
        op_witnesses,
    })
}

fn convolution(left: &[u16; LIMB_COUNT], right: &[u16; LIMB_COUNT]) -> Vec<i64> {
    let mut out = vec![0i64; PRODUCT_LIMBS];
    for (left_index, left_limb) in left.iter().enumerate() {
        for (right_index, right_limb) in right.iter().enumerate() {
            out[left_index + right_index] += i64::from(*left_limb) * i64::from(*right_limb);
        }
    }
    out
}

static SQRT_M1: std::sync::OnceLock<BigUint> = std::sync::OnceLock::new();

fn sqrt_m1() -> BigUint {
    SQRT_M1
        .get_or_init(|| {
            BigUint::from(2u32).modpow(&((modulus() - BigUint::one()) >> 2u32), modulus())
        })
        .clone()
}

/// Even-root square root on `curve25519_dalek` field elements.
///
/// Uses dalek's single-chain `sqrt_ratio_i(value, 1)` (one `(p-5)/8`
/// exponentiation) instead of a BigUint `(p+3)/8` chain with a `sqrt(-1)`
/// retry.  The returned root satisfies `root * root == value` exactly when
/// `value` is a square, and its canonical bytes are always even, matching the
/// previous BigUint witness byte for byte.
fn nonnegative_sqrt_fe(value: &fp25519::Fe) -> Option<fp25519::Fe> {
    if value.is_zero() {
        return Some(*value);
    }
    let sqrt_m1 = fp25519::Fe::from_bytes(&SQRT_M1_BYTES);
    let mut root = fp25519::Fe::sqrt_ratio_i(value, &fp25519::Fe::one());
    if root.square().to_bytes() != value.to_bytes() {
        // The raw chain landed on `sqrt(-value)`; retry with `sqrt(-1)`,
        // exactly like the legacy two-chain fallback.
        root = root.mul(&sqrt_m1);
        if root.square().to_bytes() != value.to_bytes() {
            return None;
        }
    }
    if root.to_bytes()[0] & 1 == 1 {
        root = root.neg();
    }
    Some(root)
}

fn nonnegative_sqrt(value: &BigUint) -> Option<BigUint> {
    if value.is_zero() {
        return Some(BigUint::from(0u32));
    }
    let root = nonnegative_sqrt_fe(&fp25519::Fe::from_bytes(&limbs(value)))?;
    Some(BigUint::from_bytes_le(&root.to_bytes()))
}

fn append_limb(row: &mut Vec<M31>, limb: u16) {
    // 11-bit limb; range membership is proven by the shared LogUp table.
    row.push(M31::from(u32::from(limb)));
}

/// Column indices of every LogUp use entry in one program row, in the exact
/// order the AIR emits the corresponding relation entries (value limbs and
/// witnessed canonicity sum limbs as single-limb entries, then per-mul-carry
/// `(low, high)` limb pairs).
fn trace_row_with_limbs(
    program: &RistrettoFpProgram,
) -> TexasAirResult<(Vec<M31>, Vec<usize>, Vec<[usize; 2]>)> {
    let mut row = Vec::new();
    let mut limb_columns = Vec::new();
    let mut carry_pair_columns = Vec::new();
    let mut track_limb = |row: &mut Vec<M31>, limb_columns: &mut Vec<usize>, limb: u16| {
        limb_columns.push(row.len());
        append_limb(row, limb);
    };
    let witness = program_witness(program)?;
    for (value_index, value_limbs) in witness.value_limbs.iter().enumerate() {
        for &limb in value_limbs {
            track_limb(&mut row, &mut limb_columns, limb);
        }
        if witness.value_canonicity[value_index] == ValueCanonicity::Witnessed {
            let (sum, carries) = witness.canonicity[value_index]
                .expect("witnessed values carry a canonicity limb witness");
            for limb in sum {
                track_limb(&mut row, &mut limb_columns, limb);
            }
            for carry in carries {
                row.push(M31::from(u32::from(carry)));
            }
            // Three boolean bits keep the top sum limb below eight, i.e. the
            // 264-bit limb sum below `2^256`.
            for bit in 0..3 {
                let bit_value = (sum[LIMB_COUNT - 1] >> bit) & 1;
                row.push(M31::from(u32::from(bit_value)));
            }
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
                    row.push(M31::from(u32::from(carry.negative)));
                    row.push(M31::from(u32::from(carry.magnitude)));
                }
            }
            OpWitness::Multiply { carries } => {
                for carry in carries {
                    row.push(M31::from(u32::from(carry.negative)));
                    let low_index = row.len();
                    append_limb(&mut row, (carry.magnitude & (BASE - 1)) as u16);
                    let high_index = row.len();
                    append_limb(&mut row, (carry.magnitude >> LIMB_BITS) as u16);
                    carry_pair_columns.push([low_index, high_index]);
                }
            }
        }
    }
    Ok((row, limb_columns, carry_pair_columns))
}

fn trace_row(program: &RistrettoFpProgram) -> TexasAirResult<Vec<M31>> {
    Ok(trace_row_with_limbs(program)?.0)
}

/// Shape-only mirror of [`trace_row_with_limbs`]: returns the program-row
/// width, the single-limb LogUp column indices, and the carry-pair column
/// index pairs without materializing any BigUint witness.  The layout
/// depends only on the value count, the canonicity pattern, and the op list,
/// so verifiers use it to size the trace commitment without re-deriving the
/// (constraint-enforced) witness.
fn trace_layout(program: &RistrettoFpProgram) -> TexasAirResult<(usize, Vec<usize>, Vec<[usize; 2]>)> {
    validate_indices(program.values.len(), program.ops.len(), &program.outputs)?;
    let canonicity = program_canonicity(program)?;
    let mut width = 0usize;
    let mut limb_columns = Vec::new();
    let mut carry_pair_columns = Vec::new();
    for value_index in 0..program.values.len() {
        for _ in 0..LIMB_COUNT {
            limb_columns.push(width);
            width += 1;
        }
        if canonicity[value_index] == ValueCanonicity::Witnessed {
            for _ in 0..LIMB_COUNT {
                limb_columns.push(width);
                width += 1;
            }
            width += LIMB_COUNT + 3;
        }
    }
    for op in &program.ops {
        match *op {
            RistrettoFpProgramOp::Add { .. } | RistrettoFpProgramOp::Subtract { .. } => {
                width += 3 + 2 * LIMB_COUNT;
            }
            RistrettoFpProgramOp::Multiply { .. } => {
                for _ in 0..(PRODUCT_LIMBS - 1) {
                    width += 1;
                    let low_index = width;
                    width += 1;
                    let high_index = width;
                    width += 1;
                    carry_pair_columns.push([low_index, high_index]);
                }
            }
        }
    }
    Ok((width, limb_columns, carry_pair_columns))
}

fn trace_columns(program: &RistrettoFpProgram) -> TexasAirResult<MethodTrace> {
    let (row, limb_columns, carry_pair_columns) = trace_row_with_limbs(program)?;
    let program_width = row.len();
    let table_columns = range_table_column_count(LOG_SIZE);
    // Column-wise materialization: the single program row is replicated with
    // one `vec![value; rows]` pass per column (no zero-fill, no per-row clone
    // and strided scatter); table columns are filled wholesale below.
    let rows = 1usize << LOG_SIZE;
    let mut trace = MethodTrace::new_unfilled(LOG_SIZE, program_width + table_columns);
    for (column_index, value) in row.into_iter().enumerate() {
        trace.set_column(column_index, vec![value; rows]);
    }
    append_range_table_columns(
        &mut trace,
        LOG_SIZE,
        &limb_columns,
        &carry_pair_columns,
        program_width,
    );
    Ok(trace)
}

/// Scope columns pack two 11-bit limbs per M31 column (< 2^22), shrinking
/// the preprocessed tree and the Fiat--Shamir absorption.
const SCOPE_LIMBS_PER_COLUMN: usize = 2;
const SCOPE_COLUMNS_PER_VALUE: usize = LIMB_COUNT / SCOPE_LIMBS_PER_COLUMN;

fn scope_packed(value: &[u8; LIMBS]) -> Vec<u32> {
    to_limbs(value)
        .chunks(SCOPE_LIMBS_PER_COLUMN)
        .map(|chunk| u32::from(chunk[0]) + BASE * u32::from(chunk[1]))
        .collect()
}

fn scope_row(program: &RistrettoFpProgram) -> Vec<M31> {
    let mut row = Vec::with_capacity(program.values.len() * SCOPE_COLUMNS_PER_VALUE);
    for value in &program.values {
        row.extend(scope_packed(value).into_iter().map(M31::from));
    }
    row
}

fn scope_columns(program: &RistrettoFpProgram) -> MethodTrace {
    let row = scope_row(program);
    let rows = 1usize << LOG_SIZE;
    // Replicate the single scope row column-wise: one fill per column.
    MethodTrace::from_columns(
        LOG_SIZE,
        row.into_iter().map(|value| vec![value; rows]).collect(),
    )
}

fn batch_log_size(program_count: usize) -> TexasAirResult<u32> {
    if program_count == 0 {
        return Err(TexasAirError::SpecViolation(
            "Fp program batch must not be empty".into(),
        ));
    }
    // Floor of 128 rows: the LogUp trace generator needs at least one SIMD
    // vector row, and the single-table layout assumes the full 2048-entry
    // range table stripes cleanly across the domain.
    Ok(program_count.max(1 << LOG_SIZE).next_power_of_two().ilog2())
}

fn validate_program_batch_shape(programs: &[RistrettoFpProgram]) -> TexasAirResult<()> {
    let template = programs
        .first()
        .ok_or_else(|| TexasAirError::SpecViolation("Fp program batch must not be empty".into()))?;
    validate_indices(template.values.len(), template.ops.len(), &template.outputs)?;
    for program in programs {
        validate_indices(program.values.len(), program.ops.len(), &program.outputs)?;
        if program.values.len() != template.values.len()
            || program.ops != template.ops
            || program.outputs != template.outputs
        {
            return Err(TexasAirError::SpecViolation(
                "Fp program batch rows do not share one fixed shape".into(),
            ));
        }
    }
    Ok(())
}

/// Tracked LogUp column indices (singles, then carry pairs) shared by every
/// row of an equal-shape batch; recomputed from the template shape.
fn trace_tracked_columns(program: &RistrettoFpProgram) -> (Vec<usize>, Vec<[usize; 2]>) {
    // Shape-only derivation: `trace_layout` mirrors the column indices of
    // `trace_row_with_limbs` without materializing any BigUint witness.
    let (_, limb_columns, carry_pair_columns) = trace_layout(program)
        .expect("program shape was validated before trace generation");
    (limb_columns, carry_pair_columns)
}

fn range_table_column_count(log_size: u32) -> usize {
    2 * range_table_stripes(log_size) + 3 * carry_table_stripes(log_size)
}

/// Append and fill the shared LogUp table columns: first the 2048-entry
/// single-limb table (stripes of `(multiplicity, value)`), then the
/// 131,072-entry carry pair table (stripes of `(multiplicity, lo, hi)`,
/// entry `t · 2^log_size + row = lo + 2048·hi`).  Entries beyond each table
/// size carry inert values and zero multiplicity.
fn append_range_table_columns(
    trace: &mut MethodTrace,
    log_size: u32,
    limb_columns: &[usize],
    carry_pair_columns: &[[usize; 2]],
    program_width: usize,
) {
    let rows = 1usize << log_size;
    let stripes = range_table_stripes(log_size);
    let mut multiplicities = vec![0u32; 2048];
    for column in limb_columns {
        let values = &trace.cols[*column];
        for row in 0..rows {
            multiplicities[u32::from(values[row].0) as usize] += 1;
        }
    }
    for t in 0..stripes {
        let mult_index = program_width + 2 * t;
        let value_index = program_width + 2 * t + 1;
        let mut mult_column = Vec::with_capacity(rows);
        let mut value_column = Vec::with_capacity(rows);
        for row in 0..rows {
            let entry = t * rows + row;
            // Inert entries carry value 2048 (outside the radix) and zero
            // multiplicity, contributing nothing to the LogUp balance.
            if entry < 2048 {
                value_column.push(M31::from(entry as u32));
                mult_column.push(M31::from(multiplicities[entry]));
            } else {
                value_column.push(M31::from(BASE));
                mult_column.push(M31::from(0u32));
            }
        }
        trace.set_column(value_index, value_column);
        trace.set_column(mult_index, mult_column);
    }

    let carry_stripes = carry_table_stripes(log_size);
    let carry_offset = program_width + 2 * stripes;
    let mut carry_multiplicities = vec![0u32; 131_072];
    for pair in carry_pair_columns {
        let low = &trace.cols[pair[0]];
        let high = &trace.cols[pair[1]];
        for row in 0..rows {
            let value =
                u32::from(low[row].0) as usize + 2048 * u32::from(high[row].0) as usize;
            carry_multiplicities[value] += 1;
        }
    }
    for t in 0..carry_stripes {
        let mult_index = carry_offset + 3 * t;
        let low_index = carry_offset + 3 * t + 1;
        let high_index = carry_offset + 3 * t + 2;
        let mut mult_column = Vec::with_capacity(rows);
        let mut low_column = Vec::with_capacity(rows);
        let mut high_column = Vec::with_capacity(rows);
        for row in 0..rows {
            let entry = t * rows + row;
            // Inert entries carry `hi = 2048` (outside its 0..64 range).
            if entry < 131_072 {
                low_column.push(M31::from((entry % 2048) as u32));
                high_column.push(M31::from((entry / 2048) as u32));
                mult_column.push(M31::from(carry_multiplicities[entry]));
            } else {
                low_column.push(M31::from(0u32));
                high_column.push(M31::from(BASE));
                mult_column.push(M31::from(0u32));
            }
        }
        trace.set_column(low_index, low_column);
        trace.set_column(high_index, high_column);
        trace.set_column(mult_index, mult_column);
    }
}

fn trace_columns_batch(programs: &[RistrettoFpProgram]) -> TexasAirResult<MethodTrace> {
    validate_program_batch_shape(programs)?;
    let log_size = batch_log_size(programs.len())?;
    let rows = 1usize << log_size;
    let (template_row, limb_columns, carry_pair_columns) = trace_row_with_limbs(&programs[0])?;
    let program_width = template_row.len();
    let program_rows = programs
        .par_iter()
        .map(trace_row)
        .collect::<TexasAirResult<Vec<_>>>()?;
    if program_rows.iter().any(|row| row.len() != program_width) {
        return Err(TexasAirError::SpecViolation(
            "Fp program batch witness widths disagree".into(),
        ));
    }
    let table_columns = range_table_column_count(log_size);
    // Column-wise materialization: transpose the per-program rows once so
    // every column is built in one contiguous pass (no per-row clone, no
    // cross-column strided scatter); padding rows repeat the last program.
    let program_count = program_rows.len();
    let mut trace = MethodTrace::new_unfilled(log_size, program_width + table_columns);
    for column_index in 0..program_width {
        let mut column = Vec::with_capacity(rows);
        for row_index in 0..rows {
            let source = row_index.min(program_count - 1);
            column.push(program_rows[source][column_index]);
        }
        trace.set_column(column_index, column);
    }
    append_range_table_columns(
        &mut trace,
        log_size,
        &limb_columns,
        &carry_pair_columns,
        program_width,
    );
    Ok(trace)
}

fn scope_columns_batch(programs: &[RistrettoFpProgram]) -> TexasAirResult<MethodTrace> {
    validate_program_batch_shape(programs)?;
    let log_size = batch_log_size(programs.len())?;
    let rows = 1usize << log_size;
    let scope_rows = programs
        .par_iter()
        .map(scope_row)
        .collect::<Vec<_>>();
    let width = scope_rows[0].len();
    // Column-wise transpose with the same last-row padding as the main trace.
    let scope_count = scope_rows.len();
    let mut columns = Vec::with_capacity(width);
    for column_index in 0..width {
        let mut column = Vec::with_capacity(rows);
        for row_index in 0..rows {
            let source = row_index.min(scope_count - 1);
            column.push(scope_rows[source][column_index]);
        }
        columns.push(column);
    }
    let trace = MethodTrace::from_columns(log_size, columns);
    Ok(trace)
}

fn preprocessed_ids(program: &RistrettoFpProgram) -> Vec<PreProcessedColumnId> {
    (0..program.values.len() * SCOPE_COLUMNS_PER_VALUE)
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
        let ids = &self.scope_ids;
        let canonicity = &self.canonicity;
        let mut value_limbs = Vec::with_capacity(self.program.values.len());

        for value_index in 0..self.program.values.len() {
            let mut value = Vec::with_capacity(LIMB_COUNT);
            for _ in 0..LIMB_COUNT {
                // 11-bit limb; range membership via the shared LogUp table.
                let limb = eval.next_trace_mask();
                value.push(limb);
            }
            for limb in &value {
                eval.add_to_relation(RelationEntry::new(
                    &self.range,
                    E::EF::from(one.clone()),
                    &[limb.clone()],
                ));
            }
            if canonicity[value_index] == ValueCanonicity::Witnessed {
                let mut sum = Vec::with_capacity(LIMB_COUNT);
                for _ in 0..LIMB_COUNT {
                    let limb = eval.next_trace_mask();
                    sum.push(limb);
                }
                for limb in &sum {
                    eval.add_to_relation(RelationEntry::new(
                        &self.range,
                        E::EF::from(one.clone()),
                        &[limb.clone()],
                    ));
                }

                let mut carries = Vec::with_capacity(LIMB_COUNT);
                for _ in 0..LIMB_COUNT {
                    let carry = eval.next_trace_mask();
                    eval.add_constraint(carry.clone() * (carry.clone() - one.clone()));
                    carries.push(carry);
                }
                eval.add_constraint(carries[LIMB_COUNT - 1].clone());
                for index in 0..LIMB_COUNT {
                    let carry_in = if index == 0 {
                        M31::from(0u32).into()
                    } else {
                        carries[index - 1].clone()
                    };
                    let carry_out = if index + 1 == LIMB_COUNT {
                        M31::from(0u32).into()
                    } else {
                        carries[index].clone()
                    };
                    eval.add_constraint(
                        value[index].clone()
                            + E::F::from(M31::from(u32::from(
                                CANONICITY_COMPLEMENT_LIMBS[index],
                            )))
                            + carry_in
                            - sum[index].clone()
                            - base.clone() * carry_out,
                    );
                }

                // The limb sum covers 264 bits, so canonicity additionally
                // requires the top limb below `2^3`, pinning the sum below
                // `2^256` and therefore the value below `p`.
                let mut top_bits = Vec::with_capacity(3);
                for _ in 0..3 {
                    let bit = eval.next_trace_mask();
                    eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
                    top_bits.push(bit);
                }
                let mut top_reconstruction: E::F = M31::from(0u32).into();
                for (bit_index, bit) in top_bits.iter().enumerate() {
                    top_reconstruction +=
                        bit.clone() * E::F::from(M31::from(1u32 << bit_index));
                }
                eval.add_constraint(sum[LIMB_COUNT - 1].clone() - top_reconstruction);
            }

            for (group_index, group) in value.chunks(SCOPE_LIMBS_PER_COLUMN).enumerate() {
                let scope = eval.get_preprocessed_column(
                    ids[value_index * SCOPE_COLUMNS_PER_VALUE + group_index].clone(),
                );
                let mut packed: E::F = scope;
                for (shift, limb) in group.iter().enumerate() {
                    packed = packed
                        - limb.clone() * E::F::from(M31::from(BASE.pow(shift as u32)));
                }
                eval.add_constraint(packed);
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

                    let mut signed_carries = Vec::with_capacity(LIMB_COUNT);
                    for _ in 0..LIMB_COUNT {
                        let negative = eval.next_trace_mask();
                        let magnitude = eval.next_trace_mask();
                        eval.add_constraint(negative.clone() * (negative.clone() - one.clone()));
                        eval.add_constraint(magnitude.clone() * (magnitude.clone() - one.clone()));
                        let positive = one.clone() - negative.clone();
                        signed_carries.push(positive * magnitude.clone() - negative * magnitude);
                    }
                    eval.add_constraint(signed_carries[LIMB_COUNT - 1].clone());
                    for index in 0..LIMB_COUNT {
                        let carry_in = if index == 0 {
                            M31::from(0u32).into()
                        } else {
                            signed_carries[index - 1].clone()
                        };
                        let carry_out = if index + 1 == LIMB_COUNT {
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
                                    * E::F::from(M31::from(u32::from(P_BASE_LIMBS[index])))
                                - base.clone() * carry_out,
                        );
                    }
                }
                RistrettoFpProgramOp::Multiply { a, b, out, q } => {
                    let mut signed_carries = Vec::with_capacity(PRODUCT_LIMBS - 1);
                    for _ in 0..(PRODUCT_LIMBS - 1) {
                        let negative = eval.next_trace_mask();
                        let limb_low = eval.next_trace_mask();
                        let limb_high = eval.next_trace_mask();
                        eval.add_constraint(negative.clone() * (negative.clone() - one.clone()));
                        eval.add_to_relation(RelationEntry::new(
                            &self.carry,
                            E::EF::from(one.clone()),
                            &[limb_low.clone(), limb_high.clone()],
                        ));
                        let magnitude = limb_low.clone() + base.clone() * limb_high.clone();
                        let positive = one.clone() - negative.clone();
                        signed_carries
                            .push(positive * magnitude.clone() - negative * magnitude);
                    }

                    for limb_index in 0..PRODUCT_LIMBS {
                        let start = limb_index.saturating_sub(LIMB_COUNT - 1);
                        let end = limb_index.min(LIMB_COUNT - 1);
                        let mut relation: E::F = M31::from(0u32).into();
                        for left_index in start..=end {
                            let right_index = limb_index - left_index;
                            relation += value_limbs[usize::from(a)][left_index].clone()
                                * value_limbs[usize::from(b)][right_index].clone();
                            relation = relation
                                - value_limbs[usize::from(q)][left_index].clone()
                                    * E::F::from(M31::from(u32::from(
                                        P_BASE_LIMBS[right_index],
                                    )));
                        }
                        if limb_index < LIMB_COUNT {
                            relation = relation
                                - value_limbs[usize::from(out)][limb_index].clone();
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

        // Table side of the shared range LogUp.  The last table columns hold
        // the 2048-entry limb table as `2 * table_stripes()` columns of
        // `(multiplicity, value)` followed by the 131,072-entry carry pair
        // table as `3 * carry_table_stripes()` columns of
        // `(multiplicity, lo, hi)`, so uses and tables balance to zero inside
        // this single component exactly like the cairo-air range-check
        // pattern.
        for _ in 0..self.table_stripes() {
            let multiplicity = eval.next_trace_mask();
            let entry = eval.next_trace_mask();
            eval.add_to_relation(RelationEntry::new(
                &self.range,
                -E::EF::from(multiplicity.clone()),
                &[entry.clone()],
            ));
        }
        for _ in 0..self.carry_table_stripes() {
            let multiplicity = eval.next_trace_mask();
            let entry_low = eval.next_trace_mask();
            let entry_high = eval.next_trace_mask();
            eval.add_to_relation(RelationEntry::new(
                &self.carry,
                -E::EF::from(multiplicity.clone()),
                &[entry_low.clone(), entry_high.clone()],
            ));
        }
        eval.finalize_logup_in_pairs();
        eval
    }
}

/// Deterministic canonical statement encoding: packed scope columns, ops,
/// outputs.  Hashed with Blake2b before Fiat--Shamir absorption so the
/// channel binds the full statement through a collision-resistant digest
/// (~1 ms) instead of absorbing ~5.5k field elements per program (~5 ms).
fn program_statement_bytes(program: &RistrettoFpProgram) -> Vec<u8> {
    let mut out = Vec::new();
    for value in &program.values {
        for packed in scope_packed(value) {
            out.extend_from_slice(&packed.to_le_bytes());
        }
    }
    out.extend_from_slice(&(program.ops.len() as u64).to_le_bytes());
    for op in &program.ops {
        let (selector, indices) = match *op {
            RistrettoFpProgramOp::Add { a, b, out } => (0u8, [a, b, out, 0]),
            RistrettoFpProgramOp::Subtract { a, b, out } => (1u8, [a, b, out, 0]),
            RistrettoFpProgramOp::Multiply { a, b, out, q } => (2u8, [a, b, out, q]),
        };
        out.push(selector);
        for index in indices {
            out.extend_from_slice(&index.to_le_bytes());
        }
    }
    out.extend_from_slice(&(program.outputs.len() as u64).to_le_bytes());
    for output in &program.outputs {
        out.extend_from_slice(&output.to_le_bytes());
    }
    out
}

fn program_statement_digest(program: &RistrettoFpProgram) -> [u32; 16] {
    use blake2::digest::Digest;
    let digest = blake2::Blake2b512::digest(&program_statement_bytes(program));
    core::array::from_fn(|index| {
        u32::from_le_bytes(digest[4 * index..4 * index + 4].try_into().expect("4 bytes"))
    })
}

fn mix_program(channel: &mut impl Channel, program: &RistrettoFpProgram) {
    channel.mix_u32s(&program_statement_digest(program));
}

fn mix_program_batch(channel: &mut impl Channel, programs: &[RistrettoFpProgram]) {
    channel.mix_u64(0x7269_7374_6261_7463);
    channel.mix_u64(programs.len() as u64);
    for program in programs {
        mix_program(channel, program);
    }
}

/// Prove all canonical values and field operations in one STARK.

/// Build the paired LogUp interaction columns for the shared range tables,
/// mirroring the AIR's relation-entry emission order: all single-limb use
/// entries, then the carry `(lo, hi)` pair entries, then both table sides
/// (negated multiplicities over the table value columns).  Entries are
/// paired consecutively (`finalize_logup_in_pairs` semantics); an odd total
/// leaves the last fraction alone in its own column.  Source columns are
/// bit-reversed first to match `MethodTrace::to_evaluations` storage.
#[allow(clippy::too_many_arguments)]
fn fp_range_interaction(
    trace: &MethodTrace,
    log_size: u32,
    range: &FpRange11,
    carry: &FpCarry17,
    limb_columns: &[usize],
    carry_pair_columns: &[[usize; 2]],
    program_width: usize,
) -> (
    Vec<
        stwo::prover::poly::circle::CircleEvaluation<
            stwo::prover::backend::simd::SimdBackend,
            M31,
            stwo::prover::poly::BitReversedOrder,
        >,
    >,
    SecureField,
) {
    use stwo::prover::backend::simd::m31::{LOG_N_LANES, PackedBaseField};
    use stwo::prover::backend::simd::qm31::PackedSecureField;

    let bitrev = |column: &[M31]| -> Vec<M31> {
        (0..column.len())
            .map(|i| {
                let mut r = 0usize;
                for bit in 0..log_size {
                    if (i >> bit) & 1 == 1 {
                        r |= 1 << (log_size - 1 - bit);
                    }
                }
                column[r]
            })
            .collect()
    };
    let pack_vec = |column: &[M31], vector_row: usize| {
        let mut values = [M31::from(0u32); stwo::prover::backend::simd::m31::N_LANES];
        for (lane, value) in values.iter_mut().enumerate() {
            let row = vector_row * stwo::prover::backend::simd::m31::N_LANES + lane;
            *value = if row < column.len() {
                column[row]
            } else {
                M31::from(0u32)
            };
        }
        PackedBaseField::from_array(values)
    };

    let stripes = range_table_stripes(log_size);
    let carry_stripes = carry_table_stripes(log_size);
    let carry_offset = program_width + 2 * stripes;
    let use_den: Vec<Vec<M31>> = limb_columns
        .par_iter()
        .map(|column| bitrev(&trace.cols[*column]))
        .collect();
    let carry_use_low: Vec<Vec<M31>> = carry_pair_columns
        .par_iter()
        .map(|pair| bitrev(&trace.cols[pair[0]]))
        .collect();
    let carry_use_high: Vec<Vec<M31>> = carry_pair_columns
        .par_iter()
        .map(|pair| bitrev(&trace.cols[pair[1]]))
        .collect();
    let table_mult: Vec<Vec<M31>> = (0..stripes)
        .into_par_iter()
        .map(|t| bitrev(&trace.cols[program_width + 2 * t]))
        .collect();
    let table_den: Vec<Vec<M31>> = (0..stripes)
        .into_par_iter()
        .map(|t| bitrev(&trace.cols[program_width + 2 * t + 1]))
        .collect();
    let carry_mult: Vec<Vec<M31>> = (0..carry_stripes)
        .into_par_iter()
        .map(|t| bitrev(&trace.cols[carry_offset + 3 * t]))
        .collect();
    let carry_den_low: Vec<Vec<M31>> = (0..carry_stripes)
        .into_par_iter()
        .map(|t| bitrev(&trace.cols[carry_offset + 3 * t + 1]))
        .collect();
    let carry_den_high: Vec<Vec<M31>> = (0..carry_stripes)
        .into_par_iter()
        .map(|t| bitrev(&trace.cols[carry_offset + 3 * t + 2]))
        .collect();

    // Per-row entry (numerator, denominator) sources in the AIR's emission
    // order: limb uses, carry pair uses, then both table sides.
    enum Entry {
        Use(usize),
        CarryUse(usize),
        Table(usize),
        CarryTable(usize),
    }
    let entries: Vec<Entry> = (0..limb_columns.len())
        .map(Entry::Use)
        .chain((0..carry_pair_columns.len()).map(Entry::CarryUse))
        .chain((0..stripes).map(Entry::Table))
        .chain((0..carry_stripes).map(Entry::CarryTable))
        .collect();

    let one_packed = PackedSecureField::from(PackedBaseField::from(M31::from(1u32)));
    let den_of = |entry: &Entry, vector_row: usize| -> PackedSecureField {
        match entry {
            Entry::Use(index) => range.combine(&[pack_vec(&use_den[*index], vector_row)]),
            Entry::CarryUse(index) => range_combine_pair(
                carry,
                &pack_vec(&carry_use_low[*index], vector_row),
                &pack_vec(&carry_use_high[*index], vector_row),
            ),
            Entry::Table(t) => range.combine(&[pack_vec(&table_den[*t], vector_row)]),
            Entry::CarryTable(t) => range_combine_pair(
                carry,
                &pack_vec(&carry_den_low[*t], vector_row),
                &pack_vec(&carry_den_high[*t], vector_row),
            ),
        }
    };
    let num_of = |entry: &Entry, vector_row: usize| -> PackedSecureField {
        match entry {
            Entry::Use(_) | Entry::CarryUse(_) => one_packed,
            Entry::Table(t) => -PackedSecureField::from(pack_vec(&table_mult[*t], vector_row)),
            Entry::CarryTable(t) => {
                -PackedSecureField::from(pack_vec(&carry_mult[*t], vector_row))
            }
        }
    };

    let mut generator = LogupTraceGenerator::new(log_size);
    let mut pair_index = 0usize;
    while pair_index + 1 < entries.len() {
        let mut col = generator.new_col();
        for vector_row in 0..(1usize << (log_size - LOG_N_LANES)) {
            let d0 = den_of(&entries[pair_index], vector_row);
            let d1 = den_of(&entries[pair_index + 1], vector_row);
            let n0 = num_of(&entries[pair_index], vector_row);
            let n1 = num_of(&entries[pair_index + 1], vector_row);
            col.write_frac(vector_row, n0 * d1 + n1 * d0, d0 * d1);
        }
        col.finalize_col();
        pair_index += 2;
    }
    if pair_index < entries.len() {
        let mut col = generator.new_col();
        for vector_row in 0..(1usize << (log_size - LOG_N_LANES)) {
            let n = num_of(&entries[pair_index], vector_row);
            let d = den_of(&entries[pair_index], vector_row);
            col.write_frac(vector_row, n, d);
        }
        col.finalize_col();
    }
    generator.finalize_last()
}

/// Combine an arity-2 relation over a packed `(lo, hi)` pair without an
/// intermediate slice, matching `Relation::combine` semantics.
fn range_combine_pair(
    carry: &FpCarry17,
    low: &stwo::prover::backend::simd::m31::PackedBaseField,
    high: &stwo::prover::backend::simd::m31::PackedBaseField,
) -> stwo::prover::backend::simd::qm31::PackedSecureField {
    use stwo::prover::backend::simd::qm31::PackedSecureField;
    let combined: [stwo::prover::backend::simd::m31::PackedBaseField; 2] =
        [low.clone(), high.clone()];
    <FpCarry17 as stwo_constraint_framework::Relation<_, PackedSecureField>>::combine(
        carry,
        &combined,
    )
}

/// Prove one fixed public Fp program in a single STARK with the shared
/// range LogUp interaction layer.
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
    let (limb_columns, carry_pair_columns) = trace_tracked_columns(program);
    let program_width = trace.cols.len() - range_table_column_count(LOG_SIZE);
    let range = FpRange11::draw(&mut channel);
    let carry = FpCarry17::draw(&mut channel);
    let (interaction, range_sum) = fp_range_interaction(
        &trace,
        LOG_SIZE,
        &range,
        &carry,
        &limb_columns,
        &carry_pair_columns,
        program_width,
    );
    channel.mix_felts(&[range_sum]);
    {
        let mut tree = scheme.tree_builder();
        tree.extend_evals(interaction);
        tree.commit(&mut channel);
    }
    let ids = preprocessed_ids(program);
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
    let component = FrameworkComponent::new(
        &mut allocator,
        FpProgramAir::new(LOG_SIZE, program.clone(), range, carry),
        range_sum,
    );
    let proof = prove(&[&component], &mut channel, scheme)
        .map_err(|error| TexasAirError::StwoProverError(error.to_string()))?;
    let stark_proof_bytes = options()
        .serialize(&proof)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
    Ok(ArchivedRistrettoFpProgramProof {
        program: program.clone(),
        stark_proof_bytes,
        range_claimed_sum: range_sum.to_m31_array().map(|limb| limb.0),
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
    let (program_width, limb_columns, carry_pair_columns) = trace_layout(&archive.program)?;
    let trace_width = program_width + range_table_column_count(LOG_SIZE);
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

    let mut channel = stwo::core::channel::Poseidon252Channel::default();
    mix_program(&mut channel, &archive.program);
    let mut scheme =
        stwo::core::pcs::CommitmentSchemeVerifier::<Poseidon252MerkleChannel>::new(config);
    scheme.commit(
        proof.commitments[0],
        &vec![LOG_SIZE; archive.program.values.len() * SCOPE_COLUMNS_PER_VALUE],
        &mut channel,
    );
    scheme.commit(
        proof.commitments[1],
        &vec![LOG_SIZE; trace_width],
        &mut channel,
    );
    let range = FpRange11::draw(&mut channel);
    let carry = FpCarry17::draw(&mut channel);
    let claimed = SecureField::from_m31_array(core::array::from_fn(|index| {
        M31::from(archive.range_claimed_sum[index])
    }));
    channel.mix_felts(&[claimed]);
    let interaction_columns = (limb_columns.len()
        + carry_pair_columns.len()
        + range_table_stripes(LOG_SIZE)
        + carry_table_stripes(LOG_SIZE))
        .div_ceil(2);
    scheme.commit(
        proof.commitments[2],
        &vec![LOG_SIZE; interaction_columns * 4],
        &mut channel,
    );
    let ids = preprocessed_ids(&archive.program);
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
    let component = FrameworkComponent::new(
        &mut allocator,
        FpProgramAir::new(LOG_SIZE, archive.program.clone(), range, carry),
        claimed,
    );
    stwo::core::verifier::verify(&[&component], &mut channel, &mut scheme, proof)
        .map_err(|error| TexasAirError::ConstraintUnsatisfied(error.to_string()))
}

/// Prove equal-shape canonical field programs as rows of one STARK.
pub fn prove_ristretto_fp_program_batch(
    programs: &[RistrettoFpProgram],
) -> TexasAirResult<ArchivedRistrettoFpProgramBatchProof> {
    prove_ristretto_fp_program_batch_owned(programs.to_vec())
}

/// Owning variant of [`prove_ristretto_fp_program_batch`]: callers that no
/// longer need the programs hand them over instead of re-cloning the whole
/// batch (N x 335 deep programs) into the archive.
pub(crate) fn prove_ristretto_fp_program_batch_owned(
    programs: Vec<RistrettoFpProgram>,
) -> TexasAirResult<ArchivedRistrettoFpProgramBatchProof> {
    validate_program_batch_shape(&programs)?;
    let log_size = batch_log_size(programs.len())?;
    let trace = trace_columns_batch(&programs)?;
    let scope = scope_columns_batch(&programs)?;
    let config = crate::prover_context::protocol_pcs_config();
    let twiddles =
        crate::prover_context::simd_twiddles(log_size + config.fri_config.log_blowup_factor);
    let mut channel = stwo::core::channel::Poseidon252Channel::default();
    mix_program_batch(&mut channel, &programs);
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
    let (limb_columns, carry_pair_columns) = trace_tracked_columns(&programs[0]);
    let program_width = trace.cols.len() - range_table_column_count(log_size);
    let range = FpRange11::draw(&mut channel);
    let carry = FpCarry17::draw(&mut channel);
    let (interaction, range_sum) = fp_range_interaction(
        &trace,
        log_size,
        &range,
        &carry,
        &limb_columns,
        &carry_pair_columns,
        program_width,
    );
    channel.mix_felts(&[range_sum]);
    {
        let mut tree = scheme.tree_builder();
        tree.extend_evals(interaction);
        tree.commit(&mut channel);
    }
    let ids = preprocessed_ids(&programs[0]);
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
    let component = FrameworkComponent::new(
        &mut allocator,
        FpProgramAir::new(log_size, programs[0].clone(), range, carry),
        range_sum,
    );
    let proof = prove(&[&component], &mut channel, scheme)
        .map_err(|error| TexasAirError::StwoProverError(error.to_string()))?;
    let stark_proof_bytes = options()
        .serialize(&proof)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
    Ok(ArchivedRistrettoFpProgramBatchProof {
        programs,
        stark_proof_bytes,
        range_claimed_sum: range_sum.to_m31_array().map(|limb| limb.0),
    })
}

/// Verify an equal-shape field-program batch.
pub fn verify_ristretto_fp_program_batch(
    archive: &ArchivedRistrettoFpProgramBatchProof,
) -> TexasAirResult<()> {
    type Proof = StarkProof<Poseidon252MerkleHasher>;
    validate_program_batch_shape(&archive.programs)?;
    let log_size = batch_log_size(archive.programs.len())?;
    let proof: Proof = options()
        .deserialize(&archive.stark_proof_bytes)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
    let (program_width, limb_columns, carry_pair_columns) =
        trace_layout(&archive.programs[0])?;
    let trace_width = program_width + range_table_column_count(log_size);
    let scope = scope_columns_batch(&archive.programs)?;
    let config = crate::prover_context::protocol_pcs_config();
    let twiddles =
        crate::prover_context::simd_twiddles(log_size + config.fri_config.log_blowup_factor);
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
            "Fp program batch public scope commitment mismatch".into(),
        ));
    }

    let mut channel = stwo::core::channel::Poseidon252Channel::default();
    mix_program_batch(&mut channel, &archive.programs);
    let mut scheme =
        stwo::core::pcs::CommitmentSchemeVerifier::<Poseidon252MerkleChannel>::new(config);
    scheme.commit(
        proof.commitments[0],
        &vec![log_size; archive.programs[0].values.len() * SCOPE_COLUMNS_PER_VALUE],
        &mut channel,
    );
    scheme.commit(
        proof.commitments[1],
        &vec![log_size; trace_width],
        &mut channel,
    );
    let range = FpRange11::draw(&mut channel);
    let carry = FpCarry17::draw(&mut channel);
    let claimed = SecureField::from_m31_array(core::array::from_fn(|index| {
        M31::from(archive.range_claimed_sum[index])
    }));
    channel.mix_felts(&[claimed]);
    let interaction_columns = (limb_columns.len()
        + carry_pair_columns.len()
        + range_table_stripes(log_size)
        + carry_table_stripes(log_size))
        .div_ceil(2);
    scheme.commit(
        proof.commitments[2],
        &vec![log_size; interaction_columns * 4],
        &mut channel,
    );
    let template = &archive.programs[0];
    let ids = preprocessed_ids(template);
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
    let component = FrameworkComponent::new(
        &mut allocator,
        FpProgramAir::new(log_size, template.clone(), range, carry),
        claimed,
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
    if u_value >= *p || v_value >= *p {
        return Err(TexasAirError::SpecViolation(
            "Ristretto sqrt_ratio program inputs must be canonical".into(),
        ));
    }

    let (was_square, r_value) = if u_value.is_zero() {
        (true, BigUint::from(0u32))
    } else if v_value.is_zero() {
        (false, BigUint::from(0u32))
    } else {
        let ratio = multiply_big(&u_value, &v_value.modpow(&(p - BigUint::from(2u32)), p));
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

/// Host-side Curve25519 field arithmetic for witness generation.
///
/// Built on fiat-crypto's formally verified u64 primitives — the exact
/// backend curve25519-dalek 4.x compiles internally (its `FieldElement` is
/// `pub(crate)` and cannot be imported).  Only the two exponentiation chains
/// the witness calculators need are layered on top: inversion by `p - 2`
/// (identical to BigUint `modpow(p-2)`, including `0⁻¹ = 0`) and dalek's
/// single-chain `sqrt_ratio_i(u, v) = (u·v³)·(u·v⁷)^((p−5)/8)` schedule.
pub(crate) mod fp25519 {
    use fiat_crypto::curve25519_64 as fiat;

    const LIMBS: usize = 32;

    /// `p - 2` little-endian (square-and-multiply inversion exponent).
    const INVERT_EXPONENT: [u8; LIMBS] = [
        0xeb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];

    /// `(p - 5) / 8 = 2^252 - 3` little-endian (dalek `pow_p58` exponent).
    const SQRT_P58_EXPONENT: [u8; LIMBS] = [
        0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x0f,
    ];

    /// A fully carried (tight) Curve25519 field element.
    #[derive(Clone, Copy)]
    pub(crate) struct Fe(fiat::fiat_25519_tight_field_element);

    impl Fe {
        pub(crate) fn zero() -> Fe {
            Fe(fiat::fiat_25519_tight_field_element([0u64; 5]))
        }

        pub(crate) fn one() -> Fe {
            let mut bytes = [0u8; LIMBS];
            bytes[0] = 1;
            Fe::from_bytes(&bytes)
        }

        /// Interprets the (canonical, `< p`) little-endian bytes exactly.
        pub(crate) fn from_bytes(bytes: &[u8; LIMBS]) -> Fe {
            let mut out = fiat::fiat_25519_tight_field_element([0u64; 5]);
            fiat::fiat_25519_from_bytes(&mut out, bytes);
            Fe(out)
        }

        /// Fully reduced canonical little-endian bytes.
        pub(crate) fn to_bytes(&self) -> [u8; LIMBS] {
            let mut out = [0u8; LIMBS];
            fiat::fiat_25519_to_bytes(&mut out, &self.0);
            out
        }

        pub(crate) fn is_zero(&self) -> bool {
            self.to_bytes() == [0u8; LIMBS]
        }

        pub(crate) fn add(&self, other: &Fe) -> Fe {
            let mut loose = fiat::fiat_25519_loose_field_element([0u64; 5]);
            fiat::fiat_25519_add(&mut loose, &self.0, &other.0);
            Fe::carry(loose)
        }

        pub(crate) fn sub(&self, other: &Fe) -> Fe {
            let mut loose = fiat::fiat_25519_loose_field_element([0u64; 5]);
            fiat::fiat_25519_sub(&mut loose, &self.0, &other.0);
            Fe::carry(loose)
        }

        pub(crate) fn neg(&self) -> Fe {
            let mut loose = fiat::fiat_25519_loose_field_element([0u64; 5]);
            fiat::fiat_25519_opp(&mut loose, &self.0);
            Fe::carry(loose)
        }

        fn carry(loose: fiat::fiat_25519_loose_field_element) -> Fe {
            let mut tight = fiat::fiat_25519_tight_field_element([0u64; 5]);
            fiat::fiat_25519_carry(&mut tight, &loose);
            Fe(tight)
        }

        pub(crate) fn mul(&self, other: &Fe) -> Fe {
            let mut left = fiat::fiat_25519_loose_field_element([0u64; 5]);
            let mut right = fiat::fiat_25519_loose_field_element([0u64; 5]);
            fiat::fiat_25519_relax(&mut left, &self.0);
            fiat::fiat_25519_relax(&mut right, &other.0);
            let mut out = fiat::fiat_25519_tight_field_element([0u64; 5]);
            fiat::fiat_25519_carry_mul(&mut out, &left, &right);
            Fe(out)
        }

        pub(crate) fn square(&self) -> Fe {
            let mut loose = fiat::fiat_25519_loose_field_element([0u64; 5]);
            fiat::fiat_25519_relax(&mut loose, &self.0);
            let mut out = fiat::fiat_25519_tight_field_element([0u64; 5]);
            fiat::fiat_25519_carry_square(&mut out, &loose);
            Fe(out)
        }

        /// Square-and-multiply over a little-endian exponent.
        fn pow_bytes(&self, exponent: &[u8; LIMBS]) -> Fe {
            let mut acc = Fe::one();
            for byte_index in (0..LIMBS).rev() {
                for bit in (0..8).rev() {
                    acc = acc.square();
                    if (exponent[byte_index] >> bit) & 1 == 1 {
                        acc = acc.mul(self);
                    }
                }
            }
            acc
        }

        /// Field inverse; the inverse of zero is zero, matching
        /// `modpow(p - 2)`.
        pub(crate) fn invert(&self) -> Fe {
            self.pow_bytes(&INVERT_EXPONENT)
        }

        /// dalek's single-chain `sqrt_ratio_i` root
        /// `r = (u·v³)·(u·v⁷)^((p−5)/8)`, left unclassified and possibly
        /// odd; callers derive `v·r² ∈ {±u, ±i·u}` and normalize the sign
        /// themselves.
        pub(crate) fn sqrt_ratio_i(u: &Fe, v: &Fe) -> Fe {
            let v3 = v.square().mul(v);
            let v7 = v3.square().mul(v);
            u.mul(&v3).mul(&u.mul(&v7).pow_bytes(&SQRT_P58_EXPONENT))
        }
    }
}

static NEGATIVE_EDWARDS_D: std::sync::OnceLock<[u8; LIMBS]> = std::sync::OnceLock::new();

fn negative_edwards_d() -> [u8; LIMBS] {
    *NEGATIVE_EDWARDS_D.get_or_init(|| {
        limbs(&subtract_big(&modulus(), &big_uint(&EDWARDS_D_BYTES)))
    })
}

/// Memoized successful results of [`canonical_decode_inverse_sqrt`].  The
/// function is pure (bytes in, bytes out), so caching is safe; failed decodes
/// are not cached.  Fixed-window scalar multiplication decodes the same base
/// and identity encodings hundreds of times per proof.
static CANONICAL_DECODE_INVERSE_SQRT_MEMO: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<[u8; LIMBS], [u8; LIMBS]>>,
> = std::sync::OnceLock::new();

fn canonical_decode_inverse_sqrt(encoding: &[u8; LIMBS]) -> TexasAirResult<[u8; LIMBS]> {
    let memo = CANONICAL_DECODE_INVERSE_SQRT_MEMO
        .get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    if let Ok(cached) = memo.lock() {
        if let Some(value) = cached.get(encoding) {
            return Ok(*value);
        }
    }
    let computed = canonical_decode_inverse_sqrt_uncached(encoding)?;
    if let Ok(mut cached) = memo.lock() {
        cached.insert(*encoding, computed);
    }
    Ok(computed)
}

/// Warm the decode memo for a set of encodings in parallel.
///
/// The MSM accumulation chain consumes each output's decode serially inside a
/// data-dependent loop; pre-populating the memo with a `par_iter` pass lets
/// the sqrt chains run concurrently before the chain starts.
pub(crate) fn preheat_canonical_decode_memo(encodings: &[[u8; LIMBS]]) {
    encodings
        .par_iter()
        .for_each(|encoding| drop(canonical_decode_inverse_sqrt(encoding)));
}

fn canonical_decode_inverse_sqrt_uncached(encoding: &[u8; LIMBS]) -> TexasAirResult<[u8; LIMBS]> {
    let p = modulus();
    let s = big_uint(encoding);
    if s >= *p {
        return Err(TexasAirError::SpecViolation(
            "Ristretto point encoding is noncanonical".into(),
        ));
    }
    if (&s & BigUint::one()) == BigUint::one() {
        return Err(TexasAirError::SpecViolation(
            "Ristretto point encoding is negative".into(),
        ));
    }

    let s = fp25519::Fe::from_bytes(encoding);
    let one = fp25519::Fe::one();
    let ss = s.square();
    let u1 = one.sub(&ss);
    let u2 = one.add(&ss);
    let u2sq = u2.square();
    let u1sq = u1.square();
    let negative_d = fp25519::Fe::from_bytes(&negative_edwards_d());
    let v = negative_d.mul(&u1sq).sub(&u2sq);
    let target = v.mul(&u2sq);
    let root = nonnegative_sqrt_fe(&target).ok_or_else(|| {
        TexasAirError::SpecViolation("Ristretto decode inverse square root does not exist".into())
    })?;
    let mut inverse_sqrt = root.invert();
    if inverse_sqrt.to_bytes()[0] & 1 == 1 {
        inverse_sqrt = inverse_sqrt.neg();
    }
    Ok(inverse_sqrt.to_bytes())
}

fn projective_encode_inverse_sqrt(point: &[[u8; LIMBS]; 4]) -> TexasAirResult<[u8; LIMBS]> {
    let x = fp25519::Fe::from_bytes(&point[0]);
    let y = fp25519::Fe::from_bytes(&point[1]);
    let z = fp25519::Fe::from_bytes(&point[2]);
    let z_plus_y = z.add(&y);
    let z_minus_y = z.sub(&y);
    let u1 = z_plus_y.mul(&z_minus_y);
    let u2 = x.mul(&y);
    let u2_squared = u2.square();
    let v = u1.mul(&u2_squared);
    let mut inverse_sqrt = if v.is_zero() {
        fp25519::Fe::zero()
    } else {
        let root = nonnegative_sqrt_fe(&v).ok_or_else(|| {
            TexasAirError::SpecViolation(
                "projective Ristretto encode square root does not exist".into(),
            )
        })?;
        let inverse = root.invert();
        if inverse.to_bytes()[0] & 1 == 1 {
            inverse.neg()
        } else {
            inverse
        }
    };
    if inverse_sqrt.to_bytes()[0] & 1 == 1 {
        inverse_sqrt = inverse_sqrt.neg();
    }
    Ok(inverse_sqrt.to_bytes())
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
    let inverse_sqrt_bytes = canonical_decode_inverse_sqrt(encoding)?;
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
    if ristretto_self_verify_enabled() {
        verify_ristretto_fp_program_point_decode(&point)?;
    }
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
    if ristretto_self_verify_enabled() {
        verify_ristretto_fp_program_point_decode(&left)?;
        verify_ristretto_fp_program_point_decode(&right)?;
    }
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

fn expected_projective_encode_ops(
    selected_x: u16,
    selected_y: u16,
    selected_denominator: u16,
    final_y: u16,
) -> Vec<RistrettoFpProgramOp> {
    vec![
        RistrettoFpProgramOp::Add { a: 2, b: 1, out: 8 },
        RistrettoFpProgramOp::Subtract { a: 2, b: 1, out: 9 },
        RistrettoFpProgramOp::Multiply {
            a: 8,
            b: 9,
            out: 11,
            q: 10,
        },
        RistrettoFpProgramOp::Multiply {
            a: 0,
            b: 1,
            out: 13,
            q: 12,
        },
        RistrettoFpProgramOp::Multiply {
            a: 13,
            b: 13,
            out: 15,
            q: 14,
        },
        RistrettoFpProgramOp::Multiply {
            a: 11,
            b: 15,
            out: 17,
            q: 16,
        },
        RistrettoFpProgramOp::Multiply {
            a: 4,
            b: 4,
            out: 19,
            q: 18,
        },
        RistrettoFpProgramOp::Multiply {
            a: 19,
            b: 17,
            out: 21,
            q: 20,
        },
        RistrettoFpProgramOp::Multiply {
            a: 4,
            b: 11,
            out: 23,
            q: 22,
        },
        RistrettoFpProgramOp::Multiply {
            a: 4,
            b: 13,
            out: 25,
            q: 24,
        },
        RistrettoFpProgramOp::Multiply {
            a: 25,
            b: 3,
            out: 27,
            q: 26,
        },
        RistrettoFpProgramOp::Multiply {
            a: 23,
            b: 27,
            out: 29,
            q: 28,
        },
        RistrettoFpProgramOp::Multiply {
            a: 3,
            b: 29,
            out: 31,
            q: 30,
        },
        RistrettoFpProgramOp::Multiply {
            a: 0,
            b: 6,
            out: 33,
            q: 32,
        },
        RistrettoFpProgramOp::Multiply {
            a: 1,
            b: 6,
            out: 35,
            q: 34,
        },
        RistrettoFpProgramOp::Multiply {
            a: 23,
            b: 7,
            out: 37,
            q: 36,
        },
        RistrettoFpProgramOp::Subtract {
            a: 38,
            b: selected_y,
            out: 39,
        },
        RistrettoFpProgramOp::Multiply {
            a: selected_x,
            b: 29,
            out: 41,
            q: 40,
        },
        RistrettoFpProgramOp::Subtract {
            a: 2,
            b: final_y,
            out: 42,
        },
        RistrettoFpProgramOp::Multiply {
            a: selected_denominator,
            b: 42,
            out: 44,
            q: 43,
        },
        RistrettoFpProgramOp::Subtract {
            a: 38,
            b: 44,
            out: 45,
        },
    ]
}

/// Prove canonical Ristretto encoding of an authenticated projective point.
pub fn prove_ristretto_fp_program_projective_point_encode(
    point: ArchivedRistrettoFpProgramProjectivePoint,
) -> TexasAirResult<ArchivedRistrettoFpProgramProjectivePointEncodeProof> {
    if ristretto_self_verify_enabled() {
        verify_ristretto_fp_program_projective_point(&point)?;
    }
    let inverse_sqrt = projective_encode_inverse_sqrt(&[point.x, point.y, point.z, point.t])?;

    let mut builder =
        RistrettoFpProgramBuilder::new(&[point.x, point.y, point.z, point.t, inverse_sqrt]);
    builder.constant(&ONE_BYTES)?;
    builder.constant(&SQRT_M1_BYTES)?;
    builder.constant(&INVSQRT_A_MINUS_D_BYTES)?;
    let z_plus_y_index = builder.add(2, 1)?;
    let z_minus_y_index = builder.subtract(2, 1)?;
    let u1_index = builder.multiply(z_plus_y_index, z_minus_y_index)?;
    let u2_index = builder.multiply(0, 1)?;
    let u2_squared_index = builder.multiply(u2_index, u2_index)?;
    let v_index = builder.multiply(u1_index, u2_squared_index)?;
    let inverse_sqrt_squared = builder.multiply(4, 4)?;
    let inverse_check = builder.multiply(inverse_sqrt_squared, v_index)?;
    let i1 = builder.multiply(4, u1_index)?;
    let i2 = builder.multiply(4, u2_index)?;
    let i2_times_t = builder.multiply(i2, 3)?;
    let z_inverse = builder.multiply(i1, i2_times_t)?;
    let t_times_z_inverse = builder.multiply(3, z_inverse)?;
    let i_x = builder.multiply(0, 6)?;
    let i_y = builder.multiply(1, 6)?;
    let enchanted_denominator = builder.multiply(i1, 7)?;
    builder.constant(&ZERO_BYTES)?;

    let rotate = builder_values(&builder, t_times_z_inverse)?[0] & 1 == 1;
    let selected_x_index = if rotate { i_y } else { 0 };
    let selected_y_index = if rotate { i_x } else { 1 };
    let selected_denominator = if rotate { enchanted_denominator } else { i2 };
    let negative_selected_y = builder.subtract(38, selected_y_index)?;
    let x_times_z_inverse = builder.multiply(selected_x_index, z_inverse)?;
    let negate_y = builder_values(&builder, x_times_z_inverse)?[0] & 1 == 1;
    let final_y_index = if negate_y {
        negative_selected_y
    } else {
        selected_y_index
    };
    let z_minus_final_y = builder.subtract(2, final_y_index)?;
    let s_raw = builder.multiply(selected_denominator, z_minus_final_y)?;
    let negative_s_raw = builder.subtract(38, s_raw)?;
    let encoding_index = if builder_values(&builder, s_raw)?[0] & 1 == 1 {
        negative_s_raw
    } else {
        s_raw
    };
    let encoding = builder_values(&builder, encoding_index)?;
    let identity = point.x == ZERO_BYTES && point.y == point.z && point.t == ZERO_BYTES;
    let expected_inverse_check = if identity { ZERO_BYTES } else { ONE_BYTES };
    if builder_values(&builder, inverse_check)? != expected_inverse_check {
        return Err(TexasAirError::SpecViolation(
            "projective Ristretto encode inverse-root relation is invalid".into(),
        ));
    }
    if encoding[0] & 1 == 1 {
        return Err(TexasAirError::SpecViolation(
            "projective Ristretto encode output is negative".into(),
        ));
    }

    let program = builder.finish(&[inverse_check, encoding_index])?;
    let proof = prove_ristretto_fp_program(&program)?;
    Ok(ArchivedRistrettoFpProgramProjectivePointEncodeProof {
        point,
        encoding,
        program: proof,
    })
}

/// Verify the fixed projective Ristretto encode program and its sign branches.
pub fn verify_ristretto_fp_program_projective_point_encode(
    archive: &ArchivedRistrettoFpProgramProjectivePointEncodeProof,
) -> TexasAirResult<()> {
    verify_ristretto_fp_program_projective_point(&archive.point)?;
    let program = &archive.program.program;
    if program.values.len() != 46 {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "projective Ristretto encode program value count is invalid".into(),
        ));
    }
    let rotate = program.values[31][0] & 1 == 1;
    let selected_x = if rotate { 35 } else { 0 };
    let selected_y = if rotate { 33 } else { 1 };
    let selected_denominator = if rotate { 37 } else { 25 };
    let negate_y = program.values[41][0] & 1 == 1;
    let final_y = if negate_y { 39 } else { selected_y };
    let expected_ops =
        expected_projective_encode_ops(selected_x, selected_y, selected_denominator, final_y);
    let encoding_index = if program.values[44][0] & 1 == 1 {
        45
    } else {
        44
    };
    let fixed_shape = program.ops.len() == 21
        && program.outputs == [21, encoding_index]
        && program.ops == expected_ops
        && program.values[0] == archive.point.x
        && program.values[1] == archive.point.y
        && program.values[2] == archive.point.z
        && program.values[3] == archive.point.t
        && program.values[5] == ONE_BYTES
        && program.values[6] == SQRT_M1_BYTES
        && program.values[7] == INVSQRT_A_MINUS_D_BYTES
        && program.values[38] == ZERO_BYTES
        && program.values[usize::from(encoding_index)] == archive.encoding;
    if !fixed_shape {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "projective Ristretto encode program shape is detached".into(),
        ));
    }
    verify_ristretto_fp_program(&archive.program)?;

    let identity = archive.point.x == ZERO_BYTES
        && archive.point.y == archive.point.z
        && archive.point.t == ZERO_BYTES;
    let expected_inverse_check = if identity { ZERO_BYTES } else { ONE_BYTES };
    if program.values[21] != expected_inverse_check
        || program.values[4][0] & 1 == 1
        || archive.encoding[0] & 1 == 1
        || (identity && archive.encoding != ZERO_BYTES)
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "projective Ristretto encode inverse-root or output branch is invalid".into(),
        ));
    }
    Ok(())
}

/// Prove general projective extended-Edwards addition in one program STARK.
pub fn prove_ristretto_fp_program_projective_addition(
    left: ArchivedRistrettoFpProgramProjectivePoint,
    right: ArchivedRistrettoFpProgramProjectivePoint,
) -> TexasAirResult<ArchivedRistrettoFpProgramProjectiveAdditionProof> {
    if ristretto_self_verify_enabled() {
        verify_ristretto_fp_program_projective_point(&left)?;
        verify_ristretto_fp_program_projective_point(&right)?;
    }
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

fn build_projective_addition_program_from_coordinates(
    left: RistrettoProjectiveCoordinates,
    right: RistrettoProjectiveCoordinates,
) -> TexasAirResult<(RistrettoFpProgram, RistrettoProjectiveCoordinates)> {
    let mut builder = RistrettoFpProgramBuilder::new(&[
        left[0], left[1], left[2], left[3], right[0], right[1], right[2], right[3],
    ]);
    let two = builder.constant(&TWO_BYTES)?;
    let two_d = builder.constant(&EDWARDS_TWO_D_BYTES)?;
    let output = append_projective_addition(&mut builder, [0, 1, 2, 3], [4, 5, 6, 7], two, two_d)?;
    let output_values = output
        .map(|index| builder_values(&builder, index))
        .into_iter()
        .collect::<TexasAirResult<Vec<_>>>()?;
    let output: RistrettoProjectiveCoordinates = output_values
        .try_into()
        .expect("projective addition has exactly four coordinates");
    if output[2] == ZERO_BYTES {
        return Err(TexasAirError::SpecViolation(
            "projective Edwards addition produced Z = 0".into(),
        ));
    }
    let program = builder.finish(&[31, 33, 35, 37])?;
    if program.values.len() != 38
        || program.ops.len() != 18
        || program.ops != expected_projective_edwards_addition_ops()
    {
        return Err(TexasAirError::SpecViolation(
            "projective addition batch row shape diverged".into(),
        ));
    }
    Ok((program, output))
}

/// Prove fixed-shape projective additions as rows of one Fp-program batch.
pub fn prove_ristretto_fp_program_projective_addition_batch(
    left: &[RistrettoProjectiveCoordinates],
    right: &[RistrettoProjectiveCoordinates],
    output: &[RistrettoProjectiveCoordinates],
) -> TexasAirResult<ArchivedRistrettoFpProgramProjectiveAdditionBatchProof> {
    if left.is_empty() || left.len() != right.len() || left.len() != output.len() {
        return Err(TexasAirError::SpecViolation(
            "projective addition batch coordinate lengths disagree".into(),
        ));
    }
    let mut programs = Vec::with_capacity(left.len());
    for ((left, right), expected_output) in left.iter().zip(right).zip(output) {
        let (program, actual_output) =
            build_projective_addition_program_from_coordinates(*left, *right)?;
        if actual_output != *expected_output {
            return Err(TexasAirError::SpecViolation(
                "projective addition batch output is detached from its arithmetic row".into(),
            ));
        }
        programs.push(program);
    }
    let additions = prove_ristretto_fp_program_batch_owned(programs)?;
    let archive = ArchivedRistrettoFpProgramProjectiveAdditionBatchProof {
        left: left.to_vec(),
        right: right.to_vec(),
        output: output.to_vec(),
        additions,
    };
    if ristretto_self_verify_enabled() {
        verify_ristretto_fp_program_projective_addition_batch(&archive)?;
    }
    Ok(archive)
}

/// Verify a fixed-shape projective addition batch and every public row.
pub fn verify_ristretto_fp_program_projective_addition_batch(
    archive: &ArchivedRistrettoFpProgramProjectiveAdditionBatchProof,
) -> TexasAirResult<()> {
    if archive.left.is_empty()
        || archive.left.len() != archive.right.len()
        || archive.left.len() != archive.output.len()
        || archive.additions.programs.len() != archive.left.len()
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "projective addition batch row counts disagree".into(),
        ));
    }
    verify_ristretto_fp_program_batch(&archive.additions)?;
    for index in 0..archive.left.len() {
        let (expected_program, expected_output) =
            build_projective_addition_program_from_coordinates(
                archive.left[index],
                archive.right[index],
            )?;
        if archive.additions.programs[index] != expected_program
            || archive.output[index] != expected_output
        {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "projective addition batch row is detached from its public coordinates".into(),
            ));
        }
    }
    Ok(())
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
    if ristretto_self_verify_enabled() {
        verify_ristretto_fp_program_projective_point(&base)?;
    }
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

/// Streaming BLAKE2b over a point's canonical borsh serialization.
///
/// The selector dedup pass used to materialize the full serialization (the
/// nested STARK proof bytes, hundreds of KB per table entry) as an owned
/// `Vec<u8>` key.  Hashing the same byte stream into a 64-byte digest keeps
/// the dedup semantics bit-for-bit (same key equality domain) while removing
/// the per-entry deep-copy allocations.
struct Blake2bWriter(blake2::Blake2b512);

impl borsh::io::Write for Blake2bWriter {
    fn write(&mut self, buf: &[u8]) -> borsh::io::Result<usize> {
        use blake2::digest::Update;
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> borsh::io::Result<()> {
        Ok(())
    }
}

/// Lightweight dedup fingerprint of an authenticated point.
fn point_dedup_key(
    point: &ArchivedRistrettoFpProgramProjectivePoint,
) -> TexasAirResult<[u8; 64]> {
    use blake2::digest::Digest;
    let mut writer = Blake2bWriter(blake2::Blake2b512::new());
    BorshSerialize::serialize(point, &mut writer)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
    Ok(writer.0.finalize().into())
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
        let key = point_dedup_key(point)?;
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
        let key = point_dedup_key(point)?;
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
    two_d: u16,
) -> TexasAirResult<[u16; 4]> {
    let left_y_minus_x = builder.subtract(left[1], left[0])?;
    let right_y_minus_x = builder.subtract(right[1], right[0])?;
    let left_y_plus_x = builder.add(left[1], left[0])?;
    let right_y_plus_x = builder.add(right[1], right[0])?;
    let a = builder.multiply(left_y_minus_x, right_y_minus_x)?;
    let b = builder.multiply(left_y_plus_x, right_y_plus_x)?;
    let two_d_left_t = builder.multiply(two_d, left[3])?;
    let c = builder.multiply(two_d_left_t, right[3])?;
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

#[derive(Clone, Copy)]
struct AppendedCanonicalPointDecode {
    coordinates: [u16; 4],
    inverse_check: u16,
}

#[derive(Clone, Copy)]
struct AppendedProjectivePointEncode {
    encoding: u16,
    inverse_check: u16,
}

fn parity_selector(value: &[u8; LIMBS]) -> [u8; LIMBS] {
    if value[0] & 1 == 1 {
        ONE_BYTES
    } else {
        ZERO_BYTES
    }
}

fn append_fixed_select(
    builder: &mut RistrettoFpProgramBuilder,
    when_false: u16,
    when_true: u16,
    selector: u16,
) -> TexasAirResult<u16> {
    let delta = builder.subtract(when_true, when_false)?;
    let selected_delta = builder.multiply(selector, delta)?;
    builder.add(when_false, selected_delta)
}

fn append_fixed_canonical_point_decode(
    builder: &mut RistrettoFpProgramBuilder,
    encoding: u16,
    inverse_sqrt: u16,
    one: u16,
    negative_d: u16,
    zero: u16,
) -> TexasAirResult<AppendedCanonicalPointDecode> {
    let squared_encoding = builder.multiply(encoding, encoding)?;
    let u1 = builder.subtract(one, squared_encoding)?;
    let u2 = builder.add(one, squared_encoding)?;
    let u2_squared = builder.multiply(u2, u2)?;
    let u1_squared = builder.multiply(u1, u1)?;
    let negative_d_u1_squared = builder.multiply(negative_d, u1_squared)?;
    let v = builder.subtract(negative_d_u1_squared, u2_squared)?;
    let target = builder.multiply(v, u2_squared)?;
    let inverse_sqrt_squared = builder.multiply(inverse_sqrt, inverse_sqrt)?;
    let inverse_check = builder.multiply(inverse_sqrt_squared, target)?;
    let dx = builder.multiply(inverse_sqrt, u2)?;
    let dx_v = builder.multiply(dx, v)?;
    let dy = builder.multiply(inverse_sqrt, dx_v)?;
    let two_s = builder.add(encoding, encoding)?;
    let x_raw = builder.multiply(two_s, dx)?;
    let negative_x = builder.subtract(zero, x_raw)?;
    let x_selector_value = parity_selector(&builder_values(builder, x_raw)?);
    let x_selector = builder.constant(&x_selector_value)?;
    let x = append_fixed_select(builder, x_raw, negative_x, x_selector)?;
    let y = builder.multiply(u1, dy)?;
    let t = builder.multiply(x, y)?;

    let x_value = builder_values(builder, x)?;
    let y_value = builder_values(builder, y)?;
    let t_value = builder_values(builder, t)?;
    if builder_values(builder, inverse_check)? != ONE_BYTES
        || x_value[0] & 1 == 1
        || y_value == ZERO_BYTES
        || t_value[0] & 1 == 1
    {
        return Err(TexasAirError::SpecViolation(
            "fixed-shape Ristretto decode branch is invalid".into(),
        ));
    }
    Ok(AppendedCanonicalPointDecode {
        coordinates: [x, y, one, t],
        inverse_check,
    })
}

#[allow(clippy::too_many_arguments)]
fn append_fixed_projective_point_encode(
    builder: &mut RistrettoFpProgramBuilder,
    point: [u16; 4],
    inverse_sqrt: u16,
    zero: u16,
    sqrt_m1: u16,
    invsqrt_a_minus_d: u16,
) -> TexasAirResult<AppendedProjectivePointEncode> {
    let z_plus_y = builder.add(point[2], point[1])?;
    let z_minus_y = builder.subtract(point[2], point[1])?;
    let u1 = builder.multiply(z_plus_y, z_minus_y)?;
    let u2 = builder.multiply(point[0], point[1])?;
    let u2_squared = builder.multiply(u2, u2)?;
    let v = builder.multiply(u1, u2_squared)?;
    let inverse_sqrt_squared = builder.multiply(inverse_sqrt, inverse_sqrt)?;
    let inverse_check = builder.multiply(inverse_sqrt_squared, v)?;
    let i1 = builder.multiply(inverse_sqrt, u1)?;
    let i2 = builder.multiply(inverse_sqrt, u2)?;
    let i2_times_t = builder.multiply(i2, point[3])?;
    let z_inverse = builder.multiply(i1, i2_times_t)?;
    let t_times_z_inverse = builder.multiply(point[3], z_inverse)?;
    let i_x = builder.multiply(point[0], sqrt_m1)?;
    let i_y = builder.multiply(point[1], sqrt_m1)?;
    let enchanted_denominator = builder.multiply(i1, invsqrt_a_minus_d)?;

    let rotate_value = parity_selector(&builder_values(builder, t_times_z_inverse)?);
    let rotate = builder.constant(&rotate_value)?;
    let selected_x = append_fixed_select(builder, point[0], i_y, rotate)?;
    let selected_y = append_fixed_select(builder, point[1], i_x, rotate)?;
    let selected_denominator = append_fixed_select(builder, i2, enchanted_denominator, rotate)?;

    let negative_selected_y = builder.subtract(zero, selected_y)?;
    let x_times_z_inverse = builder.multiply(selected_x, z_inverse)?;
    let negate_y_value = parity_selector(&builder_values(builder, x_times_z_inverse)?);
    let negate_y = builder.constant(&negate_y_value)?;
    let final_y = append_fixed_select(builder, selected_y, negative_selected_y, negate_y)?;
    let z_minus_final_y = builder.subtract(point[2], final_y)?;
    let s_raw = builder.multiply(selected_denominator, z_minus_final_y)?;
    let negative_s_raw = builder.subtract(zero, s_raw)?;
    let negate_s_value = parity_selector(&builder_values(builder, s_raw)?);
    let negate_s = builder.constant(&negate_s_value)?;
    let encoding = append_fixed_select(builder, s_raw, negative_s_raw, negate_s)?;

    let point_values = point
        .map(|index| builder_values(builder, index))
        .into_iter()
        .collect::<TexasAirResult<Vec<_>>>()?;
    let identity = point_values[0] == ZERO_BYTES
        && point_values[1] == point_values[2]
        && point_values[3] == ZERO_BYTES;
    let expected_inverse_check = if identity { ZERO_BYTES } else { ONE_BYTES };
    let encoding_value = builder_values(builder, encoding)?;
    if builder_values(builder, inverse_check)? != expected_inverse_check
        || encoding_value[0] & 1 == 1
        || (identity && encoding_value != ZERO_BYTES)
    {
        return Err(TexasAirError::SpecViolation(
            "fixed-shape projective Ristretto encode branch is invalid".into(),
        ));
    }
    Ok(AppendedProjectivePointEncode {
        encoding,
        inverse_check,
    })
}

/// Build one fixed-shape field program for canonical compressed Ristretto
/// addition.  Every valid input pair has identical operation and output-index
/// layouts, so independent point relations can occupy rows of one batch STARK.
pub fn build_ristretto_fp_program_compressed_point_addition(
    left_encoding: &[u8; LIMBS],
    right_encoding: &[u8; LIMBS],
) -> TexasAirResult<(RistrettoFpProgram, [u8; LIMBS])> {
    let left_inverse_sqrt = canonical_decode_inverse_sqrt(left_encoding)?;
    // Doubling rows (accumulator squaring in the Horner ladder) decode the
    // same encoding twice; the function is pure, so reuse the left result.
    let right_inverse_sqrt = if left_encoding == right_encoding {
        left_inverse_sqrt
    } else {
        canonical_decode_inverse_sqrt(right_encoding)?
    };
    let mut builder = RistrettoFpProgramBuilder::new(&[*left_encoding, *right_encoding]);
    let one = builder.constant(&ONE_BYTES)?;
    let negative_d = builder.constant(&negative_edwards_d())?;
    let zero = builder.constant(&ZERO_BYTES)?;
    let two = builder.constant(&TWO_BYTES)?;
    let two_d = builder.constant(&EDWARDS_TWO_D_BYTES)?;
    let sqrt_m1 = builder.constant(&SQRT_M1_BYTES)?;
    let invsqrt_a_minus_d = builder.constant(&INVSQRT_A_MINUS_D_BYTES)?;

    let left_inverse_sqrt = builder.constant(&left_inverse_sqrt)?;
    let left = append_fixed_canonical_point_decode(
        &mut builder,
        0,
        left_inverse_sqrt,
        one,
        negative_d,
        zero,
    )?;
    let right_inverse_sqrt = builder.constant(&right_inverse_sqrt)?;
    let right = append_fixed_canonical_point_decode(
        &mut builder,
        1,
        right_inverse_sqrt,
        one,
        negative_d,
        zero,
    )?;
    let sum = append_projective_addition(
        &mut builder,
        left.coordinates,
        right.coordinates,
        two,
        two_d,
    )?;
    let sum_values = sum
        .map(|index| builder_values(&builder, index))
        .into_iter()
        .collect::<TexasAirResult<Vec<_>>>()?;
    if sum_values[2] == ZERO_BYTES {
        return Err(TexasAirError::SpecViolation(
            "fixed-shape compressed point addition produced Z = 0".into(),
        ));
    }
    let sum_point: [[u8; LIMBS]; 4] = sum_values
        .try_into()
        .expect("projective addition has exactly four coordinates");
    let encode_inverse_sqrt = builder.constant(&projective_encode_inverse_sqrt(&sum_point)?)?;
    let encoded = append_fixed_projective_point_encode(
        &mut builder,
        sum,
        encode_inverse_sqrt,
        zero,
        sqrt_m1,
        invsqrt_a_minus_d,
    )?;
    let output_encoding = builder_values(&builder, encoded.encoding)?;
    let program = builder.finish(&[
        left.inverse_check,
        right.inverse_check,
        sum[0],
        sum[1],
        sum[2],
        sum[3],
        encoded.inverse_check,
        encoded.encoding,
    ])?;
    Ok((program, output_encoding))
}

/// Verify that one public batch row is the exact fixed-shape compressed-point
/// addition statement for `left + right = output`.
pub fn verify_ristretto_fp_program_compressed_point_addition_row(
    program: &RistrettoFpProgram,
    left_encoding: &[u8; LIMBS],
    right_encoding: &[u8; LIMBS],
    output_encoding: &[u8; LIMBS],
) -> TexasAirResult<()> {
    let (expected_program, expected_output) =
        build_ristretto_fp_program_compressed_point_addition(left_encoding, right_encoding)?;
    if program != &expected_program || output_encoding != &expected_output {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "compressed point addition batch row is detached from its canonical statement".into(),
        ));
    }
    Ok(())
}

const COMPRESSED_FIXED_WINDOW_TABLE_ROWS: usize = 15;
const COMPRESSED_FIXED_WINDOW_HORNER_ROWS: usize =
    FIXED_WINDOW_COUNT * PROJECTIVE_ADDITIONS_PER_WINDOW;
const COMPRESSED_FIXED_WINDOW_ROWS: usize =
    COMPRESSED_FIXED_WINDOW_TABLE_ROWS + COMPRESSED_FIXED_WINDOW_HORNER_ROWS;

fn build_compressed_fixed_window_scalar_mul_rows(
    windows: &[u8; FIXED_WINDOW_COUNT],
    base: &[u8; LIMBS],
) -> TexasAirResult<(Vec<RistrettoFpProgram>, [u8; LIMBS])> {
    // The Ristretto identity is a legitimate public base for composed
    // relations (for example a rare `c2 + card` slot-OR target).  The fixed
    // table/Horner schedule remains sound: all table and accumulator rows are
    // canonical identity additions and the output is the identity.
    let mut programs = Vec::with_capacity(COMPRESSED_FIXED_WINDOW_ROWS);
    let mut table = [[0u8; LIMBS]; 16];
    table[0] = ZERO_BYTES;
    for index in 1..16 {
        let (program, output) =
            build_ristretto_fp_program_compressed_point_addition(&table[index - 1], base)?;
        programs.push(program);
        table[index] = output;
    }

    let mut accumulator = ZERO_BYTES;
    for window in windows.iter().rev() {
        if *window >= 16 {
            return Err(TexasAirError::SpecViolation(
                "compressed fixed-window selector is outside 0..15".into(),
            ));
        }
        for _ in 0..4 {
            let (program, output) =
                build_ristretto_fp_program_compressed_point_addition(&accumulator, &accumulator)?;
            programs.push(program);
            accumulator = output;
        }
        let (program, output) = build_ristretto_fp_program_compressed_point_addition(
            &accumulator,
            &table[usize::from(*window)],
        )?;
        programs.push(program);
        accumulator = output;
    }
    debug_assert_eq!(programs.len(), COMPRESSED_FIXED_WINDOW_ROWS);
    Ok((programs, accumulator))
}

/// Prove compressed fixed-window scalar multiplication as one 335-row batch.
pub fn prove_ristretto_fp_program_compressed_fixed_window_scalar_mul(
    scalar: [u8; LIMBS],
    windows: [u8; FIXED_WINDOW_COUNT],
    base: [u8; LIMBS],
) -> TexasAirResult<ArchivedRistrettoFpProgramCompressedFixedWindowScalarMulProof> {
    let (programs, output) = build_compressed_fixed_window_scalar_mul_rows(&windows, &base)?;
    let additions = prove_ristretto_fp_program_batch_owned(programs)?;
    let archive = ArchivedRistrettoFpProgramCompressedFixedWindowScalarMulProof {
        scalar,
        windows,
        base,
        output,
        additions,
    };
    if ristretto_self_verify_enabled() {
        verify_ristretto_fp_program_compressed_fixed_window_scalar_mul(&archive)?;
    }
    Ok(archive)
}

fn validate_compressed_fixed_window_scalar_mul_statement(
    archive: &ArchivedRistrettoFpProgramCompressedFixedWindowScalarMulProof,
) -> TexasAirResult<()> {
    if archive.additions.programs.len() != COMPRESSED_FIXED_WINDOW_ROWS {
        return Err(TexasAirError::ConstraintUnsatisfied(format!(
            "compressed fixed-window scalar multiplication requires exactly {COMPRESSED_FIXED_WINDOW_ROWS} rows"
        )));
    }
    let (expected_programs, expected_output) = build_compressed_fixed_window_scalar_mul_rows(
        &archive.windows,
        &archive.base,
    )?;
    if archive.additions.programs != expected_programs || archive.output != expected_output {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "compressed fixed-window scalar multiplication is detached from its scalar, base, output, or row order"
                .into(),
        ));
    }
    Ok(())
}

/// Verify scalar windows, the complete table/Horner row schedule, and batch STARK.
pub fn verify_ristretto_fp_program_compressed_fixed_window_scalar_mul(
    archive: &ArchivedRistrettoFpProgramCompressedFixedWindowScalarMulProof,
) -> TexasAirResult<()> {
    validate_compressed_fixed_window_scalar_mul_statement(archive)?;
    verify_ristretto_fp_program_batch(&archive.additions)
}

/// Prove multiple compressed fixed-window scalar multiplications in one batch STARK.
pub fn prove_ristretto_fp_program_compressed_fixed_window_scalar_mul_batch(
    inputs: Vec<(
        [u8; LIMBS],
        [u8; FIXED_WINDOW_COUNT],
        [u8; LIMBS],
    )>,
) -> TexasAirResult<ArchivedRistrettoFpProgramCompressedFixedWindowScalarMulBatchProof> {
    if inputs.is_empty() {
        return Err(TexasAirError::SpecViolation(
            "compressed scalar-multiplication batch cannot be empty".into(),
        ));
    }
    let mut statements = Vec::with_capacity(inputs.len());
    let mut programs = Vec::with_capacity(inputs.len() * COMPRESSED_FIXED_WINDOW_ROWS);
    let built = inputs
        .into_par_iter()
        .map(|(scalar, windows, base)| {
            let (rows, output) = build_compressed_fixed_window_scalar_mul_rows(&windows, &base)?;
            Ok((
                RistrettoCompressedFixedWindowScalarMulStatement {
                    scalar,
                    windows,
                    base,
                    output,
                },
                rows,
            ))
        })
        .collect::<TexasAirResult<Vec<_>>>()?;
    for (statement, rows) in built {
        statements.push(statement);
        programs.extend(rows);
    }
    let additions = prove_ristretto_fp_program_batch_owned(programs)?;
    let archive = ArchivedRistrettoFpProgramCompressedFixedWindowScalarMulBatchProof {
        statements,
        additions,
    };
    if ristretto_self_verify_enabled() {
        verify_ristretto_fp_program_compressed_fixed_window_scalar_mul_batch(&archive)?;
    }
    Ok(archive)
}

fn validate_compressed_fixed_window_scalar_mul_batch_statement(
    archive: &ArchivedRistrettoFpProgramCompressedFixedWindowScalarMulBatchProof,
) -> TexasAirResult<()> {
    if archive.statements.is_empty() {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "compressed scalar-multiplication batch cannot be empty".into(),
        ));
    }
    let expected_rows = archive
        .statements
        .len()
        .checked_mul(COMPRESSED_FIXED_WINDOW_ROWS)
        .ok_or_else(|| {
            TexasAirError::SpecViolation(
                "compressed scalar-multiplication batch row count overflow".into(),
            )
        })?;
    if archive.additions.programs.len() != expected_rows {
        return Err(TexasAirError::ConstraintUnsatisfied(format!(
            "compressed scalar-multiplication batch requires exactly {expected_rows} rows"
        )));
    }
    let mut offset = 0usize;
    for statement in &archive.statements {
        let (expected_programs, expected_output) = build_compressed_fixed_window_scalar_mul_rows(
            &statement.windows,
            &statement.base,
        )?;
        let end = offset + COMPRESSED_FIXED_WINDOW_ROWS;
        if archive.additions.programs[offset..end] != expected_programs
            || statement.output != expected_output
        {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "compressed scalar-multiplication batch statement or row order is detached".into(),
            ));
        }
        offset = end;
    }
    Ok(())
}

/// Verify every fixed row slice, output, and the shared STARK.  The caller
/// owns the scalar-window decomposition proofs for the referenced scalars.
pub fn verify_ristretto_fp_program_compressed_fixed_window_scalar_mul_batch(
    archive: &ArchivedRistrettoFpProgramCompressedFixedWindowScalarMulBatchProof,
) -> TexasAirResult<()> {
    validate_compressed_fixed_window_scalar_mul_batch_statement(archive)?;
    verify_ristretto_fp_program_batch(&archive.additions)
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
    scalar: [u8; LIMBS],
    windows: [u8; FIXED_WINDOW_COUNT],
    table: ArchivedRistrettoFpProgramPointTableProof,
) -> TexasAirResult<ArchivedRistrettoFpProgramFixedWindowScalarMulProof> {
    ensure_fixed_window_program_supported()?;
    verify_ristretto_fp_program_point_table(&table)?;
    let (program, outputs) = build_fixed_window_scalar_mul_program(&windows, &table)?;
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
        scalar,
        windows,
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
    verify_ristretto_fp_program_point_table(&archive.table)?;
    let (expected, outputs) =
        build_fixed_window_scalar_mul_program(&archive.windows, &archive.table)?;
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
        assert_eq!(canonicity[2], ValueCanonicity::Witnessed);
        assert_eq!(canonicity[3], ValueCanonicity::Derived);
        assert_eq!(canonicity[4], ValueCanonicity::Witnessed);
        assert_eq!(canonicity[5], ValueCanonicity::Witnessed);
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

        let duplicate_multiplication_output = RistrettoFpProgram {
            values: vec![small(2), small(3), small(0), small(6), small(0)],
            ops: vec![
                RistrettoFpProgramOp::Multiply {
                    a: 0,
                    b: 1,
                    q: 2,
                    out: 3,
                },
                RistrettoFpProgramOp::Multiply {
                    a: 0,
                    b: 1,
                    q: 4,
                    out: 3,
                },
            ],
            outputs: vec![3],
        };
        assert!(program_canonicity(&duplicate_multiplication_output).is_err());

        let forward_produced_operand = RistrettoFpProgram {
            values: vec![small(2), small(3), small(0), small(0), small(0)],
            ops: vec![
                RistrettoFpProgramOp::Add { a: 2, b: 0, out: 3 },
                RistrettoFpProgramOp::Add { a: 0, b: 1, out: 2 },
            ],
            outputs: vec![3],
        };
        assert!(program_canonicity(&forward_produced_operand).is_err());
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
            140
        );
        assert_eq!(
            canonicity
                .iter()
                .filter(|kind| **kind == ValueCanonicity::Witnessed)
                .count(),
            236
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
    fn range_logup_multiset_balances_algebraically() {
        // Native check: for the dummy lookup elements, the sum of use
        // fractions over all rows equals the sum of table fractions --
        // independent of the prover wiring.
        let mut builder = RistrettoFpProgramBuilder::new(&[small(2), small(3), small(5)]);
        let sum = builder.add(0, 1).unwrap();
        let product = builder.multiply(sum, 2).unwrap();
        let difference = builder.subtract(product, 0).unwrap();
        let program = builder.finish(&[sum, product, difference]).unwrap();
        let trace = trace_columns(&program).unwrap();
        let (limb_columns, carry_pair_columns) = trace_tracked_columns(&program);
        let program_width = trace.cols.len() - range_table_column_count(trace.log_size);
        let rows = 1usize << trace.log_size;
        let range = FpRange11::dummy();
        let carry = FpCarry17::dummy();
        use stwo::core::fields::FieldExpOps;
        let mut use_sum = SecureField::from(0u32);
        for column in &limb_columns {
            for row in 0..rows {
                let limb = trace.cols[*column][row];
                use_sum += <FpRange11 as stwo_constraint_framework::Relation<M31, SecureField>>::combine(&range, &[limb]).inverse();
            }
        }
        for pair in &carry_pair_columns {
            for row in 0..rows {
                let low = trace.cols[pair[0]][row];
                let high = trace.cols[pair[1]][row];
                use_sum += <FpCarry17 as stwo_constraint_framework::Relation<M31, SecureField>>::combine(&carry, &[low, high]).inverse();
            }
        }
        let mut table_sum = SecureField::from(0u32);
        for t in 0..range_table_stripes(trace.log_size) {
            for row in 0..rows {
                let mult: SecureField = trace.cols[program_width + 2 * t][row].into();
                let value = trace.cols[program_width + 2 * t + 1][row];
                let den = <FpRange11 as stwo_constraint_framework::Relation<M31, SecureField>>::combine(&range, &[value]).inverse();
                table_sum += mult * den;
            }
        }
        let carry_offset = program_width + 2 * range_table_stripes(trace.log_size);
        for t in 0..carry_table_stripes(trace.log_size) {
            for row in 0..rows {
                let mult: SecureField = trace.cols[carry_offset + 3 * t][row].into();
                let low = trace.cols[carry_offset + 3 * t + 1][row];
                let high = trace.cols[carry_offset + 3 * t + 2][row];
                let den = <FpCarry17 as stwo_constraint_framework::Relation<M31, SecureField>>::combine(&carry, &[low, high]).inverse();
                table_sum += mult * den;
            }
        }
        assert_eq!(use_sum, table_sum, "range multiset is not balanced");
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

    fn small_batch_program(left: u8, right: u8) -> RistrettoFpProgram {
        let mut builder = RistrettoFpProgramBuilder::new(&[small(left), small(right)]);
        let sum = builder.add(0, 1).unwrap();
        let product = builder.multiply(sum, 1).unwrap();
        builder.finish(&[sum, product]).unwrap()
    }

    #[test]
    fn batch_backend_binds_rows_order_and_effective_count() {
        let programs = vec![
            small_batch_program(2, 3),
            small_batch_program(5, 7),
            small_batch_program(11, 13),
        ];
        let archive = prove_ristretto_fp_program_batch(&programs).unwrap();
        verify_ristretto_fp_program_batch(&archive).unwrap();

        let mut row_splice = archive.clone();
        row_splice.programs[1].values[0][0] ^= 1;
        assert!(verify_ristretto_fp_program_batch(&row_splice).is_err());

        let mut row_reorder = archive.clone();
        row_reorder.programs.swap(0, 1);
        assert!(verify_ristretto_fp_program_batch(&row_reorder).is_err());

        // Three rows use a four-row domain whose last row is deterministic
        // padding.  Appending that same row keeps both Merkle trees identical,
        // so rejection here specifically checks that the transcript binds the
        // public effective row count rather than trusting padding shape alone.
        let mut padding_relabel = archive;
        padding_relabel
            .programs
            .push(padding_relabel.programs[2].clone());
        assert!(verify_ristretto_fp_program_batch(&padding_relabel).is_err());
    }

    #[test]
    fn batch_archive_uses_versioned_compact_wire_format() {
        let programs = vec![small_batch_program(2, 3), small_batch_program(5, 7)];
        let archive = prove_ristretto_fp_program_batch(&programs).unwrap();
        let bytes = borsh::to_vec(&archive).unwrap();
        assert_eq!(&bytes[..4], b"RFPB");
        assert_eq!(bytes[4], 1);
        let decoded = ArchivedRistrettoFpProgramBatchProof::try_from_slice(&bytes).unwrap();
        assert_eq!(decoded, archive);
        verify_ristretto_fp_program_batch(&decoded).unwrap();

        let mut legacy_like = bytes;
        legacy_like[..4].copy_from_slice(b"OLD!");
        assert!(ArchivedRistrettoFpProgramBatchProof::try_from_slice(&legacy_like).is_err());
    }

    #[test]
    fn batch_backend_rejects_operation_and_output_shape_mismatch() {
        let first = small_batch_program(2, 3);

        let mut different_operation_builder = RistrettoFpProgramBuilder::new(&[small(5), small(7)]);
        let difference = different_operation_builder.subtract(0, 1).unwrap();
        let product = different_operation_builder.multiply(difference, 1).unwrap();
        let different_operation = different_operation_builder
            .finish(&[difference, product])
            .unwrap();
        assert!(prove_ristretto_fp_program_batch(&[first.clone(), different_operation]).is_err());

        let mut different_outputs = small_batch_program(5, 7);
        different_outputs.outputs.swap(0, 1);
        assert!(prove_ristretto_fp_program_batch(&[first, different_outputs]).is_err());
    }

    #[test]
    fn fixed_shape_compressed_additions_share_one_batch_stark() {
        let (identity_plus_base, identity_plus_base_output) =
            build_ristretto_fp_program_compressed_point_addition(&ZERO_BYTES, &basepoint())
                .unwrap();
        let (base_plus_base, base_plus_base_output) =
            build_ristretto_fp_program_compressed_point_addition(&basepoint(), &basepoint())
                .unwrap();
        assert_eq!(identity_plus_base_output, basepoint());
        assert_eq!(
            base_plus_base_output,
            [
                0x6a, 0x49, 0x32, 0x10, 0xf7, 0x49, 0x9c, 0xd1, 0x7f, 0xec, 0xb5, 0x10, 0xae, 0x0c,
                0xea, 0x23, 0xa1, 0x10, 0xe8, 0xd5, 0xb9, 0x01, 0xf8, 0xac, 0xad, 0xd3, 0x09, 0x5c,
                0x73, 0xa3, 0xb9, 0x19,
            ]
        );
        assert_eq!(identity_plus_base.ops, base_plus_base.ops);
        assert_eq!(identity_plus_base.outputs, base_plus_base.outputs);
        assert_eq!(identity_plus_base.values.len(), base_plus_base.values.len());

        let archive =
            prove_ristretto_fp_program_batch(&[identity_plus_base.clone(), base_plus_base.clone()])
                .unwrap();
        verify_ristretto_fp_program_batch(&archive).unwrap();
        verify_ristretto_fp_program_compressed_point_addition_row(
            &archive.programs[0],
            &ZERO_BYTES,
            &basepoint(),
            &identity_plus_base_output,
        )
        .unwrap();
        verify_ristretto_fp_program_compressed_point_addition_row(
            &archive.programs[1],
            &basepoint(),
            &basepoint(),
            &base_plus_base_output,
        )
        .unwrap();

        let mut wrong_output = base_plus_base_output;
        wrong_output[0] ^= 2;
        assert!(
            verify_ristretto_fp_program_compressed_point_addition_row(
                &archive.programs[1],
                &basepoint(),
                &basepoint(),
                &wrong_output,
            )
            .is_err()
        );

        let mut noncanonical = [0xffu8; LIMBS];
        noncanonical[31] = 0x7f;
        assert!(
            build_ristretto_fp_program_compressed_point_addition(&noncanonical, &basepoint())
                .is_err()
        );
    }

    #[test]
    fn projective_addition_rows_share_one_fixed_batch_shape() {
        let identity = [ZERO_BYTES, ONE_BYTES, ONE_BYTES, ZERO_BYTES];
        let (program, output) =
            build_projective_addition_program_from_coordinates(identity, identity).unwrap();
        assert_eq!(output[0], ZERO_BYTES);
        assert_eq!(output[1], output[2]);
        assert_eq!(output[3], ZERO_BYTES);
        assert_eq!(program.values.len(), 38);
        assert_eq!(program.ops.len(), 18);
        assert_eq!(program.outputs, vec![31, 33, 35, 37]);

        let archive = prove_ristretto_fp_program_projective_addition_batch(
            &[identity, identity],
            &[identity, identity],
            &[output, output],
        )
        .unwrap();
        verify_ristretto_fp_program_projective_addition_batch(&archive).unwrap();
        let mut swapped = archive.clone();
        swapped.output[0][0][0] ^= 1;
        assert!(verify_ristretto_fp_program_projective_addition_batch(&swapped).is_err());
    }

    #[test]
    fn witness_rows_satisfy_direct_program_constraints() {
        let mut builder = RistrettoFpProgramBuilder::new(&[small(7), small(6)]);
        let difference = builder.subtract(0, 1).unwrap();
        let program = builder.finish(&[difference]).unwrap();
        let trace = trace_columns(&program).unwrap();
        assert_program_trace(&program, &trace);
    }

    /// Row-level assertion evaluator that delegates every constraint to
    /// [`AssertEvaluator`] but treats the shared LogUp as unchecked: the
    /// balanced-sum property is exercised end-to-end by the real prover
    /// roundtrips, and replaying the interaction layer here would duplicate
    /// that machinery for no extra coverage.
    struct NoLogupAssertEvaluator<'a>(stwo_constraint_framework::AssertEvaluator<'a>);

    impl<'a> EvalAtRow for NoLogupAssertEvaluator<'a> {
        type F = M31;
        type EF = SecureField;

        fn next_interaction_mask<const N: usize>(
            &mut self,
            interaction: usize,
            offsets: [isize; N],
        ) -> [Self::F; N] {
            self.0.next_interaction_mask(interaction, offsets)
        }

        fn add_constraint<G>(&mut self, constraint: G)
        where
            Self::EF: std::ops::Mul<G, Output = Self::EF> + From<G>,
        {
            self.0.add_constraint(constraint)
        }

        fn combine_ef(values: [Self::F; 4]) -> Self::EF {
            SecureField::from_m31_array(values)
        }

        fn add_to_relation<R: Relation<Self::F, Self::EF>>(
            &mut self,
            _entry: stwo_constraint_framework::RelationEntry<'_, Self::F, Self::EF, R>,
        ) {
        }

        fn finalize_logup_in_pairs(&mut self) {}
    }

    fn assert_program_trace(program: &RistrettoFpProgram, trace: &MethodTrace) {
        let scope = scope_columns(program);
        let evals = stwo::core::pcs::TreeVec::new(vec![
            scope.cols.iter().collect(),
            trace.cols.iter().collect(),
        ]);
        let range = FpRange11::draw(&mut stwo::core::channel::Poseidon252Channel::default());
        let carry = FpCarry17::draw(&mut stwo::core::channel::Poseidon252Channel::default());
        stwo_constraint_framework::assert_constraints_on_trace(
            &evals,
            LOG_SIZE,
            |eval| {
                FpProgramAir::new(LOG_SIZE, program.clone(), range.clone(), carry.clone())
                    .evaluate(NoLogupAssertEvaluator(eval));
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
        let op_witness_start =
            program.values.len() * LIMB_COUNT + strict_values * (2 * LIMB_COUNT + 3);
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
        let op_witness_start =
            program.values.len() * LIMB_COUNT + strict_values * (2 * LIMB_COUNT + 3);
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
        evaluator = FpProgramAir::new(
            LOG_SIZE,
            program,
            FpRange11::draw(&mut stwo::core::channel::Poseidon252Channel::default()),
            FpCarry17::draw(&mut stwo::core::channel::Poseidon252Channel::default()),
        )
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

    fn structural_scalar_windows(value: u8) -> ArchivedRistrettoScalarWindowsProof {
        let mut scalar = [0u8; LIMBS];
        scalar[0] = value;
        let mut windows = [0u8; FIXED_WINDOW_COUNT];
        windows[0] = value & 0x0f;
        windows[1] = value >> 4;
        ArchivedRistrettoScalarWindowsProof {
            scalar,
            windows,
            canonical: crate::ristretto_scalar_air::ArchivedRistrettoScalarCanonicalProof {
                value: scalar,
                stark_proof_bytes: Vec::new(),
            },
            stark_proof_bytes: Vec::new(),
        }
    }

    #[test]
    fn compressed_fixed_window_batch_has_canonical_table_and_horner_order() {
        let scalar_windows = structural_scalar_windows(0x12);
        let (programs, output) =
            build_compressed_fixed_window_scalar_mul_rows(&scalar_windows.windows, &basepoint())
                .unwrap();
        assert_eq!(programs.len(), COMPRESSED_FIXED_WINDOW_ROWS);
        use poker_protocol::crypto::curve::{Curve, CurveScalar, RistrettoCurve};
        let expected = RistrettoCurve::base_g() * <RistrettoCurve as Curve>::Scalar::from_u64(0x12);
        assert_eq!(output.as_slice(), expected.compress().as_bytes());
        let archive = ArchivedRistrettoFpProgramCompressedFixedWindowScalarMulProof {
            scalar: scalar_windows.scalar,
            windows: scalar_windows.windows,
            base: basepoint(),
            output,
            additions: ArchivedRistrettoFpProgramBatchProof {
                programs,
                stark_proof_bytes: Vec::new(),
                range_claimed_sum: [0, 0, 0, 0],
            },
        };
        validate_compressed_fixed_window_scalar_mul_statement(&archive).unwrap();

        let mut row_swap = archive.clone();
        row_swap.additions.programs.swap(0, 1);
        assert!(validate_compressed_fixed_window_scalar_mul_statement(&row_swap).is_err());

        let mut output_splice = archive.clone();
        output_splice.output[0] ^= 2;
        assert!(validate_compressed_fixed_window_scalar_mul_statement(&output_splice).is_err());

        let mut scalar_splice = archive.clone();
        scalar_splice.windows[0] = 3;
        assert!(validate_compressed_fixed_window_scalar_mul_statement(&scalar_splice).is_err());

        let mut base_splice = archive;
        base_splice.base = output;
        assert!(validate_compressed_fixed_window_scalar_mul_statement(&base_splice).is_err());
        let (identity_rows, identity_output) =
            build_compressed_fixed_window_scalar_mul_rows(&[0; 64], &ZERO_BYTES).unwrap();
        assert_eq!(identity_rows.len(), COMPRESSED_FIXED_WINDOW_ROWS);
        assert_eq!(identity_output, ZERO_BYTES);
    }

    #[test]
    fn compressed_scalar_multiplications_share_one_canonical_batch_schedule() {
        let scalar_one = structural_scalar_windows(1);
        let scalar_two = structural_scalar_windows(2);
        let (rows_one, output_one) =
            build_compressed_fixed_window_scalar_mul_rows(&scalar_one.windows, &basepoint())
                .unwrap();
        let (rows_two, output_two) =
            build_compressed_fixed_window_scalar_mul_rows(&scalar_two.windows, &basepoint())
                .unwrap();
        let mut programs = rows_one;
        programs.extend(rows_two);
        let archive = ArchivedRistrettoFpProgramCompressedFixedWindowScalarMulBatchProof {
            statements: vec![
                RistrettoCompressedFixedWindowScalarMulStatement {
                    scalar: scalar_one.scalar,
                    windows: scalar_one.windows,
                    base: basepoint(),
                    output: output_one,
                },
                RistrettoCompressedFixedWindowScalarMulStatement {
                    scalar: scalar_two.scalar,
                    windows: scalar_two.windows,
                    base: basepoint(),
                    output: output_two,
                },
            ],
            additions: ArchivedRistrettoFpProgramBatchProof {
                programs,
                stark_proof_bytes: Vec::new(),
                range_claimed_sum: [0, 0, 0, 0],
            },
        };
        assert_eq!(
            archive.additions.programs.len(),
            2 * COMPRESSED_FIXED_WINDOW_ROWS
        );
        validate_compressed_fixed_window_scalar_mul_batch_statement(&archive).unwrap();

        let mut statement_swap = archive.clone();
        statement_swap.statements.swap(0, 1);
        assert!(
            validate_compressed_fixed_window_scalar_mul_batch_statement(&statement_swap).is_err()
        );

        let mut cross_slice_swap = archive.clone();
        cross_slice_swap.additions.programs.swap(
            COMPRESSED_FIXED_WINDOW_ROWS - 1,
            2 * COMPRESSED_FIXED_WINDOW_ROWS - 1,
        );
        assert!(
            validate_compressed_fixed_window_scalar_mul_batch_statement(&cross_slice_swap).is_err()
        );

        let mut padding_relabel = archive;
        padding_relabel
            .additions
            .programs
            .push(padding_relabel.additions.programs[0].clone());
        assert!(
            validate_compressed_fixed_window_scalar_mul_batch_statement(&padding_relabel).is_err()
        );
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
    fn folded_projective_encode_binds_addition_output() {
        let left = ristretto_fp_program_projective_point_from_decode(
            prove_ristretto_fp_program_point_decode(&basepoint()).unwrap(),
        )
        .unwrap();
        let right = ristretto_fp_program_projective_point_from_decode(
            prove_ristretto_fp_program_point_decode(&basepoint()).unwrap(),
        )
        .unwrap();
        let addition = prove_ristretto_fp_program_projective_addition(left, right).unwrap();
        let point = ArchivedRistrettoFpProgramProjectivePoint {
            x: addition.x,
            y: addition.y,
            z: addition.z,
            t: addition.t,
            source: ArchivedRistrettoFpProgramProjectivePointSource::Addition(Box::new(addition)),
        };
        let archive = prove_ristretto_fp_program_projective_point_encode(point).unwrap();
        assert_eq!(
            archive.encoding,
            [
                0x6a, 0x49, 0x32, 0x10, 0xf7, 0x49, 0x9c, 0xd1, 0x7f, 0xec, 0xb5, 0x10, 0xae, 0x0c,
                0xea, 0x23, 0xa1, 0x10, 0xe8, 0xd5, 0xb9, 0x01, 0xf8, 0xac, 0xad, 0xd3, 0x09, 0x5c,
                0x73, 0xa3, 0xb9, 0x19,
            ]
        );
        verify_ristretto_fp_program_projective_point_encode(&archive).unwrap();

        let mut spliced_encoding = archive.clone();
        spliced_encoding.encoding[0] ^= 2;
        assert!(verify_ristretto_fp_program_projective_point_encode(&spliced_encoding).is_err());

        let mut noncanonical_encoding = archive.clone();
        noncanonical_encoding.encoding = P_BYTES;
        assert!(
            verify_ristretto_fp_program_projective_point_encode(&noncanonical_encoding).is_err()
        );

        let mut spliced_point = archive.clone();
        spliced_point.point.x[0] ^= 2;
        assert!(verify_ristretto_fp_program_projective_point_encode(&spliced_point).is_err());

        let mut spliced_addition = archive;
        let ArchivedRistrettoFpProgramProjectivePointSource::Addition(addition) =
            &mut spliced_addition.point.source
        else {
            unreachable!("test point comes from projective addition");
        };
        addition.x[0] ^= 2;
        assert!(verify_ristretto_fp_program_projective_point_encode(&spliced_addition).is_err());
    }

    #[test]
    fn folded_projective_encode_handles_scaled_identity() {
        let left = ristretto_fp_program_projective_point_from_decode(
            prove_ristretto_fp_program_point_decode(&ZERO_BYTES).unwrap(),
        )
        .unwrap();
        let right = ristretto_fp_program_projective_point_from_decode(
            prove_ristretto_fp_program_point_decode(&ZERO_BYTES).unwrap(),
        )
        .unwrap();
        let addition = prove_ristretto_fp_program_projective_addition(left, right).unwrap();
        assert_eq!(addition.x, ZERO_BYTES);
        assert_eq!(addition.y, addition.z);
        assert_eq!(addition.t, ZERO_BYTES);
        assert_ne!(addition.z, ONE_BYTES);
        let point = ArchivedRistrettoFpProgramProjectivePoint {
            x: addition.x,
            y: addition.y,
            z: addition.z,
            t: addition.t,
            source: ArchivedRistrettoFpProgramProjectivePointSource::Addition(Box::new(addition)),
        };
        let archive = prove_ristretto_fp_program_projective_point_encode(point).unwrap();
        assert_eq!(archive.encoding, ZERO_BYTES);
        verify_ristretto_fp_program_projective_point_encode(&archive).unwrap();
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
