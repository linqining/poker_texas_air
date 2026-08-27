//! Single-STARK Ristretto255 scalar-field (`mod l`) program AIR.
//!
//! A program commits all canonical scalar values (below the Ristretto group
//! order `l`) and a fixed list of add/sub/mul operations modulo `l`.  This is
//! the Path A companion of the Fp program AIR (`ristretto_fp_program_air`,
//! which constrains `p = 2^255 - 19`): the Bayer--Groth scalar-side schedule
//! (powers table, expected product, final product check) lives in the scalar
//! field, and this AIR gives it constraints without any host-trusted
//! evaluation.
//!
//! The trace layout, carry bounds, LogUp range tables, and canonicity
//! mechanism are structurally identical to the Fp program AIR; the modulus is
//! encoded by exactly two constants (`L_BYTES` and its 2^256 complement), so
//! the proven constraint math carries over unchanged.  The public types are
//! deliberately distinct from the Fp family so a scalar program can never be
//! verified by the Fp AIR or vice versa.

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
use crate::trace_gen::MethodTrace;

const LIMBS: usize = 32;
/// The Ristretto255 group order `l = 2^252 + 27742317777372353535851937790883648493`,
/// little-endian: the modulus of every value and operation in this module.
const L_BYTES: [u8; LIMBS] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];
/// `2^256 - l` little-endian: `value + C < 2^256` exactly when `value < l`.
const CANONICITY_COMPLEMENT_BYTES: [u8; LIMBS] = [
    0x13, 0x2c, 0x0a, 0xa3, 0xe5, 0x9c, 0xed, 0xa7, 0x29, 0x63, 0x08, 0x5d, 0x21, 0x06, 0x21, 0xeb,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xef,
];
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

const ONE_BYTES: [u8; LIMBS] = {
    let mut bytes = [0u8; LIMBS];
    bytes[0] = 1;
    bytes
};

const ZERO_BYTES: [u8; LIMBS] = [0u8; LIMBS];

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

/// `l` as twenty-four 11-bit limbs (top limb zero).
const L_BASE_LIMBS: [u16; LIMB_COUNT] = base_limbs(&L_BYTES);
/// `2^256 − l` as twenty-four 11-bit limbs.
const CANONICITY_COMPLEMENT_LIMBS: [u16; LIMB_COUNT] = base_limbs(&CANONICITY_COMPLEMENT_BYTES);
/// Bound on a multiplication carry magnitude: `|carry| ≤ (2·L·(2^11−1)² +
/// terms) / 2^11 < 2^17`, so every magnitude splits into two range-checked
/// 11-bit limbs and every relation stays far below the M31 wraparound bound.
const MAX_MUL_CARRY_MAGNITUDE: u32 = 1 << 17;

/// One field operation in the public program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum RistrettoScalarProgramOp {
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
pub struct RistrettoScalarProgram {
    /// All canonical little-endian field values in column order.
    pub values: Vec<[u8; LIMBS]>,
    /// Arithmetic operations.
    pub ops: Vec<RistrettoScalarProgramOp>,
    /// Public output value indices.
    pub outputs: Vec<u16>,
}

/// Serialized single-STARK field-program proof.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoScalarProgramProof {
    /// Authenticated program statement.
    pub program: RistrettoScalarProgram,
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
pub struct ArchivedRistrettoScalarProgramBatchProof {
    /// Public programs in canonical row order. All operation/output layouts
    /// are identical; only field values differ between rows.
    pub programs: Vec<RistrettoScalarProgram>,
    /// Serialized Stwo proof for the complete batch.
    pub stark_proof_bytes: Vec<u8>,
    /// Public claimed sum of the shared range LogUp (4 M31 coordinates).
    pub range_claimed_sum: [u32; 4],
}

const FP_PROGRAM_BATCH_ARCHIVE_MAGIC: [u8; 4] = *b"RSPB";
const FP_PROGRAM_BATCH_ARCHIVE_VERSION: u8 = 1;

impl BorshSerialize for ArchivedRistrettoScalarProgramBatchProof {
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

impl BorshDeserialize for ArchivedRistrettoScalarProgramBatchProof {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if magic != FP_PROGRAM_BATCH_ARCHIVE_MAGIC {
            // Decode the pre-versioned layout explicitly for existing nested
            // archives. New encoders always emit the magic above; legacy data
            // is accepted only through this separate, unambiguous path.
            let program_count = u32::from_le_bytes(magic) as usize;
            if program_count > 1_000_000 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "legacy Ristretto Fp program batch row count is unreasonable",
                ));
            }
            let mut programs = Vec::with_capacity(program_count);
            for _ in 0..program_count {
                programs.push(RistrettoScalarProgram::deserialize_reader(reader)?);
            }
            return Ok(Self {
                programs,
                stark_proof_bytes: Vec::<u8>::deserialize_reader(reader)?,
                range_claimed_sum: <[u32; 4]>::deserialize_reader(reader)?,
            });
        }
        let version = u8::deserialize_reader(reader)?;
        if version != FP_PROGRAM_BATCH_ARCHIVE_VERSION {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unsupported Ristretto Fp program batch archive version {version}"),
            ));
        }
        let ops = Vec::<RistrettoScalarProgramOp>::deserialize_reader(reader)?;
        let outputs = Vec::<u16>::deserialize_reader(reader)?;
        let values = Vec::<Vec<[u8; LIMBS]>>::deserialize_reader(reader)?;
        let stark_proof_bytes = Vec::<u8>::deserialize_reader(reader)?;
        let range_claimed_sum = <[u32; 4]>::deserialize_reader(reader)?;
        let programs = values
            .into_iter()
            .map(|values| RistrettoScalarProgram {
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

/// Incremental host-side program builder.
#[derive(Debug, Default)]
pub struct RistrettoScalarProgramBuilder {
    values: Vec<[u8; LIMBS]>,
    ops: Vec<RistrettoScalarProgramOp>,
}

impl RistrettoScalarProgramBuilder {
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
        self.ops.push(RistrettoScalarProgramOp::Add { a, b, out });
        Ok(out)
    }

    /// Append `a-b`.
    pub fn subtract(&mut self, a: u16, b: u16) -> TexasAirResult<u16> {
        let out_value = subtract_big(&big_uint(&self.value(a)?), &big_uint(&self.value(b)?));
        let out = self.push_value(limbs(&out_value))?;
        self.ops
            .push(RistrettoScalarProgramOp::Subtract { a, b, out });
        Ok(out)
    }

    /// Append `a*b`, including the committed quotient value.
    pub fn multiply(&mut self, a: u16, b: u16) -> TexasAirResult<u16> {
        let product = big_uint(&self.value(a)?) * big_uint(&self.value(b)?);
        let (quotient, remainder) = product.div_rem(modulus());
        let q = self.push_value(limbs(&quotient))?;
        let out = self.push_value(limbs(&remainder))?;
        self.ops
            .push(RistrettoScalarProgramOp::Multiply { a, b, out, q });
        Ok(out)
    }

    /// Finalize with public output indices.
    pub fn finish(self, outputs: &[u16]) -> TexasAirResult<RistrettoScalarProgram> {
        validate_indices(self.values.len(), self.ops.len(), outputs)?;
        Ok(RistrettoScalarProgram {
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
relation!(ScalarRange11, 1);

/// Paired (lo, hi) 11-bit-limb LogUp relation for multiplication carries:
/// every magnitude below `2^17` splits as `lo + 2048·hi` with `lo < 2048`
/// and `hi < 64`, so one arity-2 entry ranges the full carry against a
/// 131,072-entry striped pair table.
relation!(ScalarCarry17, 2);

#[derive(Clone)]
pub(crate) struct ScalarProgramAir {
    log_size: u32,
    program: RistrettoScalarProgram,
    range: ScalarRange11,
    carry: ScalarCarry17,
    /// Precomputed preprocessed scope-column identifiers (built once instead
    /// of one `format!` allocation per value per evaluate pass).
    scope_ids: Vec<PreProcessedColumnId>,
    /// Precomputed value canonicity classes.
    canonicity: Vec<ValueCanonicity>,
}

impl ScalarProgramAir {
    /// Build the AIR, precomputing the preprocessed-column identifiers and
    /// the canonicity classification shared by every evaluate call.
    fn new(
        log_size: u32,
        program: RistrettoScalarProgram,
        range: ScalarRange11,
        carry: ScalarCarry17,
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
    MODULUS.get_or_init(|| BigUint::from_bytes_le(&L_BYTES))
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
fn canonicity_witness(value: &[u16; LIMB_COUNT]) -> ([u16; LIMB_COUNT], [u16; LIMB_COUNT]) {
    let mut sum = [0u16; LIMB_COUNT];
    let mut carries = [0u16; LIMB_COUNT];
    let mut carry_in = 0u16;
    for index in 0..LIMB_COUNT {
        let total = value[index] + CANONICITY_COMPLEMENT_LIMBS[index] + carry_in;
        sum[index] = total % BASE as u16;
        carry_in = total / BASE as u16;
        carries[index] = carry_in;
    }
    debug_assert_eq!(
        carry_in, 0,
        "value < p plus its complement stays below 2^256"
    );
    (sum, carries)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValueCanonicity {
    /// A root/constant or arithmetic result carrying its own strict witness.
    Witnessed,
    /// Canonicality follows from a multiplication quotient relation.
    Derived,
}

fn program_canonicity(program: &RistrettoScalarProgram) -> TexasAirResult<Vec<ValueCanonicity>> {
    let mut produced = vec![false; program.values.len()];
    for op in &program.ops {
        let (a, b, first_output, second_output) = match *op {
            RistrettoScalarProgramOp::Add { a, b, out }
            | RistrettoScalarProgramOp::Subtract { a, b, out } => (a, b, out, None),
            RistrettoScalarProgramOp::Multiply { a, b, out, q } => {
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
            RistrettoScalarProgramOp::Add { a, b, .. }
            | RistrettoScalarProgramOp::Subtract { a, b, .. }
            | RistrettoScalarProgramOp::Multiply { a, b, .. } => (a, b),
        };
        if !available[usize::from(a)] || !available[usize::from(b)] {
            return Err(TexasAirError::SpecViolation(
                "Fp program operation consumes a value produced by a later operation".into(),
            ));
        }
        match *op {
            RistrettoScalarProgramOp::Add { out, .. }
            | RistrettoScalarProgramOp::Subtract { out, .. } => {
                // The modular relation alone does not determine whether the
                // prover chose the reduced representative, so add/sub outputs
                // retain their direct `< p` witness.
                available[usize::from(out)] = true;
            }
            RistrettoScalarProgramOp::Multiply { out, q, .. } => {
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

fn program_witness(program: &RistrettoScalarProgram) -> TexasAirResult<ProgramWitness> {
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
            RistrettoScalarProgramOp::Add { a, b, out }
            | RistrettoScalarProgramOp::Subtract { a, b, out } => {
                let subtract = matches!(op, RistrettoScalarProgramOp::Subtract { .. });
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
                        - signed_k * i64::from(L_BASE_LIMBS[index]);
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
            RistrettoScalarProgramOp::Multiply { a, b, out, q } => {
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
                let quotient_prime_limbs = convolution(&value_limbs[q], &L_BASE_LIMBS);
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

fn append_limb(row: &mut Vec<M31>, limb: u16) {
    // 11-bit limb; range membership is proven by the shared LogUp table.
    row.push(M31::from(u32::from(limb)));
}

/// Column indices of every LogUp use entry in one program row, in the exact
/// order the AIR emits the corresponding relation entries (value limbs and
/// witnessed canonicity sum limbs as single-limb entries, then per-mul-carry
/// `(low, high)` limb pairs).
fn trace_row_with_limbs(
    program: &RistrettoScalarProgram,
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

fn trace_row(program: &RistrettoScalarProgram) -> TexasAirResult<Vec<M31>> {
    Ok(trace_row_with_limbs(program)?.0)
}

/// Shape-only mirror of [`trace_row_with_limbs`]: returns the program-row
/// width, the single-limb LogUp column indices, and the carry-pair column
/// index pairs without materializing any BigUint witness.  The layout
/// depends only on the value count, the canonicity pattern, and the op list,
/// so verifiers use it to size the trace commitment without re-deriving the
/// (constraint-enforced) witness.
fn trace_layout(
    program: &RistrettoScalarProgram,
) -> TexasAirResult<(usize, Vec<usize>, Vec<[usize; 2]>)> {
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
            RistrettoScalarProgramOp::Add { .. } | RistrettoScalarProgramOp::Subtract { .. } => {
                width += 3 + 2 * LIMB_COUNT;
            }
            RistrettoScalarProgramOp::Multiply { .. } => {
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

fn trace_columns(program: &RistrettoScalarProgram) -> TexasAirResult<MethodTrace> {
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

fn scope_row(program: &RistrettoScalarProgram) -> Vec<M31> {
    let mut row = Vec::with_capacity(program.values.len() * SCOPE_COLUMNS_PER_VALUE);
    for value in &program.values {
        row.extend(scope_packed(value).into_iter().map(M31::from));
    }
    row
}

fn scope_columns(program: &RistrettoScalarProgram) -> MethodTrace {
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

fn validate_program_batch_shape(programs: &[RistrettoScalarProgram]) -> TexasAirResult<()> {
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
fn trace_tracked_columns(program: &RistrettoScalarProgram) -> (Vec<usize>, Vec<[usize; 2]>) {
    // Shape-only derivation: `trace_layout` mirrors the column indices of
    // `trace_row_with_limbs` without materializing any BigUint witness.
    let (_, limb_columns, carry_pair_columns) =
        trace_layout(program).expect("program shape was validated before trace generation");
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
            let value = u32::from(low[row].0) as usize + 2048 * u32::from(high[row].0) as usize;
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

fn trace_columns_batch(programs: &[RistrettoScalarProgram]) -> TexasAirResult<MethodTrace> {
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

fn scope_columns_batch(programs: &[RistrettoScalarProgram]) -> TexasAirResult<MethodTrace> {
    validate_program_batch_shape(programs)?;
    let log_size = batch_log_size(programs.len())?;
    let rows = 1usize << log_size;
    let scope_rows = programs.par_iter().map(scope_row).collect::<Vec<_>>();
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

fn preprocessed_ids(program: &RistrettoScalarProgram) -> Vec<PreProcessedColumnId> {
    (0..program.values.len() * SCOPE_COLUMNS_PER_VALUE)
        .map(|column| PreProcessedColumnId {
            id: format!("ristretto.fp.program.scope.v2.{column}").into(),
        })
        .collect()
}

impl FrameworkEval for ScalarProgramAir {
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
                            + E::F::from(M31::from(u32::from(CANONICITY_COMPLEMENT_LIMBS[index])))
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
                    top_reconstruction += bit.clone() * E::F::from(M31::from(1u32 << bit_index));
                }
                eval.add_constraint(sum[LIMB_COUNT - 1].clone() - top_reconstruction);
            }

            for (group_index, group) in value.chunks(SCOPE_LIMBS_PER_COLUMN).enumerate() {
                let scope = eval.get_preprocessed_column(
                    ids[value_index * SCOPE_COLUMNS_PER_VALUE + group_index].clone(),
                );
                let mut packed: E::F = scope;
                for (shift, limb) in group.iter().enumerate() {
                    packed = packed - limb.clone() * E::F::from(M31::from(BASE.pow(shift as u32)));
                }
                eval.add_constraint(packed);
            }
            value_limbs.push(value);
        }

        for op in &self.program.ops {
            match *op {
                RistrettoScalarProgramOp::Add { a, b, out }
                | RistrettoScalarProgramOp::Subtract { a, b, out } => {
                    let expected_subtract = matches!(op, RistrettoScalarProgramOp::Subtract { .. });
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
                                    * E::F::from(M31::from(u32::from(L_BASE_LIMBS[index])))
                                - base.clone() * carry_out,
                        );
                    }
                }
                RistrettoScalarProgramOp::Multiply { a, b, out, q } => {
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
                        signed_carries.push(positive * magnitude.clone() - negative * magnitude);
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
                                    * E::F::from(M31::from(u32::from(L_BASE_LIMBS[right_index])));
                        }
                        if limb_index < LIMB_COUNT {
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
fn program_statement_bytes(program: &RistrettoScalarProgram) -> Vec<u8> {
    let mut out = Vec::new();
    for value in &program.values {
        for packed in scope_packed(value) {
            out.extend_from_slice(&packed.to_le_bytes());
        }
    }
    out.extend_from_slice(&(program.ops.len() as u64).to_le_bytes());
    for op in &program.ops {
        let (selector, indices) = match *op {
            RistrettoScalarProgramOp::Add { a, b, out } => (0u8, [a, b, out, 0]),
            RistrettoScalarProgramOp::Subtract { a, b, out } => (1u8, [a, b, out, 0]),
            RistrettoScalarProgramOp::Multiply { a, b, out, q } => (2u8, [a, b, out, q]),
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

fn program_statement_digest(program: &RistrettoScalarProgram) -> [u32; 16] {
    use blake2::digest::Digest;
    let digest = blake2::Blake2b512::digest(&program_statement_bytes(program));
    core::array::from_fn(|index| {
        u32::from_le_bytes(
            digest[4 * index..4 * index + 4]
                .try_into()
                .expect("4 bytes"),
        )
    })
}

fn mix_scalar_program(channel: &mut impl Channel, program: &RistrettoScalarProgram) {
    channel.mix_u32s(&program_statement_digest(program));
}

fn mix_scalar_program_batch(channel: &mut impl Channel, programs: &[RistrettoScalarProgram]) {
    channel.mix_u64(0x7269_7374_6261_7463);
    channel.mix_u64(programs.len() as u64);
    for program in programs {
        mix_scalar_program(channel, program);
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
fn scalar_range_interaction(
    trace: &MethodTrace,
    log_size: u32,
    range: &ScalarRange11,
    carry: &ScalarCarry17,
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
            Entry::CarryTable(t) => -PackedSecureField::from(pack_vec(&carry_mult[*t], vector_row)),
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
    carry: &ScalarCarry17,
    low: &stwo::prover::backend::simd::m31::PackedBaseField,
    high: &stwo::prover::backend::simd::m31::PackedBaseField,
) -> stwo::prover::backend::simd::qm31::PackedSecureField {
    use stwo::prover::backend::simd::qm31::PackedSecureField;
    let combined: [stwo::prover::backend::simd::m31::PackedBaseField; 2] =
        [low.clone(), high.clone()];
    <ScalarCarry17 as stwo_constraint_framework::Relation<_, PackedSecureField>>::combine(
        carry, &combined,
    )
}

/// Prove one fixed public Fp program in a single STARK with the shared
/// range LogUp interaction layer.
pub fn prove_ristretto_scalar_program(
    program: &RistrettoScalarProgram,
) -> TexasAirResult<ArchivedRistrettoScalarProgramProof> {
    let trace = trace_columns(program)?;
    let scope = scope_columns(program);
    let config = crate::prover_context::protocol_pcs_config();
    let twiddles =
        crate::prover_context::simd_twiddles(LOG_SIZE + config.fri_config.log_blowup_factor);
    let mut channel = stwo::core::channel::Poseidon252Channel::default();
    mix_scalar_program(&mut channel, program);
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
    let range = ScalarRange11::draw(&mut channel);
    let carry = ScalarCarry17::draw(&mut channel);
    let (interaction, range_sum) = scalar_range_interaction(
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
        ScalarProgramAir::new(LOG_SIZE, program.clone(), range, carry),
        range_sum,
    );
    let proof = prove(&[&component], &mut channel, scheme)
        .map_err(|error| TexasAirError::StwoProverError(error.to_string()))?;
    let stark_proof_bytes = options()
        .serialize(&proof)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
    Ok(ArchivedRistrettoScalarProgramProof {
        program: program.clone(),
        stark_proof_bytes,
        range_claimed_sum: range_sum.to_m31_array().map(|limb| limb.0),
    })
}

/// Verify the fixed public Fp program in one STARK.
pub fn verify_ristretto_scalar_program(
    archive: &ArchivedRistrettoScalarProgramProof,
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
    mix_scalar_program(&mut channel, &archive.program);
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
    let range = ScalarRange11::draw(&mut channel);
    let carry = ScalarCarry17::draw(&mut channel);
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
        ScalarProgramAir::new(LOG_SIZE, archive.program.clone(), range, carry),
        claimed,
    );
    stwo::core::verifier::verify(&[&component], &mut channel, &mut scheme, proof)
        .map_err(|error| TexasAirError::ConstraintUnsatisfied(error.to_string()))
}

/// Prove equal-shape canonical field programs as rows of one STARK.
pub fn prove_ristretto_scalar_program_batch(
    programs: &[RistrettoScalarProgram],
) -> TexasAirResult<ArchivedRistrettoScalarProgramBatchProof> {
    prove_ristretto_scalar_program_batch_owned(programs.to_vec())
}

/// Owning variant of [`prove_ristretto_scalar_program_batch`]: callers that no
/// longer need the programs hand them over instead of re-cloning the whole
/// batch (N x 335 deep programs) into the archive.
pub(crate) fn prove_ristretto_scalar_program_batch_owned(
    programs: Vec<RistrettoScalarProgram>,
) -> TexasAirResult<ArchivedRistrettoScalarProgramBatchProof> {
    validate_program_batch_shape(&programs)?;
    let log_size = batch_log_size(programs.len())?;
    let trace = trace_columns_batch(&programs)?;
    let scope = scope_columns_batch(&programs)?;
    let config = crate::prover_context::protocol_pcs_config();
    let twiddles =
        crate::prover_context::simd_twiddles(log_size + config.fri_config.log_blowup_factor);
    let mut channel = stwo::core::channel::Poseidon252Channel::default();
    mix_scalar_program_batch(&mut channel, &programs);
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
    let range = ScalarRange11::draw(&mut channel);
    let carry = ScalarCarry17::draw(&mut channel);
    let (interaction, range_sum) = scalar_range_interaction(
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
        ScalarProgramAir::new(log_size, programs[0].clone(), range, carry),
        range_sum,
    );
    let proof = prove(&[&component], &mut channel, scheme)
        .map_err(|error| TexasAirError::StwoProverError(error.to_string()))?;
    let stark_proof_bytes = options()
        .serialize(&proof)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
    Ok(ArchivedRistrettoScalarProgramBatchProof {
        programs,
        stark_proof_bytes,
        range_claimed_sum: range_sum.to_m31_array().map(|limb| limb.0),
    })
}

/// Verify an equal-shape field-program batch.
pub fn verify_ristretto_scalar_program_batch(
    archive: &ArchivedRistrettoScalarProgramBatchProof,
) -> TexasAirResult<()> {
    type Proof = StarkProof<Poseidon252MerkleHasher>;
    validate_program_batch_shape(&archive.programs)?;
    let log_size = batch_log_size(archive.programs.len())?;
    let proof: Proof = options()
        .deserialize(&archive.stark_proof_bytes)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
    let (program_width, limb_columns, carry_pair_columns) = trace_layout(&archive.programs[0])?;
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
    mix_scalar_program_batch(&mut channel, &archive.programs);
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
    let range = ScalarRange11::draw(&mut channel);
    let carry = ScalarCarry17::draw(&mut channel);
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
        ScalarProgramAir::new(log_size, template.clone(), range, carry),
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

// ============================================================================
// Bayer--Groth scalar-side schedule (Path A)
// ============================================================================

/// The Bayer--Groth scalar-side schedule over the Ristretto scalar field.
///
/// Given the transcript challenges `x` (powers), `y` and `z` (product) and
/// `pc` (final product), one STARK proves:
///
/// - the powers table `p_1 = x`, `p_{i+1} = p_i · x (mod l)`;
/// - the terms `v_i = y·i + p_i − z (mod l)`;
/// - the running product `q_1 = v_1`, `q_{i+1} = q_i · v_{i+1} (mod l)`;
/// - the final check value `f = pc · q_n (mod l)`.
///
/// `f` is the value the Bayer--Groth verifier compares against the proof
/// wire's `b_response[n-1]`; with this STARK that comparison is the only
/// remaining native step of the scalar-side schedule.
///
/// The program shape is deterministic in `(x, y, z, pc, n)`, so the verifier
/// rebuilds it and rejects any detached program before checking the STARK.
pub fn build_bayer_groth_scalar_schedule(
    powers_challenge: &[u8; LIMBS],
    product_y: &[u8; LIMBS],
    product_z: &[u8; LIMBS],
    product_challenge: &[u8; LIMBS],
    deck_size: usize,
) -> TexasAirResult<RistrettoScalarProgram> {
    let modulus = modulus().clone();
    for (label, value) in [
        ("powers challenge", powers_challenge),
        ("product y", product_y),
        ("product z", product_z),
        ("product challenge", product_challenge),
    ] {
        if BigUint::from_bytes_le(value) >= modulus {
            return Err(TexasAirError::SpecViolation(format!(
                "Bayer-Groth {label} is not below the Ristretto group order"
            )));
        }
    }
    if deck_size < 2 || deck_size > 128 {
        return Err(TexasAirError::SpecViolation(
            "Bayer-Groth schedule deck size is out of the supported range".into(),
        ));
    }
    let mut builder = RistrettoScalarProgramBuilder::new(&[
        *powers_challenge,
        *product_y,
        *product_z,
        *product_challenge,
    ]);
    let x = 0u16;
    let y = 1u16;
    let z = 2u16;
    let pc = 3u16;

    // Constants 1..=n as canonical scalars.
    let mut index_constants = Vec::with_capacity(deck_size);
    for index in 1..=deck_size {
        let mut bytes = [0u8; LIMBS];
        bytes[..8].copy_from_slice(&(index as u64).to_le_bytes());
        index_constants.push(builder.constant(&bytes)?);
    }

    // Powers table: p_1 = x, p_{i+1} = p_i · x.
    let mut powers = Vec::with_capacity(deck_size);
    powers.push(x);
    for _ in 1..deck_size {
        let next = builder.multiply(powers[powers.len() - 1], x)?;
        powers.push(next);
    }

    // Terms v_i = y·i + p_i − z, then the running product and final check.
    let mut product = None;
    let mut final_value = 0u16;
    for index in 0..deck_size {
        let scaled = builder.multiply(y, index_constants[index])?;
        let shifted = builder.add(scaled, powers[index])?;
        let term = builder.subtract(shifted, z)?;
        product = Some(match product {
            None => term,
            Some(running) => builder.multiply(running, term)?,
        });
    }
    if let Some(running) = product {
        final_value = builder.multiply(pc, running)?;
    }
    let outputs = vec![final_value];
    builder.finish(&outputs)
}

/// Verify a Bayer--Groth scalar-schedule STARK against its challenges and
/// return the final check value for the native `b_response[n-1]` comparison.
pub fn verify_bayer_groth_scalar_schedule(
    archive: &ArchivedRistrettoScalarProgramProof,
    powers_challenge: &[u8; LIMBS],
    product_y: &[u8; LIMBS],
    product_z: &[u8; LIMBS],
    product_challenge: &[u8; LIMBS],
    deck_size: usize,
) -> TexasAirResult<[u8; LIMBS]> {
    let expected = build_bayer_groth_scalar_schedule(
        powers_challenge,
        product_y,
        product_z,
        product_challenge,
        deck_size,
    )?;
    if archive.program != expected {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Bayer-Groth scalar schedule program is detached from its challenges".into(),
        ));
    }
    verify_ristretto_scalar_program(archive)?;
    let output_index = expected.outputs[0] as usize;
    Ok(expected.values[output_index])
}

// ---------------------------------------------------------------------------
// Unified-admission segment (multi-component folding).
// ---------------------------------------------------------------------------

/// One circle-domain column evaluation as committed into the shared trees.
pub(crate) type ScalarEval = stwo::prover::poly::circle::CircleEvaluation<
    stwo::prover::backend::simd::SimdBackend,
    M31,
    stwo::prover::poly::BitReversedOrder,
>;

/// The unified-admission segment of one (or a batch of equal-shape) scalar
/// program(s): scope/trace columns for the shared preprocessed and original
/// trees, interaction columns for the shared interaction tree, and
/// (privately) the drawn LogUp relations needed for the component.
pub(crate) struct ScalarProgramSegment {
    /// Log size of this segment's columns.
    pub(crate) log_size: u32,
    /// Distinct scope-id namespace (several scalar segments can share one
    /// admission allocator).
    scope_prefix: String,
    /// Preprocessed scope columns (shared tree 0).
    pub(crate) scope: MethodTrace,
    /// Original trace columns (shared tree 1).
    pub(crate) trace: MethodTrace,
    /// Interaction columns (shared tree 2); empty until `interact`.
    pub(crate) interaction: Vec<ScalarEval>,
    /// Claimed LogUp sum; zero until `interact`.
    pub(crate) claimed_sum: SecureField,
    relations: Option<(ScalarRange11, ScalarCarry17)>,
}

impl ScalarProgramSegment {
    /// Build the scope and original trace columns without touching the
    /// channel. Every program must share the template's shape.
    pub(crate) fn build(
        programs: &[RistrettoScalarProgram],
        scope_prefix: &str,
    ) -> TexasAirResult<Self> {
        let log_size = batch_log_size(programs.len())?;
        let trace = trace_columns_batch(programs)?;
        let scope = scope_columns_batch(programs)?;
        Ok(Self {
            log_size,
            scope_prefix: scope_prefix.to_string(),
            scope,
            trace,
            interaction: Vec::new(),
            claimed_sum: SecureField::from(0u32),
            relations: None,
        })
    }

    /// Draw this segment's LogUp relations from the channel (after the
    /// original-tree commit) and build the paired interaction columns.
    pub(crate) fn interact(
        &mut self,
        channel: &mut stwo::core::channel::Poseidon252Channel,
        template: &RistrettoScalarProgram,
    ) {
        let range = ScalarRange11::draw(channel);
        let carry = ScalarCarry17::draw(channel);
        let (program_width, limb_columns, carry_pair_columns) =
            trace_layout(template).expect("program shape was validated before trace generation");
        let (interaction, claimed_sum) = scalar_range_interaction(
            &self.trace,
            self.log_size,
            &range,
            &carry,
            &limb_columns,
            &carry_pair_columns,
            program_width,
        );
        self.interaction = interaction;
        self.claimed_sum = claimed_sum;
        self.relations = Some((range, carry));
    }

    /// Construct this segment's component against the shared allocator.
    pub(crate) fn component(
        &self,
        allocator: &mut TraceLocationAllocator,
        template: &RistrettoScalarProgram,
    ) -> FrameworkComponent<ScalarProgramAir> {
        let (range, carry) = self
            .relations
            .as_ref()
            .expect("ScalarProgramSegment::interact runs before component construction");
        let mut air = ScalarProgramAir::new(
            self.log_size,
            template.clone(),
            range.clone(),
            carry.clone(),
        );
        // Re-namespace the AIR's internal scope ids so several scalar
        // segments can share one admission allocator.
        air.scope_ids = (0..air.scope_ids.len())
            .map(|column| PreProcessedColumnId {
                id: format!("{}.{}", self.scope_prefix, column).into(),
            })
            .collect();
        FrameworkComponent::new(allocator, air, self.claimed_sum)
    }

    /// Mirror the prover's relation draws on a verifier channel without
    /// materializing interaction columns; stores the drawn relations for
    /// component construction.
    pub(crate) fn mirror_draw(&mut self, channel: &mut stwo::core::channel::Poseidon252Channel) {
        let range = ScalarRange11::draw(channel);
        let carry = ScalarCarry17::draw(channel);
        self.relations = Some((range, carry));
    }

    /// Interaction-column count of this segment (paired fractions, four M31
    /// columns per secure column), derivable from the template layout.
    pub(crate) fn interaction_columns(&self, template: &RistrettoScalarProgram) -> usize {
        let (_, limb_columns, carry_pair_columns) =
            trace_layout(template).expect("program shape was validated before trace generation");
        let range_stripes = range_table_stripes(self.log_size);
        let carry_stripes = carry_table_stripes(self.log_size);
        (limb_columns.len() + carry_pair_columns.len() + range_stripes + carry_stripes).div_ceil(2)
            * 4
    }

    /// Preprocessed-column identifiers of this segment's scope.
    pub(crate) fn preprocessed_ids(
        &self,
        template: &RistrettoScalarProgram,
    ) -> Vec<PreProcessedColumnId> {
        let count = preprocessed_ids(template).len();
        (0..count)
            .map(|column| PreProcessedColumnId {
                id: format!("{}.{}", self.scope_prefix, column).into(),
            })
            .collect()
    }
}

/// The Bayer--Groth product-argument recurrence over the scalar field.
///
/// Given the final product challenge `pc` and the masked responses
/// `b_response`/`a_response`, one program proves
/// `recurrence[i] = pc·b[i+1] − b[i]·a[i+1]` for every `i` plus the initial
/// value `d = b[0] − a[0]`, so the unified admission STARK covers the scalar
/// derivation the second product check consumes (the `d == 0` and
/// `b[n-1]` comparisons stay native on the pinned outputs).
pub fn build_bayer_groth_recurrence_program(
    product_challenge: &[u8; LIMBS],
    b_response: &[[u8; LIMBS]],
    a_response: &[[u8; LIMBS]],
) -> TexasAirResult<RistrettoScalarProgram> {
    let n = b_response.len();
    if n < 2 || n > 128 || a_response.len() != n {
        return Err(TexasAirError::SpecViolation(
            "Bayer-Groth recurrence response length is out of the supported range".into(),
        ));
    }
    let group_order = modulus().clone();
    for (label, value) in [("product challenge", product_challenge)] {
        if BigUint::from_bytes_le(value) >= group_order {
            return Err(TexasAirError::SpecViolation(format!(
                "Bayer-Groth recurrence {label} is not below the Ristretto group order"
            )));
        }
    }
    for (label, responses) in [("b", b_response), ("a", a_response)] {
        for value in responses {
            if BigUint::from_bytes_le(value) >= group_order {
                return Err(TexasAirError::SpecViolation(format!(
                    "Bayer-Groth recurrence {label} response is not below the group order"
                )));
            }
        }
    }
    let mut builder =
        RistrettoScalarProgramBuilder::new(&[*product_challenge, b_response[0], a_response[0]]);
    let pc = 0u16;
    let mut outputs = vec![builder.subtract(1, 2)?];
    let mut b_index = 1u16;
    let mut a_index = 2u16;
    for index in 1..n {
        let next_b = builder.constant(&b_response[index])?;
        let next_a = builder.constant(&a_response[index])?;
        let scaled = builder.multiply(pc, next_b)?;
        let cross = builder.multiply(b_index, next_a)?;
        outputs.push(builder.subtract(scaled, cross)?);
        b_index = next_b;
        a_index = next_a;
    }
    builder.finish(&outputs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar_bytes(value: u64) -> [u8; LIMBS] {
        let mut out = [0u8; LIMBS];
        out[..8].copy_from_slice(&value.to_le_bytes());
        out
    }

    fn native_schedule_final(
        x: &[u8; LIMBS],
        y: &[u8; LIMBS],
        z: &[u8; LIMBS],
        pc: &[u8; LIMBS],
        n: usize,
    ) -> [u8; LIMBS] {
        let modulus = modulus().clone();
        let x_big = BigUint::from_bytes_le(x);
        let y_big = BigUint::from_bytes_le(y);
        let z_big = BigUint::from_bytes_le(z);
        let pc_big = BigUint::from_bytes_le(pc);
        let mut running = BigUint::one();
        let mut power = BigUint::one();
        for index in 1..=n {
            power = if index == 1 {
                x_big.clone()
            } else {
                (&power * &x_big) % &modulus
            };
            let term = ((&y_big * BigUint::from(index as u64) + &power) % &modulus + &modulus
                - &z_big)
                % &modulus;
            running = (&running * term) % &modulus;
        }
        let final_value = (&pc_big * &running) % &modulus;
        let mut out = [0u8; LIMBS];
        let bytes = final_value.to_bytes_le();
        out[..bytes.len()].copy_from_slice(&bytes);
        out
    }

    fn bytes(value: u64) -> [u8; LIMBS] {
        let mut out = [0u8; LIMBS];
        out[..8].copy_from_slice(&value.to_le_bytes());
        out
    }

    #[test]
    fn minimal_scalar_programs_prove_and_verify() {
        // One addition.
        let mut builder = RistrettoScalarProgramBuilder::new(&[bytes(3), bytes(5)]);
        let sum = builder.add(0, 1).expect("add");
        let program = builder.finish(&[sum]).expect("add program");
        let archive = prove_ristretto_scalar_program(&program).expect("add STARK");
        assert!(verify_ristretto_scalar_program(&archive).is_ok());

        // One subtraction that wraps the modulus.
        let mut builder = RistrettoScalarProgramBuilder::new(&[bytes(3), bytes(5)]);
        let difference = builder.subtract(0, 1).expect("subtract");
        let program = builder.finish(&[difference]).expect("sub program");
        let archive = prove_ristretto_scalar_program(&program).expect("sub STARK");
        assert!(verify_ristretto_scalar_program(&archive).is_ok());

        // One multiplication with a nonzero quotient.
        let mut builder = RistrettoScalarProgramBuilder::new(&[bytes(0x10000), bytes(0x10000)]);
        let product = builder.multiply(0, 1).expect("multiply");
        let program = builder.finish(&[product]).expect("mul program");
        let archive = prove_ristretto_scalar_program(&program).expect("mul STARK");
        assert!(verify_ristretto_scalar_program(&archive).is_ok());
    }

    #[test]
    fn scalar_schedule_program_closes_against_native_arithmetic() {
        let x = scalar_bytes(7);
        let y = scalar_bytes(9);
        let z = scalar_bytes(11);
        let pc = scalar_bytes(13);
        let program =
            build_bayer_groth_scalar_schedule(&x, &y, &z, &pc, 52).expect("schedule program");
        let output_index = program.outputs[0] as usize;
        assert_eq!(
            program.values[output_index],
            native_schedule_final(&x, &y, &z, &pc, 52),
            "in-program schedule must match native mod-l arithmetic"
        );

        let started = std::time::Instant::now();
        let archive = prove_ristretto_scalar_program(&program).expect("schedule STARK");
        let prove_elapsed = started.elapsed();
        let started = std::time::Instant::now();
        let final_value = verify_bayer_groth_scalar_schedule(&archive, &x, &y, &z, &pc, 52)
            .expect("schedule verify");
        eprintln!(
            "scalar-program BG schedule: prove {prove_elapsed:?}, verify {:?}, proof {} bytes, values {}, ops {}",
            started.elapsed(),
            archive.stark_proof_bytes.len(),
            program.values.len(),
            program.ops.len(),
        );
        assert_eq!(final_value, native_schedule_final(&x, &y, &z, &pc, 52));
    }

    #[test]
    fn scalar_schedule_rejects_detached_challenges_and_spliced_proofs() {
        let x = scalar_bytes(7);
        let y = scalar_bytes(9);
        let z = scalar_bytes(11);
        let pc = scalar_bytes(13);
        let program =
            build_bayer_groth_scalar_schedule(&x, &y, &z, &pc, 52).expect("schedule program");
        let archive = prove_ristretto_scalar_program(&program).expect("schedule STARK");
        assert!(verify_bayer_groth_scalar_schedule(&archive, &x, &y, &z, &pc, 52).is_ok());

        // A different challenge detaches the program shape.
        let other = scalar_bytes(15);
        assert!(verify_bayer_groth_scalar_schedule(&archive, &x, &other, &z, &pc, 52).is_err());

        // A different deck size detaches the program shape.
        assert!(verify_bayer_groth_scalar_schedule(&archive, &x, &y, &z, &pc, 51).is_err());

        // A spliced program value (kept canonical via byte 20) fails the
        // STARK or the shape comparison.
        let mut spliced = archive.clone();
        let output_index = spliced.program.outputs[0] as usize;
        spliced.program.values[output_index][20] ^= 1;
        assert!(
            verify_bayer_groth_scalar_schedule(&spliced, &x, &y, &z, &pc, 52).is_err(),
            "splicing the final value must fail"
        );

        // Spliced proof bytes fail the STARK: byte 0 can be a benign length
        // corner, so tamper three distinct positions.
        // Spliced proof bytes fail the STARK.  The serialized proof's leading
        // `PcsConfig` field is inert metadata (the verifier uses its own
        // trusted config), so tamper consumed regions: the commitments body
        // and the tail.
        let spliced_proof_len = archive.stark_proof_bytes.len();
        for position in [64, spliced_proof_len / 2] {
            let mut spliced = archive.clone();
            spliced.stark_proof_bytes[position] ^= 1;
            assert!(
                verify_bayer_groth_scalar_schedule(&spliced, &x, &y, &z, &pc, 52).is_err(),
                "splicing proof byte {position} must fail"
            );
        }
    }

    #[test]
    fn scalar_program_family_rejects_field_modulus_values() {
        // A value at the field modulus p (not below l) must be rejected by
        // the builder, keeping the scalar and Fp program families distinct.
        let p_minus_one: [u8; LIMBS] = {
            let mut out = [0xffu8; LIMBS];
            out[31] = 0x7f;
            out
        };
        assert!(
            build_bayer_groth_scalar_schedule(
                &p_minus_one,
                &scalar_bytes(1),
                &scalar_bytes(1),
                &scalar_bytes(1),
                52
            )
            .is_err()
        );
    }
}
