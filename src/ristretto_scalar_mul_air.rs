//! Dedicated fixed-window Ristretto255 scalar-multiplication ladder AIR.
//!
//! This is the point-side Path A prerequisite: one STARK whose trace rows are
//! the 335 projective Edwards additions of a 64-window Horner ladder (fifteen
//! table rows `T[j] = T[j-1] + B` plus sixty-four windows of four doublings
//! and one selected-table addition).  The base point is decoded once and the
//! final accumulator encoded once, each as a small fixed-shape Fp program
//! batch row; the ladder interior stays in projective coordinates, so the
//! ~1005 per-multiplication decode/encode expansions of the generic
//! compressed-row route ([`crate::ristretto_fp_program_air`]) collapse to two.
//!
//! Every row carries twenty-six pinned values (both operands, the unified
//! addition intermediates, and the output) as 11-bit limb columns forced
//! equal to preprocessed scope columns, plus pure-witness quotient limbs and
//! carry chains.  Soundness does not need in-circuit canonicity or range
//! checks on the pinned limbs: the schedule is a deterministic function of
//! the public `(windows, base)` statement, so the verifier rebuilds it,
//! recomputes the scope commitment, and rejects any detached proof before
//! running the STARK — the same composition idiom as the Fp program family.
//! Only the quotient limbs (11-bit singles) and multiplication carries
//! (17-bit pairs) enter the shared LogUp tables.
//!
//! The trace layout is fully static (no program dispatch), so the AIR emits
//! one fixed constraint set per row: eight add/sub carry chains, one
//! doubling chain for `2·Z1`, one constant-operand multiplication for
//! `2d·T1`, and seven general multiplications.

#![allow(missing_docs)]

use bincode::Options;
use borsh::{BorshDeserialize, BorshSerialize};
use num_bigint::BigUint;
use num_integer::Integer;
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
use crate::ristretto_fp_program_air::fp25519;
use crate::ristretto_fp_program_air::{
    ArchivedRistrettoFpProgramBatchProof, EDWARDS_TWO_D_BYTES, INVSQRT_A_MINUS_D_BYTES, ONE_BYTES,
    RistrettoFpProgram, RistrettoFpProgramBuilder, SQRT_M1_BYTES, ZERO_BYTES,
    append_fixed_canonical_point_decode, append_fixed_projective_point_encode, builder_values,
    canonical_decode_inverse_sqrt, negative_edwards_d, projective_encode_inverse_sqrt,
    prove_ristretto_fp_program_batch_owned, verify_ristretto_fp_program_batch,
};
use crate::ristretto_scalar_windows_air::windows;
use crate::trace_gen::MethodTrace;

const LIMBS: usize = 32;
/// `p = 2^255 − 19` little-endian, the modulus of every ladder value.
/// `p = 2^255 − 19` little-endian, the modulus of every ladder value.
const P_BYTES: [u8; LIMBS] = {
    let mut bytes = [0xffu8; LIMBS];
    bytes[0] = 0xed;
    bytes[31] = 0x7f;
    bytes
};
/// Internal witness radix: twenty-four 11-bit limbs (`24 · 11 = 264 ≥ 256`).
const LIMB_COUNT: usize = 24;
const LIMB_BITS: u32 = 11;
const BASE: u32 = 1 << LIMB_BITS;
const PRODUCT_LIMBS: usize = 2 * LIMB_COUNT;
/// Sixty-four 4-bit windows per scalar (256-bit scalar, Horner radix 16).
const WINDOW_COUNT: usize = 64;
const TABLE_STEPS: usize = 15;
const DOUBLINGS_PER_WINDOW: usize = 4;
const HORNER_STEPS: usize = WINDOW_COUNT * (DOUBLINGS_PER_WINDOW + 1);
/// Fifteen table rows plus sixty-four windows of five additions.
const STEP_COUNT: usize = TABLE_STEPS + HORNER_STEPS;
/// Domain floor: the LogUp interaction generator needs one SIMD vector row
/// and FRI soundness keeps its nominal query weight at 128 rows.
const LOG_SIZE_FLOOR: u32 = 7;
/// Guard on the batch size so step counts cannot overflow the padded domain
/// or the u32 LogUp multiplicities.
const MAX_STATEMENTS: usize = 512;

// ---------------------------------------------------------------------------
// Pinned row values (fixed order, shared by builder, witness, trace, and AIR).
// ---------------------------------------------------------------------------

const VALUE_LEFT_X: usize = 0;
const VALUE_LEFT_Y: usize = 1;
const VALUE_LEFT_Z: usize = 2;
const VALUE_LEFT_T: usize = 3;
const VALUE_RIGHT_X: usize = 4;
const VALUE_RIGHT_Y: usize = 5;
const VALUE_RIGHT_Z: usize = 6;
const VALUE_RIGHT_T: usize = 7;
const VALUE_LEFT_Y_MINUS_X: usize = 8;
const VALUE_RIGHT_Y_MINUS_X: usize = 9;
const VALUE_LEFT_Y_PLUS_X: usize = 10;
const VALUE_RIGHT_Y_PLUS_X: usize = 11;
const VALUE_A: usize = 12;
const VALUE_B: usize = 13;
const VALUE_C2: usize = 14;
const VALUE_C: usize = 15;
const VALUE_D2: usize = 16;
const VALUE_D: usize = 17;
const VALUE_E: usize = 18;
const VALUE_F: usize = 19;
const VALUE_G: usize = 20;
const VALUE_H: usize = 21;
const VALUE_X3: usize = 22;
const VALUE_Y3: usize = 23;
const VALUE_Z3: usize = 24;
const VALUE_T3: usize = 25;
const PINNED_VALUES: usize = 26;

// Quotient witness indices, one per multiplication that reduces mod p.
const QUOTIENT_A: usize = 0;
const QUOTIENT_B: usize = 1;
const QUOTIENT_C2: usize = 2;
const QUOTIENT_C: usize = 3;
const QUOTIENT_X3: usize = 4;
const QUOTIENT_Y3: usize = 5;
const QUOTIENT_Z3: usize = 6;
const QUOTIENT_T3: usize = 7;
const QUOTIENT_VALUES: usize = 8;

/// One pinned add/sub relation `values[a] ± values[b] = values[out]`.
struct ChainSpec {
    subtract: bool,
    a: usize,
    b: usize,
    out: usize,
}

const CHAIN_SPECS: [ChainSpec; 8] = [
    ChainSpec {
        subtract: true,
        a: VALUE_LEFT_Y,
        b: VALUE_LEFT_X,
        out: VALUE_LEFT_Y_MINUS_X,
    },
    ChainSpec {
        subtract: true,
        a: VALUE_RIGHT_Y,
        b: VALUE_RIGHT_X,
        out: VALUE_RIGHT_Y_MINUS_X,
    },
    ChainSpec {
        subtract: false,
        a: VALUE_LEFT_Y,
        b: VALUE_LEFT_X,
        out: VALUE_LEFT_Y_PLUS_X,
    },
    ChainSpec {
        subtract: false,
        a: VALUE_RIGHT_Y,
        b: VALUE_RIGHT_X,
        out: VALUE_RIGHT_Y_PLUS_X,
    },
    ChainSpec {
        subtract: true,
        a: VALUE_B,
        b: VALUE_A,
        out: VALUE_E,
    },
    ChainSpec {
        subtract: true,
        a: VALUE_D,
        b: VALUE_C,
        out: VALUE_F,
    },
    ChainSpec {
        subtract: false,
        a: VALUE_D,
        b: VALUE_C,
        out: VALUE_G,
    },
    ChainSpec {
        subtract: false,
        a: VALUE_A,
        b: VALUE_B,
        out: VALUE_H,
    },
];

/// One pinned general multiplication `values[a] · values[b] = values[out]`
/// with quotient witness `quotients[quotient]`.
struct MulSpec {
    a: usize,
    b: usize,
    out: usize,
    quotient: usize,
}

const GENERAL_MUL_SPECS: [MulSpec; 7] = [
    MulSpec {
        a: VALUE_LEFT_Y_MINUS_X,
        b: VALUE_RIGHT_Y_MINUS_X,
        out: VALUE_A,
        quotient: QUOTIENT_A,
    },
    MulSpec {
        a: VALUE_LEFT_Y_PLUS_X,
        b: VALUE_RIGHT_Y_PLUS_X,
        out: VALUE_B,
        quotient: QUOTIENT_B,
    },
    MulSpec {
        a: VALUE_C2,
        b: VALUE_RIGHT_T,
        out: VALUE_C,
        quotient: QUOTIENT_C,
    },
    MulSpec {
        a: VALUE_E,
        b: VALUE_F,
        out: VALUE_X3,
        quotient: QUOTIENT_X3,
    },
    MulSpec {
        a: VALUE_G,
        b: VALUE_H,
        out: VALUE_Y3,
        quotient: QUOTIENT_Y3,
    },
    MulSpec {
        a: VALUE_F,
        b: VALUE_G,
        out: VALUE_Z3,
        quotient: QUOTIENT_Z3,
    },
    MulSpec {
        a: VALUE_E,
        b: VALUE_H,
        out: VALUE_T3,
        quotient: QUOTIENT_T3,
    },
];

// The constant-operand multiplication `2d · T1 = C2` uses `TWO_D_LIMBS` as
// hardcoded coefficients, so only `VALUE_LEFT_T`, `VALUE_C2`, and
// `QUOTIENT_C2` participate as trace cells.

// ---------------------------------------------------------------------------
// Trace width arithmetic (single source of truth for generator and AIR).
// ---------------------------------------------------------------------------

const PINNED_LIMB_COLUMNS: usize = PINNED_VALUES * LIMB_COUNT;
const QUOTIENT_LIMB_COLUMNS: usize = QUOTIENT_VALUES * LIMB_COUNT;
/// Per chain: `k_negative`, `k_magnitude`, then a boolean-signed pair per limb.
const CHAIN_COLUMNS: usize = 2 + 2 * LIMB_COUNT;
/// Doubling chain: one boolean `k`, then a boolean-signed pair per limb.
const DOUBLE_CHAIN_COLUMNS: usize = 1 + 2 * LIMB_COUNT;
/// Per multiplication: a `(negative, low, high)` carry triple per gap.
const MUL_COLUMNS: usize = (PRODUCT_LIMBS - 1) * 3;
const CONST_MUL_COUNT: usize = 1;
const PROGRAM_WIDTH: usize = PINNED_LIMB_COLUMNS
    + QUOTIENT_LIMB_COLUMNS
    + CHAIN_SPECS.len() * CHAIN_COLUMNS
    + DOUBLE_CHAIN_COLUMNS
    + (CONST_MUL_COUNT + GENERAL_MUL_SPECS.len()) * MUL_COLUMNS;

/// Scope columns pack two 11-bit limbs per M31 column (< 2^22).
/// Scope columns pack two 11-bit limbs per M31 column (< 2^22).
const SCOPE_LIMBS_PER_COLUMN: usize = 2;
const SCOPE_COLUMNS_PER_VALUE: usize = LIMB_COUNT / SCOPE_LIMBS_PER_COLUMN;
const SCOPE_WIDTH: usize = PINNED_VALUES * SCOPE_COLUMNS_PER_VALUE;


/// Bound on a multiplication carry magnitude: `|carry| ≤ (2·L·(2^11−1)² +
/// terms) / 2^11 < 2^17`, matching the Fp program family bound.
const MAX_MUL_CARRY_MAGNITUDE: u32 = 1 << 17;

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

/// `p` as twenty-four 11-bit limbs.
const P_BASE_LIMBS: [u16; LIMB_COUNT] = base_limbs(&P_BYTES);
/// `2d mod p` as twenty-four 11-bit limbs (hardcoded multiplication operand).
const TWO_D_LIMBS: [u16; LIMB_COUNT] = base_limbs(&EDWARDS_TWO_D_BYTES);

static MODULUS: std::sync::OnceLock<BigUint> = std::sync::OnceLock::new();

fn modulus() -> &'static BigUint {
    MODULUS.get_or_init(|| BigUint::from_bytes_le(&P_BYTES))
}

fn big_uint(value: &[u8; LIMBS]) -> BigUint {
    BigUint::from_bytes_le(value)
}

fn limbs_bytes(value: &BigUint) -> [u8; LIMBS] {
    let mut out = [0u8; LIMBS];
    let bytes = value.to_bytes_le();
    let length = bytes.len().min(LIMBS);
    out[..length].copy_from_slice(&bytes[..length]);
    out
}

/// `⌊a·b / p⌋` as canonical bytes: the committed quotient of one
/// multiplication row.
fn quotient_bytes(a: &[u8; LIMBS], b: &[u8; LIMBS]) -> [u8; LIMBS] {
    let product = big_uint(a) * big_uint(b);
    let (quotient, _remainder) = product.div_rem(modulus());
    limbs_bytes(&quotient)
}

fn options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(64 * 1024 * 1024)
}

// ---------------------------------------------------------------------------
// Native ladder schedule.
// ---------------------------------------------------------------------------

/// The Ristretto identity in projective coordinates `(0, 1, 1, 0)`.
fn identity_coords() -> [[u8; LIMBS]; 4] {
    let mut one = [0u8; LIMBS];
    one[0] = 1;
    [ZERO_BYTES, one, one, ZERO_BYTES]
}

/// One ladder step: the two projective operands, the pinned intermediate
/// values of the unified addition, and the projective output.
#[derive(Debug, Clone)]
pub(crate) struct LadderStep {
    left: [[u8; LIMBS]; 4],
    right: [[u8; LIMBS]; 4],
    output: [[u8; LIMBS]; 4],
    pinned: [[u8; LIMBS]; PINNED_VALUES],
}

/// Evaluate one unified projective Edwards addition
/// (`A = (Y1−X1)(Y2−X2)`, `B = (Y1+X1)(Y2+X2)`, `C = 2d·T1·T2`,
/// `D = 2·Z1·Z2`, `E = B−A`, `F = D−C`, `G = D+C`, `H = A+B`,
/// `X3 = E·F`, `Y3 = G·H`, `Z3 = F·G`, `T3 = E·H`) natively, returning the
/// twenty-six pinned values and the output coordinates.
fn projective_add_step(
    left: &[[u8; LIMBS]; 4],
    right: &[[u8; LIMBS]; 4],
) -> TexasAirResult<([[u8; LIMBS]; PINNED_VALUES], [[u8; LIMBS]; 4])> {
    let l = left.map(|coordinate| fp25519::Fe::from_bytes(&coordinate));
    let r = right.map(|coordinate| fp25519::Fe::from_bytes(&coordinate));
    let l_ymx = l[1].sub(&l[0]);
    let r_ymx = r[1].sub(&r[0]);
    let l_ypx = l[1].add(&l[0]);
    let r_ypx = r[1].add(&r[0]);
    let a = l_ymx.mul(&r_ymx);
    let b = l_ypx.mul(&r_ypx);
    let two_d = fp25519::Fe::from_bytes(&EDWARDS_TWO_D_BYTES);
    let c2 = two_d.mul(&l[3]);
    let c = c2.mul(&r[3]);
    let d2 = l[2].add(&l[2]);
    let d = d2.mul(&r[2]);
    let e = b.sub(&a);
    let f = d.sub(&c);
    let g = d.add(&c);
    let h = a.add(&b);
    let x3 = e.mul(&f);
    let y3 = g.mul(&h);
    let z3 = f.mul(&g);
    let t3 = e.mul(&h);
    if z3.is_zero() {
        return Err(TexasAirError::SpecViolation(
            "ladder projective addition produced Z = 0".into(),
        ));
    }
    let bytes = |value: &fp25519::Fe| value.to_bytes();
    let pinned = [
        left[0],
        left[1],
        left[2],
        left[3],
        right[0],
        right[1],
        right[2],
        right[3],
        bytes(&l_ymx),
        bytes(&r_ymx),
        bytes(&l_ypx),
        bytes(&r_ypx),
        bytes(&a),
        bytes(&b),
        bytes(&c2),
        bytes(&c),
        bytes(&d2),
        bytes(&d),
        bytes(&e),
        bytes(&f),
        bytes(&g),
        bytes(&h),
        bytes(&x3),
        bytes(&y3),
        bytes(&z3),
        bytes(&t3),
    ];
    let output = [bytes(&x3), bytes(&y3), bytes(&z3), bytes(&t3)];
    Ok((pinned, output))
}

/// Build the 335-step table/Horner schedule for `Σ w_i·16^i · base`.
///
/// The schedule is a pure function of `(windows, base coordinates)`, so the
/// verifier rebuilds it byte-for-byte before checking the scope commitment.
pub(crate) fn build_ladder_schedule(
    windows: &[u8; WINDOW_COUNT],
    base_coords: &[[u8; LIMBS]; 4],
) -> TexasAirResult<Vec<LadderStep>> {
    let mut steps = Vec::with_capacity(STEP_COUNT);
    let mut table = [identity_coords(); 16];
    for index in 1..16 {
        let (pinned, output) = projective_add_step(&table[index - 1], base_coords)?;
        steps.push(LadderStep {
            left: table[index - 1],
            right: *base_coords,
            output,
            pinned,
        });
        table[index] = output;
    }

    let mut accumulator = identity_coords();
    for window in windows.iter().rev() {
        if *window >= 16 {
            return Err(TexasAirError::SpecViolation(
                "ladder window selector is outside 0..15".into(),
            ));
        }
        for _ in 0..DOUBLINGS_PER_WINDOW {
            let (pinned, output) = projective_add_step(&accumulator, &accumulator)?;
            steps.push(LadderStep {
                left: accumulator,
                right: accumulator,
                output,
                pinned,
            });
            accumulator = output;
        }
        let selected = table[usize::from(*window)];
        let (pinned, output) = projective_add_step(&accumulator, &selected)?;
        steps.push(LadderStep {
            left: accumulator,
            right: selected,
            output,
            pinned,
        });
        accumulator = output;
    }
    debug_assert_eq!(steps.len(), STEP_COUNT);
    Ok(steps)
}

// ---------------------------------------------------------------------------
// Fixed-shape decode/encode programs (battle-tested Fp program builders).
// ---------------------------------------------------------------------------

/// Decode the base encoding natively, without building a program (the
/// schedule only needs the projective coordinates).
fn decode_base_coords(
    base_encoding: &[u8; LIMBS],
) -> TexasAirResult<[[u8; LIMBS]; 4]> {
    let inverse_sqrt = canonical_decode_inverse_sqrt(base_encoding)?;
    let mut builder = RistrettoFpProgramBuilder::new(&[*base_encoding]);
    let one = builder.constant(&ONE_BYTES)?;
    let negative_d = builder.constant(&negative_edwards_d())?;
    let zero = builder.constant(&ZERO_BYTES)?;
    let inverse_sqrt_index = builder.constant(&inverse_sqrt)?;
    let decoded = append_fixed_canonical_point_decode(
        &mut builder,
        0,
        inverse_sqrt_index,
        one,
        negative_d,
        zero,
    )?;
    let mut coordinates = [ZERO_BYTES; 4];
    for (slot, index) in decoded.coordinates.into_iter().enumerate() {
        coordinates[slot] = builder_values(&builder, index)?;
    }
    Ok(coordinates)
}

/// Prove-shape builder for the one-per-statement codec program: the base
/// decode and the final-accumulator encode folded into a single fixed-shape
/// field program, so the ladder batch carries one codec STARK instead of two
/// (halving the codec FRI fixed cost at small batch sizes).
///
/// The public inputs are the base encoding and the four final accumulator
/// coordinates; the decode branch constrains the schedule's base, the encode
/// branch constrains the public output, and both inverse-square-root witnesses
/// are checked by their `inverse_check` outputs.
fn build_ladder_codec_program(
    base_encoding: &[u8; LIMBS],
    final_acc: &[[u8; LIMBS]; 4],
) -> TexasAirResult<(RistrettoFpProgram, [u8; LIMBS])> {
    let decode_inverse_sqrt = canonical_decode_inverse_sqrt(base_encoding)?;
    let encode_inverse_sqrt = projective_encode_inverse_sqrt(final_acc)?;
    let mut builder = RistrettoFpProgramBuilder::new(&[
        *base_encoding,
        final_acc[0],
        final_acc[1],
        final_acc[2],
        final_acc[3],
    ]);
    let one = builder.constant(&ONE_BYTES)?;
    let negative_d = builder.constant(&negative_edwards_d())?;
    let zero = builder.constant(&ZERO_BYTES)?;
    let decode_inverse_sqrt_index = builder.constant(&decode_inverse_sqrt)?;
    let decoded = append_fixed_canonical_point_decode(
        &mut builder,
        0,
        decode_inverse_sqrt_index,
        one,
        negative_d,
        zero,
    )?;
    let sqrt_m1 = builder.constant(&SQRT_M1_BYTES)?;
    let invsqrt_a_minus_d = builder.constant(&INVSQRT_A_MINUS_D_BYTES)?;
    let encode_inverse_sqrt_index = builder.constant(&encode_inverse_sqrt)?;
    let encoded = append_fixed_projective_point_encode(
        &mut builder,
        [1, 2, 3, 4],
        encode_inverse_sqrt_index,
        zero,
        sqrt_m1,
        invsqrt_a_minus_d,
    )?;
    let output = builder_values(&builder, encoded.encoding)?;
    let program = builder.finish(&[decoded.inverse_check, encoded.inverse_check])?;
    Ok((program, output))
}

// ---------------------------------------------------------------------------
// Row witness derivation.
// ---------------------------------------------------------------------------

/// A boolean-signed witness magnitude (`{-1, 0, +1}`) as two columns.
#[derive(Clone, Copy, Debug)]
struct SignedBit {
    negative: bool,
    magnitude: u16,
}

/// A multiplication carry: boolean sign plus a magnitude below `2^17`,
/// witnessed as two 11-bit limbs.
#[derive(Clone, Copy, Debug)]
struct SignedLimbCarry {
    negative: bool,
    magnitude: u32,
}

#[derive(Debug)]
struct ChainWitness {
    k: SignedBit,
    carries: [SignedBit; LIMB_COUNT],
}

#[derive(Debug)]
struct DoubleChainWitness {
    k: bool,
    carries: [SignedBit; LIMB_COUNT],
}


struct StepWitness {
    chains: [ChainWitness; CHAIN_SPECS.len()],
    double: DoubleChainWitness,
    /// `2d·T1` carry chain.
    const_mul: Vec<SignedLimbCarry>,
    muls: [Vec<SignedLimbCarry>; GENERAL_MUL_SPECS.len()],
    quotients: [[u16; LIMB_COUNT]; QUOTIENT_VALUES],
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

/// Derive the add/sub carry-chain witness for one pinned relation.
fn chain_witness(
    a_limbs: &[u16; LIMB_COUNT],
    b_limbs: &[u16; LIMB_COUNT],
    out_limbs: &[u16; LIMB_COUNT],
    subtract: bool,
    a_int: &BigUint,
    b_int: &BigUint,
) -> TexasAirResult<ChainWitness> {
    let (k_negative, k_magnitude) = if subtract {
        (a_int < b_int, a_int < b_int)
    } else {
        (false, a_int + b_int >= *modulus())
    };
    let mut carry_in: i64 = 0;
    let mut carries = [SignedBit {
        negative: false,
        magnitude: 0,
    }; LIMB_COUNT];
    for index in 0..LIMB_COUNT {
        let signed_b = if subtract {
            -i64::from(b_limbs[index])
        } else {
            i64::from(b_limbs[index])
        };
        let signed_k = if k_negative {
            -i64::from(k_magnitude)
        } else {
            i64::from(k_magnitude)
        };
        let difference = i64::from(a_limbs[index]) + signed_b + carry_in
            - i64::from(out_limbs[index])
            - signed_k * i64::from(P_BASE_LIMBS[index]);
        let carry_out = difference.div_euclid(i64::from(BASE));
        if !(-1..=1).contains(&carry_out) {
            return Err(TexasAirError::SpecViolation(
                "ladder add/sub carry witness is outside {-1,0,1}".into(),
            ));
        }
        carries[index] = SignedBit {
            negative: carry_out < 0,
            magnitude: u16::try_from(carry_out.unsigned_abs())
                .expect("ladder carry magnitude is boolean"),
        };
        carry_in = carry_out;
    }
    if carry_in != 0 {
        return Err(TexasAirError::SpecViolation(
            "ladder add/sub carry chain is nonterminal".into(),
        ));
    }
    Ok(ChainWitness {
        k: SignedBit {
            negative: k_negative,
            magnitude: u16::from(k_magnitude),
        },
        carries,
    })
}

/// Derive the doubling-chain witness for `d2 = 2·Z1 − k·p`.
fn double_chain_witness(
    z_limbs: &[u16; LIMB_COUNT],
    d2_limbs: &[u16; LIMB_COUNT],
    z_int: &BigUint,
) -> TexasAirResult<DoubleChainWitness> {
    let k = (z_int + z_int) >= *modulus();
    let mut carry_in: i64 = 0;
    let mut carries = [SignedBit {
        negative: false,
        magnitude: 0,
    }; LIMB_COUNT];
    for index in 0..LIMB_COUNT {
        let difference = 2 * i64::from(z_limbs[index]) + carry_in
            - i64::from(d2_limbs[index])
            - i64::from(u16::from(k)) * i64::from(P_BASE_LIMBS[index]);
        let carry_out = difference.div_euclid(i64::from(BASE));
        if !(-1..=1).contains(&carry_out) {
            return Err(TexasAirError::SpecViolation(
                "ladder doubling carry witness is outside {-1,0,1}".into(),
            ));
        }
        carries[index] = SignedBit {
            negative: carry_out < 0,
            magnitude: u16::try_from(carry_out.unsigned_abs())
                .expect("ladder doubling carry magnitude is boolean"),
        };
        carry_in = carry_out;
    }
    if carry_in != 0 {
        return Err(TexasAirError::SpecViolation(
            "ladder doubling carry chain is nonterminal".into(),
        ));
    }
    Ok(DoubleChainWitness { k, carries })
}

/// Derive the 47 signed carries of one multiplication (or constant-operand
/// multiplication) relation `a·b − q·p − out = 0` over the limb convolution.
fn mul_witness(
    product_limbs: Vec<i64>,
    q_limbs: &[u16; LIMB_COUNT],
    out_limbs: &[u16; LIMB_COUNT],
) -> TexasAirResult<Vec<SignedLimbCarry>> {
    let quotient_prime = convolution(q_limbs, &P_BASE_LIMBS);
    let mut carry_in: i64 = 0;
    let mut carries = Vec::with_capacity(PRODUCT_LIMBS - 1);
    for limb_index in 0..PRODUCT_LIMBS {
        let output_limb = if limb_index < LIMB_COUNT {
            i64::from(out_limbs[limb_index])
        } else {
            0
        };
        let difference =
            product_limbs[limb_index] - quotient_prime[limb_index] - output_limb + carry_in;
        let carry_out = difference.div_euclid(i64::from(BASE));
        if limb_index + 1 == PRODUCT_LIMBS {
            if carry_out != 0 {
                return Err(TexasAirError::SpecViolation(
                    "ladder multiplication final carry is nonzero".into(),
                ));
            }
        } else {
            if carry_out.unsigned_abs() > u64::from(MAX_MUL_CARRY_MAGNITUDE) {
                return Err(TexasAirError::SpecViolation(
                    "ladder multiplication carry exceeds its 17-bit bound".into(),
                ));
            }
            carries.push(SignedLimbCarry {
                negative: carry_out < 0,
                magnitude: carry_out.unsigned_abs() as u32,
            });
            carry_in = carry_out;
        }
    }
    Ok(carries)
}

/// Derive the complete fixed-layout witness of one ladder step.
fn step_witness(step: &LadderStep) -> TexasAirResult<StepWitness> {
    let value_limbs: Vec<[u16; LIMB_COUNT]> =
        step.pinned.iter().map(|value| to_limbs(value)).collect();
    let value_ints: Vec<BigUint> = step.pinned.iter().map(|value| big_uint(value)).collect();

    let quotients = [
        quotient_bytes(
            &step.pinned[VALUE_LEFT_Y_MINUS_X],
            &step.pinned[VALUE_RIGHT_Y_MINUS_X],
        ),
        quotient_bytes(
            &step.pinned[VALUE_LEFT_Y_PLUS_X],
            &step.pinned[VALUE_RIGHT_Y_PLUS_X],
        ),
        quotient_bytes(&EDWARDS_TWO_D_BYTES, &step.pinned[VALUE_LEFT_T]),
        quotient_bytes(&step.pinned[VALUE_C2], &step.pinned[VALUE_RIGHT_T]),
        quotient_bytes(&step.pinned[VALUE_E], &step.pinned[VALUE_F]),
        quotient_bytes(&step.pinned[VALUE_G], &step.pinned[VALUE_H]),
        quotient_bytes(&step.pinned[VALUE_F], &step.pinned[VALUE_G]),
        quotient_bytes(&step.pinned[VALUE_E], &step.pinned[VALUE_H]),
    ]
    .map(|value| to_limbs(&value));

    let mut chains = Vec::with_capacity(CHAIN_SPECS.len());
    for spec in CHAIN_SPECS.iter() {
        chains.push(chain_witness(
            &value_limbs[spec.a],
            &value_limbs[spec.b],
            &value_limbs[spec.out],
            spec.subtract,
            &value_ints[spec.a],
            &value_ints[spec.b],
        )?);
    }
    let chains: [ChainWitness; CHAIN_SPECS.len()] = chains
        .try_into()
        .expect("chain count matches the fixed layout");

    let double = double_chain_witness(
        &value_limbs[VALUE_LEFT_Z],
        &value_limbs[VALUE_D2],
        &value_ints[VALUE_LEFT_Z],
    )?;

    let const_product = convolution(&TWO_D_LIMBS, &value_limbs[VALUE_LEFT_T]);
    let const_mul = mul_witness(
        const_product,
        &quotients[QUOTIENT_C2],
        &value_limbs[VALUE_C2],
    )?;

    let mut muls = Vec::with_capacity(GENERAL_MUL_SPECS.len());
    for spec in GENERAL_MUL_SPECS.iter() {
        let product = convolution(&value_limbs[spec.a], &value_limbs[spec.b]);
        muls.push(mul_witness(
            product,
            &quotients[spec.quotient],
            &value_limbs[spec.out],
        )?);
    }
    let muls: [Vec<SignedLimbCarry>; GENERAL_MUL_SPECS.len()] = muls
        .try_into()
        .expect("multiplication count matches the fixed layout");

    Ok(StepWitness {
        chains,
        double,
        const_mul,
        muls,
        quotients,
    })
}

// ---------------------------------------------------------------------------
// Trace generation.
// ---------------------------------------------------------------------------

fn append_limb(row: &mut Vec<M31>, limb: u16) {
    // 11-bit limb; range membership is proven by the shared LogUp table for
    // witness (quotient) limbs and by scope pinning for value limbs.
    row.push(M31::from(u32::from(limb)));
}

fn append_mul_carries(
    row: &mut Vec<M31>,
    carry_pair_columns: &mut Vec<[usize; 2]>,
    carries: &[SignedLimbCarry],
) {
    for carry in carries {
        row.push(M31::from(u32::from(carry.negative)));
        let low_index = row.len();
        append_limb(row, (carry.magnitude & (BASE - 1)) as u16);
        let high_index = row.len();
        append_limb(row, (carry.magnitude >> LIMB_BITS) as u16);
        carry_pair_columns.push([low_index, high_index]);
    }
}

/// Materialize one step row plus the LogUp-tracked column indices (quotient
/// limb singles, then multiplication carry pairs).
fn trace_row_with_columns(
    step: &LadderStep,
) -> TexasAirResult<(Vec<M31>, Vec<usize>, Vec<[usize; 2]>)> {
    let witness = step_witness(step)?;
    let mut row = Vec::with_capacity(PROGRAM_WIDTH);
    let mut limb_columns = Vec::with_capacity(QUOTIENT_LIMB_COLUMNS);
    let mut carry_pair_columns =
        Vec::with_capacity((CONST_MUL_COUNT + GENERAL_MUL_SPECS.len()) * (PRODUCT_LIMBS - 1));

    for value in &step.pinned {
        for limb in to_limbs(value) {
            append_limb(&mut row, limb);
        }
    }
    for quotient in &witness.quotients {
        for limb in quotient {
            limb_columns.push(row.len());
            append_limb(&mut row, *limb);
        }
    }
    for chain in &witness.chains {
        row.push(M31::from(u32::from(chain.k.negative)));
        row.push(M31::from(u32::from(chain.k.magnitude)));
        for carry in &chain.carries {
            row.push(M31::from(u32::from(carry.negative)));
            row.push(M31::from(u32::from(carry.magnitude)));
        }
    }
    row.push(M31::from(u32::from(witness.double.k)));
    for carry in &witness.double.carries {
        row.push(M31::from(u32::from(carry.negative)));
        row.push(M31::from(u32::from(carry.magnitude)));
    }
    append_mul_carries(&mut row, &mut carry_pair_columns, &witness.const_mul);
    for mul in &witness.muls {
        append_mul_carries(&mut row, &mut carry_pair_columns, mul);
    }
    debug_assert_eq!(row.len(), PROGRAM_WIDTH);
    Ok((row, limb_columns, carry_pair_columns))
}

/// Shape-only mirror of [`trace_row_with_columns`]: the layout is static, so
/// the verifier sizes the trace commitment without materializing witnesses.
fn trace_layout() -> (usize, Vec<usize>, Vec<[usize; 2]>) {
    let mut width = PINNED_LIMB_COLUMNS;
    let mut limb_columns = Vec::with_capacity(QUOTIENT_LIMB_COLUMNS);
    for _ in 0..QUOTIENT_LIMB_COLUMNS {
        limb_columns.push(width);
        width += 1;
    }
    width += CHAIN_SPECS.len() * CHAIN_COLUMNS + DOUBLE_CHAIN_COLUMNS;
    let mut carry_pair_columns =
        Vec::with_capacity((CONST_MUL_COUNT + GENERAL_MUL_SPECS.len()) * (PRODUCT_LIMBS - 1));
    for _ in 0..(CONST_MUL_COUNT + GENERAL_MUL_SPECS.len()) {
        for _ in 0..(PRODUCT_LIMBS - 1) {
            width += 1;
            let low_index = width;
            width += 1;
            let high_index = width;
            width += 1;
            carry_pair_columns.push([low_index, high_index]);
        }
    }
    (width, limb_columns, carry_pair_columns)
}

/// Number of `(multiplicity, value)` table stripes for the 2048-entry limb
/// range table over a `2^log_size` row domain.
fn range_table_stripes(log_size: u32) -> usize {
    (2048usize >> log_size.min(11)).max(1)
}

/// Number of `(multiplicity, lo, hi)` table stripes for the 131,072-entry
/// carry pair table over a `2^log_size` row domain.
fn carry_table_stripes(log_size: u32) -> usize {
    (131_072usize >> log_size.min(17)).max(1)
}

fn range_table_column_count(log_size: u32) -> usize {
    2 * range_table_stripes(log_size) + 3 * carry_table_stripes(log_size)
}

/// Append and fill the shared LogUp table columns (same convention as the Fp
/// program family: 2048-entry single-limb table stripes, then 131,072-entry
/// carry pair table stripes with inert entries beyond the table sizes).
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

fn ladder_log_size(statement_count: usize) -> TexasAirResult<u32> {
    if statement_count == 0 {
        return Err(TexasAirError::SpecViolation(
            "scalar-multiplication ladder batch must not be empty".into(),
        ));
    }
    if statement_count > MAX_STATEMENTS {
        return Err(TexasAirError::SpecViolation(
            "scalar-multiplication ladder batch exceeds its committed size guard".into(),
        ));
    }
    let steps = statement_count * STEP_COUNT;
    Ok(steps.max(1 << LOG_SIZE_FLOOR).next_power_of_two().ilog2())
}

/// All ladder steps of all statements, in statement order.
fn flat_steps<'a>(schedules: &'a [Vec<LadderStep>]) -> Vec<&'a LadderStep> {
    schedules
        .iter()
        .flat_map(|schedule| schedule.iter())
        .collect()
}

fn trace_columns_batch(schedules: &[Vec<LadderStep>]) -> TexasAirResult<MethodTrace> {
    let log_size = ladder_log_size(schedules.len())?;
    let rows = 1usize << log_size;
    let steps = flat_steps(schedules);
    let step_rows = steps
        .par_iter()
        .map(|step| trace_row_with_columns(step).map(|(row, _, _)| row))
        .collect::<TexasAirResult<Vec<_>>>()?;
    let (_, limb_columns, carry_pair_columns) = trace_layout();
    let table_columns = range_table_column_count(log_size);
    // Column-wise materialization with last-row padding.
    let step_count = step_rows.len();
    let mut trace = MethodTrace::new_unfilled(log_size, PROGRAM_WIDTH + table_columns);
    for column_index in 0..PROGRAM_WIDTH {
        let mut column = Vec::with_capacity(rows);
        for row_index in 0..rows {
            let source = row_index.min(step_count - 1);
            column.push(step_rows[source][column_index]);
        }
        trace.set_column(column_index, column);
    }
    append_range_table_columns(
        &mut trace,
        log_size,
        &limb_columns,
        &carry_pair_columns,
        PROGRAM_WIDTH,
    );
    Ok(trace)
}

fn scope_packed(value: &[u8; LIMBS]) -> Vec<u32> {
    to_limbs(value)
        .chunks(SCOPE_LIMBS_PER_COLUMN)
        .map(|chunk| u32::from(chunk[0]) + BASE * u32::from(chunk[1]))
        .collect()
}

fn scope_row(step: &LadderStep) -> Vec<M31> {
    let mut row = Vec::with_capacity(SCOPE_WIDTH);
    for value in &step.pinned {
        row.extend(scope_packed(value).into_iter().map(M31::from));
    }
    row
}

fn scope_columns_batch(schedules: &[Vec<LadderStep>]) -> TexasAirResult<MethodTrace> {
    let log_size = ladder_log_size(schedules.len())?;
    let rows = 1usize << log_size;
    let steps = flat_steps(schedules);
    let scope_rows = steps
        .par_iter()
        .map(|step| scope_row(step))
        .collect::<Vec<_>>();
    let mut columns = Vec::with_capacity(SCOPE_WIDTH);
    for column_index in 0..SCOPE_WIDTH {
        let mut column = Vec::with_capacity(rows);
        for row_index in 0..rows {
            let source = row_index.min(scope_rows.len() - 1);
            column.push(scope_rows[source][column_index]);
        }
        columns.push(column);
    }
    Ok(MethodTrace::from_columns(log_size, columns))
}

fn preprocessed_ids() -> Vec<PreProcessedColumnId> {
    (0..SCOPE_WIDTH)
        .map(|column| PreProcessedColumnId {
            id: format!("ristretto.scalar_mul.ladder.scope.v1.{column}").into(),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// AIR.
// ---------------------------------------------------------------------------

/// Shared single-limb (11-bit) range table LogUp relation for ladder witness
/// limbs (quotients).
relation!(LadderRange11, 1);

/// Paired `(lo, hi)` 11-bit-limb LogUp relation for ladder multiplication
/// carries below `2^17`.
relation!(LadderCarry17, 2);

#[derive(Clone)]
pub(crate) struct ScalarMulLadderAir {
    log_size: u32,
    range: LadderRange11,
    carry: LadderCarry17,
    scope_ids: Vec<PreProcessedColumnId>,
}

impl ScalarMulLadderAir {
    fn new(log_size: u32, range: LadderRange11, carry: LadderCarry17) -> Self {
        Self {
            log_size,
            range,
            carry,
            scope_ids: preprocessed_ids(),
        }
    }

    fn table_stripes(&self) -> usize {
        range_table_stripes(self.log_size)
    }

    fn carry_table_stripes(&self) -> usize {
        carry_table_stripes(self.log_size)
    }
}

/// Read one `(negative, low, high)` carry triple, constrain its sign, range
/// its magnitude through the pair table, and return the signed magnitude.
fn read_signed_carry<E: EvalAtRow>(
    eval: &mut E,
    carry: &LadderCarry17,
    one: &E::F,
    base: &E::F,
) -> E::F {
    let negative = eval.next_trace_mask();
    let limb_low = eval.next_trace_mask();
    let limb_high = eval.next_trace_mask();
    eval.add_constraint(negative.clone() * (negative.clone() - one.clone()));
    eval.add_to_relation(RelationEntry::new(
        carry,
        E::EF::from(one.clone()),
        &[limb_low.clone(), limb_high.clone()],
    ));
    let magnitude = limb_low + base.clone() * limb_high;
    let positive = one.clone() - negative.clone();
    positive * magnitude.clone() - negative * magnitude
}

impl FrameworkEval for ScalarMulLadderAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let one: E::F = M31::from(1u32).into();
        let base: E::F = M31::from(BASE).into();
        let zero: E::F = M31::from(0u32).into();

        // 1) Pinned value limbs. No LogUp range entries: each limb is forced
        //    to a preprocessed scope column below and the verifier recomputes
        //    the scope commitment from its own schedule rebuild.
        let mut value = Vec::with_capacity(PINNED_VALUES);
        for _ in 0..PINNED_VALUES {
            let mut limbs = Vec::with_capacity(LIMB_COUNT);
            for _ in 0..LIMB_COUNT {
                limbs.push(eval.next_trace_mask());
            }
            value.push(limbs);
        }
        for (value_index, limbs) in value.iter().enumerate() {
            for (group_index, group) in limbs.chunks(SCOPE_LIMBS_PER_COLUMN).enumerate() {
                let scope = eval.get_preprocessed_column(
                    self.scope_ids[value_index * SCOPE_COLUMNS_PER_VALUE + group_index].clone(),
                );
                let mut packed: E::F = scope;
                for (shift, limb) in group.iter().enumerate() {
                    packed = packed
                        - limb.clone()
                            * E::F::from(M31::from(
                                BASE.pow(u32::try_from(shift).expect("two limbs per scope column")),
                            ));
                }
                eval.add_constraint(packed);
            }
        }

        // 2) Quotient limbs: pure witnesses, range-proven via the shared table.
        let mut quotient = Vec::with_capacity(QUOTIENT_VALUES);
        for _ in 0..QUOTIENT_VALUES {
            let mut limbs = Vec::with_capacity(LIMB_COUNT);
            for _ in 0..LIMB_COUNT {
                let limb = eval.next_trace_mask();
                eval.add_to_relation(RelationEntry::new(
                    &self.range,
                    E::EF::from(one.clone()),
                    &[limb.clone()],
                ));
                limbs.push(limb);
            }
            quotient.push(limbs);
        }

        // 3) Add/sub carry chains.
        for spec in CHAIN_SPECS.iter() {
            let k_negative = eval.next_trace_mask();
            let k_magnitude = eval.next_trace_mask();
            eval.add_constraint(k_negative.clone() * (k_negative.clone() - one.clone()));
            eval.add_constraint(k_magnitude.clone() * (k_magnitude.clone() - one.clone()));
            if spec.subtract {
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
                    zero.clone()
                } else {
                    signed_carries[index - 1].clone()
                };
                let carry_out = if index + 1 == LIMB_COUNT {
                    zero.clone()
                } else {
                    signed_carries[index].clone()
                };
                let b_term = if spec.subtract {
                    zero.clone() - value[spec.b][index].clone()
                } else {
                    value[spec.b][index].clone()
                };
                eval.add_constraint(
                    value[spec.a][index].clone() + b_term + carry_in
                        - value[spec.out][index].clone()
                        - signed_k.clone() * E::F::from(M31::from(u32::from(P_BASE_LIMBS[index])))
                        - base.clone() * carry_out,
                );
            }
        }

        // 4) Doubling chain `d2 = 2·Z1 − k·p`.
        {
            let k = eval.next_trace_mask();
            eval.add_constraint(k.clone() * (k.clone() - one.clone()));
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
                    zero.clone()
                } else {
                    signed_carries[index - 1].clone()
                };
                let carry_out = if index + 1 == LIMB_COUNT {
                    zero.clone()
                } else {
                    signed_carries[index].clone()
                };
                eval.add_constraint(
                    value[VALUE_LEFT_Z][index].clone()
                        + value[VALUE_LEFT_Z][index].clone()
                        + carry_in
                        - value[VALUE_D2][index].clone()
                        - k.clone() * E::F::from(M31::from(u32::from(P_BASE_LIMBS[index])))
                        - base.clone() * carry_out,
                );
            }
        }

        // 5) Constant-operand multiplication `2d·T1 = C2 − q·p`: the operand
        //    limbs are hardcoded coefficients, so every convolution term is
        //    linear in trace cells.
        {
            let mut carries = Vec::with_capacity(PRODUCT_LIMBS - 1);
            for _ in 0..(PRODUCT_LIMBS - 1) {
                carries.push(read_signed_carry(&mut eval, &self.carry, &one, &base));
            }
            for limb_index in 0..PRODUCT_LIMBS {
                let start = limb_index.saturating_sub(LIMB_COUNT - 1);
                let end = limb_index.min(LIMB_COUNT - 1);
                let mut relation: E::F = zero.clone();
                for left_index in start..=end {
                    let right_index = limb_index - left_index;
                    relation = relation
                        + E::F::from(M31::from(u32::from(TWO_D_LIMBS[left_index])))
                            * value[VALUE_LEFT_T][right_index].clone();
                    relation = relation
                        - quotient[QUOTIENT_C2][left_index].clone()
                            * E::F::from(M31::from(u32::from(P_BASE_LIMBS[right_index])));
                }
                if limb_index < LIMB_COUNT {
                    relation = relation - value[VALUE_C2][limb_index].clone();
                }
                if limb_index > 0 {
                    relation = relation + carries[limb_index - 1].clone();
                }
                if limb_index + 1 < PRODUCT_LIMBS {
                    relation = relation - base.clone() * carries[limb_index].clone();
                }
                eval.add_constraint(relation);
            }
        }

        // 6) General multiplications.
        for spec in GENERAL_MUL_SPECS.iter() {
            let mut carries = Vec::with_capacity(PRODUCT_LIMBS - 1);
            for _ in 0..(PRODUCT_LIMBS - 1) {
                carries.push(read_signed_carry(&mut eval, &self.carry, &one, &base));
            }
            for limb_index in 0..PRODUCT_LIMBS {
                let start = limb_index.saturating_sub(LIMB_COUNT - 1);
                let end = limb_index.min(LIMB_COUNT - 1);
                let mut relation: E::F = zero.clone();
                for left_index in start..=end {
                    let right_index = limb_index - left_index;
                    relation = relation
                        + value[spec.a][left_index].clone() * value[spec.b][right_index].clone();
                    relation = relation
                        - quotient[spec.quotient][left_index].clone()
                            * E::F::from(M31::from(u32::from(P_BASE_LIMBS[right_index])));
                }
                if limb_index < LIMB_COUNT {
                    relation = relation - value[spec.out][limb_index].clone();
                }
                if limb_index > 0 {
                    relation = relation + carries[limb_index - 1].clone();
                }
                if limb_index + 1 < PRODUCT_LIMBS {
                    relation = relation - base.clone() * carries[limb_index].clone();
                }
                eval.add_constraint(relation);
            }
        }

        // 7) Table side of the shared range LogUp (negated multiplicities),
        //    identical convention to the Fp program family.
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

// ---------------------------------------------------------------------------
// Fiat–Shamir statement binding.
// ---------------------------------------------------------------------------

fn u32_words(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks(4)
        .map(|chunk| {
            let mut word = [0u8; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            u32::from_le_bytes(word)
        })
        .collect()
}

fn mix_ladder_statements(
    channel: &mut impl Channel,
    statements: &[RistrettoScalarMulLadderStatement],
) {
    channel.mix_u64(0x7363_756c_6c61_6464);
    channel.mix_u64(statements.len() as u64);
    for statement in statements {
        channel.mix_u32s(&u32_words(&statement.scalar));
        channel.mix_u32s(&u32_words(&statement.windows));
        channel.mix_u32s(&u32_words(&statement.base));
        channel.mix_u32s(&u32_words(&statement.output));
    }
}

// ---------------------------------------------------------------------------
// LogUp interaction columns.
// ---------------------------------------------------------------------------

/// Build the paired LogUp interaction columns, mirroring the AIR's
/// relation-entry emission order: quotient-limb use entries, then carry pair
/// entries (constant multiplication first, then general multiplications),
/// then both table sides with negated multiplicities.
#[allow(clippy::too_many_arguments)]
fn ladder_range_interaction(
    trace: &MethodTrace,
    log_size: u32,
    range: &LadderRange11,
    carry: &LadderCarry17,
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
            Entry::CarryUse(index) => ladder_combine_pair(
                carry,
                &pack_vec(&carry_use_low[*index], vector_row),
                &pack_vec(&carry_use_high[*index], vector_row),
            ),
            Entry::Table(t) => range.combine(&[pack_vec(&table_den[*t], vector_row)]),
            Entry::CarryTable(t) => ladder_combine_pair(
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

/// Combine an arity-2 relation over a packed `(lo, hi)` pair.
fn ladder_combine_pair(
    carry: &LadderCarry17,
    low: &stwo::prover::backend::simd::m31::PackedBaseField,
    high: &stwo::prover::backend::simd::m31::PackedBaseField,
) -> stwo::prover::backend::simd::qm31::PackedSecureField {
    use stwo::prover::backend::simd::qm31::PackedSecureField;
    let combined: [stwo::prover::backend::simd::m31::PackedBaseField; 2] =
        [low.clone(), high.clone()];
    <LadderCarry17 as stwo_constraint_framework::Relation<_, PackedSecureField>>::combine(
        carry, &combined,
    )
}

// ---------------------------------------------------------------------------
// Public statement, archives, prove and verify.
// ---------------------------------------------------------------------------

/// One public scalar-multiplication statement `output = scalar · base`.
///
/// The scalar-window decomposition proofs are owned by the caller (see
/// [`crate::ristretto_scalar_windows_air`]); this AIR proves the ladder
/// schedule that those windows select.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RistrettoScalarMulLadderStatement {
    /// Canonical scalar below the group order.
    pub scalar: [u8; LIMBS],
    /// The sixty-four 4-bit windows of the scalar (public selector schedule).
    pub windows: [u8; WINDOW_COUNT],
    /// Compressed base point.
    pub base: [u8; LIMBS],
    /// Compressed output point.
    pub output: [u8; LIMBS],
}

/// Dedicated fixed-window scalar-multiplication batch: one ladder STARK over
/// all statements' 335-step schedules plus one combined decode+encode codec
/// program batch.
///
/// The wire format is compact (`RSML` magic): statements, the serialized
/// ladder STARK, its claimed LogUp sum, and the nested codec batch archive.
/// The schedules themselves are never serialized — the verifier rebuilds them
/// deterministically.
#[derive(Debug, Clone, PartialEq)]
pub struct ArchivedRistrettoScalarMulLadderBatchProof {
    /// Public statements in row order.
    pub statements: Vec<RistrettoScalarMulLadderStatement>,
    /// Serialized ladder STARK proof.
    pub stark_proof_bytes: Vec<u8>,
    /// Public claimed sum of the shared range LogUp (4 M31 coordinates).
    pub range_claimed_sum: [u32; 4],
    /// One fixed-shape combined decode+encode codec program per statement.
    pub codecs: ArchivedRistrettoFpProgramBatchProof,
}

const LADDER_BATCH_ARCHIVE_MAGIC: [u8; 4] = *b"RSML";
const LADDER_BATCH_ARCHIVE_VERSION: u8 = 2;

impl BorshSerialize for ArchivedRistrettoScalarMulLadderBatchProof {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&LADDER_BATCH_ARCHIVE_MAGIC)?;
        LADDER_BATCH_ARCHIVE_VERSION.serialize(writer)?;
        self.statements.serialize(writer)?;
        self.stark_proof_bytes.serialize(writer)?;
        self.range_claimed_sum.serialize(writer)?;
        self.codecs.serialize(writer)
    }
}

impl BorshDeserialize for ArchivedRistrettoScalarMulLadderBatchProof {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if magic != LADDER_BATCH_ARCHIVE_MAGIC {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "scalar-multiplication ladder archive magic mismatch",
            ));
        }
        let version = u8::deserialize_reader(reader)?;
        if version != LADDER_BATCH_ARCHIVE_VERSION {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unsupported scalar-multiplication ladder archive version {version}"),
            ));
        }
        Ok(Self {
            statements: Vec::<RistrettoScalarMulLadderStatement>::deserialize_reader(reader)?,
            stark_proof_bytes: Vec::<u8>::deserialize_reader(reader)?,
            range_claimed_sum: <[u32; 4]>::deserialize_reader(reader)?,
            codecs: ArchivedRistrettoFpProgramBatchProof::deserialize_reader(reader)?,
        })
    }
}

/// Rebuild one statement's combined codec program and ladder schedule
/// deterministically from its public fields.
pub(crate) fn rebuild_statement(
    statement: &RistrettoScalarMulLadderStatement,
) -> TexasAirResult<(RistrettoFpProgram, Vec<LadderStep>)> {
    if statement.windows != windows(&statement.scalar) {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "ladder statement windows do not decompose its scalar".into(),
        ));
    }
    let coords = decode_base_coords(&statement.base)?;
    let schedule = build_ladder_schedule(&statement.windows, &coords)?;
    let final_acc = schedule
        .last()
        .map(|step| step.output)
        .ok_or_else(|| TexasAirError::SpecViolation("ladder schedule is empty".into()))?;
    let (codec_program, output) = build_ladder_codec_program(&statement.base, &final_acc)?;
    if statement.output != output {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "ladder statement output is detached from its windows and base".into(),
        ));
    }
    Ok((codec_program, schedule))
}

/// Rebuild every statement (parallel) and validate the codec batch detachment
/// before any STARK verification.
fn validate_batch_statement(
    archive: &ArchivedRistrettoScalarMulLadderBatchProof,
) -> TexasAirResult<Vec<Vec<LadderStep>>> {
    if archive.statements.is_empty() {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "scalar-multiplication ladder batch cannot be empty".into(),
        ));
    }
    let rebuilt = archive
        .statements
        .par_iter()
        .map(rebuild_statement)
        .collect::<TexasAirResult<Vec<_>>>()?;
    if archive.codecs.programs.len() != rebuilt.len() {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "codec batch row counts are detached from the statements".into(),
        ));
    }
    for ((_, (codec_program, _)), archived_codec) in archive
        .statements
        .iter()
        .zip(rebuilt.iter())
        .zip(archive.codecs.programs.iter())
    {
        if archived_codec != codec_program {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "codec batch row is detached from its base encoding and accumulator".into(),
            ));
        }
    }
    Ok(rebuilt.into_iter().map(|(_, schedule)| schedule).collect())
}

/// Prove multiple fixed-window scalar multiplications as one ladder batch
/// STARK (two components: the general-addition segment and the narrower
/// dedicated doubling segment) plus one combined codec program batch.
///
/// Each input is `(scalar, windows, base)`; the caller owns the scalar-window
/// decomposition proofs.
pub fn prove_ristretto_scalar_mul_ladder_batch(
    inputs: Vec<([u8; LIMBS], [u8; WINDOW_COUNT], [u8; LIMBS])>,
) -> TexasAirResult<ArchivedRistrettoScalarMulLadderBatchProof> {
    if inputs.is_empty() {
        return Err(TexasAirError::SpecViolation(
            "scalar-multiplication ladder batch cannot be empty".into(),
        ));
    }
    let built = inputs
        .into_par_iter()
        .map(|(scalar, windows, base)| {
            let coords = decode_base_coords(&base)?;
            let schedule = build_ladder_schedule(&windows, &coords)?;
            let final_acc = schedule
                .last()
                .map(|step| step.output)
                .ok_or_else(|| TexasAirError::SpecViolation("ladder schedule is empty".into()))?;
            let (codec_program, output) = build_ladder_codec_program(&base, &final_acc)?;
            Ok((
                RistrettoScalarMulLadderStatement {
                    scalar,
                    windows,
                    base,
                    output,
                },
                codec_program,
                schedule,
            ))
        })
        .collect::<TexasAirResult<Vec<_>>>()?;
    let statements: Vec<RistrettoScalarMulLadderStatement> =
        built.iter().map(|entry| entry.0.clone()).collect();
    let codec_programs: Vec<RistrettoFpProgram> =
        built.iter().map(|entry| entry.1.clone()).collect();
    let schedules: Vec<Vec<LadderStep>> = built.into_iter().map(|entry| entry.2).collect();

    let log_size = ladder_log_size(schedules.len())?;
    let trace = trace_columns_batch(&schedules)?;
    let scope = scope_columns_batch(&schedules)?;
    let config = crate::prover_context::protocol_pcs_config();
    let twiddles =
        crate::prover_context::simd_twiddles(log_size + config.fri_config.log_blowup_factor);
    let mut channel = stwo::core::channel::Poseidon252Channel::default();
    mix_ladder_statements(&mut channel, &statements);
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
    let (program_width, limb_columns, carry_pair_columns) = trace_layout();
    let _ = program_width;
    let range = LadderRange11::draw(&mut channel);
    let carry = LadderCarry17::draw(&mut channel);
    let (interaction, range_sum) = ladder_range_interaction(
        &trace,
        log_size,
        &range,
        &carry,
        &limb_columns,
        &carry_pair_columns,
        PROGRAM_WIDTH,
    );
    channel.mix_felts(&[range_sum]);
    {
        let mut tree = scheme.tree_builder();
        tree.extend_evals(interaction);
        tree.commit(&mut channel);
    }
    let ids = preprocessed_ids();
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
    let component = FrameworkComponent::new(
        &mut allocator,
        ScalarMulLadderAir::new(log_size, range, carry),
        range_sum,
    );
    let proof = prove(&[&component], &mut channel, scheme)
        .map_err(|error| TexasAirError::StwoProverError(error.to_string()))?;
    let stark_proof_bytes = options()
        .serialize(&proof)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;

    let codecs = prove_ristretto_fp_program_batch_owned(codec_programs)?;
    let archive = ArchivedRistrettoScalarMulLadderBatchProof {
        statements,
        stark_proof_bytes,
        range_claimed_sum: range_sum.to_m31_array().map(|limb| limb.0),
        codecs,
    };
    if crate::ristretto_fp_program_air::ristretto_self_verify_enabled() {
        verify_ristretto_scalar_mul_ladder_batch(&archive)?;
    }
    Ok(archive)
}

/// Verify the statements, the rebuilt schedules' scope commitments, the
/// two-component ladder STARK, and the combined codec program batch STARK.
pub fn verify_ristretto_scalar_mul_ladder_batch(
    archive: &ArchivedRistrettoScalarMulLadderBatchProof,
) -> TexasAirResult<()> {
    type Proof = StarkProof<Poseidon252MerkleHasher>;
    let schedules = validate_batch_statement(archive)?;
    let log_size = ladder_log_size(archive.statements.len())?;
    let proof: Proof = options()
        .deserialize(&archive.stark_proof_bytes)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
    let (_, limb_columns, carry_pair_columns) = trace_layout();
    let trace_width = PROGRAM_WIDTH + range_table_column_count(log_size);
    let scope = scope_columns_batch(&schedules)?;
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
            "scalar-multiplication ladder public scope commitment mismatch".into(),
        ));
    }

    let mut channel = stwo::core::channel::Poseidon252Channel::default();
    mix_ladder_statements(&mut channel, &archive.statements);
    let mut scheme =
        stwo::core::pcs::CommitmentSchemeVerifier::<Poseidon252MerkleChannel>::new(config);
    scheme.commit(
        proof.commitments[0],
        &vec![log_size; SCOPE_WIDTH],
        &mut channel,
    );
    scheme.commit(
        proof.commitments[1],
        &vec![log_size; trace_width],
        &mut channel,
    );
    let range = LadderRange11::draw(&mut channel);
    let carry = LadderCarry17::draw(&mut channel);
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
    let ids = preprocessed_ids();
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
    let component = FrameworkComponent::new(
        &mut allocator,
        ScalarMulLadderAir::new(log_size, range, carry),
        claimed,
    );
    stwo::core::verifier::verify(&[&component], &mut channel, &mut scheme, proof)
        .map_err(|error| TexasAirError::ConstraintUnsatisfied(error.to_string()))?;

    verify_ristretto_fp_program_batch(&archive.codecs)?;
    Ok(())
}

/// Prove one fixed-window scalar multiplication (batch of one statement).
pub fn prove_ristretto_scalar_mul_ladder(
    scalar: [u8; LIMBS],
    windows: [u8; WINDOW_COUNT],
    base: [u8; LIMBS],
) -> TexasAirResult<ArchivedRistrettoScalarMulLadderBatchProof> {
    prove_ristretto_scalar_mul_ladder_batch(vec![(scalar, windows, base)])
}

/// Verify a single-statement ladder archive.
pub fn verify_ristretto_scalar_mul_ladder(
    archive: &ArchivedRistrettoScalarMulLadderBatchProof,
) -> TexasAirResult<()> {
    if archive.statements.len() != 1 {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "single ladder archive must carry exactly one statement".into(),
        ));
    }
    verify_ristretto_scalar_mul_ladder_batch(archive)
}

// ---------------------------------------------------------------------------
// Unified-admission segment (multi-component folding).
// ---------------------------------------------------------------------------

/// One circle-domain column evaluation as committed into the shared trees.
pub(crate) type LadderEval = stwo::prover::poly::circle::CircleEvaluation<
    stwo::prover::backend::simd::SimdBackend,
    M31,
    stwo::prover::poly::BitReversedOrder,
>;

/// Everything the unified admission STARK needs from one ladder segment: the
/// scope/trace columns for the shared preprocessed and original trees, the
/// interaction columns for the shared interaction tree, and (privately) the
/// drawn LogUp relations required to construct the component.
///
/// The two-phase protocol mirrors the shared Fiat--Shamir sequence: build
/// the traces first, let the caller commit the scope and original trees,
/// then draw the relations via [`LadderSegment::interact`] and let the
/// caller mix the claimed sum before committing the interaction tree.
pub(crate) struct LadderSegment {
    /// Log size of this segment's columns.
    pub(crate) log_size: u32,
    /// Preprocessed scope columns (shared tree 0).
    pub(crate) scope: MethodTrace,
    /// Original trace columns (shared tree 1).
    pub(crate) trace: MethodTrace,
    /// Interaction columns (shared tree 2); empty until `interact`.
    pub(crate) interaction: Vec<LadderEval>,
    /// Claimed LogUp sum; zero until `interact`.
    pub(crate) claimed_sum: SecureField,
    relations: Option<(LadderRange11, LadderCarry17)>,
}

impl LadderSegment {
    /// Build the scope and original trace columns for `schedules` without
    /// touching the channel.
    pub(crate) fn build(schedules: &[Vec<LadderStep>]) -> TexasAirResult<Self> {
        let log_size = ladder_log_size(schedules.len())?;
        let trace = trace_columns_batch(schedules)?;
        let scope = scope_columns_batch(schedules)?;
        Ok(Self {
            log_size,
            scope,
            trace,
            interaction: Vec::new(),
            claimed_sum: SecureField::from(0u32),
            relations: None,
        })
    }

    /// Draw this segment's LogUp relations from the channel (after the
    /// original-tree commit) and build the paired interaction columns.
    pub(crate) fn interact(&mut self, channel: &mut stwo::core::channel::Poseidon252Channel) {
        let range = LadderRange11::draw(channel);
        let carry = LadderCarry17::draw(channel);
        let (_, limb_columns, carry_pair_columns) = trace_layout();
        let (interaction, claimed_sum) = ladder_range_interaction(
            &self.trace,
            self.log_size,
            &range,
            &carry,
            &limb_columns,
            &carry_pair_columns,
            PROGRAM_WIDTH,
        );
        self.interaction = interaction;
        self.claimed_sum = claimed_sum;
        self.relations = Some((range, carry));
    }

    /// Construct this segment's component against the shared allocator.
    pub(crate) fn component(
        &self,
        allocator: &mut TraceLocationAllocator,
    ) -> FrameworkComponent<ScalarMulLadderAir> {
        let (range, carry) = self
            .relations
            .as_ref()
            .expect("LadderSegment::interact runs before component construction");
        FrameworkComponent::new(
            allocator,
            ScalarMulLadderAir::new(self.log_size, range.clone(), carry.clone()),
            self.claimed_sum,
        )
    }

    /// Mirror the prover's relation draws on a verifier channel without
    /// materializing interaction columns; stores the drawn relations for
    /// component construction.
    pub(crate) fn mirror_draw(&mut self, channel: &mut stwo::core::channel::Poseidon252Channel) {
        let range = LadderRange11::draw(channel);
        let carry = LadderCarry17::draw(channel);
        self.relations = Some((range, carry));
    }

    /// Interaction-column count of this segment (paired fractions, four M31
    /// columns per secure column), derivable from the fixed layout.
    pub(crate) fn interaction_columns(&self) -> usize {
        let (_, limb_columns, carry_pair_columns) = trace_layout();
        let range_stripes = range_table_stripes(self.log_size);
        let carry_stripes = carry_table_stripes(self.log_size);
        (limb_columns.len() + carry_pair_columns.len() + range_stripes + carry_stripes).div_ceil(2)
            * 4
    }

    /// Preprocessed-column identifiers of this segment's scope.
    pub(crate) fn preprocessed_ids(&self) -> Vec<PreProcessedColumnId> {
        preprocessed_ids()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basepoint() -> [u8; LIMBS] {
        [
            0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71, 0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00,
            0x51, 0x5f, 0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d, 0xb6, 0xa6, 0x59, 0x45,
            0xe0, 0x8d, 0x2d, 0x76,
        ]
    }

    fn identity() -> [u8; LIMBS] {
        [0u8; LIMBS]
    }

    fn scalar_bytes(value: u64) -> [u8; LIMBS] {
        let mut out = [0u8; LIMBS];
        out[..8].copy_from_slice(&value.to_le_bytes());
        out
    }

    fn native_multiple(scalar: &[u8; LIMBS], base: &[u8; LIMBS]) -> Vec<u8> {
        use poker_protocol::crypto::curve::{Curve, CurvePoint, CurveScalar, RistrettoCurve};
        type Point = <RistrettoCurve as Curve>::Point;
        let decode = |encoding: &[u8; LIMBS]| -> Point {
            Point::from_compressed(encoding).expect("base decodes")
        };
        let decoded = decode(base);
        let product = decoded
            * <RistrettoCurve as Curve>::Scalar::from_bytes_mod_order_wide(&{
                let mut wide = [0u8; 64];
                wide[..LIMBS].copy_from_slice(scalar);
                wide
            });
        CurvePoint::compress(&product).as_ref().to_vec()
    }

    #[test]
    fn ladder_schedule_matches_native_curve_multiplication() {
        let scalar = scalar_bytes(0x0123_4567_89ab_cdef);
        let windows = windows(&scalar);
        let coords = decode_base_coords(&basepoint()).expect("decode");
        // The codec program's first value is the public encoding and the
        // projective decode fixes Z = 1.
        assert_eq!(coords[2], ONE_BYTES);

        let schedule = build_ladder_schedule(&windows, &coords).expect("schedule");
        assert_eq!(schedule.len(), STEP_COUNT);
        let final_acc = schedule.last().expect("nonempty").output;
        let (codec_program, output) =
            build_ladder_codec_program(&basepoint(), &final_acc).expect("codec program");
        assert_eq!(codec_program.values[0], basepoint());
        assert_eq!(
            output.as_slice(),
            native_multiple(&scalar, &basepoint()).as_slice(),
            "ladder schedule must agree with the curve library"
        );

        // Identity base: every step adds the identity; output is the identity.
        let identity_coords = decode_base_coords(&identity()).expect("identity decode");
        let identity_schedule =
            build_ladder_schedule(&windows, &identity_coords).expect("identity schedule");
        let identity_final = identity_schedule.last().expect("nonempty").output;
        let (_, identity_output) =
            build_ladder_codec_program(&identity(), &identity_final).expect("identity codec");
        assert_eq!(identity_output.as_slice(), identity().as_slice());
    }

    #[test]
    fn scalar_mul_ladder_proves_and_verifies() {
        let scalar = scalar_bytes(0x0123_4567_89ab_cdef);
        let window_schedule = windows(&scalar);
        let started = std::time::Instant::now();
        let archive = prove_ristretto_scalar_mul_ladder(scalar, window_schedule, basepoint())
            .expect("ladder STARK");
        let prove_elapsed = started.elapsed();
        assert_eq!(
            archive.statements[0].output.as_slice(),
            native_multiple(&scalar, &basepoint()).as_slice()
        );
        let started = std::time::Instant::now();
        verify_ristretto_scalar_mul_ladder(&archive).expect("ladder verify");
        eprintln!(
            "scalar-mul ladder (1 statement): prove {prove_elapsed:?}, verify {:?}, ladder proof {} bytes",
            started.elapsed(),
            archive.stark_proof_bytes.len(),
        );
    }

    #[test]
    fn scalar_mul_ladder_batch_proves_and_verifies() {
        let first = scalar_bytes(7);
        let second = scalar_bytes(0xfeed_beef_cafe_babe);
        let inputs = vec![
            (first, windows(&first), basepoint()),
            (second, windows(&second), identity()),
        ];
        let started = std::time::Instant::now();
        let archive = prove_ristretto_scalar_mul_ladder_batch(inputs).expect("ladder batch STARK");
        let prove_elapsed = started.elapsed();
        assert_eq!(
            archive.statements[0].output.as_slice(),
            native_multiple(&first, &basepoint()).as_slice()
        );
        // second scalar times the identity point is the identity
        assert_eq!(
            archive.statements[1].output.as_slice(),
            identity().as_slice()
        );
        let started = std::time::Instant::now();
        verify_ristretto_scalar_mul_ladder_batch(&archive).expect("ladder batch verify");
        eprintln!(
            "scalar-mul ladder (2 statements): prove {prove_elapsed:?}, verify {:?}, ladder proof {} bytes",
            started.elapsed(),
            archive.stark_proof_bytes.len(),
        );
    }

    #[test]
    fn scalar_mul_ladder_rejects_detached_and_spliced_proofs() {
        let scalar = scalar_bytes(0x0123_4567_89ab_cdef);
        let window_schedule = windows(&scalar);
        let archive = prove_ristretto_scalar_mul_ladder(scalar, window_schedule, basepoint())
            .expect("ladder STARK");
        assert!(verify_ristretto_scalar_mul_ladder(&archive).is_ok());

        // A scalar whose windows disagree with the statement is detached.
        let mut spliced = archive.clone();
        spliced.statements[0].scalar[0] ^= 1;
        assert!(verify_ristretto_scalar_mul_ladder(&spliced).is_err());

        // A spliced output byte is detached from the rebuilt schedule.
        let mut spliced = archive.clone();
        spliced.statements[0].output[1] ^= 1;
        assert!(verify_ristretto_scalar_mul_ladder(&spliced).is_err());

        // A spliced base encoding detaches the decode batch.
        let mut spliced = archive.clone();
        spliced.statements[0].base[2] ^= 1;
        assert!(verify_ristretto_scalar_mul_ladder(&spliced).is_err());

        // An extra statement without rows is detached.
        let mut spliced = archive.clone();
        spliced.statements.push(spliced.statements[0].clone());
        assert!(verify_ristretto_scalar_mul_ladder_batch(&spliced).is_err());

        // Spliced ladder proof bytes fail the STARK. The serialized proof's
        // leading `PcsConfig` field is inert metadata, so tamper consumed
        // regions: the commitments body and the tail.
        let proof_len = archive.stark_proof_bytes.len();
        for position in [64, proof_len / 2] {
            let mut spliced = archive.clone();
            spliced.stark_proof_bytes[position] ^= 1;
            assert!(
                verify_ristretto_scalar_mul_ladder(&spliced).is_err(),
                "splicing ladder proof byte {position} must fail"
            );
        }

        // A spliced range claimed sum fails the interaction commitment.
        let mut spliced = archive.clone();
        spliced.range_claimed_sum[0] ^= 1;
        assert!(verify_ristretto_scalar_mul_ladder(&spliced).is_err());
    }
}
