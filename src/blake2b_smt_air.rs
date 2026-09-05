//! Direct, sequential AIR for one fixed-width L1 Blake2b-256 compression.
//!
//! This is the soundness-first bridge between the fixed SMT witness ABI and
//! the eventual lookup-optimized Blake2b component.  It proves all ninety-six
//! Blake2b `G` invocations in separate rows, binding the complete 128-byte
//! message block, parameterized initial state, counter/final-block flags and
//! 32-byte digest through verifier-reconstructed scope columns.  In
//! particular, it does not accept a native digest receipt.
//!
//! The trace still uses Boolean decompositions for 16-bit limbs.  That is
//! intentionally temporary: the equivalent range/XOR relations will be moved
//! to LogUp tables before this component is used for a 257-compression SMT
//! path.  Keeping the compression chain in rows already avoids the
//! impractical one-row, 67k-column baseline and gives the lookup port a
//! precisely specified public ABI.
#![allow(missing_docs)]

use bincode::Options;
use stwo::core::channel::{Channel, Poseidon252Channel};
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::proof::StarkProof;
use stwo::core::utils::coset_index_to_circle_domain_index;
use stwo::core::vcs_lifted::poseidon252_merkle::{
    Poseidon252MerkleChannel, Poseidon252MerkleHasher,
};
use stwo::core::verifier::{VerificationError, verify};
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::pcs::CommitmentSchemeProver;
use stwo::prover::{ProvingError, prove};
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, ORIGINAL_TRACE_IDX, TraceLocationAllocator,
};

use crate::blake2b_smt_witness::{
    BLAKE2B_256_PARAMETER_WORD, BLAKE2B_BLOCK_BYTES, BLAKE2B_IV, BLAKE2B_SIGMA,
    Blake2bSmtFixedValuePathWitness, Blake2bSmtSingleBlock, SMT_INTERNAL_DOMAIN, SMT_LEAF_DOMAIN,
    SMT_SINGLE_BLOCK_INPUT_BYTES,
};
use crate::error::{TexasAirError, TexasAirResult};
use crate::trace_gen::MethodTrace;

const G_ROWS: usize = 12 * 8;
const LOG_SIZE: u32 = 7;
const WORD_LIMBS: usize = 4;
const LIMB_BITS: usize = 16;
const STATE_WORDS: usize = 16;
const MESSAGE_WORDS: usize = 16;
const TEMP_WORDS: usize = 8;
const CARRY_SETS: usize = 4;
const DIGEST_WORDS: usize = 4;
const SELECTOR_GROUPS: usize = 6;
const UPDATE_SELECTOR_GROUPS: usize = 4;

// state limbs, message limbs, eight G intermediates, addition carries,
// state bits, intermediate bits and four output-digest words respectively.
const NUM_COLUMNS: usize = STATE_WORDS * WORD_LIMBS
    + MESSAGE_WORDS * WORD_LIMBS
    + TEMP_WORDS * WORD_LIMBS
    + CARRY_SETS * WORD_LIMBS * 3
    + STATE_WORDS * WORD_LIMBS * LIMB_BITS
    + TEMP_WORDS * WORD_LIMBS * LIMB_BITS
    + DIGEST_WORDS * WORD_LIMBS * LIMB_BITS;

// active / first / last / advance, initial v, message, digest, the six
// input selectors (a,b,c,d,x,y), and selectors for the first 95 state
// updates.  This whole column set is reconstructed by the verifier.
const SCOPE_COLUMNS: usize = 4
    + STATE_WORDS * WORD_LIMBS
    + MESSAGE_WORDS * WORD_LIMBS
    + DIGEST_WORDS * WORD_LIMBS
    + SELECTOR_GROUPS * STATE_WORDS
    + UPDATE_SELECTOR_GROUPS * STATE_WORDS;

#[derive(Debug, Clone, Copy)]
struct Blake2bBatchAir {
    log_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchivedBlake2bSmtSingleBlockProof {
    message: [u8; BLAKE2B_BLOCK_BYTES],
    digest: [u8; 32],
    stark_proof_bytes: Vec<u8>,
}

/// A host-zero fixed-value SMT opening proof.
///
/// The witness contains only the canonical byte-level path statement.  The
/// proof binds every leaf/internal compression to that statement and binds
/// the terminal node to `root`; no native hash is called by verification.
/// This direct component is intentionally a correctness bridge.  Production
/// batches should replace its bit-decomposition columns with the Stwo XOR and
/// range LogUp tables before using large paths on the latency-sensitive route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchivedBlake2bSmtFixedValuePathProof {
    witness: Blake2bSmtFixedValuePathWitness,
    log_size: u32,
    stark_proof_bytes: Vec<u8>,
}

impl ArchivedBlake2bSmtFixedValuePathProof {
    /// Return the canonical public path statement bound by this proof.
    #[must_use]
    pub const fn witness(&self) -> &Blake2bSmtFixedValuePathWitness {
        &self.witness
    }

    /// Return the trace log size used for the fixed 257-compression batch.
    #[must_use]
    pub const fn log_size(&self) -> u32 {
        self.log_size
    }
}

impl ArchivedBlake2bSmtSingleBlockProof {
    /// The exact zero-padded 128-byte Blake2b message block proven by this archive.
    #[must_use]
    pub const fn message(&self) -> &[u8; BLAKE2B_BLOCK_BYTES] {
        &self.message
    }

    /// The public Blake2b-256 digest constrained by the STARK.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

#[derive(Clone)]
struct AtNext<F> {
    current: F,
    next: F,
}

#[derive(Clone)]
struct Carry<F> {
    value: F,
    bits: [F; 2],
}

fn options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(16 * 1024 * 1024)
}

fn compression_pcs_config(log_size: u32) -> PcsConfig {
    // On Stwo's circle domain, a degree-three product of trace polynomials
    // has a log-degree bound one larger than the trace.  Retain the
    // repository's 10 PoW / 30-query
    // baseline, which gives this standalone component a conservative 100-bit
    // FRI soundness margin rather than silently undersampling degree-nine
    // composition values.
    PcsConfig {
        pow_bits: 10,
        fri_config: FriConfig::new(0, 3, 30, 1),
        // The quotient has degree at most `2^8`; lift the committed
        // low-degree columns to that bound plus the three FRI blowup bits.
        lifting_log_size: Some(log_size + 1 + 3),
    }
}

fn limbs(value: u64) -> [M31; WORD_LIMBS] {
    std::array::from_fn(|index| M31::from(((value >> (index * 16)) & 0xffff) as u32))
}

fn bits(value: u64) -> [[M31; LIMB_BITS]; WORD_LIMBS] {
    std::array::from_fn(|limb| {
        std::array::from_fn(|bit| M31::from(((value >> (limb * 16 + bit)) & 1) as u32))
    })
}

fn word_from_bytes(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().expect("BLAKE word has eight bytes"))
}

fn words_from_message(message: &[u8; BLAKE2B_BLOCK_BYTES]) -> [u64; MESSAGE_WORDS] {
    std::array::from_fn(|index| word_from_bytes(&message[index * 8..(index + 1) * 8]))
}

fn digest_words(digest: &[u8; 32]) -> [u64; DIGEST_WORDS] {
    std::array::from_fn(|index| word_from_bytes(&digest[index * 8..(index + 1) * 8]))
}

fn initial_v() -> [u64; STATE_WORDS] {
    let mut h = BLAKE2B_IV;
    h[0] ^= BLAKE2B_256_PARAMETER_WORD;
    let mut v = [0u64; STATE_WORDS];
    v[..8].copy_from_slice(&h);
    v[8..].copy_from_slice(&BLAKE2B_IV);
    v[12] ^= SMT_SINGLE_BLOCK_INPUT_BYTES as u64;
    v[14] = !v[14];
    v
}

const G_LANES: [[usize; 4]; 8] = [
    [0, 4, 8, 12],
    [1, 5, 9, 13],
    [2, 6, 10, 14],
    [3, 7, 11, 15],
    [0, 5, 10, 15],
    [1, 6, 11, 12],
    [2, 7, 8, 13],
    [3, 4, 9, 14],
];

fn schedule(row: usize) -> Option<([usize; 4], usize, usize)> {
    (row < G_ROWS).then(|| {
        let round = row / 8;
        let g = row % 8;
        let sigma = BLAKE2B_SIGMA[round];
        (G_LANES[g], sigma[g * 2], sigma[g * 2 + 1])
    })
}

// Stwo's `next_interaction_mask(..., [0, 1])` advances in coset order, while
// `MethodTrace` is provided in circle-domain natural order before its
// commitment-time bit reversal.  Store the logical G sequence at these circle
// rows so the AIR's successor is the next G invocation, rather than an
// unrelated bit-reversed row.
fn domain_row(step: usize, log_size: u32) -> usize {
    coset_index_to_circle_domain_index(step, log_size)
}

fn add_carries(a: u64, b: u64, extra: u64) -> [u8; WORD_LIMBS] {
    let mut carry = 0u32;
    std::array::from_fn(|limb| {
        let sum = ((a >> (limb * 16)) & 0xffff) as u32
            + ((b >> (limb * 16)) & 0xffff) as u32
            + ((extra >> (limb * 16)) & 0xffff) as u32
            + carry;
        carry = sum >> 16;
        carry as u8
    })
}

fn g_with_intermediates(a: u64, b: u64, c: u64, d: u64, x: u64, y: u64) -> [u64; TEMP_WORDS] {
    let a1 = a.wrapping_add(b).wrapping_add(x);
    let d1 = (d ^ a1).rotate_right(32);
    let c1 = c.wrapping_add(d1);
    let b1 = (b ^ c1).rotate_right(24);
    let a2 = a1.wrapping_add(b1).wrapping_add(y);
    let d2 = (d1 ^ a2).rotate_right(16);
    let c2 = c1.wrapping_add(d2);
    let b2 = (b1 ^ c2).rotate_right(63);
    [a1, d1, c1, b1, a2, d2, c2, b2]
}

fn fixed_block_from_message(
    message: [u8; BLAKE2B_BLOCK_BYTES],
) -> TexasAirResult<Blake2bSmtSingleBlock> {
    if message[SMT_SINGLE_BLOCK_INPUT_BYTES..]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(TexasAirError::SpecViolation(
            "fixed Blake2b SMT block has non-zero padding".into(),
        ));
    }
    let mut first = [0u8; 32];
    let mut second = [0u8; 32];
    first.copy_from_slice(&message[1..33]);
    second.copy_from_slice(&message[33..65]);
    let block = match message[0] {
        SMT_LEAF_DOMAIN => Blake2bSmtSingleBlock::leaf(first, second),
        SMT_INTERNAL_DOMAIN => Blake2bSmtSingleBlock::internal(first, second),
        _ => {
            return Err(TexasAirError::SpecViolation(
                "fixed Blake2b SMT block has an unknown domain".into(),
            ));
        }
    };
    if block.message() != &message {
        return Err(TexasAirError::SpecViolation(
            "fixed Blake2b SMT block shape is not canonical".into(),
        ));
    }
    Ok(block)
}

fn scope_ids() -> &'static [PreProcessedColumnId] {
    static IDS: std::sync::OnceLock<Vec<PreProcessedColumnId>> = std::sync::OnceLock::new();
    IDS.get_or_init(build_scope_ids).as_slice()
}

fn build_scope_ids() -> Vec<PreProcessedColumnId> {
    let mut ids = vec![
        "blake2b.smt.active.v1",
        "blake2b.smt.first.v1",
        "blake2b.smt.last.v1",
        "blake2b.smt.advance.v1",
    ]
    .into_iter()
    .map(|id| PreProcessedColumnId { id: id.into() })
    .collect::<Vec<_>>();
    for domain in ["initial-v", "message", "digest"] {
        let words = if domain == "digest" {
            DIGEST_WORDS
        } else {
            STATE_WORDS
        };
        for word in 0..words {
            for limb in 0..WORD_LIMBS {
                ids.push(PreProcessedColumnId {
                    id: format!("blake2b.smt.{domain}.v1.{word}.{limb}").into(),
                });
            }
        }
    }
    for label in ["a", "b", "c", "d", "x", "y"] {
        for lane in 0..STATE_WORDS {
            ids.push(PreProcessedColumnId {
                id: format!("blake2b.smt.selector.{label}.v1.{lane}").into(),
            });
        }
    }
    for label in ["a", "b", "c", "d"] {
        for lane in 0..STATE_WORDS {
            ids.push(PreProcessedColumnId {
                id: format!("blake2b.smt.update.{label}.v1.{lane}").into(),
            });
        }
    }
    debug_assert_eq!(ids.len(), SCOPE_COLUMNS);
    ids
}

fn scope_trace_blocks(
    blocks: &[Blake2bSmtSingleBlock],
    digests: &[[u8; 32]],
    log_size: u32,
) -> TexasAirResult<MethodTrace> {
    if blocks.len() != digests.len()
        || blocks.is_empty()
        || blocks.len().saturating_mul(G_ROWS) > (1usize << log_size)
    {
        return Err(TexasAirError::SpecViolation(
            "invalid Blake2b batch shape".into(),
        ));
    }
    let initial = initial_v();
    let mut trace = MethodTrace::new(log_size, SCOPE_COLUMNS);
    for row in 0..(1usize << log_size) {
        let mut values = vec![M31::from(0u32); SCOPE_COLUMNS];
        let block_index = row / G_ROWS;
        let local_row = row % G_ROWS;
        let active = block_index < blocks.len();
        values[0] = M31::from(u32::from(active));
        values[1] = M31::from(u32::from(active && local_row == 0));
        values[2] = M31::from(u32::from(active && local_row + 1 == G_ROWS));
        values[3] = M31::from(u32::from(active && local_row + 1 < G_ROWS));
        let message = active.then(|| words_from_message(blocks[block_index].message()));
        let digest = active.then(|| digest_words(&digests[block_index]));
        let mut offset = 4;
        for word in initial {
            if active && local_row == 0 {
                values[offset..offset + WORD_LIMBS].copy_from_slice(&limbs(word));
            }
            offset += WORD_LIMBS;
        }
        for word in message.unwrap_or([0; MESSAGE_WORDS]) {
            if active && local_row == 0 {
                values[offset..offset + WORD_LIMBS].copy_from_slice(&limbs(word));
            }
            offset += WORD_LIMBS;
        }
        for word in digest.unwrap_or([0; DIGEST_WORDS]) {
            if active && local_row + 1 == G_ROWS {
                values[offset..offset + WORD_LIMBS].copy_from_slice(&limbs(word));
            }
            offset += WORD_LIMBS;
        }
        if let Some((lanes, x, y)) = active.then(|| schedule(local_row)).flatten() {
            for index in lanes {
                values[offset + index] = M31::from(1u32);
                offset += STATE_WORDS;
            }
            values[offset + x] = M31::from(1u32);
            offset += STATE_WORDS;
            values[offset + y] = M31::from(1u32);
            offset += STATE_WORDS;
            let update = local_row + 1 < G_ROWS;
            for index in lanes {
                if update {
                    values[offset + index] = M31::from(1u32);
                }
                offset += STATE_WORDS;
            }
        } else {
            offset += (SELECTOR_GROUPS + UPDATE_SELECTOR_GROUPS) * STATE_WORDS;
        }
        debug_assert_eq!(offset, SCOPE_COLUMNS);
        trace.write_row(domain_row(row, log_size), &values)?;
    }
    Ok(trace)
}

fn trace_for_blocks(
    blocks: &[Blake2bSmtSingleBlock],
    digests: &[[u8; 32]],
    log_size: u32,
) -> TexasAirResult<MethodTrace> {
    if blocks.len() != digests.len()
        || blocks.is_empty()
        || blocks.len().saturating_mul(G_ROWS) > (1usize << log_size)
    {
        return Err(TexasAirError::SpecViolation(
            "invalid Blake2b batch shape".into(),
        ));
    }
    let mut trace = MethodTrace::new(log_size, NUM_COLUMNS);
    for (block_index, (block, digest)) in blocks.iter().zip(digests).enumerate() {
        let message = words_from_message(block.message());
        let digest = digest_words(digest);
        let mut v = initial_v();
        for local_row in 0..G_ROWS {
            let global_row = block_index * G_ROWS + local_row;
            let (lanes, x_index, y_index) = schedule(local_row).expect("active G row has schedule");
            let [a, b, c, d] = lanes;
            let temporary =
                g_with_intermediates(v[a], v[b], v[c], v[d], message[x_index], message[y_index]);
            let carries = [
                add_carries(v[a], v[b], message[x_index]),
                add_carries(v[c], temporary[1], 0),
                add_carries(temporary[0], temporary[3], message[y_index]),
                add_carries(temporary[2], temporary[5], 0),
            ];
            let mut values = Vec::with_capacity(NUM_COLUMNS);
            for word in v {
                values.extend(limbs(word));
            }
            for word in message {
                values.extend(limbs(word));
            }
            for word in temporary {
                values.extend(limbs(word));
            }
            for set in carries {
                for carry in set {
                    values.push(M31::from(u32::from(carry)));
                    values.push(M31::from(u32::from(carry & 1)));
                    values.push(M31::from(u32::from((carry >> 1) & 1)));
                }
            }
            for word in v {
                for limb in bits(word) {
                    values.extend(limb);
                }
            }
            for word in temporary {
                for limb in bits(word) {
                    values.extend(limb);
                }
            }
            let is_last = local_row + 1 == G_ROWS;
            for output_word in 0..DIGEST_WORDS {
                let output = digest[output_word];
                for limb in bits(if is_last { output } else { 0 }) {
                    values.extend(limb);
                }
            }
            debug_assert_eq!(values.len(), NUM_COLUMNS);
            trace.write_row(domain_row(global_row, log_size), &values)?;
            v[a] = temporary[4];
            v[b] = temporary[7];
            v[c] = temporary[6];
            v[d] = temporary[5];
        }
    }
    Ok(trace)
}

fn trace_pair<E: EvalAtRow>(eval: &mut E) -> AtNext<E::F> {
    let [current, next] = eval.next_interaction_mask(ORIGINAL_TRACE_IDX, [0, 1]);
    AtNext { current, next }
}

fn trace_word_pair<E: EvalAtRow>(eval: &mut E) -> [AtNext<E::F>; WORD_LIMBS] {
    std::array::from_fn(|_| trace_pair(eval))
}

fn trace_bits_pair<E: EvalAtRow>(eval: &mut E) -> [[AtNext<E::F>; LIMB_BITS]; WORD_LIMBS] {
    std::array::from_fn(|_| std::array::from_fn(|_| trace_pair(eval)))
}

fn trace_word<E: EvalAtRow>(eval: &mut E) -> [E::F; WORD_LIMBS] {
    std::array::from_fn(|_| eval.next_trace_mask())
}

fn trace_bits<E: EvalAtRow>(eval: &mut E) -> [[E::F; LIMB_BITS]; WORD_LIMBS] {
    std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()))
}

fn next_scope<E: EvalAtRow, I: Iterator<Item = PreProcessedColumnId>>(
    eval: &mut E,
    ids: &mut I,
) -> E::F {
    eval.get_preprocessed_column(ids.next().expect("complete Blake2b scope layout"))
}

fn scope_word<E: EvalAtRow, I: Iterator<Item = PreProcessedColumnId>>(
    eval: &mut E,
    ids: &mut I,
) -> [E::F; WORD_LIMBS] {
    std::array::from_fn(|_| next_scope(eval, ids))
}

fn select_word<E: EvalAtRow>(
    selectors: &[E::F; STATE_WORDS],
    words: &[[AtNext<E::F>; WORD_LIMBS]; STATE_WORDS],
) -> [E::F; WORD_LIMBS] {
    std::array::from_fn(|limb| {
        let mut selected: E::F = M31::from(0u32).into();
        for lane in 0..STATE_WORDS {
            selected += selectors[lane].clone() * words[lane][limb].current.clone();
        }
        selected
    })
}

fn select_bits<E: EvalAtRow>(
    selectors: &[E::F; STATE_WORDS],
    words: &[[[AtNext<E::F>; LIMB_BITS]; WORD_LIMBS]; STATE_WORDS],
) -> [[E::F; LIMB_BITS]; WORD_LIMBS] {
    std::array::from_fn(|limb| {
        std::array::from_fn(|bit| {
            let mut selected: E::F = M31::from(0u32).into();
            for lane in 0..STATE_WORDS {
                selected += selectors[lane].clone() * words[lane][limb][bit].current.clone();
            }
            selected
        })
    })
}

fn range_word<E: EvalAtRow>(
    eval: &mut E,
    word: &[AtNext<E::F>; WORD_LIMBS],
    bits: &[[AtNext<E::F>; LIMB_BITS]; WORD_LIMBS],
) {
    let one: E::F = M31::from(1u32).into();
    for limb in 0..WORD_LIMBS {
        let mut reconstructed: E::F = M31::from(0u32).into();
        for bit in 0..LIMB_BITS {
            let value = bits[limb][bit].current.clone();
            eval.add_constraint(value.clone() * (value.clone() - one.clone()));
            reconstructed += value * E::F::from(M31::from(1u32 << bit));
        }
        eval.add_constraint(word[limb].current.clone() - reconstructed);
    }
}

fn range_temp_word<E: EvalAtRow>(
    eval: &mut E,
    word: &[E::F; WORD_LIMBS],
    bits: &[[E::F; LIMB_BITS]; WORD_LIMBS],
) {
    let one: E::F = M31::from(1u32).into();
    for limb in 0..WORD_LIMBS {
        let mut reconstructed: E::F = M31::from(0u32).into();
        for bit in 0..LIMB_BITS {
            let value = bits[limb][bit].clone();
            eval.add_constraint(value.clone() * (value.clone() - one.clone()));
            reconstructed += value * E::F::from(M31::from(1u32 << bit));
        }
        eval.add_constraint(word[limb].clone() - reconstructed);
    }
}

fn constrain_carry<E: EvalAtRow>(eval: &mut E, carry: &Carry<E::F>) {
    let one: E::F = M31::from(1u32).into();
    for bit in &carry.bits {
        eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
    }
    eval.add_constraint(
        carry.value.clone()
            - carry.bits[0].clone()
            - E::F::from(M31::from(2u32)) * carry.bits[1].clone(),
    );
}

fn add_words<E: EvalAtRow>(
    eval: &mut E,
    left: &[E::F; WORD_LIMBS],
    right: &[E::F; WORD_LIMBS],
    extra: Option<&[E::F; WORD_LIMBS]>,
    output: &[E::F; WORD_LIMBS],
    carries: &[Carry<E::F>; WORD_LIMBS],
) {
    let base: E::F = M31::from(65536u32).into();
    let zero: E::F = M31::from(0u32).into();
    for limb in 0..WORD_LIMBS {
        constrain_carry(eval, &carries[limb]);
        let carry_in = if limb == 0 {
            zero.clone()
        } else {
            carries[limb - 1].value.clone()
        };
        let mut sum = left[limb].clone() + right[limb].clone() + carry_in;
        if let Some(extra) = extra {
            sum += extra[limb].clone();
        }
        eval.add_constraint(
            sum - output[limb].clone() - base.clone() * carries[limb].value.clone(),
        );
    }
}

fn xor_rotate<E: EvalAtRow>(
    eval: &mut E,
    left: &[[E::F; LIMB_BITS]; WORD_LIMBS],
    right: &[[E::F; LIMB_BITS]; WORD_LIMBS],
    output: &[[E::F; LIMB_BITS]; WORD_LIMBS],
    rotation: usize,
) {
    let two: E::F = M31::from(2u32).into();
    for output_index in 0..64 {
        let source = (output_index + rotation) % 64;
        let left = left[source / LIMB_BITS][source % LIMB_BITS].clone();
        let right = right[source / LIMB_BITS][source % LIMB_BITS].clone();
        let output = output[output_index / LIMB_BITS][output_index % LIMB_BITS].clone();
        eval.add_constraint(output - left.clone() - right.clone() + two.clone() * left * right);
    }
}

fn evaluate_blake2b<E: EvalAtRow>(mut eval: E) -> E {
    let mut ids = scope_ids().iter().cloned();
    let active = next_scope(&mut eval, &mut ids);
    let first = next_scope(&mut eval, &mut ids);
    let last = next_scope(&mut eval, &mut ids);
    let advance = next_scope(&mut eval, &mut ids);
    let initial: [[E::F; WORD_LIMBS]; STATE_WORDS] =
        std::array::from_fn(|_| scope_word(&mut eval, &mut ids));
    let scoped_message: [[E::F; WORD_LIMBS]; MESSAGE_WORDS] =
        std::array::from_fn(|_| scope_word(&mut eval, &mut ids));
    let scoped_digest: [[E::F; WORD_LIMBS]; DIGEST_WORDS] =
        std::array::from_fn(|_| scope_word(&mut eval, &mut ids));
    let selectors: [[E::F; STATE_WORDS]; SELECTOR_GROUPS] =
        std::array::from_fn(|_| std::array::from_fn(|_| next_scope(&mut eval, &mut ids)));
    let updates: [[E::F; STATE_WORDS]; UPDATE_SELECTOR_GROUPS] =
        std::array::from_fn(|_| std::array::from_fn(|_| next_scope(&mut eval, &mut ids)));
    debug_assert!(ids.next().is_none());

    let state: [[AtNext<E::F>; WORD_LIMBS]; STATE_WORDS] =
        std::array::from_fn(|_| trace_word_pair(&mut eval));
    let message: [[AtNext<E::F>; WORD_LIMBS]; MESSAGE_WORDS] =
        std::array::from_fn(|_| trace_word_pair(&mut eval));
    let temporary: [[E::F; WORD_LIMBS]; TEMP_WORDS] =
        std::array::from_fn(|_| trace_word(&mut eval));
    let carries: [[Carry<E::F>; WORD_LIMBS]; CARRY_SETS] = std::array::from_fn(|_| {
        std::array::from_fn(|_| Carry {
            value: eval.next_trace_mask(),
            bits: [eval.next_trace_mask(), eval.next_trace_mask()],
        })
    });
    let state_bits: [[[AtNext<E::F>; LIMB_BITS]; WORD_LIMBS]; STATE_WORDS] =
        std::array::from_fn(|_| trace_bits_pair(&mut eval));
    let temporary_bits: [[[E::F; LIMB_BITS]; WORD_LIMBS]; TEMP_WORDS] =
        std::array::from_fn(|_| trace_bits(&mut eval));
    let digest_bits: [[[E::F; LIMB_BITS]; WORD_LIMBS]; DIGEST_WORDS] =
        std::array::from_fn(|_| trace_bits(&mut eval));

    let one: E::F = M31::from(1u32).into();
    eval.add_constraint(active.clone() * (active.clone() - one.clone()));
    eval.add_constraint(first.clone() * (first.clone() - one.clone()));
    eval.add_constraint(last.clone() * (last.clone() - one.clone()));
    eval.add_constraint(advance.clone() * (advance.clone() - one));
    for group in &selectors {
        let mut sum: E::F = M31::from(0u32).into();
        for selector in group {
            eval.add_constraint(
                selector.clone() * (selector.clone() - E::F::from(M31::from(1u32))),
            );
            sum += selector.clone();
        }
        eval.add_constraint(sum - active.clone());
    }
    for group in &updates {
        let mut sum: E::F = M31::from(0u32).into();
        for selector in group {
            eval.add_constraint(
                selector.clone() * (selector.clone() - E::F::from(M31::from(1u32))),
            );
            sum += selector.clone();
        }
        eval.add_constraint(sum - advance.clone());
    }
    for lane in 0..STATE_WORDS {
        range_word(&mut eval, &state[lane], &state_bits[lane]);
        for limb in 0..WORD_LIMBS {
            eval.add_constraint(
                first.clone() * (state[lane][limb].current.clone() - initial[lane][limb].clone()),
            );
        }
    }
    for word in 0..MESSAGE_WORDS {
        for limb in 0..WORD_LIMBS {
            eval.add_constraint(
                first.clone()
                    * (message[word][limb].current.clone() - scoped_message[word][limb].clone()),
            );
            eval.add_constraint(
                advance.clone()
                    * (message[word][limb].next.clone() - message[word][limb].current.clone()),
            );
        }
    }
    for word in 0..TEMP_WORDS {
        range_temp_word(&mut eval, &temporary[word], &temporary_bits[word]);
    }

    let a = select_word::<E>(&selectors[0], &state);
    let b = select_word::<E>(&selectors[1], &state);
    let c = select_word::<E>(&selectors[2], &state);
    let x = select_word::<E>(&selectors[4], &message);
    let y = select_word::<E>(&selectors[5], &message);
    let b_bits = select_bits::<E>(&selectors[1], &state_bits);
    let d_bits = select_bits::<E>(&selectors[3], &state_bits);

    add_words(&mut eval, &a, &b, Some(&x), &temporary[0], &carries[0]);
    xor_rotate(
        &mut eval,
        &d_bits,
        &temporary_bits[0],
        &temporary_bits[1],
        32,
    );
    add_words(
        &mut eval,
        &c,
        &temporary[1],
        None,
        &temporary[2],
        &carries[1],
    );
    xor_rotate(
        &mut eval,
        &b_bits,
        &temporary_bits[2],
        &temporary_bits[3],
        24,
    );
    add_words(
        &mut eval,
        &temporary[0],
        &temporary[3],
        Some(&y),
        &temporary[4],
        &carries[2],
    );
    xor_rotate(
        &mut eval,
        &temporary_bits[1],
        &temporary_bits[4],
        &temporary_bits[5],
        16,
    );
    add_words(
        &mut eval,
        &temporary[2],
        &temporary[5],
        None,
        &temporary[6],
        &carries[3],
    );
    xor_rotate(
        &mut eval,
        &temporary_bits[3],
        &temporary_bits[6],
        &temporary_bits[7],
        63,
    );

    // A G updates a,b,c,d to a2,b2,c2,d2.  Update selectors are zero on
    // the final row, where the final digest relation consumes the result
    // directly instead of wrapping the trace into padding.
    let outputs = [
        &temporary_bits[4],
        &temporary_bits[7],
        &temporary_bits[6],
        &temporary_bits[5],
    ];
    for lane in 0..STATE_WORDS {
        for limb in 0..WORD_LIMBS {
            for bit in 0..LIMB_BITS {
                let mut relation = advance.clone()
                    * (state_bits[lane][limb][bit].next.clone()
                        - state_bits[lane][limb][bit].current.clone());
                for group in 0..UPDATE_SELECTOR_GROUPS {
                    relation = relation
                        - updates[group][lane].clone()
                            * (outputs[group][limb][bit].clone()
                                - state_bits[lane][limb][bit].current.clone());
                }
                eval.add_constraint(relation);
            }
        }
    }

    // The final schedule position is static: G(3,4,9,14).  Use its
    // post-G a2/c2 values directly for h[3] and h[1] respectively, and
    // the current state for every other digest input word.
    for word in 0..DIGEST_WORDS {
        let left_lane = word;
        let right_lane = word + 8;
        for limb in 0..WORD_LIMBS {
            for bit in 0..LIMB_BITS {
                let left = if left_lane == 3 {
                    temporary_bits[4][limb][bit].clone()
                } else {
                    state_bits[left_lane][limb][bit].current.clone()
                };
                let right = if right_lane == 9 {
                    temporary_bits[6][limb][bit].clone()
                } else {
                    state_bits[right_lane][limb][bit].current.clone()
                };
                let h_bit = ((initial_v()[word] >> (limb * LIMB_BITS + bit)) & 1) as u32;
                let expected = if h_bit == 0 {
                    left.clone() + right.clone()
                        - E::F::from(M31::from(2u32)) * left.clone() * right.clone()
                } else {
                    E::F::from(M31::from(1u32)) - left.clone() - right.clone()
                        + E::F::from(M31::from(2u32)) * left.clone() * right.clone()
                };
                eval.add_constraint(
                    last.clone() * (digest_bits[word][limb][bit].clone() - expected),
                );
            }
            let mut reconstructed: E::F = M31::from(0u32).into();
            for bit in 0..LIMB_BITS {
                reconstructed +=
                    digest_bits[word][limb][bit].clone() * E::F::from(M31::from(1u32 << bit));
            }
            eval.add_constraint(last.clone() * (scoped_digest[word][limb].clone() - reconstructed));
        }
    }
    eval
}

impl FrameworkEval for Blake2bBatchAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, eval: E) -> E {
        evaluate_blake2b(eval)
    }
}

fn mix_scope_blocks(
    channel: &mut Poseidon252Channel,
    blocks: &[Blake2bSmtSingleBlock],
    digests: &[[u8; 32]],
) {
    for (block, digest) in blocks.iter().zip(digests) {
        for bytes in [block.message().as_slice(), digest.as_slice()] {
            channel.mix_u32s(
                &bytes
                    .chunks_exact(4)
                    .map(|chunk| u32::from_le_bytes(chunk.try_into().expect("four bytes")))
                    .collect::<Vec<_>>(),
            );
        }
    }
}

fn prove_blake2b_blocks(
    blocks: &[Blake2bSmtSingleBlock],
    digests: &[[u8; 32]],
    log_size: u32,
) -> TexasAirResult<Vec<u8>> {
    let trace = trace_for_blocks(blocks, digests, log_size)?;
    let scope = scope_trace_blocks(blocks, digests, log_size)?;
    let config = compression_pcs_config(log_size);
    let twiddles =
        crate::prover_context::simd_twiddles(log_size + 1 + config.fri_config.log_blowup_factor);
    let mut channel = Poseidon252Channel::default();
    mix_scope_blocks(&mut channel, blocks, digests);
    let mut scheme =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::with_memory_pool(
            config,
            &twiddles,
            crate::prover_context::simd_base_column_pool(),
        );
    // The sequential selectors create degree-three constraints, so Stwo must
    // retain coefficients while forming the higher-degree composition.
    scheme.set_store_polynomials_coefficients();
    {
        let mut builder = scheme.tree_builder();
        builder.extend_evals(scope.to_evaluations());
        builder.commit(&mut channel);
    }
    {
        let mut builder = scheme.tree_builder();
        builder.extend_evals(trace.to_evaluations());
        builder.commit(&mut channel);
    }
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&scope_ids());
    let component = FrameworkComponent::new(
        &mut allocator,
        Blake2bBatchAir { log_size },
        SecureField::from(0u32),
    );
    debug_assert_eq!(scheme.polynomials().len(), 2);
    debug_assert_eq!(scheme.polynomials()[0].len(), SCOPE_COLUMNS);
    debug_assert_eq!(scheme.polynomials()[1].len(), NUM_COLUMNS);
    let proof = prove(&[&component], &mut channel, scheme)
        .map_err(|error: ProvingError| TexasAirError::StwoProverError(error.to_string()))?;
    options()
        .serialize(&proof)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))
}

fn verify_blake2b_blocks(
    blocks: &[Blake2bSmtSingleBlock],
    digests: &[[u8; 32]],
    log_size: u32,
    proof_bytes: &[u8],
) -> TexasAirResult<()> {
    let proof: StarkProof<Poseidon252MerkleHasher> = options()
        .deserialize(proof_bytes)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
    if proof.commitments.len() != 3 {
        return Err(TexasAirError::SpecViolation(
            "Blake2b proof must contain scope, execution and composition commitments".into(),
        ));
    }
    let config = compression_pcs_config(log_size);
    let scope = scope_trace_blocks(blocks, digests, log_size)?;
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
        let mut builder = trusted.tree_builder();
        builder.extend_evals(scope.to_evaluations());
        builder.commit(&mut scope_channel);
    }
    if proof.commitments.first().copied() != trusted.roots().first().copied() {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Blake2b public scope commitment mismatch".into(),
        ));
    }
    let mut channel = Poseidon252Channel::default();
    mix_scope_blocks(&mut channel, blocks, digests);
    let mut scheme = CommitmentSchemeVerifier::<Poseidon252MerkleChannel>::new(config);
    scheme.commit(
        proof.commitments[0],
        &vec![log_size; SCOPE_COLUMNS],
        &mut channel,
    );
    scheme.commit(
        proof.commitments[1],
        &vec![log_size; NUM_COLUMNS],
        &mut channel,
    );
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&scope_ids());
    let component = FrameworkComponent::new(
        &mut allocator,
        Blake2bBatchAir { log_size },
        SecureField::from(0u32),
    );
    verify(&[&component], &mut channel, &mut scheme, proof)
        .map_err(|error: VerificationError| TexasAirError::ConstraintUnsatisfied(error.to_string()))
}

/// Prove a single fixed L1 leaf/internal-node Blake2b-256 compression.
///
/// `digest` is a public statement supplied by the caller (normally the
/// prover-supplied SMT node).  The routine builds arithmetic witness columns,
/// but it never decides whether the digest is correct: a mismatch makes the
/// AIR unsatisfiable.  A caller must bind this archive's message/digest to the
/// same state-opening statement before using it for admission.
pub fn prove_blake2b_smt_single_block(
    block: &Blake2bSmtSingleBlock,
    digest: [u8; 32],
) -> TexasAirResult<ArchivedBlake2bSmtSingleBlockProof> {
    let proof_bytes = prove_blake2b_blocks(
        std::slice::from_ref(block),
        std::slice::from_ref(&digest),
        LOG_SIZE,
    )?;
    Ok(ArchivedBlake2bSmtSingleBlockProof {
        message: *block.message(),
        digest,
        stark_proof_bytes: proof_bytes,
    })
}

/// Verify a fixed L1 Blake2b-256 compression proof without invoking a native hash.
pub fn verify_blake2b_smt_single_block(
    archive: &ArchivedBlake2bSmtSingleBlockProof,
) -> TexasAirResult<()> {
    let block = fixed_block_from_message(archive.message)?;
    verify_blake2b_blocks(
        std::slice::from_ref(&block),
        std::slice::from_ref(&archive.digest),
        LOG_SIZE,
        &archive.stark_proof_bytes,
    )
}

fn blake2b_batch_log_size(block_count: usize) -> TexasAirResult<u32> {
    if block_count == 0 {
        return Err(TexasAirError::SpecViolation(
            "Blake2b batch must contain at least one compression".into(),
        ));
    }
    let rows = block_count
        .checked_mul(G_ROWS)
        .ok_or_else(|| TexasAirError::SpecViolation("Blake2b batch row count overflow".into()))?;
    let domain_rows = rows.next_power_of_two();
    Ok(domain_rows.ilog2())
}

/// Prove the complete fixed-value L1 SMT opening as one batched AIR.
///
/// The witness's `nodes`, siblings and key determine every compression block
/// and every public digest.  The prover cannot substitute native hash output;
/// it must satisfy all 257 compression components in the single STARK.
pub fn prove_blake2b_smt_fixed_value_path(
    witness: &Blake2bSmtFixedValuePathWitness,
) -> TexasAirResult<ArchivedBlake2bSmtFixedValuePathProof> {
    if !witness.terminal_node_matches_root() {
        return Err(TexasAirError::SpecViolation(
            "Blake2b SMT path root does not match its terminal node".into(),
        ));
    }
    let blocks = witness.compression_blocks();
    let log_size = blake2b_batch_log_size(blocks.len())?;
    let proof_bytes = prove_blake2b_blocks(&blocks, &witness.nodes, log_size)?;
    Ok(ArchivedBlake2bSmtFixedValuePathProof {
        witness: witness.clone(),
        log_size,
        stark_proof_bytes: proof_bytes,
    })
}

/// Verify a fixed-value L1 SMT opening without native hashing or transaction
/// replay.  The verifier reconstructs only the canonical byte layout and path
/// direction; all hash relations are checked by the batched AIR.
pub fn verify_blake2b_smt_fixed_value_path(
    archive: &ArchivedBlake2bSmtFixedValuePathProof,
) -> TexasAirResult<()> {
    if !archive.witness.terminal_node_matches_root() {
        return Err(TexasAirError::SpecViolation(
            "Blake2b SMT path root does not match its terminal node".into(),
        ));
    }
    let blocks = archive.witness.compression_blocks();
    let expected_log_size = blake2b_batch_log_size(blocks.len())?;
    if archive.log_size != expected_log_size {
        return Err(TexasAirError::SpecViolation(
            "Blake2b SMT path proof has an invalid trace log size".into(),
        ));
    }
    verify_blake2b_blocks(
        &blocks,
        &archive.witness.nodes,
        archive.log_size,
        &archive.stark_proof_bytes,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_blocks_trace_satisfies_air(
        blocks: &[Blake2bSmtSingleBlock],
        digests: &[[u8; 32]],
        log_size: u32,
    ) {
        let scope = scope_trace_blocks(blocks, digests, log_size).expect("scope trace");
        let trace = trace_for_blocks(blocks, digests, log_size).expect("execution trace");
        let log_size = trace.log_size;
        let bit_reversed = |method_trace: &MethodTrace| {
            method_trace
                .cols
                .iter()
                .map(|column| {
                    (0..(1usize << log_size))
                        .map(|row| {
                            let natural_row = row.reverse_bits() >> (usize::BITS - log_size);
                            column[natural_row]
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
        };
        let scope = bit_reversed(&scope);
        let trace = bit_reversed(&trace);
        let evals =
            stwo::core::pcs::TreeVec::new(vec![scope.iter().collect(), trace.iter().collect()]);
        stwo_constraint_framework::assert_constraints_on_trace(
            &evals,
            log_size,
            |eval| {
                Blake2bBatchAir { log_size }.evaluate(eval);
            },
            SecureField::from(0u32),
        );
    }

    fn assert_trace_satisfies_air(block: &Blake2bSmtSingleBlock, digest: [u8; 32]) {
        let blocks = [block.clone()];
        let digests = [digest];
        assert_blocks_trace_satisfies_air(&blocks, &digests, LOG_SIZE);
    }

    #[ignore = "slow prove (~14s); full gate runs `--include-ignored`"]
    #[test]
    fn fixed_leaf_compression_proves_and_verifies_in_air() {
        let block = Blake2bSmtSingleBlock::leaf([0x11; 32], [0x22; 32]);
        assert_trace_satisfies_air(&block, block.native_digest());
        let archive = prove_blake2b_smt_single_block(&block, block.native_digest())
            .expect("valid fixed leaf compression proof");
        verify_blake2b_smt_single_block(&archive)
            .expect("valid fixed leaf compression verification");
    }

    #[ignore = "slow prove (~16s); full gate runs `--include-ignored`"]
    #[test]
    fn incorrect_public_digest_cannot_be_proved() {
        let block = Blake2bSmtSingleBlock::leaf([0x11; 32], [0x22; 32]);
        let mut digest = block.native_digest();
        digest[0] ^= 1;
        assert!(prove_blake2b_smt_single_block(&block, digest).is_err());
    }

    #[ignore = "slow prove (~15s); full gate runs `--include-ignored`"]
    #[test]
    fn two_compressions_share_one_batched_stark() {
        let leaf = Blake2bSmtSingleBlock::leaf([0x11; 32], [0x22; 32]);
        let leaf_digest = leaf.native_digest();
        let parent = Blake2bSmtSingleBlock::internal(leaf_digest, [0x33; 32]);
        let digests = [leaf_digest, parent.native_digest()];
        let blocks = [leaf, parent];
        let log_size = blake2b_batch_log_size(blocks.len()).expect("batch log size");
        assert_eq!(log_size, 8);
        assert_blocks_trace_satisfies_air(&blocks, &digests, log_size);
        let proof_bytes =
            prove_blake2b_blocks(&blocks, &digests, log_size).expect("two-compression batch proof");
        verify_blake2b_blocks(&blocks, &digests, log_size, &proof_bytes)
            .expect("two-compression batch verification");
    }

    #[ignore = "slow prove (~11s); full gate runs `--include-ignored`"]
    #[test]
    fn public_digest_splice_is_rejected_by_scope_reconstruction() {
        let block = Blake2bSmtSingleBlock::internal([0x33; 32], [0x44; 32]);
        let mut archive = prove_blake2b_smt_single_block(&block, block.native_digest())
            .expect("valid fixed internal compression proof");
        archive.digest[0] ^= 1;
        assert!(verify_blake2b_smt_single_block(&archive).is_err());
    }

    #[ignore = "slow prove (~14s); full gate runs `--include-ignored`"]
    #[test]
    fn malformed_commitment_shape_is_rejected_without_panic() {
        let block = Blake2bSmtSingleBlock::leaf([0x55; 32], [0x66; 32]);
        let mut archive = prove_blake2b_smt_single_block(&block, block.native_digest())
            .expect("valid fixed leaf compression proof");
        let mut proof: StarkProof<Poseidon252MerkleHasher> = options()
            .deserialize(&archive.stark_proof_bytes)
            .expect("archive proof bytes");
        proof.0.commitments.clear();
        archive.stark_proof_bytes = options()
            .serialize(&proof)
            .expect("serialize malformed proof");
        assert!(verify_blake2b_smt_single_block(&archive).is_err());
    }

    #[test]
    fn fixed_path_shape_has_a_single_log15_batch_and_rejects_bad_root_early() {
        assert_eq!(
            blake2b_batch_log_size(
                crate::blake2b_smt_witness::SMT_FIXED_VALUE_OPENING_COMPRESSIONS
            )
            .expect("fixed path batch shape"),
            15
        );
        let witness = Blake2bSmtFixedValuePathWitness {
            key: [0; 32],
            value: [0; 32],
            siblings: [[0; 32]; crate::blake2b_smt_witness::SMT_PATH_SIBLINGS],
            nodes: [[0; 32]; crate::blake2b_smt_witness::SMT_FIXED_VALUE_OPENING_COMPRESSIONS],
            root: [1; 32],
        };
        assert!(prove_blake2b_smt_fixed_value_path(&witness).is_err());
    }
}
