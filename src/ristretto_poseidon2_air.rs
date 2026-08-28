//! Poseidon2 over M31: transcript-chain segment (Path A Flock-elimination).
//!
//! Parameters follow the Circle STARKs instantiation (eprint 2024/278):
//! state `t = 16`, 8 external rounds (4+4) and 14 internal rounds, S-box
//! `x^5` (3 native multiplications — `x^3`/`x^7` are **not** permutations
//! on M31 because 3²·7 | 2^31−2), external matrix `circ(2·M4, M4, M4, M4)`
//! implemented with additions only, internal matrix `diag(2^{i+1}) + sum`.
//! With rate/capacity 8/8 the capacity is 8·31 = 248 bits ⇒ 124-bit
//! classical collision security (see eprint 2024/1635); digests must
//! serialize at least 8 state elements.
//!
//! Performance shape (measured 2026-08): one permutation occupies 158
//! columns × one row (8 instances per row, SIMD lanes in parallel), with
//! no limbs, carries, or range checks — M31-native by construction.
//!
//! Chain semantics (2026-08-28, soundness wiring): a chain step is
//! `state ← permute(state + words)` with the 8 rate-lane words public
//! (scope columns, pinned through the statement digest).  Per-step states
//! are chained by the LogUp multiset argument — every instance publishes
//! `(+1, state_j)` and `(−1, state_{j+1})`, and every chain adds the
//! boundary pair `(−1, scope initial)` / `(+1, scope digest)` gated by a
//! one-hot selector column, so the total fraction sum telescopes to
//! exactly zero and the multiset equality pins each chain's first state
//! to the scope initial and its terminal state to the scope digest —
//! the same balanced-table pattern the ladder range stripes use.
//! Round constants are deterministically generated below (splitmix-style
//! PRG, fixed seed); production must regenerate them (and re-check the
//! internal matrix coefficients) per the Poseidon2 paper's
//! nothing-up-my-sleeve procedure — the stwo reference example carries
//! the same TODOs.

#![allow(missing_docs)]

use stwo::core::channel::Channel;
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::SecureField;
use stwo::prover::backend::simd::SimdBackend;
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, LogupTraceGenerator, Relation, RelationEntry,
    TraceLocationAllocator, relation,
};

use num_traits::One;

use crate::trace_gen::MethodTrace;

// ---------------------------------------------------------------------------
// Parameters (Circle STARKs Poseidon2-M31 instantiation).
// ---------------------------------------------------------------------------

pub const N_STATE: usize = 16;
/// Rate lanes: message words absorbed before each permutation.
pub const N_RATE_LANES: usize = 8;
pub const N_PARTIAL_ROUNDS: usize = 14;
pub const N_HALF_FULL_ROUNDS: usize = 4;
pub const FULL_ROUNDS: usize = 2 * N_HALF_FULL_ROUNDS;
/// Instances (whole permutations) unrolled per trace row.
pub const N_INSTANCES_PER_ROW: usize = 8;
pub(crate) const N_COLUMNS_PER_REP: usize =
    N_STATE * (1 + 3 * FULL_ROUNDS) + 3 * N_PARTIAL_ROUNDS;
const N_COLUMNS: usize = N_INSTANCES_PER_ROW * N_COLUMNS_PER_REP;
/// Minimum segment size: one SIMD vector row of LogUp interactions.
pub(crate) const LOG_SIZE_FLOOR: u32 = 7;

const M31_P: u64 = (1 << 31) - 1;

/// Deterministic round constants (splitmix64 chain, fixed public seed).
/// See the module docs for the production regeneration note.
const fn splitmix64(state: u64) -> u64 {
    let mut z = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Reduce a u64 into M31 via Mersenne folding.
const fn to_m31_bits(value: u64) -> u32 {
    let folded = (value & M31_P) + (value >> 31);
    let folded = (folded & M31_P) + (folded >> 31);
    (folded % M31_P) as u32
}

const fn generate_constants() -> ([[u32; N_STATE]; FULL_ROUNDS], [u32; N_PARTIAL_ROUNDS]) {
    let mut state = 0x5053_4549_444F_4E32_u64; // "POSEIDON2"
    let mut external = [[0u32; N_STATE]; FULL_ROUNDS];
    let mut round = 0;
    while round < FULL_ROUNDS {
        let mut i = 0;
        while i < N_STATE {
            state = splitmix64(state);
            external[round][i] = to_m31_bits(state);
            i += 1;
        }
        round += 1;
    }
    let mut internal = [0u32; N_PARTIAL_ROUNDS];
    let mut round = 0;
    while round < N_PARTIAL_ROUNDS {
        state = splitmix64(state);
        internal[round] = to_m31_bits(state);
        round += 1;
    }
    (external, internal)
}

pub const EXTERNAL_ROUND_CONSTS: [[u32; N_STATE]; FULL_ROUNDS] = generate_constants().0;
pub const INTERNAL_ROUND_CONSTS: [u32; N_PARTIAL_ROUNDS] = generate_constants().1;

// ---------------------------------------------------------------------------
// Round functions, generic over the field so the witness generator and the
// AIR constraints share one implementation.
// ---------------------------------------------------------------------------

pub trait Poseidon2Field:
    Clone + std::ops::AddAssign + std::ops::Mul<M31, Output = Self>
{
}
impl<T> Poseidon2Field for T where T: Clone + std::ops::AddAssign + std::ops::Mul<M31, Output = T> {}

/// `x^5` — three native field multiplications.
pub fn pow5<F: Poseidon2Field + std::ops::Mul<Output = F>>(x: &F) -> F {
    let x2 = x.clone() * x.clone();
    let x4 = x2.clone() * x2.clone();
    x4 * x.clone()
}

/// The M4 matrix of Poseidon2 §5.1: additions and doublings only.
fn apply_m4<F: Poseidon2Field + std::ops::Add<Output = F>>(x: [F; 4]) -> [F; 4] {
    let t0 = x[0].clone() + x[1].clone();
    let t02 = t0.clone() + t0.clone();
    let t1 = x[2].clone() + x[3].clone();
    let t12 = t1.clone() + t1.clone();
    let t2 = x[1].clone() + x[1].clone() + t1;
    let t3 = x[3].clone() + x[3].clone() + t0;
    let t4 = t12.clone() + t12.clone() + t3.clone();
    let t5 = t02.clone() + t02.clone() + t2.clone();
    let t6 = t3 + t5.clone();
    let t7 = t2 + t4.clone();
    [t6, t5, t7, t4]
}

/// External round matrix `circ(2·M4, M4, M4, M4)` (Poseidon2 §5.1).
fn apply_external_round_matrix<
    F: Poseidon2Field + std::ops::Add<Output = F> + std::ops::Sub<Output = F>,
>(
    state: &mut [F; N_STATE],
) {
    for i in 0..4 {
        [state[4 * i], state[4 * i + 1], state[4 * i + 2], state[4 * i + 3]] = apply_m4([
            state[4 * i].clone(),
            state[4 * i + 1].clone(),
            state[4 * i + 2].clone(),
            state[4 * i + 3].clone(),
        ]);
    }
    for j in 0..4 {
        let s = state[j].clone() + state[j + 4].clone() + state[j + 8].clone() + state[j + 12].clone();
        for i in 0..4 {
            state[4 * i + j] += s.clone();
        }
    }
}

/// Internal round matrix: `x_i ← 2^{i+1}·x_i + Σ x` (Poseidon2 §5.2 shape;
/// the stwo reference example carries the same coefficient TODO).
fn apply_internal_round_matrix<F: Poseidon2Field + std::ops::Add<Output = F>>(
    state: &mut [F; N_STATE],
) {
    let sum = state[1..]
        .iter()
        .cloned()
        .fold(state[0].clone(), |acc, s| acc + s);
    state.iter_mut().enumerate().for_each(|(i, s)| {
        *s = s.clone() * M31::from_u32_unchecked(1 << (i + 1)) + sum.clone();
    });
}

/// One full Poseidon2 permutation over M31 (native witness path).
pub fn permute(state: &mut [M31; N_STATE]) {
    for round in 0..N_HALF_FULL_ROUNDS {
        for i in 0..N_STATE {
            state[i] += M31::from_u32_unchecked(EXTERNAL_ROUND_CONSTS[round][i]);
        }
        apply_external_round_matrix(state);
        *state = std::array::from_fn(|i| pow5(&state[i]));
    }
    for round in 0..N_PARTIAL_ROUNDS {
        state[0] += M31::from_u32_unchecked(INTERNAL_ROUND_CONSTS[round]);
        apply_internal_round_matrix(state);
        state[0] = pow5(&state[0]);
    }
    for round in 0..N_HALF_FULL_ROUNDS {
        for i in 0..N_STATE {
            state[i] +=
                M31::from_u32_unchecked(EXTERNAL_ROUND_CONSTS[round + N_HALF_FULL_ROUNDS][i]);
        }
        apply_external_round_matrix(state);
        *state = std::array::from_fn(|i| pow5(&state[i]));
    }
}

/// One chain step: absorb the public rate words, then permute.
pub fn absorb_and_permute(state: &mut [M31; N_STATE], words: &[u32; N_RATE_LANES]) {
    for (lane, word) in words.iter().enumerate() {
        state[lane] += M31::from_u32_unchecked(*word);
    }
    permute(state);
}

// ---------------------------------------------------------------------------
// LogUp relation and AIR.
// ---------------------------------------------------------------------------

relation!(Poseidon2State, N_STATE);

/// One transcript-chain batch statement: every chain starts at a public
/// initial state and applies `chain_length` absorb-and-permute steps; the
/// terminal state is the chain digest (scope-pinned by the segment).
///
/// The absorbed words are public and travel chain-major:
/// `absorbed_words[c * chain_length + j]` is step `j` of chain `c`.
/// Padding steps (and padding instances beyond the chain slots) absorb
/// the all-zero word vector.
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct Poseidon2ChainSpec {
    /// Public initial states, one per chain.
    pub initial_states: Vec<[u32; N_STATE]>,
    /// Public absorbed rate words per step, chain-major
    /// (`chains × chain_length` entries).
    pub absorbed_words: Vec<[u32; N_RATE_LANES]>,
    /// Uniform chain length in absorb-and-permute steps.
    pub chain_length: u32,
}

impl Poseidon2ChainSpec {
    /// Validate the shape: at least one chain, `chain_length ≥ 1`, and the
    /// words schedule sized `chains × chain_length`.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.initial_states.is_empty() {
            return Err("poseidon2 chain spec carries no chains");
        }
        if self.chain_length == 0 {
            return Err("poseidon2 chain length is zero");
        }
        let expected = self.initial_states.len() * self.chain_length as usize;
        if self.absorbed_words.len() != expected {
            return Err("poseidon2 absorbed-words schedule is detached from the chain set");
        }
        Ok(())
    }

    fn words(&self, chain: usize, step: usize) -> [u32; N_RATE_LANES] {
        self.absorbed_words[chain * self.chain_length as usize + step]
    }

    /// Native chain evaluation: the terminal state of every chain.
    pub fn digests(&self) -> Vec<[u32; N_STATE]> {
        self.initial_states
            .iter()
            .enumerate()
            .map(|(chain, initial)| {
                let mut state: [M31; N_STATE] =
                    std::array::from_fn(|i| M31::from_u32_unchecked(initial[i]));
                for step in 0..self.chain_length as usize {
                    absorb_and_permute(&mut state, &self.words(chain, step));
                }
                std::array::from_fn(|i| state[i].0)
            })
            .collect()
    }
}

/// AIR of the permutation batch: each row carries
/// [`N_INSTANCES_PER_ROW`] whole permutations (442 columns each).  Every
/// instance absorbs its public rate words into the pre-permutation state
/// (scope columns), and the LogUp relation publishes every
/// `(pre-absorption state, post-permutation state)` pair plus, per chain,
/// the boundary pair `(−selector, scope initial)` / `(+selector, scope
/// digest)` with a one-hot selector firing on row 0 — the total fraction
/// sum telescopes to zero exactly.
#[derive(Clone)]
pub struct Poseidon2Air {
    log_size: u32,
    chains: usize,
    lookup_elements: Poseidon2State,
    /// Preprocessed scope-column identities in consumption order: the
    /// words block (rep-major, `N_RATE_LANES` per instance slot) followed
    /// by the per-chain blocks `[initial (16), digest (16), select_initial,
    /// select_digest]`.  `get_preprocessed_column` consumes the
    /// preprocessed tree sequentially, so this order is the scope layout.
    scope_ids: Vec<PreProcessedColumnId>,
    #[allow(dead_code)]
    total_sum: SecureField,
}

impl FrameworkEval for Poseidon2Air {
    fn log_size(&self) -> u32 {
        self.log_size
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let mut scope_cursor = 0usize;
        let next_scope = |cursor: &mut usize| {
            let id = self.scope_ids[*cursor].clone();
            *cursor += 1;
            id
        };
        for _ in 0..N_INSTANCES_PER_ROW {
            let mut state: [_; N_STATE] = std::array::from_fn(|_| eval.next_trace_mask());
            let initial_state: [_; N_STATE] = state.clone();

            // Absorb the instance's public rate words (scope columns,
            // rep-major: the words of the instance living in this slot).
            let words: [_; N_RATE_LANES] =
                std::array::from_fn(|_| eval.get_preprocessed_column(next_scope(&mut scope_cursor)));
            for (lane, word) in words.iter().enumerate() {
                state[lane] += word.clone();
            }

            let mut pow5_split = |eval: &mut E, x: E::F| -> E::F {
                let x2 = x.clone() * x.clone();
                let m2 = eval.next_trace_mask();
                eval.add_constraint(x2.clone() - m2.clone());
                let x4 = m2.clone() * m2.clone();
                let m4 = eval.next_trace_mask();
                eval.add_constraint(x4 - m4.clone());
                let x5 = m4.clone() * x;
                let m5 = eval.next_trace_mask();
                eval.add_constraint(x5 - m5.clone());
                m5
            };

            let mut full_round = |eval: &mut E, state: &mut [E::F; N_STATE], round: usize| {
                for (i, s) in state.iter_mut().enumerate() {
                    let constant =
                        E::F::from(M31::from_u32_unchecked(EXTERNAL_ROUND_CONSTS[round][i]));
                    *s += constant;
                }
                apply_external_round_matrix(state);
                *state = std::array::from_fn(|i| pow5_split(eval, state[i].clone()));
            };

            for round in 0..N_HALF_FULL_ROUNDS {
                full_round(&mut eval, &mut state, round);
            }
            for round in 0..N_PARTIAL_ROUNDS {
                let constant = E::F::from(M31::from_u32_unchecked(INTERNAL_ROUND_CONSTS[round]));
                state[0] += constant;
                apply_internal_round_matrix(&mut state);
                state[0] = pow5_split(&mut eval, state[0].clone());
            }
            for round in 0..N_HALF_FULL_ROUNDS {
                full_round(&mut eval, &mut state, round + N_HALF_FULL_ROUNDS);
            }

            eval.add_to_relation(RelationEntry::new(
                &self.lookup_elements,
                E::EF::one(),
                &initial_state,
            ));
            eval.add_to_relation(RelationEntry::new(&self.lookup_elements, -E::EF::one(), &state));
        }
        // Chain boundaries: per chain, the scope initial is a yield and
        // the scope digest is a use, each gated by a one-hot selector so
        // the pair fires exactly once across the trace (row 0).  With the
        // per-instance (+state_j, −state_{j+1}) entries this balances the
        // LogUp sum to zero and pins both boundary tuples.
        for _ in 0..self.chains {
            let initial: [_; N_STATE] =
                std::array::from_fn(|_| eval.get_preprocessed_column(next_scope(&mut scope_cursor)));
            let digest: [_; N_STATE] =
                std::array::from_fn(|_| eval.get_preprocessed_column(next_scope(&mut scope_cursor)));
            let select_initial = eval.get_preprocessed_column(next_scope(&mut scope_cursor));
            let select_digest = eval.get_preprocessed_column(next_scope(&mut scope_cursor));
            eval.add_to_relation(RelationEntry::new(
                &self.lookup_elements,
                -E::EF::from(select_initial),
                &initial,
            ));
            eval.add_to_relation(RelationEntry::new(
                &self.lookup_elements,
                E::EF::from(select_digest),
                &digest,
            ));
        }
        eval.finalize_logup_in_pairs();
        eval
    }
}

// ---------------------------------------------------------------------------
// Segment (shared-tree wiring for the unified admission STARK).
// ---------------------------------------------------------------------------

pub(crate) type Poseidon2Eval = stwo::prover::poly::circle::CircleEvaluation<
    SimdBackend,
    M31,
    stwo::prover::poly::BitReversedOrder,
>;

pub(crate) struct Poseidon2Segment {
    pub(crate) log_size: u32,
    /// Number of chain blocks in the scope: the statement's chains plus
    /// one deterministic padding chain whenever the instance slots are not
    /// fully covered (the padding chain starts at the all-zero state and
    /// absorbs zero words, so both sides derive it from the shape alone).
    pub(crate) chains: usize,
    /// Preprocessed scope columns in the AIR's consumption order.
    pub(crate) scope: MethodTrace,
    pub(crate) trace: MethodTrace,
    pub(crate) interaction: Vec<Poseidon2Eval>,
    pub(crate) claimed_sum: SecureField,
    relations: Option<Poseidon2State>,
}

impl Poseidon2Segment {
    pub(crate) fn log_size_for(spec: &Poseidon2ChainSpec) -> u32 {
        let instances = spec.initial_states.len() * spec.chain_length as usize;
        let rows = instances.div_ceil(N_INSTANCES_PER_ROW);
        rows.max(1 << LOG_SIZE_FLOOR)
            .next_power_of_two()
            .ilog2()
    }

    /// Materialize the scope and trace of the chain batch.  Instance slots
    /// hold chains' absorb-and-permute steps in order (chain-major,
    /// statement chains first, then the padding chain); the padding chain
    /// starts at the all-zero state with zero words so both prover and
    /// verifier derive it from the shape alone.
    pub(crate) fn build(spec: &Poseidon2ChainSpec) -> Self {
        spec.validate().expect("validated poseidon2 chain spec");
        let log_size = Self::log_size_for(spec);
        let rows = 1usize << log_size;
        let instance_slots = rows * N_INSTANCES_PER_ROW;
        let chains = spec.initial_states.len();
        let length = spec.chain_length as usize;
        let padding = instance_slots - chains * length;

        // Effective chain set: statement chains, then the padding chain.
        let chain_initials: Vec<[M31; N_STATE]> = spec
            .initial_states
            .iter()
            .map(|initial| std::array::from_fn(|i| M31::from_u32_unchecked(initial[i])))
            .chain(std::iter::once([M31::from(0u32); N_STATE]).filter(|_| padding > 0))
            .collect();
        let chain_lengths: Vec<usize> = (0..chains)
            .map(|_| length)
            .chain(std::iter::once(padding).filter(|_| padding > 0))
            .collect();
        let total_chains = chain_initials.len();

        // Every chain's running PRE-absorption states: instance (chain, j)
        // carries `states[j]`; the rounds run on `states[j] + words[j]`.
        let mut chain_states: Vec<Vec<[M31; N_STATE]>> = Vec::with_capacity(total_chains);
        for chain in 0..total_chains {
            let mut states = Vec::with_capacity(chain_lengths[chain] + 1);
            let mut state = chain_initials[chain];
            states.push(state);
            for _ in 0..chain_lengths[chain] {
                let words = if chain < chains {
                    spec.words(chain, states.len() - 1)
                } else {
                    [0u32; N_RATE_LANES]
                };
                absorb_and_permute(&mut state, &words);
                states.push(state);
            }
            chain_states.push(states);
        }

        // Word schedule per instance slot (slot-major): statement slots
        // read the spec, padding slots absorb zeros.
        let slot_words = |slot: usize| -> [u32; N_RATE_LANES] {
            if slot < chains * length {
                spec.words(slot / length, slot % length)
            } else {
                [0u32; N_RATE_LANES]
            }
        };

        let mut columns: Vec<Vec<M31>> = vec![vec![M31::from(0u32); rows]; N_COLUMNS];
        for slot in 0..instance_slots {
            let row = slot / N_INSTANCES_PER_ROW;
            let rep = slot % N_INSTANCES_PER_ROW;
            let mut state: [M31; N_STATE] = if slot < chains * length {
                chain_states[slot / length][slot % length]
            } else {
                chain_states[chains][slot - chains * length]
            };
            let mut col = rep * N_COLUMNS_PER_REP;
            for value in state.iter() {
                columns[col][row] = *value;
                col += 1;
            }
            for (lane, word) in slot_words(slot).iter().enumerate() {
                state[lane] += M31::from_u32_unchecked(*word);
            }
            let mut write_pow5 = |columns: &mut Vec<Vec<M31>>, col: &mut usize, x: M31| {
                let x2 = x * x;
                let x4 = x2 * x2;
                let x5 = x4 * x;
                columns[*col][row] = x2;
                columns[*col + 1][row] = x4;
                columns[*col + 2][row] = x5;
                *col += 3;
                x5
            };
            for round in 0..N_HALF_FULL_ROUNDS {
                for i in 0..N_STATE {
                    state[i] += M31::from_u32_unchecked(EXTERNAL_ROUND_CONSTS[round][i]);
                }
                apply_external_round_matrix(&mut state);
                state = std::array::from_fn(|i| {
                    write_pow5(&mut columns, &mut col, state[i])
                });
            }
            for round in 0..N_PARTIAL_ROUNDS {
                state[0] += M31::from_u32_unchecked(INTERNAL_ROUND_CONSTS[round]);
                apply_internal_round_matrix(&mut state);
                state[0] = write_pow5(&mut columns, &mut col, state[0]);
            }
            for round in 0..N_HALF_FULL_ROUNDS {
                for i in 0..N_STATE {
                    state[i] += M31::from_u32_unchecked(
                        EXTERNAL_ROUND_CONSTS[round + N_HALF_FULL_ROUNDS][i],
                    );
                }
                apply_external_round_matrix(&mut state);
                state = std::array::from_fn(|i| {
                    write_pow5(&mut columns, &mut col, state[i])
                });
            }
            debug_assert_eq!(col, (rep + 1) * N_COLUMNS_PER_REP);
        }

        let digests: Vec<[u32; N_STATE]> = chain_states
            .iter()
            .zip(chain_lengths.iter())
            .map(|(states, length)| std::array::from_fn(|i| states[*length][i].0))
            .collect();
        let scope = Self::scope_trace(&slot_words, &chain_initials, &digests, rows);
        let trace = MethodTrace::from_columns(log_size, columns);
        Self {
            log_size,
            chains: total_chains,
            scope,
            trace,
            interaction: Vec::new(),
            claimed_sum: SecureField::from(0u32),
            relations: None,
        }
    }

    /// Scope layout, in the AIR's consumption order:
    /// `[words: N_INSTANCES_PER_ROW × N_RATE_LANES row-dependent columns,
    /// rep-major — column (rep, lane) at row R holds the absorbed word of
    /// the instance in slot (R·8+rep)]` then per chain (statement chains
    /// first, padding chain last) `[initial (16, replicated), digest (16,
    /// replicated), select_initial, select_digest]` with both selectors
    /// one-hot on row 0.
    fn scope_trace(
        slot_words: &dyn Fn(usize) -> [u32; N_RATE_LANES],
        chain_initials: &[[M31; N_STATE]],
        digests: &[[u32; N_STATE]],
        rows: usize,
    ) -> MethodTrace {
        let log_size = rows.ilog2();
        let mut columns = Vec::with_capacity(
            N_INSTANCES_PER_ROW * N_RATE_LANES + chain_initials.len() * (2 * N_STATE + 2),
        );
        for rep in 0..N_INSTANCES_PER_ROW {
            for lane in 0..N_RATE_LANES {
                let column: Vec<M31> = (0..rows)
                    .map(|row| {
                        M31::from_u32_unchecked(
                            slot_words(row * N_INSTANCES_PER_ROW + rep)[lane],
                        )
                    })
                    .collect();
                columns.push(column);
            }
        }
        for (chain, initial) in chain_initials.iter().enumerate() {
            for value in initial.iter() {
                columns.push(vec![*value; rows]);
            }
            for value in &digests[chain] {
                columns.push(vec![M31::from_u32_unchecked(*value); rows]);
            }
            let mut select_initial = vec![M31::from(0u32); rows];
            select_initial[0] = M31::from(1u32);
            columns.push(select_initial);
            let mut select_digest = vec![M31::from(0u32); rows];
            select_digest[0] = M31::from(1u32);
            columns.push(select_digest);
        }
        MethodTrace::from_columns(log_size, columns)
    }

    pub(crate) fn interact(&mut self, channel: &mut stwo::core::channel::Poseidon252Channel) {
        let lookup_elements = Poseidon2State::draw(channel);
        let (interaction, claimed_sum) = self.gen_interaction(&lookup_elements);
        self.interaction = interaction;
        self.claimed_sum = claimed_sum;
        self.relations = Some(lookup_elements);
    }

    /// LogUp columns in the AIR's emission order: per instance slot the
    /// `(initial, final)` pair as `(d_final − d_initial)/(d_initial·d_final)`,
    /// then per chain the boundary pair `(d_initial − d_digest)·selector /
    /// (d_initial·d_digest)` (the selectors are one-hot on row 0, so the
    /// boundary columns carry zero numerators elsewhere).
    ///
    /// The trace and scope columns are bit-reversed before packing: the
    /// [`LogupTraceGenerator`] stores secure columns in bit-reversed row
    /// order, so slot `u` must carry the fraction of natural row
    /// `bitrev(u)` — the same convention as the working scalar/ladder
    /// segment generators.
    fn gen_interaction(
        &self,
        lookup_elements: &Poseidon2State,
    ) -> (Vec<Poseidon2Eval>, SecureField) {
        use stwo::prover::backend::simd::m31::{LOG_N_LANES, N_LANES, PackedBaseField};
        use stwo::prover::backend::simd::qm31::PackedSecureField;

        let log_size = self.log_size;
        let vec_rows = 1usize << (log_size - LOG_N_LANES);
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
        let pack_vec = |column: &[M31], vector_row: usize| -> PackedBaseField {
            let mut values = [M31::from(0u32); N_LANES];
            for (lane, value) in values.iter_mut().enumerate() {
                let row = vector_row * N_LANES + lane;
                *value = if row < column.len() {
                    column[row]
                } else {
                    M31::from(0u32)
                };
            }
            PackedBaseField::from_array(values)
        };
        // Per instance slot, the reversed (initial, final) state columns the
        // LogUp denominators read.
        let reversed_states: Vec<([Vec<M31>; N_STATE], [Vec<M31>; N_STATE])> = (0..N_INSTANCES_PER_ROW)
            .map(|rep| {
                let base = rep * N_COLUMNS_PER_REP;
                let initial: [Vec<M31>; N_STATE] =
                    std::array::from_fn(|i| bitrev(&self.trace.cols[base + i]));
                let terminal_state: [Vec<M31>; N_STATE] = std::array::from_fn(|i| {
                    bitrev(&self.trace.cols[base + N_COLUMNS_PER_REP - 3 * N_STATE + 3 * i + 2])
                });
                (initial, terminal_state)
            })
            .collect();
        // Per chain block, the reversed (initial, digest, selectors) scope
        // columns.  The scope layout after the words block (which is
        // N_INSTANCES_PER_ROW × N_RATE_LANES rep-major columns) is per
        // chain: 16 initial, 16 digest, select_initial, select_digest.
        let words_block = N_INSTANCES_PER_ROW * N_RATE_LANES;
        let reversed_chains: Vec<([Vec<M31>; N_STATE], [Vec<M31>; N_STATE], Vec<M31>, Vec<M31>)> =
            (0..self.chains)
                .map(|chain| {
                    let base = words_block + chain * (2 * N_STATE + 2);
                    let initial: [Vec<M31>; N_STATE] =
                        std::array::from_fn(|i| bitrev(&self.scope.cols[base + i]));
                    let digest: [Vec<M31>; N_STATE] =
                        std::array::from_fn(|i| bitrev(&self.scope.cols[base + N_STATE + i]));
                    let select_initial = bitrev(&self.scope.cols[base + 2 * N_STATE]);
                    let select_digest = bitrev(&self.scope.cols[base + 2 * N_STATE + 1]);
                    (initial, digest, select_initial, select_digest)
                })
                .collect();
        let mut logup_gen = LogupTraceGenerator::new(log_size);
        for rep in 0..N_INSTANCES_PER_ROW {
            let (initial_cols, final_cols) = &reversed_states[rep];
            let mut col_gen = logup_gen.new_col();
            for vec_row in 0..vec_rows {
                let initial: [PackedBaseField; N_STATE] =
                    std::array::from_fn(|i| pack_vec(&initial_cols[i], vec_row));
                let terminal: [PackedBaseField; N_STATE] =
                    std::array::from_fn(|i| pack_vec(&final_cols[i], vec_row));
                let denom0: PackedSecureField = lookup_elements.combine(&initial);
                let denom1: PackedSecureField = lookup_elements.combine(&terminal);
                col_gen.write_frac(vec_row, denom1 - denom0, denom0 * denom1);
            }
            col_gen.finalize_col();
        }
        for (initial_cols, digest_cols, select_initial, select_digest) in &reversed_chains {
            let mut col_gen = logup_gen.new_col();
            for vec_row in 0..vec_rows {
                let initial: [PackedBaseField; N_STATE] =
                    std::array::from_fn(|i| pack_vec(&initial_cols[i], vec_row));
                let digest: [PackedBaseField; N_STATE] =
                    std::array::from_fn(|i| pack_vec(&digest_cols[i], vec_row));
                let sel0 = pack_vec(select_initial, vec_row);
                let sel1 = pack_vec(select_digest, vec_row);
                let denom0: PackedSecureField = lookup_elements.combine(&initial);
                let denom1: PackedSecureField = lookup_elements.combine(&digest);
                // −sel0/denom0 + sel1/denom1 as a single fraction:
                // (denom0·sel1 − denom1·sel0)/(denom0·denom1).
                let numerator = denom0.clone() * PackedSecureField::from(sel1)
                    - denom1.clone() * PackedSecureField::from(sel0);
                col_gen.write_frac(vec_row, numerator, denom0 * denom1);
            }
            col_gen.finalize_col();
        }
        logup_gen.finalize_last()
    }

    pub(crate) fn mirror_draw(&mut self, channel: &mut stwo::core::channel::Poseidon252Channel) {
        self.relations = Some(Poseidon2State::draw(channel));
    }

    /// Interaction-column count (paired fractions, four M31 columns per
    /// secure column): one column per instance pair plus one per chain
    /// boundary pair, derivable from the fixed layout so the verifier can
    /// declare the tree-2 shape without materializing it.
    pub(crate) fn interaction_columns(&self) -> usize {
        (N_INSTANCES_PER_ROW + self.chains) * 4
    }

    pub(crate) fn preprocessed_ids(&self) -> Vec<PreProcessedColumnId> {
        (0..self.scope.num_columns)
            .map(|column| PreProcessedColumnId {
                id: format!("ristretto.admission.poseidon2.scope.{column}").into(),
            })
            .collect()
    }

    pub(crate) fn component(
        &self,
        allocator: &mut TraceLocationAllocator,
    ) -> FrameworkComponent<Poseidon2Air> {
        let lookup_elements = self
            .relations
            .clone()
            .expect("Poseidon2Segment::interact runs before component construction");
        FrameworkComponent::new(
            allocator,
            Poseidon2Air {
                log_size: self.log_size,
                chains: self.chains,
                lookup_elements,
                scope_ids: self.preprocessed_ids(),
                total_sum: self.claimed_sum,
            },
            self.claimed_sum,
        )
    }
}
