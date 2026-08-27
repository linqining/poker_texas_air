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
//! **Benchmark-scope simplification** (flagged for production): the LogUp
//! layer publishes each permutation's (initial, final) states and the
//! round constraints fully determine every intermediate value, but the
//! chain *boundary* binding — first state pinned to the scope tree, the
//! digest equality, and message absorption into the rate lanes — is not
//! yet selector-wired.  The AIR shape (columns/rows/LogUp/constraints) is
//! the real one; only that plumbing is pending.  Round constants are
//! deterministically generated below (splitmix-style PRG, fixed seed);
//! production must regenerate them (and re-check the internal matrix
//! coefficients) per the Poseidon2 paper's nothing-up-my-sleeve
//! procedure — the stwo reference example carries the same TODOs.

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

// ---------------------------------------------------------------------------
// LogUp relation and AIR.
// ---------------------------------------------------------------------------

relation!(Poseidon2State, N_STATE);

/// One transcript-chain batch statement: every chain starts at a public
/// initial state and applies `chain_length` permutations; the terminal
/// state is the chain digest (scope-pinned by the caller).
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct Poseidon2ChainSpec {
    /// Public initial states, one per chain.
    pub initial_states: Vec<[u32; N_STATE]>,
    /// Uniform chain length in permutations.
    pub chain_length: u32,
}

impl Poseidon2ChainSpec {
    /// Native chain evaluation: the terminal state of every chain.
    pub fn digests(&self) -> Vec<[u32; N_STATE]> {
        self.initial_states
            .iter()
            .map(|initial| {
                let mut state: [M31; N_STATE] =
                    std::array::from_fn(|i| M31::from_u32_unchecked(initial[i]));
                for _ in 0..self.chain_length as usize {
                    permute(&mut state);
                }
                std::array::from_fn(|i| state[i].0)
            })
            .collect()
    }
}

/// AIR of the permutation batch: each row carries
/// [`N_INSTANCES_PER_ROW`] whole permutations (442 columns each); the LogUp
/// relation publishes every (initial, final) state pair.
#[derive(Clone)]
pub struct Poseidon2Air {
    log_size: u32,
    lookup_elements: Poseidon2State,
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
        for _ in 0..N_INSTANCES_PER_ROW {
            let mut state: [_; N_STATE] = std::array::from_fn(|_| eval.next_trace_mask());
            let initial_state: [_; N_STATE] = state.clone();

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
    /// Preprocessed scope columns: each chain's initial state then digest,
    /// one column per state element, replicated over the segment rows.
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
    /// hold chains' permutations in order (chain-major); leftover slots
    /// carry zero-state padding permutations.
    pub(crate) fn build(spec: &Poseidon2ChainSpec) -> Self {
        let log_size = Self::log_size_for(spec);
        let rows = 1usize << log_size;
        let instance_slots = rows * N_INSTANCES_PER_ROW;
        let chains = spec.initial_states.len();
        let length = spec.chain_length as usize;

        // Every chain's running states so instance (chain, step) reads the
        // state after `step` permutations.
        let mut chain_states: Vec<Vec<[M31; N_STATE]>> = Vec::with_capacity(chains);
        for chain in 0..chains {
            let mut states = Vec::with_capacity(length + 1);
            let mut state: [M31; N_STATE] =
                std::array::from_fn(|i| M31::from_u32_unchecked(spec.initial_states[chain][i]));
            states.push(state);
            for _ in 0..length {
                permute(&mut state);
                states.push(state);
            }
            chain_states.push(states);
        }

        let mut columns: Vec<Vec<M31>> = vec![vec![M31::from(0u32); rows]; N_COLUMNS];
        for slot in 0..instance_slots {
            let row = slot / N_INSTANCES_PER_ROW;
            let rep = slot % N_INSTANCES_PER_ROW;
            let mut state: [M31; N_STATE] = if slot < chains * length {
                chain_states[slot / length][slot % length]
            } else {
                [M31::from(0u32); N_STATE]
            };
            let mut col = rep * N_COLUMNS_PER_REP;
            for value in state.iter() {
                columns[col][row] = *value;
                col += 1;
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
            .map(|states| std::array::from_fn(|i| states[length][i].0))
            .collect();
        let scope = Self::scope_trace(spec, &digests, log_size);
        let trace = MethodTrace::from_columns(log_size, columns);
        Self {
            log_size,
            scope,
            trace,
            interaction: Vec::new(),
            claimed_sum: SecureField::from(0u32),
            relations: None,
        }
    }

    fn scope_trace(
        spec: &Poseidon2ChainSpec,
        digests: &[[u32; N_STATE]],
        log_size: u32,
    ) -> MethodTrace {
        let rows = 1usize << log_size;
        let mut columns = Vec::with_capacity(2 * spec.initial_states.len() * N_STATE);
        for chain in 0..spec.initial_states.len() {
            for value in &spec.initial_states[chain] {
                columns.push(vec![M31::from_u32_unchecked(*value); rows]);
            }
            for value in &digests[chain] {
                columns.push(vec![M31::from_u32_unchecked(*value); rows]);
            }
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

    /// One LogUp column per instance slot; each row's entry batches the
    /// (initial, final) pair as `(d_final − d_initial)/(d_initial·d_final)`.
    fn gen_interaction(
        &self,
        lookup_elements: &Poseidon2State,
    ) -> (Vec<Poseidon2Eval>, SecureField) {
        use stwo::prover::backend::simd::m31::{LOG_N_LANES, N_LANES, PackedBaseField};
        use stwo::prover::backend::simd::qm31::PackedSecureField;

        let log_size = self.log_size;
        let vec_rows = 1usize << (log_size - LOG_N_LANES);
        let mut logup_gen = LogupTraceGenerator::new(log_size);
        for rep in 0..N_INSTANCES_PER_ROW {
            let base = rep * N_COLUMNS_PER_REP;
            let initial_cols: [usize; N_STATE] = std::array::from_fn(|i| base + i);
            // The last full round's x5 outputs: three columns per element
            // (x2, x4, x5), element-major, ending the instance block.
            let final_cols: [usize; N_STATE] =
                std::array::from_fn(|i| base + N_COLUMNS_PER_REP - 3 * N_STATE + 3 * i + 2);
            let mut col_gen = logup_gen.new_col();
            for vec_row in 0..vec_rows {
                let pack = |column_index: usize| -> PackedBaseField {
                    let mut values = [M31::from(0u32); N_LANES];
                    for (lane, value) in values.iter_mut().enumerate() {
                        let row = vec_row * N_LANES + lane;
                        *value = self.trace.cols[column_index][row];
                    }
                    PackedBaseField::from_array(values)
                };
                let initial: [PackedBaseField; N_STATE] =
                    std::array::from_fn(|i| pack(initial_cols[i]));
                let terminal: [PackedBaseField; N_STATE] =
                    std::array::from_fn(|i| pack(final_cols[i]));
                let denom0: PackedSecureField = lookup_elements.combine(&initial);
                let denom1: PackedSecureField = lookup_elements.combine(&terminal);
                col_gen.write_frac(vec_row, denom1 - denom0, denom0 * denom1);
            }
            col_gen.finalize_col();
        }
        logup_gen.finalize_last()
    }

    pub(crate) fn mirror_draw(&mut self, channel: &mut stwo::core::channel::Poseidon252Channel) {
        self.relations = Some(Poseidon2State::draw(channel));
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
                lookup_elements,
                total_sum: self.claimed_sum,
            },
            self.claimed_sum,
        )
    }
}
