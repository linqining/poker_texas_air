//! Poseidon252 chain AIR component — constraints, range tables, interaction
//! traces, and the prove/verify drivers over the native layer of
//! [`crate::poseidon252_air`].
//!
//! # Constraint system (one row per round, 91 rows per permutation)
//!
//! Scope columns (preprocessed tree, values fixed by the chain spec):
//! round position, round-type flag, the round's three key limbs, the two
//! absorbed word limbs, the three one-hot boundary selectors, the initial
//! state tuple and the void state tuple.  Witness columns carry every
//! big-integer intermediate of the emulated round:
//!
//! ```text
//! s_c = state_in + w + k                    (16-limb carry-add)
//! square: sq = s_c²                          (32-limb schoolbook mul)
//! gate:   x2 = is_full · sq, x2c = is_full · sqc   (lanes 0/1)
//! cube:   x3 = x2 · s_c                      (48-limb mul)
//! reduce: x3 = z + q·P                       (32-limb quotient)
//! post-sbox p = is_full·z + (1−is_full)·s_c  (lanes 0/1)
//! mix:    t = p0 + p1 + p2
//! lane0:  v = 2·p0 + t
//! lane1:  v = (t + 4P) − 2·p1                (borrow chain)
//! lane2:  v = (t + 6P) − 3·p2                (borrow chain)
//! out:    v = zm + qm·P                      (1-limb quotient)
//! next state = (zm0, zm1, zm2)
//! ```
//!
//! Three LogUp relations close the system: the 2^16 and 2^12 range tables
//! (witness limbs +1, table side −multiplicity) and the 49-limb state-chain
//! relation `(state ‖ position)` whose multiset balance forces the rounds
//! to chain in exact order from the initial boundary to the void boundary,
//! with the anchor row pinned to the void state limbs (the padding is the
//! identity sponge step, so void state == anchor state).
//!
//! # Binding and soundness
//!
//! Both sides mix `blake3(borsh(spec))` and the fixed range-table digest
//! into the Fiat–Shamir channel before the first commitment, so any scope
//! divergence shifts the channel and fails verification; the outer check
//! `claimed_anchor == native recomputation` ties the STARK to the public
//! root.  See [`crate::poseidon252_air`] for the arithmetic bounds that
//! keep every gadget's limb widths static and every subtraction
//! non-negative.

#![allow(missing_docs)]

use starknet_ff::FieldElement;
use stwo::core::channel::{Channel, Poseidon252Channel};
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::SecureField;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::proof::StarkProof;
use stwo::core::utils::bit_reverse_coset_to_circle_domain_order;
use stwo::core::vcs_lifted::poseidon252_merkle::{
    Poseidon252MerkleChannel, Poseidon252MerkleHasher,
};
use stwo::core::verifier::verify;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::backend::simd::m31::{LOG_N_LANES, PackedBaseField};
use stwo::prover::backend::simd::qm31::PackedSecureField;
use stwo::prover::pcs::CommitmentSchemeProver;
use stwo::core::poly::circle::CanonicCoset;
use stwo::prover::poly::circle::CircleEvaluation;
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::{ComponentProver, prove};
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use num_traits::One;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, LogupTraceGenerator, Relation, RelationEntry,
    TraceLocationAllocator, relation,
};

use bincode::Options as _;
use num_traits::Zero;

use crate::error::{TexasAirError, TexasAirResult};
use crate::poseidon252_air as native;

// ===========================================================================
// Relations
// ===========================================================================

relation!(P252Range16, 1);
relation!(P252Range12, 1);
relation!(P252ChainState, 49);
const _: () = assert!(native::STATE_TUPLE == 49, "state tuple arity mismatch");

fn scope_ids() -> &'static Vec<PreProcessedColumnId> {
    static IDS: std::sync::OnceLock<Vec<PreProcessedColumnId>> = std::sync::OnceLock::new();
    IDS.get_or_init(|| {
        let mut ids: Vec<PreProcessedColumnId> = (0..native::SCOPE_COLUMNS)
            .map(|index| PreProcessedColumnId {
                id: format!("poseidon252.air.v1.scope.{index}").into(),
            })
            .collect();
        ids.push(PreProcessedColumnId {
            id: "poseidon252.air.v1.range16.table".into(),
        });
        ids.push(PreProcessedColumnId {
            id: "poseidon252.air.v1.range12.table".into(),
        });
        ids
    })
}

// ===========================================================================
// Main round AIR
// ===========================================================================

#[derive(Clone)]
pub struct Poseidon252RoundAir {
    log_size: u32,
    range16: P252Range16,
    range12: P252Range12,
    state: P252ChainState,
}

fn next_scope<E: EvalAtRow>(eval: &mut E, cursor: &mut usize) -> E::F {
    let id = scope_ids()[*cursor].clone();
    *cursor += 1;
    eval.get_preprocessed_column(id)
}

fn read_cols<E: EvalAtRow>(eval: &mut E, n: usize) -> Vec<E::F> {
    (0..n).map(|_| eval.next_trace_mask()).collect()
}

impl FrameworkEval for Poseidon252RoundAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        use native as nl;
        let m = |v: u32| E::F::from(M31::from_u32_unchecked(v));
        let base = m(nl::BASE16);
        let zero = m(0);
        let one = m(1);
        let p16: Vec<u32> = native::P_LIMBS.iter().map(|&v| v as u32).collect();

        // ---- scope (preprocessed) ----
        let mut cursor = 0usize;
        let pos = next_scope(&mut eval, &mut cursor);
        let is_full = next_scope(&mut eval, &mut cursor);
        let k: Vec<Vec<E::F>> = (0..3)
            .map(|_| (0..nl::L).map(|_| next_scope(&mut eval, &mut cursor)).collect())
            .collect();
        let w: Vec<Vec<E::F>> = (0..2)
            .map(|_| (0..nl::L).map(|_| next_scope(&mut eval, &mut cursor)).collect())
            .collect();
        let sel_init = next_scope(&mut eval, &mut cursor);
        let sel_void = next_scope(&mut eval, &mut cursor);
        let sel_final = next_scope(&mut eval, &mut cursor);
        let init: Vec<E::F> =
            (0..nl::STATE_TUPLE).map(|_| next_scope(&mut eval, &mut cursor)).collect();
        let void_tuple: Vec<E::F> =
            (0..nl::STATE_TUPLE).map(|_| next_scope(&mut eval, &mut cursor)).collect();
        let anchor_limbs: Vec<E::F> =
            (0..3 * nl::L).map(|_| next_scope(&mut eval, &mut cursor)).collect();

        // ---- witness (fixed layout order) ----
        let state_in: Vec<Vec<E::F>> = (0..3).map(|_| read_cols(&mut eval, nl::L)).collect();
        // builder order is interleaved per lane: out, carry, out, carry, …
        let mut abs_out: Vec<Vec<E::F>> = vec![Vec::new(); 3];
        let mut abs_carry: Vec<Vec<E::F>> = vec![Vec::new(); 3];
        for lane in 0..3 {
            abs_out[lane] = read_cols(&mut eval, nl::L);
            abs_carry[lane] = read_cols(&mut eval, nl::L);
        }
        // builder order is per-lane: (sq, sqc)? x2, x2c, x3, x3c, q, qc, z, (p)?
        let mut sq: Vec<Vec<E::F>> = vec![Vec::new(); 2];
        let mut sqc: Vec<Vec<E::F>> = vec![Vec::new(); 2];
        let mut x2: Vec<Vec<E::F>> = vec![Vec::new(); 3];
        let mut x2c: Vec<Vec<E::F>> = vec![Vec::new(); 3];
        let mut x3: Vec<Vec<E::F>> = vec![Vec::new(); 3];
        let mut x3c: Vec<Vec<E::F>> = vec![Vec::new(); 3];
        let mut q: Vec<Vec<E::F>> = vec![Vec::new(); 3];
        let mut qc: Vec<Vec<E::F>> = vec![Vec::new(); 3];
        let mut z: Vec<Vec<E::F>> = vec![Vec::new(); 3];
        let mut p: Vec<Vec<E::F>> = vec![Vec::new(); 2];
        for lane in 0..3 {
            if lane < 2 {
                sq[lane] = read_cols(&mut eval, 2 * nl::L);
                sqc[lane] = read_cols(&mut eval, 2 * nl::L - 1);
            }
            x2[lane] = read_cols(&mut eval, 2 * nl::L);
            x2c[lane] = read_cols(&mut eval, 2 * nl::L - 1);
            x3[lane] = read_cols(&mut eval, 3 * nl::L);
            x3c[lane] = read_cols(&mut eval, 3 * nl::L - 1);
            q[lane] = read_cols(&mut eval, 2 * nl::L);
            qc[lane] = read_cols(&mut eval, 3 * nl::L - 1);
            z[lane] = read_cols(&mut eval, nl::L);
            if lane < 2 {
                p[lane] = read_cols(&mut eval, nl::L);
            }
        }
        let t = read_cols(&mut eval, nl::L);
        let tc = read_cols(&mut eval, nl::L);
        let mix0 = read_cols(&mut eval, nl::MIX0_WIDTH);
        let mix1 = read_cols(&mut eval, nl::MIX12_WIDTH);
        let mix2 = read_cols(&mut eval, nl::MIX12_WIDTH);
        let mix = vec![mix0, mix1, mix2];
        let pos_next = eval.next_trace_mask();
        let is_wrap = eval.next_trace_mask();

        // Resolve any witness column (layout order) to its constraint value.
        let value_at = |col: usize| -> E::F {
            for lane in 0..3 {
                let lo = nl::W_STATE_IN + lane * nl::L;
                if col >= lo && col < lo + nl::L {
                    return state_in[lane][col - lo].clone();
                }
                let lo = nl::w_abs_out(lane);
                if col >= lo && col < lo + nl::L {
                    return abs_out[lane][col - lo].clone();
                }
                let lo = nl::w_x2(lane);
                if col >= lo && col < lo + 2 * nl::L {
                    return x2[lane][col - lo].clone();
                }
                let lo = nl::w_x2c(lane);
                if col >= lo && col < lo + 2 * nl::L - 1 {
                    return x2c[lane][col - lo].clone();
                }
                let lo = nl::w_x3(lane);
                if col >= lo && col < lo + 3 * nl::L {
                    return x3[lane][col - lo].clone();
                }
                let lo = nl::w_x3c(lane);
                if col >= lo && col < lo + 3 * nl::L - 1 {
                    return x3c[lane][col - lo].clone();
                }
                let lo = nl::w_q(lane);
                if col >= lo && col < lo + 2 * nl::L {
                    return q[lane][col - lo].clone();
                }
                let lo = nl::w_z(lane);
                if col >= lo && col < lo + nl::L {
                    return z[lane][col - lo].clone();
                }
            }
            for lane in 0..2 {
                let lo = nl::w_sq(lane);
                if col >= lo && col < lo + 2 * nl::L {
                    return sq[lane][col - lo].clone();
                }
                let lo = nl::w_sqc(lane);
                if col >= lo && col < lo + 2 * nl::L - 1 {
                    return sqc[lane][col - lo].clone();
                }
                let lo = nl::w_p(lane);
                if col >= lo && col < lo + nl::L {
                    return p[lane][col - lo].clone();
                }
            }
            let lo = nl::w_t();
            if col >= lo && col < lo + nl::L {
                return t[col - lo].clone();
            }
            for lane in 0..3 {
                let lo = nl::w_mix(lane);
                let width = if lane == 0 { nl::MIX0_WIDTH } else { nl::MIX12_WIDTH };
                if col >= lo && col < lo + width {
                    return mix[lane][col - lo].clone();
                }
            }
            if col == nl::W_POS_NEXT {
                return pos_next.clone();
            }
            if col == nl::W_IS_WRAP {
                return is_wrap.clone();
            }
            panic!("column {col} is not part of the poseidon252 witness layout");
        };

        let range_values: Vec<E::F> =
            nl::range_use_columns().iter().map(|&col| value_at(col)).collect();
        let bound_values: Vec<E::F> =
            nl::bound12_columns().iter().map(|&col| value_at(col)).collect();

        // =================================================================
        // Constraints
        // =================================================================

        // ---- absorb + round constant: s_c = state_in + w + k ----
        let zeros_limb = || m(0);
        let _ = zeros_limb;
        for lane in 0..3 {
            for i in 0..nl::L {
                let absorbed = if lane == 2 {
                    zero.clone()
                } else {
                    w[lane][i].clone()
                };
                let mut acc = state_in[lane][i].clone() + absorbed + k[lane][i].clone();
                if i > 0 {
                    acc = acc + abs_carry[lane][i - 1].clone();
                }
                let rhs = abs_out[lane][i].clone() + base.clone() * abs_carry[lane][i].clone();
                eval.add_constraint(acc - rhs);
            }
            eval.add_constraint(abs_carry[lane][nl::L - 1].clone());
        }

        // ---- squares: sq = s_c² (lanes 0/1) or x2 = s_c² (lane 2) ----
        for lane in 0..3 {
            let (src, src_carry): (&Vec<E::F>, &Vec<E::F>) = if lane < 2 {
                (&sq[lane], &sqc[lane])
            } else {
                (&x2[lane], &x2c[lane])
            };
            for kk in 0..2 * nl::L {
                let mut term = if kk == 0 { zero.clone() } else { src_carry[kk - 1].clone() };
                for i in 0..nl::L.min(kk + 1) {
                    let j = kk - i;
                    if j < nl::L {
                        term = term + abs_out[lane][i].clone() * abs_out[lane][j].clone();
                    }
                }
                if kk < 2 * nl::L - 1 {
                    let rhs = src[kk].clone() + base.clone() * src_carry[kk].clone();
                    eval.add_constraint(term - rhs);
                } else {
                    eval.add_constraint(src[kk].clone() - term);
                }
            }
        }
        // gate: x2 = is_full·sq on lanes 0/1
        for lane in 0..2 {
            for i in 0..2 * nl::L {
                eval.add_constraint(
                    x2[lane][i].clone() - is_full.clone() * sq[lane][i].clone(),
                );
            }
            for i in 0..2 * nl::L - 1 {
                eval.add_constraint(
                    x2c[lane][i].clone() - is_full.clone() * sqc[lane][i].clone(),
                );
            }
        }

        // ---- cubes: x3 = x2 · s_c ----
        for lane in 0..3 {
            for kk in 0..3 * nl::L {
                let mut term = if kk == 0 { zero.clone() } else { x3c[lane][kk - 1].clone() };
                for i in 0..(2 * nl::L).min(kk + 1) {
                    let j = kk - i;
                    if j < nl::L {
                        term = term + x2[lane][i].clone() * abs_out[lane][j].clone();
                    }
                }
                if kk < 3 * nl::L - 1 {
                    let rhs = x3[lane][kk].clone() + base.clone() * x3c[lane][kk].clone();
                    eval.add_constraint(term - rhs);
                } else {
                    eval.add_constraint(x3[lane][kk].clone() - term);
                }
            }
        }

        // ---- s-box reductions: x3 = z + q·P (carry chain in qc) ----
        for lane in 0..3 {
            for kk in 0..3 * nl::L {
                let mut term = if kk == 0 { zero.clone() } else { qc[lane][kk - 1].clone() };
                if kk < nl::L {
                    term = term + z[lane][kk].clone();
                }
                for i in 0..(2 * nl::L).min(kk + 1) {
                    let j = kk - i;
                    if j < nl::L {
                        term = term + q[lane][i].clone() * m(p16[j]);
                    }
                }
                if kk < 3 * nl::L - 1 {
                    let rhs = x3[lane][kk].clone() + base.clone() * qc[lane][kk].clone();
                    eval.add_constraint(term - rhs);
                } else {
                    eval.add_constraint(x3[lane][kk].clone() - term);
                }
            }
        }

        // ---- gated post-sbox value: p = is_full·z + (1−is_full)·s_c ----
        for lane in 0..2 {
            for i in 0..nl::L {
                let gated = p[lane][i].clone()
                    - is_full.clone() * z[lane][i].clone()
                    - (one.clone() - is_full.clone()) * abs_out[lane][i].clone();
                eval.add_constraint(gated);
            }
        }

        // ---- mix: t = p0 + p1 + p2 (= z2) ----
        for i in 0..nl::L {
            let mut acc = p[0][i].clone() + p[1][i].clone() + z[2][i].clone();
            if i > 0 {
                acc = acc + tc[i - 1].clone();
            }
            let rhs = t[i].clone() + base.clone() * tc[i].clone();
            eval.add_constraint(acc - rhs);
        }
        eval.add_constraint(tc[nl::L - 1].clone());

        // ---- mix lanes ----
        let p4 = native::p_multiple(4);
        let p6 = native::p_multiple(6);
        for lane in 0..3 {
            // relative offsets inside the lane block
            let (u_off, v_off, rc_off, bw_off, qm_off, zm_off) = if lane == 0 {
                (0usize, 2 * nl::L, 4 * nl::L, 0usize, 5 * nl::L, 5 * nl::L + 1)
            } else {
                (2 * nl::L, 4 * nl::L, 6 * nl::L, 7 * nl::L, 8 * nl::L, 8 * nl::L + 1)
            };
            let d = |i: usize| -> E::F { mix[lane][i].clone() };
            let dc = |i: usize| -> E::F { mix[lane][nl::L + i].clone() };
            let u = |i: usize| -> E::F {
                if lane == 0 {
                    t[i].clone()
                } else {
                    mix[lane][u_off + i].clone()
                }
            };
            let uc = |i: usize| -> E::F {
                if lane == 0 {
                    tc[i].clone()
                } else {
                    mix[lane][u_off + nl::L + i].clone()
                }
            };
            let v = |i: usize| -> E::F { mix[lane][v_off + i].clone() };
            let vc = |i: usize| -> E::F { mix[lane][v_off + nl::L + i].clone() };
            let rc = |i: usize| -> E::F { mix[lane][rc_off + i].clone() };
            let bw = |i: usize| -> E::F { mix[lane][bw_off + i].clone() };
            let qm = || -> E::F { mix[lane][qm_off].clone() };
            let zm = |i: usize| -> E::F { mix[lane][zm_off + i].clone() };
            let _ = (&d, &dc, &u, &uc, &v, &vc, &rc, &bw, &qm, &zm);

            // d = coeff · source
            let coeff: u32 = if lane == 2 { 3 } else { 2 };
            let source = |i: usize| -> E::F {
                if lane < 2 {
                    p[lane][i].clone()
                } else {
                    z[2][i].clone()
                }
            };
            for i in 0..nl::L {
                let mut acc = source(i) * m(coeff);
                if i > 0 {
                    acc = acc + dc(i - 1);
                }
                let rhs = d(i) + base.clone() * dc(i);
                eval.add_constraint(acc - rhs);
            }
            eval.add_constraint(dc(nl::L - 1));

            if lane == 0 {
                // v = d + t
                for i in 0..nl::L {
                    let mut acc = d(i) + t[i].clone();
                    if i > 0 {
                        acc = acc + vc(i - 1);
                    }
                    let rhs = v(i) + base.clone() * vc(i);
                    eval.add_constraint(acc - rhs);
                }
                eval.add_constraint(vc(nl::L - 1));
            } else {
                // u = t + m·P
                let multiple = if lane == 1 { &p4 } else { &p6 };
                for i in 0..nl::L {
                    let mut acc = t[i].clone() + m(multiple[i] as u32);
                    if i > 0 {
                        acc = acc + uc(i - 1);
                    }
                    let rhs = u(i) + base.clone() * uc(i);
                    eval.add_constraint(acc - rhs);
                }
                eval.add_constraint(uc(nl::L - 1));
                // v = u − d (borrow chain)
            for i in 0..nl::L {
                let mut acc = u(i) - d(i);
                if i > 0 {
                    acc = acc - bw(i - 1);
                }
                acc = acc + base.clone() * bw(i);
                eval.add_constraint(acc - v(i));
            }
            eval.add_constraint(bw(nl::L - 1));
            }

            // v = zm + qm·P
            for kk in 0..nl::L {
                let mut term = zm(kk) + qm() * m(p16[kk]);
                if kk > 0 {
                    term = term + rc(kk - 1);
                }
                if kk < nl::L - 1 {
                    let rhs = v(kk) + base.clone() * rc(kk);
                    eval.add_constraint(term - rhs);
                } else {
                    eval.add_constraint(term - v(kk));
                }
            }
            eval.add_constraint(rc(nl::L - 1));
        }

        // ---- round position recurrence ----
        // pos_next = pos + 1 − 91·is_wrap, is_wrap boolean.
        let rec =
            pos_next.clone() - pos.clone() - one.clone() + m(native::ROUND_COUNT as u32) * is_wrap.clone();
        eval.add_constraint(rec);
        eval.add_constraint(is_wrap.clone() * (is_wrap.clone() - one.clone()));

        // ---- boundary pinning ----
        // Row 0: state_in equals the initial state.  Last real row:
        // state_out equals the void state limbs (= the anchor limbs).
        let mut in_tuple: Vec<E::F> = Vec::with_capacity(native::STATE_TUPLE);
        for lane in 0..3 {
            in_tuple.extend(state_in[lane].iter().cloned());
        }
        in_tuple.push(pos.clone());
        let mut out_tuple: Vec<E::F> = Vec::with_capacity(native::STATE_TUPLE);
        for lane in 0..3 {
            let zm_off = nl::w_mix_zm(lane) - nl::w_mix(lane);
            out_tuple.extend(mix[lane][zm_off..zm_off + nl::L].iter().cloned());
        }
        out_tuple.push(pos_next.clone());

        for i in 0..3 * nl::L {
            eval.add_constraint(sel_init.clone() * (in_tuple[i].clone() - init[i].clone()));
            eval.add_constraint(
                sel_final.clone() * (out_tuple[i].clone() - anchor_limbs[i].clone()),
            );
        }

        // ---- LogUp entries (fixed order; paired by finalize_logup_in_pairs)
        // ----
        for value in &range_values {
            eval.add_to_relation(RelationEntry::new(&self.range16, E::EF::one(), &[value.clone()]));
        }
        for value in &bound_values {
            eval.add_to_relation(RelationEntry::new(&self.range12, E::EF::one(), &[value.clone()]));
        }
        eval.add_to_relation(RelationEntry::new(&self.state, -E::EF::one(), &in_tuple));
        eval.add_to_relation(RelationEntry::new(&self.state, E::EF::one(), &out_tuple));
        eval.add_to_relation(RelationEntry::new(
            &self.state,
            E::EF::from(sel_init.clone()),
            &init,
        ));
        eval.add_to_relation(RelationEntry::new(
            &self.state,
            -E::EF::from(sel_void.clone()),
            &void_tuple,
        ));
        eval.finalize_logup_in_pairs();
        eval
    }
}

// ===========================================================================
// Range table AIRs
// ===========================================================================

#[derive(Clone)]
pub struct Poseidon252RangeTableAir {
    log_size: u32,
    column: usize,
    range16: P252Range16,
    range12: P252Range12,
}

impl Poseidon252RangeTableAir {
    pub fn range16(log_size: u32, range16: P252Range16, range12: P252Range12) -> Self {
        Self {
            log_size,
            column: native::TABLE16_COLUMN,
            range16,
            range12,
        }
    }

    pub fn range12(log_size: u32, range16: P252Range16, range12: P252Range12) -> Self {
        Self {
            log_size,
            column: native::TABLE12_COLUMN,
            range16,
            range12,
        }
    }
}

impl FrameworkEval for Poseidon252RangeTableAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let ids = scope_ids();
        let value = eval.get_preprocessed_column(ids[self.column].clone());
        let multiplicity = eval.next_trace_mask();
        if self.column == native::TABLE16_COLUMN {
            eval.add_to_relation(RelationEntry::new(
                &self.range16,
                -E::EF::from(multiplicity),
                &[value],
            ));
        } else {
            eval.add_to_relation(RelationEntry::new(
                &self.range12,
                -E::EF::from(multiplicity),
                &[value],
            ));
        }
        eval.finalize_logup_in_pairs();
        eval
    }
}

// ===========================================================================
// Prove / verify
// ===========================================================================

pub const POSEIDON252_RANGE_DOMAIN: &[u8] = b"zchain.poseidon252.air.v1.range-tables";

/// Proof archive for one chain statement.
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct ArchivedPoseidon252ChainProof {
    pub spec: native::Poseidon252ChainSpec,
    pub log_size: u32,
    /// Full terminal sponge state (checked against the native recomputation).
    pub claimed_anchor: [[u8; 32]; 3],
    /// The three claimed LogUp sums (main, table16, table12) as QM31
    /// coordinate words.
    pub logup_sums: [[u32; 4]; 3],
    pub stark_proof_bytes: Vec<u8>,
}

fn range_tables_digest() -> [u8; 32] {
    crate::blake3_flock::blake3_chain_digest(POSEIDON252_RANGE_DOMAIN)
}

fn mix_digest(channel: &mut Poseidon252Channel, digest: &[u8; 32]) {
    channel.mix_u32s(
        &digest
            .chunks_exact(4)
            .map(|x| u32::from_be_bytes(x.try_into().expect("digest word")))
            .collect::<Vec<_>>(),
    );
}

fn secure_to_words(value: SecureField) -> [u32; 4] {
    let [a, b, c, d] = value.to_m31_array();
    [a.0, b.0, c.0, d.0]
}

fn words_to_secure(words: [u32; 4]) -> SecureField {
    SecureField::from_m31_array([
        M31::from(words[0]),
        M31::from(words[1]),
        M31::from(words[2]),
        M31::from(words[3]),
    ])
}

fn pcs_config(_log_size: u32) -> PcsConfig {
    // Blowup 1 as in the official cairo prover.  The lifting domain is
    // pinned explicitly (max constraint bound = table16 log + 1, plus the
    // blowup bit) so the prover and verifier derive the identical FRI
    // first-layer commitment; leaving it `None` lets the two sides pick
    // different derived values across the mixed log-size trees and fails
    // verification with a first-layer root mismatch.
    let lifting = native::TABLE16_LOG + 1 + 1;
    PcsConfig {
        pow_bits: 10,
        fri_config: FriConfig::new(0, 1, 30, 1),
        lifting_log_size: Some(lifting),
    }
}

fn column_eval(
    log_size: u32,
    column: &[M31],
) -> CircleEvaluation<SimdBackend, M31, BitReversedOrder> {
    let domain = CanonicCoset::new(log_size).circle_domain();
    CircleEvaluation::new(domain, BaseColumn::from_iter(column.iter().copied()))
}

fn range_table_column_values(log_size: u32) -> Vec<M31> {
    // the value column in bit-reversed circle-domain order, matching every
    // other committed column
    let mut values: Vec<M31> = (0..1usize << log_size).map(|i| M31::from(i as u32)).collect();
    stwo::core::utils::bit_reverse_coset_to_circle_domain_order(&mut values);
    values
}

/// Prove the chain statement.
pub fn prove_poseidon252_chain(
    spec: &native::Poseidon252ChainSpec,
) -> TexasAirResult<ArchivedPoseidon252ChainProof> {
    spec.validate()?;
    let mut trace = native::build_chain_trace(spec)?;
    let log_size = trace.log_size;
    let max_log = native::TABLE16_LOG.max(log_size);
    // Stwo's mask offsets and LogUp prefix sums operate in bit-reversed
    // circle-domain order; convert the honest (coset-ordered) trace once at
    // the boundary, exactly like the Blake2b lookup components.
    for column in trace.scope.iter_mut().chain(trace.witness.iter_mut()) {
        bit_reverse_coset_to_circle_domain_order(column);
    }
    for mult in [&mut trace.multiplicities16, &mut trace.multiplicities12] {
        let mut cast: Vec<M31> = mult.iter().map(|&v| M31::from(v)).collect();
        bit_reverse_coset_to_circle_domain_order(&mut cast);
        *mult = cast.into_iter().map(|m| m.0).collect::<Vec<u32>>();
    }
    let config = pcs_config(log_size);
    let twiddles = crate::prover_context::simd_twiddles(
        max_log + 1 + config.fri_config.log_blowup_factor,
    );

    let mut channel = Poseidon252Channel::default();
    mix_digest(&mut channel, &spec.statement_digest());
    mix_digest(&mut channel, &range_tables_digest());

    let mut scheme =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::new(config, &twiddles);
    // Match the Blake2b component setup: with coefficients stored, committed
    // columns evaluate at the OODS points through their coefficients instead
    // of the barycentric-weights fallback.
    scheme.set_store_polynomials_coefficients();
    {
        let mut tree = scheme.tree_builder();
        for column in &trace.scope {
            tree.extend_evals(vec![column_eval(log_size, column)]);
        }
        tree.extend_evals(vec![column_eval(
            native::TABLE16_LOG,
            &range_table_column_values(native::TABLE16_LOG),
        )]);
        tree.extend_evals(vec![column_eval(
            native::TABLE12_LOG,
            &range_table_column_values(native::TABLE12_LOG),
        )]);
        tree.commit(&mut channel);
    }
    {
        let mut tree = scheme.tree_builder();
        for column in &trace.witness {
            tree.extend_evals(vec![column_eval(log_size, column)]);
        }
        tree.extend_evals(vec![column_eval(
            native::TABLE16_LOG,
            &trace
                .multiplicities16
                .iter()
                .map(|&v| M31::from(v))
                .collect::<Vec<_>>(),
        )]);
        tree.extend_evals(vec![column_eval(
            native::TABLE12_LOG,
            &trace
                .multiplicities12
                .iter()
                .map(|&v| M31::from(v))
                .collect::<Vec<_>>(),
        )]);
        tree.commit(&mut channel);
    }

    let range16 = P252Range16::draw(&mut channel);
    let range12 = P252Range12::draw(&mut channel);
    let state = P252ChainState::draw(&mut channel);

    let (main_interaction, main_sum) =
        main_interaction_trace(&trace, &range16, &range12, &state);
    let (table16_interaction, table16_sum) = table_interaction_trace(
        native::TABLE16_LOG,
        &range_table_column_values(native::TABLE16_LOG),
        &trace.multiplicities16,
        &range16,
    );
    let (table12_interaction, table12_sum) = table_interaction_trace(
        native::TABLE12_LOG,
        &range_table_column_values(native::TABLE12_LOG),
        &trace.multiplicities12,
        &range12,
    );
    assert_eq!(
        main_sum + table16_sum + table12_sum,
        SecureField::from(0u32),
        "logup balance across components"
    );
    channel.mix_felts(&[main_sum, table16_sum, table12_sum]);
    {
        let mut tree = scheme.tree_builder();
        tree.extend_evals(
            main_interaction
                .into_iter()
                .chain(table16_interaction)
                .chain(table12_interaction)
                .collect::<Vec<_>>(),
        );
        tree.commit(&mut channel);
    }
    let ids = scope_ids();
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
    let main_component = FrameworkComponent::new(
        &mut allocator,
        Poseidon252RoundAir {
            log_size,
            range16: range16.clone(),
            range12: range12.clone(),
            state: state.clone(),
        },
        main_sum,
    );
    let table16_component = FrameworkComponent::new(
        &mut allocator,
        Poseidon252RangeTableAir::range16(log_size, range16.clone(), range12.clone()),
        table16_sum,
    );
    let table12_component = FrameworkComponent::new(
        &mut allocator,
        Poseidon252RangeTableAir::range12(log_size, range16.clone(), range12),
        table12_sum,
    );

    let proof = prove(
        &[
            &main_component as &dyn ComponentProver<SimdBackend>,
            &table16_component as &dyn ComponentProver<SimdBackend>,
            &table12_component as &dyn ComponentProver<SimdBackend>,
        ],
        &mut channel,
        scheme,
    )
    .map_err(|e| TexasAirError::SpecViolation(format!("poseidon252 chain prove failed: {e:?}")))?;

    let claimed_anchor = spec
        .anchor_state()
        .iter()
        .map(|f| f.to_bytes_be())
        .collect::<Vec<_>>()
        .try_into()
        .expect("3 felts");

    Ok(ArchivedPoseidon252ChainProof {
        spec: spec.clone(),
        log_size,
        claimed_anchor,
        logup_sums: [
            secure_to_words(main_sum),
            secure_to_words(table16_sum),
            secure_to_words(table12_sum),
        ],
        stark_proof_bytes: bincode::options()
            .with_fixint_encoding()
            .with_limit(1024 * 1024 * 1024)
            .serialize(&proof)
            .map_err(|e| TexasAirError::SerializationError(e.to_string()))?,
    })
}

/// Verify the chain statement against the public spec.
pub fn verify_poseidon252_chain(archive: &ArchivedPoseidon252ChainProof) -> TexasAirResult<()> {
    archive.spec.validate()?;
    let layout = archive.spec.layout();
    if layout.log_size != archive.log_size {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "poseidon252 chain log size is detached from the spec layout".into(),
        ));
    }
    let native_anchor = archive.spec.anchor_state();
    for (lane, felt) in native_anchor.iter().enumerate() {
        if archive.claimed_anchor[lane] != felt.to_bytes_be() {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "poseidon252 chain anchor is detached from the native recomputation".into(),
            ));
        }
    }

    let log_size = archive.log_size;
    let config = pcs_config(log_size);
    let proof: StarkProof<Poseidon252MerkleHasher> =
        bincode::options()
            .with_fixint_encoding()
            .with_limit(1024 * 1024 * 1024)
            .deserialize(&archive.stark_proof_bytes)
            .map_err(|e| TexasAirError::SerializationError(e.to_string()))?;

    let mut channel = Poseidon252Channel::default();
    mix_digest(&mut channel, &archive.spec.statement_digest());
    mix_digest(&mut channel, &range_tables_digest());

    let mut verifier = CommitmentSchemeVerifier::<Poseidon252MerkleChannel>::new(config);
    let mut preprocessed_log_sizes =
        vec![log_size; native::SCOPE_COLUMNS];
    preprocessed_log_sizes.push(native::TABLE16_LOG);
    preprocessed_log_sizes.push(native::TABLE12_LOG);
    verifier.commit(proof.commitments[0], &preprocessed_log_sizes, &mut channel);
    let mut witness_log_sizes = vec![log_size; native::WITNESS_COLUMNS];
    witness_log_sizes.push(native::TABLE16_LOG);
    witness_log_sizes.push(native::TABLE12_LOG);
    verifier.commit(proof.commitments[1], &witness_log_sizes, &mut channel);

    let range16 = P252Range16::draw(&mut channel);
    let range12 = P252Range12::draw(&mut channel);
    let state = P252ChainState::draw(&mut channel);

    let main_sum = words_to_secure(archive.logup_sums[0]);
    let table16_sum = words_to_secure(archive.logup_sums[1]);
    let table12_sum = words_to_secure(archive.logup_sums[2]);
    if main_sum + table16_sum + table12_sum != SecureField::from(0u32) {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "poseidon252 chain logup sums do not balance".into(),
        ));
    }
    channel.mix_felts(&[main_sum, table16_sum, table12_sum]);
    let mut interaction_log_sizes =
        vec![log_size; native::main_interaction_columns() * 4];
    interaction_log_sizes.extend(vec![native::TABLE16_LOG; 4]);
    interaction_log_sizes.extend(vec![native::TABLE12_LOG; 4]);
    verifier.commit(proof.commitments[2], &interaction_log_sizes, &mut channel);

    let ids = scope_ids();
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
    let main_component = FrameworkComponent::new(
        &mut allocator,
        Poseidon252RoundAir {
            log_size,
            range16: range16.clone(),
            range12: range12.clone(),
            state: state.clone(),
        },
        main_sum,
    );
    let table16_component = FrameworkComponent::new(
        &mut allocator,
        Poseidon252RangeTableAir::range16(log_size, range16.clone(), range12.clone()),
        table16_sum,
    );
    let table12_component = FrameworkComponent::new(
        &mut allocator,
        Poseidon252RangeTableAir::range12(log_size, range16, range12),
        table12_sum,
    );

    verify(
        &[
            &main_component as &dyn stwo::core::air::Component,
            &table16_component as &dyn stwo::core::air::Component,
            &table12_component as &dyn stwo::core::air::Component,
        ],
        &mut channel,
        &mut verifier,
        proof,
    )
    .map_err(|e| {
        TexasAirError::ConstraintUnsatisfied(format!(
            "poseidon252 chain STARK verification failed: {e:?}"
        ))
    })
}

// ===========================================================================
// Interaction traces
// ===========================================================================

type PackedEval = CircleEvaluation<SimdBackend, M31, BitReversedOrder>;

fn main_interaction_trace(
    trace: &native::Poseidon252Trace,
    range16: &P252Range16,
    range12: &P252Range12,
    state: &P252ChainState,
) -> (Vec<PackedEval>, SecureField) {
    let log_size = trace.log_size;
    let vec_rows = 1usize << (log_size - LOG_N_LANES);
    let layout = native::entry_layout();

    let scope_cols: Vec<BaseColumn> = trace
        .scope
        .iter()
        .map(|column| BaseColumn::from_iter(column.iter().copied()))
        .collect();
    let witness_cols: Vec<BaseColumn> = trace
        .witness
        .iter()
        .map(|column| BaseColumn::from_iter(column.iter().copied()))
        .collect();

    // An entry resolves to (packed multiplicity, packed coordinates,
    // relation id).
    let entry = |kind: &native::EntryKind,
                 vec_row: usize|
     -> (PackedSecureField, Vec<PackedBaseField>, usize) {
        use native::EntryKind::*;
        match *kind {
            Range16(col) => (
                PackedSecureField::one(),
                vec![witness_cols[col].data[vec_row]],
                0,
            ),
            Range12(col) => (
                PackedSecureField::one(),
                vec![witness_cols[col].data[vec_row]],
                1,
            ),
            StateIn => {
                let mut coords = Vec::with_capacity(native::STATE_TUPLE);
                for lane in 0..3 {
                    let base = native::W_STATE_IN + lane * native::L;
                    for i in 0..native::L {
                        coords.push(witness_cols[base + i].data[vec_row]);
                    }
                }
                coords.push(scope_cols[native::S_POS].data[vec_row]);
                (-PackedSecureField::one(), coords, 2)
            }
            StateOut => {
                let mut coords = Vec::with_capacity(native::STATE_TUPLE);
                for lane in 0..3 {
                    let base = native::w_mix_zm(lane);
                    for i in 0..native::L {
                        coords.push(witness_cols[base + i].data[vec_row]);
                    }
                }
                coords.push(witness_cols[native::W_POS_NEXT].data[vec_row]);
                (PackedSecureField::one(), coords, 2)
            }
            Init => {
                let mut coords = Vec::with_capacity(native::STATE_TUPLE);
                for i in 0..native::STATE_TUPLE {
                    coords.push(scope_cols[native::S_INIT + i].data[vec_row]);
                }
                (
                    PackedSecureField::from(scope_cols[native::S_SEL].data[vec_row]),
                    coords,
                    2,
                )
            }
            Void => {
                let mut coords = Vec::with_capacity(native::STATE_TUPLE);
                for i in 0..native::STATE_TUPLE {
                    coords.push(scope_cols[native::S_VOID + i].data[vec_row]);
                }
                (
                    -PackedSecureField::from(scope_cols[native::S_SEL + 1].data[vec_row]),
                    coords,
                    2,
                )
            }
        }
    };

    let n_entries = layout.len();
    let mut logup_gen = LogupTraceGenerator::new(log_size);
    for batch in 0..n_entries.div_ceil(2) {
        let mut col_gen = logup_gen.new_col();
        for vec_row in 0..vec_rows {
            // paired fraction: m1/d1 + m2/d2 = (m1·d2 + m2·d1) / (d1·d2) —
            // the batch's OWN fraction; the generator's finalize_col adds the
            // previous column's running sum itself.
            let mut num_acc: Option<PackedSecureField> = None;
            let mut den_acc: Option<PackedSecureField> = None;
            for entry_index in [batch * 2, batch * 2 + 1] {
                if entry_index >= n_entries {
                    continue;
                }
                let (mult, coords, relation_id) = entry(&layout[entry_index], vec_row);
                let denom: PackedSecureField = match relation_id {
                    0 => range16.combine(&coords),
                    1 => range12.combine(&coords),
                    _ => state.combine(&coords),
                };
                // pair accumulation: after entry 1, (num, den) = (m1, d1);
                // after entry 2, (num, den) = (m1·d2 + m2·d1, d1·d2).
                num_acc = Some(match num_acc {
                    None => mult,
                    Some(prev) => prev * denom.clone() + mult * den_acc.clone().unwrap(),
                });
                den_acc = Some(match den_acc {
                    None => denom,
                    Some(prev) => prev * denom,
                });
            }
            col_gen.write_frac(
                vec_row,
                num_acc.unwrap_or_else(PackedSecureField::zero),
                den_acc.unwrap_or_else(PackedSecureField::one),
            );
        }
        col_gen.finalize_col();
    }
    logup_gen.finalize_last()
}

fn table_interaction_trace(
    table_log: u32,
    value_column: &[M31],
    multiplicities: &[u32],
    elements: &impl Relation<PackedBaseField, PackedSecureField>,
) -> (Vec<PackedEval>, SecureField) {
    let value = BaseColumn::from_iter(value_column.iter().copied());
    let mult = BaseColumn::from_iter(multiplicities.iter().map(|&v| M31::from(v)));
    let vec_rows = 1usize << (table_log - LOG_N_LANES);
    let mut logup_gen = LogupTraceGenerator::new(table_log);
    let mut col_gen = logup_gen.new_col();
    for vec_row in 0..vec_rows {
        let denom: PackedSecureField = elements.combine(&[value.data[vec_row]]);
        let numer = -PackedSecureField::from(mult.data[vec_row]);
        col_gen.write_frac(vec_row, numer, denom);
    }
    col_gen.finalize_col();
    logup_gen.finalize_last()
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use native::Poseidon252ChainSpec;

    fn small_spec() -> Poseidon252ChainSpec {
        // 2 message felts → 2 permutations → 182 rows → log 8.
        let message = [FieldElement::from(7u64), FieldElement::from(9u64)];
        Poseidon252ChainSpec::hash_many(&message)
    }

    #[test]
    #[ignore = "superseded by poseidon252_v2 (cairo-air-style decomposition)"]
    fn chain_proof_roundtrip() {
        let spec = small_spec();
        let archive = prove_poseidon252_chain(&spec).expect("prove");
        verify_poseidon252_chain(&archive).expect("verify");
    }

    #[test]
    fn interaction_matches_naive_fractions() {
        use stwo::core::fields::m31::M31;
        use stwo::prover::backend::simd::column::BaseColumn;
        use stwo_constraint_framework::LogupTraceGenerator;
        let spec = small_spec();
        let trace = native::build_chain_trace(&spec).unwrap();
        let log_size = trace.log_size;
        let mut channel = Poseidon252Channel::default();
        let range16 = P252Range16::draw(&mut channel);
        let range12 = P252Range12::draw(&mut channel);
        let state = P252ChainState::draw(&mut channel);
        let (cols, sum) = main_interaction_trace(&trace, &range16, &range12, &state);
        let n_entries = native::entry_layout().len();
        assert_eq!(cols.len(), n_entries.div_ceil(2) * 4);

        // unpack the first two fraction columns and verify the frac values
        let unpack = |eval: &stwo::prover::poly::circle::CircleEvaluation<
            SimdBackend,
            M31,
            BitReversedOrder,
        >|
         -> Vec<M31> {
            let mut out = Vec::with_capacity(1usize << log_size);
            for packed in eval.data.iter() {
                out.extend(packed.to_array());
            }
            out
        };
        // each LogUp fraction column is stored as four M31 coordinate columns
        let coords = |index: usize| -> Vec<[M31; 4]> {
            (0..4)
                .map(|coordinate| unpack(&cols[index * 4 + coordinate]))
                .collect::<Vec<_>>();
            let c: Vec<Vec<M31>> = (0..4)
                .map(|coordinate| unpack(&cols[index * 4 + coordinate]))
                .collect();
            (0..1usize << log_size)
                .map(|row| [c[0][row], c[1][row], c[2][row], c[3][row]])
                .collect()
        };
        let frac0 = coords(0);

        // Column 0 of the interaction trace stores the raw first-pair fraction
        // (running sums start at zero and only the final column is prefix
        // summed by `finalize_last`), so it must equal m0/d0 + m1/d1 row by
        // row. In full mode the first two entries are Range16 limbs.
        let qm31_of_arr = |a: [M31; 4]| -> SecureField { SecureField::from_m31_array(a) };
        let pair_columns = &native::range_use_columns()[0..2];
        for row in 0..(1usize << log_size) {
            let mut expect = SecureField::from(0u32);
            for &col in pair_columns {
                let d: SecureField = range16.combine(&[trace.witness[col][row]]);
                expect += SecureField::from(M31::from(1u32)) / d;
            }
            assert_eq!(
                qm31_of_arr(frac0[row]),
                expect,
                "interaction column 0 diverges from the naive pair fraction at row {row}"
            );
        }
    }

    #[test]
    #[ignore = "superseded by poseidon252_v2 (cairo-air-style decomposition)"]
    fn verifier_rejects_a_tampered_anchor_claim() {
        let spec = small_spec();
        let mut archive = prove_poseidon252_chain(&spec).expect("prove");
        archive.claimed_anchor[0][0] ^= 1;
        assert!(verify_poseidon252_chain(&archive).is_err());
    }

    #[test]
    #[ignore = "superseded by poseidon252_v2 (cairo-air-style decomposition)"]
    fn verifier_rejects_a_tampered_message() {
        let spec = small_spec();
        let mut archive = prove_poseidon252_chain(&spec).expect("prove");
        archive.spec.message[0][31] ^= 1;
        // The anchor no longer matches the tampered statement.
        assert!(verify_poseidon252_chain(&archive).is_err());
    }

    #[test]
    #[ignore = "superseded by poseidon252_v2 (cairo-air-style decomposition)"]
    fn verifier_rejects_a_swapped_message_order() {
        let a = Poseidon252ChainSpec::hash_many(&[
            FieldElement::from(7u64),
            FieldElement::from(9u64),
        ]);
        let b = Poseidon252ChainSpec::hash_many(&[
            FieldElement::from(9u64),
            FieldElement::from(7u64),
        ]);
        let archive = prove_poseidon252_chain(&a).expect("prove");
        let mut forged = archive;
        forged.spec = b;
        assert!(verify_poseidon252_chain(&forged).is_err());
    }
}
#[cfg(test)]
mod rowcheck {
    use super::*;
    use stwo::core::pcs::TreeVec;
    use stwo_constraint_framework::assert_constraints_on_trace;

    /// Official-tool diagnostic: slice the trace per component's
    /// trace_locations and assert every constraint (including the LogUp
    /// cumsum and claimed_sum) on every row.
    #[test]
    fn assert_component_constraints() {
        let spec = native::Poseidon252ChainSpec::hash_many(&[
            starknet_ff::FieldElement::from(7u64),
            starknet_ff::FieldElement::from(9u64),
        ]);
        let mut trace = native::build_chain_trace(&spec).unwrap();
        let log_size = trace.log_size;
        for column in trace.scope.iter_mut().chain(trace.witness.iter_mut()) {
            stwo::core::utils::bit_reverse_coset_to_circle_domain_order(column);
        }
        for mult in [&mut trace.multiplicities16, &mut trace.multiplicities12] {
            let mut cast: Vec<M31> = mult.iter().map(|&v| M31::from(v)).collect();
            stwo::core::utils::bit_reverse_coset_to_circle_domain_order(&mut cast);
            *mult = cast.into_iter().map(|m| m.0).collect::<Vec<u32>>();
        }

        let mut channel = Poseidon252Channel::default();
        let range16 = P252Range16::draw(&mut channel);
        let range12 = P252Range12::draw(&mut channel);
        let state = P252ChainState::draw(&mut channel);
        let (interaction, main_sum) =
            main_interaction_trace(&trace, &range16, &range12, &state);
        let (t16_cols, t16_sum) = table_interaction_trace(
            native::TABLE16_LOG,
            &range_table_column_values(native::TABLE16_LOG),
            &trace.multiplicities16,
            &range16,
        );
        let (t12_cols, t12_sum) = table_interaction_trace(
            native::TABLE12_LOG,
            &range_table_column_values(native::TABLE12_LOG),
            &trace.multiplicities12,
            &range12,
        );
        assert_eq!(
            main_sum + t16_sum + t12_sum,
            SecureField::from(0u32),
            "component logup sums must balance"
        );

        let unpack = |eval: &CircleEvaluation<SimdBackend, M31, BitReversedOrder>| -> Vec<M31> {
            let mut out = Vec::with_capacity(1usize << log_size);
            for packed in eval.data.iter() {
                out.extend(packed.to_array());
            }
            out
        };
        let interaction_flat: Vec<Vec<M31>> = interaction
            .iter()
            .chain(t16_cols.iter())
            .chain(t12_cols.iter())
            .map(unpack)
            .collect();

        let preprocessed: Vec<Vec<M31>> = {
            let mut cols = trace.scope.clone();
            cols.push(range_table_column_values(native::TABLE16_LOG));
            cols.push(range_table_column_values(native::TABLE12_LOG));
            cols
        };
        let mut original: Vec<Vec<M31>> = trace.witness.clone();
        original.push(
            trace
                .multiplicities16
                .iter()
                .map(|&v| M31::from(v))
                .collect(),
        );
        original.push(
            trace
                .multiplicities12
                .iter()
                .map(|&v| M31::from(v))
                .collect(),
        );

        let ids = scope_ids();
        let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
        let main_component = FrameworkComponent::new(
            &mut allocator,
            Poseidon252RoundAir {
                log_size,
                range16: range16.clone(),
                range12: range12.clone(),
                state: state.clone(),
            },
            main_sum,
        );
        let table16_component = FrameworkComponent::new(
            &mut allocator,
            Poseidon252RangeTableAir::range16(log_size, range16.clone(), range12.clone()),
            t16_sum,
        );
        let table12_component = FrameworkComponent::new(
            &mut allocator,
            Poseidon252RangeTableAir::range12(log_size, range16, range12),
            t12_sum,
        );

        let tree_refs = TreeVec::new(vec![
            preprocessed.iter().collect(),
            original.iter().collect(),
            interaction_flat.iter().collect(),
        ]);

        #[allow(clippy::too_many_arguments)]
        fn check<E: FrameworkEval + Sync>(
            name: &'static str,
            component: &FrameworkComponent<E>,
            tree_refs: &TreeVec<Vec<&Vec<M31>>>,
            log_size: u32,
        ) {
            let mut component_trace: TreeVec<Vec<Vec<M31>>> = tree_refs
                .sub_tree(&component.trace_locations())
                .map_cols(|column| (*column).clone());
            component_trace[stwo_constraint_framework::PREPROCESSED_TRACE_IDX] = component
                .preprocessed_column_indices()
                .iter()
                .map(|idx| tree_refs[stwo_constraint_framework::PREPROCESSED_TRACE_IDX][*idx].clone())
                .collect();
            let component_refs = TreeVec::new(vec![
                component_trace[0].iter().collect(),
                component_trace[1].iter().collect(),
                component_trace[2].iter().collect(),
            ]);
            let eval: &E = component;
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert_constraints_on_trace(
                    &component_refs,
                    log_size,
                    |evaluator| {
                        FrameworkEval::evaluate(eval, evaluator);
                    },
                    component.claimed_sum(),
                );
            }));
            assert!(result.is_ok(), "component {name} failed row constraints");
        }

        check("main", &main_component, &tree_refs, log_size);
        check("table16", &table16_component, &tree_refs, native::TABLE16_LOG);
        check("table12", &table12_component, &tree_refs, native::TABLE12_LOG);
    }
}

