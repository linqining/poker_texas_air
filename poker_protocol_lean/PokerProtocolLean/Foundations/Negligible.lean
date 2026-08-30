/-
! # Negligible Probability (re-export of VCV-io's API)

This file is a thin project-local facade over `VCVio.CryptoFoundations.Asymptotics.Negligible`,
which itself wraps Mathlib's `Asymptotics.SuperpolynomialDecay` for the
cryptographically-standard `ℕ → ℝ≥0∞` setting.

## Why a facade rather than a from-scratch definition?

VCV-io's `negligible` already proves every closure property the poker-protocol
soundness reductions need:

| VCV-io lemma                  | Used in                                   |
| ----------------------------- | ----------------------------------------- |
| `negligible_zero`             | base case of zero-knowledge error bounds |
| `negligible_add`              | union bound over multi-layer soundness   |
| `negligible_sum`              | batched DLEQ error                        |
| `negligible_const_mul`        | constant factor `2` from Schwartz-Zippel |
| `negligible_of_le`            | dominate a concrete bound by a negligible |
| `negligible_pow_mul`          | absorb polynomial loss from game hops     |
| `negligible_polynomial_mul`   | absorb polynomial adversary advantage     |

Re-proving these from scratch would duplicate already-reviewed work and add
proof obligations for no scientific gain.
This module re-exports the definition and the closure lemmas under the
project's namespace so downstream `PokerProtocolLean.*` files can import
a single canonical entry point.

## References
- `soundness.md` §三 (Schwartz-Zippel: bound `52 / 2^255 ≈ 2^-248`)
- `soundness.md` §六 (ZKShuffleProof 4-layer error budget)
- VCV-io `VCVio/CryptoFoundations/Asymptotics/Negligible.lean`
-/

import VCVio.CryptoFoundations.Asymptotics.Negligible

open scoped ENNReal
open Filter Topology

namespace PokerProtocolLean.Foundations

/-- A probability function `p : ℕ → ℝ≥0∞` is negligible if it decays faster
than any inverse polynomial. This is VCV-io's `negligible`, re-exported
under the project namespace so downstream files have a single import.

We use `abbrev` so that any `Negligible p` goal can be unfolded to
`negligible p` automatically, and conversely any `negligible p` hypothesis
can be re-packed as `Negligible p` by `refl`. -/
abbrev Negligible (p : ℕ → ℝ≥0∞) : Prop := negligible p

/-- **Zero is negligible.** -/
theorem Negligible_zero : Negligible 0 :=
  negligible_zero

/-- **Pointwise-equal-to-zero functions are negligible.** -/
theorem Negligible_of_zero {p : ℕ → ℝ≥0∞} (hp : ∀ n, p n = 0) : Negligible p :=
  negligible_of_zero hp

/-- **Monotonicity: dominated by a negligible function ⇒ negligible.** -/
theorem Negligible_of_le {p q : ℕ → ℝ≥0∞} (hp : Negligible p)
    (hle : ∀ n, q n ≤ p n) : Negligible q :=
  negligible_of_le hle hp

/-- **Closure under addition** (the union bound for soundness layers). -/
theorem Negligible_add {p q : ℕ → ℝ≥0∞} (hp : Negligible p) (hq : Negligible q) :
    Negligible fun n => p n + q n :=
  negligible_add hp hq

/-- **Closure under multiplication.**

Mathematical argument: for `f, g : ℕ → ℝ≥0∞` both negligible, their pointwise
product `f * g` is negligible. For each `k`, we have `n^k * (f n * g n) =
f n * (n^k * g n)`, where `f n → 0` (from `hf 0`) and `n^k * g n → 0` (from
`hg k`). The product of two functions tending to `0` in `ℝ≥0∞` tends to `0`
(via `ENNReal.Tendsto.mul`, since `0 ≠ ⊤` so the discontinuity of `0 * ∞`
doesn't bite). -/
theorem Negligible_mul {p q : ℕ → ℝ≥0∞} (hp : Negligible p) (hq : Negligible q) :
    Negligible fun n => p n * q n := by
  intro k
  -- `hp 0` after simplification: `p` tends to 0.
  have h_p : Tendsto p atTop (𝓝 0) := by
    have := hp 0
    simpa [pow_zero, one_mul] using this
  -- `hq k`: `n^k * q n` tends to 0.
  have h_nkq : Tendsto (fun n : ℕ => (↑n : ℝ≥0∞) ^ k * q n) atTop (𝓝 0) := hq k
  -- `0 ≠ ⊤` is the side-condition `ENNReal.Tendsto.mul` needs.
  have h_zero_ne_top : (0 : ℝ≥0∞) ≠ ⊤ := by simp
  -- Product of `p` (→0) and `n^k * q n` (→0) → 0.
  have h_prod : Tendsto (fun n : ℕ => p n * ((↑n : ℝ≥0∞) ^ k * q n)) atTop (𝓝 0) := by
    have := ENNReal.Tendsto.mul h_p (Or.inr h_zero_ne_top) h_nkq (Or.inr h_zero_ne_top)
    simpa [zero_mul] using this
  -- Rearrange: `n^k * (p n * q n) = p n * (n^k * q n)` (commutativity + assoc).
  refine h_prod.congr fun n => ?_
  rw [mul_left_comm]

/-- **Closure under scalar multiplication** (constant factor, e.g. the `2`
in `2 / |F|`).

Note: VCV-io's `negligible_const_mul` requires `c ≠ ⊤` because multiplication
by `⊤` is discontinuous at `0` in `ℝ≥0∞`. For cryptographic soundness bounds
this is always the case (constants are finite). -/
theorem Negligible_const_mul {p : ℕ → ℝ≥0∞} (hp : Negligible p) (c : ℝ≥0∞)
    (hc : c ≠ ⊤) :
    Negligible fun n => c * p n :=
  negligible_const_mul hp hc

/-- **Closure under finite sum** (used for batched DLEQ soundness). -/
theorem Negligible_sum {ι : Type*} {s : Finset ι} {p : ι → ℕ → ℝ≥0∞}
    (h : ∀ i ∈ s, Negligible (p i)) :
    Negligible fun n => ∑ i ∈ s, p i n :=
  negligible_sum h

/-- **Absorption of polynomial powers of the security parameter** (used to
absorb polynomial loss from hybrid-game hops). -/
theorem Negligible_pow_mul {p : ℕ → ℝ≥0∞} (hp : Negligible p) (d : ℕ) :
    Negligible fun n => (n : ℝ≥0∞) ^ d * p n :=
  negligible_pow_mul hp d

/-- **Absorption of any polynomial factor** (most general form, used in
full polynomial-loss reductions like ZKShuffleProof Layer 4). -/
theorem Negligible_polynomial_mul {p : ℕ → ℝ≥0∞} (hp : Negligible p)
    (q : Polynomial ℕ) :
    Negligible fun n => ↑(q.eval n) * p n :=
  negligible_polynomial_mul hp q

end PokerProtocolLean.Foundations
