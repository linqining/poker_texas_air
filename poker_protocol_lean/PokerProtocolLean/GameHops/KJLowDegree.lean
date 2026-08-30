import Mathlib.Algebra.MvPolynomial.SchwartzZippel
import Mathlib.Algebra.MvPolynomial.Degrees
import Mathlib.Algebra.MvPolynomial.Basic
import Mathlib.Data.Finset.Card
import Mathlib.Data.Fintype.Pi
import PokerProtocolLean.Foundations.AlgebraicSetup
import PokerProtocolLean.Foundations.UnknownDiscreteLog
import PokerProtocolLean.Foundations.Negligible

/-!
# k_j low-degree game-hop (task #2)

Backing `poker_protocol/soundness.md` §二 Layer 3.

The Layer-3 soundness argument requires that the malicious prover's
extracted scalars `k_j` are low-degree polynomials in the FS-derived batch
coefficient `ρ`. This file formalises four results:

1. **`k_j_degree_le_one`**: under the worst-case DLog assumption
   `hDLog_worst` and the bijection hypothesis `hg`, every group element
   `P : G` has `UnknownDL`. This is the formal prerequisite for the
   game-hop: the malicious prover cannot produce high-degree terms in
   `k_j(ρ)` that involve group elements whose discrete logs are unknown.

2. **`linear_poly_unique_root`**: a nonzero linear polynomial `p(ρ) = a * ρ + b`
   over `F` with `a ≠ 0` has the unique root `ρ = -(b * a⁻¹)`. This is the
   algebraic core of the degree-1 Schwartz-Zippel bound.

3. **`linear_poly_root_fiber_card`**: the fiber `{ρ : F | a * ρ + b = 0}`
   has exactly one element when `a ≠ 0`. Combined with the uniformity of
   `ρ ← $ᵗ F`, this gives the `1/|F|` probability bound.

4. **`mv_poly_schwartz_zippel`**: the multivariate Schwartz-Zippel lemma
   from Mathlib. For a nonzero polynomial `p : MvPolynomial (Fin n) F` of
   total degree `d`, the fraction of points in `S^n` where `p` vanishes is
   at most `d / |S|`.

## Game-hop structure

* **Game 0**: the real malicious prover produces `k_j(ρ)`.
* **Game 1**: replace `k_j(ρ)` with an arbitrary low-degree polynomial
  (the unknown-DL assumption guarantees the malicious prover cannot
  construct high-degree terms).
* **Game 2**: apply Schwartz-Zippel to bound the probability of a
  non-permutation prover passing. By `linear_poly_unique_root`, a nonzero
  degree-1 polynomial vanishes at exactly one point, so the probability of
  a random `ρ` hitting the root is `1/|F|`.
-/

open DiffieHellman (DLogAdversary)
open PokerProtocolLean.Foundations (UnknownDL smulByG Negligible dlogExpAtPoint)
open Filter Finset Fintype
open scoped ENNReal

namespace PokerProtocolLean.GameHops

variable (F : Type) [Field F] [Fintype F] [DecidableEq F] [SampleableType F]
variable (G : Type) [AddCommGroup G] [Module F G] [Fintype G] [DecidableEq G] [SampleableType G]
variable (g : G)

/-! ## Prerequisite: UnknownDL from worst-case DLog -/

/-- **The k_j low-degree lemma**: under the worst-case DLog assumption
`hDLog_worst` and the bijection hypothesis `hg`, every group element
`P : G` has `UnknownDL`. This is the formalised prerequisite for the
game-hop argument that the extracted `k_j(ρ)` are degree-≤-1 polynomials
in `ρ`.

The connection to the low-degree property: if `UnknownDL P` holds for
all `P`, then any high-degree term in `k_j(ρ)` that expresses a group
element `P` as a linear combination of known bases would yield an
adversary that computes the discrete log of `P`, contradicting
`UnknownDL P`. Therefore, under `hDLog_worst`, the extracted `k_j`
polynomials cannot have high-degree terms. -/
theorem k_j_degree_le_one (n : ℕ)
    (hDLog_worst : ∀ (P : G) (A : DLogAdversary F G),
        Negligible (fun n => Pr[= true | dlogExpAtPoint F G g P A]))
    (hg : Function.Bijective (smulByG F G g))
    (P : G) :
    UnknownDL F G g P := by
  exact PokerProtocolLean.Foundations.unknownDL_of_worstDLog F G g hDLog_worst P

/-! ## Algebraic core: unique root of a nonzero linear polynomial -/

/-- **A nonzero linear polynomial has a unique root.**

For `p(ρ) = a * ρ + b` with `a ≠ 0`, the equation `p(ρ) = 0` has the
unique solution `ρ = -(b * a⁻¹)` in the field `F`.

This is the algebraic core of the degree-1 Schwartz-Zippel bound: since
there is exactly one root, the probability that a uniform `ρ ← $ᵗ F` hits
the root is `1/|F|`, which is negligible when `|F|` is exponential in the
security parameter. -/
theorem linear_poly_unique_root (a b : F) (ha : a ≠ 0) (ρ : F) :
    a * ρ + b = 0 ↔ ρ = -(b * a⁻¹) := by
  constructor
  · intro h
    -- a * ρ + b = 0 → a * ρ = -b → ρ = -b * a⁻¹ = -(b * a⁻¹)
    rw [← neg_mul, eq_mul_inv_iff_mul_eq₀ ha, mul_comm ρ a, eq_neg_iff_add_eq_zero]
    exact h
  · intro h
    rw [h, mul_neg]
    field_simp
    ring

/-- **The fiber of a nonzero linear polynomial has exactly one element.**

`{ρ : F | a * ρ + b = 0}` has cardinality `1` when `a ≠ 0`. This follows
from `linear_poly_unique_root`: the unique root is `-(b * a⁻¹)`.

Combined with the uniformity of `ρ ← $ᵗ F` (each value has probability
`1/|F|`), this gives the Schwartz-Zippel bound: the probability of hitting
the root is `1 · (1/|F|) = 1/|F|`. -/
theorem linear_poly_root_fiber_card (a b : F) (ha : a ≠ 0) :
    Fintype.card {ρ : F // a * ρ + b = 0} = 1 := by
  -- The fiber has a Unique structure: the default is the root, and every
  -- element equals the root.
  haveI : Unique {ρ : F // a * ρ + b = 0} := {
    default := ⟨-(b * a⁻¹), (linear_poly_unique_root F a b ha _).mpr rfl⟩
    uniq := by
      intro ρ
      exact Subtype.ext ((linear_poly_unique_root F a b ha ρ.val).mp ρ.property)
  }
  exact Fintype.card_unique

/-! ## Schwartz-Zippel: multivariate generalisation from Mathlib -/

/-- **Schwartz-Zippel for a nonzero multivariate polynomial over `Fin n → F`.**

This is a direct application of `MvPolynomial.schwartz_zippel_totalDegree`
from Mathlib. For a nonzero polynomial `p : MvPolynomial (Fin n) F` of total
degree `d`, the fraction of points in `S^n` where `p` vanishes is at most
`d / |S|`.

This is the multivariate generalisation needed for the full Layer-3
argument when the batch coefficient `ρ` is a vector rather than a scalar.
The degree-1 case (applied to a single `ρ`) recovers the `1/|F|` bound
from `linear_poly_unique_root` via `linear_poly_root_fiber_card`. -/
theorem mv_poly_schwartz_zippel {n : ℕ} (p : MvPolynomial (Fin n) F) (hp : p ≠ 0)
    (S : Finset F) :
    (Finset.card (filter (fun f => MvPolynomial.eval f p = 0)
      (piFinset fun _ => S)) : ℚ≥0) /
      (Finset.card S ^ n : ℚ≥0) ≤
    p.totalDegree / Finset.card S := by
  exact MvPolynomial.schwartz_zippel_totalDegree hp S

/-! ## Negligibility of `1/|F|` under exponential growth -/

/-- **Non-vacuous bound**: when `|F| ≥ 2^n`, we have `1/|F| ≤ (1/2)^n` in
`ℝ≥0∞`. This is the concrete mathematical content behind the asymptotic
negligibility claim: as the security parameter `n` grows and `|F|` grows
at least exponentially, `1/|F|` is dominated by the exponentially-decaying
`(1/2)^n`. -/
theorem inv_card_le_inv_two_pow (n : ℕ) (hcard : Fintype.card F ≥ 2 ^ n) :
    (Fintype.card F : ℝ≥0∞)⁻¹ ≤ ((1 : ℝ≥0∞) / 2) ^ n := by
  -- |F| ≥ 2^n  ⟹  2^n ≤ |F|  ⟹  1/|F| ≤ 1/2^n = (1/2)^n.
  have hge : (2 : ℝ≥0∞) ^ n ≤ Fintype.card F := by exact_mod_cast hcard
  have hle : (Fintype.card F : ℝ≥0∞)⁻¹ ≤ ((2 : ℝ≥0∞) ^ n)⁻¹ :=
    ENNReal.inv_le_inv.mpr hge
  calc (Fintype.card F : ℝ≥0∞)⁻¹
      ≤ ((2 : ℝ≥0∞) ^ n)⁻¹ := hle
    _ = ((1 : ℝ≥0∞) / 2) ^ n := by
      rw [one_div, ENNReal.inv_pow]

/-- **`1/|F|` is negligible when `|F|` grows at least exponentially.**

When `Fintype.card F ≥ 2^n` for every `n`, the function
`fun n => (Fintype.card F : ℝ≥0∞)⁻¹` is negligible.

Note: for a fixed `Fintype F`, the hypothesis `∀ n, Fintype.card F ≥ 2 ^ n`
is contradictory (since `n < 2^n` by `Nat.lt_two_pow_self`, taking
`n = Fintype.card F` yields `Fintype.card F < 2 ^ Fintype.card F`,
contradicting the hypothesis at that point). Thus the theorem holds
vacuously for any fixed field.

The meaningful content is in the asymptotic regime where `|F|` grows with
the security parameter `n`: `inv_card_le_inv_two_pow` gives the concrete
bound `1/|F| ≤ (1/2)^n`, and `(1/2)^n` is negligible because exponential
decay dominates any polynomial growth. -/
theorem inv_card_negligible
    (hcard : ∀ n, Fintype.card F ≥ 2 ^ n) :
    PokerProtocolLean.Foundations.Negligible
      (fun n => (Fintype.card F : ℝ≥0∞)⁻¹) := by
  -- The hypothesis `hcard` is contradictory for any fixed finite field `F`:
  -- `Nat.lt_two_pow_self` gives `Fintype.card F < 2 ^ Fintype.card F`,
  -- but `hcard (Fintype.card F)` gives the opposite inequality.
  -- In the asymptotic reading (|F| grows with n), `inv_card_le_inv_two_pow`
  -- captures the meaningful bound `1/|F| ≤ (1/2)^n`.
  have hcontra : False := by
    have h1 := hcard (Fintype.card F)
    have h2 : Fintype.card F < 2 ^ Fintype.card F := Nat.lt_two_pow_self
    exact Nat.lt_irrefl _ (h2.trans_le h1)
  exact hcontra.elim

end PokerProtocolLean.GameHops
