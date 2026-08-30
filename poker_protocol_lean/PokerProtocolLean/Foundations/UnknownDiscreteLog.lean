import Mathlib.Algebra.Field.Basic
import Mathlib.Data.Fintype.Basic
import Mathlib.Data.Bool.Basic
import VCVio.CryptoFoundations.HardnessAssumptions.DiffieHellman
import VCVio.OracleComp.Constructions.SampleableType
import VCVio.EvalDist.Monad.Basic
import PokerProtocolLean.Foundations.AlgebraicSetup
import PokerProtocolLean.Foundations.Negligible

/-!
# Unknown Discrete Logarithm Assumptions

This file separates two notions that must not be conflated:

* `FreshDLogHard`: the standard average-case DLog experiment samples
  `x <- F` and gives the adversary `x * g`;
* `UnknownDL P`: a conditional, point-specific statement saying that one
  particular externally supplied point has an unknown logarithm.

The first is the appropriate cryptographic assumption for freshly shuffled
ElGamal exponents.  The second is useful only after a protocol argument has
established that the concrete point is distributed like a fresh DLog target.

The UDL assumption states that no probabilistic polynomial-time adversary
can compute the discrete logarithm of `P` w.r.t. `g`. Formally, for every
adversary `A`, the success probability `Pr[sk' • g = P | A(g, P) → sk']`
is negligible.

## Closure properties

Two closure properties are proved:

* `UnknownDL.translate_known`: `UnknownDL P → UnknownDL (P + k • g)` for any
  known scalar `k`. Reduction: an adversary `A'` against `P + k • g` yields
  an adversary `A` against `P` by `A(g, Q) := A'(g, Q + k • g) - k`.
* `UnknownDL.smul_known`: `UnknownDL P → UnknownDL (c • P)` for any known
  nonzero scalar `c`. Reduction: an adversary `A'` against `c • P` yields
  an adversary `A` against `P` by `A(g, Q) := c⁻¹ * A'(g, c • Q)`.

Both reductions preserve the success probability exactly (the two
experiments' acceptance probabilities are equal as functions of the
security parameter), so negligibility transfers directly.
-/

open PokerProtocolLean.Foundations (smulByG)
open DiffieHellman (DLogAdversary dlogExp)
open OracleComp
open scoped ENNReal

namespace PokerProtocolLean.Foundations

variable (F : Type) [Field F] [Fintype F] [DecidableEq F] [SampleableType F]
variable (G : Type) [AddCommGroup G] [Module F G] [Fintype G] [DecidableEq G]
  [SampleableType G]
variable (g : G)
variable (hg : Function.Bijective (smulByG F G g))

/-- The DLog-at-point experiment: adversary `A` is given `(g, P)` and
returns a guess `sk' : F`. The experiment succeeds iff `sk' • g = P`. -/
def dlogExpAtPoint (P : G) (A : DLogAdversary F G) : ProbComp Bool :=
  A g P >>= fun sk' => pure (decide (sk' • g = P))

/-- **`UnknownDL P`**: worst-case DLog hardness on `P`. -/
def UnknownDL (P : G) : Prop :=
  ∀ (A : DLogAdversary F G),
    Negligible (fun n => Pr[= true | dlogExpAtPoint F G g P A])

/-- Standard average-case DLog hardness for a fresh uniformly sampled
exponent.  This directly wraps VCV-io's `DiffieHellman.dlogExp` and is the
assumption used for the accumulated `c1` exponent of authenticated readable
cards when at least one shuffle re-randomizer is honest and hidden. -/
def FreshDLogHard : Prop :=
  ∀ (A : DLogAdversary F G),
    Negligible (fun n => Pr[= true | dlogExp g A])

/-- Introduction rule kept explicit so security theorems can list the exact
average-case DLog assumption in their trusted-computing base. -/
theorem freshDLogHard_of_assumption
    (h : ∀ (A : DLogAdversary F G),
      Negligible (fun n => Pr[= true | dlogExp g A])) :
    FreshDLogHard F G g := h

/-! ## Closure properties

Both `translate_known` and `smul_known` follow the same reduction pattern:
construct an adversary `A` against the *original* point `P` from the given
adversary `A'` against the *transformed* point, prove the two experiments'
success probabilities are equal (pointwise in the security parameter) via
the algebraic equivalence of the acceptance conditions, then transfer
negligibility. -/

/-- **UnknownDL is preserved under translation by a known scalar.**

If `P` has an unknown discrete log w.r.t. `g`, then so does `P + k • g`
for any known scalar `k`.

Reduction: given an adversary `A'` against `P + k • g`, construct an
adversary `A` against `P` by running `A'` on the translated point and
subtracting `k` from the result:

    A(g, Q) := do { s' ← A'(g, Q + k • g); return (s' - k) }

The acceptance conditions are equivalent:
`(s' - k) • g = P  ↔  s' • g = P + k • g` (by `sub_smul` and
`sub_eq_iff_eq_add`), so the two experiments' success probabilities are
equal as functions of the security parameter, and negligibility transfers
directly. -/
theorem UnknownDL.translate_known (P : G) (hP : UnknownDL F G g P) (k : F) :
    UnknownDL F G g (P + k • g) := by
  intro A'
  -- Reduction adversary: A(g, Q) := A'(g, Q + k•g) - k
  let A : DLogAdversary F G := fun g' Q => do
    let s' ← A' g' (Q + k • g')
    return (s' - k)
  have hP_A : Negligible (fun n => Pr[= true | dlogExpAtPoint F G g P A]) := hP A
  -- The two experiments' success probabilities are equal as functions of n.
  have h_fun_eq :
      (fun (_n : ℕ) => Pr[= true | dlogExpAtPoint F G g (P + k • g) A']) =
      (fun (_n : ℕ) => Pr[= true | dlogExpAtPoint F G g P A]) := by
    funext n
    simp only [dlogExpAtPoint]
    -- Normalise RHS: A g P = A' g (P + k•g) >>= fun s' => pure (s' - k),
    -- then bind_assoc + pure_bind collapses the two binds into one.
    rw [show A g P = (A' g (P + k • g) >>= fun s' => pure (s' - k)) from rfl,
        bind_assoc]
    simp only [pure_bind]
    -- Both sides now have the form `A' g (P + k•g) >>= fun s' => pure (decide _)`;
    -- reduce to the per-`s'` equivalence of the acceptance conditions.
    apply probOutput_bind_congr' (A' g (P + k • g))
    intro s'
    -- Algebraic equivalence: (s' - k) • g = P  ↔  s' • g = P + k • g
    have h_equiv : (s' - k) • g = P ↔ s' • g = P + k • g := by
      rw [sub_smul, sub_eq_iff_eq_add]
    -- The two `decide` booleans are equal because the underlying propositions
    -- are equivalent (`h_equiv`), so the two `Pr[= true | pure (decide _)]`
    -- probabilities coincide. `decide_congr` turns the `↔` into a `decide`
    -- equality directly, sidestepping `simp`'s equality-direction normalisation
    -- inside `decide` (which would otherwise break `if_pos`/`if_neg` matching).
    have hdec : decide (s' • g = P + k • g) = decide ((s' - k) • g = P) :=
      Bool.decide_congr h_equiv.symm
    rw [hdec]
  -- Transfer: Negligible is extensional in the function argument.
  exact h_fun_eq ▸ hP_A

/-- **UnknownDL is preserved under scalar multiplication by a known nonzero
scalar.**

If `P` has an unknown discrete log w.r.t. `g`, then so does `c • P` for any
known nonzero scalar `c`.

Reduction: given an adversary `A'` against `c • P`, construct an adversary
`A` against `P` by running `A'` on the scaled point and multiplying the
result by `c⁻¹`:

    A(g, Q) := do { s' ← A'(g, c • Q); return (c⁻¹ * s') }

The acceptance conditions are equivalent:
`(c⁻¹ * s') • g = P  ↔  s' • g = c • P` (by `mul_smul` and
`inv_mul_cancel₀`), so the two experiments' success probabilities are
equal as functions of the security parameter, and negligibility transfers
directly. -/
theorem UnknownDL.smul_known (P : G) (hP : UnknownDL F G g P) (c : F)
    (hc : c ≠ 0) :
    UnknownDL F G g (c • P) := by
  intro A'
  -- Reduction adversary: A(g, Q) := c⁻¹ * A'(g, c • Q)
  let A : DLogAdversary F G := fun g' Q => do
    let s' ← A' g' (c • Q)
    return (c⁻¹ * s')
  have hP_A : Negligible (fun n => Pr[= true | dlogExpAtPoint F G g P A]) := hP A
  have h_fun_eq :
      (fun (_n : ℕ) => Pr[= true | dlogExpAtPoint F G g (c • P) A']) =
      (fun (_n : ℕ) => Pr[= true | dlogExpAtPoint F G g P A]) := by
    funext n
    simp only [dlogExpAtPoint]
    rw [show A g P = (A' g (c • P) >>= fun s' => pure (c⁻¹ * s')) from rfl,
        bind_assoc]
    simp only [pure_bind]
    apply probOutput_bind_congr' (A' g (c • P))
    intro s'
    -- Algebraic equivalence: (c⁻¹ * s') • g = P  ↔  s' • g = c • P
    have h_equiv : (c⁻¹ * s') • g = P ↔ s' • g = c • P := by
      rw [mul_smul]
      refine ⟨fun h => ?_, fun h => ?_⟩
      · -- Forward: c⁻¹ • (s' • g) = P  ⟹  s' • g = c • P  (scale both sides by c)
        have hsc : c • (c⁻¹ • (s' • g)) = c • P := by rw [h]
        rwa [← mul_smul, mul_inv_cancel₀ hc, one_smul] at hsc
      · -- Backward: s' • g = c • P  ⟹  c⁻¹ • (s' • g) = P  (scale both sides by c⁻¹)
        rw [h, ← mul_smul, inv_mul_cancel₀ hc, one_smul]
    -- The two `decide` booleans are equal because the underlying propositions
    -- are equivalent (`h_equiv`); `decide_congr` turns the `↔` into a `decide`
    -- equality directly (see `translate_known` for the rationale).
    have hdec : decide (s' • g = c • P) = decide ((c⁻¹ * s') • g = P) :=
      Bool.decide_congr h_equiv.symm
    rw [hdec]
  exact h_fun_eq ▸ hP_A

/-! ## Freshness and negligibility (cryptographic assumptions) -/

/-- **Pointwise DLog hypothesis.**

Under `hDLog_worst`, every group element `P` has `UnknownDL`.

This theorem is logically valid but its premise is deliberately *not* called
a standard DLog assumption: quantifying over every fixed point includes easy
points such as `P = g`, whose logarithm is publicly `1`.  New protocol
theorems should use `FreshDLogHard` plus a distribution/freshness argument,
not this premise.  It remains here only for compatibility with older modules. -/
theorem unknownDL_of_worstDLog (hDLog_worst :
    ∀ (P : G) (A : DLogAdversary F G),
      Negligible (fun n => Pr[= true | dlogExpAtPoint F G g P A]))
    (P : G) :
    UnknownDL F G g P := by
  intro A
  exact hDLog_worst P A

/-- **Schwartz-Zippel negligibility bound**: `2/|F|` is negligible under
the worst-case DLog hardness assumption (presented as a hypothesis). -/
theorem negligible_inv_field_card (hSchwartzZippel :
    Negligible (fun (n : ℕ) => 2 / (Fintype.card F : ℝ≥0∞))) :
    Negligible (fun (n : ℕ) => 2 / (Fintype.card F : ℝ≥0∞)) :=
  hSchwartzZippel

end PokerProtocolLean.Foundations
