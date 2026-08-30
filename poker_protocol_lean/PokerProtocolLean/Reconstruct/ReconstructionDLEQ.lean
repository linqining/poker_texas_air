import Mathlib.Algebra.BigOperators.Fin
import Mathlib.Algebra.Module.BigOperators
import Mathlib.Tactic.Module
import VCVio.CryptoFoundations.SigmaProtocol
import VCVio.OracleComp.Constructions.SampleableType
import VCVio.ProgramLogic.Tactics.Unary
import VCVio.ProgramLogic.Tactics.Relational
import PokerProtocolLean.Foundations.AlgebraicSetup

/-!
# ReconstructionDLEQ — blind DLEQ (M8-J1)

Backing `poker_protocol/src/zk_shuffle/reconstruction/swap_out.rs`
(`ReconstructionDLEQProof`).

A `ReconstructionDLEQProof` proves knowledge of a scalar `a : F` such that

    a • base_in = base_out

where `base_in = Σ_i base_coeff^i • points_in[i]` and
`base_out = Σ_i base_coeff^i • points_out[i]` are the challenge-dependent
multi-scalar combinations of two public point families, and `base_coeff`
is FS-derived from `points_in`/`points_out` (modelled as a statement
parameter here; the FS derivation happens before the Σ-protocol's commit
phase, so `base_coeff` is fixed by the time the prover commits).

This is a non-standard Schnorr variant: the base point depends on a
challenge (`base_coeff`), but the dependency is "frozen" into the
statement before the Σ-protocol's commit, so the standard Schnorr
special-soundness and HVZK arguments apply unchanged.

## Protocol

* `commit`: samples `w ← $ᵗ F`, returns `(T = w • base_in, w)`.
* `respond`: `z = w + c * a`.
* `verify`: `decide (z • base_in = T + c • base_out)`.
* `sim`: samples `c, z ← $ᵗ F`, returns `z • base_in - c • base_out`.
* `extract`: `a = (z₁ - z₂) * (c₁ - c₂)⁻¹`.

## Theorems

| Property                | Theorem                          |
| ----------------------- | -------------------------------- |
| Perfect completeness    | `sigma_complete_recon`           |
| Special soundness       | `sigma_speciallySound_recon`     |
| Perfect HVZK            | `sigma_perfect_hvzk_recon`       |

The algebra is literally that of single-base Schnorr (VCV-io's
`Examples.Schnorr.SigmaProtocol`): the bilinearity of the `Module F G`
action drives every identity.
-/

open OracleSpec OracleComp SigmaProtocol
open OracleComp.ProgramLogic OracleComp.ProgramLogic.Relational
open scoped ENNReal

namespace PokerProtocolLean.Reconstruct

variable (F : Type) [Field F] [Fintype F] [DecidableEq F] [SampleableType F]
variable (G : Type) [AddCommGroup G] [Module F G] [Fintype G] [DecidableEq G]
  [SampleableType G]

/-- Statement: input/output point families and the FS-derived `base_coeff`
(frozen into the statement before the Σ-protocol's commit phase). -/
structure Statement (F : Type) (G : Type) (n : ℕ) where
  /-- Input points. -/
  points_in : Fin n → G
  /-- Output points. -/
  points_out : Fin n → G
  /-- FS-derived base coefficient (frozen before commit). -/
  base_coeff : F

/-- Witness: the shared scalar `a` such that `a • base_in = base_out`. -/
structure Witness (F : Type) where
  /-- The shared scalar. -/
  a : F

/-- The challenge-dependent base point `Σ_i base_coeff^i • points_in[i]`. -/
def base_point_in (F : Type) [Field F] (G : Type) [AddCommGroup G] [Module F G]
    [DecidableEq G] [Fintype G] (base_coeff : F) {n : ℕ}
    (stmt : Statement F G n) : G :=
  ∑ i : Fin n, base_coeff ^ (i : ℕ) • stmt.points_in i

/-- The challenge-dependent base point `Σ_i base_coeff^i • points_out[i]`. -/
def base_point_out (F : Type) [Field F] (G : Type) [AddCommGroup G] [Module F G]
    [DecidableEq G] [Fintype G] (base_coeff : F) {n : ℕ}
    (stmt : Statement F G n) : G :=
  ∑ i : Fin n, base_coeff ^ (i : ℕ) • stmt.points_out i

/-- The relation: `a • base_in = base_out` (Schnorr-style DLog equality
between the two challenge-dependent bases). -/
def relation (n : ℕ) (stmt : Statement F G n) (wit : Witness F) : Bool :=
  decide (wit.a • base_point_in F G stmt.base_coeff stmt =
            base_point_out F G stmt.base_coeff stmt)

/-- The ReconstructionDLEQ Σ-protocol (single-base Schnorr on `base_in`). -/
def sigmaReconstructionDLEQ (n : ℕ) : SigmaProtocol
    (Statement F G n) (Witness F) G F F F
    (relation F G n) where
  commit stmt _wit := do
    let w ← ($ᵗ F)
    let T := w • base_point_in F G stmt.base_coeff stmt
    return (T, w)
  respond _stmt wit w c := pure (w + c * wit.a)
  verify stmt T c z :=
    decide (z • base_point_in F G stmt.base_coeff stmt =
              T + c • base_point_out F G stmt.base_coeff stmt)
  sim _stmt := $ᵗ G
  extract c₁ z₁ c₂ z₂ := pure ⟨(z₁ - z₂) * (c₁ - c₂)⁻¹⟩

/-! ## Perfect completeness

For an honest prover with a valid witness, `z • base_in = (w + c·a) • base_in
= w • base_in + c • (a • base_in) = T + c • base_out`. -/

set_option linter.unusedSectionVars false in
theorem sigma_complete_recon (n : ℕ) :
    PerfectlyComplete (sigmaReconstructionDLEQ F G n) := by
  intro stmt wit hrel
  have h_eq : wit.a • base_point_in F G stmt.base_coeff stmt =
      base_point_out F G stmt.base_coeff stmt :=
    of_decide_eq_true hrel
  have hverify : ∀ (w c : F),
      (w + c * wit.a) • base_point_in F G stmt.base_coeff stmt =
        w • base_point_in F G stmt.base_coeff stmt
          + c • base_point_out F G stmt.base_coeff stmt := by
    intro w c
    rw [add_smul, mul_smul, h_eq]
  simp only [sigmaReconstructionDLEQ, monad_norm]
  simp [hverify]

/-! ## Special soundness

From two accepting transcripts with the same `T` but distinct challenges
`c₁ ≠ c₂`, the extractor
`extract c₁ z₁ c₂ z₂ = ⟨(z₁ - z₂) * (c₁ - c₂)⁻¹⟩` returns a witness
satisfying the relation.

Algebra: subtracting the two verification equations gives
`(z₁ - z₂) • base_in = (c₁ - c₂) • base_out`, hence
`(z₁ - z₂) * (c₁ - c₂)⁻¹ • base_in = base_out`. -/

set_option linter.unusedSectionVars false in
theorem sigma_speciallySound_recon (n : ℕ) :
    SpeciallySound (sigmaReconstructionDLEQ F G n) := by
  intro stmt T c₁ c₂ z₁ z₂ h_ne h_v1 h_v2 w h_w
  dsimp only [sigmaReconstructionDLEQ] at *
  simp only [support_pure, Set.mem_singleton_iff] at h_w
  subst h_w
  simp only [relation, decide_eq_true_eq] at h_v1 h_v2 ⊢
  -- Subtract: (z₁ - z₂) • base_in = (c₁ - c₂) • base_out
  have h_sub : (z₁ - z₂) • base_point_in F G stmt.base_coeff stmt =
      (c₁ - c₂) • base_point_out F G stmt.base_coeff stmt := by
    rw [sub_smul, sub_smul, h_v1, h_v2, add_sub_add_left_eq_sub]
  have h_ne' : c₁ - c₂ ≠ 0 := sub_ne_zero.mpr h_ne
  calc ((z₁ - z₂) * (c₁ - c₂)⁻¹) • base_point_in F G stmt.base_coeff stmt
      = (c₁ - c₂)⁻¹ • ((z₁ - z₂) • base_point_in F G stmt.base_coeff stmt) := by
        rw [mul_comm, mul_smul]
    _ = (c₁ - c₂)⁻¹ • ((c₁ - c₂) • base_point_out F G stmt.base_coeff stmt) := by
        rw [h_sub]
    _ = ((c₁ - c₂)⁻¹ * (c₁ - c₂)) • base_point_out F G stmt.base_coeff stmt := by
        rw [← mul_smul]
    _ = (1 : F) • base_point_out F G stmt.base_coeff stmt := by
        rw [inv_mul_cancel₀ h_ne']
    _ = base_point_out F G stmt.base_coeff stmt := one_smul F _

/-! ## Perfect HVZK

The simulator samples `c, z ← $ᵗ F`, reconstructs
`T = z • base_in - c • base_out`, and the resulting transcript
distribution equals the real one via the per-`r` translation bijection
`r ↦ r + c * a` on `F`. -/

def simTranscript (n : ℕ) (stmt : Statement F G n) :
    ProbComp (G × F × F) := do
  let c ← ($ᵗ F)
  let z ← ($ᵗ F)
  return (z • base_point_in F G stmt.base_coeff stmt
            - c • base_point_out F G stmt.base_coeff stmt, c, z)

set_option linter.unusedSectionVars false in
theorem sigma_perfect_hvzk_recon (n : ℕ) :
    PerfectHVZK (sigmaReconstructionDLEQ F G n)
      (fun stmt => simTranscript F G n stmt) := by
  intro stmt wit hrel
  have h_eq : wit.a • base_point_in F G stmt.base_coeff stmt =
      base_point_out F G stmt.base_coeff stmt :=
    of_decide_eq_true hrel
  apply evalDist_ext
  intro t
  trans Pr[= t | do
    let c ← ($ᵗ F)
    let r ← ($ᵗ F)
    pure (((r + c * wit.a) • base_point_in F G stmt.base_coeff stmt
            - c • base_point_out F G stmt.base_coeff stmt,
           c, r + c * wit.a) : G × F × F)]
  · simp only [SigmaProtocol.realTranscript, sigmaReconstructionDLEQ]
    vcstep rw
    simp [add_smul, mul_smul, h_eq, add_sub_cancel_right]
  · show _ = Pr[= t | simTranscript F G n stmt]
    unfold simTranscript
    apply probOutput_eq_of_relTriple_eqRel (x := t)
    rvcstep
    intro c _ hc; subst hc
    rvcstep using (· + c * wit.a)
    exact ⟨fun _ _ h => add_right_cancel h, fun z => ⟨z - c * wit.a, sub_add_cancel z _⟩⟩

/-! ## Blind-binding lemma

**Blind-binding lemma**: a verified ReconstructionDLEQ proof implies
`base_out = a • base_in` for the extracted `a`.

This is exactly the relation `relation F G n stmt wit = true`, so the
lemma is a trivial unpacking of `SpeciallySound`'s conclusion. Stated
as `True` here because the full binding-to-reconstruct-deck reduction
(in `poker_protocol/soundness.md` §三) depends on the per-card
`SwapOutCardProof` family which is formalised separately. -/
theorem blind_binding {n : ℕ} (stmt : Statement F G n) (wit : Witness F)
    (hrel : relation F G n stmt wit = true) :
    wit.a • base_point_in F G stmt.base_coeff stmt =
      base_point_out F G stmt.base_coeff stmt := by
  exact of_decide_eq_true hrel

end PokerProtocolLean.Reconstruct
