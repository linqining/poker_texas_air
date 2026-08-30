import Mathlib.Algebra.BigOperators.Fin
import Mathlib.Algebra.Module.BigOperators
import Mathlib.Tactic.Module
import VCVio.CryptoFoundations.SigmaProtocol
import VCVio.OracleComp.Constructions.SampleableType
import VCVio.ProgramLogic.Tactics.Unary
import VCVio.ProgramLogic.Tactics.Relational
import PokerProtocolLean.Foundations.AlgebraicSetup
import PokerProtocolLean.Foundations.Negligible
import PokerProtocolLean.Schnorr.GeneralizedSchnorr

/-!
# ChaumPedersenDLEQProof — two-base shared-discrete-log Σ-protocol

This file formalises the Chaum-Pedersen "DLEQ" (Discrete-Log EQuality) proof
backing `poker_protocol/src/zk_shuffle/chaum_pedersen_dleq.rs`.

The prover proves knowledge of a single scalar `s : F` such that

    P1 = s • G1   and   P2 = s • G2

i.e. the discrete logs of `P1` w.r.t. `G1` and `P2` w.r.t. `G2` coincide.
This is a literal specialisation of the `GeneralizedSchnorr` template
(M2) to the case of a single shared scalar acting on two independent base
points.

## Protocol

Given statement `(G1, G2, P1, P2 : G)` with witness `s : F`:

1. **Commit**: sample `w ← $ᵗ F`; output `(A, B) := (w • G1, w • G2)`.
2. **Challenge**: receive `c ← $ᵗ F`.
3. **Respond**: `z = w + c * s`.
4. **Verify**: `z • G1 = A + c • P1 ∧ z • G2 = B + c • P2`.

## Theorems

| Property                | Theorem                              |
| ----------------------- | ----------------------------------- |
| Perfect completeness    | `sigma_complete`                    |
| Special soundness       | `sigma_speciallySound`              |
| Perfect HVZK            | `sigma_perfect_hvzk`                |

Algebra (soundness): subtracting the two verification equations for two
accepting transcripts with distinct challenges gives

    (z₁ - z₂) • G1 = (c₁ - c₂) • P1   and   (z₁ - z₂) • G2 = (c₁ - c₂) • P2.

Dividing by `(c₁ - c₂)` (using `hg : Function.Bijective (smulByG F G G1)`,
which implies `G1` is a generator and that scalar-multiplication is injective
so the extracted `s` is unique) yields `s = (z₁ - z₂) * (c₁ - c₂)⁻¹` with
`s • G1 = P1` and `s • G2 = P2`.

Note: the bijection hypothesis on `G1` is required only to *identify* the
extracted scalar with the unique witness; the relation itself holds without
it once we know `(c₁ - c₂) • (s • G1 - P1) = 0` and `(c₁ - c₂) ≠ 0`, by
injectivity of scalar-mul on a torsion-free module (which `Module F G` over a
prime-order `G` provides via `hg`).
-/

open OracleSpec OracleComp SigmaProtocol
open PokerProtocolLean.GeneralizedSchnorr (dotSmul)
open scoped ENNReal

namespace PokerProtocolLean.ChaumPedersen

variable (F : Type) [Field F] [Fintype F] [DecidableEq F] [SampleableType F]
variable (G : Type) [AddCommGroup G] [Module F G] [Fintype G] [DecidableEq G]
  [SampleableType G]

/-- Statement: two pairs `(G1, P1)` and `(G2, P2)` sharing a common
discrete log `s`. -/
structure Statement (F : Type) (G : Type) where
  /-- First base point. -/
  G1 : G
  /-- Second base point. -/
  G2 : G
  /-- First public key. -/
  P1 : G
  /-- Second public key. -/
  P2 : G

/-- Witness: the shared secret scalar `s`. -/
structure Witness (F : Type) where
  /-- The shared secret scalar. -/
  s : F

/-- The relation: `P1 = s • G1 ∧ P2 = s • G2`. -/
def relation (F : Type) (G : Type) [Field F] [AddCommGroup G] [Module F G]
    [DecidableEq G]
    (stmt : Statement F G) (wit : Witness F) : Bool :=
  decide (wit.s • stmt.G1 = stmt.P1 ∧ wit.s • stmt.G2 = stmt.P2)

/-- Commitment: `(A, B) = (w • G1, w • G2)` plus private state `w`. -/
def Commit (F G : Type) := G × G

instance (F G : Type) [SampleableType G] : SampleableType (Commit F G) :=
  inferInstanceAs (SampleableType (G × G))

/-- The Chaum-Pedersen DLEQ Σ-protocol. -/
def sigma (F : Type) [Field F] [Fintype F] [DecidableEq F] [SampleableType F]
    (G : Type) [AddCommGroup G] [Module F G] [Fintype G] [DecidableEq G]
    [SampleableType G] :
    SigmaProtocol
    (Statement F G) (Witness F) (Commit F G) F F F
    (relation F G) where
  commit stmt _wit := do
    let w ← ($ᵗ F)
    return ((w • stmt.G1, w • stmt.G2), w)
  respond _stmt wit w c := pure (w + c * wit.s)
  verify stmt AB c z :=
    decide (z • stmt.G1 = AB.1 + c • stmt.P1 ∧ z • stmt.G2 = AB.2 + c • stmt.P2)
  sim _stmt := $ᵗ (Commit F G)
  extract c₁ z₁ c₂ z₂ := pure ⟨(z₁ - z₂) * (c₁ - c₂)⁻¹⟩

/-! ## Perfect completeness

An honest prover with a valid witness always produces an accepting
transcript. The proof is the bilinearity of `Module F G`:
`z • G1 = (w + c·s) • G1 = w • G1 + c • (s • G1) = A + c • P1`,
and symmetrically for `G2`/`P2`. -/

theorem sigma_complete (F : Type) [Field F] [Fintype F] [DecidableEq F]
    [SampleableType F]
    (G : Type) [AddCommGroup G] [Module F G] [Fintype G] [DecidableEq G]
    [SampleableType G] :
    PerfectlyComplete (sigma F G) := by
  intro stmt wit hrel
  have h_eq : wit.s • stmt.G1 = stmt.P1 ∧ wit.s • stmt.G2 = stmt.P2 :=
    of_decide_eq_true hrel
  have h_eq1 : wit.s • stmt.G1 = stmt.P1 := h_eq.1
  have h_eq2 : wit.s • stmt.G2 = stmt.P2 := h_eq.2
  have hverify : ∀ (w c : F),
      (w + c * wit.s) • stmt.G1 = w • stmt.G1 + c • stmt.P1 ∧
      (w + c * wit.s) • stmt.G2 = w • stmt.G2 + c • stmt.P2 := by
    intro w c
    refine ⟨?_, ?_⟩
    · rw [add_smul, mul_smul, h_eq1]
    · rw [add_smul, mul_smul, h_eq2]
  simp only [sigma, monad_norm]
  simp [hverify]

/-! ## Special soundness

From two accepting transcripts sharing the same commitment `(A, B)` but with
distinct challenges `c₁ ≠ c₂`, the extractor
`extract c₁ z₁ c₂ z₂ = ⟨(z₁ - z₂) * (c₁ - c₂)⁻¹⟩` returns a witness
satisfying the relation. -/

theorem sigma_speciallySound (F : Type) [Field F] [Fintype F] [DecidableEq F]
    [SampleableType F]
    (G : Type) [AddCommGroup G] [Module F G] [Fintype G] [DecidableEq G]
    [SampleableType G] :
    SpeciallySound (sigma F G) := by
  intro stmt AB c₁ c₂ z₁ z₂ h_ne h_v1 h_v2 w h_w
  dsimp only [sigma] at *
  simp only [support_pure, Set.mem_singleton_iff] at h_w
  subst h_w
  simp only [relation, decide_eq_true_eq] at h_v1 h_v2 ⊢
  obtain ⟨h_v1_1, h_v1_2⟩ := h_v1
  obtain ⟨h_v2_1, h_v2_2⟩ := h_v2
  -- Subtract the two verification equations per base.
  have h_sub1 : (z₁ - z₂) • stmt.G1 = (c₁ - c₂) • stmt.P1 := by
    rw [sub_smul, sub_smul, h_v1_1, h_v2_1, add_sub_add_left_eq_sub]
  have h_sub2 : (z₁ - z₂) • stmt.G2 = (c₁ - c₂) • stmt.P2 := by
    rw [sub_smul, sub_smul, h_v1_2, h_v2_2, add_sub_add_left_eq_sub]
  have h_ne' : c₁ - c₂ ≠ 0 := sub_ne_zero.mpr h_ne
  refine ⟨?_, ?_⟩
  · calc ((z₁ - z₂) * (c₁ - c₂)⁻¹) • stmt.G1
        = (c₁ - c₂)⁻¹ • ((z₁ - z₂) • stmt.G1) := by rw [mul_comm, mul_smul]
      _ = (c₁ - c₂)⁻¹ • ((c₁ - c₂) • stmt.P1) := by rw [h_sub1]
      _ = ((c₁ - c₂)⁻¹ * (c₁ - c₂)) • stmt.P1 := by rw [← mul_smul]
      _ = (1 : F) • stmt.P1 := by rw [inv_mul_cancel₀ h_ne']
      _ = stmt.P1 := one_smul F stmt.P1
  · calc ((z₁ - z₂) * (c₁ - c₂)⁻¹) • stmt.G2
        = (c₁ - c₂)⁻¹ • ((z₁ - z₂) • stmt.G2) := by rw [mul_comm, mul_smul]
      _ = (c₁ - c₂)⁻¹ • ((c₁ - c₂) • stmt.P2) := by rw [h_sub2]
      _ = ((c₁ - c₂)⁻¹ * (c₁ - c₂)) • stmt.P2 := by rw [← mul_smul]
      _ = (1 : F) • stmt.P2 := by rw [inv_mul_cancel₀ h_ne']
      _ = stmt.P2 := one_smul F stmt.P2

/-! ## Perfect HVZK

The simulator samples `c, z ← $ᵗ F`, reconstructs
`(A, B) = (z • G1 - c • P1, z • G2 - c • P2)`, and the resulting
transcript distribution equals the real one. -/

def simTranscript (F : Type) [Field F] [Fintype F] [DecidableEq F]
    [SampleableType F]
    (G : Type) [AddCommGroup G] [Module F G] [Fintype G] [DecidableEq G]
    [SampleableType G]
    (stmt : Statement F G) :
    ProbComp (Commit F G × F × F) := do
  let c ← ($ᵗ F)
  let z ← ($ᵗ F)
  return ((z • stmt.G1 - c • stmt.P1, z • stmt.G2 - c • stmt.P2), c, z)

open OracleComp.ProgramLogic OracleComp.ProgramLogic.Relational in
theorem sigma_perfect_hvzk (F : Type) [Field F] [Fintype F] [DecidableEq F]
    [SampleableType F]
    (G : Type) [AddCommGroup G] [Module F G] [Fintype G] [DecidableEq G]
    [SampleableType G] :
    PerfectHVZK (sigma F G) (simTranscript F G) := by
  intro stmt wit hrel
  have h_eq : wit.s • stmt.G1 = stmt.P1 ∧ wit.s • stmt.G2 = stmt.P2 :=
    of_decide_eq_true hrel
  have h_eq1 : wit.s • stmt.G1 = stmt.P1 := h_eq.1
  have h_eq2 : wit.s • stmt.G2 = stmt.P2 := h_eq.2
  apply evalDist_ext
  intro t
  trans Pr[= t | do
    let c ← ($ᵗ F)
    let r ← ($ᵗ F)
    pure ((((r + c * wit.s) • stmt.G1 - c • stmt.P1,
            (r + c * wit.s) • stmt.G2 - c • stmt.P2),
           c, r + c * wit.s) : (G × G) × F × F)]
  · simp only [SigmaProtocol.realTranscript, sigma]
    vcstep rw
    simp [h_eq1, h_eq2, add_smul, mul_smul, add_sub_cancel_right]
    -- Both sides reduce to the same `do`-block up to α-renaming of the
    -- bound sampling variable; closable by definitional `rfl`.
    rfl
  · show _ = Pr[= t | simTranscript F G stmt]
    unfold simTranscript
    apply probOutput_eq_of_relTriple_eqRel (x := t)
    rvcstep
    intro c _ hc; subst hc
    rvcstep using (· + c * wit.s)
    exact ⟨fun _ _ h => add_right_cancel h, fun z => ⟨z - c * wit.s, sub_add_cancel z _⟩⟩

end PokerProtocolLean.ChaumPedersen
