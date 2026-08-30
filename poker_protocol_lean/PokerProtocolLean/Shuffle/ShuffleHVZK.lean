import Mathlib.Algebra.BigOperators.Fin
import Mathlib.Algebra.Module.BigOperators
import Mathlib.Tactic.Module
import VCVio.CryptoFoundations.SigmaProtocol
import VCVio.OracleComp.Constructions.SampleableType
import VCVio.ProgramLogic.Tactics.Unary
import VCVio.ProgramLogic.Tactics.Relational
import PokerProtocolLean.Foundations.AlgebraicSetup
import PokerProtocolLean.Foundations.ElGamal
import PokerProtocolLean.Shuffle.ShuffleRelation
import PokerProtocolLean.Shuffle.ShuffleSigmaProtocol

/-!
# ZKShuffleProof — perfect HVZK (M6-H4)

Backing `poker_protocol/soundness.md` §二 (ZK property).

The ZKShuffle Σ-protocol's combined-layer core is a multi-base Schnorr
proof on the linear equation `(Σ_j r_values j) • g = combinedTarget`.
The simulator samples `(c, s_vec)` uniformly and reconstructs the
commitment `T = (Σ_j s_vec j) • g - c • combinedTarget` from the
verification equation. The resulting transcript distribution equals the
real one via the per-coordinate translation bijection
`r_vec ↦ fun j => r_vec j + c * wit.r_values j` (exactly as in
`GeneralizedSchnorr.sigma_perfect_hvzk`).
-/

open OracleSpec OracleComp SigmaProtocol
open PokerProtocolLean.Foundations (ElGamalCiphertext)
open OracleComp.ProgramLogic OracleComp.ProgramLogic.Relational
open scoped ENNReal

namespace PokerProtocolLean.Shuffle

variable (F : Type) [Field F] [Fintype F] [DecidableEq F] [SampleableType F]
variable (G : Type) [AddCommGroup G] [Module F G] [Fintype G] [DecidableEq G]
  [SampleableType G]

/-- The ZKShuffle HVZK simulator: sample `(c, s_vec)` uniformly and
reconstruct `T = (Σ_j s_vec j) • g - c • combinedTarget` from the
verification equation. -/
def simTranscript (g : G) (n : ℕ) (stmt : ShuffleStatement F G n) :
    ProbComp (G × F × (Fin n → F)) := do
  let c ← ($ᵗ F)
  let s ← ($ᵗ (Fin n → F))
  pure ((∑ j : Fin n, s j) • g - c • combinedTarget F G stmt, c, s)

/-! **Perfect HVZK for the ZKShuffle Σ-protocol.**

The proof is the literal multi-base-Schnorr lift of
`GeneralizedSchnorr.sigma_perfect_hvzk`, specialised to the single-base
case `base_points j = g` with the public target `combinedTarget`. See
that file for the proof structure; the bilinearity identity is
`hverify` below, and the witness-validity identity is `h_target`. -/
set_option linter.unusedSectionVars false in
theorem sigma_perfect_hvzk (g : G) (n : ℕ) :
    PerfectHVZK (sigma F G g n) (simTranscript F G g n) := by
  intro stmt wit hrel
  classical
  -- Extract witness validity from hrel (matching shuffleRelation's Classical.dec).
  have h : @decide
      (Function.Bijective wit.permute ∧
        ∀ j, stmt.output_cts j =
          ElGamalCiphertext.re_encrypt F G g stmt.pk (wit.r_values j)
            (stmt.input_cts (wit.permute j)))
      (Classical.dec
        (Function.Bijective wit.permute ∧
          ∀ j, stmt.output_cts j =
            ElGamalCiphertext.re_encrypt F G g stmt.pk (wit.r_values j)
              (stmt.input_cts (wit.permute j))))
      = true := hrel
  have h_eq :
    Function.Bijective wit.permute ∧
      ∀ j, stmt.output_cts j =
        ElGamalCiphertext.re_encrypt F G g stmt.pk (wit.r_values j)
          (stmt.input_cts (wit.permute j)) :=
    @of_decide_eq_true _ (Classical.dec _) h
  have h_bij : Function.Bijective wit.permute := h_eq.1
  have h_reenc : ∀ j, stmt.output_cts j =
    ElGamalCiphertext.re_encrypt F G g stmt.pk (wit.r_values j)
      (stmt.input_cts (wit.permute j)) := h_eq.2
  -- Key identity (Σ r_values j) • g = combinedTarget (re-proved from h_reenc).
  have h_target : (∑ j : Fin n, wit.r_values j) • g = combinedTarget F G stmt := by
    show (∑ j : Fin n, wit.r_values j) • g =
      (∑ j : Fin n, (stmt.output_cts j).c1) - (∑ j : Fin n, (stmt.input_cts j).c1)
    have h_c1 : ∀ j, (stmt.output_cts j).c1 =
      (stmt.input_cts (wit.permute j)).c1 + wit.r_values j • g := by
      intro j
      rw [h_reenc j, ElGamalCiphertext.re_encrypt]
    rw [show (∑ j : Fin n, (stmt.output_cts j).c1) =
          (∑ j : Fin n, ((stmt.input_cts (wit.permute j)).c1 + wit.r_values j • g)) from
        Finset.sum_congr rfl (fun j _ => h_c1 j)]
    rw [Finset.sum_add_distrib,
        Function.Bijective.sum_comp h_bij (fun i => (stmt.input_cts i).c1),
        add_sub_cancel_left, Finset.sum_smul]
  -- Bilinearity identity underlying the bridge:
  -- (Σ (r_vec + c · r_values) j) • g = (Σ r_vec j) • g + c • combinedTarget.
  have hverify : ∀ (r_vec : Fin n → F) (c : F),
    (∑ j : Fin n, (r_vec j + c * wit.r_values j)) • g =
      (∑ j : Fin n, r_vec j) • g + c • combinedTarget F G stmt := by
    intro r_vec c
    have h_sum : ∑ j : Fin n, (r_vec j + c * wit.r_values j) =
        (∑ j : Fin n, r_vec j) + c * (∑ j : Fin n, wit.r_values j) := by
      rw [Finset.sum_add_distrib, ← Finset.mul_sum]
    rw [h_sum, add_smul, mul_smul, h_target]
  -- Reduce to pointwise probability equality at an arbitrary t.
  apply evalDist_ext
  intro t
  -- Bridge real transcript to independent form
  -- ((Σ (r_vec + c·r_values) j) • g - c • combinedTarget, c, r_vec + c·r_values).
  trans Pr[= t | do
    let c ← ($ᵗ F)
    let r_vec ← ($ᵗ (Fin n → F))
    pure (((∑ j : Fin n, (r_vec j + c * wit.r_values j)) • g
            - c • combinedTarget F G stmt,
           c,
           fun j => r_vec j + c * wit.r_values j) : G × F × (Fin n → F))]
  · simp only [SigmaProtocol.realTranscript, sigma]
    vcstep rw
    -- Bridge by the bilinearity identity:
    -- (Σ r_vec j) • g = (Σ (r_vec + c · r_values) j) • g - c • combinedTarget.
    have h_bridge : ∀ (r_vec : Fin n → F) (c : F),
        (∑ j : Fin n, r_vec j) • g =
          (∑ j : Fin n, (r_vec j + c * wit.r_values j)) • g
            - c • combinedTarget F G stmt := by
      intro r_vec c
      rw [hverify, add_sub_cancel_right]
    -- simp can't see through __x.1; use `simp [h_bridge]` (without `only`)
    -- so the simplifier can also unfold the let-binding via monad_norm.
    simp [add_sub_cancel_right, hverify]
  · show _ = Pr[= t | simTranscript F G g n stmt]
    unfold simTranscript
    -- Bridge simulator to the same independent form via the
    -- per-coordinate translation bijection r_vec ↦ r_vec + c · wit.r_values.
    apply probOutput_eq_of_relTriple_eqRel (x := t)
    rvcstep
    intro c _ hc; subst hc
    rvcstep using (fun rv j => rv j + c * wit.r_values j)
    -- Goal: Function.Bijective (fun rv j => rv j + c * wit.r_values j).
    -- Injectivity: pointwise add_right_cancel.
    -- Surjectivity: inverse is (s ↦ s - c · wit.r_values), pointwise sub_add_cancel.
    refine ⟨fun rv rv' h => funext fun j => add_right_cancel (congrFun h j),
            fun s => ⟨fun j => s j - c * wit.r_values j,
                       funext fun j => sub_add_cancel (s j) _⟩⟩

end PokerProtocolLean.Shuffle
