import Mathlib.Algebra.BigOperators.Fin
import Mathlib.Algebra.Module.BigOperators
import Mathlib.Tactic.Module
import VCVio.CryptoFoundations.SigmaProtocol
import VCVio.OracleComp.Constructions.SampleableType
import PokerProtocolLean.Foundations.AlgebraicSetup
import PokerProtocolLean.Foundations.ElGamal
import PokerProtocolLean.Shuffle.ShuffleRelation
import PokerProtocolLean.Shuffle.ShuffleSigmaProtocol

/-!
# ZKShuffleProof — perfect completeness (M6-H3)

Backing `poker_protocol/soundness.md` §二 (Layer 1, "honest prover" branch).

For an honest shuffle `output[j] = re_encrypt(input[π(j)], pk, r_j)`, the
re-encryption identity `output[j].c1 = input[π(j)].c1 + r_j • g` and the
bijectivity of `π` give the public linear equation

    (Σ_j r_values j) • g = (Σ_j output[j].c1) − (Σ_i input[i].c1) = combinedTarget.

The honest prover's response `s_j = r_vec j + c * r_values j` then satisfies
the verification equation

    (Σ_j s j) • g = (Σ_j r_vec j) • g + c • ((Σ_j r_values j) • g)
                  = T + c • combinedTarget

by bilinearity of the `Module F G` action. This holds for every `(r_vec, c)`
drawn by the honest prover, so `Pr[verify = true | …] = 1`.
-/

open OracleSpec OracleComp SigmaProtocol
open PokerProtocolLean.Foundations (ElGamalCiphertext)
open scoped ENNReal

namespace PokerProtocolLean.Shuffle

variable (F : Type) [Field F] [Fintype F] [DecidableEq F] [SampleableType F]
variable (G : Type) [AddCommGroup G] [Module F G] [Fintype G] [DecidableEq G]
  [SampleableType G]

set_option linter.unusedSectionVars false in
/-- **Perfect completeness of the ZKShuffle Σ-protocol.** -/
theorem sigma_complete (g : G) (n : ℕ) :
    PerfectlyComplete (sigma F G g n) := by
  intro stmt wit hrel
  classical
  -- Convert hrel to the explicit decide form, matching shuffleRelation's
  -- `Classical.dec` instance.
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
  -- Key identity: (Σ r_values j) • g = combinedTarget.
  have h_target : (∑ j : Fin n, wit.r_values j) • g = combinedTarget F G stmt := by
    show (∑ j : Fin n, wit.r_values j) • g =
      (∑ j : Fin n, (stmt.output_cts j).c1) - (∑ j : Fin n, (stmt.input_cts j).c1)
    -- From re_encrypt: output[j].c1 = input[π(j)].c1 + r_values[j] • g.
    have h_c1 : ∀ j, (stmt.output_cts j).c1 =
      (stmt.input_cts (wit.permute j)).c1 + wit.r_values j • g := by
      intro j
      rw [h_reenc j, ElGamalCiphertext.re_encrypt]
    -- Substitute output[j].c1 = input[π(j)].c1 + r_values[j] • g.
    rw [show (∑ j : Fin n, (stmt.output_cts j).c1) =
          (∑ j : Fin n, ((stmt.input_cts (wit.permute j)).c1 + wit.r_values j • g)) from
        Finset.sum_congr rfl (fun j _ => h_c1 j)]
    -- Split: Σ (a + b) = Σ a + Σ b.
    rw [Finset.sum_add_distrib]
    -- Reindex Σ input[π(j)].c1 = Σ input[i].c1 by bijectivity of π.
    rw [Function.Bijective.sum_comp h_bij (fun i => (stmt.input_cts i).c1)]
    -- Cancel: (Σ input.c1) + (Σ r_values • g) - (Σ input.c1) = (Σ r_values • g).
    rw [add_sub_cancel_left]
    -- (Σ r_values[j]) • g = Σ (r_values[j] • g)  [scalar-sum distributivity]
    rw [Finset.sum_smul]
  -- The verify equation holds for every (r_vec, c).
  have hverify : ∀ (r_vec : Fin n → F) (c : F),
    (∑ j : Fin n, (r_vec j + c * wit.r_values j)) • g =
      (∑ j : Fin n, r_vec j) • g + c • combinedTarget F G stmt := by
    intro r_vec c
    -- Scalar identity: Σ (r_vec + c * r_values) = Σ r_vec + c * Σ r_values
    have h_sum : ∑ j : Fin n, (r_vec j + c * wit.r_values j) =
        (∑ j : Fin n, r_vec j) + c * (∑ j : Fin n, wit.r_values j) := by
      rw [Finset.sum_add_distrib, ← Finset.mul_sum]
    -- Substitute and use bilinearity.
    rw [h_sum, add_smul, mul_smul, h_target]
  -- The probability that verify returns true is 1.
  simp only [sigma, monad_norm]
  simp [hverify]

end PokerProtocolLean.Shuffle
