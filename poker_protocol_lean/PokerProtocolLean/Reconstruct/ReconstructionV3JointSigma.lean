import Mathlib.Algebra.BigOperators.Fin
import Mathlib.Data.Fin.VecNotation
import VCVio.CryptoFoundations.SigmaProtocol
import VCVio.OracleComp.Constructions.SampleableType
import PokerProtocolLean.Schnorr.GeneralizedSchnorr
import PokerProtocolLean.Reconstruct.ReconstructionV3

/-!
# Reconstruction V3 joint cross-key Sigma protocol

The three cross-key equations are encoded as one two-witness generalized
Schnorr relation in the product module `G x G x G`.  This gives a genuinely
shared response for `(ownerSk, contributionRandomness)` and inherits perfect
completeness, special soundness and perfect HVZK from the machine-checked
generalized Schnorr implementation.
-/

open OracleSpec OracleComp SigmaProtocol
open scoped ENNReal

namespace PokerProtocolLean.Reconstruct.V3.JointSigma

variable (F : Type) [Field F] [Fintype F] [DecidableEq F] [SampleableType F]
variable (G : Type) [AddCommGroup G] [Module F G] [Fintype G] [DecidableEq G]
  [SampleableType G]

/-- Product group carrying the public-key, contribution-c1 and joint-c2
equations in one linear relation. -/
abbrev JointGroup := G × G × G

/-- Two public bases, one for `ownerSk` and one for contribution randomness. -/
def bases (g aggregatePk : G) (readable : Foundations.ElGamalCiphertext G) :
    Fin 2 → JointGroup G :=
  ![(g, 0, readable.c1), (0, g, aggregatePk)]

/-- Public target for the joint relation. -/
def toStatement (g ownerPk aggregatePk : G)
    (readable contribution : Foundations.ElGamalCiphertext G) :
    GeneralizedSchnorr.Statement F (JointGroup G) 2 where
  base_points := bases G g aggregatePk readable
  R := (ownerPk, contribution.c1, readable.c2 + contribution.c2)

/-- Shared two-scalar witness. -/
def toWitness (ownerSk contributionRandomness : F) :
    GeneralizedSchnorr.Witness F 2 where
  scalars := ![ownerSk, contributionRandomness]

/-- The generalized Schnorr relation is exactly the conjunction of the three
cross-key equations. -/
theorem relation_iff_cross_key
    (g ownerPk aggregatePk : G)
    (readable contribution : Foundations.ElGamalCiphertext G)
    (ownerSk contributionRandomness : F) :
    GeneralizedSchnorr.relation F (JointGroup G) 2
      (toStatement F G g ownerPk aggregatePk readable contribution)
      (toWitness F ownerSk contributionRandomness) = true ↔
    CrossKeyNegationRelation F G g ownerPk aggregatePk readable contribution
      ownerSk contributionRandomness := by
  simp only [GeneralizedSchnorr.relation, decide_eq_true_eq,
    GeneralizedSchnorr.dotSmul, Fin.sum_univ_two]
  simp [toStatement, toWitness, bases, CrossKeyNegationRelation,
    Prod.smul_mk]
  constructor
  · rintro ⟨hpk, hc1, hc2⟩
    exact ⟨hpk.symm, hc1.symm, hc2⟩
  · rintro ⟨hpk, hc1, hc2⟩
    exact ⟨hpk.symm, hc1.symm, hc2⟩

/-- The concrete joint-linear Sigma protocol. -/
def sigma : SigmaProtocol
    (GeneralizedSchnorr.Statement F (JointGroup G) 2)
    (GeneralizedSchnorr.Witness F 2)
    (JointGroup G) (Fin 2 → F) F (Fin 2 → F)
    (GeneralizedSchnorr.relation F (JointGroup G) 2) :=
  GeneralizedSchnorr.sigma F (JointGroup G) 2

/-- Perfect completeness of the joint cross-key proof. -/
theorem sigma_complete : PerfectlyComplete (sigma F G) :=
  GeneralizedSchnorr.sigma_complete F (JointGroup G) 2

/-- Special soundness extracts the same `(ownerSk, contributionRandomness)`
from two accepting transcripts with distinct challenges. -/
theorem sigma_speciallySound : SpeciallySound (sigma F G) :=
  GeneralizedSchnorr.sigma_speciallySound F (JointGroup G) 2

/-- Perfect honest-verifier zero knowledge of the joint cross-key proof. -/
theorem sigma_perfect_hvzk :
    PerfectHVZK (sigma F G)
      (fun stmt => GeneralizedSchnorr.simTranscript F (JointGroup G) 2 stmt) :=
  GeneralizedSchnorr.sigma_perfect_hvzk F (JointGroup G) 2

end PokerProtocolLean.Reconstruct.V3.JointSigma
