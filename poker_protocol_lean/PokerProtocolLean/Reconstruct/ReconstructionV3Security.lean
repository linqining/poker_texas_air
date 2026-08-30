import PokerProtocolLean.Reconstruct.ReconstructionV3
import PokerProtocolLean.Reconstruct.ReconstructionV3JointSigma
import PokerProtocolLean.Reconstruct.ReconstructionV3SlotOr

/-!
# Conditional end-to-end security theorem for Reconstruction V3

The algebraic V3 relation, joint cross-key Σ protocol and slot OR algebra are
machine checked in concrete modules. The production Rust proof additionally
contains Bayer--Groth and applies Fiat--Shamir to a shared sequential
transcript. This file makes that remaining boundary explicit as theorem
hypotheses rather than introducing protocol-specific axioms or claiming an
unproved unconditional result.

The contract separates:

1. component security of the exact Bayer--Groth implementation;
2. Fiat--Shamir extraction and sequential simulator composition in the ROM;
3. byte-level Rust/Lean statement and transcript refinement;
4. authenticated prior-state provenance and cross-player disjointness.

Any paper theorem instantiating this contract must discharge every field for
the concrete curve, serialization, transcript order and adversary model.
-/

namespace PokerProtocolLean.Reconstruct.V3.Security

open PokerProtocolLean.Reconstruct.V3

variable (F : Type) [Field F]
variable (G : Type) [AddCommGroup G] [Module F G]
variable {n k : ℕ}

/-- Exact unmechanized obligations for the production non-interactive proof. -/
structure ComponentAssumptions where
  bayerGrothPerfectCompleteness : Prop
  bayerGrothKnowledgeSoundness : Prop
  bayerGrothZeroKnowledge : Prop
  fiatShamirForkingInROM : Prop
  sequentialCompositionZK : Prop
  transcriptStatementBinding : Prop
  rustLeanSerializationRefinement : Prop
  authenticatedPriorState : Prop
  crossPlayerReadableDisjointness : Prop

/-- All production-layer obligations are available. -/
def ComponentAssumptions.Hold (a : ComponentAssumptions) : Prop :=
  a.bayerGrothPerfectCompleteness ∧
  a.bayerGrothKnowledgeSoundness ∧
  a.bayerGrothZeroKnowledge ∧
  a.fiatShamirForkingInROM ∧
  a.sequentialCompositionZK ∧
  a.transcriptStatementBinding ∧
  a.rustLeanSerializationRefinement ∧
  a.authenticatedPriorState ∧
  a.crossPlayerReadableDisjointness

/-- Abstract interface to the exact Rust proof bytes and verifier. -/
structure Implementation (Proof View : Type) where
  prove : Statement G n k → Witness F n k → Proof
  verify : Statement G n k → Proof → Prop
  realView : Statement G n k → Witness F n k → View
  simulatedView : Statement G n k → View

/-- Reduction obligations connecting component assumptions to the concrete
implementation. `Indistinguishable` is the paper's computational
indistinguishability relation for the chosen security parameter family. -/
structure Reduction (Proof View : Type) (impl : Implementation F G Proof View)
    (assumptions : ComponentAssumptions)
    (Indistinguishable : View → View → Prop) where
  completeness : assumptions.Hold →
    ∀ stmt wit, ValidRelation F G stmt wit → impl.verify stmt (impl.prove stmt wit)
  extract : Statement G n k → Proof → Option (Witness F n k)
  knowledgeSoundness : assumptions.Hold →
    ∀ stmt proof, WellFormedStatement G stmt → impl.verify stmt proof →
      ∃ wit, extract stmt proof = some wit ∧ Relation F G stmt wit
  zeroKnowledge : assumptions.Hold →
    ∀ stmt wit, ValidRelation F G stmt wit →
      Indistinguishable (impl.realView stmt wit) (impl.simulatedView stmt)

/-- Conditional protocol completeness for the exact Rust implementation. -/
theorem completeness_under_assumptions
    {Proof View : Type} (impl : Implementation F G Proof View)
    (assumptions : ComponentAssumptions)
    (Indistinguishable : View → View → Prop)
    (reduction : Reduction F G Proof View impl assumptions Indistinguishable)
    (hassumptions : assumptions.Hold)
    (stmt : Statement G n k) (wit : Witness F n k)
    (hvalid : ValidRelation F G stmt wit) :
    impl.verify stmt (impl.prove stmt wit) :=
  reduction.completeness hassumptions stmt wit hvalid

/-- Conditional knowledge soundness plus the concrete semantic consequence:
every accepted contribution is an encryption of either zero or its own
canonical negative card. -/
theorem knowledge_soundness_under_assumptions
    {Proof View : Type} (impl : Implementation F G Proof View)
    (assumptions : ComponentAssumptions)
    (Indistinguishable : View → View → Prop)
    (reduction : Reduction F G Proof View impl assumptions Indistinguishable)
    (hassumptions : assumptions.Hold)
    (stmt : Statement G n k) (proof : Proof)
    (hwellFormed : WellFormedStatement G stmt)
    (haccept : impl.verify stmt proof) :
    ∃ wit, reduction.extract stmt proof = some wit ∧
      Relation F G stmt wit ∧
      ∀ i,
        stmt.contributions i =
            PokerProtocolLean.Foundations.ElGamalCiphertext.encrypt F G stmt.g 0
              stmt.aggregatePk (wit.contributionRandomness i) ∨
        stmt.contributions i =
            PokerProtocolLean.Foundations.ElGamalCiphertext.encrypt F G stmt.g
              (-(stmt.cards i)) stmt.aggregatePk (wit.contributionRandomness i) := by
  rcases reduction.knowledgeSoundness hassumptions stmt proof hwellFormed haccept with
    ⟨wit, hextract, hrel⟩
  exact ⟨wit, hextract, hrel,
    accepted_contribution_is_zero_or_negative_card F G stmt wit hrel⟩

/-- Conditional computational zero knowledge for the exact non-interactive
view, under the explicitly supplied ROM/composition/refinement assumptions. -/
theorem zero_knowledge_under_assumptions
    {Proof View : Type} (impl : Implementation F G Proof View)
    (assumptions : ComponentAssumptions)
    (Indistinguishable : View → View → Prop)
    (reduction : Reduction F G Proof View impl assumptions Indistinguishable)
    (hassumptions : assumptions.Hold)
    (stmt : Statement G n k) (wit : Witness F n k)
    (hvalid : ValidRelation F G stmt wit) :
    Indistinguishable (impl.realView stmt wit) (impl.simulatedView stmt) :=
  reduction.zeroKnowledge hassumptions stmt wit hvalid

end PokerProtocolLean.Reconstruct.V3.Security
