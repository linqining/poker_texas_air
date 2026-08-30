import PokerProtocolLean.Reconstruct.ReconstructProof

/-!
# Reconstruction audit sanity checks

These checks intentionally exercise the audited boundary.  They no longer
refer to the removed `Unit`/`True` Sigma-protocol placeholder.
-/

namespace PokerProtocolLean.Sanity.ReconstructSanity

open PokerProtocolLean.Foundations

variable (F : Type) [Field F]
variable (G : Type) [AddCommGroup G] [Module F G]

/-- Regression check for the machine-checked v2 misplaced-swap attack. -/
example (g pk A B : G) (r s : F) :
    PokerProtocolLean.Reconstruct.V2Counterexample.correctedRelation F G g pk B
      (ElGamalCiphertext.encrypt F G g (B - A) pk r)
      (ElGamalCiphertext.encrypt F G g A pk s)
      (r + s) :=
  PokerProtocolLean.Reconstruct.rust_v2_relation_has_misplaced_swap_counterexample
    F G g pk A B r s

/-- Regression check that public ElGamal randomness reveals the plaintext. -/
example (g pk m : G) (r : F) :
    (ElGamalCiphertext.encrypt F G g m pk r).c2 - r • pk = m :=
  PokerProtocolLean.Reconstruct.rust_v2_public_randomness_recovers_plaintext
    F G g pk m r

/-- Regression check for the repaired joint cross-key relation. -/
example (g ownerPk aggregatePk m : G)
    (ownerSk readableRandomness contributionRandomness : F)
    (hpk : ownerPk = ownerSk • g) :
    PokerProtocolLean.Reconstruct.V3.CrossKeyNegationRelation F G
      g ownerPk aggregatePk
      (ElGamalCiphertext.encrypt F G g m ownerPk readableRandomness)
      (ElGamalCiphertext.encrypt F G g (-m) aggregatePk contributionRandomness)
      ownerSk contributionRandomness :=
  PokerProtocolLean.Reconstruct.V3.cross_key_negation_complete F G
    g ownerPk aggregatePk m ownerSk readableRandomness contributionRandomness hpk

end PokerProtocolLean.Sanity.ReconstructSanity
