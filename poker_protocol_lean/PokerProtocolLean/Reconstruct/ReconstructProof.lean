import PokerProtocolLean.Reconstruct.ReconstructV2Counterexample
import PokerProtocolLean.Reconstruct.ReadableCardProvenance
import PokerProtocolLean.Reconstruct.ReconstructionV3
import PokerProtocolLean.Reconstruct.ReconstructionV3JointSigma
import PokerProtocolLean.Reconstruct.ReconstructionV3SlotOr
import PokerProtocolLean.Reconstruct.ReconstructionV3Security

/-!
# Reconstruction proof: audited top-level status

This module replaces the former `Unit` witness / `True` relation placeholder.
That placeholder proved properties of a verifier that always returned `true`;
it did **not** prove anything about the Rust reconstruction protocol and is not
an acceptable basis for a security claim.

The top-level formal result is now deliberately split:

* `ReconstructV2Counterexample` proves that the current Rust v2 relation is
  insufficient for soundness and zero knowledge;
* `ReadableCardProvenance` proves the authenticated `init_deck`-to-prior-hand
  lineage algebra;
* `ReconstructionV3` specifies the repaired extracted relation and proves its
  deterministic completeness and semantic soundness consequences;
* `ReconstructionV3JointSigma` proves perfect completeness, special soundness
  and perfect HVZK for the genuinely shared cross-key linear proof.
* `ReconstructionV3SlotOr` proves honest acceptance, two-fork extraction and
  the algebraic perfect-HVZK simulation argument for slot membership.
* `ReconstructionV3Security` states the conditional end-to-end completeness,
  knowledge-soundness and computational-ZK theorems with every production
  Bayer--Groth/ROM/refinement obligation exposed as a hypothesis.

No theorem in this file claims Fiat--Shamir knowledge soundness or zero
knowledge for Rust v2.  Such a theorem would be false.  A computational V3
theorem additionally requires a faithful Bayer--Groth formalisation, a
Fiat--Shamir random-oracle composition theorem and a checked Rust
serialization/state-binding refinement.
-/

namespace PokerProtocolLean.Reconstruct

open PokerProtocolLean.Foundations

variable (F : Type) [Field F]
variable (G : Type) [AddCommGroup G] [Module F G]

/-- Audited v2 failure: the checked corrected-ciphertext equation accepts a
swap plaintext at the wrong canonical slot. -/
theorem rust_v2_relation_has_misplaced_swap_counterexample
    (g pk A B : G) (r s : F) :
    V2Counterexample.correctedRelation F G g pk B
      (ElGamalCiphertext.encrypt F G g (B - A) pk r)
      (ElGamalCiphertext.encrypt F G g A pk s)
      (r + s) :=
  V2Counterexample.misplaced_swap_satisfies_corrected_relation F G g pk A B r s

/-- Audited v2 privacy failure: public encryption randomness reveals the
plaintext without a secret key. -/
theorem rust_v2_public_randomness_recovers_plaintext
    (g pk m : G) (r : F) :
    (ElGamalCiphertext.encrypt F G g m pk r).c2 - r • pk = m :=
  V2Counterexample.recover_plaintext_from_known_randomness F G g pk m r

end PokerProtocolLean.Reconstruct
