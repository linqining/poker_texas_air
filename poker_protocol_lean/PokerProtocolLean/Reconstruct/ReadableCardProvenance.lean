import Mathlib.Tactic
import PokerProtocolLean.Foundations.ElGamal

/-!
# Authenticated provenance of `user_readable_cards`

This file formalises the protocol invariant needed by reconstruction.  A
`user_readable_card` is not arbitrary prover input and is not literally an
element copied from `init_deck`.  It is a ciphertext with an authenticated
lineage:

1. `init_deck` stores the canonical card point `m` as `(g, m)`;
2. every join/mask-and-shuffle round adds the joining public key and performs
   a proved re-encryption/permutation;
3. the dealt ciphertext therefore encrypts a canonical `init_deck` plaintext
   under the aggregate public key;
4. valid reveal-token proofs from every player except the owner remove their
   aggregate key share, leaving an ElGamal ciphertext under the owner's key.

The core algebra is machine checked below.  Authentication of each transition
is a state-machine assumption discharged in the concrete protocol by the
remask, shuffle and reveal-token proof verifiers.  This separation is
important: provenance is a protocol-state invariant, not a fact that can be
inferred from the reconstruction proof alone.
-/

namespace PokerProtocolLean.Reconstruct.ReadableCardProvenance

open PokerProtocolLean.Foundations

variable (F : Type) [Field F]
variable (G : Type) [AddCommGroup G] [Module F G]

@[ext]
theorem ciphertext_ext {left right : ElGamalCiphertext G}
    (hc1 : left.c1 = right.c1) (hc2 : left.c2 = right.c2) : left = right := by
  cases left
  cases right
  simp_all

/-- Rust/contract initial card representation: `(base_g, canonical_card)`. -/
def initialCard (g m : G) : ElGamalCiphertext G := ⟨g, m⟩

/-- The unusual initial representation is exactly ElGamal encryption under
the zero aggregate key with randomness one. -/
theorem initialCard_eq_encrypt_zero_key (g m : G) :
    initialCard G g m = ElGamalCiphertext.encrypt F G g m 0 1 := by
  apply ciphertext_ext G
  · simp [initialCard, ElGamalCiphertext.encrypt]
  · simp [initialCard, ElGamalCiphertext.encrypt]

/-- One authenticated player-join transition: first add the player's secret
key mask, then re-encrypt under the enlarged aggregate public key. -/
def joinStep (g oldPk : G) (playerSk rho : F)
    (ct : ElGamalCiphertext G) : ElGamalCiphertext G :=
  ElGamalCiphertext.re_encrypt F G g (oldPk + playerSk • g) rho
    (ElGamalCiphertext.remask F G playerSk ct)

/-- Masking a ciphertext by `playerSk` changes its key from `oldPk` to
`oldPk + playerSk * g` without changing its plaintext or randomness. -/
theorem remask_extends_aggregate_key
    (g oldPk m : G) (r playerSk : F) :
    ElGamalCiphertext.remask F G playerSk
        (ElGamalCiphertext.encrypt F G g m oldPk r) =
      ElGamalCiphertext.encrypt F G g m (oldPk + playerSk • g) r := by
  apply ciphertext_ext G
  · simp [ElGamalCiphertext.remask, ElGamalCiphertext.encrypt]
  · simp [ElGamalCiphertext.remask, ElGamalCiphertext.encrypt,
      smul_add, smul_smul]
    module

/-- A complete join step preserves the canonical plaintext, extends the
aggregate key, and adds the fresh shuffle re-randomizer to the exponent. -/
theorem joinStep_preserves_plaintext
    (g oldPk m : G) (r playerSk rho : F) :
    joinStep F G g oldPk playerSk rho
        (ElGamalCiphertext.encrypt F G g m oldPk r) =
      ElGamalCiphertext.encrypt F G g m (oldPk + playerSk • g) (r + rho) := by
  rw [joinStep, remask_extends_aggregate_key]
  apply ciphertext_ext G
  · simp [ElGamalCiphertext.re_encrypt, ElGamalCiphertext.encrypt, add_smul]
  · simp [ElGamalCiphertext.re_encrypt, ElGamalCiphertext.encrypt, add_smul]
    module

/-- Inductive authenticated lineage from a canonical `init_deck` card through
zero or more proved join/mask/shuffle transitions.  The indices record the
current aggregate public key and accumulated ElGamal exponent. -/
inductive AuthenticatedLineage (g m : G) :
    G → F → ElGamalCiphertext G → Prop
  | init : AuthenticatedLineage g m 0 1 (initialCard G g m)
  | join {oldPk : G} {r : F} {ct : ElGamalCiphertext G}
      (previous : AuthenticatedLineage g m oldPk r ct)
      (playerSk rho : F) :
      AuthenticatedLineage g m (oldPk + playerSk • g) (r + rho)
        (joinStep F G g oldPk playerSk rho ct)

/-- Every authenticated lineage denotes an honest ElGamal encryption of the
same canonical plaintext. -/
theorem lineage_is_canonical_encryption
    {g m aggregatePk : G} {r : F} {ct : ElGamalCiphertext G}
    (h : AuthenticatedLineage F G g m aggregatePk r ct) :
    ct = ElGamalCiphertext.encrypt F G g m aggregatePk r := by
  induction h with
  | init => exact initialCard_eq_encrypt_zero_key F G g m
  | @join oldPk r ct previous playerSk rho ih =>
      rw [ih]
      exact joinStep_preserves_plaintext F G g oldPk m r playerSk rho

/-- Remove the aggregate reveal token of all non-owner players. -/
def removeOtherPlayers (otherSk : F) (ct : ElGamalCiphertext G) :
    ElGamalCiphertext G :=
  ⟨ct.c1, ct.c2 - otherSk • ct.c1⟩

/-- Correct partial decryption changes an aggregate-key ciphertext into an
owner-key ciphertext while retaining the same hidden exponent. -/
theorem partial_decryption_yields_owner_ciphertext
    (g ownerPk m : G) (otherSk r : F) :
    removeOtherPlayers F G otherSk
        (ElGamalCiphertext.encrypt F G g m (ownerPk + otherSk • g) r) =
      ElGamalCiphertext.encrypt F G g m ownerPk r := by
  apply ciphertext_ext G
  · simp [removeOtherPlayers, ElGamalCiphertext.encrypt]
  · simp [removeOtherPlayers, ElGamalCiphertext.encrypt,
      smul_add, smul_smul]
    module

/-- Main provenance theorem for reconstruction input.

If a dealt card has an authenticated lineage from canonical `init_deck`, the
aggregate key decomposes into the owner's key plus all other players' key
shares, and valid partial decryptions remove precisely those other shares,
then the resulting `user_readable_card` is an encryption of the same canonical
card under the owner's public key. -/
theorem authenticated_prior_hand_yields_user_readable_card
    {g m aggregatePk ownerPk : G} {otherSk r : F}
    {dealt readable : ElGamalCiphertext G}
    (hlineage : AuthenticatedLineage F G g m aggregatePk r dealt)
    (haggregate : aggregatePk = ownerPk + otherSk • g)
    (hreadable : readable = removeOtherPlayers F G otherSk dealt) :
    readable = ElGamalCiphertext.encrypt F G g m ownerPk r := by
  rw [hreadable, lineage_is_canonical_encryption F G hlineage, haggregate]
  exact partial_decryption_yields_owner_ciphertext F G g ownerPk m otherSk r

/-- In particular, the readable card's first component is the accumulated
shuffle exponent times the generator. -/
theorem user_readable_c1_eq_accumulated_randomness
    {g m aggregatePk ownerPk : G} {otherSk r : F}
    {dealt readable : ElGamalCiphertext G}
    (hlineage : AuthenticatedLineage F G g m aggregatePk r dealt)
    (haggregate : aggregatePk = ownerPk + otherSk • g)
    (hreadable : readable = removeOtherPlayers F G otherSk dealt) :
    readable.c1 = r • g := by
  rw [authenticated_prior_hand_yields_user_readable_card F G hlineage haggregate hreadable]
  rfl

/-- A single honest uniform re-randomizer hides any fixed accumulated offset:
translation by that offset is a bijection of the scalar field. Combined with
uniform sampling, this is the distributional bridge from authenticated
shuffle freshness to the `FreshDLogHard` experiment for `readable.c1`.

This theorem deliberately does not claim that every fixed group point has an
unknown logarithm; it proves the exact change of variables required by the
average-case argument. -/
theorem honest_rerandomizer_translation_bijective (knownOffset : F) :
    Function.Bijective (fun honestRho : F => knownOffset + honestRho) := by
  constructor
  · intro x y h
    exact add_left_cancel h
  · intro z
    refine ⟨z - knownOffset, ?_⟩
    abel

end PokerProtocolLean.Reconstruct.ReadableCardProvenance
