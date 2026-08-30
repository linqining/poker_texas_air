import Mathlib.Tactic
import Mathlib.Algebra.BigOperators.Group.Finset.Basic
import PokerProtocolLean.Foundations.ElGamal
import PokerProtocolLean.Reconstruct.ReconstructV2Counterexample
import PokerProtocolLean.Reconstruct.ReadableCardProvenance

/-!
# Reconstruction V3: a sound ideal relation

This module gives the machine-checked algebraic specification that a repaired
reconstruction proof must establish.  It is intentionally separated from the
current Rust v2 verifier, which does not establish this relation (see
`ReconstructV2Counterexample.lean`).

The repair has two essential bindings:

1. **slot binding:** at canonical slot `i`, the player's contribution is an
   encryption under the aggregate key of either `0` or `-cards[i]`;
2. **readable-card binding:** every `-cards[i]` branch is in one-to-one
   correspondence with an authenticated prior-hand readable ciphertext for
   `cards[i]`.

The first binding can be implemented by a zero-knowledge OR proof.  The second
uses a joint generalized Schnorr relation across the owner key and aggregate
key.  Bayer--Groth may hide the permutation/matching, but it cannot replace the
per-slot OR relation.

This file proves deterministic completeness and the semantic soundness
consequences of the extracted relation.  Computational knowledge soundness and
Fiat--Shamir zero knowledge are conditional on concrete special-sound/HVZK
proofs for the OR, joint-linear and Bayer--Groth components; the trust boundary
is documented in `SECURITY_RECONSTRUCTION.md`.
-/

namespace PokerProtocolLean.Reconstruct.V3

open PokerProtocolLean.Foundations
open PokerProtocolLean.Reconstruct.V2Counterexample
open scoped BigOperators

variable (F : Type) [Field F]
variable (G : Type) [AddCommGroup G] [Module F G]

/-- Public reconstruction-v3 statement.  Hidden card indices, permutation and
all encryption randomness live only in `Witness`. -/
structure Statement (n k : ℕ) where
  g : G
  aggregatePk : G
  ownerPk : G
  cards : Fin n → G
  contributions : Fin n → ElGamalCiphertext G
  readableCards : Fin k → ElGamalCiphertext G

/-- Fail-closed public-statement conditions corresponding to the Rust V3
validator. Historical authentication of `readableCards` is deliberately not
included here; it is supplied by `ReadableCardProvenance` and the state root. -/
def WellFormedStatement {n k : ℕ} (stmt : Statement G n k) : Prop :=
  1 < n ∧
  0 < k ∧
  k ≤ n ∧
  stmt.g ≠ 0 ∧
  stmt.aggregatePk ≠ 0 ∧
  stmt.ownerPk ≠ 0 ∧
  Function.Injective stmt.cards ∧
  (∀ i, stmt.cards i ≠ 0) ∧
  (∀ i, (stmt.contributions i).c1 ≠ 0 ∧ (stmt.contributions i).c2 ≠ 0) ∧
  (∀ j, (stmt.readableCards j).c1 ≠ 0 ∧ (stmt.readableCards j).c2 ≠ 0)

/-- Extractable witness for the repaired statement.

`readableIndex` is injective, and `removed_iff_readable` gives exact coverage:
there are no duplicate readable cards and no unbacked removal branch. -/
structure Witness (n k : ℕ) where
  removed : Fin n → Bool
  contributionRandomness : Fin n → F
  readableIndex : Fin k → Fin n
  readableRandomness : Fin k → F
  readableIndex_injective : Function.Injective readableIndex
  removed_iff_readable : ∀ i, removed i = true ↔ ∃ j, readableIndex j = i

/-- Intended contribution plaintext at one canonical slot. -/
def contributionMessage (card : G) (removed : Bool) : G :=
  if removed then -card else 0

/-- Ideal extracted relation for reconstruction v3. -/
def Relation {n k : ℕ} (stmt : Statement G n k) (wit : Witness F n k) : Prop :=
  (∀ i, stmt.contributions i =
    ElGamalCiphertext.encrypt F G stmt.g
      (contributionMessage G (stmt.cards i) (wit.removed i))
      stmt.aggregatePk (wit.contributionRandomness i)) ∧
  (∀ j, stmt.readableCards j =
    ElGamalCiphertext.encrypt F G stmt.g
      (stmt.cards (wit.readableIndex j)) stmt.ownerPk
      (wit.readableRandomness j))

/-- Deterministic completeness of the ideal relation: honest ciphertext
equations construct a valid witness relation directly. -/
theorem relation_complete {n k : ℕ}
    (stmt : Statement G n k) (wit : Witness F n k)
    (hcontribution : ∀ i, stmt.contributions i =
      ElGamalCiphertext.encrypt F G stmt.g
        (contributionMessage G (stmt.cards i) (wit.removed i))
        stmt.aggregatePk (wit.contributionRandomness i))
    (hreadable : ∀ j, stmt.readableCards j =
      ElGamalCiphertext.encrypt F G stmt.g
        (stmt.cards (wit.readableIndex j)) stmt.ownerPk
        (wit.readableRandomness j)) :
    Relation F G stmt wit :=
  ⟨hcontribution, hreadable⟩

/-- Paper-level algebraic statement packages fail-closed public validity with
the extracted witness relation. -/
def ValidRelation {n k : ℕ} (stmt : Statement G n k) (wit : Witness F n k) : Prop :=
  WellFormedStatement G stmt ∧ Relation F G stmt wit

/-- Honest public validity plus the honest encryption equations establishes
the full V3 algebraic statement. -/
theorem valid_relation_complete {n k : ℕ}
    (stmt : Statement G n k) (wit : Witness F n k)
    (hwellFormed : WellFormedStatement G stmt)
    (hcontribution : ∀ i, stmt.contributions i =
      ElGamalCiphertext.encrypt F G stmt.g
        (contributionMessage G (stmt.cards i) (wit.removed i))
        stmt.aggregatePk (wit.contributionRandomness i))
    (hreadable : ∀ j, stmt.readableCards j =
      ElGamalCiphertext.encrypt F G stmt.g
        (stmt.cards (wit.readableIndex j)) stmt.ownerPk
        (wit.readableRandomness j)) :
    ValidRelation F G stmt wit :=
  ⟨hwellFormed, relation_complete F G stmt wit hcontribution hreadable⟩

/-- The readable-card half of the V3 relation follows from authenticated
prior-hand provenance, rather than being trusted as arbitrary prover input. -/
theorem readable_equations_of_authenticated_lineage {n k : ℕ}
    (stmt : Statement G n k) (wit : Witness F n k)
    (hprovenance : ∀ j, ∃ (priorAggregatePk : G) (otherSk : F)
        (dealt : ElGamalCiphertext G),
      ReadableCardProvenance.AuthenticatedLineage F G stmt.g
        (stmt.cards (wit.readableIndex j)) priorAggregatePk
        (wit.readableRandomness j) dealt ∧
      priorAggregatePk = stmt.ownerPk + otherSk • stmt.g ∧
      stmt.readableCards j =
        ReadableCardProvenance.removeOtherPlayers F G otherSk dealt) :
    ∀ j, stmt.readableCards j =
      ElGamalCiphertext.encrypt F G stmt.g
        (stmt.cards (wit.readableIndex j)) stmt.ownerPk
        (wit.readableRandomness j) := by
  intro j
  rcases hprovenance j with ⟨priorAggregatePk, otherSk, dealt,
    hlineage, haggregate, hreadable⟩
  exact ReadableCardProvenance.authenticated_prior_hand_yields_user_readable_card
    F G hlineage haggregate hreadable

/-- Semantic slot soundness: extraction yields exactly one of the two allowed
plaintext branches, never the v2 plaintext `B - A` counterexample. -/
theorem accepted_contribution_is_zero_or_negative_card {n k : ℕ}
    (stmt : Statement G n k) (wit : Witness F n k)
    (hrel : Relation F G stmt wit) (i : Fin n) :
    stmt.contributions i =
        ElGamalCiphertext.encrypt F G stmt.g 0 stmt.aggregatePk
          (wit.contributionRandomness i) ∨
    stmt.contributions i =
        ElGamalCiphertext.encrypt F G stmt.g (-(stmt.cards i)) stmt.aggregatePk
          (wit.contributionRandomness i) := by
  rcases hrel with ⟨hcontribution, _⟩
  have hi := hcontribution i
  cases hremoved : wit.removed i
  · left
    simpa [contributionMessage, hremoved] using hi
  · right
    simpa [contributionMessage, hremoved] using hi

/-- Exact coverage soundness: a removal branch exists iff it is backed by one
of the authenticated readable cards. -/
theorem removed_iff_has_readable_witness {n k : ℕ}
    (wit : Witness F n k) (i : Fin n) :
    wit.removed i = true ↔ ∃ j, wit.readableIndex j = i :=
  wit.removed_iff_readable i

/-- Readable-card indices cannot be duplicated. -/
theorem readable_indices_are_unique {n k : ℕ}
    (wit : Witness F n k) {j₁ j₂ : Fin k}
    (h : wit.readableIndex j₁ = wit.readableIndex j₂) : j₁ = j₂ :=
  wit.readableIndex_injective h

/-- Adding a valid contribution to a canonical aggregate-key encryption gives
an encryption of zero exactly on a removed slot, and preserves the card on an
unremoved slot. -/
theorem corrected_slot_semantics {n k : ℕ}
    (stmt : Statement G n k) (wit : Witness F n k)
    (hrel : Relation F G stmt wit) (i : Fin n) (initialRandomness : F) :
    ciphertextAdd G
      (ElGamalCiphertext.encrypt F G stmt.g (stmt.cards i)
        stmt.aggregatePk initialRandomness)
      (stmt.contributions i) =
      if wit.removed i then
        ElGamalCiphertext.encrypt F G stmt.g 0 stmt.aggregatePk
          (initialRandomness + wit.contributionRandomness i)
      else
        ElGamalCiphertext.encrypt F G stmt.g (stmt.cards i) stmt.aggregatePk
          (initialRandomness + wit.contributionRandomness i) := by
  rcases hrel with ⟨hcontribution, _⟩
  rw [hcontribution i, encrypt_add]
  cases hremoved : wit.removed i <;> simp [contributionMessage, hremoved]

/-! ## Joint cross-key plaintext-negation relation -/

/-- Witness equations for the generalized Schnorr proof that an aggregate-key
contribution encrypts the negative of an owner-readable plaintext.

The witness is `(ownerSk, contributionRandomness)`.  Crucially, it does not
contain the readable card's ElGamal exponent and therefore does not require
knowing `DL(readable.c1)`. -/
def CrossKeyNegationRelation
    (g ownerPk aggregatePk : G)
    (readable contribution : ElGamalCiphertext G)
    (ownerSk contributionRandomness : F) : Prop :=
  ownerPk = ownerSk • g ∧
  contribution.c1 = contributionRandomness • g ∧
  ownerSk • readable.c1 + contributionRandomness • aggregatePk =
    readable.c2 + contribution.c2

/-- Completeness of the joint linear relation for honest encryptions of `m`
and `-m` under the two different public keys. -/
theorem cross_key_negation_complete
    (g ownerPk aggregatePk m : G) (ownerSk readableRandomness contributionRandomness : F)
    (hpk : ownerPk = ownerSk • g) :
    CrossKeyNegationRelation F G g ownerPk aggregatePk
      (ElGamalCiphertext.encrypt F G g m ownerPk readableRandomness)
      (ElGamalCiphertext.encrypt F G g (-m) aggregatePk contributionRandomness)
      ownerSk contributionRandomness := by
  refine ⟨hpk, rfl, ?_⟩
  simp [ElGamalCiphertext.encrypt, hpk, smul_smul]
  module

/-- Soundness consequence of the joint relation: decrypting the readable card
with the extracted owner key and the contribution with its extracted
randomness gives plaintexts summing to zero.  No discrete logarithm of
`readable.c1` is used. -/
theorem cross_key_negation_binds_plaintexts
    (g ownerPk aggregatePk : G)
    (readable contribution : ElGamalCiphertext G)
    (ownerSk contributionRandomness : F)
    (hrel : CrossKeyNegationRelation F G g ownerPk aggregatePk
      readable contribution ownerSk contributionRandomness) :
    (readable.c2 - ownerSk • readable.c1) +
      (contribution.c2 - contributionRandomness • aggregatePk) = 0 := by
  rcases hrel with ⟨_, _, hlinear⟩
  calc
    (readable.c2 - ownerSk • readable.c1) +
        (contribution.c2 - contributionRandomness • aggregatePk) =
      (readable.c2 + contribution.c2) -
        (ownerSk • readable.c1 + contributionRandomness • aggregatePk) := by abel
    _ = 0 := by rw [← hlinear, sub_self]

/-! ## Multi-player plaintext aggregation -/

/-- Plaintext obtained from the canonical card after adding all players'
slot contributions. -/
def aggregatePlaintext {players : ℕ} (card : G)
    (removed : Fin players → Bool) : G :=
  card + ∑ p, contributionMessage G card (removed p)

/-- If no player removes a slot, its canonical plaintext is preserved. -/
theorem aggregatePlaintext_no_removal {players : ℕ}
    (card : G) (removed : Fin players → Bool)
    (hnone : ∀ p, removed p = false) :
    aggregatePlaintext G card removed = card := by
  simp [aggregatePlaintext, contributionMessage, hnone]

/-- If exactly one player removes a slot, its canonical plaintext is replaced
by zero.  This is the protocol-state disjointness invariant required across
players' authenticated prior hands. -/
theorem aggregatePlaintext_unique_removal {players : ℕ}
    (card : G) (removed : Fin players → Bool) (owner : Fin players)
    (howner : removed owner = true)
    (hothers : ∀ p, p ≠ owner → removed p = false) :
    aggregatePlaintext G card removed = 0 := by
  unfold aggregatePlaintext
  rw [Finset.sum_eq_single owner]
  · simp [contributionMessage, howner]
  · intro p hp hne
    simp [contributionMessage, hothers p hne]
  · simp

end PokerProtocolLean.Reconstruct.V3
