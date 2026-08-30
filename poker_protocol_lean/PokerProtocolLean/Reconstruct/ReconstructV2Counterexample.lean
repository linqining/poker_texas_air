import Mathlib.Tactic
import PokerProtocolLean.Foundations.ElGamal

/-!
# Reconstruction V2: machine-checked counterexamples

This module formalises two algebraic defects in the Rust reconstruction-v2
statement implemented by `poker-protocol-proofs/src/reconstruction/mod.rs`.
They are protocol-level counterexamples, not implementation accidents.

The verifier checks that a shuffled padded swap ciphertext can be added to an
output ciphertext to obtain an encryption of the canonical card.  It does not
check that the plaintext of that padded swap is the canonical card at the same
slot.  Consequently a swap encrypting `A` may be placed at the slot for `B`:

* `padded = Enc(A; s)`;
* `output = Enc(B - A; r)`;
* `output + padded = Enc(B; r + s)`.

For `A != 0` and `A != B`, the output plaintext `B - A` is neither zero nor
the canonical card `B`.  Bayer--Groth proves the shuffled multiset relation,
and the ordered-encryption proof proves the final corrected ciphertext, but
neither relation rules out this construction.

The second defect is confidentiality: if the encryption randomness is public,
then `ct.c2 - r * pk` recovers the plaintext without the secret key.  The Rust
v2 constructor derives all output randomness from the public `coefficient`,
so those output ciphertexts cannot hide which slots contain zero.
-/

namespace PokerProtocolLean.Reconstruct.V2Counterexample

open PokerProtocolLean.Foundations

variable (F : Type) [Field F]
variable (G : Type) [AddCommGroup G] [Module F G]

/-- Componentwise homomorphic addition of ElGamal ciphertexts. -/
def ciphertextAdd (left right : ElGamalCiphertext G) : ElGamalCiphertext G :=
  ⟨left.c1 + right.c1, left.c2 + right.c2⟩

@[ext]
theorem ciphertext_ext {left right : ElGamalCiphertext G}
    (hc1 : left.c1 = right.c1) (hc2 : left.c2 = right.c2) : left = right := by
  cases left
  cases right
  simp_all

/-- ElGamal is additively homomorphic in both plaintext and randomness. -/
theorem encrypt_add
    (g pk m₁ m₂ : G) (r₁ r₂ : F) :
    ciphertextAdd G
        (ElGamalCiphertext.encrypt F G g m₁ pk r₁)
        (ElGamalCiphertext.encrypt F G g m₂ pk r₂) =
      ElGamalCiphertext.encrypt F G g (m₁ + m₂) pk (r₁ + r₂) := by
  apply ciphertext_ext G
  · simp [ciphertextAdd, ElGamalCiphertext.encrypt, add_smul]
  · simp [ciphertextAdd, ElGamalCiphertext.encrypt, add_smul]
    module

/-- The exact corrected-ciphertext relation checked by reconstruction v2. -/
def correctedRelation (g pk card : G)
    (output padded : ElGamalCiphertext G) (randomness : F) : Prop :=
  ciphertextAdd G output padded =
    ElGamalCiphertext.encrypt F G g card pk randomness

/-- A swap for plaintext `A` can be placed at the canonical slot for `B` and
still satisfy the corrected-ciphertext relation. -/
theorem misplaced_swap_satisfies_corrected_relation
    (g pk A B : G) (r s : F) :
    correctedRelation F G g pk B
      (ElGamalCiphertext.encrypt F G g (B - A) pk r)
      (ElGamalCiphertext.encrypt F G g A pk s)
      (r + s) := by
  unfold correctedRelation
  rw [encrypt_add]
  congr 1
  exact sub_add_cancel B A

/-- Under the natural non-degeneracy assumptions, the malicious output
plaintext `B - A` is neither an allowed zero contribution nor `B`. -/
theorem misplaced_output_is_not_an_honest_branch
    (A B : G) (hA : A ≠ 0) (hBA : B ≠ A) :
    B - A ≠ 0 ∧ B - A ≠ B := by
  constructor
  · exact sub_ne_zero.mpr hBA
  · intro h
    apply hA
    have hneg : -A = 0 := by
      calc
        -A = (B - A) - B := by abel
        _ = B - B := congrArg (fun X => X - B) h
        _ = 0 := sub_self B
    exact neg_eq_zero.mp hneg

/-- Anyone knowing the encryption randomness recovers the plaintext directly;
no secret key or discrete-log computation is needed. -/
theorem recover_plaintext_from_known_randomness
    (g pk m : G) (r : F) :
    (ElGamalCiphertext.encrypt F G g m pk r).c2 - r • pk = m := by
  simp [ElGamalCiphertext.encrypt]

/-- The v2 public-randomness attack specialised to the two intended output
branches: the observer distinguishes `Enc(0; r)` from `Enc(card; r)` exactly. -/
theorem public_randomness_reveals_branch
    (g pk card : G) (r : F) :
    ((ElGamalCiphertext.encrypt F G g 0 pk r).c2 - r • pk = 0) ∧
    ((ElGamalCiphertext.encrypt F G g card pk r).c2 - r • pk = card) := by
  constructor <;> exact recover_plaintext_from_known_randomness F G g pk _ r

/-- Adding two players' ciphertexts that use the same scalar `r` under
different keys produces a first component with exponent `r + r`, but a key
term using only `r * (pk₁ + pk₂)`.  It is therefore not the usual ElGamal
encryption under the aggregate key with either of those two randomness
interpretations, except in degenerate cases. -/
theorem same_randomness_cross_key_sum_shape
    (g pk₁ pk₂ m₁ m₂ : G) (r : F) :
    ciphertextAdd G
      (ElGamalCiphertext.encrypt F G g m₁ pk₁ r)
      (ElGamalCiphertext.encrypt F G g m₂ pk₂ r) =
      ⟨(r + r) • g, (m₁ + m₂) + r • (pk₁ + pk₂)⟩ := by
  apply ciphertext_ext G
  · simp [ciphertextAdd, ElGamalCiphertext.encrypt, add_smul]
  · simp [ciphertextAdd, ElGamalCiphertext.encrypt, smul_add]
    module

end PokerProtocolLean.Reconstruct.V2Counterexample
