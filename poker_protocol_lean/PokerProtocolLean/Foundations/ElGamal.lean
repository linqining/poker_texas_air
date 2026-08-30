/-
! # ElGamal Encryption and the Layer-2 Bridge Lemma

This file formalizes ElGamal ciphertexts over an abstract prime-order group and
proves the **Layer-2 bridge lemma**:

  `ct = encrypt m pk r → pk = sk • g → ct.c2 - sk • ct.c1 = m`

This is the linchpin of `ZKShuffleProof` Layer 2 (`soundness.md` §二.层次2):
from the two ciphertext-level equations E1 and E2 extracted by the
GeneralizedSchnorr extractor, one derives the plaintext-level equation
`E_plain : Σ_j k_j • m_out_j = Σ_i ρ_i • m_in_i` by computing `E2 - sk · E1`.

## Rust correspondence
- `poker_protocol/src/crypto/elgamal.rs`: `ElGamalCiphertextGeneric`
- `poker_protocol/src/crypto/curve.rs`: `encrypt`, `decrypt`, `re_encrypt`
- `poker_protocol/src/zk_shuffle/remask_proof.rs`: `remask_ciphertext`
- `poker_protocol/src/zk_shuffle/reveal_token_proof.rs`: `gen_reveal_token`
-/

import Mathlib.Algebra.Module.Basic
import Mathlib.Algebra.Field.Basic
import Mathlib.Algebra.AddTorsor.Defs
import Mathlib.GroupTheory.GroupAction.Basic
import Mathlib.Tactic.Module

namespace PokerProtocolLean.Foundations

/-- An ElGamal ciphertext `(c1, c2)` over the group `G`.

Rust: `ElGamalCiphertextGeneric<C>` in `crypto/curve.rs`. -/
structure ElGamalCiphertext (G : Type) where
  /-- First component `c1 = r • g`. -/
  c1 : G
  /-- Second component `c2 = m + r • pk`. -/
  c2 : G

variable (F : Type) [Field F] [Fintype F] [DecidableEq F]
variable (G : Type) [AddCommGroup G] [Module F G] [Fintype G] [DecidableEq G]

/-- ElGamal encryption of `m` under public key `pk` with randomness `r`.

  `encrypt g m pk r = ⟨r • g, m + r • pk⟩`

Rust: `ElGamalCiphertextGeneric::encrypt`. -/
def ElGamalCiphertext.encrypt (g : G) (m pk : G) (r : F) : ElGamalCiphertext G :=
  ⟨r • g, m + r • pk⟩

/-- ElGamal decryption with secret key `sk`.

  `decrypt sk ct = ct.c2 - sk • ct.c1`

Rust: `ElGamalCiphertextGeneric::decrypt`. -/
def ElGamalCiphertext.decrypt (sk : F) (ct : ElGamalCiphertext G) : G :=
  ct.c2 - sk • ct.c1

/-- Re-encryption of a ciphertext under public key `pk` with fresh randomness `r`.

  `re_encrypt g pk r ct = ⟨ct.c1 + r • g, ct.c2 + r • pk⟩`

This is the homomorphic operation used by `ZKShuffleProof`:
a shuffle is `output[j] = re_encrypt(input[permute(j)], pk, r_j)`.

Rust: `ElGamalCiphertextGeneric::re_encrypt`. -/
def ElGamalCiphertext.re_encrypt (g : G) (pk : G) (r : F)
    (ct : ElGamalCiphertext G) : ElGamalCiphertext G :=
  ⟨ct.c1 + r • g, ct.c2 + r • pk⟩

/-- Remasking: apply the player's secret-key mask to a ciphertext.

  `remask sk ct = ⟨ct.c1, ct.c2 + sk • ct.c1⟩`

Note `c1` is invariant (a key soundness requirement of `DLEqProof`).

Rust: `remask_ciphertext` in `zk_shuffle/remask_proof.rs`. -/
def ElGamalCiphertext.remask (sk : F) (ct : ElGamalCiphertext G) :
    ElGamalCiphertext G :=
  ⟨ct.c1, ct.c2 + sk • ct.c1⟩

/-- Generate a reveal token `sk • ct.c1` for ciphertext `ct`.

A reveal token lets a verifier recover the plaintext as `ct.c2 - token`.

Rust: `RevealTokenProof` in `zk_shuffle/reveal_token_proof.rs`. -/
def ElGamalCiphertext.gen_reveal_token (sk : F) (ct : ElGamalCiphertext G) : G :=
  sk • ct.c1

/-- A placeholder (identity) ciphertext used for un-dealt cards.

Rust: `ElGamalCiphertextGeneric::new_placeholder_card`. -/
def ElGamalCiphertext.placeholder : ElGamalCiphertext G :=
  ⟨0, 0⟩

/-- A ciphertext is valid iff neither component is the identity.

This matches the **fixed** definition in `crypto/curve.rs` (`&&`), NOT the
legacy buggy `||` in `crypto/elgamal.rs`. See M7 fix in `dleq_proof.rs`. -/
def ElGamalCiphertext.is_valid (ct : ElGamalCiphertext G) : Bool :=
  decide (ct.c1 ≠ 0 ∧ ct.c2 ≠ 0)

-- =====================================================================
-- **Layer-2 Bridge Lemma** (the linchpin of ZKShuffleProof soundness)
-- =====================================================================

/-- **Layer-2 bridge lemma**: for an honestly-encrypted ciphertext
`ct = encrypt g m pk r` with `pk = sk • g`, we have `ct.c2 - sk • ct.c1 = m`.

This is the algebraic identity that lets the ZKShuffleProof extractor derive
the plaintext equation `E_plain` from the two ciphertext equations `E1` and
`E2` (see `soundness.md` §二.层次2):

  `E2 - sk · E1` gives `Σ_j k_j • (m_out_j) - Σ_i ρ_i • (m_in_i) = 0`,
i.e. `Σ_j k_j • m_out_j = Σ_i ρ_i • m_in_i`.

Proof: `c2 - sk • c1 = (m + r • pk) - sk • (r • g)`
                     `= m + r • (sk • g) - (sk * r) • g`   (by `mul_smul`)
                     `= m + (r * sk) • g - (sk * r) • g`   (commutativity of `*`)
                     `= m + (r * sk - sk * r) • g`         (by `smul_sub`)
                     `= m + 0`                              (since `r * sk = sk * r`)
                     `= m`. -/
theorem c2_minus_sk_c1_eq_plaintext
    (g : G) (m pk : G) (sk r : F) (ct : ElGamalCiphertext G)
    (hpk : pk = sk • g)
    (henc : ct = ElGamalCiphertext.encrypt F G g m pk r) :
    ct.c2 - sk • ct.c1 = m := by
  -- Unfold the encryption equation.
  have hc1 : ct.c1 = r • g := by rw [henc]; rfl
  have hc2 : ct.c2 = m + r • pk := by rw [henc]; rfl
  -- Substitute c1 and c2 in the goal.
  rw [hc1, hc2, hpk, smul_smul, smul_smul, mul_comm r sk]
  -- Goal: (m + (sk * r) • g) - (sk * r) • g = m
  module

-- =====================================================================
-- Re-encryption homomorphism lemmas
-- =====================================================================

/-- Re-encryption preserves decryption when `pk = sk • g`:
decrypting a re-encrypted ciphertext with the matching secret key yields the
same plaintext as decrypting the original. -/
theorem decrypt_re_encrypt_eq_decrypt
    (g : G) (pk : G) (r : F) (sk : F) (ct : ElGamalCiphertext G)
    (hpk : pk = sk • g) :
    ElGamalCiphertext.decrypt F G sk
      (ElGamalCiphertext.re_encrypt F G g pk r ct) =
    ElGamalCiphertext.decrypt F G sk ct := by
  -- LHS = (ct.c2 + r • pk) - sk • (ct.c1 + r • g)
  -- RHS = ct.c2 - sk • ct.c1
  -- LHS - RHS = (r • pk) - (sk • (r • g)) = r • pk - (sk * r) • g
  --           = r • pk - r • (sk • g)        [mul_smul on r • (sk • g)]
  --           = r • (pk - sk • g)            [sub_smul]
  --           = r • 0                          [hpk]
  --           = 0
  have hkey : r • pk - sk • (r • g) = (0 : G) := by
    -- r • pk = r • (sk • g) = (r * sk) • g  (using hpk and mul_smul)
    have h_pk : r • pk = (r * sk) • g := by rw [hpk]; rw [smul_smul]
    -- sk • (r • g) = (sk * r) • g = (r * sk) • g  (smul_smul + mul_comm)
    have h_skg : sk • (r • g) = (r * sk) • g := by
      rw [smul_smul, mul_comm sk r]
    -- Substitute and cancel.
    rw [h_pk, h_skg, sub_self]
  rw [ElGamalCiphertext.re_encrypt, ElGamalCiphertext.decrypt,
      ElGamalCiphertext.decrypt, smul_add, add_sub_add_comm, hkey, add_zero]

/-- Remasking preserves `c1` (the c1-invariance required by `DLEqProof`). -/
theorem remask_c1_unchanged (sk : F) (ct : ElGamalCiphertext G) :
    (ElGamalCiphertext.remask F G sk ct).c1 = ct.c1 := by
  rfl

/-- For a remasked ciphertext, `output.c2 - input.c2 = sk • input.c1`
(the Remask direction of `DLEqProof.compute_d2`). -/
theorem c2_remask_diff_eq_sk_times_c1 (sk : F) (ct : ElGamalCiphertext G) :
    (ElGamalCiphertext.remask F G sk ct).c2 - ct.c2 = sk • ct.c1 := by
  -- remask ct = ⟨ct.c1, ct.c2 + sk • ct.c1⟩
  -- (remask ct).c2 - ct.c2 = (ct.c2 + sk•ct.c1) - ct.c2 = sk • ct.c1
  show (ct.c2 + sk • ct.c1) - ct.c2 = sk • ct.c1
  module

/-- For a leave ciphertext (`leave` is the inverse direction of remask),
`input.c2 - output.c2 = sk • input.c1` (the Leave direction). -/
theorem c2_leave_diff_eq_sk_times_c1 (sk : F) (ct : ElGamalCiphertext G) :
    ct.c2 - (ElGamalCiphertext.remask F G sk ct).c2 = -(sk • ct.c1) := by
  -- (remask ct).c2 = ct.c2 + sk•ct.c1
  -- ct.c2 - (remask ct).c2 = ct.c2 - (ct.c2 + sk•ct.c1) = -(sk•ct.c1)
  show ct.c2 - (ct.c2 + sk • ct.c1) = -(sk • ct.c1)
  module

/-- Reveal token binding: `gen_reveal_token sk ct = sk • ct.c1` (definitional). -/
theorem gen_reveal_token_eq (sk : F) (ct : ElGamalCiphertext G) :
    ElGamalCiphertext.gen_reveal_token F G sk ct = sk • ct.c1 := by
  rfl

/-- Reveal token + Layer-2 lemma: if `token = sk • ct.c1` and the ciphertext
was honestly encrypted, then `ct.c2 - token = m` (the plaintext). -/
theorem c2_minus_reveal_token_eq_plaintext
    (g : G) (m pk : G) (sk r : F) (ct : ElGamalCiphertext G)
    (hpk : pk = sk • g)
    (henc : ct = ElGamalCiphertext.encrypt F G g m pk r) :
    ct.c2 - ElGamalCiphertext.gen_reveal_token F G sk ct = m := by
  -- gen_reveal_token sk ct = sk • ct.c1, so this is just the Layer-2 lemma.
  rw [gen_reveal_token_eq]
  exact c2_minus_sk_c1_eq_plaintext F G g m pk sk r ct hpk henc

end PokerProtocolLean.Foundations
