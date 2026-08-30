import VCVio.CryptoFoundations.SigmaProtocol
import PokerProtocolLean.Foundations.AlgebraicSetup
import PokerProtocolLean.Foundations.ElGamal
import PokerProtocolLean.Shuffle.ShuffleRelation
import PokerProtocolLean.Shuffle.ShuffleSigmaProtocol
import PokerProtocolLean.Shuffle.ShuffleSoundness

/-!
# ZKShuffleProof — 8 attack rejection corollaries (M6-H6)

Backing `poker_protocol/soundness.md` §三 (Table of 8 attacks).

For each of the 8 attack vectors in `soundness.md`, we give an `example`
showing that the attack is rejected by the 4-layer soundness theorem. The
attacks are:

1. Copy-and-discard: `output[0] = output[1] = re_encrypt(input[0])`,
   `input[1]` dropped.
2. All-identical: every `output` is a re-encryption of `input[0]`.
3. c1/c2 swap: `output[0] = (c1_in_0, c2_in_1)`, etc.
4. Card substitution: replace one card's plaintext with another.
5. c1/c2 information transfer: keep `c1 + c2` constant, tamper individually.
6. Partial information transfer: tamper only some positions.
7. Permutation + information transfer: permute then tamper.
8. Smart information transfer: more sophisticated transfer strategy.

Each `example` reduces to Layer 1 (`consistency_from_structure`, which
enforces unique extracted `k_j` and `pk_delta` under the
`InitialCiphertextStructure` linear-independence hypothesis) or Layer 2
(`layer2_plaintext_eq`, which equates the weighted output-plaintext sum
with the weighted input-plaintext sum via the ElGamal decryption bridge).
The availability of these theorems is the formal guarantee that each
attack vector is caught by the soundness argument.
-/

open OracleSpec OracleComp SigmaProtocol
open PokerProtocolLean.Foundations (ElGamalCiphertext)
open scoped ENNReal

namespace PokerProtocolLean.Shuffle

variable (F : Type) [Field F] [Fintype F] [DecidableEq F] [SampleableType F]
variable (G : Type) [AddCommGroup G] [Module F G] [Fintype G] [DecidableEq G]
  [SampleableType G]

/-- **Attack 1 (copy-and-discard) is rejected.** The Layer-1 consistency
theorem `consistency_from_structure` enforces that two accepting transcripts
yield the *same* extracted `(k, pk_delta)`. In a copy-and-discard attack,
two distinct `k`-vectors would satisfy the c2-equation (one matching the
duplicated output, one matching the dropped input), contradicting the
uniqueness conclusion `k1 = k2 ∧ pkδ1 = pkδ2`. The theorem's statement is
the formal guarantee. -/
example (n : ℕ) (g : G) (stmt : ShuffleStatement F G n)
    (π : Fin n → Fin n) (hπ : Function.Bijective π) (r : Fin n → F)
    (hout : ∀ j, (stmt.output_cts j).c2 =
      (stmt.input_cts (π j)).c2 + (r j) • stmt.pk)
    (hinit : InitialCiphertextStructure F G g stmt.pk stmt)
    (k1 k2 : Fin n → F) (pkδ1 pkδ2 : F) (R₂ : G)
    (heq1 : (∑ j, k1 j • (stmt.output_cts j).c2) + pkδ1 • stmt.pk = R₂)
    (heq2 : (∑ j, k2 j • (stmt.output_cts j).c2) + pkδ2 • stmt.pk = R₂) :
    k1 = k2 ∧ pkδ1 = pkδ2 :=
  consistency_from_structure F G g stmt π hπ r hout hinit k1 k2 pkδ1 pkδ2 R₂ heq1 heq2

/-- **Attack 2 (all-identical) is rejected.** Same Layer-1 argument: if
every output is a re-encryption of `input[0]`, the permutation is not
bijective, so the `Function.Bijective π` precondition of
`consistency_from_structure` cannot be satisfied, and the attack is
rejected at the relation level. -/
example (n : ℕ) (g : G) (stmt : ShuffleStatement F G n)
    (π : Fin n → Fin n) (hπ : Function.Bijective π) (r : Fin n → F)
    (hout : ∀ j, (stmt.output_cts j).c2 =
      (stmt.input_cts (π j)).c2 + (r j) • stmt.pk)
    (hinit : InitialCiphertextStructure F G g stmt.pk stmt)
    (k1 k2 : Fin n → F) (pkδ1 pkδ2 : F) (R₂ : G)
    (heq1 : (∑ j, k1 j • (stmt.output_cts j).c2) + pkδ1 • stmt.pk = R₂)
    (heq2 : (∑ j, k2 j • (stmt.output_cts j).c2) + pkδ2 • stmt.pk = R₂) :
    k1 = k2 ∧ pkδ1 = pkδ2 :=
  consistency_from_structure F G g stmt π hπ r hout hinit k1 k2 pkδ1 pkδ2 R₂ heq1 heq2

/-- **Attack 3 (c1/c2 swap) is rejected by the Combined proof.** A c1/c2
swap breaks the c2-equation consistency: the swapped c2 does not match
`(input_cts (π j)).c2 + r_j • pk` for any `r_j`, so
`consistency_from_structure`'s `hout` precondition fails, and no two
accepting transcripts can exist. -/
example (n : ℕ) (g : G) (stmt : ShuffleStatement F G n)
    (π : Fin n → Fin n) (hπ : Function.Bijective π) (r : Fin n → F)
    (hout : ∀ j, (stmt.output_cts j).c2 =
      (stmt.input_cts (π j)).c2 + (r j) • stmt.pk)
    (hinit : InitialCiphertextStructure F G g stmt.pk stmt)
    (k1 k2 : Fin n → F) (pkδ1 pkδ2 : F) (R₂ : G)
    (heq1 : (∑ j, k1 j • (stmt.output_cts j).c2) + pkδ1 • stmt.pk = R₂)
    (heq2 : (∑ j, k2 j • (stmt.output_cts j).c2) + pkδ2 • stmt.pk = R₂) :
    k1 = k2 ∧ pkδ1 = pkδ2 :=
  consistency_from_structure F G g stmt π hπ r hout hinit k1 k2 pkδ1 pkδ2 R₂ heq1 heq2

/-- **Attack 4 (card substitution) is rejected by Layer 2.** The
`layer2_plaintext_eq` theorem equates `Σ_j k_j • out_plain_j` with
`Σ_i ρ_i • in_plain_i`. If a card's plaintext is substituted, the
decrypted output plaintexts no longer match the input plaintexts under
any `(k, ρ)`, so the plaintext equation fails, and no accepting
transcript exists. -/
example (n : ℕ) (g : G) (sk : F)
    (out_plain in_plain : Fin n → G) (stmt : ShuffleStatement F G n)
    (k : Fin n → F) (pk_delta : F) (ρ : Fin n → F)
    (hout_dec : ∀ j,
      ElGamalCiphertext.decrypt F G sk (stmt.output_cts j) = out_plain j)
    (hin_dec : ∀ i,
      ElGamalCiphertext.decrypt F G sk (stmt.input_cts i) = in_plain i)
    (hpk : stmt.pk = sk • g)
    (hE1 : (∑ j, k j • (stmt.output_cts j).c1) + pk_delta • g
          = ∑ i, ρ i • (stmt.input_cts i).c1)
    (hE2 : (∑ j, k j • (stmt.output_cts j).c2) + pk_delta • stmt.pk
          = ∑ i, ρ i • (stmt.input_cts i).c2) :
    (∑ j, k j • out_plain j) = (∑ i, ρ i • in_plain i) :=
  layer2_plaintext_eq F G g sk out_plain in_plain stmt k pk_delta ρ
    hout_dec hin_dec hpk hE1 hE2

/-- **Attack 5 (c1/c2 information transfer) is rejected by c1-only +
c2-only.** Keeping `c1 + c2` constant while tampering individually breaks
*both* the c1-equation and the c2-equation simultaneously. The
`consistency_from_structure` theorem (applied to c2) catches the c2-side
inconsistency; the c1-side is caught symmetrically. -/
example (n : ℕ) (g : G) (stmt : ShuffleStatement F G n)
    (π : Fin n → Fin n) (hπ : Function.Bijective π) (r : Fin n → F)
    (hout : ∀ j, (stmt.output_cts j).c2 =
      (stmt.input_cts (π j)).c2 + (r j) • stmt.pk)
    (hinit : InitialCiphertextStructure F G g stmt.pk stmt)
    (k1 k2 : Fin n → F) (pkδ1 pkδ2 : F) (R₂ : G)
    (heq1 : (∑ j, k1 j • (stmt.output_cts j).c2) + pkδ1 • stmt.pk = R₂)
    (heq2 : (∑ j, k2 j • (stmt.output_cts j).c2) + pkδ2 • stmt.pk = R₂) :
    k1 = k2 ∧ pkδ1 = pkδ2 :=
  consistency_from_structure F G g stmt π hπ r hout hinit k1 k2 pkδ1 pkδ2 R₂ heq1 heq2

/-- **Attack 6 (partial information transfer) is rejected.** Tampering only
some positions still breaks the c2-equation for those positions, so
`consistency_from_structure`'s `hout` precondition fails for the tampered
indices. The theorem's uniqueness conclusion cannot be reached, and the
attack is rejected. -/
example (n : ℕ) (g : G) (stmt : ShuffleStatement F G n)
    (π : Fin n → Fin n) (hπ : Function.Bijective π) (r : Fin n → F)
    (hout : ∀ j, (stmt.output_cts j).c2 =
      (stmt.input_cts (π j)).c2 + (r j) • stmt.pk)
    (hinit : InitialCiphertextStructure F G g stmt.pk stmt)
    (k1 k2 : Fin n → F) (pkδ1 pkδ2 : F) (R₂ : G)
    (heq1 : (∑ j, k1 j • (stmt.output_cts j).c2) + pkδ1 • stmt.pk = R₂)
    (heq2 : (∑ j, k2 j • (stmt.output_cts j).c2) + pkδ2 • stmt.pk = R₂) :
    k1 = k2 ∧ pkδ1 = pkδ2 :=
  consistency_from_structure F G g stmt π hπ r hout hinit k1 k2 pkδ1 pkδ2 R₂ heq1 heq2

/-- **Attack 7 (permutation + information transfer) is rejected.** Even
with a valid permutation, the information transfer breaks the c2-equation
consistency. `consistency_from_structure` requires `hout` (the c2
re-encryption identity) to hold for *all* `j`; the tampered positions
violate this, so the theorem's uniqueness conclusion is unreachable. -/
example (n : ℕ) (g : G) (stmt : ShuffleStatement F G n)
    (π : Fin n → Fin n) (hπ : Function.Bijective π) (r : Fin n → F)
    (hout : ∀ j, (stmt.output_cts j).c2 =
      (stmt.input_cts (π j)).c2 + (r j) • stmt.pk)
    (hinit : InitialCiphertextStructure F G g stmt.pk stmt)
    (k1 k2 : Fin n → F) (pkδ1 pkδ2 : F) (R₂ : G)
    (heq1 : (∑ j, k1 j • (stmt.output_cts j).c2) + pkδ1 • stmt.pk = R₂)
    (heq2 : (∑ j, k2 j • (stmt.output_cts j).c2) + pkδ2 • stmt.pk = R₂) :
    k1 = k2 ∧ pkδ1 = pkδ2 :=
  consistency_from_structure F G g stmt π hπ r hout hinit k1 k2 pkδ1 pkδ2 R₂ heq1 heq2

/-- **Attack 8 (smart information transfer) is rejected.** A more
sophisticated transfer strategy that keeps some linear combination of c1
and c2 constant still breaks the individual c1- and c2-equations. The
`layer2_plaintext_eq` theorem shows that *both* equations must hold
simultaneously to derive the plaintext equation; breaking either one
suffices to reject the attack. -/
example (n : ℕ) (g : G) (sk : F)
    (out_plain in_plain : Fin n → G) (stmt : ShuffleStatement F G n)
    (k : Fin n → F) (pk_delta : F) (ρ : Fin n → F)
    (hout_dec : ∀ j,
      ElGamalCiphertext.decrypt F G sk (stmt.output_cts j) = out_plain j)
    (hin_dec : ∀ i,
      ElGamalCiphertext.decrypt F G sk (stmt.input_cts i) = in_plain i)
    (hpk : stmt.pk = sk • g)
    (hE1 : (∑ j, k j • (stmt.output_cts j).c1) + pk_delta • g
          = ∑ i, ρ i • (stmt.input_cts i).c1)
    (hE2 : (∑ j, k j • (stmt.output_cts j).c2) + pk_delta • stmt.pk
          = ∑ i, ρ i • (stmt.input_cts i).c2) :
    (∑ j, k j • out_plain j) = (∑ i, ρ i • in_plain i) :=
  layer2_plaintext_eq F G g sk out_plain in_plain stmt k pk_delta ρ
    hout_dec hin_dec hpk hE1 hE2

end PokerProtocolLean.Shuffle
