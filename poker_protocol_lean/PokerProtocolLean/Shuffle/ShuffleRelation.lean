import Mathlib.Algebra.BigOperators.Fin
import Mathlib.Algebra.Module.BigOperators
import Mathlib.Data.Fintype.Perm
import Mathlib.Tactic.Module
import VCVio.CryptoFoundations.SigmaProtocol
import VCVio.OracleComp.Constructions.SampleableType
import PokerProtocolLean.Foundations.AlgebraicSetup
import PokerProtocolLean.Foundations.ElGamal
import PokerProtocolLean.Schnorr.GeneralizedSchnorr

open scoped Classical

/-!
# ZKShuffleProof — relation (M6-H1)

Backing `poker_protocol/soundness.md` §一 and
`poker_protocol/src/zk_shuffle/proof.rs`.

A shuffle of `n` ciphertexts is a permutation `π : Fin n → Fin n` plus a
vector of fresh randomness `r_values : Fin n → F`, such that

    output[j] = re_encrypt(input[π(j)], pk, r_values[j])

i.e. each output ciphertext is a re-encryption of some input ciphertext
under the shared public key `pk`. The proof establishes knowledge of such
a `(π, r_values)` to the public `input_cts`/`output_cts`/`pk`.
-/

open OracleSpec OracleComp SigmaProtocol
open PokerProtocolLean.Foundations (ElGamalCiphertext)
open scoped ENNReal

namespace PokerProtocolLean.Shuffle

variable (F : Type) [Field F] [Fintype F] [DecidableEq F] [SampleableType F]
variable (G : Type) [AddCommGroup G] [Module F G] [Fintype G] [DecidableEq G]
  [SampleableType G]

/-- Public statement for a shuffle: input/output ciphertext vectors and the
shared public key. -/
structure ShuffleStatement (F : Type) (G : Type) (n : ℕ) where
  /-- Input ciphertexts (the deck before shuffling). -/
  input_cts : Fin n → ElGamalCiphertext G
  /-- Output ciphertexts (the shuffled deck). -/
  output_cts : Fin n → ElGamalCiphertext G
  /-- Shared public key under which re-encryption is performed. -/
  pk : G

/-- Witness for a shuffle: a permutation and per-output randomness. -/
structure ShuffleWitness (F : Type) (n : ℕ) where
  /-- The permutation `π`. -/
  permute : Fin n → Fin n
  /-- Fresh re-encryption randomness per output position. -/
  r_values : Fin n → F

/-- The shuffle relation with an explicit generator `g`.

Uses `Classical.dec` as the `Decidable` instance so that `of_decide_eq_true`
in downstream files can match instances (by adding `classical` to the calling
context, `Classical.dec` is in scope and matches the one used here). -/
noncomputable
def shuffleRelation (F : Type) [Field F] [Fintype F] [DecidableEq F]
    (G : Type) [AddCommGroup G] [Module F G] [Fintype G] [DecidableEq G]
    (g : G) {n : ℕ} (stmt : ShuffleStatement F G n)
    (wit : ShuffleWitness F n) : Bool :=
  have inst : Decidable
    (Function.Bijective wit.permute ∧
      ∀ j, stmt.output_cts j =
        ElGamalCiphertext.re_encrypt F G g stmt.pk (wit.r_values j)
          (stmt.input_cts (wit.permute j))) :=
    Classical.dec _
  decide
    (Function.Bijective wit.permute ∧
      ∀ j, stmt.output_cts j =
        ElGamalCiphertext.re_encrypt F G g stmt.pk (wit.r_values j)
          (stmt.input_cts (wit.permute j)))

end PokerProtocolLean.Shuffle
