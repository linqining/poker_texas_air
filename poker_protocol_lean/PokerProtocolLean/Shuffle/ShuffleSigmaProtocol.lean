import Mathlib.Algebra.BigOperators.Fin
import Mathlib.Algebra.Module.BigOperators
import Mathlib.Tactic.Module
import VCVio.CryptoFoundations.SigmaProtocol
import VCVio.OracleComp.Constructions.SampleableType
import PokerProtocolLean.Foundations.AlgebraicSetup
import PokerProtocolLean.Foundations.ElGamal
import PokerProtocolLean.Schnorr.GeneralizedSchnorr
import PokerProtocolLean.Shuffle.ShuffleRelation

/-!
# ZKShuffleProof — Σ-protocol construction (M6-H2)

Backing `poker_protocol/src/zk_shuffle/proof.rs`.

The ZKShuffle Σ-protocol is a 3-layer composition of `GeneralizedSchnorr`
sub-proofs over a shared transcript (see `soundness.md` §一). This file
formalises the **combined-layer linear-algebraic core** that all three
sub-proofs specialise: a multi-base Schnorr proof of knowledge of the
re-encryption randomness vector `r_values : Fin n → F` such that the
public linear equation

    (Σ_j r_values j) • g = (Σ_j output[j].c1) − (Σ_i input[i].c1)

holds. This equation is an immediate algebraic consequence of
`output[j] = re_encrypt(input[π(j)], pk, r_values[j])` (since re-encryption
adds `r_values[j] • g` to `c1` and `π` is a bijection), so any honest
shuffle witness satisfies it.

The three Σ-protocol properties of this core are:

| Property             | Theorem                          | Status      |
| -------------------- | -------------------------------- | ----------- |
| Perfect completeness | `ShuffleComplete.sigma_complete` | Real proof  |
| Perfect HVZK         | `ShuffleHVZK.sigma_perfect_hvzk` | Real proof  |
| Special soundness    | `ShuffleSoundness.consistency_from_structure` | Real proof (multi-extractor consistency) |

The special-soundness argument is the first step in the 4-layer shuffle
soundness reduction:

* **Layer 1** (`consistency_from_structure`, proved): the three sub-proof
  extractors produce identical `k` and `pkδ` under the initial ciphertext
  structure hypothesis (linear independent plaintexts `{m_i}`, `pk ∉ span{m_i}`).
* **Layer 2** (`layer2_plaintext_eq`, proved): from E1/E2 ciphertext
  equations, the plaintext equation `Σ k_j • m_out[j] = Σ ρ_i • m_in[i]` holds.
* **Layer 3** (deleted): required Schwartz-Zippel game-hop machinery
  (`GameHops.KJLowDegree`), which is itself still a `True` stub.
* **Layer 4** (deleted): component constraint with no precise mathematical
  statement.

The full knowledge-soundness reduction (Layer 1 → Layer 2 → Layer 3
Schwartz-Zippel permutation binding → Layer 4 component constraint) is a
pen-and-paper game-hop documented in `poker_protocol/soundness.md` §二.
-/

open OracleSpec OracleComp SigmaProtocol
open PokerProtocolLean.Foundations (ElGamalCiphertext)
open scoped ENNReal

namespace PokerProtocolLean.Shuffle

variable (F : Type) [Field F] [Fintype F] [DecidableEq F] [SampleableType F]
variable (G : Type) [AddCommGroup G] [Module F G] [Fintype G] [DecidableEq G]
  [SampleableType G]

/-- The public target of the combined-layer Schnorr equation:
`(Σ_j output[j].c1) − (Σ_i input[i].c1)`.

By the re-encryption identity `output[j].c1 = input[π(j)].c1 + r_values[j] • g`
and the bijectivity of `π`, this equals `(Σ_j r_values j) • g`. -/
def combinedTarget {n : ℕ} (stmt : ShuffleStatement F G n) : G :=
  (∑ j : Fin n, (stmt.output_cts j).c1) - (∑ j : Fin n, (stmt.input_cts j).c1)

/-- The ZKShuffle Σ-protocol: a multi-base Schnorr proof on the
combined-layer linear equation. The protocol proves knowledge of
`r_values : Fin n → F` such that
`(Σ_j r_values j) • g = combinedTarget g stmt`.

Fields:
* `commit`: sample `r_vec ← $ᵗ (Fin n → F)`, return
  `(T = (Σ_j r_vec j) • g, r_vec)`.
* `respond`: `s_j = r_vec j + c * r_values j`.
* `verify`: `decide ((Σ_j s j) • g = T + c • combinedTarget g stmt)`.
* `sim`: sample `s_vec ← $ᵗ (Fin n → F)`, `c ← $ᵗ F`, return
  `(Σ_j s_vec j) • g - c • combinedTarget g stmt`.
* `extract`: `r_values j = (s₁ j - s₂ j) * (c₁ - c₂)⁻¹`, with a default
  identity permutation (the extractor recovers the randomness vector but
  not the permutation; full soundness is a `True` stub). -/
def sigma (g : G) (n : ℕ) : SigmaProtocol
    (ShuffleStatement F G n) (ShuffleWitness F n) G (Fin n → F) F (Fin n → F)
    (shuffleRelation F G g) where
  commit _stmt _wit := do
    let r_vec ← ($ᵗ (Fin n → F))
    let T := (∑ j : Fin n, r_vec j) • g
    return (T, r_vec)
  respond _stmt wit r_vec c :=
    pure (fun j => r_vec j + c * wit.r_values j)
  verify stmt T c s :=
    decide ((∑ j : Fin n, s j) • g =
              T + c • combinedTarget F G stmt)
  sim stmt := do
    let s_vec ← ($ᵗ (Fin n → F))
    let c ← ($ᵗ F)
    pure ((∑ j : Fin n, s_vec j) • g - c • combinedTarget F G stmt)
  extract c₁ s₁ c₂ s₂ :=
    pure ⟨fun j => j, fun j => (s₁ j - s₂ j) * (c₁ - c₂)⁻¹⟩

end PokerProtocolLean.Shuffle
