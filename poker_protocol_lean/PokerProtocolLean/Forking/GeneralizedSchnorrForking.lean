import VCVio.CryptoFoundations.SigmaProtocol
import VCVio.CryptoFoundations.FiatShamir.Sigma
import VCVio.CryptoFoundations.ReplayFork
import VCVio.CryptoFoundations.FiatShamir.Sigma.Security
import VCVio.CryptoFoundations.HardnessAssumptions.DiffieHellman
import PokerProtocolLean.Foundations.AlgebraicSetup
import PokerProtocolLean.Schnorr.GeneralizedSchnorr

/-!
# GeneralizedSchnorr forking specialisation (task #1)

Backing the Fiat-Shamir knowledge-soundness reduction for
`GeneralizedSchnorrProof`.

VCV-io's `FiatShamir.euf_nma_bound` gives a generic forking-lemma bound for
any Σ-protocol satisfying `SpeciallySound` plus extractor totality. This file
specialises that bound to the multi-base Schnorr protocol of M2, yielding the
concrete `(qH + 1) / |F|` rewinding overhead.

The specialisation is mechanical: it threads the multi-base extractor
`extract c₁ s₁ c₂ s₂ = fun i => (s₁ i - s₂ i) * (c₁ - c₂)⁻¹` through the
generic `ReplayFork` infrastructure, then closes with the same
`mul_smul` + `inv_mul_cancel₀` algebra as
`GeneralizedSchnorr.sigma_speciallySound`.

## Formalised content

This file proves three results that together form the FS knowledge-soundness
reduction for `GeneralizedSchnorr.sigma`:

1. **`sigma_extract_never_fails`**: the extractor
   `extract c₁ s₁ c₂ s₂ = pure ⟨fun i => (s₁ i - s₂ i) * (c₁ - c₂)⁻¹⟩`
   is total — it returns `pure`, so `Pr[⊥ | extract …] = 0` for all inputs.
   This is the `hss_nf` hypothesis required by `FiatShamir.euf_nma_bound`.

2. **`generalized_schnorr_fs_knowledge_soundness`**: `SpeciallySound` of the
   multi-base Schnorr Σ-protocol. From two accepting transcripts sharing the
   same commitment `T` but with distinct challenges `c₁ ≠ c₂`, the extractor
   returns a witness satisfying the relation.

3. **`generalized_schnorr_fs_nma_bound`**: the composition with VCV-io's
   `FiatShamir.euf_nma_bound`. For any managed-RO NMA adversary `B` against
   the Fiat-Shamir transform of `GeneralizedSchnorr.sigma` and any fork slot
   parameter `qH`, there exists a witness-extraction reduction such that
   `Fork.advantage · (Fork.advantage / (qH + 1) - 1/|F|) ≤ Pr[extraction succeeds]`.
   This is the Pointcheval–Stern forking-lemma bound specialised to
   GeneralizedSchnorr.

The rewinding overhead `(qH + 1) / |F|` is standard for Schnorr-style
protocols: the forking lemma replays the adversary at `qH + 1` positions,
each with a fresh challenge, and the `1/|F|` factor is the probability
that a random challenge matches the one that makes the two transcripts
accept. -/

open OracleSpec OracleComp SigmaProtocol
open scoped ENNReal

namespace PokerProtocolLean.Forking

variable (F : Type) [Field F] [Fintype F] [DecidableEq F] [SampleableType F]
variable (G : Type) [AddCommGroup G] [Module F G] [Fintype G] [DecidableEq G]
  [SampleableType G]

/-- **Extractor totality for GeneralizedSchnorr.**

The extractor `extract c₁ s₁ c₂ s₂ = pure ⟨fun i => (s₁ i - s₂ i) * (c₁ - c₂)⁻¹⟩`
is defined as `pure`, so it never fails: `Pr[⊥ | extract …] = 0` for all
inputs. This is the `hss_nf` hypothesis required by `FiatShamir.euf_nma_bound`.

Note: `(c₁ - c₂)⁻¹` is well-defined for all `c₁ - c₂ : F` because `F` is a
field (`Field.inv_zero = 0`), so even when `c₁ = c₂` the extractor returns
a (trivially valid) `0` scalar family rather than failing. The
`SpeciallySound` hypothesis `c₁ ≠ c₂` is only needed for the *correctness*
of the extracted witness, not for the *totality* of the extractor. -/
theorem sigma_extract_never_fails (n : ℕ)
    (c₁ c₂ : F) (s₁ s₂ : Fin n → F) :
    Pr[⊥ | (GeneralizedSchnorr.sigma F G n).extract c₁ s₁ c₂ s₂] = 0 := by
  dsimp only [GeneralizedSchnorr.sigma]
  simp

/-- **GeneralizedSchnorr FS knowledge-soundness**: the multi-base Schnorr
Σ-protocol satisfies `SpeciallySound`. From two accepting transcripts
sharing the same commitment `T` but with distinct challenges `c₁ ≠ c₂`,
the extractor `extract c₁ s₁ c₂ s₂ = fun i => (s₁ i - s₂ i) * (c₁ - c₂)⁻¹`
returns a witness satisfying the relation.

This is the key property that, composed with VCV-io's `FiatShamir.euf_nma_bound`
(the Fiat-Shamir forking lemma, proved generically for any Σ-protocol),
yields FS knowledge soundness with rewinding overhead `(qH + 1) / |F|`.

The proof is exactly `GeneralizedSchnorr.sigma_speciallySound`, which
carries out the `mul_smul` + `inv_mul_cancel₀` algebra in
`Module F G` — showing that subtracting the two verification equations
`dotSmul s₁ g = T + c₁ • R` and `dotSmul s₂ g = T + c₂ • R` yields
`dotSmul (s₁ - s₂) g = (c₁ - c₂) • R`, and multiplying by `(c₁ - c₂)⁻¹`
gives `dotSmul ((s₁ - s₂) * (c₁ - c₂)⁻¹) g = R`. -/
theorem generalized_schnorr_fs_knowledge_soundness (n : ℕ) :
    SpeciallySound (GeneralizedSchnorr.sigma F G n) :=
  GeneralizedSchnorr.sigma_speciallySound F G n

/-- **The Pointcheval–Stern NMA-to-extraction bound for GeneralizedSchnorr.**

Composing `generalized_schnorr_fs_knowledge_soundness` (SpeciallySound) and
`sigma_extract_never_fails` (extractor totality) with VCV-io's generic
`FiatShamir.euf_nma_bound` yields: for any managed-RO NMA adversary `B`
against the Fiat-Shamir transform of `GeneralizedSchnorr.sigma` and any
fork slot parameter `qH`, there exists a witness-extraction reduction such
that

  `Fork.advantage · (Fork.advantage / (qH + 1) - 1/|F|) ≤ Pr[extraction succeeds]`.

Here `Fork.advantage` counts exactly the managed-RO executions whose
forgery already verifies from challenge values present in the adversary's
managed cache or in the live hash-query log recorded by `Fork.runTrace`.
The parameter `qH` is the fork slot parameter (the size of the `Fin (qH + 1)`
candidate-position set).

The denominator `qH + 1` is the textbook Pointcheval–Stern denominator for
a source adversary with `qH` random-oracle queries. The `1/|F|` term is
`challengeSpaceInv F`, the probability of guessing a uniform challenge in
`F`. -/
theorem generalized_schnorr_fs_nma_bound (n : ℕ) (M : Type) [DecidableEq M]
    [Inhabited F] [Inhabited G]
    (hr : GenerableRelation
      (GeneralizedSchnorr.Statement F G n) (GeneralizedSchnorr.Witness F n)
      (GeneralizedSchnorr.relation F G n))
    (nmaAdv : SignatureAlg.managedRoNmaAdv
      (FiatShamir (m := OracleComp (unifSpec + (M × G →ₒ F)))
        (GeneralizedSchnorr.sigma F G n) hr M))
    (qH : ℕ) :
    ∃ reduction : GeneralizedSchnorr.Statement F G n →
        ProbComp (GeneralizedSchnorr.Witness F n),
      (FiatShamir.Fork.advantage
        (GeneralizedSchnorr.sigma F G n) hr M nmaAdv qH *
        (FiatShamir.Fork.advantage
          (GeneralizedSchnorr.sigma F G n) hr M nmaAdv qH /
          (qH + 1 : ENNReal) - FiatShamir.challengeSpaceInv F)) ≤
        Pr[= true | hardRelationExp hr reduction] :=
  FiatShamir.euf_nma_bound
    (GeneralizedSchnorr.sigma F G n) hr M
    (generalized_schnorr_fs_knowledge_soundness F G n)
    (fun _ _ _ _ => sigma_extract_never_fails F G n _ _ _ _)
    nmaAdv qH

end PokerProtocolLean.Forking
