import Mathlib.LinearAlgebra.LinearIndependent.Basic
import VCVio.CryptoFoundations.SigmaProtocol
import VCVio.CryptoFoundations.HardnessAssumptions.DiffieHellman
import VCVio.OracleComp.Constructions.SampleableType
import PokerProtocolLean.Foundations.AlgebraicSetup
import PokerProtocolLean.Foundations.ElGamal
import PokerProtocolLean.Foundations.UnknownDiscreteLog
import PokerProtocolLean.Foundations.Negligible
import PokerProtocolLean.Shuffle.ShuffleRelation
import PokerProtocolLean.Shuffle.ShuffleSigmaProtocol

/-!
# ZKShuffleProof — soundness results

Backing `poker_protocol/soundness.md` §二 (the full soundness argument).

## Proven results

* **`consistency_from_structure`**: the multi-extractor consistency theorem.
  Given two E2-equations with a common RHS and the initial ciphertext
  structure (linearly independent `{m_i}`, `pk ∉ span{m_i}`), the two
  extractors must produce identical `k` and `pk_delta`. Fully proved.

* **`layer2_plaintext_eq`**: from E1 and E2, the plaintext equation
  `Σ_j k_j • (decrypt sk out[j]) = Σ_i ρ_i • (decrypt sk in[i])` holds.
  Proved by computing `E2 - sk · E1`, distributing, and cancelling
  `pk - sk · g = 0`. Fully proved.

## Removed stubs

The following were `True` stubs with no mathematical content and have
been deleted:

* `layer1_extract` — superseded by `consistency_from_structure`.
* `layer3_schwartz_zippel` — pure pass-through of its hypothesis, the
  actual Schwartz-Zippel application requires the game-hop machinery
  in `GameHops.KJLowDegree` (which is itself a stub).
* `layer4_component_constraint` — vague attack-description stub with no
  precise mathematical statement.
* `sigma_knowledge_sound` — top-level composition stub that depended on
  the deleted layers.
-/

open OracleSpec OracleComp SigmaProtocol
open PokerProtocolLean.Foundations (ElGamalCiphertext smulByG)
open DiffieHellman (DLogAdversary dlogExp)
open scoped ENNReal

namespace PokerProtocolLean.Shuffle

variable (F : Type) [Field F] [Fintype F] [DecidableEq F] [SampleableType F]
variable (G : Type) [AddCommGroup G] [Module F G] [Fintype G] [DecidableEq G]
  [SampleableType G]
variable (g : G)
variable (hg : Function.Bijective (smulByG F G g))

/-!
## Analysis of `initial_encrypt_deck` structure

Rust code (`game.rs::MentalPokerGame::new`):

```rust
let initial_encrypt_deck = deck_plaintext
    .iter()
    .map(|c| {
        ElGamalCiphertext {
            c1: *BASE_G,   // ← ALL cards share the SAME c1 = g
            c2: *c,        // ← plaintext (hash_to_curve label)
        }
    }).collect();
```

Therefore:
* `∀ i, input_cts[i].c1 = g` — the c1-components are NOT linearly
  independent (they are all the same point!).
* `input_cts[i].c2 = plaintext_i` — these ARE the `hash_to_curve`
  outputs `hash("texas_poker/card/i")`, which are computationally
  independent under the ROM.

After re-encryption `output[j] = re_encrypt(input[π(j)], pk, r_j)`:
* `output[j].c1 = g + r_j • g = (1 + r_j) • g`
* `output[j].c2 = plaintext[π(j)] + r_j • pk`
-/

/-- **Initial ciphertext structure hypothesis**.

The initial ciphertexts have a fixed c1 component (`g`) and plaintext c2
components (card identities via `hash_to_curve`). The plaintexts `{m_i}`
are linearly independent, and neither of the two group elements that will
appear as "free" coefficients in the Layer-1 ciphertext equations — the
generator `g` (the c1 RHS basis) and the public key `pk` (the trailing
c2 basis point) — lies in their span.

This is the refined hypothesis matching `game.rs::initial_encrypt_deck`:
`input_cts[i] = ⟨g, m_i⟩` where `{m_i}` are linearly independent. The
two `∉ span` conditions are the c1/c2 *duals* needed for the
multi-extractor consistency argument: `g ∉ span{m_i}` discharges the
c1-equation, `pk ∉ span{m_i}` discharges the c2-equation. -/
def InitialCiphertextStructure {n : ℕ} (g pk : G) (stmt : ShuffleStatement F G n) :
    Prop :=
  (∀ i : Fin n, (stmt.input_cts i).c1 = g) ∧
  LinearIndependent F (fun i : Fin n => (stmt.input_cts i).c2) ∧
  g ∉ Submodule.span F (Set.range (fun i : Fin n => (stmt.input_cts i).c2)) ∧
  pk ∉ Submodule.span F (Set.range (fun i : Fin n => (stmt.input_cts i).c2))

/-- **Output c2-independence via plaintext independence**.

Given the initial structure `input_cts[i] = ⟨g, m_i⟩` with `{m_i}`
linearly independent, after re-encryption each output ciphertext is a
re-encryption of some input, so
`output[j].c2 = m_{π(j)} + r_j • pk`. The output c2-components are *not*
literally a permutation of `{m_i}` (each is shifted by `r_j • pk`), so we
do **not** claim they are linearly independent.

What IS true — and is what the multi-extractor consistency argument needs
— is that the *input* plaintexts `{m_i}` are linearly independent, and a
bijection (permutation) of a linearly independent family is again linearly
independent. This is the correct replacement for the (false) statement
that the output c1-components are linearly independent: re-encryption adds
`r_j • g` to c1, and since `input_cts[i].c1 = g` is constant, all output
c1-components lie in the 1-dimensional subspace `span{g}`, so they cannot
be linearly independent for `n ≥ 2`. The binding power therefore comes
from the c2 / plaintext side, not the c1 side. -/
theorem out_c2_indep_via_plaintext {n : ℕ} (g : G) (stmt : ShuffleStatement F G n)
    (π : Fin n → Fin n) (hπ : Function.Bijective π)
    (hinit : InitialCiphertextStructure F G g stmt.pk stmt) :
    LinearIndependent F (fun j : Fin n => (stmt.input_cts (π j)).c2) := by
  -- A permutation of a linearly independent family is linearly independent:
  -- composition with an injective map preserves linear independence
  -- (`LinearIndependent.comp`). A bijection is in particular injective.
  have hli : LinearIndependent F (fun i : Fin n => (stmt.input_cts i).c2) := hinit.2.1
  exact hli.comp π hπ.left

/-- **Consistency from the c1/c2 equation system** (corrected statement).

This is the corrected version of the multi-extractor consistency
argument. The original statement took only the *c1*-equations as
hypotheses and concluded `k1 = k2 ∧ pkδ1 = pkδ2`. That is **false** in
general: since `input_cts[i].c1 = g` is constant, all output c1-components
`out[j].c1 = (1 + r_j) • g` lie in the 1-dimensional subspace `span{g}`,
so subtracting the two c1-equations yields a *single* scalar equation

    Σ_j (k1_j − k2_j) · (1 + r_j) + (pkδ1 − pkδ2) = 0

in `n + 1` unknowns — under-determined for `n ≥ 1`. One cannot conclude
`k1 = k2` from the c1-equations alone.

The fix (Layer 1, matching `shuffle_proof.rs` lines 92–170): the
extractor is run on **three** GeneralizedSchnorr sub-proofs and must
produce a `(k, pkδ)` satisfying **both** ciphertext equations

    (E1)  Σ_j k_j • out[j].c1 + pkδ • g  =  Σ_i ρ_i • in[i].c1
    (E2)  Σ_j k_j • out[j].c2 + pkδ • pk =  Σ_i ρ_i • in[i].c2

simultaneously. The binding power lives in E2: writing
`out[j].c2 = m_{π(j)} + r_j • pk` and `in[i].c2 = m_i`, subtracting the
two E2-equations gives

    Σ_j Δk_j • m_{π(j)} + (Σ_j Δk_j · r_j + Δδ) • pk = 0,

where `Δk := k1 − k2`, `Δδ := pkδ1 − pkδ2`. Because `pk ∉ span{m_i}` and
`{m_i}` is linearly independent, both coefficients vanish; the first
forces `Δk = 0` (the permuted family is linearly independent), the second
then forces `Δδ = 0`. E1 is consistent with this (it was never
contradictory; it simply carries no extra information about `k`).

## Hypotheses

* `hout_c2 j : out[j].c2 = in[π j].c2 + (r j) • pk` — the re-encryption
  identity on the c2 side.
* `hR_c2_*` — the two E2-equations with a common RHS `R₂`.
* `hinit` — provides `{m_i}` linearly independent and `pk ∉ span{m_i}`. -/
theorem consistency_from_structure {n : ℕ} (g : G) (stmt : ShuffleStatement F G n)
    (π : Fin n → Fin n) (hπ : Function.Bijective π)
    (r : Fin n → F)
    (hout_c2 : ∀ j : Fin n,
      (stmt.output_cts j).c2 = (stmt.input_cts (π j)).c2 + (r j) • stmt.pk)
    (hinit : InitialCiphertextStructure F G g stmt.pk stmt)
    (k1 k2 : Fin n → F) (pkδ1 pkδ2 : F) (R₂ : G)
    (heq1_c2 :
      (∑ j : Fin n, k1 j • (stmt.output_cts j).c2) + pkδ1 • stmt.pk = R₂)
    (heq2_c2 :
      (∑ j : Fin n, k2 j • (stmt.output_cts j).c2) + pkδ2 • stmt.pk = R₂) :
    k1 = k2 ∧ pkδ1 = pkδ2 := by
  -- Notation: Δk := k1 − k2, Δδ := pkδ1 − pkδ2.
  let Δk : Fin n → F := fun j => k1 j - k2 j
  let Δδ : F := pkδ1 - pkδ2
  -- (E2₁ − E2₂): Σ_j Δk_j • out[j].c2 + Δδ • pk = 0.
  -- Step 1: factor the difference of the two E2 LHSs into a single
  --         Δk-weighted sum + Δδ • pk. `sub_smul` distributes the pointwise
  --         smul, `Finset.sum_sub_distrib` moves the subtraction out of the
  --         sum, and `module` closes the residual smul/add identity.
  have hkey :
      (∑ j, k1 j • (stmt.output_cts j).c2) + pkδ1 • stmt.pk
        - ((∑ j, k2 j • (stmt.output_cts j).c2) + pkδ2 • stmt.pk)
      = (∑ j, Δk j • (stmt.output_cts j).c2) + Δδ • stmt.pk := by
    have h1 :
        (∑ j, (k1 j - k2 j) • (stmt.output_cts j).c2)
          = (∑ j, k1 j • (stmt.output_cts j).c2) - (∑ j, k2 j • (stmt.output_cts j).c2) := by
      simp only [sub_smul]; rw [Finset.sum_sub_distrib]
    rw [h1]; module
  have hdiff :
      (∑ j : Fin n, Δk j • (stmt.output_cts j).c2) + Δδ • stmt.pk = 0 := by
    calc (∑ j, Δk j • (stmt.output_cts j).c2) + Δδ • stmt.pk
        = (∑ j, k1 j • (stmt.output_cts j).c2) + pkδ1 • stmt.pk
            - ((∑ j, k2 j • (stmt.output_cts j).c2) + pkδ2 • stmt.pk) := hkey.symm
      _ = R₂ - R₂ := by rw [heq1_c2, heq2_c2]
      _ = 0 := sub_self R₂
  -- Step 2: substitute the re-encryption identity `out[j].c2 = m_{π(j)} + r_j • pk`
  --         pointwise, then collect the pk terms into a single `((Σ Δk_j·r_j) + Δδ) • pk`.
  have hexpand :
      (∑ j, Δk j • (stmt.input_cts (π j)).c2)
        + ((∑ j, Δk j * r j) + Δδ) • stmt.pk = 0 := by
    -- Per-point: Δk_j • out[j].c2 = Δk_j • m_{π(j)} + (Δk_j * r_j) • pk.
    -- `smul_add` splits the pointwise smul over the `+`, `smul_smul` turns
    -- `Δk_j • (r_j • pk)` into `(Δk_j * r_j) • pk`, and `sum_add_distrib`
    -- moves the resulting `+` outside the sum.
    have hpoint :
        (∑ j, Δk j • (stmt.output_cts j).c2)
          = (∑ j, Δk j • (stmt.input_cts (π j)).c2)
              + (∑ j, (Δk j * r j) • stmt.pk) := by
      simp only [hout_c2, smul_add, smul_smul, Finset.sum_add_distrib]
    -- The pk sum has a *varying* scalar but a *fixed* vector `pk`; `Finset.sum_smul`
    -- — NOT `Finset.smul_sum`, which needs a constant scalar — factors it out:
    --   Σ_j (Δk_j · r_j) • pk = (Σ_j Δk_j · r_j) • pk.
    have hcomb : (∑ j, (Δk j * r j) • stmt.pk) = (∑ j, Δk j * r j) • stmt.pk := by
      rw [← Finset.sum_smul]
    -- Compose: rewrite the goal back to the `out`-indexed form `Σ Δk • out + Δδ • pk`,
    -- which equals `0` by `hdiff`.
    have heq :
        (∑ j, Δk j • (stmt.input_cts (π j)).c2)
          + ((∑ j, Δk j * r j) + Δδ) • stmt.pk
        = (∑ j, Δk j • (stmt.output_cts j).c2) + Δδ • stmt.pk := by
      rw [add_smul, ← hcomb, ← add_assoc, ← hpoint]
    rw [heq]; exact hdiff
  -- Step 3: direct-sum argument. With `M := Σ_j Δk_j • m_{π(j)}` and
  --         `c := (Σ Δk_j · r_j) + Δδ`, `hexpand` is `M + c • pk = 0`.
  --         `M ∈ span{m_i}` (Step 3a); if `c ≠ 0` then `pk = (-c⁻¹) • M ∈ span{m_i}`,
  --         contradicting `pk ∉ span{m_i}` (Step 3b). Hence `c = 0` and `M = 0`.
  have h_pk_not : stmt.pk ∉
      Submodule.span F (Set.range (fun i : Fin n => (stmt.input_cts i).c2)) :=
    hinit.2.2.2
  have hM_in_span :
      (∑ j, Δk j • (stmt.input_cts (π j)).c2) ∈
        Submodule.span F (Set.range (fun i : Fin n => (stmt.input_cts i).c2)) := by
    apply Submodule.sum_mem
    intro j _
    refine Submodule.smul_mem _ _ (Submodule.subset_span ⟨π j, rfl⟩)
  set M : G := ∑ j, Δk j • (stmt.input_cts (π j)).c2
  set c : F := (∑ j, Δk j * r j) + Δδ
  have hM_eq : M = -(c • stmt.pk) := by
    have hzM : M + c • stmt.pk = 0 := hexpand
    exact add_eq_zero_iff_eq_neg.mp hzM
  have hc_zero : c = 0 := by
    by_contra hne
    apply h_pk_not
    -- From `M = -(c • pk)` and `M ∈ span`, deduce `c • pk ∈ span` (closed
    -- under negation), then `pk = c⁻¹ • (c • pk) ∈ span` (closed under scalar
    -- action) since `c ≠ 0`.
    have hcpk_in_span : c • stmt.pk ∈
        Submodule.span F (Set.range (fun i : Fin n => (stmt.input_cts i).c2)) := by
      have hneg : -(c • stmt.pk) ∈
          Submodule.span F (Set.range (fun i : Fin n => (stmt.input_cts i).c2)) :=
        hM_eq ▸ hM_in_span
      have hnegneg : -(-(c • stmt.pk)) ∈
          Submodule.span F (Set.range (fun i : Fin n => (stmt.input_cts i).c2)) :=
        Submodule.neg_mem _ hneg
      rwa [neg_neg] at hnegneg
    have hpk_eq : stmt.pk = c⁻¹ • (c • stmt.pk) := by
      rw [smul_smul, inv_mul_cancel₀ hne, one_smul]
    rw [hpk_eq]
    exact Submodule.smul_mem _ _ hcpk_in_span
  have hM_zero : M = 0 := by
    rw [hM_eq, hc_zero, zero_smul, neg_zero]
  -- Step 4: `{m_{π(j)}}` is linearly independent (a permutation of a linearly
  --         independent family), so `M = 0` forces `Δk = 0`, hence `k1 = k2`.
  have hLIπ : LinearIndependent F (fun j => (stmt.input_cts (π j)).c2) :=
    hinit.2.1.comp π hπ.left
  have hΔk_zero : ∀ j, Δk j = 0 :=
    (Fintype.linearIndependent_iff (R := F) (v := fun j => (stmt.input_cts (π j)).c2)).mp hLIπ _ hM_zero
  have hk : k1 = k2 := by
    funext j
    have hj : Δk j = 0 := hΔk_zero j
    -- Δk j unfolds definitionally to `k1 j - k2 j`.
    exact sub_eq_zero.mp hj
  -- Step 5: with Δk = 0 the sum Σ Δk_j · r_j vanishes, so `c = Δδ`;
  --         combined with `c = 0` this gives `Δδ = 0`, hence `pkδ1 = pkδ2`.
  have hδ : pkδ1 = pkδ2 := by
    have hsum_zero : (∑ j, Δk j * r j) = 0 :=
      Finset.sum_eq_zero fun j _ => by rw [hΔk_zero j, zero_mul]
    have hc : (∑ j, Δk j * r j) + (pkδ1 - pkδ2) = 0 := hc_zero
    rw [hsum_zero, zero_add] at hc
    exact sub_eq_zero.mp hc
  exact ⟨hk, hδ⟩

/-- Layer 2: from E1 and E2, the plaintext equation `E_plain` holds.

Computing `E2 - sk · E1` and using the bridge lemma
`c2_minus_sk_c1_eq_plaintext` (in `PokerProtocolLean.Foundations.ElGamal`),
we obtain the plaintext equation
`Σ_j k_j • (decrypt sk out[j]) = Σ_i ρ_i • (decrypt sk in[i])`.

The ciphertexts `in[i] = ⟨g, m_i⟩` are *not* standard ElGamal
encryptions (c1 is fixed, not r·g), but they are valid ElGamal encryptions
of `m_i - pk` with randomness 1.  The bridge lemma therefore yields
`decrypt sk in[i] = m_i - pk` and `decrypt sk out[j] = m_{π(j)} - pk`.
Substituting into `E2 - sk · E1` and cancelling `pk - sk · g = 0` gives
the equation below. -/
theorem layer2_plaintext_eq {n : ℕ} (g : G) (sk : F)
    (out_plain in_plain : Fin n → G)
    (stmt : ShuffleStatement F G n)
    (k : Fin n → F) (pk_delta : F) (ρ : Fin n → F)
    (hout_dec : ∀ j : Fin n,
      ElGamalCiphertext.decrypt F G sk (stmt.output_cts j) = out_plain j)
    (hin_dec : ∀ i : Fin n,
      ElGamalCiphertext.decrypt F G sk (stmt.input_cts i) = in_plain i)
    (hpk : stmt.pk = sk • g)
    (hE1 : (∑ j : Fin n, k j • (stmt.output_cts j).c1) + pk_delta • g
          = ∑ i : Fin n, ρ i • (stmt.input_cts i).c1)
    (hE2 : (∑ j : Fin n, k j • (stmt.output_cts j).c2) + pk_delta • stmt.pk
          = ∑ i : Fin n, ρ i • (stmt.input_cts i).c2)
    : (∑ j : Fin n, k j • out_plain j)
        = (∑ i : Fin n, ρ i • in_plain i) := by
  have hE1' : ∑ j, k j • (stmt.output_cts j).c1
      = (∑ i, ρ i • (stmt.input_cts i).c1) - pk_delta • g := by
    calc
      ∑ j, k j • (stmt.output_cts j).c1
        = ∑ j, k j • (stmt.output_cts j).c1 + pk_delta • g - pk_delta • g := by abel
      _ = (∑ i, ρ i • (stmt.input_cts i).c1) - pk_delta • g := by rw [← hE1]
  have hE2' : ∑ j, k j • (stmt.output_cts j).c2
      = (∑ i, ρ i • (stmt.input_cts i).c2) - pk_delta • stmt.pk := by
    calc
      ∑ j, k j • (stmt.output_cts j).c2
        = ∑ j, k j • (stmt.output_cts j).c2 + pk_delta • stmt.pk - pk_delta • stmt.pk := by abel
      _ = (∑ i, ρ i • (stmt.input_cts i).c2) - pk_delta • stmt.pk := by rw [← hE2]
  have hswap : sk • (pk_delta • g) = pk_delta • (sk • g) := by
    have h : ∀ (a b : F) (x : G), a • (b • x) = (a * b) • x := by
      intro a b x; rw [smul_smul]
    rw [h, mul_comm sk pk_delta, ← h]
  have hdlhs : ∑ j, k j • out_plain j
      = (∑ j, k j • (stmt.output_cts j).c2) - (∑ j, k j • sk • (stmt.output_cts j).c1) := by
    have h : ∀ j ∈ Finset.univ, k j • out_plain j
        = k j • ((stmt.output_cts j).c2 - sk • (stmt.output_cts j).c1) := by
      intro j _
      have hdeqj : out_plain j = (stmt.output_cts j).c2 - sk • (stmt.output_cts j).c1 := by
        change out_plain j = ElGamalCiphertext.decrypt F G sk (stmt.output_cts j)
        exact Eq.symm (hout_dec j)
      rw [hdeqj]
    rw [Finset.sum_congr rfl h]
    have h2 : ∀ j ∈ Finset.univ, k j • ((stmt.output_cts j).c2 - sk • (stmt.output_cts j).c1)
        = k j • (stmt.output_cts j).c2 - k j • sk • (stmt.output_cts j).c1 := by
      intro j _
      simp [smul_sub, smul_smul]
    rw [Finset.sum_congr rfl h2]
    rw [← Finset.sum_sub_distrib]
  have drhs : ∑ i, ρ i • in_plain i
      = (∑ i, ρ i • (stmt.input_cts i).c2) - (∑ i, ρ i • sk • (stmt.input_cts i).c1) := by
    have h : ∀ i ∈ Finset.univ, ρ i • in_plain i
        = ρ i • ((stmt.input_cts i).c2 - sk • (stmt.input_cts i).c1) := by
      intro i _
      have hdeqi : in_plain i = (stmt.input_cts i).c2 - sk • (stmt.input_cts i).c1 := by
        change in_plain i = ElGamalCiphertext.decrypt F G sk (stmt.input_cts i)
        exact Eq.symm (hin_dec i)
      rw [hdeqi]
    rw [Finset.sum_congr rfl h]
    have h2 : ∀ i ∈ Finset.univ, ρ i • ((stmt.input_cts i).c2 - sk • (stmt.input_cts i).c1)
        = ρ i • (stmt.input_cts i).c2 - ρ i • sk • (stmt.input_cts i).c1 := by
      intro i _
      simp [smul_sub, smul_smul]
    rw [Finset.sum_congr rfl h2]
    rw [← Finset.sum_sub_distrib]
  rw [hdlhs, drhs]
  -- Goal: (Σ k_j • c2_j) - (Σ k_j • sk • c1_j) = (Σ ρ_i • c2'_i) - (Σ ρ_i • sk • c1'_i)
  have hsmul1 : (∑ j, k j • sk • (stmt.output_cts j).c1)
      = sk • (∑ j, k j • (stmt.output_cts j).c1) := by
    have h : ∀ j ∈ Finset.univ, k j • sk • (stmt.output_cts j).c1
        = sk • (k j • (stmt.output_cts j).c1) := by
      intro j _
      simp [smul_smul, mul_comm]
    rw [Finset.sum_congr rfl h]
    rw [← Finset.smul_sum]
  have hsmul2 : (∑ i, ρ i • sk • (stmt.input_cts i).c1)
      = sk • (∑ i, ρ i • (stmt.input_cts i).c1) := by
    have h : ∀ i ∈ Finset.univ, ρ i • sk • (stmt.input_cts i).c1
        = sk • (ρ i • (stmt.input_cts i).c1) := by
      intro i _
      simp [smul_smul, mul_comm]
    rw [Finset.sum_congr rfl h]
    rw [← Finset.smul_sum]
  rw [hE2']
  rw [hsmul1]
  rw [hE1']
  rw [hsmul2]
  have hcancel : pk_delta • stmt.pk = pk_delta • (sk • g) := by rw [hpk]
  have hgoal : (∑ i, ρ i • (stmt.input_cts i).c2) - pk_delta • stmt.pk
      - (sk • ((∑ i, ρ i • (stmt.input_cts i).c1) - pk_delta • g))
    = (∑ i, ρ i • (stmt.input_cts i).c2) - sk • (∑ i, ρ i • (stmt.input_cts i).c1) := by
    rw [smul_sub]
    rw [hcancel, hswap]
    abel
  exact hgoal

end PokerProtocolLean.Shuffle
