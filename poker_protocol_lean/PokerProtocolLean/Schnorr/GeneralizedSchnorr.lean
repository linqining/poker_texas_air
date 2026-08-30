import Mathlib.Data.Fintype.Vector
import VCVio.CryptoFoundations.SigmaProtocol
import VCVio.OracleComp.Constructions.SampleableType
import VCVio.OracleComp.QueryTracking.RandomOracle.DeferredSampling
import VCVio.ProgramLogic.Tactics.Unary
import VCVio.ProgramLogic.Tactics.Relational
import PokerProtocolLean.Foundations.AlgebraicSetup
import PokerProtocolLean.Foundations.Negligible
import Mathlib.Algebra.BigOperators.Fin
import Mathlib.Algebra.Module.BigOperators
import Mathlib.Tactic.Module

/-!
# GeneralizedSchnorrProof — multi-base Σ-protocol

This file formalizes the **multi-base** Schnorr Σ-protocol that backs
`poker_protocol/src/zk_shuffle/generalized_schnorr_proof.rs`.

Concretely, the prover proves knowledge of scalars `k_0, …, k_{n-1}` such that

    Σ_i k_i • g_i = R

where `base_points : Fin n → G` and `R : G` are public. The single-base
Schnorr protocol in `VCVio.Examples.Schnorr.SigmaProtocol` is the special
case `n = 1`. The present file generalises that template to arbitrary `n`
and proves the three textbook Σ-protocol properties:

| Property                | Theorem                              |
| ----------------------- | ----------------------------------- |
| Perfect completeness    | `sigma_complete`                    |
| Special soundness       | `sigma_speciallySound`              |
| Perfect HVZK            | `sigma_perfect_hvzk`                |

Plus the two companion facts the Fiat-Shamir reduction needs:
`sigma_simCommitPredictability` and `sigma_simChalUniformGivenCommit`.

The construction is a literal `Fin n → F`-indexed lift of VCV-io's single-base
Schnorr; the algebraic identity underlying every proof is the bilinearity of
the `Module F G` action (`add_smul`, `mul_smul`).
-/

open OracleSpec OracleComp SigmaProtocol
open OracleComp.DeferredSampling
open scoped ENNReal

namespace PokerProtocolLean.GeneralizedSchnorr

variable (F : Type) [Field F] [Fintype F] [DecidableEq F] [SampleableType F]
variable (G : Type) [AddCommGroup G] [Module F G] [Fintype G] [DecidableEq G]
  [SampleableType G]

/-- Statement for the multi-base Schnorr protocol:
`(base_points, R)` where `base_points : Fin n → G` and `R` is the claimed
linear combination `Σ k_i • g_i`. -/
structure Statement (F : Type) (G : Type) (n : ℕ) where
  /-- Public base points `g_0, …, g_{n-1}`. -/
  base_points : Fin n → G
  /-- Claimed linear combination `Σ k_i • g_i`. -/
  R : G

/-- Witness: an indexed family of secret scalars `k_0, …, k_{n-1}`. -/
structure Witness (F : Type) (n : ℕ) where
  /-- Secret scalars. -/
  scalars : Fin n → F

/-- `Statement F G n` is equivalent to `(Fin n → G) × G`, transporting
`SampleableType` from the product. -/
def Statement.equivProd (F : Type) (G : Type) (n : ℕ) :
    Statement F G n ≃ ((Fin n → G) × G) where
  toFun := fun s => (s.base_points, s.R)
  invFun := fun p => ⟨p.1, p.2⟩
  left_inv := fun _ => rfl
  right_inv := fun _ => rfl

/-- `Witness F n` is equivalent to `Fin n → F`, transporting `SampleableType`. -/
def Witness.equivFun (F : Type) (n : ℕ) : Witness F n ≃ (Fin n → F) where
  toFun := fun w => w.scalars
  invFun := fun s => ⟨s⟩
  left_inv := fun _ => rfl
  right_inv := fun _ => rfl

/-- `SampleableType` for `Statement F G n` via the product equivalence. -/
noncomputable instance Statement.sampleableType (n : ℕ) [SampleableType G] :
    SampleableType (Statement F G n) :=
  SampleableType.ofEquiv (Statement.equivProd F G n).symm

/-- `SampleableType` for `Witness F n` via the function equivalence. -/
noncomputable instance Witness.sampleableType (n : ℕ) [SampleableType F] :
    SampleableType (Witness F n) :=
  SampleableType.ofEquiv (Witness.equivFun F n).symm

/-- `Inhabited` for `Statement F G n` from `Inhabited G`. -/
instance Statement.inhabited (n : ℕ) [Inhabited G] : Inhabited (Statement F G n) :=
  ⟨⟨fun _ => default, default⟩⟩

/-- `Inhabited` for `Witness F n` from `Inhabited F`. -/
instance Witness.inhabited (n : ℕ) [Inhabited F] : Inhabited (Witness F n) :=
  ⟨⟨fun _ => default⟩⟩

/-- Dot product: `Σ_i k_i • g_i` over a common-length pair of indexed families. -/
def dotSmul {F : Type} [Field F] {G : Type} [AddCommGroup G] [Module F G]
    {n : ℕ} (k : Fin n → F) (g : Fin n → G) : G :=
  ∑ i, k i • g i

/-- The relation: the witness scalars linearly combine the base points to `R`.
Bool-valued predicate (VCV-io `SigmaProtocol` convention). -/
def relation (n : ℕ) (stmt : Statement F G n) (wit : Witness F n) : Bool :=
  decide (dotSmul wit.scalars stmt.base_points = stmt.R)

/-- A multi-base Schnorr Σ-protocol.

* `commit`: samples `r_vec ← $ᵗ (Fin n → F)`, returns
  `(T = dotSmul r_vec base_points, r_vec)`.
* `respond`: `s_i = r_i + c * k_i`.
* `verify`: `decide (dotSmul s base_points = T + c • R)`.
* `extract`: `k_i = (s₁_i - s₂_i) * (c₁ - c₂)⁻¹`. -/
def sigma (n : ℕ) : SigmaProtocol
    (Statement F G n) (Witness F n) G (Fin n → F) F (Fin n → F)
    (relation F G n) where
  commit stmt _wit := do
    let r_vec ← ($ᵗ (Fin n → F))
    let T := dotSmul r_vec stmt.base_points
    return (T, r_vec)
  respond _stmt wit r_vec c :=
    pure (fun i => r_vec i + c * wit.scalars i)
  verify stmt T c s :=
    decide (dotSmul s stmt.base_points = T + c • stmt.R)
  sim _stmt := $ᵗ G
  extract c₁ s₁ c₂ s₂ :=
    pure ⟨fun i => (s₁ i - s₂ i) * (c₁ - c₂)⁻¹⟩

/-! ## Algebraic lemmas

These are the per-index identities that drive every property below. They are
just `Module`/`Field` axioms folded over a `Fin n → _` family via `Finset.sum`.
-/

section Algebra

/-- `dotSmul` distributes over pointwise addition of scalar families. -/
theorem dotSmul_add {n : ℕ} (a b : Fin n → F) (g : Fin n → G) :
    dotSmul (fun i => a i + b i) g = dotSmul a g + dotSmul b g := by
  simp only [dotSmul]
  rw [← Finset.sum_add_distrib]
  congr 1; ext i; rw [add_smul]

/-- `dotSmul` of a scalar-mul family: `dotSmul (c · a) g = c • dotSmul a g`. -/
theorem dotSmul_smul {n : ℕ} (c : F) (a : Fin n → F) (g : Fin n → G) :
    dotSmul (fun i => c * a i) g = c • dotSmul a g := by
  simp only [dotSmul, Finset.smul_sum]
  congr 1; ext i; rw [mul_smul]

/-- `dotSmul` of a pointwise subtraction. -/
theorem dotSmul_sub {n : ℕ} (a b : Fin n → F) (g : Fin n → G) :
    dotSmul (fun i => a i - b i) g = dotSmul a g - dotSmul b g := by
  simp only [dotSmul]
  rw [← Finset.sum_sub_distrib]
  congr 1; ext i; rw [sub_smul]

/-- `dotSmul` of an extractor-scaled family:
`dotSmul (fun i => (s₁ i - s₂ i) * d) g = d • dotSmul (s₁ - s₂) g`. -/
theorem dotSmul_extract_scale {n : ℕ} (s₁ s₂ : Fin n → F) (d : F)
    (g : Fin n → G) :
    dotSmul (fun i => (s₁ i - s₂ i) * d) g = d • dotSmul (fun i => s₁ i - s₂ i) g := by
  simp only [dotSmul, Finset.smul_sum]
  congr 1; ext i; module

/-- The honest-prover verification equation:
for every `(r_vec, c)`, the response `s = r + c · k` satisfies
`dotSmul s g = dotSmul r g + c • dotSmul k g`. -/
theorem honest_verify_eq {n : ℕ} (r k : Fin n → F) (g : Fin n → G) (c : F) :
    dotSmul (fun i => r i + c * k i) g =
      dotSmul r g + c • dotSmul k g := by
  rw [dotSmul_add, dotSmul_smul]

end Algebra

/-! ## Perfect completeness

An honest prover with a valid witness always produces an accepting transcript.
The proof is a `Module` calculation that reduces to
`dotSmul (r + c·k) g = dotSmul r g + c • dotSmul k g = T + c • R`. -/

theorem sigma_complete (n : ℕ) :
    PerfectlyComplete (sigma F G n) := by
  intro stmt wit hrel
  have h_eq : dotSmul wit.scalars stmt.base_points = stmt.R :=
    of_decide_eq_true hrel
  have hverify :
    ∀ (r_vec : Fin n → F) (c : F),
      dotSmul (fun i => r_vec i + c * wit.scalars i) stmt.base_points =
        dotSmul r_vec stmt.base_points + c • stmt.R := by
    intro r_vec c
    rw [honest_verify_eq, h_eq]
  simp only [sigma, monad_norm]
  simp [hverify]

/-! ## Special soundness

From two accepting transcripts sharing the same commitment `T` but with distinct
challenges `c₁ ≠ c₂`, the extractor
`extract c₁ s₁ c₂ s₂ = fun i => (s₁ i - s₂ i) * (c₁ - c₂)⁻¹`
returns a witness satisfying the relation.

Algebra: subtracting the two verification equations gives
`dotSmul (s₁ - s₂) g = (c₁ - c₂) • R`, hence (multiplying by `(c₁ - c₂)⁻¹`)
`dotSmul ((s₁ - s₂) * (c₁ - c₂)⁻¹) g = R`. -/

theorem sigma_speciallySound (n : ℕ) :
    SpeciallySound (sigma F G n) := by
  intro stmt T c₁ c₂ s₁ s₂ h_ne h_v1 h_v2 w h_w
  dsimp only [sigma] at *
  simp only [support_pure, Set.mem_singleton_iff] at h_w
  subst h_w
  simp only [decide_eq_true_eq] at h_v1 h_v2 ⊢
  have h_sub : dotSmul (fun i => s₁ i - s₂ i) stmt.base_points =
      (c₁ - c₂) • stmt.R := by
    rw [dotSmul_sub, h_v1, h_v2]
    module
  have h_ne' : c₁ - c₂ ≠ 0 := sub_ne_zero.mpr h_ne
  simp only [relation, decide_eq_true_eq] at ⊢
  rw [dotSmul_extract_scale]
  rw [h_sub]
  rw [← mul_smul, inv_mul_cancel₀ h_ne', one_smul]

/-! ## Perfect HVZK

The simulator samples `c, s ← $ᵗ (Fin n → F)`, reconstructs
`T = dotSmul s g - c • R`, and the resulting transcript distribution equals
the real one.

Bijection: for fixed `c`, the response map `r ↦ r + c · k` is a bijection on
`Fin n → F` (per-coordinate translation). -/

def simTranscript (n : ℕ) (stmt : Statement F G n) :
    ProbComp (G × F × (Fin n → F)) := do
  let c ← ($ᵗ F)
  let s ← ($ᵗ (Fin n → F))
  return (dotSmul s stmt.base_points - c • stmt.R, c, s)

open OracleComp.ProgramLogic OracleComp.ProgramLogic.Relational in
/-- **Perfect HVZK for the multi-base Schnorr protocol.**

The proof is a literal `Fin n → F`-indexed lift of VCV-io's single-base
Schnorr HVZK (`VCVio.Examples.Schnorr.SigmaProtocol.sigma_hvzk`):

1. Apply `evalDist_ext` to reduce distribution equality to pointwise
   probability equality at an arbitrary transcript `t`.
2. Bridge the real transcript `(dotSmul r_vec g, c, r_vec + c·k)` to the
   independent-sampling form `(dotSmul (r_vec + c·k) g - c • R, c, r_vec + c·k)`
   by the bilinearity identity `honest_verify_eq` (`dotSmul (r + c·k) g =
   dotSmul r g + c • dotSmul k g`) combined with the witness validity
   equation `dotSmul k g = R`.
3. Bridge the simulator transcript `(dotSmul s g - c • R, c, s)` to the same
   independent form via the per-coordinate translation bijection
   `r_vec ↦ fun i => r_vec i + c * wit.scalars i` on `Fin n → F`. The inverse
   is `s ↦ fun i => s i - c * wit.scalars i`, with cancellation by
   `sub_add_cancel` per coordinate. -/
theorem sigma_perfect_hvzk (n : ℕ) :
    PerfectHVZK (sigma F G n) (fun stmt => simTranscript F G n stmt) := by
  intro stmt wit hrel
  have h_eq : dotSmul wit.scalars stmt.base_points = stmt.R :=
    of_decide_eq_true hrel
  apply evalDist_ext
  intro t
  trans Pr[= t | do
    let c ← ($ᵗ F)
    let r_vec ← ($ᵗ (Fin n → F))
    pure ((dotSmul (fun i => r_vec i + c * wit.scalars i) stmt.base_points
            - c • stmt.R,
           c,
           fun i => r_vec i + c * wit.scalars i) : G × F × (Fin n → F))]
  · simp only [SigmaProtocol.realTranscript, sigma]
    vcstep rw
    simp only [honest_verify_eq, h_eq, add_sub_cancel_right]
    rfl
  · show _ = Pr[= t | simTranscript F G n stmt]
    unfold simTranscript
    apply probOutput_eq_of_relTriple_eqRel (x := t)
    rvcstep
    intro c _ hc; subst hc
    rvcstep using (fun r_vec i => r_vec i + c * wit.scalars i)
    refine ⟨fun r_vec r_vec' h => funext fun i => add_right_cancel (congrFun h i),
            fun s => ⟨fun i => s i - c * wit.scalars i,
                       funext fun i => sub_add_cancel (s i) _⟩⟩

/-! ## Companion facts for the Fiat-Shamir reduction

Two additional properties that the FS CMA-to-NMA reduction needs on top of
HVZK to bound the probability that the signing-simulator collides with the
random oracle when programming a hash entry. -/

omit [Fintype F] [DecidableEq F] in
/-- Closed-form for the GeneralizedSchnorr `realTranscript`: the real
transcript is the joint distribution of `(dotSmul r_vec g, c, r_vec + c·k)`
where `r_vec ← $ᵗ (Fin n → F)` and `c ← $ᵗ F` are sampled independently.

This is the form in which the commitment `dotSmul r_vec g` and the challenge
`c` are literally independent (by sampling order), making conditional
uniformity trivial. It is the multi-base analogue of VCV-io's
`Schnorr.realTranscript_eq_indep`. -/
private lemma realTranscript_eq_indep (n : ℕ) (stmt : Statement F G n)
    (wit : Witness F n) :
    SigmaProtocol.realTranscript (sigma F G n) stmt wit =
      (do
        let r_vec ← $ᵗ (Fin n → F)
        let c ← $ᵗ F
        pure ((dotSmul r_vec stmt.base_points, c,
                fun i => r_vec i + c * wit.scalars i)
              : G × F × (Fin n → F))) := by
  simp only [SigmaProtocol.realTranscript, sigma, monad_norm]

/-- **Simulator commit-predictability for GeneralizedSchnorr.**

Under the non-degeneracy hypothesis that every statement has either a
non-zero base point or non-zero `R`, the simulator's commit is uniform on
`G`, giving the tight bound `β = 1/|F|`.

Proof sketch: under `hg`, every base point is `a_i • g` for unique `a_i : F`,
and `R` is `a_R • g` for unique `a_R : F`.  The commit is
`(Σ_i s_i * a_i - c * a_R) • g = f(s, c)` where `f` is a map from
`(Fin n → F) × F` to `G`.  The map `f' : (s, c) ↦ Σ_i s_i * a_i - c * a_R`
has fibers of size `|F|^n` (proved by constructing explicit bijections
in both the non-zero-`a_i` and all-zero-`a_i` but non-zero-`a_R` cases).
Since `smulG : F → G` is a bijection, `f` also has fibers of size `|F|^n`,
so `f <$> $ᵗ ((Fin n → F) × F)` is uniform on `G` with probability
`|F|^n / |F|^(n+1) = 1/|F|`. -/
theorem sigma_simCommitPredictability (n : ℕ) (g : G)
    (hg : Function.Bijective (PokerProtocolLean.Foundations.smulByG F G g))
    (h : ∀ (stmt : Statement F G n),
        (∃ i, stmt.base_points i ≠ 0) ∨ stmt.R ≠ 0) :
    SigmaProtocol.simCommitPredictability (sigma F G n) (simTranscript F G n)
      ((Fintype.card F : ℝ≥0∞)⁻¹) := by
  classical
  letI : Fintype G := Fintype.ofBijective _ hg
  intro stmt c₀
  have hcard_FG : Fintype.card G = Fintype.card F :=
    (Fintype.card_of_bijective hg).symm
  let e : F ≃ G := PokerProtocolLean.Foundations.equivOfHg F G g hg

  let a_i : Fin n → F := fun i => e.symm (stmt.base_points i)
  let a_R : F := e.symm stmt.R
  have ha_i : ∀ i, a_i i • g = stmt.base_points i := by
    intro i
    have hdef : e (a_i i) = a_i i • g := by
      show (PokerProtocolLean.Foundations.equivOfHg F G g hg) (a_i i) = a_i i • g
      unfold PokerProtocolLean.Foundations.equivOfHg PokerProtocolLean.Foundations.smulByG
      rfl
    have h1 : e (e.symm (stmt.base_points i)) = stmt.base_points i :=
      e.apply_symm_apply (stmt.base_points i)
    have h2 : e (a_i i) = stmt.base_points i := by simpa [a_i] using h1
    exact hdef.symm.trans h2
  have ha_R : a_R • g = stmt.R := by
    have hdef : e a_R = a_R • g := by
      show (PokerProtocolLean.Foundations.equivOfHg F G g hg) a_R = a_R • g
      unfold PokerProtocolLean.Foundations.equivOfHg PokerProtocolLean.Foundations.smulByG
      rfl
    have h1 : e (e.symm stmt.R) = stmt.R := e.apply_symm_apply stmt.R
    have h2 : e a_R = stmt.R := by simpa [a_R] using h1
    exact hdef.symm.trans h2
  have h_non_degen : (∃ i, stmt.base_points i ≠ 0) ∨ stmt.R ≠ 0 := h stmt

  have h_commit_simp :
      ∀ s : Fin n → F, ∀ c : F,
        dotSmul s stmt.base_points - c • stmt.R
          = (∑ i, s i * a_i i - c * a_R) • g := by
    intro s c
    have hd : dotSmul s stmt.base_points = (∑ i, s i * a_i i) • g := by
      have h1 : dotSmul s stmt.base_points = ∑ i, s i • stmt.base_points i := rfl
      rw [h1]
      have h2 : (∑ i, s i • stmt.base_points i) = ∑ i, s i • (a_i i • g) := by
        congr
        funext i
        rw [← ha_i]
      rw [h2]
      have h3 : (∑ i, s i • (a_i i • g)) = (∑ i, s i * a_i i) • g := by
        have h3a : ∑ i, s i • (a_i i • g) = ∑ i, (s i * a_i i) • g := by
          congr
          funext i
          exact smul_smul (s i) (a_i i) g
        rw [h3a]
        rw [← Finset.sum_smul]
      rw [h3]
    have hr : c • stmt.R = (c * a_R) • g := by
      rw [← ha_R]
      rw [smul_smul]
    rw [hd, hr]
    rw [← sub_smul]

  set f : (Fin n → F) × F → G := fun ⟨s, c⟩ =>
      (∑ i, s i * a_i i - c * a_R) • g with hf_def
  set f' : (Fin n → F) × F → F := fun ⟨s, c⟩ =>
      ∑ i, s i * a_i i - c * a_R with hf'_def

  have h_fiber : ∀ y : F,
      Finset.sum (Finset.univ : Finset ((Fin n → F) × F))
        (fun x : (Fin n → F) × F => if f' x = y then (1 : ℕ) else (0 : ℕ))
        = Fintype.card (Fin n → F) := by
    have h_case1 : ∀ (y : F) (j : Fin n) (hj : a_i j ≠ 0),
        Finset.sum (Finset.univ : Finset ((Fin n → F) × F))
          (fun x : (Fin n → F) × F => if f' x = y then (1 : ℕ) else (0 : ℕ))
          = Fintype.card (Fin n → F) := by
      intro y j hj
      let e_fwd : {x : (Fin n → F) × F // f' x = y} → (Fin n → F) := by
        intro x
        rcases x with ⟨⟨s, c⟩, _⟩
        exact Function.update s j c
      let e_bwd : (Fin n → F) → {x : (Fin n → F) × F // f' x = y} := by
        intro t
        let c_val : F := t j
        let S : F := ∑ i ∈ Finset.univ.erase j, t i * a_i i
        let s_j_val : F := (y + c_val * a_R - S) / a_i j
        refine' ⟨⟨Function.update t j s_j_val, c_val⟩, _⟩
        have h_eq : ∑ i, (Function.update t j s_j_val) i * a_i i - c_val * a_R = y := by
          have hsum : ∑ i, (Function.update t j s_j_val) i * a_i i =
              s_j_val * a_i j + S := by
            have hdecomp : ∑ i, (Function.update t j s_j_val) i * a_i i
                = (Function.update t j s_j_val) j * a_i j
                  + ∑ i ∈ Finset.univ.erase j,
                      (Function.update t j s_j_val) i * a_i i := by
              rw [(Finset.add_sum_erase (Finset.univ)
                  (fun i => (Function.update t j s_j_val) i * a_i i)
                  (Finset.mem_univ j)).symm]
            rw [hdecomp]
            have h_j : (Function.update t j s_j_val) j * a_i j = s_j_val * a_i j := by
              simp
            rw [h_j]
            have h_rest : ∑ i ∈ Finset.univ.erase j,
                (Function.update t j s_j_val) i * a_i i
              = ∑ i ∈ Finset.univ.erase j, t i * a_i i := by
              apply Finset.sum_congr rfl
              intro i hi
              have hne : i ≠ j := by
                have h_and : i ≠ j ∧ i ∈ Finset.univ := Finset.mem_erase.mp hi
                exact h_and.1
              have h_at_i : (Function.update t j s_j_val) i = t i := by
                simp [hne]
              rw [h_at_i]
            rw [h_rest]
          rw [hsum]
          have h2 : a_i j ≠ 0 := hj
          have hcalc : s_j_val * a_i j + S - c_val * a_R = y := by
            have hsj : s_j_val = (y + c_val * a_R - S) / a_i j := rfl
            rw [hsj]
            field_simp
            ring
          exact hcalc
        simpa [hf'_def] using h_eq
      have hbij : Function.Bijective e_fwd := by
        constructor
        · intro x1 x2 h_eq
          rcases x1 with ⟨⟨s1, c1⟩, hs1⟩
          rcases x2 with ⟨⟨s2, c2⟩, hs2⟩
          have heq : Function.update s1 j c1 = Function.update s2 j c2 := h_eq
          have hc : c1 = c2 := by
            have h_at_j : (Function.update s1 j c1) j = (Function.update s2 j c2) j :=
              congr_fun heq j
            simp only [Function.update_apply] at h_at_j
            exact h_at_j
          have hs : s1 = s2 := by
            have hforall : ∀ i, s1 i = s2 i := by
              intro i
              by_cases hne : i ≠ j
              · have h_at_i : (Function.update s1 j c1) i = (Function.update s2 j c2) i :=
                  congr_fun heq i
                simp only [Function.update_apply, hne] at h_at_i ⊢
                exact h_at_i
              · have hieq : i = j := by tauto
                rw [hieq]
                have hf1 : ∑ k, s1 k * a_i k - c1 * a_R = y := by simpa [hf'_def] using hs1
                have hf2 : ∑ k, s2 k * a_i k - c2 * a_R = y := by simpa [hf'_def] using hs2
                have h_sum_eq : ∑ k, s1 k * a_i k = ∑ k, s2 k * a_i k := by
                  calc
                    ∑ k, s1 k * a_i k
                      = ∑ k, s1 k * a_i k - c1 * a_R + c1 * a_R := by ring
                    _ = y + c1 * a_R := by rw [hf1]
                    _ = y + c2 * a_R := by rw [hc]
                    _ = ∑ k, s2 k * a_i k - c2 * a_R + c2 * a_R := by rw [← hf2]
                    _ = ∑ k, s2 k * a_i k := by ring
                have h1 : ∑ k, s1 k * a_i k = s1 j * a_i j + ∑ k ∈ Finset.univ.erase j, s1 k * a_i k := by
                  rw [(Finset.add_sum_erase (Finset.univ)
                      (fun k => s1 k * a_i k) (Finset.mem_univ j)).symm]
                have h2 : ∑ k, s2 k * a_i k = s2 j * a_i j + ∑ k ∈ Finset.univ.erase j, s2 k * a_i k := by
                  rw [(Finset.add_sum_erase (Finset.univ)
                      (fun k => s2 k * a_i k) (Finset.mem_univ j)).symm]
                have h_rest_eq : ∑ k ∈ Finset.univ.erase j, s1 k * a_i k = ∑ k ∈ Finset.univ.erase j, s2 k * a_i k := by
                  apply Finset.sum_congr rfl
                  intro k hk
                  have hne_k : k ≠ j := by
                    have h_and : k ≠ j ∧ k ∈ Finset.univ := Finset.mem_erase.mp hk
                    exact h_and.1
                  have hsk : s1 k = s2 k := by
                    have h_at_k : (Function.update s1 j c1) k = (Function.update s2 j c2) k := congr_fun heq k
                    simp only [Function.update_apply, hne_k] at h_at_k
                    exact h_at_k
                  rw [hsk]
                have ha_j_ne : a_i j ≠ 0 := hj
                have h_eq2 : s1 j * a_i j = s2 j * a_i j := by
                  have h_sum1 : ∑ k, s1 k * a_i k = s1 j * a_i j + ∑ k ∈ Finset.univ.erase j, s1 k * a_i k := h1
                  have h_sum2 : ∑ k, s2 k * a_i k = s2 j * a_i j + ∑ k ∈ Finset.univ.erase j, s2 k * a_i k := h2
                  have h_eq3 : s1 j * a_i j + ∑ k ∈ Finset.univ.erase j, s1 k * a_i k
                      = s2 j * a_i j + ∑ k ∈ Finset.univ.erase j, s2 k * a_i k := by
                    calc
                      s1 j * a_i j + ∑ k ∈ Finset.univ.erase j, s1 k * a_i k
                        = ∑ k, s1 k * a_i k := h_sum1.symm
                      _ = ∑ k, s2 k * a_i k := h_sum_eq
                      _ = s2 j * a_i j + ∑ k ∈ Finset.univ.erase j, s2 k * a_i k := h_sum2
                  have h4 : ∑ k ∈ Finset.univ.erase j, s1 k * a_i k = ∑ k ∈ Finset.univ.erase j, s2 k * a_i k := h_rest_eq
                  have h5 : s1 j * a_i j = s2 j * a_i j := by
                    calc
                      s1 j * a_i j
                        = s1 j * a_i j + ∑ k ∈ Finset.univ.erase j, s1 k * a_i k - ∑ k ∈ Finset.univ.erase j, s1 k * a_i k := by ring
                      _ = s2 j * a_i j + ∑ k ∈ Finset.univ.erase j, s2 k * a_i k - ∑ k ∈ Finset.univ.erase j, s1 k * a_i k := by rw [h_eq3]
                      _ = s2 j * a_i j + ∑ k ∈ Finset.univ.erase j, s2 k * a_i k - ∑ k ∈ Finset.univ.erase j, s2 k * a_i k := by rw [h4]
                      _ = s2 j * a_i j := by ring
                  exact h5
                exact (mul_left_inj' ha_j_ne).mp h_eq2
            apply funext
            exact hforall
          subst hs
          subst hc
          rfl
        · intro t
          refine' ⟨e_bwd t, _⟩
          simpa [e_fwd, e_bwd]
      have hcard_eq : Fintype.card ({x : (Fin n → F) × F // f' x = y})
          = Fintype.card (Fin n → F) := by
        exact Fintype.card_congr (Equiv.ofBijective e_fwd hbij)
      have h_sum_eq : Finset.sum (Finset.univ : Finset ((Fin n → F) × F))
          (fun x : (Fin n → F) × F => if f' x = y then (1 : ℕ) else (0 : ℕ))
          = Fintype.card (Fin n → F) := by
        have h1 : Finset.sum (Finset.univ : Finset ((Fin n → F) × F))
            (fun x : (Fin n → F) × F => if f' x = y then (1 : ℕ) else (0 : ℕ))
            = (Finset.univ.filter (fun x : (Fin n → F) × F => f' x = y)).card := by
          simp [Finset.sum_boole]
        rw [h1]
        have h2 : (Finset.univ.filter (fun x : (Fin n → F) × F => f' x = y)).card
            = Fintype.card ({x : (Fin n → F) × F // f' x = y}) := by
          exact (Fintype.card_of_subtype (Finset.univ.filter (fun x : (Fin n → F) × F => f' x = y))
              (fun x => by
                simpa [Finset.mem_filter, Finset.mem_univ])).symm
        rw [h2]
        exact hcard_eq
      exact h_sum_eq
    have h_case2 : ∀ (y : F) (h_all_zero : ∀ i, a_i i = 0) (h_a_R_ne0 : a_R ≠ 0),
        Finset.sum (Finset.univ : Finset ((Fin n → F) × F))
          (fun x : (Fin n → F) × F => if f' x = y then (1 : ℕ) else (0 : ℕ))
          = Fintype.card (Fin n → F) := by
      intro y h_all_zero h_a_R_ne0
      let e_fwd : {x : (Fin n → F) × F // f' x = y} → (Fin n → F) := by
        intro x
        rcases x with ⟨⟨s, c⟩, _⟩
        exact s
      let e_bwd : (Fin n → F) → {x : (Fin n → F) × F // f' x = y} := by
        intro t
        refine' ⟨⟨t, -y * a_R⁻¹⟩, _⟩
        have h_eq : f' ⟨t, -y * a_R⁻¹⟩ = y := by
          have h_sum0 : ∑ i, t i * a_i i = 0 := by
            apply Finset.sum_eq_zero
            intro i _
            rw [h_all_zero i]
            ring
          have h_f'_val : f' ⟨t, -y * a_R⁻¹⟩ = ∑ i, t i * a_i i - (-y * a_R⁻¹) * a_R := by
            exact rfl
          rw [h_f'_val, h_sum0]
          have h2 : a_R ≠ 0 := h_a_R_ne0
          field_simp
          ring
        exact h_eq
      have hbij : Function.Bijective e_fwd := by
        constructor
        · intro x1 x2 h_eq
          rcases x1 with ⟨⟨s1, c1⟩, hs1⟩
          rcases x2 with ⟨⟨s2, c2⟩, hs2⟩
          have hs : s1 = s2 := h_eq
          have hc1 : f' ⟨s1, c1⟩ = y := hs1
          have hc2 : f' ⟨s2, c2⟩ = y := hs2
          have hc : c1 = c2 := by
            have heq1 : (0 : F) - c1 * a_R = y := by
              simpa [hf'_def, h_all_zero] using hc1
            have heq2 : (0 : F) - c2 * a_R = y := by
              simpa [hf'_def, h_all_zero] using hc2
            have h3 : a_R ≠ 0 := h_a_R_ne0
            have h4 : c1 * a_R = c2 * a_R := by
              have h : c1 * a_R = -y := by
                calc
                  c1 * a_R = -(0 - c1 * a_R) := by ring
                  _ = -y := by rw [heq1]
              have h' : c2 * a_R = -y := by
                calc
                  c2 * a_R = -(0 - c2 * a_R) := by ring
                  _ = -y := by rw [heq2]
              rw [h, ← h']
            exact (mul_left_inj' h3).mp h4
          subst hs
          subst hc
          rfl
        · intro t
          refine' ⟨e_bwd t, _⟩
          simpa [e_fwd, e_bwd]
      have hcard_eq : Fintype.card ({x : (Fin n → F) × F // f' x = y})
          = Fintype.card (Fin n → F) := by
        exact Fintype.card_congr (Equiv.ofBijective e_fwd hbij)
      have h_sum_eq : Finset.sum (Finset.univ : Finset ((Fin n → F) × F))
          (fun x : (Fin n → F) × F => if f' x = y then (1 : ℕ) else (0 : ℕ))
          = Fintype.card (Fin n → F) := by
        have h1 : Finset.sum (Finset.univ : Finset ((Fin n → F) × F))
            (fun x : (Fin n → F) × F => if f' x = y then (1 : ℕ) else (0 : ℕ))
            = (Finset.univ.filter (fun x : (Fin n → F) × F => f' x = y)).card := by
          simp [Finset.sum_boole]
        rw [h1]
        have h2 : (Finset.univ.filter (fun x : (Fin n → F) × F => f' x = y)).card
            = Fintype.card ({x : (Fin n → F) × F // f' x = y}) := by
          exact (Fintype.card_of_subtype (Finset.univ.filter (fun x : (Fin n → F) × F => f' x = y))
              (fun x => by
                simpa [Finset.mem_filter, Finset.mem_univ])).symm
        rw [h2]
        exact hcard_eq
      exact h_sum_eq
    intro y
    by_cases hA : ∃ i, a_i i ≠ 0
    · rcases hA with ⟨j, hj⟩
      exact h_case1 y j hj
    · have h_all_zero : ∀ i, a_i i = 0 := by
        intro i
        by_contra h_contra
        exact hA ⟨i, h_contra⟩
      have h_a_R_ne0 : a_R ≠ 0 := by
        by_contra h_contra
        have hR0 : stmt.R = 0 := by
          simpa [← ha_R, h_contra, zero_smul]
        have hB : ¬(∃ i, stmt.base_points i ≠ 0) := by
          intro h_contra2
          rcases h_contra2 with ⟨i, hi⟩
          have ha0 : a_i i = 0 := h_all_zero i
          have hbp0 : stmt.base_points i = 0 := by
            rw [← ha_i i, ha0, zero_smul]
          contradiction
        have hRne : stmt.R ≠ 0 := by
          exact h_non_degen.elim
            (fun h => False.elim (hB h))
            (fun h => h)
        exact hRne hR0
      exact h_case2 y h_all_zero h_a_R_ne0

  have h_commit_uniform :
      𝒟[Prod.fst <$> simTranscript F G n stmt] = 𝒟[$ᵗ G] := by
    apply evalDist_ext
    intro x
    set z : F := e.symm x with hz_def
    have h_do_form : (Prod.fst <$> simTranscript F G n stmt) =
        (($ᵗ F) >>= fun c => ($ᵗ (Fin n → F)) >>= fun s =>
            pure ((∑ i, s i * a_i i - c * a_R) • g)) := by
      have h_sim : Prod.fst <$> simTranscript F G n stmt =
          (($ᵗ F) >>= fun c => ($ᵗ (Fin n → F)) >>= fun s =>
              pure (dotSmul s stmt.base_points - c • stmt.R)) := by
        simp [simTranscript, map_bind]
      rw [h_sim]
      have h1 : ∀ (c : F),
          (($ᵗ (Fin n → F)) >>= fun s => pure (dotSmul s stmt.base_points - c • stmt.R))
          = (($ᵗ (Fin n → F)) >>= fun s => pure ((∑ i, s i * a_i i - c * a_R) • g)) := by
        intro c
        apply bind_congr
        intro s
        exact congr_arg pure (h_commit_simp s c)
      apply bind_congr
      intro c
      exact h1 c
    rw [h_do_form]
    have h_bind_comm :
        𝒟[(($ᵗ F) >>= fun c => ($ᵗ (Fin n → F)) >>= fun s =>
            pure ((∑ i, s i * a_i i - c * a_R) • g))]
      = 𝒟[(($ᵗ (Fin n → F)) >>= fun s => ($ᵗ F) >>= fun c =>
            pure ((∑ i, s i * a_i i - c * a_R) • g))] := by
      rw [evalDist_bind_comm]
      <;> rfl
    have h_prod_form :
        𝒟[(($ᵗ (Fin n → F)) >>= fun s => ($ᵗ F) >>= fun c =>
            pure ((∑ i, s i * a_i i - c * a_R) • g))]
      = 𝒟[f <$> ($ᵗ ((Fin n → F) × F))] := by
      have h_unfold : ($ᵗ ((Fin n → F) × F))
          = (($ᵗ (Fin n → F)) >>= fun s => ($ᵗ F) >>= fun c => pure (s, c)) := by
        change ((·, ·) <$> ($ᵗ (Fin n → F)) <*> ($ᵗ F)) = _
        simp [seq_eq_bind_map, map_eq_bind_pure_comp, bind_assoc, pure_bind]
      rw [h_unfold]
      have h_functor : f <$> (($ᵗ (Fin n → F)) >>= fun s => ($ᵗ F) >>= fun c => pure (s, c))
          = (($ᵗ (Fin n → F)) >>= fun s => ($ᵗ F) >>= fun c =>
              pure ((∑ i, s i * a_i i - c * a_R) • g)) := by
        simpa [map_eq_bind_pure_comp, bind_assoc, pure_bind, Function.comp_apply, hf_def]
        <;> rfl
      exact congr_arg evalDist h_functor.symm
    rw [probOutput_def]
    rw [h_bind_comm]
    rw [h_prod_form]
    rw [← probOutput_def]
    have h_map_expand :
        Pr[= x | f <$> ($ᵗ ((Fin n → F) × F))] =
          ∑ p : (Fin n → F) × F,
            if x = f p then Pr[= p | $ᵗ ((Fin n → F) × F)] else 0 := by
      exact probOutput_map_eq_sum_fintype_ite
        (mx := $ᵗ ((Fin n → F) × F)) (f := f) (y := x)
    rw [h_map_expand]
    have hterm : ∀ p : (Fin n → F) × F,
        (if x = f p then Pr[= p | $ᵗ ((Fin n → F) × F)] else 0)
          = (if z = f' p then (Fintype.card ((Fin n → F) × F) : ℝ≥0∞)⁻¹ else 0) := by
        intro p
        by_cases hif : x = f p
        · simp only [hif, if_true]
          have hz1 : z = f' p := by
            have hfeq : f p = (f' p) • g := by rfl
            have hz_eq : z = e.symm x := hz_def
            rw [hz_eq]
            have hif' : x = f p := hif
            rw [hif', hfeq]
            have hkey : e.symm ((f' p) • g) = f' p := by
              have h2 : e (f' p) = (f' p) • g := by
                show (PokerProtocolLean.Foundations.equivOfHg F G g hg) (f' p) = (f' p) • g
                unfold PokerProtocolLean.Foundations.equivOfHg PokerProtocolLean.Foundations.smulByG
                rfl
              rw [← h2]
              exact e.symm_apply_apply (f' p)
            exact hkey
          simp only [hz1, probOutput_uniformSample (α := ((Fin n → F) × F)) p, if_true]
        · simp only [hif, if_false]
          have hz2 : z ≠ f' p := by
            intro hcontra
            have hxeq : x = f p := by
              have hxeq1 : x = e z := by
                simpa [hz_def, e.apply_symm_apply]
              calc
                x = e z := hxeq1
                _ = z • g := rfl
                _ = f' p • g := by rw [← hcontra]
                _ = f p := rfl
            exact hif hxeq
          simp [hz2]
    have h_sum1 :
        ∑ p : (Fin n → F) × F,
            (if x = f p then Pr[= p | $ᵗ ((Fin n → F) × F)] else 0)
          = ∑ p : (Fin n → F) × F,
              (if z = f' p then (Fintype.card ((Fin n → F) × F) : ℝ≥0∞)⁻¹ else 0) := by
      apply Finset.sum_congr rfl
      intro p _
      exact hterm p
    rw [h_sum1]
    have h_factor :
        ∑ p : (Fin n → F) × F,
            (if z = f' p then (Fintype.card ((Fin n → F) × F) : ℝ≥0∞)⁻¹ else 0)
          = (Fintype.card ((Fin n → F) × F) : ℝ≥0∞)⁻¹ *
              ∑ p : (Fin n → F) × F, (if z = f' p then (1 : ℝ≥0∞) else 0) := by
      set c : ℝ≥0∞ := (Fintype.card ((Fin n → F) × F))⁻¹ with hc_def
      have h_term : ∀ p : (Fin n → F) × F,
          (if z = f' p then c else 0) = c * (if z = f' p then (1 : ℝ≥0∞) else 0) := by
        intro p
        by_cases hif2 : z = f' p
        · simp only [hif2, if_true, mul_one]
        · simp only [hif2, if_false, mul_zero]
      have hLHS : ∑ p : (Fin n → F) × F,
          (if z = f' p then (Fintype.card ((Fin n → F) × F) : ℝ≥0∞)⁻¹ else 0)
        = ∑ p : (Fin n → F) × F, (if z = f' p then c else 0) := by
        simp [hc_def]
      rw [hLHS]
      have h_sum2 : ∑ p : (Fin n → F) × F,
          (if z = f' p then c else 0)
        = ∑ p : (Fin n → F) × F, c * (if z = f' p then (1 : ℝ≥0∞) else 0) := by
        simp
      rw [h_sum2]
      rw [← Finset.mul_sum]
      <;> rw [hc_def]
    rw [h_factor]
    have hcard_mul : (Fintype.card ((Fin n → F) × F) : ℝ≥0∞)⁻¹
    = (Fintype.card F : ℝ≥0∞)⁻¹ * (Fintype.card (Fin n → F) : ℝ≥0∞)⁻¹ := by
      calc
        (Fintype.card ((Fin n → F) × F) : ℝ≥0∞)⁻¹
          = (↑(Fintype.card (Fin n → F) * Fintype.card F) : ℝ≥0∞)⁻¹ := by
          rw [Fintype.card_prod]
        _ = (↑(Fintype.card (Fin n → F)) * ↑(Fintype.card F) : ℝ≥0∞)⁻¹ := by
          rw [Nat.cast_mul]
        _ = (↑(Fintype.card F))⁻¹ * (↑(Fintype.card (Fin n → F)))⁻¹ := by
          rw [ENNReal.mul_inv]
          · ring
          · left
            exact_mod_cast Fintype.card_ne_zero
          · left
            exact ENNReal.natCast_ne_top (Fintype.card (Fin n → F))
        _ = (Fintype.card F : ℝ≥0∞)⁻¹ * (Fintype.card (Fin n → F) : ℝ≥0∞)⁻¹ := rfl
    rw [hcard_mul]
    have h_sum_decomp :
        ∑ p : (Fin n → F) × F, (if z = f' p then (1 : ℝ≥0∞) else 0)
          = Fintype.card (Fin n → F) := by
        have hnat : Finset.sum Finset.univ
            (fun p : (Fin n → F) × F => if z = f' p then (1 : ℕ) else (0 : ℕ))
            = Fintype.card (Fin n → F) := by
          have h1 : (∑ x : (Fin n → F) × F, if f' x = z then (1 : ℕ) else (0 : ℕ))
              = Fintype.card (Fin n → F) := h_fiber z
          have h2 : (∑ x : (Fin n → F) × F, if f' x = z then (1 : ℕ) else (0 : ℕ))
              = (∑ p : (Fin n → F) × F, if z = f' p then (1 : ℕ) else (0 : ℕ)) := by
            apply Finset.sum_congr rfl
            intro x _
            simp [eq_comm]
          rw [← h2]
          exact h1
        exact_mod_cast hnat
    rw [h_sum_decomp]
    have hcard_ne_zero : (Fintype.card (Fin n → F) : ℝ≥0∞) ≠ 0 := by
      exact_mod_cast Fintype.card_ne_zero
    have hcard_ne_top : (Fintype.card (Fin n → F) : ℝ≥0∞) ≠ ⊤ := by
      exact ENNReal.natCast_ne_top _
    have h_inv :
        (Fintype.card (Fin n → F) : ℝ≥0∞)⁻¹ * (Fintype.card (Fin n → F) : ℝ≥0∞) = 1 := by
      exact ENNReal.inv_mul_cancel hcard_ne_zero hcard_ne_top
    rw [mul_assoc]
    rw [h_inv]
    rw [mul_one]
    rw [probOutput_uniformSample (α := G) x]
    rw [hcard_FG]

  have h_eq : probOutput (Prod.fst <$> simTranscript F G n stmt) c₀
      = (Fintype.card F : ℝ≥0∞)⁻¹ := by
    rw [probOutput_def, h_commit_uniform, ← probOutput_def]
    rw [probOutput_uniformSample (α := G)]
    rw [hcard_FG]
  exact h_eq.le

omit [DecidableEq F] in
/-- **Simulator-challenge uniformity given commit, for GeneralizedSchnorr.**
For any commit value `c₀ : G` and challenge value `ch₀ : F`, the
simulator's joint marginal on `(commit, chal)` factors as
`Pr[commit = c₀] · (1/|F|)`.

This is the multi-base lift of VCV-io's `Schnorr.sigma_simChalUniformGivenCommit`.
The proof reduces to the explicit independent product
`(do r_vec ← $ᵗ (Fin n → F); c ← $ᵗ F; pure (dotSmul r_vec g, c, r_vec + c · k))`
via perfect HVZK and the closed form `realTranscript_eq_indep`; in that form
the commit `dotSmul r_vec g` and challenge `c` are literally independent
(by sampling order), so the factoring is immediate.

Unlike `sigma_simCommitPredictability`, this property holds universally
(no non-degeneracy hypothesis needed): the factoring
`P[(c₀, ch₀)] = P[c₀] · 1/|F|` is true even when `P[c₀] = 0` or `P[c₀] = 1`. -/
theorem sigma_simChalUniformGivenCommit (n : ℕ) :
    simChalUniformGivenCommit (sigma F G n)
      (fun stmt => simTranscript F G n stmt) := by
  classical
  intro stmt wit hrel c₀ ch₀
  have hHVZK := sigma_perfect_hvzk F G n stmt wit hrel
  have hReal := realTranscript_eq_indep F G n stmt wit
  set ind : ProbComp (G × F × (Fin n → F)) := do
    let r_vec ← $ᵗ (Fin n → F)
    let c ← $ᵗ F
    pure (dotSmul r_vec stmt.base_points, c,
           fun i => r_vec i + c * wit.scalars i) with hind_def
  have hSimEqIndep : 𝒟[simTranscript F G n stmt] = 𝒟[ind] := by
    rw [← hHVZK, hReal]
  rw [probEvent_congr' (fun _ _ => Iff.rfl) hSimEqIndep,
      probEvent_congr' (fun _ _ => Iff.rfl) hSimEqIndep]
  have hcard_ne_zero : (Fintype.card F : ℝ≥0∞) ≠ 0 := by
    exact_mod_cast Fintype.card_ne_zero (α := F)
  have hcard_ne_top : (Fintype.card F : ℝ≥0∞) ≠ ⊤ := ENNReal.natCast_ne_top _
  set M : ℝ≥0∞ := ∑' r_vec : Fin n → F, (Fintype.card (Fin n → F) : ℝ≥0∞)⁻¹ *
      (if dotSmul r_vec stmt.base_points = c₀ then (1 : ℝ≥0∞) else 0) with hM_def
  have hjoint :
      Pr[fun t : G × F × (Fin n → F) => t.1 = c₀ ∧ t.2.1 = ch₀ | ind] =
        (Fintype.card F : ℝ≥0∞)⁻¹ * M := by
    rw [hind_def, probEvent_bind_eq_tsum, hM_def, ← ENNReal.tsum_mul_left]
    refine tsum_congr fun r_vec => ?_
    rw [probOutput_uniformSample, probEvent_bind_eq_tsum]
    rw [show (∑' c : F,
              Pr[= c | $ᵗ F] *
                Pr[fun t : G × F × (Fin n → F) => t.1 = c₀ ∧ t.2.1 = ch₀ |
                  (pure ((dotSmul r_vec stmt.base_points, c,
                           fun i => r_vec i + c * wit.scalars i)
                         : G × F × (Fin n → F)) : ProbComp _)]) =
            (Fintype.card F : ℝ≥0∞)⁻¹ *
              (if dotSmul r_vec stmt.base_points = c₀ then (1 : ℝ≥0∞) else 0) by
      simp_rw [probOutput_uniformSample, probEvent_pure]
      rw [ENNReal.tsum_mul_left]
      congr 1
      by_cases hr : dotSmul r_vec stmt.base_points = c₀
      · simp only [hr, true_and]
        rw [tsum_eq_single ch₀]
        · simp
        · intro c hc
          simp [hc]
      · simp [hr]]
    ac_rfl
  have hmarg :
      Pr[fun t : G × F × (Fin n → F) => t.1 = c₀ | ind] = M := by
    rw [hind_def, probEvent_bind_eq_tsum, hM_def]
    refine tsum_congr fun r_vec => ?_
    rw [probOutput_uniformSample, probEvent_bind_eq_tsum]
    rw [show (∑' c : F,
              Pr[= c | $ᵗ F] *
                Pr[fun t : G × F × (Fin n → F) => t.1 = c₀ |
                  (pure ((dotSmul r_vec stmt.base_points, c,
                           fun i => r_vec i + c * wit.scalars i)
                         : G × F × (Fin n → F)) : ProbComp _)]) =
            (if dotSmul r_vec stmt.base_points = c₀ then (1 : ℝ≥0∞) else 0) by
      simp_rw [probOutput_uniformSample, probEvent_pure]
      by_cases hr : dotSmul r_vec stmt.base_points = c₀
      · simp only [hr, if_true]
        rw [ENNReal.tsum_mul_left, ENNReal.tsum_const,
          ENat.card_eq_coe_fintype_card, mul_one, ENat.toENNReal_coe,
          ENNReal.inv_mul_cancel hcard_ne_zero hcard_ne_top]
      · simp [hr]]
  rw [hjoint, hmarg, mul_comm]

end PokerProtocolLean.GeneralizedSchnorr