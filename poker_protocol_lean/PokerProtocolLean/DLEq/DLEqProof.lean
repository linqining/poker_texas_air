import Mathlib.Algebra.BigOperators.Fin
import Mathlib.Algebra.Module.BigOperators
import Mathlib.Tactic.Module
import VCVio.CryptoFoundations.SigmaProtocol
import VCVio.OracleComp.Constructions.SampleableType
import VCVio.ProgramLogic.Tactics.Unary
import VCVio.ProgramLogic.Tactics.Relational
import PokerProtocolLean.Foundations.AlgebraicSetup
import PokerProtocolLean.Foundations.ElGamal
import PokerProtocolLean.Schnorr.GeneralizedSchnorr

/-!
# DLEqProof — batched Remask/Leave DLEQ

Backing `poker_protocol/src/zk_shuffle/dleq_proof.rs`.

A player remasks a list of ciphertexts with their secret key `sk`:
`output[i] = remask sk input[i] = ⟨input[i].c1, input[i].c2 + sk • input[i].c1⟩`.
The "leave" direction is the inverse: `input[i]` is the remasked version
of `output[i]`.

Either direction must prove that there is a single `sk` such that:
  * `player_pk = sk • g` (the public-key equation), and
  * `compute_d2 kind input[i].c2 output[i].c2 = sk • input[i].c1`
    for every card `i`.

The proof batches these per-card equations with a single randomiser
`ω ← $ᵗ F` and a single Schnorr challenge `c ← $ᵗ F`: the prover commits
`B = ω • g` and `A_i = ω • input[i].c1`, and responds `s = ω + c * sk`.
Verification reconstructs each `A_i` and `B` from the single `s`.

This is a literal specialisation of `GeneralizedSchnorr` (M2) where:
  * the base-point family is
    `g :: input[0].c1 :: … :: input[n-1].c1` (length `n + 1`);
  * the witness scalars are `sk :: sk :: … :: sk` (the same scalar,
    repeated `n + 1` times);
  * the claim `R` is `player_pk :: compute_d2 kind input[0].c2 output[0].c2
    :: … :: compute_d2 kind input[n-1].c2 output[n-1].c2`, which is a
    *vector* `R` rather than a single group element — modelled here as a
    per-card family of statements sharing one Schnorr response.

## Relation and Rust statement validity

The relation is the **DLEq equation only** (witness-dependent parts):
`player_sk • g = player_pk ∧ ∀ i, compute_d2 ... = player_sk • input[i].c1`.
`relation` contains the witness-dependent equations used by the Σ-protocol.
`WellFormedStatement` separately models the fail-closed checks performed by
the Rust verifier: a non-empty batch, a non-identity public key, valid input
and output ciphertexts, and exact `c1` invariance. `RustRelation` is their
conjunction. Keeping these layers separate lets the standard Σ-protocol
theorems remain reusable without silently dropping implementation checks.
-/

open OracleSpec OracleComp SigmaProtocol
open PokerProtocolLean.Foundations (ElGamalCiphertext)
open scoped ENNReal

namespace PokerProtocolLean.DLEq

variable (F : Type) [Field F] [Fintype F] [DecidableEq F] [SampleableType F]
variable (G : Type) [AddCommGroup G] [Module F G] [Fintype G] [DecidableEq G]
  [SampleableType G]

/-- Direction of the DLEq proof.

* `remask`: `output = remask sk input`, so
  `output.c2 - input.c2 = sk • input.c1`.
* `leave`: `input = remask sk output`, so
  `input.c2 - output.c2 = sk • input.c1`
  (i.e. `output.c2 - input.c2 = -sk • input.c1`). -/
inductive DLEqKind where
  /-- `output = remask sk input`. -/
  | remask : DLEqKind
  /-- `input = remask sk output` (the inverse direction). -/
  | leave : DLEqKind

/-- Compute the per-card `d2 := output.c2 - input.c2` (remask) or its negation
(leave). -/
def compute_d2 (F : Type) [Field F] (G : Type) [AddCommGroup G] [Module F G]
    (kind : DLEqKind) (c2_in c2_out : G) : G :=
  match kind with
  | DLEqKind.remask => c2_out - c2_in
  | DLEqKind.leave  => c2_in - c2_out

/-- Both proof directions validate output ciphertexts in the strict Rust
verifier.  The function is retained only to document the former dispatch
point and to make stale legacy assumptions mechanically visible. -/
def validates_output : DLEqKind → Bool
  | DLEqKind.remask => true
  | DLEqKind.leave  => true

/-- Statement for the batched DLEq proof. -/
structure Statement (F : Type) (G : Type) (n : ℕ) where
  /-- Input ciphertexts. -/
  input_cts : Fin n → ElGamalCiphertext G
  /-- Output ciphertexts. -/
  output_cts : Fin n → ElGamalCiphertext G
  /-- Player's public key. -/
  player_pk : G
  /-- Direction (remask or leave). -/
  kind : DLEqKind

/-- Witness: the player's secret key. -/
structure Witness where
  /-- The player's secret key. -/
  player_sk : F

/-- The batched DLEq relation (witness-dependent equation only):
  * `player_pk = player_sk • g`;
  * `compute_d2 kind input[i].c2 output[i].c2 = player_sk • input[i].c1`
    for all `i`.

Statement-level preconditions (`c1` invariance, `is_valid`) are checked
outside the Σ-protocol, mirroring the Rust implementation. -/
def relation (g : G) {n : ℕ} (stmt : Statement F G n)
    (wit : Witness F) : Bool :=
  decide (
    wit.player_sk • g = stmt.player_pk ∧
    ∀ i,
      compute_d2 F G stmt.kind (stmt.input_cts i).c2 (stmt.output_cts i).c2 =
        wit.player_sk • (stmt.input_cts i).c1)

/-- Statement-only checks enforced by the strict Rust verifier before the
Schnorr equations are evaluated. -/
def WellFormedStatement {n : ℕ} (stmt : Statement F G n) : Prop :=
  0 < n ∧
  stmt.player_pk ≠ 0 ∧
  ∀ i,
    (stmt.input_cts i).is_valid = true ∧
    (stmt.output_cts i).is_valid = true ∧
    (stmt.input_cts i).c1 = (stmt.output_cts i).c1

/-- Exact logical relation corresponding to successful strict Rust
verification: public-input validity plus the witness-dependent DLEq relation. -/
def RustRelation (g : G) {n : ℕ} (stmt : Statement F G n)
    (wit : Witness F) : Prop :=
  WellFormedStatement F G stmt ∧ relation F G g stmt wit = true

/-- Honest well-formed statements and witnesses satisfy the full Rust-level
relation. -/
theorem rust_relation_complete (g : G) {n : ℕ}
    (stmt : Statement F G n) (wit : Witness F)
    (hstmt : WellFormedStatement F G stmt)
    (hrel : relation F G g stmt wit = true) :
    RustRelation F G g stmt wit :=
  ⟨hstmt, hrel⟩

/-- Extraction from the Σ equations cannot erase statement validity because
the latter depends only on the common public statement. -/
theorem rust_relation_of_extracted (g : G) {n : ℕ}
    (stmt : Statement F G n) (wit : Witness F)
    (hstmt : WellFormedStatement F G stmt)
    (hrel : relation F G g stmt wit = true) :
    RustRelation F G g stmt wit :=
  ⟨hstmt, hrel⟩

/-- The batched DLEq Σ-protocol.

The protocol uses a single randomiser `ω ← $ᵗ F` and a single Schnorr
challenge `c`. Commitment is `B = ω • g` plus per-card
`A_i = ω • input[i].c1`; response is `s = ω + c * sk`. -/
def sigma (g : G) (n : ℕ) : SigmaProtocol
    (Statement F G n) (Witness F) (G × (Fin n → G)) F F F
    (relation F G g) where
  commit stmt _wit := do
    let ω ← ($ᵗ F)
    let B := ω • g
    let A_vec : Fin n → G := fun i => ω • (stmt.input_cts i).c1
    return ((B, A_vec), ω)
  respond _stmt wit ω c := pure (ω + c * wit.player_sk)
  verify stmt BA c s :=
    decide (
      s • g = BA.1 + c • stmt.player_pk ∧
      ∀ i,
        s • (stmt.input_cts i).c1 = BA.2 i + c •
          compute_d2 F G stmt.kind (stmt.input_cts i).c2 (stmt.output_cts i).c2)
  sim stmt := do
    -- The commit distribution is independent of the witness (commit ignores
    -- `wit`), so `sim` re-samples `ω` and recomputes the commit. This matches
    -- the real commit marginal exactly.
    let ω ← ($ᵗ F)
    pure (ω • g, fun i => ω • (stmt.input_cts i).c1)
  extract c₁ s₁ c₂ s₂ := pure ⟨(s₁ - s₂) * (c₁ - c₂)⁻¹⟩

/-! ## Perfect completeness

An honest prover with a valid witness always produces an accepting transcript.
The proof is bilinearity of `Module F G`: `(ω + c·sk) • g = ω • g + c • (sk • g)
= B + c • player_pk`, and symmetrically for each `input[i].c1`. -/

theorem sigma_complete (g : G) (n : ℕ) :
    PerfectlyComplete (sigma F G g n) := by
  intro stmt wit hrel
  -- Decompose the relation into the public-key equation and the per-card equations.
  have h_eq : wit.player_sk • g = stmt.player_pk ∧
      ∀ i, compute_d2 F G stmt.kind (stmt.input_cts i).c2 (stmt.output_cts i).c2 =
        wit.player_sk • (stmt.input_cts i).c1 :=
    of_decide_eq_true hrel
  have h_eq_pk : wit.player_sk • g = stmt.player_pk := h_eq.1
  have h_eq_card : ∀ i,
      compute_d2 F G stmt.kind (stmt.input_cts i).c2 (stmt.output_cts i).c2 =
        wit.player_sk • (stmt.input_cts i).c1 := h_eq.2
  -- The verification equation holds for every (ω, c) drawn by the honest prover.
  have hverify : ∀ (ω c : F),
      (ω + c * wit.player_sk) • g = ω • g + c • stmt.player_pk ∧
      ∀ i, (ω + c * wit.player_sk) • (stmt.input_cts i).c1 =
        ω • (stmt.input_cts i).c1 + c •
          compute_d2 F G stmt.kind (stmt.input_cts i).c2 (stmt.output_cts i).c2 := by
    intro ω c
    refine ⟨?_, ?_⟩
    · rw [add_smul, mul_smul, h_eq_pk]
    · intro i
      rw [add_smul, mul_smul, h_eq_card]
  simp only [sigma, monad_norm]
  simp [hverify]

/-! ## Special soundness

From two accepting transcripts sharing the same commitment `(B, A_vec)` but
with distinct challenges `c₁ ≠ c₂`, the extractor
`extract c₁ s₁ c₂ s₂ = ⟨(s₁ - s₂) * (c₁ - c₂)⁻¹⟩` returns a witness
satisfying the relation. -/

theorem sigma_speciallySound (g : G) (n : ℕ) :
    SpeciallySound (sigma F G g n) := by
  intro stmt BA c₁ c₂ s₁ s₂ h_ne h_v1 h_v2 w h_w
  dsimp only [sigma] at *
  simp only [support_pure, Set.mem_singleton_iff] at h_w
  subst h_w
  simp only [relation, decide_eq_true_eq] at h_v1 h_v2 ⊢
  obtain ⟨h_v1_pk, h_v1_card⟩ := h_v1
  obtain ⟨h_v2_pk, h_v2_card⟩ := h_v2
  -- Subtract the two verification equations for the public-key part.
  have h_sub_pk : (s₁ - s₂) • g = (c₁ - c₂) • stmt.player_pk := by
    rw [sub_smul, sub_smul, h_v1_pk, h_v2_pk, add_sub_add_left_eq_sub]
  -- Subtract the two verification equations for each card.
  have h_sub_card : ∀ i,
      (s₁ - s₂) • (stmt.input_cts i).c1 =
        (c₁ - c₂) •
          compute_d2 F G stmt.kind (stmt.input_cts i).c2 (stmt.output_cts i).c2 := by
    intro i
    rw [sub_smul, sub_smul, h_v1_card i, h_v2_card i, add_sub_add_left_eq_sub]
  have h_ne' : c₁ - c₂ ≠ 0 := sub_ne_zero.mpr h_ne
  refine ⟨?_, ?_⟩
  · -- Public-key equation: ((s₁ - s₂) * (c₁ - c₂)⁻¹) • g = player_pk
    calc ((s₁ - s₂) * (c₁ - c₂)⁻¹) • g
        = (c₁ - c₂)⁻¹ • ((s₁ - s₂) • g) := by rw [mul_comm, mul_smul]
      _ = (c₁ - c₂)⁻¹ • ((c₁ - c₂) • stmt.player_pk) := by rw [h_sub_pk]
      _ = ((c₁ - c₂)⁻¹ * (c₁ - c₂)) • stmt.player_pk := by rw [← mul_smul]
      _ = (1 : F) • stmt.player_pk := by rw [inv_mul_cancel₀ h_ne']
      _ = stmt.player_pk := one_smul F stmt.player_pk
  · -- Per-card equation: `compute_d2 ... = ((s₁ - s₂) * (c₁ - c₂)⁻¹) • input[i].c1`.
    -- The relation puts `compute_d2` on the LHS, so we run the calc in that
    -- direction (the algebraic chain is just the symmetric version of the
    -- public-key case, with `(stmt.input_cts i).c1` replacing `g` and
    -- `compute_d2 …` replacing `stmt.player_pk`).
    intro i
    calc compute_d2 F G stmt.kind (stmt.input_cts i).c2 (stmt.output_cts i).c2
        = (1 : F) •
            compute_d2 F G stmt.kind (stmt.input_cts i).c2 (stmt.output_cts i).c2 := by
          rw [one_smul]
      _ = ((c₁ - c₂)⁻¹ * (c₁ - c₂)) •
            compute_d2 F G stmt.kind (stmt.input_cts i).c2 (stmt.output_cts i).c2 := by
          rw [inv_mul_cancel₀ h_ne', one_smul]
      _ = (c₁ - c₂)⁻¹ • ((c₁ - c₂) •
            compute_d2 F G stmt.kind (stmt.input_cts i).c2 (stmt.output_cts i).c2) := by
          rw [mul_smul]
      _ = (c₁ - c₂)⁻¹ • ((s₁ - s₂) • (stmt.input_cts i).c1) := by
          rw [h_sub_card i]
      _ = ((s₁ - s₂) * (c₁ - c₂)⁻¹) • (stmt.input_cts i).c1 := by
          module

/-! ## Perfect HVZK

The simulator samples `c, s ← $ᵗ F`, reconstructs
`B = s • g - c • player_pk` and `A_vec i = s • (input[i].c1) - c • (compute_d2 ...)`,
and the resulting transcript distribution equals the real one.

Bijection: for fixed `c`, the response map `ω ↦ ω + c * sk` is a bijection on `F`. -/

def simTranscript (g : G) (n : ℕ) (stmt : Statement F G n) :
    ProbComp ((G × (Fin n → G)) × F × F) := do
  let c ← ($ᵗ F)
  let s ← ($ᵗ F)
  let B := s • g - c • stmt.player_pk
  let A_vec : Fin n → G := fun i =>
    s • (stmt.input_cts i).c1 - c •
      compute_d2 F G stmt.kind (stmt.input_cts i).c2 (stmt.output_cts i).c2
  return ((B, A_vec), c, s)

open OracleComp.ProgramLogic OracleComp.ProgramLogic.Relational in
theorem sigma_perfect_hvzk (g : G) (n : ℕ) :
    PerfectHVZK (sigma F G g n) (fun stmt => simTranscript F G g n stmt) := by
  intro stmt wit hrel
  have h_eq : wit.player_sk • g = stmt.player_pk ∧
      ∀ i, compute_d2 F G stmt.kind (stmt.input_cts i).c2 (stmt.output_cts i).c2 =
        wit.player_sk • (stmt.input_cts i).c1 :=
    of_decide_eq_true hrel
  have h_eq_pk : wit.player_sk • g = stmt.player_pk := h_eq.1
  have h_eq_card : ∀ i,
      compute_d2 F G stmt.kind (stmt.input_cts i).c2 (stmt.output_cts i).c2 =
        wit.player_sk • (stmt.input_cts i).c1 := h_eq.2
  apply evalDist_ext
  intro t
  -- Bridge 1: real transcript to independent-sampling form.
  trans Pr[= t | do
    let c ← ($ᵗ F)
    let ω ← ($ᵗ F)
    pure ((( (ω + c * wit.player_sk) • g - c • stmt.player_pk,
             fun i =>
               (ω + c * wit.player_sk) • (stmt.input_cts i).c1 - c •
                 compute_d2 F G stmt.kind
                   (stmt.input_cts i).c2 (stmt.output_cts i).c2),
           c, ω + c * wit.player_sk)
          : ((G × (Fin n → G)) × F × F))]
  · simp only [SigmaProtocol.realTranscript, sigma]
    vcstep rw
    -- Close by bilinearity: the real commit (ω•g, ω•c1[i]) equals the
    -- independent form's commit ((ω+c·sk)•g - c•pk, (ω+c·sk)•c1[i] - c•d2[i])
    -- using add_smul, mul_smul, h_eq_pk, h_eq_card, and add_sub_cancel_right.
    simp only [add_smul, mul_smul, h_eq_pk, h_eq_card, add_sub_cancel_right]
    rfl
  · show _ = Pr[= t | simTranscript F G g n stmt]
    unfold simTranscript
    -- Bridge 2: simulator to independent form via the translation bijection
    -- `ω ↦ ω + c * wit.player_sk` (a bijection on F for fixed c).
    apply probOutput_eq_of_relTriple_eqRel (x := t)
    rvcstep
    intro c _ hc; subst hc
    rvcstep using (· + c * wit.player_sk)
    exact ⟨fun _ _ h => add_right_cancel h,
           fun s => ⟨s - c * wit.player_sk, sub_add_cancel s _⟩⟩

end PokerProtocolLean.DLEq
