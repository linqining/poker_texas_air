import Mathlib.Tactic
import Mathlib.Tactic.Module
import PokerProtocolLean.Foundations.ElGamal

/-!
# Reconstruction V3 slot-membership OR proof

This file formalizes the two-branch Chaum--Pedersen OR protocol implemented by
Rust `reconstruction/slot_or.rs`. For one canonical card `card` and aggregate-
key contribution `C`, the prover proves knowledge of `r` for either

* branch `false`: `C = Enc(0; r)`, or
* branch `true`:  `C = Enc(-card; r)`.

The wire transcript contains both branch commitments, challenge shares and
responses. The branch is witness-only. We machine-check honest acceptance,
two-fork special-sound extraction, simulator acceptance, exact real/simulated
transcript equality under the standard response translation, and the
bijection that turns this equality into perfect honest-verifier ZK.

Fiat--Shamir challenge derivation and rejection sampling of identity
commitments are implementation-layer obligations and are not modeled here.
-/

namespace PokerProtocolLean.Reconstruct.V3.SlotOr

open PokerProtocolLean.Foundations

variable (F : Type) [Field F]
variable (G : Type) [AddCommGroup G] [Module F G]

/-- Public statement for one canonical contribution slot. -/
structure Statement where
  g : G
  aggregatePk : G
  card : G
  contribution : ElGamalCiphertext G

/-- The second Chaum--Pedersen target is `c2 + card`; the first is `c2`. -/
def target (stmt : Statement G) (branch : Bool) : G :=
  if branch then stmt.contribution.c2 + stmt.card else stmt.contribution.c2

/-- Witness relation for one branch. -/
def Relation (stmt : Statement G) (branch : Bool) (randomness : F) : Prop :=
  stmt.contribution.c1 = randomness • stmt.g ∧
  target G stmt branch = randomness • stmt.aggregatePk

/-- Branch-independent public transcript. -/
@[ext]
structure Transcript where
  commitmentG : Bool → G
  commitmentPk : Bool → G
  challengeShare : Bool → F
  response : Bool → F
  challenge : F

/-- Interactive verifier equations, including `e₀ + e₁ = c`. -/
def Accepts (stmt : Statement G) (tr : Transcript F G) : Prop :=
  tr.challengeShare false + tr.challengeShare true = tr.challenge ∧
  ∀ branch,
    tr.response branch • stmt.g =
      tr.commitmentG branch + tr.challengeShare branch • stmt.contribution.c1 ∧
    tr.response branch • stmt.aggregatePk =
      tr.commitmentPk branch + tr.challengeShare branch • target G stmt branch

/-- Standard OR-proof simulator: choose both challenge shares and responses,
then reconstruct both commitments. -/
def simulate (stmt : Statement G) (challenge : F)
    (challengeShare response : Bool → F) : Transcript F G where
  commitmentG := fun branch =>
    response branch • stmt.g - challengeShare branch • stmt.contribution.c1
  commitmentPk := fun branch =>
    response branch • stmt.aggregatePk - challengeShare branch • target G stmt branch
  challengeShare := challengeShare
  response := response
  challenge := challenge

/-- Every simulated transcript whose shares sum to the global challenge is
accepted, without a witness. -/
theorem simulate_accepts (stmt : Statement G) (challenge : F)
    (challengeShare response : Bool → F)
    (hsum : challengeShare false + challengeShare true = challenge) :
    Accepts F G stmt (simulate F G stmt challenge challengeShare response) := by
  refine ⟨hsum, ?_⟩
  intro branch
  constructor <;> simp [simulate]

/-- Honest OR transcript: one branch is real and the other is simulated. -/
def honestTranscript (stmt : Statement G) (realBranch : Bool)
    (randomness realNonce simulatedChallenge simulatedResponse challenge : F) :
    Transcript F G :=
  let shares : Bool → F := fun branch =>
    if branch = realBranch then challenge - simulatedChallenge else simulatedChallenge
  let responses : Bool → F := fun branch =>
    if branch = realBranch then realNonce + shares branch * randomness
    else simulatedResponse
  {
    commitmentG := fun branch =>
      if branch = realBranch then realNonce • stmt.g
      else simulatedResponse • stmt.g - simulatedChallenge • stmt.contribution.c1
    commitmentPk := fun branch =>
      if branch = realBranch then realNonce • stmt.aggregatePk
      else simulatedResponse • stmt.aggregatePk - simulatedChallenge • target G stmt branch
    challengeShare := shares
    response := responses
    challenge := challenge
  }

/-- Perfect completeness of the interactive slot OR protocol. -/
theorem honest_accepts (stmt : Statement G) (realBranch : Bool)
    (randomness realNonce simulatedChallenge simulatedResponse challenge : F)
    (hrel : Relation F G stmt realBranch randomness) :
    Accepts F G stmt
      (honestTranscript F G stmt realBranch randomness realNonce
        simulatedChallenge simulatedResponse challenge) := by
  rcases hrel with ⟨hc1, htarget⟩
  constructor
  · cases realBranch <;> simp [honestTranscript]
  · intro branch
    by_cases hbranch : branch = realBranch
    · subst branch
      simp [honestTranscript, hc1, htarget, add_smul, mul_smul]
    · simp [honestTranscript, hbranch]

/-- Fork extractor for one branch whose challenge share differs. -/
def extract (tr₁ tr₂ : Transcript F G) (branch : Bool) : F :=
  (tr₁.response branch - tr₂.response branch) *
    (tr₁.challengeShare branch - tr₂.challengeShare branch)⁻¹

/-- One differing branch share in two accepting transcripts with common
commitments extracts a valid branch witness. -/
theorem extract_relation (stmt : Statement G) (tr₁ tr₂ : Transcript F G)
    (branch : Bool) (hcommitG : tr₁.commitmentG = tr₂.commitmentG)
    (hcommitPk : tr₁.commitmentPk = tr₂.commitmentPk)
    (haccept₁ : Accepts F G stmt tr₁) (haccept₂ : Accepts F G stmt tr₂)
    (hne : tr₁.challengeShare branch ≠ tr₂.challengeShare branch) :
    Relation F G stmt branch (extract F G tr₁ tr₂ branch) := by
  let d := tr₁.challengeShare branch - tr₂.challengeShare branch
  have hd : d ≠ 0 := sub_ne_zero.mpr hne
  have hg₁ := (haccept₁.2 branch).1
  have hg₂ := (haccept₂.2 branch).1
  have hpk₁ := (haccept₁.2 branch).2
  have hpk₂ := (haccept₂.2 branch).2
  have hcg := congrFun hcommitG branch
  have hcpk := congrFun hcommitPk branch
  have hsubg : (tr₁.response branch - tr₂.response branch) • stmt.g =
      d • stmt.contribution.c1 := by
    dsimp [d]
    rw [sub_smul, sub_smul, hg₁, hg₂, hcg]
    abel
  have hsubpk : (tr₁.response branch - tr₂.response branch) • stmt.aggregatePk =
      d • target G stmt branch := by
    dsimp [d]
    rw [sub_smul, sub_smul, hpk₁, hpk₂, hcpk]
    abel
  constructor
  · symm
    calc
      extract F G tr₁ tr₂ branch • stmt.g =
          d⁻¹ • ((tr₁.response branch - tr₂.response branch) • stmt.g) := by
            simp [extract, d, mul_comm, mul_smul]
      _ = d⁻¹ • (d • stmt.contribution.c1) := by rw [hsubg]
      _ = stmt.contribution.c1 := by rw [← mul_smul, inv_mul_cancel₀ hd, one_smul]
  · calc
      target G stmt branch = (1 : F) • target G stmt branch := by rw [one_smul]
      _ = (d⁻¹ * d) • target G stmt branch := by rw [inv_mul_cancel₀ hd]
      _ = d⁻¹ • (d • target G stmt branch) := by rw [mul_smul]
      _ = d⁻¹ • ((tr₁.response branch - tr₂.response branch) • stmt.aggregatePk) := by rw [hsubpk]
      _ = extract F G tr₁ tr₂ branch • stmt.aggregatePk := by
        simp [extract, d, mul_comm, mul_smul]

/-- Two accepting forks with the same commitments and different global
challenges extract a witness for at least one of the two branches. -/
theorem specially_sound (stmt : Statement G) (tr₁ tr₂ : Transcript F G)
    (hcommitG : tr₁.commitmentG = tr₂.commitmentG)
    (hcommitPk : tr₁.commitmentPk = tr₂.commitmentPk)
    (haccept₁ : Accepts F G stmt tr₁) (haccept₂ : Accepts F G stmt tr₂)
    (hchallenge : tr₁.challenge ≠ tr₂.challenge) :
    ∃ branch randomness, Relation F G stmt branch randomness := by
  by_cases hfalse : tr₁.challengeShare false = tr₂.challengeShare false
  · have htrue : tr₁.challengeShare true ≠ tr₂.challengeShare true := by
      intro heq
      apply hchallenge
      rw [← haccept₁.1, ← haccept₂.1, hfalse, heq]
    exact ⟨true, extract F G tr₁ tr₂ true,
      extract_relation F G stmt tr₁ tr₂ true hcommitG hcommitPk haccept₁ haccept₂ htrue⟩
  · exact ⟨false, extract F G tr₁ tr₂ false,
      extract_relation F G stmt tr₁ tr₂ false hcommitG hcommitPk haccept₁ haccept₂ hfalse⟩

/-- The honest transcript is pointwise identical to the simulator transcript
using its public challenge shares and responses. -/
theorem honest_eq_simulate (stmt : Statement G) (realBranch : Bool)
    (randomness realNonce simulatedChallenge simulatedResponse challenge : F)
    (hrel : Relation F G stmt realBranch randomness) :
    honestTranscript F G stmt realBranch randomness realNonce
        simulatedChallenge simulatedResponse challenge =
      simulate F G stmt challenge
        (honestTranscript F G stmt realBranch randomness realNonce
          simulatedChallenge simulatedResponse challenge).challengeShare
        (honestTranscript F G stmt realBranch randomness realNonce
          simulatedChallenge simulatedResponse challenge).response := by
  rcases hrel with ⟨hc1, htarget⟩
  apply Transcript.ext
  · funext branch
    by_cases hbranch : branch = realBranch
    · simp [honestTranscript, simulate, hbranch, hc1, add_smul, mul_smul]
    · simp [honestTranscript, simulate, hbranch]
  · funext branch
    by_cases hbranch : branch = realBranch
    · simp [honestTranscript, simulate, hbranch, htarget, add_smul, mul_smul]
    · simp [honestTranscript, simulate, hbranch]
  · rfl
  · rfl
  · rfl

/-- For fixed challenge share and witness, the honest response map is a
translation and therefore a bijection. This is the probability-preserving
change of variables used by the perfect-HVZK argument. -/
theorem response_translation_bijective (challengeShare randomness : F) :
    Function.Bijective (fun nonce => nonce + challengeShare * randomness) := by
  refine ⟨?_, ?_⟩
  · intro x y h
    exact add_right_cancel h
  · intro z
    exact ⟨z - challengeShare * randomness, sub_add_cancel z _⟩

/-- Algebraic perfect-HVZK package: simulator acceptance, exact transcript
reconstruction, and a bijective real-response change of variables. -/
theorem perfect_hvzk_algebraic (stmt : Statement G) (realBranch : Bool)
    (randomness realNonce simulatedChallenge simulatedResponse challenge : F)
    (hrel : Relation F G stmt realBranch randomness) :
    Accepts F G stmt
      (simulate F G stmt challenge
        (honestTranscript F G stmt realBranch randomness realNonce
          simulatedChallenge simulatedResponse challenge).challengeShare
        (honestTranscript F G stmt realBranch randomness realNonce
          simulatedChallenge simulatedResponse challenge).response) ∧
    honestTranscript F G stmt realBranch randomness realNonce
        simulatedChallenge simulatedResponse challenge =
      simulate F G stmt challenge
        (honestTranscript F G stmt realBranch randomness realNonce
          simulatedChallenge simulatedResponse challenge).challengeShare
        (honestTranscript F G stmt realBranch randomness realNonce
          simulatedChallenge simulatedResponse challenge).response ∧
    Function.Bijective
      (fun nonce => nonce +
        (challenge - simulatedChallenge) * randomness) := by
  have hhonest := honest_accepts F G stmt realBranch randomness realNonce
    simulatedChallenge simulatedResponse challenge hrel
  have heq := honest_eq_simulate F G stmt realBranch randomness realNonce
    simulatedChallenge simulatedResponse challenge hrel
  refine ⟨?_, heq, response_translation_bijective F
    (challenge - simulatedChallenge) randomness⟩
  rw [← heq]
  exact hhonest

end PokerProtocolLean.Reconstruct.V3.SlotOr
