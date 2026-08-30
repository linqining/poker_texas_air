import VCVio.CryptoFoundations.SigmaProtocol
import VCVio.OracleComp.Constructions.SampleableType
import PokerProtocolLean.Schnorr.GeneralizedSchnorr

/-!
# Public-key ownership proof

This module formalizes the interactive Σ-protocol underlying Rust
`PKOwnershipProof`. The public statement is `pk`; the witness is `sk`; and the
relation is `pk = sk • g`. It is the `n = 1` specialization of generalized
Schnorr. The Rust implementation additionally rejects zero secret keys,
identity public keys and identity commitments; those are fail-closed encoding
checks around the algebraic protocol.

The Fiat--Shamir hash used by Rust is not modeled here. The results below are
interactive perfect completeness, special soundness and perfect HVZK.
-/

open OracleSpec OracleComp SigmaProtocol

namespace PokerProtocolLean.PKOwnership

variable (F : Type) [Field F] [Fintype F] [DecidableEq F] [SampleableType F]
variable (G : Type) [AddCommGroup G] [Module F G] [Fintype G] [DecidableEq G]
  [SampleableType G]

/-- Rust-level public statement. -/
structure Statement where
  publicKey : G

/-- Secret-key witness. -/
structure Witness where
  secretKey : F

/-- Ownership relation `pk = sk • g`. -/
def relation (g : G) (stmt : Statement G) (wit : Witness F) : Prop :=
  stmt.publicKey = wit.secretKey • g

/-- Adapter to the one-base generalized Schnorr statement. -/
def toStatement (g : G) (stmt : Statement G) :
    GeneralizedSchnorr.Statement F G 1 where
  base_points := fun _ => g
  R := stmt.publicKey

/-- Adapter to the one-scalar generalized Schnorr witness. -/
def toWitness (wit : Witness F) : GeneralizedSchnorr.Witness F 1 where
  scalars := fun _ => wit.secretKey

/-- The generalized Schnorr relation is exactly public-key ownership. -/
theorem generalized_relation_iff (g : G) (stmt : Statement G) (wit : Witness F) :
    GeneralizedSchnorr.relation F G 1 (toStatement F G g stmt) (toWitness F wit) = true ↔
      relation F G g stmt wit := by
  simp [GeneralizedSchnorr.relation, GeneralizedSchnorr.dotSmul,
    toStatement, toWitness, relation]
  constructor <;> intro h <;> exact h.symm

/-- Concrete interactive ownership Σ-protocol. -/
def sigma := GeneralizedSchnorr.sigma F G 1

/-- Perfect completeness. -/
theorem sigma_complete : PerfectlyComplete (sigma F G) :=
  GeneralizedSchnorr.sigma_complete F G 1

/-- Special soundness: two accepting forks extract the secret key. -/
theorem sigma_speciallySound : SpeciallySound (sigma F G) :=
  GeneralizedSchnorr.sigma_speciallySound F G 1

/-- Perfect honest-verifier zero knowledge. -/
theorem sigma_perfect_hvzk :
    PerfectHVZK (sigma F G) (fun stmt => GeneralizedSchnorr.simTranscript F G 1 stmt) :=
  GeneralizedSchnorr.sigma_perfect_hvzk F G 1

end PokerProtocolLean.PKOwnership
