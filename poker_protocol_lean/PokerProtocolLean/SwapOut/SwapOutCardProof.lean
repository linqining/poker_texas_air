import Mathlib.Algebra.BigOperators.Fin
import Mathlib.Algebra.Module.BigOperators
import Mathlib.Tactic.Module
import VCVio.CryptoFoundations.SigmaProtocol
import VCVio.OracleComp.Constructions.SampleableType
import PokerProtocolLean.Foundations.AlgebraicSetup
import PokerProtocolLean.Foundations.ElGamal
import PokerProtocolLean.ChaumPedersen.ChaumPedersenDLEQ

/-!
# SwapOutCardProof — reduction to Chaum-Pedersen DLEQ

Backing `poker_protocol/src/zk_shuffle/swap_out_card_proof.rs`.

A "swap-out" card is one where the player replaces a `readable` ciphertext
(which they can decrypt) with a `swap` ciphertext that the user holds the
secret key for. The proof establishes that the difference ciphertext
components `delta_c1 = swap.c1 - readable.c1` and
`delta_c2 = swap.c2 - readable.c2` share the same discrete log w.r.t. the
user's public key:

    delta_c2 = user_sk • delta_c1   and   user_pk = user_sk • g.

This is exactly a Chaum-Pedersen statement with
`G1 = delta_c1, G2 = g, P1 = delta_c2, P2 = user_pk, s = user_sk`.
-/

open OracleSpec OracleComp SigmaProtocol
open PokerProtocolLean.Foundations (ElGamalCiphertext)
open scoped ENNReal

namespace PokerProtocolLean.SwapOut

variable (F : Type) [Field F] [Fintype F] [DecidableEq F] [SampleableType F]
variable (G : Type) [AddCommGroup G] [Module F G] [Fintype G] [DecidableEq G]
  [SampleableType G]

/-- Build a Chaum-Pedersen statement for the swap-out proof. -/
def toChaumPedersen (g : G) (readable swap : ElGamalCiphertext G)
    (user_pk : G) :
    PokerProtocolLean.ChaumPedersen.Statement F G where
  G1 := swap.c1 - readable.c1
  G2 := g
  P1 := swap.c2 - readable.c2
  P2 := user_pk

/-- The swap-out Σ-protocol is the Chaum-Pedersen protocol on the
specialised statement. -/
def sigma (g : G) (readable swap : ElGamalCiphertext G) (user_pk : G) :
    SigmaProtocol
      (PokerProtocolLean.ChaumPedersen.Statement F G)
      (PokerProtocolLean.ChaumPedersen.Witness F)
      (PokerProtocolLean.ChaumPedersen.Commit F G)
      F F F
      (PokerProtocolLean.ChaumPedersen.relation F G) :=
  PokerProtocolLean.ChaumPedersen.sigma F G

/-! ## The three Σ-protocol properties follow by reduction to M3

The swap-out `sigma` is *definitionally* `ChaumPedersen.sigma F G` (it is
bound by `def sigma ... := PokerProtocolLean.ChaumPedersen.sigma F G`), so
the three Σ-protocol properties reduce by `exact` to the corresponding
theorems in `PokerProtocolLean.ChaumPedersen`. The specialised statement
`(G1, G2, P1, P2) = (delta_c1, g, delta_c2, user_pk)` is constructed by
`toChaumPedersen` and is transparent to the proof, since `PerfectlyComplete`,
`SpeciallySound`, and `PerfectHVZK` are quantified over *all* statements. -/

theorem sigma_complete (g : G) (readable swap : ElGamalCiphertext G)
    (user_pk : G) :
    PerfectlyComplete (sigma F G g readable swap user_pk) := by
  exact PokerProtocolLean.ChaumPedersen.sigma_complete F G

theorem sigma_speciallySound (g : G) (readable swap : ElGamalCiphertext G)
    (user_pk : G) :
    SpeciallySound (sigma F G g readable swap user_pk) := by
  exact PokerProtocolLean.ChaumPedersen.sigma_speciallySound F G

theorem sigma_perfect_hvzk (g : G) (readable swap : ElGamalCiphertext G)
    (user_pk : G) :
    PerfectHVZK (sigma F G g readable swap user_pk)
      (fun stmt => PokerProtocolLean.ChaumPedersen.simTranscript F G stmt) := by
  exact PokerProtocolLean.ChaumPedersen.sigma_perfect_hvzk F G

end PokerProtocolLean.SwapOut
