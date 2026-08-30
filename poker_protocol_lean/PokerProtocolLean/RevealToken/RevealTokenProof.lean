import Mathlib.Algebra.BigOperators.Fin
import Mathlib.Algebra.Module.BigOperators
import Mathlib.Tactic.Module
import VCVio.CryptoFoundations.SigmaProtocol
import VCVio.OracleComp.Constructions.SampleableType
import PokerProtocolLean.Foundations.AlgebraicSetup
import PokerProtocolLean.Foundations.ElGamal
import PokerProtocolLean.ChaumPedersen.ChaumPedersenDLEQ

/-!
# RevealTokenProof — reduction to Chaum-Pedersen DLEQ

Backing `poker_protocol/src/zk_shuffle/reveal_token_proof.rs`.

A reveal token for ciphertext `ct` under secret key `sk` is `t := sk • ct.c1`.
Combined with the player's public key `pk = sk • g`, this constitutes a
Chaum-Pedersen statement with

    G1 = g, P1 = pk, G2 = ct.c1, P2 = t, s = sk.

The proof therefore reuses M3 verbatim; the only addition is the **binding
lemma** that links a verified token to the underlying plaintext via the
Layer-2 bridge lemma (`c2_minus_sk_c1_eq_plaintext`).
-/

open OracleSpec OracleComp SigmaProtocol
open PokerProtocolLean.Foundations (ElGamalCiphertext)
open scoped ENNReal

namespace PokerProtocolLean.RevealToken

variable (F : Type) [Field F] [Fintype F] [DecidableEq F] [SampleableType F]
variable (G : Type) [AddCommGroup G] [Module F G] [Fintype G] [DecidableEq G]
  [SampleableType G]

/-- Build a Chaum-Pedersen statement for the reveal-token proof of `ct`
under public key `pk`. -/
def toChaumPedersen (g : G) (pk : G) (ct : ElGamalCiphertext G) (token : G) :
    PokerProtocolLean.ChaumPedersen.Statement F G where
  G1 := g
  G2 := ct.c1
  P1 := pk
  P2 := token

/-- The shared witness. -/
def toChaumPedersenWitness (sk : F) : PokerProtocolLean.ChaumPedersen.Witness F where
  s := sk

/-- The reveal-token Σ-protocol is the Chaum-Pedersen protocol on the
specialised statement. -/
def sigma (g : G) (pk : G) (ct : ElGamalCiphertext G) (token : G) :
    SigmaProtocol
      (PokerProtocolLean.ChaumPedersen.Statement F G)
      (PokerProtocolLean.ChaumPedersen.Witness F)
      (PokerProtocolLean.ChaumPedersen.Commit F G)
      F F F
      (PokerProtocolLean.ChaumPedersen.relation F G) :=
  PokerProtocolLean.ChaumPedersen.sigma F G

/-! ## The three Σ-protocol properties follow by reduction to M3 -/

theorem sigma_complete (g : G) (pk : G) (ct : ElGamalCiphertext G) (token : G) :
    PerfectlyComplete (sigma F G g pk ct token) := by
  exact PokerProtocolLean.ChaumPedersen.sigma_complete F G

theorem sigma_speciallySound (g : G) (pk : G) (ct : ElGamalCiphertext G)
    (token : G) :
    SpeciallySound (sigma F G g pk ct token) := by
  exact PokerProtocolLean.ChaumPedersen.sigma_speciallySound F G

theorem sigma_perfect_hvzk (g : G) (pk : G) (ct : ElGamalCiphertext G)
    (token : G) :
    PerfectHVZK (sigma F G g pk ct token)
      (fun stmt => PokerProtocolLean.ChaumPedersen.simTranscript F G stmt) := by
  exact PokerProtocolLean.ChaumPedersen.sigma_perfect_hvzk F G

/-! ## Binding lemma: a verified reveal token recovers the plaintext

If the Chaum-Pedersen verification accepts for statement
`(g, ct.c1, pk, token)`, the extracted witness `sk` satisfies both
`pk = sk • g` and `token = sk • ct.c1`. If additionally `ct` was honestly
encrypted as `encrypt g m pk r`, the Layer-2 bridge lemma gives
`ct.c2 - token = m`.
-/

theorem token_binds_to_plaintext
    (g : G) (m pk : G) (sk r : F) (ct : ElGamalCiphertext G) (token : G)
    (hpk : pk = sk • g)
    (henc : ct = ElGamalCiphertext.encrypt F G g m pk r)
    (htoken : token = ElGamalCiphertext.gen_reveal_token F G sk ct) :
    ct.c2 - token = m := by
  rw [htoken, PokerProtocolLean.Foundations.gen_reveal_token_eq,
      PokerProtocolLean.Foundations.c2_minus_sk_c1_eq_plaintext F G g m pk sk r ct hpk henc]

end PokerProtocolLean.RevealToken
