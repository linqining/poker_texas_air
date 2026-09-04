# RFP-03 Alignment — Provably fair poker where cheating is mathematically impossible

Source: [strk20-hackathon IDEAS.md](https://github.com/starkience/strk20-hackathon/blob/main/IDEAS.md)
(RFP-03, Gaming) with full write-up at
[strk20.starknet.io/rfp/private-poker](https://strk20.starknet.io/rfp/private-poker).

## Positioning

RFP-03's baseline is a trusted dealer whose every obligation is proven with
STARKs, making cheating *detectable*. This submission implements **mental
poker V2**: there is no trusted dealer at all. The deck is jointly shuffled
by the players under ElGamal encryption with a sigma proof per step, so
cheating is not merely detectable — it is **mathematically impossible**
without breaking the underlying cryptography. The Lean 4 formalization
([poker_protocol_lean](../poker_protocol_lean)) machine-checks the critical
reconstruction protocol (V3) for soundness.

## Requirement mapping

| RFP-03 requirement | Implementation | Status |
|---|---|---|
| Mental poker: no trusted shuffle/deal; every step provable; unused cards leak nothing | `poker_protocol` (ElGamal + joint shuffle), `poker-protocol-proofs` (shuffle/remask/leave/reveal/DLEq/reconstruction sigma proofs), `poker-protocol-bg` (Bayer–Groth), Lean-verified V3 reconstruction | ✅ Done |
| Dealer STARK proofs per street (shuffled range / hand strength / terminal legality) | Stwo circle-STARK stack: `src/` AIRs (`texas_tagged`, `texas_canonical_air`), `hand-bench`, `proving-tool` pipeline (Cairo1 → cairo-vm → Stwo). Phase 1 runs the hand-verify sigma-batch program host-side; the real `hand_verify.cairo` circuit is Phase 2 | ⚠️ Phase 1 (RFP allows "eventually") |
| On-chain STARK verifier eventually | `PokerDualSettlement` already verifies the P layer on-chain (EC_OP); G-STARK verifier (`cairo_verifier` direction) is Phase 2 | 🗺️ Roadmap |
| STRK20 as chips; deposit into a privacy pool; buy-in/settle via pool | `poker_contracts`: `PokerVault` (1:1 STRK20 ⇄ chips), `PokerVaultAnonymizer` (private buy-in + paymaster relay, see docs/starknet-plan-b-anonymizer.md), `PokerSettlement`, `PokerDualSettlement` | ✅ Deployed on Sepolia (testnet suffices per RFP) |
| Hole cards private; reveals only after settlement (hand history public) | Encrypted dealing end-to-end; chain sees only Poseidon commitments over outcomes (`starknet_settlement::SettleHandCalldata`) | ✅ Done |
| Game engine can stay off-chain | Full Hold'em state machine in `texas/src/pokergame/` off-chain; on-chain settlement of aggregated results | ✅ Done |
| No bridge required; simplest pool bridging | None used | ✅ N/A |
| No mainnet privacy-pool deployment required | Sepolia deployment recorded in `strk20.json`; one mainnet STRK20 tx per hackathon step 3 | ✅/🗺️ tx pending |

## What the privacy pool conceals vs reveals

- **Conceals**: hole cards at all times (mental-poker encryption), individual
  per-step deal information, private buy-in via the Anonymizer.
- **Reveals** (post-settlement): final hand history, settlement deltas as
  Poseidon commitments bound to a monotonic hand range with replay
  protection (`hand_binding`).

## Evidence pointers

- Protocol spec: [../DUAL_PROOF_PROTOCOL.md](../DUAL_PROOF_PROTOCOL.md) (v2.3)
- On-chain proof policy: [../strk20.json](../strk20.json) `proof_policy`
- Trust posture (no prover service; browser-verifiable G layer):
  README "Trust model & proof policy"
- Formal verification: [../poker_protocol_lean/README.md](../poker_protocol_lean/README.md)
- Performance baselines: [plan_d_perf.md（当前基线；gas 校准数据见 plan-d-p3-metrics.md §3b）](plan_d_perf.md（当前基线；gas 校准数据见 plan-d-p3-metrics.md §3b）)
- Narrative history: [starknet-rfp-submission.md](starknet-rfp-submission.md)
