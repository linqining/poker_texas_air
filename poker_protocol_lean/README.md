# poker_protocol_lean

Lean 4 + Mathlib + VCV-io audit and formalisation of the Rust proof systems in
`poker_protocol` and `poker-protocol-proofs`.

## Audited result

The library builds with zero `sorry`/`admit`, but proof coverage is not the
same as end-to-end protocol security. In particular, the former reconstruction
top-level used a `Unit` witness and `True` relation. That placeholder has been
removed.

The current Rust reconstruction-v2 statement is machine-checked to be
insufficient:

- a readable swap plaintext can be placed at the wrong canonical slot while
  all corrected-ciphertext equations still hold;
- public coefficient-derived ElGamal randomness reveals the output plaintext;
- cross-user ciphertext aggregation has inconsistent key/randomness shape.

Therefore this repository does **not** claim completeness, knowledge soundness
or zero knowledge for reconstruction v2.

The repaired V3 formalisation provides:

- authenticated `init_deck` -> shuffle/remask -> prior hand -> partial
  decryption provenance for `user_readable_cards`;
- an exact extracted relation with per-slot `{0, -card_i}` membership and an
  injective readable-card mapping;
- a joint cross-key plaintext-negation relation that does not require knowing
  `DL(readable.c1)`;
- deterministic completeness, semantic soundness and aggregate reconstruction
  theorems.

See [SECURITY_RECONSTRUCTION.md](SECURITY_RECONSTRUCTION.md) for the paper-level
security statement, assumptions, theorem map and remaining Fiat--Shamir /
Bayer--Groth proof obligations.

## Important reconstruction modules

- `PokerProtocolLean/Reconstruct/ReconstructV2Counterexample.lean`
- `PokerProtocolLean/Reconstruct/ReadableCardProvenance.lean`
- `PokerProtocolLean/Reconstruct/ReconstructionV3.lean`
- `PokerProtocolLean/Reconstruct/ReconstructionV3JointSigma.lean`
- `PokerProtocolLean/Reconstruct/ReconstructProof.lean`

The last file is now an audited status entry point; it contains no
always-accepting placeholder Sigma protocol.

## Discrete-log model

`Foundations.UnknownDiscreteLog.FreshDLogHard` uses VCV-io's standard
average-case DLog experiment `x <- F; A(g, x*g)`. The older point-specific
`UnknownDL(P)` is conditional. A premise asserting hardness for every fixed
point is explicitly marked non-standard because easy points such as `P = g`
have public logarithms.

For a valid readable card, Lean proves `c1 = r*g`. Privacy additionally needs
an authenticated lineage containing at least one honest, secret, uniform
shuffle re-randomizer, so that the accumulated `r` is hidden.

## Build and audit

```bash
cd /Users/mac/projects/zgame/poker_protocol_lean
lake build PokerProtocolLean
bash scripts/count_sorries.sh
```

Useful focused builds:

```bash
lake build PokerProtocolLean.Reconstruct.ReconstructV2Counterexample
lake build PokerProtocolLean.Reconstruct.ReadableCardProvenance
lake build PokerProtocolLean.Reconstruct.ReconstructionV3
```

## Formal-proof boundary

Machine checked:

- core ElGamal/remask/reveal algebra;
- generalized Schnorr and Chaum--Pedersen Sigma properties present in their
  respective modules;
- reconstruction v2 counterexamples;
- readable-card provenance algebra;
- repaired V3 extracted-relation semantics.
- perfect completeness, special soundness and perfect HVZK of the V3 joint
  cross-key generalized Schnorr proof.

Still required for an end-to-end paper theorem over the concrete Rust V3
implementation:

- exact Bayer--Groth correspondence and simulator/extractor;
- a concrete per-slot OR Sigma protocol;
- shared-transcript composition and Fiat--Shamir ROM theorem;
- byte-level Rust/Lean statement correspondence;
- state-machine/AIR enforcement of provenance, epoch binding and cross-player
  disjointness.
