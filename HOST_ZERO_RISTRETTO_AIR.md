# Ristretto255 host-zero cryptographic transition

This document defines the only acceptable migration from the current
host-attested poker-precompile boundary to a Ristretto255 AIR-backed boundary.
It supplements `TRUST_MODEL_NO_TRANSACTION_REPLAY.md`.

## Non-negotiable security property

No production admission decision may depend on
`PrecompileCallBinding::{verify_shuffle,verify_leave_dleq,verify_reveal_tokens,verify_reconstruction_v3}`
or on `PrecompileBackendId::NativeBls12381V1`. Those APIs execute native BLS
verification and then expose request/receipt digests; a digest commitment is
not a proof that the cryptographic statement was true.

During migration the legacy BLS route remains readable solely for audit and
historical replay. It must not be labelled host-zero and it must not be used
to advance a Ristretto/AIR table head.

## Versioned boundary

Ristretto cannot be substituted for BLS12-381 in place:

- existing L1 state and Borsh encodings contain 48-byte BLS G1 points;
- Ristretto uses canonical 32-byte encodings;
- all Fiat--Shamir challenges bind those encodings.

The new route must therefore use a distinct `curve_id = Ristretto255`, a new
proof-system/version id, new state/receipt/manifest domains, and a new table
epoch. A verifier must reject a mixture of legacy-BLS and Ristretto/AIR
artifacts in one transition.

## Required in-AIR primitives

The prior `in_air_curve_benchmark` is only an arithmetic lower-bound and is
**not** suitable for this route. The production component needs all of the
following constraints:

1. 8-bit (or lookup-equivalent) canonical limbs for `Fp = 2^255 - 19`, with
   the top limb restricted to 7 bits and `value < p`.
   `src/ristretto_fp_air.rs` now provides the first independently verified
   canonical-limb/range STARK; decode/encode and curve arithmetic still have to
   compose it rather than reusing the arithmetic-only benchmark.
   The subtraction witness is augmented with per-limb nonzero flags and field
   inverses, so equality with `p` is rejected in AIR as well as by the prover.
   `src/ristretto_fp_add_air.rs` composes three such range proofs with a
   limbwise `a + b = c mod p` relation and a one-bit prime-reduction witness.
   Its limb carries are signed values in `{-1, 0, 1}`; each relation consumes
   the previous outgoing carry and emits the current outgoing carry, and the
   raw-sum detector includes the 33rd carry byte before subtracting `p`.
   `src/ristretto_fp_sub_air.rs` composes two verified addition statements to
   prove `a - b = c mod p` through the committed additive inverse `p - b`.
   `src/ristretto_fp_mul_air.rs` proves `a * b = c + q * p` with canonical
   operand/result/quotient limbs, school multiplication, and signed
   range-checked limb carries.  Every non-final limb relation includes both the
   incoming and outgoing signed carry,
   `conv_ab - conv_qp - c + carry_in - 256*carry_out = 0`, so the final limb
   proves that the committed carry chain is exhaustive.
   `src/ristretto_fp_inv_air.rs` composes that multiplication relation to prove
   a committed inverse and, as a consequence, that the input is non-zero.
   `src/ristretto_fp_sqrt_ratio_air.rs` composes verified multiplication
   statements for the exact field semantics of curve25519-dalek
   `sqrt_ratio_i`, including the `0/0`, `u/0`, square, and `i*u/v` nonsquare
   cases.  It is a semantic building block rather than the final performance
   layout: its three multiplication STARKs should later be folded into one
   decode/encode component.
   `src/ristretto_point_decode_air.rs` composes those field relations into the
   exact curve25519-dalek canonical decode equations, binds extended Edwards
   `X/Y/T`, enforces nonnegative `s/X/T`, rejects `Y = 0`, and authenticates
   every intermediate value.  Like `sqrt_ratio_i`, it is a semantic
   host-zero bridge rather than the final performance layout; its component
   STARKs must later be folded into one point codec.
   `src/ristretto_edwards_add_air.rs` composes two decoded canonical points
   with the complete unified extended-Edwards addition formula and authenticates
   every intermediate field value through the verified Fp operations.  It is
   likewise a semantic group-operation bridge, not the eventual single-AIR
   scalar-multiplication/MSM layout.
   `src/ristretto_point_encode_air.rs` composes the exact dalek compression
   equations and both authenticated sign branches, including the identity's
   zero inverse-sqrt edge case, to return a canonical nonnegative 32-byte
   encoding.  Decode, encode, and Edwards addition now form a semantic
   host-zero roundtrip bridge, but still need to be folded into the final
   single point-arith/codec AIR.
   `src/ristretto_scalar_air.rs` provides the matching canonical limb/bit STARK
   for scalars strictly below the Ristretto group order `l`; its nonzero
   subtraction witness is likewise verified in AIR.
   `src/ristretto_fp_program_air.rs` is the first folded performance substrate:
   it places a public DAG of canonical Fp add/sub/mul operations, including all
   limb, strict-range, carry, quotient, and bit witnesses, in one Stwo proof
   instead of composing one STARK per arithmetic operation.  The point codec,
   Edwards arithmetic, scalar multiplication, and MSM components should migrate
   onto this layout before production deployment.
   Its first folded semantic wrapper is `sqrt_ratio_i`: the three multiplication
   statements share one program STARK and one set of canonical-value witnesses.
   On the current development machine, the focused one-proof test ran in 3.58s
   versus 7.93s for the composed implementation.
2. Remaining point-composition relations, including composing decoded points
   with scalar multiplication, Edwards addition, and prime-order quotient
   checks.
3. Extended-Edwards complete addition/doubling formulas, curve membership and
   Ristretto prime-order quotient semantics. AIR internals should retain
   extended coordinates; only request/state boundaries are compressed.
4. Canonical scalar decoding and bit decomposition modulo the Ristretto group
   order, plus fixed-window scalar multiplication / MSM selectors.
5. A circuit hash transcript. Native Merlin or SHA3 output supplied as a
   witness is not acceptable: Fiat--Shamir challenges must be recomputed in
   the AIR. Prefer a versioned Poseidon transcript for the v2 protocol so the
   state/root and proof transcript can share audited AIR gadgets; it changes
   the protocol domain and cannot reuse v1 proofs.
6. Public statement binding. The AIR must either recompute the exact request
   digest or expose the exact canonical request limbs as authenticated public
   input. Merely proving equations for host-projected points leaves a splice
   attack between a ciphertext in state and a point in the trace.

Host code may build witness columns and call `prove`; it may not decide a
branch, provide an unchecked decompression/challenge, or issue a `success`
receipt consumed by a verifier.

## Arithmetic baseline (not an admission circuit)

`examples/in_air_curve_benchmark.rs` is a real Stwo proof/verification harness
for the arithmetic core, but it is intentionally not wired into any admission
path. On the current development machine it measured the following one-row,
power-of-two-padded lower bounds:

| Path | Trace columns | Arithmetic constraints | Prove | Verify |
| --- | ---: | ---: | ---: | ---: |
| Extended Edwards25519 addition | 1,920 | 873 | 144 ms | 214 ms |
| Edwards addition plus Ristretto encode/decode arithmetic | 5,901 | 2,832 | 438 ms | 491 ms |

The Ristretto row constrains only its arithmetic core and an inverse-square
root witness. It deliberately omits limb range and top-bit checks, canonical
compressed-byte validation, sign/select logic, input curve/subgroup checks,
scalar multiplication, DLEQ, and the in-AIR transcript. The numbers are
therefore a planning lower bound, not a production cost claim. They confirm
that retaining extended Edwards coordinates internally and paying the
Ristretto canonical-boundary cost only at request/state edges is the right
optimization direction.

## Blake2b SMT witness boundary

`src/blake2b_smt_witness.rs` fixes the byte-level input ABI for the production
L1's common sparse-Merkle compression shape:

```text
leaf:     Blake2b-256(0x00 || 32-byte key || 32-byte value)
internal: Blake2b-256(0x01 || 32-byte left || 32-byte right)
```

Both are a single final 65-byte block. The witness includes the zero-padded
128-byte block, little-endian 64-bit message words, the Blake2b-256 parameter
word, byte counter `65`, and final-block flag. Its native digest helper is
test-only and is checked against `poker_l1::object_model::SparseMerkleTree`;
it must never be used for admission. This boundary intentionally does **not**
cover the current variable-length hot-table value. A host-zero table epoch
must either prove that multi-block value hash or store an AIR-authenticated,
fixed-size table commitment as its L1 leaf value.

`Blake2bSmtFixedValuePathWitness` then expands such a fixed leaf into exactly
257 AIR compression inputs: one `H(0x00 || key || value)` leaf and 256
`H(0x01 || left || right)` parents. It fixes the L1-specific direction order
(`siblings[0]` is the leaf-level sibling; the first parent reads key bit 255,
and the final parent reads key bit 0) and carries the public root endpoint.
Its intermediate node hashes remain untrusted trace values until the Blake2b
AIR constrains every compression and their final value; this is intentionally
not a native SMT verifier disguised as a witness constructor.

### Blake2b component implementation and state-opening status

The implementation reference is the `blake2b` branch at commit
[`f94a1439b9a7fbb6e93f0b26d68a6725ca588624`](https://github.com/Ztarknet/stwo-cairo/tree/f94a1439b9a7fbb6e93f0b26d68a6725ca588624)
of `Ztarknet/stwo-cairo`. Its [G component](https://github.com/Ztarknet/stwo-cairo/blob/f94a1439b9a7fbb6e93f0b26d68a6725ca588624/stwo_cairo_prover/crates/cairo-air/src/components/blake_2_b_g.rs)
uses 109 trace columns and lookup interactions for byte XOR/range checks; its
round component uses 404 columns and connects eight G invocations through a
relation rather than duplicating a full compression in one row.

This repository currently uses `stwo 2.3.0`, whereas the reference pins Stwo
revision `45d0180`; the files cannot be imported verbatim. The port must retain
this component topology:

```text
u16/byte range + XOR lookup tables
        ↕
Blake2bG relation (8 G calls per round)
        ↕
Blake2bRound relation (12 rounds per compression)
        ↕
fixed 65-byte leaf/internal compression rows
        ↕
256-level sparse-Merkle path linkage
```

The checked-in lookup port now provides the `G` relation, byte-XOR LogUp
table, materialized compression scheduler, fixed-value path ABI, and standard
multi-block Blake2b-256 hashing.  `ArchivedBlake2bLookupHashesProof` batches
independent messages through one G/scheduler/XOR-table proof; every block
counter/final flag is reconstructed by the verifier and all eight chaining
words (not merely the 32-byte digest prefix) are constrained into the next
block.  The 129-byte `0..=128` known-answer regression and a second-half
`h[7]` tamper test cover this boundary.

`canonical_state_hash` uses that batch relation for the exact
`"zchain.texas.canonical-state.v2" || Borsh(CanonicalStateImage)` preimages.
It proves the two endpoint byte preimages against their public commitments
without a native Blake2b call in verification.  It is deliberately not yet an
admission component: the canonical transition AIR binds all fixed-width
endpoint fields but does not yet constrain all VM relations between those
byte images.  The canonical
AIR now binds an 841-limb endpoint projection (the ABI/header,
table/phase/balances/roots, all nine complete seat images including
identity/key/hole-card commitments, and the five board/deck/reveal/
reconstruction/run-it-twice commitments) and Fiat--Shamir-binds the complete
Borsh bytes. Fields known to be unchanged are constrained as such for
ordinary betting, funding, lifecycle and `AdvanceRound` actions. The direct
canonical AIR now also constrains shuffle/reveal/reconstruct pre-phase,
occupied submitter, and a range-bound non-zero proof commitment; its
nonterminal `FoldWithProof` row follows the betting turn, preserves funds and
identity commitments, and permits only the deck commitment to change. Those
are state-machine shape checks, not verification of crypto-bearing
transitions: the DLEQ/shuffle/reveal/reconstruction relations below are still
required.
Thus this hash proof alone cannot bridge a state image to a complete Texas
transition.
`prove_canonical_batch_with_state_image_openings` now combines that proof with
the pre/post fixed-value SMT openings, establishing the complete currently
available `Borsh(image) -> commitment -> L1 root` chain; the missing complete
byte-image-to-VM-transition relation remains explicit.

On the development machine, the two-block generic hash roundtrip took
**133.22 s** and the two canonical endpoint image preimages took **165.28 s**
with one shared batch (the latter regression is ignored in the default suite
because it is an expensive integration check).  These are correctness
measurements, not a final production latency target.

The full 257-compression regression
`fixed_value_smt_path_roundtrip_binds_root_and_siblings` passes in **622.78 s**
on the development machine. This is a correctness baseline, not the final
latency profile; production proving should batch openings and reuse the lookup
table commitment. `canonical_state_opening` uses this shared form for its
pre/post state paths rather than duplicating the lookup proof.

`in_air_blake2b_g_benchmark` provides two deliberately direct baselines:

- default mode proves one G invocation (1,104 columns, 1,392 constraints);
- `--compression` proves all 12 rounds / 96 G calls of one fixed 65-byte L1
  leaf block, including its message, initialized state, counter/final flag
  state words and 32-byte output digest (67,680 columns, 96,064 constraints).

The latter verifies a real full BLAKE2b-256 compression rather than merely a
native digest, and `--tamper-output` demonstrates that changing one public
digest bit invalidates the STARK. It remains a correctness baseline: expanding
the direct decomposition to 257 L1 compressions is not acceptable. The new
`canonical_state_opening` composition binds pre/post `key`, `value`, `root`,
table/hand/call scope, and the fixed state-object epoch to the canonical Texas
archive and receipt. It is an authenticated opening layer; the canonical
state-image commitment preimage and variable-length hot-table object still
require their own AIR before production can claim complete host-zero state
semantics.

Accordingly, `AuthenticatedCanonicalTexasReceipt::admit_canonical_proof_with_state_openings`
is deliberately fail-closed in this revision. The lower-level canonical and
opening verifiers remain usable for audit and regression work, but they cannot
advance a production head until state-image byte/trace binding, complete VM
relations, and the Ristretto relation are composed.

Before the optimized port is admitted anywhere, the fixed ABI has to pass:

- RFC 7693 BLAKE2b-256 known-answer vectors;
- hard-coded L1 leaf and internal-node domain vectors;
- a one-bit change to message, counter, final flag, sigma index, sibling or
  direction bit causing STARK verification failure; and
- a splice test showing that a valid root opening cannot be paired with a
  different canonical transition public scope.

## Route closure matrix

| Existing route | Required Ristretto AIR relation | Extra requirement |
| --- | --- | --- |
| `DleqLeave` | all 52 shared-key DLEQ equations, ciphertext `c1` equality, non-identity checks | v2 transcript binds table/hand/call/epoch |
| `RevealToken` | Chaum--Pedersen equations for every assigned card | assignment indices and encrypted-card openings bind to state root |
| `Shuffle` | full Bayer--Groth relation: permutation, rerandomization, product and multiexponentiation arguments | input/output 52-card vectors bind to deck-state opening |
| `ReconstructionV3` | shuffle plus cross-key, ordered-encryption and every slot-OR relation | reconstruction epoch, contributions and readable-card vectors bind to state root |

Completing just DLEQ does not make shuffle or reconstruction host-zero. A
host-zero manifest must enumerate only the routes for which the corresponding
AIR component and public opening are present; any missing route is fail-closed.

## Proof composition and admission

The preferred first deployment is a separate Ristretto crypto STARK per
transition, verified together with the Texas transition STARK using the same
public statement:

```text
authenticated pre-state opening + canonical Ristretto request
      -> Ristretto crypto AIR proof
      -> Texas transition AIR proof
      -> both bind identical table/hand/seq/pre-root/post-root/manifest/nullifier
      -> finalized immutable receipt inclusion
      -> admission
```

This removes trust in a native crypto result without requiring an in-AIR STARK
verifier on day one. A later recursive aggregator may compress the two STARK
proofs, but recursion is a performance feature, not the source of soundness.
The final admission verifier is allowed to *compute* STARK verification; it
must not trust an unverified host boolean or native receipt.

## Completion gates

Before a v2 route is enabled, tests must demonstrate all of the following:

- a changed compressed point, scalar, ciphertext limb, transcript label,
  context, card index or response rejects the crypto STARK;
- malformed/non-canonical Ristretto encodings and torsion-equivalent Edwards
  representatives reject before arithmetic equations are evaluated;
- prover-controlled challenge, point-coordinate splice and request-digest
  splice attempts reject;
- an old BLS binding, a native `success` receipt or an AIR proof for another
  manifest/epoch cannot satisfy the v2 admission statement;
- the state opening/root relation binds each vector used by the crypto proof
  to the same finalized state as the Texas transition.

Until every applicable row in the matrix passes these gates, the repository is
not host-zero for mental-poker cryptography.
