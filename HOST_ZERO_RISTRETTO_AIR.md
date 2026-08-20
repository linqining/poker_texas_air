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
   `src/ristretto_scalar_windows_air.rs` composes that strict canonical proof
   with 64 range-checked 4-bit windows and verifies exact reconstruction of the
   public scalar; this is the input ABI for fixed-window scalar multiplication
   and MSM.
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
   The second folded wrapper is canonical point decode.  Its focused test proves
   both identity and basepoint decode in 15.40s, while the prior composed
   implementation takes 63.04s for basepoint decode alone.
   The folded encode wrapper proves identity and basepoint roundtrips in 42.94s;
   the prior composed encode roundtrip takes 247.01s on the same machine.
   The folded unified Edwards addition wrapper proves basepoint doubling in
   28.50s, versus 112.61s for the prior composed addition implementation.
   A general projective variant accepts either a decoded point or a prior
   verified addition output, computes `D=2*Z1*Z2`, and therefore supports the
   continuous accumulator chain required by scalar multiplication.  Its focused
   one-addition test runs in 33.87s.
   The matching projective encode wrapper consumes authenticated `X/Y/Z/T`
   directly, runs the complete dalek compression equations without a host
   affine normalization, and binds the canonical 32-byte output.  It verifies
   basepoint doubling against the standard compressed `2B`, rejects
   output/input/addition splices and noncanonical encodings, and handles a
   scaled identity with `X=0`, `Y=Z`, `T=0`.  The focused
   decode+addition+projective-encode test runs in 81.90s; the scaled-identity
   path runs in 49.00s.
   The `0P..15P` fixed-window table is derived by 14 continuous projective
   additions in one program STARK and exposed as a shared point-table source.
   Its current fixed layout has 376 canonical values and 226 operations.  The
   program derives each multiplication quotient from its strict output and exact
   convolution equation; 236 values retain the generic strict-range witness
   block.  Add/Sub outputs deliberately remain strict-witnessed because their
   modular relations and reduction-sign domains alone do not force the reduced
   representative.  Add/Sub public selectors and reduction signs are constrained,
   so the arithmetic relation cannot be relabeled by prover witness bits.  The
   discarded 154.88s measurement also derived add/sub outputs and is therefore
   not a sound benchmark.  With those strict witnesses restored, the focused
   proof takes 164.17s, down about 13.0% from the original 188.63s layout.
   Multiplication carry/range witnesses remain the dominant cost and should move
   to shared lookup tables in the next specialization.
   The public 16-entry projective-point table selector uses deterministic
   authenticated-table indexing rather than a selector STARK: each distinct table
   entry is verified once, repeated identical entries are cached, and the public
   selector/output are checked directly.  The focused test takes 39.41s,
   dominated by constructing its two folded decode witnesses; selection itself
   adds no STARK.  A private-selector variant will require a dedicated AIR and
   must not reuse the rejected 2048-table-limb layout.
   `prove_ristretto_fp_program_fixed_window_scalar_mul` defines the fixed-window
   scalar-multiplication ABI and reconstructs the complete high-to-low Horner
   DAG from the authenticated scalar windows and `0P..15P` table.  The generic
   Fp program backend deliberately fails closed for this shape today: 64
   windows require 320 projective additions, 5,760 field operations, and 9,222
   committed values, while the generic program is capped at 512 of each.  This
   keeps callers from mistaking an unbounded witness allocation for a production
   proof.  A dedicated doubling/window AIR or lookup schedule must be added
   before this monolithic ABI can produce a scalar-multiplication STARK.
   A proof-producing alternative now uses canonical compressed-point rows:
   15 rows derive `1P..15P`, followed by 64 high-to-low Horner windows with
   four doublings and one selected-table addition each, for 335 equal-shape
   rows total.  `prove_ristretto_fp_program_compressed_fixed_window_scalar_mul`
   places those rows in one batch STARK, while the multi-statement variant
   concatenates several 335-row schedules into one shared batch so DLEQ/OR
   composition need not allocate one STARK per scalar multiplication.  The
   verifier rebuilds the complete row schedule from the authenticated scalar
   windows and rejects base/scalar/output/row-slice/padding splices.  This is a
   sound proof-producing bridge, but the generic compressed codec remains too
   expensive for production until lookup specialization lands.
   `src/ristretto_reconstruction_accumulator_air.rs` now uses one fixed-shape
   field-program row for the complete compressed-point relation: canonical left
   decode, canonical right decode, unified projective Edwards addition, and
   projective Ristretto encode.  Its branch choices are represented by
   constrained 0/1 selectors, so valid points with different sign branches
   still share one operation/output layout.  The fixed 52-card archive places
   all 104 equations in one dynamic-row STARK in the exact order
   `card0.c1, card0.c2, ..., card51.c2`, rather than storing 104 independent
   point-proof chains.  The transcript binds the effective row count even when
   the power-of-two padding row equals the final public row.  Verification
   rejects prior/contribution/post splices, c1/c2 swaps, card swaps,
   noncanonical points, wrong arithmetic rows, and padding-count relabeling,
   and can bind a non-initial accumulator to the lookup-authenticated canonical
   pre-state opening plus the exact Reconstruction V3 contribution vector.  A
   second reconstruction opening is included in the same Blake2b lookup batch:
   it clears exactly the selected pending bit, preserves epoch/key/seat/readable
   data, stores the proven post accumulator, and hashes to
   `post.reconstruction_commitment`.  Non-final reconstruction also preserves
   the encrypted deck commitment in both native canonical validation and the
   direct canonical AIR, matching the VM update order.
   A two-row `identity+B` / `B+B` focused proof runs in 27.58s.  The complete
   104-row reconstruction fixture proves and checks all splice cases in
   723.78s on the current development machine.  This is a major archive-count
   reduction but remains a heavy generic Fp layout; multiplication witnesses
   still need lookup-backed specialization for production latency.
   The first contribution now uses one additional equal-shape 156-row batch:
   rows `0..51` prove `1G..52G`, rows `52..103` prove `1PK..52PK`, and rows
   `104..155` prove `card_i + (i+1)PK`.  The card vector is verifier-fixed to
   the ordered Ristretto points `hash_to_curve("texas_poker/card/{i}")`.  An
   absent pre-accumulator requires this archive and a zero opening deck; a
   present pre-accumulator forbids it.  Structural splice tests pass, while a
   full 156-row proof remains unbenchmarked on the generic Fp backend.
   Final reconstruction still fails closed until the accumulated deck is bound
   to the rebuilt encrypted deck commitment and the reconstruct-shuffle
   transition.
   The Ristretto V3 request no longer accepts an arbitrary non-empty proof byte
   string at this boundary. Its `proof` field is a canonical `ZR3P/v1` envelope
   with exactly one shuffle component, two cross-key components, and 52 slot-OR
   components. The envelope authenticates a domain-separated digest of every
   public request field (excluding the envelope itself), its component
   count/order, and an independent component digest. Therefore a proof
   component or whole envelope cannot be copied to a request with a different
   key, epoch, readable ciphertext, contribution, card, or call scope. This is
   a wire/statement binding only: it deliberately does **not** treat the
   component payloads as valid until the Poseidon transcript, cross-key,
   slot-OR, and Bayer--Groth AIR verifiers consume them.
   `src/ristretto_reconstruction_relation_air.rs` now adds a request-bound
   cross-key composition archive for exactly two readable cards. It derives
   each equation statement from the validated request and `ZR3P` envelope,
   verifies statement-digest/order/key/ciphertext/proof-field binding, and
   then verifies its fixed-shape scalar-multiplication and point-addition AIR
   batches. Its `RistrettoCrossKeyTranscriptChallenges` input is deliberately
   only the typed output interface for a future Poseidon252 transcript AIR;
   host-generated challenges remain insufficient for admission. The matching
   `ristretto_scalar_add_air.rs` proves challenge-share addition modulo the
   Ristretto group order, and `ristretto_reconstruction_slot_or_air.rs` now
   composes each slot-OR relation with eight scalar multiplications and five
   ordered point additions. Its 52-slot archive binds the complete slot/card/
   contribution/proof order to `ZR3P`; its global challenge array remains only
   a typed output from the future transcript AIR. Shuffle, transcript
   recomputation, and final production composition are still incomplete and
   fail closed.
   `src/ristretto_reconstruction_transcript.rs` now fixes that future
   component's protocol ABI: a distinct v1 domain absorbs every request byte
   as labelled, length-prefixed 16-byte little-endian field chunks (not merely
   the `ZR3P` Blake2b digest), then emits challenges in the fixed order
   `cross_key[0..2)`, shuffle wire, and `slot_or[0..52)`.  Each cross-key
   challenge absorbs its negative contribution and three Sigma commitments;
   each slot challenge absorbs its canonical slot ordinal and four Sigma
   commitments.  The module also reserves a per-challenge nonzero retry count.
   It is a statement/schedule specification only: it performs no native
   Poseidon calculation and is not an AIR wrapper or an admission credential.
   It also emits a rate-two sponge operation schedule, fixing full-block
   permutations and the `+1` finalization lane for every squeeze so the AIR
   cannot choose a different padding boundary.
   The typed challenge boundary now also rejects detached digests, zero or
   non-canonical Ristretto scalars, and retry counters above the fixed bound
   before any relation archive consumes it.  This remains a shape/range gate,
   not transcript authentication; only a future Poseidon permutation AIR can
   authenticate the challenge bytes.
   `src/ristretto_reconstruction_composition.rs` now packages the available state binding,
   accumulator, cross-key, and 52 slot-OR archives under one request/envelope/transcript scope,
   rejecting component and slot-order splices before child AIR verification. This is an audit
   composition only: its admission-shaped API verifies the available pieces and then returns
   `HostZeroAdmissionIncomplete` until Poseidon permutation/retry and Bayer--Groth shuffle AIRs
   are present.
2. Remaining proof composition, especially Bayer--Groth shuffle equations,
   Poseidon252 transcript recomputation for the now-composed cross-key and
   slot-OR equations, and prime-order quotient checks.
3. Extended-Edwards complete addition/doubling formulas, curve membership and
   Ristretto prime-order quotient semantics. AIR internals should retain
   extended coordinates; only request/state boundaries are compressed.
4. Canonical scalar decoding and bit decomposition modulo the Ristretto group
   order are implemented.  The old monolithic fixed-window backend continues
   to fail closed on the 5,760-operation shape; the new compressed 335-row
   single/batched backend is proof-producing and structurally tested.  The
   remaining production work is lookup-specialized doubling/window arithmetic,
   private selectors where needed, and DLEQ/MSM composition.
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
AIR now binds an 852-limb endpoint projection (the ABI/header and five
range-checked immutable timeout durations,
table/phase/balances/roots, all nine complete seat images including
identity/key/hole-card commitments, and the five board/deck/reveal/
reconstruction/run-it-twice commitments plus the protocol pending mask) and Fiat--Shamir-binds the complete
Borsh bytes. Fields known to be unchanged are constrained as such for
ordinary betting, funding, lifecycle and `AdvanceRound` actions. The direct
canonical AIR now also constrains shuffle/reveal/reconstruct pre-phase,
occupied submitter, and a range-bound non-zero proof commitment; its
ABI-v5 pending-mask relation proves a non-final submit clears exactly the
submitting seat and leaves at least one pending participant. Final submit
phase changes remain fail-closed until their complete timeout/schedule/
betting-initialization openings are present; no host-provided completion flag
is accepted. Betting time-bank and `AutoFold` deadline arithmetic now consume
the opened `betting_timeout_ms`, rather than a hard-coded deployment default. Its
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

Accordingly, `AuthenticatedCanonicalTexasReceipt::admit_canonical_proof` and
`AuthenticatedCanonicalTexasReceipt::admit_canonical_proof_with_state_openings`
are deliberately fail-closed in this revision. The lower-level
`verify_canonical_proof` and opening verifiers remain usable for audit and
regression work, but they cannot advance a production head until state-image
byte/trace binding, complete VM relations, and the Ristretto relation are
composed.

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
