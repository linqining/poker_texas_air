# Independent Project

This workspace is the extracted `poker_texas_air` project. It includes the minimal L1/VM and
mental-poker protocol crates required to build the AIR crate without the `zchain` or `zgame`
workspace. The source snapshot was extracted from `zchain` commit `6226b84`; legacy copies remain
in place until downstream consumers migrate.

The no-transaction-replay trust boundary is documented in
[`TRUST_MODEL_NO_TRANSACTION_REPLAY.md`](TRUST_MODEL_NO_TRANSACTION_REPLAY.md).
The separate Ristretto255 migration that removes the legacy native crypto
precompile as an admission trust boundary is specified in
[`HOST_ZERO_RISTRETTO_AIR.md`](HOST_ZERO_RISTRETTO_AIR.md). The currently
checked-in BLS precompile bindings are legacy host-attested compatibility
paths, not host-zero proofs.

The direct state-transition proving paths are documented in
[`TEXAS_TAGGED_AIR.md`](TEXAS_TAGGED_AIR.md). They are independent from the legacy
`ProveTask`/transaction-replay path:

- `texas_tagged` is the existing fail-closed projected AIR for mid-round betting,
  addon, rebuy, and leave-after-hand transitions.
- `texas_canonical_air` accepts the fixed-width ABI for all 21 Texas transition
  selectors, and proves batch ordering, state-image links, selector validity,
  table scope, sequence rules, active-prefix padding, and the limited actor policy
  encoded in the AIR.

Neither API yet proves all Texas VM semantics. The canonical AIR now independently
constrains the fixed relations for `Call` (including short all-in), `Raise`, `Bet`, funding,
join/leave, force/kick, `SetLeaveAfterHand`, `AdvanceRound`, bounded betting time-bank extension,
the non-cascading `AutoFold` timeout suffix, and the final `SubmitReconstruct` normalization from
reconstruct collection back to shuffle collection. Shuffle/reveal/reconstruction cryptography,
the final shuffle/reveal phase changes, full timeout/terminal cascades, mental-poker proofs,
settlement, and state-root recomputation remain outside the AIR until their dedicated components
are implemented. A witness-free Stwo verification result alone must not advance a production
table head.

The complete-state migration starts at [`src/texas_canonical.rs`](src/texas_canonical.rs):
it defines a fixed-width ABI for every VM phase, seat lifecycle, deck/reveal/reconstruction
commitment, run-it-twice state, rules/governance, custody, settlement, and state-root field.
ABI v5 carries the fixed nine-seat protocol pending mask used by shuffle,
reveal, and reconstruction, plus the VM's five immutable timeout durations.
`texas_canonical_air` range-checks those timeout limbs and derives betting
time-bank/auto-fold arithmetic from the opened `betting_timeout_ms` instead of
a deployment constant. It proves each non-final protocol
submit clears exactly the submitting seat's bit and cannot forge a final submit;
the final reconstruct submit is additionally bound to a canonical completion opening containing
an authenticated consensus timestamp, checked shuffle deadline addition, deck cursor reset,
active-seat pending-mask rebuild, and the suspended reveal/deck/reconstruction commitments. The
completion decision is derived from the pre pending mask rather than `action.flag`. Final shuffle
and reveal submissions remain fail-closed, and the reconstruct Ristretto equations plus
deck/reveal commitment recomputation are not yet composed. The direct reconstruction route now
also has a no-replay request scope and a fixed-width table-wide Ristretto reconstruction-state
opening. One shared lookup-backed Blake2b batch authenticates both the pre and non-final post
reconstruction commitments, canonical context/prior-state digests, encoded request digest,
endpoint state images, and the request-free crypto scope. It binds epoch, aggregate/owner keys, two
readable hole cards, the exact cleared pending bit, and immutable table-wide reconstruction data to
the selected pending seat. The folded Ristretto path now also proves authenticated projective-point
compression and batches the complete canonical decode + Edwards add + projective encode relation.
Its fixed 52-card accumulator archive contains one 104-row STARK in canonical
`card0.c1, card0.c2, ..., card51.c2` order, binds non-initial prior accumulators to that pre-opening
and the exact request contributions, binds the proven post accumulator into the authenticated post
opening, and rejects row/card/ciphertext/opening splices. The initial path is now derived by a
second equal-shape 156-row batch in fixed order: `1G..52G`, `1PK..52PK`, then
`card_i + (i+1)PK`. The cards are verifier-fixed as the ordered Ristretto points
`hash_to_curve("texas_poker/card/{i}")`; the initial archive is mandatory exactly when the state
opening says no accumulator exists, and its derived deck must equal the first accumulator prior.
The final reconstruction-to-deck/shuffle path remains deliberately rejected until its dedicated
AIR relations land. The generic Fp batch is
still performance-heavy and requires lookup specialization before production admission. The ABI is still a
structural/commitment boundary; `texas_canonical_air` now binds its
fixed-width trace shape, but selector-specific semantic constraints still need to be
implemented before it replaces the projected betting image.

The Ristretto backend also now has a proof-producing compressed fixed-window scalar
multiplication route. It derives `1P..15P` in 15 rows and evaluates 64 four-bit Horner windows in
320 more rows, all with the same compressed-addition shape. Multiple scalar multiplications can
share one concatenated batch STARK, which is the intended substrate for cross-key and slot-OR
equations. The older 5,760-op monolithic generic program remains deliberately fail-closed; the
335-row bridge is sound but still needs lookup specialization before production use.

Ristretto Reconstruction V3 requests now require a strict `ZR3P/v1` public proof envelope rather
than accepting arbitrary proof bytes. It fixes the required component cardinality to one shuffle,
two cross-key, and 52 slot-OR payloads, and binds their ordered bytes to the complete public
request statement. This prevents proof-byte and component splices but is deliberately not a
substitute for the pending Poseidon transcript or Bayer--Groth AIR checks. The two cross-key
linear relations and the per-slot OR equations now have request/envelope-bound AIR archives.
Every slot archive fixes eight scalar multiplications, five point additions, and
`challenge[0] + challenge[1] = global_challenge (mod l)` using a dedicated group-order scalar
AIR rather than the Ristretto base field. Their challenges remain typed inputs from the future
Poseidon transcript AIR rather than trusted host values; production admission remains fail-closed.
`ristretto_reconstruction_transcript` now fixes the separate protocol transcript ABI: it absorbs
the full request as labelled/length-prefixed 16-byte field chunks, then binds cross-key
commitments, the shuffle wire, and ordered slot-OR commitments before their corresponding
challenge slots. This specification is intentionally not a native-Poseidon wrapper; the
permutation, scalar reduction, and nonzero-retry relations still need direct AIR constraints.
It emits the exact rate-two absorb/permute/squeeze schedule (including the Starknet `+1`
finalization lane for each challenge), so a future AIR cannot choose a different padding boundary.
Its typed challenge boundary nevertheless rejects detached digests, zero/non-canonical `mod l`
scalars, and retry counters above the fixed bound before relation archives consume them; this is
only a range/shape gate and does not authenticate host-provided challenges.

`ristretto_reconstruction_composition.rs` packages the implemented state binding, 52-card
accumulator, cross-key, and 52 slot-OR archives under one request/envelope/transcript scope. It
rejects statement, component, transcript, and slot-order splices before running child verifiers.
The audit verifier is not a complete V3 credential; its admission-shaped API remains fail-closed
until the Poseidon permutation/retry and Bayer--Groth shuffle AIRs are composed.

The canonical action ABI is also fail-closed against unused payload smuggling: ordinary VM
selectors require zero proof commitments, zero auxiliary/amount fields unless their VM method
actually consumes them, zero legacy flags outside `set_leave_after_hand`, zero deadline advice
outside permissionless timeout rows, and the no-seat sentinel for seatless lifecycle micro-steps.
These checks exist both in `CanonicalTransitionWitness::validate_shape` and in the direct AIR.

That witness-free boundary is not yet a complete chain trust boundary. The
workspace now exposes `authenticate_receipt` and
`AuthenticatedTexasReceipt::admit_tagged_proof`, which require an immutable
receipt, complete statement binding, and a finalized receipt/state-root
inclusion proof before admission. Full pre/post state-root AIR and complete VM
semantics remain tracked in `TRUST_MODEL_NO_TRANSACTION_REPLAY.md`.

For the real L1 state tree, use `authenticate_receipt_l1` with
`TexasL1ReceiptInclusionProof`. It verifies the 256-level
`poker_l1::object_model::SparseMerkleTree` path directly. The older
`TexasReceiptInclusionProof` is a generic compatibility ABI, not a chain adapter.

For the fixed-width state-opening audit path, use
`canonical_state_opening::prove_canonical_batch_with_state_openings` and its
verifier. The composition verifies its pre/post 257-compression Blake2b paths
in one shared lookup batch and rejects key/value/root/epoch splices.
`AuthenticatedCanonicalTexasReceipt::admit_canonical_proof` and
`AuthenticatedCanonicalTexasReceipt::admit_canonical_proof_with_state_openings`
intentionally fail closed today: canonical state-image byte binding, complete
VM semantics, and the Ristretto crypto relation have not yet been composed, so
neither method can advance a production host-zero head. Use
`verify_canonical_proof` for structural audit and regression checks.

Downstream migration notes are in [`MIGRATION.md`](MIGRATION.md).
