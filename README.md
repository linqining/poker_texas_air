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
- `texas_canonical_air` accepts the fixed-width ABI for all 19 Texas transition
  selectors, and proves batch ordering, state-image links, selector validity,
  table scope, sequence rules, active-prefix padding, and the limited actor policy
  encoded in the AIR.

Neither API yet proves all Texas VM semantics. The canonical AIR now independently
checks canonical-limb arithmetic for `Call` (including short all-in) and unopened-round
`Bet`, but raise/funding/crypto/terminal families, mental-poker proofs, settlement, and
state-root updates remain host-validated until their dedicated AIR components are
implemented. A witness-free Stwo verification result alone must not advance a production
table head.

The complete-state migration starts at [`src/texas_canonical.rs`](src/texas_canonical.rs):
it defines a fixed-width ABI for every VM phase, seat lifecycle, deck/reveal/reconstruction
commitment, run-it-twice state, rules/governance, custody, settlement, and state-root field.
It is currently a structural/commitment boundary; `texas_canonical_air` now binds its
fixed-width trace shape, but selector-specific semantic constraints still need to be
implemented before it replaces the projected betting image.

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
`AuthenticatedCanonicalTexasReceipt::admit_canonical_proof_with_state_openings`
intentionally fails closed today: canonical state-image byte binding, complete
VM semantics, and the Ristretto crypto relation have not yet been composed, so
it must not advance a production host-zero head.

Downstream migration notes are in [`MIGRATION.md`](MIGRATION.md).
