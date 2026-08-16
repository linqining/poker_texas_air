# Independent Project

This workspace is the extracted `poker_texas_air` project. It includes the minimal L1/VM and
mental-poker protocol crates required to build the AIR crate without the `zchain` or `zgame`
workspace. The source snapshot was extracted from `zchain` commit `6226b84`; legacy copies remain
in place until downstream consumers migrate.

The no-transaction-replay trust boundary is documented in
[`TRUST_MODEL_NO_TRANSACTION_REPLAY.md`](TRUST_MODEL_NO_TRANSACTION_REPLAY.md).

The direct state-transition proving path is documented in
[`TEXAS_TAGGED_AIR.md`](TEXAS_TAGGED_AIR.md). It is independent from the legacy
`ProveTask`/transaction-replay path. It currently covers fail-closed mid-round
betting plus canonical-witness addon, rebuy, and leave-after-hand transitions.
`verify_tagged_texas_proof` can verify an archive without a witness or replay,
but only proves the projected relation encoded by the current AIR.

The complete-state migration starts at [`src/texas_canonical.rs`](src/texas_canonical.rs):
it defines a fixed-width ABI for every VM phase, seat lifecycle, deck/reveal/reconstruction
commitment, run-it-twice state, rules/governance, custody, settlement, and state-root field.
It is currently a structural/commitment boundary; the selector-specific AIR constraints still
need to be implemented before it replaces the projected betting image.

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

Downstream migration notes are in [`MIGRATION.md`](MIGRATION.md).
