# Texas Tagged Transition AIR

`src/texas_tagged.rs` is the canonical no-replay proving path for the independent
`poker_texas_air` workspace. It accepts a fixed-width `TexasTransitionWitness`
(`pre` state image, one `TexasAction`, and `post` state image), validates the
transition relation, and places all witnesses in one Stwo heterogeneous trace.
The witness-bearing compatibility verifier reconstructs the same trace and
checks its commitment. `verify_tagged_texas_proof` verifies the archived proof
from its public scope alone, without a `ProveTask`, transaction payload, or VM
replay.

## Covered transition

The direct canonical-witness relation deliberately supports a small, explicit
subset of the VM:

- `Fold`, `Check`, `Call`, `Raise`, and `Bet`;
- acting seat equals `pre.current_turn` and was not already acted/folded/all-in;
- call sequence increments by one and table/hand scope remains fixed;
- seat `stack`, `bet`, and `total_bet` conservation;
- action-specific current-bet/min-raise and folded/all-in/acted updates;
- canonical next actionable seat and contiguous batches.
- `Addon` and `Rebuy` for an occupied in-capacity seat, with non-zero checked
  amounts, checked `pending_addon`/`stack` and `chip_pool` updates, and
  `chip_pool <= MAX_TOTAL_BET`;
- `SetLeaveAfterHand`, with an occupied in-capacity seat and exactly one
  canonical mask-bit transition. The VM's idempotent no-op is rejected because
  it cannot be represented as a `call_seq`-incrementing witness.

Action tags use eight one-hot columns. The tagged AIR carries the mid-round
betting selectors directly. Funding rows additionally carry range-checked
pending/stack/vault limbs, ripple carries, and the `MAX_TOTAL_BET` difference;
leave rows carry a complete u16 mask decomposition, a one-hot seat selector, and
the selected-bit flip relation. The canonical state image is still checked by
the host before trace construction, because the trace does not yet open every
seat and root field. The proof API is:

```rust
prove_tagged_texas_batch(&[TexasTransitionWitness])
verify_tagged_texas_batch(&[TexasTransitionWitness], &ArchivedTaggedTexasProof)
verify_tagged_texas_proof(&ArchivedTaggedTexasProof)
```

The migration target is the fixed-width `texas_canonical` ABI. It has explicit fields for the
phase union, lifecycle/status, acted mask, board/deck/reveal/reconstruction commitments,
deadlines, run-it-twice, governance/rules, custody, settlement, and roots, plus all 19 dispatch
transition kinds. Its `validate_shape` and commitment are useful structural checks before the AIR
families are complete; they do not claim that an opaque commitment was recomputed inside Stwo.

For chain admission, call `texas_receipt::authenticate_receipt` and then
`AuthenticatedTexasReceipt::admit_tagged_proof`. The authenticated wrapper is
created only after a historical receipt-mapping inclusion path reaches the
finalized state root at the receipt's block height, the confirmation threshold
is met, and the receipt value commits the complete circuit/manifest/effect/
authority/nullifier statement. This path does not inspect transaction bytes or
call VM dispatch.

Both APIs are independent of `ProveTask`, `MethodBatchV2`, VM dispatch, and
transaction replay. The legacy `tagged_method` and composite paths remain
available for downstream compatibility and retain their existing semantics.

## Explicit non-goals

This AIR does not yet model round advancement, pot collection, timeout
normalization, showdown/deck/reveal, side-pot settlement, or hand-rank
evaluation. Such inputs return `UnsupportedBettingTransition`; they must not be
encoded as a mid-round row.

The Blake2 state-image projections in the trace bind the witness to the proof,
but they are not an in-AIR state-root computation. The witness-free verifier
therefore establishes only the encoded projected relation. A production
no-replay trust model still requires an authenticated state image (or state-root
opening) and an inclusion proof at the finalized consensus height. A
prover-supplied state image without that authenticated anchor remains a
host-attested input, not a trustless chain fact.

The current trace contains only the acting seat's betting fields plus the
funding/leave fields listed above. Full seat-image invariants, the scan for the
next actionable seat, betting carry/range semantics, and authenticated state
root computation are still outside this AIR. Consequently, the witness-free
entry point must not be used as evidence of complete Texas VM execution until
those relations and receipt inclusion are implemented.

The verifier reconstructs nine fixed preprocessed columns for every trace size:
an active-row prefix plus the four 16-bit table limbs, two hand-id limbs, and
two pre-call-sequence limbs. The AIR constrains every witness row to those
columns, and inactive rows to the all-zero suffix. Each active row also carries
the post-call sequence and a binary carry; the AIR enforces
`post_call_seq = pre_call_seq + 1`, including the 16-bit rollover case. This
prevents an all-padding trace and prevents moving a valid row to a different
table, hand, or sequence slot. The scope is still a public projected relation:
a future full transition circuit must bind these values to authenticated state
openings and enforce every row's full state transition.

The required Aleo/Varuna migration is documented in
`TRUST_MODEL_NO_TRANSACTION_REPLAY.md`: immutable transition receipts, complete
pre/post public statements, authority and manifest binding, historical
state-root/receipt inclusion proofs, and coordinator admission from an
`AuthenticatedTransitionReceipt`. Removing replay code before those pieces are
available would replace replay trust with prover/RPC trust rather than remove a
trust assumption.
