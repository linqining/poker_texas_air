# Downstream Migration

`/Users/mac/projects/poker_texas_air` is now the canonical source for the
`poker_texas_air`, `poker_l1`, `vm-common`, and mental-poker protocol crates.
It is a separate Cargo workspace and does not depend on `zchain` or `zgame`.

## Current compatibility boundary

The old copies under `zchain/` and `zgame/proving/` are intentionally retained
while consumers migrate. They are not a second source of truth for new work.
The old `zchain/proving_service` cannot be switched by changing only one path:
it also imports the old `poker_protocol` feature set, whose adapters use the
old `poker_l1` types.

## Migration order

1. Pin this project by commit and make the service depend on its workspace
   crates (`poker_texas_air`, `poker_l1`, `vm-common`, and `poker_protocol`).
2. Port the service's proving adapters to use the same `poker_l1` and
   protocol types as this workspace; mixing crates with the same package
   names from different workspaces is unsafe.
3. Run the service's complete tests and compare serialized proof/task digests
   before removing the old copies.
4. Remove old workspace members and path dependencies only after all consumers
   build from this directory.

The no-transaction-replay migration is independent of this source move. Its
required receipt, proof, and finality changes are described in
[`TRUST_MODEL_NO_TRANSACTION_REPLAY.md`](TRUST_MODEL_NO_TRANSACTION_REPLAY.md).
