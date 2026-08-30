# Local patches carried by third_party/proving

Upstream: https://github.com/starkware-libs/proving, vendored at upstream
commit `dd1787b`. All patches below are local modifications made by this
repository to support the poker `proved`-settlement pipeline; the upstream
stack remains Apache-2.0 (StarkWare Ltd.).

| Patch | Location | Motivation |
|---|---|---|
| Gas-disabled Cairo1 compile config (`gas=disabled` + `skip_auto_withdraw_gas`) | `crates/prover/src/cairo1_compile.rs` | Poker hand-verify programs are pure compute; gas accounting is unnecessary and changes the execution trace. |
| `adapt_with_context` + `PublicSegmentContext` entrypoint builtins | adapter crate | Lets the host inject public segment entrypoints for the hand-batch bench programs without forking the adapter API. |
| `trace_exec.rs` debugger | `crates/runner` (cairo-vm side) | Step-through debugging of witness generation while developing new Cairo circuits. |
| hand-verify bench programs | `crates/bench` area | The default `proved` program models the hand-verify sigma batch (Poseidon + EC ops on the STARK curve); it is a stand-in until the real `hand_verify.cairo` from `poker_contracts/dual/` is wired in. |

Toolchain note: this stack requires `nightly-2026-01-15`
(`portable_simd`, `iter_array_chunks`, `raw_slice_split` in
`stwo-cairo-prover`). `proving-tool/` is a standalone workspace with its own
`rust-toolchain.toml` so the pin never leaks into the main workspace.

Reference numbers (from proving-tool measurements): 43,752 steps ≈ 10 s
prove (small program); 438,607 steps ≈ 29 s (full hand); proof size ≈ 14 MB
JSON / 1.5 MB binary (96-bit security params: blake2s channel, FRI pow 26,
blowup 1, 70 queries).
