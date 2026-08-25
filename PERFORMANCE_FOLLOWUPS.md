# Performance follow-ups

This document records optimization candidates that require protocol-level
soundness work or clean release benchmarks before implementation.

## Dedicated scalar-multiplication AIR

`src/ristretto_fp_program_air.rs` already batches compressed fixed-window scalar
multiplication into one program STARK. The generic projective fixed-window path
still rejects schedules above the operation limit rather than silently proving
an incomplete relation. A dedicated AIR must bind the scalar windows, base,
point table, doubling/addition schedule, identity and zero-scalar cases. Keep
the current implementation as the oracle until a release benchmark and
negative soundness matrix show a net win.

## MSM accumulation tree

`src/ristretto_msm_air.rs` currently uses an ordered accumulation chain. A
balanced tree could reduce dependency depth, but it changes padding, node
indices, archive layout and transcript bindings. Benchmark N = 2, 4, 8, 16,
32, 52 in release mode before changing the wire format; test non-power-of-two
padding and sibling/level tampering.

## Workload-specific limb backend

The 11-bit limb backend is advantageous for production fixed-shape batches but
can regress very small programs because of fixed range-table cost. Establish a
release matrix over rows and operation mix before introducing a protocol-bound
backend selector. The verifier must not choose a local, unbound heuristic.

## Other resource work

- `src/outer_aggregate.rs`: evaluate bounded or streaming child encoding to
  reduce peak memory while preserving digest bytes.
- `src/ristretto_point_decode_air.rs`: isolate the legacy BigUint path or route
  production callers to the current program/fiat-crypto implementation.
- `src/state_root_binding.rs`: consider per-key single-flight after measuring
  concurrent cache misses; preserve deterministic transcript semantics.
- `src/error.rs` and `poker_l1/src/error.rs`: gradually replace generic strings
  with stable categories/source errors, starting at external-input boundaries.
- Metrics currently expose a library/RPC text exporter; the repository has no
  HTTP transport. A native `/metrics` route belongs in the upper-layer server,
  not in the transport-neutral RPC library.

All benchmarks and regression tests for these items must use the pinned nightly
and `--release`; debug proving tests are intentionally excluded because they
are prohibitively slow for this project.
