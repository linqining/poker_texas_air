# Contributing

## Toolchain

This workspace uses the pinned nightly toolchain in `rust-toolchain.toml`. Stwo
requires nightly features, so run Cargo commands from the repository root. The
workspace intentionally excludes `third_party/flock`; that vendored project has
its own checks.

## Required checks

Before opening a change, run the checks relevant to the code you touched:

```bash
git diff --check
cargo check --release --workspace --lib --bins
cargo test --release --workspace -- --include-ignored
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

## Test layering

`cargo test` is a fast dev loop: multi-second prove roundtrip tests are marked
`#[ignore = "slow prove (~Ns); full gate runs `--include-ignored`"]` and are
skipped by default. Three layers:

| Layer | Command | What runs |
| --- | --- | --- |
| Dev loop | `cargo test` | everything except the ignored slow prove tests |
| Dev loop, this workspace only | `cargo test-fast` | same, skipping vendored flock's own unit tests |
| Full gate (pre-merge) | `cargo test-all` (or `cargo test --workspace -- --include-ignored`) | every test, including the slow prove roundtrips |

CI's `Workspace tests` job and the weekly coverage job run the full gate, so
the ignored tests stay covered; do not delete an `#[ignore]` to "fix" a slow
run — file the slowness instead. Tests for code under active development
(e.g. `poseidon252_air_component`) are deliberately NOT ignored: they stay in
the default loop so failures surface immediately.

The root crate's untrusted test helpers are only used in the release
integration-test harness below. Do not run the heavyweight proof suite in debug
mode; it is substantially slower on this project.

For the deliberate release integration-test harness, opt into the explicit
configuration while keeping the release guard enabled:

```bash
RUSTFLAGS='--cfg=texas_release_tests' \
  cargo test -p poker_texas_air --release --features test-helpers --tests
```

Do not enable `test-helpers` in a production release build. The crate rejects
that configuration unless it is a test artifact or the explicit release-test
configuration above is present.

## Benchmarks

Performance baselines live in `docs/plan_d_perf.md` (post-Plan-D release
numbers; the repro commands are in `poker-protocol-proofs/tests/plan_d_perf.rs`).
Run them with:

```bash
cargo +nightly test --release -p poker-protocol-proofs --test plan_d_perf -- --nocapture
```

(The former `poker_l1` Criterion benches — `task36_dag_consensus`,
`task36_bls_syscall` — were removed with the chain-machinery and BLS cleanup
in 2026-09.)

The full hand proving benchmark is intentionally not part of the pull-request
check because it is long-running and hardware-sensitive:

```bash
cargo run --release -p poker-hand-bench
```

When reporting a performance change, include the toolchain, CPU, Rayon thread
count, prove/verify time, proof/archive size, and peak memory where available.
