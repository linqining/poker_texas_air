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
cargo test --release --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

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

Short Criterion benchmarks are available with:

```bash
CARGO_TARGET_DIR=target-bench cargo +nightly bench --release -p poker_l1 \
  --bench task36_dag_consensus -- --noplot
CARGO_TARGET_DIR=target-bench cargo +nightly bench --release -p poker_l1 \
  --bench task36_bls_syscall -- --noplot
```

The full hand proving benchmark is intentionally not part of the pull-request
check because it is long-running and hardware-sensitive:

```bash
cargo run --release -p poker-hand-bench
```

When reporting a performance change, include the toolchain, CPU, Rayon thread
count, prove/verify time, proof/archive size, and peak memory where available.
