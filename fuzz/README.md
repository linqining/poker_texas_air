# Fuzz targets

This is an intentionally workspace-excluded `cargo-fuzz` package. It is not a
production dependency and is not compiled by the normal release workspace
checks.

Targets:

- `settlement_statement`: decodes and validates the untrusted-byte settlement
  privacy statement — a decode/validate error is a valid outcome, a panic or
  out-of-bounds access is the bug.
- `digest_felts`: exercises the aggregate-digest double-felt split/merge — any
  32-byte input pair must not panic, and canonical inputs must round-trip
  split→merge.

Install cargo-fuzz separately, then run optimized harnesses explicitly:

```bash
cargo +nightly install cargo-fuzz
cargo +nightly fuzz run settlement_statement --release -runs=10000
cargo +nightly fuzz run digest_felts --release -runs=10000
```

Crashes and corpora belong in CI artifacts or local temporary directories; do
not commit generated artifacts. The targets only parse untrusted bytes and do
not submit transactions, execute contracts, or verify a proof as valid.
