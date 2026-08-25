# Fuzz targets

This is an intentionally workspace-excluded `cargo-fuzz` package. It is not a
production dependency and is not compiled by the normal release workspace
checks.

Targets:

- `proof_wire`: exercises the strict Ristretto reconstruction proof envelope
  decoder.
- `tx_decode`: exercises the BCS transaction decoder.

Install cargo-fuzz separately, then run optimized harnesses explicitly:

```bash
cargo +nightly install cargo-fuzz
cargo +nightly fuzz run proof_wire --release -runs=10000
cargo +nightly fuzz run tx_decode --release -runs=10000
```

Crashes and corpora belong in CI artifacts or local temporary directories; do
not commit generated artifacts. The targets only parse untrusted bytes and do
not submit transactions, execute contracts, or verify a proof as valid.
