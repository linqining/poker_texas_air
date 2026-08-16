//! Regression for the consensus crypto-verification production gate.
//!
//! Integration tests link `poker_l1` as a normal dependency, so `cfg(test)` is
//! not set inside the library. The compile-time unit-test bypass must therefore
//! be disabled in this build mode, with no state-carried flags available.

use poker_l1::vm::contracts::texas_poker::utils::test_only_crypto_skip;

#[test]
fn crypto_skip_is_compile_time_disabled_outside_crate_unit_tests() {
    assert!(!test_only_crypto_skip());
}
