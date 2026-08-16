#[cfg(feature = "legacy-bls381")]
pub mod crypto;
#[cfg(feature = "legacy-bls381")]
pub mod z_poker;
#[cfg(feature = "legacy-bls381")]
pub mod zk_shuffle;

/// Aleo-native mental-poker protocol. This module deliberately uses the same
/// BLS12-377 `group` and `scalar` values as the Varuna settlement witness so
/// browser/WASM data can be decoded by the proving service without a foreign
/// curve conversion.
#[cfg(feature = "borsh")]
pub mod aleo_protocol;

/// Stable request/response boundary for STWO foreign calls and chain
/// precompile adapters.
#[cfg(feature = "legacy-bls381")]
pub mod precompile_abi {
    pub use poker_protocol_abi::*;
}

#[cfg(all(feature = "legacy-bls381", feature = "borsh"))]
pub mod precompile;

#[cfg(all(feature = "legacy-bls381", feature = "borsh"))]
pub mod borsh_impls;

/// Canonical browser-to-Rust proof bundles used by the Aleo-native client
/// interoperability checks.
#[cfg(all(feature = "legacy-bls381", feature = "borsh"))]
pub mod browser_proof_bundle;
