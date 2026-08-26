#[cfg(feature = "legacy-bls381")]
pub mod crypto;
#[cfg(feature = "legacy-bls381")]
pub mod z_poker;
#[cfg(feature = "legacy-bls381")]
pub mod zk_shuffle;

/// Pure Ristretto255 request construction for the AIR-backed mental-poker
/// epoch.  This module does not expose a native proof verifier.
#[cfg(feature = "ristretto-air")]
pub mod ristretto_air;

/// Stable request/response boundary for STWO foreign calls and chain
/// precompile adapters.
#[cfg(any(feature = "legacy-bls381", feature = "ristretto-air"))]
pub mod precompile_abi {
    pub use poker_protocol_abi::*;
}

#[cfg(all(feature = "legacy-bls381", feature = "borsh"))]
pub mod precompile;

#[cfg(all(feature = "legacy-bls381", feature = "borsh"))]
pub mod borsh_impls;

/// Canonical browser-to-Rust proof bundles used by client
/// interoperability checks.
#[cfg(all(feature = "legacy-bls381", feature = "borsh"))]
pub mod browser_proof_bundle;
