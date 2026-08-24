#[cfg(feature = "legacy-bls381")]
pub mod crypto;
#[cfg(feature = "legacy-bls381")]
pub mod z_poker;
#[cfg(feature = "legacy-bls381")]
pub mod zk_shuffle;

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

/// Canonical browser-to-Rust proof bundles used by client
/// interoperability checks.
#[cfg(all(feature = "legacy-bls381", feature = "borsh"))]
pub mod browser_proof_bundle;
