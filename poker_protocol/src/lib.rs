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

/// BN254 direct-sigma settlement route: canonical card derivation and curve
/// re-exports (DUAL_PROOF_PROTOCOL.md). Curve-independent of protocol
/// features — the sigma proofs themselves live in poker-protocol-proofs.
pub mod bn254_sigma;

/// secp256k1 direct-sigma settlement route (v2.2 production curve): canonical
/// card derivation and curve re-exports; contracts verify via the Starknet
/// EC_OP builtin.
pub mod secp256k1_sigma;

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

/// Per-player unified Σ-protocol (standard settlement proof shape):
/// one proof per player per hand covering ownership + fold + reveals with a
/// single challenge and response. See `poker-protocol-proofs::unified_sigma`.
#[cfg(feature = "legacy-bls381")]
pub mod unified_sigma {
    pub use poker_protocol_proofs::unified_sigma::{
        labels, PlayerHandSigma, UnifiedFoldCard, UnifiedRevealCard, UnifiedSigmaError,
        UnifiedStatement, UNIFIED_SIGMA_PROTOCOL_NAME,
    };
}
