//! poker_protocol — mental-poker 协议门面（Plan D Stark 曲线世界）。
//!
//! 2026-09-05：BLS12-381/blst legacy 构建整体移除（不考虑兼容），
//! `DefaultCurve = StarkCurve`（Cairo 原生 EC_OP 结算路线）。

pub mod crypto;
pub mod zk_shuffle;
pub mod z_poker;

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
#[cfg(feature = "ristretto-air")]
pub mod precompile_abi {
    pub use poker_protocol_abi::*;
}

#[cfg(all(feature = "stark-curve", feature = "borsh"))]
pub mod precompile;

#[cfg(feature = "borsh")]
pub mod borsh_impls;

/// Pure Ristretto255 request construction for the AIR-backed mental-poker
/// epoch.  This module does not expose a native proof verifier.
#[cfg(feature = "ristretto-air")]
pub mod ristretto_air;
