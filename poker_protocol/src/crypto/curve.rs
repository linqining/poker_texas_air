//! Compatibility re-exports for the split protocol crates.
//!
//! New backend/precompile code should depend on `poker-protocol-core`
//! directly. Existing application code can keep using this module.

pub use poker_protocol_core::{
    ec_encrypt_batch_generic, Bls12381Curve, Bls12381ElGamalCiphertext, BlsCompressedPoint,
    CompressedPoint, Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric, RistrettoCurve,
    RistrettoElGamalCiphertext,
};
#[cfg(feature = "stark-curve")]
pub use poker_protocol_core::{StarkCurve, StarkElGamalCiphertext};
