//! Compatibility re-exports for the split protocol crates.
//!
//! New backend/precompile code should depend on `poker-protocol-core`
//! directly. Existing application code can keep using this module.

pub use poker_protocol_core::{
    ec_encrypt_batch_generic, Bn254Curve, Bn254ElGamalCiphertext, BnCompressedPoint,
    CompressedPoint, Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric, RistrettoCurve,
    RistrettoElGamalCiphertext, Secp256k1Curve, Secp256k1ElGamalCiphertext, SecpCompressedPoint,
    StarkCurve, StarkElGamalCiphertext,
};
