//! Shared protocol primitives and native curve backends.
//!
//! This crate owns the curve traits, the current Ristretto/BLS12-381
//! implementations, generic ElGamal, transcript interfaces, and verification
//! errors. It intentionally contains no game state machine, networking code,
//! or chain SDK dependency.

mod backend;
pub mod curve;
pub mod error;
pub mod transcript;

#[cfg(feature = "borsh")]
mod borsh_impl;

pub use backend::{
    ec_encrypt_batch_generic, Bls12381Curve, Bls12381ElGamalCiphertext, BlsCompressedPoint,
    CompressedPoint, RistrettoCurve, RistrettoElGamalCiphertext,
};
pub use curve::{Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric};
pub use error::VerificationError;
pub use transcript::{Challenge, CryptoTranscript};
