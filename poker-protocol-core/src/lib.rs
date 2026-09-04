//! Shared protocol primitives and native curve backends.
//!
//! This crate owns the curve traits, the current Ristretto/BN254/secp256k1
//! implementations plus the Plan D Stark-curve backend ([`stark_curve`]),
//! generic ElGamal, transcript interfaces, and verification errors
//! （BLS12-381/blst 后端已按 2026-09-05 决策移除，不考虑兼容）. It intentionally contains no game state machine, networking code,
//! or chain SDK dependency.

mod backend;
pub mod curve;
#[cfg(feature = "stark-backend")]
pub mod stark_curve;
pub mod error;
pub mod transcript;

#[cfg(feature = "borsh")]
mod borsh_impl;

pub use backend::{
    ec_encrypt_batch_generic, Bn254Curve, Bn254ElGamalCiphertext, BnCompressedPoint,
    CompressedPoint, RistrettoCurve, RistrettoElGamalCiphertext, Secp256k1Curve,
    Secp256k1ElGamalCiphertext, SecpCompressedPoint,
};
#[cfg(feature = "stark-backend")]
pub use stark_curve::{
    handbatch_endorsement_challenge, handbatch_leave_challenge, handbatch_proto_label,
    handbatch_reconstruct_challenge, handbatch_reveal_challenge, handbatch_v1_label,
    PoseidonFeltTranscript, StarkCompressedPoint, StarkCurve, StarkElGamalCiphertext, StarkPoint,
    StarkScalar,
};
pub use curve::{Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric};
pub use error::VerificationError;
pub use transcript::{Challenge, CryptoTranscript};
