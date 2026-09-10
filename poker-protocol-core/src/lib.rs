//! Shared protocol primitives and native curve backends.
//!
//! This crate owns the curve traits, the Plan D Stark-curve backend
//! ([`stark_curve`]——2026-09-05 起协议唯一生产曲线), generic ElGamal,
//! transcript interfaces, and verification errors. 历史 Ristretto/BN254/
//! secp256k1 后端仍作为测试与基准的参照实现保留（BLS12-381/blst 已按
//! 2026-09-05 决策移除，不考虑兼容）. It intentionally contains no game
//! state machine, networking code, or chain SDK dependency.

mod backend;
pub mod curve;
#[cfg(feature = "stark-backend")]
pub mod stark_curve;
#[cfg(feature = "stark-backend")]
pub mod tx_schnorr;
pub mod error;
pub mod transcript;
/// 生产 Fiat–Shamir transcript 域标签（Poseidon epoch，2026-09 迁移）。
pub mod transcript_domains;

#[cfg(feature = "borsh")]
mod borsh_impl;

/// Stark 点/标量 borsh 编解码单一权威（proofs/bg/poker_protocol 复用；
/// 字节布局见 `borsh_impl` 模块文档——32B 压缩点 + 32B 大端标量）。
#[cfg(feature = "borsh")]
pub use borsh_impl::{
    read_stark_point, read_stark_scalar, write_stark_point, write_stark_scalar,
    STARK_POINT_COMPRESSED_LEN, STARK_SCALAR_LEN,
};

pub use backend::{
    ec_encrypt_batch_generic, Bn254Curve, Bn254ElGamalCiphertext, BnCompressedPoint,
    CompressedPoint, RistrettoCurve, RistrettoElGamalCiphertext, Secp256k1Curve,
    Secp256k1ElGamalCiphertext, SecpCompressedPoint,
};
#[cfg(feature = "stark-backend")]
pub use stark_curve::{
    handbatch_endorsement_challenge, handbatch_leave_challenge, handbatch_proto_label,
    handbatch_reconstruct_challenge, handbatch_reveal_challenge, handbatch_v1_label,
    poseidon_bytes_digest, PoseidonFeltTranscript, StarkCompressedPoint, StarkCurve,
    StarkElGamalCiphertext, StarkPoint, StarkScalar,
};
pub use curve::{Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric};
pub use error::VerificationError;
pub use transcript::{Challenge, CryptoTranscript};
