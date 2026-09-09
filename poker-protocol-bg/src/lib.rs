//! Bayer--Groth shuffle backend.
//!
//! The implementation depends only on the curve/transcript interfaces from
//! `poker-protocol-core`. It is currently instantiated on the Stark curve
//! (Plan D 后协议唯一曲线)；the generic backend keeps other compatible
//! backends a recompile away.

mod proof;

#[cfg(feature = "borsh")]
mod borsh_impl;

pub use proof::{BayerGrothShuffleProof, MultiExponentiationArgument, ProductArgument};
