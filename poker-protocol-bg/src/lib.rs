//! Bayer--Groth shuffle backend.
//!
//! The implementation depends only on the curve/transcript interfaces from
//! `poker-protocol-core`. It can therefore be instantiated by BLS12-381 today,
//! BLS12-377 in a precompile host, or another compatible backend later.

mod proof;

#[cfg(feature = "borsh")]
mod borsh_impl;

pub use proof::{BayerGrothShuffleProof, MultiExponentiationArgument, ProductArgument};
