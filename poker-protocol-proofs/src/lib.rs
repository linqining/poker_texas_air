//! Complete curve-generic proof suite used by the mental-poker protocol.
//!
//! This crate contains the proofs used across every game phase: public-key
//! ownership, shuffle, remask, leave, reveal-token, reconstruction and
//! swap-out. It contains no poker table state machine, network code, chain SDK
//! or STWO dependency.

pub mod bayer_groth {
    pub use poker_protocol_bg::{
        BayerGrothShuffleProof, MultiExponentiationArgument, ProductArgument,
    };

    #[cfg(test)]
    mod tests;
}
pub mod dleq_proof;
pub mod error;
pub mod generalized_schnorr_proof;
pub mod leave_proof;
pub mod pk_ownership;
pub mod reconstruction;
pub mod remask_proof;
pub mod reveal_token_proof;
pub mod shuffle_proof;
pub mod transcript_ext;
pub mod unified_sigma;
pub mod versioned;

#[cfg(feature = "borsh")]
mod borsh_impl;

pub use poker_protocol_core::{Challenge, CryptoTranscript, VerificationError};
pub use shuffle_proof::*;
pub use versioned::*;
