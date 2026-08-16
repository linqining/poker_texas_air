pub mod bayer_groth {
    pub use poker_protocol_proofs::bayer_groth::*;
}
pub mod dleq_proof {
    pub use poker_protocol_proofs::dleq_proof::*;
}
pub mod error {
    pub use poker_protocol_proofs::error::*;
}
pub mod generalized_schnorr_proof {
    pub use poker_protocol_proofs::generalized_schnorr_proof::*;
}
pub mod leave_proof {
    pub use poker_protocol_proofs::leave_proof::*;
}
pub mod reconstruction {
    pub use poker_protocol_proofs::reconstruction::*;
}
pub mod remask_proof {
    pub use poker_protocol_proofs::remask_proof::*;
}
pub mod reveal_token_proof {
    pub use poker_protocol_proofs::reveal_token_proof::*;
}
pub mod shuffle_proof {
    pub use poker_protocol_proofs::shuffle_proof::*;
}
pub mod transcript_ext {
    pub use poker_protocol_proofs::transcript_ext::*;
}
pub mod versioned {
    pub use poker_protocol_proofs::versioned::*;
}

pub use poker_protocol_proofs::shuffle_proof::*;
pub use poker_protocol_proofs::versioned::*;

use crate::crypto::DefaultCurve;

/// Production BLS12-381 shuffle proof. V1 values can still be decoded through
/// the enum, but verification is fail-closed for that variant.
pub type ShuffleProof = VersionedShuffleProof<DefaultCurve>;
