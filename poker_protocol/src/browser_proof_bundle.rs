//! Borsh bundles for browser-generated native mental-poker proofs.
//!
//! These values are deliberately small, self-contained verifier inputs. They
//! are not a chain transaction ABI: Texas still derives the caller and seat
//! from the authenticated client session before constructing a VM command.

use borsh::{BorshDeserialize, BorshSerialize};

use crate::{
    crypto::{DefaultCurve, ECPoint, ElGamalCiphertext, N_CARDS},
    zk_shuffle::{
        error::VerificationError,
        reveal_token_proof::{RevealTokenProof, REVEAL_TOKEN_PROOF_LABEL},
        transcript_ext::{CryptoTranscript, FiatShamirTranscript, MerlinTranscript},
        ShuffleProof,
    },
};

/// Browser-produced Bayer--Groth shuffle data plus every public verifier
/// input. The fixed transcript label matches `ClientPlayer::shuffle`.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct BrowserShuffleV2Bundle {
    pub aggregate_pk: ECPoint,
    pub input_cards: Vec<ElGamalCiphertext>,
    pub output_cards: Vec<ElGamalCiphertext>,
    pub proof: ShuffleProof,
}

impl BrowserShuffleV2Bundle {
    /// Verify the complete shuffle bundle with the production V2 transcript.
    pub fn verify(&self) -> Result<(), VerificationError> {
        if self.input_cards.len() != N_CARDS || self.output_cards.len() != N_CARDS {
            return Err(VerificationError::LengthMismatch);
        }
        let mut transcript = FiatShamirTranscript::new(b"zk_shuffle_proof_v2");
        self.proof.verify(
            &self.input_cards,
            &self.output_cards,
            &self.aggregate_pk.0,
            &mut transcript,
        )
    }
}

/// One browser-produced reveal token and its complete public verification
/// statement. `player_pk` is kept separately so decoding alone cannot turn a
/// proof-carried key into the trusted identity.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct BrowserRevealTokenBundle {
    pub player_pk: ECPoint,
    pub encrypted_card: ElGamalCiphertext,
    pub reveal_token: ECPoint,
    pub proof: RevealTokenProof<DefaultCurve>,
}

impl BrowserRevealTokenBundle {
    /// Verify the token against the independently supplied player key.
    pub fn verify(&self) -> Result<(), VerificationError> {
        let mut transcript = MerlinTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        self.proof
            .verify(
                &self.encrypted_card,
                &self.reveal_token.0,
                &self.player_pk.0,
                &mut transcript,
            )
            .map_err(|_| VerificationError::InvalidRevealToken)
    }
}
