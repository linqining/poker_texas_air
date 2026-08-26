//! Ristretto255 request construction for the AIR-backed Texas mental-poker
//! protocol.
//!
//! This module intentionally contains no native Bayer--Groth, DLEQ, or
//! reconstruction verifier.  A client uses it to create the exact public
//! 52-card statement and attaches an AIR proof package.  The server must pass
//! that package to `poker_texas_air`'s Ristretto AIR admission boundary; an ABI
//! shape check is not proof verification.

use poker_protocol_abi::{
    AbiError, CurveId, EncodedCiphertext, ReconstructionProofSystem, ReconstructionV3VerifyRequest,
    ShuffleProofSystem, ShuffleVerifyRequest, TranscriptId, RECONSTRUCTION_V3_STATEMENT_VERSION,
    RISTRETTO_AIR_DECK_SIZE, RISTRETTO_AIR_RECONSTRUCTION_READABLE_CARDS,
};
use poker_protocol_core::{
    Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric, RistrettoCurve,
    RistrettoElGamalCiphertext,
};

/// Number of canonical cards in the Ristretto Texas protocol.
pub const RISTRETTO_TEXAS_DECK_SIZE: usize = RISTRETTO_AIR_DECK_SIZE;
/// Number of owner-readable cards carried by one reconstruction V3 request.
pub const RISTRETTO_TEXAS_RECONSTRUCTION_READABLE_CARDS: usize =
    RISTRETTO_AIR_RECONSTRUCTION_READABLE_CARDS;
/// Fixed proof context for a Ristretto shuffle AIR request.
pub const RISTRETTO_AIR_SHUFFLE_CONTEXT: &[u8] = b"poker/ristretto-air/shuffle/v1";
/// Domain for the V2 fixed-shape batch shuffle schedule.
pub const RISTRETTO_AIR_V2_SHUFFLE_CONTEXT: &[u8] = b"poker/ristretto-air/shuffle/v2";
/// Fixed proof context for a Ristretto reconstruction V3 AIR request.
///
/// The byte label is retained while the protocol is migrated because the AIR
/// statement additionally binds `curve`, `proof_system`, and `transcript`.
/// It is not accepted by the native BLS verifier for a Ristretto request.
pub const RISTRETTO_AIR_RECONSTRUCTION_V3_CONTEXT: &[u8] = b"zk_reconstruct_proof_v3";
/// Domain for the V2 batched reconstruction schedule.
pub const RISTRETTO_AIR_V2_RECONSTRUCTION_CONTEXT: &[u8] = b"poker/ristretto-air/reconstruction/v2";

/// Canonically encoded Ristretto ElGamal ciphertext for an AIR public input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RistrettoAirCiphertext {
    /// Canonical compressed Ristretto `c1` point.
    pub c1: [u8; 32],
    /// Canonical compressed Ristretto `c2` point.
    pub c2: [u8; 32],
}

impl RistrettoAirCiphertext {
    /// Encode this fixed-width ciphertext for the stable proof ABI.
    #[must_use]
    pub fn to_abi(self) -> EncodedCiphertext {
        EncodedCiphertext {
            c1: self.c1.to_vec(),
            c2: self.c2.to_vec(),
        }
    }

    /// Decode one width-checked proof-ABI ciphertext.
    pub fn from_abi(value: &EncodedCiphertext) -> Result<Self, RistrettoAirSubmissionError> {
        Ok(Self {
            c1: value
                .c1
                .as_slice()
                .try_into()
                .map_err(|_| RistrettoAirSubmissionError::InvalidPointEncoding)?,
            c2: value
                .c2
                .as_slice()
                .try_into()
                .map_err(|_| RistrettoAirSubmissionError::InvalidPointEncoding)?,
        })
    }
}

impl From<&RistrettoElGamalCiphertext> for RistrettoAirCiphertext {
    fn from(value: &RistrettoElGamalCiphertext) -> Self {
        Self {
            c1: point_bytes(&value.c1),
            c2: point_bytes(&value.c2),
        }
    }
}

/// Fixed ordered deck used by the Ristretto Texas protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RistrettoTexasDeck {
    /// Deterministic plaintext card points in canonical slot order.
    pub cards: [[u8; 32]; RISTRETTO_TEXAS_DECK_SIZE],
    /// Encrypted deck in the same canonical slot order.
    pub encrypted: [RistrettoAirCiphertext; RISTRETTO_TEXAS_DECK_SIZE],
}

impl RistrettoTexasDeck {
    /// Build the deterministic public 52-card Ristretto plaintext deck.
    #[must_use]
    pub fn canonical_cards() -> [[u8; 32]; RISTRETTO_TEXAS_DECK_SIZE] {
        std::array::from_fn(|index| canonical_card_bytes(index).expect("fixed card index"))
    }

    /// Build the deterministic canonical base encryption under `aggregate_pk`.
    ///
    /// Public per-slot randomness `1..=52` is intentional.  It only creates
    /// the reconstruction base deck; all player contributions and subsequent
    /// shuffles add private rerandomization proved by the AIR.
    pub fn canonical_base(
        aggregate_pk: &<RistrettoCurve as Curve>::Point,
    ) -> Result<Self, RistrettoAirSubmissionError> {
        if aggregate_pk.is_identity() {
            return Err(RistrettoAirSubmissionError::IdentityPublicKey);
        }
        let cards = Self::canonical_cards();
        let encrypted = std::array::from_fn(|index| {
            let card =
                <<RistrettoCurve as Curve>::Point as CurvePoint>::from_compressed(&cards[index])
                    .expect("canonical Ristretto card must decompress");
            let randomness = <RistrettoCurve as Curve>::Scalar::from_u64((index + 1) as u64);
            let ciphertext = ElGamalCiphertextGeneric::<RistrettoCurve>::encrypt(
                &card,
                aggregate_pk,
                &randomness,
            );
            RistrettoAirCiphertext::from(&ciphertext)
        });
        Ok(Self { cards, encrypted })
    }
}

/// One complete 52-card shuffle submission for the Ristretto/AIR protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RistrettoShuffleSubmission {
    /// Aggregate ElGamal key for this table epoch.
    pub aggregate_pk: [u8; 32],
    /// Authenticated deck before the shuffle.
    pub input: [RistrettoAirCiphertext; RISTRETTO_TEXAS_DECK_SIZE],
    /// Submitted deck after permutation and rerandomization.
    pub output: [RistrettoAirCiphertext; RISTRETTO_TEXAS_DECK_SIZE],
    /// AIR proof package.  The backend AIR verifier, not this type, verifies it.
    pub air_proof: Vec<u8>,
}

impl RistrettoShuffleSubmission {
    /// Build the canonical proof-ABI request bound to one state-transition
    /// `call_context`.
    pub fn to_verify_request(
        &self,
        call_context: Vec<u8>,
    ) -> Result<ShuffleVerifyRequest, RistrettoAirSubmissionError> {
        let request = ShuffleVerifyRequest {
            curve: CurveId::Ristretto255,
            proof_system: ShuffleProofSystem::RistrettoAirV1,
            transcript: TranscriptId::Poseidon252,
            context: RISTRETTO_AIR_SHUFFLE_CONTEXT.to_vec(),
            call_context,
            public_key: self.aggregate_pk.to_vec(),
            input: self
                .input
                .iter()
                .copied()
                .map(RistrettoAirCiphertext::to_abi)
                .collect(),
            output: self
                .output
                .iter()
                .copied()
                .map(RistrettoAirCiphertext::to_abi)
                .collect(),
            proof: self.air_proof.clone(),
        };
        request.validate()?;
        Ok(request)
    }

    /// Build the V2 request. V2 keeps the public statement identical but uses
    /// the fixed-shape batch verifier domain and proof-system discriminator.
    pub fn to_verify_request_v2(
        &self,
        call_context: Vec<u8>,
    ) -> Result<ShuffleVerifyRequest, RistrettoAirSubmissionError> {
        let mut request = self.to_verify_request(call_context)?;
        request.proof_system = ShuffleProofSystem::RistrettoAirV2;
        request.transcript = TranscriptId::FlockBlake3;
        request.context = RISTRETTO_AIR_V2_SHUFFLE_CONTEXT.to_vec();
        request.validate()?;
        Ok(request)
    }
}

/// One complete reconstruction V3 submission for the Ristretto/AIR protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RistrettoReconstructionV3Submission {
    /// State-bound reconstruction context digest.
    pub context_digest: [u8; 32],
    /// Monotonic reconstruction epoch authenticated by table state.
    pub reconstruction_epoch: u64,
    /// Digest of the selected owner's readable-card state.
    pub prior_state_digest: [u8; 32],
    /// Aggregate ElGamal key for the table epoch.
    pub aggregate_pk: [u8; 32],
    /// Owner public key for this contribution.
    pub owner_pk: [u8; 32],
    /// The two owner-readable ciphertexts from authenticated table state.
    pub user_readable_cards:
        [RistrettoAirCiphertext; RISTRETTO_TEXAS_RECONSTRUCTION_READABLE_CARDS],
    /// One contribution ciphertext for every canonical card slot.
    pub contributions: [RistrettoAirCiphertext; RISTRETTO_TEXAS_DECK_SIZE],
    /// `ZR3P` envelope plus the AIR proof package selected by the backend ABI.
    pub air_proof: Vec<u8>,
}

impl RistrettoReconstructionV3Submission {
    /// Build the canonical, fixed-shape Ristretto reconstruction request.
    pub fn to_verify_request(
        &self,
        call_context: Vec<u8>,
    ) -> Result<ReconstructionV3VerifyRequest, RistrettoAirSubmissionError> {
        let request = ReconstructionV3VerifyRequest {
            curve: CurveId::Ristretto255,
            proof_system: ReconstructionProofSystem::RistrettoAirV1,
            transcript: TranscriptId::Poseidon252,
            context: RISTRETTO_AIR_RECONSTRUCTION_V3_CONTEXT.to_vec(),
            call_context,
            statement_version: RECONSTRUCTION_V3_STATEMENT_VERSION,
            context_digest: self.context_digest,
            reconstruction_epoch: self.reconstruction_epoch,
            prior_state_digest: self.prior_state_digest,
            aggregate_pk: self.aggregate_pk.to_vec(),
            owner_pk: self.owner_pk.to_vec(),
            cards: RistrettoTexasDeck::canonical_cards()
                .into_iter()
                .map(|card| card.to_vec())
                .collect(),
            user_readable_cards: self
                .user_readable_cards
                .iter()
                .copied()
                .map(RistrettoAirCiphertext::to_abi)
                .collect(),
            contributions: self
                .contributions
                .iter()
                .copied()
                .map(RistrettoAirCiphertext::to_abi)
                .collect(),
            proof: self.air_proof.clone(),
        };
        request.validate()?;
        Ok(request)
    }

    /// Build the V2 request used by the low-latency batched AIR path.
    pub fn to_verify_request_v2(
        &self,
        call_context: Vec<u8>,
    ) -> Result<ReconstructionV3VerifyRequest, RistrettoAirSubmissionError> {
        let mut request = self.to_verify_request(call_context)?;
        request.proof_system = ReconstructionProofSystem::RistrettoAirV2;
        request.transcript = TranscriptId::FlockBlake3;
        request.context = RISTRETTO_AIR_V2_RECONSTRUCTION_CONTEXT.to_vec();
        request.validate()?;
        Ok(request)
    }
}

/// Errors produced while constructing a Ristretto/AIR submission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RistrettoAirSubmissionError {
    /// A compressed point did not have the required 32-byte ABI width.
    InvalidPointEncoding,
    /// The aggregate public key cannot be the Ristretto identity.
    IdentityPublicKey,
    /// The stable proof ABI rejected request shape or limits.
    Abi(AbiError),
}

impl From<AbiError> for RistrettoAirSubmissionError {
    fn from(value: AbiError) -> Self {
        Self::Abi(value)
    }
}

impl std::fmt::Display for RistrettoAirSubmissionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for RistrettoAirSubmissionError {}

/// Return one canonical Ristretto plaintext card encoding.
pub fn canonical_card_bytes(index: usize) -> Option<[u8; 32]> {
    if index >= RISTRETTO_TEXAS_DECK_SIZE {
        return None;
    }
    let label = format!("texas_poker/card/{index}");
    Some(point_bytes(&RistrettoCurve::hash_to_curve(
        label.as_bytes(),
    )))
}

fn point_bytes(point: &<RistrettoCurve as Curve>::Point) -> [u8; 32] {
    *point.compress().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ciphertext(byte: u8) -> RistrettoAirCiphertext {
        RistrettoAirCiphertext {
            c1: [byte; 32],
            c2: [byte.wrapping_add(1); 32],
        }
    }

    #[test]
    fn canonical_cards_match_the_ristretto_hash_to_curve_domain() {
        let cards = RistrettoTexasDeck::canonical_cards();
        assert_eq!(cards[0], canonical_card_bytes(0).unwrap());
        assert_eq!(cards[51], canonical_card_bytes(51).unwrap());
        assert_ne!(cards[0], cards[1]);
        assert_eq!(canonical_card_bytes(RISTRETTO_TEXAS_DECK_SIZE), None);
    }

    #[test]
    fn shuffle_submission_has_a_fixed_52_card_ristretto_abi() {
        let submission = RistrettoShuffleSubmission {
            aggregate_pk: point_bytes(&RistrettoCurve::base_g()),
            input: std::array::from_fn(|index| ciphertext(index as u8)),
            output: std::array::from_fn(|index| ciphertext((index + 80) as u8)),
            air_proof: vec![9; 32],
        };
        let request = submission.to_verify_request(vec![7; 32]).unwrap();
        assert_eq!(request.curve, CurveId::Ristretto255);
        assert_eq!(request.input.len(), RISTRETTO_TEXAS_DECK_SIZE);
        assert_eq!(request.context, RISTRETTO_AIR_SHUFFLE_CONTEXT);
        assert_eq!(
            ShuffleVerifyRequest::decode(&request.encode().unwrap()),
            Ok(request)
        );
        let v2 = submission.to_verify_request_v2(vec![7; 32]).unwrap();
        assert_eq!(v2.proof_system, ShuffleProofSystem::RistrettoAirV2);
        assert_eq!(v2.context, RISTRETTO_AIR_V2_SHUFFLE_CONTEXT);
        assert_eq!(ShuffleVerifyRequest::decode(&v2.encode().unwrap()), Ok(v2));
    }

    #[test]
    fn reconstruction_submission_binds_the_canonical_cards() {
        let submission = RistrettoReconstructionV3Submission {
            context_digest: [1; 32],
            reconstruction_epoch: 9,
            prior_state_digest: [2; 32],
            aggregate_pk: point_bytes(&RistrettoCurve::base_g()),
            owner_pk: point_bytes(&RistrettoCurve::base_h()),
            user_readable_cards: [ciphertext(10), ciphertext(12)],
            contributions: std::array::from_fn(|index| ciphertext((index + 40) as u8)),
            air_proof: vec![9; 32],
        };
        let request = submission.to_verify_request(vec![7; 32]).unwrap();
        assert_eq!(
            request.cards,
            RistrettoTexasDeck::canonical_cards().map(|card| card.to_vec())
        );
        assert_eq!(
            request.user_readable_cards.len(),
            RISTRETTO_TEXAS_RECONSTRUCTION_READABLE_CARDS
        );
        assert_eq!(request.contributions.len(), RISTRETTO_TEXAS_DECK_SIZE);
        assert_eq!(
            ReconstructionV3VerifyRequest::decode(&request.encode().unwrap()),
            Ok(request)
        );
        let v2 = submission.to_verify_request_v2(vec![7; 32]).unwrap();
        assert_eq!(v2.proof_system, ReconstructionProofSystem::RistrettoAirV2);
        assert_eq!(v2.context, RISTRETTO_AIR_V2_RECONSTRUCTION_CONTEXT);
        assert_eq!(
            ReconstructionV3VerifyRequest::decode(&v2.encode().unwrap()),
            Ok(v2)
        );
    }

    #[test]
    fn canonical_base_deck_rejects_the_identity_key() {
        let identity = <<RistrettoCurve as Curve>::Point as CurvePoint>::identity();
        assert_eq!(
            RistrettoTexasDeck::canonical_base(&identity),
            Err(RistrettoAirSubmissionError::IdentityPublicKey)
        );
    }
}
