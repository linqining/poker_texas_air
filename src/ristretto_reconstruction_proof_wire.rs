//! Versioned public wire envelope for the Ristretto Reconstruction V3 proof.
//!
//! The cryptographic relations are intentionally still verified by dedicated
//! AIR components.  This module closes a separate, easy-to-miss boundary: a
//! request must carry one canonical, self-describing proof package rather than
//! an opaque `Vec<u8>` which can be spliced between statements.  The envelope
//! binds its component counts and bytes to the complete public request
//! statement (excluding the envelope itself).  It does **not** claim that the
//! component bytes are already a verified DLEQ/shuffle proof.

#![allow(missing_docs)]

use blake2::{
    Blake2bVar,
    digest::{Update, VariableOutput},
};
use borsh::{BorshDeserialize, BorshSerialize};
use poker_protocol::precompile_abi::{ReconstructionProofSystem, ReconstructionV3VerifyRequest};

use crate::canonical_reconstruction_binding::CANONICAL_RECONSTRUCTION_CARDS;
use crate::error::{TexasAirError, TexasAirResult};

pub const RISTRETTO_RECONSTRUCTION_PROOF_WIRE_MAGIC: [u8; 4] = *b"ZR3P";
pub const RISTRETTO_RECONSTRUCTION_PROOF_WIRE_VERSION: u8 = 1;
pub const RISTRETTO_RECONSTRUCTION_READABLE_CARDS: usize = 2;
const STATEMENT_DOMAIN: &[u8] = b"zchain.texas.ristretto-reconstruction-v3.statement.v1";
const COMPONENT_DOMAIN: &[u8] = b"zchain.texas.ristretto-reconstruction-v3.components.v1";
const TRANSCRIPT_DOMAIN: &[u8] = b"zchain.texas.ristretto-reconstruction-v3.poseidon252";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BorshSerialize, BorshDeserialize)]
pub struct RistrettoCiphertextProofWire {
    pub c1: [u8; 32],
    pub c2: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BorshSerialize, BorshDeserialize)]
pub struct RistrettoCrossKeyProofWire {
    pub commitment_owner_key: [u8; 32],
    pub commitment_contribution_c1: [u8; 32],
    pub commitment_joint_c2: [u8; 32],
    pub response_owner_sk: [u8; 32],
    pub response_contribution_randomness: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, BorshSerialize, BorshDeserialize)]
pub struct RistrettoSlotOrProofWire {
    pub commitment_g: [[u8; 32]; 2],
    pub commitment_pk: [[u8; 32]; 2],
    pub challenges: [[u8; 32]; 2],
    pub responses: [[u8; 32]; 2],
}

/// Fixed 52-card Bayer--Groth V2 public wire, represented with Ristretto
/// compressed points/scalars rather than legacy BLS serialisation.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RistrettoBayerGrothShuffleProofWire {
    pub c_permutation: [u8; 32],
    pub c_permuted_powers: [u8; 32],
    pub c_alpha: [u8; 32],
    pub c_beta: [u8; 32],
    pub ciphertext_0: RistrettoCiphertextProofWire,
    pub ciphertext_1: RistrettoCiphertextProofWire,
    pub alpha_response: [[u8; 32]; CANONICAL_RECONSTRUCTION_CARDS],
    pub commitment_response: [u8; 32],
    pub beta: [u8; 32],
    pub beta_blinding_response: [u8; 32],
    pub rerandomization_response: [u8; 32],
    pub c_d: [u8; 32],
    pub c_delta: [u8; 32],
    pub c_capital_delta: [u8; 32],
    pub a_response: [[u8; 32]; CANONICAL_RECONSTRUCTION_CARDS],
    pub b_response: [[u8; 32]; CANONICAL_RECONSTRUCTION_CARDS],
    pub r_response: [u8; 32],
    pub s_response: [u8; 32],
}

impl Default for RistrettoBayerGrothShuffleProofWire {
    fn default() -> Self {
        Self {
            c_permutation: [0; 32],
            c_permuted_powers: [0; 32],
            c_alpha: [0; 32],
            c_beta: [0; 32],
            ciphertext_0: RistrettoCiphertextProofWire::default(),
            ciphertext_1: RistrettoCiphertextProofWire::default(),
            alpha_response: [[0; 32]; CANONICAL_RECONSTRUCTION_CARDS],
            commitment_response: [0; 32],
            beta: [0; 32],
            beta_blinding_response: [0; 32],
            rerandomization_response: [0; 32],
            c_d: [0; 32],
            c_delta: [0; 32],
            c_capital_delta: [0; 32],
            a_response: [[0; 32]; CANONICAL_RECONSTRUCTION_CARDS],
            b_response: [[0; 32]; CANONICAL_RECONSTRUCTION_CARDS],
            r_response: [0; 32],
            s_response: [0; 32],
        }
    }
}

/// Public, versioned proof package.  Each component remains an opaque payload
/// until its matching AIR verifier is composed, but all payloads are fixed to
/// the statement and to their protocol-defined cardinality here.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RistrettoReconstructionProofEnvelope {
    pub version: u8,
    pub statement_digest: [u8; 32],
    /// Digest of the fixed transcript domain, not a Fiat--Shamir challenge.
    pub transcript_domain_digest: [u8; 32],
    /// One negative contribution per readable owner card, in readable order.
    pub negative_contributions:
        [RistrettoCiphertextProofWire; RISTRETTO_RECONSTRUCTION_READABLE_CARDS],
    pub shuffle_proof: RistrettoBayerGrothShuffleProofWire,
    pub cross_key_proofs: [RistrettoCrossKeyProofWire; RISTRETTO_RECONSTRUCTION_READABLE_CARDS],
    pub slot_or_proofs: [RistrettoSlotOrProofWire; CANONICAL_RECONSTRUCTION_CARDS],
    pub component_digest: [u8; 32],
}

fn digest(domain: &[u8], message: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("Blake2b-256 output is valid");
    hasher.update(domain);
    hasher.update(message);
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("Blake2b-256 output has fixed size");
    out
}

fn append_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> TexasAirResult<()> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| TexasAirError::SpecViolation("proof-wire field is too large".into()))?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn append_ciphertext(out: &mut Vec<u8>, c1: &[u8], c2: &[u8]) -> TexasAirResult<()> {
    append_bytes(out, c1)?;
    append_bytes(out, c2)
}

/// Digest the complete public request statement without including `proof`.
/// This is the stable preimage the future Poseidon transcript AIR must use.
pub fn reconstruction_v3_statement_digest(
    request: &ReconstructionV3VerifyRequest,
) -> TexasAirResult<[u8; 32]> {
    request.validate().map_err(|error| {
        TexasAirError::SpecViolation(format!("invalid Reconstruction V3 request: {error}"))
    })?;
    let mut preimage = Vec::new();
    preimage.extend_from_slice(STATEMENT_DOMAIN);
    preimage.extend_from_slice(&[
        request.curve as u8,
        request.proof_system as u8,
        request.transcript as u8,
        request.statement_version,
    ]);
    preimage.extend_from_slice(&request.reconstruction_epoch.to_le_bytes());
    preimage.extend_from_slice(&request.context_digest);
    preimage.extend_from_slice(&request.prior_state_digest);
    append_bytes(&mut preimage, &request.context)?;
    append_bytes(&mut preimage, &request.call_context)?;
    append_bytes(&mut preimage, &request.aggregate_pk)?;
    append_bytes(&mut preimage, &request.owner_pk)?;
    let card_count = u32::try_from(request.cards.len())
        .map_err(|_| TexasAirError::SpecViolation("too many reconstruction cards".into()))?;
    preimage.extend_from_slice(&card_count.to_le_bytes());
    for card in &request.cards {
        append_bytes(&mut preimage, card)?;
    }
    let readable_count = u32::try_from(request.user_readable_cards.len())
        .map_err(|_| TexasAirError::SpecViolation("too many readable cards".into()))?;
    preimage.extend_from_slice(&readable_count.to_le_bytes());
    for card in &request.user_readable_cards {
        append_ciphertext(&mut preimage, &card.c1, &card.c2)?;
    }
    let contribution_count = u32::try_from(request.contributions.len())
        .map_err(|_| TexasAirError::SpecViolation("too many contributions".into()))?;
    preimage.extend_from_slice(&contribution_count.to_le_bytes());
    for contribution in &request.contributions {
        append_ciphertext(&mut preimage, &contribution.c1, &contribution.c2)?;
    }
    Ok(digest(&[], &preimage))
}

fn component_digest(envelope: &RistrettoReconstructionProofEnvelope) -> TexasAirResult<[u8; 32]> {
    let mut preimage = envelope.statement_digest.to_vec();
    preimage.extend_from_slice(
        &borsh::to_vec(&(
            envelope.negative_contributions,
            envelope.shuffle_proof.clone(),
            envelope.cross_key_proofs,
            envelope.slot_or_proofs,
        ))
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?,
    );
    Ok(digest(COMPONENT_DOMAIN, &preimage))
}

impl RistrettoReconstructionProofEnvelope {
    pub fn from_components(
        request: &ReconstructionV3VerifyRequest,
        negative_contributions: [RistrettoCiphertextProofWire;
            RISTRETTO_RECONSTRUCTION_READABLE_CARDS],
        shuffle_proof: RistrettoBayerGrothShuffleProofWire,
        cross_key_proofs: [RistrettoCrossKeyProofWire; RISTRETTO_RECONSTRUCTION_READABLE_CARDS],
        slot_or_proofs: [RistrettoSlotOrProofWire; CANONICAL_RECONSTRUCTION_CARDS],
    ) -> TexasAirResult<Self> {
        let statement_digest = reconstruction_v3_statement_digest(request)?;
        let mut envelope = Self {
            version: RISTRETTO_RECONSTRUCTION_PROOF_WIRE_VERSION,
            statement_digest,
            transcript_domain_digest: digest(&[], TRANSCRIPT_DOMAIN),
            negative_contributions,
            shuffle_proof,
            cross_key_proofs,
            slot_or_proofs,
            component_digest: [0; 32],
        };
        envelope.component_digest = component_digest(&envelope)?;
        envelope.validate_shape()?;
        Ok(envelope)
    }

    pub fn encode_wire(&self) -> TexasAirResult<Vec<u8>> {
        self.validate_shape()?;
        let payload = borsh::to_vec(self)
            .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
        let mut out =
            Vec::with_capacity(RISTRETTO_RECONSTRUCTION_PROOF_WIRE_MAGIC.len() + payload.len());
        out.extend_from_slice(&RISTRETTO_RECONSTRUCTION_PROOF_WIRE_MAGIC);
        out.extend_from_slice(&payload);
        Ok(out)
    }

    pub fn decode_wire(bytes: &[u8]) -> TexasAirResult<Self> {
        if bytes.len() < RISTRETTO_RECONSTRUCTION_PROOF_WIRE_MAGIC.len()
            || bytes[..4] != RISTRETTO_RECONSTRUCTION_PROOF_WIRE_MAGIC
        {
            return Err(TexasAirError::SerializationError(
                "Ristretto Reconstruction V3 proof-wire magic mismatch".into(),
            ));
        }
        let envelope: Self = borsh::from_slice(&bytes[4..]).map_err(|error| {
            TexasAirError::SerializationError(format!(
                "Ristretto proof-wire decode failed: {error}"
            ))
        })?;
        envelope.validate_shape()?;
        if envelope.encode_wire()? != bytes {
            return Err(TexasAirError::SerializationError(
                "Ristretto proof-wire is not canonically encoded".into(),
            ));
        }
        Ok(envelope)
    }

    pub fn validate_shape(&self) -> TexasAirResult<()> {
        if self.version != RISTRETTO_RECONSTRUCTION_PROOF_WIRE_VERSION {
            return Err(TexasAirError::SpecViolation(
                "unsupported Ristretto Reconstruction V3 proof-wire version".into(),
            ));
        }
        if self.transcript_domain_digest != digest(&[], TRANSCRIPT_DOMAIN) {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "Ristretto Reconstruction V3 transcript domain is detached".into(),
            ));
        }
        if self.component_digest != component_digest(self)? {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "Ristretto Reconstruction V3 component digest is detached".into(),
            ));
        }
        Ok(())
    }

    pub fn validate_against_request(
        &self,
        request: &ReconstructionV3VerifyRequest,
    ) -> TexasAirResult<()> {
        request.validate().map_err(|error| {
            TexasAirError::SpecViolation(format!("invalid Reconstruction V3 request: {error}"))
        })?;
        if request.curve != poker_protocol::precompile_abi::CurveId::Ristretto255
            || request.proof_system != ReconstructionProofSystem::RistrettoAirV1
            || request.cards.len() != CANONICAL_RECONSTRUCTION_CARDS
            || request.user_readable_cards.len() != RISTRETTO_RECONSTRUCTION_READABLE_CARDS
        {
            return Err(TexasAirError::SpecViolation(
                "Ristretto Reconstruction V3 proof-wire is bound to the fixed Texas statement shape".into(),
            ));
        }
        if self.statement_digest != reconstruction_v3_statement_digest(request)? {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "Ristretto Reconstruction V3 proof-wire is detached from the request statement"
                    .into(),
            ));
        }
        Ok(())
    }
}

/// Decode and validate the strict envelope carried in `request.proof`.
pub fn validate_ristretto_reconstruction_proof_wire(
    request: &ReconstructionV3VerifyRequest,
) -> TexasAirResult<RistrettoReconstructionProofEnvelope> {
    let envelope = RistrettoReconstructionProofEnvelope::decode_wire(&request.proof)?;
    envelope.validate_against_request(request)?;
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use poker_protocol::precompile_abi::{CurveId, EncodedCiphertext, TranscriptId};

    fn request() -> ReconstructionV3VerifyRequest {
        ReconstructionV3VerifyRequest {
            curve: CurveId::Ristretto255,
            proof_system: ReconstructionProofSystem::RistrettoAirV1,
            transcript: TranscriptId::Poseidon252,
            context: b"zk_reconstruct_proof_v3".to_vec(),
            call_context: vec![7; 32],
            statement_version: 3,
            context_digest: [1; 32],
            reconstruction_epoch: 9,
            prior_state_digest: [2; 32],
            aggregate_pk: vec![3; 32],
            owner_pk: vec![4; 32],
            cards: vec![vec![5; 32]; CANONICAL_RECONSTRUCTION_CARDS],
            user_readable_cards: vec![
                EncodedCiphertext {
                    c1: vec![6; 32],
                    c2: vec![7; 32]
                };
                2
            ],
            contributions: vec![
                EncodedCiphertext {
                    c1: vec![8; 32],
                    c2: vec![9; 32]
                };
                CANONICAL_RECONSTRUCTION_CARDS
            ],
            proof: vec![1],
        }
    }

    fn envelope(request: &ReconstructionV3VerifyRequest) -> RistrettoReconstructionProofEnvelope {
        RistrettoReconstructionProofEnvelope::from_components(
            request,
            [RistrettoCiphertextProofWire {
                c1: [0xA0; 32],
                c2: [0xA1; 32],
            }; RISTRETTO_RECONSTRUCTION_READABLE_CARDS],
            RistrettoBayerGrothShuffleProofWire::default(),
            [RistrettoCrossKeyProofWire::default(); RISTRETTO_RECONSTRUCTION_READABLE_CARDS],
            [RistrettoSlotOrProofWire::default(); CANONICAL_RECONSTRUCTION_CARDS],
        )
        .unwrap()
    }

    #[test]
    fn proof_wire_roundtrip_binds_statement_and_counts() {
        let mut request = request();
        let wire = envelope(&request).encode_wire().unwrap();
        request.proof = wire;
        let decoded = validate_ristretto_reconstruction_proof_wire(&request).unwrap();
        assert_eq!(decoded.slot_or_proofs.len(), CANONICAL_RECONSTRUCTION_CARDS);

        let mut spliced = request.clone();
        spliced.contributions[0].c1[0] ^= 1;
        assert!(validate_ristretto_reconstruction_proof_wire(&spliced).is_err());

        let mut count_splice = decoded.clone();
        count_splice.slot_or_proofs[0].responses[0][0] ^= 1;
        assert!(count_splice.validate_shape().is_err());
    }

    #[test]
    fn proof_wire_rejects_noncanonical_bytes_and_component_splice() {
        let request = request();
        let mut wire = envelope(&request).encode_wire().unwrap();
        wire.push(0);
        assert!(RistrettoReconstructionProofEnvelope::decode_wire(&wire).is_err());

        let mut changed = envelope(&request);
        changed.shuffle_proof.c_permutation[0] ^= 1;
        assert!(changed.validate_shape().is_err());
    }
}
