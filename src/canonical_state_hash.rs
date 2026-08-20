//! Blake2b-256 authentication of canonical Texas state-image byte preimages.
//!
//! `CanonicalStateImage::commitment` is `Blake2b-256(domain || Borsh(image))`.
//! This module turns that byte-level relation into a shared lookup-backed
//! STARK statement.  The canonical transition AIR binds its fixed 841-limb
//! state-image projection to the same endpoint bytes; admission remains closed
//! until the remaining VM and Ristretto relations are composed as well.

#![allow(missing_docs)]

use crate::blake2b_lookup_compression::{
    ArchivedBlake2bLookupHashesProof, prove_blake2b_lookup_hashes, verify_blake2b_lookup_hashes,
};
use crate::error::{TexasAirError, TexasAirResult};
use crate::texas_canonical::CanonicalStateImage;

/// Domain prefix used by `CanonicalStateImage::commitment`.
pub const CANONICAL_STATE_IMAGE_DOMAIN: &[u8] = b"zchain.texas.canonical-state.v2";

/// The two Blake2b statements for one canonical transition's state endpoints.
/// The first statement authenticates the pre-image and the second the
/// post-image.  They share one lookup-table commitment.
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct ArchivedCanonicalStateImageHashProof {
    pub hashes: ArchivedBlake2bLookupHashesProof,
}

/// Return the exact byte preimage covered by a canonical state commitment.
/// This is a prover-side serialization routine; verification consumes the
/// archived byte statement and invokes only STARK verification.
pub fn canonical_state_image_preimage(image: &CanonicalStateImage) -> TexasAirResult<Vec<u8>> {
    let encoded = borsh::to_vec(image)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
    let mut preimage = Vec::with_capacity(CANONICAL_STATE_IMAGE_DOMAIN.len() + encoded.len());
    preimage.extend_from_slice(CANONICAL_STATE_IMAGE_DOMAIN);
    preimage.extend_from_slice(&encoded);
    Ok(preimage)
}

/// Prove the two endpoint state-image commitments with one shared Blake2b
/// lookup proof.  Native Blake2b is not used to form or verify the result.
pub fn prove_canonical_state_image_hashes(
    pre: &CanonicalStateImage,
    post: &CanonicalStateImage,
) -> TexasAirResult<ArchivedCanonicalStateImageHashProof> {
    let messages = vec![
        canonical_state_image_preimage(pre)?,
        canonical_state_image_preimage(post)?,
    ];
    Ok(ArchivedCanonicalStateImageHashProof {
        hashes: prove_blake2b_lookup_hashes(&messages)?,
    })
}

/// Verify that the archived endpoint byte statements hash to the exact public
/// canonical commitments.  This function neither serializes images nor calls
/// a native hash implementation.
pub fn verify_canonical_state_image_hashes(
    archive: &ArchivedCanonicalStateImageHashProof,
    pre_commitment: [u8; 32],
    post_commitment: [u8; 32],
) -> TexasAirResult<()> {
    let statements = &archive.hashes.statements;
    let [pre, post] = statements.as_slice() else {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "canonical state-image hash proof must contain exactly two endpoint statements".into(),
        ));
    };
    if pre.digest != pre_commitment || post.digest != post_commitment {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "canonical state-image hash proof is detached from an endpoint commitment".into(),
        ));
    }
    verify_blake2b_lookup_hashes(&archive.hashes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::texas_canonical::{
        CANONICAL_ABI_VERSION, CanonicalPhase, CanonicalSeat, MAX_CANONICAL_SEATS,
        NO_CANONICAL_SEAT,
    };

    fn image() -> CanonicalStateImage {
        CanonicalStateImage {
            abi_version: CANONICAL_ABI_VERSION,
            table_id: 7,
            hand_id: 1,
            call_seq: 0,
            phase: CanonicalPhase::Waiting,
            phase_subtag: 0,
            street: 0,
            current_turn: NO_CANONICAL_SEAT,
            deadline_ms: 0,
            shuffle_timeout_ms: 10_000,
            reveal_timeout_ms: 10_000,
            betting_timeout_ms: 30_000,
            reconstruct_timeout_ms: 10_000,
            showdown_display_ms: 3_000,
            current_bet: 0,
            min_raise: 0,
            chip_pool: 0,
            pot: 0,
            button: 0,
            max_players: 2,
            acted_mask: 0,
            leave_after_hand_mask: 0,
            protocol_pending_mask: 0,
            board_cards_commitment: [1; 32],
            deck_commitment: [2; 32],
            reveal_commitment: [3; 32],
            reconstruction_commitment: [4; 32],
            run_it_twice_commitment: [5; 32],
            rules_commitment: [6; 32],
            governance_commitment: [7; 32],
            settlement_commitment: [8; 32],
            custody_commitment: [9; 32],
            lifecycle_root: [10; 32],
            overlay_root: [11; 32],
            state_root: [12; 32],
            seats: [CanonicalSeat::EMPTY; MAX_CANONICAL_SEATS],
        }
    }

    #[test]
    fn preimage_is_the_exact_native_commitment_input() {
        use blake2::Blake2bVar;
        use blake2::digest::{Update, VariableOutput};

        let image = image();
        let preimage = canonical_state_image_preimage(&image).unwrap();
        let mut hasher = Blake2bVar::new(32).unwrap();
        hasher.update(&preimage);
        let mut digest = [0; 32];
        hasher.finalize_variable(&mut digest).unwrap();
        assert_eq!(digest, image.commitment());
    }

    #[test]
    fn verifier_rejects_an_endpoint_commitment_splice_before_stark_work() {
        let image = image();
        let preimage = canonical_state_image_preimage(&image).unwrap();
        let hashes = ArchivedBlake2bLookupHashesProof {
            statements: vec![
                crate::blake2b_lookup_compression::Blake2bLookupHashStatement {
                    message: preimage.clone(),
                    digest: image.commitment(),
                },
                crate::blake2b_lookup_compression::Blake2bLookupHashStatement {
                    message: preimage,
                    digest: image.commitment(),
                },
            ],
            compression: crate::blake2b_lookup_compression::ArchivedBlake2bLookupCompressionProof {
                messages: Vec::new(),
                digests: Vec::new(),
                initial_states: Vec::new(),
                hash_states: Vec::new(),
                chain_to_next: Vec::new(),
                calls: Vec::new(),
                g_proof_bytes: Vec::new(),
                schedule_proof_bytes: Vec::new(),
            },
        };
        let archive = ArchivedCanonicalStateImageHashProof { hashes };
        let mut wrong = image.commitment();
        wrong[0] ^= 1;
        assert!(verify_canonical_state_image_hashes(&archive, wrong, image.commitment()).is_err());
    }

    #[test]
    #[ignore = "proves two multi-block canonical state-image hashes through the shared lookup batch"]
    fn state_image_hash_proof_roundtrip_binds_both_endpoint_commitments() {
        let pre = image();
        let mut post = pre.clone();
        post.call_seq = 1;
        let archive = prove_canonical_state_image_hashes(&pre, &post).unwrap();
        verify_canonical_state_image_hashes(&archive, pre.commitment(), post.commitment()).unwrap();

        let mut tampered = archive;
        tampered.hashes.statements[1].digest[0] ^= 1;
        assert!(
            verify_canonical_state_image_hashes(&tampered, pre.commitment(), post.commitment(),)
                .is_err()
        );
    }
}
