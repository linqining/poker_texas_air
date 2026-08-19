//! Composition of a canonical Texas transition STARK with fixed-width L1
//! Blake2b state-object openings.
//!
//! This module is deliberately a *proof composition*, not a native Merkle
//! verifier.  Verification performs only STARK verification plus equality
//! checks over public statements.  The two opening proofs establish the L1
//! `H(0x00 || key || value)` / 256-parent path relations, and the canonical
//! proof establishes the Texas transition relation.  These equality checks
//! make it impossible to splice a valid opening for another table object,
//! pre/post root, state value, or fixed-state-object epoch.
//!
//! The fixed leaf's value is the canonical state-image commitment.  A caller
//! must still use a canonical AIR version that constrains the commitment's
//! preimage before treating the composed archive as a complete host-zero
//! Texas transition.  This component closes the distinct root-opening splice
//! boundary; it does not falsely claim to have implemented every Texas or
//! Ristretto relation.
#![allow(missing_docs)]

use borsh::{BorshDeserialize, BorshSerialize};

use crate::blake2b_lookup_compression::{
    ArchivedBlake2bLookupSmtFixedValuePathsProof, prove_blake2b_lookup_smt_fixed_value_paths,
    verify_blake2b_lookup_smt_fixed_value_paths,
};
use crate::blake2b_smt_witness::Blake2bSmtFixedValuePathWitness;
use crate::canonical_state_hash::{
    ArchivedCanonicalStateImageHashProof, CANONICAL_STATE_IMAGE_DOMAIN,
    prove_canonical_state_image_hashes, verify_canonical_state_image_hashes,
};
use crate::error::{TexasAirError, TexasAirResult};
use crate::texas_canonical::CanonicalTransitionWitness;
use crate::texas_canonical_air::{
    ArchivedCanonicalTaggedProof, CanonicalStateOpeningScope,
    prove_canonical_tagged_batch_for_state_opening, verify_canonical_tagged_proof,
};

/// One canonical transition proof and the exact two L1 state-object openings
/// it needs for admission.
///
/// The two paths are ordered `[pre_state, post_state]` and share one
/// lookup-backed compression proof.  They authenticate the canonical image
/// commitments at `canonical.pre_state_root` and `canonical.post_state_root`,
/// respectively, using the immutable object key and epoch in the canonical
/// proof's public scope.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedCanonicalStateOpeningProof {
    pub canonical: ArchivedCanonicalTaggedProof,
    pub state_openings: ArchivedBlake2bLookupSmtFixedValuePathsProof,
}

/// A canonical transition plus both halves of the state-image authentication
/// chain: `Borsh(image) -> Blake2b-256(image commitment) -> L1 SMT root`.
///
/// This remains a building block rather than a host-zero admission proof: the
/// canonical AIR binds its fixed 841-limb state-image projection to these
/// endpoint bytes, but complete VM settlement and Ristretto crypto relations
/// are still required before a table head can change.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedCanonicalStateImageOpeningProof {
    pub opening: ArchivedCanonicalStateOpeningProof,
    pub state_image_hashes: ArchivedCanonicalStateImageHashProof,
}

fn state_hash_message_matches_image_bytes(message: &[u8], image_bytes: &[u8]) -> bool {
    message.len() == CANONICAL_STATE_IMAGE_DOMAIN.len() + image_bytes.len()
        && message[..CANONICAL_STATE_IMAGE_DOMAIN.len()] == CANONICAL_STATE_IMAGE_DOMAIN[..]
        && message[CANONICAL_STATE_IMAGE_DOMAIN.len()..] == image_bytes[..]
}

fn validate_state_hash_byte_binding(
    opening: &ArchivedCanonicalStateOpeningProof,
    hashes: &ArchivedCanonicalStateImageHashProof,
) -> TexasAirResult<()> {
    let [pre, post] = hashes.hashes.statements.as_slice() else {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "canonical state-image hash proof has an invalid endpoint shape".into(),
        ));
    };
    if !state_hash_message_matches_image_bytes(
        &pre.message,
        &opening.canonical.pre_state_image_bytes,
    ) || !state_hash_message_matches_image_bytes(
        &post.message,
        &opening.canonical.post_state_image_bytes,
    ) {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "canonical state-image hash preimage is detached from the canonical byte scope".into(),
        ));
    }
    Ok(())
}

fn validate_opening_scope(
    canonical: &ArchivedCanonicalTaggedProof,
    paths: &[Blake2bSmtFixedValuePathWitness],
) -> TexasAirResult<()> {
    CanonicalStateOpeningScope {
        state_object_key: canonical.state_object_key,
        state_opening_epoch: canonical.state_opening_epoch,
    }
    .validate()?;

    let [pre, post] = paths else {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "canonical state opening batch must contain exactly pre and post paths".into(),
        ));
    };

    if pre.key != canonical.state_object_key || post.key != canonical.state_object_key {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "canonical state opening uses a different L1 state-object key".into(),
        ));
    }
    if pre.value != canonical.pre_state_commitment || post.value != canonical.post_state_commitment
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "canonical state opening value is detached from the transition image commitment".into(),
        ));
    }
    if pre.root != canonical.pre_state_root || post.root != canonical.post_state_root {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "canonical state opening root is detached from the transition root scope".into(),
        ));
    }
    Ok(())
}

/// Prove a canonical transition and its pre/post fixed-width L1 state-object
/// openings.
///
/// The state key and epoch are committed by the canonical proof itself.  This
/// function does not call a native hash verifier: the native prover merely
/// allocates the supplied opening witnesses, while verification of all 514
/// leaf/internal compressions occurs through one shared lookup-backed STARK
/// batch.
pub fn prove_canonical_batch_with_state_openings(
    witnesses: &[CanonicalTransitionWitness],
    state_opening: CanonicalStateOpeningScope,
    pre_state_opening: &Blake2bSmtFixedValuePathWitness,
    post_state_opening: &Blake2bSmtFixedValuePathWitness,
) -> TexasAirResult<ArchivedCanonicalStateOpeningProof> {
    state_opening.validate()?;
    let canonical = prove_canonical_tagged_batch_for_state_opening(witnesses, state_opening)?;

    // Check the inexpensive public ABI before starting the shared
    // 514-compression proof. This is not authentication; the corresponding
    // verifier repeats these equalities before accepting the proof.
    validate_opening_scope(
        &canonical,
        &[pre_state_opening.clone(), post_state_opening.clone()],
    )?;

    Ok(ArchivedCanonicalStateOpeningProof {
        canonical,
        state_openings: prove_blake2b_lookup_smt_fixed_value_paths(&[
            pre_state_opening.clone(),
            post_state_opening.clone(),
        ])?,
    })
}

/// Verify a canonical transition and its batched L1 state-object openings without
/// transaction replay or native Blake2b/SMT verification.
pub fn verify_canonical_batch_with_state_openings(
    archive: &ArchivedCanonicalStateOpeningProof,
) -> TexasAirResult<()> {
    validate_opening_scope(&archive.canonical, &archive.state_openings.paths)?;
    verify_canonical_tagged_proof(&archive.canonical)?;
    verify_blake2b_lookup_smt_fixed_value_paths(&archive.state_openings)
}

/// Prove the complete currently-available byte/hash/opening chain for a
/// canonical batch.  This shares the state-image hash lookup table across the
/// pre and post images, and separately shares the 514 L1 opening
/// compressions.  It intentionally does not make a host-zero admission claim
/// until complete VM settlement and Ristretto crypto relations are added.
pub fn prove_canonical_batch_with_state_image_openings(
    witnesses: &[CanonicalTransitionWitness],
    state_opening: CanonicalStateOpeningScope,
    pre_state_opening: &Blake2bSmtFixedValuePathWitness,
    post_state_opening: &Blake2bSmtFixedValuePathWitness,
) -> TexasAirResult<ArchivedCanonicalStateImageOpeningProof> {
    if witnesses.is_empty() {
        return Err(TexasAirError::SpecViolation(
            "canonical state-image opening proof requires at least one transition".into(),
        ));
    }
    let opening = prove_canonical_batch_with_state_openings(
        witnesses,
        state_opening,
        pre_state_opening,
        post_state_opening,
    )?;
    let state_image_hashes = prove_canonical_state_image_hashes(
        &witnesses[0].pre,
        &witnesses[witnesses.len() - 1].post,
    )?;
    validate_state_hash_byte_binding(&opening, &state_image_hashes)?;
    let [pre, post] = state_image_hashes.hashes.statements.as_slice() else {
        unreachable!("state hash byte binding checks endpoint count");
    };
    if pre.digest != opening.canonical.pre_state_commitment
        || post.digest != opening.canonical.post_state_commitment
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "canonical state-image hash output is detached from the transition opening".into(),
        ));
    }
    Ok(ArchivedCanonicalStateImageOpeningProof {
        opening,
        state_image_hashes,
    })
}

/// Verify `Borsh(image) -> commitment -> root` for a canonical batch without
/// replaying a transaction or invoking native Blake2b/SMT verification.
pub fn verify_canonical_batch_with_state_image_openings(
    archive: &ArchivedCanonicalStateImageOpeningProof,
) -> TexasAirResult<()> {
    verify_canonical_batch_with_state_openings(&archive.opening)?;
    verify_canonical_state_image_hashes(
        &archive.state_image_hashes,
        archive.opening.canonical.pre_state_commitment,
        archive.opening.canonical.post_state_commitment,
    )?;
    validate_state_hash_byte_binding(&archive.opening, &archive.state_image_hashes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn archive() -> ArchivedCanonicalTaggedProof {
        ArchivedCanonicalTaggedProof {
            log_size: 0,
            num_columns: 0,
            table_id: 7,
            first_hand_id: 2,
            last_hand_id: 2,
            first_call_seq: 4,
            last_call_seq: 5,
            transition_count: 1,
            batch_digest: [1; 32],
            pre_state_commitment: [2; 32],
            post_state_commitment: [3; 32],
            pre_state_root: [4; 32],
            post_state_root: [5; 32],
            pre_lifecycle_root: [6; 32],
            post_lifecycle_root: [7; 32],
            pre_overlay_root: [8; 32],
            post_overlay_root: [9; 32],
            pre_settlement_commitment: [10; 32],
            post_settlement_commitment: [11; 32],
            pre_custody_commitment: [12; 32],
            post_custody_commitment: [13; 32],
            pre_state_image_bytes: Vec::new(),
            post_state_image_bytes: Vec::new(),
            state_object_key: [14; 32],
            state_opening_epoch: 1,
            stark_proof_bytes: Vec::new(),
        }
    }

    fn opening(key: [u8; 32], value: [u8; 32], root: [u8; 32]) -> Blake2bSmtFixedValuePathWitness {
        Blake2bSmtFixedValuePathWitness {
            key,
            value,
            siblings: [[0; 32]; 256],
            nodes: [[0; 32]; 257],
            root,
        }
    }

    #[test]
    fn fixed_state_opening_scope_rejects_legacy_namespace() {
        assert!(CanonicalStateOpeningScope::legacy().validate().is_err());
        assert!(
            CanonicalStateOpeningScope {
                state_object_key: [7; 32],
                state_opening_epoch: 1,
            }
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn opening_scope_rejects_value_root_and_key_splices() {
        let archive = archive();
        let pre = opening(
            archive.state_object_key,
            archive.pre_state_commitment,
            archive.pre_state_root,
        );
        let post = opening(
            archive.state_object_key,
            archive.post_state_commitment,
            archive.post_state_root,
        );
        validate_opening_scope(&archive, &[pre.clone(), post.clone()])
            .expect("matching public scope");

        let mut wrong_key = pre.clone();
        wrong_key.key[0] ^= 1;
        assert!(validate_opening_scope(&archive, &[wrong_key, post.clone()]).is_err());

        let mut wrong_value = post.clone();
        wrong_value.value[0] ^= 1;
        assert!(validate_opening_scope(&archive, &[pre.clone(), wrong_value]).is_err());

        let mut wrong_root = post;
        wrong_root.root[0] ^= 1;
        assert!(validate_opening_scope(&archive, &[pre, wrong_root]).is_err());
    }
}
