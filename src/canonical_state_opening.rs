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
use crate::canonical_reveal_opening::{
    ArchivedCanonicalRevealLedgerOpening, CanonicalRevealLedgerOpening,
    prove_canonical_reveal_ledger_opening, verify_canonical_reveal_ledger_opening,
};
use crate::canonical_state_hash::{
    ArchivedCanonicalStateImageHashProof, CANONICAL_STATE_IMAGE_DOMAIN,
    prove_canonical_state_image_hashes, verify_canonical_state_image_hashes,
};
use crate::error::{TexasAirError, TexasAirResult};
use crate::texas_canonical::CanonicalTransitionKind;
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
/// canonical AIR binds its fixed 852-limb state-image projection to these
/// endpoint bytes, but complete VM settlement and Ristretto crypto relations
/// are still required before a table head can change.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedCanonicalStateImageOpeningProof {
    pub opening: ArchivedCanonicalStateOpeningProof,
    pub state_image_hashes: ArchivedCanonicalStateImageHashProof,
}

/// Complete currently-available composition for a reveal-dependent canonical
/// transition: transition AIR, authenticated pre/post state images and roots,
/// plus the fixed-width reveal-assignment ledger consumed by timeout logic.
///
/// This is still a building block for production admission; terminal VM
/// continuation and the Ristretto protocol relations remain separate gates.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedCanonicalStateImageRevealOpeningProof {
    pub opening: ArchivedCanonicalStateImageOpeningProof,
    pub reveal: ArchivedCanonicalRevealLedgerOpening,
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

/// Verify a canonical transition and its batched L1 state-object openings.
///
/// This standalone audit helper retains the legacy native endpoint-commitment
/// check.  The host-zero composition must use
/// [`verify_canonical_batch_with_state_image_openings`], which supplies the
/// byte-to-commitment relation through its dedicated hash AIR.
pub fn verify_canonical_batch_with_state_openings(
    archive: &ArchivedCanonicalStateOpeningProof,
) -> TexasAirResult<()> {
    validate_opening_scope(&archive.canonical, &archive.state_openings.paths)?;
    verify_canonical_tagged_proof(&archive.canonical)?;
    verify_blake2b_lookup_smt_fixed_value_paths(&archive.state_openings)
}

fn verify_canonical_batch_with_state_openings_for_image(
    archive: &ArchivedCanonicalStateOpeningProof,
) -> TexasAirResult<()> {
    validate_opening_scope(&archive.canonical, &archive.state_openings.paths)?;
    crate::texas_canonical_air::verify_canonical_tagged_proof_for_state_opening(
        &archive.canonical,
    )?;
    verify_blake2b_lookup_smt_fixed_value_paths(&archive.state_openings)
}

/// Verify a canonical transition together with an authenticated pre-state
/// reveal ledger.  This is the composition boundary consumed by the future
/// reveal-timeout AIR: the ledger digest is checked against the pre-image's
/// `reveal_commitment`, so a host cannot replace assignment pending masks with
/// an independently chosen union.
fn verify_canonical_batch_with_reveal_opening_unchecked(
    archive: &ArchivedCanonicalStateOpeningProof,
    reveal: &ArchivedCanonicalRevealLedgerOpening,
) -> TexasAirResult<()> {
    verify_canonical_batch_with_state_openings_for_image(archive)?;
    let (pre, _) = crate::texas_canonical_air::validate_state_image_bytes_without_commitment(
        &archive.canonical,
    )?;
    reveal.opening.validate_for_pre_state(&pre)?;
    verify_canonical_reveal_ledger_opening(reveal, pre.reveal_commitment)
}

/// Verify the authenticated reveal-ledger sidecar against the canonical
/// pre-state. Callers that need to establish the transition kind for
/// admission must use [`verify_canonical_reveal_timeout_batch_with_opening`],
/// which also binds the witness batch digest.
pub fn verify_canonical_batch_with_reveal_opening(
    archive: &ArchivedCanonicalStateOpeningProof,
    reveal: &ArchivedCanonicalRevealLedgerOpening,
) -> TexasAirResult<()> {
    if archive.canonical.reveal_timeout_cascade_count == 0 {
        verify_canonical_reveal_timeout_with_opening(archive, reveal)
    } else {
        verify_canonical_reveal_timeout_cascade_with_opening(archive, reveal)
    }
}

/// Verify the reveal-timeout composition while binding the sidecar to the
/// public transition-kind scope.  The first/last kind fields are themselves
/// constrained against the first/last tagged trace row by the canonical AIR,
/// so this verifier does not replay or deserialize any transaction witness.
pub fn verify_canonical_reveal_timeout_with_opening(
    archive: &ArchivedCanonicalStateOpeningProof,
    reveal: &ArchivedCanonicalRevealLedgerOpening,
) -> TexasAirResult<()> {
    let canonical = &archive.canonical;
    if canonical.transition_count != 1
        || canonical.first_transition_kind != CanonicalTransitionKind::RevealTimeoutReset as u8
        || canonical.last_transition_kind != CanonicalTransitionKind::RevealTimeoutReset as u8
        || canonical.reveal_timeout_cascade_count != 0
    {
        return Err(TexasAirError::SpecViolation(
            "reveal-timeout reset composition requires exactly one reset transition".into(),
        ));
    }
    verify_canonical_batch_with_reveal_opening_unchecked(archive, reveal)
}

fn validate_reveal_cascade_schedule_binding(
    canonical: &ArchivedCanonicalTaggedProof,
    reveal: &ArchivedCanonicalRevealLedgerOpening,
) -> TexasAirResult<()> {
    let expected: Vec<u8> = reveal
        .pending_union
        .kick_schedule
        .iter()
        .copied()
        .filter(|seat| *seat != crate::canonical_reveal_opening::REVEAL_TIMEOUT_SCHEDULE_EMPTY)
        .collect();
    // `kick_player_internal` reaches a terminal continuation on the last
    // pending participant. The tagged batch may carry the preceding same-phase
    // prefix and, when available, the typed final preflop reset continuation.
    let prefix_len = expected.len().checked_sub(1).ok_or_else(|| {
        TexasAirError::ConstraintUnsatisfied(
            "reveal-timeout kick batch requires at least one terminal schedule entry".into(),
        )
    })?;
    let kick_count = canonical.reveal_timeout_cascade_count as usize;
    let terminal_continuation = canonical.transition_count == kick_count as u16 + 1
        && canonical.last_transition_kind == CanonicalTransitionKind::RevealTimeoutReset as u8;
    if kick_count != prefix_len
        || canonical.reveal_timeout_cascade_schedule[..prefix_len] != expected[..prefix_len]
        || (!terminal_continuation
            && canonical.transition_count != canonical.reveal_timeout_cascade_count as u16)
        || (terminal_continuation
            && canonical.reveal_timeout_cascade_schedule[prefix_len] != expected[prefix_len])
        || canonical.reveal_timeout_cascade_schedule[if terminal_continuation {
            prefix_len + 1
        } else {
            prefix_len
        }..]
            .iter()
            .any(|seat| *seat != crate::texas_canonical_air::REVEAL_TIMEOUT_CASCADE_EMPTY_SEAT)
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "canonical reveal-timeout schedule is detached from the authenticated pending union"
                .into(),
        ));
    }
    Ok(())
}

/// Verify a multi-row reveal-timeout cascade. The compact seat schedule is
/// committed by the canonical tagged AIR and must equal the authenticated
/// ledger schedule, either as a strict non-terminal prefix or with a final
/// typed preflop reset continuation.
pub fn verify_canonical_reveal_timeout_cascade_with_opening(
    archive: &ArchivedCanonicalStateOpeningProof,
    reveal: &ArchivedCanonicalRevealLedgerOpening,
) -> TexasAirResult<()> {
    let canonical = &archive.canonical;
    if canonical.transition_count == 0
        || canonical.first_transition_kind != CanonicalTransitionKind::RevealTimeoutKick as u8
        || canonical.reveal_timeout_cascade_count == 0
    {
        return Err(TexasAirError::SpecViolation(
            "reveal-timeout cascade requires a dedicated non-terminal kick batch".into(),
        ));
    }
    verify_canonical_batch_with_reveal_opening_unchecked(archive, reveal)?;
    validate_reveal_cascade_schedule_binding(canonical, reveal)
}

/// Compatibility verifier for callers that retain their original witness
/// batch.  This only checks the public digest against that batch; the proof
/// semantics are verified by [`verify_canonical_reveal_timeout_with_opening`]
/// without invoking native transition validation or replay.
pub fn verify_canonical_reveal_timeout_batch_with_opening(
    witnesses: &[CanonicalTransitionWitness],
    archive: &ArchivedCanonicalStateOpeningProof,
    reveal: &ArchivedCanonicalRevealLedgerOpening,
) -> TexasAirResult<()> {
    if archive.canonical.batch_digest
        != crate::texas_canonical_air::batch_digest_for_witnesses(witnesses)
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "canonical proof batch digest is detached from reveal-timeout witness".into(),
        ));
    }
    verify_canonical_reveal_timeout_with_opening(archive, reveal)
}

/// Prove the canonical transition and an authenticated opening of its
/// pre-state reveal ledger.  The returned archives are deliberately separate:
/// the transition/state-object proof remains ABI-compatible while the reveal
/// sidecar can be attached only to transitions that actually consume it.
pub fn prove_canonical_batch_with_reveal_opening(
    witnesses: &[CanonicalTransitionWitness],
    state_opening: CanonicalStateOpeningScope,
    pre_state_opening: &Blake2bSmtFixedValuePathWitness,
    post_state_opening: &Blake2bSmtFixedValuePathWitness,
    reveal: CanonicalRevealLedgerOpening,
) -> TexasAirResult<(
    ArchivedCanonicalStateOpeningProof,
    ArchivedCanonicalRevealLedgerOpening,
)> {
    let is_reset =
        witnesses.len() == 1 && witnesses[0].kind == CanonicalTransitionKind::RevealTimeoutReset;
    let is_cascade = witnesses.len() >= 1
        && (witnesses
            .iter()
            .all(|w| w.kind == CanonicalTransitionKind::RevealTimeoutKick)
            || (witnesses.len() >= 2
                && witnesses[..witnesses.len() - 1]
                    .iter()
                    .all(|w| w.kind == CanonicalTransitionKind::RevealTimeoutKick)
                && witnesses
                    .last()
                    .is_some_and(|w| w.kind == CanonicalTransitionKind::RevealTimeoutReset)));
    if !is_reset && !is_cascade {
        return Err(TexasAirError::SpecViolation(
            "reveal ledger sidecar requires a reset or dedicated kick batch".into(),
        ));
    }
    let archive = prove_canonical_batch_with_state_openings(
        witnesses,
        state_opening,
        pre_state_opening,
        post_state_opening,
    )?;
    let (pre, _) = crate::texas_canonical_air::validate_canonical_state_image_scope_for_opening(
        &archive.canonical,
    )?;
    reveal.validate_for_pre_state(&pre)?;
    let reveal_archive = prove_canonical_reveal_ledger_opening(reveal)?;
    let reveal_digest = reveal_archive
        .hash
        .statements()
        .first()
        .map(|statement| statement.digest)
        .ok_or_else(|| {
            TexasAirError::ConstraintUnsatisfied(
                "reveal ledger opening hash proof must cover exactly one statement".into(),
            )
        })?;
    if reveal_digest != pre.reveal_commitment {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "revealed ledger opening does not match the pre-state reveal commitment".into(),
        ));
    }
    if is_cascade {
        validate_reveal_cascade_schedule_binding(&archive.canonical, &reveal_archive)?;
    }
    Ok((archive, reveal_archive))
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
    verify_canonical_batch_with_state_openings_for_image(&archive.opening)?;
    verify_canonical_state_image_hashes(
        &archive.state_image_hashes,
        archive.opening.canonical.pre_state_commitment,
        archive.opening.canonical.post_state_commitment,
    )?;
    validate_state_hash_byte_binding(&archive.opening, &archive.state_image_hashes)
}

/// Prove the state-image composition together with an authenticated reveal
/// ledger.  No transaction bytes or VM replay are included in this archive.
pub fn prove_canonical_batch_with_state_image_and_reveal_opening(
    witnesses: &[CanonicalTransitionWitness],
    state_opening: CanonicalStateOpeningScope,
    pre_state_opening: &Blake2bSmtFixedValuePathWitness,
    post_state_opening: &Blake2bSmtFixedValuePathWitness,
    reveal: CanonicalRevealLedgerOpening,
) -> TexasAirResult<ArchivedCanonicalStateImageRevealOpeningProof> {
    let is_reset =
        witnesses.len() == 1 && witnesses[0].kind == CanonicalTransitionKind::RevealTimeoutReset;
    let is_cascade = witnesses.len() >= 1
        && (witnesses
            .iter()
            .all(|witness| witness.kind == CanonicalTransitionKind::RevealTimeoutKick)
            || (witnesses.len() >= 2
                && witnesses[..witnesses.len() - 1]
                    .iter()
                    .all(|witness| witness.kind == CanonicalTransitionKind::RevealTimeoutKick)
                && witnesses.last().is_some_and(|witness| {
                    witness.kind == CanonicalTransitionKind::RevealTimeoutReset
                })));
    if !is_reset && !is_cascade {
        return Err(TexasAirError::SpecViolation(
            "reveal sidecar requires a reset or dedicated kick batch".into(),
        ));
    }
    let opening = prove_canonical_batch_with_state_image_openings(
        witnesses,
        state_opening,
        pre_state_opening,
        post_state_opening,
    )?;
    let (pre, _) = crate::texas_canonical_air::validate_state_image_bytes_without_commitment(
        &opening.opening.canonical,
    )?;
    reveal.validate_for_pre_state(&pre)?;
    let reveal = prove_canonical_reveal_ledger_opening(reveal)?;
    let reveal_digest = reveal
        .hash
        .statements()
        .first()
        .map(|statement| statement.digest)
        .ok_or_else(|| {
            TexasAirError::ConstraintUnsatisfied(
                "reveal ledger opening hash proof must cover exactly one statement".into(),
            )
        })?;
    if reveal_digest != pre.reveal_commitment {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "reveal ledger opening does not match the pre-state reveal commitment".into(),
        ));
    }
    if is_cascade {
        validate_reveal_cascade_schedule_binding(&opening.opening.canonical, &reveal)?;
    }
    Ok(ArchivedCanonicalStateImageRevealOpeningProof { opening, reveal })
}

/// Verify the complete currently-available reveal-dependent composition using
/// only archive statements and Stwo verifiers.
pub fn verify_canonical_batch_with_state_image_and_reveal_opening(
    archive: &ArchivedCanonicalStateImageRevealOpeningProof,
) -> TexasAirResult<()> {
    verify_canonical_batch_with_state_image_openings(&archive.opening)?;
    verify_canonical_batch_with_reveal_opening(&archive.opening.opening, &archive.reveal)
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
            first_transition_kind: 0,
            last_transition_kind: 0,
            reveal_timeout_cascade_count: 0,
            reveal_timeout_cascade_schedule:
                [crate::texas_canonical_air::REVEAL_TIMEOUT_CASCADE_EMPTY_SEAT;
                    crate::texas_canonical_air::MAX_REVEAL_TIMEOUT_CASCADE_KICKS],
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
            range_claimed_sum: [0, 0, 0, 0],
            rake_opening: None,
            rules_hash: None,
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

    fn reveal_archive_with_schedule(
        pending_union: u16,
        schedule: [u8; 9],
    ) -> ArchivedCanonicalRevealLedgerOpening {
        let mut assignments =
            [crate::canonical_reveal_opening::CanonicalRevealAssignmentOpening::EMPTY;
                crate::canonical_reveal_opening::MAX_CANONICAL_REVEAL_ASSIGNMENTS];
        assignments[0] = crate::canonical_reveal_opening::CanonicalRevealAssignmentOpening {
            present: true,
            pending_mask: pending_union,
            ..crate::canonical_reveal_opening::CanonicalRevealAssignmentOpening::EMPTY
        };
        ArchivedCanonicalRevealLedgerOpening {
            magic: crate::canonical_reveal_opening::CANONICAL_REVEAL_OPENING_MAGIC,
            version: crate::canonical_reveal_opening::CANONICAL_REVEAL_OPENING_VERSION,
            opening: CanonicalRevealLedgerOpening {
                phase: 1,
                street: 1,
                assignment_count: 1,
                pending_union,
                assignments,
            },
            pending_union:
                crate::canonical_reveal_opening::ArchivedCanonicalRevealPendingUnionProof {
                    kick_schedule: schedule,
                    stark_proof_bytes: Vec::new(),
                },
            hash: crate::hash_prover::ArchivedHashProof::Flock(
                crate::blake3_flock::ArchivedFlockHashesProof {
                    statements: Vec::new(),
                    chains: Vec::new(),
                    merkles: Vec::new(),
                },
            ),
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

    #[test]
    fn reveal_cascade_binding_accepts_only_authenticated_strict_prefix() {
        let empty = crate::canonical_reveal_opening::REVEAL_TIMEOUT_SCHEDULE_EMPTY;
        let reveal = reveal_archive_with_schedule(
            0b111,
            [0, 1, 2, empty, empty, empty, empty, empty, empty],
        );
        let mut canonical = archive();
        canonical.first_transition_kind = CanonicalTransitionKind::RevealTimeoutKick as u8;
        canonical.last_transition_kind = CanonicalTransitionKind::RevealTimeoutKick as u8;
        canonical.transition_count = 2;
        canonical.reveal_timeout_cascade_count = 2;
        canonical.reveal_timeout_cascade_schedule[0] = 0;
        canonical.reveal_timeout_cascade_schedule[1] = 1;
        validate_reveal_cascade_schedule_binding(&canonical, &reveal).unwrap();

        canonical.reveal_timeout_cascade_schedule[1] = 2;
        assert!(validate_reveal_cascade_schedule_binding(&canonical, &reveal).is_err());
        canonical.reveal_timeout_cascade_schedule[1] = 1;
        canonical.reveal_timeout_cascade_count = 3;
        assert!(validate_reveal_cascade_schedule_binding(&canonical, &reveal).is_err());
    }

    #[test]
    fn reveal_cascade_binding_rejects_detached_pending_union_schedule() {
        let empty = crate::canonical_reveal_opening::REVEAL_TIMEOUT_SCHEDULE_EMPTY;
        let reveal = reveal_archive_with_schedule(
            0b101,
            [0, 2, empty, empty, empty, empty, empty, empty, empty],
        );
        let mut canonical = archive();
        canonical.first_transition_kind = CanonicalTransitionKind::RevealTimeoutKick as u8;
        canonical.last_transition_kind = CanonicalTransitionKind::RevealTimeoutKick as u8;
        canonical.transition_count = 1;
        canonical.reveal_timeout_cascade_count = 1;
        canonical.reveal_timeout_cascade_schedule[0] = 1;
        assert!(validate_reveal_cascade_schedule_binding(&canonical, &reveal).is_err());
    }

    #[test]
    fn reveal_cascade_binding_requires_terminal_reset_seat() {
        let empty = crate::canonical_reveal_opening::REVEAL_TIMEOUT_SCHEDULE_EMPTY;
        let reveal = reveal_archive_with_schedule(
            0b101,
            [0, 2, empty, empty, empty, empty, empty, empty, empty],
        );
        let mut canonical = archive();
        canonical.first_transition_kind = CanonicalTransitionKind::RevealTimeoutKick as u8;
        canonical.last_transition_kind = CanonicalTransitionKind::RevealTimeoutReset as u8;
        canonical.transition_count = 2;
        canonical.reveal_timeout_cascade_count = 1;
        canonical.reveal_timeout_cascade_schedule[0] = 0;
        canonical.reveal_timeout_cascade_schedule[1] = 2;
        validate_reveal_cascade_schedule_binding(&canonical, &reveal).unwrap();

        canonical.reveal_timeout_cascade_schedule[1] = 1;
        assert!(validate_reveal_cascade_schedule_binding(&canonical, &reveal).is_err());
    }
}
