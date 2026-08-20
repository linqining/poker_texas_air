//! Request-scoped composition of the currently available Reconstruction V3 AIRs.
//!
//! This is deliberately a *partial* composition boundary.  It verifies the
//! canonical state/request binding, the 52-card accumulator, the two
//! cross-key equations, and all 52 slot-OR equations against one common
//! `ZR3P` envelope and one common typed transcript output.  The Poseidon252
//! permutation/retry AIR and Bayer--Groth shuffle AIR are not represented by
//! this archive, so this module is not wired into production admission.
//!
//! The important property is that an integrator cannot accidentally compose
//! separately verified component archives with different requests, proof
//! envelopes, statement digests, or transcript challenge schedules.

#![allow(missing_docs)]

use borsh::{BorshDeserialize, BorshSerialize};
use poker_protocol::precompile_abi::ReconstructionV3VerifyRequest;

use crate::canonical_reconstruction_binding::ArchivedCanonicalReconstructionStateBindingProof;
use crate::error::{TexasAirError, TexasAirResult};
use crate::ristretto_reconstruction_accumulator_air::{
    ArchivedCanonicalReconstructionAccumulatorTransitionProof,
    verify_canonical_reconstruction_accumulator_transition,
};
use crate::ristretto_reconstruction_proof_wire::validate_ristretto_reconstruction_proof_wire;
use crate::ristretto_reconstruction_relation_air::{
    ArchivedRistrettoReconstructionCrossKeyBatchProof, RistrettoCrossKeyTranscriptChallenges,
    verify_ristretto_reconstruction_cross_key_batch,
};
use crate::ristretto_reconstruction_slot_or_air::{
    ArchivedRistrettoReconstructionSlotOrBatchProof, RistrettoSlotOrTranscriptChallenges,
    verify_ristretto_reconstruction_slot_or_batch,
};
use crate::ristretto_reconstruction_transcript::RistrettoPoseidonTranscriptChallenges;

/// A single request-scoped archive for every Reconstruction V3 relation that
/// currently has a direct AIR implementation.
///
/// `transcript` is the typed output boundary of the future Poseidon AIR.  The
/// value is range/digest checked here, but this module intentionally does not
/// treat host-provided challenge bytes as authenticated Fiat--Shamir output.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoReconstructionRelationBundle {
    /// Canonical state-image/request/hash binding.
    pub binding: ArchivedCanonicalReconstructionStateBindingProof,
    /// Accumulator and optional canonical initial deck proof.
    pub accumulator: ArchivedCanonicalReconstructionAccumulatorTransitionProof,
    /// Typed full transcript output consumed by both relation families.
    pub transcript: RistrettoPoseidonTranscriptChallenges,
    /// Two fixed-order cross-key equation proofs.
    pub cross_key: ArchivedRistrettoReconstructionCrossKeyBatchProof,
    /// 52 fixed-order slot-OR proofs.
    pub slot_or: ArchivedRistrettoReconstructionSlotOrBatchProof,
}

fn validate_common_statement_digest(
    envelope_digest: [u8; 32],
    cross_key_digest: [u8; 32],
    slot_or_digest: [u8; 32],
    transcript_digest: [u8; 32],
) -> TexasAirResult<()> {
    if cross_key_digest != envelope_digest
        || slot_or_digest != envelope_digest
        || transcript_digest != envelope_digest
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Reconstruction V3 bundle components are detached from the common statement digest"
                .into(),
        ));
    }
    Ok(())
}

/// Decode the request once and validate all cheap cross-component scope
/// bindings before running the individual STARK verifiers.
pub fn validate_ristretto_reconstruction_relation_bundle_scope(
    bundle: &ArchivedRistrettoReconstructionRelationBundle,
) -> TexasAirResult<ReconstructionV3VerifyRequest> {
    if bundle.accumulator.binding != bundle.binding {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Reconstruction V3 accumulator is detached from the bundle state/request binding"
                .into(),
        ));
    }
    let request =
        ReconstructionV3VerifyRequest::decode(&bundle.binding.request_bytes).map_err(|error| {
            TexasAirError::SerializationError(format!(
                "Reconstruction V3 bundle request decode failed: {error}"
            ))
        })?;
    let envelope = validate_ristretto_reconstruction_proof_wire(&request)?;
    validate_common_statement_digest(
        envelope.statement_digest,
        bundle.cross_key.statement_digest,
        bundle.slot_or.statement_digest,
        bundle.transcript.statement_digest,
    )?;
    for (index, equation) in bundle.cross_key.equations.iter().enumerate() {
        if equation.statement.statement_digest != envelope.statement_digest {
            return Err(TexasAirError::ConstraintUnsatisfied(format!(
                "cross-key equation {index} is detached from the common statement"
            )));
        }
    }
    for (index, slot) in bundle.slot_or.slots.iter().enumerate() {
        if slot.statement.statement_digest != envelope.statement_digest
            || usize::from(slot.statement.slot_index) != index
        {
            return Err(TexasAirError::ConstraintUnsatisfied(format!(
                "slot-OR equation {index} is detached from the common statement or order"
            )));
        }
    }
    // Projecting the full output is itself the fixed schedule boundary.  It
    // rejects zero/non-canonical scalars and prevents relation-specific
    // challenge arrays from silently selecting a different transcript slot.
    let _ = RistrettoCrossKeyTranscriptChallenges::from_poseidon_output(
        &bundle.transcript,
        envelope.statement_digest,
    )?;
    let _ = RistrettoSlotOrTranscriptChallenges::from_poseidon_output(
        &bundle.transcript,
        envelope.statement_digest,
    )?;
    Ok(request)
}

/// Verify every currently implemented Reconstruction V3 relation in one
/// request-scoped composition.
///
/// Success means exactly the relations listed in the module-level docs have
/// been verified.  It does **not** mean a complete Reconstruction V3 proof:
/// callers still need the Poseidon permutation/retry and Bayer--Groth shuffle
/// AIRs before a production head may advance.
pub fn verify_ristretto_reconstruction_relation_bundle(
    bundle: &ArchivedRistrettoReconstructionRelationBundle,
) -> TexasAirResult<()> {
    let request = validate_ristretto_reconstruction_relation_bundle_scope(bundle)?;
    verify_canonical_reconstruction_accumulator_transition(&bundle.accumulator)?;
    let cross_challenges = RistrettoCrossKeyTranscriptChallenges::from_poseidon_output(
        &bundle.transcript,
        bundle.cross_key.statement_digest,
    )?;
    verify_ristretto_reconstruction_cross_key_batch(
        &request,
        &cross_challenges,
        &bundle.cross_key,
    )?;
    let slot_challenges = RistrettoSlotOrTranscriptChallenges::from_poseidon_output(
        &bundle.transcript,
        bundle.slot_or.statement_digest,
    )?;
    verify_ristretto_reconstruction_slot_or_batch(&request, &slot_challenges, &bundle.slot_or)?;
    Ok(())
}

/// Production-shaped entry point for this partial bundle.
///
/// It verifies the available relations first, then refuses to advance an
/// admission head until transcript permutation/retry and shuffle AIRs are
/// present.  Keeping this explicit API beside the audit verifier prevents a
/// caller from treating `verify_*` success as a complete V3 credential.
pub fn admit_ristretto_reconstruction_relation_bundle(
    bundle: &ArchivedRistrettoReconstructionRelationBundle,
) -> TexasAirResult<()> {
    verify_ristretto_reconstruction_relation_bundle(bundle)?;
    Err(TexasAirError::HostZeroAdmissionIncomplete(
        "Reconstruction V3 Poseidon transcript and Bayer--Groth shuffle AIRs are not composed"
            .into(),
    ))
}

/// Compile-time-facing marker for admission code and audit tooling.
///
/// Keeping this as a constant makes it harder for a future caller to infer
/// completeness from the existence of the bundle type alone.
pub const RISTRETTO_RECONSTRUCTION_RELATION_BUNDLE_COMPLETE: bool = false;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scope_rejects_component_digest_splice_before_stark_verification() {
        let digest = [7; 32];
        let mut slot_digest = digest;
        slot_digest[0] ^= 1;
        let error =
            validate_common_statement_digest(digest, digest, slot_digest, digest).unwrap_err();
        assert!(error.to_string().contains("common statement digest"));
    }

    #[test]
    fn scope_rejects_transcript_statement_splice_before_relation_projection() {
        let digest = [8; 32];
        let mut transcript_digest = digest;
        transcript_digest[0] ^= 1;
        let error = validate_common_statement_digest(digest, digest, digest, transcript_digest)
            .unwrap_err();
        assert!(error.to_string().contains("common statement digest"));
    }
}
