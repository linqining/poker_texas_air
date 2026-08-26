//! Request-scoped composition of the currently available Reconstruction V3 AIRs.
//!
//! This is deliberately a *partial* composition boundary.  It verifies the
//! canonical state/request binding, the 52-card accumulator, the two
//! cross-key equations, and all 52 slot-OR equations against one common
//! `ZR3P` envelope and one common typed transcript output.  The Flock-BLAKE3
//! transcript/permutation AIR and Ristretto shuffle AIR are not represented by
//! this archive, so this module is not wired into production admission.
//!
//! The important property is that an integrator cannot accidentally compose
//! separately verified component archives with different requests, proof
//! envelopes, statement digests, or transcript challenge schedules.

#![allow(missing_docs)]

use borsh::{BorshDeserialize, BorshSerialize};
use poker_protocol::precompile_abi::{
    ReconstructionProofSystem, ReconstructionV3VerifyRequest, RistrettoAirV2SubmissionPackage,
    ShuffleProofSystem, ShuffleVerifyRequest,
};
use rayon::join;

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
use crate::ristretto_reconstruction_transcript::{
    ArchivedRistrettoFlockTranscriptProof, RistrettoPoseidonTranscriptChallenges,
};

/// Magic prefix for a serialized, composable Reconstruction V3 relation
/// archive.  This is intentionally distinct from the `ZR3P` proof wire:
/// `ZR3P` carries the protocol proof components while `ZR3A` carries the
/// STARK relation archives that verify those components.
pub const RISTRETTO_RECONSTRUCTION_RELATION_ARCHIVE_MAGIC: [u8; 4] = *b"ZR3A";
/// Version of the relation-archive container, not the Reconstruction V3 ABI.
pub const RISTRETTO_RECONSTRUCTION_RELATION_ARCHIVE_VERSION: u8 = 2;
const RELATION_ARCHIVE_DOMAIN: &[u8] =
    b"zchain.texas.ristretto-reconstruction-v3.relation-archive.v1";

/// A single request-scoped archive for every Reconstruction V3 relation that
/// currently has a direct AIR implementation.
///
/// `transcript` is the typed output boundary of the future transcript AIR.  The
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
    /// V2 Flock transcript proof.  Required when the request discriminator is
    /// `RistrettoAirV2`; absent only for the V1 compatibility archive.
    pub flock_transcript: Option<ArchivedRistrettoFlockTranscriptProof>,
    /// Two fixed-order cross-key equation proofs.
    pub cross_key: ArchivedRistrettoReconstructionCrossKeyBatchProof,
    /// 52 fixed-order slot-OR proofs.
    pub slot_or: ArchivedRistrettoReconstructionSlotOrBatchProof,
}

/// Strict outer serialization for [`ArchivedRistrettoReconstructionRelationBundle`].
///
/// The digest is an archive-transport integrity check, not a replacement for
/// any STARK verifier.  In particular, a producer can recompute it, so the
/// semantic checks in [`verify_ristretto_reconstruction_relation_bundle`] are
/// always required after decoding.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
struct RistrettoReconstructionRelationArchiveWire {
    version: u8,
    bundle: ArchivedRistrettoReconstructionRelationBundle,
    bundle_digest: [u8; 32],
}

/// Compute the transport digest over an already serialized bundle.  Keeping
/// this separate lets the archive encoder hash the exact bytes it is about to
/// emit, avoiding a second full serialization of the (often very large)
/// relation proofs.
fn relation_archive_digest_payload(payload: &[u8]) -> TexasAirResult<[u8; 32]> {
    let mut preimage = Vec::with_capacity(RELATION_ARCHIVE_DOMAIN.len() + payload.len());
    preimage.extend_from_slice(RELATION_ARCHIVE_DOMAIN);
    preimage.extend_from_slice(payload);
    Ok(crate::blake3_flock::blake3_chain_digest(&preimage))
}

fn encode_relation_archive_bytes(bundle_payload: &[u8], bundle_digest: [u8; 32]) -> Vec<u8> {
    // `RistrettoReconstructionRelationArchiveWire` is encoded as
    // `(version, bundle, digest)` by Borsh.  Assemble those fields directly so
    // callers can reuse the one serialized bundle payload and avoid cloning
    // the complete archive merely to compute its digest.
    let mut encoded = Vec::with_capacity(
        RISTRETTO_RECONSTRUCTION_RELATION_ARCHIVE_MAGIC.len()
            + 1
            + bundle_payload.len()
            + bundle_digest.len(),
    );
    encoded.extend_from_slice(&RISTRETTO_RECONSTRUCTION_RELATION_ARCHIVE_MAGIC);
    encoded.push(RISTRETTO_RECONSTRUCTION_RELATION_ARCHIVE_VERSION);
    encoded.extend_from_slice(bundle_payload);
    encoded.extend_from_slice(&bundle_digest);
    encoded
}

impl ArchivedRistrettoReconstructionRelationBundle {
    /// Serialize this relation bundle with a versioned, self-identifying
    /// archive boundary suitable for another prover or verifier process.
    pub fn encode_archive(&self) -> TexasAirResult<Vec<u8>> {
        // Serialize directly into the final output buffer.  The previous
        // implementation cloned the complete bundle and serialized it twice
        // (once for the digest and once for the wire), which briefly doubled
        // peak memory for large STARK archives.  Here the digest is computed
        // over the in-place bundle slice and only its fixed 32-byte result is
        // appended afterward.
        let prefix_len = RISTRETTO_RECONSTRUCTION_RELATION_ARCHIVE_MAGIC.len() + 1;
        let mut encoded = Vec::with_capacity(prefix_len);
        encoded.extend_from_slice(&RISTRETTO_RECONSTRUCTION_RELATION_ARCHIVE_MAGIC);
        encoded.push(RISTRETTO_RECONSTRUCTION_RELATION_ARCHIVE_VERSION);
        self.serialize(&mut encoded)
            .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
        let digest = relation_archive_digest_payload(&encoded[prefix_len..])?;
        encoded.extend_from_slice(&digest);
        Ok(encoded)
    }

    /// Decode a strict relation archive.  This verifies only its version,
    /// canonical encoding and transport digest; call the relation verifier to
    /// check the contained STARKs and statement bindings.
    pub fn decode_archive(bytes: &[u8]) -> TexasAirResult<Self> {
        if bytes.len() < RISTRETTO_RECONSTRUCTION_RELATION_ARCHIVE_MAGIC.len()
            || bytes[..RISTRETTO_RECONSTRUCTION_RELATION_ARCHIVE_MAGIC.len()]
                != RISTRETTO_RECONSTRUCTION_RELATION_ARCHIVE_MAGIC
        {
            return Err(TexasAirError::SerializationError(
                "Ristretto Reconstruction V3 relation-archive magic mismatch".into(),
            ));
        }
        let wire: RistrettoReconstructionRelationArchiveWire =
            borsh::from_slice(&bytes[RISTRETTO_RECONSTRUCTION_RELATION_ARCHIVE_MAGIC.len()..])
                .map_err(|error| {
                    TexasAirError::SerializationError(format!(
                        "Ristretto Reconstruction V3 relation-archive decode failed: {error}"
                    ))
                })?;
        if wire.version != RISTRETTO_RECONSTRUCTION_RELATION_ARCHIVE_VERSION {
            return Err(TexasAirError::SpecViolation(
                "unsupported Ristretto Reconstruction V3 relation-archive version".into(),
            ));
        }
        let bundle_payload = borsh::to_vec(&wire.bundle)
            .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
        if wire.bundle_digest != relation_archive_digest_payload(&bundle_payload)? {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "Ristretto Reconstruction V3 relation-archive digest is detached".into(),
            ));
        }
        if encode_relation_archive_bytes(&bundle_payload, wire.bundle_digest) != bytes {
            return Err(TexasAirError::SerializationError(
                "Ristretto Reconstruction V3 relation-archive is not canonically encoded".into(),
            ));
        }
        Ok(wire.bundle)
    }
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
    let transcript = if request.proof_system == ReconstructionProofSystem::RistrettoAirV2 {
        let flock = bundle.flock_transcript.as_ref().ok_or_else(|| {
            TexasAirError::HostZeroAdmissionIncomplete(
                "Ristretto AIR V2 relation bundle is missing its Flock transcript proof".into(),
            )
        })?;
        verify_ristretto_air_v2_flock_transcript(
            flock,
            envelope.statement_digest,
            envelope.component_digest,
        )?;
        let compat = flock.as_poseidon_compat();
        if compat.challenge != bundle.transcript.challenge
            || compat.retry_count != bundle.transcript.retry_count
            || compat.statement_digest != bundle.transcript.statement_digest
        {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "Ristretto AIR V2 relation challenges are detached from the Flock transcript"
                    .into(),
            ));
        }
        compat
    } else {
        bundle.transcript
    };
    validate_common_statement_digest(
        envelope.statement_digest,
        bundle.cross_key.statement_digest,
        bundle.slot_or.statement_digest,
        transcript.statement_digest,
    )?;
    for (index, equation) in bundle.cross_key.equations.iter().enumerate() {
        if equation.statement.statement_digest != envelope.statement_digest {
            return Err(TexasAirError::ConstraintUnsatisfied(format!(
                "cross-key equation {index} is detached from the common statement"
            )));
        }
    }
    for (index, statement) in bundle.slot_or.statements.iter().enumerate() {
        if statement.statement_digest != envelope.statement_digest
            || usize::from(statement.slot_index) != index
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
        &transcript,
        envelope.statement_digest,
    )?;
    let _ = RistrettoSlotOrTranscriptChallenges::from_poseidon_output(
        &transcript,
        envelope.statement_digest,
    )?;
    Ok(request)
}

/// Verify every currently implemented Reconstruction V3 relation in one
/// request-scoped composition.
///
/// Success means exactly the relations listed in the module-level docs have
/// been verified.  It does **not** mean a complete Reconstruction V3 proof:
/// callers still need the permutation/rerandomization shuffle AIR before a
/// production head may advance.  V2 additionally authenticates its challenge
/// schedule with the Flock transcript contained in the bundle.
pub fn verify_ristretto_reconstruction_relation_bundle(
    bundle: &ArchivedRistrettoReconstructionRelationBundle,
) -> TexasAirResult<()> {
    let request = validate_ristretto_reconstruction_relation_bundle_scope(bundle)?;
    let cross_challenges = RistrettoCrossKeyTranscriptChallenges::from_poseidon_output(
        &bundle.transcript,
        bundle.cross_key.statement_digest,
    )?;
    let (accumulator_result, relation_result) = join(
        || verify_canonical_reconstruction_accumulator_transition(&bundle.accumulator),
        || {
            let (cross_result, slot_result) = join(
                || {
                    verify_ristretto_reconstruction_cross_key_batch(
                        &request,
                        &cross_challenges,
                        &bundle.cross_key,
                    )
                },
                || {
                    let slot_challenges =
                        RistrettoSlotOrTranscriptChallenges::from_poseidon_output(
                            &bundle.transcript,
                            bundle.slot_or.statement_digest,
                        )?;
                    verify_ristretto_reconstruction_slot_or_batch(
                        &request,
                        &slot_challenges,
                        &bundle.slot_or,
                    )
                },
            );
            cross_result.and(slot_result)
        },
    );
    accumulator_result?;
    relation_result
}

/// Decode and verify a portable `ZR3A` relation archive.
///
/// This is the safe entry point for an archive received from another process:
/// it never treats a successful outer decode or digest check as proof
/// verification.
pub fn verify_ristretto_reconstruction_relation_archive(bytes: &[u8]) -> TexasAirResult<()> {
    let bundle = ArchivedRistrettoReconstructionRelationBundle::decode_archive(bytes)?;
    verify_ristretto_reconstruction_relation_bundle(&bundle)
}

/// Decode an externally submitted Reconstruction V3 statement and its `ZR3A`
/// relation archive as one inseparable proof package.
///
/// This is the server-side boundary for the Ristretto/AIR route.  It does not
/// construct a [`crate::precompile_binding::PrecompileCallBinding`] and never
/// invokes a native Bayer--Groth verifier.  The exact canonical request bytes
/// must be embedded in the archive's state-binding proof, so a valid archive
/// cannot be replayed against a different submitted deck, owner, call scope,
/// or reconstruction epoch.
pub fn decode_ristretto_reconstruction_relation_submission(
    request_bytes: &[u8],
    relation_archive_bytes: &[u8],
) -> TexasAirResult<ArchivedRistrettoReconstructionRelationBundle> {
    let request = ReconstructionV3VerifyRequest::decode(request_bytes).map_err(|error| {
        TexasAirError::SerializationError(format!(
            "Ristretto Reconstruction V3 submission request decode failed: {error}"
        ))
    })?;
    let canonical_request_bytes = request.encode().map_err(|error| {
        TexasAirError::SerializationError(format!(
            "Ristretto Reconstruction V3 submission request encoding failed: {error}"
        ))
    })?;
    if canonical_request_bytes != request_bytes {
        return Err(TexasAirError::SerializationError(
            "Ristretto Reconstruction V3 submission request is not canonically encoded".into(),
        ));
    }

    let bundle =
        ArchivedRistrettoReconstructionRelationBundle::decode_archive(relation_archive_bytes)?;
    if bundle.binding.request_bytes != canonical_request_bytes {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Ristretto Reconstruction V3 relation archive is detached from the submitted request"
                .into(),
        ));
    }
    Ok(bundle)
}

/// Verify all currently implemented AIR relations for an externally submitted
/// Ristretto Reconstruction V3 package.
///
/// Unlike the legacy `PrecompileAirBinding` route, the backend's result comes
/// solely from relation proofs contained in `relation_archive_bytes`.
pub fn verify_ristretto_reconstruction_relation_submission(
    request_bytes: &[u8],
    relation_archive_bytes: &[u8],
) -> TexasAirResult<()> {
    let bundle =
        decode_ristretto_reconstruction_relation_submission(request_bytes, relation_archive_bytes)?;
    verify_ristretto_reconstruction_relation_bundle(&bundle)
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
        "Reconstruction V3 transcript and shuffle AIRs are not composed".into(),
    ))
}

/// Production-shaped portable archive entry point.  It is deliberately the
/// same fail-closed boundary as [`admit_ristretto_reconstruction_relation_bundle`].
pub fn admit_ristretto_reconstruction_relation_archive(bytes: &[u8]) -> TexasAirResult<()> {
    let bundle = ArchivedRistrettoReconstructionRelationBundle::decode_archive(bytes)?;
    admit_ristretto_reconstruction_relation_bundle(&bundle)
}

/// Production admission boundary for an externally submitted Ristretto
/// Reconstruction V3 package.
///
/// This shares the same fail-closed completeness gate as the archive-only
/// helper, while additionally preventing archive/request substitution at the
/// protocol ingress.
pub fn admit_ristretto_reconstruction_relation_submission(
    request_bytes: &[u8],
    relation_archive_bytes: &[u8],
) -> TexasAirResult<()> {
    let bundle =
        decode_ristretto_reconstruction_relation_submission(request_bytes, relation_archive_bytes)?;
    admit_ristretto_reconstruction_relation_bundle(&bundle)
}

/// V2-only server boundary. The request discriminator and domain are checked
/// before any expensive STARK work, preventing a V1 archive from being
/// relabeled as the low-latency V2 schedule.
pub fn verify_ristretto_air_v2_submission(
    request_bytes: &[u8],
    relation_archive_bytes: &[u8],
) -> TexasAirResult<()> {
    let request = ReconstructionV3VerifyRequest::decode(request_bytes).map_err(|error| {
        TexasAirError::SerializationError(format!(
            "Ristretto AIR V2 request decode failed: {error}"
        ))
    })?;
    if request.proof_system != ReconstructionProofSystem::RistrettoAirV2
        || request.transcript != poker_protocol::precompile_abi::TranscriptId::FlockBlake3
        || request.context.as_slice()
            != poker_protocol::ristretto_air::RISTRETTO_AIR_V2_RECONSTRUCTION_CONTEXT
    {
        return Err(TexasAirError::SpecViolation(
            "Ristretto AIR V2 endpoint received a non-V2 reconstruction request".into(),
        ));
    }
    verify_ristretto_reconstruction_relation_submission(request_bytes, relation_archive_bytes)
}

/// Verify a self-contained `ZR4A` transport package.  Decoding the package
/// first makes request/archive substitution impossible at the API boundary.
pub fn verify_ristretto_air_v2_submission_package(package_bytes: &[u8]) -> TexasAirResult<()> {
    let package = RistrettoAirV2SubmissionPackage::decode_ref(package_bytes).map_err(|error| {
        TexasAirError::SerializationError(format!(
            "Ristretto AIR V2 package decode failed: {error}"
        ))
    })?;
    verify_ristretto_air_v2_submission(&package.request, &package.relation_archive)
}

/// Verify the Flock-BLAKE3 transcript proof that must accompany a V2 relation
/// bundle.  This helper is intentionally independent of the old Poseidon
/// challenge projection, so callers can validate the cheap transcript proof
/// before paying for the relation AIRs.
pub fn verify_ristretto_air_v2_flock_transcript(
    proof: &ArchivedRistrettoFlockTranscriptProof,
    statement_digest: [u8; 32],
    component_digest: [u8; 32],
) -> TexasAirResult<()> {
    if proof.statement_digest != statement_digest || proof.component_digest != component_digest {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Ristretto AIR V2 Flock transcript is detached from the statement".into(),
        ));
    }
    proof.verify()
}

/// Production V2 admission boundary.  Dispatches on the archive magic:
/// `ZR3N` routes to the complete low-latency native relation verifier
/// (Flock transcript + native sigma equations + native deck transition),
/// while the legacy `ZR3A` relation archive keeps its explicit fail-closed
/// completeness gate.
pub fn admit_ristretto_air_v2_submission(
    request_bytes: &[u8],
    relation_archive_bytes: &[u8],
) -> TexasAirResult<()> {
    if relation_archive_bytes.len() >= 4
        && relation_archive_bytes[..4]
            == crate::ristretto_reconstruction_v2_air::RISTRETTO_RECONSTRUCTION_V2_NATIVE_MAGIC
    {
        return crate::ristretto_reconstruction_v2_air::admit_ristretto_air_v2_native_submission(
            request_bytes,
            relation_archive_bytes,
        );
    }
    verify_ristretto_air_v2_submission(request_bytes, relation_archive_bytes)?;
    Err(TexasAirError::HostZeroAdmissionIncomplete(
        "Ristretto AIR V2 legacy relation archive lacks the native composition; use ZR3N".into(),
    ))
}

/// Fail-closed admission for the self-contained V2 transport package.  The
/// `relation_archive` part is dispatched exactly like
/// [`admit_ristretto_air_v2_submission`].
pub fn admit_ristretto_air_v2_submission_package(package_bytes: &[u8]) -> TexasAirResult<()> {
    let package = RistrettoAirV2SubmissionPackage::decode_ref(package_bytes).map_err(|error| {
        TexasAirError::SerializationError(format!(
            "Ristretto AIR V2 package decode failed: {error}"
        ))
    })?;
    admit_ristretto_air_v2_submission(&package.request, &package.relation_archive)
}

/// Decode and canonicalize a V2 52-card shuffle request at the server
/// boundary. No native Bayer--Groth verifier is reachable from this helper.
pub fn decode_ristretto_air_v2_shuffle_request(
    request_bytes: &[u8],
) -> TexasAirResult<ShuffleVerifyRequest> {
    let request = ShuffleVerifyRequest::decode(request_bytes).map_err(|error| {
        TexasAirError::SerializationError(format!(
            "Ristretto AIR V2 shuffle request decode failed: {error}"
        ))
    })?;
    if request.proof_system != ShuffleProofSystem::RistrettoAirV2
        || request.context.as_slice()
            != poker_protocol::ristretto_air::RISTRETTO_AIR_V2_SHUFFLE_CONTEXT
    {
        return Err(TexasAirError::SpecViolation(
            "Ristretto AIR V2 shuffle endpoint received a non-V2 request".into(),
        ));
    }
    let canonical = request.encode().map_err(|error| {
        TexasAirError::SerializationError(format!(
            "Ristretto AIR V2 shuffle request encoding failed: {error}"
        ))
    })?;
    if canonical != request_bytes {
        return Err(TexasAirError::SerializationError(
            "Ristretto AIR V2 shuffle request is not canonically encoded".into(),
        ));
    }
    Ok(request)
}

/// Production V2 shuffle admission.  The shuffle relation is complete in the
/// V2 envelope (Bayer--Groth argument + Flock transcript + canonical request
/// binding), so admission succeeds when that verifier accepts.
pub fn admit_ristretto_air_v2_shuffle_submission(request_bytes: &[u8]) -> TexasAirResult<()> {
    crate::ristretto_shuffle_air::admit_ristretto_air_v2_shuffle_submission(request_bytes)
}

/// Compile-time-facing marker for admission code and audit tooling.
///
/// Keeping this as a constant makes it harder for a future caller to infer
/// completeness from the existence of the bundle type alone.
pub const RISTRETTO_RECONSTRUCTION_RELATION_BUNDLE_COMPLETE: bool = false;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // The serialization boundary is intentionally independent from semantic
    // proof validity.  A zero-filled decode supplies a shape-complete but
    // invalid bundle cheaply, which is sufficient to test strict transport
    // encoding without manufacturing 54 expensive STARK proofs.
    fn malformed_bundle_for_wire_test() -> ArchivedRistrettoReconstructionRelationBundle {
        let mut bytes = Cursor::new(vec![0u8; 1_000_000]);
        ArchivedRistrettoReconstructionRelationBundle::deserialize_reader(&mut bytes)
            .expect("zero fixture covers the fixed archive layout")
    }

    fn submission_request(call_context: Vec<u8>) -> Vec<u8> {
        use poker_protocol::ristretto_air::{
            RistrettoAirCiphertext, RistrettoReconstructionV3Submission,
        };

        let ciphertext = RistrettoAirCiphertext {
            c1: [3; 32],
            c2: [4; 32],
        };
        RistrettoReconstructionV3Submission {
            context_digest: [1; 32],
            reconstruction_epoch: 9,
            prior_state_digest: [2; 32],
            aggregate_pk: [5; 32],
            owner_pk: [6; 32],
            user_readable_cards: [ciphertext; 2],
            contributions: [ciphertext; 52],
            // This test exercises only the request/archive transport binding;
            // relation validity is intentionally checked by the verifier API.
            air_proof: vec![7],
        }
        .to_verify_request(call_context)
        .unwrap()
        .encode()
        .unwrap()
    }

    #[test]
    fn relation_archive_roundtrip_is_versioned_and_strict() {
        let bundle = malformed_bundle_for_wire_test();
        let wire = bundle.encode_archive().unwrap();
        // The optimized encoder must remain byte-for-byte compatible with
        // the canonical Borsh representation used by the pre-optimization
        // implementation.
        let bundle_payload = borsh::to_vec(&bundle).unwrap();
        let digest = relation_archive_digest_payload(&bundle_payload).unwrap();
        let canonical_payload = borsh::to_vec(&RistrettoReconstructionRelationArchiveWire {
            version: RISTRETTO_RECONSTRUCTION_RELATION_ARCHIVE_VERSION,
            bundle: bundle.clone(),
            bundle_digest: digest,
        })
        .unwrap();
        let mut canonical_wire = Vec::with_capacity(
            RISTRETTO_RECONSTRUCTION_RELATION_ARCHIVE_MAGIC.len() + canonical_payload.len(),
        );
        canonical_wire.extend_from_slice(&RISTRETTO_RECONSTRUCTION_RELATION_ARCHIVE_MAGIC);
        canonical_wire.extend_from_slice(&canonical_payload);
        assert_eq!(wire, canonical_wire);
        assert_eq!(
            &wire[..RISTRETTO_RECONSTRUCTION_RELATION_ARCHIVE_MAGIC.len()],
            &RISTRETTO_RECONSTRUCTION_RELATION_ARCHIVE_MAGIC
        );
        assert_eq!(
            ArchivedRistrettoReconstructionRelationBundle::decode_archive(&wire).unwrap(),
            bundle
        );

        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(ArchivedRistrettoReconstructionRelationBundle::decode_archive(&trailing).is_err());

        let mut wrong_version = wire;
        wrong_version[RISTRETTO_RECONSTRUCTION_RELATION_ARCHIVE_MAGIC.len()] ^= 1;
        assert!(
            ArchivedRistrettoReconstructionRelationBundle::decode_archive(&wrong_version).is_err()
        );
    }

    #[test]
    fn relation_archive_rejects_magic_and_payload_splices() {
        let bundle = malformed_bundle_for_wire_test();
        let wire = bundle.encode_archive().unwrap();

        let mut wrong_magic = wire.clone();
        wrong_magic[0] ^= 1;
        assert!(
            ArchivedRistrettoReconstructionRelationBundle::decode_archive(&wrong_magic).is_err()
        );

        // The digest is the final fixed-width field in the wire.  Altering a
        // relation-archive payload without regenerating that binding fails at
        // the archive boundary, before any STARK verifier can be invoked.
        let mut payload_splice = wire;
        let payload_index = RISTRETTO_RECONSTRUCTION_RELATION_ARCHIVE_MAGIC.len() + 1;
        payload_splice[payload_index] ^= 1;
        assert!(
            ArchivedRistrettoReconstructionRelationBundle::decode_archive(&payload_splice).is_err()
        );
    }

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

    #[test]
    fn submission_rejects_an_archive_bound_to_a_different_request() {
        let archive_request = submission_request(vec![8; 32]);
        let submitted_request = submission_request(vec![9; 32]);
        let mut bundle = malformed_bundle_for_wire_test();
        bundle.binding.request_bytes = archive_request;
        let archive = bundle.encode_archive().unwrap();

        let error =
            decode_ristretto_reconstruction_relation_submission(&submitted_request, &archive)
                .expect_err("archive must bind the exact submitted request bytes");
        assert!(
            error
                .to_string()
                .contains("detached from the submitted request")
        );
    }

    #[test]
    fn v2_endpoint_rejects_a_v1_request_before_stark_verification() {
        let request = submission_request(vec![8; 32]);
        let mut bundle = malformed_bundle_for_wire_test();
        bundle.binding.request_bytes = request.clone();
        let archive = bundle.encode_archive().unwrap();
        let error = verify_ristretto_air_v2_submission(&request, &archive)
            .expect_err("V1 request must not enter the V2 endpoint");
        assert!(error.to_string().contains("non-V2 reconstruction request"));
    }

    #[test]
    fn v2_shuffle_boundary_rejects_a_v1_request() {
        use poker_protocol::ristretto_air::{RistrettoAirCiphertext, RistrettoShuffleSubmission};
        let submission = RistrettoShuffleSubmission {
            aggregate_pk: [3; 32],
            input: std::array::from_fn(|_| RistrettoAirCiphertext {
                c1: [4; 32],
                c2: [5; 32],
            }),
            output: std::array::from_fn(|_| RistrettoAirCiphertext {
                c1: [6; 32],
                c2: [7; 32],
            }),
            air_proof: vec![8; 32],
        };
        let request = submission.to_verify_request(vec![9; 32]).unwrap();
        let bytes = request.encode().unwrap();
        let error = decode_ristretto_air_v2_shuffle_request(&bytes)
            .expect_err("V1 shuffle request must not enter V2");
        assert!(error.to_string().contains("non-V2 request"));
    }
}
