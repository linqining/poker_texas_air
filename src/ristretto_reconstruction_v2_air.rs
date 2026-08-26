//! RistrettoAirV2 native reconstruction route: the complete Reconstruction V3
//! relation at low latency.
//!
//! # What this module replaces and what it keeps
//!
//! The V1 relation bundle proves the cross-key and slot-membership sigma
//! equations by expanding every scalar multiplication into compressed
//! Fp-program rows (416 scalar multiplications per submission, the dominant
//! cost of the historical ~1.27 GB archives).  This V2 route keeps the same
//! public wire (the `ZR3P` envelope already carries the sigma wires) and
//! verifies those equations natively against Flock-transcript challenges,
//! mirroring the trust model already accepted for the V2 shuffle:
//!
//! - the Fiat--Shamir challenge schedule is authenticated by the Flock
//!   transcript STARK, seeded over a commitments-only digest so the standard
//!   commit-then-challenge ordering holds without circularity;
//! - the sigma equations and the Bayer--Groth contribution-shuffle argument
//!   are deterministic public-equation checks (native curve algebra over
//!   public points), the same trust class as the V2 shuffle verifier;
//! - the state/request binding and the deck accumulator remain STARKs.
//!
//! # Privacy
//!
//! The readable-to-canonical slot mapping stays hidden: the slot-membership
//! OR wires carry only blinded commitments/responses, and the mapping itself
//! lives solely inside the Bayer--Groth witness.  No witness enters any
//! transparent STARK trace.
//!
//! # Cost profile
//!
//! Client proving is native sigma algebra plus one small Flock STARK for the
//! transcript chains (sub-second).  Server verification is ~520 native
//! scalar multiplications (~tens of milliseconds) plus three small STARK
//! verifications.  The 416-multiplication Fp-program expansion is no longer
//! produced at all.

#![allow(missing_docs)]

use borsh::{BorshDeserialize, BorshSerialize};
use rand_core::{CryptoRng, RngCore};

use poker_protocol::precompile_abi::{ReconstructionV3VerifyRequest, TranscriptId};
use poker_protocol_bg::BayerGrothShuffleProof;
use poker_protocol_core::{
    Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric, RistrettoCurve,
};
use rayon::prelude::*;

use crate::canonical_reconstruction_binding::{
    ArchivedCanonicalReconstructionStateBindingProof, CANONICAL_RECONSTRUCTION_CARDS,
    CanonicalReconstructionStateOpening, CanonicalRistrettoCiphertext,
};
use crate::error::{TexasAirError, TexasAirResult};
use crate::hash_prover::{ArchivedHashProof, Blake2bStatement, HashProofProvider};
use crate::ristretto_reconstruction_proof_wire::{
    RistrettoBayerGrothShuffleProofWire, RistrettoCiphertextProofWire, RistrettoCrossKeyProofWire,
    RistrettoReconstructionProofEnvelope, RistrettoSlotOrProofWire,
    reconstruction_v3_statement_digest, validate_ristretto_reconstruction_proof_wire,
};
use crate::ristretto_reconstruction_relation_air::RistrettoCrossKeyTranscriptChallenges;
use crate::ristretto_reconstruction_slot_or_air::RistrettoSlotOrTranscriptChallenges;
use crate::ristretto_reconstruction_transcript::ArchivedRistrettoFlockTranscriptProof;
use crate::ristretto_shuffle_air::{
    FlockShuffleTranscript, RistrettoShuffleV2ChallengeWire, run_bayer_groth_verify,
};
use crate::texas_canonical::CanonicalTransitionWitness;

/// Magic prefix of the serialized V2 native reconstruction relation archive.
pub const RISTRETTO_RECONSTRUCTION_V2_NATIVE_MAGIC: [u8; 4] = *b"ZR3N";
/// Version of the V2 native relation-archive container.
pub const RISTRETTO_RECONSTRUCTION_V2_NATIVE_VERSION: u8 = 1;
/// Digest domain over the commitment fields of the `ZR3P` envelope.  The
/// Fiat--Shamir challenges of the sigma relations are derived from
/// `(statement_digest, commitments_digest)` so that challenge derivation
/// precedes every response without a digest circularity.
pub const RISTRETTO_RECONSTRUCTION_V2_COMMITMENTS_DOMAIN: &[u8] =
    b"zchain.texas.ristretto-air-v2.reconstruction.commitments.v1";
/// Transcript protocol name for the contribution shuffle argument.
pub const RISTRETTO_RECONSTRUCTION_V2_SHUFFLE_PROTOCOL: &[u8] =
    b"poker/ristretto-air/reconstruction/v2/contribution-shuffle";

type RistrettoPoint = <RistrettoCurve as Curve>::Point;
type RistrettoScalar = <RistrettoCurve as Curve>::Scalar;
type RistrettoCiphertext = ElGamalCiphertextGeneric<RistrettoCurve>;

const READABLE_COUNT: usize = 2;
const SLOT_COUNT: usize = CANONICAL_RECONSTRUCTION_CARDS;

fn native_hash(message: &[u8]) -> [u8; 32] {
    use blake2::digest::{Update, VariableOutput};
    let mut hasher = blake2::Blake2bVar::new(32).expect("blake2b 32");
    hasher.update(message);
    let mut digest = [0u8; 32];
    hasher
        .finalize_variable(&mut digest)
        .expect("blake2b finalize");
    digest
}

fn chain_digest(message: &[u8]) -> [u8; 32] {
    crate::blake3_flock::blake3_chain_digest(message)
}

fn decode_point(bytes: &[u8; 32], label: &str) -> TexasAirResult<RistrettoPoint> {
    RistrettoPoint::from_compressed(bytes).ok_or_else(|| {
        TexasAirError::SpecViolation(format!("reconstruction {label} failed to decompress"))
    })
}

fn decode_scalar(bytes: &[u8; 32], label: &str) -> TexasAirResult<RistrettoScalar> {
    <RistrettoScalar as CurveScalar>::from_canonical_bytes(bytes).ok_or_else(|| {
        TexasAirError::SpecViolation(format!("reconstruction {label} is not canonically encoded"))
    })
}

fn decode_ciphertext(
    wire: &RistrettoCiphertextProofWire,
    label: &str,
) -> TexasAirResult<RistrettoCiphertext> {
    Ok(RistrettoCiphertext {
        c1: decode_point(&wire.c1, &format!("{label}.c1"))?,
        c2: decode_point(&wire.c2, &format!("{label}.c2"))?,
    })
}

fn point_bytes(point: &RistrettoPoint) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(point.compress().as_bytes());
    out
}

fn scalar_bytes(scalar: &RistrettoScalar) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = scalar.as_bytes();
    out.copy_from_slice(&bytes[..32]);
    out
}

fn scalar_from_bytes(bytes: &[u8; 32], label: &str) -> TexasAirResult<RistrettoScalar> {
    decode_scalar(bytes, label)
}

/// Digest over exactly the commitment fields of one `ZR3P` envelope: the
/// negative contributions, the cross-key commitments, the slot-membership
/// commitments, and the Bayer--Groth commitments.  Responses are excluded by
/// construction so challenge derivation can precede them.
pub fn reconstruction_v2_commitments_digest(
    envelope: &RistrettoReconstructionProofEnvelope,
) -> TexasAirResult<[u8; 32]> {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(RISTRETTO_RECONSTRUCTION_V2_COMMITMENTS_DOMAIN);
    preimage.extend_from_slice(&envelope.statement_digest);
    for negative in &envelope.negative_contributions {
        preimage.extend_from_slice(&negative.c1);
        preimage.extend_from_slice(&negative.c2);
    }
    for cross_key in &envelope.cross_key_proofs {
        preimage.extend_from_slice(&cross_key.commitment_owner_key);
        preimage.extend_from_slice(&cross_key.commitment_contribution_c1);
        preimage.extend_from_slice(&cross_key.commitment_joint_c2);
    }
    for slot_or in &envelope.slot_or_proofs {
        for point in &slot_or.commitment_g {
            preimage.extend_from_slice(point);
        }
        for point in &slot_or.commitment_pk {
            preimage.extend_from_slice(point);
        }
    }
    let shuffle = &envelope.shuffle_proof;
    preimage.extend_from_slice(&shuffle.c_permutation);
    preimage.extend_from_slice(&shuffle.c_permuted_powers);
    preimage.extend_from_slice(&shuffle.c_alpha);
    preimage.extend_from_slice(&shuffle.c_beta);
    preimage.extend_from_slice(&shuffle.ciphertext_0.c1);
    preimage.extend_from_slice(&shuffle.ciphertext_0.c2);
    preimage.extend_from_slice(&shuffle.ciphertext_1.c1);
    preimage.extend_from_slice(&shuffle.ciphertext_1.c2);
    preimage.extend_from_slice(&shuffle.c_d);
    preimage.extend_from_slice(&shuffle.c_delta);
    preimage.extend_from_slice(&shuffle.c_capital_delta);
    Ok(chain_digest(&preimage))
}

/// Verify one cross-key negation wire natively.
///
/// Equations (challenge `c`, from the Flock transcript projection):
/// `G·resp_sk = commit_owner + owner_pk·c`,
/// `G·resp_r  = commit_c1 + negative.c1·c`,
/// `readable.c1·resp_sk + PK·resp_r = commit_joint + (readable.c2 + negative.c2)·c`.
pub fn verify_cross_key_wire_native(
    readable: &RistrettoCiphertext,
    negative: &RistrettoCiphertext,
    owner_pk: &RistrettoPoint,
    aggregate_pk: &RistrettoPoint,
    wire: &RistrettoCrossKeyProofWire,
    challenge: &RistrettoScalar,
) -> TexasAirResult<()> {
    let base = RistrettoCurve::base_g();
    if owner_pk.is_identity()
        || aggregate_pk.is_identity()
        || !readable.is_valid()
        || !negative.is_valid()
    {
        return Err(TexasAirError::SpecViolation(
            "cross-key native statement contains identity points".into(),
        ));
    }
    let commitment_owner = decode_point(&wire.commitment_owner_key, "cross-key commitment")?;
    let commitment_c1 = decode_point(&wire.commitment_contribution_c1, "cross-key commitment")?;
    let commitment_joint = decode_point(&wire.commitment_joint_c2, "cross-key commitment")?;
    if commitment_owner.is_identity()
        || commitment_c1.is_identity()
        || commitment_joint.is_identity()
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "cross-key native commitment is the identity".into(),
        ));
    }
    let response_sk = decode_scalar(&wire.response_owner_sk, "cross-key response")?;
    let response_randomness =
        decode_scalar(&wire.response_contribution_randomness, "cross-key response")?;

    let owner_equation = base * response_sk == commitment_owner + *owner_pk * *challenge;
    let contribution_c1_equation =
        base * response_randomness == commitment_c1 + negative.c1 * *challenge;
    let joint_c2_equation = readable.c1 * response_sk + *aggregate_pk * response_randomness
        == commitment_joint + (readable.c2 + negative.c2) * *challenge;
    if owner_equation && contribution_c1_equation && joint_c2_equation {
        Ok(())
    } else {
        Err(TexasAirError::ConstraintUnsatisfied(
            "cross-key native equation is not satisfied".into(),
        ))
    }
}

/// Verify one slot-membership OR wire natively against its global challenge.
///
/// Targets are `t0 = contribution.c2` and `t1 = contribution.c2 + card`.  The
/// shares must sum to the challenge and each branch must close both
/// Chaum--Pedersen equations.
pub fn verify_slot_or_wire_native(
    card: &RistrettoPoint,
    contribution: &RistrettoCiphertext,
    aggregate_pk: &RistrettoPoint,
    wire: &RistrettoSlotOrProofWire,
    global_challenge: &RistrettoScalar,
) -> TexasAirResult<()> {
    let base = RistrettoCurve::base_g();
    if card.is_identity() || aggregate_pk.is_identity() || !contribution.is_valid() {
        return Err(TexasAirError::SpecViolation(
            "slot-membership native statement contains identity points".into(),
        ));
    }
    let mut commitments_g = [RistrettoPoint::identity(); 2];
    let mut commitments_pk = [RistrettoPoint::identity(); 2];
    for branch in 0..2 {
        commitments_g[branch] =
            decode_point(&wire.commitment_g[branch], "slot-membership commitment")?;
        commitments_pk[branch] =
            decode_point(&wire.commitment_pk[branch], "slot-membership commitment")?;
        if commitments_g[branch].is_identity() || commitments_pk[branch].is_identity() {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "slot-membership native commitment is the identity".into(),
            ));
        }
    }
    let mut challenges = [RistrettoScalar::zero(); 2];
    let mut responses = [RistrettoScalar::zero(); 2];
    for branch in 0..2 {
        challenges[branch] =
            decode_scalar(&wire.challenges[branch], "slot-membership challenge share")?;
        responses[branch] = decode_scalar(&wire.responses[branch], "slot-membership response")?;
    }
    if challenges[0] + challenges[1] != *global_challenge {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "slot-membership challenge shares do not sum to the global challenge".into(),
        ));
    }
    let targets = [contribution.c2, contribution.c2 + *card];
    for branch in 0..2 {
        let first = base * responses[branch]
            == commitments_g[branch] + contribution.c1 * challenges[branch];
        let second = *aggregate_pk * responses[branch]
            == commitments_pk[branch] + targets[branch] * challenges[branch];
        if !first || !second {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "slot-membership native equation is not satisfied".into(),
            ));
        }
    }
    Ok(())
}

/// The deterministic public zero encryptions padding the shuffle input.
pub fn deterministic_zero_contributions(
    count: usize,
    aggregate_pk: &RistrettoPoint,
) -> TexasAirResult<Vec<(RistrettoCiphertext, RistrettoScalar)>> {
    let identity = RistrettoPoint::identity();
    let mut output = Vec::with_capacity(count);
    for index in 0..count {
        let randomness = RistrettoScalar::from_u64((index as u64) + 1);
        let ciphertext = RistrettoCiphertext::encrypt(&identity, aggregate_pk, &randomness);
        if !ciphertext.is_valid() {
            return Err(TexasAirError::SpecViolation(
                "deterministic zero contribution is not a valid ciphertext".into(),
            ));
        }
        output.push((ciphertext, randomness));
    }
    Ok(output)
}

/// The Bayer--Groth contribution-shuffle component of the V2 archive.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoReconstructionV2ShuffleComponent {
    /// Recorded challenge images and retry counts of the shuffle transcript.
    pub challenges: Vec<RistrettoShuffleV2ChallengeWire>,
    /// Flock STARK over the shuffle transcript chain statements.
    pub flock: ArchivedHashProof,
}

/// The complete V2 native reconstruction relation archive.
///
/// The deck transition (`post = prior + contributions`) is verified natively
/// against the state-binding-authenticated openings instead of an Fp-program
/// STARK: it is a public linear relation over public points, the same trust
/// class as the sigma equations, and dropping its 104 compressed-point
/// addition rows shrinks the archive by an order of magnitude.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoReconstructionV2NativeBundle {
    /// Canonical state-image/request/hash binding STARK.
    pub binding: ArchivedCanonicalReconstructionStateBindingProof,
    /// Flock transcript proof over `(statement_digest, commitments_digest)`.
    pub flock_transcript: ArchivedRistrettoFlockTranscriptProof,
    /// Contribution shuffle component.
    pub contribution_shuffle: ArchivedRistrettoReconstructionV2ShuffleComponent,
}

const NATIVE_ARCHIVE_DOMAIN: &[u8] =
    b"zchain.texas.ristretto-air-v2.reconstruction.native-archive.v1";

fn native_archive_digest(payload: &[u8]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(NATIVE_ARCHIVE_DOMAIN.len() + payload.len());
    preimage.extend_from_slice(NATIVE_ARCHIVE_DOMAIN);
    preimage.extend_from_slice(payload);
    chain_digest(&preimage)
}

impl ArchivedRistrettoReconstructionV2NativeBundle {
    /// Serialize with strict magic/version framing and a transport digest.
    pub fn encode_archive(&self) -> TexasAirResult<Vec<u8>> {
        let mut payload = Vec::new();
        borsh::to_writer(&mut payload, self)
            .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
        let digest = native_archive_digest(&payload);
        let mut out = Vec::with_capacity(
            RISTRETTO_RECONSTRUCTION_V2_NATIVE_MAGIC.len() + 1 + payload.len() + 32,
        );
        out.extend_from_slice(&RISTRETTO_RECONSTRUCTION_V2_NATIVE_MAGIC);
        out.push(RISTRETTO_RECONSTRUCTION_V2_NATIVE_VERSION);
        out.extend_from_slice(&payload);
        out.extend_from_slice(&digest);
        Ok(out)
    }

    /// Decode the strict archive; semantic verification stays with the
    /// relation verifier.
    pub fn decode_archive(bytes: &[u8]) -> TexasAirResult<Self> {
        if bytes.len() < RISTRETTO_RECONSTRUCTION_V2_NATIVE_MAGIC.len() + 1
            || bytes[..RISTRETTO_RECONSTRUCTION_V2_NATIVE_MAGIC.len()]
                != RISTRETTO_RECONSTRUCTION_V2_NATIVE_MAGIC
        {
            return Err(TexasAirError::SerializationError(
                "V2 native reconstruction archive magic mismatch".into(),
            ));
        }
        if bytes[RISTRETTO_RECONSTRUCTION_V2_NATIVE_MAGIC.len()]
            != RISTRETTO_RECONSTRUCTION_V2_NATIVE_VERSION
        {
            return Err(TexasAirError::SpecViolation(
                "unsupported V2 native reconstruction archive version".into(),
            ));
        }
        let header = RISTRETTO_RECONSTRUCTION_V2_NATIVE_MAGIC.len() + 1;
        let digest_start = bytes.len() - 32;
        let payload = &bytes[header..digest_start];
        if native_archive_digest(payload) != bytes[digest_start..] {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "V2 native reconstruction archive digest is detached".into(),
            ));
        }
        let bundle: Self = borsh::from_slice(payload).map_err(|error| {
            TexasAirError::SerializationError(format!(
                "V2 native reconstruction archive decode failed: {error}"
            ))
        })?;
        Ok(bundle)
    }
}

struct NativeRelationInputs {
    request: ReconstructionV3VerifyRequest,
    envelope: RistrettoReconstructionProofEnvelope,
    readable: Vec<RistrettoCiphertext>,
    contributions: Vec<RistrettoCiphertext>,
    negatives: Vec<RistrettoCiphertext>,
    cards: Vec<RistrettoPoint>,
    aggregate_pk: RistrettoPoint,
    owner_pk: RistrettoPoint,
    shuffle_input: Vec<RistrettoCiphertext>,
}

fn native_relation_inputs(
    request: &ReconstructionV3VerifyRequest,
) -> TexasAirResult<NativeRelationInputs> {
    let envelope = validate_ristretto_reconstruction_proof_wire(request)?;
    let decode_all = |ciphertexts: &Vec<poker_protocol::precompile_abi::EncodedCiphertext>| {
        ciphertexts
            .iter()
            .map(|ciphertext| {
                decode_ciphertext(
                    &RistrettoCiphertextProofWire {
                        c1: ciphertext.c1.as_slice().try_into().map_err(|_| {
                            TexasAirError::SpecViolation("ciphertext c1 width".into())
                        })?,
                        c2: ciphertext.c2.as_slice().try_into().map_err(|_| {
                            TexasAirError::SpecViolation("ciphertext c2 width".into())
                        })?,
                    },
                    "request ciphertext",
                )
            })
            .collect::<TexasAirResult<Vec<_>>>()
    };
    let readable = decode_all(&request.user_readable_cards)?;
    let contributions = decode_all(&request.contributions)?;
    let negatives = envelope
        .negative_contributions
        .iter()
        .map(|wire| decode_ciphertext(wire, "negative contribution"))
        .collect::<TexasAirResult<Vec<_>>>()?;
    let cards = request
        .cards
        .iter()
        .map(|card| {
            decode_point(
                card.as_slice()
                    .try_into()
                    .map_err(|_| TexasAirError::SpecViolation("request card width".into()))?,
                "request card",
            )
        })
        .collect::<TexasAirResult<Vec<_>>>()?;
    let aggregate_pk = decode_point(
        request
            .aggregate_pk
            .as_slice()
            .try_into()
            .map_err(|_| TexasAirError::SpecViolation("aggregate key width".into()))?,
        "aggregate_pk",
    )?;
    let owner_pk = decode_point(
        request
            .owner_pk
            .as_slice()
            .try_into()
            .map_err(|_| TexasAirError::SpecViolation("owner key width".into()))?,
        "owner_pk",
    )?;
    let zeros = deterministic_zero_contributions(
        SLOT_COUNT - envelope.negative_contributions.len(),
        &aggregate_pk,
    )?;
    let mut shuffle_input = negatives.clone();
    shuffle_input.extend(zeros.into_iter().map(|(ciphertext, _)| ciphertext));
    Ok(NativeRelationInputs {
        request: request.clone(),
        envelope,
        readable,
        contributions,
        negatives,
        cards,
        aggregate_pk,
        owner_pk,
        shuffle_input,
    })
}

/// The state-authenticated prior deck of a submission: the opening's
/// accumulated deck for non-initial contributions, and the deterministic
/// canonical base deck for the initial one.
fn prior_deck_wire(
    opening: &CanonicalReconstructionStateOpening,
    aggregate_pk: &RistrettoPoint,
) -> TexasAirResult<[CanonicalRistrettoCiphertext; SLOT_COUNT]> {
    if opening.accumulator_present {
        return Ok(opening.accumulated_deck);
    }
    if opening
        .accumulated_deck
        .iter()
        .any(|ciphertext| *ciphertext != CanonicalRistrettoCiphertext::default())
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "initial reconstruction pre-opening accumulator is not canonically zero".into(),
        ));
    }
    let cards = crate::canonical_reconstruction_binding::canonical_ristretto_cards();
    let identity = RistrettoPoint::identity();
    let mut deck = [CanonicalRistrettoCiphertext::default(); SLOT_COUNT];
    for index in 0..SLOT_COUNT {
        let card = decode_point(&cards[index], "canonical card")?;
        let randomness = RistrettoScalar::from_u64((index + 1) as u64);
        let ciphertext = RistrettoCiphertext::encrypt(&card, aggregate_pk, &randomness);
        let _ = identity;
        deck[index] = CanonicalRistrettoCiphertext {
            c1: point_bytes(&ciphertext.c1),
            c2: point_bytes(&ciphertext.c2),
        };
    }
    Ok(deck)
}

/// Verify the public deck transition `post = prior + contributions` with
/// native curve arithmetic against the binding-authenticated openings.
fn verify_deck_transition_native(
    binding: &ArchivedCanonicalReconstructionStateBindingProof,
    inputs: &NativeRelationInputs,
) -> TexasAirResult<()> {
    if !binding.post_opening.accumulator_present {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "V2 native post-state opening does not carry the accumulated deck".into(),
        ));
    }
    let prior = prior_deck_wire(&binding.opening, &inputs.aggregate_pk)?;
    for index in 0..SLOT_COUNT {
        let prior_ciphertext = decode_ciphertext(
            &RistrettoCiphertextProofWire {
                c1: prior[index].c1,
                c2: prior[index].c2,
            },
            "prior deck",
        )?;
        let expected = RistrettoCiphertext {
            c1: prior_ciphertext.c1 + inputs.contributions[index].c1,
            c2: prior_ciphertext.c2 + inputs.contributions[index].c2,
        };
        let actual = decode_ciphertext(
            &RistrettoCiphertextProofWire {
                c1: binding.post_opening.accumulated_deck[index].c1,
                c2: binding.post_opening.accumulated_deck[index].c2,
            },
            "post deck",
        )?;
        if expected.c1 != actual.c1 || expected.c2 != actual.c2 {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "V2 native deck transition is not prior plus contributions".into(),
            ));
        }
    }
    Ok(())
}

/// Verify every relation of the V2 native bundle against one canonical
/// request.  See the module-level docs for the trust boundary.
pub fn verify_ristretto_reconstruction_v2_native(
    bundle: &ArchivedRistrettoReconstructionV2NativeBundle,
    canonical_request_bytes: &[u8],
) -> TexasAirResult<()> {
    let request =
        ReconstructionV3VerifyRequest::decode(canonical_request_bytes).map_err(|error| {
            TexasAirError::SerializationError(format!(
                "V2 native reconstruction request decode failed: {error}"
            ))
        })?;
    if bundle.binding.request_bytes != canonical_request_bytes {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "V2 native reconstruction archive is detached from the submitted request".into(),
        ));
    }
    let inputs = native_relation_inputs(&request)?;

    // State binding STARK, in parallel with the cheap transcript-scope
    // projection.
    let binding_result =
        crate::canonical_reconstruction_binding::verify_canonical_reconstruction_state_binding(
            &bundle.binding,
        );

    let commitments_digest = reconstruction_v2_commitments_digest(&inputs.envelope)?;
    crate::ristretto_reconstruction_composition::verify_ristretto_air_v2_flock_transcript(
        &bundle.flock_transcript,
        inputs.envelope.statement_digest,
        commitments_digest,
    )?;
    let compat = bundle.flock_transcript.as_poseidon_compat();
    let cross_challenges = RistrettoCrossKeyTranscriptChallenges::from_poseidon_output(
        &compat,
        inputs.envelope.statement_digest,
    )?;
    let slot_challenges = RistrettoSlotOrTranscriptChallenges::from_poseidon_output(
        &compat,
        inputs.envelope.statement_digest,
    )?;

    binding_result?;

    // Native deck transition: the binding STARK authenticates both openings,
    // so the linear relation `post = prior + contributions` is checked with
    // plain curve arithmetic.  The initial-contribution branch additionally
    // requires the pre-opening accumulator to be canonically zero and derives
    // the prior deck from the public canonical base construction.
    verify_deck_transition_native(&bundle.binding, &inputs)?;

    // Native cross-key equations in readable order.
    for (index, wire) in inputs.envelope.cross_key_proofs.iter().enumerate() {
        let challenge =
            scalar_from_bytes(&cross_challenges.challenges[index], "cross-key challenge")?;
        verify_cross_key_wire_native(
            &inputs.readable[index],
            &inputs.negatives[index],
            &inputs.owner_pk,
            &inputs.aggregate_pk,
            wire,
            &challenge,
        )?;
    }

    // Native slot-membership equations in canonical slot order.
    let slot_results: TexasAirResult<Vec<()>> = (0..SLOT_COUNT)
        .into_par_iter()
        .map(|slot| {
            let challenge =
                scalar_from_bytes(&slot_challenges.global_challenges[slot], "slot challenge")?;
            verify_slot_or_wire_native(
                &inputs.cards[slot],
                &inputs.contributions[slot],
                &inputs.aggregate_pk,
                &inputs.envelope.slot_or_proofs[slot],
                &challenge,
            )
        })
        .collect();
    slot_results?;

    // Contribution shuffle: Bayer--Groth under the Flock transcript, with the
    // statement digest absorbed ahead of the argument schedule.
    let shuffle_proof = inputs.envelope.shuffle_proof.to_proof()?;
    let mut transcript = FlockShuffleTranscript::new(RISTRETTO_RECONSTRUCTION_V2_SHUFFLE_PROTOCOL);
    transcript.absorb(b"zr3n-statement-digest", &inputs.envelope.statement_digest);
    run_bayer_groth_verify(
        &shuffle_proof,
        &inputs.shuffle_input,
        &inputs.contributions,
        &inputs.aggregate_pk,
        &mut transcript,
    )?;
    if transcript.challenges() != bundle.contribution_shuffle.challenges.as_slice() {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "V2 native contribution shuffle challenge schedule is detached".into(),
        ));
    }
    crate::blake3_flock::FlockProvider
        .verify_statements(&bundle.contribution_shuffle.flock, transcript.statements())
        .map_err(|error| {
            TexasAirError::ConstraintUnsatisfied(format!(
                "V2 native contribution shuffle Flock verification failed: {error}"
            ))
        })?;
    Ok(())
}

/// Client-side inputs for one V2 native reconstruction proof.
pub struct RistrettoReconstructionV2ProverInputs {
    /// Unsealed transition witness matching the table state machine.
    pub witness: CanonicalTransitionWitness,
    /// Authenticated collecting-state opening of the submitting seat.
    pub opening: CanonicalReconstructionStateOpening,
    /// Aggregate ElGamal key of the table epoch.
    pub aggregate_pk: RistrettoPoint,
    /// Owner secret key of the submitting seat.
    pub owner_sk: RistrettoScalar,
    /// Owner public key (`base_g * owner_sk`).
    pub owner_pk: RistrettoPoint,
    /// The two owner-readable ciphertexts, equal to the opening's selected
    /// seat cards.
    pub user_readable_cards: [RistrettoCiphertext; READABLE_COUNT],
}

struct SigmaCommitments {
    cross_key: [RistrettoCrossKeyProofWire; READABLE_COUNT],
    slot_or: [RistrettoSlotOrProofWire; SLOT_COUNT],
}

/// Prove one complete V2 native reconstruction submission.
///
/// Returns the canonical request bytes (with the `ZR3P` envelope in `proof`)
/// and the `ZR3N` relation archive.  The caller seals nothing: the witness is
/// sealed here after the request commitment is set.
pub fn prove_ristretto_reconstruction_v2_native(
    inputs: RistrettoReconstructionV2ProverInputs,
    rng: &mut (impl CryptoRng + RngCore),
) -> TexasAirResult<(Vec<u8>, ArchivedRistrettoReconstructionV2NativeBundle)> {
    let RistrettoReconstructionV2ProverInputs {
        mut witness,
        opening,
        aggregate_pk,
        owner_sk,
        owner_pk,
        user_readable_cards,
    } = inputs;

    if owner_pk.is_identity()
        || aggregate_pk.is_identity()
        || owner_pk != RistrettoCurve::base_g() * owner_sk
    {
        return Err(TexasAirError::SpecViolation(
            "V2 native reconstruction owner key is inconsistent".into(),
        ));
    }

    // The prior accumulated deck is state-authenticated: it comes from the
    // opening when the epoch already accumulated one, and from the canonical
    // base-deck construction for the initial contribution.  Both sides derive
    // it natively; the deck transition itself is verified as a public linear
    // relation against the binding-authenticated openings.
    let prior_wire = prior_deck_wire(&opening, &aggregate_pk)?;
    let prior_deck = prior_wire
        .iter()
        .map(|wire| {
            decode_ciphertext(
                &RistrettoCiphertextProofWire {
                    c1: wire.c1,
                    c2: wire.c2,
                },
                "prior deck",
            )
        })
        .collect::<TexasAirResult<Vec<_>>>()?;
    let cards = crate::canonical_reconstruction_binding::canonical_ristretto_cards()
        .iter()
        .map(|card| decode_point(card, "canonical card"))
        .collect::<TexasAirResult<Vec<_>>>()?;

    // 1. Crypto values: negatives, deterministic zeros, permutation and
    //    rerandomizers produce the canonical contributions.
    let mut canonical_index_of = std::collections::HashMap::new();
    for (index, card) in cards.iter().enumerate() {
        canonical_index_of.insert(point_bytes(card), index);
    }
    let mut canonical_indices = Vec::with_capacity(READABLE_COUNT);
    let mut negatives = Vec::with_capacity(READABLE_COUNT);
    let mut negative_randomness = Vec::with_capacity(READABLE_COUNT);
    let mut seen = std::collections::HashSet::new();
    for readable in &user_readable_cards {
        let plaintext = readable.decrypt(&owner_sk);
        let key = point_bytes(&plaintext);
        let index = canonical_index_of.get(&key).copied().ok_or_else(|| {
            TexasAirError::SpecViolation(
                "V2 native reconstruction readable card is not a canonical card".into(),
            )
        })?;
        if !seen.insert(key) {
            return Err(TexasAirError::SpecViolation(
                "V2 native reconstruction readable cards repeat a plaintext".into(),
            ));
        }
        let negative_plaintext = RistrettoPoint::identity() - plaintext;
        let (randomness, ciphertext) = loop {
            let randomness = RistrettoScalar::random(rng);
            let ciphertext =
                RistrettoCiphertext::encrypt(&negative_plaintext, &aggregate_pk, &randomness);
            if randomness != RistrettoScalar::zero() && ciphertext.is_valid() {
                break (randomness, ciphertext);
            }
        };
        canonical_indices.push(index);
        negative_randomness.push(randomness);
        negatives.push(ciphertext);
    }
    let zeros = deterministic_zero_contributions(SLOT_COUNT - READABLE_COUNT, &aggregate_pk)?;
    let mut shuffle_input = negatives.clone();
    let mut input_randomness = negative_randomness.clone();
    shuffle_input.extend(zeros.iter().map(|(ciphertext, _)| *ciphertext));
    input_randomness.extend(zeros.iter().map(|(_, randomness)| *randomness));

    let mut permutation = vec![usize::MAX; SLOT_COUNT];
    for (negative_position, canonical_slot) in canonical_indices.iter().enumerate() {
        permutation[*canonical_slot] = negative_position;
    }
    let mut zero_cursor = 0usize;
    for slot in &mut permutation {
        if *slot == usize::MAX {
            *slot = READABLE_COUNT + zero_cursor;
            zero_cursor += 1;
        }
    }
    let mut rerandomizers = Vec::with_capacity(SLOT_COUNT);
    let mut contributions = Vec::with_capacity(SLOT_COUNT);
    let mut contribution_randomness = Vec::with_capacity(SLOT_COUNT);
    for slot in 0..SLOT_COUNT {
        let input_index = permutation[slot];
        let (rerandomizer, total_randomness, contribution) = loop {
            let rerandomizer = RistrettoScalar::random(rng);
            let total = input_randomness[input_index] + rerandomizer;
            let contribution = shuffle_input[input_index].re_encrypt(&aggregate_pk, &rerandomizer);
            if total != RistrettoScalar::zero() && contribution.is_valid() {
                break (rerandomizer, total, contribution);
            }
        };
        rerandomizers.push(rerandomizer);
        contribution_randomness.push(total_randomness);
        contributions.push(contribution);
    }
    let post_deck: Vec<RistrettoCiphertext> = prior_deck
        .iter()
        .zip(&contributions)
        .map(|(prior, contribution)| RistrettoCiphertext {
            c1: prior.c1 + contribution.c1,
            c2: prior.c2 + contribution.c2,
        })
        .collect();

    // 2. Request template: every public field, placeholder proof.
    let mut request = unbound_request_template(
        &witness,
        &opening,
        &aggregate_pk,
        &owner_pk,
        &user_readable_cards,
        &contributions,
    );

    // 3. State digest derivation (BLAKE2b, mirroring the binding fixtures).
    witness.pre.reconstruction_commitment = native_hash(
        &crate::canonical_reconstruction_binding::canonical_reconstruction_state_preimage(&opening)
            .map_err(|error| {
                TexasAirError::SpecViolation(format!("pre-state preimage failed: {error}"))
            })?,
    );
    let post_deck_wire: [CanonicalRistrettoCiphertext; SLOT_COUNT] = post_deck
        .iter()
        .map(|ciphertext| CanonicalRistrettoCiphertext {
            c1: point_bytes(&ciphertext.c1),
            c2: point_bytes(&ciphertext.c2),
        })
        .collect::<Vec<_>>()
        .try_into()
        .expect("fixed deck size");
    let post_opening =
        crate::canonical_reconstruction_binding::canonical_reconstruction_post_opening(
            &witness,
            &opening,
            post_deck_wire,
        )?;
    witness.post.reconstruction_commitment = native_hash(
        &crate::canonical_reconstruction_binding::canonical_reconstruction_state_preimage(
            &post_opening,
        )
        .map_err(|error| {
            TexasAirError::SpecViolation(format!("post-state preimage failed: {error}"))
        })?,
    );
    request.context_digest = native_hash(
        &crate::canonical_reconstruction_binding::canonical_reconstruction_context_preimage(
            &witness,
        ),
    );
    request.prior_state_digest = native_hash(
        &crate::canonical_reconstruction_binding::canonical_reconstruction_prior_state_preimage(
            &witness, &opening, &request,
        )?,
    );
    request.call_context = crate::precompile_binding::canonical_precompile_call_context(&witness);
    let statement_digest = reconstruction_v3_statement_digest(&request)?;

    // 4. Contribution shuffle: Bayer--Groth under its own Flock transcript,
    //    with the statement digest absorbed first.
    let mut shuffle_transcript =
        FlockShuffleTranscript::new(RISTRETTO_RECONSTRUCTION_V2_SHUFFLE_PROTOCOL);
    shuffle_transcript.absorb(b"zr3n-statement-digest", &statement_digest);
    let shuffle_proof = BayerGrothShuffleProof::<RistrettoCurve>::prove(
        &shuffle_input,
        &contributions,
        &permutation,
        &rerandomizers,
        &aggregate_pk,
        rng,
        &mut shuffle_transcript,
    )
    .map_err(|error| {
        TexasAirError::ConstraintUnsatisfied(format!(
            "contribution shuffle proving failed: {error:?}"
        ))
    })?;
    let shuffle_wire = RistrettoBayerGrothShuffleProofWire::from_proof(&shuffle_proof);

    // 5. Sigma commitments (nonces only; responses wait for the challenges).
    let sigma = sigma_commitments(
        &user_readable_cards,
        &negatives,
        &cards,
        &contributions,
        &canonical_indices,
        &aggregate_pk,
        rng,
    )?;

    // 6. Flock transcript over the commitments-only digest, then responses.
    let placeholder_negatives = envelope_negatives(&negatives);
    let mut envelope = envelope_from_parts(
        &request,
        &placeholder_negatives,
        &shuffle_wire,
        &sigma.commitments.cross_key,
        &sigma.commitments.slot_or,
    )?;
    let commitments_digest = reconstruction_v2_commitments_digest(&envelope)?;
    let flock_transcript =
        ArchivedRistrettoFlockTranscriptProof::prove(statement_digest, commitments_digest)?;
    let compat = flock_transcript.as_poseidon_compat();
    let cross_challenges =
        RistrettoCrossKeyTranscriptChallenges::from_poseidon_output(&compat, statement_digest)?;
    let slot_challenges =
        RistrettoSlotOrTranscriptChallenges::from_poseidon_output(&compat, statement_digest)?;

    let mut cross_key_wires = sigma.commitments.cross_key;
    for index in 0..READABLE_COUNT {
        let challenge =
            scalar_from_bytes(&cross_challenges.challenges[index], "cross-key challenge")?;
        cross_key_wires[index].response_owner_sk =
            scalar_bytes(&(sigma.cross_key_nonces[index].0 + challenge * owner_sk));
        cross_key_wires[index].response_contribution_randomness = scalar_bytes(
            &(sigma.cross_key_nonces[index].1 + challenge * negative_randomness[index]),
        );
    }
    let mut slot_or_wires = sigma.commitments.slot_or;
    for slot in 0..SLOT_COUNT {
        let global = scalar_from_bytes(&slot_challenges.global_challenges[slot], "slot challenge")?;
        let branch = sigma.slot_branches[slot];
        let simulated = 1 - branch;
        let mut challenges = [RistrettoScalar::zero(); 2];
        let mut responses = [RistrettoScalar::zero(); 2];
        challenges[simulated] = sigma.slot_simulated[slot].0;
        responses[simulated] = sigma.slot_simulated[slot].1;
        challenges[branch] = global - challenges[simulated];
        responses[branch] =
            sigma.slot_nonces[slot] + challenges[branch] * contribution_randomness[slot];
        slot_or_wires[slot].challenges =
            [scalar_bytes(&challenges[0]), scalar_bytes(&challenges[1])];
        slot_or_wires[slot].responses = [scalar_bytes(&responses[0]), scalar_bytes(&responses[1])];
    }

    // 7. Final envelope, canonical request, sealed binding.
    let envelope = envelope_from_parts(
        &request,
        &placeholder_negatives,
        &shuffle_wire,
        &cross_key_wires,
        &slot_or_wires,
    )?;
    request.proof = envelope.encode_wire()?;
    let canonical_request_bytes = request.encode().map_err(|error| {
        TexasAirError::SerializationError(format!("request encoding failed: {error}"))
    })?;
    witness.action.proof_commitment =
        crate::precompile_binding::precompile_request_digest(&canonical_request_bytes);
    witness.seal();

    let binding =
        crate::canonical_reconstruction_binding::prove_canonical_reconstruction_state_binding(
            witness,
            opening,
            post_opening,
            request.clone(),
        )?;
    let contribution_shuffle_flock = crate::blake3_flock::FlockProvider
        .prove_statements(shuffle_transcript.statements())
        .map_err(|error| {
            TexasAirError::StwoProverError(format!(
                "contribution shuffle Flock proving failed: {error}"
            ))
        })?;
    let bundle = ArchivedRistrettoReconstructionV2NativeBundle {
        binding,
        flock_transcript,
        contribution_shuffle: ArchivedRistrettoReconstructionV2ShuffleComponent {
            challenges: shuffle_transcript.challenges().to_vec(),
            flock: contribution_shuffle_flock,
        },
    };
    Ok((canonical_request_bytes, bundle))
}

struct SigmaBuilder {
    commitments: SigmaCommitments,
    cross_key_nonces: [(RistrettoScalar, RistrettoScalar); READABLE_COUNT],
    slot_nonces: Vec<RistrettoScalar>,
    slot_simulated: Vec<(RistrettoScalar, RistrettoScalar)>,
    slot_branches: [usize; SLOT_COUNT],
}

type SigmaCommitmentsBuilt = SigmaBuilder;

fn sigma_commitments(
    readable: &[RistrettoCiphertext; READABLE_COUNT],
    negatives: &[RistrettoCiphertext],
    cards: &[RistrettoPoint],
    contributions: &[RistrettoCiphertext],
    canonical_indices: &[usize],
    aggregate_pk: &RistrettoPoint,
    rng: &mut (impl CryptoRng + RngCore),
) -> TexasAirResult<SigmaCommitmentsBuilt> {
    let base = RistrettoCurve::base_g();
    let mut cross_key_nonces = [(RistrettoScalar::zero(), RistrettoScalar::zero()); READABLE_COUNT];
    let mut cross_key = [RistrettoCrossKeyProofWire::default(); READABLE_COUNT];
    for index in 0..READABLE_COUNT {
        let nonce_sk = RistrettoScalar::random(rng);
        let nonce_randomness = RistrettoScalar::random(rng);
        let commitment_owner = base * nonce_sk;
        let commitment_c1 = base * nonce_randomness;
        let commitment_joint = readable[index].c1 * nonce_sk + *aggregate_pk * nonce_randomness;
        if commitment_owner.is_identity()
            || commitment_c1.is_identity()
            || commitment_joint.is_identity()
        {
            return Err(TexasAirError::SpecViolation(
                "cross-key commitment degenerated to the identity; reseed".into(),
            ));
        }
        cross_key_nonces[index] = (nonce_sk, nonce_randomness);
        cross_key[index] = RistrettoCrossKeyProofWire {
            commitment_owner_key: point_bytes(&commitment_owner),
            commitment_contribution_c1: point_bytes(&commitment_c1),
            commitment_joint_c2: point_bytes(&commitment_joint),
            response_owner_sk: [0; 32],
            response_contribution_randomness: [0; 32],
        };
    }

    let mut slot_nonces = Vec::with_capacity(SLOT_COUNT);
    let mut slot_simulated = Vec::with_capacity(SLOT_COUNT);
    let mut slot_branches = [0usize; SLOT_COUNT];
    let mut slot_or = [RistrettoSlotOrProofWire::default(); SLOT_COUNT];
    for slot in 0..SLOT_COUNT {
        // Branch 0 encrypts zero; branch 1 encrypts `-cards[slot]`.  A slot is
        // on the negative branch exactly when it received a negative input.
        let branch = canonical_indices.iter().any(|&index| index == slot) as usize;
        let nonce = RistrettoScalar::random(rng);
        let simulated_challenge = RistrettoScalar::random(rng);
        let simulated_response = RistrettoScalar::random(rng);
        let contribution = &contributions[slot];
        let targets = [contribution.c2, contribution.c2 + cards[slot]];
        let simulated_branch = 1 - branch;
        let mut commitment_g = [RistrettoPoint::identity(); 2];
        let mut commitment_pk = [RistrettoPoint::identity(); 2];
        commitment_g[branch] = base * nonce;
        commitment_pk[branch] = *aggregate_pk * nonce;
        commitment_g[simulated_branch] =
            base * simulated_response - contribution.c1 * simulated_challenge;
        commitment_pk[simulated_branch] =
            *aggregate_pk * simulated_response - targets[simulated_branch] * simulated_challenge;
        if commitment_g.iter().any(CurvePoint::is_identity)
            || commitment_pk.iter().any(CurvePoint::is_identity)
        {
            return Err(TexasAirError::SpecViolation(
                "slot-membership commitment degenerated to the identity; reseed".into(),
            ));
        }
        slot_nonces.push(nonce);
        slot_simulated.push((simulated_challenge, simulated_response));
        slot_branches[slot] = branch;
        slot_or[slot] = RistrettoSlotOrProofWire {
            commitment_g: [point_bytes(&commitment_g[0]), point_bytes(&commitment_g[1])],
            commitment_pk: [
                point_bytes(&commitment_pk[0]),
                point_bytes(&commitment_pk[1]),
            ],
            challenges: [[0; 32]; 2],
            responses: [[0; 32]; 2],
        };
    }
    Ok(SigmaBuilder {
        commitments: SigmaCommitments { cross_key, slot_or },
        cross_key_nonces,
        slot_nonces,
        slot_simulated,
        slot_branches,
    })
}

fn envelope_negatives(
    negatives: &[RistrettoCiphertext],
) -> [RistrettoCiphertextProofWire; READABLE_COUNT] {
    negatives
        .iter()
        .map(|ciphertext| RistrettoCiphertextProofWire {
            c1: point_bytes(&ciphertext.c1),
            c2: point_bytes(&ciphertext.c2),
        })
        .collect::<Vec<_>>()
        .try_into()
        .expect("fixed readable count")
}

fn deck_wire(deck: &[RistrettoCiphertext]) -> [CanonicalRistrettoCiphertext; SLOT_COUNT] {
    deck.iter()
        .map(|ciphertext| CanonicalRistrettoCiphertext {
            c1: point_bytes(&ciphertext.c1),
            c2: point_bytes(&ciphertext.c2),
        })
        .collect::<Vec<_>>()
        .try_into()
        .expect("fixed deck size")
}

fn envelope_from_parts(
    request: &ReconstructionV3VerifyRequest,
    negatives: &[RistrettoCiphertextProofWire; READABLE_COUNT],
    shuffle: &RistrettoBayerGrothShuffleProofWire,
    cross_key: &[RistrettoCrossKeyProofWire; READABLE_COUNT],
    slot_or: &[RistrettoSlotOrProofWire; SLOT_COUNT],
) -> TexasAirResult<RistrettoReconstructionProofEnvelope> {
    RistrettoReconstructionProofEnvelope::from_components(
        request,
        *negatives,
        shuffle.clone(),
        *cross_key,
        *slot_or,
    )
}

fn unbound_request_template(
    witness: &CanonicalTransitionWitness,
    opening: &CanonicalReconstructionStateOpening,
    aggregate_pk: &RistrettoPoint,
    owner_pk: &RistrettoPoint,
    user_readable_cards: &[RistrettoCiphertext; READABLE_COUNT],
    contributions: &[RistrettoCiphertext],
) -> ReconstructionV3VerifyRequest {
    let cards = crate::canonical_reconstruction_binding::canonical_ristretto_cards();
    ReconstructionV3VerifyRequest {
        curve: poker_protocol::precompile_abi::CurveId::Ristretto255,
        proof_system: poker_protocol::precompile_abi::ReconstructionProofSystem::RistrettoAirV2,
        transcript: TranscriptId::FlockBlake3,
        context: poker_protocol::ristretto_air::RISTRETTO_AIR_V2_RECONSTRUCTION_CONTEXT.to_vec(),
        call_context: crate::precompile_binding::canonical_precompile_call_context(witness),
        statement_version: 3,
        context_digest: [0; 32],
        reconstruction_epoch: opening.reconstruction_epoch,
        prior_state_digest: [0; 32],
        aggregate_pk: point_bytes(aggregate_pk).to_vec(),
        owner_pk: point_bytes(owner_pk).to_vec(),
        cards: cards.iter().map(|card| card.to_vec()).collect(),
        user_readable_cards: user_readable_cards
            .iter()
            .map(
                |ciphertext| poker_protocol::precompile_abi::EncodedCiphertext {
                    c1: point_bytes(&ciphertext.c1).to_vec(),
                    c2: point_bytes(&ciphertext.c2).to_vec(),
                },
            )
            .collect(),
        contributions: contributions
            .iter()
            .map(
                |ciphertext| poker_protocol::precompile_abi::EncodedCiphertext {
                    c1: point_bytes(&ciphertext.c1).to_vec(),
                    c2: point_bytes(&ciphertext.c2).to_vec(),
                },
            )
            .collect(),
        proof: vec![0; 8],
    }
}

/// Server-side V2 native submission entry: canonical request bytes plus the
/// `ZR3N` archive.  Discriminators are checked before any relation work.
pub fn verify_ristretto_air_v2_native_submission(
    request_bytes: &[u8],
    native_archive_bytes: &[u8],
) -> TexasAirResult<()> {
    let request = ReconstructionV3VerifyRequest::decode(request_bytes).map_err(|error| {
        TexasAirError::SerializationError(format!(
            "V2 native submission request decode failed: {error}"
        ))
    })?;
    let canonical = request.encode().map_err(|error| {
        TexasAirError::SerializationError(format!("request encode failed: {error}"))
    })?;
    if canonical != request_bytes {
        return Err(TexasAirError::SerializationError(
            "V2 native submission request is not canonically encoded".into(),
        ));
    }
    if request.proof_system
        != poker_protocol::precompile_abi::ReconstructionProofSystem::RistrettoAirV2
        || request.transcript != TranscriptId::FlockBlake3
        || request.context.as_slice()
            != poker_protocol::ristretto_air::RISTRETTO_AIR_V2_RECONSTRUCTION_CONTEXT
    {
        return Err(TexasAirError::SpecViolation(
            "V2 native endpoint received a non-V2 reconstruction request".into(),
        ));
    }
    let bundle =
        ArchivedRistrettoReconstructionV2NativeBundle::decode_archive(native_archive_bytes)?;
    verify_ristretto_reconstruction_v2_native(&bundle, request_bytes)
}

/// Production V2 native admission.  The relation set is complete (state
/// binding, deck accumulator, Flock transcript, cross-key negations,
/// slot-membership disjunctions, contribution shuffle), so admission succeeds
/// exactly when the verifier accepts.
pub fn admit_ristretto_air_v2_native_submission(
    request_bytes: &[u8],
    native_archive_bytes: &[u8],
) -> TexasAirResult<()> {
    verify_ristretto_air_v2_native_submission(request_bytes, native_archive_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical_reconstruction_binding::{
        CanonicalReadableHoleCard, CanonicalReconstructionSeatState,
    };
    use crate::texas_canonical::{
        CANONICAL_ABI_VERSION, CANONICAL_RECONSTRUCT_COLLECTING_SUBTAG, CanonicalActionPayload,
        CanonicalPhase, CanonicalRoundAdvanceOpening, CanonicalSeat, CanonicalSeatStatus,
        CanonicalStateImage, MAX_CANONICAL_SEATS, NO_CANONICAL_SEAT,
    };

    fn test_rng() -> rand::rngs::StdRng {
        use rand::SeedableRng;
        rand::rngs::StdRng::seed_from_u64(0x2E5A_11C0)
    }

    fn state(call_seq: u32, pending_mask: u16) -> CanonicalStateImage {
        let mut seats = [CanonicalSeat::EMPTY; MAX_CANONICAL_SEATS];
        for (index, seat) in seats[..2].iter_mut().enumerate() {
            *seat = CanonicalSeat {
                status: CanonicalSeatStatus::Active,
                acted: false,
                stack: 100,
                bet: 0,
                total_bet: 0,
                pending_addon: 0,
                time_bank_ms: 0,
                identity_commitment: [10 + index as u8; 32],
                key_commitment: [20 + index as u8; 32],
                hole_cards_commitment: [30 + index as u8; 32],
            };
        }
        CanonicalStateImage {
            abi_version: CANONICAL_ABI_VERSION,
            table_id: 7,
            hand_id: 3,
            call_seq,
            phase: CanonicalPhase::Reconstructing,
            phase_subtag: CANONICAL_RECONSTRUCT_COLLECTING_SUBTAG,
            street: 2,
            current_turn: NO_CANONICAL_SEAT,
            deadline_ms: 18_000,
            shuffle_timeout_ms: 10_000,
            reveal_timeout_ms: 10_000,
            betting_timeout_ms: 30_000,
            reconstruct_timeout_ms: 10_000,
            showdown_display_ms: 3_000,
            current_bet: 0,
            min_raise: 0,
            chip_pool: 200,
            pot: 0,
            button: 0,
            max_players: 2,
            acted_mask: 0,
            leave_after_hand_mask: 0,
            protocol_pending_mask: pending_mask,
            board_cards_commitment: [1; 32],
            deck_commitment: [2; 32],
            reveal_commitment: [3; 32],
            reconstruction_commitment: [4 + call_seq as u8; 32],
            run_it_twice_commitment: [5; 32],
            rules_commitment: [6; 32],
            governance_commitment: [7; 32],
            settlement_commitment: [8; 32],
            custody_commitment: [9; 32],
            lifecycle_root: [10; 32],
            overlay_root: [11; 32],
            state_root: [12 + call_seq as u8; 32],
            seats,
        }
    }

    fn unsealed_witness() -> CanonicalTransitionWitness {
        CanonicalTransitionWitness {
            pre: state(0, 0b11),
            post: state(1, 0b10),
            kind: crate::texas_canonical::CanonicalTransitionKind::SubmitReconstruct,
            actor: [40; 32],
            action: CanonicalActionPayload {
                seat: 0,
                amount: 0,
                auxiliary: 0,
                flag: false,
                proof_commitment: [0; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            protocol_completion: Default::default(),
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        }
    }

    struct Fixture {
        witness: CanonicalTransitionWitness,
        opening: CanonicalReconstructionStateOpening,
        aggregate_pk: RistrettoPoint,
        owner_sk: RistrettoScalar,
        owner_pk: RistrettoPoint,
        readable: [RistrettoCiphertext; READABLE_COUNT],
    }

    fn ciphertext_wire(ciphertext: &RistrettoCiphertext) -> CanonicalRistrettoCiphertext {
        CanonicalRistrettoCiphertext {
            c1: point_bytes(&ciphertext.c1),
            c2: point_bytes(&ciphertext.c2),
        }
    }

    fn fixture(readable_card_indices: [usize; 2]) -> Fixture {
        let mut rng = test_rng();
        let aggregate_sk = RistrettoScalar::random(&mut rng);
        let aggregate_pk = RistrettoCurve::base_g() * aggregate_sk;
        let owner_sk = RistrettoScalar::random(&mut rng);
        let owner_pk = RistrettoCurve::base_g() * owner_sk;
        let cards = crate::canonical_reconstruction_binding::canonical_ristretto_cards();
        let decode_card = |bytes: &[u8; 32]| decode_point(bytes, "card").expect("card decodes");
        let readable = readable_card_indices.map(|index| {
            let randomness = RistrettoScalar::random(&mut rng);
            RistrettoCiphertext::encrypt(&decode_card(&cards[index]), &owner_pk, &randomness)
        });
        let prior_deck: [RistrettoCiphertext; SLOT_COUNT] = (0..SLOT_COUNT)
            .map(|index| {
                let randomness = RistrettoScalar::from_u64((index + 1) as u64);
                RistrettoCiphertext::encrypt(
                    &decode_card(&cards[index]),
                    &aggregate_pk,
                    &randomness,
                )
            })
            .collect::<Vec<_>>()
            .try_into()
            .expect("fixed deck size");

        let mut seats = [CanonicalReconstructionSeatState::default(); MAX_CANONICAL_SEATS];
        seats[0] = CanonicalReconstructionSeatState {
            present: true,
            owner_pk: point_bytes(&owner_pk),
            readable_cards: [
                CanonicalReadableHoleCard {
                    present: true,
                    card_slot: 0,
                    encrypted_card_index: readable_card_indices[0] as u8,
                    ciphertext: ciphertext_wire(&readable[0]),
                },
                CanonicalReadableHoleCard {
                    present: true,
                    card_slot: 1,
                    encrypted_card_index: readable_card_indices[1] as u8,
                    ciphertext: ciphertext_wire(&readable[1]),
                },
            ],
        };
        seats[1] = CanonicalReconstructionSeatState {
            present: true,
            owner_pk: [5; 32],
            readable_cards: [
                CanonicalReadableHoleCard {
                    present: true,
                    card_slot: 0,
                    encrypted_card_index: 12,
                    ciphertext: CanonicalRistrettoCiphertext {
                        c1: [64; 32],
                        c2: [65; 32],
                    },
                },
                CanonicalReadableHoleCard {
                    present: true,
                    card_slot: 1,
                    encrypted_card_index: 13,
                    ciphertext: CanonicalRistrettoCiphertext {
                        c1: [66; 32],
                        c2: [67; 32],
                    },
                },
            ],
        };
        let opening = CanonicalReconstructionStateOpening {
            abi_version: CANONICAL_ABI_VERSION,
            table_id: 7,
            hand_id: 3,
            max_players: 2,
            reconstruction_epoch: 8_000,
            pending_mask: 0b11,
            aggregate_pk: point_bytes(&aggregate_pk),
            seats,
            accumulator_present: true,
            accumulated_deck: prior_deck.map(|ciphertext| ciphertext_wire(&ciphertext)),
        };
        Fixture {
            witness: unsealed_witness(),
            opening,
            aggregate_pk,
            owner_sk,
            owner_pk,
            readable,
        }
    }

    fn proved_submission() -> (Vec<u8>, Vec<u8>) {
        let fixture = fixture([5, 41]);
        let mut rng = test_rng();
        let (request_bytes, bundle) = prove_ristretto_reconstruction_v2_native(
            RistrettoReconstructionV2ProverInputs {
                witness: fixture.witness,
                opening: fixture.opening,
                aggregate_pk: fixture.aggregate_pk,
                owner_sk: fixture.owner_sk,
                owner_pk: fixture.owner_pk,
                user_readable_cards: fixture.readable,
            },
            &mut rng,
        )
        .expect("V2 native reconstruction proof");
        let archive = bundle.encode_archive().expect("ZR3N archive");
        (request_bytes, archive)
    }

    #[test]
    fn proves_and_verifies_a_complete_v2_native_reconstruction() {
        let started = std::time::Instant::now();
        let (request_bytes, archive_bytes) = proved_submission();
        let prove_elapsed = started.elapsed();
        let started = std::time::Instant::now();
        admit_ristretto_air_v2_native_submission(&request_bytes, &archive_bytes)
            .expect("complete V2 native reconstruction admits");
        eprintln!(
            "ristretto-air v2 native reconstruction: prove {:?}, verify+admit {:?}, request {} bytes, archive {} bytes",
            prove_elapsed,
            started.elapsed(),
            request_bytes.len(),
            archive_bytes.len(),
        );
    }

    #[test]
    fn verifier_rejects_tampered_v2_native_submissions() {
        let (request_bytes, archive_bytes) = proved_submission();
        admit_ristretto_air_v2_native_submission(&request_bytes, &archive_bytes)
            .expect("baseline submission admits");

        // Request contribution splice: the archive detaches from the request.
        let request = ReconstructionV3VerifyRequest::decode(&request_bytes).expect("decode");
        let mut swapped = request.clone();
        swapped.contributions[9] = swapped.contributions[10].clone();
        let swapped_bytes = swapped.encode().expect("encode");
        assert!(admit_ristretto_air_v2_native_submission(&swapped_bytes, &archive_bytes).is_err());

        // Slot-membership response splice inside the envelope.  Rebuild the
        // envelope so the tamper reaches the native equations rather than the
        // component digest.
        let envelope = validate_ristretto_reconstruction_proof_wire(&request).expect("envelope");
        let mut slot_or = envelope.slot_or_proofs;
        slot_or[17].responses[1][20] ^= 1;
        let rebuilt = envelope_from_parts(
            &request,
            &envelope.negative_contributions,
            &envelope.shuffle_proof,
            &envelope.cross_key_proofs,
            &slot_or,
        )
        .expect("rebuilt envelope");
        let mut tampered = request.clone();
        tampered.proof = rebuilt.encode_wire().expect("wire");
        let tampered_bytes = tampered.encode().expect("encode");
        assert!(admit_ristretto_air_v2_native_submission(&tampered_bytes, &archive_bytes).is_err());

        // Cross-key response splice.
        let mut cross_key = envelope.cross_key_proofs;
        cross_key[1].response_owner_sk[20] ^= 1;
        let rebuilt = envelope_from_parts(
            &request,
            &envelope.negative_contributions,
            &envelope.shuffle_proof,
            &cross_key,
            &envelope.slot_or_proofs,
        )
        .expect("rebuilt envelope");
        let mut tampered = request.clone();
        tampered.proof = rebuilt.encode_wire().expect("wire");
        assert!(
            admit_ristretto_air_v2_native_submission(
                &tampered.encode().expect("encode"),
                &archive_bytes
            )
            .is_err()
        );

        // Bayer--Groth commitment splice.
        let mut shuffle = envelope.shuffle_proof.clone();
        shuffle.c_permutation[7] ^= 4;
        let rebuilt = envelope_from_parts(
            &request,
            &envelope.negative_contributions,
            &shuffle,
            &envelope.cross_key_proofs,
            &envelope.slot_or_proofs,
        )
        .expect("rebuilt envelope");
        let mut tampered = request.clone();
        tampered.proof = rebuilt.encode_wire().expect("wire");
        assert!(
            admit_ristretto_air_v2_native_submission(
                &tampered.encode().expect("encode"),
                &archive_bytes
            )
            .is_err()
        );

        // Recorded shuffle challenge splice inside the ZR3N archive.
        let mut bundle =
            ArchivedRistrettoReconstructionV2NativeBundle::decode_archive(&archive_bytes)
                .expect("bundle");
        bundle.contribution_shuffle.challenges[2].image[0] ^= 1;
        let tampered_archive = bundle.encode_archive().expect("archive");
        let error = admit_ristretto_air_v2_native_submission(&request_bytes, &tampered_archive)
            .expect_err("spliced shuffle challenge must fail");
        assert!(error.to_string().contains("challenge schedule"));

        // Flock transcript splice inside the bundle.
        let mut bundle =
            ArchivedRistrettoReconstructionV2NativeBundle::decode_archive(&archive_bytes)
                .expect("bundle");
        bundle.flock_transcript.component_digest[0] ^= 1;
        let tampered_archive = bundle.encode_archive().expect("archive");
        assert!(
            admit_ristretto_air_v2_native_submission(&request_bytes, &tampered_archive).is_err()
        );

        // Non-canonical archive bytes.
        let mut trailing = archive_bytes.clone();
        trailing.push(0);
        assert!(ArchivedRistrettoReconstructionV2NativeBundle::decode_archive(&trailing).is_err());
    }

    #[test]
    fn verifier_rejects_a_replayed_archive_against_another_table() {
        // Prove against one readable pair, submit against a request whose
        // readable pair differs: the state binding detaches.
        let (request_bytes, archive_bytes) = proved_submission();
        let fixture = fixture([6, 42]);
        let mut rng = test_rng();
        let (other_request, _other_archive) = prove_ristretto_reconstruction_v2_native(
            RistrettoReconstructionV2ProverInputs {
                witness: fixture.witness,
                opening: fixture.opening,
                aggregate_pk: fixture.aggregate_pk,
                owner_sk: fixture.owner_sk,
                owner_pk: fixture.owner_pk,
                user_readable_cards: fixture.readable,
            },
            &mut rng,
        )
        .expect("other proof");
        assert_ne!(other_request, request_bytes);
        let error = admit_ristretto_air_v2_native_submission(&other_request, &archive_bytes)
            .expect_err("archive replay across tables must fail");
        assert!(
            error
                .to_string()
                .contains("detached from the submitted request")
        );
    }
}
