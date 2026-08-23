//! No-replay scope binding for canonical Reconstruction V3 requests.
//!
//! This module does not verify the reconstruction group equations yet.  It
//! closes the independent detachment gap between a direct canonical tagged row
//! and the future Ristretto reconstruction AIR request: the request is scoped
//! to the complete canonical transition without `ProveTask` or VM dispatch
//! replay, and its canonical byte digest is the row's proof commitment.

#![allow(missing_docs)]

use poker_protocol::precompile_abi::{
    CurveId, EncodedCiphertext, ReconstructionProofSystem, ReconstructionV3VerifyRequest,
    TranscriptId,
};

use crate::blake2b_lookup_compression::{
    ArchivedBlake2bLookupHashesProof, prove_blake2b_lookup_hashes, verify_blake2b_lookup_hashes,
};
use crate::canonical_state_hash::canonical_state_image_preimage;
use crate::error::{TexasAirError, TexasAirResult};
use crate::precompile_binding::{
    canonical_crypto_scope_preimage, canonical_precompile_call_context,
    canonical_precompile_call_context_from_digests, precompile_request_digest,
    precompile_request_preimage,
};
use crate::ristretto_reconstruction_proof_wire::validate_ristretto_reconstruction_proof_wire;
use crate::texas_canonical::{
    CANONICAL_ABI_VERSION, CANONICAL_RECONSTRUCT_COLLECTING_SUBTAG, CanonicalPhase,
    CanonicalSeatStatus, CanonicalTransitionKind, CanonicalTransitionWitness, MAX_CANONICAL_SEATS,
};

pub const CANONICAL_RECONSTRUCTION_CARDS: usize = 52;
pub const CANONICAL_RECONSTRUCTION_HOLE_CARDS: usize = 2;
pub const CANONICAL_RECONSTRUCTION_STATE_DOMAIN: &[u8] =
    b"zchain.texas.canonical-reconstruction-state.v1";
pub const CANONICAL_RECONSTRUCTION_CONTEXT_DOMAIN: &[u8] =
    b"zchain.texas.canonical-reconstruction-context.v1";
pub const CANONICAL_RECONSTRUCTION_PRIOR_STATE_DOMAIN: &[u8] =
    b"zchain.texas.canonical-reconstruction-prior-state.v1";

/// Deterministic public Ristretto card point for one canonical slot.
///
/// The Ristretto/AIR migration uses the same slot labels as the Texas VM's
/// deterministic card generator, but hashes them with the Ristretto backend;
/// it is intentionally a distinct 32-byte route from the legacy BLS12-381
/// 48-byte state encoding.
pub fn canonical_ristretto_card(index: usize) -> TexasAirResult<[u8; 32]> {
    if index >= CANONICAL_RECONSTRUCTION_CARDS {
        return Err(TexasAirError::SpecViolation(
            "canonical Ristretto card index is out of bounds".into(),
        ));
    }
    use poker_protocol::crypto::curve::{Curve, RistrettoCurve};
    let label = format!("texas_poker/card/{index}");
    Ok(*RistrettoCurve::hash_to_curve(label.as_bytes())
        .compress()
        .as_bytes())
}

/// Return the complete deterministic 52-card Ristretto route in canonical
/// slot order.
pub fn canonical_ristretto_cards() -> [[u8; 32]; CANONICAL_RECONSTRUCTION_CARDS] {
    std::array::from_fn(|index| {
        canonical_ristretto_card(index).expect("fixed canonical Ristretto card index")
    })
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct CanonicalRistrettoCiphertext {
    pub c1: [u8; 32],
    pub c2: [u8; 32],
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct CanonicalReadableHoleCard {
    pub present: bool,
    pub card_slot: u8,
    pub encrypted_card_index: u8,
    pub ciphertext: CanonicalRistrettoCiphertext,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, borsh::BorshSerialize, borsh::BorshDeserialize,
)]
pub struct CanonicalReconstructionSeatState {
    pub present: bool,
    pub owner_pk: [u8; 32],
    pub readable_cards: [CanonicalReadableHoleCard; CANONICAL_RECONSTRUCTION_HOLE_CARDS],
}

/// Fixed-width pre-state opening behind
/// [`crate::texas_canonical::CanonicalStateImage::reconstruction_commitment`]
/// for the new Ristretto route.
///
/// This is intentionally a complete table-wide opening rather than an
/// action-seat-only projection.  Consequently one committed pre-state can
/// authenticate every pending seat without changing its meaning according to
/// which player submits next.
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct CanonicalReconstructionStateOpening {
    pub abi_version: u16,
    pub table_id: u64,
    pub hand_id: u32,
    pub max_players: u8,
    pub reconstruction_epoch: u64,
    pub pending_mask: u16,
    pub aggregate_pk: [u8; 32],
    pub seats: [CanonicalReconstructionSeatState; MAX_CANONICAL_SEATS],
    pub accumulator_present: bool,
    pub accumulated_deck: [CanonicalRistrettoCiphertext; CANONICAL_RECONSTRUCTION_CARDS],
}

/// Shared lookup proof for all hashes needed to detach a Reconstruction V3
/// statement from native transaction replay.
///
/// Statement order is fixed as: pre reconstruction state, post reconstruction
/// state, context, selected-seat prior state, encoded request, canonical pre
/// image, canonical post image, and the transition crypto scope.  Group
/// equations and the accumulator update are deliberately outside this archive.
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct ArchivedCanonicalReconstructionStateBindingProof {
    pub witness: CanonicalTransitionWitness,
    /// Authenticated collecting-state opening before the submission.
    pub opening: CanonicalReconstructionStateOpening,
    /// Authenticated collecting-state opening after a non-final submission.
    pub post_opening: CanonicalReconstructionStateOpening,
    pub request_bytes: Vec<u8>,
    pub hashes: ArchivedBlake2bLookupHashesProof,
}

fn fixed_ciphertext(value: &EncodedCiphertext) -> TexasAirResult<CanonicalRistrettoCiphertext> {
    let c1: [u8; 32] = value.c1.as_slice().try_into().map_err(|_| {
        TexasAirError::SpecViolation("Ristretto ciphertext c1 is not 32 bytes".into())
    })?;
    let c2: [u8; 32] = value.c2.as_slice().try_into().map_err(|_| {
        TexasAirError::SpecViolation("Ristretto ciphertext c2 is not 32 bytes".into())
    })?;
    Ok(CanonicalRistrettoCiphertext { c1, c2 })
}

pub fn canonical_reconstruction_state_preimage(
    opening: &CanonicalReconstructionStateOpening,
) -> TexasAirResult<Vec<u8>> {
    let encoded = borsh::to_vec(opening)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
    let mut message =
        Vec::with_capacity(CANONICAL_RECONSTRUCTION_STATE_DOMAIN.len() + encoded.len());
    message.extend_from_slice(CANONICAL_RECONSTRUCTION_STATE_DOMAIN);
    message.extend_from_slice(&encoded);
    Ok(message)
}

pub fn canonical_reconstruction_context_preimage(witness: &CanonicalTransitionWitness) -> Vec<u8> {
    let mut message = Vec::with_capacity(CANONICAL_RECONSTRUCTION_CONTEXT_DOMAIN.len() + 40);
    message.extend_from_slice(CANONICAL_RECONSTRUCTION_CONTEXT_DOMAIN);
    message.extend_from_slice(&CANONICAL_ABI_VERSION.to_le_bytes());
    message.extend_from_slice(&witness.pre.table_id.to_le_bytes());
    message.extend_from_slice(&witness.pre.hand_id.to_le_bytes());
    message.extend_from_slice(b"ristretto255");
    message
}

pub fn canonical_reconstruction_prior_state_preimage(
    witness: &CanonicalTransitionWitness,
    opening: &CanonicalReconstructionStateOpening,
    request: &ReconstructionV3VerifyRequest,
) -> TexasAirResult<Vec<u8>> {
    let selected = opening
        .seats
        .get(usize::from(witness.action.seat))
        .ok_or_else(|| {
            TexasAirError::SpecViolation("reconstruction seat is out of bounds".into())
        })?;
    let mut message = Vec::with_capacity(
        CANONICAL_RECONSTRUCTION_PRIOR_STATE_DOMAIN.len() + 2 + 8 + 8 + 1 + 8 + 32 + 52 * 32 + 132,
    );
    message.extend_from_slice(CANONICAL_RECONSTRUCTION_PRIOR_STATE_DOMAIN);
    message.extend_from_slice(&opening.abi_version.to_le_bytes());
    message.extend_from_slice(&opening.table_id.to_le_bytes());
    message.extend_from_slice(&opening.hand_id.to_le_bytes());
    message.push(witness.action.seat);
    message.extend_from_slice(&opening.reconstruction_epoch.to_le_bytes());
    message.extend_from_slice(&opening.aggregate_pk);
    for card in &request.cards {
        let card: &[u8; 32] = card.as_slice().try_into().map_err(|_| {
            TexasAirError::SpecViolation("canonical reconstruction card is not 32 bytes".into())
        })?;
        message.extend_from_slice(card);
    }
    for card in &selected.readable_cards {
        message.push(card.card_slot);
        message.push(card.encrypted_card_index);
        message.extend_from_slice(&card.ciphertext.c1);
        message.extend_from_slice(&card.ciphertext.c2);
    }
    Ok(message)
}

fn validate_opening_shape(
    witness: &CanonicalTransitionWitness,
    opening: &CanonicalReconstructionStateOpening,
    request: &ReconstructionV3VerifyRequest,
) -> TexasAirResult<()> {
    if witness.pre.phase != CanonicalPhase::Reconstructing
        || witness.pre.phase_subtag != CANONICAL_RECONSTRUCT_COLLECTING_SUBTAG
    {
        return Err(TexasAirError::SpecViolation(
            "canonical reconstruction opening requires the collecting phase".into(),
        ));
    }
    if opening.abi_version != CANONICAL_ABI_VERSION
        || opening.table_id != witness.pre.table_id
        || opening.hand_id != witness.pre.hand_id
        || opening.max_players != witness.pre.max_players
        || opening.pending_mask != witness.pre.protocol_pending_mask
        || opening.reconstruction_epoch == 0
    {
        return Err(TexasAirError::SpecViolation(
            "canonical reconstruction opening is detached from the pre-state scope".into(),
        ));
    }
    let expected_deadline = opening
        .reconstruction_epoch
        .checked_add(u64::from(witness.pre.reconstruct_timeout_ms))
        .ok_or_else(|| TexasAirError::SpecViolation("reconstruction deadline overflow".into()))?;
    if witness.pre.deadline_ms != expected_deadline || opening.aggregate_pk == [0; 32] {
        return Err(TexasAirError::SpecViolation(
            "canonical reconstruction epoch/key is not authenticated by the pre-state".into(),
        ));
    }
    for (index, state) in opening.seats.iter().enumerate() {
        let occupied = index < usize::from(opening.max_players)
            && witness.pre.seats[index].status != CanonicalSeatStatus::Empty;
        if state.present != occupied {
            return Err(TexasAirError::SpecViolation(
                "canonical reconstruction owner-key presence disagrees with the seat image".into(),
            ));
        }
        if !state.present {
            if *state != CanonicalReconstructionSeatState::default() {
                return Err(TexasAirError::SpecViolation(
                    "absent canonical reconstruction seat is not zeroed".into(),
                ));
            }
            continue;
        }
        if state.owner_pk == [0; 32]
            || state.readable_cards.iter().enumerate().any(|(slot, card)| {
                !card.present
                    || usize::from(card.card_slot) != slot
                    || usize::from(card.encrypted_card_index) >= CANONICAL_RECONSTRUCTION_CARDS
            })
        {
            return Err(TexasAirError::SpecViolation(
                "present canonical reconstruction seat lacks two canonical readable cards".into(),
            ));
        }
    }
    if !opening.accumulator_present
        && opening
            .accumulated_deck
            .iter()
            .any(|ciphertext| *ciphertext != CanonicalRistrettoCiphertext::default())
    {
        return Err(TexasAirError::SpecViolation(
            "absent reconstruction accumulator is not canonically zeroed".into(),
        ));
    }

    let selected = opening
        .seats
        .get(usize::from(witness.action.seat))
        .ok_or_else(|| {
            TexasAirError::SpecViolation("reconstruction seat is outside the opening width".into())
        })?;
    let selected_bit = 1u16
        .checked_shl(u32::from(witness.action.seat))
        .ok_or_else(|| {
            TexasAirError::SpecViolation("reconstruction seat bit is out of range".into())
        })?;
    if opening.pending_mask & selected_bit == 0
        || request.reconstruction_epoch != opening.reconstruction_epoch
        || request.aggregate_pk.as_slice() != opening.aggregate_pk
        || request.owner_pk.as_slice() != selected.owner_pk
    {
        return Err(TexasAirError::SpecViolation(
            "reconstruction request key/epoch statement is detached from the state opening".into(),
        ));
    }
    for (request_card, opened_card) in request
        .user_readable_cards
        .iter()
        .zip(selected.readable_cards)
    {
        if fixed_ciphertext(request_card)? != opened_card.ciphertext {
            return Err(TexasAirError::SpecViolation(
                "reconstruction request readable card is detached from the state opening".into(),
            ));
        }
    }
    Ok(())
}

fn validate_post_opening_shape(
    witness: &CanonicalTransitionWitness,
    opening: &CanonicalReconstructionStateOpening,
    post_opening: &CanonicalReconstructionStateOpening,
) -> TexasAirResult<()> {
    let selected_bit = 1u16
        .checked_shl(u32::from(witness.action.seat))
        .ok_or_else(|| {
            TexasAirError::SpecViolation("reconstruction seat bit is out of range".into())
        })?;
    if opening.pending_mask & selected_bit == 0 {
        return Err(TexasAirError::SpecViolation(
            "selected reconstruction seat is not pending in the pre opening".into(),
        ));
    }
    let remaining = opening.pending_mask & !selected_bit;
    if remaining == 0 {
        return Err(TexasAirError::SpecViolation(
            "final reconstruction submission requires the unfinished deck/shuffle composition"
                .into(),
        ));
    }
    if witness.post.phase != CanonicalPhase::Reconstructing
        || witness.post.phase_subtag != CANONICAL_RECONSTRUCT_COLLECTING_SUBTAG
        || witness.post.protocol_pending_mask != remaining
        || witness.post.deck_commitment != witness.pre.deck_commitment
    {
        return Err(TexasAirError::SpecViolation(
            "non-final reconstruction post-state does not remain in the collecting phase".into(),
        ));
    }
    if post_opening.abi_version != opening.abi_version
        || post_opening.table_id != opening.table_id
        || post_opening.hand_id != opening.hand_id
        || post_opening.max_players != opening.max_players
        || post_opening.reconstruction_epoch != opening.reconstruction_epoch
        || post_opening.pending_mask != remaining
        || post_opening.aggregate_pk != opening.aggregate_pk
        || post_opening.seats != opening.seats
        || !post_opening.accumulator_present
    {
        return Err(TexasAirError::SpecViolation(
            "canonical reconstruction post opening is not the exact non-final accumulator update"
                .into(),
        ));
    }
    Ok(())
}

/// Derive the only valid collecting-state opening after a non-final
/// reconstruction submission.
pub fn canonical_reconstruction_post_opening(
    witness: &CanonicalTransitionWitness,
    opening: &CanonicalReconstructionStateOpening,
    accumulated_deck: [CanonicalRistrettoCiphertext; CANONICAL_RECONSTRUCTION_CARDS],
) -> TexasAirResult<CanonicalReconstructionStateOpening> {
    let mut post_opening = opening.clone();
    let selected_bit = 1u16
        .checked_shl(u32::from(witness.action.seat))
        .ok_or_else(|| {
            TexasAirError::SpecViolation("reconstruction seat bit is out of range".into())
        })?;
    post_opening.pending_mask &= !selected_bit;
    post_opening.accumulator_present = true;
    post_opening.accumulated_deck = accumulated_deck;
    validate_post_opening_shape(witness, opening, &post_opening)?;
    Ok(post_opening)
}

fn reconstruction_hash_messages(
    witness: &CanonicalTransitionWitness,
    opening: &CanonicalReconstructionStateOpening,
    post_opening: &CanonicalReconstructionStateOpening,
    request: &ReconstructionV3VerifyRequest,
    request_bytes: &[u8],
) -> TexasAirResult<Vec<Vec<u8>>> {
    Ok(vec![
        canonical_reconstruction_state_preimage(opening)?,
        canonical_reconstruction_state_preimage(post_opening)?,
        canonical_reconstruction_context_preimage(witness),
        canonical_reconstruction_prior_state_preimage(witness, opening, request)?,
        precompile_request_preimage(request_bytes),
        canonical_state_image_preimage(&witness.pre)?,
        canonical_state_image_preimage(&witness.post)?,
        canonical_crypto_scope_preimage(witness),
    ])
}

fn validate_hash_statement_binding(
    archive: &ArchivedCanonicalReconstructionStateBindingProof,
    request: &ReconstructionV3VerifyRequest,
) -> TexasAirResult<()> {
    let messages = reconstruction_hash_messages(
        &archive.witness,
        &archive.opening,
        &archive.post_opening,
        request,
        &archive.request_bytes,
    )?;
    if archive.hashes.statements.len() != messages.len()
        || archive
            .hashes
            .statements
            .iter()
            .zip(&messages)
            .any(|(statement, message)| statement.message != *message)
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "canonical reconstruction hash batch has detached message bytes".into(),
        ));
    }
    let statements = &archive.hashes.statements;
    if statements[0].digest != archive.witness.pre.reconstruction_commitment
        || statements[1].digest != archive.witness.post.reconstruction_commitment
        || statements[2].digest != request.context_digest
        || statements[3].digest != request.prior_state_digest
        || statements[4].digest != archive.witness.action.proof_commitment
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "canonical reconstruction hash batch has a detached public digest".into(),
        ));
    }
    let expected_context = canonical_precompile_call_context_from_digests(
        &archive.witness,
        statements[5].digest,
        statements[6].digest,
        statements[7].digest,
    );
    if request.call_context != expected_context {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "canonical reconstruction call context is detached from lookup-backed state/scope hashes"
                .into(),
        ));
    }
    Ok(())
}

pub fn prove_canonical_reconstruction_state_binding(
    witness: CanonicalTransitionWitness,
    opening: CanonicalReconstructionStateOpening,
    post_opening: CanonicalReconstructionStateOpening,
    request: ReconstructionV3VerifyRequest,
) -> TexasAirResult<ArchivedCanonicalReconstructionStateBindingProof> {
    validate_canonical_reconstruction_request_scope(&witness, &request)?;
    validate_opening_shape(&witness, &opening, &request)?;
    validate_post_opening_shape(&witness, &opening, &post_opening)?;
    let request_bytes = request.encode().map_err(|error| {
        TexasAirError::SerializationError(format!("canonical request encoding failed: {error}"))
    })?;
    let messages =
        reconstruction_hash_messages(&witness, &opening, &post_opening, &request, &request_bytes)?;
    let archive = ArchivedCanonicalReconstructionStateBindingProof {
        witness,
        opening,
        post_opening,
        request_bytes,
        hashes: prove_blake2b_lookup_hashes(&messages)?,
    };
    validate_hash_statement_binding(&archive, &request)?;
    Ok(archive)
}

pub fn verify_canonical_reconstruction_state_binding(
    archive: &ArchivedCanonicalReconstructionStateBindingProof,
) -> TexasAirResult<()> {
    let request =
        ReconstructionV3VerifyRequest::decode(&archive.request_bytes).map_err(|error| {
            TexasAirError::SerializationError(format!("canonical request decoding failed: {error}"))
        })?;
    validate_reconstruction_request_shape(&request)?;
    validate_reconstruction_witness_scope_shape(&archive.witness)?;
    validate_opening_shape(&archive.witness, &archive.opening, &request)?;
    validate_post_opening_shape(&archive.witness, &archive.opening, &archive.post_opening)?;
    validate_hash_statement_binding(archive, &request)?;
    verify_blake2b_lookup_hashes(&archive.hashes)
}

fn validate_reconstruction_witness_scope_shape(
    witness: &CanonicalTransitionWitness,
) -> TexasAirResult<()> {
    // This archive is independently constructible from the lookup proofs, so
    // verification must not rely on the prover-side
    // `validate_canonical_reconstruction_request_scope` call having happened.
    // In particular, an attacker must not be able to authenticate hashes for
    // a witness carrying a reserved action field, a detached nullifier, or an
    // otherwise invalid non-final reconstruction transition and then present
    // it as a state-binding archive.  The direct canonical AIR remains the
    // production relation; this check keeps this standalone composition
    // helper fail-closed with exactly the same canonical ABI predicate.
    witness
        .validate_shape()
        .map_err(TexasAirError::SpecViolation)?;
    witness
        .pre
        .validate()
        .map_err(TexasAirError::SpecViolation)?;
    witness
        .post
        .validate()
        .map_err(TexasAirError::SpecViolation)?;
    if witness.kind != CanonicalTransitionKind::SubmitReconstruct
        || witness.pre.table_id != witness.post.table_id
        || witness.action.seat >= witness.pre.max_players
        || witness.actor == [0; 32]
        || witness.action.amount != 0
        || witness.action.auxiliary != 0
        || witness.post.call_seq
            != witness.pre.call_seq.checked_add(1).ok_or_else(|| {
                TexasAirError::SpecViolation(
                    "canonical reconstruction call sequence overflow".into(),
                )
            })?
    {
        return Err(TexasAirError::SpecViolation(
            "canonical reconstruction lookup archive has an invalid transition scope".into(),
        ));
    }
    Ok(())
}

fn validate_reconstruction_request_shape(
    request: &ReconstructionV3VerifyRequest,
) -> TexasAirResult<()> {
    request.validate().map_err(|error| {
        TexasAirError::SpecViolation(format!(
            "canonical reconstruction request shape is invalid: {error}"
        ))
    })?;
    if request.curve != CurveId::Ristretto255
        || request.proof_system != ReconstructionProofSystem::RistrettoAirV1
        || request.transcript != TranscriptId::Poseidon252
    {
        return Err(TexasAirError::SpecViolation(
            "canonical reconstruction route requires RistrettoAirV1 with Poseidon252".into(),
        ));
    }
    if request.context.as_slice()
        != poker_protocol::zk_shuffle::reconstruction::RECONSTRUCTION_V3_PROOF_LABEL
    {
        return Err(TexasAirError::SpecViolation(
            "canonical reconstruction request uses the wrong proof transcript label".into(),
        ));
    }
    if request.cards.len() != CANONICAL_RECONSTRUCTION_CARDS
        || request.contributions.len() != CANONICAL_RECONSTRUCTION_CARDS
        || request.user_readable_cards.len() != CANONICAL_RECONSTRUCTION_HOLE_CARDS
    {
        return Err(TexasAirError::SpecViolation(
            "canonical Texas reconstruction requires 52 cards/contributions and two readable hole cards"
                .into(),
        ));
    }
    validate_ristretto_reconstruction_proof_wire(request)?;
    let expected_cards = canonical_ristretto_cards();
    if request
        .cards
        .iter()
        .enumerate()
        .any(|(index, card)| card.as_slice() != expected_cards[index])
    {
        return Err(TexasAirError::SpecViolation(
            "canonical reconstruction request cards are not the fixed Ristretto card set".into(),
        ));
    }
    if request.reconstruction_epoch == 0
        || request.context_digest == [0; 32]
        || request.prior_state_digest == [0; 32]
    {
        return Err(TexasAirError::SpecViolation(
            "canonical reconstruction request has a null state-binding digest or epoch".into(),
        ));
    }
    Ok(())
}

/// Validate one Ristretto Reconstruction V3 request against a direct canonical
/// transition, without decoding a `ProveTask` or replaying Texas VM dispatch.
///
/// This inexpensive scope check is paired with
/// [`prove_canonical_reconstruction_state_binding`] when lookup-backed hash
/// authentication is required.  The remaining composition must prove the 52
/// fixed card constants, contribution/accumulator group equations, and final
/// deck/reveal commitment transition.
pub fn validate_canonical_reconstruction_request_scope(
    witness: &CanonicalTransitionWitness,
    request: &ReconstructionV3VerifyRequest,
) -> TexasAirResult<()> {
    witness
        .validate_shape()
        .map_err(TexasAirError::SpecViolation)?;
    if witness.kind != CanonicalTransitionKind::SubmitReconstruct {
        return Err(TexasAirError::SpecViolation(
            "canonical reconstruction request is bound to the wrong transition kind".into(),
        ));
    }
    validate_reconstruction_request_shape(request)?;
    if request.call_context != canonical_precompile_call_context(witness) {
        return Err(TexasAirError::SpecViolation(
            "canonical reconstruction request is detached from the tagged transition scope".into(),
        ));
    }
    let request_bytes = request.encode().map_err(|error| {
        TexasAirError::SerializationError(format!(
            "canonical reconstruction request encoding failed: {error}"
        ))
    })?;
    if witness.action.proof_commitment != precompile_request_digest(&request_bytes) {
        return Err(TexasAirError::SpecViolation(
            "canonical reconstruction request digest does not match the tagged proof commitment"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use blake2::Blake2bVar;
    use blake2::digest::{Update, VariableOutput};

    use crate::texas_canonical::{
        CANONICAL_ABI_VERSION, CANONICAL_RECONSTRUCT_COLLECTING_SUBTAG, CanonicalActionPayload,
        CanonicalPhase, CanonicalRoundAdvanceOpening, CanonicalSeat, CanonicalSeatStatus,
        CanonicalStateImage, MAX_CANONICAL_SEATS, NO_CANONICAL_SEAT,
    };

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
            kind: CanonicalTransitionKind::SubmitReconstruct,
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

    fn ciphertext(byte: u8) -> EncodedCiphertext {
        EncodedCiphertext {
            c1: vec![byte; 32],
            c2: vec![byte.wrapping_add(1); 32],
        }
    }

    fn request(witness: &CanonicalTransitionWitness) -> ReconstructionV3VerifyRequest {
        ReconstructionV3VerifyRequest {
            curve: CurveId::Ristretto255,
            proof_system: ReconstructionProofSystem::RistrettoAirV1,
            transcript: TranscriptId::Poseidon252,
            context: poker_protocol::zk_shuffle::reconstruction::RECONSTRUCTION_V3_PROOF_LABEL
                .to_vec(),
            call_context: canonical_precompile_call_context(witness),
            statement_version: 3,
            context_digest: [1; 32],
            reconstruction_epoch: 8_000,
            prior_state_digest: [2; 32],
            aggregate_pk: vec![3; 32],
            owner_pk: vec![4; 32],
            cards: canonical_ristretto_cards()
                .into_iter()
                .map(|card| card.to_vec())
                .collect(),
            user_readable_cards: vec![ciphertext(60), ciphertext(62)],
            contributions: (0..52)
                .map(|index| ciphertext(80u8.wrapping_add(index as u8)))
                .collect(),
            proof: vec![9; 32],
        }
    }

    fn bound_pair() -> (CanonicalTransitionWitness, ReconstructionV3VerifyRequest) {
        let mut witness = unsealed_witness();
        let mut request = request(&witness);
        request.proof = crate::ristretto_reconstruction_proof_wire::RistrettoReconstructionProofEnvelope::from_components(
            &request,
            [crate::ristretto_reconstruction_proof_wire::RistrettoCiphertextProofWire {
                c1: [0xA0; 32], c2: [0xA1; 32]
            }; crate::ristretto_reconstruction_proof_wire::RISTRETTO_RECONSTRUCTION_READABLE_CARDS],
            crate::ristretto_reconstruction_proof_wire::RistrettoBayerGrothShuffleProofWire::default(),
            [crate::ristretto_reconstruction_proof_wire::RistrettoCrossKeyProofWire::default(); crate::ristretto_reconstruction_proof_wire::RISTRETTO_RECONSTRUCTION_READABLE_CARDS],
            [crate::ristretto_reconstruction_proof_wire::RistrettoSlotOrProofWire::default(); CANONICAL_RECONSTRUCTION_CARDS],
        )
        .unwrap()
        .encode_wire()
        .unwrap();
        let encoded = request.encode().expect("canonical request encoding");
        witness.action.proof_commitment = precompile_request_digest(&encoded);
        witness.seal();
        (witness, request)
    }

    fn native_hash(message: &[u8]) -> [u8; 32] {
        let mut hasher = Blake2bVar::new(32).unwrap();
        hasher.update(message);
        let mut digest = [0; 32];
        hasher.finalize_variable(&mut digest).unwrap();
        digest
    }

    fn opened_card(slot: u8, index: u8, byte: u8) -> CanonicalReadableHoleCard {
        CanonicalReadableHoleCard {
            present: true,
            card_slot: slot,
            encrypted_card_index: index,
            ciphertext: CanonicalRistrettoCiphertext {
                c1: [byte; 32],
                c2: [byte.wrapping_add(1); 32],
            },
        }
    }

    fn opening() -> CanonicalReconstructionStateOpening {
        let mut seats = [CanonicalReconstructionSeatState::default(); MAX_CANONICAL_SEATS];
        seats[0] = CanonicalReconstructionSeatState {
            present: true,
            owner_pk: [4; 32],
            readable_cards: [opened_card(0, 10, 60), opened_card(1, 11, 62)],
        };
        seats[1] = CanonicalReconstructionSeatState {
            present: true,
            owner_pk: [5; 32],
            readable_cards: [opened_card(0, 12, 64), opened_card(1, 13, 66)],
        };
        CanonicalReconstructionStateOpening {
            abi_version: CANONICAL_ABI_VERSION,
            table_id: 7,
            hand_id: 3,
            max_players: 2,
            reconstruction_epoch: 8_000,
            pending_mask: 0b11,
            aggregate_pk: [3; 32],
            seats,
            accumulator_present: false,
            accumulated_deck: [CanonicalRistrettoCiphertext::default();
                CANONICAL_RECONSTRUCTION_CARDS],
        }
    }

    fn lookup_bound_fixture() -> (
        CanonicalTransitionWitness,
        CanonicalReconstructionStateOpening,
        CanonicalReconstructionStateOpening,
        ReconstructionV3VerifyRequest,
        ArchivedBlake2bLookupHashesProof,
    ) {
        let opening = opening();
        let mut witness = unsealed_witness();
        witness.pre.reconstruction_commitment =
            native_hash(&canonical_reconstruction_state_preimage(&opening).unwrap());
        let post_opening = canonical_reconstruction_post_opening(
            &witness,
            &opening,
            [CanonicalRistrettoCiphertext::default(); CANONICAL_RECONSTRUCTION_CARDS],
        )
        .unwrap();
        witness.post.reconstruction_commitment =
            native_hash(&canonical_reconstruction_state_preimage(&post_opening).unwrap());
        let mut request = request(&witness);
        request.context_digest = native_hash(&canonical_reconstruction_context_preimage(&witness));
        request.prior_state_digest = native_hash(
            &canonical_reconstruction_prior_state_preimage(&witness, &opening, &request).unwrap(),
        );
        request.call_context = canonical_precompile_call_context(&witness);
        request.proof = crate::ristretto_reconstruction_proof_wire::RistrettoReconstructionProofEnvelope::from_components(
            &request,
            [crate::ristretto_reconstruction_proof_wire::RistrettoCiphertextProofWire {
                c1: [0xA0; 32], c2: [0xA1; 32]
            }; crate::ristretto_reconstruction_proof_wire::RISTRETTO_RECONSTRUCTION_READABLE_CARDS],
            crate::ristretto_reconstruction_proof_wire::RistrettoBayerGrothShuffleProofWire::default(),
            [crate::ristretto_reconstruction_proof_wire::RistrettoCrossKeyProofWire::default(); crate::ristretto_reconstruction_proof_wire::RISTRETTO_RECONSTRUCTION_READABLE_CARDS],
            [crate::ristretto_reconstruction_proof_wire::RistrettoSlotOrProofWire::default(); CANONICAL_RECONSTRUCTION_CARDS],
        )
        .unwrap()
        .encode_wire()
        .unwrap();
        let request_bytes = request.encode().unwrap();
        witness.action.proof_commitment = precompile_request_digest(&request_bytes);
        witness.seal();

        let messages = reconstruction_hash_messages(
            &witness,
            &opening,
            &post_opening,
            &request,
            &request_bytes,
        )
        .unwrap();
        let hashes = ArchivedBlake2bLookupHashesProof {
            statements: messages
                .into_iter()
                .map(
                    |message| crate::blake2b_lookup_compression::Blake2bLookupHashStatement {
                        digest: native_hash(&message),
                        message,
                    },
                )
                .collect(),
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
        (witness, opening, post_opening, request, hashes)
    }

    #[test]
    fn canonical_reconstruction_scope_binds_request_without_replay() {
        let (witness, request) = bound_pair();
        validate_canonical_reconstruction_request_scope(&witness, &request)
            .expect("canonical reconstruction scope");

        let mut spliced_proof = request.clone();
        spliced_proof.proof[0] ^= 1;
        assert!(validate_canonical_reconstruction_request_scope(&witness, &spliced_proof).is_err());

        let mut spliced_scope = request.clone();
        spliced_scope.call_context[0] ^= 1;
        assert!(validate_canonical_reconstruction_request_scope(&witness, &spliced_scope).is_err());

        let mut legacy_route = request.clone();
        legacy_route.proof_system = ReconstructionProofSystem::BayerGrothSlotOrV3;
        assert!(validate_canonical_reconstruction_request_scope(&witness, &legacy_route).is_err());

        let mut wrong_card_route = request;
        wrong_card_route.cards[0][0] ^= 1;
        assert!(
            validate_canonical_reconstruction_request_scope(&witness, &wrong_card_route).is_err()
        );
    }

    #[test]
    fn canonical_ristretto_card_set_is_fixed_width_ordered_and_unique() {
        let cards = canonical_ristretto_cards();
        assert_eq!(cards.len(), CANONICAL_RECONSTRUCTION_CARDS);
        let unique = cards.iter().collect::<std::collections::HashSet<_>>();
        assert_eq!(unique.len(), CANONICAL_RECONSTRUCTION_CARDS);
        assert!(canonical_ristretto_card(CANONICAL_RECONSTRUCTION_CARDS).is_err());
    }

    #[test]
    fn crypto_scope_commitment_has_no_request_digest_fixed_point() {
        let mut witness = unsealed_witness();
        let before = witness.crypto_scope_commitment();
        witness.action.proof_commitment = [0xAA; 32];
        witness.seal();
        assert_eq!(before, witness.crypto_scope_commitment());

        witness.post.state_root[0] ^= 1;
        assert_ne!(before, witness.crypto_scope_commitment());
    }

    #[test]
    fn lookup_batch_opens_reconstruction_state_and_request_digests() {
        let (witness, opening, post_opening, request, hashes) = lookup_bound_fixture();
        validate_canonical_reconstruction_request_scope(&witness, &request).unwrap();
        validate_opening_shape(&witness, &opening, &request).unwrap();
        let request_bytes = request.encode().unwrap();
        let archive = ArchivedCanonicalReconstructionStateBindingProof {
            witness,
            opening,
            post_opening,
            request_bytes,
            hashes,
        };
        validate_hash_statement_binding(&archive, &request).unwrap();

        let mut owner_splice = archive.clone();
        owner_splice.opening.seats[0].owner_pk[0] ^= 1;
        assert!(
            validate_opening_shape(&owner_splice.witness, &owner_splice.opening, &request).is_err()
        );

        let mut post_owner_splice = archive.clone();
        post_owner_splice.post_opening.seats[0].owner_pk[0] ^= 1;
        assert!(
            validate_post_opening_shape(
                &post_owner_splice.witness,
                &post_owner_splice.opening,
                &post_owner_splice.post_opening,
            )
            .is_err()
        );

        let mut post_digest_splice = archive.clone();
        post_digest_splice.hashes.statements[1].digest[0] ^= 1;
        assert!(validate_hash_statement_binding(&post_digest_splice, &request).is_err());

        let mut post_accumulator_splice = archive.clone();
        post_accumulator_splice.post_opening.accumulated_deck[0].c1[0] ^= 2;
        assert!(
            validate_post_opening_shape(
                &post_accumulator_splice.witness,
                &post_accumulator_splice.opening,
                &post_accumulator_splice.post_opening,
            )
            .is_ok()
        );
        // The deck value is authenticated by the post opening hash statement;
        // changing it without changing that statement must fail the byte
        // binding check even though the static shape remains valid.
        assert!(validate_hash_statement_binding(&post_accumulator_splice, &request).is_err());

        let mut post_pending_splice = archive.clone();
        post_pending_splice.post_opening.pending_mask = 0;
        assert!(
            validate_post_opening_shape(
                &post_pending_splice.witness,
                &post_pending_splice.opening,
                &post_pending_splice.post_opening,
            )
            .is_err()
        );

        let mut post_key_splice = archive.clone();
        post_key_splice.post_opening.aggregate_pk[0] ^= 2;
        assert!(
            validate_post_opening_shape(
                &post_key_splice.witness,
                &post_key_splice.opening,
                &post_key_splice.post_opening,
            )
            .is_err()
        );

        let mut prior_digest_splice = archive;
        prior_digest_splice.hashes.statements[3].digest[0] ^= 1;
        assert!(validate_hash_statement_binding(&prior_digest_splice, &request).is_err());
    }

    #[test]
    fn proves_nonfinal_pre_and_post_reconstruction_openings_in_one_hash_batch() {
        let (witness, opening, post_opening, request, _) = lookup_bound_fixture();
        let archive =
            prove_canonical_reconstruction_state_binding(witness, opening, post_opening, request)
                .unwrap();
        verify_canonical_reconstruction_state_binding(&archive).unwrap();
    }

    #[test]
    fn post_opening_clears_only_the_selected_pending_bit_and_rejects_final_scope() {
        let opening = opening();
        let witness = unsealed_witness();
        let post_opening = canonical_reconstruction_post_opening(
            &witness,
            &opening,
            [CanonicalRistrettoCiphertext::default(); CANONICAL_RECONSTRUCTION_CARDS],
        )
        .unwrap();
        assert_eq!(post_opening.pending_mask, 0b10);
        assert!(post_opening.accumulator_present);

        let mut pending_splice = post_opening.clone();
        pending_splice.pending_mask = 0;
        assert!(validate_post_opening_shape(&witness, &opening, &pending_splice).is_err());

        let mut deck_drift = witness.clone();
        deck_drift.post.deck_commitment[0] ^= 1;
        assert!(validate_post_opening_shape(&deck_drift, &opening, &post_opening).is_err());

        let mut final_witness = witness;
        final_witness.pre.protocol_pending_mask = 0b01;
        final_witness.post.protocol_pending_mask = 0;
        let mut final_opening = opening;
        final_opening.pending_mask = 0b01;
        assert!(
            canonical_reconstruction_post_opening(
                &final_witness,
                &final_opening,
                [CanonicalRistrettoCiphertext::default(); CANONICAL_RECONSTRUCTION_CARDS],
            )
            .is_err()
        );

        let mut invalid_seat = final_witness;
        invalid_seat.action.seat = 15;
        let invalid_request = request(&invalid_seat);
        assert!(validate_opening_shape(&invalid_seat, &final_opening, &invalid_request).is_err());
    }

    #[test]
    fn reconstruction_opening_routes_the_second_pending_seat_by_its_actual_bit() {
        // The table-wide opening must be usable by whichever pending seat is
        // selected next.  Exercise seat one explicitly so a bit-position
        // error cannot accidentally clear/validate seat zero instead.
        let opening = opening();
        let mut witness = unsealed_witness();
        witness.action.seat = 1;
        witness.post.protocol_pending_mask = 0b01;

        let mut selected_request = request(&witness);
        selected_request.owner_pk = vec![5; 32];
        selected_request.user_readable_cards = vec![ciphertext(64), ciphertext(66)];
        validate_opening_shape(&witness, &opening, &selected_request)
            .expect("seat one must bind to its own opening and pending bit");

        let post_opening = canonical_reconstruction_post_opening(
            &witness,
            &opening,
            [CanonicalRistrettoCiphertext::default(); CANONICAL_RECONSTRUCTION_CARDS],
        )
        .expect("seat one non-final contribution");
        assert_eq!(post_opening.pending_mask, 0b01);
        validate_post_opening_shape(&witness, &opening, &post_opening)
            .expect("seat one post opening");

        let mut wrong_pending_transition = witness;
        wrong_pending_transition.post.protocol_pending_mask = 0b10;
        assert!(
            validate_post_opening_shape(&wrong_pending_transition, &opening, &post_opening,)
                .is_err()
        );
    }

    #[test]
    fn reconstruction_binding_verifier_rechecks_the_complete_canonical_transition() {
        let (witness, _) = bound_pair();
        validate_reconstruction_witness_scope_shape(&witness)
            .expect("sealed non-final reconstruction witness");

        // These fields are hash-authenticated by the archive, but that alone
        // must not turn a malformed canonical transition into an acceptable
        // state-binding statement. Both are reserved on SubmitReconstruct and
        // must therefore be rejected before the lookup proof is trusted.
        let mut reserved_flag = witness.clone();
        reserved_flag.action.flag = true;
        reserved_flag.seal();
        assert!(validate_reconstruction_witness_scope_shape(&reserved_flag).is_err());

        let mut unused_deadline = witness;
        unused_deadline.deadline_height = 1;
        unused_deadline.seal();
        assert!(validate_reconstruction_witness_scope_shape(&unused_deadline).is_err());
    }

    #[test]
    fn request_digest_preimage_is_the_public_commitment_message() {
        let (witness, _, _, request, _) = lookup_bound_fixture();
        let encoded = request.encode().unwrap();
        assert_eq!(
            native_hash(&precompile_request_preimage(&encoded)),
            witness.action.proof_commitment
        );
        assert_eq!(
            native_hash(&canonical_crypto_scope_preimage(&witness)),
            witness.crypto_scope_commitment()
        );
    }
}
