//! Direct heterogeneous AIR for the fixed-width canonical Texas transition ABI.
//!
//! This circuit deliberately consumes [`crate::texas_canonical::CanonicalTransitionWitness`]
//! rather than a transaction or a VM prove task. The AIR binds the fixed-width state-image links,
//! selector, limited actor policy, sequence arithmetic, table scope, batch boundaries, and padding
//! rows. It is intentionally not a proof of every Texas VM rule yet; see
//! `TRUST_MODEL_NO_TRANSACTION_REPLAY.md` before using it for production admission.
#![allow(missing_docs)]

use bincode::Options;
use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};
use stwo::core::channel::{Channel, Poseidon252Channel};
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::CommitmentSchemeVerifier;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::poseidon252_merkle::{
    Poseidon252MerkleChannel, Poseidon252MerkleHasher,
};
use stwo::core::verifier::{VerificationError, verify};
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::pcs::CommitmentSchemeProver;
use stwo::prover::{ProvingError, prove};
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
};

use crate::error::{TexasAirError, TexasAirResult};
use crate::texas_canonical::{
    CANONICAL_ABI_VERSION, CANONICAL_BETTING_TIMEOUT_MS, CanonicalSeatStatus, CanonicalStateImage,
    CanonicalTransitionKind, CanonicalTransitionWitness, MAX_CANONICAL_BOARD_REVEAL_ASSIGNMENTS,
    MAX_CANONICAL_SEATS, validate_batch,
};
use crate::trace_gen::MethodTrace;
use crate::trace_gen::generic_trace::tagged_batch_log_size;

const MAX_ROWS: usize = 1 << 10;
const KIND_COUNT: usize = 20;

// active, kinds, table, hand(pre/post), seq(pre/post), image commitments(pre/post),
// state roots(pre/post), lifecycle roots(pre/post), overlay roots(pre/post), settlement roots
// (pre/post), custody roots(pre/post), actor, action, deadline, and the sequence carry.
// The first 271 columns are the fixed canonical ABI.  The projection suffix carries the
// phase/round scalars and selected-seat image needed by the betting family.  Keeping it in
// the same row preserves the tagged batch's one-proof-per-table performance profile.
const BASE_NUM_COLUMNS: usize = 1563;
const FULL_BETTING_SEAT_WIDTH: usize = SEAT_STATUS_COUNT + 4 * 4 + 2;
const FULL_BETTING_SEATS_OFFSET: usize = BASE_NUM_COLUMNS;
const FULL_POST_BETTING_SEATS_OFFSET: usize =
    FULL_BETTING_SEATS_OFFSET + MAX_CANONICAL_SEATS * FULL_BETTING_SEAT_WIDTH;
const FULL_SEAT_STACK_BLOCK_OFFSET: usize = MAX_CANONICAL_SEATS * SEAT_STATUS_COUNT;
const NEXT_TURN_ADVICE_OFFSET: usize =
    BASE_NUM_COLUMNS + 2 * MAX_CANONICAL_SEATS * FULL_BETTING_SEAT_WIDTH + 2 * MAX_CANONICAL_SEATS;
const NEXT_TURN_SELECTOR_OFFSET: usize = NEXT_TURN_ADVICE_OFFSET + 1;
const NEXT_TURN_PAIR_OFFSET: usize = NEXT_TURN_SELECTOR_OFFSET + MAX_CANONICAL_SEATS;
const FUNDING_SEAT_SELECTOR_OFFSET: usize =
    NEXT_TURN_PAIR_OFFSET + MAX_CANONICAL_SEATS * MAX_CANONICAL_SEATS;
const ROUND_COLLECT_CARRIES_OFFSET: usize = FUNDING_SEAT_SELECTOR_OFFSET + MAX_CANONICAL_SEATS;
const ROUND_COLLECT_CARRY_BITS_OFFSET: usize = ROUND_COLLECT_CARRIES_OFFSET + 3;
const ROUND_COLLECT_BET_BITS_OFFSET: usize = ROUND_COLLECT_CARRY_BITS_OFFSET + 3 * 4;
const ROUND_COMPLETE_ACTIVE_OFFSET: usize =
    ROUND_COLLECT_BET_BITS_OFFSET + MAX_CANONICAL_SEATS * 4 * 16;
const ROUND_ADVANCE_OPENING_OFFSET: usize = ROUND_COMPLETE_ACTIVE_OFFSET + MAX_CANONICAL_SEATS;
const ROUND_ADVANCE_SCHEDULE_SELECTOR_OFFSET: usize =
    ROUND_ADVANCE_OPENING_OFFSET + 9 + MAX_CANONICAL_BOARD_REVEAL_ASSIGNMENTS * 6;
// For each of the pre/post deck cursors: 6 cursor bits, 6 bits of
// `52 - cursor`, and the six binary-addition carry-outs.  The subtraction is
// kept in the AIR so a prover cannot use a field element outside the 52-card
// deck after bypassing Rust-side witness validation.
const ROUND_ADVANCE_CARD_CURSOR_RANGE_OFFSET: usize = ROUND_ADVANCE_SCHEDULE_SELECTOR_OFFSET + 6;
// One selector per fixed seat for every canonical action that addresses a
// player.  This binds the selected status projection to the full-seat image
// for lifecycle/crypto families as well as the existing betting/funding
// projections.
const IMMUTABLE_COMMITMENTS_OFFSET: usize = ROUND_ADVANCE_CARD_CURSOR_RANGE_OFFSET + 2 * 6 * 3;
const DEADLINE_IMAGE_OFFSET: usize = IMMUTABLE_COMMITMENTS_OFFSET + 4 * 16;
const POST_DEADLINE_INV_OFFSET: usize = DEADLINE_IMAGE_OFFSET + 8;
const ADVANCE_DEADLINE_DIFFERENCE_OFFSET: usize = POST_DEADLINE_INV_OFFSET + 1;
const ADVANCE_DEADLINE_CARRIES_OFFSET: usize = ADVANCE_DEADLINE_DIFFERENCE_OFFSET + 4;
const ADVANCE_DEADLINE_RANGE_BITS_OFFSET: usize = ADVANCE_DEADLINE_CARRIES_OFFSET + 3;
const ADVANCE_DEADLINE_PRE_INV_OFFSET: usize = ADVANCE_DEADLINE_RANGE_BITS_OFFSET + 3 * 4 * 16;
const ADVANCE_DEADLINE_PHASE_INV_OFFSET: usize = ADVANCE_DEADLINE_PRE_INV_OFFSET + 1;
const LEAVE_AFTER_HAND_MASK_BITS_OFFSET: usize = ADVANCE_DEADLINE_PHASE_INV_OFFSET + 1;
const TRANSITION_SEAT_SELECTOR_OFFSET: usize =
    LEAVE_AFTER_HAND_MASK_BITS_OFFSET + 2 * MAX_CANONICAL_SEATS;
const OPAQUE_COMMITMENTS_OFFSET: usize = TRANSITION_SEAT_SELECTOR_OFFSET + MAX_CANONICAL_SEATS;
const OPAQUE_COMMITMENT_COUNT: usize = 5;
const STATE_IMAGE_METADATA_LIMBS: usize = 3;
const STATE_IMAGE_METADATA_OFFSET: usize =
    OPAQUE_COMMITMENTS_OFFSET + 2 * OPAQUE_COMMITMENT_COUNT * 16;
const SEAT_COMMITMENT_FIELD_COUNT: usize = 3;
const SEAT_COMMITMENT_LIMBS: usize = 16 * SEAT_COMMITMENT_FIELD_COUNT;
const SEAT_COMMITMENTS_OFFSET: usize = STATE_IMAGE_METADATA_OFFSET + 2 * STATE_IMAGE_METADATA_LIMBS;
// Each crypto-tagged row proves that its fixed 32-byte proof commitment is
// non-zero. The 16-bit decomposition is carried in the trace so unconstrained
// M31 limbs cannot cancel in the inverse relation.
const PROOF_COMMITMENT_BITS_OFFSET: usize =
    SEAT_COMMITMENTS_OFFSET + 2 * MAX_CANONICAL_SEATS * SEAT_COMMITMENT_LIMBS;
const ADVANCE_DEADLINE_TIME_BANK_ALL_OFFSET: usize = PROOF_COMMITMENT_BITS_OFFSET + 16 * 16;
const ADVANCE_DEADLINE_TIME_BANK_SLACK_OFFSET: usize = ADVANCE_DEADLINE_TIME_BANK_ALL_OFFSET + 1;
const ADVANCE_DEADLINE_TIME_BANK_EXCESS_OFFSET: usize = ADVANCE_DEADLINE_TIME_BANK_SLACK_OFFSET + 2;
const ADVANCE_DEADLINE_TIME_BANK_RANGE_BITS_OFFSET: usize =
    ADVANCE_DEADLINE_TIME_BANK_EXCESS_OFFSET + 2;
const ADVANCE_DEADLINE_TIME_BANK_CARRIES_OFFSET: usize =
    ADVANCE_DEADLINE_TIME_BANK_RANGE_BITS_OFFSET + 2 * 2 * 16;
const ADVANCE_DEADLINE_EXTENSION_CARRIES_OFFSET: usize =
    ADVANCE_DEADLINE_TIME_BANK_CARRIES_OFFSET + 3;
const ADVANCE_DEADLINE_GATES_OFFSET: usize = ADVANCE_DEADLINE_EXTENSION_CARRIES_OFFSET + 3;
const START_ACTIVE_PRODUCT_OFFSET: usize = ADVANCE_DEADLINE_GATES_OFFSET + 2;
const START_ACTIVE_COUNT_INV_OFFSET: usize = START_ACTIVE_PRODUCT_OFFSET + 1;
const START_BUTTON_SELECTOR_OFFSET: usize = START_ACTIVE_COUNT_INV_OFFSET + 1;
const START_PRE_BUTTON_SELECTOR_OFFSET: usize = START_BUTTON_SELECTOR_OFFSET + MAX_CANONICAL_SEATS;
const CONTINUITY_NEXT_PRE_OFFSET: usize = START_PRE_BUTTON_SELECTOR_OFFSET + MAX_CANONICAL_SEATS;
const CONTINUITY_DOMAIN_COUNT: usize = 6;
const NUM_COLUMNS: usize = CONTINUITY_NEXT_PRE_OFFSET + CONTINUITY_DOMAIN_COUNT * 16;
// The fixed public scope contains the table/sequence/image boundary plus the
// five authenticated root domains (state, lifecycle, overlay, settlement and
// custody) at both ends of the batch.
const PREPROCESSED_COLUMNS: usize = 39 + 16 * 10 + 2 * STATE_IMAGE_PROJECTION_LIMBS;
const SEAT_STATUS_COUNT: usize = 6;
const ROOT_SCOPE_OFFSET: usize = 39;
const ROOT_DOMAIN_COUNT: usize = 5;
const STATE_IMAGE_SCOPE_OFFSET: usize = ROOT_SCOPE_OFFSET + 16 * ROOT_DOMAIN_COUNT * 2;

// `CanonicalStateImage` is deliberately a fixed Borsh ABI.  These constants
// are byte positions in its 1,658-byte v3 encoding, not host projections.
// The endpoint scope below materializes every byte of that fixed image: u8
// fields stay separate, while the remaining bytes use 16-bit little-endian
// limbs.  Remaining host-zero gaps concern transition semantics, not an
// unbound endpoint field.
const CANONICAL_STATE_IMAGE_BORSH_BYTES: usize = 1_658;
const STATE_IMAGE_TABLE_OFFSET: usize = 2;
const STATE_IMAGE_HAND_OFFSET: usize = 10;
const STATE_IMAGE_CALL_SEQ_OFFSET: usize = 14;
const STATE_IMAGE_PHASE_OFFSET: usize = 18;
const STATE_IMAGE_PHASE_SUBTAG_OFFSET: usize = 19;
const STATE_IMAGE_STREET_OFFSET: usize = 20;
const STATE_IMAGE_TURN_OFFSET: usize = 21;
const STATE_IMAGE_DEADLINE_OFFSET: usize = 22;
const STATE_IMAGE_CURRENT_BET_OFFSET: usize = 30;
const STATE_IMAGE_MIN_RAISE_OFFSET: usize = 38;
const STATE_IMAGE_CHIP_POOL_OFFSET: usize = 46;
const STATE_IMAGE_POT_OFFSET: usize = 54;
const STATE_IMAGE_ACTED_MASK_OFFSET: usize = 64;
const STATE_IMAGE_LEAVE_MASK_OFFSET: usize = 66;
const STATE_IMAGE_BOARD_CARDS_COMMITMENT_OFFSET: usize = 68;
const STATE_IMAGE_DECK_COMMITMENT_OFFSET: usize = 100;
const STATE_IMAGE_REVEAL_COMMITMENT_OFFSET: usize = 132;
const STATE_IMAGE_RECONSTRUCTION_COMMITMENT_OFFSET: usize = 164;
const STATE_IMAGE_RUN_IT_TWICE_COMMITMENT_OFFSET: usize = 196;
const STATE_IMAGE_RULES_OFFSET: usize = 228;
const STATE_IMAGE_GOVERNANCE_OFFSET: usize = 260;
const STATE_IMAGE_SETTLEMENT_OFFSET: usize = 292;
const STATE_IMAGE_CUSTODY_OFFSET: usize = 324;
const STATE_IMAGE_LIFECYCLE_OFFSET: usize = 356;
const STATE_IMAGE_OVERLAY_OFFSET: usize = 388;
const STATE_IMAGE_ROOT_OFFSET: usize = 420;
const STATE_IMAGE_SEATS_OFFSET: usize = 452;
const STATE_IMAGE_SEAT_BYTES: usize = 134;
const STATE_IMAGE_SEAT_STATUS_OFFSET: usize = 0;
const STATE_IMAGE_SEAT_ACTED_OFFSET: usize = 1;
const STATE_IMAGE_SEAT_STACK_OFFSET: usize = 2;
const STATE_IMAGE_SEAT_BET_OFFSET: usize = 10;
const STATE_IMAGE_SEAT_TOTAL_OFFSET: usize = 18;
const STATE_IMAGE_SEAT_PENDING_OFFSET: usize = 26;
const STATE_IMAGE_SEAT_TIME_BANK_OFFSET: usize = 34;
const STATE_IMAGE_SEAT_IDENTITY_COMMITMENT_OFFSET: usize = 38;
const STATE_IMAGE_SEAT_KEY_COMMITMENT_OFFSET: usize = 70;
const STATE_IMAGE_SEAT_HOLE_CARDS_COMMITMENT_OFFSET: usize = 102;
const STATE_IMAGE_HEADER_PROJECTION_LIMBS: usize = 37;
const STATE_IMAGE_COMMITMENT_PROJECTION_LIMBS: usize = 16 * (7 + OPAQUE_COMMITMENT_COUNT);
const STATE_IMAGE_SEAT_PROJECTION_LIMBS: usize = 20 + SEAT_COMMITMENT_LIMBS;
const STATE_IMAGE_PROJECTION_LIMBS: usize = STATE_IMAGE_HEADER_PROJECTION_LIMBS
    + STATE_IMAGE_COMMITMENT_PROJECTION_LIMBS
    + MAX_CANONICAL_SEATS * STATE_IMAGE_SEAT_PROJECTION_LIMBS;

// Stable positions in the fixed canonical ABI prefix.  Keep mutation tests
// named rather than coupling them to incidental trace growth in the advice
// suffix below.
const ACTION_AMOUNT_OFFSET: usize = 258;
const PROOF_COMMITMENT_OFFSET: usize = ACTION_AMOUNT_OFFSET - 17;
const ACTION_AMOUNT_INVERSE_OFFSET: usize = 349;
const PRE_PHASE_OFFSET: usize = 272;
const POST_PHASE_OFFSET: usize = 273;
const POST_TURN_OFFSET: usize = 279;
const POST_LEAVE_MASK_OFFSET: usize = 307;
const SELECTED_POST_STATUS_OFFSET: usize = 328;
const DEADLINE_HEIGHT_OFFSET: usize = 267;

#[derive(Debug, Clone, Copy)]
struct CanonicalAir {
    log_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedCanonicalTaggedProof {
    pub log_size: u32,
    pub num_columns: u32,
    pub table_id: u64,
    pub first_hand_id: u32,
    pub last_hand_id: u32,
    pub first_call_seq: u32,
    pub last_call_seq: u32,
    pub transition_count: u16,
    pub batch_digest: [u8; 32],
    pub pre_state_commitment: [u8; 32],
    pub post_state_commitment: [u8; 32],
    pub pre_state_root: [u8; 32],
    pub post_state_root: [u8; 32],
    pub pre_lifecycle_root: [u8; 32],
    pub post_lifecycle_root: [u8; 32],
    pub pre_overlay_root: [u8; 32],
    pub post_overlay_root: [u8; 32],
    pub pre_settlement_commitment: [u8; 32],
    pub post_settlement_commitment: [u8; 32],
    pub pre_custody_commitment: [u8; 32],
    pub post_custody_commitment: [u8; 32],
    /// Exact Borsh bytes of the canonical endpoint images.  They are mixed
    /// into Fiat--Shamir and their AIR-visible projection is constrained to
    /// the first/last trace rows.  A companion Blake2b proof authenticates
    /// the complete byte strings to the two image commitments.
    pub pre_state_image_bytes: Vec<u8>,
    pub post_state_image_bytes: Vec<u8>,
    /// Immutable L1 object key of the fixed-width state-commitment leaf.
    ///
    /// A value of zero is reserved for the legacy canonical proof API.  The
    /// host-zero opening-composition API rejects it and requires this key to
    /// equal both authenticated SMT openings and the finalized receipt.
    pub state_object_key: [u8; 32],
    /// Versioned fixed-width state-leaf ABI.  It prevents a proof for one
    /// table-object layout from being accepted under another epoch.
    pub state_opening_epoch: u32,
    pub stark_proof_bytes: Vec<u8>,
}

/// Public state-object scope for a canonical transition proof.
///
/// The key is deliberately an L1 object key rather than a host-derived table
/// hash.  The finalized receipt authenticates that key for the table, while a
/// companion Blake2b SMT proof authenticates its value at the pre/post roots.
/// This keeps the verifier from depending on an RPC lookup or transaction
/// replay to associate an opening with the transition statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalStateOpeningScope {
    pub state_object_key: [u8; 32],
    pub state_opening_epoch: u32,
}

impl CanonicalStateOpeningScope {
    /// Legacy proofs intentionally have no fixed-width state-object opening.
    #[must_use]
    pub const fn legacy() -> Self {
        Self {
            state_object_key: [0; 32],
            state_opening_epoch: 0,
        }
    }

    /// Validate the non-legacy opening namespace.
    pub fn validate(self) -> TexasAirResult<()> {
        if self.state_object_key == [0; 32] || self.state_opening_epoch == 0 {
            return Err(TexasAirError::SpecViolation(
                "canonical fixed-width state opening requires a non-zero key and epoch".into(),
            ));
        }
        Ok(())
    }
}

fn options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(16 * 1024 * 1024)
}

fn digest_batch(witnesses: &[CanonicalTransitionWitness]) -> [u8; 32] {
    let encoded = borsh::to_vec(witnesses).expect("canonical witness encoding");
    let mut h = Blake2bVar::new(32).expect("digest length");
    h.update(b"zchain.texas.canonical-tagged-batch.v2");
    h.update(&encoded);
    let mut out = [0; 32];
    h.finalize_variable(&mut out).expect("digest length");
    out
}

fn bytes16(bytes: &[u8; 32]) -> Vec<M31> {
    bytes
        .chunks_exact(2)
        .map(|x| M31::from(u32::from(u16::from_le_bytes([x[0], x[1]]))))
        .collect()
}

fn state_image_limb(bytes: &[u8], offset: usize) -> M31 {
    M31::from(u32::from(u16::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
    ])))
}

fn append_state_image_u64_projection(out: &mut Vec<M31>, bytes: &[u8], offset: usize) {
    for limb in 0..4 {
        out.push(state_image_limb(bytes, offset + limb * 2));
    }
}

fn append_state_image_u32_projection(out: &mut Vec<M31>, bytes: &[u8], offset: usize) {
    for limb in 0..2 {
        out.push(state_image_limb(bytes, offset + limb * 2));
    }
}

fn append_state_image_commitment_projection(out: &mut Vec<M31>, bytes: &[u8], offset: usize) {
    for limb in 0..16 {
        out.push(state_image_limb(bytes, offset + limb * 2));
    }
}

/// Project the Borsh endpoint bytes onto values that the current canonical
/// transition AIR already carries in its trace.  This keeps the expensive
/// full byte statement in Fiat--Shamir while adding only 841 endpoint scope
/// limbs, rather than thousands of public columns.
fn state_image_projection(bytes: &[u8]) -> TexasAirResult<Vec<M31>> {
    if bytes.len() != CANONICAL_STATE_IMAGE_BORSH_BYTES {
        return Err(TexasAirError::SpecViolation(
            "canonical state-image Borsh byte length is invalid".into(),
        ));
    }
    let mut out = Vec::with_capacity(STATE_IMAGE_PROJECTION_LIMBS);
    out.push(state_image_limb(bytes, 0));
    out.push(M31::from(u32::from(bytes[62])));
    out.push(M31::from(u32::from(bytes[63])));
    append_state_image_u64_projection(&mut out, bytes, STATE_IMAGE_TABLE_OFFSET);
    append_state_image_u32_projection(&mut out, bytes, STATE_IMAGE_HAND_OFFSET);
    append_state_image_u32_projection(&mut out, bytes, STATE_IMAGE_CALL_SEQ_OFFSET);
    for offset in [
        STATE_IMAGE_PHASE_OFFSET,
        STATE_IMAGE_PHASE_SUBTAG_OFFSET,
        STATE_IMAGE_STREET_OFFSET,
        STATE_IMAGE_TURN_OFFSET,
    ] {
        out.push(M31::from(u32::from(bytes[offset])));
    }
    append_state_image_u64_projection(&mut out, bytes, STATE_IMAGE_DEADLINE_OFFSET);
    append_state_image_u64_projection(&mut out, bytes, STATE_IMAGE_CURRENT_BET_OFFSET);
    append_state_image_u64_projection(&mut out, bytes, STATE_IMAGE_MIN_RAISE_OFFSET);
    append_state_image_u64_projection(&mut out, bytes, STATE_IMAGE_CHIP_POOL_OFFSET);
    append_state_image_u64_projection(&mut out, bytes, STATE_IMAGE_POT_OFFSET);
    out.push(state_image_limb(bytes, STATE_IMAGE_ACTED_MASK_OFFSET));
    out.push(state_image_limb(bytes, STATE_IMAGE_LEAVE_MASK_OFFSET));
    for offset in [
        STATE_IMAGE_RULES_OFFSET,
        STATE_IMAGE_GOVERNANCE_OFFSET,
        STATE_IMAGE_ROOT_OFFSET,
        STATE_IMAGE_LIFECYCLE_OFFSET,
        STATE_IMAGE_OVERLAY_OFFSET,
        STATE_IMAGE_SETTLEMENT_OFFSET,
        STATE_IMAGE_CUSTODY_OFFSET,
    ] {
        append_state_image_commitment_projection(&mut out, bytes, offset);
    }
    for offset in [
        STATE_IMAGE_BOARD_CARDS_COMMITMENT_OFFSET,
        STATE_IMAGE_DECK_COMMITMENT_OFFSET,
        STATE_IMAGE_REVEAL_COMMITMENT_OFFSET,
        STATE_IMAGE_RECONSTRUCTION_COMMITMENT_OFFSET,
        STATE_IMAGE_RUN_IT_TWICE_COMMITMENT_OFFSET,
    ] {
        append_state_image_commitment_projection(&mut out, bytes, offset);
    }
    for seat in 0..MAX_CANONICAL_SEATS {
        let offset = STATE_IMAGE_SEATS_OFFSET + seat * STATE_IMAGE_SEAT_BYTES;
        out.push(M31::from(u32::from(
            bytes[offset + STATE_IMAGE_SEAT_STATUS_OFFSET],
        )));
        out.push(M31::from(u32::from(
            bytes[offset + STATE_IMAGE_SEAT_ACTED_OFFSET],
        )));
        append_state_image_u64_projection(&mut out, bytes, offset + STATE_IMAGE_SEAT_STACK_OFFSET);
        append_state_image_u64_projection(&mut out, bytes, offset + STATE_IMAGE_SEAT_BET_OFFSET);
        append_state_image_u64_projection(&mut out, bytes, offset + STATE_IMAGE_SEAT_TOTAL_OFFSET);
        append_state_image_u64_projection(
            &mut out,
            bytes,
            offset + STATE_IMAGE_SEAT_PENDING_OFFSET,
        );
        append_state_image_u32_projection(
            &mut out,
            bytes,
            offset + STATE_IMAGE_SEAT_TIME_BANK_OFFSET,
        );
        for commitment_offset in [
            STATE_IMAGE_SEAT_IDENTITY_COMMITMENT_OFFSET,
            STATE_IMAGE_SEAT_KEY_COMMITMENT_OFFSET,
            STATE_IMAGE_SEAT_HOLE_CARDS_COMMITMENT_OFFSET,
        ] {
            append_state_image_commitment_projection(&mut out, bytes, offset + commitment_offset);
        }
    }
    debug_assert_eq!(out.len(), STATE_IMAGE_PROJECTION_LIMBS);
    Ok(out)
}

fn validate_state_image_bytes(proof: &ArchivedCanonicalTaggedProof) -> TexasAirResult<()> {
    state_image_projection(&proof.pre_state_image_bytes)?;
    state_image_projection(&proof.post_state_image_bytes)?;
    Ok(())
}

fn u32_limbs(value: u32) -> [M31; 2] {
    [M31::from(value & 0xffff), M31::from(value >> 16)]
}

fn u64_limbs(value: u64) -> [M31; 4] {
    [
        M31::from((value & 0xffff) as u32),
        M31::from(((value >> 16) & 0xffff) as u32),
        M31::from(((value >> 32) & 0xffff) as u32),
        M31::from((value >> 48) as u32),
    ]
}

fn add_carries(left: u64, right: u64) -> [M31; 3] {
    let a = u64_limbs(left);
    let b = u64_limbs(right);
    let mut carry = 0u64;
    let mut out = [M31::from(0); 3];
    for index in 0..4 {
        let sum = u64::from(a[index].0) + u64::from(b[index].0) + carry;
        carry = sum >> 16;
        if index < 3 {
            out[index] = M31::from(carry as u32);
        }
    }
    out
}

/// Carries for `post_pot = pre_pot + sum(pre_seat_bet)`.  The final
/// high-limb carry is deliberately omitted: the AIR requires it to be zero,
/// which is the VM's checked-overflow condition.
fn round_collect_carries(pot: u64, seats: &[crate::texas_canonical::CanonicalSeat]) -> [M31; 3] {
    let pot = u64_limbs(pot);
    let bets: Vec<_> = seats.iter().map(|seat| u64_limbs(seat.bet)).collect();
    let mut carry = 0u64;
    let mut out = [M31::from(0); 3];
    for limb in 0..4 {
        let sum = u64::from(pot[limb].0)
            + bets.iter().map(|bet| u64::from(bet[limb].0)).sum::<u64>()
            + carry;
        carry = sum >> 16;
        if limb < 3 {
            out[limb] = M31::from(carry as u32);
        }
    }
    out
}

fn u16_bits(value: u16) -> [M31; 16] {
    std::array::from_fn(|index| M31::from(u32::from((value >> index) & 1)))
}

fn append_u64_bits(out: &mut Vec<M31>, value: u64) {
    for limb in 0..4 {
        out.extend(u16_bits(((value >> (limb * 16)) & 0xffff) as u16));
    }
}

fn mask_bits(value: u16) -> [M31; MAX_CANONICAL_SEATS] {
    std::array::from_fn(|index| M31::from(u32::from((value >> index) & 1)))
}

fn status_one_hot(status: CanonicalSeatStatus) -> [M31; SEAT_STATUS_COUNT] {
    std::array::from_fn(|index| M31::from(u32::from(index == status as usize)))
}

fn is_betting_action(kind: CanonicalTransitionKind) -> bool {
    matches!(
        kind,
        CanonicalTransitionKind::Fold
            | CanonicalTransitionKind::Check
            | CanonicalTransitionKind::Call
            | CanonicalTransitionKind::Raise
            | CanonicalTransitionKind::Bet
            | CanonicalTransitionKind::FoldWithProof
    )
}

fn is_crypto_action(kind: CanonicalTransitionKind) -> bool {
    matches!(
        kind,
        CanonicalTransitionKind::SubmitShuffle
            | CanonicalTransitionKind::SubmitReveal
            | CanonicalTransitionKind::SubmitReconstruct
            | CanonicalTransitionKind::FoldWithProof
    )
}

fn is_funding_action(kind: CanonicalTransitionKind) -> bool {
    matches!(
        kind,
        CanonicalTransitionKind::Addon | CanonicalTransitionKind::Rebuy
    )
}

fn row(w: &CanonicalTransitionWitness, next_pre: Option<&CanonicalStateImage>) -> Vec<M31> {
    let mut out = Vec::with_capacity(NUM_COLUMNS);
    out.push(M31::from(1u32));
    for index in 0..KIND_COUNT {
        out.push(M31::from(u32::from(index == w.kind as usize)));
    }
    out.extend(u64_limbs(w.pre.table_id));
    out.extend(u32_limbs(w.pre.hand_id));
    out.extend(u32_limbs(w.post.hand_id));
    out.extend(u32_limbs(w.pre.call_seq));
    out.extend(u32_limbs(w.post.call_seq));
    out.extend(bytes16(&w.pre.commitment()));
    out.extend(bytes16(&w.post.commitment()));
    for digest in [
        w.pre.state_root,
        w.post.state_root,
        w.pre.lifecycle_root,
        w.post.lifecycle_root,
        w.pre.overlay_root,
        w.post.overlay_root,
        w.pre.settlement_commitment,
        w.post.settlement_commitment,
        w.pre.custody_commitment,
        w.post.custody_commitment,
        w.actor,
        w.action.proof_commitment,
    ] {
        out.extend(bytes16(&digest));
    }
    out.push(M31::from(u32::from(w.action.seat)));
    out.extend(u64_limbs(w.action.amount));
    out.extend(u64_limbs(w.action.auxiliary));
    out.push(M31::from(u32::from(w.action.flag)));
    out.extend(u64_limbs(w.deadline_height));
    out.push(M31::from(u32::from(w.pre.call_seq & 0xffff == 0xffff)));
    for (pre, post) in [
        (w.pre.phase as u8, w.post.phase as u8),
        (w.pre.phase_subtag, w.post.phase_subtag),
        (w.pre.street, w.post.street),
        (w.pre.current_turn, w.post.current_turn),
    ] {
        out.push(M31::from(u32::from(pre)));
        out.push(M31::from(u32::from(post)));
    }
    for (pre, post) in [
        (w.pre.current_bet, w.post.current_bet),
        (w.pre.min_raise, w.post.min_raise),
        (w.pre.pot, w.post.pot),
    ] {
        out.extend(u64_limbs(pre));
        out.extend(u64_limbs(post));
    }
    out.push(M31::from(u32::from(w.pre.acted_mask)));
    out.push(M31::from(u32::from(w.post.acted_mask)));
    out.push(M31::from(u32::from(w.pre.leave_after_hand_mask)));
    out.push(M31::from(u32::from(w.post.leave_after_hand_mask)));
    let seat = usize::from(w.action.seat);
    let before = if seat < w.pre.seats.len() {
        Some(w.pre.seats[seat])
    } else {
        None
    };
    let after = if seat < w.post.seats.len() {
        Some(w.post.seats[seat])
    } else {
        None
    };
    let before_seat = before.unwrap_or(crate::texas_canonical::CanonicalSeat::EMPTY);
    for image in [before, after] {
        let image = image.unwrap_or(crate::texas_canonical::CanonicalSeat::EMPTY);
        out.push(M31::from(image.status as u32));
        out.push(M31::from(u32::from(image.acted)));
        out.extend(u64_limbs(image.stack));
        out.extend(u64_limbs(image.bet));
        out.extend(u64_limbs(image.total_bet));
        out.extend(u64_limbs(image.pending_addon));
        out.extend(u32_limbs(image.time_bank_ms));
    }
    // The inverse makes the AIR's `post_turn != action.seat` check a true field constraint.
    // Protocol-submit rows reuse this otherwise idle advice cell to prove the
    // selected seat is non-empty before accepting a shuffle/reveal/reconstruct
    // submission.
    let turn_delta = u32::from(w.post.current_turn) as u64 + 16 - u64::from(w.action.seat);
    let turn_delta = (turn_delta % 16) as u32;
    let protocol_submit = matches!(
        w.kind,
        CanonicalTransitionKind::SubmitShuffle
            | CanonicalTransitionKind::SubmitReveal
            | CanonicalTransitionKind::SubmitReconstruct
    );
    let turn_inverse_input = if protocol_submit {
        before_seat.status as u32
    } else {
        turn_delta
    };
    let turn_inv = if turn_inverse_input == 0 {
        M31::from(0)
    } else {
        // M31 inversion is represented by a host constant; the AIR still checks the product.
        M31::from(turn_inverse_input).inverse()
    };
    out.push(turn_inv);
    // Keep Call's ripple carries in the committed row. The fourth limb equation
    // constrains the omitted final carry to zero, so overflow cannot wrap.
    let amount_limb_sum = u64_limbs(w.action.amount)
        .into_iter()
        .map(|limb| u64::from(limb.0))
        .sum::<u64>();
    let proof_limb_sum = bytes16(&w.action.proof_commitment)
        .into_iter()
        .map(|limb| u64::from(limb.0))
        .sum::<u64>();
    let inverse_input = if is_crypto_action(w.kind) {
        proof_limb_sum
    } else {
        amount_limb_sum
    };
    out.push(if inverse_input == 0 {
        M31::from(0u32)
    } else {
        M31::from(inverse_input as u32).inverse()
    });
    let uses_delta_wager_carries = matches!(
        w.kind,
        CanonicalTransitionKind::Call | CanonicalTransitionKind::Bet
    );
    out.extend(if uses_delta_wager_carries {
        add_carries(after.map_or(0, |seat| seat.stack), w.action.amount)
    } else {
        [M31::from(0u32); 3]
    });
    out.extend(if uses_delta_wager_carries {
        add_carries(before.map_or(0, |seat| seat.bet), w.action.amount)
    } else {
        [M31::from(0u32); 3]
    });
    out.extend(if uses_delta_wager_carries {
        add_carries(before.map_or(0, |seat| seat.total_bet), w.action.amount)
    } else {
        [M31::from(0u32); 3]
    });
    // The VM keeps current-round wagers on seats and collects them into the
    // pot only when the betting round advances.
    out.extend([M31::from(0u32); 3]);
    // Canonical bit decompositions are essential for the ripple equations below:
    // without them a malicious prover could use arbitrary M31 elements as limbs
    // and satisfy an apparent u64 addition only modulo the field.
    for value in [
        before.map_or(0, |seat| seat.stack),
        after.map_or(0, |seat| seat.stack),
        before.map_or(0, |seat| seat.bet),
        after.map_or(0, |seat| seat.bet),
        before.map_or(0, |seat| seat.total_bet),
        after.map_or(0, |seat| seat.total_bet),
        w.pre.pot,
        w.post.pot,
        w.action.amount,
    ] {
        append_u64_bits(&mut out, value);
    }
    // Call requires its own comparison witness: `owed = current_bet - seat_bet`
    // and `amount = min(owed, stack)`.  A positive shortfall distinguishes a
    // short all-in from the equal-stack ordinary-call case.
    let owed = if w.kind == CanonicalTransitionKind::Call {
        w.pre.current_bet.saturating_sub(before_seat.bet)
    } else {
        0
    };
    let call_all_in = w.kind == CanonicalTransitionKind::Call && before_seat.stack < owed;
    let call_difference = if call_all_in {
        owed - before_seat.stack
    } else {
        before_seat.stack.saturating_sub(owed)
    };
    out.extend(u64_limbs(owed));
    out.extend(u64_limbs(call_difference));
    out.push(M31::from(u32::from(call_all_in)));
    let difference_limb_sum = u64_limbs(call_difference)
        .into_iter()
        .map(|limb| u64::from(limb.0))
        .sum::<u64>();
    out.push(if call_all_in {
        M31::from(difference_limb_sum as u32).inverse()
    } else {
        M31::from(0u32)
    });
    out.extend(add_carries(before_seat.bet, owed));
    out.extend(if call_all_in {
        [M31::from(0u32); 3]
    } else {
        add_carries(owed, call_difference)
    });
    out.extend(if call_all_in {
        add_carries(before_seat.stack, call_difference)
    } else {
        [M31::from(0u32); 3]
    });
    append_u64_bits(&mut out, owed);
    append_u64_bits(&mut out, call_difference);
    // Raise carries an absolute target bet. Its private comparison witnesses
    // prove the two strict target bounds, available stack, and the short
    // all-in exception to the minimum-raise rule without using host ordering.
    let is_raise = w.kind == CanonicalTransitionKind::Raise;
    let raise_needed = if is_raise {
        w.action.amount.saturating_sub(before_seat.bet)
    } else {
        0
    };
    let raise_delta = if is_raise {
        w.action.amount.saturating_sub(w.pre.current_bet)
    } else {
        0
    };
    let raise_stack_difference = if is_raise {
        before_seat.stack.saturating_sub(raise_needed)
    } else {
        0
    };
    let raise_meets_min = is_raise && raise_delta >= w.pre.min_raise;
    let raise_min_difference = if is_raise {
        if raise_meets_min {
            raise_delta - w.pre.min_raise
        } else {
            w.pre.min_raise.saturating_sub(raise_delta)
        }
    } else {
        0
    };
    let raise_all_in = is_raise && raise_needed == before_seat.stack;
    out.extend(u64_limbs(raise_needed));
    out.extend(u64_limbs(raise_delta));
    out.extend(u64_limbs(raise_stack_difference));
    out.extend(u64_limbs(raise_min_difference));
    out.push(M31::from(u32::from(raise_all_in)));
    out.push(M31::from(u32::from(raise_meets_min)));
    for value in [raise_needed, raise_delta] {
        let limb_sum = u64_limbs(value)
            .into_iter()
            .map(|limb| u64::from(limb.0))
            .sum::<u64>();
        out.push(if is_raise && limb_sum != 0 {
            M31::from(limb_sum as u32).inverse()
        } else {
            M31::from(0u32)
        });
    }
    let stack_difference_sum = u64_limbs(raise_stack_difference)
        .into_iter()
        .map(|limb| u64::from(limb.0))
        .sum::<u64>();
    out.push(if raise_all_in {
        M31::from(0u32)
    } else if is_raise {
        M31::from(stack_difference_sum as u32).inverse()
    } else {
        M31::from(0u32)
    });
    out.extend(add_carries(before_seat.bet, raise_needed));
    out.extend(add_carries(w.pre.current_bet, raise_delta));
    out.extend(add_carries(raise_needed, raise_stack_difference));
    out.extend(add_carries(before_seat.total_bet, raise_needed));
    out.extend([M31::from(0u32); 3]);
    for value in [
        raise_needed,
        raise_delta,
        raise_stack_difference,
        raise_min_difference,
    ] {
        append_u64_bits(&mut out, value);
    }
    // A chip-moving betting action must derive the selected-seat lifecycle
    // directly from the resulting stack: zero means AllIn, otherwise Active.
    // The inverse is checked in AIR, so this is not a host-selected branch.
    let is_chip_action = matches!(
        w.kind,
        CanonicalTransitionKind::Check
            | CanonicalTransitionKind::Call
            | CanonicalTransitionKind::Raise
            | CanonicalTransitionKind::Bet
    );
    let post_stack_sum = u64_limbs(after.map_or(0, |seat| seat.stack))
        .into_iter()
        .map(|limb| u64::from(limb.0))
        .sum::<u64>();
    let post_all_in = is_chip_action
        && after.map_or(false, |seat| {
            seat.status == crate::texas_canonical::CanonicalSeatStatus::AllIn
        });
    out.push(M31::from(u32::from(post_all_in)));
    out.push(M31::from(if is_chip_action {
        post_stack_sum as u32
    } else {
        0
    }));
    out.push(if is_chip_action && !post_all_in {
        M31::from(post_stack_sum as u32).inverse()
    } else {
        M31::from(0u32)
    });
    let pre_stack_sum = u64_limbs(before_seat.stack)
        .into_iter()
        .map(|limb| u64::from(limb.0))
        .sum::<u64>();
    out.push(M31::from(if is_betting_action(w.kind) {
        pre_stack_sum as u32
    } else {
        0
    }));
    out.push(if is_betting_action(w.kind) {
        M31::from(pre_stack_sum as u32).inverse()
    } else {
        M31::from(0u32)
    });
    // The complete fixed-width acted-mask is decomposed on every row.  For
    // betting actions a one-hot selected-seat vector proves that the chosen
    // seat's `acted` projection matches that mask.  Check/Call/Fold then use
    // the delta bits below to prove the VM's exact one-bit update.
    let is_betting = is_betting_action(w.kind);
    let seat_selectors: [M31; MAX_CANONICAL_SEATS] = std::array::from_fn(|index| {
        M31::from(u32::from(is_betting && usize::from(w.action.seat) == index))
    });
    let pre_acted_bits = mask_bits(w.pre.acted_mask);
    let post_acted_bits = mask_bits(w.post.acted_mask);
    let acted_deltas: [M31; MAX_CANONICAL_SEATS] = std::array::from_fn(|index| {
        M31::from(u32::from(
            is_betting
                && usize::from(w.action.seat) == index
                && pre_acted_bits[index] == M31::from(0u32),
        ))
    });
    out.extend(seat_selectors);
    out.extend(pre_acted_bits);
    out.extend(post_acted_bits);
    out.extend(acted_deltas);
    // TableVault is a distinct custody bucket in the VM.  It changes for
    // funding/join deposits and leave/kick refunds.
    let funding = is_funding_action(w.kind);
    let is_join = w.kind == CanonicalTransitionKind::JoinTable;
    let is_leave = w.kind == CanonicalTransitionKind::LeaveTable;
    let is_kick = w.kind == CanonicalTransitionKind::KickPlayer;
    let kick_refund = before_seat.stack.saturating_add(before_seat.pending_addon);
    out.extend(u64_limbs(w.pre.chip_pool));
    out.extend(u64_limbs(w.post.chip_pool));
    out.extend(if funding {
        add_carries(w.pre.chip_pool, w.action.amount)
    } else if is_join {
        add_carries(w.pre.chip_pool, w.action.amount)
    } else if is_leave || is_kick {
        add_carries(w.post.chip_pool, kick_refund)
    } else {
        [M31::from(0u32); 3]
    });
    out.extend(if w.kind == CanonicalTransitionKind::Addon {
        add_carries(before_seat.pending_addon, w.action.amount)
    } else if is_kick {
        add_carries(w.pre.pot, before_seat.bet)
    } else {
        [M31::from(0u32); 3]
    });
    out.extend(if w.kind == CanonicalTransitionKind::Rebuy {
        add_carries(before_seat.stack, w.action.amount)
    } else if is_leave || is_kick {
        add_carries(before_seat.stack, before_seat.pending_addon)
    } else {
        [M31::from(0u32); 3]
    });
    append_u64_bits(&mut out, w.pre.chip_pool);
    append_u64_bits(&mut out, w.post.chip_pool);
    debug_assert_eq!(out.len(), FULL_BETTING_SEATS_OFFSET);
    // The selected-seat projection above is sufficient for the first betting
    // arithmetic components, but it cannot prove the VM's reset of other
    // players' acted flags. Carry every mutable betting field for every seat
    // here. The root hash is still a separate follow-up component; these
    // columns remove the host's ability to choose an unobserved seat image for
    // the mid-round AIR relation.
    for image in [&w.pre, &w.post] {
        for seat in &image.seats {
            out.extend(status_one_hot(seat.status));
        }
        for seat in &image.seats {
            out.extend(u64_limbs(seat.stack));
        }
        for seat in &image.seats {
            out.extend(u64_limbs(seat.bet));
        }
        for seat in &image.seats {
            out.extend(u64_limbs(seat.total_bet));
        }
        for seat in &image.seats {
            out.extend(u64_limbs(seat.pending_addon));
        }
        for seat in &image.seats {
            out.extend(u32_limbs(seat.time_bank_ms));
        }
    }
    let is_raise = w.kind == CanonicalTransitionKind::Raise;
    for index in 0..MAX_CANONICAL_SEATS {
        out.push(M31::from(u32::from(
            is_raise && usize::from(w.action.seat) == index,
        )));
    }
    for index in 0..MAX_CANONICAL_SEATS {
        out.push(M31::from(u32::from(
            is_raise && w.pre.seats[index].status == CanonicalSeatStatus::Active,
        )));
    }
    debug_assert_eq!(out.len(), NEXT_TURN_ADVICE_OFFSET);
    let is_force_fold = w.kind == CanonicalTransitionKind::ForceFold;
    let uses_turn_advance = is_betting || is_force_fold;
    let no_next_turn =
        uses_turn_advance && w.post.current_turn == crate::texas_canonical::NO_CANONICAL_SEAT;
    out.push(M31::from(u32::from(no_next_turn)));
    for index in 0..MAX_CANONICAL_SEATS {
        out.push(M31::from(u32::from(
            uses_turn_advance && usize::from(w.post.current_turn) == index,
        )));
    }
    for from in 0..MAX_CANONICAL_SEATS {
        for to in 0..MAX_CANONICAL_SEATS {
            out.push(M31::from(u32::from(
                uses_turn_advance
                    && usize::from(w.action.seat) == from
                    && usize::from(w.post.current_turn) == to,
            )));
        }
    }
    debug_assert_eq!(out.len(), FUNDING_SEAT_SELECTOR_OFFSET);
    for index in 0..MAX_CANONICAL_SEATS {
        out.push(M31::from(u32::from(
            funding && usize::from(w.action.seat) == index,
        )));
    }
    debug_assert_eq!(out.len(), ROUND_COLLECT_CARRIES_OFFSET);
    let is_round_advance = w.kind == CanonicalTransitionKind::AdvanceRound;
    out.extend(if is_round_advance {
        round_collect_carries(w.pre.pot, &w.pre.seats)
    } else {
        [M31::from(0u32); 3]
    });
    for carry in if is_round_advance {
        round_collect_carries(w.pre.pot, &w.pre.seats)
    } else {
        [M31::from(0u32); 3]
    } {
        for bit in 0..4 {
            out.push(M31::from(u32::from((carry.0 >> bit) & 1)));
        }
    }
    debug_assert_eq!(out.len(), ROUND_COLLECT_BET_BITS_OFFSET);
    for seat in &w.pre.seats {
        for limb in u64_limbs(if is_round_advance { seat.bet } else { 0 }) {
            out.extend(u16_bits(limb.0 as u16));
        }
    }
    debug_assert_eq!(out.len(), ROUND_COMPLETE_ACTIVE_OFFSET);
    let completed_betting =
        is_betting && w.post.current_turn == crate::texas_canonical::NO_CANONICAL_SEAT;
    for seat in &w.post.seats {
        out.push(M31::from(u32::from(
            completed_betting && seat.status == CanonicalSeatStatus::Active,
        )));
    }
    debug_assert_eq!(out.len(), ROUND_ADVANCE_OPENING_OFFSET);
    let opening = if is_round_advance {
        w.round_advance.clone()
    } else {
        Default::default()
    };
    out.extend([
        M31::from(u32::from(opening.pre_cards_dealt)),
        M31::from(u32::from(opening.post_cards_dealt)),
        M31::from(u32::from(opening.pre_board_len)),
        M31::from(u32::from(opening.post_board_len)),
        M31::from(u32::from(opening.pre_second_board_len)),
        M31::from(u32::from(opening.post_second_board_len)),
        M31::from(u32::from(opening.run_it_twice)),
        M31::from(u32::from(opening.reveal_purpose)),
        M31::from(u32::from(opening.assignment_count)),
    ]);
    for assignment in opening.assignments {
        out.extend([
            M31::from(u32::from(assignment.present)),
            M31::from(u32::from(assignment.encrypted_card_index)),
            M31::from(u32::from(assignment.runout_index)),
            M31::from(u32::from(assignment.board_position)),
            M31::from(u32::from(assignment.pending_mask)),
            M31::from(u32::from(assignment.submitted_mask)),
        ]);
    }
    debug_assert_eq!(out.len(), ROUND_ADVANCE_SCHEDULE_SELECTOR_OFFSET);
    // (preflop, flop, turn) × (single, RIT), matching the fixed table in
    // `CanonicalAir::evaluate`.
    let schedule = match (w.pre.street, opening.run_it_twice) {
        (1, false) => 0,
        (1, true) => 1,
        (2, false) => 2,
        (2, true) => 3,
        (3, false) => 4,
        (3, true) => 5,
        _ => usize::MAX,
    };
    for index in 0..6 {
        out.push(M31::from(u32::from(is_round_advance && index == schedule)));
    }
    debug_assert_eq!(out.len(), ROUND_ADVANCE_CARD_CURSOR_RANGE_OFFSET);
    for cards_dealt in [opening.pre_cards_dealt, opening.post_cards_dealt] {
        let cards_dealt = if is_round_advance { cards_dealt } else { 0 };
        let remaining = if is_round_advance {
            // The range/equality constraints below reject a cursor beyond the
            // deck.  Keep advice generation total so an invalid witness reaches
            // those constraints instead of being rejected by the host.
            52u8.saturating_sub(cards_dealt)
        } else {
            0
        };
        let mut carry = 0u8;
        for bit in 0..6 {
            out.push(M31::from(u32::from((cards_dealt >> bit) & 1)));
        }
        for bit in 0..6 {
            out.push(M31::from(u32::from((remaining >> bit) & 1)));
        }
        for bit in 0..6 {
            let sum = ((cards_dealt >> bit) & 1) + ((remaining >> bit) & 1) + carry;
            carry = sum >> 1;
            out.push(M31::from(u32::from(carry)));
        }
    }
    // Rules and governance are immutable across every table transition.  They
    // were formerly checked only by the native canonical validator; carrying
    // both pre/post encodings here makes that invariant part of the STARK.
    for commitment in [
        w.pre.rules_commitment,
        w.post.rules_commitment,
        w.pre.governance_commitment,
        w.post.governance_commitment,
    ] {
        out.extend(bytes16(&commitment));
    }
    debug_assert_eq!(out.len(), DEADLINE_IMAGE_OFFSET);
    out.extend(u64_limbs(w.pre.deadline_ms));
    out.extend(u64_limbs(w.post.deadline_ms));
    let post_deadline_sum = u64_limbs(w.post.deadline_ms)
        .into_iter()
        .map(|limb| u64::from(limb.0))
        .sum::<u64>();
    out.push(
        if w.kind != CanonicalTransitionKind::StartHand || post_deadline_sum == 0 {
            M31::from(0u32)
        } else {
            M31::from(post_deadline_sum as u32).inverse()
        },
    );
    let is_advance_deadline = w.kind == CanonicalTransitionKind::AdvanceDeadline;
    let advance_deadline_difference = if is_advance_deadline {
        // A checked limb addition in the AIR proves `height >= deadline`.
        // Saturation is only an advice fallback for an invalid witness; it
        // cannot satisfy that addition when the deadline is early.
        w.deadline_height.saturating_sub(w.pre.deadline_ms)
    } else {
        0
    };
    out.extend(u64_limbs(advance_deadline_difference));
    out.extend(if is_advance_deadline {
        add_carries(w.pre.deadline_ms, advance_deadline_difference)
    } else {
        [M31::from(0u32); 3]
    });
    for value in [
        if is_advance_deadline {
            w.deadline_height
        } else {
            0
        },
        if is_advance_deadline {
            w.pre.deadline_ms
        } else {
            0
        },
        advance_deadline_difference,
    ] {
        append_u64_bits(&mut out, value);
    }
    let pre_deadline_sum = u64_limbs(w.pre.deadline_ms)
        .into_iter()
        .map(|limb| u64::from(limb.0))
        .sum::<u64>();
    out.push(if is_advance_deadline && pre_deadline_sum != 0 {
        M31::from(pre_deadline_sum as u32).inverse()
    } else {
        M31::from(0u32)
    });
    out.push(if is_advance_deadline && w.pre.phase as u8 != 0 {
        M31::from(u32::from(w.pre.phase as u8)).inverse()
    } else {
        M31::from(0u32)
    });
    debug_assert_eq!(out.len(), LEAVE_AFTER_HAND_MASK_BITS_OFFSET);
    // Like the acted mask, the leave-after-hand mask is a canonical nine-bit
    // value.  Its bits make SetLeaveAfterHand an exact bit transition in the
    // AIR rather than a host-side u16 operation.
    out.extend(mask_bits(w.pre.leave_after_hand_mask));
    out.extend(mask_bits(w.post.leave_after_hand_mask));
    debug_assert_eq!(out.len(), TRANSITION_SEAT_SELECTOR_OFFSET);
    let requires_seat = w.kind.requires_seat();
    for index in 0..MAX_CANONICAL_SEATS {
        out.push(M31::from(u32::from(
            requires_seat && usize::from(w.action.seat) == index,
        )));
    }
    // These commitments are opaque to the current transition relation, but
    // they are state fields, not host metadata.  Carry them in the trace so
    // ordinary lifecycle, betting, and funding operations cannot silently
    // alter their Borsh endpoint projection.  Crypto/round transitions keep
    // their own dedicated semantics and are intentionally not constrained by
    // this generic preservation gate.
    debug_assert_eq!(out.len(), OPAQUE_COMMITMENTS_OFFSET);
    for commitment in [
        w.pre.board_cards_commitment,
        w.pre.deck_commitment,
        w.pre.reveal_commitment,
        w.pre.reconstruction_commitment,
        w.pre.run_it_twice_commitment,
        w.post.board_cards_commitment,
        w.post.deck_commitment,
        w.post.reveal_commitment,
        w.post.reconstruction_commitment,
        w.post.run_it_twice_commitment,
    ] {
        out.extend(bytes16(&commitment));
    }
    debug_assert_eq!(out.len(), STATE_IMAGE_METADATA_OFFSET);
    for value in [
        u32::from(w.pre.abi_version),
        u32::from(w.pre.button),
        u32::from(w.pre.max_players),
        u32::from(w.post.abi_version),
        u32::from(w.post.button),
        u32::from(w.post.max_players),
    ] {
        out.push(M31::from(value));
    }
    debug_assert_eq!(out.len(), SEAT_COMMITMENTS_OFFSET);
    for state in [&w.pre, &w.post] {
        for seat in &state.seats {
            for commitment in [
                seat.identity_commitment,
                seat.key_commitment,
                seat.hole_cards_commitment,
            ] {
                out.extend(bytes16(&commitment));
            }
        }
    }
    debug_assert_eq!(out.len(), PROOF_COMMITMENT_BITS_OFFSET);
    for limb in bytes16(&w.action.proof_commitment) {
        for bit in u16_bits(if is_crypto_action(w.kind) {
            limb.0 as u16
        } else {
            0
        }) {
            out.push(bit);
        }
    }
    let advance_deadline = w.kind == CanonicalTransitionKind::AdvanceDeadline;
    let timeout = u64::from(CANONICAL_BETTING_TIMEOUT_MS);
    let selected_time_bank = if advance_deadline {
        w.pre
            .seats
            .get(usize::from(w.action.seat))
            .map_or(0, |seat| u64::from(seat.time_bank_ms))
    } else {
        0
    };
    let consume_all = advance_deadline && selected_time_bank <= timeout;
    let slack = if consume_all {
        timeout - selected_time_bank
    } else {
        0
    };
    let excess = if advance_deadline && !consume_all {
        selected_time_bank - timeout
    } else {
        0
    };
    out.push(M31::from(u32::from(consume_all)));
    out.extend(u32_limbs(
        u32::try_from(slack).expect("time-bank slack fits in u32"),
    ));
    out.extend(u32_limbs(
        u32::try_from(excess).expect("time-bank excess fits in u32"),
    ));
    for value in [slack, excess] {
        for limb in u32_limbs(u32::try_from(value).expect("time-bank witness fits in u32")) {
            out.extend(u16_bits(limb.0 as u16));
        }
    }
    out.extend(if advance_deadline {
        [
            add_carries(selected_time_bank, slack)[0],
            add_carries(timeout, excess)[0],
            add_carries(
                w.post
                    .seats
                    .get(usize::from(w.action.seat))
                    .map_or(0, |seat| u64::from(seat.time_bank_ms)),
                w.action.amount,
            )[0],
        ]
    } else {
        [M31::from(0u32); 3]
    });
    out.extend(if advance_deadline {
        add_carries(w.pre.deadline_ms, w.action.amount)
    } else {
        [M31::from(0u32); 3]
    });
    // These gates keep selector * consume-all out of the carry boolean
    // relations, so the whole AIR remains cubic without enlarging the PCS.
    out.push(M31::from(u32::from(consume_all)));
    out.push(M31::from(u32::from(advance_deadline && !consume_all)));
    let is_start = w.kind == CanonicalTransitionKind::StartHand;
    let active_count = w
        .pre
        .seats
        .iter()
        .filter(|seat| {
            matches!(
                seat.status,
                CanonicalSeatStatus::Active
                    | CanonicalSeatStatus::Folded
                    | CanonicalSeatStatus::AllIn
            )
        })
        .count() as u32;
    let start_active_product = active_count * active_count.saturating_sub(1);
    out.push(if is_start {
        M31::from(start_active_product)
    } else {
        M31::from(0u32)
    });
    out.push(if is_start && start_active_product != 0 {
        M31::from(start_active_product).inverse()
    } else {
        M31::from(0u32)
    });
    let mut button = usize::from(w.pre.button);
    for offset in 1..=usize::from(w.pre.max_players) {
        let index = (usize::from(w.pre.button) + offset) % usize::from(w.pre.max_players);
        if !matches!(
            w.pre.seats[index].status,
            CanonicalSeatStatus::Empty | CanonicalSeatStatus::Out
        ) {
            button = index;
            break;
        }
    }
    for index in 0..MAX_CANONICAL_SEATS {
        out.push(M31::from(u32::from(is_start && index == button)));
    }
    for index in 0..MAX_CANONICAL_SEATS {
        out.push(M31::from(u32::from(index == usize::from(w.pre.button))));
    }
    let zero_digest = [0u8; 32];
    for digest in [
        next_pre
            .map(CanonicalStateImage::commitment)
            .unwrap_or(zero_digest),
        next_pre
            .map(|state| state.state_root)
            .unwrap_or(zero_digest),
        next_pre
            .map(|state| state.lifecycle_root)
            .unwrap_or(zero_digest),
        next_pre
            .map(|state| state.overlay_root)
            .unwrap_or(zero_digest),
        next_pre
            .map(|state| state.settlement_commitment)
            .unwrap_or(zero_digest),
        next_pre
            .map(|state| state.custody_commitment)
            .unwrap_or(zero_digest),
    ] {
        out.extend(bytes16(&digest));
    }
    debug_assert_eq!(out.len(), NUM_COLUMNS);
    out
}

fn mix_digest(channel: &mut Poseidon252Channel, digest: &[u8; 32]) {
    channel.mix_u32s(
        &digest
            .chunks_exact(4)
            .map(|x| u32::from_be_bytes(x.try_into().expect("digest word")))
            .collect::<Vec<_>>(),
    );
}

fn mix_scope(channel: &mut Poseidon252Channel, proof: &ArchivedCanonicalTaggedProof) {
    channel.mix_u64(proof.table_id);
    channel.mix_u32s(&[
        proof.first_hand_id,
        proof.last_hand_id,
        proof.first_call_seq,
        proof.last_call_seq,
        u32::from(proof.transition_count),
    ]);
    mix_digest(channel, &proof.batch_digest);
    mix_digest(channel, &proof.pre_state_commitment);
    mix_digest(channel, &proof.post_state_commitment);
    mix_digest(channel, &proof.state_object_key);
    channel.mix_u32s(&[proof.state_opening_epoch]);
    for root in archive_root_scope(proof) {
        mix_digest(channel, &root);
    }
    for image in [&proof.pre_state_image_bytes, &proof.post_state_image_bytes] {
        channel.mix_u64(image.len() as u64);
        channel.mix_u32s(&image.iter().copied().map(u32::from).collect::<Vec<_>>());
    }
}

fn archive_root_scope(proof: &ArchivedCanonicalTaggedProof) -> [[u8; 32]; ROOT_DOMAIN_COUNT * 2] {
    [
        proof.pre_state_root,
        proof.post_state_root,
        proof.pre_lifecycle_root,
        proof.post_lifecycle_root,
        proof.pre_overlay_root,
        proof.post_overlay_root,
        proof.pre_settlement_commitment,
        proof.post_settlement_commitment,
        proof.pre_custody_commitment,
        proof.post_custody_commitment,
    ]
}

fn preprocessed_ids() -> Vec<PreProcessedColumnId> {
    let mut ids = vec![
        "texas.canonical.active.v2",
        "texas.canonical.first.v2",
        "texas.canonical.last.v2",
        "texas.canonical.table.v2.0",
        "texas.canonical.table.v2.1",
        "texas.canonical.table.v2.2",
        "texas.canonical.table.v2.3",
        "texas.canonical.pre-image.v2.0",
        "texas.canonical.pre-image.v2.1",
        "texas.canonical.pre-image.v2.2",
        "texas.canonical.pre-image.v2.3",
        "texas.canonical.pre-image.v2.4",
        "texas.canonical.pre-image.v2.5",
        "texas.canonical.pre-image.v2.6",
        "texas.canonical.pre-image.v2.7",
        "texas.canonical.pre-image.v2.8",
        "texas.canonical.pre-image.v2.9",
        "texas.canonical.pre-image.v2.10",
        "texas.canonical.pre-image.v2.11",
        "texas.canonical.pre-image.v2.12",
        "texas.canonical.pre-image.v2.13",
        "texas.canonical.pre-image.v2.14",
        "texas.canonical.pre-image.v2.15",
        "texas.canonical.post-image.v2.0",
        "texas.canonical.post-image.v2.1",
        "texas.canonical.post-image.v2.2",
        "texas.canonical.post-image.v2.3",
        "texas.canonical.post-image.v2.4",
        "texas.canonical.post-image.v2.5",
        "texas.canonical.post-image.v2.6",
        "texas.canonical.post-image.v2.7",
        "texas.canonical.post-image.v2.8",
        "texas.canonical.post-image.v2.9",
        "texas.canonical.post-image.v2.10",
        "texas.canonical.post-image.v2.11",
        "texas.canonical.post-image.v2.12",
        "texas.canonical.post-image.v2.13",
        "texas.canonical.post-image.v2.14",
        "texas.canonical.post-image.v2.15",
    ]
    .into_iter()
    .map(|id| PreProcessedColumnId { id: id.into() })
    .collect::<Vec<_>>();
    for domain in [
        "state-root",
        "lifecycle-root",
        "overlay-root",
        "settlement-commitment",
        "custody-commitment",
    ] {
        for endpoint in ["pre", "post"] {
            for limb in 0..16 {
                ids.push(PreProcessedColumnId {
                    id: format!("texas.canonical.{endpoint}-{domain}.v2.{limb}").into(),
                });
            }
        }
    }
    for endpoint in ["pre-state-image", "post-state-image"] {
        for limb in 0..STATE_IMAGE_PROJECTION_LIMBS {
            ids.push(PreProcessedColumnId {
                id: format!("texas.canonical.{endpoint}.v3.{limb}").into(),
            });
        }
    }
    debug_assert_eq!(ids.len(), PREPROCESSED_COLUMNS);
    ids
}

fn scope_trace(proof: &ArchivedCanonicalTaggedProof, log_size: u32) -> MethodTrace {
    let mut trace = MethodTrace::new(log_size, PREPROCESSED_COLUMNS);
    let table = u64_limbs(proof.table_id);
    let pre_image = bytes16(&proof.pre_state_commitment);
    let post_image = bytes16(&proof.post_state_commitment);
    let pre_state_projection = state_image_projection(&proof.pre_state_image_bytes)
        .expect("validated canonical pre-state image bytes");
    let post_state_projection = state_image_projection(&proof.post_state_image_bytes)
        .expect("validated canonical post-state image bytes");
    let roots = archive_root_scope(proof);
    for index in 0..usize::from(proof.transition_count) {
        let mut values = vec![M31::from(0u32); PREPROCESSED_COLUMNS];
        values[0] = M31::from(1u32);
        values[1] = M31::from(u32::from(index == 0));
        values[2] = M31::from(u32::from(index + 1 == usize::from(proof.transition_count)));
        values[3..7].copy_from_slice(&table);
        if index == 0 {
            values[7..23].copy_from_slice(&pre_image);
        }
        if index + 1 == usize::from(proof.transition_count) {
            values[23..39].copy_from_slice(&post_image);
        }
        for (root_index, root) in roots.iter().enumerate() {
            let is_pre = root_index % 2 == 0;
            if (is_pre && index == 0)
                || (!is_pre && index + 1 == usize::from(proof.transition_count))
            {
                let offset = ROOT_SCOPE_OFFSET + root_index * 16;
                values[offset..offset + 16].copy_from_slice(&bytes16(root));
            }
        }
        if index == 0 {
            values
                [STATE_IMAGE_SCOPE_OFFSET..STATE_IMAGE_SCOPE_OFFSET + STATE_IMAGE_PROJECTION_LIMBS]
                .copy_from_slice(&pre_state_projection);
        }
        if index + 1 == usize::from(proof.transition_count) {
            let offset = STATE_IMAGE_SCOPE_OFFSET + STATE_IMAGE_PROJECTION_LIMBS;
            values[offset..offset + STATE_IMAGE_PROJECTION_LIMBS]
                .copy_from_slice(&post_state_projection);
        }
        trace.write_row(index, &values).expect("scope width");
    }
    trace
}

fn trace_for_with_state_opening_scope(
    witnesses: &[CanonicalTransitionWitness],
    state_opening: CanonicalStateOpeningScope,
) -> TexasAirResult<(MethodTrace, ArchivedCanonicalTaggedProof)> {
    if witnesses.is_empty() || witnesses.len() > MAX_ROWS {
        return Err(TexasAirError::SpecViolation(
            "canonical batch must contain 1..=1024 transitions".into(),
        ));
    }
    // The direct production admission API remains fail-closed while the AIR
    // coverage is incomplete.  Do not remove this prefilter until every
    // relation below has an AIR-equivalent malicious-witness regression test.
    validate_batch(witnesses).map_err(TexasAirError::SpecViolation)?;
    let log_size = tagged_batch_log_size(witnesses.len())?;
    let mut trace = MethodTrace::new(log_size, NUM_COLUMNS);
    for (index, witness) in witnesses.iter().enumerate() {
        let next_pre = witnesses.get(index + 1).map(|next| &next.pre);
        trace.write_row(index, &row(witness, next_pre))?;
    }
    let first = &witnesses[0];
    let last = &witnesses[witnesses.len() - 1];
    let pre_state_image_bytes = borsh::to_vec(&first.pre)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
    let post_state_image_bytes = borsh::to_vec(&last.post)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
    if pre_state_image_bytes.len() != CANONICAL_STATE_IMAGE_BORSH_BYTES
        || post_state_image_bytes.len() != CANONICAL_STATE_IMAGE_BORSH_BYTES
    {
        return Err(TexasAirError::SpecViolation(
            "canonical state-image Borsh ABI width changed".into(),
        ));
    }
    Ok((
        trace,
        ArchivedCanonicalTaggedProof {
            log_size,
            num_columns: NUM_COLUMNS as u32,
            table_id: first.pre.table_id,
            first_hand_id: first.pre.hand_id,
            last_hand_id: last.post.hand_id,
            first_call_seq: first.pre.call_seq,
            last_call_seq: last.post.call_seq,
            transition_count: witnesses.len() as u16,
            batch_digest: digest_batch(witnesses),
            pre_state_commitment: first.pre.commitment(),
            post_state_commitment: last.post.commitment(),
            pre_state_root: first.pre.state_root,
            post_state_root: last.post.state_root,
            pre_lifecycle_root: first.pre.lifecycle_root,
            post_lifecycle_root: last.post.lifecycle_root,
            pre_overlay_root: first.pre.overlay_root,
            post_overlay_root: last.post.overlay_root,
            pre_settlement_commitment: first.pre.settlement_commitment,
            post_settlement_commitment: last.post.settlement_commitment,
            pre_custody_commitment: first.pre.custody_commitment,
            post_custody_commitment: last.post.custody_commitment,
            pre_state_image_bytes,
            post_state_image_bytes,
            state_object_key: state_opening.state_object_key,
            state_opening_epoch: state_opening.state_opening_epoch,
            stark_proof_bytes: Vec::new(),
        },
    ))
}

fn trace_for(
    witnesses: &[CanonicalTransitionWitness],
) -> TexasAirResult<(MethodTrace, ArchivedCanonicalTaggedProof)> {
    trace_for_with_state_opening_scope(witnesses, CanonicalStateOpeningScope::legacy())
}

fn add_limb_eq<E: EvalAtRow>(eval: &mut E, gate: &E::F, left: &[E::F], right: &[E::F]) {
    for (a, b) in left.iter().zip(right.iter()) {
        eval.add_constraint(gate.clone() * (a.clone() - b.clone()));
    }
}

fn limb4_add_constraints<E: EvalAtRow>(
    eval: &mut E,
    gate: &E::F,
    left: &[E::F; 4],
    right: &[E::F; 4],
    result: &[E::F; 4],
    carries: &[E::F; 3],
) {
    let one: E::F = M31::from(1u32).into();
    let zero: E::F = M31::from(0u32).into();
    let base: E::F = M31::from(65536u32).into();
    let carry_in = [
        zero.clone(),
        carries[0].clone(),
        carries[1].clone(),
        carries[2].clone(),
    ];
    let carry_out = [
        carries[0].clone(),
        carries[1].clone(),
        carries[2].clone(),
        zero,
    ];
    for index in 0..4 {
        eval.add_constraint(
            gate.clone()
                * (left[index].clone() + right[index].clone() + carry_in[index].clone()
                    - result[index].clone()
                    - base.clone() * carry_out[index].clone()),
        );
    }
    for carry in carries {
        eval.add_constraint(gate.clone() * carry.clone() * (carry.clone() - one.clone()));
    }
}

fn limb2_add_constraints<E: EvalAtRow>(
    eval: &mut E,
    gate: &E::F,
    left: &[E::F; 2],
    right: &[E::F; 2],
    result: &[E::F; 2],
    carry: &E::F,
) {
    let base: E::F = M31::from(65536u32).into();
    eval.add_constraint(
        gate.clone()
            * (left[0].clone() + right[0].clone()
                - result[0].clone()
                - base.clone() * carry.clone()),
    );
    eval.add_constraint(gate.clone() * (left[1].clone() + carry.clone() - result[1].clone()));
    eval.add_constraint(gate.clone() * carry.clone() * (carry.clone() - M31::from(1u32).into()));
}

fn trace_limbs<E: EvalAtRow>(eval: &mut E) -> [E::F; 4] {
    std::array::from_fn(|_| eval.next_trace_mask())
}

fn trace_bits16<E: EvalAtRow>(eval: &mut E) -> [E::F; 16] {
    std::array::from_fn(|_| eval.next_trace_mask())
}

fn range16_constraints<E: EvalAtRow>(eval: &mut E, gate: &E::F, value: &E::F, bits: &[E::F; 16]) {
    let one: E::F = M31::from(1u32).into();
    let two: E::F = M31::from(2u32).into();
    let mut reconstructed = bits[0].clone();
    let mut power = two.clone();
    for bit in &bits[1..] {
        reconstructed = reconstructed + bit.clone() * power.clone();
        power = power * two.clone();
    }
    eval.add_constraint(gate.clone() * (value.clone() - reconstructed));
    for bit in bits {
        eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
    }
}

impl FrameworkEval for CanonicalAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        // Although selector-gated relations such as `active * bit * (bit - 1)`
        // are cubic in the committed columns, their quotients have degree
        // below 2 * |H|. Stwo's bound therefore remains one above the trace
        // size, matching the other cubic AIRs in this crate.
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let active = eval.next_trace_mask();
        let one: E::F = M31::from(1u32).into();
        let two: E::F = M31::from(2u32).into();
        let scoped_active = eval.get_preprocessed_column(preprocessed_ids()[0].clone());
        eval.add_constraint(active.clone() - scoped_active);
        eval.add_constraint(active.clone() * (active.clone() - one.clone()));
        let kinds: Vec<_> = (0..KIND_COUNT).map(|_| eval.next_trace_mask()).collect();
        let mut kind_sum: E::F = M31::from(0u32).into();
        for kind in &kinds {
            eval.add_constraint(active.clone() * (kind.clone() * (kind.clone() - one.clone())));
            kind_sum += kind.clone();
        }
        eval.add_constraint(active.clone() * (kind_sum.clone() - one.clone()));
        let table: Vec<_> = (0..4).map(|_| eval.next_trace_mask()).collect();
        let pre_hand: Vec<_> = (0..2).map(|_| eval.next_trace_mask()).collect();
        let post_hand: Vec<_> = (0..2).map(|_| eval.next_trace_mask()).collect();
        let pre_seq: Vec<_> = (0..2).map(|_| eval.next_trace_mask()).collect();
        let post_seq: Vec<_> = (0..2).map(|_| eval.next_trace_mask()).collect();
        let pre_image: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let post_image: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        // Every root domain is a first/last public boundary and must remain
        // contiguous inside the tagged batch.  The state-transition relation
        // does not yet recompute Blake2b here, but a receipt can no longer
        // splice a proof to unrelated state/lifecycle/overlay/economic roots.
        let pre_state_root: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let post_state_root: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let pre_lifecycle_root: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let post_lifecycle_root: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let pre_overlay_root: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let post_overlay_root: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let pre_settlement_commitment: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let post_settlement_commitment: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let pre_custody_commitment: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let post_custody_commitment: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let actor: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let proof_commitment: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let seat = eval.next_trace_mask();
        let amount = trace_limbs(&mut eval);
        let auxiliary: Vec<_> = (0..4).map(|_| eval.next_trace_mask()).collect();
        let flag = eval.next_trace_mask();
        let deadline_height = trace_limbs(&mut eval);
        let seq_carry = eval.next_trace_mask();
        let pre_phase = eval.next_trace_mask();
        let post_phase = eval.next_trace_mask();
        let pre_subtag = eval.next_trace_mask();
        let post_subtag = eval.next_trace_mask();
        let pre_street = eval.next_trace_mask();
        let post_street = eval.next_trace_mask();
        let pre_turn = eval.next_trace_mask();
        let post_turn = eval.next_trace_mask();
        let pre_current = trace_limbs(&mut eval);
        let post_current = trace_limbs(&mut eval);
        let pre_min = trace_limbs(&mut eval);
        let post_min = trace_limbs(&mut eval);
        let pre_pot = trace_limbs(&mut eval);
        let post_pot = trace_limbs(&mut eval);
        let pre_acted_mask = eval.next_trace_mask();
        let post_acted_mask = eval.next_trace_mask();
        let pre_leave_mask = eval.next_trace_mask();
        let post_leave_mask = eval.next_trace_mask();
        let pre_status = eval.next_trace_mask();
        let pre_seat_acted = eval.next_trace_mask();
        let pre_stack = trace_limbs(&mut eval);
        let pre_bet = trace_limbs(&mut eval);
        let pre_total = trace_limbs(&mut eval);
        let pre_pending = trace_limbs(&mut eval);
        let pre_time_bank = [eval.next_trace_mask(), eval.next_trace_mask()];
        let post_status = eval.next_trace_mask();
        let post_seat_acted = eval.next_trace_mask();
        let post_stack = trace_limbs(&mut eval);
        let post_bet = trace_limbs(&mut eval);
        let post_total = trace_limbs(&mut eval);
        let post_pending = trace_limbs(&mut eval);
        let post_time_bank = [eval.next_trace_mask(), eval.next_trace_mask()];
        let turn_delta_inv = eval.next_trace_mask();
        let amount_inv = eval.next_trace_mask();
        let stack_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let bet_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let total_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let pot_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let stack_range_bits: [[E::F; 16]; 4] = std::array::from_fn(|_| trace_bits16(&mut eval));
        let post_stack_range_bits: [[E::F; 16]; 4] =
            std::array::from_fn(|_| trace_bits16(&mut eval));
        let bet_range_bits: [[E::F; 16]; 4] = std::array::from_fn(|_| trace_bits16(&mut eval));
        let post_bet_range_bits: [[E::F; 16]; 4] = std::array::from_fn(|_| trace_bits16(&mut eval));
        let total_range_bits: [[E::F; 16]; 4] = std::array::from_fn(|_| trace_bits16(&mut eval));
        let post_total_range_bits: [[E::F; 16]; 4] =
            std::array::from_fn(|_| trace_bits16(&mut eval));
        let pot_range_bits: [[E::F; 16]; 4] = std::array::from_fn(|_| trace_bits16(&mut eval));
        let post_pot_range_bits: [[E::F; 16]; 4] = std::array::from_fn(|_| trace_bits16(&mut eval));
        let amount_range_bits: [[E::F; 16]; 4] = std::array::from_fn(|_| trace_bits16(&mut eval));
        let call_owed = trace_limbs(&mut eval);
        let call_difference = trace_limbs(&mut eval);
        let call_all_in = eval.next_trace_mask();
        let call_difference_inv = eval.next_trace_mask();
        let call_owed_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let call_excess_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let call_shortfall_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let call_owed_bits: [[E::F; 16]; 4] = std::array::from_fn(|_| trace_bits16(&mut eval));
        let call_difference_bits: [[E::F; 16]; 4] =
            std::array::from_fn(|_| trace_bits16(&mut eval));
        let raise_needed = trace_limbs(&mut eval);
        let raise_delta = trace_limbs(&mut eval);
        let raise_stack_difference = trace_limbs(&mut eval);
        let raise_min_difference = trace_limbs(&mut eval);
        let raise_all_in = eval.next_trace_mask();
        let raise_meets_min = eval.next_trace_mask();
        let raise_needed_inv = eval.next_trace_mask();
        let raise_delta_inv = eval.next_trace_mask();
        let raise_stack_difference_inv = eval.next_trace_mask();
        let raise_needed_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let raise_delta_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let raise_stack_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let raise_total_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let raise_pot_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let raise_needed_bits: [[E::F; 16]; 4] = std::array::from_fn(|_| trace_bits16(&mut eval));
        let raise_delta_bits: [[E::F; 16]; 4] = std::array::from_fn(|_| trace_bits16(&mut eval));
        let raise_stack_difference_bits: [[E::F; 16]; 4] =
            std::array::from_fn(|_| trace_bits16(&mut eval));
        let raise_min_difference_bits: [[E::F; 16]; 4] =
            std::array::from_fn(|_| trace_bits16(&mut eval));
        let post_all_in = eval.next_trace_mask();
        let chip_action_post_stack_sum = eval.next_trace_mask();
        let chip_action_post_stack_inv = eval.next_trace_mask();
        let betting_pre_stack_sum = eval.next_trace_mask();
        let betting_pre_stack_inv = eval.next_trace_mask();
        let acted_seat_selectors: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let pre_acted_bits: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let post_acted_bits: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let acted_deltas: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let pre_chip_pool = trace_limbs(&mut eval);
        let post_chip_pool = trace_limbs(&mut eval);
        let funding_chip_pool_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let funding_addon_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let funding_rebuy_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let pre_chip_pool_bits: [[E::F; 16]; 4] = std::array::from_fn(|_| trace_bits16(&mut eval));
        let post_chip_pool_bits: [[E::F; 16]; 4] = std::array::from_fn(|_| trace_bits16(&mut eval));
        let full_pre_status: [[E::F; SEAT_STATUS_COUNT]; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
        let full_pre_stack: [[E::F; 4]; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| trace_limbs(&mut eval));
        let full_pre_bet: [[E::F; 4]; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| trace_limbs(&mut eval));
        let full_pre_total: [[E::F; 4]; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| trace_limbs(&mut eval));
        let full_pre_pending: [[E::F; 4]; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| trace_limbs(&mut eval));
        let full_pre_time_bank: [[E::F; 2]; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| [eval.next_trace_mask(), eval.next_trace_mask()]);
        let full_post_status: [[E::F; SEAT_STATUS_COUNT]; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
        let full_post_stack: [[E::F; 4]; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| trace_limbs(&mut eval));
        let full_post_bet: [[E::F; 4]; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| trace_limbs(&mut eval));
        let full_post_total: [[E::F; 4]; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| trace_limbs(&mut eval));
        let full_post_pending: [[E::F; 4]; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| trace_limbs(&mut eval));
        let full_post_time_bank: [[E::F; 2]; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| [eval.next_trace_mask(), eval.next_trace_mask()]);
        let raise_actor: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let mut selected_transition_pre_time: [E::F; 2] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_transition_post_time: [E::F; 2] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let raise_active: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let no_next_turn = eval.next_trace_mask();
        let next_turn_selectors: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let next_turn_pairs: [[E::F; MAX_CANONICAL_SEATS]; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
        let funding_seat_selectors: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let round_collect_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let round_collect_carry_bits: [[E::F; 4]; 3] =
            std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
        let round_collect_bet_bits: [[[E::F; 16]; 4]; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| std::array::from_fn(|_| trace_bits16(&mut eval)));
        let round_complete_active: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let round_pre_cards_dealt = eval.next_trace_mask();
        let round_post_cards_dealt = eval.next_trace_mask();
        let round_pre_board_len = eval.next_trace_mask();
        let round_post_board_len = eval.next_trace_mask();
        let round_pre_second_board_len = eval.next_trace_mask();
        let round_post_second_board_len = eval.next_trace_mask();
        let round_run_it_twice = eval.next_trace_mask();
        let round_reveal_purpose = eval.next_trace_mask();
        let round_assignment_count = eval.next_trace_mask();
        let round_assignments: [[E::F; 6]; MAX_CANONICAL_BOARD_REVEAL_ASSIGNMENTS] =
            std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
        let round_schedule_selectors: [E::F; 6] = std::array::from_fn(|_| eval.next_trace_mask());
        // Trace layout is cursor-major: `[cursor_bits, complement_bits,
        // carry_bits]` for pre, then the same three blocks for post.
        let round_card_cursor_range: [[[E::F; 6]; 3]; 2] = std::array::from_fn(|_| {
            std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()))
        });
        let pre_rules_commitment: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let post_rules_commitment: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let pre_governance_commitment: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let post_governance_commitment: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let pre_deadline_image = trace_limbs(&mut eval);
        let post_deadline_image = trace_limbs(&mut eval);
        let post_deadline_inv = eval.next_trace_mask();
        let advance_deadline_difference = trace_limbs(&mut eval);
        let advance_deadline_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let advance_deadline_height_bits: [[E::F; 16]; 4] =
            std::array::from_fn(|_| trace_bits16(&mut eval));
        let advance_deadline_pre_bits: [[E::F; 16]; 4] =
            std::array::from_fn(|_| trace_bits16(&mut eval));
        let advance_deadline_difference_bits: [[E::F; 16]; 4] =
            std::array::from_fn(|_| trace_bits16(&mut eval));
        let advance_deadline_pre_inv = eval.next_trace_mask();
        let advance_deadline_phase_inv = eval.next_trace_mask();
        let pre_leave_mask_bits: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let post_leave_mask_bits: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let transition_seat_selectors: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let pre_opaque_commitments: [[E::F; 16]; OPAQUE_COMMITMENT_COUNT] =
            std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
        let post_opaque_commitments: [[E::F; 16]; OPAQUE_COMMITMENT_COUNT] =
            std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()));
        let pre_state_metadata: [E::F; STATE_IMAGE_METADATA_LIMBS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let post_state_metadata: [E::F; STATE_IMAGE_METADATA_LIMBS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let pre_seat_commitments: [[[E::F; 16]; SEAT_COMMITMENT_FIELD_COUNT]; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| {
                std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()))
            });
        let post_seat_commitments: [[[E::F; 16]; SEAT_COMMITMENT_FIELD_COUNT];
            MAX_CANONICAL_SEATS] = std::array::from_fn(|_| {
            std::array::from_fn(|_| std::array::from_fn(|_| eval.next_trace_mask()))
        });
        let proof_commitment_bits: [[E::F; 16]; 16] =
            std::array::from_fn(|_| trace_bits16(&mut eval));
        let advance_deadline_time_bank_all = eval.next_trace_mask();
        let advance_deadline_time_bank_slack = [eval.next_trace_mask(), eval.next_trace_mask()];
        let advance_deadline_time_bank_excess = [eval.next_trace_mask(), eval.next_trace_mask()];
        let advance_deadline_time_bank_range_bits: [[[E::F; 16]; 2]; 2] =
            std::array::from_fn(|_| std::array::from_fn(|_| trace_bits16(&mut eval)));
        let advance_deadline_time_bank_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let advance_deadline_extension_carries = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let consume_all_gate = eval.next_trace_mask();
        let partial_gate = eval.next_trace_mask();
        let start_active_product = eval.next_trace_mask();
        let start_active_count_inv = eval.next_trace_mask();
        let start_button_selectors: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let start_pre_button_selectors: [E::F; MAX_CANONICAL_SEATS] =
            std::array::from_fn(|_| eval.next_trace_mask());
        let next_pre_image: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let next_pre_state_root: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let next_pre_lifecycle_root: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let next_pre_overlay_root: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let next_pre_settlement_commitment: Vec<_> =
            (0..16).map(|_| eval.next_trace_mask()).collect();
        let next_pre_custody_commitment: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        eval.add_constraint(active.clone() * flag.clone() * (flag.clone() - one.clone()));
        eval.add_constraint(seq_carry.clone() * (seq_carry.clone() - one.clone()));
        for (pre, post) in [
            (&pre_rules_commitment, &post_rules_commitment),
            (&pre_governance_commitment, &post_governance_commitment),
        ] {
            for (left, right) in pre.iter().zip(post.iter()) {
                eval.add_constraint(active.clone() * (right.clone() - left.clone()));
            }
        }
        for value in [&pre_seat_acted, &post_seat_acted] {
            eval.add_constraint(active.clone() * value.clone() * (value.clone() - one.clone()));
        }
        for index in 0..4 {
            range16_constraints(
                &mut eval,
                &active,
                &pre_stack[index],
                &stack_range_bits[index],
            );
            range16_constraints(
                &mut eval,
                &active,
                &post_stack[index],
                &post_stack_range_bits[index],
            );
            range16_constraints(&mut eval, &active, &pre_bet[index], &bet_range_bits[index]);
            range16_constraints(
                &mut eval,
                &active,
                &post_bet[index],
                &post_bet_range_bits[index],
            );
            range16_constraints(
                &mut eval,
                &active,
                &pre_total[index],
                &total_range_bits[index],
            );
            range16_constraints(
                &mut eval,
                &active,
                &post_total[index],
                &post_total_range_bits[index],
            );
            range16_constraints(&mut eval, &active, &pre_pot[index], &pot_range_bits[index]);
            range16_constraints(
                &mut eval,
                &active,
                &post_pot[index],
                &post_pot_range_bits[index],
            );
            range16_constraints(
                &mut eval,
                &active,
                &amount[index],
                &amount_range_bits[index],
            );
        }
        // The selected-seat projection is verifier-owned by the action seat and is not allowed
        // to drift from the canonical phase/turn image.
        let is_fold_with_proof = kinds[CanonicalTransitionKind::FoldWithProof as usize].clone();
        let is_betting = kinds[CanonicalTransitionKind::Fold as usize].clone()
            + kinds[CanonicalTransitionKind::Check as usize].clone()
            + kinds[CanonicalTransitionKind::Call as usize].clone()
            + kinds[CanonicalTransitionKind::Raise as usize].clone()
            + kinds[CanonicalTransitionKind::Bet as usize].clone()
            + is_fold_with_proof.clone();
        eval.add_constraint(is_betting.clone() * (pre_phase.clone() - M31::from(4u32).into()));
        eval.add_constraint(is_betting.clone() * (pre_turn.clone() - seat.clone()));
        eval.add_constraint(is_betting.clone() * (pre_status.clone() - M31::from(2u32).into()));
        eval.add_constraint(is_betting.clone() * (post_seat_acted.clone() - one.clone()));
        eval.add_constraint(
            is_betting.clone()
                * ((post_turn.clone() - seat.clone()) * turn_delta_inv.clone() - one.clone()),
        );
        eval.add_constraint(is_betting.clone() * (post_phase.clone() - pre_phase.clone()));
        eval.add_constraint(is_betting.clone() * (post_subtag.clone() - pre_subtag.clone()));
        eval.add_constraint(is_betting.clone() * (post_street.clone() - pre_street.clone()));
        eval.add_constraint(
            is_betting.clone() * (post_leave_mask.clone() - pre_leave_mask.clone()),
        );
        let is_fold = kinds[CanonicalTransitionKind::Fold as usize].clone();
        let is_fold_like = is_fold.clone() + is_fold_with_proof.clone();
        eval.add_constraint(is_fold_like.clone() * (post_status.clone() - M31::from(3u32).into()));
        let is_check = kinds[CanonicalTransitionKind::Check as usize].clone();
        let is_call = kinds[CanonicalTransitionKind::Call as usize].clone();
        let is_raise = kinds[CanonicalTransitionKind::Raise as usize].clone();
        let is_bet = kinds[CanonicalTransitionKind::Bet as usize].clone();
        let is_addon = kinds[CanonicalTransitionKind::Addon as usize].clone();
        let is_rebuy = kinds[CanonicalTransitionKind::Rebuy as usize].clone();
        let is_funding = is_addon.clone() + is_rebuy.clone();
        let is_advance_deadline = kinds[CanonicalTransitionKind::AdvanceDeadline as usize].clone();
        let is_round_advance = kinds[CanonicalTransitionKind::AdvanceRound as usize].clone();
        let is_create = kinds[CanonicalTransitionKind::CreateTable as usize].clone();
        let is_start = kinds[CanonicalTransitionKind::StartHand as usize].clone();
        let is_join = kinds[CanonicalTransitionKind::JoinTable as usize].clone();
        let is_leave = kinds[CanonicalTransitionKind::LeaveTable as usize].clone();
        let is_force_fold = kinds[CanonicalTransitionKind::ForceFold as usize].clone();
        let is_kick = kinds[CanonicalTransitionKind::KickPlayer as usize].clone();
        let is_force_or_kick = is_force_fold.clone() + is_kick.clone();
        let is_submit_shuffle = kinds[CanonicalTransitionKind::SubmitShuffle as usize].clone();
        let is_submit_reveal = kinds[CanonicalTransitionKind::SubmitReveal as usize].clone();
        let is_submit_reconstruct =
            kinds[CanonicalTransitionKind::SubmitReconstruct as usize].clone();
        let is_set_leave = kinds[CanonicalTransitionKind::SetLeaveAfterHand as usize].clone();
        let is_crypto = is_submit_shuffle.clone()
            + is_submit_reveal.clone()
            + is_submit_reconstruct.clone()
            + is_fold_with_proof.clone();
        // A crypto tag carries a real, fixed-width proof commitment rather
        // than a host boolean.  Every limb is range-bound before the inverse
        // proves that at least one of the 32 commitment bytes is non-zero.
        // This is only an anti-null relation; verification of the bound
        // Ristretto proof payload is added by the dedicated crypto AIR.
        let mut proof_commitment_sum: E::F = M31::from(0u32).into();
        for limb in 0..16 {
            range16_constraints(
                &mut eval,
                &is_crypto,
                &proof_commitment[limb],
                &proof_commitment_bits[limb],
            );
            for bit in &proof_commitment_bits[limb] {
                eval.add_constraint((active.clone() - is_crypto.clone()) * bit.clone());
            }
            proof_commitment_sum += proof_commitment[limb].clone();
        }
        eval.add_constraint(
            is_crypto.clone() * (proof_commitment_sum * amount_inv.clone() - one.clone()),
        );
        // These direct canonical tags do not overload the betting/funding
        // action fields.  Keeping them zero removes an otherwise free advice
        // surface until each protocol's fixed witness ABI is introduced.
        for value in amount.iter().chain(auxiliary.iter()) {
            eval.add_constraint(is_crypto.clone() * value.clone());
        }
        eval.add_constraint(is_crypto.clone() * flag.clone());
        eval.add_constraint(
            is_submit_shuffle.clone() * (pre_phase.clone() - M31::from(1u32).into()),
        );
        eval.add_constraint(
            is_submit_reveal.clone() * (pre_phase.clone() - M31::from(2u32).into()),
        );
        eval.add_constraint(
            is_submit_reconstruct.clone() * (pre_phase.clone() - M31::from(3u32).into()),
        );
        let is_protocol_submit =
            is_submit_shuffle.clone() + is_submit_reveal.clone() + is_submit_reconstruct.clone();
        eval.add_constraint(
            is_protocol_submit.clone()
                * (pre_status.clone() * turn_delta_inv.clone() - one.clone()),
        );
        // Protocol submissions carry proof payloads but must not become a
        // side channel for economic, seat, or betting-state mutation.
        for (pre, post) in [
            (&pre_street, &post_street),
            (&pre_turn, &post_turn),
            (&pre_acted_mask, &post_acted_mask),
            (&pre_leave_mask, &post_leave_mask),
        ] {
            eval.add_constraint(is_protocol_submit.clone() * (post.clone() - pre.clone()));
        }
        for (pre, post) in [
            (&pre_current, &post_current),
            (&pre_min, &post_min),
            (&pre_pot, &post_pot),
            (&pre_chip_pool, &post_chip_pool),
        ] {
            for (left, right) in pre.iter().zip(post.iter()) {
                eval.add_constraint(is_protocol_submit.clone() * (right.clone() - left.clone()));
            }
        }
        // Each family has one protocol-owned commitment surface.  Reconstruct
        // completion may additionally rebuild the deck, matching the VM.
        for commitment in [0usize, 2, 3, 4] {
            for limb in 0..16 {
                eval.add_constraint(
                    is_submit_shuffle.clone()
                        * (post_opaque_commitments[commitment][limb].clone()
                            - pre_opaque_commitments[commitment][limb].clone()),
                );
            }
        }
        for commitment in [0usize, 1, 3, 4] {
            for limb in 0..16 {
                eval.add_constraint(
                    is_submit_reveal.clone()
                        * (post_opaque_commitments[commitment][limb].clone()
                            - pre_opaque_commitments[commitment][limb].clone()),
                );
            }
        }
        for commitment in [0usize, 2, 4] {
            for limb in 0..16 {
                eval.add_constraint(
                    is_submit_reconstruct.clone()
                        * (post_opaque_commitments[commitment][limb].clone()
                            - pre_opaque_commitments[commitment][limb].clone()),
                );
            }
        }
        for limb in 0..16 {
            eval.add_constraint(
                is_protocol_submit.clone()
                    * (post_custody_commitment[limb].clone()
                        - pre_custody_commitment[limb].clone()),
            );
        }
        // `CanonicalStateImage` binds these commitments at fixed Borsh
        // offsets.  For the non-crypto transitions below, their VM semantics
        // are strict preservation.  This removes a remaining host-controlled
        // state mutation path without pretending to verify the cryptographic
        // payloads of shuffle/reveal/reconstruct/round transitions yet.
        let opaque_must_be_immutable = (is_betting.clone() - is_fold_with_proof.clone())
            + is_funding.clone()
            + is_join.clone()
            + is_leave.clone()
            + is_force_or_kick.clone()
            + is_set_leave.clone();
        for commitment in 0..OPAQUE_COMMITMENT_COUNT {
            for limb in 0..16 {
                eval.add_constraint(
                    opaque_must_be_immutable.clone()
                        * (post_opaque_commitments[commitment][limb].clone()
                            - pre_opaque_commitments[commitment][limb].clone()),
                );
            }
        }
        // `fold_with_proof` removes one ElGamal layer and may therefore only
        // replace the deck commitment.  Board/reveal/reconstruct/run-it-twice
        // state belongs to other protocol phases and must remain fixed.
        for commitment in [0usize, 2, 3, 4] {
            for limb in 0..16 {
                eval.add_constraint(
                    is_fold_with_proof.clone()
                        * (post_opaque_commitments[commitment][limb].clone()
                            - pre_opaque_commitments[commitment][limb].clone()),
                );
            }
        }
        let canonical_abi_version: E::F = M31::from(u32::from(CANONICAL_ABI_VERSION)).into();
        for metadata in [&pre_state_metadata, &post_state_metadata] {
            eval.add_constraint(
                active.clone() * (metadata[0].clone() - canonical_abi_version.clone()),
            );
        }
        // Table capacity is a genesis parameter.  The button advances only at
        // `StartHand`; all other tags must preserve the materialized header.
        eval.add_constraint(
            active.clone() * (post_state_metadata[2].clone() - pre_state_metadata[2].clone()),
        );
        eval.add_constraint(
            (active.clone() - is_start.clone())
                * (post_state_metadata[1].clone() - pre_state_metadata[1].clone()),
        );
        let seat_commitments_immutable = is_create.clone()
            + is_betting.clone()
            + is_funding.clone()
            + is_set_leave.clone()
            + is_round_advance.clone();
        let selected_seat_commitment_transition =
            is_join.clone() + is_leave.clone() + is_force_or_kick.clone();
        for seat_index in 0..MAX_CANONICAL_SEATS {
            for commitment in 0..SEAT_COMMITMENT_FIELD_COUNT {
                for limb in 0..16 {
                    let pre = pre_seat_commitments[seat_index][commitment][limb].clone();
                    let post = post_seat_commitments[seat_index][commitment][limb].clone();
                    eval.add_constraint(
                        seat_commitments_immutable.clone() * (post.clone() - pre.clone()),
                    );
                    eval.add_constraint(
                        selected_seat_commitment_transition.clone()
                            * (one.clone() - transition_seat_selectors[seat_index].clone())
                            * (post - pre),
                    );
                }
            }
            for limb in 0..16 {
                let pre_identity = pre_seat_commitments[seat_index][0][limb].clone();
                let post_identity = post_seat_commitments[seat_index][0][limb].clone();
                eval.add_constraint(
                    is_join.clone()
                        * transition_seat_selectors[seat_index].clone()
                        * post_seat_commitments[seat_index][2][limb].clone(),
                );
                for commitment in 0..SEAT_COMMITMENT_FIELD_COUNT {
                    eval.add_constraint(
                        is_leave.clone()
                            * transition_seat_selectors[seat_index].clone()
                            * post_seat_commitments[seat_index][commitment][limb].clone(),
                    );
                }
                for commitment in 0..SEAT_COMMITMENT_FIELD_COUNT {
                    eval.add_constraint(
                        is_force_fold.clone()
                            * transition_seat_selectors[seat_index].clone()
                            * (post_seat_commitments[seat_index][commitment][limb].clone()
                                - pre_seat_commitments[seat_index][commitment][limb].clone()),
                    );
                }
                eval.add_constraint(
                    is_kick.clone()
                        * transition_seat_selectors[seat_index].clone()
                        * (post_identity - pre_identity),
                );
                for commitment in 1..SEAT_COMMITMENT_FIELD_COUNT {
                    eval.add_constraint(
                        is_kick.clone()
                            * transition_seat_selectors[seat_index].clone()
                            * post_seat_commitments[seat_index][commitment][limb].clone(),
                    );
                }
            }
        }
        // These actions may update exactly one seat image.  The full opening
        // still makes every other seat immutable in the AIR; this is stronger
        // than relying on `only_allowed_changes` during witness construction.
        let is_selected_lifecycle = is_join.clone()
            + is_leave.clone()
            + is_force_or_kick.clone()
            + is_fold_with_proof.clone();
        let requires_transition_seat = is_betting.clone()
            + is_funding.clone()
            + is_join.clone()
            + is_leave.clone()
            + is_force_fold.clone()
            + is_kick.clone()
            + is_submit_shuffle.clone()
            + is_submit_reveal.clone()
            + is_submit_reconstruct.clone()
            + is_set_leave.clone()
            + is_advance_deadline.clone();
        // Lifecycle actions that do not depend on an opaque crypto commitment
        // are constrained directly from the fixed canonical image.  The
        // transition-seat selector below binds `pre_status`/`post_status` to
        // the full nine-seat opening, rather than trusting a host projection.
        let no_seat: E::F = M31::from(15u32).into();
        eval.add_constraint(is_create.clone() * pre_phase.clone());
        eval.add_constraint(is_create.clone() * post_phase.clone());
        eval.add_constraint(is_create.clone() * (pre_turn.clone() - no_seat.clone()));
        eval.add_constraint(is_create.clone() * (post_turn.clone() - no_seat.clone()));
        eval.add_constraint(is_force_fold.clone() * (pre_phase.clone() - M31::from(4u32).into()));
        eval.add_constraint(is_force_fold.clone() * (pre_turn.clone() - seat.clone()));
        for value in amount.iter().chain(auxiliary.iter()) {
            eval.add_constraint(is_force_fold.clone() * value.clone());
        }
        eval.add_constraint(is_force_fold.clone() * flag.clone());
        eval.add_constraint(is_join.clone() * pre_phase.clone());
        eval.add_constraint(is_join.clone() * post_phase.clone());
        eval.add_constraint(is_join.clone() * pre_status.clone());
        eval.add_constraint(is_join.clone() * (post_status.clone() - M31::from(2u32).into()));
        let mut join_amount_sum: E::F = M31::from(0u32).into();
        for limb in &amount {
            join_amount_sum += limb.clone();
        }
        eval.add_constraint(is_join.clone() * (join_amount_sum * amount_inv.clone() - one.clone()));
        eval.add_constraint(is_leave.clone() * pre_phase.clone());
        eval.add_constraint(is_leave.clone() * post_phase.clone());
        eval.add_constraint(
            is_leave.clone()
                * (pre_status.clone() - M31::from(1u32).into())
                * (pre_status.clone() - M31::from(5u32).into()),
        );
        eval.add_constraint(
            is_leave.clone() * post_status.clone() * (post_status.clone() - M31::from(5u32).into()),
        );
        for index in 0..MAX_CANONICAL_SEATS {
            eval.add_constraint(
                is_join.clone() * (post_acted_bits[index].clone() - pre_acted_bits[index].clone()),
            );
            eval.add_constraint(
                is_join.clone()
                    * (post_leave_mask_bits[index].clone() - pre_leave_mask_bits[index].clone()),
            );
            eval.add_constraint(
                is_leave.clone() * (post_acted_bits[index].clone() - pre_acted_bits[index].clone()),
            );
            eval.add_constraint(
                is_leave.clone()
                    * (post_leave_mask_bits[index].clone() - pre_leave_mask_bits[index].clone()),
            );
        }
        // `AdvanceDeadline` is permissionless, but its expiry predicate is
        // not trusted to the host.  These canonical u64 limbs prove the
        // committed height is at least the active pre-state deadline, using a
        // checked subtraction witness (`height = deadline + difference`).
        for index in 0..4 {
            range16_constraints(
                &mut eval,
                &is_advance_deadline,
                &deadline_height[index],
                &advance_deadline_height_bits[index],
            );
            range16_constraints(
                &mut eval,
                &is_advance_deadline,
                &pre_deadline_image[index],
                &advance_deadline_pre_bits[index],
            );
            range16_constraints(
                &mut eval,
                &is_advance_deadline,
                &advance_deadline_difference[index],
                &advance_deadline_difference_bits[index],
            );
        }
        limb4_add_constraints(
            &mut eval,
            &is_advance_deadline,
            &pre_deadline_image,
            &advance_deadline_difference,
            &deadline_height,
            &advance_deadline_carries,
        );
        for carry in &advance_deadline_carries {
            eval.add_constraint((active.clone() - is_advance_deadline.clone()) * carry.clone());
        }
        let mut advance_pre_deadline_sum: E::F = M31::from(0u32).into();
        for limb in &pre_deadline_image {
            advance_pre_deadline_sum += limb.clone();
        }
        eval.add_constraint(
            is_advance_deadline.clone()
                * (advance_pre_deadline_sum * advance_deadline_pre_inv.clone() - one.clone()),
        );
        eval.add_constraint(
            is_advance_deadline.clone()
                * (pre_phase.clone() * advance_deadline_phase_inv.clone() - one.clone()),
        );
        eval.add_constraint(
            (active.clone() - is_advance_deadline.clone()) * advance_deadline_pre_inv.clone(),
        );
        eval.add_constraint(
            (active.clone() - is_advance_deadline.clone()) * advance_deadline_phase_inv.clone(),
        );

        // `AdvanceDeadline` is a VM transition on the active betting seat.  A
        // valid row must preserve the betting image and consume exactly the
        // selected seat's time bank; none of these values may be supplied by
        // an unrelated host projection.
        eval.add_constraint(
            is_advance_deadline.clone() * (pre_phase.clone() - M31::from(4u32).into()),
        );
        eval.add_constraint(is_advance_deadline.clone() * (post_phase.clone() - pre_phase.clone()));
        eval.add_constraint(is_advance_deadline.clone() * (pre_turn.clone() - seat.clone()));
        eval.add_constraint(is_advance_deadline.clone() * (post_turn.clone() - pre_turn.clone()));
        eval.add_constraint(
            is_advance_deadline.clone()
                * (pre_status.clone() - M31::from(CanonicalSeatStatus::Active as u32).into()),
        );
        eval.add_constraint(
            is_advance_deadline.clone()
                * (post_status.clone() - M31::from(CanonicalSeatStatus::Active as u32).into()),
        );
        for (left, right) in [
            (&pre_subtag, &post_subtag),
            (&pre_street, &post_street),
            (&pre_leave_mask, &post_leave_mask),
        ] {
            eval.add_constraint(is_advance_deadline.clone() * (right.clone() - left.clone()));
        }
        for (pre_value, post_value) in [
            (&pre_current, &post_current),
            (&pre_min, &post_min),
            (&pre_pot, &post_pot),
            (&pre_chip_pool, &post_chip_pool),
        ] {
            for (left, right) in pre_value.iter().zip(post_value.iter()) {
                eval.add_constraint(is_advance_deadline.clone() * (right.clone() - left.clone()));
            }
        }
        eval.add_constraint(is_advance_deadline.clone() * flag.clone());
        eval.add_constraint(is_advance_deadline.clone() * (auxiliary[0].clone() - one.clone()));
        for value in &auxiliary[1..] {
            eval.add_constraint(is_advance_deadline.clone() * value.clone());
        }
        for value in &amount[2..] {
            eval.add_constraint(is_advance_deadline.clone() * value.clone());
        }

        // The extension deadline is the committed pre-deadline plus the
        // consumed amount.  This also binds the third carry advice emitted by
        // `row()` and prevents a fabricated post-deadline image.
        limb4_add_constraints(
            &mut eval,
            &is_advance_deadline,
            &pre_deadline_image,
            &amount,
            &post_deadline_image,
            &advance_deadline_extension_carries,
        );

        let timeout_limbs: [E::F; 2] = [
            M31::from(CANONICAL_BETTING_TIMEOUT_MS).into(),
            M31::from(0u32).into(),
        ];
        let consume_all = advance_deadline_time_bank_all.clone();
        // The selected transition time-bank projection is consumed by the
        // deadline arithmetic below. The selector loop later emits the remaining
        // seat projections and must not add these values a second time.
        for index in 0..MAX_CANONICAL_SEATS {
            let selector = transition_seat_selectors[index].clone();
            for limb in 0..2 {
                selected_transition_pre_time[limb] +=
                    selector.clone() * full_pre_time_bank[index][limb].clone();
                selected_transition_post_time[limb] +=
                    selector.clone() * full_post_time_bank[index][limb].clone();
            }
        }
        eval.add_constraint(
            consume_all_gate.clone() - is_advance_deadline.clone() * consume_all.clone(),
        );
        eval.add_constraint(
            partial_gate.clone()
                - is_advance_deadline.clone() * (one.clone() - consume_all.clone()),
        );
        eval.add_constraint(
            is_advance_deadline.clone() * consume_all.clone() * (consume_all.clone() - one.clone()),
        );
        eval.add_constraint((active.clone() - is_advance_deadline.clone()) * consume_all.clone());
        for (value, bits) in advance_deadline_time_bank_slack
            .iter()
            .zip(advance_deadline_time_bank_range_bits[0].iter())
            .chain(
                advance_deadline_time_bank_excess
                    .iter()
                    .zip(advance_deadline_time_bank_range_bits[1].iter()),
            )
        {
            range16_constraints(&mut eval, &is_advance_deadline, value, bits);
        }
        limb2_add_constraints(
            &mut eval,
            &consume_all_gate,
            &selected_transition_pre_time,
            &advance_deadline_time_bank_slack,
            &timeout_limbs,
            &advance_deadline_time_bank_carries[0],
        );
        limb2_add_constraints(
            &mut eval,
            &partial_gate,
            &timeout_limbs,
            &advance_deadline_time_bank_excess,
            &selected_transition_pre_time,
            &advance_deadline_time_bank_carries[1],
        );
        let amount_low = [amount[0].clone(), amount[1].clone()];
        limb2_add_constraints(
            &mut eval,
            &is_advance_deadline,
            &selected_transition_post_time,
            &amount_low,
            &selected_transition_pre_time,
            &advance_deadline_time_bank_carries[2],
        );
        for limb in 0..2 {
            eval.add_constraint(
                consume_all_gate.clone()
                    * (amount[limb].clone() - selected_transition_pre_time[limb].clone()),
            );
            eval.add_constraint(
                partial_gate.clone() * (amount[limb].clone() - timeout_limbs[limb].clone()),
            );
            eval.add_constraint(
                consume_all_gate.clone() * selected_transition_post_time[limb].clone(),
            );
            eval.add_constraint(
                consume_all_gate.clone() * advance_deadline_time_bank_excess[limb].clone(),
            );
            eval.add_constraint(
                partial_gate.clone() * advance_deadline_time_bank_slack[limb].clone(),
            );
        }
        let chip_action = is_check.clone() + is_call.clone() + is_raise.clone() + is_bet.clone();
        for (pre, post) in pre_chip_pool.iter().zip(post_chip_pool.iter()) {
            eval.add_constraint(is_betting.clone() * (post.clone() - pre.clone()));
        }
        // `advance_round` is a VM micro-step after the final betting action.
        // It is deliberately a separate tagged row so its all-seat pot
        // collection is visible to the AIR instead of being hidden behind an
        // unconstrained post-action reveal commitment.
        eval.add_constraint(
            is_round_advance.clone() * (pre_phase.clone() - M31::from(4u32).into()),
        );
        eval.add_constraint(
            is_round_advance.clone() * (post_phase.clone() - M31::from(2u32).into()),
        );
        eval.add_constraint(is_round_advance.clone() * (pre_turn.clone() - no_seat.clone()));
        eval.add_constraint(is_round_advance.clone() * (post_turn.clone() - no_seat));
        eval.add_constraint(
            is_round_advance.clone() * (post_street.clone() - pre_street.clone() - one.clone()),
        );
        for value in post_current.iter().chain(post_min.iter()) {
            eval.add_constraint(is_round_advance.clone() * value.clone());
        }
        eval.add_constraint(
            is_round_advance.clone() * (post_acted_mask.clone() - pre_acted_mask.clone()),
        );
        eval.add_constraint(
            is_round_advance.clone() * (post_leave_mask.clone() - pre_leave_mask.clone()),
        );
        for (pre, post) in pre_chip_pool.iter().zip(post_chip_pool.iter()) {
            eval.add_constraint(is_round_advance.clone() * (post.clone() - pre.clone()));
        }
        for index in 0..MAX_CANONICAL_SEATS {
            for limb in 0..4 {
                range16_constraints(
                    &mut eval,
                    &is_round_advance,
                    &full_pre_bet[index][limb],
                    &round_collect_bet_bits[index][limb],
                );
                eval.add_constraint(is_round_advance.clone() * full_post_bet[index][limb].clone());
            }
            for status in 0..SEAT_STATUS_COUNT {
                eval.add_constraint(
                    is_round_advance.clone()
                        * (full_post_status[index][status].clone()
                            - full_pre_status[index][status].clone()),
                );
            }
            for (pre, post) in [
                (&full_pre_stack[index], &full_post_stack[index]),
                (&full_pre_total[index], &full_post_total[index]),
                (&full_pre_pending[index], &full_post_pending[index]),
            ] {
                for (left, right) in pre.iter().zip(post.iter()) {
                    eval.add_constraint(is_round_advance.clone() * (right.clone() - left.clone()));
                }
            }
            for (left, right) in full_pre_time_bank[index]
                .iter()
                .zip(full_post_time_bank[index].iter())
            {
                eval.add_constraint(is_round_advance.clone() * (right.clone() - left.clone()));
            }
        }
        // Fixed VM board-reveal schedule.  The six selectors represent
        // (preflop, flop, turn) × (single runout, run-it-twice); this keeps the
        // schedule quadratic and avoids trusting a host-provided branch or
        // variable-length assignment vector.
        let schedule_profiles = [
            // pre street, RIT, cards allocated, first-board length,
            // second-board length, assignment count, cards per runout.
            (1u32, 0u32, 3u32, 0u32, 0u32, 3u32, 3usize),
            (1, 1, 6, 0, 0, 6, 3),
            (2, 0, 1, 3, 0, 1, 1),
            (2, 1, 2, 3, 3, 2, 1),
            (3, 0, 1, 4, 0, 1, 1),
            (3, 1, 2, 4, 4, 2, 1),
        ];
        let mut selector_sum: E::F = M31::from(0u32).into();
        let mut expected_street: E::F = M31::from(0u32).into();
        let mut expected_rit: E::F = M31::from(0u32).into();
        let mut expected_cards: E::F = M31::from(0u32).into();
        let mut expected_first_len: E::F = M31::from(0u32).into();
        let mut expected_second_len: E::F = M31::from(0u32).into();
        let mut expected_count: E::F = M31::from(0u32).into();
        for (selector, profile) in round_schedule_selectors.iter().zip(schedule_profiles) {
            let street: E::F = M31::from(profile.0).into();
            let run_it_twice: E::F = M31::from(profile.1).into();
            let cards: E::F = M31::from(profile.2).into();
            let first_len: E::F = M31::from(profile.3).into();
            let second_len: E::F = M31::from(profile.4).into();
            let assignment_count: E::F = M31::from(profile.5).into();
            eval.add_constraint(
                active.clone() * selector.clone() * (selector.clone() - one.clone()),
            );
            eval.add_constraint((active.clone() - is_round_advance.clone()) * selector.clone());
            selector_sum += selector.clone();
            expected_street += selector.clone() * street;
            expected_rit += selector.clone() * run_it_twice;
            expected_cards += selector.clone() * cards;
            expected_first_len += selector.clone() * first_len;
            expected_second_len += selector.clone() * second_len;
            expected_count += selector.clone() * assignment_count;
        }
        eval.add_constraint(selector_sum - is_round_advance.clone());
        eval.add_constraint(is_round_advance.clone() * (pre_street.clone() - expected_street));
        eval.add_constraint(round_run_it_twice.clone() - expected_rit);
        eval.add_constraint(round_pre_board_len.clone() - expected_first_len.clone());
        eval.add_constraint(round_post_board_len.clone() - expected_first_len);
        eval.add_constraint(round_pre_second_board_len.clone() - expected_second_len.clone());
        eval.add_constraint(round_post_second_board_len.clone() - expected_second_len);
        eval.add_constraint(round_assignment_count.clone() - expected_count.clone());
        eval.add_constraint(
            round_post_cards_dealt.clone() - round_pre_cards_dealt.clone() - expected_count,
        );
        eval.add_constraint(
            is_round_advance.clone() * (round_reveal_purpose.clone() - M31::from(2u32).into()),
        );
        eval.add_constraint(
            is_round_advance.clone() * (post_subtag.clone() - M31::from(2u32).into()),
        );
        // Both deck cursors are native 6-bit values in the closed interval
        // [0, 52].  `cursor + complement = 52` is checked bit-by-bit with
        // constrained carries, so this relation remains sound even when a
        // malicious prover bypasses `CanonicalTransitionWitness::validate_shape`.
        for cursor_index in 0..2 {
            let cursor = if cursor_index == 0 {
                round_pre_cards_dealt.clone()
            } else {
                round_post_cards_dealt.clone()
            };
            let mut reconstructed: E::F = M31::from(0u32).into();
            let mut carry_in: E::F = M31::from(0u32).into();
            for bit_index in 0..6 {
                let cursor_bit = round_card_cursor_range[cursor_index][0][bit_index].clone();
                let remaining_bit = round_card_cursor_range[cursor_index][1][bit_index].clone();
                let carry_out = round_card_cursor_range[cursor_index][2][bit_index].clone();
                for value in [&cursor_bit, &remaining_bit, &carry_out] {
                    eval.add_constraint(
                        active.clone() * value.clone() * (value.clone() - one.clone()),
                    );
                    eval.add_constraint(
                        (active.clone() - is_round_advance.clone()) * value.clone(),
                    );
                }
                let weight: E::F = M31::from(1u32 << bit_index).into();
                let constant_bit: E::F = M31::from((52u32 >> bit_index) & 1).into();
                let two: E::F = M31::from(2u32).into();
                reconstructed += cursor_bit.clone() * weight;
                eval.add_constraint(
                    is_round_advance.clone()
                        * (cursor_bit + remaining_bit + carry_in
                            - constant_bit
                            - two * carry_out.clone()),
                );
                carry_in = carry_out;
            }
            eval.add_constraint(is_round_advance.clone() * (cursor - reconstructed));
            eval.add_constraint(is_round_advance.clone() * carry_in);
        }
        for value in [
            round_pre_cards_dealt.clone(),
            round_post_cards_dealt.clone(),
            round_pre_board_len.clone(),
            round_post_board_len.clone(),
            round_pre_second_board_len.clone(),
            round_post_second_board_len.clone(),
            round_run_it_twice.clone(),
            round_reveal_purpose.clone(),
            round_assignment_count.clone(),
        ] {
            eval.add_constraint((active.clone() - is_round_advance.clone()) * value);
        }
        let mut expected_pending_mask: E::F = M31::from(0u32).into();
        for index in 0..MAX_CANONICAL_SEATS {
            let weight: E::F = M31::from(1u32 << index).into();
            let active_or_folded_or_all_in =
                full_pre_status[index][CanonicalSeatStatus::Active as usize].clone()
                    + full_pre_status[index][CanonicalSeatStatus::Folded as usize].clone()
                    + full_pre_status[index][CanonicalSeatStatus::AllIn as usize].clone();
            expected_pending_mask += active_or_folded_or_all_in * weight;
        }
        for index in 0..MAX_CANONICAL_BOARD_REVEAL_ASSIGNMENTS {
            let present = round_assignments[index][0].clone();
            let encrypted_index = round_assignments[index][1].clone();
            let runout_index = round_assignments[index][2].clone();
            let board_position = round_assignments[index][3].clone();
            let pending_mask = round_assignments[index][4].clone();
            let submitted_mask = round_assignments[index][5].clone();
            let mut expected_present: E::F = M31::from(0u32).into();
            let mut expected_runout: E::F = M31::from(0u32).into();
            let mut expected_position: E::F = M31::from(0u32).into();
            for (selector, profile) in round_schedule_selectors.iter().zip(schedule_profiles) {
                let assignment_count = profile.5 as usize;
                if index < assignment_count {
                    expected_present += selector.clone();
                    let runout = u32::from(index >= profile.6);
                    let offset = (index % profile.6) as u32;
                    let board_len = if runout == 0 { profile.3 } else { profile.4 };
                    let runout_value: E::F = M31::from(runout).into();
                    let position_value: E::F = M31::from(board_len + offset).into();
                    expected_runout += selector.clone() * runout_value;
                    expected_position += selector.clone() * position_value;
                }
            }
            eval.add_constraint(present.clone() - expected_present);
            eval.add_constraint(submitted_mask.clone());
            let absent = one.clone() - present.clone();
            for value in [
                encrypted_index.clone(),
                runout_index.clone(),
                board_position.clone(),
                pending_mask.clone(),
            ] {
                eval.add_constraint(absent.clone() * value);
            }
            eval.add_constraint(
                present.clone()
                    * (encrypted_index
                        - round_pre_cards_dealt.clone()
                        - M31::from(index as u32).into()),
            );
            eval.add_constraint(present.clone() * (runout_index - expected_runout));
            eval.add_constraint(present.clone() * (board_position - expected_position));
            eval.add_constraint(present * (pending_mask - expected_pending_mask.clone()));
        }
        for (carry, bits) in round_collect_carries
            .iter()
            .zip(round_collect_carry_bits.iter())
        {
            let mut reconstructed: E::F = M31::from(0u32).into();
            for (bit, weight) in bits.iter().zip([1u32, 2, 4, 8]) {
                eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
                eval.add_constraint((active.clone() - is_round_advance.clone()) * bit.clone());
                let weight: E::F = M31::from(weight).into();
                reconstructed += bit.clone() * weight;
            }
            eval.add_constraint(carry.clone() - reconstructed);
            eval.add_constraint((active.clone() - is_round_advance.clone()) * carry.clone());
        }
        let round_base: E::F = M31::from(65536u32).into();
        for limb in 0..4 {
            let mut sum = pre_pot[limb].clone();
            for index in 0..MAX_CANONICAL_SEATS {
                sum += full_pre_bet[index][limb].clone();
            }
            if limb > 0 {
                sum += round_collect_carries[limb - 1].clone();
            }
            if limb < 3 {
                eval.add_constraint(
                    is_round_advance.clone()
                        * (sum
                            - post_pot[limb].clone()
                            - round_base.clone() * round_collect_carries[limb].clone()),
                );
            } else {
                // No final carry is admitted: this is exactly the VM's
                // checked `pot + sum(bets)` overflow rejection.
                eval.add_constraint(is_round_advance.clone() * (sum - post_pot[limb].clone()));
            }
        }
        let non_raise_betting = is_betting.clone() - is_raise.clone();
        let mut selector_sum: E::F = M31::from(0u32).into();
        let mut selected_pre_acted: E::F = M31::from(0u32).into();
        let mut selected_post_acted: E::F = M31::from(0u32).into();
        let mut pre_mask_from_bits: E::F = M31::from(0u32).into();
        let mut post_mask_from_bits: E::F = M31::from(0u32).into();
        let mut selected_seat: E::F = M31::from(0u32).into();
        for index in 0..MAX_CANONICAL_SEATS {
            let selector = acted_seat_selectors[index].clone();
            let pre_bit = pre_acted_bits[index].clone();
            let post_bit = post_acted_bits[index].clone();
            let delta = acted_deltas[index].clone();
            let bit_weight: E::F = M31::from(1u32 << index).into();
            let seat_value: E::F = M31::from(index as u32).into();
            eval.add_constraint(selector.clone() * (selector.clone() - one.clone()));
            eval.add_constraint(pre_bit.clone() * (pre_bit.clone() - one.clone()));
            eval.add_constraint(post_bit.clone() * (post_bit.clone() - one.clone()));
            eval.add_constraint(delta.clone() * (delta.clone() - one.clone()));
            eval.add_constraint(delta - selector.clone() * (one.clone() - pre_bit.clone()));
            eval.add_constraint(
                non_raise_betting.clone()
                    * (post_bit.clone() - pre_bit.clone() - acted_deltas[index].clone()),
            );
            selector_sum += selector.clone();
            selected_pre_acted += selector.clone() * pre_bit.clone();
            selected_post_acted += selector.clone() * post_bit.clone();
            selected_seat += selector * seat_value;
            pre_mask_from_bits += pre_bit * bit_weight.clone();
            post_mask_from_bits += post_bit * bit_weight;
        }
        eval.add_constraint(selector_sum - is_betting.clone());
        eval.add_constraint(selected_seat - is_betting.clone() * seat.clone());
        eval.add_constraint(pre_mask_from_bits - pre_acted_mask.clone());
        eval.add_constraint(post_mask_from_bits - post_acted_mask.clone());
        eval.add_constraint(is_betting.clone() * pre_seat_acted.clone() - selected_pre_acted);
        eval.add_constraint(is_betting.clone() * post_seat_acted.clone() - selected_post_acted);
        let mut pre_leave_mask_from_bits: E::F = M31::from(0u32).into();
        let mut post_leave_mask_from_bits: E::F = M31::from(0u32).into();
        for index in 0..MAX_CANONICAL_SEATS {
            let pre_bit = pre_leave_mask_bits[index].clone();
            let post_bit = post_leave_mask_bits[index].clone();
            let bit_weight: E::F = M31::from(1u32 << index).into();
            eval.add_constraint(active.clone() * pre_bit.clone() * (pre_bit.clone() - one.clone()));
            eval.add_constraint(
                active.clone() * post_bit.clone() * (post_bit.clone() - one.clone()),
            );
            pre_leave_mask_from_bits += pre_bit * bit_weight.clone();
            post_leave_mask_from_bits += post_bit * bit_weight;
        }
        eval.add_constraint(active.clone() * (pre_leave_mask_from_bits - pre_leave_mask.clone()));
        eval.add_constraint(active.clone() * (post_leave_mask_from_bits - post_leave_mask.clone()));
        // Open every seat that the VM consults while progressing a betting
        // round.  This makes the current selected-seat projection a derived
        // value and prevents the host from changing a non-acting stack/bet or
        // lifecycle image outside the former narrow projection.
        let mut selected_full_pre_status: E::F = M31::from(0u32).into();
        let mut selected_full_post_status: E::F = M31::from(0u32).into();
        let mut selected_full_pre_stack: [E::F; 4] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_full_post_stack: [E::F; 4] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_full_pre_bet: [E::F; 4] = std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_full_post_bet: [E::F; 4] = std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_full_pre_total: [E::F; 4] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_full_post_total: [E::F; 4] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_full_pre_pending: [E::F; 4] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_full_post_pending: [E::F; 4] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_full_pre_time: [E::F; 2] = std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_full_post_time: [E::F; 2] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_funding_pre_status: E::F = M31::from(0u32).into();
        let mut selected_funding_post_status: E::F = M31::from(0u32).into();
        let mut selected_funding_pre_stack: [E::F; 4] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_funding_post_stack: [E::F; 4] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_funding_pre_bet: [E::F; 4] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_funding_post_bet: [E::F; 4] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_funding_pre_total: [E::F; 4] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_funding_post_total: [E::F; 4] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_funding_pre_pending: [E::F; 4] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_funding_post_pending: [E::F; 4] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_funding_pre_time: [E::F; 2] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_funding_post_time: [E::F; 2] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut funding_selector_sum: E::F = M31::from(0u32).into();
        let mut selected_funding_seat: E::F = M31::from(0u32).into();
        let mut transition_selector_sum: E::F = M31::from(0u32).into();
        let mut selected_transition_seat: E::F = M31::from(0u32).into();
        let mut selected_transition_pre_status: E::F = M31::from(0u32).into();
        let mut selected_transition_post_status: E::F = M31::from(0u32).into();
        let mut selected_transition_pre_stack: [E::F; 4] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_transition_pre_pending: [E::F; 4] =
            std::array::from_fn(|_| M31::from(0u32).into());
        let mut selected_transition_pre_bet: [E::F; 4] =
            std::array::from_fn(|_| M31::from(0u32).into());
        for index in 0..MAX_CANONICAL_SEATS {
            let betting_selector = acted_seat_selectors[index].clone();
            let funding_selector = funding_seat_selectors[index].clone();
            let transition_selector = transition_seat_selectors[index].clone();
            let selector = betting_selector.clone();
            eval.add_constraint(
                active.clone()
                    * funding_selector.clone()
                    * (funding_selector.clone() - one.clone()),
            );
            eval.add_constraint((active.clone() - is_funding.clone()) * funding_selector.clone());
            funding_selector_sum += funding_selector.clone();
            let index_value: E::F = M31::from(index as u32).into();
            selected_funding_seat += funding_selector.clone() * index_value.clone();
            eval.add_constraint(
                active.clone()
                    * transition_selector.clone()
                    * (transition_selector.clone() - one.clone()),
            );
            eval.add_constraint(
                (active.clone() - requires_transition_seat.clone()) * transition_selector.clone(),
            );
            // `SetLeaveAfterHand` writes precisely the selected bit.  With
            // binary mask bits, `post - pre = 2 * flag - 1` forces a false
            // flag to clear a previously-set bit and a true flag to set a
            // previously-clear bit; every non-selected bit is unchanged.
            eval.add_constraint(
                is_set_leave.clone()
                    * (post_leave_mask_bits[index].clone()
                        - pre_leave_mask_bits[index].clone()
                        - transition_selector.clone()
                            * (flag.clone() + flag.clone() - one.clone())),
            );
            transition_selector_sum += transition_selector.clone();
            selected_transition_seat += transition_selector.clone() * index_value;
            let mut pre_status_value: E::F = M31::from(0u32).into();
            let mut post_status_value: E::F = M31::from(0u32).into();
            let mut weight: E::F = M31::from(0u32).into();
            for status in 0..SEAT_STATUS_COUNT {
                let pre = full_pre_status[index][status].clone();
                let post = full_post_status[index][status].clone();
                eval.add_constraint(active.clone() * pre.clone() * (pre.clone() - one.clone()));
                eval.add_constraint(active.clone() * post.clone() * (post.clone() - one.clone()));
                pre_status_value += pre * weight.clone();
                post_status_value += post * weight.clone();
                weight += one.clone();
            }
            let pre_status_sum = full_pre_status[index]
                .iter()
                .fold(M31::from(0u32).into(), |sum: E::F, value| {
                    sum + value.clone()
                });
            let post_status_sum = full_post_status[index]
                .iter()
                .fold(M31::from(0u32).into(), |sum: E::F, value| {
                    sum + value.clone()
                });
            eval.add_constraint(active.clone() * (pre_status_sum - one.clone()));
            eval.add_constraint(active.clone() * (post_status_sum - one.clone()));
            for status in 0..SEAT_STATUS_COUNT {
                eval.add_constraint(
                    is_protocol_submit.clone()
                        * (full_post_status[index][status].clone()
                            - full_pre_status[index][status].clone()),
                );
            }
            for (pre, post) in [
                (&full_pre_stack[index], &full_post_stack[index]),
                (&full_pre_bet[index], &full_post_bet[index]),
                (&full_pre_total[index], &full_post_total[index]),
                (&full_pre_pending[index], &full_post_pending[index]),
            ] {
                for (left, right) in pre.iter().zip(post.iter()) {
                    eval.add_constraint(
                        is_protocol_submit.clone() * (right.clone() - left.clone()),
                    );
                }
            }
            for (left, right) in full_pre_time_bank[index]
                .iter()
                .zip(full_post_time_bank[index].iter())
            {
                eval.add_constraint(is_protocol_submit.clone() * (right.clone() - left.clone()));
            }
            eval.add_constraint(
                is_protocol_submit.clone()
                    * (post_acted_bits[index].clone() - pre_acted_bits[index].clone()),
            );
            eval.add_constraint(
                is_protocol_submit.clone()
                    * (post_leave_mask_bits[index].clone() - pre_leave_mask_bits[index].clone()),
            );
            for commitment in 0..SEAT_COMMITMENT_FIELD_COUNT {
                for limb in 0..16 {
                    eval.add_constraint(
                        is_protocol_submit.clone()
                            * (post_seat_commitments[index][commitment][limb].clone()
                                - pre_seat_commitments[index][commitment][limb].clone()),
                    );
                }
            }
            for status in 0..SEAT_STATUS_COUNT {
                let expected: E::F =
                    M31::from(u32::from(status == CanonicalSeatStatus::Empty as usize)).into();
                eval.add_constraint(
                    is_create.clone()
                        * (full_post_status[index][status].clone() - expected.clone()),
                );
                eval.add_constraint(
                    is_create.clone() * (full_pre_status[index][status].clone() - expected),
                );
            }
            // ForceFold and KickPlayer have a finite, VM-defined lifecycle
            // transition.  Use the full one-hot seat opening rather than the
            // host-provided scalar projection, so a different seat cannot
            // satisfy the action's pre/post status rule.
            eval.add_constraint(
                is_force_or_kick.clone()
                    * transition_selector.clone()
                    * (full_pre_status[index][CanonicalSeatStatus::Active as usize].clone()
                        + full_pre_status[index][CanonicalSeatStatus::Waiting as usize].clone()
                        - one.clone()),
            );
            eval.add_constraint(
                is_force_or_kick.clone()
                    * transition_selector.clone()
                    * (full_post_status[index][CanonicalSeatStatus::Folded as usize].clone()
                        + full_post_status[index][CanonicalSeatStatus::Out as usize].clone()
                        + full_post_status[index][CanonicalSeatStatus::Empty as usize].clone()
                        - one.clone()),
            );
            // JoinTable credits the buy-in exactly once: the selected stack
            // receives it and TableVault locks it.  The VM creates a Playing
            // seat that participates in the next hand, with no current-round
            // accounting yet.
            eval.add_constraint(
                is_join.clone()
                    * transition_selector.clone()
                    * (full_pre_status[index][CanonicalSeatStatus::Empty as usize].clone()
                        - one.clone()),
            );
            for earlier in 0..index {
                eval.add_constraint(
                    is_join.clone()
                        * transition_selector.clone()
                        * full_pre_status[earlier][CanonicalSeatStatus::Empty as usize].clone(),
                );
            }
            eval.add_constraint(
                is_join.clone()
                    * transition_selector.clone()
                    * (full_post_status[index][CanonicalSeatStatus::Active as usize].clone()
                        - one.clone()),
            );
            for limb in 0..4 {
                eval.add_constraint(
                    is_join.clone()
                        * transition_selector.clone()
                        * (full_post_stack[index][limb].clone() - amount[limb].clone()),
                );
                eval.add_constraint(
                    is_join.clone()
                        * transition_selector.clone()
                        * full_post_bet[index][limb].clone(),
                );
                eval.add_constraint(
                    is_join.clone()
                        * transition_selector.clone()
                        * full_post_total[index][limb].clone(),
                );
                eval.add_constraint(
                    is_join.clone()
                        * transition_selector.clone()
                        * full_post_pending[index][limb].clone(),
                );
            }
            eval.add_constraint(
                is_join.clone()
                    * transition_selector.clone()
                    * (full_post_time_bank[index][0].clone() - M31::from(30_000u32).into()),
            );
            eval.add_constraint(
                is_join.clone()
                    * transition_selector.clone()
                    * full_post_time_bank[index][1].clone(),
            );
            eval.add_constraint(
                is_join.clone() * transition_selector.clone() * post_acted_bits[index].clone(),
            );
            eval.add_constraint(
                is_join.clone() * transition_selector.clone() * post_leave_mask_bits[index].clone(),
            );
            eval.add_constraint(
                is_join.clone() * transition_selector.clone() * pre_acted_bits[index].clone(),
            );
            eval.add_constraint(
                is_join.clone() * transition_selector.clone() * pre_leave_mask_bits[index].clone(),
            );
            // LeaveTable is the inverse custody operation: refund stack plus
            // pending addon and replace the selected image with the unique
            // vacant representation.
            eval.add_constraint(
                is_leave.clone()
                    * transition_selector.clone()
                    * (full_pre_status[index][CanonicalSeatStatus::Waiting as usize].clone()
                        - one.clone()),
            );
            eval.add_constraint(
                is_leave.clone()
                    * transition_selector.clone()
                    * (full_post_status[index][CanonicalSeatStatus::Empty as usize].clone()
                        - one.clone()),
            );
            for limb in 0..4 {
                eval.add_constraint(
                    is_leave.clone()
                        * transition_selector.clone()
                        * full_post_stack[index][limb].clone(),
                );
                eval.add_constraint(
                    is_leave.clone()
                        * transition_selector.clone()
                        * full_post_bet[index][limb].clone(),
                );
                eval.add_constraint(
                    is_leave.clone()
                        * transition_selector.clone()
                        * full_post_total[index][limb].clone(),
                );
                eval.add_constraint(
                    is_leave.clone()
                        * transition_selector.clone()
                        * full_post_pending[index][limb].clone(),
                );
            }
            for time_bank_limb in full_post_time_bank[index].iter() {
                eval.add_constraint(
                    is_leave.clone() * transition_selector.clone() * time_bank_limb.clone(),
                );
            }
            eval.add_constraint(
                is_leave.clone() * transition_selector.clone() * post_acted_bits[index].clone(),
            );
            eval.add_constraint(
                is_leave.clone()
                    * transition_selector.clone()
                    * post_leave_mask_bits[index].clone(),
            );
            eval.add_constraint(
                is_leave.clone() * transition_selector.clone() * pre_acted_bits[index].clone(),
            );
            eval.add_constraint(
                is_leave.clone() * transition_selector.clone() * pre_leave_mask_bits[index].clone(),
            );
            // ForceFold lowers to the VM's nonterminal Fold action.  It is
            // player-turn gated, moves only Active -> Folded, sets the actor's
            // acted bit, and preserves every custody bucket and commitment.
            eval.add_constraint(
                is_force_fold.clone()
                    * transition_selector.clone()
                    * (full_pre_status[index][CanonicalSeatStatus::Active as usize].clone()
                        - one.clone()),
            );
            eval.add_constraint(
                is_force_fold.clone()
                    * transition_selector.clone()
                    * (full_post_status[index][CanonicalSeatStatus::Folded as usize].clone()
                        - one.clone()),
            );
            for (pre, post) in [
                (&full_pre_stack[index], &full_post_stack[index]),
                (&full_pre_bet[index], &full_post_bet[index]),
                (&full_pre_total[index], &full_post_total[index]),
                (&full_pre_pending[index], &full_post_pending[index]),
            ] {
                for (left, right) in pre.iter().zip(post.iter()) {
                    eval.add_constraint(
                        is_force_fold.clone()
                            * transition_selector.clone()
                            * (right.clone() - left.clone()),
                    );
                }
            }
            for (left, right) in full_pre_time_bank[index]
                .iter()
                .zip(full_post_time_bank[index].iter())
            {
                eval.add_constraint(
                    is_force_fold.clone()
                        * transition_selector.clone()
                        * (right.clone() - left.clone()),
                );
            }
            eval.add_constraint(
                is_force_fold.clone()
                    * transition_selector.clone()
                    * (post_acted_bits[index].clone() - one.clone()),
            );
            eval.add_constraint(
                is_force_fold.clone()
                    * (one.clone() - transition_selector.clone())
                    * (post_acted_bits[index].clone() - pre_acted_bits[index].clone()),
            );
            eval.add_constraint(
                is_force_fold.clone()
                    * (post_leave_mask_bits[index].clone() - pre_leave_mask_bits[index].clone()),
            );
            // A non-cascading VM kick departs the selected seat, clears live
            // custody and current-round wager buckets, and retains only the
            // side-pot/audit fields explicitly listed below.
            eval.add_constraint(
                is_kick.clone()
                    * transition_selector.clone()
                    * (full_post_status[index][CanonicalSeatStatus::Out as usize].clone()
                        - one.clone()),
            );
            for (pre, post) in [
                (&full_pre_stack[index], &full_post_stack[index]),
                (&full_pre_bet[index], &full_post_bet[index]),
                (&full_pre_pending[index], &full_post_pending[index]),
            ] {
                for limb in 0..4 {
                    eval.add_constraint(
                        is_kick.clone() * transition_selector.clone() * post[limb].clone(),
                    );
                    let _ = pre;
                }
            }
            for limb in 0..4 {
                eval.add_constraint(
                    is_kick.clone()
                        * transition_selector.clone()
                        * (full_post_total[index][limb].clone()
                            - full_pre_total[index][limb].clone()),
                );
            }
            for (pre, post) in full_pre_time_bank[index]
                .iter()
                .zip(full_post_time_bank[index].iter())
            {
                eval.add_constraint(
                    is_kick.clone() * transition_selector.clone() * (post.clone() - pre.clone()),
                );
            }
            eval.add_constraint(
                is_kick.clone() * transition_selector.clone() * post_acted_bits[index].clone(),
            );
            eval.add_constraint(
                is_kick.clone() * transition_selector.clone() * post_leave_mask_bits[index].clone(),
            );
            // A leave-after-hand flag can only be toggled for an occupied
            // seat.  The exact bit update is constrained below; this closes
            // the otherwise host-only empty-seat precondition.
            eval.add_constraint(
                is_set_leave.clone()
                    * transition_selector.clone()
                    * full_pre_status[index][CanonicalSeatStatus::Empty as usize].clone(),
            );

            selected_full_pre_status += selector.clone() * pre_status_value.clone();
            selected_full_post_status += selector.clone() * post_status_value.clone();
            selected_funding_pre_status += funding_selector.clone() * pre_status_value.clone();
            selected_funding_post_status += funding_selector.clone() * post_status_value.clone();
            selected_transition_pre_status +=
                transition_selector.clone() * pre_status_value.clone();
            selected_transition_post_status +=
                transition_selector.clone() * post_status_value.clone();
            for limb in 0..4 {
                selected_transition_pre_stack[limb] +=
                    transition_selector.clone() * full_pre_stack[index][limb].clone();
                selected_transition_pre_pending[limb] +=
                    transition_selector.clone() * full_pre_pending[index][limb].clone();
                selected_transition_pre_bet[limb] +=
                    transition_selector.clone() * full_pre_bet[index][limb].clone();
            }
            for limb in 0..4 {
                selected_full_pre_stack[limb] +=
                    selector.clone() * full_pre_stack[index][limb].clone();
                selected_full_post_stack[limb] +=
                    selector.clone() * full_post_stack[index][limb].clone();
                selected_full_pre_bet[limb] += selector.clone() * full_pre_bet[index][limb].clone();
                selected_full_post_bet[limb] +=
                    selector.clone() * full_post_bet[index][limb].clone();
                selected_full_pre_total[limb] +=
                    selector.clone() * full_pre_total[index][limb].clone();
                selected_full_post_total[limb] +=
                    selector.clone() * full_post_total[index][limb].clone();
                selected_full_pre_pending[limb] +=
                    selector.clone() * full_pre_pending[index][limb].clone();
                selected_full_post_pending[limb] +=
                    selector.clone() * full_post_pending[index][limb].clone();
                selected_funding_pre_stack[limb] +=
                    funding_selector.clone() * full_pre_stack[index][limb].clone();
                selected_funding_post_stack[limb] +=
                    funding_selector.clone() * full_post_stack[index][limb].clone();
                selected_funding_pre_bet[limb] +=
                    funding_selector.clone() * full_pre_bet[index][limb].clone();
                selected_funding_post_bet[limb] +=
                    funding_selector.clone() * full_post_bet[index][limb].clone();
                selected_funding_pre_total[limb] +=
                    funding_selector.clone() * full_pre_total[index][limb].clone();
                selected_funding_post_total[limb] +=
                    funding_selector.clone() * full_post_total[index][limb].clone();
                selected_funding_pre_pending[limb] +=
                    funding_selector.clone() * full_pre_pending[index][limb].clone();
                selected_funding_post_pending[limb] +=
                    funding_selector.clone() * full_post_pending[index][limb].clone();
            }
            for limb in 0..2 {
                selected_full_pre_time[limb] +=
                    selector.clone() * full_pre_time_bank[index][limb].clone();
                selected_full_post_time[limb] +=
                    selector.clone() * full_post_time_bank[index][limb].clone();
                selected_funding_pre_time[limb] +=
                    funding_selector.clone() * full_pre_time_bank[index][limb].clone();
                selected_funding_post_time[limb] +=
                    funding_selector.clone() * full_post_time_bank[index][limb].clone();
            }

            let unselected_betting = is_betting.clone() - betting_selector;
            for status in 0..SEAT_STATUS_COUNT {
                eval.add_constraint(
                    unselected_betting.clone()
                        * (full_post_status[index][status].clone()
                            - full_pre_status[index][status].clone()),
                );
            }
            for (pre, post) in [
                (&full_pre_stack[index], &full_post_stack[index]),
                (&full_pre_bet[index], &full_post_bet[index]),
                (&full_pre_total[index], &full_post_total[index]),
                (&full_pre_pending[index], &full_post_pending[index]),
            ] {
                for (left, right) in pre.iter().zip(post.iter()) {
                    eval.add_constraint(
                        unselected_betting.clone() * (right.clone() - left.clone()),
                    );
                }
            }
            for (left, right) in full_pre_time_bank[index]
                .iter()
                .zip(full_post_time_bank[index].iter())
            {
                eval.add_constraint(unselected_betting.clone() * (right.clone() - left.clone()));
            }

            // CreateTable and StartHand do not alter any public seat bucket.
            // For actions that target one lifecycle seat, every non-target
            // seat must also remain identical.  This uses the complete nine
            // seat projection, not the single legacy action-seat projection.
            let immutable_full_seat = is_create.clone()
                + is_start.clone()
                + is_set_leave.clone()
                + is_advance_deadline.clone();
            let immutable_time_bank = (immutable_full_seat.clone() - is_advance_deadline.clone())
                + is_advance_deadline.clone() * (one.clone() - transition_selector.clone());
            let unselected_lifecycle =
                is_selected_lifecycle.clone() * (one.clone() - transition_selector.clone());
            for status in 0..SEAT_STATUS_COUNT {
                let unchanged = full_post_status[index][status].clone()
                    - full_pre_status[index][status].clone();
                eval.add_constraint(immutable_full_seat.clone() * unchanged.clone());
                eval.add_constraint(unselected_lifecycle.clone() * unchanged);
            }
            for (pre, post) in [
                (&full_pre_stack[index], &full_post_stack[index]),
                (&full_pre_bet[index], &full_post_bet[index]),
                (&full_pre_total[index], &full_post_total[index]),
                (&full_pre_pending[index], &full_post_pending[index]),
            ] {
                for (left, right) in pre.iter().zip(post.iter()) {
                    let unchanged = right.clone() - left.clone();
                    eval.add_constraint(immutable_full_seat.clone() * unchanged.clone());
                    eval.add_constraint(unselected_lifecycle.clone() * unchanged);
                }
            }
            for (left, right) in full_pre_time_bank[index]
                .iter()
                .zip(full_post_time_bank[index].iter())
            {
                let unchanged = right.clone() - left.clone();
                eval.add_constraint(immutable_time_bank.clone() * unchanged.clone());
                eval.add_constraint(unselected_lifecycle.clone() * unchanged);
            }

            // Funding is also selected from the fixed full-seat opening.  It
            // may change only the target's stack or pending addon; every other
            // mutable bucket stays byte-for-byte represented by the same
            // limbs.  The selected projection below then feeds the existing
            // exact ripple-carry funding relation.
            let unselected_funding = is_funding.clone() - funding_selector.clone();
            for status in 0..SEAT_STATUS_COUNT {
                eval.add_constraint(
                    is_funding.clone()
                        * (full_post_status[index][status].clone()
                            - full_pre_status[index][status].clone()),
                );
            }
            for (pre, post) in [
                (&full_pre_stack[index], &full_post_stack[index]),
                (&full_pre_bet[index], &full_post_bet[index]),
                (&full_pre_total[index], &full_post_total[index]),
                (&full_pre_pending[index], &full_post_pending[index]),
            ] {
                for (left, right) in pre.iter().zip(post.iter()) {
                    eval.add_constraint(
                        unselected_funding.clone() * (right.clone() - left.clone()),
                    );
                }
            }
            for (left, right) in full_pre_time_bank[index]
                .iter()
                .zip(full_post_time_bank[index].iter())
            {
                eval.add_constraint(unselected_funding.clone() * (right.clone() - left.clone()));
            }
            for (left, right) in full_pre_bet[index].iter().zip(full_post_bet[index].iter()) {
                eval.add_constraint(funding_selector.clone() * (right.clone() - left.clone()));
            }
            for (left, right) in full_pre_total[index]
                .iter()
                .zip(full_post_total[index].iter())
            {
                eval.add_constraint(funding_selector.clone() * (right.clone() - left.clone()));
            }
            for (left, right) in full_pre_time_bank[index]
                .iter()
                .zip(full_post_time_bank[index].iter())
            {
                eval.add_constraint(funding_selector.clone() * (right.clone() - left.clone()));
            }

            eval.add_constraint(
                raise_actor[index].clone() - is_raise.clone() * acted_seat_selectors[index].clone(),
            );
            eval.add_constraint(
                raise_active[index].clone()
                    - is_raise.clone()
                        * full_pre_status[index][CanonicalSeatStatus::Active as usize].clone(),
            );
            eval.add_constraint(
                raise_actor[index].clone() * (post_acted_bits[index].clone() - one.clone()),
            );
            eval.add_constraint(
                (raise_active[index].clone() - raise_actor[index].clone())
                    * post_acted_bits[index].clone(),
            );
            eval.add_constraint(
                (is_raise.clone() - raise_active[index].clone())
                    * (post_acted_bits[index].clone() - pre_acted_bits[index].clone()),
            );
        }
        eval.add_constraint(funding_selector_sum - is_funding.clone());
        eval.add_constraint(selected_funding_seat - is_funding.clone() * seat.clone());
        eval.add_constraint(transition_selector_sum - requires_transition_seat.clone());
        eval.add_constraint(
            selected_transition_seat - requires_transition_seat.clone() * seat.clone(),
        );
        eval.add_constraint(
            requires_transition_seat.clone() * pre_status.clone() - selected_transition_pre_status,
        );
        eval.add_constraint(
            requires_transition_seat.clone() * post_status.clone()
                - selected_transition_post_status,
        );
        for (projected, full) in pre_time_bank
            .iter()
            .zip(selected_transition_pre_time.iter())
        {
            eval.add_constraint(
                requires_transition_seat.clone() * projected.clone() - full.clone(),
            );
        }
        for (projected, full) in post_time_bank
            .iter()
            .zip(selected_transition_post_time.iter())
        {
            eval.add_constraint(
                requires_transition_seat.clone() * projected.clone() - full.clone(),
            );
        }
        // The funding selector must open the very same selected seat that the
        // fixed ABI projects into the arithmetic rows below.  Without these
        // equalities a prover could satisfy the Addon/Rebuy limb equations
        // against an unrelated synthetic seat while changing a different
        // full-seat image.
        eval.add_constraint(is_funding.clone() * pre_status.clone() - selected_funding_pre_status);
        eval.add_constraint(
            is_funding.clone() * post_status.clone() - selected_funding_post_status,
        );
        for (projected, full) in pre_stack.iter().zip(selected_funding_pre_stack.iter()) {
            eval.add_constraint(is_funding.clone() * projected.clone() - full.clone());
        }
        for (projected, full) in post_stack.iter().zip(selected_funding_post_stack.iter()) {
            eval.add_constraint(is_funding.clone() * projected.clone() - full.clone());
        }
        for (projected, full) in pre_bet.iter().zip(selected_funding_pre_bet.iter()) {
            eval.add_constraint(is_funding.clone() * projected.clone() - full.clone());
        }
        for (projected, full) in post_bet.iter().zip(selected_funding_post_bet.iter()) {
            eval.add_constraint(is_funding.clone() * projected.clone() - full.clone());
        }
        for (projected, full) in pre_total.iter().zip(selected_funding_pre_total.iter()) {
            eval.add_constraint(is_funding.clone() * projected.clone() - full.clone());
        }
        for (projected, full) in post_total.iter().zip(selected_funding_post_total.iter()) {
            eval.add_constraint(is_funding.clone() * projected.clone() - full.clone());
        }
        for (projected, full) in pre_pending.iter().zip(selected_funding_pre_pending.iter()) {
            eval.add_constraint(is_funding.clone() * projected.clone() - full.clone());
        }
        for (projected, full) in post_pending
            .iter()
            .zip(selected_funding_post_pending.iter())
        {
            eval.add_constraint(is_funding.clone() * projected.clone() - full.clone());
        }
        for (projected, full) in pre_time_bank.iter().zip(selected_funding_pre_time.iter()) {
            eval.add_constraint(is_funding.clone() * projected.clone() - full.clone());
        }
        for (projected, full) in post_time_bank.iter().zip(selected_funding_post_time.iter()) {
            eval.add_constraint(is_funding.clone() * projected.clone() - full.clone());
        }
        // `advance_turn` scans circularly from the acting seat.  Its choice is
        // no longer a host-selected `post.current_turn`: a one-hot successor
        // and a 9x9 pair decomposition bind the first post-action Active seat.
        // `no_next_turn` is permitted only when no Active seat remains.
        eval.add_constraint(no_next_turn.clone() * (no_next_turn.clone() - one.clone()));
        eval.add_constraint((active.clone() - is_betting.clone()) * no_next_turn.clone());
        let mut next_sum: E::F = M31::from(0u32).into();
        let mut next_turn_value: E::F = M31::from(0u32).into();
        for index in 0..MAX_CANONICAL_SEATS {
            let selector = next_turn_selectors[index].clone();
            eval.add_constraint(
                active.clone() * selector.clone() * (selector.clone() - one.clone()),
            );
            eval.add_constraint(
                (active.clone() - is_betting.clone() - is_force_fold.clone()) * selector.clone(),
            );
            eval.add_constraint(
                selector.clone()
                    * (full_post_status[index][CanonicalSeatStatus::Active as usize].clone()
                        - one.clone()),
            );
            // If the action stays in this mid-round component, the VM's next
            // actor cannot already have acted.  Otherwise the just-completed
            // round must follow the separate collect/advance relation rather
            // than be represented as a stale betting row.
            eval.add_constraint(selector.clone() * post_acted_bits[index].clone());
            // No successor is valid only at the exact completed-round
            // boundary: every remaining actionable seat must already have
            // acted and matched the final current bet.  The following
            // `AdvanceRound` row then performs the all-seat collection.
            let post_active = full_post_status[index][CanonicalSeatStatus::Active as usize].clone();
            let completed_active = round_complete_active[index].clone();
            eval.add_constraint(
                completed_active.clone() - no_next_turn.clone() * post_active.clone(),
            );
            eval.add_constraint(
                completed_active.clone() * (post_acted_bits[index].clone() - one.clone()),
            );
            for limb in 0..4 {
                eval.add_constraint(
                    completed_active.clone()
                        * (full_post_bet[index][limb].clone() - post_current[limb].clone()),
                );
            }
            next_sum += selector.clone();
            let index_value: E::F = M31::from(index as u32).into();
            next_turn_value += selector * index_value;
        }
        eval.add_constraint(
            next_sum.clone() + no_next_turn.clone() - is_betting.clone() - is_force_fold.clone(),
        );
        let fifteen: E::F = M31::from(15u32).into();
        eval.add_constraint(
            (is_betting.clone() + is_force_fold.clone())
                * (post_turn.clone() - next_turn_value - fifteen * no_next_turn.clone()),
        );
        for from in 0..MAX_CANONICAL_SEATS {
            for to in 0..MAX_CANONICAL_SEATS {
                let pair = next_turn_pairs[from][to].clone();
                eval.add_constraint(
                    pair.clone()
                        - transition_seat_selectors[from].clone() * next_turn_selectors[to].clone(),
                );
                let distance = (to + MAX_CANONICAL_SEATS - from) % MAX_CANONICAL_SEATS;
                let distance = if distance == 0 {
                    MAX_CANONICAL_SEATS
                } else {
                    distance
                };
                for offset in 1..distance {
                    let between = (from + offset) % MAX_CANONICAL_SEATS;
                    eval.add_constraint(
                        pair.clone()
                            * full_post_status[between][CanonicalSeatStatus::Active as usize]
                                .clone(),
                    );
                }
            }
        }
        eval.add_constraint(is_betting.clone() * pre_status.clone() - selected_full_pre_status);
        eval.add_constraint(is_betting.clone() * post_status.clone() - selected_full_post_status);
        for (projected, full) in pre_stack.iter().zip(selected_full_pre_stack.iter()) {
            eval.add_constraint(is_betting.clone() * projected.clone() - full.clone());
        }
        for (projected, full) in post_stack.iter().zip(selected_full_post_stack.iter()) {
            eval.add_constraint(is_betting.clone() * projected.clone() - full.clone());
        }
        for (projected, full) in pre_bet.iter().zip(selected_full_pre_bet.iter()) {
            eval.add_constraint(is_betting.clone() * projected.clone() - full.clone());
        }
        for (projected, full) in post_bet.iter().zip(selected_full_post_bet.iter()) {
            eval.add_constraint(is_betting.clone() * projected.clone() - full.clone());
        }
        for (projected, full) in pre_total.iter().zip(selected_full_pre_total.iter()) {
            eval.add_constraint(is_betting.clone() * projected.clone() - full.clone());
        }
        for (projected, full) in post_total.iter().zip(selected_full_post_total.iter()) {
            eval.add_constraint(is_betting.clone() * projected.clone() - full.clone());
        }
        for (projected, full) in pre_pending.iter().zip(selected_full_pre_pending.iter()) {
            eval.add_constraint(is_betting.clone() * projected.clone() - full.clone());
        }
        for (projected, full) in post_pending.iter().zip(selected_full_post_pending.iter()) {
            eval.add_constraint(is_betting.clone() * projected.clone() - full.clone());
        }
        for (projected, full) in pre_time_bank.iter().zip(selected_full_pre_time.iter()) {
            eval.add_constraint(is_betting.clone() * projected.clone() - full.clone());
        }
        for (projected, full) in post_time_bank.iter().zip(selected_full_post_time.iter()) {
            eval.add_constraint(is_betting.clone() * projected.clone() - full.clone());
        }
        let mut post_stack_sum: E::F = M31::from(0u32).into();
        let mut pre_stack_sum: E::F = M31::from(0u32).into();
        for limb in &post_stack {
            post_stack_sum += limb.clone();
        }
        for limb in &pre_stack {
            pre_stack_sum += limb.clone();
        }
        // The VM transitions an acting player to AllIn exactly when its stack
        // reaches zero.  `chip_action_post_stack_sum` keeps the selector out
        // of the inverse relation, preserving degree two over M31.
        eval.add_constraint(post_all_in.clone() * (post_all_in.clone() - one.clone()));
        eval.add_constraint((active.clone() - chip_action.clone()) * post_all_in.clone());
        eval.add_constraint(
            (active.clone() - chip_action.clone()) * chip_action_post_stack_sum.clone(),
        );
        eval.add_constraint(
            (active.clone() - chip_action.clone()) * chip_action_post_stack_inv.clone(),
        );
        eval.add_constraint(
            chip_action_post_stack_sum.clone() - chip_action.clone() * post_stack_sum,
        );
        eval.add_constraint(post_all_in.clone() * chip_action_post_stack_sum.clone());
        eval.add_constraint(
            chip_action_post_stack_sum.clone() * chip_action_post_stack_inv.clone()
                - (chip_action.clone() - post_all_in.clone()),
        );
        eval.add_constraint(
            chip_action.clone()
                * (post_status.clone() - (two.clone() + two.clone() * post_all_in.clone())),
        );
        // An active player may be selected only while it owns chips.  This
        // mirrors the VM invariant that a stack reaching zero becomes AllIn
        // before the next turn scan.  As above, the scaled sum keeps the
        // inverse relation quadratic.
        eval.add_constraint((active.clone() - is_betting.clone()) * betting_pre_stack_sum.clone());
        eval.add_constraint((active.clone() - is_betting.clone()) * betting_pre_stack_inv.clone());
        eval.add_constraint(betting_pre_stack_sum.clone() - is_betting.clone() * pre_stack_sum);
        eval.add_constraint(
            betting_pre_stack_sum.clone() * betting_pre_stack_inv.clone() - is_betting.clone(),
        );
        for index in 0..4 {
            range16_constraints(
                &mut eval,
                &is_call,
                &call_owed[index],
                &call_owed_bits[index],
            );
            range16_constraints(
                &mut eval,
                &is_call,
                &call_difference[index],
                &call_difference_bits[index],
            );
            range16_constraints(
                &mut eval,
                &is_raise,
                &raise_needed[index],
                &raise_needed_bits[index],
            );
            range16_constraints(
                &mut eval,
                &is_raise,
                &raise_delta[index],
                &raise_delta_bits[index],
            );
            range16_constraints(
                &mut eval,
                &is_raise,
                &raise_stack_difference[index],
                &raise_stack_difference_bits[index],
            );
            range16_constraints(
                &mut eval,
                &is_raise,
                &raise_min_difference[index],
                &raise_min_difference_bits[index],
            );
            range16_constraints(
                &mut eval,
                &active,
                &pre_chip_pool[index],
                &pre_chip_pool_bits[index],
            );
            range16_constraints(
                &mut eval,
                &active,
                &post_chip_pool[index],
                &post_chip_pool_bits[index],
            );
        }
        // Check and Fold do not move chips. A Call amount is a strictly positive
        // delta, proved with an inverse of the sum of its canonical limbs.
        for limb in &amount {
            eval.add_constraint((is_check.clone() + is_fold.clone()) * limb.clone());
        }
        let mut amount_sum: E::F = M31::from(0u32).into();
        for limb in &amount {
            amount_sum += limb.clone();
        }
        eval.add_constraint(
            (is_call.clone() + is_bet.clone()) * (amount_sum * amount_inv.clone() - one.clone()),
        );
        // The native funding selectors are the only transitions that credit
        // TableVault.  Addon credits the next-hand balance; Rebuy credits the
        // live stack.  No VM replay-derived amount or branch is used here.
        let mut funding_amount_sum: E::F = M31::from(0u32).into();
        for limb in &amount {
            funding_amount_sum += limb.clone();
        }
        eval.add_constraint(
            is_funding.clone() * (funding_amount_sum * amount_inv.clone() - one.clone()),
        );
        limb4_add_constraints(
            &mut eval,
            &is_funding,
            &pre_chip_pool,
            &amount,
            &post_chip_pool,
            &funding_chip_pool_carries,
        );
        for carry in &funding_chip_pool_carries {
            eval.add_constraint(
                (active.clone()
                    - is_funding.clone()
                    - is_kick.clone()
                    - is_join.clone()
                    - is_leave.clone())
                    * carry.clone(),
            );
        }
        for (pre, post) in [
            (&pre_phase, &post_phase),
            (&pre_subtag, &post_subtag),
            (&pre_street, &post_street),
            (&pre_turn, &post_turn),
            (&pre_acted_mask, &post_acted_mask),
            (&pre_leave_mask, &post_leave_mask),
            (&pre_status, &post_status),
            (&pre_seat_acted, &post_seat_acted),
        ] {
            eval.add_constraint(is_funding.clone() * (post.clone() - pre.clone()));
        }
        for (pre, post) in [
            (&pre_current, &post_current),
            (&pre_min, &post_min),
            (&pre_pot, &post_pot),
            (&pre_bet, &post_bet),
            (&pre_total, &post_total),
        ] {
            for (left, right) in pre.iter().zip(post.iter()) {
                eval.add_constraint(is_funding.clone() * (right.clone() - left.clone()));
            }
        }
        for (pre, post) in pre_time_bank.iter().zip(post_time_bank.iter()) {
            eval.add_constraint(is_funding.clone() * (post.clone() - pre.clone()));
        }
        limb4_add_constraints(
            &mut eval,
            &is_addon,
            &pre_pending,
            &amount,
            &post_pending,
            &funding_addon_carries,
        );
        for (left, right) in post_stack.iter().zip(pre_stack.iter()) {
            eval.add_constraint(is_addon.clone() * (left.clone() - right.clone()));
        }
        limb4_add_constraints(
            &mut eval,
            &is_rebuy,
            &pre_stack,
            &amount,
            &post_stack,
            &funding_rebuy_carries,
        );
        for (left, right) in post_pending.iter().zip(pre_pending.iter()) {
            eval.add_constraint(is_rebuy.clone() * (left.clone() - right.clone()));
        }
        for carry in &funding_addon_carries {
            eval.add_constraint(
                (active.clone() - is_addon.clone() - is_kick.clone()) * carry.clone(),
            );
        }
        for carry in &funding_rebuy_carries {
            eval.add_constraint(
                (active.clone() - is_rebuy.clone() - is_kick.clone() - is_leave.clone())
                    * carry.clone(),
            );
        }
        // Join locks the buy-in into TableVault and the selected seat stack.
        // Leave performs the inverse refund of stack plus pending addon.
        limb4_add_constraints(
            &mut eval,
            &is_join,
            &pre_chip_pool,
            &amount,
            &post_chip_pool,
            &funding_chip_pool_carries,
        );
        for limb in 0..4 {
            eval.add_constraint(
                is_leave.clone()
                    * (pre_stack[limb].clone() - selected_transition_pre_stack[limb].clone()),
            );
            eval.add_constraint(
                is_leave.clone()
                    * (pre_pending[limb].clone() - selected_transition_pre_pending[limb].clone()),
            );
        }
        limb4_add_constraints(
            &mut eval,
            &is_leave,
            &selected_transition_pre_stack,
            &selected_transition_pre_pending,
            &amount,
            &funding_rebuy_carries,
        );
        limb4_add_constraints(
            &mut eval,
            &is_leave,
            &post_chip_pool,
            &amount,
            &pre_chip_pool,
            &funding_chip_pool_carries,
        );
        // Non-cascading KickPlayer is the VM's explicit refund path:
        // `amount = stack + pending_addon`, `pot += current bet`, and
        // `chip_pool -= amount`.  The carry witnesses above are reused without
        // widening the committed trace.
        for limb in 0..4 {
            eval.add_constraint(
                is_kick.clone()
                    * (pre_stack[limb].clone() - selected_transition_pre_stack[limb].clone()),
            );
            eval.add_constraint(
                is_kick.clone()
                    * (pre_pending[limb].clone() - selected_transition_pre_pending[limb].clone()),
            );
            eval.add_constraint(
                is_kick.clone()
                    * (pre_bet[limb].clone() - selected_transition_pre_bet[limb].clone()),
            );
        }
        limb4_add_constraints(
            &mut eval,
            &is_kick,
            &selected_transition_pre_stack,
            &selected_transition_pre_pending,
            &amount,
            &funding_rebuy_carries,
        );
        limb4_add_constraints(
            &mut eval,
            &is_kick,
            &post_chip_pool,
            &amount,
            &pre_chip_pool,
            &funding_chip_pool_carries,
        );
        limb4_add_constraints(
            &mut eval,
            &is_kick,
            &pre_pot,
            &selected_transition_pre_bet,
            &post_pot,
            &funding_addon_carries,
        );
        for (pre, post) in [
            (&pre_phase, &post_phase),
            (&pre_subtag, &post_subtag),
            (&pre_street, &post_street),
            (&pre_turn, &post_turn),
        ] {
            eval.add_constraint(is_kick.clone() * (post.clone() - pre.clone()));
        }
        for (left, right) in pre_deadline_image.iter().zip(post_deadline_image.iter()) {
            eval.add_constraint(is_kick.clone() * (right.clone() - left.clone()));
        }
        eval.add_constraint(
            active.clone() * call_all_in.clone() * (call_all_in.clone() - one.clone()),
        );
        eval.add_constraint((active.clone() - is_call.clone()) * call_all_in.clone());
        let mut call_difference_sum: E::F = M31::from(0u32).into();
        for limb in &call_difference {
            call_difference_sum += limb.clone();
        }
        eval.add_constraint(
            call_all_in.clone() * (call_difference_sum * call_difference_inv.clone() - one.clone()),
        );
        limb4_add_constraints(
            &mut eval,
            &is_call,
            &pre_bet,
            &call_owed,
            &pre_current,
            &call_owed_carries,
        );
        let ordinary_call = is_call.clone() - call_all_in.clone();
        limb4_add_constraints(
            &mut eval,
            &ordinary_call,
            &call_owed,
            &call_difference,
            &pre_stack,
            &call_excess_carries,
        );
        let short_call = call_all_in.clone();
        limb4_add_constraints(
            &mut eval,
            &short_call,
            &pre_stack,
            &call_difference,
            &call_owed,
            &call_shortfall_carries,
        );
        for index in 0..4 {
            eval.add_constraint(
                is_call.clone() * (amount[index].clone() - call_owed[index].clone())
                    + call_all_in.clone() * (call_owed[index].clone() - pre_stack[index].clone()),
            );
        }
        // Raise uses an absolute target (`amount`), unlike Call/Bet deltas.
        // The three canonical subtractions prove target > seat bet, target >
        // current bet, and needed <= stack. No host comparison result selects
        // a branch here.
        for value in [&raise_all_in, &raise_meets_min] {
            eval.add_constraint(active.clone() * value.clone() * (value.clone() - one.clone()));
            eval.add_constraint((active.clone() - is_raise.clone()) * value.clone());
        }
        // All Raise-only auxiliary columns must be zero on every other active
        // transition.  Besides making the tagged trace canonical, this closes
        // an otherwise unconstrained witness surface on Call/Bet/Fold/Check
        // rows.  These values are private advice, but an AIR must never leave
        // advice free merely because a selector is false.
        let non_raise = active.clone() - is_raise.clone();
        for value in [
            &raise_needed,
            &raise_delta,
            &raise_stack_difference,
            &raise_min_difference,
        ] {
            for limb in value {
                eval.add_constraint(non_raise.clone() * limb.clone());
            }
        }
        for value in [
            &raise_needed_inv,
            &raise_delta_inv,
            &raise_stack_difference_inv,
        ] {
            eval.add_constraint(non_raise.clone() * value.clone());
        }
        for carry in raise_needed_carries
            .iter()
            .chain(raise_delta_carries.iter())
            .chain(raise_stack_carries.iter())
            .chain(raise_total_carries.iter())
            .chain(raise_pot_carries.iter())
        {
            eval.add_constraint(non_raise.clone() * carry.clone());
        }
        for bits in raise_needed_bits
            .iter()
            .chain(raise_delta_bits.iter())
            .chain(raise_stack_difference_bits.iter())
            .chain(raise_min_difference_bits.iter())
        {
            for bit in bits {
                eval.add_constraint(non_raise.clone() * bit.clone());
            }
        }
        let mut raise_needed_sum: E::F = M31::from(0u32).into();
        let mut raise_delta_sum: E::F = M31::from(0u32).into();
        let mut raise_stack_difference_sum: E::F = M31::from(0u32).into();
        for index in 0..4 {
            raise_needed_sum += raise_needed[index].clone();
            raise_delta_sum += raise_delta[index].clone();
            raise_stack_difference_sum += raise_stack_difference[index].clone();
        }
        eval.add_constraint(
            is_raise.clone() * (raise_needed_sum.clone() * raise_needed_inv.clone() - one.clone()),
        );
        eval.add_constraint(
            is_raise.clone() * (raise_delta_sum.clone() * raise_delta_inv.clone() - one.clone()),
        );
        eval.add_constraint(
            is_raise.clone() * raise_all_in.clone() * raise_stack_difference_sum.clone(),
        );
        eval.add_constraint(
            is_raise.clone()
                * (raise_stack_difference_sum.clone() * raise_stack_difference_inv.clone()
                    - (one.clone() - raise_all_in.clone())),
        );
        // A sub-minimum raise is valid only when it consumes the entire stack.
        eval.add_constraint(
            is_raise.clone()
                * (one.clone() - raise_meets_min.clone())
                * (one.clone() - raise_all_in.clone()),
        );
        limb4_add_constraints(
            &mut eval,
            &is_raise,
            &pre_bet,
            &raise_needed,
            &amount,
            &raise_needed_carries,
        );
        limb4_add_constraints(
            &mut eval,
            &is_raise,
            &pre_current,
            &raise_delta,
            &amount,
            &raise_delta_carries,
        );
        limb4_add_constraints(
            &mut eval,
            &is_raise,
            &raise_needed,
            &raise_stack_difference,
            &pre_stack,
            &raise_stack_carries,
        );
        limb4_add_constraints(
            &mut eval,
            &is_raise,
            &pre_total,
            &raise_needed,
            &post_total,
            &raise_total_carries,
        );
        for index in 0..4 {
            eval.add_constraint(
                is_raise.clone() * (post_current[index].clone() - amount[index].clone()),
            );
            eval.add_constraint(
                is_raise.clone() * (post_bet[index].clone() - amount[index].clone()),
            );
            eval.add_constraint(
                is_raise.clone()
                    * (post_stack[index].clone() - raise_stack_difference[index].clone()),
            );
            eval.add_constraint(
                is_raise.clone() * (post_pending[index].clone() - pre_pending[index].clone()),
            );
            eval.add_constraint(
                is_raise.clone() * (post_pot[index].clone() - pre_pot[index].clone()),
            );
            eval.add_constraint(
                is_raise.clone()
                    * (raise_meets_min.clone()
                        * (pre_min[index].clone() + raise_min_difference[index].clone()
                            - raise_delta[index].clone())
                        + (one.clone() - raise_meets_min.clone())
                            * (raise_delta[index].clone() + raise_min_difference[index].clone()
                                - pre_min[index].clone())),
            );
            eval.add_constraint(
                is_raise.clone()
                    * (raise_meets_min.clone()
                        * (post_min[index].clone() - raise_delta[index].clone())
                        + (one.clone() - raise_meets_min.clone())
                            * (post_min[index].clone() - pre_min[index].clone())),
            );
        }
        for carry in &raise_pot_carries {
            eval.add_constraint(is_raise.clone() * carry.clone());
        }
        for (left, right) in pre_bet.iter().zip(pre_current.iter()) {
            eval.add_constraint(is_check.clone() * (left.clone() - right.clone()));
        }
        for (post, pre) in [
            (&post_current, &pre_current),
            (&post_min, &pre_min),
            (&post_pot, &pre_pot),
            (&post_stack, &pre_stack),
            (&post_bet, &pre_bet),
            (&post_total, &pre_total),
            (&post_pending, &pre_pending),
        ] {
            for (left, right) in post.iter().zip(pre.iter()) {
                eval.add_constraint(is_check.clone() * (left.clone() - right.clone()));
            }
        }
        // Fold and FoldWithProof leave the monetary image unchanged. The
        // latter changes only the encrypted deck lineage, not chips or the
        // selected participant's identity material. A Call keeps the round
        // target/minimum and collected pot unchanged: its wager remains in
        // the seat until the VM's round-advance collection step.
        for (post, pre) in [
            (&post_current, &pre_current),
            (&post_min, &pre_min),
            (&post_pot, &pre_pot),
            (&post_stack, &pre_stack),
            (&post_bet, &pre_bet),
            (&post_total, &pre_total),
            (&post_pending, &pre_pending),
        ] {
            for (left, right) in post.iter().zip(pre.iter()) {
                eval.add_constraint(is_fold_like.clone() * (left.clone() - right.clone()));
            }
        }
        for (post, pre) in post_time_bank.iter().zip(pre_time_bank.iter()) {
            eval.add_constraint(is_fold_like.clone() * (post.clone() - pre.clone()));
        }
        for (post, pre) in [(&post_current, &pre_current), (&post_min, &pre_min)] {
            for (left, right) in post.iter().zip(pre.iter()) {
                eval.add_constraint(is_call.clone() * (left.clone() - right.clone()));
            }
        }
        for (left, right) in post_pot.iter().zip(pre_pot.iter()) {
            eval.add_constraint(is_call.clone() * (left.clone() - right.clone()));
        }
        limb4_add_constraints(
            &mut eval,
            &is_call,
            &post_stack,
            &amount,
            &pre_stack,
            &stack_carries,
        );
        limb4_add_constraints(
            &mut eval,
            &is_call,
            &pre_bet,
            &amount,
            &post_bet,
            &bet_carries,
        );
        limb4_add_constraints(
            &mut eval,
            &is_call,
            &pre_total,
            &amount,
            &post_total,
            &total_carries,
        );
        for carry in &pot_carries {
            eval.add_constraint((is_call.clone() + is_bet.clone()) * carry.clone());
        }
        let non_delta_wager = active.clone() - is_call.clone() - is_bet.clone();
        for carry in stack_carries
            .iter()
            .chain(bet_carries.iter())
            .chain(total_carries.iter())
            .chain(pot_carries.iter())
        {
            eval.add_constraint(non_delta_wager.clone() * carry.clone());
        }
        // An unopened-round Bet commits exactly `amount` chips.  This is kept
        // separate from Raise, whose action amount is an absolute target bet.
        for (left, right) in pre_bet.iter().zip(pre_current.iter()) {
            eval.add_constraint(is_bet.clone() * (left.clone() - right.clone()));
        }
        for (left, right) in post_current.iter().zip(post_bet.iter()) {
            eval.add_constraint(is_bet.clone() * (left.clone() - right.clone()));
        }
        for (left, right) in post_min.iter().zip(amount.iter()) {
            eval.add_constraint(is_bet.clone() * (left.clone() - right.clone()));
        }
        limb4_add_constraints(
            &mut eval,
            &is_bet,
            &post_stack,
            &amount,
            &pre_stack,
            &stack_carries,
        );
        limb4_add_constraints(
            &mut eval,
            &is_bet,
            &pre_bet,
            &amount,
            &post_bet,
            &bet_carries,
        );
        limb4_add_constraints(
            &mut eval,
            &is_bet,
            &pre_total,
            &amount,
            &post_total,
            &total_carries,
        );
        for (left, right) in post_pot.iter().zip(pre_pot.iter()) {
            eval.add_constraint(is_bet.clone() * (left.clone() - right.clone()));
        }
        let inactive = one.clone() - active.clone();
        for value in [
            &pre_phase,
            &post_phase,
            &pre_subtag,
            &post_subtag,
            &pre_street,
            &post_street,
            &pre_turn,
            &post_turn,
            &pre_acted_mask,
            &post_acted_mask,
            &pre_leave_mask,
            &post_leave_mask,
            &pre_status,
            &post_status,
            &pre_seat_acted,
            &post_seat_acted,
        ] {
            eval.add_constraint(inactive.clone() * value.clone());
        }
        for value in [
            &pre_current,
            &post_current,
            &pre_min,
            &post_min,
            &pre_pot,
            &post_pot,
            &pre_stack,
            &post_stack,
            &pre_bet,
            &post_bet,
            &pre_total,
            &post_total,
            &pre_pending,
            &post_pending,
            &call_owed,
            &call_difference,
            &raise_needed,
            &raise_delta,
            &raise_stack_difference,
            &raise_min_difference,
        ] {
            for limb in value {
                eval.add_constraint(inactive.clone() * limb.clone());
            }
        }
        for limb in pre_time_bank.iter().chain(post_time_bank.iter()) {
            eval.add_constraint(inactive.clone() * limb.clone());
        }
        eval.add_constraint(inactive.clone() * turn_delta_inv.clone());
        eval.add_constraint(inactive.clone() * amount_inv.clone());
        eval.add_constraint(inactive.clone() * call_all_in.clone());
        eval.add_constraint(inactive.clone() * call_difference_inv.clone());
        eval.add_constraint(inactive.clone() * raise_all_in.clone());
        eval.add_constraint(inactive.clone() * raise_meets_min.clone());
        eval.add_constraint(inactive.clone() * raise_needed_inv.clone());
        eval.add_constraint(inactive.clone() * raise_delta_inv.clone());
        eval.add_constraint(inactive.clone() * raise_stack_difference_inv.clone());
        eval.add_constraint(inactive.clone() * post_all_in.clone());
        eval.add_constraint(inactive.clone() * chip_action_post_stack_sum.clone());
        eval.add_constraint(inactive.clone() * chip_action_post_stack_inv.clone());
        eval.add_constraint(inactive.clone() * betting_pre_stack_sum.clone());
        eval.add_constraint(inactive.clone() * betting_pre_stack_inv.clone());
        for value in acted_seat_selectors
            .iter()
            .chain(pre_acted_bits.iter())
            .chain(post_acted_bits.iter())
            .chain(acted_deltas.iter())
            .chain(pre_leave_mask_bits.iter())
            .chain(post_leave_mask_bits.iter())
        {
            eval.add_constraint(inactive.clone() * value.clone());
        }
        for carry in stack_carries
            .iter()
            .chain(bet_carries.iter())
            .chain(total_carries.iter())
            .chain(pot_carries.iter())
            .chain(call_owed_carries.iter())
            .chain(call_excess_carries.iter())
            .chain(call_shortfall_carries.iter())
            .chain(raise_needed_carries.iter())
            .chain(raise_delta_carries.iter())
            .chain(raise_stack_carries.iter())
            .chain(raise_total_carries.iter())
            .chain(raise_pot_carries.iter())
            .chain(funding_chip_pool_carries.iter())
            .chain(funding_addon_carries.iter())
            .chain(funding_rebuy_carries.iter())
            .chain(round_collect_carries.iter())
        {
            eval.add_constraint(inactive.clone() * carry.clone());
        }
        for bits in &round_collect_carry_bits {
            for bit in bits {
                eval.add_constraint(inactive.clone() * bit.clone());
            }
        }
        for bits in round_collect_bet_bits.iter().flatten() {
            for bit in bits {
                eval.add_constraint(inactive.clone() * bit.clone());
            }
        }
        for bits in pre_chip_pool_bits.iter().chain(post_chip_pool_bits.iter()) {
            for bit in bits {
                eval.add_constraint(inactive.clone() * bit.clone());
            }
        }
        for index in 0..MAX_CANONICAL_SEATS {
            for value in full_pre_status[index]
                .iter()
                .chain(full_post_status[index].iter())
                .chain(full_pre_stack[index].iter())
                .chain(full_post_stack[index].iter())
                .chain(full_pre_bet[index].iter())
                .chain(full_post_bet[index].iter())
                .chain(full_pre_total[index].iter())
                .chain(full_post_total[index].iter())
                .chain(full_pre_pending[index].iter())
                .chain(full_post_pending[index].iter())
                .chain(full_pre_time_bank[index].iter())
                .chain(full_post_time_bank[index].iter())
            {
                eval.add_constraint(inactive.clone() * value.clone());
            }
            eval.add_constraint(inactive.clone() * raise_actor[index].clone());
            eval.add_constraint(inactive.clone() * raise_active[index].clone());
            eval.add_constraint(inactive.clone() * next_turn_selectors[index].clone());
            eval.add_constraint(inactive.clone() * funding_seat_selectors[index].clone());
            eval.add_constraint(inactive.clone() * transition_seat_selectors[index].clone());
            eval.add_constraint(inactive.clone() * round_complete_active[index].clone());
            for pair in &next_turn_pairs[index] {
                eval.add_constraint(inactive.clone() * pair.clone());
            }
        }
        for value in [
            round_pre_cards_dealt,
            round_post_cards_dealt,
            round_pre_board_len,
            round_post_board_len,
            round_pre_second_board_len,
            round_post_second_board_len,
            round_run_it_twice,
            round_reveal_purpose,
            round_assignment_count,
        ] {
            eval.add_constraint(inactive.clone() * value);
        }
        for assignment in &round_assignments {
            for value in assignment {
                eval.add_constraint(inactive.clone() * value.clone());
            }
        }
        for selector in &round_schedule_selectors {
            eval.add_constraint(inactive.clone() * selector.clone());
        }
        for (pre, post) in [
            (&pre_state_root, &post_state_root),
            (&pre_lifecycle_root, &post_lifecycle_root),
            (&pre_overlay_root, &post_overlay_root),
            (&pre_settlement_commitment, &post_settlement_commitment),
            (&pre_custody_commitment, &post_custody_commitment),
        ] {
            for value in pre.iter().chain(post.iter()) {
                eval.add_constraint(inactive.clone() * value.clone());
            }
        }
        for value in pre_rules_commitment
            .iter()
            .chain(post_rules_commitment.iter())
            .chain(pre_governance_commitment.iter())
            .chain(post_governance_commitment.iter())
        {
            eval.add_constraint(inactive.clone() * value.clone());
        }
        for commitment in pre_opaque_commitments
            .iter()
            .chain(post_opaque_commitments.iter())
        {
            for limb in commitment {
                eval.add_constraint(inactive.clone() * limb.clone());
            }
        }
        for value in pre_state_metadata.iter().chain(post_state_metadata.iter()) {
            eval.add_constraint(inactive.clone() * value.clone());
        }
        for commitment in pre_seat_commitments
            .iter()
            .chain(post_seat_commitments.iter())
            .flat_map(|seat| seat.iter())
        {
            for limb in commitment {
                eval.add_constraint(inactive.clone() * limb.clone());
            }
        }
        for limb in pre_deadline_image.iter().chain(post_deadline_image.iter()) {
            eval.add_constraint(inactive.clone() * limb.clone());
        }
        eval.add_constraint(inactive.clone() * post_deadline_inv.clone());
        eval.add_constraint(inactive.clone() * start_active_product.clone());
        eval.add_constraint(inactive.clone() * start_active_count_inv.clone());
        for selector in start_button_selectors
            .iter()
            .chain(start_pre_button_selectors.iter())
        {
            eval.add_constraint(inactive.clone() * selector.clone());
        }
        for value in next_pre_image
            .iter()
            .chain(next_pre_state_root.iter())
            .chain(next_pre_lifecycle_root.iter())
            .chain(next_pre_overlay_root.iter())
            .chain(next_pre_settlement_commitment.iter())
            .chain(next_pre_custody_commitment.iter())
        {
            eval.add_constraint(inactive.clone() * value.clone());
        }
        for limb in advance_deadline_difference
            .iter()
            .chain(deadline_height.iter())
        {
            eval.add_constraint(inactive.clone() * limb.clone());
        }
        for carry in &advance_deadline_carries {
            eval.add_constraint(inactive.clone() * carry.clone());
        }
        for bits in advance_deadline_height_bits
            .iter()
            .chain(advance_deadline_pre_bits.iter())
            .chain(advance_deadline_difference_bits.iter())
        {
            for bit in bits {
                eval.add_constraint(inactive.clone() * bit.clone());
            }
        }
        eval.add_constraint(inactive.clone() * advance_deadline_pre_inv.clone());
        eval.add_constraint(inactive.clone() * advance_deadline_phase_inv.clone());
        eval.add_constraint(inactive.clone() * advance_deadline_time_bank_all.clone());
        for value in advance_deadline_time_bank_slack
            .iter()
            .chain(advance_deadline_time_bank_excess.iter())
        {
            eval.add_constraint(inactive.clone() * value.clone());
        }
        for bits in &advance_deadline_time_bank_range_bits {
            for limb_bits in bits {
                for bit in limb_bits {
                    eval.add_constraint(inactive.clone() * bit.clone());
                }
            }
        }
        for carry in advance_deadline_time_bank_carries
            .iter()
            .chain(advance_deadline_extension_carries.iter())
        {
            eval.add_constraint(inactive.clone() * carry.clone());
        }
        let non_advance_deadline = active.clone() * (one.clone() - is_advance_deadline.clone());
        eval.add_constraint(non_advance_deadline.clone() * advance_deadline_time_bank_all.clone());
        for value in advance_deadline_time_bank_slack
            .iter()
            .chain(advance_deadline_time_bank_excess.iter())
        {
            eval.add_constraint(non_advance_deadline.clone() * value.clone());
        }
        for bits in &advance_deadline_time_bank_range_bits {
            for limb_bits in bits {
                for bit in limb_bits {
                    eval.add_constraint(non_advance_deadline.clone() * bit.clone());
                }
            }
        }
        for carry in advance_deadline_time_bank_carries
            .iter()
            .chain(advance_deadline_extension_carries.iter())
        {
            eval.add_constraint(non_advance_deadline.clone() * carry.clone());
        }
        eval.add_constraint(inactive.clone() * no_next_turn.clone());
        let base: E::F = M31::from(65536u32).into();
        eval.add_constraint(is_start.clone() * pre_phase.clone());
        eval.add_constraint(is_start.clone() * (post_phase.clone() - M31::from(1u32).into()));
        eval.add_constraint(is_start.clone() * (post_turn.clone() - M31::from(15u32).into()));
        let mut start_pre_button_sum: E::F = M31::from(0u32).into();
        let mut start_pre_button_value: E::F = M31::from(0u32).into();
        for (index, selector) in start_pre_button_selectors.iter().enumerate() {
            eval.add_constraint(
                active.clone() * selector.clone() * (selector.clone() - one.clone()),
            );
            let index_value: E::F = M31::from(index as u32).into();
            start_pre_button_sum += selector.clone();
            start_pre_button_value += selector.clone() * index_value;
        }
        eval.add_constraint(active.clone() * (start_pre_button_sum.clone() - one.clone()));
        eval.add_constraint(
            active.clone() * (start_pre_button_value.clone() - pre_state_metadata[1].clone()),
        );
        let mut start_button_sum: E::F = M31::from(0u32).into();
        let mut start_button_value: E::F = M31::from(0u32).into();
        for (index, selector) in start_button_selectors.iter().enumerate() {
            eval.add_constraint(
                active.clone() * selector.clone() * (selector.clone() - one.clone()),
            );
            eval.add_constraint((active.clone() - is_start.clone()) * selector.clone());
            let occupied = full_pre_status[index][CanonicalSeatStatus::Waiting as usize].clone()
                + full_pre_status[index][CanonicalSeatStatus::Active as usize].clone()
                + full_pre_status[index][CanonicalSeatStatus::Folded as usize].clone()
                + full_pre_status[index][CanonicalSeatStatus::AllIn as usize].clone();
            eval.add_constraint(is_start.clone() * selector.clone() * (occupied - one.clone()));
            let index_value: E::F = M31::from(index as u32).into();
            start_button_sum += selector.clone();
            start_button_value += selector.clone() * index_value;
        }
        eval.add_constraint(start_button_sum.clone() - is_start.clone());
        eval.add_constraint(
            is_start.clone() * (start_button_value.clone() - post_state_metadata[1].clone()),
        );
        for from in 0..MAX_CANONICAL_SEATS {
            for to in 0..MAX_CANONICAL_SEATS {
                let pair =
                    start_pre_button_selectors[from].clone() * start_button_selectors[to].clone();
                let distance = (to + MAX_CANONICAL_SEATS - from) % MAX_CANONICAL_SEATS;
                let distance = if distance == 0 {
                    MAX_CANONICAL_SEATS
                } else {
                    distance
                };
                for offset in 1..distance {
                    let between = (from + offset) % MAX_CANONICAL_SEATS;
                    let occupied = full_pre_status[between][CanonicalSeatStatus::Waiting as usize]
                        .clone()
                        + full_pre_status[between][CanonicalSeatStatus::Active as usize].clone()
                        + full_pre_status[between][CanonicalSeatStatus::Folded as usize].clone()
                        + full_pre_status[between][CanonicalSeatStatus::AllIn as usize].clone();
                    eval.add_constraint(pair.clone() * occupied);
                }
            }
        }
        let mut post_deadline_sum: E::F = M31::from(0u32).into();
        for limb in &post_deadline_image {
            post_deadline_sum += limb.clone();
        }
        // Starting a hand must arm a real deadline.  The inverse makes this a
        // field-native non-zero statement without a host comparison branch.
        eval.add_constraint(
            is_start.clone() * (post_deadline_sum * post_deadline_inv.clone() - one.clone()),
        );
        eval.add_constraint((active.clone() - is_start.clone()) * post_deadline_inv.clone());
        let non_start = active.clone() * (one.clone() - is_start.clone());
        eval.add_constraint(
            non_start.clone()
                * (pre_seq[0].clone() + one.clone()
                    - post_seq[0].clone()
                    - base.clone() * seq_carry.clone()),
        );
        eval.add_constraint(
            non_start.clone() * (pre_seq[1].clone() + seq_carry.clone() - post_seq[1].clone()),
        );
        let table_scope = [
            eval.get_preprocessed_column(preprocessed_ids()[3].clone()),
            eval.get_preprocessed_column(preprocessed_ids()[4].clone()),
            eval.get_preprocessed_column(preprocessed_ids()[5].clone()),
            eval.get_preprocessed_column(preprocessed_ids()[6].clone()),
        ];
        add_limb_eq(&mut eval, &active, &table, &table_scope);
        eval.add_constraint(
            active.clone()
                * (one.clone() - is_start.clone())
                * (pre_hand[0].clone() - post_hand[0].clone()),
        );
        eval.add_constraint(
            active.clone()
                * (one.clone() - is_start.clone())
                * (pre_hand[1].clone() - post_hand[1].clone()),
        );
        eval.add_constraint(
            active.clone() * is_start.clone() * (post_seq[0].clone() + post_seq[1].clone()),
        );
        eval.add_constraint(
            active.clone()
                * is_start.clone()
                * (post_hand[0].clone() - pre_hand[0].clone() - one.clone()),
        );
        eval.add_constraint(
            active.clone() * is_start.clone() * (post_hand[1].clone() - pre_hand[1].clone()),
        );
        let mut start_active_count: E::F = M31::from(0u32).into();
        for index in 0..MAX_CANONICAL_SEATS {
            start_active_count += full_pre_status[index][CanonicalSeatStatus::Active as usize]
                .clone()
                + full_pre_status[index][CanonicalSeatStatus::Folded as usize].clone()
                + full_pre_status[index][CanonicalSeatStatus::AllIn as usize].clone();
        }
        eval.add_constraint(
            is_start.clone()
                * (start_active_product.clone()
                    - start_active_count.clone() * (start_active_count.clone() - one.clone())),
        );
        eval.add_constraint(
            is_start.clone()
                * (start_active_product.clone() * start_active_count_inv.clone() - one.clone()),
        );
        eval.add_constraint((active.clone() - is_start.clone()) * start_active_count_inv.clone());
        eval.add_constraint((active.clone() - is_start.clone()) * start_active_product.clone());
        eval.add_constraint(is_start.clone() * pre_subtag.clone());
        eval.add_constraint(is_start.clone() * (post_subtag.clone() - one.clone()));
        eval.add_constraint(is_start.clone() * post_street.clone());
        for bit in pre_acted_bits.iter().chain(post_acted_bits.iter()) {
            eval.add_constraint(is_start.clone() * bit.clone());
        }
        for commitment in [0usize, 2, 3, 4] {
            for limb in 0..16 {
                eval.add_constraint(
                    is_start.clone()
                        * (post_opaque_commitments[commitment][limb].clone()
                            - pre_opaque_commitments[commitment][limb].clone()),
                );
            }
        }
        let is_permissionless = kinds[CanonicalTransitionKind::AdvanceDeadline as usize].clone();
        let mut actor_nonzero: E::F = M31::from(0u32).into();
        for limb in &actor {
            actor_nonzero += limb.clone();
        }
        eval.add_constraint(is_permissionless * actor_nonzero);
        eval.add_constraint((one.clone() - active.clone()) * (kind_sum + seat + flag));
        let first = eval.get_preprocessed_column(preprocessed_ids()[1].clone());
        let last = eval.get_preprocessed_column(preprocessed_ids()[2].clone());
        for value in next_pre_image
            .iter()
            .chain(next_pre_state_root.iter())
            .chain(next_pre_lifecycle_root.iter())
            .chain(next_pre_overlay_root.iter())
            .chain(next_pre_settlement_commitment.iter())
            .chain(next_pre_custody_commitment.iter())
        {
            eval.add_constraint(active.clone() * last.clone() * value.clone());
        }
        add_limb_eq(
            &mut eval,
            &(active.clone() * (one.clone() - last.clone())),
            &post_image,
            &next_pre_image,
        );
        let scope_pre: Vec<_> = (0..16)
            .map(|i| eval.get_preprocessed_column(preprocessed_ids()[7 + i].clone()))
            .collect();
        let scope_post: Vec<_> = (0..16)
            .map(|i| eval.get_preprocessed_column(preprocessed_ids()[23 + i].clone()))
            .collect();
        add_limb_eq(
            &mut eval,
            &(active.clone() * first.clone()),
            &pre_image,
            &scope_pre,
        );
        add_limb_eq(
            &mut eval,
            &(active.clone() * last.clone()),
            &post_image,
            &scope_post,
        );
        // Each committed root domain follows the same first/last public scope
        // and adjacent-row continuity rule as the canonical state image.
        // This is deliberately independent of a future Blake2b AIR: it makes
        // the exact root bytes verifier-visible today, rather than leaving
        // them as an unscoped host witness.
        let root_domains = [
            (&pre_state_root, &post_state_root, &next_pre_state_root),
            (
                &pre_lifecycle_root,
                &post_lifecycle_root,
                &next_pre_lifecycle_root,
            ),
            (
                &pre_overlay_root,
                &post_overlay_root,
                &next_pre_overlay_root,
            ),
            (
                &pre_settlement_commitment,
                &post_settlement_commitment,
                &next_pre_settlement_commitment,
            ),
            (
                &pre_custody_commitment,
                &post_custody_commitment,
                &next_pre_custody_commitment,
            ),
        ];
        let root_ids = preprocessed_ids();
        for (domain, (pre, post, next_pre)) in root_domains.into_iter().enumerate() {
            add_limb_eq(
                &mut eval,
                &(active.clone() * (one.clone() - last.clone())),
                post,
                next_pre,
            );
            let scope_pre: Vec<_> = (0..16)
                .map(|limb| {
                    eval.get_preprocessed_column(
                        root_ids[ROOT_SCOPE_OFFSET + (2 * domain) * 16 + limb].clone(),
                    )
                })
                .collect();
            let scope_post: Vec<_> = (0..16)
                .map(|limb| {
                    eval.get_preprocessed_column(
                        root_ids[ROOT_SCOPE_OFFSET + (2 * domain + 1) * 16 + limb].clone(),
                    )
                })
                .collect();
            add_limb_eq(
                &mut eval,
                &(active.clone() * first.clone()),
                pre,
                &scope_pre,
            );
            add_limb_eq(
                &mut eval,
                &(active.clone() * last.clone()),
                post,
                &scope_post,
            );
        }

        // Bind the endpoint values already materialized by this AIR to the
        // corresponding fixed positions in the full Borsh state-image byte
        // statement.  The entire byte string is Fiat--Shamir-bound in
        // `mix_scope`; this 841-limb projection is the bridge preventing the
        // host from pairing a different table/seat/balance/root image with a
        // valid canonical trace.
        let mut pre_state_binding = Vec::with_capacity(STATE_IMAGE_PROJECTION_LIMBS);
        let mut post_state_binding = Vec::with_capacity(STATE_IMAGE_PROJECTION_LIMBS);
        pre_state_binding.extend(pre_state_metadata.iter().cloned());
        post_state_binding.extend(post_state_metadata.iter().cloned());
        pre_state_binding.extend(table.iter().cloned());
        post_state_binding.extend(table.iter().cloned());
        pre_state_binding.extend(pre_hand.iter().cloned());
        post_state_binding.extend(post_hand.iter().cloned());
        pre_state_binding.extend(pre_seq.iter().cloned());
        post_state_binding.extend(post_seq.iter().cloned());
        for (pre, post) in [
            (&pre_phase, &post_phase),
            (&pre_subtag, &post_subtag),
            (&pre_street, &post_street),
            (&pre_turn, &post_turn),
        ] {
            pre_state_binding.push(pre.clone());
            post_state_binding.push(post.clone());
        }
        for (pre, post) in [
            (&pre_deadline_image, &post_deadline_image),
            (&pre_current, &post_current),
            (&pre_min, &post_min),
            (&pre_chip_pool, &post_chip_pool),
            (&pre_pot, &post_pot),
        ] {
            pre_state_binding.extend(pre.iter().cloned());
            post_state_binding.extend(post.iter().cloned());
        }
        pre_state_binding.push(pre_acted_mask.clone());
        post_state_binding.push(post_acted_mask.clone());
        pre_state_binding.push(pre_leave_mask.clone());
        post_state_binding.push(post_leave_mask.clone());
        for (pre, post) in [
            (&pre_rules_commitment, &post_rules_commitment),
            (&pre_governance_commitment, &post_governance_commitment),
            (&pre_state_root, &post_state_root),
            (&pre_lifecycle_root, &post_lifecycle_root),
            (&pre_overlay_root, &post_overlay_root),
            (&pre_settlement_commitment, &post_settlement_commitment),
            (&pre_custody_commitment, &post_custody_commitment),
        ] {
            pre_state_binding.extend(pre.iter().cloned());
            post_state_binding.extend(post.iter().cloned());
        }
        for commitment in 0..OPAQUE_COMMITMENT_COUNT {
            pre_state_binding.extend(pre_opaque_commitments[commitment].iter().cloned());
            post_state_binding.extend(post_opaque_commitments[commitment].iter().cloned());
        }
        for seat_index in 0..MAX_CANONICAL_SEATS {
            let mut pre_status_value: E::F = M31::from(0u32).into();
            let mut post_status_value: E::F = M31::from(0u32).into();
            for status in 0..SEAT_STATUS_COUNT {
                let weight: E::F = M31::from(status as u32).into();
                pre_status_value += full_pre_status[seat_index][status].clone() * weight.clone();
                post_status_value += full_post_status[seat_index][status].clone() * weight;
            }
            pre_state_binding.push(pre_status_value);
            post_state_binding.push(post_status_value);
            pre_state_binding.push(pre_acted_bits[seat_index].clone());
            post_state_binding.push(post_acted_bits[seat_index].clone());
            for (pre, post) in [
                (&full_pre_stack[seat_index], &full_post_stack[seat_index]),
                (&full_pre_bet[seat_index], &full_post_bet[seat_index]),
                (&full_pre_total[seat_index], &full_post_total[seat_index]),
                (
                    &full_pre_pending[seat_index],
                    &full_post_pending[seat_index],
                ),
            ] {
                pre_state_binding.extend(pre.iter().cloned());
                post_state_binding.extend(post.iter().cloned());
            }
            pre_state_binding.extend(full_pre_time_bank[seat_index].iter().cloned());
            post_state_binding.extend(full_post_time_bank[seat_index].iter().cloned());
            for commitment in 0..SEAT_COMMITMENT_FIELD_COUNT {
                pre_state_binding
                    .extend(pre_seat_commitments[seat_index][commitment].iter().cloned());
                post_state_binding.extend(
                    post_seat_commitments[seat_index][commitment]
                        .iter()
                        .cloned(),
                );
            }
        }
        debug_assert_eq!(pre_state_binding.len(), STATE_IMAGE_PROJECTION_LIMBS);
        debug_assert_eq!(post_state_binding.len(), STATE_IMAGE_PROJECTION_LIMBS);
        let image_scope_ids = preprocessed_ids();
        let scope_pre_state: Vec<_> = (0..STATE_IMAGE_PROJECTION_LIMBS)
            .map(|limb| {
                eval.get_preprocessed_column(
                    image_scope_ids[STATE_IMAGE_SCOPE_OFFSET + limb].clone(),
                )
            })
            .collect();
        let scope_post_state: Vec<_> = (0..STATE_IMAGE_PROJECTION_LIMBS)
            .map(|limb| {
                eval.get_preprocessed_column(
                    image_scope_ids[STATE_IMAGE_SCOPE_OFFSET + STATE_IMAGE_PROJECTION_LIMBS + limb]
                        .clone(),
                )
            })
            .collect();
        add_limb_eq(
            &mut eval,
            &(active.clone() * first.clone()),
            &pre_state_binding,
            &scope_pre_state,
        );
        add_limb_eq(
            &mut eval,
            &(active.clone() * last.clone()),
            &post_state_binding,
            &scope_post_state,
        );
        eval
    }
}

pub fn prove_canonical_tagged_batch(
    witnesses: &[CanonicalTransitionWitness],
) -> TexasAirResult<ArchivedCanonicalTaggedProof> {
    let (trace, mut archive) = trace_for(witnesses)?;
    let scope = scope_trace(&archive, trace.log_size);
    let config = crate::prover_context::protocol_pcs_config();
    let twiddles =
        crate::prover_context::simd_twiddles(trace.log_size + config.fri_config.log_blowup_factor);
    let mut channel = Poseidon252Channel::default();
    mix_scope(&mut channel, &archive);
    let mut scheme =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::with_memory_pool(
            config,
            &twiddles,
            crate::prover_context::simd_base_column_pool(),
        );
    {
        let mut b = scheme.tree_builder();
        b.extend_evals(scope.to_evaluations());
        b.commit(&mut channel);
    }
    {
        let mut b = scheme.tree_builder();
        b.extend_evals(trace.to_evaluations());
        b.commit(&mut channel);
    }
    let ids = preprocessed_ids();
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
    let component = FrameworkComponent::new(
        &mut allocator,
        CanonicalAir {
            log_size: trace.log_size,
        },
        SecureField::from(0u32),
    );
    let proof = prove(&[&component], &mut channel, scheme)
        .map_err(|e: ProvingError| TexasAirError::StwoProverError(e.to_string()))?;
    archive.stark_proof_bytes = options()
        .serialize(&proof)
        .map_err(|e| TexasAirError::SerializationError(e.to_string()))?;
    Ok(archive)
}

/// Prove a canonical batch whose public scope is reserved for a fixed-width
/// L1 state-object opening.
///
/// This function only commits the key/epoch into the canonical STARK's
/// Fiat--Shamir scope.  [`crate::canonical_state_opening`] proves and checks
/// the matching Blake2b sparse-Merkle openings; keeping the two STARKs
/// separate avoids an in-AIR STARK verifier on the latency-sensitive route.
pub fn prove_canonical_tagged_batch_for_state_opening(
    witnesses: &[CanonicalTransitionWitness],
    state_opening: CanonicalStateOpeningScope,
) -> TexasAirResult<ArchivedCanonicalTaggedProof> {
    state_opening.validate()?;
    let (trace, mut archive) = trace_for_with_state_opening_scope(witnesses, state_opening)?;
    let scope = scope_trace(&archive, trace.log_size);
    let config = crate::prover_context::protocol_pcs_config();
    let twiddles =
        crate::prover_context::simd_twiddles(trace.log_size + config.fri_config.log_blowup_factor);
    let mut channel = Poseidon252Channel::default();
    mix_scope(&mut channel, &archive);
    let mut scheme =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::with_memory_pool(
            config,
            &twiddles,
            crate::prover_context::simd_base_column_pool(),
        );
    {
        let mut b = scheme.tree_builder();
        b.extend_evals(scope.to_evaluations());
        b.commit(&mut channel);
    }
    {
        let mut b = scheme.tree_builder();
        b.extend_evals(trace.to_evaluations());
        b.commit(&mut channel);
    }
    let ids = preprocessed_ids();
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
    let component = FrameworkComponent::new(
        &mut allocator,
        CanonicalAir {
            log_size: trace.log_size,
        },
        SecureField::from(0u32),
    );
    let proof = prove(&[&component], &mut channel, scheme)
        .map_err(|e: ProvingError| TexasAirError::StwoProverError(e.to_string()))?;
    archive.stark_proof_bytes = options()
        .serialize(&proof)
        .map_err(|e| TexasAirError::SerializationError(e.to_string()))?;
    Ok(archive)
}

pub fn verify_canonical_tagged_proof(archive: &ArchivedCanonicalTaggedProof) -> TexasAirResult<()> {
    if archive.num_columns != NUM_COLUMNS as u32
        || archive.transition_count == 0
        || archive.transition_count as usize > (1usize << archive.log_size)
        || archive.log_size > 10
    {
        return Err(TexasAirError::SpecViolation(
            "canonical proof shape is invalid".into(),
        ));
    }
    validate_state_image_bytes(archive)?;
    let proof: StarkProof<Poseidon252MerkleHasher> = options()
        .deserialize(&archive.stark_proof_bytes)
        .map_err(|e| TexasAirError::SerializationError(e.to_string()))?;
    let config = crate::prover_context::protocol_pcs_config();
    let scope = scope_trace(archive, archive.log_size);
    let twiddles = crate::prover_context::simd_twiddles(
        archive.log_size + config.fri_config.log_blowup_factor,
    );
    let mut trusted =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::with_memory_pool(
            config,
            &twiddles,
            crate::prover_context::simd_base_column_pool(),
        );
    let mut scope_channel = Poseidon252Channel::default();
    {
        let mut b = trusted.tree_builder();
        b.extend_evals(scope.to_evaluations());
        b.commit(&mut scope_channel);
    }
    if proof.commitments.first().copied() != trusted.roots().first().copied() {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "canonical public scope commitment mismatch".into(),
        ));
    }
    let mut channel = Poseidon252Channel::default();
    mix_scope(&mut channel, archive);
    let mut scheme = CommitmentSchemeVerifier::<Poseidon252MerkleChannel>::new(config);
    scheme.commit(
        proof.commitments[0],
        &vec![archive.log_size; PREPROCESSED_COLUMNS],
        &mut channel,
    );
    scheme.commit(
        proof.commitments[1],
        &vec![archive.log_size; NUM_COLUMNS],
        &mut channel,
    );
    let ids = preprocessed_ids();
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
    let component = FrameworkComponent::new(
        &mut allocator,
        CanonicalAir {
            log_size: archive.log_size,
        },
        SecureField::from(0u32),
    );
    verify(&[&component], &mut channel, &mut scheme, proof)
        .map_err(|e: VerificationError| TexasAirError::ConstraintUnsatisfied(e.to_string()))
}

pub fn verify_canonical_tagged_batch(
    witnesses: &[CanonicalTransitionWitness],
    archive: &ArchivedCanonicalTaggedProof,
) -> TexasAirResult<()> {
    let (_, expected) = trace_for(witnesses)?;
    if expected.table_id != archive.table_id
        || expected.batch_digest != archive.batch_digest
        || expected.pre_state_commitment != archive.pre_state_commitment
        || expected.post_state_commitment != archive.post_state_commitment
        || expected.pre_state_image_bytes != archive.pre_state_image_bytes
        || expected.post_state_image_bytes != archive.post_state_image_bytes
        || archive_root_scope(&expected) != archive_root_scope(archive)
        || expected.state_object_key != archive.state_object_key
        || expected.state_opening_epoch != archive.state_opening_epoch
        || expected.transition_count != archive.transition_count
    {
        return Err(TexasAirError::SpecViolation(
            "canonical proof public scope mismatch".into(),
        ));
    }
    verify_canonical_tagged_proof(archive)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub};

    use crate::texas_canonical::{
        CANONICAL_ABI_VERSION, CanonicalActionPayload, CanonicalBoardRevealAssignment,
        CanonicalPhase, CanonicalRoundAdvanceOpening, CanonicalSeat, CanonicalSeatStatus,
        CanonicalStateImage, MAX_CANONICAL_SEATS, NO_CANONICAL_SEAT,
    };
    use stwo::core::fields::qm31::SECURE_EXTENSION_DEGREE;
    use stwo_constraint_framework::EvalAtRow;

    #[derive(Clone, Copy, Debug)]
    struct Degree(usize);

    impl std::fmt::Display for Degree {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl num_traits::One for Degree {
        fn one() -> Self {
            Self(0)
        }
    }

    impl num_traits::Zero for Degree {
        fn zero() -> Self {
            Self(0)
        }

        fn is_zero(&self) -> bool {
            self.0 == 0
        }
    }

    impl stwo::core::fields::FieldExpOps for Degree {
        fn inverse(&self) -> Self {
            *self
        }
    }

    impl Add for Degree {
        type Output = Self;
        fn add(self, rhs: Self) -> Self {
            Self(self.0.max(rhs.0))
        }
    }

    impl Sub for Degree {
        type Output = Self;
        fn sub(self, rhs: Self) -> Self {
            Self(self.0.max(rhs.0))
        }
    }

    impl Mul for Degree {
        type Output = Self;
        fn mul(self, rhs: Self) -> Self {
            Self(self.0 + rhs.0)
        }
    }

    impl Neg for Degree {
        type Output = Self;
        fn neg(self) -> Self {
            self
        }
    }

    impl AddAssign for Degree {
        fn add_assign(&mut self, rhs: Self) {
            self.0 = self.0.max(rhs.0);
        }
    }

    impl MulAssign for Degree {
        fn mul_assign(&mut self, rhs: Self) {
            self.0 += rhs.0;
        }
    }

    impl AddAssign<M31> for Degree {
        fn add_assign(&mut self, _: M31) {}
    }

    impl Mul<M31> for Degree {
        type Output = Self;
        fn mul(self, _: M31) -> Self {
            self
        }
    }

    impl Add<M31> for Degree {
        type Output = Self;
        fn add(self, _: M31) -> Self {
            self
        }
    }

    impl Add<SecureField> for Degree {
        type Output = Self;
        fn add(self, _: SecureField) -> Self {
            self
        }
    }

    impl Mul<SecureField> for Degree {
        type Output = Self;
        fn mul(self, _: SecureField) -> Self {
            self
        }
    }

    impl Sub<SecureField> for Degree {
        type Output = Self;
        fn sub(self, _: SecureField) -> Self {
            self
        }
    }

    impl From<M31> for Degree {
        fn from(_: M31) -> Self {
            Self(0)
        }
    }

    impl From<SecureField> for Degree {
        fn from(_: SecureField) -> Self {
            Self(0)
        }
    }

    struct DegreeEvaluator {
        max: usize,
    }

    impl EvalAtRow for DegreeEvaluator {
        type F = Degree;
        type EF = Degree;

        fn next_trace_mask(&mut self) -> Self::F {
            Degree(1)
        }

        fn get_preprocessed_column(
            &mut self,
            _column: stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId,
        ) -> Self::F {
            Degree(1)
        }

        fn next_interaction_mask<const N: usize>(
            &mut self,
            _interaction: usize,
            _offsets: [isize; N],
        ) -> [Self::F; N] {
            std::array::from_fn(|_| Degree(1))
        }

        fn add_constraint<G>(&mut self, constraint: G)
        where
            Self::EF: Mul<G, Output = Self::EF> + From<G>,
        {
            let constraint = Self::EF::from(constraint);
            self.max = self.max.max(constraint.0);
        }

        fn combine_ef(_: [Self::F; SECURE_EXTENSION_DEGREE]) -> Self::EF {
            num_traits::Zero::zero()
        }
    }

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
            current_bet: 0,
            min_raise: 0,
            chip_pool: 0,
            pot: 0,
            button: 0,
            max_players: 2,
            acted_mask: 0,
            leave_after_hand_mask: 0,
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
    fn canonical_air_declares_the_maximum_expression_degree() {
        let mut evaluator = DegreeEvaluator { max: 0 };
        evaluator = CanonicalAir { log_size: 10 }.evaluate(evaluator);
        assert_eq!(evaluator.max, 3);
    }

    fn create_table() -> CanonicalTransitionWitness {
        let pre = image();
        let mut post = pre.clone();
        post.call_seq = pre.call_seq + 1;
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::CreateTable,
            actor: [1; 32],
            action: CanonicalActionPayload {
                seat: NO_CANONICAL_SEAT,
                amount: 0,
                auxiliary: 0,
                flag: false,
                proof_commitment: [13; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 2,
        };
        witness.seal();
        witness
    }

    fn advance_deadline() -> CanonicalTransitionWitness {
        let mut pre = image();
        pre.phase = CanonicalPhase::Betting;
        pre.phase_subtag = 1;
        pre.street = 1;
        pre.current_turn = 0;
        pre.deadline_ms = 1_000;
        pre.chip_pool = 100;
        pre.seats[0] = CanonicalSeat {
            status: CanonicalSeatStatus::Active,
            acted: false,
            stack: 100,
            bet: 0,
            total_bet: 0,
            pending_addon: 0,
            time_bank_ms: 40,
            identity_commitment: [41; 32],
            key_commitment: [42; 32],
            hole_cards_commitment: [43; 32],
        };
        let mut post = pre.clone();
        post.call_seq = 1;
        post.deadline_ms = 1_040;
        post.seats[0].time_bank_ms = 0;
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::AdvanceDeadline,
            actor: [0; 32],
            action: CanonicalActionPayload {
                seat: 0,
                amount: 40,
                auxiliary: 1,
                flag: false,
                proof_commitment: [13; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 1_000,
        };
        witness.seal();
        witness
    }

    fn start_hand() -> CanonicalTransitionWitness {
        let mut pre = image();
        pre.chip_pool = 1_000;
        pre.seats[0] = active_opponent(false, 0);
        pre.seats[1] = active_opponent(false, 0);
        let mut post = pre.clone();
        post.hand_id = 2;
        post.button = 1;
        post.phase = CanonicalPhase::Shuffling;
        post.phase_subtag = 1;
        post.deadline_ms = 100;
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::StartHand,
            actor: [2; 32],
            action: CanonicalActionPayload {
                seat: NO_CANONICAL_SEAT,
                amount: 0,
                auxiliary: 0,
                flag: false,
                proof_commitment: [13; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        witness
    }

    fn join_table_at(
        pre: CanonicalStateImage,
        seat: u8,
        actor: [u8; 32],
        identity_commitment: [u8; 32],
        key_commitment: [u8; 32],
    ) -> CanonicalTransitionWitness {
        let mut post = pre.clone();
        post.call_seq = pre.call_seq + 1;
        post.chip_pool = pre.chip_pool + 1;
        post.seats[usize::from(seat)] = CanonicalSeat {
            status: CanonicalSeatStatus::Active,
            acted: false,
            stack: 1,
            bet: 0,
            total_bet: 0,
            pending_addon: 0,
            time_bank_ms: 30_000,
            identity_commitment,
            key_commitment,
            hole_cards_commitment: [0; 32],
        };
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::JoinTable,
            actor,
            action: CanonicalActionPayload {
                seat,
                amount: 1,
                auxiliary: 0,
                flag: false,
                proof_commitment: [13; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        witness
    }

    fn join_table() -> CanonicalTransitionWitness {
        join_table_at(image(), 0, [2; 32], [31; 32], [32; 32])
    }

    fn leave_table() -> CanonicalTransitionWitness {
        let mut pre = image();
        pre.chip_pool = 10;
        pre.seats[0] = CanonicalSeat {
            status: CanonicalSeatStatus::Waiting,
            acted: false,
            stack: 7,
            bet: 0,
            total_bet: 0,
            pending_addon: 3,
            time_bank_ms: 0,
            identity_commitment: [31; 32],
            key_commitment: [32; 32],
            hole_cards_commitment: [0; 32],
        };
        let mut post = pre.clone();
        post.call_seq = 1;
        post.chip_pool = 0;
        post.seats[0] = CanonicalSeat::EMPTY;
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::LeaveTable,
            actor: [2; 32],
            action: CanonicalActionPayload {
                seat: 0,
                amount: 10,
                auxiliary: 0,
                flag: false,
                proof_commitment: [13; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        witness
    }

    fn active_opponent(acted: bool, bet: u64) -> CanonicalSeat {
        CanonicalSeat {
            status: CanonicalSeatStatus::Active,
            acted,
            stack: 500,
            bet,
            total_bet: bet,
            pending_addon: 0,
            time_bank_ms: 0,
            identity_commitment: [41; 32],
            key_commitment: [42; 32],
            hole_cards_commitment: [43; 32],
        }
    }

    fn force_fold() -> CanonicalTransitionWitness {
        let mut pre = image();
        pre.phase = CanonicalPhase::Betting;
        pre.phase_subtag = 1;
        pre.street = 1;
        pre.current_turn = 0;
        pre.deadline_ms = 100;
        pre.chip_pool = 1_000;
        pre.seats[0] = active_opponent(false, 0);
        pre.seats[1] = active_opponent(false, 0);
        let mut post = pre.clone();
        post.call_seq = 1;
        post.current_turn = 1;
        post.seats[0].status = CanonicalSeatStatus::Folded;
        post.seats[0].acted = true;
        post.acted_mask = 1;
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::ForceFold,
            actor: [2; 32],
            action: CanonicalActionPayload {
                seat: 0,
                amount: 0,
                auxiliary: 0,
                flag: false,
                proof_commitment: [13; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        witness
    }

    fn kick_player() -> CanonicalTransitionWitness {
        let mut pre = image();
        pre.phase = CanonicalPhase::Betting;
        pre.phase_subtag = 1;
        pre.street = 1;
        pre.current_turn = 1;
        pre.deadline_ms = 100;
        pre.current_bet = 100;
        pre.chip_pool = 1_230;
        pre.seats[0] = CanonicalSeat {
            status: CanonicalSeatStatus::Active,
            acted: false,
            stack: 500,
            bet: 100,
            total_bet: 100,
            pending_addon: 30,
            time_bank_ms: 77,
            identity_commitment: [41; 32],
            key_commitment: [42; 32],
            hole_cards_commitment: [43; 32],
        };
        pre.seats[1] = active_opponent(false, 100);
        let mut post = pre.clone();
        post.call_seq = 1;
        post.pot = 100;
        post.chip_pool = 700;
        post.seats[0].status = CanonicalSeatStatus::Out;
        post.seats[0].stack = 0;
        post.seats[0].bet = 0;
        post.seats[0].pending_addon = 0;
        post.seats[0].key_commitment = [0; 32];
        post.seats[0].hole_cards_commitment = [0; 32];
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::KickPlayer,
            actor: [2; 32],
            action: CanonicalActionPayload {
                seat: 0,
                amount: 530,
                auxiliary: 0,
                flag: false,
                proof_commitment: [13; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        witness
    }

    fn submit_shuffle() -> CanonicalTransitionWitness {
        let mut pre = image();
        pre.phase = CanonicalPhase::Shuffling;
        pre.phase_subtag = 1;
        pre.deadline_ms = 100;
        pre.chip_pool = 100;
        pre.seats[0] = CanonicalSeat {
            status: CanonicalSeatStatus::Active,
            acted: false,
            stack: 100,
            bet: 0,
            total_bet: 0,
            pending_addon: 0,
            time_bank_ms: 30_000,
            identity_commitment: [51; 32],
            key_commitment: [52; 32],
            hole_cards_commitment: [0; 32],
        };
        let mut post = pre.clone();
        post.call_seq = 1;
        post.deck_commitment = [54; 32];
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::SubmitShuffle,
            actor: [2; 32],
            action: CanonicalActionPayload {
                seat: 0,
                amount: 0,
                auxiliary: 0,
                flag: false,
                proof_commitment: [53; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        witness
    }

    fn fold_with_proof() -> CanonicalTransitionWitness {
        let mut pre = image();
        pre.phase = CanonicalPhase::Betting;
        pre.phase_subtag = 1;
        pre.street = 1;
        pre.deadline_ms = 100;
        pre.current_turn = 0;
        pre.current_bet = 100;
        pre.min_raise = 100;
        pre.chip_pool = 1_600;
        pre.seats[0] = CanonicalSeat {
            status: CanonicalSeatStatus::Active,
            acted: false,
            stack: 1_000,
            bet: 0,
            total_bet: 0,
            pending_addon: 0,
            time_bank_ms: 0,
            identity_commitment: [21; 32],
            key_commitment: [22; 32],
            hole_cards_commitment: [23; 32],
        };
        pre.seats[1] = active_opponent(false, 100);

        let mut post = pre.clone();
        post.call_seq = 1;
        post.current_turn = 1;
        post.acted_mask = 1;
        post.seats[0].status = CanonicalSeatStatus::Folded;
        post.seats[0].acted = true;
        // In the VM this is the commitment to the ciphertext deck with the
        // actor's ElGamal layer removed by the leave DLEQ relation.
        post.deck_commitment = [0x55; 32];
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::FoldWithProof,
            actor: [31; 32],
            action: CanonicalActionPayload {
                seat: 0,
                amount: 0,
                auxiliary: 0,
                flag: false,
                proof_commitment: [0x77; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        witness
    }

    fn set_leave_after_hand() -> CanonicalTransitionWitness {
        let mut pre = image();
        pre.seats[0] = CanonicalSeat {
            status: CanonicalSeatStatus::Waiting,
            acted: false,
            stack: 0,
            bet: 0,
            total_bet: 0,
            pending_addon: 0,
            time_bank_ms: 0,
            identity_commitment: [31; 32],
            key_commitment: [32; 32],
            hole_cards_commitment: [0; 32],
        };
        let mut post = pre.clone();
        post.call_seq = 1;
        post.leave_after_hand_mask = 1;
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::SetLeaveAfterHand,
            actor: [2; 32],
            action: CanonicalActionPayload {
                seat: 0,
                amount: 0,
                auxiliary: 0,
                flag: true,
                proof_commitment: [13; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        witness
    }

    fn call() -> CanonicalTransitionWitness {
        let mut pre = image();
        pre.phase = CanonicalPhase::Betting;
        pre.phase_subtag = 1;
        pre.street = 1;
        pre.deadline_ms = 100;
        pre.current_turn = 0;
        pre.current_bet = 100;
        pre.min_raise = 100;
        pre.chip_pool = 1_600;
        pre.seats[0] = CanonicalSeat {
            status: CanonicalSeatStatus::Active,
            acted: false,
            stack: 1_000,
            bet: 0,
            total_bet: 0,
            pending_addon: 0,
            time_bank_ms: 0,
            identity_commitment: [21; 32],
            key_commitment: [22; 32],
            hole_cards_commitment: [23; 32],
        };
        pre.seats[1] = active_opponent(false, 100);
        let mut post = pre.clone();
        post.call_seq = 1;
        post.current_turn = 1;
        post.seats[0].acted = true;
        post.seats[0].stack = 900;
        post.seats[0].bet = 100;
        post.seats[0].total_bet = 100;
        post.acted_mask = 1;
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::Call,
            actor: [31; 32],
            action: CanonicalActionPayload {
                seat: 0,
                amount: 100,
                auxiliary: 0,
                flag: false,
                proof_commitment: [32; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        witness
    }

    fn short_all_in_call() -> CanonicalTransitionWitness {
        let mut witness = call();
        witness.pre.seats[0].stack = 50;
        witness.pre.chip_pool = 650;
        witness.post.chip_pool = 650;
        witness.post.seats[0].status = CanonicalSeatStatus::AllIn;
        witness.post.seats[0].stack = 0;
        witness.post.seats[0].bet = 50;
        witness.post.seats[0].total_bet = 50;
        witness.action.amount = 50;
        witness.seal();
        witness
    }

    fn bet() -> CanonicalTransitionWitness {
        let mut pre = image();
        pre.phase = CanonicalPhase::Betting;
        pre.phase_subtag = 1;
        pre.street = 2;
        pre.deadline_ms = 100;
        pre.current_turn = 0;
        pre.min_raise = 100;
        pre.chip_pool = 1_500;
        pre.seats[0] = CanonicalSeat {
            status: CanonicalSeatStatus::Active,
            acted: false,
            stack: 1_000,
            bet: 0,
            total_bet: 0,
            pending_addon: 0,
            time_bank_ms: 0,
            identity_commitment: [21; 32],
            key_commitment: [22; 32],
            hole_cards_commitment: [23; 32],
        };
        pre.seats[1] = active_opponent(false, 0);
        let mut post = pre.clone();
        post.call_seq = 1;
        post.current_turn = 1;
        post.current_bet = 100;
        post.min_raise = 100;
        post.seats[0].acted = true;
        post.seats[0].stack = 900;
        post.seats[0].bet = 100;
        post.seats[0].total_bet = 100;
        post.acted_mask = 1;
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::Bet,
            actor: [31; 32],
            action: CanonicalActionPayload {
                seat: 0,
                amount: 100,
                auxiliary: 0,
                flag: false,
                proof_commitment: [32; 32],
            },
            round_advance: Default::default(),
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        witness
    }

    fn funding(kind: CanonicalTransitionKind) -> CanonicalTransitionWitness {
        let mut pre = image();
        pre.seats[0] = CanonicalSeat {
            status: CanonicalSeatStatus::Waiting,
            acted: false,
            stack: 100,
            bet: 0,
            total_bet: 0,
            pending_addon: 10,
            time_bank_ms: 0,
            identity_commitment: [21; 32],
            key_commitment: [22; 32],
            hole_cards_commitment: [23; 32],
        };
        pre.chip_pool = 110;
        let mut post = pre.clone();
        post.call_seq = 1;
        post.chip_pool = 160;
        match kind {
            CanonicalTransitionKind::Addon => post.seats[0].pending_addon = 60,
            CanonicalTransitionKind::Rebuy => post.seats[0].stack = 150,
            _ => unreachable!("funding fixture needs addon or rebuy"),
        }
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind,
            actor: [31; 32],
            action: CanonicalActionPayload {
                seat: 0,
                amount: 50,
                auxiliary: 0,
                flag: false,
                proof_commitment: [32; 32],
            },
            round_advance: Default::default(),
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        witness
    }

    fn raise() -> CanonicalTransitionWitness {
        let mut pre = image();
        pre.phase = CanonicalPhase::Betting;
        pre.phase_subtag = 1;
        pre.street = 2;
        pre.deadline_ms = 100;
        pre.current_turn = 0;
        pre.current_bet = 100;
        pre.min_raise = 100;
        pre.pot = 250;
        pre.chip_pool = 1_850;
        pre.seats[0] = CanonicalSeat {
            status: CanonicalSeatStatus::Active,
            acted: false,
            stack: 950,
            bet: 50,
            total_bet: 50,
            pending_addon: 0,
            time_bank_ms: 0,
            identity_commitment: [21; 32],
            key_commitment: [22; 32],
            hole_cards_commitment: [23; 32],
        };
        pre.seats[1] = active_opponent(true, 100);
        pre.acted_mask = 1 << 1;
        let mut post = pre.clone();
        post.call_seq = 1;
        post.current_turn = 1;
        post.current_bet = 200;
        post.seats[0].acted = true;
        post.seats[0].stack = 800;
        post.seats[0].bet = 200;
        post.seats[0].total_bet = 200;
        post.seats[1].acted = false;
        post.acted_mask = 1;
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::Raise,
            actor: [31; 32],
            action: CanonicalActionPayload {
                seat: 0,
                amount: 200,
                auxiliary: 0,
                flag: false,
                proof_commitment: [32; 32],
            },
            round_advance: Default::default(),
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        witness
    }

    fn short_all_in_raise() -> CanonicalTransitionWitness {
        let mut witness = raise();
        witness.pre.seats[0].stack = 125;
        witness.pre.chip_pool = 1_025;
        witness.post.chip_pool = 1_025;
        witness.post.seats[0].status = CanonicalSeatStatus::AllIn;
        witness.post.current_bet = 175;
        witness.post.min_raise = 100;
        witness.post.seats[0].stack = 0;
        witness.post.seats[0].bet = 175;
        witness.post.seats[0].total_bet = 175;
        witness.action.amount = 175;
        witness.seal();
        witness
    }

    fn raise_against_acted_opponent() -> CanonicalTransitionWitness {
        let mut witness = raise();
        let opponent = CanonicalSeat {
            status: CanonicalSeatStatus::Active,
            acted: true,
            stack: 500,
            bet: 100,
            total_bet: 100,
            pending_addon: 0,
            time_bank_ms: 0,
            identity_commitment: [41; 32],
            key_commitment: [42; 32],
            hole_cards_commitment: [43; 32],
        };
        witness.pre.seats[1] = opponent;
        witness.post.seats[1] = opponent;
        witness.post.seats[1].acted = false;
        witness.pre.acted_mask = 1 << 1;
        // VM `RaiseTo` resets every other actionable player's acted bit.
        witness.post.acted_mask = 1;
        witness.pre.chip_pool = 1_850;
        witness.post.chip_pool = 1_850;
        witness.seal();
        witness
    }

    fn advance_round() -> CanonicalTransitionWitness {
        let mut pre = image();
        pre.phase = CanonicalPhase::Betting;
        pre.phase_subtag = 1;
        pre.street = 2;
        pre.current_turn = NO_CANONICAL_SEAT;
        pre.deadline_ms = 100;
        pre.current_bet = 100;
        pre.min_raise = 100;
        pre.pot = 50;
        pre.seats[0] = active_opponent(true, 100);
        pre.seats[1] = active_opponent(true, 100);
        pre.acted_mask = 0b11;
        pre.chip_pool = 1_250;

        let mut post = pre.clone();
        post.call_seq = 1;
        post.phase = CanonicalPhase::Revealing;
        post.phase_subtag = 2;
        post.street = 3;
        post.deadline_ms = 200;
        post.current_bet = 0;
        post.min_raise = 0;
        post.pot = 250;
        for seat in &mut post.seats {
            seat.bet = 0;
        }

        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::AdvanceRound,
            actor: [0; 32],
            action: CanonicalActionPayload {
                seat: NO_CANONICAL_SEAT,
                amount: 0,
                auxiliary: 0,
                flag: false,
                proof_commitment: [32; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening {
                // VM flop -> turn: seven encrypted cards have been consumed
                // (four hole cards and the flop); allocate one board card.
                pre_cards_dealt: 7,
                post_cards_dealt: 8,
                pre_board_len: 3,
                post_board_len: 3,
                pre_second_board_len: 0,
                post_second_board_len: 0,
                run_it_twice: false,
                reveal_purpose: 2,
                assignment_count: 1,
                assignments: [
                    CanonicalBoardRevealAssignment {
                        present: true,
                        encrypted_card_index: 7,
                        runout_index: 0,
                        board_position: 3,
                        pending_mask: 0b11,
                        submitted_mask: 0,
                    },
                    CanonicalBoardRevealAssignment::EMPTY,
                    CanonicalBoardRevealAssignment::EMPTY,
                    CanonicalBoardRevealAssignment::EMPTY,
                    CanonicalBoardRevealAssignment::EMPTY,
                    CanonicalBoardRevealAssignment::EMPTY,
                ],
            },
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        witness
    }

    fn assert_trace_satisfies_air(trace: &MethodTrace, archive: &ArchivedCanonicalTaggedProof) {
        let scope = scope_trace(archive, trace.log_size);
        // `FrameworkComponent` consumes preprocessed masks in the order in which
        // `evaluate` requests them, rather than the storage order of `scope`.
        let preprocessed_cols = [
            scope.cols[0..1].iter(),
            scope.cols[3..7].iter(),
            scope.cols[1..3].iter(),
            scope.cols[7..PREPROCESSED_COLUMNS].iter(),
        ]
        .into_iter()
        .flatten()
        .collect();
        let evals =
            stwo::core::pcs::TreeVec::new(vec![preprocessed_cols, trace.cols.iter().collect()]);
        stwo_constraint_framework::assert_constraints_on_trace(
            &evals,
            trace.log_size,
            |eval| {
                CanonicalAir {
                    log_size: trace.log_size,
                }
                .evaluate(eval);
            },
            SecureField::from(0u32),
        );
    }

    fn assert_air_rejects_trace_mutation(
        trace: &MethodTrace,
        archive: &ArchivedCanonicalTaggedProof,
        column: usize,
    ) {
        let mut tampered = trace.clone();
        tampered.cols[column][0] += M31::from(1u32);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert_trace_satisfies_air(&tampered, archive);
            }))
            .is_err()
        );
    }

    #[test]
    fn canonical_direct_air_proves_and_verifies_without_replay() {
        let witness = create_table();
        let archive = prove_canonical_tagged_batch_for_state_opening(
            &[witness],
            CanonicalStateOpeningScope {
                state_object_key: [0x5a; 32],
                state_opening_epoch: 1,
            },
        )
        .expect("canonical proof");
        verify_canonical_tagged_proof(&archive).expect("canonical verification");

        // Key and epoch are part of the canonical proof's Fiat--Shamir
        // scope. They cannot be changed later to attach the proof to a
        // different L1 state object or value ABI.
        let mut wrong_key = archive.clone();
        wrong_key.state_object_key[0] ^= 1;
        assert!(verify_canonical_tagged_proof(&wrong_key).is_err());
        let mut wrong_epoch = archive;
        wrong_epoch.state_opening_epoch += 1;
        assert!(verify_canonical_tagged_proof(&wrong_epoch).is_err());
    }

    #[test]
    fn canonical_air_binds_state_image_bytes_to_endpoint_trace_and_fiat_shamir_scope() {
        let witness = create_table();
        let (trace, archive) = trace_for(std::slice::from_ref(&witness)).expect("canonical trace");

        // This full-seat field is not the selected legacy seat projection.
        // CreateTable's original relation leaves it zero, so this rejection
        // specifically demonstrates the Borsh endpoint projection binding.
        let mut bad_trace = trace.clone();
        bad_trace.cols[FULL_BETTING_SEATS_OFFSET + FULL_SEAT_STACK_BLOCK_OFFSET][0] =
            M31::from(1u32);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert_trace_satisfies_air(&bad_trace, &archive);
            }))
            .is_err()
        );

        let mut proven = prove_canonical_tagged_batch(&[witness]).expect("canonical proof");
        // Board commitment bytes are part of the endpoint projection and
        // Fiat--Shamir scope, so an opaque Borsh-byte splice cannot survive
        // verification.
        proven.pre_state_image_bytes[STATE_IMAGE_BOARD_CARDS_COMMITMENT_OFFSET] ^= 1;
        assert!(verify_canonical_tagged_proof(&proven).is_err());
    }

    #[test]
    fn canonical_air_preserves_opaque_commitments_during_call() {
        let witness = call();
        let (trace, mut archive) =
            trace_for(std::slice::from_ref(&witness)).expect("canonical trace");
        assert_trace_satisfies_air(&trace, &archive);

        // Alter both representations together: this rules out the endpoint
        // projection check as the cause of rejection.  `Call` itself must
        // preserve every opaque crypto-state commitment.
        let mut tampered = trace.clone();
        let post_board_column = OPAQUE_COMMITMENTS_OFFSET + OPAQUE_COMMITMENT_COUNT * 16;
        tampered.cols[post_board_column][0] += M31::from(1u32);
        let board_limb = u16::from_le_bytes(
            archive.post_state_image_bytes[STATE_IMAGE_BOARD_CARDS_COMMITMENT_OFFSET
                ..STATE_IMAGE_BOARD_CARDS_COMMITMENT_OFFSET + 2]
                .try_into()
                .expect("board commitment limb"),
        );
        let incremented = board_limb
            .checked_add(1)
            .expect("fixture must leave space in board commitment limb");
        archive.post_state_image_bytes[STATE_IMAGE_BOARD_CARDS_COMMITMENT_OFFSET
            ..STATE_IMAGE_BOARD_CARDS_COMMITMENT_OFFSET + 2]
            .copy_from_slice(&incremented.to_le_bytes());
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert_trace_satisfies_air(&tampered, &archive);
            }))
            .is_err()
        );
    }

    #[test]
    fn canonical_air_preserves_seat_commitments_during_call() {
        let witness = call();
        let (trace, mut archive) =
            trace_for(std::slice::from_ref(&witness)).expect("canonical trace");
        assert_trace_satisfies_air(&trace, &archive);

        // Splice the endpoint and trace together.  This rejection must come
        // from Call's preservation relation rather than the endpoint-image
        // equality check.
        let mut tampered = trace.clone();
        let post_seat_zero_identity_column =
            SEAT_COMMITMENTS_OFFSET + MAX_CANONICAL_SEATS * SEAT_COMMITMENT_LIMBS;
        tampered.cols[post_seat_zero_identity_column][0] += M31::from(1u32);
        let identity_offset =
            STATE_IMAGE_SEATS_OFFSET + STATE_IMAGE_SEAT_IDENTITY_COMMITMENT_OFFSET;
        let identity_limb = u16::from_le_bytes(
            archive.post_state_image_bytes[identity_offset..identity_offset + 2]
                .try_into()
                .expect("seat identity commitment limb"),
        );
        let incremented = identity_limb
            .checked_add(1)
            .expect("fixture must leave space in seat identity commitment limb");
        archive.post_state_image_bytes[identity_offset..identity_offset + 2]
            .copy_from_slice(&incremented.to_le_bytes());
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert_trace_satisfies_air(&tampered, &archive);
            }))
            .is_err()
        );
    }

    #[test]
    fn canonical_air_constrains_lifecycle_phase_and_selected_seat_opening() {
        let cases = [
            create_table(),
            start_hand(),
            advance_deadline(),
            join_table(),
            leave_table(),
            force_fold(),
            kick_player(),
            set_leave_after_hand(),
        ];
        for witness in cases {
            let (trace, archive) =
                trace_for(std::slice::from_ref(&witness)).expect("valid lifecycle trace");
            assert_trace_satisfies_air(&trace, &archive);
        }

        let (trace, archive) = trace_for(&[create_table()]).expect("create trace");
        // `pre_phase` is Waiting on CreateTable; it is no longer merely a
        // host-side `validate_transition_relation` check.
        assert_air_rejects_trace_mutation(&trace, &archive, PRE_PHASE_OFFSET);
        // Rules/governance cannot be switched under any canonical selector.
        assert_air_rejects_trace_mutation(&trace, &archive, IMMUTABLE_COMMITMENTS_OFFSET);

        let (trace, archive) = trace_for(&[start_hand()]).expect("start trace");
        // StartHand must enter Shuffling and retain the no-actor turn marker.
        assert_air_rejects_trace_mutation(&trace, &archive, POST_PHASE_OFFSET);
        assert_air_rejects_trace_mutation(&trace, &archive, POST_TURN_OFFSET);
        assert_air_rejects_trace_mutation(&trace, &archive, POST_DEADLINE_INV_OFFSET);

        let (trace, archive) = trace_for(&[advance_deadline()]).expect("deadline trace");
        // The permissionless action height is tied to the pre-state deadline
        // with a four-limb checked comparison, rather than a host-side u64
        // branch.
        assert_air_rejects_trace_mutation(&trace, &archive, DEADLINE_HEIGHT_OFFSET);
        assert_air_rejects_trace_mutation(&trace, &archive, ADVANCE_DEADLINE_PRE_INV_OFFSET);

        let (trace, archive) = trace_for(&[join_table()]).expect("join trace");
        // The selected post status is derived from the full seat opening and
        // must be Waiting; a changed action amount also fails its AIR inverse.
        assert_air_rejects_trace_mutation(&trace, &archive, SELECTED_POST_STATUS_OFFSET);
        assert_air_rejects_trace_mutation(&trace, &archive, ACTION_AMOUNT_OFFSET);

        let (trace, archive) = trace_for(&[leave_table()]).expect("leave trace");
        assert_air_rejects_trace_mutation(&trace, &archive, SELECTED_POST_STATUS_OFFSET);
        // Seat 1 is not addressed by this LeaveTable row.  The full-seat
        // opening makes its stack immutable even though it is not part of the
        // legacy selected-seat projection or a u64 range-advice family.
        assert_air_rejects_trace_mutation(
            &trace,
            &archive,
            FULL_POST_BETTING_SEATS_OFFSET + FULL_SEAT_STACK_BLOCK_OFFSET + 4,
        );

        let (trace, archive) = trace_for(&[force_fold()]).expect("force-fold trace");
        // ForceFold may only move Active/Waiting to Folded/Out/Empty.  The
        // scalar projection is bound to the selected full-seat one-hot image.
        assert_air_rejects_trace_mutation(&trace, &archive, SELECTED_POST_STATUS_OFFSET);

        let (trace, archive) = trace_for(&[set_leave_after_hand()]).expect("set-leave trace");
        // The post mask is reconstructed from nine canonical bits and follows
        // the selected action flag; this mutation cannot be accepted as a
        // host-provided u16 update.
        assert_air_rejects_trace_mutation(&trace, &archive, POST_LEAVE_MASK_OFFSET);
    }

    #[test]
    fn canonical_direct_air_proves_vm_kick_refund_and_bet_collection() {
        let witness = kick_player();
        let (trace, archive) = trace_for(std::slice::from_ref(&witness)).expect("kick trace");
        assert_trace_satisfies_air(&trace, &archive);
        let archive = prove_canonical_tagged_batch(&[witness.clone()]).expect("kick proof");
        verify_canonical_tagged_batch(&[witness], &archive).expect("kick verification");

        // The action amount is the checked refund `stack + pending_addon`,
        // not an opaque administrator payload.
        assert_air_rejects_trace_mutation(&trace, &archive, ACTION_AMOUNT_OFFSET);

        // A kicked seat cannot retain live custody or a current-round wager.
        let post_stack = FULL_POST_BETTING_SEATS_OFFSET + FULL_SEAT_STACK_BLOCK_OFFSET;
        let post_bet = post_stack + MAX_CANONICAL_SEATS * 4;
        let post_pending = post_stack + 3 * MAX_CANONICAL_SEATS * 4;
        assert_air_rejects_trace_mutation(&trace, &archive, post_stack);
        assert_air_rejects_trace_mutation(&trace, &archive, post_bet);
        assert_air_rejects_trace_mutation(&trace, &archive, post_pending);
    }

    #[test]
    fn canonical_direct_air_proves_join_and_leave_custody_updates() {
        let witness = join_table();
        let (trace, archive) = trace_for(std::slice::from_ref(&witness)).expect("join trace");
        assert_trace_satisfies_air(&trace, &archive);
        let archive = prove_canonical_tagged_batch(&[witness.clone()]).expect("join proof");
        verify_canonical_tagged_batch(&[witness], &archive).expect("join verification");

        let selected_post_stack = FULL_POST_BETTING_SEATS_OFFSET + FULL_SEAT_STACK_BLOCK_OFFSET;
        assert_air_rejects_trace_mutation(&trace, &archive, ACTION_AMOUNT_OFFSET);
        assert_air_rejects_trace_mutation(&trace, &archive, selected_post_stack);

        let witness = leave_table();
        let (trace, archive) = trace_for(std::slice::from_ref(&witness)).expect("leave trace");
        assert_trace_satisfies_air(&trace, &archive);
        let archive = prove_canonical_tagged_batch(&[witness.clone()]).expect("leave proof");
        verify_canonical_tagged_batch(&[witness], &archive).expect("leave verification");

        assert_air_rejects_trace_mutation(&trace, &archive, ACTION_AMOUNT_OFFSET);
        assert_air_rejects_trace_mutation(
            &trace,
            &archive,
            FULL_POST_BETTING_SEATS_OFFSET + FULL_SEAT_STACK_BLOCK_OFFSET,
        );
    }

    #[test]
    fn canonical_direct_air_proves_start_hand_button_and_participant_gate() {
        let witness = start_hand();
        let (trace, archive) = trace_for(std::slice::from_ref(&witness)).expect("start trace");
        assert_trace_satisfies_air(&trace, &archive);
        let archive = prove_canonical_tagged_batch(&[witness.clone()]).expect("start proof");
        verify_canonical_tagged_batch(&[witness], &archive).expect("start verification");

        // The button successor, minimum-participant gate, and fresh-shuffle
        // preservation boundary are all AIR objects rather than host advice.
        assert_air_rejects_trace_mutation(&trace, &archive, START_BUTTON_SELECTOR_OFFSET + 1);
        assert_air_rejects_trace_mutation(&trace, &archive, START_ACTIVE_COUNT_INV_OFFSET);
        assert_air_rejects_trace_mutation(&trace, &archive, STATE_IMAGE_METADATA_OFFSET + 4);
        assert_air_rejects_trace_mutation(&trace, &archive, OPAQUE_COMMITMENTS_OFFSET + 5 * 16);
    }

    #[test]
    fn canonical_direct_air_proves_join_join_start_hand_chain() {
        let first = join_table();
        let second = join_table_at(first.post.clone(), 1, [3; 32], [35; 32], [36; 32]);
        assert_eq!(first.post, second.pre);
        let mut post = second.post.clone();
        post.hand_id = 2;
        post.button = 1;
        post.phase = CanonicalPhase::Shuffling;
        post.phase_subtag = 1;
        post.deadline_ms = 100;
        post.call_seq = 0;
        let mut start = CanonicalTransitionWitness {
            pre: second.post.clone(),
            post,
            kind: CanonicalTransitionKind::StartHand,
            actor: [2; 32],
            action: CanonicalActionPayload {
                seat: NO_CANONICAL_SEAT,
                amount: 0,
                auxiliary: 0,
                flag: false,
                proof_commitment: [13; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        start.seal();
        let batch = [first, second, start];
        let (trace, archive) = trace_for(&batch).expect("join-join-start trace");
        assert_trace_satisfies_air(&trace, &archive);
        let archive =
            prove_canonical_tagged_batch(&batch).expect("join-join-start canonical proof");
        verify_canonical_tagged_batch(&batch, &archive)
            .expect("join-join-start canonical verification");
    }

    #[test]
    fn canonical_direct_air_closes_submit_shuffle_state_envelope() {
        let witness = submit_shuffle();
        let (trace, archive) =
            trace_for(std::slice::from_ref(&witness)).expect("submit-shuffle trace");
        assert_trace_satisfies_air(&trace, &archive);
        let archive = prove_canonical_tagged_batch(&[witness.clone()]).expect("shuffle proof");
        verify_canonical_tagged_batch(&[witness], &archive).expect("shuffle verification");

        // Shuffle owns the deck commitment, but it cannot mutate board/reveal
        // protocol state or a selected seat's custody bucket.
        assert_air_rejects_trace_mutation(&trace, &archive, OPAQUE_COMMITMENTS_OFFSET + 5 * 16);
        assert_air_rejects_trace_mutation(
            &trace,
            &archive,
            FULL_POST_BETTING_SEATS_OFFSET + FULL_SEAT_STACK_BLOCK_OFFSET,
        );
    }

    #[test]
    fn canonical_direct_air_proves_nonterminal_force_fold_turn_advance() {
        let witness = force_fold();
        let (trace, archive) = trace_for(std::slice::from_ref(&witness)).expect("force-fold trace");
        assert_trace_satisfies_air(&trace, &archive);
        let archive = prove_canonical_tagged_batch(&[witness.clone()]).expect("force-fold proof");
        verify_canonical_tagged_batch(&[witness], &archive).expect("force-fold verification");

        // ForceFold lowers to the VM Fold action, so the successor must be the
        // first post-action Active seat rather than a host-selected actor.
        assert_air_rejects_trace_mutation(&trace, &archive, POST_TURN_OFFSET);
        assert_air_rejects_trace_mutation(&trace, &archive, SELECTED_POST_STATUS_OFFSET);
        assert_air_rejects_trace_mutation(&trace, &archive, ACTION_AMOUNT_OFFSET);
    }

    #[test]
    fn canonical_direct_air_proves_nonterminal_fold_with_proof_shape() {
        let witness = fold_with_proof();
        let (trace, archive) = trace_for(std::slice::from_ref(&witness)).expect("fold proof trace");
        assert_trace_satisfies_air(&trace, &archive);
        let archive =
            prove_canonical_tagged_batch(&[witness.clone()]).expect("fold proof canonical proof");
        verify_canonical_tagged_batch(&[witness.clone()], &archive)
            .expect("fold proof canonical verification");

        // The direct row has no host-side predicate at verification time: an
        // attempted Betting->non-Betting splice or selected-seat fund change
        // is rejected by the tagged AIR itself.
        assert_air_rejects_trace_mutation(&trace, &archive, PRE_PHASE_OFFSET);
        assert_air_rejects_trace_mutation(&trace, &archive, SELECTED_POST_STATUS_OFFSET);
        assert_air_rejects_trace_mutation(&trace, &archive, 330);

        // Zero every commitment limb, its 16-bit witness, and the reused
        // non-zero inverse.  The only remaining difference is the direct
        // crypto anti-null relation, which must reject this forged row.
        let mut null_proof = trace.clone();
        for limb in 0..16 {
            null_proof.cols[PROOF_COMMITMENT_OFFSET + limb][0] = M31::from(0u32);
        }
        for bit in 0..(16 * 16) {
            null_proof.cols[PROOF_COMMITMENT_BITS_OFFSET + bit][0] = M31::from(0u32);
        }
        null_proof.cols[ACTION_AMOUNT_INVERSE_OFFSET][0] = M31::from(0u32);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert_trace_satisfies_air(&null_proof, &archive);
            }))
            .is_err()
        );

        let mut missing_commitment = witness;
        missing_commitment.action.proof_commitment = [0; 32];
        missing_commitment.seal();
        assert!(trace_for(&[missing_commitment]).is_err());
    }

    #[test]
    fn canonical_direct_air_enforces_call_chip_conservation() {
        let witness = call();
        let (trace, archive) = trace_for(std::slice::from_ref(&witness)).expect("call trace");
        assert_trace_satisfies_air(&trace, &archive);
        let archive = prove_canonical_tagged_batch(&[witness.clone()]).expect("call proof");
        verify_canonical_tagged_batch(&[witness], &archive).expect("call verification");

        let mut invalid = call();
        invalid.post.seats[0].stack += 1;
        invalid.seal();
        assert!(prove_canonical_tagged_batch(&[invalid]).is_err());
    }

    #[test]
    fn canonical_direct_air_rejects_noncanonical_call_limb_without_host_validation() {
        let witness = call();
        let (mut trace, archive) = trace_for(std::slice::from_ref(&witness)).expect("call trace");
        // The first bit of the selected pre-stack decomposition. Changing this
        // does not alter the business columns, so rejection demonstrates the
        // AIR's own range relation rather than `validate_shape`.
        trace.cols[361][0] = M31::from(1u32);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert_trace_satisfies_air(&trace, &archive);
            }))
            .is_err()
        );
    }

    #[test]
    fn canonical_direct_air_proves_short_all_in_call() {
        let witness = short_all_in_call();
        let archive = prove_canonical_tagged_batch(&[witness.clone()]).expect("short-call proof");
        verify_canonical_tagged_batch(&[witness], &archive).expect("short-call verification");
    }

    #[test]
    fn canonical_direct_air_derives_all_in_status_from_zero_stack() {
        let witness = short_all_in_call();
        let (trace, archive) = trace_for(&[witness]).expect("short-all-in trace");
        assert_trace_satisfies_air(&trace, &archive);

        // The selected post-seat status is AllIn in the valid row.  Replacing
        // it with Active leaves every business amount untouched, so this
        // failure specifically exercises the AIR's zero-stack lifecycle
        // relation rather than canonical host validation.
        let mut tampered = trace.clone();
        tampered.cols[327][0] = M31::from(2u32);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert_trace_satisfies_air(&tampered, &archive);
            }))
            .is_err()
        );
    }

    #[test]
    fn canonical_direct_air_proves_unopened_round_bet() {
        let witness = bet();
        let archive = prove_canonical_tagged_batch(&[witness.clone()]).expect("bet proof");
        verify_canonical_tagged_batch(&[witness], &archive).expect("bet verification");
    }

    #[test]
    fn canonical_direct_air_collects_every_seat_bet_before_round_advance() {
        let witness = advance_round();
        let (trace, archive) = trace_for(std::slice::from_ref(&witness)).expect("round trace");
        assert_trace_satisfies_air(&trace, &archive);
        let archive = prove_canonical_tagged_batch(&[witness.clone()]).expect("round proof");
        verify_canonical_tagged_batch(&[witness], &archive).expect("round verification");

        // The all-seat pre-bet opening is range-bound and feeds the exact
        // carry chain, so a changed wager cannot be hidden behind the post
        // pot or the opaque reveal commitment.
        assert_air_rejects_trace_mutation(&trace, &archive, ROUND_COLLECT_BET_BITS_OFFSET);

        // The fixed-width board assignment is an AIR object, not trusted
        // auxiliary metadata.  Its deck cursor, participant set and padding
        // are each tied to the selected VM street schedule.
        assert_air_rejects_trace_mutation(&trace, &archive, ROUND_ADVANCE_OPENING_OFFSET + 9 + 1);
        assert_air_rejects_trace_mutation(&trace, &archive, ROUND_ADVANCE_OPENING_OFFSET + 9 + 4);
        assert_air_rejects_trace_mutation(&trace, &archive, ROUND_ADVANCE_OPENING_OFFSET + 9 + 6);
    }

    #[test]
    fn canonical_round_opening_rejects_noncanonical_host_witnesses() {
        let mut wrong_pending_mask = advance_round();
        wrong_pending_mask.round_advance.assignments[0].pending_mask = 0b01;
        wrong_pending_mask.seal();
        assert!(trace_for(&[wrong_pending_mask]).is_err());

        let mut nonzero_padding = advance_round();
        nonzero_padding.round_advance.assignments[1].present = true;
        nonzero_padding.seal();
        assert!(trace_for(&[nonzero_padding]).is_err());

        let mut river_to_showdown = advance_round();
        river_to_showdown.pre.street = 4;
        river_to_showdown.post.street = 5;
        river_to_showdown.seal();
        // River/showdown remains fail-closed until a fixed-width,
        // owner-readable hole-card ledger opening is constrained in the AIR.
        assert!(trace_for(&[river_to_showdown]).is_err());
    }

    #[test]
    fn canonical_air_rejects_card_cursor_outside_52_card_deck_without_host_validation() {
        let witness = advance_round();
        let (mut trace, archive) = trace_for(&[witness]).expect("round trace");

        // Preserve the pre-existing schedule equations: cursor delta remains
        // one and the first assignment still equals the pre cursor.  Before
        // the fixed-width range component this adversarial trace could use
        // field values 53/54 after bypassing Rust shape validation.
        trace.cols[ROUND_ADVANCE_OPENING_OFFSET][0] = M31::from(53u32);
        trace.cols[ROUND_ADVANCE_OPENING_OFFSET + 1][0] = M31::from(54u32);
        trace.cols[ROUND_ADVANCE_OPENING_OFFSET + 9 + 1][0] = M31::from(53u32);
        for (cursor, value) in [53u32, 54u32].into_iter().enumerate() {
            let bits_offset = ROUND_ADVANCE_CARD_CURSOR_RANGE_OFFSET + cursor * 18;
            for bit in 0..6 {
                trace.cols[bits_offset + bit][0] = M31::from((value >> bit) & 1);
            }
        }
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert_trace_satisfies_air(&trace, &archive);
            }))
            .is_err()
        );
    }

    #[test]
    fn canonical_direct_air_proves_run_it_twice_board_schedule() {
        let mut witness = advance_round();
        let opening = &mut witness.round_advance;
        opening.post_cards_dealt = 9;
        opening.pre_second_board_len = 3;
        opening.post_second_board_len = 3;
        opening.run_it_twice = true;
        opening.assignment_count = 2;
        opening.assignments[1] = CanonicalBoardRevealAssignment {
            present: true,
            encrypted_card_index: 8,
            runout_index: 1,
            board_position: 3,
            pending_mask: 0b11,
            submitted_mask: 0,
        };
        witness.seal();

        let archive = prove_canonical_tagged_batch(&[witness.clone()]).expect("RIT round proof");
        verify_canonical_tagged_batch(&[witness], &archive).expect("RIT round verification");
    }

    #[test]
    fn canonical_direct_air_proves_vm_funding_custody_updates() {
        for kind in [
            CanonicalTransitionKind::Addon,
            CanonicalTransitionKind::Rebuy,
        ] {
            let witness = funding(kind);
            let (trace, archive) =
                trace_for(std::slice::from_ref(&witness)).expect("funding trace");
            assert_trace_satisfies_air(&trace, &archive);
            let archive = prove_canonical_tagged_batch(&[witness.clone()]).expect("funding proof");
            verify_canonical_tagged_proof(&archive).expect("standalone funding verification");
            verify_canonical_tagged_batch(&[witness], &archive).expect("funding verification");
        }
    }

    #[test]
    fn canonical_direct_air_rejects_funding_chip_pool_tampering() {
        let witness = funding(CanonicalTransitionKind::Addon);
        let (trace, archive) = trace_for(&[witness]).expect("funding trace");
        assert_trace_satisfies_air(&trace, &archive);
        // The appended post-chip-pool low limb is bound by the exact funding
        // addition, not merely by the host-built canonical state image.
        assert_air_rejects_trace_mutation(&trace, &archive, 1_430);
    }

    #[test]
    fn canonical_direct_air_binds_funding_to_the_full_selected_seat() {
        let witness = funding(CanonicalTransitionKind::Addon);
        let (trace, archive) = trace_for(&[witness]).expect("funding trace");
        assert_trace_satisfies_air(&trace, &archive);

        // This is the selected target's post `pending_addon[0]` in the
        // full-seat opening.  Before the funding one-hot projection was
        // bound back to the canonical selected-seat image, the Addon limb
        // equation only constrained the older projection and this mutation
        // was not observable by the full-seat suffix relation.
        let post_seat_zero_pending_low = FULL_BETTING_SEATS_OFFSET
            + MAX_CANONICAL_SEATS * FULL_BETTING_SEAT_WIDTH
            + MAX_CANONICAL_SEATS * SEAT_STATUS_COUNT
            + 3 * MAX_CANONICAL_SEATS * 4;
        assert_air_rejects_trace_mutation(&trace, &archive, post_seat_zero_pending_low);
    }

    #[test]
    fn canonical_direct_air_proves_raise_and_short_all_in_raise() {
        for witness in [raise(), short_all_in_raise()] {
            let (trace, archive) = trace_for(std::slice::from_ref(&witness)).expect("raise trace");
            assert_trace_satisfies_air(&trace, &archive);
            let archive = prove_canonical_tagged_batch(&[witness.clone()]).expect("raise proof");
            verify_canonical_tagged_proof(&archive).expect("standalone raise verification");
            verify_canonical_tagged_batch(&[witness], &archive).expect("raise verification");
        }
    }

    #[test]
    fn canonical_direct_air_enforces_raise_reset_and_nonacting_seat_stability() {
        let witness = raise_against_acted_opponent();
        let (trace, archive) = trace_for(&[witness]).expect("raise trace");
        assert_trace_satisfies_air(&trace, &archive);

        // The post acted-bit suffix has one entry per seat.  Seat 1 is active
        // but not the raiser, so setting it back to one violates the exact VM
        // reset, independently of the host transition validator.
        assert_air_rejects_trace_mutation(&trace, &archive, 1_400);

        // The full-seat suffix binds non-acting stacks to their pre-state
        // images.  Modifying opponent stack[0] cannot be hidden behind the
        // selected seat projection used by the older AIR.
        let post_seat_one_stack_low = FULL_BETTING_SEATS_OFFSET
            + MAX_CANONICAL_SEATS * FULL_BETTING_SEAT_WIDTH
            + MAX_CANONICAL_SEATS * SEAT_STATUS_COUNT
            + 4;
        assert_air_rejects_trace_mutation(&trace, &archive, post_seat_one_stack_low);
    }

    #[test]
    fn canonical_direct_air_rejects_skipping_an_active_next_turn() {
        let mut witness = call();
        witness.pre.max_players = 3;
        witness.post.max_players = 3;
        witness.pre.seats[2] = active_opponent(false, 100);
        witness.post.seats[2] = active_opponent(false, 100);
        witness.pre.chip_pool = 2_200;
        witness.post.chip_pool = 2_200;
        witness.seal();
        let (mut trace, archive) = trace_for(&[witness]).expect("three-player call trace");
        assert_trace_satisfies_air(&trace, &archive);

        // Rebuild the next-turn advice consistently for 0 -> 2. Seat 1 is
        // Active and lies between them, so only the circular scan constraint
        // (not a stale one-hot or scalar mismatch) can reject the splice.
        trace.cols[278][0] = M31::from(2u32);
        trace.cols[NEXT_TURN_SELECTOR_OFFSET + 1][0] = M31::from(0u32);
        trace.cols[NEXT_TURN_SELECTOR_OFFSET + 2][0] = M31::from(1u32);
        trace.cols[NEXT_TURN_PAIR_OFFSET + 1][0] = M31::from(0u32);
        trace.cols[NEXT_TURN_PAIR_OFFSET + 2][0] = M31::from(1u32);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert_trace_satisfies_air(&trace, &archive);
            }))
            .is_err()
        );
    }

    #[test]
    fn canonical_direct_air_rejects_a_stale_already_acted_successor() {
        let witness = call();
        let (mut trace, archive) = trace_for(&[witness]).expect("call trace");
        assert_trace_satisfies_air(&trace, &archive);

        // Keep all old mask relations consistent while making the selected
        // successor (seat 1) already acted. Before the new successor rule,
        // this was a structurally valid but VM-impossible stale betting row.
        trace.cols[303][0] = M31::from(2u32);
        trace.cols[304][0] = M31::from(3u32);
        trace.cols[1_391][0] = M31::from(1u32);
        trace.cols[1_400][0] = M31::from(1u32);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                assert_trace_satisfies_air(&trace, &archive);
            }))
            .is_err()
        );
    }

    #[test]
    fn canonical_direct_air_rejects_raise_projection_and_advice_tampering() {
        let witness = raise();
        let (trace, archive) = trace_for(&[witness]).expect("raise trace");
        assert_trace_satisfies_air(&trace, &archive);

        // Projection fields: selected post-seat bet, post pot, and post stack.
        // These locations are in the stable canonical projection prefix.
        for column in [333, 299, 329] {
            assert_air_rejects_trace_mutation(&trace, &archive, column);
        }
        // Raise-only advice starts at 1085: needed limbs, then carries at
        // 1106 and the 16-bit decomposition at 1121.  None of these checks
        // calls `validate_batch`; rejection is solely the AIR relation.
        for column in [1085, 1106, 1121] {
            assert_air_rejects_trace_mutation(&trace, &archive, column);
        }
    }

    #[test]
    fn canonical_direct_air_rejects_raise_advice_on_non_raise_transition() {
        let witness = call();
        let (trace, archive) = trace_for(&[witness]).expect("call trace");
        // This was previously an unconstrained column on a Call row because
        // all Raise relations were selector-gated.  The canonical-zero
        // constraints above make the same malicious advice invalid without
        // relying on host validation.
        assert_air_rejects_trace_mutation(&trace, &archive, 1084);
    }

    #[test]
    fn canonical_direct_air_binds_acted_mask_to_selected_seat() {
        let witness = call();
        let (trace, archive) = trace_for(&[witness]).expect("call trace");
        assert_trace_satisfies_air(&trace, &archive);

        // 304 is the canonical post acted-mask projection.  It is now linked
        // to nine boolean mask bits and to the selected seat's `acted` flag,
        // rather than being accepted as a host-provided scalar.
        assert_air_rejects_trace_mutation(&trace, &archive, 304);
        // The appended selected-seat/mask advice begins at the former trace
        // width 1381: selector[0], then pre bits, then post bits.  Tampering
        // with post bit 0 must fail independently of the raw mask field.
        assert_air_rejects_trace_mutation(&trace, &archive, 1_399);
    }

    #[test]
    fn canonical_direct_air_rejects_splices_and_invalid_transition_authority() {
        let first = create_table();
        let mut second = first.clone();
        second.pre = first.post.clone();
        second.post = second.pre.clone();
        second.post.call_seq += 1;
        second.seal();
        assert!(trace_for(&[first.clone(), second.clone()]).is_ok());

        let mut spliced = second.clone();
        spliced.pre.table_id = 8;
        spliced.post.table_id = 8;
        spliced.seal();
        assert!(prove_canonical_tagged_batch(&[first.clone(), spliced]).is_err());

        let mut wrong_actor = first;
        wrong_actor.actor = [0; 32];
        wrong_actor.seal();
        assert!(prove_canonical_tagged_batch(&[wrong_actor]).is_err());

        let mut sequence_reset = second;
        sequence_reset.post.call_seq = 0;
        sequence_reset.seal();
        assert!(prove_canonical_tagged_batch(&[sequence_reset]).is_err());
    }

    #[test]
    fn canonical_direct_air_rejects_early_deadlines_and_immutable_settlement_mutation() {
        let mut early = advance_deadline();
        early.deadline_height = 9;
        early.seal();
        assert!(prove_canonical_tagged_batch(&[early]).is_err());

        let mut settlement_mutation = create_table();
        settlement_mutation.post.settlement_commitment[0] ^= 1;
        settlement_mutation.seal();
        assert!(prove_canonical_tagged_batch(&[settlement_mutation]).is_err());

        let mut permissionless_actor = advance_deadline();
        permissionless_actor.actor = [2; 32];
        permissionless_actor.seal();
        assert!(prove_canonical_tagged_batch(&[permissionless_actor]).is_err());
    }

    #[test]
    fn canonical_direct_air_accepts_betting_time_bank_extension() {
        let witness = advance_deadline();
        let (trace, archive) = trace_for(std::slice::from_ref(&witness)).expect("deadline trace");
        assert_trace_satisfies_air(&trace, &archive);
        prove_canonical_tagged_batch(&[witness]).expect("deadline proof");
    }

    #[test]
    fn canonical_direct_air_rejects_betting_time_bank_extension_tampering() {
        let witness = advance_deadline();
        let (trace, archive) = trace_for(std::slice::from_ref(&witness)).expect("deadline trace");
        let selected_post_time_bank_offset = FULL_POST_BETTING_SEATS_OFFSET
            + FULL_SEAT_STACK_BLOCK_OFFSET
            + 4 * MAX_CANONICAL_SEATS * 4;
        for column in [
            ADVANCE_DEADLINE_TIME_BANK_ALL_OFFSET,
            ADVANCE_DEADLINE_TIME_BANK_SLACK_OFFSET,
            ADVANCE_DEADLINE_TIME_BANK_EXCESS_OFFSET,
            ADVANCE_DEADLINE_TIME_BANK_CARRIES_OFFSET,
            ADVANCE_DEADLINE_EXTENSION_CARRIES_OFFSET,
            selected_post_time_bank_offset,
            ACTION_AMOUNT_OFFSET,
            TRANSITION_SEAT_SELECTOR_OFFSET,
        ] {
            assert_air_rejects_trace_mutation(&trace, &archive, column);
        }
    }

    #[test]
    fn canonical_archive_metadata_is_authenticated() {
        let archive = prove_canonical_tagged_batch(&[create_table()]).expect("canonical proof");
        let mut wrong_table = archive.clone();
        wrong_table.table_id ^= 1;
        assert!(verify_canonical_tagged_proof(&wrong_table).is_err());

        let mut wrong_post = archive.clone();
        wrong_post.post_state_commitment[0] ^= 1;
        assert!(verify_canonical_tagged_proof(&wrong_post).is_err());

        let mut wrong_state_root = archive.clone();
        wrong_state_root.post_state_root[0] ^= 1;
        assert!(verify_canonical_tagged_proof(&wrong_state_root).is_err());

        let mut wrong_count = archive;
        wrong_count.transition_count = 2;
        assert!(verify_canonical_tagged_proof(&wrong_count).is_err());
    }
}
