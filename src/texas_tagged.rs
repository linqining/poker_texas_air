//! Canonical heterogeneous Texas Poker transition AIR.
//!
//! This module is intentionally independent from [`crate::prove_task::ProveTask`].  A
//! transition witness is a compact state image plus one canonical action.  The verifier
//! reconstructs the row from that witness and checks the transition relation in this AIR;
//! it does not replay the Texas VM or a transaction command stream.
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

use crate::airs::common::{
    MAX_TOTAL_BET, ZERO, compute_add_carries, compute_bound_carries, max_total_bet_limbs,
    u64_to_m31_limbs,
};
use crate::error::{TexasAirError, TexasAirResult};
use crate::trace_gen::MethodTrace;
use crate::trace_gen::generic_trace::{BATCH_LOG_SIZE, tagged_batch_log_size};

pub const MAX_SEATS: usize = 9;
const LOG_SIZE: u32 = BATCH_LOG_SIZE;

/// Fixed-width seat state used by the canonical witness ABI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TexasSeatImage {
    pub occupied: bool,
    pub folded: bool,
    pub all_in: bool,
    pub acted: bool,
    pub stack: u64,
    pub bet: u64,
    pub total_bet: u64,
    /// Chips committed for the next hand by an addon request.
    pub pending_addon: u64,
}

/// Minimal state image required by the betting transition AIR.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TexasStateImage {
    pub table_id: u64,
    pub hand_id: u32,
    pub call_seq: u32,
    pub round_state: u8,
    pub current_turn: u8,
    pub current_bet: u64,
    pub min_raise: u64,
    pub pot: u64,
    pub button: u8,
    /// Canonical table capacity. Seats at or above this value must be empty.
    pub max_players: u8,
    /// Total chips held by the table vault.
    pub chip_pool: u64,
    /// Seats requested to leave after the current hand.
    pub leave_after_hand_mask: u16,
    pub seats: [TexasSeatImage; MAX_SEATS],
}

impl TexasStateImage {
    /// Return the canonical commitment to this fixed-width state image.
    ///
    /// This is a commitment, not a consensus state-root proof. A production caller must
    /// authenticate it against a finalized receipt (or provide an in-circuit state-root
    /// opening) before using it for chain admission.
    pub fn commitment(&self) -> [u8; 32] {
        self.digest(b"zchain.texas.state-image.v1")
    }

    fn digest(&self, domain: &[u8]) -> [u8; 32] {
        let encoded = borsh::to_vec(self).expect("fixed state image is serializable");
        let mut h = Blake2bVar::new(32).expect("32-byte Blake2 digest");
        h.update(domain);
        h.update(&encoded);
        let mut out = [0u8; 32];
        h.finalize_variable(&mut out).expect("fixed digest length");
        out
    }
}

/// Canonical action tag. `Bet` carries an increment; `Raise` carries an absolute round bet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum TexasAction {
    Fold {
        seat: u8,
    },
    Check {
        seat: u8,
    },
    Call {
        seat: u8,
    },
    Raise {
        seat: u8,
        raise_to: u64,
    },
    Bet {
        seat: u8,
        amount: u64,
    },
    /// Add chips for the next hand without changing the current stack.
    Addon {
        seat: u8,
        amount: u64,
    },
    /// Add chips to the current stack immediately.
    Rebuy {
        seat: u8,
        amount: u64,
    },
    /// Change the leave-after-hand bit. Repeating the current value is a no-op
    /// in the VM and is intentionally not a transition witness.
    SetLeaveAfterHand {
        seat: u8,
        want_leave: bool,
    },
}

impl TexasAction {
    fn tag(self) -> u8 {
        match self {
            Self::Fold { .. } => 0,
            Self::Check { .. } => 1,
            Self::Call { .. } => 2,
            Self::Raise { .. } => 3,
            Self::Bet { .. } => 4,
            Self::Addon { .. } => 5,
            Self::Rebuy { .. } => 6,
            Self::SetLeaveAfterHand { .. } => 7,
        }
    }
    fn seat(self) -> u8 {
        match self {
            Self::Fold { seat }
            | Self::Check { seat }
            | Self::Call { seat }
            | Self::Raise { seat, .. }
            | Self::Bet { seat, .. }
            | Self::Addon { seat, .. }
            | Self::Rebuy { seat, .. }
            | Self::SetLeaveAfterHand { seat, .. } => seat,
        }
    }
    fn amount(self) -> u64 {
        match self {
            Self::Fold { .. }
            | Self::Check { .. }
            | Self::Call { .. }
            | Self::SetLeaveAfterHand { .. } => 0,
            Self::Raise { raise_to, .. } => raise_to,
            Self::Bet { amount, .. } | Self::Addon { amount, .. } | Self::Rebuy { amount, .. } => {
                amount
            }
        }
    }
}

/// A no-replay proof witness.  The action is checked against both images by pure arithmetic.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TexasTransitionWitness {
    pub pre: TexasStateImage,
    pub post: TexasStateImage,
    pub action: TexasAction,
}

/// Public scope returned for callers that want to bind a proof to consensus metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TexasTransitionPublic {
    pub table_id: u64,
    pub hand_id: u32,
    pub first_call_seq: u32,
    pub last_call_seq: u32,
    pub transition_count: u16,
    pub batch_digest: [u8; 32],
    /// Commitment of the first pre-state image in the batch.
    pub pre_state_commitment: [u8; 32],
    /// Commitment of the last post-state image in the batch.
    pub post_state_commitment: [u8; 32],
}

fn next_turn(state: &TexasStateImage, from: u8) -> u8 {
    // Scan each other seat exactly once; wrapping back to `from` would make a
    // completed round appear to have another action for the same player.
    for offset in 1..MAX_SEATS {
        let idx = (usize::from(from) + offset) % MAX_SEATS;
        let seat = state.seats[idx];
        if seat.occupied && !seat.folded && !seat.all_in && !seat.acted {
            return idx as u8;
        }
    }
    u8::MAX
}

fn validate_state_image(state: &TexasStateImage) -> TexasAirResult<()> {
    if state.max_players < 2 || usize::from(state.max_players) > MAX_SEATS {
        return Err(TexasAirError::SpecViolation(
            "max_players must be within 2..=MAX_SEATS".into(),
        ));
    }
    if usize::from(state.button) >= usize::from(state.max_players)
        || (state.current_turn != u8::MAX
            && usize::from(state.current_turn) >= usize::from(state.max_players))
    {
        return Err(TexasAirError::SpecViolation(
            "button/current_turn is outside the seat domain".into(),
        ));
    }
    if state.leave_after_hand_mask >> state.max_players != 0 {
        return Err(TexasAirError::SpecViolation(
            "leave-after-hand mask exceeds table capacity".into(),
        ));
    }
    if state.chip_pool > MAX_TOTAL_BET {
        return Err(TexasAirError::SpecViolation(
            "chip_pool exceeds MAX_TOTAL_BET".into(),
        ));
    }
    let max_bet = state.seats.iter().map(|seat| seat.bet).max().unwrap_or(0);
    if state.current_bet > max_bet {
        return Err(TexasAirError::SpecViolation(
            "current_bet exceeds seat bet".into(),
        ));
    }
    for (index, seat) in state.seats.into_iter().enumerate() {
        if index >= usize::from(state.max_players) && seat.occupied {
            return Err(TexasAirError::SpecViolation(
                "seat outside table capacity is occupied".into(),
            ));
        }
        if !seat.occupied {
            if seat.folded
                || seat.all_in
                || seat.acted
                || seat.stack != 0
                || seat.bet != 0
                || seat.total_bet != 0
                || seat.pending_addon != 0
            {
                return Err(TexasAirError::SpecViolation(
                    "empty seat carries state".into(),
                ));
            }
        }
        if seat.total_bet < seat.bet {
            return Err(TexasAirError::SpecViolation(
                "total_bet is below round bet".into(),
            ));
        }
        if seat.occupied && seat.bet > state.current_bet {
            return Err(TexasAirError::SpecViolation(
                "seat bet exceeds current_bet".into(),
            ));
        }
        // The VM stores Folded and AllIn as mutually exclusive tags. A folded player may
        // have exhausted the stack, so an empty stack implies AllIn only for a live seat.
        if seat.all_in != (seat.stack == 0 && seat.occupied && !seat.folded) {
            return Err(TexasAirError::SpecViolation(
                "all_in flag does not match an active zero stack".into(),
            ));
        }
    }
    Ok(())
}

fn ensure_same_except(a: &TexasStateImage, b: &TexasStateImage, seat: usize) -> TexasAirResult<()> {
    let mut aa = a.clone();
    let mut bb = b.clone();
    // These fields are the explicit transition outputs and are checked by the
    // action-specific branches below. Every other state field must be immutable.
    aa.call_seq = 0;
    bb.call_seq = 0;
    aa.current_turn = 0;
    bb.current_turn = 0;
    aa.current_bet = 0;
    bb.current_bet = 0;
    aa.min_raise = 0;
    bb.min_raise = 0;
    aa.seats[seat] = TexasSeatImage {
        occupied: false,
        folded: false,
        all_in: false,
        acted: false,
        stack: 0,
        bet: 0,
        total_bet: 0,
        pending_addon: 0,
    };
    bb.seats[seat] = TexasSeatImage {
        occupied: false,
        folded: false,
        all_in: false,
        acted: false,
        stack: 0,
        bet: 0,
        total_bet: 0,
        pending_addon: 0,
    };
    if aa != bb {
        return Err(TexasAirError::SpecViolation(
            "non-acting state field changed".into(),
        ));
    }
    Ok(())
}

fn ensure_fund_same_except(
    a: &TexasStateImage,
    b: &TexasStateImage,
    seat: usize,
) -> TexasAirResult<()> {
    let mut aa = a.clone();
    let mut bb = b.clone();
    aa.call_seq = 0;
    bb.call_seq = 0;
    aa.chip_pool = 0;
    bb.chip_pool = 0;
    aa.seats[seat] = TexasSeatImage {
        occupied: false,
        folded: false,
        all_in: false,
        acted: false,
        stack: 0,
        bet: 0,
        total_bet: 0,
        pending_addon: 0,
    };
    bb.seats[seat] = aa.seats[seat];
    if aa != bb {
        return Err(TexasAirError::SpecViolation(
            "non-funding state field changed".into(),
        ));
    }
    Ok(())
}

fn ensure_leave_same_except(a: &TexasStateImage, b: &TexasStateImage) -> TexasAirResult<()> {
    let mut aa = a.clone();
    let mut bb = b.clone();
    aa.call_seq = 0;
    bb.call_seq = 0;
    aa.leave_after_hand_mask = 0;
    bb.leave_after_hand_mask = 0;
    if aa != bb {
        return Err(TexasAirError::SpecViolation(
            "non-leave state field changed".into(),
        ));
    }
    Ok(())
}

/// Validate one action without invoking any VM code or transaction replay.
pub fn validate_transition(w: &TexasTransitionWitness) -> TexasAirResult<()> {
    let pre = &w.pre;
    let post = &w.post;
    validate_state_image(pre)?;
    validate_state_image(post)?;
    let seat = usize::from(w.action.seat());
    if seat >= usize::from(pre.max_players) {
        return Err(TexasAirError::SpecViolation(
            "action seat is outside table capacity".into(),
        ));
    }
    if pre.table_id != post.table_id || pre.hand_id != post.hand_id {
        return Err(TexasAirError::SpecViolation(
            "table/hand scope changed".into(),
        ));
    }
    if post.call_seq
        != pre
            .call_seq
            .checked_add(1)
            .ok_or_else(|| TexasAirError::SpecViolation("call_seq overflow".into()))?
    {
        return Err(TexasAirError::SpecViolation(
            "post call_seq must equal pre + 1".into(),
        ));
    }
    let before = pre.seats[seat];
    if !before.occupied {
        return Err(TexasAirError::SpecViolation(
            "action seat is not occupied".into(),
        ));
    }
    match w.action {
        TexasAction::Addon { amount, .. } => {
            if amount == 0 {
                return Err(TexasAirError::SpecViolation(
                    "addon amount must be non-zero".into(),
                ));
            }
            ensure_fund_same_except(pre, post, seat)?;
            if post.call_seq
                != pre
                    .call_seq
                    .checked_add(1)
                    .ok_or_else(|| TexasAirError::SpecViolation("call_seq overflow".into()))?
                || post.chip_pool
                    != pre
                        .chip_pool
                        .checked_add(amount)
                        .ok_or_else(|| TexasAirError::SpecViolation("chip_pool overflow".into()))?
                || post.seats[seat].pending_addon
                    != before.pending_addon.checked_add(amount).ok_or_else(|| {
                        TexasAirError::SpecViolation("pending_addon overflow".into())
                    })?
                || post.seats[seat].stack != before.stack
                || post.seats[seat].bet != before.bet
                || post.seats[seat].total_bet != before.total_bet
            {
                return Err(TexasAirError::SpecViolation(
                    "addon mutation is invalid".into(),
                ));
            }
            return Ok(());
        }
        TexasAction::Rebuy { amount, .. } => {
            if amount == 0 {
                return Err(TexasAirError::SpecViolation(
                    "rebuy amount must be non-zero".into(),
                ));
            }
            ensure_fund_same_except(pre, post, seat)?;
            if post.call_seq
                != pre
                    .call_seq
                    .checked_add(1)
                    .ok_or_else(|| TexasAirError::SpecViolation("call_seq overflow".into()))?
                || post.chip_pool
                    != pre
                        .chip_pool
                        .checked_add(amount)
                        .ok_or_else(|| TexasAirError::SpecViolation("chip_pool overflow".into()))?
                || post.seats[seat].stack
                    != before
                        .stack
                        .checked_add(amount)
                        .ok_or_else(|| TexasAirError::SpecViolation("stack overflow".into()))?
                || post.seats[seat].pending_addon != before.pending_addon
                || post.seats[seat].bet != before.bet
                || post.seats[seat].total_bet != before.total_bet
            {
                return Err(TexasAirError::SpecViolation(
                    "rebuy mutation is invalid".into(),
                ));
            }
            return Ok(());
        }
        TexasAction::SetLeaveAfterHand { want_leave, .. } => {
            ensure_leave_same_except(pre, post)?;
            let bit = 1u16 << seat;
            let was_set = pre.leave_after_hand_mask & bit != 0;
            if was_set == want_leave {
                return Err(TexasAirError::SpecViolation(
                    "idempotent leave request is not a transition".into(),
                ));
            }
            let expected_mask = if want_leave {
                pre.leave_after_hand_mask | bit
            } else {
                pre.leave_after_hand_mask & !bit
            };
            if post.call_seq
                != pre
                    .call_seq
                    .checked_add(1)
                    .ok_or_else(|| TexasAirError::SpecViolation("call_seq overflow".into()))?
                || post.leave_after_hand_mask != expected_mask
            {
                return Err(TexasAirError::SpecViolation(
                    "leave-after-hand mutation is invalid".into(),
                ));
            }
            return Ok(());
        }
        _ => {}
    }
    if pre.current_turn != w.action.seat()
        || pre.round_state < 2
        || pre.round_state > 5
        || pre.min_raise == 0
        || post.round_state != pre.round_state
        || post.pot != pre.pot
    {
        return Err(TexasAirError::UnsupportedBettingTransition(
            "only mid-round betting transitions are enabled".into(),
        ));
    }
    if before.folded || before.all_in || before.acted {
        return Err(TexasAirError::SpecViolation(
            "seat is not actionable".into(),
        ));
    }
    ensure_same_except(pre, post, seat)?;
    let after = post.seats[seat];
    if !after.occupied || !after.acted {
        return Err(TexasAirError::SpecViolation(
            "invalid post acted/current_turn".into(),
        ));
    }
    let expected_turn = next_turn(pre, w.action.seat());
    if expected_turn == u8::MAX {
        return Err(TexasAirError::UnsupportedBettingTransition(
            "action completes the betting round".into(),
        ));
    }
    if post.current_turn != expected_turn {
        return Err(TexasAirError::SpecViolation(
            "invalid post current_turn".into(),
        ));
    }
    if after.occupied != before.occupied {
        return Err(TexasAirError::SpecViolation(
            "acting seat occupancy changed".into(),
        ));
    }
    if post.current_bet > post.seats.iter().map(|s| s.bet).max().unwrap_or(0) {
        return Err(TexasAirError::SpecViolation(
            "post current_bet exceeds seat bet".into(),
        ));
    }
    match w.action {
        TexasAction::Fold { .. } => {
            if !after.folded
                || after.all_in != before.all_in
                || after.stack != before.stack
                || after.bet != before.bet
                || after.total_bet != before.total_bet
            {
                return Err(TexasAirError::SpecViolation(
                    "fold mutation is invalid".into(),
                ));
            }
        }
        TexasAction::Check { .. } => {
            let expected = TexasSeatImage {
                acted: true,
                ..before
            };
            if pre.current_bet != before.bet
                || after != expected
                || post.current_bet != pre.current_bet
                || post.min_raise != pre.min_raise
            {
                return Err(TexasAirError::SpecViolation(
                    "check requires matched bet and unchanged amounts".into(),
                ));
            }
        }
        TexasAction::Call { .. } => {
            let owed = pre.current_bet.checked_sub(before.bet).ok_or_else(|| {
                TexasAirError::SpecViolation("seat bet exceeds current bet".into())
            })?;
            let delta = owed.min(before.stack);
            if delta == 0
                || after.folded
                || after.stack != before.stack - delta
                || after.bet != before.bet + delta
                || after.total_bet != before.total_bet + delta
                || after.all_in != (after.stack == 0)
                || post.current_bet != pre.current_bet
                || post.min_raise != pre.min_raise
            {
                return Err(TexasAirError::SpecViolation(
                    "call mutation is invalid".into(),
                ));
            }
        }
        TexasAction::Raise { raise_to, .. } => {
            let delta = raise_to
                .checked_sub(before.bet)
                .ok_or_else(|| TexasAirError::SpecViolation("raise_to below seat bet".into()))?;
            let inc = raise_to
                .checked_sub(pre.current_bet)
                .ok_or_else(|| TexasAirError::SpecViolation("raise_to below current bet".into()))?;
            if inc == 0
                || delta > before.stack
                || (inc < pre.min_raise && delta != before.stack)
                || after.folded
                || after.stack != before.stack - delta
                || after.bet != raise_to
                || after.total_bet != before.total_bet + delta
                || after.all_in != (after.stack == 0)
                || post.current_bet != raise_to
                || post.min_raise
                    != if inc >= pre.min_raise {
                        inc
                    } else {
                        pre.min_raise
                    }
            {
                return Err(TexasAirError::SpecViolation(
                    "raise mutation is invalid".into(),
                ));
            }
        }
        TexasAction::Bet { amount, .. } => {
            let raise_to = before
                .bet
                .checked_add(amount)
                .ok_or_else(|| TexasAirError::SpecViolation("bet overflow".into()))?;
            if amount == 0 || pre.current_bet != before.bet {
                return Err(TexasAirError::SpecViolation(
                    "bet requires an unopened postflop round".into(),
                ));
            }
            let delta = raise_to - before.bet;
            if delta > before.stack
                || after.folded
                || after.stack != before.stack - delta
                || after.bet != raise_to
                || after.total_bet != before.total_bet + delta
                || after.all_in != (after.stack == 0)
                || post.current_bet != raise_to
                || post.min_raise != amount
            {
                return Err(TexasAirError::SpecViolation(
                    "bet mutation is invalid".into(),
                ));
            }
        }
        TexasAction::Addon { .. }
        | TexasAction::Rebuy { .. }
        | TexasAction::SetLeaveAfterHand { .. } => unreachable!("handled before betting checks"),
    }
    Ok(())
}

// The original 69 columns modeled only the selected seat's betting fields. The
// appended direct columns make Addon/Rebuy/SetLeaveAfterHand real AIR branches:
// every money limb is range checked, additions have ripple carries, deposits
// prove the vault bound, and leave requests prove a single selected mask-bit
// change.  They still are not an authenticated full-table state opening; that
// binding is deliberately kept explicit in the no-replay roadmap.
// The final eight columns are the row's table/hand/sequence scope.  They are
// bound against verifier-reconstructed preprocessed columns below, so a proof
// cannot move a valid betting row into a different table or sequence slot.
// The final scope columns also carry the post-call sequence and a one-bit
// carry.  Keeping the post sequence in the trace matters: a verifier-free
// STARK must prove the transition increment itself, not merely commit the
// pre-state sequence in a public scope.
const NUM_COLUMNS: usize = 698;
const PREPROCESSED_COLUMNS: usize = 9; // active + table(4) + hand(2) + call-seq(2)

fn u16_to_bits(value: u16) -> [M31; 16] {
    std::array::from_fn(|index| M31::from(u32::from((value >> index) & 1)))
}

fn u64_to_bits(value: u64) -> [[M31; 16]; 4] {
    std::array::from_fn(|limb| u16_to_bits(((value >> (limb * 16)) & 0xffff) as u16))
}

fn append_u64_bits(out: &mut Vec<M31>, value: u64) {
    for bits in u64_to_bits(value) {
        out.extend(bits);
    }
}

fn append_u32_limbs(out: &mut Vec<M31>, value: u32) {
    out.push(M31::from(value & 0xffff));
    out.push(M31::from(value >> 16));
}

fn row(w: &TexasTransitionWitness) -> Vec<M31> {
    let s = usize::from(w.action.seat());
    let a = w.pre.seats[s];
    let b = w.post.seats[s];
    let action_amount = match w.action {
        TexasAction::Call { .. } => w.pre.current_bet.saturating_sub(a.bet).min(a.stack),
        _ => w.action.amount(),
    };
    let tag = w.action.tag();
    let mut out = vec![M31::from(1u32), M31::from(u32::from(tag))];
    out.extend((0..8).map(|index| M31::from(u32::from(index == usize::from(tag)))));
    out.push(M31::from(u32::from(w.action.seat())));
    out.extend(u64_to_m31_limbs(a.bet));
    out.extend(u64_to_m31_limbs(a.stack));
    out.extend(u64_to_m31_limbs(a.total_bet));
    out.extend(u64_to_m31_limbs(action_amount));
    out.extend(u64_to_m31_limbs(b.bet));
    out.extend(u64_to_m31_limbs(b.stack));
    out.extend(u64_to_m31_limbs(b.total_bet));
    out.extend(u64_to_m31_limbs(w.pre.current_bet));
    out.extend(u64_to_m31_limbs(w.post.current_bet));
    out.extend(u64_to_m31_limbs(w.pre.min_raise));
    out.extend(u64_to_m31_limbs(w.post.min_raise));
    out.push(M31::from(u32::from(w.pre.current_turn)));
    out.push(M31::from(u32::from(w.post.current_turn)));
    out.push(M31::from(if b.acted { 1 } else { 0 }));
    out.push(M31::from(if b.all_in { 1 } else { 0 }));
    out.push(M31::from(if b.folded { 1 } else { 0 }));
    out.push(M31::from(if a.folded { 1 } else { 0 }));
    for digest in [
        w.pre.digest(b"zchain.texas.state-image.pre.v1"),
        w.post.digest(b"zchain.texas.state-image.post.v1"),
    ] {
        for word in digest.chunks_exact(4).take(4) {
            out.push(M31::from(
                u32::from_be_bytes(word.try_into().unwrap()) & 0x7fff_ffff,
            ));
        }
    }

    // Funding data and arithmetic witnesses.  For non-funding rows the values
    // are still canonical zero/field values so their global range constraints
    // remain meaningful without adding a separate padding layout.
    let funding = matches!(
        w.action,
        TexasAction::Addon { .. } | TexasAction::Rebuy { .. }
    );
    let pre_pending = a.pending_addon;
    let post_pending = b.pending_addon;
    let pre_chip_pool = w.pre.chip_pool;
    let post_chip_pool = w.post.chip_pool;
    out.extend(u64_to_m31_limbs(pre_pending));
    out.extend(u64_to_m31_limbs(post_pending));
    out.extend(u64_to_m31_limbs(pre_chip_pool));
    out.extend(u64_to_m31_limbs(post_chip_pool));
    let amount_sum = u64_to_m31_limbs(action_amount)
        .into_iter()
        .map(|limb| u64::from(limb.0))
        .sum::<u64>();
    // The inverse only participates in funding branches. A zero witness is
    // canonical for the remaining action tags.
    out.push(if funding {
        M31::from(amount_sum as u32).inverse()
    } else {
        ZERO
    });
    let zero_carries = [ZERO; 3];
    let pending_carries = if matches!(w.action, TexasAction::Addon { .. }) {
        compute_add_carries(pre_pending, action_amount)
    } else {
        zero_carries
    };
    let stack_carries = if matches!(w.action, TexasAction::Rebuy { .. }) {
        compute_add_carries(a.stack, action_amount)
    } else {
        zero_carries
    };
    let pool_carries = if funding {
        compute_add_carries(pre_chip_pool, action_amount)
    } else {
        zero_carries
    };
    out.extend(pending_carries);
    out.extend(stack_carries);
    out.extend(pool_carries);
    let (bound_diff, bound_carry_lo, bound_carry_hi) = if funding {
        let diff = MAX_TOTAL_BET - pre_chip_pool - action_amount;
        let (lo, hi) = compute_bound_carries(pre_chip_pool, action_amount, diff);
        (diff, lo, hi)
    } else {
        (0, zero_carries, zero_carries)
    };
    out.extend(u64_to_m31_limbs(bound_diff));
    out.extend(bound_carry_lo);
    out.extend(bound_carry_hi);
    append_u64_bits(&mut out, bound_diff);
    for value in [
        a.stack,
        b.stack,
        a.pending_addon,
        b.pending_addon,
        w.pre.chip_pool,
        w.post.chip_pool,
        action_amount,
    ] {
        append_u64_bits(&mut out, value);
    }

    // A one-hot physical-seat selection avoids a high-degree dynamic-index
    // polynomial. Capacity is 2 + a three-bit value, and the four-bit
    // difference proves the selected seat is within that capacity.
    out.push(M31::from(u32::from(a.occupied)));
    out.push(M31::from(u32::from(b.occupied)));
    out.push(M31::from(u32::from(w.pre.max_players)));
    out.push(M31::from(u32::from(w.post.max_players)));
    let capacity_offset = w.pre.max_players - 2;
    for bit in 0..3 {
        out.push(M31::from(u32::from((capacity_offset >> bit) & 1)));
    }
    for index in 0..MAX_SEATS {
        out.push(M31::from(u32::from(index == s)));
    }
    out.push(M31::from(u32::from(
        w.pre.max_players - w.action.seat() - 1,
    )));
    out.extend(u16_to_bits(u16::from(
        w.pre.max_players - w.action.seat() - 1,
    )));

    let want_leave = matches!(
        w.action,
        TexasAction::SetLeaveAfterHand {
            want_leave: true,
            ..
        }
    );
    out.push(M31::from(u32::from(want_leave)));
    out.push(M31::from(u32::from(w.pre.leave_after_hand_mask)));
    out.push(M31::from(u32::from(w.post.leave_after_hand_mask)));
    let pre_mask_bits = u16_to_bits(w.pre.leave_after_hand_mask);
    let post_mask_bits = u16_to_bits(w.post.leave_after_hand_mask);
    out.extend(pre_mask_bits);
    out.extend(post_mask_bits);
    out.push(pre_mask_bits[s]);
    out.push(post_mask_bits[s]);
    out.extend(u64_to_m31_limbs(w.pre.table_id));
    append_u32_limbs(&mut out, w.pre.hand_id);
    append_u32_limbs(&mut out, w.pre.call_seq);
    append_u32_limbs(&mut out, w.post.call_seq);
    out.push(M31::from(u32::from((w.pre.call_seq & 0xffff) == 0xffff)));
    debug_assert_eq!(out.len(), NUM_COLUMNS);
    out
}

fn padding() -> Vec<M31> {
    vec![ZERO; NUM_COLUMNS]
}

#[derive(Debug, Clone, Copy)]
struct TexasTaggedAir {
    log_size: u32,
}

fn preprocessed_column_ids() -> [PreProcessedColumnId; PREPROCESSED_COLUMNS] {
    [
        "texas.tagged.active.v1",
        "texas.tagged.table-0.v1",
        "texas.tagged.table-1.v1",
        "texas.tagged.table-2.v1",
        "texas.tagged.table-3.v1",
        "texas.tagged.hand-0.v1",
        "texas.tagged.hand-1.v1",
        "texas.tagged.call-seq-0.v1",
        "texas.tagged.call-seq-1.v1",
    ]
    .map(|id| PreProcessedColumnId { id: id.into() })
}

fn preprocessed_scope(public: &TexasTransitionPublic, log_size: u32) -> MethodTrace {
    let rows = 1usize << log_size;
    let mut trace = MethodTrace::new(log_size, PREPROCESSED_COLUMNS);
    let table = u64_to_m31_limbs(public.table_id);
    let hand = [
        M31::from(public.hand_id & 0xffff),
        M31::from(public.hand_id >> 16),
    ];
    for index in 0..rows {
        let mut values = vec![ZERO; PREPROCESSED_COLUMNS];
        if index < usize::from(public.transition_count) {
            values[0] = M31::from(1u32);
            values[1..5].copy_from_slice(&table);
            values[5..7].copy_from_slice(&hand);
            let seq = public
                .first_call_seq
                .checked_add(u32::try_from(index).expect("bounded trace row"))
                .expect("bounded call sequence");
            values[7] = M31::from(seq & 0xffff);
            values[8] = M31::from(seq >> 16);
        }
        trace.write_row(index, &values).expect("scope row width");
    }
    trace
}

fn limbs<E: EvalAtRow>(eval: &mut E) -> [E::F; 4] {
    [
        eval.next_trace_mask(),
        eval.next_trace_mask(),
        eval.next_trace_mask(),
        eval.next_trace_mask(),
    ]
}

fn bits16<E: EvalAtRow>(eval: &mut E) -> [E::F; 16] {
    std::array::from_fn(|_| eval.next_trace_mask())
}

fn range16_constraints<E: EvalAtRow>(eval: &mut E, active: &E::F, value: &E::F, bits: &[E::F; 16]) {
    let one: E::F = M31::from(1u32).into();
    let two: E::F = M31::from(2u32).into();
    let mut reconstructed = bits[0].clone();
    let mut power = two.clone();
    for bit in &bits[1..] {
        reconstructed = reconstructed + bit.clone() * power.clone();
        power = power * two.clone();
    }
    eval.add_constraint(active.clone() * (value.clone() - reconstructed));
    for bit in bits {
        eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
    }
}

fn limb4_add_constraints<E: EvalAtRow>(
    eval: &mut E,
    gate: &E::F,
    pre: &[E::F; 4],
    post: &[E::F; 4],
    amount: &[E::F; 4],
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
                * (pre[index].clone() + amount[index].clone() + carry_in[index].clone()
                    - post[index].clone()
                    - base.clone() * carry_out[index].clone()),
        );
    }
    for carry in carries {
        eval.add_constraint(carry.clone() * (carry.clone() - one.clone()));
    }
}
impl FrameworkEval for TexasTaggedAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }
    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }
    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let active = eval.next_trace_mask();
        let tag = eval.next_trace_mask();
        let tag_bits = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let seat = eval.next_trace_mask();
        let pre_bet = limbs(&mut eval);
        let pre_stack = limbs(&mut eval);
        let pre_total = limbs(&mut eval);
        let amount = limbs(&mut eval);
        let post_bet = limbs(&mut eval);
        let post_stack = limbs(&mut eval);
        let post_total = limbs(&mut eval);
        let pre_current = limbs(&mut eval);
        let post_current = limbs(&mut eval);
        let pre_min = limbs(&mut eval);
        let post_min = limbs(&mut eval);
        let pre_turn = eval.next_trace_mask();
        let post_turn = eval.next_trace_mask();
        let post_acted = eval.next_trace_mask();
        let post_all_in = eval.next_trace_mask();
        let post_folded = eval.next_trace_mask();
        let pre_folded = eval.next_trace_mask();
        let pre_digest = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let post_digest = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let pre_pending = limbs(&mut eval);
        let post_pending = limbs(&mut eval);
        let pre_chip_pool = limbs(&mut eval);
        let post_chip_pool = limbs(&mut eval);
        let amount_inv = eval.next_trace_mask();
        let pending_add_carry = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let stack_add_carry = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let chip_pool_add_carry = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let bound_diff = limbs(&mut eval);
        let bound_carry_lo = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let bound_carry_hi = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let bound_diff_bits: [[E::F; 16]; 4] = std::array::from_fn(|_| bits16(&mut eval));
        let stack_range_bits: [[E::F; 16]; 4] = std::array::from_fn(|_| bits16(&mut eval));
        let post_stack_range_bits: [[E::F; 16]; 4] = std::array::from_fn(|_| bits16(&mut eval));
        let pending_range_bits: [[E::F; 16]; 4] = std::array::from_fn(|_| bits16(&mut eval));
        let post_pending_range_bits: [[E::F; 16]; 4] = std::array::from_fn(|_| bits16(&mut eval));
        let chip_pool_range_bits: [[E::F; 16]; 4] = std::array::from_fn(|_| bits16(&mut eval));
        let post_chip_pool_range_bits: [[E::F; 16]; 4] = std::array::from_fn(|_| bits16(&mut eval));
        let amount_range_bits: [[E::F; 16]; 4] = std::array::from_fn(|_| bits16(&mut eval));
        let pre_occupied = eval.next_trace_mask();
        let post_occupied = eval.next_trace_mask();
        let max_players = eval.next_trace_mask();
        let post_max_players = eval.next_trace_mask();
        let max_player_bits = [
            eval.next_trace_mask(),
            eval.next_trace_mask(),
            eval.next_trace_mask(),
        ];
        let seat_selectors: [E::F; MAX_SEATS] = std::array::from_fn(|_| eval.next_trace_mask());
        let capacity_diff = eval.next_trace_mask();
        let capacity_diff_bits = bits16(&mut eval);
        let want_leave = eval.next_trace_mask();
        let pre_leave_mask = eval.next_trace_mask();
        let post_leave_mask = eval.next_trace_mask();
        let pre_leave_bits = bits16(&mut eval);
        let post_leave_bits = bits16(&mut eval);
        let pre_selected_leave = eval.next_trace_mask();
        let post_selected_leave = eval.next_trace_mask();
        let row_table = limbs(&mut eval);
        let row_hand = [eval.next_trace_mask(), eval.next_trace_mask()];
        let row_call_seq = [eval.next_trace_mask(), eval.next_trace_mask()];
        let row_post_call_seq = [eval.next_trace_mask(), eval.next_trace_mask()];
        let seq_carry = eval.next_trace_mask();
        let ids = preprocessed_column_ids();
        let expected_active = eval.get_preprocessed_column(ids[0].clone());
        let expected_table = [
            eval.get_preprocessed_column(ids[1].clone()),
            eval.get_preprocessed_column(ids[2].clone()),
            eval.get_preprocessed_column(ids[3].clone()),
            eval.get_preprocessed_column(ids[4].clone()),
        ];
        let expected_hand = [
            eval.get_preprocessed_column(ids[5].clone()),
            eval.get_preprocessed_column(ids[6].clone()),
        ];
        let expected_call_seq = [
            eval.get_preprocessed_column(ids[7].clone()),
            eval.get_preprocessed_column(ids[8].clone()),
        ];
        let one: E::F = M31::from(1u32).into();
        let zero: E::F = M31::from(0u32).into();
        // The mask is verifier-owned, not a prover witness.  This both excludes
        // the all-padding proof and binds every active row to the public batch
        // table/hand/sequence slot.
        eval.add_constraint(active.clone() - expected_active);
        for (actual, expected) in row_table.iter().zip(expected_table.iter()) {
            eval.add_constraint(actual.clone() - expected.clone());
        }
        for (actual, expected) in row_hand.iter().zip(expected_hand.iter()) {
            eval.add_constraint(actual.clone() - expected.clone());
        }
        for (actual, expected) in row_call_seq.iter().zip(expected_call_seq.iter()) {
            eval.add_constraint(actual.clone() - expected.clone());
        }
        eval.add_constraint(active.clone() * (active.clone() - one.clone()));
        let mut tag_sum = zero.clone();
        let mut tag_from_bits = zero.clone();
        for (index, bit) in tag_bits.iter().enumerate() {
            eval.add_constraint(active.clone() * bit.clone() * (bit.clone() - one.clone()));
            eval.add_constraint((one.clone() - active.clone()) * bit.clone());
            tag_sum = tag_sum + bit.clone();
            let coefficient: E::F = M31::from(index as u32).into();
            tag_from_bits = tag_from_bits + coefficient * bit.clone();
        }
        eval.add_constraint(tag_sum - active.clone());
        eval.add_constraint(active.clone() * (tag.clone() - tag_from_bits));
        let is_betting = tag_bits[0].clone()
            + tag_bits[1].clone()
            + tag_bits[2].clone()
            + tag_bits[3].clone()
            + tag_bits[4].clone();
        eval.add_constraint(is_betting.clone() * (seat.clone() - pre_turn.clone()));
        eval.add_constraint(is_betting.clone() * (post_acted.clone() - one.clone()));
        for flag in [&post_acted, &post_all_in, &post_folded] {
            eval.add_constraint(is_betting.clone() * flag.clone() * (flag.clone() - one.clone()));
        }
        // Padding rows carry no witness payload. This prevents an inactive row from
        // satisfying a later action constraint with arbitrary non-zero limbs.
        let inactive = one.clone() - active.clone();
        for value in pre_bet
            .iter()
            .chain(pre_stack.iter())
            .chain(pre_total.iter())
            .chain(amount.iter())
            .chain(post_bet.iter())
            .chain(post_stack.iter())
            .chain(post_total.iter())
            .chain(pre_current.iter())
            .chain(post_current.iter())
            .chain(pre_min.iter())
            .chain(post_min.iter())
            .chain(pre_digest.iter())
            .chain(post_digest.iter())
            .chain(
                [
                    &tag,
                    &seat,
                    &pre_turn,
                    &post_turn,
                    &post_acted,
                    &post_all_in,
                    &post_folded,
                    &pre_folded,
                    &row_post_call_seq[0],
                    &row_post_call_seq[1],
                    &seq_carry,
                ]
                .into_iter(),
            )
        {
            eval.add_constraint(inactive.clone() * value.clone());
        }
        for value in pre_pending
            .iter()
            .chain(post_pending.iter())
            .chain(pre_chip_pool.iter())
            .chain(post_chip_pool.iter())
            .chain(bound_diff.iter())
            .chain(
                [
                    &amount_inv,
                    &pre_occupied,
                    &post_occupied,
                    &max_players,
                    &post_max_players,
                    &capacity_diff,
                    &want_leave,
                    &pre_leave_mask,
                    &post_leave_mask,
                    &pre_selected_leave,
                    &post_selected_leave,
                ]
                .into_iter(),
            )
        {
            eval.add_constraint(inactive.clone() * value.clone());
        }
        let is_fold = tag_bits[0].clone();
        let is_check = tag_bits[1].clone();
        let is_call = tag_bits[2].clone();
        let is_raise = tag_bits[3].clone();
        let is_bet = tag_bits[4].clone();
        let is_addon = tag_bits[5].clone();
        let is_rebuy = tag_bits[6].clone();
        let is_leave = tag_bits[7].clone();
        let is_funding = is_addon.clone() + is_rebuy.clone();
        for i in 0..4 {
            eval.add_constraint(is_check.clone() * (post_bet[i].clone() - pre_bet[i].clone()));
            eval.add_constraint(is_check.clone() * (post_stack[i].clone() - pre_stack[i].clone()));
            eval.add_constraint(is_check.clone() * (post_total[i].clone() - pre_total[i].clone()));
            eval.add_constraint(
                is_check.clone() * (post_current[i].clone() - pre_current[i].clone()),
            );
            eval.add_constraint(is_check.clone() * (post_min[i].clone() - pre_min[i].clone()));
            eval.add_constraint(is_fold.clone() * (post_bet[i].clone() - pre_bet[i].clone()));
            eval.add_constraint(is_fold.clone() * (post_stack[i].clone() - pre_stack[i].clone()));
            eval.add_constraint(is_fold.clone() * (post_total[i].clone() - pre_total[i].clone()));
            eval.add_constraint(
                is_fold.clone() * (post_current[i].clone() - pre_current[i].clone()),
            );
            eval.add_constraint(is_fold.clone() * (post_min[i].clone() - pre_min[i].clone()));
            // `amount` is the actual chip delta for Call/Bet and the absolute
            // target bet for Raise; each branch binds it to the corresponding row.
            eval.add_constraint(
                is_call.clone() * (amount[i].clone() - post_bet[i].clone() + pre_bet[i].clone()),
            );
            eval.add_constraint(
                is_bet.clone() * (post_bet[i].clone() - pre_bet[i].clone() - amount[i].clone()),
            );
            eval.add_constraint(is_raise.clone() * (post_bet[i].clone() - amount[i].clone()));
        }
        for i in 0..4 {
            eval.add_constraint((is_fold.clone() + is_check.clone()) * amount[i].clone());
        }
        // Calls and raises/bets bind all four amount limbs.  Full arithmetic and branch validity is
        // checked by `validate_transition`; the AIR fixes every resulting limb to the witness row.
        for i in 0..4 {
            let money_gate = is_call.clone() + is_raise.clone() + is_bet.clone();
            eval.add_constraint(
                money_gate.clone()
                    * (post_total[i].clone()
                        - pre_total[i].clone()
                        - (post_bet[i].clone() - pre_bet[i].clone())),
            );
            eval.add_constraint(
                money_gate.clone()
                    * (post_stack[i].clone() + post_bet[i].clone()
                        - pre_stack[i].clone()
                        - pre_bet[i].clone()),
            );
        }
        eval.add_constraint(is_fold.clone() * (post_folded.clone() - one.clone()));
        eval.add_constraint((is_betting.clone() - is_fold.clone()) * post_folded.clone());
        for i in 0..4 {
            eval.add_constraint(
                (is_raise.clone() + is_bet.clone())
                    * (post_current[i].clone() - post_bet[i].clone()),
            );
        }
        eval.add_constraint(is_bet.clone() * (post_min[0].clone() - amount[0].clone()));
        eval.add_constraint(is_bet.clone() * (post_min[1].clone() - amount[1].clone()));
        eval.add_constraint(is_bet.clone() * (post_min[2].clone() - amount[2].clone()));
        eval.add_constraint(is_bet.clone() * (post_min[3].clone() - amount[3].clone()));

        // Every money limb used by the funding branches is a canonical 16-bit
        // limb. This is what makes the carry equations below ordinary u64
        // arithmetic rather than arithmetic modulo M31.
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
            range16_constraints(
                &mut eval,
                &active,
                &pre_pending[index],
                &pending_range_bits[index],
            );
            range16_constraints(
                &mut eval,
                &active,
                &post_pending[index],
                &post_pending_range_bits[index],
            );
            range16_constraints(
                &mut eval,
                &active,
                &pre_chip_pool[index],
                &chip_pool_range_bits[index],
            );
            range16_constraints(
                &mut eval,
                &active,
                &post_chip_pool[index],
                &post_chip_pool_range_bits[index],
            );
            range16_constraints(
                &mut eval,
                &active,
                &amount[index],
                &amount_range_bits[index],
            );
            range16_constraints(
                &mut eval,
                &is_funding,
                &bound_diff[index],
                &bound_diff_bits[index],
            );
        }

        // The selected actor must be one of the nine physical seats, and the
        // capacity witness proves its index is below canonical max_players.
        // max_players = 2 + [0,7] gives the exact valid domain 2..=9.
        let mut selector_sum = zero.clone();
        let mut selected_seat = zero.clone();
        for (index, selector) in seat_selectors.iter().enumerate() {
            eval.add_constraint(selector.clone() * (selector.clone() - one.clone()));
            selector_sum = selector_sum + selector.clone();
            let coefficient: E::F = M31::from(index as u32).into();
            selected_seat = selected_seat + coefficient * selector.clone();
        }
        eval.add_constraint(selector_sum - active.clone());
        eval.add_constraint(seat.clone() - selected_seat);
        let mut max_from_bits: E::F = M31::from(2u32).into();
        for (index, bit) in max_player_bits.iter().enumerate() {
            eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
            let coefficient: E::F = M31::from(1u32 << index).into();
            max_from_bits = max_from_bits + coefficient * bit.clone();
        }
        eval.add_constraint(active.clone() * (max_players.clone() - max_from_bits));
        eval.add_constraint(active.clone() * (post_max_players - max_players.clone()));
        range16_constraints(&mut eval, &active, &capacity_diff, &capacity_diff_bits);
        eval.add_constraint(
            active.clone()
                * (max_players.clone() - seat.clone() - one.clone() - capacity_diff.clone()),
        );

        for flag in [
            &pre_occupied,
            &post_occupied,
            &post_acted,
            &post_all_in,
            &post_folded,
            &pre_folded,
            &want_leave,
            &pre_selected_leave,
            &post_selected_leave,
        ] {
            eval.add_constraint(active.clone() * flag.clone() * (flag.clone() - one.clone()));
        }
        for occupied in [&pre_occupied, &post_occupied] {
            eval.add_constraint(
                active.clone() * occupied.clone() * (occupied.clone() - one.clone()),
            );
        }
        eval.add_constraint(is_funding.clone() * (pre_occupied.clone() - one.clone()));
        eval.add_constraint(is_funding.clone() * (post_occupied.clone() - one.clone()));
        let amount_sum = amount
            .iter()
            .fold(zero.clone(), |sum, limb| sum + limb.clone());
        eval.add_constraint(is_funding.clone() * (amount_sum * amount_inv - one.clone()));
        for index in 0..4 {
            eval.add_constraint(
                is_addon.clone() * (post_stack[index].clone() - pre_stack[index].clone()),
            );
            eval.add_constraint(
                is_rebuy.clone() * (post_pending[index].clone() - pre_pending[index].clone()),
            );
            // Betting values, round current bet and min raise stay unchanged
            // for both canonical funding operations.
            for (post, pre) in [
                (&post_bet[index], &pre_bet[index]),
                (&post_total[index], &pre_total[index]),
                (&post_current[index], &pre_current[index]),
                (&post_min[index], &pre_min[index]),
            ] {
                eval.add_constraint(is_funding.clone() * (post.clone() - pre.clone()));
            }
        }
        limb4_add_constraints(
            &mut eval,
            &is_addon,
            &pre_pending,
            &post_pending,
            &amount,
            &pending_add_carry,
        );
        limb4_add_constraints(
            &mut eval,
            &is_rebuy,
            &pre_stack,
            &post_stack,
            &amount,
            &stack_add_carry,
        );
        limb4_add_constraints(
            &mut eval,
            &is_funding,
            &pre_chip_pool,
            &post_chip_pool,
            &amount,
            &chip_pool_add_carry,
        );
        let max_total = max_total_bet_limbs();
        let base: E::F = M31::from(65536u32).into();
        let two: E::F = M31::from(2u32).into();
        let carries = [
            bound_carry_lo[0].clone() + two.clone() * bound_carry_hi[0].clone(),
            bound_carry_lo[1].clone() + two.clone() * bound_carry_hi[1].clone(),
            bound_carry_lo[2].clone() + two.clone() * bound_carry_hi[2].clone(),
        ];
        for carry in bound_carry_lo.iter().chain(bound_carry_hi.iter()) {
            eval.add_constraint(carry.clone() * (carry.clone() - one.clone()));
        }
        for index in 0..4 {
            let carry_in = if index == 0 {
                zero.clone()
            } else {
                carries[index - 1].clone()
            };
            let carry_out = if index == 3 {
                zero.clone()
            } else {
                carries[index].clone()
            };
            let expected: E::F = max_total[index].into();
            eval.add_constraint(
                is_funding.clone()
                    * (pre_chip_pool[index].clone()
                        + amount[index].clone()
                        + bound_diff[index].clone()
                        + carry_in
                        - expected
                        - base.clone() * carry_out),
            );
        }

        // SetLeaveAfterHand uses a bit decomposition of the complete u16 mask.
        // The selector converts the dynamic seat choice into degree-two rows;
        // the flip equation rejects idempotent requests.
        eval.add_constraint(
            active.clone() * want_leave.clone() * (want_leave.clone() - one.clone()),
        );
        let mut pre_mask_reconstructed = zero.clone();
        let mut post_mask_reconstructed = zero.clone();
        let mut pre_selected_from_mask = zero.clone();
        let mut post_selected_from_mask = zero.clone();
        let mut mask_delta = zero.clone();
        for index in 0..16 {
            let bit_value: E::F = M31::from(1u32 << index).into();
            eval.add_constraint(
                pre_leave_bits[index].clone() * (pre_leave_bits[index].clone() - one.clone()),
            );
            eval.add_constraint(
                post_leave_bits[index].clone() * (post_leave_bits[index].clone() - one.clone()),
            );
            pre_mask_reconstructed =
                pre_mask_reconstructed + bit_value.clone() * pre_leave_bits[index].clone();
            post_mask_reconstructed =
                post_mask_reconstructed + bit_value.clone() * post_leave_bits[index].clone();
            if index < MAX_SEATS {
                pre_selected_from_mask = pre_selected_from_mask
                    + seat_selectors[index].clone() * pre_leave_bits[index].clone();
                post_selected_from_mask = post_selected_from_mask
                    + seat_selectors[index].clone() * post_leave_bits[index].clone();
                let coefficient: E::F = M31::from(1u32 << index).into();
                mask_delta = mask_delta
                    + coefficient
                        * seat_selectors[index].clone()
                        * (post_leave_bits[index].clone() - pre_leave_bits[index].clone());
            }
        }
        eval.add_constraint(active.clone() * (pre_leave_mask.clone() - pre_mask_reconstructed));
        eval.add_constraint(active.clone() * (post_leave_mask.clone() - post_mask_reconstructed));
        eval.add_constraint(pre_selected_leave.clone() - pre_selected_from_mask);
        eval.add_constraint(post_selected_leave.clone() - post_selected_from_mask);
        eval.add_constraint(
            (active.clone() - is_leave.clone())
                * (post_leave_mask.clone() - pre_leave_mask.clone()),
        );
        eval.add_constraint(post_leave_mask - pre_leave_mask - mask_delta);
        eval.add_constraint(is_leave.clone() * (pre_occupied - one.clone()));
        eval.add_constraint(is_leave.clone() * (post_occupied - one.clone()));
        eval.add_constraint(is_leave.clone() * (post_selected_leave.clone() - want_leave));
        eval.add_constraint(
            is_leave.clone() * (pre_selected_leave + post_selected_leave - one.clone()),
        );
        for index in 0..4 {
            for (post, pre) in [
                (&post_bet[index], &pre_bet[index]),
                (&post_stack[index], &pre_stack[index]),
                (&post_total[index], &pre_total[index]),
                (&post_pending[index], &pre_pending[index]),
                (&post_chip_pool[index], &pre_chip_pool[index]),
                (&post_current[index], &pre_current[index]),
                (&post_min[index], &pre_min[index]),
            ] {
                eval.add_constraint(is_leave.clone() * (post.clone() - pre.clone()));
            }
        }
        eval.add_constraint((one.clone() - active.clone()) * tag.clone());
        // The preprocessed sequence is canonical, so this two-limb relation
        // proves post.call_seq = pre.call_seq + 1 without relying on the host
        // witness validator.  The carry is verifier-constrained to one bit.
        let seq_base: E::F = M31::from(65536u32).into();
        eval.add_constraint(seq_carry.clone() * (seq_carry.clone() - one.clone()));
        eval.add_constraint(
            active.clone()
                * (row_call_seq[0].clone() + one.clone()
                    - row_post_call_seq[0].clone()
                    - seq_base.clone() * seq_carry.clone()),
        );
        eval.add_constraint(
            active.clone()
                * (row_call_seq[1].clone() + seq_carry.clone() - row_post_call_seq[1].clone()),
        );
        let _ = (active, post_all_in);
        let _ = (post_turn, zero);
        eval
    }
}

/// Durable proof archive for one heterogeneous tagged batch.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedTaggedTexasProof {
    pub log_size: u32,
    pub num_columns: u32,
    /// Public table scope mixed into Fiat-Shamir when the proof was created.
    pub table_id: u64,
    /// Public hand scope mixed into Fiat-Shamir when the proof was created.
    pub hand_id: u32,
    /// First transition sequence in the bounded batch.
    pub first_call_seq: u32,
    /// Last transition sequence in the bounded batch.
    pub last_call_seq: u32,
    pub transition_count: u16,
    pub batch_digest: [u8; 32],
    /// Commitment of the first pre-state image in the batch.
    pub pre_state_commitment: [u8; 32],
    /// Commitment of the last post-state image in the batch.
    pub post_state_commitment: [u8; 32],
    pub stark_proof_bytes: Vec<u8>,
}

fn options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(16 * 1024 * 1024)
}
fn batch_digest(witnesses: &[TexasTransitionWitness]) -> [u8; 32] {
    let bytes = borsh::to_vec(witnesses).expect("fixed witness encoding");
    let mut h = Blake2bVar::new(32).unwrap();
    h.update(b"zchain.texas.tagged-transition-batch.v1");
    h.update(&bytes);
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).unwrap();
    out
}

fn trace_for(
    witnesses: &[TexasTransitionWitness],
) -> TexasAirResult<(MethodTrace, TexasTransitionPublic)> {
    if witnesses.is_empty() || witnesses.len() > (1 << LOG_SIZE) {
        return Err(TexasAirError::SpecViolation(
            "transition batch must contain 1..=1024 rows".into(),
        ));
    }
    for w in witnesses {
        validate_transition(w)?;
    }
    let first = &witnesses[0];
    let last = &witnesses[witnesses.len() - 1];
    for pair in witnesses.windows(2) {
        if pair[1].pre != pair[0].post {
            return Err(TexasAirError::SpecViolation(
                "transition batch is not state-contiguous".into(),
            ));
        }
    }
    let log_size = tagged_batch_log_size(witnesses.len())?;
    let mut trace = MethodTrace::new(log_size, NUM_COLUMNS);
    for (i, w) in witnesses.iter().enumerate() {
        trace.write_row(i, &row(w))?;
    }
    for i in witnesses.len()..(1usize << log_size) {
        trace.write_row(i, &padding())?;
    }
    Ok((
        trace,
        TexasTransitionPublic {
            table_id: first.pre.table_id,
            hand_id: first.pre.hand_id,
            first_call_seq: first.pre.call_seq,
            last_call_seq: last.post.call_seq,
            transition_count: u16::try_from(witnesses.len()).unwrap(),
            batch_digest: batch_digest(witnesses),
            pre_state_commitment: first.pre.commitment(),
            post_state_commitment: last.post.commitment(),
        },
    ))
}

fn mix_digest(channel: &mut Poseidon252Channel, digest: &[u8; 32]) {
    channel.mix_u32s(
        &digest
            .chunks_exact(4)
            .map(|word| u32::from_be_bytes(word.try_into().expect("4-byte digest word")))
            .collect::<Vec<_>>(),
    );
}

fn mix_public_scope(channel: &mut Poseidon252Channel, public: &TexasTransitionPublic) {
    channel.mix_u64(public.table_id);
    channel.mix_u32s(&[
        public.hand_id,
        public.first_call_seq,
        public.last_call_seq,
        u32::from(public.transition_count),
    ]);
    mix_digest(channel, &public.batch_digest);
    mix_digest(channel, &public.pre_state_commitment);
    mix_digest(channel, &public.post_state_commitment);
}

fn mix_archive_scope(channel: &mut Poseidon252Channel, archive: &ArchivedTaggedTexasProof) {
    channel.mix_u64(archive.table_id);
    channel.mix_u32s(&[
        archive.hand_id,
        archive.first_call_seq,
        archive.last_call_seq,
        u32::from(archive.transition_count),
    ]);
    mix_digest(channel, &archive.batch_digest);
    mix_digest(channel, &archive.pre_state_commitment);
    mix_digest(channel, &archive.post_state_commitment);
}

/// Prove a heterogeneous batch with one Stwo proving startup.
pub fn prove_tagged_texas_batch(
    witnesses: &[TexasTransitionWitness],
) -> TexasAirResult<ArchivedTaggedTexasProof> {
    let (trace, public) = trace_for(witnesses)?;
    let scope_trace = preprocessed_scope(&public, trace.log_size);
    let config = crate::prover_context::protocol_pcs_config();
    let twiddles =
        crate::prover_context::simd_twiddles(trace.log_size + config.fri_config.log_blowup_factor);
    let mut channel = Poseidon252Channel::default();
    mix_public_scope(&mut channel, &public);
    let mut scheme =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::with_memory_pool(
            config,
            &twiddles,
            crate::prover_context::simd_base_column_pool(),
        );
    {
        let mut b = scheme.tree_builder();
        b.extend_evals(scope_trace.to_evaluations());
        b.commit(&mut channel);
    }
    {
        let mut b = scheme.tree_builder();
        b.extend_evals(trace.to_evaluations());
        b.commit(&mut channel);
    }
    let preprocessed_ids = preprocessed_column_ids();
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&preprocessed_ids);
    let component = FrameworkComponent::new(
        &mut allocator,
        TexasTaggedAir {
            log_size: trace.log_size,
        },
        SecureField::from(0u32),
    );
    let proof = prove(&[&component], &mut channel, scheme)
        .map_err(|e: ProvingError| TexasAirError::StwoProverError(e.to_string()))?;
    let bytes = options()
        .serialize(&proof)
        .map_err(|e| TexasAirError::SerializationError(e.to_string()))?;
    Ok(ArchivedTaggedTexasProof {
        log_size: trace.log_size,
        num_columns: u32::try_from(NUM_COLUMNS).unwrap(),
        table_id: public.table_id,
        hand_id: public.hand_id,
        first_call_seq: public.first_call_seq,
        last_call_seq: public.last_call_seq,
        transition_count: public.transition_count,
        batch_digest: public.batch_digest,
        pre_state_commitment: public.pre_state_commitment,
        post_state_commitment: public.post_state_commitment,
        stark_proof_bytes: bytes,
    })
}

fn verify_archived_tagged_proof(archive: &ArchivedTaggedTexasProof) -> TexasAirResult<()> {
    if archive.log_size == 0 || archive.log_size > LOG_SIZE {
        return Err(TexasAirError::SpecViolation(
            "tagged proof log size is outside the configured bound".into(),
        ));
    }
    if archive.num_columns != NUM_COLUMNS as u32 {
        return Err(TexasAirError::SpecViolation(
            "tagged proof column count does not match the circuit".into(),
        ));
    }
    if archive.transition_count == 0
        || usize::from(archive.transition_count) > (1usize << archive.log_size)
    {
        return Err(TexasAirError::SpecViolation(
            "tagged proof transition count is outside the trace".into(),
        ));
    }
    archive
        .first_call_seq
        .checked_add(u32::from(archive.transition_count))
        .filter(|last| *last == archive.last_call_seq)
        .ok_or_else(|| {
            TexasAirError::SpecViolation("tagged proof call sequence range is invalid".into())
        })?;

    let proof: StarkProof<Poseidon252MerkleHasher> = options()
        .deserialize(&archive.stark_proof_bytes)
        .map_err(|e| TexasAirError::SerializationError(e.to_string()))?;
    let public = TexasTransitionPublic {
        table_id: archive.table_id,
        hand_id: archive.hand_id,
        first_call_seq: archive.first_call_seq,
        last_call_seq: archive.last_call_seq,
        transition_count: archive.transition_count,
        batch_digest: archive.batch_digest,
        pre_state_commitment: archive.pre_state_commitment,
        post_state_commitment: archive.post_state_commitment,
    };
    let config = crate::prover_context::protocol_pcs_config();
    let twiddles = crate::prover_context::simd_twiddles(
        archive.log_size + config.fri_config.log_blowup_factor,
    );
    let scope_trace = preprocessed_scope(&public, archive.log_size);
    let mut trusted_scope =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::with_memory_pool(
            config,
            &twiddles,
            crate::prover_context::simd_base_column_pool(),
        );
    {
        let mut builder = trusted_scope.tree_builder();
        builder.extend_evals(scope_trace.to_evaluations());
        let mut scope_channel = Poseidon252Channel::default();
        builder.commit(&mut scope_channel);
    }
    if proof.commitments.first().copied() != trusted_scope.roots().first().copied() {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "preprocessed scope commitment does not match archived public scope".into(),
        ));
    }
    let mut channel = Poseidon252Channel::default();
    mix_archive_scope(&mut channel, archive);
    let mut scheme = CommitmentSchemeVerifier::<Poseidon252MerkleChannel>::new(config);
    let pre = *proof.commitments.first().ok_or_else(|| {
        TexasAirError::SerializationError("missing preprocessed commitment".into())
    })?;
    let trace_root = *proof
        .commitments
        .get(1)
        .ok_or_else(|| TexasAirError::SerializationError("missing trace commitment".into()))?;
    scheme.commit(
        pre,
        &vec![archive.log_size; PREPROCESSED_COLUMNS],
        &mut channel,
    );
    scheme.commit(
        trace_root,
        &vec![archive.log_size; NUM_COLUMNS],
        &mut channel,
    );
    let preprocessed_ids = preprocessed_column_ids();
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&preprocessed_ids);
    let component = FrameworkComponent::new(
        &mut allocator,
        TexasTaggedAir {
            log_size: archive.log_size,
        },
        SecureField::from(0u32),
    );
    verify(&[&component], &mut channel, &mut scheme, proof)
        .map_err(|e: VerificationError| TexasAirError::ConstraintUnsatisfied(e.to_string()))
}

/// Verify a tagged proof using only its archived public scope and Stwo proof.
///
/// This is the no-transaction-replay boundary: the verifier does not need a
/// `ProveTask`, transaction payload, or native VM execution. It proves only the
/// relations encoded by [`TexasTaggedAir`]. Full-table state-root and terminal
/// VM semantics remain a separate circuit milestone and are intentionally not
/// implied by this API.
pub fn verify_tagged_texas_proof(archive: &ArchivedTaggedTexasProof) -> TexasAirResult<()> {
    verify_archived_tagged_proof(archive)
}

/// Verify a tagged batch against the supplied canonical witnesses without VM replay.
pub fn verify_tagged_texas_batch(
    witnesses: &[TexasTransitionWitness],
    archive: &ArchivedTaggedTexasProof,
) -> TexasAirResult<()> {
    let (trace, public) = trace_for(witnesses)?;
    if archive.log_size != trace.log_size
        || archive.num_columns != NUM_COLUMNS as u32
        || archive.table_id != public.table_id
        || archive.hand_id != public.hand_id
        || archive.first_call_seq != public.first_call_seq
        || archive.last_call_seq != public.last_call_seq
        || archive.transition_count != public.transition_count
        || archive.batch_digest != public.batch_digest
        || archive.pre_state_commitment != public.pre_state_commitment
        || archive.post_state_commitment != public.post_state_commitment
    {
        return Err(TexasAirError::SpecViolation(
            "tagged Texas proof scope mismatch".into(),
        ));
    }
    let proof: StarkProof<Poseidon252MerkleHasher> = options()
        .deserialize(&archive.stark_proof_bytes)
        .map_err(|e| TexasAirError::SerializationError(e.to_string()))?;
    let config = crate::prover_context::protocol_pcs_config();
    let twiddles =
        crate::prover_context::simd_twiddles(trace.log_size + config.fri_config.log_blowup_factor);
    let scope_trace = preprocessed_scope(&public, trace.log_size);
    let mut trusted =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::with_memory_pool(
            config,
            &twiddles,
            crate::prover_context::simd_base_column_pool(),
        );
    let mut ch = Poseidon252Channel::default();
    {
        let mut scope_builder = trusted.tree_builder();
        scope_builder.extend_evals(scope_trace.to_evaluations());
        scope_builder.commit(&mut ch);
    }
    {
        let mut b = trusted.tree_builder();
        b.extend_evals(trace.to_evaluations());
        b.commit(&mut ch);
    }
    let scope_root = trusted.roots()[0];
    let root = trusted.roots()[1];
    if proof.commitments.first().copied() != Some(scope_root) {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "preprocessed scope commitment does not match canonical public scope".into(),
        ));
    }
    if proof.commitments.get(1).copied() != Some(root) {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "trace commitment does not match canonical witnesses".into(),
        ));
    }
    let mut channel = Poseidon252Channel::default();
    mix_public_scope(&mut channel, &public);
    let mut scheme = CommitmentSchemeVerifier::<Poseidon252MerkleChannel>::new(config);
    let pre = *proof.commitments.first().ok_or_else(|| {
        TexasAirError::SerializationError("missing preprocessed commitment".into())
    })?;
    scheme.commit(
        pre,
        &vec![trace.log_size; PREPROCESSED_COLUMNS],
        &mut channel,
    );
    scheme.commit(root, &vec![trace.log_size; NUM_COLUMNS], &mut channel);
    let preprocessed_ids = preprocessed_column_ids();
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&preprocessed_ids);
    let component = FrameworkComponent::new(
        &mut allocator,
        TexasTaggedAir {
            log_size: trace.log_size,
        },
        SecureField::from(0u32),
    );
    verify(&[&component], &mut channel, &mut scheme, proof)
        .map_err(|e: VerificationError| TexasAirError::ConstraintUnsatisfied(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn state() -> TexasStateImage {
        let empty = TexasSeatImage {
            occupied: false,
            folded: false,
            all_in: false,
            acted: false,
            stack: 0,
            bet: 0,
            total_bet: 0,
            pending_addon: 0,
        };
        let mut seats = [empty; MAX_SEATS];
        seats[0] = TexasSeatImage {
            occupied: true,
            folded: false,
            all_in: false,
            acted: false,
            stack: 100,
            bet: 10,
            total_bet: 10,
            pending_addon: 0,
        };
        seats[1] = TexasSeatImage {
            occupied: true,
            folded: false,
            all_in: false,
            acted: false,
            stack: 100,
            bet: 10,
            total_bet: 10,
            pending_addon: 0,
        };
        TexasStateImage {
            table_id: 1,
            hand_id: 2,
            call_seq: 3,
            round_state: 3,
            current_turn: 0,
            current_bet: 10,
            min_raise: 10,
            pot: 20,
            button: 0,
            max_players: 2,
            chip_pool: 220,
            leave_after_hand_mask: 0,
            seats,
        }
    }
    fn valid_call() -> TexasTransitionWitness {
        let mut pre = state();
        pre.current_bet = 20;
        pre.seats[1].bet = 20;
        pre.seats[1].total_bet = 20;
        let mut post = pre.clone();
        post.call_seq += 1;
        post.current_turn = 1;
        post.seats[0].stack = 90;
        post.seats[0].bet = 20;
        post.seats[0].total_bet = 20;
        post.seats[0].acted = true;
        TexasTransitionWitness {
            pre,
            post,
            action: TexasAction::Call { seat: 0 },
        }
    }

    fn valid_check() -> TexasTransitionWitness {
        let pre = state();
        let mut post = pre.clone();
        post.call_seq += 1;
        post.current_turn = 1;
        post.seats[0].acted = true;
        TexasTransitionWitness {
            pre,
            post,
            action: TexasAction::Check { seat: 0 },
        }
    }

    fn valid_fold() -> TexasTransitionWitness {
        let pre = state();
        let mut post = pre.clone();
        post.call_seq += 1;
        post.current_turn = 1;
        post.seats[0].acted = true;
        post.seats[0].folded = true;
        TexasTransitionWitness {
            pre,
            post,
            action: TexasAction::Fold { seat: 0 },
        }
    }

    fn valid_raise() -> TexasTransitionWitness {
        let mut pre = state();
        pre.current_bet = 10;
        let mut post = pre.clone();
        post.call_seq += 1;
        post.current_turn = 1;
        post.current_bet = 20;
        post.seats[0].stack = 90;
        post.seats[0].bet = 20;
        post.seats[0].total_bet = 20;
        post.seats[0].acted = true;
        TexasTransitionWitness {
            pre,
            post,
            action: TexasAction::Raise {
                seat: 0,
                raise_to: 20,
            },
        }
    }

    fn valid_bet() -> TexasTransitionWitness {
        let pre = state();
        let mut post = pre.clone();
        post.call_seq += 1;
        post.current_turn = 1;
        post.current_bet = 20;
        post.min_raise = 10;
        post.seats[0].stack = 90;
        post.seats[0].bet = 20;
        post.seats[0].total_bet = 20;
        post.seats[0].acted = true;
        TexasTransitionWitness {
            pre,
            post,
            action: TexasAction::Bet {
                seat: 0,
                amount: 10,
            },
        }
    }

    fn valid_addon() -> TexasTransitionWitness {
        let pre = state();
        let mut post = pre.clone();
        post.call_seq += 1;
        post.chip_pool += 25;
        post.seats[0].pending_addon = 25;
        TexasTransitionWitness {
            pre,
            post,
            action: TexasAction::Addon {
                seat: 0,
                amount: 25,
            },
        }
    }

    fn valid_rebuy() -> TexasTransitionWitness {
        let pre = state();
        let mut post = pre.clone();
        post.call_seq += 1;
        post.chip_pool += 25;
        post.seats[0].stack += 25;
        TexasTransitionWitness {
            pre,
            post,
            action: TexasAction::Rebuy {
                seat: 0,
                amount: 25,
            },
        }
    }

    fn valid_leave() -> TexasTransitionWitness {
        let pre = state();
        let mut post = pre.clone();
        post.call_seq += 1;
        post.leave_after_hand_mask = 1;
        TexasTransitionWitness {
            pre,
            post,
            action: TexasAction::SetLeaveAfterHand {
                seat: 0,
                want_leave: true,
            },
        }
    }

    #[test]
    fn accepts_valid_call_without_vm_replay() {
        assert!(validate_transition(&valid_call()).is_ok());
    }

    #[test]
    fn accepts_valid_fold_check_raise_and_bet_without_vm_replay() {
        for witness in [valid_fold(), valid_check(), valid_raise(), valid_bet()] {
            assert!(validate_transition(&witness).is_ok());
        }
    }

    #[test]
    fn accepts_canonical_funds_and_leave_transitions() {
        for witness in [valid_addon(), valid_rebuy(), valid_leave()] {
            assert!(validate_transition(&witness).is_ok());
        }
    }

    #[test]
    fn rejects_invalid_funds_and_leave_transitions() {
        let mut zero_addon = valid_addon();
        zero_addon.action = TexasAction::Addon { seat: 0, amount: 0 };
        assert!(validate_transition(&zero_addon).is_err());

        let mut wrong_pool = valid_rebuy();
        wrong_pool.post.chip_pool -= 1;
        assert!(validate_transition(&wrong_pool).is_err());

        let mut over_limit = valid_addon();
        over_limit.pre.chip_pool = MAX_TOTAL_BET;
        over_limit.post.chip_pool = MAX_TOTAL_BET + 25;
        assert!(validate_transition(&over_limit).is_err());

        let mut unrelated_mutation = valid_leave();
        unrelated_mutation.post.seats[1].stack += 1;
        assert!(validate_transition(&unrelated_mutation).is_err());

        let mut idempotent = valid_leave();
        idempotent.pre.leave_after_hand_mask = 1;
        idempotent.post.leave_after_hand_mask = 1;
        assert!(validate_transition(&idempotent).is_err());
    }

    #[test]
    fn rejects_wrong_stack() {
        let pre = state();
        let mut post = pre.clone();
        post.call_seq += 1;
        post.seats[0].stack = 99;
        post.seats[0].bet = 11;
        post.seats[0].total_bet = 11;
        post.seats[0].acted = true;
        post.current_turn = 1;
        assert!(
            validate_transition(&TexasTransitionWitness {
                pre,
                post,
                action: TexasAction::Call { seat: 0 }
            })
            .is_err()
        );
    }

    #[test]
    fn rejects_action_from_already_acted_seat() {
        let mut witness = valid_call();
        witness.pre.seats[0].acted = true;
        assert!(validate_transition(&witness).is_err());
    }

    #[test]
    fn rejects_non_contiguous_batch() {
        let first = valid_call();
        let mut second = valid_call();
        second.pre.call_seq += 100;
        assert!(trace_for(&[first, second]).is_err());
    }

    #[test]
    fn rejects_round_completion_in_mid_round_path() {
        let mut witness = valid_call();
        witness.pre.seats[1].acted = true;
        witness.post.seats[1].acted = true;
        witness.post.current_turn = 0;
        assert!(matches!(
            validate_transition(&witness),
            Err(TexasAirError::UnsupportedBettingTransition(_))
        ));
    }

    #[test]
    fn proves_and_verifies_valid_call_batch() {
        let witness = valid_call();
        let proof = prove_tagged_texas_batch(std::slice::from_ref(&witness)).expect("prove");
        verify_tagged_texas_batch(std::slice::from_ref(&witness), &proof).expect("verify");
        verify_tagged_texas_proof(&proof).expect("witness-free verify");

        let mut tampered_scope = proof.clone();
        tampered_scope.table_id ^= 1;
        assert!(verify_tagged_texas_proof(&tampered_scope).is_err());

        let mut tampered_state_scope = proof.clone();
        tampered_state_scope.pre_state_commitment[0] ^= 1;
        assert!(verify_tagged_texas_proof(&tampered_state_scope).is_err());
    }

    #[test]
    fn rejects_public_scope_and_active_prefix_tampering() {
        let first = valid_addon();
        let mut second = valid_leave();
        second.pre = first.post.clone();
        second.post = second.pre.clone();
        second.post.call_seq += 1;
        second.post.leave_after_hand_mask = 1;
        let proof = prove_tagged_texas_batch(&[first, second]).expect("prove");

        // The verifier-owned active prefix is committed separately from the trace.  Changing
        // the archived count or sequence range must therefore fail even when the STARK bytes
        // themselves are untouched.
        let mut bad_count = proof.clone();
        bad_count.transition_count = 1;
        bad_count.last_call_seq = bad_count.first_call_seq + 1;
        assert!(verify_tagged_texas_proof(&bad_count).is_err());

        let mut bad_sequence = proof.clone();
        bad_sequence.first_call_seq += 1;
        bad_sequence.last_call_seq += 1;
        assert!(verify_tagged_texas_proof(&bad_sequence).is_err());

        let mut bad_digest = proof.clone();
        bad_digest.batch_digest[0] ^= 1;
        assert!(verify_tagged_texas_proof(&bad_digest).is_err());

        let mut bad_columns = proof;
        bad_columns.num_columns -= 1;
        assert!(verify_tagged_texas_proof(&bad_columns).is_err());
    }

    #[test]
    fn proves_and_verifies_mixed_non_betting_batch() {
        let first = valid_addon();
        let mut second = valid_leave();
        second.pre = first.post.clone();
        second.post = second.pre.clone();
        second.post.call_seq += 1;
        second.post.leave_after_hand_mask = 1;
        let batch = [first, second];
        let proof = prove_tagged_texas_batch(&batch).expect("prove");
        verify_tagged_texas_batch(&batch, &proof).expect("verify");
    }
}
