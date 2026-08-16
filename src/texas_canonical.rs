//! Fixed-width canonical ABI for the complete Texas Poker state machine.
//!
//! This module is deliberately independent from VM replay.  It is the state/transition
//! contract that a direct AIR must consume.  The current tagged betting AIR remains a
//! projection of this ABI until each transition family is wired into its own constraints.
#![allow(missing_docs)]

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};

pub const CANONICAL_ABI_VERSION: u16 = 1;
pub const MAX_CANONICAL_SEATS: usize = 9;
pub const NO_CANONICAL_SEAT: u8 = 0x0f;

#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum CanonicalPhase {
    Waiting = 0,
    Shuffling = 1,
    Revealing = 2,
    Reconstructing = 3,
    Betting = 4,
    ShowdownDisplay = 5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum CanonicalSeatStatus {
    Empty = 0,
    Waiting = 1,
    Active = 2,
    Folded = 3,
    AllIn = 4,
    Out = 5,
}

/// A fixed-width seat image.  Identity, key, and private-card material are commitments so the
/// public state shape is constant without exposing player secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CanonicalSeat {
    pub status: CanonicalSeatStatus,
    pub acted: bool,
    pub stack: u64,
    pub bet: u64,
    pub total_bet: u64,
    pub pending_addon: u64,
    pub time_bank_ms: u32,
    pub identity_commitment: [u8; 32],
    pub key_commitment: [u8; 32],
    pub hole_cards_commitment: [u8; 32],
}

impl CanonicalSeat {
    pub const EMPTY: Self = Self {
        status: CanonicalSeatStatus::Empty,
        acted: false,
        stack: 0,
        bet: 0,
        total_bet: 0,
        pending_addon: 0,
        time_bank_ms: 0,
        identity_commitment: [0; 32],
        key_commitment: [0; 32],
        hole_cards_commitment: [0; 32],
    };

    fn validate(&self) -> Result<(), String> {
        if self.total_bet < self.bet {
            return Err("seat total_bet is below current bet".into());
        }
        match self.status {
            CanonicalSeatStatus::Empty => {
                if self.acted
                    || self.stack != 0
                    || self.bet != 0
                    || self.total_bet != 0
                    || self.pending_addon != 0
                    || self.identity_commitment != [0; 32]
                    || self.key_commitment != [0; 32]
                    || self.hole_cards_commitment != [0; 32]
                {
                    return Err("empty seat carries lifecycle, custody, or commitment data".into());
                }
            }
            CanonicalSeatStatus::Out => {
                if self.identity_commitment == [0; 32]
                    || self.key_commitment != [0; 32]
                    || self.hole_cards_commitment != [0; 32]
                    || self.stack != 0
                    || self.pending_addon != 0
                {
                    return Err("departed seat has an invalid retained custody image".into());
                }
            }
            _ => {
                if self.identity_commitment == [0; 32] || self.key_commitment == [0; 32] {
                    return Err("occupied seat is missing identity/key commitment".into());
                }
            }
        }
        Ok(())
    }
}

/// Complete public image of a Texas table.  Opaque commitments are explicit fields rather than
/// host-only summaries, so adding a VM state component requires changing this ABI and its digest.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CanonicalStateImage {
    pub abi_version: u16,
    pub table_id: u64,
    pub hand_id: u32,
    pub call_seq: u32,
    pub phase: CanonicalPhase,
    pub phase_subtag: u8,
    pub street: u8,
    pub current_turn: u8,
    pub deadline_ms: u64,
    pub current_bet: u64,
    pub min_raise: u64,
    pub pot: u64,
    pub button: u8,
    pub max_players: u8,
    pub acted_mask: u16,
    pub leave_after_hand_mask: u16,
    pub board_cards_commitment: [u8; 32],
    pub deck_commitment: [u8; 32],
    pub reveal_commitment: [u8; 32],
    pub reconstruction_commitment: [u8; 32],
    pub run_it_twice_commitment: [u8; 32],
    pub rules_commitment: [u8; 32],
    pub governance_commitment: [u8; 32],
    pub settlement_commitment: [u8; 32],
    pub custody_commitment: [u8; 32],
    pub lifecycle_root: [u8; 32],
    pub overlay_root: [u8; 32],
    pub state_root: [u8; 32],
    pub seats: [CanonicalSeat; MAX_CANONICAL_SEATS],
}

impl CanonicalStateImage {
    pub fn validate(&self) -> Result<(), String> {
        if self.abi_version != CANONICAL_ABI_VERSION {
            return Err("unsupported canonical Texas ABI version".into());
        }
        if !(2..=MAX_CANONICAL_SEATS as u8).contains(&self.max_players) {
            return Err("max_players must be within 2..=9".into());
        }
        for (name, value) in [("button", self.button), ("current_turn", self.current_turn)] {
            if value != NO_CANONICAL_SEAT && value >= self.max_players {
                return Err(format!("{name} is outside the seat domain"));
            }
        }
        let valid_mask = if self.max_players == MAX_CANONICAL_SEATS as u8 {
            u16::MAX >> (16 - MAX_CANONICAL_SEATS)
        } else {
            (1u16 << self.max_players) - 1
        };
        if self.acted_mask & !valid_mask != 0 || self.leave_after_hand_mask & !valid_mask != 0 {
            return Err("seat mask exceeds table capacity".into());
        }
        for (name, value) in [
            ("rules_commitment", self.rules_commitment),
            ("governance_commitment", self.governance_commitment),
            ("settlement_commitment", self.settlement_commitment),
            ("custody_commitment", self.custody_commitment),
            ("lifecycle_root", self.lifecycle_root),
            ("overlay_root", self.overlay_root),
            ("state_root", self.state_root),
        ] {
            if value == [0; 32] {
                return Err(format!("{name} must be bound to a non-zero commitment"));
            }
        }
        if self.phase == CanonicalPhase::Waiting {
            if self.phase_subtag != 0 || self.street != 0 || self.acted_mask != 0 {
                return Err("waiting phase carries active hand progress".into());
            }
        } else {
            if self.deadline_ms == 0 {
                return Err("active phase must carry an absolute deadline".into());
            }
            if self.phase_subtag == 0 {
                return Err("active phase is missing its protocol subtag".into());
            }
        }
        if self.phase == CanonicalPhase::Betting && !(1..=4).contains(&self.street) {
            return Err("betting phase street is outside preflop..river".into());
        }
        if self.phase == CanonicalPhase::Waiting {
            if self.current_turn != NO_CANONICAL_SEAT || self.deadline_ms != 0 {
                return Err("waiting phase must have no actor or deadline".into());
            }
        } else if self.deadline_ms == 0 {
            return Err("active phase must carry an absolute deadline".into());
        }
        for (index, seat) in self.seats.iter().enumerate() {
            seat.validate()?;
            if index >= usize::from(self.max_players)
                && !matches!(seat.status, CanonicalSeatStatus::Empty)
            {
                return Err("seat outside table capacity is not empty".into());
            }
            if seat.bet > self.current_bet {
                return Err("seat bet exceeds current bet".into());
            }
            let bit = 1u16 << index;
            if seat.acted != (self.acted_mask & bit != 0) {
                return Err("acted mask is not the fixed-width seat projection".into());
            }
            if self.phase == CanonicalPhase::Betting
                && self.current_turn != NO_CANONICAL_SEAT
                && index == usize::from(self.current_turn)
                && !matches!(seat.status, CanonicalSeatStatus::Active)
            {
                return Err("current turn does not point at an active seat".into());
            }
            if matches!(seat.status, CanonicalSeatStatus::Folded | CanonicalSeatStatus::AllIn)
                && !seat.acted
            {
                return Err("folded/all-in seat must be marked acted".into());
            }
        }
        Ok(())
    }

    pub fn commitment(&self) -> [u8; 32] {
        digest(b"zchain.texas.canonical-state.v1", self)
    }
}

/// All dispatch selector families are represented by the direct transition ABI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum CanonicalTransitionKind {
    CreateTable = 0,
    JoinTable = 1,
    LeaveTable = 2,
    StartHand = 3,
    AdvanceDeadline = 4,
    ForceFold = 5,
    KickPlayer = 6,
    SubmitShuffle = 7,
    SubmitReveal = 8,
    SubmitReconstruct = 9,
    Fold = 10,
    Check = 11,
    Call = 12,
    Raise = 13,
    Bet = 14,
    Addon = 15,
    Rebuy = 16,
    SetLeaveAfterHand = 17,
    FoldWithProof = 18,
}

impl CanonicalTransitionKind {
    pub const fn requires_seat(self) -> bool {
        matches!(
            self,
            Self::JoinTable
                | Self::LeaveTable
                | Self::ForceFold
                | Self::KickPlayer
                | Self::SubmitShuffle
                | Self::SubmitReveal
                | Self::SubmitReconstruct
                | Self::Fold
                | Self::Check
                | Self::Call
                | Self::Raise
                | Self::Bet
                | Self::Addon
                | Self::Rebuy
                | Self::SetLeaveAfterHand
                | Self::FoldWithProof
        )
    }

    pub const fn permissionless(self) -> bool {
        matches!(self, Self::AdvanceDeadline)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CanonicalActionPayload {
    pub seat: u8,
    pub amount: u64,
    pub auxiliary: u64,
    pub flag: bool,
    pub proof_commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CanonicalTransitionWitness {
    pub pre: CanonicalStateImage,
    pub post: CanonicalStateImage,
    pub kind: CanonicalTransitionKind,
    pub actor: [u8; 32],
    pub action: CanonicalActionPayload,
    pub transition_commitment: [u8; 32],
    pub nullifier: [u8; 32],
    pub deadline_height: u64,
}

impl CanonicalTransitionWitness {
    /// Fill the derived transition commitment and nullifier fields.
    ///
    /// Callers construct a witness with both fields zeroed, then seal it before
    /// passing it to the direct prover.  This keeps the anti-replay derivation
    /// deterministic and prevents accidental self-referential commitments.
    pub fn seal(&mut self) {
        self.transition_commitment = self.content_commitment();
        self.nullifier = transition_nullifier(self);
    }

    pub fn validate_shape(&self) -> Result<(), String> {
        self.pre.validate()?;
        self.post.validate()?;
        if self.pre.table_id != self.post.table_id {
            return Err("transition changes table scope".into());
        }
        if self.transition_commitment == [0; 32] || self.nullifier == [0; 32] {
            return Err("transition commitment and nullifier must be non-zero".into());
        }
        if self.transition_commitment != self.content_commitment() {
            return Err("transition commitment does not commit to the complete witness".into());
        }
        let expected_nullifier = transition_nullifier(self);
        if self.nullifier != expected_nullifier {
            return Err("nullifier is not domain-separated from the complete transition".into());
        }
        if self.kind.permissionless() {
            if self.actor != [0; 32] {
                return Err("permissionless transition must have zero actor".into());
            }
        } else if self.actor == [0; 32] {
            return Err("actor transition must bind a non-zero actor".into());
        }
        if self.kind.requires_seat() && self.action.seat >= self.pre.max_players {
            return Err("transition seat is outside table capacity".into());
        }
        if self.kind == CanonicalTransitionKind::StartHand {
            if self.post.hand_id != self.pre.hand_id.checked_add(1).ok_or("hand overflow")?
                || self.post.call_seq != 0
            {
                return Err("start-hand transition must increment hand and reset sequence".into());
            }
        } else if self.post.call_seq
            != self
                .pre
                .call_seq
                .checked_add(1)
                .ok_or("sequence overflow")?
        {
            return Err("transition sequence is not contiguous".into());
        }
        validate_transition_relation(self)?;
        Ok(())
    }

    pub fn commitment(&self) -> [u8; 32] {
        digest(b"zchain.texas.canonical-transition.v1", self)
    }

    /// Commitment over the complete transition payload excluding the two derived
    /// anti-replay fields.  `transition_commitment` is this value; keeping the
    /// derivation separate avoids a self-referential fixed-point commitment.
    pub fn content_commitment(&self) -> [u8; 32] {
        let mut payload = self.clone();
        payload.transition_commitment = [0; 32];
        payload.nullifier = [0; 32];
        digest(b"zchain.texas.canonical-transition-content.v1", &payload)
    }
}

/// Validate a contiguous heterogeneous batch without invoking the Texas VM.
///
/// The first pre-state and final post-state are the only external scope. Every
/// interior boundary is checked byte-for-byte, so a prover cannot splice two
/// tables/hands or reset `call_seq` in the middle of a batch.
pub fn validate_batch(witnesses: &[CanonicalTransitionWitness]) -> Result<(), String> {
    if witnesses.is_empty() {
        return Err("canonical transition batch must not be empty".into());
    }
    for witness in witnesses {
        witness.validate_shape()?;
    }
    for pair in witnesses.windows(2) {
        if pair[0].post.commitment() != pair[1].pre.commitment() {
            return Err("canonical transition batch has a non-contiguous state boundary".into());
        }
    }
    let first = &witnesses[0];
    let mut hand_id = first.pre.hand_id;
    for witness in witnesses {
        if witness.pre.table_id != first.pre.table_id {
            return Err("canonical transition batch changes table scope".into());
        }
        if witness.pre.hand_id != hand_id {
            return Err("canonical transition batch changes hand without a contiguous start_hand".into());
        }
        if witness.kind == CanonicalTransitionKind::StartHand {
            hand_id = witness.post.hand_id;
        }
    }
    Ok(())
}

pub fn transition_nullifier(witness: &CanonicalTransitionWitness) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(32 * 3 + 8);
    bytes.extend_from_slice(b"zchain.texas.nullifier.v1");
    bytes.extend_from_slice(&witness.transition_commitment);
    bytes.extend_from_slice(&witness.actor);
    bytes.extend_from_slice(&witness.pre.state_root);
    bytes.extend_from_slice(&witness.post.state_root);
    digest_bytes(&bytes)
}

fn digest_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut h = Blake2bVar::new(32).expect("32-byte Blake2 digest");
    h.update(bytes);
    let mut out = [0; 32];
    h.finalize_variable(&mut out).expect("fixed digest length");
    out
}

fn same_except(
    pre: &CanonicalStateImage,
    post: &CanonicalStateImage,
    changed_seat: Option<usize>,
    allow: impl Fn(&CanonicalStateImage, &CanonicalStateImage) -> bool,
) -> Result<(), String> {
    let mut left = pre.clone();
    let mut right = post.clone();
    left.state_root = [0; 32];
    right.state_root = [0; 32];
    left.lifecycle_root = [0; 32];
    right.lifecycle_root = [0; 32];
    left.overlay_root = [0; 32];
    right.overlay_root = [0; 32];
    if let Some(index) = changed_seat {
        left.seats[index] = CanonicalSeat::EMPTY;
        right.seats[index] = CanonicalSeat::EMPTY;
    }
    if left != right && !allow(&left, &right) {
        return Err("transition changed a field outside its canonical relation".into());
    }
    Ok(())
}

fn validate_transition_relation(w: &CanonicalTransitionWitness) -> Result<(), String> {
    let pre = &w.pre;
    let post = &w.post;
    let seat = usize::from(w.action.seat);
    let seat_index = (seat < MAX_CANONICAL_SEATS).then_some(seat);
    let before = seat_index.map(|index| pre.seats[index]).unwrap_or(CanonicalSeat::EMPTY);
    let after = seat_index.map(|index| post.seats[index]).unwrap_or(CanonicalSeat::EMPTY);
    let bit = seat_index.map_or(0, |index| 1u16 << index);
    match w.kind {
        CanonicalTransitionKind::CreateTable => {
            if pre.phase != CanonicalPhase::Waiting || post.phase != CanonicalPhase::Waiting {
                return Err("create_table must start and end in waiting phase".into());
            }
            if pre.table_id != post.table_id || post.seats.iter().any(|s| s.status != CanonicalSeatStatus::Empty) {
                return Err("create_table has an invalid empty-table boundary".into());
            }
            same_except(pre, post, None, |a, b| {
                a.call_seq.checked_add(1) == Some(b.call_seq)
            })?;
        }
        CanonicalTransitionKind::JoinTable => {
            if pre.phase != CanonicalPhase::Waiting || before.status != CanonicalSeatStatus::Empty {
                return Err("join_table requires an empty seat in waiting phase".into());
            }
            if after.status != CanonicalSeatStatus::Waiting || w.action.amount == 0 {
                return Err("join_table must create a funded waiting seat".into());
            }
            same_except(pre, post, seat_index, |a, b| {
                a.acted_mask == b.acted_mask && a.leave_after_hand_mask == b.leave_after_hand_mask
            })?;
        }
        CanonicalTransitionKind::LeaveTable => {
            if pre.phase != CanonicalPhase::Waiting
                || !matches!(before.status, CanonicalSeatStatus::Waiting | CanonicalSeatStatus::Out)
                || !matches!(after.status, CanonicalSeatStatus::Empty | CanonicalSeatStatus::Out)
            {
                return Err("leave_table is only valid for a waiting/out seat".into());
            }
            same_except(pre, post, seat_index, |_, _| true)?;
        }
        CanonicalTransitionKind::StartHand => {
            if pre.phase != CanonicalPhase::Waiting || post.phase != CanonicalPhase::Shuffling {
                return Err("start_hand must enter shuffling from waiting".into());
            }
            if post.deadline_ms == 0 || post.current_turn != NO_CANONICAL_SEAT {
                return Err("start_hand must arm the shuffle deadline".into());
            }
            same_except(pre, post, None, |a, b| {
                a.hand_id + 1 == b.hand_id && b.call_seq == 0
            })?;
        }
        CanonicalTransitionKind::AdvanceDeadline => {
            if pre.phase == CanonicalPhase::Waiting || w.deadline_height == 0 {
                return Err("advance_deadline requires an active expiring phase".into());
            }
            if w.deadline_height < pre.deadline_ms {
                return Err("advance_deadline is before the committed deadline".into());
            }
            same_except(pre, post, None, |a, b| {
                a.deadline_ms <= b.deadline_ms || b.phase != a.phase
            })?;
        }
        CanonicalTransitionKind::Fold
        | CanonicalTransitionKind::Check
        | CanonicalTransitionKind::Call
        | CanonicalTransitionKind::Raise
        | CanonicalTransitionKind::Bet => {
            if pre.phase != CanonicalPhase::Betting
                || pre.current_turn != w.action.seat
                || before.status != CanonicalSeatStatus::Active
            {
                return Err("betting action is not authorized by the pre-state turn".into());
            }
            if w.kind == CanonicalTransitionKind::Fold {
                if after.status != CanonicalSeatStatus::Folded || !after.acted {
                    return Err("fold must mark the selected seat folded and acted".into());
                }
            } else if after.status != CanonicalSeatStatus::Active || !after.acted {
                return Err("betting action must mark the selected seat acted".into());
            }
            if post.current_turn == w.action.seat {
                return Err("betting action did not advance the turn".into());
            }
            if w.kind == CanonicalTransitionKind::Check && before.bet != pre.current_bet {
                return Err("check requires a matched current bet".into());
            }
            if matches!(w.kind, CanonicalTransitionKind::Raise | CanonicalTransitionKind::Bet)
                && after.bet < pre.current_bet
            {
                return Err("raise/bet did not reach the current bet".into());
            }
            same_except(pre, post, Some(seat), |a, b| {
                a.acted_mask ^ b.acted_mask == bit || a.current_turn != b.current_turn
            })?;
        }
        CanonicalTransitionKind::Addon | CanonicalTransitionKind::Rebuy => {
            if pre.phase == CanonicalPhase::Waiting && before.status == CanonicalSeatStatus::Empty {
                return Err("funding requires an occupied seat".into());
            }
            if w.action.amount == 0 || after.status != before.status {
                return Err("funding transition has an invalid amount or lifecycle".into());
            }
            if w.kind == CanonicalTransitionKind::Addon {
                if after.pending_addon < before.pending_addon || after.stack != before.stack {
                    return Err("addon must only increase pending_addon".into());
                }
            } else if after.stack < before.stack || after.pending_addon != before.pending_addon {
                return Err("rebuy must only increase stack".into());
            }
            same_except(pre, post, seat_index, |_, _| true)?;
        }
        CanonicalTransitionKind::SetLeaveAfterHand => {
            if before.status == CanonicalSeatStatus::Empty
                || ((pre.leave_after_hand_mask & bit != 0) == w.action.flag)
                || post.leave_after_hand_mask
                    != if w.action.flag { pre.leave_after_hand_mask | bit } else { pre.leave_after_hand_mask & !bit }
            {
                return Err("leave-after-hand transition is not a single bit flip".into());
            }
            same_except(pre, post, None, |_, _| true)?;
        }
        CanonicalTransitionKind::ForceFold | CanonicalTransitionKind::KickPlayer => {
            if !matches!(before.status, CanonicalSeatStatus::Active | CanonicalSeatStatus::Waiting)
                || !matches!(after.status, CanonicalSeatStatus::Folded | CanonicalSeatStatus::Out | CanonicalSeatStatus::Empty)
            {
                return Err("force-fold/kick has an invalid lifecycle transition".into());
            }
            same_except(pre, post, seat_index, |_, _| true)?;
        }
        CanonicalTransitionKind::SubmitShuffle
        | CanonicalTransitionKind::SubmitReveal
        | CanonicalTransitionKind::SubmitReconstruct
        | CanonicalTransitionKind::FoldWithProof => {
            if w.action.proof_commitment == [0; 32] {
                return Err("crypto transition is missing its proof commitment".into());
            }
            if pre.phase == CanonicalPhase::Waiting || pre.phase == CanonicalPhase::Betting {
                return Err("crypto transition is outside its protocol phase".into());
            }
            if pre.deck_commitment == post.deck_commitment
                && pre.reveal_commitment == post.reveal_commitment
                && pre.reconstruction_commitment == post.reconstruction_commitment
            {
                return Err("crypto transition did not advance a protocol commitment".into());
            }
            same_except(pre, post, seat_index, |_, _| true)?;
        }
    }
    Ok(())
}

fn digest<T: BorshSerialize>(domain: &[u8], value: &T) -> [u8; 32] {
    let bytes = borsh::to_vec(value).expect("canonical ABI is serializable");
    let mut h = Blake2bVar::new(32).expect("32-byte Blake2 digest");
    h.update(domain);
    h.update(&bytes);
    let mut out = [0; 32];
    h.finalize_variable(&mut out).expect("fixed digest length");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn canonical_image_rejects_waiting_actor_or_deadline() {
        let mut value = image();
        value.current_turn = 0;
        assert!(value.validate().is_err());
        let mut value = image();
        value.deadline_ms = 1;
        assert!(value.validate().is_err());
    }

    #[test]
    fn canonical_transition_binds_sequence_and_actor_policy() {
        let pre = image();
        let mut post = pre.clone();
        post.call_seq = 1;
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
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 2,
        };
        witness.transition_commitment = witness.content_commitment();
        witness.nullifier = transition_nullifier(&witness);
        assert!(witness.validate_shape().is_ok());
        assert_ne!(witness.commitment(), [0; 32]);
    }
}
