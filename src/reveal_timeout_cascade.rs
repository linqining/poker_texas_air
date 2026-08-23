//! Fixed-width semantic scope for the non-terminal part of a reveal-timeout cascade.
//!
//! The VM does not apply a reveal timeout as one state jump.  It walks the
//! assignment pending union in ascending seat order and invokes
//! `kick_player_internal` once per seat.  This module records that walk as a
//! bounded, replay-free transition batch.  It is intentionally independent of
//! the existing canonical tagged ABI: the latter currently has only the narrow
//! single-row timeout-reset selector.  The scope is the input contract for the
//! dedicated Stwo micro-step AIR that will be composed with the tagged proof.
#![allow(missing_docs)]

use borsh::{BorshDeserialize, BorshSerialize};

use crate::canonical_reveal_opening::CanonicalRevealLedgerOpening;
use crate::error::{TexasAirError, TexasAirResult};
use crate::texas_canonical::{
    CANONICAL_RECONSTRUCT_COLLECTING_SUBTAG, CanonicalPhase, CanonicalSeatStatus,
    CanonicalStateImage, MAX_CANONICAL_SEATS, NO_CANONICAL_SEAT,
};

/// The complete VM schedule may contain every seat.  Its final kick is
/// terminal and is proved by the reset/end/reconstruct continuation rather
/// than this non-terminal prefix.
pub const MAX_REVEAL_TIMEOUT_SCHEDULE: usize = MAX_CANONICAL_SEATS;
/// At least the final scheduled kick is terminal, so only eight of nine
/// seats can appear in the non-terminal same-phase prefix.
pub const MAX_REVEAL_TIMEOUT_KICKS: usize = MAX_CANONICAL_SEATS - 1;
pub const REVEAL_TIMEOUT_EMPTY_SEAT: u8 = u8::MAX;

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RevealTimeoutKickTransition {
    pub pre: CanonicalStateImage,
    pub post: CanonicalStateImage,
    pub seat: u8,
}

/// The terminal non-preflop row of a reveal-timeout cascade.
///
/// The last pending participant is kicked by the same internal VM primitive as
/// every prefix row.  Provided that two live players remain, `on_reveal_timeout`
/// then suspends the authenticated reveal ledger and enters reconstruction
/// collection.  This fixed-width statement deliberately keeps that boundary
/// separate from the tagged selector while the latter is under concurrent
/// review; it gives the selector a complete, replay-free state relation to
/// compose with rather than treating the phase change as host advice.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RevealTimeoutReconstructTransition {
    pub pre: CanonicalStateImage,
    pub post: CanonicalStateImage,
    /// The final ascending pending-union slot consumed by the terminal kick.
    pub seat: u8,
    /// Consensus height/time used for the newly armed reconstruct deadline.
    pub deadline_height: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RevealTimeoutCascadeScope {
    pub phase: u8,
    pub street: u8,
    pub pending_union: u16,
    pub kick_count: u8,
    /// Slot `i` is the i-th VM kick; unused slots are the fixed sentinel.
    pub kick_schedule: [u8; MAX_REVEAL_TIMEOUT_SCHEDULE],
    pub transitions: Vec<RevealTimeoutKickTransition>,
    /// Optional terminal continuation for a non-preflop reveal timeout.
    /// Preflop timeout instead ends in the reset selector, so existing users
    /// may leave this absent.
    pub reconstruct_terminal: Option<RevealTimeoutReconstructTransition>,
}

impl RevealTimeoutCascadeScope {
    pub fn from_opening(opening: &CanonicalRevealLedgerOpening) -> TexasAirResult<Self> {
        opening.validate()?;
        let mut schedule = [REVEAL_TIMEOUT_EMPTY_SEAT; MAX_REVEAL_TIMEOUT_SCHEDULE];
        let mut count = 0usize;
        for seat in 0..MAX_CANONICAL_SEATS {
            if opening.pending_union & (1u16 << seat) == 0 {
                continue;
            }
            if count == MAX_REVEAL_TIMEOUT_SCHEDULE {
                return Err(TexasAirError::SpecViolation(
                    "reveal timeout kick schedule exceeds fixed bound".into(),
                ));
            }
            schedule[count] = seat as u8;
            count += 1;
        }
        Ok(Self {
            phase: opening.phase,
            street: opening.street,
            pending_union: opening.pending_union,
            kick_count: count as u8,
            kick_schedule: schedule,
            transitions: Vec::new(),
            reconstruct_terminal: None,
        })
    }

    pub fn validate_header(&self) -> TexasAirResult<()> {
        if self.phase == 0
            || self.street == 0
            || self.pending_union & !0x01ff != 0
            || self.kick_count as usize > MAX_REVEAL_TIMEOUT_SCHEDULE
        {
            return Err(TexasAirError::SpecViolation(
                "reveal timeout cascade header is outside the fixed domain".into(),
            ));
        }
        let mut expected = 0usize;
        for (index, seat) in self.kick_schedule.iter().copied().enumerate() {
            let present = index < usize::from(self.kick_count);
            if present {
                if seat >= MAX_CANONICAL_SEATS as u8
                    || self.pending_union & (1u16 << seat) == 0
                    || seat as usize != expected_next_pending(self.pending_union, expected)
                {
                    return Err(TexasAirError::ConstraintUnsatisfied(
                        "reveal timeout kick schedule is not ascending pending-seat order".into(),
                    ));
                }
                expected += 1;
            } else if seat != REVEAL_TIMEOUT_EMPTY_SEAT {
                return Err(TexasAirError::SpecViolation(
                    "reveal timeout kick schedule has non-canonical padding".into(),
                ));
            }
        }
        if expected != usize::from(self.kick_count)
            || self.kick_count as usize != self.pending_union.count_ones() as usize
        {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "reveal timeout kick count is detached from pending union".into(),
            ));
        }
        Ok(())
    }

    pub fn validate_transitions(&self) -> TexasAirResult<()> {
        self.validate_header()?;
        if self.transitions.len() > usize::from(self.kick_count) {
            return Err(TexasAirError::SpecViolation(
                "reveal timeout non-terminal prefix exceeds schedule".into(),
            ));
        }
        if let Some(first) = self.transitions.first() {
            if first.pre.phase != CanonicalPhase::Revealing
                || first.pre.phase_subtag != self.phase
                || first.pre.street != self.street
                || first.pre.protocol_pending_mask != self.pending_union
            {
                return Err(TexasAirError::ConstraintUnsatisfied(
                    "reveal timeout kick prefix is detached from the opened ledger".into(),
                ));
            }
        }
        for (index, transition) in self.transitions.iter().enumerate() {
            if transition.seat != self.kick_schedule[index] {
                return Err(TexasAirError::ConstraintUnsatisfied(
                    "reveal timeout transition seat is detached from schedule".into(),
                ));
            }
            validate_kick_transition(transition, self.phase, self.street)?;
            if index > 0 {
                let prior = &self.transitions[index - 1].post;
                if prior.commitment() != transition.pre.commitment() {
                    return Err(TexasAirError::ConstraintUnsatisfied(
                        "reveal timeout kick batch has a non-contiguous state boundary".into(),
                    ));
                }
            }
        }
        if let Some(terminal) = &self.reconstruct_terminal {
            if self.phase == 1
                || self.street == 1
                || self.transitions.len() + 1 != usize::from(self.kick_count)
                || terminal.seat != self.kick_schedule[self.transitions.len()]
            {
                return Err(TexasAirError::ConstraintUnsatisfied(
                    "reveal timeout reconstruct continuation is detached from the terminal schedule"
                        .into(),
                ));
            }
            let expected_pre = self.transitions.last().map(|transition| &transition.post);
            if let Some(expected_pre) = expected_pre {
                if expected_pre.commitment() != terminal.pre.commitment() {
                    return Err(TexasAirError::ConstraintUnsatisfied(
                        "reveal timeout reconstruct continuation has a non-contiguous state boundary"
                            .into(),
                    ));
                }
            } else if terminal.pre.phase != CanonicalPhase::Revealing
                || terminal.pre.phase_subtag != self.phase
                || terminal.pre.street != self.street
                || terminal.pre.protocol_pending_mask != self.pending_union
            {
                return Err(TexasAirError::ConstraintUnsatisfied(
                    "reveal timeout reconstruct continuation is detached from the opened ledger"
                        .into(),
                ));
            }
            validate_reconstruct_terminal(terminal, self.phase, self.street)?;
        }
        Ok(())
    }
}

fn expected_next_pending(mask: u16, ordinal: usize) -> usize {
    (0..MAX_CANONICAL_SEATS)
        .filter(|seat| mask & (1u16 << seat) != 0)
        .nth(ordinal)
        .unwrap_or(MAX_CANONICAL_SEATS)
}

fn validate_kick_transition(
    transition: &RevealTimeoutKickTransition,
    phase: u8,
    street: u8,
) -> TexasAirResult<()> {
    let pre = &transition.pre;
    let post = &transition.post;
    let seat = usize::from(transition.seat);
    if seat >= usize::from(pre.max_players)
        || pre.phase != CanonicalPhase::Revealing
        || pre.phase_subtag != phase
        || pre.street != street
        || post.phase != pre.phase
        || post.phase_subtag != pre.phase_subtag
        || post.street != pre.street
        || pre.current_turn != NO_CANONICAL_SEAT
        || post.current_turn != NO_CANONICAL_SEAT
        || pre.protocol_pending_mask & (1u16 << seat) == 0
        || pre.seats[seat].status != CanonicalSeatStatus::Active
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "reveal timeout kick has an invalid phase or pending-seat header".into(),
        ));
    }
    let before = pre.seats[seat];
    let after = post.seats[seat];
    let refund = before
        .stack
        .checked_add(before.pending_addon)
        .ok_or_else(|| TexasAirError::ConstraintUnsatisfied("kick refund overflow".into()))?;
    if after.status != CanonicalSeatStatus::Out
        || after.stack != 0
        || after.pending_addon != 0
        || after.bet != 0
        || after.total_bet != before.total_bet
        || after.time_bank_ms != before.time_bank_ms
        || after.identity_commitment != before.identity_commitment
        || after.key_commitment != [0; 32]
        || after.hole_cards_commitment != [0; 32]
        || post.pot
            != pre
                .pot
                .checked_add(before.bet)
                .ok_or_else(|| TexasAirError::ConstraintUnsatisfied("kick pot overflow".into()))?
        || post.chip_pool
            != pre.chip_pool.checked_sub(refund).ok_or_else(|| {
                TexasAirError::ConstraintUnsatisfied("kick chip_pool underflow".into())
            })?
        || post.protocol_pending_mask != pre.protocol_pending_mask & !(1u16 << seat)
        || post.acted_mask != pre.acted_mask & !(1u16 << seat)
        || post.leave_after_hand_mask != pre.leave_after_hand_mask & !(1u16 << seat)
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "reveal timeout kick has an invalid custody/lifecycle delta".into(),
        ));
    }
    for (index, (before, after)) in pre.seats.iter().zip(post.seats.iter()).enumerate() {
        if index == seat {
            continue;
        }
        if before != after {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "reveal timeout kick changed an unrelated seat".into(),
            ));
        }
    }
    // A non-terminal kick must leave enough active players for the VM to stay
    // in the reveal loop.  The terminal reset/end branch is a separate proof.
    let remaining_active = post
        .seats
        .iter()
        .filter(|seat| seat.status == CanonicalSeatStatus::Active)
        .count();
    if remaining_active < 2 {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "non-terminal reveal timeout kick reaches a terminal population".into(),
        ));
    }
    Ok(())
}

fn reconstruct_participant(status: CanonicalSeatStatus) -> bool {
    matches!(
        status,
        CanonicalSeatStatus::Active | CanonicalSeatStatus::Folded | CanonicalSeatStatus::AllIn
    )
}

fn live_player(status: CanonicalSeatStatus) -> bool {
    matches!(
        status,
        CanonicalSeatStatus::Active | CanonicalSeatStatus::AllIn
    )
}

fn validate_reconstruct_terminal(
    transition: &RevealTimeoutReconstructTransition,
    phase: u8,
    street: u8,
) -> TexasAirResult<()> {
    let pre = &transition.pre;
    let post = &transition.post;
    let seat = usize::from(transition.seat);
    if seat >= usize::from(pre.max_players)
        || pre.phase != CanonicalPhase::Revealing
        || pre.phase_subtag != phase
        || pre.street != street
        || pre.current_turn != NO_CANONICAL_SEAT
        || pre.protocol_pending_mask != (1u16 << seat)
        || pre.seats[seat].status != CanonicalSeatStatus::Active
        || transition.deadline_height < pre.deadline_ms
        || post.phase != CanonicalPhase::Reconstructing
        || post.phase_subtag != CANONICAL_RECONSTRUCT_COLLECTING_SUBTAG
        || post.street != pre.street
        || post.current_turn != NO_CANONICAL_SEAT
        || post.deadline_ms
            != transition
                .deadline_height
                .checked_add(u64::from(pre.reconstruct_timeout_ms))
                .ok_or_else(|| {
                    TexasAirError::ConstraintUnsatisfied(
                        "reveal timeout reconstruct deadline overflow".into(),
                    )
                })?
        || post.current_bet != pre.current_bet
        || post.min_raise != pre.min_raise
        || post.board_cards_commitment != pre.board_cards_commitment
        || post.deck_commitment != pre.deck_commitment
        // `take_reveal_payload` preserves the full ledger as suspended state;
        // the final tagged composition also proves this hash equality against
        // the ZR4 opening.
        || post.reveal_commitment != pre.reveal_commitment
        || post.run_it_twice_commitment != pre.run_it_twice_commitment
        || post.reconstruction_commitment == [0; 32]
        || post.reconstruction_commitment == pre.reconstruction_commitment
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "reveal timeout reconstruct continuation has an invalid protocol header".into(),
        ));
    }
    let before = pre.seats[seat];
    let after = post.seats[seat];
    let refund = before
        .stack
        .checked_add(before.pending_addon)
        .ok_or_else(|| {
            TexasAirError::ConstraintUnsatisfied("reveal timeout terminal refund overflow".into())
        })?;
    if after.status != CanonicalSeatStatus::Out
        || after.stack != 0
        || after.pending_addon != 0
        || after.bet != 0
        || after.total_bet != before.total_bet
        || after.time_bank_ms != before.time_bank_ms
        || after.identity_commitment != before.identity_commitment
        || after.key_commitment != [0; 32]
        || after.hole_cards_commitment != [0; 32]
        || post.pot
            != pre.pot.checked_add(before.bet).ok_or_else(|| {
                TexasAirError::ConstraintUnsatisfied("reveal timeout terminal pot overflow".into())
            })?
        || post.chip_pool
            != pre.chip_pool.checked_sub(refund).ok_or_else(|| {
                TexasAirError::ConstraintUnsatisfied(
                    "reveal timeout terminal chip_pool underflow".into(),
                )
            })?
        || post.acted_mask != pre.acted_mask & !(1u16 << seat)
        || post.leave_after_hand_mask != pre.leave_after_hand_mask & !(1u16 << seat)
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "reveal timeout reconstruct terminal kick has an invalid custody delta".into(),
        ));
    }
    let mut expected_pending_mask = 0u16;
    let mut live_count = 0usize;
    for (index, (before, after)) in pre.seats.iter().zip(post.seats.iter()).enumerate() {
        if index == seat {
            continue;
        }
        if before != after || before.status == CanonicalSeatStatus::Waiting {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "reveal timeout reconstruct terminal changed an unrelated seat".into(),
            ));
        }
        if reconstruct_participant(after.status) {
            expected_pending_mask |= 1u16 << index;
        }
        if live_player(after.status) {
            live_count += 1;
        }
    }
    if live_count < 2 || post.protocol_pending_mask != expected_pending_mask {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "reveal timeout reconstruct did not derive the VM active-seat pending mask".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical_reveal_opening::{
        CanonicalRevealAssignmentOpening, MAX_CANONICAL_REVEAL_ASSIGNMENTS,
    };
    use poker_l1::object_model::ObjectID;
    use poker_l1::vm::contracts::texas_poker::constants::ROUND_PREFLOP;
    use poker_l1::vm::contracts::texas_poker::events::TexasPokerEvent;
    use poker_l1::vm::contracts::texas_poker::state_machine;
    use poker_l1::vm::contracts::texas_poker::types::{
        RevealAssignment, RevealPurpose, RevealTarget, RevealTokenState, Seat, SeatStatus,
        TexasPokerTable,
    };
    use poker_l1::vm::contracts::texas_poker::utils::{g1_generator, scalar_from_u64};
    use poker_protocol::crypto::types::ECPoint;

    fn opening(mask: u16) -> CanonicalRevealLedgerOpening {
        let mut assignments =
            [CanonicalRevealAssignmentOpening::EMPTY; MAX_CANONICAL_REVEAL_ASSIGNMENTS];
        assignments[0] = CanonicalRevealAssignmentOpening {
            present: true,
            encrypted_card_index: 0,
            target_kind: 0,
            target_seat: 0,
            target_slot: 0,
            runout_index: 0,
            board_position: 0,
            pending_mask: mask,
            submitted_mask: 0,
        };
        CanonicalRevealLedgerOpening {
            phase: 1,
            street: 1,
            assignment_count: 1,
            pending_union: mask,
            assignments,
        }
    }

    fn reveal_image() -> CanonicalStateImage {
        let mut image = CanonicalStateImage {
            abi_version: crate::texas_canonical::CANONICAL_ABI_VERSION,
            table_id: 9,
            hand_id: 2,
            call_seq: 0,
            phase: CanonicalPhase::Revealing,
            phase_subtag: 1,
            street: 1,
            current_turn: NO_CANONICAL_SEAT,
            deadline_ms: 100,
            shuffle_timeout_ms: 10_000,
            reveal_timeout_ms: 10_000,
            betting_timeout_ms: 30_000,
            reconstruct_timeout_ms: 10_000,
            showdown_display_ms: 3_000,
            current_bet: 0,
            min_raise: 0,
            chip_pool: 300,
            pot: 0,
            button: 0,
            max_players: 3,
            acted_mask: 0,
            leave_after_hand_mask: 0,
            protocol_pending_mask: 0b111,
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
            seats: [crate::texas_canonical::CanonicalSeat::EMPTY; MAX_CANONICAL_SEATS],
        };
        for (index, seat) in image.seats[..3].iter_mut().enumerate() {
            *seat = crate::texas_canonical::CanonicalSeat {
                status: CanonicalSeatStatus::Active,
                acted: false,
                stack: 100,
                bet: 0,
                total_bet: 0,
                pending_addon: 0,
                time_bank_ms: 30_000,
                identity_commitment: [20 + index as u8; 32],
                key_commitment: [30 + index as u8; 32],
                hole_cards_commitment: [40 + index as u8; 32],
            };
        }
        image
    }

    #[test]
    fn schedule_is_fixed_width_and_ascending() {
        let plan = RevealTimeoutCascadeScope::from_opening(&opening(0b10101)).unwrap();
        assert_eq!(plan.kick_count, 3);
        assert_eq!(&plan.kick_schedule[..3], &[0, 2, 4]);
        assert_eq!(plan.kick_schedule[3], REVEAL_TIMEOUT_EMPTY_SEAT);
        plan.validate_header().unwrap();
    }

    #[test]
    fn schedule_mutations_are_rejected() {
        let mut plan = RevealTimeoutCascadeScope::from_opening(&opening(0b10101)).unwrap();
        plan.kick_schedule.swap(0, 1);
        assert!(plan.validate_header().is_err());
        let mut plan = RevealTimeoutCascadeScope::from_opening(&opening(0b11)).unwrap();
        plan.kick_count = 1;
        assert!(plan.validate_header().is_err());
    }

    #[test]
    fn complete_schedule_keeps_its_terminal_slot() {
        let plan = RevealTimeoutCascadeScope::from_opening(&opening(0x01ff)).unwrap();
        assert_eq!(plan.kick_count as usize, MAX_REVEAL_TIMEOUT_SCHEDULE);
        assert_eq!(plan.kick_schedule[8], 8);
        plan.validate_header().unwrap();
    }

    #[test]
    fn kick_delta_binds_refund_pot_and_intermediate_state() {
        let mut pre = reveal_image();
        pre.seats[0].stack = 90;
        pre.seats[0].pending_addon = 10;
        pre.seats[0].bet = 7;
        pre.seats[0].total_bet = 7;
        pre.chip_pool = 300;
        let mut post = pre.clone();
        post.call_seq = 1;
        post.pot = 7;
        post.chip_pool = 200;
        post.protocol_pending_mask = 0b110;
        post.seats[0].status = CanonicalSeatStatus::Out;
        post.seats[0].stack = 0;
        post.seats[0].pending_addon = 0;
        post.seats[0].bet = 0;
        post.seats[0].key_commitment = [0; 32];
        post.seats[0].hole_cards_commitment = [0; 32];
        let mut plan = RevealTimeoutCascadeScope::from_opening(&opening(0b111)).unwrap();
        plan.transitions
            .push(RevealTimeoutKickTransition { pre, post, seat: 0 });
        plan.validate_transitions().unwrap();

        plan.transitions[0].post.chip_pool -= 1;
        assert!(plan.validate_transitions().is_err());
    }

    #[test]
    fn nonpreflop_terminal_kick_enters_reconstruct_collecting() {
        let mut pre = reveal_image();
        pre.phase_subtag = 3;
        pre.street = 3;
        pre.max_players = 4;
        pre.protocol_pending_mask = 0b0101;
        pre.chip_pool = 400;
        pre.seats[3] = crate::texas_canonical::CanonicalSeat {
            status: CanonicalSeatStatus::Active,
            acted: false,
            stack: 100,
            bet: 0,
            total_bet: 0,
            pending_addon: 0,
            time_bank_ms: 30_000,
            identity_commitment: [23; 32],
            key_commitment: [33; 32],
            hole_cards_commitment: [43; 32],
        };

        let mut first_post = pre.clone();
        first_post.call_seq = 1;
        first_post.protocol_pending_mask = 0b0100;
        first_post.chip_pool = 300;
        first_post.seats[0].status = CanonicalSeatStatus::Out;
        first_post.seats[0].stack = 0;
        first_post.seats[0].pending_addon = 0;
        first_post.seats[0].bet = 0;
        first_post.seats[0].key_commitment = [0; 32];
        first_post.seats[0].hole_cards_commitment = [0; 32];

        let mut terminal_post = first_post.clone();
        terminal_post.call_seq = 2;
        terminal_post.phase = CanonicalPhase::Reconstructing;
        terminal_post.phase_subtag = CANONICAL_RECONSTRUCT_COLLECTING_SUBTAG;
        terminal_post.deadline_ms = 21_000;
        terminal_post.protocol_pending_mask = 0b1010;
        terminal_post.chip_pool = 200;
        terminal_post.reconstruction_commitment = [44; 32];
        terminal_post.seats[2].status = CanonicalSeatStatus::Out;
        terminal_post.seats[2].stack = 0;
        terminal_post.seats[2].pending_addon = 0;
        terminal_post.seats[2].bet = 0;
        terminal_post.seats[2].key_commitment = [0; 32];
        terminal_post.seats[2].hole_cards_commitment = [0; 32];

        let mut assignments =
            [CanonicalRevealAssignmentOpening::EMPTY; MAX_CANONICAL_REVEAL_ASSIGNMENTS];
        assignments[0] = CanonicalRevealAssignmentOpening {
            present: true,
            encrypted_card_index: 0,
            target_kind: 1,
            target_seat: 0,
            target_slot: 0,
            runout_index: 0,
            board_position: 0,
            pending_mask: 0b0101,
            submitted_mask: 0,
        };
        let mut plan = RevealTimeoutCascadeScope::from_opening(&CanonicalRevealLedgerOpening {
            phase: 3,
            street: 3,
            assignment_count: 1,
            pending_union: 0b0101,
            assignments,
        })
        .unwrap();
        plan.transitions.push(RevealTimeoutKickTransition {
            pre,
            post: first_post.clone(),
            seat: 0,
        });
        plan.reconstruct_terminal = Some(RevealTimeoutReconstructTransition {
            pre: first_post,
            post: terminal_post,
            seat: 2,
            deadline_height: 11_000,
        });
        plan.validate_transitions().unwrap();

        plan.reconstruct_terminal
            .as_mut()
            .unwrap()
            .post
            .protocol_pending_mask = 0b0010;
        assert!(plan.validate_transitions().is_err());
    }

    #[test]
    fn native_vm_walks_multi_pending_timeout_in_ascending_order() {
        let mut table = TexasPokerTable::new(
            ObjectID::new([0xD7; 20], 0),
            "multi-pending-reveal-timeout".into(),
            [0; 20],
            4,
            50,
            100,
        );
        let generator = g1_generator();
        for seat in 0..4u8 {
            table.seats[usize::from(seat)] = Seat::occupied(
                [seat + 1; 20],
                100,
                ECPoint(generator * scalar_from_u64(u64::from(seat + 1))),
                SeatStatus::Active,
            )
            .unwrap();
        }
        table.chip_pool = 400;
        state_machine::set_initial_encrypted_deck(&mut table).unwrap();
        table.deck_state.contributor_mask = 0b1111;
        table
            .enter_revealing(
                ROUND_PREFLOP,
                RevealTokenState {
                    purpose: RevealPurpose::DealHole,
                    assignments: vec![RevealAssignment {
                        encrypted_card_index: 0,
                        target: RevealTarget::Hole {
                            seat_index: 3,
                            card_slot: 0,
                        },
                        pending_mask: 0b0111,
                        submitted_mask: 0,
                        reveal_tokens: vec![],
                    }],
                },
                1_000,
            )
            .unwrap();

        let mut events = Vec::new();
        state_machine::advance_deadline(&mut table, 11_000, &mut events).unwrap();
        let kicked: Vec<u8> = events
            .iter()
            .filter_map(|event| match event {
                TexasPokerEvent::PlayerKicked { seat_index, .. } => Some(*seat_index),
                _ => None,
            })
            .collect();
        assert_eq!(kicked, vec![0, 1, 2]);
        assert_eq!(table.round_state(), 0);
        assert!(table.seats[3].is_occupied());
        assert_eq!(table.seats[3].stack(), 100);
        assert_eq!(table.chip_pool, 100);
    }

    #[test]
    fn native_vm_raked_one_survivor_reveal_timeout_charges_the_exact_rake() {
        let mut table = TexasPokerTable::new(
            ObjectID::new([0xDB; 20], 0),
            "raked-one-survivor-reveal-timeout".into(),
            [0; 20],
            4,
            50,
            100,
        );
        table.rules.rake_mode = 1;
        table.rules.rake_bps = 500;
        table.rules.rake_cap = 1_000;
        let generator = g1_generator();
        for seat in 0..3u8 {
            table.seats[usize::from(seat)] = Seat::occupied(
                [seat + 1; 20],
                100,
                ECPoint(generator * scalar_from_u64(u64::from(seat + 1))),
                SeatStatus::Active,
            )
            .unwrap();
        }
        table.chip_pool = 390;
        table.pot = 90;
        state_machine::set_initial_encrypted_deck(&mut table).unwrap();
        table.deck_state.contributor_mask = 0b0111;
        table
            .enter_revealing(
                3,
                RevealTokenState {
                    purpose: RevealPurpose::Board,
                    assignments: vec![RevealAssignment {
                        encrypted_card_index: 0,
                        target: RevealTarget::Board {
                            runout_index: 0,
                            board_position: 0,
                        },
                        pending_mask: 0b0011,
                        submitted_mask: 0,
                        reveal_tokens: vec![],
                    }],
                },
                1_000,
            )
            .unwrap();

        let mut events = Vec::new();
        state_machine::advance_deadline(&mut table, 11_000, &mut events).unwrap();
        // floor(90 * 500 / 10_000) = 4 raked from the 90-chip pot.
        assert_eq!(table.seats[2].stack(), 186);
        assert_eq!(table.chip_pool, 186);
        assert_eq!(table.pot, 0);
        let mut accounted = table.pot;
        for seat in &table.seats {
            accounted += seat.stack() + seat.pending_addon() + seat.bet();
        }
        assert_eq!(accounted, table.chip_pool);
    }

    #[test]
    fn native_vm_one_survivor_reveal_timeout_awards_the_complete_pot() {
        let mut table = TexasPokerTable::new(
            ObjectID::new([0xDA; 20], 0),
            "one-survivor-reveal-timeout".into(),
            [0; 20],
            4,
            50,
            100,
        );
        let generator = g1_generator();
        for seat in 0..3u8 {
            table.seats[usize::from(seat)] = Seat::occupied(
                [seat + 1; 20],
                100,
                ECPoint(generator * scalar_from_u64(u64::from(seat + 1))),
                SeatStatus::Active,
            )
            .unwrap();
        }
        table.chip_pool = 390;
        table.pot = 90;
        state_machine::set_initial_encrypted_deck(&mut table).unwrap();
        table.deck_state.contributor_mask = 0b0111;
        table
            .enter_revealing(
                3,
                RevealTokenState {
                    purpose: RevealPurpose::Board,
                    assignments: vec![RevealAssignment {
                        encrypted_card_index: 0,
                        target: RevealTarget::Board {
                            runout_index: 0,
                            board_position: 0,
                        },
                        pending_mask: 0b0011,
                        submitted_mask: 0,
                        reveal_tokens: vec![],
                    }],
                },
                1_000,
            )
            .unwrap();

        let mut events = Vec::new();
        state_machine::advance_deadline(&mut table, 11_000, &mut events).unwrap();
        let kicked: Vec<u8> = events
            .iter()
            .filter_map(|event| match event {
                TexasPokerEvent::PlayerKicked { seat_index, .. } => Some(*seat_index),
                _ => None,
            })
            .collect();
        assert_eq!(kicked, vec![0, 1]);
        let award = events
            .iter()
            .find_map(|event| match event {
                TexasPokerEvent::HandEndedWithoutShowdown {
                    winner_seat, pot, ..
                } => Some((*winner_seat, *pot)),
                _ => None,
            })
            .expect("sole-survivor award event");
        assert_eq!(award, (2, 90));
        // The survivor is credited the complete pot and table custody stays
        // conserved: the kicked seats left with their stacks only.
        assert_eq!(table.round_state(), 0);
        assert_eq!(table.pot, 0);
        assert_eq!(table.chip_pool, 190);
        assert_eq!(table.seats[2].stack(), 190);
        assert!(!table.seats[0].is_occupied());
        assert!(!table.seats[1].is_occupied());
        assert!(table.seats[2].is_occupied());
        let mut accounted = table.pot;
        for seat in &table.seats {
            accounted += seat.stack() + seat.pending_addon() + seat.bet();
        }
        assert_eq!(accounted, table.chip_pool);
    }

    #[test]
    fn native_vm_nonpreflop_timeout_enters_reconstruct_after_terminal_kick() {
        let mut table = TexasPokerTable::new(
            ObjectID::new([0xD8; 20], 0),
            "nonpreflop-reveal-timeout".into(),
            [0; 20],
            4,
            50,
            100,
        );
        let generator = g1_generator();
        for seat in 0..4u8 {
            table.seats[usize::from(seat)] = Seat::occupied(
                [seat + 1; 20],
                100,
                ECPoint(generator * scalar_from_u64(u64::from(seat + 1))),
                SeatStatus::Active,
            )
            .unwrap();
        }
        table.chip_pool = 400;
        state_machine::set_initial_encrypted_deck(&mut table).unwrap();
        table.deck_state.contributor_mask = 0b1111;
        table
            .enter_revealing(
                3,
                RevealTokenState {
                    purpose: RevealPurpose::Board,
                    assignments: vec![RevealAssignment {
                        encrypted_card_index: 0,
                        target: RevealTarget::Board {
                            runout_index: 0,
                            board_position: 0,
                        },
                        pending_mask: 0b0011,
                        submitted_mask: 0,
                        reveal_tokens: vec![],
                    }],
                },
                1_000,
            )
            .unwrap();

        let mut events = Vec::new();
        state_machine::advance_deadline(&mut table, 11_000, &mut events).unwrap();
        let kicked: Vec<u8> = events
            .iter()
            .filter_map(|event| match event {
                TexasPokerEvent::PlayerKicked { seat_index, .. } => Some(*seat_index),
                _ => None,
            })
            .collect();
        assert_eq!(kicked, vec![0, 1]);
        assert_eq!(table.round_state(), 3);
        assert_eq!(table.reconstruct_state().pending_mask, 0b1100);
        assert_eq!(table.reconstruct_deadline_ms().unwrap(), Some(21_000));
        assert!(!table.seats[0].is_occupied());
        assert!(!table.seats[1].is_occupied());
        assert!(table.seats[2].is_occupied());
        assert!(table.seats[3].is_occupied());
    }
}
