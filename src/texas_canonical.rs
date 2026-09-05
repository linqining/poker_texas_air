//! Fixed-width canonical ABI for the complete Texas Poker state machine.
//!
//! This module is deliberately independent from VM replay.  It is the state/transition
//! contract that a direct AIR must consume.  The current tagged betting AIR remains a
//! projection of this ABI until each transition family is wired into its own constraints.
#![allow(missing_docs)]

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};

pub const CANONICAL_ABI_VERSION: u16 = 6;
pub const MAX_CANONICAL_SEATS: usize = 9;
/// The flop under run-it-twice is the largest board reveal batch: three cards
/// on each of two runouts.  Keeping this array fixed is essential for the
/// tagged AIR's one-proof-per-table trace layout.
pub const MAX_CANONICAL_BOARD_REVEAL_ASSIGNMENTS: usize = 6;
pub const NO_CANONICAL_SEAT: u8 = 0x0f;
/// Legacy VM subtag for `ReconstructState::COLLECTING`.
pub const CANONICAL_RECONSTRUCT_COLLECTING_SUBTAG: u8 = 1;
/// Legacy VM subtag for `ShufflingPhase::Reconstruct`.
pub const CANONICAL_SHUFFLE_RECONSTRUCT_SUBTAG: u8 = 2;

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
            CanonicalSeatStatus::Active if self.stack == 0 => {
                return Err("active seat has zero stack; it must be all-in".into());
            }
            CanonicalSeatStatus::AllIn if self.stack != 0 => {
                return Err("all-in seat retains a non-zero stack".into());
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
    /// Canonical VM timeout configuration.  These durations are immutable
    /// table parameters and are opened directly so phase-completion deadlines
    /// never depend on a prover-selected deployment default.
    pub shuffle_timeout_ms: u32,
    pub reveal_timeout_ms: u32,
    pub betting_timeout_ms: u32,
    pub reconstruct_timeout_ms: u32,
    pub showdown_display_ms: u32,
    pub current_bet: u64,
    pub min_raise: u64,
    /// Exact TableVault custody balance.  It is not derivable from a selected
    /// seat projection, so it must be part of the canonical state opening.
    pub chip_pool: u64,
    pub pot: u64,
    pub button: u8,
    pub max_players: u8,
    pub acted_mask: u16,
    pub leave_after_hand_mask: u16,
    /// Seats that still owe the active shuffle/reveal/reconstruct protocol a
    /// submission.  Reveal uses the union of every assignment's pending mask;
    /// the VM requires one submit call to cover every assignment owed by that
    /// seat, so one bit is removed atomically per accepted protocol action.
    pub protocol_pending_mask: u16,
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
        if self.acted_mask & !valid_mask != 0
            || self.leave_after_hand_mask & !valid_mask != 0
            || self.protocol_pending_mask & !valid_mask != 0
        {
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
            if self.phase_subtag != 0
                || self.street != 0
                || self.acted_mask != 0
                || self.protocol_pending_mask != 0
            {
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
        if matches!(
            self.phase,
            CanonicalPhase::Shuffling | CanonicalPhase::Revealing | CanonicalPhase::Reconstructing
        ) {
            if self.protocol_pending_mask == 0 {
                return Err("active protocol phase has no pending participant".into());
            }
        } else if self.protocol_pending_mask != 0 {
            return Err("non-protocol phase carries a pending participant mask".into());
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
            if self.protocol_pending_mask & bit != 0
                && !matches!(
                    seat.status,
                    CanonicalSeatStatus::Active
                        | CanonicalSeatStatus::Folded
                        | CanonicalSeatStatus::AllIn
                )
            {
                return Err("protocol pending mask addresses an ineligible seat".into());
            }
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
            if matches!(
                seat.status,
                CanonicalSeatStatus::Folded | CanonicalSeatStatus::AllIn
            ) && !seat.acted
            {
                return Err("folded/all-in seat must be marked acted".into());
            }
        }
        // This is the same custody identity enforced by
        // `poker_l1::...::reconcile_table_vault`: `total_bet` is an accounting
        // view, while value lives exactly once in stack, pending addon, current
        // round bet, or collected pot.  Keeping it in the ABI is necessary for
        // a no-replay funding proof.
        let accounted = self.seats.iter().try_fold(self.pot, |total, seat| {
            total
                .checked_add(seat.stack)
                .and_then(|value| value.checked_add(seat.pending_addon))
                .and_then(|value| value.checked_add(seat.bet))
        });
        if accounted != Some(self.chip_pool) {
            return Err("TableVault chip_pool does not match canonical custody buckets".into());
        }
        Ok(())
    }

    pub fn commitment(&self) -> [u8; 32] {
        // BLAKE3 padded-chain commitment (v3); the flock chain statement
        // authenticates the identical preimage on the verify path.
        const CANONICAL_STATE_DOMAIN: &[u8] = b"zchain.texas.canonical-state.v3";
        let bytes = borsh::to_vec(self).expect("canonical ABI is serializable");
        let mut preimage = Vec::with_capacity(CANONICAL_STATE_DOMAIN.len() + bytes.len());
        preimage.extend_from_slice(CANONICAL_STATE_DOMAIN);
        preimage.extend_from_slice(&bytes);
        crate::blake3_flock::blake3_chain_digest(&preimage)
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
    /// Internal VM micro-step emitted immediately after the final action of a
    /// betting round.  It collects every per-seat wager into the pot before
    /// entering the next reveal/showdown phase.  It has no public dispatcher
    /// selector: an authenticated tagged batch may contain it only as the
    /// canonical continuation of a completed betting state.
    AdvanceRound = 19,
    /// Permissionless betting-timeout action.  This is the non-cascading VM
    /// suffix: the timed-out actor folds and a fresh betting deadline is
    /// armed for the first remaining active seat.  Terminal settlement and
    /// round advancement remain separate canonical micro-steps.
    AutoFold = 20,
    /// Deterministic last-player-standing settlement followed by the
    /// next-hand reset.  The first direct branch is deliberately narrow:
    /// zero rake, no pending addon/leave ledger, and a fully funded winner.
    EndWithoutShowdown = 21,
    /// Deterministic reset-only micro-step.  This is used by timeout/error
    /// normalization when no pot or live wager remains.
    ResetOnly = 22,
    /// Narrow reconstruct-timeout branch: exactly one pending participant is
    /// kicked and a zero-wager hand is reset to WAITING.  The pre-state has
    /// at most two active seats, so the VM's internal kick cascade resets
    /// before the outer timeout handler can inspect the reconstruction
    /// accumulator.  The general multi-pending/three-or-more-active timeout
    /// cascade remains separate.
    ReconstructTimeoutReset = 23,
    /// Narrow preflop reveal-timeout branch: one pending active participant
    /// is kicked and the VM's low-population cascade resets the hand.
    RevealTimeoutReset = 24,
    /// Non-terminal reveal-timeout kick.  This is one row of the deterministic
    /// ascending pending-seat cascade; the terminal kick/reset continuation is
    /// represented by a separate typed transition.
    RevealTimeoutKick = 25,
    /// Non-preflop reveal-timeout continuation after the complete pending
    /// union has been kicked. The VM suspends the reveal ledger and enters
    /// reconstruct collecting for every retained participant.
    RevealTimeoutReconstruct = 26,
    /// Sole-survivor reveal-timeout terminal: the final pending seat is
    /// kicked and the complete pot is awarded to the one remaining live
    /// player, mirroring the VM's `end_without_showdown` endpoint.  Only the
    /// zero-rake branch is represented; a raked award requires the dedicated
    /// settlement opening and stays fail-closed.
    RevealTimeoutAward = 27,
    /// Raked sole-survivor reveal-timeout terminal: identical kick and award
    /// shape as `RevealTimeoutAward`, but the authenticated rules opening
    /// carries a percentage rake configuration and the AIR proves
    /// `rake = min(floor(pot * bps / 10_000), cap, pot)` before crediting
    /// `pot - rake` to the survivor and removing the rake from table custody.
    RevealTimeoutRakedAward = 28,
}

impl CanonicalTransitionKind {
    pub const fn requires_seat(self) -> bool {
        matches!(
            self,
            Self::AdvanceDeadline
                | Self::AutoFold
                | Self::JoinTable
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
                | Self::EndWithoutShowdown
                | Self::ReconstructTimeoutReset
                | Self::RevealTimeoutReset
                | Self::RevealTimeoutKick
                | Self::RevealTimeoutReconstruct
                | Self::RevealTimeoutAward
                | Self::RevealTimeoutRakedAward
        )
    }

    pub const fn permissionless(self) -> bool {
        matches!(
            self,
            Self::AdvanceDeadline
                | Self::AdvanceRound
                | Self::AutoFold
                | Self::EndWithoutShowdown
                | Self::ResetOnly
                | Self::ReconstructTimeoutReset
                | Self::RevealTimeoutReset
                | Self::RevealTimeoutKick
                | Self::RevealTimeoutReconstruct
                | Self::RevealTimeoutAward
                | Self::RevealTimeoutRakedAward
        )
    }

    pub const fn carries_crypto_proof(self) -> bool {
        matches!(
            self,
            Self::SubmitShuffle
                | Self::SubmitReveal
                | Self::SubmitReconstruct
                | Self::FoldWithProof
        )
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

/// One fixed-width pending board-reveal assignment.  The encrypted-card index
/// is public protocol routing data; the ciphertext and individual reveal
/// tokens remain committed and are verified by the subsequent crypto AIR.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CanonicalBoardRevealAssignment {
    /// Whether this entry is occupied.  Unused entries must be all zero.
    pub present: bool,
    /// Position in the current encrypted deck, always below 52.
    pub encrypted_card_index: u8,
    /// First board (`0`) or the run-it-twice second board (`1`).
    pub runout_index: u8,
    /// Destination index in the complete target board, always below 5.
    pub board_position: u8,
    /// Players that must submit a token for this card.
    pub pending_mask: u16,
    /// Tokens already submitted at transition construction.  A newly opened
    /// board reveal must have no submissions.
    pub submitted_mask: u16,
}

impl CanonicalBoardRevealAssignment {
    /// Canonical padding entry.
    pub const EMPTY: Self = Self {
        present: false,
        encrypted_card_index: 0,
        runout_index: 0,
        board_position: 0,
        pending_mask: 0,
        submitted_mask: 0,
    };
}

/// Fixed-width public opening for the board-reveal schedule created by the
/// VM's `start_community_reveal_phase`.  It is present only on the internal
/// [`CanonicalTransitionKind::AdvanceRound`] micro-step.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CanonicalRoundAdvanceOpening {
    /// Deck cursor before assignments are allocated.
    pub pre_cards_dealt: u8,
    /// Deck cursor after all assignments are allocated.
    pub post_cards_dealt: u8,
    /// Materialized first-board length before/after opening the reveal phase.
    /// It does not change until reveal tokens resolve.
    pub pre_board_len: u8,
    pub post_board_len: u8,
    /// Materialized second-board length for run-it-twice.
    pub pre_second_board_len: u8,
    pub post_second_board_len: u8,
    /// Whether the VM run-it-twice schedule is active.
    pub run_it_twice: bool,
    /// Fixed `RevealPurpose::Board` tag (`2`) while active, otherwise zero.
    pub reveal_purpose: u8,
    /// Number of occupied entries in `assignments`.
    pub assignment_count: u8,
    /// Canonically ordered assignments; padding is [`CanonicalBoardRevealAssignment::EMPTY`].
    pub assignments: [CanonicalBoardRevealAssignment; MAX_CANONICAL_BOARD_REVEAL_ASSIGNMENTS],
}

impl Default for CanonicalRoundAdvanceOpening {
    fn default() -> Self {
        Self {
            pre_cards_dealt: 0,
            post_cards_dealt: 0,
            pre_board_len: 0,
            post_board_len: 0,
            pre_second_board_len: 0,
            post_second_board_len: 0,
            run_it_twice: false,
            reveal_purpose: 0,
            assignment_count: 0,
            assignments: [CanonicalBoardRevealAssignment::EMPTY;
                MAX_CANONICAL_BOARD_REVEAL_ASSIGNMENTS],
        }
    }
}

/// Fixed protocol-completion branch carried by the canonical transition ABI.
///
/// Shuffle and reveal completion remain disabled.  Keeping an explicit `None`
/// tag makes every unrelated transition carry one canonical all-zero opening.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum CanonicalProtocolCompletionKind {
    None = 0,
    Reconstruct = 1,
    /// Final shuffle contribution (preflop): the completing submit advances
    /// the hand from `Shuffling` into the preflop reveal phase.  The opening
    /// mirrors the VM's `start_preflop_reveal_phase` normalization (deck
    /// unchanged, hole-card cursor 0 -> 2×participants, reveal pending mask =
    /// active participants, deadline re-armed with the reveal timeout).
    Shuffle = 2,
}

impl Default for CanonicalProtocolCompletionKind {
    fn default() -> Self {
        Self::None
    }
}

/// Fixed-width opening for the deterministic normalization performed after
/// the final reconstruction contribution.
///
/// The deck/reconstruction fields are deliberately duplicated from the state
/// image.  The canonical AIR binds the duplicates to the endpoint image so a
/// dedicated reconstruction/commitment AIR can consume this statement without
/// reopening an unconstrained host projection.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize, Default)]
pub struct CanonicalProtocolCompletionOpening {
    pub kind: CanonicalProtocolCompletionKind,
    /// Authenticated consensus timestamp used by VM normalization.
    pub completion_timestamp_ms: u64,
    /// Cursor in the pre-reconstruction deck and the freshly rebuilt deck.
    pub pre_cards_dealt: u8,
    pub post_cards_dealt: u8,
    /// Commitment to the reveal payload suspended across reconstruction and
    /// the subsequent reconstruct-shuffle phase.
    pub suspended_reveal_commitment: [u8; 32],
    /// Complete shuffle progress opened by `on_complete_reconstruct`.
    pub post_shuffle_pending_mask: u16,
    pub post_shuffle_completed_mask: u16,
    /// Endpoint commitment statement reserved for reconstruction crypto and
    /// deck-state commitment composition.
    pub pre_deck_commitment: [u8; 32],
    pub post_deck_commitment: [u8; 32],
    pub pre_reconstruction_commitment: [u8; 32],
    pub post_reconstruction_commitment: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CanonicalTransitionWitness {
    pub pre: CanonicalStateImage,
    pub post: CanonicalStateImage,
    pub kind: CanonicalTransitionKind,
    pub actor: [u8; 32],
    pub action: CanonicalActionPayload,
    /// Fixed-width schedule opening for a completed betting round.  It is
    /// canonical-zero for every other transition kind.
    pub round_advance: CanonicalRoundAdvanceOpening,
    /// Fixed-width deterministic protocol-completion opening.  It is non-zero
    /// only for the final `SubmitReconstruct` branch currently enabled.
    pub protocol_completion: CanonicalProtocolCompletionOpening,
    /// Authenticated rake configuration for raked settlement terminals.  It
    /// is canonical-zero for every other kind and is bound to the pre rules
    /// commitment by the companion Blake2b rules-opening proof.
    pub rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening,
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
        if !self.kind.carries_crypto_proof()
            && !matches!(
                self.kind,
                CanonicalTransitionKind::EndWithoutShowdown
                    | CanonicalTransitionKind::ResetOnly
                    | CanonicalTransitionKind::ReconstructTimeoutReset
                    | CanonicalTransitionKind::RevealTimeoutReset
                    | CanonicalTransitionKind::RevealTimeoutKick
                    | CanonicalTransitionKind::RevealTimeoutReconstruct
                    | CanonicalTransitionKind::RevealTimeoutAward
                    | CanonicalTransitionKind::RevealTimeoutRakedAward
            )
            && self.action.proof_commitment != [0; 32]
        {
            return Err("non-crypto transition carries a reserved proof commitment".into());
        }
        if !matches!(
            self.kind,
            CanonicalTransitionKind::AdvanceDeadline
                | CanonicalTransitionKind::AutoFold
                | CanonicalTransitionKind::ReconstructTimeoutReset
                | CanonicalTransitionKind::RevealTimeoutReset
                | CanonicalTransitionKind::RevealTimeoutKick
                | CanonicalTransitionKind::RevealTimeoutReconstruct
                | CanonicalTransitionKind::RevealTimeoutAward
                | CanonicalTransitionKind::RevealTimeoutRakedAward
        ) && self.deadline_height != 0
        {
            return Err("transition carries an unused consensus deadline height".into());
        }
        if !matches!(
            self.kind,
            CanonicalTransitionKind::AdvanceDeadline
                | CanonicalTransitionKind::EndWithoutShowdown
                | CanonicalTransitionKind::ReconstructTimeoutReset
                | CanonicalTransitionKind::RevealTimeoutReset
                | CanonicalTransitionKind::RevealTimeoutKick
                | CanonicalTransitionKind::RevealTimeoutReconstruct
        ) && self.action.auxiliary != 0
        {
            return Err("transition carries an unused auxiliary action field".into());
        }
        if self.kind != CanonicalTransitionKind::SetLeaveAfterHand
            && self.kind != CanonicalTransitionKind::AdvanceDeadline
            && self.action.flag
        {
            return Err("transition carries an unused action flag".into());
        }
        if matches!(
            self.kind,
            CanonicalTransitionKind::CreateTable
                | CanonicalTransitionKind::StartHand
                | CanonicalTransitionKind::AdvanceRound
                | CanonicalTransitionKind::ResetOnly
        ) && self.action.seat != NO_CANONICAL_SEAT
        {
            return Err("seatless transition does not use the canonical no-seat sentinel".into());
        }
        if matches!(
            self.kind,
            CanonicalTransitionKind::CreateTable
                | CanonicalTransitionKind::StartHand
                | CanonicalTransitionKind::ForceFold
                | CanonicalTransitionKind::SubmitShuffle
                | CanonicalTransitionKind::SubmitReveal
                | CanonicalTransitionKind::SubmitReconstruct
                | CanonicalTransitionKind::Fold
                | CanonicalTransitionKind::Check
                | CanonicalTransitionKind::SetLeaveAfterHand
                | CanonicalTransitionKind::FoldWithProof
                | CanonicalTransitionKind::AdvanceRound
                | CanonicalTransitionKind::AutoFold
                | CanonicalTransitionKind::ResetOnly
        ) && self.action.amount != 0
        {
            return Err("transition carries an unused action amount".into());
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
        digest(b"zchain.texas.canonical-transition.v2", self)
    }

    /// Commitment over the complete transition payload excluding the two derived
    /// anti-replay fields.  `transition_commitment` is this value; keeping the
    /// derivation separate avoids a self-referential fixed-point commitment.
    pub fn content_commitment(&self) -> [u8; 32] {
        let mut payload = self.clone();
        payload.transition_commitment = [0; 32];
        payload.nullifier = [0; 32];
        digest(b"zchain.texas.canonical-transition-content.v2", &payload)
    }

    /// Commitment used by canonical crypto requests before the request/proof
    /// digest itself is known.
    ///
    /// The crypto commitment and the two derived anti-replay fields are zeroed
    /// to avoid a circular fixed point: the request call context commits to
    /// this value, while the encoded request digest is subsequently installed
    /// as [`CanonicalActionPayload::proof_commitment`] and covered by
    /// [`Self::content_commitment`].
    pub fn crypto_scope_commitment(&self) -> [u8; 32] {
        let mut payload = self.clone();
        payload.action.proof_commitment = [0; 32];
        payload.transition_commitment = [0; 32];
        payload.nullifier = [0; 32];
        digest(b"zchain.texas.canonical-crypto-scope.v1", &payload)
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
            return Err(
                "canonical transition batch changes hand without a contiguous start_hand".into(),
            );
        }
        if witness.kind == CanonicalTransitionKind::StartHand {
            hand_id = witness.post.hand_id;
        }
    }
    Ok(())
}

/// Validate the witness envelope accepted by the canonical direct AIR.
///
/// #22④：`SubmitShuffle` / `SubmitReconstruct` 已解除 fail-closed——状态机
/// 规范化语义（协议进度、相位/截止时间、全字段冻结集）由 canonical AIR
/// 直接约束；deck/reconstruction 承诺**轮转**与实际密文的绑定属 native
/// 验证 + 链上 EC_OP 批次通道（Plan D ④，残留信任见 README 信任模型）。
/// `SubmitReveal`（betting-state turn 规则与盲注派生 opening 未设计）与
/// `FoldWithProof` 维持拒绝。
pub fn validate_direct_batch(witnesses: &[CanonicalTransitionWitness]) -> Result<(), String> {
    validate_batch(witnesses)?;
    if witnesses.iter().any(|witness| {
        witness.kind.carries_crypto_proof()
            && witness.kind != CanonicalTransitionKind::SubmitShuffle
            && witness.kind != CanonicalTransitionKind::SubmitReconstruct
    }) {
        return Err(
            "canonical crypto transition is unavailable until its dedicated crypto AIR is composed"
                .into(),
        );
    }
    Ok(())
}

pub fn transition_nullifier(witness: &CanonicalTransitionWitness) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(32 * 3 + 8);
    bytes.extend_from_slice(b"zchain.texas.nullifier.v2");
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

/// Enforce a closed set of mutable fields for a transition family.
///
/// Unlike the historical `same_except` predicate, this helper copies only fields explicitly
/// named by the family into the comparison image.  A true predicate is not allowed to bless an
/// unrelated state mutation.
fn only_allowed_changes(
    pre: &CanonicalStateImage,
    post: &CanonicalStateImage,
    changed_seat: Option<usize>,
    allow: impl Fn(&mut CanonicalStateImage, &CanonicalStateImage),
) -> Result<(), String> {
    let mut expected = pre.clone();
    expected.state_root = [0; 32];
    expected.lifecycle_root = [0; 32];
    expected.overlay_root = [0; 32];
    let mut actual = post.clone();
    actual.state_root = [0; 32];
    actual.lifecycle_root = [0; 32];
    actual.overlay_root = [0; 32];
    if let Some(index) = changed_seat {
        expected.seats[index] = CanonicalSeat::EMPTY;
    }
    allow(&mut expected, post);
    if let Some(index) = changed_seat {
        expected.seats[index] = post.seats[index];
    }
    if expected != actual {
        return Err("transition changed a field outside its canonical relation".into());
    }
    Ok(())
}

fn active_reveal_mask(seats: &[CanonicalSeat; MAX_CANONICAL_SEATS]) -> u16 {
    seats.iter().enumerate().fold(0u16, |mask, (index, seat)| {
        if matches!(
            seat.status,
            CanonicalSeatStatus::Active | CanonicalSeatStatus::Folded | CanonicalSeatStatus::AllIn
        ) {
            mask | (1u16 << index)
        } else {
            mask
        }
    })
}

/// Mirror the VM's circular `advance_turn` scan for a betting action.  An
/// occupied Active seat that has already acted is not actionable and must be
/// skipped; returning an arbitrary different seat would otherwise let the
/// native canonical relation diverge from the direct AIR.
fn expected_betting_successor(post: &CanonicalStateImage, actor: usize) -> u8 {
    (1..=MAX_CANONICAL_SEATS)
        .map(|offset| ((actor + offset) % usize::from(post.max_players)) as u8)
        .find(|&candidate| {
            let seat = post.seats[usize::from(candidate)];
            // A short all-in can raise the water over an already-acted seat;
            // such a seat still owes chips and remains actionable (it must
            // call or fold) even though its acted bit stays set (TDA #41).
            seat.status == CanonicalSeatStatus::Active
                && (!seat.acted || seat.bet < post.current_bet)
        })
        .unwrap_or(NO_CANONICAL_SEAT)
}

/// Validate the final-shuffle-completion opening against the VM's
/// `advance_shuffle` -> `start_preflop_reveal_phase` normalization: the deck
/// is unchanged (the completing contribution already replaced it), the
/// hole-card cursor opens 2 cards per active participant, the reveal pending
/// mask is the active set, and the deadline is re-armed with the reveal
/// timeout opened from the pre-state image.
fn validate_shuffle_completion_opening(
    pre: &CanonicalStateImage,
    post: &CanonicalStateImage,
    opening: &CanonicalProtocolCompletionOpening,
) -> Result<(), String> {
    if opening.kind != CanonicalProtocolCompletionKind::Shuffle
        || opening.completion_timestamp_ms == 0
        || opening.pre_cards_dealt != 0
        || opening.post_cards_dealt > 52
        || opening.post_cards_dealt % 2 != 0
    {
        return Err("final shuffle completion has invalid kind/time/deck cursor".into());
    }
    let active_mask = active_reveal_mask(&post.seats);
    if active_mask == 0
        || opening.post_shuffle_pending_mask != active_mask
        || opening.post_shuffle_pending_mask != post.protocol_pending_mask
        || opening.post_shuffle_completed_mask != active_mask
    {
        return Err("final shuffle completion has invalid protocol progress".into());
    }
    // deck 承诺在完成提交内**轮转**（最后贡献者的输出即终局 deck）——
    // 轮转与实际密文的绑定属 native/链上 EC_OP 通道（Plan D，设计 ④），
    // canonical 组合只锚定 opening 与端点镜像一致。
    if opening.suspended_reveal_commitment != [0; 32]
        || opening.pre_deck_commitment != pre.deck_commitment
        || opening.post_deck_commitment != post.deck_commitment
        || opening.pre_reconstruction_commitment != pre.reconstruction_commitment
        || opening.post_reconstruction_commitment != post.reconstruction_commitment
    {
        return Err("final shuffle completion is detached from endpoint commitments".into());
    }
    let deadline_ms = opening
        .completion_timestamp_ms
        .checked_add(u64::from(pre.reveal_timeout_ms))
        .ok_or("final shuffle reveal deadline overflow")?;
    if pre.phase != CanonicalPhase::Shuffling
        || pre.phase_subtag != 1
        || pre.current_turn != NO_CANONICAL_SEAT
        || post.phase != CanonicalPhase::Revealing
        || post.phase_subtag != 1
        || post.street != pre.street
        || post.current_turn != NO_CANONICAL_SEAT
        || post.deadline_ms != deadline_ms
    {
        return Err("final shuffle completion has invalid VM normalization header".into());
    }
    Ok(())
}

fn validate_reconstruct_completion_opening(
    pre: &CanonicalStateImage,
    post: &CanonicalStateImage,
    opening: &CanonicalProtocolCompletionOpening,
) -> Result<(), String> {
    if opening.kind != CanonicalProtocolCompletionKind::Reconstruct
        || opening.completion_timestamp_ms == 0
        || opening.pre_cards_dealt > 52
        || opening.post_cards_dealt != 0
    {
        return Err("final reconstruct completion has invalid kind/time/deck cursor".into());
    }
    let active_mask = active_reveal_mask(&post.seats);
    if active_mask == 0
        || opening.post_shuffle_pending_mask != active_mask
        || opening.post_shuffle_pending_mask != post.protocol_pending_mask
        || opening.post_shuffle_completed_mask != 0
    {
        return Err("final reconstruct completion has invalid shuffle progress".into());
    }
    if opening.suspended_reveal_commitment != pre.reveal_commitment
        || opening.suspended_reveal_commitment != post.reveal_commitment
        || opening.pre_deck_commitment != pre.deck_commitment
        || opening.post_deck_commitment != post.deck_commitment
        || opening.pre_reconstruction_commitment != pre.reconstruction_commitment
        || opening.post_reconstruction_commitment != post.reconstruction_commitment
    {
        return Err("final reconstruct completion is detached from endpoint commitments".into());
    }
    let deadline_ms = opening
        .completion_timestamp_ms
        .checked_add(u64::from(pre.shuffle_timeout_ms))
        .ok_or("final reconstruct shuffle deadline overflow")?;
    if pre.phase_subtag != CANONICAL_RECONSTRUCT_COLLECTING_SUBTAG
        || pre.current_turn != NO_CANONICAL_SEAT
        || post.phase != CanonicalPhase::Shuffling
        || post.phase_subtag != CANONICAL_SHUFFLE_RECONSTRUCT_SUBTAG
        || post.street != pre.street
        || post.current_turn != NO_CANONICAL_SEAT
        || post.deadline_ms != deadline_ms
    {
        return Err("final reconstruct completion has invalid VM normalization header".into());
    }
    Ok(())
}

fn validate_board_reveal_opening(
    pre: &CanonicalStateImage,
    _post: &CanonicalStateImage,
    opening: &CanonicalRoundAdvanceOpening,
) -> Result<(), String> {
    // Canonical street values intentionally use the compact direct-ABI domain
    // 1=preflop, 2=flop, 3=turn, 4=river.  River->showdown needs the
    // owner-readable-hole-card opening and is fail-closed until that distinct
    // fixed-width ledger component is in the AIR.
    let (cards_per_runout, expected_board_len) = match pre.street {
        1 => (3u8, 0u8),
        2 => (1u8, 3u8),
        3 => (1u8, 4u8),
        _ => {
            return Err(
                "advance_round showdown requires the owner-hole-card opening, which is not enabled"
                    .into(),
            );
        }
    };
    if opening.pre_cards_dealt > 52
        || opening.post_cards_dealt > 52
        || opening.pre_board_len > 5
        || opening.post_board_len > 5
        || opening.pre_second_board_len > 5
        || opening.post_second_board_len > 5
        || opening.pre_board_len != expected_board_len
        || opening.post_board_len != opening.pre_board_len
        || opening.post_second_board_len != opening.pre_second_board_len
        || (opening.run_it_twice && opening.pre_second_board_len != opening.pre_board_len)
        || opening.reveal_purpose != 2
    {
        return Err("advance_round board opening has invalid deck/board metadata".into());
    }
    let runout_count = if opening.run_it_twice { 2 } else { 1 };
    let expected_assignments = cards_per_runout
        .checked_mul(runout_count)
        .ok_or("advance_round assignment count overflow")?;
    if opening.assignment_count != expected_assignments
        || usize::from(opening.assignment_count) > MAX_CANONICAL_BOARD_REVEAL_ASSIGNMENTS
        || opening.post_cards_dealt
            != opening
                .pre_cards_dealt
                .checked_add(expected_assignments)
                .ok_or("advance_round deck cursor overflow")?
    {
        return Err("advance_round board opening has an invalid assignment count".into());
    }
    let pending_mask = active_reveal_mask(&pre.seats);
    if pending_mask == 0 {
        return Err("advance_round board opening has no reveal participants".into());
    }
    for index in 0..MAX_CANONICAL_BOARD_REVEAL_ASSIGNMENTS {
        let assignment = opening.assignments[index];
        if index >= usize::from(expected_assignments) {
            if assignment != CanonicalBoardRevealAssignment::EMPTY {
                return Err("advance_round board opening has non-zero assignment padding".into());
            }
            continue;
        }
        let runout_index = (index / usize::from(cards_per_runout)) as u8;
        let offset = (index % usize::from(cards_per_runout)) as u8;
        let board_len = if runout_index == 0 {
            opening.pre_board_len
        } else {
            opening.pre_second_board_len
        };
        if !assignment.present
            || assignment.encrypted_card_index
                != opening
                    .pre_cards_dealt
                    .checked_add(index as u8)
                    .ok_or("advance_round encrypted card index overflow")?
            || assignment.runout_index != runout_index
            || assignment.board_position
                != board_len
                    .checked_add(offset)
                    .ok_or("advance_round board position overflow")?
            || assignment.board_position >= 5
            || assignment.pending_mask != pending_mask
            || assignment.submitted_mask != 0
        {
            return Err("advance_round board assignment is not the canonical VM schedule".into());
        }
    }
    Ok(())
}

const TERMINAL_TIME_BANK_MS: u32 = 30_000;

/// Validate the common, deliberately narrow direct-AIR reset projection.
///
/// The full VM reset has addon credits, deferred leaves, departures and a
/// capped time-bank refill.  Those branches need their own fixed ledgers.  A
/// canonical terminal row therefore admits only the economically closed
/// subset in which every retained participant is already at the time-bank
/// cap and there is no deferred funding or leave state.  This is a real VM
/// branch, rather than a host-computed approximation of the general reset.
fn validate_simple_reset_projection(
    pre: &CanonicalStateImage,
    post: &CanonicalStateImage,
    winner: Option<usize>,
    award: u64,
) -> Result<(), String> {
    if post.phase != CanonicalPhase::Waiting
        || post.phase_subtag != 0
        || post.street != 0
        || post.current_turn != NO_CANONICAL_SEAT
        || post.deadline_ms != 0
        || post.current_bet != 0
        || post.min_raise != 0
        || post.pot != 0
        || post.acted_mask != 0
        || post.leave_after_hand_mask != 0
        || post.protocol_pending_mask != 0
        || pre.leave_after_hand_mask != 0
        || pre.protocol_pending_mask != 0
        || post.deck_commitment == [0; 32]
    {
        return Err("terminal reset has an invalid cleared lifecycle header".into());
    }
    if post.board_cards_commitment != [0; 32]
        || post.reveal_commitment != [0; 32]
        || post.reconstruction_commitment != [0; 32]
        || post.run_it_twice_commitment != [0; 32]
    {
        return Err("terminal reset must clear hand-local protocol commitments".into());
    }
    for (index, (before, after)) in pre.seats.iter().zip(post.seats.iter()).enumerate() {
        let expected_status = match before.status {
            CanonicalSeatStatus::Empty => CanonicalSeatStatus::Empty,
            CanonicalSeatStatus::Active | CanonicalSeatStatus::Folded => {
                CanonicalSeatStatus::Active
            }
            CanonicalSeatStatus::AllIn
            | CanonicalSeatStatus::Out
            | CanonicalSeatStatus::Waiting => {
                return Err("terminal reset only supports retained active/folded seats".into());
            }
        };
        let expected_stack = if winner == Some(index) {
            before
                .stack
                .checked_add(award)
                .ok_or("terminal winner stack overflow")?
        } else {
            before.stack
        };
        if before.pending_addon != 0
            || before.time_bank_ms
                != if before.status == CanonicalSeatStatus::Empty {
                    0
                } else {
                    TERMINAL_TIME_BANK_MS
                }
            || after.status != expected_status
            || after.acted
            || after.stack != expected_stack
            || after.bet != 0
            || after.total_bet != 0
            || after.pending_addon != 0
            || after.time_bank_ms
                != if expected_status == CanonicalSeatStatus::Empty {
                    0
                } else {
                    TERMINAL_TIME_BANK_MS
                }
            || after.identity_commitment != before.identity_commitment
            || after.key_commitment != before.key_commitment
            || after.hole_cards_commitment != [0; 32]
        {
            return Err("terminal reset seat projection is not canonical".into());
        }
    }
    only_allowed_changes(pre, post, None, |expected, actual| {
        expected.call_seq = actual.call_seq;
        expected.phase = actual.phase;
        expected.phase_subtag = actual.phase_subtag;
        expected.street = actual.street;
        expected.current_turn = actual.current_turn;
        expected.deadline_ms = actual.deadline_ms;
        expected.current_bet = actual.current_bet;
        expected.min_raise = actual.min_raise;
        expected.pot = actual.pot;
        expected.acted_mask = actual.acted_mask;
        expected.leave_after_hand_mask = actual.leave_after_hand_mask;
        expected.protocol_pending_mask = actual.protocol_pending_mask;
        expected.board_cards_commitment = actual.board_cards_commitment;
        expected.deck_commitment = actual.deck_commitment;
        expected.reveal_commitment = actual.reveal_commitment;
        expected.reconstruction_commitment = actual.reconstruction_commitment;
        expected.run_it_twice_commitment = actual.run_it_twice_commitment;
        expected.custody_commitment = actual.custody_commitment;
        expected.seats = actual.seats;
    })?;
    Ok(())
}

/// Validate the no-rake last-player-standing settlement followed by the
/// narrow direct reset projection above.
fn validate_terminal_without_showdown(w: &CanonicalTransitionWitness) -> Result<(), String> {
    let pre = &w.pre;
    let post = &w.post;
    let winner = usize::from(w.action.seat);
    if pre.phase != CanonicalPhase::Betting
        || winner >= usize::from(pre.max_players)
        || w.action.auxiliary != 0
        || w.action.flag
        || w.action.proof_commitment != post.deck_commitment
        || pre.seats[winner].status != CanonicalSeatStatus::Active
        || pre
            .seats
            .iter()
            .filter(|seat| seat.status == CanonicalSeatStatus::Active)
            .count()
            != 1
    {
        return Err("end_without_showdown has an invalid winner/header".into());
    }
    let gross_pot = pre.seats.iter().try_fold(pre.pot, |sum, seat| {
        sum.checked_add(seat.bet)
            .ok_or("terminal collected-bet sum overflow")
    })?;
    if gross_pot == 0 || w.action.amount != gross_pot || post.chip_pool != pre.chip_pool {
        return Err("end_without_showdown has an invalid zero-rake award/custody relation".into());
    }
    validate_simple_reset_projection(pre, post, Some(winner), gross_pot)
}

/// Validate the no-pot reset branch used after a separately proved refund or
/// timeout cleanup.  It intentionally rejects any wager/refund/addon work so
/// that those value-moving paths cannot be smuggled through a reset selector.
fn validate_reset_only(w: &CanonicalTransitionWitness) -> Result<(), String> {
    let pre = &w.pre;
    let post = &w.post;
    if pre.phase == CanonicalPhase::Waiting
        || w.action.seat != NO_CANONICAL_SEAT
        || w.action.amount != 0
        || w.action.auxiliary != 0
        || w.action.flag
        || w.action.proof_commitment != post.deck_commitment
        || pre.pot != 0
        || pre.current_bet != 0
        || pre.min_raise != 0
        || pre
            .seats
            .iter()
            .any(|seat| seat.bet != 0 || seat.total_bet != 0)
        || post.chip_pool != pre.chip_pool
    {
        return Err("reset_only has an unproved monetary or action payload".into());
    }
    validate_simple_reset_projection(pre, post, None, 0)
}

/// Validate the fixed-width subset of `on_reconstruct_timeout` that can be
/// represented by one tagged row: one active participant is pending, there are
/// at most two active seats, no wager/addon ledger, and the VM's internal kick
/// cascade resets before the outer timeout handler can inspect the accumulator.
fn validate_reconstruct_timeout_reset(w: &CanonicalTransitionWitness) -> Result<(), String> {
    let pre = &w.pre;
    let post = &w.post;
    let seat = usize::from(w.action.seat);
    if pre.phase != CanonicalPhase::Reconstructing
        || pre.phase_subtag != CANONICAL_RECONSTRUCT_COLLECTING_SUBTAG
        || pre.street == 0
        || w.action.flag
        || w.action.auxiliary != 0
        || w.action.proof_commitment != post.deck_commitment
        || w.deadline_height < pre.deadline_ms
        || seat >= usize::from(pre.max_players)
        || pre.protocol_pending_mask != (1u16 << seat)
        || pre.seats[seat].status != CanonicalSeatStatus::Active
        || pre.seats[seat].bet != 0
        || pre.seats[seat].total_bet != 0
        || pre.seats[seat].pending_addon != 0
        || pre.pot != 0
        || pre.current_bet != 0
        || pre.min_raise != 0
    {
        return Err("reconstruct timeout reset has an invalid pending/wager header".into());
    }
    let refund = pre.seats[seat].stack;
    if refund == 0 || w.action.amount != refund {
        return Err("reconstruct timeout reset has an invalid refund amount".into());
    }
    let active_count = pre
        .seats
        .iter()
        .filter(|seat| seat.status == CanonicalSeatStatus::Active)
        .count();
    if !(1..=2).contains(&active_count) {
        return Err("reconstruct timeout reset must have one or two active seats".into());
    }
    if post.phase != CanonicalPhase::Waiting
        || post.phase_subtag != 0
        || post.street != 0
        || post.current_turn != NO_CANONICAL_SEAT
        || post.deadline_ms != 0
        || post.current_bet != 0
        || post.min_raise != 0
        || post.pot != 0
        || post.acted_mask != 0
        || post.leave_after_hand_mask != 0
        || post.protocol_pending_mask != 0
        || post.chip_pool
            != pre
                .chip_pool
                .checked_sub(refund)
                .ok_or("refund underflow")?
        || post.deck_commitment == [0; 32]
        || post.board_cards_commitment != [0; 32]
        || post.reveal_commitment != [0; 32]
        || post.reconstruction_commitment != [0; 32]
        || post.run_it_twice_commitment != [0; 32]
    {
        return Err("reconstruct timeout reset has an invalid waiting endpoint".into());
    }
    for (index, (before, after)) in pre.seats.iter().zip(post.seats.iter()).enumerate() {
        if index == seat {
            if after != &CanonicalSeat::EMPTY {
                return Err("timed-out reconstruct seat was not vacated".into());
            }
            continue;
        }
        match before.status {
            CanonicalSeatStatus::Empty | CanonicalSeatStatus::Out => {
                if after != before {
                    return Err("unoccupied reconstruct seat changed during reset".into());
                }
            }
            CanonicalSeatStatus::Active | CanonicalSeatStatus::Folded => {
                if before.bet != 0
                    || before.total_bet != 0
                    || before.pending_addon != 0
                    || before.time_bank_ms != TERMINAL_TIME_BANK_MS
                    || after.status != CanonicalSeatStatus::Active
                    || after.acted
                    || after.stack != before.stack
                    || after.bet != 0
                    || after.total_bet != 0
                    || after.pending_addon != 0
                    || after.time_bank_ms != TERMINAL_TIME_BANK_MS
                    || after.identity_commitment != before.identity_commitment
                    || after.key_commitment != before.key_commitment
                    || after.hole_cards_commitment != [0; 32]
                {
                    return Err("retained reconstruct seat has an invalid reset image".into());
                }
            }
            CanonicalSeatStatus::Waiting | CanonicalSeatStatus::AllIn => {
                return Err("unsupported seat status in reconstruct timeout reset".into());
            }
        }
    }
    Ok(())
}

/// Validate the bounded preflop reveal-timeout cascade.  The authenticated
/// reveal ledger is supplied as a composition sidecar; this transition only
/// consumes the already-projected single pending seat and proves the VM's
/// low-population kick/reset result.
fn validate_reveal_timeout_reset(w: &CanonicalTransitionWitness) -> Result<(), String> {
    let pre = &w.pre;
    let post = &w.post;
    let seat = usize::from(w.action.seat);
    if pre.phase != CanonicalPhase::Revealing
        || pre.phase_subtag != 1
        || pre.street != 1
        || w.action.flag
        || w.action.auxiliary != 0
        || w.action.proof_commitment != post.deck_commitment
        || w.deadline_height < pre.deadline_ms
        || seat >= usize::from(pre.max_players)
        || pre.protocol_pending_mask != (1u16 << seat)
        || pre.seats[seat].status != CanonicalSeatStatus::Active
        || pre.seats[seat].bet != 0
        || pre.seats[seat].total_bet != 0
        || pre.seats[seat].pending_addon != 0
        || pre.pot != 0
        || pre.current_bet != 0
        || pre.min_raise != 0
    {
        return Err("reveal timeout reset has an invalid pending/wager header".into());
    }
    let refund = pre.seats[seat].stack;
    if refund == 0 || w.action.amount != refund {
        return Err("reveal timeout reset has an invalid refund amount".into());
    }
    // Unlike reconstruct timeout, preflop reveal timeout resets after every
    // pending seat has been kicked regardless of how many non-pending players
    // remain. `on_reveal_timeout` takes its preflop reset branch after the
    // complete pending-union loop, so limiting this endpoint to one or two
    // active seats would reject a real VM continuation.
    if post.phase != CanonicalPhase::Waiting
        || post.phase_subtag != 0
        || post.street != 0
        || post.current_turn != NO_CANONICAL_SEAT
        || post.deadline_ms != 0
        || post.current_bet != 0
        || post.min_raise != 0
        || post.pot != 0
        || post.acted_mask != 0
        || post.leave_after_hand_mask != 0
        || post.protocol_pending_mask != 0
        || post.chip_pool
            != pre
                .chip_pool
                .checked_sub(refund)
                .ok_or("refund underflow")?
        || post.deck_commitment == [0; 32]
        || post.board_cards_commitment != [0; 32]
        || post.reveal_commitment != [0; 32]
        || post.reconstruction_commitment != [0; 32]
        || post.run_it_twice_commitment != [0; 32]
    {
        return Err("reveal timeout reset has an invalid waiting endpoint".into());
    }
    for (index, (before, after)) in pre.seats.iter().zip(post.seats.iter()).enumerate() {
        if index == seat {
            if after != &CanonicalSeat::EMPTY {
                return Err("timed-out reveal seat was not vacated".into());
            }
            continue;
        }
        match before.status {
            CanonicalSeatStatus::Empty | CanonicalSeatStatus::Out => {
                if after != before {
                    return Err("unoccupied reveal seat changed during reset".into());
                }
            }
            CanonicalSeatStatus::Active | CanonicalSeatStatus::Folded => {
                if before.bet != 0
                    || before.total_bet != 0
                    || before.pending_addon != 0
                    || before.time_bank_ms != TERMINAL_TIME_BANK_MS
                    || after.status != CanonicalSeatStatus::Active
                    || after.acted
                    || after.stack != before.stack
                    || after.bet != 0
                    || after.total_bet != 0
                    || after.pending_addon != 0
                    || after.time_bank_ms != TERMINAL_TIME_BANK_MS
                    || after.identity_commitment != before.identity_commitment
                    || after.key_commitment != before.key_commitment
                    || after.hole_cards_commitment != [0; 32]
                {
                    return Err("retained reveal seat has an invalid reset image".into());
                }
            }
            CanonicalSeatStatus::Waiting | CanonicalSeatStatus::AllIn => {
                return Err("unsupported seat status in reveal timeout reset".into());
            }
        }
    }
    Ok(())
}

/// Validate one non-terminal micro-step in the VM's ordered reveal-timeout
/// cascade.  The reveal-ledger sidecar proves that the selected seat is the
/// next assignment-union bit and that its removal changes every assignment
/// mask; this state relation proves the accompanying custody/lifecycle delta.
fn validate_reveal_timeout_kick(w: &CanonicalTransitionWitness) -> Result<(), String> {
    let pre = &w.pre;
    let post = &w.post;
    let seat = usize::from(w.action.seat);
    if pre.phase != CanonicalPhase::Revealing
        || pre.phase_subtag == 0
        || pre.street == 0
        || pre.current_turn != NO_CANONICAL_SEAT
        || post.phase != pre.phase
        || post.phase_subtag != pre.phase_subtag
        || post.street != pre.street
        || post.current_turn != NO_CANONICAL_SEAT
        || post.deadline_ms != pre.deadline_ms
        || w.deadline_height < pre.deadline_ms
        || w.action.auxiliary != 0
        || w.action.flag
        || seat >= usize::from(pre.max_players)
        || pre.protocol_pending_mask & (1u16 << seat) == 0
        || post.protocol_pending_mask != pre.protocol_pending_mask & !(1u16 << seat)
        || post.protocol_pending_mask == 0
        || pre.seats[seat].status != CanonicalSeatStatus::Active
        || post.seats[seat].status != CanonicalSeatStatus::Out
        || post.reveal_commitment == pre.reveal_commitment
        || w.action.proof_commitment != post.reveal_commitment
    {
        return Err("reveal timeout kick has an invalid protocol header".into());
    }
    let before = pre.seats[seat];
    let after = post.seats[seat];
    let refund = before
        .stack
        .checked_add(before.pending_addon)
        .ok_or("reveal timeout kick refund overflow")?;
    if refund == 0
        || w.action.amount != refund
        || post.pot
            != pre
                .pot
                .checked_add(before.bet)
                .ok_or("reveal timeout kick pot overflow")?
        || post.chip_pool
            != pre
                .chip_pool
                .checked_sub(refund)
                .ok_or("reveal timeout kick chip_pool underflow")?
        || after.stack != 0
        || after.pending_addon != 0
        || after.bet != 0
        || after.total_bet != before.total_bet
        || after.time_bank_ms != before.time_bank_ms
        || after.identity_commitment != before.identity_commitment
        || after.key_commitment != [0; 32]
        || after.hole_cards_commitment != [0; 32]
        || post.acted_mask != pre.acted_mask & !(1u16 << seat)
        || post.leave_after_hand_mask != pre.leave_after_hand_mask & !(1u16 << seat)
    {
        return Err("reveal timeout kick has an invalid custody/lifecycle delta".into());
    }
    if post
        .seats
        .iter()
        .filter(|seat| seat.status == CanonicalSeatStatus::Active)
        .count()
        < 2
    {
        return Err("reveal timeout kick must leave a non-terminal population".into());
    }
    only_allowed_changes(pre, post, Some(seat), |expected, actual| {
        expected.call_seq = actual.call_seq;
        expected.acted_mask = actual.acted_mask;
        expected.leave_after_hand_mask = actual.leave_after_hand_mask;
        expected.protocol_pending_mask = actual.protocol_pending_mask;
        expected.pot = actual.pot;
        expected.chip_pool = actual.chip_pool;
        expected.reveal_commitment = actual.reveal_commitment;
        expected.custody_commitment = actual.custody_commitment;
        expected.seats[seat] = actual.seats[seat];
    })?;
    Ok(())
}

/// Validate the non-preflop terminal continuation of a reveal-timeout
/// cascade. The VM kicks the final pending seat, then suspends the reveal
/// payload and enters `Reconstructing/Collecting` when at least two live
/// players remain. The reveal ledger itself is authenticated by the ZR4
/// sidecar; this row proves the resulting public state boundary.
fn validate_reveal_timeout_reconstruct(w: &CanonicalTransitionWitness) -> Result<(), String> {
    let pre = &w.pre;
    let post = &w.post;
    let seat = usize::from(w.action.seat);
    if pre.phase != CanonicalPhase::Revealing
        || pre.phase_subtag == 1
        || pre.street <= 1
        || pre.current_turn != NO_CANONICAL_SEAT
        || post.phase != CanonicalPhase::Reconstructing
        || post.phase_subtag != CANONICAL_RECONSTRUCT_COLLECTING_SUBTAG
        || post.street != pre.street
        || post.current_turn != NO_CANONICAL_SEAT
        || w.action.flag
        || w.action.auxiliary != 0
        || w.action.proof_commitment != post.reconstruction_commitment
        || post.reconstruction_commitment == [0; 32]
        || post.reconstruction_commitment == pre.reconstruction_commitment
        || post.reveal_commitment != pre.reveal_commitment
        || w.deadline_height < pre.deadline_ms
        || post.deadline_ms
            != w.deadline_height
                .checked_add(u64::from(pre.reconstruct_timeout_ms))
                .ok_or("reveal timeout reconstruct deadline overflow")?
        || seat >= usize::from(pre.max_players)
        || pre.protocol_pending_mask != (1u16 << seat)
        || pre.seats[seat].status != CanonicalSeatStatus::Active
    {
        return Err("reveal timeout reconstruct has an invalid phase/header".into());
    }
    let before = pre.seats[seat];
    let after = post.seats[seat];
    let refund = before
        .stack
        .checked_add(before.pending_addon)
        .ok_or("reveal timeout reconstruct refund overflow")?;
    if refund == 0
        || w.action.amount != refund
        || after.status != CanonicalSeatStatus::Out
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
                .ok_or("reveal timeout reconstruct pot overflow")?
        || post.chip_pool
            != pre
                .chip_pool
                .checked_sub(refund)
                .ok_or("reveal timeout reconstruct chip_pool underflow")?
        || post.acted_mask != pre.acted_mask & !(1u16 << seat)
        || post.leave_after_hand_mask != pre.leave_after_hand_mask & !(1u16 << seat)
        || post.current_bet != pre.current_bet
        || post.min_raise != pre.min_raise
    {
        return Err("reveal timeout reconstruct has an invalid terminal kick delta".into());
    }
    let expected_pending = post
        .seats
        .iter()
        .enumerate()
        .filter(|(_, value)| {
            matches!(
                value.status,
                CanonicalSeatStatus::Active
                    | CanonicalSeatStatus::Folded
                    | CanonicalSeatStatus::AllIn
            )
        })
        .fold(0u16, |mask, (index, _)| mask | (1u16 << index));
    if post.protocol_pending_mask != expected_pending
        || post
            .seats
            .iter()
            .filter(|value| {
                matches!(
                    value.status,
                    CanonicalSeatStatus::Active | CanonicalSeatStatus::AllIn
                )
            })
            .count()
            < 2
    {
        return Err("reveal timeout reconstruct has an invalid active pending mask".into());
    }
    only_allowed_changes(pre, post, Some(seat), |expected, actual| {
        expected.call_seq = actual.call_seq;
        expected.phase = actual.phase;
        expected.phase_subtag = actual.phase_subtag;
        expected.deadline_ms = actual.deadline_ms;
        expected.acted_mask = actual.acted_mask;
        expected.leave_after_hand_mask = actual.leave_after_hand_mask;
        expected.protocol_pending_mask = actual.protocol_pending_mask;
        expected.pot = actual.pot;
        expected.chip_pool = actual.chip_pool;
        expected.reconstruction_commitment = actual.reconstruction_commitment;
        expected.custody_commitment = actual.custody_commitment;
        expected.seats[seat] = actual.seats[seat];
    })?;
    Ok(())
}

/// Sole-survivor reveal-timeout terminal: the final pending participant is
/// kicked and the complete pot is awarded to the one remaining live player,
/// mirroring `end_without_showdown` after the raw reveal-timeout kick loop.
/// Only the zero-rake branch is represented; a raked award needs the
/// dedicated settlement opening and stays fail-closed.
fn validate_reveal_timeout_award(w: &CanonicalTransitionWitness) -> Result<(), String> {
    let pre = &w.pre;
    let post = &w.post;
    let seat = usize::from(w.action.seat);
    if pre.phase != CanonicalPhase::Revealing
        || pre.phase_subtag == 0
        || pre.phase_subtag != pre.street
        || pre.street == 0
        || pre.current_turn != NO_CANONICAL_SEAT
        || w.action.flag
        || w.action.auxiliary != 0
        || w.action.proof_commitment != post.deck_commitment
        || post.deck_commitment == [0; 32]
        || w.deadline_height < pre.deadline_ms
        || seat >= usize::from(pre.max_players)
        || pre.protocol_pending_mask != (1u16 << seat)
        || pre.seats[seat].status != CanonicalSeatStatus::Active
        || pre.leave_after_hand_mask != 0
        || pre.seats.iter().any(|value| value.bet != 0)
    {
        return Err("reveal timeout award has an invalid phase/wager header".into());
    }
    let refund = pre.seats[seat]
        .stack
        .checked_add(pre.seats[seat].pending_addon)
        .ok_or("reveal timeout award refund overflow")?;
    if refund == 0 || w.action.amount != refund || pre.pot == 0 {
        return Err("reveal timeout award has an invalid refund/award payload".into());
    }
    let live: Vec<usize> = pre
        .seats
        .iter()
        .enumerate()
        .filter(|(_, value)| {
            matches!(
                value.status,
                CanonicalSeatStatus::Active | CanonicalSeatStatus::AllIn
            )
        })
        .map(|(index, _)| index)
        .collect();
    if live.len() != 2 || !live.contains(&seat) {
        return Err("reveal timeout award must retain exactly one survivor".into());
    }
    let winner = live
        .iter()
        .copied()
        .find(|index| *index != seat)
        .expect("two distinct live seats contain a survivor");
    if post.phase != CanonicalPhase::Waiting
        || post.phase_subtag != 0
        || post.street != 0
        || post.current_turn != NO_CANONICAL_SEAT
        || post.deadline_ms != 0
        || post.current_bet != 0
        || post.min_raise != 0
        || post.pot != 0
        || post.acted_mask != 0
        || post.leave_after_hand_mask != 0
        || post.protocol_pending_mask != 0
        || post.board_cards_commitment != [0; 32]
        || post.reveal_commitment != [0; 32]
        || post.reconstruction_commitment != [0; 32]
        || post.run_it_twice_commitment != [0; 32]
        || post.chip_pool
            != pre
                .chip_pool
                .checked_sub(refund)
                .ok_or("reveal timeout award chip_pool underflow")?
    {
        return Err("reveal timeout award has an invalid waiting endpoint".into());
    }
    for (index, (before, after)) in pre.seats.iter().zip(post.seats.iter()).enumerate() {
        if index == seat {
            if after != &CanonicalSeat::EMPTY {
                return Err("reveal timeout award did not vacate the kicked seat".into());
            }
            continue;
        }
        if before.status == CanonicalSeatStatus::Out {
            // Seats kicked by earlier cascade rows are vacated by the reset.
            if after != &CanonicalSeat::EMPTY {
                return Err("reveal timeout award did not vacate an earlier kicked seat".into());
            }
            continue;
        }
        if index == winner {
            if after.status != CanonicalSeatStatus::Active
                || after.stack
                    != before
                        .stack
                        .checked_add(pre.pot)
                        .ok_or("reveal timeout award winner stack overflow")?
            {
                return Err("reveal timeout award did not credit the survivor".into());
            }
        } else {
            let expected_status =
                match before.status {
                    CanonicalSeatStatus::Empty => CanonicalSeatStatus::Empty,
                    CanonicalSeatStatus::Active | CanonicalSeatStatus::Folded => {
                        CanonicalSeatStatus::Active
                    }
                    // Seats kicked by earlier cascade rows are still marked `Out`
                    // here; the reset vacates them like the kicked terminal seat.
                    CanonicalSeatStatus::Out => CanonicalSeatStatus::Empty,
                    CanonicalSeatStatus::AllIn | CanonicalSeatStatus::Waiting => return Err(
                        "reveal timeout award only supports retained active/folded/kicked seats"
                            .into(),
                    ),
                };
            if after.status != expected_status
                || (before.status != CanonicalSeatStatus::Out && after.stack != before.stack)
                || (before.status == CanonicalSeatStatus::Out && after != &CanonicalSeat::EMPTY)
            {
                return Err("reveal timeout award changed an unrelated seat".into());
            }
        }
        let time_bank = if before.status == CanonicalSeatStatus::Empty {
            0
        } else {
            TERMINAL_TIME_BANK_MS
        };
        if before.pending_addon != 0
            || before.time_bank_ms != time_bank
            || after.acted
            || after.bet != 0
            || after.total_bet != 0
            || after.pending_addon != 0
            || after.time_bank_ms != time_bank
            || after.identity_commitment != before.identity_commitment
            || after.key_commitment != before.key_commitment
            || after.hole_cards_commitment != [0; 32]
        {
            return Err("reveal timeout award seat projection is not canonical".into());
        }
    }
    only_allowed_changes(pre, post, None, |expected, actual| {
        expected.call_seq = actual.call_seq;
        expected.phase = actual.phase;
        expected.phase_subtag = actual.phase_subtag;
        expected.street = actual.street;
        expected.current_turn = actual.current_turn;
        expected.deadline_ms = actual.deadline_ms;
        expected.current_bet = actual.current_bet;
        expected.min_raise = actual.min_raise;
        expected.pot = actual.pot;
        expected.acted_mask = actual.acted_mask;
        expected.leave_after_hand_mask = actual.leave_after_hand_mask;
        expected.protocol_pending_mask = actual.protocol_pending_mask;
        expected.board_cards_commitment = actual.board_cards_commitment;
        expected.deck_commitment = actual.deck_commitment;
        expected.reveal_commitment = actual.reveal_commitment;
        expected.reconstruction_commitment = actual.reconstruction_commitment;
        expected.run_it_twice_commitment = actual.run_it_twice_commitment;
        expected.custody_commitment = actual.custody_commitment;
        expected.chip_pool = actual.chip_pool;
        expected.seats = actual.seats;
    })?;
    Ok(())
}

/// Raked sole-survivor reveal-timeout terminal.  Identical shape to
/// [`validate_reveal_timeout_award`], except the authenticated rules opening
/// carries a percentage rake configuration: the AIR proves
/// `rake = min(floor(pot * bps / 10_000), cap, pot)`, the survivor is
/// credited `pot - rake`, and the rake leaves table custody.
fn validate_reveal_timeout_raked_award(w: &CanonicalTransitionWitness) -> Result<(), String> {
    let opening = &w.rake_opening;
    if opening.rake_mode != crate::canonical_rake_opening::CanonicalRakeOpening::PERCENTAGE_MODE
        || opening.rake_bps == 0
        || opening.rake_bps > 10_000
        || w.pre.pot > u32::MAX as u64
    {
        return Err("raked award has an invalid rake configuration".into());
    }
    let rake = crate::canonical_rake_opening::canonical_settlement_rake(w.pre.pot, opening);
    let winner = winner_of(w)?;
    let refund = w.pre.seats[usize::from(w.action.seat)]
        .stack
        .checked_add(w.pre.seats[usize::from(w.action.seat)].pending_addon)
        .ok_or("raked award refund overflow")?;
    // The raked terminal differs from the zero-rake shape by exactly the
    // rake on the two credited amounts; everything else is validated by the
    // shared award relation against the zero-rake projection.
    let mut adjusted = w.clone();
    adjusted.kind = CanonicalTransitionKind::RevealTimeoutAward;
    adjusted.post.seats[winner].stack = adjusted.pre.seats[winner].stack + adjusted.pre.pot;
    adjusted.post.chip_pool = adjusted
        .pre
        .chip_pool
        .checked_sub(refund)
        .ok_or("chip underflow")?;
    adjusted.rake_opening = crate::canonical_rake_opening::CanonicalRakeOpening::ZERO;
    validate_reveal_timeout_award(&adjusted)?;
    if w.post.seats[winner]
        .stack
        .checked_add(rake)
        .map(|value| value != adjusted.post.seats[winner].stack)
        .unwrap_or(true)
        || w.post
            .chip_pool
            .checked_add(rake)
            .map(|value| value != adjusted.post.chip_pool)
            .unwrap_or(true)
    {
        return Err("raked award does not remove the exact rake from the credit".into());
    }
    Ok(())
}

/// The unique live seat other than the action seat of an award terminal.
fn winner_of(w: &CanonicalTransitionWitness) -> Result<usize, String> {
    let seat = usize::from(w.action.seat);
    w.pre
        .seats
        .iter()
        .enumerate()
        .filter(|(_, value)| {
            matches!(
                value.status,
                CanonicalSeatStatus::Active | CanonicalSeatStatus::AllIn
            )
        })
        .map(|(index, _)| index)
        .find(|index| *index != seat)
        .ok_or_else(|| "reveal timeout award has no live survivor".into())
}

fn validate_transition_relation(w: &CanonicalTransitionWitness) -> Result<(), String> {
    let pre = &w.pre;
    let post = &w.post;
    // None of the table actions is a rules, governance, or settlement
    // configuration update.  Keep these domains immutable even while the
    // broader canonical relation is still host-validated.
    if pre.rules_commitment != post.rules_commitment
        || pre.governance_commitment != post.governance_commitment
        || pre.settlement_commitment != post.settlement_commitment
    {
        return Err("transition changed an immutable protocol commitment".into());
    }
    if !matches!(
        w.kind,
        CanonicalTransitionKind::SubmitReconstruct | CanonicalTransitionKind::SubmitShuffle
    ) && w.protocol_completion != CanonicalProtocolCompletionOpening::default()
    {
        return Err("only submit_reconstruct/submit_shuffle may carry a protocol completion opening".into());
    }
    if w.kind != CanonicalTransitionKind::RevealTimeoutRakedAward
        && w.rake_opening != crate::canonical_rake_opening::CanonicalRakeOpening::ZERO
    {
        return Err("only the raked award may carry a rake opening".into());
    }
    let seat = usize::from(w.action.seat);
    let seat_index = (seat < MAX_CANONICAL_SEATS).then_some(seat);
    let before = seat_index
        .map(|index| pre.seats[index])
        .unwrap_or(CanonicalSeat::EMPTY);
    let after = seat_index
        .map(|index| post.seats[index])
        .unwrap_or(CanonicalSeat::EMPTY);
    let bit = seat_index.map_or(0, |index| 1u16 << index);
    if w.kind != CanonicalTransitionKind::AdvanceRound
        && w.round_advance != CanonicalRoundAdvanceOpening::default()
    {
        return Err("only advance_round may carry a board-reveal opening".into());
    }
    match w.kind {
        CanonicalTransitionKind::CreateTable => {
            if pre.phase != CanonicalPhase::Waiting || post.phase != CanonicalPhase::Waiting {
                return Err("create_table must start and end in waiting phase".into());
            }
            if pre.table_id != post.table_id
                || post
                    .seats
                    .iter()
                    .any(|s| s.status != CanonicalSeatStatus::Empty)
            {
                return Err("create_table has an invalid empty-table boundary".into());
            }
            only_allowed_changes(pre, post, None, |expected, actual| {
                expected.call_seq = actual.call_seq;
            })?;
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
            if pre.seats[..seat]
                .iter()
                .any(|seat| seat.status == CanonicalSeatStatus::Empty)
            {
                return Err("join_table must occupy the first empty seat".into());
            }
            if after.stack != w.action.amount
                || after.bet != 0
                || after.total_bet != 0
                || after.pending_addon != 0
                || after.acted
                || post.leave_after_hand_mask & bit != 0
                || post.chip_pool
                    != pre
                        .chip_pool
                        .checked_add(w.action.amount)
                        .ok_or("join chip_pool overflow")?
            {
                return Err("join_table custody transition is invalid".into());
            }
            only_allowed_changes(pre, post, seat_index, |expected, actual| {
                expected.call_seq = actual.call_seq;
                expected.acted_mask = actual.acted_mask;
                expected.leave_after_hand_mask = actual.leave_after_hand_mask;
                expected.custody_commitment = actual.custody_commitment;
                expected.chip_pool = actual.chip_pool;
            })?;
            same_except(pre, post, seat_index, |a, b| {
                a.acted_mask == b.acted_mask && a.leave_after_hand_mask == b.leave_after_hand_mask
            })?;
        }
        CanonicalTransitionKind::LeaveTable => {
            if pre.phase != CanonicalPhase::Waiting
                || !matches!(
                    before.status,
                    CanonicalSeatStatus::Waiting | CanonicalSeatStatus::Out
                )
                || !matches!(
                    after.status,
                    CanonicalSeatStatus::Empty | CanonicalSeatStatus::Out
                )
            {
                return Err("leave_table is only valid for a waiting/out seat".into());
            }
            let refund = before
                .stack
                .checked_add(before.pending_addon)
                .ok_or("leave refund overflow")?;
            if before.status != CanonicalSeatStatus::Waiting
                || after.status != CanonicalSeatStatus::Empty
                || w.action.amount != refund
                || post.chip_pool
                    != pre
                        .chip_pool
                        .checked_sub(refund)
                        .ok_or("leave chip_pool underflow")?
                || after != CanonicalSeat::EMPTY
            {
                return Err("leave_table custody/lifecycle transition is invalid".into());
            }
            only_allowed_changes(pre, post, seat_index, |expected, actual| {
                expected.call_seq = actual.call_seq;
                expected.acted_mask = actual.acted_mask;
                expected.leave_after_hand_mask = actual.leave_after_hand_mask;
                expected.custody_commitment = actual.custody_commitment;
                expected.chip_pool = actual.chip_pool;
            })?;
            same_except(pre, post, seat_index, |_, _| true)?;
        }
        CanonicalTransitionKind::StartHand => {
            if pre.phase != CanonicalPhase::Waiting || post.phase != CanonicalPhase::Shuffling {
                return Err("start_hand must enter shuffling from waiting".into());
            }
            if post.deadline_ms == 0 || post.current_turn != NO_CANONICAL_SEAT {
                return Err("start_hand must arm the shuffle deadline".into());
            }
            // Count post-state participants: waiting-for-big-blind seats that
            // StartHand promotes into the new hand must satisfy the gate too.
            let active_count = post
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
                .count();
            if active_count < 2 {
                return Err("start_hand requires at least two participating seats".into());
            }
            let mut button = None;
            for offset in 1..=usize::from(pre.max_players) {
                let index = (usize::from(pre.button) + offset) % usize::from(pre.max_players);
                if !matches!(
                    pre.seats[index].status,
                    CanonicalSeatStatus::Empty | CanonicalSeatStatus::Out
                ) {
                    button = Some(index as u8);
                    break;
                }
            }
            let participant_mask = active_reveal_mask(&post.seats);
            if post.button != button.unwrap_or(pre.button)
                || post.phase_subtag != 1
                || post.street != 0
                || post.acted_mask != 0
                || post.protocol_pending_mask != participant_mask
            {
                return Err("start_hand header/button initialization is invalid".into());
            }
            only_allowed_changes(pre, post, None, |expected, actual| {
                expected.hand_id = actual.hand_id;
                expected.button = actual.button;
                expected.phase = actual.phase;
                expected.phase_subtag = actual.phase_subtag;
                expected.deadline_ms = actual.deadline_ms;
                expected.call_seq = actual.call_seq;
                expected.protocol_pending_mask = actual.protocol_pending_mask;
                // Waiting-for-big-blind admission: a Waiting seat may be
                // promoted to Active for the new hand; every other seat field
                // stays identical.
                for (expected_seat, actual_seat) in
                    expected.seats.iter_mut().zip(actual.seats.iter())
                {
                    if expected_seat.status == CanonicalSeatStatus::Waiting
                        && actual_seat.status == CanonicalSeatStatus::Active
                    {
                        expected_seat.status = CanonicalSeatStatus::Active;
                    }
                }
            })?;
        }
        CanonicalTransitionKind::AdvanceDeadline => {
            let seat = usize::from(w.action.seat);
            if w.deadline_height == 0 || w.deadline_height < pre.deadline_ms {
                return Err("advance_deadline is before the committed deadline".into());
            }
            if !w.action.flag {
                if pre.phase != CanonicalPhase::Betting
                    || pre.current_turn == NO_CANONICAL_SEAT
                    || seat >= MAX_CANONICAL_SEATS
                    || w.action.seat != pre.current_turn
                    || pre.seats[seat].status != CanonicalSeatStatus::Active
                    || w.action.auxiliary != 1
                {
                    return Err("advance_deadline has an invalid betting extension selector".into());
                }
                let consume =
                    u64::from(pre.seats[seat].time_bank_ms).min(u64::from(pre.betting_timeout_ms));
                if consume == 0
                    || w.action.amount != consume
                    || post.deadline_ms != pre.deadline_ms.saturating_add(consume)
                    || post.seats[seat].time_bank_ms
                        != pre.seats[seat].time_bank_ms - consume as u32
                    || post.acted_mask != pre.acted_mask
                    || post
                        .seats
                        .iter()
                        .zip(pre.seats.iter())
                        .any(|(after, before)| after.acted != before.acted)
                {
                    return Err("advance_deadline has an invalid time-bank extension".into());
                }
                only_allowed_changes(pre, post, Some(seat), |expected, actual| {
                    expected.call_seq = actual.call_seq;
                    expected.deadline_ms = actual.deadline_ms;
                    expected.seats[seat] = actual.seats[seat];
                })?;
            } else {
                // Fixed, non-cascading shuffle-timeout micro-step.  The VM
                // kicks the current shuffler, rebuilds the encrypted deck and
                // arms a fresh shuffle deadline.  Terminal refund/award/reset
                // normalization is intentionally a separate transition.
                if pre.phase != CanonicalPhase::Shuffling
                    || pre.current_turn != NO_CANONICAL_SEAT
                    || w.action.auxiliary != 2
                    || pre.shuffle_timeout_ms == 0
                    || seat >= MAX_CANONICAL_SEATS
                    || pre.protocol_pending_mask != active_reveal_mask(&pre.seats)
                    || pre.protocol_pending_mask & (1u16 << seat) == 0
                    || (pre.protocol_pending_mask & (1u16 << seat)).trailing_zeros() as usize
                        != seat
                    || pre.seats[seat].status != CanonicalSeatStatus::Active
                {
                    return Err("advance_deadline has an invalid shuffle-timeout selector".into());
                }
                let before = pre.seats[seat];
                let refund = before
                    .stack
                    .checked_add(before.pending_addon)
                    .ok_or("shuffle timeout refund overflow")?;
                if w.action.amount != refund
                    || post.seats[seat].status != CanonicalSeatStatus::Out
                    || post.seats[seat].stack != 0
                    || post.seats[seat].pending_addon != 0
                    || post.seats[seat].bet != 0
                    || post.seats[seat].total_bet != before.total_bet
                    || post.seats[seat].time_bank_ms != before.time_bank_ms
                    || post.seats[seat].identity_commitment != before.identity_commitment
                    || post.seats[seat].key_commitment != [0; 32]
                    || post.seats[seat].hole_cards_commitment != [0; 32]
                    || post.pot
                        != pre
                            .pot
                            .checked_add(before.bet)
                            .ok_or("shuffle timeout pot overflow")?
                    || post.chip_pool
                        != pre
                            .chip_pool
                            .checked_sub(refund)
                            .ok_or("shuffle timeout chip_pool underflow")?
                    || post.acted_mask != pre.acted_mask & !(1u16 << seat)
                    || post.leave_after_hand_mask != pre.leave_after_hand_mask & !(1u16 << seat)
                    || post.protocol_pending_mask != active_reveal_mask(&post.seats)
                    || post.protocol_pending_mask.count_ones() < 2
                    || post.phase_subtag == 0
                    || post.current_turn != NO_CANONICAL_SEAT
                    || post.deadline_ms
                        != w.deadline_height
                            .checked_add(u64::from(pre.shuffle_timeout_ms))
                            .ok_or("shuffle timeout deadline overflow")?
                    || post.deck_commitment == [0; 32]
                    || post.deck_commitment == pre.deck_commitment
                    || post.board_cards_commitment != pre.board_cards_commitment
                    || post.reveal_commitment != pre.reveal_commitment
                    || post.reconstruction_commitment != pre.reconstruction_commitment
                    || post.run_it_twice_commitment != pre.run_it_twice_commitment
                {
                    return Err("shuffle timeout transition is invalid".into());
                }
                only_allowed_changes(pre, post, Some(seat), |expected, actual| {
                    expected.call_seq = actual.call_seq;
                    expected.deadline_ms = actual.deadline_ms;
                    expected.acted_mask = actual.acted_mask;
                    expected.leave_after_hand_mask = actual.leave_after_hand_mask;
                    expected.protocol_pending_mask = actual.protocol_pending_mask;
                    expected.pot = actual.pot;
                    expected.chip_pool = actual.chip_pool;
                    expected.deck_commitment = actual.deck_commitment;
                    expected.custody_commitment = actual.custody_commitment;
                })?;
            }
        }
        CanonicalTransitionKind::EndWithoutShowdown => {
            validate_terminal_without_showdown(w)?;
        }
        CanonicalTransitionKind::ResetOnly => {
            validate_reset_only(w)?;
        }
        CanonicalTransitionKind::ReconstructTimeoutReset => {
            validate_reconstruct_timeout_reset(w)?;
        }
        CanonicalTransitionKind::RevealTimeoutReset => {
            validate_reveal_timeout_reset(w)?;
        }
        CanonicalTransitionKind::RevealTimeoutKick => {
            validate_reveal_timeout_kick(w)?;
        }
        CanonicalTransitionKind::RevealTimeoutReconstruct => {
            validate_reveal_timeout_reconstruct(w)?;
        }
        CanonicalTransitionKind::RevealTimeoutAward => {
            validate_reveal_timeout_award(w)?;
        }
        CanonicalTransitionKind::RevealTimeoutRakedAward => {
            validate_reveal_timeout_raked_award(w)?;
        }
        CanonicalTransitionKind::AutoFold => {
            if pre.phase != CanonicalPhase::Betting
                || pre.current_turn != w.action.seat
                || before.status != CanonicalSeatStatus::Active
                || post.phase != CanonicalPhase::Betting
                || post.current_turn == NO_CANONICAL_SEAT
                || post.current_turn == w.action.seat
                || w.deadline_height < pre.deadline_ms
                || w.action.amount != 0
                || w.action.auxiliary != 0
                || w.action.flag
                || post.deadline_ms
                    != w.deadline_height
                        .checked_add(u64::from(pre.betting_timeout_ms))
                        .ok_or("auto-fold deadline overflow")?
                || after.status != CanonicalSeatStatus::Folded
                || !after.acted
                || after.stack != before.stack
                || after.bet != before.bet
                || after.total_bet != before.total_bet
                || after.pending_addon != before.pending_addon
                || after.time_bank_ms != before.time_bank_ms
                || after.identity_commitment != before.identity_commitment
                || after.key_commitment != before.key_commitment
                || after.hole_cards_commitment != before.hole_cards_commitment
            {
                return Err("auto-fold timeout transition is invalid".into());
            }
            if post.phase_subtag != pre.phase_subtag
                || post.street != pre.street
                || post.current_bet != pre.current_bet
                || post.min_raise != pre.min_raise
                || post.pot != pre.pot
                || post.chip_pool != pre.chip_pool
                || post.leave_after_hand_mask != pre.leave_after_hand_mask
                || post.board_cards_commitment != pre.board_cards_commitment
                || post.deck_commitment != pre.deck_commitment
                || post.reveal_commitment != pre.reveal_commitment
                || post.reconstruction_commitment != pre.reconstruction_commitment
                || post.run_it_twice_commitment != pre.run_it_twice_commitment
            {
                return Err("auto-fold changed unrelated betting state".into());
            }
            let successor = (1..=MAX_CANONICAL_SEATS)
                .map(|offset| ((seat + offset) % usize::from(pre.max_players)) as u8)
                .find(|&candidate| {
                    let seat = post.seats[usize::from(candidate)];
                    seat.status == CanonicalSeatStatus::Active && !seat.acted
                })
                .ok_or("auto-fold requires a remaining active successor")?;
            if post.current_turn != successor {
                return Err("auto-fold did not select the first active successor".into());
            }
            for (index, (source, target)) in pre.seats.iter().zip(post.seats.iter()).enumerate() {
                let expected_acted = if index == seat { true } else { source.acted };
                if target.acted != expected_acted
                    || (index != seat
                        && (source.status != target.status
                            || source.stack != target.stack
                            || source.bet != target.bet
                            || source.total_bet != target.total_bet
                            || source.pending_addon != target.pending_addon
                            || source.time_bank_ms != target.time_bank_ms
                            || source.identity_commitment != target.identity_commitment
                            || source.key_commitment != target.key_commitment
                            || source.hole_cards_commitment != target.hole_cards_commitment))
                {
                    return Err("auto-fold changed an unrelated seat image".into());
                }
            }
            only_allowed_changes(pre, post, seat_index, |expected, actual| {
                expected.call_seq = actual.call_seq;
                expected.current_turn = actual.current_turn;
                expected.deadline_ms = actual.deadline_ms;
                expected.acted_mask = actual.acted_mask;
                expected.seats[seat] = actual.seats[seat];
            })?;
        }
        CanonicalTransitionKind::AdvanceRound => {
            // `advance_turn` invokes this VM micro-step only after the final
            // actor has left no further actionable seat.  Keeping this as a
            // distinct fixed-width transition lets the AIR prove the exact
            // all-seat collection relation rather than treating a changed pot
            // or reveal commitment as a host-side side effect.
            if pre.phase != CanonicalPhase::Betting
                || pre.current_turn != NO_CANONICAL_SEAT
                || post.phase != CanonicalPhase::Revealing
                || post.current_turn != NO_CANONICAL_SEAT
                || post.street != pre.street.saturating_add(1)
            {
                return Err("advance_round has an invalid betting/reveal boundary".into());
            }
            if pre.seats.iter().any(|seat| {
                seat.status == CanonicalSeatStatus::Active
                    && (!seat.acted || seat.bet != pre.current_bet)
            }) {
                return Err(
                    "advance_round requires every actionable seat to have matched and acted".into(),
                );
            }
            validate_board_reveal_opening(pre, post, &w.round_advance)?;
            if post.protocol_pending_mask != active_reveal_mask(&post.seats) {
                return Err(
                    "advance_round did not open the canonical reveal participant mask".into(),
                );
            }
            let collected = pre.seats.iter().try_fold(0u64, |sum, seat| {
                sum.checked_add(seat.bet)
                    .ok_or("advance_round seat-bet sum overflow")
            })?;
            if pre.pot.checked_add(collected) != Some(post.pot) {
                return Err("advance_round did not collect every seat bet into the pot".into());
            }
            if post.current_bet != 0 || post.min_raise != 0 {
                return Err("advance_round must clear the completed betting round".into());
            }
            for (before, after) in pre.seats.iter().zip(post.seats.iter()) {
                if before.status != after.status
                    || before.acted != after.acted
                    || before.stack != after.stack
                    || before.total_bet != after.total_bet
                    || before.pending_addon != after.pending_addon
                    || before.time_bank_ms != after.time_bank_ms
                    || before.identity_commitment != after.identity_commitment
                    || before.key_commitment != after.key_commitment
                    || before.hole_cards_commitment != after.hole_cards_commitment
                    || after.bet != 0
                {
                    return Err("advance_round changed a seat outside wager collection".into());
                }
            }
            only_allowed_changes(pre, post, None, |expected, actual| {
                expected.call_seq = actual.call_seq;
                expected.phase = actual.phase;
                expected.phase_subtag = actual.phase_subtag;
                expected.street = actual.street;
                expected.current_turn = actual.current_turn;
                expected.deadline_ms = actual.deadline_ms;
                expected.current_bet = actual.current_bet;
                expected.min_raise = actual.min_raise;
                expected.pot = actual.pot;
                expected.deck_commitment = actual.deck_commitment;
                expected.reveal_commitment = actual.reveal_commitment;
                expected.reconstruction_commitment = actual.reconstruction_commitment;
                expected.run_it_twice_commitment = actual.run_it_twice_commitment;
                expected.custody_commitment = actual.custody_commitment;
                expected.protocol_pending_mask = actual.protocol_pending_mask;
                for seat in &mut expected.seats {
                    seat.bet = 0;
                }
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
            } else if !after.acted
                || match after.stack {
                    0 => after.status != CanonicalSeatStatus::AllIn,
                    _ => after.status != CanonicalSeatStatus::Active,
                }
            {
                return Err(
                    "betting action must mark the selected seat acted and preserve its active/all-in lifecycle"
                        .into(),
                );
            }
            if post.current_turn == w.action.seat {
                return Err("betting action did not advance the turn".into());
            }
            if post.current_turn != expected_betting_successor(post, seat) {
                return Err("betting action did not select the first actionable successor".into());
            }
            if w.kind == CanonicalTransitionKind::Check && before.bet != pre.current_bet {
                return Err("check requires a matched current bet".into());
            }
            match w.kind {
                CanonicalTransitionKind::Fold => {
                    if after.stack != before.stack
                        || after.bet != before.bet
                        || after.total_bet != before.total_bet
                        || after.pending_addon != before.pending_addon
                        || after.time_bank_ms != before.time_bank_ms
                        || after.identity_commitment != before.identity_commitment
                        || after.key_commitment != before.key_commitment
                        || after.hole_cards_commitment != before.hole_cards_commitment
                    {
                        return Err("fold changed selected-seat custody or identity data".into());
                    }
                }
                CanonicalTransitionKind::Check => {
                    if after.status != CanonicalSeatStatus::Active
                        || after.stack != before.stack
                        || after.bet != before.bet
                        || after.total_bet != before.total_bet
                        || after.pending_addon != before.pending_addon
                        || after.time_bank_ms != before.time_bank_ms
                        || after.identity_commitment != before.identity_commitment
                        || after.key_commitment != before.key_commitment
                        || after.hole_cards_commitment != before.hole_cards_commitment
                        || post.current_bet != pre.current_bet
                        || post.min_raise != pre.min_raise
                    {
                        return Err("check changed selected-seat or betting economics".into());
                    }
                }
                CanonicalTransitionKind::Call => {
                    let owed = pre
                        .current_bet
                        .checked_sub(before.bet)
                        .ok_or("call seat bet exceeds current bet")?;
                    let delta = owed.min(before.stack);
                    if delta == 0
                        || w.action.amount != delta
                        || after.stack != before.stack - delta
                        || after.bet != before.bet + delta
                        || after.total_bet != before.total_bet + delta
                        || after.pending_addon != before.pending_addon
                        || after.time_bank_ms != before.time_bank_ms
                        || after.identity_commitment != before.identity_commitment
                        || after.key_commitment != before.key_commitment
                        || after.hole_cards_commitment != before.hole_cards_commitment
                        || after.status
                            != if after.stack == 0 {
                                CanonicalSeatStatus::AllIn
                            } else {
                                CanonicalSeatStatus::Active
                            }
                        || post.current_bet != pre.current_bet
                        || post.min_raise != pre.min_raise
                    {
                        return Err("call amount/custody/lifecycle transition is invalid".into());
                    }
                }
                CanonicalTransitionKind::Raise => {
                    let raise_to = w.action.amount;
                    let needed = raise_to
                        .checked_sub(before.bet)
                        .ok_or("raise target is below the seat bet")?;
                    let increment = raise_to
                        .checked_sub(pre.current_bet)
                        .ok_or("raise target is below the current bet")?;
                    if increment == 0
                        || needed > before.stack
                        || (increment < pre.min_raise && needed != before.stack)
                        || after.stack != before.stack - needed
                        || after.bet != raise_to
                        || after.total_bet != before.total_bet + needed
                        || after.pending_addon != before.pending_addon
                        || after.time_bank_ms != before.time_bank_ms
                        || after.identity_commitment != before.identity_commitment
                        || after.key_commitment != before.key_commitment
                        || after.hole_cards_commitment != before.hole_cards_commitment
                        || after.status
                            != if after.stack == 0 {
                                CanonicalSeatStatus::AllIn
                            } else {
                                CanonicalSeatStatus::Active
                            }
                        || post.current_bet != raise_to
                        || post.min_raise
                            != if increment >= pre.min_raise {
                                increment
                            } else {
                                pre.min_raise
                            }
                    {
                        return Err("raise amount/custody/lifecycle transition is invalid".into());
                    }
                }
                CanonicalTransitionKind::Bet => {
                    if w.action.amount == 0 || pre.current_bet != before.bet {
                        return Err("bet requires a positive unopened-round amount".into());
                    }
                    let raise_to = before
                        .bet
                        .checked_add(w.action.amount)
                        .ok_or("bet target overflows")?;
                    if w.action.amount > before.stack
                        || after.stack != before.stack - w.action.amount
                        || after.bet != raise_to
                        || after.total_bet != before.total_bet + w.action.amount
                        || after.pending_addon != before.pending_addon
                        || after.time_bank_ms != before.time_bank_ms
                        || after.identity_commitment != before.identity_commitment
                        || after.key_commitment != before.key_commitment
                        || after.hole_cards_commitment != before.hole_cards_commitment
                        || after.status
                            != if after.stack == 0 {
                                CanonicalSeatStatus::AllIn
                            } else {
                                CanonicalSeatStatus::Active
                            }
                        || post.current_bet != raise_to
                        || post.min_raise != w.action.amount
                    {
                        return Err("bet amount/custody/lifecycle transition is invalid".into());
                    }
                }
                _ => unreachable!("only betting actions reach the canonical betting branch"),
            }
            // `acted` is the per-seat projection of `acted_mask`.  A normal
            // action changes only its own bit; a full Raise (increment >=
            // pre.min_raise) reopens action by clearing every other actionable
            // (Active) seat, while a sub-minimum all-in keeps their flags —
            // folded/all-in/waiting seats always keep theirs, as the VM does.
            let raise_increment = w.action.amount.saturating_sub(pre.current_bet);
            let raise_reopens =
                w.kind == CanonicalTransitionKind::Raise && raise_increment >= pre.min_raise;
            for index in 0..MAX_CANONICAL_SEATS {
                let expected_acted = if index == seat {
                    true
                } else if raise_reopens && pre.seats[index].status == CanonicalSeatStatus::Active {
                    false
                } else {
                    pre.seats[index].acted
                };
                if post.seats[index].acted != expected_acted {
                    return Err("betting action has an invalid acted-seat projection".into());
                }
            }
            only_allowed_changes(pre, post, Some(seat), |expected, actual| {
                expected.call_seq = actual.call_seq;
                expected.current_turn = actual.current_turn;
                expected.acted_mask = actual.acted_mask;
                expected.current_bet = actual.current_bet;
                expected.min_raise = actual.min_raise;
                expected.pot = actual.pot;
                expected.deadline_ms = actual.deadline_ms;
                expected.custody_commitment = actual.custody_commitment;
                for (index, (expected_seat, actual_seat)) in
                    expected.seats.iter_mut().zip(actual.seats).enumerate()
                {
                    if index != seat {
                        expected_seat.acted = actual_seat.acted;
                    }
                }
            })?;
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
            if pre.chip_pool.checked_add(w.action.amount) != Some(post.chip_pool) {
                return Err(
                    "funding must credit TableVault chip_pool by exactly the action amount".into(),
                );
            }
            if w.kind == CanonicalTransitionKind::Addon {
                if before.pending_addon.checked_add(w.action.amount) != Some(after.pending_addon)
                    || after.stack != before.stack
                {
                    return Err("addon must only increase pending_addon".into());
                }
            } else if before.stack.checked_add(w.action.amount) != Some(after.stack)
                || after.pending_addon != before.pending_addon
            {
                return Err("rebuy must only increase stack".into());
            }
            only_allowed_changes(pre, post, seat_index, |expected, actual| {
                expected.call_seq = actual.call_seq;
                expected.pot = actual.pot;
                expected.chip_pool = actual.chip_pool;
                expected.custody_commitment = actual.custody_commitment;
            })?;
            same_except(pre, post, seat_index, |_, _| true)?;
        }
        CanonicalTransitionKind::SetLeaveAfterHand => {
            if before.status == CanonicalSeatStatus::Empty
                || w.action.amount != 0
                || w.action.auxiliary != 0
                || ((pre.leave_after_hand_mask & bit != 0) == w.action.flag)
                || post.leave_after_hand_mask
                    != if w.action.flag {
                        pre.leave_after_hand_mask | bit
                    } else {
                        pre.leave_after_hand_mask & !bit
                    }
            {
                return Err("leave-after-hand transition is not a single bit flip".into());
            }
            only_allowed_changes(pre, post, None, |expected, actual| {
                expected.call_seq = actual.call_seq;
                expected.leave_after_hand_mask = actual.leave_after_hand_mask;
            })?;
            same_except(pre, post, None, |_, _| true)?;
        }
        CanonicalTransitionKind::ForceFold => {
            if pre.phase != CanonicalPhase::Betting
                || pre.current_turn != w.action.seat
                || before.status != CanonicalSeatStatus::Active
                || after.status != CanonicalSeatStatus::Folded
                || !after.acted
                || after.stack != before.stack
                || after.bet != before.bet
                || after.total_bet != before.total_bet
                || after.pending_addon != before.pending_addon
                || after.time_bank_ms != before.time_bank_ms
                || after.identity_commitment != before.identity_commitment
                || after.key_commitment != before.key_commitment
                || after.hole_cards_commitment != before.hole_cards_commitment
            {
                return Err("force-fold lifecycle transition is invalid".into());
            }
            for (index, source_seat) in pre.seats.iter().enumerate() {
                let bit = 1u16 << index;
                let expected = if index == seat {
                    true
                } else {
                    source_seat.acted
                };
                if post.seats[index].acted != expected
                    || (post.leave_after_hand_mask & bit != 0)
                        != (pre.leave_after_hand_mask & bit != 0)
                {
                    return Err("force-fold mask transition is invalid".into());
                }
            }
            only_allowed_changes(pre, post, seat_index, |expected, actual| {
                expected.call_seq = actual.call_seq;
                expected.acted_mask = actual.acted_mask;
                expected.leave_after_hand_mask = actual.leave_after_hand_mask;
                expected.current_turn = actual.current_turn;
                expected.pot = actual.pot;
                expected.custody_commitment = actual.custody_commitment;
            })?;
            same_except(pre, post, seat_index, |_, _| true)?;
        }
        CanonicalTransitionKind::KickPlayer => {
            let refund = before
                .stack
                .checked_add(before.pending_addon)
                .ok_or("kick refund overflows")?;
            let post_pot = pre.pot.checked_add(before.bet).ok_or("kick pot overflow")?;
            let post_chip_pool = pre
                .chip_pool
                .checked_sub(refund)
                .ok_or("kick chip_pool underflow")?;
            if !matches!(
                before.status,
                CanonicalSeatStatus::Active | CanonicalSeatStatus::Waiting
            ) || after.status != CanonicalSeatStatus::Out
                || w.action.amount != refund
                || post.pot != post_pot
                || post.chip_pool != post_chip_pool
                || after.stack != 0
                || after.pending_addon != 0
                || after.bet != 0
                || after.total_bet != before.total_bet
                || after.time_bank_ms != before.time_bank_ms
                || after.identity_commitment != before.identity_commitment
                || after.key_commitment != [0; 32]
                || after.hole_cards_commitment != [0; 32]
            {
                return Err("kick player custody/lifecycle transition is invalid".into());
            }
            only_allowed_changes(pre, post, seat_index, |expected, actual| {
                expected.call_seq = actual.call_seq;
                expected.acted_mask = actual.acted_mask;
                expected.leave_after_hand_mask = actual.leave_after_hand_mask;
                expected.current_turn = actual.current_turn;
                expected.pot = actual.pot;
                expected.chip_pool = actual.chip_pool;
                expected.custody_commitment = actual.custody_commitment;
            })?;
            same_except(pre, post, seat_index, |_, _| true)?;
        }
        CanonicalTransitionKind::SubmitShuffle
        | CanonicalTransitionKind::SubmitReveal
        | CanonicalTransitionKind::SubmitReconstruct => {
            if w.action.proof_commitment == [0; 32] {
                return Err("crypto transition is missing its proof commitment".into());
            }
            let expected_phase = match w.kind {
                CanonicalTransitionKind::SubmitShuffle => CanonicalPhase::Shuffling,
                CanonicalTransitionKind::SubmitReveal => CanonicalPhase::Revealing,
                CanonicalTransitionKind::SubmitReconstruct => CanonicalPhase::Reconstructing,
                _ => unreachable!("only the three protocol submit tags reach this branch"),
            };
            if pre.phase != expected_phase {
                return Err("crypto transition is outside its protocol phase".into());
            }
            if pre.current_turn != NO_CANONICAL_SEAT || post.current_turn != NO_CANONICAL_SEAT {
                return Err("protocol transition must use the no-seat turn sentinel".into());
            }
            if w.action.amount != 0 || w.action.auxiliary != 0 {
                return Err("protocol transition carries non-zero economic action fields".into());
            }
            if before.status == CanonicalSeatStatus::Empty {
                return Err("crypto transition requires an occupied submitting seat".into());
            }
            let seat_bit = 1u16 << w.action.seat;
            if pre.protocol_pending_mask & seat_bit == 0 {
                return Err("crypto transition seat is not pending".into());
            }
            let remaining = pre.protocol_pending_mask & !seat_bit;
            if remaining == 0 {
                match w.kind {
                    CanonicalTransitionKind::SubmitReconstruct => {
                        validate_reconstruct_completion_opening(
                            pre,
                            post,
                            &w.protocol_completion,
                        )?;
                    }
                    CanonicalTransitionKind::SubmitShuffle => {
                        validate_shuffle_completion_opening(
                            pre,
                            post,
                            &w.protocol_completion,
                        )?;
                    }
                    _ => {
                        return Err(
                            "final reveal submission requires the reveal-completion opening, whose betting-state turn rule is not enabled yet"
                                .into(),
                        );
                    }
                }
                only_allowed_changes(pre, post, None, |expected, actual| {
                    expected.call_seq = actual.call_seq;
                    expected.phase = actual.phase;
                    expected.phase_subtag = actual.phase_subtag;
                    expected.deadline_ms = actual.deadline_ms;
                    expected.protocol_pending_mask = actual.protocol_pending_mask;
                    expected.deck_commitment = actual.deck_commitment;
                    expected.reconstruction_commitment = actual.reconstruction_commitment;
                })?;
                return Ok(());
            }
            if w.protocol_completion != CanonicalProtocolCompletionOpening::default() {
                return Err("non-final reconstruct submission carries a completion opening".into());
            }
            if post.phase != pre.phase
                || post.phase_subtag != pre.phase_subtag
                || post.street != pre.street
                || post.deadline_ms != pre.deadline_ms
                || post.protocol_pending_mask != remaining
            {
                return Err(
                    "non-final protocol submission has an invalid progress transition".into(),
                );
            }
            // The protocol-state commitments are expanded by their dedicated
            // Ristretto AIRs.  Until those relations land, keep the canonical
            // admission closed: each submit family may only replace its own
            // protocol commitment (plus the deck when reconstruction
            // completes), while seats and custody buckets remain immutable.
            only_allowed_changes(pre, post, None, |expected, actual| {
                expected.call_seq = actual.call_seq;
                expected.protocol_pending_mask = actual.protocol_pending_mask;
                match w.kind {
                    CanonicalTransitionKind::SubmitShuffle => {
                        expected.deck_commitment = actual.deck_commitment;
                    }
                    CanonicalTransitionKind::SubmitReveal => {
                        expected.reveal_commitment = actual.reveal_commitment;
                    }
                    CanonicalTransitionKind::SubmitReconstruct => {
                        expected.reconstruction_commitment = actual.reconstruction_commitment;
                    }
                    _ => unreachable!("only the three crypto submit tags reach this branch"),
                }
            })?;
        }
        CanonicalTransitionKind::FoldWithProof => {
            if w.action.proof_commitment == [0; 32] {
                return Err("fold_with_proof is missing its leave DLEQ commitment".into());
            }
            if pre.phase != CanonicalPhase::Betting
                || post.phase != CanonicalPhase::Betting
                || pre.current_turn != w.action.seat
                || before.status != CanonicalSeatStatus::Active
            {
                return Err("fold_with_proof must be an active betting-turn transition".into());
            }
            if post.phase_subtag != pre.phase_subtag || post.street != pre.street {
                return Err("fold_with_proof may not change the betting-round identity".into());
            }
            if after.status != CanonicalSeatStatus::Folded || !after.acted {
                return Err("fold_with_proof must mark the selected seat folded and acted".into());
            }
            if post.current_turn == w.action.seat {
                return Err("fold_with_proof did not advance the betting turn".into());
            }
            if pre.deck_commitment == post.deck_commitment {
                return Err("fold_with_proof must replace the encrypted deck commitment".into());
            }
            if pre.board_cards_commitment != post.board_cards_commitment
                || pre.reveal_commitment != post.reveal_commitment
                || pre.reconstruction_commitment != post.reconstruction_commitment
                || pre.run_it_twice_commitment != post.run_it_twice_commitment
            {
                return Err("fold_with_proof changed an unrelated protocol commitment".into());
            }
            if after.stack != before.stack
                || after.bet != before.bet
                || after.total_bet != before.total_bet
                || after.pending_addon != before.pending_addon
                || after.time_bank_ms != before.time_bank_ms
                || after.identity_commitment != before.identity_commitment
                || after.key_commitment != before.key_commitment
                || after.hole_cards_commitment != before.hole_cards_commitment
            {
                return Err(
                    "fold_with_proof changed selected-seat funds or identity material".into(),
                );
            }
            for index in 0..MAX_CANONICAL_SEATS {
                let expected_acted = if index == seat {
                    true
                } else {
                    pre.seats[index].acted
                };
                if post.seats[index].acted != expected_acted {
                    return Err("fold_with_proof has an invalid acted-seat projection".into());
                }
            }
            // VM terminal settlement/round advancement performs additional
            // collection and normalization.  It remains fail-closed here and
            // must be represented by the dedicated typed micro-steps rather
            // than accepted as an unconstrained side effect of the DLEQ row.
            only_allowed_changes(pre, post, seat_index, |expected, actual| {
                expected.call_seq = actual.call_seq;
                expected.current_turn = actual.current_turn;
                expected.acted_mask = actual.acted_mask;
                expected.deadline_ms = actual.deadline_ms;
                expected.deck_commitment = actual.deck_commitment;
                expected.custody_commitment = actual.custody_commitment;
            })?;
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
    use poker_l1::object_model::ObjectID;
    use poker_l1::vm::contracts::texas_poker::constants::ROUND_FLOP;
    use poker_l1::vm::contracts::texas_poker::state_machine;
    use poker_l1::vm::contracts::texas_poker::types::{
        ReconstructState, RevealAssignment, RevealPurpose, RevealTarget, RevealTokenState, Seat,
        SeatStatus, TexasPokerTable,
    };
    use poker_l1::vm::contracts::texas_poker::utils::{g1_generator, scalar_from_u64};
    use poker_protocol::crypto::types::ECPoint;

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
            shuffle_timeout_ms: 10_000,
            reveal_timeout_ms: 10_000,
            betting_timeout_ms: 30_000,
            reconstruct_timeout_ms: 10_000,
            showdown_display_ms: 3_000,
            current_bet: 0,
            min_raise: 0,
            chip_pool: 0,
            pot: 0,
            button: 0,
            max_players: 2,
            acted_mask: 0,
            leave_after_hand_mask: 0,
            protocol_pending_mask: 0,
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

        let mut value = image();
        value.protocol_pending_mask = 1;
        assert!(value.validate().is_err());

        let mut value = image();
        value.phase = CanonicalPhase::Shuffling;
        value.phase_subtag = 1;
        value.deadline_ms = u64::from(value.shuffle_timeout_ms);
        assert!(value.validate().is_err());
        value.protocol_pending_mask = 1;
        value.chip_pool = 1;
        value.seats[0] = CanonicalSeat {
            status: CanonicalSeatStatus::Active,
            acted: false,
            stack: 1,
            bet: 0,
            total_bet: 0,
            pending_addon: 0,
            time_bank_ms: 0,
            identity_commitment: [21; 32],
            key_commitment: [22; 32],
            hole_cards_commitment: [0; 32],
        };
        assert!(value.validate().is_ok());
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
                proof_commitment: [0; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            protocol_completion: CanonicalProtocolCompletionOpening::default(),
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.transition_commitment = witness.content_commitment();
        witness.nullifier = transition_nullifier(&witness);
        assert!(witness.validate_shape().is_ok());
        assert_ne!(witness.commitment(), [0; 32]);
    }

    #[test]
    fn canonical_all_in_action_requires_all_in_lifecycle() {
        let mut pre = image();
        pre.phase = CanonicalPhase::Betting;
        pre.phase_subtag = 1;
        pre.street = 1;
        pre.deadline_ms = 10;
        pre.current_turn = 0;
        pre.current_bet = 100;
        pre.min_raise = 100;
        pre.chip_pool = 50;
        pre.seats[0] = CanonicalSeat {
            status: CanonicalSeatStatus::Active,
            acted: false,
            stack: 50,
            bet: 0,
            total_bet: 0,
            pending_addon: 0,
            time_bank_ms: 0,
            identity_commitment: [21; 32],
            key_commitment: [22; 32],
            hole_cards_commitment: [23; 32],
        };
        let mut post = pre.clone();
        post.call_seq = 1;
        post.current_turn = NO_CANONICAL_SEAT;
        post.acted_mask = 1;
        post.seats[0].status = CanonicalSeatStatus::AllIn;
        post.seats[0].acted = true;
        post.seats[0].stack = 0;
        post.seats[0].bet = 50;
        post.seats[0].total_bet = 50;
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::Call,
            actor: [31; 32],
            action: CanonicalActionPayload {
                seat: 0,
                amount: 50,
                auxiliary: 0,
                flag: false,
                proof_commitment: [0; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            protocol_completion: CanonicalProtocolCompletionOpening::default(),
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        assert!(witness.validate_shape().is_ok());

        witness.post.seats[0].status = CanonicalSeatStatus::Active;
        witness.seal();
        assert!(witness.validate_shape().is_err());

        let mut identity_drift = witness;
        identity_drift.post.seats[0].status = CanonicalSeatStatus::AllIn;
        identity_drift.post.seats[0].identity_commitment[0] ^= 1;
        identity_drift.seal();
        assert!(identity_drift.validate_shape().is_err());
    }

    fn reconstruct_completion() -> CanonicalTransitionWitness {
        let mut pre = image();
        pre.phase = CanonicalPhase::Reconstructing;
        pre.phase_subtag = CANONICAL_RECONSTRUCT_COLLECTING_SUBTAG;
        pre.street = 2;
        pre.deadline_ms = 5_000;
        pre.chip_pool = 200;
        pre.protocol_pending_mask = 0b01;
        for (index, seat) in pre.seats[..2].iter_mut().enumerate() {
            *seat = CanonicalSeat {
                status: CanonicalSeatStatus::Active,
                acted: false,
                stack: 100,
                bet: 0,
                total_bet: 0,
                pending_addon: 0,
                time_bank_ms: 0,
                identity_commitment: [20 + index as u8; 32],
                key_commitment: [30 + index as u8; 32],
                hole_cards_commitment: [40 + index as u8; 32],
            };
        }
        let timestamp = 8_000;
        let mut post = pre.clone();
        post.call_seq = 1;
        post.phase = CanonicalPhase::Shuffling;
        post.phase_subtag = CANONICAL_SHUFFLE_RECONSTRUCT_SUBTAG;
        post.deadline_ms = timestamp + u64::from(pre.shuffle_timeout_ms);
        post.protocol_pending_mask = 0b11;
        post.deck_commitment = [50; 32];
        post.reconstruction_commitment = [51; 32];
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::SubmitReconstruct,
            actor: [60; 32],
            action: CanonicalActionPayload {
                seat: 0,
                amount: 0,
                auxiliary: 0,
                // Completion is derived from the pre pending mask.  The
                // legacy action bit is therefore canonical zero.
                flag: false,
                proof_commitment: [61; 32],
            },
            round_advance: CanonicalRoundAdvanceOpening::default(),
            protocol_completion: CanonicalProtocolCompletionOpening {
                kind: CanonicalProtocolCompletionKind::Reconstruct,
                completion_timestamp_ms: timestamp,
                pre_cards_dealt: 7,
                post_cards_dealt: 0,
                suspended_reveal_commitment: [3; 32],
                post_shuffle_pending_mask: 0b11,
                post_shuffle_completed_mask: 0,
                pre_deck_commitment: [2; 32],
                post_deck_commitment: [50; 32],
                pre_reconstruction_commitment: [4; 32],
                post_reconstruction_commitment: [51; 32],
            },
            rake_opening: crate::canonical_rake_opening::CanonicalRakeOpening::ZERO,
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 0,
        };
        witness.seal();
        witness
    }

    #[test]
    fn final_reconstruct_completion_matches_vm_normalization() {
        let witness = reconstruct_completion();
        assert!(witness.validate_shape().is_ok());

        let mut flag_is_not_completion_authority = witness.clone();
        flag_is_not_completion_authority.action.flag = true;
        flag_is_not_completion_authority.seal();
        assert!(flag_is_not_completion_authority.validate_shape().is_err());

        let mut non_final = witness.clone();
        non_final.pre.protocol_pending_mask = 0b11;
        non_final.seal();
        assert!(non_final.validate_shape().is_err());

        let mut wrong_deadline = witness.clone();
        wrong_deadline.protocol_completion.completion_timestamp_ms += 1;
        wrong_deadline.seal();
        assert!(wrong_deadline.validate_shape().is_err());

        let mut completed_mask = witness.clone();
        completed_mask
            .protocol_completion
            .post_shuffle_completed_mask = 1;
        completed_mask.seal();
        assert!(completed_mask.validate_shape().is_err());

        let mut detached_reveal = witness;
        detached_reveal
            .protocol_completion
            .suspended_reveal_commitment[0] ^= 1;
        detached_reveal.seal();
        assert!(detached_reveal.validate_shape().is_err());
    }

    #[test]
    fn non_final_reconstruct_preserves_the_encrypted_deck_commitment() {
        let mut witness = reconstruct_completion();
        witness.pre.protocol_pending_mask = 0b11;
        witness.post = witness.pre.clone();
        witness.post.call_seq = witness.pre.call_seq + 1;
        witness.post.protocol_pending_mask = 0b10;
        witness.post.reconstruction_commitment = [51; 32];
        witness.protocol_completion = CanonicalProtocolCompletionOpening::default();
        witness.seal();
        assert!(witness.validate_shape().is_ok());

        witness.post.deck_commitment[0] ^= 1;
        witness.seal();
        assert!(witness.validate_shape().is_err());
    }

    #[test]
    fn vm_reconstruct_timeout_narrow_population_resets_before_accumulator_branch() {
        let mut table = TexasPokerTable::new(
            ObjectID::new([0xA5; 20], 0),
            "narrow-reconstruct-timeout".into(),
            [0; 20],
            2,
            50,
            100,
        );
        let generator = g1_generator();
        table.seats[0] = Seat::occupied(
            [1; 20],
            100,
            ECPoint(generator * scalar_from_u64(1)),
            SeatStatus::Active,
        )
        .expect("active timed-out fixture seat");
        table.seats[1] = Seat::occupied(
            [2; 20],
            200,
            ECPoint(generator * scalar_from_u64(2)),
            SeatStatus::Active,
        )
        .expect("active retained fixture seat");
        table.seats[1].set_status(SeatStatus::Folded);
        table.chip_pool = 300;
        state_machine::set_initial_encrypted_deck(&mut table).expect("fixture deck");
        table.deck_state.contributor_mask = 0b11;
        table
            .enter_reconstructing(
                ROUND_FLOP,
                ReconstructState {
                    pending_mask: 0b01,
                    accumulated_deck: None,
                },
                RevealTokenState {
                    purpose: RevealPurpose::Board,
                    assignments: vec![],
                },
                1_000,
            )
            .expect("fixture reconstruction phase");

        let mut events = Vec::new();
        state_machine::advance_deadline(&mut table, 11_000, &mut events)
            .expect("expired reconstruct deadline");

        // Kicking seat 0 leaves zero active players, so the internal kick
        // cascade resets first. The outer handler subsequently sees only one
        // retained seat and resets again without ever observing the
        // reconstruction accumulator.
        assert_eq!(table.round_state(), 0);
        assert!(!table.seats[0].is_occupied());
        assert_eq!(table.seats[1].status(), SeatStatus::Active);
        assert_eq!(table.seats[1].stack(), 200);
        assert_eq!(table.chip_pool, 200);
        assert_eq!(table.reconstruct_phase(), 0);
    }

    #[test]
    fn vm_reveal_timeout_uses_assignment_union_before_preflop_reset() {
        let mut table = TexasPokerTable::new(
            ObjectID::new([0xA6; 20], 0),
            "narrow-reveal-timeout".into(),
            [0; 20],
            2,
            50,
            100,
        );
        let generator = g1_generator();
        table.seats[0] = Seat::occupied(
            [1; 20],
            100,
            ECPoint(generator * scalar_from_u64(1)),
            SeatStatus::Active,
        )
        .expect("active timed-out reveal fixture seat");
        table.seats[1] = Seat::occupied(
            [2; 20],
            200,
            ECPoint(generator * scalar_from_u64(2)),
            SeatStatus::Active,
        )
        .expect("active retained reveal fixture seat");
        table.chip_pool = 300;
        state_machine::set_initial_encrypted_deck(&mut table).expect("fixture deck");
        table.deck_state.contributor_mask = 0b11;
        table
            .enter_revealing(
                poker_l1::vm::contracts::texas_poker::constants::ROUND_PREFLOP,
                RevealTokenState {
                    purpose: RevealPurpose::DealHole,
                    assignments: vec![
                        RevealAssignment {
                            encrypted_card_index: 0,
                            target: RevealTarget::Hole {
                                seat_index: 1,
                                card_slot: 0,
                            },
                            pending_mask: 0b01,
                            submitted_mask: 0,
                            reveal_tokens: vec![],
                        },
                        RevealAssignment {
                            encrypted_card_index: 1,
                            target: RevealTarget::Hole {
                                seat_index: 1,
                                card_slot: 1,
                            },
                            pending_mask: 0b01,
                            submitted_mask: 0,
                            reveal_tokens: vec![],
                        },
                    ],
                },
                1_000,
            )
            .expect("fixture reveal phase");

        let mut events = Vec::new();
        state_machine::advance_deadline(&mut table, 11_000, &mut events)
            .expect("expired reveal deadline");

        assert_eq!(table.round_state(), 0);
        assert!(!table.seats[0].is_occupied());
        assert_eq!(table.seats[1].status(), SeatStatus::Active);
        assert_eq!(table.seats[1].stack(), 200);
        assert_eq!(table.chip_pool, 200);
        assert_eq!(table.reveal_phase(), 0);
    }
}
