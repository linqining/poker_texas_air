//! Deterministic Texas Hold'em settlement planning.
//!
//! Settlement is deliberately split into two phases:
//!
//! 1. [`derive_settlement_plan`] is a pure function over an authenticated table snapshot and
//!    canonical runout boards.
//! 2. The state machine validates and applies the returned plan without re-running hand ranking,
//!    side-pot construction, rake allocation, or odd-chip selection while mutating balances.
//!
//! The normalized plan is bounded by the protocol constants (9 seats, 9 pots, 2 runouts), has a
//! canonical Borsh encoding, and can therefore be committed by the host verifier and projected
//! into AIR columns without depending on event ordering or dynamic winner lists.

use std::collections::HashSet;

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};

use super::card::Card;
use super::constants::{MAX_PLAYERS, MAX_TOTAL_BET, RAKE_MODE_NONE, RAKE_MODE_PERCENTAGE};
use super::hand_evaluator::{HandRank, evaluate_best};
use super::side_pot::{self, SidePot};
use super::types::{RitStartStreet, Seat, TexasPokerTable};
use crate::error::{PokerL1Error, PokerL1Result};

/// Canonical settlement-plan encoding version.
pub const SETTLEMENT_PLAN_VERSION: u8 = 2;
/// Maximum number of independent boards supported by the protocol.
pub const MAX_RUNOUTS: usize = 2;
/// Fixed number of award/rank slots in every plan.
pub const SETTLEMENT_SEATS: usize = MAX_PLAYERS as usize;

/// Canonical board input used while deriving a settlement plan.
///
/// With two runouts, `shared_board_len` cards at the beginning of both boards must be identical.
/// Cards after that prefix must be distinct across both runouts.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize)]
pub enum SettlementBoards {
    /// One complete five-card board.
    Single {
        /// Canonical board.
        board: Vec<Card>,
    },
    /// Two complete boards with one shared prefix.
    Twice {
        /// Street at which the two-runout schedule started.
        start: RitStartStreet,
        /// First canonical board.
        board1: Vec<Card>,
        /// Second canonical board.
        board2: Vec<Card>,
    },
}

impl BorshDeserialize for SettlementBoards {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let variant = u8::deserialize_reader(reader)?;
        let boards = match variant {
            0 => Self::Single {
                board: Vec::<Card>::deserialize_reader(reader)?,
            },
            1 => Self::Twice {
                start: RitStartStreet::deserialize_reader(reader)?,
                board1: Vec::<Card>::deserialize_reader(reader)?,
                board2: Vec::<Card>::deserialize_reader(reader)?,
            },
            _ => {
                return Err(borsh::io::Error::new(
                    borsh::io::ErrorKind::InvalidData,
                    "invalid settlement boards variant",
                ));
            }
        };
        boards.validate().map_err(|error| {
            borsh::io::Error::new(borsh::io::ErrorKind::InvalidData, error.to_string())
        })?;
        Ok(boards)
    }
}

impl SettlementBoards {
    /// Construct the normal single-board settlement input.
    #[must_use]
    pub fn single(board: Vec<Card>) -> Self {
        Self::Single { board }
    }

    /// Construct a two-runout settlement input.
    #[must_use]
    pub fn twice(start: RitStartStreet, board1: Vec<Card>, board2: Vec<Card>) -> Self {
        Self::Twice {
            start,
            board1,
            board2,
        }
    }

    #[must_use]
    const fn runout_count(&self) -> u8 {
        match self {
            Self::Single { .. } => 1,
            Self::Twice { .. } => 2,
        }
    }

    #[must_use]
    const fn shared_board_len(&self) -> u8 {
        match self {
            Self::Single { .. } => 0,
            Self::Twice { start, .. } => start.shared_board_len(),
        }
    }

    #[must_use]
    const fn schedule(&self) -> SettlementRunoutSchedule {
        match self {
            Self::Single { .. } => SettlementRunoutSchedule::Single,
            Self::Twice { start, .. } => SettlementRunoutSchedule::Twice { start: *start },
        }
    }

    fn board1(&self) -> &[Card] {
        match self {
            Self::Single { board } => board,
            Self::Twice { board1, .. } => board1,
        }
    }

    fn board2(&self) -> &[Card] {
        match self {
            Self::Single { .. } => &[],
            Self::Twice { board2, .. } => board2,
        }
    }

    fn board(&self, runout_index: usize) -> &[Card] {
        if runout_index == 0 {
            self.board1()
        } else {
            self.board2()
        }
    }

    fn validate(&self) -> PokerL1Result<()> {
        if self.board1().len() != 5 {
            return Err(PokerL1Error::Serialization(format!(
                "settlement: board 1 must contain exactly 5 cards, got {}",
                self.board1().len()
            )));
        }
        if let Self::Twice {
            start,
            board1,
            board2,
        } = self
        {
            if board2.len() != 5 {
                return Err(PokerL1Error::Serialization(format!(
                    "settlement: board 2 must contain exactly 5 cards, got {}",
                    board2.len()
                )));
            }
            let shared = usize::from(start.shared_board_len());
            if board1[..shared] != board2[..shared] {
                return Err(PokerL1Error::Serialization(
                    "settlement: runout boards disagree on their shared prefix".into(),
                ));
            }
        }
        if self
            .board1()
            .iter()
            .chain(self.board2())
            .any(|card| !card.is_valid())
        {
            return Err(PokerL1Error::Serialization(
                "settlement: runout contains an invalid card".into(),
            ));
        }

        let mut seen = HashSet::new();
        for card in self.board1() {
            if !seen.insert(card.to_index()) {
                return Err(PokerL1Error::Serialization(
                    "settlement: duplicate card within board 1".into(),
                ));
            }
        }
        if let Self::Twice { start, board2, .. } = self {
            let shared = usize::from(start.shared_board_len());
            for card in board2.iter().skip(shared) {
                if !seen.insert(card.to_index()) {
                    return Err(PokerL1Error::Serialization(
                        "settlement: duplicate non-shared card across runouts".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Canonical number and shared-prefix shape of a settlement's runouts.
///
/// The enum makes invalid pairs such as `(runout_count=1, shared_board_len=3)` and non-street
/// prefixes such as `2` unrepresentable in the normalized plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum SettlementRunoutSchedule {
    /// One normal board with no duplicated runout suffix.
    Single,
    /// Two boards that diverge at a canonical Hold'em street boundary.
    Twice {
        /// Street at which both boards begin receiving independent cards.
        start: RitStartStreet,
    },
}

impl SettlementRunoutSchedule {
    /// Number of active boards.
    #[must_use]
    pub const fn count(self) -> u8 {
        match self {
            Self::Single => 1,
            Self::Twice { .. } => 2,
        }
    }

    /// Number of first-board cards shared by both runouts.
    #[must_use]
    pub const fn shared_board_len(self) -> u8 {
        match self {
            Self::Single => 0,
            Self::Twice { start } => start.shared_board_len(),
        }
    }
}

/// Settlement details for one pot on one runout.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize)]
pub struct RunoutPotPlan {
    /// Amount of this pot assigned to the runout.
    pub amount: u64,
    /// Winning seats for this runout/pot.
    pub winner_mask: u16,
    /// Canonical best rank for every seat (`None` when ineligible).
    pub ranks: [Option<HandRank>; SETTLEMENT_SEATS],
    /// Award paid to every seat from this runout/pot.
    pub awards: [u64; SETTLEMENT_SEATS],
}

impl RunoutPotPlan {
    fn inactive() -> Self {
        Self {
            amount: 0,
            winner_mask: 0,
            ranks: [None; SETTLEMENT_SEATS],
            awards: [0; SETTLEMENT_SEATS],
        }
    }

    /// Whether this fixed runout slot participates in settlement.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.winner_mask != 0
    }
}

impl BorshDeserialize for RunoutPotPlan {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let amount = u64::deserialize_reader(reader)?;
        let winner_mask = u16::deserialize_reader(reader)?;
        let ranks = <[Option<HandRank>; SETTLEMENT_SEATS]>::deserialize_reader(reader)?;
        let awards = <[u64; SETTLEMENT_SEATS]>::deserialize_reader(reader)?;
        let derived_active = winner_mask != 0;
        if !derived_active
            && (amount != 0 || ranks.iter().any(Option::is_some) || awards.iter().any(|v| *v != 0))
        {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "inactive settlement runout carries non-zero payload",
            ));
        }
        Ok(Self {
            amount,
            winner_mask,
            ranks,
            awards,
        })
    }
}

/// Canonical settlement details for one main/side-pot layer.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize)]
pub struct SettlementPotPlan {
    /// Stable layer index (`0` is the main pot).
    pub pot_index: u8,
    /// Amount before rake.
    pub gross_amount: u64,
    /// Rake allocated to this layer.
    pub rake: u64,
    /// Amount after rake and before runout splitting.
    pub net_amount: u64,
    /// Seats eligible to win this layer.
    pub eligible_mask: u16,
    /// Fixed two-slot runout projection.
    pub runouts: [RunoutPotPlan; MAX_RUNOUTS],
}

impl SettlementPotPlan {
    /// Whether at least two seats are eligible to contest this layer.
    ///
    /// A one-seat outer layer is an uncalled return. It is never raked and is paid directly to
    /// that seat without depending on either runout board. This bit is derived from the sole
    /// canonical eligibility set and is not stored as a second runtime fact.
    #[must_use]
    pub const fn is_contested(&self) -> bool {
        self.eligible_mask.count_ones() >= 2
    }
}

impl BorshDeserialize for SettlementPotPlan {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let pot_index = u8::deserialize_reader(reader)?;
        let gross_amount = u64::deserialize_reader(reader)?;
        let rake = u64::deserialize_reader(reader)?;
        let net_amount = u64::deserialize_reader(reader)?;
        let eligible_mask = u16::deserialize_reader(reader)?;
        let runouts = <[RunoutPotPlan; MAX_RUNOUTS]>::deserialize_reader(reader)?;
        if eligible_mask == 0 {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "settlement pot has no eligible seats",
            ));
        }
        Ok(Self {
            pot_index,
            gross_amount,
            rake,
            net_amount,
            eligible_mask,
            runouts,
        })
    }
}

/// Fully normalized settlement output.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SettlementPlan {
    /// Encoding/domain version.
    pub version: u8,
    /// Typed single/twice schedule and canonical shared-prefix boundary.
    pub schedule: SettlementRunoutSchedule,
    /// Sum of all wager contributions before rake.
    pub gross_pot: u64,
    /// Total rake removed from table custody.
    pub rake: u64,
    /// Total paid to players.
    pub total_awards: u64,
    /// Winner union across every pot and runout.
    pub winner_mask: u16,
    /// Aggregate award paid to each seat.
    pub awards: [u64; SETTLEMENT_SEATS],
    /// Ordered main/side-pot layers (bounded by `MAX_PLAYERS`).
    pub pots: Vec<SettlementPotPlan>,
}

impl SettlementPlan {
    /// Domain-separated digest of the canonical plan encoding.
    pub fn digest(&self) -> PokerL1Result<[u8; 32]> {
        let encoded = borsh::to_vec(self).map_err(|error| {
            PokerL1Error::Serialization(format!("settlement plan borsh: {error}"))
        })?;
        let mut hasher = Blake2bVar::new(32).expect("32 <= Blake2b maximum output");
        hasher.update(b"zchain.texas_poker.settlement_plan.v2");
        hasher.update(&encoded);
        let mut digest = [0u8; 32];
        hasher
            .finalize_variable(&mut digest)
            .expect("32 <= Blake2b maximum output");
        Ok(digest)
    }

    /// Recheck all internal conservation and shape invariants without recomputing poker logic.
    pub fn validate(&self, seat_count: usize) -> PokerL1Result<()> {
        if self.version != SETTLEMENT_PLAN_VERSION {
            return Err(PokerL1Error::Serialization(format!(
                "settlement: unsupported plan version {}",
                self.version
            )));
        }
        if seat_count > SETTLEMENT_SEATS || self.pots.len() > SETTLEMENT_SEATS {
            return Err(PokerL1Error::Serialization(
                "settlement: plan exceeds fixed seat/pot bounds".into(),
            ));
        }
        if self
            .gross_pot
            .checked_sub(self.rake)
            .filter(|net| *net == self.total_awards)
            .is_none()
        {
            return Err(PokerL1Error::Serialization(
                "settlement: gross_pot != rake + total_awards".into(),
            ));
        }

        let mut gross = 0u64;
        let mut rake = 0u64;
        let mut awards = [0u64; SETTLEMENT_SEATS];
        let mut winner_mask = 0u16;
        for (index, pot) in self.pots.iter().enumerate() {
            if usize::from(pot.pot_index) != index {
                return Err(PokerL1Error::Serialization(
                    "settlement: non-canonical pot index".into(),
                ));
            }
            if pot.gross_amount.checked_sub(pot.rake) != Some(pot.net_amount) {
                return Err(PokerL1Error::Serialization(
                    "settlement: pot gross/rake/net mismatch".into(),
                ));
            }
            let eligible_count = pot.eligible_mask.count_ones();
            if eligible_count == 0 {
                return Err(PokerL1Error::Serialization(
                    "settlement: pot has no eligible seats".into(),
                ));
            }
            let contested = pot.is_contested();
            if !contested && pot.rake != 0 {
                return Err(PokerL1Error::Serialization(
                    "settlement: uncontested pot must not be raked".into(),
                ));
            }
            gross = gross.checked_add(pot.gross_amount).ok_or_else(|| {
                PokerL1Error::Serialization("settlement: gross pot sum overflow".into())
            })?;
            rake = rake.checked_add(pot.rake).ok_or_else(|| {
                PokerL1Error::Serialization("settlement: rake sum overflow".into())
            })?;
            let mut runout_total = 0u64;
            let active_runouts = if contested {
                usize::from(self.schedule.count())
            } else {
                1
            };
            for (runout_index, runout) in pot.runouts.iter().enumerate() {
                if runout_index >= active_runouts {
                    if runout != &RunoutPotPlan::inactive() {
                        return Err(PokerL1Error::Serialization(
                            "settlement: inactive runout slot is non-zero".into(),
                        ));
                    }
                    continue;
                }
                if !runout.is_active() {
                    return Err(PokerL1Error::Serialization(
                        "settlement: active runout has no winners".into(),
                    ));
                }
                if runout.winner_mask & !pot.eligible_mask != 0 {
                    return Err(PokerL1Error::Serialization(
                        "settlement: runout winner is not eligible for the pot".into(),
                    ));
                }
                if !contested
                    && (runout.winner_mask != pot.eligible_mask
                        || runout.amount != pot.net_amount
                        || runout.ranks.iter().any(Option::is_some))
                {
                    return Err(PokerL1Error::Serialization(
                        "settlement: uncontested pot projection is non-canonical".into(),
                    ));
                }
                let runout_awards = runout.awards.iter().try_fold(0u64, |sum, amount| {
                    sum.checked_add(*amount).ok_or_else(|| {
                        PokerL1Error::Serialization("settlement: runout award overflow".into())
                    })
                })?;
                if runout_awards != runout.amount {
                    return Err(PokerL1Error::Serialization(
                        "settlement: runout amount != awards".into(),
                    ));
                }
                runout_total = runout_total.checked_add(runout.amount).ok_or_else(|| {
                    PokerL1Error::Serialization("settlement: runout total overflow".into())
                })?;
                winner_mask |= runout.winner_mask;
                for (seat, amount) in runout.awards.iter().enumerate() {
                    awards[seat] = awards[seat].checked_add(*amount).ok_or_else(|| {
                        PokerL1Error::Serialization("settlement: seat award overflow".into())
                    })?;
                }
            }
            if runout_total != pot.net_amount {
                return Err(PokerL1Error::Serialization(
                    "settlement: runout split does not equal pot net amount".into(),
                ));
            }
        }
        if gross != self.gross_pot
            || rake != self.rake
            || awards != self.awards
            || winner_mask != self.winner_mask
        {
            return Err(PokerL1Error::Serialization(
                "settlement: aggregate projection mismatch".into(),
            ));
        }
        Ok(())
    }
}

/// Derive the normal one-board settlement plan from the table's community cards.
pub fn derive_settlement_plan(table: &TexasPokerTable) -> PokerL1Result<SettlementPlan> {
    derive_settlement_plan_for_boards(
        table,
        &SettlementBoards::single(table.community_cards.to_vec()),
    )
}

/// Derive a deterministic settlement plan for one or two canonical boards.
pub fn derive_settlement_plan_for_boards(
    table: &TexasPokerTable,
    boards: &SettlementBoards,
) -> PokerL1Result<SettlementPlan> {
    boards.validate()?;
    if table.seats.len() > SETTLEMENT_SEATS {
        return Err(PokerL1Error::Serialization(
            "settlement: table exceeds MAX_PLAYERS".into(),
        ));
    }
    validate_exposed_cards(table, boards)?;

    let bets: Vec<u64> = table.seats.iter().map(Seat::total_bet).collect();
    let folded: Vec<bool> = table
        .seats
        .iter()
        .map(|seat| seat.is_folded() || seat.has_left_hand())
        .collect();
    let all_in: Vec<bool> = table.seats.iter().map(Seat::is_all_in).collect();
    let result = side_pot::calculate_side_pots(&bets, &folded, &all_in).map_err(|error| {
        PokerL1Error::Serialization(format!("settlement: side-pot calculation failed: {error}"))
    })?;
    if result.pots.len() > SETTLEMENT_SEATS {
        return Err(PokerL1Error::Serialization(
            "settlement: side-pot count exceeds MAX_PLAYERS".into(),
        ));
    }
    let gross_pot = result.total();
    if gross_pot > MAX_TOTAL_BET || gross_pot != table.pot {
        return Err(PokerL1Error::Serialization(format!(
            "settlement: contribution total {gross_pot} does not match table pot {}",
            table.pot
        )));
    }
    let contested_gross = result.pots.iter().try_fold(0u64, |sum, pot| {
        if pot.eligible_seats.count_ones() >= 2 {
            sum.checked_add(pot.amount).ok_or_else(|| {
                PokerL1Error::Serialization("settlement: contested pot sum overflow".into())
            })
        } else {
            Ok(sum)
        }
    })?;
    let rake = compute_rake(table, contested_gross)?;
    let pot_rakes = allocate_rake(&result.pots, rake, contested_gross)?;

    let mut plan = SettlementPlan {
        version: SETTLEMENT_PLAN_VERSION,
        schedule: boards.schedule(),
        gross_pot,
        rake,
        total_awards: 0,
        winner_mask: 0,
        awards: [0; SETTLEMENT_SEATS],
        pots: Vec::with_capacity(result.pots.len()),
    };

    for (pot_index, side_pot) in result.pots.iter().enumerate() {
        if side_pot.amount == 0 || side_pot.eligible_seats == 0 {
            return Err(PokerL1Error::Serialization(format!(
                "settlement: pot {pot_index} has zero amount or no eligible player"
            )));
        }
        let pot_rake = pot_rakes[pot_index];
        let net_amount = side_pot.amount.checked_sub(pot_rake).ok_or_else(|| {
            PokerL1Error::Serialization("settlement: pot rake exceeds gross amount".into())
        })?;
        let contested = side_pot.eligible_seats.count_ones() >= 2;
        let mut runouts = [RunoutPotPlan::inactive(), RunoutPotPlan::inactive()];
        if contested {
            let runout_amounts = split_across_runouts(net_amount, boards.runout_count());
            for runout_index in 0..usize::from(boards.runout_count()) {
                let (winner_mask, ranks) =
                    find_winners(table, side_pot.eligible_seats, boards.board(runout_index))?;
                let awards = split_among_winners(
                    runout_amounts[runout_index],
                    winner_mask,
                    table.button,
                    table.seats.len(),
                )?;
                runouts[runout_index] = RunoutPotPlan {
                    amount: runout_amounts[runout_index],
                    winner_mask,
                    ranks,
                    awards,
                };
                plan.winner_mask |= winner_mask;
                for (seat, amount) in awards.iter().enumerate() {
                    plan.awards[seat] =
                        plan.awards[seat].checked_add(*amount).ok_or_else(|| {
                            PokerL1Error::Serialization(
                                "settlement: aggregate award overflow".into(),
                            )
                        })?;
                }
            }
        } else {
            let winner_mask = side_pot.eligible_seats;
            let awards =
                split_among_winners(net_amount, winner_mask, table.button, table.seats.len())?;
            runouts[0] = RunoutPotPlan {
                amount: net_amount,
                winner_mask,
                ranks: [None; SETTLEMENT_SEATS],
                awards,
            };
            plan.winner_mask |= winner_mask;
            for (seat, amount) in awards.iter().enumerate() {
                plan.awards[seat] = plan.awards[seat].checked_add(*amount).ok_or_else(|| {
                    PokerL1Error::Serialization("settlement: aggregate award overflow".into())
                })?;
            }
        }
        plan.pots.push(SettlementPotPlan {
            pot_index: u8::try_from(pot_index).map_err(|_| {
                PokerL1Error::Serialization("settlement: pot index exceeds u8".into())
            })?,
            gross_amount: side_pot.amount,
            rake: pot_rake,
            net_amount,
            eligible_mask: side_pot.eligible_seats,
            runouts,
        });
    }
    plan.total_awards = plan.awards.iter().try_fold(0u64, |sum, amount| {
        sum.checked_add(*amount)
            .ok_or_else(|| PokerL1Error::Serialization("settlement: total award overflow".into()))
    })?;
    plan.validate(table.seats.len())?;
    Ok(plan)
}

fn validate_exposed_cards(table: &TexasPokerTable, boards: &SettlementBoards) -> PokerL1Result<()> {
    let mut seen_hole_cards = HashSet::new();
    for (seat_index, seat) in table.seats.iter().enumerate() {
        if !seat.is_occupied() || seat.is_folded() || seat.has_left_hand() {
            continue;
        }
        let hand = seat.hand().ok_or_else(|| {
            PokerL1Error::Serialization(format!(
                "settlement: eligible seat {seat_index} has no in-hand payload"
            ))
        })?;
        if hand.len() != 2 || hand.iter().any(|card| !card.is_valid()) {
            return Err(PokerL1Error::Serialization(format!(
                "settlement: eligible seat {seat_index} must expose exactly two valid cards"
            )));
        }
        for card in hand.iter() {
            if !seen_hole_cards.insert(card.to_index()) {
                return Err(PokerL1Error::Serialization(
                    "settlement: duplicate exposed hole card".into(),
                ));
            }
        }
    }
    for card in boards.board1() {
        if seen_hole_cards.contains(&card.to_index()) {
            return Err(PokerL1Error::Serialization(
                "settlement: board card duplicates an exposed hole card".into(),
            ));
        }
    }
    if boards.runout_count() == 2 {
        for card in boards
            .board2()
            .iter()
            .skip(usize::from(boards.shared_board_len()))
        {
            if seen_hole_cards.contains(&card.to_index()) {
                return Err(PokerL1Error::Serialization(
                    "settlement: second board duplicates an exposed hole card".into(),
                ));
            }
        }
    }
    Ok(())
}

fn compute_rake(table: &TexasPokerTable, gross_pot: u64) -> PokerL1Result<u64> {
    match table.rake_mode {
        RAKE_MODE_NONE => Ok(0),
        RAKE_MODE_PERCENTAGE => {
            let raw = u128::from(gross_pot)
                .checked_mul(u128::from(table.rake_bps))
                .ok_or_else(|| {
                    PokerL1Error::Serialization("settlement: rake multiplication overflow".into())
                })?
                / 10_000;
            Ok(raw
                .min(u128::from(table.rake_cap))
                .min(u128::from(gross_pot)) as u64)
        }
        mode => Err(PokerL1Error::Serialization(format!(
            "settlement: unsupported rake mode {mode}"
        ))),
    }
}

fn allocate_rake(pots: &[SidePot], rake: u64, gross_pot: u64) -> PokerL1Result<Vec<u64>> {
    if rake == 0 {
        return Ok(vec![0; pots.len()]);
    }
    if gross_pot == 0 || pots.is_empty() {
        return Err(PokerL1Error::Serialization(
            "settlement: cannot allocate rake over an empty pot set".into(),
        ));
    }
    let mut allocations = Vec::with_capacity(pots.len());
    let mut allocated = 0u64;
    for pot in pots {
        let share = if pot.eligible_seats.count_ones() >= 2 {
            (u128::from(pot.amount) * u128::from(rake) / u128::from(gross_pot)) as u64
        } else {
            0
        };
        allocations.push(share);
        allocated = allocated.checked_add(share).ok_or_else(|| {
            PokerL1Error::Serialization("settlement: rake allocation overflow".into())
        })?;
    }
    let mut remainder = rake.checked_sub(allocated).ok_or_else(|| {
        PokerL1Error::Serialization("settlement: proportional rake exceeds total rake".into())
    })?;
    for (pot, allocation) in pots.iter().zip(&mut allocations) {
        if remainder == 0 {
            break;
        }
        if pot.eligible_seats.count_ones() < 2 {
            continue;
        }
        let available = pot.amount.checked_sub(*allocation).ok_or_else(|| {
            PokerL1Error::Serialization("settlement: pot rake allocation exceeds pot".into())
        })?;
        let take = remainder.min(available);
        *allocation += take;
        remainder -= take;
    }
    if remainder != 0 {
        return Err(PokerL1Error::Serialization(
            "settlement: rake remainder exceeds available pots".into(),
        ));
    }
    Ok(allocations)
}

fn split_across_runouts(amount: u64, runout_count: u8) -> [u64; MAX_RUNOUTS] {
    if runout_count == 1 {
        [amount, 0]
    } else {
        // The first board receives the deterministic odd chip.
        [amount / 2 + amount % 2, amount / 2]
    }
}

fn find_winners(
    table: &TexasPokerTable,
    eligible_mask: u16,
    board: &[Card],
) -> PokerL1Result<(u16, [Option<HandRank>; SETTLEMENT_SEATS])> {
    let mut ranks = [None; SETTLEMENT_SEATS];
    let mut best_rank = None;
    let mut winner_mask = 0u16;
    for seat_index in 0..table.seats.len() {
        if !side_pot::is_eligible(eligible_mask, seat_index as u8) {
            continue;
        }
        let seat = &table.seats[seat_index];
        let hand = seat.hand().ok_or_else(|| {
            PokerL1Error::Serialization(format!(
                "settlement: eligible seat {seat_index} has no in-hand payload"
            ))
        })?;
        if hand.len() != 2 {
            return Err(PokerL1Error::Serialization(format!(
                "settlement: eligible seat {seat_index} has no complete hand"
            )));
        }
        let mut cards = Vec::with_capacity(7);
        cards.extend_from_slice(hand);
        cards.extend_from_slice(board);
        let rank = evaluate_best(&cards);
        ranks[seat_index] = Some(rank);
        match best_rank {
            None => {
                best_rank = Some(rank);
                winner_mask = 1u16 << seat_index;
            }
            Some(best) if rank > best => {
                best_rank = Some(rank);
                winner_mask = 1u16 << seat_index;
            }
            Some(best) if rank == best => winner_mask |= 1u16 << seat_index,
            Some(_) => {}
        }
    }
    if winner_mask == 0 {
        return Err(PokerL1Error::Serialization(
            "settlement: side pot has no ranked eligible winner".into(),
        ));
    }
    Ok((winner_mask, ranks))
}

fn split_among_winners(
    amount: u64,
    winner_mask: u16,
    button: u8,
    seat_count: usize,
) -> PokerL1Result<[u64; SETTLEMENT_SEATS]> {
    let mut ordered = Vec::new();
    for offset in 1..=seat_count {
        let seat = (usize::from(button) + offset) % seat_count;
        if winner_mask & (1u16 << seat) != 0 {
            ordered.push(seat);
        }
    }
    if ordered.is_empty() {
        return Err(PokerL1Error::Serialization(
            "settlement: winner mask is empty or outside the table".into(),
        ));
    }
    let winner_count = u64::try_from(ordered.len())
        .map_err(|_| PokerL1Error::Serialization("settlement: winner count exceeds u64".into()))?;
    let share = amount / winner_count;
    let remainder = amount % winner_count;
    let mut awards = [0u64; SETTLEMENT_SEATS];
    for (position, seat) in ordered.into_iter().enumerate() {
        awards[seat] = share + u64::from((position as u64) < remainder);
    }
    Ok(awards)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object_model::ObjectID;
    use crate::vm::contracts::texas_poker::types::SeatStatus;

    #[derive(BorshSerialize, Clone)]
    struct LegacyRunoutPotPlanV1 {
        active: bool,
        amount: u64,
        winner_mask: u16,
        ranks: [Option<HandRank>; SETTLEMENT_SEATS],
        awards: [u64; SETTLEMENT_SEATS],
    }

    #[derive(BorshSerialize)]
    struct LegacySettlementPotPlanV1 {
        pot_index: u8,
        contested: bool,
        gross_amount: u64,
        rake: u64,
        net_amount: u64,
        eligible_mask: u16,
        runouts: [LegacyRunoutPotPlanV1; MAX_RUNOUTS],
    }

    fn table() -> TexasPokerTable {
        let mut table = TexasPokerTable::new(
            ObjectID::new([0xFF; 20], 0),
            "settlement".into(),
            [0xAA; 20],
            3,
            1,
            2,
        );
        for (index, stack) in [900u64, 800, 700].into_iter().enumerate() {
            table.seats[index].fixture_set_player([index as u8 + 1; 20]);
            table.seats[index].set_stack(stack).unwrap();
            table.seats[index].fixture_set_total_bet([100, 200, 300][index]);
            table.seats[index].set_status(SeatStatus::AllIn);
        }
        table.seats[0].fixture_set_hand([Card::new(0, 14), Card::new(1, 14)].into());
        table.seats[1].fixture_set_hand([Card::new(0, 13), Card::new(1, 13)].into());
        table.seats[2].fixture_set_hand([Card::new(0, 12), Card::new(1, 12)].into());
        table.pot = 600;
        table.chip_pool = 3_000;
        table.community_cards = vec![
            Card::new(2, 2),
            Card::new(3, 4),
            Card::new(2, 6),
            Card::new(3, 8),
            Card::new(2, 10),
        ]
        .try_into()
        .unwrap();
        table
    }

    #[test]
    fn settlement_pot_v2_omits_contested_and_rejects_v1_bytes() {
        let plan = derive_settlement_plan(&table()).unwrap();
        let pot = plan.pots[0].clone();
        let legacy = LegacySettlementPotPlanV1 {
            pot_index: pot.pot_index,
            contested: pot.is_contested(),
            gross_amount: pot.gross_amount,
            rake: pot.rake,
            net_amount: pot.net_amount,
            eligible_mask: pot.eligible_mask,
            runouts: std::array::from_fn(|index| {
                let runout = &pot.runouts[index];
                LegacyRunoutPotPlanV1 {
                    active: runout.is_active(),
                    amount: runout.amount,
                    winner_mask: runout.winner_mask,
                    ranks: runout.ranks,
                    awards: runout.awards,
                }
            }),
        };

        let canonical_bytes = borsh::to_vec(&pot).unwrap();
        let legacy_bytes = borsh::to_vec(&legacy).unwrap();
        assert_eq!(legacy_bytes.len(), canonical_bytes.len() + 3);
        let decoded: SettlementPotPlan = borsh::from_slice(&canonical_bytes).unwrap();
        assert_eq!(decoded, pot);
        assert!(
            borsh::from_slice::<SettlementPotPlan>(&legacy_bytes).is_err(),
            "v1 pot bytes with contested plus two nested active bits must fail closed"
        );
    }

    #[test]
    fn settlement_boards_and_plan_use_one_typed_runout_schedule() {
        let board = table().community_cards.to_vec();
        let boards = SettlementBoards::single(board.clone());
        let canonical_bytes = borsh::to_vec(&boards).unwrap();
        assert_eq!(
            borsh::from_slice::<SettlementBoards>(&canonical_bytes).unwrap(),
            boards
        );
        assert_eq!(boards.schedule(), SettlementRunoutSchedule::Single);
        assert!(RitStartStreet::from_shared_board_len(2).is_err());

        let twice = SettlementBoards::twice(RitStartStreet::Flop, board.clone(), board);
        assert_eq!(
            twice.schedule(),
            SettlementRunoutSchedule::Twice {
                start: RitStartStreet::Flop
            }
        );

        let mut mismatched_board = table().community_cards.to_vec();
        mismatched_board[0] = Card::new(0, 3);
        let malformed = SettlementBoards::twice(
            RitStartStreet::Flop,
            table().community_cards.to_vec(),
            mismatched_board,
        );
        assert!(
            borsh::from_slice::<SettlementBoards>(&borsh::to_vec(&malformed).unwrap()).is_err(),
            "typed tags still require both boards to agree on the street-derived shared prefix"
        );
    }

    #[test]
    fn settlement_runout_v2_omits_active_and_rejects_v1_bytes() {
        let plan = derive_settlement_plan(&table()).unwrap();
        let runout = plan.pots[0].runouts[0].clone();
        let legacy = LegacyRunoutPotPlanV1 {
            active: runout.is_active(),
            amount: runout.amount,
            winner_mask: runout.winner_mask,
            ranks: runout.ranks,
            awards: runout.awards,
        };

        let canonical_bytes = borsh::to_vec(&runout).unwrap();
        let legacy_bytes = borsh::to_vec(&legacy).unwrap();
        assert_eq!(legacy_bytes.len(), canonical_bytes.len() + 1);
        let decoded: RunoutPotPlan = borsh::from_slice(&canonical_bytes).unwrap();
        assert_eq!(decoded, runout);
        assert!(
            borsh::from_slice::<RunoutPotPlan>(&legacy_bytes).is_err(),
            "v1 runout bytes with the duplicated active bit must fail closed"
        );
    }

    #[test]
    fn single_runout_plan_is_canonical_and_conserves_funds() {
        let table = table();
        let plan = derive_settlement_plan(&table).expect("derive plan");
        assert_eq!(plan.schedule, SettlementRunoutSchedule::Single);
        assert_eq!(plan.gross_pot, 600);
        assert_eq!(plan.rake, 0);
        assert_eq!(plan.total_awards, 600);
        assert_eq!(plan.pots.len(), 3);
        assert_eq!(plan.awards, [300, 200, 100, 0, 0, 0, 0, 0, 0]);
        assert_eq!(plan.digest().unwrap(), plan.clone().digest().unwrap());
        plan.validate(table.seats.len()).unwrap();

        let mut retired = plan;
        retired.version = 1;
        assert!(retired.validate(table.seats.len()).is_err());
    }

    #[test]
    fn two_runouts_split_each_side_pot_before_selecting_winners() {
        let table = table();
        let board1 = table.community_cards.to_vec();
        let board2 = vec![
            Card::new(2, 2),
            Card::new(3, 4),
            Card::new(2, 6),
            Card::new(2, 12),
            Card::new(3, 10),
        ];
        let boards = SettlementBoards::twice(RitStartStreet::Flop, board1, board2);
        let plan = derive_settlement_plan_for_boards(&table, &boards).expect("derive RIT plan");
        assert_eq!(
            plan.schedule,
            SettlementRunoutSchedule::Twice {
                start: RitStartStreet::Flop
            }
        );
        assert_eq!(plan.total_awards, 600);
        assert_eq!(plan.pots[0].runouts[0].amount, 150);
        assert_eq!(plan.pots[0].runouts[1].amount, 150);
        assert_eq!(plan.pots[0].runouts[0].winner_mask, 0b001);
        assert_eq!(plan.pots[0].runouts[1].winner_mask, 0b100);
    }

    #[test]
    fn odd_chip_order_starts_clockwise_after_button() {
        let awards = split_among_winners(5, 0b111, 0, 3).unwrap();
        assert_eq!(awards[..3], [1, 2, 2]);
    }

    #[test]
    fn duplicate_cross_runout_card_is_rejected() {
        let table = table();
        let board1 = table.community_cards.to_vec();
        let board2 = vec![board1[0], board1[1], board1[2], board1[3], Card::new(3, 10)];
        let error = derive_settlement_plan_for_boards(
            &table,
            &SettlementBoards::twice(RitStartStreet::Flop, board1, board2),
        )
        .unwrap_err();
        assert!(error.to_string().contains("duplicate non-shared card"));
    }

    #[test]
    fn uncalled_outer_layer_is_returned_without_rake_or_runout_dependency() {
        let mut table = table();
        table.seats[0].fixture_set_total_bet(50);
        table.seats[1].fixture_set_total_bet(100);
        table.seats[2] = super::super::types::Seat::empty();
        table.pot = 150;
        table.rake_mode = RAKE_MODE_PERCENTAGE;
        table.rake_bps = 1_000;
        table.rake_cap = u64::MAX;

        let board1 = table.community_cards.to_vec();
        let board2 = vec![
            Card::new(2, 2),
            Card::new(3, 4),
            Card::new(2, 6),
            Card::new(2, 11),
            Card::new(3, 12),
        ];
        let plan = derive_settlement_plan_for_boards(
            &table,
            &SettlementBoards::twice(RitStartStreet::Flop, board1, board2),
        )
        .unwrap();

        assert_eq!(plan.pots.len(), 2);
        assert!(plan.pots[0].is_contested());
        assert_eq!(plan.pots[0].gross_amount, 100);
        assert_eq!(plan.pots[0].rake, 10);
        assert!(!plan.pots[1].is_contested());
        assert_eq!(plan.pots[1].gross_amount, 50);
        assert_eq!(plan.pots[1].rake, 0);
        assert_eq!(plan.pots[1].runouts[0].amount, 50);
        assert_eq!(plan.pots[1].runouts[0].winner_mask, 0b010);
        assert_eq!(plan.pots[1].runouts[0].awards[1], 50);
        assert_eq!(plan.pots[1].runouts[1], RunoutPotPlan::inactive());
        assert_eq!(plan.rake, 10);
        assert_eq!(plan.total_awards, 140);
        plan.validate(table.seats.len()).unwrap();
    }

    #[test]
    fn multiway_rit_side_pots_ties_rake_and_odd_chips_are_canonical() {
        let mut table = table();
        table.button = 0;
        for (seat, bet) in table.seats.iter_mut().zip([101u64, 202, 303]) {
            seat.fixture_set_total_bet(bet);
        }
        table.pot = 606;
        table.rake_mode = RAKE_MODE_PERCENTAGE;
        table.rake_bps = 500;
        table.rake_cap = 29;
        table.seats[0].fixture_set_hand([Card::new(0, 2), Card::new(1, 7)].into());
        table.seats[1].fixture_set_hand([Card::new(0, 3), Card::new(1, 8)].into());
        table.seats[2].fixture_set_hand([Card::new(0, 4), Card::new(1, 9)].into());

        // Both boards play entirely from the board, so every eligible seat ties. This makes the
        // button-relative odd-chip order observable at every side-pot depth.
        let boards = SettlementBoards::twice(
            RitStartStreet::Preflop,
            vec![
                Card::new(2, 10),
                Card::new(2, 11),
                Card::new(2, 12),
                Card::new(2, 13),
                Card::new(2, 14),
            ],
            vec![
                Card::new(3, 2),
                Card::new(3, 3),
                Card::new(3, 4),
                Card::new(3, 5),
                Card::new(3, 6),
            ],
        );
        let plan = derive_settlement_plan_for_boards(&table, &boards).unwrap();

        assert_eq!(plan.gross_pot, 606);
        // The final 101-chip layer is uncontested, so only 505 chips are rakeable.
        assert_eq!(plan.rake, 25);
        assert_eq!(plan.total_awards, 581);
        assert_eq!(plan.pots.len(), 3);
        assert!(plan.pots[0].is_contested());
        assert!(plan.pots[1].is_contested());
        assert!(!plan.pots[2].is_contested());
        assert_eq!(plan.pots[2].rake, 0);
        assert_eq!(plan.pots[2].runouts[0].awards[2], 101);
        assert!(!plan.pots[2].runouts[1].is_active());
        assert_eq!(plan.pots[0].runouts[0].winner_mask, 0b111);
        assert_eq!(plan.pots[0].runouts[1].winner_mask, 0b111);
        assert_eq!(plan.pots[1].runouts[0].winner_mask, 0b110);
        assert_eq!(plan.pots[1].runouts[1].winner_mask, 0b110);
        assert_eq!(plan.awards.iter().sum::<u64>(), 581);
        plan.validate(table.seats.len()).unwrap();
    }
}
