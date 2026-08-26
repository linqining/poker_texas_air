//! Fixed-width decomposition plan for the showdown settlement AIR.
//!
//! This module fixes the column layout and constraint plan the showdown
//! settlement AIR will commit to, mirroring the VM semantics locked by
//! `poker_l1::vm::contracts::texas_poker::settlement_fixture`:
//!
//! - **9 seats / ≤9 pot layers** (`SETTLEMENT_SEATS`): one trace row per
//!   (pot layer, seat) award cell plus per-layer rows, exactly the
//!   `SettlementPotPlan`/`RunoutPotPlan` projection.
//! - **≤2 runouts** (`MAX_RUNOUTS`): every contested layer splits its net
//!   amount across the two fixed runout slots (`first = amount/2 +
//!   amount%2`, `second = amount/2`).
//! - **hand ranks**: `HandRank { category: u8 (0..=9), kickers: [u8; 5] }`
//!   per (layer, runout, seat) with lexicographic comparison advice
//!   (category first, then kickers) constrained via byte LogUp lookups.
//! - **odd chip**: winners clockwise after the button; `share = amount /
//!   winner_count`, first `remainder` seats in order take one extra chip.
//! - **rake**: reuse the proven `RevealTimeoutRakedAward` chain
//!   (`min(floor(gross × bps / 10⁴), cap, gross)` on the contested gross,
//!   proportional layer allocation with remainder cascades) — the same
//!   LogUp range-table machinery from `texas_canonical_air`.
//! - **conservation**: `Σ layers gross == gross_pot`, `gross == rake +
//!   awards`, per-runout award sums, uncalled layers unraked.
//!
//! The AIR is not implemented yet; these constants are the committed
//! fixed-width contract that the implementation and the VM fixtures must
//! agree on, so width arithmetic is asserted here.

#![allow(missing_docs)]

use crate::texas_canonical::MAX_CANONICAL_SEATS;

/// Fixed award/rank width of every plan row (VM `SETTLEMENT_SEATS`).
pub const SETTLEMENT_SEATS: usize = MAX_CANONICAL_SEATS;
/// Maximum independent boards (VM `MAX_RUNOUTS`).
pub const MAX_RUNOUTS: usize = 2;
/// Maximum pot layers including the main pot (VM bound: one per all-in
/// level, capped by the seat count).
pub const MAX_POT_LAYERS: usize = SETTLEMENT_SEATS;

/// Hand-rank category width (0..=9: high card..=straight flush).
pub const HAND_RANK_CATEGORY_BYTES: usize = 1;
/// Kicker bytes of one canonical hand rank (5 kickers, 0..=14 each).
pub const HAND_RANK_KICKER_BYTES: usize = 5;
/// Fixed byte width of one hand rank.
pub const HAND_RANK_BYTES: usize = HAND_RANK_CATEGORY_BYTES + HAND_RANK_KICKER_BYTES;

/// Award amount decomposition: 64-bit values as 8 bytes (LogUp range
/// lookups, mirroring the raked-award byte chains).
pub const AWARD_BYTES: usize = 8;
/// Bet/stack amounts share the award decomposition width.
pub const AMOUNT_BYTES: usize = AWARD_BYTES;

/// Per-layer public projection: layer index (1), gross (8), rake (8),
/// net (8), eligible mask (2 bytes = u16).
pub const LAYER_HEADER_COLUMNS: usize = 1 + AMOUNT_BYTES * 3 + 2;

/// Per-(layer, runout) projection: amount (8), winner mask (2), and per
/// seat: rank (6 bytes) + award (8 bytes).
pub const RUNOUT_HEADER_COLUMNS: usize = AMOUNT_BYTES + 2;
/// Columns for one seat inside one runout slot.
pub const RUNOUT_SEAT_COLUMNS: usize = HAND_RANK_BYTES + AWARD_BYTES;

/// Total per-layer width across both fixed runout slots.
pub const LAYER_RUNOUT_COLUMNS: usize =
    MAX_RUNOUTS * (RUNOUT_HEADER_COLUMNS + SETTLEMENT_SEATS * RUNOUT_SEAT_COLUMNS);

/// Full fixed-width layer row (header + runouts).
pub const LAYER_ROW_COLUMNS: usize = LAYER_HEADER_COLUMNS + LAYER_RUNOUT_COLUMNS;

/// Plan-level header: version (1), schedule tag (2: runout count + shared
/// prefix), gross pot (8), rake (8), total awards (8), winner mask (2),
/// per-seat aggregate awards (9 × 8).
pub const PLAN_HEADER_COLUMNS: usize = 3 + AMOUNT_BYTES * 3 + 2 + SETTLEMENT_SEATS * AWARD_BYTES;

/// Fixed-width trace width of the complete settlement plan projection:
/// plan header + every layer row.
pub const PLAN_ROW_COLUMNS: usize = PLAN_HEADER_COLUMNS + MAX_POT_LAYERS * LAYER_ROW_COLUMNS;

/// Active-layer selector columns: one boolean per layer plus one per
/// (layer, runout) slot, all LogUp-constrained to 0/1.
pub const LAYER_SELECTOR_COLUMNS: usize = MAX_POT_LAYERS * (1 + MAX_RUNOUTS);

/// Odd-chip advice per (layer, runout): winner count (8), share (8),
/// remainder (8), plus one clockwise-order index byte per seat.
pub const ODD_CHIP_COLUMNS: usize =
    MAX_POT_LAYERS * MAX_RUNOUTS * (3 * AMOUNT_BYTES + SETTLEMENT_SEATS);

/// Rake allocation advice per layer: contested gross share (8), allocated
/// rake (8), and the byte chains of the shared
/// `min(floor(gross × bps / 10⁴), cap, gross)` computation (reusing the
/// raked-award constants: 56 ordered byte columns over the whole plan).
pub const RAKE_ALLOCATION_COLUMNS: usize = MAX_POT_LAYERS * 2 * AMOUNT_BYTES;

/// Byte columns fed into the shared 256-entry range LogUp table per plan
/// row (amounts, ranks, masks, odd-chip and rake advice).
pub const PLAN_BYTE_LOOKUP_COLUMNS: usize =
    PLAN_ROW_COLUMNS + ODD_CHIP_COLUMNS + RAKE_ALLOCATION_COLUMNS;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn widths_match_the_vm_plan_projection() {
        // Layer row carries both runout slots with every seat's rank+award.
        assert_eq!(RUNOUT_HEADER_COLUMNS, 10);
        assert_eq!(RUNOUT_SEAT_COLUMNS, 14);
        assert_eq!(LAYER_RUNOUT_COLUMNS, 2 * (10 + 9 * 14));
        // Header: version+schedule (3) + 3 amounts + mask + 9 seat awards.
        assert_eq!(PLAN_HEADER_COLUMNS, 3 + 24 + 2 + 72);
        // The full plan fits the fixed width for the maximum 9 layers.
        assert_eq!(
            PLAN_ROW_COLUMNS,
            PLAN_HEADER_COLUMNS + 9 * LAYER_ROW_COLUMNS
        );
    }

    #[test]
    fn vm_fixture_bounds_fit_the_fixed_width() {
        let scene = poker_l1::vm::contracts::texas_poker::settlement_fixture::nine_seat_ladder();
        let plan = scene.assert_invariants();
        assert_eq!(plan.pots.len(), MAX_POT_LAYERS);
        assert_eq!(plan.awards.len(), SETTLEMENT_SEATS);
        assert_eq!(
            plan.awards,
            [90, 80, 70, 60, 50, 40, 30, 20, 10],
            "layer k is won by seat k; the deepest all-in tail is uncalled"
        );
    }
}
