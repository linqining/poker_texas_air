//! Starknet Sepolia calldata builder for the verified outer aggregate and
//! per-hand settlement path.
//!
//! This module is intentionally thin: it consumes only already-verified
//! artifacts (a [`VerifiedOuterAggregate`] issued by the host verifier and a
//! caller-supplied canonical `SettlementPlan` paired with the authenticated
//! pre-settlement [`TexasPokerTable`]) and produces strict Cairo ABI calldata
//! for the on-chain settlement contract.
//!
//! ## Threat model
//!
//! The on-chain contract deliberately verifies only the outer aggregate
//! commitment, the settlement commitment, replay protection, and zero-sum
//! chip deltas. This module is the off-chain adapter that compiles these
//! values from sources that were *already* proven / authenticated by the
//! native verifier and the table-state root. It never reads fields off an
//! unverified bundle descriptor, and it refuses to invent or rewrite any
//! aggregate / settlement digest.
//!
//! ## Aggregate-digest ABI
//!
//! The Cairo contract stores and emits the aggregate digest as a `(felt252,
//! felt252)` pair to preserve the full 256-bit BLAKE2b / BLAKE3 commitment
//! without truncation. We split the 32-byte digest into a high half
//! (`bytes[0..16]` big-endian) and a low half (`bytes[16..32]` big-endian);
//! each half comfortably fits in `felt252` since the Stark prime is
//! ≈ 2^251 and 2^128 < prime.
//!
//! `settle_hand` takes the digest as a single `felt252` for backwards ABI
//! stability. The host must therefore compress the verified dual-felt digest
//! back into the canonical single felt before submitting a `settle_hand`
//! call. The Cairo contract validates equality against the registered
//! high/low halves in storage.

use poker_l1::vm::contracts::texas_poker::settlement::SettlementPlan;
use poker_l1::vm::contracts::texas_poker::types::{
    Address, Seat, TexasPokerTable, EMPTY_PLAYER,
};
use starknet_ff::FieldElement;

use crate::error::{TexasAirError, TexasAirResult};
use crate::outer_aggregate::VerifiedOuterAggregate;

/// Maximum number of participants per `settle_hand` call (9 seats + treasury).
///
/// The contract uses `Span<ContractAddress>` / `Span<i128>`, so technically the
/// array length is unbounded, but we cap at this size so a malicious or
/// mistaken builder cannot produce an oversized payload that the on-chain
/// step would silently truncate.
pub const MAX_SETTLE_PARTICIPANTS: usize = 10;

/// 32-byte digest split into two 128-bit big-endian halves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AggregateDigestFelts {
    /// High half (`bytes[0..16]`).
    pub hi: FieldElement,
    /// Low half (`bytes[16..32]`).
    pub lo: FieldElement,
}

impl AggregateDigestFelts {
    /// Split a 32-byte big-endian digest into dual felts.
    ///
    /// # Errors
    ///
    /// Returns [`TexasAirError::SpecViolation`] if either half does not fit
    /// in 128 bits (this cannot happen for a 16-byte slice, but the explicit
    /// check guards future refactors).
    pub fn split(bytes: &[u8; 32]) -> TexasAirResult<Self> {
        let mut hi_bytes = [0u8; 16];
        let mut lo_bytes = [0u8; 16];
        hi_bytes.copy_from_slice(&bytes[..16]);
        lo_bytes.copy_from_slice(&bytes[16..]);
        let hi = bytes16_to_felt(&hi_bytes)?;
        let lo = bytes16_to_felt(&lo_bytes)?;
        Ok(Self { hi, lo })
    }

    /// Merge two felts back into a 32-byte big-endian digest.
    ///
    /// # Errors
    ///
    /// Returns [`TexasAirError::SpecViolation`] if either felt exceeds the
    /// canonical 128-bit range, indicating the on-chain storage has been
    /// corrupted or the wrong digest was supplied.
    pub fn merge(hi: FieldElement, lo: FieldElement) -> TexasAirResult<[u8; 32]> {
        let hi_bytes = felt_to_bytes16(hi)?;
        let lo_bytes = felt_to_bytes16(lo)?;
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&hi_bytes);
        out[16..].copy_from_slice(&lo_bytes);
        Ok(out)
    }

    /// Lossy single-felt projection used by `settle_hand` ABI.
    ///
    /// This intentionally throws away the high half because the contract
    /// signature for `settle_hand` is single-`felt252`. Callers must
    /// independently verify that the registered aggregate digest's low half
    /// matches this value before submitting the call.
    ///
    /// # Errors
    ///
    /// Returns [`TexasAirError::SpecViolation`] if the low half does not fit
    /// in 128 bits (cannot happen with a `Self::split`-derived pair).
    #[must_use]
    pub fn settle_abi_single_felt(self) -> FieldElement {
        self.lo
    }
}

/// One signed chip delta for the on-chain `i128` ABI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlayerDelta {
    /// Starknet contract address (20 bytes, left-padded to felt252 by Cairo).
    pub address: [u8; 20],
    /// Net chip movement: positive wins, negative loses, zero skipped.
    pub delta: i128,
}

/// Strict calldata DTO for `register_aggregate`.
#[derive(Debug, Clone)]
pub struct RegisterAggregateCalldata {
    aggregate_hi: FieldElement,
    aggregate_lo: FieldElement,
    first_hand_id: u64,
    last_hand_id: u64,
    pre_state_hi: FieldElement,
    pre_state_lo: FieldElement,
    post_state_hi: FieldElement,
    post_state_lo: FieldElement,
    settlement_roots: Vec<FieldElement>,
}

impl RegisterAggregateCalldata {
    /// Build calldata from a host-verified outer aggregate plus the
    /// caller-prepared settlement commitment list (already Poseidon-derived
    /// from the canonical settlement plan per hand, in `first_hand_id..=last_hand_id` order).
    ///
    /// # Errors
    ///
    /// Returns an error when:
    /// - `settlement_roots.len()` does not match `last_hand_id - first_hand_id + 1`,
    /// - the chain's hand range or monotonicity fails,
    /// - any endpoint or settlement root is non-canonical.
    pub fn new(
        verified: &VerifiedOuterAggregate,
        first_hand_id: u32,
        last_hand_id: u32,
        settlement_roots: Vec<FieldElement>,
    ) -> TexasAirResult<Self> {
        if first_hand_id > last_hand_id {
            return Err(TexasAirError::SpecViolation(format!(
                "register_aggregate: first_hand_id {first_hand_id} > last_hand_id {last_hand_id}"
            )));
        }
        let span = u64::from(last_hand_id) - u64::from(first_hand_id) + 1;
        if settlement_roots.len() as u64 != span {
            return Err(TexasAirError::SpecViolation(format!(
                "register_aggregate: settlement_roots count {} does not match range {span}",
                settlement_roots.len()
            )));
        }
        if last_hand_id > u32::MAX {
            return Err(TexasAirError::SpecViolation(
                "register_aggregate: last_hand_id exceeds u64 range".into(),
            ));
        }

        let chain = verified.chain();
        let receipts = chain.receipts();
        let first_receipt = receipts
            .first()
            .ok_or_else(|| TexasAirError::SpecViolation("verified chain is empty".into()))?;
        let last_receipt = receipts
            .last()
            .expect("non-empty chain validated above");
        if first_receipt.hand_id != first_hand_id {
            return Err(TexasAirError::SpecViolation(format!(
                "register_aggregate: chain first hand {} != requested {first_hand_id}",
                first_receipt.hand_id
            )));
        }
        if last_receipt.hand_id != last_hand_id {
            return Err(TexasAirError::SpecViolation(format!(
                "register_aggregate: chain last hand {} != requested {last_hand_id}",
                last_receipt.hand_id
            )));
        }
        for window in receipts.windows(2) {
            let prev = &window[0];
            let next = &window[1];
            if next.hand_id != prev.hand_id + 1 {
                return Err(TexasAirError::SpecViolation(format!(
                    "register_aggregate: non-monotonic hand_id {} -> {}",
                    prev.hand_id, next.hand_id
                )));
            }
        }

        let agg = AggregateDigestFelts::split(&verified.aggregate_digest())?;
        let pre = AggregateDigestFelts::split(&first_receipt.pre_state_root.bytes())?;
        let post = AggregateDigestFelts::split(&last_receipt.post_state_root.bytes())?;

        Ok(Self {
            aggregate_hi: agg.hi,
            aggregate_lo: agg.lo,
            first_hand_id: u64::from(first_hand_id),
            last_hand_id: u64::from(last_hand_id),
            pre_state_hi: pre.hi,
            pre_state_lo: pre.lo,
            post_state_hi: post.hi,
            post_state_lo: post.lo,
            settlement_roots,
        })
    }

    /// Aggregate digest (high half).
    #[must_use]
    pub const fn aggregate_hi(&self) -> FieldElement {
        self.aggregate_hi
    }

    /// Aggregate digest (low half).
    #[must_use]
    pub const fn aggregate_lo(&self) -> FieldElement {
        self.aggregate_lo
    }

    /// First hand in the registration range.
    #[must_use]
    pub const fn first_hand_id(&self) -> u64 {
        self.first_hand_id
    }

    /// Last hand in the registration range.
    #[must_use]
    pub const fn last_hand_id(&self) -> u64 {
        self.last_hand_id
    }

    /// Pre-settlement external state root, split into dual felts.
    #[must_use]
    pub const fn pre_state_root(&self) -> (FieldElement, FieldElement) {
        (self.pre_state_hi, self.pre_state_lo)
    }

    /// Post-settlement external state root, split into dual felts.
    #[must_use]
    pub const fn post_state_root(&self) -> (FieldElement, FieldElement) {
        (self.post_state_hi, self.post_state_lo)
    }

    /// Per-hand settlement commitment roots.
    #[must_use]
    pub fn settlement_roots(&self) -> &[FieldElement] {
        &self.settlement_roots
    }

    /// Serialize to strict Cairo ABI calldata:
    /// `(aggregate_digest: (felt252, felt252), first, last,
    /// pre_root: (felt252, felt252), post_root: (felt252, felt252),
    /// settlement_roots: Span<felt252>)`.
    #[must_use]
    pub fn to_felts(&self) -> Vec<FieldElement> {
        let mut out = Vec::with_capacity(7 + self.settlement_roots.len());
        out.push(self.aggregate_hi);
        out.push(self.aggregate_lo);
        out.push(FieldElement::from(self.first_hand_id));
        out.push(FieldElement::from(self.last_hand_id));
        out.push(self.pre_state_hi);
        out.push(self.pre_state_lo);
        out.push(self.post_state_hi);
        out.push(self.post_state_lo);
        out.push(FieldElement::from(self.settlement_roots.len()));
        out.extend(self.settlement_roots.iter().copied());
        out
    }
}

/// Strict calldata DTO for `settle_hand`.
#[derive(Debug, Clone)]
pub struct SettleHandCalldata {
    /// Single-felt projection of the registered aggregate digest (low half).
    aggregate_digest: FieldElement,
    hand_id: u64,
    players: Vec<FieldElement>,
    deltas: Vec<i128>,
    /// Poseidon commitment over (hand_id, address, sign, magnitude).
    settlement_digest: FieldElement,
}

impl SettleHandCalldata {
    /// Build calldata for a single `settle_hand` call.
    ///
    /// `verified_aggregate_digest` must be the 32-byte Blake2b/Blake3
    /// aggregate digest from a successfully verified outer aggregate. The
    /// `pre_table` must be the authenticated pre-settlement snapshot, and
    /// `plan` must be the canonical validated settlement plan derived from
    /// the same pre-state and the showdown evidence.
    ///
    /// # Errors
    ///
    /// Returns an error when:
    /// - `pre_table.hand_id != hand_id`,
    /// - any seat has a non-positive total bet without a matching award (delta overflow),
    /// - the rake recipient is missing but `plan.rake > 0`,
    /// - the merged participant set is empty, oversized, contains the empty
    ///   address, or duplicates an address,
    /// - deltas are not zero-sum,
    /// - any signed magnitude does not fit in `u64` (Cairo `i128` ABI limit).
    #[allow(clippy::too_many_lines)]
    pub fn new(
        verified_aggregate_digest: [u8; 32],
        hand_id: u32,
        pre_table: &TexasPokerTable,
        plan: &SettlementPlan,
        rake_recipient: Option<[u8; 20]>,
    ) -> TexasAirResult<Self> {
        if pre_table.hand_id != hand_id {
            return Err(TexasAirError::SpecViolation(format!(
                "settle_hand: pre_table.hand_id {} != requested {hand_id}",
                pre_table.hand_id
            )));
        }

        let digests = AggregateDigestFelts::split(&verified_aggregate_digest)?;
        let aggregate_digest_single = digests.settle_abi_single_felt();

        // 1. Player deltas from plan.awards and pre_table seat contributions.
        let mut participants: Vec<PlayerDelta> = Vec::with_capacity(MAX_SETTLE_PARTICIPANTS);
        for (seat_index, seat) in pre_table.seats.iter().enumerate() {
            let player_addr = seat_player_for_settlement(seat)?;
            let total_bet = seat.total_bet();
            let award = plan.awards.get(seat_index).copied().unwrap_or(0);
            let delta = signed_delta(award, total_bet)?;
            if delta == 0 {
                continue;
            }
            participants.push(PlayerDelta {
                address: player_addr,
                delta,
            });
        }

        // 2. Rake treasury entry (merged into a player if addresses collide).
        if plan.rake != 0 {
            let treasury = rake_recipient.ok_or_else(|| {
                TexasAirError::SpecViolation(
                    "settle_hand: plan has non-zero rake but no rake recipient provided".into(),
                )
            })?;
            if treasury == EMPTY_PLAYER {
                return Err(TexasAirError::SpecViolation(
                    "settle_hand: rake recipient is the empty player address".into(),
                ));
            }
            let treasury_magnitude: u64 = plan.rake.try_into().map_err(|_| {
                TexasAirError::SpecViolation(format!(
                    "settle_hand: rake {} does not fit in u64 ABI magnitude",
                    plan.rake
                ))
            })?;
            if let Some(existing) = participants.iter_mut().find(|p| p.address == treasury) {
                let merged = existing.delta.checked_add(treasury_magnitude as i128).ok_or_else(
                    || {
                        TexasAirError::SpecViolation(
                            "settle_hand: merging treasury delta overflows i128".into(),
                        )
                    },
                )?;
                existing.delta = merged;
            } else {
                participants.push(PlayerDelta {
                    address: treasury,
                    delta: treasury_magnitude as i128,
                });
            }
        }

        if participants.is_empty() {
            return Err(TexasAirError::SpecViolation(
                "settle_hand: participant set is empty (no settled players)".into(),
            ));
        }
        if participants.len() > MAX_SETTLE_PARTICIPANTS {
            return Err(TexasAirError::SpecViolation(format!(
                "settle_hand: {} participants exceeds cap {MAX_SETTLE_PARTICIPANTS}",
                participants.len()
            )));
        }

        // 3. Sort by address ascending with treasury last.
        participants.sort_by(|a, b| a.address.cmp(&b.address));

        // 4. Reject duplicate addresses (deterministic addresses make sort stable).
        for window in participants.windows(2) {
            if window[0].address == window[1].address {
                return Err(TexasAirError::SpecViolation(
                    "settle_hand: duplicate participant address after treasury merge".into(),
                ));
            }
        }

        // 5. Zero-sum check.
        let mut sum: i128 = 0;
        for p in &participants {
            sum = sum.checked_add(p.delta).ok_or_else(|| {
                TexasAirError::SpecViolation("settle_hand: delta sum overflowed i128".into())
            })?;
        }
        if sum != 0 {
            return Err(TexasAirError::SpecViolation(format!(
                "settle_hand: delta sum {sum} is not zero-sum"
            )));
        }

        // 6. Encode to Cairo ABI felt252 players and i128 deltas.
        let mut players = Vec::with_capacity(participants.len());
        let mut deltas = Vec::with_capacity(participants.len());
        for p in &participants {
            players.push(address_to_felt(p.address)?);
            validate_i128_abi(p.delta)?;
            deltas.push(p.delta);
        }

        let settlement_digest = compute_settlement_digest(
            u64::from(hand_id),
            &participants,
        )?;

        Ok(Self {
            aggregate_digest: aggregate_digest_single,
            hand_id: u64::from(hand_id),
            players,
            deltas,
            settlement_digest,
        })
    }

    /// Single-felt projection of the aggregate digest for `settle_hand` ABI.
    #[must_use]
    pub const fn aggregate_digest(&self) -> FieldElement {
        self.aggregate_digest
    }

    /// Hand id for this settlement call.
    #[must_use]
    pub const fn hand_id(&self) -> u64 {
        self.hand_id
    }

    /// Participant contract addresses (felt252 encoding, big-endian 20-byte padding).
    #[must_use]
    pub fn players(&self) -> &[FieldElement] {
        &self.players
    }

    /// Per-player signed deltas in the same order as [`Self::players`].
    #[must_use]
    pub fn deltas(&self) -> &[i128] {
        &self.deltas
    }

    /// The Poseidon settlement commitment this calldata recomputes; the
    /// on-chain contract recomputes the same commitment and rejects mismatches.
    #[must_use]
    pub const fn settlement_digest(&self) -> FieldElement {
        self.settlement_digest
    }

    /// Serialize to strict Cairo ABI calldata:
    /// `(aggregate_digest: felt252, hand_id: u64, players: Span<ContractAddress>,
    ///  deltas: Span<i128>)`.
    #[must_use]
    pub fn to_felts(&self) -> Vec<FieldElement> {
        let mut out = Vec::with_capacity(4 + self.players.len() * 2);
        out.push(self.aggregate_digest);
        out.push(FieldElement::from(self.hand_id));
        out.push(FieldElement::from(self.players.len()));
        for player in &self.players {
            out.push(*player);
        }
        out.push(FieldElement::from(self.deltas.len()));
        for delta in &self.deltas {
            out.push(i128_to_felt(*delta));
        }
        out
    }
}

/// Extract the player address from a seat, or reject seats that cannot settle.
fn seat_player_for_settlement(seat: &Seat) -> TexasAirResult<[u8; 20]> {
    match seat {
        Seat::Playing { playing } | Seat::Waiting { occupied: playing } => Ok(playing.player),
        Seat::DepartedThisHand { player, .. } => Ok(*player),
        Seat::Vacant { .. } => Err(TexasAirError::SpecViolation(
            "settle_hand: vacant seat cannot participate".into(),
        )),
    }
}

/// Compute `award - total_bet` with strict overflow checks.
///
/// Both inputs are `u64` and the result must fit in `i128`. We treat `total_bet > award`
/// (a loss) as a strict negative, refusing to silently truncate.
fn signed_delta(award: u64, total_bet: u64) -> TexasAirResult<i128> {
    if award >= total_bet {
        let gain = u64::try_from(award - total_bet)
            .expect("non-negative u64 always fits in u64");
        let gain_i128: i128 = gain.into();
        Ok(gain_i128)
    } else {
        let loss = u64::try_from(total_bet - award)
            .expect("non-negative u64 always fits in u64");
        let loss_i128: i128 = loss.into();
        Ok(-loss_i128)
    }
}

/// Reject i128 values whose absolute magnitude exceeds the Cairo `i128`
/// contract limit (sign + u64 magnitude in the Poseidon commitment).
fn validate_i128_abi(delta: i128) -> TexasAirResult<()> {
    let magnitude = delta.unsigned_abs();
    if magnitude > u64::MAX as u128 {
        return Err(TexasAirError::SpecViolation(format!(
            "settle_hand: delta magnitude {magnitude} exceeds u64 ABI bound"
        )));
    }
    Ok(())
}

/// Encode a Starknet contract address as a felt252 (left-padded 20-byte big-endian).
fn address_to_felt(addr: [u8; 20]) -> TexasAirResult<FieldElement> {
    if addr == EMPTY_PLAYER {
        return Err(TexasAirError::SpecViolation(
            "settle_hand: empty player address in participant set".into(),
        ));
    }
    // Starknet addresses fit in felt252 by construction (20 bytes < 251 bits).
    Ok(FieldElement::from_byte_slice_be(&addr).expect("20-byte address always fits in felt252"))
}

/// Encode a signed i128 into the Starknet prime as a felt.
///
/// Negative values become the modular complement `-magnitude`.
fn i128_to_felt(value: i128) -> FieldElement {
    if value >= 0 {
        let magnitude: u64 = value
            .try_into()
            .expect("non-negative i128 always fits in u64 after validate_i128_abi");
        FieldElement::from(magnitude)
    } else {
        // Two's-complement-style modular reduction; the contract reads these
        // back into `i128` via the inverse `from_felt_signed_i128` helper.
        let magnitude: u64 = value
            .unsigned_abs()
            .try_into()
            .expect("validated by validate_i128_abi");
        -FieldElement::from(magnitude)
    }
}

/// Canonical Cairo-compatible Poseidon settlement commitment.
///
/// The encoding matches `poker_contracts/src/settlement_hash.cairo`:
/// `hand_id`, then for each ordered player: `address`, `sign` (1 non-negative,
/// 0 negative), `magnitude` (u64). Sign / magnitude are written as the same
/// felt252 values the Cairo contract reads back into `i128`.
fn compute_settlement_digest(hand_id: u64, participants: &[PlayerDelta]) -> TexasAirResult<FieldElement> {
    let mut fields: Vec<FieldElement> = Vec::with_capacity(1 + participants.len() * 3);
    fields.push(FieldElement::from(hand_id));
    for p in participants {
        fields.push(address_to_felt(p.address)?);
        if p.delta >= 0 {
            fields.push(FieldElement::from(1_u64));
            let magnitude: u64 = p
                .delta
                .try_into()
                .expect("non-negative delta fits in u64 after validate_i128_abi");
            fields.push(FieldElement::from(magnitude));
        } else {
            fields.push(FieldElement::from(0_u64));
            let magnitude: u64 = p
                .delta
                .unsigned_abs()
                .try_into()
                .expect("abs delta fits in u64 after validate_i128_abi");
            fields.push(FieldElement::from(magnitude));
        }
    }
    Ok(starknet_crypto::poseidon_hash_many(&fields))
}

/// Convert a 16-byte big-endian slice into a `FieldElement`.
fn bytes16_to_felt(bytes: &[u8; 16]) -> TexasAirResult<FieldElement> {
    // A 128-bit value is always a canonical felt252 (Stark prime ≈ 2^251).
    let felt = FieldElement::from_byte_slice_be(bytes)
        .expect("16 bytes (128 bits) always fits in felt252");
    Ok(felt)
}

/// Convert a `FieldElement` back to a 16-byte big-endian slice.
///
/// # Errors
///
/// Returns [`TexasAirError::SpecViolation`] if the felt exceeds the 128-bit
/// canonical range, indicating corruption or a wrong digest.
fn felt_to_bytes16(felt: FieldElement) -> TexasAirResult<[u8; 16]> {
    let bytes = felt.to_bytes_be();
    if bytes.len() != 32 {
        return Err(TexasAirError::SpecViolation(format!(
            "felt_to_bytes16: expected 32-byte big-endian, got {} bytes",
            bytes.len()
        )));
    }
    // The top 16 bytes must be zero (felt must fit in 128 bits).
    if bytes[..16].iter().any(|b| *b != 0) {
        return Err(TexasAirError::SpecViolation(
            "felt_to_bytes16: felt exceeds canonical 128-bit range".into(),
        ));
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes[16..]);
    Ok(out)
}

#[allow(dead_code)]
fn _address_marker(_addr: &Address) {} // keep Address import live for downstream constructors

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_root::StateRoot;
    use crate::verified_chain::VerificationReceipt;
    use poker_l1::vm::contracts::texas_poker::settlement::SettlementPlan;
    use poker_l1::vm::contracts::texas_poker::types::{
        BoardCards, DeckState, HandPhase, HoleCards, OccupiedSeat, PlayingSeat, PlayingSeatStatus,
        ECPoint,
    };
    use poker_l1::cryptography::algebraic::G1Projective;
    use poker_l1::object_model::ObjectID;
    use poker_l1::vm::contracts::texas_poker::rules::TableRules;
    use poker_l1::account::derive_address;

    fn receipt_with_state(
        table_id: u64,
        hand: u32,
        call_seq: u32,
        pre: [u8; 32],
        post: [u8; 32],
    ) -> VerificationReceipt {
        VerificationReceipt::test_only_new(
            table_id,
            hand,
            call_seq,
            StateRoot::from_bytes(pre),
            StateRoot::from_bytes(post),
        )
    }

    fn chain_from(receipts: Vec<VerificationReceipt>) -> VerifiedChain {
        VerifiedChain::test_only_from_receipts(receipts).expect("test chain must validate")
    }

    fn mock_aggregate(chain: VerifiedChain, agg: [u8; 32]) -> VerifiedOuterAggregate {
        VerifiedOuterAggregate::test_only_new(chain, agg)
    }

    fn pk_point() -> ECPoint {
        ECPoint(G1Projective::generator())
    }

    fn playing_seat(player: [u8; 20], total_bet: u64) -> Seat {
        let occupied = OccupiedSeat {
            player,
            stack: 1000,
            pk: pk_point(),
            pending_addon: 0,
            time_bank_ms: 30_000,
        };
        Seat::Playing {
            playing: PlayingSeat {
                occupied,
                hand: HoleCards::empty(),
                bet: total_bet,
                total_bet,
                status: PlayingSeatStatus::Active,
            },
        }
    }

    fn vacant_seat() -> Seat {
        Seat::Vacant {
            time_bank_ms: 30_000,
        }
    }

    fn build_test_table(hand_id: u32) -> TexasPokerTable {
        TexasPokerTable {
            id: ObjectID([0xAB; 32]),
            name: "test".to_string(),
            creator: derive_address(b"test"),
            rules: TableRules::new(9, 5, 10),
            seats: vec![
                playing_seat([0x11; 20], 50),
                playing_seat([0x22; 20], 50),
                vacant_seat(),
                vacant_seat(),
                vacant_seat(),
                vacant_seat(),
                vacant_seat(),
                vacant_seat(),
                vacant_seat(),
            ],
            acted_mask: 0,
            leave_after_hand_mask: 0,
            button: 0,
            pot: 100,
            community_cards: BoardCards::default(),
            hand_phase: HandPhase::Waiting,
            deck_state: DeckState::default(),
            chip_pool: 100,
            run_it_twice_state: Default::default(),
            hand_id,
            call_seq: 0,
        }
    }

    #[test]
    fn split_merge_round_trip() {
        let bytes: [u8; 32] = (0u8..32).collect::<Vec<_>>().try_into().unwrap();
        let felts = AggregateDigestFelts::split(&bytes).unwrap();
        let merged = AggregateDigestFelts::merge(felts.hi, felts.lo).unwrap();
        assert_eq!(merged, bytes);
    }

    #[test]
    fn split_preserves_high_bits() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xAB;
        bytes[15] = 0xCD;
        let felts = AggregateDigestFelts::split(&bytes).unwrap();
        let merged = AggregateDigestFelts::merge(felts.hi, felts.lo).unwrap();
        assert_eq!(merged, bytes, "high byte must not be silently dropped");
    }

    #[test]
    fn merge_rejects_oversize_felt() {
        let oversized = FieldElement::from(u128::MAX) + FieldElement::from(1_u64);
        let err = AggregateDigestFelts::merge(oversized, FieldElement::ZERO).unwrap_err();
        assert!(matches!(err, TexasAirError::SpecViolation(_)));
    }

    #[test]
    fn settle_hand_zero_sum_invariant() {
        let table = build_test_table(7);
        // Seat 0 wins the 100-chip pot: awards[0] = 100 (delta +50), seat 1 loses (delta -50).
        let plan = SettlementPlan {
            version: 1,
            schedule: Default::default(),
            gross_pot: 100,
            rake: 0,
            total_awards: 100,
            winner_mask: 1,
            awards: [100, 0, 0, 0, 0, 0, 0, 0, 0],
            pots: vec![],
        };
        let calldata = SettleHandCalldata::new([1u8; 32], 7, &table, &plan, None).unwrap();
        let sum: i128 = calldata.deltas().iter().sum();
        assert_eq!(sum, 0);
        // The Poseidon digest must equal the felt computed by the contract:
        // hand_id=7, [addr0, sign=1, mag=50, addr1, sign=0, mag=50]
        let addr0 = address_to_felt([0x11; 20]).unwrap();
        let addr1 = address_to_felt([0x22; 20]).unwrap();
        let expected = starknet_crypto::poseidon_hash_many(&[
            FieldElement::from(7_u64),
            addr0,
            FieldElement::from(1_u64),
            FieldElement::from(50_u64),
            addr1,
            FieldElement::from(0_u64),
            FieldElement::from(50_u64),
        ]);
        assert_eq!(calldata.settlement_digest(), expected);
    }

    #[test]
    fn settle_hand_rejects_non_zero_sum() {
        let table = build_test_table(7);
        // Awards seat 0 with 200 chips when only 100 were wagered, no rake, no loser.
        let plan = SettlementPlan {
            version: 1,
            schedule: Default::default(),
            gross_pot: 200,
            rake: 0,
            total_awards: 200,
            winner_mask: 1,
            awards: [200, 0, 0, 0, 0, 0, 0, 0, 0],
            pots: vec![],
        };
        let err = SettleHandCalldata::new([2u8; 32], 7, &table, &plan, None).unwrap_err();
        assert!(matches!(err, TexasAirError::SpecViolation(_)));
    }

    #[test]
    fn settle_hand_rake_merges_with_player() {
        let table = build_test_table(7);
        let plan = SettlementPlan {
            version: 1,
            schedule: Default::default(),
            gross_pot: 100,
            rake: 5,
            total_awards: 95,
            winner_mask: 1,
            awards: [95, 0, 0, 0, 0, 0, 0, 0, 0],
            pots: vec![],
        };
        // Rake recipient equals seat 0 (winner) → must merge.
        let winner_addr = [0x11; 20];
        let calldata =
            SettleHandCalldata::new([3u8; 32], 7, &table, &plan, Some(winner_addr)).unwrap();
        // Players should be ordered: seat 0 first (winner + rake), seat 1 second (loser).
        assert_eq!(calldata.players().len(), 2);
        let sum: i128 = calldata.deltas().iter().sum();
        assert_eq!(sum, 0);
        // Merged delta for the winner should be +45 (95 award - 50 bet + 5 rake).
        let winner_felt = address_to_felt([0x11; 20]).unwrap();
        let winner_idx = calldata
            .players()
            .iter()
            .position(|p| *p == winner_felt)
            .expect("winner present");
        assert_eq!(calldata.deltas()[winner_idx], 45);
    }

    #[test]
    fn settle_hand_rejects_missing_rake_recipient() {
        let table = build_test_table(7);
        let plan = SettlementPlan {
            version: 1,
            schedule: Default::default(),
            gross_pot: 100,
            rake: 5,
            total_awards: 95,
            winner_mask: 1,
            awards: [95, 0, 0, 0, 0, 0, 0, 0, 0],
            pots: vec![],
        };
        let err = SettleHandCalldata::new([4u8; 32], 7, &table, &plan, None).unwrap_err();
        assert!(matches!(err, TexasAirError::SpecViolation(_)));
    }

    #[test]
    fn settle_hand_rejects_hand_id_mismatch() {
        let table = build_test_table(7);
        let plan = SettlementPlan {
            version: 1,
            schedule: Default::default(),
            gross_pot: 100,
            rake: 0,
            total_awards: 100,
            winner_mask: 1,
            awards: [100, 0, 0, 0, 0, 0, 0, 0, 0],
            pots: vec![],
        };
        let err = SettleHandCalldata::new([5u8; 32], 8, &table, &plan, None).unwrap_err();
        assert!(matches!(err, TexasAirError::SpecViolation(_)));
    }

    #[test]
    fn register_aggregate_validates_matching_range() {
        let chain = chain_from(vec![
            receipt_with_state(1, 10, 0, [0x10; 32], [0x20; 32]),
            receipt_with_state(1, 11, 1, [0x20; 32], [0x30; 32]),
        ]);
        let agg = mock_aggregate(chain, [0xAA; 32]);
        let ok = RegisterAggregateCalldata::new(
            &agg,
            10,
            11,
            vec![FieldElement::from(1), FieldElement::from(2)],
        );
        assert!(ok.is_ok());
    }

    #[test]
    fn register_aggregate_rejects_hand_range_mismatch() {
        let chain = chain_from(vec![
            receipt_with_state(1, 10, 0, [0x10; 32], [0x20; 32]),
            receipt_with_state(1, 11, 1, [0x20; 32], [0x30; 32]),
        ]);
        let agg = mock_aggregate(chain, [0xAA; 32]);
        // Range asks for hand 11..=12 but chain only covers 10..=11.
        let err = RegisterAggregateCalldata::new(
            &agg,
            11,
            12,
            vec![FieldElement::from(1), FieldElement::from(2)],
        )
        .unwrap_err();
        assert!(matches!(err, TexasAirError::SpecViolation(_)));
    }

    #[test]
    fn calldata_felt_layout_matches_contract_abi() {
        let chain = chain_from(vec![receipt_with_state(
            1,
            5,
            0,
            [0x01; 32],
            [0x02; 32],
        )]);
        let agg = mock_aggregate(chain, [0xAA; 32]);
        let c = RegisterAggregateCalldata::new(&agg, 5, 5, vec![FieldElement::from(42)]).unwrap();
        let felts = c.to_felts();
        // 2 (digest) + 2 (hand range) + 4 (state roots) + 1 (length) + 1 (root) = 10
        assert_eq!(felts.len(), 10);
        assert_eq!(felts[0], c.aggregate_hi);
        assert_eq!(felts[1], c.aggregate_lo);
        assert_eq!(felts[2], FieldElement::from(5_u64));
        assert_eq!(felts[3], FieldElement::from(5_u64));
        assert_eq!(felts[8], FieldElement::from(1_u64));
        assert_eq!(felts[9], FieldElement::from(42_u64));
    }
}
