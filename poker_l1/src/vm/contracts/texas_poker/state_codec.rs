//! Canonical persisted-state codec for Texas Poker tables.
//!
//! Production deliberately supports only the current resolved snapshot (v29) and the ObjectDb
//! hot-table layout (v30). Historical schemas are not consensus inputs and fail closed instead of
//! carrying an ever-growing migration surface in the execution path.

use std::io::{self, Read, Write};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};
use poker_protocol::crypto::types::ECPoint;

use super::card::BoardCards;
use super::types::{
    DeckState, HandPhase, RunItTwiceState, Seat, SeatMask, TableContextBinding,
    TableContextBindings, TableContextOpenings, TableRules, TexasPokerTable, seat_mask_contains,
    seat_mask_is_canonical,
};
use super::utils::{g1_add, g1_is_identity};
use super::{
    TEXAS_POKER_GOVERNANCE_OBJECT_TYPE, TEXAS_POKER_HOT_STATE_SCHEMA_VERSION,
    TEXAS_POKER_METADATA_OBJECT_TYPE, TEXAS_POKER_RULES_OBJECT_TYPE, TEXAS_POKER_TABLE_OBJECT_TYPE,
    TEXAS_POKER_TABLE_STATE_SCHEMA_VERSION,
};
use crate::Address;
use crate::error::{PokerL1Error, PokerL1Result};
use crate::object_model::{Object, ObjectID, Ownership};

const METADATA_CONTEXT_DOMAIN: &[u8] = b"zchain.texas_poker.metadata.v1";
const RULES_CONTEXT_DOMAIN: &[u8] = b"zchain.texas_poker.rules.v1";
const GOVERNANCE_CONTEXT_DOMAIN: &[u8] = b"zchain.texas_poker.governance.v1";

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct PersistedDeckStateV29 {
    encrypted: super::types::CipherDeck,
    contributor_mask: SeatMask,
    cards_dealt: u8,
    owner_readable_hole_cards: super::types::PartialHoleCardLedger,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct PersistedTexasPokerTableV29 {
    id: ObjectID,
    state_schema_version: u8,
    name: String,
    creator: Address,
    rules: TableRules,
    seats: Vec<Seat>,
    acted_mask: SeatMask,
    leave_after_hand_mask: SeatMask,
    button: u8,
    pot: u64,
    community_cards: BoardCards,
    hand_phase: HandPhase,
    deck_state: PersistedDeckStateV29,
    chip_pool: u64,
    run_it_twice_state: RunItTwiceState,
    hand_id: u32,
    call_seq: u32,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
struct PersistedTexasPokerHotTableV30 {
    id: ObjectID,
    state_schema_version: u8,
    context: TableContextBindings,
    seats: Vec<Seat>,
    acted_mask: SeatMask,
    leave_after_hand_mask: SeatMask,
    button: u8,
    pot: u64,
    community_cards: BoardCards,
    hand_phase: HandPhase,
    deck_state: PersistedDeckStateV29,
    chip_pool: u64,
    run_it_twice_state: RunItTwiceState,
    hand_id: u32,
    call_seq: u32,
}

fn persisted_seats(seats: &[Seat]) -> PokerL1Result<Vec<Seat>> {
    for seat in seats {
        seat.validate_canonical()?;
    }
    Ok(seats.to_vec())
}

fn restore_seats(seats: Vec<Seat>) -> PokerL1Result<Vec<Seat>> {
    for seat in &seats {
        seat.validate_canonical()?;
    }
    Ok(seats)
}

fn persisted_deck(table: &TexasPokerTable) -> PersistedDeckStateV29 {
    PersistedDeckStateV29 {
        encrypted: table.deck_state.encrypted.clone(),
        contributor_mask: table.deck_state.contributor_mask,
        cards_dealt: table.deck_state.cards_dealt,
        owner_readable_hole_cards: table.deck_state.owner_readable_hole_cards.clone(),
    }
}

fn aggregate_pk_for_mask(
    seats: &[Seat],
    max_players: u8,
    mask: SeatMask,
) -> PokerL1Result<Option<ECPoint>> {
    if !seat_mask_is_canonical(mask, max_players) || seats.len() != usize::from(max_players) {
        return Err(PokerL1Error::Serialization(
            "Texas contributor mask/seat layout is not canonical".into(),
        ));
    }
    let mut aggregate: Option<ECPoint> = None;
    for seat_index in 0..max_players {
        if !seat_mask_contains(mask, seat_index) {
            continue;
        }
        let seat = &seats[usize::from(seat_index)];
        let pk = seat.pk().ok_or_else(|| {
            PokerL1Error::Serialization(format!(
                "Texas contributor seat {seat_index} has no live key"
            ))
        })?;
        if !seat.is_occupied() || g1_is_identity(&pk.0) {
            return Err(PokerL1Error::Serialization(format!(
                "Texas contributor seat {seat_index} is not a live non-identity key"
            )));
        }
        aggregate = Some(match aggregate {
            None => *pk,
            Some(current) => ECPoint::from(g1_add(&current.0, &pk.0)),
        });
    }
    if aggregate
        .as_ref()
        .is_some_and(|point| g1_is_identity(&point.0))
    {
        return Err(PokerL1Error::Serialization(
            "Texas contributor aggregate cannot be identity".into(),
        ));
    }
    Ok(aggregate)
}

fn restore_table(
    id: ObjectID,
    rules: TableRules,
    name: String,
    creator: Address,
    seats: Vec<Seat>,
    acted_mask: SeatMask,
    leave_after_hand_mask: SeatMask,
    button: u8,
    pot: u64,
    community_cards: BoardCards,
    hand_phase: HandPhase,
    deck_state: PersistedDeckStateV29,
    chip_pool: u64,
    run_it_twice_state: RunItTwiceState,
    hand_id: u32,
    call_seq: u32,
) -> PokerL1Result<TexasPokerTable> {
    let seats = restore_seats(seats)?;
    let _ = aggregate_pk_for_mask(&seats, rules.max_players, deck_state.contributor_mask)?;
    let table = TexasPokerTable {
        id,
        name,
        creator,
        rules,
        seats,
        acted_mask,
        leave_after_hand_mask,
        button,
        pot,
        community_cards,
        hand_phase,
        deck_state: DeckState {
            encrypted: deck_state.encrypted,
            contributor_mask: deck_state.contributor_mask,
            cards_dealt: deck_state.cards_dealt,
            owner_readable_hole_cards: deck_state.owner_readable_hole_cards,
        },
        chip_pool,
        run_it_twice_state,
        hand_id,
        call_seq,
    };
    table.validate_state_schema()?;
    Ok(table)
}

impl TryFrom<&TexasPokerTable> for PersistedTexasPokerTableV29 {
    type Error = PokerL1Error;

    fn try_from(value: &TexasPokerTable) -> Result<Self, Self::Error> {
        value.validate_state_schema()?;
        Ok(Self {
            id: value.id,
            state_schema_version: TEXAS_POKER_TABLE_STATE_SCHEMA_VERSION,
            name: value.name.clone(),
            creator: value.creator,
            rules: value.rules.clone(),
            seats: persisted_seats(&value.seats)?,
            acted_mask: value.acted_mask,
            leave_after_hand_mask: value.leave_after_hand_mask,
            button: value.button,
            pot: value.pot,
            community_cards: value.community_cards.clone(),
            hand_phase: value.canonical_hand_phase()?,
            deck_state: persisted_deck(value),
            chip_pool: value.chip_pool,
            run_it_twice_state: value.run_it_twice_state.clone(),
            hand_id: value.hand_id,
            call_seq: value.call_seq,
        })
    }
}

impl TryFrom<PersistedTexasPokerTableV29> for TexasPokerTable {
    type Error = PokerL1Error;

    fn try_from(value: PersistedTexasPokerTableV29) -> Result<Self, Self::Error> {
        if value.state_schema_version != TEXAS_POKER_TABLE_STATE_SCHEMA_VERSION {
            return Err(PokerL1Error::Serialization(format!(
                "unsupported canonical Texas schema {}",
                value.state_schema_version
            )));
        }
        restore_table(
            value.id,
            value.rules,
            value.name,
            value.creator,
            value.seats,
            value.acted_mask,
            value.leave_after_hand_mask,
            value.button,
            value.pot,
            value.community_cards,
            value.hand_phase,
            value.deck_state,
            value.chip_pool,
            value.run_it_twice_state,
            value.hand_id,
            value.call_seq,
        )
    }
}

impl BorshSerialize for TexasPokerTable {
    fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        PersistedTexasPokerTableV29::try_from(self)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?
            .serialize(writer)
    }
}

impl BorshDeserialize for TexasPokerTable {
    fn deserialize_reader<R: Read>(reader: &mut R) -> io::Result<Self> {
        let id = ObjectID::deserialize_reader(reader)?;
        let schema = u8::deserialize_reader(reader)?;
        if schema != TEXAS_POKER_TABLE_STATE_SCHEMA_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported Texas table schema {schema}"),
            ));
        }
        let mut prefix = Vec::new();
        id.serialize(&mut prefix)?;
        schema.serialize(&mut prefix)?;
        let mut replay = prefix.as_slice().chain(reader);
        PersistedTexasPokerTableV29::deserialize_reader(&mut replay)?
            .try_into()
            .map_err(|error: PokerL1Error| {
                io::Error::new(io::ErrorKind::InvalidData, error.to_string())
            })
    }
}

fn derive_context_object_id(table_id: ObjectID, domain: &[u8]) -> ObjectID {
    let mut hasher = Blake2bVar::new(32).expect("32 <= 64");
    hasher.update(b"zchain.texas_poker.context_object_id.v1");
    hasher.update(&table_id.to_bytes());
    hasher.update(domain);
    let mut digest = [0u8; 32];
    hasher.finalize_variable(&mut digest).expect("32 <= 64");
    let mut creator_address = [0u8; 20];
    creator_address.copy_from_slice(&digest[..20]);
    ObjectID::new(creator_address, 0)
}

fn context_digest<T: BorshSerialize>(
    table_id: ObjectID,
    domain: &[u8],
    value: &T,
) -> PokerL1Result<[u8; 32]> {
    let encoded = borsh::to_vec(value).map_err(|error| {
        PokerL1Error::Serialization(format!("Texas context opening borsh: {error}"))
    })?;
    let mut hasher = Blake2bVar::new(32).expect("32 <= 64");
    hasher.update(domain);
    hasher.update(&table_id.to_bytes());
    hasher.update(&encoded);
    let mut digest = [0u8; 32];
    hasher.finalize_variable(&mut digest).expect("32 <= 64");
    Ok(digest)
}

#[must_use]
/// Deterministic ObjectDb ID for the immutable metadata opening.
pub fn table_metadata_object_id(table_id: ObjectID) -> ObjectID {
    derive_context_object_id(table_id, METADATA_CONTEXT_DOMAIN)
}

#[must_use]
/// Deterministic ObjectDb ID for the immutable rules opening.
pub fn table_rules_object_id(table_id: ObjectID) -> ObjectID {
    derive_context_object_id(table_id, RULES_CONTEXT_DOMAIN)
}

#[must_use]
/// Deterministic ObjectDb ID for the immutable governance opening.
pub fn table_governance_object_id(table_id: ObjectID) -> ObjectID {
    derive_context_object_id(table_id, GOVERNANCE_CONTEXT_DOMAIN)
}

/// Compute the exact immutable-object IDs and domain-separated digests bound by a hot table.
pub fn table_context_bindings(
    table_id: ObjectID,
    openings: &TableContextOpenings,
) -> PokerL1Result<TableContextBindings> {
    openings.validate_canonical()?;
    Ok(TableContextBindings {
        metadata: TableContextBinding {
            object_id: table_metadata_object_id(table_id),
            digest: context_digest(table_id, METADATA_CONTEXT_DOMAIN, &openings.metadata)?,
        },
        rules: TableContextBinding {
            object_id: table_rules_object_id(table_id),
            digest: context_digest(table_id, RULES_CONTEXT_DOMAIN, &openings.rules)?,
        },
        governance: TableContextBinding {
            object_id: table_governance_object_id(table_id),
            digest: context_digest(table_id, GOVERNANCE_CONTEXT_DOMAIN, &openings.governance)?,
        },
    })
}

#[must_use]
/// Return whether bytes use the ObjectDb-only hot schema.
pub fn is_hot_table_state(bytes: &[u8]) -> bool {
    let prefix_len = ObjectID::default().to_bytes().len();
    bytes.get(prefix_len) == Some(&TEXAS_POKER_HOT_STATE_SCHEMA_VERSION)
}

/// Encode only mutable hand state and immutable context commitments for ObjectDb storage.
pub fn encode_hot_table_state(table: &TexasPokerTable) -> PokerL1Result<Vec<u8>> {
    table.validate_state_schema()?;
    let openings = TableContextOpenings::from_table(table);
    let persisted = PersistedTexasPokerHotTableV30 {
        id: table.id,
        state_schema_version: TEXAS_POKER_HOT_STATE_SCHEMA_VERSION,
        context: table_context_bindings(table.id, &openings)?,
        seats: persisted_seats(&table.seats)?,
        acted_mask: table.acted_mask,
        leave_after_hand_mask: table.leave_after_hand_mask,
        button: table.button,
        pot: table.pot,
        community_cards: table.community_cards.clone(),
        hand_phase: table.canonical_hand_phase()?,
        deck_state: persisted_deck(table),
        chip_pool: table.chip_pool,
        run_it_twice_state: table.run_it_twice_state.clone(),
        hand_id: table.hand_id,
        call_seq: table.call_seq,
    };
    borsh::to_vec(&persisted)
        .map_err(|error| PokerL1Error::Serialization(format!("Texas hot table borsh: {error}")))
}

/// Hydrate a hot table from independently authenticated immutable context openings.
pub fn decode_hot_table_state(
    bytes: &[u8],
    openings: &TableContextOpenings,
) -> PokerL1Result<TexasPokerTable> {
    let value = PersistedTexasPokerHotTableV30::try_from_slice(bytes).map_err(|error| {
        PokerL1Error::Serialization(format!("Texas hot table v30 borsh: {error}"))
    })?;
    if value.state_schema_version != TEXAS_POKER_HOT_STATE_SCHEMA_VERSION {
        return Err(PokerL1Error::Serialization(format!(
            "unsupported Texas hot table schema {}",
            value.state_schema_version
        )));
    }
    if value.context != table_context_bindings(value.id, openings)? {
        return Err(PokerL1Error::Serialization(
            "Texas hot table context binding/opening mismatch".into(),
        ));
    }
    restore_table(
        value.id,
        openings.rules.clone(),
        openings.metadata.name.clone(),
        openings.governance.creator,
        value.seats,
        value.acted_mask,
        value.leave_after_hand_mask,
        value.button,
        value.pot,
        value.community_cards,
        value.hand_phase,
        value.deck_state,
        value.chip_pool,
        value.run_it_twice_state,
        value.hand_id,
        value.call_seq,
    )
}

/// Build the four objects atomically created for a table: hot state, metadata, rules, governance.
pub fn table_storage_objects(table: &TexasPokerTable) -> PokerL1Result<[Object; 4]> {
    let openings = TableContextOpenings::from_table(table);
    openings.validate_canonical()?;
    Ok([
        Object::new(
            table.id,
            Ownership::Shared,
            TEXAS_POKER_TABLE_OBJECT_TYPE,
            encode_hot_table_state(table)?,
            None,
        ),
        Object::new(
            table_metadata_object_id(table.id),
            Ownership::Immutable,
            TEXAS_POKER_METADATA_OBJECT_TYPE,
            borsh::to_vec(&openings.metadata)?,
            None,
        ),
        Object::new(
            table_rules_object_id(table.id),
            Ownership::Immutable,
            TEXAS_POKER_RULES_OBJECT_TYPE,
            borsh::to_vec(&openings.rules)?,
            None,
        ),
        Object::new(
            table_governance_object_id(table.id),
            Ownership::Immutable,
            TEXAS_POKER_GOVERNANCE_OBJECT_TYPE,
            borsh::to_vec(&openings.governance)?,
            None,
        ),
    ])
}

/// Encode the complete resolved table used by proof tasks and service snapshots.
pub fn encode_table_state(table: &TexasPokerTable) -> PokerL1Result<Vec<u8>> {
    table.validate_state_schema()?;
    borsh::to_vec(table)
        .map_err(|error| PokerL1Error::Serialization(format!("TexasPokerTable borsh: {error}")))
}

/// Decode only the current resolved schema. Historical tables are intentionally unsupported.
pub fn decode_table_state(bytes: &[u8]) -> PokerL1Result<TexasPokerTable> {
    let table = TexasPokerTable::try_from_slice(bytes).map_err(|error| {
        PokerL1Error::Serialization(format!(
            "TexasPokerTable must use current resolved schema v{}: {error}",
            TEXAS_POKER_TABLE_STATE_SCHEMA_VERSION
        ))
    })?;
    table.validate_state_schema()?;
    Ok(table)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::contracts::texas_poker::constants::DEFAULT_TIME_BANK_MS;

    #[test]
    fn current_resolved_and_hot_roundtrip() {
        let table = TexasPokerTable::new(ObjectID::default(), "table".into(), [7; 20], 2, 10, 20);
        let resolved = encode_table_state(&table).unwrap();
        assert_eq!(decode_table_state(&resolved).unwrap(), table);

        let openings = TableContextOpenings::from_table(&table);
        let hot = encode_hot_table_state(&table).unwrap();
        assert!(is_hot_table_state(&hot));
        assert_eq!(decode_hot_table_state(&hot, &openings).unwrap(), table);
    }

    #[test]
    fn old_schema_fails_closed() {
        let table = TexasPokerTable::new(ObjectID::default(), "table".into(), [7; 20], 2, 10, 20);
        let mut bytes = encode_table_state(&table).unwrap();
        let schema_offset = ObjectID::default().to_bytes().len();
        bytes[schema_offset] = TEXAS_POKER_TABLE_STATE_SCHEMA_VERSION - 1;
        assert!(decode_table_state(&bytes).is_err());
    }

    #[test]
    fn old_hot_schema_fails_closed() {
        let table = TexasPokerTable::new(ObjectID::default(), "table".into(), [7; 20], 2, 10, 20);
        let openings = TableContextOpenings::from_table(&table);
        let mut bytes = encode_hot_table_state(&table).unwrap();
        let schema_offset = ObjectID::default().to_bytes().len();
        bytes[schema_offset] = TEXAS_POKER_HOT_STATE_SCHEMA_VERSION - 1;

        assert!(!is_hot_table_state(&bytes));
        assert!(decode_hot_table_state(&bytes, &openings).is_err());
    }

    #[test]
    fn vacant_seat_keeps_only_time_bank() {
        let seat = Seat::Vacant {
            time_bank_ms: DEFAULT_TIME_BANK_MS / 2,
        };
        let restored = Seat::try_from_slice(&borsh::to_vec(&seat).unwrap()).unwrap();
        assert_eq!(restored, seat);
    }
}
