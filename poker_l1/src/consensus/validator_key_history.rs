//! Versioned history for epoch-bound validator consensus-key rotations.

use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::error::{PokerL1Error, PokerL1Result};
use crate::object_model::{Object, ObjectID, Ownership};
use crate::signature::TaggedPubkey;
use crate::storage::ObjectBackend;
use crate::{BlockHeight, ChainId};

/// Reserved type tag for immutable validator key history.
pub const VALIDATOR_KEY_HISTORY_OBJECT_TYPE: &str = "0x2::consensus::ValidatorKeyHistoryV1";

/// Dedicated singleton identity after the validator-bond escrow slot.
pub const VALIDATOR_KEY_HISTORY_OBJECT_ID: ObjectID = ObjectID::new([0u8; 20], u64::MAX - 7);

/// Whether an object occupies the reserved validator-key-history singleton slot.
#[must_use]
pub fn is_validator_key_history_object(object: &Object) -> bool {
    object.id == VALIDATOR_KEY_HISTORY_OBJECT_ID
        && object.object_type == VALIDATOR_KEY_HISTORY_OBJECT_TYPE
}

/// One committed key replacement.  The old key remains resolvable for evidence verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ValidatorKeyRotationRecord {
    /// Previous consensus signing key.
    pub old_pubkey: TaggedPubkey,
    /// Current replacement consensus signing key.
    pub new_pubkey: TaggedPubkey,
    /// Epoch at which the replacement became authoritative.
    pub activated_epoch: u64,
    /// Block height of the authenticated epoch transition.
    pub activated_height: BlockHeight,
}

/// Canonical map of every historical key to its immediate successor.
#[derive(
    Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct ValidatorKeyHistory {
    pub rotations: BTreeMap<TaggedPubkey, ValidatorKeyRotationRecord>,
}

impl ValidatorKeyHistory {
    /// Record one atomic rotation and reject ambiguous key aliases.
    pub fn record(
        &mut self,
        old_pubkey: TaggedPubkey,
        new_pubkey: TaggedPubkey,
        activated_epoch: u64,
        activated_height: BlockHeight,
    ) -> PokerL1Result<()> {
        if old_pubkey == new_pubkey {
            return Err(PokerL1Error::Other(
                "validator key history cannot record an identity rotation".into(),
            ));
        }
        if self.rotations.contains_key(&old_pubkey)
            || self
                .rotations
                .values()
                .any(|record| record.new_pubkey == new_pubkey)
        {
            return Err(PokerL1Error::Other(
                "validator key history contains a conflicting rotation".into(),
            ));
        }
        self.rotations.insert(
            old_pubkey.clone(),
            ValidatorKeyRotationRecord {
                old_pubkey,
                new_pubkey,
                activated_epoch,
                activated_height,
            },
        );
        Ok(())
    }

    /// Resolve an old key to the currently authoritative key through a bounded chain.
    pub fn resolve_current(&self, key: &TaggedPubkey) -> PokerL1Result<TaggedPubkey> {
        let mut current = key.clone();
        let mut visited = std::collections::BTreeSet::new();
        while let Some(record) = self.rotations.get(&current) {
            if !visited.insert(current.clone()) {
                return Err(PokerL1Error::Other(
                    "validator key history contains a cycle".into(),
                ));
            }
            current = record.new_pubkey.clone();
        }
        Ok(current)
    }

    /// Validate history ordering and uniqueness on persisted decode.
    pub fn validate(&self) -> PokerL1Result<()> {
        for (old, record) in &self.rotations {
            if old != &record.old_pubkey || old == &record.new_pubkey {
                return Err(PokerL1Error::Other(
                    "validator key history record key mismatch".into(),
                ));
            }
            self.resolve_current(old)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
struct PersistedValidatorKeyHistory {
    chain_id: ChainId,
    history: ValidatorKeyHistory,
}

/// Encode the optional history singleton.
pub fn validator_key_history_object(
    chain_id: ChainId,
    history: &ValidatorKeyHistory,
    version: u64,
) -> PokerL1Result<Object> {
    let mut object = Object::new(
        VALIDATOR_KEY_HISTORY_OBJECT_ID,
        Ownership::Immutable,
        VALIDATOR_KEY_HISTORY_OBJECT_TYPE,
        borsh::to_vec(&PersistedValidatorKeyHistory {
            chain_id,
            history: history.clone(),
        })?,
        None,
    );
    object.version = version;
    Ok(object)
}

/// Decode the history singleton for a chain.
pub fn decode_validator_key_history_object(
    object: &Object,
    expected_chain_id: ChainId,
) -> PokerL1Result<ValidatorKeyHistory> {
    if object.id != VALIDATOR_KEY_HISTORY_OBJECT_ID
        || object.object_type != VALIDATOR_KEY_HISTORY_OBJECT_TYPE
        || object.owner != Ownership::Immutable
        || object.assigned_validator.is_some()
    {
        return Err(PokerL1Error::Other(
            "invalid ValidatorKeyHistory singleton identity, type or ownership".into(),
        ));
    }
    let persisted: PersistedValidatorKeyHistory =
        borsh::from_slice(&object.data).map_err(|error| {
            PokerL1Error::Serialization(format!("decode ValidatorKeyHistory: {error}"))
        })?;
    if persisted.chain_id != expected_chain_id {
        return Err(PokerL1Error::Other(format!(
            "ValidatorKeyHistory chain_id {} does not match configured chain_id {expected_chain_id}",
            persisted.chain_id
        )));
    }
    persisted.history.validate()?;
    Ok(persisted.history)
}

/// Validate the immutable singleton shape independently of a node's chain namespace.
pub fn validate_validator_key_history_object(object: &Object) -> PokerL1Result<()> {
    if !is_validator_key_history_object(object)
        || object.owner != Ownership::Immutable
        || object.assigned_validator.is_some()
    {
        return Err(PokerL1Error::Other(
            "invalid ValidatorKeyHistory singleton identity, type or ownership".into(),
        ));
    }
    let persisted: PersistedValidatorKeyHistory =
        borsh::from_slice(&object.data).map_err(|error| {
            PokerL1Error::Serialization(format!("decode ValidatorKeyHistory: {error}"))
        })?;
    persisted.history.validate()
}

/// Read the optional history singleton.
pub fn read_validator_key_history<B: ObjectBackend>(
    object_db: &B,
    chain_id: ChainId,
) -> PokerL1Result<Option<(ValidatorKeyHistory, u64)>> {
    match object_db.read(&VALIDATOR_KEY_HISTORY_OBJECT_ID) {
        Ok(object) => Ok(Some((
            decode_validator_key_history_object(&object, chain_id)?,
            object.version,
        ))),
        Err(PokerL1Error::ObjectNotFound(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Create the singleton on the first rotation or replace the existing version.
pub fn write_validator_key_history<B: ObjectBackend>(
    object_db: &mut B,
    chain_id: ChainId,
    previous_version: Option<u64>,
    history: &ValidatorKeyHistory,
) -> PokerL1Result<()> {
    match previous_version {
        Some(version) => {
            let next_version = version.checked_add(1).ok_or_else(|| {
                PokerL1Error::Other("ValidatorKeyHistory object version overflow".into())
            })?;
            object_db.replace_system_object(validator_key_history_object(
                chain_id,
                history,
                next_version,
            )?)
        }
        None => object_db.system_create(validator_key_history_object(chain_id, history, 0)?),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::tagged_pubkey::{SignatureScheme, encode_tag};

    fn key(seed: u8) -> TaggedPubkey {
        TaggedPubkey {
            tag: encode_tag(SignatureScheme::Secp256k1, 1),
            raw: vec![seed; 33],
        }
    }

    #[test]
    fn resolves_chained_historical_keys_and_rejects_conflicts() {
        let first = key(1);
        let second = key(2);
        let third = key(3);
        let mut history = ValidatorKeyHistory::default();
        history
            .record(first.clone(), second.clone(), 4, 400)
            .unwrap();
        history
            .record(second.clone(), third.clone(), 7, 700)
            .unwrap();
        assert_eq!(history.resolve_current(&first).unwrap(), third);
        assert!(history.record(first, key(4), 8, 800).is_err());
        history.validate().unwrap();
    }

    #[test]
    fn object_roundtrip_binds_history_to_chain() {
        let mut history = ValidatorKeyHistory::default();
        history.record(key(5), key(6), 1, 10).unwrap();
        let object = validator_key_history_object(9, &history, 0).unwrap();
        assert_eq!(
            decode_validator_key_history_object(&object, 9).unwrap(),
            history
        );
        assert!(decode_validator_key_history_object(&object, 10).is_err());
    }
}
