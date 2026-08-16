//! Canonical genesis commitment and its immutable on-chain anchor.
//!
//! A chain ID alone is not a genesis identifier: two independent networks can accidentally use
//! the same ID while bootstrapping different validator sets or allocations.  This module makes
//! the complete bootstrap input canonical, hashes it with a versioned domain separator, and
//! stores that hash in a reserved immutable system object.

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::consensus::ValidatorEntry;
use crate::economics::FeePolicy;
use crate::error::{PokerL1Error, PokerL1Result};
use crate::object_model::{Object, ObjectID, Ownership};
use crate::signature::TaggedPubkey;
use crate::{ChainId, Hash};

/// Version of the canonical genesis-manifest encoding.
pub const GENESIS_MANIFEST_VERSION: u16 = 2;
/// Domain separator for [`GenesisManifest::hash`].
const GENESIS_MANIFEST_DOMAIN: &[u8] = b"ZCHAIN_GENESIS_MANIFEST_V1";
/// Object type used only by the immutable genesis anchor.
pub const GENESIS_ANCHOR_OBJECT_TYPE: &str = "GenesisAnchor";
/// Reserved singleton ID for the genesis anchor.
pub const GENESIS_ANCHOR_OBJECT_ID: ObjectID = ObjectID::new([0xFF; 20], 1);

/// One initial native allocation, identified by the exact public key rather than only its
/// truncated address.  This prevents a configuration from changing the account identity while
/// retaining the same allocation address by accident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct GenesisAllocation {
    /// Recipient key whose derived address receives the native coin.
    pub recipient: TaggedPubkey,
    /// Native amount issued at genesis.
    pub amount: u64,
}

/// Versioned, canonical commitment to every consensus-relevant bootstrap input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct GenesisManifest {
    /// Encoding and semantics version.
    pub version: u16,
    /// Network identifier.
    pub chain_id: ChainId,
    /// Validator entries sorted by tagged public-key bytes.
    pub validators: Vec<ValidatorEntry>,
    /// Initial native allocations sorted by tagged public-key bytes.
    pub allocations: Vec<GenesisAllocation>,
    /// Canonical execution fee policy installed with genesis state.
    pub fee_policy: FeePolicy,
}

impl GenesisManifest {
    /// Build a canonical manifest, rejecting ambiguous duplicate identities and invalid amounts.
    pub fn new(
        chain_id: ChainId,
        validators: Vec<ValidatorEntry>,
        allocations: Vec<GenesisAllocation>,
    ) -> PokerL1Result<Self> {
        Self::new_with_fee_policy(chain_id, validators, allocations, FeePolicy::Free)
    }

    /// Build a canonical manifest with its consensus-committed fee policy.
    pub fn new_with_fee_policy(
        chain_id: ChainId,
        mut validators: Vec<ValidatorEntry>,
        mut allocations: Vec<GenesisAllocation>,
        fee_policy: FeePolicy,
    ) -> PokerL1Result<Self> {
        validators.sort_by_key(|validator| validator.pubkey.to_bytes());
        for pair in validators.windows(2) {
            if pair[0].pubkey == pair[1].pubkey {
                return Err(PokerL1Error::Other(
                    "duplicate validator pubkey in genesis manifest".into(),
                ));
            }
        }

        allocations.sort_by_key(|allocation| allocation.recipient.to_bytes());
        for allocation in &allocations {
            if allocation.amount == 0 {
                return Err(PokerL1Error::Other(
                    "genesis allocation amount must be greater than zero".into(),
                ));
            }
        }
        for pair in allocations.windows(2) {
            if pair[0].recipient == pair[1].recipient {
                return Err(PokerL1Error::Other(
                    "duplicate allocation pubkey in genesis manifest".into(),
                ));
            }
        }

        Ok(Self {
            version: GENESIS_MANIFEST_VERSION,
            chain_id,
            validators,
            allocations,
            fee_policy,
        })
    }

    /// Compute the stable bootstrap commitment.
    #[must_use]
    pub fn hash(&self) -> Hash {
        let mut hasher = Blake2bVar::new(32).expect("32-byte Blake2b output is valid");
        hasher.update(GENESIS_MANIFEST_DOMAIN);
        hasher.update(&borsh::to_vec(self).expect("genesis manifest serialization is infallible"));
        let mut digest = [0u8; 32];
        hasher
            .finalize_variable(&mut digest)
            .expect("fixed Blake2b output length");
        digest
    }
}

/// Immutable state object proving which manifest initialized this database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct GenesisAnchor {
    /// Canonical manifest version.
    pub version: u16,
    /// Canonical manifest hash.
    pub manifest_hash: Hash,
}

/// Construct the reserved immutable anchor object for one manifest hash.
pub fn genesis_anchor_object(manifest_hash: Hash) -> PokerL1Result<Object> {
    Ok(Object::new(
        GENESIS_ANCHOR_OBJECT_ID,
        Ownership::Immutable,
        GENESIS_ANCHOR_OBJECT_TYPE,
        borsh::to_vec(&GenesisAnchor {
            version: GENESIS_MANIFEST_VERSION,
            manifest_hash,
        })?,
        None,
    ))
}

/// Whether an object occupies the reserved genesis-anchor identity or type.
#[must_use]
pub fn is_genesis_anchor_object(object: &Object) -> bool {
    object.id == GENESIS_ANCHOR_OBJECT_ID || object.object_type == GENESIS_ANCHOR_OBJECT_TYPE
}

/// Decode and validate a canonical genesis anchor.
pub fn decode_genesis_anchor(object: &Object) -> PokerL1Result<GenesisAnchor> {
    if object.id != GENESIS_ANCHOR_OBJECT_ID
        || object.object_type != GENESIS_ANCHOR_OBJECT_TYPE
        || object.owner != Ownership::Immutable
        || object.version != 0
        || object.assigned_validator.is_some()
    {
        return Err(PokerL1Error::Other(
            "malformed genesis anchor system object".into(),
        ));
    }
    let anchor: GenesisAnchor = borsh::from_slice(&object.data)?;
    if anchor.version != GENESIS_MANIFEST_VERSION {
        return Err(PokerL1Error::Other(format!(
            "unsupported genesis manifest version {}",
            anchor.version
        )));
    }
    Ok(anchor)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{ValidatorEntry, ValidatorStatus};
    use crate::signature::{CURRENT_VERSION, SignatureScheme, TaggedPubkey};

    fn key(byte: u8) -> TaggedPubkey {
        TaggedPubkey::new(SignatureScheme::Secp256k1, CURRENT_VERSION, vec![byte; 33]).unwrap()
    }

    fn validator(byte: u8) -> ValidatorEntry {
        let mut entry = ValidatorEntry::new(key(byte), [byte; 33], 0, 0);
        entry.status = ValidatorStatus::Active;
        entry
    }

    #[test]
    fn manifest_hash_is_independent_of_input_order() {
        let left = GenesisManifest::new(
            7,
            vec![validator(2), validator(1)],
            vec![
                GenesisAllocation {
                    recipient: key(4),
                    amount: 4,
                },
                GenesisAllocation {
                    recipient: key(3),
                    amount: 3,
                },
            ],
        )
        .unwrap();
        let right = GenesisManifest::new(
            7,
            vec![validator(1), validator(2)],
            vec![
                GenesisAllocation {
                    recipient: key(3),
                    amount: 3,
                },
                GenesisAllocation {
                    recipient: key(4),
                    amount: 4,
                },
            ],
        )
        .unwrap();
        assert_eq!(left.hash(), right.hash());
    }

    #[test]
    fn manifest_hash_binds_validator_and_allocation() {
        let manifest = GenesisManifest::new(
            7,
            vec![validator(1)],
            vec![GenesisAllocation {
                recipient: key(3),
                amount: 3,
            }],
        )
        .unwrap();
        let changed_validator = GenesisManifest::new(
            7,
            vec![validator(2)],
            vec![GenesisAllocation {
                recipient: key(3),
                amount: 3,
            }],
        )
        .unwrap();
        let changed_amount = GenesisManifest::new(
            7,
            vec![validator(1)],
            vec![GenesisAllocation {
                recipient: key(3),
                amount: 4,
            }],
        )
        .unwrap();
        assert_ne!(manifest.hash(), changed_validator.hash());
        assert_ne!(manifest.hash(), changed_amount.hash());
    }
}
