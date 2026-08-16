//! Versioned escrow for NativeCoin-backed validator-admission proposals.
//!
//! `GovernanceState` and `ValidatorSet` are long-lived Borsh consensus objects.  Adding pending
//! bond fields to either would silently change their persisted encoding.  This independent
//! singleton therefore carries the value which has left a funder's NativeCoin UTXOs while a
//! validator-set proposal is being voted on.  At the scheduled epoch boundary the value moves
//! atomically into `ValidatorSet::stake`; a rejected or revoked proposal may be refunded only to
//! its recorded funder.

use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::error::{PokerL1Error, PokerL1Result};
use crate::governance::{ProposalStatus, ValidatorAddition};
use crate::object_model::{Object, ObjectID, Ownership};
use crate::storage::ObjectBackend;
use crate::{Address, ChainId};

/// Reserved type tag for pending validator-admission bonds.
pub const VALIDATOR_BOND_ESCROW_OBJECT_TYPE: &str = "0x2::governance::ValidatorBondEscrowV1";

/// Dedicated singleton identity.  Existing system singleton slots end at `MAX - 5`.
pub const VALIDATOR_BOND_ESCROW_OBJECT_ID: ObjectID = ObjectID::new([0u8; 20], u64::MAX - 6);

/// Whether an object occupies the reserved validator-bond singleton slot.
#[must_use]
pub fn is_validator_bond_escrow_object(object: &Object) -> bool {
    object.id == VALIDATOR_BOND_ESCROW_OBJECT_ID
        && object.object_type == VALIDATOR_BOND_ESCROW_OBJECT_TYPE
}

/// One funded addition held while its governance proposal is unresolved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct PendingValidatorBond {
    /// Governance proposal that owns this bond.
    pub proposal_id: u64,
    /// Validator identity to which the stake is assigned after activation.
    pub validator: crate::signature::TaggedPubkey,
    /// Native ZCN amount held in escrow.
    pub amount: u64,
    /// Address that supplied the NativeCoin inputs and is eligible for a refund.
    pub refund_address: Address,
}

/// Canonical state of all unresolved NativeCoin-backed validator-admission proposals.
#[derive(
    Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct ValidatorBondEscrow {
    /// Proposal ID to its exact funded validator additions.
    pub pending: BTreeMap<u64, Vec<PendingValidatorBond>>,
}

impl ValidatorBondEscrow {
    /// Sum every value currently locked in pending admission proposals.
    pub fn total_amount(&self) -> PokerL1Result<u64> {
        self.pending
            .values()
            .flatten()
            .try_fold(0u64, |total, bond| {
                total.checked_add(bond.amount).ok_or_else(|| {
                    PokerL1Error::Other("pending validator bond escrow overflow".into())
                })
            })
    }

    /// Record the exact NativeCoin backing for a newly created proposal.
    pub fn insert_proposal(
        &mut self,
        proposal_id: u64,
        additions: &[ValidatorAddition],
        refund_address: Address,
    ) -> PokerL1Result<()> {
        if additions.is_empty() {
            return Err(PokerL1Error::Other(
                "bonded validator proposal must contain at least one addition".into(),
            ));
        }
        if self.pending.contains_key(&proposal_id) {
            return Err(PokerL1Error::Other(format!(
                "validator bond escrow already contains proposal {proposal_id}"
            )));
        }
        let mut bonds = Vec::with_capacity(additions.len());
        for addition in additions {
            if addition.stake == 0 {
                return Err(PokerL1Error::Other(
                    "validator bond escrow cannot record zero stake".into(),
                ));
            }
            bonds.push(PendingValidatorBond {
                proposal_id,
                validator: addition.pubkey.clone(),
                amount: addition.stake,
                refund_address,
            });
        }
        self.pending.insert(proposal_id, bonds);
        Ok(())
    }

    /// Verify that a passed proposal's additions exactly match its locked value.
    pub fn validate_activation(
        &self,
        proposal_id: u64,
        additions: &[ValidatorAddition],
    ) -> PokerL1Result<()> {
        let bonds = self.pending.get(&proposal_id).ok_or_else(|| {
            PokerL1Error::Other(format!(
                "validator-set proposal {proposal_id} has additions but no pending NativeCoin bond escrow"
            ))
        })?;
        if bonds.len() != additions.len() {
            return Err(PokerL1Error::Other(format!(
                "validator bond escrow count mismatch for proposal {proposal_id}"
            )));
        }
        for (bond, addition) in bonds.iter().zip(additions) {
            if bond.proposal_id != proposal_id
                || bond.validator != addition.pubkey
                || bond.amount != addition.stake
            {
                return Err(PokerL1Error::Other(format!(
                    "validator bond escrow contents do not match proposal {proposal_id}"
                )));
            }
        }
        Ok(())
    }

    /// Remove escrow only after the matching additions have been inserted into `ValidatorSet`.
    pub fn release_activated(
        &mut self,
        proposal_id: u64,
        additions: &[ValidatorAddition],
    ) -> PokerL1Result<u64> {
        self.validate_activation(proposal_id, additions)?;
        let bonds = self
            .pending
            .remove(&proposal_id)
            .expect("validated pending validator bond must exist");
        bonds.into_iter().try_fold(0u64, |total, bond| {
            total
                .checked_add(bond.amount)
                .ok_or_else(|| PokerL1Error::Other("activated validator bond sum overflow".into()))
        })
    }

    /// Remove a rejected/revoked proposal's escrow and return its refundable amount.
    pub fn claim_refund(
        &mut self,
        proposal_id: u64,
        claimant: Address,
        proposal_status: ProposalStatus,
    ) -> PokerL1Result<u64> {
        if !matches!(
            proposal_status,
            ProposalStatus::Rejected | ProposalStatus::Revoked
        ) {
            return Err(PokerL1Error::Other(
                "validator bond refund is available only after proposal rejection or revocation"
                    .into(),
            ));
        }
        let bonds = self.pending.get(&proposal_id).ok_or_else(|| {
            PokerL1Error::Other(format!(
                "no pending validator bond for proposal {proposal_id}"
            ))
        })?;
        if bonds.is_empty() || bonds.iter().any(|bond| bond.refund_address != claimant) {
            return Err(PokerL1Error::Other(
                "only the recorded validator-bond funder may claim this refund".into(),
            ));
        }
        let bonds = self
            .pending
            .remove(&proposal_id)
            .expect("validator bond checked above must exist");
        bonds.into_iter().try_fold(0u64, |total, bond| {
            total
                .checked_add(bond.amount)
                .ok_or_else(|| PokerL1Error::Other("validator bond refund sum overflow".into()))
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
struct PersistedValidatorBondEscrow {
    chain_id: ChainId,
    escrow: ValidatorBondEscrow,
}

/// Encode a versioned pending-bond singleton.
pub fn validator_bond_escrow_object(
    chain_id: ChainId,
    escrow: &ValidatorBondEscrow,
    version: u64,
) -> PokerL1Result<Object> {
    let mut object = Object::new(
        VALIDATOR_BOND_ESCROW_OBJECT_ID,
        Ownership::Immutable,
        VALIDATOR_BOND_ESCROW_OBJECT_TYPE,
        borsh::to_vec(&PersistedValidatorBondEscrow {
            chain_id,
            escrow: escrow.clone(),
        })?,
        None,
    );
    object.version = version;
    Ok(object)
}

/// Decode a pending-bond singleton and bind it to one chain namespace.
pub fn decode_validator_bond_escrow_object(
    object: &Object,
    expected_chain_id: ChainId,
) -> PokerL1Result<ValidatorBondEscrow> {
    if object.id != VALIDATOR_BOND_ESCROW_OBJECT_ID
        || object.object_type != VALIDATOR_BOND_ESCROW_OBJECT_TYPE
        || object.owner != Ownership::Immutable
        || object.assigned_validator.is_some()
    {
        return Err(PokerL1Error::Other(
            "invalid ValidatorBondEscrow singleton identity, type or ownership".into(),
        ));
    }
    let persisted: PersistedValidatorBondEscrow =
        borsh::from_slice(&object.data).map_err(|error| {
            PokerL1Error::Serialization(format!("decode ValidatorBondEscrow: {error}"))
        })?;
    if persisted.chain_id != expected_chain_id {
        return Err(PokerL1Error::Other(format!(
            "ValidatorBondEscrow chain_id {} does not match configured chain_id {expected_chain_id}",
            persisted.chain_id
        )));
    }
    // Validate aggregate arithmetic on read so a corrupt persisted map cannot evade supply
    // reconciliation through integer overflow.
    persisted.escrow.total_amount()?;
    Ok(persisted.escrow)
}

/// Validate the immutable singleton shape independently of a node's chain namespace.
///
/// `ObjectStore` uses this at its trusted system-object boundary.  Consensus callers must still
/// call [`decode_validator_bond_escrow_object`] with their configured chain ID before using the
/// contents.
pub fn validate_validator_bond_escrow_object(object: &Object) -> PokerL1Result<()> {
    if !is_validator_bond_escrow_object(object)
        || object.owner != Ownership::Immutable
        || object.assigned_validator.is_some()
    {
        return Err(PokerL1Error::Other(
            "invalid ValidatorBondEscrow singleton identity, type or ownership".into(),
        ));
    }
    let persisted: PersistedValidatorBondEscrow =
        borsh::from_slice(&object.data).map_err(|error| {
            PokerL1Error::Serialization(format!("decode ValidatorBondEscrow: {error}"))
        })?;
    persisted.escrow.total_amount()?;
    Ok(())
}

/// Load the optional V1 escrow singleton.  Its absence is valid on chains which have never used
/// the V2 bonded-admission contract.
pub fn read_validator_bond_escrow<B: ObjectBackend>(
    object_db: &B,
    chain_id: ChainId,
) -> PokerL1Result<Option<(ValidatorBondEscrow, u64)>> {
    match object_db.read(&VALIDATOR_BOND_ESCROW_OBJECT_ID) {
        Ok(object) => Ok(Some((
            decode_validator_bond_escrow_object(&object, chain_id)?,
            object.version,
        ))),
        Err(PokerL1Error::ObjectNotFound(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

/// Create the singleton on first bonded proposal, or replace the previously decoded version.
pub fn write_validator_bond_escrow<B: ObjectBackend>(
    object_db: &mut B,
    chain_id: ChainId,
    previous_version: Option<u64>,
    escrow: &ValidatorBondEscrow,
) -> PokerL1Result<()> {
    match previous_version {
        Some(version) => {
            let next_version = version.checked_add(1).ok_or_else(|| {
                PokerL1Error::Other("ValidatorBondEscrow object version overflow".into())
            })?;
            object_db.replace_system_object(validator_bond_escrow_object(
                chain_id,
                escrow,
                next_version,
            )?)
        }
        None => object_db.system_create(validator_bond_escrow_object(chain_id, escrow, 0)?),
    }
}

/// Sum pending admission escrow from an optional singleton for supply reconciliation.
pub fn pending_validator_bond_escrow<B: ObjectBackend>(
    object_db: &B,
    chain_id: ChainId,
) -> PokerL1Result<u64> {
    Ok(read_validator_bond_escrow(object_db, chain_id)?
        .map(|(escrow, _)| escrow.total_amount())
        .transpose()?
        .unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::VRF_PUBKEY_SIZE;
    use crate::signature::tagged_pubkey::{SignatureScheme, encode_tag};

    fn pubkey(seed: u8) -> crate::signature::TaggedPubkey {
        crate::signature::TaggedPubkey {
            tag: encode_tag(SignatureScheme::Secp256k1, 1),
            raw: vec![seed; 33],
        }
    }

    fn addition(seed: u8, amount: u64) -> ValidatorAddition {
        ValidatorAddition {
            pubkey: pubkey(seed),
            vrf_pubkey: [seed; VRF_PUBKEY_SIZE],
            stake: amount,
        }
    }

    #[test]
    fn activation_requires_exact_proposal_backing_and_moves_escrow_once() {
        let mut escrow = ValidatorBondEscrow::default();
        let additions = vec![addition(1, 40), addition(2, 60)];
        escrow.insert_proposal(7, &additions, [0xAA; 20]).unwrap();
        assert_eq!(escrow.total_amount().unwrap(), 100);
        escrow.validate_activation(7, &additions).unwrap();
        assert_eq!(escrow.release_activated(7, &additions).unwrap(), 100);
        assert_eq!(escrow.total_amount().unwrap(), 0);
        assert!(escrow.release_activated(7, &additions).is_err());
    }

    #[test]
    fn refund_requires_terminal_status_and_recorded_funder() {
        let mut escrow = ValidatorBondEscrow::default();
        let additions = vec![addition(3, 75)];
        escrow.insert_proposal(9, &additions, [0xBB; 20]).unwrap();
        assert!(
            escrow
                .claim_refund(9, [0xBB; 20], ProposalStatus::Voting)
                .is_err()
        );
        assert!(
            escrow
                .claim_refund(9, [0xCC; 20], ProposalStatus::Rejected)
                .is_err()
        );
        assert_eq!(
            escrow
                .claim_refund(9, [0xBB; 20], ProposalStatus::Rejected)
                .unwrap(),
            75
        );
    }

    #[test]
    fn object_roundtrip_binds_chain_and_rejects_wrong_namespace() {
        let mut escrow = ValidatorBondEscrow::default();
        escrow
            .insert_proposal(1, &[addition(4, 8)], [0xDD; 20])
            .unwrap();
        let object = validator_bond_escrow_object(42, &escrow, 3).unwrap();
        assert_eq!(
            decode_validator_bond_escrow_object(&object, 42).unwrap(),
            escrow
        );
        assert!(decode_validator_bond_escrow_object(&object, 43).is_err());
    }
}
