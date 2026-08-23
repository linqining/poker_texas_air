//! Finalized-receipt binding for the direct Texas tagged AIR.
//!
//! A STARK archive proves the relation encoded by its AIR, but the archive alone does not
//! establish that its state images came from a canonical chain state.  This module defines the
//! small immutable receipt ABI that a finality/light-client layer must authenticate and then bind
//! to the archive.  It intentionally contains no RPC client and no transaction replay code.

#![allow(missing_docs)]

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};
use poker_l1::object_model::{MerklePath, SparseMerkleTree, TREE_DEPTH};

use crate::error::{TexasAirError, TexasAirResult};
use crate::texas_canonical::CanonicalTransitionKind;
use crate::texas_canonical_air::ArchivedCanonicalTaggedProof;
use crate::texas_tagged::ArchivedTaggedTexasProof;

/// Receipt ABI version.  Changing any field encoding requires a new version and domain.
pub const TEXAS_RECEIPT_VERSION: u8 = 2;
/// Canonical AIR receipt ABI. Version 5 adds the fixed-width first/last
/// transition-kind selectors alongside the state-object key and epoch; it
/// must never be decoded as an earlier root-only layout.
pub const CANONICAL_TEXAS_RECEIPT_VERSION: u8 = 5;
pub const TEXAS_RECEIPT_PATH_DOMAIN: &[u8] = b"zchain.texas.transition-receipt.path.v2";
pub const TEXAS_RECEIPT_VALUE_DOMAIN: &[u8] = b"zchain.texas.transition-receipt.value.v2";

/// Public metadata that the state kernel binds to a transition proof.
///
/// This is deliberately separate from the legacy receipt ABI so callers can migrate
/// without silently treating an old receipt as an authenticated no-replay statement.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TexasReceiptStatement {
    pub circuit_id: [u8; 32],
    pub manifest_digest: [u8; 32],
    pub effect_kind: u8,
    pub authority_kind: u8,
    pub authority: [u8; 32],
    pub transition_commitment: [u8; 32],
    pub nullifier: [u8; 32],
    pub pre_state_root: [u8; 32],
    pub post_state_root: [u8; 32],
    pub lifecycle_root: [u8; 32],
    pub overlay_root: [u8; 32],
}

impl TexasReceiptStatement {
    pub fn validate(&self) -> TexasAirResult<()> {
        for (name, value) in [
            ("circuit_id", self.circuit_id),
            ("manifest_digest", self.manifest_digest),
            ("transition_commitment", self.transition_commitment),
            ("nullifier", self.nullifier),
            ("pre_state_root", self.pre_state_root),
            ("post_state_root", self.post_state_root),
            ("lifecycle_root", self.lifecycle_root),
            ("overlay_root", self.overlay_root),
        ] {
            if value == [0; 32] {
                return Err(TexasAirError::SpecViolation(format!(
                    "Texas receipt statement {name} must be non-zero"
                )));
            }
        }
        if self.effect_kind == 0 {
            return Err(TexasAirError::SpecViolation(
                "Texas receipt effect kind must be non-zero".into(),
            ));
        }
        if self.authority_kind > 3 {
            return Err(TexasAirError::SpecViolation(
                "Texas receipt authority kind is outside the registry".into(),
            ));
        }
        if self.authority_kind == 3 {
            if self.authority != [0; 32] {
                return Err(TexasAirError::SpecViolation(
                    "permissionless receipt must have zero authority".into(),
                ));
            }
        } else if self.authority == [0; 32] {
            return Err(TexasAirError::SpecViolation(
                "actor/operator receipt must bind a non-zero authority".into(),
            ));
        }
        Ok(())
    }
}

/// Historical state-root proof for one immutable receipt mapping entry.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TexasReceiptInclusionProof {
    pub finalized_block_hash: [u8; 32],
    pub finalized_block_height: u64,
    pub state_root: [u8; 32],
    pub receipt_key: [u8; 32],
    pub leaf_value: [u8; 32],
    pub siblings: Vec<[u8; 32]>,
    /// One bit per sibling: zero means current hash is left, one means right.
    pub directions: Vec<bool>,
    pub confirmations: u64,
}

/// Inclusion proof using the production `poker_l1` sparse-Merkle encoding.
///
/// The receipt mapping is intentionally represented as a 32-byte value here: the state
/// kernel stores `TexasTransitionReceipt::receipt_value` as the immutable mapping value.
/// Unlike [`TexasReceiptInclusionProof`], this type does not carry caller-selected
/// directions or a custom hash domain; key bits and the chain's canonical SMT implementation
/// determine both.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TexasL1ReceiptInclusionProof {
    pub finalized_block_hash: [u8; 32],
    pub finalized_block_height: u64,
    pub state_root: [u8; 32],
    pub receipt_key: [u8; 32],
    pub path: MerklePath,
    pub confirmations: u64,
}

impl TexasL1ReceiptInclusionProof {
    fn validate_shape(&self) -> TexasAirResult<()> {
        if self.finalized_block_hash == [0; 32]
            || self.state_root == [0; 32]
            || self.receipt_key == [0; 32]
        {
            return Err(TexasAirError::ConsensusAnchor(
                "L1 receipt inclusion proof contains a zero identifier".into(),
            ));
        }
        if self.path.is_empty_leaf || self.path.siblings.len() != TREE_DEPTH as usize {
            return Err(TexasAirError::ConsensusAnchor(
                "L1 receipt inclusion path is not a 256-level non-empty proof".into(),
            ));
        }
        Ok(())
    }
}

impl TexasReceiptInclusionProof {
    fn validate_shape(&self) -> TexasAirResult<()> {
        if self.finalized_block_hash == [0; 32]
            || self.state_root == [0; 32]
            || self.receipt_key == [0; 32]
            || self.leaf_value == [0; 32]
        {
            return Err(TexasAirError::ConsensusAnchor(
                "receipt inclusion proof contains a zero identifier".into(),
            ));
        }
        if self.siblings.len() != self.directions.len() {
            return Err(TexasAirError::ConsensusAnchor(
                "receipt inclusion path length does not match directions".into(),
            ));
        }
        Ok(())
    }

    fn root(&self) -> [u8; 32] {
        let mut current = hash_parts(&[
            TEXAS_RECEIPT_PATH_DOMAIN,
            &self.receipt_key,
            &self.leaf_value,
        ]);
        for (sibling, right) in self.siblings.iter().zip(&self.directions) {
            current = if *right {
                hash_parts(&[TEXAS_RECEIPT_PATH_DOMAIN, sibling, &current])
            } else {
                hash_parts(&[TEXAS_RECEIPT_PATH_DOMAIN, &current, sibling])
            };
        }
        current
    }
}

/// Receipt that has crossed the finality boundary and can be used for admission.
///
/// Fields are private by design: callers must obtain this value from
/// [`authenticate_receipt`], never by casting a prover-supplied receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedTexasReceipt {
    receipt: TexasTransitionReceipt,
    statement: TexasReceiptStatement,
    inclusion: TexasReceiptInclusionProof,
    l1_inclusion: Option<TexasL1ReceiptInclusionProof>,
}

/// Public metadata for the heterogeneous canonical transition AIR.
///
/// This statement intentionally uses image commitments rather than pretending that an
/// opaque state-root field is a proof of the complete state preimage.  The chain receipt
/// authenticates these commitments; the canonical AIR authenticates the transition shape.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CanonicalReceiptStatement {
    pub circuit_id: [u8; 32],
    pub manifest_digest: [u8; 32],
    pub effect_kind: u8,
    pub authority_kind: u8,
    pub authority: [u8; 32],
    pub table_id: u64,
    pub first_hand_id: u32,
    pub last_hand_id: u32,
    pub first_call_seq: u32,
    pub last_call_seq: u32,
    pub transition_count: u16,
    pub first_transition_kind: u8,
    pub last_transition_kind: u8,
    pub reveal_timeout_cascade_count: u8,
    pub reveal_timeout_cascade_schedule:
        [u8; crate::texas_canonical_air::MAX_REVEAL_TIMEOUT_CASCADE_KICKS],
    pub batch_digest: [u8; 32],
    pub pre_state_commitment: [u8; 32],
    pub post_state_commitment: [u8; 32],
    pub pre_state_root: [u8; 32],
    pub post_state_root: [u8; 32],
    pub pre_lifecycle_root: [u8; 32],
    pub post_lifecycle_root: [u8; 32],
    pub pre_overlay_root: [u8; 32],
    pub post_overlay_root: [u8; 32],
    pub pre_settlement_commitment: [u8; 32],
    pub post_settlement_commitment: [u8; 32],
    pub pre_custody_commitment: [u8; 32],
    pub post_custody_commitment: [u8; 32],
    /// Immutable L1 object key holding the fixed-width state commitment.
    pub state_object_key: [u8; 32],
    /// Versioned ABI for the fixed-width state-object value.
    pub state_opening_epoch: u32,
}

impl CanonicalReceiptStatement {
    pub fn validate(&self) -> TexasAirResult<()> {
        for (name, value) in [
            ("circuit_id", self.circuit_id),
            ("manifest_digest", self.manifest_digest),
            ("batch_digest", self.batch_digest),
            ("pre_state_commitment", self.pre_state_commitment),
            ("post_state_commitment", self.post_state_commitment),
            ("pre_state_root", self.pre_state_root),
            ("post_state_root", self.post_state_root),
            ("pre_lifecycle_root", self.pre_lifecycle_root),
            ("post_lifecycle_root", self.post_lifecycle_root),
            ("pre_overlay_root", self.pre_overlay_root),
            ("post_overlay_root", self.post_overlay_root),
            ("pre_settlement_commitment", self.pre_settlement_commitment),
            (
                "post_settlement_commitment",
                self.post_settlement_commitment,
            ),
            ("pre_custody_commitment", self.pre_custody_commitment),
            ("post_custody_commitment", self.post_custody_commitment),
            ("state_object_key", self.state_object_key),
        ] {
            if value == [0; 32] {
                return Err(TexasAirError::SpecViolation(format!(
                    "canonical receipt statement {name} must be non-zero"
                )));
            }
        }
        if self.effect_kind == 0 || self.transition_count == 0 {
            return Err(TexasAirError::SpecViolation(
                "canonical receipt statement has an empty effect or batch".into(),
            ));
        }
        if self.first_transition_kind > CanonicalTransitionKind::RevealTimeoutKick as u8
            || self.last_transition_kind > CanonicalTransitionKind::RevealTimeoutKick as u8
        {
            return Err(TexasAirError::SpecViolation(
                "canonical receipt transition kind is outside the ABI".into(),
            ));
        }
        if self.state_opening_epoch == 0 {
            return Err(TexasAirError::SpecViolation(
                "canonical receipt statement has no fixed-width state-object epoch".into(),
            ));
        }
        if self.authority_kind > 3 {
            return Err(TexasAirError::SpecViolation(
                "canonical receipt authority kind is outside the registry".into(),
            ));
        }
        if self.authority_kind == 3 {
            if self.authority != [0; 32] {
                return Err(TexasAirError::SpecViolation(
                    "permissionless canonical receipt must have zero authority".into(),
                ));
            }
        } else if self.authority == [0; 32] {
            return Err(TexasAirError::SpecViolation(
                "canonical actor/operator receipt must bind authority".into(),
            ));
        }
        Ok(())
    }
}

/// Immutable finalized receipt for one canonical AIR batch.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CanonicalTransitionReceipt {
    pub version: u8,
    pub table_id: u64,
    pub first_hand_id: u32,
    pub last_hand_id: u32,
    pub first_call_seq: u32,
    pub last_call_seq: u32,
    pub transition_count: u16,
    pub first_transition_kind: u8,
    pub last_transition_kind: u8,
    pub reveal_timeout_cascade_count: u8,
    pub reveal_timeout_cascade_schedule:
        [u8; crate::texas_canonical_air::MAX_REVEAL_TIMEOUT_CASCADE_KICKS],
    pub batch_digest: [u8; 32],
    pub pre_state_commitment: [u8; 32],
    pub post_state_commitment: [u8; 32],
    pub pre_state_root: [u8; 32],
    pub post_state_root: [u8; 32],
    pub pre_lifecycle_root: [u8; 32],
    pub post_lifecycle_root: [u8; 32],
    pub pre_overlay_root: [u8; 32],
    pub post_overlay_root: [u8; 32],
    pub pre_settlement_commitment: [u8; 32],
    pub post_settlement_commitment: [u8; 32],
    pub pre_custody_commitment: [u8; 32],
    pub post_custody_commitment: [u8; 32],
    /// Immutable L1 object key holding the table's fixed-width state leaf.
    pub state_object_key: [u8; 32],
    /// Versioned state-leaf layout expected by the canonical proof.
    pub state_opening_epoch: u32,
    pub block_height: u64,
    pub block_hash: [u8; 32],
    pub receipt_key: [u8; 32],
    pub receipt_value: [u8; 32],
}

impl CanonicalTransitionReceipt {
    pub fn validate(&self) -> TexasAirResult<()> {
        if self.version != CANONICAL_TEXAS_RECEIPT_VERSION
            || self.transition_count == 0
            || self.first_transition_kind > CanonicalTransitionKind::RevealTimeoutKick as u8
            || self.last_transition_kind > CanonicalTransitionKind::RevealTimeoutKick as u8
            || self.block_hash == [0; 32]
            || self.receipt_key == [0; 32]
        {
            return Err(TexasAirError::SpecViolation(
                "invalid canonical transition receipt header".into(),
            ));
        }
        for (name, value) in [
            ("batch_digest", self.batch_digest),
            ("pre_state_commitment", self.pre_state_commitment),
            ("post_state_commitment", self.post_state_commitment),
            ("pre_state_root", self.pre_state_root),
            ("post_state_root", self.post_state_root),
            ("pre_lifecycle_root", self.pre_lifecycle_root),
            ("post_lifecycle_root", self.post_lifecycle_root),
            ("pre_overlay_root", self.pre_overlay_root),
            ("post_overlay_root", self.post_overlay_root),
            ("pre_settlement_commitment", self.pre_settlement_commitment),
            (
                "post_settlement_commitment",
                self.post_settlement_commitment,
            ),
            ("pre_custody_commitment", self.pre_custody_commitment),
            ("post_custody_commitment", self.post_custody_commitment),
            ("state_object_key", self.state_object_key),
        ] {
            if value == [0; 32] {
                return Err(TexasAirError::SpecViolation(format!(
                    "canonical transition receipt {name} must be non-zero"
                )));
            }
        }
        if self.state_opening_epoch == 0 {
            return Err(TexasAirError::SpecViolation(
                "canonical transition receipt has no fixed-width state-object epoch".into(),
            ));
        }
        Ok(())
    }

    pub fn value_digest_with_statement(&self, statement: &CanonicalReceiptStatement) -> [u8; 32] {
        let mut receipt = self.clone();
        receipt.receipt_value = [0; 32];
        let receipt_bytes = borsh::to_vec(&receipt).expect("canonical receipt ABI is serializable");
        let statement_bytes =
            borsh::to_vec(statement).expect("canonical statement is serializable");
        hash_parts(&[TEXAS_RECEIPT_VALUE_DOMAIN, &receipt_bytes, &statement_bytes])
    }
}

/// Finality-authenticated wrapper for a canonical AIR receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedCanonicalTexasReceipt {
    receipt: CanonicalTransitionReceipt,
    statement: CanonicalReceiptStatement,
    inclusion: TexasL1ReceiptInclusionProof,
}

impl AuthenticatedCanonicalTexasReceipt {
    pub fn receipt(&self) -> &CanonicalTransitionReceipt {
        &self.receipt
    }

    pub fn statement(&self) -> &CanonicalReceiptStatement {
        &self.statement
    }

    pub fn inclusion(&self) -> &TexasL1ReceiptInclusionProof {
        &self.inclusion
    }

    /// Verify the canonical AIR and bind its public scope for audit tooling.
    ///
    /// This intentionally does not advance a production head: the canonical
    /// AIR still leaves timeout cascades, settlement, and the Ristretto
    /// protocol equations outside the circuit.
    pub fn verify_canonical_proof(
        &self,
        archive: &ArchivedCanonicalTaggedProof,
    ) -> TexasAirResult<()> {
        crate::texas_canonical_air::verify_canonical_tagged_proof(archive)?;
        bind_canonical_proof_to_receipt(archive, &self.receipt)
    }

    /// Production admission for the canonical AIR.
    ///
    /// The structural verifier above remains useful for audit and regression
    /// tests, but accepting it as a head-changing transition would turn the
    /// unproven VM/crypto relations into host trust.  Keep this API explicitly
    /// fail-closed until those relations are composed.
    pub fn admit_canonical_proof(
        &self,
        archive: &ArchivedCanonicalTaggedProof,
    ) -> TexasAirResult<()> {
        self.verify_canonical_proof(archive)?;
        Err(TexasAirError::HostZeroAdmissionIncomplete(
            "canonical AIR does not yet prove complete Texas VM timeout, settlement, or Ristretto semantics".into(),
        ))
    }

    /// Fail closed for production admission of the canonical/opening
    /// composition.
    ///
    /// The archive must carry the complete `Borsh(image) -> Blake2b image
    /// commitment -> L1 SMT root` chain.  The canonical AIR binds its fixed
    /// 841-limb state-image projection to that byte statement, but the full VM
    /// timeout, settlement, deck, and Ristretto relations are not yet complete.
    /// Accepting the archive as a head-changing host-zero transition would
    /// therefore turn those missing relations into host trust.  This method
    /// deliberately remains unavailable after auditing the composed proofs.
    pub fn admit_canonical_proof_with_state_openings(
        &self,
        archive: &crate::canonical_state_opening::ArchivedCanonicalStateImageOpeningProof,
    ) -> TexasAirResult<()> {
        crate::canonical_state_opening::verify_canonical_batch_with_state_image_openings(archive)?;
        bind_canonical_proof_to_receipt(&archive.opening.canonical, &self.receipt)?;
        Err(TexasAirError::HostZeroAdmissionIncomplete(
            "complete Texas VM semantics and Ristretto crypto AIR are not yet composed into this proof".into(),
        ))
    }

    /// Verify a reveal-dependent state-image composition without VM replay.
    /// Admission remains fail-closed until the terminal continuation and
    /// complete Texas/Ristretto relations are composed.
    pub fn verify_canonical_proof_with_state_image_and_reveal_opening(
        &self,
        archive: &crate::canonical_state_opening::ArchivedCanonicalStateImageRevealOpeningProof,
    ) -> TexasAirResult<()> {
        crate::canonical_state_opening::verify_canonical_batch_with_state_image_and_reveal_opening(
            archive,
        )?;
        bind_canonical_proof_to_receipt(&archive.opening.opening.canonical, &self.receipt)
    }

    /// Production admission for the reveal-dependent composition.  This
    /// explicit gate prevents callers from treating the partial composition
    /// as a complete host-zero Texas proof.
    pub fn admit_canonical_proof_with_state_image_and_reveal_opening(
        &self,
        archive: &crate::canonical_state_opening::ArchivedCanonicalStateImageRevealOpeningProof,
    ) -> TexasAirResult<()> {
        self.verify_canonical_proof_with_state_image_and_reveal_opening(archive)?;
        Err(TexasAirError::HostZeroAdmissionIncomplete(
            "complete Texas terminal continuation, settlement, and Ristretto AIR are not yet composed".into(),
        ))
    }
}

impl AuthenticatedTexasReceipt {
    pub fn receipt(&self) -> &TexasTransitionReceipt {
        &self.receipt
    }
    pub fn statement(&self) -> &TexasReceiptStatement {
        &self.statement
    }
    pub fn inclusion(&self) -> &TexasReceiptInclusionProof {
        &self.inclusion
    }

    /// Return the canonical `poker_l1` proof when this receipt crossed the L1 adapter.
    pub fn l1_inclusion(&self) -> Option<&TexasL1ReceiptInclusionProof> {
        self.l1_inclusion.as_ref()
    }

    /// Verify the STARK and bind it to this finalized receipt, without VM replay.
    pub fn admit_tagged_proof(&self, archive: &ArchivedTaggedTexasProof) -> TexasAirResult<()> {
        crate::texas_tagged::verify_tagged_texas_proof(archive)?;
        bind_tagged_proof_to_receipt(archive, &self.receipt)?;
        if self.statement.transition_commitment != archive.batch_digest {
            return Err(TexasAirError::SpecViolation(
                "authenticated receipt statement is detached from the tagged proof batch".into(),
            ));
        }
        Ok(())
    }
}

fn hash_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Blake2bVar::new(32).expect("32-byte Blake2 digest");
    for part in parts {
        h.update(part);
    }
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).expect("fixed digest length");
    out
}

fn validate_statement_receipt_binding(
    receipt: &TexasTransitionReceipt,
    statement: &TexasReceiptStatement,
) -> TexasAirResult<()> {
    if statement.transition_commitment != receipt.batch_digest
        || statement.pre_state_root != receipt.pre_state_commitment
        || statement.post_state_root != receipt.post_state_commitment
        || statement.lifecycle_root != receipt.lifecycle_root
        || statement.overlay_root != receipt.overlay_root
    {
        return Err(TexasAirError::ConsensusAnchor(
            "receipt statement is detached from the authenticated transition roots".into(),
        ));
    }
    Ok(())
}

/// Immutable receipt emitted by the chain state kernel for one contiguous tagged batch.
///
/// `block_hash`, `block_height`, `receipt_key`, and `receipt_value` are opaque finality
/// material.  Their inclusion in a finalized state root must be checked by a light client or
/// consensus adapter before constructing an authenticated receipt binding.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TexasTransitionReceipt {
    pub version: u8,
    pub table_id: u64,
    pub hand_id: u32,
    pub first_call_seq: u32,
    pub last_call_seq: u32,
    pub transition_count: u16,
    pub batch_digest: [u8; 32],
    pub pre_state_commitment: [u8; 32],
    pub post_state_commitment: [u8; 32],
    pub lifecycle_root: [u8; 32],
    pub overlay_root: [u8; 32],
    pub rules_commitment: [u8; 32],
    pub block_height: u64,
    pub block_hash: [u8; 32],
    pub receipt_key: [u8; 32],
    pub receipt_value: [u8; 32],
}

impl TexasTransitionReceipt {
    /// Check only the receipt's local ABI and sequence invariants.
    pub fn validate(&self) -> TexasAirResult<()> {
        if self.version != TEXAS_RECEIPT_VERSION {
            return Err(TexasAirError::SpecViolation(
                "unsupported Texas transition receipt version".into(),
            ));
        }
        if self.transition_count == 0
            || self
                .first_call_seq
                .checked_add(u32::from(self.transition_count))
                != Some(self.last_call_seq)
        {
            return Err(TexasAirError::SpecViolation(
                "receipt sequence range is not contiguous".into(),
            ));
        }
        if self.block_hash == [0; 32] || self.receipt_key == [0; 32] {
            return Err(TexasAirError::SpecViolation(
                "receipt finality identifiers must be non-zero".into(),
            ));
        }
        for (name, value) in [
            ("batch_digest", self.batch_digest),
            ("pre_state_commitment", self.pre_state_commitment),
            ("post_state_commitment", self.post_state_commitment),
            ("lifecycle_root", self.lifecycle_root),
            ("overlay_root", self.overlay_root),
            ("rules_commitment", self.rules_commitment),
        ] {
            if value == [0; 32] {
                return Err(TexasAirError::SpecViolation(format!(
                    "Texas transition receipt {name} must be non-zero"
                )));
            }
        }
        Ok(())
    }

    /// Legacy receipt-only value digest.
    ///
    /// New state-kernel mappings must use [`Self::value_digest_with_statement`],
    /// otherwise the proof statement is not committed by the mapping value.
    pub fn value_digest(&self) -> [u8; 32] {
        let mut canonical = self.clone();
        canonical.receipt_value = [0; 32];
        let bytes = borsh::to_vec(&canonical).expect("receipt ABI is serializable");
        hash_parts(&[TEXAS_RECEIPT_VALUE_DOMAIN, &bytes])
    }

    /// Canonical mapping value including the complete proof statement.
    pub fn value_digest_with_statement(&self, statement: &TexasReceiptStatement) -> [u8; 32] {
        let mut canonical = self.clone();
        canonical.receipt_value = [0; 32];
        let receipt_bytes = borsh::to_vec(&canonical).expect("receipt ABI is serializable");
        let statement_bytes = borsh::to_vec(statement).expect("receipt statement is serializable");
        hash_parts(&[TEXAS_RECEIPT_VALUE_DOMAIN, &receipt_bytes, &statement_bytes])
    }
}

/// Cross the finality boundary for a receipt mapping entry.
///
/// This replaces transaction replay in admission. The caller supplies a proof obtained from
/// a light client or consensus adapter; this function checks the proof locally and returns a
/// private authenticated wrapper.
pub fn authenticate_receipt(
    receipt: TexasTransitionReceipt,
    statement: TexasReceiptStatement,
    inclusion: TexasReceiptInclusionProof,
    minimum_confirmations: u64,
) -> TexasAirResult<AuthenticatedTexasReceipt> {
    receipt.validate()?;
    statement.validate()?;
    inclusion.validate_shape()?;
    validate_statement_receipt_binding(&receipt, &statement)?;
    if minimum_confirmations == 0 || inclusion.confirmations < minimum_confirmations {
        return Err(TexasAirError::ConsensusAnchor(
            "receipt is not finalized to the required confirmation depth".into(),
        ));
    }
    let expected_value = receipt.value_digest_with_statement(&statement);
    if receipt.receipt_value != expected_value {
        return Err(TexasAirError::ConsensusAnchor(
            "receipt value is not the canonical statement-bound digest".into(),
        ));
    }
    if inclusion.finalized_block_hash != receipt.block_hash
        || inclusion.finalized_block_height != receipt.block_height
        || inclusion.receipt_key != receipt.receipt_key
        || inclusion.leaf_value != expected_value
    {
        return Err(TexasAirError::ConsensusAnchor(
            "receipt inclusion proof does not bind the receipt value or block".into(),
        ));
    }
    if inclusion.root() != inclusion.state_root {
        return Err(TexasAirError::ConsensusAnchor(
            "receipt inclusion path does not reach the finalized state root".into(),
        ));
    }
    Ok(AuthenticatedTexasReceipt {
        receipt,
        statement,
        inclusion,
        l1_inclusion: None,
    })
}

/// Authenticate a receipt against the actual `poker_l1` sparse-Merkle state-root encoding.
///
/// This is the production-facing variant of [`authenticate_receipt`].  The latter remains
/// available only for the legacy generic ABI and must not be used as a chain adapter.  The
/// caller still has to establish that `state_root`, block hash/height, and confirmation count
/// belong to the canonical finalized chain before calling this function.
pub fn authenticate_receipt_l1(
    receipt: TexasTransitionReceipt,
    statement: TexasReceiptStatement,
    inclusion: TexasL1ReceiptInclusionProof,
    minimum_confirmations: u64,
) -> TexasAirResult<AuthenticatedTexasReceipt> {
    receipt.validate()?;
    statement.validate()?;
    inclusion.validate_shape()?;
    validate_statement_receipt_binding(&receipt, &statement)?;
    if minimum_confirmations == 0 || inclusion.confirmations < minimum_confirmations {
        return Err(TexasAirError::ConsensusAnchor(
            "receipt is not finalized to the required confirmation depth".into(),
        ));
    }
    let expected_value = receipt.value_digest_with_statement(&statement);
    if receipt.receipt_value != expected_value {
        return Err(TexasAirError::ConsensusAnchor(
            "receipt value is not the canonical statement-bound digest".into(),
        ));
    }
    if inclusion.finalized_block_hash != receipt.block_hash
        || inclusion.finalized_block_height != receipt.block_height
        || inclusion.receipt_key != receipt.receipt_key
    {
        return Err(TexasAirError::ConsensusAnchor(
            "L1 receipt inclusion proof does not bind the receipt block or key".into(),
        ));
    }
    if !SparseMerkleTree::verify(
        &inclusion.state_root,
        &inclusion.receipt_key,
        Some(&receipt.receipt_value),
        &inclusion.path,
    ) {
        return Err(TexasAirError::ConsensusAnchor(
            "receipt inclusion path does not reach the finalized L1 state root".into(),
        ));
    }
    let leaf_value = receipt.receipt_value;
    Ok(AuthenticatedTexasReceipt {
        receipt,
        statement,
        inclusion: TexasReceiptInclusionProof {
            finalized_block_hash: inclusion.finalized_block_hash,
            finalized_block_height: inclusion.finalized_block_height,
            state_root: inclusion.state_root,
            receipt_key: inclusion.receipt_key,
            leaf_value,
            siblings: Vec::new(),
            directions: Vec::new(),
            confirmations: inclusion.confirmations,
        },
        l1_inclusion: Some(inclusion),
    })
}

/// Authenticate a canonical AIR receipt against the production L1 sparse-Merkle state root.
pub fn authenticate_canonical_receipt_l1(
    receipt: CanonicalTransitionReceipt,
    statement: CanonicalReceiptStatement,
    inclusion: TexasL1ReceiptInclusionProof,
    minimum_confirmations: u64,
) -> TexasAirResult<AuthenticatedCanonicalTexasReceipt> {
    receipt.validate()?;
    statement.validate()?;
    inclusion.validate_shape()?;
    if receipt.table_id != statement.table_id
        || receipt.first_hand_id != statement.first_hand_id
        || receipt.last_hand_id != statement.last_hand_id
        || receipt.first_call_seq != statement.first_call_seq
        || receipt.last_call_seq != statement.last_call_seq
        || receipt.transition_count != statement.transition_count
        || receipt.first_transition_kind != statement.first_transition_kind
        || receipt.last_transition_kind != statement.last_transition_kind
        || receipt.reveal_timeout_cascade_count != statement.reveal_timeout_cascade_count
        || receipt.reveal_timeout_cascade_schedule != statement.reveal_timeout_cascade_schedule
        || receipt.batch_digest != statement.batch_digest
        || receipt.pre_state_commitment != statement.pre_state_commitment
        || receipt.post_state_commitment != statement.post_state_commitment
        || receipt.pre_state_root != statement.pre_state_root
        || receipt.post_state_root != statement.post_state_root
        || receipt.pre_lifecycle_root != statement.pre_lifecycle_root
        || receipt.post_lifecycle_root != statement.post_lifecycle_root
        || receipt.pre_overlay_root != statement.pre_overlay_root
        || receipt.post_overlay_root != statement.post_overlay_root
        || receipt.pre_settlement_commitment != statement.pre_settlement_commitment
        || receipt.post_settlement_commitment != statement.post_settlement_commitment
        || receipt.pre_custody_commitment != statement.pre_custody_commitment
        || receipt.post_custody_commitment != statement.post_custody_commitment
        || receipt.state_object_key != statement.state_object_key
        || receipt.state_opening_epoch != statement.state_opening_epoch
    {
        return Err(TexasAirError::ConsensusAnchor(
            "canonical receipt statement is detached from receipt scope".into(),
        ));
    }
    if minimum_confirmations == 0 || inclusion.confirmations < minimum_confirmations {
        return Err(TexasAirError::ConsensusAnchor(
            "canonical receipt is not finalized to the required confirmation depth".into(),
        ));
    }
    let expected_value = receipt.value_digest_with_statement(&statement);
    if receipt.receipt_value != expected_value {
        return Err(TexasAirError::ConsensusAnchor(
            "canonical receipt value is not statement-bound".into(),
        ));
    }
    if inclusion.finalized_block_hash != receipt.block_hash
        || inclusion.finalized_block_height != receipt.block_height
        || inclusion.receipt_key != receipt.receipt_key
    {
        return Err(TexasAirError::ConsensusAnchor(
            "canonical receipt inclusion does not bind its block or key".into(),
        ));
    }
    if !SparseMerkleTree::verify(
        &inclusion.state_root,
        &inclusion.receipt_key,
        Some(&receipt.receipt_value),
        &inclusion.path,
    ) {
        return Err(TexasAirError::ConsensusAnchor(
            "canonical receipt inclusion path does not reach the finalized state root".into(),
        ));
    }
    Ok(AuthenticatedCanonicalTexasReceipt {
        receipt,
        statement,
        inclusion,
    })
}

/// Bind a finalized receipt to a direct tagged proof archive.
///
/// This function is intentionally narrower than finality verification: it proves that the
/// finality layer's already-authenticated receipt describes exactly the proof scope.  Callers
/// must verify the receipt's historical mapping inclusion at `block_height` before invoking it.
pub fn bind_tagged_proof_to_receipt(
    archive: &ArchivedTaggedTexasProof,
    receipt: &TexasTransitionReceipt,
) -> TexasAirResult<()> {
    receipt.validate()?;
    if archive.table_id != receipt.table_id
        || archive.hand_id != receipt.hand_id
        || archive.first_call_seq != receipt.first_call_seq
        || archive.last_call_seq != receipt.last_call_seq
        || archive.transition_count != receipt.transition_count
        || archive.batch_digest != receipt.batch_digest
        || archive.pre_state_commitment != receipt.pre_state_commitment
        || archive.post_state_commitment != receipt.post_state_commitment
    {
        return Err(TexasAirError::SpecViolation(
            "Texas proof archive does not match finalized transition receipt".into(),
        ));
    }
    Ok(())
}

/// Bind every canonical archive scope field to an already-authenticated receipt.
pub fn bind_canonical_proof_to_receipt(
    archive: &ArchivedCanonicalTaggedProof,
    receipt: &CanonicalTransitionReceipt,
) -> TexasAirResult<()> {
    receipt.validate()?;
    if archive.table_id != receipt.table_id
        || archive.first_hand_id != receipt.first_hand_id
        || archive.last_hand_id != receipt.last_hand_id
        || archive.first_call_seq != receipt.first_call_seq
        || archive.last_call_seq != receipt.last_call_seq
        || archive.transition_count != receipt.transition_count
        || archive.first_transition_kind != receipt.first_transition_kind
        || archive.last_transition_kind != receipt.last_transition_kind
        || archive.reveal_timeout_cascade_count != receipt.reveal_timeout_cascade_count
        || archive.reveal_timeout_cascade_schedule != receipt.reveal_timeout_cascade_schedule
        || archive.batch_digest != receipt.batch_digest
        || archive.pre_state_commitment != receipt.pre_state_commitment
        || archive.post_state_commitment != receipt.post_state_commitment
        || archive.pre_state_root != receipt.pre_state_root
        || archive.post_state_root != receipt.post_state_root
        || archive.pre_lifecycle_root != receipt.pre_lifecycle_root
        || archive.post_lifecycle_root != receipt.post_lifecycle_root
        || archive.pre_overlay_root != receipt.pre_overlay_root
        || archive.post_overlay_root != receipt.post_overlay_root
        || archive.pre_settlement_commitment != receipt.pre_settlement_commitment
        || archive.post_settlement_commitment != receipt.post_settlement_commitment
        || archive.pre_custody_commitment != receipt.pre_custody_commitment
        || archive.post_custody_commitment != receipt.post_custody_commitment
        || archive.state_object_key != receipt.state_object_key
        || archive.state_opening_epoch != receipt.state_opening_epoch
    {
        return Err(TexasAirError::SpecViolation(
            "canonical proof archive does not match finalized receipt".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::texas_tagged::{
        TexasAction, TexasSeatImage, TexasStateImage, TexasTransitionWitness,
        prove_tagged_texas_batch,
    };

    fn receipt_for(archive: &ArchivedTaggedTexasProof) -> TexasTransitionReceipt {
        TexasTransitionReceipt {
            version: TEXAS_RECEIPT_VERSION,
            table_id: archive.table_id,
            hand_id: archive.hand_id,
            first_call_seq: archive.first_call_seq,
            last_call_seq: archive.last_call_seq,
            transition_count: archive.transition_count,
            batch_digest: archive.batch_digest,
            pre_state_commitment: archive.pre_state_commitment,
            post_state_commitment: archive.post_state_commitment,
            lifecycle_root: [30; 32],
            overlay_root: [31; 32],
            rules_commitment: [7; 32],
            block_height: 10,
            block_hash: [8; 32],
            receipt_key: [9; 32],
            receipt_value: [10; 32],
        }
    }

    fn statement() -> TexasReceiptStatement {
        TexasReceiptStatement {
            circuit_id: [1; 32],
            manifest_digest: [2; 32],
            effect_kind: 1,
            authority_kind: 1,
            authority: [3; 32],
            transition_commitment: [4; 32],
            nullifier: [5; 32],
            pre_state_root: [6; 32],
            post_state_root: [7; 32],
            lifecycle_root: [8; 32],
            overlay_root: [9; 32],
        }
    }

    fn statement_for_batch(batch_digest: [u8; 32]) -> TexasReceiptStatement {
        let mut value = statement();
        value.transition_commitment = batch_digest;
        value
    }

    #[test]
    fn receipt_binding_rejects_scope_splice() {
        let empty = TexasSeatImage {
            occupied: false,
            folded: false,
            all_in: false,
            acted: false,
            stack: 0,
            bet: 0,
            total_bet: 0,
            pending_addon: 0,
        };
        let mut seats = [empty; 9];
        seats[0] = TexasSeatImage {
            occupied: true,
            stack: 100,
            bet: 10,
            total_bet: 10,
            ..empty
        };
        seats[1] = TexasSeatImage {
            occupied: true,
            stack: 100,
            bet: 10,
            total_bet: 10,
            ..empty
        };
        let pre = TexasStateImage {
            table_id: 1,
            hand_id: 1,
            call_seq: 0,
            round_state: 3,
            current_turn: 0,
            current_bet: 10,
            min_raise: 10,
            pot: 20,
            button: 0,
            max_players: 2,
            chip_pool: 220,
            leave_after_hand_mask: 0,
            seats,
        };
        let mut post = pre.clone();
        post.call_seq = 1;
        post.current_turn = 1;
        post.seats[0].acted = true;
        let archive = prove_tagged_texas_batch(&[TexasTransitionWitness {
            pre,
            post,
            action: TexasAction::Check { seat: 0 },
        }])
        .unwrap();
        let receipt = receipt_for(&archive);
        assert!(receipt.validate().is_ok());

        let mut bad_version = receipt.clone();
        bad_version.version = 0;
        assert!(bad_version.validate().is_err());

        let mut bad_range = receipt.clone();
        bad_range.last_call_seq += 1;
        assert!(bad_range.validate().is_err());

        let mut bad_finality = receipt.clone();
        bad_finality.block_hash = [0; 32];
        assert!(bad_finality.validate().is_err());

        bind_tagged_proof_to_receipt(&archive, &receipt).unwrap();
        let mut bad = receipt;
        bad.post_state_commitment[0] ^= 1;
        assert!(bind_tagged_proof_to_receipt(&archive, &bad).is_err());
    }

    #[test]
    fn authentication_requires_historical_finalized_inclusion() {
        let receipt = TexasTransitionReceipt {
            version: TEXAS_RECEIPT_VERSION,
            table_id: 7,
            hand_id: 2,
            first_call_seq: 4,
            last_call_seq: 5,
            transition_count: 1,
            batch_digest: [11; 32],
            pre_state_commitment: [6; 32],
            post_state_commitment: [7; 32],
            lifecycle_root: [8; 32],
            overlay_root: [9; 32],
            rules_commitment: [14; 32],
            block_height: 99,
            block_hash: [15; 32],
            receipt_key: [16; 32],
            receipt_value: [0; 32],
        };
        let receipt_statement = statement_for_batch(receipt.batch_digest);
        let value = receipt.value_digest_with_statement(&receipt_statement);
        let mut receipt = receipt;
        receipt.receipt_value = value;
        let leaf = TexasReceiptInclusionProof {
            finalized_block_hash: receipt.block_hash,
            finalized_block_height: receipt.block_height,
            state_root: hash_parts(&[TEXAS_RECEIPT_PATH_DOMAIN, &receipt.receipt_key, &value]),
            receipt_key: receipt.receipt_key,
            leaf_value: value,
            siblings: vec![],
            directions: vec![],
            confirmations: 12,
        };
        let authenticated =
            authenticate_receipt(receipt.clone(), receipt_statement, leaf.clone(), 6)
                .expect("finalized inclusion should authenticate");
        assert_eq!(authenticated.receipt().table_id, 7);

        let mut shallow = leaf.clone();
        shallow.confirmations = 1;
        assert!(
            authenticate_receipt(
                receipt.clone(),
                statement_for_batch(receipt.batch_digest),
                shallow,
                6
            )
            .is_err()
        );

        let mut forged = leaf;
        forged.leaf_value[0] ^= 1;
        assert!(authenticate_receipt(receipt, statement_for_batch([11; 32]), forged, 6).is_err());
    }

    #[test]
    fn l1_authentication_uses_canonical_sparse_merkle_encoding() {
        let mut receipt = TexasTransitionReceipt {
            version: TEXAS_RECEIPT_VERSION,
            table_id: 7,
            hand_id: 2,
            first_call_seq: 4,
            last_call_seq: 5,
            transition_count: 1,
            batch_digest: [21; 32],
            pre_state_commitment: [6; 32],
            post_state_commitment: [7; 32],
            lifecycle_root: [8; 32],
            overlay_root: [9; 32],
            rules_commitment: [24; 32],
            block_height: 199,
            block_hash: [25; 32],
            receipt_key: [26; 32],
            receipt_value: [0; 32],
        };
        let statement = statement_for_batch(receipt.batch_digest);
        receipt.receipt_value = receipt.value_digest_with_statement(&statement);

        let mut tree = SparseMerkleTree::new();
        tree.upsert(receipt.receipt_key, &receipt.receipt_value);
        let inclusion = TexasL1ReceiptInclusionProof {
            finalized_block_hash: receipt.block_hash,
            finalized_block_height: receipt.block_height,
            state_root: tree.root(),
            receipt_key: receipt.receipt_key,
            path: tree.prove(&receipt.receipt_key),
            confirmations: 12,
        };
        let authenticated =
            authenticate_receipt_l1(receipt.clone(), statement, inclusion.clone(), 6).unwrap();
        assert!(authenticated.l1_inclusion().is_some());

        let mut forged = inclusion;
        forged.state_root[0] ^= 1;
        assert!(
            authenticate_receipt_l1(receipt, statement_for_batch([21; 32]), forged, 6).is_err()
        );
    }

    #[test]
    fn canonical_receipt_binding_rejects_root_domain_splices() {
        let archive = ArchivedCanonicalTaggedProof {
            log_size: 0,
            num_columns: 0,
            table_id: 7,
            first_hand_id: 2,
            last_hand_id: 2,
            first_call_seq: 4,
            last_call_seq: 5,
            transition_count: 1,
            first_transition_kind: 0,
            last_transition_kind: 0,
            reveal_timeout_cascade_count: 0,
            reveal_timeout_cascade_schedule:
                [crate::texas_canonical_air::REVEAL_TIMEOUT_CASCADE_EMPTY_SEAT;
                    crate::texas_canonical_air::MAX_REVEAL_TIMEOUT_CASCADE_KICKS],
            batch_digest: [11; 32],
            pre_state_commitment: [12; 32],
            post_state_commitment: [13; 32],
            pre_state_root: [14; 32],
            post_state_root: [15; 32],
            pre_lifecycle_root: [16; 32],
            post_lifecycle_root: [17; 32],
            pre_overlay_root: [18; 32],
            post_overlay_root: [19; 32],
            pre_settlement_commitment: [20; 32],
            post_settlement_commitment: [21; 32],
            pre_custody_commitment: [22; 32],
            post_custody_commitment: [23; 32],
            pre_state_image_bytes: Vec::new(),
            post_state_image_bytes: Vec::new(),
            rake_opening: None,
            rules_hash: None,
            state_object_key: [24; 32],
            state_opening_epoch: 1,
            stark_proof_bytes: vec![],
            range_claimed_sum: [0, 0, 0, 0],
        };
        let receipt = CanonicalTransitionReceipt {
            version: CANONICAL_TEXAS_RECEIPT_VERSION,
            table_id: archive.table_id,
            first_hand_id: archive.first_hand_id,
            last_hand_id: archive.last_hand_id,
            first_call_seq: archive.first_call_seq,
            last_call_seq: archive.last_call_seq,
            transition_count: archive.transition_count,
            first_transition_kind: archive.first_transition_kind,
            last_transition_kind: archive.last_transition_kind,
            reveal_timeout_cascade_count: archive.reveal_timeout_cascade_count,
            reveal_timeout_cascade_schedule: archive.reveal_timeout_cascade_schedule,
            batch_digest: archive.batch_digest,
            pre_state_commitment: archive.pre_state_commitment,
            post_state_commitment: archive.post_state_commitment,
            pre_state_root: archive.pre_state_root,
            post_state_root: archive.post_state_root,
            pre_lifecycle_root: archive.pre_lifecycle_root,
            post_lifecycle_root: archive.post_lifecycle_root,
            pre_overlay_root: archive.pre_overlay_root,
            post_overlay_root: archive.post_overlay_root,
            pre_settlement_commitment: archive.pre_settlement_commitment,
            post_settlement_commitment: archive.post_settlement_commitment,
            pre_custody_commitment: archive.pre_custody_commitment,
            post_custody_commitment: archive.post_custody_commitment,
            state_object_key: archive.state_object_key,
            state_opening_epoch: archive.state_opening_epoch,
            block_height: 9,
            block_hash: [24; 32],
            receipt_key: [25; 32],
            receipt_value: [0; 32],
        };
        bind_canonical_proof_to_receipt(&archive, &receipt).expect("matching scope binds");

        let mut forged = receipt.clone();
        forged.post_custody_commitment[0] ^= 1;
        assert!(bind_canonical_proof_to_receipt(&archive, &forged).is_err());

        let mut forged = receipt.clone();
        forged.state_object_key[0] ^= 1;
        assert!(bind_canonical_proof_to_receipt(&archive, &forged).is_err());

        let mut forged = receipt.clone();
        forged.state_opening_epoch += 1;
        assert!(bind_canonical_proof_to_receipt(&archive, &forged).is_err());

        let mut forged = receipt.clone();
        forged.first_transition_kind = CanonicalTransitionKind::JoinTable as u8;
        assert!(bind_canonical_proof_to_receipt(&archive, &forged).is_err());

        let empty_compression =
            crate::blake2b_lookup_compression::ArchivedBlake2bLookupCompressionProof {
                messages: Vec::new(),
                digests: Vec::new(),
                initial_states: Vec::new(),
                hash_states: Vec::new(),
                chain_to_next: Vec::new(),
                calls: Vec::new(),
                g_proof_bytes: Vec::new(),
                schedule_proof_bytes: Vec::new(),
            };
        let composed = crate::canonical_state_opening::ArchivedCanonicalStateImageOpeningProof {
            opening: crate::canonical_state_opening::ArchivedCanonicalStateOpeningProof {
                canonical: archive.clone(),
                state_openings:
                    crate::blake2b_lookup_compression::ArchivedBlake2bLookupSmtFixedValuePathsProof {
                        paths: Vec::new(),
                        compression: empty_compression.clone(),
                    },
            },
            state_image_hashes: crate::canonical_state_hash::ArchivedCanonicalStateImageHashProof {
                hashes: crate::blake3_flock::ArchivedFlockHashesProof {
                    statements: Vec::new(),
                    chains: Vec::new(),
                    merkles: Vec::new(),
                },
            },
        };
        let authenticated = AuthenticatedCanonicalTexasReceipt {
            receipt: receipt.clone(),
            statement: CanonicalReceiptStatement {
                circuit_id: [0; 32],
                manifest_digest: [0; 32],
                effect_kind: 0,
                authority_kind: 0,
                authority: [0; 32],
                table_id: archive.table_id,
                first_hand_id: archive.first_hand_id,
                last_hand_id: archive.last_hand_id,
                first_call_seq: archive.first_call_seq,
                last_call_seq: archive.last_call_seq,
                transition_count: archive.transition_count,
                first_transition_kind: archive.first_transition_kind,
                last_transition_kind: archive.last_transition_kind,
                reveal_timeout_cascade_count: archive.reveal_timeout_cascade_count,
                reveal_timeout_cascade_schedule: archive.reveal_timeout_cascade_schedule,
                batch_digest: archive.batch_digest,
                pre_state_commitment: archive.pre_state_commitment,
                post_state_commitment: archive.post_state_commitment,
                pre_state_root: archive.pre_state_root,
                post_state_root: archive.post_state_root,
                pre_lifecycle_root: archive.pre_lifecycle_root,
                post_lifecycle_root: archive.post_lifecycle_root,
                pre_overlay_root: archive.pre_overlay_root,
                post_overlay_root: archive.post_overlay_root,
                pre_settlement_commitment: archive.pre_settlement_commitment,
                post_settlement_commitment: archive.post_settlement_commitment,
                pre_custody_commitment: archive.pre_custody_commitment,
                post_custody_commitment: archive.post_custody_commitment,
                state_object_key: archive.state_object_key,
                state_opening_epoch: archive.state_opening_epoch,
            },
            inclusion: TexasL1ReceiptInclusionProof {
                finalized_block_hash: [1; 32],
                finalized_block_height: 1,
                state_root: [1; 32],
                receipt_key: [1; 32],
                path: MerklePath {
                    siblings: vec![[0; 32]; TREE_DEPTH as usize],
                    is_empty_leaf: false,
                },
                confirmations: 6,
            },
        };
        let error = authenticated
            .admit_canonical_proof_with_state_openings(&composed)
            .unwrap_err();
        assert!(!matches!(
            error,
            TexasAirError::HostZeroAdmissionIncomplete(_)
        ));
    }
}
