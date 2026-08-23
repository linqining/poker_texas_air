//! Backend-agnostic Blake2b statement proving seam.
//!
//! The hash layer is migrating to a binary-field prover (Binius/Flock class)
//! while the M31 lookup stack remains the audited default.  This module is
//! the single seam both backends plug into: callers construct public
//! `preimage -> digest` statements and ask a [`HashProofProvider`] to prove
//! or verify them, without knowing which proving system produced the
//! artifact.  The first backend is the existing shared lookup STARK; a
//! binary-field backend can be added without touching any consumer.
//!
//! Splice protection is provider-level and order-sensitive: verification
//! fails unless the supplied statements equal, byte for byte and in order,
//! the statements the proof actually covers.

#![allow(missing_docs)]

use crate::blake2b_lookup_compression::{
    ArchivedBlake2bLookupHashesProof, prove_blake2b_lookup_hashes, verify_blake2b_lookup_hashes,
};
use crate::error::{TexasAirError, TexasAirResult};

/// One public Blake2b-256 statement: `digest = Blake2b-256(message)`.
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct Blake2bStatement {
    pub message: Vec<u8>,
    pub digest: [u8; 32],
}

impl Blake2bStatement {
    #[must_use]
    pub fn new(message: Vec<u8>, digest: [u8; 32]) -> Self {
        Self { message, digest }
    }
}

/// A backend-tagged proof over an ordered list of Blake2b statements.
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub enum ArchivedHashProof {
    /// The shared lookup-backed M31 STARK (legacy Blake2b fallback).
    LookupStack(ArchivedBlake2bLookupHashesProof),
    /// The binary-field BLAKE3 flock backend.
    Flock(crate::blake3_flock::ArchivedFlockHashesProof),
}

impl ArchivedHashProof {
    /// The ordered statements this proof covers.
    #[must_use]
    pub fn statements(&self) -> Vec<Blake2bStatement> {
        match self {
            ArchivedHashProof::LookupStack(inner) => inner
                .statements
                .iter()
                .map(|statement| Blake2bStatement::new(statement.message.clone(), statement.digest))
                .collect(),
            ArchivedHashProof::Flock(inner) => inner
                .statements
                .iter()
                .map(|statement| Blake2bStatement::new(statement.message.clone(), statement.digest))
                .collect(),
        }
    }
}

/// Prove and verify ordered Blake2b-256 statement batches.
pub trait HashProofProvider {
    /// Prove every statement in one shared proof.
    fn prove_statements(
        &self,
        statements: &[Blake2bStatement],
    ) -> TexasAirResult<ArchivedHashProof>;

    /// Verify a proof against the exact ordered statement list.  Any splice,
    /// reorder, or statement substitution fails closed.
    fn verify_statements(
        &self,
        proof: &ArchivedHashProof,
        statements: &[Blake2bStatement],
    ) -> TexasAirResult<()> {
        let covered = proof.statements();
        if covered.len() != statements.len() {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "hash proof statement count does not match the request".into(),
            ));
        }
        for (covered, requested) in covered.iter().zip(statements.iter()) {
            if covered.message != requested.message || covered.digest != requested.digest {
                return Err(TexasAirError::ConstraintUnsatisfied(
                    "hash proof is detached from the requested statements".into(),
                ));
            }
        }
        self.verify_proof(proof)
    }

    /// Verify the proof's internal consistency (backend-specific).
    fn verify_proof(&self, proof: &ArchivedHashProof) -> TexasAirResult<()>;
}

/// The default M31 lookup-stack backend.
#[derive(Debug, Clone, Copy, Default)]
pub struct LookupStackProvider;

impl HashProofProvider for LookupStackProvider {
    fn prove_statements(
        &self,
        statements: &[Blake2bStatement],
    ) -> TexasAirResult<ArchivedHashProof> {
        if statements.is_empty() {
            return Err(TexasAirError::SpecViolation(
                "hash proof batch must not be empty".into(),
            ));
        }
        let messages: Vec<Vec<u8>> = statements.iter().map(|s| s.message.clone()).collect();
        let inner = prove_blake2b_lookup_hashes(&messages)?;
        Ok(ArchivedHashProof::LookupStack(inner))
    }

    fn verify_proof(&self, proof: &ArchivedHashProof) -> TexasAirResult<()> {
        match proof {
            ArchivedHashProof::LookupStack(inner) => verify_blake2b_lookup_hashes(inner),
            ArchivedHashProof::Flock(_) => Err(TexasAirError::ConstraintUnsatisfied(
                "lookup-stack backend cannot verify flock proofs".into(),
            )),
        }
    }
}

/// The process-wide default provider: the binary-field BLAKE3 flock
/// backend.  Callers that do not care about the backend (tests, the hand
/// bench, transitional consumers) use this; the admission path may inject an
/// explicit provider.  The M31 lookup stack stays available as the legacy
/// Blake2b fallback via [`LookupStackProvider`].
#[must_use]
pub fn default_hash_provider() -> crate::blake3_flock::FlockProvider {
    crate::blake3_flock::FlockProvider
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest_of(message: &[u8]) -> [u8; 32] {
        crate::blake3_flock::blake3_chain_digest(message)
    }

    #[test]
    fn provider_round_trips_ordered_statements() {
        let statements = vec![
            Blake2bStatement::new(
                b"zchain.texas.rules.v2".to_vec(),
                digest_of(b"zchain.texas.rules.v2"),
            ),
            Blake2bStatement::new(vec![7u8; 200], digest_of(&[7u8; 200])),
        ];
        let provider = default_hash_provider();
        let proof = provider.prove_statements(&statements).expect("proof");
        provider
            .verify_statements(&proof, &statements)
            .expect("verify");
    }

    #[test]
    fn provider_rejects_splices_reorders_and_substitutions() {
        let statements = vec![
            Blake2bStatement::new(b"first".to_vec(), digest_of(b"first")),
            Blake2bStatement::new(b"second".to_vec(), digest_of(b"second")),
        ];
        let provider = default_hash_provider();
        let proof = provider.prove_statements(&statements).expect("proof");

        let reordered = vec![statements[1].clone(), statements[0].clone()];
        assert!(provider.verify_statements(&proof, &reordered).is_err());

        let mut wrong_digest = statements.clone();
        wrong_digest[0].digest[0] ^= 1;
        assert!(provider.verify_statements(&proof, &wrong_digest).is_err());

        let truncated = vec![statements[0].clone()];
        assert!(provider.verify_statements(&proof, &truncated).is_err());

        let extended = statements
            .iter()
            .cloned()
            .chain(std::iter::once(Blake2bStatement::new(
                b"extra".to_vec(),
                digest_of(b"extra"),
            )))
            .collect::<Vec<_>>();
        assert!(provider.verify_statements(&proof, &extended).is_err());
    }

    #[test]
    fn provider_rejects_empty_batches() {
        assert!(default_hash_provider().prove_statements(&[]).is_err());
    }
}
