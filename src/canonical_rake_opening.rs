//! Blake2b-256 authentication of the canonical Texas table-rules preimage.
//!
//! The hot canonical state image carries only an opaque `rules_commitment`.
//! Raked settlement terminals (the sole-survivor award today, showdown
//! settlement later) must not trust a host-selected `rake_mode`/`rake_bps`/
//! `rake_cap` triple, so this module defines the fixed-width opening that
//! authenticates the complete `TableRules` byte string to that commitment:
//!
//! ```text
//! rules_commitment = Blake2b-256("zchain.texas.rules.v1" || Borsh(TableRules))
//! ```
//!
//! The proof itself is the shared lookup-backed Blake2b STARK used by the
//! state-image endpoints; no native hashing runs on the verify path.  The
//! canonical transition AIR consumes the authenticated rake configuration
//! through public scope columns, keeping the tagged batch's one-proof profile
//! while closing the host advice surface for rake computation.

#![allow(missing_docs)]

use borsh::BorshDeserialize;
use poker_l1::vm::contracts::texas_poker::types::TableRules;

use crate::error::{TexasAirError, TexasAirResult};
use crate::hash_prover::HashProofProvider as _;

/// Domain prefix separating rules preimages from every other canonical
/// Blake2b statement.
pub const CANONICAL_RULES_DOMAIN: &[u8] = b"zchain.texas.rules.v2";

/// The authenticated rake-relevant projection of one rules opening.
#[derive(Debug, Clone, Copy, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct CanonicalRakeOpening {
    /// `RAKE_MODE_NONE` (0) or `RAKE_MODE_PERCENTAGE` (1).
    pub rake_mode: u8,
    /// Basis points, at most 10_000.
    pub rake_bps: u16,
    /// Maximum rake charged for one hand.
    pub rake_cap: u64,
}

impl CanonicalRakeOpening {
    /// Canonical zero opening for every non-raked transition kind.
    pub const ZERO: Self = Self {
        rake_mode: 0,
        rake_bps: 0,
        rake_cap: 0,
    };

    /// The percentage-mode discriminator used by raked settlement terminals.
    pub const PERCENTAGE_MODE: u8 = 1;
}

/// One BLAKE3 statement authenticating the complete rules byte string.
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct ArchivedCanonicalRulesHashProof {
    pub hashes: crate::blake3_flock::ArchivedFlockHashesProof,
}

/// The authenticated opening extracted from a verified rules statement.
pub struct AuthenticatedRulesOpening {
    pub rules: TableRules,
    pub rake: CanonicalRakeOpening,
}

/// Return the exact byte preimage covered by a canonical rules commitment.
pub fn canonical_rules_preimage(rules: &TableRules) -> TexasAirResult<Vec<u8>> {
    let encoded = borsh::to_vec(rules)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
    let mut preimage = Vec::with_capacity(CANONICAL_RULES_DOMAIN.len() + encoded.len());
    preimage.extend_from_slice(CANONICAL_RULES_DOMAIN);
    preimage.extend_from_slice(&encoded);
    Ok(preimage)
}

/// Host-side digest (BLAKE3 padded chain) used by fixture construction and
/// test oracles; the verify path authenticates it through the flock chain
/// proof instead.
pub fn canonical_rules_commitment(rules: &TableRules) -> TexasAirResult<[u8; 32]> {
    let preimage = canonical_rules_preimage(rules)?;
    Ok(crate::blake3_flock::blake3_chain_digest(&preimage))
}

/// Project the rake-relevant triple out of a full rules value.
#[must_use]
pub fn rake_opening_of(rules: &TableRules) -> CanonicalRakeOpening {
    CanonicalRakeOpening {
        rake_mode: rules.rake_mode,
        rake_bps: rules.rake_bps,
        rake_cap: rules.rake_cap,
    }
}

/// Prove `Blake2b-256(domain || Borsh(rules)) == rules_commitment` with the
/// shared lookup-backed Blake2b STARK.  Native Blake2b is not used to form or
/// verify the statement.
pub fn prove_canonical_rules_hash(
    rules: &TableRules,
) -> TexasAirResult<ArchivedCanonicalRulesHashProof> {
    let statements = vec![crate::hash_prover::Blake2bStatement::new(
        canonical_rules_preimage(rules)?,
        canonical_rules_commitment(rules)?,
    )];
    let hashes = crate::blake3_flock::FlockProvider
        .prove_statements(&statements)
        .map_err(|error| {
            TexasAirError::SpecViolation(format!("flock rules chain proof failed: {error:?}"))
        })?;
    let crate::hash_prover::ArchivedHashProof::Flock(hashes) = hashes else {
        return Err(TexasAirError::SpecViolation(
            "flock backend must produce flock proofs".into(),
        ));
    };
    Ok(ArchivedCanonicalRulesHashProof { hashes })
}

/// Verify the archived rules byte statement against the public canonical
/// `rules_commitment` and return the authenticated opening.  This function
/// neither serializes rules nor calls a native hash implementation.
pub fn verify_canonical_rules_hash(
    archive: &ArchivedCanonicalRulesHashProof,
    rules_commitment: [u8; 32],
) -> TexasAirResult<AuthenticatedRulesOpening> {
    let statements = &archive.hashes.statements;
    let [statement] = statements.as_slice() else {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "canonical rules hash proof must contain exactly one statement".into(),
        ));
    };
    if statement.digest != rules_commitment {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "canonical rules hash proof is detached from the rules commitment".into(),
        ));
    }
    crate::blake3_flock::verify_flock_archive(&archive.hashes)?;
    let rules = decode_rules_statement(&statement.message)?;
    Ok(AuthenticatedRulesOpening {
        rake: rake_opening_of(&rules),
        rules,
    })
}

/// Decode the fixed-width Borsh `TableRules` covered by a verified statement.
fn decode_rules_statement(message: &[u8]) -> TexasAirResult<TableRules> {
    let encoded = message
        .strip_prefix(CANONICAL_RULES_DOMAIN)
        .ok_or_else(|| {
            TexasAirError::ConstraintUnsatisfied(
                "canonical rules statement is missing its domain prefix".into(),
            )
        })?;
    let rules = TableRules::try_from_slice(encoded).map_err(|error| {
        TexasAirError::ConstraintUnsatisfied(format!(
            "canonical rules statement is malformed: {error}"
        ))
    })?;
    validate_rules_opening(&rules)?;
    Ok(rules)
}

/// Mirror the VM's `TableRules::validate_canonical` rake invariants so a
/// verified opening cannot smuggle an out-of-range configuration into the
/// settlement arithmetic.
pub fn validate_rules_opening(rules: &TableRules) -> TexasAirResult<()> {
    if !matches!(
        rules.rake_mode,
        0 | 1 // RAKE_MODE_NONE | RAKE_MODE_PERCENTAGE
    ) || rules.rake_bps > 10_000
    {
        return Err(TexasAirError::SpecViolation(
            "canonical rules opening carries an out-of-range rake configuration".into(),
        ));
    }
    Ok(())
}

/// Deterministic rake for a raked settlement terminal, mirroring the VM's
/// `compute_rake_amount` exactly: `min(floor(pot * bps / 10_000), cap, pot)`,
/// and zero when the mode is `RAKE_MODE_NONE`.
#[must_use]
pub fn canonical_settlement_rake(pot: u64, opening: &CanonicalRakeOpening) -> u64 {
    if opening.rake_mode == 0 {
        return 0;
    }
    let raw = u128::from(pot) * u128::from(opening.rake_bps) / 10_000;
    raw.min(u128::from(opening.rake_cap)).min(u128::from(pot)) as u64
}

/// One shared Blake2b statement batch for a complete hand's fixed openings:
/// the table rules and both endpoint state images.  Sharing a single lookup
/// STARK amortizes the dominant fixed cost (table commitment + FRI), which
/// measurements show is independent of the message-block count.
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct ArchivedCanonicalHandOpeningsProof {
    pub hashes: crate::blake3_flock::ArchivedFlockHashesProof,
}

/// Prove the rules and both endpoint state-image commitments in one shared
/// lookup-backed Blake2b STARK.  Statement order is fixed:
/// `[rules, pre image, post image]`.
pub fn prove_canonical_hand_openings(
    rules: &TableRules,
    pre_image: &crate::texas_canonical::CanonicalStateImage,
    post_image: &crate::texas_canonical::CanonicalStateImage,
) -> TexasAirResult<ArchivedCanonicalHandOpeningsProof> {
    let statements = vec![
        crate::hash_prover::Blake2bStatement::new(
            canonical_rules_preimage(rules)?,
            canonical_rules_commitment(rules)?,
        ),
        crate::hash_prover::Blake2bStatement::new(
            crate::canonical_state_hash::canonical_state_image_preimage(pre_image)?,
            pre_image.commitment(),
        ),
        crate::hash_prover::Blake2bStatement::new(
            crate::canonical_state_hash::canonical_state_image_preimage(post_image)?,
            post_image.commitment(),
        ),
    ];
    let hashes = crate::blake3_flock::FlockProvider
        .prove_statements(&statements)
        .map_err(|error| {
            TexasAirError::SpecViolation(format!("flock hand-opening proof failed: {error:?}"))
        })?;
    let crate::hash_prover::ArchivedHashProof::Flock(hashes) = hashes else {
        return Err(TexasAirError::SpecViolation(
            "flock backend must produce flock proofs".into(),
        ));
    };
    Ok(ArchivedCanonicalHandOpeningsProof { hashes })
}

/// Verify the combined hand-opening statement batch against the three public
/// commitments without any native hashing.
pub fn verify_canonical_hand_openings(
    archive: &ArchivedCanonicalHandOpeningsProof,
    rules_commitment: [u8; 32],
    pre_commitment: [u8; 32],
    post_commitment: [u8; 32],
) -> TexasAirResult<AuthenticatedRulesOpening> {
    let statements = &archive.hashes.statements;
    let [rules_statement, pre_statement, post_statement] = statements.as_slice() else {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "hand-opening proof must contain exactly three statements".into(),
        ));
    };
    if rules_statement.digest != rules_commitment
        || pre_statement.digest != pre_commitment
        || post_statement.digest != post_commitment
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "hand-opening proof is detached from a public commitment".into(),
        ));
    }
    crate::blake3_flock::verify_flock_archive(&archive.hashes)?;
    let rules = decode_rules_statement(&rules_statement.message)?;
    Ok(AuthenticatedRulesOpening {
        rake: rake_opening_of(&rules),
        rules,
    })
}

/// The complete fixed hash bundle for one finalized hand: table rules, both
/// endpoint state images, and (for host-zero admission) both L1 sparse-Merkle
/// openings, proven as one ordered statement batch through the shared
/// hash-prover seam.
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct ArchivedCanonicalHandBundleProof {
    pub hash: crate::hash_prover::ArchivedHashProof,
    /// Public SMT opening witnesses, included so the verifier can rebuild and
    /// structurally check the path statements from public data alone.
    pub smt_pre: Option<crate::blake2b_smt_witness::Blake2bSmtFixedValuePathWitness>,
    pub smt_post: Option<crate::blake2b_smt_witness::Blake2bSmtFixedValuePathWitness>,
}

/// Statement order: `[rules, pre image, post image, smt_pre nodes...,
/// smt_post nodes...]`.
fn hand_bundle_statements(
    rules: &TableRules,
    pre_image: &crate::texas_canonical::CanonicalStateImage,
    post_image: &crate::texas_canonical::CanonicalStateImage,
    smt_pre: Option<&crate::blake2b_smt_witness::Blake2bSmtFixedValuePathWitness>,
    smt_post: Option<&crate::blake2b_smt_witness::Blake2bSmtFixedValuePathWitness>,
) -> TexasAirResult<Vec<crate::hash_prover::Blake2bStatement>> {
    use crate::hash_prover::Blake2bStatement;
    let mut statements = vec![
        Blake2bStatement::new(
            canonical_rules_preimage(rules)?,
            canonical_rules_commitment(rules)?,
        ),
        Blake2bStatement::new(
            crate::canonical_state_hash::canonical_state_image_preimage(pre_image)?,
            pre_image.commitment(),
        ),
        Blake2bStatement::new(
            crate::canonical_state_hash::canonical_state_image_preimage(post_image)?,
            post_image.commitment(),
        ),
    ];
    for witness in [smt_pre, smt_post].into_iter().flatten() {
        statements.extend(crate::smt_statements::smt_path_statements(witness)?);
    }
    Ok(statements)
}

/// Prove the complete hand bundle in one shared proof.
pub fn prove_canonical_hand_bundle<P: crate::hash_prover::HashProofProvider>(
    provider: &P,
    rules: &TableRules,
    pre_image: &crate::texas_canonical::CanonicalStateImage,
    post_image: &crate::texas_canonical::CanonicalStateImage,
    smt_pre: Option<&crate::blake2b_smt_witness::Blake2bSmtFixedValuePathWitness>,
    smt_post: Option<&crate::blake2b_smt_witness::Blake2bSmtFixedValuePathWitness>,
) -> TexasAirResult<ArchivedCanonicalHandBundleProof> {
    Ok(ArchivedCanonicalHandBundleProof {
        hash: provider.prove_statements(&hand_bundle_statements(
            rules, pre_image, post_image, smt_pre, smt_post,
        )?)?,
        smt_pre: smt_pre.cloned(),
        smt_post: smt_post.cloned(),
    })
}

/// Verify the complete hand bundle against the public commitments.  Checks
/// the exact ordered statement list (splice-proof), the SMT path structure
/// over public bytes, and returns the authenticated rules opening.
pub fn verify_canonical_hand_bundle<P: crate::hash_prover::HashProofProvider>(
    provider: &P,
    archive: &ArchivedCanonicalHandBundleProof,
    rules: &TableRules,
    pre_image: &crate::texas_canonical::CanonicalStateImage,
    post_image: &crate::texas_canonical::CanonicalStateImage,
) -> TexasAirResult<AuthenticatedRulesOpening> {
    let statements = hand_bundle_statements(
        rules,
        pre_image,
        post_image,
        archive.smt_pre.as_ref(),
        archive.smt_post.as_ref(),
    )?;
    provider.verify_statements(&archive.hash, &statements)?;
    let mut cursor = 3;
    for witness in [archive.smt_pre.as_ref(), archive.smt_post.as_ref()]
        .into_iter()
        .flatten()
    {
        crate::smt_statements::verify_smt_path_statements(
            witness,
            &statements[cursor..cursor + crate::smt_statements::SMT_PATH_STATEMENTS],
        )?;
        cursor += crate::smt_statements::SMT_PATH_STATEMENTS;
    }
    let rules_statement = &statements[0];
    let rules = decode_rules_statement(&rules_statement.message)?;
    Ok(AuthenticatedRulesOpening {
        rake: rake_opening_of(&rules),
        rules,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> TableRules {
        TableRules {
            max_players: 4,
            small_blind: 25,
            big_blind: 50,
            timeout_config: Default::default(),
            ante_mode: 0,
            ante_amount: 0,
            rake_mode: 1,
            rake_bps: 500,
            rake_cap: 1_000,
            rit_mode: 0,
        }
    }

    #[test]
    fn preimage_is_the_exact_native_commitment_input() {
        let rules = rules();
        let preimage = canonical_rules_preimage(&rules).unwrap();
        assert!(preimage.starts_with(CANONICAL_RULES_DOMAIN));
        assert_eq!(
            canonical_rules_commitment(&rules).unwrap(),
            crate::blake3_flock::blake3_chain_digest(&preimage)
        );
    }

    #[test]
    fn rules_hash_proof_verifies_against_the_public_commitment() {
        let rules = rules();
        let commitment = canonical_rules_commitment(&rules).unwrap();
        let archive = prove_canonical_rules_hash(&rules).expect("rules hash proof");
        let authenticated =
            verify_canonical_rules_hash(&archive, commitment).expect("rules hash verification");
        assert_eq!(authenticated.rake, rake_opening_of(&rules));
        assert_eq!(authenticated.rules, rules);

        let mut detached = commitment;
        detached[0] ^= 1;
        assert!(verify_canonical_rules_hash(&archive, detached).is_err());
    }

    #[test]
    fn out_of_range_rake_configurations_are_rejected() {
        let mut rules = rules();
        rules.rake_bps = 10_001;
        let commitment = canonical_rules_commitment(&rules).unwrap();
        let archive = prove_canonical_rules_hash(&rules).expect("rules hash proof");
        assert!(verify_canonical_rules_hash(&archive, commitment).is_err());
    }

    #[test]
    #[ignore = "performance benchmark"]
    fn bench_rules_hash_phases() {
        use std::time::Instant;
        let rules = rules();
        let commitment = canonical_rules_commitment(&rules).unwrap();

        // Phase 1: the tiny rules preimage through the shared lookup STARK.
        let start = Instant::now();
        let archive = prove_canonical_rules_hash(&rules).expect("rules hash proof");
        println!("rules-hash prove (76-byte message): {:?}", start.elapsed());

        let start = Instant::now();
        verify_canonical_rules_hash(&archive, commitment).expect("verify");
        println!("rules-hash verify: {:?}", start.elapsed());
        println!(
            "rules-hash proof bytes: {}",
            borsh::to_vec(&archive).unwrap().len()
        );
    }

    #[test]
    fn hand_bundle_rejects_statement_splices() {
        use crate::blake3_flock::FlockProvider;
        use crate::hash_prover::{Blake2bStatement, HashProofProvider as _};
        use crate::texas_canonical::{
            CANONICAL_ABI_VERSION, CanonicalPhase, CanonicalSeat, CanonicalStateImage,
            MAX_CANONICAL_SEATS, NO_CANONICAL_SEAT,
        };
        let image = || CanonicalStateImage {
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
        };
        let rules = rules();
        let pre = image();
        let mut post = image();
        post.call_seq = 1;
        let smt = crate::smt_statements::synthetic_smt_witness(0x5a, [0x11; 32], [0x22; 32]);
        let provider = FlockProvider;
        let bundle = prove_canonical_hand_bundle(&provider, &rules, &pre, &post, Some(&smt), None)
            .expect("bundle");
        verify_canonical_hand_bundle(&provider, &bundle, &rules, &pre, &post)
            .expect("bundle verify");

        // A tampered witness node detaches the statements.
        let mut tampered = bundle.clone();
        if let Some(witness) = tampered.smt_pre.as_mut() {
            witness.nodes[7][0] ^= 1;
        }
        assert!(verify_canonical_hand_bundle(&provider, &tampered, &rules, &pre, &post).is_err());

        // A wrong rules value detaches the rules statement.
        let mut wrong_rules = rules;
        wrong_rules.rake_bps = 250;
        assert!(
            verify_canonical_hand_bundle(&provider, &bundle, &wrong_rules, &pre, &post).is_err()
        );
        let _ = Blake2bStatement::new(Vec::new(), [0; 32]);
    }

    #[test]
    fn settlement_rake_mirrors_the_vm_formula() {
        let opening = rake_opening_of(&rules());
        // 5% of 90 is 4.5 -> floor 4, below the cap.
        assert_eq!(canonical_settlement_rake(90, &opening), 4);
        // 5% of 100_000 is 5_000 -> capped at 1_000.
        assert_eq!(canonical_settlement_rake(100_000, &opening), 1_000);
        // The rake can never exceed the pot itself.
        assert_eq!(canonical_settlement_rake(3, &opening), 0);
        // A NONE-mode table never rakes.
        let mut none = rules();
        none.rake_mode = 0;
        assert_eq!(
            canonical_settlement_rake(100_000, &rake_opening_of(&none)),
            0
        );
    }
}
