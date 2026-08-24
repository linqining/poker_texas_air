//! Folded Ristretto group-addition binding for reconstruction accumulators.
//!
//! This module proves the canonical initial Ristretto deck and the homomorphic
//! accumulator equation for one encrypted card:
//! `post.c1 = prior.c1 + contribution.c1` and
//! `post.c2 = prior.c2 + contribution.c2`.
//! It does not prove the Reconstruction V3 slot-membership, cross-key,
//! shuffle, transcript, or final rebuilt-deck relations.

use borsh::{BorshDeserialize, BorshSerialize};
use rayon::prelude::*;

use crate::canonical_reconstruction_binding::{
    ArchivedCanonicalReconstructionStateBindingProof, CANONICAL_RECONSTRUCTION_CARDS,
    CanonicalRistrettoCiphertext, canonical_ristretto_cards,
    verify_canonical_reconstruction_state_binding,
};
use crate::error::{TexasAirError, TexasAirResult};
use crate::ristretto_fp_program_air::{
    ArchivedRistrettoFpProgramBatchProof, build_ristretto_fp_program_compressed_point_addition,
    prove_ristretto_fp_program_batch, verify_ristretto_fp_program_batch,
    verify_ristretto_fp_program_compressed_point_addition_row,
};
use crate::ristretto_reconstruction_proof_wire::validate_ristretto_reconstruction_proof_wire;
use poker_protocol::precompile_abi::{EncodedCiphertext, ReconstructionV3VerifyRequest};

/// Fixed 52-card reconstruction accumulator transition.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoReconstructionDeckAccumulatorProof {
    /// Accumulator deck before applying one contribution vector.
    pub prior: [CanonicalRistrettoCiphertext; CANONICAL_RECONSTRUCTION_CARDS],
    /// Canonical Reconstruction V3 contribution vector.
    pub contributions: [CanonicalRistrettoCiphertext; CANONICAL_RECONSTRUCTION_CARDS],
    /// Accumulator deck after applying the contribution vector.
    pub post: [CanonicalRistrettoCiphertext; CANONICAL_RECONSTRUCTION_CARDS],
    /// One batch STARK containing exactly 104 rows in canonical order:
    /// `card0.c1, card0.c2, ..., card51.c1, card51.c2`.
    pub additions: ArchivedRistrettoFpProgramBatchProof,
}

/// Canonical initial encrypted deck for the Ristretto migration route.
///
/// The single equal-shape batch has exactly 156 compressed-addition rows:
/// `1G..52G`, `1PK..52PK`, then `card_i + (i+1)PK` for all 52 slots.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoCanonicalBaseDeckProof {
    /// Aggregate public key used by every initial ElGamal ciphertext.
    pub aggregate_pk: [u8; 32],
    /// Derived canonical initial encrypted deck.
    pub deck: [CanonicalRistrettoCiphertext; CANONICAL_RECONSTRUCTION_CARDS],
    /// One 156-row compressed-point-addition STARK.
    pub additions: ArchivedRistrettoFpProgramBatchProof,
}

/// Complete non-final reconstruction accumulator transition archive currently
/// available to the host-zero route.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedCanonicalReconstructionAccumulatorTransitionProof {
    /// Lookup-backed pre/request/post state binding.
    pub binding: ArchivedCanonicalReconstructionStateBindingProof,
    /// One 104-row Ristretto addition batch.
    pub accumulator: ArchivedRistrettoReconstructionDeckAccumulatorProof,
    /// Required exactly for the first contribution, and forbidden afterward.
    pub base_deck: Option<ArchivedRistrettoCanonicalBaseDeckProof>,
}

const RECONSTRUCTION_ADDITION_ROWS: usize = CANONICAL_RECONSTRUCTION_CARDS * 2;
const BASE_DECK_ADDITION_ROWS: usize = CANONICAL_RECONSTRUCTION_CARDS * 3;
const RISTRETTO_IDENTITY: [u8; 32] = [0; 32];
const RISTRETTO_BASEPOINT: [u8; 32] = [
    0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71, 0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00, 0x51, 0x5f,
    0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d, 0xb6, 0xa6, 0x59, 0x45, 0xe0, 0x8d, 0x2d, 0x76,
];

fn build_ristretto_canonical_base_deck_rows(
    aggregate_pk: &[u8; 32],
) -> TexasAirResult<(
    [CanonicalRistrettoCiphertext; CANONICAL_RECONSTRUCTION_CARDS],
    Vec<crate::ristretto_fp_program_air::RistrettoFpProgram>,
)> {
    let mut programs = Vec::with_capacity(BASE_DECK_ADDITION_ROWS);
    let mut generator_multiples = [[0u8; 32]; CANONICAL_RECONSTRUCTION_CARDS];
    let mut prior = RISTRETTO_IDENTITY;
    for multiple in &mut generator_multiples {
        let (program, output) =
            build_ristretto_fp_program_compressed_point_addition(&prior, &RISTRETTO_BASEPOINT)?;
        programs.push(program);
        *multiple = output;
        prior = output;
    }

    let mut key_multiples = [[0u8; 32]; CANONICAL_RECONSTRUCTION_CARDS];
    prior = RISTRETTO_IDENTITY;
    for multiple in &mut key_multiples {
        let (program, output) =
            build_ristretto_fp_program_compressed_point_addition(&prior, aggregate_pk)?;
        programs.push(program);
        *multiple = output;
        prior = output;
    }

    let cards = canonical_ristretto_cards();
    let mut deck = [CanonicalRistrettoCiphertext::default(); CANONICAL_RECONSTRUCTION_CARDS];
    for index in 0..CANONICAL_RECONSTRUCTION_CARDS {
        let (program, c2) = build_ristretto_fp_program_compressed_point_addition(
            &cards[index],
            &key_multiples[index],
        )?;
        programs.push(program);
        deck[index] = CanonicalRistrettoCiphertext {
            c1: generator_multiples[index],
            c2,
        };
    }
    Ok((deck, programs))
}

/// Prove the deterministic 52-card initial Ristretto ElGamal deck.
pub fn prove_ristretto_canonical_base_deck(
    aggregate_pk: [u8; 32],
) -> TexasAirResult<ArchivedRistrettoCanonicalBaseDeckProof> {
    let (deck, programs) = build_ristretto_canonical_base_deck_rows(&aggregate_pk)?;
    let additions = prove_ristretto_fp_program_batch(&programs)?;
    let archive = ArchivedRistrettoCanonicalBaseDeckProof {
        aggregate_pk,
        deck,
        additions,
    };
    if crate::ristretto_fp_program_air::ristretto_self_verify_enabled() {
        verify_ristretto_canonical_base_deck(&archive)?;
    }
    Ok(archive)
}

fn validate_ristretto_canonical_base_deck_statement(
    archive: &ArchivedRistrettoCanonicalBaseDeckProof,
) -> TexasAirResult<()> {
    if archive.aggregate_pk == RISTRETTO_IDENTITY {
        return Err(TexasAirError::SpecViolation(
            "canonical base deck aggregate key cannot be the Ristretto identity".into(),
        ));
    }
    if archive.additions.programs.len() != BASE_DECK_ADDITION_ROWS {
        return Err(TexasAirError::ConstraintUnsatisfied(format!(
            "canonical base deck requires exactly {BASE_DECK_ADDITION_ROWS} point-addition rows"
        )));
    }
    let (expected_deck, expected_programs) =
        build_ristretto_canonical_base_deck_rows(&archive.aggregate_pk)?;
    if archive.deck != expected_deck || archive.additions.programs != expected_programs {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "canonical base deck is detached from its fixed generator, cards, key, or row order"
                .into(),
        ));
    }
    Ok(())
}

/// Verify the fixed generator/key chains, ordered card additions, and batch STARK.
pub fn verify_ristretto_canonical_base_deck(
    archive: &ArchivedRistrettoCanonicalBaseDeckProof,
) -> TexasAirResult<()> {
    validate_ristretto_canonical_base_deck_statement(archive)?;
    verify_ristretto_fp_program_batch(&archive.additions)
}

/// Prove all 104 compressed-point additions as rows of one STARK.
pub fn prove_ristretto_reconstruction_deck_accumulator(
    prior: [CanonicalRistrettoCiphertext; CANONICAL_RECONSTRUCTION_CARDS],
    contributions: [CanonicalRistrettoCiphertext; CANONICAL_RECONSTRUCTION_CARDS],
    post: [CanonicalRistrettoCiphertext; CANONICAL_RECONSTRUCTION_CARDS],
) -> TexasAirResult<ArchivedRistrettoReconstructionDeckAccumulatorProof> {
    // Cards are independent equations; build all 104 programs in parallel.
    let rows = (0..CANONICAL_RECONSTRUCTION_CARDS)
        .into_par_iter()
        .map(|index| {
            let (c1, c1_output) = build_ristretto_fp_program_compressed_point_addition(
                &prior[index].c1,
                &contributions[index].c1,
            )?;
            if c1_output != post[index].c1 {
                return Err(TexasAirError::SpecViolation(
                    "reconstruction card c1 post encoding is not prior plus contribution".into(),
                ));
            }
            let (c2, c2_output) = build_ristretto_fp_program_compressed_point_addition(
                &prior[index].c2,
                &contributions[index].c2,
            )?;
            if c2_output != post[index].c2 {
                return Err(TexasAirError::SpecViolation(
                    "reconstruction card c2 post encoding is not prior plus contribution".into(),
                ));
            }
            Ok([c1, c2])
        })
        .collect::<TexasAirResult<Vec<_>>>()?;
    let programs = rows.into_iter().flatten().collect::<Vec<_>>();
    let additions = prove_ristretto_fp_program_batch(&programs)?;
    let archive = ArchivedRistrettoReconstructionDeckAccumulatorProof {
        prior,
        contributions,
        post,
        additions,
    };
    if crate::ristretto_fp_program_air::ristretto_self_verify_enabled() {
        verify_ristretto_reconstruction_deck_accumulator(&archive)?;
    }
    Ok(archive)
}

/// Verify the fixed 52-card accumulator transition and canonical row order.
pub fn verify_ristretto_reconstruction_deck_accumulator(
    archive: &ArchivedRistrettoReconstructionDeckAccumulatorProof,
) -> TexasAirResult<()> {
    if archive.additions.programs.len() != RECONSTRUCTION_ADDITION_ROWS {
        return Err(TexasAirError::ConstraintUnsatisfied(format!(
            "reconstruction deck accumulator requires exactly {RECONSTRUCTION_ADDITION_ROWS} point-addition rows"
        )));
    }
    verify_ristretto_fp_program_batch(&archive.additions)?;
    (0..CANONICAL_RECONSTRUCTION_CARDS).into_par_iter().try_for_each(|index| {
        verify_ristretto_fp_program_compressed_point_addition_row(
            &archive.additions.programs[index * 2],
            &archive.prior[index].c1,
            &archive.contributions[index].c1,
            &archive.post[index].c1,
        )?;
        verify_ristretto_fp_program_compressed_point_addition_row(
            &archive.additions.programs[index * 2 + 1],
            &archive.prior[index].c2,
            &archive.contributions[index].c2,
            &archive.post[index].c2,
        )
    })
}

fn canonical_ciphertext(value: &EncodedCiphertext) -> TexasAirResult<CanonicalRistrettoCiphertext> {
    let c1 = value.c1.as_slice().try_into().map_err(|_| {
        TexasAirError::SpecViolation("Ristretto reconstruction c1 is not 32 bytes".into())
    })?;
    let c2 = value.c2.as_slice().try_into().map_err(|_| {
        TexasAirError::SpecViolation("Ristretto reconstruction c2 is not 32 bytes".into())
    })?;
    Ok(CanonicalRistrettoCiphertext { c1, c2 })
}

/// Bind a 52-card accumulator transition to the authenticated
/// canonical pre-state opening and exact Reconstruction V3 contribution vector.
pub fn verify_ristretto_reconstruction_deck_prestate_request_scope(
    binding: &ArchivedCanonicalReconstructionStateBindingProof,
    accumulator: &ArchivedRistrettoReconstructionDeckAccumulatorProof,
    base_deck: Option<&ArchivedRistrettoCanonicalBaseDeckProof>,
) -> TexasAirResult<()> {
    let request =
        ReconstructionV3VerifyRequest::decode(&binding.request_bytes).map_err(|error| {
            TexasAirError::SerializationError(format!(
                "canonical reconstruction request decoding failed: {error}"
            ))
        })?;
    // The accumulator archive is a public composition entry point.  Do not
    // let it accept an opaque/non-canonical `request.proof` merely because the
    // state-opening and point-addition pieces happen to verify.
    validate_ristretto_reconstruction_proof_wire(&request)?;
    validate_reconstruction_accumulator_opening_request_scope(
        &binding.opening,
        &binding.post_opening,
        &request,
        accumulator,
        base_deck,
    )?;
    verify_canonical_reconstruction_state_binding(binding)?;
    if let Some(base_deck) = base_deck {
        verify_ristretto_canonical_base_deck(base_deck)?;
    }
    verify_ristretto_reconstruction_deck_accumulator(accumulator)
}

fn validate_reconstruction_accumulator_opening_request_scope(
    opening: &crate::canonical_reconstruction_binding::CanonicalReconstructionStateOpening,
    post_opening: &crate::canonical_reconstruction_binding::CanonicalReconstructionStateOpening,
    request: &ReconstructionV3VerifyRequest,
    accumulator: &ArchivedRistrettoReconstructionDeckAccumulatorProof,
    base_deck: Option<&ArchivedRistrettoCanonicalBaseDeckProof>,
) -> TexasAirResult<()> {
    if !post_opening.accumulator_present
        || accumulator.post != post_opening.accumulated_deck
        || request.contributions.len() != CANONICAL_RECONSTRUCTION_CARDS
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "reconstruction deck accumulator is detached from the pre/post state openings or request shape"
                .into(),
        ));
    }
    if opening.accumulator_present {
        if base_deck.is_some() || accumulator.prior != opening.accumulated_deck {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "non-initial reconstruction must use only the authenticated prior accumulator"
                    .into(),
            ));
        }
    } else {
        let base_deck = base_deck.ok_or_else(|| {
            TexasAirError::ConstraintUnsatisfied(
                "initial reconstruction requires the canonical base-deck proof".into(),
            )
        })?;
        if opening.accumulated_deck
            != [CanonicalRistrettoCiphertext::default(); CANONICAL_RECONSTRUCTION_CARDS]
            || base_deck.aggregate_pk != opening.aggregate_pk
            || request.aggregate_pk.as_slice() != base_deck.aggregate_pk
            || base_deck.deck != accumulator.prior
        {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "initial reconstruction base deck is detached from the opening, request, or prior accumulator"
                    .into(),
            ));
        }
        validate_ristretto_canonical_base_deck_statement(base_deck)?;
    }
    for (encoded, contribution) in request.contributions.iter().zip(&accumulator.contributions) {
        if canonical_ciphertext(encoded)? != *contribution {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "reconstruction deck accumulator contribution is detached from the canonical request"
                    .into(),
            ));
        }
    }
    Ok(())
}

/// Verify the currently complete non-final reconstruction composition.
pub fn verify_canonical_reconstruction_accumulator_transition(
    archive: &ArchivedCanonicalReconstructionAccumulatorTransitionProof,
) -> TexasAirResult<()> {
    verify_ristretto_reconstruction_deck_prestate_request_scope(
        &archive.binding,
        &archive.accumulator,
        archive.base_deck.as_ref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical_reconstruction_binding::{
        CanonicalReconstructionSeatState, CanonicalReconstructionStateOpening,
    };
    use crate::texas_canonical::MAX_CANONICAL_SEATS;
    use poker_protocol::precompile_abi::{CurveId, ReconstructionProofSystem, TranscriptId};

    fn basepoint() -> [u8; 32] {
        [
            0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71, 0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00,
            0x51, 0x5f, 0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d, 0xb6, 0xa6, 0x59, 0x45,
            0xe0, 0x8d, 0x2d, 0x76,
        ]
    }

    fn double_basepoint() -> [u8; 32] {
        [
            0x6a, 0x49, 0x32, 0x10, 0xf7, 0x49, 0x9c, 0xd1, 0x7f, 0xec, 0xb5, 0x10, 0xae, 0x0c,
            0xea, 0x23, 0xa1, 0x10, 0xe8, 0xd5, 0xb9, 0x01, 0xf8, 0xac, 0xad, 0xd3, 0x09, 0x5c,
            0x73, 0xa3, 0xb9, 0x19,
        ]
    }

    fn structural_opening(
        accumulator_present: bool,
        deck: [CanonicalRistrettoCiphertext; CANONICAL_RECONSTRUCTION_CARDS],
    ) -> CanonicalReconstructionStateOpening {
        CanonicalReconstructionStateOpening {
            abi_version: 1,
            table_id: 7,
            hand_id: 3,
            max_players: 2,
            reconstruction_epoch: 8_000,
            pending_mask: 0b11,
            aggregate_pk: [3; 32],
            seats: [CanonicalReconstructionSeatState::default(); MAX_CANONICAL_SEATS],
            accumulator_present,
            accumulated_deck: deck,
        }
    }

    fn structural_request(
        contribution: CanonicalRistrettoCiphertext,
    ) -> ReconstructionV3VerifyRequest {
        let encoded = EncodedCiphertext {
            c1: contribution.c1.to_vec(),
            c2: contribution.c2.to_vec(),
        };
        ReconstructionV3VerifyRequest {
            curve: CurveId::Ristretto255,
            proof_system: ReconstructionProofSystem::RistrettoAirV1,
            transcript: TranscriptId::Poseidon252,
            context: Vec::new(),
            call_context: Vec::new(),
            statement_version: 3,
            context_digest: [1; 32],
            reconstruction_epoch: 8_000,
            prior_state_digest: [2; 32],
            aggregate_pk: vec![3; 32],
            owner_pk: vec![4; 32],
            cards: Vec::new(),
            user_readable_cards: Vec::new(),
            contributions: vec![encoded; CANONICAL_RECONSTRUCTION_CARDS],
            proof: Vec::new(),
        }
    }

    fn structural_accumulator(
        prior: [CanonicalRistrettoCiphertext; CANONICAL_RECONSTRUCTION_CARDS],
        contributions: [CanonicalRistrettoCiphertext; CANONICAL_RECONSTRUCTION_CARDS],
        post: [CanonicalRistrettoCiphertext; CANONICAL_RECONSTRUCTION_CARDS],
    ) -> ArchivedRistrettoReconstructionDeckAccumulatorProof {
        ArchivedRistrettoReconstructionDeckAccumulatorProof {
            prior,
            contributions,
            post,
            additions: ArchivedRistrettoFpProgramBatchProof {
                programs: Vec::new(),
                stark_proof_bytes: Vec::new(),
            range_claimed_sum: [0, 0, 0, 0],
            },
        }
    }

    #[test]
    fn accumulator_scope_binds_pre_request_and_post_opening_without_proving_again() {
        let identity = CanonicalRistrettoCiphertext::default();
        let contribution = CanonicalRistrettoCiphertext {
            c1: basepoint(),
            c2: double_basepoint(),
        };
        let prior = [identity; CANONICAL_RECONSTRUCTION_CARDS];
        let contributions = [contribution; CANONICAL_RECONSTRUCTION_CARDS];
        let post = contributions;
        let opening = structural_opening(true, prior);
        let mut post_opening = structural_opening(true, post);
        post_opening.pending_mask = 0b10;
        let request = structural_request(contribution);
        let accumulator = structural_accumulator(prior, contributions, post);
        validate_reconstruction_accumulator_opening_request_scope(
            &opening,
            &post_opening,
            &request,
            &accumulator,
            None,
        )
        .unwrap();

        let mut post_splice = post_opening.clone();
        post_splice.accumulated_deck[0].c1[0] ^= 2;
        assert!(
            validate_reconstruction_accumulator_opening_request_scope(
                &opening,
                &post_splice,
                &request,
                &accumulator,
                None,
            )
            .is_err()
        );

        let mut request_splice = request.clone();
        request_splice.contributions[0].c2[0] ^= 2;
        assert!(
            validate_reconstruction_accumulator_opening_request_scope(
                &opening,
                &post_opening,
                &request_splice,
                &accumulator,
                None,
            )
            .is_err()
        );

        let initial_opening = structural_opening(false, prior);
        assert!(
            validate_reconstruction_accumulator_opening_request_scope(
                &initial_opening,
                &post_opening,
                &request,
                &accumulator,
                None,
            )
            .is_err()
        );
    }

    fn structural_base_deck(aggregate_pk: [u8; 32]) -> ArchivedRistrettoCanonicalBaseDeckProof {
        let (deck, programs) = build_ristretto_canonical_base_deck_rows(&aggregate_pk).unwrap();
        ArchivedRistrettoCanonicalBaseDeckProof {
            aggregate_pk,
            deck,
            additions: ArchivedRistrettoFpProgramBatchProof {
                programs,
                stark_proof_bytes: Vec::new(),
            range_claimed_sum: [0, 0, 0, 0],
            },
        }
    }

    #[test]
    fn canonical_base_deck_has_fixed_generator_key_and_card_row_order() {
        let archive = structural_base_deck(basepoint());
        assert_eq!(archive.additions.programs.len(), BASE_DECK_ADDITION_ROWS);
        validate_ristretto_canonical_base_deck_statement(&archive).unwrap();
        assert_eq!(archive.deck[0].c1, basepoint());
        assert_eq!(archive.deck[1].c1, double_basepoint());

        let mut wrong_basepoint = archive.clone();
        let (wrong_first_row, _) = build_ristretto_fp_program_compressed_point_addition(
            &RISTRETTO_IDENTITY,
            &double_basepoint(),
        )
        .unwrap();
        wrong_basepoint.additions.programs[0] = wrong_first_row;
        assert!(validate_ristretto_canonical_base_deck_statement(&wrong_basepoint).is_err());

        let mut aggregate_key_splice = archive.clone();
        aggregate_key_splice.aggregate_pk = double_basepoint();
        assert!(validate_ristretto_canonical_base_deck_statement(&aggregate_key_splice).is_err());

        let mut generator_row_swap = archive.clone();
        generator_row_swap.additions.programs.swap(0, 1);
        assert!(validate_ristretto_canonical_base_deck_statement(&generator_row_swap).is_err());

        let mut key_row_swap = archive.clone();
        key_row_swap.additions.programs.swap(
            CANONICAL_RECONSTRUCTION_CARDS,
            CANONICAL_RECONSTRUCTION_CARDS + 1,
        );
        assert!(validate_ristretto_canonical_base_deck_statement(&key_row_swap).is_err());

        let mut card_row_swap = archive.clone();
        card_row_swap.additions.programs.swap(
            CANONICAL_RECONSTRUCTION_CARDS * 2,
            CANONICAL_RECONSTRUCTION_CARDS * 2 + 1,
        );
        assert!(validate_ristretto_canonical_base_deck_statement(&card_row_swap).is_err());

        let mut deck_splice = archive;
        deck_splice.deck[0].c2[0] ^= 2;
        assert!(validate_ristretto_canonical_base_deck_statement(&deck_splice).is_err());

        let mut missing_stark = structural_base_deck(basepoint());
        assert!(verify_ristretto_canonical_base_deck(&missing_stark).is_err());
        missing_stark.aggregate_pk = [0; 32];
        assert!(validate_ristretto_canonical_base_deck_statement(&missing_stark).is_err());
    }

    #[test]
    fn initial_scope_requires_base_deck_and_later_scope_forbids_it() {
        let base_deck = structural_base_deck(basepoint());
        let contribution = CanonicalRistrettoCiphertext {
            c1: basepoint(),
            c2: double_basepoint(),
        };
        let contributions = [contribution; CANONICAL_RECONSTRUCTION_CARDS];
        let accumulator = structural_accumulator(base_deck.deck, contributions, contributions);
        let mut opening = structural_opening(
            false,
            [CanonicalRistrettoCiphertext::default(); CANONICAL_RECONSTRUCTION_CARDS],
        );
        opening.aggregate_pk = basepoint();
        let mut post_opening = structural_opening(true, contributions);
        post_opening.aggregate_pk = basepoint();
        let mut request = structural_request(contribution);
        request.aggregate_pk = basepoint().to_vec();

        validate_reconstruction_accumulator_opening_request_scope(
            &opening,
            &post_opening,
            &request,
            &accumulator,
            Some(&base_deck),
        )
        .unwrap();
        assert!(
            validate_reconstruction_accumulator_opening_request_scope(
                &opening,
                &post_opening,
                &request,
                &accumulator,
                None,
            )
            .is_err()
        );

        let later_opening = structural_opening(true, base_deck.deck);
        assert!(
            validate_reconstruction_accumulator_opening_request_scope(
                &later_opening,
                &post_opening,
                &request,
                &accumulator,
                Some(&base_deck),
            )
            .is_err()
        );

        let mut key_splice = base_deck;
        key_splice.aggregate_pk = double_basepoint();
        assert!(
            validate_reconstruction_accumulator_opening_request_scope(
                &opening,
                &post_opening,
                &request,
                &accumulator,
                Some(&key_splice),
            )
            .is_err()
        );
    }

    #[test]
    #[ignore = "timing probe for step-2 optimization"]
    fn timing_single_reconstruction_batch() {
        let prior = CanonicalRistrettoCiphertext { c1: [0; 32], c2: [0; 32] };
        let c1_base_c2_double = CanonicalRistrettoCiphertext {
            c1: basepoint(),
            c2: double_basepoint(),
        };
        let contributions = [c1_base_c2_double; CANONICAL_RECONSTRUCTION_CARDS];
        let post = contributions;
        let t = std::time::Instant::now();
        let deck = prove_ristretto_reconstruction_deck_accumulator(
            [prior; CANONICAL_RECONSTRUCTION_CARDS],
            contributions,
            post,
        )
        .unwrap();
        eprintln!("104-row batch prove: {:.2}s", t.elapsed().as_secs_f64());
        let t = std::time::Instant::now();
        verify_ristretto_reconstruction_deck_accumulator(&deck).unwrap();
        eprintln!("104-row batch verify: {:.2}s", t.elapsed().as_secs_f64());
        let bytes = borsh::to_vec(&deck).map(|v| v.len()).unwrap_or(0);
        eprintln!("proof bytes: {bytes}");
    }

    #[test]
    fn proves_reconstruction_deck_in_one_ordered_batch_stark() {
        let prior = CanonicalRistrettoCiphertext {
            c1: [0; 32],
            c2: [0; 32],
        };
        let c1_base_c2_double = CanonicalRistrettoCiphertext {
            c1: basepoint(),
            c2: double_basepoint(),
        };
        let c1_double_c2_base = CanonicalRistrettoCiphertext {
            c1: double_basepoint(),
            c2: basepoint(),
        };
        let mut contributions = [c1_base_c2_double; CANONICAL_RECONSTRUCTION_CARDS];
        contributions[1] = c1_double_c2_base;
        let post = contributions;
        let deck = prove_ristretto_reconstruction_deck_accumulator(
            [prior; CANONICAL_RECONSTRUCTION_CARDS],
            contributions,
            post,
        )
        .unwrap();
        assert_eq!(deck.additions.programs.len(), RECONSTRUCTION_ADDITION_ROWS);
        verify_ristretto_reconstruction_deck_accumulator(&deck).unwrap();

        let mut prior_splice = deck.clone();
        prior_splice.prior[0].c1[0] ^= 2;
        assert!(verify_ristretto_reconstruction_deck_accumulator(&prior_splice).is_err());

        let mut contribution_splice = deck.clone();
        contribution_splice.contributions[0].c2[0] ^= 2;
        assert!(verify_ristretto_reconstruction_deck_accumulator(&contribution_splice).is_err());

        let mut post_splice = deck.clone();
        post_splice.post[0].c1[0] ^= 2;
        assert!(verify_ristretto_reconstruction_deck_accumulator(&post_splice).is_err());

        let mut c1_c2_row_swap = deck.clone();
        c1_c2_row_swap.additions.programs.swap(0, 1);
        assert!(verify_ristretto_reconstruction_deck_accumulator(&c1_c2_row_swap).is_err());

        let mut card_row_swap = deck.clone();
        card_row_swap.additions.programs.swap(0, 2);
        card_row_swap.additions.programs.swap(1, 3);
        assert!(verify_ristretto_reconstruction_deck_accumulator(&card_row_swap).is_err());

        let mut noncanonical_point = deck.clone();
        noncanonical_point.prior[0].c1 = [0xff; 32];
        assert!(verify_ristretto_reconstruction_deck_accumulator(&noncanonical_point).is_err());

        let mut wrong_addition = deck.clone();
        wrong_addition.additions.programs[0].values[0][0] ^= 2;
        assert!(verify_ristretto_reconstruction_deck_accumulator(&wrong_addition).is_err());

        let mut padding_relabel = deck;
        padding_relabel
            .additions
            .programs
            .push(padding_relabel.additions.programs[103].clone());
        assert!(verify_ristretto_reconstruction_deck_accumulator(&padding_relabel).is_err());
    }
}
