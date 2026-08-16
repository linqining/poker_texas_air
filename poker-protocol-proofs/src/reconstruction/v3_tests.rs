use super::{
    apply_reconstruction_contributions, canonical_base_deck, ContributionBranch,
    ReconstructProofV3, ReconstructionV3Statement, SlotContributionOrProof,
    RECONSTRUCTION_V3_PROOF_LABEL,
};
use crate::transcript_ext::{CryptoTranscript, MerlinTranscript};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use poker_protocol_core::{
    Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric, RistrettoCurve,
};

type Ciphertext = ElGamalCiphertextGeneric<RistrettoCurve>;

struct V3Fixture {
    statement: ReconstructionV3Statement<RistrettoCurve>,
    proof: ReconstructProofV3<RistrettoCurve>,
    aggregate_sk: Scalar,
    selected_indices: Vec<usize>,
}

fn scalar(value: u64) -> Scalar {
    <Scalar as CurveScalar>::from_u64(value)
}

fn fixture(n: usize, selected_indices: &[usize], transcript_label: &'static [u8]) -> V3Fixture {
    let cards = (0..n)
        .map(|i| RistrettoCurve::hash_to_curve(format!("reconstruction-v3-card-{i}").as_bytes()))
        .collect::<Vec<_>>();
    let owner_sk = scalar(73);
    let other_players_sk = scalar(29);
    let aggregate_sk = owner_sk + other_players_sk;
    let owner_pk = RistrettoCurve::base_g() * owner_sk;
    let aggregate_pk = RistrettoCurve::base_g() * aggregate_sk;

    // These model the output of the authenticated prior-hand lineage: after
    // every non-owner reveal token is removed, each card remains encrypted
    // only under owner_pk with hidden accumulated randomness.
    let readable_cards = selected_indices
        .iter()
        .enumerate()
        .map(|(j, index)| Ciphertext::encrypt(&cards[*index], &owner_pk, &scalar(1000 + j as u64)))
        .collect::<Vec<_>>();

    let mut transcript = MerlinTranscript::new(transcript_label);
    let (statement, proof) = ReconstructProofV3::prove(
        [7u8; 32],
        11,
        [9u8; 32],
        cards,
        readable_cards,
        &owner_sk,
        &owner_pk,
        &aggregate_pk,
        &mut rand_core::OsRng,
        &mut transcript,
    )
    .unwrap();

    V3Fixture {
        statement,
        proof,
        aggregate_sk,
        selected_indices: selected_indices.to_vec(),
    }
}

fn verify(
    fixture: &V3Fixture,
    transcript_label: &'static [u8],
) -> Result<(), poker_protocol_core::VerificationError> {
    let mut transcript = MerlinTranscript::new(transcript_label);
    fixture.proof.verify(&fixture.statement, &mut transcript)
}

#[test]
fn reconstruction_v3_honest_and_plaintext_semantics() {
    let fixture = fixture(8, &[1, 5], RECONSTRUCTION_V3_PROOF_LABEL);
    verify(&fixture, RECONSTRUCTION_V3_PROOF_LABEL).unwrap();

    // Each contribution decrypts to exactly zero or -card_i under the common
    // aggregate key.  No public coefficient is needed to inspect randomness.
    for (i, contribution) in fixture.statement.contributions.iter().enumerate() {
        let plaintext = contribution.decrypt(&fixture.aggregate_sk);
        if fixture.selected_indices.contains(&i) {
            assert_eq!(
                plaintext,
                RistrettoPoint::identity() - fixture.statement.cards[i]
            );
        } else {
            assert!(plaintext.is_identity());
        }
    }

    let base_deck = canonical_base_deck::<RistrettoCurve>(
        &fixture.statement.cards,
        &fixture.statement.aggregate_pk,
    )
    .unwrap();
    let rebuilt =
        apply_reconstruction_contributions(&base_deck, &fixture.statement.contributions).unwrap();
    for (i, ciphertext) in rebuilt.iter().enumerate() {
        let plaintext = ciphertext.decrypt(&fixture.aggregate_sk);
        if fixture.selected_indices.contains(&i) {
            assert!(plaintext.is_identity());
        } else {
            assert_eq!(plaintext, fixture.statement.cards[i]);
        }
    }
}

#[test]
fn reconstruction_v3_all_cards_removed() {
    let fixture = fixture(8, &(0..8).collect::<Vec<_>>(), b"reconstruction-v3-all");
    verify(&fixture, b"reconstruction-v3-all").unwrap();
    assert_eq!(fixture.proof.negative_contributions.len(), 8);
    assert_eq!(fixture.proof.slot_membership_proofs.len(), 8);
}

#[test]
fn reconstruction_v3_rejects_statement_and_proof_tampering() {
    let fixture = fixture(8, &[1, 5], b"reconstruction-v3-tamper");

    let mut tampered_statement = fixture.statement.clone();
    tampered_statement.contributions[2].c2 += RistrettoCurve::base_g();
    let mut transcript = MerlinTranscript::new(b"reconstruction-v3-tamper");
    assert!(fixture
        .proof
        .verify(&tampered_statement, &mut transcript)
        .is_err());

    let mut tampered_proof = fixture.proof.clone();
    tampered_proof.negative_contributions[0].c2 += RistrettoCurve::base_g();
    let mut transcript = MerlinTranscript::new(b"reconstruction-v3-tamper");
    assert!(tampered_proof
        .verify(&fixture.statement, &mut transcript)
        .is_err());

    let mut tampered_or = fixture.proof.clone();
    tampered_or.slot_membership_proofs[0].responses[0] += scalar(1);
    let mut transcript = MerlinTranscript::new(b"reconstruction-v3-tamper");
    assert!(tampered_or
        .verify(&fixture.statement, &mut transcript)
        .is_err());
}

#[test]
fn reconstruction_v3_rejects_wrong_context_epoch_and_prior_state() {
    let fixture = fixture(8, &[1, 5], b"reconstruction-v3-binding");

    for mutation in 0..3 {
        let mut statement = fixture.statement.clone();
        match mutation {
            0 => statement.context_digest[0] ^= 1,
            1 => statement.reconstruction_epoch += 1,
            _ => statement.prior_state_digest[0] ^= 1,
        }
        let mut transcript = MerlinTranscript::new(b"reconstruction-v3-binding");
        assert!(fixture.proof.verify(&statement, &mut transcript).is_err());
    }

    assert!(verify(&fixture, b"different-outer-transcript").is_err());
}

#[test]
fn slot_or_rejects_the_v2_misplaced_swap_attack() {
    let card_a = RistrettoCurve::hash_to_curve(b"reconstruction-v3-attack-a");
    let card_b = RistrettoCurve::hash_to_curve(b"reconstruction-v3-attack-b");
    assert_ne!(card_a, card_b);
    let aggregate_pk = RistrettoCurve::base_g() * scalar(91);
    let randomness = scalar(17);

    // Maliciously place Enc(-A) at B's canonical slot.  Bayer--Groth could
    // prove that this ciphertext came from the input multiset, but B's slot OR
    // relation requires Enc(0) or Enc(-B), so witness construction fails.
    let misplaced = Ciphertext::encrypt(
        &(RistrettoPoint::identity() - card_a),
        &aggregate_pk,
        &randomness,
    );
    let mut transcript = MerlinTranscript::new(b"reconstruction-v3-misplaced");
    assert!(SlotContributionOrProof::<RistrettoCurve>::prove(
        &card_b,
        &misplaced,
        &randomness,
        ContributionBranch::NegativeCard,
        &aggregate_pk,
        &mut rand_core::OsRng,
        &mut transcript,
    )
    .is_err());
}

#[test]
fn reconstruction_v3_proofs_are_randomized_without_mapping_fields() {
    let fixture_1 = fixture(8, &[1, 5], b"reconstruction-v3-randomized");
    let fixture_2 = fixture(8, &[1, 5], b"reconstruction-v3-randomized");

    assert_ne!(
        fixture_1.proof.contribution_shuffle_proof.c_permutation,
        fixture_2.proof.contribution_shuffle_proof.c_permutation
    );
    assert_ne!(
        fixture_1.proof.cross_key_proofs[0].response_owner_sk,
        fixture_2.proof.cross_key_proofs[0].response_owner_sk
    );
}
