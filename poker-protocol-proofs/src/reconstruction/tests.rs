use super::{reconstruct_deck, ChaumPedersenDLEQProof, OrderedEncryptionProof, ReconstructProof};
use crate::transcript_ext::{CryptoTranscript, MerlinTranscript};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use poker_protocol_core::{
    Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric, RistrettoCurve,
};

type Ciphertext = ElGamalCiphertextGeneric<RistrettoCurve>;

struct Fixture {
    cards: Vec<RistrettoPoint>,
    user_readable_cards: Vec<Ciphertext>,
    output_cards: Vec<Ciphertext>,
    swap_out_cards: Vec<(usize, Ciphertext)>,
    s_vec: Vec<Scalar>,
    user_sk: Scalar,
    user_pk: RistrettoPoint,
}

fn scalar(value: u64) -> Scalar {
    <Scalar as CurveScalar>::from_u64(value)
}

fn fixture(n: usize, swap_indices: &[usize]) -> Fixture {
    let cards = (0..n)
        .map(|i| RistrettoCurve::hash_to_curve(format!("reconstruction-card-{i}").as_bytes()))
        .collect::<Vec<_>>();
    assert!(cards.iter().all(|card| !card.is_identity()));

    let user_sk = scalar(73);
    let user_pk = RistrettoCurve::base_g() * user_sk;
    let user_readable_cards = swap_indices
        .iter()
        .enumerate()
        .map(|(i, index)| Ciphertext::encrypt(&cards[*index], &user_pk, &scalar(1000 + i as u64)))
        .collect::<Vec<_>>();
    let (s_vec, output_cards, swap_out_cards) = reconstruct_deck::<RistrettoCurve>(
        &cards,
        &user_readable_cards,
        &user_sk,
        &user_pk,
        &scalar(7),
    )
    .unwrap();

    Fixture {
        cards,
        user_readable_cards,
        output_cards,
        swap_out_cards,
        s_vec,
        user_sk,
        user_pk,
    }
}

fn prove(fixture: &Fixture, context: &'static [u8]) -> ReconstructProof<RistrettoCurve> {
    let mut transcript = MerlinTranscript::new(context);
    ReconstructProof::prove(
        fixture.cards.clone(),
        fixture.user_readable_cards.clone(),
        fixture.output_cards.clone(),
        fixture.swap_out_cards.clone(),
        &fixture.user_sk,
        &fixture.user_pk,
        fixture.s_vec.clone(),
        &mut transcript,
    )
    .unwrap()
}

fn verify(
    proof: &ReconstructProof<RistrettoCurve>,
    fixture: &Fixture,
    context: &'static [u8],
) -> Result<(), super::VerificationError> {
    let swap_ciphertexts = fixture
        .swap_out_cards
        .iter()
        .map(|(_, ciphertext)| ciphertext.clone())
        .collect::<Vec<_>>();
    let mut transcript = MerlinTranscript::new(context);
    proof.verify(
        &fixture.cards,
        &fixture.output_cards,
        &swap_ciphertexts,
        &fixture.user_readable_cards,
        &fixture.user_pk,
        &mut transcript,
    )
}

#[test]
fn chaum_pedersen_honest_and_tampered() {
    let base_1 = RistrettoCurve::base_g();
    let base_2 = RistrettoCurve::hash_to_curve(b"cp-second-base");
    let witness = scalar(19);
    let point_1 = base_1 * witness;
    let point_2 = base_2 * witness;
    let mut prover_transcript = MerlinTranscript::new(b"cp-test");
    let mut proof = ChaumPedersenDLEQProof::<RistrettoCurve>::prove(
        base_1,
        base_2,
        witness,
        point_1,
        point_2,
        &mut prover_transcript,
    )
    .unwrap();

    let mut verifier_transcript = MerlinTranscript::new(b"cp-test");
    assert!(proof
        .verify(base_1, base_2, point_1, point_2, &mut verifier_transcript)
        .is_ok());

    proof.response += scalar(1);
    let mut verifier_transcript = MerlinTranscript::new(b"cp-test");
    assert!(proof
        .verify(base_1, base_2, point_1, point_2, &mut verifier_transcript)
        .is_err());
}

#[test]
fn reconstruction_v2_honest_2_8_and_52_cards() {
    for (n, indices) in [(2, vec![1]), (8, vec![1, 5]), (52, vec![3, 19, 41])] {
        let fixture = fixture(n, &indices);
        let proof = prove(&fixture, b"reconstruction-v2-honest");
        verify(&proof, &fixture, b"reconstruction-v2-honest").unwrap();
        assert_eq!(proof.padded_swap_cards.len(), n);
        assert_eq!(proof.ordered_encryption_proof.responses.len(), n);
    }
}

#[test]
fn reconstruction_v2_all_cards_swapped() {
    let fixture = fixture(8, &(0..8).collect::<Vec<_>>());
    let proof = prove(&fixture, b"reconstruction-v2-all-swapped");
    verify(&proof, &fixture, b"reconstruction-v2-all-swapped").unwrap();
}

#[test]
fn reconstruction_rejects_duplicate_plaintext_and_swap_index() {
    let mut fixture = fixture(8, &[1, 5]);
    fixture.swap_out_cards[1].0 = fixture.swap_out_cards[0].0;
    let mut transcript = MerlinTranscript::new(b"duplicate-index");
    assert!(ReconstructProof::prove(
        fixture.cards.clone(),
        fixture.user_readable_cards.clone(),
        fixture.output_cards.clone(),
        fixture.swap_out_cards.clone(),
        &fixture.user_sk,
        &fixture.user_pk,
        fixture.s_vec.clone(),
        &mut transcript,
    )
    .is_err());

    let cards = (0..8)
        .map(|i| RistrettoCurve::hash_to_curve(format!("duplicate-card-{i}").as_bytes()))
        .collect::<Vec<_>>();
    let sk = scalar(31);
    let pk = RistrettoCurve::base_g() * sk;
    let readable = Ciphertext::encrypt(&cards[2], &pk, &scalar(90));
    assert!(reconstruct_deck::<RistrettoCurve>(
        &cards,
        &[readable.clone(), readable],
        &sk,
        &pk,
        &scalar(7),
    )
    .is_err());
}

#[test]
fn reconstruction_rejects_out_of_range_swap_index() {
    let mut fixture = fixture(8, &[1, 5]);
    fixture.swap_out_cards[0].0 = fixture.cards.len();
    let mut transcript = MerlinTranscript::new(b"out-of-range-index");
    assert!(ReconstructProof::prove(
        fixture.cards.clone(),
        fixture.user_readable_cards.clone(),
        fixture.output_cards.clone(),
        fixture.swap_out_cards.clone(),
        &fixture.user_sk,
        &fixture.user_pk,
        fixture.s_vec.clone(),
        &mut transcript,
    )
    .is_err());
}

#[test]
fn reconstruction_rejects_tampered_canonical_output() {
    let fixture = fixture(8, &[1, 5]);
    let proof = prove(&fixture, b"tampered-output");
    let mut tampered = fixture.output_cards.clone();
    tampered[3].c2 += RistrettoCurve::base_g();
    let swap_ciphertexts = fixture
        .swap_out_cards
        .iter()
        .map(|(_, ciphertext)| ciphertext.clone())
        .collect::<Vec<_>>();
    let mut transcript = MerlinTranscript::new(b"tampered-output");
    assert!(proof
        .verify(
            &fixture.cards,
            &tampered,
            &swap_ciphertexts,
            &fixture.user_readable_cards,
            &fixture.user_pk,
            &mut transcript,
        )
        .is_err());
}

#[test]
fn reconstruction_rejects_permuted_non_swap_slots() {
    let fixture = fixture(8, &[1, 5]);
    let proof = prove(&fixture, b"permuted-output");
    let mut tampered = fixture.output_cards.clone();
    tampered.swap(2, 4);
    let swap_ciphertexts = fixture
        .swap_out_cards
        .iter()
        .map(|(_, ciphertext)| ciphertext.clone())
        .collect::<Vec<_>>();
    let mut transcript = MerlinTranscript::new(b"permuted-output");
    assert!(proof
        .verify(
            &fixture.cards,
            &tampered,
            &swap_ciphertexts,
            &fixture.user_readable_cards,
            &fixture.user_pk,
            &mut transcript,
        )
        .is_err());
}

#[test]
fn reconstruction_rejects_tampered_padded_swap_vector() {
    let fixture = fixture(8, &[1, 5]);
    let mut proof = prove(&fixture, b"tampered-padded");
    proof.padded_swap_cards[0].c1 += RistrettoCurve::base_g();
    assert!(verify(&proof, &fixture, b"tampered-padded").is_err());
}

#[test]
fn reconstruction_rejects_tampered_swap_or_readable_card() {
    let fixture = fixture(8, &[1, 5]);
    let proof = prove(&fixture, b"tampered-swap");
    let mut swap_ciphertexts = fixture
        .swap_out_cards
        .iter()
        .map(|(_, ciphertext)| ciphertext.clone())
        .collect::<Vec<_>>();
    swap_ciphertexts[0].c2 += RistrettoCurve::base_g();
    let mut transcript = MerlinTranscript::new(b"tampered-swap");
    assert!(proof
        .verify(
            &fixture.cards,
            &fixture.output_cards,
            &swap_ciphertexts,
            &fixture.user_readable_cards,
            &fixture.user_pk,
            &mut transcript,
        )
        .is_err());

    let mut readable = fixture.user_readable_cards.clone();
    readable[0].c2 += RistrettoCurve::base_g();
    let honest_swap_ciphertexts = fixture
        .swap_out_cards
        .iter()
        .map(|(_, ciphertext)| ciphertext.clone())
        .collect::<Vec<_>>();
    let mut transcript = MerlinTranscript::new(b"tampered-swap");
    assert!(proof
        .verify(
            &fixture.cards,
            &fixture.output_cards,
            &honest_swap_ciphertexts,
            &readable,
            &fixture.user_pk,
            &mut transcript,
        )
        .is_err());
}

#[test]
fn reconstruction_rejects_wrong_public_key_and_context() {
    let fixture = fixture(8, &[1, 5]);
    let proof = prove(&fixture, b"bound-context");
    let swap_ciphertexts = fixture
        .swap_out_cards
        .iter()
        .map(|(_, ciphertext)| ciphertext.clone())
        .collect::<Vec<_>>();
    let wrong_pk = RistrettoCurve::base_g() * scalar(99);
    let mut transcript = MerlinTranscript::new(b"bound-context");
    assert!(proof
        .verify(
            &fixture.cards,
            &fixture.output_cards,
            &swap_ciphertexts,
            &fixture.user_readable_cards,
            &wrong_pk,
            &mut transcript,
        )
        .is_err());
    assert!(verify(&proof, &fixture, b"different-context").is_err());
}

#[test]
fn reconstruction_rejects_mixed_ordered_response() {
    let fixture = fixture(8, &[1, 5]);
    let mut proof = prove(&fixture, b"mixed-response");
    proof.ordered_encryption_proof.responses.swap(0, 1);
    assert!(verify(&proof, &fixture, b"mixed-response").is_err());
}

#[test]
fn reconstruction_proofs_are_randomized_without_index_responses() {
    let fixture = fixture(8, &[1, 5]);
    let proof_1 = prove(&fixture, b"randomized-proof");
    let proof_2 = prove(&fixture, b"randomized-proof");
    assert_ne!(
        proof_1.padded_swap_shuffle_proof.c_permutation,
        proof_2.padded_swap_shuffle_proof.c_permutation
    );
    assert_eq!(proof_1.ordered_encryption_proof.responses.len(), 8);
    assert_eq!(proof_1.swap_out_cards_proofs.len(), 2);
}

#[test]
fn ordered_encryption_proof_rejects_different_witness_for_c2() {
    let pk = RistrettoCurve::base_g() * scalar(17);
    let plaintexts = vec![
        RistrettoCurve::hash_to_curve(b"ordered-plaintext-0"),
        RistrettoCurve::hash_to_curve(b"ordered-plaintext-1"),
    ];
    let randomness = vec![scalar(9), scalar(11)];
    let mut ciphertexts = plaintexts
        .iter()
        .zip(&randomness)
        .map(|(plaintext, r)| Ciphertext::encrypt(plaintext, &pk, r))
        .collect::<Vec<_>>();
    ciphertexts[1].c2 += pk;

    let mut transcript = MerlinTranscript::new(b"ordered-mixed-witness");
    assert!(OrderedEncryptionProof::<RistrettoCurve>::prove(
        &plaintexts,
        &ciphertexts,
        &randomness,
        &pk,
        &mut rand_core::OsRng,
        &mut transcript,
    )
    .is_err());
}
