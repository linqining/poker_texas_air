//! BN254 direct-sigma instantiation of the curve-generic proof suite
//! (DUAL_PROOF_PROTOCOL.md §3.3: the sigma stack is the production P-proof
//! stack, instantiated on BN254 G1 with the FiatShamirSha3 transcript).
//!
//! These tests are the Rust side of the Rust↔Cairo cross-validation plan
//! (§4.2): the same statements and challenge schedules must be replayed by
//! the Cairo verifier, so any semantic drift shows up here first.

use poker_protocol_core::{
    Bn254Curve, Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric,
};
use poker_protocol_proofs::bayer_groth::BayerGrothShuffleProof;
use poker_protocol_proofs::dleq_proof::{DLEqProof, LeaveKind, RemaskKind};
use poker_protocol_proofs::pk_ownership::PKOwnershipProof;
use poker_protocol_proofs::reveal_token_proof::RevealTokenProof;
use poker_protocol_proofs::transcript_ext::FiatShamirTranscript;
use poker_protocol_proofs::CryptoTranscript;
use rand_core::{CryptoRng, RngCore};

type Bn = Bn254Curve;
type BnScalar = <Bn as Curve>::Scalar;
type BnPoint = <Bn as Curve>::Point;
type BnCt = ElGamalCiphertextGeneric<Bn>;

fn transcript(label: &'static str) -> FiatShamirTranscript {
    FiatShamirTranscript::new(label.as_bytes())
}

fn random_scalar(rng: &mut (impl CryptoRng + RngCore)) -> BnScalar {
    <Bn as Curve>::Scalar::random(rng)
}

fn encrypt_deck(
    deck: &[BnPoint],
    pk: &BnPoint,
    rng: &mut (impl CryptoRng + RngCore),
) -> Vec<BnCt> {
    deck.iter()
        .map(|card| {
            let r = random_scalar(rng);
            BnCt::encrypt(card, pk, &r)
        })
        .collect()
}

#[test]
fn bn254_pk_ownership_roundtrip_and_rejection() {
    let sk = random_scalar(&mut rand_core::OsRng);
    let pk = Bn::base_g() * &sk;
    let proof = PKOwnershipProof::<Bn>::prove(&sk, &pk, &mut rand_core::OsRng);
    assert!(proof.verify(&pk));
    assert!(!proof.verify(&(Bn::base_g() * random_scalar(&mut rand_core::OsRng))));

    // Zero secret key must be rejected at prove time.
    let zero = BnScalar::zero();
    assert!(PKOwnershipProof::<Bn>::try_prove(&zero, &BnPoint::identity(), &mut rand_core::OsRng)
        .is_err());
}

#[test]
fn bn254_bg_shuffle_roundtrip_and_tamper_rejection() {
    let deck: Vec<BnPoint> = (0..8)
        .map(|i| Bn::hash_to_curve(format!("texas_poker_bn254/card/{i}").as_bytes()))
        .collect();
    let sk = random_scalar(&mut rand_core::OsRng);
    let pk = Bn::base_g() * &sk;
    let input = encrypt_deck(&deck, &pk, &mut rand_core::OsRng);

    let permutation = [3usize, 0, 7, 5, 1, 6, 2, 4];
    let rerandomizers: Vec<BnScalar> = (0..deck.len()).map(|_| random_scalar(&mut rand_core::OsRng)).collect();
    let output: Vec<BnCt> = permutation
        .iter()
        .enumerate()
        .map(|(out_i, &in_i)| input[in_i].re_encrypt(&pk, &rerandomizers[out_i]))
        .collect();

    let mut prove_transcript = transcript("bn254_bg_shuffle_v3");
    let proof = BayerGrothShuffleProof::<Bn>::prove(
        &input,
        &output,
        &permutation,
        &rerandomizers,
        &pk,
        &mut rand_core::OsRng,
        &mut prove_transcript,
    )
    .expect("valid shuffle statement proves");

    let mut verify_transcript = transcript("bn254_bg_shuffle_v3");
    proof
        .verify(&input, &output, &pk, &mut verify_transcript)
        .expect("honest shuffle verifies");

    // Tampered output breaks the statement → verify fails.
    let mut tampered = output.clone();
    tampered[0] = input[0].re_encrypt(&pk, &random_scalar(&mut rand_core::OsRng));
    let mut tamper_transcript = transcript("bn254_bg_shuffle_v3");
    assert!(proof.verify(&input, &tampered, &pk, &mut tamper_transcript).is_err());

    // A different transcript domain must not verify (cross-protocol binding).
    let mut wrong_domain = transcript("bn254_bg_shuffle_v4");
    assert!(proof.verify(&input, &output, &pk, &mut wrong_domain).is_err());
}

#[test]
#[ignore = "52-card full-deck BG proof: run with `cargo test --release -- --ignored`"]
fn bn254_bg_shuffle_full_deck_52() {
    let deck: Vec<BnPoint> = (0..52)
        .map(|i| Bn::hash_to_curve(format!("texas_poker_bn254/card/{i}").as_bytes()))
        .collect();
    let sk = random_scalar(&mut rand_core::OsRng);
    let pk = Bn::base_g() * &sk;
    let input = encrypt_deck(&deck, &pk, &mut rand_core::OsRng);

    let permutation: Vec<usize> = {
        // Deterministic full-cycle permutation (rotate by 17, coprime with 52).
        (0..52).map(|i| (i * 17 + 3) % 52).collect()
    };
    let rerandomizers: Vec<BnScalar> = (0..52).map(|_| random_scalar(&mut rand_core::OsRng)).collect();
    let output: Vec<BnCt> = permutation
        .iter()
        .enumerate()
        .map(|(out_i, &in_i)| input[in_i].re_encrypt(&pk, &rerandomizers[out_i]))
        .collect();

    let mut prove_transcript = transcript("bn254_bg_shuffle_v3");
    let proof = BayerGrothShuffleProof::<Bn>::prove(
        &input,
        &output,
        &permutation,
        &rerandomizers,
        &pk,
        &mut rand_core::OsRng,
        &mut prove_transcript,
    )
    .expect("52-card shuffle proves");

    let mut verify_transcript = transcript("bn254_bg_shuffle_v3");
    proof
        .verify(&input, &output, &pk, &mut verify_transcript)
        .expect("52-card shuffle verifies");
}

#[test]
fn bn254_fold_leave_dleq_roundtrip_and_tamper_rejection() {
    let deck: Vec<BnPoint> = (0..6)
        .map(|i| Bn::hash_to_curve(format!("texas_poker_bn254/card/{i}").as_bytes()))
        .collect();
    let sk = random_scalar(&mut rand_core::OsRng);
    let pk = Bn::base_g() * &sk;
    let input = encrypt_deck(&deck, &pk, &mut rand_core::OsRng);

    // Leave/fold: remove the player's key layer, out_c2 = in_c2 - c1*sk.
    let output: Vec<BnCt> = input
        .iter()
        .map(|ct| BnCt {
            c1: ct.c1,
            c2: ct.c2 - ct.c1 * &sk,
        })
        .collect();

    let mut prove_transcript = transcript("bn254_fold_leave_v3");
    let proof = DLEqProof::<Bn, LeaveKind>::prove(
        &input,
        &output,
        &sk,
        &pk,
        &mut prove_transcript,
    );
    let mut verify_transcript = transcript("bn254_fold_leave_v3");
    assert!(proof.verify(&input, &output, &pk, &mut verify_transcript));

    // Remask direction: out_c2 = in_c2 + c1*sk2 for a second key layer.
    let sk2 = random_scalar(&mut rand_core::OsRng);
    let remasked: Vec<BnCt> = input.iter().map(|ct| ct.remask(&sk2)).collect();
    let mut remask_prove = transcript("bn254_remask_v3");
    let remask_proof = DLEqProof::<Bn, RemaskKind>::prove(
        &input,
        &remasked,
        &sk2,
        &(Bn::base_g() * &sk2),
        &mut remask_prove,
    );
    let mut remask_verify = transcript("bn254_remask_v3");
    assert!(remask_proof.verify(&input, &remasked, &(Bn::base_g() * &sk2), &mut remask_verify));

    // Cross-kind forgery: a remask proof must not validate a leave transition.
    let mut cross = transcript("bn254_remask_v3");
    assert!(!remask_proof.verify(&input, &output, &pk, &mut cross));

    // Tampered output (wrong direction) must fail leave verification.
    let tampered: Vec<BnCt> = input.iter().map(|ct| ct.remask(&sk)).collect();
    let mut tamper_verify = transcript("bn254_fold_leave_v3");
    assert!(!proof.verify(&input, &tampered, &pk, &mut tamper_verify));
}

#[test]
fn bn254_reveal_tokens_roundtrip_and_wrong_key_rejection() {
    let deck: Vec<BnPoint> = (0..5)
        .map(|i| Bn::hash_to_curve(format!("texas_poker_bn254/card/{i}").as_bytes()))
        .collect();
    let sk = random_scalar(&mut rand_core::OsRng);
    let pk = Bn::base_g() * &sk;
    let ciphertexts = encrypt_deck(&deck, &pk, &mut rand_core::OsRng);

    for (ct, card) in ciphertexts.iter().zip(&deck) {
        let token = ct.gen_reveal_token(&sk);
        assert_eq!(ct.c2 - &token, *card, "decryption via token recovers card");

        let mut prove_transcript = transcript("bn254_reveal_token_v3");
        let proof = RevealTokenProof::<Bn>::prove(
            &sk,
            &pk,
            ct,
            &token,
            &mut rand_core::OsRng,
            &mut prove_transcript,
        );
        let mut verify_transcript = transcript("bn254_reveal_token_v3");
        proof.verify(ct, &token, &pk, &mut verify_transcript).expect("honest token verifies");

        // Wrong key binding must be rejected.
        let wrong_pk = Bn::base_g() * random_scalar(&mut rand_core::OsRng);
        let mut wrong_key_verify = transcript("bn254_reveal_token_v3");
        assert!(proof.verify(ct, &token, &wrong_pk, &mut wrong_key_verify).is_err());

        // A forged token must be rejected.
        let forged = ct.c1 * random_scalar(&mut rand_core::OsRng);
        let mut forged_verify = transcript("bn254_reveal_token_v3");
        assert!(proof.verify(ct, &forged, &pk, &mut forged_verify).is_err());
    }
}

#[test]
fn bn254_three_player_hand_end_to_end() {
    // Mini mental-poker hand over BN254: 3 players register keys, the
    // aggregate-key deck is shuffled 3× (each shuffle proven), a player
    // folds (leave DLEQ), and the remaining layers decrypt to the cards.
    const N: usize = 8;
    let deck: Vec<BnPoint> = (0..N)
        .map(|i| Bn::hash_to_curve(format!("texas_poker_bn254/card/{i}").as_bytes()))
        .collect();

    let sks: Vec<BnScalar> = (0..3).map(|_| random_scalar(&mut rand_core::OsRng)).collect();
    let pks: Vec<BnPoint> = sks.iter().map(|sk| Bn::base_g() * sk).collect();

    // Ownership proofs for every seat.
    for (sk, pk) in sks.iter().zip(&pks) {
        let proof = PKOwnershipProof::<Bn>::prove(sk, pk, &mut rand_core::OsRng);
        assert!(proof.verify(pk));
    }

    // Aggregate key: pk_A = sk_A * G summed over players (curve Add semantics).
    let aggregate_pk = pks.iter().fold(<Bn as Curve>::Point::identity(), |acc, pk| acc + *pk);
    let mut deck_cts = encrypt_deck(&deck, &aggregate_pk, &mut rand_core::OsRng);

    // Three sequential proven shuffles.
    for round in 0..3 {
        let permutation: Vec<usize> = if round % 2 == 0 {
            (0..N).rev().collect()
        } else {
            (0..N).map(|i| (i + 3) % N).collect()
        };
        let rerandomizers: Vec<BnScalar> =
            (0..N).map(|_| random_scalar(&mut rand_core::OsRng)).collect();
        let output: Vec<BnCt> = permutation
            .iter()
            .enumerate()
            .map(|(out_i, &in_i)| deck_cts[in_i].re_encrypt(&aggregate_pk, &rerandomizers[out_i]))
            .collect();

        let mut prove_transcript = transcript("bn254_bg_shuffle_v3");
        let proof = BayerGrothShuffleProof::<Bn>::prove(
            &deck_cts,
            &output,
            &permutation,
            &rerandomizers,
            &aggregate_pk,
            &mut rand_core::OsRng,
            &mut prove_transcript,
        )
        .expect("shuffle proves");
        let mut verify_transcript = transcript("bn254_bg_shuffle_v3");
        proof
            .verify(&deck_cts, &output, &aggregate_pk, &mut verify_transcript)
            .expect("shuffle verifies");
        deck_cts = output;
    }

    // Player 1 folds: strip its key layer from every ciphertext, proven by a
    // batch leave DLEQ.
    let folded: Vec<BnCt> = deck_cts
        .iter()
        .map(|ct| BnCt {
            c1: ct.c1,
            c2: ct.c2 - ct.c1 * &sks[1],
        })
        .collect();
    let mut fold_prove = transcript("bn254_fold_leave_v3");
    let fold_proof = DLEqProof::<Bn, LeaveKind>::prove(
        &deck_cts,
        &folded,
        &sks[1],
        &pks[1],
        &mut fold_prove,
    );
    let mut fold_verify = transcript("bn254_fold_leave_v3");
    assert!(fold_proof.verify(&deck_cts, &folded, &pks[1], &mut fold_verify));
    deck_cts = folded;

    // Remaining players reveal tokens and decrypt to recover the deck.
    for ct in &deck_cts {
        let mut plaintext = ct.c2;
        for sk in [&sks[0], &sks[2]] {
            let token = ct.gen_reveal_token(sk);
            let mut token_prove = transcript("bn254_reveal_token_v3");
            let proof = RevealTokenProof::<Bn>::prove(
                sk,
                &(Bn::base_g() * sk),
                ct,
                &token,
                &mut rand_core::OsRng,
                &mut token_prove,
            );
            let mut token_verify = transcript("bn254_reveal_token_v3");
            proof
                .verify(ct, &token, &(Bn::base_g() * sk), &mut token_verify)
                .expect("reveal token verifies");
            plaintext = plaintext - token;
        }
        assert!(
            deck.iter().any(|card| card == &plaintext),
            "decrypted plaintext must be a canonical card"
        );
    }
}
