use super::BayerGrothShuffleProof;
use crate::error::VerificationError;
use crate::transcript_ext::{CryptoTranscript, MerlinTranscript};
use poker_protocol_core::{
    Bls12381Curve, Curve, CurveScalar, ElGamalCiphertextGeneric, RistrettoCurve,
};
use rand::seq::SliceRandom;
use rand_core::OsRng;

fn fixture<C: Curve>(
    n: usize,
) -> (
    C::Point,
    Vec<ElGamalCiphertextGeneric<C>>,
    Vec<ElGamalCiphertextGeneric<C>>,
    Vec<usize>,
    Vec<C::Scalar>,
) {
    let secret_key = C::Scalar::random(&mut OsRng);
    let public_key = C::base_g() * secret_key;
    let input: Vec<_> = (0..n)
        .map(|i| {
            let plaintext = C::hash_to_curve(format!("bg12/test/card/{i}").as_bytes());
            let randomness = C::Scalar::random(&mut OsRng);
            ElGamalCiphertextGeneric::<C>::encrypt(&plaintext, &public_key, &randomness)
        })
        .collect();
    let mut permutation: Vec<usize> = (0..n).collect();
    permutation.shuffle(&mut OsRng);
    let rerandomizers: Vec<C::Scalar> = (0..n).map(|_| C::Scalar::random(&mut OsRng)).collect();
    let output = (0..n)
        .map(|i| input[permutation[i]].re_encrypt(&public_key, &rerandomizers[i]))
        .collect();
    (public_key, input, output, permutation, rerandomizers)
}

fn prove<C: Curve>(
    public_key: &C::Point,
    input: &[ElGamalCiphertextGeneric<C>],
    output: &[ElGamalCiphertextGeneric<C>],
    permutation: &[usize],
    rerandomizers: &[C::Scalar],
    context: &'static [u8],
) -> BayerGrothShuffleProof<C> {
    BayerGrothShuffleProof::prove(
        input,
        output,
        permutation,
        rerandomizers,
        public_key,
        &mut OsRng,
        &mut MerlinTranscript::new(context),
    )
    .unwrap()
}

#[test]
fn honest_ristretto_shuffle_verifies() {
    let (pk, input, output, permutation, rerandomizers) = fixture::<RistrettoCurve>(8);
    let proof = prove(
        &pk,
        &input,
        &output,
        &permutation,
        &rerandomizers,
        b"bg12-test",
    );
    assert!(proof
        .verify(
            &input,
            &output,
            &pk,
            &mut MerlinTranscript::new(b"bg12-test")
        )
        .is_ok());
}

#[test]
fn honest_bls_52_card_shuffle_verifies() {
    let (pk, input, output, permutation, rerandomizers) = fixture::<Bls12381Curve>(52);
    let proof = prove(
        &pk,
        &input,
        &output,
        &permutation,
        &rerandomizers,
        b"bg12-bls-52",
    );
    assert!(proof
        .verify(
            &input,
            &output,
            &pk,
            &mut MerlinTranscript::new(b"bg12-bls-52")
        )
        .is_ok());
}

#[test]
fn malformed_permutation_is_rejected() {
    let (pk, input, output, mut permutation, rerandomizers) = fixture::<RistrettoCurve>(8);
    permutation[1] = permutation[0];
    let result = BayerGrothShuffleProof::prove(
        &input,
        &output,
        &permutation,
        &rerandomizers,
        &pk,
        &mut OsRng,
        &mut MerlinTranscript::new(b"bg12-bad-permutation"),
    );
    assert_eq!(result.unwrap_err(), VerificationError::InvalidPermutation);
}

#[test]
fn statement_context_and_proof_tampering_are_rejected() {
    let (pk, input, output, permutation, rerandomizers) = fixture::<RistrettoCurve>(8);
    let proof = prove(
        &pk,
        &input,
        &output,
        &permutation,
        &rerandomizers,
        b"bg12-bound",
    );

    assert!(proof
        .verify(
            &input,
            &output,
            &pk,
            &mut MerlinTranscript::new(b"wrong-context")
        )
        .is_err());

    let mut wrong_output = output.clone();
    wrong_output.swap(0, 1);
    assert!(proof
        .verify(
            &input,
            &wrong_output,
            &pk,
            &mut MerlinTranscript::new(b"bg12-bound")
        )
        .is_err());

    let mut tampered = proof.clone();
    tampered.multi_exponentiation.alpha_response[0] += CScalar::<RistrettoCurve>::one();
    assert!(tampered
        .verify(
            &input,
            &output,
            &pk,
            &mut MerlinTranscript::new(b"bg12-bound")
        )
        .is_err());

    let mut tampered = proof.clone();
    tampered.product.c_d += <RistrettoCurve as Curve>::base_g();
    assert!(tampered
        .verify(
            &input,
            &output,
            &pk,
            &mut MerlinTranscript::new(b"bg12-bound")
        )
        .is_err());
}

type CScalar<C> = <C as Curve>::Scalar;

#[test]
fn proofs_are_randomized() {
    let (pk, input, output, permutation, rerandomizers) = fixture::<RistrettoCurve>(8);
    let proof_a = prove(
        &pk,
        &input,
        &output,
        &permutation,
        &rerandomizers,
        b"bg12-randomized",
    );
    let proof_b = prove(
        &pk,
        &input,
        &output,
        &permutation,
        &rerandomizers,
        b"bg12-randomized",
    );
    assert_ne!(proof_a.c_permutation, proof_b.c_permutation);
    assert_ne!(
        proof_a.multi_exponentiation.c_alpha,
        proof_b.multi_exponentiation.c_alpha
    );
}
