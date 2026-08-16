//! Leave transition and its batched inverse-remask DLEQ proof.
//!
//! `leave_ciphertext` removes one player's mask:
//! `(c1, c2) -> (c1, c2 - sk*c1)`. `LeaveProof` proves the same non-zero
//! registered `sk` is used for every slot. The strict Rust verifier validates
//! both input and output ciphertexts, exact lengths, non-identity commitments
//! and `c1` invariance; it is intentionally stricter than legacy verifiers.

use crate::dleq_proof::{DLEqProof, LeaveKind};
use crate::error::VerificationError;
use poker_protocol_core::{Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric};
use rand_core::{CryptoRng, RngCore};

/// Type alias for leave DLEq proofs.
pub type LeaveProof<C> = DLEqProof<C, LeaveKind>;

pub fn leave_ciphertext<C: Curve>(
    ct: &ElGamalCiphertextGeneric<C>,
    sk: &C::Scalar,
    pk: &C::Point,
    _rng: &mut (impl CryptoRng + RngCore),
) -> Result<ElGamalCiphertextGeneric<C>, VerificationError> {
    if !ct.is_valid() {
        return Err(VerificationError::InvalidCiphertext);
    }
    if *sk == C::Scalar::zero() {
        return Err(VerificationError::InvalidSecretKey);
    }
    if pk.is_identity() || *pk != C::base_g() * *sk {
        return Err(VerificationError::InvalidPublicKey);
    }
    let mut mask_card = ct.clone();
    mask_card.c2 = mask_card.c2 - mask_card.c1 * *sk;
    if !mask_card.is_valid() {
        return Err(VerificationError::InvalidCiphertext);
    }
    Ok(mask_card)
}

/// Type alias for Ristretto255 LeaveProof (backward compatibility).
pub type RistrettoLeaveProof = LeaveProof<poker_protocol_core::RistrettoCurve>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transcript_ext::{CryptoTranscript, MerlinTranscript};
    use poker_protocol_core::{CurvePoint, CurveScalar, RistrettoCurve};
    use rand_core::OsRng;

    type RistrettoElGamalCiphertext = ElGamalCiphertextGeneric<RistrettoCurve>;

    fn gen_keypair<C: Curve>(rng: &mut (impl CryptoRng + RngCore)) -> (C::Scalar, C::Point) {
        let sk = C::Scalar::random(rng);
        (sk, C::base_g() * sk)
    }

    fn make_leave_pair<C: Curve>(
        input: &ElGamalCiphertextGeneric<C>,
        sk: &C::Scalar,
        _pk: &C::Point,
        _rng: &mut (impl CryptoRng + RngCore),
    ) -> ElGamalCiphertextGeneric<C> {
        ElGamalCiphertextGeneric {
            c1: input.c1,
            c2: input.c2 - input.c1 * *sk,
        }
    }

    #[test]
    fn test_honest_prover_passes() {
        let mut rng = OsRng;
        let (sk, pk) = gen_keypair::<RistrettoCurve>(&mut rng);
        let plaintexts: Vec<_> = (0..RistrettoCurve::n_cards())
            .map(|i| {
                RistrettoCurve::base_h() * <RistrettoCurve as Curve>::Scalar::from_u64(i as u64)
            })
            .collect();
        let r_values: Vec<_> = (0..RistrettoCurve::n_cards())
            .map(|_| <RistrettoCurve as Curve>::Scalar::random(&mut rng))
            .collect();

        let input_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| RistrettoElGamalCiphertext::encrypt(&plaintexts[i], &pk, &r_values[i]))
            .collect();
        // Simulate remask first, then leave
        let remasked_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| ElGamalCiphertextGeneric {
                c1: input_cts[i].c1,
                c2: input_cts[i].c2 + input_cts[i].c1 * sk,
            })
            .collect();
        let output_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| leave_ciphertext(&remasked_cts[i], &sk, &pk, &mut rng).unwrap())
            .collect();

        let proof = LeaveProof::prove(
            &remasked_cts,
            &output_cts,
            &sk,
            &pk,
            &mut MerlinTranscript::new(b"test_honest_prover_passes"),
        );
        assert!(
            proof.verify(
                &remasked_cts,
                &output_cts,
                &pk,
                &mut MerlinTranscript::new(b"test_honest_prover_passes")
            ),
            "honest prover should pass"
        );
    }

    #[test]
    fn test_honest_prover_passes_2() {
        let mut rng = OsRng;
        let (sk, pk) = gen_keypair::<RistrettoCurve>(&mut rng);

        let plaintexts: Vec<_> = (0..RistrettoCurve::n_cards())
            .map(|i| {
                RistrettoCurve::base_g() * <RistrettoCurve as Curve>::Scalar::from_u64(i as u64)
            })
            .collect();
        let r_values: Vec<_> = (0..RistrettoCurve::n_cards())
            .map(|_| <RistrettoCurve as Curve>::Scalar::random(&mut rng))
            .collect();

        // 兼容 Move 合约 M7 修复：使用有效密文（c1/c2 非 identity），而非 identity c1
        let original_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| RistrettoElGamalCiphertext::encrypt(&plaintexts[i], &pk, &r_values[i]))
            .collect();
        // Remask to create input for leave
        let input_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| ElGamalCiphertextGeneric {
                c1: original_cts[i].c1,
                c2: original_cts[i].c2 + original_cts[i].c1 * sk,
            })
            .collect();
        // Leave to create output
        let mut output_cts = Vec::new();
        for i in 0..input_cts.len() {
            let mut mask_card = input_cts[i].clone();
            mask_card.c2 = mask_card.c2 - mask_card.c1 * sk;
            output_cts.push(mask_card);
        }

        let proof = LeaveProof::prove(
            &input_cts,
            &output_cts,
            &sk,
            &pk,
            &mut MerlinTranscript::new(b"test_honest_prover_passes_2"),
        );
        assert!(
            proof.verify(
                &input_cts,
                &output_cts,
                &pk,
                &mut MerlinTranscript::new(b"test_honest_prover_passes_2")
            ),
            "honest prover should pass"
        );
    }

    #[test]
    fn test_honest_prover_passes_3() {
        let mut rng = OsRng;
        let (_sk1, pk1) = gen_keypair::<RistrettoCurve>(&mut rng);
        let plaintexts: Vec<_> = (0..RistrettoCurve::n_cards())
            .map(|i| {
                RistrettoCurve::base_h() * <RistrettoCurve as Curve>::Scalar::from_u64(i as u64)
            })
            .collect();
        let r_values: Vec<_> = (0..RistrettoCurve::n_cards())
            .map(|_| <RistrettoCurve as Curve>::Scalar::random(&mut rng))
            .collect();

        // User1 encrypts
        let input_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| RistrettoElGamalCiphertext::encrypt(&plaintexts[i], &pk1, &r_values[i]))
            .collect();

        // User2 remasks
        let (sk2, pk2) = gen_keypair::<RistrettoCurve>(&mut rng);
        let mut remasked_cts = Vec::new();
        for i in 0..input_cts.len() {
            let mut mask_card = input_cts[i].clone();
            mask_card.c2 = mask_card.c2 + mask_card.c1 * sk2;
            remasked_cts.push(mask_card);
        }

        // User2 leaves
        let mut output_cts = Vec::new();
        for i in 0..remasked_cts.len() {
            let mut mask_card = remasked_cts[i].clone();
            mask_card.c2 = mask_card.c2 - mask_card.c1 * sk2;
            output_cts.push(mask_card);
        }

        let mut transcript = MerlinTranscript::new(b"test_honest_prover_passes_3");
        let proof = LeaveProof::prove(&remasked_cts, &output_cts, &sk2, &pk2, &mut transcript);
        let mut transcript = MerlinTranscript::new(b"test_honest_prover_passes_3");
        assert!(
            proof.verify(&remasked_cts, &output_cts, &pk2, &mut transcript),
            "honest prover should pass"
        );
    }

    #[test]
    fn test_identity_c1_rejected() {
        let mut rng = OsRng;
        let c1 = <RistrettoCurve as Curve>::Point::identity();
        let ct = RistrettoElGamalCiphertext {
            c1: c1,
            c2: <RistrettoCurve as Curve>::Point::random(&mut rng),
        };

        let (sk2, pk2) = gen_keypair::<RistrettoCurve>(&mut rng);

        // c1 is identity, so leave_ciphertext should return Err
        assert!(
            leave_ciphertext(&ct, &sk2, &pk2, &mut rng).is_err(),
            "leave_ciphertext should reject identity c1"
        );
    }

    #[test]
    fn test_wrong_pk_fails() {
        let mut rng = OsRng;
        let (sk, pk) = gen_keypair::<RistrettoCurve>(&mut rng);
        let (_, wrong_pk) = gen_keypair::<RistrettoCurve>(&mut rng);
        let plaintexts: Vec<_> = (0..RistrettoCurve::n_cards())
            .map(|i| {
                RistrettoCurve::base_h() * <RistrettoCurve as Curve>::Scalar::from_u64(i as u64)
            })
            .collect();
        let r_values: Vec<_> = (0..RistrettoCurve::n_cards())
            .map(|_| <RistrettoCurve as Curve>::Scalar::random(&mut rng))
            .collect();

        let input_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| RistrettoElGamalCiphertext::encrypt(&plaintexts[i], &pk, &r_values[i]))
            .collect();
        // Remask first
        let remasked_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| ElGamalCiphertextGeneric {
                c1: input_cts[i].c1,
                c2: input_cts[i].c2 + input_cts[i].c1 * sk,
            })
            .collect();
        let output_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| make_leave_pair(&remasked_cts[i], &sk, &pk, &mut rng))
            .collect();

        let mut transcript = MerlinTranscript::new(b"test_wrong_pk_fails");
        let proof = LeaveProof::prove(&remasked_cts, &output_cts, &sk, &pk, &mut transcript);
        let mut transcript = MerlinTranscript::new(b"test_wrong_pk_fails");
        assert!(
            !proof.verify(&remasked_cts, &output_cts, &wrong_pk, &mut transcript),
            "wrong pk should fail"
        );
    }

    #[test]
    fn test_tampered_output_fails() {
        let mut rng = OsRng;
        let (sk, pk) = gen_keypair::<RistrettoCurve>(&mut rng);
        let plaintexts: Vec<_> = (0..RistrettoCurve::n_cards())
            .map(|i| {
                RistrettoCurve::base_h() * <RistrettoCurve as Curve>::Scalar::from_u64(i as u64)
            })
            .collect();
        let r_values: Vec<_> = (0..RistrettoCurve::n_cards())
            .map(|_| <RistrettoCurve as Curve>::Scalar::random(&mut rng))
            .collect();

        let input_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| RistrettoElGamalCiphertext::encrypt(&plaintexts[i], &pk, &r_values[i]))
            .collect();
        let remasked_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| ElGamalCiphertextGeneric {
                c1: input_cts[i].c1,
                c2: input_cts[i].c2 + input_cts[i].c1 * sk,
            })
            .collect();
        let output_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| make_leave_pair(&remasked_cts[i], &sk, &pk, &mut rng))
            .collect();

        let mut transcript = MerlinTranscript::new(b"test_tampered_output_fails");
        let proof = LeaveProof::prove(&remasked_cts, &output_cts, &sk, &pk, &mut transcript);

        // Tamper: apply leave again on output[0] (double leave)
        let mut tampered = output_cts.clone();
        tampered[0] = make_leave_pair(&tampered[0], &sk, &pk, &mut rng);
        let mut transcript = MerlinTranscript::new(b"test_tampered_output_fails");
        assert!(
            !proof.verify(&remasked_cts, &tampered, &pk, &mut transcript),
            "tampered output should fail"
        );
    }

    #[test]
    fn test_tampered_input_fails() {
        let mut rng = OsRng;
        let (sk, pk) = gen_keypair::<RistrettoCurve>(&mut rng);
        let plaintexts: Vec<_> = (0..RistrettoCurve::n_cards())
            .map(|i| {
                RistrettoCurve::base_h() * <RistrettoCurve as Curve>::Scalar::from_u64(i as u64)
            })
            .collect();
        let r_values: Vec<_> = (0..RistrettoCurve::n_cards())
            .map(|_| <RistrettoCurve as Curve>::Scalar::random(&mut rng))
            .collect();

        let input_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| RistrettoElGamalCiphertext::encrypt(&plaintexts[i], &pk, &r_values[i]))
            .collect();
        let remasked_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| ElGamalCiphertextGeneric {
                c1: input_cts[i].c1,
                c2: input_cts[i].c2 + input_cts[i].c1 * sk,
            })
            .collect();
        let output_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| make_leave_pair(&remasked_cts[i], &sk, &pk, &mut rng))
            .collect();

        let mut transcript = MerlinTranscript::new(b"test_tampered_input_fails");
        let proof = LeaveProof::prove(&remasked_cts, &output_cts, &sk, &pk, &mut transcript);

        let mut tampered = remasked_cts.clone();
        tampered[1] = RistrettoElGamalCiphertext::encrypt(
            &(RistrettoCurve::base_h() * <RistrettoCurve as Curve>::Scalar::from_u64(99u64)),
            &pk,
            &<RistrettoCurve as Curve>::Scalar::random(&mut rng),
        );
        let mut transcript = MerlinTranscript::new(b"test_tampered_input_fails");
        assert!(
            !proof.verify(&tampered, &output_cts, &pk, &mut transcript),
            "tampered input should fail"
        );
    }

    #[test]
    fn test_wrong_prover_sk_fails() {
        let mut rng = OsRng;
        let (sk, pk) = gen_keypair::<RistrettoCurve>(&mut rng);
        let (wrong_sk, _) = gen_keypair::<RistrettoCurve>(&mut rng);
        let plaintexts: Vec<_> = (0..RistrettoCurve::n_cards())
            .map(|i| {
                RistrettoCurve::base_h() * <RistrettoCurve as Curve>::Scalar::from_u64(i as u64)
            })
            .collect();
        let r_values: Vec<_> = (0..RistrettoCurve::n_cards())
            .map(|_| <RistrettoCurve as Curve>::Scalar::random(&mut rng))
            .collect();

        let input_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| RistrettoElGamalCiphertext::encrypt(&plaintexts[i], &pk, &r_values[i]))
            .collect();
        let remasked_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| ElGamalCiphertextGeneric {
                c1: input_cts[i].c1,
                c2: input_cts[i].c2 + input_cts[i].c1 * sk,
            })
            .collect();
        let output_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| make_leave_pair(&remasked_cts[i], &sk, &pk, &mut rng))
            .collect();

        let mut transcript = MerlinTranscript::new(b"test_wrong_prover_sk_fails");
        assert!(
            LeaveProof::try_prove(&remasked_cts, &output_cts, &wrong_sk, &pk, &mut transcript)
                .is_err(),
            "prover must reject a secret key that does not match player_pk"
        );
    }

    #[test]
    fn test_single_card() {
        let mut rng = OsRng;
        let (sk, pk) = gen_keypair::<RistrettoCurve>(&mut rng);
        let pt = RistrettoCurve::base_h() * <RistrettoCurve as Curve>::Scalar::from_u64(42u64);
        let r = <RistrettoCurve as Curve>::Scalar::random(&mut rng);
        let input: RistrettoElGamalCiphertext = RistrettoElGamalCiphertext::encrypt(&pt, &pk, &r);
        // Remask first
        let remasked: RistrettoElGamalCiphertext = RistrettoElGamalCiphertext {
            c1: input.c1,
            c2: input.c2 + input.c1 * sk,
        };
        let output = make_leave_pair(&remasked, &sk, &pk, &mut rng);

        let mut transcript = MerlinTranscript::new(b"test_single_card");
        let proof = LeaveProof::prove(
            &[remasked.clone()],
            &[output.clone()],
            &sk,
            &pk,
            &mut transcript,
        );
        let mut transcript = MerlinTranscript::new(b"test_single_card");
        assert!(
            proof.verify(&[remasked], &[output], &pk, &mut transcript),
            "single card should pass"
        );
    }

    #[test]
    fn test_single_card_two_user() {
        let mut rng = OsRng;
        let (sk1, pk1) = gen_keypair::<RistrettoCurve>(&mut rng);
        let pt = RistrettoCurve::base_g() * <RistrettoCurve as Curve>::Scalar::from_u64(42u64);
        let input = RistrettoElGamalCiphertext {
            c1: <RistrettoCurve as Curve>::Point::identity(),
            c2: pt,
        };
        let r_prime = <RistrettoCurve as Curve>::Scalar::random(&mut rng);
        let enc_one = input.re_encrypt(&pk1, &r_prime);

        // User2 remasks
        let (sk2, pk2) = gen_keypair::<RistrettoCurve>(&mut rng);
        let mut remasked = enc_one.clone();
        remasked.c2 = remasked.c2 + remasked.c1 * sk2;

        // User2 leaves
        let mut output = remasked.clone();
        output.c2 = output.c2 - output.c1 * sk2;

        let mut transcript = MerlinTranscript::new(b"test_single_card_two_user");
        let proof = LeaveProof::prove(
            &[remasked.clone()],
            &[output.clone()],
            &sk2,
            &pk2,
            &mut transcript,
        );
        let mut transcript = MerlinTranscript::new(b"test_single_card_two_user");
        assert!(
            proof.verify(
                &[remasked.clone()],
                &[output.clone()],
                &pk2,
                &mut transcript
            ),
            "single card should pass"
        );

        // Verify decryption: after user2 leaves, we should get back enc_one
        let reveal_token1 = output.gen_reveal_token(&sk1);
        let decrypted = output.c2 - reveal_token1;
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn test_single_card_one_user() {
        let mut rng = OsRng;
        let (sk, pk) = gen_keypair::<RistrettoCurve>(&mut rng);
        let pt = RistrettoCurve::base_g() * <RistrettoCurve as Curve>::Scalar::from_u64(42u64);
        // 兼容 Move 合约 M7 修复：使用有效密文（c1/c2 非 identity）
        let r = <RistrettoCurve as Curve>::Scalar::random(&mut rng);
        let input = RistrettoElGamalCiphertext::encrypt(&pt, &pk, &r);
        // Remask
        let mut remasked = input.clone();
        remasked.c2 = remasked.c2 + remasked.c1 * sk;

        // Leave
        let mut output = remasked.clone();
        output.c2 = output.c2 - output.c1 * sk;

        let mut transcript = MerlinTranscript::new(b"test_single_card_one_user");
        let proof = LeaveProof::prove(
            &[remasked.clone()],
            &[output.clone()],
            &sk,
            &pk,
            &mut transcript,
        );
        let mut transcript = MerlinTranscript::new(b"test_single_card_one_user");
        assert!(
            proof.verify(&[remasked.clone()], &[output.clone()], &pk, &mut transcript),
            "single card should pass"
        );

        let reveal_token1 = output.clone().gen_reveal_token(&sk);
        let decrypted = output.c2 - reveal_token1;
        assert_eq!(decrypted, pt);
    }

    /// SECURITY FIX VERIFICATION: LeaveProof per-card DLEq prevents
    /// aggregate manipulation attacks.
    #[test]
    fn test_forgery_individual_card_manipulation() {
        let mut rng = OsRng;
        let (sk, pk) = gen_keypair::<RistrettoCurve>(&mut rng);

        let plaintexts: Vec<_> = (0..RistrettoCurve::n_cards())
            .map(|i| {
                RistrettoCurve::base_h() * <RistrettoCurve as Curve>::Scalar::from_u64(i as u64)
            })
            .collect();
        let r_values: Vec<_> = (0..RistrettoCurve::n_cards())
            .map(|_| <RistrettoCurve as Curve>::Scalar::random(&mut rng))
            .collect();

        let input_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| RistrettoElGamalCiphertext::encrypt(&plaintexts[i], &pk, &r_values[i]))
            .collect();
        // Remask first
        let remasked_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| ElGamalCiphertextGeneric {
                c1: input_cts[i].c1,
                c2: input_cts[i].c2 + input_cts[i].c1 * sk,
            })
            .collect();
        let output_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| leave_ciphertext(&remasked_cts[i], &sk, &pk, &mut rng).unwrap())
            .collect();

        // Verify honest proof passes
        let mut transcript = MerlinTranscript::new(b"test_forgery_individual_card_manipulation");
        let honest_proof = LeaveProof::prove(&remasked_cts, &output_cts, &sk, &pk, &mut transcript);
        let mut transcript = MerlinTranscript::new(b"test_forgery_individual_card_manipulation");
        assert!(
            honest_proof.verify(&remasked_cts, &output_cts, &pk, &mut transcript),
            "honest proof should pass"
        );

        // Attack: modify output_cts[0].c2 by a random perturbation
        let mut forged_output_cts = output_cts.clone();
        let delta = <RistrettoCurve as Curve>::Scalar::random(&mut rng);
        let delta_point = RistrettoCurve::base_g() * delta;
        forged_output_cts[0].c2 = forged_output_cts[0].c2 + delta_point;

        // Verify the forged output_cts[0] is NOT a valid leave
        let forged_d2_0 = remasked_cts[0].c2 - forged_output_cts[0].c2;
        let expected_d2_0 = remasked_cts[0].c1 * sk;
        assert_ne!(
            forged_d2_0, expected_d2_0,
            "forged output_cts[0] should NOT be a valid leave"
        );

        // Strict proving rejects the malformed per-card relation.
        let mut transcript = MerlinTranscript::new(b"test_forgery_leave_proof_forged");
        assert!(
            LeaveProof::try_prove(&remasked_cts, &forged_output_cts, &sk, &pk, &mut transcript)
                .is_err(),
            "strict prover should reject manipulated output_cts"
        );
    }

    /// FORGERY: 当 c1 = identity 时，per-card DLEq 退化
    #[test]
    fn test_forgery_identity_c1_vacuous_check() {
        let mut rng = OsRng;
        let (sk, pk) = gen_keypair::<RistrettoCurve>(&mut rng);

        // Create input with c1 = identity
        let pt = RistrettoCurve::base_h() * <RistrettoCurve as Curve>::Scalar::from_u64(42u64);
        let input = RistrettoElGamalCiphertext {
            c1: <RistrettoCurve as Curve>::Point::identity(),
            c2: pt,
        };

        // leave_ciphertext rejects identity c1
        assert!(
            leave_ciphertext(&input, &sk, &pk, &mut rng).is_err(),
            "leave_ciphertext should reject identity c1"
        );

        // Manually construct output (identity * sk = identity, so c2 unchanged)
        let mut manual_output = input.clone();
        manual_output.c2 = manual_output.c2 - manual_output.c1 * sk; // identity * sk = identity

        // Manual output and input are identical
        assert_eq!(
            manual_output.c2, input.c2,
            "c2 unchanged when c1 is identity"
        );

        // 兼容 Move 合约 M7 修复：verify 现在拒绝 identity c1 密文
        let mut transcript = MerlinTranscript::new(b"test_identity_c1");
        assert!(LeaveProof::try_prove(
            &[input.clone()],
            &[manual_output.clone()],
            &sk,
            &pk,
            &mut transcript,
        )
        .is_err());

        // Tampered output should also be rejected (identity c1)
        let mut tampered_output = manual_output.clone();
        tampered_output.c2 = tampered_output.c2 + RistrettoCurve::base_g();
        let mut transcript2 = MerlinTranscript::new(b"test_identity_c1_tampered");
        assert!(LeaveProof::try_prove(
            &[input.clone()],
            &[tampered_output.clone()],
            &sk,
            &pk,
            &mut transcript2,
        )
        .is_err());
    }

    #[test]
    fn test_leave_restores_original() {
        let mut rng = OsRng;
        let (sk, pk) = gen_keypair::<RistrettoCurve>(&mut rng);
        let plaintexts: Vec<_> = (0..RistrettoCurve::n_cards())
            .map(|i| {
                RistrettoCurve::base_h() * <RistrettoCurve as Curve>::Scalar::from_u64(i as u64)
            })
            .collect();
        let r_values: Vec<_> = (0..RistrettoCurve::n_cards())
            .map(|_| <RistrettoCurve as Curve>::Scalar::random(&mut rng))
            .collect();

        let input_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| RistrettoElGamalCiphertext::encrypt(&plaintexts[i], &pk, &r_values[i]))
            .collect();

        // Remask then leave should restore original
        let remasked_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| ElGamalCiphertextGeneric {
                c1: input_cts[i].c1,
                c2: input_cts[i].c2 + input_cts[i].c1 * sk,
            })
            .collect();
        let output_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| leave_ciphertext(&remasked_cts[i], &sk, &pk, &mut rng).unwrap())
            .collect();

        // After leave, output should equal input
        for i in 0..RistrettoCurve::n_cards() {
            assert_eq!(output_cts[i].c1, input_cts[i].c1, "c1 should be preserved");
            assert_eq!(
                output_cts[i].c2, input_cts[i].c2,
                "c2 should be restored after leave"
            );
        }
    }
}
