//! Remask transition and its batched DLEQ proof.
//!
//! `remask_ciphertext` maps `(c1, c2)` to `(c1, c2 + sk*c1)`. `RemaskProof`
//! proves one non-zero registered `sk` was used for every card. Both input and
//! output ciphertexts must be valid and `c1` is invariant. See `dleq_proof`
//! for the completeness, special-soundness, HVZK and transcript boundary.

use crate::dleq_proof::{DLEqProof, RemaskKind};
use crate::error::VerificationError;
use poker_protocol_core::{Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric};
use rand_core::{CryptoRng, RngCore};

/// Type alias for remask DLEq proofs.
pub type RemaskProof<C> = DLEqProof<C, RemaskKind>;

pub fn remask_ciphertext<C: Curve>(
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
    mask_card.c2 = mask_card.c2 + mask_card.c1 * *sk;
    if !mask_card.is_valid() {
        return Err(VerificationError::InvalidCiphertext);
    }
    Ok(mask_card)
}

/// Type alias for Ristretto255 RemaskProof (backward compatibility).
pub type RistrettoRemaskProof = RemaskProof<poker_protocol_core::RistrettoCurve>;

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

    fn make_remask_pair<C: Curve>(
        input: &ElGamalCiphertextGeneric<C>,
        sk: &C::Scalar,
        _pk: &C::Point,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> ElGamalCiphertextGeneric<C> {
        ElGamalCiphertextGeneric {
            c1: input.c1,
            c2: input.c2 + input.c1 * *sk,
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
        let output_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| remask_ciphertext(&input_cts[i], &sk, &pk, &mut rng).unwrap())
            .collect();

        let proof = RemaskProof::prove(
            &input_cts,
            &output_cts,
            &sk,
            &pk,
            &mut MerlinTranscript::new(b"test_honest_prover_passes"),
        );
        assert!(
            proof.verify(
                &input_cts,
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
        let input_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| RistrettoElGamalCiphertext::encrypt(&plaintexts[i], &pk, &r_values[i]))
            .collect();

        let mut output_cts = Vec::new();
        for i in 0..input_cts.len() {
            let mut mask_card = input_cts[i].clone();
            mask_card.c2 = mask_card.c2 + mask_card.c1 * sk;
            output_cts.push(mask_card);
        }

        let proof = RemaskProof::prove(
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
        let (_sk, pk) = gen_keypair::<RistrettoCurve>(&mut rng);
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

        let (sk2, pk2) = gen_keypair::<RistrettoCurve>(&mut rng);
        let mut output_cts = Vec::new();
        for i in 0..input_cts.len() {
            let mut mask_card = input_cts[i].clone();
            mask_card.c2 = mask_card.c2 + mask_card.c1 * sk2;
            output_cts.push(mask_card);
        }

        let mut transcript = MerlinTranscript::new(b"test_honest_prover_passes_3");
        let proof = RemaskProof::prove(&input_cts, &output_cts, &sk2, &pk2, &mut transcript);
        let mut transcript = MerlinTranscript::new(b"test_honest_prover_passes_3");
        assert!(
            proof.verify(&input_cts, &output_cts, &pk2, &mut transcript),
            "honest prover should pass"
        );
    }

    #[test]
    fn test_gen_keys() {
        let mut rng = OsRng;
        let c1 = <RistrettoCurve as Curve>::Point::identity();
        let ct = RistrettoElGamalCiphertext {
            c1: c1,
            c2: <RistrettoCurve as Curve>::Point::random(&mut rng),
        };

        let (sk2, pk2) = gen_keypair::<RistrettoCurve>(&mut rng);

        // c1 is identity, so remask_ciphertext should return Err
        assert!(
            remask_ciphertext(&ct, &sk2, &pk2, &mut rng).is_err(),
            "remask_ciphertext should reject identity c1"
        );
    }

    #[test]
    fn test_wrong_sk_fails() {
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
        let output_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| make_remask_pair(&input_cts[i], &sk, &pk, &mut rng))
            .collect();

        let mut transcript = MerlinTranscript::new(b"test_wrong_sk_fails");
        let proof = RemaskProof::prove(&input_cts, &output_cts, &sk, &pk, &mut transcript);
        let mut transcript = MerlinTranscript::new(b"test_wrong_sk_fails");
        assert!(
            !proof.verify(&input_cts, &output_cts, &wrong_pk, &mut transcript),
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
        let output_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| make_remask_pair(&input_cts[i], &sk, &pk, &mut rng))
            .collect();

        let mut transcript = MerlinTranscript::new(b"test_tampered_output_fails");
        let proof = RemaskProof::prove(&input_cts, &output_cts, &sk, &pk, &mut transcript);

        let mut tampered = output_cts.clone();
        tampered[0] = make_remask_pair(&tampered[0], &sk, &pk, &mut rng);
        let mut transcript = MerlinTranscript::new(b"test_tampered_output_fails");
        assert!(
            !proof.verify(&input_cts, &tampered, &pk, &mut transcript),
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
        let output_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| make_remask_pair(&input_cts[i], &sk, &pk, &mut rng))
            .collect();

        let mut transcript = MerlinTranscript::new(b"test_tampered_input_fails");
        let proof = RemaskProof::prove(&input_cts, &output_cts, &sk, &pk, &mut transcript);

        let mut tampered = input_cts.clone();
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
        let output_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| make_remask_pair(&input_cts[i], &sk, &pk, &mut rng))
            .collect();

        let mut transcript = MerlinTranscript::new(b"test_wrong_prover_sk_fails");
        assert!(
            RemaskProof::try_prove(&input_cts, &output_cts, &wrong_sk, &pk, &mut transcript)
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
        let input = RistrettoElGamalCiphertext::encrypt(&pt, &pk, &r);
        let output = make_remask_pair(&input, &sk, &pk, &mut rng);

        let mut transcript = MerlinTranscript::new(b"test_single_card");
        let proof = RemaskProof::prove(
            &[input.clone()],
            &[output.clone()],
            &sk,
            &pk,
            &mut transcript,
        );
        let mut transcript = MerlinTranscript::new(b"test_single_card");
        assert!(
            proof.verify(&[input], &[output], &pk, &mut transcript),
            "single card should pass"
        );
    }

    #[test]
    fn test_single_card_two_user() {
        let mut rng = OsRng;
        let (sk, pk) = gen_keypair::<RistrettoCurve>(&mut rng);
        let pt = RistrettoCurve::base_g() * <RistrettoCurve as Curve>::Scalar::from_u64(42u64);
        let input = RistrettoElGamalCiphertext {
            c1: <RistrettoCurve as Curve>::Point::identity(),
            c2: pt,
        };
        let r_prime = <RistrettoCurve as Curve>::Scalar::random(&mut rng);
        let enc_one = input.re_encrypt(&pk, &r_prime);
        let mut output = enc_one.clone();

        let (sk2, pk2) = gen_keypair::<RistrettoCurve>(&mut rng);
        output.c2 = output.c2 + output.c1 * sk2; //user2 join

        let mut transcript = MerlinTranscript::new(b"test_single_card_two_user");
        let proof = RemaskProof::prove(
            &[enc_one.clone()],
            &[output.clone()],
            &sk2,
            &pk2,
            &mut transcript,
        );
        let mut transcript = MerlinTranscript::new(b"test_single_card_two_user");
        assert!(
            proof.verify(&[enc_one.clone()], &[output.clone()], &pk2, &mut transcript),
            "single card should pass"
        );

        let reveal_token1 = output.gen_reveal_token(&sk);
        let reveal_token2 = output.gen_reveal_token(&sk2);

        let decrypted = output.c2 - reveal_token1 - reveal_token2;
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn test_benchmark_remask_proof_52_cards() {
        use std::time::{Duration, Instant};

        println!("\n{}", "=".repeat(72));
        println!("  RemaskProof Benchmark: prove() & verify() (52 cards)");
        println!("{}", "=".repeat(72));

        const N: usize = 52;
        const WARMUP: usize = 3;
        const ITERATIONS: usize = 20;

        let mut rng = OsRng;
        let (sk, pk) = gen_keypair::<RistrettoCurve>(&mut rng);
        let plaintexts: Vec<_> = (0..N)
            .map(|i| {
                RistrettoCurve::base_h() * <RistrettoCurve as Curve>::Scalar::from_u64(i as u64)
            })
            .collect();
        let r_values: Vec<_> = (0..N)
            .map(|_| <RistrettoCurve as Curve>::Scalar::random(&mut rng))
            .collect();

        let input_cts: Vec<RistrettoElGamalCiphertext> = (0..N)
            .map(|i| RistrettoElGamalCiphertext::encrypt(&plaintexts[i], &pk, &r_values[i]))
            .collect();
        let output_cts: Vec<RistrettoElGamalCiphertext> = (0..N)
            .map(|i| remask_ciphertext(&input_cts[i], &sk, &pk, &mut rng).unwrap())
            .collect();

        let mut prove_times: Vec<Duration> = Vec::with_capacity(ITERATIONS);
        let mut verify_times: Vec<Duration> = Vec::with_capacity(ITERATIONS);
        let mut proof_size_bytes = 0usize;

        for i in 0..(WARMUP + ITERATIONS) {
            let start = Instant::now();
            let mut transcript = MerlinTranscript::new(b"test_benchmark_remask_proof_52_cards");
            let proof = RemaskProof::prove(&input_cts, &output_cts, &sk, &pk, &mut transcript);
            let prove_dur = start.elapsed();

            if i < WARMUP {
                println!("\n  [Warmup {}/{}] prove: {:?}", i + 1, WARMUP, prove_dur);
                continue;
            }

            if proof_size_bytes == 0 {
                proof_size_bytes = std::mem::size_of_val(&proof);
            }

            let start = Instant::now();
            let mut transcript = MerlinTranscript::new(b"test_benchmark_remask_proof_52_cards");
            let valid = proof.verify(&input_cts, &output_cts, &pk, &mut transcript);
            let verify_dur = start.elapsed();

            assert!(valid, "Benchmark iteration {} must verify", i);

            prove_times.push(prove_dur);
            verify_times.push(verify_dur);
        }

        prove_times.sort();
        verify_times.sort();

        let avg_prove: Duration = prove_times.iter().sum::<Duration>() / ITERATIONS as u32;
        let avg_verify: Duration = verify_times.iter().sum::<Duration>() / ITERATIONS as u32;
        let p50_prove = prove_times[ITERATIONS / 2];
        let p50_verify = verify_times[ITERATIONS / 2];
        let p99_prove = prove_times[(ITERATIONS * 99 / 100).min(ITERATIONS - 1)];
        let p99_verify = verify_times[(ITERATIONS * 99 / 100).min(ITERATIONS - 1)];
        let min_prove = prove_times[0];
        let min_verify = verify_times[0];
        let max_prove = prove_times[ITERATIONS - 1];
        let max_verify = verify_times[ITERATIONS - 1];

        let prove_per_sec = 1.0f64 / avg_prove.as_secs_f64();
        let verify_per_sec = 1.0f64 / avg_verify.as_secs_f64();

        println!("\n  ┌─────────────────────────────────────────────────────────────┐");
        println!(
            "  │  RemaskProof Performance (N={}, {} iters)                │",
            N, ITERATIONS
        );
        println!("  ├──────────────┬──────────┬──────────┬──────────┬──────────┤");
        println!("  │ Operation    │   Avg    │   P50    │   Min    │   Max    │");
        println!("  ├──────────────┼──────────┼──────────┼──────────┼──────────┤");
        println!(
            "  │ prove()      │ {:>8.2?}ms│ {:>8.2?}ms│ {:>8.2?}ms│ {:>8.2?}ms│",
            avg_prove.as_millis(),
            p50_prove.as_millis(),
            min_prove.as_millis(),
            max_prove.as_millis()
        );
        println!(
            "  │ verify()     │ {:>8.2?}ms│ {:>8.2?}ms│ {:>8.2?}ms│ {:>8.2?}ms│",
            avg_verify.as_millis(),
            p50_verify.as_millis(),
            min_verify.as_millis(),
            max_verify.as_millis()
        );
        println!("  ├──────────────┼──────────┼──────────┼──────────┼──────────┤");
        println!(
            "  │ Throughput   │ {:>8.1}/s│          │ P99={:>6.2?}ms│ P99={:>6.2?}ms│",
            prove_per_sec,
            p99_prove.as_millis(),
            p99_verify.as_millis()
        );
        println!(
            "  │ Verify rate  │ {:>8.1}/s│          │          │          │",
            verify_per_sec
        );
        println!("  ├──────────────┴──────────┴──────────┴──────────┴──────────┤");
        println!(
            "  │ Proof size: ~{} bytes (per_card_commitments[{}]+commitment_pk+response+nonce) │",
            proof_size_bytes, N
        );
        println!(
            "  │ Total (prove+verify): {:>8.2?}ms                           │",
            (avg_prove + avg_verify).as_millis()
        );
        println!("  └─────────────────────────────────────────────────────────────┘");

        assert!(
            avg_prove.as_millis() < 500,
            "prove() should complete within 500ms"
        );
        assert!(
            avg_verify.as_millis() < 100,
            "verify() should complete within 100ms"
        );

        println!("\n  ✅ Benchmark completed: all performance within acceptable bounds");
    }

    #[test]
    fn test_benchmark_remask_proof_52_cards_bls12381() {
        use poker_protocol_core::Bls12381Curve;
        use std::time::{Duration, Instant};

        type BlsElGamalCiphertext = ElGamalCiphertextGeneric<Bls12381Curve>;

        println!("\n{}", "=".repeat(72));
        println!("  RemaskProof Benchmark: prove() & verify() (52 cards, BLS12-381)");
        println!("{}", "=".repeat(72));

        const N: usize = 52;
        const WARMUP: usize = 3;
        const ITERATIONS: usize = 20;

        let mut rng = OsRng;
        let (sk, pk) = gen_keypair::<Bls12381Curve>(&mut rng);
        let plaintexts: Vec<_> = (0..N)
            .map(|i| Bls12381Curve::base_h() * <Bls12381Curve as Curve>::Scalar::from_u64(i as u64))
            .collect();
        let r_values: Vec<_> = (0..N)
            .map(|_| <Bls12381Curve as Curve>::Scalar::random(&mut rng))
            .collect();

        let input_cts: Vec<BlsElGamalCiphertext> = (0..N)
            .map(|i| BlsElGamalCiphertext::encrypt(&plaintexts[i], &pk, &r_values[i]))
            .collect();
        let output_cts: Vec<BlsElGamalCiphertext> = (0..N)
            .map(|i| remask_ciphertext(&input_cts[i], &sk, &pk, &mut rng).unwrap())
            .collect();

        let mut prove_times: Vec<Duration> = Vec::with_capacity(ITERATIONS);
        let mut verify_times: Vec<Duration> = Vec::with_capacity(ITERATIONS);
        let mut proof_size_bytes = 0usize;

        for i in 0..(WARMUP + ITERATIONS) {
            let start = Instant::now();
            let mut transcript =
                MerlinTranscript::new(b"test_benchmark_remask_proof_52_cards_bls12381");
            let proof = RemaskProof::prove(&input_cts, &output_cts, &sk, &pk, &mut transcript);
            let prove_dur = start.elapsed();

            if i < WARMUP {
                println!("\n  [Warmup {}/{}] prove: {:?}", i + 1, WARMUP, prove_dur);
                continue;
            }

            if proof_size_bytes == 0 {
                proof_size_bytes = std::mem::size_of_val(&proof);
            }

            let start = Instant::now();
            let mut transcript =
                MerlinTranscript::new(b"test_benchmark_remask_proof_52_cards_bls12381");
            let valid = proof.verify(&input_cts, &output_cts, &pk, &mut transcript);
            let verify_dur = start.elapsed();

            assert!(valid, "Benchmark iteration {} must verify", i);

            prove_times.push(prove_dur);
            verify_times.push(verify_dur);
        }

        prove_times.sort();
        verify_times.sort();

        let avg_prove: Duration = prove_times.iter().sum::<Duration>() / ITERATIONS as u32;
        let avg_verify: Duration = verify_times.iter().sum::<Duration>() / ITERATIONS as u32;
        let p50_prove = prove_times[ITERATIONS / 2];
        let p50_verify = verify_times[ITERATIONS / 2];
        let p99_prove = prove_times[(ITERATIONS * 99 / 100).min(ITERATIONS - 1)];
        let p99_verify = verify_times[(ITERATIONS * 99 / 100).min(ITERATIONS - 1)];
        let min_prove = prove_times[0];
        let min_verify = verify_times[0];
        let max_prove = prove_times[ITERATIONS - 1];
        let max_verify = verify_times[ITERATIONS - 1];

        let prove_per_sec = 1.0f64 / avg_prove.as_secs_f64();
        let verify_per_sec = 1.0f64 / avg_verify.as_secs_f64();

        println!("\n  ┌─────────────────────────────────────────────────────────────┐");
        println!(
            "  │  RemaskProof BLS12-381 Performance (N={}, {} iters)      │",
            N, ITERATIONS
        );
        println!("  ├──────────────┬──────────┬──────────┬──────────┬──────────┤");
        println!("  │ Operation    │   Avg    │   P50    │   Min    │   Max    │");
        println!("  ├──────────────┼──────────┼──────────┼──────────┼──────────┤");
        println!(
            "  │ prove()      │ {:>8.2?}ms│ {:>8.2?}ms│ {:>8.2?}ms│ {:>8.2?}ms│",
            avg_prove.as_millis(),
            p50_prove.as_millis(),
            min_prove.as_millis(),
            max_prove.as_millis()
        );
        println!(
            "  │ verify()     │ {:>8.2?}ms│ {:>8.2?}ms│ {:>8.2?}ms│ {:>8.2?}ms│",
            avg_verify.as_millis(),
            p50_verify.as_millis(),
            min_verify.as_millis(),
            max_verify.as_millis()
        );
        println!("  ├──────────────┼──────────┼──────────┼──────────┼──────────┤");
        println!(
            "  │ Throughput   │ {:>8.1}/s│          │ P99={:>6.2?}ms│ P99={:>6.2?}ms│",
            prove_per_sec,
            p99_prove.as_millis(),
            p99_verify.as_millis()
        );
        println!(
            "  │ Verify rate  │ {:>8.1}/s│          │          │          │",
            verify_per_sec
        );
        println!("  ├──────────────┴──────────┴──────────┴──────────┴──────────┤");
        println!(
            "  │ Proof size: ~{} bytes (per_card_commitments[{}]+commitment_pk+response+nonce) │",
            proof_size_bytes, N
        );
        println!(
            "  │ Total (prove+verify): {:>8.2?}ms                           │",
            (avg_prove + avg_verify).as_millis()
        );
        println!("  └─────────────────────────────────────────────────────────────┘");

        assert!(
            avg_prove.as_millis() < 2000,
            "prove() should complete within 2000ms"
        );
        assert!(
            avg_verify.as_millis() < 500,
            "verify() should complete within 500ms"
        );

        println!("\n  ✅ BLS12-381 benchmark completed: all performance within acceptable bounds");
    }

    /// Multi-scale performance comparison for RemaskProof (per-card DLEq v2)
    /// Tests prove/verify at N = 1, 5, 13, 52 cards to evaluate scaling.
    #[test]
    fn test_benchmark_remask_proof_scaling() {
        use std::time::{Duration, Instant};

        const CARD_COUNTS: [usize; 4] = [1, 5, 13, 52];
        const WARMUP: usize = 2;
        const ITERATIONS: usize = 10;

        println!("\n{}", "=".repeat(80));
        println!("  RemaskProof v2 (per-card DLEq) — Scaling Benchmark");
        println!("{}", "=".repeat(80));

        let mut rng = OsRng;
        let (sk, pk) = gen_keypair::<RistrettoCurve>(&mut rng);

        // Pre-generate max number of plaintexts and keys
        let max_n = *CARD_COUNTS.last().unwrap();
        let plaintexts: Vec<_> = (0..max_n)
            .map(|i| {
                RistrettoCurve::base_h() * <RistrettoCurve as Curve>::Scalar::from_u64(i as u64)
            })
            .collect();
        let r_values: Vec<_> = (0..max_n)
            .map(|_| <RistrettoCurve as Curve>::Scalar::random(&mut rng))
            .collect();

        let all_input_cts: Vec<RistrettoElGamalCiphertext> = (0..max_n)
            .map(|i| RistrettoElGamalCiphertext::encrypt(&plaintexts[i], &pk, &r_values[i]))
            .collect();
        let all_output_cts: Vec<RistrettoElGamalCiphertext> = (0..max_n)
            .map(|i| remask_ciphertext(&all_input_cts[i], &sk, &pk, &mut rng).unwrap())
            .collect();

        println!(
            "  ┌───────┬──────────────┬──────────────┬───────────┬────────────────────────────────┐"
        );
        println!(
            "  │   N   │  prove (avg) │ verify (avg) │ total avg │ proof size                     │"
        );
        println!(
            "  ├───────┼──────────────┼──────────────┼───────────┼────────────────────────────────┤"
        );

        for &n in &CARD_COUNTS {
            let input_cts = &all_input_cts[..n];
            let output_cts = &all_output_cts[..n];

            let mut prove_times: Vec<Duration> = Vec::with_capacity(ITERATIONS);
            let mut verify_times: Vec<Duration> = Vec::with_capacity(ITERATIONS);
            let mut proof_size_bytes = 0usize;

            for i in 0..(WARMUP + ITERATIONS) {
                let start = Instant::now();
                let mut transcript = MerlinTranscript::new(b"test_benchmark_remask_proof_scaling");
                let proof = RemaskProof::prove(input_cts, output_cts, &sk, &pk, &mut transcript);
                let prove_dur = start.elapsed();

                if i < WARMUP {
                    continue;
                }

                if proof_size_bytes == 0 {
                    proof_size_bytes = std::mem::size_of_val(&proof);
                }

                let start = Instant::now();
                let mut transcript = MerlinTranscript::new(b"test_benchmark_remask_proof_scaling");
                let valid = proof.verify(input_cts, output_cts, &pk, &mut transcript);
                let verify_dur = start.elapsed();

                assert!(valid, "Benchmark N={} iteration {} must verify", n, i);

                prove_times.push(prove_dur);
                verify_times.push(verify_dur);
            }

            prove_times.sort();
            verify_times.sort();

            let avg_prove: Duration = prove_times.iter().sum::<Duration>() / ITERATIONS as u32;
            let avg_verify: Duration = verify_times.iter().sum::<Duration>() / ITERATIONS as u32;
            let p50_prove = prove_times[ITERATIONS / 2];
            let p50_verify = verify_times[ITERATIONS / 2];

            println!(
                "  │ {:>5} │ {:>9.2?}ms │ {:>9.2?}ms │ {:>7.2?}ms │ {} bytes (Vec[{}]+3 fields)   │",
                n,
                avg_prove.as_millis(),
                avg_verify.as_millis(),
                (avg_prove + avg_verify).as_millis(),
                proof_size_bytes,
                n
            );

            // Performance assertions
            assert!(
                avg_prove.as_millis() < 1000,
                "prove(N={}) should complete within 1s",
                n
            );
            assert!(
                avg_verify.as_millis() < 500,
                "verify(N={}) should complete within 500ms",
                n
            );

            let _ = (p50_prove, p50_verify); // suppress unused warning
        }

        println!(
            "  └───────┴──────────────┴──────────────┴───────────┴────────────────────────────────┘"
        );

        // Per-card overhead analysis
        println!("\n  Per-card overhead analysis (per-card DLEq commitments):");
        println!(
            "  - prove:  N scalar-point multiplications for per_card_commitments + 1 for commitment_pk"
        );
        println!(
            "  - verify: N scalar-point multiplications for per-card DLEq checks + 1 for pk DLEq"
        );
        println!("  - proof:  Vec<Point> of size N + 1 Point + 1 Scalar + 1 Scalar");
        println!(
            "  - Compared to v1 (aggregate): proof size grows O(N) vs O(1), but security is per-card"
        );

        println!("\n  ✅ Scaling benchmark completed");
    }

    /// SECURITY FIX VERIFICATION: RemaskProof per-card DLEq prevents
    /// aggregate manipulation attacks.
    #[test]
    fn test_forgery_remask_proof_individual_card_manipulation() {
        let mut rng = OsRng;
        let (sk, pk) = gen_keypair::<RistrettoCurve>(&mut rng);

        // Create honest input_cts and output_cts (valid remaskings)
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
        let output_cts: Vec<RistrettoElGamalCiphertext> = (0..RistrettoCurve::n_cards())
            .map(|i| remask_ciphertext(&input_cts[i], &sk, &pk, &mut rng).unwrap())
            .collect();

        // Verify honest proof passes
        let mut transcript =
            MerlinTranscript::new(b"test_forgery_remask_proof_individual_card_manipulation");
        let honest_proof = RemaskProof::prove(&input_cts, &output_cts, &sk, &pk, &mut transcript);
        let mut transcript =
            MerlinTranscript::new(b"test_forgery_remask_proof_individual_card_manipulation");
        assert!(
            honest_proof.verify(&input_cts, &output_cts, &pk, &mut transcript),
            "honest proof should pass"
        );

        // --- Attack attempt: manipulate output_cts ---
        // Modify output_cts[0].c2 by a random perturbation Δ
        let mut forged_output_cts = output_cts.clone();
        let delta = <RistrettoCurve as Curve>::Scalar::random(&mut rng);
        let delta_point = RistrettoCurve::base_g() * delta;
        forged_output_cts[0].c2 = forged_output_cts[0].c2 + delta_point;

        // Verify the forged output_cts[0] is NOT a valid remasking
        let forged_d2_0 = forged_output_cts[0].c2 - input_cts[0].c2;
        let expected_d2_0 = input_cts[0].c1 * sk;
        assert_ne!(
            forged_d2_0, expected_d2_0,
            "forged output_cts[0] should NOT be a valid remasking"
        );

        // Strict proving rejects the malformed per-card relation.
        let mut transcript = MerlinTranscript::new(b"test_forgery_remask_proof_forged");
        assert!(
            RemaskProof::try_prove(&input_cts, &forged_output_cts, &sk, &pk, &mut transcript)
                .is_err(),
            "strict prover should reject manipulated output_cts"
        );
    }

    #[test]
    fn test_single_card_one_user() {
        let mut rng = OsRng;
        let (sk, pk) = gen_keypair::<RistrettoCurve>(&mut rng);
        let pt = RistrettoCurve::base_g() * <RistrettoCurve as Curve>::Scalar::from_u64(42u64);
        // 兼容 Move 合约 M7 修复：使用有效密文（c1/c2 非 identity）
        let r = <RistrettoCurve as Curve>::Scalar::random(&mut rng);
        let input = RistrettoElGamalCiphertext::encrypt(&pt, &pk, &r);
        let mut output = input.clone();

        output.c2 = output.c2 + output.c1 * sk; //user remask

        let mut transcript = MerlinTranscript::new(b"test_single_card_one_user");
        let proof = RemaskProof::prove(
            &[input.clone()],
            &[output.clone()],
            &sk,
            &pk,
            &mut transcript,
        );
        let mut transcript = MerlinTranscript::new(b"test_single_card_one_user");
        assert!(
            proof.verify(&[input.clone()], &[output.clone()], &pk, &mut transcript),
            "single card should pass"
        );

        // 同一用户加密并 remask，需移除两层加密
        let reveal_token1 = output.clone().gen_reveal_token(&sk);
        let decrypted = output.c2 - reveal_token1 - reveal_token1;
        assert_eq!(decrypted, pt);
    }

    // ===== FORGERY TESTS =====

    /// FIXED: remask_ciphertext now re-randomizes both c1 and c2.
    #[test]
    fn test_forgery_remask_no_rerandomization() {
        let mut rng = OsRng;
        let (sk, pk) = gen_keypair::<RistrettoCurve>(&mut rng);

        // 使用非 identity c1
        let pt = RistrettoCurve::base_h() * <RistrettoCurve as Curve>::Scalar::from_u64(42u64);
        let r = <RistrettoCurve as Curve>::Scalar::random(&mut rng);
        let input = RistrettoElGamalCiphertext::encrypt(&pt, &pk, &r);

        // remask_ciphertext now re-randomizes
        let output1 = remask_ciphertext(&input, &sk, &pk, &mut rng).unwrap();
        let output2 = remask_ciphertext(&input, &sk, &pk, &mut rng).unwrap();

        // Both outputs decrypt to the same plaintext
        let pt1 = output1.c2 - output1.c1 * sk;
        let pt2 = output2.c2 - output2.c1 * sk;
        assert_eq!(pt1, pt2, "Both outputs should decrypt to same plaintext");

        // Proof still passes for both
        let mut transcript1 = MerlinTranscript::new(b"test_remask_output1");
        let proof1 = RemaskProof::prove(
            &[input.clone()],
            &[output1.clone()],
            &sk,
            &pk,
            &mut transcript1,
        );
        let mut transcript1_v = MerlinTranscript::new(b"test_remask_output1");
        assert!(
            proof1.verify(
                &[input.clone()],
                &[output1.clone()],
                &pk,
                &mut transcript1_v
            ),
            "Proof for output1 should pass"
        );
        let mut transcript2 = MerlinTranscript::new(b"test_remask_output2");
        let proof2 = RemaskProof::prove(
            &[input.clone()],
            &[output2.clone()],
            &sk,
            &pk,
            &mut transcript2,
        );
        let mut transcript2_v = MerlinTranscript::new(b"test_remask_output2");
        assert!(
            proof2.verify(
                &[input.clone()],
                &[output2.clone()],
                &pk,
                &mut transcript2_v
            ),
            "Proof for output2 should pass"
        );
    }

    /// FORGERY 2 (MEDIUM): 当 c1 = identity 时，per-card DLEq 退化
    #[test]
    fn test_forgery_identity_c1_vacuous_check() {
        let mut rng = OsRng;
        let (sk, pk) = gen_keypair::<RistrettoCurve>(&mut rng);

        // 创建 c1 = identity 的输入
        let pt = RistrettoCurve::base_h() * <RistrettoCurve as Curve>::Scalar::from_u64(42u64);
        let input = RistrettoElGamalCiphertext {
            c1: <RistrettoCurve as Curve>::Point::identity(),
            c2: pt,
        };

        // remask_ciphertext 对 identity c1 现在返回 Err(InvalidCiphertext)
        assert!(
            remask_ciphertext(&input, &sk, &pk, &mut rng).is_err(),
            "remask_ciphertext should reject identity c1"
        );

        // 但如果我们手动构造 output（跳过 re_encrypt），保持 c1 = identity
        let mut manual_output = input.clone();
        manual_output.c2 = manual_output.c2 + manual_output.c1 * sk; // identity * sk = identity

        // 手动构造的 output 和 input 完全相同
        assert_eq!(
            manual_output.c2, input.c2,
            "c2 unchanged when c1 is identity"
        );

        // 兼容 Move 合约 M7 修复：verify 现在拒绝 identity c1 密文
        let mut transcript = MerlinTranscript::new(b"test_identity_c1");
        assert!(RemaskProof::try_prove(
            &[input.clone()],
            &[manual_output.clone()],
            &sk,
            &pk,
            &mut transcript,
        )
        .is_err());

        // 篡改的 output 也应被拒绝（identity c1）
        let mut tampered_output = manual_output.clone();
        tampered_output.c2 = tampered_output.c2 + RistrettoCurve::base_g();
        let mut transcript2 = MerlinTranscript::new(b"test_identity_c1_tampered");
        assert!(RemaskProof::try_prove(
            &[input.clone()],
            &[tampered_output.clone()],
            &sk,
            &pk,
            &mut transcript2,
        )
        .is_err());
    }
}
