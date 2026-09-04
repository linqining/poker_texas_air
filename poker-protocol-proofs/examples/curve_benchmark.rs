//! Compare the curve backends used by the poker proof suite.
//!
//! This measures the native cryptographic work that is performed before a
//! Stwo AIR receives its precompile receipt. The AIR itself is curve-agnostic:
//! it commits fixed-width M31 request/receipt digests.
//!
//! Run with:
//! `cargo run -p poker-protocol-proofs --release --example curve_benchmark`

use std::hint::black_box;
use std::time::{Duration, Instant};

use poker_protocol_bg::BayerGrothShuffleProof;
use poker_protocol_core::{
    StarkCurve, CryptoTranscript, Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric,
    RistrettoCurve,
};
use poker_protocol_proofs::{
    dleq_proof::{DLEqProof, RemaskKind},
    transcript_ext::MerlinTranscript,
};
use rand_core::{OsRng, RngCore};

const N: usize = 52;
const SAMPLES: usize = 5;

struct Fixture<C: Curve> {
    secret: C::Scalar,
    public: C::Point,
    input: Vec<ElGamalCiphertextGeneric<C>>,
    output: Vec<ElGamalCiphertextGeneric<C>>,
    permutation: Vec<usize>,
    rerandomizers: Vec<C::Scalar>,
    remasked: Vec<ElGamalCiphertextGeneric<C>>,
}

fn fixture<C: Curve>() -> Fixture<C> {
    let secret = C::Scalar::random(&mut OsRng);
    let public = C::base_g() * secret;
    let plaintexts = (0..N)
        .map(|i| C::hash_to_curve(format!("curve-benchmark/card/{i}").as_bytes()))
        .collect::<Vec<_>>();
    let randomness = (0..N)
        .map(|_| C::Scalar::random(&mut OsRng))
        .collect::<Vec<_>>();
    let input = plaintexts
        .iter()
        .zip(&randomness)
        .map(|(point, r)| ElGamalCiphertextGeneric::encrypt(point, &public, r))
        .collect::<Vec<_>>();
    let permutation = (0..N).rev().collect::<Vec<_>>();
    let rerandomizers = (0..N)
        .map(|_| C::Scalar::random(&mut OsRng))
        .collect::<Vec<_>>();
    let output = permutation
        .iter()
        .zip(&rerandomizers)
        .map(|(index, r)| input[*index].re_encrypt(&public, r))
        .collect::<Vec<_>>();
    let remasked = input
        .iter()
        .map(|ct| ct.remask(&secret))
        .collect::<Vec<_>>();
    Fixture {
        secret,
        public,
        input,
        output,
        permutation,
        rerandomizers,
        remasked,
    }
}

fn median(mut values: Vec<Duration>) -> Duration {
    values.sort_unstable();
    values[values.len() / 2]
}

fn sample<F: FnMut()>(mut operation: F) -> Duration {
    // Warm up hash-to-curve/MSM code paths and CPU frequency scaling.
    operation();
    let mut values = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let start = Instant::now();
        operation();
        values.push(start.elapsed());
    }
    median(values)
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

fn run<C: Curve>(name: &str) {
    let fixture = fixture::<C>();
    let point_bytes = fixture.public.compress().as_ref().len();
    let scalar_bytes = fixture.secret.as_bytes().len();
    let ciphertext_bytes = 2 * point_bytes;

    let prepare = sample(|| {
        let mut rng = OsRng;
        let plaintexts = (0..N)
            .map(|i| C::hash_to_curve(format!("curve-benchmark/prepare/{i}").as_bytes()))
            .collect::<Vec<_>>();
        let _ = black_box(poker_protocol_core::ec_encrypt_batch_generic::<C>(
            &plaintexts,
            &fixture.public,
            &mut rng,
        ));
    });

    let prove = sample(|| {
        let mut transcript = MerlinTranscript::new(b"curve-benchmark/bg12");
        let proof = BayerGrothShuffleProof::prove(
            &fixture.input,
            &fixture.output,
            &fixture.permutation,
            &fixture.rerandomizers,
            &fixture.public,
            &mut OsRng,
            &mut transcript,
        )
        .expect("valid Bayer-Groth fixture");
        black_box(proof);
    });

    let proof = {
        let mut transcript = MerlinTranscript::new(b"curve-benchmark/bg12");
        BayerGrothShuffleProof::prove(
            &fixture.input,
            &fixture.output,
            &fixture.permutation,
            &fixture.rerandomizers,
            &fixture.public,
            &mut OsRng,
            &mut transcript,
        )
        .expect("valid Bayer-Groth fixture")
    };
    let verify = sample(|| {
        let mut transcript = MerlinTranscript::new(b"curve-benchmark/bg12");
        assert!(proof
            .verify(
                &fixture.input,
                &fixture.output,
                &fixture.public,
                &mut transcript
            )
            .is_ok());
    });

    let dleq_prove = sample(|| {
        let mut transcript = MerlinTranscript::new(b"curve-benchmark/dleq");
        let proof = DLEqProof::<C, RemaskKind>::prove(
            &fixture.input,
            &fixture.remasked,
            &fixture.secret,
            &fixture.public,
            &mut transcript,
        );
        black_box(proof);
    });
    let dleq_proof = {
        let mut transcript = MerlinTranscript::new(b"curve-benchmark/dleq");
        DLEqProof::<C, RemaskKind>::prove(
            &fixture.input,
            &fixture.remasked,
            &fixture.secret,
            &fixture.public,
            &mut transcript,
        )
    };
    let dleq_verify = sample(|| {
        let mut transcript = MerlinTranscript::new(b"curve-benchmark/dleq");
        assert!(dleq_proof.verify(
            &fixture.input,
            &fixture.remasked,
            &fixture.public,
            &mut transcript
        ));
    });

    println!(
        "{name}\tpoint={point_bytes}B\tscalar={scalar_bytes}B\tciphertext={ciphertext_bytes}B\t"
    );
    println!(
        "  encrypt+hash_to_curve(52): {:>9.3} ms\n  BG12 prove (52):          {:>9.3} ms\n  BG12 verify (52):          {:>9.3} ms\n  DLEQ prove (52):           {:>9.3} ms\n  DLEQ verify (52):           {:>9.3} ms",
        millis(prepare),
        millis(prove),
        millis(verify),
        millis(dleq_prove),
        millis(dleq_verify),
    );
}

fn main() {
    // Make accidental dead-code elimination of setup visible to the compiler.
    black_box(OsRng.next_u64());
    println!("curve\tencoding");
    run::<RistrettoCurve>("Ristretto255");
    run::<StarkCurve>("BLS12-381-G1");
}
