//! Ristretto Fp-program STARK micro-benchmark.
//!
//! Times proving and verification of the three production layers (a small
//! field program, one compressed-point addition program, and an N-pair
//! compressed fixed-window scalar-multiplication batch) plus the composed
//! variable-base MSM, and reports serialized proof sizes.  Run with:
//!
//! ```text
//! cargo +nightly run --release --bin ristretto_perf
//! ```

use std::time::Instant;

use poker_texas_air::ristretto_fp_program_air::{
    build_ristretto_fp_program_compressed_point_addition, prove_ristretto_fp_program,
    prove_ristretto_fp_program_compressed_fixed_window_scalar_mul,
    prove_ristretto_fp_program_compressed_fixed_window_scalar_mul_batch,
    verify_ristretto_fp_program,
    verify_ristretto_fp_program_compressed_fixed_window_scalar_mul_batch,
};
use poker_texas_air::ristretto_msm_air::{prove_ristretto_msm, verify_ristretto_msm};

const LIMBS: usize = 32;
const WINDOWS: usize = 64;

fn basepoint() -> [u8; LIMBS] {
    [
        0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71, 0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00, 0x51,
        0x5f, 0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d, 0xb6, 0xa6, 0x59, 0x45, 0xe0, 0x8d,
        0x2d, 0x76,
    ]
}

fn scalar(value: u8) -> [u8; LIMBS] {
    let mut out = [0u8; LIMBS];
    out[0] = value;
    out
}

fn nibbles(scalar: &[u8; LIMBS]) -> [u8; WINDOWS] {
    let mut out = [0u8; WINDOWS];
    for (index, byte) in scalar.iter().enumerate() {
        out[index * 2] = byte & 0x0f;
        out[index * 2 + 1] = byte >> 4;
    }
    out
}

fn borsh_len(value: &impl borsh::BorshSerialize) -> usize {
    borsh::to_vec(value).expect("serialization succeeds").len()
}

fn main() {
    println!("=== small field program (add/mul/sub) ===");
    {
        use poker_texas_air::ristretto_fp_program_air::RistrettoFpProgramBuilder;
        let mut builder = RistrettoFpProgramBuilder::new(&[scalar(2), scalar(3), scalar(5)]);
        let sum = builder.add(0, 1).unwrap();
        let product = builder.multiply(sum, 2).unwrap();
        let difference = builder.subtract(product, 0).unwrap();
        let program = builder.finish(&[sum, product, difference]).unwrap();

        let started = Instant::now();
        let archive = prove_ristretto_fp_program(&program).unwrap();
        let prove_elapsed = started.elapsed();
        let started = Instant::now();
        verify_ristretto_fp_program(&archive).unwrap();
        let verify_elapsed = started.elapsed();
        println!(
            "prove {:>9.1?}  verify {:>8.1?}  proof bytes {}",
            prove_elapsed,
            verify_elapsed,
            borsh_len(&archive)
        );
    }

    println!("=== one compressed-point addition program ===");
    {
        let (program, _output) =
            build_ristretto_fp_program_compressed_point_addition(&basepoint(), &basepoint())
                .unwrap();
        let started = Instant::now();
        let archive = prove_ristretto_fp_program(&program).unwrap();
        let prove_elapsed = started.elapsed();
        let started = Instant::now();
        verify_ristretto_fp_program(&archive).unwrap();
        let verify_elapsed = started.elapsed();
        println!(
            "prove {:>9.1?}  verify {:>8.1?}  proof bytes {}",
            prove_elapsed,
            verify_elapsed,
            borsh_len(&archive)
        );
    }

    for pairs in [2usize, 4, 8, 16, 52] {
        println!("=== compressed fixed-window scalar-mul batch N={pairs} ===");
        let inputs = (1..=pairs)
            .map(|index| {
                let scalar = scalar(index as u8);
                (scalar, nibbles(&scalar), basepoint())
            })
            .collect::<Vec<_>>();
        let started = Instant::now();
        let archive =
            prove_ristretto_fp_program_compressed_fixed_window_scalar_mul_batch(inputs).unwrap();
        let prove_elapsed = started.elapsed();
        let started = Instant::now();
        verify_ristretto_fp_program_compressed_fixed_window_scalar_mul_batch(&archive).unwrap();
        let verify_elapsed = started.elapsed();
        println!(
            "prove {:>9.1?}  verify {:>8.1?}  proof bytes {}",
            prove_elapsed,
            verify_elapsed,
            borsh_len(&archive)
        );
    }

    for pairs in [2usize, 4] {
        println!("=== variable-base MSM N={pairs} (windows + muls + accumulation) ===");
        let scalars = (1..=pairs)
            .map(|index| scalar(index as u8))
            .collect::<Vec<_>>();
        let bases = (1..=pairs).map(|_| basepoint()).collect::<Vec<_>>();
        let started = Instant::now();
        let archive = prove_ristretto_msm(&scalars, &bases).unwrap();
        let prove_elapsed = started.elapsed();
        let started = Instant::now();
        verify_ristretto_msm(&archive).unwrap();
        let verify_elapsed = started.elapsed();
        println!(
            "prove {:>9.1?}  verify {:>8.1?}  proof bytes {}",
            prove_elapsed,
            verify_elapsed,
            borsh_len(&archive)
        );
    }

    println!(
        "=== per-input 8-batches vs single 8-input batch (simulated per-slot vs global slot-OR muls) ==="
    );
    for batch_size in [4usize, 8] {
        let inputs: Vec<_> = (1..=batch_size)
            .map(|index| {
                let scalar = scalar(index as u8);
                (scalar, nibbles(&scalar), basepoint())
            })
            .collect();
        let started = Instant::now();
        let single =
            prove_ristretto_fp_program_compressed_fixed_window_scalar_mul_batch(inputs.clone())
                .unwrap();
        let single_prove = started.elapsed();
        let single_bytes = borsh_len(&single);

        let started = Instant::now();
        let mut total_prove = std::time::Duration::ZERO;
        let mut total_bytes = 0usize;
        for input in &inputs {
            let item_started = Instant::now();
            let one =
                prove_ristretto_fp_program_compressed_fixed_window_scalar_mul_batch(vec![*input])
                    .unwrap();
            total_prove = total_prove + item_started.elapsed();
            total_bytes += borsh_len(&one);
        }
        let _ = started;
        let per_input_prove = total_prove;

        println!(
            "N={batch_size:>2}  single 8-input batch: prove {:>8.1?}  proof bytes {}",
            single_prove, single_bytes
        );
        println!(
            "N={batch_size:>2}  {batch_size} separate N=1 batches: prove {:>8.1?}  proof bytes {}",
            per_input_prove, total_bytes
        );
    }
}
