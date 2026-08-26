//! Variable-base multi-scalar multiplication (MSM) over Ristretto255.
//!
//! One MSM statement `output = Σ scalars[i] · bases[i]` is proven by
//! composing three existing batched STARK layers instead of a new AIR:
//!
//! 1. a scalar-window batch STARK ([`crate::ristretto_scalar_windows_air`])
//!    proving every scalar is canonical below the group order and that its
//!    sixty-four 4-bit windows are the exact decomposition;
//! 2. a compressed fixed-window scalar-multiplication batch STARK
//!    ([`crate::ristretto_fp_program_air`]) proving every product
//!    `scalars[i] · bases[i]` as 335 equal-shape compressed-point addition
//!    rows sharing one trace; and
//! 3. a compressed-point addition batch STARK (this module) accumulating the
//!    N product outputs into the public MSM output through N−1 equal-shape
//!    addition rows.
//!
//! The accumulation layer is the only new glue: like the scalar-multiplication
//! batch it rebuilds every row deterministically from its public `(left,
//! right, output)` statement, so a verifier rejects any detached row before
//! checking the shared STARK.

use rayon::prelude::*;

use crate::error::{TexasAirError, TexasAirResult};
use crate::ristretto_fp_program_air::{
    ArchivedRistrettoFpProgramBatchProof,
    ArchivedRistrettoFpProgramCompressedFixedWindowScalarMulBatchProof,
    build_ristretto_fp_program_compressed_point_addition, preheat_canonical_decode_memo,
    prove_ristretto_fp_program_batch_owned,
    prove_ristretto_fp_program_compressed_fixed_window_scalar_mul_batch,
    verify_ristretto_fp_program_batch,
    verify_ristretto_fp_program_compressed_fixed_window_scalar_mul_batch,
    verify_ristretto_fp_program_compressed_point_addition_row,
};
use crate::ristretto_scalar_windows_air::{
    ArchivedRistrettoScalarWindowsBatchProof, prove_ristretto_scalar_windows_batch,
    verify_ristretto_scalar_windows_batch, windows,
};

/// Canonical little-endian width shared by every MSM operand.
const LIMBS: usize = 32;

/// One public compressed-point addition row `left + right = output`.
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct ArchivedRistrettoCompressedAdditionRow {
    /// Canonical compressed left summand.
    pub left: [u8; LIMBS],
    /// Canonical compressed right summand.
    pub right: [u8; LIMBS],
    /// Canonical compressed sum.
    pub output: [u8; LIMBS],
}

/// Many compressed-point additions proven as rows of one equal-shape batch.
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct ArchivedRistrettoCompressedAdditionBatchProof {
    /// Public rows in canonical caller-defined order.
    pub rows: Vec<ArchivedRistrettoCompressedAdditionRow>,
    /// Equal-shape Fp-program batch proving every row.
    pub additions: ArchivedRistrettoFpProgramBatchProof,
}

/// Public `Σ scalars[i] · bases[i] = output` MSM statement and proofs.
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct ArchivedRistrettoMsmProof {
    /// Canonical scalars below the Ristretto255 group order.
    pub scalars: Vec<[u8; LIMBS]>,
    /// Canonical compressed base points, including the identity.
    pub bases: Vec<[u8; LIMBS]>,
    /// Canonical compressed MSM output.
    pub output: [u8; LIMBS],
    /// Window decomposition proofs for every scalar.
    pub windows: ArchivedRistrettoScalarWindowsBatchProof,
    /// Per-pair scalar-multiplication proofs sharing one batch STARK.
    pub muls: ArchivedRistrettoFpProgramCompressedFixedWindowScalarMulBatchProof,
    /// Output accumulation rows; `None` exactly for single-pair MSMs.
    pub accumulation: Option<ArchivedRistrettoCompressedAdditionBatchProof>,
}

/// Prove many compressed-point additions as rows of one batch STARK.
pub fn prove_ristretto_compressed_addition_batch(
    pairs: &[([u8; LIMBS], [u8; LIMBS])],
) -> TexasAirResult<ArchivedRistrettoCompressedAdditionBatchProof> {
    if pairs.is_empty() {
        return Err(TexasAirError::SpecViolation(
            "compressed addition batch cannot be empty".into(),
        ));
    }
    let built = pairs
        .par_iter()
        .map(|(left, right)| {
            build_ristretto_fp_program_compressed_point_addition(left, right)
                .map(|(program, output)| (program, *left, *right, output))
        })
        .collect::<TexasAirResult<Vec<_>>>()?;
    let mut rows = Vec::with_capacity(built.len());
    let mut programs = Vec::with_capacity(built.len());
    for (program, left, right, output) in built {
        rows.push(ArchivedRistrettoCompressedAdditionRow {
            left,
            right,
            output,
        });
        programs.push(program);
    }
    let additions = prove_ristretto_fp_program_batch_owned(programs)?;
    Ok(ArchivedRistrettoCompressedAdditionBatchProof { rows, additions })
}

/// Verify the row statements and the shared addition batch STARK.
pub fn verify_ristretto_compressed_addition_batch(
    archive: &ArchivedRistrettoCompressedAdditionBatchProof,
) -> TexasAirResult<()> {
    if archive.rows.len() != archive.additions.programs.len() {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "compressed addition batch row count is detached".into(),
        ));
    }
    for (row, program) in archive.rows.iter().zip(&archive.additions.programs) {
        verify_ristretto_fp_program_compressed_point_addition_row(
            program, &row.left, &row.right, &row.output,
        )?;
    }
    verify_ristretto_fp_program_batch(&archive.additions)
}

/// Sequentially fold the per-pair product outputs into one accumulation
/// batch, threading each partial sum as the next row's left summand.
///
/// The accumulation chain is data-serial (row `i`'s left summand is row
/// `i-1`'s output), but only the *curve arithmetic* needs to run serially.
/// The expensive Fp-program construction for each row is independent once
/// the `(left, right)` pair is known, so it runs on rayon after a fast
/// serial pass precomputes every partial sum with the curve library.
fn prove_msm_accumulation(
    outputs: &[[u8; LIMBS]],
) -> TexasAirResult<ArchivedRistrettoCompressedAdditionBatchProof> {
    if outputs.len() < 2 {
        return Err(TexasAirError::SpecViolation(
            "MSM accumulation requires at least two outputs".into(),
        ));
    }
    use poker_protocol::crypto::curve::{Curve, CurvePoint, RistrettoCurve};
    type Point = <RistrettoCurve as Curve>::Point;
    let decode = |encoding: &[u8; LIMBS]| -> TexasAirResult<Point> {
        Point::from_compressed(encoding).ok_or_else(|| {
            TexasAirError::SpecViolation("MSM accumulation point failed to decode".into())
        })
    };
    let encode = |point: &Point| -> [u8; LIMBS] {
        let mut out = [0u8; LIMBS];
        let bytes = CurvePoint::compress(point);
        let slice: &[u8] = bytes.as_ref();
        out.copy_from_slice(&slice[..LIMBS]);
        out
    };

    // Fast serial pass: compute every partial sum with plain curve
    // arithmetic (microseconds per addition).  `partial_sums[i]` is
    // `outputs[0] + … + outputs[i]`; row `i` proves
    // `(partial_sums[i], outputs[i+1]) -> partial_sums[i+1]`.
    let mut partial_sums = Vec::with_capacity(outputs.len());
    partial_sums.push(outputs[0]);
    let mut running = decode(&outputs[0])?;
    for output in &outputs[1..] {
        running = running + decode(output)?;
        partial_sums.push(encode(&running));
    }

    // Warm the decode memo for every input the parallel builders will see
    // (both the original outputs and the derived partial sums).
    preheat_canonical_decode_memo(outputs);
    preheat_canonical_decode_memo(&partial_sums);

    // Parallel pass: build every Fp program from its precomputed pair.  The
    // builder recomputes the sum internally; a debug assertion confirms the
    // fast path and the builder agree on the canonical encoding.
    let built: Vec<TexasAirResult<(crate::ristretto_fp_program_air::RistrettoFpProgram, [u8; LIMBS])>> =
        (0..outputs.len() - 1)
            .into_par_iter()
            .map(|i| {
                let left = partial_sums[i];
                let right = outputs[i + 1];
                let (program, sum) =
                    build_ristretto_fp_program_compressed_point_addition(&left, &right)?;
                debug_assert_eq!(
                    sum, partial_sums[i + 1],
                    "fast-path curve sum must match the Fp program builder's recomputation"
                );
                Ok((program, sum))
            })
            .collect();

    let mut rows = Vec::with_capacity(outputs.len() - 1);
    let mut programs = Vec::with_capacity(outputs.len() - 1);
    for (i, result) in built.into_iter().enumerate() {
        let (program, sum) = result?;
        rows.push(ArchivedRistrettoCompressedAdditionRow {
            left: partial_sums[i],
            right: outputs[i + 1],
            output: sum,
        });
        programs.push(program);
    }
    let additions = prove_ristretto_fp_program_batch_owned(programs)?;
    Ok(ArchivedRistrettoCompressedAdditionBatchProof { rows, additions })
}

/// Prove `output = Σ scalars[i] · bases[i]` by composing the three batched
/// STARK layers.
pub fn prove_ristretto_msm(
    scalars: &[[u8; LIMBS]],
    bases: &[[u8; LIMBS]],
) -> TexasAirResult<ArchivedRistrettoMsmProof> {
    if scalars.is_empty() || scalars.len() != bases.len() {
        return Err(TexasAirError::SpecViolation(
            "MSM requires a non-empty matching scalar/base list".into(),
        ));
    }
    let windows_proof = prove_ristretto_scalar_windows_batch(scalars)?;
    let inputs = scalars
        .iter()
        .zip(bases)
        .map(|(scalar, base)| (*scalar, windows(scalar), *base))
        .collect::<Vec<_>>();
    let muls = prove_ristretto_fp_program_compressed_fixed_window_scalar_mul_batch(inputs)?;
    let outputs = muls
        .statements
        .iter()
        .map(|statement| statement.output)
        .collect::<Vec<_>>();

    let (output, accumulation) = if outputs.len() == 1 {
        (outputs[0], None)
    } else {
        let accumulation = prove_msm_accumulation(&outputs)?;
        let output = accumulation
            .rows
            .last()
            .expect("accumulation batch is non-empty")
            .output;
        (output, Some(accumulation))
    };

    let archive = ArchivedRistrettoMsmProof {
        scalars: scalars.to_vec(),
        bases: bases.to_vec(),
        output,
        windows: windows_proof,
        muls,
        accumulation,
    };
    if crate::ristretto_fp_program_air::ristretto_self_verify_enabled() {
        verify_ristretto_msm(&archive)?;
    }
    Ok(archive)
}

/// Verify the complete MSM statement: window decompositions, per-pair scalar
/// multiplications, and the output accumulation chain.
pub fn verify_ristretto_msm(archive: &ArchivedRistrettoMsmProof) -> TexasAirResult<()> {
    let count = archive.scalars.len();
    if count == 0 || archive.bases.len() != count {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "MSM statement requires a non-empty matching scalar/base list".into(),
        ));
    }
    verify_ristretto_scalar_windows_batch(&archive.windows)?;
    if archive.windows.rows.len() != count {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "MSM window proof row count is detached".into(),
        ));
    }
    for (row, scalar) in archive.windows.rows.iter().zip(&archive.scalars) {
        if row.scalar != *scalar || row.windows != windows(scalar) {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "MSM window decomposition is detached from its scalar".into(),
            ));
        }
    }

    verify_ristretto_fp_program_compressed_fixed_window_scalar_mul_batch(&archive.muls)?;
    if archive.muls.statements.len() != count {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "MSM scalar-multiplication statement count is detached".into(),
        ));
    }
    let mut outputs = Vec::with_capacity(count);
    for (statement, (scalar, base)) in archive
        .muls
        .statements
        .iter()
        .zip(archive.scalars.iter().zip(&archive.bases))
    {
        if statement.scalar != *scalar
            || statement.windows != windows(scalar)
            || statement.base != *base
        {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "MSM scalar-multiplication statement is detached".into(),
            ));
        }
        outputs.push(statement.output);
    }

    match (&archive.accumulation, count) {
        (None, 1) => {
            if archive.output != outputs[0] {
                return Err(TexasAirError::ConstraintUnsatisfied(
                    "single-pair MSM output is detached".into(),
                ));
            }
        }
        (Some(accumulation), _) => {
            verify_ristretto_compressed_addition_batch(accumulation)?;
            if accumulation.rows.len() != count - 1 {
                return Err(TexasAirError::ConstraintUnsatisfied(
                    "MSM accumulation row count is detached".into(),
                ));
            }
            let mut expected_left = outputs[0];
            for (index, row) in accumulation.rows.iter().enumerate() {
                if row.left != expected_left || row.right != outputs[index + 1] {
                    return Err(TexasAirError::ConstraintUnsatisfied(
                        "MSM accumulation chain is detached".into(),
                    ));
                }
                expected_left = row.output;
            }
            if archive.output != expected_left {
                return Err(TexasAirError::ConstraintUnsatisfied(
                    "MSM output is detached from the accumulation chain".into(),
                ));
            }
        }
        (None, _) => {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "multi-pair MSM requires an accumulation proof".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basepoint() -> [u8; LIMBS] {
        [
            0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71, 0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00,
            0x51, 0x5f, 0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d, 0xb6, 0xa6, 0x59, 0x45,
            0xe0, 0x8d, 0x2d, 0x76,
        ]
    }

    fn identity() -> [u8; LIMBS] {
        [0u8; LIMBS]
    }

    fn scalar(value: u8) -> [u8; LIMBS] {
        let mut out = [0u8; LIMBS];
        out[0] = value;
        out
    }

    fn native_multiple(multiplier: u64) -> Vec<u8> {
        use poker_protocol::crypto::curve::{Curve, CurveScalar, RistrettoCurve};
        let expected = RistrettoCurve::base_g() * <RistrettoCurve as Curve>::Scalar::from_u64(multiplier);
        expected.compress().as_bytes().to_vec()
    }

    #[test]
    fn proves_and_verifies_a_single_pair_msm() {
        let archive = prove_ristretto_msm(&[scalar(2)], &[basepoint()]).unwrap();
        assert_eq!(archive.output.as_slice(), native_multiple(2).as_slice());
        assert!(archive.accumulation.is_none());
        verify_ristretto_msm(&archive).unwrap();
    }

    #[test]
    fn proves_and_verifies_a_three_pair_msm_with_identity() {
        let scalars = [scalar(1), scalar(2), scalar(3)];
        let bases = [basepoint(), basepoint(), identity()];
        let archive = prove_ristretto_msm(&scalars, &bases).unwrap();
        // 1·B + 2·B + 3·𝟘 = 3·B.
        assert_eq!(archive.output.as_slice(), native_multiple(3).as_slice());
        assert_eq!(archive.accumulation.as_ref().map(|a| a.rows.len()), Some(2));
        verify_ristretto_msm(&archive).unwrap();
    }

    #[test]
    fn verifier_rejects_spliced_msm_statements() {
        let archive =
            prove_ristretto_msm(&[scalar(1), scalar(2)], &[basepoint(), basepoint()]).unwrap();
        assert_eq!(archive.output.as_slice(), native_multiple(3).as_slice());
        verify_ristretto_msm(&archive).unwrap();

        let mut spliced = archive.clone();
        spliced.output[0] ^= 1;
        assert!(verify_ristretto_msm(&spliced).is_err());

        let mut spliced = archive.clone();
        spliced.bases[0][0] ^= 1;
        assert!(verify_ristretto_msm(&spliced).is_err());

        let mut spliced = archive.clone();
        spliced.scalars[1][0] ^= 1;
        assert!(verify_ristretto_msm(&spliced).is_err());

        let mut spliced = archive.clone();
        if let Some(accumulation) = &mut spliced.accumulation {
            accumulation.rows[0].output[1] ^= 1;
        }
        assert!(verify_ristretto_msm(&spliced).is_err());

        let mut spliced = archive;
        spliced.scalars.push(scalar(1));
        assert!(verify_ristretto_msm(&spliced).is_err());

        assert!(prove_ristretto_msm(&[], &[]).is_err());
        assert!(prove_ristretto_msm(&[scalar(1)], &[]).is_err());
    }
}
