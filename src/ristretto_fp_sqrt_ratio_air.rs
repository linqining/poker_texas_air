//! Composed Ristretto255 `sqrt_ratio_i` proof.
//!
//! The host computes only the nonnegative-root witness. Verification checks
//! authenticated limb STARKs for `r²`, `v*r²`, and `i*u`, then derives the
//! square/nonsquare choice from those verified public values. It never invokes
//! native field arithmetic to decide admission.

use borsh::{BorshDeserialize, BorshSerialize};
use num_bigint::BigUint;
use num_traits::{One, Zero};

use crate::error::{TexasAirError, TexasAirResult};
use crate::ristretto_fp_mul_air::{
    ArchivedRistrettoFpMultiplicationProof, prove_ristretto_fp_multiplication,
    verify_ristretto_fp_multiplication,
};

const LIMBS: usize = 32;

/// Little-endian bytes of the nonnegative `sqrt(-1)` in
/// `Fp = 2^255 - 19`.
const SQRT_M1_BYTES: [u8; LIMBS] = [
    0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4, 0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
    0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b, 0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b,
];

/// Public `sqrt_ratio_i(u, v)` statement and its verified field relations.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoFpSqrtRatioProof {
    /// Canonical numerator.
    pub u: [u8; LIMBS],
    /// Canonical denominator.
    pub v: [u8; LIMBS],
    /// Canonical nonnegative root returned by `sqrt_ratio_i`.
    pub r: [u8; LIMBS],
    /// Verified `r * r`.
    pub r_squared: [u8; LIMBS],
    /// Verified `v * r_squared`.
    pub check: [u8; LIMBS],
    /// Verified `sqrt(-1) * u`.
    pub i_times_u: [u8; LIMBS],
    /// True when the returned root is `sqrt(u/v)`.
    ///
    /// If false, the returned root is `sqrt(i*u/v)`.
    pub was_square: bool,
    /// Multiplication proof for `r * r = r_squared`.
    pub r_square: ArchivedRistrettoFpMultiplicationProof,
    /// Multiplication proof for `r_squared * v = check`.
    pub check_multiplication: ArchivedRistrettoFpMultiplicationProof,
    /// Multiplication proof for `sqrt(-1) * u = i_times_u`.
    pub i_times_u_multiplication: ArchivedRistrettoFpMultiplicationProof,
}

fn modulus() -> BigUint {
    (BigUint::one() << 255u32) - BigUint::from(19u32)
}

fn big_uint(value: &[u8; LIMBS]) -> BigUint {
    BigUint::from_bytes_le(value)
}

fn limbs(value: &BigUint) -> [u8; LIMBS] {
    let mut out = [0u8; LIMBS];
    let bytes = value.to_bytes_le();
    let length = bytes.len().min(LIMBS);
    out[..length].copy_from_slice(&bytes[..length]);
    out
}

fn multiply(left: &BigUint, right: &BigUint) -> BigUint {
    left * right % modulus()
}

fn sqrt_m1() -> BigUint {
    let p = modulus();
    BigUint::from(2u32).modpow(&((&p - BigUint::one()) >> 2u32), &p)
}

/// Return the unique nonnegative square root, or `None` for a nonsquare.
fn nonnegative_sqrt(value: &BigUint) -> Option<BigUint> {
    if value.is_zero() {
        return Some(BigUint::zero());
    }
    let p = modulus();
    let mut root = value.modpow(&((&p + BigUint::from(3u32)) >> 3u32), &p);
    if multiply(&root, &root) != *value {
        root = multiply(&root, &sqrt_m1());
    }
    if multiply(&root, &root) != *value {
        return None;
    }
    if (&root & BigUint::one()) == BigUint::one() {
        root = &p - root;
    }
    Some(root)
}

/// Prove the exact field-only behavior of curve25519-dalek's
/// `FieldElement::sqrt_ratio_i`.
///
/// In particular, `u = 0` returns `(true, 0)`, a zero denominator with a
/// nonzero numerator returns `(false, 0)`, and otherwise the returned root is
/// the nonnegative square root of either `u/v` or `i*u/v`.
pub fn prove_ristretto_fp_sqrt_ratio(
    u: &[u8; LIMBS],
    v: &[u8; LIMBS],
) -> TexasAirResult<ArchivedRistrettoFpSqrtRatioProof> {
    let p = modulus();
    let u_value = big_uint(u);
    let v_value = big_uint(v);
    if u_value >= p || v_value >= p {
        return Err(TexasAirError::SpecViolation(
            "Ristretto sqrt_ratio inputs must be canonical".into(),
        ));
    }

    let (was_square, r_value) = if u_value.is_zero() {
        (true, BigUint::zero())
    } else if v_value.is_zero() {
        (false, BigUint::zero())
    } else {
        let ratio = multiply(&u_value, &v_value.modpow(&(&p - BigUint::from(2u32)), &p));
        if let Some(root) = nonnegative_sqrt(&ratio) {
            (true, root)
        } else {
            let non_square_target = multiply(&sqrt_m1(), &ratio);
            let root = nonnegative_sqrt(&non_square_target).ok_or_else(|| {
                TexasAirError::SpecViolation(
                    "Ristretto sqrt_ratio witness is neither square nor i-square".into(),
                )
            })?;
            (false, root)
        }
    };

    let r = limbs(&r_value);
    let r_squared_value = multiply(&r_value, &r_value);
    let r_squared = limbs(&r_squared_value);
    let check_value = multiply(&r_squared_value, &v_value);
    let check = limbs(&check_value);
    let i_times_u_value = multiply(&sqrt_m1(), &u_value);
    let i_times_u = limbs(&i_times_u_value);

    let r_square = prove_ristretto_fp_multiplication(&r, &r)?;
    let check_multiplication = prove_ristretto_fp_multiplication(&r_squared, v)?;
    let i_times_u_multiplication = prove_ristretto_fp_multiplication(&SQRT_M1_BYTES, u)?;

    Ok(ArchivedRistrettoFpSqrtRatioProof {
        u: *u,
        v: *v,
        r,
        r_squared,
        check,
        i_times_u,
        was_square,
        r_square,
        check_multiplication,
        i_times_u_multiplication,
    })
}

/// Verify the exact public semantics of `sqrt_ratio_i`.
pub fn verify_ristretto_fp_sqrt_ratio(
    archive: &ArchivedRistrettoFpSqrtRatioProof,
) -> TexasAirResult<()> {
    verify_ristretto_fp_multiplication(&archive.r_square)?;
    verify_ristretto_fp_multiplication(&archive.check_multiplication)?;
    verify_ristretto_fp_multiplication(&archive.i_times_u_multiplication)?;

    let r_square_bound = archive.r_square.a == archive.r
        && archive.r_square.b == archive.r
        && archive.r_square.c == archive.r_squared;
    let check_bound = archive.check_multiplication.a == archive.r_squared
        && archive.check_multiplication.b == archive.v
        && archive.check_multiplication.c == archive.check;
    let i_times_u_bound = archive.i_times_u_multiplication.a == SQRT_M1_BYTES
        && archive.i_times_u_multiplication.b == archive.u
        && archive.i_times_u_multiplication.c == archive.i_times_u;
    if !r_square_bound || !check_bound || !i_times_u_bound {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Ristretto sqrt_ratio multiplication relation is detached".into(),
        ));
    }

    if archive.r[0] & 1 == 1 {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Ristretto sqrt_ratio root must be nonnegative".into(),
        ));
    }

    let zero = [0u8; LIMBS];
    if archive.u == zero {
        if !archive.was_square
            || archive.r != zero
            || archive.r_squared != zero
            || archive.check != zero
        {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "Ristretto sqrt_ratio(0, v) must return the zero root".into(),
            ));
        }
        return Ok(());
    }

    if archive.v == zero {
        if archive.was_square
            || archive.r != zero
            || archive.r_squared != zero
            || archive.check != zero
        {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "Ristretto sqrt_ratio(u, 0) must return false with zero root".into(),
            ));
        }
        return Ok(());
    }

    let expected_check = if archive.was_square {
        archive.u
    } else {
        archive.i_times_u
    };
    if archive.check != expected_check {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Ristretto sqrt_ratio classification is inconsistent with v*r*r".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small(value: u8) -> [u8; LIMBS] {
        let mut out = [0u8; LIMBS];
        out[0] = value;
        out
    }

    fn field(value: &BigUint) -> [u8; LIMBS] {
        limbs(&(value % modulus()))
    }

    #[test]
    fn proves_square_nonsquare_and_ratio_cases() {
        let square = prove_ristretto_fp_sqrt_ratio(&small(4), &small(1)).unwrap();
        assert!(square.was_square);
        assert_eq!(square.r, small(2));
        verify_ristretto_fp_sqrt_ratio(&square).unwrap();

        let nonsquare = prove_ristretto_fp_sqrt_ratio(&small(2), &small(1)).unwrap();
        assert!(!nonsquare.was_square);
        assert_eq!(
            nonsquare.r_squared,
            field(&(big_uint(&SQRT_M1_BYTES) * BigUint::from(2u32)))
        );
        verify_ristretto_fp_sqrt_ratio(&nonsquare).unwrap();

        let ratio = prove_ristretto_fp_sqrt_ratio(&small(1), &small(4)).unwrap();
        assert!(ratio.was_square);
        verify_ristretto_fp_sqrt_ratio(&ratio).unwrap();
    }

    #[test]
    fn proves_dalek_zero_edge_cases() {
        let zero_over_zero = prove_ristretto_fp_sqrt_ratio(&small(0), &small(0)).unwrap();
        assert!(zero_over_zero.was_square);
        assert_eq!(zero_over_zero.r, small(0));
        verify_ristretto_fp_sqrt_ratio(&zero_over_zero).unwrap();

        let nonzero_over_zero = prove_ristretto_fp_sqrt_ratio(&small(1), &small(0)).unwrap();
        assert!(!nonzero_over_zero.was_square);
        assert_eq!(nonzero_over_zero.r, small(0));
        verify_ristretto_fp_sqrt_ratio(&nonzero_over_zero).unwrap();
    }

    #[test]
    fn verifier_rejects_a_flipped_square_classification() {
        let mut archive = prove_ristretto_fp_sqrt_ratio(&small(4), &small(1)).unwrap();
        archive.was_square = false;
        assert!(verify_ristretto_fp_sqrt_ratio(&archive).is_err());
    }

    #[test]
    fn verifier_rejects_a_spliced_root() {
        let archive = prove_ristretto_fp_sqrt_ratio(&small(4), &small(1)).unwrap();
        let mut forged = archive.clone();
        forged.r = small(3);
        assert!(verify_ristretto_fp_sqrt_ratio(&forged).is_err());
    }

    #[test]
    fn witness_matches_dalek_sqrt_ratio_semantics() {
        let i = sqrt_m1();
        for (u_value, v_value) in [(4u32, 1u32), (2, 1), (1, 4), (5, 7)] {
            let u = field(&BigUint::from(u_value));
            let v = field(&BigUint::from(v_value));
            let archive = prove_ristretto_fp_sqrt_ratio(&u, &v).unwrap();
            verify_ristretto_fp_sqrt_ratio(&archive).unwrap();

            let ratio = multiply(
                &big_uint(&u),
                &big_uint(&v).modpow(&(&modulus() - BigUint::from(2u32)), &modulus()),
            );
            let target = if archive.was_square {
                ratio
            } else {
                multiply(&i, &ratio)
            };
            assert_eq!(
                multiply(&big_uint(&archive.r), &big_uint(&archive.r)),
                target
            );
            assert_eq!(archive.r[0] & 1, 0);
        }
    }
}
