//! Composed Ristretto255 field-element modular subtraction.
//!
//! Subtraction is expressed as `a - b = a + (p - b)`.  Two modular-addition
//! STARKs prove both the additive inverse relation and the final sum; the host
//! constructs witnesses but no native comparison or subtraction result is
//! trusted by verification.

use borsh::{BorshDeserialize, BorshSerialize};

use crate::error::{TexasAirError, TexasAirResult};
use crate::ristretto_fp_add_air::{
    ArchivedRistrettoFpAdditionProof, prove_ristretto_fp_addition, verify_ristretto_fp_addition,
};

const LIMBS: usize = 32;

/// Little-endian bytes of the Ristretto255 prime `2^255 - 19`.
const P_BYTES: [u8; LIMBS] = {
    let mut bytes = [0xffu8; LIMBS];
    bytes[0] = 0xed;
    bytes[31] = 0x7f;
    bytes
};

/// Public subtraction statement and its two modular-addition STARKs.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoFpSubtractionProof {
    /// Canonical minuend.
    pub a: [u8; LIMBS],
    /// Canonical subtrahend.
    pub b: [u8; LIMBS],
    /// Canonical difference `a - b mod p`.
    pub c: [u8; LIMBS],
    /// Committed additive inverse `p - b`.
    pub additive_inverse: [u8; LIMBS],
    /// Proves `b + (p - b) = 0 mod p` with exactly one prime reduction.
    pub inverse: ArchivedRistrettoFpAdditionProof,
    /// Proves `a + (p - b) = c mod p`.
    pub difference: ArchivedRistrettoFpAdditionProof,
}

fn less_than_prime(value: &[u8; LIMBS]) -> bool {
    for index in (0..LIMBS).rev() {
        if value[index] != P_BYTES[index] {
            return value[index] < P_BYTES[index];
        }
    }
    false
}

fn prime_minus(value: &[u8; LIMBS]) -> [u8; LIMBS] {
    let mut out = [0u8; LIMBS];
    let mut borrow = false;
    for index in 0..LIMBS {
        let mut prime_limb = u16::from(P_BYTES[index]);
        if borrow {
            prime_limb = prime_limb.saturating_sub(1);
        }
        let current = u16::from(value[index]);
        if prime_limb >= current {
            out[index] =
                u8::try_from(prime_limb - current).expect("prime subtraction limb fits in u8");
            borrow = false;
        } else {
            out[index] = u8::try_from(prime_limb + 256u16 - current)
                .expect("prime subtraction limb fits in u8");
            borrow = true;
        }
    }
    debug_assert!(!borrow);
    out
}

/// Prove `a - b = c mod p` through independently verified addition relations.
pub fn prove_ristretto_fp_subtraction(
    a: &[u8; LIMBS],
    b: &[u8; LIMBS],
) -> TexasAirResult<ArchivedRistrettoFpSubtractionProof> {
    if !less_than_prime(a) || !less_than_prime(b) {
        return Err(TexasAirError::SpecViolation(
            "Ristretto modular subtraction inputs must be canonical".into(),
        ));
    }
    let additive_inverse = if b == &[0u8; LIMBS] {
        [0u8; LIMBS]
    } else {
        prime_minus(b)
    };
    let inverse = prove_ristretto_fp_addition(b, &additive_inverse)?;
    let difference = prove_ristretto_fp_addition(a, &additive_inverse)?;
    if !inverse.reduced && b != &[0u8; LIMBS] {
        return Err(TexasAirError::SpecViolation(
            "nonzero Ristretto inverse must reduce exactly once".into(),
        ));
    }
    Ok(ArchivedRistrettoFpSubtractionProof {
        a: *a,
        b: *b,
        c: difference.c,
        additive_inverse,
        inverse,
        difference,
    })
}

/// Verify the inverse and difference STARKs and their binding to public operands.
pub fn verify_ristretto_fp_subtraction(
    archive: &ArchivedRistrettoFpSubtractionProof,
) -> TexasAirResult<()> {
    verify_ristretto_fp_addition(&archive.inverse)?;
    verify_ristretto_fp_addition(&archive.difference)?;
    let zero = [0u8; LIMBS];
    if archive.inverse.a != archive.b
        || archive.inverse.b != archive.additive_inverse
        || archive.inverse.c != zero
        || (archive.b != zero && !archive.inverse.reduced)
        || (archive.b == zero && archive.inverse.reduced)
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Ristretto additive-inverse relation is invalid".into(),
        ));
    }
    if archive.difference.a != archive.a
        || archive.difference.b != archive.additive_inverse
        || archive.difference.c != archive.c
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Ristretto subtraction result is detached from public operands".into(),
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

    #[test]
    fn proves_reduced_and_unreduced_subtraction() {
        let archive = prove_ristretto_fp_subtraction(&small(2), &small(1)).unwrap();
        assert_eq!(archive.c, small(1));
        verify_ristretto_fp_subtraction(&archive).unwrap();

        let archive = prove_ristretto_fp_subtraction(&small(1), &small(2)).unwrap();
        assert_eq!(archive.c, prime_minus(&small(1)));
        verify_ristretto_fp_subtraction(&archive).unwrap();

        let archive = prove_ristretto_fp_subtraction(&small(0), &small(0)).unwrap();
        assert_eq!(archive.c, [0u8; LIMBS]);
        verify_ristretto_fp_subtraction(&archive).unwrap();
    }

    #[test]
    fn verifier_rejects_operand_and_result_splices() {
        let archive = prove_ristretto_fp_subtraction(&small(2), &small(1)).unwrap();
        let mut wrong_a = archive.clone();
        wrong_a.a = small(9);
        assert!(verify_ristretto_fp_subtraction(&wrong_a).is_err());

        let mut wrong_c = archive;
        wrong_c.c = small(9);
        assert!(verify_ristretto_fp_subtraction(&wrong_c).is_err());
    }
}
