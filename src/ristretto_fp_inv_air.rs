//! Composed Ristretto255 field-element multiplicative-inverse proof.
//!
//! The host proposes an inverse witness, but verification only accepts it when
//! the independently verified multiplication STARK proves `x * y = 1 mod p`.
//! This also proves `x != 0`; no native modular exponentiation is used by the
//! verifier.

use borsh::{BorshDeserialize, BorshSerialize};
use num_bigint::BigUint;
use num_traits::{One, Zero};

use crate::error::{TexasAirError, TexasAirResult};
use crate::ristretto_fp_mul_air::{
    ArchivedRistrettoFpMultiplicationProof, prove_ristretto_fp_multiplication,
    verify_ristretto_fp_multiplication,
};

const LIMBS: usize = 32;

/// Little-endian bytes of the Ristretto255 prime `2^255 - 19`.
#[cfg(test)]
const P_BYTES: [u8; LIMBS] = {
    let mut bytes = [0xffu8; LIMBS];
    bytes[0] = 0xed;
    bytes[31] = 0x7f;
    bytes
};

/// Public inverse statement and its verified multiplication relation.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoFpInverseProof {
    /// Canonical non-zero input.
    pub value: [u8; LIMBS],
    /// Verified multiplicative inverse modulo the Ristretto prime.
    pub inverse: [u8; LIMBS],
    /// Multiplication proof for `value * inverse = 1`.
    pub multiplication: ArchivedRistrettoFpMultiplicationProof,
}

fn limbs(value: &BigUint) -> [u8; LIMBS] {
    let mut out = [0u8; LIMBS];
    let bytes = value.to_bytes_le();
    let length = bytes.len().min(LIMBS);
    out[..length].copy_from_slice(&bytes[..length]);
    out
}

/// Prove that `inverse` is the multiplicative inverse of a non-zero input.
pub fn prove_ristretto_fp_inverse(
    value: &[u8; LIMBS],
) -> TexasAirResult<ArchivedRistrettoFpInverseProof> {
    let value_integer = BigUint::from_bytes_le(value);
    let p = (BigUint::one() << 255u32) - BigUint::from(19u32);
    if value_integer >= p {
        return Err(TexasAirError::SpecViolation(
            "Ristretto inverse input must be canonical".into(),
        ));
    }
    if value_integer.is_zero() {
        return Err(TexasAirError::SpecViolation(
            "zero has no Ristretto multiplicative inverse".into(),
        ));
    }
    let inverse_integer = value_integer.modpow(&(&p - BigUint::from(2u32)), &p);
    let inverse = limbs(&inverse_integer);
    let multiplication = prove_ristretto_fp_multiplication(value, &inverse)?;
    Ok(ArchivedRistrettoFpInverseProof {
        value: *value,
        inverse,
        multiplication,
    })
}

/// Verify `value * inverse = 1 mod p` through the multiplication STARK.
pub fn verify_ristretto_fp_inverse(
    archive: &ArchivedRistrettoFpInverseProof,
) -> TexasAirResult<()> {
    verify_ristretto_fp_multiplication(&archive.multiplication)?;
    let mut one = [0u8; LIMBS];
    one[0] = 1;
    if archive.multiplication.a != archive.value
        || archive.multiplication.b != archive.inverse
        || archive.multiplication.c != one
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Ristretto inverse relation is detached from public operands".into(),
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
    fn proves_one_two_and_prime_minus_one_inverses() {
        let mut prime_minus_one = P_BYTES;
        prime_minus_one[0] -= 1;
        for value in [small(1), small(2), prime_minus_one] {
            let archive = prove_ristretto_fp_inverse(&value).unwrap();
            verify_ristretto_fp_inverse(&archive).unwrap();
        }
    }

    #[test]
    fn zero_rejects_before_proving() {
        assert!(prove_ristretto_fp_inverse(&[0u8; LIMBS]).is_err());
    }

    #[test]
    fn verifier_rejects_public_operand_splice() {
        let archive = prove_ristretto_fp_inverse(&small(2)).unwrap();
        let mut forged = archive;
        forged.value[0] ^= 1;
        assert!(verify_ristretto_fp_inverse(&forged).is_err());
    }
}
