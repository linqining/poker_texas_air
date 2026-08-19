//! Composed host-zero Ristretto255 canonical-point encoding.
//!
//! The input is a decoded, already-authenticated extended Edwards point. Every
//! field value used by the Ristretto compression formula is bound to a verified
//! add/sub/mul or `sqrt_ratio_i` proof, and the verifier derives both branch
//! selections from authenticated sign bits.

use borsh::{BorshDeserialize, BorshSerialize};
use num_bigint::BigUint;
use num_traits::{One, Zero};

use crate::error::{TexasAirError, TexasAirResult};
use crate::ristretto_fp_add_air::{
    ArchivedRistrettoFpAdditionProof, prove_ristretto_fp_addition, verify_ristretto_fp_addition,
};
use crate::ristretto_fp_mul_air::{
    ArchivedRistrettoFpMultiplicationProof, prove_ristretto_fp_multiplication,
    verify_ristretto_fp_multiplication,
};
use crate::ristretto_fp_sqrt_ratio_air::{
    ArchivedRistrettoFpSqrtRatioProof, prove_ristretto_fp_sqrt_ratio,
    verify_ristretto_fp_sqrt_ratio,
};
use crate::ristretto_fp_sub_air::{
    ArchivedRistrettoFpSubtractionProof, prove_ristretto_fp_subtraction,
    verify_ristretto_fp_subtraction,
};
use crate::ristretto_point_decode_air::{
    ArchivedRistrettoPointDecodeProof, prove_ristretto_point_decode, verify_ristretto_point_decode,
};

const LIMBS: usize = 32;
const ZERO: [u8; LIMBS] = [0u8; LIMBS];
const ONE: [u8; LIMBS] = {
    let mut bytes = [0u8; LIMBS];
    bytes[0] = 1;
    bytes
};

/// Public encode result and all verified compression intermediates.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoPointEncodeProof {
    /// Authenticated decoded input point.
    pub point: ArchivedRistrettoPointDecodeProof,
    /// Canonical nonnegative 32-byte output encoding.
    pub encoding: [u8; LIMBS],
    /// Verified `Z+Y`.
    pub z_plus_y: [u8; LIMBS],
    /// Verified `Z-Y`.
    pub z_minus_y: [u8; LIMBS],
    /// Verified `u1=(Z+Y)(Z-Y)`.
    pub u1: [u8; LIMBS],
    /// Verified `u2=X*Y`.
    pub u2: [u8; LIMBS],
    /// Verified `u2*u2`.
    pub u2_squared: [u8; LIMBS],
    /// Verified `u1*u2*u2`.
    pub v: [u8; LIMBS],
    /// Verified `1/sqrt(u1*u2*u2)`.
    pub invsqrt: [u8; LIMBS],
    /// Verified `invsqrt*u1`.
    pub i1: [u8; LIMBS],
    /// Verified `invsqrt*u2`.
    pub i2: [u8; LIMBS],
    /// Verified `i2*T`.
    pub i2_times_t: [u8; LIMBS],
    /// Verified `i1*i2*T`.
    pub z_inverse: [u8; LIMBS],
    /// Verified `T*z_inverse`.
    pub t_times_z_inverse: [u8; LIMBS],
    /// Verified `X*sqrt(-1)`.
    pub i_x: [u8; LIMBS],
    /// Verified `Y*sqrt(-1)`.
    pub i_y: [u8; LIMBS],
    /// Verified `i1*INVSQRT_A_MINUS_D`.
    pub enchanted_denominator: [u8; LIMBS],
    /// Branch-selected `X`.
    pub selected_x: [u8; LIMBS],
    /// Branch-selected `Y` before final sign correction.
    pub selected_y: [u8; LIMBS],
    /// Branch-selected denominator inverse.
    pub selected_denominator: [u8; LIMBS],
    /// Verified `selected_x*z_inverse`.
    pub x_times_z_inverse: [u8; LIMBS],
    /// Additive inverse of `selected_y`.
    pub negative_selected_y: [u8; LIMBS],
    /// Final branch-selected `Y`.
    pub final_y: [u8; LIMBS],
    /// Verified `Z-final_y`.
    pub z_minus_final_y: [u8; LIMBS],
    /// Verified `selected_denominator*(Z-final_y)`.
    pub s_raw: [u8; LIMBS],
    /// Additive inverse of `s_raw`.
    pub negative_s_raw: [u8; LIMBS],
    /// Proves `Z+Y`.
    pub z_plus_y_proof: ArchivedRistrettoFpAdditionProof,
    /// Proves `Z-Y`.
    pub z_minus_y_proof: ArchivedRistrettoFpSubtractionProof,
    /// Proves `u1`.
    pub u1_proof: ArchivedRistrettoFpMultiplicationProof,
    /// Proves `u2`.
    pub u2_proof: ArchivedRistrettoFpMultiplicationProof,
    /// Proves `u2_squared`.
    pub u2_squared_proof: ArchivedRistrettoFpMultiplicationProof,
    /// Proves `v`.
    pub v_proof: ArchivedRistrettoFpMultiplicationProof,
    /// Proves `sqrt_ratio_i(1,v)`.
    pub invsqrt_proof: ArchivedRistrettoFpSqrtRatioProof,
    /// Proves `i1`.
    pub i1_proof: ArchivedRistrettoFpMultiplicationProof,
    /// Proves `i2`.
    pub i2_proof: ArchivedRistrettoFpMultiplicationProof,
    /// Proves `i2*T`.
    pub i2_times_t_proof: ArchivedRistrettoFpMultiplicationProof,
    /// Proves `z_inverse`.
    pub z_inverse_proof: ArchivedRistrettoFpMultiplicationProof,
    /// Proves `T*z_inverse`.
    pub t_times_z_inverse_proof: ArchivedRistrettoFpMultiplicationProof,
    /// Proves `i_x`.
    pub i_x_proof: ArchivedRistrettoFpMultiplicationProof,
    /// Proves `i_y`.
    pub i_y_proof: ArchivedRistrettoFpMultiplicationProof,
    /// Proves enchanted denominator.
    pub enchanted_denominator_proof: ArchivedRistrettoFpMultiplicationProof,
    /// Proves `selected_x*z_inverse`.
    pub x_times_z_inverse_proof: ArchivedRistrettoFpMultiplicationProof,
    /// Proves `-selected_y`.
    pub negative_selected_y_proof: ArchivedRistrettoFpSubtractionProof,
    /// Proves `Z-final_y`.
    pub z_minus_final_y_proof: ArchivedRistrettoFpSubtractionProof,
    /// Proves `s_raw`.
    pub s_raw_proof: ArchivedRistrettoFpMultiplicationProof,
    /// Proves `-s_raw`.
    pub negative_s_raw_proof: ArchivedRistrettoFpSubtractionProof,
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

fn add(left: &BigUint, right: &BigUint) -> BigUint {
    (left + right) % modulus()
}

fn subtract(left: &BigUint, right: &BigUint) -> BigUint {
    if left >= right {
        left - right
    } else {
        left + modulus() - right
    }
}

fn negative(value: &BigUint) -> BigUint {
    if value.is_zero() {
        BigUint::zero()
    } else {
        modulus() - value
    }
}

fn sqrt_m1() -> BigUint {
    BigUint::from(2u32).modpow(&((&modulus() - BigUint::one()) >> 2u32), &modulus())
}

fn invsqrt_a_minus_d() -> BigUint {
    BigUint::parse_bytes(
        b"54469307008909316920995813868745141605393597292927456921205312896311721017578",
        10,
    )
    .expect("decimal Ristretto magic constant is valid")
}

/// Decode and then prove the canonical Ristretto encoding of a 32-byte point.
pub fn prove_ristretto_point_encode(
    encoding: &[u8; LIMBS],
) -> TexasAirResult<ArchivedRistrettoPointEncodeProof> {
    let point = prove_ristretto_point_decode(encoding)?;
    prove_ristretto_decoded_point_encode(point)
}

/// Prove canonical encoding of an already-generated decoded point witness.
pub fn prove_ristretto_decoded_point_encode(
    point: ArchivedRistrettoPointDecodeProof,
) -> TexasAirResult<ArchivedRistrettoPointEncodeProof> {
    let x = big_uint(&point.x);
    let y = big_uint(&point.y);
    let z = big_uint(&ONE);
    let t = big_uint(&point.t);

    let z_plus_y_value = add(&z, &y);
    let z_minus_y_value = subtract(&z, &y);
    let u1_value = multiply(&z_plus_y_value, &z_minus_y_value);
    let u2_value = multiply(&x, &y);
    let u2_squared_value = multiply(&u2_value, &u2_value);
    let v_value = multiply(&u1_value, &u2_squared_value);
    let invsqrt_proof_value = prove_ristretto_fp_sqrt_ratio(&ONE, &limbs(&v_value))?;
    let v = limbs(&v_value);
    if !invsqrt_proof_value.was_square && v != ZERO {
        return Err(TexasAirError::SpecViolation(
            "Ristretto encode inverse square root does not exist".into(),
        ));
    }
    let invsqrt_value = big_uint(&invsqrt_proof_value.r);
    let i1_value = multiply(&invsqrt_value, &u1_value);
    let i2_value = multiply(&invsqrt_value, &u2_value);
    let i2_times_t_value = multiply(&i2_value, &t);
    let z_inverse_value = multiply(&i1_value, &i2_times_t_value);
    let t_times_z_inverse_value = multiply(&t, &z_inverse_value);
    let i_x_value = multiply(&x, &sqrt_m1());
    let i_y_value = multiply(&y, &sqrt_m1());
    let enchanted_value = multiply(&i1_value, &invsqrt_a_minus_d());

    let rotate = (t_times_z_inverse_value.clone() & BigUint::one()) == BigUint::one();
    let selected_x_value = if rotate { i_y_value.clone() } else { x.clone() };
    let selected_y_value = if rotate { i_x_value.clone() } else { y.clone() };
    let selected_denominator_value = if rotate {
        enchanted_value.clone()
    } else {
        i2_value.clone()
    };
    let x_times_z_inverse_value = multiply(&selected_x_value, &z_inverse_value);
    let negate_y = (x_times_z_inverse_value.clone() & BigUint::one()) == BigUint::one();
    let negative_selected_y_value = negative(&selected_y_value);
    let final_y_value = if negate_y {
        negative_selected_y_value.clone()
    } else {
        selected_y_value.clone()
    };
    let z_minus_final_y_value = subtract(&z, &final_y_value);
    let s_raw_value = multiply(&selected_denominator_value, &z_minus_final_y_value);
    let negative_s_raw_value = negative(&s_raw_value);
    let encoding_value = if (s_raw_value.clone() & BigUint::one()) == BigUint::one() {
        negative_s_raw_value.clone()
    } else {
        s_raw_value.clone()
    };

    let z_plus_y = limbs(&z_plus_y_value);
    let z_minus_y = limbs(&z_minus_y_value);
    let u1 = limbs(&u1_value);
    let u2 = limbs(&u2_value);
    let u2_squared = limbs(&u2_squared_value);
    let i1 = limbs(&i1_value);
    let i2 = limbs(&i2_value);
    let i2_times_t = limbs(&i2_times_t_value);
    let z_inverse = limbs(&z_inverse_value);
    let t_times_z_inverse = limbs(&t_times_z_inverse_value);
    let i_x = limbs(&i_x_value);
    let i_y = limbs(&i_y_value);
    let enchanted_denominator = limbs(&enchanted_value);
    let x_times_z_inverse = limbs(&x_times_z_inverse_value);
    let negative_selected_y = limbs(&negative_selected_y_value);
    let z_minus_final_y = limbs(&z_minus_final_y_value);
    let s_raw = limbs(&s_raw_value);
    let negative_s_raw = limbs(&negative_s_raw_value);
    let sqrt_m1_bytes = limbs(&sqrt_m1());
    let magic = limbs(&invsqrt_a_minus_d());

    let z_plus_y_proof = prove_ristretto_fp_addition(&ONE, &point.y)?;
    let z_minus_y_proof = prove_ristretto_fp_subtraction(&ONE, &point.y)?;
    let u1_proof = prove_ristretto_fp_multiplication(&z_plus_y, &z_minus_y)?;
    let u2_proof = prove_ristretto_fp_multiplication(&point.x, &point.y)?;
    let u2_squared_proof = prove_ristretto_fp_multiplication(&u2, &u2)?;
    let v_proof = prove_ristretto_fp_multiplication(&u1, &u2_squared)?;
    let i1_proof = prove_ristretto_fp_multiplication(&invsqrt_proof_value.r, &u1)?;
    let i2_proof = prove_ristretto_fp_multiplication(&invsqrt_proof_value.r, &u2)?;
    let i2_times_t_proof = prove_ristretto_fp_multiplication(&i2, &point.t)?;
    let z_inverse_proof = prove_ristretto_fp_multiplication(&i1, &i2_times_t)?;
    let t_times_z_inverse_proof = prove_ristretto_fp_multiplication(&point.t, &z_inverse)?;
    let i_x_proof = prove_ristretto_fp_multiplication(&point.x, &sqrt_m1_bytes)?;
    let i_y_proof = prove_ristretto_fp_multiplication(&point.y, &sqrt_m1_bytes)?;
    let enchanted_denominator_proof = prove_ristretto_fp_multiplication(&i1, &magic)?;
    let x_times_z_inverse_proof =
        prove_ristretto_fp_multiplication(&limbs(&selected_x_value), &z_inverse)?;
    let negative_selected_y_proof =
        prove_ristretto_fp_subtraction(&ZERO, &limbs(&selected_y_value))?;
    let z_minus_final_y_proof = prove_ristretto_fp_subtraction(&ONE, &limbs(&final_y_value))?;
    let s_raw_proof =
        prove_ristretto_fp_multiplication(&limbs(&selected_denominator_value), &z_minus_final_y)?;
    let negative_s_raw_proof = prove_ristretto_fp_subtraction(&ZERO, &s_raw)?;

    Ok(ArchivedRistrettoPointEncodeProof {
        point,
        encoding: limbs(&encoding_value),
        z_plus_y,
        z_minus_y,
        u1,
        u2,
        u2_squared,
        v,
        invsqrt: invsqrt_proof_value.r,
        i1,
        i2,
        i2_times_t,
        z_inverse,
        t_times_z_inverse,
        i_x,
        i_y,
        enchanted_denominator,
        selected_x: limbs(&selected_x_value),
        selected_y: limbs(&selected_y_value),
        selected_denominator: limbs(&selected_denominator_value),
        x_times_z_inverse,
        negative_selected_y,
        final_y: limbs(&final_y_value),
        z_minus_final_y,
        s_raw,
        negative_s_raw,
        z_plus_y_proof,
        z_minus_y_proof,
        u1_proof,
        u2_proof,
        u2_squared_proof,
        v_proof,
        invsqrt_proof: invsqrt_proof_value,
        i1_proof,
        i2_proof,
        i2_times_t_proof,
        z_inverse_proof,
        t_times_z_inverse_proof,
        i_x_proof,
        i_y_proof,
        enchanted_denominator_proof,
        x_times_z_inverse_proof,
        negative_selected_y_proof,
        z_minus_final_y_proof,
        s_raw_proof,
        negative_s_raw_proof,
    })
}

fn bind_multiplication(
    proof: &ArchivedRistrettoFpMultiplicationProof,
    a: &[u8; LIMBS],
    b: &[u8; LIMBS],
    c: &[u8; LIMBS],
) -> bool {
    proof.a == *a && proof.b == *b && proof.c == *c
}

fn bind_addition(
    proof: &ArchivedRistrettoFpAdditionProof,
    a: &[u8; LIMBS],
    b: &[u8; LIMBS],
    c: &[u8; LIMBS],
) -> bool {
    proof.a == *a && proof.b == *b && proof.c == *c
}

fn bind_subtraction(
    proof: &ArchivedRistrettoFpSubtractionProof,
    a: &[u8; LIMBS],
    b: &[u8; LIMBS],
    c: &[u8; LIMBS],
) -> bool {
    proof.a == *a && proof.b == *b && proof.c == *c
}

/// Verify canonical Ristretto encoding without native curve operations.
pub fn verify_ristretto_point_encode(
    archive: &ArchivedRistrettoPointEncodeProof,
) -> TexasAirResult<()> {
    verify_ristretto_point_decode(&archive.point)?;
    verify_ristretto_fp_addition(&archive.z_plus_y_proof)?;
    verify_ristretto_fp_subtraction(&archive.z_minus_y_proof)?;
    verify_ristretto_fp_multiplication(&archive.u1_proof)?;
    verify_ristretto_fp_multiplication(&archive.u2_proof)?;
    verify_ristretto_fp_multiplication(&archive.u2_squared_proof)?;
    verify_ristretto_fp_multiplication(&archive.v_proof)?;
    verify_ristretto_fp_sqrt_ratio(&archive.invsqrt_proof)?;
    verify_ristretto_fp_multiplication(&archive.i1_proof)?;
    verify_ristretto_fp_multiplication(&archive.i2_proof)?;
    verify_ristretto_fp_multiplication(&archive.i2_times_t_proof)?;
    verify_ristretto_fp_multiplication(&archive.z_inverse_proof)?;
    verify_ristretto_fp_multiplication(&archive.t_times_z_inverse_proof)?;
    verify_ristretto_fp_multiplication(&archive.i_x_proof)?;
    verify_ristretto_fp_multiplication(&archive.i_y_proof)?;
    verify_ristretto_fp_multiplication(&archive.enchanted_denominator_proof)?;
    verify_ristretto_fp_multiplication(&archive.x_times_z_inverse_proof)?;
    verify_ristretto_fp_subtraction(&archive.negative_selected_y_proof)?;
    verify_ristretto_fp_subtraction(&archive.z_minus_final_y_proof)?;
    verify_ristretto_fp_multiplication(&archive.s_raw_proof)?;
    verify_ristretto_fp_subtraction(&archive.negative_s_raw_proof)?;

    let sqrt_m1 = limbs(&sqrt_m1());
    let magic = limbs(&invsqrt_a_minus_d());
    let checks = [
        (
            true,
            bind_addition(
                &archive.z_plus_y_proof,
                &ONE,
                &archive.point.y,
                &archive.z_plus_y,
            ),
        ),
        (
            true,
            bind_subtraction(
                &archive.z_minus_y_proof,
                &ONE,
                &archive.point.y,
                &archive.z_minus_y,
            ),
        ),
        (
            true,
            bind_multiplication(
                &archive.u1_proof,
                &archive.z_plus_y,
                &archive.z_minus_y,
                &archive.u1,
            ),
        ),
        (
            true,
            bind_multiplication(
                &archive.u2_proof,
                &archive.point.x,
                &archive.point.y,
                &archive.u2,
            ),
        ),
        (
            true,
            bind_multiplication(
                &archive.u2_squared_proof,
                &archive.u2,
                &archive.u2,
                &archive.u2_squared,
            ),
        ),
        (
            true,
            bind_multiplication(
                &archive.v_proof,
                &archive.u1,
                &archive.u2_squared,
                &archive.v,
            ),
        ),
        (
            archive.invsqrt_proof.u == ONE
                && archive.invsqrt_proof.v == archive.v
                && archive.invsqrt_proof.r == archive.invsqrt
                && ((archive.invsqrt_proof.was_square && archive.v != ZERO)
                    || (!archive.invsqrt_proof.was_square
                        && archive.v == ZERO
                        && archive.invsqrt == ZERO)),
            bind_multiplication(
                &archive.i1_proof,
                &archive.invsqrt,
                &archive.u1,
                &archive.i1,
            ),
        ),
        (
            true,
            bind_multiplication(
                &archive.i2_proof,
                &archive.invsqrt,
                &archive.u2,
                &archive.i2,
            ),
        ),
        (
            true,
            bind_multiplication(
                &archive.i2_times_t_proof,
                &archive.i2,
                &archive.point.t,
                &archive.i2_times_t,
            ),
        ),
        (
            true,
            bind_multiplication(
                &archive.z_inverse_proof,
                &archive.i1,
                &archive.i2_times_t,
                &archive.z_inverse,
            ),
        ),
        (
            true,
            bind_multiplication(
                &archive.t_times_z_inverse_proof,
                &archive.point.t,
                &archive.z_inverse,
                &archive.t_times_z_inverse,
            ),
        ),
        (
            true,
            bind_multiplication(&archive.i_x_proof, &archive.point.x, &sqrt_m1, &archive.i_x),
        ),
        (
            true,
            bind_multiplication(&archive.i_y_proof, &archive.point.y, &sqrt_m1, &archive.i_y),
        ),
        (
            true,
            bind_multiplication(
                &archive.enchanted_denominator_proof,
                &archive.i1,
                &magic,
                &archive.enchanted_denominator,
            ),
        ),
        (
            true,
            bind_multiplication(
                &archive.x_times_z_inverse_proof,
                &archive.selected_x,
                &archive.z_inverse,
                &archive.x_times_z_inverse,
            ),
        ),
        (
            true,
            bind_subtraction(
                &archive.negative_selected_y_proof,
                &ZERO,
                &archive.selected_y,
                &archive.negative_selected_y,
            ),
        ),
        (
            true,
            bind_subtraction(
                &archive.z_minus_final_y_proof,
                &ONE,
                &archive.final_y,
                &archive.z_minus_final_y,
            ),
        ),
        (
            true,
            bind_multiplication(
                &archive.s_raw_proof,
                &archive.selected_denominator,
                &archive.z_minus_final_y,
                &archive.s_raw,
            ),
        ),
        (
            true,
            bind_subtraction(
                &archive.negative_s_raw_proof,
                &ZERO,
                &archive.s_raw,
                &archive.negative_s_raw,
            ),
        ),
    ];
    if checks.iter().any(|(bound, _)| !bound) {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Ristretto encode field relation is detached".into(),
        ));
    }

    let rotate = archive.t_times_z_inverse[0] & 1 == 1;
    let expected_x = if rotate { archive.i_y } else { archive.point.x };
    let expected_y = if rotate { archive.i_x } else { archive.point.y };
    let expected_denominator = if rotate {
        archive.enchanted_denominator
    } else {
        archive.i2
    };
    let negate_y = archive.x_times_z_inverse[0] & 1 == 1;
    let expected_final_y = if negate_y {
        archive.negative_selected_y
    } else {
        archive.selected_y
    };
    let expected_encoding = if archive.s_raw[0] & 1 == 1 {
        archive.negative_s_raw
    } else {
        archive.s_raw
    };

    if archive.selected_x != expected_x
        || archive.selected_y != expected_y
        || archive.selected_denominator != expected_denominator
        || archive.final_y != expected_final_y
        || archive.encoding != expected_encoding
        || archive.encoding[0] & 1 == 1
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Ristretto encode canonical branch is invalid".into(),
        ));
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

    #[test]
    fn encode_restores_identity_and_basepoint() {
        let identity = prove_ristretto_point_encode(&ZERO).unwrap();
        assert_eq!(identity.encoding, ZERO);
        verify_ristretto_point_encode(&identity).unwrap();

        let base = prove_ristretto_point_encode(&basepoint()).unwrap();
        assert_eq!(base.encoding, basepoint());
        verify_ristretto_point_encode(&base).unwrap();
    }

    #[test]
    fn verifier_rejects_a_spliced_encoding() {
        let mut archive = prove_ristretto_point_encode(&basepoint()).unwrap();
        archive.encoding[0] ^= 2;
        assert!(verify_ristretto_point_encode(&archive).is_err());
    }
}
