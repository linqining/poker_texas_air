//! Composed host-zero Ristretto255 canonical-point decoding.
//!
//! This bridges an authenticated 32-byte state/request encoding to extended
//! Edwards coordinates. The host constructs witnesses; verification accepts an
//! encoding only when every field relation and canonical branch condition is
//! independently proven.

use borsh::{BorshDeserialize, BorshSerialize};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use std::sync::OnceLock;

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

const LIMBS: usize = 32;
const ZERO: [u8; LIMBS] = [0u8; LIMBS];
const ONE: [u8; LIMBS] = {
    let mut bytes = [0u8; LIMBS];
    bytes[0] = 1;
    bytes
};

/// Public decode statement and all verified intermediate field relations.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoPointDecodeProof {
    /// Canonical nonnegative input encoding.
    pub encoding: [u8; LIMBS],
    /// Nonnegative extended-coordinate `X`.
    pub x: [u8; LIMBS],
    /// Nonzero extended-coordinate `Y`.
    pub y: [u8; LIMBS],
    /// Nonnegative extended-coordinate `T = X*Y`.
    pub t: [u8; LIMBS],
    /// Verified `s*s`.
    pub s_squared: [u8; LIMBS],
    /// Verified `1 - s*s`.
    pub u1: [u8; LIMBS],
    /// Verified `1 + s*s`.
    pub u2: [u8; LIMBS],
    /// Verified `u2*u2`.
    pub u2_squared: [u8; LIMBS],
    /// Verified `u1*u1`.
    pub u1_squared: [u8; LIMBS],
    /// Verified `(-d)*u1*u1`.
    pub negative_d_times_u1_squared: [u8; LIMBS],
    /// Verified `(-d)*u1*u1 - u2*u2`.
    pub v: [u8; LIMBS],
    /// Verified `v*u2*u2`.
    pub v_times_u2_squared: [u8; LIMBS],
    /// Verified `1/sqrt(v*u2*u2)`.
    pub inverse_sqrt: [u8; LIMBS],
    /// Verified `inverse_sqrt*u2`.
    pub dx: [u8; LIMBS],
    /// Verified `dx*v`.
    pub dx_times_v: [u8; LIMBS],
    /// Verified `inverse_sqrt*dx*v`.
    pub dy: [u8; LIMBS],
    /// Verified `s+s`.
    pub two_s: [u8; LIMBS],
    /// Verified `2s*dx` before nonnegative selection.
    pub x_raw: [u8; LIMBS],
    /// Verified additive inverse of `x_raw`.
    pub x_negative: [u8; LIMBS],
    /// Proves `s*s = s_squared`.
    pub s_squared_proof: ArchivedRistrettoFpMultiplicationProof,
    /// Proves `1 - s_squared = u1`.
    pub u1_proof: ArchivedRistrettoFpSubtractionProof,
    /// Proves `1 + s_squared = u2`.
    pub u2_proof: ArchivedRistrettoFpAdditionProof,
    /// Proves `u2*u2 = u2_squared`.
    pub u2_squared_proof: ArchivedRistrettoFpMultiplicationProof,
    /// Proves `u1*u1 = u1_squared`.
    pub u1_squared_proof: ArchivedRistrettoFpMultiplicationProof,
    /// Proves `(-d)*u1_squared = negative_d_times_u1_squared`.
    pub negative_d_times_u1_squared_proof: ArchivedRistrettoFpMultiplicationProof,
    /// Proves the final Edwards `v` expression.
    pub v_proof: ArchivedRistrettoFpSubtractionProof,
    /// Proves `v*u2_squared = v_times_u2_squared`.
    pub v_times_u2_squared_proof: ArchivedRistrettoFpMultiplicationProof,
    /// Proves the decode inverse square root and square branch.
    pub inverse_sqrt_proof: ArchivedRistrettoFpSqrtRatioProof,
    /// Proves `inverse_sqrt*u2 = dx`.
    pub dx_proof: ArchivedRistrettoFpMultiplicationProof,
    /// Proves `dx*v = dx_times_v`.
    pub dx_times_v_proof: ArchivedRistrettoFpMultiplicationProof,
    /// Proves `inverse_sqrt*dx_times_v = dy`.
    pub dy_proof: ArchivedRistrettoFpMultiplicationProof,
    /// Proves `s+s = two_s`.
    pub two_s_proof: ArchivedRistrettoFpAdditionProof,
    /// Proves `two_s*dx = x_raw`.
    pub x_raw_proof: ArchivedRistrettoFpMultiplicationProof,
    /// Proves `0-x_raw = x_negative`.
    pub x_negative_proof: ArchivedRistrettoFpSubtractionProof,
    /// Proves `u1*dy = y`.
    pub y_proof: ArchivedRistrettoFpMultiplicationProof,
    /// Proves `x*y = t`.
    pub t_proof: ArchivedRistrettoFpMultiplicationProof,
}

fn modulus() -> &'static BigUint {
    static MODULUS: OnceLock<BigUint> = OnceLock::new();
    MODULUS.get_or_init(|| (BigUint::one() << 255u32) - BigUint::from(19u32))
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

fn subtract(left: &BigUint, right: &BigUint) -> BigUint {
    if left >= right {
        left - right
    } else {
        left + modulus() - right
    }
}

fn add(left: &BigUint, right: &BigUint) -> BigUint {
    (left + right) % modulus()
}

fn edwards_d() -> &'static BigUint {
    static EDWARDS_D: OnceLock<BigUint> = OnceLock::new();
    EDWARDS_D.get_or_init(|| {
        BigUint::parse_bytes(
            b"37095705934669439343138083508754565189542113879843219016388785533085940283555",
            10,
        )
        .expect("decimal Edwards d is valid")
    })
}

fn nonnegative(value: &BigUint) -> BigUint {
    if (value & BigUint::one()) == BigUint::one() {
        modulus() - value
    } else {
        value.clone()
    }
}

fn negative_edwards_d_bytes() -> &'static [u8; LIMBS] {
    static NEGATIVE_D: OnceLock<[u8; LIMBS]> = OnceLock::new();
    NEGATIVE_D.get_or_init(|| limbs(&(modulus() - edwards_d())))
}

/// Prove canonical decoding of a Ristretto255 compressed point.
pub fn prove_ristretto_point_decode(
    encoding: &[u8; LIMBS],
) -> TexasAirResult<ArchivedRistrettoPointDecodeProof> {
    let p = modulus();
    let s = big_uint(encoding);
    if s >= *p {
        return Err(TexasAirError::SpecViolation(
            "Ristretto point encoding is noncanonical".into(),
        ));
    }
    if (s.clone() & BigUint::one()) == BigUint::one() {
        return Err(TexasAirError::SpecViolation(
            "Ristretto point encoding is negative".into(),
        ));
    }

    let one = BigUint::one();
    let s_squared_value = multiply(&s, &s);
    let u1_value = subtract(&one, &s_squared_value);
    let u2_value = add(&one, &s_squared_value);
    let u2_squared_value = multiply(&u2_value, &u2_value);
    let u1_squared_value = multiply(&u1_value, &u1_value);
    let negative_d = subtract(&p, &edwards_d());
    let negative_d_times_u1_squared_value = multiply(&negative_d, &u1_squared_value);
    let v_value = subtract(&negative_d_times_u1_squared_value, &u2_squared_value);
    let v_times_u2_squared_value = multiply(&v_value, &u2_squared_value);

    let inverse_sqrt_proof =
        prove_ristretto_fp_sqrt_ratio(&ONE, &limbs(&v_times_u2_squared_value))?;
    if !inverse_sqrt_proof.was_square {
        return Err(TexasAirError::SpecViolation(
            "Ristretto point decode inverse square root does not exist".into(),
        ));
    }
    let inverse_sqrt_value = big_uint(&inverse_sqrt_proof.r);

    let dx_value = multiply(&inverse_sqrt_value, &u2_value);
    let dx_times_v_value = multiply(&dx_value, &v_value);
    let dy_value = multiply(&inverse_sqrt_value, &dx_times_v_value);
    let two_s_value = add(&s, &s);
    let x_raw_value = multiply(&two_s_value, &dx_value);
    let x_value = nonnegative(&x_raw_value);
    let y_value = multiply(&u1_value, &dy_value);
    let t_value = multiply(&x_value, &y_value);
    if y_value.is_zero() {
        return Err(TexasAirError::SpecViolation(
            "Ristretto point decode produced Y = 0".into(),
        ));
    }
    if (t_value.clone() & BigUint::one()) == BigUint::one() {
        return Err(TexasAirError::SpecViolation(
            "Ristretto point decode produced negative T".into(),
        ));
    }

    let s_squared = limbs(&s_squared_value);
    let u1 = limbs(&u1_value);
    let u2 = limbs(&u2_value);
    let u2_squared = limbs(&u2_squared_value);
    let u1_squared = limbs(&u1_squared_value);
    let negative_d_times_u1_squared = limbs(&negative_d_times_u1_squared_value);
    let v = limbs(&v_value);
    let v_times_u2_squared = limbs(&v_times_u2_squared_value);
    let dx = limbs(&dx_value);
    let dx_times_v = limbs(&dx_times_v_value);
    let dy = limbs(&dy_value);
    let two_s = limbs(&two_s_value);
    let x_raw = limbs(&x_raw_value);
    let x_negative = limbs(&subtract(&BigUint::zero(), &x_raw_value));
    let y = limbs(&y_value);
    let t = limbs(&t_value);
    let negative_d_bytes = limbs(&negative_d);

    let s_squared_proof = prove_ristretto_fp_multiplication(encoding, encoding)?;
    let u1_proof = prove_ristretto_fp_subtraction(&ONE, &s_squared)?;
    let u2_proof = prove_ristretto_fp_addition(&ONE, &s_squared)?;
    let u2_squared_proof = prove_ristretto_fp_multiplication(&u2, &u2)?;
    let u1_squared_proof = prove_ristretto_fp_multiplication(&u1, &u1)?;
    let negative_d_times_u1_squared_proof =
        prove_ristretto_fp_multiplication(&negative_d_bytes, &u1_squared)?;
    let v_proof = prove_ristretto_fp_subtraction(&negative_d_times_u1_squared, &u2_squared)?;
    let v_times_u2_squared_proof = prove_ristretto_fp_multiplication(&v, &u2_squared)?;
    let dx_proof = prove_ristretto_fp_multiplication(&inverse_sqrt_proof.r, &u2)?;
    let dx_times_v_proof = prove_ristretto_fp_multiplication(&dx, &v)?;
    let dy_proof = prove_ristretto_fp_multiplication(&inverse_sqrt_proof.r, &dx_times_v)?;
    let two_s_proof = prove_ristretto_fp_addition(encoding, encoding)?;
    let x_raw_proof = prove_ristretto_fp_multiplication(&two_s, &dx)?;
    let x_negative_proof = prove_ristretto_fp_subtraction(&ZERO, &x_raw)?;
    let y_proof = prove_ristretto_fp_multiplication(&u1, &dy)?;
    let t_proof = prove_ristretto_fp_multiplication(&limbs(&x_value), &y)?;

    Ok(ArchivedRistrettoPointDecodeProof {
        encoding: *encoding,
        x: limbs(&x_value),
        y,
        t,
        s_squared,
        u1,
        u2,
        u2_squared,
        u1_squared,
        negative_d_times_u1_squared,
        v,
        v_times_u2_squared,
        inverse_sqrt: inverse_sqrt_proof.r,
        dx,
        dx_times_v,
        dy,
        two_s,
        x_raw,
        x_negative,
        s_squared_proof,
        u1_proof,
        u2_proof,
        u2_squared_proof,
        u1_squared_proof,
        negative_d_times_u1_squared_proof,
        v_proof,
        v_times_u2_squared_proof,
        inverse_sqrt_proof,
        dx_proof,
        dx_times_v_proof,
        dy_proof,
        two_s_proof,
        x_raw_proof,
        x_negative_proof,
        y_proof,
        t_proof,
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

/// Verify canonical Ristretto255 decoding without native curve operations.
pub fn verify_ristretto_point_decode(
    archive: &ArchivedRistrettoPointDecodeProof,
) -> TexasAirResult<()> {
    verify_ristretto_fp_multiplication(&archive.s_squared_proof)?;
    verify_ristretto_fp_subtraction(&archive.u1_proof)?;
    verify_ristretto_fp_addition(&archive.u2_proof)?;
    verify_ristretto_fp_multiplication(&archive.u2_squared_proof)?;
    verify_ristretto_fp_multiplication(&archive.u1_squared_proof)?;
    verify_ristretto_fp_multiplication(&archive.negative_d_times_u1_squared_proof)?;
    verify_ristretto_fp_subtraction(&archive.v_proof)?;
    verify_ristretto_fp_multiplication(&archive.v_times_u2_squared_proof)?;
    verify_ristretto_fp_sqrt_ratio(&archive.inverse_sqrt_proof)?;
    verify_ristretto_fp_multiplication(&archive.dx_proof)?;
    verify_ristretto_fp_multiplication(&archive.dx_times_v_proof)?;
    verify_ristretto_fp_multiplication(&archive.dy_proof)?;
    verify_ristretto_fp_addition(&archive.two_s_proof)?;
    verify_ristretto_fp_multiplication(&archive.x_raw_proof)?;
    verify_ristretto_fp_subtraction(&archive.x_negative_proof)?;
    verify_ristretto_fp_multiplication(&archive.y_proof)?;
    verify_ristretto_fp_multiplication(&archive.t_proof)?;

    let negative_d = *negative_edwards_d_bytes();
    let bindings = [
        (
            "s_squared",
            bind_multiplication(
                &archive.s_squared_proof,
                &archive.encoding,
                &archive.encoding,
                &archive.s_squared,
            ),
        ),
        (
            "u1",
            bind_subtraction(&archive.u1_proof, &ONE, &archive.s_squared, &archive.u1),
        ),
        (
            "u2",
            bind_addition(&archive.u2_proof, &ONE, &archive.s_squared, &archive.u2),
        ),
        (
            "u2_squared",
            bind_multiplication(
                &archive.u2_squared_proof,
                &archive.u2,
                &archive.u2,
                &archive.u2_squared,
            ),
        ),
        (
            "u1_squared",
            bind_multiplication(
                &archive.u1_squared_proof,
                &archive.u1,
                &archive.u1,
                &archive.u1_squared,
            ),
        ),
        (
            "negative_d_times_u1_squared",
            bind_multiplication(
                &archive.negative_d_times_u1_squared_proof,
                &negative_d,
                &archive.u1_squared,
                &archive.negative_d_times_u1_squared,
            ),
        ),
        (
            "v",
            bind_subtraction(
                &archive.v_proof,
                &archive.negative_d_times_u1_squared,
                &archive.u2_squared,
                &archive.v,
            ),
        ),
        (
            "v_times_u2_squared",
            bind_multiplication(
                &archive.v_times_u2_squared_proof,
                &archive.v,
                &archive.u2_squared,
                &archive.v_times_u2_squared,
            ),
        ),
        (
            "inverse_sqrt",
            archive.inverse_sqrt_proof.u == ONE
                && archive.inverse_sqrt_proof.v == archive.v_times_u2_squared
                && archive.inverse_sqrt_proof.r == archive.inverse_sqrt
                && archive.inverse_sqrt_proof.was_square,
        ),
        (
            "dx",
            bind_multiplication(
                &archive.dx_proof,
                &archive.inverse_sqrt,
                &archive.u2,
                &archive.dx,
            ),
        ),
        (
            "dx_times_v",
            bind_multiplication(
                &archive.dx_times_v_proof,
                &archive.dx,
                &archive.v,
                &archive.dx_times_v,
            ),
        ),
        (
            "dy",
            bind_multiplication(
                &archive.dy_proof,
                &archive.inverse_sqrt,
                &archive.dx_times_v,
                &archive.dy,
            ),
        ),
        (
            "two_s",
            bind_addition(
                &archive.two_s_proof,
                &archive.encoding,
                &archive.encoding,
                &archive.two_s,
            ),
        ),
        (
            "x_raw",
            bind_multiplication(
                &archive.x_raw_proof,
                &archive.two_s,
                &archive.dx,
                &archive.x_raw,
            ),
        ),
        (
            "x_negative",
            bind_subtraction(
                &archive.x_negative_proof,
                &ZERO,
                &archive.x_raw,
                &archive.x_negative,
            ),
        ),
        (
            "y",
            bind_multiplication(&archive.y_proof, &archive.u1, &archive.dy, &archive.y),
        ),
        (
            "t",
            bind_multiplication(&archive.t_proof, &archive.x, &archive.y, &archive.t),
        ),
    ];
    if let Some((relation, _)) = bindings.iter().find(|(_, bound)| !bound) {
        return Err(TexasAirError::ConstraintUnsatisfied(format!(
            "Ristretto decode relation {relation} is detached"
        )));
    }

    let expected_x = if archive.x_raw[0] & 1 == 0 {
        archive.x_raw
    } else {
        archive.x_negative
    };
    if archive.encoding[0] & 1 == 1
        || archive.x != expected_x
        || archive.x[0] & 1 == 1
        || archive.y == ZERO
        || archive.t[0] & 1 == 1
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "Ristretto decode canonical branch is invalid".into(),
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
    fn proves_identity_decode() {
        let identity = prove_ristretto_point_decode(&ZERO).unwrap();
        assert_eq!(identity.x, ZERO);
        assert_eq!(identity.y, ONE);
        assert_eq!(identity.t, ZERO);
        verify_ristretto_point_decode(&identity).unwrap();
    }

    #[test]
    fn proves_basepoint_decode() {
        let base = prove_ristretto_point_decode(&basepoint()).unwrap();
        assert_ne!(base.x, ZERO);
        assert_ne!(base.y, ZERO);
        verify_ristretto_point_decode(&base).unwrap();
    }

    #[test]
    fn rejects_negative_and_noncanonical_encodings_before_proving() {
        let mut negative = ZERO;
        negative[0] = 1;
        assert!(prove_ristretto_point_decode(&negative).is_err());

        let mut noncanonical = [0xffu8; LIMBS];
        noncanonical[31] = 0x7f;
        assert!(prove_ristretto_point_decode(&noncanonical).is_err());
    }

    #[test]
    fn verifier_rejects_spliced_encoding_and_coordinates() {
        let archive = prove_ristretto_point_decode(&basepoint()).unwrap();
        let mut spliced_encoding = archive.clone();
        spliced_encoding.encoding[0] ^= 2;
        assert!(verify_ristretto_point_decode(&spliced_encoding).is_err());

        let mut spliced_x = archive;
        spliced_x.x[0] ^= 2;
        assert!(verify_ristretto_point_decode(&spliced_x).is_err());
    }
}
