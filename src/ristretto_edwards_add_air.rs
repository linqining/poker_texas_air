//! Composed host-zero extended-Edwards25519 point addition.
//!
//! Both summands are first authenticated by canonical Ristretto decode proofs.
//! The verifier then checks every field operation in the unified extended
//! addition formula, so the output is bound to valid decoded group elements
//! rather than host-projected coordinates.

use borsh::{BorshDeserialize, BorshSerialize};
use num_bigint::BigUint;
use num_traits::One;

use crate::error::{TexasAirError, TexasAirResult};
use crate::ristretto_fp_add_air::{
    ArchivedRistrettoFpAdditionProof, prove_ristretto_fp_addition, verify_ristretto_fp_addition,
};
use crate::ristretto_fp_mul_air::{
    ArchivedRistrettoFpMultiplicationProof, prove_ristretto_fp_multiplication,
    verify_ristretto_fp_multiplication,
};
use crate::ristretto_fp_sub_air::{
    ArchivedRistrettoFpSubtractionProof, prove_ristretto_fp_subtraction,
    verify_ristretto_fp_subtraction,
};
use crate::ristretto_point_decode_air::{
    ArchivedRistrettoPointDecodeProof, prove_ristretto_point_decode, verify_ristretto_point_decode,
};

const LIMBS: usize = 32;
const TWO: [u8; LIMBS] = {
    let mut bytes = [0u8; LIMBS];
    bytes[0] = 2;
    bytes
};

/// Public point-addition statement and all verified field relations.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoEdwardsAdditionProof {
    /// Canonical decoded left summand.
    pub left: ArchivedRistrettoPointDecodeProof,
    /// Canonical decoded right summand.
    pub right: ArchivedRistrettoPointDecodeProof,
    /// Output extended coordinate `X`.
    pub x: [u8; LIMBS],
    /// Output extended coordinate `Y`.
    pub y: [u8; LIMBS],
    /// Output extended coordinate `Z`.
    pub z: [u8; LIMBS],
    /// Output extended coordinate `T`.
    pub t: [u8; LIMBS],
    /// Verified `Yleft-Xleft`.
    pub left_y_minus_x: [u8; LIMBS],
    /// Verified `Yright-Xright`.
    pub right_y_minus_x: [u8; LIMBS],
    /// Verified `Yleft+Xleft`.
    pub left_y_plus_x: [u8; LIMBS],
    /// Verified `Yright+Xright`.
    pub right_y_plus_x: [u8; LIMBS],
    /// Verified `A=(Y1-X1)(Y2-X2)`.
    pub a: [u8; LIMBS],
    /// Verified `B=(Y1+X1)(Y2+X2)`.
    pub b: [u8; LIMBS],
    /// Verified `T1*T2`.
    pub t_product: [u8; LIMBS],
    /// Verified `C=2*d*T1*T2`.
    pub c: [u8; LIMBS],
    /// Verified `E=B-A`.
    pub e: [u8; LIMBS],
    /// Verified `F=2-C`.
    pub f: [u8; LIMBS],
    /// Verified `G=2+C`.
    pub g: [u8; LIMBS],
    /// Verified `H=A+B`.
    pub h: [u8; LIMBS],
    /// Proves left `Y-X`.
    pub left_y_minus_x_proof: ArchivedRistrettoFpSubtractionProof,
    /// Proves right `Y-X`.
    pub right_y_minus_x_proof: ArchivedRistrettoFpSubtractionProof,
    /// Proves left `Y+X`.
    pub left_y_plus_x_proof: ArchivedRistrettoFpAdditionProof,
    /// Proves right `Y+X`.
    pub right_y_plus_x_proof: ArchivedRistrettoFpAdditionProof,
    /// Proves `A`.
    pub a_proof: ArchivedRistrettoFpMultiplicationProof,
    /// Proves `B`.
    pub b_proof: ArchivedRistrettoFpMultiplicationProof,
    /// Proves `T1*T2`.
    pub t_product_proof: ArchivedRistrettoFpMultiplicationProof,
    /// Proves `C`.
    pub c_proof: ArchivedRistrettoFpMultiplicationProof,
    /// Proves `E`.
    pub e_proof: ArchivedRistrettoFpSubtractionProof,
    /// Proves `F`.
    pub f_proof: ArchivedRistrettoFpSubtractionProof,
    /// Proves `G`.
    pub g_proof: ArchivedRistrettoFpAdditionProof,
    /// Proves `H`.
    pub h_proof: ArchivedRistrettoFpAdditionProof,
    /// Proves output `X=E*F`.
    pub x_proof: ArchivedRistrettoFpMultiplicationProof,
    /// Proves output `Y=G*H`.
    pub y_proof: ArchivedRistrettoFpMultiplicationProof,
    /// Proves output `Z=F*G`.
    pub z_proof: ArchivedRistrettoFpMultiplicationProof,
    /// Proves output `T=E*H`.
    pub t_proof: ArchivedRistrettoFpMultiplicationProof,
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

fn edwards_d() -> BigUint {
    BigUint::parse_bytes(
        b"37095705934669439343138083508754565189542113879843219016388785533085940283555",
        10,
    )
    .expect("decimal Edwards d is valid")
}

/// Prove the extended-Edwards sum of two canonical Ristretto encodings.
pub fn prove_ristretto_edwards_addition(
    left_encoding: &[u8; LIMBS],
    right_encoding: &[u8; LIMBS],
) -> TexasAirResult<ArchivedRistrettoEdwardsAdditionProof> {
    let left = prove_ristretto_point_decode(left_encoding)?;
    let right = if left_encoding == right_encoding {
        left.clone()
    } else {
        prove_ristretto_point_decode(right_encoding)?
    };

    let left_x = big_uint(&left.x);
    let left_y = big_uint(&left.y);
    let left_t = big_uint(&left.t);
    let right_x = big_uint(&right.x);
    let right_y = big_uint(&right.y);
    let right_t = big_uint(&right.t);

    let left_y_minus_x_value = subtract(&left_y, &left_x);
    let right_y_minus_x_value = subtract(&right_y, &right_x);
    let left_y_plus_x_value = add(&left_y, &left_x);
    let right_y_plus_x_value = add(&right_y, &right_x);
    let a_value = multiply(&left_y_minus_x_value, &right_y_minus_x_value);
    let b_value = multiply(&left_y_plus_x_value, &right_y_plus_x_value);
    let t_product_value = multiply(&left_t, &right_t);
    let two_d = add(&edwards_d(), &edwards_d());
    let c_value = multiply(&two_d, &t_product_value);
    let e_value = subtract(&b_value, &a_value);
    let two = big_uint(&TWO);
    let f_value = subtract(&two, &c_value);
    let g_value = add(&two, &c_value);
    let h_value = add(&a_value, &b_value);
    let x_value = multiply(&e_value, &f_value);
    let y_value = multiply(&g_value, &h_value);
    let z_value = multiply(&f_value, &g_value);
    let t_value = multiply(&e_value, &h_value);

    let left_y_minus_x = limbs(&left_y_minus_x_value);
    let right_y_minus_x = limbs(&right_y_minus_x_value);
    let left_y_plus_x = limbs(&left_y_plus_x_value);
    let right_y_plus_x = limbs(&right_y_plus_x_value);
    let a = limbs(&a_value);
    let b = limbs(&b_value);
    let t_product = limbs(&t_product_value);
    let c = limbs(&c_value);
    let e = limbs(&e_value);
    let f = limbs(&f_value);
    let g = limbs(&g_value);
    let h = limbs(&h_value);
    let two_d_bytes = limbs(&two_d);

    let left_y_minus_x_proof = prove_ristretto_fp_subtraction(&left.y, &left.x)?;
    let right_y_minus_x_proof = prove_ristretto_fp_subtraction(&right.y, &right.x)?;
    let left_y_plus_x_proof = prove_ristretto_fp_addition(&left.y, &left.x)?;
    let right_y_plus_x_proof = prove_ristretto_fp_addition(&right.y, &right.x)?;
    let a_proof = prove_ristretto_fp_multiplication(&left_y_minus_x, &right_y_minus_x)?;
    let b_proof = prove_ristretto_fp_multiplication(&left_y_plus_x, &right_y_plus_x)?;
    let t_product_proof = prove_ristretto_fp_multiplication(&left.t, &right.t)?;
    let c_proof = prove_ristretto_fp_multiplication(&two_d_bytes, &t_product)?;
    let e_proof = prove_ristretto_fp_subtraction(&b, &a)?;
    let f_proof = prove_ristretto_fp_subtraction(&TWO, &c)?;
    let g_proof = prove_ristretto_fp_addition(&TWO, &c)?;
    let h_proof = prove_ristretto_fp_addition(&a, &b)?;
    let x_proof = prove_ristretto_fp_multiplication(&e, &f)?;
    let y_proof = prove_ristretto_fp_multiplication(&g, &h)?;
    let z_proof = prove_ristretto_fp_multiplication(&f, &g)?;
    let t_proof = prove_ristretto_fp_multiplication(&e, &h)?;

    Ok(ArchivedRistrettoEdwardsAdditionProof {
        left,
        right,
        x: limbs(&x_value),
        y: limbs(&y_value),
        z: limbs(&z_value),
        t: limbs(&t_value),
        left_y_minus_x,
        right_y_minus_x,
        left_y_plus_x,
        right_y_plus_x,
        a,
        b,
        t_product,
        c,
        e,
        f,
        g,
        h,
        left_y_minus_x_proof,
        right_y_minus_x_proof,
        left_y_plus_x_proof,
        right_y_plus_x_proof,
        a_proof,
        b_proof,
        t_product_proof,
        c_proof,
        e_proof,
        f_proof,
        g_proof,
        h_proof,
        x_proof,
        y_proof,
        z_proof,
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

/// Verify a complete extended-Edwards addition relation.
pub fn verify_ristretto_edwards_addition(
    archive: &ArchivedRistrettoEdwardsAdditionProof,
) -> TexasAirResult<()> {
    verify_ristretto_point_decode(&archive.left)?;
    verify_ristretto_point_decode(&archive.right)?;
    verify_ristretto_fp_subtraction(&archive.left_y_minus_x_proof)?;
    verify_ristretto_fp_subtraction(&archive.right_y_minus_x_proof)?;
    verify_ristretto_fp_addition(&archive.left_y_plus_x_proof)?;
    verify_ristretto_fp_addition(&archive.right_y_plus_x_proof)?;
    verify_ristretto_fp_multiplication(&archive.a_proof)?;
    verify_ristretto_fp_multiplication(&archive.b_proof)?;
    verify_ristretto_fp_multiplication(&archive.t_product_proof)?;
    verify_ristretto_fp_multiplication(&archive.c_proof)?;
    verify_ristretto_fp_subtraction(&archive.e_proof)?;
    verify_ristretto_fp_subtraction(&archive.f_proof)?;
    verify_ristretto_fp_addition(&archive.g_proof)?;
    verify_ristretto_fp_addition(&archive.h_proof)?;
    verify_ristretto_fp_multiplication(&archive.x_proof)?;
    verify_ristretto_fp_multiplication(&archive.y_proof)?;
    verify_ristretto_fp_multiplication(&archive.z_proof)?;
    verify_ristretto_fp_multiplication(&archive.t_proof)?;

    let two_d = limbs(&add(&edwards_d(), &edwards_d()));
    let checks = [
        (
            "left_y_minus_x",
            bind_subtraction(
                &archive.left_y_minus_x_proof,
                &archive.left.y,
                &archive.left.x,
                &archive.left_y_minus_x,
            ),
        ),
        (
            "right_y_minus_x",
            bind_subtraction(
                &archive.right_y_minus_x_proof,
                &archive.right.y,
                &archive.right.x,
                &archive.right_y_minus_x,
            ),
        ),
        (
            "left_y_plus_x",
            bind_addition(
                &archive.left_y_plus_x_proof,
                &archive.left.y,
                &archive.left.x,
                &archive.left_y_plus_x,
            ),
        ),
        (
            "right_y_plus_x",
            bind_addition(
                &archive.right_y_plus_x_proof,
                &archive.right.y,
                &archive.right.x,
                &archive.right_y_plus_x,
            ),
        ),
        (
            "a",
            bind_multiplication(
                &archive.a_proof,
                &archive.left_y_minus_x,
                &archive.right_y_minus_x,
                &archive.a,
            ),
        ),
        (
            "b",
            bind_multiplication(
                &archive.b_proof,
                &archive.left_y_plus_x,
                &archive.right_y_plus_x,
                &archive.b,
            ),
        ),
        (
            "t_product",
            bind_multiplication(
                &archive.t_product_proof,
                &archive.left.t,
                &archive.right.t,
                &archive.t_product,
            ),
        ),
        (
            "c",
            bind_multiplication(&archive.c_proof, &two_d, &archive.t_product, &archive.c),
        ),
        (
            "e",
            bind_subtraction(&archive.e_proof, &archive.b, &archive.a, &archive.e),
        ),
        (
            "f",
            bind_subtraction(&archive.f_proof, &TWO, &archive.c, &archive.f),
        ),
        (
            "g",
            bind_addition(&archive.g_proof, &TWO, &archive.c, &archive.g),
        ),
        (
            "h",
            bind_addition(&archive.h_proof, &archive.a, &archive.b, &archive.h),
        ),
        (
            "x",
            bind_multiplication(&archive.x_proof, &archive.e, &archive.f, &archive.x),
        ),
        (
            "y",
            bind_multiplication(&archive.y_proof, &archive.g, &archive.h, &archive.y),
        ),
        (
            "z",
            bind_multiplication(&archive.z_proof, &archive.f, &archive.g, &archive.z),
        ),
        (
            "t",
            bind_multiplication(&archive.t_proof, &archive.e, &archive.h, &archive.t),
        ),
    ];
    if let Some((relation, _)) = checks.iter().find(|(_, bound)| !bound) {
        return Err(TexasAirError::ConstraintUnsatisfied(format!(
            "Ristretto Edwards addition relation {relation} is detached"
        )));
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
    fn proves_basepoint_doubling() {
        let archive = prove_ristretto_edwards_addition(&basepoint(), &basepoint()).unwrap();
        assert_ne!(archive.x, [0u8; LIMBS]);
        assert_ne!(archive.z, [0u8; LIMBS]);
        verify_ristretto_edwards_addition(&archive).unwrap();
    }

    #[test]
    fn verifier_rejects_spliced_output_coordinates() {
        let archive = prove_ristretto_edwards_addition(&basepoint(), &basepoint()).unwrap();
        let mut forged = archive;
        forged.x[0] ^= 2;
        assert!(verify_ristretto_edwards_addition(&forged).is_err());
    }
}
