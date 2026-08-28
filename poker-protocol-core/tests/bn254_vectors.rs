//! Generator for the Cairo-side BN254 verifier test vectors
//! (poker_contracts/src/dual/). Run with:
//! `cargo test -p poker-protocol-core --test bn254_vectors -- --nocapture --ignored`
//!
//! The printed values are pasted into the Cairo unit tests so the Rust and
//! Cairo implementations are pinned to the same arithmetic.

use halo2curves::bn256::{Fq, Fr, G1, G1Affine};
use halo2curves::ff::{Field, PrimeField};
use halo2curves::group::Group;
use halo2curves::CurveAffine;
use poker_protocol_core::{Bn254Curve, Curve, CurvePoint, CurveScalar};

fn repr32<F: PrimeField>(value: &F) -> [u8; 32] {
    let repr = value.to_repr();
    let mut out = [0u8; 32];
    out.copy_from_slice(repr.as_ref());
    out
}

fn limbs_le(repr: &[u8; 32]) -> [u64; 4] {
    [
        u64::from_le_bytes(repr[0..8].try_into().unwrap()),
        u64::from_le_bytes(repr[8..16].try_into().unwrap()),
        u64::from_le_bytes(repr[16..24].try_into().unwrap()),
        u64::from_le_bytes(repr[24..32].try_into().unwrap()),
    ]
}

fn print_fq(name: &str, value: &[u8; 32]) {
    let l = limbs_le(value);
    println!(
        "    let ({name}_0, {name}_1, {name}_2, {name}_3) = (0x{:016x}, 0x{:016x}, 0x{:016x}, 0x{:016x});",
        l[0], l[1], l[2], l[3]
    );
}

fn print_point(name: &str, point: &G1Affine) {
    let coords = point.coordinates().expect("not identity");
    print_fq(&format!("{name}_x"), &repr32(coords.x()));
    print_fq(&format!("{name}_y"), &repr32(coords.y()));
}

#[test]
#[ignore]
fn print_bn254_cairo_vectors() {
    // Montgomery domain constants.
    let r1 = Fq::from(2u64).pow(&[256, 0, 0, 0]); // 2^256 mod p
    let r2 = Fq::from(2u64).pow(&[512, 0, 0, 0]); // 2^512 mod p
    print_fq("P_R1", &repr32(&r1));
    print_fq("P_R2", &repr32(&r2));
    // -(p^{-1}) mod 2^64 via Newton iteration on the low limb of p.
    let p_u64 = 0x43e1f593f0000001u64;
    let mut inv_newton: u64 = 1;
    for _ in 0..6 {
        inv_newton = inv_newton.wrapping_mul(2u64.wrapping_sub(p_u64.wrapping_mul(inv_newton)));
    }
    println!("    let P_INV = 0x{inv_newton:016x};");

    // Fp arithmetic sample.
    let a = Fq::from(0x1234567890abcdefu64).square();
    let b = Fq::from(0x0fedcba987654321u64).square() + Fq::from(7);
    print_fq("A", &repr32(&a));
    print_fq("B", &repr32(&b));
    print_fq("A_ADD_B", &repr32(&(a + b)));
    print_fq("A_SUB_B", &repr32(&(a - b)));
    print_fq("A_MUL_B", &repr32(&(a * b)));

    // Curve sample: base generator and a scalar multiple.
    let g = <G1 as Group>::generator();
    let k = Fr::from(0xdeadbeefcafebabeu64);
    let kg: G1Affine = (g * k).into();
    print_point("G", &g.into());
    print_point("K_G", &kg);

    // Full Schnorr (ownership) statement via the protocol stack:
    // sk, pk = sk*G, blinding w, R = w*G, c, s = w + c*sk,
    // verified by s*G == R + c*pk.
    let sk = <Bn254Curve as Curve>::hash_to_scalar(b"cairo_vector_sk");
    let pk: G1Affine = (Bn254Curve::base_g() * &sk).into();
    let w = <Bn254Curve as Curve>::hash_to_scalar(b"cairo_vector_w");
    let big_r: G1Affine = (Bn254Curve::base_g() * &w).into();
    let c = <Bn254Curve as Curve>::hash_to_scalar(b"cairo_vector_c");
    let s = w + c * sk;
    print_point("PK", &pk);
    print_point("BIG_R", &big_r);
    print_fq("C", &repr32(&c));
    print_fq("S", &repr32(&s));
    // Negative vector: s' = s + 1 must NOT verify.
    let s_bad = s + Fr::from(1);
    print_fq("S_BAD", &repr32(&s_bad));
}
