pub mod curve;
pub mod elgamal;
pub mod types;

pub use curve::{
    ec_encrypt_batch_generic, Bls12381Curve, Bls12381ElGamalCiphertext, Curve, CurvePoint,
    CurveScalar, ElGamalCiphertextGeneric, RistrettoCurve, RistrettoElGamalCiphertext,
};
pub use elgamal::ec_encrypt_batch_v2;
pub use types::{
    derive_scalar_from_card_and_pk, derive_scalar_from_card_and_sk, hash_to_scalar, DefaultCurve,
    ECPoint, EcPoint, ElGamalCiphertext, Plaintext, Scalar, BASE_G, N_CARDS,
};

pub type PublicKey = EcPoint;
pub fn encrypt_batch(
    plaintexts: &[EcPoint],
    pk: &EcPoint,
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
) -> Vec<ElGamalCiphertext> {
    ec_encrypt_batch_v2(plaintexts, pk, rng)
}
