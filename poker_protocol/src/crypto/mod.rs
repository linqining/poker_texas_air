pub mod curve;
pub mod elgamal;
pub mod types;

pub use curve::{
    ec_encrypt_batch_generic, Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric,
    RistrettoCurve, RistrettoElGamalCiphertext, StarkCurve,
};
pub use elgamal::ec_encrypt_batch_v2;
pub use types::{
    derive_scalar_from_card_and_pk, derive_scalar_from_card_and_sk, hash_to_scalar, DefaultCurve,
    base_g, ECPoint, EcPoint, ElGamalCiphertext, Plaintext, Scalar, N_CARDS,
};

pub type PublicKey = EcPoint;
pub fn encrypt_batch(
    plaintexts: &[EcPoint],
    pk: &EcPoint,
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
) -> Vec<ElGamalCiphertext> {
    ec_encrypt_batch_v2(plaintexts, pk, rng)
}
