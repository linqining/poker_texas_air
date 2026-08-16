use super::types::{DefaultCurve, EcPoint, ElGamalCiphertext, Scalar};
use crate::crypto::curve::{CurveScalar, ElGamalCiphertextGeneric};
use rand_core::{CryptoRng, RngCore};
use rayon::prelude::*;

pub fn ec_encrypt_batch_v2(
    plaintexts: &[EcPoint],
    pk: &EcPoint,
    rng: &mut (impl CryptoRng + RngCore),
) -> Vec<ElGamalCiphertext> {
    let r_vec: Vec<Scalar> = (0..plaintexts.len())
        .map(|_| Scalar::random(&mut *rng))
        .collect();
    plaintexts
        .par_iter()
        .zip(r_vec.par_iter())
        .map(|(pt, r)| ElGamalCiphertextGeneric::<DefaultCurve>::encrypt(pt, pk, r))
        .collect()
}
