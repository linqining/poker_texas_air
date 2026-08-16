//! Ordered vector encryption proof used by reconstruction V2.
//!
//! Each canonical slot has one shared Chaum--Pedersen response proving both
//! ElGamal encryption equations under a common challenge. This binds the
//! ciphertext vector to the supplied ordered plaintext vector. It does not
//! repair V2's public-randomness privacy leak or misplaced-swap relation and
//! is not part of the V3 contribution relation.

use crate::transcript_ext::CryptoTranscript;
use poker_protocol_core::{
    Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric, VerificationError,
};
use rand_core::{CryptoRng, RngCore};

const PROTOCOL_ID: &[u8] = b"poker/reconstruction/ordered-encryption/v1";

/// A vector Chaum--Pedersen proof for an ordered ElGamal encryption relation.
///
/// For every canonical slot `i`, this proves knowledge of one shared response
/// witness `r_i` satisfying both
///
/// `ciphertexts[i].c1 = r_i * G` and
/// `ciphertexts[i].c2 - plaintexts[i] = r_i * public_key`.
///
/// All slots share one Fiat--Shamir challenge, while each slot has exactly one
/// response. This prevents the mixed-witness issue caused by composing
/// independent aggregate Schnorr proofs.
#[derive(Debug, Clone)]
pub struct OrderedEncryptionProof<C: Curve> {
    pub commitment_g: Vec<C::Point>,
    pub commitment_pk: Vec<C::Point>,
    pub responses: Vec<C::Scalar>,
}

fn append_statement<C: Curve>(
    plaintexts: &[C::Point],
    ciphertexts: &[ElGamalCiphertextGeneric<C>],
    public_key: &C::Point,
    transcript: &mut impl CryptoTranscript,
) {
    transcript.append_message(b"ordered_encryption_protocol", PROTOCOL_ID);
    transcript.append_message(
        b"ordered_encryption_len",
        &(plaintexts.len() as u64).to_le_bytes(),
    );
    transcript.append_point::<C>(b"ordered_encryption_pk", public_key);
    for plaintext in plaintexts {
        transcript.append_point::<C>(b"ordered_encryption_plaintext", plaintext);
    }
    for ciphertext in ciphertexts {
        transcript.append_point::<C>(b"ordered_encryption_c1", &ciphertext.c1);
        transcript.append_point::<C>(b"ordered_encryption_c2", &ciphertext.c2);
    }
}

fn challenge_nonzero<C: Curve>(transcript: &mut impl CryptoTranscript) -> C::Scalar {
    let mut challenge = transcript
        .challenge::<C>(b"ordered_encryption_challenge")
        .scalar;
    let mut counter = 0u32;
    while challenge == C::Scalar::zero() {
        transcript.append_message(
            b"ordered_encryption_zero_challenge_retry",
            &counter.to_le_bytes(),
        );
        challenge = transcript
            .challenge::<C>(b"ordered_encryption_challenge")
            .scalar;
        counter = counter.wrapping_add(1);
    }
    challenge
}

fn validate_statement<C: Curve>(
    plaintexts: &[C::Point],
    ciphertexts: &[ElGamalCiphertextGeneric<C>],
    public_key: &C::Point,
) -> Result<(), VerificationError> {
    if plaintexts.is_empty() || plaintexts.len() != ciphertexts.len() {
        return Err(VerificationError::LengthMismatch);
    }
    if public_key.is_identity() {
        return Err(VerificationError::InvalidPublicKey);
    }
    for (plaintext, ciphertext) in plaintexts.iter().zip(ciphertexts) {
        let encryption_component = ciphertext.c2 - *plaintext;
        if plaintext.is_identity()
            || ciphertext.c1.is_identity()
            || encryption_component.is_identity()
        {
            return Err(VerificationError::IdentityBasePoint);
        }
    }
    Ok(())
}

impl<C: Curve> OrderedEncryptionProof<C> {
    pub(crate) fn prove(
        plaintexts: &[C::Point],
        ciphertexts: &[ElGamalCiphertextGeneric<C>],
        randomness: &[C::Scalar],
        public_key: &C::Point,
        rng: &mut (impl CryptoRng + RngCore),
        transcript: &mut impl CryptoTranscript,
    ) -> Result<Self, VerificationError> {
        validate_statement(plaintexts, ciphertexts, public_key)?;
        if randomness.len() != plaintexts.len() {
            return Err(VerificationError::LengthMismatch);
        }
        for ((plaintext, ciphertext), witness) in plaintexts.iter().zip(ciphertexts).zip(randomness)
        {
            if *witness == C::Scalar::zero()
                || ciphertext.c1 != C::base_g() * *witness
                || ciphertext.c2 - *plaintext != *public_key * *witness
            {
                return Err(VerificationError::InvalidInput);
            }
        }

        append_statement(plaintexts, ciphertexts, public_key, transcript);

        let mut nonces = Vec::with_capacity(plaintexts.len());
        let mut commitment_g = Vec::with_capacity(plaintexts.len());
        let mut commitment_pk = Vec::with_capacity(plaintexts.len());
        for _ in plaintexts {
            let mut nonce = C::Scalar::random(rng);
            while nonce == C::Scalar::zero() {
                nonce = C::Scalar::random(rng);
            }
            nonces.push(nonce);
            commitment_g.push(C::base_g() * nonce);
            commitment_pk.push(*public_key * nonce);
        }
        for point in &commitment_g {
            transcript.append_point::<C>(b"ordered_encryption_commitment_g", point);
        }
        for point in &commitment_pk {
            transcript.append_point::<C>(b"ordered_encryption_commitment_pk", point);
        }
        let challenge = challenge_nonzero::<C>(transcript);
        let responses = nonces
            .iter()
            .zip(randomness)
            .map(|(nonce, witness)| *nonce + challenge * *witness)
            .collect();

        Ok(Self {
            commitment_g,
            commitment_pk,
            responses,
        })
    }

    pub fn verify(
        &self,
        plaintexts: &[C::Point],
        ciphertexts: &[ElGamalCiphertextGeneric<C>],
        public_key: &C::Point,
        transcript: &mut impl CryptoTranscript,
    ) -> Result<(), VerificationError> {
        validate_statement(plaintexts, ciphertexts, public_key)?;
        let n = plaintexts.len();
        if self.commitment_g.len() != n
            || self.commitment_pk.len() != n
            || self.responses.len() != n
        {
            return Err(VerificationError::LengthMismatch);
        }
        if self.commitment_g.iter().any(CurvePoint::is_identity)
            || self.commitment_pk.iter().any(CurvePoint::is_identity)
        {
            return Err(VerificationError::InvalidDLEQProof);
        }

        append_statement(plaintexts, ciphertexts, public_key, transcript);
        for point in &self.commitment_g {
            transcript.append_point::<C>(b"ordered_encryption_commitment_g", point);
        }
        for point in &self.commitment_pk {
            transcript.append_point::<C>(b"ordered_encryption_commitment_pk", point);
        }
        let challenge = challenge_nonzero::<C>(transcript);

        for i in 0..n {
            let encryption_component = ciphertexts[i].c2 - plaintexts[i];
            if C::base_g() * self.responses[i]
                != self.commitment_g[i] + ciphertexts[i].c1 * challenge
                || *public_key * self.responses[i]
                    != self.commitment_pk[i] + encryption_component * challenge
            {
                return Err(VerificationError::InvalidProofAtPosition(i));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transcript_ext::MerlinTranscript;
    use poker_protocol_core::RistrettoCurve;
    use rand_core::OsRng;

    type C = RistrettoCurve;

    #[test]
    fn verifier_distinguishes_shape_from_identity_commitments() {
        let sk = <C as Curve>::Scalar::from_u64(9);
        let pk = C::base_g() * sk;
        let plaintext = C::base_h();
        let randomness = <C as Curve>::Scalar::from_u64(13);
        let ciphertext = ElGamalCiphertextGeneric::<C>::encrypt(&plaintext, &pk, &randomness);
        let mut proof = OrderedEncryptionProof::<C>::prove(
            &[plaintext],
            &[ciphertext],
            &[randomness],
            &pk,
            &mut OsRng,
            &mut MerlinTranscript::new(b"ordered-identity-commitment"),
        )
        .unwrap();
        proof.commitment_g[0] = <C as Curve>::Point::identity();
        assert_eq!(
            proof
                .verify(
                    &[plaintext],
                    &[ciphertext],
                    &pk,
                    &mut MerlinTranscript::new(b"ordered-identity-commitment")
                )
                .unwrap_err(),
            VerificationError::InvalidDLEQProof
        );
    }
}
