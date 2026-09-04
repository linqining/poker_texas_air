//! Schnorr proof of ownership of a registered public key.
//!
//! Statement: `public_key`. Witness: a non-zero `secret_key` satisfying
//! `public_key = secret_key * G`. Verification rejects identity public keys and
//! commitments. The interactive proof has perfect completeness, special
//! soundness and perfect HVZK. This legacy-compatible encoding hashes
//! `G || public_key || commitment`; game/epoch binding must be supplied by the
//! authenticated registration context.

use poker_protocol_core::{Curve, CurvePoint, CurveScalar, VerificationError};
use rand_core::{CryptoRng, RngCore};

/// Schnorr proof of knowledge for a player's public key.
///
/// The challenge schedule matches the Move verifier:
/// `hash_to_scalar(G || public_key || commitment)`.
#[derive(Debug, Clone)]
pub struct PKOwnershipProof<C: Curve> {
    pub commitment: C::Point,
    pub response: C::Scalar,
}

impl<C: Curve> PKOwnershipProof<C> {
    pub fn try_prove(
        secret_key: &C::Scalar,
        public_key: &C::Point,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self, VerificationError> {
        if *secret_key == C::Scalar::zero() {
            return Err(VerificationError::InvalidSecretKey);
        }
        if public_key.is_identity() || *public_key != C::base_g() * *secret_key {
            return Err(VerificationError::InvalidPublicKey);
        }
        let (witness_blinding, commitment) = loop {
            let witness_blinding = C::Scalar::random(rng);
            if witness_blinding == C::Scalar::zero() {
                continue;
            }
            let commitment = C::base_g() * witness_blinding;
            if !commitment.is_identity() {
                break (witness_blinding, commitment);
            }
        };
        let challenge = challenge::<C>(public_key, &commitment);
        let response = witness_blinding + challenge * *secret_key;
        Ok(Self {
            commitment,
            response,
        })
    }

    /// Backward-compatible wrapper; protocol code should prefer
    /// [`Self::try_prove`] and propagate invalid-key errors.
    pub fn prove(
        secret_key: &C::Scalar,
        public_key: &C::Point,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Self {
        Self::try_prove(secret_key, public_key, rng)
            .expect("PKOwnershipProof::prove received an invalid keypair")
    }

    pub fn verify(&self, public_key: &C::Point) -> bool {
        if public_key.is_identity() || self.commitment.is_identity() {
            return false;
        }
        let challenge = challenge::<C>(public_key, &self.commitment);
        C::base_g() * self.response == self.commitment + *public_key * challenge
    }
}

fn challenge<C: Curve>(public_key: &C::Point, commitment: &C::Point) -> C::Scalar {
    let mut input = Vec::new();
    input.extend_from_slice(C::base_g().compress().as_ref());
    input.extend_from_slice(public_key.compress().as_ref());
    input.extend_from_slice(commitment.compress().as_ref());
    C::hash_to_scalar(&input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use poker_protocol_core::{StarkCurve, RistrettoCurve};
    use rand_core::OsRng;

    fn roundtrip<C: Curve>() {
        let secret_key = C::Scalar::random(&mut OsRng);
        let public_key = C::base_g() * secret_key;
        let proof = PKOwnershipProof::<C>::prove(&secret_key, &public_key, &mut OsRng);
        assert!(proof.verify(&public_key));

        let wrong_key = C::base_g() * C::Scalar::random(&mut OsRng);
        assert!(!proof.verify(&wrong_key));
    }

    #[test]
    fn ristretto_ownership_proof() {
        roundtrip::<RistrettoCurve>();
    }

    #[test]
    fn bls12381_ownership_proof() {
        roundtrip::<StarkCurve>();
    }

    #[test]
    fn identity_statement_is_rejected() {
        let proof = PKOwnershipProof::<RistrettoCurve> {
            commitment: RistrettoCurve::base_g(),
            response: <RistrettoCurve as Curve>::Scalar::one(),
        };
        assert!(!proof.verify(&<RistrettoCurve as Curve>::Point::identity()));
    }

    #[test]
    fn prover_rejects_zero_or_mismatched_keypair() {
        let zero = <RistrettoCurve as Curve>::Scalar::zero();
        let identity = <RistrettoCurve as Curve>::Point::identity();
        assert_eq!(
            PKOwnershipProof::<RistrettoCurve>::try_prove(&zero, &identity, &mut OsRng)
                .unwrap_err(),
            VerificationError::InvalidSecretKey
        );

        let sk = <RistrettoCurve as Curve>::Scalar::random(&mut OsRng);
        let wrong_pk =
            RistrettoCurve::base_g() * <RistrettoCurve as Curve>::Scalar::random(&mut OsRng);
        assert_eq!(
            PKOwnershipProof::<RistrettoCurve>::try_prove(&sk, &wrong_pk, &mut OsRng).unwrap_err(),
            VerificationError::InvalidPublicKey
        );
    }
}
