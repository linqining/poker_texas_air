//! Generalized Schnorr proof of a linear representation.
//!
//! The statement is `(G_0, ..., G_{n-1}, R)` and the witness is
//! `(k_0, ..., k_{n-1})` satisfying `R = sum(k_i * G_i)`. This primitive proves
//! only that representation relation; it does not by itself force several
//! independently constructed proofs to share the same witness vector.
//!
//! The strict prover validates the witness equation and the verifier rejects
//! empty shapes, identity bases/targets/commitments and response-length
//! mismatches. The interactive protocol has perfect completeness, special
//! soundness and perfect HVZK; non-interactive security additionally relies on
//! the Fiat--Shamir random-oracle model and exact transcript binding.

use crate::error::VerificationError;
use crate::transcript_ext::CryptoTranscript;
use poker_protocol_core::{Curve, CurvePoint, CurveScalar};

/// Fiat--Shamir proof of knowledge of a multi-base linear representation.
#[derive(Debug, Clone)]
pub struct GeneralizedSchnorrProof<C: Curve> {
    /// Commitment point T = sum(r_i * g_i)
    pub commitment: C::Point,
    /// Response scalars s_i = r_i + c * k_i for each secret
    pub responses: Vec<C::Scalar>,
}

impl<C: Curve> GeneralizedSchnorrProof<C> {
    /// Generate a generalized Schnorr proof.
    ///
    /// # Arguments
    /// * `base_points` - Base points G_1, G_2, ..., G_n
    /// * `secrets` - Secret scalars k_1, k_2, ..., k_n
    /// * `R` - The point R = sum(k_i * g_i) to prove knowledge of
    /// * `transcript` - Merlin transcript for Fiat-Shamir transform
    ///
    /// # Security
    /// This function validates that base points are not identity to prevent
    /// trivial attacks where a base point of zero could compromise the proof.
    pub fn prove(
        base_points: &[C::Point],
        secrets: &[C::Scalar],
        R: &C::Point,
        transcript: &mut impl CryptoTranscript,
    ) -> Result<Self, VerificationError> {
        Self::prove_inner(base_points, secrets, R, transcript, true)
    }

    /// Preserve the ability of legacy V1 shuffle regression tests to construct
    /// adversarial transcripts. This is deliberately unavailable outside unit
    /// tests; production callers always receive witness-consistency checks.
    #[cfg(test)]
    pub(crate) fn prove_unchecked(
        base_points: &[C::Point],
        secrets: &[C::Scalar],
        R: &C::Point,
        transcript: &mut impl CryptoTranscript,
    ) -> Result<Self, VerificationError> {
        Self::prove_inner(base_points, secrets, R, transcript, false)
    }

    fn prove_inner(
        base_points: &[C::Point],
        secrets: &[C::Scalar],
        R: &C::Point,
        transcript: &mut impl CryptoTranscript,
        validate_witness: bool,
    ) -> Result<Self, VerificationError> {
        if base_points.is_empty() || base_points.len() != secrets.len() {
            return Err(VerificationError::LengthMismatch);
        }
        if R.is_identity() {
            return Err(VerificationError::IdentityBasePoint);
        }

        let n = base_points.len();

        // Identity bases create unconstrained witness coordinates.
        for g_i in base_points.iter() {
            if g_i.is_identity() {
                return Err(VerificationError::IdentityBasePoint);
            }
        }

        if validate_witness && C::Point::vartime_multiscalar_mul(secrets, base_points) != *R {
            return Err(VerificationError::InvalidInput);
        }

        // Append public values to transcript
        transcript.append_message(b"gen_schnorr_n", &(n as u64).to_le_bytes());
        for g_i in base_points {
            transcript.append_point::<C>(b"gen_schnorr_base", g_i);
        }
        transcript.append_point::<C>(b"gen_schnorr_R", R);

        // Generate n random scalars r_1, r_2, ..., r_n
        let (r_vec, commitment) = loop {
            let r_vec: Vec<C::Scalar> = (0..n)
                .map(|_| C::Scalar::random(&mut rand_core::OsRng))
                .collect();
            let commitment = C::Point::vartime_multiscalar_mul(&r_vec, base_points);
            if !commitment.is_identity() {
                break (r_vec, commitment);
            }
        };

        // Append commitment to transcript
        transcript.append_point::<C>(b"gen_schnorr_commitment", &commitment);

        // Get challenge scalar c = H(G_1, ..., G_n, R, T)
        let c = transcript.challenge::<C>(b"gen_schnorr_challenge").scalar;

        // Compute responses: s_i = r_i + c * k_i
        let responses: Vec<C::Scalar> = r_vec
            .iter()
            .zip(secrets.iter())
            .map(|(r_i, k_i)| *r_i + c * *k_i)
            .collect();

        Ok(Self {
            commitment,
            responses,
        })
    }

    /// Verify a generalized Schnorr proof.
    ///
    /// # Arguments
    /// * `base_points` - Base points G_1, G_2, ..., G_n
    /// * `R` - The claimed linear combination point
    /// * `transcript` - Merlin transcript for Fiat-Shamir transform
    ///
    /// # Security
    /// This function validates that base points are not identity to ensure
    /// the proof maintains its knowledge soundness property.
    pub fn verify(
        &self,
        base_points: &[C::Point],
        R: &C::Point,
        transcript: &mut impl CryptoTranscript,
    ) -> Result<(), VerificationError> {
        if base_points.is_empty() || self.responses.len() != base_points.len() {
            return Err(VerificationError::InvalidDLEQProof);
        }

        if R.is_identity() {
            return Err(VerificationError::InvalidDLEQProof);
        }

        let n = base_points.len();

        // Match the strict prover's statement validation.
        for g_i in base_points.iter() {
            if g_i.is_identity() {
                return Err(VerificationError::InvalidDLEQProof);
            }
        }

        // The production wire format rejects identity commitments.
        if self.commitment.is_identity() {
            return Err(VerificationError::InvalidDLEQProof);
        }

        // Append public values to transcript (same as in prove)
        transcript.append_message(b"gen_schnorr_n", &(n as u64).to_le_bytes());
        for g_i in base_points {
            transcript.append_point::<C>(b"gen_schnorr_base", g_i);
        }
        transcript.append_point::<C>(b"gen_schnorr_R", R);

        // Append commitment to transcript
        transcript.append_point::<C>(b"gen_schnorr_commitment", &self.commitment);

        // Get challenge scalar c
        let c = transcript.challenge::<C>(b"gen_schnorr_challenge").scalar;

        // Verify: sum(s_i * g_i) == T + c * R
        let lhs = C::Point::vartime_multiscalar_mul(&self.responses, base_points);
        let rhs = self.commitment + *R * c;

        if lhs == rhs {
            Ok(())
        } else {
            Err(VerificationError::InvalidDLEQProof)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transcript_ext::MerlinTranscript;
    use poker_protocol_core::RistrettoCurve;

    type C = RistrettoCurve;

    #[test]
    fn strict_prover_rejects_empty_and_inconsistent_witnesses() {
        let r = C::base_g();
        assert_eq!(
            GeneralizedSchnorrProof::<C>::prove(
                &[],
                &[],
                &r,
                &mut MerlinTranscript::new(b"gen-empty")
            )
            .unwrap_err(),
            VerificationError::LengthMismatch
        );

        let secret = <C as Curve>::Scalar::from_u64(3);
        let wrong_r = C::base_g() * <C as Curve>::Scalar::from_u64(4);
        assert_eq!(
            GeneralizedSchnorrProof::<C>::prove(
                &[C::base_g()],
                &[secret],
                &wrong_r,
                &mut MerlinTranscript::new(b"gen-wrong-witness")
            )
            .unwrap_err(),
            VerificationError::InvalidInput
        );
    }

    #[test]
    fn verifier_rejects_empty_shape() {
        let proof = GeneralizedSchnorrProof::<C> {
            commitment: C::base_g(),
            responses: vec![],
        };
        assert!(proof
            .verify(
                &[],
                &C::base_g(),
                &mut MerlinTranscript::new(b"gen-empty-verify")
            )
            .is_err());
    }
}
