//! Legacy reconstruction V2 swap-out and compressed DLEQ helpers.
//!
//! `SwapOutCardProof` uses Chaum--Pedersen to bind the ciphertext difference
//! to the registered user key. `ReconstructionDLEQProof` compresses a vector
//! of scalar-multiplication claims with transcript-derived coefficients.
//! These types remain for V2 compatibility; V3 uses cross-key negation,
//! Bayer--Groth hidden permutation and per-slot OR proofs instead.

use super::chaum_pedersen::ChaumPedersenDLEQProof;
pub use crate::error::VerificationError;
use crate::transcript_ext::CryptoTranscript;
use poker_protocol_core::{Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric};
use rand_core::OsRng;

#[derive(Debug, Clone)]
/// Legacy V2 proof that a swap-out ciphertext differs from a readable card by
/// the registered secret-key action.
pub struct SwapOutCardProof<C: Curve> {
    pub user_readable_card: ElGamalCiphertextGeneric<C>,
    pub swap_out_card: ElGamalCiphertextGeneric<C>,
    /// Shared-witness proof of `delta_c2 = user_sk * delta_c1` and
    /// `user_pk = user_sk * G`.
    pub chaum_pedersen_proof: ChaumPedersenDLEQProof<C>,
}

impl<C: Curve> SwapOutCardProof<C> {
    /// Construct the legacy V2 difference proof after validating the keypair
    /// and both ciphertexts.
    pub(crate) fn prove(
        user_readable_card: ElGamalCiphertextGeneric<C>,
        swap_out_card: ElGamalCiphertextGeneric<C>,
        user_sk: &C::Scalar,
        user_pk: &C::Point,
        transcript: &mut impl CryptoTranscript,
    ) -> Result<Self, VerificationError> {
        if !user_readable_card.is_valid() || !swap_out_card.is_valid() {
            return Err(VerificationError::InvalidCiphertext);
        }
        if *user_sk == C::Scalar::zero()
            || user_pk.is_identity()
            || *user_pk != C::base_g() * *user_sk
        {
            return Err(VerificationError::InvalidPublicKey);
        }
        let delta_c1 = swap_out_card.c1 - user_readable_card.c1;
        let delta_c2 = swap_out_card.c2 - user_readable_card.c2;
        // Prove the two difference/key equations with one shared response.
        let chaum_pedersen_proof = ChaumPedersenDLEQProof::<C>::prove(
            delta_c1,
            C::base_g(),
            *user_sk,
            delta_c2,
            *user_pk,
            transcript,
        )?;

        Ok(Self {
            user_readable_card,
            swap_out_card,
            chaum_pedersen_proof,
        })
    }
}

#[derive(Debug, Clone)]
/// Legacy transcript-compressed vector DLEQ proof.
pub struct ReconstructionDLEQProof<C: Curve> {
    pub commitment: C::Point,
    pub response: C::Scalar,
    pub nonce: C::Scalar,
}

impl<C: Curve> ReconstructionDLEQProof<C> {
    pub fn prove(
        points_in: &[C::Point],
        points_out: &[C::Point],
        a: C::Scalar,
        transcript: &mut impl CryptoTranscript,
    ) -> Result<Self, VerificationError> {
        if points_in.is_empty() || points_in.len() != points_out.len() {
            return Err(VerificationError::LengthMismatch);
        }
        if points_in.iter().any(CurvePoint::is_identity)
            || points_out.iter().any(CurvePoint::is_identity)
        {
            return Err(VerificationError::IdentityBasePoint);
        }
        if a == C::Scalar::zero()
            || points_in
                .iter()
                .zip(points_out)
                .any(|(point_in, point_out)| *point_out != *point_in * a)
        {
            return Err(VerificationError::InvalidInput);
        }
        let nonce = C::Scalar::random(&mut OsRng);
        // Legacy V2 transcript order; changing these labels requires a new
        // proof version.
        transcript.append_scalar::<C>(b"reconstruct_blind_nonce", &nonce);
        for (i, point) in points_in.iter().enumerate() {
            let label = format!("reconstruct_blind_in_{}", i);
            transcript.append_point::<C>(label.as_bytes(), point);
        }
        for (i, point) in points_out.iter().enumerate() {
            let label = format!("reconstruct_blind_out_{}", i);
            transcript.append_point::<C>(label.as_bytes(), point);
        }
        let base_coefficient = transcript.challenge::<C>(b"reconstruct_base_coeff").scalar;
        if base_coefficient == C::Scalar::zero() {
            return Err(VerificationError::InvalidCoefficient);
        }

        // Coefficients start at base^0 = 1 by wire definition.
        let mut sum_point_total = C::Point::identity();
        let mut coefficient = C::Scalar::one();
        for point in points_in {
            sum_point_total = sum_point_total + *point * coefficient;
            coefficient = coefficient * base_coefficient;
        }

        if sum_point_total.is_identity() {
            return Err(VerificationError::InvalidDLEQProof);
        }

        let (w, commitment) = loop {
            let w = C::Scalar::random(&mut OsRng);
            if w == C::Scalar::zero() {
                continue;
            }
            let commitment = sum_point_total * w;
            if !commitment.is_identity() {
                break (w, commitment);
            }
        };
        transcript.append_point::<C>(b"reconstruct_blind_commitment", &commitment);
        let c = transcript
            .challenge::<C>(b"reconstruct_blind_challenge")
            .scalar;
        let response = w + a * c;
        Ok(Self {
            commitment,
            response,
            nonce,
        })
    }

    pub fn verify(
        &self,
        points_in: &[C::Point],
        points_out: &[C::Point],
        transcript: &mut impl CryptoTranscript,
    ) -> Result<(), VerificationError> {
        if points_in.is_empty() || points_in.len() != points_out.len() {
            return Err(VerificationError::LengthMismatch);
        }
        if points_in.iter().any(CurvePoint::is_identity)
            || points_out.iter().any(CurvePoint::is_identity)
        {
            return Err(VerificationError::IdentityBasePoint);
        }
        if self.commitment.is_identity() {
            return Err(VerificationError::InvalidDLEQProof);
        }
        // Reproduce the prover's legacy V2 transcript.
        transcript.append_scalar::<C>(b"reconstruct_blind_nonce", &self.nonce);
        for (i, point) in points_in.iter().enumerate() {
            let label = format!("reconstruct_blind_in_{}", i);
            transcript.append_point::<C>(label.as_bytes(), point);
        }
        for (i, point) in points_out.iter().enumerate() {
            let label = format!("reconstruct_blind_out_{}", i);
            transcript.append_point::<C>(label.as_bytes(), point);
        }
        let base_coefficient = transcript.challenge::<C>(b"reconstruct_base_coeff").scalar;
        if base_coefficient == C::Scalar::zero() {
            return Err(VerificationError::InvalidCoefficient);
        }

        // Coefficients start at base^0 = 1 by wire definition.
        let mut sum_point_in_total = C::Point::identity();
        let mut sum_point_out_total = C::Point::identity();

        let mut coefficient = C::Scalar::one();
        for (point_in, point_out) in points_in.iter().zip(points_out) {
            sum_point_in_total = sum_point_in_total + *point_in * coefficient;
            sum_point_out_total = sum_point_out_total + *point_out * coefficient;
            coefficient = coefficient * base_coefficient;
        }
        if sum_point_in_total.is_identity() || sum_point_out_total.is_identity() {
            return Err(VerificationError::InvalidDLEQProof);
        }
        transcript.append_point::<C>(b"reconstruct_blind_commitment", &self.commitment);
        let c = transcript
            .challenge::<C>(b"reconstruct_blind_challenge")
            .scalar;
        let lhs1 = sum_point_in_total * self.response;
        let rhs1 = self.commitment + sum_point_out_total * c;
        if lhs1 == rhs1 {
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
    fn reconstruction_dleq_rejects_empty_length_mismatch_and_wrong_witness() {
        let a = <C as Curve>::Scalar::from_u64(7);
        let points_in = vec![C::base_g(), C::base_h()];
        let points_out: Vec<_> = points_in.iter().map(|point| *point * a).collect();

        assert_eq!(
            ReconstructionDLEQProof::<C>::prove(
                &[],
                &[],
                a,
                &mut MerlinTranscript::new(b"reconstruct-dleq-empty")
            )
            .unwrap_err(),
            VerificationError::LengthMismatch
        );
        assert_eq!(
            ReconstructionDLEQProof::<C>::prove(
                &points_in,
                &points_out[..1],
                a,
                &mut MerlinTranscript::new(b"reconstruct-dleq-length")
            )
            .unwrap_err(),
            VerificationError::LengthMismatch
        );

        let mut wrong_out = points_out.clone();
        wrong_out[1] = wrong_out[1] + C::base_g();
        assert_eq!(
            ReconstructionDLEQProof::<C>::prove(
                &points_in,
                &wrong_out,
                a,
                &mut MerlinTranscript::new(b"reconstruct-dleq-wrong-witness")
            )
            .unwrap_err(),
            VerificationError::InvalidInput
        );
    }

    #[test]
    fn reconstruction_dleq_honest_and_verify_shape_checks() {
        let a = <C as Curve>::Scalar::from_u64(11);
        let points_in = vec![C::base_g(), C::base_h()];
        let points_out: Vec<_> = points_in.iter().map(|point| *point * a).collect();
        let proof = ReconstructionDLEQProof::<C>::prove(
            &points_in,
            &points_out,
            a,
            &mut MerlinTranscript::new(b"reconstruct-dleq-honest"),
        )
        .unwrap();
        assert!(proof
            .verify(
                &points_in,
                &points_out,
                &mut MerlinTranscript::new(b"reconstruct-dleq-honest")
            )
            .is_ok());
        assert_eq!(
            proof
                .verify(
                    &points_in,
                    &points_out[..1],
                    &mut MerlinTranscript::new(b"reconstruct-dleq-honest")
                )
                .unwrap_err(),
            VerificationError::LengthMismatch
        );
    }

    #[test]
    fn chaum_pedersen_prover_rejects_mismatched_statement() {
        let witness = <C as Curve>::Scalar::from_u64(5);
        let result = ChaumPedersenDLEQProof::<C>::prove(
            C::base_g(),
            C::base_h(),
            witness,
            C::base_g() * witness,
            C::base_h() * witness + C::base_g(),
            &mut MerlinTranscript::new(b"cp-wrong-witness"),
        );
        assert_eq!(result.unwrap_err(), VerificationError::InvalidInput);
    }
}
