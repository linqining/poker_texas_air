//! Reconstruction V3 joint cross-key plaintext-negation proof.
//!
//! This is one two-witness generalized Schnorr proof, not three independent
//! Schnorr proofs. The shared responses bind `owner_sk` and contribution
//! randomness simultaneously across the owner-key, contribution-`c1`, and
//! joint-`c2` equations. It proves opposite plaintexts without knowing or
//! revealing `DL(readable.c1)` or a readable-to-slot index.

use crate::transcript_ext::CryptoTranscript;
use poker_protocol_core::{
    Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric, VerificationError,
};
use rand_core::{CryptoRng, RngCore};

const PROTOCOL_ID: &[u8] = b"poker/reconstruction/v3/cross-key-negation";

/// Joint Sigma proof that two ciphertexts under different public keys contain
/// opposite plaintexts.
///
/// For `R = Enc_owner(m; r)` and `S = Enc_aggregate(-m; v)`, the prover knows
/// only `(owner_sk, v)` and proves the three linear equations
///
/// ```text
/// owner_pk = owner_sk * G
/// S.c1     = v * G
/// owner_sk * R.c1 + v * aggregate_pk = R.c2 + S.c2
/// ```
///
/// Notice that the witness does not contain `r = DL(R.c1)`.  Unknown
/// `DL(R.c1)` is a privacy requirement, not a soundness requirement here.
#[derive(Debug, Clone)]
pub struct CrossKeyNegationProof<C: Curve> {
    pub commitment_owner_key: C::Point,
    pub commitment_contribution_c1: C::Point,
    pub commitment_joint_c2: C::Point,
    pub response_owner_sk: C::Scalar,
    pub response_contribution_randomness: C::Scalar,
}

fn append_statement<C: Curve>(
    readable: &ElGamalCiphertextGeneric<C>,
    negative_contribution: &ElGamalCiphertextGeneric<C>,
    owner_pk: &C::Point,
    aggregate_pk: &C::Point,
    transcript: &mut impl CryptoTranscript,
) {
    transcript.append_message(b"reconstruct_v3_cross_key_protocol", PROTOCOL_ID);
    transcript.append_point::<C>(b"reconstruct_v3_cross_key_owner_pk", owner_pk);
    transcript.append_point::<C>(b"reconstruct_v3_cross_key_aggregate_pk", aggregate_pk);
    transcript.append_point::<C>(b"reconstruct_v3_cross_key_readable_c1", &readable.c1);
    transcript.append_point::<C>(b"reconstruct_v3_cross_key_readable_c2", &readable.c2);
    transcript.append_point::<C>(
        b"reconstruct_v3_cross_key_contribution_c1",
        &negative_contribution.c1,
    );
    transcript.append_point::<C>(
        b"reconstruct_v3_cross_key_contribution_c2",
        &negative_contribution.c2,
    );
}

fn challenge_nonzero<C: Curve>(transcript: &mut impl CryptoTranscript) -> C::Scalar {
    let mut challenge = transcript
        .challenge::<C>(b"reconstruct_v3_cross_key_challenge")
        .scalar;
    let mut counter = 0u32;
    while challenge == C::Scalar::zero() {
        transcript.append_message(
            b"reconstruct_v3_cross_key_zero_challenge_retry",
            &counter.to_le_bytes(),
        );
        challenge = transcript
            .challenge::<C>(b"reconstruct_v3_cross_key_challenge")
            .scalar;
        counter = counter.wrapping_add(1);
    }
    challenge
}

fn validate_statement<C: Curve>(
    readable: &ElGamalCiphertextGeneric<C>,
    negative_contribution: &ElGamalCiphertextGeneric<C>,
    owner_pk: &C::Point,
    aggregate_pk: &C::Point,
) -> Result<(), VerificationError> {
    if owner_pk.is_identity() || aggregate_pk.is_identity() {
        return Err(VerificationError::InvalidPublicKey);
    }
    if !readable.is_valid() || !negative_contribution.is_valid() {
        return Err(VerificationError::InvalidCiphertext);
    }
    Ok(())
}

impl<C: Curve> CrossKeyNegationProof<C> {
    #[allow(clippy::too_many_arguments)]
    pub fn prove(
        readable: &ElGamalCiphertextGeneric<C>,
        negative_contribution: &ElGamalCiphertextGeneric<C>,
        owner_sk: &C::Scalar,
        contribution_randomness: &C::Scalar,
        owner_pk: &C::Point,
        aggregate_pk: &C::Point,
        rng: &mut (impl CryptoRng + RngCore),
        transcript: &mut impl CryptoTranscript,
    ) -> Result<Self, VerificationError> {
        validate_statement(readable, negative_contribution, owner_pk, aggregate_pk)?;

        if *owner_sk == C::Scalar::zero()
            || *contribution_randomness == C::Scalar::zero()
            || *owner_pk != C::base_g() * *owner_sk
            || negative_contribution.c1 != C::base_g() * *contribution_randomness
            || readable.c1 * *owner_sk + *aggregate_pk * *contribution_randomness
                != readable.c2 + negative_contribution.c2
        {
            return Err(VerificationError::InvalidInput);
        }

        // Both witness coordinates get independent one-time masks.  The third
        // commitment combines them, which is what forces both public equations
        // to use the same responses.
        let (
            nonce_owner_sk,
            nonce_contribution,
            commitment_owner_key,
            commitment_contribution_c1,
            commitment_joint_c2,
        ) = loop {
            let nonce_owner_sk = C::Scalar::random(rng);
            let nonce_contribution = C::Scalar::random(rng);
            if nonce_owner_sk == C::Scalar::zero() || nonce_contribution == C::Scalar::zero() {
                continue;
            }
            let commitment_owner_key = C::base_g() * nonce_owner_sk;
            let commitment_contribution_c1 = C::base_g() * nonce_contribution;
            let commitment_joint_c2 =
                readable.c1 * nonce_owner_sk + *aggregate_pk * nonce_contribution;
            if !commitment_owner_key.is_identity()
                && !commitment_contribution_c1.is_identity()
                && !commitment_joint_c2.is_identity()
            {
                break (
                    nonce_owner_sk,
                    nonce_contribution,
                    commitment_owner_key,
                    commitment_contribution_c1,
                    commitment_joint_c2,
                );
            }
        };

        append_statement(
            readable,
            negative_contribution,
            owner_pk,
            aggregate_pk,
            transcript,
        );
        transcript.append_point::<C>(
            b"reconstruct_v3_cross_key_commitment_owner",
            &commitment_owner_key,
        );
        transcript.append_point::<C>(
            b"reconstruct_v3_cross_key_commitment_c1",
            &commitment_contribution_c1,
        );
        transcript.append_point::<C>(
            b"reconstruct_v3_cross_key_commitment_c2",
            &commitment_joint_c2,
        );
        let challenge = challenge_nonzero::<C>(transcript);

        Ok(Self {
            commitment_owner_key,
            commitment_contribution_c1,
            commitment_joint_c2,
            response_owner_sk: nonce_owner_sk + challenge * *owner_sk,
            response_contribution_randomness: nonce_contribution
                + challenge * *contribution_randomness,
        })
    }

    pub fn verify(
        &self,
        readable: &ElGamalCiphertextGeneric<C>,
        negative_contribution: &ElGamalCiphertextGeneric<C>,
        owner_pk: &C::Point,
        aggregate_pk: &C::Point,
        transcript: &mut impl CryptoTranscript,
    ) -> Result<(), VerificationError> {
        validate_statement(readable, negative_contribution, owner_pk, aggregate_pk)?;
        if self.commitment_owner_key.is_identity()
            || self.commitment_contribution_c1.is_identity()
            || self.commitment_joint_c2.is_identity()
        {
            return Err(VerificationError::InvalidDLEQProof);
        }

        append_statement(
            readable,
            negative_contribution,
            owner_pk,
            aggregate_pk,
            transcript,
        );
        transcript.append_point::<C>(
            b"reconstruct_v3_cross_key_commitment_owner",
            &self.commitment_owner_key,
        );
        transcript.append_point::<C>(
            b"reconstruct_v3_cross_key_commitment_c1",
            &self.commitment_contribution_c1,
        );
        transcript.append_point::<C>(
            b"reconstruct_v3_cross_key_commitment_c2",
            &self.commitment_joint_c2,
        );
        let challenge = challenge_nonzero::<C>(transcript);

        let owner_equation = C::base_g() * self.response_owner_sk
            == self.commitment_owner_key + *owner_pk * challenge;
        let contribution_c1_equation = C::base_g() * self.response_contribution_randomness
            == self.commitment_contribution_c1 + negative_contribution.c1 * challenge;
        let joint_c2_equation = readable.c1 * self.response_owner_sk
            + *aggregate_pk * self.response_contribution_randomness
            == self.commitment_joint_c2 + (readable.c2 + negative_contribution.c2) * challenge;

        if owner_equation && contribution_c1_equation && joint_c2_equation {
            Ok(())
        } else {
            Err(VerificationError::InvalidDLEQProof)
        }
    }
}
