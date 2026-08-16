//! Reconstruction V3 per-slot membership OR proof.
//!
//! For canonical slot `i`, this witness-hiding Chaum--Pedersen OR proof shows
//! that the public contribution encrypts either `0` or `-cards[i]` under the
//! aggregate key. One branch is real and one simulated; the proof contains no
//! branch flag or readable-card index. Special soundness follows because two
//! accepting forks with different global challenges differ in at least one
//! challenge share, from which that branch's randomness is extracted.

use crate::transcript_ext::CryptoTranscript;
use poker_protocol_core::{
    Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric, VerificationError,
};
use rand_core::{CryptoRng, RngCore};

const PROTOCOL_ID: &[u8] = b"poker/reconstruction/v3/slot-or";

/// Private branch used only while constructing a proof.  It is deliberately
/// absent from `SlotContributionOrProof` and therefore absent from the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContributionBranch {
    Zero = 0,
    NegativeCard = 1,
}

/// Chaum--Pedersen OR proof for one canonical contribution slot.
///
/// It proves knowledge of `r` for either
///
/// ```text
/// C = Enc_aggregate(0; r)
/// ```
///
/// or
///
/// ```text
/// C = Enc_aggregate(-card_i; r).
/// ```
///
/// One branch is simulated and the other is real.  The verifier sees both
/// challenge shares but cannot tell which share was chosen before the global
/// Fiat--Shamir challenge.
#[derive(Debug, Clone)]
pub struct SlotContributionOrProof<C: Curve> {
    pub commitment_g: [C::Point; 2],
    pub commitment_pk: [C::Point; 2],
    pub challenges: [C::Scalar; 2],
    pub responses: [C::Scalar; 2],
}

fn branch_targets<C: Curve>(
    card: &C::Point,
    contribution: &ElGamalCiphertextGeneric<C>,
) -> [C::Point; 2] {
    // For the negative-card branch:
    //   contribution.c2 + card = r * aggregate_pk.
    [contribution.c2, contribution.c2 + *card]
}

fn append_statement<C: Curve>(
    card: &C::Point,
    contribution: &ElGamalCiphertextGeneric<C>,
    aggregate_pk: &C::Point,
    transcript: &mut impl CryptoTranscript,
) {
    transcript.append_message(b"reconstruct_v3_slot_or_protocol", PROTOCOL_ID);
    transcript.append_point::<C>(b"reconstruct_v3_slot_or_card", card);
    transcript.append_point::<C>(b"reconstruct_v3_slot_or_aggregate_pk", aggregate_pk);
    transcript.append_point::<C>(b"reconstruct_v3_slot_or_c1", &contribution.c1);
    transcript.append_point::<C>(b"reconstruct_v3_slot_or_c2", &contribution.c2);
}

fn challenge_nonzero<C: Curve>(transcript: &mut impl CryptoTranscript) -> C::Scalar {
    let mut challenge = transcript
        .challenge::<C>(b"reconstruct_v3_slot_or_challenge")
        .scalar;
    let mut counter = 0u32;
    while challenge == C::Scalar::zero() {
        transcript.append_message(
            b"reconstruct_v3_slot_or_zero_challenge_retry",
            &counter.to_le_bytes(),
        );
        challenge = transcript
            .challenge::<C>(b"reconstruct_v3_slot_or_challenge")
            .scalar;
        counter = counter.wrapping_add(1);
    }
    challenge
}

fn validate_statement<C: Curve>(
    card: &C::Point,
    contribution: &ElGamalCiphertextGeneric<C>,
    aggregate_pk: &C::Point,
) -> Result<(), VerificationError> {
    if card.is_identity() {
        return Err(VerificationError::IdentityBasePoint);
    }
    if aggregate_pk.is_identity() {
        return Err(VerificationError::InvalidPublicKey);
    }
    if !contribution.is_valid() {
        return Err(VerificationError::InvalidCiphertext);
    }
    Ok(())
}

impl<C: Curve> SlotContributionOrProof<C> {
    pub(crate) fn prove(
        card: &C::Point,
        contribution: &ElGamalCiphertextGeneric<C>,
        randomness: &C::Scalar,
        branch: ContributionBranch,
        aggregate_pk: &C::Point,
        rng: &mut (impl CryptoRng + RngCore),
        transcript: &mut impl CryptoTranscript,
    ) -> Result<Self, VerificationError> {
        validate_statement(card, contribution, aggregate_pk)?;
        if *randomness == C::Scalar::zero() || contribution.c1 != C::base_g() * *randomness {
            return Err(VerificationError::InvalidInput);
        }

        let targets = branch_targets::<C>(card, contribution);
        let real = branch as usize;
        if targets[real] != *aggregate_pk * *randomness {
            return Err(VerificationError::InvalidInput);
        }
        let simulated = 1usize - real;

        let (
            real_nonce,
            simulated_challenge,
            simulated_response,
            mut commitment_g,
            mut commitment_pk,
        ) = loop {
            let real_nonce = C::Scalar::random(rng);
            let simulated_challenge = C::Scalar::random(rng);
            let simulated_response = C::Scalar::random(rng);
            if real_nonce == C::Scalar::zero() {
                continue;
            }

            let mut commitment_g = [C::Point::identity(); 2];
            let mut commitment_pk = [C::Point::identity(); 2];
            commitment_g[real] = C::base_g() * real_nonce;
            commitment_pk[real] = *aggregate_pk * real_nonce;
            commitment_g[simulated] =
                C::base_g() * simulated_response - contribution.c1 * simulated_challenge;
            commitment_pk[simulated] =
                *aggregate_pk * simulated_response - targets[simulated] * simulated_challenge;

            if commitment_g.iter().all(|point| !point.is_identity())
                && commitment_pk.iter().all(|point| !point.is_identity())
            {
                break (
                    real_nonce,
                    simulated_challenge,
                    simulated_response,
                    commitment_g,
                    commitment_pk,
                );
            }
        };

        append_statement(card, contribution, aggregate_pk, transcript);
        for point in &commitment_g {
            transcript.append_point::<C>(b"reconstruct_v3_slot_or_commitment_g", point);
        }
        for point in &commitment_pk {
            transcript.append_point::<C>(b"reconstruct_v3_slot_or_commitment_pk", point);
        }
        let challenge = challenge_nonzero::<C>(transcript);

        let mut challenges = [C::Scalar::zero(); 2];
        let mut responses = [C::Scalar::zero(); 2];
        challenges[simulated] = simulated_challenge;
        responses[simulated] = simulated_response;
        challenges[real] = challenge - simulated_challenge;
        responses[real] = real_nonce + challenges[real] * *randomness;

        // Keep the assignments above close to the standard OR-proof equations;
        // these mutable arrays are the public, branch-independent wire form.
        commitment_g[real] = C::base_g() * real_nonce;
        commitment_pk[real] = *aggregate_pk * real_nonce;

        Ok(Self {
            commitment_g,
            commitment_pk,
            challenges,
            responses,
        })
    }

    pub fn verify(
        &self,
        card: &C::Point,
        contribution: &ElGamalCiphertextGeneric<C>,
        aggregate_pk: &C::Point,
        transcript: &mut impl CryptoTranscript,
    ) -> Result<(), VerificationError> {
        validate_statement(card, contribution, aggregate_pk)?;
        if self.commitment_g.iter().any(CurvePoint::is_identity)
            || self.commitment_pk.iter().any(CurvePoint::is_identity)
        {
            return Err(VerificationError::InvalidDLEQProof);
        }

        append_statement(card, contribution, aggregate_pk, transcript);
        for point in &self.commitment_g {
            transcript.append_point::<C>(b"reconstruct_v3_slot_or_commitment_g", point);
        }
        for point in &self.commitment_pk {
            transcript.append_point::<C>(b"reconstruct_v3_slot_or_commitment_pk", point);
        }
        let challenge = challenge_nonzero::<C>(transcript);
        if self.challenges[0] + self.challenges[1] != challenge {
            return Err(VerificationError::InvalidDLEQProof);
        }

        let targets = branch_targets::<C>(card, contribution);
        for branch in 0..2 {
            if C::base_g() * self.responses[branch]
                != self.commitment_g[branch] + contribution.c1 * self.challenges[branch]
                || *aggregate_pk * self.responses[branch]
                    != self.commitment_pk[branch] + targets[branch] * self.challenges[branch]
            {
                return Err(VerificationError::InvalidDLEQProof);
            }
        }
        Ok(())
    }
}
