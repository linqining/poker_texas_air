//! Generic Chaum--Pedersen equality-of-discrete-log proof.
//!
//! Statement: `(G1, G2, P1, P2)`. Witness: one non-zero scalar `x` satisfying
//! `P1 = x*G1` and `P2 = x*G2`. Proving validates the witness relation;
//! verification rejects identity bases, targets and commitments. The
//! interactive protocol has perfect completeness, special soundness and
//! perfect HVZK. Fiat--Shamir security relies on the fixed statement and
//! commitment transcript order below.

pub use crate::error::VerificationError;
use crate::transcript_ext::CryptoTranscript;
use poker_protocol_core::{Curve, CurvePoint, CurveScalar};
use rand_core::OsRng;

/// Chaum-Pedersen DLEQ proof for proving that two points have the same discrete logarithm
/// with respect to two different base points.
/// Proves: P1 = s*G1 and P2 = s*G2 for the same secret s
#[derive(Debug, Clone)]
pub struct ChaumPedersenDLEQProof<C: Curve> {
    /// Commitment A = w*G1
    pub commitment_a: C::Point,
    /// Commitment B = w*G2
    pub commitment_b: C::Point,
    /// Response s = w + c*x (where x is the secret discrete log)
    pub response: C::Scalar,
}
impl<C: Curve> ChaumPedersenDLEQProof<C> {
    /// Prove that P1 = s*G1 and P2 = s*G2 for the same secret s
    ///
    /// # Arguments
    /// * `G1` - First base point
    /// * `G2` - Second base point
    /// * `s` - Secret scalar (the discrete logarithm)
    /// * `P1` - First point (should equal s*G1)
    /// * `P2` - Second point (should equal s*G2)
    /// * `transcript` - Merlin transcript for Fiat-Shamir
    pub fn prove(
        G1: C::Point,
        G2: C::Point,
        s: C::Scalar,
        P1: C::Point,
        P2: C::Point,
        transcript: &mut impl CryptoTranscript,
    ) -> Result<Self, VerificationError> {
        // Identity bases make one or both equations vacuous.
        if G1.is_identity() || G2.is_identity() {
            return Err(VerificationError::IdentityBasePoint);
        }

        // Identity targets encode the trivial zero-witness statement.
        if P1.is_identity() || P2.is_identity() {
            return Err(VerificationError::IdentityBasePoint);
        }

        // A prover API must not manufacture a proof for a statement that does
        // not match its witness.  Verification would eventually reject such a
        // proof, but failing here prevents callers from accidentally publishing
        // an unusable proof and makes the witness contract explicit.
        if s == C::Scalar::zero() || P1 != G1 * s || P2 != G2 * s {
            return Err(VerificationError::InvalidInput);
        }

        // Consensus-sensitive statement order shared by every verifier.
        transcript.append_point::<C>(b"cp_G1", &G1);
        transcript.append_point::<C>(b"cp_G2", &G2);
        transcript.append_point::<C>(b"cp_P1", &P1);
        transcript.append_point::<C>(b"cp_P2", &P2);

        // Resample instead of emitting an identity commitment.  On the
        // prime-order curves supported by this crate, a non-zero nonce and
        // non-identity bases make both commitments non-identity.
        let (w, commitment_a, commitment_b) = loop {
            let w = C::Scalar::random(&mut OsRng);
            if w == C::Scalar::zero() {
                continue;
            }
            let commitment_a = G1 * w;
            let commitment_b = G2 * w;
            if !commitment_a.is_identity() && !commitment_b.is_identity() {
                break (w, commitment_a, commitment_b);
            }
        };

        // Append commitments to transcript
        transcript.append_point::<C>(b"cp_commitment_a", &commitment_a);
        transcript.append_point::<C>(b"cp_commitment_b", &commitment_b);

        // Get challenge scalar from transcript
        let c = transcript.challenge::<C>(b"cp_challenge").scalar;

        // Compute response: s = w + c*x
        let response = w + s * c;

        Ok(Self {
            commitment_a,
            commitment_b,
            response,
        })
    }

    /// Verify the Chaum-Pedersen DLEQ proof
    ///
    /// # Arguments
    /// * `G1` - First base point
    /// * `G2` - Second base point
    /// * `P1` - First point (claimed to be s*G1)
    /// * `P2` - Second point (claimed to be s*G2)
    /// * `transcript` - Merlin transcript for Fiat-Shamir
    pub fn verify(
        &self,
        G1: C::Point,
        G2: C::Point,
        P1: C::Point,
        P2: C::Point,
        transcript: &mut impl CryptoTranscript,
    ) -> Result<(), VerificationError> {
        // SECURITY: Reject identity base points to prevent trivial attacks
        if G1.is_identity() || G2.is_identity() {
            return Err(VerificationError::IdentityBasePoint);
        }

        // Identity targets encode a trivial zero-witness statement.
        if P1.is_identity() || P2.is_identity() {
            return Err(VerificationError::IdentityBasePoint);
        }

        // Strict wire validation rejects identity commitments.
        if self.commitment_a.is_identity() || self.commitment_b.is_identity() {
            return Err(VerificationError::InvalidDLEQProof);
        }

        // Reproduce the consensus-sensitive prover transcript order.
        // Append public values to transcript
        transcript.append_point::<C>(b"cp_G1", &G1);
        transcript.append_point::<C>(b"cp_G2", &G2);
        transcript.append_point::<C>(b"cp_P1", &P1);
        transcript.append_point::<C>(b"cp_P2", &P2);

        // Append commitments to transcript
        transcript.append_point::<C>(b"cp_commitment_a", &self.commitment_a);
        transcript.append_point::<C>(b"cp_commitment_b", &self.commitment_b);

        // Get challenge scalar from transcript
        let c = transcript.challenge::<C>(b"cp_challenge").scalar;

        // Verify: s*G1 = A + c*P1
        let lhs1 = G1 * self.response;
        let rhs1 = self.commitment_a + P1 * c;

        // Verify: s*G2 = B + c*P2
        let lhs2 = G2 * self.response;
        let rhs2 = self.commitment_b + P2 * c;

        if lhs1 == rhs1 && lhs2 == rhs2 {
            Ok(())
        } else {
            Err(VerificationError::InvalidDLEQProof)
        }
    }
}
