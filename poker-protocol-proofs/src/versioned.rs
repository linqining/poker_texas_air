//! Versioned shuffle dispatch and production fail-closed policy.
//!
//! Legacy V1 remains decodable but is cryptographically unsound and always
//! rejected. V2 delegates to the Bayer--Groth permutation/re-encryption
//! argument. Callers must bind the curve/domain, deck length, public key and
//! application state into the surrounding transcript/context.

use crate::bayer_groth::BayerGrothShuffleProof;
use crate::error::VerificationError;
use crate::shuffle_proof::ZKShuffleProof;
use crate::transcript_ext::CryptoTranscript;
use poker_protocol_core::{Curve, ElGamalCiphertextGeneric};
use rand_core::{CryptoRng, RngCore};

pub const LEGACY_SHUFFLE_PROOF_VERSION: u8 = 1;
pub const BAYER_GROTH_SHUFFLE_PROOF_VERSION: u8 = 2;

/// Wire-versioned shuffle proof.  V1 remains decodable for migration and
/// forensic tooling, but the production verifier intentionally fails closed.
#[derive(Debug, Clone)]
pub enum VersionedShuffleProof<C: Curve> {
    LegacyV1(ZKShuffleProof<C>),
    BayerGrothV2(BayerGrothShuffleProof<C>),
}

impl<C: Curve> VersionedShuffleProof<C> {
    /// Production proving always emits Bayer--Groth V2.
    pub fn prove(
        input: &[ElGamalCiphertextGeneric<C>],
        output: &[ElGamalCiphertextGeneric<C>],
        permutation: &[usize],
        rerandomizers: &[C::Scalar],
        public_key: &C::Point,
        rng: &mut (impl CryptoRng + RngCore),
        transcript: &mut impl CryptoTranscript,
    ) -> Result<Self, VerificationError> {
        BayerGrothShuffleProof::prove(
            input,
            output,
            permutation,
            rerandomizers,
            public_key,
            rng,
            transcript,
        )
        .map(Self::BayerGrothV2)
    }

    /// Production verification rejects V1 regardless of whether its legacy
    /// equations happen to accept the proof.
    pub fn verify(
        &self,
        input: &[ElGamalCiphertextGeneric<C>],
        output: &[ElGamalCiphertextGeneric<C>],
        public_key: &C::Point,
        transcript: &mut impl CryptoTranscript,
    ) -> Result<(), VerificationError> {
        match self {
            Self::LegacyV1(_) => Err(VerificationError::LegacyShuffleProofDisabled),
            Self::BayerGrothV2(proof) => proof.verify(input, output, public_key, transcript),
        }
    }

    pub fn version(&self) -> u8 {
        match self {
            Self::LegacyV1(_) => LEGACY_SHUFFLE_PROOF_VERSION,
            Self::BayerGrothV2(_) => BAYER_GROTH_SHUFFLE_PROOF_VERSION,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generalized_schnorr_proof::GeneralizedSchnorrProof;
    use crate::transcript_ext::{CryptoTranscript, MerlinTranscript};
    use poker_protocol_core::{CurvePoint, CurveScalar, RistrettoCurve};

    #[test]
    fn legacy_variant_is_fail_closed() {
        let zero = <RistrettoCurve as Curve>::Scalar::zero();
        let identity = <RistrettoCurve as Curve>::Point::identity();
        let legacy = ZKShuffleProof::<RistrettoCurve> {
            sum_c1_commit: identity,
            sum_c2_commit: identity,
            combined_schnorr_proof: GeneralizedSchnorrProof {
                commitment: identity,
                responses: vec![],
            },
            sum_c1_schnorr_proof: GeneralizedSchnorrProof {
                commitment: identity,
                responses: vec![],
            },
            sum_c2_schnorr_proof: GeneralizedSchnorrProof {
                commitment: identity,
                responses: vec![],
            },
            nonce: zero,
        };
        let versioned = VersionedShuffleProof::LegacyV1(legacy);
        let result = versioned.verify(
            &[],
            &[],
            &identity,
            &mut MerlinTranscript::new(b"legacy-disabled"),
        );
        assert_eq!(
            result.unwrap_err(),
            VerificationError::LegacyShuffleProofDisabled
        );
    }
}
