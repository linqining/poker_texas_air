//! Native BLS12-381 reference adapters for the stable poker precompile ABI.
//!
//! Production STWO and chain integrations bind the canonical request bytes and
//! may replace this backend with BLS12-377 without changing the AIR contract.

use crate::crypto::curve::{Bls12381Curve, Curve, CurvePoint, ElGamalCiphertextGeneric};
use crate::zk_shuffle::bayer_groth::BayerGrothShuffleProof;
use crate::zk_shuffle::reconstruction::{
    ReconstructProof, ReconstructProofV3, ReconstructionV3Statement,
};
use crate::zk_shuffle::transcript_ext::{CryptoTranscript, FiatShamirTranscript, MerlinTranscript};
use crate::zk_shuffle::{ShuffleProof, VersionedShuffleProof};
use borsh::BorshDeserialize;
use poker_protocol_abi::{
    AbiError, CurveId, EncodedCiphertext, ReconstructionProofSystem, ReconstructionV3Verifier,
    ReconstructionV3VerifyRequest, ReconstructionVerifier, ReconstructionVerifyRequest,
    ShuffleProofSystem, ShuffleVerifier, ShuffleVerifyRequest, TranscriptId,
};

pub fn build_bls12381_shuffle_request(
    context: &[u8],
    call_context: &[u8],
    transcript: TranscriptId,
    public_key: &<Bls12381Curve as Curve>::Point,
    input: &[ElGamalCiphertextGeneric<Bls12381Curve>],
    output: &[ElGamalCiphertextGeneric<Bls12381Curve>],
    proof: &ShuffleProof,
) -> Result<ShuffleVerifyRequest, NativePrecompileError> {
    let VersionedShuffleProof::BayerGrothV2(proof) = proof else {
        return Err(NativePrecompileError::LegacyProofDisabled);
    };
    let request = ShuffleVerifyRequest {
        curve: CurveId::Bls12381G1,
        proof_system: ShuffleProofSystem::BayerGrothV2,
        transcript,
        context: context.to_vec(),
        call_context: call_context.to_vec(),
        public_key: public_key.compress().as_ref().to_vec(),
        input: encode_ciphertexts(input),
        output: encode_ciphertexts(output),
        proof: borsh::to_vec(proof).map_err(|_| NativePrecompileError::InvalidProofEncoding)?,
    };
    request.validate()?;
    Ok(request)
}

#[allow(clippy::too_many_arguments)]
pub fn build_bls12381_reconstruction_request(
    context: &[u8],
    call_context: &[u8],
    transcript: TranscriptId,
    cards: &[<Bls12381Curve as Curve>::Point],
    output_cards: &[ElGamalCiphertextGeneric<Bls12381Curve>],
    swap_out_cards: &[ElGamalCiphertextGeneric<Bls12381Curve>],
    user_readable_cards: &[ElGamalCiphertextGeneric<Bls12381Curve>],
    user_public_key: &<Bls12381Curve as Curve>::Point,
    proof: &ReconstructProof<Bls12381Curve>,
) -> Result<ReconstructionVerifyRequest, NativePrecompileError> {
    let request = ReconstructionVerifyRequest {
        curve: CurveId::Bls12381G1,
        proof_system: ReconstructionProofSystem::BayerGrothOrderedV2,
        transcript,
        context: context.to_vec(),
        call_context: call_context.to_vec(),
        cards: cards
            .iter()
            .map(|card| card.compress().as_ref().to_vec())
            .collect(),
        output_cards: encode_ciphertexts(output_cards),
        swap_out_cards: encode_ciphertexts(swap_out_cards),
        user_readable_cards: encode_ciphertexts(user_readable_cards),
        user_public_key: user_public_key.compress().as_ref().to_vec(),
        proof: borsh::to_vec(proof).map_err(|_| NativePrecompileError::InvalidProofEncoding)?,
    };
    request.validate()?;
    Ok(request)
}

/// Encode exactly the V3 statement that was proved.
///
/// Taking the statement as one object prevents a caller from accidentally
/// sending a contribution vector or epoch different from the values absorbed
/// by the cryptographic transcript.
pub fn build_bls12381_reconstruction_v3_request(
    context: &[u8],
    call_context: &[u8],
    transcript: TranscriptId,
    statement: &ReconstructionV3Statement<Bls12381Curve>,
    proof: &ReconstructProofV3<Bls12381Curve>,
) -> Result<ReconstructionV3VerifyRequest, NativePrecompileError> {
    statement
        .validate()
        .map_err(|_| NativePrecompileError::VerificationFailed)?;
    let request = ReconstructionV3VerifyRequest {
        curve: CurveId::Bls12381G1,
        proof_system: ReconstructionProofSystem::BayerGrothSlotOrV3,
        transcript,
        context: context.to_vec(),
        call_context: call_context.to_vec(),
        statement_version: statement.version,
        context_digest: statement.context_digest,
        reconstruction_epoch: statement.reconstruction_epoch,
        prior_state_digest: statement.prior_state_digest,
        aggregate_pk: statement.aggregate_pk.compress().as_ref().to_vec(),
        owner_pk: statement.owner_pk.compress().as_ref().to_vec(),
        cards: statement
            .cards
            .iter()
            .map(|card| card.compress().as_ref().to_vec())
            .collect(),
        user_readable_cards: encode_ciphertexts(&statement.user_readable_cards),
        contributions: encode_ciphertexts(&statement.contributions),
        proof: borsh::to_vec(proof).map_err(|_| NativePrecompileError::InvalidProofEncoding)?,
    };
    request.validate()?;
    Ok(request)
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NativeBls12381ShuffleVerifier;

impl ShuffleVerifier for NativeBls12381ShuffleVerifier {
    type Error = NativePrecompileError;

    fn verify(&self, request: &ShuffleVerifyRequest) -> Result<(), Self::Error> {
        request.validate()?;
        if request.curve != CurveId::Bls12381G1 {
            return Err(NativePrecompileError::UnsupportedCurve);
        }
        if request.proof_system != ShuffleProofSystem::BayerGrothV2 {
            return Err(NativePrecompileError::UnsupportedProofSystem);
        }
        let public_key = decode_point(&request.public_key)?;
        let input = decode_ciphertexts(&request.input)?;
        let output = decode_ciphertexts(&request.output)?;
        let proof = BayerGrothShuffleProof::<Bls12381Curve>::try_from_slice(&request.proof)
            .map_err(|_| NativePrecompileError::InvalidProofEncoding)?;
        match request.transcript {
            TranscriptId::Merlin => verify_shuffle(
                &proof,
                &input,
                &output,
                &public_key,
                &mut MerlinTranscript::new(&request.context),
            ),
            TranscriptId::FiatShamirSha3 => verify_shuffle(
                &proof,
                &input,
                &output,
                &public_key,
                &mut FiatShamirTranscript::new(&request.context),
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NativeBls12381ReconstructionVerifier;

impl ReconstructionVerifier for NativeBls12381ReconstructionVerifier {
    type Error = NativePrecompileError;

    fn verify(&self, request: &ReconstructionVerifyRequest) -> Result<(), Self::Error> {
        request.validate()?;
        if request.curve != CurveId::Bls12381G1 {
            return Err(NativePrecompileError::UnsupportedCurve);
        }
        if request.proof_system != ReconstructionProofSystem::BayerGrothOrderedV2 {
            return Err(NativePrecompileError::UnsupportedProofSystem);
        }
        let cards = request
            .cards
            .iter()
            .map(|card| decode_point(card))
            .collect::<Result<Vec<_>, _>>()?;
        let output_cards = decode_ciphertexts(&request.output_cards)?;
        let swap_out_cards = decode_ciphertexts(&request.swap_out_cards)?;
        let user_readable_cards = decode_ciphertexts(&request.user_readable_cards)?;
        let user_public_key = decode_point(&request.user_public_key)?;
        let proof = ReconstructProof::<Bls12381Curve>::try_from_slice(&request.proof)
            .map_err(|_| NativePrecompileError::InvalidProofEncoding)?;
        match request.transcript {
            TranscriptId::Merlin => verify_reconstruction(
                &proof,
                &cards,
                &output_cards,
                &swap_out_cards,
                &user_readable_cards,
                &user_public_key,
                &mut MerlinTranscript::new(&request.context),
            ),
            TranscriptId::FiatShamirSha3 => verify_reconstruction(
                &proof,
                &cards,
                &output_cards,
                &swap_out_cards,
                &user_readable_cards,
                &user_public_key,
                &mut FiatShamirTranscript::new(&request.context),
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NativeBls12381ReconstructionV3Verifier;

impl ReconstructionV3Verifier for NativeBls12381ReconstructionV3Verifier {
    type Error = NativePrecompileError;

    fn verify(&self, request: &ReconstructionV3VerifyRequest) -> Result<(), Self::Error> {
        request.validate()?;
        if request.curve != CurveId::Bls12381G1 {
            return Err(NativePrecompileError::UnsupportedCurve);
        }
        if request.proof_system != ReconstructionProofSystem::BayerGrothSlotOrV3 {
            return Err(NativePrecompileError::UnsupportedProofSystem);
        }

        let statement = ReconstructionV3Statement::<Bls12381Curve> {
            version: request.statement_version,
            context_digest: request.context_digest,
            reconstruction_epoch: request.reconstruction_epoch,
            prior_state_digest: request.prior_state_digest,
            aggregate_pk: decode_point(&request.aggregate_pk)?,
            owner_pk: decode_point(&request.owner_pk)?,
            cards: request
                .cards
                .iter()
                .map(|card| decode_point(card))
                .collect::<Result<Vec<_>, _>>()?,
            user_readable_cards: decode_ciphertexts(&request.user_readable_cards)?,
            contributions: decode_ciphertexts(&request.contributions)?,
        };
        statement
            .validate()
            .map_err(|_| NativePrecompileError::VerificationFailed)?;
        let proof = ReconstructProofV3::<Bls12381Curve>::try_from_slice(&request.proof)
            .map_err(|_| NativePrecompileError::InvalidProofEncoding)?;

        match request.transcript {
            TranscriptId::Merlin => verify_reconstruction_v3(
                &proof,
                &statement,
                &mut MerlinTranscript::new(&request.context),
            ),
            TranscriptId::FiatShamirSha3 => verify_reconstruction_v3(
                &proof,
                &statement,
                &mut FiatShamirTranscript::new(&request.context),
            ),
        }
    }
}

fn verify_shuffle(
    proof: &BayerGrothShuffleProof<Bls12381Curve>,
    input: &[ElGamalCiphertextGeneric<Bls12381Curve>],
    output: &[ElGamalCiphertextGeneric<Bls12381Curve>],
    public_key: &<Bls12381Curve as Curve>::Point,
    transcript: &mut impl CryptoTranscript,
) -> Result<(), NativePrecompileError> {
    proof
        .verify(input, output, public_key, transcript)
        .map_err(|_| NativePrecompileError::VerificationFailed)
}

#[allow(clippy::too_many_arguments)]
fn verify_reconstruction(
    proof: &ReconstructProof<Bls12381Curve>,
    cards: &[<Bls12381Curve as Curve>::Point],
    output_cards: &[ElGamalCiphertextGeneric<Bls12381Curve>],
    swap_out_cards: &[ElGamalCiphertextGeneric<Bls12381Curve>],
    user_readable_cards: &[ElGamalCiphertextGeneric<Bls12381Curve>],
    user_public_key: &<Bls12381Curve as Curve>::Point,
    transcript: &mut impl CryptoTranscript,
) -> Result<(), NativePrecompileError> {
    proof
        .verify(
            cards,
            output_cards,
            swap_out_cards,
            user_readable_cards,
            user_public_key,
            transcript,
        )
        .map_err(|_| NativePrecompileError::VerificationFailed)
}

fn verify_reconstruction_v3(
    proof: &ReconstructProofV3<Bls12381Curve>,
    statement: &ReconstructionV3Statement<Bls12381Curve>,
    transcript: &mut impl CryptoTranscript,
) -> Result<(), NativePrecompileError> {
    proof
        .verify(statement, transcript)
        .map_err(|_| NativePrecompileError::VerificationFailed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativePrecompileError {
    Abi(AbiError),
    UnsupportedCurve,
    UnsupportedProofSystem,
    LegacyProofDisabled,
    InvalidPointEncoding,
    InvalidProofEncoding,
    VerificationFailed,
}

impl From<AbiError> for NativePrecompileError {
    fn from(value: AbiError) -> Self {
        Self::Abi(value)
    }
}

impl std::fmt::Display for NativePrecompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for NativePrecompileError {}

fn encode_ciphertexts(
    ciphertexts: &[ElGamalCiphertextGeneric<Bls12381Curve>],
) -> Vec<EncodedCiphertext> {
    ciphertexts
        .iter()
        .map(|ciphertext| EncodedCiphertext {
            c1: ciphertext.c1.compress().as_ref().to_vec(),
            c2: ciphertext.c2.compress().as_ref().to_vec(),
        })
        .collect()
}

fn decode_ciphertexts(
    ciphertexts: &[EncodedCiphertext],
) -> Result<Vec<ElGamalCiphertextGeneric<Bls12381Curve>>, NativePrecompileError> {
    ciphertexts
        .iter()
        .map(|ciphertext| {
            Ok(ElGamalCiphertextGeneric {
                c1: decode_point(&ciphertext.c1)?,
                c2: decode_point(&ciphertext.c2)?,
            })
        })
        .collect()
}

fn decode_point(encoded: &[u8]) -> Result<<Bls12381Curve as Curve>::Point, NativePrecompileError> {
    <<Bls12381Curve as Curve>::Point as CurvePoint>::from_compressed(encoded)
        .ok_or(NativePrecompileError::InvalidPointEncoding)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::curve::CurveScalar;
    use rand_core::OsRng;

    #[test]
    fn abi_roundtrip_matches_native_shuffle_verification() {
        let n = 8;
        let secret_key = <Bls12381Curve as Curve>::Scalar::random(&mut OsRng);
        let public_key = <Bls12381Curve as Curve>::base_g() * secret_key;
        let input: Vec<_> = (0..n)
            .map(|i| {
                let message =
                    Bls12381Curve::hash_to_curve(format!("precompile/test/card/{i}").as_bytes());
                let randomness = <Bls12381Curve as Curve>::Scalar::random(&mut OsRng);
                ElGamalCiphertextGeneric::encrypt(&message, &public_key, &randomness)
            })
            .collect();
        let permutation = vec![3, 0, 7, 1, 6, 2, 5, 4];
        let rerandomizers: Vec<_> = (0..n)
            .map(|_| <Bls12381Curve as Curve>::Scalar::random(&mut OsRng))
            .collect();
        let output: Vec<_> = (0..n)
            .map(|i| input[permutation[i]].re_encrypt(&public_key, &rerandomizers[i]))
            .collect();
        let context = b"zk_shuffle_proof_v2";
        let proof = ShuffleProof::prove(
            &input,
            &output,
            &permutation,
            &rerandomizers,
            &public_key,
            &mut OsRng,
            &mut FiatShamirTranscript::new(context),
        )
        .unwrap();

        let request = build_bls12381_shuffle_request(
            context,
            b"table=1/hand=2/call=3/seat=4",
            TranscriptId::FiatShamirSha3,
            &public_key,
            &input,
            &output,
            &proof,
        )
        .unwrap();
        let encoded = request.encode().unwrap();
        let decoded = ShuffleVerifyRequest::decode(&encoded).unwrap();
        NativeBls12381ShuffleVerifier.verify(&decoded).unwrap();

        let mut changed = decoded.clone();
        changed.context.push(0);
        assert!(NativeBls12381ShuffleVerifier.verify(&changed).is_err());

        let mut changed = decoded.clone();
        changed.public_key[0] ^= 1;
        assert!(NativeBls12381ShuffleVerifier.verify(&changed).is_err());

        let mut changed = decoded.clone();
        changed.input[0].c1[0] ^= 1;
        assert!(NativeBls12381ShuffleVerifier.verify(&changed).is_err());

        let mut changed = decoded.clone();
        changed.output[0].c2[0] ^= 1;
        assert!(NativeBls12381ShuffleVerifier.verify(&changed).is_err());

        let mut changed = decoded;
        changed.proof[0] ^= 1;
        assert!(NativeBls12381ShuffleVerifier.verify(&changed).is_err());
    }

    #[test]
    fn abi_roundtrip_matches_native_reconstruction_verification() {
        use crate::zk_shuffle::reconstruction::{reconstruct_deck, RECONSTRUCTION_PROOF_LABEL};

        let n = 8;
        let secret_key = <Bls12381Curve as Curve>::Scalar::random(&mut OsRng);
        let public_key = <Bls12381Curve as Curve>::base_g() * secret_key;
        let cards: Vec<_> = (0..n)
            .map(|i| {
                Bls12381Curve::hash_to_curve(format!("precompile/reconstruct/card/{i}").as_bytes())
            })
            .collect();
        let user_readable_cards: Vec<_> = [1usize, 6]
            .iter()
            .map(|&i| {
                ElGamalCiphertextGeneric::encrypt(
                    &cards[i],
                    &public_key,
                    &<Bls12381Curve as Curve>::Scalar::random(&mut OsRng),
                )
            })
            .collect();
        let coefficient = <Bls12381Curve as Curve>::Scalar::from_u64(7);
        let (s_vec, output_cards, indexed_swap_cards) = reconstruct_deck::<Bls12381Curve>(
            &cards,
            &user_readable_cards,
            &secret_key,
            &public_key,
            &coefficient,
        )
        .unwrap();
        let mut prover_transcript = FiatShamirTranscript::new(RECONSTRUCTION_PROOF_LABEL);
        let proof = ReconstructProof::prove(
            cards.clone(),
            user_readable_cards.clone(),
            output_cards.clone(),
            indexed_swap_cards.clone(),
            &secret_key,
            &public_key,
            s_vec,
            &mut prover_transcript,
        )
        .unwrap();
        let swap_cards: Vec<_> = indexed_swap_cards
            .into_iter()
            .map(|(_, ciphertext)| ciphertext)
            .collect();
        let request = build_bls12381_reconstruction_request(
            RECONSTRUCTION_PROOF_LABEL,
            b"table=1/hand=2/call=4/seat=3",
            TranscriptId::FiatShamirSha3,
            &cards,
            &output_cards,
            &swap_cards,
            &user_readable_cards,
            &public_key,
            &proof,
        )
        .unwrap();
        let encoded = request.encode().unwrap();
        let decoded = ReconstructionVerifyRequest::decode(&encoded).unwrap();
        NativeBls12381ReconstructionVerifier
            .verify(&decoded)
            .unwrap();
    }

    #[test]
    fn abi_roundtrip_matches_native_reconstruction_v3_verification() {
        use crate::zk_shuffle::reconstruction::RECONSTRUCTION_V3_PROOF_LABEL;

        let n = 8;
        let owner_sk = <Bls12381Curve as Curve>::Scalar::random(&mut OsRng);
        let owner_pk = <Bls12381Curve as Curve>::base_g() * owner_sk;
        // A distinct aggregate key exercises the cross-key relation rather
        // than accidentally reducing the test to a same-key DLEQ proof.
        let aggregate_sk = <Bls12381Curve as Curve>::Scalar::random(&mut OsRng);
        let aggregate_pk = <Bls12381Curve as Curve>::base_g() * aggregate_sk;
        let cards: Vec<_> = (0..n)
            .map(|i| {
                Bls12381Curve::hash_to_curve(
                    format!("precompile/reconstruct-v3/card/{i}").as_bytes(),
                )
            })
            .collect();
        let user_readable_cards: Vec<_> = [1usize, 6]
            .iter()
            .map(|&i| {
                ElGamalCiphertextGeneric::encrypt(
                    &cards[i],
                    &owner_pk,
                    &<Bls12381Curve as Curve>::Scalar::random(&mut OsRng),
                )
            })
            .collect();

        let mut prover_transcript = FiatShamirTranscript::new(RECONSTRUCTION_V3_PROOF_LABEL);
        let (statement, proof) = ReconstructProofV3::prove(
            [11; 32],
            3,
            [22; 32],
            cards,
            user_readable_cards,
            &owner_sk,
            &owner_pk,
            &aggregate_pk,
            &mut OsRng,
            &mut prover_transcript,
        )
        .unwrap();

        let request = build_bls12381_reconstruction_v3_request(
            RECONSTRUCTION_V3_PROOF_LABEL,
            b"table=1/hand=3/call=4/seat=3/state=9",
            TranscriptId::FiatShamirSha3,
            &statement,
            &proof,
        )
        .unwrap();
        let encoded = request.encode().unwrap();
        let decoded = ReconstructionV3VerifyRequest::decode(&encoded).unwrap();
        NativeBls12381ReconstructionV3Verifier
            .verify(&decoded)
            .unwrap();

        let mut changed = decoded.clone();
        changed.reconstruction_epoch += 1;
        assert!(NativeBls12381ReconstructionV3Verifier
            .verify(&changed)
            .is_err());

        let mut changed = decoded;
        changed.contributions[0].c2[0] ^= 1;
        assert!(NativeBls12381ReconstructionV3Verifier
            .verify(&changed)
            .is_err());
    }
}
