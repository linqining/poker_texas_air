//! Reconstruction proof families.
//!
//! V2 is retained for compatibility and documented counterexample testing; it
//! does not provide the V3 soundness or zero-knowledge relation. V3 publishes
//! aggregate-key contributions, uses a shared cross-key negation proof for
//! each prior readable card, hides their placement with Bayer--Groth, and
//! proves per-canonical-slot membership in `{0, -card[i]}`. Historical
//! provenance of `user_readable_cards` is authenticated by the outer state
//! digest rather than reconstructed by this crate.

mod chaum_pedersen;
mod cross_key;
mod ordered_encryption;
mod slot_or;
mod swap_out;
#[cfg(test)]
mod tests;
mod v3;
#[cfg(test)]
mod v3_tests;

pub use crate::error::VerificationError;
use crate::transcript_ext::CryptoTranscript;
pub use chaum_pedersen::ChaumPedersenDLEQProof;
pub use cross_key::CrossKeyNegationProof;
pub use ordered_encryption::OrderedEncryptionProof;
use poker_protocol_bg::BayerGrothShuffleProof;
use poker_protocol_core::{Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric};
use rand_core::OsRng;
use rayon::prelude::*;
pub(crate) use slot_or::ContributionBranch;
pub use slot_or::SlotContributionOrProof;
use std::collections::{HashMap, HashSet};
pub use swap_out::{ReconstructionDLEQProof, SwapOutCardProof};
pub use v3::{
    apply_reconstruction_contributions, canonical_base_deck, ReconstructProofV3,
    ReconstructionV3Statement, RECONSTRUCTION_V3_PROOF_LABEL, RECONSTRUCTION_V3_PROOF_VERSION,
};

const RECONSTRUCTION_PROTOCOL_ID: &[u8] = b"poker/reconstruction/v2";
pub const RECONSTRUCTION_PROOF_VERSION: u8 = 2;
pub const RECONSTRUCTION_PROOF_LABEL: &[u8] = b"zk_reconstruct_proof_v2";

pub fn exp_iter<C: Curve>(x: C::Scalar) -> impl Iterator<Item = C::Scalar> {
    std::iter::successors(Some(x), move |acc| Some(*acc * x))
}

pub fn derive_from_output_cards<C: Curve>(
    output_cards: &[ElGamalCiphertextGeneric<C>],
    user_sk: &C::Scalar,
) -> C::Scalar {
    let mut sum_c1 = C::Point::identity();
    let mut sum_c2 = C::Point::identity();
    for ct in output_cards {
        sum_c1 = sum_c1 + ct.c1;
        sum_c2 = sum_c2 + ct.c2;
    }
    let sum_c1_sk = sum_c1 * *user_sk;
    let sum_c2_sk = sum_c2 * *user_sk;
    let mut buffer = Vec::new();
    buffer.extend_from_slice(b"derive_from_output_cards_v1:");
    buffer.extend_from_slice(sum_c1_sk.compress().as_ref());
    buffer.extend_from_slice(sum_c2_sk.compress().as_ref());
    C::hash_to_scalar(&buffer)
}

pub fn reconstruct_deck<C: Curve>(
    cards: &[C::Point],
    user_readable_cards: &[ElGamalCiphertextGeneric<C>],
    user_sk: &C::Scalar,
    user_pk: &C::Point,
    coefficient: &C::Scalar,
) -> Result<
    (
        Vec<C::Scalar>,
        Vec<ElGamalCiphertextGeneric<C>>,
        Vec<(usize, ElGamalCiphertextGeneric<C>)>,
    ),
    VerificationError,
> {
    if cards.len() < 2 || user_readable_cards.is_empty() || user_readable_cards.len() > cards.len()
    {
        return Err(VerificationError::InvalidOperation);
    }
    if user_pk.is_identity() || *user_pk != C::base_g() * *user_sk {
        return Err(VerificationError::InvalidPublicKey);
    }
    if cards.iter().any(CurvePoint::is_identity) {
        return Err(VerificationError::IdentityBasePoint);
    }
    if coefficient == &C::Scalar::zero() || coefficient == &C::Scalar::one() {
        return Err(VerificationError::InvalidCoefficient);
    }

    let mut user_plain_cards = Vec::with_capacity(user_readable_cards.len());
    let mut seen_plaintexts = HashSet::with_capacity(user_readable_cards.len());
    for user_readable_card in user_readable_cards {
        if !user_readable_card.is_valid() {
            return Err(VerificationError::InvalidCiphertext);
        }
        let plaintext = user_readable_card.decrypt(user_sk);
        if !cards.contains(&plaintext)
            || !seen_plaintexts.insert(plaintext.compress().as_ref().to_vec())
        {
            return Err(VerificationError::InvalidPlaintext);
        }
        user_plain_cards.push(plaintext);
    }

    let s_vec = exp_iter::<C>(*coefficient)
        .take(cards.len() + user_readable_cards.len())
        .collect::<Vec<_>>();
    let output_cards: Vec<ElGamalCiphertextGeneric<C>> = cards
        .par_iter()
        .enumerate()
        .map(|(i, card)| {
            let mut encrypted = ElGamalCiphertextGeneric::<C>::encrypt(card, user_pk, &s_vec[i]);
            if user_plain_cards.contains(card) {
                encrypted.c2 = encrypted.c2 - *card;
            }
            encrypted
        })
        .collect();

    let card_indices: HashMap<Vec<u8>, usize> = cards
        .iter()
        .enumerate()
        .map(|(i, card)| (card.compress().as_ref().to_vec(), i))
        .collect();
    if card_indices.len() != cards.len() {
        return Err(VerificationError::InvalidInput);
    }

    let mut swap_out_cards = Vec::with_capacity(user_plain_cards.len());
    for (i, plaintext) in user_plain_cards.iter().enumerate() {
        let index = *card_indices
            .get(plaintext.compress().as_ref())
            .ok_or(VerificationError::InvalidPlaintext)?;
        let encrypted =
            ElGamalCiphertextGeneric::<C>::encrypt(plaintext, user_pk, &s_vec[cards.len() + i]);
        swap_out_cards.push((index, encrypted));
    }
    Ok((s_vec, output_cards, swap_out_cards))
}

/// Reconstruction proof version 2.
///
/// The Bayer--Groth proof hides the swap indices as a permutation witness. The
/// ordered encryption proof then restores the canonical card order without
/// exposing per-slot coefficients or the hidden mapping.
#[derive(Debug, Clone)]
pub struct ReconstructProof<C: Curve> {
    pub swap_out_cards_proofs: Vec<SwapOutCardProof<C>>,
    pub padded_swap_cards: Vec<ElGamalCiphertextGeneric<C>>,
    pub padded_swap_shuffle_proof: BayerGrothShuffleProof<C>,
    pub ordered_encryption_proof: OrderedEncryptionProof<C>,
}

fn append_ciphertext<C: Curve>(
    transcript: &mut impl CryptoTranscript,
    label: &[u8],
    ciphertext: &ElGamalCiphertextGeneric<C>,
) {
    transcript.append_message(b"reconstruction_ciphertext_label", label);
    transcript.append_point::<C>(b"reconstruction_ciphertext_c1", &ciphertext.c1);
    transcript.append_point::<C>(b"reconstruction_ciphertext_c2", &ciphertext.c2);
}

fn append_statement<C: Curve>(
    cards: &[C::Point],
    output_cards: &[ElGamalCiphertextGeneric<C>],
    swap_out_cards: &[ElGamalCiphertextGeneric<C>],
    user_readable_cards: &[ElGamalCiphertextGeneric<C>],
    user_pk: &C::Point,
    transcript: &mut impl CryptoTranscript,
) {
    transcript.append_message(b"reconstruction_protocol", RECONSTRUCTION_PROTOCOL_ID);
    transcript.append_message(b"reconstruction_n", &(cards.len() as u64).to_le_bytes());
    transcript.append_message(
        b"reconstruction_k",
        &(swap_out_cards.len() as u64).to_le_bytes(),
    );
    transcript.append_point::<C>(b"reconstruction_user_pk", user_pk);
    for card in cards {
        transcript.append_point::<C>(b"reconstruction_card", card);
    }
    for ciphertext in output_cards {
        append_ciphertext::<C>(transcript, b"output", ciphertext);
    }
    for ciphertext in user_readable_cards {
        append_ciphertext::<C>(transcript, b"user_readable", ciphertext);
    }
    for ciphertext in swap_out_cards {
        append_ciphertext::<C>(transcript, b"swap_out", ciphertext);
    }
}

fn deterministic_zero_ciphertexts<C: Curve>(
    count: usize,
    user_pk: &C::Point,
) -> Vec<(ElGamalCiphertextGeneric<C>, C::Scalar)> {
    (0..count)
        .map(|i| {
            let randomness = C::Scalar::from_u64((i as u64) + 1);
            (
                ElGamalCiphertextGeneric::<C>::encrypt(&C::Point::identity(), user_pk, &randomness),
                randomness,
            )
        })
        .collect()
}

fn corrected_ciphertexts<C: Curve>(
    output_cards: &[ElGamalCiphertextGeneric<C>],
    padded_swap_cards: &[ElGamalCiphertextGeneric<C>],
) -> Vec<ElGamalCiphertextGeneric<C>> {
    output_cards
        .iter()
        .zip(padded_swap_cards)
        .map(|(output, padded)| ElGamalCiphertextGeneric {
            c1: output.c1 + padded.c1,
            c2: output.c2 + padded.c2,
        })
        .collect()
}

impl<C: Curve> ReconstructProof<C> {
    #[allow(clippy::too_many_arguments)]
    pub fn prove(
        cards: Vec<C::Point>,
        user_readable_cards: Vec<ElGamalCiphertextGeneric<C>>,
        output_cards: Vec<ElGamalCiphertextGeneric<C>>,
        swap_out_cards: Vec<(usize, ElGamalCiphertextGeneric<C>)>,
        user_sk: &C::Scalar,
        user_pk: &C::Point,
        s_vec: Vec<C::Scalar>,
        transcript: &mut impl CryptoTranscript,
    ) -> Result<Self, VerificationError> {
        let n = cards.len();
        let k = swap_out_cards.len();
        if n < 2
            || output_cards.len() != n
            || user_readable_cards.len() != k
            || k == 0
            || k > n
            || s_vec.len() != n + k
        {
            return Err(VerificationError::LengthMismatch);
        }
        if user_pk.is_identity() || *user_pk != C::base_g() * *user_sk {
            return Err(VerificationError::InvalidPublicKey);
        }
        if cards.iter().any(CurvePoint::is_identity) {
            return Err(VerificationError::IdentityBasePoint);
        }
        let unique_cards = cards
            .iter()
            .map(|card| card.compress().as_ref().to_vec())
            .collect::<HashSet<_>>();
        if unique_cards.len() != n {
            return Err(VerificationError::InvalidInput);
        }
        if output_cards.iter().any(|ciphertext| !ciphertext.is_valid())
            || user_readable_cards
                .iter()
                .any(|ciphertext| !ciphertext.is_valid())
            || swap_out_cards
                .iter()
                .any(|(_, ciphertext)| !ciphertext.is_valid())
        {
            return Err(VerificationError::InvalidCiphertext);
        }
        let mut seen_indices = vec![false; n];
        for (index, _) in &swap_out_cards {
            if *index >= n || seen_indices[*index] {
                return Err(VerificationError::InvalidPermutation);
            }
            seen_indices[*index] = true;
        }

        let swap_ciphertexts: Vec<_> = swap_out_cards
            .iter()
            .map(|(_, card)| card.clone())
            .collect();
        append_statement(
            &cards,
            &output_cards,
            &swap_ciphertexts,
            &user_readable_cards,
            user_pk,
            transcript,
        );

        let mut swap_out_cards_proofs = Vec::with_capacity(k);
        for (user_readable_card, swap_out_card) in user_readable_cards.iter().zip(&swap_ciphertexts)
        {
            swap_out_cards_proofs.push(SwapOutCardProof::prove(
                user_readable_card.clone(),
                swap_out_card.clone(),
                user_sk,
                user_pk,
                transcript,
            )?);
        }

        let zero_ciphertexts = deterministic_zero_ciphertexts::<C>(n - k, user_pk);
        let mut shuffle_input = Vec::with_capacity(n);
        shuffle_input.extend_from_slice(&swap_ciphertexts);
        shuffle_input.extend(
            zero_ciphertexts
                .iter()
                .map(|(ciphertext, _)| ciphertext.clone()),
        );

        let mut permutation = vec![usize::MAX; n];
        let mut base_randomness = vec![C::Scalar::zero(); n];
        for (swap_position, (canonical_index, _)) in swap_out_cards.iter().enumerate() {
            permutation[*canonical_index] = swap_position;
            base_randomness[*canonical_index] = s_vec[n + swap_position];
        }
        let mut zero_cursor = 0usize;
        for i in 0..n {
            if permutation[i] == usize::MAX {
                permutation[i] = k + zero_cursor;
                base_randomness[i] = zero_ciphertexts[zero_cursor].1;
                zero_cursor += 1;
            }
        }

        let mut rerandomizers = Vec::with_capacity(n);
        let mut padded_swap_cards = Vec::with_capacity(n);
        let mut corrected_randomness = Vec::with_capacity(n);
        for i in 0..n {
            loop {
                let rerandomizer = C::Scalar::random(&mut OsRng);
                let padded = shuffle_input[permutation[i]].re_encrypt(user_pk, &rerandomizer);
                let corrected_randomizer = s_vec[i] + base_randomness[i] + rerandomizer;
                let corrected: ElGamalCiphertextGeneric<C> = ElGamalCiphertextGeneric {
                    c1: output_cards[i].c1 + padded.c1,
                    c2: output_cards[i].c2 + padded.c2,
                };
                if !padded.c1.is_identity()
                    && !padded.c2.is_identity()
                    && corrected_randomizer != C::Scalar::zero()
                    && !corrected.c1.is_identity()
                    && !(corrected.c2 - cards[i]).is_identity()
                {
                    rerandomizers.push(rerandomizer);
                    padded_swap_cards.push(padded);
                    corrected_randomness.push(corrected_randomizer);
                    break;
                }
            }
        }

        let padded_swap_shuffle_proof = BayerGrothShuffleProof::<C>::prove(
            &shuffle_input,
            &padded_swap_cards,
            &permutation,
            &rerandomizers,
            user_pk,
            &mut OsRng,
            transcript,
        )?;

        let corrected = corrected_ciphertexts(&output_cards, &padded_swap_cards);
        let ordered_encryption_proof = OrderedEncryptionProof::<C>::prove(
            &cards,
            &corrected,
            &corrected_randomness,
            user_pk,
            &mut OsRng,
            transcript,
        )?;

        Ok(Self {
            swap_out_cards_proofs,
            padded_swap_cards,
            padded_swap_shuffle_proof,
            ordered_encryption_proof,
        })
    }

    pub fn verify(
        &self,
        cards: &[C::Point],
        output_cards: &[ElGamalCiphertextGeneric<C>],
        swap_out_cards: &[ElGamalCiphertextGeneric<C>],
        user_readable_cards: &[ElGamalCiphertextGeneric<C>],
        user_pk: &C::Point,
        transcript: &mut impl CryptoTranscript,
    ) -> Result<(), VerificationError> {
        let n = cards.len();
        let k = swap_out_cards.len();
        if n < 2
            || output_cards.len() != n
            || self.padded_swap_cards.len() != n
            || user_readable_cards.len() != k
            || self.swap_out_cards_proofs.len() != k
            || k == 0
            || k > n
        {
            return Err(VerificationError::LengthMismatch);
        }
        if user_pk.is_identity() {
            return Err(VerificationError::InvalidPublicKey);
        }
        if cards.iter().any(CurvePoint::is_identity) {
            return Err(VerificationError::IdentityBasePoint);
        }
        let unique_cards = cards
            .iter()
            .map(|card| card.compress().as_ref().to_vec())
            .collect::<HashSet<_>>();
        if unique_cards.len() != n {
            return Err(VerificationError::InvalidInput);
        }
        if output_cards.iter().any(|ciphertext| !ciphertext.is_valid())
            || swap_out_cards
                .iter()
                .any(|ciphertext| !ciphertext.is_valid())
            || user_readable_cards
                .iter()
                .any(|ciphertext| !ciphertext.is_valid())
        {
            return Err(VerificationError::InvalidCiphertext);
        }

        append_statement(
            cards,
            output_cards,
            swap_out_cards,
            user_readable_cards,
            user_pk,
            transcript,
        );

        for i in 0..k {
            let proof = &self.swap_out_cards_proofs[i];
            if proof.swap_out_card != swap_out_cards[i]
                || proof.user_readable_card != user_readable_cards[i]
            {
                return Err(VerificationError::InvalidProofAtPosition(i));
            }
            let delta_c1 = proof.swap_out_card.c1 - proof.user_readable_card.c1;
            let delta_c2 = proof.swap_out_card.c2 - proof.user_readable_card.c2;
            proof
                .chaum_pedersen_proof
                .verify(delta_c1, C::base_g(), delta_c2, *user_pk, transcript)
                .map_err(|_| VerificationError::InvalidProofAtPosition(i))?;
        }

        let zero_ciphertexts = deterministic_zero_ciphertexts::<C>(n - k, user_pk);
        let mut shuffle_input = Vec::with_capacity(n);
        shuffle_input.extend_from_slice(swap_out_cards);
        shuffle_input.extend(
            zero_ciphertexts
                .iter()
                .map(|(ciphertext, _)| ciphertext.clone()),
        );
        self.padded_swap_shuffle_proof.verify(
            &shuffle_input,
            &self.padded_swap_cards,
            user_pk,
            transcript,
        )?;

        let corrected = corrected_ciphertexts(output_cards, &self.padded_swap_cards);
        self.ordered_encryption_proof
            .verify(cards, &corrected, user_pk, transcript)
    }
}
