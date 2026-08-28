//! Per-player unified Σ-protocol (`PlayerHandSigma`) — the standard
//! settlement-grade proof shape for the direct-sigma route.
//!
//! One proof per player per hand replaces the per-statement sigma batch
//! (ownership + fold leave DLEQ + reveal-token CP). All statements of a
//! player share a single witness `sk`, so they compose into one Schnorr-type
//! argument with a **single challenge and a single response**:
//!
//! Relation set `R` (the prover proves knowledge of `sk` with `Y = sk·X`
//! for every pair, in order):
//!
//! | # | pair `(X, Y)` | statement |
//! | --- | --- | --- |
//! | 0 | `(G, pk)` | key ownership |
//! | 1..=n_fold | `(in_c1_i, d2_i)`, `d2_i = in_c2_i − out_c2_i` | fold leave (key-layer removal) |
//! | next n_reveal | `(c1_j, token_j)` | reveal token (Chaum–Pedersen) |
//!
//! Proof: commitments `A_k = w·X_k` (one point per relation), response
//! `s = w + c·sk` with `c` the Fiat–Shamir challenge below.
//! Verification: `s·X_k == A_k + c·Y_k` for every `k`.
//!
//! ## Soundness
//!
//! Exact (not merely computational): special soundness extracts
//! `sk = (s − s′)/(c − c′)` from two accepting transcripts, and the
//! per-relation commitment shape `A_k = w·X_k` forces the extracted `sk` to
//! satisfy **every** relation simultaneously — the standard AND-composition
//! of Σ-protocols over a shared witness. HVZK holds by the usual
//! Schnorr-type simulator `(A, s) ← (r·X, r)` per relation.
//!
//! ## Transcript (domain-separated, Keccak-256)
//!
//! `PROTOCOL_NAME = b"poker_unified_sigma_v1"`, then in order:
//! `unified_pk` (pk), `unified_n_fold` (32-byte BE scalar), per fold card
//! `unified_fold_in_c1`/`unified_fold_in_c2`/`unified_fold_out_c1`/
//! `unified_fold_out_c2`, `unified_n_reveal` (32-byte BE scalar), per reveal
//! `unified_reveal_c1`/`unified_reveal_c2`/`unified_reveal_token`, then one
//! `unified_commitment` append per `A_k` (same order as `R`), finally the
//! challenge labeled `"challenge"`. Every label and encoding is
//! consensus-sensitive and MUST match all verifiers byte-for-byte.

use poker_protocol_core::{
    Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric, VerificationError,
};
use rand_core::{CryptoRng, RngCore};

use crate::CryptoTranscript;

/// Consensus transcript labels (byte-for-byte stable across all verifiers).
pub mod labels {
    pub const UNIFIED_PK: &[u8] = b"unified_pk";
    pub const UNIFIED_N_FOLD: &[u8] = b"unified_n_fold";
    pub const UNIFIED_FOLD_IN_C1: &[u8] = b"unified_fold_in_c1";
    pub const UNIFIED_FOLD_IN_C2: &[u8] = b"unified_fold_in_c2";
    pub const UNIFIED_FOLD_OUT_C1: &[u8] = b"unified_fold_out_c1";
    pub const UNIFIED_FOLD_OUT_C2: &[u8] = b"unified_fold_out_c2";
    pub const UNIFIED_N_REVEAL: &[u8] = b"unified_n_reveal";
    pub const UNIFIED_REVEAL_C1: &[u8] = b"unified_reveal_c1";
    pub const UNIFIED_REVEAL_C2: &[u8] = b"unified_reveal_c2";
    pub const UNIFIED_REVEAL_TOKEN: &[u8] = b"unified_reveal_token";
    pub const UNIFIED_COMMITMENT: &[u8] = b"unified_commitment";
    pub const CHALLENGE: &[u8] = b"challenge";
}

/// Transcript protocol name for the unified proof.
pub const UNIFIED_SIGMA_PROTOCOL_NAME: &[u8] = b"poker_unified_sigma_v1";

/// One fold (leave) transition: input/output ciphertext of a single card.
/// `d2 = in_c2 − out_c2` is recomputed by every verifier from these fields.
#[derive(Debug, Clone)]
pub struct UnifiedFoldCard<C: Curve> {
    pub in_ct: ElGamalCiphertextGeneric<C>,
    pub out_ct: ElGamalCiphertextGeneric<C>,
}

/// One revealed card: its ciphertext and the player's reveal token.
#[derive(Debug, Clone)]
pub struct UnifiedRevealCard<C: Curve> {
    pub ct: ElGamalCiphertextGeneric<C>,
    pub token: C::Point,
}

/// Public statement of the unified proof.
#[derive(Debug, Clone)]
pub struct UnifiedStatement<C: Curve> {
    pub pk: C::Point,
    pub fold: Vec<UnifiedFoldCard<C>>,
    pub reveal: Vec<UnifiedRevealCard<C>>,
}

impl<C: Curve> UnifiedStatement<C> {
    /// Number of relations: ownership + one per fold card + one per reveal.
    pub fn relation_count(&self) -> usize {
        1 + self.fold.len() + self.reveal.len()
    }

    /// Relation pair `(X, Y)` by index, in transcript order.
    pub fn relation(&self, index: usize) -> (C::Point, C::Point) {
        assert!(index < self.relation_count(), "relation index out of range");
        if index == 0 {
            return (C::base_g(), self.pk);
        }
        let index = index - 1;
        if index < self.fold.len() {
            let card = &self.fold[index];
            // Leave direction: d2 = in_c2 − out_c2.
            let d2 = card.in_ct.c2 - card.out_ct.c2;
            return (card.in_ct.c1, d2);
        }
        let card = &self.reveal[index - self.fold.len()];
        (card.ct.c1, card.token)
    }

    /// Statement shape validation shared by prove and verify (fail-closed).
    pub fn validate(&self) -> Result<(), VerificationError> {
        if self.pk.is_identity() {
            return Err(VerificationError::InvalidPublicKey);
        }
        for card in &self.fold {
            if !card.in_ct.is_valid() || !card.out_ct.is_valid() {
                return Err(VerificationError::InvalidCiphertext);
            }
            if card.in_ct.c1 != card.out_ct.c1 {
                return Err(VerificationError::InvalidInput);
            }
            // A no-op leave (identity d2) is a trivial statement.
            if (card.in_ct.c2 - card.out_ct.c2).is_identity() {
                return Err(VerificationError::InvalidInput);
            }
        }
        for card in &self.reveal {
            if !card.ct.is_valid() || card.token.is_identity() {
                return Err(VerificationError::InvalidCiphertext);
            }
        }
        Ok(())
    }

    /// Append the full statement to the transcript (consensus order).
    pub fn append_to_transcript(&self, transcript: &mut impl CryptoTranscript) {
        transcript.append_point::<C>(labels::UNIFIED_PK, &self.pk);
        transcript.append_scalar::<C>(
            labels::UNIFIED_N_FOLD,
            &C::Scalar::from_u64(self.fold.len() as u64),
        );
        for card in &self.fold {
            transcript.append_point::<C>(labels::UNIFIED_FOLD_IN_C1, &card.in_ct.c1);
            transcript.append_point::<C>(labels::UNIFIED_FOLD_IN_C2, &card.in_ct.c2);
            transcript.append_point::<C>(labels::UNIFIED_FOLD_OUT_C1, &card.out_ct.c1);
            transcript.append_point::<C>(labels::UNIFIED_FOLD_OUT_C2, &card.out_ct.c2);
        }
        transcript.append_scalar::<C>(
            labels::UNIFIED_N_REVEAL,
            &C::Scalar::from_u64(self.reveal.len() as u64),
        );
        for card in &self.reveal {
            transcript.append_point::<C>(labels::UNIFIED_REVEAL_C1, &card.ct.c1);
            transcript.append_point::<C>(labels::UNIFIED_REVEAL_C2, &card.ct.c2);
            transcript.append_point::<C>(labels::UNIFIED_REVEAL_TOKEN, &card.token);
        }
    }
}

/// The unified proof: one commitment point per relation plus one response.
#[derive(Debug, Clone)]
pub struct PlayerHandSigma<C: Curve> {
    pub commitments: Vec<C::Point>,
    pub response: C::Scalar,
}

#[derive(Debug, Clone)]
pub enum UnifiedSigmaError {
    /// Invalid statement shape (identity points, malformed ciphertexts).
    InvalidStatement(VerificationError),
    /// Witness does not satisfy the statement.
    WitnessMismatch,
}

impl std::fmt::Display for UnifiedSigmaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidStatement(e) => write!(f, "invalid statement: {e}"),
            Self::WitnessMismatch => write!(f, "witness does not satisfy statement"),
        }
    }
}

impl std::error::Error for UnifiedSigmaError {}

impl<C: Curve> PlayerHandSigma<C> {
    /// Prove knowledge of `sk` for the whole statement.
    pub fn try_prove(
        sk: &C::Scalar,
        statement: &UnifiedStatement<C>,
        rng: &mut (impl CryptoRng + RngCore),
        transcript: &mut impl CryptoTranscript,
    ) -> Result<Self, UnifiedSigmaError> {
        statement
            .validate()
            .map_err(UnifiedSigmaError::InvalidStatement)?;
        if *sk == C::Scalar::zero() || statement.pk != C::base_g() * *sk {
            return Err(UnifiedSigmaError::WitnessMismatch);
        }
        // Witness contract: every relation must hold for sk.
        for index in 0..statement.relation_count() {
            let (x, y) = statement.relation(index);
            if y != x * *sk {
                return Err(UnifiedSigmaError::WitnessMismatch);
            }
        }

        let w = loop {
            let w = C::Scalar::random(rng);
            if w != C::Scalar::zero() {
                break w;
            }
        };
        let commitments: Vec<C::Point> = (0..statement.relation_count())
            .map(|index| {
                let (x, _) = statement.relation(index);
                x * w
            })
            .collect();

        statement.append_to_transcript(transcript);
        for commitment in &commitments {
            transcript.append_point::<C>(labels::UNIFIED_COMMITMENT, commitment);
        }
        let challenge = transcript.challenge::<C>(labels::CHALLENGE).scalar;
        let response = w + challenge * *sk;

        Ok(Self {
            commitments,
            response,
        })
    }

    /// Verify the unified proof against the statement.
    pub fn verify(
        &self,
        statement: &UnifiedStatement<C>,
        transcript: &mut impl CryptoTranscript,
    ) -> bool {
        if statement.validate().is_err() {
            return false;
        }
        if self.commitments.len() != statement.relation_count() {
            return false;
        }
        for commitment in &self.commitments {
            if commitment.is_identity() {
                return false;
            }
        }

        statement.append_to_transcript(transcript);
        for commitment in &self.commitments {
            transcript.append_point::<C>(labels::UNIFIED_COMMITMENT, commitment);
        }
        let challenge = transcript.challenge::<C>(labels::CHALLENGE).scalar;

        (0..statement.relation_count()).all(|index| {
            let (x, y) = statement.relation(index);
            x * self.response == self.commitments[index] + y * challenge
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transcript_ext::KeccakTranscript;
    use poker_protocol_core::{RistrettoCurve, Secp256k1Curve};
    use rand_core::OsRng;

    fn sample_statement<C: Curve>(
        sk: &C::Scalar,
        pk: &C::Point,
        n_fold: usize,
        n_reveal: usize,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> UnifiedStatement<C> {
        let mut fold = Vec::new();
        for _ in 0..n_fold {
            let card = C::hash_to_curve(b"unified/fold/card");
            let r = C::Scalar::random(rng);
            let in_ct = ElGamalCiphertextGeneric::encrypt(&card, pk, &r);
            // Leave: out_c2 = in_c2 − in_c1·sk.
            let out_ct = ElGamalCiphertextGeneric {
                c1: in_ct.c1,
                c2: in_ct.c2 - in_ct.c1 * sk,
            };
            fold.push(UnifiedFoldCard { in_ct, out_ct });
        }
        let mut reveal = Vec::new();
        for i in 0..n_reveal {
            let card = C::hash_to_curve(format!("unified/reveal/card/{i}").as_bytes());
            let r = C::Scalar::random(rng);
            let ct = ElGamalCiphertextGeneric::encrypt(&card, pk, &r);
            reveal.push(UnifiedRevealCard {
                token: ct.c1 * sk,
                ct,
            });
        }
        UnifiedStatement { pk: *pk, fold, reveal }
    }

    fn roundtrip<C: Curve>() {
        let sk = C::Scalar::random(&mut OsRng);
        let pk = C::base_g() * &sk;
        let statement = sample_statement::<C>(&sk, &pk, 3, 5, &mut OsRng);

        let proof = PlayerHandSigma::<C>::try_prove(
            &sk,
            &statement,
            &mut OsRng,
            &mut KeccakTranscript::new(UNIFIED_SIGMA_PROTOCOL_NAME),
        )
        .expect("prove");

        assert!(proof.verify(
            &statement,
            &mut KeccakTranscript::new(UNIFIED_SIGMA_PROTOCOL_NAME)
        ));

        // Tampered statement (one fold card swapped) must fail.
        let mut tampered = statement.clone();
        if tampered.fold.len() >= 2 {
            tampered.fold.swap(0, 1);
            assert!(!proof.verify(
                &tampered,
                &mut KeccakTranscript::new(UNIFIED_SIGMA_PROTOCOL_NAME)
            ));
        }

        // Tampered response must fail.
        let mut bad = proof.clone();
        bad.response = bad.response + C::Scalar::one();
        assert!(!bad.verify(
            &statement,
            &mut KeccakTranscript::new(UNIFIED_SIGMA_PROTOCOL_NAME)
        ));

        // Wrong transcript domain must fail.
        assert!(!proof.verify(
            &statement,
            &mut KeccakTranscript::new(b"other_protocol")
        ));
    }

    #[test]
    fn ristretto_unified_roundtrip() {
        roundtrip::<RistrettoCurve>();
    }

    #[test]
    fn secp256k1_unified_roundtrip() {
        roundtrip::<Secp256k1Curve>();
    }

    #[test]
    fn empty_sections_still_prove_ownership() {
        let sk = <Secp256k1Curve as Curve>::Scalar::random(&mut OsRng);
        let pk = Secp256k1Curve::base_g() * &sk;
        let statement = UnifiedStatement::<Secp256k1Curve> {
            pk,
            fold: vec![],
            reveal: vec![],
        };
        let proof = PlayerHandSigma::try_prove(
            &sk,
            &statement,
            &mut OsRng,
            &mut KeccakTranscript::new(UNIFIED_SIGMA_PROTOCOL_NAME),
        )
        .expect("ownership-only proves");
        assert!(proof.verify(
            &statement,
            &mut KeccakTranscript::new(UNIFIED_SIGMA_PROTOCOL_NAME)
        ));
    }
}
