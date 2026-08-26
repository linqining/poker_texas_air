//! Versioned Poseidon252 transcript statement for Reconstruction V3.
//!
//! This module specifies the protocol input to the future transcript AIR.  It
//! intentionally does **not** calculate Fiat--Shamir challenges and it does
//! not accept host-provided challenge bytes as authenticated output.  The
//! output of [`RistrettoPoseidonTranscriptStatement::absorption_words`] is a
//! canonical field-word schedule that a Poseidon252 permutation AIR must
//! consume and reproduce.
//!
//! The schedule is independent from Stwo's `Poseidon252Channel`: that channel
//! is reserved for commitment/FRI sampling and is not the protocol transcript.

#![allow(missing_docs)]

use borsh::{BorshDeserialize, BorshSerialize};
use num_bigint::BigUint;
use num_traits::Zero;
use starknet_ff::FieldElement;

use poker_protocol::precompile_abi::ReconstructionV3VerifyRequest;

use crate::canonical_reconstruction_binding::CANONICAL_RECONSTRUCTION_CARDS;
use crate::error::{TexasAirError, TexasAirResult};
use crate::hash_prover::HashProofProvider;
use crate::ristretto_reconstruction_proof_wire::{
    RISTRETTO_RECONSTRUCTION_READABLE_CARDS, RistrettoReconstructionProofEnvelope,
    reconstruction_v3_statement_digest,
};
use crate::ristretto_scalar_air::GROUP_ORDER_BYTES;

/// Domain for the V2 protocol Fiat--Shamir transcript.  Stwo's Poseidon252
/// channel is deliberately not used here; it remains an internal PCS/FRI
/// channel only.
pub const RISTRETTO_FLOCK_TRANSCRIPT_DOMAIN: &[u8] =
    b"zchain.texas.ristretto-air-v2.flock-transcript.v1";

/// A Flock-proven transcript seed and its deterministically derived challenge
/// schedule.  The message is public and binds the request statement and proof
/// commitments; the Flock chain proof authenticates the digest without
/// trusting a host-computed hash.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoFlockTranscriptProof {
    pub statement_digest: [u8; 32],
    pub component_digest: [u8; 32],
    pub message: Vec<u8>,
    pub digest: [u8; 32],
    pub hash_proof: crate::hash_prover::ArchivedHashProof,
    pub challenges: [[u8; 32]; RISTRETTO_POSEIDON_TRANSCRIPT_CHALLENGE_COUNT],
    pub retry_count: [u32; RISTRETTO_POSEIDON_TRANSCRIPT_CHALLENGE_COUNT],
}

fn flock_transcript_message(statement_digest: &[u8; 32], component_digest: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        RISTRETTO_FLOCK_TRANSCRIPT_DOMAIN.len() + statement_digest.len() + component_digest.len(),
    );
    message.extend_from_slice(RISTRETTO_FLOCK_TRANSCRIPT_DOMAIN);
    message.extend_from_slice(statement_digest);
    message.extend_from_slice(component_digest);
    message
}

fn derive_flock_challenge(digest: &[u8; 32], ordinal: usize, retry: u32) -> [u8; 32] {
    let mut input = Vec::with_capacity(32 + 8);
    input.extend_from_slice(digest);
    input.extend_from_slice(&(ordinal as u32).to_le_bytes());
    input.extend_from_slice(&retry.to_le_bytes());
    crate::blake3_flock::blake3_chain_digest(&input)
}

impl ArchivedRistrettoFlockTranscriptProof {
    pub fn prove(statement_digest: [u8; 32], component_digest: [u8; 32]) -> TexasAirResult<Self> {
        let message = flock_transcript_message(&statement_digest, &component_digest);
        let digest = crate::blake3_flock::blake3_chain_digest(&message);
        let statement = crate::hash_prover::Blake2bStatement::new(message.clone(), digest);
        let hash_proof = crate::blake3_flock::FlockProvider.prove_statements(&[statement])?;
        let modulus = BigUint::from_bytes_le(&GROUP_ORDER_BYTES);
        let mut challenges = [[0u8; 32]; RISTRETTO_POSEIDON_TRANSCRIPT_CHALLENGE_COUNT];
        let mut retry_count = [0u32; RISTRETTO_POSEIDON_TRANSCRIPT_CHALLENGE_COUNT];
        for ordinal in 0..challenges.len() {
            let mut retry = 0u32;
            loop {
                let candidate = derive_flock_challenge(&digest, ordinal, retry);
                if !BigUint::from_bytes_le(&candidate).is_zero()
                    && BigUint::from_bytes_le(&candidate) < modulus
                {
                    challenges[ordinal] = candidate;
                    retry_count[ordinal] = retry;
                    break;
                }
                retry = retry.checked_add(1).ok_or_else(|| {
                    TexasAirError::SpecViolation("Flock transcript retry overflow".into())
                })?;
            }
        }
        Ok(Self {
            statement_digest,
            component_digest,
            message,
            digest,
            hash_proof,
            challenges,
            retry_count,
        })
    }

    pub fn verify(&self) -> TexasAirResult<()> {
        let expected_message =
            flock_transcript_message(&self.statement_digest, &self.component_digest);
        if self.message != expected_message
            || self.digest != crate::blake3_flock::blake3_chain_digest(&self.message)
        {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "Flock transcript message/digest is detached".into(),
            ));
        }
        let statement =
            crate::hash_prover::Blake2bStatement::new(self.message.clone(), self.digest);
        crate::blake3_flock::FlockProvider.verify_statements(&self.hash_proof, &[statement])?;
        let modulus = BigUint::from_bytes_le(&GROUP_ORDER_BYTES);
        for ordinal in 0..self.challenges.len() {
            let retry = self.retry_count[ordinal];
            if retry > RISTRETTO_POSEIDON_TRANSCRIPT_MAX_RETRIES {
                return Err(TexasAirError::SpecViolation(
                    "Flock transcript retry count exceeds the fixed bound".into(),
                ));
            }
            let expected = derive_flock_challenge(&self.digest, ordinal, retry);
            if self.challenges[ordinal] != expected
                || BigUint::from_bytes_le(&expected).is_zero()
                || BigUint::from_bytes_le(&expected) >= modulus
            {
                return Err(TexasAirError::ConstraintUnsatisfied(
                    "Flock transcript challenge schedule is detached".into(),
                ));
            }
        }
        Ok(())
    }

    pub fn as_poseidon_compat(&self) -> RistrettoPoseidonTranscriptChallenges {
        RistrettoPoseidonTranscriptChallenges {
            statement_digest: self.statement_digest,
            challenge: self.challenges,
            retry_count: self.retry_count,
        }
    }
}

pub const RISTRETTO_POSEIDON_TRANSCRIPT_ABI_VERSION: u8 = 1;
pub const RISTRETTO_POSEIDON_TRANSCRIPT_DOMAIN: &[u8] =
    b"zchain.texas.ristretto-reconstruction-v3.poseidon252.transcript.v1";
pub const RISTRETTO_POSEIDON_TRANSCRIPT_CHALLENGE_COUNT: usize =
    RISTRETTO_RECONSTRUCTION_READABLE_CARDS + CANONICAL_RECONSTRUCTION_CARDS;
/// A retry counter is part of the authenticated transcript boundary.  A
/// bounded value keeps malformed archives from creating an unbounded sponge
/// trace while still making the probability of exhausting the bound
/// negligible for a 252-bit squeeze.
pub const RISTRETTO_POSEIDON_TRANSCRIPT_MAX_RETRIES: u32 = 1024;
const BYTES_PER_FIELD_WORD: usize = 16;
/// Starknet Poseidon252 absorbs two field words per permutation.
pub const RISTRETTO_POSEIDON_TRANSCRIPT_RATE: u8 = 2;

/// The relation which consumes one protocol challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RistrettoTranscriptChallengeKind {
    CrossKey,
    SlotOr,
}

/// One contiguous sponge-absorption segment. A transcript AIR must absorb
/// every word in order, execute a challenge squeeze immediately after a
/// `*Challenge` segment, and execute no squeeze after the initial or shuffle
/// segments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RistrettoPoseidonTranscriptStepKind {
    Initial,
    CrossKeyChallenge { index: u8 },
    Shuffle,
    SlotOrChallenge { slot: u8 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RistrettoPoseidonTranscriptAbsorptionStep {
    pub kind: RistrettoPoseidonTranscriptStepKind,
    pub words: Vec<FieldElement>,
}

/// One fully specified operation for the future rate-two Poseidon252 sponge
/// AIR.  `Permute` follows every full pair of absorbed words.  A `Squeeze`
/// absorbs standard Starknet one-padding in `padding_lane`, performs exactly
/// one permutation, exposes state lane zero as the challenge candidate, and
/// restarts absorption at lane zero.
///
/// This intentionally describes the permutation boundary rather than
/// calculating it natively.  The AIR must constrain all 91 Poseidon rounds
/// for every `Permute` and `Squeeze` operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RistrettoPoseidonTranscriptSpongeOp {
    Absorb {
        lane: u8,
        word: FieldElement,
    },
    Permute,
    Squeeze {
        kind: RistrettoTranscriptChallengeKind,
        index: u8,
        padding_lane: u8,
    },
}

impl RistrettoTranscriptChallengeKind {
    pub const fn ordinal(self, index: usize) -> usize {
        match self {
            Self::CrossKey => index,
            Self::SlotOr => RISTRETTO_RECONSTRUCTION_READABLE_CARDS + index,
        }
    }
}

/// A typed challenge output boundary.  `challenge` and `retry_count` are
/// witness fields for the future transcript AIR, not verifier-authenticated
/// values by themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RistrettoPoseidonTranscriptChallenges {
    pub statement_digest: [u8; 32],
    pub challenge: [[u8; 32]; RISTRETTO_POSEIDON_TRANSCRIPT_CHALLENGE_COUNT],
    pub retry_count: [u32; RISTRETTO_POSEIDON_TRANSCRIPT_CHALLENGE_COUNT],
}

impl RistrettoPoseidonTranscriptChallenges {
    /// Validate the typed output boundary before relation AIRs consume it.
    ///
    /// This does not authenticate the challenges: only a future Poseidon252
    /// transcript AIR can do that.  It does ensure that a malformed or
    /// detached challenge archive cannot reach the scalar/equation AIRs.
    pub fn validate_for_statement(&self, statement_digest: [u8; 32]) -> TexasAirResult<()> {
        if self.statement_digest != statement_digest {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "Poseidon transcript challenges are detached from the statement".into(),
            ));
        }
        let group_order = BigUint::from_bytes_le(&GROUP_ORDER_BYTES);
        for ordinal in 0..RISTRETTO_POSEIDON_TRANSCRIPT_CHALLENGE_COUNT {
            if self.retry_count[ordinal] > RISTRETTO_POSEIDON_TRANSCRIPT_MAX_RETRIES {
                return Err(TexasAirError::SpecViolation(
                    "Poseidon transcript retry count exceeds the fixed bound".into(),
                ));
            }
            let challenge = BigUint::from_bytes_le(&self.challenge[ordinal]);
            if challenge.is_zero() || challenge >= group_order {
                return Err(TexasAirError::SpecViolation(
                    "Poseidon transcript challenge is not a non-zero canonical scalar".into(),
                ));
            }
        }
        Ok(())
    }

    /// Return the challenge for one fixed schedule position after validating
    /// the archive shape and statement binding.
    pub fn challenge_for(
        &self,
        statement_digest: [u8; 32],
        kind: RistrettoTranscriptChallengeKind,
        index: usize,
    ) -> TexasAirResult<[u8; 32]> {
        self.validate_for_statement(statement_digest)?;
        let ordinal = match kind {
            RistrettoTranscriptChallengeKind::CrossKey
                if index < RISTRETTO_RECONSTRUCTION_READABLE_CARDS =>
            {
                index
            }
            RistrettoTranscriptChallengeKind::SlotOr if index < CANONICAL_RECONSTRUCTION_CARDS => {
                RISTRETTO_RECONSTRUCTION_READABLE_CARDS + index
            }
            _ => RISTRETTO_POSEIDON_TRANSCRIPT_CHALLENGE_COUNT,
        };
        if ordinal >= RISTRETTO_POSEIDON_TRANSCRIPT_CHALLENGE_COUNT {
            return Err(TexasAirError::SpecViolation(
                "Poseidon transcript challenge selector is outside the fixed schedule".into(),
            ));
        }
        Ok(self.challenge[ordinal])
    }
}

/// Validate a relation-specific challenge output at the transcript boundary.
/// Relation archives use this helper because their compact typed structs carry
/// only the subset of the full 54-slot output they consume.
pub fn validate_relation_challenges(
    statement_digest: [u8; 32],
    expected_statement_digest: [u8; 32],
    challenges: &[[u8; 32]],
) -> TexasAirResult<()> {
    if statement_digest != expected_statement_digest {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "relation transcript challenges are detached from the statement".into(),
        ));
    }
    let group_order = BigUint::from_bytes_le(&GROUP_ORDER_BYTES);
    for challenge in challenges {
        let value = BigUint::from_bytes_le(challenge);
        if value.is_zero() || value >= group_order {
            return Err(TexasAirError::SpecViolation(
                "relation transcript challenge is not a non-zero canonical scalar".into(),
            ));
        }
    }
    Ok(())
}

/// Canonical protocol transcript statement and absorption schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RistrettoPoseidonTranscriptStatement {
    pub statement_digest: [u8; 32],
    /// Exact request statement encoded as canonical field words.  This is
    /// retained alongside `statement_digest` so the future AIR can bind every
    /// byte without relying on a native Blake2b digest calculation.
    pub request_words: Vec<FieldElement>,
    pub envelope: RistrettoReconstructionProofEnvelope,
}

impl RistrettoPoseidonTranscriptStatement {
    pub fn from_request(request: &ReconstructionV3VerifyRequest) -> TexasAirResult<Self> {
        let envelope = crate::ristretto_reconstruction_proof_wire::
            validate_ristretto_reconstruction_proof_wire(request)?;
        let statement_digest = reconstruction_v3_statement_digest(request)?;
        if envelope.statement_digest != statement_digest {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "Poseidon transcript statement digest is detached from request".into(),
            ));
        }
        Ok(Self {
            statement_digest,
            request_words: request_absorption_words(request)?,
            envelope,
        })
    }

    /// Return the exact relation/challenge order.  Every producer and every
    /// future verifier must use this order; a permutation is a transcript
    /// binding failure, not a recoverable decoding difference.
    pub fn challenge_schedule()
    -> [(RistrettoTranscriptChallengeKind, usize); RISTRETTO_POSEIDON_TRANSCRIPT_CHALLENGE_COUNT]
    {
        std::array::from_fn(|ordinal| {
            if ordinal < RISTRETTO_RECONSTRUCTION_READABLE_CARDS {
                (RistrettoTranscriptChallengeKind::CrossKey, ordinal)
            } else {
                (
                    RistrettoTranscriptChallengeKind::SlotOr,
                    ordinal - RISTRETTO_RECONSTRUCTION_READABLE_CARDS,
                )
            }
        })
    }

    /// Build the exact sponge segments and challenge-squeeze boundaries.
    ///
    /// Each byte string is length-prefixed and split into 16-byte little-endian
    /// chunks, so no input byte is silently reduced modulo the Poseidon field.
    /// The chunk size is below the 252-bit field capacity.
    pub fn absorption_steps(
        &self,
    ) -> TexasAirResult<Vec<RistrettoPoseidonTranscriptAbsorptionStep>> {
        let mut words = Vec::new();
        absorb_bytes(&mut words, RISTRETTO_POSEIDON_TRANSCRIPT_DOMAIN, b"domain")?;
        absorb_u64(
            &mut words,
            u64::from(RISTRETTO_POSEIDON_TRANSCRIPT_ABI_VERSION),
        );
        absorb_bytes(&mut words, &self.statement_digest, b"statement_digest")?;
        words.extend_from_slice(&self.request_words);
        let mut steps = vec![RistrettoPoseidonTranscriptAbsorptionStep {
            kind: RistrettoPoseidonTranscriptStepKind::Initial,
            words,
        }];

        // Responses are deliberately excluded from the cross-key and slot-OR
        // prefixes, matching Fiat--Shamir's commit-then-challenge order.
        for index in 0..RISTRETTO_RECONSTRUCTION_READABLE_CARDS {
            let mut words = Vec::new();
            let negative = self.envelope.negative_contributions[index];
            let proof = self.envelope.cross_key_proofs[index];
            absorb_u64(
                &mut words,
                RistrettoTranscriptChallengeKind::CrossKey.ordinal(index) as u64,
            );
            absorb_bytes(&mut words, &negative.c1, b"cross_key.negative.c1")?;
            absorb_bytes(&mut words, &negative.c2, b"cross_key.negative.c2")?;
            absorb_bytes(
                &mut words,
                &proof.commitment_owner_key,
                b"cross_key.commitment.owner",
            )?;
            absorb_bytes(
                &mut words,
                &proof.commitment_contribution_c1,
                b"cross_key.commitment.c1",
            )?;
            absorb_bytes(
                &mut words,
                &proof.commitment_joint_c2,
                b"cross_key.commitment.c2",
            )?;
            steps.push(RistrettoPoseidonTranscriptAbsorptionStep {
                kind: RistrettoPoseidonTranscriptStepKind::CrossKeyChallenge {
                    index: u8::try_from(index).expect("fixed readable-card count fits in u8"),
                },
                words,
            });
        }

        // Cross-key challenges precede the shuffle in the protocol.  The full
        // shuffle wire is then absorbed before every slot challenge so the
        // slot-OR relations cannot be spliced across a different shuffle.
        let mut words = Vec::new();
        absorb_bytes(
            &mut words,
            &borsh::to_vec(&self.envelope.shuffle_proof)
                .map_err(|error| TexasAirError::SerializationError(error.to_string()))?,
            b"shuffle_proof_wire",
        )?;
        steps.push(RistrettoPoseidonTranscriptAbsorptionStep {
            kind: RistrettoPoseidonTranscriptStepKind::Shuffle,
            words,
        });

        for index in 0..CANONICAL_RECONSTRUCTION_CARDS {
            let mut words = Vec::new();
            let proof = self.envelope.slot_or_proofs[index];
            absorb_u64(
                &mut words,
                RistrettoTranscriptChallengeKind::SlotOr.ordinal(index) as u64,
            );
            // Card and contribution bytes are in the request statement digest;
            // the fixed slot ordinal and all six Sigma commitments are not.
            for (label, point) in [
                (b"slot_or.commitment_g.0".as_slice(), &proof.commitment_g[0]),
                (b"slot_or.commitment_g.1".as_slice(), &proof.commitment_g[1]),
                (
                    b"slot_or.commitment_pk.0".as_slice(),
                    &proof.commitment_pk[0],
                ),
                (
                    b"slot_or.commitment_pk.1".as_slice(),
                    &proof.commitment_pk[1],
                ),
            ] {
                absorb_bytes(&mut words, point, label)?;
            }
            steps.push(RistrettoPoseidonTranscriptAbsorptionStep {
                kind: RistrettoPoseidonTranscriptStepKind::SlotOrChallenge {
                    slot: u8::try_from(index).expect("fixed deck size fits in u8"),
                },
                words,
            });
        }
        Ok(steps)
    }

    /// Flatten the segments for callers which only need a commitment to the
    /// full public input. Transcript AIR implementations must use
    /// [`Self::absorption_steps`] instead so challenge squeeze boundaries are
    /// retained.
    pub fn absorption_words(&self) -> TexasAirResult<Vec<FieldElement>> {
        Ok(self
            .absorption_steps()?
            .into_iter()
            .flat_map(|step| step.words)
            .collect())
    }

    /// Expand the absorption steps into the exact rate-two sponge schedule.
    ///
    /// This fixes two details which must not be left to the prover: a full
    /// rate block is permuted before the next word, and every challenge uses a
    /// `+1` finalization word in the current rate lane before its squeeze
    /// permutation.  The challenge candidate is state lane zero after that
    /// permutation.  Future nonzero retries append
    /// [`retry_absorption_words`] at the same point and execute another
    /// `Squeeze` with the identical challenge selector.
    pub fn sponge_operations(&self) -> TexasAirResult<Vec<RistrettoPoseidonTranscriptSpongeOp>> {
        let mut operations = Vec::new();
        let mut lane = 0u8;
        for step in self.absorption_steps()? {
            for word in step.words {
                operations.push(RistrettoPoseidonTranscriptSpongeOp::Absorb { lane, word });
                lane += 1;
                if lane == RISTRETTO_POSEIDON_TRANSCRIPT_RATE {
                    operations.push(RistrettoPoseidonTranscriptSpongeOp::Permute);
                    lane = 0;
                }
            }
            match step.kind {
                RistrettoPoseidonTranscriptStepKind::Initial
                | RistrettoPoseidonTranscriptStepKind::Shuffle => {}
                RistrettoPoseidonTranscriptStepKind::CrossKeyChallenge { index } => {
                    operations.push(RistrettoPoseidonTranscriptSpongeOp::Squeeze {
                        kind: RistrettoTranscriptChallengeKind::CrossKey,
                        index,
                        padding_lane: lane,
                    });
                    lane = 0;
                }
                RistrettoPoseidonTranscriptStepKind::SlotOrChallenge { slot } => {
                    operations.push(RistrettoPoseidonTranscriptSpongeOp::Squeeze {
                        kind: RistrettoTranscriptChallengeKind::SlotOr,
                        index: slot,
                        padding_lane: lane,
                    });
                    lane = 0;
                }
            }
        }
        Ok(operations)
    }
}

/// Canonical absorption following a zero challenge squeeze. `retry` is the
/// one-based retry number, so the first zero result is followed by retry `1`.
/// The transcript AIR must prove that every preceding candidate was zero,
/// derive the final scalar by reduction modulo the Ristretto group order, and
/// prove that the accepted candidate is nonzero.
pub fn retry_absorption_words(
    kind: RistrettoTranscriptChallengeKind,
    index: usize,
    retry: u32,
) -> TexasAirResult<Vec<FieldElement>> {
    if retry == 0
        || match kind {
            RistrettoTranscriptChallengeKind::CrossKey => {
                index >= RISTRETTO_RECONSTRUCTION_READABLE_CARDS
            }
            RistrettoTranscriptChallengeKind::SlotOr => index >= CANONICAL_RECONSTRUCTION_CARDS,
        }
    {
        return Err(TexasAirError::SpecViolation(
            "Poseidon transcript retry selector is outside the fixed challenge schedule".into(),
        ));
    }
    let mut words = Vec::new();
    absorb_bytes(&mut words, b"challenge_nonzero_retry", b"retry.label")?;
    absorb_u64(
        &mut words,
        match kind {
            RistrettoTranscriptChallengeKind::CrossKey => 0,
            RistrettoTranscriptChallengeKind::SlotOr => 1,
        },
    );
    absorb_u64(
        &mut words,
        u64::try_from(index)
            .map_err(|_| TexasAirError::SpecViolation("retry index overflows u64".into()))?,
    );
    absorb_u64(&mut words, u64::from(retry));
    Ok(words)
}

fn request_absorption_words(
    request: &ReconstructionV3VerifyRequest,
) -> TexasAirResult<Vec<FieldElement>> {
    request.validate().map_err(|error| {
        TexasAirError::SpecViolation(format!("invalid Reconstruction V3 request: {error}"))
    })?;
    let mut words = Vec::new();
    absorb_bytes(
        &mut words,
        &[
            request.curve as u8,
            request.proof_system as u8,
            request.transcript as u8,
            request.statement_version,
        ],
        b"request.header",
    )?;
    absorb_u64(&mut words, request.reconstruction_epoch);
    absorb_bytes(
        &mut words,
        &request.context_digest,
        b"request.context_digest",
    )?;
    absorb_bytes(
        &mut words,
        &request.prior_state_digest,
        b"request.prior_state_digest",
    )?;
    absorb_bytes(&mut words, &request.context, b"request.context")?;
    absorb_bytes(&mut words, &request.call_context, b"request.call_context")?;
    absorb_bytes(&mut words, &request.aggregate_pk, b"request.aggregate_pk")?;
    absorb_bytes(&mut words, &request.owner_pk, b"request.owner_pk")?;
    absorb_u64(
        &mut words,
        u64::try_from(request.cards.len())
            .map_err(|_| TexasAirError::SpecViolation("request card count overflows u64".into()))?,
    );
    for card in &request.cards {
        absorb_bytes(&mut words, card, b"request.card")?;
    }
    absorb_u64(
        &mut words,
        u64::try_from(request.user_readable_cards.len()).map_err(|_| {
            TexasAirError::SpecViolation("request readable-card count overflows u64".into())
        })?,
    );
    for ciphertext in &request.user_readable_cards {
        absorb_bytes(&mut words, &ciphertext.c1, b"request.readable.c1")?;
        absorb_bytes(&mut words, &ciphertext.c2, b"request.readable.c2")?;
    }
    absorb_u64(
        &mut words,
        u64::try_from(request.contributions.len()).map_err(|_| {
            TexasAirError::SpecViolation("request contribution count overflows u64".into())
        })?,
    );
    for ciphertext in &request.contributions {
        absorb_bytes(&mut words, &ciphertext.c1, b"request.contribution.c1")?;
        absorb_bytes(&mut words, &ciphertext.c2, b"request.contribution.c2")?;
    }
    Ok(words)
}

fn absorb_u64(words: &mut Vec<FieldElement>, value: u64) {
    words.push(FieldElement::from(value));
}

fn absorb_bytes(words: &mut Vec<FieldElement>, bytes: &[u8], label: &[u8]) -> TexasAirResult<()> {
    // Labels and lengths are protocol data, not host-side metadata. Keeping
    // both in the field schedule prevents concatenation and role splices.
    absorb_raw(words, label)?;
    let length = u64::try_from(bytes.len())
        .map_err(|_| TexasAirError::SpecViolation("transcript field input too large".into()))?;
    absorb_u64(words, length);
    for chunk in bytes.chunks(BYTES_PER_FIELD_WORD) {
        let mut encoded = [0u8; 32];
        for (destination, source) in encoded[32 - chunk.len()..]
            .iter_mut()
            .zip(chunk.iter().rev())
        {
            *destination = *source;
        }
        words.push(FieldElement::from_bytes_be(&encoded).map_err(|_| {
            TexasAirError::SpecViolation(
                "transcript byte chunk is not a canonical field word".into(),
            )
        })?);
    }
    Ok(())
}

fn absorb_raw(words: &mut Vec<FieldElement>, bytes: &[u8]) -> TexasAirResult<()> {
    let length = u64::try_from(bytes.len())
        .map_err(|_| TexasAirError::SpecViolation("transcript label too large".into()))?;
    absorb_u64(words, length);
    for chunk in bytes.chunks(BYTES_PER_FIELD_WORD) {
        let mut encoded = [0u8; 32];
        for (destination, source) in encoded[32 - chunk.len()..]
            .iter_mut()
            .zip(chunk.iter().rev())
        {
            *destination = *source;
        }
        words.push(FieldElement::from_bytes_be(&encoded).map_err(|_| {
            TexasAirError::SpecViolation("transcript label is not a canonical field word".into())
        })?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ristretto_reconstruction_proof_wire::{
        RistrettoBayerGrothShuffleProofWire, RistrettoCiphertextProofWire,
        RistrettoCrossKeyProofWire, RistrettoSlotOrProofWire,
    };
    use poker_protocol::precompile_abi::{
        CurveId, EncodedCiphertext, ReconstructionProofSystem, TranscriptId,
    };

    fn request() -> ReconstructionV3VerifyRequest {
        ReconstructionV3VerifyRequest {
            curve: CurveId::Ristretto255,
            proof_system: ReconstructionProofSystem::RistrettoAirV1,
            transcript: TranscriptId::Poseidon252,
            context: b"zk_reconstruct_proof_v3".to_vec(),
            call_context: vec![7; 32],
            statement_version: 3,
            context_digest: [1; 32],
            reconstruction_epoch: 9,
            prior_state_digest: [2; 32],
            aggregate_pk: vec![3; 32],
            owner_pk: vec![4; 32],
            cards: vec![vec![5; 32]; CANONICAL_RECONSTRUCTION_CARDS],
            user_readable_cards: vec![
                EncodedCiphertext {
                    c1: vec![6; 32],
                    c2: vec![7; 32]
                };
                2
            ],
            contributions: vec![
                EncodedCiphertext {
                    c1: vec![8; 32],
                    c2: vec![9; 32]
                };
                CANONICAL_RECONSTRUCTION_CARDS
            ],
            proof: vec![1],
        }
    }

    fn envelope(request: &ReconstructionV3VerifyRequest) -> RistrettoReconstructionProofEnvelope {
        RistrettoReconstructionProofEnvelope::from_components(
            request,
            [RistrettoCiphertextProofWire {
                c1: [0xA0; 32],
                c2: [0xA1; 32],
            }; 2],
            RistrettoBayerGrothShuffleProofWire::default(),
            [RistrettoCrossKeyProofWire::default(); 2],
            [RistrettoSlotOrProofWire::default(); CANONICAL_RECONSTRUCTION_CARDS],
        )
        .unwrap()
    }

    #[test]
    fn schedule_is_fixed_and_ordered() {
        let schedule = RistrettoPoseidonTranscriptStatement::challenge_schedule();
        assert_eq!(schedule.len(), 54);
        assert!(
            schedule[..2]
                .iter()
                .enumerate()
                .all(
                    |(i, (kind, index))| *kind == RistrettoTranscriptChallengeKind::CrossKey
                        && *index == i
                )
        );

        assert!(retry_absorption_words(RistrettoTranscriptChallengeKind::CrossKey, 2, 1).is_err());
        assert!(retry_absorption_words(RistrettoTranscriptChallengeKind::SlotOr, 52, 1).is_err());
        assert!(retry_absorption_words(RistrettoTranscriptChallengeKind::SlotOr, 51, 0).is_err());
        assert!(
            !retry_absorption_words(RistrettoTranscriptChallengeKind::SlotOr, 51, 1)
                .unwrap()
                .is_empty()
        );
        assert!(
            schedule[2..]
                .iter()
                .enumerate()
                .all(
                    |(i, (kind, index))| *kind == RistrettoTranscriptChallengeKind::SlotOr
                        && *index == i
                )
        );
    }

    #[test]
    fn flock_transcript_roundtrip_is_statement_bound() {
        let proof = ArchivedRistrettoFlockTranscriptProof::prove([7; 32], [9; 32])
            .expect("Flock transcript proof");
        proof.verify().expect("Flock transcript verifies");
        let mut tampered = proof.clone();
        tampered.component_digest[0] ^= 1;
        assert!(tampered.verify().is_err());
    }

    #[test]
    fn absorption_is_deterministic_and_commitment_bound() {
        let mut req = request();
        let wire = envelope(&req).encode_wire().unwrap();
        req.proof = wire;
        let statement = RistrettoPoseidonTranscriptStatement::from_request(&req).unwrap();
        let first = statement.absorption_words().unwrap();
        assert!(!first.is_empty());
        assert_eq!(first, statement.absorption_words().unwrap());
        let steps = statement.absorption_steps().unwrap();
        assert_eq!(steps.len(), 56);
        assert_eq!(steps[0].kind, RistrettoPoseidonTranscriptStepKind::Initial);
        assert_eq!(
            steps[1].kind,
            RistrettoPoseidonTranscriptStepKind::CrossKeyChallenge { index: 0 }
        );
        assert_eq!(steps[3].kind, RistrettoPoseidonTranscriptStepKind::Shuffle);
        assert_eq!(
            steps[4].kind,
            RistrettoPoseidonTranscriptStepKind::SlotOrChallenge { slot: 0 }
        );

        let mut changed_request = request();
        let mut changed_envelope = envelope(&changed_request);
        changed_envelope.slot_or_proofs[0].commitment_g[0][0] ^= 1;
        changed_envelope = RistrettoReconstructionProofEnvelope::from_components(
            &changed_request,
            changed_envelope.negative_contributions,
            changed_envelope.shuffle_proof,
            changed_envelope.cross_key_proofs,
            changed_envelope.slot_or_proofs,
        )
        .unwrap();
        changed_request.proof = changed_envelope.encode_wire().unwrap();
        let changed = RistrettoPoseidonTranscriptStatement::from_request(&changed_request).unwrap();
        assert_ne!(first, changed.absorption_words().unwrap());
    }

    #[test]
    fn challenge_boundary_rejects_detached_zero_noncanonical_and_unbounded_outputs() {
        let digest = [9u8; 32];
        let mut challenges = [[0u8; 32]; RISTRETTO_POSEIDON_TRANSCRIPT_CHALLENGE_COUNT];
        challenges.fill({
            let mut value = [0u8; 32];
            value[0] = 7;
            value
        });
        let mut output = RistrettoPoseidonTranscriptChallenges {
            statement_digest: digest,
            challenge: challenges,
            retry_count: [0; RISTRETTO_POSEIDON_TRANSCRIPT_CHALLENGE_COUNT],
        };
        output.validate_for_statement(digest).unwrap();
        assert!(output.validate_for_statement([8u8; 32]).is_err());

        output.challenge[0] = [0; 32];
        assert!(output.validate_for_statement(digest).is_err());
        output.challenge[0][0] = 7;
        output.retry_count[0] = RISTRETTO_POSEIDON_TRANSCRIPT_MAX_RETRIES + 1;
        assert!(output.validate_for_statement(digest).is_err());
    }

    #[test]
    fn relation_selector_cannot_escape_fixed_schedule() {
        let digest = [1u8; 32];
        let challenge = [[3u8; 32], [5u8; 32]];
        validate_relation_challenges(digest, digest, &challenge).unwrap();
        assert!(validate_relation_challenges([2u8; 32], digest, &challenge).is_err());
        assert!(validate_relation_challenges(digest, digest, &[[0u8; 32]]).is_err());
    }

    #[test]
    fn full_output_projects_to_relation_specific_fixed_orders() {
        let digest = [4u8; 32];
        let mut challenge = [[0u8; 32]; RISTRETTO_POSEIDON_TRANSCRIPT_CHALLENGE_COUNT];
        for (index, value) in challenge.iter_mut().enumerate() {
            value[0] = u8::try_from(index + 1).unwrap();
        }
        let output = RistrettoPoseidonTranscriptChallenges {
            statement_digest: digest,
            challenge,
            retry_count: [0; RISTRETTO_POSEIDON_TRANSCRIPT_CHALLENGE_COUNT],
        };
        let cross = crate::ristretto_reconstruction_relation_air::
            RistrettoCrossKeyTranscriptChallenges::from_poseidon_output(&output, digest)
            .unwrap();
        assert_eq!(cross.challenges[0][0], 1);
        assert_eq!(cross.challenges[1][0], 2);
        let slot = crate::ristretto_reconstruction_slot_or_air::
            RistrettoSlotOrTranscriptChallenges::from_poseidon_output(&output, digest)
            .unwrap();
        assert_eq!(slot.global_challenges[0][0], 3);
        assert_eq!(slot.global_challenges[51][0], 54);
    }

    #[test]
    fn canonical_reference_vector_preserves_absorption_boundaries() {
        let mut req = request();
        req.proof = envelope(&req).encode_wire().unwrap();
        let statement = RistrettoPoseidonTranscriptStatement::from_request(&req).unwrap();
        let steps = statement.absorption_steps().unwrap();
        let flattened_len: usize = steps.iter().map(|step| step.words.len()).sum();

        // These are ABI vector anchors, not a native Poseidon result.  They
        // make changes to labels, chunking, and challenge boundaries visible
        // without turning a host hash into an AIR credential.
        assert_eq!(steps.len(), 56);
        assert_eq!(steps[0].words[0], FieldElement::from(6u64));
        assert_eq!(
            steps[0].words[1],
            FieldElement::from_hex_be("0x6e69616d6f64").unwrap()
        );
        assert_eq!(steps[1].words[0], FieldElement::from(0u64));
        assert_eq!(steps[1].words[1], FieldElement::from(21u64));
        assert!(flattened_len > steps[0].words.len());
        let retry =
            retry_absorption_words(RistrettoTranscriptChallengeKind::SlotOr, 51, 1).unwrap();
        assert_eq!(retry[0], FieldElement::from(11u64));
        assert_eq!(retry[2], FieldElement::from(23u64));
        assert_eq!(retry[5], FieldElement::from(1u64));
        assert_eq!(retry[6], FieldElement::from(51u64));
        assert_eq!(retry[7], FieldElement::from(1u64));
    }

    #[test]
    fn sponge_schedule_has_exact_challenge_squeeze_boundaries() {
        let mut req = request();
        req.proof = envelope(&req).encode_wire().unwrap();
        let statement = RistrettoPoseidonTranscriptStatement::from_request(&req).unwrap();
        let operations = statement.sponge_operations().unwrap();
        assert!(matches!(
            operations.first(),
            Some(RistrettoPoseidonTranscriptSpongeOp::Absorb { lane: 0, .. })
        ));
        let squeezes = operations
            .iter()
            .filter_map(|op| match op {
                RistrettoPoseidonTranscriptSpongeOp::Squeeze { kind, index, .. } => {
                    Some((*kind, *index))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            squeezes.len(),
            RISTRETTO_POSEIDON_TRANSCRIPT_CHALLENGE_COUNT
        );
        assert_eq!(squeezes[0], (RistrettoTranscriptChallengeKind::CrossKey, 0));
        assert_eq!(squeezes[1], (RistrettoTranscriptChallengeKind::CrossKey, 1));
        assert_eq!(squeezes[2], (RistrettoTranscriptChallengeKind::SlotOr, 0));
        assert_eq!(squeezes[53], (RistrettoTranscriptChallengeKind::SlotOr, 51));
        assert!(operations.iter().all(|op| match op {
            RistrettoPoseidonTranscriptSpongeOp::Absorb { lane, .. } => {
                *lane < RISTRETTO_POSEIDON_TRANSCRIPT_RATE
            }
            RistrettoPoseidonTranscriptSpongeOp::Squeeze { padding_lane, .. } => {
                *padding_lane < RISTRETTO_POSEIDON_TRANSCRIPT_RATE
            }
            RistrettoPoseidonTranscriptSpongeOp::Permute => true,
        }));
    }
}
