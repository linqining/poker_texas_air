//! Shared batched DLEQ proof used by remask and leave.
//!
//! Public statement: two non-empty, equal-length ciphertext vectors and the
//! registered player public key. Private witness: one non-zero player secret
//! key shared by every slot. The verifier checks valid input/output
//! ciphertexts, exact `c1` invariance, `pk = sk * G`, and for every slot
//! `d2[i] = sk * input[i].c1`, with the sign of `d2` selected by the operation.
//!
//! The interactive protocol has perfect completeness, special soundness and
//! perfect HVZK. Rust applies Fiat--Shamir over all statement fields,
//! commitments, derived `d2` values and the nonce. Replay protection across
//! games/epochs remains the caller's responsibility unless the outer
//! transcript already binds that context.

use crate::transcript_ext::CryptoTranscript;
use poker_protocol_core::{Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric};
use rand_core::OsRng;
use std::marker::PhantomData;

/// Labels used in the Merlin transcript for DLEq proof generation/verification.
pub struct DLEqProofLabels {
    pub pk: &'static [u8],
    pub input_c1: &'static [u8],
    pub input_c2: &'static [u8],
    pub output_c1: &'static [u8],
    pub output_c2: &'static [u8],
    pub per_card_commitment: &'static [u8],
    pub commitment_pk: &'static [u8],
    pub d2: &'static [u8],
    pub nonce: &'static [u8],
    pub challenge: &'static [u8],
}

/// Trait distinguishing different DLEq proof kinds (remask vs leave).
///
/// Each kind provides its own transcript labels and d2 computation direction:
/// - Remask: d2 = output.c2 - input.c2 (adds encryption layer)
/// - Leave:  d2 = input.c2 - output.c2 (removes encryption layer)
pub trait DLEqProofKind<C: Curve> {
    /// Transcript labels for this proof kind.
    fn labels() -> &'static DLEqProofLabels;

    /// Compute the d2 value from input and output ciphertext c2 components.
    fn compute_d2(input_c2: &C::Point, output_c2: &C::Point) -> C::Point;

    /// Whether verification validates output ciphertexts. Both strict Rust
    /// proof kinds return `true`; the hook remains for wire compatibility.
    fn validates_output_ciphertexts() -> bool;
}

/// Marker type for remask DLEq proofs.
#[derive(Debug, Clone, Copy)]
pub struct RemaskKind;

/// Marker type for leave DLEq proofs.
#[derive(Debug, Clone, Copy)]
pub struct LeaveKind;

impl<C: Curve> DLEqProofKind<C> for RemaskKind {
    fn labels() -> &'static DLEqProofLabels {
        static LABELS: DLEqProofLabels = DLEqProofLabels {
            pk: b"remask_pk",
            input_c1: b"remask_input_c1",
            input_c2: b"remask_input_c2",
            output_c1: b"remask_output_c1",
            output_c2: b"remask_output_c2",
            per_card_commitment: b"remask_per_card_commitment",
            commitment_pk: b"remask_commitment_pk",
            d2: b"remask_d2",
            nonce: b"remask_nonce",
            challenge: b"remask_challenge",
        };
        &LABELS
    }

    fn compute_d2(input_c2: &C::Point, output_c2: &C::Point) -> C::Point {
        *output_c2 - *input_c2
    }

    fn validates_output_ciphertexts() -> bool {
        true
    }
}

impl<C: Curve> DLEqProofKind<C> for LeaveKind {
    fn labels() -> &'static DLEqProofLabels {
        static LABELS: DLEqProofLabels = DLEqProofLabels {
            pk: b"leave_pk",
            input_c1: b"leave_input_c1",
            input_c2: b"leave_input_c2",
            output_c1: b"leave_output_c1",
            output_c2: b"leave_output_c2",
            per_card_commitment: b"leave_per_card_commitment",
            commitment_pk: b"leave_commitment_pk",
            d2: b"leave_d2",
            nonce: b"leave_nonce",
            challenge: b"leave_challenge",
        };
        &LABELS
    }

    fn compute_d2(input_c2: &C::Point, output_c2: &C::Point) -> C::Point {
        *input_c2 - *output_c2
    }

    fn validates_output_ciphertexts() -> bool {
        // Rust verification is intentionally stricter than the legacy Move
        // verifier: a leave result is still an ElGamal ciphertext and both of
        // its components must be non-identity.
        true
    }
}

/// Generic per-card DLEq proof structure.
///
/// Parameterized by curve type `C` and proof kind `K` (RemaskKind or LeaveKind).
/// The proof kind determines the transcript labels and the direction of the
/// d2 computation (output - input for remask, input - output for leave).
#[derive(Debug, Clone)]
pub struct DLEqProof<C: Curve, K: DLEqProofKind<C>> {
    /// Per-card DLEq commitments: A_i = input_cts[i].c1 * ω
    /// These bind each card individually, preventing aggregate-only attacks
    /// where a malicious prover modifies pairs of output cards while
    /// preserving the aggregate relationship.
    pub per_card_commitments: Vec<C::Point>,
    /// Commitment for pk DLEq: B = G * ω
    pub commitment_pk: C::Point,
    /// Single response: s = ω + c * sk (shared witness across all cards)
    pub response: C::Scalar,
    /// Nonce for uniqueness
    pub nonce: C::Scalar,
    _kind: PhantomData<K>,
}

/// Append the DLEq proof context to the transcript and derive the challenge scalar.
///
/// Shared between [`DLEqProof::prove`] and [`DLEqProof::verify`] to guarantee both
/// sides append identical bytes in identical order. Any divergence between the two
/// would silently break soundness (the prover and verifier would derive different
/// challenges without any compile-time or runtime error).
///
/// Appends, in order: `player_pk`, per-card input `c1`/`c2`, per-card output
/// `c1`/`c2`, per-card commitments, `commitment_pk`, per-card `d2` values, `nonce`.
/// Then derives and returns the challenge scalar.
fn append_dleq_context<C, K>(
    transcript: &mut impl CryptoTranscript,
    input_cts: &[ElGamalCiphertextGeneric<C>],
    output_cts: &[ElGamalCiphertextGeneric<C>],
    player_pk: &C::Point,
    per_card_commitments: &[C::Point],
    commitment_pk: &C::Point,
    d2_values: &[C::Point],
    nonce: &C::Scalar,
) -> C::Scalar
where
    C: Curve,
    K: DLEqProofKind<C>,
{
    let labels = K::labels();
    transcript.append_point::<C>(labels.pk, player_pk);
    for ct in input_cts {
        transcript.append_point::<C>(labels.input_c1, &ct.c1);
        transcript.append_point::<C>(labels.input_c2, &ct.c2);
    }
    for ct in output_cts {
        transcript.append_point::<C>(labels.output_c1, &ct.c1);
        transcript.append_point::<C>(labels.output_c2, &ct.c2);
    }
    for a_i in per_card_commitments {
        transcript.append_point::<C>(labels.per_card_commitment, a_i);
    }
    transcript.append_point::<C>(labels.commitment_pk, commitment_pk);
    for d2 in d2_values {
        transcript.append_point::<C>(labels.d2, d2);
    }
    transcript.append_scalar::<C>(labels.nonce, nonce);
    transcript.challenge::<C>(labels.challenge).scalar
}

impl<C: Curve, K: DLEqProofKind<C>> DLEqProof<C, K> {
    /// Reconstruct a DLEqProof from its constituent parts.
    ///
    /// This is intended for deserialization (e.g., from JSON). For proof
    /// generation, use [`DLEqProof::prove`] instead.
    pub fn from_parts(
        per_card_commitments: Vec<C::Point>,
        commitment_pk: C::Point,
        response: C::Scalar,
        nonce: C::Scalar,
    ) -> Self {
        DLEqProof {
            per_card_commitments,
            commitment_pk,
            response,
            nonce,
            _kind: PhantomData,
        }
    }

    /// Strictly generate a DLEq proof that the same non-zero secret key was
    /// used across every card.
    pub fn try_prove(
        input_cts: &[ElGamalCiphertextGeneric<C>],
        output_cts: &[ElGamalCiphertextGeneric<C>],
        player_sk: &C::Scalar,
        player_pk: &C::Point,
        transcript: &mut impl CryptoTranscript,
    ) -> Result<Self, poker_protocol_core::VerificationError> {
        if input_cts.is_empty() || input_cts.len() != output_cts.len() {
            return Err(poker_protocol_core::VerificationError::LengthMismatch);
        }
        if *player_sk == C::Scalar::zero()
            || player_pk.is_identity()
            || *player_pk != C::base_g() * *player_sk
        {
            return Err(poker_protocol_core::VerificationError::InvalidPublicKey);
        }

        let n = input_cts.len();
        let mut d2_values = Vec::with_capacity(n);
        for i in 0..n {
            if !input_cts[i].is_valid() || !output_cts[i].is_valid() {
                return Err(poker_protocol_core::VerificationError::InvalidCiphertext);
            }
            if input_cts[i].c1 != output_cts[i].c1 {
                return Err(poker_protocol_core::VerificationError::InvalidInput);
            }
            let d2 = K::compute_d2(&input_cts[i].c2, &output_cts[i].c2);
            // This check is the prover-side witness contract.  Without it the
            // API can silently create a proof for a different key or operation.
            if d2.is_identity() || d2 != input_cts[i].c1 * *player_sk {
                return Err(poker_protocol_core::VerificationError::InvalidInput);
            }
            d2_values.push(d2);
        }

        let mut rng = OsRng;
        let (omega, per_card_commitments, commitment_pk) = loop {
            let omega = C::Scalar::random(&mut rng);
            if omega == C::Scalar::zero() {
                continue;
            }
            let per_card_commitments: Vec<C::Point> =
                input_cts.iter().map(|ct| ct.c1 * omega).collect();
            let commitment_pk = C::base_g() * omega;
            if !commitment_pk.is_identity()
                && per_card_commitments
                    .iter()
                    .all(|commitment| !commitment.is_identity())
            {
                break (omega, per_card_commitments, commitment_pk);
            }
        };

        let nonce = C::Scalar::random(&mut rng);

        // Derive challenge using Merlin Transcript (properly hashes all inputs).
        // Shared with verify() via append_dleq_context to guarantee identical
        // transcript bytes — any divergence would silently break soundness.
        let c = append_dleq_context::<C, K>(
            transcript,
            input_cts,
            output_cts,
            player_pk,
            &per_card_commitments,
            &commitment_pk,
            &d2_values,
            &nonce,
        );

        let response = omega + c * *player_sk;

        Ok(DLEqProof {
            per_card_commitments,
            commitment_pk,
            response,
            nonce,
            _kind: PhantomData,
        })
    }

    /// Backward-compatible convenience wrapper.
    ///
    /// New protocol code should call [`Self::try_prove`] and propagate the
    /// error.  This wrapper remains for downstream source compatibility and
    /// treats an invalid witness/statement pair as a programmer error.
    pub fn prove(
        input_cts: &[ElGamalCiphertextGeneric<C>],
        output_cts: &[ElGamalCiphertextGeneric<C>],
        player_sk: &C::Scalar,
        player_pk: &C::Point,
        transcript: &mut impl CryptoTranscript,
    ) -> Self {
        Self::try_prove(input_cts, output_cts, player_sk, player_pk, transcript)
            .expect("DLEqProof::prove received an invalid witness or statement")
    }

    /// Verify a DLEq proof.
    pub fn verify(
        &self,
        input_cts: &[ElGamalCiphertextGeneric<C>],
        output_cts: &[ElGamalCiphertextGeneric<C>],
        player_pk: &C::Point,
        transcript: &mut impl CryptoTranscript,
    ) -> bool {
        // The commitment vector determines the proof shape on the wire.
        let n = self.per_card_commitments.len();

        // An empty batch proves no card transition and is rejected.
        if n == 0 {
            tracing::error!("Invalid proof: n == 0");
            return false;
        }

        // Every public vector must match the proof shape exactly.
        if n != input_cts.len() {
            tracing::error!("Invalid input_cts length: {} != {}", n, input_cts.len());
            return false;
        }
        if n != output_cts.len() {
            tracing::error!("Invalid output_cts length: {} != {}", n, output_cts.len());
            return false;
        }

        // Reject the trivial zero-key/no-op statement.
        if player_pk.is_identity() {
            tracing::error!("Invalid player_pk: identity");
            return false;
        }

        // Validate both sides, enforce c1 invariance, and derive each claim.
        let mut d2_values: Vec<C::Point> = Vec::with_capacity(n);
        for i in 0..n {
            if !input_cts[i].is_valid() {
                tracing::error!("Invalid input ciphertext at index {}", i);
                return false;
            }
            // Both remask and leave outputs are required to remain valid
            // ciphertexts in the Rust verifier.
            if K::validates_output_ciphertexts() && !output_cts[i].is_valid() {
                tracing::error!("Invalid output ciphertext at index {}", i);
                return false;
            }
            if input_cts[i].c1 != output_cts[i].c1 {
                tracing::error!(
                    "c1 mismatch at index {} (n={}): input_c1={:?} output_c1={:?}",
                    i,
                    n,
                    input_cts[i].c1,
                    output_cts[i].c1
                );
                return false;
            }
            let d2 = K::compute_d2(&input_cts[i].c2, &output_cts[i].c2);
            if d2.is_identity() {
                tracing::error!("Invalid d2 at index {}: identity", i);
                return false;
            }
            d2_values.push(d2);
        }

        // Identity commitments are not accepted by the strict wire verifier.
        if self.commitment_pk.is_identity() {
            tracing::error!("Invalid commitment_pk: identity");
            return false;
        }
        if self
            .per_card_commitments
            .iter()
            .any(CurvePoint::is_identity)
        {
            tracing::error!("Invalid per-card commitment: identity");
            return false;
        }

        // Reproduce the prover's transcript and derive the challenge.
        // Shared with prove() via append_dleq_context to guarantee identical
        // transcript bytes — any divergence would silently break soundness.
        let c = append_dleq_context::<C, K>(
            transcript,
            &input_cts[..n],
            &output_cts[..n],
            player_pk,
            &self.per_card_commitments,
            &self.commitment_pk,
            &d2_values,
            &self.nonce,
        );

        // Public-key equation: G * response = commitment_pk + c * pk.
        if C::base_g() * self.response != self.commitment_pk + *player_pk * c {
            tracing::error!("Invalid response: {:?}", self.response);
            return false;
        }

        // Per-card equations share the same response and extracted key.
        for i in 0..n {
            if input_cts[i].c1 * self.response != self.per_card_commitments[i] + d2_values[i] * c {
                tracing::error!(
                    "Invalid per-card commitment: {:?}",
                    self.per_card_commitments[i]
                );
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transcript_ext::MerlinTranscript;
    use poker_protocol_core::RistrettoCurve;

    type C = RistrettoCurve;
    type Ciphertext = ElGamalCiphertextGeneric<C>;

    fn fixture() -> (
        <C as Curve>::Scalar,
        <C as Curve>::Point,
        Ciphertext,
        Ciphertext,
    ) {
        let sk = <C as Curve>::Scalar::random(&mut OsRng);
        let pk = C::base_g() * sk;
        let randomness = <C as Curve>::Scalar::random(&mut OsRng);
        let input = Ciphertext::encrypt(&(C::base_g() + C::base_h()), &pk, &randomness);
        let output = Ciphertext {
            c1: input.c1,
            c2: input.c2 + input.c1 * sk,
        };
        (sk, pk, input, output)
    }

    #[test]
    fn strict_prover_rejects_empty_mismatched_and_wrong_relations() {
        let (sk, pk, input, output) = fixture();
        assert!(DLEqProof::<C, RemaskKind>::try_prove(
            &[],
            &[],
            &sk,
            &pk,
            &mut MerlinTranscript::new(b"dleq-empty")
        )
        .is_err());
        assert!(DLEqProof::<C, RemaskKind>::try_prove(
            &[input.clone()],
            &[],
            &sk,
            &pk,
            &mut MerlinTranscript::new(b"dleq-length")
        )
        .is_err());

        let mut malformed = output;
        malformed.c2 = malformed.c2 + C::base_h();
        assert!(DLEqProof::<C, RemaskKind>::try_prove(
            &[input],
            &[malformed],
            &sk,
            &pk,
            &mut MerlinTranscript::new(b"dleq-wrong-relation")
        )
        .is_err());
    }

    #[test]
    fn verifier_rejects_identity_per_card_commitment_and_identity_delta() {
        let (sk, pk, input, output) = fixture();
        let mut proof = DLEqProof::<C, RemaskKind>::try_prove(
            &[input.clone()],
            &[output],
            &sk,
            &pk,
            &mut MerlinTranscript::new(b"dleq-identity-commitment"),
        )
        .unwrap();
        proof.per_card_commitments[0] = <C as Curve>::Point::identity();
        assert!(!proof.verify(
            &[input.clone()],
            &[Ciphertext {
                c1: input.c1,
                c2: input.c2 + input.c1 * sk,
            }],
            &pk,
            &mut MerlinTranscript::new(b"dleq-identity-commitment")
        ));

        let honest_proof = DLEqProof::<C, RemaskKind>::try_prove(
            &[input.clone()],
            &[Ciphertext {
                c1: input.c1,
                c2: input.c2 + input.c1 * sk,
            }],
            &sk,
            &pk,
            &mut MerlinTranscript::new(b"dleq-identity-delta"),
        )
        .unwrap();
        assert!(!honest_proof.verify(
            &[input.clone()],
            &[input],
            &pk,
            &mut MerlinTranscript::new(b"dleq-identity-delta")
        ));
    }
}
