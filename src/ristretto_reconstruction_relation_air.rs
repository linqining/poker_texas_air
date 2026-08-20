//! Ristretto Reconstruction V3 cross-key equation composition.
//!
//! The wire envelope authenticates the shape and bytes of a reconstruction
//! proof, but it is not itself a proof of the Sigma equations.  This module
//! closes the next layer for the cross-key negation relation.  It expands the
//! three public equations into one shared fixed-window scalar-multiplication
//! STARK and one fixed-shape compressed point-addition batch STARK.
//!
//! The challenge is deliberately a public input in this first composition
//! layer.  A later transcript component must recompute it from the canonical
//! Poseidon252 transcript and bind the same challenge to every cross-key and
//! slot-OR statement before production admission is enabled.

#![allow(missing_docs)]

use borsh::{BorshDeserialize, BorshSerialize};
use num_bigint::BigUint;
use num_traits::{One, Zero};

use crate::error::{TexasAirError, TexasAirResult};
use crate::ristretto_fp_program_air::{
    ArchivedRistrettoFpProgramBatchProof,
    ArchivedRistrettoFpProgramCompressedFixedWindowScalarMulBatchProof,
    ArchivedRistrettoFpProgramProof, RistrettoFpProgramBuilder,
    build_ristretto_fp_program_compressed_point_addition, prove_ristretto_fp_program,
    prove_ristretto_fp_program_batch,
    prove_ristretto_fp_program_compressed_fixed_window_scalar_mul_batch,
    verify_ristretto_fp_program, verify_ristretto_fp_program_batch,
    verify_ristretto_fp_program_compressed_fixed_window_scalar_mul_batch,
};
use crate::ristretto_reconstruction_proof_wire::{
    RISTRETTO_RECONSTRUCTION_READABLE_CARDS, RistrettoCiphertextProofWire,
    RistrettoCrossKeyProofWire, RistrettoReconstructionProofEnvelope,
    validate_ristretto_reconstruction_proof_wire,
};
use crate::ristretto_reconstruction_transcript::validate_relation_challenges;
use crate::ristretto_reconstruction_transcript::{
    RistrettoPoseidonTranscriptChallenges, RistrettoTranscriptChallengeKind,
};
use crate::ristretto_scalar_air::GROUP_ORDER_BYTES;
use crate::ristretto_scalar_windows_air::{
    prove_ristretto_scalar_windows, verify_ristretto_scalar_windows,
};
use poker_protocol::precompile_abi::ReconstructionV3VerifyRequest;

const LIMBS: usize = 32;
const SCALAR_MUL_COUNT: usize = 8;
const ADDITION_COUNT: usize = 5;
const BASEPOINT: [u8; LIMBS] = [
    0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71, 0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00, 0x51, 0x5f,
    0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d, 0xb6, 0xa6, 0x59, 0x45, 0xe0, 0x8d, 0x2d, 0x76,
];
const ONE: [u8; LIMBS] = {
    let mut value = [0u8; LIMBS];
    value[0] = 1;
    value
};

/// Public statement for one cross-key negation proof.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RistrettoCrossKeyEquationStatement {
    pub statement_digest: [u8; 32],
    pub readable: RistrettoCiphertextProofWire,
    pub negative_contribution: RistrettoCiphertextProofWire,
    pub owner_pk: [u8; 32],
    pub aggregate_pk: [u8; 32],
    /// Public non-zero Fiat--Shamir challenge for this equation layer.
    pub challenge: [u8; 32],
    /// Field inverse used by the AIR to prove `challenge != 0`.
    pub challenge_inverse: [u8; 32],
    pub proof: RistrettoCrossKeyProofWire,
}

/// Host-zero equation archive for one cross-key relation.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoCrossKeyEquationProof {
    pub statement: RistrettoCrossKeyEquationStatement,
    pub challenge_nonzero: ArchivedRistrettoFpProgramProof,
    /// Rows, in fixed order:
    /// `response_owner*G`, `challenge*owner_pk`,
    /// `response_randomness*G`, `challenge*negative.c1`,
    /// `response_owner*readable.c1`, `response_randomness*aggregate_pk`,
    /// `challenge*readable.c2`, `challenge*negative.c2`.
    pub scalar_multiplications: ArchivedRistrettoFpProgramCompressedFixedWindowScalarMulBatchProof,
    /// Rows, in fixed order: owner-key equation, contribution-c1 equation,
    /// challenge-c2 sum, joint-c2 left side, joint-c2 right side.
    pub additions: ArchivedRistrettoFpProgramBatchProof,
}

/// The two public challenges emitted by the Reconstruction V3 transcript
/// component, in the exact readable-card order.
///
/// This is deliberately only a typed boundary between the cross-key relation
/// component and the future Poseidon252 transcript AIR.  It is **not** a
/// transcript proof: production verification must accept this value only as
/// the authenticated public output of that AIR, never as an arbitrary
/// host-provided challenge pair.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RistrettoCrossKeyTranscriptChallenges {
    /// Same digest as the authenticated `ZR3P` envelope and every equation.
    pub statement_digest: [u8; 32],
    /// One non-zero scalar challenge per readable-card cross-key proof.
    pub challenges: [[u8; LIMBS]; RISTRETTO_RECONSTRUCTION_READABLE_CARDS],
}

impl RistrettoCrossKeyTranscriptChallenges {
    /// Project the authenticated full-transcript output onto the two
    /// cross-key relation slots.  The full transcript output must already be
    /// checked by its transcript AIR; this method only performs the fixed
    /// order/digest projection and scalar boundary checks.
    pub fn from_poseidon_output(
        output: &RistrettoPoseidonTranscriptChallenges,
        statement_digest: [u8; 32],
    ) -> TexasAirResult<Self> {
        output.validate_for_statement(statement_digest)?;
        let challenges: [TexasAirResult<[u8; LIMBS]>; RISTRETTO_RECONSTRUCTION_READABLE_CARDS] =
            std::array::from_fn(|index| {
                output.challenge_for(
                    statement_digest,
                    RistrettoTranscriptChallengeKind::CrossKey,
                    index,
                )
            });
        let challenges = challenges
            .into_iter()
            .collect::<TexasAirResult<Vec<_>>>()?
            .try_into()
            .map_err(|_| {
                TexasAirError::ConstraintUnsatisfied("cross-key challenge projection shape".into())
            })?;
        Ok(Self {
            statement_digest,
            challenges,
        })
    }
}

/// Both cross-key equation archives bound to one Reconstruction V3 request.
///
/// This covers only the two cross-key negation relations.  It deliberately
/// does not claim to be a complete Reconstruction V3 proof: shuffle, slot-OR,
/// transcript recomputation, and their final composition remain separate AIR
/// components.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoReconstructionCrossKeyBatchProof {
    /// Digest shared with the `ZR3P` proof envelope.
    pub statement_digest: [u8; 32],
    /// Exactly two equations, ordered as `request.user_readable_cards`.
    pub equations:
        [ArchivedRistrettoCrossKeyEquationProof; RISTRETTO_RECONSTRUCTION_READABLE_CARDS],
}

fn modulus() -> BigUint {
    (BigUint::one() << 255u32) - BigUint::from(19u32)
}

fn scalar_modulus() -> BigUint {
    BigUint::from_bytes_le(&GROUP_ORDER_BYTES)
}

fn big(value: &[u8; LIMBS]) -> BigUint {
    BigUint::from_bytes_le(value)
}

fn inverse(value: &[u8; LIMBS]) -> TexasAirResult<[u8; LIMBS]> {
    let value = big(value);
    if value.is_zero() || value >= modulus() {
        return Err(TexasAirError::SpecViolation(
            "cross-key challenge must be a non-zero canonical field element".into(),
        ));
    }
    let inverse = value.modpow(&(modulus() - BigUint::from(2u32)), &modulus());
    let mut bytes = [0u8; LIMBS];
    let encoded = inverse.to_bytes_le();
    bytes[..encoded.len()].copy_from_slice(&encoded);
    Ok(bytes)
}

fn validate_canonical_scalar(value: &[u8; LIMBS], label: &str) -> TexasAirResult<()> {
    let value = big(value);
    if value >= scalar_modulus() {
        return Err(TexasAirError::SpecViolation(format!(
            "cross-key {label} must be a canonical Ristretto scalar"
        )));
    }
    Ok(())
}

fn validate_nonzero_scalar(value: &[u8; LIMBS], label: &str) -> TexasAirResult<()> {
    validate_canonical_scalar(value, label)?;
    if big(value).is_zero() {
        return Err(TexasAirError::SpecViolation(format!(
            "cross-key {label} must be non-zero"
        )));
    }
    Ok(())
}

fn fixed_point(value: &[u8], label: &str) -> TexasAirResult<[u8; LIMBS]> {
    value.try_into().map_err(|_| {
        TexasAirError::SpecViolation(format!(
            "cross-key {label} is not a 32-byte Ristretto point"
        ))
    })
}

fn fixed_ciphertext(
    c1: &[u8],
    c2: &[u8],
    label: &str,
) -> TexasAirResult<RistrettoCiphertextProofWire> {
    Ok(RistrettoCiphertextProofWire {
        c1: fixed_point(c1, &format!("{label}.c1"))?,
        c2: fixed_point(c2, &format!("{label}.c2"))?,
    })
}

fn expected_cross_key_equation_statements(
    request: &ReconstructionV3VerifyRequest,
    envelope: &RistrettoReconstructionProofEnvelope,
    transcript_challenges: &RistrettoCrossKeyTranscriptChallenges,
) -> TexasAirResult<[RistrettoCrossKeyEquationStatement; RISTRETTO_RECONSTRUCTION_READABLE_CARDS]> {
    validate_relation_challenges(
        transcript_challenges.statement_digest,
        envelope.statement_digest,
        &transcript_challenges.challenges,
    )?;
    let owner_pk = fixed_point(&request.owner_pk, "request.owner_pk")?;
    let aggregate_pk = fixed_point(&request.aggregate_pk, "request.aggregate_pk")?;
    let mut equations = Vec::with_capacity(RISTRETTO_RECONSTRUCTION_READABLE_CARDS);
    for index in 0..RISTRETTO_RECONSTRUCTION_READABLE_CARDS {
        let readable = request.user_readable_cards.get(index).ok_or_else(|| {
            TexasAirError::SpecViolation("cross-key readable-card index is out of bounds".into())
        })?;
        let challenge = transcript_challenges.challenges[index];
        validate_nonzero_scalar(&challenge, "transcript challenge")?;
        equations.push(RistrettoCrossKeyEquationStatement {
            statement_digest: envelope.statement_digest,
            readable: fixed_ciphertext(&readable.c1, &readable.c2, "request.readable")?,
            negative_contribution: envelope.negative_contributions[index],
            owner_pk,
            aggregate_pk,
            challenge,
            // This field inverse exists only to establish `challenge != 0`
            // inside the Fp program.  Scalar canonicality is independently
            // enforced by every fixed-window scalar multiplication row.
            challenge_inverse: inverse(&challenge)?,
            proof: envelope.cross_key_proofs[index],
        });
    }
    equations.try_into().map_err(|_| {
        TexasAirError::ConstraintUnsatisfied("cross-key equation count is not fixed".into())
    })
}

fn validate_cross_key_batch_statement_binding(
    request: &ReconstructionV3VerifyRequest,
    transcript_challenges: &RistrettoCrossKeyTranscriptChallenges,
    archive: &ArchivedRistrettoReconstructionCrossKeyBatchProof,
) -> TexasAirResult<[RistrettoCrossKeyEquationStatement; RISTRETTO_RECONSTRUCTION_READABLE_CARDS]> {
    let envelope = validate_ristretto_reconstruction_proof_wire(request)?;
    if archive.statement_digest != envelope.statement_digest {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "cross-key batch archive is detached from the ZR3P statement".into(),
        ));
    }
    let expected =
        expected_cross_key_equation_statements(request, &envelope, transcript_challenges)?;
    for (actual, expected_statement) in archive.equations.iter().zip(&expected) {
        if actual.statement != *expected_statement {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "cross-key equation archive is detached from its request, envelope, or transcript challenge"
                    .into(),
            ));
        }
    }
    Ok(expected)
}

fn validate_non_identity_encoding(value: &[u8; LIMBS], label: &str) -> TexasAirResult<()> {
    if *value == [0; LIMBS] {
        return Err(TexasAirError::SpecViolation(format!(
            "cross-key {label} cannot be the Ristretto identity"
        )));
    }
    // The fixed compressed-point AIR builder performs the full canonical
    // decode and rejects noncanonical, negative, and non-decodable encodings.
    let _ = build_ristretto_fp_program_compressed_point_addition(value, &BASEPOINT)?;
    Ok(())
}

fn build_nonzero_challenge_program(
    challenge: &[u8; LIMBS],
    challenge_inverse: &[u8; LIMBS],
) -> TexasAirResult<crate::ristretto_fp_program_air::RistrettoFpProgram> {
    let mut builder = RistrettoFpProgramBuilder::new(&[*challenge, *challenge_inverse]);
    let product = builder.multiply(0, 1)?;
    let program = builder.finish(&[product])?;
    if program.values[usize::from(product)] != ONE {
        return Err(TexasAirError::SpecViolation(
            "cross-key challenge inverse does not multiply to one".into(),
        ));
    }
    Ok(program)
}

fn prove_nonzero_challenge(
    challenge: &[u8; LIMBS],
    challenge_inverse: &[u8; LIMBS],
) -> TexasAirResult<ArchivedRistrettoFpProgramProof> {
    prove_ristretto_fp_program(&build_nonzero_challenge_program(
        challenge,
        challenge_inverse,
    )?)
}

fn scalar_inputs(
    statement: &RistrettoCrossKeyEquationStatement,
) -> Vec<([u8; LIMBS], [u8; LIMBS])> {
    let proof = &statement.proof;
    vec![
        (proof.response_owner_sk, BASEPOINT),
        (statement.challenge, statement.owner_pk),
        (proof.response_contribution_randomness, BASEPOINT),
        (statement.challenge, statement.negative_contribution.c1),
        (proof.response_owner_sk, statement.readable.c1),
        (
            proof.response_contribution_randomness,
            statement.aggregate_pk,
        ),
        (statement.challenge, statement.readable.c2),
        (statement.challenge, statement.negative_contribution.c2),
    ]
}

fn expected_addition_programs(
    statement: &RistrettoCrossKeyEquationStatement,
    outputs: &[[u8; LIMBS]; SCALAR_MUL_COUNT],
) -> TexasAirResult<Vec<crate::ristretto_fp_program_air::RistrettoFpProgram>> {
    let proof = &statement.proof;
    let c2_sum = build_ristretto_fp_program_compressed_point_addition(&outputs[6], &outputs[7])?;
    let lhs = build_ristretto_fp_program_compressed_point_addition(&outputs[4], &outputs[5])?;
    let rhs = build_ristretto_fp_program_compressed_point_addition(
        &proof.commitment_joint_c2,
        &c2_sum.1,
    )?;
    let owner = build_ristretto_fp_program_compressed_point_addition(
        &proof.commitment_owner_key,
        &outputs[1],
    )?;
    let contribution_c1 = build_ristretto_fp_program_compressed_point_addition(
        &proof.commitment_contribution_c1,
        &outputs[3],
    )?;

    if owner.1 != outputs[0] || contribution_c1.1 != outputs[2] || lhs.1 != rhs.1 {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "cross-key public equation does not close".into(),
        ));
    }
    Ok(vec![owner.0, contribution_c1.0, c2_sum.0, lhs.0, rhs.0])
}

fn scalar_outputs(
    archive: &ArchivedRistrettoFpProgramCompressedFixedWindowScalarMulBatchProof,
) -> TexasAirResult<[[u8; LIMBS]; SCALAR_MUL_COUNT]> {
    if archive.statements.len() != SCALAR_MUL_COUNT {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "cross-key scalar multiplication row count is not fixed".into(),
        ));
    }
    archive
        .statements
        .iter()
        .map(|statement| statement.output)
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| TexasAirError::ConstraintUnsatisfied("cross-key scalar output shape".into()))
}

/// Build and prove one cross-key negation equation archive.
pub fn prove_ristretto_cross_key_equation(
    statement: RistrettoCrossKeyEquationStatement,
) -> TexasAirResult<ArchivedRistrettoCrossKeyEquationProof> {
    validate_cross_key_statement(&statement)?;
    let inverse = inverse(&statement.challenge)?;
    if inverse != statement.challenge_inverse {
        return Err(TexasAirError::SpecViolation(
            "cross-key challenge inverse is detached from the challenge".into(),
        ));
    }
    let challenge_nonzero =
        prove_nonzero_challenge(&statement.challenge, &statement.challenge_inverse)?;
    let scalar_windows = scalar_inputs(&statement)
        .into_iter()
        .map(|(scalar, _)| prove_ristretto_scalar_windows(&scalar))
        .collect::<TexasAirResult<Vec<_>>>()?;
    let scalar_multiplications =
        prove_ristretto_fp_program_compressed_fixed_window_scalar_mul_batch(
            scalar_windows
                .into_iter()
                .zip(scalar_inputs(&statement).into_iter().map(|(_, base)| base))
                .collect(),
        )?;
    let outputs = scalar_outputs(&scalar_multiplications)?;
    let programs = expected_addition_programs(&statement, &outputs)?;
    let additions = prove_ristretto_fp_program_batch(&programs)?;
    let archive = ArchivedRistrettoCrossKeyEquationProof {
        statement,
        challenge_nonzero,
        scalar_multiplications,
        additions,
    };
    verify_ristretto_cross_key_equation(&archive)?;
    Ok(archive)
}

fn validate_cross_key_statement(
    statement: &RistrettoCrossKeyEquationStatement,
) -> TexasAirResult<()> {
    validate_nonzero_scalar(&statement.challenge, "challenge")?;
    validate_canonical_scalar(&statement.proof.response_owner_sk, "owner response")?;
    validate_canonical_scalar(
        &statement.proof.response_contribution_randomness,
        "contribution response",
    )?;
    for (label, value) in [
        ("owner_pk", statement.owner_pk),
        ("aggregate_pk", statement.aggregate_pk),
        ("readable.c1", statement.readable.c1),
        ("readable.c2", statement.readable.c2),
        ("negative.c1", statement.negative_contribution.c1),
        ("negative.c2", statement.negative_contribution.c2),
        ("commitment_owner_key", statement.proof.commitment_owner_key),
        (
            "commitment_contribution_c1",
            statement.proof.commitment_contribution_c1,
        ),
        ("commitment_joint_c2", statement.proof.commitment_joint_c2),
    ] {
        validate_non_identity_encoding(&value, label)?;
    }
    Ok(())
}

/// Verify all fixed-shape STARKs and the three cross-key equations.
pub fn verify_ristretto_cross_key_equation(
    archive: &ArchivedRistrettoCrossKeyEquationProof,
) -> TexasAirResult<()> {
    validate_cross_key_statement(&archive.statement)?;
    let expected_inverse = inverse(&archive.statement.challenge)?;
    if expected_inverse != archive.statement.challenge_inverse {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "cross-key challenge inverse is detached".into(),
        ));
    }
    let inverse_program = build_nonzero_challenge_program(
        &archive.statement.challenge,
        &archive.statement.challenge_inverse,
    )?;
    if archive.challenge_nonzero.program != inverse_program {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "cross-key non-zero challenge program is detached".into(),
        ));
    }
    verify_ristretto_fp_program(&archive.challenge_nonzero)?;

    let expected_inputs = scalar_inputs(&archive.statement);
    if archive.scalar_multiplications.statements.len() != SCALAR_MUL_COUNT {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "cross-key scalar multiplication count mismatch".into(),
        ));
    }
    for (actual, (scalar, base)) in archive
        .scalar_multiplications
        .statements
        .iter()
        .zip(expected_inputs)
    {
        if actual.scalar_windows.scalar != scalar || actual.base != base {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "cross-key scalar multiplication statement is detached".into(),
            ));
        }
    }
    for statement in &archive.scalar_multiplications.statements {
        verify_ristretto_scalar_windows(&statement.scalar_windows)?;
    }
    verify_ristretto_fp_program_compressed_fixed_window_scalar_mul_batch(
        &archive.scalar_multiplications,
    )?;

    let outputs = scalar_outputs(&archive.scalar_multiplications)?;
    let expected_programs = expected_addition_programs(&archive.statement, &outputs)?;
    if archive.additions.programs != expected_programs
        || archive.additions.programs.len() != ADDITION_COUNT
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "cross-key point-addition rows are detached".into(),
        ));
    }
    verify_ristretto_fp_program_batch(&archive.additions)
}

/// Build both request-bound cross-key equation archives.
///
/// This is intentionally a proving helper, not a production admission API.
/// It accepts challenges only through [`RistrettoCrossKeyTranscriptChallenges`]
/// so its output shape is ready to compose with the future Poseidon252
/// transcript AIR.  Until that component is present, callers must not treat
/// successful verification as a complete Reconstruction V3 verification.
pub fn prove_ristretto_reconstruction_cross_key_batch(
    request: &ReconstructionV3VerifyRequest,
    transcript_challenges: &RistrettoCrossKeyTranscriptChallenges,
) -> TexasAirResult<ArchivedRistrettoReconstructionCrossKeyBatchProof> {
    let envelope = validate_ristretto_reconstruction_proof_wire(request)?;
    let statements =
        expected_cross_key_equation_statements(request, &envelope, transcript_challenges)?;
    let equations = statements
        .into_iter()
        .map(prove_ristretto_cross_key_equation)
        .collect::<TexasAirResult<Vec<_>>>()?
        .try_into()
        .map_err(|_| {
            TexasAirError::ConstraintUnsatisfied(
                "cross-key proving result count is not fixed".into(),
            )
        })?;
    let archive = ArchivedRistrettoReconstructionCrossKeyBatchProof {
        statement_digest: envelope.statement_digest,
        equations,
    };
    verify_ristretto_reconstruction_cross_key_batch(request, transcript_challenges, &archive)?;
    Ok(archive)
}

/// Verify both cross-key equation archives against the exact V3 request and
/// `ZR3P` proof envelope.
///
/// The caller must provide `transcript_challenges` as the authenticated output
/// of the future Poseidon252 transcript AIR.  This verifier intentionally does
/// not accept a host-generated challenge pair as sufficient for production
/// admission, and it does not verify the separate shuffle or slot-OR
/// components.
pub fn verify_ristretto_reconstruction_cross_key_batch(
    request: &ReconstructionV3VerifyRequest,
    transcript_challenges: &RistrettoCrossKeyTranscriptChallenges,
    archive: &ArchivedRistrettoReconstructionCrossKeyBatchProof,
) -> TexasAirResult<()> {
    validate_cross_key_batch_statement_binding(request, transcript_challenges, archive)?;
    for equation in &archive.equations {
        verify_ristretto_cross_key_equation(equation)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use poker_protocol::crypto::curve::{Curve, CurveScalar, RistrettoCurve};
    use poker_protocol::precompile_abi::{
        CurveId, EncodedCiphertext, ReconstructionProofSystem, TranscriptId,
    };

    fn statement() -> RistrettoCrossKeyEquationStatement {
        RistrettoCrossKeyEquationStatement {
            statement_digest: [7; 32],
            readable: RistrettoCiphertextProofWire {
                c1: BASEPOINT,
                c2: BASEPOINT,
            },
            negative_contribution: RistrettoCiphertextProofWire {
                c1: BASEPOINT,
                c2: BASEPOINT,
            },
            owner_pk: BASEPOINT,
            aggregate_pk: BASEPOINT,
            challenge: {
                let mut value = [0u8; LIMBS];
                value[0] = 9;
                value
            },
            challenge_inverse: [0; LIMBS],
            proof: RistrettoCrossKeyProofWire {
                commitment_owner_key: BASEPOINT,
                commitment_contribution_c1: BASEPOINT,
                commitment_joint_c2: BASEPOINT,
                response_owner_sk: [0; LIMBS],
                response_contribution_randomness: [0; LIMBS],
            },
        }
    }

    #[test]
    fn rejects_zero_challenge_before_building_equations() {
        let mut statement = statement();
        assert!(validate_cross_key_statement(&statement).is_ok());
        statement.challenge = [0; LIMBS];
        assert!(inverse(&statement.challenge).is_err());
    }

    #[test]
    fn challenge_inverse_program_is_fixed_to_one() {
        let mut challenge = [0u8; LIMBS];
        challenge[0] = 9;
        let inverse = inverse(&challenge).unwrap();
        let program = build_nonzero_challenge_program(&challenge, &inverse).unwrap();
        assert_eq!(program.outputs.len(), 1);
        assert_eq!(program.values[usize::from(program.outputs[0])], ONE);
        let mut changed = program.clone();
        changed.values[0][0] ^= 1;
        assert_ne!(changed, program);
    }

    fn compressed(point: <RistrettoCurve as Curve>::Point) -> [u8; LIMBS] {
        *point.compress().as_bytes()
    }

    #[test]
    fn native_cross_key_fixture_closes_the_fixed_air_equation_schedule() {
        let scalar = <RistrettoCurve as Curve>::Scalar::from_u64;
        let g = RistrettoCurve::base_g();
        let owner_secret = scalar(5);
        let aggregate_secret = scalar(11);
        let readable_randomness = scalar(13);
        let contribution_randomness = scalar(17);
        let plaintext = g * scalar(19);
        let owner_pk = g * owner_secret;
        let aggregate_pk = g * aggregate_secret;
        let readable_c1 = g * readable_randomness;
        let readable_c2 = plaintext + owner_pk * readable_randomness;
        let negative_c1 = g * contribution_randomness;
        let negative_c2 = -plaintext + aggregate_pk * contribution_randomness;

        let owner_nonce = scalar(23);
        let contribution_nonce = scalar(29);
        let challenge_scalar = scalar(31);
        let mut challenge = [0; LIMBS];
        challenge.copy_from_slice(challenge_scalar.as_bytes());
        let statement = RistrettoCrossKeyEquationStatement {
            statement_digest: [42; 32],
            readable: RistrettoCiphertextProofWire {
                c1: compressed(readable_c1),
                c2: compressed(readable_c2),
            },
            negative_contribution: RistrettoCiphertextProofWire {
                c1: compressed(negative_c1),
                c2: compressed(negative_c2),
            },
            owner_pk: compressed(owner_pk),
            aggregate_pk: compressed(aggregate_pk),
            challenge,
            challenge_inverse: inverse(&challenge).unwrap(),
            proof: RistrettoCrossKeyProofWire {
                commitment_owner_key: compressed(g * owner_nonce),
                commitment_contribution_c1: compressed(g * contribution_nonce),
                commitment_joint_c2: compressed(
                    readable_c1 * owner_nonce + aggregate_pk * contribution_nonce,
                ),
                response_owner_sk: {
                    let mut response = [0; LIMBS];
                    response.copy_from_slice(
                        (owner_nonce + challenge_scalar * owner_secret).as_bytes(),
                    );
                    response
                },
                response_contribution_randomness: {
                    let mut response = [0; LIMBS];
                    response.copy_from_slice(
                        (contribution_nonce + challenge_scalar * contribution_randomness)
                            .as_bytes(),
                    );
                    response
                },
            },
        };
        validate_cross_key_statement(&statement).unwrap();
        let outputs = [
            compressed(g * (owner_nonce + challenge_scalar * owner_secret)),
            compressed(owner_pk * challenge_scalar),
            compressed(g * (contribution_nonce + challenge_scalar * contribution_randomness)),
            compressed(negative_c1 * challenge_scalar),
            compressed(readable_c1 * (owner_nonce + challenge_scalar * owner_secret)),
            compressed(
                aggregate_pk * (contribution_nonce + challenge_scalar * contribution_randomness),
            ),
            compressed(readable_c2 * challenge_scalar),
            compressed(negative_c2 * challenge_scalar),
        ];
        assert_eq!(
            expected_addition_programs(&statement, &outputs)
                .unwrap()
                .len(),
            ADDITION_COUNT
        );

        let mut output_splice = outputs;
        output_splice[4] = compressed(g * scalar(37));
        assert!(expected_addition_programs(&statement, &output_splice).is_err());
    }

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
            cards: vec![vec![5; 32]; 52],
            user_readable_cards: vec![
                EncodedCiphertext {
                    c1: vec![6; 32],
                    c2: vec![7; 32],
                };
                RISTRETTO_RECONSTRUCTION_READABLE_CARDS
            ],
            contributions: vec![
                EncodedCiphertext {
                    c1: vec![8; 32],
                    c2: vec![9; 32],
                };
                52
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
            }; RISTRETTO_RECONSTRUCTION_READABLE_CARDS],
            crate::ristretto_reconstruction_proof_wire::RistrettoBayerGrothShuffleProofWire::default(),
            [RistrettoCrossKeyProofWire {
                commitment_owner_key: [0xB0; 32],
                commitment_contribution_c1: [0xB1; 32],
                commitment_joint_c2: [0xB2; 32],
                response_owner_sk: [0x0B; 32],
                response_contribution_randomness: [0x0C; 32],
            }; RISTRETTO_RECONSTRUCTION_READABLE_CARDS],
            [crate::ristretto_reconstruction_proof_wire::RistrettoSlotOrProofWire::default(); 52],
        )
        .unwrap()
    }

    #[test]
    fn cross_key_batch_statement_cannot_be_spliced_from_request_or_envelope() {
        let mut request = request();
        request.user_readable_cards[1].c1[0] ^= 1;
        let envelope = envelope(&request);
        request.proof = envelope.encode_wire().unwrap();
        let challenges = RistrettoCrossKeyTranscriptChallenges {
            statement_digest: envelope.statement_digest,
            challenges: std::array::from_fn(|index| {
                let mut scalar = [0; LIMBS];
                scalar[0] = u8::try_from(9 + index).unwrap();
                scalar
            }),
        };
        let statements =
            expected_cross_key_equation_statements(&request, &envelope, &challenges).unwrap();
        let archive = ArchivedRistrettoReconstructionCrossKeyBatchProof {
            statement_digest: envelope.statement_digest,
            equations: std::array::from_fn(|index| ArchivedRistrettoCrossKeyEquationProof {
                statement: statements[index].clone(),
                challenge_nonzero: ArchivedRistrettoFpProgramProof {
                    program: build_nonzero_challenge_program(
                        &statements[index].challenge,
                        &statements[index].challenge_inverse,
                    )
                    .unwrap(),
                    stark_proof_bytes: Vec::new(),
                },
                scalar_multiplications:
                    ArchivedRistrettoFpProgramCompressedFixedWindowScalarMulBatchProof {
                        statements: Vec::new(),
                        additions: ArchivedRistrettoFpProgramBatchProof {
                            programs: Vec::new(),
                            stark_proof_bytes: Vec::new(),
                        },
                    },
                additions: ArchivedRistrettoFpProgramBatchProof {
                    programs: Vec::new(),
                    stark_proof_bytes: Vec::new(),
                },
            }),
        };
        assert!(
            validate_cross_key_batch_statement_binding(&request, &challenges, &archive).is_ok()
        );

        let mut request_splice = request.clone();
        request_splice.user_readable_cards[0].c1[0] ^= 1;
        assert!(
            validate_cross_key_batch_statement_binding(&request_splice, &challenges, &archive)
                .is_err()
        );

        let mut challenge_splice = challenges.clone();
        challenge_splice.challenges[1][0] ^= 1;
        assert!(
            validate_cross_key_batch_statement_binding(&request, &challenge_splice, &archive)
                .is_err()
        );

        let mut zero_challenge = challenges.clone();
        zero_challenge.challenges[0] = [0; LIMBS];
        assert!(
            validate_cross_key_batch_statement_binding(&request, &zero_challenge, &archive)
                .is_err()
        );

        let mut digest_splice = challenges.clone();
        digest_splice.statement_digest[0] ^= 1;
        assert!(
            validate_cross_key_batch_statement_binding(&request, &digest_splice, &archive).is_err()
        );

        let mut equation_splice = archive.clone();
        equation_splice.equations.swap(0, 1);
        assert!(
            validate_cross_key_batch_statement_binding(&request, &challenges, &equation_splice,)
                .is_err()
        );
    }
}
