//! Ristretto Reconstruction V3 slot-membership OR composition.
//!
//! A slot proves, without revealing the selected branch, the two equations
//! for each challenge share `b`:
//!
//! `response[b] G = commitment_g[b] + challenge[b] contribution.c1`
//!
//! `response[b] aggregate_pk = commitment_pk[b] + target[b] challenge[b]`,
//! where `target[0] = contribution.c2` and `target[1] = contribution.c2 + card`.
//! The global challenge is constrained as `challenge[0] + challenge[1] = c`
//! modulo the Ristretto group order `l`.

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
    RistrettoCiphertextProofWire, RistrettoReconstructionProofEnvelope, RistrettoSlotOrProofWire,
    validate_ristretto_reconstruction_proof_wire,
};
use crate::ristretto_reconstruction_transcript::validate_relation_challenges;
use crate::ristretto_reconstruction_transcript::{
    RistrettoPoseidonTranscriptChallenges, RistrettoTranscriptChallengeKind,
};
use crate::ristretto_scalar_add_air::{
    ArchivedRistrettoScalarAdditionProof, prove_ristretto_scalar_addition,
    verify_ristretto_scalar_addition,
};
use crate::ristretto_scalar_air::GROUP_ORDER_BYTES;
use crate::ristretto_scalar_windows_air::{
    prove_ristretto_scalar_windows, verify_ristretto_scalar_windows,
};
use poker_protocol::precompile_abi::ReconstructionV3VerifyRequest;

const LIMBS: usize = 32;
const SLOT_COUNT: usize = 52;
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

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RistrettoSlotOrStatement {
    pub statement_digest: [u8; 32],
    pub slot_index: u8,
    pub card: [u8; LIMBS],
    pub contribution: RistrettoCiphertextProofWire,
    pub aggregate_pk: [u8; LIMBS],
    pub global_challenge: [u8; LIMBS],
    pub global_challenge_inverse: [u8; LIMBS],
    pub proof: RistrettoSlotOrProofWire,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoSlotOrProof {
    pub statement: RistrettoSlotOrStatement,
    pub challenge_nonzero: ArchivedRistrettoFpProgramProof,
    pub challenge_addition: ArchivedRistrettoScalarAdditionProof,
    pub scalar_multiplications: ArchivedRistrettoFpProgramCompressedFixedWindowScalarMulBatchProof,
    pub additions: ArchivedRistrettoFpProgramBatchProof,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct RistrettoSlotOrTranscriptChallenges {
    pub statement_digest: [u8; 32],
    pub global_challenges: [[u8; LIMBS]; SLOT_COUNT],
}

impl RistrettoSlotOrTranscriptChallenges {
    /// Project the authenticated full-transcript output onto the 52 fixed
    /// slot-OR challenge positions.
    pub fn from_poseidon_output(
        output: &RistrettoPoseidonTranscriptChallenges,
        statement_digest: [u8; 32],
    ) -> TexasAirResult<Self> {
        output.validate_for_statement(statement_digest)?;
        let global_challenges: [TexasAirResult<[u8; LIMBS]>; SLOT_COUNT] =
            std::array::from_fn(|slot| {
                output.challenge_for(
                    statement_digest,
                    RistrettoTranscriptChallengeKind::SlotOr,
                    slot,
                )
            });
        let global_challenges = global_challenges
            .into_iter()
            .collect::<TexasAirResult<Vec<_>>>()?
            .try_into()
            .map_err(|_| {
                TexasAirError::ConstraintUnsatisfied("slot-OR challenge projection shape".into())
            })?;
        Ok(Self {
            statement_digest,
            global_challenges,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedRistrettoReconstructionSlotOrBatchProof {
    pub statement_digest: [u8; 32],
    /// Exactly 52 archives in canonical card-slot order.  This is a `Vec` so
    /// serialized relation bundles can remain heap-backed; the verifier
    /// rejects every other length before inspecting any equation.
    pub slots: Vec<ArchivedRistrettoSlotOrProof>,
}

fn scalar_modulus() -> BigUint {
    BigUint::from_bytes_le(&GROUP_ORDER_BYTES)
}

fn field_modulus() -> BigUint {
    (BigUint::one() << 255u32) - BigUint::from(19u32)
}

fn bytes_to_big(value: &[u8; LIMBS]) -> BigUint {
    BigUint::from_bytes_le(value)
}

fn scalar_canonical(value: &[u8; LIMBS], label: &str) -> TexasAirResult<()> {
    if bytes_to_big(value) >= scalar_modulus() {
        return Err(TexasAirError::SpecViolation(format!(
            "slot-OR {label} is not a canonical scalar"
        )));
    }
    Ok(())
}

fn nonzero_scalar(value: &[u8; LIMBS], label: &str) -> TexasAirResult<()> {
    scalar_canonical(value, label)?;
    if bytes_to_big(value).is_zero() {
        return Err(TexasAirError::SpecViolation(format!(
            "slot-OR {label} must be non-zero"
        )));
    }
    Ok(())
}

fn field_inverse(value: &[u8; LIMBS]) -> TexasAirResult<[u8; LIMBS]> {
    let value_big = bytes_to_big(value);
    if value_big.is_zero() || value_big >= field_modulus() {
        return Err(TexasAirError::SpecViolation(
            "slot-OR challenge must be a non-zero canonical field element".into(),
        ));
    }
    let inverse = value_big.modpow(&(field_modulus() - BigUint::from(2u32)), &field_modulus());
    let encoded = inverse.to_bytes_le();
    let mut out = [0u8; LIMBS];
    out[..encoded.len()].copy_from_slice(&encoded);
    Ok(out)
}

fn fixed_point(value: &[u8], label: &str) -> TexasAirResult<[u8; LIMBS]> {
    value.try_into().map_err(|_| {
        TexasAirError::SpecViolation(format!("slot-OR {label} must be a 32-byte Ristretto point"))
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

fn validate_point(value: &[u8; LIMBS], label: &str, allow_identity: bool) -> TexasAirResult<()> {
    if !allow_identity && *value == [0; LIMBS] {
        return Err(TexasAirError::SpecViolation(format!(
            "slot-OR {label} cannot be the identity"
        )));
    }
    // The fixed addition builder authenticates canonical decoding and curve
    // membership.  Use a non-identity operand to keep the row schedule fixed.
    let _ = build_ristretto_fp_program_compressed_point_addition(value, &BASEPOINT)?;
    Ok(())
}

fn validate_statement(statement: &RistrettoSlotOrStatement) -> TexasAirResult<()> {
    if usize::from(statement.slot_index) >= SLOT_COUNT {
        return Err(TexasAirError::SpecViolation(
            "slot-OR slot index is out of bounds".into(),
        ));
    }
    validate_point(&statement.card, "card", false)?;
    validate_point(&statement.aggregate_pk, "aggregate key", false)?;
    validate_point(&statement.contribution.c1, "contribution.c1", false)?;
    validate_point(&statement.contribution.c2, "contribution.c2", false)?;
    for (branch, point) in statement.proof.commitment_g.iter().enumerate() {
        validate_point(point, &format!("commitment_g[{branch}]"), false)?;
    }
    for (branch, point) in statement.proof.commitment_pk.iter().enumerate() {
        validate_point(point, &format!("commitment_pk[{branch}]"), false)?;
    }
    scalar_canonical(&statement.proof.challenges[0], "challenge share 0")?;
    scalar_canonical(&statement.proof.challenges[1], "challenge share 1")?;
    scalar_canonical(&statement.proof.responses[0], "response 0")?;
    scalar_canonical(&statement.proof.responses[1], "response 1")?;
    nonzero_scalar(&statement.global_challenge, "global challenge")?;
    Ok(())
}

fn nonzero_program(
    challenge: &[u8; LIMBS],
    inverse: &[u8; LIMBS],
) -> TexasAirResult<crate::ristretto_fp_program_air::RistrettoFpProgram> {
    let mut builder = RistrettoFpProgramBuilder::new(&[*challenge, *inverse]);
    let output = builder.multiply(0, 1)?;
    let program = builder.finish(&[output])?;
    if program.values[usize::from(output)] != ONE {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "slot-OR global challenge inverse does not close".into(),
        ));
    }
    Ok(program)
}

fn scalar_inputs(
    statement: &RistrettoSlotOrStatement,
) -> TexasAirResult<Vec<([u8; LIMBS], [u8; LIMBS])>> {
    let p = &statement.proof;
    let target1 = build_ristretto_fp_program_compressed_point_addition(
        &statement.contribution.c2,
        &statement.card,
    )?
    .1;
    Ok(vec![
        (p.responses[0], BASEPOINT),
        (p.responses[0], statement.aggregate_pk),
        (p.responses[1], BASEPOINT),
        (p.responses[1], statement.aggregate_pk),
        (p.challenges[0], statement.contribution.c1),
        (p.challenges[1], statement.contribution.c1),
        (p.challenges[0], statement.contribution.c2),
        (p.challenges[1], target1),
    ])
}

fn scalar_outputs(
    archive: &ArchivedRistrettoFpProgramCompressedFixedWindowScalarMulBatchProof,
) -> TexasAirResult<[[u8; LIMBS]; SCALAR_MUL_COUNT]> {
    if archive.statements.len() != SCALAR_MUL_COUNT {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "slot-OR scalar multiplication count is not fixed".into(),
        ));
    }
    archive
        .statements
        .iter()
        .map(|statement| statement.output)
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| TexasAirError::ConstraintUnsatisfied("slot-OR scalar output shape".into()))
}

fn expected_additions(
    statement: &RistrettoSlotOrStatement,
    outputs: &[[u8; LIMBS]; SCALAR_MUL_COUNT],
) -> TexasAirResult<Vec<crate::ristretto_fp_program_air::RistrettoFpProgram>> {
    let p = &statement.proof;
    let target1 = build_ristretto_fp_program_compressed_point_addition(
        &statement.contribution.c2,
        &statement.card,
    )?;
    let g0 = build_ristretto_fp_program_compressed_point_addition(&p.commitment_g[0], &outputs[4])?;
    let g1 = build_ristretto_fp_program_compressed_point_addition(&p.commitment_g[1], &outputs[5])?;
    let pk0 =
        build_ristretto_fp_program_compressed_point_addition(&p.commitment_pk[0], &outputs[6])?;
    let pk1 =
        build_ristretto_fp_program_compressed_point_addition(&p.commitment_pk[1], &outputs[7])?;
    if g0.1 != outputs[0] || g1.1 != outputs[2] || pk0.1 != outputs[1] || pk1.1 != outputs[3] {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "slot-OR point equations do not close".into(),
        ));
    }
    Ok(vec![target1.0, g0.0, g1.0, pk0.0, pk1.0])
}

pub fn prove_ristretto_slot_or(
    statement: RistrettoSlotOrStatement,
) -> TexasAirResult<ArchivedRistrettoSlotOrProof> {
    validate_statement(&statement)?;
    let inverse = field_inverse(&statement.global_challenge)?;
    if inverse != statement.global_challenge_inverse {
        return Err(TexasAirError::SpecViolation(
            "slot-OR global challenge inverse is detached".into(),
        ));
    }
    let challenge_nonzero = prove_ristretto_fp_program(&nonzero_program(
        &statement.global_challenge,
        &statement.global_challenge_inverse,
    )?)?;
    let challenge_addition = prove_ristretto_scalar_addition(
        &statement.proof.challenges[0],
        &statement.proof.challenges[1],
    )?;
    if challenge_addition.c != statement.global_challenge {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "slot-OR challenge shares do not sum to global challenge".into(),
        ));
    }
    let inputs = scalar_inputs(&statement)?;
    let scalar_windows = inputs
        .iter()
        .map(|(scalar, _)| prove_ristretto_scalar_windows(scalar))
        .collect::<TexasAirResult<Vec<_>>>()?;
    let scalar_multiplications =
        prove_ristretto_fp_program_compressed_fixed_window_scalar_mul_batch(
            scalar_windows
                .into_iter()
                .zip(inputs.iter().map(|(_, base)| *base))
                .collect(),
        )?;
    let outputs = scalar_outputs(&scalar_multiplications)?;
    let additions = prove_ristretto_fp_program_batch(&expected_additions(&statement, &outputs)?)?;
    let archive = ArchivedRistrettoSlotOrProof {
        statement,
        challenge_nonzero,
        challenge_addition,
        scalar_multiplications,
        additions,
    };
    verify_ristretto_slot_or(&archive)?;
    Ok(archive)
}

pub fn verify_ristretto_slot_or(archive: &ArchivedRistrettoSlotOrProof) -> TexasAirResult<()> {
    validate_statement(&archive.statement)?;
    let expected_inverse = field_inverse(&archive.statement.global_challenge)?;
    if archive.statement.global_challenge_inverse != expected_inverse {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "slot-OR global challenge inverse is detached".into(),
        ));
    }
    if archive.challenge_nonzero.program
        != nonzero_program(
            &archive.statement.global_challenge,
            &archive.statement.global_challenge_inverse,
        )?
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "slot-OR non-zero challenge program is detached".into(),
        ));
    }
    verify_ristretto_fp_program(&archive.challenge_nonzero)?;
    if archive.challenge_addition.a != archive.statement.proof.challenges[0]
        || archive.challenge_addition.b != archive.statement.proof.challenges[1]
        || archive.challenge_addition.c != archive.statement.global_challenge
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "slot-OR scalar challenge-addition statement is detached".into(),
        ));
    }
    verify_ristretto_scalar_addition(&archive.challenge_addition)?;
    let inputs = scalar_inputs(&archive.statement)?;
    if archive.scalar_multiplications.statements.len() != SCALAR_MUL_COUNT {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "slot-OR scalar multiplication count mismatch".into(),
        ));
    }
    for (actual, (scalar, base)) in archive
        .scalar_multiplications
        .statements
        .iter()
        .zip(inputs.iter())
    {
        if actual.scalar_windows.scalar != *scalar || actual.base != *base {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "slot-OR scalar multiplication statement is detached".into(),
            ));
        }
        verify_ristretto_scalar_windows(&actual.scalar_windows)?;
    }
    verify_ristretto_fp_program_compressed_fixed_window_scalar_mul_batch(
        &archive.scalar_multiplications,
    )?;
    let outputs = scalar_outputs(&archive.scalar_multiplications)?;
    let programs = expected_additions(&archive.statement, &outputs)?;
    if archive.additions.programs != programs || archive.additions.programs.len() != ADDITION_COUNT
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "slot-OR point-addition rows are detached".into(),
        ));
    }
    verify_ristretto_fp_program_batch(&archive.additions)
}

fn expected_statement(
    request: &ReconstructionV3VerifyRequest,
    envelope: &RistrettoReconstructionProofEnvelope,
    challenges: &RistrettoSlotOrTranscriptChallenges,
    slot: usize,
) -> TexasAirResult<RistrettoSlotOrStatement> {
    validate_relation_challenges(
        challenges.statement_digest,
        envelope.statement_digest,
        &challenges.global_challenges,
    )?;
    let card = fixed_point(
        request.cards.get(slot).ok_or_else(|| {
            TexasAirError::SpecViolation("slot-OR card index is out of bounds".into())
        })?,
        "request.card",
    )?;
    let contribution = fixed_ciphertext(
        &request
            .contributions
            .get(slot)
            .ok_or_else(|| {
                TexasAirError::SpecViolation("slot-OR contribution index is out of bounds".into())
            })?
            .c1,
        &request.contributions[slot].c2,
        "request.contribution",
    )?;
    let aggregate_pk = fixed_point(&request.aggregate_pk, "request.aggregate_pk")?;
    let global_challenge = challenges.global_challenges[slot];
    nonzero_scalar(&global_challenge, "global challenge")?;
    Ok(RistrettoSlotOrStatement {
        statement_digest: envelope.statement_digest,
        slot_index: u8::try_from(slot)
            .map_err(|_| TexasAirError::SpecViolation("slot index overflow".into()))?,
        card,
        contribution,
        aggregate_pk,
        global_challenge,
        global_challenge_inverse: field_inverse(&global_challenge)?,
        proof: envelope.slot_or_proofs[slot],
    })
}

pub fn prove_ristretto_reconstruction_slot_or_batch(
    request: &ReconstructionV3VerifyRequest,
    challenges: &RistrettoSlotOrTranscriptChallenges,
) -> TexasAirResult<ArchivedRistrettoReconstructionSlotOrBatchProof> {
    let envelope = validate_ristretto_reconstruction_proof_wire(request)?;
    let slots = (0..SLOT_COUNT)
        .map(|slot| {
            prove_ristretto_slot_or(expected_statement(request, &envelope, challenges, slot)?)
        })
        .collect::<TexasAirResult<Vec<_>>>()?;
    let archive = ArchivedRistrettoReconstructionSlotOrBatchProof {
        statement_digest: envelope.statement_digest,
        slots,
    };
    verify_ristretto_reconstruction_slot_or_batch(request, challenges, &archive)?;
    Ok(archive)
}

fn validate_slot_or_batch_statement_binding(
    request: &ReconstructionV3VerifyRequest,
    challenges: &RistrettoSlotOrTranscriptChallenges,
    archive: &ArchivedRistrettoReconstructionSlotOrBatchProof,
) -> TexasAirResult<[RistrettoSlotOrStatement; SLOT_COUNT]> {
    validate_slot_or_batch_cardinality(archive)?;
    let envelope = validate_ristretto_reconstruction_proof_wire(request)?;
    if archive.statement_digest != envelope.statement_digest {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "slot-OR batch archive is detached from the proof envelope".into(),
        ));
    }
    let expected: [RistrettoSlotOrStatement; SLOT_COUNT] = (0..SLOT_COUNT)
        .map(|slot| expected_statement(request, &envelope, challenges, slot))
        .collect::<TexasAirResult<Vec<_>>>()?
        .try_into()
        .map_err(|_| {
            TexasAirError::ConstraintUnsatisfied("slot-OR statement count is not fixed".into())
        })?;
    for (actual, expected_statement) in archive.slots.iter().zip(expected.iter()) {
        if actual.statement != *expected_statement {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "slot-OR archive is detached from request, envelope, or transcript order".into(),
            ));
        }
    }
    Ok(expected)
}

fn validate_slot_or_batch_cardinality(
    archive: &ArchivedRistrettoReconstructionSlotOrBatchProof,
) -> TexasAirResult<()> {
    if archive.slots.len() != SLOT_COUNT {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "slot-OR batch archive count is not fixed".into(),
        ));
    }
    Ok(())
}

pub fn verify_ristretto_reconstruction_slot_or_batch(
    request: &ReconstructionV3VerifyRequest,
    challenges: &RistrettoSlotOrTranscriptChallenges,
    archive: &ArchivedRistrettoReconstructionSlotOrBatchProof,
) -> TexasAirResult<()> {
    validate_slot_or_batch_statement_binding(request, challenges, archive)?;
    for actual in &archive.slots {
        verify_ristretto_slot_or(actual)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use poker_protocol::crypto::curve::{Curve, CurveScalar, RistrettoCurve};

    fn compressed(point: <RistrettoCurve as Curve>::Point) -> [u8; LIMBS] {
        *point.compress().as_bytes()
    }

    fn fixture() -> RistrettoSlotOrStatement {
        let scalar = <RistrettoCurve as Curve>::Scalar::from_u64;
        let g = RistrettoCurve::base_g();
        let aggregate_secret = scalar(11);
        let card = g * scalar(19);
        let randomness = scalar(17);
        let aggregate_pk = g * aggregate_secret;
        let contribution_c1 = g * randomness;
        let contribution_c2 = -card + aggregate_pk * randomness;

        // Branch zero is simulated and branch one proves the negative-card
        // witness.  The values are deliberately deterministic so a failure
        // identifies a schedule or ordering regression rather than entropy.
        let real_nonce = scalar(23);
        let simulated_challenge = scalar(29);
        let simulated_response = scalar(31);
        let global_challenge = scalar(37);
        let real_challenge = global_challenge - simulated_challenge;
        let real_response = real_nonce + real_challenge * randomness;
        let commitment_g_simulated = g * simulated_response - contribution_c1 * simulated_challenge;
        let commitment_pk_simulated =
            aggregate_pk * simulated_response - contribution_c2 * simulated_challenge;
        let mut global_challenge_bytes = [0u8; LIMBS];
        global_challenge_bytes.copy_from_slice(global_challenge.as_bytes());
        let mut simulated_challenge_bytes = [0u8; LIMBS];
        simulated_challenge_bytes.copy_from_slice(simulated_challenge.as_bytes());
        let mut real_challenge_bytes = [0u8; LIMBS];
        real_challenge_bytes.copy_from_slice(real_challenge.as_bytes());
        let mut simulated_response_bytes = [0u8; LIMBS];
        simulated_response_bytes.copy_from_slice(simulated_response.as_bytes());
        let mut real_response_bytes = [0u8; LIMBS];
        real_response_bytes.copy_from_slice(real_response.as_bytes());

        RistrettoSlotOrStatement {
            statement_digest: [73; 32],
            slot_index: 9,
            card: compressed(card),
            contribution: RistrettoCiphertextProofWire {
                c1: compressed(contribution_c1),
                c2: compressed(contribution_c2),
            },
            aggregate_pk: compressed(aggregate_pk),
            global_challenge: global_challenge_bytes,
            global_challenge_inverse: field_inverse(&global_challenge_bytes).unwrap(),
            proof: RistrettoSlotOrProofWire {
                commitment_g: [
                    compressed(commitment_g_simulated),
                    compressed(g * real_nonce),
                ],
                commitment_pk: [
                    compressed(commitment_pk_simulated),
                    compressed(aggregate_pk * real_nonce),
                ],
                challenges: [simulated_challenge_bytes, real_challenge_bytes],
                responses: [simulated_response_bytes, real_response_bytes],
            },
        }
    }

    #[test]
    fn native_slot_or_fixture_closes_the_fixed_air_equation_schedule() {
        let statement = fixture();
        validate_statement(&statement).unwrap();
        let inputs = scalar_inputs(&statement).unwrap();
        assert_eq!(inputs.len(), SCALAR_MUL_COUNT);

        let scalar = <RistrettoCurve as Curve>::Scalar::from_u64;
        let g = RistrettoCurve::base_g();
        let aggregate_pk = g * scalar(11);
        let card = g * scalar(19);
        let randomness = scalar(17);
        let contribution_c1 = g * randomness;
        let contribution_c2 = -card + aggregate_pk * randomness;
        let global = scalar(37);
        let simulated_challenge = scalar(29);
        let real_challenge = global - simulated_challenge;
        let simulated_response = scalar(31);
        let real_response = scalar(23) + real_challenge * randomness;
        let outputs = [
            compressed(g * simulated_response),
            compressed(aggregate_pk * simulated_response),
            compressed(g * real_response),
            compressed(aggregate_pk * real_response),
            compressed(contribution_c1 * simulated_challenge),
            compressed(contribution_c1 * real_challenge),
            compressed(contribution_c2 * simulated_challenge),
            compressed((contribution_c2 + card) * real_challenge),
        ];
        assert_eq!(
            expected_additions(&statement, &outputs).unwrap().len(),
            ADDITION_COUNT
        );
    }

    #[test]
    fn fixture_rejects_challenge_share_or_equation_splice() {
        let statement = fixture();
        let scalar = <RistrettoCurve as Curve>::Scalar::from_u64;
        let g = RistrettoCurve::base_g();
        let aggregate_pk = g * scalar(11);
        let card = g * scalar(19);
        let randomness = scalar(17);
        let c1 = g * randomness;
        let c2 = -card + aggregate_pk * randomness;
        let global = scalar(37);
        let e0 = scalar(29);
        let e1 = global - e0;
        let outputs = [
            compressed(g * scalar(31)),
            compressed(aggregate_pk * scalar(31)),
            compressed(g * (scalar(23) + e1 * randomness)),
            compressed(aggregate_pk * (scalar(23) + e1 * randomness)),
            compressed(c1 * e0),
            compressed(c1 * e1),
            compressed(c2 * e0),
            compressed((c2 + card) * e1),
        ];
        let mut changed = statement.clone();
        changed.proof.challenges.swap(0, 1);
        assert_ne!(
            scalar_inputs(&changed).unwrap(),
            scalar_inputs(&fixture()).unwrap()
        );
        changed.proof.commitment_g[0] = compressed(g * scalar(41));
        assert!(expected_additions(&changed, &outputs).is_err());

        let mut changed = statement;
        changed.global_challenge[0] ^= 1;
        assert!(validate_statement(&changed).is_ok());
        assert_ne!(
            prove_ristretto_scalar_addition(
                &changed.proof.challenges[0],
                &changed.proof.challenges[1]
            )
            .unwrap()
            .c,
            changed.global_challenge
        );
    }

    #[test]
    fn batch_rejects_any_slot_count_other_than_52() {
        let archive = ArchivedRistrettoReconstructionSlotOrBatchProof {
            statement_digest: [0; 32],
            slots: Vec::new(),
        };
        assert!(validate_slot_or_batch_cardinality(&archive).is_err());
    }
}
