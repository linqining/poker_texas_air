//! Unified admission STARK skeleton (Path A recursive-aggregator prototype).
//!
//! One multi-component STARK folds the in-circuit admission components that
//! were previously separate proofs, each carrying its own FRI:
//!
//! 1. the dedicated fixed-window scalar-multiplication ladder component
//!    ([`crate::ristretto_scalar_mul_air::ScalarMulLadderAir`]) proving every
//!    point-equation scalar multiplication of the admission;
//! 2. the Bayer--Groth scalar-schedule component
//!    ([`crate::ristretto_scalar_program_air::ScalarProgramAir`]) proving the
//!    powers table / expected product / final check value;
//! 3. an admission binding row pinning the domain-separated admission digest
//!    (and its public scalars) inside the constrained trace.
//!
//! stwo's multi-component layout is forced by the constraint framework's
//! fixed indices, so the three trees are shared by kind: tree 0 carries every
//! component's preprocessed scope columns, tree 1 every original trace, tree
//! 2 every LogUp interaction layer.  The Fiat--Shamir sequence is therefore
//! `mix admission digest → tree 0 → tree 1 → draw both relation pairs → mix
//! both claimed sums → tree 2 → prove([ladder, scalar, binding])`, mirrored
//! exactly by the verifier.
//!
//! Trust model (the codebase's fail-closed discipline): the admission
//! statement is a deterministic function of its public fields, so the
//! verifier rebuilds every ladder schedule and the scalar schedule natively,
//! recomputes the shared scope tree, and rejects any detached statement
//! before running the single STARK.  The decode/encode Fp program segments
//! of a full Bayer--Groth point equation are not part of this skeleton yet;
//! they plug into the same three-tree layout as additional components.

#![allow(missing_docs)]

use bincode::Options;
use borsh::{BorshDeserialize, BorshSerialize};
use rayon::prelude::*;
use stwo::core::channel::Channel;
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::SecureField;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::poseidon252_merkle::Poseidon252MerkleChannel;
use stwo::core::vcs_lifted::poseidon252_merkle::Poseidon252MerkleHasher;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::pcs::CommitmentSchemeProver;
use stwo::prover::{ComponentProver, prove};
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
};

use crate::error::{TexasAirError, TexasAirResult};
use crate::ristretto_scalar_mul_air::{
    LadderSegment, RistrettoScalarMulLadderStatement, rebuild_statement,
};
use crate::ristretto_scalar_program_air::{
    RistrettoScalarProgram, ScalarProgramSegment, build_bayer_groth_scalar_schedule,
};

const LIMBS: usize = 32;
/// Single-row binding trace replicated over the 128-row domain floor.
const BINDING_LOG_SIZE: u32 = 7;
/// Sixteen digest limbs plus the admission tag (eight u32 limbs), the ladder
/// statement count, and the schedule deck size.
const BINDING_DIGEST_LIMBS: usize = 16;
const BINDING_TAG_LIMBS: usize = 8;
const BINDING_COLUMNS: usize = BINDING_DIGEST_LIMBS + BINDING_TAG_LIMBS + 2;
const ADMISSION_LOG_SIZE_FLOOR: u32 = 7;

/// One Bayer--Groth scalar-schedule specification: the transcript challenges
/// `(x, y, z, pc)` and the deck size.
#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AdmissionScheduleSpec {
    /// Powers challenge.
    pub powers_challenge: [u8; LIMBS],
    /// Product challenge `y`.
    pub product_y: [u8; LIMBS],
    /// Product challenge `z`.
    pub product_z: [u8; LIMBS],
    /// Final product challenge.
    pub product_challenge: [u8; LIMBS],
    /// Deck size (also the schedule length).
    pub deck_size: usize,
}

/// The public admission statement: a caller tag, the point-equation ladder
/// statements, and one Bayer--Groth scalar schedule.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AdmissionStatement {
    /// Caller-domain admission tag (for example a shuffle statement digest);
    /// mixed into the admission digest verbatim.
    pub tag: [u8; 32],
    /// Point-equation scalar multiplications; the scalar-window decomposition
    /// proofs stay owned by the caller.
    pub ladders: Vec<RistrettoScalarMulLadderStatement>,
    /// The single Bayer--Groth scalar schedule of this admission.
    pub schedule: AdmissionScheduleSpec,
}

/// Serialized unified admission STARK.
#[derive(Debug, Clone, PartialEq)]
pub struct ArchivedRistrettoAdmissionProof {
    /// The public statement (rebuilt deterministically at verify).
    pub statement: AdmissionStatement,
    /// Serialized multi-component Stwo proof.
    pub stark_proof_bytes: Vec<u8>,
    /// Claimed LogUp sum of the ladder component (4 M31 coordinates).
    pub ladder_claimed_sum: [u32; 4],
    /// Claimed LogUp sum of the scalar-schedule component (4 M31 coordinates).
    pub scalar_claimed_sum: [u32; 4],
}

const ADMISSION_ARCHIVE_MAGIC: [u8; 4] = *b"RSAD";
const ADMISSION_ARCHIVE_VERSION: u8 = 1;

impl BorshSerialize for ArchivedRistrettoAdmissionProof {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&ADMISSION_ARCHIVE_MAGIC)?;
        ADMISSION_ARCHIVE_VERSION.serialize(writer)?;
        self.statement.serialize(writer)?;
        self.stark_proof_bytes.serialize(writer)?;
        self.ladder_claimed_sum.serialize(writer)?;
        self.scalar_claimed_sum.serialize(writer)
    }
}

impl BorshDeserialize for ArchivedRistrettoAdmissionProof {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if magic != ADMISSION_ARCHIVE_MAGIC {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "admission archive magic mismatch",
            ));
        }
        let version = u8::deserialize_reader(reader)?;
        if version != ADMISSION_ARCHIVE_VERSION {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unsupported admission archive version {version}"),
            ));
        }
        Ok(Self {
            statement: AdmissionStatement::deserialize_reader(reader)?,
            stark_proof_bytes: Vec::<u8>::deserialize_reader(reader)?,
            ladder_claimed_sum: <[u32; 4]>::deserialize_reader(reader)?,
            scalar_claimed_sum: <[u32; 4]>::deserialize_reader(reader)?,
        })
    }
}

fn options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(64 * 1024 * 1024)
}

fn u32_words(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks(4)
        .map(|chunk| {
            let mut word = [0u8; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            u32::from_le_bytes(word)
        })
        .collect()
}

/// Domain-separated Blake2b digest of the admission statement, split into
/// sixteen M31 limbs.
fn admission_digest(statement: &AdmissionStatement) -> [u32; BINDING_DIGEST_LIMBS] {
    use blake2::digest::Digest;
    let mut hasher = blake2::Blake2b512::new();
    hasher.update(b"zchain.poker.admission.statement.v1");
    hasher.update(&statement.tag);
    hasher.update(&(statement.ladders.len() as u64).to_le_bytes());
    for ladder in &statement.ladders {
        hasher.update(&ladder.scalar);
        hasher.update(&ladder.windows);
        hasher.update(&ladder.base);
        hasher.update(&ladder.output);
    }
    hasher.update(&statement.schedule.powers_challenge);
    hasher.update(&statement.schedule.product_y);
    hasher.update(&statement.schedule.product_z);
    hasher.update(&statement.schedule.product_challenge);
    hasher.update(&(statement.schedule.deck_size as u64).to_le_bytes());
    let digest = hasher.finalize();
    core::array::from_fn(|index| {
        u32::from_le_bytes(
            digest[4 * index..4 * index + 4]
                .try_into()
                .expect("4 bytes"),
        )
    })
}

/// The single-row admission binding AIR: the trace carries the admission
/// digest limbs, the tag limbs, and the public scalars, each constrained
/// equal to the verifier-rebuilt binding.
#[derive(Clone)]
struct AdmissionBindingAir {
    log_size: u32,
    digest: [u32; BINDING_DIGEST_LIMBS],
    tag: [u32; BINDING_TAG_LIMBS],
    ladder_count: u32,
    deck_size: u32,
}

impl AdmissionBindingAir {
    fn new(statement: &AdmissionStatement) -> Self {
        Self {
            log_size: BINDING_LOG_SIZE,
            digest: admission_digest(statement),
            tag: u32_words(&statement.tag)
                .try_into()
                .expect("tag splits into eight u32 limbs"),
            ladder_count: statement.ladders.len() as u32,
            deck_size: statement.schedule.deck_size as u32,
        }
    }

    fn trace_row(&self) -> Vec<M31> {
        let mut row = Vec::with_capacity(BINDING_COLUMNS);
        for limb in self.digest {
            row.push(M31::from(limb));
        }
        for limb in self.tag {
            row.push(M31::from(limb));
        }
        row.push(M31::from(self.ladder_count));
        row.push(M31::from(self.deck_size));
        row
    }

    fn trace_columns(&self) -> crate::trace_gen::MethodTrace {
        let row = self.trace_row();
        let rows = 1usize << self.log_size;
        crate::trace_gen::MethodTrace::from_columns(
            self.log_size,
            row.into_iter().map(|value| vec![value; rows]).collect(),
        )
    }
}

impl FrameworkEval for AdmissionBindingAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let constants = self
            .digest
            .iter()
            .copied()
            .chain(self.tag.iter().copied())
            .chain([self.ladder_count, self.deck_size]);
        for expected in constants {
            let limb = eval.next_trace_mask();
            eval.add_constraint(limb - E::F::from(M31::from(expected)));
        }
        eval
    }
}

/// Rebuild every ladder schedule of the statement (rejecting detached
/// scalars, windows, bases, and outputs) plus the scalar schedule program.
fn rebuild_admission(
    statement: &AdmissionStatement,
) -> TexasAirResult<(
    Vec<Vec<crate::ristretto_scalar_mul_air::LadderStep>>,
    RistrettoScalarProgram,
)> {
    if statement.ladders.is_empty() {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "admission ladder statement set is empty".into(),
        ));
    }
    let schedules = statement
        .ladders
        .par_iter()
        .map(rebuild_statement)
        .map(|result| result.map(|(_, _, schedule)| schedule))
        .collect::<TexasAirResult<Vec<_>>>()?;
    let program = build_bayer_groth_scalar_schedule(
        &statement.schedule.powers_challenge,
        &statement.schedule.product_y,
        &statement.schedule.product_z,
        &statement.schedule.product_challenge,
        statement.schedule.deck_size,
    )?;
    Ok((schedules, program))
}

/// Interaction-column count of one LogUp segment (paired fractions, four M31
/// columns per secure column).
fn interaction_column_count(
    singles: usize,
    pairs: usize,
    range_stripes: usize,
    carry_stripes: usize,
) -> usize {
    (singles + pairs + range_stripes + carry_stripes).div_ceil(2) * 4
}

/// Prove one unified admission STARK over the ladder and scalar-schedule
/// components plus the binding row.
pub fn prove_ristretto_admission_stark(
    statement: AdmissionStatement,
) -> TexasAirResult<ArchivedRistrettoAdmissionProof> {
    let (schedules, program) = rebuild_admission(&statement)?;
    let mut ladder_segment = LadderSegment::build(&schedules)?;
    let mut scalar_segment = ScalarProgramSegment::build(&[program.clone()])?;
    let binding = AdmissionBindingAir::new(&statement);
    let binding_trace = binding.trace_columns();

    let config = crate::prover_context::protocol_pcs_config();
    let max_log = ladder_segment
        .log_size
        .max(scalar_segment.log_size)
        .max(BINDING_LOG_SIZE);
    let twiddles =
        crate::prover_context::simd_twiddles(max_log + config.fri_config.log_blowup_factor);
    let mut channel = stwo::core::channel::Poseidon252Channel::default();
    channel.mix_u64(0x7a63_6861_646d_6973);
    channel.mix_u32s(&admission_digest(&statement));
    let mut scheme =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::with_memory_pool(
            config,
            &twiddles,
            crate::prover_context::simd_base_column_pool(),
        );
    {
        let mut tree = scheme.tree_builder();
        tree.extend_evals(ladder_segment.scope.to_evaluations());
        tree.extend_evals(scalar_segment.scope.to_evaluations());
        tree.commit(&mut channel);
    }
    {
        let mut tree = scheme.tree_builder();
        tree.extend_evals(ladder_segment.trace.to_evaluations());
        tree.extend_evals(scalar_segment.trace.to_evaluations());
        tree.extend_evals(binding_trace.to_evaluations());
        tree.commit(&mut channel);
    }
    ladder_segment.interact(&mut channel);
    scalar_segment.interact(&mut channel, &program);
    channel.mix_felts(&[ladder_segment.claimed_sum, scalar_segment.claimed_sum]);
    {
        let mut tree = scheme.tree_builder();
        tree.extend_evals(ladder_segment.interaction.clone());
        tree.extend_evals(scalar_segment.interaction.clone());
        tree.commit(&mut channel);
    }

    let mut ids: Vec<PreProcessedColumnId> = ladder_segment.preprocessed_ids();
    ids.extend(scalar_segment.preprocessed_ids(&program));
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
    let ladder_component = ladder_segment.component(&mut allocator);
    let scalar_component = scalar_segment.component(&mut allocator, &program);
    let binding_component =
        FrameworkComponent::new(&mut allocator, binding, SecureField::from(0u32));
    let proof = prove(
        &[
            &ladder_component as &dyn ComponentProver<SimdBackend>,
            &scalar_component as &dyn ComponentProver<SimdBackend>,
            &binding_component as &dyn ComponentProver<SimdBackend>,
        ],
        &mut channel,
        scheme,
    )
    .map_err(|error| TexasAirError::StwoProverError(error.to_string()))?;
    let stark_proof_bytes = options()
        .serialize(&proof)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
    Ok(ArchivedRistrettoAdmissionProof {
        statement,
        stark_proof_bytes,
        ladder_claimed_sum: ladder_segment.claimed_sum.to_m31_array().map(|limb| limb.0),
        scalar_claimed_sum: scalar_segment.claimed_sum.to_m31_array().map(|limb| limb.0),
    })
}

/// Verify the unified admission STARK: rebuild every statement natively,
/// recompute the shared scope tree, and run the single multi-component
/// verification.
pub fn verify_ristretto_admission_stark(
    archive: &ArchivedRistrettoAdmissionProof,
) -> TexasAirResult<()> {
    type Proof = StarkProof<Poseidon252MerkleHasher>;
    let (schedules, program) = rebuild_admission(&archive.statement)?;
    let mut ladder_segment = LadderSegment::build(&schedules)?;
    let mut scalar_segment = ScalarProgramSegment::build(&[program.clone()])?;
    let binding = AdmissionBindingAir::new(&archive.statement);
    let proof: Proof = options()
        .deserialize(&archive.stark_proof_bytes)
        .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;

    let config = crate::prover_context::protocol_pcs_config();
    let max_log = ladder_segment
        .log_size
        .max(scalar_segment.log_size)
        .max(BINDING_LOG_SIZE);
    let twiddles =
        crate::prover_context::simd_twiddles(max_log + config.fri_config.log_blowup_factor);
    let mut trusted =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::with_memory_pool(
            config,
            &twiddles,
            crate::prover_context::simd_base_column_pool(),
        );
    let mut scope_channel = stwo::core::channel::Poseidon252Channel::default();
    {
        let mut tree = trusted.tree_builder();
        tree.extend_evals(ladder_segment.scope.to_evaluations());
        tree.extend_evals(scalar_segment.scope.to_evaluations());
        tree.commit(&mut scope_channel);
    }
    if proof.commitments.first().copied() != trusted.roots().first().copied() {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "admission public scope commitment mismatch".into(),
        ));
    }

    let mut channel = stwo::core::channel::Poseidon252Channel::default();
    channel.mix_u64(0x7a63_6861_646d_6973);
    channel.mix_u32s(&admission_digest(&archive.statement));
    let mut scheme =
        stwo::core::pcs::CommitmentSchemeVerifier::<Poseidon252MerkleChannel>::new(config);
    let mut pre_sizes = vec![ladder_segment.log_size; ladder_segment.scope.num_columns];
    pre_sizes.extend(vec![
        scalar_segment.log_size;
        scalar_segment.scope.num_columns
    ]);
    scheme.commit(proof.commitments[0], &pre_sizes, &mut channel);
    let mut trace_sizes = vec![ladder_segment.log_size; ladder_segment.trace.num_columns];
    trace_sizes.extend(vec![
        scalar_segment.log_size;
        scalar_segment.trace.num_columns
    ]);
    trace_sizes.extend(vec![BINDING_LOG_SIZE; BINDING_COLUMNS]);
    scheme.commit(proof.commitments[1], &trace_sizes, &mut channel);
    // Mirror the prover's relation draws; the interaction columns themselves
    // are never materialized on the verifier side, only their counts.
    ladder_segment.mirror_draw(&mut channel);
    scalar_segment.mirror_draw(&mut channel);
    let ladder_claimed = SecureField::from_m31_array(core::array::from_fn(|index| {
        M31::from(archive.ladder_claimed_sum[index])
    }));
    let scalar_claimed = SecureField::from_m31_array(core::array::from_fn(|index| {
        M31::from(archive.scalar_claimed_sum[index])
    }));
    channel.mix_felts(&[ladder_claimed, scalar_claimed]);
    let mut interaction_sizes = vec![ladder_segment.log_size; ladder_segment.interaction_columns()];
    interaction_sizes.extend(vec![
        scalar_segment.log_size;
        scalar_segment.interaction_columns(&program)
    ]);
    scheme.commit(proof.commitments[2], &interaction_sizes, &mut channel);

    let mut ids: Vec<PreProcessedColumnId> = ladder_segment.preprocessed_ids();
    ids.extend(scalar_segment.preprocessed_ids(&program));
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
    let ladder_component = ladder_segment.component(&mut allocator);
    let scalar_component = scalar_segment.component(&mut allocator, &program);
    let binding_component =
        FrameworkComponent::new(&mut allocator, binding, SecureField::from(0u32));
    stwo::core::verifier::verify(
        &[
            &ladder_component as &dyn ComponentProver<SimdBackend>,
            &scalar_component as &dyn ComponentProver<SimdBackend>,
            &binding_component as &dyn ComponentProver<SimdBackend>,
        ],
        &mut channel,
        &mut scheme,
        proof,
    )
    .map_err(|error| TexasAirError::ConstraintUnsatisfied(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ristretto_scalar_mul_air::prove_ristretto_scalar_mul_ladder_batch;
    use crate::ristretto_scalar_program_air::prove_ristretto_scalar_program;
    use crate::ristretto_scalar_windows_air::windows;

    fn basepoint() -> [u8; LIMBS] {
        [
            0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71, 0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00,
            0x51, 0x5f, 0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d, 0xb6, 0xa6, 0x59, 0x45,
            0xe0, 0x8d, 0x2d, 0x76,
        ]
    }

    fn scalar_bytes(value: u64) -> [u8; LIMBS] {
        let mut out = [0u8; LIMBS];
        out[..8].copy_from_slice(&value.to_le_bytes());
        out
    }

    fn sample_statement() -> AdmissionStatement {
        // Two point-equation multiplications against the basepoint plus one
        // small deck schedule.
        let first = scalar_bytes(7);
        let second = scalar_bytes(0x0123_4567_89ab_cdef);
        let ladder_archives = prove_ristretto_scalar_mul_ladder_batch(vec![
            (first, windows(&first), basepoint()),
            (second, windows(&second), basepoint()),
        ])
        .expect("ladder statements");
        AdmissionStatement {
            tag: [0xab; 32],
            ladders: ladder_archives.statements,
            schedule: AdmissionScheduleSpec {
                powers_challenge: scalar_bytes(7),
                product_y: scalar_bytes(9),
                product_z: scalar_bytes(11),
                product_challenge: scalar_bytes(13),
                deck_size: 12,
            },
        }
    }

    #[test]
    fn admission_stark_proves_and_verifies() {
        let statement = sample_statement();
        let started = std::time::Instant::now();
        let archive = prove_ristretto_admission_stark(statement.clone()).expect("admission STARK");
        let prove_elapsed = started.elapsed();
        let started = std::time::Instant::now();
        verify_ristretto_admission_stark(&archive).expect("admission verify");
        let verify_elapsed = started.elapsed();
        let proof_len = archive.stark_proof_bytes.len();
        eprintln!(
            "admission STARK (2 ladders + schedule deck 12): prove {prove_elapsed:?}, verify {verify_elapsed:?}, proof {proof_len} bytes"
        );

        // Reference: the same components as separate proofs.
        let started = std::time::Instant::now();
        let separate_ladders = prove_ristretto_scalar_mul_ladder_batch(
            statement
                .ladders
                .iter()
                .map(|ladder| (ladder.scalar, ladder.windows, ladder.base))
                .collect(),
        )
        .expect("separate ladder proof");
        let separate_schedule = prove_ristretto_scalar_program(&{
            let spec = &statement.schedule;
            build_bayer_groth_scalar_schedule(
                &spec.powers_challenge,
                &spec.product_y,
                &spec.product_z,
                &spec.product_challenge,
                spec.deck_size,
            )
            .expect("schedule program")
        })
        .expect("separate schedule proof");
        let separate_elapsed = started.elapsed();
        let started = std::time::Instant::now();
        crate::ristretto_scalar_mul_air::verify_ristretto_scalar_mul_ladder_batch(
            &separate_ladders,
        )
        .expect("separate ladder verify");
        crate::ristretto_scalar_program_air::verify_ristretto_scalar_program(&separate_schedule)
            .expect("separate schedule verify");
        let separate_verify = started.elapsed();
        let separate_bytes =
            separate_ladders.stark_proof_bytes.len() + separate_schedule.stark_proof_bytes.len();
        eprintln!(
            "separate proofs: prove {separate_elapsed:?}, verify {separate_verify:?}, proofs {separate_bytes} bytes (ladder {} + schedule {})",
            separate_ladders.stark_proof_bytes.len(),
            separate_schedule.stark_proof_bytes.len()
        );
    }

    #[test]
    fn admission_stark_rejects_detached_and_spliced_proofs() {
        let statement = sample_statement();
        let archive = prove_ristretto_admission_stark(statement.clone()).expect("admission STARK");
        assert!(verify_ristretto_admission_stark(&archive).is_ok());

        // A detached schedule challenge rebuilds a different program.
        let mut spliced = archive.clone();
        spliced.statement.schedule.product_y[0] ^= 1;
        assert!(verify_ristretto_admission_stark(&spliced).is_err());

        // A detached ladder output fails the native rebuild.
        let mut spliced = archive.clone();
        spliced.statement.ladders[0].output[3] ^= 1;
        assert!(verify_ristretto_admission_stark(&spliced).is_err());

        // A detached tag changes the admission digest and the binding row.
        let mut spliced = archive.clone();
        spliced.statement.tag[0] ^= 1;
        assert!(verify_ristretto_admission_stark(&spliced).is_err());

        // A dropped ladder statement detaches the scope commitment.
        let mut spliced = archive.clone();
        spliced.statement.ladders.pop();
        assert!(verify_ristretto_admission_stark(&spliced).is_err());

        // Spliced proof bytes fail the STARK (tamper consumed regions).
        let proof_len = archive.stark_proof_bytes.len();
        for position in [64, proof_len / 2] {
            let mut spliced = archive.clone();
            spliced.stark_proof_bytes[position] ^= 1;
            assert!(
                verify_ristretto_admission_stark(&spliced).is_err(),
                "splicing admission proof byte {position} must fail"
            );
        }

        // Spliced claimed sums fail the interaction commitment.
        let mut spliced = archive.clone();
        spliced.ladder_claimed_sum[1] ^= 1;
        assert!(verify_ristretto_admission_stark(&spliced).is_err());
        let mut spliced = archive.clone();
        spliced.scalar_claimed_sum[2] ^= 1;
        assert!(verify_ristretto_admission_stark(&spliced).is_err());
    }
}
