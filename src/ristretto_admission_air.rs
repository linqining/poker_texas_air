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
//! 3. the base-decode, accumulator-encode, and compressed-point accumulation
//!    Fp program components ([`crate::ristretto_fp_program_air`]) — together
//!    with the ladder segment these cover one complete point-equation family
//!    (decode → ladder → encode → accumulate) inside a single proof;
//! 4. an admission binding row pinning the domain-separated admission digest
//!    (and its public scalars) inside the constrained trace.
//!
//! stwo's multi-component layout is forced by the constraint framework's
//! fixed indices, so the three trees are shared by kind: tree 0 carries every
//! component's preprocessed scope columns, tree 1 every original trace, tree
//! 2 every LogUp interaction layer.  The Fiat--Shamir sequence is therefore
//! `mix admission digest → tree 0 → tree 1 → draw each segment's relation
//! pair → mix every claimed sum → tree 2 → prove(all components)`, mirrored
//! exactly by the verifier.
//!
//! Trust model (the codebase's fail-closed discipline): the admission
//! statement is a deterministic function of its public fields, so the
//! verifier rebuilds every ladder schedule (with its decode/encode
//! programs), every accumulation addition, and the scalar schedule natively,
//! recomputes the shared scope tree, and rejects any detached statement
//! before running the single STARK.  The accumulation-chain semantics (which
//! ladder outputs feed which additions, and what the final MSM value is)
//! stay with the caller's admission logic, exactly like the MSM layer.

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
use crate::prove_timing::TimingKind;
use crate::ristretto_fp_program_air::{
    FpProgramSegment, RistrettoFpProgram, build_ristretto_fp_program_compressed_point_addition,
};
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
/// statement count, the addition-row count, and the schedule deck size.
const BINDING_DIGEST_LIMBS: usize = 16;
const BINDING_TAG_LIMBS: usize = 8;
const BINDING_COLUMNS: usize = BINDING_DIGEST_LIMBS + BINDING_TAG_LIMBS + 4;

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

/// The Bayer--Groth product-argument recurrence specification: the final
/// product challenge and the masked responses whose mod-l derivation
/// (`recurrence[i] = pc·b[i+1] − b[i]·a[i+1]`, `d = b[0] − a[0]`) rides a
/// second scalar-program segment.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AdmissionRecurrenceSpec {
    /// Final product challenge.
    pub product_challenge: [u8; LIMBS],
    /// Masked Sigma responses `b`.
    pub b_response: Vec<[u8; LIMBS]>,
    /// Masked Sigma responses `a`.
    pub a_response: Vec<[u8; LIMBS]>,
}

/// One public compressed-point accumulation row `left + right = output`.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AdmissionAdditionRow {
    /// Compressed left operand.
    pub left: [u8; LIMBS],
    /// Compressed right operand.
    pub right: [u8; LIMBS],
    /// Compressed output.
    pub output: [u8; LIMBS],
}

/// The public admission statement: a caller tag, the point-equation ladder
/// statements, the accumulation rows, and one Bayer--Groth scalar schedule.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AdmissionStatement {
    /// Caller-domain admission tag (for example a shuffle statement digest);
    /// mixed into the admission digest verbatim.
    pub tag: [u8; 32],
    /// Point-equation scalar multiplications; the scalar-window decomposition
    /// proofs stay owned by the caller.
    pub ladders: Vec<RistrettoScalarMulLadderStatement>,
    /// Compressed-point accumulation rows (may be empty).
    pub additions: Vec<AdmissionAdditionRow>,
    /// The Bayer--Groth scalar schedules of this admission (player-proof
    /// admissions carry none; a whole-hand admission carries one per
    /// folded shuffle, batched by deck shape at segment build).
    pub schedules: Vec<AdmissionScheduleSpec>,
    /// The Bayer--Groth product-argument recurrences (one per folded
    /// shuffle).
    pub recurrences: Vec<AdmissionRecurrenceSpec>,
    /// Folded Poseidon2-M31 transcript chains, when present (Path A
    /// Flock-elimination prototype; see `ristretto_poseidon2_air`).
    pub poseidon2: Option<crate::ristretto_poseidon2_air::Poseidon2ChainSpec>,
}

/// Serialized unified admission STARK.
#[derive(Debug, Clone, PartialEq)]
pub struct ArchivedRistrettoAdmissionProof {
    /// The public statement (rebuilt deterministically at verify).
    pub statement: AdmissionStatement,
    /// Serialized multi-component Stwo proof.
    pub stark_proof_bytes: Vec<u8>,
    /// Claimed LogUp sums, one per LogUp-bearing component, in segment
    /// order: ladder, schedule?, recurrence?, decode, encode, additions?
    /// (4 M31 coordinates each).
    pub claimed_sums: Vec<[u32; 4]>,
}

const ADMISSION_ARCHIVE_MAGIC: [u8; 4] = *b"RSAD";
const ADMISSION_ARCHIVE_VERSION: u8 = 5;

impl BorshSerialize for ArchivedRistrettoAdmissionProof {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&ADMISSION_ARCHIVE_MAGIC)?;
        ADMISSION_ARCHIVE_VERSION.serialize(writer)?;
        self.statement.serialize(writer)?;
        self.stark_proof_bytes.serialize(writer)?;
        self.claimed_sums.serialize(writer)
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
            claimed_sums: Vec::<[u32; 4]>::deserialize_reader(reader)?,
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
/// sixteen u32 limbs.
fn admission_digest(statement: &AdmissionStatement) -> [u32; BINDING_DIGEST_LIMBS] {
    use blake2::digest::Digest;
    let mut hasher = blake2::Blake2b512::new();
    hasher.update(b"zchain.poker.admission.statement.v2");
    hasher.update(&statement.tag);
    hasher.update(&(statement.ladders.len() as u64).to_le_bytes());
    for ladder in &statement.ladders {
        hasher.update(&ladder.scalar);
        hasher.update(&ladder.windows);
        hasher.update(&ladder.base);
        hasher.update(&ladder.output);
    }
    hasher.update(&(statement.additions.len() as u64).to_le_bytes());
    for addition in &statement.additions {
        hasher.update(&addition.left);
        hasher.update(&addition.right);
        hasher.update(&addition.output);
    }
    hasher.update(&(statement.schedules.len() as u64).to_le_bytes());
    for schedule in &statement.schedules {
        hasher.update(b"schedule");
        hasher.update(&schedule.powers_challenge);
        hasher.update(&schedule.product_y);
        hasher.update(&schedule.product_z);
        hasher.update(&schedule.product_challenge);
        hasher.update(&(schedule.deck_size as u64).to_le_bytes());
    }
    hasher.update(&(statement.recurrences.len() as u64).to_le_bytes());
    for recurrence in &statement.recurrences {
        hasher.update(b"recurrence");
        hasher.update(&recurrence.product_challenge);
        for value in &recurrence.b_response {
            hasher.update(value);
        }
        for value in &recurrence.a_response {
            hasher.update(value);
        }
    }
    match &statement.poseidon2 {
        Some(spec) => {
            hasher.update(b"poseidon2");
            hasher.update(&(spec.initial_states.len() as u64).to_le_bytes());
            for state in &spec.initial_states {
                for value in state {
                    hasher.update(&value.to_le_bytes());
                }
            }
            hasher.update(&spec.chain_length.to_le_bytes());
            hasher.update(&(spec.absorbed_words.len() as u64).to_le_bytes());
            for words in &spec.absorbed_words {
                for word in words {
                    hasher.update(&word.to_le_bytes());
                }
            }
        }
        None => hasher.update(b"no-poseidon2"),
    }
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
    addition_count: u32,
    schedule_count: u32,
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
            addition_count: statement.additions.len() as u32,
            schedule_count: statement.schedules.len() as u32,
        }
    }

    fn trace_columns(&self) -> crate::trace_gen::MethodTrace {
        let mut row = Vec::with_capacity(BINDING_COLUMNS);
        for limb in self.digest {
            row.push(M31::from(limb));
        }
        for limb in self.tag {
            row.push(M31::from(limb));
        }
        row.push(M31::from(self.ladder_count));
        row.push(M31::from(self.addition_count));
        row.push(M31::from(self.schedule_count));
        row.push(M31::from(u32::from(ADMISSION_ARCHIVE_VERSION)));
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
            .chain([
                self.ladder_count,
                self.addition_count,
                self.schedule_count,
                u32::from(ADMISSION_ARCHIVE_VERSION),
            ]);
        for expected in constants {
            let limb = eval.next_trace_mask();
            eval.add_constraint(limb - E::F::from(M31::from(expected)));
        }
        eval
    }
}

/// The deterministic rebuild of one admission statement: every ladder
/// schedule (with its decode/encode programs), every accumulation addition
/// program, and the scalar schedule program.
struct AdmissionRebuilt {
    schedules: Vec<Vec<crate::ristretto_scalar_mul_air::LadderStep>>,
    codec_programs: Vec<RistrettoFpProgram>,
    addition_programs: Vec<RistrettoFpProgram>,
    /// Same-shape schedule programs, one group per distinct deck shape
    /// (each group batches into ONE scalar segment).
    schedule_programs: Vec<Vec<RistrettoScalarProgram>>,
    /// Same-shape recurrence programs, one group per distinct response
    /// length.
    recurrence_programs: Vec<Vec<RistrettoScalarProgram>>,
    poseidon2_spec: Option<crate::ristretto_poseidon2_air::Poseidon2ChainSpec>,
}

fn rebuild_admission(statement: &AdmissionStatement) -> TexasAirResult<AdmissionRebuilt> {
    if statement.ladders.is_empty() {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "admission ladder statement set is empty".into(),
        ));
    }
    let rebuilt_ladders = statement
        .ladders
        .par_iter()
        .map(rebuild_statement)
        .collect::<TexasAirResult<Vec<_>>>()?;
    let schedules = rebuilt_ladders
        .iter()
        .map(|(_, schedule)| schedule.clone())
        .collect::<Vec<_>>();
    let codec_programs = rebuilt_ladders
        .iter()
        .map(|(codec, _)| codec.clone())
        .collect::<Vec<_>>();
    let addition_programs = statement
        .additions
        .par_iter()
        .map(|row| {
            let (program, expected_output) =
                build_ristretto_fp_program_compressed_point_addition(&row.left, &row.right)?;
            if row.output != expected_output {
                return Err(TexasAirError::ConstraintUnsatisfied(
                    "admission accumulation row is detached from its operands".into(),
                ));
            }
            Ok(program)
        })
        .collect::<TexasAirResult<Vec<_>>>()?;
    let schedule_programs = statement
        .schedules
        .par_iter()
        .map(|schedule| {
            build_bayer_groth_scalar_schedule(
                &schedule.powers_challenge,
                &schedule.product_y,
                &schedule.product_z,
                &schedule.product_challenge,
                schedule.deck_size,
            )
        })
        .collect::<TexasAirResult<Vec<_>>>()?;
    // Batch same-shape schedules into one segment per deck shape
    // (deterministic ascending group order).
    let mut schedule_groups: Vec<(usize, Vec<RistrettoScalarProgram>)> = Vec::new();
    for (spec, program) in statement.schedules.iter().zip(schedule_programs) {
        match schedule_groups.iter_mut().find(|(deck, _)| *deck == spec.deck_size) {
            Some((_, group)) => group.push(program),
            None => schedule_groups.push((spec.deck_size, vec![program])),
        }
    }
    schedule_groups.sort_by_key(|(deck, _)| *deck);
    let schedule_programs: Vec<Vec<RistrettoScalarProgram>> =
        schedule_groups.into_iter().map(|(_, group)| group).collect();

    let recurrence_programs = statement
        .recurrences
        .par_iter()
        .map(|recurrence| {
            crate::ristretto_scalar_program_air::build_bayer_groth_recurrence_program(
                &recurrence.product_challenge,
                &recurrence.b_response,
                &recurrence.a_response,
            )
        })
        .collect::<TexasAirResult<Vec<_>>>()?;
    let mut recurrence_groups: Vec<(usize, Vec<RistrettoScalarProgram>)> = Vec::new();
    for (spec, program) in statement
        .recurrences
        .iter()
        .zip(recurrence_programs)
    {
        let length = spec.b_response.len();
        match recurrence_groups.iter_mut().find(|(len, _)| *len == length) {
            Some((_, group)) => group.push(program),
            None => recurrence_groups.push((length, vec![program])),
        }
    }
    recurrence_groups.sort_by_key(|(length, _)| *length);
    let recurrence_programs: Vec<Vec<RistrettoScalarProgram>> =
        recurrence_groups.into_iter().map(|(_, group)| group).collect();

    Ok(AdmissionRebuilt {
        schedules,
        codec_programs,
        addition_programs,
        schedule_programs,
        recurrence_programs,
        poseidon2_spec: statement.poseidon2.clone(),
    })
}

// ---------------------------------------------------------------------------
// Phase timing (TEXAS_PROVE_TIMING): per-segment attribution of the shared
// tree commits (evaluation conversion + interpolation), the LogUp
// interaction build, and the outer prove/verify phases. Inert — a single
// relaxed atomic read per phase — when the env var is absent.
// ---------------------------------------------------------------------------

type AdmissionTreeBuilder<'a, 'b> =
    stwo::prover::pcs::TreeBuilder<'a, 'b, SimdBackend, Poseidon252MerkleChannel>;

type AdmissionEval = stwo::prover::poly::circle::CircleEvaluation<
    SimdBackend,
    M31,
    stwo::prover::poly::BitReversedOrder,
>;

fn timed_phase<T>(
    label: &str,
    kind: TimingKind,
    columns: Option<usize>,
    body: impl FnOnce() -> T,
) -> T {
    if !crate::prove_timing::enabled() {
        return body();
    }
    let started = std::time::Instant::now();
    let outcome = body();
    crate::prove_timing::record(format!("admission.{label}"), kind, started, columns);
    outcome
}

/// Commit one segment's columns into a shared tree under timing: the label
/// covers both the evaluation conversion and the per-column interpolation.
fn extend_timed(
    tree: &mut AdmissionTreeBuilder<'_, '_>,
    label: &str,
    kind: TimingKind,
    make_evals: impl FnOnce() -> Vec<AdmissionEval>,
) {
    if !crate::prove_timing::enabled() {
        tree.extend_evals(make_evals());
        return;
    }
    let started = std::time::Instant::now();
    let evals = make_evals();
    let columns = evals.len();
    tree.extend_evals(evals);
    crate::prove_timing::record(
        format!("admission.commit.{label}"),
        kind,
        started,
        Some(columns),
    );
}

/// The ordered segment set of one admission. Empty Fp segments are skipped
/// deterministically (currently only the additions segment can be empty).
struct AdmissionSegments {
    ladder: LadderSegment,
    /// One scalar segment per schedule shape group (same-shape programs
    /// share a single FRI-sized batch).
    schedule: Vec<ScalarProgramSegment>,
    /// One scalar segment per recurrence shape group.
    recurrence: Vec<ScalarProgramSegment>,
    codec: FpProgramSegment,
    additions: Option<FpProgramSegment>,
    /// Texas method-AIR folds (Layer-1): trace columns only — a method AIR
    /// carries no preprocessed columns and no LogUp layer, so each fold's
    /// component is a zero-claim construction supplied by its factory.
    /// Multiple method AIRs (lifecycle/hand/betting/settlement) share the
    /// single admission STARK.
    texas: Vec<(crate::trace_gen::MethodTrace, [u32; BINDING_DIGEST_LIMBS])>,
    /// Folded Poseidon2-M31 transcript chains (optional segment).
    poseidon2: Option<crate::ristretto_poseidon2_air::Poseidon2Segment>,
}

impl AdmissionSegments {
    fn build(rebuilt: &AdmissionRebuilt) -> TexasAirResult<Self> {
        Ok(Self {
            ladder: LadderSegment::build(&rebuilt.schedules)?,
            schedule: rebuilt
                .schedule_programs
                .iter()
                .enumerate()
                .map(|(group, programs)| {
                    ScalarProgramSegment::build(
                        programs,
                        &format!("ristretto.admission.scalar.schedule.{group}.scope.v1"),
                    )
                })
                .collect::<TexasAirResult<Vec<_>>>()?,
            recurrence: rebuilt
                .recurrence_programs
                .iter()
                .enumerate()
                .map(|(group, programs)| {
                    ScalarProgramSegment::build(
                        programs,
                        &format!("ristretto.admission.scalar.recurrence.{group}.scope.v1"),
                    )
                })
                .collect::<TexasAirResult<Vec<_>>>()?,
            codec: FpProgramSegment::build(
                &rebuilt.codec_programs,
                "ristretto.admission.fp.codec.scope.v1",
            )?,
            additions: if rebuilt.addition_programs.is_empty() {
                None
            } else {
                Some(FpProgramSegment::build(
                    &rebuilt.addition_programs,
                    "ristretto.admission.fp.additions.scope.v1",
                )?)
            },
            texas: Vec::new(),
            poseidon2: rebuilt
                .poseidon2_spec
                .as_ref()
                .map(crate::ristretto_poseidon2_air::Poseidon2Segment::build),
        })
    }

    /// Verifier-side build (⑥b): every segment skips its witness-heavy
    /// trace materialization; only the shared scope tree and the trace
    /// shapes are produced, which is all the verification path reads.
    fn build_shape_only(rebuilt: &AdmissionRebuilt) -> TexasAirResult<Self> {
        Ok(Self {
            ladder: LadderSegment::build_shape_only(&rebuilt.schedules)?,
            schedule: rebuilt
                .schedule_programs
                .iter()
                .enumerate()
                .map(|(group, programs)| {
                    ScalarProgramSegment::build_shape_only(
                        programs,
                        &format!("ristretto.admission.scalar.schedule.{group}.scope.v1"),
                    )
                })
                .collect::<TexasAirResult<Vec<_>>>()?,
            recurrence: rebuilt
                .recurrence_programs
                .iter()
                .enumerate()
                .map(|(group, programs)| {
                    ScalarProgramSegment::build_shape_only(
                        programs,
                        &format!("ristretto.admission.scalar.recurrence.{group}.scope.v1"),
                    )
                })
                .collect::<TexasAirResult<Vec<_>>>()?,
            codec: FpProgramSegment::build_shape_only(
                &rebuilt.codec_programs,
                "ristretto.admission.fp.codec.scope.v1",
            )?,
            additions: if rebuilt.addition_programs.is_empty() {
                None
            } else {
                Some(FpProgramSegment::build_shape_only(
                    &rebuilt.addition_programs,
                    "ristretto.admission.fp.additions.scope.v1",
                )?)
            },
            texas: Vec::new(),
            poseidon2: rebuilt
                .poseidon2_spec
                .as_ref()
                .map(crate::ristretto_poseidon2_air::Poseidon2Segment::build),
        })
    }

    fn max_log(&self) -> u32 {
        let mut log = self
            .ladder
            .log_size
            .max(self.codec.log_size)
            .max(BINDING_LOG_SIZE);
        if let Some(additions) = &self.additions {
            log = log.max(additions.log_size);
        }
        for schedule in &self.schedule {
            log = log.max(schedule.log_size);
        }
        for recurrence in &self.recurrence {
            log = log.max(recurrence.log_size);
        }
        if let Some(poseidon2) = &self.poseidon2 {
            log = log.max(poseidon2.log_size);
        }
        for (trace, _) in &self.texas {
            log = log.max(trace.log_size);
        }
        log
    }

    fn interact(
        &mut self,
        channel: &mut stwo::core::channel::Poseidon252Channel,
        rebuilt: &AdmissionRebuilt,
    ) {
        let kind = TimingKind::Prove;
        timed_phase("interact.ladder", kind, None, || self.ladder.interact(channel));
        for (group, schedule) in self.schedule.iter_mut().enumerate() {
            let program = &rebuilt.schedule_programs[group][0];
            timed_phase("interact.schedule", kind, None, || {
                schedule.interact(channel, program)
            });
        }
        for (group, recurrence) in self.recurrence.iter_mut().enumerate() {
            let program = &rebuilt.recurrence_programs[group][0];
            timed_phase("interact.recurrence", kind, None, || {
                recurrence.interact(channel, program)
            });
        }
        if let Some(poseidon2) = &mut self.poseidon2 {
            timed_phase("interact.poseidon2", kind, None, || {
                poseidon2.interact(channel)
            });
        }
        timed_phase("interact.codec", kind, None, || {
            self.codec.interact(channel, &rebuilt.codec_programs[0])
        });
        if let Some(additions) = &mut self.additions {
            timed_phase("interact.additions", kind, None, || {
                additions.interact(channel, &rebuilt.addition_programs[0])
            });
        }
    }

    fn mirror_draw(&mut self, channel: &mut stwo::core::channel::Poseidon252Channel) {
        self.ladder.mirror_draw(channel);
        for schedule in &mut self.schedule {
            schedule.mirror_draw(channel);
        }
        for recurrence in &mut self.recurrence {
            recurrence.mirror_draw(channel);
        }
        if let Some(poseidon2) = &mut self.poseidon2 {
            poseidon2.mirror_draw(channel);
        }
        self.codec.mirror_draw(channel);
        if let Some(additions) = &mut self.additions {
            additions.mirror_draw(channel);
        }
    }

    /// Restore each segment's LogUp claimed sum from the archive, in the
    /// fixed order of [`Self::claimed_sums`].  The shape-only verifier build
    /// leaves every sum at zero (no interaction columns are materialized),
    /// but the OODS constraint evaluation reads the sum through the
    /// components' cumsum shift, so a segment whose LogUp does not telescope
    /// to zero — the Poseidon2 chain segment's `Σ (1/d_init − 1/d_digest)`
    /// never does — must see its real prover-side sum.
    fn restore_claimed_sums(&mut self, sums: &[SecureField]) {
        let mut slot = 0;
        self.ladder.claimed_sum = sums[slot];
        slot += 1;
        for schedule in &mut self.schedule {
            schedule.claimed_sum = sums[slot];
            slot += 1;
        }
        for recurrence in &mut self.recurrence {
            recurrence.claimed_sum = sums[slot];
            slot += 1;
        }
        if let Some(poseidon2) = &mut self.poseidon2 {
            poseidon2.claimed_sum = sums[slot];
            slot += 1;
        }
        self.codec.claimed_sum = sums[slot];
        slot += 1;
        if let Some(additions) = &mut self.additions {
            additions.claimed_sum = sums[slot];
        }
        debug_assert_eq!(slot, sums.len() - usize::from(self.additions.is_some()));
    }

    fn claimed_sum_count(&self) -> usize {
        2 + self.schedule.len()
            + self.recurrence.len()
            + usize::from(self.poseidon2.is_some())
            + usize::from(self.additions.is_some())
    }

    fn claimed_sums(&self) -> Vec<SecureField> {
        let mut sums = vec![self.ladder.claimed_sum];
        for schedule in &self.schedule {
            sums.push(schedule.claimed_sum);
        }
        for recurrence in &self.recurrence {
            sums.push(recurrence.claimed_sum);
        }
        if let Some(poseidon2) = &self.poseidon2 {
            sums.push(poseidon2.claimed_sum);
        }
        sums.push(self.codec.claimed_sum);
        if let Some(additions) = &self.additions {
            sums.push(additions.claimed_sum);
        }
        sums
    }

    fn commit_scope(&self, tree: &mut AdmissionTreeBuilder<'_, '_>, kind: TimingKind) {
        extend_timed(tree, "scope.ladder", kind, || self.ladder.scope.to_evaluations());
        for schedule in &self.schedule {
            extend_timed(tree, "scope.schedule", kind, || schedule.scope.to_evaluations());
        }
        for recurrence in &self.recurrence {
            extend_timed(tree, "scope.recurrence", kind, || {
                recurrence.scope.to_evaluations()
            });
        }
        if let Some(poseidon2) = &self.poseidon2 {
            extend_timed(tree, "scope.poseidon2", kind, || {
                poseidon2.scope.to_evaluations()
            });
        }
        extend_timed(tree, "scope.codec", kind, || self.codec.scope.to_evaluations());
        if let Some(additions) = &self.additions {
            extend_timed(tree, "scope.additions", kind, || additions.scope.to_evaluations());
        }
    }

    fn commit_trace(
        &self,
        tree: &mut AdmissionTreeBuilder<'_, '_>,
        binding_trace: &crate::trace_gen::MethodTrace,
        kind: TimingKind,
    ) {
        extend_timed(tree, "trace.ladder", kind, || self.ladder.trace.to_evaluations());
        for schedule in &self.schedule {
            extend_timed(tree, "trace.schedule", kind, || schedule.trace.to_evaluations());
        }
        for recurrence in &self.recurrence {
            extend_timed(tree, "trace.recurrence", kind, || {
                recurrence.trace.to_evaluations()
            });
        }
        if let Some(poseidon2) = &self.poseidon2 {
            extend_timed(tree, "trace.poseidon2", kind, || {
                poseidon2.trace.to_evaluations()
            });
        }
        extend_timed(tree, "trace.codec", kind, || self.codec.trace.to_evaluations());
        if let Some(additions) = &self.additions {
            extend_timed(tree, "trace.additions", kind, || additions.trace.to_evaluations());
        }
        for (trace, _) in &self.texas {
            extend_timed(tree, "trace.texas", kind, || trace.to_evaluations());
        }
        extend_timed(tree, "trace.binding", kind, || binding_trace.to_evaluations());
    }

    fn commit_interaction(&self, tree: &mut AdmissionTreeBuilder<'_, '_>) {
        let kind = TimingKind::Prove;
        extend_timed(tree, "interaction.ladder", kind, || {
            self.ladder.interaction.clone()
        });
        for schedule in &self.schedule {
            extend_timed(tree, "interaction.schedule", kind, || {
                schedule.interaction.clone()
            });
        }
        for recurrence in &self.recurrence {
            extend_timed(tree, "interaction.recurrence", kind, || {
                recurrence.interaction.clone()
            });
        }
        if let Some(poseidon2) = &self.poseidon2 {
            extend_timed(tree, "interaction.poseidon2", kind, || {
                poseidon2.interaction.clone()
            });
        }
        extend_timed(tree, "interaction.codec", kind, || {
            self.codec.interaction.clone()
        });
        if let Some(additions) = &self.additions {
            extend_timed(tree, "interaction.additions", kind, || {
                additions.interaction.clone()
            });
        }
    }

    fn scope_sizes(&self) -> Vec<u32> {
        let mut sizes = vec![vec![self.ladder.log_size; self.ladder.scope.num_columns]];
        for schedule in &self.schedule {
            sizes.push(vec![schedule.log_size; schedule.scope.num_columns]);
        }
        for recurrence in &self.recurrence {
            sizes.push(vec![recurrence.log_size; recurrence.scope.num_columns]);
        }
        if let Some(poseidon2) = &self.poseidon2 {
            sizes.push(vec![poseidon2.log_size; poseidon2.scope.num_columns]);
        }
        sizes.push(vec![self.codec.log_size; self.codec.scope.num_columns]);
        let mut sizes = sizes.concat();
        if let Some(additions) = &self.additions {
            sizes.extend(vec![additions.log_size; additions.scope.num_columns]);
        }
        sizes
    }

    fn trace_sizes(&self) -> Vec<u32> {
        let mut sizes = vec![vec![self.ladder.log_size; self.ladder.trace.num_columns]];
        for schedule in &self.schedule {
            sizes.push(vec![schedule.log_size; schedule.trace.num_columns]);
        }
        for recurrence in &self.recurrence {
            sizes.push(vec![recurrence.log_size; recurrence.trace.num_columns]);
        }
        if let Some(poseidon2) = &self.poseidon2 {
            sizes.push(vec![poseidon2.log_size; poseidon2.trace.num_columns]);
        }
        sizes.push(vec![self.codec.log_size; self.codec.trace.num_columns]);
        let mut sizes = sizes.concat();
        if let Some(additions) = &self.additions {
            sizes.extend(vec![additions.log_size; additions.trace.num_columns]);
        }
        for (trace, _) in &self.texas {
            sizes.extend(vec![trace.log_size; trace.num_columns]);
        }
        sizes.extend(vec![BINDING_LOG_SIZE; BINDING_COLUMNS]);
        sizes
    }

    fn interaction_sizes(&self, rebuilt: &AdmissionRebuilt) -> Vec<u32> {
        let mut sizes = vec![vec![
            self.ladder.log_size;
            self.ladder.interaction_columns()
        ]];
        for (group, schedule) in self.schedule.iter().enumerate() {
            let program = &rebuilt.schedule_programs[group][0];
            sizes.push(vec![
                schedule.log_size;
                schedule.interaction_columns(program)
            ]);
        }
        for (group, recurrence) in self.recurrence.iter().enumerate() {
            let program = &rebuilt.recurrence_programs[group][0];
            sizes.push(vec![
                recurrence.log_size;
                recurrence.interaction_columns(program)
            ]);
        }
        if let Some(poseidon2) = &self.poseidon2 {
            sizes.push(vec![poseidon2.log_size; poseidon2.interaction_columns()]);
        }
        sizes.push(vec![
            self.codec.log_size;
            self.codec
                .interaction_columns(&rebuilt.codec_programs[0])
        ]);
        let mut sizes = sizes.concat();
        if let Some(additions) = &self.additions {
            sizes.extend(vec![
                additions.log_size;
                additions
                    .interaction_columns(&rebuilt.addition_programs[0])
            ]);
        }
        sizes
    }

    fn preprocessed_ids(&self, rebuilt: &AdmissionRebuilt) -> Vec<PreProcessedColumnId> {
        let mut ids = self.ladder.preprocessed_ids();
        for (group, schedule) in self.schedule.iter().enumerate() {
            let program = &rebuilt.schedule_programs[group][0];
            ids.extend(schedule.preprocessed_ids(program));
        }
        for (group, recurrence) in self.recurrence.iter().enumerate() {
            let program = &rebuilt.recurrence_programs[group][0];
            ids.extend(recurrence.preprocessed_ids(program));
        }
        if let Some(poseidon2) = &self.poseidon2 {
            ids.extend(poseidon2.preprocessed_ids());
        }
        ids.extend(self.codec.preprocessed_ids(&rebuilt.codec_programs[0]));
        if let Some(additions) = &self.additions {
            ids.extend(additions.preprocessed_ids(&rebuilt.addition_programs[0]));
        }
        ids
    }

    #[allow(clippy::type_complexity)]
    fn components(
        &self,
        allocator: &mut TraceLocationAllocator,
        rebuilt: &AdmissionRebuilt,
        binding: AdmissionBindingAir,
        texas_components: &mut dyn Iterator<
            Item = &(
                dyn Fn(&mut TraceLocationAllocator) -> Box<dyn ComponentProver<SimdBackend>>
                    + Send
                    + Sync
            ),
        >,
    ) -> Vec<Box<dyn ComponentProver<SimdBackend>>> {
        let mut components: Vec<Box<dyn ComponentProver<SimdBackend>>> =
            vec![Box::new(self.ladder.component(allocator))];
        for (group, schedule) in self.schedule.iter().enumerate() {
            let program = &rebuilt.schedule_programs[group][0];
            components.push(Box::new(schedule.component(allocator, program)));
        }
        for (group, recurrence) in self.recurrence.iter().enumerate() {
            let program = &rebuilt.recurrence_programs[group][0];
            components.push(Box::new(recurrence.component(allocator, program)));
        }
        if let Some(poseidon2) = &self.poseidon2 {
            components.push(Box::new(poseidon2.component(allocator)));
        }
        components.push(Box::new(
            self.codec.component(allocator, &rebuilt.codec_programs[0]),
        ));
        if let Some(additions) = &self.additions {
            components.push(Box::new(
                additions.component(allocator, &rebuilt.addition_programs[0]),
            ));
        }
        for factory in texas_components {
            components.push(factory(allocator));
        }
        components.push(Box::new(FrameworkComponent::new(
            allocator,
            binding,
            SecureField::from(0u32),
        )));
        components
    }
}

/// Prove one unified admission STARK over the ladder, scalar-schedule,
/// decode, encode, and accumulation components plus the binding row.
pub fn prove_ristretto_admission_stark(
    statement: AdmissionStatement,
) -> TexasAirResult<ArchivedRistrettoAdmissionProof> {
    prove_admission_inner(statement, &[])
}

/// One Layer-1 method fold bound to its component factory: the trace
/// enters shared tree 1, the ingredient digest binds the statement through
/// the channel, and the factory builds the zero-claim `BoundAir` component
/// against the shared allocator.
pub struct TexasFold {
    pub trace: crate::trace_gen::MethodTrace,
    pub digest: [u32; BINDING_DIGEST_LIMBS],
    pub factory: Box<
        dyn Fn(&mut TraceLocationAllocator) -> Box<dyn ComponentProver<SimdBackend>>
            + Send
            + Sync,
    >,
}

/// Fiat--Shamir binding of the method folds: domain tag, fold count, then
/// every ingredient digest in order (mirrored by the verifier).
fn mix_texas_domain(channel: &mut stwo::core::channel::Poseidon252Channel, texas: &[TexasFold]) {
    channel.mix_u64(0x7a63_6861_7465_7861);
    channel.mix_u64(texas.len() as u64);
    for fold in texas {
        channel.mix_u32s(&fold.digest);
    }
}

fn prove_admission_inner(
    statement: AdmissionStatement,
    texas: &[TexasFold],
) -> TexasAirResult<ArchivedRistrettoAdmissionProof> {
    let kind = TimingKind::Prove;
    let rebuilt = timed_phase("rebuild", kind, None, || rebuild_admission(&statement))?;
    let mut segments =
        timed_phase("segments.build", kind, None, || AdmissionSegments::build(&rebuilt))?;
    segments.texas = texas.iter().map(|fold| (fold.trace.clone(), fold.digest)).collect();
    let binding = AdmissionBindingAir::new(&statement);
    let binding_trace = timed_phase("binding.trace", kind, None, || binding.trace_columns());

    let config = crate::prover_context::protocol_pcs_config();
    let twiddles = crate::prover_context::simd_twiddles(
        segments.max_log() + config.fri_config.log_blowup_factor,
    );
    let mut channel = stwo::core::channel::Poseidon252Channel::default();
    channel.mix_u64(0x7a63_6861_646d_6973);
    channel.mix_u32s(&admission_digest(&statement));
    mix_texas_domain(&mut channel, texas);
    let mut scheme =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::with_memory_pool(
            config,
            &twiddles,
            crate::prover_context::simd_base_column_pool(),
        );
    {
        let mut tree = scheme.tree_builder();
        segments.commit_scope(&mut tree, kind);
        timed_phase("tree-commit.scope", kind, None, || tree.commit(&mut channel));
    }
    {
        let mut tree = scheme.tree_builder();
        segments.commit_trace(&mut tree, &binding_trace, kind);
        timed_phase("tree-commit.trace", kind, None, || tree.commit(&mut channel));
    }
    timed_phase("interact-total", kind, None, || {
        segments.interact(&mut channel, &rebuilt)
    });
    let sums = segments.claimed_sums();
    channel.mix_felts(&sums);
    {
        let mut tree = scheme.tree_builder();
        segments.commit_interaction(&mut tree);
        timed_phase("tree-commit.interaction", kind, None, || tree.commit(&mut channel));
    }

    let ids = segments.preprocessed_ids(&rebuilt);
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
    let factories: Vec<
        &(
            dyn Fn(&mut TraceLocationAllocator) -> Box<dyn ComponentProver<SimdBackend>>
                + Send
                + Sync
        ),
    > = texas.iter().map(|fold| &*fold.factory).collect();
    let components = segments.components(&mut allocator, &rebuilt, binding, &mut factories.into_iter());
    let component_refs: Vec<&dyn ComponentProver<SimdBackend>> =
        components.iter().map(|component| &**component).collect();
    let proof = timed_phase("prove.stwo", kind, None, || {
        prove(&component_refs, &mut channel, scheme)
    })
    .map_err(|error| TexasAirError::StwoProverError(error.to_string()))?;
    let stark_proof_bytes = timed_phase("serialize", kind, None, || {
        options().serialize(&proof)
    })
    .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;
    let claimed_sums = sums
        .iter()
        .map(|sum| sum.to_m31_array().map(|limb| limb.0))
        .collect::<Vec<_>>();
    Ok(ArchivedRistrettoAdmissionProof {
        statement,
        stark_proof_bytes,
        claimed_sums,
    })
}

/// Verify the unified admission STARK: rebuild every statement natively,
/// recompute the shared scope tree, and run the single multi-component
/// verification.
pub fn verify_ristretto_admission_stark(
    archive: &ArchivedRistrettoAdmissionProof,
) -> TexasAirResult<()> {
    verify_admission_inner(archive, &[])
}

fn verify_admission_inner(
    archive: &ArchivedRistrettoAdmissionProof,
    texas: &[TexasFold],
) -> TexasAirResult<()> {
    type Proof = StarkProof<Poseidon252MerkleHasher>;
    let kind = TimingKind::Verify;
    let rebuilt = timed_phase("rebuild", kind, None, || rebuild_admission(&archive.statement))?;
    let mut segments = timed_phase("segments.build", kind, None, || {
        AdmissionSegments::build_shape_only(&rebuilt)
    })?;
    segments.texas = texas.iter().map(|fold| (fold.trace.clone(), fold.digest)).collect();
    let binding = AdmissionBindingAir::new(&archive.statement);
    let proof: Proof = timed_phase("deserialize", kind, None, || {
        options().deserialize(&archive.stark_proof_bytes)
    })
    .map_err(|error| TexasAirError::SerializationError(error.to_string()))?;

    let config = crate::prover_context::protocol_pcs_config();
    let twiddles = crate::prover_context::simd_twiddles(
        segments.max_log() + config.fri_config.log_blowup_factor,
    );
    let mut trusted =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::with_memory_pool(
            config,
            &twiddles,
            crate::prover_context::simd_base_column_pool(),
        );
    let mut scope_channel = stwo::core::channel::Poseidon252Channel::default();
    {
        let mut tree = trusted.tree_builder();
        segments.commit_scope(&mut tree, kind);
        timed_phase("tree-commit.scope", kind, None, || tree.commit(&mut scope_channel));
    }
    if proof.commitments.first().copied() != trusted.roots().first().copied() {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "admission public scope commitment mismatch".into(),
        ));
    }

    let mut channel = stwo::core::channel::Poseidon252Channel::default();
    channel.mix_u64(0x7a63_6861_646d_6973);
    channel.mix_u32s(&admission_digest(&archive.statement));
    mix_texas_domain(&mut channel, texas);
    let mut scheme =
        stwo::core::pcs::CommitmentSchemeVerifier::<Poseidon252MerkleChannel>::new(config);
    scheme.commit(proof.commitments[0], &segments.scope_sizes(), &mut channel);
    scheme.commit(proof.commitments[1], &segments.trace_sizes(), &mut channel);
    // Mirror the prover's relation draws; the interaction columns themselves
    // are never materialized on the verifier side, only their counts.
    segments.mirror_draw(&mut channel);
    let sum_count = segments.claimed_sum_count();
    if archive.claimed_sums.len() != sum_count {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "admission claimed-sum count is detached from its segment set".into(),
        ));
    }
    let sums: Vec<SecureField> = (0..sum_count)
        .map(|slot| {
            SecureField::from_m31_array(core::array::from_fn(|index| {
                M31::from(archive.claimed_sums[slot][index])
            }))
        })
        .collect();
    segments.restore_claimed_sums(&sums);
    channel.mix_felts(&sums);
    scheme.commit(
        proof.commitments[2],
        &segments.interaction_sizes(&rebuilt),
        &mut channel,
    );

    let ids = segments.preprocessed_ids(&rebuilt);
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
    let factories: Vec<
        &(
            dyn Fn(&mut TraceLocationAllocator) -> Box<dyn ComponentProver<SimdBackend>>
                + Send
                + Sync
        ),
    > = texas.iter().map(|fold| &*fold.factory).collect();
    let components = segments.components(&mut allocator, &rebuilt, binding, &mut factories.into_iter());
    let component_refs: Vec<&dyn stwo::core::air::Component> = components
        .iter()
        .map(|component| component.as_ref() as &dyn stwo::core::air::Component)
        .collect();
    timed_phase("verify.stwo", kind, None, || {
        stwo::core::verifier::verify(&component_refs, &mut channel, &mut scheme, proof)
    })
    .map_err(|error| TexasAirError::ConstraintUnsatisfied(error.to_string()))
}

// ===========================================================================
// Real Bayer--Groth admission wiring (Path A roadmap item 3).
// ===========================================================================

use poker_protocol::crypto::curve::{Curve, CurvePoint, CurveScalar, RistrettoCurve};
use poker_protocol_bg::BayerGrothShuffleProof;
use poker_protocol_core::ElGamalCiphertextGeneric;

type BgPoint = <RistrettoCurve as Curve>::Point;
type BgScalar = <RistrettoCurve as Curve>::Scalar;
type BgCiphertext = ElGamalCiphertextGeneric<RistrettoCurve>;

/// The component set one Bayer--Groth admission constrains, matching
/// [`crate::ristretto_shuffle_air::RistrettoAirV2ShuffleInCircuitComponents`].
#[derive(Debug, Clone)]
pub struct BgAdmissionComponents {
    /// Caller-domain statement digest used as the admission tag.
    pub statement_digest: [u8; 32],
    /// Input deck ciphertexts.
    pub input: Vec<BgCiphertext>,
    /// Output deck ciphertexts.
    pub output: Vec<BgCiphertext>,
    /// Aggregate public key.
    pub public_key: BgPoint,
    /// The Bayer--Groth proof under admission.
    pub proof: BayerGrothShuffleProof<RistrettoCurve>,
    /// Transcript challenges in derivation order `[x, y, z, mexp, product]`.
    pub challenges: Vec<BgScalar>,
}

/// `scalar_pow(base, exponent)` over the Ristretto scalar field (the BG
/// prover/verifier helper, local because the crate keeps it private).
fn bg_scalar_pow(mut base: BgScalar, mut exponent: usize) -> BgScalar {
    let mut result = BgScalar::one();
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = result * base;
        }
        base = base * base;
        exponent >>= 1;
    }
    result
}

fn bg_encode_point(point: &BgPoint) -> [u8; LIMBS] {
    let mut out = [0u8; LIMBS];
    let bytes = CurvePoint::compress(point);
    out.copy_from_slice(&bytes.as_ref()[..LIMBS]);
    out
}

fn bg_decode_point(bytes: &[u8; LIMBS]) -> TexasAirResult<BgPoint> {
    BgPoint::from_compressed(bytes).ok_or_else(|| {
        TexasAirError::ConstraintUnsatisfied("BG admission point failed to decode".into())
    })
}

fn bg_scalar_bytes(scalar: &BgScalar) -> [u8; LIMBS] {
    let mut out = [0u8; LIMBS];
    let bytes = CurveScalar::as_bytes(scalar);
    out.copy_from_slice(&bytes[..LIMBS]);
    out
}

/// Host-side builder that decomposes every Bayer--Groth point equation into
/// ladder statements (scalar multiplications) and compressed-point
/// accumulation rows, tracking native encoding equalities as it goes.
#[derive(Default)]
struct PointEquationBuilder {
    ladders: Vec<RistrettoScalarMulLadderStatement>,
    additions: Vec<([u8; LIMBS], [u8; LIMBS], [u8; LIMBS])>,
    equalities: Vec<([u8; LIMBS], [u8; LIMBS])>,
}

impl PointEquationBuilder {
    /// Append one scalar multiplication `scalar · base` and return its
    /// compressed output.
    fn mul(&mut self, scalar: &BgScalar, base: &BgPoint) -> [u8; LIMBS] {
        let scalar = bg_scalar_bytes(scalar);
        let base = bg_encode_point(base);
        let output = bg_encode_point(
            &(bg_decode_point(&base).expect("base decodes") * scalar_value(&scalar)),
        );
        let windows = crate::ristretto_scalar_windows_air::windows(&scalar);
        self.ladders.push(RistrettoScalarMulLadderStatement {
            scalar,
            windows,
            base,
            output,
        });
        output
    }

    /// Append one compressed-point addition and return its output.
    fn add(&mut self, left: &[u8; LIMBS], right: &[u8; LIMBS]) -> TexasAirResult<[u8; LIMBS]> {
        let output = bg_encode_point(&(bg_decode_point(left)? + bg_decode_point(right)?));
        self.additions.push((*left, *right, output));
        Ok(output)
    }

    /// Fold `Σ scalars[i] · bases[i]` through ladder rows and accumulation
    /// additions, returning the chain's compressed output.
    fn msm(&mut self, scalars: &[BgScalar], bases: &[BgPoint]) -> TexasAirResult<[u8; LIMBS]> {
        if scalars.len() != bases.len() || scalars.is_empty() {
            return Err(TexasAirError::SpecViolation(
                "BG admission MSM shape mismatch".into(),
            ));
        }
        let mut accumulator = self.mul(&scalars[0], &bases[0]);
        for (scalar, base) in scalars.iter().zip(bases.iter()).skip(1) {
            let term = self.mul(scalar, base);
            accumulator = self.add(&accumulator, &term)?;
        }
        Ok(accumulator)
    }

    /// Record one native encoding equality the admission must check.
    fn eq(&mut self, lhs: [u8; LIMBS], rhs: [u8; LIMBS]) {
        self.equalities.push((lhs, rhs));
    }

    fn check_equalities(&self) -> TexasAirResult<()> {
        for (index, (lhs, rhs)) in self.equalities.iter().enumerate() {
            if lhs != rhs {
                return Err(TexasAirError::ConstraintUnsatisfied(format!(
                    "BG admission point equality {index} does not hold"
                )));
            }
        }
        Ok(())
    }
}

fn base_point_value() -> BgPoint {
    RistrettoCurve::base_g()
}

fn scalar_value(bytes: &[u8; LIMBS]) -> BgScalar {
    <BgScalar as CurveScalar>::from_canonical_bytes(bytes)
        .expect("ladder scalar bytes are canonical")
}

/// Decompose one Bayer--Groth admission into the unified admission statement
/// (ladders, accumulation rows, scalar schedule) plus the native encoding
/// equalities and scalar checks that complete the verification.
///
/// The decomposition mirrors every public equation of
/// `BayerGrothShuffleProof::verify`: the multi-exponentiation ciphertext
/// check, the commitment-key vector/scalar commitments, the ciphertext
/// re-randomization identity, and both product-argument checks.  The scalar
/// product check `b_response[n-1] == pc · ∏(y·i + x^i − z)` rides the BG
/// scalar schedule STARK; the recurrence values of the second product check
/// stay native (a mod-l program segment is the follow-up).
fn decompose_bg_admission(
    components: &BgAdmissionComponents,
) -> TexasAirResult<(AdmissionStatement, Vec<([u8; LIMBS], [u8; LIMBS])>)> {
    let n = components.input.len();
    if components.output.len() != n || n < 2 || n > 62 {
        return Err(TexasAirError::SpecViolation(
            "BG admission deck size is outside the supported range".into(),
        ));
    }
    if components.challenges.len() != 5 {
        return Err(TexasAirError::SpecViolation(
            "BG admission requires exactly five transcript challenges".into(),
        ));
    }
    let powers_challenge = components.challenges[0];
    let product_y = components.challenges[1];
    let product_z = components.challenges[2];
    let mexp_challenge = components.challenges[3];
    let product_challenge = components.challenges[4];

    // Deterministic commitment key (mirrors the BG crate's private derive).
    let h = RistrettoCurve::hash_to_curve(b"poker/bg12/v2/H");
    let generators = (0..n)
        .map(|index| {
            RistrettoCurve::hash_to_curve(format!("poker/bg12/v2/G/{n}/{index}").as_bytes())
        })
        .collect::<Vec<_>>();
    let g = base_point_value();

    let mut builder = PointEquationBuilder::default();
    let mexp = &components.proof.multi_exponentiation;
    let product = &components.proof.product;

    // Equation 1: mexp.ciphertext_1 == ciphertext_msm(input, public powers).
    let powers = (1..=n)
        .map(|i| bg_scalar_pow(powers_challenge, i))
        .collect::<Vec<_>>();
    let msm_input_c1 = builder.msm(
        &powers,
        &components.input.iter().map(|ct| ct.c1).collect::<Vec<_>>(),
    )?;
    let msm_input_c2 = builder.msm(
        &powers,
        &components.input.iter().map(|ct| ct.c2).collect::<Vec<_>>(),
    )?;
    builder.eq(msm_input_c1, bg_encode_point(&mexp.ciphertext_1.c1));
    builder.eq(msm_input_c2, bg_encode_point(&mexp.ciphertext_1.c2));

    // Equation 2: c_permuted_powers·mc + c_alpha == vector_commit(alpha, cr).
    let permuted_powers_scaled = builder.mul(&mexp_challenge, &components.proof.c_permuted_powers);
    let commitment_lhs = builder.add(&permuted_powers_scaled, &bg_encode_point(&mexp.c_alpha))?;
    let mut commitment_scalars = mexp.alpha_response.clone();
    commitment_scalars.push(mexp.commitment_response);
    let mut commitment_bases = generators.clone();
    commitment_bases.push(h);
    let commitment_rhs = builder.msm(&commitment_scalars, &commitment_bases)?;
    builder.eq(commitment_lhs, commitment_rhs);

    // Equation 3: c_beta == G·beta + H·beta_blinding.
    let beta_scaled = builder.mul(&mexp.beta, &g);
    let beta_blinding_scaled = builder.mul(&mexp.beta_blinding_response, &h);
    let scalar_commit = builder.add(&beta_scaled, &beta_blinding_scaled)?;
    builder.eq(bg_encode_point(&mexp.c_beta), scalar_commit);

    // Equation 4: ciphertext_0 + mc·ciphertext_1 == (G·rerand + msm_alpha(output).c1,
    //                                           G·beta + pk·rerand + msm_alpha(output).c2).
    let ciphertext_1_c1_scaled = builder.mul(&mexp_challenge, &mexp.ciphertext_1.c1);
    let ciphertext_1_c2_scaled = builder.mul(&mexp_challenge, &mexp.ciphertext_1.c2);
    let lhs_c1 = builder.add(
        &bg_encode_point(&mexp.ciphertext_0.c1),
        &ciphertext_1_c1_scaled,
    )?;
    let lhs_c2 = builder.add(
        &bg_encode_point(&mexp.ciphertext_0.c2),
        &ciphertext_1_c2_scaled,
    )?;
    let output_msm_c1 = builder.msm(
        &mexp.alpha_response,
        &components.output.iter().map(|ct| ct.c1).collect::<Vec<_>>(),
    )?;
    let output_msm_c2 = builder.msm(
        &mexp.alpha_response,
        &components.output.iter().map(|ct| ct.c2).collect::<Vec<_>>(),
    )?;
    let rerandomization_scaled = builder.mul(&mexp.rerandomization_response, &g);
    let rhs_c1 = builder.add(&rerandomization_scaled, &output_msm_c1)?;
    let beta_message_scaled = builder.mul(&mexp.beta, &g);
    let rerandomization_key_scaled =
        builder.mul(&mexp.rerandomization_response, &components.public_key);
    let rhs_c2_inner = builder.add(&beta_message_scaled, &rerandomization_key_scaled)?;
    let rhs_c2 = builder.add(&rhs_c2_inner, &output_msm_c2)?;
    builder.eq(lhs_c1, rhs_c1);
    builder.eq(lhs_c2, rhs_c2);

    // Equation 5: c_d + (c_a + c_minus_z)·pc == vector_commit(a_response, r_response)
    // with c_a = c_permutation·y + c_permuted_powers and c_minus_z the
    // constant-vector commitment of −z.
    let permutation_scaled = builder.mul(&product_y, &components.proof.c_permutation);
    let c_a = builder.add(
        &permutation_scaled,
        &bg_encode_point(&components.proof.c_permuted_powers),
    )?;
    let minus_z = vec![-product_z; n];
    let c_minus_z = builder.msm(&minus_z, &generators)?;
    let c_a_plus_minus_z = builder.add(&c_a, &c_minus_z)?;
    let scaled_sum = builder.mul(&product_challenge, &bg_decode_point(&c_a_plus_minus_z)?);
    let product_lhs = builder.add(&bg_encode_point(&product.c_d), &scaled_sum)?;
    let mut product_scalars = product.a_response.clone();
    product_scalars.push(product.r_response);
    let mut product_bases = generators.clone();
    product_bases.push(h);
    let product_rhs = builder.msm(&product_scalars, &product_bases)?;
    builder.eq(product_lhs, product_rhs);

    // Equation 6: c_delta + c_capital_delta·pc == vector_commit(recurrence, s_response)
    // with recurrence[i] = pc·b[i+1] − b[i]·a[i+1] (native scalar arithmetic;
    // a mod-l program segment is the follow-up).
    let mut recurrence = vec![BgScalar::zero(); n];
    for index in 0..n - 1 {
        recurrence[index] = product_challenge * product.b_response[index + 1]
            - product.b_response[index] * product.a_response[index + 1];
    }
    let capital_delta_scaled = builder.mul(&product_challenge, &product.c_capital_delta);
    let recurrence_lhs = builder.add(&bg_encode_point(&product.c_delta), &capital_delta_scaled)?;
    let mut recurrence_scalars = recurrence;
    recurrence_scalars.push(product.s_response);
    let mut recurrence_bases = generators.clone();
    recurrence_bases.push(h);
    let recurrence_rhs = builder.msm(&recurrence_scalars, &recurrence_bases)?;
    builder.eq(recurrence_lhs, recurrence_rhs);

    // Equation 7 (scalar): b_response[n-1] == pc · ∏(y·i + x^i − z); the
    // product schedule rides the mod-l program STARK, this checks it natively.
    let expected_final = (1..=n)
        .map(|index| {
            product_y * BgScalar::from_u64(index as u64) + bg_scalar_pow(powers_challenge, index)
                - product_z
        })
        .fold(BgScalar::one(), |accumulator, value| accumulator * value);
    let expected_final = product_challenge * expected_final;
    if bg_scalar_bytes(&expected_final) != bg_scalar_bytes(&product.b_response[n - 1]) {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "BG admission scalar product check does not hold".into(),
        ));
    }
    // Equation 8 (scalar): b_response[0] == a_response[0].
    if bg_scalar_bytes(&product.b_response[0]) != bg_scalar_bytes(&product.a_response[0]) {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "BG admission initial response check does not hold".into(),
        ));
    }
    builder.check_equalities()?;

    let statement = AdmissionStatement {
        poseidon2: None,
        tag: components.statement_digest,
        ladders: builder.ladders,
        additions: builder
            .additions
            .into_iter()
            .map(|(left, right, output)| AdmissionAdditionRow {
                left,
                right,
                output,
            })
            .collect(),
        schedules: vec![AdmissionScheduleSpec {
            powers_challenge: bg_scalar_bytes(&powers_challenge),
            product_y: bg_scalar_bytes(&product_y),
            product_z: bg_scalar_bytes(&product_z),
            product_challenge: bg_scalar_bytes(&product_challenge),
            deck_size: n,
        }],
        recurrences: vec![AdmissionRecurrenceSpec {
            product_challenge: bg_scalar_bytes(&product_challenge),
            b_response: product.b_response.iter().map(bg_scalar_bytes).collect(),
            a_response: product.a_response.iter().map(bg_scalar_bytes).collect(),
        }],
    };
    Ok((statement, builder.equalities))
}

/// Prove the unified admission STARK for one Bayer--Groth component set.
///
/// The decomposition validates every BG equation natively (point equalities
/// and scalar checks) before proving, so a detached or invalid proof never
/// reaches the STARK.
pub fn prove_ristretto_bg_admission_components(
    components: &BgAdmissionComponents,
) -> TexasAirResult<ArchivedRistrettoAdmissionProof> {
    let (statement, _) = decompose_bg_admission(components)?;
    prove_ristretto_admission_stark(statement)
}

/// Verify the unified admission STARK for one Bayer--Groth component set:
/// re-decompose (which re-validates every equation natively), require the
/// archived statement to be exactly the derived one, and verify the STARK.
pub fn verify_ristretto_bg_admission_components(
    components: &BgAdmissionComponents,
    archive: &ArchivedRistrettoAdmissionProof,
) -> TexasAirResult<()> {
    let (statement, _) = decompose_bg_admission(components)?;
    if archive.statement != statement {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "BG admission statement is detached from its component set".into(),
        ));
    }
    verify_ristretto_admission_stark(archive)
}

/// Prove one Bayer--Groth shuffle under the Poseidon2-M31 transcript and
/// return its admission components together with the replayed transcript
/// chain (public data only — the challenge schedule, no witness, no
/// permutation hint, HVZK preserved).  This is the Flock-free shuffle
/// path for whole-hand admissions.
pub fn prove_bg_admission_poseidon2(
    input: &[BgCiphertext],
    output: &[BgCiphertext],
    permutation: &[usize],
    rerandomizers: &[BgScalar],
    public_key: &BgPoint,
    statement_digest: [u8; 32],
    rng: &mut (impl rand_core::CryptoRng + rand_core::RngCore),
) -> TexasAirResult<(BgAdmissionComponents, crate::ristretto_poseidon2_air::Poseidon2ChainSpec)>
{
    use crate::ristretto_poseidon2_transcript::Poseidon2M31Transcript;
    let context = poker_protocol::ristretto_air::RISTRETTO_AIR_V2_SHUFFLE_CONTEXT;
    let mut prove_transcript = Poseidon2M31Transcript::new(context);
    let proof = BayerGrothShuffleProof::<RistrettoCurve>::prove(
        input,
        output,
        permutation,
        rerandomizers,
        public_key,
        rng,
        &mut prove_transcript,
    )
    .map_err(|error| TexasAirError::ConstraintUnsatisfied(error.to_string()))?;
    let mut replay = Poseidon2M31Transcript::new(context);
    proof
        .verify(input, output, public_key, &mut replay)
        .map_err(|error| TexasAirError::ConstraintUnsatisfied(error.to_string()))?;
    let images = replay.challenge_images();
    if images.len() != 5 {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "BG verify replay must derive exactly five challenges".into(),
        ));
    }
    let challenges = images
        .iter()
        .map(|image| {
            <BgScalar as CurveScalar>::from_canonical_bytes(image).ok_or_else(|| {
                TexasAirError::ConstraintUnsatisfied(
                    "BG challenge image is not a canonical scalar".into(),
                )
            })
        })
        .collect::<TexasAirResult<Vec<_>>>()?;
    Ok((
        BgAdmissionComponents {
            statement_digest,
            input: input.to_vec(),
            output: output.to_vec(),
            public_key: *public_key,
            proof,
            challenges,
        },
        replay.into_chain_spec(),
    ))
}

/// Merge per-action Poseidon2 chain statements into one uniform-length
/// batch: shorter chains are padded with all-zero word steps.  The
/// padding is deterministic and unambiguous (every absorbed word is
/// public), and the padded chains keep their honest prefix semantics —
/// challenges were derived from intermediate states the batch still pins.
pub fn merge_poseidon2_chain_specs(
    specs: &[crate::ristretto_poseidon2_air::Poseidon2ChainSpec],
) -> Option<crate::ristretto_poseidon2_air::Poseidon2ChainSpec> {
    use crate::ristretto_poseidon2_air::{N_RATE_LANES, Poseidon2ChainSpec};
    let specs: Vec<_> = specs
        .iter()
        .filter(|spec| !spec.initial_states.is_empty())
        .collect();
    if specs.is_empty() {
        return None;
    }
    let chain_length = specs.iter().map(|spec| spec.chain_length).max().unwrap();
    let mut initial_states = Vec::new();
    let mut absorbed_words = Vec::new();
    for spec in &specs {
        for chain in 0..spec.initial_states.len() {
            initial_states.push(spec.initial_states[chain]);
            for step in 0..chain_length as usize {
                let index = chain * spec.chain_length as usize + step;
                absorbed_words.push(if step < spec.chain_length as usize {
                    spec.absorbed_words[index]
                } else {
                    [0u32; N_RATE_LANES]
                });
            }
        }
    }
    Some(Poseidon2ChainSpec {
        initial_states,
        absorbed_words,
        chain_length,
    })
}

/// One key-ownership equation whose challenge is derived from the
/// Poseidon2-M31 transcript (the Flock-free admission path).
#[derive(Debug, Clone, Copy)]
pub struct PlayerPkOwnershipPoseidon2Entry<'a> {
    pub pk: &'a BgPoint,
    pub context: &'a [u8],
    pub wire: &'a crate::ristretto_player_proofs_air::RistrettoPkOwnershipWire,
}

/// One reveal-token equation pair derived from the Poseidon2-M31
/// transcript.
#[derive(Debug, Clone, Copy)]
pub struct PlayerRevealTokenPoseidon2Entry<'a> {
    pub pk: &'a BgPoint,
    pub ciphertext: &'a BgCiphertext,
    pub reveal_token: &'a BgPoint,
    pub context: &'a [u8],
    pub wire: &'a crate::ristretto_player_proofs_air::RistrettoRevealTokenWire,
}

/// One batched deck-DLEQ family (52 cards) derived from the Poseidon2-M31
/// transcript.
#[derive(Debug, Clone, Copy)]
pub struct PlayerDeckDleqPoseidon2Entry<'a> {
    pub direction: crate::ristretto_player_proofs_air::RistrettoDeckDleqDirection,
    pub input: &'a [BgCiphertext],
    pub output: &'a [BgCiphertext],
    pub pk: &'a BgPoint,
    pub context: &'a [u8],
    pub wire: &'a crate::ristretto_player_proofs_air::RistrettoDeckDleqWire,
}

/// Player obligations on the Poseidon2-M31 transcript path: every
/// challenge comes from the M31 sponge, every transcript run is a chain
/// statement folded into the hand's Poseidon2 batch, and there is no
/// Flock sidecar at all.
#[derive(Debug, Clone, Default)]
pub struct PlayerPoseidon2Inputs<'a> {
    pub pk_ownership: Vec<PlayerPkOwnershipPoseidon2Entry<'a>>,
    pub reveal_tokens: Vec<PlayerRevealTokenPoseidon2Entry<'a>>,
    pub deck_dleqs: Vec<PlayerDeckDleqPoseidon2Entry<'a>>,
}

/// One whole hand's admission obligations, settled by a single STARK: all
/// shuffle equations, all player equations, the hand-transcript root, and
/// the hand's folded Poseidon2 chains.  This is the "one proof per hand"
/// artifact — every obligation that the deployment path checks natively
/// (BG verification, player proofs) folds into one multi-component prove
/// call with one FRI over the shared trees.
pub struct HandAdmissionComponents<'a> {
    /// The hand's shuffle admissions (typically nine deck-52 sets).
    pub shuffles: Vec<BgAdmissionComponents>,
    /// The shuffles' Poseidon2 replay chains, when they were proven under
    /// the M31 transcript (see [`prove_bg_admission_poseidon2`]); one per
    /// shuffle, merged into the hand's Poseidon2 batch.  Empty when the
    /// shuffles ride the Flock deployment path.
    pub shuffle_chains:
        Vec<crate::ristretto_poseidon2_air::Poseidon2ChainSpec>,
    /// Player obligations folded into the same proof (ownership, reveal
    /// tokens, deck DLEQs); may be empty when the artifact covers only
    /// the shuffles.
    pub players: Vec<PlayerAdmissionInputs<'a>>,
    /// Player obligations on the Poseidon2-M31 transcript path: their
    /// equations fold the same way, and their transcript chains merge
    /// into the hand's Poseidon2 batch (no Flock artifacts).
    pub poseidon2_players: Vec<PlayerPoseidon2Inputs<'a>>,
    /// The hand-transcript root (a Poseidon2 digest over the per-action
    /// chains); becomes the admission tag.
    pub hand_root: [u8; 32],
    /// The hand's transcript chains as one uniform Poseidon2 batch
    /// (see [`merge_poseidon2_chain_specs`]).
    pub poseidon2: Option<crate::ristretto_poseidon2_air::Poseidon2ChainSpec>,
}

/// Fold the Poseidon2-path player equations into the builder, collecting
/// every replayed transcript chain.
fn decompose_player_poseidon2_into(
    inputs: &PlayerPoseidon2Inputs<'_>,
    builder: &mut PointEquationBuilder,
    chain_specs: &mut Vec<crate::ristretto_poseidon2_air::Poseidon2ChainSpec>,
) -> TexasAirResult<()> {
    use crate::ristretto_player_proofs_air::{
        derive_pk_ownership_challenge_poseidon2, derive_reveal_token_challenge_poseidon2,
    };
    let g = base_point_value();
    for entry in &inputs.pk_ownership {
        let (challenge, spec) =
            derive_pk_ownership_challenge_poseidon2(entry.pk, entry.context, entry.wire);
        chain_specs.push(spec);
        let response = checked_scalar(&entry.wire.response, "pk-ownership response")?;
        let commitment = bg_decode_point(&entry.wire.commitment)?;
        let lhs = builder.mul(&response, &g);
        let pk_scaled = builder.mul(&challenge, entry.pk);
        let rhs = builder.add(&pk_scaled, &bg_encode_point(&commitment))?;
        builder.eq(lhs, rhs);
    }
    for entry in &inputs.reveal_tokens {
        let (challenge, spec) = derive_reveal_token_challenge_poseidon2(
            entry.pk,
            entry.ciphertext,
            entry.reveal_token,
            entry.context,
            entry.wire,
        );
        chain_specs.push(spec);
        let response = checked_scalar(&entry.wire.response, "reveal-token response")?;
        let t1 = bg_decode_point(&entry.wire.commitment_t1)?;
        let t2 = bg_decode_point(&entry.wire.commitment_t2)?;
        let lhs = builder.mul(&response, &g);
        let pk_scaled = builder.mul(&challenge, entry.pk);
        let rhs = builder.add(&pk_scaled, &bg_encode_point(&t1))?;
        builder.eq(lhs, rhs);
        let lhs = builder.mul(&response, &entry.ciphertext.c1);
        let token_scaled = builder.mul(&challenge, entry.reveal_token);
        let rhs = builder.add(&token_scaled, &bg_encode_point(&t2))?;
        builder.eq(lhs, rhs);
    }
    for entry in &inputs.deck_dleqs {
        let (challenge, spec) = crate::ristretto_player_proofs_air::derive_deck_dleq_challenge_poseidon2(
            entry.direction,
            entry.input,
            entry.output,
            entry.pk,
            entry.context,
            entry.wire,
        )?;
        chain_specs.push(spec);
        let response = checked_scalar(&entry.wire.response, "deck DLEQ response")?;
        let commitment_pk = bg_decode_point(&entry.wire.commitment_pk)?;
        let lhs = builder.mul(&response, &g);
        let pk_scaled = builder.mul(&challenge, entry.pk);
        let rhs = builder.add(&pk_scaled, &bg_encode_point(&commitment_pk))?;
        builder.eq(lhs, rhs);
        for index in 0..entry.input.len() {
            let d2 = entry
                .direction
                .compute_d2(&entry.input[index].c2, &entry.output[index].c2);
            let commitment = bg_decode_point(&entry.wire.per_card_commitments[index])?;
            let lhs = builder.mul(&response, &entry.input[index].c1);
            let d2_scaled = builder.mul(&challenge, &d2);
            let rhs = builder.add(&d2_scaled, &bg_encode_point(&commitment))?;
            builder.eq(lhs, rhs);
        }
    }
    Ok(())
}

/// Decompose a whole hand into one admission statement: every shuffle's
/// ladders/additions/schedules/recurrences and every player's point
/// equations merge into the shared statement under the hand root.  The
/// Poseidon2-path players' transcript chains merge with the caller's
/// shuffle-side chains into one uniform batch.
pub fn decompose_hand_admission(
    components: &HandAdmissionComponents<'_>,
) -> TexasAirResult<AdmissionStatement> {
    if components.shuffles.is_empty() {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "hand admission carries no shuffle obligations".into(),
        ));
    }
    let mut ladders = Vec::new();
    let mut additions = Vec::new();
    let mut schedules = Vec::new();
    let mut recurrences = Vec::new();
    for shuffle in &components.shuffles {
        let (statement, _) = decompose_bg_admission(shuffle)?;
        ladders.extend(statement.ladders);
        additions.extend(statement.additions);
        schedules.extend(statement.schedules);
        recurrences.extend(statement.recurrences);
    }
    for player in &components.players {
        let statement = decompose_player_admission(player)?;
        ladders.extend(statement.ladders);
        additions.extend(statement.additions);
    }
    let mut chain_specs = Vec::new();
    if let Some(spec) = &components.poseidon2 {
        chain_specs.push(spec.clone());
    }
    chain_specs.extend(components.shuffle_chains.iter().cloned());
    if !components.poseidon2_players.is_empty() {
        let mut builder = PointEquationBuilder::default();
        decompose_player_poseidon2_into(
            &combine_poseidon2_players(&components.poseidon2_players),
            &mut builder,
            &mut chain_specs,
        )?;
        builder.check_equalities()?;
        ladders.extend(builder.ladders);
        additions.extend(builder.additions.into_iter().map(|(left, right, output)| {
            AdmissionAdditionRow {
                left,
                right,
                output,
            }
        }));
    }
    let poseidon2 = merge_poseidon2_chain_specs(&chain_specs);
    Ok(AdmissionStatement {
        tag: components.hand_root,
        ladders,
        additions,
        schedules,
        recurrences,
        poseidon2,
    })
}

/// Flatten per-player Poseidon2 inputs into one set (equation order is
/// players in order, ownership before reveal tokens).
fn combine_poseidon2_players<'a>(
    players: &[PlayerPoseidon2Inputs<'a>],
) -> PlayerPoseidon2Inputs<'a> {
    let mut combined = PlayerPoseidon2Inputs::default();
    for player in players {
        combined.pk_ownership.extend(player.pk_ownership.iter().copied());
        combined.reveal_tokens.extend(player.reveal_tokens.iter().copied());
        combined.deck_dleqs.extend(player.deck_dleqs.iter().copied());
    }
    combined
}

/// Prove the whole hand's admission obligations in ONE STARK.
pub fn prove_hand_admission_components(
    components: &HandAdmissionComponents<'_>,
) -> TexasAirResult<ArchivedRistrettoAdmissionProof> {
    let statement = decompose_hand_admission(components)?;
    prove_ristretto_admission_stark(statement)
}

/// Verify the whole-hand admission STARK, fail-closed: every player proof
/// is natively verified, the archived statement must be exactly the
/// derived merge (each shuffle's decomposition re-runs the canonical
/// challenge replay and all equation checks natively), and the single
/// STARK verifies.
pub fn verify_hand_admission_components(
    components: &HandAdmissionComponents<'_>,
    archive: &ArchivedRistrettoAdmissionProof,
) -> TexasAirResult<()> {
    for player in &components.players {
        verify_player_inputs_native(player)?;
    }
    for player in &components.poseidon2_players {
        verify_player_poseidon2_native(player)?;
    }
    let statement = decompose_hand_admission(components)?;
    if archive.statement != statement {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "hand admission statement is detached from its component set".into(),
        ));
    }
    verify_ristretto_admission_stark(archive)
}

/// Serialized real-BG admission: the canonical shuffle request bytes plus
/// the unified admission STARK derived from them.
#[derive(Debug, Clone, PartialEq)]
pub struct ArchivedRistrettoBgAdmissionProof {
    /// Canonical V2 shuffle request bytes (the full admission statement is
    /// derived deterministically from these).
    pub request_bytes: Vec<u8>,
    /// The unified admission STARK over the decomposed equations.
    pub admission: ArchivedRistrettoAdmissionProof,
}

/// Prove the unified admission STARK for one complete V2 shuffle request.
///
/// The extractor (`ristretto_air_v2_shuffle_in_circuit_components`) runs the
/// canonical decode, envelope binding, and native Bayer--Groth verification
/// first; the returned proof then carries every point equation of that
/// verification inside one multi-component STARK.
pub fn prove_ristretto_bg_admission_stark(
    request_bytes: &[u8],
) -> TexasAirResult<ArchivedRistrettoBgAdmissionProof> {
    let components = ristretto_shuffle_components(request_bytes)?;
    let admission = prove_ristretto_bg_admission_components(&components)?;
    Ok(ArchivedRistrettoBgAdmissionProof {
        request_bytes: request_bytes.to_vec(),
        admission,
    })
}

/// Verify a real-BG admission proof end to end.
pub fn verify_ristretto_bg_admission_stark(
    archive: &ArchivedRistrettoBgAdmissionProof,
) -> TexasAirResult<()> {
    let components = ristretto_shuffle_components(&archive.request_bytes)?;
    verify_ristretto_bg_admission_components(&components, &archive.admission)
}

fn ristretto_shuffle_components(request_bytes: &[u8]) -> TexasAirResult<BgAdmissionComponents> {
    let components = crate::ristretto_shuffle_air::ristretto_air_v2_shuffle_in_circuit_components(
        request_bytes,
    )?;
    Ok(BgAdmissionComponents {
        statement_digest: components.statement_digest,
        input: components.input,
        output: components.output,
        public_key: components.public_key,
        proof: components.proof,
        challenges: components.challenges,
    })
}

// ===========================================================================
// Player proofs admission wiring (pk ownership, reveal token, deck DLEQ).
// ===========================================================================

use crate::ristretto_player_proofs_air::{
    ArchivedRistrettoPlayerProof, RistrettoDeckDleqDirection, RistrettoDeckDleqWire,
    RistrettoPkOwnershipWire, RistrettoRevealTokenWire, derive_deck_dleq_challenge,
    derive_pk_ownership_challenge, derive_reveal_token_challenge, verify_deck_dleq,
    verify_pk_ownership, verify_reveal_token,
};

/// One pk-ownership equation admission entry: `G·response == commitment +
/// pk·challenge`.
#[derive(Clone)]
pub struct PlayerPkOwnershipEntry<'a> {
    /// Public key behind the ownership claim.
    pub pk: &'a BgPoint,
    /// Transcript context bytes.
    pub context: &'a [u8],
    /// The Schnorr wire under admission.
    pub wire: &'a RistrettoPkOwnershipWire,
    /// The Flock transcript proof binding the challenge.
    pub proof: &'a ArchivedRistrettoPlayerProof,
}

/// One reveal-token equation pair: `G·response == t1 + pk·challenge` and
/// `ct.c1·response == t2 + reveal_token·challenge`.
#[derive(Clone)]
pub struct PlayerRevealTokenEntry<'a> {
    /// Public key.
    pub pk: &'a BgPoint,
    /// The ciphertext whose `c1` masks the token.
    pub ciphertext: &'a BgCiphertext,
    /// The revealed token point.
    pub reveal_token: &'a BgPoint,
    /// Transcript context bytes.
    pub context: &'a [u8],
    /// The Chaum--Pedersen wire under admission.
    pub wire: &'a RistrettoRevealTokenWire,
    /// The Flock transcript proof binding the challenge.
    pub proof: &'a ArchivedRistrettoPlayerProof,
}

/// One batched deck-DLEQ equation family (remask or leave): the key
/// equation `G·response == commitment_pk + pk·challenge` plus one equation
/// per card `input_i.c1·response == A_i + d2_i·challenge` with `d2_i`
/// derived from the direction.
#[derive(Clone)]
pub struct PlayerDeckDleqEntry<'a> {
    /// Transition direction.
    pub direction: RistrettoDeckDleqDirection,
    /// Input deck.
    pub input: &'a [BgCiphertext],
    /// Output deck.
    pub output: &'a [BgCiphertext],
    /// The acting public key.
    pub pk: &'a BgPoint,
    /// Transcript context bytes.
    pub context: &'a [u8],
    /// The batched DLEQ wire under admission.
    pub wire: &'a RistrettoDeckDleqWire,
    /// The Flock transcript proof binding the challenge.
    pub proof: &'a ArchivedRistrettoPlayerProof,
}

/// The full player-proof component set of one admission.
pub struct PlayerAdmissionInputs<'a> {
    /// Caller-domain statement digest used as the admission tag.
    pub statement_digest: [u8; 32],
    /// Key-ownership equations.
    pub pk_ownership: Vec<PlayerPkOwnershipEntry<'a>>,
    /// Reveal-token equation pairs.
    pub reveal_tokens: Vec<PlayerRevealTokenEntry<'a>>,
    /// Batched deck-DLEQ families (remask, leave, or fold-with-proof's
    /// leave; the fold key-update subtraction stays a caller-side native
    /// check).
    pub deck_dleqs: Vec<PlayerDeckDleqEntry<'a>>,
}

fn checked_scalar(bytes: &[u8; LIMBS], label: &str) -> TexasAirResult<BgScalar> {
    <BgScalar as CurveScalar>::from_canonical_bytes(bytes)
        .ok_or_else(|| TexasAirError::ConstraintUnsatisfied(format!("{label} is not canonical")))
}

/// Decompose the player-proof component set into the unified admission
/// statement: every equation becomes ladder statements plus accumulation
/// rows, with native encoding equalities completing each check.
fn decompose_player_admission(
    inputs: &PlayerAdmissionInputs,
) -> TexasAirResult<AdmissionStatement> {
    let g = base_point_value();
    let mut builder = PointEquationBuilder::default();

    for entry in &inputs.pk_ownership {
        let challenge = derive_pk_ownership_challenge(entry.pk, entry.context, entry.wire);
        let response = checked_scalar(&entry.wire.response, "pk-ownership response")?;
        let commitment = bg_decode_point(&entry.wire.commitment)?;
        let lhs = builder.mul(&response, &g);
        let pk_scaled = builder.mul(&challenge, entry.pk);
        let rhs = builder.add(&pk_scaled, &bg_encode_point(&commitment))?;
        builder.eq(lhs, rhs);
    }

    for entry in &inputs.reveal_tokens {
        let challenge = derive_reveal_token_challenge(
            entry.pk,
            entry.ciphertext,
            entry.reveal_token,
            entry.context,
            entry.wire,
        );
        let response = checked_scalar(&entry.wire.response, "reveal-token response")?;
        let t1 = bg_decode_point(&entry.wire.commitment_t1)?;
        let t2 = bg_decode_point(&entry.wire.commitment_t2)?;
        // G·response == t1 + pk·challenge
        let lhs = builder.mul(&response, &g);
        let pk_scaled = builder.mul(&challenge, entry.pk);
        let rhs = builder.add(&pk_scaled, &bg_encode_point(&t1))?;
        builder.eq(lhs, rhs);
        // ct.c1·response == t2 + reveal_token·challenge
        let lhs = builder.mul(&response, &entry.ciphertext.c1);
        let token_scaled = builder.mul(&challenge, entry.reveal_token);
        let rhs = builder.add(&token_scaled, &bg_encode_point(&t2))?;
        builder.eq(lhs, rhs);
    }

    for entry in &inputs.deck_dleqs {
        let challenge = derive_deck_dleq_challenge(
            entry.direction,
            entry.input,
            entry.output,
            entry.pk,
            entry.context,
            entry.wire,
        )?;
        let response = checked_scalar(&entry.wire.response, "deck DLEQ response")?;
        let commitment_pk = bg_decode_point(&entry.wire.commitment_pk)?;
        // Key equation: G·response == commitment_pk + pk·challenge.
        let lhs = builder.mul(&response, &g);
        let pk_scaled = builder.mul(&challenge, entry.pk);
        let rhs = builder.add(&pk_scaled, &bg_encode_point(&commitment_pk))?;
        builder.eq(lhs, rhs);
        // Per-card equations.
        for index in 0..entry.input.len() {
            let d2 = entry
                .direction
                .compute_d2(&entry.input[index].c2, &entry.output[index].c2);
            let commitment = bg_decode_point(&entry.wire.per_card_commitments[index])?;
            let lhs = builder.mul(&response, &entry.input[index].c1);
            let d2_scaled = builder.mul(&challenge, &d2);
            let rhs = builder.add(&d2_scaled, &bg_encode_point(&commitment))?;
            builder.eq(lhs, rhs);
        }
    }
    builder.check_equalities()?;

    Ok(AdmissionStatement {
        poseidon2: None,
        tag: inputs.statement_digest,
        ladders: builder.ladders,
        additions: builder
            .additions
            .into_iter()
            .map(|(left, right, output)| AdmissionAdditionRow {
                left,
                right,
                output,
            })
            .collect(),
        schedules: Vec::new(),
        recurrences: Vec::new(),
    })
}

/// Run every Poseidon2-path player verification natively (the fail-closed
/// gate; each replays the M31 transcript and checks the sigma equation).
fn verify_player_poseidon2_native(inputs: &PlayerPoseidon2Inputs<'_>) -> TexasAirResult<()> {
    use crate::ristretto_player_proofs_air::{
        verify_pk_ownership_poseidon2, verify_reveal_token_poseidon2,
    };
    for entry in &inputs.pk_ownership {
        verify_pk_ownership_poseidon2(entry.pk, entry.context, entry.wire)?;
    }
    for entry in &inputs.reveal_tokens {
        verify_reveal_token_poseidon2(
            entry.pk,
            entry.ciphertext,
            entry.reveal_token,
            entry.context,
            entry.wire,
        )?;
    }
    for entry in &inputs.deck_dleqs {
        crate::ristretto_player_proofs_air::verify_deck_dleq_poseidon2(
            entry.direction,
            entry.input,
            entry.output,
            entry.pk,
            entry.context,
            entry.wire,
        )?;
    }
    Ok(())
}

/// Run every native player-proof verification (the fail-closed gate; each
/// includes the Flock transcript STARK).
fn verify_player_inputs_native(inputs: &PlayerAdmissionInputs) -> TexasAirResult<()> {
    for entry in &inputs.pk_ownership {
        verify_pk_ownership(entry.pk, entry.context, entry.wire, entry.proof)?;
    }
    for entry in &inputs.reveal_tokens {
        verify_reveal_token(
            entry.pk,
            entry.ciphertext,
            entry.reveal_token,
            entry.context,
            entry.wire,
            entry.proof,
        )?;
    }
    for entry in &inputs.deck_dleqs {
        verify_deck_dleq(
            entry.direction,
            entry.input,
            entry.output,
            entry.pk,
            entry.context,
            entry.wire,
            entry.proof,
        )?;
    }
    Ok(())
}

/// Prove the unified admission STARK for one player-proof component set.
pub fn prove_player_admission_components(
    inputs: &PlayerAdmissionInputs,
) -> TexasAirResult<ArchivedRistrettoAdmissionProof> {
    verify_player_inputs_native(inputs)?;
    let statement = decompose_player_admission(inputs)?;
    prove_ristretto_admission_stark(statement)
}

/// Verify the unified admission STARK for one player-proof component set.
pub fn verify_player_admission_components(
    inputs: &PlayerAdmissionInputs,
    archive: &ArchivedRistrettoAdmissionProof,
) -> TexasAirResult<()> {
    verify_player_inputs_native(inputs)?;
    let statement = decompose_player_admission(inputs)?;
    if archive.statement != statement {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "player admission statement is detached from its component set".into(),
        ));
    }
    verify_ristretto_admission_stark(archive)
}

// ===========================================================================
// Texas Layer-1 fold (method AIR as an admission component).
// ===========================================================================

/// One Texas method-AIR ingredient set for Layer-1 folding: the rebuilt
/// method trace, the method AIR, and its verifier-trusted expected trace
/// row.  A method AIR contributes only original trace columns (no
/// preprocessed columns, no LogUp layer), so its component is a zero-claim
/// construction bound into the admission channel through a domain-separated
/// digest of the expected row.
pub struct TexasMethodIngredient<A: crate::airs::TexasAir + 'static> {
    /// The method's rebuilt trace columns.
    pub trace: crate::trace_gen::MethodTrace,
    /// The method AIR.
    pub air: A,
    /// Verifier-trusted expected trace row (from
    /// `TexasPublicInputs::require_expected_trace_row`).
    pub expected_trace_row: Vec<M31>,
}

fn texas_ingredient_digest<A: crate::airs::TexasAir>(
    trace_log_size: u32,
    air: &A,
    expected_trace_row: &[M31],
) -> [u32; BINDING_DIGEST_LIMBS] {
    use blake2::digest::Digest;
    let mut hasher = blake2::Blake2b512::new();
    hasher.update(b"zchain.poker.admission.texas.v1");
    hasher.update(&trace_log_size.to_le_bytes());
    hasher.update(&(air.trace_num_columns() as u64).to_le_bytes());
    for limb in expected_trace_row {
        hasher.update(&limb.0.to_le_bytes());
    }
    let digest = hasher.finalize();
    core::array::from_fn(|index| {
        u32::from_le_bytes(
            digest[4 * index..4 * index + 4]
                .try_into()
                .expect("4 bytes"),
        )
    })
}

/// Prove one unified admission STARK that additionally folds a Texas method
/// AIR (Layer-1 component) alongside the crypto segments.
pub fn prove_ristretto_admission_stark_with_texas<A: crate::airs::TexasAir + Send + 'static>(
    statement: AdmissionStatement,
    texas: TexasMethodIngredient<A>,
) -> TexasAirResult<ArchivedRistrettoAdmissionProof> {
    prove_ristretto_admission_stark_with_texas_batch(statement, vec![texas])
}

/// Prove one unified admission STARK folding SEVERAL same-type method AIRs
/// (the multi-ingredient Layer-1 batch: lifecycle/hand/betting rows in one
/// proof).  Ingredient order is part of the Fiat--Shamir binding.
pub fn prove_ristretto_admission_stark_with_texas_batch<A: crate::airs::TexasAir + Send + 'static>(
    statement: AdmissionStatement,
    ingredients: Vec<TexasMethodIngredient<A>>,
) -> TexasAirResult<ArchivedRistrettoAdmissionProof> {
    let folds: Vec<TexasFold> = ingredients
        .iter()
        .map(|ingredient| {
            let air = ingredient.air.clone();
            let expected_trace_row = ingredient.expected_trace_row.clone();
            TexasFold {
                digest: texas_ingredient_digest(
                    ingredient.trace.log_size,
                    &ingredient.air,
                    &ingredient.expected_trace_row,
                ),
                factory: Box::new(move |allocator: &mut TraceLocationAllocator| {
                    Box::new(FrameworkComponent::new(
                        allocator,
                        crate::airs::bound::BoundAir::new(air.clone(), expected_trace_row.clone()),
                        SecureField::from(0u32),
                    )) as Box<dyn ComponentProver<SimdBackend>>
                }),
                trace: ingredient.trace.clone(),
            }
        })
        .collect();
    prove_admission_inner(statement, &folds)
}

/// Verify one unified admission STARK that additionally folds a Texas
/// method AIR; the ingredient set must be the caller's rebuilt one.
pub fn verify_ristretto_admission_stark_with_texas<A: crate::airs::TexasAir + Send + 'static>(
    archive: &ArchivedRistrettoAdmissionProof,
    texas: TexasMethodIngredient<A>,
) -> TexasAirResult<()> {
    verify_ristretto_admission_stark_with_texas_batch(archive, vec![texas])
}

/// Verify a multi-ingredient Texas fold (same rebuilt ingredient set, same
/// order as the prove call).
pub fn verify_ristretto_admission_stark_with_texas_batch<A: crate::airs::TexasAir + Send + 'static>(
    archive: &ArchivedRistrettoAdmissionProof,
    ingredients: Vec<TexasMethodIngredient<A>>,
) -> TexasAirResult<()> {
    let folds: Vec<TexasFold> = ingredients
        .iter()
        .map(|ingredient| {
            let air = ingredient.air.clone();
            let expected_trace_row = ingredient.expected_trace_row.clone();
            TexasFold {
                digest: texas_ingredient_digest(
                    ingredient.trace.log_size,
                    &ingredient.air,
                    &ingredient.expected_trace_row,
                ),
                factory: Box::new(move |allocator: &mut TraceLocationAllocator| {
                    Box::new(FrameworkComponent::new(
                        allocator,
                        crate::airs::bound::BoundAir::new(air.clone(), expected_trace_row.clone()),
                        SecureField::from(0u32),
                    )) as Box<dyn ComponentProver<SimdBackend>>
                }),
                trace: ingredient.trace.clone(),
            }
        })
        .collect();
    verify_admission_inner(archive, &folds)
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

    fn curve_add(left: &[u8; LIMBS], right: &[u8; LIMBS]) -> [u8; LIMBS] {
        use poker_protocol::crypto::curve::{Curve, CurvePoint, RistrettoCurve};
        type Point = <RistrettoCurve as Curve>::Point;
        let decode = |encoding: &[u8; LIMBS]| -> Point {
            Point::from_compressed(encoding).expect("point decodes")
        };
        let sum = decode(left) + decode(right);
        let mut out = [0u8; LIMBS];
        out.copy_from_slice(&CurvePoint::compress(&sum).as_ref()[..LIMBS]);
        out
    }

    fn sample_statement() -> AdmissionStatement {
        // Two point-equation multiplications against the basepoint, their
        // accumulation into one compressed output, and one small deck
        // schedule. The ladder outputs come from a real ladder batch so the
        // statements are self-consistent.
        let first = scalar_bytes(7);
        let second = scalar_bytes(0x0123_4567_89ab_cdef);
        let ladder_archives = prove_ristretto_scalar_mul_ladder_batch(vec![
            (first, windows(&first), basepoint()),
            (second, windows(&second), basepoint()),
        ])
        .expect("ladder statements");
        let output_one = ladder_archives.statements[0].output;
        let output_two = ladder_archives.statements[1].output;
        AdmissionStatement {
            poseidon2: None,
            tag: [0xab; 32],
            ladders: ladder_archives.statements,
            additions: vec![AdmissionAdditionRow {
                left: output_one,
                right: output_two,
                output: curve_add(&output_one, &output_two),
            }],
            schedules: vec![AdmissionScheduleSpec {
                powers_challenge: scalar_bytes(7),
                product_y: scalar_bytes(9),
                product_z: scalar_bytes(11),
                product_challenge: scalar_bytes(13),
                deck_size: 12,
            }],
            recurrences: Vec::new(),
        }
    }

    fn bg_components_fixture(deck: usize) -> BgAdmissionComponents {
        bg_components_fixture_seeded(deck, 0x5A1E)
    }

    fn bg_components_fixture_seeded(deck: usize, seed: u64) -> BgAdmissionComponents {
        use rand::SeedableRng;
        use rand::rngs::StdRng;
        let mut rng = StdRng::seed_from_u64(seed);
        let g = RistrettoCurve::base_g();
        let secret = BgScalar::random(&mut rng);
        let public_key = g * secret;
        let input = (0..deck)
            .map(|_| {
                let rerandomizer = BgScalar::random(&mut rng);
                ElGamalCiphertextGeneric {
                    c1: g * rerandomizer,
                    c2: public_key * rerandomizer,
                }
            })
            .collect::<Vec<_>>();
        let mut permutation = (0..deck).collect::<Vec<_>>();
        use rand::seq::SliceRandom;
        permutation.shuffle(&mut rng);
        let rerandomizers = (0..deck)
            .map(|_| BgScalar::random(&mut rng))
            .collect::<Vec<_>>();
        let output = permutation
            .iter()
            .zip(&rerandomizers)
            .map(|(&source, rerandomizer)| input[source].re_encrypt(&public_key, rerandomizer))
            .collect::<Vec<_>>();
        let context = poker_protocol::ristretto_air::RISTRETTO_AIR_V2_SHUFFLE_CONTEXT;
        let mut prove_transcript =
            crate::ristretto_shuffle_air::FlockShuffleTranscript::new(context);
        let proof = BayerGrothShuffleProof::<RistrettoCurve>::prove(
            &input,
            &output,
            &permutation,
            &rerandomizers,
            &public_key,
            &mut rng,
            &mut prove_transcript,
        )
        .expect("BG proof");
        // Derive the verifier-side challenges exactly like the extractor: a
        // fresh transcript driven by the native verify replay.
        let mut verify_transcript =
            crate::ristretto_shuffle_air::FlockShuffleTranscript::new(context);
        crate::ristretto_shuffle_air::run_bayer_groth_verify(
            &proof,
            &input,
            &output,
            &public_key,
            &mut verify_transcript,
        )
        .expect("native BG verify");
        let challenges = verify_transcript
            .challenges()
            .iter()
            .map(|wire| {
                <BgScalar as CurveScalar>::from_canonical_bytes(&wire.image)
                    .expect("canonical challenge")
            })
            .collect::<Vec<_>>();
        BgAdmissionComponents {
            statement_digest: [0x5a; 32],
            input,
            output,
            public_key,
            proof,
            challenges,
        }
    }

    struct PlayerFixture {
        pk_ownership: Vec<(
            BgPoint,
            crate::ristretto_player_proofs_air::RistrettoPkOwnershipWire,
            crate::ristretto_player_proofs_air::ArchivedRistrettoPlayerProof,
        )>,
        reveal_tokens: Vec<(
            BgPoint,
            BgCiphertext,
            BgPoint,
            crate::ristretto_player_proofs_air::RistrettoRevealTokenWire,
            crate::ristretto_player_proofs_air::ArchivedRistrettoPlayerProof,
        )>,
        deck_dleqs: Vec<(
            Vec<BgCiphertext>,
            Vec<BgCiphertext>,
            BgPoint,
            crate::ristretto_player_proofs_air::RistrettoDeckDleqWire,
            crate::ristretto_player_proofs_air::ArchivedRistrettoPlayerProof,
        )>,
    }

    fn player_roundtrip_fixture(with_dleq: bool) -> &'static PlayerFixture {
        // Leaked on purpose: the admission inputs borrow the freshly proven
        // wires and Flock proofs for the test's lifetime.
        use crate::ristretto_player_proofs_air::{
            prove_deck_dleq, prove_pk_ownership, prove_reveal_token,
        };
        use rand::SeedableRng;
        use rand::rngs::StdRng;
        let mut rng = StdRng::seed_from_u64(0x0F01_D2A3);
        Box::leak(Box::new(PlayerFixture {
            pk_ownership: {
                let sk = BgScalar::random(&mut rng);
                let pk = base_point_value() * sk;
                let (wire, proof) =
                    prove_pk_ownership(&sk, &pk, b"table7-hand3", &mut rng).expect("pk proof");
                vec![(pk, wire, proof)]
            },
            reveal_tokens: {
                let sk = BgScalar::random(&mut rng);
                let pk = base_point_value() * sk;
                let card = RistrettoCurve::hash_to_curve(b"bench/card/17");
                let randomness = BgScalar::random(&mut rng);
                let ciphertext = BgCiphertext::encrypt(&card, &pk, &randomness);
                let reveal_token = ciphertext.c1 * sk;
                let (wire, proof) = prove_reveal_token(
                    &sk,
                    &pk,
                    &ciphertext,
                    &reveal_token,
                    b"table7-hand3",
                    &mut rng,
                )
                .expect("reveal proof");
                vec![(pk, ciphertext, reveal_token, wire, proof)]
            },
            deck_dleqs: if with_dleq {
                let sk = BgScalar::random(&mut rng);
                let pk = base_point_value() * sk;
                let input = (0..52)
                    .map(|index| {
                        let card =
                            RistrettoCurve::hash_to_curve(format!("bench/card/{index}").as_bytes());
                        let randomness = BgScalar::random(&mut rng);
                        BgCiphertext::encrypt(&card, &pk, &randomness)
                    })
                    .collect::<Vec<_>>();
                let output = input
                    .iter()
                    .map(|ct| BgCiphertext {
                        c1: ct.c1,
                        c2: ct.c2 + ct.c1 * sk,
                    })
                    .collect::<Vec<_>>();
                let (wire, proof) = prove_deck_dleq(
                    RistrettoDeckDleqDirection::Remask,
                    &input,
                    &output,
                    &sk,
                    &pk,
                    b"table7-hand3",
                    &mut rng,
                )
                .expect("dleq proof");
                vec![(input, output, pk, wire, proof)]
            } else {
                Vec::new()
            },
        }))
    }

    fn texas_create_table_ingredient()
    -> TexasMethodIngredient<crate::airs::lifecycle::create_table::CreateTableAir> {
        texas_create_table_ingredient_seeded(0)
    }

    fn texas_create_table_ingredient_seeded(
        variant: u8,
    ) -> TexasMethodIngredient<crate::airs::lifecycle::create_table::CreateTableAir> {
        use poker_l1::object_model::ObjectID;
        use poker_l1::vm::contracts::texas_poker::types::{EMPTY_PLAYER, TexasPokerTable};
        let mut pre_table = TexasPokerTable::new(
            ObjectID::new([0xAA; 20], 42),
            String::new(),
            EMPTY_PLAYER,
            2,
            1,
            1,
        );
        pre_table.call_seq = 0;
        let mut post_table = TexasPokerTable::new(
            ObjectID::new([0xAA; 20], 42),
            format!("test_table_{variant}"),
            [0xCC + variant; 20],
            6,
            10 + variant as u64,
            20,
        );
        post_table.call_seq = 1;
        let input = crate::airs::lifecycle::create_table::CreateTableInput {
            name: format!("test_table_{variant}"),
            max_players: 6,
            small_blind: 10 + variant as u64,
            big_blind: 20,
        };
        let trace = crate::trace_gen::create_table_trace::gen_create_table_trace(
            input,
            &pre_table,
            &post_table,
            42,
            0,
            1,
        )
        .expect("create table trace");
        let public_inputs = crate::public_inputs::TexasPublicInputs::from_tables(
            &pre_table,
            &post_table,
            crate::method_kind::MethodKind::CreateTable,
            42,
            0,
            1,
        )
        .expect("public inputs");
        let public_inputs = crate::prover::prepare_public_inputs_for_trace(
            public_inputs,
            &trace.trace,
            crate::airs::lifecycle::create_table::CreateTableAir::num_columns(),
        )
        .expect("prepared inputs");
        let expected_trace_row = public_inputs
            .require_expected_trace_row(
                crate::airs::lifecycle::create_table::CreateTableAir::num_columns(),
            )
            .expect("expected row");
        TexasMethodIngredient {
            trace: trace.trace,
            air: trace.air,
            expected_trace_row,
        }
    }

    #[test]
    fn texas_layer1_fold_proves_and_verifies() {
        // Crypto side: the pk + reveal player equations.
        let owned = player_roundtrip_fixture(false);
        let inputs = PlayerAdmissionInputs {
            statement_digest: [0x79; 32],
            pk_ownership: owned
                .pk_ownership
                .iter()
                .map(|(pk, wire, proof)| PlayerPkOwnershipEntry {
                    pk,
                    context: b"table7-hand3",
                    wire,
                    proof,
                })
                .collect(),
            reveal_tokens: owned
                .reveal_tokens
                .iter()
                .map(
                    |(pk, ciphertext, reveal_token, wire, proof)| PlayerRevealTokenEntry {
                        pk,
                        ciphertext,
                        reveal_token,
                        context: b"table7-hand3",
                        wire,
                        proof,
                    },
                )
                .collect(),
            deck_dleqs: Vec::new(),
        };
        let statement = decompose_player_admission(&inputs).expect("decomposition");
        let ingredient = texas_create_table_ingredient();
        let started = std::time::Instant::now();
        let archive = prove_ristretto_admission_stark_with_texas(statement.clone(), ingredient)
            .expect("texas fold STARK");
        let prove_elapsed = started.elapsed();
        let started = std::time::Instant::now();
        verify_ristretto_admission_stark_with_texas(&archive, texas_create_table_ingredient())
            .expect("texas fold verify");
        eprintln!(
            "texas Layer-1 fold (pk + reveal + create_table): prove {prove_elapsed:?}, verify {:?}, proof {} bytes",
            started.elapsed(),
            archive.stark_proof_bytes.len()
        );

        // A tampered expected row detaches the method digest.
        let mut wrong = texas_create_table_ingredient();
        wrong.expected_trace_row[0] = wrong.expected_trace_row[0] + M31::from(1u32);
        assert!(
            verify_ristretto_admission_stark_with_texas(&archive, wrong).is_err(),
            "tampered texas expected row must fail"
        );

        // A spliced crypto statement still rejects.
        let mut spliced = archive.clone();
        spliced.statement.ladders[0].output[4] ^= 1;
        assert!(
            verify_ristretto_admission_stark_with_texas(&spliced, texas_create_table_ingredient())
                .is_err()
        );
    }

    /// Multi-ingredient Layer-1 fold: SEVERAL method AIRs (two distinct
    /// CreateTable transitions) share one admission STARK with the crypto
    /// equations — the "dual-proof 全方法接线" building block.  Order is
    /// part of the Fiat--Shamir binding.
    #[test]
    fn texas_layer1_multi_fold_proves_and_verifies() {
        let owned = player_roundtrip_fixture(false);
        let inputs = PlayerAdmissionInputs {
            statement_digest: [0x79; 32],
            pk_ownership: owned
                .pk_ownership
                .iter()
                .map(|(pk, wire, proof)| PlayerPkOwnershipEntry {
                    pk,
                    context: b"table7-hand3",
                    wire,
                    proof,
                })
                .collect(),
            reveal_tokens: owned
                .reveal_tokens
                .iter()
                .map(
                    |(pk, ciphertext, reveal_token, wire, proof)| PlayerRevealTokenEntry {
                        pk,
                        ciphertext,
                        reveal_token,
                        context: b"table7-hand3",
                        wire,
                        proof,
                    },
                )
                .collect(),
            deck_dleqs: Vec::new(),
        };
        let statement = decompose_player_admission(&inputs).expect("decomposition");
        let ingredients = vec![
            texas_create_table_ingredient_seeded(0),
            texas_create_table_ingredient_seeded(1),
            texas_create_table_ingredient_seeded(2),
        ];
        let archive = prove_ristretto_admission_stark_with_texas_batch(
            statement.clone(),
            ingredients,
        )
        .expect("multi-fold STARK");
        verify_ristretto_admission_stark_with_texas_batch(
            &archive,
            vec![
                texas_create_table_ingredient_seeded(0),
                texas_create_table_ingredient_seeded(1),
                texas_create_table_ingredient_seeded(2),
            ],
        )
        .expect("multi-fold verify");

        // Wrong ingredient count detaches.
        assert!(verify_ristretto_admission_stark_with_texas_batch(
            &archive,
            vec![texas_create_table_ingredient_seeded(0)],
        )
        .is_err());

        // Swapped order changes the Fiat--Shamir binding.
        let swapped = vec![
            texas_create_table_ingredient_seeded(1),
            texas_create_table_ingredient_seeded(0),
            texas_create_table_ingredient_seeded(2),
        ];
        assert!(verify_ristretto_admission_stark_with_texas_batch(&archive, swapped).is_err());

        // A tampered expected row still rejects.
        let mut wrong = texas_create_table_ingredient_seeded(0);
        wrong.expected_trace_row[0] = wrong.expected_trace_row[0] + M31::from(1u32);
        assert!(verify_ristretto_admission_stark_with_texas_batch(
            &archive,
            vec![
                wrong,
                texas_create_table_ingredient_seeded(1),
                texas_create_table_ingredient_seeded(2),
            ],
        )
        .is_err());
    }

    #[test]
    fn player_admission_stark_proves_and_verifies() {
        let owned = player_roundtrip_fixture(false);
        let inputs = PlayerAdmissionInputs {
            statement_digest: [0x77; 32],
            pk_ownership: owned
                .pk_ownership
                .iter()
                .map(|(pk, wire, proof)| PlayerPkOwnershipEntry {
                    pk,
                    context: b"table7-hand3",
                    wire,
                    proof,
                })
                .collect(),
            reveal_tokens: owned
                .reveal_tokens
                .iter()
                .map(
                    |(pk, ciphertext, reveal_token, wire, proof)| PlayerRevealTokenEntry {
                        pk,
                        ciphertext,
                        reveal_token,
                        context: b"table7-hand3",
                        wire,
                        proof,
                    },
                )
                .collect(),
            deck_dleqs: Vec::new(),
        };
        let statement = decompose_player_admission(&inputs).expect("decomposition");
        eprintln!(
            "player admission decomposition (pk + reveal): {} ladders, {} additions",
            statement.ladders.len(),
            statement.additions.len()
        );
        let started = std::time::Instant::now();
        let archive = prove_player_admission_components(&inputs).expect("player STARK");
        let prove_elapsed = started.elapsed();
        let started = std::time::Instant::now();
        verify_player_admission_components(&inputs, &archive).expect("player verify");
        eprintln!(
            "player admission STARK (pk + reveal): prove {prove_elapsed:?}, verify {:?}, proof {} bytes",
            started.elapsed(),
            archive.stark_proof_bytes.len()
        );

        // A spliced admission statement detaches from the component set.
        let mut spliced = archive.clone();
        spliced.statement.ladders[0].output[9] ^= 1;
        assert!(verify_player_admission_components(&inputs, &spliced).is_err());

        // Spliced proof bytes fail the STARK.
        let proof_len = archive.stark_proof_bytes.len();
        let mut spliced = archive.clone();
        spliced.stark_proof_bytes[proof_len / 2] ^= 1;
        assert!(verify_player_admission_components(&inputs, &spliced).is_err());
    }

    #[test]
    fn player_admission_deck_dleq_proves_and_verifies() {
        let owned = player_roundtrip_fixture(true);
        let inputs = PlayerAdmissionInputs {
            statement_digest: [0x78; 32],
            pk_ownership: owned
                .pk_ownership
                .iter()
                .map(|(pk, wire, proof)| PlayerPkOwnershipEntry {
                    pk,
                    context: b"table7-hand3",
                    wire,
                    proof,
                })
                .collect(),
            reveal_tokens: owned
                .reveal_tokens
                .iter()
                .map(
                    |(pk, ciphertext, reveal_token, wire, proof)| PlayerRevealTokenEntry {
                        pk,
                        ciphertext,
                        reveal_token,
                        context: b"table7-hand3",
                        wire,
                        proof,
                    },
                )
                .collect(),
            deck_dleqs: owned
                .deck_dleqs
                .iter()
                .map(|(input, output, pk, wire, proof)| PlayerDeckDleqEntry {
                    direction: RistrettoDeckDleqDirection::Remask,
                    input,
                    output,
                    pk,
                    context: b"table7-hand3",
                    wire,
                    proof,
                })
                .collect(),
        };
        let statement = decompose_player_admission(&inputs).expect("decomposition");
        eprintln!(
            "player admission decomposition (pk + reveal + deck DLEQ): {} ladders, {} additions",
            statement.ladders.len(),
            statement.additions.len()
        );
        let started = std::time::Instant::now();
        let archive = prove_player_admission_components(&inputs).expect("player STARK");
        let prove_elapsed = started.elapsed();
        let started = std::time::Instant::now();
        verify_player_admission_components(&inputs, &archive).expect("player verify");
        eprintln!(
            "player admission STARK (pk + reveal + deck DLEQ): prove {prove_elapsed:?}, verify {:?}, proof {} bytes",
            started.elapsed(),
            archive.stark_proof_bytes.len()
        );

        // A wrong direction flips the d2 derivation and breaks an equation.
        let mut wrong = PlayerAdmissionInputs {
            statement_digest: [0x78; 32],
            pk_ownership: inputs.pk_ownership.clone(),
            reveal_tokens: inputs.reveal_tokens.clone(),
            deck_dleqs: vec![PlayerDeckDleqEntry {
                direction: RistrettoDeckDleqDirection::Leave,
                input: inputs.deck_dleqs[0].input,
                output: inputs.deck_dleqs[0].output,
                pk: inputs.deck_dleqs[0].pk,
                context: b"table7-hand3",
                wire: inputs.deck_dleqs[0].wire,
                proof: inputs.deck_dleqs[0].proof,
            }],
        };
        let _ = &mut wrong;
        assert!(decompose_player_admission(&wrong).is_err());
    }

    #[test]
    #[ignore = "full-deck BG admission benchmark: minutes of proving and multiple GB of memory"]
    fn bg_admission_deck52_benchmark() {
        let components = bg_components_fixture(52);
        let (statement, _) = decompose_bg_admission(&components).expect("decomposition");
        eprintln!(
            "BG admission decomposition (deck 52): {} ladders, {} additions",
            statement.ladders.len(),
            statement.additions.len()
        );
        let started = std::time::Instant::now();
        let archive =
            prove_ristretto_bg_admission_components(&components).expect("BG admission STARK");
        let prove_elapsed = started.elapsed();
        let started = std::time::Instant::now();
        verify_ristretto_bg_admission_components(&components, &archive)
            .expect("BG admission verify");
        let verify_elapsed = started.elapsed();
        eprintln!(
            "BG admission STARK (deck 52): prove {prove_elapsed:?}, verify {verify_elapsed:?}, proof {} bytes",
            archive.stark_proof_bytes.len()
        );
    }

    /// Cost-attribution A/B matrix for the deck-52 admission STARK: the same
    /// statement with the wide scalar segments (schedule, recurrence) removed,
    /// proved and verified in one process with `TEXAS_PROVE_TIMING` phase
    /// records.  Deltas between variants attribute prove/verify/bytes to each
    /// segment; the phase records attribute each segment's cost to rebuild /
    /// tree commits / LogUp interaction / the shared stwo prove.  Set
    /// `TEXAS_STWO_TRACING=1` to additionally print stwo's internal spans
    /// (interpolation, composition, FRI) with busy times.
    #[test]
    #[ignore = "full-deck BG admission attribution matrix: ~4 proves at minutes each"]
    fn bg_admission_deck52_attribution() {
        if std::env::var_os("TEXAS_STWO_TRACING").is_some() {
            use tracing_subscriber::fmt::format::FmtSpan;
            let _ = tracing_subscriber::fmt()
                .with_span_events(FmtSpan::CLOSE)
                .with_target(false)
                .try_init();
        }
        // Phase records are emitted only when the recorder was latched by the
        // environment (`TEXAS_PROVE_TIMING=1` in the test invocation); the
        // recorder's Once latch makes setting it here unreliable, so warn
        // instead.
        if !crate::prove_timing::enabled() {
            eprintln!(
                "note: TEXAS_PROVE_TIMING is not set — running without phase attribution; \
                 re-run with TEXAS_PROVE_TIMING=1 for the phase table"
            );
        }

        let components = bg_components_fixture(52);
        let (statement, _) = decompose_bg_admission(&components).expect("decomposition");
        eprintln!(
            "BG admission decomposition (deck 52): {} ladders, {} additions",
            statement.ladders.len(),
            statement.additions.len()
        );
        // Drop any records accumulated by the fixture/decomposition itself.
        let _ = crate::prove_timing::take_drain();

        let mut variants: Vec<(&str, AdmissionStatement)> = vec![("full", statement.clone())];
        let mut no_recurrence = statement.clone();
        no_recurrence.recurrences.clear();
        variants.push(("no-recurrence", no_recurrence));
        let mut no_schedule = statement.clone();
        no_schedule.schedules.clear();
        variants.push(("no-schedule", no_schedule));
        let mut ladder_only = statement.clone();
        ladder_only.schedules.clear();
        ladder_only.recurrences.clear();
        variants.push(("ladder-only", ladder_only));
        // The transcript-replacement load of one BG shuffle: six chains
        // (1 init + 5 challenges) × ~172 absorbed 31-bit elements ≈ the
        // 5.5 KB BG wire at rate 8, padded to a uniform chain length.
        let mut with_poseidon2 = statement;
        with_poseidon2.poseidon2 = Some(crate::ristretto_poseidon2_air::Poseidon2ChainSpec {
            initial_states: (0..6)
                .map(|chain| core::array::from_fn(|i| (chain as u32 * 9_778 + i as u32 * 131) % 0x7FFF_FFFF))
                .collect(),
            absorbed_words: (0..6 * 176)
                .map(|step| core::array::from_fn(|lane| (step as u32 * 17 + lane as u32 * 5) % 0x7FFF_FFFF))
                .collect(),
            chain_length: 176,
        });
        variants.push(("full+poseidon2", with_poseidon2));

        for (name, variant) in variants {
            let started = std::time::Instant::now();
            let archive = prove_ristretto_admission_stark(variant).expect("admission STARK");
            let prove_elapsed = started.elapsed();
            let prove_records = crate::prove_timing::take_drain();
            let started = std::time::Instant::now();
            verify_ristretto_admission_stark(&archive).expect("admission verify");
            let verify_elapsed = started.elapsed();
            let verify_records = crate::prove_timing::take_drain();
            eprintln!();
            eprintln!(
                "=== variant {name}: prove {prove_elapsed:?}, verify {verify_elapsed:?}, proof {} bytes ===",
                archive.stark_proof_bytes.len()
            );
            print_phase_records("prove", &prove_records);
            print_phase_records("verify", &verify_records);
        }
    }

    fn print_phase_records(side: &str, records: &[crate::prove_timing::TimingRecord]) {
        let mut sorted = records.to_vec();
        sorted.sort_by(|a, b| b.elapsed.cmp(&a.elapsed));
        eprintln!("--- {side} phases ({} records, by elapsed) ---", sorted.len());
        for record in &sorted {
            let ms = record.elapsed.as_millis();
            let columns = record
                .num_columns
                .map_or_else(String::new, |count| format!(", {count} cols"));
            eprintln!("  {ms:>8} ms  {}{columns}", record.label);
        }
    }

    /// Full-hand Path A benchmark with the correct client/server split:
    /// ALL player proofs (ownership, reveal tokens, deck DLEQ) and the
    /// Bayer--Groth shuffle arguments are CLIENT-side native proofs — never
    /// circuit-proven.  The server's recursion artifact covers only the
    /// shuffle-admission obligations: one BG admission STARK per shuffle
    /// (deck 52), the folding target of Path A.  Transcript chains
    /// (BLAKE3/Flock) remain separate artifacts, unfolded.
    #[test]
    #[ignore = "full-hand recursion benchmark: ~22 minutes of shuffle admissions"]
    fn full_hand_recursion_benchmark() {
        use crate::ristretto_player_proofs_air::{
            prove_deck_dleq, prove_pk_ownership, prove_reveal_token, RistrettoDeckDleqDirection,
            verify_deck_dleq, verify_pk_ownership, verify_reveal_token,
        };
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        let mut client_prove = std::time::Duration::ZERO;
        let mut server_native_verify = std::time::Duration::ZERO;

        // ---- Client phase (native, no circuits): nine ownership, nine
        // shuffles (native BG, inside the fixture), one fold DLEQ, and a
        // representative reveal batch scaled to the street pattern. ----
        let mut ownership_artifacts = Vec::new();
        for seat in 0..9u64 {
            let mut rng = StdRng::seed_from_u64(0xC0DE_0000 + seat);
            let started = std::time::Instant::now();
            let sk = BgScalar::random(&mut rng);
            let pk = base_point_value() * sk;
            let context: &'static [u8] =
                Box::leak(format!("recursion-hand1-seat{seat}").into_boxed_str()).as_bytes();
            let (wire, proof) =
                prove_pk_ownership(&sk, &pk, context, &mut rng).expect("ownership proof");
            client_prove += started.elapsed();
            let started = std::time::Instant::now();
            verify_pk_ownership(&pk, context, &wire, &proof).expect("ownership verify");
            server_native_verify += started.elapsed();
            ownership_artifacts.push((pk, context, wire, proof));
        }
        eprintln!("[client native] ownership x9: included in client total below");

        {
            // One fold deck-DLEQ (52 cards) + one 3-token reveal batch,
            // both native; the reveal batch scales to 32 street batches.
            let mut rng = StdRng::seed_from_u64(0xF01D_0001);
            let sk = BgScalar::random(&mut rng);
            let pk = base_point_value() * sk;
            let input = (0..52)
                .map(|index| {
                    let card =
                        RistrettoCurve::hash_to_curve(format!("recursion/card/{index}").as_bytes());
                    let randomness = BgScalar::random(&mut rng);
                    BgCiphertext::encrypt(&card, &pk, &randomness)
                })
                .collect::<Vec<_>>();
            let output = input
                .iter()
                .map(|ct| BgCiphertext {
                    c1: ct.c1,
                    c2: ct.c2 + ct.c1 * sk,
                })
                .collect::<Vec<_>>();
            let started = std::time::Instant::now();
            let (wire, proof) = prove_deck_dleq(
                RistrettoDeckDleqDirection::Remask,
                &input,
                &output,
                &sk,
                &pk,
                b"recursion-hand1-fold",
                &mut rng,
            )
            .expect("deck DLEQ proof");
            let reveal_start = std::time::Instant::now();
            let mut reveal_prove = std::time::Duration::ZERO;
            let mut reveal_verify = std::time::Duration::ZERO;
            for batch in 0..32u64 {
                let mut rng = StdRng::seed_from_u64(0xEA1A_0004 + batch);
                let sk = BgScalar::random(&mut rng);
                let pk = base_point_value() * sk;
                for index in 0..3u64 {
                    let card = RistrettoCurve::hash_to_curve(
                        format!("recursion/reveal/{batch}/{index}").as_bytes(),
                    );
                    let randomness = BgScalar::random(&mut rng);
                    let ciphertext = BgCiphertext::encrypt(&card, &pk, &randomness);
                    let reveal_token = ciphertext.c1 * sk;
                    let started = std::time::Instant::now();
                    let (wire, proof) = prove_reveal_token(
                        &sk,
                        &pk,
                        &ciphertext,
                        &reveal_token,
                        b"recursion-hand1-reveal",
                        &mut rng,
                    )
                    .expect("reveal proof");
                    reveal_prove += started.elapsed();
                    let started = std::time::Instant::now();
                    verify_reveal_token(
                        &pk,
                        &ciphertext,
                        &reveal_token,
                        b"recursion-hand1-reveal",
                        &wire,
                        &proof,
                    )
                    .expect("reveal verify");
                    reveal_verify += started.elapsed();
                }
            }
            let fold_prove = reveal_start.elapsed() - reveal_prove;
            client_prove += fold_prove + reveal_prove;
            let started = std::time::Instant::now();
            verify_deck_dleq(
                RistrettoDeckDleqDirection::Remask,
                &input,
                &output,
                &pk,
                b"recursion-hand1-fold",
                &wire,
                &proof,
            )
            .expect("deck DLEQ verify");
            server_native_verify += reveal_verify + started.elapsed();
        }
        eprintln!(
            "[client native] fold x1 + reveal x32x3: included in client total below"
        );
        eprintln!(
            "client native prove total (ownership+shuffle+fold+reveal): {client_prove:?}; server native verify (player proofs): {server_native_verify:?}"
        );

        // ---- Server recursion artifacts: the ONLY circuit proving. Nine
        // deck-52 BG shuffle admissions, one admission STARK per shuffle.
        // (The fixture's native BG prove/verify above plays the client;
        // only the admission STARK below is server-side.) -----------------
        let mut recursion_prove = std::time::Duration::ZERO;
        let mut recursion_verify = std::time::Duration::ZERO;
        let mut recursion_bytes = 0usize;
        for shuffle in 0..9u64 {
            // The fixture runs the client's native BG prove and the
            // extractor's native verify replay — time it as client work.
            let started = std::time::Instant::now();
            let components = bg_components_fixture_seeded(52, 0x5A1E + shuffle);
            client_prove += started.elapsed();
            let started = std::time::Instant::now();
            let archive = prove_ristretto_bg_admission_components(&components)
                .expect("BG admission STARK");
            let prove_elapsed = started.elapsed();
            let started = std::time::Instant::now();
            verify_ristretto_bg_admission_components(&components, &archive)
                .expect("BG admission verify");
            let verify_elapsed = started.elapsed();
            let bytes = archive.stark_proof_bytes.len();
            eprintln!(
                "[shuffle{shuffle} admission] prove {prove_elapsed:>9.2?}, verify {verify_elapsed:>8.3?}, {:.2} MB",
                bytes as f64 / 1e6
            );
            recursion_prove += prove_elapsed;
            recursion_verify += verify_elapsed;
            recursion_bytes += bytes;
        }
        eprintln!(
            "=== full-hand recursion artifacts (9 shuffle admissions): prove {recursion_prove:?}, verify {recursion_verify:?}, {:.2} MB ===",
            recursion_bytes as f64 / 1e6
        );
    }

    /// Microbenchmark of the two lifted Merkle hashers stwo 2.3 ships
    /// (Starknet Poseidon252, the current channel, vs Blake2s) on the leaf
    /// and node shapes the admission commitment uses. Leaves absorb 16 M31
    /// values per Poseidon permutation block (64 bytes for Blake2s); nodes
    /// hash two 32-byte digests. Blake3 has no lifted channel in stwo 2.3
    /// and matches Blake2s per-block at these sizes.
    #[test]
    #[ignore = "microbenchmark: cargo test --release --lib merkle_hasher_microbench -- --ignored --nocapture"]
    fn merkle_hasher_microbench() {
        use std::hint::black_box;
        use stwo::core::fields::m31::M31;
        use stwo::core::vcs_lifted::blake2_merkle::Blake2sMerkleHasher;
        use stwo::core::vcs_lifted::merkle_hasher::MerkleHasherLifted;
        use stwo::core::vcs_lifted::poseidon252_merkle::Poseidon252MerkleHasher;

        const BLOCKS: usize = 150; // ~2,400 M31 values: one ladder trace point.
        let values: Vec<M31> = (0..(16 * BLOCKS) as u32).map(M31::from).collect();

        fn bench_leaf<F: FnMut(&[M31])>(label: &str, mut absorb: F) {
            const ITERS: usize = 2_000;
            let values: Vec<M31> = (0..(16 * 150) as u32).map(M31::from).collect();
            let started = std::time::Instant::now();
            for _ in 0..ITERS {
                absorb(black_box(&values));
            }
            let elapsed = started.elapsed();
            eprintln!(
                "{label}: {elapsed:?} total, {:.1} ns per 16-value block, {:.1} us per {}-value leaf",
                elapsed.as_nanos() as f64 / ITERS as f64 / 150.0,
                elapsed.as_nanos() as f64 / ITERS as f64 / 1_000.0,
                values.len(),
            );
        }

        fn bench_node<F: FnMut()>(label: &str, mut hash_node: F) {
            const ITERS: usize = 200_000;
            let started = std::time::Instant::now();
            for _ in 0..ITERS {
                hash_node();
            }
            let elapsed = started.elapsed();
            eprintln!(
                "{label}: {:.1} ns per node hash",
                elapsed.as_nanos() as f64 / ITERS as f64,
            );
        }

        bench_leaf("poseidon252 leaf", |values| {
            let mut hasher = Poseidon252MerkleHasher::default();
            hasher.update_leaf(values);
            black_box(hasher.finalize());
        });
        bench_leaf("blake2s    leaf", |values| {
            let mut hasher = Blake2sMerkleHasher::default();
            hasher.update_leaf(values);
            black_box(hasher.finalize());
        });

        // Node hashing: two child digests per call (the tree's internal
        // layer, ~one hash per node).
        let poseidon_children = {
            let mut hasher = Poseidon252MerkleHasher::default();
            hasher.update_leaf(&values[..16]);
            let digest = hasher.finalize();
            (digest, digest)
        };
        bench_node("poseidon252 node", || {
            let digest = Poseidon252MerkleHasher::hash_children(poseidon_children.clone());
            black_box(&digest);
        });

        let blake_children = {
            let mut hasher = Blake2sMerkleHasher::default();
            hasher.update_leaf(&values[..16]);
            let digest = hasher.finalize();
            (digest, digest)
        };
        bench_node("blake2s    node", || {
            let digest = Blake2sMerkleHasher::hash_children(blake_children.clone());
            black_box(&digest);
        });
    }

    #[test]
    fn bg_admission_stark_proves_and_verifies() {
        let components = bg_components_fixture(4);
        let (statement, equalities) = decompose_bg_admission(&components).expect("decomposition");
        eprintln!(
            "BG admission decomposition (deck 4): {} ladders, {} additions, {} equalities",
            statement.ladders.len(),
            statement.additions.len(),
            equalities.len()
        );
        assert_eq!(statement.schedules[0].deck_size, 4);
        assert_eq!(statement.schedules.len(), 1);
        let started = std::time::Instant::now();
        let archive =
            prove_ristretto_bg_admission_components(&components).expect("BG admission STARK");
        let prove_elapsed = started.elapsed();
        let started = std::time::Instant::now();
        verify_ristretto_bg_admission_components(&components, &archive)
            .expect("BG admission verify");
        let verify_elapsed = started.elapsed();
        eprintln!(
            "BG admission STARK (deck 4): prove {prove_elapsed:?}, verify {verify_elapsed:?}, proof {} bytes",
            archive.stark_proof_bytes.len()
        );
    }

    #[test]
    fn bg_admission_rejects_tampered_proofs() {
        let components = bg_components_fixture(4);
        let archive =
            prove_ristretto_bg_admission_components(&components).expect("BG admission STARK");
        assert!(verify_ristretto_bg_admission_components(&components, &archive).is_ok());

        // A tampered response scalar breaks a decomposed equation natively.
        let mut tampered = components.clone();
        tampered.proof.multi_exponentiation.alpha_response[0] =
            tampered.proof.multi_exponentiation.alpha_response[0] + BgScalar::one();
        assert!(verify_ristretto_bg_admission_components(&tampered, &archive).is_err());

        // A tampered commitment point breaks the multi-exponentiation check.
        let mut tampered = components.clone();
        tampered.proof.multi_exponentiation.c_beta =
            tampered.proof.multi_exponentiation.c_beta + RistrettoCurve::base_g();
        assert!(verify_ristretto_bg_admission_components(&tampered, &archive).is_err());

        // A spliced admission statement detaches from the component set.
        let mut spliced = archive.clone();
        spliced.statement.ladders[0].output[7] ^= 1;
        assert!(verify_ristretto_bg_admission_components(&components, &spliced).is_err());

        // Spliced proof bytes fail the STARK.
        let proof_len = archive.stark_proof_bytes.len();
        let mut spliced = archive.clone();
        spliced.stark_proof_bytes[proof_len / 2] ^= 1;
        assert!(verify_ristretto_bg_admission_components(&components, &spliced).is_err());
    }

    /// The folded Poseidon2-M31 transcript segment proves and verifies
    /// inside the unified admission STARK (fixed 2026-08-28).  Three
    /// stacked defects had parked it: (1) the LogUp fraction generator
    /// packed trace columns in natural row order, but
    /// `LogupTraceGenerator` stores secure columns bit-reversed — the
    /// fractions were permuted relative to the constraint evaluation;
    /// (2) the verifier built its components with zero LogUp claimed
    /// sums — harmless while every other segment telescopes to exactly
    /// zero, but this segment's `Σ (1/d_init − 1/d_digest)` never does,
    /// so the archive sums are now restored into the verifier-side
    /// segments; (3) the verifier declared the tree-2 layout from the
    /// (never materialized) interaction vector instead of the fixed
    /// per-row entry count.
    #[test]
    fn admission_poseidon2_segment_proves_and_verifies() {
        use crate::ristretto_poseidon2_air::Poseidon2ChainSpec;

        let components = bg_components_fixture(4);
        let (mut statement, _) = decompose_bg_admission(&components).expect("decomposition");
        let initial_states = vec![
            core::array::from_fn(|i| (i as u32 * 31) % 0x7FFF_FFFF),
            core::array::from_fn(|i| (i as u32 * 17 + 5) % 0x7FFF_FFFF),
        ];
        statement.poseidon2 = Some(Poseidon2ChainSpec {
            absorbed_words: (0..initial_states.len() * 24)
                .map(|step| core::array::from_fn(|lane| (step as u32 * 8 + lane as u32 * 3) % 0x7FFF_FFFF))
                .collect(),
            initial_states,
            chain_length: 24,
        });
        let archive = prove_ristretto_admission_stark(statement).expect("admission STARK");
        verify_ristretto_admission_stark(&archive).expect("admission verify");

        // A spliced initial state detaches the scope tree (the digest pins
        // the spec).
        let mut spliced = archive.clone();
        spliced.statement.poseidon2.as_mut().unwrap().initial_states[0][0] ^= 1;
        assert!(verify_ristretto_admission_stark(&spliced).is_err());

        // A spliced absorbed word detaches the digest-bound word schedule.
        let mut spliced = archive.clone();
        spliced.statement.poseidon2.as_mut().unwrap().absorbed_words[3][2] ^= 1;
        assert!(verify_ristretto_admission_stark(&spliced).is_err());
    }

    /// A player's ownership + reveal proofs on the Poseidon2-M31 path,
    /// leaked for the test's lifetime (the entries borrow the wires).
    fn player_poseidon2_fixture() -> PlayerPoseidon2Inputs<'static> {
        use crate::ristretto_player_proofs_air::{
            prove_pk_ownership_poseidon2, prove_reveal_token_poseidon2,
        };
        use rand::SeedableRng;
        use rand::rngs::StdRng;
        let mut rng = StdRng::seed_from_u64(0x51DE_00AA);
        let sk = BgScalar::random(&mut rng);
        let pk = base_point_value() * sk;
        let (ownership_wire, _) =
            prove_pk_ownership_poseidon2(&sk, &pk, b"hand-1-seat-0", &mut rng)
                .expect("poseidon2 ownership proof");
        let card = RistrettoCurve::hash_to_curve(b"poseidon2-hand/card/1");
        let randomness = BgScalar::random(&mut rng);
        let ciphertext = BgCiphertext::encrypt(&card, &pk, &randomness);
        let reveal_token = ciphertext.c1 * sk;
        let (reveal_wire, _) = prove_reveal_token_poseidon2(
            &sk,
            &pk,
            &ciphertext,
            &reveal_token,
            b"hand-1-reveal",
            &mut rng,
        )
        .expect("poseidon2 reveal proof");
        let pk = Box::leak(Box::new(pk));
        let ciphertext = Box::leak(Box::new(ciphertext));
        let reveal_token = Box::leak(Box::new(reveal_token));
        let ownership_wire = Box::leak(Box::new(ownership_wire));
        let reveal_wire = Box::leak(Box::new(reveal_wire));
        PlayerPoseidon2Inputs {
            pk_ownership: vec![PlayerPkOwnershipPoseidon2Entry {
                pk,
                context: b"hand-1-seat-0",
                wire: ownership_wire,
            }],
            reveal_tokens: vec![PlayerRevealTokenPoseidon2Entry {
                pk,
                ciphertext,
                reveal_token,
                context: b"hand-1-reveal",
                wire: reveal_wire,
            }],
            deck_dleqs: Vec::new(),
        }
    }

    /// Whole-hand admission ("一手一证"): three deck-4 shuffles plus a
    /// player's ownership/reveal equations and REAL Poseidon2 transcript
    /// chains fold into ONE STARK under a Poseidon2 hand root.
    #[test]
    fn hand_admission_proves_and_verifies() {
        use crate::ristretto_poseidon2_transcript::{Poseidon2M31Transcript, poseidon2_root};
        use poker_protocol_core::CryptoTranscript;

        let shuffles: Vec<BgAdmissionComponents> = (0..3u64)
            .map(|shuffle| bg_components_fixture_seeded(4, 0x5A1E + shuffle))
            .collect();

        // One real Poseidon2 transcript per folded action: absorb the
        // action context and derive a challenge, exactly as the native
        // protocol would.
        let specs: Vec<_> = (0..4u64)
            .map(|action| {
                let mut transcript = Poseidon2M31Transcript::new(
                    format!("recursion-hand1-action{action}").as_bytes(),
                );
                transcript.append_message(
                    b"context",
                    format!("hand-1-action-{action}").as_bytes(),
                );
                transcript.append_message(b"pk", &[(action + 1) as u8; 32]);
                let _ = transcript.challenge::<RistrettoCurve>(b"challenge");
                transcript.into_chain_spec()
            })
            .collect();
        let poseidon2 = merge_poseidon2_chain_specs(&specs).expect("chains");
        let hand_root = poseidon2_root(&poseidon2.digests());

        // REAL Poseidon2 player proofs: the folded equations' challenges
        // are derived from the very transcript chains folded into the
        // statement below — the closed Flock-free loop.
        let poseidon2_players = vec![player_poseidon2_fixture()];

        let components = HandAdmissionComponents {
            shuffles,
            shuffle_chains: Vec::new(),
            players: Vec::new(),
            poseidon2_players,
            hand_root,
            poseidon2: Some(poseidon2),
        };
        // The merged statement carries every shuffle's schedule and the
        // folded player equations.
        let statement = decompose_hand_admission(&components).expect("hand decomposition");
        assert_eq!(statement.schedules.len(), 3);
        assert_eq!(statement.recurrences.len(), 3);
        assert!(statement.ladders.len() > 3 * 40);

        let archive = prove_hand_admission_components(&components).expect("hand STARK");
        verify_hand_admission_components(&components, &archive).expect("hand verify");

        // A spliced hand root detaches the statement.
        let mut spliced = archive.clone();
        spliced.statement.tag[7] ^= 1;
        assert!(verify_hand_admission_components(&components, &spliced).is_err());

        // Dropping a shuffle detaches the statement.
        let fewer = HandAdmissionComponents {
            shuffles: components.shuffles[..2].to_vec(),
            shuffle_chains: components.shuffle_chains.clone(),
            players: Vec::new(),
            poseidon2_players: components.poseidon2_players.clone(),
            hand_root: components.hand_root,
            poseidon2: components.poseidon2.clone(),
        };
        assert!(verify_hand_admission_components(&fewer, &archive).is_err());

        // A spliced transcript word detaches the digest-bound chain spec.
        let mut spliced = archive.clone();
        spliced.statement.poseidon2.as_mut().unwrap().absorbed_words[2][1] ^= 1;
        assert!(verify_hand_admission_components(&components, &spliced).is_err());

        // Spliced proof bytes fail the STARK.
        let mut spliced = archive.clone();
        let len = spliced.stark_proof_bytes.len();
        spliced.stark_proof_bytes[len / 2] ^= 1;
        assert!(verify_hand_admission_components(&components, &spliced).is_err());
    }

    /// Fully-Poseidon2 hand: the SHUFFLES themselves are proven under the
    /// M31 transcript (`prove_bg_admission_poseidon2`), a 52-card deck
    /// DLEQ rides the same path, and the player equations come from the
    /// Poseidon2 fixture — every folded chain is a real protocol
    /// transcript, zero Flock artifacts anywhere.
    #[test]
    fn hand_admission_poseidon2_end_to_end() {
        use crate::ristretto_poseidon2_transcript::poseidon2_root;
        use rand::SeedableRng;
        use rand::rngs::StdRng;

        // Three deck-4 shuffles proven over the Poseidon2 transcript.
        let mut shuffle_chains = Vec::new();
        let mut shuffles = Vec::new();
        for shuffle in 0..3u64 {
            let mut rng = StdRng::seed_from_u64(0x90C1_0000 + shuffle);
            let g = RistrettoCurve::base_g();
            let secret = BgScalar::random(&mut rng);
            let public_key = g * secret;
            let input = (0..4)
                .map(|_| {
                    let rerandomizer = BgScalar::random(&mut rng);
                    BgCiphertext {
                        c1: g * rerandomizer,
                        c2: public_key * rerandomizer,
                    }
                })
                .collect::<Vec<_>>();
            let mut permutation = vec![0usize, 1, 2, 3];
            use rand::seq::SliceRandom;
            permutation.shuffle(&mut rng);
            let rerandomizers = (0..4)
                .map(|_| BgScalar::random(&mut rng))
                .collect::<Vec<_>>();
            let output = permutation
                .iter()
                .zip(&rerandomizers)
                .map(|(&source, rerandomizer)| {
                    input[source].re_encrypt(&public_key, rerandomizer)
                })
                .collect::<Vec<_>>();
            let (components, chain) = prove_bg_admission_poseidon2(
                &input,
                &output,
                &permutation,
                &rerandomizers,
                &public_key,
                [0x5b + shuffle as u8; 32],
                &mut rng,
            )
            .expect("poseidon2 BG admission");
            shuffles.push(components);
            shuffle_chains.push(chain);
        }

        // A fold (deck DLEQ, 52 cards) on the same Poseidon2 path.
        let mut rng = StdRng::seed_from_u64(0xF01D_00BB);
        let sk = BgScalar::random(&mut rng);
        let pk = base_point_value() * sk;
        let dleq_input = (0..52)
            .map(|index| {
                let card = RistrettoCurve::hash_to_curve(
                    format!("poseidon2-e2e/card/{index}").as_bytes(),
                );
                let randomness = BgScalar::random(&mut rng);
                BgCiphertext::encrypt(&card, &pk, &randomness)
            })
            .collect::<Vec<_>>();
        let dleq_output = dleq_input
            .iter()
            .map(|ct| BgCiphertext {
                c1: ct.c1,
                c2: ct.c2 + ct.c1 * sk,
            })
            .collect::<Vec<_>>();
        let (dleq_wire, dleq_chain) = crate::ristretto_player_proofs_air::prove_deck_dleq_poseidon2(
            crate::ristretto_player_proofs_air::RistrettoDeckDleqDirection::Remask,
            &dleq_input,
            &dleq_output,
            &sk,
            &pk,
            b"poseidon2-e2e-fold",
            &mut rng,
        )
        .expect("poseidon2 deck DLEQ");
        let dleq_input = Box::leak(Box::new(dleq_input));
        let dleq_output = Box::leak(Box::new(dleq_output));
        let dleq_pk = Box::leak(Box::new(pk));
        let dleq_wire = Box::leak(Box::new(dleq_wire));

        let mut all_chains = shuffle_chains.clone();
        all_chains.push(dleq_chain);
        let hand_root = poseidon2_root(
            &merge_poseidon2_chain_specs(&all_chains)
                .expect("chains")
                .digests(),
        );

        let components = HandAdmissionComponents {
            shuffles,
            shuffle_chains,
            players: Vec::new(),
            poseidon2_players: vec![PlayerPoseidon2Inputs {
                pk_ownership: Vec::new(),
                reveal_tokens: Vec::new(),
                deck_dleqs: vec![PlayerDeckDleqPoseidon2Entry {
                    direction:
                        crate::ristretto_player_proofs_air::RistrettoDeckDleqDirection::Remask,
                    input: dleq_input,
                    output: dleq_output,
                    pk: dleq_pk,
                    context: b"poseidon2-e2e-fold",
                    wire: dleq_wire,
                }],
            }],
            hand_root,
            poseidon2: None,
        };
        let statement = decompose_hand_admission(&components).expect("decomposition");
        // Three schedules, three recurrences, the fold's 53 extra
        // equations, and every action's chain in one batch.
        assert_eq!(statement.schedules.len(), 3);
        assert_eq!(statement.recurrences.len(), 3);
        let chains = statement.poseidon2.as_ref().expect("folded chains");
        assert_eq!(chains.initial_states.len(), 4); // 3 shuffles + 1 fold

        let archive = prove_hand_admission_components(&components).expect("hand STARK");
        verify_hand_admission_components(&components, &archive).expect("hand verify");

        // Tampering the folded transcript words detaches the digest.
        let mut spliced = archive.clone();
        spliced.statement.poseidon2.as_mut().unwrap().absorbed_words[5][0] ^= 1;
        assert!(verify_hand_admission_components(&components, &spliced).is_err());

        // A wrong fold direction derives different challenges.
        let mut wrong = components;
        wrong.poseidon2_players[0].deck_dleqs[0].direction =
            crate::ristretto_player_proofs_air::RistrettoDeckDleqDirection::Leave;
        assert!(verify_hand_admission_components(&wrong, &archive).is_err());
    }

    /// Whole-hand deck-52 batch benchmark: nine shuffle admissions folded
    /// into ONE STARK (the "一手一证" settlement artifact), with the
    /// hand's transcript chains (6 × 176 steps per shuffle) folded into
    /// the Poseidon2 segment.  Compare against §4.0.1's nine separate
    /// artifacts (1,417.8s prove / 384.6 MB).  The shuffle count defaults
    /// to nine; `TEXAS_HAND_SHUFFLES=k` runs a k-shuffle variant (a
    /// nine-shuffle ladder segment is log-21 — expect a heavy memory
    /// footprint and swap on 32 GB machines).
    #[test]
    #[ignore = "whole-hand batch benchmark: tens of minutes"]
    fn hand_admission_deck52_batch_benchmark() {
        use crate::ristretto_poseidon2_transcript::{Poseidon2M31Transcript, poseidon2_root};
        use poker_protocol_core::CryptoTranscript;

        let shuffle_count: u64 = std::env::var("TEXAS_HAND_SHUFFLES")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(9);
        let shuffles: Vec<BgAdmissionComponents> = (0..shuffle_count)
            .map(|shuffle| bg_components_fixture_seeded(52, 0x5A1E + shuffle))
            .collect();

        // Realistic transcript load: six chains of 176 steps per shuffle
        // (1 init + 5 challenge flushes × ~172 absorbed elements).
        let specs: Vec<_> = (0..shuffle_count * 6)
            .map(|action| {
                let mut transcript = Poseidon2M31Transcript::new(
                    format!("recursion-hand1-chain{action}").as_bytes(),
                );
                transcript.append_message(b"context", &[7u8; 96]);
                for round in 0..5u64 {
                    transcript.append_message(b"wire", &[(action + round) as u8; 1_100]);
                    let _ = transcript.challenge::<RistrettoCurve>(b"challenge");
                }
                transcript.into_chain_spec()
            })
            .collect();
        let poseidon2 = merge_poseidon2_chain_specs(&specs).expect("chains");
        let hand_root = poseidon2_root(&poseidon2.digests());

        let components = HandAdmissionComponents {
            shuffles,
            shuffle_chains: Vec::new(),
            players: Vec::new(),
            poseidon2_players: Vec::new(),
            hand_root,
            poseidon2: Some(poseidon2),
        };
        let started = std::time::Instant::now();
        let archive = prove_hand_admission_components(&components).expect("hand STARK");
        let prove_elapsed = started.elapsed();
        let bytes = archive.stark_proof_bytes.len();
        let started = std::time::Instant::now();
        verify_hand_admission_components(&components, &archive).expect("hand verify");
        let verify_elapsed = started.elapsed();
        eprintln!(
            "=== whole-hand admission ({shuffle_count} shuffles + {} chains, ONE STARK): prove {prove_elapsed:?}, verify {verify_elapsed:?}, {:.2} MB ===",
            shuffle_count * 6,
            bytes as f64 / 1e6
        );
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
            "admission STARK v2 (2 ladders + accumulation + schedule deck 12): prove {prove_elapsed:?}, verify {verify_elapsed:?}, proof {proof_len} bytes"
        );

        // Reference: the same components as separate proofs (ladder batch
        // with its codec STARKs, then the schedule).
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
            let spec = &statement.schedules[0];
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
        // The addition row as its own separate one-row Fp program batch.
        let separate_addition =
            crate::ristretto_fp_program_air::prove_ristretto_fp_program_batch(&vec![
                build_ristretto_fp_program_compressed_point_addition(
                    &statement.additions[0].left,
                    &statement.additions[0].right,
                )
                .expect("separate addition program")
                .0,
            ])
            .expect("separate addition proof");
        let separate_elapsed = started.elapsed();
        let started = std::time::Instant::now();
        crate::ristretto_scalar_mul_air::verify_ristretto_scalar_mul_ladder_batch(
            &separate_ladders,
        )
        .expect("separate ladder verify");
        crate::ristretto_scalar_program_air::verify_ristretto_scalar_program(&separate_schedule)
            .expect("separate schedule verify");
        crate::ristretto_fp_program_air::verify_ristretto_fp_program_batch(&separate_addition)
            .expect("separate addition verify");
        let separate_verify = started.elapsed();
        // Account for every separate STARK: the ladder proof, its embedded
        // decode/encode batch proofs, the addition batch, and the schedule.
        let separate_bytes = separate_ladders.stark_proof_bytes.len()
            + separate_ladders.codecs.stark_proof_bytes.len()
            + separate_addition.stark_proof_bytes.len()
            + separate_schedule.stark_proof_bytes.len();
        eprintln!(
            "separate proofs: prove {separate_elapsed:?}, verify {separate_verify:?}, proofs {separate_bytes} bytes (ladder {} + codecs {} + addition {} + schedule {})",
            separate_ladders.stark_proof_bytes.len(),
            separate_ladders.codecs.stark_proof_bytes.len(),
            separate_addition.stark_proof_bytes.len(),
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
        spliced.statement.schedules[0].product_y[0] ^= 1;
        assert!(verify_ristretto_admission_stark(&spliced).is_err());

        // A detached ladder output fails the native rebuild.
        let mut spliced = archive.clone();
        spliced.statement.ladders[0].output[3] ^= 1;
        assert!(verify_ristretto_admission_stark(&spliced).is_err());

        // A detached accumulation row fails its native rebuild.
        let mut spliced = archive.clone();
        spliced.statement.additions[0].output[5] ^= 1;
        assert!(verify_ristretto_admission_stark(&spliced).is_err());

        // Dropping the accumulation row changes the digest and segment set.
        let mut spliced = archive.clone();
        spliced.statement.additions.clear();
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
        for slot in 0..archive.claimed_sums.len() {
            let mut spliced = archive.clone();
            spliced.claimed_sums[slot][1] ^= 1;
            assert!(
                verify_ristretto_admission_stark(&spliced).is_err(),
                "splicing claimed sum {slot} must fail"
            );
        }
    }
}
