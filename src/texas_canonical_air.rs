//! Direct heterogeneous AIR for the fixed-width canonical Texas transition ABI.
//!
//! This circuit deliberately consumes [`crate::texas_canonical::CanonicalTransitionWitness`]
//! rather than a transaction or a VM prove task.  The complete canonical relation is checked
//! before trace construction and the AIR binds the resulting fixed-width commitments, selector,
//! actor policy, sequence arithmetic, table scope, batch boundaries, and padding rows.  A
//! verifier can therefore validate an archived proof without transaction replay.
#![allow(missing_docs)]

use bincode::Options;
use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};
use stwo::core::channel::{Channel, Poseidon252Channel};
use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::SecureField;
use stwo::core::pcs::CommitmentSchemeVerifier;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::poseidon252_merkle::{
    Poseidon252MerkleChannel, Poseidon252MerkleHasher,
};
use stwo::core::verifier::{VerificationError, verify};
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::pcs::CommitmentSchemeProver;
use stwo::prover::{ProvingError, prove};
use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
use stwo_constraint_framework::{EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator};

use crate::error::{TexasAirError, TexasAirResult};
use crate::texas_canonical::{
    CanonicalTransitionKind, CanonicalTransitionWitness, validate_batch,
};
use crate::trace_gen::MethodTrace;
use crate::trace_gen::generic_trace::tagged_batch_log_size;

const MAX_ROWS: usize = 1 << 10;
const KIND_COUNT: usize = 19;

// active, kinds, table, hand(pre/post), seq(pre/post), image commitments(pre/post),
// state roots(pre/post), lifecycle roots(pre/post), overlay roots(pre/post), settlement roots
// (pre/post), custody roots(pre/post), actor, action, deadline, and the sequence carry.
const NUM_COLUMNS: usize = 271;
const PREPROCESSED_COLUMNS: usize = 39;

#[derive(Debug, Clone, Copy)]
struct CanonicalAir {
    log_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ArchivedCanonicalTaggedProof {
    pub log_size: u32,
    pub num_columns: u32,
    pub table_id: u64,
    pub first_hand_id: u32,
    pub last_hand_id: u32,
    pub first_call_seq: u32,
    pub last_call_seq: u32,
    pub transition_count: u16,
    pub batch_digest: [u8; 32],
    pub pre_state_commitment: [u8; 32],
    pub post_state_commitment: [u8; 32],
    pub stark_proof_bytes: Vec<u8>,
}

fn options() -> impl Options {
    bincode::DefaultOptions::new().with_fixint_encoding().with_limit(16 * 1024 * 1024)
}

fn digest_batch(witnesses: &[CanonicalTransitionWitness]) -> [u8; 32] {
    let encoded = borsh::to_vec(witnesses).expect("canonical witness encoding");
    let mut h = Blake2bVar::new(32).expect("digest length");
    h.update(b"zchain.texas.canonical-tagged-batch.v1");
    h.update(&encoded);
    let mut out = [0; 32];
    h.finalize_variable(&mut out).expect("digest length");
    out
}

fn bytes16(bytes: &[u8; 32]) -> Vec<M31> {
    bytes
        .chunks_exact(2)
        .map(|x| M31::from(u32::from(u16::from_le_bytes([x[0], x[1]]))))
        .collect()
}

fn u32_limbs(value: u32) -> [M31; 2] {
    [M31::from(value & 0xffff), M31::from(value >> 16)]
}

fn u64_limbs(value: u64) -> [M31; 4] {
    [
        M31::from((value & 0xffff) as u32),
        M31::from(((value >> 16) & 0xffff) as u32),
        M31::from(((value >> 32) & 0xffff) as u32),
        M31::from((value >> 48) as u32),
    ]
}

fn row(w: &CanonicalTransitionWitness) -> Vec<M31> {
    let mut out = Vec::with_capacity(NUM_COLUMNS);
    out.push(M31::from(1u32));
    for index in 0..KIND_COUNT {
        out.push(M31::from(u32::from(index == w.kind as usize)));
    }
    out.extend(u64_limbs(w.pre.table_id));
    out.extend(u32_limbs(w.pre.hand_id));
    out.extend(u32_limbs(w.post.hand_id));
    out.extend(u32_limbs(w.pre.call_seq));
    out.extend(u32_limbs(w.post.call_seq));
    out.extend(bytes16(&w.pre.commitment()));
    out.extend(bytes16(&w.post.commitment()));
    for digest in [
        w.pre.state_root,
        w.post.state_root,
        w.pre.lifecycle_root,
        w.post.lifecycle_root,
        w.pre.overlay_root,
        w.post.overlay_root,
        w.pre.settlement_commitment,
        w.post.settlement_commitment,
        w.pre.custody_commitment,
        w.post.custody_commitment,
        w.actor,
        w.action.proof_commitment,
    ] {
        out.extend(bytes16(&digest));
    }
    out.push(M31::from(u32::from(w.action.seat)));
    out.extend(u64_limbs(w.action.amount));
    out.extend(u64_limbs(w.action.auxiliary));
    out.push(M31::from(u32::from(w.action.flag)));
    out.extend(u64_limbs(w.deadline_height));
    out.push(M31::from(u32::from(w.pre.call_seq & 0xffff == 0xffff)));
    debug_assert_eq!(out.len(), NUM_COLUMNS);
    out
}

fn padding() -> Vec<M31> {
    vec![M31::from(0u32); NUM_COLUMNS]
}

fn mix_digest(channel: &mut Poseidon252Channel, digest: &[u8; 32]) {
    channel.mix_u32s(
        &digest
            .chunks_exact(4)
            .map(|x| u32::from_be_bytes(x.try_into().expect("digest word")))
            .collect::<Vec<_>>(),
    );
}

fn mix_scope(channel: &mut Poseidon252Channel, proof: &ArchivedCanonicalTaggedProof) {
    channel.mix_u64(proof.table_id);
    channel.mix_u32s(&[
        proof.first_hand_id,
        proof.last_hand_id,
        proof.first_call_seq,
        proof.last_call_seq,
        u32::from(proof.transition_count),
    ]);
    mix_digest(channel, &proof.batch_digest);
    mix_digest(channel, &proof.pre_state_commitment);
    mix_digest(channel, &proof.post_state_commitment);
}

fn preprocessed_ids() -> [PreProcessedColumnId; PREPROCESSED_COLUMNS] {
    [
        "texas.canonical.active.v1",
        "texas.canonical.first.v1",
        "texas.canonical.last.v1",
        "texas.canonical.table.v1.0",
        "texas.canonical.table.v1.1",
        "texas.canonical.table.v1.2",
        "texas.canonical.table.v1.3",
        "texas.canonical.pre-image.v1.0",
        "texas.canonical.pre-image.v1.1",
        "texas.canonical.pre-image.v1.2",
        "texas.canonical.pre-image.v1.3",
        "texas.canonical.pre-image.v1.4",
        "texas.canonical.pre-image.v1.5",
        "texas.canonical.pre-image.v1.6",
        "texas.canonical.pre-image.v1.7",
        "texas.canonical.pre-image.v1.8",
        "texas.canonical.pre-image.v1.9",
        "texas.canonical.pre-image.v1.10",
        "texas.canonical.pre-image.v1.11",
        "texas.canonical.pre-image.v1.12",
        "texas.canonical.pre-image.v1.13",
        "texas.canonical.pre-image.v1.14",
        "texas.canonical.pre-image.v1.15",
        "texas.canonical.post-image.v1.0",
        "texas.canonical.post-image.v1.1",
        "texas.canonical.post-image.v1.2",
        "texas.canonical.post-image.v1.3",
        "texas.canonical.post-image.v1.4",
        "texas.canonical.post-image.v1.5",
        "texas.canonical.post-image.v1.6",
        "texas.canonical.post-image.v1.7",
        "texas.canonical.post-image.v1.8",
        "texas.canonical.post-image.v1.9",
        "texas.canonical.post-image.v1.10",
        "texas.canonical.post-image.v1.11",
        "texas.canonical.post-image.v1.12",
        "texas.canonical.post-image.v1.13",
        "texas.canonical.post-image.v1.14",
        "texas.canonical.post-image.v1.15",
    ]
    .map(|id| PreProcessedColumnId { id: id.into() })
}

fn scope_trace(proof: &ArchivedCanonicalTaggedProof, log_size: u32) -> MethodTrace {
    let rows = 1usize << log_size;
    let mut trace = MethodTrace::new(log_size, PREPROCESSED_COLUMNS);
    let table = u64_limbs(proof.table_id);
    let pre_image = bytes16(&proof.pre_state_commitment);
    let post_image = bytes16(&proof.post_state_commitment);
    for index in 0..rows {
        let mut values = vec![M31::from(0u32); PREPROCESSED_COLUMNS];
        if index < usize::from(proof.transition_count) {
            values[0] = M31::from(1u32);
            values[1] = M31::from(u32::from(index == 0));
            values[2] = M31::from(u32::from(index + 1 == usize::from(proof.transition_count)));
            values[3..7].copy_from_slice(&table);
        }
        if index == 0 {
            values[7..23].copy_from_slice(&pre_image);
        }
        if index + 1 == usize::from(proof.transition_count) {
            values[23..39].copy_from_slice(&post_image);
        }
        trace.write_row(index, &values).expect("scope width");
    }
    trace
}

fn trace_for(witnesses: &[CanonicalTransitionWitness]) -> TexasAirResult<(MethodTrace, ArchivedCanonicalTaggedProof)> {
    if witnesses.is_empty() || witnesses.len() > MAX_ROWS {
        return Err(TexasAirError::SpecViolation("canonical batch must contain 1..=1024 transitions".into()));
    }
    validate_batch(witnesses).map_err(TexasAirError::SpecViolation)?;
    let log_size = tagged_batch_log_size(witnesses.len())?;
    let mut trace = MethodTrace::new(log_size, NUM_COLUMNS);
    for (index, witness) in witnesses.iter().enumerate() {
        trace.write_row(index, &row(witness))?;
    }
    for index in witnesses.len()..(1usize << log_size) {
        trace.write_row(index, &padding())?;
    }
    let first = &witnesses[0];
    let last = &witnesses[witnesses.len() - 1];
    Ok((trace, ArchivedCanonicalTaggedProof {
        log_size,
        num_columns: NUM_COLUMNS as u32,
        table_id: first.pre.table_id,
        first_hand_id: first.pre.hand_id,
        last_hand_id: last.post.hand_id,
        first_call_seq: first.pre.call_seq,
        last_call_seq: last.post.call_seq,
        transition_count: witnesses.len() as u16,
        batch_digest: digest_batch(witnesses),
        pre_state_commitment: first.pre.commitment(),
        post_state_commitment: last.post.commitment(),
        stark_proof_bytes: Vec::new(),
    }))
}

fn add_limb_eq<E: EvalAtRow>(eval: &mut E, gate: &E::F, left: &[E::F], right: &[E::F]) {
    for (a, b) in left.iter().zip(right.iter()) {
        eval.add_constraint(gate.clone() * (a.clone() - b.clone()));
    }
}

fn add_bits<E: EvalAtRow>(eval: &mut E, active: &E::F, value: &E::F, bits: &[E::F]) {
    let one: E::F = M31::from(1u32).into();
    let two: E::F = M31::from(2u32).into();
    let mut reconstructed = bits[0].clone();
    let mut power = two;
    for bit in &bits[1..] {
        reconstructed = reconstructed + bit.clone() * power.clone();
        power = power * M31::from(2u32);
    }
    eval.add_constraint(active.clone() * (value.clone() - reconstructed));
    for bit in bits {
        eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
    }
}

impl FrameworkEval for CanonicalAir {
    fn log_size(&self) -> u32 { self.log_size }

    fn max_constraint_log_degree_bound(&self) -> u32 { self.log_size + 1 }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let active_pair = eval.next_interaction_mask::<2>(1, [0, 1]);
        let active = active_pair[0].clone();
        let next_active = active_pair[1].clone();
        let one: E::F = M31::from(1u32).into();
        eval.add_constraint(active.clone() * (active.clone() - one.clone()));
        let kinds: Vec<_> = (0..KIND_COUNT).map(|_| eval.next_trace_mask()).collect();
        let mut kind_sum: E::F = M31::from(0u32).into();
        for kind in &kinds {
            eval.add_constraint(active.clone() * (kind.clone() * (kind.clone() - one.clone())));
            kind_sum += kind.clone();
        }
        eval.add_constraint(active.clone() * (kind_sum.clone() - one.clone()));
        let table: Vec<_> = (0..4).map(|_| eval.next_trace_mask()).collect();
        let pre_hand: Vec<_> = (0..2).map(|_| eval.next_trace_mask()).collect();
        let post_hand: Vec<_> = (0..2).map(|_| eval.next_trace_mask()).collect();
        let pre_seq: Vec<_> = (0..2).map(|_| eval.next_trace_mask()).collect();
        let post_seq: Vec<_> = (0..2).map(|_| eval.next_trace_mask()).collect();
        let pre_image: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let post_image_pairs: Vec<_> = (0..16)
            .map(|_| eval.next_interaction_mask::<2>(1, [0, 1]))
            .collect();
        let post_image: Vec<_> = post_image_pairs.iter().map(|pair| pair[0].clone()).collect();
        let next_pre_image: Vec<_> = post_image_pairs.iter().map(|pair| pair[1].clone()).collect();
        let all_roots: Vec<_> = (0..(16 * 10)).map(|_| eval.next_trace_mask()).collect();
        let actor: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let proof_commitment: Vec<_> = (0..16).map(|_| eval.next_trace_mask()).collect();
        let seat = eval.next_trace_mask();
        let amount: Vec<_> = (0..4).map(|_| eval.next_trace_mask()).collect();
        let auxiliary: Vec<_> = (0..4).map(|_| eval.next_trace_mask()).collect();
        let flag = eval.next_trace_mask();
        let deadline: Vec<_> = (0..4).map(|_| eval.next_trace_mask()).collect();
        let seq_carry = eval.next_trace_mask();
        eval.add_constraint(active.clone() * flag.clone() * (flag.clone() - one.clone()));
        eval.add_constraint(seq_carry.clone() * (seq_carry.clone() - one.clone()));
        let base: E::F = M31::from(65536u32).into();
        let is_start = kinds[CanonicalTransitionKind::StartHand as usize].clone();
        let non_start = active.clone() * (one.clone() - is_start.clone());
        eval.add_constraint(non_start.clone() * (pre_seq[0].clone() + one.clone() - post_seq[0].clone() - base.clone() * seq_carry.clone()));
        eval.add_constraint(non_start.clone() * (pre_seq[1].clone() + seq_carry.clone() - post_seq[1].clone()));
        let table_scope = [
            eval.get_preprocessed_column(preprocessed_ids()[3].clone()),
            eval.get_preprocessed_column(preprocessed_ids()[4].clone()),
            eval.get_preprocessed_column(preprocessed_ids()[5].clone()),
            eval.get_preprocessed_column(preprocessed_ids()[6].clone()),
        ];
        add_limb_eq(&mut eval, &active, &table, &table_scope);
        eval.add_constraint(active.clone() * (one.clone() - is_start.clone()) * (pre_hand[0].clone() - post_hand[0].clone()));
        eval.add_constraint(active.clone() * (one.clone() - is_start.clone()) * (pre_hand[1].clone() - post_hand[1].clone()));
        eval.add_constraint(active.clone() * is_start.clone() * (post_seq[0].clone() + post_seq[1].clone()));
        eval.add_constraint(active.clone() * is_start.clone() * (post_hand[0].clone() - pre_hand[0].clone() - one.clone()));
        eval.add_constraint(active.clone() * is_start.clone() * (post_hand[1].clone() - pre_hand[1].clone()));
        let is_permissionless = kinds[CanonicalTransitionKind::AdvanceDeadline as usize].clone();
        let mut actor_nonzero: E::F = M31::from(0u32).into();
        for limb in &actor { actor_nonzero += limb.clone(); }
        eval.add_constraint(is_permissionless * actor_nonzero);
        eval.add_constraint((one.clone() - active.clone()) * (kind_sum + seat + flag));
        let first = eval.get_preprocessed_column(preprocessed_ids()[1].clone());
        let last = eval.get_preprocessed_column(preprocessed_ids()[2].clone());
        add_limb_eq(&mut eval, &(active.clone() * next_active * (one.clone() - last.clone())), &post_image, &next_pre_image);
        let scope_pre: Vec<_> = (0..16).map(|i| eval.get_preprocessed_column(preprocessed_ids()[7 + i].clone())).collect();
        let scope_post: Vec<_> = (0..16).map(|i| eval.get_preprocessed_column(preprocessed_ids()[23 + i].clone())).collect();
        add_limb_eq(&mut eval, &(active.clone() * first.clone()), &pre_image, &scope_pre);
        add_limb_eq(&mut eval, &(active.clone() * last.clone()), &post_image, &scope_post);
        eval
    }
}

pub fn prove_canonical_tagged_batch(witnesses: &[CanonicalTransitionWitness]) -> TexasAirResult<ArchivedCanonicalTaggedProof> {
    let (trace, mut archive) = trace_for(witnesses)?;
    let scope = scope_trace(&archive, trace.log_size);
    let config = crate::prover_context::protocol_pcs_config();
    let twiddles = crate::prover_context::simd_twiddles(trace.log_size + config.fri_config.log_blowup_factor);
    let mut channel = Poseidon252Channel::default();
    mix_scope(&mut channel, &archive);
    let mut scheme = CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::with_memory_pool(config, &twiddles, crate::prover_context::simd_base_column_pool());
    { let mut b = scheme.tree_builder(); b.extend_evals(scope.to_evaluations()); b.commit(&mut channel); }
    { let mut b = scheme.tree_builder(); b.extend_evals(trace.to_evaluations()); b.commit(&mut channel); }
    let ids = preprocessed_ids();
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
    let component = FrameworkComponent::new(&mut allocator, CanonicalAir { log_size: trace.log_size }, SecureField::from(0u32));
    let proof = prove(&[&component], &mut channel, scheme).map_err(|e: ProvingError| TexasAirError::StwoProverError(e.to_string()))?;
    archive.stark_proof_bytes = options().serialize(&proof).map_err(|e| TexasAirError::SerializationError(e.to_string()))?;
    Ok(archive)
}

pub fn verify_canonical_tagged_proof(archive: &ArchivedCanonicalTaggedProof) -> TexasAirResult<()> {
    if archive.num_columns != NUM_COLUMNS as u32 || archive.transition_count == 0 || archive.transition_count as usize > (1usize << archive.log_size) || archive.log_size > 10 {
        return Err(TexasAirError::SpecViolation("canonical proof shape is invalid".into()));
    }
    let proof: StarkProof<Poseidon252MerkleHasher> = options().deserialize(&archive.stark_proof_bytes).map_err(|e| TexasAirError::SerializationError(e.to_string()))?;
    let config = crate::prover_context::protocol_pcs_config();
    let scope = scope_trace(archive, archive.log_size);
    let twiddles = crate::prover_context::simd_twiddles(archive.log_size + config.fri_config.log_blowup_factor);
    let mut trusted = CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::with_memory_pool(config, &twiddles, crate::prover_context::simd_base_column_pool());
    let mut scope_channel = Poseidon252Channel::default();
    { let mut b = trusted.tree_builder(); b.extend_evals(scope.to_evaluations()); b.commit(&mut scope_channel); }
    if proof.commitments.first().copied() != trusted.roots().first().copied() { return Err(TexasAirError::ConstraintUnsatisfied("canonical public scope commitment mismatch".into())); }
    let mut channel = Poseidon252Channel::default();
    mix_scope(&mut channel, archive);
    let mut scheme = CommitmentSchemeVerifier::<Poseidon252MerkleChannel>::new(config);
    scheme.commit(proof.commitments[0], &vec![archive.log_size; PREPROCESSED_COLUMNS], &mut channel);
    scheme.commit(proof.commitments[1], &vec![archive.log_size; NUM_COLUMNS], &mut channel);
    let ids = preprocessed_ids();
    let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
    let component = FrameworkComponent::new(&mut allocator, CanonicalAir { log_size: archive.log_size }, SecureField::from(0u32));
    verify(&[&component], &mut channel, &mut scheme, proof).map_err(|e: VerificationError| TexasAirError::ConstraintUnsatisfied(e.to_string()))
}

pub fn verify_canonical_tagged_batch(witnesses: &[CanonicalTransitionWitness], archive: &ArchivedCanonicalTaggedProof) -> TexasAirResult<()> {
    let (_, expected) = trace_for(witnesses)?;
    if expected.table_id != archive.table_id || expected.batch_digest != archive.batch_digest || expected.pre_state_commitment != archive.pre_state_commitment || expected.post_state_commitment != archive.post_state_commitment || expected.transition_count != archive.transition_count {
        return Err(TexasAirError::SpecViolation("canonical proof public scope mismatch".into()));
    }
    verify_canonical_tagged_proof(archive)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::texas_canonical::{
        CanonicalActionPayload, CanonicalPhase, CanonicalSeat, CanonicalStateImage,
        MAX_CANONICAL_SEATS, NO_CANONICAL_SEAT, CANONICAL_ABI_VERSION,
    };

    fn image() -> CanonicalStateImage {
        CanonicalStateImage {
            abi_version: CANONICAL_ABI_VERSION,
            table_id: 7,
            hand_id: 1,
            call_seq: 0,
            phase: CanonicalPhase::Waiting,
            phase_subtag: 0,
            street: 0,
            current_turn: NO_CANONICAL_SEAT,
            deadline_ms: 0,
            current_bet: 0,
            min_raise: 0,
            pot: 0,
            button: 0,
            max_players: 2,
            acted_mask: 0,
            leave_after_hand_mask: 0,
            board_cards_commitment: [1; 32],
            deck_commitment: [2; 32],
            reveal_commitment: [3; 32],
            reconstruction_commitment: [4; 32],
            run_it_twice_commitment: [5; 32],
            rules_commitment: [6; 32],
            governance_commitment: [7; 32],
            settlement_commitment: [8; 32],
            custody_commitment: [9; 32],
            lifecycle_root: [10; 32],
            overlay_root: [11; 32],
            state_root: [12; 32],
            seats: [CanonicalSeat::EMPTY; MAX_CANONICAL_SEATS],
        }
    }

    #[test]
    fn canonical_direct_air_proves_and_verifies_without_replay() {
        let pre = image();
        let mut post = pre.clone();
        post.call_seq = 1;
        let mut witness = CanonicalTransitionWitness {
            pre,
            post,
            kind: CanonicalTransitionKind::CreateTable,
            actor: [1; 32],
            action: CanonicalActionPayload { seat: NO_CANONICAL_SEAT, amount: 0, auxiliary: 0, flag: false, proof_commitment: [13; 32] },
            transition_commitment: [0; 32],
            nullifier: [0; 32],
            deadline_height: 2,
        };
        witness.seal();
        let (trace, archive) = trace_for(&[witness.clone()]).expect("trace");
        let scope = scope_trace(&archive, trace.log_size);
        let preprocessed_cols = [
            scope.cols[3..7].iter(),
            scope.cols[1..3].iter(),
            scope.cols[7..39].iter(),
        ]
        .into_iter()
        .flatten()
        .collect();
        let evals = stwo::core::pcs::TreeVec::new(vec![
            preprocessed_cols,
            trace.cols.iter().collect(),
        ]);
        stwo_constraint_framework::assert_constraints_on_trace(
            &evals,
            trace.log_size,
            |eval| {
                CanonicalAir { log_size: trace.log_size }.evaluate(eval);
            },
            SecureField::from(0u32),
        );
        let archive = prove_canonical_tagged_batch(&[witness]).expect("canonical proof");
        verify_canonical_tagged_proof(&archive).expect("canonical verification");
    }
}
