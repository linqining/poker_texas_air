//! End-to-end proving benchmark for one complete Texas Hold'em hand.
//!
//! The hand is composed of the canonical transitions the tagged AIR currently
//! admits end-to-end: the table lifecycle (create, two joins, start) and one
//! complete betting hand (bet, raise, fold, zero-rake settlement).  The
//! shuffle/reveal crypto phase is still fail-closed pending the Ristretto
//! composition, so the hand is split at that boundary into two contiguous
//! tagged batches — exactly the seams a production coordinator would prove.
//!
//! Run with `cargo run --release -p poker-hand-bench`.

use std::time::Instant;

use poker_l1::vm::contracts::texas_poker::types::TableRules;
use poker_texas_air::canonical_rake_opening::CanonicalRakeOpening;
use poker_texas_air::texas_canonical::{
    CanonicalActionPayload, CanonicalPhase, CanonicalRoundAdvanceOpening, CanonicalSeat,
    CanonicalSeatStatus, CanonicalStateImage, CanonicalTransitionKind, CanonicalTransitionWitness,
    MAX_CANONICAL_SEATS, NO_CANONICAL_SEAT,
};
use poker_texas_air::texas_canonical_air::{
    prove_canonical_tagged_batch, verify_canonical_tagged_proof,
};

fn base_image() -> CanonicalStateImage {
    let mut image = CanonicalStateImage {
        abi_version: poker_texas_air::texas_canonical::CANONICAL_ABI_VERSION,
        table_id: 7,
        hand_id: 1,
        call_seq: 0,
        phase: CanonicalPhase::Waiting,
        phase_subtag: 0,
        street: 0,
        current_turn: NO_CANONICAL_SEAT,
        deadline_ms: 0,
        shuffle_timeout_ms: 10_000,
        reveal_timeout_ms: 10_000,
        betting_timeout_ms: 30_000,
        reconstruct_timeout_ms: 10_000,
        showdown_display_ms: 3_000,
        current_bet: 0,
        min_raise: 0,
        chip_pool: 0,
        pot: 0,
        button: 0,
        max_players: 9,
        acted_mask: 0,
        leave_after_hand_mask: 0,
        protocol_pending_mask: 0,
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
    };
    image
}

fn witness(
    pre: CanonicalStateImage,
    post: CanonicalStateImage,
    kind: CanonicalTransitionKind,
    actor: [u8; 32],
    seat: u8,
    amount: u64,
) -> CanonicalTransitionWitness {
    let mut value = CanonicalTransitionWitness {
        pre,
        post,
        kind,
        actor,
        action: CanonicalActionPayload {
            seat,
            amount,
            auxiliary: 0,
            flag: false,
            proof_commitment: [0; 32],
        },
        round_advance: CanonicalRoundAdvanceOpening::default(),
        protocol_completion: Default::default(),
        rake_opening: CanonicalRakeOpening::ZERO,
        transition_commitment: [0; 32],
        nullifier: [0; 32],
        deadline_height: 0,
    };
    value.seal();
    value
}

fn active_seat(stack: u64, acted: bool, index: usize) -> CanonicalSeat {
    CanonicalSeat {
        status: CanonicalSeatStatus::Active,
        acted,
        stack,
        bet: 0,
        total_bet: 0,
        pending_addon: 0,
        time_bank_ms: 30_000,
        identity_commitment: [31 + index as u8; 32],
        key_commitment: [41 + index as u8; 32],
        hole_cards_commitment: [51 + index as u8; 32],
    }
}

/// Standard nine-seat lifecycle: CreateTable -> JoinTable x9 -> StartHand.
/// Everything up to the shuffle boundary, where the fail-closed crypto phase
/// begins.
fn lifecycle_batch() -> Vec<CanonicalTransitionWitness> {
    const SEATS: usize = 9;
    let create_pre = base_image();
    let mut create_post = create_pre.clone();
    create_post.call_seq = 1;
    let create = witness(
        create_pre,
        create_post,
        CanonicalTransitionKind::CreateTable,
        [1; 32],
        NO_CANONICAL_SEAT,
        0,
    );

    let mut rows = vec![create];
    for seat in 0..SEATS {
        let pre = rows.last().expect("chain").post.clone();
        let mut post = pre.clone();
        post.call_seq = 2 + seat as u32;
        post.chip_pool = 1_000 * (seat as u64 + 1);
        post.seats[seat] = active_seat(1_000, false, seat);
        post.seats[seat].hole_cards_commitment = [0; 32];
        let join = witness(
            pre,
            post,
            CanonicalTransitionKind::JoinTable,
            [2 + seat as u8; 32],
            seat as u8,
            1_000,
        );
        rows.push(join);
    }

    let start_pre = rows.last().expect("chain").post.clone();
    let mut start_post = start_pre.clone();
    start_post.call_seq = 0;
    start_post.hand_id = 2;
    start_post.button = 1;
    start_post.phase = CanonicalPhase::Shuffling;
    start_post.phase_subtag = 1;
    start_post.deadline_ms = 100;
    start_post.protocol_pending_mask = 0x1ff;
    let start = witness(
        start_pre,
        start_post,
        CanonicalTransitionKind::StartHand,
        [2; 32],
        NO_CANONICAL_SEAT,
        0,
    );
    rows.push(start);
    rows
}

/// One complete nine-seat preflop hand after the shuffle boundary: seat 0
/// opens, seat 1 raises, seats 2..=8 and seat 0 fold, and the single
/// survivor takes the pot without a showdown.
fn hand_batch() -> Vec<CanonicalTransitionWitness> {
    const SEATS: usize = 9;
    const BUY_IN: u64 = 1_000;
    let mut pre = base_image();
    pre.hand_id = 2;
    pre.call_seq = 0;
    pre.phase = CanonicalPhase::Betting;
    pre.phase_subtag = 1;
    pre.street = 1;
    pre.current_turn = 0;
    pre.deadline_ms = 100;
    pre.chip_pool = 9_000;
    pre.max_players = 9;
    for seat in 0..SEATS {
        pre.seats[seat] = active_seat(BUY_IN, false, seat);
    }

    let mut rows: Vec<CanonicalTransitionWitness> = Vec::new();
    let mut seq = 0u32;
    let mut step = |kind: CanonicalTransitionKind,
                    actor: [u8; 32],
                    seat: u8,
                    amount: u64,
                    edit: &dyn Fn(&mut CanonicalStateImage)| {
        seq += 1;
        let mut post = pre.clone();
        post.call_seq = seq;
        edit(&mut post);
        let row = witness(pre.clone(), post, kind, actor, seat, amount);
        pre = row.post.clone();
        rows.push(row);
    };

    // Seat 0 opens for 50; the first actionable successor is seat 1.
    step(
        CanonicalTransitionKind::Bet,
        [31; 32],
        0,
        50,
        &|post: &mut CanonicalStateImage| {
            post.current_turn = 1;
            post.current_bet = 50;
            post.min_raise = 50;
            post.seats[0].acted = true;
            post.seats[0].stack = 950;
            post.seats[0].bet = 50;
            post.seats[0].total_bet = 50;
            post.acted_mask = 1;
        },
    );

    // Seat 1 raises to 150; every other seat's acted flag resets.
    step(
        CanonicalTransitionKind::Raise,
        [32; 32],
        1,
        150,
        &|post: &mut CanonicalStateImage| {
            post.current_turn = 2;
            post.current_bet = 150;
            post.min_raise = 100;
            post.seats[0].acted = false;
            post.seats[1].acted = true;
            post.seats[1].stack = 850;
            post.seats[1].bet = 150;
            post.seats[1].total_bet = 150;
            post.acted_mask = 0b10;
        },
    );

    // Seats 2..=8 fold in turn order; each successor is the next live seat.
    for seat in 2..SEATS {
        let successor = if seat + 1 == SEATS {
            0
        } else {
            (seat + 1) as u8
        };
        step(
            CanonicalTransitionKind::Fold,
            [31 + seat as u8; 32],
            seat as u8,
            0,
            &move |post: &mut CanonicalStateImage| {
                post.current_turn = successor;
                post.seats[seat].status = CanonicalSeatStatus::Folded;
                post.seats[seat].acted = true;
                post.acted_mask |= 1 << seat;
            },
        );
    }

    // Seat 0, facing the raise with its open bet live, folds; no actionable
    // seat remains.
    step(
        CanonicalTransitionKind::Fold,
        [31; 32],
        0,
        0,
        &|post: &mut CanonicalStateImage| {
            post.current_turn = NO_CANONICAL_SEAT;
            post.seats[0].status = CanonicalSeatStatus::Folded;
            post.seats[0].acted = true;
            post.acted_mask = 0x1ff;
        },
    );

    // Zero-rake settlement: the pot is the sum of both live bets (200).
    let amount = 50 + 150;
    step(
        CanonicalTransitionKind::EndWithoutShowdown,
        [0; 32],
        1,
        amount,
        &|post: &mut CanonicalStateImage| {
            post.phase = CanonicalPhase::Waiting;
            post.phase_subtag = 0;
            post.street = 0;
            post.deadline_ms = 0;
            post.current_bet = 0;
            post.min_raise = 0;
            post.acted_mask = 0;
            post.deck_commitment = [77; 32];
            post.board_cards_commitment = [0; 32];
            post.reveal_commitment = [0; 32];
            post.reconstruction_commitment = [0; 32];
            post.run_it_twice_commitment = [0; 32];
            for seat in 0..SEATS {
                post.seats[seat].status = CanonicalSeatStatus::Active;
                post.seats[seat].acted = false;
                post.seats[seat].bet = 0;
                post.seats[seat].total_bet = 0;
                post.seats[seat].hole_cards_commitment = [0; 32];
            }
            post.seats[1].stack += amount;
        },
    );
    let mut end = rows.pop().expect("terminal row");
    end.action.proof_commitment = [77; 32];
    end.seal();
    rows.push(end);
    rows
}

fn main() {
    if std::env::args().any(|arg| arg == "ristretto-timing") {
        ristretto_timing();
        return;
    }
    if std::env::args().any(|arg| arg == "slot-or-deep-batch") {
        slot_or_deep_batch();
        return;
    }
    println!("=== poker_texas_air complete-hand proving benchmark ===");
    println!("host: {} / {}", std::env::consts::ARCH, sysctl_model());
    let lifecycle = lifecycle_batch();
    let hand = hand_batch();

    let mut total_prove = std::time::Duration::ZERO;
    let mut total_verify = std::time::Duration::ZERO;
    let mut total_bytes = 0usize;

    // The two tagged batches are independent statements; a production
    // coordinator can pipeline them on the shared rayon pool instead of
    // paying their wall clocks serially.
    let pipelined_start = Instant::now();
    let (lifecycle_archive, hand_archive) = rayon::join(
        || prove_canonical_tagged_batch(&lifecycle),
        || prove_canonical_tagged_batch(&hand),
    );
    let lifecycle_archive = lifecycle_archive.expect("lifecycle proof");
    let hand_archive = hand_archive.expect("hand proof");
    let pipelined_prove = pipelined_start.elapsed();
    for (label, rows, archive) in [
        ("lifecycle", lifecycle.len(), &lifecycle_archive),
        ("hand", hand.len(), &hand_archive),
    ] {
        let start = Instant::now();
        verify_canonical_tagged_proof(archive).expect("canonical verify");
        let verify_elapsed = start.elapsed();
        let bytes = borsh_ser(archive).len();
        total_verify += verify_elapsed;
        total_bytes += bytes;
        println!("{label} batch ({rows} rows): verify {verify_elapsed:?}, proof {bytes} bytes");
    }
    println!("pipelined canonical batches (2x prove in parallel): {pipelined_prove:?}");
    total_prove += pipelined_prove;

    // Companion Blake2b openings a finalized hand needs.  The rules and both
    // endpoint state images share one lookup STARK: the fixed per-proof cost
    // (table commitment + FRI) dominates and is independent of block count.
    let pre_image = lifecycle[0].pre.clone();
    let post_image = hand.last().expect("hand").post.clone();
    let rules = TableRules {
        max_players: 9,
        small_blind: 25,
        big_blind: 50,
        timeout_config: Default::default(),
        ante_mode: 0,
        ante_amount: 0,
        rake_mode: 1,
        rake_bps: 500,
        rake_cap: 1_000,
        rit_mode: 0,
    };
    // Complete host-zero bundle: rules + both images + both L1 SMT openings
    // (synthetic 256-deep witnesses) in one provider-batched proof.
    let smt_pre = poker_texas_air::smt_statements::synthetic_smt_witness(
        0x5a,
        [0x11; 32],
        pre_image.commitment(),
    );
    let smt_post = poker_texas_air::smt_statements::synthetic_smt_witness(
        0x3c,
        [0x22; 32],
        post_image.commitment(),
    );
    let provider = poker_texas_air::hash_prover::default_hash_provider();
    let start = Instant::now();
    let bundle = poker_texas_air::canonical_rake_opening::prove_canonical_hand_bundle(
        &provider,
        &rules,
        &pre_image,
        &post_image,
        Some(&smt_pre),
        Some(&smt_post),
    )
    .expect("hand bundle");
    let openings_prove = start.elapsed();
    let start = Instant::now();
    let authenticated = poker_texas_air::canonical_rake_opening::verify_canonical_hand_bundle(
        &provider,
        &bundle,
        &rules,
        &pre_image,
        &post_image,
    )
    .expect("hand bundle verify");
    let openings_verify = start.elapsed();
    assert_eq!(
        authenticated.rake.rake_bps, 500,
        "authenticated opening must round-trip"
    );
    let openings_bytes = borsh_ser(&bundle).len();
    total_bytes += openings_bytes;
    println!(
        "complete hand bundle (rules + 2 images + 2 SMT paths, {} statements): prove {openings_prove:?}, verify {openings_verify:?}, proof {openings_bytes} bytes",
        3 + 2 * poker_texas_air::smt_statements::SMT_PATH_STATEMENTS,
    );
    total_prove += openings_prove;
    total_verify += openings_verify;

    for record in poker_texas_air::prove_timing::take_drain() {
        println!("component {}: {:?}", record.label, record.elapsed);
    }
    println!(
        "\nTOTAL: prove {total_prove:?}, verify {total_verify:?}, tagged proof bytes {total_bytes}"
    );
}

fn slot_or_deep_batch() {
    use poker_protocol::crypto::curve::{Curve, CurveScalar, RistrettoCurve};
    use poker_protocol::precompile_abi::{
        CurveId, EncodedCiphertext, ReconstructionProofSystem, ReconstructionV3VerifyRequest,
        TranscriptId,
    };
    use poker_texas_air::ristretto_reconstruction_proof_wire::{
        RistrettoBayerGrothShuffleProofWire, RistrettoCiphertextProofWire,
        RistrettoCrossKeyProofWire, RistrettoReconstructionProofEnvelope, RistrettoSlotOrProofWire,
        RISTRETTO_RECONSTRUCTION_READABLE_CARDS,
    };
    use poker_texas_air::ristretto_reconstruction_slot_or_air::{
        RistrettoSlotOrTranscriptChallenges, prove_ristretto_reconstruction_slot_or_batch,
        verify_ristretto_reconstruction_slot_or_batch,
    };

    const SLOT_COUNT: usize = 52;
    const LIMBS: usize = 32;
    let scalar = <RistrettoCurve as Curve>::Scalar::from_u64;
    let g = RistrettoCurve::base_g();
    let compressed = |point: <RistrettoCurve as Curve>::Point| *point.compress().as_bytes();
    let point_bytes =
        |point: <RistrettoCurve as Curve>::Point| point.compress().as_bytes().to_vec();
    let scalar_bytes = |value: <RistrettoCurve as Curve>::Scalar| {
        let mut out = [0u8; LIMBS];
        out.copy_from_slice(value.as_bytes());
        out
    };

    let aggregate_pk = g * scalar(11);
    let mut request = ReconstructionV3VerifyRequest {
        curve: CurveId::Ristretto255,
        proof_system: ReconstructionProofSystem::RistrettoAirV1,
        transcript: TranscriptId::Poseidon252,
        context: b"zk_reconstruct_proof_v3".to_vec(),
        call_context: vec![7; 32],
        statement_version: 3,
        context_digest: [1; 32],
        reconstruction_epoch: 9,
        prior_state_digest: [2; 32],
        aggregate_pk: point_bytes(aggregate_pk),
        owner_pk: vec![4; 32],
        cards: (0..SLOT_COUNT)
            .map(|index| point_bytes(g * scalar(100 + index as u64)))
            .collect(),
        user_readable_cards: vec![
            EncodedCiphertext { c1: vec![6; 32], c2: vec![7; 32] };
            RISTRETTO_RECONSTRUCTION_READABLE_CARDS
        ],
        contributions: (0..SLOT_COUNT)
            .map(|index| EncodedCiphertext {
                c1: point_bytes(g * scalar(200 + index as u64)),
                c2: point_bytes(g * scalar(300 + index as u64)),
            })
            .collect(),
        proof: vec![1],
    };
    let global_challenges: Vec<_> = (0..SLOT_COUNT)
        .map(|slot| scalar(37 + slot as u64))
        .collect();
    let slot_wires: Vec<RistrettoSlotOrProofWire> = global_challenges
        .iter()
        .enumerate()
        .map(|(slot, global)| {
            let share0 = scalar(5);
            let share1 = *global - share0;
            RistrettoSlotOrProofWire {
                commitment_g: [
                    compressed(g * scalar(400 + slot as u64)),
                    compressed(g * scalar(500 + slot as u64)),
                ],
                commitment_pk: [
                    compressed(aggregate_pk * scalar(600 + slot as u64)),
                    compressed(aggregate_pk * scalar(700 + slot as u64)),
                ],
                challenges: [scalar_bytes(share0), scalar_bytes(share1)],
                responses: [scalar_bytes(scalar(800 + slot as u64)); 2],
            }
        })
        .collect();
    let envelope = RistrettoReconstructionProofEnvelope::from_components(
        &request,
        [RistrettoCiphertextProofWire { c1: [0xA0; 32], c2: [0xA1; 32] };
            RISTRETTO_RECONSTRUCTION_READABLE_CARDS],
        RistrettoBayerGrothShuffleProofWire::default(),
        [RistrettoCrossKeyProofWire {
            commitment_owner_key: [0xB0; 32],
            commitment_contribution_c1: [0xB1; 32],
            commitment_joint_c2: [0xB2; 32],
            response_owner_sk: [0x0B; 32],
            response_contribution_randomness: [0x0C; 32],
        }; RISTRETTO_RECONSTRUCTION_READABLE_CARDS],
        slot_wires.try_into().unwrap(),
    )
    .unwrap();
    request.proof = envelope.encode_wire().unwrap();
    let challenges = RistrettoSlotOrTranscriptChallenges {
        statement_digest: envelope.statement_digest,
        global_challenges: global_challenges
            .into_iter()
            .map(scalar_bytes)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
    };

    let t = std::time::Instant::now();
    let archive = prove_ristretto_reconstruction_slot_or_batch(&request, &challenges)
        .expect("deep slot-OR batch prove");
    println!("deep slot-OR batch prove: {:.2}s", t.elapsed().as_secs_f64());
    let t = std::time::Instant::now();
    verify_ristretto_reconstruction_slot_or_batch(&request, &challenges, &archive)
        .expect("deep slot-OR batch verify");
    println!("deep slot-OR batch verify: {:.2}s", t.elapsed().as_secs_f64());
    println!(
        "proof bytes: {}",
        borsh::to_vec(&archive).map(|v| v.len()).unwrap_or(0)
    );

    let mut spliced = archive;
    spliced.additions.programs[3].values[2][0] ^= 1;
    assert!(verify_ristretto_reconstruction_slot_or_batch(&request, &challenges, &spliced).is_err());
    println!("tampered point-addition row rejected");
}

fn sysctl_model() -> String {
    std::process::Command::new("sysctl")
        .arg("-n")
        .arg("hw.model")
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".into())
}

fn borsh_ser<T: borsh::BorshSerialize>(value: &T) -> Vec<u8> {
    borsh::to_vec(value).expect("borsh serialize")
}

fn ristretto_timing() {
    use poker_texas_air::ristretto_reconstruction_accumulator_air::{
        prove_ristretto_reconstruction_deck_accumulator,
        verify_ristretto_reconstruction_deck_accumulator,
    };
    use poker_texas_air::canonical_reconstruction_binding::{
        CanonicalRistrettoCiphertext, CANONICAL_RECONSTRUCTION_CARDS,
    };
    let basepoint: [u8; 32] = [
        0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71, 0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00,
        0x51, 0x5f, 0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d, 0xb6, 0xa6, 0x59, 0x45,
        0xe0, 0x8d, 0x2d, 0x76,
    ];
    let prior = CanonicalRistrettoCiphertext { c1: [0; 32], c2: [0; 32] };
    let contribution = CanonicalRistrettoCiphertext { c1: basepoint, c2: basepoint };
    let contributions = [contribution; CANONICAL_RECONSTRUCTION_CARDS];
    let post = contributions;
    let t = std::time::Instant::now();
    let deck = prove_ristretto_reconstruction_deck_accumulator(
        [prior; CANONICAL_RECONSTRUCTION_CARDS],
        contributions,
        post,
    )
    .expect("deck accumulator");
    println!("104-row batch prove: {:.2}s", t.elapsed().as_secs_f64());
    let t = std::time::Instant::now();
    verify_ristretto_reconstruction_deck_accumulator(&deck).expect("verify");
    println!("104-row batch verify: {:.2}s", t.elapsed().as_secs_f64());
    println!(
        "proof bytes: {}",
        borsh::to_vec(&deck).map(|v| v.len()).unwrap_or(0)
    );
}
