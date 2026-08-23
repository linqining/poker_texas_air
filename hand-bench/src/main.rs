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
