//! Regression tests for verifier-trusted complete business-row binding.

use poker_l1::object_model::ObjectID;
use poker_l1::signature::TaggedPubkey;
use poker_l1::vm::contracts::dispatch::DispatchContext;
use poker_l1::vm::contracts::texas_poker::betting::BettingRound;
use poker_l1::vm::contracts::texas_poker::constants::ROUND_PREFLOP;
use poker_l1::vm::contracts::texas_poker::dispatch::{
    self as texas_dispatch, JoinTableArgs, LeaveTableArgs, SeatIndexArgs,
};
use poker_l1::vm::contracts::texas_poker::state_machine;
use poker_l1::vm::contracts::texas_poker::types::{EMPTY_PLAYER, SeatStatus, TexasPokerTable};
use poker_l1::vm::contracts::texas_poker::utils;
use poker_texas_air::airs::actions::call::{CallAir, CallInput, CallRow};
use poker_texas_air::airs::actions::end_betting_round::BettingOutcome;
use poker_texas_air::airs::actions::end_without_showdown::{EndWithoutShowdownInput, FoldOutcome};
use poker_texas_air::airs::actions::fold::{FoldAir, FoldInput, FoldRow};
use poker_texas_air::airs::actions::kick_player::{KickPlayerAir, KickPlayerInput, KickPlayerRow};
use poker_texas_air::airs::funds::addon::{AddonAir, AddonInput, AddonRow};
use poker_texas_air::airs::funds::rebuy::{RebuyAir, RebuyInput, RebuyRow};
use poker_texas_air::airs::lifecycle::create_table::CreateTableInput;
use poker_texas_air::airs::lifecycle::join_table::{JoinTableAir, JoinTableInput, JoinTableRow};
use poker_texas_air::airs::lifecycle::leave_table::{
    LeaveTableAir, LeaveTableInput, LeaveTableRow,
};
use poker_texas_air::airs::lifecycle::start_hand::{StartHandAir, StartHandInput, StartHandRow};
use poker_texas_air::airs::{AirStatement, TexasAir};
use poker_texas_air::authorization_binding::AdminAuthorizationAirBinding;
use poker_texas_air::method_kind::MethodKind;
use poker_texas_air::prover::{prove_create_table, prove_method};
use poker_texas_air::public_inputs::TexasPublicInputs;
use poker_texas_air::state_root::state_root_to_air_limbs;
use poker_texas_air::test_support as seat_fixture;
use poker_texas_air::trace_gen::create_table_trace::gen_create_table_trace;
use poker_texas_air::trace_gen::generic_trace::{gen_method_trace, gen_method_trace_with_log_size};
use poker_texas_air::verifier::{verify_create_table_against, verify_method_against};
use stwo::core::fields::m31::M31;
use stwo_constraint_framework::{EvalAtRow, FrameworkEval};

const FIXTURE_TIMESTAMP_MS: u64 = 1_000_000;
const FIXTURE_CREATOR: [u8; 20] = [0xA7; 20];

/// Minimal AIR with a deliberately unconstrained second business column.
/// `BoundAir` must still bind that column to the trusted row.
#[derive(Debug, Clone)]
struct PartiallyConstrainedAir {
    statement: AirStatement,
}

fn synthetic_admin_authorization() -> AdminAuthorizationAirBinding {
    AdminAuthorizationAirBinding::synthetic_unverified()
}

impl FrameworkEval for PartiallyConstrainedAir {
    fn log_size(&self) -> u32 {
        10
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        11
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let first = eval.next_trace_mask();
        let seven: E::F = M31::from(7u32).into();
        eval.add_constraint(first - seven);
        // Column 1 is intentionally unread/unconstrained by this inner AIR.
        eval
    }
}

impl TexasAir for PartiallyConstrainedAir {
    fn statement(&self) -> AirStatement {
        self.statement.clone()
    }

    fn trace_num_columns(&self) -> usize {
        2
    }
}

fn generic_fixture() -> (
    poker_texas_air::prover::MethodProof<PartiallyConstrainedAir>,
    PartiallyConstrainedAir,
    TexasPublicInputs,
) {
    let mut public_inputs = TexasPublicInputs::synthetic_for_test(MethodKind::Fold, 42, 3, 9);
    let row = [M31::from(7u32), M31::from(42u32)];
    public_inputs
        .bind_expected_trace_row(&row)
        .expect("trusted row should bind");
    let trace = gen_method_trace_with_log_size(10, 2, &row, &[M31::from(0u32); 2])
        .expect("trace should be generated");
    let air = PartiallyConstrainedAir {
        statement: AirStatement {
            kind: MethodKind::Fold,
            pre_state_root: state_root_to_air_limbs(public_inputs.pre_state_root),
            post_state_root: state_root_to_air_limbs(public_inputs.post_state_root),
            table_id: 42,
            hand_id: 3,
            call_seq: 9,
            pre_version: 0,
            post_version: 1,
            component: None,
        },
    };
    let proof = prove_method(&trace, air.clone(), 2, public_inputs.clone())
        .expect("bound generic proof should be generated");
    (proof, air, public_inputs)
}

#[test]
fn generic_verifier_accepts_the_independently_supplied_complete_row() {
    let (proof, air, public_inputs) = generic_fixture();
    verify_method_against(proof, air, &public_inputs)
        .expect("the independently reconstructed row should verify");
}

#[test]
fn generic_verifier_rejects_a_changed_unconstrained_business_column() {
    let (proof, air, mut public_inputs) = generic_fixture();
    public_inputs.expected_trace_row.as_mut().unwrap()[1] = 43;
    assert!(
        verify_method_against(proof, air, &public_inputs).is_err(),
        "an inner-AIR-unconstrained column must still be bound by BoundAir"
    );
}

#[test]
fn generic_verifier_does_not_fallback_to_the_proof_carried_row() {
    let (proof, air, mut public_inputs) = generic_fixture();
    assert!(proof.public_inputs.expected_trace_row.is_some());
    public_inputs.expected_trace_row = None;
    assert!(
        verify_method_against(proof, air, &public_inputs).is_err(),
        "production verification must fail closed when its trusted row is absent"
    );
}

fn make_create_tables() -> (TexasPokerTable, TexasPokerTable) {
    let id = ObjectID::new([0xAA; 20], 42);
    let pre = TexasPokerTable::new(id, String::new(), EMPTY_PLAYER, 2, 1, 1);
    let mut post = TexasPokerTable::new(id, "test_table".to_owned(), FIXTURE_CREATOR, 6, 10, 20);
    post.call_seq = pre.call_seq.checked_add(1).unwrap();
    post.call_seq = 1;
    (pre, post)
}

#[test]
fn create_table_verifier_requires_and_binds_the_complete_row() {
    let (pre, post) = make_create_tables();
    let trace = gen_create_table_trace(
        CreateTableInput {
            name: "test_table".to_owned(),
            max_players: 6,
            small_blind: 10,
            big_blind: 20,
        },
        &pre,
        &post,
        42,
        0,
        1,
    )
    .expect("create-table trace should be generated");
    let mut public_inputs =
        TexasPublicInputs::from_tables(&pre, &post, MethodKind::CreateTable, 42, 0, 1)
            .expect("public inputs should be generated");
    public_inputs
        .bind_expected_trace_row(&trace.trace.first_row().unwrap())
        .expect("trusted create-table row should bind");
    let proof = prove_create_table(&trace, public_inputs.clone())
        .expect("bound create-table proof should be generated");

    verify_create_table_against(proof.clone(), trace.air.clone(), &public_inputs)
        .expect("trusted create-table row should verify");

    let mut changed = public_inputs.clone();
    let last = changed
        .expected_trace_row
        .as_mut()
        .unwrap()
        .last_mut()
        .unwrap();
    *last = (*last + 1) % (stwo::core::fields::m31::P - 1);
    assert!(
        verify_create_table_against(proof.clone(), trace.air.clone(), &changed).is_err(),
        "changing any create-table business column must invalidate verification"
    );

    let mut missing = public_inputs;
    missing.expected_trace_row = None;
    assert!(
        verify_create_table_against(proof, trace.air, &missing).is_err(),
        "create-table verification must fail closed without a trusted row"
    );
}

fn make_canonical_call_tables() -> (TexasPokerTable, TexasPokerTable) {
    let mut pre = TexasPokerTable::new(
        ObjectID::new([0xCC; 20], 7),
        "canonical-call".to_owned(),
        FIXTURE_CREATOR,
        6,
        50,
        100,
    );
    pre.enter_betting(
        ROUND_PREFLOP,
        BettingRound::new(100, 100),
        0,
        FIXTURE_TIMESTAMP_MS,
    )
    .unwrap();
    pre.pot = 25;
    pre.hand_id = 5;
    pre.call_seq = 8;
    for i in 0..3 {
        seat_fixture::set_player(&mut pre.seats[i], [u8::try_from(i + 1).unwrap(); 20]);
        pre.seats[i].set_status(SeatStatus::Active);
        seat_fixture::set_stack(&mut pre.seats[i], 1_000);
    }
    seat_fixture::set_bet(&mut pre.seats[0], 50);
    seat_fixture::set_total_bet(&mut pre.seats[0], 50);
    seat_fixture::set_bet(&mut pre.seats[1], 100);
    seat_fixture::set_total_bet(&mut pre.seats[1], 100);
    seat_fixture::set_bet(&mut pre.seats[2], 100);
    seat_fixture::set_total_bet(&mut pre.seats[2], 100);

    let mut post = pre.clone();
    state_machine::apply_call(&mut post, 0, &mut vec![]).unwrap();
    state_machine::normalize_until_blocked(&mut post, FIXTURE_TIMESTAMP_MS, &mut vec![]).unwrap();
    post.call_seq = pre.call_seq + 1;
    assert_eq!(post.seats[0].bet(), 100);
    assert_eq!(post.current_turn(), 1);
    (pre, post)
}

#[test]
fn production_verifier_rejects_action_row_not_reconstructed_from_canonical_tables() {
    let (pre, post) = make_canonical_call_tables();

    // This row is internally valid for a fictitious current_bet=70/call=20,
    // but the canonical pre/post tables commit to current_bet=100/call=50.
    // Before verifier-side table decoding, such a proof could verify because
    // roots and business row were transcript-bound but unrelated.
    let fake_input = CallInput {
        seat_index: 0,
        call_amount: 20,
        pre_current_bet: 70,
        pre_seat_bet: 50,
        pre_seat_stack: 1_000,
        pre_seat_total_bet: 50,
        outcome: BettingOutcome::MidRound {
            post_current_turn: 1,
        },
    };
    let mut public_inputs = TexasPublicInputs::from_tables(
        &pre,
        &post,
        MethodKind::Call,
        pre.id.creation_nonce,
        post.hand_id,
        post.call_seq,
    )
    .expect("canonical public inputs should be generated");
    let fake_row = CallRow::active(
        &fake_input,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        u64::from(pre.call_seq),
        u64::from(post.call_seq),
        pre.round_state(),
        post.round_state(),
        pre.pot,
        post.pot,
        980,
        70,
        false,
        50,
        1_000,
        70,
        50,
    );
    public_inputs
        .bind_expected_trace_row(&fake_row.to_vec())
        .expect("fictitious row should bind at construction time");
    let trace = gen_method_trace(
        CallAir::num_columns(),
        &fake_row.to_vec(),
        &CallRow::padding().to_vec(),
    )
    .expect("fictitious but AIR-consistent trace should be generated");
    let air = CallAir {
        log_size: trace.log_size,
        input: fake_input,
        pre_state_root: state_root_to_air_limbs(public_inputs.pre_state_root),
        post_state_root: state_root_to_air_limbs(public_inputs.post_state_root),
        table_id: public_inputs.table_id,
        hand_id: public_inputs.hand_id,
        call_seq: public_inputs.call_seq,
        pre_version: public_inputs.pre_version,
        post_version: public_inputs.post_version,
    };
    let proof = prove_method(
        &trace,
        air.clone(),
        CallAir::num_columns(),
        public_inputs.clone(),
    )
    .expect("the fictitious row is intentionally AIR-consistent");

    assert!(
        verify_method_against(proof, air, &public_inputs).is_err(),
        "production verifier must derive action semantics from canonical table images"
    );
}

#[test]
fn production_verifier_derives_terminal_fold_winner_from_canonical_tables() {
    let mut pre = TexasPokerTable::new(
        ObjectID::new([0xCF; 20], 17),
        "canonical-terminal-fold".to_owned(),
        FIXTURE_CREATOR,
        6,
        50,
        100,
    );
    pre.enter_betting(
        ROUND_PREFLOP,
        BettingRound::new(100, 100),
        0,
        FIXTURE_TIMESTAMP_MS,
    )
    .unwrap();
    pre.pot = 200;
    pre.hand_id = 6;
    pre.call_seq = 9;
    for i in 0..2 {
        seat_fixture::set_player(&mut pre.seats[i], [u8::try_from(i + 1).unwrap(); 20]);
        pre.seats[i].set_status(SeatStatus::Active);
        seat_fixture::set_stack(&mut pre.seats[i], 1_000);
    }
    seat_fixture::set_bet(&mut pre.seats[0], 25);
    seat_fixture::set_total_bet(&mut pre.seats[0], 25);
    seat_fixture::set_bet(&mut pre.seats[1], 75);
    seat_fixture::set_total_bet(&mut pre.seats[1], 75);

    let mut post = pre.clone();
    state_machine::apply_fold(&mut post, 0, &mut vec![]).unwrap();
    post.call_seq = pre.call_seq + 1;
    assert_eq!(post.seats[1].stack(), 1_300);

    // The arithmetic is self-consistent, but seat 2 is not the canonical
    // last player standing. The low-level AIR intentionally cannot discover
    // that from a complete table it does not carry.
    let fake_input = FoldInput {
        seat_index: 0,
        outcome: FoldOutcome::EndWithoutShowdown(EndWithoutShowdownInput {
            winner_seat: 2,
            collected_bets: 100,
            gross_pot: 300,
            rake: 0,
            award: 300,
            pre_winner_stack: 1_000,
            post_winner_stack: 1_300,
        }),
    };
    let mut public_inputs = TexasPublicInputs::from_tables(
        &pre,
        &post,
        MethodKind::Fold,
        pre.id.creation_nonce,
        post.hand_id,
        post.call_seq,
    )
    .expect("canonical public inputs should be generated");
    let fake_row = FoldRow::active(
        &fake_input,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        u64::from(pre.call_seq),
        u64::from(post.call_seq),
        pre.round_state(),
        post.round_state(),
        pre.pot,
        post.pot,
    );
    public_inputs
        .bind_expected_trace_row(&fake_row.to_vec())
        .expect("fake terminal row should bind for the low-level proof");
    let trace = gen_method_trace(
        FoldAir::num_columns(),
        &fake_row.to_vec(),
        &FoldRow::padding().to_vec(),
    )
    .expect("fake terminal trace should generate");
    let air = FoldAir {
        log_size: trace.log_size,
        input: fake_input,
        pre_state_root: state_root_to_air_limbs(public_inputs.pre_state_root),
        post_state_root: state_root_to_air_limbs(public_inputs.post_state_root),
        table_id: public_inputs.table_id,
        hand_id: public_inputs.hand_id,
        call_seq: public_inputs.call_seq,
        pre_version: public_inputs.pre_version,
        post_version: public_inputs.post_version,
    };
    let proof = prove_method(
        &trace,
        air.clone(),
        FoldAir::num_columns(),
        public_inputs.clone(),
    )
    .expect("the fake winner row is intentionally AIR-consistent");

    assert!(
        verify_method_against(proof, air, &public_inputs).is_err(),
        "production verification must derive the winner seat from canonical VM replay"
    );
}

#[test]
fn production_verifier_rejects_action_table_id_not_bound_to_canonical_table() {
    let (pre, post) = make_canonical_call_tables();
    let input = CallInput {
        seat_index: 0,
        call_amount: 50,
        pre_current_bet: 100,
        pre_seat_bet: 50,
        pre_seat_stack: 1_000,
        pre_seat_total_bet: 50,
        outcome: BettingOutcome::MidRound {
            post_current_turn: 1,
        },
    };

    // The canonical table id nonce is 7. Build a self-consistent proof statement
    // labelled as table 42; transcript binding alone cannot relate that label to
    // the canonical table image, so the action validation hook must reject it.
    let mut public_inputs = TexasPublicInputs::from_tables(
        &pre,
        &post,
        MethodKind::Call,
        42,
        post.hand_id,
        post.call_seq,
    )
    .expect("canonical public inputs should be generated");
    let row = CallRow::active(
        &input,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        u64::from(pre.call_seq),
        u64::from(post.call_seq),
        pre.round_state(),
        post.round_state(),
        pre.pot,
        post.pot,
        post.seats[0].stack(),
        post.seats[0].bet(),
        post.seats[0].is_all_in(),
        pre.seats[0].bet(),
        pre.seats[0].stack(),
        post.seats[0].total_bet(),
        pre.seats[0].total_bet(),
    );
    public_inputs
        .bind_expected_trace_row(&row.to_vec())
        .expect("trusted row should bind");
    let trace = gen_method_trace(
        CallAir::num_columns(),
        &row.to_vec(),
        &CallRow::padding().to_vec(),
    )
    .expect("valid call trace should be generated");
    let air = CallAir {
        log_size: trace.log_size,
        input,
        pre_state_root: state_root_to_air_limbs(public_inputs.pre_state_root),
        post_state_root: state_root_to_air_limbs(public_inputs.post_state_root),
        table_id: public_inputs.table_id,
        hand_id: public_inputs.hand_id,
        call_seq: public_inputs.call_seq,
        pre_version: public_inputs.pre_version,
        post_version: public_inputs.post_version,
    };
    let proof = prove_method(
        &trace,
        air.clone(),
        CallAir::num_columns(),
        public_inputs.clone(),
    )
    .expect("AIR-consistent proof should be generated before canonical id validation");

    assert!(
        verify_method_against(proof, air, &public_inputs).is_err(),
        "production verifier must bind table_id to the canonical table image"
    );
}

fn make_funds_pre_table() -> TexasPokerTable {
    let mut table = TexasPokerTable::new(
        ObjectID::new([0xDD; 20], 19),
        "canonical-funds".to_owned(),
        FIXTURE_CREATOR,
        6,
        50,
        100,
    );
    table.hand_id = 3;
    table.call_seq = 11;
    seat_fixture::set_player(&mut table.seats[0], [0x31; 20]);
    table.seats[0].set_status(SeatStatus::Active);
    seat_fixture::set_stack(&mut table.seats[0], 1_000);
    table.chip_pool = 1_000;
    table
}

fn dispatch_context(caller: [u8; 20]) -> DispatchContext {
    DispatchContext {
        caller,
        caller_pubkey: TaggedPubkey {
            tag: 0,
            raw: vec![0xA5; 32],
        },
        chain_id: poker_l1::DEFAULT_CHAIN_ID,
        block_height: 100,
        block_timestamp: FIXTURE_TIMESTAMP_MS,
    }
}

fn make_kick_player_transition() -> (DispatchContext, TexasPokerTable, TexasPokerTable, Vec<u8>) {
    let creator = [0x61; 20];
    let context = dispatch_context(creator);
    let mut pre = TexasPokerTable::new(
        ObjectID::new([0xE2; 20], 24),
        "canonical-kick".to_owned(),
        creator,
        6,
        50,
        100,
    );
    pre.hand_id = 5;
    pre.call_seq = 19;
    pre.enter_betting(
        ROUND_PREFLOP,
        BettingRound::new(100, 100),
        0,
        FIXTURE_TIMESTAMP_MS,
    )
    .unwrap();
    pre.pot = 75;
    for seat_index in 0..3 {
        seat_fixture::set_player(
            &mut pre.seats[seat_index],
            [u8::try_from(seat_index + 1).unwrap(); 20],
        );
        pre.seats[seat_index].set_status(SeatStatus::Active);
        seat_fixture::set_stack(&mut pre.seats[seat_index], 1_000);
    }
    seat_fixture::set_bet(&mut pre.seats[2], 25);
    seat_fixture::set_total_bet(&mut pre.seats[2], 25);
    pre.chip_pool = 3_000;

    let raw_args = borsh::to_vec(&SeatIndexArgs { seat_index: 2 }).unwrap();
    let mut post = pre.clone();
    texas_dispatch::dispatch(
        &context,
        &mut post,
        &texas_dispatch::selectors::kick_player_v2(),
        &raw_args,
    )
    .unwrap();
    (context, pre, post, raw_args)
}

#[test]
fn production_verifier_rejects_kick_row_attached_to_unrelated_post_table() {
    let (context, pre, canonical_post, raw_args) = make_kick_player_transition();
    let input = KickPlayerInput {
        seat_index: 2,
        refund: pre.seats[2].stack(),
        pre_stack: pre.seats[2].stack(),
        pre_pending_addon: pre.seats[2].pending_addon(),
        kicked_bet: pre.seats[2].bet(),
        version_increment: 1,
        reset_cascade: false,
        authorization: poker_texas_air::authorization_binding::AdminAuthorizationAirBinding::synthetic_unverified(),
    };

    let mut unrelated_post = canonical_post.clone();
    unrelated_post.name = "unrelated-kick-post".to_owned();
    let mut public_inputs = TexasPublicInputs::from_tables(
        &pre,
        &unrelated_post,
        MethodKind::KickPlayer,
        pre.id.creation_nonce,
        unrelated_post.hand_id,
        unrelated_post.call_seq,
    )
    .unwrap();
    public_inputs
        .bind_dispatch_call(
            context,
            texas_dispatch::selectors::kick_player_v2(),
            raw_args,
        )
        .unwrap();
    let row = KickPlayerRow::active(
        &input,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        u64::from(pre.call_seq),
        u64::from(canonical_post.call_seq),
        pre.round_state(),
        canonical_post.round_state(),
        pre.pot,
        canonical_post.pot,
    );
    public_inputs
        .bind_expected_trace_row(&row.to_vec())
        .unwrap();
    let trace = gen_method_trace(
        KickPlayerAir::num_columns(),
        &row.to_vec(),
        &KickPlayerRow::padding().to_vec(),
    )
    .unwrap();
    let air = KickPlayerAir {
        log_size: trace.log_size,
        input,
        pre_state_root: state_root_to_air_limbs(public_inputs.pre_state_root),
        post_state_root: state_root_to_air_limbs(public_inputs.post_state_root),
        table_id: public_inputs.table_id,
        hand_id: public_inputs.hand_id,
        call_seq: public_inputs.call_seq,
        pre_version: public_inputs.pre_version,
        post_version: public_inputs.post_version,
    };
    let proof = prove_method(
        &trace,
        air.clone(),
        KickPlayerAir::num_columns(),
        public_inputs.clone(),
    )
    .expect("unrelated kick roots and row are intentionally AIR-consistent");

    let error = verify_method_against(proof, air, &public_inputs)
        .expect_err("production kick verification must replay the exact dispatch");
    assert!(error.to_string().contains("native VM dispatch replay"));
}

fn make_start_hand_transition() -> (DispatchContext, TexasPokerTable, TexasPokerTable, Vec<u8>) {
    let creator = [0x71; 20];
    let context = dispatch_context(creator);
    let mut pre = TexasPokerTable::new(
        ObjectID::new([0xE3; 20], 25),
        "canonical-start".to_owned(),
        creator,
        6,
        50,
        100,
    );
    pre.hand_id = 6;
    pre.call_seq = 20;
    pre.button = 0;
    seat_fixture::set_player(&mut pre.seats[0], [0x72; 20]);
    pre.seats[0].set_status(SeatStatus::Active);
    seat_fixture::set_stack(&mut pre.seats[0], 1_000);
    seat_fixture::set_player(&mut pre.seats[2], [0x73; 20]);
    pre.seats[2].set_status(SeatStatus::Active);
    seat_fixture::set_stack(&mut pre.seats[2], 1_000);
    pre.chip_pool = 2_000;

    let raw_args = vec![];
    let mut post = pre.clone();
    texas_dispatch::dispatch(
        &context,
        &mut post,
        &texas_dispatch::selectors::start_hand(),
        &raw_args,
    )
    .unwrap();
    (context, pre, post, raw_args)
}

fn start_hand_input(pre: &TexasPokerTable, post: &TexasPokerTable) -> StartHandInput {
    StartHandInput {
        active_count: u8::try_from(pre.seats.iter().filter(|seat| seat.is_occupied()).count())
            .unwrap(),
        new_button: post.button,
        ante_mode: post.ante_mode,
        ante_amount: post.ante_amount,
        ante_collected: post.pot.checked_sub(pre.pot).unwrap(),
        pre_pot: pre.pot,
        post_pot: post.pot,
        authorization: synthetic_admin_authorization(),
    }
}

#[test]
fn production_verifier_rejects_start_hand_row_attached_to_unrelated_post_table() {
    let (context, pre, canonical_post, raw_args) = make_start_hand_transition();
    let input = start_hand_input(&pre, &canonical_post);
    let count = M31::from(u32::from(input.active_count));
    let count_product = count * (count - M31::from(1u32));

    let mut unrelated_post = canonical_post.clone();
    unrelated_post.name = "unrelated-start-post".to_owned();
    let mut public_inputs = TexasPublicInputs::from_tables(
        &pre,
        &unrelated_post,
        MethodKind::StartHand,
        pre.id.creation_nonce,
        unrelated_post.hand_id,
        unrelated_post.call_seq,
    )
    .unwrap();
    public_inputs
        .bind_dispatch_call(context, texas_dispatch::selectors::start_hand(), raw_args)
        .unwrap();
    let row = StartHandRow::active(
        &input,
        count_product.inverse(),
        count_product,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        u64::from(pre.call_seq),
        u64::from(canonical_post.call_seq),
    );
    public_inputs
        .bind_expected_trace_row(&row.to_vec())
        .unwrap();
    let trace = gen_method_trace(
        StartHandAir::num_columns(),
        &row.to_vec(),
        &StartHandRow::padding().to_vec(),
    )
    .unwrap();
    let air = StartHandAir {
        log_size: trace.log_size,
        input,
        pre_state_root: state_root_to_air_limbs(public_inputs.pre_state_root),
        post_state_root: state_root_to_air_limbs(public_inputs.post_state_root),
        table_id: public_inputs.table_id,
        hand_id: public_inputs.hand_id,
        call_seq: public_inputs.call_seq,
        pre_version: public_inputs.pre_version,
        post_version: public_inputs.post_version,
    };
    let proof = prove_method(
        &trace,
        air.clone(),
        StartHandAir::num_columns(),
        public_inputs.clone(),
    )
    .expect("unrelated start roots and row are intentionally AIR-consistent");

    let error = verify_method_against(proof, air, &public_inputs)
        .expect_err("production start-hand verification must replay the exact dispatch");
    assert!(error.to_string().contains("native VM dispatch replay"));
}

#[test]
fn production_verifier_rejects_retired_reset_selector_before_proving() {
    let selector = texas_dispatch::compute_method_selector("reset_for_next_hand");
    assert!(texas_dispatch::CanonicalCommand::from_u8(5).is_none());
    assert!(texas_dispatch::CanonicalCommand::from_selector(&selector).is_none());
    assert!(MethodKind::from_u8(5).is_none());
}

#[test]
fn production_verifier_rejects_join_row_attached_to_unrelated_post_table() {
    let player = [0x51; 20];
    let context = dispatch_context(player);
    let args = JoinTableArgs::with_key(
        player,
        500,
        utils::scalar_from_u64(1),
        utils::scalar_from_u64(801),
    )
    .unwrap();
    let raw_args = borsh::to_vec(&args).unwrap();
    let mut pre = TexasPokerTable::new(
        ObjectID::new([0xE1; 20], 23),
        "canonical-join".to_owned(),
        FIXTURE_CREATOR,
        6,
        50,
        100,
    );
    pre.hand_id = 4;
    pre.call_seq = 9;
    let mut canonical_post = pre.clone();
    texas_dispatch::dispatch(
        &context,
        &mut canonical_post,
        &texas_dispatch::selectors::join_table(),
        &raw_args,
    )
    .unwrap();
    let seat_index = pre.find_empty_seat().unwrap();
    let input = JoinTableInput {
        seat_index,
        buy_in: args.buy_in,
        player_addr: player,
    };

    // The row remains internally valid, while the committed post table changes
    // an unrelated field. Transcript binding alone cannot prove that the roots
    // came from this dispatch; verifier-side replay must reject it.
    let mut unrelated_post = canonical_post.clone();
    unrelated_post.name = "unrelated-join-post".to_owned();
    let mut public_inputs = TexasPublicInputs::from_tables(
        &pre,
        &unrelated_post,
        MethodKind::JoinTable,
        pre.id.creation_nonce,
        unrelated_post.hand_id,
        unrelated_post.call_seq,
    )
    .unwrap();
    public_inputs
        .bind_dispatch_call(context, texas_dispatch::selectors::join_table(), raw_args)
        .unwrap();
    let row = JoinTableRow::active(
        &input,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        u64::from(pre.call_seq),
        u64::from(canonical_post.call_seq),
        pre.big_blind,
        pre.chip_pool,
    );
    public_inputs
        .bind_expected_trace_row(&row.to_vec())
        .unwrap();
    let trace = gen_method_trace(
        JoinTableAir::num_columns(),
        &row.to_vec(),
        &JoinTableRow::padding().to_vec(),
    )
    .unwrap();
    let air = JoinTableAir {
        log_size: trace.log_size,
        input,
        pre_state_root: state_root_to_air_limbs(public_inputs.pre_state_root),
        post_state_root: state_root_to_air_limbs(public_inputs.post_state_root),
        table_id: public_inputs.table_id,
        hand_id: public_inputs.hand_id,
        call_seq: public_inputs.call_seq,
        pre_version: public_inputs.pre_version,
        post_version: public_inputs.post_version,
    };
    let proof = prove_method(
        &trace,
        air.clone(),
        JoinTableAir::num_columns(),
        public_inputs.clone(),
    )
    .expect("unrelated join roots and row are intentionally AIR-consistent");

    let error = verify_method_against(proof, air, &public_inputs)
        .expect_err("production join verification must replay the exact dispatch");
    assert!(!error.to_string().is_empty());
}

#[test]
fn production_verifier_rejects_leave_row_attached_to_unrelated_post_table() {
    let player = [0x61; 20];
    let context = dispatch_context(player);
    let join_args = JoinTableArgs::with_key(
        player,
        700,
        utils::scalar_from_u64(1),
        utils::scalar_from_u64(802),
    )
    .unwrap();
    let mut pre = TexasPokerTable::new(
        ObjectID::new([0xE2; 20], 24),
        "canonical-leave".to_owned(),
        FIXTURE_CREATOR,
        6,
        50,
        100,
    );
    pre.hand_id = 5;
    pre.call_seq = 12;
    texas_dispatch::dispatch(
        &context,
        &mut pre,
        &texas_dispatch::selectors::join_table(),
        &borsh::to_vec(&join_args).unwrap(),
    )
    .unwrap();

    let seat_index = 0;
    let leave_args = LeaveTableArgs { seat_index };
    let raw_args = borsh::to_vec(&leave_args).unwrap();
    let mut canonical_post = pre.clone();
    texas_dispatch::dispatch(
        &context,
        &mut canonical_post,
        &texas_dispatch::selectors::leave_table(),
        &raw_args,
    )
    .unwrap();
    let pre_seat = pre.seats[usize::from(seat_index)].clone();
    let input = LeaveTableInput { seat_index };

    let mut unrelated_post = canonical_post.clone();
    unrelated_post.name = "unrelated-leave-post".to_owned();
    let mut public_inputs = TexasPublicInputs::from_tables(
        &pre,
        &unrelated_post,
        MethodKind::LeaveTable,
        pre.id.creation_nonce,
        unrelated_post.hand_id,
        unrelated_post.call_seq,
    )
    .unwrap();
    public_inputs
        .bind_dispatch_call(context, texas_dispatch::selectors::leave_table(), raw_args)
        .unwrap();
    let row = LeaveTableRow::active(
        &input,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        u64::from(pre.call_seq),
        u64::from(canonical_post.call_seq),
        pre_seat.stack(),
        pre_seat.pending_addon(),
        pre.chip_pool,
        canonical_post.chip_pool,
    );
    public_inputs
        .bind_expected_trace_row(&row.to_vec())
        .unwrap();
    let trace = gen_method_trace(
        LeaveTableAir::num_columns(),
        &row.to_vec(),
        &LeaveTableRow::padding().to_vec(),
    )
    .unwrap();
    let air = LeaveTableAir {
        log_size: trace.log_size,
        input,
        pre_state_root: state_root_to_air_limbs(public_inputs.pre_state_root),
        post_state_root: state_root_to_air_limbs(public_inputs.post_state_root),
        table_id: public_inputs.table_id,
        hand_id: public_inputs.hand_id,
        call_seq: public_inputs.call_seq,
        pre_version: public_inputs.pre_version,
        post_version: public_inputs.post_version,
    };
    let proof = prove_method(
        &trace,
        air.clone(),
        LeaveTableAir::num_columns(),
        public_inputs.clone(),
    )
    .expect("unrelated leave roots and row are intentionally AIR-consistent");

    let error = verify_method_against(proof, air, &public_inputs)
        .expect_err("production leave verification must replay the exact dispatch");
    assert!(!error.to_string().is_empty());
}

#[test]
fn production_verifier_rejects_addon_row_attached_to_unrelated_post_table() {
    let pre = make_funds_pre_table();
    let input = AddonInput {
        seat_index: 0,
        amount: 200,
    };
    let mut canonical_post = pre.clone();
    state_machine::apply_addon(
        &mut canonical_post,
        input.seat_index,
        input.amount,
        &mut vec![],
    )
    .unwrap();
    canonical_post.call_seq = pre.call_seq + 1;

    // Keep every row-visible funds value valid, but commit to a different table name.
    // Before canonical replay, roots and this self-consistent row were unrelated inputs.
    let mut unrelated_post = canonical_post.clone();
    unrelated_post.name = "unrelated-post".to_owned();
    let mut public_inputs = TexasPublicInputs::from_tables(
        &pre,
        &unrelated_post,
        MethodKind::Addon,
        pre.id.creation_nonce,
        unrelated_post.hand_id,
        unrelated_post.call_seq,
    )
    .unwrap();
    let row = AddonRow::active(
        &input,
        pre.seats[0].pending_addon(),
        pre.chip_pool,
        canonical_post.chip_pool,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        u64::from(pre.call_seq),
        u64::from(canonical_post.call_seq),
        pre.round_state(),
        canonical_post.round_state(),
    );
    public_inputs
        .bind_expected_trace_row(&row.to_vec())
        .unwrap();
    let trace = gen_method_trace(
        AddonAir::num_columns(),
        &row.to_vec(),
        &AddonRow::padding().to_vec(),
    )
    .unwrap();
    let air = AddonAir {
        log_size: trace.log_size,
        input,
        pre_state_root: state_root_to_air_limbs(public_inputs.pre_state_root),
        post_state_root: state_root_to_air_limbs(public_inputs.post_state_root),
        table_id: public_inputs.table_id,
        hand_id: public_inputs.hand_id,
        call_seq: public_inputs.call_seq,
        pre_version: public_inputs.pre_version,
        post_version: public_inputs.post_version,
    };
    let proof = prove_method(
        &trace,
        air.clone(),
        AddonAir::num_columns(),
        public_inputs.clone(),
    )
    .expect("unrelated roots and row are intentionally AIR-consistent");

    let error = verify_method_against(proof, air, &public_inputs)
        .expect_err("production addon verification must replay the canonical table transition");
    assert!(error.to_string().contains("native VM replay"));
}

#[test]
fn production_verifier_rejects_rebuy_row_attached_to_unrelated_post_table() {
    let pre = make_funds_pre_table();
    let input = RebuyInput {
        seat_index: 0,
        amount: 300,
    };
    let mut canonical_post = pre.clone();
    state_machine::apply_rebuy(
        &mut canonical_post,
        input.seat_index,
        input.amount,
        &mut vec![],
    )
    .unwrap();
    canonical_post.call_seq = pre.call_seq + 1;

    let mut unrelated_post = canonical_post.clone();
    unrelated_post.name = "unrelated-post".to_owned();
    let mut public_inputs = TexasPublicInputs::from_tables(
        &pre,
        &unrelated_post,
        MethodKind::Rebuy,
        pre.id.creation_nonce,
        unrelated_post.hand_id,
        unrelated_post.call_seq,
    )
    .unwrap();
    let row = RebuyRow::active(
        &input,
        pre.seats[0].stack(),
        pre.chip_pool,
        canonical_post.chip_pool,
        state_root_to_air_limbs(public_inputs.pre_state_root),
        state_root_to_air_limbs(public_inputs.post_state_root),
        public_inputs.table_id,
        public_inputs.hand_id,
        public_inputs.call_seq,
        u64::from(pre.call_seq),
        u64::from(canonical_post.call_seq),
        pre.round_state(),
        canonical_post.round_state(),
    );
    public_inputs
        .bind_expected_trace_row(&row.to_vec())
        .unwrap();
    let trace = gen_method_trace(
        RebuyAir::num_columns(),
        &row.to_vec(),
        &RebuyRow::padding().to_vec(),
    )
    .unwrap();
    let air = RebuyAir {
        log_size: trace.log_size,
        input,
        pre_state_root: state_root_to_air_limbs(public_inputs.pre_state_root),
        post_state_root: state_root_to_air_limbs(public_inputs.post_state_root),
        table_id: public_inputs.table_id,
        hand_id: public_inputs.hand_id,
        call_seq: public_inputs.call_seq,
        pre_version: public_inputs.pre_version,
        post_version: public_inputs.post_version,
    };
    let proof = prove_method(
        &trace,
        air.clone(),
        RebuyAir::num_columns(),
        public_inputs.clone(),
    )
    .expect("unrelated roots and row are intentionally AIR-consistent");

    let error = verify_method_against(proof, air, &public_inputs)
        .expect_err("production rebuy verification must replay the canonical table transition");
    assert!(error.to_string().contains("native VM replay"));
}
