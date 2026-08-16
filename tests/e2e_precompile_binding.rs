//! Production-path tests for shuffle precompile request/receipt binding.

use poker_l1::object_model::ObjectID;
use poker_l1::signature::TaggedPubkey;
use poker_l1::vm::contracts::dispatch::DispatchContext;
use poker_l1::vm::contracts::texas_poker::card::{BoardCards, Card};
use poker_l1::vm::contracts::texas_poker::constants::{
    RIT_MODE_TWICE, ROUND_PREFLOP, ROUND_SHOWDOWN, ROUND_TURN,
};
use poker_l1::vm::contracts::texas_poker::dispatch::{
    self as texas_dispatch, SubmitReconstructDeckArgs, SubmitRevealTokensArgs, SubmitShuffleV2Args,
};
use poker_l1::vm::contracts::texas_poker::types::{
    PartialHoleCard, ReconstructState, RevealAssignment, RevealPurpose, RevealTarget,
    RevealTokenState, RitStartStreet, RunItTwiceState, SeatStatus, ShuffleState, TexasPokerTable,
};
use poker_l1::vm::contracts::texas_poker::utils;
use poker_protocol::crypto::curve::{Bls12381Curve, Curve, CurveScalar, ElGamalCiphertextGeneric};
use poker_protocol::crypto::types::ECPoint;
use poker_protocol::precompile::{
    build_bls12381_reconstruction_v3_request, build_bls12381_shuffle_request,
};
use poker_protocol::precompile_abi::TranscriptId;
use poker_protocol::zk_shuffle::ShuffleProof;
use poker_protocol::zk_shuffle::reconstruction::{
    RECONSTRUCTION_V3_PROOF_LABEL, ReconstructProofV3,
};
use poker_protocol::zk_shuffle::reveal_token_proof::{REVEAL_TOKEN_PROOF_LABEL, RevealTokenProof};
use poker_protocol::zk_shuffle::transcript_ext::{
    CryptoTranscript, FiatShamirTranscript, MerlinTranscript,
};
use poker_texas_air::airs::crypto::submit_player_reveal_tokens::{
    SubmitPlayerRevealTokensAir, SubmitPlayerRevealTokensInput, SubmitPlayerRevealTokensRow,
};
use poker_texas_air::airs::crypto::submit_reconstruct_deck::{
    SubmitReconstructDeckAir, SubmitReconstructDeckInput, SubmitReconstructDeckRow,
};
use poker_texas_air::airs::crypto::submit_shuffle_v2::{
    SubmitShuffleV2Air, SubmitShuffleV2Input, SubmitShuffleV2Row,
};
use poker_texas_air::deck_commitment::deck_commitment;
use poker_texas_air::method_kind::MethodKind;
use poker_texas_air::orchestrator::Orchestrator;
use poker_texas_air::precompile_binding::{
    PrecompileCallBinding, RevealTokenVerifyRequest, precompile_call_context,
};
use poker_texas_air::prove_task::{DispatchOutput, ProveTask};
use poker_texas_air::prover::{MethodProof, prove_method};
use poker_texas_air::public_inputs::TexasPublicInputs;
use poker_texas_air::state_root::state_root_to_air_limbs;
use poker_texas_air::test_support as seat_fixture;
use poker_texas_air::trace_gen::generic_trace::gen_method_trace;
use poker_texas_air::verifier::verify_method_against;
use rand::rngs::OsRng;

const FIXTURE_TIMESTAMP_MS: u64 = 1_900_000;

fn context(caller: poker_l1::Address) -> DispatchContext {
    DispatchContext {
        caller,
        caller_pubkey: TaggedPubkey {
            tag: 0,
            raw: vec![0xA7; 32],
        },
        chain_id: 377,
        block_height: 9_001,
        block_timestamp: FIXTURE_TIMESTAMP_MS,
    }
}

fn dispatch_task(
    pre_table: TexasPokerTable,
    caller: poker_l1::Address,
    selector: [u8; 32],
    raw_args: Vec<u8>,
) -> ProveTask {
    let mut post_table = pre_table;
    let result = texas_dispatch::dispatch(&context(caller), &mut post_table, &selector, &raw_args)
        .expect("valid crypto dispatch should succeed");
    let output: DispatchOutput =
        borsh::from_slice(&result.return_value).expect("dispatch output should decode");
    output.prove_task.expect("state change should emit task")
}

fn canonical_public_inputs(task: &ProveTask) -> TexasPublicInputs {
    let mut public_inputs = TexasPublicInputs::from_tables(
        &task.pre_table,
        &task.post_table,
        task.method_kind,
        task.table_id,
        task.hand_id,
        task.call_seq,
    )
    .expect("canonical public inputs should build");
    public_inputs
        .bind_dispatch_call(task.context.clone(), task.selector(), task.raw_args.clone())
        .expect("dispatch call should bind");
    public_inputs
}

fn fixture(
    statement_call_seq: u32,
    request_scope_call_seq: u32,
) -> (
    MethodProof<SubmitShuffleV2Air>,
    SubmitShuffleV2Air,
    TexasPublicInputs,
) {
    let table_id = 42;
    let hand_id = 7;
    let seat_index = 2;
    let secret_key = <Bls12381Curve as Curve>::Scalar::random(&mut OsRng);
    let public_key = <Bls12381Curve as Curve>::base_g() * secret_key;
    let prior_secret_key = <Bls12381Curve as Curve>::Scalar::random(&mut OsRng);
    let prior_public_key = <Bls12381Curve as Curve>::base_g() * prior_secret_key;
    let aggregate_public_key = prior_public_key + public_key;
    let input_cards: Vec<_> = (0..52)
        .map(|i| {
            let card = Bls12381Curve::hash_to_curve(format!("air-binding/card/{i}").as_bytes());
            ElGamalCiphertextGeneric::encrypt(
                &card,
                &aggregate_public_key,
                &<Bls12381Curve as Curve>::Scalar::random(&mut OsRng),
            )
        })
        .collect();
    let mut permutation: Vec<usize> = (0..52).collect();
    permutation[..8].copy_from_slice(&[3, 0, 7, 1, 6, 2, 5, 4]);
    let rerandomizers: Vec<_> = (0..input_cards.len())
        .map(|_| <Bls12381Curve as Curve>::Scalar::random(&mut OsRng))
        .collect();
    let output_cards: Vec<_> = (0..input_cards.len())
        .map(|i| input_cards[permutation[i]].re_encrypt(&aggregate_public_key, &rerandomizers[i]))
        .collect();
    let transcript_context = b"zk_shuffle_proof_v2";
    let shuffle_proof = ShuffleProof::prove(
        &input_cards,
        &output_cards,
        &permutation,
        &rerandomizers,
        &aggregate_public_key,
        &mut OsRng,
        &mut FiatShamirTranscript::new(transcript_context),
    )
    .unwrap();

    let player = [0x31; 20];
    let mut table = TexasPokerTable::new(
        ObjectID::new([0xD3; 20], table_id),
        "precompile-binding-shuffle".into(),
        [0xC0; 20],
        4,
        50,
        100,
    );
    table.call_seq = statement_call_seq
        .checked_sub(1)
        .expect("statement call sequence must be non-zero");
    table.hand_id = hand_id;
    seat_fixture::set_player(&mut table.seats[0], [0x30; 20]);
    table.seats[0].set_status(SeatStatus::Active);
    seat_fixture::set_stack(&mut table.seats[0], 1_000);
    seat_fixture::set_pk(&mut table.seats[0], ECPoint(prior_public_key));
    seat_fixture::set_player(&mut table.seats[usize::from(seat_index)], player);
    table.seats[usize::from(seat_index)].set_status(SeatStatus::Active);
    seat_fixture::set_stack(&mut table.seats[usize::from(seat_index)], 1_000);
    seat_fixture::set_pk(
        &mut table.seats[usize::from(seat_index)],
        ECPoint(public_key),
    );
    table.deck_state.encrypted = input_cards.clone().try_into().unwrap();
    table.deck_state.contributor_mask = 1u16 | (1u16 << seat_index);
    table.derived_aggregated_pk().unwrap();
    table
        .enter_initial_shuffling(
            ShuffleState {
                pending_mask: 1u16 << seat_index,
                completed_mask: 1u16,
            },
            FIXTURE_TIMESTAMP_MS,
        )
        .unwrap();
    let raw_args = borsh::to_vec(&SubmitShuffleV2Args {
        seat_index,
        output_cards: output_cards.clone(),
        shuffle_proof: shuffle_proof.clone(),
    })
    .expect("shuffle args should encode");
    let task = dispatch_task(
        table,
        player,
        texas_dispatch::selectors::submit_shuffle_v2(),
        raw_args,
    );
    assert_eq!(task.call_seq, statement_call_seq);
    let mut public_inputs = canonical_public_inputs(&task);

    let call_context = precompile_call_context(
        MethodKind::SubmitShuffleV2,
        seat_index,
        table_id,
        hand_id,
        request_scope_call_seq,
        public_inputs.pre_version,
        public_inputs.post_version,
        public_inputs.pre_state_root,
        public_inputs.post_state_root,
        public_inputs.dispatch_call_digest,
    );
    let request = build_bls12381_shuffle_request(
        transcript_context,
        &call_context,
        TranscriptId::FiatShamirSha3,
        &aggregate_public_key,
        &input_cards,
        &output_cards,
        &shuffle_proof,
    )
    .unwrap();
    let binding = PrecompileCallBinding::verify_shuffle(&request).unwrap();
    let input = SubmitShuffleV2Input {
        seat_index,
        new_deck_commitment: deck_commitment(&task.post_table),
        shuffle_phase: task.pre_table.shuffle_phase(),
        precompile: binding.air_binding(),
    };
    let pre_root = state_root_to_air_limbs(public_inputs.pre_state_root);
    let post_root = state_root_to_air_limbs(public_inputs.post_state_root);
    let row = SubmitShuffleV2Row::active(
        &input,
        pre_root,
        post_root,
        table_id,
        hand_id,
        statement_call_seq,
        public_inputs.pre_version,
        public_inputs.post_version,
        u8::try_from(task.post_table.shuffle_state().completed_mask.count_ones())
            .expect("completed player count should fit u8"),
    );
    let trace = gen_method_trace(
        SubmitShuffleV2Air::num_columns(),
        &row.to_vec(),
        &SubmitShuffleV2Row::padding().to_vec(),
    )
    .unwrap();
    let air = SubmitShuffleV2Air {
        log_size: trace.log_size,
        input,
        pre_state_root: pre_root,
        post_state_root: post_root,
        table_id,
        hand_id,
        call_seq: statement_call_seq,
        pre_version: public_inputs.pre_version,
        post_version: public_inputs.post_version,
    };
    public_inputs.precompile_binding = Some(binding);
    public_inputs
        .bind_expected_trace_row(&row.to_vec())
        .unwrap();
    let proof = prove_method(
        &trace,
        air.clone(),
        SubmitShuffleV2Air::num_columns(),
        public_inputs.clone(),
    )
    .unwrap();
    (proof, air, public_inputs)
}

#[test]
fn honest_verified_request_and_receipt_are_bound_to_the_air() {
    let (proof, air, public_inputs) = fixture(3, 3);
    verify_method_against(proof, air, &public_inputs).unwrap();
}

#[test]
fn bare_air_success_without_a_verifier_binding_fails_closed() {
    let (proof, air, mut public_inputs) = fixture(3, 3);
    public_inputs.precompile_binding = None;
    assert!(verify_method_against(proof, air, &public_inputs).is_err());
}

#[test]
fn valid_crypto_receipt_cannot_be_replayed_at_another_call_sequence() {
    let (proof, air, public_inputs) = fixture(3, 4);
    assert!(verify_method_against(proof, air, &public_inputs).is_err());
}

#[test]
fn changing_a_receipt_digest_limb_invalidates_the_statement() {
    let (proof, mut air, public_inputs) = fixture(3, 3);
    air.input.precompile.receipt_digest[15] += stwo::core::fields::m31::M31::from(1u32);
    assert!(verify_method_against(proof, air, &public_inputs).is_err());
}

#[test]
fn changing_a_request_digest_limb_invalidates_the_statement() {
    let (proof, mut air, public_inputs) = fixture(3, 3);
    air.input.precompile.request_digest[0] += stwo::core::fields::m31::M31::from(1u32);
    assert!(verify_method_against(proof, air, &public_inputs).is_err());
}

#[derive(Clone, Copy)]
enum RevealRequestVariant {
    Honest,
    OtherCallSequence,
    OtherCiphertext,
    OtherAssignment,
    OtherPlayerKey,
    OtherValidProof,
}

fn prove_reveal_token(
    secret_key: &<Bls12381Curve as Curve>::Scalar,
    public_key: &<Bls12381Curve as Curve>::Point,
    encrypted_card: &ElGamalCiphertextGeneric<Bls12381Curve>,
) -> (ECPoint, RevealTokenProof<Bls12381Curve>) {
    let reveal_token = encrypted_card.c1 * *secret_key;
    let proof = RevealTokenProof::prove(
        secret_key,
        public_key,
        encrypted_card,
        &reveal_token,
        &mut OsRng,
        &mut MerlinTranscript::new(REVEAL_TOKEN_PROOF_LABEL),
    );
    (ECPoint(reveal_token), proof)
}

fn reveal_fixture(
    variant: RevealRequestVariant,
) -> (
    MethodProof<SubmitPlayerRevealTokensAir>,
    SubmitPlayerRevealTokensAir,
    TexasPublicInputs,
) {
    let table_id = 71;
    let hand_id = 11;
    let call_seq = 8;
    let seat_index = 1;
    let secret_key = <Bls12381Curve as Curve>::Scalar::random(&mut OsRng);
    let public_key = <Bls12381Curve as Curve>::base_g() * secret_key;
    let encrypted_cards: Vec<_> = (0..52)
        .map(|i| {
            let plaintext = Bls12381Curve::hash_to_curve(format!("air-reveal/card/{i}").as_bytes());
            ElGamalCiphertextGeneric::encrypt(
                &plaintext,
                &public_key,
                &<Bls12381Curve as Curve>::Scalar::random(&mut OsRng),
            )
        })
        .collect();
    let (reveal_token, reveal_proof) =
        prove_reveal_token(&secret_key, &public_key, &encrypted_cards[0]);

    let player = [0x71; 20];
    let mut table = TexasPokerTable::new(
        ObjectID::new([0xA6; 20], table_id),
        "precompile-binding-reveal".into(),
        [0xC0; 20],
        3,
        50,
        100,
    );
    table.call_seq = call_seq - 1;
    table.hand_id = hand_id;
    let other_secret_key = <Bls12381Curve as Curve>::Scalar::random(&mut OsRng);
    let other_public_key = <Bls12381Curve as Curve>::base_g() * other_secret_key;
    seat_fixture::set_player(&mut table.seats[0], [0x70; 20]);
    table.seats[0].set_status(SeatStatus::Active);
    seat_fixture::set_stack(&mut table.seats[0], 1_000);
    seat_fixture::set_pk(&mut table.seats[0], ECPoint(other_public_key));
    seat_fixture::set_player(&mut table.seats[usize::from(seat_index)], player);
    table.seats[usize::from(seat_index)].set_status(SeatStatus::Active);
    seat_fixture::set_stack(&mut table.seats[usize::from(seat_index)], 1_000);
    seat_fixture::set_pk(
        &mut table.seats[usize::from(seat_index)],
        ECPoint(public_key),
    );
    table.deck_state.encrypted = encrypted_cards.clone().try_into().unwrap();
    table.deck_state.contributor_mask = 1u16 | (1u16 << seat_index);
    table.derived_aggregated_pk().unwrap();
    table
        .enter_revealing(
            ROUND_PREFLOP,
            RevealTokenState {
                purpose: RevealPurpose::DealHole,
                assignments: vec![
                    RevealAssignment {
                        encrypted_card_index: 0,
                        target: RevealTarget::Hole {
                            seat_index: 0,
                            card_slot: 0,
                        },
                        pending_mask: 1u16 << seat_index,
                        submitted_mask: 0,
                        reveal_tokens: vec![],
                    },
                    RevealAssignment {
                        encrypted_card_index: 1,
                        target: RevealTarget::Hole {
                            seat_index: 1,
                            card_slot: 0,
                        },
                        pending_mask: 1u16,
                        submitted_mask: 0,
                        reveal_tokens: vec![],
                    },
                ],
            },
            FIXTURE_TIMESTAMP_MS,
        )
        .unwrap();
    let args = SubmitRevealTokensArgs {
        seat_index,
        reveal_tokens: vec![reveal_token],
        proofs: vec![reveal_proof],
    };
    let raw_args = borsh::to_vec(&args).expect("reveal args should encode");
    let task = dispatch_task(
        table,
        player,
        texas_dispatch::selectors::submit_player_reveal_tokens(),
        raw_args,
    );
    assert_eq!(task.call_seq, call_seq);
    let mut public_inputs = canonical_public_inputs(&task);

    let request_call_seq = if matches!(variant, RevealRequestVariant::OtherCallSequence) {
        call_seq + 1
    } else {
        call_seq
    };
    let call_context = precompile_call_context(
        MethodKind::SubmitPlayerRevealTokens,
        seat_index,
        table_id,
        hand_id,
        request_call_seq,
        public_inputs.pre_version,
        public_inputs.post_version,
        public_inputs.pre_state_root,
        public_inputs.post_state_root,
        public_inputs.dispatch_call_digest,
    );
    let mut request_table = task.pre_table.clone();
    let mut request_args = args;
    match variant {
        RevealRequestVariant::Honest | RevealRequestVariant::OtherCallSequence => {}
        RevealRequestVariant::OtherCiphertext => {
            let plaintext = Bls12381Curve::hash_to_curve(b"air-reveal/other-ciphertext");
            let ciphertext = ElGamalCiphertextGeneric::encrypt(
                &plaintext,
                &public_key,
                &<Bls12381Curve as Curve>::Scalar::random(&mut OsRng),
            );
            let (token, proof) = prove_reveal_token(&secret_key, &public_key, &ciphertext);
            request_table.deck_state.encrypted[0] = ciphertext;
            request_args.reveal_tokens[0] = token;
            request_args.proofs[0] = proof;
        }
        RevealRequestVariant::OtherAssignment => {
            let assignments = &mut request_table.active_reveal_state_mut().unwrap().assignments;
            assignments[0].pending_mask = 0;
            assignments[0].submitted_mask = 1u16 << seat_index;
            assignments[0].reveal_tokens = vec![request_args.reveal_tokens[0]];
            assignments[1].pending_mask = 1u16 << seat_index;
            assignments[1].submitted_mask = 0;
            assignments[1].reveal_tokens.clear();
            let (token, proof) = prove_reveal_token(&secret_key, &public_key, &encrypted_cards[1]);
            request_args.reveal_tokens[0] = token;
            request_args.proofs[0] = proof;
        }
        RevealRequestVariant::OtherPlayerKey => {
            let other_secret_key = <Bls12381Curve as Curve>::Scalar::random(&mut OsRng);
            let other_public_key = <Bls12381Curve as Curve>::base_g() * other_secret_key;
            let (token, proof) =
                prove_reveal_token(&other_secret_key, &other_public_key, &encrypted_cards[0]);
            seat_fixture::set_pk(
                &mut request_table.seats[usize::from(seat_index)],
                ECPoint(other_public_key),
            );
            request_args.reveal_tokens[0] = token;
            request_args.proofs[0] = proof;
        }
        RevealRequestVariant::OtherValidProof => {
            let (_, proof) = prove_reveal_token(&secret_key, &public_key, &encrypted_cards[0]);
            request_args.proofs[0] = proof;
        }
    }
    let request =
        RevealTokenVerifyRequest::from_dispatch(call_context, &request_table, &request_args)
            .unwrap();
    let binding = PrecompileCallBinding::verify_reveal_tokens(&request).unwrap();
    let input = SubmitPlayerRevealTokensInput {
        seat_index,
        reveal_phase: task.pre_table.reveal_phase(),
        version_increment: u8::try_from(task.post_table.call_seq - task.pre_table.call_seq)
            .expect("reveal call-sequence delta should fit u8"),
        precompile: binding.air_binding(),
        settlement: poker_texas_air::settlement_binding::SettlementPlanBinding::inactive(),
    };
    let pre_root = state_root_to_air_limbs(public_inputs.pre_state_root);
    let post_root = state_root_to_air_limbs(public_inputs.post_state_root);
    let row = SubmitPlayerRevealTokensRow::active(
        &input,
        pre_root,
        post_root,
        table_id,
        hand_id,
        call_seq,
        public_inputs.pre_version,
        public_inputs.post_version,
        u8::try_from(task.post_table.reveal_assignments().len())
            .expect("reveal assignment count should fit u8"),
    );
    let trace = gen_method_trace(
        SubmitPlayerRevealTokensAir::num_columns(),
        &row.to_vec(),
        &SubmitPlayerRevealTokensRow::padding().to_vec(),
    )
    .unwrap();
    let air = SubmitPlayerRevealTokensAir {
        log_size: trace.log_size,
        input,
        pre_state_root: pre_root,
        post_state_root: post_root,
        table_id,
        hand_id,
        call_seq,
        pre_version: public_inputs.pre_version,
        post_version: public_inputs.post_version,
    };
    public_inputs.precompile_binding = Some(binding);
    public_inputs
        .bind_expected_trace_row(&row.to_vec())
        .unwrap();
    let proof = prove_method(
        &trace,
        air.clone(),
        SubmitPlayerRevealTokensAir::num_columns(),
        public_inputs.clone(),
    )
    .unwrap();
    (proof, air, public_inputs)
}

#[test]
fn honest_reveal_token_receipt_is_bound_to_exact_dispatch() {
    let (proof, air, public_inputs) = reveal_fixture(RevealRequestVariant::Honest);
    verify_method_against(proof, air, &public_inputs).unwrap();
}

#[test]
fn reveal_token_fails_closed_without_a_verifier_binding() {
    let (proof, air, mut public_inputs) = reveal_fixture(RevealRequestVariant::Honest);
    public_inputs.precompile_binding = None;
    assert!(verify_method_against(proof, air, &public_inputs).is_err());
}

#[test]
fn reveal_token_receipt_cannot_cross_call_sequence_scope() {
    let (proof, air, public_inputs) = reveal_fixture(RevealRequestVariant::OtherCallSequence);
    assert!(verify_method_against(proof, air, &public_inputs).is_err());
}

#[test]
fn reveal_token_receipt_binds_ciphertext_assignment_player_key_and_proof() {
    for variant in [
        RevealRequestVariant::OtherCiphertext,
        RevealRequestVariant::OtherAssignment,
        RevealRequestVariant::OtherPlayerKey,
        RevealRequestVariant::OtherValidProof,
    ] {
        let (proof, air, public_inputs) = reveal_fixture(variant);
        assert!(verify_method_against(proof, air, &public_inputs).is_err());
    }
}

#[test]
fn changing_reveal_token_digest_columns_invalidates_the_statement() {
    let (proof, mut air, public_inputs) = reveal_fixture(RevealRequestVariant::Honest);
    air.input.precompile.receipt_digest[3] += stwo::core::fields::m31::M31::from(1u32);
    assert!(verify_method_against(proof, air, &public_inputs).is_err());
}

#[test]
fn non_terminal_reveal_cannot_claim_an_active_settlement() {
    let (proof, mut air, public_inputs) = reveal_fixture(RevealRequestVariant::Honest);
    air.input.settlement.active = true;
    air.input.settlement.plan_digest = [0x77; 32];
    air.input.settlement.runout_count = 1;
    assert!(verify_method_against(proof, air, &public_inputs).is_err());
}

#[test]
fn terminal_rit_reveal_arms_showdown_display_and_proves() {
    let table_id = 72;
    let hand_id = 12;
    let seat_index = 1;
    let secret_key = <Bls12381Curve as Curve>::Scalar::random(&mut OsRng);
    let public_key = <Bls12381Curve as Curve>::base_g() * secret_key;
    let canonical_cards = utils::generate_plaintext_cards();
    let card_order = [30usize, 31]
        .into_iter()
        .chain(0usize..30)
        .chain(32usize..52);
    let encrypted_cards: Vec<_> = card_order
        .map(|card_id| {
            ElGamalCiphertextGeneric::encrypt(
                &canonical_cards[card_id],
                &public_key,
                &<Bls12381Curve as Curve>::Scalar::random(&mut OsRng),
            )
        })
        .collect();
    let submissions: Vec<_> = encrypted_cards
        .iter()
        .take(2)
        .map(|ciphertext| prove_reveal_token(&secret_key, &public_key, ciphertext))
        .collect();

    let player0 = [0x72; 20];
    let player1 = [0x73; 20];
    let mut table = TexasPokerTable::new(
        ObjectID::new([0xA6; 20], table_id),
        "terminal-rit-binding".into(),
        [0xC0; 20],
        3,
        50,
        100,
    );
    table.call_seq = 8;
    table.hand_id = hand_id;
    table.rit_mode = RIT_MODE_TWICE;
    table.run_it_twice_state = RunItTwiceState::Twice {
        start: RitStartStreet::Preflop,
        second_board_suffix: BoardCards::try_from(
            (5u8..10).map(Card::from_index).collect::<Vec<_>>(),
        )
        .unwrap(),
    };
    table.community_cards =
        BoardCards::try_from((0u8..5).map(Card::from_index).collect::<Vec<_>>()).unwrap();
    table.pot = 200;
    table.chip_pool = 2_000;
    seat_fixture::set_player(&mut table.seats[0], player0);
    table.seats[0].set_status(SeatStatus::Active);
    seat_fixture::set_stack(&mut table.seats[0], 900);
    seat_fixture::set_total_bet(&mut table.seats[0], 100);
    table.seats[0].set_status(SeatStatus::AllIn);
    seat_fixture::set_hand(
        &mut table.seats[0],
        [Card::from_index(20), Card::from_index(21)].into(),
    );
    seat_fixture::set_player(&mut table.seats[1], player1);
    table.seats[1].set_status(SeatStatus::Active);
    seat_fixture::set_stack(&mut table.seats[1], 900);
    seat_fixture::set_total_bet(&mut table.seats[1], 100);
    table.seats[1].set_status(SeatStatus::AllIn);
    seat_fixture::set_pk(&mut table.seats[1], ECPoint(public_key));
    table.deck_state.encrypted = encrypted_cards.clone().try_into().unwrap();
    table.deck_state.contributor_mask = 1u16 << 1;
    table.derived_aggregated_pk().unwrap();
    for (index, ciphertext) in encrypted_cards.iter().take(2).copied().enumerate() {
        table
            .deck_state
            .owner_readable_hole_cards
            .insert(
                seat_index,
                u8::try_from(index).unwrap(),
                PartialHoleCard::new(u8::try_from(index).unwrap(), ciphertext),
            )
            .unwrap();
    }
    table
        .enter_revealing(
            ROUND_SHOWDOWN,
            RevealTokenState {
                purpose: RevealPurpose::ShowdownOwner,
                assignments: (0u8..2)
                    .map(|encrypted_card_index| RevealAssignment {
                        encrypted_card_index,
                        target: RevealTarget::Hole {
                            seat_index,
                            card_slot: encrypted_card_index,
                        },
                        pending_mask: 1u16 << seat_index,
                        submitted_mask: 0,
                        reveal_tokens: vec![],
                    })
                    .collect(),
            },
            FIXTURE_TIMESTAMP_MS,
        )
        .unwrap();

    let mut rejected_table = table.clone();
    let rejected_pre = rejected_table.clone();
    let short_args = borsh::to_vec(&SubmitRevealTokensArgs {
        seat_index,
        reveal_tokens: vec![submissions[0].0],
        proofs: vec![submissions[0].1],
    })
    .unwrap();
    let error = texas_dispatch::dispatch(
        &context(player1),
        &mut rejected_table,
        &texas_dispatch::selectors::submit_player_reveal_tokens(),
        &short_args,
    )
    .expect_err("reveal submission must cover every pending assignment");
    assert!(error.to_string().contains("expected 2 token/proof pairs"));
    assert_eq!(rejected_table, rejected_pre, "failed reveal must be atomic");

    let raw_args = borsh::to_vec(&SubmitRevealTokensArgs {
        seat_index,
        reveal_tokens: submissions.iter().map(|(token, _)| *token).collect(),
        proofs: submissions.into_iter().map(|(_, proof)| proof).collect(),
    })
    .unwrap();
    let task = dispatch_task(
        table,
        player1,
        texas_dispatch::selectors::submit_player_reveal_tokens(),
        raw_args,
    );
    assert_eq!(task.post_table.call_seq - task.pre_table.call_seq, 1);
    assert_eq!(task.post_table.pot, 200);
    assert_eq!(task.post_table.round_state(), ROUND_SHOWDOWN);
    assert!(task.post_table.reveal_assignments().is_empty());

    let mut replayed = task.pre_table.clone();
    let replay_args = texas_dispatch::replay_dispatch_args(
        task.method_kind as u8,
        &task.raw_args,
        &task.context,
        &task.pre_table,
    )
    .unwrap();
    let result =
        texas_dispatch::dispatch(&task.context, &mut replayed, &task.selector(), &replay_args)
            .unwrap();
    let output: DispatchOutput = borsh::from_slice(&result.return_value).unwrap();
    assert!(
        poker_texas_air::settlement_binding::SettlementPlanBinding::from_events(&output.events)
            .is_err()
    );

    Orchestrator::new()
        .prove_and_verify_task(&task)
        .expect("terminal RIT reveal should prove and verify before deadline settlement");
}

#[test]
fn honest_reconstruction_v3_receipt_is_bound_to_the_air() {
    let table_id = 51;
    let hand_id = 8;
    let call_seq = 6;
    let seat_index = 1;
    let secret_key = <Bls12381Curve as Curve>::Scalar::random(&mut OsRng);
    let public_key = <Bls12381Curve as Curve>::base_g() * secret_key;
    let cards = utils::generate_plaintext_cards();
    let readable_cards: Vec<_> = [2usize, 5]
        .iter()
        .map(|&i| {
            ElGamalCiphertextGeneric::encrypt(
                &cards[i],
                &public_key,
                &<Bls12381Curve as Curve>::Scalar::random(&mut OsRng),
            )
        })
        .collect();

    let player = [0x51; 20];
    let mut table = TexasPokerTable::new(
        ObjectID::new([0xE4; 20], table_id),
        "precompile-binding-reconstruct".into(),
        [0xC0; 20],
        2,
        50,
        100,
    );
    table.call_seq = call_seq - 1;
    table.hand_id = hand_id;
    seat_fixture::set_player(&mut table.seats[0], [0x52; 20]);
    table.seats[0].set_status(SeatStatus::Active);
    seat_fixture::set_stack(&mut table.seats[0], 1_000);
    seat_fixture::set_player(&mut table.seats[1], player);
    table.seats[1].set_status(SeatStatus::Active);
    seat_fixture::set_stack(&mut table.seats[1], 1_000);
    seat_fixture::set_pk(&mut table.seats[1], ECPoint(public_key));
    table.deck_state.contributor_mask = 1u16 << 1;
    table.derived_aggregated_pk().unwrap();
    for (index, ciphertext) in readable_cards.iter().copied().enumerate() {
        table
            .deck_state
            .owner_readable_hole_cards
            .insert(
                seat_index,
                index as u8,
                PartialHoleCard::new(index as u8, ciphertext),
            )
            .unwrap();
    }
    let epoch_ms = 9;
    table
        .enter_reconstructing(
            ROUND_TURN,
            ReconstructState {
                pending_mask: (1u16 << 0) | (1u16 << seat_index),
                accumulated_deck: None,
            },
            RevealTokenState {
                purpose: RevealPurpose::Board,
                assignments: vec![],
            },
            epoch_ms,
        )
        .unwrap();
    let context_digest = utils::reconstruction_v3_context_digest(&table);
    let prior_state_digest =
        utils::reconstruction_v3_prior_state_digest(&table, seat_index).unwrap();
    let (statement, reconstruction_proof) = ReconstructProofV3::prove(
        context_digest,
        epoch_ms,
        prior_state_digest,
        cards.clone(),
        readable_cards.clone(),
        &secret_key,
        &public_key,
        &public_key,
        &mut OsRng,
        &mut FiatShamirTranscript::new(RECONSTRUCTION_V3_PROOF_LABEL),
    )
    .unwrap();
    let raw_args = borsh::to_vec(&SubmitReconstructDeckArgs {
        seat_index,
        statement: statement.clone(),
        proof: reconstruction_proof.clone(),
    })
    .expect("reconstruction args should encode");
    let task = dispatch_task(
        table,
        player,
        texas_dispatch::selectors::submit_reconstruct_deck(),
        raw_args,
    );
    assert_eq!(task.call_seq, call_seq);
    let mut public_inputs = canonical_public_inputs(&task);

    let call_context = precompile_call_context(
        MethodKind::SubmitReconstructDeck,
        seat_index,
        table_id,
        hand_id,
        call_seq,
        public_inputs.pre_version,
        public_inputs.post_version,
        public_inputs.pre_state_root,
        public_inputs.post_state_root,
        public_inputs.dispatch_call_digest,
    );
    let request = build_bls12381_reconstruction_v3_request(
        RECONSTRUCTION_V3_PROOF_LABEL,
        &call_context,
        TranscriptId::FiatShamirSha3,
        &statement,
        &reconstruction_proof,
    )
    .unwrap();
    let binding = PrecompileCallBinding::verify_reconstruction_v3(&request).unwrap();
    let input = SubmitReconstructDeckInput {
        seat_index,
        reconstruct_phase: task.pre_table.reconstruct_phase(),
        precompile: binding.air_binding(),
    };
    let pre_root = state_root_to_air_limbs(public_inputs.pre_state_root);
    let post_root = state_root_to_air_limbs(public_inputs.post_state_root);
    let row = SubmitReconstructDeckRow::active(
        &input,
        pre_root,
        post_root,
        table_id,
        hand_id,
        call_seq,
        public_inputs.pre_version,
        public_inputs.post_version,
    );
    let trace = gen_method_trace(
        SubmitReconstructDeckAir::num_columns(),
        &row.to_vec(),
        &SubmitReconstructDeckRow::padding().to_vec(),
    )
    .unwrap();
    let air = SubmitReconstructDeckAir {
        log_size: trace.log_size,
        input,
        pre_state_root: pre_root,
        post_state_root: post_root,
        table_id,
        hand_id,
        call_seq,
        pre_version: public_inputs.pre_version,
        post_version: public_inputs.post_version,
    };
    public_inputs.precompile_binding = Some(binding);
    public_inputs
        .bind_expected_trace_row(&row.to_vec())
        .unwrap();
    let proof = prove_method(
        &trace,
        air.clone(),
        SubmitReconstructDeckAir::num_columns(),
        public_inputs.clone(),
    )
    .unwrap();
    verify_method_against(proof, air, &public_inputs).unwrap();
}
