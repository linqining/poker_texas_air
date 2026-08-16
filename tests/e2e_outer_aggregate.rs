//! Stage-4 safe outer-aggregate tests.

use poker_l1::object_model::ObjectID;
use poker_l1::signature::TaggedPubkey;
use poker_l1::vm::contracts::dispatch::DispatchContext;
use poker_l1::vm::contracts::texas_poker::dispatch::{self as texas_dispatch, SubmitShuffleV2Args};
use poker_l1::vm::contracts::texas_poker::types::{SeatStatus, ShuffleState, TexasPokerTable};
use poker_protocol::crypto::curve::{Bls12381Curve, Curve, CurveScalar, ElGamalCiphertextGeneric};
use poker_protocol::crypto::types::ECPoint;
use poker_protocol::zk_shuffle::ShuffleProof;
use poker_protocol::zk_shuffle::transcript_ext::{CryptoTranscript, FiatShamirTranscript};
use poker_texas_air::dual_proof::{DualProofBundle, prove_dual_proof};
use poker_texas_air::outer_aggregate::{
    OUTER_AGGREGATE_VERSION, OuterAggregateBundle, aggregate_dual_proofs, prove_outer_aggregate,
    verify_outer_aggregate,
};
use poker_texas_air::outer_precompile::{
    HostVerifiedOuterAggregateProof, prove_host_verified_outer_aggregate_from_bundle,
    verify_host_verified_outer_aggregate,
};
use poker_texas_air::prove_task::{DispatchOutput, ProveTask};
use poker_texas_air::test_support as seat_fixture;
use poker_texas_air::verified_chain::ExpectedChainAnchor;
use rand::rngs::OsRng;

const HEADER_LEN: usize = 144;
const FIXTURE_TIMESTAMP_MS: u64 = 2_000_000;

fn context(caller: poker_l1::Address) -> DispatchContext {
    DispatchContext {
        caller,
        caller_pubkey: TaggedPubkey {
            tag: 0,
            raw: vec![0xA4; 32],
        },
        chain_id: 377,
        block_height: 12_345,
        block_timestamp: FIXTURE_TIMESTAMP_MS,
    }
}

fn dispatch_task(
    pre_table: TexasPokerTable,
    caller: poker_l1::Address,
    raw_args: Vec<u8>,
) -> (ProveTask, TexasPokerTable) {
    let mut post_table = pre_table;
    let result = texas_dispatch::dispatch(
        &context(caller),
        &mut post_table,
        &texas_dispatch::selectors::submit_shuffle_v2(),
        &raw_args,
    )
    .expect("valid sequential shuffle should dispatch");
    let output: DispatchOutput =
        borsh::from_slice(&result.return_value).expect("dispatch output should decode");
    (
        output.prove_task.expect("shuffle should emit a task"),
        post_table,
    )
}

fn next_shuffle_task(
    table: TexasPokerTable,
    seat_index: u8,
    aggregated_pk: <Bls12381Curve as Curve>::Point,
    round: usize,
) -> (ProveTask, TexasPokerTable) {
    let input_cards = table.deck_state.encrypted.to_vec();
    let first_eight = match round % 3 {
        0 => [3, 0, 7, 1, 6, 2, 5, 4],
        1 => [1, 7, 3, 5, 0, 6, 4, 2],
        _ => [6, 4, 2, 0, 7, 5, 3, 1],
    };
    let mut permutation: Vec<usize> = (0..52).collect();
    permutation[..8].copy_from_slice(&first_eight);
    let rerandomizers: Vec<_> = (0..input_cards.len())
        .map(|_| <Bls12381Curve as Curve>::Scalar::random(&mut OsRng))
        .collect();
    let output_cards: Vec<_> = (0..input_cards.len())
        .map(|i| input_cards[permutation[i]].re_encrypt(&aggregated_pk, &rerandomizers[i]))
        .collect();
    let proof = ShuffleProof::prove(
        &input_cards,
        &output_cards,
        &permutation,
        &rerandomizers,
        &aggregated_pk,
        &mut OsRng,
        &mut FiatShamirTranscript::new(b"zk_shuffle_proof_v2"),
    )
    .expect("Bayer--Groth proof should build");
    let raw_args = borsh::to_vec(&SubmitShuffleV2Args {
        seat_index,
        output_cards,
        shuffle_proof: proof,
    })
    .expect("shuffle args should encode");
    let caller = table.seats[seat_index as usize].player();
    dispatch_task(table, caller, raw_args)
}

fn sequential_shuffle_tasks(nonce: u64) -> Vec<ProveTask> {
    let seat_secrets: Vec<_> = (0..4)
        .map(|_| <Bls12381Curve as Curve>::Scalar::random(&mut OsRng))
        .collect();
    let seat_keys: Vec<_> = seat_secrets
        .iter()
        .map(|secret| <Bls12381Curve as Curve>::base_g() * secret)
        .collect();
    let aggregated_pk = seat_keys
        .iter()
        .copied()
        .reduce(|left, right| left + right)
        .expect("four keys");
    let input_cards: Vec<_> = (0..52)
        .map(|i| {
            let card = Bls12381Curve::hash_to_curve(
                format!("outer-aggregate/{nonce}/card/{i}").as_bytes(),
            );
            ElGamalCiphertextGeneric::encrypt(
                &card,
                &aggregated_pk,
                &<Bls12381Curve as Curve>::Scalar::random(&mut OsRng),
            )
        })
        .collect();

    let mut table = TexasPokerTable::new(
        ObjectID::new([0xB4; 20], nonce),
        format!("outer-{nonce}"),
        [0xC0; 20],
        4,
        50,
        100,
    );
    table.call_seq = 20;
    table.hand_id = 9;
    for (index, key) in seat_keys.into_iter().enumerate() {
        seat_fixture::set_player(
            &mut table.seats[index],
            [u8::try_from(index + 1).unwrap(); 20],
        );
        table.seats[index].set_status(SeatStatus::Active);
        seat_fixture::set_stack(&mut table.seats[index], 1_000);
        seat_fixture::set_pk(&mut table.seats[index], ECPoint(key));
    }
    table.deck_state.encrypted = input_cards.try_into().unwrap();
    table.deck_state.contributor_mask = 0b1111;
    assert_eq!(
        table.derived_aggregated_pk().unwrap(),
        Some(ECPoint(aggregated_pk))
    );
    table
        .enter_initial_shuffling(
            ShuffleState {
                pending_mask: 0b1111,
                completed_mask: 0,
            },
            FIXTURE_TIMESTAMP_MS,
        )
        .unwrap();

    let mut tasks = Vec::new();
    for round in 0..3 {
        let seat_index = table.shuffle_state().derived_current_shuffler();
        assert_ne!(seat_index, u8::MAX, "three shufflers should remain");
        let (task, post) = next_shuffle_task(table, seat_index, aggregated_pk, round);
        tasks.push(task);
        table = post;
    }
    tasks
}

fn child_segments(encoded: &[u8]) -> Vec<Vec<u8>> {
    let count = u32::from_le_bytes(encoded[12..16].try_into().unwrap()) as usize;
    let mut cursor = HEADER_LEN;
    let mut children = Vec::with_capacity(count);
    for _ in 0..count {
        let len = u32::from_le_bytes(encoded[cursor..cursor + 4].try_into().unwrap()) as usize;
        let end = cursor + 4 + len;
        children.push(encoded[cursor..end].to_vec());
        cursor = end;
    }
    assert_eq!(cursor, encoded.len());
    children
}

fn rebuild_outer(header: &[u8], children: &[Vec<u8>]) -> Vec<u8> {
    let mut out = header[..HEADER_LEN].to_vec();
    out[12..16].copy_from_slice(&(children.len() as u32).to_le_bytes());
    for child in children {
        out.extend_from_slice(child);
    }
    out
}

fn anchor_from_verified(
    verified: &poker_texas_air::outer_aggregate::VerifiedOuterAggregate,
) -> ExpectedChainAnchor {
    let receipts = verified.chain().receipts();
    let first = &receipts[0];
    let last = receipts.last().unwrap();
    ExpectedChainAnchor::new(
        first.table_id(),
        first.hand_id(),
        first.call_seq(),
        first.pre_state_root(),
        last.post_state_root(),
        first.pre_version(),
        last.post_version(),
        receipts
            .iter()
            .map(|receipt| receipt.dispatch_call_digest())
            .collect(),
    )
    .unwrap()
}

#[test]
fn honest_outer_aggregate_roundtrips_verifies_and_anchors() {
    let tasks = sequential_shuffle_tasks(501);
    let aggregate = prove_outer_aggregate(&tasks).expect("outer aggregate should prove");
    let encoded = aggregate.encode().expect("outer aggregate should encode");
    let decoded = OuterAggregateBundle::decode(&encoded).expect("outer aggregate should decode");
    let verified = verify_outer_aggregate(&tasks, &decoded).expect("all children should verify");
    assert_eq!(verified.chain().len(), 3);
    assert_eq!(verified.precompile_bindings().len(), 3);
    assert_eq!(verified.aggregate_digest(), decoded.aggregate_digest());
    verified
        .verify_against_anchor(&anchor_from_verified(&verified))
        .expect("exact external range shape should match");
}

#[test]
fn host_verified_outer_precompile_roundtrips_and_rejects_anchor_or_air_tampering() {
    let tasks = sequential_shuffle_tasks(551);
    let aggregate = prove_outer_aggregate(&tasks).expect("outer aggregate should prove");
    let verified = verify_outer_aggregate(&tasks, &aggregate).expect("children should verify");
    let anchor = anchor_from_verified(&verified);
    let package = prove_host_verified_outer_aggregate_from_bundle(&tasks, aggregate, &anchor)
        .expect("outer precompile package should prove");
    let encoded = package
        .encode()
        .expect("outer precompile package should encode");
    let decoded = HostVerifiedOuterAggregateProof::decode(&encoded)
        .expect("outer precompile package should decode");
    let accepted = verify_host_verified_outer_aggregate(&decoded, &anchor)
        .expect("native replay and final AIR should verify");
    assert_eq!(accepted.child_count(), 3);
    assert_eq!(accepted.table_id(), anchor.table_id());
    assert_eq!(accepted.pre_state_root(), anchor.pre_state_root());
    assert_eq!(accepted.post_state_root(), anchor.post_state_root());

    // Package header (20) + request header (24) + anchor fixed fields (112)
    // reaches the first authenticated dispatch digest. Changing it preserves
    // canonical decoding but must fail comparison with the external anchor.
    let mut changed_anchor = encoded.clone();
    changed_anchor[20 + 24 + 112] ^= 1;
    let changed_anchor = HostVerifiedOuterAggregateProof::decode(&changed_anchor)
        .expect("changed digest remains structurally canonical");
    assert!(verify_host_verified_outer_aggregate(&changed_anchor, &anchor).is_err());

    let mut changed_air = encoded;
    let request_len = u32::from_le_bytes(changed_air[12..16].try_into().unwrap()) as usize;
    let proof_start = 20 + request_len;
    // Fixed-int bincode starts the commitments Vec with an eight-byte length;
    // mutate the low byte of the first commitment rather than corrupting an
    // internal polynomial length (which some upstream Stwo versions panic on).
    changed_air[proof_start + 8 + 31] ^= 1;
    if let Ok(changed_air) = HostVerifiedOuterAggregateProof::decode(&changed_air) {
        assert!(verify_host_verified_outer_aggregate(&changed_air, &anchor).is_err());
    }
}

#[test]
fn outer_aggregate_rejects_reorder_splice_deletion_and_manifest_tampering() {
    let tasks = sequential_shuffle_tasks(601);
    let aggregate = prove_outer_aggregate(&tasks).expect("fixture aggregate should prove");
    let encoded = aggregate.encode().unwrap();
    let segments = child_segments(&encoded);

    let mut reordered = segments.clone();
    reordered.swap(0, 1);
    let reordered = OuterAggregateBundle::decode(&rebuild_outer(&encoded, &reordered)).unwrap();
    assert!(verify_outer_aggregate(&tasks, &reordered).is_err());

    let other_tasks = sequential_shuffle_tasks(602);
    let foreign_child = prove_dual_proof(&other_tasks[0]).expect("foreign child should prove");
    let mut spliced = segments.clone();
    let foreign_bytes = foreign_child.encode().unwrap();
    let mut foreign_segment = Vec::new();
    foreign_segment.extend_from_slice(&(foreign_bytes.len() as u32).to_le_bytes());
    foreign_segment.extend_from_slice(&foreign_bytes);
    spliced[1] = foreign_segment;
    let spliced = OuterAggregateBundle::decode(&rebuild_outer(&encoded, &spliced)).unwrap();
    assert!(verify_outer_aggregate(&tasks, &spliced).is_err());

    let deleted = OuterAggregateBundle::decode(&rebuild_outer(&encoded, &segments[..2])).unwrap();
    assert!(verify_outer_aggregate(&tasks[..2], &deleted).is_err());

    // A legitimately rebuilt subrange verifies locally, but cannot satisfy the
    // externally authenticated complete-range anchor.
    let child_prefix: Vec<DualProofBundle> = aggregate.children()[..2].to_vec();
    let subrange = aggregate_dual_proofs(&tasks[..2], child_prefix).unwrap();
    let verified_subrange = verify_outer_aggregate(&tasks[..2], &subrange).unwrap();
    let full_verified = verify_outer_aggregate(&tasks, &aggregate).unwrap();
    assert!(
        verified_subrange
            .verify_against_anchor(&anchor_from_verified(&full_verified))
            .is_err()
    );

    let mut bad_digest = encoded.clone();
    bad_digest[112] ^= 1;
    let bad_digest = OuterAggregateBundle::decode(&bad_digest).unwrap();
    assert!(verify_outer_aggregate(&tasks, &bad_digest).is_err());

    let mut bad_table = encoded;
    bad_table[16] ^= 1;
    let bad_table = OuterAggregateBundle::decode(&bad_table).unwrap();
    assert!(verify_outer_aggregate(&tasks, &bad_table).is_err());
}

#[test]
fn strict_outer_wire_rejects_unknown_flags_trailing_and_bad_child_lengths() {
    let tasks = sequential_shuffle_tasks(701);
    let aggregate = prove_outer_aggregate(&tasks).expect("fixture aggregate should prove");
    let encoded = aggregate.encode().unwrap();

    let mut bad_version = encoded.clone();
    bad_version[8] = OUTER_AGGREGATE_VERSION + 1;
    assert!(OuterAggregateBundle::decode(&bad_version).is_err());

    let mut bad_flags = encoded.clone();
    bad_flags[9] = 1;
    assert!(OuterAggregateBundle::decode(&bad_flags).is_err());

    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(OuterAggregateBundle::decode(&trailing).is_err());

    let mut zero_child = encoded.clone();
    zero_child[HEADER_LEN..HEADER_LEN + 4].copy_from_slice(&0u32.to_le_bytes());
    assert!(OuterAggregateBundle::decode(&zero_child).is_err());

    let mut oversized_child = encoded;
    oversized_child[HEADER_LEN..HEADER_LEN + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(OuterAggregateBundle::decode(&oversized_child).is_err());
}
