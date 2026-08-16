//! Task 36.1 + 36.5: DAG 并行 TPS 基准 + Bullshark 共识延迟。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）+ tasks.md Task 36：
//! - SubTask 36.1: 多 validator DAG 并行 TPS 基准
//!   测量 DAG vertex 插入吞吐 + Bullshark 线性排序 + block 投影端到端 TPS
//! - SubTask 36.5: DAG vertex 传播延迟 + Bullshark 共识延迟
//!   测量 detect_commit_leader + bullshark_linear_order + project_block_from_commit 单次延迟

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use poker_l1::account::AccountStore;
use poker_l1::consensus::bullshark::{
    Dag, bullshark_linear_order, detect_commit_leader, project_block_from_commit,
};
use poker_l1::consensus::{DagCommitCertificate, DagVertex};
use poker_l1::executor::ExecutionEnvironment;
use poker_l1::signature::TaggedPubkey;
use poker_l1::signature::tagged_pubkey::{CURRENT_VERSION, SignatureScheme, encode_tag};
use poker_l1::storage::ObjectDb;
use poker_l1::transaction::{Gas, RouteHint, Transaction, TxLane};
use poker_l1::{ChainId, Hash};

// ===== 辅助函数 =====

/// 构造占位 tagged pubkey。
fn make_tagged(byte: u8) -> TaggedPubkey {
    let mut raw = vec![byte];
    raw.extend_from_slice(&[0x02u8; 32]);
    TaggedPubkey {
        tag: encode_tag(SignatureScheme::Secp256k1, CURRENT_VERSION),
        raw,
    }
}

/// 构造含 N 笔 tx 的 DagVertex。
fn make_vertex_with_txs(
    epoch: u64,
    round: u64,
    author: TaggedPubkey,
    tx_count: usize,
    parents: Vec<Hash>,
) -> DagVertex {
    let tx_list: Vec<Transaction> = (0..tx_count)
        .map(|i| Transaction {
            inputs: vec![],
            outputs: vec![],
            contract_call: None,
            tagged_pubkey: author.clone(),
            signature: vec![0u8; 65],
            gas: Gas::new(1000, 1),
            lane_hint: if i % 2 == 0 {
                TxLane::GameTurn
            } else {
                TxLane::Public
            },
            route_hint: RouteHint::AnyValidator,
            chain_id: ChainId::from(0x706F_6B31u32),
            nonce: i as u64,
            gameturn_nonce: if i % 2 == 0 { Some(i as u64) } else { None },
            is_fallback: false,
        })
        .collect();
    DagVertex {
        epoch,
        round,
        author_pubkey: author,
        tx_list,
        parent_hashes: parents,
        author_sig: vec![0u8; 65],
    }
}

/// 构造全零 DagCommitCertificate（占位）。
fn make_commit_cert() -> DagCommitCertificate {
    DagCommitCertificate {
        epoch: 1,
        commit_round: 1,
        prev_commit_hash: [0u8; 32],
        epoch_transition: None,
        vertex_hash_list: vec![],
        round_attendance_bitmap: vec![0xFF; 1],
        state_root: [0u8; 32],
        public_tx_root: [0u8; 32],
        gameturn_tx_root: [0u8; 32],
        signature_list: vec![],
        signer_bitmap: vec![0xFF; 1],
    }
}

/// 构造 N 个 validator 的 DAG：每轮 N 个 vertex，每轮 vertex 引用上一轮所有 vertex。
///
/// 返回 (dag, leader_hash)，leader 为最后一轮的第一个 vertex。
fn build_dag(validators: usize, rounds: usize, txs_per_vertex: usize) -> (Dag, Hash) {
    let mut dag = Dag::new();
    let authors: Vec<TaggedPubkey> = (0..validators)
        .map(|i| make_tagged(0x10 + i as u8))
        .collect();
    let mut prev_hashes: Vec<Hash> = Vec::new();

    for r in 1..=rounds {
        let mut current_hashes: Vec<Hash> = Vec::new();
        for author in authors.iter().take(validators) {
            let vertex = make_vertex_with_txs(
                1,
                r as u64,
                author.clone(),
                txs_per_vertex,
                if r == 1 { vec![] } else { prev_hashes.clone() },
            );
            let h = dag.insert(vertex);
            current_hashes.push(h);
        }
        prev_hashes = current_hashes;
    }

    // leader = 最后一轮第一个 vertex
    let leader_hash = prev_hashes[0];
    (dag, leader_hash)
}

// ===== SubTask 36.1: DAG 并行 TPS 基准 =====

/// 测量 DAG 插入吞吐（vertex/秒）+ 完整共识 pipeline TPS（tx/秒）。
fn bench_dag_tps(c: &mut Criterion) {
    let mut group = c.benchmark_group("task36_1_dag_tps");
    group.sample_size(20);

    // 不同 validator 数量的 TPS 基准
    for &validators in &[5usize, 10, 20] {
        let txs_per_vertex = 50;
        let rounds = 5;

        group.throughput(Throughput::Elements(
            (validators * rounds * txs_per_vertex) as u64,
        ));

        group.bench_with_input(
            BenchmarkId::new("consensus_pipeline", format!("v{}", validators)),
            &validators,
            |b, &v| {
                b.iter(|| {
                    let (dag, leader_hash) = build_dag(v, rounds, txs_per_vertex);

                    // detect_commit_leader
                    let leader = detect_commit_leader(&dag, &leader_hash, v).expect("detect");

                    // bullshark_linear_order
                    if let Some(ref cl) = leader {
                        let _ordered =
                            bullshark_linear_order(&dag, &cl.referencing_hashes).expect("order");
                    }

                    // project_block_from_commit
                    if let Some(cl) = leader {
                        let cert = make_commit_cert();
                        let env = ExecutionEnvironment::new(ChainId::from(0x706F_6B31u32), 1, 1000);
                        let mut object_db = ObjectDb::open_inmemory().expect("打开内存 ObjectDb");
                        let mut account_store = AccountStore::new();
                        let _projection = project_block_from_commit(
                            &dag,
                            &cl,
                            cert,
                            &env,
                            &mut object_db,
                            &mut account_store,
                            [0u8; 32],
                            1,
                            1000,
                        )
                        .expect("project");
                    }

                    black_box(dag.len());
                });
            },
        );
    }

    // 纯插入吞吐（不含共识）
    for &txs_per_vertex in &[10usize, 50, 100, 500] {
        group.throughput(Throughput::Elements(txs_per_vertex as u64));

        group.bench_with_input(
            BenchmarkId::new("vertex_insert", format!("tx{}", txs_per_vertex)),
            &txs_per_vertex,
            |b, &txs| {
                b.iter(|| {
                    let mut dag = Dag::new();
                    let author = make_tagged(0x10);
                    for r in 1..=10 {
                        let vertex = make_vertex_with_txs(1, r as u64, author.clone(), txs, vec![]);
                        dag.insert(vertex);
                    }
                    black_box(dag.len());
                });
            },
        );
    }

    group.finish();
}

// ===== SubTask 36.5: DAG vertex 传播延迟 + Bullshark 共识延迟 =====

/// 测量单次 detect_commit_leader + bullshark_linear_order + project_block 延迟。
fn bench_consensus_latency(c: &mut Criterion) {
    let mut group = c.benchmark_group("task36_5_consensus_latency");
    group.sample_size(30);

    // 不同 DAG 规模的单次共识延迟
    for &(validators, rounds) in &[(5usize, 3usize), (10, 5), (20, 10)] {
        let (dag, leader_hash) = build_dag(validators, rounds, 50);

        // detect_commit_leader 延迟
        group.bench_function(
            format!("detect_commit_leader_v{}_r{}", validators, rounds),
            |b| {
                b.iter(|| {
                    let result =
                        detect_commit_leader(&dag, &leader_hash, validators).expect("detect");
                    black_box(result);
                });
            },
        );

        // 完整共识 pipeline 延迟
        group.bench_function(format!("full_pipeline_v{}_r{}", validators, rounds), |b| {
            b.iter(|| {
                let leader = detect_commit_leader(&dag, &leader_hash, validators).expect("detect");
                if let Some(ref cl) = leader {
                    let ordered =
                        bullshark_linear_order(&dag, &cl.referencing_hashes).expect("order");
                    let cert = make_commit_cert();
                    let env = ExecutionEnvironment::new(ChainId::from(0x706F_6B31u32), 1, 1000);
                    let mut object_db = ObjectDb::open_inmemory().expect("打开内存 ObjectDb");
                    let mut account_store = AccountStore::new();
                    let _projection = project_block_from_commit(
                        &dag,
                        cl,
                        cert,
                        &env,
                        &mut object_db,
                        &mut account_store,
                        [0u8; 32],
                        1,
                        1000,
                    )
                    .expect("project");
                    black_box(ordered.len());
                }
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_dag_tps, bench_consensus_latency);
criterion_main!(benches);
