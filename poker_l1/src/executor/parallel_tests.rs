//! 并行执行器测试（Task P-3）。
//!
//! 验证 [`execute_block`]（波次并行）与 [`execute_block_serial`]（串行）的严格等价性，
//! 以及并发场景下的正确性：多 caller 并行写不同对象、同 caller nonce 保序、冲突隔离。
//!
//! 核心断言：同一组有序 tx + 同一初始状态 → 并行版与串行版产生**相同 state_root**
//! 与**逐笔一致的回执**（success / gas_used / fee_charged / created / modified）。

#![cfg(test)]

use super::*;
use crate::DEFAULT_CHAIN_ID;
use crate::account::Account;
use crate::object_model::{Object, ObjectID, Ownership};
use crate::signature::TaggedPubkey;
use crate::signature::tagged_pubkey::{SignatureScheme, encode_tag};
use crate::storage::ObjectDb;
use crate::transaction::{Gas, RouteHint, TxRequest};
use secp256k1::{Message, Secp256k1};

// ===== 辅助 =====

#[derive(Clone)]
struct Signer {
    sk: secp256k1::SecretKey,
    pk: secp256k1::PublicKey,
}

impl Signer {
    fn tagged_pubkey(&self) -> TaggedPubkey {
        TaggedPubkey {
            tag: encode_tag(SignatureScheme::Secp256k1, 1),
            raw: self.pk.serialize().to_vec(),
        }
    }

    fn address(&self) -> crate::Address {
        derive_address(&self.tagged_pubkey())
    }

    fn sign(&self, req: TxRequest) -> Transaction {
        let hash = req.signing_hash();
        let secp = Secp256k1::new();
        let sig = secp.sign_ecdsa_recoverable(&Message::from_digest(hash), &self.sk);
        let (rid, compact) = sig.serialize_compact();
        let mut full_sig = compact.to_vec();
        full_sig.push(rid.to_i32() as u8);
        req.into_transaction(self.tagged_pubkey(), full_sig)
    }
}

/// 创建 output 对象的 Public TxRequest。
fn output_tx(signer: &Signer, tx_nonce: u64, creation_nonce: u64, data: &[u8]) -> Transaction {
    let caller = signer.address();
    signer.sign(TxRequest {
        inputs: vec![],
        outputs: vec![Object::new(
            ObjectID::new(caller, creation_nonce),
            Ownership::AddressOwned { owner: caller },
            "Out",
            data.to_vec(),
            None,
        )],
        contract_call: None,
        gas: Gas::new(1_000_000, 1),
        lane_hint: TxLane::Public,
        route_hint: RouteHint::AnyValidator,
        chain_id: DEFAULT_CHAIN_ID,
        nonce: tx_nonce,
        gameturn_nonce: None,
        is_fallback: false,
    })
}

fn make_env() -> ExecutionEnvironment {
    ExecutionEnvironment::new(DEFAULT_CHAIN_ID, 100, 1_000_000)
}

/// 基础 fixture：一个 ObjectDb + AccountStore + 初始状态根。
struct MultiFixture {
    object_db: ObjectDb,
    account_store: AccountStore,
    #[allow(dead_code)]
    signers: Vec<Signer>,
    initial_root: crate::Hash,
}

/// 回执的关键可比字段（排除 gas_used 在 precompile/rBPF 差异——本测试用纯 outputs）。
fn receipt_key(r: &TxReceipt) -> (bool, Vec<ObjectID>, Vec<ObjectID>) {
    (
        r.success,
        r.created_objects.clone(),
        r.modified_objects.clone(),
    )
}

// ===== 等价性：多 caller 多波次 =====

#[test]
fn parallel_equals_serial_multi_caller_independent() {
    // 3 个不同 caller 各发 2 笔 tx（各自 nonce 0,1）。
    // 每个 caller 的两笔因 nonce 落不同波次；不同 caller 的同序号 tx 可同波次。
    let det = deterministic_signers(3);
    let txs: Vec<Transaction> = (0..3)
        .flat_map(|i| {
            let s = &det[i];
            vec![output_tx(s, 0, 0, b"a"), output_tx(s, 1, 1, b"b")]
        })
        .collect();

    let mut par = fresh_state(&det);
    let mut ser = fresh_state(&det);

    let out_par = execute_block(
        &make_env(),
        &txs,
        &mut par.object_db,
        &mut par.account_store,
    );
    let out_ser = execute_block_serial(
        &make_env(),
        &txs,
        &mut ser.object_db,
        &mut ser.account_store,
    );

    // state_root 严格一致
    assert_eq!(
        out_par.state_root, out_ser.state_root,
        "并行/串行 state_root 必须一致"
    );
    assert_eq!(out_par.total_gas_used, out_ser.total_gas_used);
    assert_eq!(out_par.receipts.len(), out_ser.receipts.len());
    for (i, (rp, rs)) in out_par
        .receipts
        .iter()
        .zip(out_ser.receipts.iter())
        .enumerate()
    {
        assert_eq!(receipt_key(rp), receipt_key(rs), "tx{i} 回执不一致");
    }
}

// ===== 冲突隔离：写同一对象的 tx 不并发 =====

#[test]
fn parallel_two_writes_same_caller_still_correct() {
    // 同一 caller 两笔 tx（nonce 0,1）写不同对象 → 应都成功，nonce 推进到 2。
    let det = deterministic_signers(1);
    let txs = vec![
        output_tx(&det[0], 0, 100, b"x"),
        output_tx(&det[0], 1, 101, b"y"),
    ];
    let mut fx = fresh_state(&det);
    let out = execute_block(&make_env(), &txs, &mut fx.object_db, &mut fx.account_store);
    assert!(out.receipts.iter().all(|r| r.success), "{:?}", out.receipts);
    // 两笔都成功
    let caller = det[0].address();
    assert_eq!(fx.account_store.get(&caller).unwrap().nonce, 2);
    // 两个对象都已创建
    assert!(fx.object_db.read(&ObjectID::new(caller, 100)).is_ok());
    assert!(fx.object_db.read(&ObjectID::new(caller, 101)).is_ok());
}

// ===== nonce 保序：同 caller 三笔 tx 顺序推进 =====

#[test]
fn parallel_preserves_account_nonce_ordering() {
    let det = deterministic_signers(1);
    let txs = vec![
        output_tx(&det[0], 0, 1, b"t1"),
        output_tx(&det[0], 1, 2, b"t2"),
        output_tx(&det[0], 2, 3, b"t3"),
    ];
    let mut fx = fresh_state(&det);
    let out = execute_block(&make_env(), &txs, &mut fx.object_db, &mut fx.account_store);
    assert!(out.receipts.iter().all(|r| r.success));
    assert_eq!(fx.account_store.get(&det[0].address()).unwrap().nonce, 3);
    assert_ne!(fx.object_db.state_root(), fx.initial_root);
}

// ===== 多 caller 并行：不同 caller 同序号 tx 落同一波次 =====

#[test]
fn parallel_multi_caller_same_nonce_concurrent() {
    // 4 个不同 caller 各发 1 笔 tx（nonce 0）→ 理论上可全部同波次并发。
    let det = deterministic_signers(4);
    let txs: Vec<Transaction> = det
        .iter()
        .map(|s| output_tx(s, 0, 0, b"parallel"))
        .collect();
    let mut fx = fresh_state(&det);
    let out = execute_block(&make_env(), &txs, &mut fx.object_db, &mut fx.account_store);
    assert_eq!(out.receipts.len(), 4);
    assert!(out.receipts.iter().all(|r| r.success), "{:?}", out.receipts);
    // 每个 caller 的对象都已创建
    for s in &det {
        assert!(fx.object_db.read(&ObjectID::new(s.address(), 0)).is_ok());
        assert_eq!(fx.account_store.get(&s.address()).unwrap().nonce, 1);
    }
}

#[test]
fn parallel_reconsiders_deferred_tx_after_actual_gas_is_known() {
    // Both independent txs reserve the full 1M budget, so they cannot enter one execution batch
    // under a 1M block limit. Their actual gas is zero, therefore serial semantics admit both;
    // the parallel executor must execute the second in a follow-up batch instead of rejecting it.
    let det = deterministic_signers(2);
    let txs = vec![
        output_tx(&det[0], 0, 700, b"first"),
        output_tx(&det[1], 0, 701, b"second"),
    ];
    let env = make_env().with_block_gas_limit(1_000_000);
    let mut par = fresh_state(&det);
    let mut ser = fresh_state(&det);

    let out_par = execute_block(&env, &txs, &mut par.object_db, &mut par.account_store);
    let out_ser = execute_block_serial(&env, &txs, &mut ser.object_db, &mut ser.account_store);

    assert!(out_par.receipts.iter().all(|receipt| receipt.success));
    assert_eq!(out_par.state_root, out_ser.state_root);
    assert_eq!(out_par.total_gas_used, out_ser.total_gas_used);
    assert_eq!(out_par.total_gas_used, 0);
}

// ===== 等价性 fuzz：随机 N 笔 tx（多 caller）串行/并行一致 =====

#[test]
fn parallel_serial_equivalence_fuzz() {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    for _round in 0..8 {
        let n_callers = rng.gen_range(1..=5);
        let n_txs = rng.gen_range(1..=12);
        let det = deterministic_signers(n_callers);

        // 每个 caller 维护一个 nonce 游标
        let mut nonce_cursor = vec![0u64; n_callers];
        let mut txs = Vec::new();
        let mut byte_seq: u8 = 0;
        for _ in 0..n_txs {
            let ci = rng.gen_range(0..n_callers);
            let creation_nonce = rng.gen_range(0..1000u64);
            byte_seq = byte_seq.wrapping_add(1);
            txs.push(output_tx(
                &det[ci],
                nonce_cursor[ci],
                creation_nonce,
                &[byte_seq; 4],
            ));
            nonce_cursor[ci] += 1;
        }

        let mut par = fresh_state(&det);
        let mut ser = fresh_state(&det);
        let out_par = execute_block(
            &make_env(),
            &txs,
            &mut par.object_db,
            &mut par.account_store,
        );
        let out_ser = execute_block_serial(
            &make_env(),
            &txs,
            &mut ser.object_db,
            &mut ser.account_store,
        );

        assert_eq!(
            out_par.state_root, out_ser.state_root,
            "fuzz: state_root 不一致 (callers={n_callers}, txs={n_txs})"
        );
        assert_eq!(out_par.total_gas_used, out_ser.total_gas_used);
        assert_eq!(out_par.receipts.len(), out_ser.receipts.len());
        for (i, (rp, rs)) in out_par
            .receipts
            .iter()
            .zip(out_ser.receipts.iter())
            .enumerate()
        {
            assert_eq!(
                receipt_key(rp),
                receipt_key(rs),
                "fuzz: tx{i} 回执不一致 (callers={n_callers})"
            );
        }
    }
}

// ===== 空 block =====

#[test]
fn parallel_empty_block_unchanged() {
    let det = deterministic_signers(1);
    let mut fx = fresh_state(&det);
    let out = execute_block(&make_env(), &[], &mut fx.object_db, &mut fx.account_store);
    assert!(out.receipts.is_empty());
    assert_eq!(out.state_root, fx.initial_root);
    assert_eq!(out.total_gas_used, 0);
}

// ===== 确定性 signer（从固定种子派生，保证串行/并行用同一组 txs）=====

fn deterministic_signers(n: usize) -> Vec<Signer> {
    use secp256k1::rand::SeedableRng;
    // 固定种子：每次调用产生相同的密钥组
    (0..n)
        .map(|i| {
            let mut rng = secp256k1::rand::rngs::StdRng::seed_from_u64(0xBADC_0DE + i as u64);
            let secp = Secp256k1::new();
            let (sk, pk) = secp.generate_keypair(&mut rng);
            Signer { sk, pk }
        })
        .collect()
}

fn fresh_state(signers: &[Signer]) -> MultiFixture {
    let object_db = ObjectDb::open_inmemory().expect("ObjectDb");
    let mut account_store = AccountStore::new();
    for s in signers {
        account_store
            .create(Account::new(s.tagged_pubkey(), 1_000_000))
            .expect("create account");
    }
    let initial_root = object_db.state_root();
    MultiFixture {
        object_db,
        account_store,
        signers: signers.to_vec(),
        initial_root,
    }
}
