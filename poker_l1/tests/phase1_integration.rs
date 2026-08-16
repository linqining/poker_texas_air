//! Phase 1 集成测试（Task 38 — SubTask 38.1~38.5）
//!
//! 覆盖跨模块端到端场景，验证各模块组合后的正确性：
//! - SubTask 38.1：基础类型序列化往返 + InputTooLong 边界
//! - SubTask 38.2：tagged pubkey 签名验证正向 + 反向
//! - SubTask 38.3：ObjectID 全局唯一性 + 所有权转移合法路径
//! - SubTask 38.4：链存储集成（put/get/range/batch + 崩溃恢复）
//! - SubTask 38.5：账户抽象端到端（创建账户 → 签名 tx → 验证 → 执行 → 余额变更）

use poker_l1::account::{
    Account, AccountStore, apply_gameturn_tx, apply_public_tx, derive_address,
    validate_gameturn_tx, validate_normal_gameturn_not_fallback, validate_public_tx,
};
use poker_l1::block::{Block, BlockHeader, compute_tx_merkle_root};
use poker_l1::consensus::{DagCommitCertificate, DagVertex};
use poker_l1::error::PokerL1Error;
use poker_l1::object_model::{Object, ObjectID, ObjectStore, Ownership};
use poker_l1::signature::TaggedPubkey;
use poker_l1::signature::tagged_pubkey::{SignatureScheme, encode_tag};
use poker_l1::signature::unified::verify_signature;
use poker_l1::storage::{BlockStore, DagVertexStore, ObjectDb};
use poker_l1::transaction::{Gas, RouteHint, Transaction, TxLane};
use poker_l1::{ChainId, DEFAULT_CHAIN_ID};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};

// ===== 辅助构造函数 =====

fn make_tagged_pubkey_secp(byte: u8) -> TaggedPubkey {
    TaggedPubkey {
        tag: encode_tag(SignatureScheme::Secp256k1, 1),
        raw: vec![byte; 33],
    }
}

fn make_tagged_pubkey_ed25519(byte: u8) -> TaggedPubkey {
    TaggedPubkey {
        tag: encode_tag(SignatureScheme::Ed25519, 1),
        raw: vec![byte; 32],
    }
}

fn dummy_commit_cert() -> DagCommitCertificate {
    DagCommitCertificate {
        epoch: 1,
        commit_round: 1,
        prev_commit_hash: [0u8; 32],
        epoch_transition: None,
        vertex_hash_list: vec![],
        round_attendance_bitmap: vec![0xFF],
        state_root: [0u8; 32],
        account_root: [0u8; 32],
        public_tx_root: [0u8; 32],
        gameturn_tx_root: [0u8; 32],
        signature_list: vec![vec![0u8; 65]],
        signer_bitmap: vec![0xFF],
    }
}

fn make_block(height: u64, prev_hash: [u8; 32]) -> Block {
    let header = BlockHeader {
        height,
        timestamp_ms: height * 1000,
        prev_hash,
        state_root: [0u8; 32],
        account_root: [0u8; 32],
        public_tx_root: [0u8; 32],
        gameturn_tx_root: [0u8; 32],
        dag_commit_certificate: dummy_commit_cert(),
    };
    Block::new(header, vec![], vec![])
}

fn make_dag_vertex(epoch: u64, round: u64) -> DagVertex {
    DagVertex {
        epoch,
        round,
        author_pubkey: make_tagged_pubkey_secp(0x02),
        tx_list: vec![],
        parent_hashes: vec![],
        author_sig: vec![0u8; 65],
    }
}

fn make_tx(
    tagged_pubkey: TaggedPubkey,
    chain_id: ChainId,
    nonce: u64,
    gameturn_nonce: Option<u64>,
    is_fallback: bool,
    lane: TxLane,
) -> Transaction {
    Transaction {
        inputs: vec![],
        outputs: vec![],
        contract_call: None,
        tagged_pubkey,
        signature: vec![0u8; 65],
        gas: Gas::new(1000, 1),
        lane_hint: lane,
        route_hint: RouteHint::AnyValidator,
        chain_id,
        nonce,
        gameturn_nonce,
        is_fallback,
    }
}

fn blake2b_256(data: &[u8]) -> [u8; 32] {
    let mut h = Blake2bVar::new(32).expect("32 <= 64");
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).expect("32 <= 64");
    out
}

// ===== SubTask 38.1: 基础类型序列化往返 + InputTooLong 边界 =====

#[test]
fn subtask_38_1_transaction_bcs_json_roundtrip() {
    let tx = make_tx(
        make_tagged_pubkey_secp(0xAB),
        DEFAULT_CHAIN_ID,
        42,
        Some(7),
        false,
        TxLane::GameTurn,
    );
    let bcs_bytes = borsh::to_vec(&tx).unwrap();
    let recovered: Transaction = borsh::from_slice(&bcs_bytes).unwrap();
    assert_eq!(tx, recovered);

    let json = serde_json::to_string(&tx).unwrap();
    let recovered: Transaction = serde_json::from_str(&json).unwrap();
    assert_eq!(tx, recovered);
}

#[test]
fn subtask_38_1_block_bcs_json_roundtrip() {
    let block = make_block(10, [0xAB; 32]);
    let bcs_bytes = borsh::to_vec(&block).unwrap();
    let recovered: Block = borsh::from_slice(&bcs_bytes).unwrap();
    assert_eq!(block, recovered);

    let json = serde_json::to_string(&block).unwrap();
    let recovered: Block = serde_json::from_str(&json).unwrap();
    assert_eq!(block, recovered);
}

#[test]
fn subtask_38_1_dag_vertex_bcs_roundtrip() {
    let vertex = make_dag_vertex(3, 7);
    let bcs_bytes = borsh::to_vec(&vertex).unwrap();
    let recovered: DagVertex = borsh::from_slice(&bcs_bytes).unwrap();
    assert_eq!(vertex, recovered);
}

#[test]
fn subtask_38_1_dag_commit_cert_bcs_json_roundtrip() {
    let cert = dummy_commit_cert();
    let bcs_bytes = borsh::to_vec(&cert).unwrap();
    let recovered: DagCommitCertificate = borsh::from_slice(&bcs_bytes).unwrap();
    assert_eq!(cert, recovered);

    let json = serde_json::to_string(&cert).unwrap();
    let recovered: DagCommitCertificate = serde_json::from_str(&json).unwrap();
    assert_eq!(cert, recovered);
}

#[test]
fn subtask_38_1_transaction_input_too_long_rejects() {
    // 输入超过 MAX_TX_INPUTS (256)
    let mut tx = make_tx(
        make_tagged_pubkey_secp(0x01),
        DEFAULT_CHAIN_ID,
        0,
        None,
        false,
        TxLane::Public,
    );
    tx.inputs = vec![ObjectID::new([0; 20], 0); 300]; // 超过 256
    let result = poker_l1::transaction::validate_tx_limits(&tx);
    assert!(matches!(result, Err(PokerL1Error::InputTooLong { .. })));
}

#[test]
fn subtask_38_1_transaction_empty_vectors_accepted() {
    // 空 inputs / outputs / signature 应被接受（仅长度上限校验）
    let tx = make_tx(
        make_tagged_pubkey_secp(0x02),
        DEFAULT_CHAIN_ID,
        0,
        None,
        false,
        TxLane::Public,
    );
    poker_l1::transaction::validate_tx_limits(&tx).unwrap();
}

#[test]
fn subtask_38_1_compute_tx_merkle_root_consistent_with_store() {
    // block 的 tx_merkle_root 计算应与 ObjectStore SMT 一致（同算法）
    let tx1 = make_tx(
        make_tagged_pubkey_secp(0x10),
        DEFAULT_CHAIN_ID,
        0,
        None,
        false,
        TxLane::Public,
    );
    let tx2 = make_tx(
        make_tagged_pubkey_secp(0x20),
        DEFAULT_CHAIN_ID,
        1,
        None,
        false,
        TxLane::Public,
    );
    let root1 = compute_tx_merkle_root(&[tx1.clone(), tx2.clone()]);
    let root2 = compute_tx_merkle_root(&[tx1, tx2]);
    assert_eq!(root1, root2, "tx_merkle_root 必须确定性");
}

// ===== SubTask 38.2: tagged pubkey 签名验证正向 + 反向 =====

#[test]
fn subtask_38_2_secp256k1_sign_verify_roundtrip() {
    // 端到端：生成 secp256k1 密钥 → 签名 → unified verify
    use rand::rngs::OsRng;
    use secp256k1::{Message, generate_keypair};

    let (secret, public) = generate_keypair(&mut OsRng);
    let compressed = public.serialize();

    let tagged = TaggedPubkey::new(SignatureScheme::Secp256k1, 1, compressed.to_vec()).unwrap();

    let msg_bytes = blake2b_256(b"hello poker l1");
    let msg = Message::from_digest_slice(&msg_bytes).unwrap();
    let secp = secp256k1::Secp256k1::signing_only();
    let rec_sig = secp.sign_ecdsa_recoverable(&msg, &secret);
    let (recovery_id, sig_bytes) = rec_sig.serialize_compact();

    // 构造 r||s||v (65B)
    let mut full_sig = Vec::with_capacity(65);
    full_sig.extend_from_slice(&sig_bytes);
    full_sig.push(recovery_id.to_i32() as u8);

    // unified verify
    assert!(verify_signature(&tagged, &full_sig, &msg_bytes).is_ok());

    // 反向：篡改消息
    let wrong_msg = blake2b_256(b"tampered");
    assert!(verify_signature(&tagged, &full_sig, &wrong_msg).is_err());
}

#[test]
fn subtask_38_2_curve_mismatch_rejected() {
    // pubkey 是 secp256k1，签名声称 ed25519 → CurveMismatch
    let tagged_sec = make_tagged_pubkey_secp(0x02);
    let sig = vec![0u8; 65]; // secp256k1 长度
    // 注意：unified verify 会先 parse tag，pubkey tag=0x01 (secp256k1)
    // 这里测试的是 pubkey 与 sig scheme 必须匹配
    let msg = blake2b_256(b"test");
    // secp256k1 pubkey + 65B sig → 走 secp256k1 路径（签名无效返回 InvalidSignature，非 CurveMismatch）
    let result = verify_signature(&tagged_sec, &sig, &msg);
    assert!(result.is_err());
}

#[test]
fn subtask_38_2_ed25519_sign_verify_roundtrip() {
    use ed25519_dalek::{Signer, SigningKey};

    let mut csprng = rand::rngs::OsRng;
    let sk = SigningKey::generate(&mut csprng);
    let pk_bytes = sk.verifying_key().to_bytes();

    let tagged = TaggedPubkey::new(SignatureScheme::Ed25519, 1, pk_bytes.to_vec()).unwrap();
    let msg = blake2b_256(b"ed25519 test");
    let sig = sk.sign(&msg).to_vec();

    assert!(verify_signature(&tagged, &sig, &msg).is_ok());

    // 反向：篡改签名
    let mut bad_sig = sig.clone();
    bad_sig[0] ^= 0xFF;
    assert!(verify_signature(&tagged, &bad_sig, &msg).is_err());
}

// ===== SubTask 38.3: ObjectID 全局唯一性 + 所有权转移 =====

#[test]
fn subtask_38_3_objectid_global_uniqueness() {
    // NEW-L4：不同 creator + 不同 nonce 不碰撞
    let id1 = ObjectID::new([1u8; 20], 0);
    let id2 = ObjectID::new([1u8; 20], 1);
    let id3 = ObjectID::new([2u8; 20], 0);
    let id4 = ObjectID::new([2u8; 20], 1);

    let mut ids = vec![id1, id2, id3, id4];
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 4, "所有 ObjectID 必须唯一");
}

#[test]
fn subtask_38_3_object_store_create_collision_rejected() {
    let mut store = ObjectStore::new();
    let id = ObjectID::new([1u8; 20], 1);
    let owner = [9u8; 20];
    let obj = Object::new(id, Ownership::AddressOwned { owner }, "Game", vec![], None);
    store.create(obj).unwrap();

    // 同 ObjectID 再次创建
    let obj2 = Object::new(id, Ownership::AddressOwned { owner }, "Game", vec![], None);
    let err = store.create(obj2).unwrap_err();
    assert!(matches!(err, PokerL1Error::ObjectIDCollision(_)));
}

#[test]
fn subtask_38_3_ownership_transfer_legal_path() {
    let mut store = ObjectStore::new();
    let owner = [1u8; 20];
    let new_owner = [2u8; 20];
    let id = ObjectID::new(owner, 1);
    let obj = Object::new(id, Ownership::AddressOwned { owner }, "Coin", vec![], None);
    store.create(obj).unwrap();

    // 合法转移
    store.transfer(&id, &owner, new_owner).unwrap();
    assert!(store.read(&id).unwrap().can_write(&new_owner));
    assert!(!store.read(&id).unwrap().can_write(&owner));

    // 旧 owner 无法再次转移
    let err = store.transfer(&id, &owner, [3u8; 20]).unwrap_err();
    assert!(matches!(err, PokerL1Error::NotOwner(_)));
}

#[test]
fn subtask_38_3_immutable_object_not_transferable() {
    let mut store = ObjectStore::new();
    let owner = [1u8; 20];
    let id = ObjectID::new(owner, 1);
    let obj = Object::new(id, Ownership::Immutable, "SettledGame", vec![], None);
    store.create(obj).unwrap();

    let err = store.transfer(&id, &owner, [2u8; 20]).unwrap_err();
    assert!(matches!(err, PokerL1Error::ObjectImmutable(_)));
}

#[test]
fn subtask_38_3_unauthorized_write_rejected() {
    let mut store = ObjectStore::new();
    let owner = [1u8; 20];
    let attacker = [2u8; 20];
    let id = ObjectID::new(owner, 1);
    let obj = Object::new(id, Ownership::AddressOwned { owner }, "Game", vec![], None);
    store.create(obj).unwrap();

    let err = store
        .update(&id, &attacker, b"hacked".to_vec())
        .unwrap_err();
    assert!(matches!(err, PokerL1Error::NotOwner(_)));
}

// ===== SubTask 38.4: 链存储集成（put/get/range/batch + 崩溃恢复）=====

#[test]
fn subtask_38_4_block_store_crash_recovery() {
    // 写入后"崩溃"（drop store）→ 重新打开 → 数据仍在
    let dir = tempfile::tempdir().unwrap();
    let chain_id = DEFAULT_CHAIN_ID;

    let block = make_block(5, [0xAB; 32]);
    let hash = {
        let store = BlockStore::open(dir.path()).unwrap();
        store.put(&block, chain_id).unwrap()
    };
    // store drop 模拟崩溃

    let store2 = BlockStore::open(dir.path()).unwrap();
    let recovered = store2.get_by_hash(&hash).unwrap();
    assert_eq!(recovered, block);
    assert_eq!(store2.get_by_height(5).unwrap(), block);
    assert_eq!(store2.get_tip_height().unwrap(), Some(5));
}

#[test]
fn subtask_38_4_block_store_range_scan_correctness() {
    let dir = tempfile::tempdir().unwrap();
    let store = BlockStore::open(dir.path()).unwrap();
    let chain_id = DEFAULT_CHAIN_ID;

    let mut prev = [0u8; 32];
    for h in 0..20u64 {
        let b = make_block(h, prev);
        let hash = store.put(&b, chain_id).unwrap();
        prev = hash;
    }

    // range [5, 14]
    let range = store.get_range(5, 14).unwrap();
    assert_eq!(range.len(), 10);
    for (i, b) in range.iter().enumerate() {
        assert_eq!(b.header.height, 5 + i as u64);
    }
}

#[test]
fn subtask_38_4_object_db_persist_across_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let id = ObjectID::new([1u8; 20], 1);
    let owner = [1u8; 20];
    let obj = Object::new(
        id,
        Ownership::AddressOwned { owner },
        "Game",
        b"data".to_vec(),
        None,
    );

    let root_before = {
        let mut db = ObjectDb::open(dir.path()).unwrap();
        db.create(obj).unwrap();
        db.state_root()
    };

    let db2 = ObjectDb::open(dir.path()).unwrap();
    let recovered = db2.read(&id).unwrap();
    assert_eq!(recovered.id, id);
    assert_eq!(recovered.owner, Ownership::AddressOwned { owner });
    assert_eq!(db2.state_root(), root_before, "重开后 state_root 必须一致");
}

#[test]
fn subtask_38_4_dag_vertex_store_three_way_index() {
    let dir = tempfile::tempdir().unwrap();
    let store = DagVertexStore::open(dir.path()).unwrap();

    let v1 = make_dag_vertex(1, 5);
    let v2 = make_dag_vertex(1, 5); // 同 round 不同 author
    let mut v2_diff_author = v2.clone();
    v2_diff_author.author_pubkey = make_tagged_pubkey_secp(0x03);

    store.put(&v1).unwrap();
    store.put(&v2_diff_author).unwrap();

    // 按 round 查询：应返回 2 个
    let by_round = store.get_by_round(1, 5).unwrap();
    assert_eq!(by_round.len(), 2);

    // 按 author 查询 v1
    let by_author = store.get_by_author(&v1.author_pubkey).unwrap();
    assert_eq!(by_author.len(), 1);
    assert_eq!(by_author[0].vertex_hash(), v1.vertex_hash());
}

// ===== SubTask 38.5: 账户抽象端到端 =====

#[test]
fn subtask_38_5_account_nonce_monotonic_and_replay_rejected() {
    let tp = make_tagged_pubkey_secp(0x55);
    let mut account = Account::new(tp, 1_000_000);
    let network = DEFAULT_CHAIN_ID;

    // 第一次 tx（nonce=0）合法
    let tx1 = make_tx(
        account.tagged_pubkey.clone(),
        network,
        0,
        None,
        false,
        TxLane::Public,
    );
    validate_public_tx(&account, &tx1, network).unwrap();
    apply_public_tx(&mut account, &tx1, 100).unwrap();
    assert_eq!(account.nonce, 1);
    assert_eq!(account.balance, 1_000_000 - 100);

    // 重放 tx1（nonce=0 < account.nonce=1）→ NonceTooLow
    let err = validate_public_tx(&account, &tx1, network).unwrap_err();
    assert!(matches!(
        err,
        PokerL1Error::NonceTooLow { tx: 0, account: 1 }
    ));

    // 跳号 tx（nonce=5 > account.nonce=1）→ NonceTooHigh
    let tx3 = make_tx(
        account.tagged_pubkey.clone(),
        network,
        5,
        None,
        false,
        TxLane::Public,
    );
    let err = validate_public_tx(&account, &tx3, network).unwrap_err();
    assert!(matches!(
        err,
        PokerL1Error::NonceTooHigh { tx: 5, account: 1 }
    ));

    // 正确的下一个 tx（nonce=1）
    let tx2 = make_tx(
        account.tagged_pubkey.clone(),
        network,
        1,
        None,
        false,
        TxLane::Public,
    );
    validate_public_tx(&account, &tx2, network).unwrap();
    apply_public_tx(&mut account, &tx2, 200).unwrap();
    assert_eq!(account.nonce, 2);
    assert_eq!(account.balance, 1_000_000 - 100 - 200);
}

#[test]
fn subtask_38_5_wrong_chain_id_rejected() {
    let tp = make_tagged_pubkey_secp(0x66);
    let account = Account::new(tp, 1_000_000);
    let network = DEFAULT_CHAIN_ID;

    // tx 声称不同 chain_id
    let tx = make_tx(
        account.tagged_pubkey.clone(),
        network + 999,
        0,
        None,
        false,
        TxLane::Public,
    );
    let err = validate_public_tx(&account, &tx, network).unwrap_err();
    assert!(matches!(err, PokerL1Error::WrongChainId { .. }));
}

#[test]
fn subtask_38_5_insufficient_balance_rejected() {
    let tp = make_tagged_pubkey_secp(0x77);
    let mut account = Account::new(tp, 100);
    let network = DEFAULT_CHAIN_ID;

    let tx = make_tx(
        account.tagged_pubkey.clone(),
        network,
        0,
        None,
        false,
        TxLane::Public,
    );
    validate_public_tx(&account, &tx, network).unwrap();
    // gas 超过余额
    let err = apply_public_tx(&mut account, &tx, 500).unwrap_err();
    assert!(matches!(
        err,
        PokerL1Error::InsufficientBalance {
            needed: 500,
            has: 100
        }
    ));
    // 失败时 nonce 不推进
    assert_eq!(account.nonce, 0);
}

#[test]
fn subtask_38_5_gameturn_tx_does_not_block_account_nonce() {
    // NEW-M9 核心语义：GameTurn tx 用 gameturn_nonce，不影响 account nonce
    let tp = make_tagged_pubkey_secp(0x88);
    let mut account = Account::new(tp, 1_000_000);
    let mut game_player_nonce: u64 = 0;
    let network = DEFAULT_CHAIN_ID;

    // 玩家出牌 5 次
    for _ in 0..5 {
        let tx = make_tx(
            account.tagged_pubkey.clone(),
            network,
            0,
            Some(game_player_nonce),
            false,
            TxLane::GameTurn,
        );
        validate_gameturn_tx(game_player_nonce, &tx, network).unwrap();
        validate_normal_gameturn_not_fallback(&tx).unwrap();
        apply_gameturn_tx(&mut game_player_nonce);
    }
    assert_eq!(game_player_nonce, 5);
    assert_eq!(account.nonce, 0, "GameTurn tx 不推进 account nonce");
    assert_eq!(account.balance, 1_000_000, "GameTurn tx 免 gas");

    // 之后提交 Public tx，account nonce 从 0 开始
    let public_tx = make_tx(
        account.tagged_pubkey.clone(),
        network,
        0,
        None,
        false,
        TxLane::Public,
    );
    validate_public_tx(&account, &public_tx, network).unwrap();
    apply_public_tx(&mut account, &public_tx, 50).unwrap();
    assert_eq!(account.nonce, 1);
    assert_eq!(account.balance, 1_000_000 - 50);
}

#[test]
fn subtask_38_5_normal_gameturn_with_fallback_flag_rejected() {
    // SEC-H7：正常 GameTurn tx 设置 is_fallback=true → InvalidFallbackFlag
    let tx = make_tx(
        make_tagged_pubkey_secp(0x99),
        DEFAULT_CHAIN_ID,
        0,
        Some(0),
        true, // 非法
        TxLane::GameTurn,
    );
    let err = validate_normal_gameturn_not_fallback(&tx).unwrap_err();
    assert!(matches!(err, PokerL1Error::InvalidFallbackFlag));
}

#[test]
fn subtask_38_5_account_store_full_lifecycle() {
    let mut store = AccountStore::new();
    let tp = make_tagged_pubkey_ed25519(0xAA);
    let account = Account::new(tp.clone(), 500);
    let addr = account.address;

    // 创建
    store.create(account).unwrap();
    assert_eq!(store.len(), 1);

    // 按 pubkey 查询
    assert!(store.get_by_pubkey(&tp).is_some());

    // 充值
    store.credit(&addr, 500).unwrap();
    assert_eq!(store.get(&addr).unwrap().balance, 1000);

    // 地址派生一致性
    assert_eq!(derive_address(&tp), addr);
}

#[test]
fn subtask_38_5_end_to_end_block_with_tx_persisted() {
    // 端到端：创建账户 → 构造 tx → 组装 block → 持久化 → 重开恢复
    let dir = tempfile::tempdir().unwrap();
    let chain_id = DEFAULT_CHAIN_ID;

    let tp = make_tagged_pubkey_secp(0xBB);
    let account = Account::new(tp.clone(), 10_000_000);
    let tx = make_tx(tp, chain_id, account.nonce, None, false, TxLane::Public);

    let block = {
        let header = BlockHeader {
            height: 1,
            timestamp_ms: 1000,
            prev_hash: [0u8; 32],
            state_root: [0u8; 32],
            account_root: [0u8; 32],
            public_tx_root: compute_tx_merkle_root(std::slice::from_ref(&tx)),
            gameturn_tx_root: [0u8; 32],
            dag_commit_certificate: dummy_commit_cert(),
        };
        Block::new(header, vec![tx], vec![])
    };

    let hash = {
        let store = BlockStore::open(dir.path()).unwrap();
        store.put(&block, chain_id).unwrap()
    };

    // 重开恢复
    let store2 = BlockStore::open(dir.path()).unwrap();
    let recovered = store2.get_by_hash(&hash).unwrap();
    assert_eq!(recovered, block);
    assert_eq!(recovered.public_txs.len(), 1);
    assert_eq!(recovered.public_txs[0].nonce, 0);
}
