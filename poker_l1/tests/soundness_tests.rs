//! poker_l1 Soundness 负向测试 — 验证安全边界与错误路径。
//!
//! 参考 poker_zkvm `tests/soundness_tests.rs` 模式，覆盖 6 类安全边界：
//! 1. 交易校验 — 输入/输出/签名/参数长度限制边界
//! 2. 签名验证 — 篡改签名/非规范编码/错误长度/跨 scheme 路由
//! 3. SMT — 篡改兄弟/截断路径/错误 key/空非空不一致
//! 4. Bridge — 非协议调用/重放/目标链不匹配
//! 5. Block 时间共识 — 高度不递增/时间回退/间隔超限
//! 6. 网络大小限制 — tx/vertex 超限

mod common;

use common::{
    dummy_commit_cert, make_real_ed25519_keypair, make_real_secp_keypair,
    make_tagged_pubkey_ed25519, make_tagged_pubkey_secp, make_tx,
};
use poker_l1::DEFAULT_CHAIN_ID;
use poker_l1::bridge::{
    BridgeDeposit, BridgeRegistry, BridgeValidatorSlot, BridgeVerifyTx, bridge_verify,
};
use poker_l1::error::PokerL1Error;
use poker_l1::network::{validate_tx_size, validate_vertex_size};
use poker_l1::object_model::{Object, ObjectID, Ownership, SparseMerkleTree};
use poker_l1::signature::unified::verify_signature;
use poker_l1::transaction::TxLane;

use std::collections::BTreeSet;

use ed25519_dalek::Signer;
use secp256k1::Message;

// ===========================================================================
// 1. 交易校验 — 长度限制边界
// ===========================================================================

#[test]
fn test_soundness_tx_inputs_at_limit_passes() {
    let tp = make_tagged_pubkey_secp(0x02);
    let mut tx = make_tx(tp, DEFAULT_CHAIN_ID, 1, None, false, TxLane::Public);
    tx.inputs = vec![ObjectID::new([0u8; 20], 0); 256]; // 恰好 MAX_INPUTS
    assert!(
        poker_l1::transaction::validate_tx_limits(&tx).is_ok(),
        "256 inputs（恰好 MAX_INPUTS）应通过校验"
    );
}

#[test]
fn test_soundness_tx_outputs_at_limit_passes() {
    let tp = make_tagged_pubkey_secp(0x02);
    let mut tx = make_tx(tp, DEFAULT_CHAIN_ID, 1, None, false, TxLane::Public);
    let dummy_obj = Object::new(
        ObjectID::new([0u8; 20], 0),
        Ownership::Shared,
        "TestType",
        vec![],
        None,
    );
    tx.outputs = vec![dummy_obj; 256]; // 恰好 MAX_OUTPUTS
    assert!(
        poker_l1::transaction::validate_tx_limits(&tx).is_ok(),
        "256 outputs（恰好 MAX_OUTPUTS）应通过校验"
    );
}

#[test]
fn test_soundness_tx_outputs_above_limit_fails() {
    let tp = make_tagged_pubkey_secp(0x02);
    let mut tx = make_tx(tp, DEFAULT_CHAIN_ID, 1, None, false, TxLane::Public);
    let dummy_obj = Object::new(
        ObjectID::new([0u8; 20], 0),
        Ownership::Shared,
        "TestType",
        vec![],
        None,
    );
    tx.outputs = vec![dummy_obj; 257]; // 超过 MAX_OUTPUTS
    let err = poker_l1::transaction::validate_tx_limits(&tx).unwrap_err();
    assert!(
        matches!(
            err,
            PokerL1Error::InputTooLong {
                actual: 257,
                limit: 256
            }
        ),
        "257 outputs 应返回 InputTooLong {{ actual: 257, limit: 256 }}, got: {err:?}"
    );
}

#[test]
fn test_soundness_tx_sig_above_limit_fails() {
    let tp = make_tagged_pubkey_secp(0x02);
    let mut tx = make_tx(tp, DEFAULT_CHAIN_ID, 1, None, false, TxLane::Public);
    tx.signature = vec![0u8; 66]; // 超过 MAX_SIG_LEN (65)
    let err = poker_l1::transaction::validate_tx_limits(&tx).unwrap_err();
    assert!(
        matches!(
            err,
            PokerL1Error::InputTooLong {
                actual: 66,
                limit: 65
            }
        ),
        "66 字节签名应返回 InputTooLong {{ actual: 66, limit: 65 }}, got: {err:?}"
    );
}

// ===========================================================================
// 2. 签名验证 — 篡改/非规范/错误长度/跨 scheme
// ===========================================================================

#[test]
fn test_soundness_sig_tampered_secp_bytes_fails() {
    let (_sk, _pk, tagged) = make_real_secp_keypair();
    let secp = secp256k1::Secp256k1::new();
    let msg_hash = [0x42u8; 32];
    let msg = Message::from_digest(msg_hash);
    let sig = secp.sign_ecdsa_recoverable(&msg, &_sk);
    let (recid, compact) = sig.serialize_compact();
    let mut sig_bytes = compact.to_vec();
    sig_bytes.push(recid.to_i32() as u8);

    // 翻转 r 首字节
    sig_bytes[0] ^= 0xFF;

    let result = verify_signature(&tagged, &sig_bytes, &msg_hash);
    assert!(
        result.is_err(),
        "篡改 secp 签名字节应验证失败, got: {result:?}"
    );
}

#[test]
fn test_soundness_sig_ed25519_non_canonical_s_fails() {
    let (sk, _vk, tagged) = make_real_ed25519_keypair();
    let msg = [0x42u8; 32];
    let sig = sk.sign(&msg);
    let mut sig_bytes = sig.to_bytes().to_vec();

    // 将 S（字节 32-63）设为全 0xFF（远大于 L，非 canonical）
    for b in &mut sig_bytes[32..64] {
        *b = 0xFF;
    }

    let result = verify_signature(&tagged, &sig_bytes, &msg);
    assert!(
        matches!(result, Err(PokerL1Error::InvalidSignatureCanonical)),
        "S 非规范应返回 InvalidSignatureCanonical, got: {result:?}"
    );
}

#[test]
fn test_soundness_sig_ed25519_wrong_pubkey_length_fails() {
    let (sk, _vk, _tagged) = make_real_ed25519_keypair();
    let msg = [0x42u8; 32];
    let sig = sk.sign(&msg);
    let sig_bytes = sig.to_bytes().to_vec();

    // 构造 raw.len()=31 的 ed25519 tagged pubkey
    let wrong_tp = poker_l1::signature::TaggedPubkey {
        tag: poker_l1::signature::tagged_pubkey::encode_tag(
            poker_l1::signature::SignatureScheme::Ed25519,
            1,
        ),
        raw: vec![0u8; 31],
    };

    let result = verify_signature(&wrong_tp, &sig_bytes, &msg);
    assert!(
        matches!(
            result,
            Err(PokerL1Error::InvalidPubkeyLength {
                actual: 31,
                expected: 32,
                ..
            })
        ),
        "raw.len()=31 应返回 InvalidPubkeyLength {{ actual: 31, expected: 32 }}, got: {result:?}"
    );
}

#[test]
fn test_soundness_sig_cross_scheme_routing_fails() {
    // ed25519 tagged pubkey + 65 字节签名（secp256k1 长度）
    let tp = make_tagged_pubkey_ed25519(0x42);
    let sig_65 = vec![0u8; 65];
    let msg = [0x42u8; 32];

    let result = verify_signature(&tp, &sig_65, &msg);
    assert!(
        matches!(
            result,
            Err(PokerL1Error::InvalidSignatureLength {
                actual: 65,
                expected: 64
            })
        ),
        "ed25519 + 65B sig 应返回 InvalidSignatureLength {{ actual: 65, expected: 64 }}, got: {result:?}"
    );
}

// ===========================================================================
// 3. SMT — 篡改兄弟/截断路径/错误 key/空非空不一致
// ===========================================================================

#[test]
fn test_soundness_smt_tampered_sibling_fails() {
    let mut t = SparseMerkleTree::new();
    let key = [7u8; 32];
    let value = b"hello";
    t.upsert(key, value);

    let mut path = t.prove(&key);
    // 翻转 siblings[0] 首字节
    path.siblings[0][0] ^= 0xFF;

    assert!(
        !SparseMerkleTree::verify(&t.root(), &key, Some(value), &path),
        "篡改兄弟哈希应导致 verify 返回 false"
    );
}

#[test]
fn test_soundness_smt_truncated_path_fails() {
    let mut t = SparseMerkleTree::new();
    let key = [7u8; 32];
    t.upsert(key, b"v");

    let mut path = t.prove(&key);
    // 截断 siblings 到 100（非 256）
    path.siblings.truncate(100);

    assert!(
        !SparseMerkleTree::verify(&t.root(), &key, Some(b"v"), &path),
        "截断路径应导致 verify 返回 false"
    );
}

#[test]
fn test_soundness_smt_wrong_key_fails() {
    let mut t = SparseMerkleTree::new();
    let key_a = [7u8; 32];
    let key_b = [8u8; 32];
    t.upsert(key_a, b"real");

    let path = t.prove(&key_a);
    // 用 key_b 调 verify
    assert!(
        !SparseMerkleTree::verify(&t.root(), &key_b, Some(b"real"), &path),
        "用错误 key 调 verify 应返回 false"
    );
}

#[test]
fn test_soundness_smt_empty_nonempty_mismatch_fails() {
    let mut t = SparseMerkleTree::new();
    let key = [7u8; 32];
    t.upsert(key, b"real");

    let mut path = t.prove(&key);
    // 设置 is_empty_leaf=true 但 value=Some(...)
    path.is_empty_leaf = true;

    assert!(
        !SparseMerkleTree::verify(&t.root(), &key, Some(b"real"), &path),
        "is_empty_leaf=true + value=Some 应返回 false"
    );
}

// ===========================================================================
// 4. Bridge — 非协议调用/重放/目标链不匹配
// ===========================================================================

fn make_bridge_deposit(nonce: u64, dest_chain_id: u64) -> BridgeDeposit {
    BridgeDeposit {
        nonce,
        source_chain_id: 0xAAAA,
        dest_chain_id,
        asset: [0xAB; 32],
        amount: 100,
        recipient: [0x01; 20],
        source_tx_hash: [0xCD; 32],
    }
}

fn make_bridge_tx(deposit: BridgeDeposit) -> BridgeVerifyTx {
    BridgeVerifyTx {
        deposit,
        validator_signatures: vec![],
        recipient_sig: vec![],
        recipient_pubkey: make_tagged_pubkey_secp(0x01),
        preferred_relayer: None,
    }
}

#[test]
fn test_soundness_bridge_not_protocol_caller_fails() {
    let mut registry = BridgeRegistry::new();
    let tx = make_bridge_tx(make_bridge_deposit(1, DEFAULT_CHAIN_ID));
    let result = bridge_verify(&mut registry, &tx, DEFAULT_CHAIN_ID, false);
    assert!(
        matches!(result, Err(PokerL1Error::BridgeVerifyNotAuthorized)),
        "is_protocol_caller=false 应返回 BridgeVerifyNotAuthorized, got: {result:?}"
    );
}

#[test]
fn test_soundness_bridge_replay_nonce_fails() {
    let mut registry = BridgeRegistry::new();
    // 注册 slot
    let validators: BTreeSet<_> = (0..5).map(|i| make_tagged_pubkey_secp(0x10 + i)).collect();
    let slot = BridgeValidatorSlot::new(0xAAAA, validators);
    registry.register_slot(slot);
    // 预消费 nonce=1
    registry.consume_nonce(0xAAAA, 1);

    let tx = make_bridge_tx(make_bridge_deposit(1, DEFAULT_CHAIN_ID));
    let result = bridge_verify(&mut registry, &tx, DEFAULT_CHAIN_ID, true);
    assert!(
        matches!(result, Err(PokerL1Error::BridgeNonceConsumed(1))),
        "重放 nonce=1 应返回 BridgeNonceConsumed(1), got: {result:?}"
    );
}

#[test]
fn test_soundness_bridge_wrong_dest_chain_fails() {
    let mut registry = BridgeRegistry::new();
    let tx = make_bridge_tx(make_bridge_deposit(1, 0x9999)); // 错误 dest_chain_id
    let result = bridge_verify(&mut registry, &tx, DEFAULT_CHAIN_ID, true);
    assert!(
        matches!(result, Err(PokerL1Error::BridgeSignatureInvalid(_))),
        "dest_chain_id 不匹配应返回 BridgeSignatureInvalid, got: {result:?}"
    );
}

// ===========================================================================
// 5. Block 时间共识 — 高度不递增/时间回退/间隔超限
// ===========================================================================

#[test]
fn test_soundness_block_height_not_increasing_fails() {
    use poker_l1::block::{BlockHeader, TimeConsensusConfig, validate_block_time};

    let config = TimeConsensusConfig::new();
    let prev = BlockHeader {
        height: 10,
        timestamp_ms: 10_000,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        account_root: [0u8; 32],
        public_tx_root: [0u8; 32],
        gameturn_tx_root: [0u8; 32],
        dag_commit_certificate: dummy_commit_cert(),
    };
    let curr = BlockHeader {
        height: 10, // 不递增（应 = 11）
        timestamp_ms: 11_000,
        ..prev.clone()
    };

    let result = validate_block_time(Some(&prev), &curr, &config);
    assert!(
        matches!(
            result,
            Err(PokerL1Error::BlockHeightNotIncreasing { prev: 10, got: 10 })
        ),
        "高度不递增应返回 BlockHeightNotIncreasing, got: {result:?}"
    );
}

#[test]
fn test_soundness_block_timestamp_backwards_fails() {
    use poker_l1::block::{BlockHeader, TimeConsensusConfig, validate_block_time};

    let config = TimeConsensusConfig::new();
    let prev = BlockHeader {
        height: 10,
        timestamp_ms: 10_000,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        account_root: [0u8; 32],
        public_tx_root: [0u8; 32],
        gameturn_tx_root: [0u8; 32],
        dag_commit_certificate: dummy_commit_cert(),
    };
    let curr = BlockHeader {
        height: 11,
        timestamp_ms: 9_000, // 回退
        ..prev.clone()
    };

    let result = validate_block_time(Some(&prev), &curr, &config);
    assert!(
        matches!(
            result,
            Err(PokerL1Error::BlockTimestampMovedBackwards { .. })
        ),
        "时间回退应返回 BlockTimestampMovedBackwards, got: {result:?}"
    );
}

#[test]
fn test_soundness_block_timestamp_interval_exceeded_fails() {
    use poker_l1::block::{BlockHeader, TimeConsensusConfig, validate_block_time};

    let config = TimeConsensusConfig::new(); // max_interval_ms = 30_000
    let prev = BlockHeader {
        height: 10,
        timestamp_ms: 10_000,
        prev_hash: [0u8; 32],
        state_root: [0u8; 32],
        account_root: [0u8; 32],
        public_tx_root: [0u8; 32],
        gameturn_tx_root: [0u8; 32],
        dag_commit_certificate: dummy_commit_cert(),
    };
    let curr = BlockHeader {
        height: 11,
        timestamp_ms: 10_000 + 30_001, // 超过 max_interval_ms
        ..prev.clone()
    };

    let result = validate_block_time(Some(&prev), &curr, &config);
    assert!(
        matches!(
            result,
            Err(PokerL1Error::BlockTimestampIntervalExceeded { .. })
        ),
        "间隔超限应返回 BlockTimestampIntervalExceeded, got: {result:?}"
    );
}

// ===========================================================================
// 6. 网络大小限制 — tx/vertex 超限
// ===========================================================================

#[test]
fn test_soundness_tx_too_large_fails() {
    let tp = make_tagged_pubkey_secp(0x02);
    let mut tx = make_tx(tp, DEFAULT_CHAIN_ID, 1, None, false, TxLane::Public);
    // 设置超大 signature 使 BCS 序列化后 > 128KB
    tx.signature = vec![0u8; 200_000];

    let result = validate_tx_size(&tx);
    assert!(
        matches!(result, Err(PokerL1Error::TxTooLarge { .. })),
        "200KB tx 应返回 TxTooLarge, got: {result:?}"
    );
}

#[test]
fn test_soundness_vertex_too_large_fails() {
    let vertex = poker_l1::consensus::DagVertex {
        epoch: 1,
        round: 1,
        author_pubkey: make_tagged_pubkey_secp(0x02),
        tx_list: vec![],
        parent_hashes: vec![],
        author_sig: vec![0u8; 300_000], // 300KB > 256KB
    };

    let result = validate_vertex_size(&vertex);
    assert!(
        matches!(result, Err(PokerL1Error::VertexTooLarge { .. })),
        "300KB vertex 应返回 VertexTooLarge, got: {result:?}"
    );
}

// ===========================================================================
// 7. P0 安全修复 — 重复签名 / identity point / partial hash / Fr 归零 / 内存 DoS
// ===========================================================================

/// H1：Bridge quorum bypass — 重复验证器签名应被拒绝。
///
/// 攻击者用同一 validator 的签名填充签名列表以达到 quorum。
#[test]
fn test_p0_bridge_duplicate_validator_sig_rejected() {
    use poker_l1::bridge::{BridgeValidatorSig, BridgeValidatorSlot};

    let validator = make_tagged_pubkey_secp(0x10);
    let validators: BTreeSet<_> = std::iter::once(validator.clone()).collect();
    let slot = BridgeValidatorSlot::new(0xAAAA, validators);

    // 同一 validator 的 2 份签名（模拟 quorum bypass）
    let sigs = vec![
        BridgeValidatorSig {
            validator: validator.clone(),
            signature: vec![0u8; 65],
        },
        BridgeValidatorSig {
            validator: validator.clone(),
            signature: vec![0u8; 65],
        },
    ];

    let result = slot.validate_signers(&sigs);
    assert!(
        matches!(result, Err(PokerL1Error::DuplicateBridgeValidator(_))),
        "重复验证器签名应返回 DuplicateBridgeValidator, got: {result:?}"
    );
}

/// H2：Light client quorum bypass — 重复签名者应被拒绝。
///
/// 攻击者用同一 validator 的签名填充签名列表以达到 2/3 quorum。
#[test]
fn test_p0_light_client_duplicate_signer_rejected() {
    use poker_l1::network::{LightClientHeader, ValidatorSig, verify_light_client_header};

    let validator = make_tagged_pubkey_secp(0x10);
    let header = LightClientHeader {
        header_bytes: vec![0x42; 100],
        signatures: vec![
            ValidatorSig {
                validator: validator.clone(),
                signature: vec![0u8; 65],
            },
            ValidatorSig {
                validator: validator.clone(),
                signature: vec![0u8; 65],
            },
        ],
        signer_bitmap: vec![true, true, false],
    };

    let validators = vec![
        validator.clone(),
        make_tagged_pubkey_secp(0x11),
        make_tagged_pubkey_secp(0x12),
    ];
    let result = verify_light_client_header(&header, &validators, |_, _, _| Ok(()));
    assert!(
        matches!(result, Err(PokerL1Error::DuplicateLightClientSigner(_))),
        "重复签名者应返回 DuplicateLightClientSigner, got: {result:?}"
    );
}

/// H3：BLS identity point 攻击 — signature_g1 为 identity point 应被拒绝。
///
/// 当 signature_g1 = O（identity）时，e(O, G2) = 1，对任意消息都返回 true。
#[test]
fn test_p0_bls_identity_signature_rejected() {
    use poker_l1::crypto_precompiles::native_api::bls_verify;

    // BLS12-381 G1 identity point: 首字节 0xc0，其余全零
    let identity_sig = [
        0xc0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let pubkey = [0u8; 96]; // 不影响测试，identity 检查在长度校验之后

    let result = bls_verify(&pubkey, &identity_sig, b"any message");
    assert!(
        matches!(result, Err(PokerL1Error::InvalidBlsPoint(_))),
        "identity point 签名应返回 InvalidBlsPoint, got: {result:?}"
    );
}

/// H3：BLS identity point 攻击 — pubkey_g2 为 identity point 应被拒绝。
///
/// 当 pubkey_g2 = O（identity）时，e(H_m, O) = 1，对任意消息都返回 true。
#[test]
fn test_p0_bls_identity_pubkey_rejected() {
    use poker_l1::crypto_precompiles::native_api::bls_verify;

    // BLS12-381 G2 identity point: 首字节 0xc0，其余全零
    let identity_pubkey = [
        0xc0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let sig = [0u8; 48]; // 不影响测试，identity 检查在长度校验之后

    let result = bls_verify(&identity_pubkey, &sig, b"any message");
    assert!(
        matches!(result, Err(PokerL1Error::InvalidBlsPoint(_))),
        "identity point 公钥应返回 InvalidBlsPoint, got: {result:?}"
    );
}

/// H4：ack_chain partial hash 不匹配应被拒绝。
///
/// 攻击者提交 has_partial_checkin=true 但 ack_chain 前 N 项与
/// last_partial_fold.ack_chain_partial_hash 不匹配的 checkin tx。
#[test]
fn test_p0_ack_chain_partial_hash_mismatch_rejected() {
    use poker_l1::offline::ack_chain::AckEntry;
    use poker_l1::offline::state::{CheckinTx, LastPartialFold, execute_checkin};
    use poker_l1::offline::zk_verifier::{ProofKind, ZkVerifierRegistry, ZkVerifyContext};
    use poker_l1::signature::TaggedPubkey;

    let registry = ZkVerifierRegistry::new();

    let make_ack = |seq: u64| AckEntry {
        chain_id: DEFAULT_CHAIN_ID,
        epoch: 1,
        game_id: poker_l1::object_model::ObjectID::new([0x01; 20], 1),
        current_turn: [0x02; 20],
        state_hash: [0x42; 32],
        checkpoint_seq: seq,
        participant: TaggedPubkey {
            tag: 0x01,
            raw: vec![0xAA; 33],
        },
        participant_signature: vec![0xBB; 64],
    };

    let ack_chain = vec![make_ack(1), make_ack(2)];

    let tx = CheckinTx {
        game_id: poker_l1::object_model::ObjectID::new([0x01; 20], 1),
        proof: vec![0xAA; 64],
        state_delta: vec![0xBB; 32],
        new_commitment: [0xCC; 32],
        ack_chain,
        scheme_id: 1,
        proof_kind: ProofKind::Zkvm,
        has_partial_checkin: true,
        folded_step_count: 1,
        skip_count: 0,
        segment_continuity_proof: Vec::new(),
    };

    // last_partial_fold 的 ack_chain_partial_hash 故意不匹配
    let last_partial_fold = LastPartialFold {
        intermediate_commitment: [0xDD; 32],
        folded_step_count: 2,
        proof_partial_hash: [0xEE; 32],
        ack_chain_partial_hash: [0xFF; 32], // 故意错误
    };

    let ctx = ZkVerifyContext {
        current_height: 0,
        production_switch_height: 0,
        grace_blocks: 0,
        last_partial_proof_hash: None,
        uses_new_signature: true,
    };

    let result = execute_checkin(
        &tx,
        &registry,
        DEFAULT_CHAIN_ID,
        Some(&last_partial_fold),
        3,
        1000,
        &ctx,
        [0xDD; 32],
    );

    assert!(
        matches!(result, Err(PokerL1Error::PartialCheckinMismatch(_))),
        "ack_chain_partial_hash 不匹配应返回 PartialCheckinMismatch, got: {result:?}"
    );
}

/// H5：v2 已删除 Hypernova，原 Fr 非规范化字节检查不再适用。
///
/// v2 改用 Stwo M31 field（原生 31-bit），由 StwoProver/Verifier AIR 自行保证字段范围。
/// 此测试已废弃，相关 soundness 检查将由 Phase 5 Stwo Verifier AIR 测试覆盖。

/// H7：tx_cache FIFO 淘汰 — 超限时最旧条目应被淘汰。
///
/// 攻击者持续广播 tx 使 tx_cache 无限增长，FIFO 淘汰保证内存有界。
#[test]
fn test_p0_tx_cache_bounded_eviction() {
    use poker_l1::network::GossipManager;
    use poker_l1::transaction::{Gas, RouteHint, Transaction, TxLane};

    let manager = GossipManager::with_max_tx_cache_size(5);

    // 插入 7 条 tx（超过上限 5）
    let mut hashes = Vec::new();
    for i in 1..=7u64 {
        let tx = Transaction {
            inputs: vec![],
            outputs: vec![],
            contract_call: None,
            tagged_pubkey: make_tagged_pubkey_secp(0x02),
            signature: vec![0u8; 65],
            gas: Gas::default(),
            lane_hint: TxLane::Public,
            route_hint: RouteHint::default(),
            chain_id: DEFAULT_CHAIN_ID,
            nonce: i,
            gameturn_nonce: None,
            is_fallback: false,
        };
        let h = tx.tx_hash();
        hashes.push(h);
        manager.receive_tx(tx).unwrap();
    }

    // 缓存应被限制在 5 条
    assert_eq!(manager.tx_cache_len(), 5, "tx_cache 应被淘汰至 max=5");

    // 最旧 2 条应已被淘汰
    assert!(!manager.tx_cache_contains(&hashes[0]), "tx[0] 应被淘汰");
    assert!(!manager.tx_cache_contains(&hashes[1]), "tx[1] 应被淘汰");
    // 最新 5 条应保留
    for i in 2..7 {
        assert!(manager.tx_cache_contains(&hashes[i]), "tx[{i}] 应保留");
    }
}
