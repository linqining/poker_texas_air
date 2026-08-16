//! poker_l1 形式化属性测试 — proptest 不变量验证。
//!
//! 参考 poker_zkvm `tests/formal_properties.rs` 模式，覆盖 5 类核心不变量：
//! 1. SMT — 插入/证明/验证往返、顺序无关性、删除恢复、篡改失败
//! 2. 签名 — secp256k1 / ed25519 签名验证往返
//! 3. 地址派生 — 确定性、跨 scheme 差异
//! 4. 序列化 — Transaction / TaggedPubkey BCS 往返
//! 5. 哈希 — AckEntry 哈希确定性、blake2b 域分隔

mod common;

use common::{make_real_ed25519_keypair, make_real_secp_keypair, make_tx};
use poker_l1::account::derive_address;
use poker_l1::object_model::{SparseMerkleTree, internal_hash, leaf_hash};
use poker_l1::offline::ack_chain::AckEntry;
use poker_l1::signature::tagged_pubkey::encode_tag;
use poker_l1::signature::unified::verify_signature;
use poker_l1::signature::{SignatureScheme, TaggedPubkey};
use poker_l1::transaction::TxLane;
use poker_l1::{DEFAULT_CHAIN_ID, Hash, object_model::ObjectID};

use ed25519_dalek::Signer;
use proptest::prelude::*;
use secp256k1::Message;

// ===========================================================================
// 辅助函数
// ===========================================================================

/// 构造 AckEntry（用于 ack_hash 确定性测试）。
fn make_ack_entry(epoch: u64, checkpoint_seq: u64) -> AckEntry {
    AckEntry {
        chain_id: DEFAULT_CHAIN_ID,
        epoch,
        game_id: ObjectID::new([0xAB; 20], 0),
        current_turn: [0x01; 20],
        state_hash: [0xCD; 32],
        checkpoint_seq,
        participant: common::make_tagged_pubkey_secp(0x42),
        participant_signature: vec![0u8; 65],
    }
}

/// 生成任意 32 字节数组策略。
fn hash_strategy() -> impl Strategy<Value = Hash> {
    prop::array::uniform32(0u8..255)
}

// ===========================================================================
// 1. SMT — 4 个属性
// ===========================================================================

proptest! {
    /// 属性 1：upsert → prove → verify 必须闭环成功（任意 key/value）。
    #[test]
    fn prop_smt_insert_prove_verify_roundtrip(
        key in hash_strategy(),
        value in prop::collection::vec(0u8..255, 0..256)
    ) {
        let mut t = SparseMerkleTree::new();
        t.upsert(key, &value);
        let path = t.prove(&key);
        prop_assert!(
            SparseMerkleTree::verify(&t.root(), &key, Some(&value), &path),
            "upsert→prove→verify 闭环必须成功"
        );
    }

    /// 属性 2：插入顺序无关 — 正向/反向/乱序构建得到相同 root（key 唯一）。
    #[test]
    fn prop_smt_insertion_order_independence(
        entries in prop::collection::vec(
            (hash_strategy(), prop::collection::vec(0u8..255, 1..64)),
            1..32
        ).prop_flat_map(|mut v| {
            // 去重 key
            v.sort_by_key(|(k, _)| *k);
            v.dedup_by_key(|(k, _)| *k);
            Just(v)
        })
    ) {
        if entries.is_empty() {
            return Ok(());
        }

        let mut t_forward = SparseMerkleTree::new();
        let mut t_reverse = SparseMerkleTree::new();
        let mut t_sorted = SparseMerkleTree::new();

        for (k, v) in &entries {
            t_forward.upsert(*k, v);
        }
        for (k, v) in entries.iter().rev() {
            t_reverse.upsert(*k, v);
        }
        let mut sorted = entries.clone();
        sorted.sort_by_key(|(k, _)| *k);
        for (k, v) in &sorted {
            t_sorted.upsert(*k, v);
        }

        prop_assert_eq!(t_forward.root(), t_reverse.root(), "正向/反向 root 必须相同");
        prop_assert_eq!(t_forward.root(), t_sorted.root(), "正向/排序 root 必须相同");
    }

    /// 属性 3：insert + delete 后 root 必须恢复为 empty_root。
    #[test]
    fn prop_smt_delete_restores_empty_root(
        key in hash_strategy(),
        value in prop::collection::vec(0u8..255, 0..256)
    ) {
        let empty_root = SparseMerkleTree::new().root();

        let mut t = SparseMerkleTree::new();
        t.upsert(key, &value);
        t.remove(&key);

        prop_assert_eq!(t.root(), empty_root, "insert+delete 后 root 必须恢复为 empty_root");
    }

    /// 属性 4：篡改 value 后 verify 必须失败。
    #[test]
    fn prop_smt_tampered_value_fails(
        key in hash_strategy(),
        value in prop::collection::vec(0u8..255, 1..256),
        tamper_byte in 0u8..255
    ) {
        let mut t = SparseMerkleTree::new();
        t.upsert(key, &value);
        let path = t.prove(&key);

        // 篡改 value 首字节
        let mut tampered = value.clone();
        tampered[0] = tampered[0].wrapping_add(tamper_byte).wrapping_add(1);

        prop_assert!(
            !SparseMerkleTree::verify(&t.root(), &key, Some(&tampered), &path),
            "篡改 value 后 verify 必须失败"
        );
    }
}

// ===========================================================================
// 2. 签名 — 2 个属性
// ===========================================================================

proptest! {
    /// 属性 5：secp256k1 sign → verify_signature 闭环成功（任意 msg_hash）。
    #[test]
    fn prop_sig_secp_sign_verify_roundtrip(msg_hash in hash_strategy()) {
        let (sk, _pk, tagged) = make_real_secp_keypair();
        let secp = secp256k1::Secp256k1::new();
        let msg = Message::from_digest(msg_hash);
        let sig = secp.sign_ecdsa_recoverable(&msg, &sk);
        let (recid, compact) = sig.serialize_compact();
        let mut sig_bytes = compact.to_vec();
        sig_bytes.push(recid.to_i32() as u8);

        prop_assert!(
            verify_signature(&tagged, &sig_bytes, &msg_hash).is_ok(),
            "secp256k1 sign→verify 必须成功"
        );
    }

    /// 属性 6：ed25519 sign → verify_signature 闭环成功（任意 msg_hash）。
    ///
    /// 注：verify_signature 内部调用 `vk.verify(msg_hash, &sig)`，
    /// 故签名对象必须是 msg_hash（32 字节），而非原始消息。
    #[test]
    fn prop_sig_ed25519_sign_verify_roundtrip(msg_hash in hash_strategy()) {
        let (sk, _vk, tagged) = make_real_ed25519_keypair();
        let sig = sk.sign(&msg_hash);
        let sig_bytes = sig.to_bytes().to_vec();

        prop_assert!(
            verify_signature(&tagged, &sig_bytes, &msg_hash).is_ok(),
            "ed25519 sign→verify 必须成功"
        );
    }
}

// ===========================================================================
// 3. 地址派生 — 2 个属性
// ===========================================================================

proptest! {
    /// 属性 7：同一 tagged pubkey 两次 derive_address 得到相同 Address（确定性）。
    #[test]
    fn prop_address_derivation_deterministic(byte in 0u8..255) {
        let tp = common::make_tagged_pubkey_secp(byte);
        let addr1 = derive_address(&tp);
        let addr2 = derive_address(&tp);
        prop_assert_eq!(addr1, addr2, "derive_address 必须确定性");
    }

    /// 属性 8：同 byte 但不同 scheme 的 tagged pubkey 派生不同地址。
    #[test]
    fn prop_address_different_schemes_differ(byte in 0u8..255) {
        let secp_tp = common::make_tagged_pubkey_secp(byte);
        let ed_tp = common::make_tagged_pubkey_ed25519(byte);
        let secp_addr = derive_address(&secp_tp);
        let ed_addr = derive_address(&ed_tp);
        prop_assert_ne!(
            secp_addr, ed_addr,
            "不同 scheme（tag 不同）应派生不同地址"
        );
    }
}

// ===========================================================================
// 4. 序列化往返 — 2 个属性
// ===========================================================================

proptest! {
    /// 属性 9：Transaction BCS 序列化/反序列化往返（任意 nonce / is_fallback）。
    #[test]
    fn prop_transaction_bcs_roundtrip(
        nonce in 0u64..100_000,
        is_fallback in proptest::bool::ANY
    ) {
        let tp = common::make_tagged_pubkey_secp(0x42);
        let tx = make_tx(tp, DEFAULT_CHAIN_ID, nonce, None, is_fallback, TxLane::Public);

        let bytes = borsh::to_vec(&tx).expect("BCS 序列化不应失败");
        let decoded: poker_l1::transaction::Transaction =
            borsh::from_slice(&bytes).expect("BCS 反序列化不应失败");

        prop_assert_eq!(tx, decoded, "BCS 往返必须得到原值");
    }

    /// 属性 10：TaggedPubkey to_bytes / from_bytes 往返（任意 scheme / fill）。
    ///
    /// 注：from_bytes 仅支持 CURRENT_VERSION（=1），故 version 固定为 1。
    #[test]
    fn prop_tagged_pubkey_encode_decode_roundtrip(
        scheme_byte in 0u8..2,
        fill_byte in 0u8..255
    ) {
        let scheme = if scheme_byte == 0 {
            SignatureScheme::Secp256k1
        } else {
            SignatureScheme::Ed25519
        };
        let raw_len = match scheme {
            SignatureScheme::Secp256k1 => 33,
            SignatureScheme::Ed25519 => 32,
        };
        let tp = TaggedPubkey {
            tag: encode_tag(scheme, poker_l1::signature::CURRENT_VERSION),
            raw: vec![fill_byte; raw_len],
        };

        let bytes = tp.to_bytes();
        let decoded = TaggedPubkey::from_bytes(&bytes).expect("from_bytes 不应失败");

        prop_assert_eq!(tp, decoded, "to_bytes/from_bytes 往返必须得到原值");
    }
}

// ===========================================================================
// 5. 哈希确定性 — 2 个属性
// ===========================================================================

proptest! {
    /// 属性 11：同一 AckEntry 两次 ack_hash() 得到相同 Hash（确定性）。
    #[test]
    fn prop_ack_chain_hash_deterministic(
        epoch in 0u64..100_000,
        checkpoint_seq in 0u64..100_000
    ) {
        let entry = make_ack_entry(epoch, checkpoint_seq);
        let hash1 = entry.ack_hash();
        let hash2 = entry.ack_hash();
        prop_assert_eq!(hash1, hash2, "ack_hash 必须确定性");
    }

    /// 属性 12：blake2b 域分隔 — leaf_hash（0x00 前缀）≠ internal_hash（0x01 前缀）。
    #[test]
    fn prop_blake2b_domain_separation(
        key in hash_strategy(),
        value in prop::collection::vec(0u8..255, 1..256)
    ) {
        let leaf = leaf_hash(&key, &value);
        let internal = internal_hash(&leaf, &leaf);
        prop_assert_ne!(
            leaf, internal,
            "leaf_hash（0x00 前缀）与 internal_hash（0x01 前缀）必须不同"
        );
    }
}
