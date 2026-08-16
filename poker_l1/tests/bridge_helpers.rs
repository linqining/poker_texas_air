//! Bridge 测试辅助函数（供 phase6_integration.rs 共享）。
//!
//! 从 `src/bridge/mod.rs` 测试代码中提取，避免在集成测试中重复实现。

use poker_l1::DEFAULT_CHAIN_ID;
use poker_l1::account::derive_address;
use poker_l1::bridge::{BridgeDeposit, BridgeValidatorSig, BridgeVerifyTx};
use poker_l1::signature::{CURRENT_VERSION, SignatureScheme, TaggedPubkey};
use secp256k1::Secp256k1;
use secp256k1::rand::rngs::OsRng;

/// 生成真实的 secp256k1 密钥对（用于桥测试）。
///
/// 返回 `(secret_key, public_key, tagged_pubkey)`，其中 `tagged_pubkey.raw`
/// 为 33 字节 compressed pubkey（与 `secp256k1_scheme::verify` 期望一致）。
pub fn make_real_keypair() -> (secp256k1::SecretKey, secp256k1::PublicKey, TaggedPubkey) {
    let secp = Secp256k1::new();
    let mut rng = OsRng;
    let (secret_key, public_key) = secp.generate_keypair(&mut rng);
    let compressed = public_key.serialize();
    let tagged = TaggedPubkey::new(
        SignatureScheme::Secp256k1,
        CURRENT_VERSION,
        compressed.to_vec(),
    )
    .expect("构造 tagged pubkey 不应失败");
    (secret_key, public_key, tagged)
}

/// 构造结构合法的 `BridgeVerifyTx`（签名占位为 65 字节零，调用方可覆盖）。
///
/// # 字段说明
///
/// - `deposit.recipient` 从传入的 `recipient` tagged pubkey 派生
/// - `deposit.dest_chain_id` = `DEFAULT_CHAIN_ID`
/// - `validator_signatures` 含 1 个占位签名（结构合法，签名无效）
/// - `recipient_sig` = 65 字节零（占位）
/// - `preferred_relayer` = None
pub fn make_valid_bridge_verify_tx(recipient: &TaggedPubkey) -> BridgeVerifyTx {
    let recipient_addr = derive_address(recipient);
    let deposit = BridgeDeposit {
        nonce: 1,
        source_chain_id: 0xAAAA,
        dest_chain_id: DEFAULT_CHAIN_ID,
        asset: [0xAB; 32],
        amount: 1000,
        recipient: recipient_addr,
        source_tx_hash: [0xCD; 32],
    };

    // 占位 validator（结构合法的 tagged pubkey）
    let mut raw = vec![0x10u8];
    raw.extend_from_slice(&[0x02u8; 32]);
    let validator = TaggedPubkey::new(SignatureScheme::Secp256k1, CURRENT_VERSION, raw)
        .expect("构造占位 validator 不应失败");

    BridgeVerifyTx {
        deposit,
        validator_signatures: vec![BridgeValidatorSig {
            validator,
            signature: vec![0u8; 65],
        }],
        recipient_sig: vec![0u8; 65],
        recipient_pubkey: recipient.clone(),
        preferred_relayer: None,
    }
}
