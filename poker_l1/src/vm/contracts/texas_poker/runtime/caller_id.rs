//! 调用方寻址与（历史）确定性身份——stark curve。
//!
//! **P1-2 会话委托（2026-09-10）后的定位**：
//! - **寻址**（现行）：[`wallet_to_address`] 给出钱包的稳定 VM 20 字节
//!   地址——座位身份与交易消息的 caller 绑定都只用这一层派生；
//! - **授权**（已移交）：交易签名按**座位登记的会话公钥**验证
//!   （`OccupiedSeat.tx_pk`，join 时经链上 vault `set_session_tx_pk[_for]`
//!   核验），见 [`super::table_runtime`]。确定性身份密钥
//!   （`identity_sk`/`identity_pk`，公式与客户端
//!   `ClientPlayer::new_with_wallet_address` 同源）**公开可计算**，不再
//!   充当任何验签锚，仅保留给离线测试与 `CallerIdentity` 的 unsigned
//!   上下文填充。

use poker_protocol::crypto::curve::CurvePoint;
use poker_protocol::crypto::types::{EcPoint, Scalar, base_g, hash_to_scalar};

use crate::Address;
use crate::error::{PokerL1Error, PokerL1Result};
use crate::signature::stark_scheme;
use crate::signature::tagged_pubkey::{SignatureScheme, TaggedPubkey};

/// 钱包 felt hex → VM 20 字节地址。
///
/// 与 texas 侧 `TableMirror::addr_from_starknet` 同公式：解析 32 字节
/// felt，取低 20 字节（`bytes_be[12..32]`）。这是两个实现共享的权威
/// 公式；修改任何一侧必须同步另一侧（texas e2e 有等价性断言）。
pub fn wallet_to_address(felt_hex: &str) -> PokerL1Result<Address> {
    let hex = felt_hex
        .strip_prefix("0x")
        .or_else(|| felt_hex.strip_prefix("0X"))
        .unwrap_or(felt_hex);
    if hex.is_empty() || hex.len() > 64 {
        return Err(PokerL1Error::Serialization(format!(
            "wallet felt hex malformed: {felt_hex}"
        )));
    }
    // felt hex 允许奇数长度（前导零省略）；左补一个 nibble 对齐字节。
    let padded = if !hex.len().is_multiple_of(2) {
        format!("0{hex}")
    } else {
        hex.to_string()
    };
    let mut decoded = [0u8; 32];
    let raw = hex::decode(&padded)
        .map_err(|e| PokerL1Error::Serialization(format!("wallet felt hex decode: {e}")))?;
    if raw.len() > 32 {
        return Err(PokerL1Error::Serialization(format!(
            "wallet felt exceeds 32 bytes: {felt_hex}"
        )));
    }
    decoded[32 - raw.len()..].copy_from_slice(&raw);
    Ok(decoded[12..32].try_into().expect("20 bytes"))
}

/// 身份私钥：`hash_to_scalar(wallet.as_bytes())`。
///
/// 与 `ClientPlayer::new_with_wallet_address`（client.rs）逐字节同源——
/// 客户端、服务端、链运行时对同一钱包派生出同一密钥。
#[must_use]
pub fn identity_sk(felt_hex: &str) -> Scalar {
    hash_to_scalar(felt_hex.as_bytes())
}

/// 身份公钥：`base_g() * identity_sk(wallet)`。
#[must_use]
pub fn identity_pk(felt_hex: &str) -> EcPoint {
    base_g() * identity_sk(felt_hex)
}

/// 身份公钥的 tagged 编码（Stark scheme，raw = 32B 压缩点）。
#[must_use]
pub fn identity_tagged_pk(felt_hex: &str) -> TaggedPubkey {
    let raw = identity_pk(felt_hex).compress().as_ref().to_vec();
    TaggedPubkey::new(
        SignatureScheme::Stark,
        crate::signature::CURRENT_VERSION,
        raw,
    )
    .expect("compressed stark point is 32 bytes")
}

/// 以钱包的确定性身份签名（Stark Schnorr，确定性 nonce）。
/// 消息哈希构造见 [`super::dispatch::tx_message_hash`]。
#[must_use]
pub fn sign(felt_hex: &str, msg_hash: &[u8; 32]) -> [u8; stark_scheme::SIGNATURE_LEN] {
    stark_scheme::sign(&identity_sk(felt_hex), msg_hash)
}

/// 用钱包的确定性身份公钥验签（等价于 `verify_signature` 的 Stark 路由）。
pub fn verify(felt_hex: &str, msg_hash: &[u8; 32], sig: &[u8]) -> PokerL1Result<()> {
    stark_scheme::verify_point(&identity_pk(felt_hex), msg_hash, sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    const WALLET_A: &str = "0x6e37d33462f7319261396d7d7f669d147e40cdef91c6a8305cfde771805c782";
    const WALLET_B: &str = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

    #[test]
    fn identity_derivation_is_deterministic() {
        assert_eq!(identity_sk(WALLET_A), identity_sk(WALLET_A));
        assert_ne!(identity_sk(WALLET_A), identity_sk(WALLET_B));
        // 与 ClientPlayer::new_with_wallet_address 同公式：
        // sk = hash_to_scalar(wallet.as_bytes())。
        assert_eq!(
            identity_sk(WALLET_A).to_bytes_be(),
            hash_to_scalar(WALLET_A.as_bytes()).to_bytes_be()
        );
        let pk = identity_pk(WALLET_A);
        assert_eq!(pk, base_g() * identity_sk(WALLET_A));
        assert!(!pk.is_identity());
    }

    #[test]
    fn tagged_pk_roundtrip_via_compressed() {
        let tp = identity_tagged_pk(WALLET_A);
        assert_eq!(tp.scheme().unwrap(), SignatureScheme::Stark);
        assert_eq!(tp.raw.len(), SignatureScheme::Stark.raw_pubkey_len());
        let pk = EcPoint::from_compressed(&tp.raw).unwrap();
        assert_eq!(pk, identity_pk(WALLET_A));
    }

    #[test]
    fn wallet_address_takes_low_20_bytes() {
        let addr = wallet_to_address(WALLET_A).unwrap();
        // 手工对拍：felt bytes_be[12..32]（WALLET_A 是 63 位 hex，左补零对齐）
        let hex = WALLET_A.strip_prefix("0x").unwrap();
        let padded = format!("0{hex}");
        let decoded = hex::decode(&padded).unwrap();
        let expected: [u8; 20] = decoded[12..32].try_into().unwrap();
        assert_eq!(addr, expected);
    }

    #[test]
    fn wallet_address_rejects_malformed_hex() {
        assert!(wallet_to_address("0x").is_err());
        assert!(wallet_to_address("").is_err());
        assert!(wallet_to_address("not-hex!").is_err());
        // 超过 32 字节的 felt 拒绝
        assert!(wallet_to_address(&format!("0x{}", "ab".repeat(33))).is_err());
        // 奇数长度（前导零省略）与无 0x 前缀均可解析
        assert!(wallet_to_address("0xabc").is_ok());
        assert_eq!(
            wallet_to_address(WALLET_A.strip_prefix("0x").unwrap()).unwrap(),
            wallet_to_address(WALLET_A).unwrap()
        );
    }

    #[test]
    fn sign_verify_roundtrip_and_cross_wallet_rejected() {
        let msg = [0x42u8; 32];
        let sig = sign(WALLET_A, &msg);
        assert_eq!(sig.len(), stark_scheme::SIGNATURE_LEN);
        verify(WALLET_A, &msg, &sig).expect("own signature verifies");
        // WALLET_B 的签名不能通过 WALLET_A 的公钥验证（身份绑定）。
        let sig_b = sign(WALLET_B, &msg);
        assert!(verify(WALLET_A, &msg, &sig_b).is_err());
        // 篡改消息后验不过
        let mut other = msg;
        other[31] ^= 1;
        assert!(verify(WALLET_A, &other, &sig).is_err());
    }
}
