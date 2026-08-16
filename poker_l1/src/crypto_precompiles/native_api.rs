//! 节点级 native API（Task 20 — SubTask 20.1 / 20.2）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）：
//! - **SubTask 20.1**：
//!   - `secp256k1_aggregate_verify` — DAG consensus 多签验证
//!   - `bls_verify` — 仅合约层 ZK 证明验证
//! - **SubTask 20.2**：复用 `poker_protocol::crypto::Bls12381Curve` 实现（G1 部分）+
//!   `blstrs` 直接调用（G2 / pairing 部分）

use crate::crypto_precompiles::bls::{self, G1_COMPRESSED_SIZE, G2_COMPRESSED_SIZE};
use crate::error::{PokerL1Error, PokerL1Result};
use crate::signature::{TaggedPubkey, verify_signature};

/// `secp256k1_aggregate_verify(pubkeys, msg_hashes, sigs)` — DAG consensus 多签验证。
///
/// 验证 N 个 secp256k1 签名：对每个 i，验证 `verify(pubkeys[i], msg_hashes[i], sigs[i])`。
/// 全部通过返回 `true`，任一失败返回 `false`。
///
/// 用于 DAG commit certificate 的 signer_bitmap + signature_list 多签验证。
///
/// # 参数
///
/// - `pubkeys`：N 个 tagged pubkey
/// - `msg_hashes`：N 个消息哈希（每个 32 字节）
/// - `sigs`：N 个签名字节（secp256k1 = 65B r||s||v）
pub fn secp256k1_aggregate_verify(
    pubkeys: &[TaggedPubkey],
    msg_hashes: &[&[u8; 32]],
    sigs: &[&[u8]],
) -> PokerL1Result<bool> {
    if pubkeys.len() != msg_hashes.len() || pubkeys.len() != sigs.len() {
        return Err(PokerL1Error::InvalidSyscallArgument(format!(
            "length mismatch: pubkeys={}, msg_hashes={}, sigs={}",
            pubkeys.len(),
            msg_hashes.len(),
            sigs.len()
        )));
    }

    for ((pk, msg_hash), sig) in pubkeys.iter().zip(msg_hashes.iter()).zip(sigs.iter()) {
        match verify_signature(pk, sig, msg_hash) {
            Ok(()) => continue,
            Err(PokerL1Error::InvalidSignature) | Err(PokerL1Error::InvalidSignatureLowS) => {
                return Ok(false);
            }
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

/// `bls_verify(pubkey_g2, signature_g1, msg)` — BLS 签名验证（仅合约层 ZK 证明验证）。
///
/// 验证 BLS 签名：`e(signature, g2) == e(hash_to_g1(msg), pubkey_g2)`。
///
/// 注意：spec 明确 BLS12-381 仅用于 ZK 证明验证，非共识签名。
/// 共识签名使用 secp256k1（见 `secp256k1_aggregate_verify`）。
///
/// # 参数
///
/// - `pubkey_g2`：签名者公钥（G2 compressed，96 字节）
/// - `signature_g1`：签名（G1 compressed，48 字节）
/// - `msg`：被签名的消息
pub fn bls_verify(pubkey_g2: &[u8], signature_g1: &[u8], msg: &[u8]) -> PokerL1Result<bool> {
    if pubkey_g2.len() != G2_COMPRESSED_SIZE {
        return Err(PokerL1Error::InvalidBlsPoint(format!(
            "pubkey_g2 size mismatch: {} != {}",
            pubkey_g2.len(),
            G2_COMPRESSED_SIZE
        )));
    }
    if signature_g1.len() != G1_COMPRESSED_SIZE {
        return Err(PokerL1Error::InvalidBlsPoint(format!(
            "signature_g1 size mismatch: {} != {}",
            signature_g1.len(),
            G1_COMPRESSED_SIZE
        )));
    }

    // H3 修复：拒绝 identity point（防止 e(O, G2) == e(H_m, O) == 1 伪造签名）
    if is_identity_g1(signature_g1) {
        return Err(PokerL1Error::InvalidBlsPoint(
            "signature_g1 is identity point (not a valid BLS signature)".to_string(),
        ));
    }
    if is_identity_g2(pubkey_g2) {
        return Err(PokerL1Error::InvalidBlsPoint(
            "pubkey_g2 is identity point (not a valid BLS pubkey)".to_string(),
        ));
    }

    // hash msg to G1（使用固定 DST）
    let h_m = bls::bls_hash_to_g1(msg)?;

    // G2 生成元
    let g2_gen = {
        use blstrs::G2Projective;
        use group::Group;
        let g = G2Projective::generator();
        let compressed = g.to_compressed();
        let mut arr = [0u8; G2_COMPRESSED_SIZE];
        arr.copy_from_slice(compressed.as_ref());
        arr
    };

    // pairing check: e(sig, g2_gen) == e(h_m, pubkey)
    // bls_pairing_check(a, b, c, d) 内部计算 e(a,b) * e(-c, d) == identity
    // 即 e(a,b) == e(c,d)，因此直接传 h_m（不预先取负）
    bls::bls_pairing_check(signature_g1, &g2_gen, &h_m, pubkey_g2)
}

/// 检查 G1 compressed bytes 是否为 identity point（H3 修复）。
///
/// BLS12-381 ZCash compressed 格式：首字节 bit7=compression, bit6=infinity。
/// identity point 首字节 = 0xc0，其余全零。
fn is_identity_g1(bytes: &[u8]) -> bool {
    bytes.len() == G1_COMPRESSED_SIZE && bytes[0] == 0xc0 && bytes[1..].iter().all(|&b| b == 0)
}

/// 检查 G2 compressed bytes 是否为 identity point（H3 修复）。
fn is_identity_g2(bytes: &[u8]) -> bool {
    bytes.len() == G2_COMPRESSED_SIZE && bytes[0] == 0xc0 && bytes[1..].iter().all(|&b| b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::tagged_pubkey::{SignatureScheme, encode_tag};

    fn make_tagged_pubkey(byte: u8) -> TaggedPubkey {
        TaggedPubkey {
            tag: encode_tag(SignatureScheme::Secp256k1, 1),
            raw: vec![byte; 33],
        }
    }

    #[test]
    fn test_secp256k1_aggregate_verify_length_mismatch() {
        let pubkeys = vec![make_tagged_pubkey(0x01)];
        let msg1: &[u8; 32] = &[0u8; 32];
        let msg2: &[u8; 32] = &[0u8; 32];
        let msgs: Vec<&[u8; 32]> = vec![msg1, msg2]; // 长度不匹配
        let sigs: Vec<&[u8]> = vec![&[0u8; 65]];
        let result = secp256k1_aggregate_verify(&pubkeys, &msgs, &sigs);
        assert!(result.is_err(), "长度不匹配应返回错误");
    }

    #[test]
    fn test_bls_verify_invalid_pubkey_length() {
        let bad_pubkey = [0u8; 95]; // 错误长度
        let sig = [0u8; G1_COMPRESSED_SIZE];
        let result = bls_verify(&bad_pubkey, &sig, b"msg");
        assert!(result.is_err(), "错误公钥长度应返回错误");
    }

    #[test]
    fn test_bls_verify_invalid_signature_length() {
        let pubkey = [0u8; G2_COMPRESSED_SIZE];
        let bad_sig = [0u8; 47]; // 错误长度
        let result = bls_verify(&pubkey, &bad_sig, b"msg");
        assert!(result.is_err(), "错误签名长度应返回错误");
    }
}
