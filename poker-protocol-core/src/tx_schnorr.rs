//! VM 交易 Schnorr 签名核心（P1-2 会话委托，scheme_id = 2，单一权威）。
//!
//! 2026-09-10 起 poker_l1 `signature::stark_scheme` 与 client-wasm
//! `WasmTxSession` 的签名核心收敛到本模块——此前两侧各自持有一份
//! "必须逐字节同步"的拷贝（域常量 + schnorr_challenge + sign），现为
//! 同一实现的自证（两侧 KAT 携带同一向量）。
//!
//! 字节布局（冻结，勿动）：
//!
//! - 公钥编码 = StarkPoint 32B 压缩点（`CurvePoint::compress`）
//! - 签名 = `R_compressed(32B) ‖ s_be(32B)`，共 64B
//! - 确定性 nonce：`r = H("zchain.schnorr.nonce.v1" ‖ sk ‖ msg_hash)`
//! - 挑战：`e = H("zchain.schnorr.v1" ‖ R ‖ pk ‖ msg_hash)`，`s = r + e·sk`
//!
//! 验签方程：`base_g()·s − pk·e == R`（拒绝：长度错误、s 非规范（≥ 群阶）、
//! R/pk 非法编码或恒等元、方程不成立——验签外壳在 poker_l1，错误类型
//! 属于其 error 模块）。
//!
//! 注意：本方案配套的调用方身份是**公开可派生**的——签名是完整性层
//! （消息/nonce 承诺 + 重放锚），不是钱包持有证明。

use crate::curve::{Curve, CurvePoint, CurveScalar};
use crate::stark_curve::{StarkCurve, StarkPoint, StarkScalar};

/// Schnorr 挑战域分隔（e = H(domain ‖ R ‖ pk ‖ msg)）。
pub const SCHNORR_CHALLENGE_DOMAIN: &[u8] = b"zchain.schnorr.v1";

/// 确定性 nonce 域分隔（r = H(domain ‖ sk ‖ msg)，可复现、无 RNG 依赖）。
pub const SCHNORR_NONCE_DOMAIN: &[u8] = b"zchain.schnorr.nonce.v1";

/// 签名字节长度：R 压缩(32B) ‖ s 大端(32B)。
pub const SIGNATURE_LEN: usize = 64;

/// Schnorr 挑战标量：`H(domain ‖ R ‖ pk ‖ msg_hash)`。
pub fn schnorr_challenge(big_r: &StarkPoint, pk: &StarkPoint, msg_hash: &[u8; 32]) -> StarkScalar {
    let mut buf = Vec::with_capacity(SCHNORR_CHALLENGE_DOMAIN.len() + 32 * 3);
    buf.extend_from_slice(SCHNORR_CHALLENGE_DOMAIN);
    buf.extend_from_slice(big_r.compress().as_ref());
    buf.extend_from_slice(pk.compress().as_ref());
    buf.extend_from_slice(msg_hash);
    StarkCurve::hash_to_scalar(&buf)
}

/// 签名（确定性 nonce）：
///
/// - `r = H(nonce_domain ‖ sk ‖ msg_hash)`（可复现，测试与重放友好）
/// - `R = base_g() · r`，`e = H(challenge_domain ‖ R ‖ pk ‖ msg_hash)`
/// - `s = r + e · sk`
///
/// 返回 `R_compressed(32B) ‖ s_be(32B)`。
#[must_use]
pub fn sign(sk: &StarkScalar, msg_hash: &[u8; 32]) -> [u8; SIGNATURE_LEN] {
    let pk = StarkCurve::base_g() * *sk;
    let mut nonce_input = Vec::with_capacity(SCHNORR_NONCE_DOMAIN.len() + 32 + 32);
    nonce_input.extend_from_slice(SCHNORR_NONCE_DOMAIN);
    nonce_input.extend_from_slice(&CurveScalar::as_bytes(sk));
    nonce_input.extend_from_slice(msg_hash);
    let r = StarkCurve::hash_to_scalar(&nonce_input);

    let big_r = StarkCurve::base_g() * r;
    let e = schnorr_challenge(&big_r, &pk, msg_hash);
    let s = r + e * *sk;

    let mut out = [0u8; SIGNATURE_LEN];
    out[..32].copy_from_slice(big_r.compress().as_ref());
    out[32..].copy_from_slice(&s.to_bytes_be());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 跨 crate 已知答案向量（P2-2，同一向量三处自证：本模块、poker_l1
    /// `schnorr_known_answer_vector`、client-wasm
    /// `tx_session_known_answer_vector_matches_poker_l1`）。
    /// sk = hash_to_scalar(b"zgame.tx-vector.kat.v1")。
    #[test]
    fn schnorr_known_answer_vector() {
        let sk = StarkCurve::hash_to_scalar(b"zgame.tx-vector.kat.v1");
        let msg = [0x42u8; 32];
        let sig = sign(&sk, &msg);
        assert_eq!(
            hex::encode(sig),
            "80e93d41175f69487f916da094a1cacb0d2b1dfc0c4c5caa386c7263ca78a09e007bfd2b92bf6112390243cc66f4b77fdfd71c03021a1d33c9ccae0543200c42",
            "KAT mismatch — tx_schnorr signature space drifted"
        );
        let pk = StarkCurve::base_g() * sk;
        assert_eq!(
            hex::encode(pk.compress().as_ref()),
            "82496bd9c700a1c1252d27b5b8063bdeab149411436157dc3dfe1dd29c79faa3",
            "KAT pk mismatch — derivation drifted"
        );
        // 验签方程自检：base_g·s − pk·e == R。
        let big_r = <StarkPoint as CurvePoint>::from_compressed(&sig[..32]).expect("R decodes");
        let s = <StarkScalar as CurveScalar>::from_canonical_bytes(&sig[32..]).expect("s canonical");
        let e = schnorr_challenge(&big_r, &pk, &msg);
        assert_eq!(StarkCurve::base_g() * s - pk * e, big_r);
    }

    /// 确定性 nonce：同 sk 同消息必得同签名；不同消息不同签名。
    #[test]
    fn deterministic_nonce_reproduces_signature() {
        let sk = StarkCurve::hash_to_scalar(b"determinism-probe");
        let msg = [0x42u8; 32];
        assert_eq!(sign(&sk, &msg), sign(&sk, &msg));
        assert_ne!(sign(&sk, &msg), sign(&sk, &[0x43u8; 32]));
        assert_eq!(sign(&sk, &msg).len(), SIGNATURE_LEN);
    }
}
