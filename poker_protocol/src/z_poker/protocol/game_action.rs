//! #16 抗审查动作签名（`ACTION_SIGNING_CENSORSHIP_RESISTANCE.md` §2）。
//!
//! 玩家以**牌局身份 SK**（Part B 随机密钥，与钱包零派生，Stark curve）
//! 对动作签名：
//!
//! ```text
//! msg  = "zgame.action-sig.v1" || table_id(u32 BE) || seq(u64 BE)
//!      || len(action)(u32 BE) || action || amount(u64 BE)
//! r    = w·G
//! c    = H_stark(msg || r_compressed)          -- StarkCurve::hash_to_scalar
//! s    = w + c·sk
//! ```
//! 验证：`s·G == r + c·pk`（pk = 座位牌局公钥，SIT_DOWN 时已绑定；本项目
//! 全链路为 Stark curve，与 DAPV 认可/`hand_batch_stark` 同域同式）。
//!
//! 域分离：常量域名 + 定长编码 + 动作名长度前缀；`amount` 仅 raise 非零。
//! 防重放：seq 由客户端按桌持久单调递增（服务端校验严格递增）。
//! 本项目全部使用 Stark curve；legacy-bls381 仅为参考实现，不在此处出现。

use poker_protocol_core::curve::{Curve, CurvePoint, CurveScalar};
use poker_protocol_core::StarkCurve;
use rand_core::{CryptoRng, RngCore};

pub const ACTION_SIG_DOMAIN: &[u8] = b"zgame.action-sig.v1";

/// 规范化动作消息字节（客户端 / 服务端 / 测试三方共用的唯一口径）。
pub fn action_msg_bytes(table_id: u32, seq: u64, action: &str, amount: u64) -> Vec<u8> {
    let mut m = Vec::with_capacity(ACTION_SIG_DOMAIN.len() + 24 + action.len());
    m.extend_from_slice(ACTION_SIG_DOMAIN);
    m.extend_from_slice(&table_id.to_be_bytes());
    m.extend_from_slice(&seq.to_be_bytes());
    m.extend_from_slice(&(action.len() as u32).to_be_bytes());
    m.extend_from_slice(action.as_bytes());
    m.extend_from_slice(&amount.to_be_bytes());
    m
}

/// 曲线泛型签名核心（`w` 注入便于确定性测试；对外入口固定 StarkCurve）。
pub fn sign_game_action_generic<C: Curve>(
    sk: &C::Scalar,
    table_id: u32,
    seq: u64,
    action: &str,
    amount: u64,
    nonce: &C::Scalar,
) -> (C::Point, C::Scalar) {
    let msg = action_msg_bytes(table_id, seq, action, amount);
    let g = C::base_g();
    let r = g * *nonce;
    let mut challenge_input = msg.clone();
    challenge_input.extend_from_slice(r.compress().as_ref());
    let c = C::hash_to_scalar(&challenge_input);
    let s = *nonce + c * *sk;
    (r, s)
}

/// 曲线泛型验证核心（与签名核心同式重算挑战）。
pub fn verify_game_action_generic<C: Curve>(
    pk: &C::Point,
    table_id: u32,
    seq: u64,
    action: &str,
    amount: u64,
    r: &C::Point,
    s: &C::Scalar,
) -> bool {
    if r.is_identity() {
        return false;
    }
    let msg = action_msg_bytes(table_id, seq, action, amount);
    let mut challenge_input = msg.clone();
    challenge_input.extend_from_slice(r.compress().as_ref());
    let c = C::hash_to_scalar(&challenge_input);
    let g = C::base_g();
    let lhs = g * s;
    let rhs = *r + *pk * c;
    lhs == rhs
}

fn stark_scalar_from_hex(hex_str: &str) -> Option<<StarkCurve as Curve>::Scalar> {
    let bytes = hex::decode(hex_str).ok()?;
    <StarkCurve as Curve>::Scalar::from_canonical_bytes(&bytes)
}

fn stark_point_from_hex(hex_str: &str) -> Option<<StarkCurve as Curve>::Point> {
    let bytes = hex::decode(hex_str).ok()?;
    <StarkCurve as Curve>::Point::from_compressed(&bytes)
}

fn stark_point_to_hex(p: &<StarkCurve as Curve>::Point) -> String {
    hex::encode(p.compress().as_ref())
}

fn stark_scalar_to_hex(s: &<StarkCurve as Curve>::Scalar) -> String {
    hex::encode(<StarkCurve as Curve>::Scalar::as_bytes(s))
}

/// 对外（StarkCurve）签名：返回 `(r_compressed_hex, s_hex)`。
/// sk 由调用方（client-wasm / dev_bot / 测试）从游戏身份存储反序列化。
pub fn sign_game_action(
    sk: &<StarkCurve as Curve>::Scalar,
    table_id: u32,
    seq: u64,
    action: &str,
    amount: u64,
    rng: &mut (impl RngCore + CryptoRng),
) -> (String, String) {
    loop {
        let nonce = <StarkCurve as Curve>::Scalar::random(rng);
        if nonce == <StarkCurve as Curve>::Scalar::zero() {
            continue;
        }
        let (r, s_val) =
            sign_game_action_generic::<StarkCurve>(sk, table_id, seq, action, amount, &nonce);
        if s_val == <StarkCurve as Curve>::Scalar::zero() || r.is_identity() {
            continue;
        }
        return (stark_point_to_hex(&r), stark_scalar_to_hex(&s_val));
    }
}

/// 对外（StarkCurve）验证（hex 入参：pk 为座位牌局公钥压缩编码，
/// r/s 为 sign_game_action 的返回值——服务端与 wasm/客户端同一编码）。
pub fn verify_game_action_hex(
    pk_hex: &str,
    table_id: u32,
    seq: u64,
    action: &str,
    amount: u64,
    r_hex: &str,
    s_hex: &str,
) -> bool {
    let (Some(pk), Some(r), Some(s)) = (
        stark_point_from_hex(pk_hex),
        stark_point_from_hex(r_hex),
        stark_scalar_from_hex(s_hex),
    ) else {
        return false;
    };
    verify_game_action_generic::<StarkCurve>(&pk, table_id, seq, action, amount, &r, &s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn sample_sk() -> <StarkCurve as Curve>::Scalar {
        StarkCurve::hash_to_scalar(b"test-sk-seed")
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let sk = sample_sk();
        let pk = StarkCurve::base_g() * sk;
        let nonce = <StarkCurve as Curve>::Scalar::random(&mut OsRng);
        let (r, s) = sign_game_action_generic::<StarkCurve>(&sk, 7, 5, "raise", 320, &nonce);
        assert!(verify_game_action_generic::<StarkCurve>(
            &pk, 7, 5, "raise", 320, &r, &s
        ));
    }

    #[test]
    fn tampered_fields_rejected() {
        let sk = sample_sk();
        let pk = StarkCurve::base_g() * sk;
        let nonce = <StarkCurve as Curve>::Scalar::random(&mut OsRng);
        let (r, s) = sign_game_action_generic::<StarkCurve>(&sk, 7, 5, "raise", 320, &nonce);
        assert!(!verify_game_action_generic::<StarkCurve>(
            &pk, 7, 6, "raise", 320, &r, &s
        ));
        assert!(!verify_game_action_generic::<StarkCurve>(
            &pk, 7, 5, "fold", 320, &r, &s
        ));
        assert!(!verify_game_action_generic::<StarkCurve>(
            &pk, 7, 5, "raise", 321, &r, &s
        ));
        let other_pk = StarkCurve::base_g() * StarkCurve::hash_to_scalar(b"other-sk");
        assert!(!verify_game_action_generic::<StarkCurve>(
            &other_pk, 7, 5, "raise", 320, &r, &s
        ));
    }

    #[test]
    fn different_tables_dont_share_signatures() {
        let sk = sample_sk();
        let pk = StarkCurve::base_g() * sk;
        let nonce = <StarkCurve as Curve>::Scalar::random(&mut OsRng);
        let (r, s) = sign_game_action_generic::<StarkCurve>(&sk, 1, 5, "call", 0, &nonce);
        assert!(!verify_game_action_generic::<StarkCurve>(
            &pk, 2, 5, "call", 0, &r, &s
        ));
    }

    #[test]
    fn hex_helpers_roundtrip() {
        let sk = sample_sk();
        let pk = StarkCurve::base_g() * sk;
        let pk_hex = stark_point_to_hex(&pk);
        let (r_hex, s_hex) = sign_game_action(&sk, 3, 11, "check", 0, &mut OsRng);
        assert!(verify_game_action_hex(&pk_hex, 3, 11, "check", 0, &r_hex, &s_hex));
        assert!(!verify_game_action_hex(&pk_hex, 3, 12, "check", 0, &r_hex, &s_hex));
    }
}
