//! #16 抗审查动作签名（`docs/design/ACTION_SIGNING_CENSORSHIP_RESISTANCE.md` §2）。
//!
//! 玩家以**牌局身份 SK**（Part B 随机密钥，与钱包零派生，Stark curve）
//! 对动作签名（endorsement 通道删除后的唯一参与背书来源）：
//!
//! ```text
//! c = poseidon_hash_many([label, table_id, hand_id, seq, action_felt,
//!                         amount, R_x, R_y]) mod n     -- felt 直通挑战
//! R = w·G；s = w + c·sk
//! ```
//! 验证：`s·G == R + c·pk`（pk = 座位牌局公钥，SIT_DOWN 时已绑定）。
//!
//! v3（2026-09-06）：挑战从 v2 字节域（poseidon_over_bytes(msg‖R)）升级为
//! **felt 定长域**——与 ownership/reveal 挑战同构（`ACTION_SIG_LABEL`
//! short-string felt、R 用仿射坐标、action 名 short-string felt），递归
//! 信封的 Cairo 验证器原生复刻（`recursion.cairo` action-sig kind），
//! 无字节级操作。v2 未上生产即被取代。
//!
//! 防重放：`(table_id, hand_id)` 域分离 + seq 单调（hand_id 在开局时由
//! `record_hand_start` 分配并进 HandStartData，签名/验证两侧同源）。
//! 本项目全部使用 Stark curve。

use poker_protocol_core::curve::{Curve, CurvePoint, CurveScalar};
use poker_protocol_core::stark_curve::action_sig_challenge;
use poker_protocol_core::StarkCurve;
use rand_core::{CryptoRng, RngCore};

use crate::z_poker::convert;

/// StarkCurve 签名核心（`w` 注入便于确定性测试）。
/// 方程：`s = w + c·sk`，`c = poseidon(label, table, hand, seq, action,
/// amount, R_x, R_y) mod n`。
pub fn sign_game_action_generic(
    sk: &<StarkCurve as Curve>::Scalar,
    table_id: u32,
    hand_id: u32,
    seq: u64,
    action: &str,
    amount: u64,
    nonce: &<StarkCurve as Curve>::Scalar,
) -> (<StarkCurve as Curve>::Point, <StarkCurve as Curve>::Scalar) {
    let g = StarkCurve::base_g();
    let r = g * *nonce;
    // 挑战（core 的 action_sig_challenge 与此处 felts 表同源同式）
    let c = {
        let (rx, ry) = r
            .to_affine_parts()
            .expect("nonce point not identity");
        action_sig_challenge(table_id, hand_id, seq, action, amount, rx, ry)
            .expect("action name must encode")
    };
    let s = *nonce + c * *sk;
    (r, s)
}

/// StarkCurve 验证核心（与签名核心同式重算挑战）。
pub fn verify_game_action_generic(
    pk: &<StarkCurve as Curve>::Point,
    table_id: u32,
    hand_id: u32,
    seq: u64,
    action: &str,
    amount: u64,
    r: &<StarkCurve as Curve>::Point,
    s: &<StarkCurve as Curve>::Scalar,
) -> bool {
    if r.is_identity() {
        return false;
    }
    let c = match r.to_affine_parts() {
        Some((rx, ry)) => {
            action_sig_challenge(table_id, hand_id, seq, action, amount, rx, ry)
        }
        None => None,
    };
    let Some(c) = c else { return false };
    let g = StarkCurve::base_g();
    let lhs = g * *s;
    let rhs = *r + *pk * c;
    lhs == rhs
}

// hex 编解码薄包装（2026-09-10 收敛）：单一权威在 z_poker::convert
// （曲线/标量 hex 家族的第三份拷贝在此删除；Option 语义保持——
// convert 的 Result<_, String> 经 .ok() 折叠，接受/拒绝行为不变）。
fn stark_scalar_from_hex(hex_str: &str) -> Option<<StarkCurve as Curve>::Scalar> {
    convert::hex_to_scalar(hex_str).ok()
}

fn stark_point_from_hex(hex_str: &str) -> Option<<StarkCurve as Curve>::Point> {
    convert::hex_to_curve_point::<StarkCurve>(hex_str).ok()
}

fn stark_point_to_hex(p: &<StarkCurve as Curve>::Point) -> String {
    convert::curve_point_to_hex::<StarkCurve>(p)
}

fn stark_scalar_to_hex(s: &<StarkCurve as Curve>::Scalar) -> String {
    convert::scalar_to_hex(s)
}

/// 对外（StarkCurve）签名：返回 `(r_compressed_hex, s_hex)`。
/// sk 由调用方（client-wasm / dev_bot / 测试）从游戏身份存储反序列化。
pub fn sign_game_action(
    sk: &<StarkCurve as Curve>::Scalar,
    table_id: u32,
    hand_id: u32,
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
            sign_game_action_generic(sk, table_id, hand_id, seq, action, amount, &nonce);
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
    hand_id: u32,
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
    verify_game_action_generic(&pk, table_id, hand_id, seq, action, amount, &r, &s)
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
        let (r, s) = sign_game_action_generic(&sk, 7, 3, 5, "raise", 320, &nonce);
        assert!(verify_game_action_generic(
            &pk, 7, 3, 5, "raise", 320, &r, &s
        ));
    }

    #[test]
    fn tampered_fields_rejected() {
        let sk = sample_sk();
        let pk = StarkCurve::base_g() * sk;
        let nonce = <StarkCurve as Curve>::Scalar::random(&mut OsRng);
        let (r, s) = sign_game_action_generic(&sk, 7, 3, 5, "raise", 320, &nonce);
        assert!(!verify_game_action_generic(
            &pk, 7, 3, 6, "raise", 320, &r, &s
        ));
        assert!(!verify_game_action_generic(
            &pk, 7, 3, 5, "fold", 320, &r, &s
        ));
        assert!(!verify_game_action_generic(
            &pk, 7, 3, 5, "raise", 321, &r, &s
        ));
        let other_pk = StarkCurve::base_g() * StarkCurve::hash_to_scalar(b"other-sk");
        assert!(!verify_game_action_generic(
            &other_pk, 7, 3, 5, "raise", 320, &r, &s
        ));
    }

    #[test]
    fn different_tables_dont_share_signatures() {
        let sk = sample_sk();
        let pk = StarkCurve::base_g() * sk;
        let nonce = <StarkCurve as Curve>::Scalar::random(&mut OsRng);
        let (r, s) = sign_game_action_generic(&sk, 1, 3, 5, "call", 0, &nonce);
        assert!(!verify_game_action_generic(
            &pk, 2, 3, 5, "call", 0, &r, &s
        ));
    }

    #[test]
    fn different_hands_dont_share_signatures() {
        // v2 核心缺口回归：签名必须绑定到具体手——跨手重放的签名在另一手
        // 的挑战域下失效（动作签名 = 逐手参与背书的前提）。
        let sk = sample_sk();
        let pk = StarkCurve::base_g() * sk;
        let nonce = <StarkCurve as Curve>::Scalar::random(&mut OsRng);
        let (r, s) = sign_game_action_generic(&sk, 7, 3, 5, "call", 0, &nonce);
        assert!(!verify_game_action_generic(
            &pk, 7, 4, 5, "call", 0, &r, &s
        ));
    }

    #[test]
    fn hex_helpers_roundtrip() {
        let sk = sample_sk();
        let pk = StarkCurve::base_g() * sk;
        let pk_hex = stark_point_to_hex(&pk);
        let (r_hex, s_hex) = sign_game_action(&sk, 3, 9, 11, "check", 0, &mut OsRng);
        assert!(verify_game_action_hex(&pk_hex, 3, 9, 11, "check", 0, &r_hex, &s_hex));
        assert!(!verify_game_action_hex(&pk_hex, 3, 9, 12, "check", 0, &r_hex, &s_hex));
    }
}
