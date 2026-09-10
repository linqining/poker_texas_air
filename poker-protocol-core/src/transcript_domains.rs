//! Production Fiat–Shamir transcript domain labels（Poseidon epoch）。
//!
//! 2026-09 Poseidon 迁移：poker_l1 / texas / z_poker / precompile 全链路的
//! 生产 transcript 从 SHA3-256（`FiatShamirTranscript`，Move 兼容遗留）与
//! Merlin（`MerlinTranscript`，离线测试遗留）统一切换到
//! [`PoseidonFeltTranscript`]（felt 直通，Cairo 原生置换）。
//!
//! # 纪律
//!
//! - **所有标签必须 ≤31 字节**：transcript absorb 阶段标签按
//!   `ascii_bytes31` 规范截断，截断是规范行为而非意外，但新标签应直接
//!   满足约束以保证三端（host/wasm/Cairo）逐字节一致。
//! - **标签带 epoch 后缀**：域标签与旧 SHA3/Merlin 域不同名，旧域证明
//!   无法跨域重放到新验证器（域分离由 transcript 初始状态强制）。
//! - 一次 hand 内 shuffle→deal→reveal→leave→reconstruct 必须使用同一
//!   epoch 的标签集合；epoch 切换只允许发生在 hand 边界。
//!
//! digest 域（`poseidon_bytes_digest` 的字节材料前缀）无 31 字节约束，
//! 单列在 [`self`] 尾部。

/// Bayer–Groth V2 全员洗牌证明（对应旧 `zk_shuffle_proof_v2` SHA3 域）。
pub const SHUFFLE_V2_POSEIDON: &[u8] = b"zk_shuffle_poseidon_v3";

/// remask 自剥层 + 洗牌复合证明（对应旧 `zk_mask_shuffle_proof_v2`）。
pub const MASK_SHUFFLE_V2_POSEIDON: &[u8] = b"zk_mask_shuffle_poseidon_v3";

/// 离场 / fold 剥层 DLEq（对应旧 `zk_leave_proof_v1`；该路径此前存在
/// poker_l1=Merlin 与 texas=FiatShamirSha3 的域分裂，本次一并统一）。
pub const LEAVE_POSEIDON_V2: &[u8] = b"zk_leave_poseidon_v2";

/// 揭牌令牌 DLEq（对应旧 `reveal_token_proof_v3`）。
pub const REVEAL_TOKEN_V3_POSEIDON: &[u8] = b"reveal_token_poseidon_v3";

/// 离场重建 V2（对应旧 `RECONSTRUCTION_PROOF_LABEL` 域）。
pub const RECONSTRUCT_V2_POSEIDON: &[u8] = b"zk_reconstruct_poseidon_v2";

/// 离场重建 V3（对应旧 `zk_reconstruct_proof_v3`）。
pub const RECONSTRUCT_V3_POSEIDON: &[u8] = b"zk_reconstruct_poseidon_v3";

/// 操作员强洗（对应旧 `poker_protocol_force_shuffle`）。
pub const FORCE_SHUFFLE_POSEIDON_V1: &[u8] = b"force_shuffle_poseidon_v1";

/// reconstruction V3 上下文摘要域（字节材料前缀，随压缩函数切换 bump）。
pub const RECONSTRUCTION_V3_CONTEXT_DIGEST_DOMAIN: &[u8] =
    b"zchain.texas_poker.reconstruction_v3.context.v2.poseidon";

/// reconstruction V3 前置状态摘要域（字节材料前缀，随压缩函数切换 bump）。
pub const RECONSTRUCTION_V3_PRIOR_STATE_DIGEST_DOMAIN: &[u8] =
    b"zchain.texas_poker.reconstruction_v3.prior_state.v3.poseidon";

#[cfg(test)]
mod tests {
    use super::*;

    /// 域标签纪律：absorb 阶段按 31 字节规范截断，新标签必须直接满足。
    #[test]
    fn labels_fit_single_felt() {
        for (name, label) in [
            ("shuffle", SHUFFLE_V2_POSEIDON),
            ("mask_shuffle", MASK_SHUFFLE_V2_POSEIDON),
            ("leave", LEAVE_POSEIDON_V2),
            ("reveal_token", REVEAL_TOKEN_V3_POSEIDON),
            ("reconstruct_v2", RECONSTRUCT_V2_POSEIDON),
            ("reconstruct_v3", RECONSTRUCT_V3_POSEIDON),
            ("force_shuffle", FORCE_SHUFFLE_POSEIDON_V1),
        ] {
            assert!(
                label.len() <= 31,
                "transcript domain label {name} must fit one felt (<=31 bytes)"
            );
        }
    }

    /// 跨端对拍 KAT（host / wasm / Cairo 三端挑战派生逐字节一致的锚点）。
    ///
    /// 语句：域 `zk_shuffle_poseidon_v3`，`append_message(b"stmt",
    /// b"kat-statement")`，随后 `challenge("c")` / `challenge("c2")`。
    /// 任何一端改动 init / absorb / challenge 规范都会破坏这两个向量。
    #[test]
    fn poseidon_epoch_challenge_kat() {
        use crate::{CryptoTranscript, PoseidonFeltTranscript, StarkCurve};

        let mut t = PoseidonFeltTranscript::new_domain(SHUFFLE_V2_POSEIDON);
        t.append_message(b"stmt", b"kat-statement");
        let c = t.challenge::<StarkCurve>(b"c").scalar;
        let c2 = t.challenge::<StarkCurve>(b"c2").scalar;
        assert_eq!(
            crate::curve::CurveScalar::as_bytes(&c).to_vec(),
            hex::decode("0530f2437f81a86f3a653bafbb28b534c9cf71fa1abbdffbebd1e47dc2dd280b")
                .unwrap(),
            "challenge schedule deviated from the pinned Poseidon-epoch KAT"
        );
        assert_eq!(
            crate::curve::CurveScalar::as_bytes(&c2).to_vec(),
            hex::decode("018f5cf46689d476627c03f1ba3797b680a11a59f31ecf09eea6fb1f3fcc32e9")
                .unwrap(),
            "challenge ratchet deviated from the pinned Poseidon-epoch KAT"
        );
    }
}
