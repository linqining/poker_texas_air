//! 嵌入式 sequencer 的确定性账户派生（v1 内嵌运营方托管模型）。
//!
//! **信任模型（如实记录）**：v1 嵌入式 sequencer 里，玩家的 appchain
//! 身份密钥由游戏服务器按钱包 felt 确定性派生并托管（`sk =
//! blake2s("texas-appchain.owner.v1" || wallet)`，派生失败按计数器重试）。
//! 这与现行 Starknet legacy 路径的信任面一致——operator 一直代管全部链上
//! 提交；生产去托管化（客户端持有 P 层密钥、服务器只见公钥）是 v2 客户端
//! 协议升级项，届时仅需替换本模块的密钥来源，结算语义不变。

use poker_appchain::keys::OwnerKey;

/// 密钥域标签。
const OWNER_DOMAIN: &[u8] = b"texas-appchain.owner.v1";

/// 钱包 felt（32B）→ 该钱包的 appchain owner 密钥（确定性；派生失败按
/// 计数器重试——secp256k1 模数外的种子概率 ≈ 2⁻¹²⁸，循环实际不二次进入）。
#[must_use]
pub fn owner_key_of(wallet_felt: &[u8; 32]) -> OwnerKey {
    let mut counter = 0u8;
    loop {
        let mut seed = poker_appchain::keys::blake2s32(&[OWNER_DOMAIN, wallet_felt]);
        seed[31] = seed[31].wrapping_add(counter);
        if let Ok(k) = OwnerKey::from_seed(&seed) {
            return k;
        }
        counter = counter.wrapping_add(1);
    }
}

/// 花费密钥（nullifier 派生输入）：与 owner 密钥同源派生（v1 托管模型）。
#[must_use]
pub fn spend_secret_of(wallet_felt: &[u8; 32]) -> [u8; 32] {
    poker_appchain::keys::blake2s32(&[OWNER_DOMAIN, b"/spend", wallet_felt])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 确定性：同钱包同钥；不同钱包不同钥。
    #[test]
    fn derivation_is_deterministic_and_injective() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(owner_key_of(&a).public_bytes(), owner_key_of(&a).public_bytes());
        assert_ne!(owner_key_of(&a).public_bytes(), owner_key_of(&b).public_bytes());
        assert_ne!(spend_secret_of(&a), spend_secret_of(&b));
    }
}
