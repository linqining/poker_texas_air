//! 委托逃生机制（Task 27 — SubTask 27.5c）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）：
//! - **凭证格式**：`delegated_escape_authorization` = `(game_id, delegator_tagged_pubkey,
//!   expiry_height, credential_nonce, operator_signature)`
//!   - `expiry_height` 为**绝对 block height**（NEW-M2 修复）
//!   - `credential_nonce` 单调递增，链上 Game 维护 `delegated_escape_nonce`
//! - **R4-H7 修正 — 签名对象**：`hash(chain_id || game_id || tagged_pubkey ||
//!   expiry_height || credential_nonce)`
//! - **链上验证**：签名有效 + `block.height <= expiry_height`（未过期，NEW-M2）+
//!   game_id 匹配 + `expiry_height - tx.block_height <=
//!   delegated_escape_max_expiry_blocks`（有效期不超限，NEW-M2）+
//!   `credential_nonce > Game.delegated_escape_nonce`
//! - **NEW-M1 修复 — 凭证一次性消费**：接受后链上执行
//!   `Game.delegated_escape_nonce = credential_nonce`，同一凭证不可重复使用
//! - **撤销机制**：`revoke_delegated_escape` tx（任意 validator，正常计费 gas）：
//!   操作方签名 → `Game.delegated_escape_nonce += 1` → 所有旧 nonce 凭证失效；
//!   新凭证使用 `credential_nonce = Game.delegated_escape_nonce + 1`
//! - **NEW-M2 修复**：默认 `delegated_escape_max_expiry_blocks` 降至 100（缩小滥用窗口）
//! - **SEC2-L4 修复 — credential_nonce 消费时机**：
//!   - credential_nonce 仅在 force_checkpoint 被接受（evidence 验证通过）时消费
//!   - 被拒绝时不消费可重新提交
//!   - 同一 nonce 每 turn_timeout_blocks 最多 1 次
//!   - 消费时机 = force_checkpoint tx finality 后

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::ChainId;
use crate::Hash;
use crate::error::PokerL1Error;
use crate::object_model::ObjectID;
use crate::signature::{TaggedPubkey, verify_signature};

use super::types::GameContract;

/// delegated_escape_max_expiry_blocks 默认值（NEW-M2：由原 1000 降至 100）。
pub const DEFAULT_DELEGATED_ESCAPE_MAX_EXPIRY_BLOCKS: u64 = 100;

/// 委托逃生凭证（SubTask 27.5c）。
///
/// 操作方签名授权 watchtower/参与者在指定 expiry_height 前代为提交
/// `force_checkpoint`，用于操作方临时离线场景。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct DelegatedEscapeAuthorization {
    /// Game 对象 ID。
    pub game_id: ObjectID,
    /// 委托方（操作方）tagged pubkey。
    pub delegator: TaggedPubkey,
    /// 绝对过期 block height（NEW-M2：必须为绝对值，非相对 delta）。
    pub expiry_height: u64,
    /// 凭证 nonce（严格单调递增，每次撤销或消费后递增）。
    pub credential_nonce: u64,
    /// 操作方对签名域哈希的签名。
    pub operator_signature: Vec<u8>,
}

impl DelegatedEscapeAuthorization {
    /// 计算委托逃生凭证的签名域哈希（R4-H7 修正）。
    ///
    /// `hash(chain_id || game_id || delegator || expiry_height || credential_nonce)`
    #[must_use]
    pub fn signing_hash(&self, chain_id: ChainId) -> Hash {
        let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32) 不应失败");
        hasher.update(&chain_id.to_be_bytes());
        hasher.update(&self.game_id.to_bytes());
        hasher.update(&self.delegator.to_bytes());
        hasher.update(&self.expiry_height.to_be_bytes());
        hasher.update(&self.credential_nonce.to_be_bytes());
        let mut out = [0u8; 32];
        hasher
            .finalize_variable(&mut out)
            .expect("Blake2bVar finalize 不应失败");
        out
    }

    /// 验证委托逃生凭证（SubTask 27.5c）。
    ///
    /// 校验链：
    /// 1. 签名有效性（操作方签名）
    /// 2. game_id 匹配（外部传入 expected_game_id）
    /// 3. `current_block_height <= expiry_height`（未过期，NEW-M2）
    /// 4. `expiry_height - current_block_height <= max_expiry_blocks`（有效期不超限，NEW-M2）
    /// 5. `credential_nonce > game.delegated_escape_nonce`（未消费 + 防回退）
    ///
    /// # 参数
    /// - `chain_id`：链 ID
    /// - `game`：当前 GameContract 状态
    /// - `current_block_height`：当前 block height
    /// - `max_expiry_blocks`：delegated_escape_max_expiry_blocks 治理参数
    pub fn verify(
        &self,
        chain_id: ChainId,
        game: &GameContract,
        current_block_height: u64,
        max_expiry_blocks: u64,
    ) -> Result<(), PokerL1Error> {
        // (2) game_id 匹配
        if self.game_id != game.id {
            return Err(PokerL1Error::InvalidDelegatedEscapeAuthorization(format!(
                "game_id mismatch: credential={:?}, game={:?}",
                self.game_id, game.id
            )));
        }

        // (3) 未过期校验（NEW-M2）
        if current_block_height > self.expiry_height {
            return Err(PokerL1Error::DelegatedEscapeExpired {
                expiry: self.expiry_height,
                current: current_block_height,
            });
        }

        // (4) 有效期不超限（NEW-M2）
        let expiry_delta = self.expiry_height - current_block_height;
        if expiry_delta > max_expiry_blocks {
            return Err(PokerL1Error::InvalidDelegatedEscapeAuthorization(format!(
                "expiry_delta {expiry_delta} > max_expiry_blocks {max_expiry_blocks}"
            )));
        }

        // (5) credential_nonce 未消费 + 防回退
        if self.credential_nonce <= game.delegated_escape_nonce {
            return Err(PokerL1Error::DelegatedEscapeNonceConsumed(
                self.credential_nonce,
            ));
        }

        // (1) 签名验证（最后做，最昂贵）
        let msg_hash = self.signing_hash(chain_id);
        verify_signature(&self.delegator, &self.operator_signature, &msg_hash)?;

        Ok(())
    }
}

/// 撤销委托逃生凭证 tx（SubTask 27.5c — 撤销机制）。
///
/// 操作方签名 → `Game.delegated_escape_nonce += 1` → 所有旧 nonce 凭证失效。
/// 走 Public 通道，正常计费 gas。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct RevokeDelegatedEscapeTx {
    /// Game 对象 ID。
    pub game_id: ObjectID,
    /// 操作方 tagged pubkey。
    pub operator: TaggedPubkey,
    /// 操作方签名（签名对象 = `hash(chain_id || game_id || operator || current_nonce)`）。
    pub signature: Vec<u8>,
}

impl RevokeDelegatedEscapeTx {
    /// 计算撤销 tx 的签名域哈希。
    ///
    /// `hash(chain_id || game_id || operator || current_nonce)`
    #[must_use]
    pub fn signing_hash(&self, chain_id: ChainId, current_nonce: u64) -> Hash {
        let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32) 不应失败");
        hasher.update(&chain_id.to_be_bytes());
        hasher.update(&self.game_id.to_bytes());
        hasher.update(&self.operator.to_bytes());
        hasher.update(&current_nonce.to_be_bytes());
        let mut out = [0u8; 32];
        hasher
            .finalize_variable(&mut out)
            .expect("Blake2bVar finalize 不应失败");
        out
    }

    /// 验证撤销 tx 签名 + game_id 匹配。
    pub fn verify(&self, chain_id: ChainId, game: &GameContract) -> Result<(), PokerL1Error> {
        // game_id 匹配
        if self.game_id != game.id {
            return Err(PokerL1Error::GameNotFound(self.game_id));
        }
        // 操作方须为 assigned_validator（操作方即 assigned_validator）
        if self.operator != game.assigned_validator {
            return Err(PokerL1Error::InvalidDelegatedEscapeAuthorization(
                "revoke tx signer != game.assigned_validator".to_string(),
            ));
        }
        // 签名验证
        let msg_hash = self.signing_hash(chain_id, game.delegated_escape_nonce);
        verify_signature(&self.operator, &self.signature, &msg_hash)?;
        Ok(())
    }
}

// ===== 应用函数 =====

/// 计算下一个 credential_nonce（SubTask 27.5c）。
///
/// 新凭证使用 `credential_nonce = Game.delegated_escape_nonce + 1`。
#[must_use]
pub const fn compute_next_credential_nonce(game: &GameContract) -> u64 {
    game.delegated_escape_nonce.saturating_add(1)
}

/// 消费委托逃生凭证（NEW-M1 + SEC2-L4）。
///
/// **SEC2-L4 修复 — credential_nonce 消费时机**：
/// - 仅在 force_checkpoint 被接受（evidence 验证通过）时调用此函数
/// - 被拒绝时不消费可重新提交
/// - 消费 = `Game.delegated_escape_nonce = credential_nonce`
///
/// # 参数
/// - `game`：可变的 GameContract 引用
/// - `authorization`：已通过 `verify` 的委托凭证
///
/// # 返回
/// - `Ok(())`：消费成功
/// - `Err(DelegatedEscapeNonceConsumed)`：nonce 已被消费或回退（双重检查）
pub const fn consume_delegated_escape_authorization(
    game: &mut GameContract,
    authorization: &DelegatedEscapeAuthorization,
) -> Result<(), PokerL1Error> {
    // 双重检查：防止 verify 后到 consume 之间状态变化
    if authorization.credential_nonce <= game.delegated_escape_nonce {
        return Err(PokerL1Error::DelegatedEscapeNonceConsumed(
            authorization.credential_nonce,
        ));
    }
    // NEW-M1: 凭证一次性消费
    game.delegated_escape_nonce = authorization.credential_nonce;
    game.version = game.version.saturating_add(1);
    Ok(())
}

/// 应用撤销委托逃生 tx（SubTask 27.5c — 撤销机制）。
///
/// `Game.delegated_escape_nonce += 1` → 所有旧 nonce 凭证失效。
pub fn apply_revoke_delegated_escape(
    game: &mut GameContract,
    tx: &RevokeDelegatedEscapeTx,
    chain_id: ChainId,
) -> Result<(), PokerL1Error> {
    // 验证 tx
    tx.verify(chain_id, game)?;

    // 撤销：nonce += 1
    game.delegated_escape_nonce = game.delegated_escape_nonce.saturating_add(1);
    game.version = game.version.saturating_add(1);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Address;
    use crate::signature::{CURRENT_VERSION, SignatureScheme};
    use crate::vm::contracts::types::{ExecutionMode, RakeConfigRef};

    fn make_test_tagged_pubkey(byte: u8) -> TaggedPubkey {
        let mut raw = vec![byte];
        raw.extend_from_slice(&[0x02u8; 32]);
        TaggedPubkey::new(SignatureScheme::Secp256k1, CURRENT_VERSION, raw)
            .expect("构造 tagged pubkey 不应失败")
    }

    fn make_addr(byte: u8) -> Address {
        [byte; 20]
    }

    fn make_game_id() -> ObjectID {
        ObjectID::new(make_addr(0x01), 1)
    }

    fn make_minimal_game() -> GameContract {
        GameContract::new(
            make_game_id(),
            make_addr(0x01),
            make_test_tagged_pubkey(0xFF),
            ExecutionMode::OffChain,
            RakeConfigRef {
                rake_rate_bps: 0,
                rake_cap: 0,
                rake_recipient: make_addr(0x00),
            },
            10,
        )
    }

    fn make_authorization(
        nonce: u64,
        expiry: u64,
        delegator: TaggedPubkey,
    ) -> DelegatedEscapeAuthorization {
        DelegatedEscapeAuthorization {
            game_id: make_game_id(),
            delegator,
            expiry_height: expiry,
            credential_nonce: nonce,
            operator_signature: vec![0u8; 65], // 占位签名
        }
    }

    fn make_revoke_tx(operator: TaggedPubkey) -> RevokeDelegatedEscapeTx {
        RevokeDelegatedEscapeTx {
            game_id: make_game_id(),
            operator,
            signature: vec![0u8; 65], // 占位签名
        }
    }

    // ===== signing_hash 测试 =====

    #[test]
    fn test_authorization_signing_hash_deterministic() {
        let auth = make_authorization(1, 1000, make_test_tagged_pubkey(0xAB));
        let h1 = auth.signing_hash(crate::DEFAULT_CHAIN_ID);
        let h2 = auth.signing_hash(crate::DEFAULT_CHAIN_ID);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_authorization_signing_hash_differs_by_chain_id() {
        let auth = make_authorization(1, 1000, make_test_tagged_pubkey(0xAB));
        let h1 = auth.signing_hash(1);
        let h2 = auth.signing_hash(2);
        assert_ne!(h1, h2, "不同 chain_id 应产生不同哈希");
    }

    #[test]
    fn test_authorization_signing_hash_differs_by_nonce() {
        let a1 = make_authorization(1, 1000, make_test_tagged_pubkey(0xAB));
        let a2 = make_authorization(2, 1000, make_test_tagged_pubkey(0xAB));
        let h1 = a1.signing_hash(crate::DEFAULT_CHAIN_ID);
        let h2 = a2.signing_hash(crate::DEFAULT_CHAIN_ID);
        assert_ne!(h1, h2, "不同 nonce 应产生不同哈希");
    }

    #[test]
    fn test_authorization_signing_hash_differs_by_expiry() {
        let a1 = make_authorization(1, 1000, make_test_tagged_pubkey(0xAB));
        let a2 = make_authorization(1, 2000, make_test_tagged_pubkey(0xAB));
        let h1 = a1.signing_hash(crate::DEFAULT_CHAIN_ID);
        let h2 = a2.signing_hash(crate::DEFAULT_CHAIN_ID);
        assert_ne!(h1, h2, "不同 expiry 应产生不同哈希");
    }

    #[test]
    fn test_authorization_signing_hash_differs_by_delegator() {
        let a1 = make_authorization(1, 1000, make_test_tagged_pubkey(0xAB));
        let a2 = make_authorization(1, 1000, make_test_tagged_pubkey(0xCD));
        let h1 = a1.signing_hash(crate::DEFAULT_CHAIN_ID);
        let h2 = a2.signing_hash(crate::DEFAULT_CHAIN_ID);
        assert_ne!(h1, h2, "不同 delegator 应产生不同哈希");
    }

    // ===== verify 测试 =====

    #[test]
    fn test_authorization_verify_game_id_mismatch() {
        let mut auth = make_authorization(1, 1000, make_test_tagged_pubkey(0xAB));
        auth.game_id = ObjectID::new([0xFF; 20], 999);
        let game = make_minimal_game();
        let result = auth.verify(crate::DEFAULT_CHAIN_ID, &game, 500, 1000);
        assert!(
            matches!(
                result,
                Err(PokerL1Error::InvalidDelegatedEscapeAuthorization { .. })
            ),
            "game_id 不匹配应返回 InvalidDelegatedEscapeAuthorization"
        );
    }

    #[test]
    fn test_authorization_verify_expired() {
        // current=1500 > expiry=1000
        let auth = make_authorization(1, 1000, make_test_tagged_pubkey(0xAB));
        let game = make_minimal_game();
        let result = auth.verify(crate::DEFAULT_CHAIN_ID, &game, 1500, 1000);
        assert!(
            matches!(
                result,
                Err(PokerL1Error::DelegatedEscapeExpired {
                    expiry: 1000,
                    current: 1500
                })
            ),
            "过期应返回 DelegatedEscapeExpired"
        );
    }

    #[test]
    fn test_authorization_verify_expiry_at_boundary() {
        // current=1000 == expiry=1000 → 未过期（<= 边界，SEC2-L6）
        // 但 signature 验证会失败（占位签名）
        let auth = make_authorization(1, 1000, make_test_tagged_pubkey(0xAB));
        let game = make_minimal_game();
        let result = auth.verify(crate::DEFAULT_CHAIN_ID, &game, 1000, 1000);
        // 期望到达签名验证步骤（即非过期/nonce 错误）
        assert!(
            matches!(result, Err(PokerL1Error::InvalidSignature)),
            "边界时刻应通过过期校验，到达签名验证"
        );
    }

    #[test]
    fn test_authorization_verify_expiry_delta_exceeds_max() {
        // current=500, expiry=2000, delta=1500 > max=1000
        let auth = make_authorization(1, 2000, make_test_tagged_pubkey(0xAB));
        let game = make_minimal_game();
        let result = auth.verify(crate::DEFAULT_CHAIN_ID, &game, 500, 1000);
        assert!(
            matches!(
                result,
                Err(PokerL1Error::InvalidDelegatedEscapeAuthorization { .. })
            ),
            "expiry_delta 超限应失败"
        );
    }

    #[test]
    fn test_authorization_verify_nonce_consumed() {
        // game.delegated_escape_nonce = 5, auth.credential_nonce = 3 → 已消费
        let mut game = make_minimal_game();
        game.delegated_escape_nonce = 5;
        let auth = make_authorization(3, 1000, make_test_tagged_pubkey(0xAB));
        let result = auth.verify(crate::DEFAULT_CHAIN_ID, &game, 500, 1000);
        assert!(
            matches!(result, Err(PokerL1Error::DelegatedEscapeNonceConsumed(3))),
            "已消费 nonce 应返回 DelegatedEscapeNonceConsumed"
        );
    }

    #[test]
    fn test_authorization_verify_nonce_equal_to_current() {
        // nonce == current_nonce → 应失败（须严格大于）
        let mut game = make_minimal_game();
        game.delegated_escape_nonce = 5;
        let auth = make_authorization(5, 1000, make_test_tagged_pubkey(0xAB));
        let result = auth.verify(crate::DEFAULT_CHAIN_ID, &game, 500, 1000);
        assert!(
            matches!(result, Err(PokerL1Error::DelegatedEscapeNonceConsumed(5))),
            "nonce == current 应失败（须严格大于）"
        );
    }

    #[test]
    fn test_authorization_verify_nonce_valid_reaches_signature() {
        // nonce=6 > current=5 → 通过 nonce 校验，到达签名验证
        let mut game = make_minimal_game();
        game.delegated_escape_nonce = 5;
        let auth = make_authorization(6, 1000, make_test_tagged_pubkey(0xAB));
        let result = auth.verify(crate::DEFAULT_CHAIN_ID, &game, 500, 1000);
        assert!(
            matches!(result, Err(PokerL1Error::InvalidSignature)),
            "有效 nonce 应通过到签名验证"
        );
    }

    // ===== RevokeDelegatedEscapeTx 测试 =====

    #[test]
    fn test_revoke_tx_signing_hash_deterministic() {
        let tx = make_revoke_tx(make_test_tagged_pubkey(0xAB));
        let h1 = tx.signing_hash(crate::DEFAULT_CHAIN_ID, 5);
        let h2 = tx.signing_hash(crate::DEFAULT_CHAIN_ID, 5);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_revoke_tx_signing_hash_differs_by_nonce() {
        let tx = make_revoke_tx(make_test_tagged_pubkey(0xAB));
        let h1 = tx.signing_hash(crate::DEFAULT_CHAIN_ID, 5);
        let h2 = tx.signing_hash(crate::DEFAULT_CHAIN_ID, 6);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_revoke_tx_verify_game_id_mismatch() {
        let mut tx = make_revoke_tx(make_test_tagged_pubkey(0xFF));
        tx.game_id = ObjectID::new([0xFF; 20], 999);
        let game = make_minimal_game();
        let result = tx.verify(crate::DEFAULT_CHAIN_ID, &game);
        assert!(
            matches!(result, Err(PokerL1Error::GameNotFound { .. })),
            "game_id 不匹配应返回 GameNotFound"
        );
    }

    #[test]
    fn test_revoke_tx_verify_operator_not_assigned_validator() {
        // operator != game.assigned_validator
        let tx = make_revoke_tx(make_test_tagged_pubkey(0xEE));
        let game = make_minimal_game();
        let result = tx.verify(crate::DEFAULT_CHAIN_ID, &game);
        assert!(
            matches!(
                result,
                Err(PokerL1Error::InvalidDelegatedEscapeAuthorization { .. })
            ),
            "非 assigned_validator 应失败"
        );
    }

    #[test]
    fn test_revoke_tx_verify_reaches_signature() {
        // operator == game.assigned_validator (0xFF) → 到达签名验证
        let tx = make_revoke_tx(make_test_tagged_pubkey(0xFF));
        let game = make_minimal_game();
        let result = tx.verify(crate::DEFAULT_CHAIN_ID, &game);
        assert!(
            matches!(result, Err(PokerL1Error::InvalidSignature)),
            "正确 operator 应通过到签名验证"
        );
    }

    // ===== consume_delegated_escape_authorization 测试 =====

    #[test]
    fn test_consume_authorization_success() {
        let mut game = make_minimal_game();
        game.delegated_escape_nonce = 5;
        let auth = make_authorization(6, 1000, make_test_tagged_pubkey(0xAB));
        let result = consume_delegated_escape_authorization(&mut game, &auth);
        assert!(result.is_ok(), "有效 nonce 应消费成功");
        assert_eq!(game.delegated_escape_nonce, 6, "nonce 应更新为 6");
    }

    #[test]
    fn test_consume_authorization_nonce_already_consumed() {
        let mut game = make_minimal_game();
        game.delegated_escape_nonce = 5;
        let auth = make_authorization(3, 1000, make_test_tagged_pubkey(0xAB));
        let result = consume_delegated_escape_authorization(&mut game, &auth);
        assert!(
            matches!(result, Err(PokerL1Error::DelegatedEscapeNonceConsumed(3))),
            "已消费 nonce 应失败"
        );
        assert_eq!(game.delegated_escape_nonce, 5, "失败时 nonce 不应变化");
    }

    #[test]
    fn test_consume_authorization_double_consume_fails() {
        let mut game = make_minimal_game();
        let auth = make_authorization(1, 1000, make_test_tagged_pubkey(0xAB));
        // 首次消费
        let r1 = consume_delegated_escape_authorization(&mut game, &auth);
        assert!(r1.is_ok());
        assert_eq!(game.delegated_escape_nonce, 1);
        // 再次消费同一凭证 → 失败（NEW-M1：凭证一次性消费）
        let r2 = consume_delegated_escape_authorization(&mut game, &auth);
        assert!(r2.is_err(), "同一凭证不可重复消费");
        assert_eq!(game.delegated_escape_nonce, 1, "二次消费失败时 nonce 不变");
    }

    // ===== apply_revoke_delegated_escape 测试 =====

    #[test]
    fn test_apply_revoke_fails_on_invalid_signature() {
        let mut game = make_minimal_game();
        let tx = make_revoke_tx(make_test_tagged_pubkey(0xFF));
        let result = apply_revoke_delegated_escape(&mut game, &tx, crate::DEFAULT_CHAIN_ID);
        assert!(result.is_err(), "占位签名应失败");
        assert_eq!(game.delegated_escape_nonce, 0, "失败时 nonce 不变");
    }

    // ===== compute_next_credential_nonce 测试 =====

    #[test]
    fn test_compute_next_credential_nonce() {
        let mut game = make_minimal_game();
        assert_eq!(compute_next_credential_nonce(&game), 1);
        game.delegated_escape_nonce = 5;
        assert_eq!(compute_next_credential_nonce(&game), 6);
    }

    #[test]
    fn test_compute_next_credential_nonce_saturating() {
        let mut game = make_minimal_game();
        game.delegated_escape_nonce = u64::MAX;
        assert_eq!(compute_next_credential_nonce(&game), u64::MAX);
    }

    // ===== 常量测试 =====

    #[test]
    fn test_constants() {
        assert_eq!(
            DEFAULT_DELEGATED_ESCAPE_MAX_EXPIRY_BLOCKS, 100,
            "NEW-M2: 默认 100"
        );
    }
}
