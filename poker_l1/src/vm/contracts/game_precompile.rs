//! 游戏合约预编译实现（包装现有的 dispatch 逻辑）。
//!
//! 将现有的 `dispatch.rs` 逻辑包装为 `Precompile` trait 的实现，
//! 通过 `PrecompileRegistry` 注册后即可被 executor 调用。

use std::sync::Arc;

use super::{dispatch, dispatch::selectors, types::GameContract};
use crate::Address;
use crate::error::{PokerL1Error, PokerL1Result};
use crate::object_model::ObjectID;
use crate::signature::TaggedPubkey;
use crate::storage::{ObjectBackend, ObjectDb};
use crate::vm::precompile::{DispatchResult, ExecutionEnvironment, Precompile};

/// 游戏合约预编译实现。
///
/// 将现有的游戏合约 dispatch 逻辑包装为 `Precompile` trait，
/// 通过 ObjectID 路由到对应的游戏合约方法。
#[derive(Debug, Clone)]
pub struct GamePrecompile {
    version: u32,
}

impl GamePrecompile {
    /// 创建游戏合约预编译实例。
    #[must_use]
    pub fn new(version: u32) -> Self {
        Self { version }
    }

    /// 创建游戏合约预编译实例（Arc 包装）。
    #[must_use]
    pub fn new_arc(version: u32) -> Arc<dyn Precompile> {
        Arc::new(Self::new(version))
    }
}

impl Precompile for GamePrecompile {
    fn id(&self) -> ObjectID {
        crate::vm::precompile::reserved::game_contract_id()
    }

    fn version(&self) -> u32 {
        self.version
    }

    fn call(
        &self,
        caller: &Address,
        caller_pubkey: &TaggedPubkey,
        method_selector: &[u8; 32],
        args: &[u8],
        env: &ExecutionEnvironment,
        object_db: &mut dyn ObjectBackend,
    ) -> PokerL1Result<DispatchResult> {
        let dispatch_context = dispatch::DispatchContext {
            caller: *caller,
            caller_pubkey: caller_pubkey.clone(),
            chain_id: env.chain_id,
            block_height: env.block_height,
            block_timestamp: env.block_timestamp,
        };

        let game_id = crate::vm::precompile::reserved::game_contract_id();
        let game_obj = object_db.read(&game_id).map_err(|e| match e {
            PokerL1Error::ObjectNotFound(_) => PokerL1Error::ContractNotFound(game_id),
            other => other,
        })?;

        let mut game: GameContract = borsh::from_slice(&game_obj.data)
            .map_err(|e| PokerL1Error::Serialization(format!("GameContract BCS: {e}")))?;

        let result = dispatch::dispatch(&dispatch_context, &mut game, method_selector, args)?;

        let game_data = borsh::to_vec(&game)
            .map_err(|e| PokerL1Error::Serialization(format!("GameContract BCS write: {e}")))?;
        object_db.update(&game_id, caller, game_data)?;

        Ok(DispatchResult {
            created_objects: result.created_objects,
            modified_objects: result.modified_objects,
            // 本预编译读取 game_id（用于反序列化 GameContract），
            // 必须报告给并行执行器以免漏掉读-写冲突。
            read_objects: vec![game_id],
            return_value: result.return_value,
        })
    }

    fn supports_selector(&self, selector: &[u8; 32]) -> bool {
        let known_selectors = [
            selectors::hand_started(),
            selectors::force_advance(),
            selectors::settle_hand(),
            selectors::force_checkpoint(),
            selectors::checkpoint_anchor(),
            selectors::force_checkin(),
            selectors::force_settle(),
            selectors::request_revert(),
            selectors::force_revert(),
            selectors::apply_forfeit(),
            selectors::challenge_delta(),
            selectors::request_da(),
            selectors::checkpoint_skip(),
            selectors::revoke_delegated_escape(),
            selectors::request_ack(),
            selectors::refuse_ack(),
        ];
        known_selectors.contains(selector)
    }

    /// 游戏合约预编译免 gas（spec SubTask 8.5：GameTurn 通道游戏操作 tx 免 gas）。
    ///
    /// 反滥用由以下机制保障：
    /// - 游戏买入锁仓（Phase 3 合约层）
    /// - `gameturn_nonce` per-game per-player 重放保护（SEC-L3 / NEW-M9）
    /// - 轮次约束（routing.rs：`validate_turn_order` / `validate_game_turn_phase_aware`）
    /// - assigned_validator 路由（routing.rs：`validate_assigned_validator`）
    fn is_gas_free(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::TaggedPubkey;

    fn make_env() -> ExecutionEnvironment {
        ExecutionEnvironment {
            chain_id: 1,
            block_height: 100,
            block_timestamp: 1_000_000,
            tx_inputs: vec![],
            tx_hash: [0u8; 32],
        }
    }

    #[test]
    fn test_game_precompile_id() {
        let precompile = GamePrecompile::new(1);
        let expected_id = crate::vm::precompile::reserved::game_contract_id();
        assert_eq!(precompile.id(), expected_id);
    }

    #[test]
    fn test_game_precompile_version() {
        let precompile = GamePrecompile::new(2);
        assert_eq!(precompile.version(), 2);
    }

    #[test]
    fn test_game_precompile_supports_known_selector() {
        let precompile = GamePrecompile::new(1);
        assert!(precompile.supports_selector(&selectors::hand_started()));
        assert!(precompile.supports_selector(&selectors::force_advance()));
        assert!(precompile.supports_selector(&selectors::settle_hand()));
    }

    #[test]
    fn test_game_precompile_rejects_unknown_selector() {
        let precompile = GamePrecompile::new(1);
        let unknown_selector = [255u8; 32];
        assert!(!precompile.supports_selector(&unknown_selector));
    }
}
