//! Texas Poker 合约预编译实现（包装 `texas_poker::dispatch` 逻辑）。
//!
//! 将 `texas_poker::dispatch` 路由包装为 `Precompile` trait 实现，
//! 通过 `PrecompileRegistry` 注册后即可被 executor 调用。
//!
//! # ObjectID
//!
//! 固定为 `reserved::texas_poker_contract_id()`（`0xFF..02`）。
//!
//! # 首次调用（create_table）
//!
//! 当 `method_selector == selectors::create_table()` 且 ObjectDb 中无
//! `texas_poker_contract_id()` 对象时，先构造空 `TexasPokerTable`（占位）
//! 写入 ObjectDb，再交给 dispatch::dispatch::create_table 完成字段初始化。
//!
//! # Gas
//!
//! Texas Poker 操作通过 GameTurn 通道提交，故不向调用者收取 resource credits。
//! 但 host-native 密码学验证仍计入 block resource gas，避免无效 proof 免费占满
//! validator CPU。重放保护继续由 `gameturn_nonce`、轮次约束和 assigned-validator
//! 路由共同提供。

use std::sync::Arc;

use super::texas_poker::dispatch as tp_dispatch;
use super::texas_poker::dispatch::selectors;
use super::texas_poker::events::{
    REFUND_TYPE_BET_ONLY, REFUND_TYPE_STACK_AND_BET, REFUND_TYPE_STACK_ONLY, TexasPokerEvent,
};
use super::texas_poker::prove_task::L1DispatchOutput;
use super::texas_poker::state_machine::reconcile_table_vault;
use super::texas_poker::types::{TableContextOpenings, TexasPokerTable};
use super::texas_poker::{
    TEXAS_POKER_GOVERNANCE_OBJECT_TYPE, TEXAS_POKER_METADATA_OBJECT_TYPE,
    TEXAS_POKER_RULES_OBJECT_TYPE, TEXAS_POKER_TABLE_OBJECT_TYPE,
};
use crate::Address;
use crate::economics::{
    NativeCoinSelection, TREASURY_SYSTEM_ADDRESS, coin_output_nonce, consume_native_coin_selection,
    create_native_coin_output, native_coin_object, select_owned_native_coins,
};
use crate::error::{PokerL1Error, PokerL1Result};
#[cfg(test)]
use crate::object_model::Object;
use crate::object_model::{ObjectID, Ownership};
use crate::signature::TaggedPubkey;
use crate::storage::ObjectBackend;
#[cfg(test)]
use crate::storage::ObjectDb;
use crate::vm::contracts::dispatch::DispatchContext;
use crate::vm::precompile::{DispatchResult, ExecutionEnvironment, Precompile, reserved};

/// Texas Poker 合约预编译实现。
///
/// 将 `texas_poker::dispatch` 路由包装为 `Precompile` trait，
/// 通过固定 ObjectID（`reserved::texas_poker_contract_id()`）寻址。
#[derive(Debug, Clone)]
pub struct TexasPokerPrecompile {
    version: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContextStorageState {
    /// The table was already encoded as hot v30 and all three openings were loaded.
    Existing,
    /// This is the first create-table call.
    NewTable,
}

impl TexasPokerPrecompile {
    /// 创建 Texas Poker 合约预编译实例。
    #[must_use]
    pub fn new(version: u32) -> Self {
        Self { version }
    }

    /// 创建 Texas Poker 合约预编译实例（Arc 包装）。
    #[must_use]
    pub fn new_arc(version: u32) -> Arc<dyn Precompile> {
        Arc::new(Self::new(version))
    }

    fn decode_context_object<T: borsh::BorshDeserialize>(
        object_db: &dyn ObjectBackend,
        id: ObjectID,
        expected_type: &str,
        label: &str,
    ) -> PokerL1Result<T> {
        let object = object_db.read(&id)?;
        if object.object_type != expected_type || object.owner != Ownership::Immutable {
            return Err(PokerL1Error::Serialization(format!(
                "Texas {label} object has non-canonical type or ownership"
            )));
        }
        borsh::from_slice(&object.data).map_err(|error| {
            PokerL1Error::Serialization(format!("decode Texas {label} opening: {error}"))
        })
    }

    fn read_context_openings(
        object_db: &dyn ObjectBackend,
        table_id: ObjectID,
    ) -> PokerL1Result<TableContextOpenings> {
        use super::texas_poker::state_codec::{
            table_governance_object_id, table_metadata_object_id, table_rules_object_id,
        };

        let openings = TableContextOpenings {
            metadata: Self::decode_context_object(
                object_db,
                table_metadata_object_id(table_id),
                TEXAS_POKER_METADATA_OBJECT_TYPE,
                "metadata",
            )?,
            rules: Self::decode_context_object(
                object_db,
                table_rules_object_id(table_id),
                TEXAS_POKER_RULES_OBJECT_TYPE,
                "rules",
            )?,
            governance: Self::decode_context_object(
                object_db,
                table_governance_object_id(table_id),
                TEXAS_POKER_GOVERNANCE_OBJECT_TYPE,
                "governance",
            )?,
        };
        openings.validate_canonical()?;
        Ok(openings)
    }

    #[cfg(test)]
    fn context_objects(table: &TexasPokerTable) -> PokerL1Result<Vec<Object>> {
        Ok(
            super::texas_poker::state_codec::table_storage_objects(table)?
                .into_iter()
                .skip(1)
                .collect(),
        )
    }

    fn ensure_context_slots_absent(
        object_db: &dyn ObjectBackend,
        table_id: ObjectID,
    ) -> PokerL1Result<()> {
        use super::texas_poker::state_codec::{
            table_governance_object_id, table_metadata_object_id, table_rules_object_id,
        };
        for id in [
            table_metadata_object_id(table_id),
            table_rules_object_id(table_id),
            table_governance_object_id(table_id),
        ] {
            match object_db.read(&id) {
                Err(PokerL1Error::ObjectNotFound(_)) => {}
                Ok(_) => return Err(PokerL1Error::ObjectIDCollision(id)),
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Decode every native Coin output that must leave the Texas TableVault.
    ///
    /// Player stack refunds and rake have the same conservation requirement, but different
    /// recipients: rake is paid to the protocol-owned Treasury address.  The state machine has
    /// already subtracted every returned amount from `chip_pool`, while `RakeCollected` records
    /// the exact amount that must become a Treasury-owned UTXO in this transaction.
    fn escrow_outputs(return_value: &[u8]) -> PokerL1Result<Vec<(Address, u64)>> {
        let output: L1DispatchOutput = borsh::from_slice(return_value).map_err(|error| {
            PokerL1Error::Serialization(format!("decode Texas dispatch funding output: {error}"))
        })?;
        let mut outputs = Vec::new();
        for event in &output.events {
            match event {
                TexasPokerEvent::PlayerRefund {
                    player,
                    amount,
                    refund_type,
                    ..
                } => match *refund_type {
                    // STACK refunds leave the TableVault and therefore become wallet-owned
                    // UTXOs.
                    REFUND_TYPE_STACK_ONLY | REFUND_TYPE_STACK_AND_BET if *amount > 0 => {
                        outputs.push((*player, *amount));
                    }
                    // BET_ONLY is an in-table rollback: state_machine puts the value back into
                    // the seat stack while chip_pool remains unchanged. Creating a UTXO here
                    // would pay the same value twice and make the TableVault transition
                    // inconsistent.
                    REFUND_TYPE_BET_ONLY | REFUND_TYPE_STACK_ONLY | REFUND_TYPE_STACK_AND_BET => {}
                    unknown => {
                        return Err(PokerL1Error::Other(format!(
                            "unknown Texas refund type {unknown}"
                        )));
                    }
                },
                _ => {}
            }
        }
        if let Some(receipt) = output.settlement_treasury_receipt()? {
            outputs.push((TREASURY_SYSTEM_ADDRESS, receipt.amount));
        }
        Ok(outputs)
    }
}

impl Precompile for TexasPokerPrecompile {
    fn id(&self) -> ObjectID {
        reserved::texas_poker_contract_id()
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
        let dispatch_context = DispatchContext {
            caller: *caller,
            caller_pubkey: caller_pubkey.clone(),
            chain_id: env.chain_id,
            block_height: env.block_height,
            block_timestamp: env.block_timestamp,
        };

        let table_id = reserved::texas_poker_contract_id();

        // ObjectDb production state is hot v30 only. Resolved-v29 snapshots remain valid proof
        // payloads, but accepting them here would silently bypass independently authenticated
        // metadata/rules/governance openings.
        let (mut table, context_state) = match object_db.read(&table_id) {
            Ok(obj) => {
                if obj.object_type != TEXAS_POKER_TABLE_OBJECT_TYPE
                    || obj.owner != Ownership::Shared
                {
                    return Err(PokerL1Error::Serialization(
                        "Texas hot table has non-canonical type or ownership".into(),
                    ));
                }
                if !crate::vm::contracts::texas_poker::state_codec::is_hot_table_state(&obj.data) {
                    return Err(PokerL1Error::Serialization(
                        "Texas ObjectDb table must use hot v30 state".into(),
                    ));
                }
                let openings = Self::read_context_openings(object_db, table_id)?;
                let table = crate::vm::contracts::texas_poker::state_codec::decode_hot_table_state(
                    &obj.data, &openings,
                )?;
                (table, ContextStorageState::Existing)
            }
            Err(PokerL1Error::ObjectNotFound(_)) => {
                // 首次调用：仅 create_table 允许在无对象时执行
                if method_selector != &selectors::create_table() {
                    return Err(PokerL1Error::ContractNotFound(table_id));
                }
                // These IDs are deterministic.  Reject a partial/colliding context namespace
                // before dispatch or any economic mutation.
                Self::ensure_context_slots_absent(object_db, table_id)?;
                // 构造占位空表（dispatch_create_table 会用 args 覆写，含 creator 字段）
                let placeholder = TexasPokerTable::new(
                    table_id,
                    String::new(),
                    crate::vm::contracts::texas_poker::types::EMPTY_PLAYER,
                    2,
                    1,
                    1,
                );
                (placeholder, ContextStorageState::NewTable)
            }
            Err(e) => return Err(e),
        };

        let pre_locked = reconcile_table_vault(&table)?;
        let required_funding = tp_dispatch::required_funding(method_selector, args)?;
        let selected_coins: Option<NativeCoinSelection> = required_funding
            .map(|required| select_owned_native_coins(object_db, &env.tx_inputs, *caller, required))
            .transpose()?;

        let result = tp_dispatch::dispatch(&dispatch_context, &mut table, method_selector, args)?;
        let escrow_outputs = Self::escrow_outputs(&result.return_value)?;
        let total_escrow_outputs = escrow_outputs.iter().try_fold(0u64, |total, (_, amount)| {
            total
                .checked_add(*amount)
                .ok_or_else(|| PokerL1Error::Other("Texas escrow output sum overflow".into()))
        })?;
        let expected_locked = pre_locked
            .checked_add(required_funding.unwrap_or(0))
            .and_then(|value| value.checked_sub(total_escrow_outputs))
            .ok_or_else(|| {
                PokerL1Error::Other("Texas TableVault balance transition overflow".into())
            })?;
        if table.chip_pool != expected_locked {
            return Err(PokerL1Error::Other(format!(
                "Texas TableVault mismatch: pre={pre_locked}, funding={}, escrow_outputs={total_escrow_outputs}, post={}, expected={expected_locked}",
                required_funding.unwrap_or(0),
                table.chip_pool,
            )));
        }
        reconcile_table_vault(&table)?;

        // Preflight every deterministic output before consuming an input. Normal execution uses
        // WriteCaptureBackend and therefore rolls the complete transaction back on any later
        // error; this preflight also keeps the direct ObjectBackend path fail-before-write.
        let change_output = selected_coins
            .as_ref()
            .and_then(|selection| required_funding.map(|required| (selection, required)))
            .and_then(|(selection, required)| {
                selection
                    .total
                    .checked_sub(required)
                    .filter(|change| *change > 0)
            })
            .map(|change| native_coin_object(*caller, change, coin_output_nonce(&env.tx_hash, 0)))
            .transpose()?;
        if let Some(change) = &change_output {
            if object_db.read(&change.id).is_ok() {
                return Err(PokerL1Error::ObjectIDCollision(change.id));
            }
        }
        for (index, (player, amount)) in escrow_outputs.iter().enumerate() {
            let output_index = u32::try_from(index + 1)
                .map_err(|_| PokerL1Error::Other("too many Texas escrow outputs".into()))?;
            let payout = native_coin_object(
                *player,
                *amount,
                coin_output_nonce(&env.tx_hash, output_index),
            )?;
            if object_db.read(&payout.id).is_ok() {
                return Err(PokerL1Error::ObjectIDCollision(payout.id));
            }
        }

        let mut economic_created = Vec::new();
        if let (Some(selection), Some(required)) = (&selected_coins, required_funding) {
            if let Some(change_id) = consume_native_coin_selection(
                object_db,
                selection,
                *caller,
                required,
                &env.tx_hash,
                0,
            )? {
                economic_created.push(change_id);
            }
        }
        for (index, (player, amount)) in escrow_outputs.into_iter().enumerate() {
            let output_index = u32::try_from(index + 1)
                .map_err(|_| PokerL1Error::Other("too many Texas escrow outputs".into()))?;
            economic_created.push(create_native_coin_output(
                object_db,
                player,
                amount,
                &env.tx_hash,
                output_index,
            )?);
        }

        // Persist only the hot projection.  Immutable context openings are created once and are
        // never rewritten by hand-local transitions.
        let context_ids = crate::vm::contracts::texas_poker::state_codec::table_context_bindings(
            table.id,
            &TableContextOpenings::from_table(&table),
        )?;
        if context_state == ContextStorageState::NewTable {
            let objects =
                crate::vm::contracts::texas_poker::state_codec::table_storage_objects(&table)?;
            object_db.replace_objects(&[], objects.into_iter().collect())?;
        } else {
            let table_data =
                crate::vm::contracts::texas_poker::state_codec::encode_hot_table_state(&table)?;
            object_db.update(&table_id, caller, table_data)?;
        }

        let mut final_result = DispatchResult {
            created_objects: result.created_objects,
            modified_objects: result.modified_objects,
            // Existing execution reads the hot state plus all immutable openings.  Creation only
            // performs absence checks, so it has no successful object reads.
            read_objects: if context_state == ContextStorageState::NewTable {
                vec![]
            } else {
                vec![
                    table_id,
                    context_ids.metadata.object_id,
                    context_ids.rules.object_id,
                    context_ids.governance.object_id,
                ]
            },
            return_value: result.return_value,
        };
        final_result.created_objects.extend(economic_created);
        final_result
            .read_objects
            .extend(env.tx_inputs.iter().copied());
        if context_state == ContextStorageState::NewTable {
            for id in [
                table_id,
                context_ids.metadata.object_id,
                context_ids.rules.object_id,
                context_ids.governance.object_id,
            ] {
                if !final_result.created_objects.contains(&id) {
                    final_result.created_objects.push(id);
                }
            }
        }

        Ok(final_result)
    }

    fn supports_selector(&self, selector: &[u8; 32]) -> bool {
        selectors::active().contains(selector)
    }

    fn gas_cost(&self, selector: &[u8; 32], args: &[u8]) -> u64 {
        let dispatch_cost = crate::vm::gas_table::precompile_gas(args.len() as u64);
        let performs_native_crypto = *selector == selectors::submit_shuffle_v2()
            || *selector == selectors::submit_player_reveal_tokens()
            || *selector == selectors::submit_reconstruct_deck()
            || *selector == selectors::fold_with_proof();
        if performs_native_crypto {
            dispatch_cost.saturating_add(crate::vm::gas_table::GAS_STWO_VERIFY)
        } else {
            dispatch_cost
        }
    }

    /// Texas Poker 合约预编译免 caller fee（GameTurn 通道）。
    ///
    /// 反滥用由以下机制保障：
    /// - `gameturn_nonce` per-game per-player 重放保护
    /// - 轮次约束（routing.rs：`validate_turn_order`）
    /// - assigned_validator 路由（routing.rs：`validate_assigned_validator`）
    fn is_gas_free(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::economics::{
        TREASURY_SYSTEM_ADDRESS, coin_output_nonce, decode_native_coin, genesis_mint,
        list_owned_native_coins, native_coin_object, read_treasury, reconcile_native_supply,
    };
    use crate::executor::write_capture::WriteCaptureBackend;
    use crate::object_model::Version;
    use crate::signature::TaggedPubkey;
    use crate::vm::contracts::texas_poker::dispatch::{
        AddonArgs, CreateTableArgs, JoinTableArgs, LeaveTableArgs, RebuyArgs, SeatIndexArgs,
    };
    use crate::vm::contracts::texas_poker::types::SeatStatus;
    use crate::vm::contracts::texas_poker::{betting::BettingRound, constants::ROUND_PREFLOP};

    fn make_env() -> ExecutionEnvironment {
        ExecutionEnvironment {
            chain_id: 1,
            block_height: 100,
            block_timestamp: 1_000_000,
            tx_inputs: vec![],
            tx_hash: [0u8; 32],
        }
    }

    fn make_caller() -> (Address, TaggedPubkey) {
        (
            [0xAA; 20],
            TaggedPubkey {
                tag: 0,
                raw: vec![0xBB; 32],
            },
        )
    }

    fn join_args(player: Address, buy_in: u64, secret: u64) -> JoinTableArgs {
        JoinTableArgs::with_key(
            player,
            buy_in,
            crate::vm::contracts::texas_poker::utils::scalar_from_u64(secret),
            crate::vm::contracts::texas_poker::utils::scalar_from_u64(secret + 20_000),
        )
        .unwrap()
    }

    fn read_resolved_table(object_db: &dyn ObjectBackend, table_id: ObjectID) -> TexasPokerTable {
        let object = object_db.read(&table_id).unwrap();
        let openings = TexasPokerPrecompile::read_context_openings(object_db, table_id).unwrap();
        crate::vm::contracts::texas_poker::state_codec::decode_hot_table_state(
            &object.data,
            &openings,
        )
        .unwrap()
    }

    fn write_resolved_table(
        object_db: &mut dyn ObjectBackend,
        actor: &Address,
        table: &TexasPokerTable,
    ) {
        let bytes =
            crate::vm::contracts::texas_poker::state_codec::encode_hot_table_state(table).unwrap();
        object_db.update(&table.id, actor, bytes).unwrap();
    }

    /// Test-only fixture replacement for cases that need non-default immutable rules.  Production
    /// has no context mutation path: these values are fixed by table creation/governance design.
    fn replace_resolved_table_fixture(
        object_db: &mut ObjectDb,
        actor: &Address,
        table: &TexasPokerTable,
    ) {
        use crate::vm::contracts::texas_poker::state_codec::{
            table_governance_object_id, table_metadata_object_id, table_rules_object_id,
        };
        for id in [
            table_metadata_object_id(table.id),
            table_rules_object_id(table.id),
            table_governance_object_id(table.id),
        ] {
            object_db.delete(&id).unwrap();
        }
        for object in TexasPokerPrecompile::context_objects(table).unwrap() {
            object_db.create(object).unwrap();
        }
        write_resolved_table(object_db, actor, table);
    }

    #[test]
    fn test_texas_poker_precompile_id() {
        let precompile = TexasPokerPrecompile::new(1);
        let expected = reserved::texas_poker_contract_id();
        assert_eq!(precompile.id(), expected);
    }

    #[test]
    fn test_texas_poker_precompile_version() {
        let precompile = TexasPokerPrecompile::new(3);
        assert_eq!(precompile.version(), 3);
    }

    #[test]
    fn test_texas_poker_precompile_supports_known_selector() {
        let precompile = TexasPokerPrecompile::new(1);
        assert!(precompile.supports_selector(&selectors::create_table()));
        assert!(precompile.supports_selector(&selectors::join_table()));
        assert!(precompile.supports_selector(&selectors::fold()));
        assert!(!precompile.supports_selector(
            &crate::vm::contracts::texas_poker::dispatch::compute_method_selector("tick")
        ));
        assert!(precompile.supports_selector(&selectors::advance_deadline()));
        assert!(!precompile.supports_selector(
            &crate::vm::contracts::texas_poker::dispatch::compute_method_selector("kick_player")
        ));
        assert!(precompile.supports_selector(&selectors::kick_player_v2()));
        assert!(!precompile.supports_selector(
            &crate::vm::contracts::texas_poker::dispatch::compute_method_selector(
                "join_and_shuffle",
            )
        ));
        assert!(!precompile.supports_selector(
            &crate::vm::contracts::texas_poker::dispatch::compute_method_selector(
                "leave_with_proof",
            )
        ));
        assert!(!precompile.supports_selector(
            &crate::vm::contracts::texas_poker::dispatch::compute_method_selector("auto_fold")
        ));
        assert!(!precompile.supports_selector(
            &crate::vm::contracts::texas_poker::dispatch::compute_method_selector(
                "reset_for_next_hand",
            )
        ));
    }

    #[test]
    fn test_texas_poker_precompile_rejects_unknown_selector() {
        let precompile = TexasPokerPrecompile::new(1);
        let unknown = [0xFE; 32];
        assert!(!precompile.supports_selector(&unknown));
    }

    #[test]
    fn test_texas_poker_precompile_is_gas_free() {
        let precompile = TexasPokerPrecompile::new(1);
        assert!(precompile.is_gas_free());
    }

    #[test]
    fn bet_only_refund_stays_inside_table_vault() {
        let table_id = reserved::texas_poker_contract_id();
        let player = [0x44; 20];
        let output = L1DispatchOutput::events_only(vec![TexasPokerEvent::PlayerRefund {
            table_id,
            seat_index: 2,
            player,
            amount: 75,
            refund_type: REFUND_TYPE_BET_ONLY,
        }]);

        let encoded = borsh::to_vec(&output).unwrap();
        assert!(
            TexasPokerPrecompile::escrow_outputs(&encoded)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn stack_refunds_leave_table_vault_but_unknown_types_fail_closed() {
        let table_id = reserved::texas_poker_contract_id();
        let player = [0x55; 20];
        for refund_type in [REFUND_TYPE_STACK_ONLY, REFUND_TYPE_STACK_AND_BET] {
            let output = L1DispatchOutput::events_only(vec![TexasPokerEvent::PlayerRefund {
                table_id,
                seat_index: 1,
                player,
                amount: 90,
                refund_type,
            }]);
            let encoded = borsh::to_vec(&output).unwrap();
            assert_eq!(
                TexasPokerPrecompile::escrow_outputs(&encoded).unwrap(),
                vec![(player, 90)]
            );
        }

        let unknown = L1DispatchOutput::events_only(vec![TexasPokerEvent::PlayerRefund {
            table_id,
            seat_index: 1,
            player,
            amount: 90,
            refund_type: u8::MAX,
        }]);
        let error =
            TexasPokerPrecompile::escrow_outputs(&borsh::to_vec(&unknown).unwrap()).unwrap_err();
        assert!(error.to_string().contains("unknown Texas refund type"));
    }

    #[test]
    fn rake_event_creates_a_treasury_escrow_output() {
        let table_id = reserved::texas_poker_contract_id();
        let output = L1DispatchOutput::events_only(vec![
            TexasPokerEvent::SettlementPlanCommitted {
                table_id,
                plan_digest: [7; 32],
                runout_count: 1,
                gross_pot: 200,
                rake: 10,
                total_awards: 190,
            },
            TexasPokerEvent::RakeCollected {
                table_id,
                pot_before: 200,
                rake_amount: 10,
                pot_after: 190,
                rake_mode: 1,
            },
        ]);

        assert_eq!(
            TexasPokerPrecompile::escrow_outputs(&borsh::to_vec(&output).unwrap()).unwrap(),
            vec![(TREASURY_SYSTEM_ADDRESS, 10)]
        );
    }

    #[test]
    fn rake_receipt_must_be_unique_and_match_the_settlement_plan() {
        let table_id = reserved::texas_poker_contract_id();
        let plan = TexasPokerEvent::SettlementPlanCommitted {
            table_id,
            plan_digest: [9; 32],
            runout_count: 1,
            gross_pot: 200,
            rake: 10,
            total_awards: 190,
        };
        let rake = TexasPokerEvent::RakeCollected {
            table_id,
            pot_before: 200,
            rake_amount: 10,
            pot_after: 190,
            rake_mode: 1,
        };

        for events in [
            vec![rake.clone()],
            vec![plan.clone()],
            vec![plan.clone(), rake.clone(), rake.clone()],
            vec![
                plan,
                TexasPokerEvent::RakeCollected {
                    table_id,
                    pot_before: 200,
                    rake_amount: 9,
                    pot_after: 190,
                    rake_mode: 1,
                },
            ],
        ] {
            let output = L1DispatchOutput::events_only(events);
            assert!(
                TexasPokerPrecompile::escrow_outputs(&borsh::to_vec(&output).unwrap()).is_err()
            );
        }
    }

    #[test]
    fn test_texas_poker_precompile_create_table_first_call() {
        use crate::storage::object_db::ObjectDb;
        let precompile = TexasPokerPrecompile::new(1);
        let env = make_env();
        let (caller, caller_pk) = make_caller();
        let mut object_db = ObjectDb::open_inmemory().unwrap();
        let table_id = reserved::texas_poker_contract_id();

        // 首次调用：create_table（对象不存在）
        let args = CreateTableArgs {
            name: "first_game".into(),
            max_players: 6,
            small_blind: 25,
            big_blind: 50,
        };
        let args_bytes = borsh::to_vec(&args).unwrap();
        let result = precompile
            .call(
                &caller,
                &caller_pk,
                &selectors::create_table(),
                &args_bytes,
                &env,
                &mut object_db,
            )
            .unwrap();

        use crate::vm::contracts::texas_poker::state_codec::{
            is_hot_table_state, table_governance_object_id, table_metadata_object_id,
            table_rules_object_id,
        };
        let context_ids = [
            table_metadata_object_id(table_id),
            table_rules_object_id(table_id),
            table_governance_object_id(table_id),
        ];
        for id in [table_id, context_ids[0], context_ids[1], context_ids[2]] {
            assert!(result.created_objects.contains(&id));
        }
        // ObjectDb stores only hot mutable state.  Full values are recovered from immutable
        // context openings and are deliberately not decodable from the hot object alone.
        let obj = object_db.read(&table_id).unwrap();
        assert!(is_hot_table_state(&obj.data));
        assert!(borsh::from_slice::<TexasPokerTable>(&obj.data).is_err());
        for id in context_ids {
            assert_eq!(object_db.read(&id).unwrap().owner, Ownership::Immutable);
        }
        let table = read_resolved_table(&object_db, table_id);
        assert_eq!(table.name, "first_game");
        assert_eq!(table.max_players, 6);
        assert_eq!(table.big_blind, 50);
    }

    #[test]
    fn test_texas_poker_precompile_non_create_first_call_rejected() {
        use crate::storage::object_db::ObjectDb;
        let precompile = TexasPokerPrecompile::new(1);
        let env = make_env();
        let (caller, caller_pk) = make_caller();
        let mut object_db = ObjectDb::open_inmemory().unwrap();

        // 首次调用非 create_table → ContractNotFound
        let result = precompile.call(
            &caller,
            &caller_pk,
            &selectors::start_hand(),
            &[],
            &env,
            &mut object_db,
        );
        assert!(matches!(result, Err(PokerL1Error::ContractNotFound(_))));
    }

    fn create_test_table(
        precompile: &TexasPokerPrecompile,
        caller: &Address,
        caller_pk: &TaggedPubkey,
        object_db: &mut ObjectDb,
    ) {
        let args = borsh::to_vec(&CreateTableArgs {
            name: "funded_game".into(),
            max_players: 6,
            small_blind: 25,
            big_blind: 50,
        })
        .unwrap();
        precompile
            .call(
                caller,
                caller_pk,
                &selectors::create_table(),
                &args,
                &make_env(),
                object_db,
            )
            .unwrap();
    }

    #[test]
    fn context_openings_are_required_and_digest_bound() {
        use crate::vm::contracts::texas_poker::state_codec::{
            table_governance_object_id, table_metadata_object_id, table_rules_object_id,
        };
        let precompile = TexasPokerPrecompile::new(1);
        let (caller, caller_pk) = make_caller();
        let table_id = reserved::texas_poker_contract_id();
        let context_ids = [
            table_metadata_object_id(table_id),
            table_rules_object_id(table_id),
            table_governance_object_id(table_id),
        ];

        for context_id in context_ids {
            let mut object_db = ObjectDb::open_inmemory().unwrap();
            create_test_table(&precompile, &caller, &caller_pk, &mut object_db);
            let mut context = object_db.delete(&context_id).unwrap();
            *context.data.last_mut().unwrap() ^= 1;
            object_db.create(context).unwrap();

            let error = precompile
                .call(
                    &caller,
                    &caller_pk,
                    &selectors::start_hand(),
                    &[],
                    &make_env(),
                    &mut object_db,
                )
                .unwrap_err();
            assert!(
                error.to_string().contains("binding/opening mismatch"),
                "unexpected error for {context_id:?}: {error}"
            );
        }
    }

    #[test]
    fn missing_or_non_canonical_context_objects_fail_closed() {
        use crate::vm::contracts::texas_poker::state_codec::table_rules_object_id;
        let precompile = TexasPokerPrecompile::new(1);
        let (caller, caller_pk) = make_caller();
        let table_id = reserved::texas_poker_contract_id();
        let rules_id = table_rules_object_id(table_id);

        let mut missing_db = ObjectDb::open_inmemory().unwrap();
        create_test_table(&precompile, &caller, &caller_pk, &mut missing_db);
        missing_db.delete(&rules_id).unwrap();
        assert!(matches!(
            precompile.call(
                &caller,
                &caller_pk,
                &selectors::start_hand(),
                &[],
                &make_env(),
                &mut missing_db,
            ),
            Err(PokerL1Error::ObjectNotFound(id)) if id == rules_id
        ));

        for corrupt_owner in [false, true] {
            let mut object_db = ObjectDb::open_inmemory().unwrap();
            create_test_table(&precompile, &caller, &caller_pk, &mut object_db);
            let mut rules = object_db.delete(&rules_id).unwrap();
            if corrupt_owner {
                rules.owner = Ownership::Shared;
            } else {
                rules.object_type = "WrongTexasRulesType".into();
            }
            object_db.create(rules).unwrap();
            let error = precompile
                .call(
                    &caller,
                    &caller_pk,
                    &selectors::start_hand(),
                    &[],
                    &make_env(),
                    &mut object_db,
                )
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("non-canonical type or ownership")
            );
        }
    }

    #[test]
    fn old_resolved_objectdb_layout_and_failed_create_are_rejected_without_partial_context() {
        use crate::vm::contracts::texas_poker::state_codec::{
            encode_table_state, table_governance_object_id, table_metadata_object_id,
            table_rules_object_id,
        };
        let precompile = TexasPokerPrecompile::new(1);
        let (caller, caller_pk) = make_caller();
        let table_id = reserved::texas_poker_contract_id();

        let mut legacy_db = ObjectDb::open_inmemory().unwrap();
        let legacy = TexasPokerTable::new(table_id, "legacy".into(), caller, 6, 25, 50);
        legacy_db
            .create(Object::new(
                table_id,
                Ownership::Shared,
                TEXAS_POKER_TABLE_OBJECT_TYPE,
                encode_table_state(&legacy).unwrap(),
                None,
            ))
            .unwrap();
        let error = precompile
            .call(
                &caller,
                &caller_pk,
                &selectors::start_hand(),
                &[],
                &make_env(),
                &mut legacy_db,
            )
            .unwrap_err();
        assert!(error.to_string().contains("must use hot v30 state"));

        let mut failed_create_db = ObjectDb::open_inmemory().unwrap();
        let invalid_args = borsh::to_vec(&CreateTableArgs {
            name: "invalid".into(),
            max_players: 1,
            small_blind: 25,
            big_blind: 50,
        })
        .unwrap();
        assert!(
            precompile
                .call(
                    &caller,
                    &caller_pk,
                    &selectors::create_table(),
                    &invalid_args,
                    &make_env(),
                    &mut failed_create_db,
                )
                .is_err()
        );
        for id in [
            table_id,
            table_metadata_object_id(table_id),
            table_rules_object_id(table_id),
            table_governance_object_id(table_id),
        ] {
            assert!(failed_create_db.read(&id).is_err());
        }
    }

    fn create_funded_table(
        precompile: &TexasPokerPrecompile,
        caller: &Address,
        caller_pk: &TaggedPubkey,
        total_supply: u64,
    ) -> (ObjectDb, ObjectID) {
        let mut object_db = ObjectDb::open_inmemory().unwrap();
        genesis_mint(&mut object_db, 1, &[(*caller, total_supply)]).unwrap();
        create_test_table(precompile, caller, caller_pk, &mut object_db);
        let coins = list_owned_native_coins(&object_db, *caller).unwrap();
        assert_eq!(coins.len(), 1);
        (object_db, coins[0].id)
    }

    fn funded_join(
        precompile: &TexasPokerPrecompile,
        caller: &Address,
        caller_pk: &TaggedPubkey,
        object_db: &mut ObjectDb,
        input_id: ObjectID,
        buy_in: u64,
        tx_hash: [u8; 32],
    ) -> ObjectID {
        let join_args = borsh::to_vec(&join_args(*caller, buy_in, 1)).unwrap();
        precompile
            .call(
                caller,
                caller_pk,
                &selectors::join_table(),
                &join_args,
                &ExecutionEnvironment {
                    tx_inputs: vec![input_id],
                    tx_hash,
                    ..make_env()
                },
                object_db,
            )
            .unwrap();
        ObjectID::new(*caller, coin_output_nonce(&tx_hash, 0))
    }

    struct FailTableUpdateBackend<'a> {
        inner: WriteCaptureBackend<'a>,
        table_id: ObjectID,
    }

    impl ObjectBackend for FailTableUpdateBackend<'_> {
        fn create(&mut self, object: Object) -> PokerL1Result<()> {
            self.inner.create(object)
        }

        fn read(&self, id: &ObjectID) -> PokerL1Result<Object> {
            self.inner.read(id)
        }

        fn version_of(&self, id: &ObjectID) -> PokerL1Result<Version> {
            self.inner.version_of(id)
        }

        fn update(
            &mut self,
            id: &ObjectID,
            actor: &Address,
            new_data: Vec<u8>,
        ) -> PokerL1Result<()> {
            if id == &self.table_id {
                return Err(PokerL1Error::Other(
                    "injected table persistence failure".into(),
                ));
            }
            self.inner.update(id, actor, new_data)
        }

        fn transfer(
            &mut self,
            id: &ObjectID,
            actor: &Address,
            new_owner: Address,
        ) -> PokerL1Result<()> {
            self.inner.transfer(id, actor, new_owner)
        }

        fn delete(&mut self, id: &ObjectID) -> PokerL1Result<Object> {
            self.inner.delete(id)
        }

        fn replace_objects(
            &mut self,
            delete_ids: &[ObjectID],
            create_objects: Vec<Object>,
        ) -> PokerL1Result<()> {
            self.inner.replace_objects(delete_ids, create_objects)
        }

        fn state_root(&self) -> crate::Hash {
            self.inner.state_root()
        }
    }

    #[test]
    fn funded_join_creates_change_and_leave_creates_payout() {
        let precompile = TexasPokerPrecompile::new(1);
        let (caller, caller_pk) = make_caller();
        let mut object_db = ObjectDb::open_inmemory().unwrap();
        create_test_table(&precompile, &caller, &caller_pk, &mut object_db);

        let input = native_coin_object(caller, 150, 77).unwrap();
        object_db.create(input.clone()).unwrap();
        let join_hash = [0x11; 32];
        let join_env = ExecutionEnvironment {
            tx_inputs: vec![input.id],
            tx_hash: join_hash,
            ..make_env()
        };
        let join_args = borsh::to_vec(&join_args(caller, 100, 1)).unwrap();

        let result = precompile
            .call(
                &caller,
                &caller_pk,
                &selectors::join_table(),
                &join_args,
                &join_env,
                &mut object_db,
            )
            .unwrap();

        assert!(object_db.read(&input.id).is_err());
        let change_id = ObjectID::new(caller, coin_output_nonce(&join_hash, 0));
        assert!(result.created_objects.contains(&change_id));
        assert_eq!(
            decode_native_coin(&object_db.read(&change_id).unwrap())
                .unwrap()
                .amount,
            50
        );
        let table_id = reserved::texas_poker_contract_id();
        let table = read_resolved_table(&object_db, table_id);
        assert_eq!(table.chip_pool, 100);
        assert_eq!(table.seats[0].stack(), 100);

        let leave_hash = [0x22; 32];
        let leave_env = ExecutionEnvironment {
            tx_hash: leave_hash,
            ..make_env()
        };
        let leave_args = borsh::to_vec(&LeaveTableArgs { seat_index: 0 }).unwrap();
        let result = precompile
            .call(
                &caller,
                &caller_pk,
                &selectors::leave_table(),
                &leave_args,
                &leave_env,
                &mut object_db,
            )
            .unwrap();

        let payout_id = ObjectID::new(caller, coin_output_nonce(&leave_hash, 1));
        assert!(result.created_objects.contains(&payout_id));
        assert_eq!(
            decode_native_coin(&object_db.read(&payout_id).unwrap())
                .unwrap()
                .amount,
            100
        );
        let table = read_resolved_table(&object_db, table_id);
        assert_eq!(table.chip_pool, 0);
        assert!(!table.seats[0].is_occupied());
    }

    #[test]
    fn rake_settlement_pays_treasury_once_and_preserves_native_supply() {
        let precompile = TexasPokerPrecompile::new(1);
        let (player_a, player_a_pk) = make_caller();
        let player_b = [0xBC; 20];
        let player_b_pk = TaggedPubkey {
            tag: 0,
            raw: vec![0xCD; 32],
        };
        let mut object_db = ObjectDb::open_inmemory().unwrap();
        genesis_mint(&mut object_db, 1, &[(player_a, 100), (player_b, 100)]).unwrap();
        create_test_table(&precompile, &player_a, &player_a_pk, &mut object_db);

        let a_coin = list_owned_native_coins(&object_db, player_a).unwrap()[0].id;
        funded_join(
            &precompile,
            &player_a,
            &player_a_pk,
            &mut object_db,
            a_coin,
            100,
            [0x71; 32],
        );
        let b_coin = list_owned_native_coins(&object_db, player_b).unwrap()[0].id;
        let b_join_args = borsh::to_vec(&join_args(player_b, 100, 2)).unwrap();
        precompile
            .call(
                &player_b,
                &player_b_pk,
                &selectors::join_table(),
                &b_join_args,
                &ExecutionEnvironment {
                    tx_inputs: vec![b_coin],
                    tx_hash: [0x72; 32],
                    ..make_env()
                },
                &mut object_db,
            )
            .unwrap();

        // Build a valid two-player all-in pot from the funded table. Folding player A ends the
        // hand, charges 5% rake, and exercises the same precompile path as production settlement.
        let table_id = reserved::texas_poker_contract_id();
        let mut table = read_resolved_table(&object_db, table_id);
        table
            .enter_betting(ROUND_PREFLOP, BettingRound::new(50, 100), 0, 0)
            .unwrap();
        table.arm_betting_deadline(1).unwrap();
        table.pot = 200;
        table.rake_mode = crate::vm::contracts::texas_poker::constants::RAKE_MODE_PERCENTAGE;
        table.rake_bps = 500;
        table.rake_cap = 100;
        for seat in table.seats.iter_mut().take(2) {
            seat.set_stack(0).unwrap();
            seat.fixture_set_bet(0);
            seat.fixture_set_total_bet(100);
            seat.set_status(SeatStatus::Active);
        }
        replace_resolved_table_fixture(&mut object_db, &player_a, &table);

        // A later persistence failure must roll back the Treasury output together with the
        // state transition.  This exercises the failure point after the rake UTXO has been
        // staged, not just the deterministic-output collision preflight.
        let table_before = object_db.read(&table_id).unwrap();
        let treasury_before = read_treasury(&object_db).unwrap();
        let root_before = object_db.state_root();
        let failed_settlement_hash = [0x75; 32];
        let error = {
            let mut backend = FailTableUpdateBackend {
                inner: WriteCaptureBackend::new(&object_db),
                table_id,
            };
            precompile
                .call(
                    &player_a,
                    &player_a_pk,
                    &selectors::fold(),
                    &borsh::to_vec(&SeatIndexArgs { seat_index: 0 }).unwrap(),
                    &ExecutionEnvironment {
                        tx_hash: failed_settlement_hash,
                        ..make_env()
                    },
                    &mut backend,
                )
                .unwrap_err()
        };
        assert!(
            error
                .to_string()
                .contains("injected table persistence failure")
        );
        assert_eq!(object_db.read(&table_id).unwrap(), table_before);
        assert_eq!(read_treasury(&object_db).unwrap(), treasury_before);
        assert_eq!(object_db.state_root(), root_before);
        let discarded_treasury_coin = ObjectID::new(
            TREASURY_SYSTEM_ADDRESS,
            coin_output_nonce(&failed_settlement_hash, 1),
        );
        assert!(object_db.read(&discarded_treasury_coin).is_err());
        assert!(
            list_owned_native_coins(&object_db, TREASURY_SYSTEM_ADDRESS)
                .unwrap()
                .is_empty()
        );
        reconcile_native_supply(&object_db, 0).unwrap();

        let settlement_hash = [0x73; 32];
        let result = precompile
            .call(
                &player_a,
                &player_a_pk,
                &selectors::fold(),
                &borsh::to_vec(&SeatIndexArgs { seat_index: 0 }).unwrap(),
                &ExecutionEnvironment {
                    tx_hash: settlement_hash,
                    ..make_env()
                },
                &mut object_db,
            )
            .unwrap();

        let treasury_coin = ObjectID::new(
            TREASURY_SYSTEM_ADDRESS,
            coin_output_nonce(&settlement_hash, 1),
        );
        assert!(result.created_objects.contains(&treasury_coin));
        assert_eq!(
            decode_native_coin(&object_db.read(&treasury_coin).unwrap())
                .unwrap()
                .amount,
            10
        );
        let stored = read_resolved_table(&object_db, table_id);
        let prove_task = borsh::from_slice::<L1DispatchOutput>(&result.return_value)
            .unwrap()
            .prove_task
            .expect("settling fold must issue a proof task");
        assert_eq!(prove_task.post_table, stored);
        assert_eq!(stored.chip_pool, 190);
        assert_eq!(stored.seats[1].stack(), 190);
        reconcile_table_vault(&stored).unwrap();
        reconcile_native_supply(&object_db, 0).unwrap();

        // The finished hand cannot be paid twice: the folded player has been removed during
        // reset, so a replayed action fails before any extra Treasury output is created.
        assert!(
            precompile
                .call(
                    &player_a,
                    &player_a_pk,
                    &selectors::fold(),
                    &borsh::to_vec(&SeatIndexArgs { seat_index: 0 }).unwrap(),
                    &ExecutionEnvironment {
                        tx_hash: [0x74; 32],
                        ..make_env()
                    },
                    &mut object_db,
                )
                .is_err()
        );
        assert_eq!(
            list_owned_native_coins(&object_db, TREASURY_SYSTEM_ADDRESS)
                .unwrap()
                .len(),
            1
        );
        reconcile_native_supply(&object_db, 0).unwrap();
    }

    #[test]
    fn funded_join_without_coin_input_is_rejected_without_table_mutation() {
        let precompile = TexasPokerPrecompile::new(1);
        let (caller, caller_pk) = make_caller();
        let mut object_db = ObjectDb::open_inmemory().unwrap();
        create_test_table(&precompile, &caller, &caller_pk, &mut object_db);
        let table_id = reserved::texas_poker_contract_id();
        let table_before = object_db.read(&table_id).unwrap();
        let join_args = borsh::to_vec(&join_args(caller, 100, 1)).unwrap();

        let error = precompile
            .call(
                &caller,
                &caller_pk,
                &selectors::join_table(),
                &join_args,
                &make_env(),
                &mut object_db,
            )
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("requires at least one native coin input")
        );
        assert_eq!(object_db.read(&table_id).unwrap(), table_before);
    }

    #[test]
    fn funded_addon_consumes_input_creates_change_and_updates_all_vaults() {
        let precompile = TexasPokerPrecompile::new(1);
        let (caller, caller_pk) = make_caller();
        let (mut object_db, genesis_coin) =
            create_funded_table(&precompile, &caller, &caller_pk, 300);
        let join_change = funded_join(
            &precompile,
            &caller,
            &caller_pk,
            &mut object_db,
            genesis_coin,
            100,
            [0x31; 32],
        );
        let treasury_before = read_treasury(&object_db).unwrap();

        let addon_hash = [0x32; 32];
        let addon_args = borsh::to_vec(&AddonArgs {
            seat_index: 0,
            amount: 60,
        })
        .unwrap();
        let result = precompile
            .call(
                &caller,
                &caller_pk,
                &selectors::addon(),
                &addon_args,
                &ExecutionEnvironment {
                    tx_inputs: vec![join_change],
                    tx_hash: addon_hash,
                    ..make_env()
                },
                &mut object_db,
            )
            .unwrap();

        assert!(object_db.read(&join_change).is_err());
        let addon_change = ObjectID::new(caller, coin_output_nonce(&addon_hash, 0));
        assert!(result.created_objects.contains(&addon_change));
        assert_eq!(
            decode_native_coin(&object_db.read(&addon_change).unwrap())
                .unwrap()
                .amount,
            140
        );
        let table = read_resolved_table(&object_db, reserved::texas_poker_contract_id());
        assert_eq!(table.seats[0].stack(), 100);
        assert_eq!(table.seats[0].pending_addon(), 60);
        assert_eq!(table.chip_pool, 160);
        assert_eq!(
            table
                .seats
                .iter()
                .map(|seat| seat.pending_addon())
                .sum::<u64>(),
            60
        );
        assert_eq!(read_treasury(&object_db).unwrap(), treasury_before);
    }

    #[test]
    fn funded_rebuy_consumes_input_creates_change_and_preserves_pending_addons() {
        let precompile = TexasPokerPrecompile::new(1);
        let (caller, caller_pk) = make_caller();
        let (mut object_db, genesis_coin) =
            create_funded_table(&precompile, &caller, &caller_pk, 300);
        let join_change = funded_join(
            &precompile,
            &caller,
            &caller_pk,
            &mut object_db,
            genesis_coin,
            100,
            [0x41; 32],
        );
        let treasury_before = read_treasury(&object_db).unwrap();

        let rebuy_hash = [0x42; 32];
        let rebuy_args = borsh::to_vec(&RebuyArgs {
            seat_index: 0,
            amount: 70,
        })
        .unwrap();
        precompile
            .call(
                &caller,
                &caller_pk,
                &selectors::rebuy(),
                &rebuy_args,
                &ExecutionEnvironment {
                    tx_inputs: vec![join_change],
                    tx_hash: rebuy_hash,
                    ..make_env()
                },
                &mut object_db,
            )
            .unwrap();

        assert!(object_db.read(&join_change).is_err());
        let rebuy_change = ObjectID::new(caller, coin_output_nonce(&rebuy_hash, 0));
        assert_eq!(
            decode_native_coin(&object_db.read(&rebuy_change).unwrap())
                .unwrap()
                .amount,
            130
        );
        let table = read_resolved_table(&object_db, reserved::texas_poker_contract_id());
        assert_eq!(table.seats[0].stack(), 170);
        assert_eq!(table.seats[0].pending_addon(), 0);
        assert_eq!(table.chip_pool, 170);
        assert_eq!(
            table
                .seats
                .iter()
                .map(|seat| seat.pending_addon())
                .sum::<u64>(),
            0
        );
        assert_eq!(read_treasury(&object_db).unwrap(), treasury_before);
    }

    #[test]
    fn leave_after_pending_addon_refunds_stack_and_pending_addon() {
        let precompile = TexasPokerPrecompile::new(1);
        let (caller, caller_pk) = make_caller();
        let (mut object_db, genesis_coin) =
            create_funded_table(&precompile, &caller, &caller_pk, 300);
        let join_change = funded_join(
            &precompile,
            &caller,
            &caller_pk,
            &mut object_db,
            genesis_coin,
            100,
            [0x51; 32],
        );
        let addon_hash = [0x52; 32];
        let addon_args = borsh::to_vec(&AddonArgs {
            seat_index: 0,
            amount: 60,
        })
        .unwrap();
        precompile
            .call(
                &caller,
                &caller_pk,
                &selectors::addon(),
                &addon_args,
                &ExecutionEnvironment {
                    tx_inputs: vec![join_change],
                    tx_hash: addon_hash,
                    ..make_env()
                },
                &mut object_db,
            )
            .unwrap();

        let leave_hash = [0x53; 32];
        let leave_args = borsh::to_vec(&LeaveTableArgs { seat_index: 0 }).unwrap();
        precompile
            .call(
                &caller,
                &caller_pk,
                &selectors::leave_table(),
                &leave_args,
                &ExecutionEnvironment {
                    tx_hash: leave_hash,
                    ..make_env()
                },
                &mut object_db,
            )
            .unwrap();

        let payout_id = ObjectID::new(caller, coin_output_nonce(&leave_hash, 1));
        assert_eq!(
            decode_native_coin(&object_db.read(&payout_id).unwrap())
                .unwrap()
                .amount,
            160
        );
        let addon_change = ObjectID::new(caller, coin_output_nonce(&addon_hash, 0));
        assert_eq!(
            decode_native_coin(&object_db.read(&addon_change).unwrap())
                .unwrap()
                .amount,
            140
        );
        let table = read_resolved_table(&object_db, reserved::texas_poker_contract_id());
        assert_eq!(table.chip_pool, 0);
        assert_eq!(
            table
                .seats
                .iter()
                .map(|seat| seat.pending_addon())
                .sum::<u64>(),
            0
        );
        assert!(!table.seats[0].is_occupied());
        assert_eq!(
            read_treasury(&object_db).unwrap().unwrap().total_supply,
            300
        );
    }

    #[test]
    fn join_addon_rebuy_leave_preserves_wallet_vault_and_treasury() {
        let precompile = TexasPokerPrecompile::new(1);
        let (caller, caller_pk) = make_caller();
        let (mut object_db, genesis_coin) =
            create_funded_table(&precompile, &caller, &caller_pk, 400);
        let treasury_before = read_treasury(&object_db).unwrap();

        let join_hash = [0x81; 32];
        let join_change = funded_join(
            &precompile,
            &caller,
            &caller_pk,
            &mut object_db,
            genesis_coin,
            100,
            join_hash,
        );
        assert_eq!(
            decode_native_coin(&object_db.read(&join_change).unwrap())
                .unwrap()
                .amount,
            300
        );

        let addon_hash = [0x82; 32];
        precompile
            .call(
                &caller,
                &caller_pk,
                &selectors::addon(),
                &borsh::to_vec(&AddonArgs {
                    seat_index: 0,
                    amount: 60,
                })
                .unwrap(),
                &ExecutionEnvironment {
                    tx_inputs: vec![join_change],
                    tx_hash: addon_hash,
                    ..make_env()
                },
                &mut object_db,
            )
            .unwrap();
        let addon_change = ObjectID::new(caller, coin_output_nonce(&addon_hash, 0));
        assert_eq!(
            decode_native_coin(&object_db.read(&addon_change).unwrap())
                .unwrap()
                .amount,
            240
        );

        let rebuy_hash = [0x83; 32];
        precompile
            .call(
                &caller,
                &caller_pk,
                &selectors::rebuy(),
                &borsh::to_vec(&RebuyArgs {
                    seat_index: 0,
                    amount: 70,
                })
                .unwrap(),
                &ExecutionEnvironment {
                    tx_inputs: vec![addon_change],
                    tx_hash: rebuy_hash,
                    ..make_env()
                },
                &mut object_db,
            )
            .unwrap();
        let rebuy_change = ObjectID::new(caller, coin_output_nonce(&rebuy_hash, 0));
        assert_eq!(
            decode_native_coin(&object_db.read(&rebuy_change).unwrap())
                .unwrap()
                .amount,
            170
        );

        let table_id = reserved::texas_poker_contract_id();
        let table = read_resolved_table(&object_db, table_id);
        assert_eq!(table.seats[0].stack(), 170);
        assert_eq!(table.seats[0].pending_addon(), 60);
        assert_eq!(table.chip_pool, 230);
        assert_eq!(
            table
                .seats
                .iter()
                .map(|seat| seat.pending_addon())
                .sum::<u64>(),
            60
        );
        reconcile_table_vault(&table).unwrap();

        let leave_hash = [0x84; 32];
        precompile
            .call(
                &caller,
                &caller_pk,
                &selectors::leave_table(),
                &borsh::to_vec(&LeaveTableArgs { seat_index: 0 }).unwrap(),
                &ExecutionEnvironment {
                    tx_hash: leave_hash,
                    ..make_env()
                },
                &mut object_db,
            )
            .unwrap();

        let payout_id = ObjectID::new(caller, coin_output_nonce(&leave_hash, 1));
        assert_eq!(
            decode_native_coin(&object_db.read(&payout_id).unwrap())
                .unwrap()
                .amount,
            230
        );
        let final_table = read_resolved_table(&object_db, table_id);
        assert_eq!(final_table.chip_pool, 0);
        assert_eq!(
            final_table
                .seats
                .iter()
                .map(|seat| seat.pending_addon())
                .sum::<u64>(),
            0
        );
        assert!(!final_table.seats[0].is_occupied());
        reconcile_table_vault(&final_table).unwrap();

        let wallet_total = list_owned_native_coins(&object_db, caller)
            .unwrap()
            .iter()
            .try_fold(0u64, |total, coin| total.checked_add(coin.amount))
            .unwrap();
        assert_eq!(wallet_total, 400);
        assert_eq!(read_treasury(&object_db).unwrap(), treasury_before);
        reconcile_native_supply(&object_db, 0).unwrap();
    }

    #[test]
    fn funded_addon_failure_discards_table_coin_treasury_and_root_changes() {
        let precompile = TexasPokerPrecompile::new(1);
        let (caller, caller_pk) = make_caller();
        let (mut object_db, genesis_coin) =
            create_funded_table(&precompile, &caller, &caller_pk, 300);
        let join_change = funded_join(
            &precompile,
            &caller,
            &caller_pk,
            &mut object_db,
            genesis_coin,
            100,
            [0x61; 32],
        );
        let table_id = reserved::texas_poker_contract_id();
        let table_before = object_db.read(&table_id).unwrap();
        let input_before = object_db.read(&join_change).unwrap();
        let treasury_before = read_treasury(&object_db).unwrap();
        let root_before = object_db.state_root();

        let addon_args = borsh::to_vec(&AddonArgs {
            seat_index: 0,
            amount: 60,
        })
        .unwrap();
        let error = {
            let mut backend = FailTableUpdateBackend {
                inner: WriteCaptureBackend::new(&object_db),
                table_id,
            };
            precompile
                .call(
                    &caller,
                    &caller_pk,
                    &selectors::addon(),
                    &addon_args,
                    &ExecutionEnvironment {
                        tx_inputs: vec![join_change],
                        tx_hash: [0x62; 32],
                        ..make_env()
                    },
                    &mut backend,
                )
                .unwrap_err()
        };

        assert!(
            error
                .to_string()
                .contains("injected table persistence failure")
        );
        assert_eq!(object_db.read(&table_id).unwrap(), table_before);
        assert_eq!(object_db.read(&join_change).unwrap(), input_before);
        assert_eq!(read_treasury(&object_db).unwrap(), treasury_before);
        assert_eq!(object_db.state_root(), root_before);
        let discarded_change = ObjectID::new(caller, coin_output_nonce(&[0x62; 32], 0));
        assert!(object_db.read(&discarded_change).is_err());
    }
}
