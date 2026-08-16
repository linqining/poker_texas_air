//! 游戏合约 dispatch 表（P0-5 — Task 16 第二批）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）：
//! - **SubTask 16.1 ~ 16.6**：原生游戏合约业务逻辑（hand_started / force_advance / settle 等）
//! - **method_selector**: `blake2b_256(method_name)[0..32]`（与 rBPF 合约调用协议一致）
//! - **BCS 编码**: args / 返回值使用 BCS 序列化，与 executor 层交互
//!
//! # Dispatch 路由
//!
//! ContractCall.method_selector → 业务方法：
//! - hand_started      → hand_started_branch()
//! - force_advance     → apply_force_advance()
//! - settle_hand       → settle_hand()
//! - force_checkpoint  → apply_force_checkpoint()
//! - checkpoint_anchor → apply_checkpoint_anchor()
//! - force_checkin     → apply_force_checkin()
//! - force_settle      → apply_force_settle()
//! - request_revert    → apply_request_revert()
//! - force_revert      → apply_force_revert()
//! - apply_forfeit     → apply_forfeit()
//! - challenge_delta   → apply_challenge_delta()
//! - request_da        → apply_request_da()
//! - checkpoint_skip   → apply_checkpoint_skip()
//! - revoke_delegated_escape → apply_revoke_delegated_escape()
//! - request_ack       → apply_request_ack()
//! - refuse_ack        → apply_refuse_ack()

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};

use crate::error::{PokerL1Error, PokerL1Result};
use crate::object_model::ObjectID;
use crate::signature::TaggedPubkey;
use crate::{Address, BlockHeight, ChainId};

use super::{
    ack_protocol, challenge_delta, checkpoint_anchor, checkpoint_skip, delegated_escape,
    force_advance, force_checkin, force_checkpoint, force_settle, forfeit, hand_started,
    request_da, revert, settle, types::GameContract,
};

/// 方法选择器长度（32 字节 = blake2b_256 输出）。
pub const METHOD_SELECTOR_LEN: usize = 32;

/// 计算方法选择器：`blake2b_256(method_name)[0..32]`。
///
/// method_name 为 ASCII 字符串，如 "hand_started"、"force_advance"。
pub fn compute_method_selector(method_name: &str) -> [u8; METHOD_SELECTOR_LEN] {
    let mut h = Blake2bVar::new(METHOD_SELECTOR_LEN).expect("32 <= 64");
    h.update(method_name.as_bytes());
    let mut out = [0u8; METHOD_SELECTOR_LEN];
    h.finalize_variable(&mut out).expect("32 <= 64");
    out
}

/// 方法选择器常量（与 rBPF 合约方法名一一对应）。
///
/// 所有方法名使用 snake_case，与 Rust 风格一致。
pub mod selectors {
    use super::compute_method_selector;

    pub fn hand_started() -> [u8; 32] {
        compute_method_selector("hand_started")
    }

    pub fn force_advance() -> [u8; 32] {
        compute_method_selector("force_advance")
    }

    pub fn settle_hand() -> [u8; 32] {
        compute_method_selector("settle_hand")
    }

    pub fn force_checkpoint() -> [u8; 32] {
        compute_method_selector("force_checkpoint")
    }

    pub fn checkpoint_anchor() -> [u8; 32] {
        compute_method_selector("checkpoint_anchor")
    }

    pub fn force_checkin() -> [u8; 32] {
        compute_method_selector("force_checkin")
    }

    pub fn force_settle() -> [u8; 32] {
        compute_method_selector("force_settle")
    }

    pub fn request_revert() -> [u8; 32] {
        compute_method_selector("request_revert")
    }

    pub fn force_revert() -> [u8; 32] {
        compute_method_selector("force_revert")
    }

    pub fn apply_forfeit() -> [u8; 32] {
        compute_method_selector("apply_forfeit")
    }

    pub fn challenge_delta() -> [u8; 32] {
        compute_method_selector("challenge_delta")
    }

    pub fn request_da() -> [u8; 32] {
        compute_method_selector("request_da")
    }

    pub fn checkpoint_skip() -> [u8; 32] {
        compute_method_selector("checkpoint_skip")
    }

    pub fn revoke_delegated_escape() -> [u8; 32] {
        compute_method_selector("revoke_delegated_escape")
    }

    pub fn request_ack() -> [u8; 32] {
        compute_method_selector("request_ack")
    }

    pub fn refuse_ack() -> [u8; 32] {
        compute_method_selector("refuse_ack")
    }
}

/// 合约调用上下文（传递给 dispatch 的执行环境）。
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct DispatchContext {
    /// 调用者地址。
    pub caller: Address,
    /// 调用者 tagged_pubkey。
    pub caller_pubkey: TaggedPubkey,
    /// 链 ID。
    pub chain_id: ChainId,
    /// 当前 block height。
    pub block_height: BlockHeight,
    /// 当前 block timestamp（毫秒）。
    pub block_timestamp: u64,
}

/// Dispatch 执行结果。
///
/// 包含状态变更信息，executor 层据此更新 ObjectDb。
#[derive(Debug, Clone)]
pub struct DispatchResult {
    /// 新创建的对象 ID 列表。
    pub created_objects: Vec<ObjectID>,
    /// 修改的对象 ID 列表。
    pub modified_objects: Vec<ObjectID>,
    /// 返回值（BCS 编码，可被调用者解析）。
    pub return_value: Vec<u8>,
}

impl DispatchResult {
    /// 创建空结果（无状态变更）。
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            created_objects: vec![],
            modified_objects: vec![],
            return_value: vec![],
        }
    }

    /// 创建仅修改 GameContract 的结果。
    #[must_use]
    pub fn game_only(game_id: ObjectID) -> Self {
        Self {
            created_objects: vec![],
            modified_objects: vec![game_id],
            return_value: vec![],
        }
    }
}

/// Dispatch 路由入口。
///
/// 将 ContractCall 路由到对应的原生游戏合约业务方法。
///
/// 参数：
/// - `context`：执行上下文（调用者、block 信息等）
/// - `game`：可变的 GameContract 引用（状态变更目标）
/// - `selector`：方法选择器（32 字节）
/// - `args`：调用参数（BCS 编码）
///
/// 返回：`DispatchResult` 包含状态变更信息。
///
/// 失败时返回 `PokerL1Error::UnknownContractMethod`（未知方法）或各业务方法的具体错误。
pub fn dispatch(
    context: &DispatchContext,
    game: &mut GameContract,
    selector: &[u8; 32],
    args: &[u8],
) -> PokerL1Result<DispatchResult> {
    match selector {
        s if s == &selectors::hand_started() => dispatch_hand_started(context, game, args),
        s if s == &selectors::force_advance() => dispatch_force_advance(context, game, args),
        s if s == &selectors::settle_hand() => dispatch_settle_hand(context, game, args),
        s if s == &selectors::force_checkpoint() => dispatch_force_checkpoint(context, game, args),
        s if s == &selectors::checkpoint_anchor() => {
            dispatch_checkpoint_anchor(context, game, args)
        }
        s if s == &selectors::force_checkin() => dispatch_force_checkin(context, game, args),
        s if s == &selectors::force_settle() => dispatch_force_settle(context, game, args),
        s if s == &selectors::request_revert() => dispatch_request_revert(context, game, args),
        s if s == &selectors::force_revert() => dispatch_force_revert(context, game, args),
        s if s == &selectors::apply_forfeit() => dispatch_apply_forfeit(context, game, args),
        s if s == &selectors::challenge_delta() => dispatch_challenge_delta(context, game, args),
        s if s == &selectors::request_da() => dispatch_request_da(context, game, args),
        s if s == &selectors::checkpoint_skip() => dispatch_checkpoint_skip(context, game, args),
        s if s == &selectors::revoke_delegated_escape() => {
            dispatch_revoke_delegated_escape(context, game, args)
        }
        s if s == &selectors::request_ack() => dispatch_request_ack(context, game, args),
        s if s == &selectors::refuse_ack() => dispatch_refuse_ack(context, game, args),
        _ => Err(PokerL1Error::UnknownContractMethod {
            selector: *selector,
        }),
    }
}

/// Dispatch: hand_started。
fn dispatch_hand_started(
    _context: &DispatchContext,
    game: &mut GameContract,
    args: &[u8],
) -> PokerL1Result<DispatchResult> {
    let input: hand_started::HandStartedInput = borsh::from_slice(args)
        .map_err(|e| PokerL1Error::Serialization(format!("hand_started: {e}")))?;
    let result = hand_started::hand_started_branch(game, input)?;
    let return_value = borsh::to_vec(&result)
        .map_err(|e| PokerL1Error::Serialization(format!("hand_started return: {e}")))?;
    Ok(DispatchResult {
        created_objects: vec![],
        modified_objects: vec![game.id],
        return_value,
    })
}

/// Dispatch: force_advance。
fn dispatch_force_advance(
    _context: &DispatchContext,
    game: &mut GameContract,
    args: &[u8],
) -> PokerL1Result<DispatchResult> {
    let input: force_advance::ForceAdvanceInput = borsh::from_slice(args)
        .map_err(|e| PokerL1Error::Serialization(format!("force_advance: {e}")))?;
    let _action = force_advance::apply_force_advance(game, &input)?;
    Ok(DispatchResult::game_only(game.id))
}

/// Dispatch: settle_hand。
fn dispatch_settle_hand(
    _context: &DispatchContext,
    game: &mut GameContract,
    _args: &[u8],
) -> PokerL1Result<DispatchResult> {
    let hand = game
        .current_hand
        .as_ref()
        .ok_or_else(|| PokerL1Error::SettleError(settle::SettleError::NoWinner))?;
    let rake_config = settle::RakeConfig {
        rake_rate_bps: game.rake_config.rake_rate_bps,
        rake_cap: game.rake_config.rake_cap,
        rake_recipient: game.rake_config.rake_recipient,
    };
    let result = settle::settle_hand(hand, &rake_config)?;
    let return_value = borsh::to_vec(&result)
        .map_err(|e| PokerL1Error::Serialization(format!("settle_hand return: {e}")))?;
    game.current_hand = None;
    game.hand_number += 1;
    Ok(DispatchResult {
        created_objects: vec![],
        modified_objects: vec![game.id],
        return_value,
    })
}

/// Dispatch: force_checkpoint。
fn dispatch_force_checkpoint(
    context: &DispatchContext,
    game: &mut GameContract,
    args: &[u8],
) -> PokerL1Result<DispatchResult> {
    let tx: force_checkpoint::ForceCheckpointTx = borsh::from_slice(args)
        .map_err(|e| PokerL1Error::Serialization(format!("force_checkpoint: {e}")))?;
    force_checkpoint::apply_force_checkpoint(game, &tx, context.block_height, 3)?;
    Ok(DispatchResult::game_only(game.id))
}

/// Dispatch: checkpoint_anchor。
fn dispatch_checkpoint_anchor(
    context: &DispatchContext,
    game: &mut GameContract,
    args: &[u8],
) -> PokerL1Result<DispatchResult> {
    let tx: checkpoint_anchor::CheckpointAnchorTx = borsh::from_slice(args)
        .map_err(|e| PokerL1Error::Serialization(format!("checkpoint_anchor: {e}")))?;
    checkpoint_anchor::apply_checkpoint_anchor(game, &tx, context.block_height)?;
    Ok(DispatchResult::game_only(game.id))
}

/// Dispatch: force_checkin。
fn dispatch_force_checkin(
    _context: &DispatchContext,
    game: &mut GameContract,
    args: &[u8],
) -> PokerL1Result<DispatchResult> {
    let input: force_checkin::ForceCheckinInput = borsh::from_slice(args)
        .map_err(|e| PokerL1Error::Serialization(format!("force_checkin: {e}")))?;
    force_checkin::apply_force_checkin(game, &input)?;
    Ok(DispatchResult::game_only(game.id))
}

/// Dispatch: force_settle。
fn dispatch_force_settle(
    _context: &DispatchContext,
    game: &mut GameContract,
    args: &[u8],
) -> PokerL1Result<DispatchResult> {
    let tx: force_settle::ForceSettleTx = borsh::from_slice(args)
        .map_err(|e| PokerL1Error::Serialization(format!("force_settle: {e}")))?;
    let rake_config = settle::RakeConfig {
        rake_rate_bps: game.rake_config.rake_rate_bps,
        rake_cap: game.rake_config.rake_cap,
        rake_recipient: game.rake_config.rake_recipient,
    };
    force_settle::apply_force_settle(game, &tx, &rake_config)?;
    Ok(DispatchResult::game_only(game.id))
}

/// Dispatch: request_revert。
fn dispatch_request_revert(
    context: &DispatchContext,
    game: &mut GameContract,
    args: &[u8],
) -> PokerL1Result<DispatchResult> {
    let tx: revert::RequestRevertTx = borsh::from_slice(args)
        .map_err(|e| PokerL1Error::Serialization(format!("request_revert: {e}")))?;
    revert::apply_request_revert(game, &tx, context.block_height, 10, 20, 30)?;
    Ok(DispatchResult::game_only(game.id))
}

/// Dispatch: force_revert。
fn dispatch_force_revert(
    _context: &DispatchContext,
    game: &mut GameContract,
    args: &[u8],
) -> PokerL1Result<DispatchResult> {
    let tx: revert::ForceRevertTx = borsh::from_slice(args)
        .map_err(|e| PokerL1Error::Serialization(format!("force_revert: {e}")))?;
    revert::apply_force_revert(game, &tx)?;
    Ok(DispatchResult::game_only(game.id))
}

/// Dispatch: apply_forfeit。
fn dispatch_apply_forfeit(
    _context: &DispatchContext,
    game: &mut GameContract,
    _args: &[u8],
) -> PokerL1Result<DispatchResult> {
    forfeit::apply_forfeit(
        game,
        None,
        force_checkin::ForfeitReason::MachineFailure,
        None,
        0,
        &[],
    )?;
    Ok(DispatchResult::game_only(game.id))
}

/// Dispatch: challenge_delta。
fn dispatch_challenge_delta(
    _context: &DispatchContext,
    game: &mut GameContract,
    args: &[u8],
) -> PokerL1Result<DispatchResult> {
    let tx: challenge_delta::ChallengeDeltaTx = borsh::from_slice(args)
        .map_err(|e| PokerL1Error::Serialization(format!("challenge_delta: {e}")))?;
    challenge_delta::apply_challenge_delta(game, &tx, [0u8; 32], 50)?;
    Ok(DispatchResult::game_only(game.id))
}

/// Dispatch: request_da。
fn dispatch_request_da(
    _context: &DispatchContext,
    game: &mut GameContract,
    args: &[u8],
) -> PokerL1Result<DispatchResult> {
    let tx: request_da::RequestDaTx = borsh::from_slice(args)
        .map_err(|e| PokerL1Error::Serialization(format!("request_da: {e}")))?;
    request_da::apply_request_da(game, &tx)?;
    Ok(DispatchResult::game_only(game.id))
}

/// Dispatch: checkpoint_skip。
fn dispatch_checkpoint_skip(
    context: &DispatchContext,
    game: &mut GameContract,
    args: &[u8],
) -> PokerL1Result<DispatchResult> {
    let tx: checkpoint_skip::CheckpointSkipTx = borsh::from_slice(args)
        .map_err(|e| PokerL1Error::Serialization(format!("checkpoint_skip: {e}")))?;
    checkpoint_skip::apply_checkpoint_skip(game, &tx, context.block_height, 3)?;
    Ok(DispatchResult::game_only(game.id))
}

/// Dispatch: revoke_delegated_escape。
fn dispatch_revoke_delegated_escape(
    context: &DispatchContext,
    game: &mut GameContract,
    args: &[u8],
) -> PokerL1Result<DispatchResult> {
    let tx: delegated_escape::RevokeDelegatedEscapeTx = borsh::from_slice(args)
        .map_err(|e| PokerL1Error::Serialization(format!("revoke_delegated_escape: {e}")))?;
    delegated_escape::apply_revoke_delegated_escape(game, &tx, context.chain_id)?;
    Ok(DispatchResult::game_only(game.id))
}

/// Dispatch: request_ack。
fn dispatch_request_ack(
    context: &DispatchContext,
    game: &mut GameContract,
    args: &[u8],
) -> PokerL1Result<DispatchResult> {
    let tx: ack_protocol::RequestAckTx = borsh::from_slice(args)
        .map_err(|e| PokerL1Error::Serialization(format!("request_ack: {e}")))?;
    ack_protocol::apply_request_ack(game, &tx, context.block_height, 20, 2)?;
    Ok(DispatchResult::game_only(game.id))
}

/// Dispatch: refuse_ack。
fn dispatch_refuse_ack(
    context: &DispatchContext,
    game: &mut GameContract,
    args: &[u8],
) -> PokerL1Result<DispatchResult> {
    let tx: ack_protocol::RefuseAckTx = borsh::from_slice(args)
        .map_err(|e| PokerL1Error::Serialization(format!("refuse_ack: {e}")))?;
    ack_protocol::apply_refuse_ack(game, &tx, context.block_height, context.chain_id, 3)?;
    Ok(DispatchResult::game_only(game.id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::TaggedPubkey;
    use crate::vm::contracts::types::{
        ExecutionMode, GamePhase, HandState, PlayerStack, RakeConfigRef,
    };

    fn create_test_game(id: ObjectID) -> GameContract {
        GameContract::new(
            id,
            [1u8; 20],
            TaggedPubkey {
                tag: 0,
                raw: vec![2u8; 32],
            },
            ExecutionMode::OnChain,
            RakeConfigRef {
                rake_rate_bps: 50,
                rake_cap: 1000,
                rake_recipient: [3u8; 20],
            },
            10,
        )
    }

    fn create_test_hand_state() -> HandState {
        HandState {
            phase: GamePhase::Preflop,
            pot: 200,
            current_bet: 100,
            big_blind_amount: 100,
            small_blind_amount: 50,
            raise_count: 0,
            bet_count: 0,
            current_turn: [4u8; 20],
            players: vec![
                PlayerStack {
                    address: [4u8; 20],
                    contributed: 100,
                    folded: false,
                    is_big_blind: true,
                    is_small_blind: false,
                    is_button: false,
                },
                PlayerStack {
                    address: [5u8; 20],
                    contributed: 50,
                    folded: false,
                    is_big_blind: false,
                    is_small_blind: true,
                    is_button: true,
                },
            ],
            last_action_height: 0,
            hand_start_height: 0,
        }
    }

    fn create_test_context() -> DispatchContext {
        DispatchContext {
            caller: [6u8; 20],
            caller_pubkey: TaggedPubkey {
                tag: 0,
                raw: vec![7u8; 32],
            },
            chain_id: 1,
            block_height: 100,
            block_timestamp: 1_000_000,
        }
    }

    #[test]
    fn method_selector_deterministic() {
        let h1 = selectors::hand_started();
        let h2 = compute_method_selector("hand_started");
        assert_eq!(h1, h2, "selector 常量与计算函数必须一致");
    }

    #[test]
    fn method_selector_unique() {
        let selectors = [
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
        for i in 0..selectors.len() {
            for j in (i + 1)..selectors.len() {
                assert_ne!(selectors[i], selectors[j], "所有 selector 必须唯一");
            }
        }
    }

    #[test]
    fn dispatch_hand_started_onchain() {
        let context = create_test_context();
        let mut game = create_test_game(ObjectID::new([1u8; 20], 1));

        let input = hand_started::HandStartedInput {
            hand_state: create_test_hand_state(),
            execution_mode_override: None,
        };
        let args = borsh::to_vec(&input).unwrap();

        let result = dispatch(&context, &mut game, &selectors::hand_started(), &args).unwrap();

        assert!(result.created_objects.is_empty());
        assert!(!result.modified_objects.is_empty());
        assert_eq!(game.hand_number, 1);
        assert!(game.current_hand.is_some());
        assert_eq!(
            game.current_hand.as_ref().unwrap().phase,
            GamePhase::Preflop
        );
    }

    #[test]
    fn dispatch_force_advance_fold() {
        let context = create_test_context();
        let mut game = create_test_game(ObjectID::new([1u8; 20], 1));

        let mut hand_state = create_test_hand_state();
        hand_state.current_bet = 200;
        hand_state.raise_count = 1;
        game.current_hand = Some(hand_state);

        let input = force_advance::ForceAdvanceInput {
            timeout_player: [5u8; 20],
            current_block_height: 200,
        };
        let args = borsh::to_vec(&input).unwrap();

        let result = dispatch(&context, &mut game, &selectors::force_advance(), &args).unwrap();

        assert!(result.created_objects.is_empty());
        assert!(!result.modified_objects.is_empty());
        assert!(game.current_hand.as_ref().unwrap().players[1].folded);
    }

    #[test]
    fn dispatch_settle_hand() {
        let context = create_test_context();
        let mut game = create_test_game(ObjectID::new([1u8; 20], 1));

        let mut hand_state = create_test_hand_state();
        hand_state.phase = GamePhase::Showdown;
        game.current_hand = Some(hand_state);

        let result = dispatch(&context, &mut game, &selectors::settle_hand(), &[]).unwrap();

        assert!(result.created_objects.is_empty());
        assert!(!result.modified_objects.is_empty());
        assert!(game.is_hand_settled());
    }

    #[test]
    fn dispatch_unknown_method() {
        let context = create_test_context();
        let mut game = create_test_game(ObjectID::new([1u8; 20], 1));

        let unknown_selector = [255u8; 32];
        let result = dispatch(&context, &mut game, &unknown_selector, &[]);

        assert!(matches!(
            result,
            Err(PokerL1Error::UnknownContractMethod { .. })
        ));
    }

    #[test]
    fn dispatch_hand_started_offchain() {
        let context = create_test_context();
        let mut game = create_test_game(ObjectID::new([1u8; 20], 1));

        let input = hand_started::HandStartedInput {
            hand_state: create_test_hand_state(),
            execution_mode_override: Some(ExecutionMode::OffChain),
        };
        let args = borsh::to_vec(&input).unwrap();

        let result = dispatch(&context, &mut game, &selectors::hand_started(), &args).unwrap();

        assert!(result.created_objects.is_empty());
        assert!(!result.modified_objects.is_empty());
        assert_eq!(game.hand_number, 1);
        assert!(game.current_hand.is_some());
        assert!(game.last_commitment.is_some());
    }
}
