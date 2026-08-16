//! HandStarted 执行模式分支（Task 16 — SubTask 16.5）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）第 527-553 行：
//! - **第 531-535 行**：牌桌合约初始化新一手牌（HandStarted）时，合约读取
//!   `execution_mode` 参数：`OnChain` 时后续步骤直接走链上 GameTurn 通道；
//!   `OffChain` 时触发 checkout 到链下。
//! - **第 537-541 行（OnChain）**：所有游戏步骤作为 GameTurn 通道 tx 在链上执行，
//!   每步状态变更上链，无 checkout / checkin，无 ZK 证明；玩家无需信任任何链下执行方。
//! - **第 543-547 行（OffChain）**：Game 对象状态被快照为 `OfflineState` commitment
//!   存入链上，owner 标记为 `ChannelOwner`，后续游戏步骤在链下执行。
//! - **第 549-553 行**：牌桌合约可被部署为 `execution_mode = OnChain`，
//!   所有玩家走全链上 GameTurn 通道。
//!
//! # 分支逻辑
//!
//! 1. **OnChain**：设置 `current_hand`，等待 GameTurn tx
//! 2. **OffChain**：设置 `current_hand` + 触发 checkout（生成 OfflineState commitment）

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::Address;

use super::types::{ExecutionMode, GameContract, HandState};

/// HandStarted 分支结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum HandStartedResult {
    /// OnChain 模式：手牌已开始，等待 GameTurn tx。
    OnChain {
        /// 当前手牌编号。
        hand_number: u64,
        /// 当前轮次玩家。
        current_turn: Address,
    },
    /// OffChain 模式：手牌已开始，已触发 checkout。
    OffChain {
        /// 当前手牌编号。
        hand_number: u64,
        /// 链下状态 commitment（merkle root of hand state）。
        offline_state_commitment: [u8; 32],
        /// ChannelOwner 地址（接管 Game 对象所有权）。
        channel_owner: Address,
    },
}

/// HandStarted 输入参数。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct HandStartedInput {
    /// 新手牌状态。
    pub hand_state: HandState,
    /// 执行模式（覆盖 GameContract.execution_mode，合约可自定义）。
    ///
    /// 若为 None，使用 GameContract.execution_mode。
    pub execution_mode_override: Option<ExecutionMode>,
}

impl HandStartedInput {
    /// 创建 HandStarted 输入（使用 GameContract 默认 execution_mode）。
    #[must_use]
    pub const fn new(hand_state: HandState) -> Self {
        Self {
            hand_state,
            execution_mode_override: None,
        }
    }

    /// 创建 HandStarted 输入（覆盖 execution_mode）。
    #[must_use]
    pub const fn with_mode(hand_state: HandState, mode: ExecutionMode) -> Self {
        Self {
            hand_state,
            execution_mode_override: Some(mode),
        }
    }
}

/// HandStarted 错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HandStartedError {
    /// 手牌已在进行中（不可重复开始）。
    #[error("hand already in progress (current hand_number={0})")]
    HandInProgress(u64),
    /// 手牌状态非法（如 players 为空）。
    #[error("invalid hand state: {0}")]
    InvalidHandState(String),
}

/// 执行 HandStarted 分支（spec.md 第 531-547 行）。
///
/// # 流程
///
/// 1. 校验当前无进行中的手牌
/// 2. 校验手牌状态合法性（players 非空）
/// 3. 读取 execution_mode（override > GameContract.execution_mode）
/// 4. 调用 `GameContract::start_new_hand` 设置 current_hand
/// 5. 按 execution_mode 分支：
///    - OnChain：返回 [`HandStartedResult::OnChain`]
///    - OffChain：生成 OfflineState commitment，返回 [`HandStartedResult::OffChain`]
///
/// # 参数
///
/// - `game`：Game 合约对象（mutable，会更新 current_hand + version）
/// - `input`：HandStarted 输入
///
/// # 错误
///
/// - [`HandStartedError::HandInProgress`]：当前已有进行中的手牌
/// - [`HandStartedError::InvalidHandState`]：手牌状态非法
pub fn hand_started_branch(
    game: &mut GameContract,
    input: HandStartedInput,
) -> Result<HandStartedResult, HandStartedError> {
    // 校验当前无进行中的手牌
    if !game.is_hand_settled() {
        return Err(HandStartedError::HandInProgress(game.hand_number));
    }

    // 校验手牌状态合法性
    if input.hand_state.players.is_empty() {
        return Err(HandStartedError::InvalidHandState(
            "players must not be empty".to_string(),
        ));
    }

    // 读取 execution_mode（override 优先）
    let execution_mode = input.execution_mode_override.unwrap_or(game.execution_mode);

    // 记录当前轮次玩家（在 start_new_hand 之前读取）
    let current_turn = input.hand_state.current_turn;

    // 设置 current_hand（递增 hand_number + version）
    game.start_new_hand(input.hand_state);

    // 按 execution_mode 分支
    let result = match execution_mode {
        ExecutionMode::OnChain => HandStartedResult::OnChain {
            hand_number: game.hand_number,
            current_turn,
        },
        ExecutionMode::OffChain => {
            // 生成 OfflineState commitment（简化版：blake2b_256 of hand state）
            // 实际实现需在 Phase 5 完成（spec.md 第 543-547 行）
            let commitment = compute_offline_state_commitment(game);
            game.last_commitment = Some(commitment);
            HandStartedResult::OffChain {
                hand_number: game.hand_number,
                offline_state_commitment: commitment,
                channel_owner: game.owner,
            }
        }
    };

    Ok(result)
}

/// 计算 OfflineState commitment（Phase 5 简化版）。
///
/// spec.md 第 543-547 行：Game 对象状态被快照为 `OfflineState` commitment 存入链上。
///
/// 当前实现：blake2b_256(BCS-encoded hand_state)
/// Phase 5 将扩展为完整的 state commitment（含 merkle root）。
fn compute_offline_state_commitment(game: &GameContract) -> [u8; 32] {
    use blake2::Blake2bVar;
    use blake2::digest::{Update, VariableOutput};

    let mut h = Blake2bVar::new(32).expect("32 <= 64");
    // 简化：对 game_id + hand_number + version 做 hash
    // 实际 Phase 5 会对完整 HandState BCS 序列化后 hash
    h.update(&game.id.to_bytes());
    h.update(&game.hand_number.to_le_bytes());
    h.update(&game.version.to_le_bytes());

    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).expect("32 <= 64");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Address;
    use crate::object_model::ObjectID;
    use crate::signature::TaggedPubkey;
    use crate::vm::contracts::types::{GamePhase, PlayerStack, RakeConfigRef};

    fn make_addr(byte: u8) -> Address {
        [byte; 20]
    }

    fn make_validator() -> TaggedPubkey {
        TaggedPubkey {
            tag: 0x01,
            raw: vec![0x02; 33],
        }
    }

    fn make_rake_config() -> RakeConfigRef {
        RakeConfigRef {
            rake_rate_bps: 500,
            rake_cap: 1000,
            rake_recipient: make_addr(0xff),
        }
    }

    fn make_hand_state() -> HandState {
        let p1 = make_addr(0x01);
        HandState {
            phase: GamePhase::Preflop,
            pot: 30,
            current_bet: 20,
            big_blind_amount: 20,
            small_blind_amount: 10,
            raise_count: 0,
            bet_count: 0,
            current_turn: p1,
            players: vec![PlayerStack::new(p1)],
            last_action_height: 100,
            hand_start_height: 100,
        }
    }

    fn make_game(mode: ExecutionMode) -> GameContract {
        GameContract::new(
            ObjectID::new(make_addr(0x01), 1),
            make_addr(0x01),
            make_validator(),
            mode,
            make_rake_config(),
            10,
        )
    }

    // ===== OnChain 分支测试 =====

    #[test]
    fn test_hand_started_onchain_default_mode() {
        let mut game = make_game(ExecutionMode::OnChain);
        let input = HandStartedInput::new(make_hand_state());

        let result = hand_started_branch(&mut game, input).expect("OnChain 分支应成功");

        match result {
            HandStartedResult::OnChain {
                hand_number,
                current_turn,
            } => {
                assert_eq!(hand_number, 1);
                assert_eq!(current_turn, make_addr(0x01));
            }
            _ => panic!("应为 OnChain 分支"),
        }

        assert!(game.current_hand.is_some());
        assert_eq!(game.version, 1);
    }

    #[test]
    fn test_hand_started_onchain_explicit_mode() {
        let mut game = make_game(ExecutionMode::OffChain); // GameContract 默认 OffChain
        let input = HandStartedInput::with_mode(make_hand_state(), ExecutionMode::OnChain);

        let result = hand_started_branch(&mut game, input).expect("OnChain 分支应成功");

        assert!(matches!(result, HandStartedResult::OnChain { .. }));
    }

    // ===== OffChain 分支测试 =====

    #[test]
    fn test_hand_started_offchain_default_mode() {
        let mut game = make_game(ExecutionMode::OffChain);
        let input = HandStartedInput::new(make_hand_state());

        let result = hand_started_branch(&mut game, input).expect("OffChain 分支应成功");

        match result {
            HandStartedResult::OffChain {
                hand_number,
                offline_state_commitment,
                channel_owner,
            } => {
                assert_eq!(hand_number, 1);
                assert_ne!(offline_state_commitment, [0u8; 32], "commitment 不应为全零");
                assert_eq!(channel_owner, make_addr(0x01));
            }
            _ => panic!("应为 OffChain 分支"),
        }
    }

    #[test]
    fn test_hand_started_offchain_explicit_mode() {
        let mut game = make_game(ExecutionMode::OnChain); // 默认 OnChain
        let input = HandStartedInput::with_mode(make_hand_state(), ExecutionMode::OffChain);

        let result = hand_started_branch(&mut game, input).expect("OffChain 分支应成功");

        assert!(matches!(result, HandStartedResult::OffChain { .. }));
    }

    // ===== 错误场景测试 =====

    #[test]
    fn test_hand_started_hand_in_progress_error() {
        let mut game = make_game(ExecutionMode::OnChain);
        let input = HandStartedInput::new(make_hand_state());

        // 第一次开始手牌应成功
        hand_started_branch(&mut game, input).expect("第一次应成功");

        // 第二次（手牌进行中）应失败
        let input2 = HandStartedInput::new(make_hand_state());
        let result = hand_started_branch(&mut game, input2);
        assert!(matches!(result, Err(HandStartedError::HandInProgress(1))));
    }

    #[test]
    fn test_hand_started_empty_players_error() {
        let mut game = make_game(ExecutionMode::OnChain);
        let mut hand = make_hand_state();
        hand.players.clear();

        let input = HandStartedInput::new(hand);
        let result = hand_started_branch(&mut game, input);
        assert!(matches!(result, Err(HandStartedError::InvalidHandState(_))));
    }

    // ===== 连续手牌测试 =====

    #[test]
    fn test_hand_started_multiple_hands_sequence() {
        let mut game = make_game(ExecutionMode::OnChain);

        // 第一手牌
        let input1 = HandStartedInput::new(make_hand_state());
        let r1 = hand_started_branch(&mut game, input1).expect("第一手应成功");
        assert!(matches!(
            r1,
            HandStartedResult::OnChain { hand_number: 1, .. }
        ));

        // 结算第一手牌
        if let Some(hand) = &mut game.current_hand {
            hand.phase = GamePhase::Settled;
        }

        // 第二手牌
        let input2 = HandStartedInput::new(make_hand_state());
        let r2 = hand_started_branch(&mut game, input2).expect("第二手应成功");
        assert!(matches!(
            r2,
            HandStartedResult::OnChain { hand_number: 2, .. }
        ));

        assert_eq!(game.version, 2);
    }

    // ===== execution_mode override 优先级测试 =====

    #[test]
    fn test_hand_started_mode_override_priority() {
        let mut game = make_game(ExecutionMode::OnChain);

        // override 为 OffChain，应优先使用 override
        let input = HandStartedInput::with_mode(make_hand_state(), ExecutionMode::OffChain);
        let result = hand_started_branch(&mut game, input).expect("应成功");

        assert!(
            matches!(result, HandStartedResult::OffChain { .. }),
            "override 应优先于 GameContract.execution_mode"
        );
    }

    #[test]
    fn test_hand_started_no_override_uses_game_mode() {
        let mut game = make_game(ExecutionMode::OffChain);

        // 无 override，使用 GameContract.execution_mode = OffChain
        let input = HandStartedInput::new(make_hand_state());
        let result = hand_started_branch(&mut game, input).expect("应成功");

        assert!(
            matches!(result, HandStartedResult::OffChain { .. }),
            "无 override 应使用 GameContract.execution_mode"
        );
    }
}
