//! Poker 合约数据类型（Task 16 — SubTask 16.2 / 16.4 / 16.5 / 16.6 共用）。
//!
//! 定义 poker 合约对象的核心数据结构：
//! - [`GameContract`]：poker 牌桌合约对象（扩展 Phase 2 的 `GameStatus`，增加牌局状态）
//! - [`HandState`]：单手牌状态（底池 / 当前下注 / 玩家筹码 / 阶段）
//! - [`GameAction`]：玩家动作（fold / check / call / raise / bet）
//! - [`BettingRound`] / [`GamePhase`]：下注轮 / 游戏阶段
//!
//! 这些类型对应 spec.md 第 347-361 行的对象模型，以及第 307-339 行的台费结算规范。
//! 序列化采用 BCS（Binary Canonical Serialization），与 ObjectStore 一致。

use std::collections::BTreeMap;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::Address;
use crate::Hash;
use crate::object_model::ObjectID;
use crate::signature::TaggedPubkey;

/// 游戏执行模式（spec.md 第 527-553 行）。
///
/// 复用 `consensus::routing::ExecutionMode`，此处重新定义以避免合约层
/// 反向依赖共识模块（合约对象应自包含）。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum ExecutionMode {
    /// 全链上执行（默认 trustless 模式）。
    OnChain,
    /// 链下执行 + ZK 证明（opt-in 性能模式，Phase 5）。
    OffChain,
}

/// 游戏阶段（spec.md 第 683-693 行 force_advance 规则需要区分 preflop / postflop）。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum GamePhase {
    /// 翻牌前（preflop）— 盲注已下，发牌完成。
    Preflop,
    /// 翻牌（flop）— 3 张公共牌已发。
    Flop,
    /// 转牌（turn）— 第 4 张公共牌已发。
    Turn,
    /// 河牌（river）— 第 5 张公共牌已发。
    River,
    /// 摊牌（showdown）— 已结算。
    Showdown,
    /// 已结束（settled）— settle 函数已执行。
    Settled,
}

/// 下注轮类型（用于 force_advance 规则区分 preflop / postflop）。
///
/// spec.md 第 689-693 行 SEC2-L5 修复：
/// - preflop：盲注阶段，current_bet == big_blind_amount 表示无人 raise
/// - postflop：flop / turn / river 阶段，current_bet == 0 表示无人下注
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum BettingRound {
    /// 翻牌前（preflop）。
    Preflop,
    /// 翻牌后（postflop：flop / turn / river）。
    Postflop,
}

impl GamePhase {
    /// 将阶段映射到下注轮（preflop / postflop）。
    ///
    /// 用于 force_advance 规则判定（spec.md 第 689-693 行 SEC2-L5）。
    #[must_use]
    pub const fn betting_round(&self) -> BettingRound {
        match self {
            Self::Preflop => BettingRound::Preflop,
            Self::Flop | Self::Turn | Self::River => BettingRound::Postflop,
            Self::Showdown | Self::Settled => BettingRound::Postflop,
        }
    }

    /// 是否为已结算阶段。
    #[must_use]
    pub const fn is_settled(&self) -> bool {
        matches!(self, Self::Settled)
    }
}

/// 玩家动作（spec.md 第 311-315 行 GameTurn 通道操作）。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum GameAction {
    /// 弃牌（失去本轮已投入筹码）。
    Fold,
    /// 过牌（不下注，轮次传递给下一位）。
    Check,
    /// 跟注（匹配当前下注）。
    Call,
    /// 加注（在当前下注基础上增加）。
    Raise {
        /// 加注后的新下注总额。
        new_bet: u64,
    },
    /// 下注（postflop 首次下注）。
    Bet {
        /// 下注金额。
        amount: u64,
    },
}

impl GameAction {
    /// 是否为 fold 动作。
    #[must_use]
    pub const fn is_fold(&self) -> bool {
        matches!(self, Self::Fold)
    }

    /// 是否为 check 动作。
    #[must_use]
    pub const fn is_check(&self) -> bool {
        matches!(self, Self::Check)
    }
}

/// 玩家筹码状态（per-hand）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct PlayerStack {
    /// 玩家地址。
    pub address: Address,
    /// 当前手牌已投入筹码（本下注轮累计）。
    pub contributed: u64,
    /// 是否已 fold。
    pub folded: bool,
    /// 是否为大盲位。
    pub is_big_blind: bool,
    /// 是否为小盲位。
    pub is_small_blind: bool,
    /// 是否为 button（庄家）。
    pub is_button: bool,
}

impl PlayerStack {
    /// 创建新玩家筹码状态。
    #[must_use]
    pub const fn new(address: Address) -> Self {
        Self {
            address,
            contributed: 0,
            folded: false,
            is_big_blind: false,
            is_small_blind: false,
            is_button: false,
        }
    }
}

/// 单手牌状态（合约对象的核心数据）。
///
/// 对应 spec.md 第 347-361 行的 Game 对象，扩展 Phase 2 的 `GameStatus`
/// 增加牌局状态（底池 / 当前下注 / 玩家筹码 / 阶段）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct HandState {
    /// 当前阶段。
    pub phase: GamePhase,
    /// 底池总额（所有玩家 contributed 之和）。
    pub pot: u64,
    /// 当前下注轮的最高下注额。
    pub current_bet: u64,
    /// 大盲金额（preflop force_advance 规则需要）。
    pub big_blind_amount: u64,
    /// 小盲金额。
    pub small_blind_amount: u64,
    /// 当前下注轮的 raise 次数（preflop force_advance 规则需要）。
    pub raise_count: u32,
    /// 当前下注轮的 bet 次数（postflop force_advance 规则需要）。
    pub bet_count: u32,
    /// 当前轮次玩家地址。
    pub current_turn: Address,
    /// 玩家筹码状态（按座位顺序）。
    pub players: Vec<PlayerStack>,
    /// 最后一次动作的 block height。
    pub last_action_height: u64,
    /// 手牌起始 block height。
    pub hand_start_height: u64,
}

impl HandState {
    /// 查找玩家索引。
    pub fn find_player(&self, addr: &Address) -> Option<usize> {
        self.players.iter().position(|p| &p.address == addr)
    }

    /// 查找大盲位玩家索引。
    #[must_use]
    pub fn big_blind_index(&self) -> Option<usize> {
        self.players.iter().position(|p| p.is_big_blind)
    }

    /// 获取当前下注轮类型（preflop / postflop）。
    #[must_use]
    pub const fn betting_round(&self) -> BettingRound {
        self.phase.betting_round()
    }

    /// 当前下注轮无人 raise（preflop）或无人下注（postflop）。
    ///
    /// spec.md 第 689-693 行 SEC2-L5 修复：
    /// - preflop：current_bet == big_blind_amount 且 raise_count == 0
    /// - postflop：current_bet == 0 且 bet_count == 0
    #[must_use]
    pub const fn no_betting_action(&self) -> bool {
        match self.betting_round() {
            BettingRound::Preflop => {
                self.current_bet == self.big_blind_amount && self.raise_count == 0
            }
            BettingRound::Postflop => self.current_bet == 0 && self.bet_count == 0,
        }
    }
}

/// Poker 牌桌合约对象（spec.md 第 347-361 行）。
///
/// 存储在 ObjectStore 中，通过 `object_create` 创建，`object_write` 修改。
/// 包含牌桌元数据 + 当前手牌状态。
///
/// Phase 5b/5c 扩展字段（SubTask 27.x / 28.x）：
/// - `checkpoint_seq`：checkpoint_anchor 序号（SubTask 27.1）
/// - `pending_ack_requests`：未完成的 ACK 请求（SubTask 27.6，地址→deadline height）
/// - `skip_count`：checkpoint_skip 段计数（SubTask 27.10）
/// - `delegated_escape_nonce`：委托逃生凭证 nonce（SubTask 27.5c）
/// - `designated_operator_check_exemptions`：designated operator check 豁免次数（SubTask 27.5）
/// - `under_investigation_count`：assigned_validator 审查调查累积计数（SubTask 27.5a）
/// - `forfeit_deposit`：操作方预锁 forfeit 保证金（SubTask 28.9）
/// - `designated_operator_bond`：designated operator 保证金金额（SubTask 28.9 / R5-H3 / SEC-L8）
/// - `partial_checkin_count`：partial_checkin 已提交次数（SubTask 28.7a）
/// - `malicious_refuse_count`：恶意 refuse_ack 累计计数（SubTask 27.9）
/// - `no_progress_count`：无进度 checkpoint_anchor 计数（SubTask 28.3 / SEC-H2）
/// - `last_checkpoint_state_hash`：上一次 checkpoint_anchor 的 state_hash（SEC-H2 无进度检测）
/// - `last_partial_fold`：partial_checkin 锚点（SubTask 28.7a）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct GameContract {
    /// 合约对象 ID（全局唯一）。
    pub id: ObjectID,
    /// 牌桌所有者（部署合约的地址）。
    pub owner: Address,
    /// 当前 epoch 的 assigned_validator。
    pub assigned_validator: TaggedPubkey,
    /// 执行模式（OnChain / OffChain）。
    pub execution_mode: ExecutionMode,
    /// 当前手牌编号（从 1 开始递增）。
    pub hand_number: u64,
    /// 当前手牌状态（None 表示两手牌之间的间隙）。
    pub current_hand: Option<HandState>,
    /// 台费配置。
    pub rake_config: RakeConfigRef,
    /// 轮次超时 block 数（spec.md 第 683-687 行 turn_timeout_blocks）。
    pub turn_timeout_blocks: u64,
    /// 对象版本号（optimistic concurrency）。
    pub version: u64,
    // ===== Phase 5b/5c 扩展字段（SubTask 27.x / 28.x）=====
    /// Game 级 last_action_height（SubTask 28.1 / 27.2 / 27.4 / 28.3）。
    /// 由 checkpoint_anchor / force_checkpoint / GameTurn tx 更新；
    /// force_advance / force_checkin 判定依据 `block.height - last_action_height`。
    /// 注意：`HandState.last_action_height` 为 per-hand 追踪，本字段为 game 级。
    pub last_action_height: u64,
    /// checkpoint_anchor 序号（SubTask 27.1，单调递增，去重判定依据）。
    pub checkpoint_seq: u64,
    /// 未完成的 ACK 请求（SubTask 27.6，地址→ack_deadline height）。
    /// 每 Game 每参与者同时只允许 1 个 active 请求（NEW-M7）。
    pub pending_ack_requests: BTreeMap<Address, u64>,
    /// checkpoint_skip 段计数（SubTask 27.10，上限 `max_skip_segments` 默认 3）。
    pub skip_count: u32,
    /// 委托逃生凭证 nonce（SubTask 27.5c，初始 0，消费后递增）。
    pub delegated_escape_nonce: u64,
    /// designated operator check 豁免次数（SubTask 27.5，上限默认 2）。
    pub designated_operator_check_exemptions: u32,
    /// assigned_validator 审查调查累积计数（SubTask 27.5a，达阈值默认 3 触发 slashing）。
    pub under_investigation_count: u32,
    /// 操作方预锁 forfeit 保证金（SubTask 28.9，= 桌面总 buy-in * forfeit_deposit_ratio / 100）。
    pub forfeit_deposit: u64,
    /// designated operator 保证金金额（SubTask 28.9 / R5-H3 / SEC-L8）。
    ///
    /// 若操作方为 designated operator（非玩家），forfeit 保证金 =
    /// `designated_operator_bond_amount`（默认 = 桌面 buy-in 中位数）。
    /// 0 表示非 designated operator 场景（使用 `forfeit_deposit` 基于 buy-in 计算）。
    pub designated_operator_bond: u64,
    /// partial_checkin 已提交次数（SubTask 28.7a，上限 `max_partial_checkin_count` 默认 3）。
    pub partial_checkin_count: u32,
    /// 恶意 refuse_ack 累计计数（SubTask 27.9，达阈值默认 3 触发 slashing）。
    pub malicious_refuse_count: u32,
    /// 无进度 checkpoint_anchor 计数（SubTask 28.3 / SEC-H2，达阈值默认 2 触发 force_revert）。
    pub no_progress_count: u32,
    /// 上一次 checkpoint_anchor 的 state_hash（SEC-H2，用于无进度检测）。
    pub last_checkpoint_state_hash: Option<Hash>,
    /// partial_checkin 锚点（SubTask 28.7a，None 表示无 partial_checkin 记录）。
    pub last_partial_fold: Option<crate::offline::state::LastPartialFold>,
    /// 最后一次 checkout/checkin commitment（SubTask 28.1，OffChain 模式下
    /// 由 checkout 写入 / checkin 清除；用于 force_checkin / request_revert 回退锚点）。
    pub last_commitment: Option<Hash>,
}

/// 台费配置（引用类型，避免循环依赖）。
///
/// 对应 [`crate::vm::contracts::settle::RakeConfig`]，此处用独立结构避免
/// 合约层与 settle 模块的双向引用。序列化时保持一致。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct RakeConfigRef {
    /// 台费比例（basis points，100 = 1%，max 1000 = 10%）。
    pub rake_rate_bps: u32,
    /// 台费封顶金额（单手牌最高台费）。
    pub rake_cap: u64,
    /// 台费收款方地址（可配置为 validator 奖励池）。
    pub rake_recipient: Address,
}

impl GameContract {
    /// 创建新 Game 合约对象。
    #[must_use]
    pub const fn new(
        id: ObjectID,
        owner: Address,
        assigned_validator: TaggedPubkey,
        execution_mode: ExecutionMode,
        rake_config: RakeConfigRef,
        turn_timeout_blocks: u64,
    ) -> Self {
        Self {
            id,
            owner,
            assigned_validator,
            execution_mode,
            hand_number: 0,
            current_hand: None,
            rake_config,
            turn_timeout_blocks,
            version: 0,
            // Phase 5b/5c 扩展字段默认值
            last_action_height: 0,
            checkpoint_seq: 0,
            pending_ack_requests: BTreeMap::new(),
            skip_count: 0,
            delegated_escape_nonce: 0,
            designated_operator_check_exemptions: 0,
            under_investigation_count: 0,
            forfeit_deposit: 0,
            designated_operator_bond: 0,
            partial_checkin_count: 0,
            malicious_refuse_count: 0,
            no_progress_count: 0,
            last_checkpoint_state_hash: None,
            last_partial_fold: None,
            last_commitment: None,
        }
    }

    /// 是否已结算（当前手牌）。
    #[must_use]
    pub fn is_hand_settled(&self) -> bool {
        self.current_hand
            .as_ref()
            .map(|h| h.phase.is_settled())
            .unwrap_or(true)
    }

    /// 开始新一手牌（HandStarted）。
    ///
    /// 递增 hand_number，初始化 HandState。
    pub fn start_new_hand(&mut self, hand_state: HandState) {
        self.hand_number = self.hand_number.saturating_add(1);
        self.current_hand = Some(hand_state);
        self.version = self.version.saturating_add(1);
    }
}

/// 玩家活跃 Game 索引（spec.md 第 317-321 行，per-player active Game limit）。
///
/// 用于校验玩家活跃 Game 数量是否超限（默认 10）。
#[derive(
    Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct PlayerActiveGames {
    /// player address → 活跃 Game ID 列表。
    pub games: BTreeMap<Address, Vec<ObjectID>>,
}

impl PlayerActiveGames {
    /// 玩家活跃 Game 数量。
    pub fn count(&self, player: &Address) -> usize {
        self.games.get(player).map(|v| v.len()).unwrap_or(0)
    }

    /// 添加活跃 Game。
    pub fn add(&mut self, player: Address, game_id: ObjectID) {
        self.games.entry(player).or_default().push(game_id);
    }

    /// 移除活跃 Game（结算后）。
    pub fn remove(&mut self, player: &Address, game_id: &ObjectID) {
        if let Some(v) = self.games.get_mut(player) {
            v.retain(|id| id != game_id);
            if v.is_empty() {
                self.games.remove(player);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_addr(byte: u8) -> Address {
        [byte; 20]
    }

    #[test]
    fn test_game_phase_betting_round() {
        assert_eq!(GamePhase::Preflop.betting_round(), BettingRound::Preflop);
        assert_eq!(GamePhase::Flop.betting_round(), BettingRound::Postflop);
        assert_eq!(GamePhase::Turn.betting_round(), BettingRound::Postflop);
        assert_eq!(GamePhase::River.betting_round(), BettingRound::Postflop);
    }

    #[test]
    fn test_game_phase_is_settled() {
        assert!(!GamePhase::Preflop.is_settled());
        assert!(!GamePhase::Flop.is_settled());
        assert!(GamePhase::Settled.is_settled());
    }

    #[test]
    fn test_game_action_is_fold_check() {
        assert!(GameAction::Fold.is_fold());
        assert!(!GameAction::Check.is_fold());
        assert!(GameAction::Check.is_check());
        assert!(!GameAction::Fold.is_check());
        assert!(!GameAction::Call.is_fold());
        assert!(!GameAction::Call.is_check());
    }

    #[test]
    fn test_player_stack_new() {
        let addr = make_addr(0x01);
        let stack = PlayerStack::new(addr);
        assert_eq!(stack.address, addr);
        assert_eq!(stack.contributed, 0);
        assert!(!stack.folded);
        assert!(!stack.is_big_blind);
    }

    #[test]
    fn test_hand_state_no_betting_action_preflop() {
        let bb = make_addr(0x01);
        let mut players = vec![PlayerStack::new(bb)];
        players[0].is_big_blind = true;

        // preflop, current_bet == big_blind_amount, raise_count == 0 → no_betting_action = true
        let hand = HandState {
            phase: GamePhase::Preflop,
            pot: 30,
            current_bet: 20,
            big_blind_amount: 20,
            small_blind_amount: 10,
            raise_count: 0,
            bet_count: 0,
            current_turn: bb,
            players,
            last_action_height: 100,
            hand_start_height: 90,
        };
        assert!(hand.no_betting_action(), "preflop 无人 raise 应为 true");

        // preflop, current_bet > big_blind_amount → false
        let mut hand2 = hand.clone();
        hand2.current_bet = 40;
        assert!(!hand2.no_betting_action());

        // preflop, raise_count > 0 → false
        let mut hand3 = hand;
        hand3.raise_count = 1;
        assert!(!hand3.no_betting_action());
    }

    #[test]
    fn test_hand_state_no_betting_action_postflop() {
        let p1 = make_addr(0x01);
        let players = vec![PlayerStack::new(p1)];

        // postflop, current_bet == 0, bet_count == 0 → true
        let hand = HandState {
            phase: GamePhase::Flop,
            pot: 100,
            current_bet: 0,
            big_blind_amount: 20,
            small_blind_amount: 10,
            raise_count: 0,
            bet_count: 0,
            current_turn: p1,
            players,
            last_action_height: 100,
            hand_start_height: 90,
        };
        assert!(hand.no_betting_action(), "postflop 无人下注应为 true");

        // postflop, current_bet > 0 → false
        let mut hand2 = hand.clone();
        hand2.current_bet = 50;
        assert!(!hand2.no_betting_action());

        // postflop, bet_count > 0 → false
        let mut hand3 = hand;
        hand3.bet_count = 1;
        assert!(!hand3.no_betting_action());
    }

    #[test]
    fn test_hand_state_find_player_and_big_blind() {
        let p1 = make_addr(0x01);
        let p2 = make_addr(0x02);
        let mut players = vec![PlayerStack::new(p1), PlayerStack::new(p2)];
        players[1].is_big_blind = true;

        let hand = HandState {
            phase: GamePhase::Preflop,
            pot: 30,
            current_bet: 20,
            big_blind_amount: 20,
            small_blind_amount: 10,
            raise_count: 0,
            bet_count: 0,
            current_turn: p1,
            players,
            last_action_height: 100,
            hand_start_height: 90,
        };

        assert_eq!(hand.find_player(&p1), Some(0));
        assert_eq!(hand.find_player(&p2), Some(1));
        assert_eq!(hand.find_player(&make_addr(0x03)), None);
        assert_eq!(hand.big_blind_index(), Some(1));
    }

    #[test]
    fn test_game_contract_new_and_start_hand() {
        let id = ObjectID::new(make_addr(0x01), 1);
        let owner = make_addr(0x01);
        let validator = TaggedPubkey {
            tag: 0x01,
            raw: vec![0x02; 33],
        };
        let rake = RakeConfigRef {
            rake_rate_bps: 500, // 5%
            rake_cap: 1000,
            rake_recipient: make_addr(0xff),
        };
        let mut game = GameContract::new(id, owner, validator, ExecutionMode::OnChain, rake, 10);

        assert_eq!(game.hand_number, 0);
        assert!(game.current_hand.is_none());
        assert!(game.is_hand_settled());

        // 开始新一手牌
        let hand = HandState {
            phase: GamePhase::Preflop,
            pot: 30,
            current_bet: 20,
            big_blind_amount: 20,
            small_blind_amount: 10,
            raise_count: 0,
            bet_count: 0,
            current_turn: owner,
            players: vec![PlayerStack::new(owner)],
            last_action_height: 100,
            hand_start_height: 100,
        };
        game.start_new_hand(hand);

        assert_eq!(game.hand_number, 1);
        assert!(game.current_hand.is_some());
        assert!(!game.is_hand_settled());
        assert_eq!(game.version, 1);
    }

    #[test]
    fn test_player_active_games() {
        let mut pag = PlayerActiveGames::default();
        let p1 = make_addr(0x01);
        let g1 = ObjectID::new(p1, 1);
        let g2 = ObjectID::new(p1, 2);

        assert_eq!(pag.count(&p1), 0);

        pag.add(p1, g1);
        assert_eq!(pag.count(&p1), 1);

        pag.add(p1, g2);
        assert_eq!(pag.count(&p1), 2);

        pag.remove(&p1, &g1);
        assert_eq!(pag.count(&p1), 1);

        pag.remove(&p1, &g2);
        assert_eq!(pag.count(&p1), 0);
        assert!(pag.games.is_empty());
    }
}
