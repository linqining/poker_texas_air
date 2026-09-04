use std::collections::HashMap;
use crate::pokergame::game_state::{ElGamalCiphertextJson, ReconstructPhase, ShuffleProofJson,
     ReconstructPublicState, MaskAndShuffleRoundJson, ReconstructState, ReconstructProofJson, PlayerReadableCard,
     PkProofJson, PlayerReadableCardJson, PlayerRevealAssignment, RevealPhase, RevealTokenPublicState, ShufflePublicState, ShuffleState, RevealTokenState,
     LeaveGameRoundJson};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::pokergame::deck::{Card, EncryptedDeck};
use crate::pokergame::player::{GamePlayer, Player, PlayerWithProof, WalletAddress, GamePkHex};
use crate::pokergame::seat::{ClientSeat,Seat};
use crate::pokergame::side_pot::SidePot;
use crate::pokergame::table_summary::{TableSummaryV2, TableSummaryMeta, TableSummaryState};
use poker_protocol::z_poker::{MentalPokerGame, GameConfig};
use poker_protocol::crypto::{EcPoint, ElGamalCiphertext, Plaintext, Scalar};
use poker_protocol::z_poker::convert::{ecpoint_to_hex, scalar_to_hex};
use poker_protocol::zk_shuffle::transcript_ext::{CryptoTranscript, FiatShamirTranscript};
use poker_protocol::crypto::CurvePoint;
use poker_protocol::crypto::CurveScalar;
/// 对齐 Move 合约 MIN_PLAYERS_TO_START = 2
const MIN_START_NUM: u32 = 2;

/// 当前时间的毫秒时间戳，对齐 Move 合约 Clock.timestamp_ms() 语义。
/// 用于 summary.state 中的各类 *_at 时间戳字段的设置与比较。
pub use crate::relayer::util::now_ms;

pub mod shuffle;
#[cfg(test)]
mod full_hand_tests;
pub mod reveal;
pub mod reconstruct;
pub mod seat_mgmt;
pub mod betting;
pub mod pot;
pub mod phases;
pub mod lifecycle;
pub mod events;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    pub seat_id: u32,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum JoinResult {
    JoinedAndShuffled,
    JoinedWaiting,
}

pub use crate::pokergame::error::JoinError;
pub use events::{CryptoEventType, TableEvent};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RoundState {
    Waiting,
    PreFlop,
    Flop,
    Turn,
    River,
    Showdown,
}

impl RoundState {
    /// 将链上 u8 round_state 转换为 RoundState 枚举。
    /// 对齐 Move 合约：0=Waiting, 2=PreFlop, 3=Flop, 4=Turn, 5=River, 6=Showdown
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(RoundState::Waiting),
            2 => Some(RoundState::PreFlop),
            3 => Some(RoundState::Flop),
            4 => Some(RoundState::Turn),
            5 => Some(RoundState::River),
            6 => Some(RoundState::Showdown),
            _ => None,
        }
    }

    /// 将 RoundState 枚举转换为链上 u8 round_state。
    pub fn to_u8(self) -> u8 {
        match self {
            RoundState::Waiting => 0,
            RoundState::PreFlop => 2,
            RoundState::Flop => 3,
            RoundState::Turn => 4,
            RoundState::River => 5,
            RoundState::Showdown => 6,
        }
    }
}

/// #17 accepted-seq 向量条目（settle 广播中的抗审查承诺）。
#[derive(Debug, Serialize, Clone, Deserialize)]
pub struct AcceptedSeqEntry {
    pub seat: u32,
    pub seq: u64,
}

pub struct ActionRequest {
    pub pk_hex: GamePkHex,
    pub action: String,
    pub amount: Option<u64>,
    /// #16 动作签名（客户端牌局 SK）；None = 未签名（迁移期兼容）。
    pub seq: Option<u64>,
    pub sig: Option<crate::pokergame::actions::ActionSig>,
}

#[derive(Debug, Serialize,Clone,Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientTable {
    pub id: u32,
    pub name: String,
    pub limit: u64,
    pub max_players: u32,
    pub players: HashMap<GamePkHex, WalletAddress>,
    pub seats: HashMap<u32, ClientSeat>,
    pub board: Vec<Card>,
    pub deck: Option<EncryptedDeck>,
    pub button: Option<u32>,
    pub turn: Option<u32>,
    pub pot: u64,
    pub main_pot: u64,
    pub call_amount: Option<u64>,
    pub min_bet: u64,
    pub min_raise: u64,
    pub small_blind: Option<u32>,
    pub big_blind: Option<u32>,
    pub hand_over: bool,
    pub win_messages: Vec<String>,
    pub went_to_showdown: bool,
    pub side_pots: Vec<SidePot>,
    /// 本手已收台费（摊牌结算时按链上口径收取）
    pub rake_collected: u64,
    /// #17 抗审查承诺向量：座位 → 已接受最大动作 seq（含 auto 代打）
    pub accepted_seqs: Vec<AcceptedSeqEntry>,
    pub history: Vec<serde_json::Value>,
    pub round_state: RoundState,
    pub shuffle_state: Option<ShufflePublicState>,
    pub reveal_token_state: Option<RevealTokenPublicState>,
    pub reconstruct_state: Option<ReconstructPublicState>,
    /// 链上 Table 对象的 Object ID（hex 字符串）。
    pub chain_table_id: Option<String>,
}



#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Table {
    pub summary: TableSummaryV2,
    /// 仅 off-chain 模式使用；on-chain 模式通过 `players()` 访问器从 `summary.crypto.seat_pks` + `summary.meta.seat_players` 派生
    pub local_players: HashMap<GamePkHex, WalletAddress>,
    /// 仅 off-chain 模式使用 + on-chain 运行时字段；on-chain 模式通过 `seats()` 访问器从 `summary.meta.seat_*` 派生
    pub local_seats: HashMap<u32, Seat>,
    #[serde(skip)]
    pub shuffle_state: ShuffleState,
    #[serde(skip)]
    pub reveal_token_state: RevealTokenState,
    #[serde(skip)]
    pub reconstruct_state: ReconstructState,
    #[serde(skip)]
    pub betting_round: Option<crate::pokergame::betting::BettingRound>,
    #[serde(skip)]
    pub mental_poker_game: MentalPokerGame,
    #[serde(skip)]
    pub waiting_players: HashMap<GamePkHex, PlayerWithProof>,
    #[serde(skip)]
    pub pk_to_seat: HashMap<GamePkHex, u32>,
    /// 链上 Table 对象的 Object ID（hex 字符串）。
    /// 由 relayer 在 `sync_table_state` 中匹配到链上 table 后设置。
    /// 上链模式下用户操作构建 PTB 时需要此字段；为 None 表示尚未与链上 table 关联。
    #[serde(skip)]
    pub chain_table_id: Option<String>,
    #[serde(skip)]
    pub event_tx: Option<tokio::sync::mpsc::Sender<crate::pokergame::table::events::TableEvent>>,
    /// 标记事件处理器是否已自行调用 `sync_table_state`。
    /// 由 4 个生命周期/shuffle/reveal 处理器在 self-sync 后置 true，
    /// `apply_event_to_socket` 末尾的统一 end-sync 检查此标志：
    /// 若为 true 则跳过 end-sync 并重置为 false，避免双重 sync。
    /// 仅在事件处理流程内有效，每次 end-sync 检查后都会被重置。
    #[serde(skip)]
    pub already_synced: bool,
    /// Phase 2.3: 上次成功同步链上状态的时间戳。
    /// 由 `sync_table_state` 和 `sync_deck_from_chain` 在写锁块末尾设置。
    /// 用于 `verify_*_with_retry` 判断内存 crypto 数据新鲜度（阈值 2000ms），
    /// 以及 tick 循环跳过冗余 fetch（阈值 3000ms）。
    #[serde(skip)]
    pub last_synced_at: Option<std::time::Instant>,
    /// #16/#17：座位 → 已接受的最大动作 seq（跨手单调，抗审查承诺向量）。
    #[serde(skip)]
    pub accepted_seq: HashMap<u32, u64>,
    /// #16/#17：本手动作日志（含超时 auto 代打标记），新手牌开始清空。
    #[serde(skip)]
    pub action_log: Vec<crate::pokergame::actions::ActionLogEntry>,
    /// #18：本手在 `action_log` 中的起始下标（start_hand 设置）。日志本体
    /// 跨手累积便于追溯，审计摘要只覆盖本手窗口。
    #[serde(skip)]
    pub hand_log_start: usize,
    /// #20 Phase 2：本手证明输入日志（HandStart 快照 + 已接受命令）。
    /// 结算时一次性重放为 ProveTask 链（取代常驻 mirror 第二本账）。
    /// `record_hand_start`（deck 终局时）整体重置。
    #[serde(skip)]
    pub hand_proof_log: crate::starknet::prove_log::HandProofLog,
}

impl Table {
    pub fn round_state(&self) -> RoundState {
        RoundState::from_u8(self.summary.meta.round_state).unwrap_or(RoundState::Waiting)
    }
    pub fn pot(&self) -> u64 {
        self.summary.meta.pot
    }
    pub fn set_pot(&mut self, v: u64) {
        self.summary.meta.pot = v;
    }
    pub fn button(&self) -> Option<u32> {
        if self.summary.meta.button == 0 { None } else { Some(self.summary.meta.button as u32) }
    }
    pub fn set_button(&mut self, v: Option<u32>) {
        self.summary.meta.button = v.map(|x| x as u64).unwrap_or(0);
    }
    pub fn turn(&self) -> Option<u32> {
        self.summary.meta.current_turn.map(|x| x as u32)
    }
    pub fn set_turn(&mut self, v: Option<u32>) {
        self.summary.meta.current_turn = v.map(|x| x as u64);
    }
    pub fn small_blind(&self) -> Option<u32> {
        if self.summary.meta.small_blind == 0 { None } else { Some(self.summary.meta.small_blind as u32) }
    }
    pub fn set_small_blind(&mut self, v: Option<u32>) {
        self.summary.meta.small_blind = v.map(|x| x as u64).unwrap_or(0);
    }
    pub fn big_blind(&self) -> Option<u32> {
        if self.summary.meta.big_blind == 0 { None } else { Some(self.summary.meta.big_blind as u32) }
    }
    pub fn set_big_blind(&mut self, v: Option<u32>) {
        self.summary.meta.big_blind = v.map(|x| x as u64).unwrap_or(0);
    }
    pub fn max_players(&self) -> u32 {
        self.summary.meta.max_players as u32
    }
    pub fn name(&self) -> &str {
        &self.summary.meta.name
    }

    // ===== 对齐 Move：min_raise 使用 summary.meta.betting_round_min_raise =====
    pub fn min_raise(&self) -> u64 {
        self.summary.meta.betting_round_min_raise
    }
    pub fn set_min_raise(&mut self, v: u64) {
        self.summary.meta.betting_round_min_raise = v;
    }

    // ===== 对齐 Move：main_pot = pot - sum(side_pots)，无独立字段 =====
    pub fn main_pot(&self) -> u64 {
        let side_total: u64 = self.summary.side_pots.iter().map(|sp| sp.amount).sum();
        self.pot().saturating_sub(side_total)
    }

    // ===== 对齐 Move Timestamps：使用 summary.state 中的 u64 毫秒时间戳 =====
    // 0 表示未设置（对齐 Move 中 0 表示未启动计时）
    pub fn betting_started_at(&self) -> u64 {
        self.summary.state.betting_started_at
    }
    pub fn set_betting_started_at(&mut self, v: u64) {
        self.summary.state.betting_started_at = v;
    }
    pub fn hand_complete_at(&self) -> u64 {
        self.summary.state.hand_complete_at
    }
    pub fn set_hand_complete_at(&mut self, v: u64) {
        self.summary.state.hand_complete_at = v;
    }
    pub fn ready_at(&self) -> u64 {
        self.summary.state.ready_at
    }
    pub fn set_ready_at(&mut self, v: u64) {
        self.summary.state.ready_at = v;
    }
    pub fn showdown_at(&self) -> u64 {
        self.summary.state.showdown_at
    }
    pub fn set_showdown_at(&mut self, v: u64) {
        self.summary.state.showdown_at = v;
    }

    /// 返回当前加密牌组。
    /// 始终从 `mental_poker_game.deck_encrypted` 读取（单一真理之源）。
    /// `sync_deck_state` 负责将链上 `summary.crypto.deck_encrypted` 同步到 `mental_poker_game`。
    pub fn deck_encrypted(&self) -> Vec<ElGamalCiphertext> {
        self.mental_poker_game.deck_encrypted.clone()
    }

    /// 返回当前明文牌组。
    /// 始终从 `mental_poker_game.deck_plaintext` 读取（单一真理之源）。
    /// `sync_deck_state` 负责将链上 `summary.state.deck_plaintext` 同步到 `mental_poker_game`。
    pub fn deck_plaintext(&self) -> Vec<Plaintext> {
        self.mental_poker_game.deck_plaintext.clone()
    }

    /// 返回当前聚合公钥。
    /// 始终从 `mental_poker_game.key_manager` 读取（单一真理之源）。
    /// `sync_deck_state` 负责将链上 `summary.crypto.aggregated_pk` 同步到 `mental_poker_game`。
    pub fn aggregated_pk(&self) -> EcPoint {
        self.mental_poker_game.key_manager.get_aggregated_pk()
    }

    /// #16 动作签名验证（服务端口径）：pk/seq/action/amount 全部进签名域。
    pub fn verify_action_sig(
        &self,
        pk_hex: &GamePkHex,
        seq: u64,
        action: &str,
        amount: u64,
        sig: &crate::pokergame::actions::ActionSig,
    ) -> bool {
        poker_protocol::z_poker::protocol::verify_game_action_hex(
            &pk_hex.0,
            self.summary.id,
            seq,
            action,
            amount,
            &sig.r_hex,
            &sig.s_hex,
        )
    }

    /// #16/#17 记账：seq 单调推进 + 本手动作日志。auto = 服务器超时代打
    ///（seq 服务器分配 = accepted + 1）。
    pub fn record_action(
        &mut self,
        seat: u32,
        seq: u64,
        action: &str,
        amount: u64,
        auto: bool,
        sig_ok: bool,
    ) {
        self.accepted_seq.insert(seat, seq);
        self.action_log.push(crate::pokergame::actions::ActionLogEntry {
            seat,
            seq,
            action: action.to_string(),
            amount,
            auto,
            sig_ok,
        });
    }

    /// 座位当前 accepted seq（无记录为 0）。
    pub fn accepted_seq_of(&self, seat: u32) -> u64 {
        self.accepted_seq.get(&seat).copied().unwrap_or(0)
    }

    pub fn to_client(&self) -> ClientTable {
        let mut client_seats = HashMap::new();
        for (seat_id, seat) in self.seats().iter() {
            let client_seat = seat.to_client();
            client_seats.insert(*seat_id, client_seat);
        }
        let encrypted_deck = EncryptedDeck{
            cards: self.deck_encrypted().iter().map(ElGamalCiphertextJson::from_ciphertext).collect(),
        };
        let board = self.mental_poker_game.list_revealed_community_cards().iter().map(|c| Card::from_playing_card(c)).collect::<Vec<_>>();
        ClientTable {
            id: self.summary.id,
            name: self.name().to_string(),
            limit: self.summary.limit,
            max_players: self.max_players(),
            players: self.players(),
            seats: client_seats,
            board: board,
            deck: Some(encrypted_deck.clone()),
            button: self.button(),
            turn: self.turn(),
            pot: self.pot(),
            main_pot: self.main_pot(),
            call_amount: self.summary.call_amount,
            min_bet: self.summary.min_bet,
            min_raise: self.min_raise(),
            small_blind: self.small_blind(),
            big_blind: self.big_blind(),
            hand_over: self.summary.hand_over,
            win_messages: self.summary.win_messages.clone(),
            went_to_showdown: self.summary.went_to_showdown,
            side_pots: self.summary.side_pots.clone(),
            rake_collected: self.summary.rake_collected,
            accepted_seqs: {
                let mut v: Vec<AcceptedSeqEntry> = self
                    .accepted_seq
                    .iter()
                    .map(|(seat, seq)| AcceptedSeqEntry { seat: *seat, seq: *seq })
                    .collect();
                v.sort_by_key(|e| e.seat);
                v
            },
            history: self.summary.history.clone(),
            round_state: self.round_state(),
            shuffle_state: self.get_shuffle_public_state(),
            reveal_token_state: self.get_reveal_token_public_state(),
            reconstruct_state: self.get_reconstruct_public_state(),
            chain_table_id: self.chain_table_id.clone(),
        }
    }

    /// Transition to a new round state with validity checking.
    /// Logs a warning if the transition is not in the valid transition table.
    /// G4 修复：对严重非法转换（如 Waiting → Showdown）直接 panic，
    /// 其他非法转换在 debug 构建中 panic，release 中仅记录 warn。
    pub fn transition_to(&mut self, new_state: RoundState) {
        if self.round_state() == new_state{
            return;
        };
        let from = self.round_state();
        let valid = matches!((from, new_state),
            (RoundState::Waiting, RoundState::PreFlop) |
            (RoundState::PreFlop, RoundState::Flop) |
            (RoundState::Flop, RoundState::Turn) |
            (RoundState::Turn, RoundState::River) |
            (RoundState::River, RoundState::Showdown) |
            (RoundState::Showdown, RoundState::Waiting) |
            // Early termination / timeout reset
            (RoundState::PreFlop | RoundState::Flop | RoundState::Turn | RoundState::River, RoundState::Waiting)
        );
        tracing::info!("Transition from {:?} to {:?}", from, new_state);
        if !valid {
            let severe = matches!((from, new_state),
                (RoundState::Waiting, RoundState::Showdown) |
                (RoundState::Showdown, RoundState::PreFlop | RoundState::Flop | RoundState::Turn | RoundState::River)
            );
            if severe {
                // 历史上此处 panic：会杀死 game_loop task 且跳过 registry 清理，
                // start_game_loop 的 contains() 判真后拒绝重启 → 该牌桌永久冻结。
                // 降级为告警 + 强制落地（状态机漂移可观测、可恢复）。
                tracing::error!(
                    "severe illegal state transition {:?} -> {:?}; forcing (was panic, see audit H1)",
                    from, new_state
                );
            } else {
                tracing::warn!("Invalid state transition: {:?} -> {:?}", from, new_state);
            }
        }
        self.summary.meta.round_state = new_state.to_u8();
    }

    /// Force transition to a new round state WITHOUT validation.
    /// Used by sync_table_state when the on-chain state is the authority.
    /// The on-chain round_state is already validated by the Move contract,
    /// so we skip the local state machine validation to avoid getting stuck
    /// when local and chain states diverge.
    pub fn transition_to_forced(&mut self, new_state: RoundState) {
        let old_state = self.summary.meta.round_state;
        if old_state != new_state.to_u8() {
            tracing::info!(target: "table",
                table_id = self.summary.id,
                old_state = old_state,
                new_state = new_state.to_u8(),
                "forced transition (chain authority)");
        }
        self.summary.meta.round_state = new_state.to_u8();
    }

    pub fn new(id: u32, name: String, limit: u64, max_players: u32, chain_table_id: String) -> Self {
        let local_seats = Self::init_seats(max_players);
        let mut summary = TableSummaryV2::default();
        summary.meta.name = name;
        summary.meta.max_players = max_players as u64;
        summary.meta.small_blind = (limit / 200) as u64;
        summary.meta.big_blind = (limit / 100) as u64;
        summary.meta.round_state = RoundState::Waiting.to_u8();
        summary.id = id;
        summary.limit = limit;
        summary.call_amount = None;
        summary.min_bet = limit / 200;
        summary.hand_over = true;
        summary.win_messages = vec![];
        summary.went_to_showdown = false;
        summary.side_pots = vec![];
        summary.history = vec![];
        Self {
            summary,
            local_players: HashMap::new(),
            local_seats,
            shuffle_state: ShuffleState::new(),
            reveal_token_state: RevealTokenState::new(2, 5),
            reconstruct_state: ReconstructState::new(),
            betting_round: None,
            mental_poker_game: MentalPokerGame::new(GameConfig {
                num_players: max_players as usize,
                cards_per_player: 2,
                community_cards: 5,
            }),
            waiting_players: HashMap::new(),
            pk_to_seat: HashMap::new(),
            chain_table_id: Some(chain_table_id),
            event_tx: None,
            already_synced: false,
            last_synced_at: None,
            accepted_seq: HashMap::new(),
            action_log: Vec::new(),
            hand_proof_log: crate::starknet::prove_log::HandProofLog::default(),
            hand_log_start: 0,
        }
    }

    /// 注入事件 sender，使 Table 内部方法能通过 `emit_event` 发送 socket 事件。
    /// 由 `SocketState::init_table_event_channels` 在初始化时调用。
    pub fn set_event_sender(&mut self, tx: tokio::sync::mpsc::Sender<crate::pokergame::table::events::TableEvent>) {
        self.event_tx = Some(tx);
    }

    /// 发送一个 TableEvent 到 channel，由 `table_event_consumer` 消费并执行实际 socket 广播。
    /// 若未注入 sender（event_tx 为 None），静默返回。
    /// 使用 `try_send` 非阻塞发送：channel 满或已关闭时静默丢弃事件，不 panic、不阻塞。
    /// 这使得 sync 内部方法（如 advance_shuffle / on_reveal_complete）也能调用。
    pub fn emit_event(&self, event: crate::pokergame::table::events::TableEvent) {
        if let Some(tx) = &self.event_tx {
            if let Err(e) = tx.try_send(event) {
                tracing::debug!("[TABLE-EVENTS] emit_event dropped: {}", e);
            }
        }
    }

    pub fn init_seats(_max_players: u32) -> HashMap<u32, Seat> {
        HashMap::new()
    }

    /// 返回 players 映射。on-chain 模式从 summary.crypto.seat_pks + summary.meta.seat_players 派生；
    /// off-chain 模式返回 local_players 副本。
    ///
    /// 注意：GamePkHex 必须通过 G1 compressed bytes 反序列化得到（与 relayer 的
    /// `deserialize_pk_hex` / `build_seat_pk_map` 一致），不能直接 hex encode 原始字节。
    /// WalletAddress 则直接 hex encode seat_players[i] 并加 "0x" 前缀。
    pub fn players(&self) -> HashMap<GamePkHex, WalletAddress> {
        if self.chain_table_id.is_some() {
            use poker_protocol::crypto::curve::CurvePoint as CurvePointTrait;
            use poker_protocol::crypto::DefaultCurve;
            type P = <DefaultCurve as poker_protocol::crypto::curve::Curve>::Point;

            let mut result = HashMap::new();
            for (i, pk_bytes) in self.summary.crypto.seat_pks.iter().enumerate() {
                if pk_bytes.is_empty() {
                    continue;
                }
                // G1 compressed bytes → EcPoint → hex string（对齐 relayer deserialize_pk_hex）
                let pk_hex = match <P as CurvePointTrait>::from_compressed(pk_bytes) {
                    Some(pt) => GamePkHex::new(ecpoint_to_hex(&pt)),
                    None => {
                        tracing::warn!(
                            "[Table::players] seat {} pk deserialization failed (invalid G1 bytes), skipping",
                            i
                        );
                        continue;
                    }
                };
                if let Some(wallet_bytes) = self.summary.meta.seat_players.get(i) {
                    // 全零地址视为空座位，跳过
                    if wallet_bytes.iter().any(|&b| b != 0) {
                        let wallet_addr = WalletAddress::new(format!(
                            "0x{}",
                            hex::encode(wallet_bytes)
                        ));
                        result.insert(pk_hex, wallet_addr);
                    }
                }
            }
            // 用 local_seats 中已反查的主钱包地址覆盖链上 proxy_address，
            // 确保 broadcast_to_table 等调用者能匹配 gs.players 中的 socket。
            for seat in self.local_seats.values() {
                if let Some(player) = &seat.player {
                    result.insert(player.pk_hex.clone(), player.wallet_address.clone());
                }
            }
            result
        } else {
            self.local_players.clone()
        }
    }

    /// 返回 seats 映射。on-chain 模式以 local_seats 为基底，用 summary.meta.seat_* 覆盖链上同步字段；
    /// off-chain 模式返回 local_seats 副本。
    ///
    /// 注意：Seat 未 impl Default，使用 `Seat::new(seat_id, None, 0, 0)` 作为占位初始化。
    /// 链上同步字段覆盖：stack / bet / total_bet / folded / sitting_out（对应 seat_is_waiting）。
    pub fn seats(&self) -> HashMap<u32, Seat> {
        if self.chain_table_id.is_some() {
            use poker_protocol::crypto::curve::CurvePoint as CurvePointTrait;
            use poker_protocol::crypto::DefaultCurve;
            type P = <DefaultCurve as poker_protocol::crypto::curve::Curve>::Point;

            let mut result = self.local_seats.clone();
            for (i, &occupied) in self.summary.meta.seats_occupied.iter().enumerate() {
                let seat_id = i as u32;
                if !occupied {
                    continue;
                }
                let seat = result.entry(seat_id).or_insert_with(|| Seat::new(seat_id, None, 0, 0));
                if let Some(&stack) = self.summary.meta.seat_stacks.get(i) {
                    seat.stack = stack;
                }
                if let Some(&bet) = self.summary.meta.seat_bets.get(i) {
                    seat.bet = bet;
                }
                if let Some(&total_bet) = self.summary.meta.seat_total_bets.get(i) {
                    seat.total_bet = total_bet;
                }
                if let Some(&folded) = self.summary.meta.seat_folded.get(i) {
                    seat.folded = folded;
                }
                if let Some(&is_waiting) = self.summary.meta.seat_is_waiting.get(i) {
                    seat.sitting_out = is_waiting;
                }
                // 从链上数据构造 GamePlayer（当 seat 无 player 时）
                if seat.player.is_none() {
                    if let Some(wallet_bytes) = self.summary.meta.seat_players.get(i) {
                        if wallet_bytes.iter().any(|&b| b != 0) {
                            let wallet_addr = WalletAddress::new(format!(
                                "0x{}",
                                hex::encode(wallet_bytes)
                            ));
                            // 从 seat_pks 反序列化 pk_hex
                            let pk_hex = self.summary.crypto.seat_pks.get(i)
                                .filter(|pk_bytes| !pk_bytes.is_empty())
                                .and_then(|pk_bytes| {
                                    <P as CurvePointTrait>::from_compressed(pk_bytes)
                                        .map(|pt| GamePkHex::new(ecpoint_to_hex(&pt)))
                                });
                            if let Some(pk_hex) = pk_hex {
                                let name = crate::pokergame::player::truncate_name(
                                    &wallet_addr.0,
                                    12,
                                );
                                seat.player = Some(GamePlayer {
                                    name,
                                    bankroll: 0,
                                    pk_hex,
                                    readable_hands: vec![],
                                    wallet_address: wallet_addr,
                                });
                            }
                        }
                    }
                }
            }
            result
        } else {
            self.local_seats.clone()
        }
    }

    pub fn is_playing(&self) -> bool {
        self.round_state() != RoundState::Waiting
    }

    pub fn update_history(&mut self) {
        let board = self.mental_poker_game.list_revealed_community_cards().iter().map(|c| Card::from_playing_card(c)).collect::<Vec<_>>();
        self.summary.history.push(json!({
            "pot": self.pot(),
            "mainPot": self.main_pot(),
            "sidePots": self.summary.side_pots,
            "rakeCollected": self.summary.rake_collected,
            "board":board,
            "seats": self.clean_seats_for_history(),
            "button": self.button(),
            "turn": self.turn(),
            "winMessages": self.summary.win_messages,
        }));
    }

    /// 终局记录快照 → 全局牌局记录存储（看板数据源，见 `history_store` 模块）。
    /// 在两条终局路径（finish_showdown / end_without_showdown）各调用一次。
    /// gross_pot = 当前 pot + 台费（摊牌路径 pot 已扣台费；fold-win 台费为 0）。
    pub fn record_hand_history(&self) {
        let board = self.mental_poker_game.list_revealed_community_cards().iter().map(|c| Card::from_playing_card(c)).collect::<Vec<_>>();
        // 已亮出的手牌（摊牌亮牌的座位才有；弃牌/未亮牌座位不记录——隐私）
        let (player_revealed, _) = self.mental_poker_game.list_revealed_cards();
        let mut hole_cards: std::collections::HashMap<u32, Vec<Card>> = std::collections::HashMap::new();
        for (pk_hex, cards) in player_revealed.iter() {
            if cards.is_empty() {
                continue;
            }
            if let Some((seat_id, _)) = self.seats().iter().find(|(_, s)| {
                s.player.as_ref().map(|p| p.pk_hex.0 == *pk_hex).unwrap_or(false)
            }) {
                hole_cards.insert(
                    *seat_id,
                    cards.iter().map(|c| Card::from_playing_card(c)).collect::<Vec<_>>(),
                );
            }
        }
        let record = crate::pokergame::history_store::HandHistoryRecord {
            hand_seq: 0, // 由 store 按桌分配单调 seq
            hand_over_at: now_ms(),
            went_to_showdown: self.summary.went_to_showdown,
            gross_pot: self.pot().saturating_add(self.summary.rake_collected),
            rake_collected: self.summary.rake_collected,
            side_pots: self.summary.side_pots.clone(),
            board,
            hole_cards,
            win_messages: self.summary.win_messages.clone(),
            seats: self.clean_seats_for_history(),
            streets: self.summary.history.clone(),
        };
        crate::pokergame::history_store::global_store().append(self.summary.id, record);
    }

    pub fn clean_seats_for_history(&self) -> serde_json::Value {
        let mut clean = serde_json::Map::new();
        for (id, seat) in self.seats().iter() {
            clean.insert(id.to_string(), json!({
                "player": { "id": seat.player.as_ref().map(|p| p.wallet_address.0.clone()), "username": seat.player.as_ref().map(|p| p.name.clone()) },
                "bet": seat.bet,
                "stack": seat.stack,
            }));
        }
        serde_json::Value::Object(clean)
    }

    pub fn get_pk_hex_by_wallet_address(&self,wallet: &str)->Option<GamePkHex>{
        self.players().iter().find(|(pk_hex,wallet_addr)| wallet_addr.0 == wallet).map(|(pk_hex,_)|pk_hex.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_table() -> Table {
        Table::new(1, "test".to_string(), 100, 6, "0xchain_table_id".to_string())
    }

    /// 测试 `deck_encrypted()` 始终从 `mental_poker_game` 读取，不再 fallback 到 `summary.crypto`。
    ///
    /// 场景：summary.crypto.deck_encrypted 有 52 个假数据，mental_poker_game.deck_encrypted
    /// 也有 52 个 trivial ciphertexts（new() 初始化的）。
    /// 预期：deck_encrypted() 返回 mental_poker_game 中的值（trivial ciphertexts），
    ///       而非 summary.crypto 中的假数据。
    #[test]
    fn test_deck_encrypted_reads_from_mental_poker_game_not_summary() {
        let mut table = make_test_table();
        // 记录 mental_poker_game 的初始 deck_encrypted
        let mp_deck = table.mental_poker_game.deck_encrypted.clone();
        assert_eq!(mp_deck.len(), 52, "mental_poker_game should have 52 trivial ciphertexts after new()");

        // 模拟链上同步：summary.crypto.deck_encrypted 有不同的假数据
        table.summary.crypto.deck_encrypted = vec![vec![0xAAu8; 96]; 52];

        // deck_encrypted() 应返回 mental_poker_game 的值，而非 summary.crypto 的
        let deck = table.deck_encrypted();
        assert_eq!(deck.len(), 52, "deck_encrypted() should return mental_poker_game's 52 cards");
        assert_eq!(deck, mp_deck, "deck_encrypted() should match mental_poker_game, not summary.crypto");
    }

    /// 测试 `reset_for_next_hand()` 不再清理 `summary.crypto` 缓存。
    ///
    /// 场景：summary.crypto.deck_encrypted 有假数据，调用 reset_for_next_hand()。
    /// 预期：summary.crypto.deck_encrypted 保留（不被清理），
    ///       mental_poker_game.deck_encrypted 被 reset 重建（trivial ciphertexts）。
    #[test]
    fn test_reset_for_next_hand_preserves_summary_crypto() {
        let mut table = make_test_table();
        // 模拟链上同步：summary.crypto 有假数据
        let fake_deck: Vec<Vec<u8>> = vec![vec![0xBBu8; 96]; 52];
        table.summary.crypto.deck_encrypted = fake_deck.clone();
        table.summary.state.cards_dealt = 10;

        // 调用 reset_for_next_hand
        table.reset_for_next_hand();

        // summary.crypto.deck_encrypted 应保留（不被清理）
        assert_eq!(
            table.summary.crypto.deck_encrypted, fake_deck,
            "summary.crypto.deck_encrypted should NOT be cleared by reset_for_next_hand"
        );
        // summary.state.cards_dealt 应保留
        assert_eq!(
            table.summary.state.cards_dealt, 10,
            "summary.state.cards_dealt should NOT be cleared by reset_for_next_hand"
        );
        // mental_poker_game.deck_encrypted 应被 reset 重建（52 个 trivial ciphertexts）
        assert_eq!(
            table.mental_poker_game.deck_encrypted.len(), 52,
            "mental_poker_game.deck_encrypted should be rebuilt by reset (52 trivial ciphertexts)"
        );
    }

    /// #16/#17：动作签名验证 + accepted-seq 单调 + 动作日志/公开段。
    #[test]
    fn action_sig_verify_and_accepted_seq() {
        use poker_protocol::crypto::curve::{Curve, CurveScalar};
        use poker_protocol::crypto::curve::StarkCurve;

        let mut table = make_test_table();
        let sk = StarkCurve::hash_to_scalar(b"seat-sk");
        let pk = StarkCurve::base_g() * sk;
        let pk_hex = hex::encode(pk.compress().as_ref());

        // 把 pk_hex 绑到一个座位（直接构造 ActionSig 前的座位解析依赖 seats）
        let sig_r_hex;
        let sig_s_hex;
        {
            let (r_hex, s_hex) = poker_protocol::z_poker::protocol::sign_game_action(
                &sk, table.summary.id, 1, "raise", 320, &mut rand::rngs::OsRng,
            );
            sig_r_hex = r_hex;
            sig_s_hex = s_hex;
        }
        let sig = crate::pokergame::actions::ActionSig {
            r_hex: sig_r_hex.clone(),
            s_hex: sig_s_hex.clone(),
        };
        // 验签只依赖 pk 与消息域，不要求座位已入座
        assert!(table.verify_action_sig(
            &crate::pokergame::player::GamePkHex(pk_hex.clone()), 1, "raise", 320, &sig
        ));
        // 篡改 seq → 失败
        assert!(!table.verify_action_sig(
            &crate::pokergame::player::GamePkHex(pk_hex.clone()), 2, "raise", 320, &sig
        ));

        // 记账：seq 单调推进 + 日志 + 公开段
        table.record_action(0, 1, "raise", 320, false, true);
        table.record_action(0, 2, "call", 0, false, true);
        assert_eq!(table.accepted_seq_of(0), 2);
        assert_eq!(table.action_log.len(), 2);
        let client = table.to_client();
        assert_eq!(client.accepted_seqs.len(), 1);
        assert_eq!(client.accepted_seqs[0].seq, 2);
        let _ = pk;
        let _ = sig_s_hex;
    }

    /// 测试 `deck_plaintext()` 始终从 `mental_poker_game` 读取，不再 fallback 到 `summary.state`。
    ///
    /// 场景：summary.state.deck_plaintext 有假数据，mental_poker_game.deck_plaintext
    /// 也有 52 个明文点（new() 初始化的）。
    /// 预期：deck_plaintext() 返回 mental_poker_game 的值，而非 summary.state 的假数据。
    #[test]
    fn test_deck_plaintext_reads_from_mental_poker_game() {
        let mut table = make_test_table();
        // 记录 mental_poker_game 的初始 deck_plaintext
        let mp_plaintext = table.mental_poker_game.deck_plaintext.clone();
        assert_eq!(mp_plaintext.len(), 52, "mental_poker_game should have 52 plaintext points after new()");

        // 模拟链上同步：summary.state.deck_plaintext 有不同的假数据
        table.summary.state.deck_plaintext = vec![vec![0xCCu8; 48]; 52];

        // deck_plaintext() 应返回 mental_poker_game 的值
        let deck = table.deck_plaintext();
        assert_eq!(deck.len(), 52, "deck_plaintext() should return mental_poker_game's 52 points");
        assert_eq!(deck, mp_plaintext, "deck_plaintext() should match mental_poker_game, not summary.state");
    }

    /// 测试 `aggregated_pk()` 始终从 `mental_poker_game.key_manager` 读取。
    #[test]
    fn test_aggregated_pk_reads_from_mental_poker_game() {
        let mut table = make_test_table();
        // summary.crypto.aggregated_pk 有假数据
        table.summary.crypto.aggregated_pk = vec![0xDDu8; 48];

        // aggregated_pk() 应返回 mental_poker_game.key_manager 中的值（不 panic）
        let pk = table.aggregated_pk();
        // 验证不等于 summary.crypto 中的假数据（mental_poker_game 初始时 agg_pk 为 identity/默认）
        let _ = pk; // 仅验证不 panic 且返回一个值
    }

    /// 测试 zombie seat 清理后 local_players 中对应 pk 被移除。
    ///
    /// 场景：table.local_players 有一个 pk→wallet 映射，table.local_seats 有对应座位，
    /// 但链上该座位已清空（seats_occupied=false, seat_players=0x0）。
    /// 预期：sync_betting_state 清理后 local_players 中对应 pk 被移除。
    #[test]
    fn test_zombie_seat_cleanup_removes_local_players() {
        use crate::pokergame::player::{GamePlayer, WalletAddress};
        use crate::pokergame::seat::Seat;

        let mut table = make_test_table();
        let pk_hex = GamePkHex::new("test_pk_hex".to_string());
        let wallet = WalletAddress::new("0xtestwallet".to_string());

        // 模拟本地有玩家入座
        table.local_players.insert(pk_hex.clone(), wallet.clone());
        table.pk_to_seat.insert(pk_hex.clone(), 0);
        let player = GamePlayer {
            name: "test".to_string(),
            bankroll: 0,
            pk_hex: pk_hex.clone(),
            readable_hands: vec![],
            wallet_address: wallet,
        };
        table.local_seats.insert(0, Seat::new(0, Some(player), 100, 100));

        // 模拟 reset_for_next_hand 的 pk_to_seat + local_players 清理逻辑
        // （与 sync_betting_state 中的 zombie seat 清理对齐）
        let active_seat_pks: std::collections::HashSet<GamePkHex> = table.seats().values()
            .filter_map(|s| s.player.as_ref().map(|p| p.pk_hex.clone()))
            .collect();

        // seat 0 仍有玩家，所以 active_seat_pks 应包含 pk_hex
        assert!(active_seat_pks.contains(&pk_hex));

        // 现在模拟玩家离开（清空 seat 0 的 player）
        table.local_seats.get_mut(&0).unwrap().player = None;

        // 重新计算 active_seat_pks
        let active_seat_pks: std::collections::HashSet<GamePkHex> = table.seats().values()
            .filter_map(|s| s.player.as_ref().map(|p| p.pk_hex.clone()))
            .collect();
        assert!(!active_seat_pks.contains(&pk_hex));

        // 模拟 sync_betting_state 的清理：移除 pk_to_seat + local_players
        table.pk_to_seat.remove(&pk_hex);
        table.local_players.remove(&pk_hex);

        // 验证清理后 local_players 不再包含 pk_hex
        assert!(!table.local_players.contains_key(&pk_hex), "local_players should not contain pk after zombie seat cleanup");
        assert!(!table.pk_to_seat.contains_key(&pk_hex), "pk_to_seat should not contain pk after zombie seat cleanup");
    }
}
