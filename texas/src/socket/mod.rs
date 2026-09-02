pub use handlers::register_handlers;
pub use broadcast::{broadcast_player_update, PlayerUpdatePayload};

pub mod broadcast;
pub mod game_loop;
pub mod handlers;
pub mod table_events;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::OnceLock;
use tokio::sync::RwLock;

use serde::{Deserialize, Serialize};
use socketioxide::{SocketIo, extract::SocketRef};

use crate::config::Config;
use crate::models::Database;
use crate::pokergame::actions;
use crate::pokergame::deck::Card;
use crate::pokergame::game_state::{ElGamalCiphertextJson, MaskAndShuffleRoundJson, ShuffleProofJson, PlayerReadableCardJson,
    PkProofJson, ReconstructProofJson, RevealPhase, ShufflePublicState, LeaveGameRoundJson, SubmitRevealTokenJson};
use crate::pokergame::player::{Player, WalletAddress, GamePkHex, GamePlayer};
use crate::pokergame::table::{ActionRequest, ClientTable, JoinError, JoinResult, RoundState, Table};
use poker_protocol::crypto::EcPoint;
use poker_protocol::z_poker::convert::{ecpoint_to_hex, hex_to_ecpoint, scalar_to_hex};

pub(crate) const MIN_START_NUM: u32 = 2;

pub(crate) fn table_room_name(table_id: u32) -> String {
    format!("table_{}", table_id)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LobbyInfo {
    pub tables: Vec<TableSummary>,
    pub players: Vec<PlayerInfo>,
    pub socket_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct JoinTablePayload {
    pub table_id: u32,
    pub pk_hex: GamePkHex,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LeaveTablePayload {
    pub table_id: u32,
    pub pk_hex: GamePkHex,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TableSummary {
    pub id: u32,
    pub name: String,
    pub limit: u64,
    pub max_players: u32,
    pub current_number_players: usize,
    pub small_blind: u64,
    pub big_blind: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PlayerInfo {
    pub socket_id: String,
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TableLeftPayload {
    pub tables: Vec<TableSummary>,
    pub table_id: u32,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct LeaveDeferredPayload {
    pub table_id: u32,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TableUpdatePayload {
    pub table: ClientTable,
    pub message: Option<String>,
    pub from: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RaisePayload {
    pub table_id: u32,
    pub amount: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TableMessagePayload {
    pub message: String,
    pub from: String,
    pub table_id: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SitDownPayload {
    pub table_id: u32,
    pub seat_id: u32,
    pub amount: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SitDownV2Payload {
    pub token: String,
    pub table_id: u32,
    pub seat_id: u32,
    pub amount: u64,
    pub pk_hex: GamePkHex,
    pub pk_proof: PkProofJson,
    /// 入座模式（服务端权威决定，客户端值仅作参考提示）：
    /// Some = join_and_shuffle（牌桌 waiting/shuffle 阶段）；None = plain join
    /// （牌局进行中买入，waiting 身份入座，下一手参与洗牌）。
    #[serde(default)]
    pub mask_and_shuffle_round: Option<MaskAndShuffleRoundJson>,
    /// Starknet 买入：PokerVault.deposit 交易哈希（前端钱包执行 approve+deposit 后回传）。
    #[serde(default)]
    pub deposit_tx_hash: Option<String>,
    /// 玩家 Starknet 钱包地址（买入校验与结算参与者地址来源）。缺省回退 token 中的用户地址。
    #[serde(default)]
    pub wallet_address: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StandUpPayload {
    pub table_id: u32,
    pub pk_hex: GamePkHex,
    /// 链上模式下，若客户端已直接提交
    /// leave_with_proof_verified 交易，则 leave_round 为 None。
    /// 此时后端跳过本地 proof 验证和 PTB 构建，仅清理 socket 状态，
    /// 实际玩家移除由 relayer 从 PlayerLeft 事件同步。
    pub leave_round: Option<LeaveGameRoundJson>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RebuyPayload {
    pub table_id: u32,
    pub seat_id: u32,
    pub amount: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SittingPayload {
    pub table_id: u32,
    pub seat_id: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ShuffleSubmitPayload {
    pub table_id: u32,
    pub pk_hex: GamePkHex,
    #[serde(default)]
    pub output_cards: Vec<ElGamalCiphertextJson>,
    /// 纯 re_encrypt 路径必填；join 语义路径（携带 mask_and_shuffle_round）可省。
    #[serde(default)]
    pub shuffle_proof: Option<ShuffleProofJson>,
    /// join 语义洗牌（waiting 入座玩家补层）：remask 自身层 + shuffle。
    /// 与 needs_join_layer=true 的 SHUFFLE_NOTICE/快照配套；缺省走纯 re_encrypt 路径。
    #[serde(default)]
    pub mask_and_shuffle_round: Option<MaskAndShuffleRoundJson>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RevealSubmitPayload {
    pub table_id: u32,
    /// Task 5: 可选 pk_hex（向后兼容旧客户端不传该字段）
    pub pk_hex: Option<GamePkHex>,
    /// Task 5: 可选 reveal_tokens（向后兼容旧客户端不传该字段）
    /// 若提供则在 on-chain 模式下构建 PTB，本地模式下走 submit_reveal_tokens_for_pk
    pub reveal_tokens: Option<Vec<SubmitRevealTokenJson>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RedealRequestPayload {
    pub table_id: u32,
    pub player_pk: GamePkHex,
    pub failed_card_indices: Vec<usize>,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ReconstructSubmitPayload {
    pub table_id: u32,
    pub pk_hex: GamePkHex,
    pub output_cards: Vec<ElGamalCiphertextJson>,
    pub swap_cards: Vec<ElGamalCiphertextJson>,
    /// Task 4: 用户可读牌（每个 swap_out 对应一张），on-chain 模式下需要传给 Move 合约
    /// 旧客户端不发送该字段，缺省按空处理。
    #[serde(default)]
    pub user_readable_cards: Vec<ElGamalCiphertextJson>,
    pub proof: ReconstructProofJson,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HandRevealResultPayload {
    pub table_id: u32,
    pub player_pk: GamePkHex,
    pub readable_cards: Vec<ElGamalCiphertextJson>,
    pub deck_plaintext: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CommunityRevealResultPayload {
    pub table_id: u32,
    pub community_cards: Vec<Card>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReconstructInitiatePayload {
    pub table_id: u32,
    pub target_socket_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReconstructVotePayload {
    pub table_id: u32,
    pub vote: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ShuffleNoticePayload {
    pub table_id: u32,
    pub shuffle_state: Option<ShufflePublicState>,
}

/// Plan D P2.1：Hand-batch 认可收集的请求/提交载荷。
/// 客户端（useGameSocket）按 camelCase 读取，序列化须用 camelCase。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EndorsementRequestPayload {
    pub table_id: u32,
    pub hand_id: u32,
    /// 32B 大端 hand_binding（认可铸造的挑战域）
    pub hand_binding_hex: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EndorsementSubmitPayload {
    pub wallet: String,
    #[serde(alias = "tableId")]
    pub table_id: u32,
    #[serde(alias = "handId")]
    pub hand_id: u32,
    pub pk_x_hex: String,
    pub pk_y_hex: String,
    pub r_x_hex: String,
    pub r_y_hex: String,
    pub s_hex: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RevealNoticePayload {
    pub table_id: u32,
    pub phase: RevealPhase,
    pub pending_players: Vec<GamePkHex>,
    pub completed_players: Vec<GamePkHex>,
    pub player_assignments: HashMap<GamePkHex, crate::pokergame::game_state::PlayerRevealAssignment>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ReconstructNoticePayload {
    pub table_id: u32,
    pub completed_players: Vec<GamePkHex>,
    pub pending_players: Vec<GamePkHex>,
    pub cards: Vec<String>,
    pub coefficient_hex: String,
    pub player_readable_cards: HashMap<GamePkHex, PlayerReadableCardJson>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ReconstructResultPayload {
    pub table_id: u32,
    pub completed_players: Vec<GamePkHex>,
    pub reconstructed: bool,
}

pub(crate) struct GameLoopEntry {
    pub _handle: tokio::task::JoinHandle<()>,
    pub action_sender: tokio::sync::mpsc::Sender<ActionRequest>,
    pub stop_sender: tokio::sync::watch::Sender<bool>,
}

pub(crate) struct GameLoopRegistry {
    pub entries: HashMap<u32, GameLoopEntry>,
}

impl GameLoopRegistry {
    pub fn new() -> Self {
        Self { entries: HashMap::new() }
    }

    pub fn contains(&self, table_id: u32) -> bool {
        self.entries.contains_key(&table_id)
    }

    pub fn get_sender(&self, table_id: u32) -> Option<tokio::sync::mpsc::Sender<ActionRequest>> {
        self.entries.get(&table_id).map(|e| e.action_sender.clone())
    }

    pub fn insert(&mut self, table_id: u32, entry: GameLoopEntry) {
        self.entries.insert(table_id, entry);
    }

    pub fn remove(&mut self, table_id: u32) {
        if let Some(entry) = self.entries.remove(&table_id) {
            let _ = entry.stop_sender.send(true);
        }
    }
}

static SOCKET_IO: OnceLock<SocketIo> = OnceLock::new();

pub fn set_socket_io(io: SocketIo) {
    let _ = SOCKET_IO.set(io);
}

pub(crate) fn get_socket_io() -> Option<SocketIo> {
    SOCKET_IO.get().cloned()
}

pub(crate) struct GameState {
    pub tables: HashMap<u32, Table>,
    pub players: HashMap<String, Player>,
    pub disconnect_cancellers: HashMap<String, tokio::sync::watch::Sender<bool>>,
}

impl GameState {
    /// Remove a player by pk_hex from the specified table and the players map.
    /// Returns the player's socket_id if found.
    pub fn remove_player_by_pk(&mut self, table_id: u32, pk_hex: &GamePkHex) -> Option<String> {
        let wallet_address = self.tables.get(&table_id)
            .and_then(|table| table.players().get(pk_hex).cloned());

        if let Some(wallet_addr) = wallet_address {
            let socket_id = self.players.iter()
                .find(|(_, p)| p.wallet_address == wallet_addr)
                .map(|(_, p)| p.socket_id.clone());

            // Remove from the specified table
            if let Some(table) = self.tables.get_mut(&table_id) {
                table.remove_player_by_pk(pk_hex);
            }

            // Remove from players map
            if let Some(ref sid) = socket_id {
                self.players.remove(sid);
            }

            socket_id
        } else {
            None
        }
    }
}

pub struct SocketState {
    pub db: Database,
    pub state: RwLock<GameState>,
    pub config: Config,
    pub game_loop_registry: RwLock<GameLoopRegistry>,
}

impl SocketState {
    pub fn new(db: Database, tables: HashMap<u32, Table>, config: Config) -> Self {
        Self {
            db,
            state: RwLock::new(GameState {
                tables,
                players: HashMap::new(),
                disconnect_cancellers: HashMap::new(),
            }),
            config,
            game_loop_registry: RwLock::new(GameLoopRegistry::new()),
        }
    }

    /// 已弃用：原从 relayer 缓存同步 deck 的逻辑。
    /// 移除 RelayerState 后，`sync_table_state`（relayer/mod.rs）已直接将
    /// `summary.crypto` 同步到 `table.summary.crypto`，本函数无需再做事。
    pub async fn sync_deck_from_relayer_cache(&self, _table_id: u32) {
        // no-op: table.summary.crypto 已由 sync_table_state 同步
    }

    /// 为所有已注册的 table 创建事件 channel 并 spawn consumer 任务。
    ///
    /// 在 `main.rs` 中 `SocketIo` 实例创建后调用。对每个 table：
    /// 1. 创建 `mpsc::channel::<TableEvent>(256)`
    /// 2. 调用 `table.set_event_sender(tx)` 注入 sender
    /// 3. spawn `table_event_consumer` 任务消费事件并执行 socket 广播
    pub async fn init_table_event_channels(self: &Arc<Self>, io: SocketIo) {
        let mut gs = self.state.write().await;
        let table_ids: Vec<u32> = gs.tables.keys().copied().collect();
        for table_id in table_ids {
            if let Some(table) = gs.tables.get_mut(&table_id) {
                let (tx, rx) = tokio::sync::mpsc::channel::<crate::pokergame::table::events::TableEvent>(256);
                table.set_event_sender(tx);
                tracing::info!("[TABLE-EVENTS] Initialized event channel for table {}", table_id);
                // spawn 不会立即执行 consumer，它在当前任务释放锁后才调度
                tokio::spawn(crate::socket::table_events::table_event_consumer(
                    io.clone(),
                    self.clone(),
                    table_id,
                    rx,
                ));
            }
        }
    }

    pub(crate) async fn get_current_tables(&self) -> Vec<TableSummary> {
        let gs = self.state.read().await;
        gs.tables
            .values()
            .map(|t| TableSummary {
                id: t.summary.id,
                name: t.name().to_string(),
                limit: t.summary.limit,
                max_players: t.max_players(),
                current_number_players: t.players().len(),
                small_blind: t.summary.min_bet,
                big_blind: t.summary.min_bet * 2,
            })
            .collect()
    }

    pub(crate) async fn get_current_players(&self) -> Vec<PlayerInfo> {
        let gs = self.state.read().await;
        gs.players
            .values()
            .map(|p| PlayerInfo {
                socket_id: p.socket_id.clone(),
                id: p.id.clone(),
                name: p.name.clone(),
            })
            .collect()
    }

    pub async fn get_action_sender(&self, table_id: u32) -> Option<tokio::sync::mpsc::Sender<ActionRequest>> {
        let registry = self.game_loop_registry.read().await;
        registry.get_sender(table_id)
    }

    pub async fn start_game_loop(&self, io: SocketIo, state: Arc<SocketState>, table_id: u32) {
        let mut registry = self.game_loop_registry.write().await;
        if registry.contains(table_id) {
            return;
        }
        let (tx, rx) = tokio::sync::mpsc::channel::<ActionRequest>(100);
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let handle = tokio::spawn(game_loop::game_loop_task(io, state, table_id, rx, stop_rx));
        registry.insert(table_id, GameLoopEntry {
            _handle: handle,
            action_sender: tx,
            stop_sender: stop_tx,
        });
    }

    pub async fn start_game_loop_from_ctx(&self, state: Arc<SocketState>, table_id: u32) {
        let io = match get_socket_io() {
            Some(io) => io,
            None => return,
        };
        self.start_game_loop(io, state, table_id).await;
    }

    pub async fn stop_game_loop(&self, table_id: u32) {
        // tracing::info!("stop_game_loop: {}", table_id);
        let mut registry = self.game_loop_registry.write().await;
        registry.remove(table_id);
    }

    /// Resolve socket_id from a pk_hex for a given table
    pub async fn resolve_socket_id_by_pk(&self, table_id: u32, pk_hex: &GamePkHex) -> Option<String> {
        let gs = self.state.read().await;
        let wallet_addr = gs.tables.get(&table_id)
            .and_then(|table| table.players().get(pk_hex).cloned());
        if let Some(wallet_addr) = wallet_addr {
            gs.players.values()
                .find(|p| p.wallet_address == wallet_addr)
                .map(|p| p.socket_id.clone())
        } else {
            None
        }
    }

    pub async fn find_socket_id_by_pk(&self, table_id: u32, pk_hex: &GamePkHex) -> Option<String> {
        self.resolve_socket_id_by_pk(table_id, pk_hex).await
    }

    pub async fn send_shuffle_notice(&self, table_id: u32) {
        let io = match get_socket_io() {
            Some(io) => io,
            None => return,
        };

        // 非阻塞地从 relayer 已同步好的 TableSummaryV2 缓存中同步 deck_encrypted。
        // 客户端会用此 deck 生成 remask proof，如果 deck 过期会导致上链验证失败。
        // 这里只读 relayer 内存缓存（已被链上事件同步），不做阻塞式 RPC 调用，
        // 避免阻塞 SHUFFLE_NOTICE 推送。
        self.sync_deck_from_relayer_cache(table_id).await;

        let shuffle_notice_data = {
            let gs = self.state.read().await;
            if let Some(table) = gs.tables.get(&table_id) {
                // 诊断日志：记录 deck 来源信息
                let mp_deck_len = table.mental_poker_game.deck_encrypted.len();
                let summary_deck_len = table.summary.crypto.deck_encrypted.len();
                let shuffle_active = table.shuffle_state.is_active();
                let shuffle_phase = format!("{:?}", table.shuffle_state.phase);
                tracing::info!(
                    "[send_shuffle_notice] table={} mental_poker_deck_len={} summary_crypto_deck_len={} shuffle_active={} shuffle_phase={}",
                    table_id, mp_deck_len, summary_deck_len, shuffle_active, shuffle_phase
                );

                let shuffle_state = table.get_shuffle_public_state();
                let current_pk = table.shuffle_state.current_player_pk.clone();
                let socket_id = if let Some(pk) = &current_pk {
                    if let Some(wallet_address) = table.players().get(pk) {
                        let found = gs.players.values()
                            .find(|p| &p.wallet_address == wallet_address)
                            .map(|p| p.socket_id.clone());
                        if found.is_none() {
                            tracing::warn!(
                                "send_shuffle_notice: table {} pk {} wallet {} not found in gs.players (wallet_addr mismatch - possible proxy_address issue)",
                                table_id,
                                pk,
                                wallet_address.0
                            );
                        }
                        found
                    } else {
                        None
                    }
                } else {
                    None
                };
                shuffle_state.zip(socket_id)
            } else {
                None
            }
        };

        if let Some((shuffle_state, socket_id)) = shuffle_notice_data {
            let deck_len = shuffle_state.deck_encrypted.len();
            let first_c1 = shuffle_state.deck_encrypted.first().map(|c| c.c1_hex.as_str()).unwrap_or("none");
            let first_c2 = shuffle_state.deck_encrypted.first().map(|c| c.c2_hex.as_str()).unwrap_or("none");
            tracing::info!(
                "[send_shuffle_notice] table={} deck_len={} first_c1={}... first_c2={}... current_pk={:?}",
                table_id,
                deck_len,
                &first_c1[..std::cmp::min(16, first_c1.len())],
                &first_c2[..std::cmp::min(16, first_c2.len())],
                shuffle_state.current_player_pk
            );
            if let Ok(sid) = socket_id.parse::<socketioxide::socket::Sid>() {
                if let Some(socket) = io.get_socket(sid) {
                    let notice = ShuffleNoticePayload { table_id, shuffle_state: Some(shuffle_state) };
                    let _ = socket.emit(actions::SHUFFLE_NOTICE, &notice);
                }
            } else {
                tracing::warn!(
                    "[send_shuffle_notice] table={} failed to parse socket_id={:?} or socket not found",
                    table_id, socket_id
                );
            }
        } else {
            tracing::warn!(
                "[send_shuffle_notice] table={} no shuffle_notice_data (shuffle_state inactive or no socket)",
                table_id
            );
        }
    }

    pub async fn mark_player_sitting_out(&self, table_id: u32, wallet_address: &WalletAddress) {
        let mut gs = self.state.write().await;
        if let Some(table) = gs.tables.get_mut(&table_id) {
            for seat in table.local_seats.values_mut() {
                if seat.player.as_ref().map_or(false, |p| &p.wallet_address == wallet_address) {
                    seat.sitting_out = true;
                }
            }
        }
    }

    pub async fn is_player_in_seat(&self, pk_hex: &GamePkHex) -> bool {
        let gs = self.state.read().await;
        gs.tables.values().any(|table| {
            table.seats().values().any(|seat| {
                seat.player.as_ref().map_or(false, |p| &p.pk_hex == pk_hex)
            })
        })
    }

    pub async fn find_player_by_pk(&self, table_id: u32, pk_hex: &GamePkHex) -> Option<Player> {
        let gs = self.state.read().await;
        let wallet_address = gs.tables.get(&table_id).and_then(|table| table.players().get(pk_hex).cloned());
        if let Some(wallet_addr) = wallet_address {
            gs.players.iter().find(|(_, p)| &p.wallet_address == &wallet_addr).map(|(_, p)| p.clone())
        } else {
            None
        }
    }

    pub async fn get_client_table(&self, table_id: u32) -> Option<ClientTable> {
        let gs = self.state.read().await;
        gs.tables.get(&table_id).map(|t| t.to_client())
    }

    pub async fn add_player_to_table(&self, table_id: u32, player: Player, pk_hex: &GamePkHex) -> Result<usize, String> {
        let mut gs = self.state.write().await;
        gs.players.insert(player.socket_id.clone(), player.clone());
        if let Some(table) = gs.tables.get_mut(&table_id) {
            table.add_player(pk_hex.clone(), player.wallet_address.clone());
            Ok(table.active_players().len())
        } else {
            Err("Table not found".to_string())
        }
    }

    pub async fn join_player_and_shuffle(
        &self,
        table_id: u32,
        player: Player,
        player_pk: EcPoint,
        pk_proof_json: PkProofJson,
        round_json: Option<MaskAndShuffleRoundJson>,
        seat_id: u32,
        amount: u64,
    ) -> Result<(bool, JoinResult), JoinError> {
        let mirror_pk_proof = pk_proof_json.to_proof()
            .map(|p| crate::relayer::proof_bytes::serialize_pk_ownership_proof(&p))
            .unwrap_or_default();
        let socket_id = player.socket_id.clone();
        let pk_hex = GamePkHex::new(ecpoint_to_hex(&player_pk));
        crate::starknet::hooks::register_seat_wallet(&pk_hex.0, &player.wallet_address.0);
        let player_wallet_address = player.wallet_address.clone();

        let player_name = player.name.clone();
        let player_id = player.id.clone();
        let player_bankroll = player.bankroll;

                // Starknet 镜像：缓冲带真实证明的 join（下一手 start_preflop_shuffle 应用）
                crate::starknet::hooks::mirror_buffer_join_pk(
                    table_id,
                    &player_wallet_address,
                    pk_hex.clone().0.as_str(),
                    amount,
                    &pk_proof_json,
                    mirror_pk_proof,
                );


        let result = {
            let mut gs = self.state.write().await;
            if let Some(table) = gs.tables.get_mut(&table_id) {
                table.join_player_and_shuffle(player, player_pk, pk_proof_json, round_json, seat_id, amount)
            } else {
                Err(JoinError::Crypto("Table not found".to_string()))
            }
        };

        match &result {
            Ok(JoinResult::JoinedAndShuffled) => {
                let mut gs = self.state.write().await;
                let already_exists = gs.players.values().any(|p| p.wallet_address == player_wallet_address);
                if !already_exists {
                    gs.players.insert(socket_id.clone(), Player {
                        socket_id: socket_id.clone(),
                        id: player_id,
                        name: player_name,
                        bankroll: player_bankroll,
                        wallet_address: player_wallet_address.clone(),
                    });
                }

                if let Some(table) = gs.tables.get_mut(&table_id) {
                    if table.is_pending_shuffle_player_empty() && table.complete_shuffle_player_count() >= MIN_START_NUM as usize  {
                        table.shuffle_state.phase = crate::pokergame::game_state::ShufflePhase::None;
                        tracing::info!("[SHUFFLE] Player {} joined and shuffled, all players shuffled {:?}", pk_hex,table.shuffle_state.completed_players);
                        return Ok((true, JoinResult::JoinedAndShuffled));
                    } else {
                        tracing::info!("[SHUFFLE] Player {} joined and shuffled, but not enough players to start,shuffle cnt {}", pk_hex, table.complete_shuffle_player_count());
                        table.complete_or_continue_next_shuffler();
                    }
                }
                Ok((false, JoinResult::JoinedAndShuffled))
            }
            Ok(JoinResult::JoinedWaiting) => {
                let mut gs = self.state.write().await;
                let already_exists = gs.players.values().any(|p| p.wallet_address.0 == player_wallet_address.0);
                if !already_exists {
                    gs.players.insert(socket_id.clone(), Player {
                        socket_id: socket_id.clone(),
                        id: player_id,
                        name: player_name,
                        bankroll: player_bankroll,
                        wallet_address: player_wallet_address,
                    });
                }
                Ok((false, JoinResult::JoinedWaiting))
            }
            Err(e) => Err(e.clone()),
        }
    }

    /// 返回 Ok(true) 表示洗牌完成且 reveal phase 已启动（需外部 broadcast reveal）。
    pub async fn submit_verified_shuffle_for_pk(
        &self,
        table_id: u32,
        pk_hex: &GamePkHex,
        _player: Player,
        output_cards: Vec<ElGamalCiphertextJson>,
        shuffle_proof: Option<ShuffleProofJson>,
        join_round: Option<MaskAndShuffleRoundJson>,
    ) -> Result<bool, String> {
        let mut gs = self.state.write().await;
        if let Some(table) = gs.tables.get_mut(&table_id) {
                    let verified = match &join_round {
                        // join 语义：waiting 入座玩家补自身层（remask+shuffle）
                        Some(round) => table.submit_join_shuffle(pk_hex, round.clone()),
                        None => match shuffle_proof {
                            Some(proof) => {
                                table.submit_verified_shuffle(pk_hex, output_cards.clone(), proof)
                            }
                            None => Err("missing shuffle_proof (plain path)".to_string()),
                        },
                    };
                    match verified {
                        Ok(()) => {
                            // 方案A：洗牌不再转发 mirror（deck 由游戏层验证后
                            // 在 advance_shuffle 终局点整体注入）。
                            if table.is_all_players_shuffled()
                                && table.complete_shuffle_player_count() >= MIN_START_NUM as usize
                            {
                                // 所有玩家完成洗牌 → advance_shuffle 推进流程
                                // (on_shuffle_complete + on_before_preflop_shuffle_complete + transition_to(PreFlop) + start_preflop_reveal_phase)
                                table.advance_shuffle();
                                // advance_shuffle 内部可能启动 reveal phase，
                                // 外部调用方需据此 broadcast reveal notice
                                Ok(table.reveal_token_state.is_active())
                            } else {
                                table.complete_or_continue_next_shuffler();
                                Ok(false)
                            }
                        }
                        Err(e) => Err(e),
                    }
                } else {
            Err("Table not found".to_string())
        }
    }

    pub async fn mark_reveal_complete_for_pk(&self, table_id: u32, pk_hex: &GamePkHex) -> Result<bool, String> {
        let mut gs = self.state.write().await;
        if let Some(table) = gs.tables.get_mut(&table_id) {
            Ok(table.mark_player_reveal_complete(pk_hex))
        } else {
            Err("Table not found".to_string())
        }
    }

    pub async fn submit_reveal_tokens_for_pk(
        &self,
        table_id: u32,
        pk_hex: &GamePkHex,
        tokens: Vec<poker_protocol::z_poker::protocol::RevealToken>,
    ) -> Result<(), String> {
        let mut gs = self.state.write().await;
        if let Some(table) = gs.tables.get_mut(&table_id) {
            let result = table.submit_player_reveal_tokens(pk_hex, tokens.clone());
            if result.is_ok() {
                // Starknet 镜像：同步 reveal tokens（失败仅告警）
                crate::starknet::hooks::mirror_sync_reveal(table_id, pk_hex, &tokens);
            }
            result
        } else {
            Err("Table not found".to_string())
        }
    }

    pub async fn get_reveal_phase_for_table(&self, table_id: u32) -> Option<crate::pokergame::game_state::RevealPhase> {
        let gs = self.state.read().await;
        gs.tables.get(&table_id).map(|t| t.reveal_token_state.phase)
    }
}

pub(crate) fn hide_opponent_cards(base: &ClientTable, wallet_address: &WalletAddress) -> ClientTable {
    let mut copy = base.clone();
    let hidden_card = Card { suit: "hidden".to_string(), rank: "hidden".to_string() };
    let hidden_hand = vec![hidden_card.clone(), hidden_card];

    let cards_dealt = !matches!(
        copy.round_state,
        RoundState::Waiting
    );

    for seat in copy.seats.values_mut() {
        let is_opponent = seat.player.as_ref().map_or(true, |p| &p.wallet_address != wallet_address);
        // 摊牌时所有未弃牌玩家都应亮牌；非摊牌时仅赢家亮牌
        let should_show = if copy.went_to_showdown {
            !seat.folded
        } else {
            seat.last_action.as_deref() == Some(actions::WINNER)
        };

        if is_opponent && !should_show {
            if seat.hand.len() > 0 {
                seat.hand = hidden_hand.clone();
            } else if cards_dealt && !seat.folded && !seat.sitting_out && seat.player.is_some() {
                seat.hand = hidden_hand.clone();
            }
        }
    }
    copy
}

pub(crate) async fn send_simple_action(socket: &SocketRef, state: &Arc<SocketState>, table_id: u32, action: &str) {
    let socket_id = socket.id.to_string();
    let pk_hex = {
        let gs = state.state.read().await;
        gs.players.get(&socket_id)
            .and_then(|p| gs.tables.get(&table_id).and_then(|t| t.get_pk_hex_by_wallet_address(&p.wallet_address.0)))
    };
    if let (Some(pk_hex), Some(sender)) = (pk_hex, state.get_action_sender(table_id).await) {
        let _ = sender.send(ActionRequest { pk_hex, action: action.to_string(), amount: None }).await;
    }
}
