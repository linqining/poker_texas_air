use std::sync::Arc;

use super::*;
pub(crate) use crate::pokergame::table::events::CryptoEventType;

pub(crate) async fn broadcast_to_table(io: &SocketIo, state: &Arc<SocketState>, table_id: u32, message: Option<&str>) {
    let table_views = {
        let gs = state.state.read().await;
        let Some(table) = gs.tables.get(&table_id) else { return };
        let base_client_table = table.to_client();
        table.players().iter()
            .flat_map(|(_game_pk, wallet_addr)| {
                // 同一钱包可能残留多条 players 条目（旧会话 socket 未清理），
                // 只 find 一个会把广播发到僵尸 socket 上造成客户端丢事件；
                // 对该钱包的所有活跃 socket 各发一份（视图按钱包定制一致）。
                let view = hide_opponent_cards(&base_client_table, wallet_addr);
                gs.players.values()
                    .filter(|p| p.wallet_address.0.eq_ignore_ascii_case(&wallet_addr.0))
                    .map(move |p| (p.socket_id.clone(), view.clone()))
            })
            .collect::<Vec<_>>()
    };

    for (sid_str, table_view) in table_views {
        let payload = TableUpdatePayload {
            table: table_view,
            message: message.map(|s| s.to_string()),
            from: None,
        };
        if let Ok(sid) = sid_str.parse::<socketioxide::socket::Sid>() {
            if let Some(socket) = io.get_socket(sid) {
                tracing::info!("broadcast_to_table: socket {} found", sid_str);
                if let Err(e) = socket.emit(actions::TABLE_UPDATED, &payload) {
                    tracing::warn!("broadcast_to_table emit failed for {}: {:?}", sid_str, e);
                }
            } else {
                tracing::warn!("broadcast_to_table: socket {} not found (wallet_addr mismatch - possible proxy_address issue)", sid_str);
            }
        }
    }
}

pub(crate) async fn join_table_push(io: &SocketIo, state: &Arc<SocketState>, table_id: u32, wallet: WalletAddress) {
    // G18 修复：原实现使用 io.emit 广播给所有 socket，但 table_view 是为该 wallet
    // 定制的（hide_opponent_cards 隐藏对手手牌），广播会导致其他玩家看到错误的 view。
    // 改为只 emit 给加入的 socket。
    tracing::info!("[join_table_push] enter, table_id={}, wallet={}", table_id, wallet.0);

    let (socket_id_opt, table_view) = {
        let gs = state.state.read().await;
        let Some(table) = gs.tables.get(&table_id) else { return };
        let base_client_table = table.to_client();
        let view = hide_opponent_cards(&base_client_table, &wallet);
        // 找到该 wallet 对应的 socket_id
        let sid = gs.players.values()
            .find(|p| p.wallet_address.0.eq_ignore_ascii_case(&wallet.0))
            .map(|p| p.socket_id.clone());
        (sid, view)
    };

    let payload = TableUpdatePayload {
        table: table_view,
        message: Some("".to_string()),
        from: None,
    };

    let Some(sid_str) = socket_id_opt else {
        tracing::debug!("[join_table_push] socket not found for wallet {}", wallet.0);
        return;
    };
    if let Ok(sid) = sid_str.parse::<socketioxide::socket::Sid>() {
        if let Some(socket) = io.get_socket(sid) {
            if let Err(e) = socket.emit(actions::TABLE_UPDATED, &payload) {
                tracing::warn!("[join_table_push] emit failed for {}: {:?}", sid_str, e);
            }
        } else {
            tracing::debug!("[join_table_push] socket {} not found", sid_str);
        }
    }
}

impl SocketState {
    pub(crate) async fn broadcast_player_reveal_result(&self, table_id: u32, action: &str) {
        let io = match get_socket_io() {
            Some(io) => io,
            None => return,
        };
        tracing::info!("broadcast_player_reveal_result: {} {}", table_id, action);
        let (player_cards, deck_plaintext, socket_id_map) = {
            let gs = self.state.read().await;
            let table = match gs.tables.get(&table_id) {
                Some(t) => t,
                None => return,
            };
            let player_cards = table.mental_poker_game.get_player_readable_tokens();
            // 同一钱包可能残留多条 players 条目（重连后的旧 socket），
            // find 单选会把 HAND_REVEAL_RESULT 发到僵尸 socket 上，
            // 客户端永远收不到自己的可读牌 → 自己的牌不显示。
            // 这里改为收集该钱包的全部活跃 socket。
            let mut socket_id_map: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
            for (game_pk, wallet_addr) in table.players().iter() {
                for p in gs.players.values()
                    .filter(|p| p.wallet_address.0.eq_ignore_ascii_case(&wallet_addr.0)) {
                    socket_id_map.entry(game_pk.0.clone()).or_default().push(p.socket_id.clone());
                }
            }
            if socket_id_map.len() < table.players().len() {
                tracing::warn!(
                    "broadcast_player_reveal_result: table {} socket_id_map missing {} players (wallet_addr mismatch - possible proxy_address issue)",
                    table_id,
                    table.players().len() - socket_id_map.len()
                );
            }
            let deck_plaintext = table.deck_plaintext()
                .iter()
                .map(|p| ecpoint_to_hex(p))
                .collect::<Vec<String>>();
            (player_cards, deck_plaintext, socket_id_map)
        };

        for (player_pk, cards) in player_cards {
            let socket_ids = match socket_id_map.get(&player_pk) {
                Some(s) if !s.is_empty() => s.clone(),
                _ => continue,
            };
            for socket_id in socket_ids {
            let readable_cards: Vec<ElGamalCiphertextJson> = cards.iter()
                .map(|c| ElGamalCiphertextJson::from_ciphertext(c))
                .collect();
            let payload = HandRevealResultPayload {
                table_id,
                player_pk: GamePkHex::new(player_pk.clone()),
                readable_cards,
                deck_plaintext: deck_plaintext.clone(),
            };
                if let Ok(sid) = socket_id.parse::<socketioxide::socket::Sid>() {
                    if let Some(socket) = io.get_socket(sid) {
                        let _ = socket.emit(action, &payload);
                    }
                }
            }
        }
    }

    pub async fn broadcast_hand_reveal_result(&self, table_id: u32) {
        self.broadcast_player_reveal_result(table_id, actions::HAND_REVEAL_RESULT).await;
    }

    pub async fn broadcast_redeal_result(&self, table_id: u32) {
        self.broadcast_player_reveal_result(table_id, actions::REDEAL_RESULT).await;
    }







    pub async fn broadcast_redeal_notice(&self, table_id: u32) {
        let io = match get_socket_io() {
            Some(io) => io,
            None => return,
        };

        let reveal_notice = {
            let gs = self.state.read().await;
            gs.tables.get(&table_id).map(|t| {
                let phase = t.reveal_token_state.phase.clone();
                let pending = t.reveal_token_state.pending_players.clone();
                let completed = t.reveal_token_state.completed_players.clone();
                let player_assignments = t.reveal_token_state.player_assignments.clone();
                RevealNoticePayload { table_id, phase, pending_players: pending, completed_players: completed, player_assignments }
            })
        };

        if let Some(notice) = reveal_notice {
            let _ = io.to(table_room_name(table_id)).emit(actions::REDEAL_NOTICE, &notice).await;
        }
    }

    pub async fn broadcast_showdown_result(self: &Arc<Self>, table_id: u32) {
        let io = match get_socket_io() {
            Some(io) => io,
            None => return,
        };

        {
            let mut gs = self.state.write().await;
            if let Some(table) = gs.tables.get_mut(&table_id) {
                let (player_revealed_map, _) = table.mental_poker_game.list_revealed_cards();

                for seat in table.local_seats.values_mut() {
                    if let Some(player) = &seat.player {
                        if let Some(revealed_cards) = player_revealed_map.get(&player.pk_hex.0) {
                            if revealed_cards.len() >= 2 {
                                let hand: Vec<Card> = revealed_cards.iter()
                                    .map(|pc| Card::from_playing_card(pc))
                                    .collect();
                                seat.hand = hand;
                            }
                        }
                    }
                }
            }
        }
        broadcast_to_table(&io, self, table_id, None).await;
    }



    /// 链下模式：从 `mental_poker_game` 读取已揭示的公共牌并广播 `COMMUNITY_REVEAL_RESULT`。
    pub async fn broadcast_community_cards(&self, table_id: u32) {
        let io = match get_socket_io() {
            Some(io) => io,
            None => return,
        };

        let community_cards = {
            let gs = self.state.read().await;
            match gs.tables.get(&table_id) {
                Some(table) => table.mental_poker_game.list_revealed_community_cards(),
                None => return,
            }
        };

        let cards: Vec<Card> = community_cards
            .iter()
            .map(|pc| Card::from_playing_card(pc))
            .collect();

        let payload = CommunityRevealResultPayload {
            table_id,
            community_cards: cards,
        };
        let _ = io
            .to(table_room_name(table_id))
            .emit(actions::COMMUNITY_REVEAL_RESULT, &payload)
            .await;
    }


}

// ---------------------------------------------------------------------------
// ZK 密码学事件广播（crypto_event）
// ---------------------------------------------------------------------------

/// ZK 密码学事件载荷，对应前端约定的 `crypto_event` WS 消息格式。
///
/// 顶层 `type` 字段固定为 `"crypto_event"`，便于前端区分此事件与现有 GameState 广播。
#[derive(Debug, Clone, Serialize)]
pub(crate) struct CryptoEventPayload {
    /// 固定为 `"crypto_event"`，前端据此区分消息类型
    #[serde(rename = "type")]
    pub msg_type: &'static str,
    /// 事件子类型：shuffle / remask / reveal_token / leave / reconstruct
    pub event_type: &'static str,
    /// 提交证明的玩家公钥（hex）
    pub player_pk: String,
    /// 卡片索引，仅 reveal_token 类事件可能携带；其他类型为 null
    pub card_index: Option<u32>,
    /// 链上交易 digest，若验证在链下完成则为 null（前端显示 "pending onchain"）
    pub tx_digest: Option<String>,
    /// 链上/链下验证是否通过
    pub verified: bool,
    /// 事件时间戳（Unix 秒）
    pub timestamp: u64,
    /// 可选的人话描述
    pub message: Option<String>,
}

impl SocketState {
    /// 广播一条 `crypto_event` 消息给该桌所有 WS 客户端。
    ///
    /// 这是"观察者"事件：广播失败只记日志，不传播错误，绝不阻塞游戏主流程。
    /// `tx_digest` 为链上交易 digest（链下验证场景传 None，前端显示 "pending onchain"）。
    pub async fn broadcast_crypto_event(
        &self,
        table_id: u32,
        event_type: CryptoEventType,
        player_pk: String,
        card_index: Option<u32>,
        verified: bool,
        message: Option<String>,
        tx_digest: Option<String>,
    ) {
        let io = match get_socket_io() {
            Some(io) => io,
            None => {
                tracing::debug!(
                    "[crypto_event] socket.io 未初始化，跳过广播: table_id={}, event_type={}",
                    table_id,
                    event_type.as_str()
                );
                return;
            }
        };

        let payload = CryptoEventPayload {
            msg_type: actions::CRYPTO_EVENT,
            event_type: event_type.as_str(),
            player_pk,
            card_index,
            tx_digest,
            verified,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            message,
        };

        // 复用现有 room emit 机制（与 broadcast_redeal_notice 相同），
        // crypto_event 载荷对所有客户端一致，无需 per-player 定制。
        if let Err(e) = io
            .to(table_room_name(table_id))
            .emit(actions::CRYPTO_EVENT, &payload)
            .await
        {
            tracing::warn!(
                "[crypto_event] 广播失败: table_id={}, event_type={}, error={:?}",
                table_id,
                event_type.as_str(),
                e
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 玩家变更事件广播（player_update）
// ---------------------------------------------------------------------------

/// 玩家变更事件载荷，对应前端约定的 `player_update` WS 消息格式。
///
/// 顶层 `type` 字段固定为 `"player_update"`，用于同步链上玩家加入/离开/踢出/退款事件。
#[derive(Debug, Clone, Serialize)]
pub struct PlayerUpdatePayload {
    #[serde(rename = "type")]
    pub event_type: String,
    pub action: String,
    pub table_id: u64,
    pub seat_index: u64,
    pub pk_hex: String,
    pub wallet: String,
    pub buy_in: u64,
    pub reason: u64,
    pub message: String,
}

/// 广播一条 `player_update` 消息给该桌所有 WS 客户端。
///
/// 这是"观察者"事件：广播失败只记日志，不传播错误，绝不阻塞游戏主流程。
pub async fn broadcast_player_update(
    io: &SocketIo,
    table_id: u64,
    action: &str,
    seat_index: u64,
    pk_hex: String,
    wallet: String,
    buy_in: u64,
    reason: u64,
    message: String,
) {
    let payload = PlayerUpdatePayload {
        event_type: actions::PLAYER_UPDATE.to_string(),
        action: action.to_string(),
        table_id,
        seat_index,
        pk_hex,
        wallet,
        buy_in,
        reason,
        message,
    };
    match io.to(table_room_name(table_id as u32)).emit(actions::PLAYER_UPDATE, &payload).await {
        Ok(_) => {}
        Err(e) => tracing::warn!("broadcast_player_update emit failed: {}", e),
    }
}

/// #17：ACTION_RECEIPT 广播（全桌可见；客户端留存作为审查证据）。
pub(crate) async fn broadcast_action_receipt(
    io: &SocketIo,
    state: &Arc<SocketState>,
    table_id: u32,
    payload: &serde_json::Value,
) {
    let socket_ids: Vec<String> = {
        let gs = state.state.read().await;
        let Some(table) = gs.tables.get(&table_id) else { return };
        table
            .players()
            .iter()
            .flat_map(|(_, wallet_addr)| {
                gs.players
                    .values()
                    .filter(|p| p.wallet_address.0.eq_ignore_ascii_case(&wallet_addr.0))
                    .map(|p| p.socket_id.clone())
            })
            .collect()
    };
    for sid in socket_ids {
        if let Ok(sid) = sid.parse::<socketioxide::socket::Sid>() {
            if let Some(socket) = io.get_socket(sid) {
                let _ = socket.emit(crate::pokergame::actions::ACTION_RECEIPT, payload);
            }
        }
    }
}
