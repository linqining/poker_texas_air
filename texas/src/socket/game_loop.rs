use std::sync::Arc;

use super::*;
use crate::pokergame::table::now_ms;

pub(crate) async fn game_loop_task(io: SocketIo, state: Arc<SocketState>, table_id: u32, mut action_rx: tokio::sync::mpsc::Receiver<ActionRequest>, mut stop_rx: tokio::sync::watch::Receiver<bool>) {
    tracing::info!("[GAME-LOOP] Started for table {}", table_id);
    let mut ticker = tokio::time::interval(tokio::time::Duration::from_millis(500));
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if !process_tick(&io, &state, table_id).await {
                    tracing::info!("[GAME-LOOP] Table {} process_tick signaled stop", table_id);
                    break;
                }
            }
            action = action_rx.recv() => {
                match action {
                    Some(req) => {
                        tracing::info!("[GAME-LOOP] Table {} received action: {} from {}", table_id, req.action, req.pk_hex);
                        process_action(&io, &state, table_id, req).await;
                    }
                    None => {
                        tracing::info!("[GAME-LOOP] Channel closed for table {}", table_id);
                        break;
                    }
                }
            }
            _ = stop_rx.changed() => {
                tracing::info!("[GAME-LOOP] Stop signal received for table {}", table_id);
                break;
            }
        };
    }

    {
        let mut registry = state.game_loop_registry.write().await;
        registry.remove(table_id);
    }
    tracing::info!("[GAME-LOOP] Stopped for table {}", table_id);
}

// ---------------------------------------------------------------------------
// 广播辅助函数
// ---------------------------------------------------------------------------

/// 当 reveal_token_state 处于活跃状态时，广播 RevealNoticePayload 给桌上所有客户端。
/// 用于 advance_shuffle / advance_to_next_phase 启动 reveal 阶段后通知前端。
pub async fn broadcast_reveal_notice_if_active(io: &SocketIo, state: &Arc<SocketState>, table_id: u32) {
    let reveal_notice = {
        let gs = state.state.read().await;
        gs.tables.get(&table_id)
            .filter(|t| t.reveal_token_state.is_active())
            .map(|t| {
                let phase = t.reveal_token_state.phase;
                let pending = t.reveal_token_state.pending_players.clone();
                let completed = t.reveal_token_state.completed_players.clone();
                let player_assignments = t.reveal_token_state.player_assignments.clone();
                RevealNoticePayload { table_id, phase, pending_players: pending, completed_players: completed, player_assignments }
            })
    };
    if let Some(notice) = reveal_notice {
        let _ = io.to(table_room_name(table_id)).emit(actions::REVEAL_NOTICE, &notice).await;
    }
}

/// 当 reconstruct_state 处于活跃状态时，广播 ReconstructNoticePayload 给桌上所有客户端。
/// 用于 on_reveal_timeout 触发 reconstruct 后通知前端。
pub(crate) async fn broadcast_reconstruct_notice_if_active(io: &SocketIo, state: &Arc<SocketState>, table_id: u32) {
    let reconstruct_notice = {
        let gs = state.state.read().await;
        gs.tables.get(&table_id)
            .filter(|t| t.reconstruct_state.is_active)
            .map(|t| {
                let completed_players = t.reconstruct_state.completed_players.clone();
                let pending_players = t.reconstruct_state.pending_players.clone();
                let cards = t.reconstruct_state.cards.iter().map(|c| ecpoint_to_hex(c)).collect();
                let coefficient_hex = scalar_to_hex(&t.reconstruct_state.coefficient);
                let player_readable_cards = t.reconstruct_state.player_readable_cards.iter()
                    .map(|(k, v)| {
                        (k.clone(), PlayerReadableCardJson {
                            readable_cards: v.readable_cards.iter().map(ElGamalCiphertextJson::from_ciphertext).collect(),
                        })
                    })
                    .collect();
                ReconstructNoticePayload { table_id, completed_players, pending_players, cards, coefficient_hex, player_readable_cards }
            })
    };
    if let Some(notice) = reconstruct_notice {
        let _ = io.to(table_room_name(table_id)).emit(actions::RECONSTRUCT_NOTICE, &notice).await;
    }
}

// ---------------------------------------------------------------------------
// 超时玩家 socket 清理辅助函数
// ---------------------------------------------------------------------------

/// 在调用 on_*_timeout 之前，记录待踢玩家的 pk_hex → socket_id 映射。
/// on_*_timeout 内部会调用 table.remove_player_by_pk，从 table.players 中移除玩家，
/// 之后便无法通过 table.players 查找 wallet_address → socket_id，所以必须提前记录。
async fn record_pk_to_socket_ids(state: &Arc<SocketState>, table_id: u32, pks: &[GamePkHex]) -> Vec<(GamePkHex, String)> {
    let gs = state.state.read().await;
    let Some(table) = gs.tables.get(&table_id) else { return Vec::new() };
    pks.iter()
        .filter_map(|pk| {
            let players = table.players();
            let wallet_addr = players.get(pk)?;
            let socket_id = gs.players.values()
                .find(|p| &p.wallet_address == wallet_addr)
                .map(|p| p.socket_id.clone())?;
            Some((pk.clone(), socket_id))
        })
        .collect()
}

/// on_*_timeout 调用后，对被踢玩家执行 socket 层清理：
/// 从 gs.players 移除、离开 table room、emit TABLE_LEFT。
async fn cleanup_player_sockets(
    io: &SocketIo,
    state: &Arc<SocketState>,
    table_id: u32,
    pk_socket_pairs: Vec<(GamePkHex, String)>,
    reason: Option<&str>,
) {
    if pk_socket_pairs.is_empty() {
        return;
    }
    let current_tables = state.get_current_tables().await;
    {
        let mut gs = state.state.write().await;
        for (_, socket_id) in &pk_socket_pairs {
            gs.players.remove(socket_id);
        }
    }
    for (_, socket_id) in &pk_socket_pairs {
        if let Ok(sid) = socket_id.parse::<socketioxide::socket::Sid>() {
            if let Some(socket) = io.get_socket(sid) {
                socket.leave(table_room_name(table_id));
                let _ = socket.emit(actions::TABLE_LEFT, &TableLeftPayload {
                    tables: current_tables.clone(),
                    table_id,
                    reason: reason.map(|s| s.to_string()),
                });
            }
        }
    }
    // Broadcast global table/player updates so lobby UI syncs
    let players_info = state.get_current_players().await;
    let _ = io.emit(actions::TABLES_UPDATED, &current_tables).await;
    let _ = io.emit(actions::PLAYERS_UPDATED, &players_info).await;
}

// ---------------------------------------------------------------------------
// process_tick — 严格对齐 Move 合约 tick 优先级
// ---------------------------------------------------------------------------

pub(crate) async fn process_tick(io: &SocketIo, state: &Arc<SocketState>, table_id: u32) -> bool {
    // 读取状态快照
    // 对齐 Move：时间戳使用 u64 ms（summary.state.*_at），0 表示未设置
    let (round_state, active_count, hand_complete_at, ready_at, showdown_at,
         shuffle_active, reveal_active, reconstruct_active) = {
        let gs = state.state.read().await;
        if let Some(table) = gs.tables.get(&table_id) {
            (table.round_state(), table.active_players().len(), table.hand_complete_at(), table.ready_at(), table.showdown_at(),
             table.shuffle_state.is_active(), table.reveal_token_state.is_active(), table.reconstruct_state.is_active)
        } else { return false }
    };

    if active_count == 0 {
        return false;
    }

    // ===== Priority 1: reconstruct =====
    if reconstruct_active {
        // 1a. 检查 reconstruct 是否完成
        let completed = {
            let mut gs = state.state.write().await;
            if let Some(table) = gs.tables.get_mut(&table_id) {
                table.execute_reconstruct_if_completed()
            } else { false }
        };
        if completed {
            broadcast::broadcast_to_table(io, state, table_id, Some("Reconstruct completed")).await;
            // on_complete_reconstruct 已在 execute_reconstruct_if_completed 内部调用，
            // 它会启动 shuffle(RECONSTRUCT) + advance_shuffle。
            // 广播 ReconstructResultPayload
            let reconstruct_payload = ReconstructResultPayload {
                table_id,
                completed_players: vec![],
                reconstructed: true,
            };
            let _ = io.to(table_room_name(table_id)).emit(actions::RECONSTRUCT_RESULT, &reconstruct_payload).await;
            // 广播 shuffle notice（advance_shuffle 可能已设置 current_shuffler）
            state.send_shuffle_notice(table_id).await;
            // 广播 reveal notice（如果 advance_shuffle 已启动 reveal）
            broadcast_reveal_notice_if_active(io, state, table_id).await;
            // crypto_event: reconstruct complete
            state.broadcast_crypto_event(
                table_id,
                broadcast::CryptoEventType::Reconstruct,
                "".to_string(),
                None, true,
                Some("reconstruct complete".to_string()),
                None,
            ).await;
            // crypto_event: reveal phase started (if active)
            state.broadcast_crypto_event(
                table_id,
                broadcast::CryptoEventType::RevealToken,
                "".to_string(),
                None, true,
                Some("reveal phase started".to_string()),
                None,
            ).await;
            return true;
        }

        // 1b. 检查 reconstruct 超时
        let (is_timed_out, timed_out_pks) = {
            let gs = state.state.read().await;
            if let Some(table) = gs.tables.get(&table_id) {
                if !table.reconstruct_state.is_active {
                    (false, Vec::new())
                } else if let Some(timeout_start) = table.reconstruct_state.timeout_start {
                    if timeout_start.elapsed().as_secs() >= table.reconstruct_state.timeout_seconds
                        && !table.reconstruct_state.pending_players.is_empty() {
                        (true, table.reconstruct_state.pending_players.clone())
                    } else {
                        (false, Vec::new())
                    }
                } else {
                    (false, Vec::new())
                }
            } else {
                (false, Vec::new())
            }
        };
        if is_timed_out {
            // 提前记录 socket_id，因为 on_reconstruct_timeout 会从 table.players 移除玩家
            let pk_socket_pairs = record_pk_to_socket_ids(state, table_id, &timed_out_pks).await;
            {
                let mut gs = state.state.write().await;
                if let Some(table) = gs.tables.get_mut(&table_id) {
                    table.on_reconstruct_timeout();
                }
            }
            // 在 cleanup_player_sockets 移除 gs.players 之前查找玩家名称
            let player_names: Vec<String> = {
                let gs = state.state.read().await;
                pk_socket_pairs.iter()
                    .filter_map(|(_, socket_id)| gs.players.get(socket_id))
                    .map(|p| p.name.clone())
                    .collect()
            };
            cleanup_player_sockets(io, state, table_id, pk_socket_pairs, Some("reconstruct timeout")).await;
            let msg = if player_names.is_empty() {
                "Reconstruct timed out".to_string()
            } else {
                format!("{} timed out (reconstruct)", player_names.join(", "))
            };
            broadcast::broadcast_to_table(io, state, table_id, Some(&msg)).await;
            // 与 reconstruct 完成分支保持一致：广播 shuffle notice 和 reveal notice
            state.send_shuffle_notice(table_id).await;
            broadcast_reveal_notice_if_active(io, state, table_id).await;
            // crypto_event: reconstruct timeout
            state.broadcast_crypto_event(
                table_id,
                broadcast::CryptoEventType::Reconstruct,
                "".to_string(),
                None, true,
                Some("reconstruct timeout".to_string()),
                None,
            ).await;
            // crypto_event: reveal phase started (if active)
            state.broadcast_crypto_event(
                table_id,
                broadcast::CryptoEventType::RevealToken,
                "".to_string(),
                None, true,
                Some("reveal phase started".to_string()),
                None,
            ).await;
        }
        // reconstruct 进行中或刚超时，不处理其他状态
        return true;
    }

    // ===== Priority 2: shuffle =====
    if shuffle_active {
        // 2a. 活跃玩家不足 → 回到 Waiting
        if active_count < MIN_START_NUM as usize {
            let mut gs = state.state.write().await;
            if let Some(table) = gs.tables.get_mut(&table_id) {
                table.shuffle_state.phase = crate::pokergame::game_state::ShufflePhase::None;
                if round_state != RoundState::Waiting {
                    table.transition_to(RoundState::Waiting);
                }
            }
            return true;
        }

        // 2b. 所有玩家完成洗牌 → advance_shuffle
        let pending_empty = {
            let gs = state.state.read().await;
            gs.tables.get(&table_id)
                .map(|t| t.shuffle_state.pending_players.is_empty())
                .unwrap_or(false)
        };
        if pending_empty {
            let reveal_started = {
                let mut gs = state.state.write().await;
                if let Some(table) = gs.tables.get_mut(&table_id) {
                    table.advance_shuffle();
                    table.reveal_token_state.is_active()
                } else { false }
            };
            broadcast::broadcast_to_table(io, state, table_id, Some("Shuffle complete")).await;
            // crypto_event: shuffle round complete
            state.broadcast_crypto_event(
                table_id,
                broadcast::CryptoEventType::Shuffle,
                "".to_string(),
                None, true,
                Some("shuffle round complete".to_string()),
                None,
            ).await;
            if reveal_started {
                broadcast_reveal_notice_if_active(io, state, table_id).await;
                // crypto_event: reveal phase started
                state.broadcast_crypto_event(
                    table_id,
                    broadcast::CryptoEventType::RevealToken,
                    "".to_string(),
                    None, true,
                    Some("reveal phase started".to_string()),
                    None,
                ).await;
            }
            return true;
        }

        // 2c. 检查 shuffle 超时（check_shuffle_timeout 只检查不修改状态）
        let timed_out_pk = {
            let mut gs = state.state.write().await;
            if let Some(table) = gs.tables.get_mut(&table_id) {
                table.check_shuffle_timeout()
            } else { None }
        };
        if let Some(timed_out_pk) = timed_out_pk {
            // 提前记录 socket_id
            let pk_socket_pairs = record_pk_to_socket_ids(state, table_id, &[timed_out_pk.clone()]).await;
            {
                let mut gs = state.state.write().await;
                if let Some(table) = gs.tables.get_mut(&table_id) {
                    table.on_shuffle_timeout();
                }
            }
            // 在 cleanup_player_sockets 移除 gs.players 之前查找玩家名称
            let player_name = {
                let gs = state.state.read().await;
                pk_socket_pairs.iter()
                    .filter_map(|(_, socket_id)| gs.players.get(socket_id))
                    .next()
                    .map(|p| p.name.clone())
                    .unwrap_or_else(|| "Unknown".to_string())
            };
            cleanup_player_sockets(io, state, table_id, pk_socket_pairs, Some("shuffle timeout")).await;
            let msg = format!("{} timed out (shuffle)", player_name);
            broadcast::broadcast_to_table(io, state, table_id, Some(&msg)).await;
            state.send_shuffle_notice(table_id).await;
            broadcast_reveal_notice_if_active(io, state, table_id).await;
            // crypto_event: reveal phase started (if active)
            state.broadcast_crypto_event(
                table_id,
                broadcast::CryptoEventType::RevealToken,
                "".to_string(),
                None, true,
                Some("reveal phase started".to_string()),
                None,
            ).await;
            return true;
        }
        // shuffle 进行中
        return true;
    }

    // ===== Priority 3: reveal =====
    if reveal_active {
        // 3a. 所有玩家完成 reveal → on_reveal_complete
        let all_pending_empty = {
            let gs = state.state.read().await;
            gs.tables.get(&table_id)
                .map(|t| t.reveal_token_state.pending_players.is_empty())
                .unwrap_or(false)
        };
        if all_pending_empty {
            {
                let mut gs = state.state.write().await;
                if let Some(table) = gs.tables.get_mut(&table_id) {
                    table.on_reveal_complete();
                }
            }
            broadcast::broadcast_to_table(io, state, table_id, None).await;
            // crypto_event: reveal phase complete
            state.broadcast_crypto_event(
                table_id,
                broadcast::CryptoEventType::RevealToken,
                "".to_string(),
                None, true,
                Some("reveal phase complete".to_string()),
                None,
            ).await;
            return true;
        }

        // 3b. 检查 reveal 超时（手动检查，不调用 check_reveal_timeout 以免它 reset 状态）
        let (is_timed_out, timed_out_pks) = {
            let gs = state.state.read().await;
            if let Some(table) = gs.tables.get(&table_id) {
                if !table.reveal_token_state.is_active() {
                    (false, Vec::new())
                } else if let Some(timeout_start) = table.reveal_token_state.timeout_start {
                    if timeout_start.elapsed().as_secs() >= table.reveal_token_state.timeout_seconds
                        && !table.reveal_token_state.pending_players.is_empty() {
                        (true, table.reveal_token_state.pending_players.clone())
                    } else {
                        (false, Vec::new())
                    }
                } else {
                    (false, Vec::new())
                }
            } else {
                (false, Vec::new())
            }
        };
        if is_timed_out {
            // 提前记录 socket_id
            let pk_socket_pairs = record_pk_to_socket_ids(state, table_id, &timed_out_pks).await;
            {
                let mut gs = state.state.write().await;
                if let Some(table) = gs.tables.get_mut(&table_id) {
                    table.on_reveal_timeout();
                }
            }
            // 在 cleanup_player_sockets 移除 gs.players 之前查找玩家名称
            let player_names: Vec<String> = {
                let gs = state.state.read().await;
                pk_socket_pairs.iter()
                    .filter_map(|(_, socket_id)| gs.players.get(socket_id))
                    .map(|p| p.name.clone())
                    .collect()
            };
            cleanup_player_sockets(io, state, table_id, pk_socket_pairs, Some("reveal timeout")).await;
            let msg = if player_names.is_empty() {
                "Reveal timeout".to_string()
            } else {
                format!("{} timed out (reveal)", player_names.join(", "))
            };
            broadcast::broadcast_to_table(io, state, table_id, Some(&msg)).await;
            // on_reveal_timeout 可能触发了 reconstruct，广播 reconstruct notice
            broadcast_reconstruct_notice_if_active(io, state, table_id).await;
            return true;
        }
        // reveal 进行中
        return true;
    }

    // ===== Priority 4+: match round_state =====
    match round_state {
        RoundState::Waiting => {
            // 保留 hand_complete_at 清理逻辑：reset_for_next_hand 后的玩家移除
            if hand_complete_at != 0 {
                let elapsed = now_ms().saturating_sub(hand_complete_at) / 1000;
                if elapsed >= state.config.hand_complete_wait_secs as u64 {
                    // Leave grace: 若仍有 sitting_out 玩家（正在完成链上 leave 交易），
                    // 延迟清理以给他们更多时间。所有 sitting_out 玩家被移除后（链上 tx 完成 +
                    // relayer 同步），下一 tick has_sitting_out 为 false，立即推进清理。
                    // 上限为 hand_complete_wait_secs + leave_grace_secs，避免无限等待。
                    let sitting_out_count = {
                        let gs = state.state.read().await;
                        gs.tables.get(&table_id)
                            .map(|t| t.seats().values().filter(|s| s.sitting_out).count())
                            .unwrap_or(0)
                    };
                    if sitting_out_count > 0
                        && elapsed < state.config.hand_complete_wait_secs as u64
                            + state.config.leave_grace_secs as u64
                    {
                        tracing::debug!(
                            "[TICK] Table {} Waiting: {} sitting_out players, leave grace {}/{}s",
                            table_id, sitting_out_count, elapsed,
                            state.config.hand_complete_wait_secs as u64 + state.config.leave_grace_secs as u64
                        );
                        return true;
                    }
                    let (active, removed_players) = {
                        // First pass: collect wallet->player_id mappings with read lock
                        let wallet_to_player_id: std::collections::HashMap<String, String> = {
                            let gs = state.state.read().await;
                            let mut map = std::collections::HashMap::new();
                            if let Some(table) = gs.tables.get(&table_id) {
                                for seat in table.seats().values() {
                                    let is_broke = seat.stack == 0;
                                    let is_sitting_out = seat.sitting_out;
                                    if is_broke || is_sitting_out {
                                        if let Some(player) = &seat.player {
                                            if let Some(p) = gs.players.values().find(|p| p.wallet_address.0 == player.wallet_address.0) {
                                                map.insert(player.wallet_address.to_string(), p.id.clone());
                                            }
                                        }
                                    }
                                }
                            }
                            map
                        };

                        let mut gs = state.state.write().await;
                        if let Some(table) = gs.tables.get_mut(&table_id) {
                            let mut to_remove = Vec::new();
                            for seat in table.local_seats.values_mut() {
                                let is_broke = seat.stack == 0;
                                let is_sitting_out = seat.sitting_out;
                                if is_broke || is_sitting_out {
                                    if let Some(player) = &seat.player {
                                        let stack = if is_sitting_out { seat.stack } else { 0 };
                                        to_remove.push((player.wallet_address.to_string(), stack));
                                    }
                                }
                            }
                            // Return chips to sitting_out players
                            for (address, stack) in to_remove.iter() {
                                if *stack > 0 {
                                    tracing::info!("return chips to sitting_out player: {} stack: {}", address, stack);
                                    if let Some(pid) = wallet_to_player_id.get(address) {
                                        let _ = state.db.unlock_chips(pid, *stack as i64).await;
                                    }
                                }
                            }
                            // Remove players from table
                            for (wallet_addr,_) in to_remove.iter() {
                                tracing::info!("remove_player_by_pk: {}", wallet_addr);
                                if let Some(pk_hex) = table.get_pk_hex_by_wallet_address(wallet_addr) {
                                    table.remove_player_by_pk(&pk_hex);
                                }
                            }
                            table.reset_for_next_hand();
                            (table.active_players().len(), to_remove)
                        } else { (0, Vec::new()) }
                    };

                    let tables_info = state.get_current_tables().await;
                    let players_info = state.get_current_players().await;
                    let _ = io.emit(actions::TABLES_UPDATED, &tables_info).await;
                    let _ = io.emit(actions::PLAYERS_UPDATED, &players_info).await;


                    for (wallet_address, _) in removed_players.iter() {
                        let gs = state.state.read().await;
                        let socket_id = gs.players.values().find(|p| p.wallet_address.0 == *wallet_address).map(|p| p.socket_id.clone());
                        drop(gs);
                        if let Some(sid_str) = socket_id {
                            if let Ok(sid) = sid_str.parse::<socketioxide::socket::Sid>() {
                                if let Some(socket) = io.get_socket(sid) {
                                    let _ = socket.emit(actions::TABLE_LEFT, &TableLeftPayload { tables: tables_info.clone(), table_id, reason: None });
                                }
                            }
                        }
                    }

                    for (wallet_address, _) in removed_players.iter() {
                        let player_name = {
                            let gs = state.state.read().await;
                            gs.players.values().find(|p| p.wallet_address.0 == *wallet_address).map(|p| p.name.clone())
                        };
                        if let Some(name) = player_name {
                            broadcast::broadcast_to_table(&io, &state, table_id, Some(&format!("{} left the table.", name))).await;
                        }
                    }

                    tracing::info!("[TICK] Table {} Waiting: cleanup after hand_complete, {} active, {} players removed", table_id, active, removed_players.len());
                    if active < MIN_START_NUM as usize {
                        broadcast::broadcast_to_table(io, state, table_id, Some("Waiting for more players")).await;
                        return false;
                    }
                    // hand_complete_at already cleared by reset_for_next_hand; proceed to auto-start
                } else {
                    // Not timed out yet, wait
                    return true;
                }
            }

            // Auto-start logic (do_start_hand: start_shuffle)
            if active_count >= MIN_START_NUM as usize {
                let io_c = io.clone();
                let state_c = state.clone();
                if ready_at != 0 {
                    let elapsed = now_ms().saturating_sub(ready_at) / 1000;
                    if elapsed <= state.config.ready_countdown_secs as u64 {
                        tracing::debug!("[TICK] Table {} Waiting: {} active, ready countdown {}/5s", table_id, active_count, elapsed);
                        return true;
                    }
                    tracing::info!("[TICK] Table {} Waiting → starting hand ({} active)", table_id, active_count);

                    {
                        let mut gs = state_c.state.write().await;
                        if let Some(table) = gs.tables.get_mut(&table_id) {
                            if table.active_players().len() >= MIN_START_NUM as usize {
                                // 对齐 Move tick → do_start_hand：start_hand 内部会
                                // move_button + start_preflop_shuffle + advance_shuffle
                                let _ = table.start_shuffle();
                            }
                        }
                    }
                    state_c.send_shuffle_notice(table_id).await;
                    broadcast::broadcast_to_table(&io_c, &state_c, table_id, Some("--- New hand started ---")).await;
                } else {
                    tracing::info!("[TICK] Table {} Waiting: setting ready_at, starting 5s countdown", table_id);
                    {
                        let mut gs = state_c.state.write().await;
                        if let Some(table) = gs.tables.get_mut(&table_id) {
                            table.set_ready_at(now_ms());
                        }
                    }
                    broadcast::broadcast_to_table(io, state, table_id, Some("---New hand starting in 5 seconds---")).await;
                }
            } else {
                // tracing::info!("[TICK] Table {} Waiting: only {} active, stopping game loop", table_id, active_count);
                return false;
            }
        }
        RoundState::PreFlop | RoundState::Flop | RoundState::Turn | RoundState::River => {
            // Priority 5: betting round
            let timeout_result = {
                let mut gs = state.state.write().await;
                if let Some(table) = gs.tables.get_mut(&table_id) {
                    table.check_betting_timeout(state.config.betting_timeout_secs)
                } else { None }
            };
            if let Some(res) = timeout_result {
                tracing::info!("[TICK] Table {} {:?}: betting timeout → {}", table_id, round_state, res.message);
                broadcast::broadcast_to_table(io, state, table_id, Some(&res.message)).await;
                handle_turn_advance(io, state, table_id).await;
                return true;
            }

            let auto_folded = handle_auto_fold(io, state, table_id).await;

            // 修复：handle_auto_fold 内部 fold 后已调用 handle_turn_advance，
            // 此处不再重复检查 is_complete，避免双重推进 turn（导致连续行动/阶段跳进）。
            if !auto_folded {
                let is_complete = {
                    let gs = state.state.read().await;
                    if let Some(table) = gs.tables.get(&table_id) {
                        table.is_betting_round_complete()
                    } else { false }
                };

                if is_complete {
                    tracing::info!("[TICK] Table {} {:?}: betting round complete, advancing", table_id, round_state);
                    handle_turn_advance(io, state, table_id).await;
                }
            }
        }
        RoundState::Showdown => {
            // Priority 6: showdown
            if showdown_at != 0 {
                let elapsed = now_ms().saturating_sub(showdown_at) / 1000;
                if elapsed >= state.config.showdown_display_secs as u64 {
                    tracing::info!("[TICK] Table {} Showdown: display time elapsed, finishing showdown", table_id);
                    // on_reveal_complete(ShowdownReveal) 已确定赢家并设置 showdown_at，
                    // 此处只需 finish_showdown 重置牌桌。使用 settle_hand 会重复分配底池。
                    {
                        let mut gs = state.state.write().await;
                        if let Some(table) = gs.tables.get_mut(&table_id) {
                            table.finish_showdown();
                        }
                    }
                    broadcast::broadcast_to_table(io, state, table_id, None).await;
                } else {
                    tracing::debug!("[TICK] Table {} Showdown: displaying results {}/{}s", table_id, elapsed, state.config.showdown_display_secs);
                }
            } else {
                // showdown_at 未设置，设置它（下一轮 tick 再检查超时）
                tracing::info!("[TICK] Table {} Showdown: setting showdown_at", table_id);
                {
                    let mut gs = state.state.write().await;
                    if let Some(table) = gs.tables.get_mut(&table_id) {
                        table.set_showdown_at(now_ms());
                    }
                }
            }
        }
    }
    true
}

pub(crate) async fn handle_auto_fold(io: &SocketIo, state: &Arc<SocketState>, table_id: u32) -> bool {
    let auto_fold = {
        let gs = state.state.read().await;
        if let Some(table) = gs.tables.get(&table_id) {
            if let Some(turn_id) = table.turn() {
                table.seats().get(&turn_id)
                    .and_then(|seat| {
                        if seat.disconnected && !seat.folded {
                            seat.player.as_ref().map(|p| p.pk_hex.clone())
                        } else {
                            None
                        }
                    })
            } else {
                None
            }
        } else {
            None
        }
    };
    if let Some(pk_hex) = auto_fold {
        let fold_result = {
            let mut gs = state.state.write().await;
            if let Some(table) = gs.tables.get_mut(&table_id) {
                table.handle_fold(&pk_hex)
            } else {
                None
            }
        };
        if let Some(res) = fold_result {
            broadcast::broadcast_to_table(io, state, table_id, Some(&res.message)).await;
            handle_turn_advance(io, state, table_id).await;
            // 已 fold 并推进 turn，调用方不应再次检查 is_complete（避免双重推进）
            return true;
        }
    }
    false
}

pub(crate) async fn handle_turn_advance(io: &SocketIo, state: &Arc<SocketState>, table_id: u32) {
    let result = {
        let mut gs = state.state.write().await;
        if let Some(table) = gs.tables.get_mut(&table_id) {
            if table.unfolded_players().len() <= 1 {
                table.end_without_showdown();
            } else if table.is_betting_round_complete() {
                table.advance_to_next_phase();
                // advance_to_next_phase 启动 reveal phase，turn 由 on_reveal_complete 设置。
                // 仅在 Showdown（无 reveal）时不需要设置 turn。
                // 注意：不再手动设置 turn，因为 reveal 期间无行动者。
            } else {
                let last_turn = table.turn().unwrap_or(1);
                table.set_turn(table.next_unfolded_player(last_turn, 1));
                table.set_betting_started_at(now_ms());
                let current_turn = table.turn();
                for i in 1..=table.max_players() {
                    if let Some(seat) = table.local_seats.get_mut(&i) {
                        seat.turn = current_turn == Some(i);
                    }
                }
            }
            Some(())
        } else { None }
    };
    if result.is_some() {
        broadcast::broadcast_to_table(io, state, table_id, None).await;
        broadcast_reveal_notice_if_active(io, state, table_id).await;
        // crypto_event: reveal phase started (if active)
        state.broadcast_crypto_event(
            table_id,
            broadcast::CryptoEventType::RevealToken,
            "".to_string(),
            None, true,
            Some("reveal phase started".to_string()),
            None,
        ).await;
    }
}

pub(crate) async fn process_action(io: &SocketIo, state: &Arc<SocketState>, table_id: u32, req: ActionRequest) {
    let result = {
        let mut gs = state.state.write().await;
        if let Some(table) = gs.tables.get_mut(&table_id) {
            // F8 fix: validate that it's the requesting player's turn and
            // the game is in a betting phase before processing any action.
            let is_betting_phase = matches!(table.round_state(),
                RoundState::PreFlop | RoundState::Flop | RoundState::Turn | RoundState::River);
            let is_valid_turn = is_betting_phase && table.turn().map_or(false, |turn_id| {
                table.seats().get(&turn_id).map_or(false, |seat| {
                    seat.player.as_ref().map_or(false, |p| p.pk_hex == req.pk_hex)
                        && !seat.folded
                        && !seat.sitting_out
                        && seat.stack > 0
                })
            });

            if !is_valid_turn {
                tracing::warn!(
                    "[process_action] Rejected action {} from pk={}: not their turn or not betting phase (turn={:?}, state={:?})",
                    req.action, req.pk_hex, table.turn(), table.round_state()
                );
                None
            } else {
                // F9 fix: only clear sitting_out after turn validation passes.
                // (A valid turn implies the player is not sitting_out, but we
                // keep this for safety in case of race conditions.)
                if let Some(seat) = table.find_player_by_pk_mut(&req.pk_hex) {
                    seat.sitting_out = false;
                }
                let action_result = match req.action.as_str() {
                    "fold" => table.handle_fold(&req.pk_hex),
                    "check" => table.handle_check(&req.pk_hex),
                    "call" => table.handle_call(&req.pk_hex),
                    "raise" => table.handle_raise(&req.pk_hex, req.amount.unwrap_or(0)),
                    "allin" => table.handle_allin(&req.pk_hex), // D2 fix
                    _ => None,
                };
                if action_result.is_some() {
                    // Starknet 镜像：下注动作同步到 poker_l1（失败仅告警）
                    crate::starknet::hooks::mirror_betting(
                        table,
                        &req.pk_hex,
                        &req.action,
                        req.amount,
                    );
                }
                action_result
            }
        } else { None }
    };
    if let Some(res) = result {
        broadcast::broadcast_to_table(io, state, table_id, Some(&res.message)).await;
        handle_turn_advance(io, state, table_id).await;
    } else if req.action == "check" {
        // check 成功但无消息（handle_check 返回 None）：仍需推进 turn/round，
        // 否则两人互相 check 时 turn 永不轮转、30 秒下注超时废掉整手。
        handle_turn_advance(io, state, table_id).await;
    }
}

pub(crate) async fn clear_for_one_player(io: &SocketIo, state: Arc<SocketState>, table_id: u32) {
    {
        let mut gs = state.state.write().await;
        if let Some(table) = gs.tables.get_mut(&table_id) {
            table.clear_win_messages();
        }
    }

    let io_c = io.clone();
    let state_c = state;

    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        {
            let mut gs = state_c.state.write().await;
            if let Some(table) = gs.tables.get_mut(&table_id) {
                table.clear_seat_hands();
                table.reset_board_and_pot();
            }
        }

        broadcast::broadcast_to_table(&io_c, &state_c, table_id, Some("Waiting for more players")).await;
    });
}
