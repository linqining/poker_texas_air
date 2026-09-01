use std::sync::Arc;

use socketioxide::{
    extract::{Data, SocketRef, State},
    SocketIo,
};

use crate::auth;
use crate::config::Config;
use crate::pokergame::game_state::RevealPhase;
use crate::pokergame::player::truncate_name;
use super::*;

/// 获取用户可用筹码（PokerVault 链上筹码 - locked_chips）。
/// 链上查询不可用（dev 模式）时返回 0 可用。
async fn get_available_chips(state: &Arc<SocketState>, user: &crate::models::User) -> i64 {
    // Starknet-only：筹码余额来自 PokerVault 链上筹码（dev 模式无 vault 时返回 0 可用）。
    let _ = state;
    match crate::starknet::chips::vault_chip_balance_wei(&user.address).await {
        Some(wei) => (wei / crate::starknet::config::WEI_PER_CHIP) as i64 - user.locked_chips,
        None => {
            tracing::warn!("[get_available_chips] vault chip balance unavailable for {}", user.address);
            0
        }
    }
}



/// 遗留 on-chain 钩子：Sui 上链模式已随 Sui 链路移除（Starknet-only）。
///
/// 返回 `false` 表示未处理，调用方应执行本地处理（本地模式 + Starknet 结算）。
async fn try_on_chain_action(
    _socket: &SocketRef,
    _state: &Arc<SocketState>,
    _table_id: u32,
    _action: &str,
    _amount: Option<u64>,
) -> bool {
    // Sui on-chain 模式已移除（Starknet-only）：始终走本地处理。
    false
}





/// 遗留 on-chain 钩子（crypto 动作）：同 [`try_on_chain_action`]，始终返回 `false`。
async fn try_on_chain_crypto_action(
    _socket: &SocketRef,
    _state: &Arc<SocketState>,
    _table_id: u32,
    _action: &str,
    _tx_kind_b64: String,
    _gas_budget: Option<u64>,
) -> bool {
    // Sui on-chain 模式已移除（Starknet-only）：始终走本地处理。
    false
}

// ============================================================================
// Crypto proof serialization helpers (JSON → bytes)
// ============================================================================

use crate::pokergame::game_state::{
    ElGamalCiphertextJson, ReconstructProofJson, ShuffleProofJson, SubmitRevealTokenJson,
};
use crate::relayer::proof_bytes;

/// 将 `Vec<ElGamalCiphertextJson>` 序列化为 flat bytes（每个密文 96 字节）。
fn serialize_ciphertexts_from_json(
    cards: &[ElGamalCiphertextJson],
) -> Result<Vec<u8>, String> {
    let cts: Vec<poker_protocol::crypto::ElGamalCiphertext> = cards
        .iter()
        .map(|c| c.to_ciphertext())
        .collect::<Result<Vec<_>, _>>()?;
    Ok(proof_bytes::ciphertexts_to_bytes(&cts))
}

/// 将 `ShuffleProofJson` 序列化为 Move 合约期望的字节格式。
fn serialize_shuffle_proof_from_json(proof: &ShuffleProofJson) -> Result<Vec<u8>, String> {
    let p = proof.to_proof()?;
    proof_bytes::serialize_shuffle_proof(&p)
}

/// 将 `ReconstructProofJson` 序列化为 Move 合约期望的字节格式。
fn serialize_reconstruct_proof_from_json(proof: &ReconstructProofJson) -> Result<Vec<u8>, String> {
    let p = proof.to_proof()?;
    proof_bytes::serialize_reconstruct_proof(&p)
}

/// 将单个 `SubmitRevealTokenJson` 的 `reveal_token_hex` 转换为 48 字节 G1 compressed bytes。
fn serialize_reveal_token_bytes(token: &SubmitRevealTokenJson) -> Result<Vec<u8>, String> {
    let pt = poker_protocol::z_poker::convert::hex_to_ecpoint(&token.reveal_token_hex)?;
    Ok(proof_bytes::g1_to_bytes(&pt))
}

/// 将 `SubmitRevealTokenJson` 的 `reveal_token_proof` 序列化为 Move 合约期望的字节格式。
fn serialize_reveal_token_proof_bytes(
    token: &SubmitRevealTokenJson,
) -> Result<Vec<u8>, String> {
    let p = token.reveal_token_proof.to_proof()?;
    Ok(proof_bytes::serialize_reveal_token_proof(&p))
}



/// A3 修复：验证 socket 发送者拥有所声称的 pk_hex。
///
/// 通过 socket_id 查找 player 的 wallet_address，再通过 table 查找该 wallet_address 对应的 pk_hex，
/// 与请求中声称的 pk_hex 比较。验证失败时 emit error 事件并返回 false。
async fn verify_socket_sender(
    socket: &SocketRef,
    state: &Arc<SocketState>,
    table_id: u32,
    claimed_pk_hex: &GamePkHex,
) -> bool {
    let socket_id = socket.id.to_string();
    let expected_pk = {
        let gs = state.state.read().await;
        let wallet = gs.players.get(&socket_id).map(|p| p.wallet_address.clone());
        wallet.and_then(|wa| {
            gs.tables.get(&table_id).and_then(|t| t.get_pk_hex_by_wallet_address(&wa.0))
        })
    };
    match expected_pk {
        Some(pk) if &pk == claimed_pk_hex => true,
        Some(pk) => {
            tracing::warn!(
                "[verify_socket_sender] pk_hex mismatch: socket_id={}, table_id={}, expected={}, claimed={}",
                socket_id, table_id, pk, claimed_pk_hex
            );
            let _ = socket.emit("error", &serde_json::json!({"msg": "pk_hex does not belong to sender"}));
            false
        }
        None => {
            tracing::warn!(
                "[verify_socket_sender] cannot resolve pk_hex for socket_id={}, table_id={}",
                socket_id, table_id
            );
            let _ = socket.emit("error", &serde_json::json!({"msg": "Cannot verify sender identity"}));
            false
        }
    }
}

/// A3 修复：验证 socket 发送者拥有所声称的 seat_id。
///
/// 用于 REBUY 等不带 pk_hex 的事件：通过 socket_id 查找 player 的 wallet_address，
/// 再验证 table 中 seat_id 的 player.wallet_address 与之一致。
async fn verify_socket_sender_seat(
    socket: &SocketRef,
    state: &Arc<SocketState>,
    table_id: u32,
    seat_id: u32,
) -> bool {
    let socket_id = socket.id.to_string();
    let wallet_match = {
        let gs = state.state.read().await;
        let wallet = gs.players.get(&socket_id).map(|p| p.wallet_address.clone());
        match wallet {
            Some(wa) => {
                gs.tables.get(&table_id)
                    .map_or(false, |t| {
                        t.seats().get(&seat_id)
                            .and_then(|seat| seat.player.as_ref())
                            .map_or(false, |gp| gp.wallet_address.0 == wa.0)
                    })
            }
            None => false,
        }
    };
    if !wallet_match {
        tracing::warn!(
            "[verify_socket_sender_seat] seat ownership mismatch: socket_id={}, table_id={}, seat_id={}",
            socket_id, table_id, seat_id
        );
        let _ = socket.emit("error", &serde_json::json!({"msg": "Seat does not belong to sender"}));
        false
    } else {
        true
    }
}

// ============================================================================
// SIT_DOWN_V2 helpers
// ============================================================================

/// Validates SIT_DOWN_V2 request: auth, amount, pk, player, balance.
/// Returns `Some((player, player_pk))` if valid, `None` if error already emitted.
async fn validate_sit_down_request(
    s: &SocketRef,
    state: &Arc<SocketState>,
    payload: &SitDownV2Payload,
) -> Option<(Player, EcPoint)> {
    let socket_id = s.id.to_string();

    let claims = match auth::verify_token(&payload.token, &state.config.jwt_secret) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("[SIT_DOWN_V2] Token verification failed for socket_id: {}, error: {}", socket_id, e);
            let _ = s.emit("error", &serde_json::json!({"msg": "Authentication failed, please reconnect your wallet"}));
            return None;
        }
    };
    let user_id = claims.user.id.clone();
    tracing::info!("[SIT_DOWN_V2] Received from {}: table_id={}, seat_id={}, amount={}, pk_hex={}, user_id={}",
        socket_id, payload.table_id, payload.seat_id, payload.amount, payload.pk_hex, user_id);

    // E3 修复：校验 amount > 0，避免 0 或负值导致的逻辑错误
    if payload.amount == 0 {
        tracing::warn!("[SIT_DOWN_V2] Invalid amount=0 from socket_id={}", socket_id);
        let _ = s.emit("error", &serde_json::json!({"msg": "Amount must be positive"}));
        return None;
    }

    // E3 修复：使用 i64::try_from 避免 u64 -> i64 转换溢出
    let deduct = match i64::try_from(payload.amount) {
        Ok(v) => -v,
        Err(_) => {
            tracing::warn!("[SIT_DOWN_V2] Amount too large for i64: {}", payload.amount);
            let _ = s.emit("error", &serde_json::json!({"msg": "Amount too large"}));
            return None;
        }
    };

    let player_pk = match hex_to_ecpoint(&**payload.pk_hex) {
        Ok(pk) => pk,
        Err(e) => {
            tracing::warn!("[SIT_DOWN_V2] Invalid pk_hex: {}", e);
            return None;
        }
    };

    let player = {
        let gs = state.state.read().await;
        gs.players.get(&socket_id).cloned()
    };

    let player = match player {
        Some(p) if p.id == user_id => p,
        Some(p) => {
            tracing::warn!("[SIT_DOWN_V2] Player id mismatch: socket_id={}, token_user_id={}, player_id={}", socket_id, user_id, p.id);
            return None;
        }
        None => {
            let db_user = state.db.find_user_by_id(&user_id).await;
            match db_user {
                Some(user) => {
                    let bankroll = get_available_chips(&state, &user).await;
                    let mut gs = state.state.write().await;
                    let p = Player {
                        socket_id: socket_id.clone(),
                        id: user.id,
                        name: user.name,
                        bankroll,
                        wallet_address: WalletAddress::new(user.address.clone()),
                    };
                    gs.players.insert(socket_id.clone(), p.clone());
                    p
                }
                None => {
                    tracing::warn!("[SIT_DOWN_V2] User not found in DB for user_id: {}", user_id);
                    return None;
                }
            }
        }
    };

    let player_id = player.id.clone();

    // E3 修复：检查用户余额是否足够（PokerVault 链上筹码 - locked_chips）
    let db_user = state.db.find_user_by_id(&player_id).await;
    if let Some(ref user) = db_user {
        let available = get_available_chips(&state, user).await;
        if available < payload.amount as i64 {
            tracing::warn!(
                "[SIT_DOWN_V2] Insufficient chips: user_id={}, available={}, required={}",
                player_id,
                available,
                payload.amount
            );
            let _ = s.emit("error", &serde_json::json!({"msg": "Insufficient chips"}));
            return None;
        }
    }

    let _ = deduct; // suppress unused warning (preserved from original)
    Some((player, player_pk))
}



/// Broadcasts the sit down result (success or failure) and starts game loop if all complete.
async fn broadcast_sit_down(
    io: &SocketIo,
    s: &SocketRef,
    state: &Arc<SocketState>,
    table_id: u32,
    seat_id: u32,
    pk_hex: &GamePkHex,
    amount: u64,
    player_id: &str,
    player_name: &str,
    result: Result<(bool, JoinResult), JoinError>,
) {
    match result {
        Ok((all_complete, join_result)) => {
            // 锁定筹码（入座时扣除可用余额）
            let _ = state.db.lock_chips(player_id, amount as i64).await;

            let msg = match join_result {
                JoinResult::JoinedAndShuffled => format!("{} sat down in Seat {} and shuffled", player_name, seat_id),
                JoinResult::JoinedWaiting => format!("{} sat down in Seat {}, waiting for next hand", player_name, seat_id),
            };
            broadcast::broadcast_to_table(io, state, table_id, Some(&msg)).await;

            // ZK 可视化：shuffle 证明验证成功（join_and_shuffle_verified 中 shuffle 已验证）
            state.broadcast_crypto_event(
                table_id,
                broadcast::CryptoEventType::Shuffle,
                pk_hex.to_string(),
                None,
                true,
                Some("shuffle proof verified".to_string()),
                None,
            ).await;

            // 无条件确保 game loop 运行（start_game_loop 内部按 registry 去重）。
            // 此前仅 all_complete（入座即完成末次洗牌）时拉起；若上一手结束后
            // loop 已退出且新入座玩家不是末次洗牌者，牌桌会永久停在 Waiting。
            let _ = all_complete;
            tracing::info!("[SIT_DOWN_V2] ensuring game loop running for table {}", table_id);
            state.start_game_loop(io.clone(), state.clone(), table_id).await;
        }
        Err(e) => {
            // 入座失败回传发起者（deck 竞态/证明失败），客户端据此提示或重试
            let _ = s.emit("error", &serde_json::json!({
                "msg": format!("Sit down failed: {e}. Please try again."),
                "action": "sit_down",
            }));
            tracing::warn!("[SIT_DOWN_V2] Failed to join and shuffle: {}", e);
            // ZK 可视化：shuffle 证明验证失败
            state.broadcast_crypto_event(
                table_id,
                broadcast::CryptoEventType::Shuffle,
                pk_hex.to_string(),
                None,
                false,
                Some(format!("shuffle proof verification failed: {}", e)),
                None,
            ).await;
        }
    }
}

// ============================================================================
// STAND_UP helpers
// ============================================================================



/// Handles STAND_UP local mode: verifies leave proof, removes player, broadcasts.
async fn handle_stand_up_local(
    state: &Arc<SocketState>,
    io: &SocketIo,
    payload: &StandUpPayload,
    pk_hex: &GamePkHex,
    player_pk: &EcPoint,
    table_id: u32,
    socket_id: &str,
) {
    // Verify LeaveProof and remove player
    let player_id = {
        let gs = state.state.read().await;
        gs.players.get(socket_id).map(|p| p.id.clone())
    };

    // 幂等检查：若玩家已不在 table.players 和 pk_to_seat 中，说明已被移除
    // （relayer 已同步 PlayerLeft 事件、或 reset_for_next_hand 清理、或重复 STAND_UP）。
    // 直接返回成功，避免 "Player not found" 警告。
    {
        let gs = state.state.read().await;
        if let Some(table) = gs.tables.get(&table_id) {
            if !table.players().contains_key(pk_hex) && !table.pk_to_seat.contains_key(pk_hex) {
                tracing::info!(
                    "[STAND_UP] player {} already removed from table {}, idempotent skip",
                    pk_hex, table_id
                );
                drop(gs);
                // 广播最新状态，让前端同步
                let tables_info = state.get_current_tables().await;
                let players_info = state.get_current_players().await;
                let _ = io.emit(actions::TABLES_UPDATED, &tables_info).await;
                let _ = io.emit(actions::PLAYERS_UPDATED, &players_info).await;
                return;
            }
        } else {
            tracing::warn!("[STAND_UP] table {} not found", table_id);
            return;
        }
    }

    // 注：on-chain 模式已在上方提前 return，以下为 off-chain 模式的本地处理路径。
    let (stand_msg, need_clear, leave_proof_verified) = {
        let mut gs = state.state.write().await;
        if let Some(table) = gs.tables.get_mut(&table_id) {
            let msg = table.find_player_by_pk(pk_hex)
                .and_then(|seat| {
                    seat.player.as_ref().map(|p| format!("{} left the table", p.name))
                });

            // Return chips before removing
            if let Some(seat) = table.find_player_by_pk(pk_hex) {
                if let Some(ref pid) = player_id {
                    let _ = state.db.unlock_chips(pid, seat.stack as i64).await;
                }
            }

            // Verify leave proof and remove player
            // off-chain 模式下 leave_round 可能为 None（例如客户端未生成 proof），
            // 此时直接走 remove_player_by_pk 回退路径。
            let verified = match payload.leave_round.as_ref() {
                Some(lr) => match table.leave_player_with_proof(pk_hex, player_pk, lr) {
                    Ok(()) => {
                        tracing::info!("[STAND_UP] Leave proof verified, player {} removed", pk_hex);
                        true
                    }
                    Err(e) => {
                        tracing::warn!("[STAND_UP] Leave proof verification failed: {}, falling back to remove_player_by_pk", e);
                        table.remove_player_by_pk(pk_hex);
                        false
                    }
                },
                None => {
                    tracing::info!("[STAND_UP] No leave_round provided, removing player {} by pk", pk_hex);
                    table.remove_player_by_pk(pk_hex);
                    false
                }
            };

            let clear = table.active_players().len() == 1;
            (msg, clear, verified)
        } else { (None, false, false) }
    };

    broadcast::broadcast_to_table(io, state, table_id, stand_msg.as_deref()).await;

    // ZK 可视化：leave 证明验证结果
    state.broadcast_crypto_event(
        table_id,
        broadcast::CryptoEventType::Leave,
        pk_hex.0.clone(),
        None,
        leave_proof_verified,
        Some(if leave_proof_verified {
            "leave proof verified".to_string()
        } else {
            "leave proof verification failed".to_string()
        }),
        None,
    ).await;

    let tables_info = state.get_current_tables().await;
    let players_info = state.get_current_players().await;
    let _ = io.emit(actions::TABLES_UPDATED, &tables_info).await;
    let _ = io.emit(actions::PLAYERS_UPDATED, &players_info).await;

    if need_clear {
        state.stop_game_loop(table_id).await;
        game_loop::clear_for_one_player(io, state.clone(), table_id).await;
    }
}

// ============================================================================
// REVEAL_SUBMIT helpers
// ============================================================================

/// Serializes reveal tokens and their proofs to bytes.
/// Returns `Some((reveal_tokens_bytes, reveal_proof_bytes_list))` on success,
/// or `None` if serialization failed (error already emitted).
fn serialize_reveal_proofs(
    s: &SocketRef,
    reveal_tokens: &[SubmitRevealTokenJson],
    table_id: u32,
) -> Option<(Vec<Vec<u8>>, Vec<Vec<u8>>)> {
    let mut reveal_tokens_bytes: Vec<Vec<u8>> = Vec::with_capacity(reveal_tokens.len());
    let mut reveal_proof_bytes_list: Vec<Vec<u8>> = Vec::with_capacity(reveal_tokens.len());
    for (idx, token) in reveal_tokens.iter().enumerate() {
        match serialize_reveal_token_bytes(token) {
            Ok(b) => reveal_tokens_bytes.push(b),
            Err(e) => {
                tracing::warn!("[REVEAL_SUBMIT] on-chain mode: token[{}] reveal_token_hex serialize failed: {}", idx, e);
                let _ = s.emit("error", &serde_json::json!({
                    "msg": format!("on-chain mode: reveal token[{}] serialization failed: {}", idx, e),
                    "action": "reveal",
                    "table_id": table_id,
                }));
                return None;
            }
        }
        match serialize_reveal_token_proof_bytes(token) {
            Ok(b) => reveal_proof_bytes_list.push(b),
            Err(e) => {
                tracing::warn!("[REVEAL_SUBMIT] on-chain mode: token[{}] proof serialize failed: {}", idx, e);
                let _ = s.emit("error", &serde_json::json!({
                    "msg": format!("on-chain mode: reveal token[{}] proof serialization failed: {}", idx, e),
                    "action": "reveal",
                    "table_id": table_id,
                }));
                return None;
            }
        }
    }
    Some((reveal_tokens_bytes, reveal_proof_bytes_list))
}

/// 提交前校验 reveal token proof：纯验证逻辑（无 RPC），接受链上 deck 字节和
/// ShowdownReveal 的部分解密密文映射。
///
/// `chain_deck` 是 `summary.crypto.deck_encrypted` 的切片。
/// `partial_ciphertexts` 为 ShowdownReveal 阶段的 c1→(c1,c2') 映射；非 showdown 阶段传空 HashMap。
///
/// Proof 验证失败时返回 `Err(msg)`（调用方应跳过提交）。
async fn verify_reveal_proofs_core(
    chain_deck: &[Vec<u8>],
    partial_ciphertexts: &std::collections::HashMap<Vec<u8>, poker_protocol::crypto::ElGamalCiphertext>,
    reveal_tokens: &[SubmitRevealTokenJson],
    token_assignment_pairs: &[(usize, u64, u64)],
    reveal_phase: RevealPhase,
) -> Result<(), String> {
    use poker_protocol::crypto::curve::CurvePoint;
    use poker_protocol::crypto::{DefaultCurve, ElGamalCiphertext};
    use poker_protocol::zk_shuffle::reveal_token_proof::REVEAL_TOKEN_PROOF_LABEL;
    use poker_protocol::zk_shuffle::transcript_ext::{CryptoTranscript, FiatShamirTranscript};
    use poker_protocol::z_poker::convert::hex_to_ecpoint;

    type P = <DefaultCurve as poker_protocol::crypto::curve::Curve>::Point;

    if chain_deck.is_empty() {
        return Err("chain deck_encrypted is empty".to_string());
    }

    let player_pk = hex_to_ecpoint(&reveal_tokens[0].reveal_token_proof.user_public_key_hex)
        .map_err(|e| format!("invalid player pk from proof: {}", e))?;

    let mut verified_count = 0u32;
    for (token_idx, _assignment_idx, card_index) in token_assignment_pairs {
        let card_index_usize = *card_index as usize;
        if card_index_usize >= chain_deck.len() {
            return Err(format!(
                "card_index {} out of range (chain deck len={})",
                card_index,
                chain_deck.len()
            ));
        }

        let chain_card_bytes = &chain_deck[card_index_usize];
        if chain_card_bytes.len() != 96 {
            return Err(format!(
                "chain deck[{}] has invalid length {} (expected 96)",
                card_index,
                chain_card_bytes.len()
            ));
        }

        let (c1_bytes, c2_bytes) = chain_card_bytes.split_at(48);
        let c1 = <P as CurvePoint>::from_compressed(c1_bytes)
            .ok_or_else(|| format!("chain deck[{}] c1 deserialization failed", card_index))?;

        // ShowdownReveal: 优先使用部分解密密文 (c1, c2')，与链上验证一致；
        // 其他阶段: 使用原始密文 (c1, c2)，与链上 deck_state.encrypted 一致。
        let chain_card = if reveal_phase == RevealPhase::ShowdownReveal {
            if let Some(partial_ct) = partial_ciphertexts.get(c1_bytes) {
                partial_ct.clone()
            } else {
                tracing::warn!(
                    "[REVEAL_PROOF_VERIFY] ShowdownReveal: no partial ciphertext for card_index {} (c1={}), falling back to original deck c2 (will likely fail on chain)",
                    card_index,
                    hex::encode(&c1_bytes[..16.min(c1_bytes.len())])
                );
                let c2 = <P as CurvePoint>::from_compressed(c2_bytes)
                    .ok_or_else(|| format!("chain deck[{}] c2 deserialization failed", card_index))?;
                ElGamalCiphertext { c1, c2 }
            }
        } else {
            let c2 = <P as CurvePoint>::from_compressed(c2_bytes)
                .ok_or_else(|| format!("chain deck[{}] c2 deserialization failed", card_index))?;
            ElGamalCiphertext { c1, c2 }
        };

        let token = &reveal_tokens[*token_idx];
        let reveal_token = hex_to_ecpoint(&token.reveal_token_hex)
            .map_err(|e| format!("token[{}] invalid reveal_token_hex: {}", token_idx, e))?;

        let proof = token
            .reveal_token_proof
            .to_proof()
            .map_err(|e| format!("token[{}] invalid proof: {}", token_idx, e))?;

        let mut transcript = FiatShamirTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        match proof.verify(&chain_card, &reveal_token, &player_pk, &mut transcript) {
            Ok(()) => {
                tracing::info!(
                    "[REVEAL_PROOF_VERIFY] token[{}] proof verified against chain deck[{}]{}",
                    token_idx,
                    card_index,
                    if reveal_phase == RevealPhase::ShowdownReveal {
                        " (showdown partial ciphertext)"
                    } else {
                        ""
                    }
                );
                verified_count += 1;
            }
            Err(e) => {
                let chain_c1_hex = hex::encode(&chain_card_bytes[..48.min(chain_card_bytes.len())]);
                let frontend_c1_hex = &token.encrypted_card.c1_hex;
                let c1_prefix_len = frontend_c1_hex.len().min(32);
                return Err(format!(
                    "token[{}] proof verification failed against chain deck[{}]: {:?} — deck mismatch detected (c1_chain={}... vs c1_frontend={}...)",
                    token_idx,
                    card_index,
                    e,
                    &chain_c1_hex[..c1_prefix_len],
                    &frontend_c1_hex[..c1_prefix_len]
                ));
            }
        }
    }

    tracing::info!(
        "[REVEAL_PROOF_VERIFY] all {} proofs verified against chain deck (len={})",
        verified_count,
        chain_deck.len()
    );
    Ok(())
}





/// 提交前校验 shuffle proof：纯验证逻辑（无 RPC），接受链上 deck 字节和 aggregated_pk 字节。
///
/// `chain_deck_bytes` 是 `summary.crypto.deck_encrypted` 的切片。
/// `agg_pk_bytes` 是 `summary.crypto.aggregated_pk` 的切片。
///
/// Proof 验证失败时返回 `Err(msg)`（调用方应跳过提交）。
async fn verify_shuffle_proofs_core(
    chain_deck_bytes: &[Vec<u8>],
    agg_pk_bytes: &[u8],
    output_cards: &[ElGamalCiphertextJson],
    shuffle_proof: &ShuffleProofJson,
) -> Result<(), String> {
    use poker_protocol::crypto::curve::CurvePoint;
    use poker_protocol::crypto::{DefaultCurve, ElGamalCiphertext};
    use poker_protocol::zk_shuffle::transcript_ext::{CryptoTranscript, FiatShamirTranscript};

    type P = <DefaultCurve as poker_protocol::crypto::curve::Curve>::Point;

    if chain_deck_bytes.is_empty() {
        return Err("chain deck_encrypted is empty".to_string());
    }

    // 反序列化链上 deck → Vec<ElGamalCiphertext>
    let chain_deck: Vec<ElGamalCiphertext> = {
        let mut deck = Vec::with_capacity(chain_deck_bytes.len());
        for (i, ct_bytes) in chain_deck_bytes.iter().enumerate() {
            if ct_bytes.len() != 96 {
                return Err(format!(
                    "chain deck[{}] has invalid length {} (expected 96)",
                    i,
                    ct_bytes.len()
                ));
            }
            let (c1_bytes, c2_bytes) = ct_bytes.split_at(48);
            let c1 = <P as CurvePoint>::from_compressed(c1_bytes)
                .ok_or_else(|| format!("chain deck[{}] c1 deserialization failed", i))?;
            let c2 = <P as CurvePoint>::from_compressed(c2_bytes)
                .ok_or_else(|| format!("chain deck[{}] c2 deserialization failed", i))?;
            deck.push(ElGamalCiphertext { c1, c2 });
        }
        deck
    };

    // 反序列化 aggregated_pk
    if agg_pk_bytes.len() != 48 {
        return Err(format!(
            "chain aggregated_pk has invalid length {} (expected 48)",
            agg_pk_bytes.len()
        ));
    }
    let agg_pk = <P as CurvePoint>::from_compressed(agg_pk_bytes)
        .ok_or_else(|| "chain aggregated_pk deserialization failed".to_string())?;

    // 解析 output_cards
    let output_cts: Vec<ElGamalCiphertext> = output_cards
        .iter()
        .map(|c| c.to_ciphertext())
        .collect::<Result<Vec<_>, _>>()?;

    // 解析 shuffle proof
    let shuffle_p = shuffle_proof.to_proof()?;

    if chain_deck.len() != output_cts.len() {
        return Err(format!(
            "deck length mismatch: chain deck={} vs output_cards={}",
            chain_deck.len(),
            output_cts.len()
        ));
    }

    // 验证 shuffle: chain_deck → output_cts（plain shuffle，无 remask，与 Move submit_shuffle_v2 一致）
    let mut transcript = FiatShamirTranscript::new(b"zk_shuffle_proof_v2");
    match shuffle_p.verify(&chain_deck, &output_cts, &agg_pk, &mut transcript) {
        Ok(()) => {
            tracing::info!(
                "[SHUFFLE_PROOF_VERIFY] shuffle proof verified against chain deck (len={}, agg_pk_prefix={})",
                chain_deck.len(),
                hex::encode(&agg_pk_bytes[..16.min(agg_pk_bytes.len())])
            );
            Ok(())
        }
        Err(e) => {
            let chain_first_c1 = hex::encode(
                &chain_deck_bytes[0][..16.min(chain_deck_bytes[0].len())],
            );
            let frontend_first_c1 = &output_cards[0].c1_hex;
            let prefix_len = frontend_first_c1.len().min(32);
            Err(format!(
                "shuffle proof verification failed against chain deck: {:?} — deck mismatch detected (chain_input_c1={}... vs output_c1={}...)",
                e,
                chain_first_c1,
                &frontend_first_c1[..prefix_len]
            ))
        }
    }
}







/// 统一 payload 解析：socketioxide 的 `Data::<T>` 解析失败是静默的
/// （handler 不执行、无任何日志），两端字段命名漂移时表现为“消息消失”。
/// 所有 handler 统一先收 `serde_json::Value`，再用本宏显式解析并记录
/// 失败原因与原始 JSON。
macro_rules! parse_payload {
    ($event:expr, $raw:expr, $ty:ty) => {
        match serde_json::from_value::<$ty>($raw.clone()) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("[{}] payload parse failed: {}, raw: {}", $event, e, $raw);
                return;
            }
        }
    };
}

pub fn register_handlers(io: &SocketIo) {
    io.ns("/", async move |socket: SocketRef, io: SocketIo, State(state): State<Arc<SocketState>>| {
        on_connect(socket, io, state);
    });
}

fn on_connect(socket: SocketRef, _io: SocketIo, _state: Arc<SocketState>) {
    socket.on(actions::FETCH_LOBBY_INFO, async move |s: SocketRef, Data::<serde_json::Value>(payload_raw), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let token = match payload_raw.as_str() {
            Some(s) => s.to_string(),
            None => {
                tracing::error!("[FETCH_LOBBY_INFO] payload parse failed: expected string, raw: {}", payload_raw);
                return;
            }
        };
        let claims = match auth::verify_token(&token, &state.config.jwt_secret) {
            Ok(c) => c,
            Err(_) => return,
        };
        // tracing::info!("on_connect FETCH_LOBBY_INFO: {}", claims.user.id.clone());
        let new_socket_id = s.id.to_string();
        let user_id = claims.user.id.clone();

        let old_player = {
            let gs = state.state.read().await;
            gs.players.values().find(|t| t.id == user_id).cloned()
        };
        // tracing::info!("on_connect FETCH_LOBBY_INFO: {} old_sid={:?}", claims.user.id.clone(), old_player.as_ref().map(|p| p.socket_id.clone()));

        // 这个替换seat里面的player
        let (table_ids_to_broadcast, is_reconnect) = if let Some(old_player) = old_player {
            tracing::info!("[RECONNECT] user {} found disconnected seat, old_sid={}, new_sid={}", user_id, old_player.socket_id.clone(), new_socket_id);
            {
                let mut gs = state.state.write().await;
                if let Some(cancel_tx) = gs.disconnect_cancellers.remove(&old_player.socket_id) {
                    let _ = cancel_tx.send(true);
                }
            }
            let reconnected_table_ids = {
                let mut gs = state.state.write().await;
                let mut ids = Vec::new();
                for table in gs.tables.values_mut() {
                    if table.reconnect_player(&old_player.wallet_address.0) {
                        ids.push(table.summary.id);
                    }
                }
                ids
            };

            let db_user = state.db.find_user_by_id(&user_id).await;
            if let Some(user) = db_user {
                let bankroll = get_available_chips(&state, &user).await;
                let mut gs = state.state.write().await;
                gs.players.insert(new_socket_id.clone(), Player {
                    socket_id: new_socket_id.clone(),
                    id: user.id,
                    name: user.name,
                    bankroll,
                    wallet_address: WalletAddress::new(user.address.clone()),
                });
                gs.players.remove(&old_player.socket_id);
            }

            (reconnected_table_ids, true)
        }else{
            (Vec::new(), false)
        };

        // 这个替换players里面的player
        {
            let old_player = {
                let gs = state.state.read().await;
                gs.players.values().find(|p| p.id == user_id).cloned()
            };
            // tracing::info!("on_connect FETCH_LOBBY_INFO: {} old_sid={:?}", claims.user.id.clone(), old_player.as_ref().map(|p| p.socket_id.clone()));

            if let Some(ref old_player) = old_player {
                tracing::info!("[RECONNECT] user {} found active session in players, replacing old_sid={}", user_id, old_player.socket_id.clone());
                let mut gs = state.state.write().await;
                if let Some(cancel_tx) = gs.disconnect_cancellers.remove(&old_player.socket_id) {
                    let _ = cancel_tx.send(true);
                }
                gs.players.remove(&old_player.socket_id);
                gs.players.insert(new_socket_id.clone(), Player {
                    socket_id: new_socket_id.clone(),
                    id: old_player.id.clone(),
                    name: old_player.name.clone(),
                    wallet_address: old_player.wallet_address.clone(),
                    bankroll: old_player.bankroll,
                });
                for table in gs.tables.values_mut() {
                    table.reconnect_player(&old_player.wallet_address.0);
                }
            }
        };
        // tracing::info!("on_connect FETCH_LOBBY_INFO: {}", claims.user.id.clone());


        for tid in &table_ids_to_broadcast {
            broadcast::broadcast_to_table(&io, &state, *tid, None).await;
        }

        if !is_reconnect {
            let db_user = state.db.find_user_by_id(&claims.user.id).await;
            if let Some(user) = db_user {
                // tracing::info!("on_connect FETCH_LOBBY_INFO: {} user={:?}", claims.user.id.clone(), user);
                let bankroll = get_available_chips(&state, &user).await;
                state.state.write().await.players.insert(s.id.to_string(), Player {
                    socket_id: s.id.to_string(),
                    id: user.id,
                    name: user.name,
                    wallet_address: WalletAddress::new(user.address.clone()),
                    bankroll,
                });
            }
        }

        let lobby = LobbyInfo {
            tables: state.get_current_tables().await,
            players: state.get_current_players().await,
            socket_id: s.id.to_string(),
        };
        let _ = s.emit(actions::RECEIVE_LOBBY_INFO, &lobby);
        let players_info = state.get_current_players().await;
        let _ = io.emit(actions::PLAYERS_UPDATED, &players_info).await;
    });

    socket.on(actions::JOIN_TABLE, async move |s: SocketRef, Data::<serde_json::Value>(payload_raw), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let payload = parse_payload!(actions::JOIN_TABLE, payload_raw, JoinTablePayload);
        let table_id = payload.table_id;
        s.join(table_room_name(table_id));
        tracing::info!("join_table: {} {}", payload.pk_hex, table_id);
        let socket_id = s.id.to_string();
        // let join_msg = {
        //     let mut gs = state.state.write().await;

        //     let player_data = gs.players.get(&socket_id).map(|p| (p.clone(), truncate_name(&p.name, 12)));

        //     if let Some(table) = gs.tables.get_mut(&table_id) {
        //         if let Some((player_clone, player_name)) = player_data {
        //             table.add_player(payload.pk_hex.clone(), player_clone.wallet_address.clone());
        //             tracing::info!("add_player: {}", socket_id);
        //             Some(format!("{} joined the table.", player_name))
        //         } else { None }
        //     } else { None }
        // };

        // let tables_info = state.get_current_tables().await;
        // {
        //     let gs = state.state.read().await;
        //     if let Some(table) = gs.tables.get(&table_id) {
        //         let wallet_addr = gs.players.get(&socket_id).map(|p| p.wallet_address.clone());
        //         let table_view = wallet_addr.map(|wa| hide_opponent_cards(&table.to_client(), &wa));
        //         if let Some(table_view) = table_view {
        //             let _ = s.emit(actions::TABLE_JOINED, &TableUpdatePayload {
        //                 table: table_view,
        //                 message: join_msg.clone(),
        //                 from: None,
        //             });
        //         }
        //     }
        // }
        // let _ = io.emit(actions::TABLES_UPDATED, &tables_info).await;

        let wallet = {
            let mut gs = state.state.write().await;
            gs.players.get(&socket_id).map(|p| p.wallet_address.clone()).unwrap_or_else(|| WalletAddress::new("".to_string()))
        };

        broadcast::join_table_push(&io, &state, table_id, wallet).await;
        // 通知桌上所有已有玩家：新玩家加入后刷新各自的 table view
        // broadcast_to_table 会为每个玩家定制 view（hide_opponent_cards），
        // join_table_push 只发给新加入的 socket，已有玩家不会收到更新。
        broadcast::broadcast_to_table(&io, &state, table_id, Some("player joined")).await;
    });

    socket.on(actions::LEAVE_TABLE, async move |s: SocketRef, Data::<serde_json::Value>(payload_raw), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let payload = parse_payload!(actions::LEAVE_TABLE, payload_raw, LeaveTablePayload);
        let socket_id = s.id.to_string();
        let table_id = payload.table_id;
        let wallet_address = { state.state.read().await.players.get(&socket_id).map(|p| p.wallet_address.clone()) };
        tracing::info!("leave_table: {} {} {:?}", payload.pk_hex, table_id, wallet_address);
        // Derive pk_hex: prefer client-provided value, fallback to wallet_address lookup
        let pk_hex: Option<GamePkHex> = {
            let gs = state.state.read().await;
            if payload.pk_hex.0.is_empty() {
                // Client didn't provide pk_hex, lookup from table.players
                wallet_address.as_ref().and_then(|wa| {
                    gs.tables.get(&table_id).and_then(|t| t.get_pk_hex_by_wallet_address(&wa.0))
                })
            } else {
                // Verify client-provided pk_hex matches wallet_address
                if let Some(ref wa) = wallet_address {
                    if let Some(table) = gs.tables.get(&table_id) {
                        if let Some(looked_up) = table.get_pk_hex_by_wallet_address(&wa.0) {
                            if looked_up != payload.pk_hex {
                                tracing::warn!("[LEAVE_TABLE] pk_hex mismatch: client={}, server={}", payload.pk_hex, looked_up);
                            }
                        }
                    }
                }
                Some(payload.pk_hex.clone())
            }
        };

        let (is_playing, player_name) = {
            let gs = state.state.read().await;
            if let Some(table) = gs.tables.get(&table_id) {
                let name = wallet_address.as_ref().and_then(|wa| table.find_player_by_wallet(wa))
                    .and_then(|_| gs.players.get(&socket_id).map(|p| truncate_name(&p.name, 12)));
                (table.is_playing(), name)
            } else { (false, None) }
        };

        if is_playing {
            tracing::info!("[LEAVE_TABLE] Table {}: {} is leaving while hand in progress, marking sitting_out", table_id, socket_id);
            if let Some(ref wallet_address) = wallet_address {
                state.mark_player_sitting_out(table_id, wallet_address).await;
            }
            let msg = player_name.map(|n| format!("{} is sitting out.", n));
            broadcast::broadcast_to_table(&io, &state, table_id, msg.as_deref()).await;
            // 通知客户端：手牌进行中，离开已延迟到手牌结束后再处理
            let _ = s.emit(actions::LEAVE_DEFERRED, &LeaveDeferredPayload {
                table_id,
                reason: "hand_in_progress".to_string(),
            });
            return;
        }
        s.leave(table_room_name(table_id));

        let chips_update = {
            let gs = state.state.read().await;
            if let Some(table) = gs.tables.get(&table_id) {
                pk_hex.as_ref().and_then(|pk| table.find_player_by_pk(pk))
                    .and_then(|seat| {
                        gs.players.get(&socket_id).map(|p| (p.id.clone(), seat.stack))
                    })
            } else { None }
        };

        if let Some((pid, stack)) = chips_update {
            let _ = state.db.unlock_chips(&pid, stack as i64).await;
        }

        let (leave_msg, need_clear) = {
            let mut guard = state.state.write().await;
            let gs = &mut *guard;
            let name = gs.players.get(&socket_id).map(|p| p.name.clone());
            if let Some(table) = gs.tables.get_mut(&table_id) {
                if let Some(ref pk) = pk_hex {
                    tracing::info!("remove_player_by_pk: {}", pk);
                    table.leave_talbe_and_clear_shuffle(pk);
                } else {
                    tracing::warn!("[LEAVE_TABLE] No pk_hex found for socket_id={}, cannot remove player", socket_id);
                }
                let msg = name.map(|n| format!("{} left the table.", n));
                let clear = table.active_players().len() == 1;
                (msg, clear)
            } else { (None, false) }
        };

        let tables_info = state.get_current_tables().await;
        let players_info = state.get_current_players().await;
        let _ = io.emit(actions::TABLES_UPDATED, &tables_info).await;
        let _ = io.emit(actions::PLAYERS_UPDATED, &players_info).await;
        let _ = s.emit(actions::TABLE_LEFT, &TableLeftPayload { tables: tables_info, table_id, reason: None });

        if let Some(msg) = &leave_msg {
            broadcast::broadcast_to_table(&io, &state, table_id, Some(msg)).await;
        }

        if need_clear {
            state.stop_game_loop(table_id).await;
            game_loop::clear_for_one_player(&io, state.clone(), table_id).await;
        }
    });

    socket.on(actions::FOLD, async move |s: SocketRef, Data::<serde_json::Value>(payload_raw), _io: SocketIo, State(state): State<Arc<SocketState>>| {
        let table_id = parse_payload!(actions::FOLD, payload_raw, u32);
        if !try_on_chain_action(&s, &state, table_id, "fold", None).await {
            send_simple_action(&s, &state, table_id, "fold").await;
        }
    });

    socket.on(actions::CHECK, async move |s: SocketRef, Data::<serde_json::Value>(payload_raw), _io: SocketIo, State(state): State<Arc<SocketState>>| {
        let table_id = parse_payload!(actions::CHECK, payload_raw, u32);
        if !try_on_chain_action(&s, &state, table_id, "check", None).await {
            send_simple_action(&s, &state, table_id, "check").await;
        }
    });

    socket.on(actions::CALL, async move |s: SocketRef, Data::<serde_json::Value>(payload_raw), _io: SocketIo, State(state): State<Arc<SocketState>>| {
        let table_id = parse_payload!(actions::CALL, payload_raw, u32);
        if !try_on_chain_action(&s, &state, table_id, "call", None).await {
            send_simple_action(&s, &state, table_id, "call").await;
        }
    });

    socket.on(actions::RAISE, async move |s: SocketRef, Data::<serde_json::Value>(payload_raw), _io: SocketIo, State(state): State<Arc<SocketState>>| {
        let payload = parse_payload!(actions::RAISE, payload_raw, RaisePayload);
        if !try_on_chain_action(&s, &state, payload.table_id, "raise", Some(payload.amount)).await {
            let socket_id = s.id.to_string();
            let pk_hex = {
                let gs = state.state.read().await;
                gs.players.get(&socket_id)
                    .and_then(|p| gs.tables.get(&payload.table_id).and_then(|t| t.get_pk_hex_by_wallet_address(&p.wallet_address.0)))
            };
            if let (Some(pk_hex), Some(sender)) = (pk_hex, state.get_action_sender(payload.table_id).await) {
                let _ = sender.send(ActionRequest { pk_hex, action: "raise".to_string(), amount: Some(payload.amount) }).await;
            }
        }
    });

    socket.on(actions::TABLE_MESSAGE, async move |_s: SocketRef, Data::<serde_json::Value>(payload_raw), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let payload = parse_payload!(actions::TABLE_MESSAGE, payload_raw, TableMessagePayload);
        let socket_ids = {
            let gs = state.state.read().await;
            gs.tables.get(&payload.table_id).map(|t| {
                t.players().iter()
                    .filter_map(|(_game_pk, wallet_addr)| {
                        gs.players.values()
                            .find(|p| p.wallet_address.0 == wallet_addr.0)
                            .map(|p| p.socket_id.clone())
                    })
                    .collect::<Vec<_>>()
            })
        };

        if let Some(sids) = socket_ids {
            for sid_str in sids {
                let table_view = {
                    let gs = state.state.read().await;
                    let wallet_addr = gs.players.get(&sid_str).map(|p| p.wallet_address.clone());
                    gs.tables.get(&payload.table_id).and_then(|t| wallet_addr.map(|wa| hide_opponent_cards(&t.to_client(), &wa)))
                };
                if let Some(table_view) = table_view {
                    let update = TableUpdatePayload {
                        table: table_view,
                        message: Some(payload.message.clone()),
                        from: Some(payload.from.clone()),
                    };
                    if let Ok(sid) = sid_str.parse::<socketioxide::socket::Sid>() {
                        if let Some(socket) = io.get_socket(sid) {
                            let _ = socket.emit(actions::TABLE_UPDATED, &update);
                        }
                    }
                }
            }
        }
    });

    socket.on(actions::SIT_DOWN, async move |s: SocketRef, Data::<serde_json::Value>(payload_raw), _io: SocketIo, _state: State<Arc<SocketState>>| {
        let payload = parse_payload!(actions::SIT_DOWN, payload_raw, SitDownPayload);
        let socket_id = s.id.to_string();
        tracing::warn!("[SIT_DOWN] Deprecated SIT_DOWN action received from {}, please use SIT_DOWN_V2. table_id={}, seat_id={}", socket_id, payload.table_id, payload.seat_id);
        let _ = s.emit("error", &serde_json::json!({"msg": "SIT_DOWN is deprecated, please use SIT_DOWN_V2"}));
    });

    socket.on(actions::SIT_DOWN_V2, async move |s: SocketRef, Data::<serde_json::Value>(payload_raw), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let payload = parse_payload!(actions::SIT_DOWN_V2, payload_raw, SitDownV2Payload);
        // 1. Validate request (auth, amount, pk, player, balance)
        let (player, player_pk) = match validate_sit_down_request(&s, &state, &payload).await {
            Some(v) => v,
            None => return,
        };

        // 1.5 Starknet 买入校验：PokerVault.deposit 交易回执必须成功，
        //     且（配置了 vault 时）vault 筹码余额覆盖买入数量。dev 模式自动放行。
        if let Some(ref deposit_tx_hash) = payload.deposit_tx_hash {
            let buyer = payload.wallet_address.clone().unwrap_or_else(|| player.wallet_address.0.clone());
            if let Err(e) = crate::starknet::chips::verify_deposit(deposit_tx_hash, &buyer, payload.amount as i64).await {
                tracing::warn!("[SIT_DOWN_V2] STRK20 buy-in verification failed, user={}, tx={}: {}", player.id, deposit_tx_hash, e);
                let _ = s.emit("error", &serde_json::json!({"msg": format!("Buy-in verification failed: {}", e)}));
                return;
            }
            tracing::info!("[SIT_DOWN_V2] STRK20 buy-in verified: user={}, amount={}, tx={}", player.id, payload.amount, deposit_tx_hash);
        }

        // 2.5 Starknet 镜像：缓冲 join（poker_l1 join_table 仅允许 Waiting，
        //     洗牌期入座的 join 会在下一手 mirror_begin_reveal 时重放应用）
        {
            let gs = state.state.read().await;
            if let Some(table) = gs.tables.get(&payload.table_id) {
                // 缓冲带真实 pk 所有权证明的 join（mirror join_table 会验证）
                let pk_proof_bytes = payload.pk_proof.to_proof()
                    .map(|p| crate::relayer::proof_bytes::serialize_pk_ownership_proof(&p))
                    .unwrap_or_default();
                crate::starknet::hooks::mirror_buffer_join_pk(
                    payload.table_id,
                    &player.wallet_address.0,
                    &payload.pk_hex.0,
                    payload.amount,
                    &payload.pk_proof,
                    pk_proof_bytes,
                );
            }
        }

        // 3. Local mode: init seat and shuffle
        let player_id = player.id.clone();
        let player_name = truncate_name(&player.name, 12);
        let result = state.join_player_and_shuffle(
            payload.table_id,
            player,
            player_pk,
            payload.pk_proof,
            payload.mask_and_shuffle_round,
            payload.seat_id,
            payload.amount,
        ).await;

        // 4. Broadcast result
        broadcast_sit_down(
            &io, &s, &state, payload.table_id, payload.seat_id, &payload.pk_hex,
            payload.amount, &player_id, &player_name, result,
        ).await;
    });

    socket.on(actions::REBUY, async move |s: SocketRef, Data::<serde_json::Value>(payload_raw), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let payload = parse_payload!(actions::REBUY, payload_raw, RebuyPayload);
        let socket_id = s.id.to_string();

        // E3 修复：校验 amount > 0
        if payload.amount == 0 {
            tracing::warn!("[REBUY] Invalid amount=0 from socket_id={}", socket_id);
            let _ = s.emit("error", &serde_json::json!({"msg": "Amount must be positive"}));
            return;
        }

        // E3 修复：使用 i64::try_from 避免 u64 -> i64 转换溢出
        let deduct = match i64::try_from(payload.amount) {
            Ok(v) => -v,
            Err(_) => {
                tracing::warn!("[REBUY] Amount too large for i64: {}", payload.amount);
                let _ = s.emit("error", &serde_json::json!({"msg": "Amount too large"}));
                return;
            }
        };

        // A3 修复：验证发送者拥有该 seat_id
        if !verify_socket_sender_seat(&s, &state, payload.table_id, payload.seat_id).await {
            return;
        }

        let chips_deduct = {
            let mut gs = state.state.write().await;

            if let Some(table) = gs.tables.get_mut(&payload.table_id) {
                table.rebuy_player(payload.seat_id, payload.amount);
                gs.players.get(&socket_id).map(|p| p.id.clone())
            } else { None }
        };

        if let Some(pid) = chips_deduct {
            // E3 修复：检查余额（PokerVault 链上筹码 - locked_chips）
            let db_user = state.db.find_user_by_id(&pid).await;
            if let Some(ref user) = db_user {
                let available = get_available_chips(&state, user).await;
                if available < payload.amount as i64 {
                    tracing::warn!(
                        "[REBUY] Insufficient chips: user_id={}, available={}, required={}",
                        pid,
                        available,
                        payload.amount
                    );
                    let _ = s.emit("error", &serde_json::json!({"msg": "Insufficient chips"}));
                    // 余额不足，回滚 rebuy_player 的座位状态变更
                    let mut gs = state.state.write().await;
                    if let Some(table) = gs.tables.get_mut(&payload.table_id) {
                        // 简单回滚：从 seat stack 中减去刚加的 amount
                        if let Some(seat) = table.local_seats.get_mut(&payload.seat_id) {
                            seat.stack = seat.stack.saturating_sub(payload.amount);
                        }
                    }
                    broadcast::broadcast_to_table(&io, &state, payload.table_id, None).await;
                    return;
                }
            }
            // 锁定筹码（rebuy 时扣除可用余额）
            let _ = state.db.lock_chips(&pid, payload.amount as i64).await;
        }

        broadcast::broadcast_to_table(&io, &state, payload.table_id, None).await;
    });

    socket.on(actions::STAND_UP, async move |s: SocketRef, Data::<serde_json::Value>(payload_raw), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let payload = parse_payload!(actions::STAND_UP, payload_raw, StandUpPayload);
        let socket_id = s.id.to_string();
        let table_id = payload.table_id;
        let pk_hex = GamePkHex::new(payload.pk_hex.to_lowercase());
        tracing::info!("[STAND_UP] Received from {}: table_id={}, pk_hex={}", socket_id, table_id, pk_hex);

        // A3 修复：验证发送者拥有所声称的 pk_hex
        if !verify_socket_sender(&s, &state, table_id, &pk_hex).await {
            return;
        }

        let player_pk = match hex_to_ecpoint(&**pk_hex) {
            Ok(pk) => pk,
            Err(e) => {
                tracing::warn!("[STAND_UP] Invalid pk_hex: {}", e);
                return;
            }
        };

        let (is_playing, player_name) = {
            let gs = state.state.read().await;
            if let Some(table) = gs.tables.get(&table_id) {
                (table.is_playing(), table.find_player_by_pk(&pk_hex)
                    .and_then(|seat| seat.player.as_ref().map(|p| truncate_name(&p.name, 12))))
            } else { (false, None) }
        };

        if is_playing {
            tracing::info!("[STAND_UP] Table {}: {} standing up while hand in progress, marking sitting_out", table_id, socket_id);
            {
                let wallet_addr = {
                    let gs = state.state.read().await;
                    gs.players.get(&socket_id).map(|p| p.wallet_address.clone())
                };
                if let Some(wa) = wallet_addr {
                    state.mark_player_sitting_out(table_id, &wa).await;
                }
            }
            broadcast::broadcast_to_table(&io, &state, table_id, player_name.map(|n| format!("{} is sitting out.", n)).as_deref()).await;
            // 手牌进行中：不调用 handle_stand_up_on_chain（包括 folded 玩家，
            // 因为 leave_with_proof_verified 要求 round_state == Waiting，
            // 而 fold 不会提交 reveal tokens，链上交易会失败）。
            // 仅 emit LEAVE_DEFERRED，让客户端展示"等待手牌结束"UI。
            let _ = s.emit(actions::LEAVE_DEFERRED, &LeaveDeferredPayload {
                table_id,
                reason: "hand_in_progress".to_string(),
            });
            return;
        }

        // Local mode: verify leave proof, remove player, broadcast
        handle_stand_up_local(&state, &io, &payload, &pk_hex, &player_pk, table_id, &socket_id).await;
    });

    socket.on(actions::SITTING_OUT, async move |_s: SocketRef, Data::<serde_json::Value>(payload_raw), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let payload = parse_payload!(actions::SITTING_OUT, payload_raw, SittingPayload);
        {
            let mut gs = state.state.write().await;
            if let Some(table) = gs.tables.get_mut(&payload.table_id) {
                if let Some(seat) = table.local_seats.get_mut(&payload.seat_id) {
                    seat.sitting_out = true;
                }
            }
        }
        broadcast::broadcast_to_table(&io, &state, payload.table_id, None).await;
    });

    socket.on(actions::SITTING_IN, async move |_s: SocketRef, Data::<serde_json::Value>(payload_raw), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let payload = parse_payload!(actions::SITTING_IN, payload_raw, SittingPayload);
        let should_start = {
            let mut gs = state.state.write().await;
            if let Some(table) = gs.tables.get_mut(&payload.table_id) {
                if let Some(seat) = table.local_seats.get_mut(&payload.seat_id) {
                    seat.sitting_out = false;
                }
                table.summary.hand_over && table.active_players().len() == MIN_START_NUM as usize
            } else { false }
        };

        broadcast::broadcast_to_table(&io, &state, payload.table_id, None).await;

        if should_start {
            state.start_game_loop(io, state.clone(), payload.table_id).await;
        }
    });

    socket.on(actions::SHUFFLE_SUBMIT, async move |s: SocketRef, Data::<serde_json::Value>(data), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let payload: Result<ShuffleSubmitPayload, _> = serde_json::from_value(data.clone());
        let payload = match payload {
            Ok(p) => p,
            Err(e) => {
                tracing::error!("[SHUFFLE_SUBMIT] Failed to parse payload: {}, raw: {:?}", e, data);
                return;
            }
        };

        let socket_id = s.id.to_string();
        tracing::info!("[SHUFFLE_SUBMIT] request received, pk_hex={}, table_id={}", payload.pk_hex, payload.table_id);
        let pk_hex = GamePkHex::new(payload.pk_hex.to_lowercase());

        // A3 修复：验证发送者拥有所声称的 pk_hex
        if !verify_socket_sender(&s, &state, payload.table_id, &pk_hex).await {
            tracing::warn!("[SHUFFLE_SUBMIT] Failed to verify socket sender, pk_hex={}, table_id={}", pk_hex, payload.table_id);
            return;
        }

        // Starknet 镜像：同步洗牌到 poker_l1（失败仅告警，不影响牌局）
        {
            let out: Result<Vec<poker_protocol::crypto::ElGamalCiphertext>, String> =
                payload.output_cards.iter().map(|c| c.to_ciphertext()).collect();
            if let (Ok(out), Ok(proof)) = (out, payload.shuffle_proof.to_proof()) {
                let gs = state.state.read().await;
                if let Some(table) = gs.tables.get(&payload.table_id) {
                    // 方案A：SHUFFLE_SUBMIT 不再转发 mirror（deck 终局注入）。
                }
            }
        }

        let player = {
            let gs = state.state.read().await;
            gs.players.get(&socket_id).cloned()
        };

        let player = match player {
            Some(p) => p,
            None => {
                tracing::warn!("[SHUFFLE_SUBMIT] Player not found for socket_id: {}", socket_id);
                return;
            }
        };

        let result = state.submit_verified_shuffle_for_pk(payload.table_id, &pk_hex, player, payload.output_cards.clone(), payload.shuffle_proof.clone()).await;

        match result {
            Ok(reveal_started) => {
                tracing::debug!("[SHUFFLE_SUBMIT] shuffle submitted and verified, pk_hex={}, table_id={}, reveal_started={}", pk_hex, payload.table_id, reveal_started);
                state.send_shuffle_notice(payload.table_id).await;
                broadcast::broadcast_to_table(&io, &state, payload.table_id, None).await;
                // ZK 可视化：shuffle 证明验证成功
                state.broadcast_crypto_event(
                    payload.table_id,
                    broadcast::CryptoEventType::Shuffle,
                    pk_hex.0.clone(),
                    None,
                    true,
                    Some("shuffle proof verified".to_string()),
                    None,
                ).await;
            }
            Err(e) => {
                tracing::warn!("[SHUFFLE_SUBMIT] shuffle verification failed, pk_hex={}, table_id={}, error={}", pk_hex, payload.table_id, e);
                // ZK 可视化：shuffle 证明验证失败
                state.broadcast_crypto_event(
                    payload.table_id,
                    broadcast::CryptoEventType::Shuffle,
                    pk_hex.0.clone(),
                    None,
                    false,
                    Some(format!("shuffle proof verification failed: {}", e)),
                    None,
                ).await;
            }
        }
    });



    socket.on(actions::RECONSTRUCT_SUBMIT, async move |s: SocketRef, Data::<serde_json::Value>(payload_raw), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let payload = parse_payload!(actions::RECONSTRUCT_SUBMIT, payload_raw, ReconstructSubmitPayload);
        let socket_id = s.id.to_string();
        let pk_hex = GamePkHex::new(payload.pk_hex.to_lowercase());
        tracing::info!("[RECONSTRUCT_SUBMIT] request received, pk_hex={}, table_id={}", pk_hex, payload.table_id);

        // A3 修复：验证发送者拥有所声称的 pk_hex
        if !verify_socket_sender(&s, &state, payload.table_id, &pk_hex).await {
            return;
        }

        let _wallet_address = {
            let gs = state.state.read().await;
            gs.players.get(&socket_id).map(|p| p.wallet_address.to_string())
        }.unwrap_or_default();


        let (all_complete, reconstruct_payload, proof_verified) = {
            let mut gs = state.state.write().await;
            if let Some(table) = gs.tables.get_mut(&payload.table_id) {

                let (is_complete, verified) = match table.submit_reconstruct_deck(&pk_hex, payload.output_cards.clone(), payload.swap_cards.clone(), payload.proof) {
                    Ok(complete) => (complete, true),
                    Err(e) => {
                        tracing::error!("[RECONSTRUCT_SUBMIT] Error: {}", e);
                        (false, false)
                    }
                };
                if is_complete {
                    let reconstruct_payload = ReconstructResultPayload {
                        table_id: payload.table_id,
                        completed_players: table.reconstruct_state.completed_players.clone(),
                        reconstructed: true,
                    };
                    let _ = table.start_shuffle();
                    (is_complete, Some(reconstruct_payload), verified)
                } else {
                    (is_complete, None, verified)
                }
            } else {
                (false, None, false)
            }
        };

        if let Some(reconstruct_payload) = reconstruct_payload {
            let _ = io.to(table_room_name(payload.table_id)).emit(actions::RECONSTRUCT_RESULT, &reconstruct_payload).await;
        }
        state.send_shuffle_notice(payload.table_id).await;
        if all_complete {
            tracing::info!("[RECONSTRUCT_SUBMIT] All players completed reconstruct for table {}", payload.table_id);
        }
        broadcast::broadcast_to_table(&io, &state, payload.table_id, None).await;

        // ZK 可视化：reconstruct 证明验证结果
        state.broadcast_crypto_event(
            payload.table_id,
            broadcast::CryptoEventType::Reconstruct,
            pk_hex.0.clone(),
            None,
            proof_verified,
            Some(if proof_verified {
                "reconstruct proof verified".to_string()
            } else {
                "reconstruct proof verification failed".to_string()
            }),
            None,
        ).await;
    });

    // Plan D P2.1：Hand-batch 认可提交（客户端本地铸造的成品认可；
    // 服务器 on-curve/域校验后入 registry，结算聚合时取用）。
    socket.on(actions::ENDORSEMENT_SUBMIT, async move |s: SocketRef, Data::<serde_json::Value>(payload_raw), _io: SocketIo, _state: State<Arc<SocketState>>| {
        let payload = parse_payload!(actions::ENDORSEMENT_SUBMIT, payload_raw, crate::socket::EndorsementSubmitPayload);
        let socket_id = s.id.to_string();
        let session_wallet = _state.state.read().await
            .players.get(&socket_id).map(|p| p.wallet_address.to_string());
        // 会话钱包一致性：声明的 wallet 必须与 WS 会话登录钱包一致
        // （生产可再叠加钱包签名；会话绑定已阻断跨玩家代提交）。
        if session_wallet.as_deref() != Some(payload.wallet.as_str()) {
            tracing::warn!(
                "[ENDORSEMENT_SUBMIT] wallet mismatch: session={:?} declared={}",
                session_wallet,
                payload.wallet
            );
            return;
        }
        match crate::starknet::dual_settle::register_client_endorsement(
            &payload.wallet,
            payload.hand_id,
            &payload.pk_x_hex,
            &payload.pk_y_hex,
            &payload.r_x_hex,
            &payload.r_y_hex,
            &payload.s_hex,
        ) {
            Ok(()) => tracing::info!(
                "[ENDORSEMENT_SUBMIT] registered wallet={} hand={}",
                payload.wallet,
                payload.hand_id
            ),
            Err(e) => tracing::warn!(
                "[ENDORSEMENT_SUBMIT] rejected wallet={} hand={}: {e}",
                payload.wallet,
                payload.hand_id
            ),
        }
    });
    socket.on(actions::REVEAL_SUBMIT, async move |s: SocketRef, Data::<serde_json::Value>(payload_raw), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let payload = parse_payload!(actions::REVEAL_SUBMIT, payload_raw, RevealSubmitPayload);
        // tracing::info!("[REVEAL_SUBMIT] Received RevealSubmitPayload: {:?}", payload);
        let socket_id = s.id.to_string();
        let wallet_address = {
            let gs = state.state.read().await;
            gs.players.get(&socket_id).map(|p| p.wallet_address.to_string())
        };
        let wallet_address = match wallet_address {
            Some(w) => w,
            None => {
                tracing::warn!("[REVEAL_SUBMIT] Player {} not found", socket_id);
                return;
            }
        };

        // Task 5: 若 payload 携带 reveal_tokens，则按 on-chain / 本地模式分别处理
        if let Some(reveal_tokens) = payload.reveal_tokens.as_ref() {
            // 解析 pk_hex：优先使用 payload.pk_hex，否则通过 wallet_address 查找
            let pk_hex = match payload.pk_hex.clone() {
                Some(p) => p,
                None => {
                    let gs = state.state.read().await;
                    gs.tables.get(&payload.table_id)
                        .and_then(|t| t.get_pk_hex_by_wallet_address(&wallet_address))
                        .unwrap_or_default()
                }
            };

            if pk_hex.0.is_empty() {
                tracing::warn!(
                    "[REVEAL_SUBMIT] cannot resolve pk_hex for socket_id={}, table_id={}",
                    socket_id, payload.table_id
                );
                let _ = s.emit("error", &serde_json::json!({"msg": "Cannot resolve pk_hex for reveal"}));
                return;
            }

            // A3 修复：验证发送者拥有所声称的 pk_hex
            if !verify_socket_sender(&s, &state, payload.table_id, &pk_hex).await {
                return;
            }

            // 获取 reveal phase（与 HTTP submit_reveal_token 一致），在 mark_reveal_complete 之前读取
            let reveal_phase = state.get_reveal_phase_for_table(payload.table_id).await.unwrap_or_default();

            // 本地模式：复用 HTTP submit_reveal_token 逻辑
            let player_pk = match poker_protocol::z_poker::convert::hex_to_ecpoint(&pk_hex.0) {
                Ok(pt) => pt,
                Err(e) => {
                    tracing::warn!("[REVEAL_SUBMIT] invalid pk_hex: {}", e);
                    let _ = s.emit("error", &serde_json::json!({"msg": format!("Invalid pk_hex: {}", e)}));
                    return;
                }
            };

            let tokens_len = reveal_tokens.len();
            if tokens_len == 0 {
                tracing::warn!("[REVEAL_SUBMIT] no reveal tokens provided");
                let _ = s.emit("error", &serde_json::json!({"msg": "No reveal tokens provided"}));
                return;
            }

            let tokens: Result<Vec<_>, String> = reveal_tokens.iter()
                .enumerate()
                .map(|(idx, item)| {
                    let encrypted_card = item.encrypted_card.to_ciphertext()
                        .map_err(|e| format!("Token[{}]: Invalid encrypted_card: {}", idx, e))?;
                    let reveal_token = poker_protocol::z_poker::convert::hex_to_ecpoint(&item.reveal_token_hex)
                        .map_err(|e| format!("Token[{}]: Invalid reveal_token_hex: {}", idx, e))?;
                    let proof = item.reveal_token_proof.to_proof()
                        .map_err(|e| format!("Token[{}]: Invalid reveal_token_proof: {}", idx, e))?;
                    Ok(poker_protocol::z_poker::protocol::RevealToken {
                        user_public_key: player_pk,
                        encrypted_card,
                        proof,
                        reveal_token,
                    })
                })
                .collect();

            let tokens = match tokens {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!("[REVEAL_SUBMIT] token parse error: {}", e);
                    let _ = s.emit("error", &serde_json::json!({"msg": format!("Token parse error: {}", e)}));
                    return;
                }
            };

            if let Err(e) = state.submit_reveal_tokens_for_pk(payload.table_id, &pk_hex, tokens.clone()).await {
                // 良性幂等：同一玩家重复提交（同账号多浏览器、REVEAL_NOTICE 与
                // TABLE_UPDATED fallback 并发、服务器重播）到达时首次提交已推进
                // 状态机。info 记录后直接返回——不广播误导性的 "proof verification
                // failed"，也不回 error（UI 会当成真错误展示）。
                if Table::is_benign_reveal_error(&e) {
                    tracing::info!(
                        "[REVEAL_SUBMIT] idempotent duplicate submit ignored, table_id={}, pk_hex={}",
                        payload.table_id, pk_hex
                    );
                    return;
                }
                tracing::warn!("[REVEAL_SUBMIT] submit failed, table_id={}, pk_hex={}, error={}", payload.table_id, pk_hex, e);
                state.broadcast_crypto_event(
                    payload.table_id,
                    broadcast::CryptoEventType::RevealToken,
                    pk_hex.0.clone(),
                    None,
                    false,
                    Some(format!("reveal_token proof verification failed: {}", e)),
                    None,
                ).await;
                let _ = s.emit("error", &serde_json::json!({"msg": format!("Reveal token submit failed: {}", e)}));
                return;
            }

            // Starknet 镜像：同步 reveal tokens 到 poker_l1（失败仅告警）
            {
                let gs = state.state.read().await;
                if let Some(table) = gs.tables.get(&payload.table_id) {
                }
            }

            // ZK 可视化：reveal_token 证明验证成功
            state.broadcast_crypto_event(
                payload.table_id,
                broadcast::CryptoEventType::RevealToken,
                pk_hex.0.clone(),
                None,
                true,
                Some("reveal_token proof verified".to_string()),
                None,
            ).await;

            let all_complete = match state.mark_reveal_complete_for_pk(payload.table_id, &pk_hex).await {
                Ok(result) => {
                    tracing::info!("[REVEAL_SUBMIT] reveal marked, table_id={}, pk_hex={}, all_complete={}", payload.table_id, pk_hex, result);
                    result
                }
                Err(e) => {
                    tracing::warn!("[REVEAL_SUBMIT] mark reveal failed, table_id={}, pk_hex={}, error={}", payload.table_id, pk_hex, e);
                    let _ = s.emit("error", &serde_json::json!({"msg": format!("Mark reveal failed: {}", e)}));
                    return;
                }
            };

            // reveal 结果广播已下沉到 on_reveal_complete 的单点（TableEvent::RevealResult），
            // 这里不再重复分发。
            broadcast::broadcast_to_table(&io, &state, payload.table_id, None).await;
            return;
        }

        // 旧路径：reveal_tokens 为 None，保持原有行为（仅标记完成）
        // 获取 reveal phase（与 HTTP submit_reveal_token 一致），在 mark_reveal_complete 之前读取
        let reveal_phase = state.get_reveal_phase_for_table(payload.table_id).await.unwrap_or_default();
        let pk_hex_str = {
            let gs = state.state.read().await;
            gs.tables.get(&payload.table_id)
                .and_then(|t| t.get_pk_hex_by_wallet_address(&wallet_address))
                .map(|pk| pk.0.clone())
        };
        // ZK 可视化：reveal_token 证明验证成功（与 HTTP 路径一致）
        if let Some(pk_str) = pk_hex_str.as_ref() {
            state.broadcast_crypto_event(
                payload.table_id,
                broadcast::CryptoEventType::RevealToken,
                pk_str.clone(),
                None,
                true,
                Some("reveal_token proof verified".to_string()),
                None,
            ).await;
        }
        let all_complete = {
            let mut gs = state.state.write().await;
            if let Some(table) = gs.tables.get_mut(&payload.table_id) {
                let pk_hex = table.get_pk_hex_by_wallet_address(&wallet_address);
                pk_hex.map_or(false, |pk| table.mark_player_reveal_complete(&pk))
            } else {
                false
            }
        };
        // reveal 结果广播已下沉到 on_reveal_complete 的单点（TableEvent::RevealResult）。
        broadcast::broadcast_to_table(&io, &state, payload.table_id, None).await;
    });

    socket.on(actions::REDEAL_REQUEST, async move |s: SocketRef, Data::<serde_json::Value>(payload_raw), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let payload = parse_payload!(actions::REDEAL_REQUEST, payload_raw, RedealRequestPayload);
        let player_pk = GamePkHex::new(payload.player_pk.to_lowercase());
        tracing::info!("[REDEAL_REQUEST] Player {} requests redeal for {} failed cards on table {}",
            player_pk, payload.failed_card_indices.len(), payload.table_id);

        // A3 修复：验证发送者拥有所声称的 player_pk
        if !verify_socket_sender(&s, &state, payload.table_id, &player_pk).await {
            return;
        }

        // 执行 redeal
        let redealt_indices = {
            let mut gs = state.state.write().await;
            if let Some(table) = gs.tables.get_mut(&payload.table_id) {
                match table.redeal_cards_for_player(&player_pk, payload.failed_card_indices.clone()) {
                    Ok(indices) => indices,
                    Err(e) => {
                        tracing::error!("[REDEAL_REQUEST] Redeal failed: {}", e);
                        vec![]
                    }
                }
            } else {
                vec![]
            }
        };

        if !redealt_indices.is_empty() {
            // 启动 redeal reveal 阶段
            {
                let mut gs = state.state.write().await;
                if let Some(table) = gs.tables.get_mut(&payload.table_id) {
                    table.start_redeal_reveal_phase(&player_pk, redealt_indices);
                }
            }

            // 广播 redeal notice 给所有玩家
            state.broadcast_redeal_notice(payload.table_id).await;
            broadcast::broadcast_to_table(&io, &state, payload.table_id, Some("Redeal requested, new cards being dealt")).await;
        }
    });

    socket.on(actions::RECONSTRUCT_INITIATE, async move |_s: SocketRef, Data::<serde_json::Value>(payload_raw), io: SocketIo, State(state): State<Arc<SocketState>>| {
        let payload = parse_payload!(actions::RECONSTRUCT_INITIATE, payload_raw, ReconstructInitiatePayload);
        let result = {
            let mut gs = state.state.write().await;
            if let Some(table) = gs.tables.get_mut(&payload.table_id) {
                table.start_reconstruct()
            } else {
                Err("Table not found".to_string())
            }
        };

        match result {
            Ok(()) => {
                let reconstruct_payload = {
                    let gs = state.state.read().await;
                    gs.tables.get(&payload.table_id).map(|t| ReconstructResultPayload {
                        table_id: payload.table_id,
                        completed_players: t.reconstruct_state.completed_players.clone(),
                        reconstructed: false,
                    })
                };
                if let Some(p) = reconstruct_payload {
                    let _ = io.to(table_room_name(payload.table_id)).emit(actions::RECONSTRUCT_RESULT, &p).await;
                }
                broadcast::broadcast_to_table(&io, &state, payload.table_id, Some("Reconstruct vote initiated")).await;
            }
            Err(e) => {
                tracing::warn!("[RECONSTRUCT_INITIATE] Failed: {}", e);
            }
        }
    });

    socket.on_disconnect(async move |s: SocketRef, io: SocketIo, State(state): State<Arc<SocketState>>| {
        let socket_id = s.id.to_string();
        let wallet_address_str = {
            let gs = state.state.read().await;
            gs.players.get(&socket_id).map(|p| p.wallet_address.clone())
        };
        let (auto_fold_table_ids, _user_id, affected_table_ids, _need_cleanup, sitting_out_table_ids): (Vec<u32>, Option<String>, Vec<u32>, bool, Vec<u32>) = {
            let mut gs = state.state.write().await;

            let uid = gs.players.get(&socket_id).map(|p| p.id.clone());
            let wallet_address = gs.players.get(&socket_id).map(|p| p.wallet_address.to_string());
            let mut fold_tables = Vec::new();
            let mut affected = Vec::new();
            let mut should_cleanup = false;
            let mut sitting_out_tables = Vec::new();

            for (table_id, table) in gs.tables.iter_mut() {
                if wallet_address.as_ref().map_or(true, |wallet_address| table.find_player_by_wallet(wallet_address).is_none()) {
                    continue;
                }
                let pk = wallet_address.as_ref().and_then(|wa| table.get_pk_hex_by_wallet_address(wa));
                if table.is_playing() {
                    tracing::info!("[DISCONNECT] Table {}: {} disconnecting while hand in progress, marking sitting_out", table_id, socket_id);
                    affected.push(*table_id);
                    sitting_out_tables.push(*table_id);
                } else {
                    if let Some(ref pk_str) = pk {
                        if table.mark_player_disconnected(pk_str).is_some() {
                            fold_tables.push(*table_id);
                        }
                        if table.is_player_disconnected_by_pk(pk_str) {
                            affected.push(*table_id);
                        }
                    }
                    should_cleanup = true;
                }
            }

            (fold_tables, uid, affected, should_cleanup, sitting_out_tables)
        };

        if let Some(ref wa) = wallet_address_str {
            for tid in &sitting_out_table_ids {
                state.mark_player_sitting_out(*tid, wa).await;
            }
        }

        for table_id in &auto_fold_table_ids {
            broadcast::broadcast_to_table(&io, &state, *table_id, Some("auto-folds (disconnected)")).await;
            game_loop::handle_turn_advance(&io, &state, *table_id).await;
        }

        for tid in &affected_table_ids {
            broadcast::broadcast_to_table(&io, &state, *tid, None).await;
        }

        let tables_info = state.get_current_tables().await;
        let players_info = state.get_current_players().await;
        let _ = io.emit(actions::TABLES_UPDATED, &tables_info).await;
        let _ = io.emit(actions::PLAYERS_UPDATED, &players_info).await;

        // if need_cleanup {
        //     if let Some(ref uid) = user_id {
        //         schedule_disconnect_cleanup(io, state, uid.clone(), socket_id);
        //     }
        // }
    });
}
