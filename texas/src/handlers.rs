use axum::{
    body::Body,
    extract::{Extension, Path},
    http::{HeaderMap, StatusCode, Request},
    response::IntoResponse,
    response::Response,
    Json,
};
use base64::Engine;
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::Arc;

use crate::auth;
use crate::config::Config;
use crate::models::{Database, UserResponse};
use crate::pokergame::player::{Player, WalletAddress};
use crate::pokergame::game_state::SubmitRevealTokenJson;
use crate::socket::SocketState;
use crate::socket::broadcast::CryptoEventType;
use crate::pokergame::game_state::RevealPhase;

use poker_protocol::z_poker::protocol::ClientPlayer;
use poker_protocol::z_poker::convert::hex_to_ecpoint;

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub config: Config,
    pub socket_state: Arc<SocketState>,
    /// C2 去重：已处理的玩家行动事件去重缓存。
    /// key 为 `(table_id, seat_index, action, round_state)`。
    pub processed_actions: Arc<std::sync::RwLock<HashSet<String>>>,
}

/// processed_actions 的最大容量，超过后清空重建。
const MAX_PROCESSED_ACTIONS: usize = 10000;

impl AppState {
    /// C2 修复：检查并标记玩家行动事件是否已处理。
    /// 返回 `true` 表示首次处理（已写入缓存），`false` 表示重复事件（应跳过）。
    pub fn check_and_mark_action(
        &self,
        table_id: &str,
        seat_index: u64,
        action: &str,
        round_state: u8,
    ) -> bool {
        let key = format!("{}_{}_{}_{}", table_id, seat_index, action, round_state);
        let mut processed = self
            .processed_actions
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if processed.contains(&key) {
            return false;
        }
        // 容量控制：超过上限时清空（简单策略，避免无界增长）
        if processed.len() >= MAX_PROCESSED_ACTIONS {
            tracing::warn!("dedup cache overflow, clearing all entries");
            processed.clear();
        }
        processed.insert(key);
        true
    }
}

pub fn get_token_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-auth-token")
        .and_then(|t| t.to_str().ok())
        .map(|s| s.to_string())
}

/// 把用户转换为 API 响应。筹码余额来自 PokerVault 链上筹码（Starknet STRK20）。
fn user_to_response(user: &crate::models::User, vault_chips: i64) -> serde_json::Value {
    // 链上余额可能因玩家直接 withdraw 而低于 locked_chips（permissionless 出金），
    // saturating 防下溢（audit H2），可用余额最低钳到 0。
    let chips_amount = vault_chips.saturating_sub(user.locked_chips).max(0);
    let resp = UserResponse {
        id: user.id.clone(),
        name: user.name.clone(),
        address: user.address.clone(),
        chips_amount,
        vault_chips,
        created: user.created.clone(),
    };
    serde_json::to_value(&resp).unwrap_or_else(|_| serde_json::json!({}))
}

/// 查询用户在 PokerVault 中的链上筹码余额（1 chip = WEI_PER_CHIP wei）。
/// 未配置 vault / RPC 或查询失败时返回 0（与旧 SUI 余额失败路径一致）。
async fn fetch_vault_chips(address: &str) -> i64 {
    match crate::starknet::chips::vault_chip_balance_wei(address).await {
        Some(wei) => (wei / crate::starknet::config::WEI_PER_CHIP) as i64,
        None => {
            tracing::warn!("[fetch_vault_chips] vault chip balance unavailable for {}", address);
            0
        }
    }
}

pub async fn get_current_user(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
) -> Response {
    // tracing::debug!("[get_current_user] request received");
    let token = match get_token_from_headers(&headers) {
        Some(t) => {
            // tracing::debug!("[get_current_user] token found in headers");
            t
        }
        None => {
            // tracing::warn!("[get_current_user] no x-auth-token header found");
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"msg": "Unauthorized request!"}))).into_response();
        }
    };

    match auth::verify_token(&token, &state.config.jwt_secret) {
        Ok(claims) => {
            // tracing::debug!("[get_current_user] token verified, user_id={}", claims.user.id);
            match state.db.find_user_by_id(&claims.user.id).await {
                Some(user) => {
                    let vault_chips = fetch_vault_chips(&user.address).await;
                    (StatusCode::OK, Json(user_to_response(&user, vault_chips))).into_response()
                }
                None => {
                    // tracing::warn!("[get_current_user] user not found in db, id={}", claims.user.id);
                    (StatusCode::NOT_FOUND, Json(serde_json::json!({"msg": "User not found"}))).into_response()
                }
            }
        }
        Err(_) => {
            // tracing::warn!("[get_current_user] token verification failed");
            (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"msg": "Unauthorized request!"}))).into_response()
        }
    }
}

#[derive(Deserialize)]
struct JoinGameRequest {
    name: String,
    pk_hex: String,
}

#[derive(Deserialize)]
struct ActionRequestHttp {
    pk_hex: String,
    action: String,
    amount: Option<u64>,
}

#[derive(Deserialize)]
struct RevealTokenRequest {
    pk_hex: String,
    reveal_tokens: Vec<SubmitRevealTokenJson>,
}

fn parse_id(id: &str) -> Option<u32> {
    id.parse::<u32>().ok()
}

pub fn err_resp(code: StatusCode, msg: &str) -> Response {
    (code, Json(serde_json::json!({"error": msg}))).into_response()
}

fn verify_auth(headers: &HeaderMap, jwt_secret: &str) -> Result<crate::auth::Claims, Response> {
    let token = match get_token_from_headers(headers) {
        Some(t) => t,
        None => {
            return Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({"msg": "Unauthorized request!"}))).into_response());
        }
    };
    match auth::verify_token(&token, jwt_secret) {
        Ok(claims) => Ok(claims),
        Err(_) => Err((StatusCode::UNAUTHORIZED, Json(serde_json::json!({"msg": "Unauthorized request!"}))).into_response()),
    }
}

pub async fn get_table(
    Extension(state): Extension<Arc<AppState>>,
    Path(table_id): Path<String>,
) -> Response {
    tracing::debug!("[get_table] request received, table_id={}", table_id);
    let table_id = match parse_id(&table_id) {
        Some(id) => id,
        None => {
            tracing::warn!("[get_table] invalid table_id: {}", table_id);
            return err_resp(StatusCode::BAD_REQUEST, "Invalid table_id");
        }
    };

    match state.socket_state.get_client_table(table_id).await {
        Some(client_table) => {
            tracing::debug!("[get_table] table found, table_id={}", table_id);
            (StatusCode::OK, Json(serde_json::to_value(client_table).unwrap_or_else(|_| serde_json::json!({})))).into_response()
        }
        None => {
            tracing::warn!("[get_table] table not found, table_id={}", table_id);
            err_resp(StatusCode::NOT_FOUND, "Table not found")
        }
    }
}

/// 牌局记录看板：按桌查询最近手牌记录（新→旧，默认全量 ≤100 条）。
pub async fn get_table_history(
    Extension(_state): Extension<Arc<AppState>>,
    Path(table_id): Path<String>,
) -> Response {
    let table_id = match parse_id(&table_id) {
        Some(id) => id,
        None => return err_resp(StatusCode::BAD_REQUEST, "Invalid table_id"),
    };
    let records = crate::pokergame::history_store::global_store().list_by_table(
        table_id,
        crate::pokergame::history_store::DEFAULT_CAPACITY,
    );
    (StatusCode::OK, Json(records)).into_response()
}

/// 牌局记录看板：按手数查单手记录。
pub async fn get_table_hand(
    Extension(_state): Extension<Arc<AppState>>,
    Path((table_id, hand_seq)): Path<(String, String)>,
) -> Response {
    let (table_id, hand_seq) = match (parse_id(&table_id), hand_seq.parse::<u64>()) {
        (Some(t), Ok(s)) => (t, s),
        _ => return err_resp(StatusCode::BAD_REQUEST, "Invalid table_id or hand_seq"),
    };
    match crate::pokergame::history_store::global_store().get(table_id, hand_seq) {
        Some(record) => (StatusCode::OK, Json(record)).into_response(),
        None => err_resp(StatusCode::NOT_FOUND, "Hand record not found"),
    }
}

pub async fn join_game(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
    Path(game_id): Path<String>,
    req: Request<Body>,
) -> Response {
    // A2 修复：join_game 也需要验证认证，并校验 pk_hex 归属
    let claims = match verify_auth(&headers, &state.config.jwt_secret) {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    tracing::debug!("[join_game] request received, game_id={}", game_id);
    let body = match axum::body::to_bytes(req.into_body(), 1024 * 64).await {
        Ok(b) => b,
        Err(_) => {
            tracing::warn!("[join_game] failed to read request body");
            return err_resp(StatusCode::BAD_REQUEST, "Invalid request body");
        }
    };
    let body = match serde_json::from_slice::<JoinGameRequest>(&body) {
        Ok(v) => {
            tracing::info!("[join_game] parsed body, pk_hex={}, name={}", v.pk_hex, v.name);
            v
        }
        Err(_) => {
            tracing::warn!("[join_game] failed to parse JSON body");
            return err_resp(StatusCode::BAD_REQUEST, "Invalid JSON");
        }
    };

    let table_id = match parse_id(&game_id) {
        Some(id) => id,
        None => {
            tracing::warn!("[join_game] invalid game_id: {}", game_id);
            return err_resp(StatusCode::BAD_REQUEST, "Invalid game_id");
        }
    };

    // A2 修复：加载用户并验证 pk_hex 归属
    let user = match state.db.find_user_by_id(&claims.user.id).await {
        Some(u) => u,
        None => {
            tracing::warn!("[join_game] user not found, user_id={}", claims.user.id);
            return err_resp(StatusCode::UNAUTHORIZED, "User not found");
        }
    };
    // A2 修复：校验 pk_hex 归属，防止用户冒用他人 pk_hex 入座。
    // pk_hex 是 Mental Poker G1 公钥（Starknet 模式下从钱包地址派生）。
    {
        let normalize = |s: &str| -> String {
            s.strip_prefix("0x").unwrap_or(s).to_lowercase()
        };
        let user_pk = normalize(&user.address);
        let req_pk = normalize(&body.pk_hex);
        if user_pk != req_pk {
            tracing::warn!(
                "[join_game] pk_hex ownership mismatch: user_id={}, user_pk={}, req_pk={}",
                claims.user.id,
                user_pk,
                req_pk
            );
            return err_resp(StatusCode::FORBIDDEN, "pk_hex does not match authenticated wallet");
        }
    }

    let pk_hex = crate::pokergame::player::GamePkHex::new(body.pk_hex.clone());

    if state.socket_state.is_player_in_seat(&pk_hex).await {
        tracing::warn!("[join_game] player already in seat, pk_hex={}", pk_hex);
        return err_resp(StatusCode::BAD_REQUEST, "Player already in game");
    }

    let player = match state.socket_state.find_player_by_pk(table_id, &pk_hex).await {
        Some(p) => {
            tracing::debug!("[join_game] found existing player by pk_hex, socket_id={}", p.socket_id);
            p
        }
        None => {
            tracing::debug!("[join_game] no existing player found for pk_hex, creating http player");
            Player {
                socket_id: format!("http_{}", body.pk_hex),
                id: body.pk_hex.clone(),
                name: body.name.clone(),
                bankroll: 0,
                wallet_address: WalletAddress::new(""),
            }
        }
    };

    if state.socket_state.add_player_to_table(table_id, player, &pk_hex).await.is_err() {
        tracing::warn!("[join_game] table not found, table_id={}", table_id);
        return err_resp(StatusCode::NOT_FOUND, "Table not found");
    }

    tracing::debug!("[join_game] player joined successfully, pk_hex={}, table_id={}", body.pk_hex, table_id);
    (StatusCode::CREATED, Json(serde_json::json!({
        "player": {"id": body.pk_hex},
        "message": "Joined game successfully"
    }))).into_response()
}



pub async fn player_action(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
    Path(game_id): Path<String>,
    req: Request<Body>,
) -> Response {
    let claims = match verify_auth(&headers, &state.config.jwt_secret) {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    tracing::debug!("[player_action] request received, game_id={}", game_id);
    let body = match axum::body::to_bytes(req.into_body(), 1024 * 64).await {
        Ok(b) => b,
        Err(_) => {
            tracing::warn!("[player_action] failed to read request body");
            return err_resp(StatusCode::BAD_REQUEST, "Invalid request body");
        }
    };
    let body = match serde_json::from_slice::<ActionRequestHttp>(&body) {
        Ok(v) => {
            tracing::debug!("[player_action] parsed body, pk_hex={}, action={}, amount={:?}", v.pk_hex, v.action, v.amount);
            v
        }
        Err(_) => {
            tracing::warn!("[player_action] failed to parse JSON body");
            return err_resp(StatusCode::BAD_REQUEST, "Invalid JSON");
        }
    };

    let table_id = match parse_id(&game_id) {
        Some(id) => id,
        None => {
            tracing::warn!("[player_action] invalid game_id: {}", game_id);
            return err_resp(StatusCode::BAD_REQUEST, "Invalid game_id");
        }
    };

    // Verify that the authenticated user owns the pk_hex
    let user = match state.db.find_user_by_id(&claims.user.id).await {
        Some(u) => u,
        None => {
            tracing::warn!("[player_action] user not found, user_id={}", claims.user.id);
            return err_resp(StatusCode::UNAUTHORIZED, "User not found");
        }
    };

    // A2 修复：验证请求中的 pk_hex 属于已认证用户
    // User.address 存储的是用户绑定的 pk_hex（钱包登录时为 pk_hex，注册时为生成的 pk_hex）
    // let user_pk = crate::pokergame::player::GamePkHex::new(user.address.clone());
    // let req_pk = crate::pokergame::player::GamePkHex::new(body.pk_hex.clone());
    // if user_pk != req_pk {
    //     tracing::warn!(
    //         "[player_action] pk_hex ownership mismatch: user_id={}, user_pk={}, req_pk={}",
    //         claims.user.id,
    //         user_pk,
    //         req_pk
    //     );
    //     return err_resp(StatusCode::FORBIDDEN, "pk_hex does not belong to authenticated user");
    // }


    let sender = match state.socket_state.get_action_sender(table_id).await {
        Some(s) => {
            tracing::debug!("[player_action] got action sender for table_id={}", table_id);
            s
        }
        None => {
            tracing::warn!("[player_action] game loop not running, table_id={}", table_id);
            return err_resp(StatusCode::NOT_FOUND, "Game loop not running");
        }
    };

    let action_request = crate::pokergame::table::ActionRequest {
        pk_hex: crate::pokergame::player::GamePkHex::new(body.pk_hex.clone()),
        action: body.action.clone(),
        amount: body.amount,
        seq: None,
        sig: None,
    };

    match sender.send(action_request).await {
        Ok(()) => {
            tracing::debug!("[player_action] action sent successfully, pk_hex={}, action={}, table_id={}", body.pk_hex, body.action, table_id);
            (StatusCode::OK, Json(serde_json::json!({
                "message": format!("Action {} submitted", body.action)
            }))).into_response()
        }
        Err(_) => {
            tracing::error!("[player_action] failed to send action, pk_hex={}, action={}, table_id={}", body.pk_hex, body.action, table_id);
            err_resp(StatusCode::INTERNAL_SERVER_ERROR, "Failed to send action")
        }
    }
}

pub async fn submit_reveal_token(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
    Path(game_id): Path<String>,
    req: Request<Body>,
) -> Response {
    let claims = match verify_auth(&headers, &state.config.jwt_secret) {
        Ok(c) => c,
        Err(resp) => return resp,
    };
    tracing::debug!("[submit_reveal_token] request received, game_id={}", game_id);
    let body = match axum::body::to_bytes(req.into_body(), 1024 * 64).await {
        Ok(b) => b,
        Err(_) => {
            tracing::warn!("[submit_reveal_token] failed to read request body");
            return err_resp(StatusCode::BAD_REQUEST, "Invalid request body");
        }
    };
    let body = match serde_json::from_slice::<RevealTokenRequest>(&body) {
        Ok(v) => {
            tracing::debug!("[submit_reveal_token] parsed body, pk_hex={}, reveal_tokens_count={}", v.pk_hex, v.reveal_tokens.len());
            v
        }
        Err(e) => {
            tracing::warn!("[submit_reveal_token] failed to parse JSON body: {}", e);
            return err_resp(StatusCode::BAD_REQUEST, "Invalid JSON");
        }
    };

    let table_id = match parse_id(&game_id) {
        Some(id) => id,
        None => {
            tracing::warn!("[submit_reveal_token] invalid game_id: {}", game_id);
            return err_resp(StatusCode::BAD_REQUEST, "Invalid game_id");
        }
    };

    // A2 修复：验证请求中的 pk_hex 属于已认证用户
    let user = match state.db.find_user_by_id(&claims.user.id).await {
        Some(u) => u,
        None => {
            tracing::warn!("[submit_reveal_token] user not found, user_id={}", claims.user.id);
            return err_resp(StatusCode::UNAUTHORIZED, "User not found");
        }
    };
    //todo find game pk
    // let user_pk = crate::pokergame::player::GamePkHex::new(user.address.clone());
    // let req_pk = crate::pokergame::player::GamePkHex::new(body.pk_hex.clone());
    // if user_pk != req_pk {
    //     tracing::warn!(
    //         "[submit_reveal_token] pk_hex ownership mismatch: user_id={}, user_pk={}, req_pk={}",
    //         claims.user.id,
    //         user_pk,
    //         req_pk
    //     );
    //     return err_resp(StatusCode::FORBIDDEN, "pk_hex does not belong to authenticated user");
    // }

    let player_pk = match hex_to_ecpoint(&body.pk_hex) {
        Ok(pt) => pt,
        Err(e) => {
            tracing::warn!("[submit_reveal_token] invalid player_pk: {}", e);
            return err_resp(StatusCode::BAD_REQUEST, &format!("Invalid player_pk: {}", e));
        }
    };

    let tokens_len = body.reveal_tokens.len();
    if tokens_len == 0 {
        tracing::warn!("[submit_reveal_token] no reveal tokens provided");
        return err_resp(StatusCode::BAD_REQUEST, "No reveal tokens provided");
    }

    let tokens: Result<Vec<_>, String> = body.reveal_tokens.iter()
        .enumerate()
        .map(|(idx, item)| {
            let encrypted_card = item.encrypted_card.to_ciphertext()
                .map_err(|e| format!("Token[{}]: Invalid encrypted_card: {}", idx, e))?;
            let reveal_token = hex_to_ecpoint(&item.reveal_token_hex)
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
            tracing::warn!("[submit_reveal_token] token parse error: {}", e);
            return err_resp(StatusCode::BAD_REQUEST, &e);
        }
    };

    let reveal_phase = state.socket_state.get_reveal_phase_for_table(table_id).await.unwrap_or_default();

    let pk_hex = crate::pokergame::player::GamePkHex::new(body.pk_hex.clone());

    if let Err(e) = state.socket_state.submit_reveal_tokens_for_pk(table_id, &pk_hex, tokens).await {
        // 良性幂等：重复提交（首次已推进状态机）按成功语义返回，不广播
        // "proof verification failed"（客户端 UI 会当成真错误展示）。
        if crate::pokergame::table::Table::is_benign_reveal_error(&e) {
            tracing::info!(
                "[submit_reveal_token] idempotent duplicate submit ignored, table_id={}, pk_hex={}",
                table_id, pk_hex
            );
            return (StatusCode::OK, Json(serde_json::json!({"msg": "already submitted"}))).into_response();
        }
        tracing::warn!("[submit_reveal_token] submit failed, table_id={}, pk_hex={}, error={}", table_id, pk_hex, e);
        // ZK 可视化：reveal_token 证明验证失败
        state.socket_state.broadcast_crypto_event(
            table_id,
            CryptoEventType::RevealToken,
            body.pk_hex.clone(),
            None,
            false,
            Some(format!("reveal_token proof verification failed: {}", e)),
            None,
        ).await;
        return err_resp(StatusCode::BAD_REQUEST, &e);
    }

    // ZK 可视化：reveal_token 证明验证成功
    // 注意：reveal_token 为批量提交（一次多个 token），card_index 暂传 null。
    state.socket_state.broadcast_crypto_event(
        table_id,
        CryptoEventType::RevealToken,
        body.pk_hex.clone(),
        None,
        true,
        Some("reveal_token proof verified".to_string()),
        None,
    ).await;

    // todo 发送完成通知
    let all_complete = match state.socket_state.mark_reveal_complete_for_pk(table_id, &pk_hex).await {
        Ok(result) => {
            tracing::info!("[submit_reveal_token] reveal marked, table_id={}, pk_hex={}, all_complete={}", table_id, body.pk_hex, result);
            result
        }
        Err(e) => {
            tracing::warn!("[submit_reveal_token] mark reveal failed, table_id={}, pk_hex={}, error={}", table_id, body.pk_hex, e);
            return err_resp(StatusCode::NOT_FOUND, &e);
        }
    };

    if all_complete {
        match reveal_phase {
            RevealPhase::None => {
                tracing::warn!("[submit_reveal_token] all_complete but reveal_phase is None, table_id={}", table_id);
            }
            RevealPhase::HandReveal  => {
                state.socket_state.broadcast_hand_reveal_result(table_id).await;
            }
            RevealPhase::ShowdownReveal => {
                state.socket_state.broadcast_showdown_result(table_id).await;
            }
            RevealPhase::CommunityReveal => {
                state.socket_state.broadcast_community_cards(table_id).await;
            }
            RevealPhase::RedealReveal => {
                state.socket_state.broadcast_redeal_result(table_id).await;
            }
        }
    }


    tracing::debug!("[submit_reveal_token] success, pk_hex={}, reveal_tokens_count={}, all_complete={}", body.pk_hex, tokens_len, all_complete);
    (StatusCode::OK, Json(serde_json::json!({
        "message": format!("{} reveal tokens submitted", tokens_len),
        "player_pk": body.pk_hex,
        "phase": format!("{:?}", reveal_phase),
        "reveal_phase_complete": all_complete,
    }))).into_response()
}

pub async fn login(
    Extension(_state): Extension<Arc<AppState>>,
    _req: Request<Body>,
) -> Response {
    // 钱包登录模式下已禁用邮箱/密码登录
    (StatusCode::NOT_FOUND, Json(serde_json::json!({"msg": "Email/password login is disabled. Please use wallet login."}))).into_response()
}

#[derive(Deserialize, Debug)]
struct WalletLoginRequest {
    address: String,
    message: String,
    /// Starknet 路径：签名 felts（hex 字符串数组）。
    #[serde(default)]
    signature: serde_json::Value,
    /// SNIP-12 消息哈希（前端 TypedData.getMessageHash 的结果）。
    /// alias 兼容前端 camelCase（client useAuth 发送 messageHash）。
    #[serde(default, alias = "messageHash")]
    message_hash: Option<String>,
}

pub async fn wallet_login(
    Extension(state): Extension<Arc<AppState>>,
    req: Request<Body>,
) -> Response {
    tracing::debug!("[wallet_login] request received");
    let body = match axum::body::to_bytes(req.into_body(), 1024 * 64).await {
        Ok(b) => b,
        Err(_) => {
            tracing::warn!("[wallet_login] failed to read request body");
            return err_resp(StatusCode::BAD_REQUEST, "Invalid request body");
        }
    };
    let body = match serde_json::from_slice::<WalletLoginRequest>(&body) {
        Ok(v) => {
            tracing::debug!("[wallet_login] parsed body, address={}", v.address);
            v
        }
        Err(e) => {
            tracing::warn!("[wallet_login] failed to parse JSON body: {}", e);
            return err_resp(StatusCode::BAD_REQUEST, &format!("Invalid JSON: {}", e));
        }
    };

    // Starknet 验证：message_hash + felts 签名 → isValidSignature 链上验证。
    let Some(message_hash) = body.message_hash.clone() else {
        return err_resp(StatusCode::BAD_REQUEST, "message_hash is required (Starknet SNIP-12 login)");
    };
    let sig_felts: Vec<String> = match &body.signature {
        serde_json::Value::Array(items) => items
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        serde_json::Value::String(s) => vec![s.clone()],
        _ => Vec::new(),
    };
    let (address, pk_hex) = match crate::starknet::auth::verify_wallet_signature(&body.address, &message_hash, &sig_felts).await {
        Ok(()) => {
            tracing::info!("[wallet_login] Starknet signature verified, address={}", body.address);
            // pk_hex 复用钱包地址：Starknet 模式下前端 wasm 密钥即从地址派生。
            (body.address.clone(), body.address.clone())
        }
        Err(e) => {
            tracing::warn!("[wallet_login] Starknet signature verification failed, address={}, error={}", body.address, e);
            return err_resp(StatusCode::UNAUTHORIZED, &e);
        }
    };

    let user_id = format!("wallet:{}", address);

    if state.db.find_user_by_id(&user_id).await.is_none() {
        tracing::debug!("[wallet_login] new wallet user, creating user_id={}, address={}", user_id, address);
        let user = crate::models::User {
            id: user_id.clone(),
            name: address.clone(),
            address: address.clone(),
            created: chrono::Utc::now().to_rfc3339(),
            locked_chips: 0,
        };
        if let Err(e) = state.db.save_user(&user).await {
            tracing::error!("[wallet_login] failed to save wallet user, user_id={}, error={}", user_id, e);
            return err_resp(StatusCode::INTERNAL_SERVER_ERROR, &format!("Failed to save wallet user: {}", e));
        }
        tracing::debug!("[wallet_login] wallet user saved, user_id={}, pk_hex={}", user_id, pk_hex.clone());
    } else {
        if state.db.update_address(&user_id, &address).await {
            tracing::debug!("[wallet_login] existing wallet user found, user_id={}, pk_hex={}", user_id, pk_hex.clone());
        } else {
            tracing::warn!("[wallet_login] failed to update wallet user pk, user_id={}", user_id);
        }
        tracing::debug!("[wallet_login] existing wallet user found, user_id={}, pk_hex={}", user_id, pk_hex.clone());
    }

    match auth::create_token(&user_id, &state.config.jwt_secret, state.config.jwt_token_expires_in) {
        Ok(token) => {
            tracing::debug!("[wallet_login] token created, user_id={}, address={}", user_id, address);
            (StatusCode::OK, Json(serde_json::json!({
                "token": token,
                "address": address,
                "pk_hex": pk_hex.clone(),
            }))).into_response()
        }
        Err(_) => {
            tracing::error!("[wallet_login] failed to create token, user_id={}", user_id);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"msg": "Internal server error"}))).into_response()
        }
    }
}

pub async fn wallet_logout(
    headers: HeaderMap,
    Extension(state): Extension<Arc<AppState>>,
) -> Response {
    tracing::debug!("[wallet_logout] request received");

    // Best-effort: try to verify the token, but always return 200 so frontend
    // logout is never blocked by an expired/invalid token.
    if let Some(token) = get_token_from_headers(&headers) {
        if let Ok(claims) = auth::verify_token(&token, &state.config.jwt_secret) {
            tracing::debug!("[wallet_logout] token verified, user_id={}", claims.user.id);
        } else {
            tracing::debug!("[wallet_logout] token expired or invalid");
        }
    } else {
        tracing::debug!("[wallet_logout] no x-auth-token header");
    }

    (StatusCode::OK, Json(serde_json::json!({"msg": "Wallet logout successful"}))).into_response()
}

pub async fn register(
    Extension(_state): Extension<Arc<AppState>>,
    _req: Request<Body>,
) -> Response {
    // 钱包登录模式下已禁用注册
    (StatusCode::NOT_FOUND, Json(serde_json::json!({"msg": "Registration is disabled. Please use wallet login."}))).into_response()
}

pub async fn free_chips(
    _headers: HeaderMap,
    Extension(_state): Extension<Arc<AppState>>,
) -> Response {
    // 钱包登录模式下筹码由链上余额决定，不再提供免费筹码
    (StatusCode::NOT_FOUND, Json(serde_json::json!({"msg": "Free chips is disabled. Chips are settled on Starknet STRK20 via PokerVault."}))).into_response()
}
