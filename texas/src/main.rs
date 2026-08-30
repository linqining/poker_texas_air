mod config;
mod models;
mod auth;
mod handlers;
mod pokergame;
mod socket;
mod relayer;
mod starknet;
mod dev_bot;

use std::collections::HashMap;
use axum::Json;
use axum::response::IntoResponse;
use socketioxide::extract::State;
use std::sync::Arc;

use axum::{routing, Router};
use socket::SocketState;
use socketioxide::SocketIo;
use tower::ServiceBuilder;

use config::Config;
use handlers::AppState;
use models::Database;
use pokergame::table::Table;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    dotenv::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,texas=debug".into())
        )
        .with_target(true)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(true)
        .init();

    let config = Config::from_env();
    let port = config.port;

    // Starknet 链客户端（dev 模式下 RPC 为空也可启动，买入/结算校验自动放行）。
    let sn_config = starknet::StarknetConfig::from_env();
    if sn_config.rpc_enabled() {
        tracing::info!(
            "Starknet enabled: rpc={} settlement={} vault={}",
            sn_config.rpc_url,
            if sn_config.settlement_enabled() { "on" } else { "off" },
            if sn_config.vault_address.is_empty() { "not-configured" } else { "configured" }
        );
    } else {
        tracing::info!("Starknet dev mode: no STARKNET_RPC_URL, on-chain checks skipped");
    }
    starknet::init(sn_config);
    // Plan C：paymaster 中继（未配置时自动禁用，客户端回退直签）。
    starknet::paymaster::init_from_env();

    let db = Database::new();

    let mut initial_tables = HashMap::new();
    initial_tables.insert(1, Table::new(1, "Table 1".to_string(), 10000, config.max_players_per_table, config.default_chain_table_id.clone()));
    // initial_tables.insert(2, Table::new(2, "Table 2".to_string(), 20000, config.max_players_per_table, "".to_string()));
    // initial_tables.insert(3, Table::new(3, "Table 3".to_string(), 50000, config.max_players_per_table, "".to_string()));
    for table in initial_tables.values_mut() {
        table.start_shuffle();
    }

    let config_for_socket = config.clone();

    let socket_state = Arc::new(SocketState::new(db, initial_tables, config_for_socket));

    let (layer, io) = SocketIo::builder()
        .with_state(socket_state.clone())
        .build_layer();

    socket::set_socket_io(io.clone());
    socket_state.init_table_event_channels(io.clone()).await;
    socket::register_handlers(&io);

    let app_state = Arc::new(AppState {
        db: socket_state.db.clone(),
        config: config.clone(),
        socket_state: socket_state.clone(),
        processed_actions: Arc::new(std::sync::RwLock::new(std::collections::HashSet::new())),
    });

    let api_routes = Router::new()
        .route("/auth",routing::get(handlers::get_current_user))
        .route("/auth/wallet", routing::post(handlers::wallet_login))
        .route("/auth/wallet/logout", routing::post(handlers::wallet_logout))
        .route("/tables/:table_id", routing::get(handlers::get_table))
        .route("/games/:game_id/join", routing::post(handlers::join_game))
        .route("/games/:game_id/action", routing::post(handlers::player_action))
        .route("/games/:game_id/reveal-token", routing::post(handlers::submit_reveal_token))
        .route("/dev/bot", routing::post(dev_bot_start))
        // Plan C：paymaster 中继通道（提交者与用户解耦；API key 只在服务端）。
        .route("/starknet/paymaster", routing::post(starknet::paymaster::relay))
        .route(
            "/starknet/paymaster/status",
            routing::get(starknet::paymaster::status),
        )
        // Plan D P2.1：客户端 Hand-batch 认可注册（私钥不出客户端）。
        .route(
            "/starknet/endorsement",
            routing::post(starknet::paymaster::register_endorsement),
        );

    let app = Router::new()
        .nest("/api", api_routes)
        .route("/", routing::get(|| async { "Welcome to Secret Poker (Rust)!" }))
        // G17 TODO: 当前未实现 API 速率限制（rate limiting）。生产环境应引入
        // tower_governor 或类似中间件对 /api/* 路由（尤其是 /auth/*、/chips/free、
        // /sponsor/* 等敏感端点）添加 per-IP / per-user 限流，防止暴力破解与滥用。
        .layer(
            ServiceBuilder::new()
                .map_request(move |mut req: axum::http::Request<axum::body::Body>| {
                    let state = app_state.clone();
                    req.extensions_mut().insert(state);
                    req
                })
                .into_inner(),
        )
        .layer(layer)
        .layer(
            tower_http::cors::CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods([axum::http::Method::GET, axum::http::Method::POST, axum::http::Method::OPTIONS])
                .allow_headers([axum::http::header::CONTENT_TYPE, axum::http::header::HeaderName::from_static("x-auth-token")])
        )
        .layer(tower_http::trace::TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    tracing::info!("Secret Poker Server (Rust) starting on port {}", port);
    tracing::info!("Using in-memory user storage (MongoDB removed). 筹码余额由 Starknet STRK20 链上结算决定。");

    axum::serve(listener, app).await
}

/// dev: 启动进程内机器人玩家（本地联调用）
async fn dev_bot_start(
    state: axum::extract::Extension<Arc<AppState>>,
    body: axum::body::Body,
) -> axum::response::Response {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct BotReq { wallet: String, #[serde(default)] deposit_tx_hash: String, #[serde(default)] seat_id: u32 }
    let bytes = match axum::body::to_bytes(body, 4096).await { Ok(b) => b, Err(_) => return (axum::http::StatusCode::BAD_REQUEST, "bad body").into_response() };
    let Ok(req) = serde_json::from_slice::<BotReq>(&bytes) else {
        return (axum::http::StatusCode::BAD_REQUEST, "bad json").into_response()
    };
    let seat = if req.seat_id == 0 { 2 } else { req.seat_id };
    tokio::spawn(async move {
        if let Err(e) = dev_bot::start_bot(state.socket_state.clone(), req.wallet, req.deposit_tx_hash, seat).await {
            eprintln!("[bot] FAILED: {e}");
        }
    });
    axum::Json(serde_json::json!({"started": true})).into_response()
}
