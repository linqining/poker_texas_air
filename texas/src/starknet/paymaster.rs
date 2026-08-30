//! Plan C 执行层加固 —— paymaster 中继（API key 只留服务端）。
//!
//! 客户端用 starknet.js 的 `PaymasterRpc` 把本端点当作 paymaster JSON-RPC
//! 服务：`paymaster_*` 请求被原样透传给上游 paymaster（如 AVNU），转发时
//! 由服务端注入 `x-api-key`。上游以自己的账户合约提交交易（OutsideExecution），
//! 链上交易的发送者不是用户地址 —— 链下执行方无法按用户身份定向审查。
//!
//! 隐私边界：签名与证明全部留在客户端，本模块只见 calls 与 typed data；
//! API key 永不出现在前端。
//!
//! 未配置（STARKNET_PAYMASTER_URL 为空）时 status 返回 configured=false、
//! 中继返回 503 JSON-RPC 错误，客户端自动回退 session key 直签路径。

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use serde_json::{json, Value};
use std::sync::OnceLock;
use std::time::Duration;

/// 上游请求超时。paymaster_buildTransaction 含费用估算，给足余量。
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(30);

pub struct PaymasterConfig {
    /// 上游 paymaster JSON-RPC 端点（如 https://api.avnu.fi/paymaster）。
    pub url: String,
    /// 上游 API key，经 x-api-key 头注入。可留空（上游免鉴权时）。
    pub api_key: String,
}

static PAYMASTER: OnceLock<Option<PaymasterConfig>> = OnceLock::new();

/// main.rs 启动时调用一次；未配置则进入"未启用"态（中继 503 + status=false）。
pub fn init_from_env() {
    let cfg = match std::env::var("STARKNET_PAYMASTER_URL") {
        Ok(url) if !url.trim().is_empty() => Some(PaymasterConfig {
            url: url.trim().to_string(),
            api_key: std::env::var("STARKNET_PAYMASTER_API_KEY").unwrap_or_default(),
        }),
        _ => None,
    };
    match &cfg {
        Some(c) => tracing::info!("[starknet-paymaster] relay enabled → {}", c.url),
        None => tracing::info!(
            "[starknet-paymaster] not configured (STARKNET_PAYMASTER_URL empty); \
             clients fall back to session-key direct submission"
        ),
    }
    let _ = PAYMASTER.set(cfg);
}

fn config() -> Option<&'static PaymasterConfig> {
    PAYMASTER.get().and_then(|c| c.as_ref())
}

#[derive(Serialize)]
pub struct StatusResponse {
    pub configured: bool,
}

/// GET /api/starknet/paymaster/status —— 客户端能力探测（不回显 url/key）。
pub async fn status() -> Json<StatusResponse> {
    Json(StatusResponse {
        configured: config().is_some(),
    })
}

/// JSON-RPC 错误信封，与 starknet.js PaymasterRpc 的错误解析预期一致。
fn rpc_error(id: Value, code: i64, message: &str) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": code, "message": message }
        })),
    )
        .into_response()
}

/// POST /api/starknet/paymaster —— `paymaster_*` JSON-RPC 透明中继。
///
/// 只透传 `paymaster_` 前缀方法（isAvailable / buildTransaction /
/// executeTransaction / getSupportedTokens），避免成为任意 RPC 代理。
pub async fn relay(Json(body): Json<Value>) -> Response {
    let id = body.get("id").cloned().unwrap_or(Value::Null);

    let Some(cfg) = config() else {
        return rpc_error(id, -32601, "paymaster relay not configured");
    };
    let method = body.get("method").and_then(|m| m.as_str()).unwrap_or("");
    if !method.starts_with("paymaster_") {
        return rpc_error(id, -32601, &format!("method {method:?} not allowed"));
    }

    let client = match reqwest::Client::builder().timeout(UPSTREAM_TIMEOUT).build() {
        Ok(c) => c,
        Err(e) => return rpc_error(id, -32603, &format!("http client: {e}")),
    };
    let mut req = client
        .post(&cfg.url)
        .header("Content-Type", "application/json");
    if !cfg.api_key.is_empty() {
        req = req.header("x-api-key", &cfg.api_key);
    }

    let resp = match req.json(&body).send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("[starknet-paymaster] upstream {} error: {e}", cfg.url);
            return rpc_error(id, -32603, "paymaster upstream unreachable");
        }
    };
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let body = resp.bytes().await.unwrap_or_default();
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|e| rpc_error(id, -32603, &format!("response build: {e}")))
}

// ============================================================
// Plan D P2.1：客户端 Hand-batch 认可注册端点（挂在 paymaster 模块的邻近路由）
// ============================================================

/// 客户端认可注册请求体（P2.1）。
#[derive(Debug, serde::Deserialize)]
pub struct EndorsementRegistration {
    pub wallet: String,
    pub hand_id: u32,
    pub pk_x_hex: String,
    pub pk_y_hex: String,
    pub r_x_hex: String,
    pub r_y_hex: String,
    pub s_hex: String,
}

/// POST /starknet/endorsement：玩家客户端提交其本地铸造的 hand-bound
/// 认可（STARK 曲线）。服务器仅做 on-curve/域校验并缓存，结算聚合时
/// 取用——私钥永不出客户端。
/// 生产加固 TODO：请求须附钱包签名（session key / typed-data）证明
/// wallet 归属；当前信任调用方声明的 wallet（与 WS 会话同源时安全）。
pub async fn register_endorsement(Json(body): Json<EndorsementRegistration>) -> Response {
    match super::dual_settle::register_client_endorsement(
        &body.wallet,
        body.hand_id,
        &body.pk_x_hex,
        &body.pk_y_hex,
        &body.r_x_hex,
        &body.r_y_hex,
        &body.s_hex,
    ) {
        Ok(()) => {
            tracing::info!(
                "[endorsement] registered client endorsement wallet={} hand={}",
                body.wallet,
                body.hand_id
            );
            Json(serde_json::json!({ "ok": true })).into_response()
        }
        Err(e) => (axum::http::StatusCode::BAD_REQUEST, e).into_response(),
    }
}
