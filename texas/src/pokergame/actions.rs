pub const FOLD: &str = "FOLD";
pub const CHECK: &str = "CHECK";
pub const CALL: &str = "CALL";
pub const RAISE: &str = "RAISE";
pub const WINNER: &str = "WINNER";
pub const FETCH_LOBBY_INFO: &str = "FETCH_LOBBY_INFO";
pub const RECEIVE_LOBBY_INFO: &str = "RECEIVE_LOBBY_INFO";
pub const PLAYERS_UPDATED: &str = "PLAYERS_UPDATED";
pub const JOIN_TABLE: &str = "JOIN_TABLE";
pub const TABLE_JOINED: &str = "TABLE_JOINED";
pub const LEAVE_TABLE: &str = "LEAVE_TABLE";
pub const TABLE_LEFT: &str = "TABLE_LEFT";
pub const LEAVE_DEFERRED: &str = "LEAVE_DEFERRED";
pub const TABLES_UPDATED: &str = "TABLES_UPDATED";
pub const TABLE_UPDATED: &str = "TABLE_UPDATED";
pub const TABLE_MESSAGE: &str = "TABLE_MESSAGE";
pub const REBUY: &str = "REBUY";
pub const SIT_DOWN: &str = "SIT_DOWN";
pub const SIT_DOWN_V2: &str = "SIT_DOWN_V2";
pub const STAND_UP: &str = "STAND_UP";
pub const SITTING_OUT: &str = "SITTING_OUT";
pub const SITTING_IN: &str = "SITTING_IN";
pub const SHUFFLE_SUBMIT: &str = "SHUFFLE_SUBMIT";
pub const SHUFFLE_NOTICE: &str = "SHUFFLE_NOTICE";
pub const REVEAL_SUBMIT: &str = "REVEAL_SUBMIT";
// Plan D P2.1：Hand-batch 认可收集（客户端本地铸造，服务器只收成品）
pub const ENDORSEMENT_REQUEST: &str = "ENDORSEMENT_REQUEST";
pub const ENDORSEMENT_SUBMIT: &str = "ENDORSEMENT_SUBMIT";
pub const REVEAL_NOTICE: &str = "REVEAL_NOTICE";
pub const HAND_REVEAL_RESULT: &str = "HAND_REVEAL_RESULT";
pub const COMMUNITY_REVEAL_RESULT: &str = "COMMUNITY_REVEAL_RESULT";
pub const RECONSTRUCT_INITIATE: &str = "RECONSTRUCT_INITIATE";
pub const RECONSTRUCT_VOTE: &str = "RECONSTRUCT_VOTE";
pub const RECONSTRUCT_RESULT: &str = "RECONSTRUCT_RESULT";
pub const RECONSTRUCT_NOTICE: &str = "RECONSTRUCT_NOTICE";
pub const RECONSTRUCT_SUBMIT: &str = "RECONSTRUCT_SUBMIT";
pub const REDEAL_NOTICE: &str = "REDEAL_NOTICE";
pub const REDEAL_RESULT: &str = "REDEAL_RESULT";
pub const REDEAL_REQUEST: &str = "REDEAL_REQUEST";
pub const CRYPTO_EVENT: &str = "crypto_event";
pub const PLAYER_UPDATE: &str = "player_update";


/// #16 动作签名（抗审查）：客户端以牌局身份 SK 对动作签名后随消息附上。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ActionSig {
    pub r_hex: String,
    pub s_hex: String,
}

/// #16/#17 动作日志条目：本手每条被接受（或超时代打）的动作。
/// `auto = true` 表示服务器按合法默认动作代打（超时路径），
/// `seq` 为服务器分配（accepted_seq + 1）。
#[derive(Debug, Clone, serde::Serialize)]
pub struct ActionLogEntry {
    pub seat: u32,
    pub seq: u64,
    pub action: String,
    pub amount: u64,
    pub auto: bool,
    pub sig_ok: bool,
}
pub const ACTION_RECEIPT: &str = "ACTION_RECEIPT";

/// #16 enforcement 开关：`STARKNET_ACTION_SIG_REQUIRED=1` 时，携带了签名但
/// 验签失败/seq 非单调的动作会被拒绝；默认 off（迁移期放行并记日志）。
pub fn action_sig_required() -> bool {
    std::env::var("STARKNET_ACTION_SIG_REQUIRED").as_deref() == Ok("1")
}
