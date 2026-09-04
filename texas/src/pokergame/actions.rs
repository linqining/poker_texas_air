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

/// #18 超时默认动作（服务器代打）。语义（2026-09-04 定稿，规则比 TODO 原文
/// 更护玩家）：可 check（无需跟注）→ Check；普通跟注差额（≤ 大盲）→ Call
/// （保住手牌，避免网络抖动把在线玩家弃出局）；只有面对超出大盲的加注
/// 才 Fold。TODO 原文的"面对下注只能 auto-fold"是下界——Call(≤BB) 是
/// 显式放宽项，电路合法性表达式若收紧到原文需先改这里的规则与测试。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoActionKind {
    Check,
    Call,
    Fold,
}

/// 由下注轮状态推导合法默认动作（纯函数，`handle_auto_fold` 与未来的
/// 电路合法性表达式共用同一规则源）。`call_amount` 为本轮需跟注总额，
/// `my_bet` 为该座位已投入，`big_blind` 为大盲绝对值。
pub fn legal_auto_action(
    call_amount: u64,
    my_bet: u64,
    big_blind: u64,
) -> Option<AutoActionKind> {
    if call_amount == 0 || my_bet >= call_amount {
        Some(AutoActionKind::Check)
    } else if call_amount - my_bet <= big_blind {
        Some(AutoActionKind::Call)
    } else {
        Some(AutoActionKind::Fold)
    }
}

/// 手牌动作日志的可追溯哈希（#18/#8.2 绑定前置）：对 (seat, seq, action,
/// amount, auto, sig_ok) 序列做 starknet_keccak。结算时随日志输出，供
/// 运营核对；§8.2 电路吸收（第 37 入参）启用后即为其输入源。
pub fn action_log_digest_hex(log: &[ActionLogEntry]) -> String {
    use starknet::core::utils::starknet_keccak;
    let mut h = starknet_keccak(b"zgame.action_log.v1");
    for e in log {
        let mut buf = h.to_bytes_be().to_vec();
        buf.extend_from_slice(&e.seat.to_be_bytes());
        buf.extend_from_slice(&e.seq.to_be_bytes());
        buf.extend_from_slice(&e.amount.to_be_bytes());
        buf.push(u8::from(e.auto));
        buf.push(u8::from(e.sig_ok));
        buf.extend_from_slice(e.action.as_bytes());
        h = starknet_keccak(&buf);
    }
    format!("0x{}", hex_encode_starknet(h))
}

fn hex_encode_starknet(f: starknet::core::types::Felt) -> String {
    let bytes = f.to_bytes_be();
    let s = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let trimmed = s.trim_start_matches('0');
    if trimmed.is_empty() { "0x0".to_string() } else { format!("0x{trimmed}") }
}

#[cfg(test)]
mod auto_action_tests {
    use super::*;

    #[test]
    fn zero_owed_check() {
        assert_eq!(legal_auto_action(0, 0, 20), Some(AutoActionKind::Check));
        assert_eq!(legal_auto_action(20, 20, 20), Some(AutoActionKind::Check));
        assert_eq!(legal_auto_action(20, 35, 20), Some(AutoActionKind::Check));
    }

    #[test]
    fn blind_level_difference_calls() {
        // 欠 20（大盲级）→ Call；欠 40 超大盲 → Fold。
        assert_eq!(legal_auto_action(20, 10, 20), Some(AutoActionKind::Call));
        assert_eq!(legal_auto_action(40, 10, 20), Some(AutoActionKind::Fold));
        // 边界：恰好等于大盲 → Call。
        assert_eq!(legal_auto_action(30, 10, 20), Some(AutoActionKind::Call));
    }

    #[test]
    fn big_raise_folds() {
        assert_eq!(legal_auto_action(500, 20, 20), Some(AutoActionKind::Fold));
    }

    #[test]
    fn action_log_digest_is_order_and_flag_sensitive() {
        let e = |seq: u64, action: &str, auto: bool| ActionLogEntry {
            seat: 1, seq, action: action.into(), amount: 0, auto, sig_ok: true,
        };
        let a = action_log_digest_hex(&[e(1, "check", false), e(2, "fold", true)]);
        let b = action_log_digest_hex(&[e(1, "check", false), e(2, "fold", false)]);
        let c = action_log_digest_hex(&[e(2, "fold", true), e(1, "check", false)]);
        assert_ne!(a, b, "auto flag must change digest");
        assert_ne!(a, c, "order must change digest");
        assert_eq!(
            a,
            action_log_digest_hex(&[e(1, "check", false), e(2, "fold", true)]),
            "same log → same digest"
        );
    }
}
