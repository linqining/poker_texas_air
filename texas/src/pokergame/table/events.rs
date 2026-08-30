/// ZK 密码学事件类型，对应前端 ZK 可视化面板的事件分类。
///
/// 这些事件在玩家提交 ZK 证明并验证后广播给该桌所有 WS 客户端，
/// 供前端"ZK 密码学可视化面板"实时展示证明提交与验证状态。
#[derive(Debug, Clone, Copy)]
pub enum CryptoEventType {
    Shuffle,
    Remask,
    RevealToken,
    Leave,
    Reconstruct,
}

impl CryptoEventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Shuffle => "shuffle",
            Self::Remask => "remask",
            Self::RevealToken => "reveal_token",
            Self::Leave => "leave",
            Self::Reconstruct => "reconstruct",
        }
    }
}

/// Table 内部方法可发送的 socket 事件。
///
/// 通过 `Table::emit_event` 发送到 mpsc channel，由 `socket::table_event_consumer`
/// 消费并执行实际的 `io.emit` 广播。
#[derive(Debug, Clone)]
pub enum TableEvent {
    /// 广播 TABLE_UPDATED 给该桌所有玩家（含 per-player 视图定制，隐藏对手手牌）。
    TableUpdated { message: Option<String> },
    /// 广播 crypto_event 消息（shuffle/reveal/reconstruct 等协议阶段事件）。
    CryptoEvent {
        event_type: CryptoEventType,
        player_pk: String,
        card_index: Option<u32>,
        verified: bool,
        message: Option<String>,
    },
    /// 发送 SHUFFLE_NOTICE 给下一个洗牌玩家。
    ShuffleNotice,
    /// 发送 REVEAL_NOTICE 给活跃玩家。
    RevealNotice,
    /// 发送 RECONSTRUCT_NOTICE 给活跃玩家。
    ReconstructNotice,
}
