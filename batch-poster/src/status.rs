//! status JSON 端点（survey §9.7 监控最小集）+ 手动 drain 逃生口。
//!
//! 监控最小集：pending 批数 / 最老批年龄 / in-flight / 余额（余额观测由
//! 调用方注入——StarknetSend 接缝不含余额读取，避免 poster 自行扩展
//! 链上触点）。drain = 停止拾取新任务、完成在途后退出（运营逃生）。

use serde::{Deserialize, Serialize};

/// poster 运行状态快照。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PosterStatus {
    /// 队列中未终态任务数（poster 已拾取未回执）。
    pub pending_tasks: usize,
    /// fold 攒批中（未回执）批数。
    pub pending_batches: usize,
    /// 最老未决批年龄（秒；None = 无在途批）。
    pub oldest_batch_age_secs: Option<u64>,
    /// txmgr 在途交易数。
    pub in_flight_txs: usize,
    /// txmgr 熔断位（true = fail-closed 停发，需人工 resume）。
    pub txmgr_halted: bool,
    /// drain 已触发。
    pub draining: bool,
    /// 操作员余额（观测值；None = 未接入）。
    pub operator_balance: Option<String>,
}

impl PosterStatus {
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}

/// 最小 HTTP 端点（单次连接、GET → status JSON）。骨架实现：daemon 内
/// 循环 accept；生产可换 axum。
pub async fn serve_status_once(
    listener: &tokio::net::TcpListener,
    status: &PosterStatus,
) -> std::io::Result<()> {
    let (mut socket, _) = listener.accept().await?;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = [0u8; 1024];
    let _ = socket.read(&mut buf).await;
    let body = status.to_json();
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    socket.write_all(resp.as_bytes()).await?;
    socket.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// status JSON 字段（监控最小集口径）。
    #[test]
    fn status_json_fields() {
        let st = PosterStatus {
            pending_tasks: 3,
            pending_batches: 1,
            oldest_batch_age_secs: Some(120),
            in_flight_txs: 2,
            txmgr_halted: false,
            draining: false,
            operator_balance: None,
        };
        let json = st.to_json();
        for field in [
            "pending_tasks",
            "pending_batches",
            "oldest_batch_age_secs",
            "in_flight_txs",
            "txmgr_halted",
            "draining",
        ] {
            assert!(json.contains(field), "缺字段 {field}");
        }
        let back: PosterStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, st);
    }
}
