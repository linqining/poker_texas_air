use std::sync::Arc;

use socketioxide::SocketIo;
use tokio::sync::mpsc;

use crate::pokergame::table::events::TableEvent;
use crate::socket::SocketState;
use crate::socket::broadcast;
use crate::socket::game_loop;

/// 消费 `TableEvent` 并执行实际 socket 广播的异步任务。
///
/// 每个 Table 在 `SocketState::init_table_event_channels` 中创建一个独立的
/// mpsc channel，并将 receiver 传给此函数。Table 内部方法通过
/// `Table::emit_event` 发送事件到 channel，由本 consumer 统一消费并调用
/// 对应的 broadcast 方法执行 `io.emit`。
///
/// 当 channel 的所有 sender 已 drop（Table 被销毁），`rx.recv()` 返回 None，
/// consumer 任务正常退出。
pub async fn table_event_consumer(
    io: SocketIo,
    state: Arc<SocketState>,
    table_id: u32,
    mut rx: mpsc::Receiver<TableEvent>,
) {
    tracing::info!("[TABLE-EVENTS] Consumer started for table {}", table_id);
    while let Some(event) = rx.recv().await {
        match event {
            TableEvent::TableUpdated { message } => {
                broadcast::broadcast_to_table(&io, &state, table_id, message.as_deref()).await;
            }
            TableEvent::CryptoEvent {
                event_type,
                player_pk,
                card_index,
                verified,
                message,
            } => {
                state
                    .broadcast_crypto_event(
                        table_id,
                        event_type,
                        player_pk,
                        card_index,
                        verified,
                        message,
                        None,
                    )
                    .await;
            }
            TableEvent::ShuffleNotice => {
                state.send_shuffle_notice(table_id).await;
            }
            TableEvent::RevealNotice => {
                game_loop::broadcast_reveal_notice_if_active(&io, &state, table_id).await;
            }
            TableEvent::ReconstructNotice => {
                game_loop::broadcast_reconstruct_notice_if_active(&io, &state, table_id).await;
            }
        }
    }
    tracing::info!("[TABLE-EVENTS] Consumer stopped for table {}", table_id);
}
