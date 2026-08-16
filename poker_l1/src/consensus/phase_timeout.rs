//! 多玩家阶段超时惩罚执行（spec Phase 4 Task 8）。
//!
//! 严格遵循 spec.md（change-id：`extend-game-multiplayer-phases`）：
//! - 当 [`crate::block::is_submit_phase_timed_out`] 判定某多玩家提交阶段超时，
//!   assigned_validator 调用 [`handle_submit_phase_timeout`] kick `pending_submitters`
//!   中所有未提交者并退款
//! - kick 后剩余 `active_participants < 2` → 标记 `is_finalized = true`
//!   （Phase 2 不实际触发 end_without_showdown 事件，仅标记 finalized）
//!
//! ## 设计决策
//!
//! - **退款金额由上层闭包注入**：本函数不查 `total_bet`（Phase 2 routing 层不存储该字段），
//!   通过 `refund_calc: F: Fn(&Address) -> u64` 闭包由调用方填充实际退款金额
//! - **所有多玩家阶段行为一致**：`timed_out_phase` 参数保留供日志/事件使用，
//!   本函数逻辑不分支（Shuffle / RevealToken / Reconstruct / LeaveProof 行为相同）
//! - **`last_action_height` 由调用方更新**：本函数不更新该字段，避免与上层
//!   block 推进逻辑产生时序冲突
//! - **不触发 end_without_showdown 事件**：Phase 2 仅标记 `is_finalized = true`，
//!   实际事件触发由上层 Phase 3 合约层完成

use crate::consensus::{GameStatus, SubmitPhaseKind};
use crate::{Address, BlockHeight};

/// 单个玩家被 kick 的结果（spec Phase 4 Task 8.2）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KickResult {
    /// 被 kick 的玩家地址。
    pub player: Address,
    /// 退款金额（=该玩家 total_bet，spec：超时 kick 退款）。
    /// Phase 2 routing 层不存储 `total_bet`，此处保留字段供上层填充，默认 0。
    pub refund_amount: u64,
}

/// 处理多玩家阶段超时：kick `pending_submitters` 中所有未提交者并退款。
///
/// spec Phase 4 Task 8.2 — 行为：
/// 1. 收集 `pending_submitters` 中所有玩家（这些是要被 kick 的未提交者）
/// 2. 对每个被 kick 的玩家调用 `refund_calc(&player)` 计算 `refund_amount`
/// 3. 从 `active_participants` / `pending_submitters` / `completed_submitters` /
///    `player_nonce` 中移除被 kick 的玩家
/// 4. 清空 `pending_submitters`（已全部处理）
/// 5. 若剩余 `active_participants < 2`，标记 `is_finalized = true`
///    （Phase 2 不实际触发 end_without_showdown 事件，仅标记 finalized）
///
/// 参数：
/// - `game`：&mut GameStatus — 待更新的游戏状态
/// - `timed_out_phase`：触发超时的阶段（保留供日志/事件使用，本函数逻辑不分支）
/// - `current_height`：当前 block height（保留供上层使用，本函数不更新 `last_action_height`，
///   该字段由调用方负责更新）
/// - `refund_calc`：闭包，给定玩家地址返回退款金额（上层填充，本函数不查 `total_bet`）
///
/// 返回 `Vec<KickResult>`：每个被 kick 的玩家一项（按 `pending_submitters` 的 BTreeSet 升序）。
///
/// 副作用（见上文行为 1-5）。
///
/// # 不变量
///
/// - 调用后 `pending_submitters` 为空
/// - `completed_submitters` 中不再包含任何被 kick 的玩家
/// - `active_participants` 中不再包含任何被 kick 的玩家
/// - `player_nonce` 中不再包含任何被 kick 的玩家
/// - 若 `active_participants.len() < 2`，则 `is_finalized = true`
#[allow(unused_variables)] // timed_out_phase / current_height 保留供日志/上层使用
pub fn handle_submit_phase_timeout<F>(
    game: &mut GameStatus,
    timed_out_phase: SubmitPhaseKind,
    current_height: BlockHeight,
    refund_calc: F,
) -> Vec<KickResult>
where
    F: Fn(&Address) -> u64,
{
    // 收集 pending_submitters 中所有玩家（按 BTreeSet 升序），这些是要被 kick 的未提交者
    let kicked_players: Vec<Address> = game.pending_submitters.iter().copied().collect();

    let mut results = Vec::with_capacity(kicked_players.len());

    for player in &kicked_players {
        // 由上层闭包计算退款金额（Phase 2 routing 层不存储 total_bet）
        let refund_amount = refund_calc(player);
        results.push(KickResult {
            player: *player,
            refund_amount,
        });

        // 从 active_participants 移除
        game.active_participants.remove(player);
        // 从 completed_submitters 移除（若在 — 例如玩家提交后又被判定超时的情况）
        game.completed_submitters.remove(player);
        // 从 player_nonce 移除（SEC-L3：清除该玩家的 per-game nonce 记录）
        game.player_nonce.remove(player);
    }

    // 清空 pending_submitters（这些玩家已被全部处理）
    game.pending_submitters.clear();

    // 若剩余 active_participants < 2，标记 is_finalized = true
    // （Phase 2 不实际触发 end_without_showdown 事件，仅标记 finalized）
    if game.active_participants.len() < 2 {
        game.is_finalized = true;
    }

    // 注意：last_action_height 由调用方负责更新（避免与上层 block 推进逻辑产生时序冲突）
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{ExecutionMode, GamePhase, GameStatus};
    use crate::object_model::ObjectID;
    use crate::signature::TaggedPubkey;
    use crate::signature::tagged_pubkey::{SignatureScheme, encode_tag};
    use std::collections::BTreeMap;

    /// 构造测试用 tagged pubkey。
    fn make_tagged_pubkey(byte: u8) -> TaggedPubkey {
        TaggedPubkey {
            tag: encode_tag(SignatureScheme::Secp256k1, 1),
            raw: vec![byte; 33],
        }
    }

    /// 构造测试用 GameStatus，可指定 active_participants / pending_submitters /
    /// completed_submitters。
    fn make_game_with_phase(
        active: &[Address],
        pending: &[Address],
        completed: &[Address],
        kind: SubmitPhaseKind,
    ) -> GameStatus {
        let assigned_tp = make_tagged_pubkey(0x02);
        GameStatus {
            id: ObjectID::new([0xAA; 20], 1),
            assigned_validator: assigned_tp,
            current_turn_player: active.first().copied().unwrap_or([0; 20]),
            active_participants: active.iter().copied().collect(),
            player_nonce: active
                .iter()
                .map(|p| (*p, 0u64))
                .collect::<BTreeMap<_, _>>(),
            last_action_height: 100,
            hand_start_height: 90,
            execution_mode: ExecutionMode::OnChain,
            is_finalized: false,
            phase: GamePhase::MultiPlayerSubmit { kind },
            pending_submitters: pending.iter().copied().collect(),
            phase_started_height: 1000,
            completed_submitters: completed.iter().copied().collect(),
        }
    }

    /// 测试用地址辅助：用单字节生成 20 字节地址。
    fn addr(b: u8) -> Address {
        [b; 20]
    }

    // ===== SubTask 8.3: 单玩家超时测试 =====

    #[test]
    fn handle_submit_phase_timeout_single_player_kick() {
        // 场景：3 玩家 active，1 个在 pending（被 kick），2 个保留
        // 期望：active 减少 1，is_finalized=false（剩余 2 >= 2）
        let active = [addr(0x10), addr(0x20), addr(0x30)];
        let pending = [addr(0x10)];
        let completed: [Address; 0] = [];
        let mut game =
            make_game_with_phase(&active, &pending, &completed, SubmitPhaseKind::Shuffle);

        let results =
            handle_submit_phase_timeout(&mut game, SubmitPhaseKind::Shuffle, 1101, |_player| 500);

        // 返回 1 个 KickResult
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].player, addr(0x10));
        assert_eq!(results[0].refund_amount, 500);

        // 0x10 从 active / pending / completed / player_nonce 移除
        assert!(!game.active_participants.contains(&addr(0x10)));
        assert!(game.pending_submitters.is_empty());
        assert!(!game.completed_submitters.contains(&addr(0x10)));
        assert!(!game.player_nonce.contains_key(&addr(0x10)));

        // 0x20 / 0x30 仍在 active
        assert!(game.active_participants.contains(&addr(0x20)));
        assert!(game.active_participants.contains(&addr(0x30)));
        assert_eq!(game.active_participants.len(), 2);

        // 剩余 2 >= 2 → 不 finalize
        assert!(!game.is_finalized);
    }

    // ===== SubTask 8.3: 多玩家超时测试 =====

    #[test]
    fn handle_submit_phase_timeout_multi_player_kick_all() {
        // 场景：3 玩家 active，全部在 pending（被 kick），0 在 completed
        // 期望：active 清空，is_finalized=true（剩余 0 < 2）
        let active = [addr(0x10), addr(0x20), addr(0x30)];
        let pending = [addr(0x10), addr(0x20), addr(0x30)];
        let completed: [Address; 0] = [];
        let mut game =
            make_game_with_phase(&active, &pending, &completed, SubmitPhaseKind::Shuffle);

        let results =
            handle_submit_phase_timeout(&mut game, SubmitPhaseKind::Shuffle, 1101, |player| {
                // 不同玩家返回不同金额，验证闭包被正确调用
                if *player == addr(0x10) {
                    100
                } else if *player == addr(0x20) {
                    200
                } else {
                    300
                }
            });

        // 返回 3 个 KickResult，按 BTreeSet 升序（0x10 < 0x20 < 0x30）
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].player, addr(0x10));
        assert_eq!(results[0].refund_amount, 100);
        assert_eq!(results[1].player, addr(0x20));
        assert_eq!(results[1].refund_amount, 200);
        assert_eq!(results[2].player, addr(0x30));
        assert_eq!(results[2].refund_amount, 300);

        // active 清空
        assert!(game.active_participants.is_empty());
        assert_eq!(game.active_participants.len(), 0);

        // pending 清空
        assert!(game.pending_submitters.is_empty());

        // completed 为空（无玩家保留）
        assert!(game.completed_submitters.is_empty());

        // player_nonce 清空
        assert!(game.player_nonce.is_empty());

        // 剩余 0 < 2 → finalize
        assert!(game.is_finalized);
    }

    // ===== SubTask 8.3: 剩余不足两人测试 =====

    #[test]
    fn handle_submit_phase_timeout_remaining_less_than_two() {
        // 场景：3 玩家 active，2 在 pending（被 kick），1 在 completed（保留）
        // 期望：active 剩 1（completed 玩家保留），is_finalized=true（剩余 1 < 2）
        let active = [addr(0x10), addr(0x20), addr(0x30)];
        let pending = [addr(0x10), addr(0x20)];
        let completed = [addr(0x30)];
        let mut game =
            make_game_with_phase(&active, &pending, &completed, SubmitPhaseKind::RevealToken);

        let results =
            handle_submit_phase_timeout(&mut game, SubmitPhaseKind::RevealToken, 2051, |_player| {
                1000
            });

        // 返回 2 个 KickResult（0x10 / 0x20）
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].player, addr(0x10));
        assert_eq!(results[1].player, addr(0x20));
        // 退款金额由闭包返回
        assert_eq!(results[0].refund_amount, 1000);
        assert_eq!(results[1].refund_amount, 1000);

        // 0x30 仍在 active / completed / player_nonce（保留）
        assert!(game.active_participants.contains(&addr(0x30)));
        assert!(game.completed_submitters.contains(&addr(0x30)));
        assert!(game.player_nonce.contains_key(&addr(0x30)));

        // 0x10 / 0x20 已被移除
        assert!(!game.active_participants.contains(&addr(0x10)));
        assert!(!game.active_participants.contains(&addr(0x20)));
        assert!(!game.completed_submitters.contains(&addr(0x10)));
        assert!(!game.completed_submitters.contains(&addr(0x20)));

        // active 剩 1
        assert_eq!(game.active_participants.len(), 1);

        // pending 清空
        assert!(game.pending_submitters.is_empty());

        // 剩余 1 < 2 → finalize
        assert!(game.is_finalized);
    }

    // ===== SubTask 8.3: refund_calc 闭包正确调用测试 =====

    #[test]
    fn handle_submit_phase_timeout_refund_calc_called_per_player() {
        // 验证 refund_calc 闭包对每个被 kick 的玩家调用一次，且金额正确填充
        let active = [addr(0x10), addr(0x20), addr(0x30), addr(0x40)];
        let pending = [addr(0x10), addr(0x30)];
        let completed = [addr(0x20), addr(0x40)];
        let mut game =
            make_game_with_phase(&active, &pending, &completed, SubmitPhaseKind::Reconstruct);

        // 闭包：根据玩家地址首字节返回不同金额
        let results =
            handle_submit_phase_timeout(&mut game, SubmitPhaseKind::Reconstruct, 3101, |player| {
                let byte = player[0];
                (byte as u64) * 10 // 0x10 → 160, 0x30 → 480
            });

        // 2 个 KickResult
        assert_eq!(results.len(), 2);
        // 0x10: 0x10 = 16, * 10 = 160
        assert_eq!(results[0].player, addr(0x10));
        assert_eq!(results[0].refund_amount, 160);
        // 0x30: 0x30 = 48, * 10 = 480
        assert_eq!(results[1].player, addr(0x30));
        assert_eq!(results[1].refund_amount, 480);

        // completed 中 0x20 / 0x40 保留（不在 pending，未被 kick）
        assert!(game.completed_submitters.contains(&addr(0x20)));
        assert!(game.completed_submitters.contains(&addr(0x40)));
        assert_eq!(game.completed_submitters.len(), 2);

        // active 剩 2（0x20 / 0x40）
        assert_eq!(game.active_participants.len(), 2);
        // 剩余 2 >= 2 → 不 finalize
        assert!(!game.is_finalized);
    }

    // ===== SubTask 8.5: LeaveProof 阶段调用此函数行为一致 =====

    #[test]
    fn handle_submit_phase_timeout_leave_proof_behaves_consistently() {
        // 虽 is_submit_phase_timed_out 不会返回 LeaveProof，但本函数应能正确处理任何 SubmitPhaseKind
        // 验证 LeaveProof 阶段调用时行为与 Shuffle / RevealToken / Reconstruct 一致
        let active = [addr(0x10), addr(0x20), addr(0x30)];
        let pending = [addr(0x10), addr(0x20)];
        let completed: [Address; 0] = [];
        let mut game =
            make_game_with_phase(&active, &pending, &completed, SubmitPhaseKind::LeaveProof);

        let results =
            handle_submit_phase_timeout(&mut game, SubmitPhaseKind::LeaveProof, 5000, |_| 999);

        // 行为与 Shuffle 一致：2 个 pending 玩家被 kick
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].player, addr(0x10));
        assert_eq!(results[1].player, addr(0x20));
        assert_eq!(results[0].refund_amount, 999);
        assert_eq!(results[1].refund_amount, 999);

        // active 剩 1（0x30）
        assert_eq!(game.active_participants.len(), 1);
        assert!(game.active_participants.contains(&addr(0x30)));

        // pending 清空
        assert!(game.pending_submitters.is_empty());

        // 剩余 1 < 2 → finalize
        assert!(game.is_finalized);
    }

    // ===== SubTask 8.3: 边界场景 — pending 为空 =====

    #[test]
    fn handle_submit_phase_timeout_empty_pending_no_op() {
        // pending 为空时，无玩家被 kick，状态不变（除可能因 active<2 触发 finalize）
        let active = [addr(0x10), addr(0x20), addr(0x30)];
        let pending: [Address; 0] = [];
        let completed: [Address; 0] = [];
        let mut game =
            make_game_with_phase(&active, &pending, &completed, SubmitPhaseKind::Shuffle);

        let results = handle_submit_phase_timeout(&mut game, SubmitPhaseKind::Shuffle, 1101, |_| 0);

        // 无 KickResult
        assert!(results.is_empty());

        // active 不变
        assert_eq!(game.active_participants.len(), 3);
        // pending 仍为空
        assert!(game.pending_submitters.is_empty());
        // 3 >= 2 → 不 finalize
        assert!(!game.is_finalized);
    }

    // ===== SubTask 8.3: pending 玩家在 completed 中也存在的边角情况 =====

    #[test]
    fn handle_submit_phase_timeout_player_in_both_pending_and_completed() {
        // 边角情况：某玩家同时在 pending 和 completed 中（理论上不应发生，但函数应稳健处理）
        // 期望：该玩家被 kick，从两个集合中均移除
        let active = [addr(0x10), addr(0x20), addr(0x30), addr(0x40)];
        let pending = [addr(0x10)];
        let completed = [addr(0x10), addr(0x20)]; // 0x10 同时在 pending 和 completed
        let mut game =
            make_game_with_phase(&active, &pending, &completed, SubmitPhaseKind::Shuffle);

        let results =
            handle_submit_phase_timeout(&mut game, SubmitPhaseKind::Shuffle, 1101, |_| 100);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].player, addr(0x10));

        // 0x10 从 completed 移除（若在）
        assert!(!game.completed_submitters.contains(&addr(0x10)));
        // 0x20 仍在 completed（保留）
        assert!(game.completed_submitters.contains(&addr(0x20)));
        // active 剩 3（0x20 / 0x30 / 0x40）
        assert_eq!(game.active_participants.len(), 3);
        // 3 >= 2 → 不 finalize
        assert!(!game.is_finalized);
    }

    // ===== SubTask 8.3: 恰好剩余 2 人不 finalize 边界 =====

    #[test]
    fn handle_submit_phase_timeout_exactly_two_remaining_no_finalize() {
        // 边界：4 玩家 active，2 在 pending（被 kick），2 保留 → 剩余 2 == 2 → 不 finalize
        let active = [addr(0x10), addr(0x20), addr(0x30), addr(0x40)];
        let pending = [addr(0x10), addr(0x20)];
        let completed: [Address; 0] = [];
        let mut game =
            make_game_with_phase(&active, &pending, &completed, SubmitPhaseKind::Shuffle);

        let _results =
            handle_submit_phase_timeout(&mut game, SubmitPhaseKind::Shuffle, 1101, |_| 0);

        assert_eq!(game.active_participants.len(), 2);
        // 边界：剩余 2 == 2，不 < 2 → 不 finalize
        assert!(!game.is_finalized);
    }

    // ===== SubTask 8.3: 各 SubmitPhaseKind 行为一致性参数化测试 =====

    #[test]
    fn handle_submit_phase_timeout_all_kinds_behave_consistently() {
        // 验证 Shuffle / RevealToken / Reconstruct / LeaveProof 四种阶段行为一致
        for kind in [
            SubmitPhaseKind::Shuffle,
            SubmitPhaseKind::RevealToken,
            SubmitPhaseKind::Reconstruct,
            SubmitPhaseKind::LeaveProof,
        ] {
            let active = [addr(0x10), addr(0x20), addr(0x30)];
            let pending = [addr(0x10), addr(0x20), addr(0x30)];
            let completed: [Address; 0] = [];
            let mut game = make_game_with_phase(&active, &pending, &completed, kind);

            let results = handle_submit_phase_timeout(&mut game, kind, 9999, |_| 100);

            // 行为一致：3 个 pending 玩家被 kick
            assert_eq!(results.len(), 3, "kind={kind:?} 应 kick 3 玩家");
            assert!(
                game.pending_submitters.is_empty(),
                "kind={kind:?} pending 应清空"
            );
            assert!(
                game.active_participants.is_empty(),
                "kind={kind:?} active 应清空"
            );
            assert!(game.is_finalized, "kind={kind:?} 应 finalize");
        }
    }

    // ===== KickResult 派生 trait 测试 =====

    #[test]
    fn kick_result_derives_debug_clone_eq() {
        let kr1 = KickResult {
            player: addr(0x10),
            refund_amount: 500,
        };
        let kr2 = kr1.clone();
        assert_eq!(kr1, kr2);
        // Debug 可格式化
        let _msg = format!("{kr1:?}");
    }
}
