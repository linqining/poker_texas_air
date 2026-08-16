//! B 档 — 已启用的玩家动作 AIRs（8 个）。
//!
//! - [`fold`] — 玩家主动 fold（弃牌）
//! - [`check`] — 玩家过牌（不下注且无需跟注）
//! - [`call`] — 玩家跟注（匹配当前最高下注）
//! - [`raise`] — 玩家加注（提高当前下注）
//! - [`bet`] — 玩家主动下注（postflop 第一个下注者，语义等同 raise）
//! - [`force_fold`] — 管理员强制 fold 玩家
//! - [`kick_player`] — 踢出玩家（管理员操作）
//! - [`set_leave_after_hand`] — 显式设置下一手前离场标记
//!
//! ## 约束模板
//!
//! 每个 action AIR 验证：
//! 1. 通用约束（[`crate::airs::common::CommonConstraints`]）
//! 2. `seat_index == input.seat_index`（输入一致性）
//! 3. 业务约束（如 `fold` 约束 `output_folded == 1`，`call` 约束 `output_call_amount == input.amount`）

pub mod bet;
pub mod call;
pub mod check;
pub mod end_betting_round;
pub mod end_without_showdown;
pub mod fold;
pub mod force_fold;
pub mod kick_player;
pub mod raise;
pub mod set_leave_after_hand;
pub(crate) mod validation;
