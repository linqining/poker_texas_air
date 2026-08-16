//! Texas Poker 原生 Precompile 合约（移植自 `/Users/mac/projects/zgame/texas_poker_move`）。
//!
//! 本模块将 Sui Move 德州扑克合约（~8000 行，含完整 Mental Poker 协议）
//! 移植为 zchain 原生预编译合约。合约字节码内嵌于 zchain 节点二进制，
//! 通过 `PrecompileRegistry` 注册，ObjectID = `reserved::texas_poker_contract_id()`
//! （`0xFF..02`）。
//!
//! # 模块结构
//!
//! - `constants`：状态常量（ROUND_*/SHUFFLE_PHASE_*/REVEAL_PHASE_*/...）
//! - `card`：扑克牌数据结构（Card/PlayingCard + 花色映射）
//! - `hand_evaluator`：7选5最佳手牌评估（10 种牌型）
//! - `betting`：下注规则（BettingRound + all-in 处理）
//! - `side_pot`：边池分层算法（统一 pots 结构 + 位掩码 eligible）
//! - `settlement`：确定性结算计划（side-pot/rake/runout/winner/award）
//! - `events`：40 种事件类型枚举
//! - `types`：核心数据结构（TexasPokerTable/Seat/DeckState/ShuffleState/...）
//! - `state_machine`：状态机推进 + deadline + reveal/reconstruct 编排
//! - `dispatch`：19 个 active method selector 路由
//! - `utils`：Mental Poker 密码学适配层（包 `poker_protocol` crate，提供 G1/Scalar 自由函数 + verify_or_skip）
//!
//! # Mental Poker 协议
//!
//! 1. 玩家轮流 shuffle 加密牌组并提交 shuffle proof
//! 2. 每个玩家为非自己手牌提交 reveal token（部分解密）
//! 3. 牌主用自己 sk 完成解密（showdown 阶段）
//! 4. 公共牌由所有玩家 reveal token 聚合解密
//!
//! 链上仅做 verify，链下做 prove（`#[cfg(feature = "client")]` 门控）。
//!
//! # ZK 跳过回退（仅 crate 内单元测试）
//!
//! 单元测试的密码学跳过是编译期 `cfg(test)` 行为，不属于桌台状态。生产、普通库和
//! 集成测试构建始终执行真实密码学验证，状态/preimage 无法携带运行时绕过开关。

pub mod betting;
pub mod card;
pub mod constants;
pub mod events;
pub mod hand_evaluator;
pub mod settlement;
pub mod side_pot;
pub mod types;
pub mod utils;

/// Canonical Object type tag for persisted Texas Poker table state.
///
/// Keep this separate from the reserved precompile contract ID: reconciliation, snapshots and
/// proof anchors identify table escrow by this stable type tag, while the current MVP happens to
/// store its single table at the precompile ID.
pub const TEXAS_POKER_TABLE_OBJECT_TYPE: &str = "TexasPokerTable";

/// Object type tag for immutable table display metadata.
pub const TEXAS_POKER_METADATA_OBJECT_TYPE: &str = "TexasPokerTableMetadata";

/// Object type tag for immutable poker rules.
pub const TEXAS_POKER_RULES_OBJECT_TYPE: &str = "TexasPokerTableRules";

/// Object type tag for immutable creator/admin policy.
pub const TEXAS_POKER_GOVERNANCE_OBJECT_TYPE: &str = "TexasPokerGovernancePolicy";

/// Persisted Borsh schema version for [`types::TexasPokerTable`].
///
/// Version 3 removed persisted derived/transient fields while preserving the complete game state.
/// Version 4 replaces redundant seat lifecycle booleans with one status enum and packs orthogonal
/// booleans into flags. Version 5 moves all seat-set state to canonical u16 masks and replaces
/// persisted optional seat indices with `NO_SEAT`. Version 16 replaces the variable-length
/// encrypted deck with an absent-or-fixed-52 tagged union. Version 17 removes the duplicate
/// table-local command version. Version 18 removes `addon_pool`, which is uniquely derived from
/// the checked sum of every occupied seat's `pending_addon`. Version 19 removes
/// `ante_collected`; the start-hand transition derives it from checked per-seat debits and the pot
/// delta. Versions 2 through 18 are decoded through explicit fail-closed migrations in
/// [`state_codec`]. Version 23 physically groups immutable/low-frequency poker parameters into
/// one canonical `TableRules` value, preparing it to move behind a rules hash without keeping
/// duplicate flat fields in the hot table state. Version 25 makes the tagged `Seat` enum the
/// physical runtime and resolved-snapshot representation; version 27 replaces the redundant
/// numeric reveal phase with a typed purpose whose exact board street comes from `HandPhase`.
/// Version 28 replaces the byte-wide `0xff` missing-seat marker with the canonical four-bit
/// sentinel `0x0f`. Version 29 replaces the variable-length reveal ledger with a fixed
/// `(seat, hole_slot)` owner-readable partial-ciphertext ledger.
/// Incompatible older layouts are deliberately unsupported.
pub const TEXAS_POKER_TABLE_STATE_SCHEMA_VERSION: u8 = 29;

/// ObjectDb-only hot-state schema.
///
/// Runtime/proof snapshots use resolved schema v29. The v30 ObjectDb encoding combines immutable
/// context commitments with the same physical tagged-seat and typed-reveal representation.
pub const TEXAS_POKER_HOT_STATE_SCHEMA_VERSION: u8 = 30;

/// Versioned persisted-state codec and fail-closed legacy migrations.
pub mod state_codec;

// Phase 3: 状态机 + dispatch
pub mod dispatch;
pub mod state_machine;

// Post-commit Prover：证明任务（return_value 的 prove_task 部分）。
// 与 poker_texas_air::prove_task 保持 borsh 二进制兼容（MethodInput 共享自 vm-common）。
pub mod prove_task;

// Phase 3.3: TexasPokerPrecompile impl（待 state_machine/dispatch 完成后补）
// pub struct TexasPokerPrecompile { ... }
// impl
