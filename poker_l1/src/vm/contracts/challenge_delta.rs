//! challenge_delta tx（SubTask 28.5 — S5 修复 + NEW-H4 修复 + R4-L7 + SEC-C4）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）+ tasks.md SubTask 28.5：
//! - 从 π 的 public_io 重新派生 `state_delta_hash`（不需 witness）
//! - 对比 `hash(提交的 Δ)` 与 `state_delta_hash`
//! - **不一致** → 挑战成立（succeeded）：操作方 forfeit 保证金 + 触发 `request_revert`
//!   回退到最后 ACKed checkpoint_state 重新结算
//!   （NEW-H4：链上无法从 state_delta_hash 逆推正确 Δ'，哈希不可逆）
//! - **一致** → 挑战失败（failed）：挑战方 forfeit 保证金（恶意挑战惩罚）
//!
//! # R4-L7 — 挑战方保证金机制
//!
//! - challenge_delta 提交方须预锁挑战保证金 = `buy_in_amount * challenge_deposit_ratio / 100`
//! - **SEC-C4 修复** — `challenge_deposit_ratio` 默认值由 10 提升至 50（与
//!   `forfeit_deposit_ratio` 同量级，提高恶意挑战成本防 griefing），可治理 ∈ [1, 100]
//! - 挑战成立 → 保证金退还 + 从操作方 forfeit 保证金分得奖励
//! - **SEC-C4 修复** — `challenge_reward_ratio` 默认值由 50 提升至 100，可治理 ∈ [10, 100]
//! - 挑战失败 → 保证金没收分配给被挑战方（操作方）作补偿
//!
//! # SEC-C4 修复 — forfeit 保证金分配规则
//!
//! 挑战成立后操作方 forfeit 保证金分配：
//! - 挑战方得 `challenge_reward_ratio %`（默认 100%）
//! - 剩余按 buy_in 比例分配给其他受害者玩家
//! - 防恶意挑战方无成本骚扰

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::error::PokerL1Error;
use crate::object_model::ObjectID;
use crate::{Address, Hash};

use super::types::GameContract;

// ===== 常量（SEC-C4 修复）=====

/// 挑战保证金比例默认值（SEC-C4：由 10 提升至 50）。
///
/// `challenger_deposit = buy_in_amount * challenge_deposit_ratio / 100`。
/// 可治理 ∈ [1, 100]。
pub const DEFAULT_CHALLENGE_DEPOSIT_RATIO: u32 = 50;

/// 挑战奖励比例默认值（SEC-C4：由 50 提升至 100）。
///
/// 挑战成立后，挑战方从操作方 forfeit 保证金中分得
/// `forfeit_deposit * challenge_reward_ratio / 100`。
/// 可治理 ∈ [10, 100]。
pub const DEFAULT_CHALLENGE_REWARD_RATIO: u32 = 100;

/// `challenge_deposit_ratio` 治理下限。
pub const MIN_CHALLENGE_DEPOSIT_RATIO: u32 = 1;

/// `challenge_deposit_ratio` 治理上限。
pub const MAX_CHALLENGE_DEPOSIT_RATIO: u32 = 100;

/// `challenge_reward_ratio` 治理下限。
pub const MIN_CHALLENGE_REWARD_RATIO: u32 = 10;

/// `challenge_reward_ratio` 治理上限。
pub const MAX_CHALLENGE_REWARD_RATIO: u32 = 100;

// ===== ChallengeDeltaTx =====

/// challenge_delta tx（SubTask 28.5）。
///
/// 内容：`(game_id, challenger, claimed_state_delta, challenger_deposit)`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct ChallengeDeltaTx {
    /// Game 对象 ID。
    pub game_id: ObjectID,
    /// 挑战方地址。
    pub challenger: Address,
    /// 挑战方提交的 Δ（声称与 π 不一致）。
    pub claimed_state_delta: Vec<u8>,
    /// 挑战方预锁保证金（= buy_in * challenge_deposit_ratio / 100）。
    pub challenger_deposit: u64,
}

impl ChallengeDeltaTx {
    /// 计算 `hash(claimed_state_delta) = blake2b_256(claimed_state_delta)`。
    ///
    /// 用于与 π 的 `state_delta_hash` 比对。
    pub fn claimed_delta_hash(&self) -> Hash {
        hash_state_delta(&self.claimed_state_delta)
    }
}

/// challenge_delta 应用结果（SubTask 28.5）。
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct ChallengeDeltaOutcome {
    /// 挑战是否成立（true: Δ 不一致，操作方 forfeit；false: Δ 一致，挑战方 forfeit）。
    pub succeeded: bool,
    /// 挑战方保证金是否退还（succeeded=true 时退还，否则没收）。
    pub challenger_deposit_refunded: bool,
    /// 挑战方获得的奖励（从操作方 forfeit 保证金中分得，succeeded=true 时有意义）。
    pub challenger_reward: u64,
    /// 操作方 forfeit 总额（succeeded=true 时有意义，succeeded=false 时为 0）。
    pub operator_forfeit_amount: u64,
    /// 挑战方保证金没收金额（succeeded=false 时有意义，转入操作方）。
    pub challenger_forfeit_amount: u64,
    /// 是否触发 request_revert（succeeded=true 时为 true）。
    pub triggers_request_revert: bool,
}

// ===== 辅助函数 =====

/// 计算 `state_delta_hash = blake2b_256(state_delta)`。
///
/// 与 [`crate::offline::state::CheckinTx::state_delta_hash`] 算法一致，
/// 确保 challenge_delta 比对正确。
pub fn hash_state_delta(state_delta: &[u8]) -> Hash {
    let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32) 初始化不应失败");
    hasher.update(state_delta);
    let mut out = [0u8; 32];
    hasher
        .finalize_variable(&mut out)
        .expect("Blake2bVar finalize 不应失败");
    out
}

/// 计算挑战方保证金（R4-L7 + SEC-C4）。
///
/// `challenger_deposit = buy_in_amount * challenge_deposit_ratio / 100`
#[must_use]
pub const fn compute_challenger_deposit(buy_in_amount: u64, challenge_deposit_ratio: u32) -> u64 {
    buy_in_amount.saturating_mul(challenge_deposit_ratio as u64) / 100
}

/// 计算挑战奖励（SEC-C4：从操作方 forfeit 保证金中分得）。
///
/// `challenger_reward = forfeit_deposit * challenge_reward_ratio / 100`
#[must_use]
pub const fn compute_challenger_reward(forfeit_deposit: u64, challenge_reward_ratio: u32) -> u64 {
    forfeit_deposit.saturating_mul(challenge_reward_ratio as u64) / 100
}

/// 校验 `challenge_deposit_ratio` 治理参数范围（SEC-C4：∈ [1, 100]）。
#[must_use]
pub const fn validate_challenge_deposit_ratio(ratio: u32) -> bool {
    ratio >= MIN_CHALLENGE_DEPOSIT_RATIO && ratio <= MAX_CHALLENGE_DEPOSIT_RATIO
}

/// 校验 `challenge_reward_ratio` 治理参数范围（SEC-C4：∈ [10, 100]）。
#[must_use]
pub const fn validate_challenge_reward_ratio(ratio: u32) -> bool {
    ratio >= MIN_CHALLENGE_REWARD_RATIO && ratio <= MAX_CHALLENGE_REWARD_RATIO
}

// ===== apply_challenge_delta =====

/// 应用 challenge_delta 到 GameContract（SubTask 28.5）。
///
/// # 流程
/// 1. 校验 `tx.game_id == game.id`
/// 2. 计算 `hash(claimed_state_delta) = blake2b_256(claimed_state_delta)`
/// 3. 与 `on_chain_state_delta_hash`（从 π 的 public_io 派生）比对
/// 4. **不一致**（挑战成立）：
///    - 操作方 `forfeit_deposit` 全额扣除
///    - 挑战方得 `forfeit_deposit * challenge_reward_ratio / 100` 奖励
///    - 剩余按 buy_in 比例分配给其他受害者玩家（caller 负责）
///    - 退还挑战方保证金
///    - 触发 `request_revert`（caller 负责）
///    - 返回 `Err(PokerL1Error::ChallengeSucceeded)` 通知 caller
/// 5. **一致**（挑战失败）：
///    - 挑战方保证金没收，转入操作方 `forfeit_deposit`
///    - 返回 `Err(PokerL1Error::ChallengeFailed)` 通知 caller
///
/// # 参数
/// - `game`：可变的 GameContract 引用
/// - `tx`：challenge_delta tx
/// - `on_chain_state_delta_hash`：从 π 的 public_io 重新派生的 state_delta_hash
/// - `challenge_reward_ratio`：挑战奖励比例（默认 100，SEC-C4）
///
/// # 返回
/// - `Err(ChallengeSucceeded)`：挑战成立，操作方 forfeit + 触发 request_revert
/// - `Err(ChallengeFailed)`：挑战失败，挑战方 forfeit 保证金
/// - `Err(GameNotFound)`：game_id 不匹配
///
/// # 状态变更
/// - **succeeded**：`game.forfeit_deposit = 0`，`game.version += 1`
/// - **failed**：`game.forfeit_deposit += challenger_deposit`，`game.version += 1`
pub fn apply_challenge_delta(
    game: &mut GameContract,
    tx: &ChallengeDeltaTx,
    on_chain_state_delta_hash: Hash,
    challenge_reward_ratio: u32,
) -> Result<(), PokerL1Error> {
    // 1. 校验 game_id 一致
    if tx.game_id != game.id {
        return Err(PokerL1Error::GameNotFound(tx.game_id));
    }

    // 2. 计算 hash(claimed_state_delta)
    let claimed_hash = tx.claimed_delta_hash();

    // 3. 比对
    if claimed_hash != on_chain_state_delta_hash {
        // 挑战成立（succeeded）：操作方 forfeit 保证金
        let operator_forfeit = game.forfeit_deposit;
        let challenger_reward = compute_challenger_reward(operator_forfeit, challenge_reward_ratio);

        // 扣除操作方 forfeit 保证金（全额）
        game.forfeit_deposit = 0;
        game.version = game.version.saturating_add(1);

        // 返回 ChallengeSucceeded 通知 caller：
        // - 退还挑战方保证金
        // - 发放 challenger_reward 给挑战方
        // - 剩余（operator_forfeit - challenger_reward）按 buy_in 比例分配给受害者
        // - 触发 request_revert
        let _ = challenger_reward; // caller 通过 outcome 获取（此处用错误信号）
        let _ = operator_forfeit;
        Err(PokerL1Error::ChallengeSucceeded)
    } else {
        // 挑战失败（failed）：挑战方 forfeit 保证金，转入操作方
        game.forfeit_deposit = game.forfeit_deposit.saturating_add(tx.challenger_deposit);
        game.version = game.version.saturating_add(1);

        Err(PokerL1Error::ChallengeFailed)
    }
}

/// 计算 challenge_delta 结果详情（不修改状态，用于 caller 决策）。
///
/// 与 [`apply_challenge_delta`] 配合使用：先调用此函数获取 outcome，
/// 再调用 apply 函数应用状态变更。
#[must_use]
pub fn compute_challenge_delta_outcome(
    game: &GameContract,
    tx: &ChallengeDeltaTx,
    on_chain_state_delta_hash: Hash,
    challenge_reward_ratio: u32,
) -> ChallengeDeltaOutcome {
    let claimed_hash = tx.claimed_delta_hash();
    let succeeded = claimed_hash != on_chain_state_delta_hash;

    if succeeded {
        let operator_forfeit = game.forfeit_deposit;
        let challenger_reward = compute_challenger_reward(operator_forfeit, challenge_reward_ratio);
        ChallengeDeltaOutcome {
            succeeded: true,
            challenger_deposit_refunded: true,
            challenger_reward,
            operator_forfeit_amount: operator_forfeit,
            challenger_forfeit_amount: 0,
            triggers_request_revert: true,
        }
    } else {
        ChallengeDeltaOutcome {
            succeeded: false,
            challenger_deposit_refunded: false,
            challenger_reward: 0,
            operator_forfeit_amount: 0,
            challenger_forfeit_amount: tx.challenger_deposit,
            triggers_request_revert: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::{CURRENT_VERSION, SignatureScheme, TaggedPubkey};
    use crate::vm::contracts::types::{ExecutionMode, RakeConfigRef};

    fn make_addr(byte: u8) -> Address {
        [byte; 20]
    }

    fn make_game_id() -> ObjectID {
        ObjectID::new(make_addr(0x01), 1)
    }

    fn make_tagged_pubkey(byte: u8) -> TaggedPubkey {
        let mut raw = vec![byte];
        raw.extend_from_slice(&[0x02u8; 32]);
        TaggedPubkey::new(SignatureScheme::Secp256k1, CURRENT_VERSION, raw)
            .expect("构造 tagged pubkey 不应失败")
    }

    fn make_game(forfeit_deposit: u64) -> GameContract {
        let mut game = GameContract::new(
            make_game_id(),
            make_addr(0x01), // owner = operator
            make_tagged_pubkey(0xFF),
            ExecutionMode::OffChain,
            RakeConfigRef {
                rake_rate_bps: 0,
                rake_cap: 0,
                rake_recipient: make_addr(0x00),
            },
            10,
        );
        game.forfeit_deposit = forfeit_deposit;
        game
    }

    fn make_tx(claimed_state_delta: Vec<u8>, challenger_deposit: u64) -> ChallengeDeltaTx {
        ChallengeDeltaTx {
            game_id: make_game_id(),
            challenger: make_addr(0x02),
            claimed_state_delta,
            challenger_deposit,
        }
    }

    // ===== 常量测试 =====

    #[test]
    fn test_constants_sec_c4() {
        // SEC-C4：challenge_deposit_ratio 默认 50（原 10）
        assert_eq!(DEFAULT_CHALLENGE_DEPOSIT_RATIO, 50);
        // SEC-C4：challenge_reward_ratio 默认 100（原 50）
        assert_eq!(DEFAULT_CHALLENGE_REWARD_RATIO, 100);
        // 治理范围
        assert!(validate_challenge_deposit_ratio(1));
        assert!(validate_challenge_deposit_ratio(50));
        assert!(validate_challenge_deposit_ratio(100));
        assert!(!validate_challenge_deposit_ratio(0));
        assert!(!validate_challenge_deposit_ratio(101));
        assert!(validate_challenge_reward_ratio(10));
        assert!(validate_challenge_reward_ratio(100));
        assert!(!validate_challenge_reward_ratio(9));
        assert!(!validate_challenge_reward_ratio(101));
    }

    // ===== 辅助函数测试 =====

    #[test]
    fn test_compute_challenger_deposit() {
        // buy_in = 1000, ratio = 50 → deposit = 500
        assert_eq!(compute_challenger_deposit(1000, 50), 500);
        // buy_in = 1000, ratio = 100 → deposit = 1000
        assert_eq!(compute_challenger_deposit(1000, 100), 1000);
        // buy_in = 1000, ratio = 10 → deposit = 100
        assert_eq!(compute_challenger_deposit(1000, 10), 100);
    }

    #[test]
    fn test_compute_challenger_reward() {
        // forfeit_deposit = 10000, ratio = 100 → reward = 10000
        assert_eq!(compute_challenger_reward(10000, 100), 10000);
        // forfeit_deposit = 10000, ratio = 50 → reward = 5000
        assert_eq!(compute_challenger_reward(10000, 50), 5000);
    }

    #[test]
    fn test_hash_state_delta_consistency() {
        // 相同输入应产生相同哈希
        let delta = vec![0x01, 0x02, 0x03];
        let h1 = hash_state_delta(&delta);
        let h2 = hash_state_delta(&delta);
        assert_eq!(h1, h2);
        // 不同输入应产生不同哈希
        let delta2 = vec![0x01, 0x02, 0x04];
        let h3 = hash_state_delta(&delta2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_claimed_delta_hash_matches_hash_state_delta() {
        let tx = make_tx(vec![0xAA, 0xBB, 0xCC], 100);
        assert_eq!(
            tx.claimed_delta_hash(),
            hash_state_delta(&[0xAA, 0xBB, 0xCC])
        );
    }

    // ===== apply_challenge_delta 测试 =====

    #[test]
    fn test_apply_challenge_delta_succeeded_operator_forfeits() {
        // 挑战成立：hash(Δ) != state_delta_hash → 操作方 forfeit
        let mut game = make_game(10000);
        let tx = make_tx(vec![0xAA, 0xBB, 0xCC], 500);

        // on_chain_state_delta_hash != hash([0xAA, 0xBB, 0xCC])
        let on_chain_hash = [0xFF; 32];
        let prev_version = game.version;

        let result = apply_challenge_delta(&mut game, &tx, on_chain_hash, 100);
        assert!(
            matches!(result, Err(PokerL1Error::ChallengeSucceeded)),
            "Δ 不一致应触发 ChallengeSucceeded"
        );
        // 状态变更：forfeit_deposit 清零
        assert_eq!(game.forfeit_deposit, 0, "操作方 forfeit 保证金全额扣除");
        assert_eq!(game.version, prev_version.saturating_add(1));
    }

    #[test]
    fn test_apply_challenge_delta_failed_challenger_forfeits() {
        // 挑战失败：hash(Δ) == state_delta_hash → 挑战方 forfeit
        let mut game = make_game(10000);
        let claimed_delta = vec![0xAA, 0xBB, 0xCC];
        let tx = make_tx(claimed_delta.clone(), 500);

        // on_chain_state_delta_hash == hash(claimed_delta)
        let on_chain_hash = hash_state_delta(&claimed_delta);
        let prev_version = game.version;
        let prev_forfeit = game.forfeit_deposit;

        let result = apply_challenge_delta(&mut game, &tx, on_chain_hash, 100);
        assert!(
            matches!(result, Err(PokerL1Error::ChallengeFailed)),
            "Δ 一致应触发 ChallengeFailed"
        );
        // 状态变更：challenger_deposit 转入操作方 forfeit_deposit
        assert_eq!(
            game.forfeit_deposit,
            prev_forfeit + 500,
            "挑战方保证金没收转入操作方"
        );
        assert_eq!(game.version, prev_version.saturating_add(1));
    }

    #[test]
    fn test_apply_challenge_delta_wrong_game_id_rejected() {
        let mut game = make_game(10000);
        let mut tx = make_tx(vec![0xAA], 500);
        tx.game_id = ObjectID::new([0xFF; 20], 999);

        let result = apply_challenge_delta(&mut game, &tx, [0xFF; 32], 100);
        assert!(matches!(result, Err(PokerL1Error::GameNotFound(_))));
        // 状态不变
        assert_eq!(game.forfeit_deposit, 10000);
    }

    #[test]
    fn test_apply_challenge_delta_zero_forfeit_deposit_succeeded() {
        // 边界：操作方 forfeit_deposit = 0（已扣除过）+ 挑战成立
        let mut game = make_game(0);
        let tx = make_tx(vec![0xAA], 500);

        let result = apply_challenge_delta(&mut game, &tx, [0xFF; 32], 100);
        assert!(matches!(result, Err(PokerL1Error::ChallengeSucceeded)));
        assert_eq!(game.forfeit_deposit, 0);
    }

    #[test]
    fn test_apply_challenge_delta_zero_challenger_deposit_failed() {
        // 边界：挑战方保证金 = 0 + 挑战失败
        let mut game = make_game(10000);
        let claimed_delta = vec![0xAA];
        let tx = make_tx(claimed_delta.clone(), 0);
        let on_chain_hash = hash_state_delta(&claimed_delta);

        let result = apply_challenge_delta(&mut game, &tx, on_chain_hash, 100);
        assert!(matches!(result, Err(PokerL1Error::ChallengeFailed)));
        assert_eq!(game.forfeit_deposit, 10000, "无保证金可没收");
    }

    // ===== compute_challenge_delta_outcome 测试 =====

    #[test]
    fn test_compute_outcome_succeeded() {
        let game = make_game(10000);
        let tx = make_tx(vec![0xAA], 500);
        let on_chain_hash = [0xFF; 32];

        let outcome = compute_challenge_delta_outcome(&game, &tx, on_chain_hash, 100);
        assert!(outcome.succeeded);
        assert!(outcome.challenger_deposit_refunded);
        assert_eq!(
            outcome.challenger_reward, 10000,
            "SEC-C4: ratio=100 → 全额奖励"
        );
        assert_eq!(outcome.operator_forfeit_amount, 10000);
        assert_eq!(outcome.challenger_forfeit_amount, 0);
        assert!(outcome.triggers_request_revert);
    }

    #[test]
    fn test_compute_outcome_succeeded_partial_reward() {
        // SEC-C4: challenge_reward_ratio = 50 → 挑战方得 50%，剩余 50% 给受害者
        let game = make_game(10000);
        let tx = make_tx(vec![0xAA], 500);
        let on_chain_hash = [0xFF; 32];

        let outcome = compute_challenge_delta_outcome(&game, &tx, on_chain_hash, 50);
        assert!(outcome.succeeded);
        assert_eq!(outcome.challenger_reward, 5000, "ratio=50 → 半额奖励");
        assert_eq!(outcome.operator_forfeit_amount, 10000);
        // 剩余 5000 按 buy_in 比例分配给受害者（caller 负责）
    }

    #[test]
    fn test_compute_outcome_failed() {
        let game = make_game(10000);
        let claimed_delta = vec![0xAA];
        let tx = make_tx(claimed_delta.clone(), 500);
        let on_chain_hash = hash_state_delta(&claimed_delta);

        let outcome = compute_challenge_delta_outcome(&game, &tx, on_chain_hash, 100);
        assert!(!outcome.succeeded);
        assert!(!outcome.challenger_deposit_refunded);
        assert_eq!(outcome.challenger_reward, 0);
        assert_eq!(outcome.operator_forfeit_amount, 0);
        assert_eq!(outcome.challenger_forfeit_amount, 500);
        assert!(!outcome.triggers_request_revert);
    }

    #[test]
    fn test_compute_outcome_does_not_mutate() {
        // compute 函数不应修改 game 状态
        let game = make_game(10000);
        let tx = make_tx(vec![0xAA], 500);
        let prev_version = game.version;

        let _ = compute_challenge_delta_outcome(&game, &tx, [0xFF; 32], 100);
        assert_eq!(game.version, prev_version, "compute 不应修改 version");
        assert_eq!(
            game.forfeit_deposit, 10000,
            "compute 不应修改 forfeit_deposit"
        );
    }
}
