//! forfeit 保证金扣除/分配/退还（SubTask 28.9 — R4-L6 + SEC-C4 + R5-H3 + SEC-L8 + SEC2-M7）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）+ tasks.md SubTask 28.9：
//! - **R4-L6 修正 — Game 创建时预锁 forfeit 保证金**：
//!   - 普通操作方（玩家）：`forfeit_deposit = total_table_buy_in * forfeit_deposit_ratio / 100`
//!   - designated operator（非玩家）：`forfeit_deposit = designated_operator_bond_amount`
//! - **SEC-C4 修复 — 保证金基数**：由"操作方 buy_in_amount"改为"桌面总 buy-in（所有玩家
//!   buy-in 之和）"，确保 forfeit 足以补偿所有受害者
//! - **SEC-C4 修复 — 分配规则**：挑战成立后操作方 forfeit 保证金分配 =
//!   `挑战方得 challenge_reward_ratio %（默认 100%），剩余按 buy_in 比例分配给其他受害者玩家`
//! - **R5-H3 修正 — designated operator forfeit 保证金**：
//!   - 若操作方为 designated operator（非玩家，无 buy_in_amount），
//!     forfeit 保证金 = `designated_operator_bond_amount`
//!   - **SEC-L8 修复**：默认 = 桌面所有玩家 buy-in 的中位数 `median(buy_in)`，
//!     避免异常值拉高平均
//! - **forfeit 保证金独立于 slashing 保证金**
//! - **Game 结算后未触发 forfeit 则退还操作方**
//!
//! # 触发场景
//!
//! forfeit 由以下 tx 触发（`should_forfeit = true` 时调用 [`apply_forfeit`]）：
//! - `force_checkin`（H4：`last_checkpoint_age <= boundary` → MaliciousWithholding）
//! - `challenge_delta`（Δ 不一致 → ChallengeSucceeded）
//! - `force_revert` / `request_revert`（reason = malicious_withholding / data_unavailable）
//! - `refuse_ack`（evidence 验证失败，SubTask 27.7）
//!
//! # 分配算法（SEC-C4）
//!
//! 1. `operator_forfeit = game.forfeit_deposit`（全额扣除）
//! 2. `challenger_reward = min(challenger_reward, operator_forfeit)`（挑战方奖励，可为 0）
//! 3. `remaining = operator_forfeit - challenger_reward`
//! 4. `total_victims_buy_in = sum(victims.buy_in)`
//! 5. 每个 victim 得 `remaining * victim.buy_in / total_victims_buy_in`
//! 6. 舍入余额归最后一个 victim（防总额短缺）

use serde::{Deserialize, Serialize};

use crate::Address;
use crate::error::PokerL1Error;
use crate::object_model::ObjectID;

use super::force_checkin::ForfeitReason;
use super::types::GameContract;

// ===== 常量（SEC-C4 + R4-L6）=====

/// forfeit 保证金比例默认值（SEC-C4 / R4-L6：默认 100，等额桌面总 buy-in）。
///
/// `forfeit_deposit = total_table_buy_in * forfeit_deposit_ratio / 100`。
/// 可治理 ∈ [10, 200]。
pub const DEFAULT_FORFEIT_DEPOSIT_RATIO: u32 = 100;

/// `forfeit_deposit_ratio` 治理下限（R4-L6）。
pub const MIN_FORFEIT_DEPOSIT_RATIO: u32 = 10;

/// `forfeit_deposit_ratio` 治理上限（R4-L6）。
pub const MAX_FORFEIT_DEPOSIT_RATIO: u32 = 200;

// ===== ForfeitDistribution =====

/// forfeit 保证金分配方案（SEC-C4）。
///
/// 由 [`compute_forfeit_distribution`] 计算，[`apply_forfeit`] 返回。
/// caller 据此实际转账给挑战方与各受害者。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForfeitDistribution {
    /// 操作方被扣除的 forfeit 保证金总额。
    pub operator_forfeit_amount: u64,
    /// 挑战方获得的奖励（从 forfeit 保证金中分得，可为 0）。
    pub challenger_reward: u64,
    /// 挑战方地址（Some 表示由 challenge_delta 触发，None 表示无挑战方）。
    pub challenger: Option<Address>,
    /// 受害者玩家分配列表 `(address, amount)`（按 buy-in 比例分配剩余）。
    pub victim_distributions: Vec<(Address, u64)>,
    /// 实际分配总额（= challenger_reward + sum(victim_distributions.amount)）。
    pub total_distributed: u64,
}

// ===== ForfeitOutcome / RefundOutcome =====

/// forfeit 应用结果（SubTask 28.9）。
///
/// 调用 [`apply_forfeit`] 后返回，caller 据此执行实际转账。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForfeitOutcome {
    /// 是否成功触发 forfeit（`game.forfeit_deposit > 0` 时为 true）。
    pub forfeited: bool,
    /// 扣除的 forfeit 保证金总额（= 变更前的 `game.forfeit_deposit`）。
    pub forfeit_amount: u64,
    /// 触发原因（MaliciousWithholding / MachineFailure / 等）。
    pub reason: ForfeitReason,
    /// 保证金分配方案。
    pub distribution: ForfeitDistribution,
}

/// forfeit 退还结果（SubTask 28.9：Game 结算后未触发 forfeit 则退还操作方）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefundOutcome {
    /// 是否成功退还（`game.forfeit_deposit > 0` 时为 true）。
    pub refunded: bool,
    /// 退还金额（= 变更前的 `game.forfeit_deposit`）。
    pub refund_amount: u64,
    /// 操作方地址（退还收款方）。
    pub operator: Address,
}

// ===== 辅助函数 =====

/// 计算普通操作方的 forfeit 保证金（R4-L6 + SEC-C4）。
///
/// `forfeit_deposit = total_table_buy_in * forfeit_deposit_ratio / 100`
///
/// # 参数
/// - `total_table_buy_in`：桌面所有玩家 buy-in 之和（SEC-C4：基数改为桌面总 buy-in）
/// - `forfeit_deposit_ratio`：forfeit 保证金比例（默认 100，可治理 ∈ [10, 200]）
#[must_use]
pub const fn compute_forfeit_deposit(total_table_buy_in: u64, forfeit_deposit_ratio: u32) -> u64 {
    total_table_buy_in.saturating_mul(forfeit_deposit_ratio as u64) / 100
}

/// 计算 designated operator 的 forfeit 保证金（R5-H3 + SEC-L8）。
///
/// **SEC-L8 修复**：默认 = 桌面所有玩家 buy-in 的中位数 `median(buy_in)`，
/// 避免异常值拉高平均。
///
/// # 参数
/// - `buy_ins`：桌面所有玩家的 buy-in 列表
///
/// # 返回
/// buy-in 中位数。空列表返回 0。
///
/// # 算法
/// - 排序后取中位数
/// - 奇数个：取中间元素
/// - 偶数个：取中间两个的平均（向下取整）
#[must_use]
pub fn compute_designated_operator_bond(buy_ins: &[u64]) -> u64 {
    if buy_ins.is_empty() {
        return 0;
    }
    let mut sorted = buy_ins.to_vec();
    sorted.sort_unstable();
    let len = sorted.len();
    if len % 2 == 1 {
        // 奇数：取中间
        sorted[len / 2]
    } else {
        // 偶数：取中间两个的平均（向下取整）
        let mid1 = sorted[len / 2 - 1];
        let mid2 = sorted[len / 2];
        (mid1 + mid2) / 2
    }
}

/// 校验 `forfeit_deposit_ratio` 治理参数范围（R4-L6：∈ [10, 200]）。
#[must_use]
pub const fn validate_forfeit_deposit_ratio(ratio: u32) -> bool {
    ratio >= MIN_FORFEIT_DEPOSIT_RATIO && ratio <= MAX_FORFEIT_DEPOSIT_RATIO
}

/// 校验 designated operator bond_amount（SEC2-M7）。
///
/// **SEC2-M7 修复**：
/// - bond_amount 须 == 治理参数 `designated_operator_bond_amount`（操作方不可自行设置）
/// - bond_amount 须 >= 桌面总 buy-in
///
/// # 参数
/// - `bond_amount`：任命 tx 中的 bond_amount
/// - `governed_bond_amount`：治理参数 `designated_operator_bond_amount`
/// - `total_table_buy_in`：桌面总 buy-in
///
/// # 返回
/// - `Ok(())`：校验通过
/// - `Err(InvalidBondAmount)`：bond_amount != 治理参数
/// - `Err(InsufficientOperatorBond)`：bond_amount < 桌面总 buy-in
pub const fn validate_designated_operator_bond(
    bond_amount: u64,
    governed_bond_amount: u64,
    total_table_buy_in: u64,
) -> Result<(), PokerL1Error> {
    if bond_amount != governed_bond_amount {
        return Err(PokerL1Error::InvalidBondAmount {
            expected: governed_bond_amount,
            got: bond_amount,
        });
    }
    if bond_amount < total_table_buy_in {
        return Err(PokerL1Error::InsufficientOperatorBond {
            bond: bond_amount,
            required: total_table_buy_in,
        });
    }
    Ok(())
}

// ===== 分配计算（SEC-C4）=====

/// 计算 forfeit 保证金分配方案（SEC-C4，不修改状态）。
///
/// # 分配规则
/// 1. `operator_forfeit = forfeit_amount`（全额扣除）
/// 2. `challenger_reward = min(challenger_reward, operator_forfeit)`（挑战方奖励）
/// 3. `remaining = operator_forfeit - challenger_reward`
/// 4. `remaining` 按 buy-in 比例分配给受害者玩家
/// 5. 舍入余额归最后一个 victim（防总额短缺）
///
/// # 参数
/// - `forfeit_amount`：操作方 forfeit 保证金总额
/// - `challenger`：挑战方地址（None 表示无挑战方，全部按 buy-in 分配给受害者）
/// - `challenger_reward`：挑战方奖励金额（可为 0）
/// - `victims`：受害者列表 `(address, buy_in_amount)`
///
/// # 返回
/// [`ForfeitDistribution`]，caller 据此执行实际转账。
#[must_use]
pub fn compute_forfeit_distribution(
    forfeit_amount: u64,
    challenger: Option<Address>,
    challenger_reward: u64,
    victims: &[(Address, u64)],
) -> ForfeitDistribution {
    // 挑战方奖励上限 = forfeit_amount（不可超额）
    let actual_challenger_reward = challenger_reward.min(forfeit_amount);
    let remaining = forfeit_amount.saturating_sub(actual_challenger_reward);

    // 按买in比例分配剩余给受害者
    let total_victims_buy_in: u64 = victims.iter().map(|(_, b)| *b).sum();
    let mut victim_distributions: Vec<(Address, u64)> = Vec::with_capacity(victims.len());

    if remaining == 0 || victims.is_empty() {
        // 无剩余或无受害者：不分配
    } else if total_victims_buy_in == 0 {
        // 所有 victim buy_in = 0：均分剩余
        let equal_share = remaining / victims.len() as u64;
        let mut distributed: u64 = 0;
        for (i, (addr, _)) in victims.iter().enumerate() {
            let amount = if i == victims.len() - 1 {
                // 最后一个 victim 得舍入余额
                remaining - distributed
            } else {
                equal_share
            };
            victim_distributions.push((*addr, amount));
            distributed += amount;
        }
    } else {
        // 按 buy-in 比例分配
        let mut distributed: u64 = 0;
        for (i, (addr, buy_in)) in victims.iter().enumerate() {
            let amount = if i == victims.len() - 1 {
                // 最后一个 victim 得舍入余额（防总额短缺）
                remaining - distributed
            } else {
                (remaining * (*buy_in))
                    .checked_div(total_victims_buy_in)
                    .unwrap_or(0)
            };
            victim_distributions.push((*addr, amount));
            distributed += amount;
        }
    }

    let total_distributed =
        actual_challenger_reward.saturating_add(victim_distributions.iter().map(|(_, a)| *a).sum());

    ForfeitDistribution {
        operator_forfeit_amount: forfeit_amount,
        challenger_reward: actual_challenger_reward,
        challenger,
        victim_distributions,
        total_distributed,
    }
}

// ===== apply_forfeit =====

/// 应用 forfeit 到 GameContract（SubTask 28.9）。
///
/// 触发 forfeit 时调用：全额扣除 `game.forfeit_deposit` 并计算分配方案。
/// caller 据返回的 [`ForfeitOutcome`] 执行实际转账。
///
/// # 流程
/// 1. 校验 `game.id == tx_game_id`（若传入）
/// 2. 记录 `forfeit_amount = game.forfeit_deposit`（BEFORE mutation）
/// 3. 全额扣除：`game.forfeit_deposit = 0`
/// 4. 计算分配方案（SEC-C4：挑战方得 challenger_reward，剩余按 buy-in 比例给受害者）
/// 5. 递增 `game.version`
///
/// # 参数
/// - `game`：可变的 GameContract 引用
/// - `game_id`：tx 携带的 game_id（用于校验，传 `None` 跳过校验）
/// - `reason`：forfeit 原因
/// - `challenger`：挑战方地址（None 表示非 challenge_delta 触发）
/// - `challenger_reward`：挑战方奖励金额（可为 0）
/// - `victims`：受害者列表 `(address, buy_in_amount)`
///
/// # 返回
/// [`ForfeitOutcome`]，`forfeited = false` 当 `game.forfeit_deposit` 已为 0。
///
/// # 错误
/// - [`PokerL1Error::GameNotFound`]：`game_id` 不匹配
pub fn apply_forfeit(
    game: &mut GameContract,
    game_id: Option<&ObjectID>,
    reason: ForfeitReason,
    challenger: Option<Address>,
    challenger_reward: u64,
    victims: &[(Address, u64)],
) -> Result<ForfeitOutcome, PokerL1Error> {
    // 1. 校验 game_id（若传入）
    if let Some(gid) = game_id
        && &game.id != gid
    {
        return Err(PokerL1Error::GameNotFound(*gid));
    }

    // 2. 记录 forfeit_amount（BEFORE mutation）
    let forfeit_amount = game.forfeit_deposit;

    // 3. 全额扣除
    game.forfeit_deposit = 0;

    // 4. 计算分配方案
    let distribution =
        compute_forfeit_distribution(forfeit_amount, challenger, challenger_reward, victims);

    // 5. 递增 version
    game.version = game.version.saturating_add(1);

    let forfeited = forfeit_amount > 0;
    Ok(ForfeitOutcome {
        forfeited,
        forfeit_amount,
        reason,
        distribution,
    })
}

/// 应用 forfeit 退还到 GameContract（SubTask 28.9）。
///
/// Game 结算后未触发 forfeit 则退还操作方。
/// caller 据返回的 [`RefundOutcome`] 执行实际退款转账。
///
/// # 流程
/// 1. 记录 `refund_amount = game.forfeit_deposit`（BEFORE mutation）
/// 2. 清零：`game.forfeit_deposit = 0`
/// 3. 递增 `game.version`
///
/// # 参数
/// - `game`：可变的 GameContract 引用
/// - `operator`：操作方地址（退款收款方）
///
/// # 返回
/// [`RefundOutcome`]，`refunded = false` 当 `game.forfeit_deposit` 已为 0。
pub const fn apply_forfeit_refund(game: &mut GameContract, operator: Address) -> RefundOutcome {
    let refund_amount = game.forfeit_deposit;
    game.forfeit_deposit = 0;
    game.version = game.version.saturating_add(1);

    let refunded = refund_amount > 0;
    RefundOutcome {
        refunded,
        refund_amount,
        operator,
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

    // ===== 常量测试 =====

    #[test]
    fn test_constants_sec_c4() {
        // SEC-C4 / R4-L6：forfeit_deposit_ratio 默认 100（等额桌面总 buy-in）
        assert_eq!(DEFAULT_FORFEIT_DEPOSIT_RATIO, 100);
        // 治理范围 [10, 200]
        assert_eq!(MIN_FORFEIT_DEPOSIT_RATIO, 10);
        assert_eq!(MAX_FORFEIT_DEPOSIT_RATIO, 200);
    }

    #[test]
    fn test_validate_forfeit_deposit_ratio() {
        assert!(validate_forfeit_deposit_ratio(10));
        assert!(validate_forfeit_deposit_ratio(100));
        assert!(validate_forfeit_deposit_ratio(200));
        assert!(!validate_forfeit_deposit_ratio(9));
        assert!(!validate_forfeit_deposit_ratio(201));
        assert!(!validate_forfeit_deposit_ratio(0));
    }

    // ===== compute_forfeit_deposit 测试 =====

    #[test]
    fn test_compute_forfeit_deposit_default_ratio() {
        // SEC-C4: ratio = 100 → 等额桌面总 buy-in
        assert_eq!(compute_forfeit_deposit(1000, 100), 1000);
        assert_eq!(compute_forfeit_deposit(500, 100), 500);
    }

    #[test]
    fn test_compute_forfeit_deposit_half_ratio() {
        // ratio = 50 → 半额
        assert_eq!(compute_forfeit_deposit(1000, 50), 500);
    }

    #[test]
    fn test_compute_forfeit_deposit_double_ratio() {
        // ratio = 200 → 双倍（可治理上限）
        assert_eq!(compute_forfeit_deposit(1000, 200), 2000);
    }

    #[test]
    fn test_compute_forfeit_deposit_zero_buy_in() {
        assert_eq!(compute_forfeit_deposit(0, 100), 0);
    }

    #[test]
    fn test_compute_forfeit_deposit_saturating() {
        // 防溢出
        let _ = compute_forfeit_deposit(u64::MAX, 200);
    }

    // ===== compute_designated_operator_bond 测试（SEC-L8）=====

    #[test]
    fn test_designated_operator_bond_odd_count() {
        // 奇数个：取中间
        let buy_ins = vec![100, 300, 500];
        assert_eq!(compute_designated_operator_bond(&buy_ins), 300);
    }

    #[test]
    fn test_designated_operator_bond_even_count() {
        // 偶数个：取中间两个的平均（向下取整）
        let buy_ins = vec![100, 200, 300, 400];
        // (200 + 300) / 2 = 250
        assert_eq!(compute_designated_operator_bond(&buy_ins), 250);
    }

    #[test]
    fn test_designated_operator_bond_even_count_floor() {
        // 偶数个 + 奇数和：向下取整（201 + 300 = 501, 501/2 = 250）
        let buy_ins = vec![100, 201, 300, 400];
        // sorted = [100, 201, 300, 400], mid1 = 201, mid2 = 300
        // (201 + 300) / 2 = 250 (floor of 250.5)
        assert_eq!(compute_designated_operator_bond(&buy_ins), 250);
    }

    #[test]
    fn test_designated_operator_bond_single() {
        let buy_ins = vec![500];
        assert_eq!(compute_designated_operator_bond(&buy_ins), 500);
    }

    #[test]
    fn test_designated_operator_bond_empty() {
        assert_eq!(compute_designated_operator_bond(&[]), 0);
    }

    #[test]
    fn test_designated_operator_bond_unsorted_input() {
        // 输入未排序，函数内部应排序
        let buy_ins = vec![500, 100, 300, 200, 400];
        // sorted = [100, 200, 300, 400, 500], median = 300
        assert_eq!(compute_designated_operator_bond(&buy_ins), 300);
    }

    #[test]
    fn test_designated_operator_bond_avoids_outlier() {
        // SEC-L8：中位数避免异常值拉高平均
        let buy_ins = vec![100, 100, 100, 10000];
        // sorted = [100, 100, 100, 10000], mid1 = 100, mid2 = 100
        // median = 100（而非平均 = 2575）
        assert_eq!(compute_designated_operator_bond(&buy_ins), 100);
    }

    // ===== validate_designated_operator_bond 测试（SEC2-M7）=====

    #[test]
    fn test_validate_designated_operator_bond_ok() {
        // bond_amount == governed && bond_amount >= total_buy_in
        assert!(validate_designated_operator_bond(1000, 1000, 800).is_ok());
        assert!(validate_designated_operator_bond(1000, 1000, 1000).is_ok());
    }

    #[test]
    fn test_validate_designated_operator_bond_mismatch() {
        // bond_amount != governed
        let result = validate_designated_operator_bond(500, 1000, 800);
        assert!(matches!(
            result,
            Err(PokerL1Error::InvalidBondAmount {
                expected: 1000,
                got: 500
            })
        ));
    }

    #[test]
    fn test_validate_designated_operator_bond_insufficient() {
        // bond_amount < total_buy_in
        let result = validate_designated_operator_bond(500, 500, 800);
        assert!(matches!(
            result,
            Err(PokerL1Error::InsufficientOperatorBond {
                bond: 500,
                required: 800
            })
        ));
    }

    // ===== compute_forfeit_distribution 测试（SEC-C4）=====

    #[test]
    fn test_distribution_with_challenger_full_reward() {
        // SEC-C4: challenge_reward_ratio = 100 → 挑战方得全额，受害者得 0
        let dist = compute_forfeit_distribution(
            10000,
            Some(make_addr(0x02)),
            10000, // 全额奖励
            &[(make_addr(0x03), 500), (make_addr(0x04), 500)],
        );
        assert_eq!(dist.operator_forfeit_amount, 10000);
        assert_eq!(dist.challenger_reward, 10000);
        assert_eq!(dist.challenger, Some(make_addr(0x02)));
        assert_eq!(dist.total_distributed, 10000);
        // remaining = 0 → 受害者得 0
        assert!(dist.victim_distributions.iter().all(|(_, a)| *a == 0));
    }

    #[test]
    fn test_distribution_with_challenger_partial_reward() {
        // SEC-C4: challenge_reward_ratio = 50 → 挑战方得 50%，剩余 50% 按 buy-in 分配
        let dist = compute_forfeit_distribution(
            10000,
            Some(make_addr(0x02)),
            5000, // 半额奖励
            &[(make_addr(0x03), 300), (make_addr(0x04), 700)],
        );
        assert_eq!(dist.challenger_reward, 5000);
        // remaining = 5000, total_buy_in = 1000
        // victim1 = 5000 * 300 / 1000 = 1500
        // victim2 = 5000 - 1500 = 3500 (舍入余额)
        assert_eq!(dist.victim_distributions[0], (make_addr(0x03), 1500));
        assert_eq!(dist.victim_distributions[1], (make_addr(0x04), 3500));
        assert_eq!(dist.total_distributed, 10000);
    }

    #[test]
    fn test_distribution_no_challenger() {
        // 无挑战方：全部按 buy-in 分配给受害者
        let dist = compute_forfeit_distribution(
            10000,
            None,
            0,
            &[(make_addr(0x03), 400), (make_addr(0x04), 600)],
        );
        assert_eq!(dist.challenger_reward, 0);
        assert!(dist.challenger.is_none());
        // victim1 = 10000 * 400 / 1000 = 4000
        // victim2 = 10000 - 4000 = 6000
        assert_eq!(dist.victim_distributions[0], (make_addr(0x03), 4000));
        assert_eq!(dist.victim_distributions[1], (make_addr(0x04), 6000));
        assert_eq!(dist.total_distributed, 10000);
    }

    #[test]
    fn test_distribution_no_victims() {
        // 无受害者：挑战方得全额（或全部"丢失"若无挑战方）
        let dist = compute_forfeit_distribution(10000, Some(make_addr(0x02)), 10000, &[]);
        assert_eq!(dist.challenger_reward, 10000);
        assert!(dist.victim_distributions.is_empty());
        assert_eq!(dist.total_distributed, 10000);
    }

    #[test]
    fn test_distribution_zero_forfeit_amount() {
        // forfeit_deposit = 0：无分配
        let dist =
            compute_forfeit_distribution(0, Some(make_addr(0x02)), 0, &[(make_addr(0x03), 100)]);
        assert_eq!(dist.operator_forfeit_amount, 0);
        assert_eq!(dist.challenger_reward, 0);
        assert_eq!(dist.total_distributed, 0);
    }

    #[test]
    fn test_distribution_challenger_reward_capped() {
        // challenger_reward > forfeit_amount → 截断为 forfeit_amount
        let dist = compute_forfeit_distribution(
            5000,
            Some(make_addr(0x02)),
            10000, // 超过 forfeit_amount
            &[(make_addr(0x03), 100)],
        );
        assert_eq!(dist.challenger_reward, 5000, "奖励截断为 forfeit_amount");
        assert_eq!(dist.total_distributed, 5000);
    }

    #[test]
    fn test_distribution_victims_zero_buy_in_equal_split() {
        // 所有 victim buy_in = 0：均分剩余
        let dist = compute_forfeit_distribution(
            9000,
            None,
            0,
            &[
                (make_addr(0x03), 0),
                (make_addr(0x04), 0),
                (make_addr(0x05), 0),
            ],
        );
        // remaining = 9000, 3 victims → 3000 each
        // 但用均分：9000 / 3 = 3000, 最后一个得 9000 - 6000 = 3000
        assert_eq!(dist.victim_distributions[0], (make_addr(0x03), 3000));
        assert_eq!(dist.victim_distributions[1], (make_addr(0x04), 3000));
        assert_eq!(dist.victim_distributions[2], (make_addr(0x05), 3000));
        assert_eq!(dist.total_distributed, 9000);
    }

    #[test]
    fn test_distribution_rounding_to_last_victim() {
        // 舍入余额归最后一个 victim（防总额短缺）
        let dist = compute_forfeit_distribution(
            100,
            None,
            0,
            &[
                (make_addr(0x03), 1),
                (make_addr(0x04), 1),
                (make_addr(0x05), 1),
            ],
        );
        // remaining = 100, total_buy_in = 3
        // victim1 = 100 * 1 / 3 = 33
        // victim2 = 100 * 1 / 3 = 33
        // victim3 = 100 - 66 = 34 (舍入余额)
        assert_eq!(dist.victim_distributions[0], (make_addr(0x03), 33));
        assert_eq!(dist.victim_distributions[1], (make_addr(0x04), 33));
        assert_eq!(dist.victim_distributions[2], (make_addr(0x05), 34));
        assert_eq!(dist.total_distributed, 100);
    }

    // ===== apply_forfeit 测试 =====

    #[test]
    fn test_apply_forfeit_deducts_deposit() {
        let mut game = make_game(10000);
        let prev_version = game.version;
        let victims = vec![(make_addr(0x03), 500), (make_addr(0x04), 500)];

        let outcome = apply_forfeit(
            &mut game,
            Some(&make_game_id()),
            ForfeitReason::MaliciousWithholding,
            None,
            0,
            &victims,
        )
        .expect("应成功");

        assert!(outcome.forfeited);
        assert_eq!(outcome.forfeit_amount, 10000);
        assert_eq!(outcome.reason, ForfeitReason::MaliciousWithholding);
        assert_eq!(game.forfeit_deposit, 0, "forfeit_deposit 全额扣除");
        assert_eq!(game.version, prev_version.saturating_add(1));
        // 无挑战方 → 全部分给受害者
        assert_eq!(outcome.distribution.total_distributed, 10000);
    }

    #[test]
    fn test_apply_forfeit_with_challenger() {
        let mut game = make_game(10000);
        let victims = vec![(make_addr(0x03), 300), (make_addr(0x04), 700)];

        let outcome = apply_forfeit(
            &mut game,
            None,
            ForfeitReason::MaliciousWithholding,
            Some(make_addr(0x02)),
            5000, // challenger 得 50%
            &victims,
        )
        .expect("应成功");

        assert_eq!(outcome.distribution.challenger_reward, 5000);
        assert_eq!(outcome.distribution.challenger, Some(make_addr(0x02)));
        // remaining = 5000, victim1 = 5000*300/1000 = 1500, victim2 = 3500
        assert_eq!(
            outcome.distribution.victim_distributions[0],
            (make_addr(0x03), 1500)
        );
        assert_eq!(
            outcome.distribution.victim_distributions[1],
            (make_addr(0x04), 3500)
        );
    }

    #[test]
    fn test_apply_forfeit_zero_deposit() {
        // forfeit_deposit = 0（已扣除过）：forfeited = false
        let mut game = make_game(0);
        let outcome = apply_forfeit(
            &mut game,
            None,
            ForfeitReason::MaliciousWithholding,
            None,
            0,
            &[(make_addr(0x03), 100)],
        )
        .expect("应成功");

        assert!(!outcome.forfeited, "forfeit_deposit=0 → forfeited=false");
        assert_eq!(outcome.forfeit_amount, 0);
        assert_eq!(outcome.distribution.total_distributed, 0);
    }

    #[test]
    fn test_apply_forfeit_wrong_game_id() {
        let mut game = make_game(10000);
        let wrong_id = ObjectID::new([0xFF; 20], 999);

        let result = apply_forfeit(
            &mut game,
            Some(&wrong_id),
            ForfeitReason::MaliciousWithholding,
            None,
            0,
            &[],
        );
        assert!(matches!(result, Err(PokerL1Error::GameNotFound(_))));
        // 状态不变
        assert_eq!(game.forfeit_deposit, 10000);
    }

    #[test]
    fn test_apply_forfeit_increments_version() {
        let mut game = make_game(1000);
        let prev_version = game.version;

        apply_forfeit(
            &mut game,
            None,
            ForfeitReason::MaliciousWithholding,
            None,
            0,
            &[],
        )
        .expect("应成功");

        assert_eq!(game.version, prev_version.saturating_add(1));
    }

    #[test]
    fn test_apply_forfeit_machine_failure_reason() {
        let mut game = make_game(1000);
        let outcome = apply_forfeit(&mut game, None, ForfeitReason::MachineFailure, None, 0, &[])
            .expect("应成功");

        assert_eq!(outcome.reason, ForfeitReason::MachineFailure);
    }

    // ===== apply_forfeit_refund 测试 =====

    #[test]
    fn test_apply_forfeit_refund_full() {
        // Game 结算后未触发 forfeit → 退还操作方
        let mut game = make_game(10000);
        let operator = make_addr(0x01);
        let prev_version = game.version;

        let outcome = apply_forfeit_refund(&mut game, operator);

        assert!(outcome.refunded);
        assert_eq!(outcome.refund_amount, 10000);
        assert_eq!(outcome.operator, operator);
        assert_eq!(game.forfeit_deposit, 0, "forfeit_deposit 清零");
        assert_eq!(game.version, prev_version.saturating_add(1));
    }

    #[test]
    fn test_apply_forfeit_refund_zero_deposit() {
        // forfeit_deposit = 0（已扣除或未预锁）：refunded = false
        let mut game = make_game(0);
        let operator = make_addr(0x01);

        let outcome = apply_forfeit_refund(&mut game, operator);

        assert!(!outcome.refunded);
        assert_eq!(outcome.refund_amount, 0);
    }

    #[test]
    fn test_apply_forfeit_refund_increments_version() {
        let mut game = make_game(500);
        let prev_version = game.version;

        apply_forfeit_refund(&mut game, make_addr(0x01));

        assert_eq!(game.version, prev_version.saturating_add(1));
    }

    #[test]
    fn test_apply_forfeit_then_refund_zero() {
        // 先 forfeit 再 refund → refund 得 0（forfeit_deposit 已清零）
        let mut game = make_game(10000);
        apply_forfeit(
            &mut game,
            None,
            ForfeitReason::MaliciousWithholding,
            None,
            0,
            &[],
        )
        .expect("forfeit 应成功");

        let outcome = apply_forfeit_refund(&mut game, make_addr(0x01));
        assert!(!outcome.refunded, "forfeit 已扣除 → refund 得 0");
        assert_eq!(outcome.refund_amount, 0);
    }

    // ===== designated_operator_bond 字段测试 =====

    #[test]
    fn test_game_contract_has_designated_operator_bond_field() {
        let game = make_game(0);
        assert_eq!(
            game.designated_operator_bond, 0,
            "新 Game 默认 designated_operator_bond = 0"
        );
    }

    #[test]
    fn test_designated_operator_bond_independent_of_forfeit_deposit() {
        // designated_operator_bond 与 forfeit_deposit 是独立字段
        let mut game = make_game(0);
        game.forfeit_deposit = 5000;
        game.designated_operator_bond = 3000;
        assert_eq!(game.forfeit_deposit, 5000);
        assert_eq!(game.designated_operator_bond, 3000);
    }
}
