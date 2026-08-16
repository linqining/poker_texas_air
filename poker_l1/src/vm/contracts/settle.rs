//! Poker settle 台费逻辑（Task 16 — SubTask 16.4）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）第 307-339 行：
//! - **第 317-321 行**：Game 调用合约 `settle` 函数结束一局时，合约按配置的
//!   台费规则（比例 / 封顶 / 收款方）从底池扣除台费，剩余部分分配给胜者。
//!   台费收款方由合约配置（可配置为 validator 奖励池以覆盖免 gas 成本）。
//! - **第 323-327 行（M1 修复）**：settle 时底池为 0（所有人 preflop fold 到大盲），
//!   合约跳过台费扣除（台费 = `min(rake_rate × pot, rake_cap) = 0`），不产生负数。
//!
//! # 台费公式
//!
//! `rake = min(rake_rate_bps * pot / 10_000, rake_cap)`
//!
//! - `rake_rate_bps`：台费比例（basis points，100 = 1%，max 1000 = 10%）
//! - `rake_cap`：单手牌台费封顶金额
//! - `rake_recipient`：台费收款方地址
//!
//! # 安全约束
//!
//! - 台费不得超过底池（`rake <= pot`）
//! - 胜者分配金额 = `pot - rake`，不得为负
//! - 底池为 0 时台费 = 0，跳过分配

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::Address;
use crate::error::{PokerL1Error, PokerL1Result};

use super::types::HandState;

/// 台费配置（spec.md 第 317-321 行）。
///
/// 由合约部署时配置，链底层不硬编码。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct RakeConfig {
    /// 台费比例（basis points，100 = 1%，max 1000 = 10%）。
    ///
    /// 安全上限：1000 bps（10%），超过视为配置错误。
    pub rake_rate_bps: u32,
    /// 台费封顶金额（单手牌最高台费）。
    pub rake_cap: u64,
    /// 台费收款方地址（可配置为 validator 奖励池）。
    pub rake_recipient: Address,
}

impl RakeConfig {
    /// 台费比例上限（10%）。
    pub const MAX_RAKE_RATE_BPS: u32 = 1000;

    /// 校验台费配置合法性。
    pub fn validate(&self) -> PokerL1Result<()> {
        if self.rake_rate_bps > Self::MAX_RAKE_RATE_BPS {
            return Err(PokerL1Error::Other(format!(
                "rake_rate_bps {} > MAX_RAKE_RATE_BPS {}",
                self.rake_rate_bps,
                Self::MAX_RAKE_RATE_BPS
            )));
        }
        Ok(())
    }
}

/// settle 结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct SettleResult {
    /// 底池总额。
    pub pot: u64,
    /// 台费金额（= min(rake_rate * pot, rake_cap)）。
    pub rake: u64,
    /// 台费收款方。
    pub rake_recipient: Address,
    /// 胜者分得金额（= pot - rake）。
    pub winner_payout: u64,
    /// 胜者地址。
    pub winner: Address,
}

/// settle 错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SettleError {
    /// 底池为负（不应发生）。
    #[error("pot underflow")]
    PotUnderflow,
    /// 无有效胜者（所有玩家已 fold）。
    #[error("no winner (all players folded)")]
    NoWinner,
    /// 台费配置非法。
    #[error("invalid rake config: {0}")]
    InvalidRakeConfig(String),
}

/// 计算台费金额（spec.md 第 327 行：`rake = min(rake_rate × pot, rake_cap)`）。
///
/// **M1 修复**：底池为 0 时返回 0，不产生负数。
///
/// # 参数
///
/// - `pot`：底池总额
/// - `config`：台费配置
///
/// # 返回
///
/// 台费金额（≤ pot）。
#[must_use]
pub fn compute_rake(pot: u64, config: &RakeConfig) -> u64 {
    if pot == 0 {
        return 0; // M1 修复：底池为 0 跳过台费
    }
    // rake = pot * rake_rate_bps / 10_000
    let rake_by_rate = pot.saturating_mul(u64::from(config.rake_rate_bps)) / 10_000;
    // rake = min(rake_by_rate, rake_cap)
    let rake = rake_by_rate.min(config.rake_cap);
    // 安全约束：rake <= pot（防止配置错误导致负数）
    rake.min(pot)
}

/// 执行 settle 结算（spec.md 第 317-327 行）。
///
/// # 流程
///
/// 1. 校验台费配置
/// 2. 确定胜者（最后一个未 fold 的玩家）
/// 3. 计算台费 `rake = min(rake_rate × pot, rake_cap)`（底池为 0 时跳过）
/// 4. 胜者分得 `pot - rake`
/// 5. 台费转入 `rake_recipient`
///
/// # 参数
///
/// - `hand`：当前手牌状态
/// - `config`：台费配置
///
/// # 错误
///
/// - [`SettleError::NoWinner`]：所有玩家已 fold
/// - [`SettleError::InvalidRakeConfig`]：台费配置非法
pub fn settle_hand(hand: &HandState, config: &RakeConfig) -> Result<SettleResult, SettleError> {
    // 校验台费配置
    config
        .validate()
        .map_err(|e| SettleError::InvalidRakeConfig(e.to_string()))?;

    // 确定胜者（最后一个未 fold 的玩家）
    let winner = hand
        .players
        .iter()
        .find(|p| !p.folded)
        .ok_or(SettleError::NoWinner)?;

    let pot = hand.pot;
    let rake = compute_rake(pot, config);

    // 安全约束：rake <= pot（compute_rake 已保证，此处二次校验）
    let winner_payout = pot.checked_sub(rake).ok_or(SettleError::PotUnderflow)?;

    Ok(SettleResult {
        pot,
        rake,
        rake_recipient: config.rake_recipient,
        winner_payout,
        winner: winner.address,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object_model::ObjectID;
    use crate::vm::contracts::types::{GamePhase, PlayerStack};

    fn make_addr(byte: u8) -> Address {
        [byte; 20]
    }

    fn make_rake_config(rate_bps: u32, cap: u64) -> RakeConfig {
        RakeConfig {
            rake_rate_bps: rate_bps,
            rake_cap: cap,
            rake_recipient: make_addr(0xff),
        }
    }

    fn make_hand(pot: u64, folded: &[bool]) -> HandState {
        let players: Vec<PlayerStack> = folded
            .iter()
            .enumerate()
            .map(|(i, &f)| {
                let mut p = PlayerStack::new(make_addr(i as u8 + 1));
                p.folded = f;
                p
            })
            .collect();
        HandState {
            phase: GamePhase::Showdown,
            pot,
            current_bet: 0,
            big_blind_amount: 20,
            small_blind_amount: 10,
            raise_count: 0,
            bet_count: 0,
            current_turn: make_addr(1),
            players,
            last_action_height: 100,
            hand_start_height: 90,
        }
    }

    // ===== compute_rake 测试 =====

    #[test]
    fn test_compute_rake_basic() {
        let config = make_rake_config(500, 1000); // 5%, cap 1000
        // pot = 1000, rake = 1000 * 5% = 50
        assert_eq!(compute_rake(1000, &config), 50);
    }

    #[test]
    fn test_compute_rake_capped() {
        let config = make_rake_config(500, 30); // 5%, cap 30
        // pot = 1000, rake_by_rate = 50, but cap = 30 → rake = 30
        assert_eq!(compute_rake(1000, &config), 30);
    }

    #[test]
    fn test_compute_rake_zero_pot() {
        // M1 修复：底池为 0 时台费 = 0
        let config = make_rake_config(500, 1000);
        assert_eq!(compute_rake(0, &config), 0);
    }

    #[test]
    fn test_compute_rake_zero_rate() {
        let config = make_rake_config(0, 1000); // 0%
        assert_eq!(compute_rake(1000, &config), 0);
    }

    #[test]
    fn test_compute_rake_never_exceeds_pot() {
        // 即使 cap 配置错误（cap > pot），rake 也不得超过 pot
        let config = make_rake_config(1000, 10_000); // 10%, cap 10000
        let pot = 100;
        let rake = compute_rake(pot, &config);
        assert!(rake <= pot, "rake {rake} must not exceed pot {pot}");
        // rake_by_rate = 100 * 10% = 10, cap = 10000, min(10, 10000) = 10, min(10, 100) = 10
        assert_eq!(rake, 10);
    }

    #[test]
    fn test_compute_rake_full_rate() {
        // 10% rate (max allowed)
        let config = make_rake_config(1000, 1000);
        assert_eq!(compute_rake(1000, &config), 100);
    }

    // ===== settle_hand 测试 =====

    #[test]
    fn test_settle_hand_basic() {
        let config = make_rake_config(500, 1000); // 5%, cap 1000
        let hand = make_hand(1000, &[false, true, true]); // p1 胜

        let result = settle_hand(&hand, &config).expect("settle 应成功");

        assert_eq!(result.pot, 1000);
        assert_eq!(result.rake, 50); // 1000 * 5%
        assert_eq!(result.winner_payout, 950); // 1000 - 50
        assert_eq!(result.winner, make_addr(1));
        assert_eq!(result.rake_recipient, make_addr(0xff));
    }

    #[test]
    fn test_settle_hand_zero_pot() {
        // M1 修复：底池为 0 跳过台费
        let config = make_rake_config(500, 1000);
        let hand = make_hand(0, &[false, true]); // p1 胜，pot=0

        let result = settle_hand(&hand, &config).expect("settle 应成功");

        assert_eq!(result.pot, 0);
        assert_eq!(result.rake, 0, "底池为 0 时台费必须为 0");
        assert_eq!(result.winner_payout, 0, "胜者分得 0");
        assert_eq!(result.winner, make_addr(1));
    }

    #[test]
    fn test_settle_hand_capped_rake() {
        let config = make_rake_config(500, 30); // 5%, cap 30
        let hand = make_hand(1000, &[false, true]); // p1 胜

        let result = settle_hand(&hand, &config).expect("settle 应成功");

        assert_eq!(result.rake, 30, "台费应被 cap 限制");
        assert_eq!(result.winner_payout, 970); // 1000 - 30
    }

    #[test]
    fn test_settle_hand_all_folded_error() {
        let config = make_rake_config(500, 1000);
        let hand = make_hand(1000, &[true, true]); // 全 fold

        let result = settle_hand(&hand, &config);
        assert!(matches!(result, Err(SettleError::NoWinner)));
    }

    #[test]
    fn test_settle_hand_invalid_rake_config() {
        let config = RakeConfig {
            rake_rate_bps: 2000, // 超过 10% 上限
            rake_cap: 1000,
            rake_recipient: make_addr(0xff),
        };
        let hand = make_hand(1000, &[false, true]);

        let result = settle_hand(&hand, &config);
        assert!(matches!(result, Err(SettleError::InvalidRakeConfig(_))));
    }

    #[test]
    fn test_settle_hand_winner_is_last_unfolded() {
        let config = make_rake_config(0, 1000); // 0% rake
        let hand = make_hand(500, &[true, true, false, true]); // p3 胜

        let result = settle_hand(&hand, &config).expect("settle 应成功");

        assert_eq!(result.winner, make_addr(3));
        assert_eq!(result.winner_payout, 500);
        assert_eq!(result.rake, 0);
    }

    #[test]
    fn test_rake_config_validate() {
        assert!(make_rake_config(0, 1000).validate().is_ok());
        assert!(make_rake_config(500, 1000).validate().is_ok());
        assert!(make_rake_config(1000, 1000).validate().is_ok()); // 上限

        let bad = RakeConfig {
            rake_rate_bps: 1001,
            rake_cap: 1000,
            rake_recipient: make_addr(0xff),
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn test_settle_hand_multiple_winners_takes_first() {
        // 多个未 fold 玩家时取第一个（实际 poker 有 side pot 逻辑，此处简化）
        let config = make_rake_config(500, 1000);
        let hand = make_hand(1000, &[false, false, true]); // p1, p2 未 fold

        let result = settle_hand(&hand, &config).expect("settle 应成功");
        assert_eq!(result.winner, make_addr(1)); // 取第一个
    }

    #[test]
    fn test_settle_hand_id_type_check() {
        // 验证 SettleResult 字段类型与 spec 一致
        let config = make_rake_config(500, 1000);
        let hand = make_hand(1000, &[false, true]);

        let result = settle_hand(&hand, &config).unwrap();

        let _: u64 = result.pot;
        let _: u64 = result.rake;
        let _: Address = result.rake_recipient;
        let _: u64 = result.winner_payout;
        let _: Address = result.winner;
    }

    #[test]
    fn test_settle_hand_object_id_independent() {
        // 验证 settle 不依赖 ObjectID（纯牌局逻辑）
        let _id1 = ObjectID::new(make_addr(1), 1);
        let _id2 = ObjectID::new(make_addr(2), 2);
        let config = make_rake_config(500, 1000);
        let hand = make_hand(1000, &[false, true]);

        let result = settle_hand(&hand, &config).unwrap();
        assert_eq!(result.rake, 50);
    }
}
