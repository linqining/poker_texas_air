//! 链下抽水（rake）——与链上结算口径逐字对齐：
//! - 公式：`rake = min(pot * rake_bps / 10_000, rake_cap)`（poker_l1 `settle.rs::compute_rake`）
//! - 摊牌（contested）底池才抽；fold-win（uncontested）不抽
//!   （`state_machine.rs::end_without_showdown`、`SettlementPlan::validate`）
//! - 边池分层：仅争夺层（eligible ≥ 2）按比例分摊，余数按层序补齐
//!   （`settlement.rs::allocate_rake`）
//!
//! 参数来源与链上相同的环境变量（`starknet/config.rs`）：`STARKNET_RAKE_BPS` /
//! `STARKNET_RAKE_CAP`，缺省用 poker_l1 常量，保证链下显示与链上到账一致。

use std::sync::OnceLock;

use poker_l1::vm::contracts::texas_poker::constants::{DEFAULT_RAKE_BPS, DEFAULT_RAKE_CAP};

/// 抽水参数（进程级，从环境变量读一次）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RakeParams {
    /// 台费比例（basis points，500 = 5%）。
    pub rake_bps: u16,
    /// 单手牌台费封顶金额。
    pub rake_cap: u64,
}

static RAKE_PARAMS: OnceLock<RakeParams> = OnceLock::new();

/// 进程级抽水参数。首次调用时读环境变量并缓存。
pub fn rake_params() -> &'static RakeParams {
    RAKE_PARAMS.get_or_init(|| RakeParams {
        rake_bps: std::env::var("STARKNET_RAKE_BPS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_RAKE_BPS),
        rake_cap: std::env::var("STARKNET_RAKE_CAP")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_RAKE_CAP),
    })
}

/// 计算本手总台费（不修改状态）。u128 中间量避免 `pot * bps` 溢出。
pub fn compute_rake(pot: u64, params: &RakeParams) -> u64 {
    if pot == 0 {
        return 0;
    }
    let by_rate = (u128::from(pot) * u128::from(params.rake_bps) / 10_000) as u64;
    by_rate.min(params.rake_cap).min(pot)
}

/// 把总台费分摊到底池层（镜像链上 `allocate_rake`）。
///
/// `layers` 为 `(层金额, 争夺人数)`，顺序与链上一致：主池在前、边池按层级在后。
/// 仅争夺层（人数 ≥ 2）按 `层金额 / gross_pot` 比例承担；uncontested 层为 0；
/// 整除余数按层序补到争夺层（不超过该层剩余金额）。
///
/// 返回与 `layers` 等长的分摊列表，总和 ≤ `total_rake`
/// （正常对局必有争夺层，余数必然放得下；防御性 saturating，不再panic）。
pub fn allocate_rake(layers: &[(u64, usize)], total_rake: u64, gross_pot: u64) -> Vec<u64> {
    if total_rake == 0 || layers.is_empty() || gross_pot == 0 {
        return vec![0; layers.len()];
    }
    let mut allocations = vec![0u64; layers.len()];
    let mut allocated: u64 = 0;
    for (i, &(amount, eligible)) in layers.iter().enumerate() {
        if eligible >= 2 {
            let share =
                (u128::from(amount) * u128::from(total_rake) / u128::from(gross_pot)) as u64;
            allocations[i] = share;
            allocated = allocated.saturating_add(share);
        }
    }
    let mut remainder = total_rake.saturating_sub(allocated);
    for (i, &(amount, eligible)) in layers.iter().enumerate() {
        if remainder == 0 {
            break;
        }
        if eligible < 2 {
            continue;
        }
        let available = amount.saturating_sub(allocations[i]);
        let take = remainder.min(available);
        allocations[i] += take;
        remainder -= take;
    }
    allocations
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(bps: u16, cap: u64) -> RakeParams {
        RakeParams { rake_bps: bps, rake_cap: cap }
    }

    #[test]
    fn compute_rake_matches_chain_formula() {
        // 与 poker_l1 settle.rs 测试同参对齐
        assert_eq!(compute_rake(1000, &params(500, 1000)), 50);
        assert_eq!(compute_rake(1000, &params(500, 30)), 30);
        assert_eq!(compute_rake(0, &params(500, 1000)), 0);
        assert_eq!(compute_rake(1000, &params(0, 1000)), 0);
        assert_eq!(compute_rake(100, &params(1000, 10_000)), 10);
    }

    #[test]
    fn allocate_single_contested_layer() {
        // 无边池：整笔 rake 全落在主池
        let allocs = allocate_rake(&[(1000, 2)], 50, 1000);
        assert_eq!(allocs, vec![50]);
    }

    #[test]
    fn allocate_skips_uncontested_layers() {
        // 主池(3人争夺) + 边池(1人独占)：边池不承担
        let allocs = allocate_rake(&[(600, 3), (400, 1)], 50, 1000);
        assert_eq!(allocs, vec![50, 0]);
    }

    #[test]
    fn allocate_pro_rata_with_remainder() {
        // 1000 总池，rake 50：主池 600 → 30，边池 400 → 20，无余数
        let allocs = allocate_rake(&[(600, 2), (400, 2)], 50, 1000);
        assert_eq!(allocs, vec![30, 20]);
        // 700/300，rake 51：333…→ 35 与 15（整除向下），余数 1 补到首个争夺层
        let allocs = allocate_rake(&[(700, 2), (300, 2)], 51, 1000);
        assert_eq!(allocs[0] + allocs[1], 51);
        assert_eq!(allocs, vec![36, 15]);
    }

    #[test]
    fn allocate_zero_rake() {
        assert_eq!(allocate_rake(&[(1000, 2)], 0, 1000), vec![0]);
    }
}
