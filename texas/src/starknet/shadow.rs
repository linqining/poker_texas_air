//! 影子证明机（Phase 1，VM-first 迁移第一步）。
//!
//! 游戏层每接受一个动作，同一命令**实时** dispatch 到一张影子 VM 表
//! （单遍 + deferred reveal 缓冲——正是 Phase 2 权威切换要运行的语义），
//! 手牌结束时把影子 VM 的终局派生（board / rake / 逐钱包 deltas）与游戏层
//! 事实逐分比对。分歧只记日志、绝不阻断牌局——它是 Phase 0 结算对账的
//! 提前量：在派奖当下就暴露双引擎分歧，并归因到具体命令。
//!
//! 与结算重放（mirror.rs `build_from_log`）的区别：重放在结算时刻把整份
//! 日志重排两遍消化；影子表按到达序单遍应用——度量"单遍 live dispatch
//! 的失配率"正是本阶段要采集的数据（bet apply 失败 = 重放靠两遍重排掩盖
//! 的乱序场景，Phase 2 权威切换前必须清零的缺口）。
//!
//! 开关：`TEXAS_SHADOW_PROVER=1`（默认关闭——reveal 会在影子表里再做一次
//! EC 验证，双倍开销，由运营在灰度环境显式打开）。测试可用
//! `set_enabled_for_test` 直接开关。

use poker_l1::vm::contracts::texas_poker::settlement::{
    derive_fold_win_plan, derive_settlement_plan,
};
use poker_l1::vm::contracts::texas_poker::types::HandPhase;

use super::mirror::{seat_player_addr, TableMirror};
use super::prove_log::{HandCommand, HandSettleInput};

/// 单手影子表：一张 live VM + 命令映射 + deferred 缓冲 + 计数。
pub struct ShadowHand {
    table_id: u32,
    hand_id: u32,
    mirror: TableMirror,
    /// pk_hex（游戏层座位标识）→ VM 20 字节地址。
    by_pk: std::collections::HashMap<String, poker_l1::Address>,
    /// wallet hex → VM 20 字节地址。
    by_wallet: std::collections::HashMap<String, poker_l1::Address>,
    /// VM 20 字节地址 → 参与者钱包 hex（终局 deltas 对账回全精度 felt 用）。
    addr_to_wallet: std::collections::HashMap<poker_l1::Address, String>,
    /// 到达时相位未开、等待未来窗口的 reveal（单遍语义的乱序容忍）。
    deferred: Vec<(u8, Vec<poker_protocol::z_poker::protocol::RevealToken>)>,
    metrics: Metrics,
}

#[derive(Default, Debug, Clone)]
pub struct Metrics {
    pub commands: usize,
    pub reveal_ok: usize,
    pub reveal_deferred: usize,
    pub reveal_flushed: usize,
    pub bet_ok: usize,
    pub bet_fail: usize,
    pub force_folds: usize,
    pub unknown_player: usize,
}

/// 终局比对报告（finish 时产出；测试经 take_last_report_for_test 读取）。
#[derive(Debug, Clone)]
pub struct FinishReport {
    pub table_id: u32,
    pub hand_id: u32,
    pub metrics: Metrics,
    /// 单遍未能消化的 deferred reveal 数。
    pub unmatched_reveals: usize,
    /// 派生/对账分歧（空 = 影子 VM 与游戏层完全一致）。
    pub issues: Vec<String>,
}

impl ShadowHand {
    /// 开局引导（deck 注入 + DealHole 窗口），与结算重放同一 bootstrap。
    pub fn start(
        table_id: u32,
        start: &super::prove_log::HandStartData,
    ) -> Result<Self, String> {
        let mirror = super::mirror::mirror_bootstrap(table_id, start, start.hand_id)?;
        let mut by_pk = std::collections::HashMap::new();
        let mut by_wallet = std::collections::HashMap::new();
        let mut addr_to_wallet = std::collections::HashMap::new();
        for p in &start.participants {
            if let Some(addr) = TableMirror::addr_from_starknet(&p.wallet) {
                by_pk.insert(p.pk_hex.clone(), addr);
                by_wallet.insert(p.wallet.clone(), addr);
                addr_to_wallet.insert(addr, p.wallet.clone());
            }
        }
        Ok(Self {
            table_id,
            hand_id: start.hand_id,
            mirror,
            by_pk,
            by_wallet,
            addr_to_wallet,
            deferred: Vec::new(),
            metrics: Metrics::default(),
        })
    }

    /// 应用一条实时采集的命令（单遍语义）。
    pub fn on_command(&mut self, cmd: &HandCommand) {
        self.metrics.commands += 1;
        match cmd {
            HandCommand::RevealTokens { pk_hex, tokens } => {
                let Some(seat) = self.seat_of_pk(pk_hex) else {
                    self.metrics.unknown_player += 1;
                    tracing::warn!(
                        "[shadow] table {} hand {}: reveal from unknown pk {pk_hex}",
                        self.table_id, self.hand_id
                    );
                    return;
                };
                match self.mirror.apply_recorded_reveal(seat, tokens) {
                    Ok(()) => {
                        self.metrics.reveal_ok += 1;
                        self.flush_deferred();
                    }
                    Err(_e) => {
                        // 到达早于窗口（或乱序）——缓冲，由后续命令冲刷重试。
                        self.metrics.reveal_deferred += 1;
                        self.deferred.push((seat, tokens.clone()));
                    }
                }
            }
            HandCommand::Bet { pk_hex, action, total_bet } => {
                self.flush_deferred();
                let Some(seat) = self.seat_of_pk(pk_hex) else {
                    self.metrics.unknown_player += 1;
                    tracing::warn!(
                        "[shadow] table {} hand {}: bet from unknown pk {pk_hex}",
                        self.table_id, self.hand_id
                    );
                    return;
                };
                match self.mirror.apply_recorded_bet(seat, action, *total_bet) {
                    Ok(()) => self.metrics.bet_ok += 1,
                    Err(e) => {
                        // 单遍 live 语义下的真失配：结算重放靠两遍重排消化，
                        // 权威切换后没有"重排时间"——必须在此显式暴露。
                        self.metrics.bet_fail += 1;
                        tracing::warn!(
                            "[shadow] table {} hand {}: bet apply failed (one-pass divergence) \
                             seat {seat} action {action} total_bet {total_bet:?}: {e}",
                            self.table_id, self.hand_id
                        );
                    }
                }
                self.flush_deferred();
            }
            HandCommand::ForceFold { wallet } => {
                let Some(addr) = self.by_wallet.get(wallet) else {
                    return; // 非本手参与者（跨手残留）：与结算重放同语义跳过
                };
                if let Some(seat) = self.mirror.seat_index_of(*addr) {
                    self.mirror.apply_recorded_force_fold(seat);
                    self.metrics.force_folds += 1;
                    self.flush_deferred();
                }
            }
        }
    }

    /// 手牌结束：冲刷缓冲 → 派奖推进 → 派生结算计划 → 与游戏层事实对账。
    pub fn finish(mut self, input: &HandSettleInput) -> FinishReport {
        self.flush_deferred();
        let unmatched_reveals = self.deferred.len();
        if unmatched_reveals > 0 {
            tracing::warn!(
                "[shadow] table {} hand {}: {unmatched_reveals} deferred reveal(s) never matched a VM window",
                self.table_id, self.hand_id
            );
        }

        let mut issues: Vec<String> = Vec::new();

        // 摊牌展示期 → 派奖前快照 + 推进 VM 复位（与结算重放收尾一致）。
        if matches!(
            self.mirror.table.hand_phase,
            HandPhase::ShowdownDisplay { .. }
        ) {
            self.mirror.mark_pre_settlement();
            if let Err(e) = self.mirror.advance_deadline() {
                issues.push(format!("payout advance failed: {e}"));
            }
        }

        // pre-payout 表：fold-win 快照先落终局弃牌（与 submit::settle_hand 同一语义）。
        let fold_snapshot = self
            .mirror
            .pre_settlement_final_fold
            .zip(self.mirror.pre_settlement.as_ref())
            .map(|(seat, snap)| super::submit::apply_pending_final_fold(snap, seat));
        let settle_table = fold_snapshot
            .as_ref()
            .or(self.mirror.pre_settlement.as_ref())
            .unwrap_or(&self.mirror.table);

        // 对账 1：公共牌数。
        if settle_table.community_cards.len() != input.board_len {
            issues.push(format!(
                "board mismatch: vm {} vs game {}",
                settle_table.community_cards.len(),
                input.board_len
            ));
        }

        // 对账 2/3：rake 与逐钱包净输赢（复用 hooks 的单一对账规则）。
        let unfolded_count = settle_table
            .seats
            .iter()
            .filter(|seat| seat.is_occupied() && !seat.is_folded() && !seat.has_left_hand())
            .count();
        let plan = if unfolded_count <= 1 {
            derive_fold_win_plan(settle_table)
        } else {
            derive_settlement_plan(settle_table)
        };
        match plan {
            Err(e) => issues.push(format!("plan derivation failed: {e}")),
            Ok(plan) => {
                if plan.rake != input.rake_collected {
                    issues.push(format!(
                        "rake mismatch: vm {} vs game {}",
                        plan.rake, input.rake_collected
                    ));
                }
                let mut players: Vec<starknet_ff::FieldElement> = Vec::new();
                let mut deltas: Vec<i128> = Vec::new();
                for (i, seat) in settle_table.seats.iter().enumerate() {
                    let Some(addr) = seat_player_addr(seat) else { continue };
                    let total_bet = seat.total_bet();
                    let award = plan.awards.get(i).copied().unwrap_or(0);
                    let delta = award as i128 - total_bet as i128;
                    if delta == 0 {
                        continue; // SettleHandCalldata 同语义跳过零 delta
                    }
                    let Some(wallet_hex) = self.addr_to_wallet.get(&addr) else {
                        issues.push(format!("seat {i} address not in participants"));
                        continue;
                    };
                    let Some(felt) =
                        super::chain::parse_felt(wallet_hex).map(|f| super::submit::felt_to_ff(&f))
                    else {
                        issues.push(format!("seat {i} wallet unparsable: {wallet_hex}"));
                        continue;
                    };
                    players.push(felt);
                    deltas.push(delta);
                }
                if let Err(e) = super::hooks::cross_check_deltas(&players, &deltas, input) {
                    issues.push(e);
                }
            }
        }

        FinishReport {
            table_id: self.table_id,
            hand_id: self.hand_id,
            metrics: self.metrics.clone(),
            unmatched_reveals,
            issues,
        }
    }

    fn seat_of_pk(&self, pk_hex: &str) -> Option<u8> {
        let addr = self.by_pk.get(pk_hex)?;
        self.mirror.seat_index_of(*addr)
    }

    /// 冲刷缓冲 reveal：反复尝试直到一轮无进展（归位一条可能解锁下一条）。
    fn flush_deferred(&mut self) {
        let Self { mirror, deferred, .. } = self;
        let mut progressed = true;
        while progressed {
            progressed = false;
            let mut i = 0;
            while i < deferred.len() {
                let (seat, tokens) = &deferred[i];
                if mirror.apply_recorded_reveal(*seat, tokens).is_ok() {
                    deferred.remove(i);
                    progressed = true;
                } else {
                    i += 1;
                }
            }
        }
    }
}

// ===== 全局登记表：record_* 采集点直连（同步应用，无线程） =====

static ENABLED_TEST: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static ENV_INIT: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

fn enabled() -> bool {
    let env_on = *ENV_INIT.get_or_init(|| {
        std::env::var("TEXAS_SHADOW_PROVER").ok().as_deref() == Some("1")
    });
    env_on || ENABLED_TEST.load(std::sync::atomic::Ordering::Relaxed)
}

/// 测试开关（进程级；对账只读不阻断，误开无副作用）。
#[cfg(test)]
pub(crate) fn set_enabled_for_test(on: bool) {
    ENABLED_TEST.store(on, std::sync::atomic::Ordering::Relaxed);
}

static SHADOWS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<u32, ShadowHand>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// 开局：record_hand_start 成功后调用（deck 终局时刻）。
pub fn hand_start(table_id: u32, start: &super::prove_log::HandStartData) {
    if !enabled() {
        return;
    }
    match ShadowHand::start(table_id, start) {
        Ok(sh) => {
            if let Ok(mut g) = SHADOWS.lock() {
                g.insert(table_id, sh);
            }
        }
        Err(e) => {
            tracing::warn!("[shadow] table {table_id} bootstrap failed: {e} — hand unshadowed");
        }
    }
}

/// 动作接受点：record_bet / record_reveal / record_force_fold 成功后调用。
pub fn on_command(table_id: u32, cmd: &HandCommand) {
    if !enabled() {
        return;
    }
    if let Ok(mut g) = SHADOWS.lock() {
        if let Some(sh) = g.get_mut(&table_id) {
            sh.on_command(cmd);
        }
    }
}

/// 终局：on_hand_complete 采集结算输入后调用（在结算/运行时检查之前，
/// 保证无 tokio runtime 的测试环境也执行）。
pub fn finish(input: &HandSettleInput) {
    if !enabled() {
        return;
    }
    let sh = SHADOWS.lock().ok().and_then(|mut g| g.remove(&input.table_id));
    let Some(sh) = sh else { return };
    let report = sh.finish(input);
    if report.issues.is_empty() && report.unmatched_reveals == 0 && report.metrics.bet_fail == 0 {
        tracing::info!(
            "[shadow] table {} hand {} parity OK: cmds={} reveal_ok={} flushed={} deferred={} bets={} folds={} \
             — one-pass live dispatch matches game layer",
            report.table_id, report.hand_id, report.metrics.commands,
            report.metrics.reveal_ok, report.metrics.reveal_flushed,
            report.metrics.reveal_deferred, report.metrics.bet_ok, report.metrics.force_folds,
        );
    } else {
        tracing::warn!(
            "[shadow] table {} hand {} DIVERGENCE: {:?}",
            report.table_id, report.hand_id, report
        );
    }
    #[cfg(test)]
    {
        if let Ok(mut g) = LAST_REPORTS.lock() {
            g.insert(report.table_id, report);
        }
    }
}

#[cfg(test)]
static LAST_REPORTS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<u32, FinishReport>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// 测试读取指定桌的最近一次影子终局报告。
#[cfg(test)]
pub(crate) fn take_last_report_for_test(table_id: u32) -> Option<FinishReport> {
    LAST_REPORTS.lock().ok().and_then(|mut g| g.remove(&table_id))
}
