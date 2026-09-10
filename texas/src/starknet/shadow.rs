//! 实时 VM 镜像——手牌的唯一 VM 状态表示（Phase 2b 权威切换载体）。
//!
//! 游戏层每个接受点同步 dispatch 到本模块持有的 VM 表（权威应用，
//! 拒绝即拒绝客户端动作），手牌结束时把 VM 终局派生（board / rake /
//! 逐钱包 deltas）与游戏层事实逐分比对。比对干净 → 这份镜像就是
//! **结算的唯一 VM 状态来源**（ProveTask 链、pre-payout 快照、状态根
//! 全部取自这里）；比对不干净 → fail-closed 拒绝该手结算。历史上
//! "结算时从日志重放出第二份 VM 状态"的 `build_from_log` 已删除。
//!
//! 权威域（Phase 2b 逐域切换完成情况）：
//! - **betting**：`mirror_try_bet`——VM 校验并应用，游戏层下注账本
//!   经 `apply_betting_view` 派生；turn 轮转归 VM。
//! - **reveal**：`mirror_try_reveal`——VM canonical 重排 + 证明验证 +
//!   窗口推进；游戏层 reveal_token_state 退化为 ceremony 调度视图。
//! - **deck**：洗牌仪式产物经 bootstrap 注入后为只读快照（方案A），
//!   非独立演化的状态。
//! - **生命周期**：街道推进/收尾由 VM 相位驱动游戏层 ceremony
//!   （apply_betting_view 的联锁触发）。
//!
//! 开关：默认开启（单一表示的正确性前提）；`TEXAS_SHADOW_PROVER=0`
//! 作为紧急停用开关（停用期间的手牌不可证明、不上链——与历史
//! "缺 join 证明则 hand unprovable" 同类语义）。
//!
//! 开销说明：reveal 在游戏层与 VM 各验证一次（双倍 EC 成本）——这是
//! 单一状态 + fail-closed 的代价；betting 动作为纯整数搬运，开销可忽略。

use poker_l1::vm::contracts::texas_poker::settlement::{
    derive_fold_win_plan, derive_settlement_plan,
};
use poker_l1::vm::contracts::texas_poker::types::HandPhase;

use super::mirror::{seat_player_addr, TableMirror};
use super::prove_log::HandSettleInput;

/// 游戏层 Table 的镜像接线（accept 点与权威入口）。
impl crate::pokergame::table::Table {
    /// 下注动作接受点与权威提交（betting.rs handle_*）：VM 校验并应用，
    /// 返回派生视图；None = 本手无实时镜像（不可证明手，走本地规则兜底）。
    pub fn mirror_try_bet(
        &mut self,
        pk_hex: &str,
        action: &'static str,
        total_bet: Option<u64>,
    ) -> Option<Result<BettingView, String>> {
        self.live_mirror
            .as_mut()
            .map(|sh| sh.try_bet(pk_hex, action, total_bet))
    }

    /// reveal 令牌接受点与权威提交（Table::submit_player_reveal_tokens）：
    /// VM canonical 重排 + 证明验证 + 窗口推进；None = 本手无实时镜像。
    pub fn mirror_try_reveal(
        &mut self,
        pk_hex: &str,
        tokens: &[poker_protocol::z_poker::protocol::RevealToken],
    ) -> Option<Result<RevealView, String>> {
        self.live_mirror
            .as_mut()
            .map(|sh| sh.try_reveal(pk_hex, tokens))
    }

    /// 强制弃牌接受点（手牌进行中移除玩家）。
    pub fn mirror_on_force_fold(&mut self, wallet: &str) {
        if let Some(sh) = self.live_mirror.as_mut() {
            sh.force_fold(wallet);
        }
    }
}

/// betting 域权威提交：VM 校验并应用，返回派生视图。
/// 单手实时镜像：一张 live VM + 命令映射 + 计数。
#[derive(Debug)]
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
    metrics: Metrics,
}

#[derive(Default, Debug, Clone)]
pub struct Metrics {
    pub reveal_ok: usize,
    pub bet_ok: usize,
    /// VM 拒绝的下注动作数（**观测指标，不是结算门**，2026-09-10 变更）：
    /// VM 是接受点本身，被拒动作游戏层同样拒绝，不构成状态分歧。hooks
    /// 的结算门只看 `FinishReport.issues`（对账分歧）；本计数仅 warn 日志，
    /// 用于监控客户端噪音（抢跑/轮次竞态/畸形加注）的规模。
    pub bet_fail: usize,
    pub force_folds: usize,
}

/// 终局比对报告（finish 时产出；测试经 take_last_report_for_test 读取）。
#[derive(Debug, Clone)]
pub struct FinishReport {
    pub table_id: u32,
    pub hand_id: u32,
    pub metrics: Metrics,
    /// 派生/对账分歧（空 = 实时 VM 与游戏层完全一致）。
    pub issues: Vec<String>,
}

/// betting 域的权威视图（从 VM 状态提取，游戏层据此派生自己的下注状态）。
#[derive(Debug, Clone, Default)]
pub struct BettingView {
    /// 全部座位（VM 座位序 = 参与者升序）。
    pub seats: Vec<BettingViewSeat>,
    /// VM 已收集底池（不含当前街在途下注）。
    pub pot: u64,
    /// 当前街在途下注合计（VM pot + street_bets = 游戏层派生 pot）。
    pub street_bets: u64,
    /// 当前行动者（pk hex；None = 无行动者/非下注相位）。
    pub current_turn_pk: Option<String>,
    /// VM 本轮当前注额。
    pub current_bet: Option<u64>,
    /// VM 本轮最小加注额。
    pub min_raise: Option<u64>,
    /// VM 是否处于下注相位。
    pub in_betting: bool,
    /// VM 已在本次 dispatch 内结束本手（fold-win）。
    pub hand_over: bool,
    /// 终局前底池（hand_over 时游戏层派奖基数）。
    pub fold_win_pot: Option<u64>,
}

/// reveal 域的权威视图（ceremony 调度用派生信息）。
#[derive(Debug, Clone, Default)]
pub struct RevealView {
    /// VM 揭牌窗口是否仍开启（false = 已全消化、相位已推进）。
    pub window_open: bool,
    /// 当前已揭示公共牌数。
    pub revealed_board: usize,
    /// 仍未提交的座位（pk hex，去重升序）。
    pub pending_pks: Vec<String>,
}

/// 单座位下注视图。
#[derive(Debug, Clone, Default)]
pub struct BettingViewSeat {
    pub pk_hex: String,
    pub folded: bool,
    pub bet: u64,
    pub total_bet: u64,
    pub stack: u64,
    pub has_acted: bool,
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
            metrics: Metrics::default(),
        })
    }

    /// reveal 域权威入口：VM 对令牌做 canonical 重排、覆盖性检查与
    /// 证明验证，并推进窗口（全消化时 normalize 自动进入下一相位）。
    /// 错误 = 动作非法，直接拒绝——与游戏层"窗口未开不接受"的客户端
    /// 契约一致，live 路径不再需要 deferred 队列（那是历史日志重放的
    /// 乱序补救，重放已删除）。
    pub fn try_reveal(
        &mut self,
        pk_hex: &str,
        tokens: &[poker_protocol::z_poker::protocol::RevealToken],
    ) -> Result<RevealView, String> {
        let seat = self
            .seat_of_pk(pk_hex)
            .ok_or_else(|| format!("reveal from unknown pk {pk_hex}"))?;
        self.mirror.apply_recorded_reveal(seat, tokens)?;
        self.metrics.reveal_ok += 1;
        Ok(self.reveal_view())
    }

    /// 从 VM 状态提取 reveal 视图（ceremony 调度用）。
    fn reveal_view(&self) -> RevealView {
        let t = &self.mirror.table;
        let pending_pks = t
            .reveal_token_state()
            .map(|st| {
                st.assignments
                    .iter()
                    .flat_map(|a| {
                        let m = a.pending_mask();
                        (0u8..16).filter(move |i| m & (1u16 << i) != 0)
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let pending_pks: Vec<String> = pending_pks
            .into_iter()
            .collect::<std::collections::BTreeSet<u8>>()
            .into_iter()
            .filter_map(|idx| {
                self.by_pk
                    .iter()
                    .find(|(_, addr)| self.mirror.seat_index_of(**addr) == Some(idx))
                    .map(|(pk, _)| pk.clone())
            })
            .collect();
        RevealView {
            window_open: t.reveal_token_state().is_some(),
            revealed_board: t.community_cards.len(),
            pending_pks,
        }
    }

    /// 强制弃牌（内部应用原语；VM 拒绝不致命——与旧同步路径语义一致）。
    fn force_fold(&mut self, wallet: &str) {
        let Some(addr) = self.by_wallet.get(wallet) else {
            return; // 非本手参与者（跨手残留）：跳过
        };
        if let Some(seat) = self.mirror.seat_index_of(*addr) {
            self.mirror.apply_recorded_force_fold(seat);
            self.metrics.force_folds += 1;
        }
    }

    /// 手牌结束：派奖推进 → 派生结算计划 → 与游戏层事实对账。
    ///
    /// 返回 (比对报告, 镜像)。镜像只有在报告**零分歧**（`issues` 为空）
    /// 时才可作为结算来源——调用方（hooks）按 issues 拒绝脏镜像。
    /// `metrics.bet_fail` 是**观测指标**（客户端噪音/非法动作计数），不是
    /// 结算门（2026-09-10：VM 拒绝的动作游戏层同样拒绝，不构成状态分歧；
    /// 把它当门会把"单条非法下注"变成拒结算的 griefing 武器）。
    pub fn finish(mut self, input: &HandSettleInput) -> (FinishReport, TableMirror) {
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
                let mut players: Vec<starknet_crypto::Felt> = Vec::new();
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
                    let Some(felt) = super::chain::parse_felt(wallet_hex)
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

        let report = FinishReport {
            table_id: self.table_id,
            hand_id: self.hand_id,
            metrics: self.metrics.clone(),
            issues,
        };
        #[cfg(test)]
        {
            if let Ok(mut g) = LAST_REPORTS.lock() {
                g.insert(report.table_id, report.clone());
            }
            if let Ok(mut g) = LAST_MIRRORS.lock() {
                g.insert(self.table_id, self.mirror.clone());
            }
        }
        let mirror = self.mirror;
        (report, mirror)
    }

    /// betting 域权威入口：VM 校验并应用下注动作（错误 = 非法动作，
    /// 直接上抛拒绝——不再被统计吞掉）。成功返回从 VM 状态提取的
    /// 下注视图，游戏层据此派生自己的下注状态（派生视图）。
    pub fn try_bet(
        &mut self,
        pk_hex: &str,
        action: &str,
        total_bet: Option<u64>,
    ) -> Result<BettingView, String> {
        let seat = self.seat_of_pk(pk_hex).ok_or_else(|| format!("bet from unknown pk {pk_hex}"))?;
        // 终局 fold 检测（与 apply_recorded_bet 的快照判定同构）：
        // 本次弃牌后只剩一名未弃牌玩家 → VM 将在本次 dispatch 内结束本手。
        let unfolded_others = self
            .mirror
            .table
            .seats
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != seat as usize)
            .filter(|(_, s)| s.is_occupied() && !s.is_folded() && !s.is_waiting())
            .count();
        let terminal_fold = action == "fold" && unfolded_others == 1;
        // 终局前的底池事实（VM pot + 在途下注）——游戏层派奖需要它：
        // VM 派奖在 dispatch 内部原子完成，事后 pot 已清零。
        let pre_pot = self.mirror.table.pot
            + self
                .mirror
                .table
                .seats
                .iter()
                .map(|s| s.bet())
                .sum::<u64>();

        if let Err(e) = self.mirror.apply_recorded_bet(seat, action, total_bet) {
            self.metrics.bet_fail += 1;
            return Err(e);
        }
        self.metrics.bet_ok += 1;

        let mut view = self.betting_view();
        if terminal_fold {
            view.hand_over = true;
            view.fold_win_pot = Some(pre_pot);
        }
        Ok(view)
    }

    /// 从 VM 状态提取下注视图（座位序 = 参与者升序，pk 反查映射）。
    fn betting_view(&self) -> BettingView {
        use poker_l1::vm::contracts::texas_poker::types::HandPhase;
        let t = &self.mirror.table;
        let mut pk_by_seat: Vec<(u8, &str)> = Vec::with_capacity(self.by_pk.len());
        for (pk, addr) in &self.by_pk {
            if let Some(idx) = self.mirror.seat_index_of(*addr) {
                pk_by_seat.push((idx, pk));
            }
        }
        pk_by_seat.sort_unstable();

        let (in_betting, current_bet, min_raise, current_turn) = match &t.hand_phase {
            HandPhase::Betting { round, current_turn, .. } => {
                (true, Some(round.current_bet), Some(round.min_raise), Some(*current_turn))
            }
            _ => (false, None, None, None),
        };
        let seats = t
            .seats
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let acted = t.acted_mask & (1u16 << i) != 0;
                BettingViewSeat {
                    pk_hex: pk_by_seat
                        .iter()
                        .find(|(idx, _)| *idx == i as u8)
                        .map(|(_, pk)| pk.to_string())
                        .unwrap_or_default(),
                    folded: s.is_folded(),
                    bet: s.bet(),
                    total_bet: s.total_bet(),
                    stack: s.stack(),
                    has_acted: acted,
                }
            })
            .collect();
        BettingView {
            seats,
            pot: t.pot,
            street_bets: t.seats.iter().map(|s| s.bet()).sum::<u64>(),
            current_turn_pk: current_turn
                .and_then(|idx| pk_by_seat.iter().find(|(i, _)| *i == idx))
                .map(|(_, pk)| pk.to_string()),
            current_bet,
            min_raise,
            in_betting,
            hand_over: false,
            fold_win_pot: None,
        }
    }

    fn seat_of_pk(&self, pk_hex: &str) -> Option<u8> {
        let addr = self.by_pk.get(pk_hex)?;
        self.mirror.seat_index_of(*addr)
    }

}

pub(crate) fn enabled() -> bool {
    static ENV_INIT: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENV_INIT.get_or_init(|| std::env::var("TEXAS_SHADOW_PROVER").ok().as_deref() != Some("0"))
}

/// 开局引导（record_hand_start 成功后由 Table 挂载，见 prove_log）。
pub(crate) fn bootstrap(
    table_id: u32,
    start: &super::prove_log::HandStartData,
) -> Option<ShadowHand> {
    if !enabled() {
        // 紧急停用开关：本手不挂载实时镜像，动作走游戏层本地兜底
        // （*_local / 本地轮转），该手不可证明、不上链（结算 fail-closed）。
        tracing::warn!(
            "[live-mirror] table {table_id} hand {}: disabled by TEXAS_SHADOW_PROVER=0 — hand unprovable",
            start.hand_id
        );
        return None;
    }
    match ShadowHand::start(table_id, start) {
        Ok(sh) => Some(sh),
        Err(e) => {
            tracing::warn!("[live-mirror] table {table_id} bootstrap failed: {e} — hand unprovable");
            None
        }
    }
}

#[cfg(test)]
static LAST_REPORTS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<u32, FinishReport>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// 测试读取指定桌的最近一次终局比对报告。
#[cfg(test)]
pub(crate) fn take_last_report_for_test(table_id: u32) -> Option<FinishReport> {
    LAST_REPORTS.lock().ok().and_then(|mut g| g.remove(&table_id))
}

#[cfg(test)]
static LAST_MIRRORS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<u32, TableMirror>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// 测试读取指定桌的最近一次终局镜像（on_hand_complete 已消费实时镜像，
/// 测试经此取用做生产结算路径验证）。
#[cfg(test)]
pub(crate) fn take_last_mirror_for_test(table_id: u32) -> Option<TableMirror> {
    LAST_MIRRORS.lock().ok().and_then(|mut g| g.remove(&table_id))
}
