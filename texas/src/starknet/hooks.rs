//! 服务器接线钩子：把牌局事件桥接到 Starknet 结算（#20 Phase 2）。
//!
//! 常驻 mirror（第二本账）已移除。游戏层在接受动作的同一条代码路径上把
//! 已验证输入记录进 `prove_log::HandProofLog`；[`on_hand_complete`] 在锁外
//! 用日志**一次性**重放出 ProveTask 链与 pre-payout 快照（`mirror::build_from_log`），
//! 与游戏层终局事实强制对账后构建 register_aggregate/settle_hand 上链，
//! 失败由 game_loop tick 有界重试。
//!
//! 禁止事项（防止回到老路）：不再引入常驻镜像/实时同步；不新增"事后追赶"
//! 型补丁；不引入第二套密文派生（deck 必须同源）；不为绕过验证失败放宽
//! VM 证明校验；对账不一致宁可不结算，绝不带分歧状态上链。

use std::sync::OnceLock;
use super::mirror::{seat_player_addr, TableMirror};

/// 把 vault 的 settlement 绑定切到指定结算合约（operator 必须是 vault owner）。
/// settle 成功上链的 (table, mirror_hand) 集合：失败可重试（game_loop tick
/// 驱动），成功后幂等跳过。
static SETTLE_OK: OnceLock<std::sync::Mutex<std::collections::HashSet<(u32, u32)>>> =
    OnceLock::new();

fn settle_ok_once(table_id: u32, mirror_hand: u32) -> bool {
    let set = SETTLE_OK.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()));
    set.lock().map(|mut g| g.insert((table_id, mirror_hand))).unwrap_or(false)
}

pub(crate) fn settle_ok_already(table_id: u32, mirror_hand: u32) -> bool {
    let set = SETTLE_OK.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()));
    set.lock().map(|g| g.contains(&(table_id, mirror_hand))).unwrap_or(false)
}

/// 失败重试上限（防镜像状态与游戏永久分歧时的无限重试）。
static SETTLE_ATTEMPTS: OnceLock<std::sync::Mutex<std::collections::HashMap<(u32, u32), u32>>> =
    OnceLock::new();

fn settle_attempts_bumped_max(table_id: u32, mirror_hand: u32) -> bool {
    let m = SETTLE_ATTEMPTS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let mut g = match m.lock() { Ok(g) => g, Err(_) => return true };
    let k = (table_id, mirror_hand);
    let n = g.entry(k).or_insert(0);
    *n += 1;
    *n > 5
}

/// 待投递结算：按桌保留**构建时快照**（HandSettlement + mirror 克隆）。
/// 链上提交失败（nonce 竞争/RPC 抖动）时由 game_loop tick 用同一快照重投，
/// 绝不读取已被新手替换的 mirror 活状态（避免跨手状态污染）。
struct PendingSettle {
    settlement: super::submit::HandSettlement,
    mirror: TableMirror,
    attempts: u32,
}

static PENDING_SETTLE: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<u32, PendingSettle>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

const MAX_SETTLE_ATTEMPTS: u32 = 8;

/// 错误文本是否表示"本手已在链上结算过"（幂等重放）。
fn is_already_settled_error(e: &str) -> bool {
    e.contains("Binding already registered")
        || e.contains("Hand already settled")
        || e.contains("Digest already registered")
}

pub fn on_hand_complete(table: &Table) {
    // 阶段 1（快速，锁内只克隆）：提取本手证明输入日志 + 游戏层终局事实。
    // 日志重放（验证 EC 证明）与证明生成都是重活，必须全部移出写锁。
    let table_id = table.summary.id;
    if PENDING_SETTLE.lock().ok().map(|g| g.contains_key(&table_id)).unwrap_or(false) {
        // 上一手结算仍在重投队列：保留它（链上 hand_id 单调，两不冲突），
        // 新手结算不再入队以免覆盖。正常节奏下不会发生。
        tracing::warn!("[starknet-settle] table {table_id} previous settle still pending — skipped");
        return;
    }
    let Some(input) = super::prove_log::take_settle_input(table) else {
        return; // 本手未记录（未开局/缺 join 证明）——无可证明结算
    };
    // 无 tokio runtime 的环境（游戏层单测直接调 settle_hand）跳过链上
    // 结算——此前这里会 panic；生产恒有 runtime，不受影响。
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        tracing::warn!("[starknet-settle] no tokio runtime — settle skipped (test context)");
        return;
    };
    handle.spawn(async move {
        settle_hand_from_log(input).await;
    });
}

/// 锁外结算：日志一次性重放 → 强制对账 → 证明 → 入队上链。
async fn settle_hand_from_log(mut input: super::prove_log::HandSettleInput) {
    let table_id = input.table_id;
    let Some(start) = input.log.start.clone() else { return };
    // hand_id 在开局时由 record_hand_start 分配（动作签名挑战域同源）。
    let hand_id = start.hand_id;

    // 一次性构建（取代常驻 mirror）：按记录序重放已接受命令，产出
    // ProveTask 链 + pre-payout 快照。重放输入与游戏层接受输入逐字节相同，
    // 失败 = 记录/时序异常——显式放弃该手，绝不带着分歧状态结算。
    let mirror = match super::mirror::build_from_log(table_id, &start, &input.log.commands, hand_id) {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(
                "[starknet-settle] table {table_id} hand {hand_id} build failed: {e} — hand not settled"
            );
            return;
        }
    };
    if settle_ok_already(table_id, hand_id) {
        return; // 本手已成功上链（幂等）
    }
    if settle_attempts_bumped_max(table_id, hand_id) {
        return; // 重试上限：记录与游戏层永久分歧
    }
    // 强制对账（游戏层 = 唯一真相）：per-wallet total_bet 与公共牌数逐分一致。
    if let Err(e) = cross_check_snapshot(&mirror, &input) {
        tracing::error!(
            "[starknet-settle] table {table_id} hand {hand_id} cross-check FAILED: {e} — settlement refused"
        );
        return;
    }

    // 台费接收方：平台 treasury 地址（STARKNET_TREASURY_ADDRESS），
    // 未配置时缺省 operator（#27 遗留注释已实现，2026-09-04 清理）。
    let rake_recipient = {
        let cfg_treasury = super::chain()
            .map(|c| c.config.treasury_address.clone())
            .unwrap_or_default();
        let treasury_full = if cfg_treasury.trim().is_empty() {
            super::chain()
                .map(|c| c.config.operator_address.clone())
                .unwrap_or_default()
        } else {
            cfg_treasury
        };
        if treasury_full.trim().is_empty() {
            None
        } else {
            register_treasury_wallet(&treasury_full);
            TableMirror::addr_from_starknet(&treasury_full)
        }
    };

    // 完整钱包 felt 记账：参与者映射来自本手记录（无全局截断重映射表）。
    let wallet_map = hand_wallet_map(&start);

    // #18 Phase B/C：game 层产出的本手动作日志（词条 + Poseidon 链根）——
    // 根词进 settlement digest 尾词，词条进电路见证。
    let action_log_digest = starknet_ff::FieldElement::from_bytes_be(&input.action_log_digest)
        .expect("action log digest is a canonical felt");
    // settle_hand 为同步 CPU 重活（prove 约 2s/手），按其调用方约定放
    // spawn_blocking，避免占死一个 tokio worker。mirror 移入闭包借用后
    // 原样带回（后续还要进 PENDING_SETTLE），action_log 取走所有权。
    let (settlement, mirror) = {
        let action_log = std::mem::take(&mut input.action_log);
        match tokio::task::spawn_blocking(move || {
            let result = super::submit::settle_hand(
                &mirror,
                rake_recipient,
                &wallet_map,
                action_log_digest,
                &action_log,
            );
            (result, mirror)
        })
        .await
        {
            Ok((Ok(s), m)) => (s, m),
            Ok((Err(e), _)) => {
                tracing::warn!("[starknet-settle] table {table_id} hand {hand_id} settlement build failed: {e}");
                // 第三类终局：结算构建失败（一次性、无重试）——该手永不
                // 上链（无 debit/credit，零和守恒），挂在该手上的离桌释放
                // 不能等 settle，在此 flush（与 refund_all_bets 中止路径
                // 同语义；2026-09-07 hand 1788734417 board-0 线上盲区）。
                super::lock::abort_flush_leave_releases(hand_id);
                return;
            }
            Err(join_err) => {
                tracing::error!("[starknet-settle] table {table_id} hand {hand_id} settlement build task panicked: {join_err}");
                super::lock::abort_flush_leave_releases(hand_id);
                return;
            }
        }
    };
    // 对账 2：抽水必须与游戏层同分（前端筹码 / 牌史 / 链上三本账的锚）。
    if settlement.plan.rake != input.rake_collected {
        tracing::error!(
            "[starknet-settle] table {table_id} hand {hand_id} rake mismatch: plan {} vs game {} — settlement refused",
            settlement.plan.rake,
            input.rake_collected
        );
        return;
    }
    tracing::info!(
        "[starknet-settle] table {table_id} hand {} settled: aggregate={}",
        settlement.hand_id,
        hex_encode(&settlement.aggregate_digest)
    );

    // ===== snip36 模式：异步递归证明（action-sig 批次）→ 提交 =====
    // 非 snip36 模式（legacy/v2）不启动任何证明进程。
    if super::chain()
        .map(|c| c.config.settlement_mode_snip36())
        .unwrap_or(false)
    {
        let dual_addr = super::chain()
            .map(|c| c.config.dual_settlement_address.clone())
            .unwrap_or_default();
        let work_dir = super::chain()
            .map(|c| c.config.prover_work_dir.clone())
            .unwrap_or_else(|| "/tmp/zgame-prover".to_string());
        tokio::spawn(async move {
            snip36_settle_flow(table_id, mirror, settlement, start, input, dual_addr, work_dir)
                .await;
        });
        return;
    }

    PENDING_SETTLE
        .lock()
        .map(|mut g| g.insert(table_id, PendingSettle { settlement, mirror, attempts: 0 }))
        .ok();
    run_settle_attempt(table_id).await;
}

/// snip36 结算流：递归证明（action-sig 批次）→ 工件落盘 → v3 入口提交
/// （合约随 cairo ≥2.12 上链后激活）→ 失败回退 legacy 结算。
/// 结算永不因证明阻塞/失败而丢失（对账已通过的 settlement 保底上链）。
async fn snip36_settle_flow(
    table_id: u32,
    mirror: TableMirror,
    settlement: super::submit::HandSettlement,
    start: super::prove_log::HandStartData,
    input: super::prove_log::HandSettleInput,
    dual_addr: String,
    work_dir: String,
) {
    let hand_id = settlement.hand_id;

    // 1. 材料：每参与者首条已签名动作（v3 域：含 hand_id）。
    //    真实客户端未带签名时材料为空——空批次没有可证语句（handbatch
    //    的 host 直验对零方程同样 Truncated 拒绝），直接跳过出证，
    //    不再"warn 后仍然进 prove"（2026-09-07 线上：两手均
    //    "no signed actions → host verify: Truncated"假失败）。
    let materials =
        super::recursion_prover::action_sig_materials(&input.action_log, &start.participants);
    if materials.is_empty() {
        tracing::warn!(
            "[snip36] table {table_id} hand {hand_id}: no signed actions — proof skipped"
        );
    }

    // 2. 异步出证（阻塞调用移入 spawn_blocking；hand_binding = 注册值）。
    let binding = super::dual_settle::prepare_handbatch_binding(&mirror, &settlement);
    let prove_result = if materials.is_empty() {
        Err("no signed actions — proving skipped".to_string())
    } else {
        match binding {
            Ok(b) => {
                let out_dir =
                    std::path::Path::new(&work_dir).join(format!("hand-{hand_id}-recursion"));
                let mats = materials.clone();
                let table_id = input.table_id;
                let hand_id = settlement.hand_id;
                let hb_bytes = b.hand_binding.to_bytes_be();
                tokio::task::spawn_blocking(move || {
                    super::recursion_prover::prove_batch_blocking(
                        table_id, hand_id, hb_bytes, &mats, &out_dir,
                    )
                })
                .await
                .unwrap_or_else(|e| Err(format!("join: {e:?}")))
            }
            Err(e) => Err(format!("binding: {e}")),
        }
    };

    match prove_result {
        Ok(out) => {
            tracing::info!(
                "[snip36] table {table_id} hand {hand_id} recursion proof ok: acc={} steps={} ec_ops={} out={}",
                out.acc, out.steps, out.ec_ops, out.out_dir
            );
            if dual_addr.is_empty() {
                tracing::warn!(
                    "[snip36] dual settlement address not configured — proof archived, settlement falls back to legacy"
                );
            } else {
                // v3 入口提交：calldata = [hand_binding, hand_id, segment(15)]
                // —— segment 由 settlement_private 公开段给出；外部 settle
                // prover 未配置时落盘工件并回退 legacy（P2/P4 激活项）。
                tracing::info!(
                    "[snip36] hand {hand_id} proof ready; v3 settlement submission activates with the cairo >= 2.12 contract (plan-snip36-execution P2/P4)"
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                "[snip36] table {table_id} hand {hand_id} recursion proof failed: {e} — settlement falls back to legacy"
            );
        }
    }

    // 3. 保底：对账已通过的 settlement 经 dual 线性入口上链
    //    （register_hand + verify_and_settle_dapv_stark）。
    submit_dual_fallback(table_id, &mirror, &settlement).await;
}

/// 结算保底腿：dual 线性结算（无证明依赖）。
///
/// 2026-09-07 起 legacy PokerSettlement（0x76a0b49a）在链上是 2026-08-31
/// 的 4 参 `settle_hand` ABI（#18 Phase B 只改了源码未重部署），且构造时
/// 绑定的还是旧 vault v2——新 5 参 calldata 反序列化必拒（线上
/// "Failed to deserialize param #3"），双重失效。回退改走 dual：
/// `vault.settlement_contract` 已指向 dual v5，`register_hand` +
/// `verify_and_settle_dapv_stark` 与 e2e 冒烟（2026-09-05）同路径；
/// endorsement 退役后 P-batch 由操作员自铸（纯形状合规的折叠方程）。
async fn submit_dual_fallback(
    table_id: u32,
    mirror: &super::mirror::TableMirror,
    settlement: &super::submit::HandSettlement,
) {
    let Some(chain) = super::chain() else { return };
    let dual_addr = chain.config.dual_settlement_address.clone();
    if dual_addr.is_empty() {
        tracing::info!(
            "[snip36] dev mode: dual settlement not configured, on-chain submit skipped              (register {} felts, settle {} felts)",
            settlement.register_calldata.len(),
            settlement.settle_calldata.len()
        );
        return;
    }
    // P-batch 词条：每参与者一条操作员自铸 endorsement（与 e2e 冒烟一致；
    // 认可退役后合约只折叠方程形状，不再约束签名主体）。
    let produce = |hb: &[u8; 32], _players: &[starknet_ff::FieldElement]| {
        let mut out = Vec::new();
        for _ in 0.._players.len() {
            let sk = <super::dual_settle::Sc as poker_protocol::crypto::curve::CurveScalar>::random(
                &mut rand::rngs::OsRng,
            );
            let pk = <poker_protocol::crypto::curve::StarkCurve as poker_protocol::crypto::curve::Curve>::base_g() * sk;
            out.push(super::dual_settle::mint_endorsement(&sk, &pk, hb));
        }
        Ok(out)
    };
    let dual = match super::dual_settle::build_dual_settlement_with(mirror, settlement, &produce) {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(
                "[snip36-fallback] table {table_id} hand {} dual settlement build failed: {e}",
                settlement.hand_id
            );
            return;
        }
    };
    // #33 离桌快解锁：本手的挂起离桌玩家随结算 bundle 同笔释放；
    // 失败归还，等下次重试或 TTL 兜底。赢额回锁与续钟也在同一笔
    // bundle 里（原子，无异步窗口），不再有后置补锁调用。
    let departed = super::lock::take_pending_releases_for(settlement.hand_id);
    match super::dual_settle::submit_dual_settlement(
        &dual,
        &dual_addr,
        &settlement.players_remapped,
        &settlement.deltas,
        &departed,
    )
    .await
    {
        Ok((register_hash, settle_hash)) => {
            let _ = settle_ok_once(table_id, settlement.hand_id);
            tracing::info!(
                "[snip36-fallback] table {table_id} hand {} dual atomic settle ok: tx={register_hash} ({settle_hash}), departed-released={}",
                settlement.hand_id,
                departed.len()
            );
            // 兜底：结算流程启动后才注册离桌的玩家在此补放（独立交易，
            // invoke_vault 内置 nonce 重试）。
            super::lock::flush_leave_releases(settlement.hand_id).await;
        }
        Err(e) if is_already_settled_error(&e) => {
            let _ = settle_ok_once(table_id, settlement.hand_id);
        }
        Err(e) => {
            super::lock::restore_pending_releases(departed, settlement.hand_id);
            tracing::error!(
                "[snip36-fallback] table {table_id} hand {} dual atomic settle failed: {e}",
                settlement.hand_id
            );
        }
    }
}

/// 强制对账：VM 快照与游戏层终局事实逐分比对（total_bet / 公共牌数 /
/// 参与者集合）。任何不一致都拒绝结算——输赢金额以游戏层为准，
/// 证明工件必须为其背书，否则宁可不结算。
fn cross_check_snapshot(
    mirror: &TableMirror,
    input: &super::prove_log::HandSettleInput,
) -> Result<(), String> {
    let snap = mirror.pre_settlement.as_ref().unwrap_or(&mirror.table);
    let vm_board = snap.community_cards.len();
    if vm_board != input.board_len {
        return Err(format!("board mismatch: vm {vm_board} vs game {}", input.board_len));
    }
    for (wallet, bet) in &input.total_bets {
        let Some(addr) = TableMirror::addr_from_starknet(wallet) else {
            continue;
        };
        let vm_bet = snap
            .seats
            .iter()
            .find(|s| seat_player_addr(s) == Some(addr))
            .map(|s| s.total_bet());
        match vm_bet {
            None => {
                if *bet != 0 {
                    return Err(format!(
                        "participant missing in vm snapshot: {wallet} (game total_bet {bet})"
                    ));
                }
            }
            Some(v) if v != *bet => {
                return Err(format!("total_bet mismatch: {wallet} vm {v} vs game {bet}"));
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// 本手完整钱包映射：参与者（来自 HandStart 记录）+ treasury，
/// 供 settle_hand 把 20 字节座位地址重映射回全精度 felt 记账。
fn hand_wallet_map(start: &super::prove_log::HandStartData) -> Vec<(poker_l1::Address, starknet_ff::FieldElement)> {
    let mut out: Vec<(poker_l1::Address, starknet_ff::FieldElement)> = start
        .participants
        .iter()
        .filter_map(|p| {
            let addr = TableMirror::addr_from_starknet(&p.wallet)?;
            let felt = super::chain::parse_felt(&p.wallet)?;
            Some((addr, super::submit::felt_to_ff(&felt)))
        })
        .collect();
    if let Ok(set) = TREASURY_WALLETS.lock() {
        for w in set.iter() {
            if let (Some(a), Some(f)) = (
                TableMirror::addr_from_starknet(w),
                super::chain::parse_felt(w),
            ) {
                out.push((a, super::submit::felt_to_ff(&f)));
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out.dedup_by(|a, b| a.0 == b.0);
    out
}

/// 一次投递尝试：legacy 结算上链。成功（含链上幂等重放）则清除待投递
/// 条目并标记 SETTLE_OK。
async fn run_settle_attempt(table_id: u32) {
    let Some(mut pending) = PENDING_SETTLE.lock().ok().and_then(|mut g| g.remove(&table_id)) else {
        return;
    };
    pending.attempts += 1;
    let settlement = &pending.settlement;

    let Some(chain) = super::chain() else { return };

    // legacy 结算（settlement_address 为空 = dev 模式只记日志）。
    let Some(addr) = (!chain.config.settlement_address.is_empty())
        .then(|| chain.config.settlement_address.clone())
    else {
        tracing::info!(
            "[starknet-settle] dev mode: settlement calldata generated, on-chain submit skipped              (register {} felts, settle {} felts)",
            settlement.register_calldata.len(),
            settlement.settle_calldata.len()
        );
        return;
    };
    match super::submit::submit_settlement(settlement, &addr).await {
        Ok((register_hash, settle_hash)) => {
            let _ = settle_ok_once(table_id, settlement.hand_id);
            tracing::info!(
                "[starknet-settle] table {table_id} hand {} on-chain: register={register_hash} settle={settle_hash}",
                settlement.hand_id
            );
            refresh_settlement_sessions(&settlement.players_remapped).await;
        }
        Err(e) if is_already_settled_error(&e) => {
            let _ = settle_ok_once(table_id, settlement.hand_id);
            tracing::info!(
                "[starknet-settle] table {table_id} hand {} already settled on-chain (legacy replay suppressed)",
                settlement.hand_id
            );
        }
        Err(e) => {
            tracing::warn!(
                "[starknet-settle] table {table_id} hand {} submit failed (attempt {}): {e}",
                settlement.hand_id,
                pending.attempts
            );
            // 失败不是终点：保留同一快照由 game_loop tick 重投
            // （nonce 竞争/RPC 抖动均可恢复），超过上限自动放弃。
            retry_later(pending, table_id);
        }
    }
}

/// 有界重投：保留待投递快照等下一次 tick；超过 [`MAX_SETTLE_ATTEMPTS`]
/// 放弃并丢弃（防镜像状态与游戏永久分歧时的无限重试轰炸 RPC）。
fn retry_later(pending: PendingSettle, table_id: u32) {
    if pending.attempts >= MAX_SETTLE_ATTEMPTS {
        tracing::warn!(
            "[starknet-settle] table {table_id} hand {} dropped after {} attempts",
            pending.settlement.hand_id,
            MAX_SETTLE_ATTEMPTS
        );
        return;
    }
    PENDING_SETTLE
        .lock()
        .ok()
        .and_then(|mut g| g.insert(table_id, pending));
}

/// tick 驱动的重投：仅当仍有待投递快照时重试（同一快照，绝不读新 mirror）。
pub async fn retry_pending_settlement(table_id: u32) {
    let in_flight = PENDING_SETTLE.lock().ok().map(|g| g.contains_key(&table_id)).unwrap_or(false);
    if in_flight {
        run_settle_attempt(table_id).await;
    }
}


fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 结算成功后续各参与者的 #33 session 时钟（owner=operator，逐人独立
/// 交易，失败仅告警）。必须每手刷新：TTL（12h）从最后一次活动计时，
/// 停刷即触发玩家无许可自助解锁。
async fn refresh_settlement_sessions(players_remapped: &[starknet_ff::FieldElement]) {
    for p in players_remapped {
        let wallet = format!("0x{}", hex_encode(&p.to_bytes_be()));
        super::lock::refresh_player_session(&wallet).await;
    }
}


use crate::pokergame::table::Table;

/// 平台 treasury 钱包（抽水接收方）：settle calldata 的玩家地址只有 20 字节
/// 截断，上链前经 seat_wallet_remaps 还原为全精度 felt；treasury 不是牌手，
/// 需要单独登记才能参与重映射。
static TREASURY_WALLETS: std::sync::LazyLock<std::sync::Mutex<std::collections::HashSet<String>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));

pub fn register_treasury_wallet(wallet: &str) {
    if let Ok(mut set) = TREASURY_WALLETS.lock() {
        set.insert(wallet.to_string());
    }
}

/// 直接记录 join（bot 进程内路径：wallet + pk hex + 80 字节证明）。
pub fn mirror_buffer_join_raw(
    table_id: u32,
    wallet: &str,
    pk_hex: &str,
    proof: Vec<u8>,
) {
    super::prove_log::record_join(table_id, wallet, pk_hex, proof);
}
