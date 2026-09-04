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
async fn rebind_vault_settlement(vault_address: &str, settlement_address: &str) -> Result<(), String> {
    let chain = super::chain().ok_or("starknet chain not initialized")?;
    let vault = super::chain::parse_felt(vault_address).ok_or("invalid vault address")?;
    let target = super::chain::parse_felt(settlement_address).ok_or("invalid settlement address")?;
    let operator = chain.operator().await.ok_or("operator account unavailable")?;
    use starknet::accounts::Account;
    operator
        .execute_v3(vec![starknet::core::types::Call {
            to: vault,
            selector: starknet::core::utils::starknet_keccak(b"set_settlement_contract"),
            calldata: vec![target],
        }])
        .send()
        .await
        .map(|_| ())
        .map_err(|e| format!("vault rebind submit failed: {e}"))
}

/// settle 成功上链的 (table, mirror_hand) 集合：失败可重试（game_loop tick
/// 驱动），成功后幂等跳过。
static SETTLE_OK: OnceLock<std::sync::Mutex<std::collections::HashSet<(u32, u32)>>> =
    OnceLock::new();

fn settle_ok_once(table_id: u32, mirror_hand: u32) -> bool {
    let set = SETTLE_OK.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()));
    set.lock().map(|mut g| g.insert((table_id, mirror_hand))).unwrap_or(false)
}

fn settle_ok_already(table_id: u32, mirror_hand: u32) -> bool {
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

/// 待投递结算：按桌保留**构建时快照**（HandSettlement + binding + mirror 克隆）。
/// 链上提交失败（nonce 竞争/RPC 抖动）时由 game_loop tick 用同一快照重投，
/// 绝不读取已被新手替换的 mirror 活状态（避免跨手状态污染）。
struct PendingSettle {
    settlement: super::submit::HandSettlement,
    binding: Option<super::dual_settle::HandBatchBinding>,
    mirror: TableMirror,
    attempts: u32,
}

static PENDING_SETTLE: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<u32, PendingSettle>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

const MAX_SETTLE_ATTEMPTS: u32 = 8;

/// 每桌单调递增的 mirror hand_id。种子取 unix 秒：服务器重启后仍满足
/// 链上 register_aggregate 的 first_hand_id 严格递增校验。
static HAND_ID_SEQ: OnceLock<std::sync::Mutex<std::collections::HashMap<u32, u32>>> =
    OnceLock::new();

fn next_hand_id(table_id: u32) -> u32 {
    let m = HAND_ID_SEQ.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    let unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(1);
    let mut g = match m.lock() {
        Ok(g) => g,
        Err(_) => return unix,
    };
    let e = g.entry(table_id).or_insert(0);
    *e = (*e + 1).max(unix);
    *e
}

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
    tokio::spawn(async move {
        settle_hand_from_log(input).await;
    });
}

/// 锁外结算：日志一次性重放 → 强制对账 → 证明 → 入队上链。
async fn settle_hand_from_log(input: super::prove_log::HandSettleInput) {
    let table_id = input.table_id;
    let Some(start) = input.log.start.clone() else { return };
    let hand_id = next_hand_id(table_id);

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

    let (try_dapv, _dual_addr) = super::chain()
        .map(|c| (c.config.try_dapv(), c.config.dual_settlement_address.clone()))
        .unwrap_or((false, String::new()));

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

    // #18 Phase B：game 层产出的本手动作日志哈希进 settlement digest 尾词。
    let action_log_digest = starknet_ff::FieldElement::from_bytes_be(&input.action_log_digest)
        .expect("action log digest is a canonical felt");
    let settlement =
        match super::submit::settle_hand(&mirror, rake_recipient, &wallet_map, action_log_digest)
        {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("[starknet-settle] table {table_id} hand {hand_id} settlement build failed: {e}");
            return;
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

    let binding = if try_dapv {
        match super::dual_settle::prepare_handbatch_binding(&mirror, &settlement) {
            Ok(b) => {
                // bot 认可由服务器代铸；真实客户端经 ENDORSEMENT_REQUEST 铸造。
                mint_bot_endorsements(&b.hand_id_bytes, settlement.hand_id, &settlement.players_remapped);
                if let Some(io) = crate::socket::get_socket_io() {
                    let request = crate::socket::EndorsementRequestPayload {
                        table_id,
                        hand_id: settlement.hand_id,
                        hand_binding_hex: hex_encode(&b.hand_id_bytes),
                    };
                    let room = crate::socket::table_room_name(table_id);
                    let _ = io.to(room).emit(crate::pokergame::actions::ENDORSEMENT_REQUEST, &request).await;
                    tracing::info!(
                        "[starknet-settle] table {table_id} hand {} endorsement request broadcast",
                        settlement.hand_id
                    );
                }
                Some(b)
            }
            Err(e) => {
                tracing::warn!("[starknet-settle] table {table_id} hand {} dapv binding prepare failed: {e}", settlement.hand_id);
                None
            }
        }
    } else {
        None
    };

    PENDING_SETTLE
        .lock()
        .map(|mut g| g.insert(table_id, PendingSettle { settlement, binding, mirror, attempts: 0 }))
        .ok();
    run_settle_attempt(table_id).await;
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

/// 一次投递尝试：DAPV 优先（认可等待 3s），失败/不可用回退 legacy（按模式）。
/// 成功（含链上幂等重放）则清除待投递条目并标记 SETTLE_OK。
async fn run_settle_attempt(table_id: u32) {
    let Some(mut pending) = PENDING_SETTLE.lock().ok().and_then(|mut g| g.remove(&table_id)) else {
        return;
    };
    pending.attempts += 1;
    let settlement = &pending.settlement;

    let Some(chain) = super::chain() else { return };
    let dual_addr = chain.config.dual_settlement_address.clone();

    // DAPV 路径：重发认可请求（重投时客户端可能已重新就绪）→ 短暂等待收齐
    // → 构建并提交 dual。
    if chain.config.try_dapv() && pending.binding.is_some() {
        let binding_bytes: [u8; 32] = pending
            .binding
            .as_ref()
            .map(|b| b.hand_id_bytes)
            .unwrap_or([0u8; 32]);
        // 重投节流：客户端每手只需回应一次（有 per-hand 去重），但请求本身
        // 每次尝试都重发——客户端恰好在刷新/重连窗口错过单次广播会永久
        // 丢失请求，导致认可永远收不齐、结算被静默跳过（2026-09-04 线上
        // 复现）。客户端去重保证重播不会重复铸造。
        if let Some(io) = crate::socket::get_socket_io() {
            let hand_binding_hex = hex_encode(&binding_bytes);
            if !hand_binding_hex.is_empty() {
                let request = crate::socket::EndorsementRequestPayload {
                    table_id,
                    hand_id: settlement.hand_id,
                    hand_binding_hex: hand_binding_hex.clone(),
                };
                let room = crate::socket::table_room_name(table_id);
                let _ = io.to(room).emit(crate::pokergame::actions::ENDORSEMENT_REQUEST, &request).await;
            }
        }
        mint_bot_endorsements(
            &binding_bytes,
            settlement.hand_id,
            &settlement.players_remapped,
        );
        // 认可等待窗口：10s（刷新页面/后台标签页的客户端靠重播请求补交，
        // 3s 对手动钱包确认场景太紧——线上复现收不齐即被跳过）。
        let deadline = std::time::Duration::from_secs(10);
        let start = std::time::Instant::now();
        while start.elapsed() < deadline {
            if super::dual_settle::take_client_endorsements(
                &settlement.players_remapped,
                settlement.hand_id,
            ).is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        }
        if let Some(endorsed) = super::dual_settle::take_client_endorsements(
            &settlement.players_remapped,
            settlement.hand_id,
        ) {
            match super::dual_settle::build_dual_settlement_from_client(
                &pending.mirror,
                settlement,
                &endorsed,
            ) {
                Ok(dual) => match super::dual_settle::submit_dual_settlement(&dual, &dual_addr, &settlement.players_remapped, &settlement.deltas).await {
                    Ok((register_hash, settle_hash)) => {
                        let _ = settle_ok_once(table_id, settlement.hand_id);
                        tracing::info!(
                            "[starknet-settle] table {table_id} hand {} dapv on-chain: binding={:#x} register={register_hash} settle={settle_hash}",
                            settlement.hand_id,
                            dual.hand_binding
                        );
                        refresh_settlement_sessions(&settlement.players_remapped).await;
                        return;
                    }
                    Err(e) if is_already_settled_error(&e) => {
                        let _ = settle_ok_once(table_id, settlement.hand_id);
                        tracing::info!(
                            "[starknet-settle] table {table_id} hand {} already settled on-chain (dapv replay suppressed)",
                            settlement.hand_id
                        );
                        return;
                    }
                    Err(e) => {
                        tracing::warn!(
                            "[starknet-settle] table {table_id} hand {} dapv submit failed: {e}",
                            settlement.hand_id
                        );
                    }
                },
                Err(e) => {
                    tracing::warn!("[starknet-settle] table {table_id} hand {} dapv build failed: {e}", settlement.hand_id);
                }
            }
        } else {
            tracing::warn!(
                "[starknet-settle] table {table_id} hand {} endorsements incomplete — DAPV skipped this attempt",
                settlement.hand_id
            );
        }
        // dapv 严格模式不回退：保留待投递，等下一次尝试（认可可能迟到）。
        if !chain.config.dapv_fallback_legacy() {
            retry_later(pending, table_id);
            return;
        }
    }

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

/// 进程内 bot 的通知（endorsement）私钥注册表：wallet → StarkCurve sk。
/// bot 是服务器自己的测试玩家，认可私钥托管在服务器（与真实客户端把私钥
/// 保持在浏览器 localStorage 等价）。
static BOT_ENDORSEMENT_SKS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, super::dual_settle::Sc>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

pub fn register_bot_endorsement_key(wallet: &str, sk: super::dual_settle::Sc) {
    if let Ok(mut map) = BOT_ENDORSEMENT_SKS.lock() {
        map.insert(wallet.to_string(), sk);
    }
}

/// 启动时为 STARKNET_DEV_ENDORSEMENT_WALLETS（逗号分隔）注册服务端托管的
/// 认可私钥：dev 联调中这些钱包的对局也走 DAPV 结算（与 bot 同机制）。
/// 生产环境不要配置该变量——真实玩家的认可私钥必须留在客户端。
pub fn register_dev_endorsement_wallets() {
    let list = match std::env::var("STARKNET_DEV_ENDORSEMENT_WALLETS") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => return,
    };
    use poker_protocol::crypto::curve::{Curve, CurveScalar};
    for wallet in list.split(',') {
        let wallet = wallet.trim();
        if wallet.is_empty() {
            continue;
        }
        let sk = <super::dual_settle::Sc as CurveScalar>::random(&mut rand::rngs::OsRng);
        register_bot_endorsement_key(wallet, sk);
        tracing::info!("[starknet-settle] dev endorsement wallet registered: {wallet}");
    }
}

/// 为所有已注册且参与本手的 bot 钱包本地铸造认可并写入收集注册表。
fn mint_bot_endorsements(
    hand_binding_bytes: &[u8; 32],
    hand_id: u32,
    players_remapped: &[starknet_ff::FieldElement],
) {
    use poker_protocol::crypto::curve::{Curve, CurveScalar};
    use poker_protocol::crypto::curve::StarkCurve;
    use std::format as fmt;

    let Ok(map) = BOT_ENDORSEMENT_SKS.lock() else { return };
    for (wallet, sk) in map.iter() {
        // 只为参与本手的 bot 钱包铸造（键格式与 take_client_endorsements 一致）
        let normalized = fmt!("{:#x}", {
            let f = super::chain::parse_felt(wallet);
            match f {
                Some(f) => f,
                None => continue,
            }
        });
        if !players_remapped.iter().any(|p| fmt!("{p:#x}") == normalized) {
            continue;
        }
        let pk = <StarkCurve as Curve>::base_g() * sk;
        let e = super::dual_settle::mint_endorsement(sk, &pk, hand_binding_bytes);
        super::dual_settle::register_client_endorsement_raw(wallet, hand_id, e);
        tracing::info!("[starknet-settle] bot endorsement minted for {wallet} hand {hand_id}");
    }
}

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
