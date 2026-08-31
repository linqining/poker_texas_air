//! 服务器接线钩子：把牌局事件桥接到 Starknet mirror 与链上结算。
//!
//! 方案A（MIRROR_UNIFICATION_PLAN.md）：poker_l1 VM 成为唯一可证明状态机。
//! - [`mirror_begin_reveal`]：游戏层洗牌完成、底牌发出（deck 终局）时，
//!   把已验证 deck 原样注入全新 TableMirror，VM 直接进入 DealHole——
//!   两条 deck 链逐字节同源，无需任何事后追赶（fill/replay/autoplay）。
//! - [`mirror_sync_reveal`] / [`mirror_betting`] / [`mirror_force_fold`]：
//!   在游戏层**接受动作的同一条代码路径**上单点派发到 VM。
//! - [`on_hand_complete`]：showdown 后从 VM 的 ProveTask 链构建结算并上链
//!   （register_aggregate + settle_hand），失败由 game_loop tick 有界重试。
//!
//! 禁止事项（防止回到老路）：不再新增"事后追赶"型同步补丁；不引入第二套
//! 密文派生（deck 必须同源）；不为绕过验证失败放宽 VM 证明校验。

use std::sync::OnceLock;
use super::mirror::{MirrorRegistry, TableMirror};

static REGISTRY: OnceLock<MirrorRegistry> = OnceLock::new();

pub fn mirror_registry() -> &'static MirrorRegistry {
    REGISTRY.get_or_init(MirrorRegistry::new)
}

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

pub fn on_hand_complete(table_id: u32) {
    // Hand-batch 模式判定需在镜像闭包外完成（闭包内构建 dual 工件）。
    let (try_dapv, dual_addr) = super::chain()
        .map(|c| (c.config.try_dapv(), c.config.dual_settlement_address.clone()))
        .unwrap_or((false, String::new()));

    // 阶段 1（同步）：构建 legacy settlement + 派生 hand_binding +
    // 向牌桌房间广播 ENDORSEMENT_REQUEST（P2.1：客户端本地铸造）。
    let result = mirror_registry().with_mirror(
        table_id,
        || TableMirror::new(u64::from(table_id), "table", [0xC0; 20], 9, 10, 20, [0xC0; 20]),
        |mirror| {
            if !mirror.has_provable_activity() {
                return Ok(None);
            }
            if settle_ok_already(table_id, mirror.table.hand_id) {
                return Ok(None); // 本手已成功上链（幂等）
            }
            if settle_attempts_bumped_max(table_id, mirror.table.hand_id) {
                return Ok(None); // 重试上限：mirror 状态与游戏永久分歧
            }
            // lockstep 下游戏 finish_showdown 时 mirror 必已进入
            // ShowdownDisplay（双方由同一批 reveal token 驱动）；此刻打
            // 派奖前快照，结算不再依赖 tick 时序。
            if matches!(
                mirror.table.hand_phase,
                poker_l1::vm::contracts::texas_poker::types::HandPhase::ShowdownDisplay { .. }
            ) {
                mirror.mark_pre_settlement();
            }
            // TODO(结算参数)：rake 接收方取平台 treasury 地址（env 配置）。
            let rake_recipient = None;
            let settlement =
                super::submit::settle_hand(mirror, rake_recipient)?;

            let binding = if try_dapv {
                match super::dual_settle::prepare_handbatch_binding(mirror, &settlement) {
                    Ok(binding) => {
                        // P2.1：请求各客户端对其 hand_binding 域铸造认可。
                        // 私钥只在玩家客户端；服务器经 ENDORSEMENT_SUBMIT
                        // （WS）或 POST /starknet/endorsement 收取成品。
                        if let Some(io) = crate::socket::get_socket_io() {
                            let request = crate::socket::EndorsementRequestPayload {
                                table_id,
                                hand_id: settlement.hand_id,
                                hand_binding_hex: hex_encode(&binding.hand_id_bytes),
                            };
                            let _ = io
                                .to(crate::socket::table_room_name(table_id))
                                .emit(crate::pokergame::actions::ENDORSEMENT_REQUEST, &request);
                            tracing::info!(
                                "[starknet-settle] table {table_id} hand {} endorsement request broadcast",
                                settlement.hand_id
                            );
                        }
                        Some(binding)
                    }
                    Err(e) => {
                        tracing::warn!("[starknet-settle] table {table_id} hand {} dapv binding prepare failed: {e}", settlement.hand_id);
                        None
                    }
                }
            } else {
                None
            };
            // 阶段 2 异步提交期间 mirror 可能已被下一手替换——这里克隆
            // 本手镜像（tasks + pre_settlement），dual 构建不再借用注册表。
            Ok(Some((settlement, binding, mirror.clone())))
        },
    );
    let (settlement, binding, mirror_snapshot) = match result {
        Ok(Some(s)) => s,
        Ok(None) => return, // 无可证明活动 / 已结算 / 超出重试上限
        Err(e) => {
            tracing::warn!("[starknet-settle] table {table_id} settlement build failed: {e}");
            return;
        }
    };

    tracing::info!(
        "[starknet-settle] table {table_id} hand {} settled: aggregate={}",
        settlement.hand_id,
        hex_encode(&settlement.aggregate_digest)
    );

    // 阶段 2（异步）：等待客户端认可收齐 → 构建 dual → 上链。
    // P2.1 收尾：无服务器铸造 fallback——收不齐则只走 legacy 结算。
    tokio::spawn(async move {
        let Some(chain) = super::chain() else { return };

        // P2.1：等待客户端认可收齐（超时则放弃 DAPV，仅 legacy 结算）。
        let dual = match binding {
            Some(b) => {
                let deadline = std::time::Duration::from_secs(10);
                let mut collected = None;
                let start = std::time::Instant::now();
                while start.elapsed() < deadline {
                    if let Some(endorsed) = super::dual_settle::take_client_endorsements(
                        &settlement.players_remapped,
                        settlement.hand_id,
                    ) {
                        collected = Some(endorsed);
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
                match collected {
                    Some(endorsed) => {
                        let built = super::dual_settle::build_dual_settlement_from_client(
                            &mirror_snapshot,
                            &settlement,
                            &endorsed,
                        );
                        match built {
                            Ok(d) => {
                                tracing::info!(
                                    "[starknet-settle] table {table_id} hand {} dapv endorsements collected from CLIENTS",
                                    settlement.hand_id
                                );
                                Some(d)
                            }
                            Err(e) => {
                                tracing::warn!("[starknet-settle] table {table_id} hand {} dapv build failed: {e}", settlement.hand_id);
                                None
                            }
                        }
                    }
                    None => {
                        tracing::warn!(
                            "[starknet-settle] table {table_id} hand {} client endorsements not collected in {:?} — Hand-batch skipped, legacy settlement only",
                            settlement.hand_id,
                            deadline
                        );
                        None
                    }
                }
            }
            None => None,
        };

        // 优先 Hand-batch 路径；失败按模式回退 legacy（auto 默认允许）。
        if let Some(dual) = &dual {
            match super::dual_settle::submit_dual_settlement(dual, &dual_addr).await {
                Ok((register_hash, settle_hash)) => {
                    tracing::info!(
                        "[starknet-settle] table {table_id} hand {} dapv on-chain: binding={:#x} register={register_hash} settle={settle_hash}",
                        settlement.hand_id,
                        dual.hand_binding
                    );
                    return;
                }
                Err(e) if is_already_settled_error(&e) => {
                    // 本手已通过 dual（或本合约）结算过——幂等成功，禁止
                    // 回退 legacy（否则同一手经两套合约双重派彩）。
                    tracing::info!(
                        "[starknet-settle] table {table_id} hand {} already settled on-chain (dapv replay suppressed)",
                        settlement.hand_id
                    );
                    return;
                }
                Err(e) => {
                    if !chain.config.dapv_fallback_legacy() {
                        tracing::warn!(
                            "[starknet-settle] table {table_id} hand {} dapv submit failed (no fallback): {e}",
                            settlement.hand_id
                        );
                        return;
                    }
                    tracing::warn!(
                        "[starknet-settle] table {table_id} hand {} dapv submit failed, falling back to legacy: {e}",
                        settlement.hand_id
                    );
                    // vault 的 settlement 绑定当前指向 dual 合约；legacy 的
                    // settle_hand 需要绑定切回 legacy 合约（operator 即 owner）。
                    if !chain.config.vault_address.is_empty() {
                        if let Err(rebind) = rebind_vault_settlement(
                            &chain.config.vault_address,
                            &chain.config.settlement_address,
                        )
                        .await
                        {
                            tracing::warn!(
                                "[starknet-settle] vault rebind to legacy failed: {rebind}"
                            );
                        }
                    }
                }
            }
        }

        let Some(addr) = (!chain.config.settlement_address.is_empty())
            .then(|| chain.config.settlement_address.clone())
        else {
            tracing::info!(
                "[starknet-settle] dev mode: settlement calldata generated, on-chain submit skipped \
                 (register {} felts, settle {} felts, dapv {})",
                settlement.register_calldata.len(),
                settlement.settle_calldata.len(),
                dual.as_ref().map(|d| d.settle_calldata.len()).unwrap_or(0)
            );
            return;
        };
        match super::submit::submit_settlement(&settlement, &addr).await {
            Ok((register_hash, settle_hash)) => {
                let _ = settle_ok_once(table_id, settlement.hand_id);
                tracing::info!(
                    "[starknet-settle] table {table_id} hand {} on-chain: register={register_hash} settle={settle_hash}",
                    settlement.hand_id
                );
            }
            Err(e) if is_already_settled_error(&e) => tracing::info!(
                "[starknet-settle] table {table_id} hand {} already settled on-chain (legacy replay suppressed)",
                settlement.hand_id
            ),
            Err(e) => tracing::warn!(
                "[starknet-settle] table {table_id} hand {} submit failed: {e}",
                settlement.hand_id
            ),
        }
    });
}

/// game loop tick 驱动的结算重试：游戏手已结束（hand_over）而链上提交
/// 尚未成功时，每 tick 重试直至成功上链或达到重试上限。
pub async fn retry_pending_settlement(table_id: u32) {
    on_hand_complete(table_id);
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}


// ---------------------------------------------------------------------------
// 运行时镜像同步：把 WS 牌局操作在游戏层接受点上单点派发到 TableMirror
// ---------------------------------------------------------------------------

use crate::pokergame::player::GamePkHex;
use crate::pokergame::table::Table;
use std::collections::HashMap;

/// 每桌"最新 join 快照"：addr → (addr, buy_in, pk, proof)。
/// mirror 开局（mirror_begin_reveal）据此把游戏层座位重放进 VM。
type JoinEntry = (poker_l1::Address, u64, super::mirror::PtxECPoint, Vec<u8>);
static LAST_JOINS: OnceLock<std::sync::Mutex<HashMap<u32, HashMap<poker_l1::Address, JoinEntry>>>> = OnceLock::new();

fn last_joins_for(table_id: u32) -> Option<std::collections::HashMap<poker_l1::Address, JoinEntry>> {
    LAST_JOINS
        .get_or_init(|| std::sync::Mutex::new(HashMap::new()))
        .lock()
        .ok()
        .and_then(|map| map.get(&table_id).cloned())
}

fn record_join(table_id: u32, addr: poker_l1::Address, buy_in: u64, pk: super::mirror::PtxECPoint, proof: Vec<u8>) {
    let m = LAST_JOINS.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
    if let Ok(mut g) = m.lock() {
        g.entry(table_id).or_default().insert(addr, (addr, buy_in, pk, proof));
    }
}

/// SIT_DOWN_V2 成功后调用：记录玩家 join（pk + 80 字节所有权证明），
/// 下一手 mirror_begin_reveal 时按游戏座位计划重放进 VM。
pub fn mirror_buffer_join_pk(
    table_id: u32,
    wallet_addr: &str,
    pk_hex: &str,
    buy_in: u64,
    _pk_proof: &crate::pokergame::game_state::PkProofJson,
    proof_bytes: Vec<u8>,
) -> Result<(), String> {
    let Some(addr) = TableMirror::addr_from_starknet(wallet_addr) else { return Err("bad wallet".into()) };
    // pk_hex → ptx ECPoint：poker_protocol 的 z_poker::convert::hex_to_ecpoint 返回
    // zgame EcPoint(G1Projective)，直接取内点再包为 ptx ECPoint
    let zp = poker_protocol::z_poker::convert::hex_to_ecpoint(pk_hex)
        .map_err(|e| format!("pk hex: {e}"))?;
    let pk = crate::starknet::mirror::conv::ec_point(&poker_protocol::crypto::types::ECPoint(zp))
        .map_err(|e| format!("pk conv: {e}"))?;
    record_join(table_id, addr, buy_in, pk, proof_bytes);
    Ok(())
}

/// 方案A 注入式开局：游戏层 `advance_shuffle`（BeforePreflop 完成）时调用。
///
/// 此刻 deck 已终局（全部客户端洗牌已验证、deal_preflop 已发底牌）。把这份
/// deck 原样注入全新 TableMirror，按游戏座位升序重放 join，VM 直接进入
/// DealHole。任何失败都只放弃本手 mirror（该手无可证明结算），绝不阻塞
/// 游戏层，也绝不做状态追赶。
pub fn mirror_begin_reveal(table: &Table) {
    let table_id = table.summary.id;

    // 参与座位计划：与 deal_preflop 同一参与谓词（occupied && !sitting_out），
    // 按游戏座位号升序 → 与 VM DealHole 的升序座位规范逐一对齐。
    let mut joins_snapshot = last_joins_for(table_id).unwrap_or_default();
    let mut plan: Vec<(u32, poker_l1::Address, u64, super::mirror::PtxECPoint, Vec<u8>)> = Vec::new();
    for (seat_id, seat) in table.seats() {
        let Some(player) = seat.player.as_ref() else { continue };
        if seat.sitting_out || seat.is_waiting {
            continue;
        }
        let Some(addr) = TableMirror::addr_from_starknet(&player.wallet_address.0) else { continue };
        let Some((_, buy_in, pk, proof)) = joins_snapshot.remove(&addr) else {
            tracing::warn!(
                "[mirror] table {table_id} seat {seat_id} has no buffered join pk/proof — mirror hand skipped"
            );
            return;
        };
        plan.push((seat_id, addr, buy_in, pk, proof));
    }
    plan.sort_by_key(|(seat_id, ..)| *seat_id);
    if plan.len() < 2 {
        return; // 不足 2 人不开 mirror 手（与游戏 MIN_START_NUM 一致）
    }
    let button_rank = table
        .button()
        .and_then(|b| plan.iter().position(|(seat_id, ..)| *seat_id == b))
        .unwrap_or(0) as u8;
    let plan_tuples: Vec<(poker_l1::Address, u64, super::mirror::PtxECPoint, Vec<u8>)> = plan
        .into_iter()
        .map(|(_, addr, buy_in, pk, proof)| (addr, buy_in, pk, proof))
        .collect();

    let deck = match super::mirror::conv::ciphertexts(&table.mental_poker_game.deck_encrypted) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!("[mirror] table {table_id} deck conv failed: {e} — mirror hand skipped");
            return;
        }
    };
    let hand_id = next_hand_id(table_id);
    // 盲注与游戏层对齐（VM post_blinds 据此Posting，保证 bet/total_bet 一致）。
    let sb = table.summary.min_bet.max(1);
    let bb = sb.saturating_mul(2);

    let build = || {
        let mut mirror = new_mirror_with_blinds(table_id, sb, bb);
        mirror
            .begin_reveal_hand(deck.clone(), &plan_tuples, button_rank, hand_id)
            .map(|_| mirror)
    };
    match build() {
        Ok(mirror) => {
            mirror_registry().install(table_id, mirror);
            tracing::info!(
                "[mirror] table {table_id} hand {hand_id} opened: {} seats, deck injected ({} bytes), button_rank={button_rank}",
                plan_tuples.len(),
                deck.len()
            );
        }
        Err(e) => {
            tracing::warn!("[mirror] table {table_id} hand {hand_id} begin_reveal failed: {e} — hand proceeds without mirror settlement");
        }
    }
}

/// reveal 提交接受点（SocketState::submit_reveal_tokens_for_pk）：把客户端
/// 已验证的 reveal token 重排成 VM canonical 顺序后单点派发到 mirror。
pub fn mirror_sync_reveal(
    table_id: u32,
    pk_hex: &GamePkHex,
    tokens: &[poker_protocol::z_poker::protocol::RevealToken],
) {
    let Some(wallet) = mirror_seat_wallet_by_pk(table_id, pk_hex) else { return };
    let Some(addr) = TableMirror::addr_from_starknet(&wallet) else { return };
    // 预转换客户端 token（转换失败 = 协议不一致，直接放弃本批同步）
    let mut converted: Vec<(super::mirror::PtxECPoint, super::mirror::PtxRevealTokenProof<super::mirror::PtxCurve>)> = Vec::new();
    let mut cards: Vec<poker_protocol::crypto::ElGamalCiphertext> = Vec::new();
    for t in tokens {
        let (Ok(tok), Ok(proof)) = (
            crate::starknet::mirror::conv::ec_point(&poker_protocol::crypto::types::ECPoint(
                t.reveal_token.clone(),
            )),
            crate::starknet::mirror::conv::reveal_token_proof(&t.proof),
        ) else {
            tracing::warn!("[mirror] reveal token conv failed — batch dropped");
            return;
        };
        converted.push((tok, proof));
        cards.push(t.encrypted_card.clone());
    }
    let result = mirror_registry().with_mirror(table_id, || new_mirror(table_id), |m| {
        let Some(seat) = m.seat_index_of(addr) else { return Ok(()) };
        let targets = m.pending_reveal_ciphertexts(seat)?;
        if targets.len() != converted.len() {
            return Err(format!(
                "reveal set size mismatch: vm expects {}, client submitted {}",
                targets.len(),
                converted.len()
            ));
        }
        // canonical 重排：VM 要求 token 覆盖全部 pending assignment 且按
        // assignment 顺序（全有或全无）。按密文逐字节匹配客户端 token。
        let mut ordered: Vec<Option<usize>> = vec![None; targets.len()];
        for (ti, card) in cards.iter().enumerate() {
            for (pos, target) in targets.iter().enumerate() {
                if target.c1 == card.c1 && target.c2 == card.c2 {
                    ordered[pos] = Some(ti);
                    break;
                }
            }
        }
        if ordered.iter().any(|o| o.is_none()) {
            return Err("reveal set does not cover vm assignments byte-wise".into());
        }
        let mut pt_tokens = Vec::with_capacity(targets.len());
        let mut proofs = Vec::with_capacity(targets.len());
        for pos in 0..targets.len() {
            let ti = ordered[pos].expect("checked complete above");
            let (tok, proof) = converted[ti].clone();
            pt_tokens.push(tok);
            proofs.push(proof);
        }
        m.submit_reveal_tokens(seat, pt_tokens, proofs)
    });
    if let Err(e) = result {
        tracing::warn!("[mirror] reveal sync failed: {e}");
    }
}

/// 下注动作接受点（betting.rs 各 handle_* 成功后）：单点派发到 mirror。
/// 派发失败仅告警（该手结算将以镜像侧真实状态为准；不做缓冲追赶）。
pub fn mirror_betting(table: &Table, pk_hex: &GamePkHex, action: &str, total_bet: Option<u64>) {
    let table_id = table.summary.id;
    let Some(seat) = mirror_seat_of(table, pk_hex) else { return };
    let result = mirror_registry().with_mirror(table_id, || new_mirror(table_id), |m| {
        apply_mirror_bet(m, seat, action, total_bet)
    });
    if let Err(e) = result {
        tracing::warn!("[mirror] betting sync failed ({action} seat {seat}): {e}");
    }
}

/// 手牌进行中玩家被移除（超时踢出/离桌）的接受点：mirror 侧强制弃牌，
/// 使 VM 与游戏层的存活玩家集合保持一致。
pub fn mirror_force_fold(table_id: u32, wallet_addr: &str) {
    let Some(addr) = TableMirror::addr_from_starknet(wallet_addr) else { return };
    let result = mirror_registry().with_mirror(table_id, || new_mirror(table_id), |m| {
        let Some(seat) = m.seat_index_of(addr) else { return Ok(()) };
        let args = borsh::to_vec(&poker_l1::vm::contracts::texas_poker::dispatch::SeatIndexArgs {
            seat_index: seat,
        })
        .map_err(|e| e.to_string())?;
        m.apply([0xC0; 20], &poker_l1::vm::contracts::texas_poker::dispatch::selectors::force_fold(), args)
    });
    if let Err(e) = result {
        tracing::warn!("[mirror] force_fold sync failed: {e}");
    }
}

/// game loop tick 的 mirror 驱动（方案A 收缩版）：仅在 mirror 处于
/// ShowdownDisplay 时推进 deadline（VM 派奖 + 复位，为下一手腾出
/// Waiting 状态）。洗牌/reveal/下注阶段的推进完全由游戏层接受点驱动，
/// 不允许 VM 自行超时产生与游戏层的分歧。
pub fn mirror_advance_showdown_display(table_id: u32) {
    let _ = mirror_registry().with_mirror(table_id, || new_mirror(table_id), |m| {
        if matches!(
            m.table.hand_phase,
            poker_l1::vm::contracts::texas_poker::types::HandPhase::ShowdownDisplay { .. }
        ) {
            m.mark_pre_settlement();
            m.advance_deadline()?;
        }
        Ok(())
    });
}

fn apply_mirror_bet(m: &mut TableMirror, seat: u8, action: &str, total_bet: Option<u64>) -> Result<(), String> {
    match action {
        "fold" => m.fold(seat),
        "check" => m.check(seat),
        "call" => m.call(seat),
        "raise" => match total_bet {
            Some(tb) => m.raise(seat, tb),
            None => Err("raise requires total_bet".into()),
        },
        other => Err(format!("unknown betting action {other}")),
    }
}

fn mirror_seat_of(table: &Table, pk_hex: &GamePkHex) -> Option<u8> {
    let wallet = table
        .local_seats
        .values()
        .find(|s| s.player.as_ref().map(|p| p.pk_hex.0 == pk_hex.0).unwrap_or(false))?
        .player
        .as_ref()?
        .wallet_address
        .0
        .clone();
    let addr = TableMirror::addr_from_starknet(&wallet)?;
    mirror_registry()
        .with_mirror(table.summary.id, || new_mirror(table.summary.id), |m| {
            Ok(m.seat_index_of(addr))
        })
        .ok()
        .flatten()
}

fn new_mirror(table_id: u32) -> TableMirror {
    TableMirror::new(u64::from(table_id), "table", [0xC0; 20], 9, 10, 20, [0xC0; 20])
}

fn new_mirror_with_blinds(table_id: u32, small_blind: u64, big_blind: u64) -> TableMirror {
    TableMirror::new(u64::from(table_id), "table", [0xC0; 20], 9, small_blind, big_blind, [0xC0; 20])
}

/// 通过 pk_hex 查座位里的钱包地址（server 座位表）。
fn mirror_seat_wallet_by_pk(table_id: u32, pk_hex: &GamePkHex) -> Option<String> {
    let _ = table_id;
    SEAT_WALLETS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
        .lock().ok()
        .and_then(|map| map.get(&pk_hex.0).cloned())
}

static SEAT_WALLETS: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, String>>> = std::sync::OnceLock::new();

pub fn register_seat_wallet(pk_hex: &str, wallet: &str) {
    let m = SEAT_WALLETS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    if let Ok(mut map) = m.lock() {
        map.insert(pk_hex.to_string(), wallet.to_string());
    }
}

/// 钱包重映射表：poker_l1 座位地址（钱包 felt 的低 160 位截断）→ 真实钱包 felt。
/// mirror 座位只存 20 字节截断地址，而 vault 余额以完整钱包 felt 为键，
/// settle_hand 上链前据此把参与者地址重映射回真实钱包。
pub fn seat_wallet_remaps() -> Vec<(poker_l1::Address, String)> {
    let Some(map) = SEAT_WALLETS
        .get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
        .lock()
        .ok()
    else {
        return Vec::new();
    };
    let mut out: Vec<(poker_l1::Address, String)> = map
        .values()
        .filter_map(|w| super::mirror::TableMirror::addr_from_starknet(w).map(|a| (a, w.clone())))
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out.dedup_by(|a, b| a.0 == b.0);
    out
}

/// 直接记录 join（bot 进程内路径：wallet + pk 点 + 80 字节证明）。
pub fn mirror_buffer_join_raw(
    table_id: u32,
    wallet: &str,
    pk_hex: &str,
    proof: Vec<u8>,
) {
    let Some(addr) = TableMirror::addr_from_starknet(wallet) else { return };
    // pk_hex → zgame EcPoint（裸 G1Projective）→ ptx ECPoint（borsh 桥）
    let Ok(pk_zg) = poker_protocol::z_poker::convert::hex_to_ecpoint(pk_hex) else { return };
    let pk_ptx = match crate::starknet::mirror::conv::ec_point(&poker_protocol::crypto::types::ECPoint(pk_zg)) {
        Ok(p) => p,
        Err(e) => { eprintln!("[mirror] pk conv: {e}"); return; }
    };
    record_join(table_id, addr, 1000, pk_ptx, proof);
}
