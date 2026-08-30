//! 服务器接线钩子：把牌局事件桥接到 Starknet mirror 与链上结算。
//!
//! - [`mirror_registry`]：全局 TableMirror 注册表（table_id → mirror）
//! - [`on_hand_complete`]：finish_showdown 时触发，取镜像手牌 → prove →
//!   outer aggregate → Cairo calldata → 操作员账户提交 register_aggregate +
//!   settle_hand（配置齐备时；dev 模式只记日志）

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

/// 手牌结束（finish_showdown）：结算证明 + 上链。
///
/// prove 约 2 秒/手，放 spawn_blocking，不阻塞 game_loop。
/// 所有失败仅记日志——链上结算失败不影响链下记账（服务器栈数已更新），
/// 可由后续对账流程补偿。
/// 每手只触发一次结算（进程内去重）。链上防重放（binding/hand_id）
/// 是硬保护；本守卫只避免重复证明与重复提交工作。
static SETTLED_HANDS: OnceLock<std::sync::Mutex<std::collections::HashSet<(u32, u32)>>> =
    OnceLock::new();

fn mark_hand_settled_once(table_id: u32, hand_id: u32) -> bool {
    let set = SETTLED_HANDS
        .get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()));
    set.lock().map(|mut g| g.insert((table_id, hand_id))).unwrap_or(false)
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
            if !mark_hand_settled_once(table_id, mirror.table.hand_id) {
                return Ok(None); // 本手已触发过结算（链上幂等保护兜底）
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
            Ok(Some((settlement, binding)))
        },
    );
    let (settlement, binding) = match result {
        Ok(Some(s)) => s,
        Ok(None) => {
            eprintln!("[starknet-settle] hand skipped: mirror has no provable activity (hand did not run through mirror)");
            return;
        } // 该手无可证明活动（如无洗牌即结束）
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
                        // 第二阶段镜像借用：从 registry 重新取（状态持久）。
                        let built = mirror_registry().with_mirror(
                            table_id,
                            || TableMirror::new(u64::from(table_id), "table", [0xC0; 20], 9, 10, 20, [0xC0; 20]),
                            |mirror| {
                                super::dual_settle::build_dual_settlement_from_client(
                                    mirror,
                                    &settlement,
                                    &endorsed,
                                )
                            },
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
            Ok((register_hash, settle_hash)) => tracing::info!(
                "[starknet-settle] table {table_id} hand {} on-chain: register={register_hash} settle={settle_hash}",
                settlement.hand_id
            ),
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

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}


// ---------------------------------------------------------------------------
// 运行时镜像同步：把 WS 牌局事件喂给 TableMirror
// ---------------------------------------------------------------------------

use crate::pokergame::player::GamePkHex;
use crate::pokergame::game_state::{ElGamalCiphertextJson, ShuffleProofJson};
use crate::pokergame::table::Table;
use poker_protocol::crypto::curve::Curve;
use std::collections::HashMap;

/// 单桌缓冲：延迟 join（poker_l1 join_table 仅允许 Waiting，而服务器允许洗牌期入座）
#[derive(Default)]
struct PendingJoins {
    joins: Vec<(poker_l1::Address, u64, super::mirror::PtxECPoint, Vec<u8>)>,
}

static PENDING: OnceLock<std::sync::Mutex<HashMap<u32, PendingJoins>>> = OnceLock::new();

fn pending_for(table_id: u32) -> &'static std::sync::Mutex<HashMap<u32, PendingJoins>> {
    PENDING.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

fn with_pending<R>(table_id: u32, f: impl FnOnce(&mut PendingJoins) -> R) -> R {
    let mut map = pending_for(table_id).lock().unwrap();
    f(map.entry(table_id).or_default())
}

/// SIT_DOWN_V2 成功后调用：缓冲玩家 join（等下一手 begin_hand 时批量应用）。
/// 缓冲一个 join（带真实 80 字节 pk 所有权证明）。
pub fn mirror_buffer_join_pk(
    table_id: u32,
    wallet_addr: &str,
    pk_hex: &str,
    buy_in: u64,
    pk_proof: &crate::pokergame::game_state::PkProofJson,
    proof_bytes: Vec<u8>,
) -> Result<(), String> {
    let Some(addr) = TableMirror::addr_from_starknet(wallet_addr) else { return Err("bad wallet".into()) };
    // pk_hex → ptx ECPoint：poker_protocol 的 z_poker::convert::hex_to_ecpoint 返回
    // zgame EcPoint(G1Projective)，直接取内点再包为 ptx ECPoint
    let zp = poker_protocol::z_poker::convert::hex_to_ecpoint(pk_hex)
        .map_err(|e| format!("pk hex: {e}"))?;
    let pk = crate::starknet::mirror::conv::ec_point(&poker_protocol::crypto::types::ECPoint(zp))
        .map_err(|e| format!("pk conv: {e}"))?;
    with_pending(table_id, |p| p.joins.push((addr, buy_in, pk, proof_bytes)));
    Ok(())
}

/// start_preflop_shuffle 时调用：应用缓冲 joins + 开局 + mirror 自治初始洗牌。
///
/// zgame 客户端的 join_and_shuffle（玩家自行 mask）与 poker_l1 的
/// join_table+submit_shuffle_v2（服务端 add_pk）洗牌语义不同，deck 链无法
/// 逐字节同步。因此 mirror 走自治链：join_table → start_hand → mirror 内部
/// 用真实玩家 pk 生成初始洗牌（poker_protocol 真实 BG 证明，产 dual-proof
/// 任务）。settle 的赢家以 mirror 牌局为准（生产需客户端协议对齐，见
/// DUAL_PROOF_PROTOCOL.md §5.3）。
pub fn mirror_begin_hand(table: &Table) {
    let table_id = table.summary.id;
    let joins = with_pending(table_id, |p| std::mem::take(&mut p.joins));
    let out = mirror_registry().with_mirror(
        table_id,
        || new_mirror(table_id),
        |mirror| {
            for (addr, buy_in, pk, proof) in joins {
                if let Err(e) = mirror.join(addr, buy_in, pk, proof) {
                    tracing::warn!("[mirror] join buffered apply failed: {e}");
                    continue;
                }
            }
            mirror.begin_hand([0xC0; 20]).map_err(|e| format!("begin_hand: {e}"))?;
            // mirror 自治初始洗牌：每个已 join 座位一次真实 BG 洗牌
            mirror.autonomous_initial_shuffle()
        },
    );
    if let Err(e) = out {
        tracing::warn!("[mirror] begin_hand: {e}");
    }
}

/// SHUFFLE_SUBMIT 成功后调用。
pub fn mirror_shuffle_submit(
    table: &Table,
    pk_hex: &GamePkHex,
    output_cards: &[poker_protocol::crypto::ElGamalCiphertext],
    shuffle_proof: &poker_protocol::zk_shuffle::ShuffleProof,
) {
    let table_id = table.summary.id;
    let Some(seat) = mirror_seat_of(table, pk_hex) else { return };
    let Ok(out) = super::mirror::conv::ciphertexts(output_cards) else { return };
    let Ok(proof) = super::mirror::conv::shuffle_proof(shuffle_proof) else { return };
    if let Err(e) = mirror_registry().with_mirror(
        table_id,
        || new_mirror(table_id),
        |m| m.submit_shuffle(seat, out, proof).map_err(|e| e),
    ) {
        tracing::warn!("[mirror] shuffle sync failed: {e}");
    }
}

/// 下注动作成功后调用。
pub fn mirror_betting(table: &Table, pk_hex: &GamePkHex, action: &str, total_bet: Option<u64>) {
    let table_id = table.summary.id;
    let Some(seat) = mirror_seat_of(table, pk_hex) else { return };
    let result = mirror_registry().with_mirror(table_id, || new_mirror(table_id), |m| {
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
    });
    if let Err(e) = result {
        tracing::warn!("[mirror] betting sync failed ({action}): {e}");
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

/// SHUFFLE_SUBMIT / submit_verified_shuffle_for_pk 成功后调用。
pub fn sync_shuffle(
    table: &Table,
    pk_hex: &GamePkHex,
    output_cards: &[ElGamalCiphertextJson],
    shuffle_proof: &ShuffleProofJson,
) {
    let table_id = table.summary.id;
    let out: Vec<_> = output_cards.iter()
        .filter_map(|c| c.to_ciphertext().ok())
        .collect();
    let (Ok(proof_typed), Ok(out_ptx)) = (shuffle_proof.to_proof(), crate::starknet::mirror::conv::ciphertexts(&out)) else { return };
    let Ok(proof_ptx) = crate::starknet::mirror::conv::shuffle_proof(&proof_typed) else { return };

    // seat：从 registry 里 mirror 的座位（需先 join 过）
    let Some(wallet) = mirror_seat_wallet(table, pk_hex) else { return };
    let Some(addr) = TableMirror::addr_from_starknet(&wallet) else { return };
    if let Err(e) = mirror_registry().with_mirror(table_id, || new_mirror(table_id), |m| {
        let Some(seat) = m.seat_index_of(addr) else { return Ok(()) };
        m.submit_shuffle(seat, out_ptx, proof_ptx)
    }) {
        tracing::warn!("[mirror] shuffle sync failed: {e}");
    }
}

/// REVEAL 提交成功后调用（reveal 提交由 state 层在 token 提交时完成，
/// poker_l1 的 submit_player_reveal_tokens 已推进 mirror 的 reveal 窗口）。
pub fn mirror_reveal_submit(_table: &Table, _pk_hex: &GamePkHex, _tokens: &[poker_protocol::z_poker::protocol::RevealToken]) {
}

/// 洗牌证明镜像同步（state 层调用）。

/// state 层 reveal 镜像：把已验证 tokens 提交进 poker_l1 mirror（产 ProveTask）。
pub fn mirror_sync_reveal(
    table_id: u32,
    pk_hex: &GamePkHex,
    tokens: &[poker_protocol::z_poker::protocol::RevealToken],
) {
    let Some(wallet) = mirror_seat_wallet_by_pk(table_id, pk_hex) else { return };
    let Some(addr) = TableMirror::addr_from_starknet(&wallet) else { return };
    let Some(seat) = mirror_registry().with_mirror(table_id, || new_mirror(table_id), |m| {
        Ok(m.seat_index_of(addr))
    }).ok().flatten() else { return };

    let mut pt_tokens = Vec::new();
    let mut proofs = Vec::new();
    for t in tokens {
        let Ok(tok) = crate::starknet::mirror::conv::ec_point(&poker_protocol::crypto::types::ECPoint(
            t.reveal_token.clone(),
        )) else { return };
        let Ok(proof) = crate::starknet::mirror::conv::reveal_token_proof(&t.proof) else { return };
        pt_tokens.push(tok);
        proofs.push(proof);
    }
    if let Err(e) = mirror_registry().with_mirror(table_id, || new_mirror(table_id), |m| {
        m.submit_reveal_tokens(seat, pt_tokens, proofs)
    }) {
        tracing::warn!("[mirror] reveal sync failed: {e}");
    }
}

/// 通过 pk_hex 查座位里的钱包地址（server 座位表）。
fn mirror_seat_wallet_by_pk(table_id: u32, pk_hex: &GamePkHex) -> Option<String> {
    // 由调用方（SocketState）持有 gs——这里用静态注册表查询。
    // 简化：调用点在 state 方法内，改为直接传入 wallet。保留占位。
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

fn mirror_seat_wallet(table: &Table, pk_hex: &GamePkHex) -> Option<String> {
    table.local_seats.values()
        .find(|s| s.player.as_ref().map(|p| p.pk_hex.0 == pk_hex.0).unwrap_or(false))
        .and_then(|s| s.player.as_ref())
        .map(|p| p.wallet_address.0.clone())
}

/// 直接缓冲 join（bot 进程内路径：wallet + pk 点 + 80 字节证明）。
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
    with_pending(table_id, |p| p.joins.push((addr, 1000, pk_ptx, proof)));
}


// ---------------------------------------------------------------------------
// mirror 直驱接口（dev_bot 用：对 mirror 自己的 deck 生成 token 推进状态机）
// ---------------------------------------------------------------------------

/// 当前 mirror reveal 阶段中该座位待提交的加密卡（poker_l1 谱系）。
pub fn mirror_pending_reveal_cards(table_id: u32, addr: poker_l1::Address)
    -> Result<Option<Vec<crate::starknet::mirror::PtxElGamalCiphertext>>, String>
{
    mirror_registry().with_mirror(table_id, || new_mirror(table_id), |m| {
        let Some(seat) = m.seat_index_of(addr) else { return Ok(None) };
        let Some(state) = m.table.reveal_token_state() else { return Ok(None) };
        let is_showdown = m.table.reveal_phase()
            == poker_l1::vm::contracts::texas_poker::constants::REVEAL_PHASE_SHOWDOWN;
        let mut out = Vec::new();
        for a in &state.assignments {
            if a.pending_mask & (1u16 << seat) != 0 {
                // showdown：owner 账本的部分密文（非 owner 层已剥离）
                let ct = if is_showdown {
                    let poker_l1::vm::contracts::texas_poker::types::RevealTarget::Hole {
                        seat_index: owner,
                        card_slot,
                    } = a.target
                    else {
                        return Ok(None);
                    };
                    match m
                        .table
                        .deck_state
                        .owner_readable_hole_cards
                        .get(owner, card_slot)
                    {
                        Some(p) => p.ciphertext,
                        None => return Ok(None),
                    }
                } else {
                    match m.table.deck_state.encrypted.get(a.encrypted_card_index as usize) {
                        Some(ct) => *ct,
                        None => return Ok(None),
                    }
                };
                out.push(ct);
            }
        }
        Ok(Some(out))
    })
}

/// 直接向 mirror 提交 reveal tokens（bot 用自己 sk 对 mirror deck 卡生成）。
pub fn mirror_submit_reveal(
    table_id: u32,
    addr: poker_l1::Address,
    tokens: Vec<crate::starknet::mirror::PtxECPoint>,
    proofs: Vec<crate::starknet::mirror::PtxRevealTokenProof<crate::starknet::mirror::PtxCurve>>,
) -> Result<(), String> {
    mirror_registry().with_mirror(table_id, || new_mirror(table_id), |m| {
        let seat = m.seat_index_of(addr).ok_or_else(|| "no seat".to_string())?;
        m.submit_reveal_tokens(seat, tokens, proofs)
    })
}

/// 直接向 mirror 提交下注动作。
pub fn mirror_submit_betting(
    table_id: u32,
    addr: poker_l1::Address,
    action: &str,
    total_bet: Option<u64>,
) -> Result<(), String> {
    mirror_registry().with_mirror(table_id, || new_mirror(table_id), |m| {
        let seat = m.seat_index_of(addr).ok_or_else(|| "no seat".to_string())?;
        match action {
            "fold" => m.fold(seat),
            "check" => m.check(seat),
            "call" => m.call(seat),
            "raise" => match total_bet {
                Some(tb) => m.raise(seat, tb),
                None => Err("raise requires amount".into()),
            },
            other => Err(format!("unknown action {other}")),
        }
    })
}

/// mirror 当前下注轮的行动者与待跟差额（zgame seat 侧视图）。
pub fn mirror_betting_state(table_id: u32, addr: poker_l1::Address)
    -> Option<(u8, u64)>
{
    mirror_registry().with_mirror(table_id, || new_mirror(table_id), |m| {
        let Some(seat) = m.seat_index_of(addr) else { return Ok(None) };
        let actor = m.table.current_turn_option();
        let other = m.table.seats.iter()
            .enumerate()
            .filter(|(i, s)| *i != seat as usize && s.is_occupied())
            .map(|(_, s)| s.total_bet())
            .max()
            .unwrap_or(0);
        Ok(actor.map(|a| (a, other)))
    }).ok().flatten()
}

/// mirror 当前是否在洗牌阶段（自治洗牌已内置，恒 false）。
pub fn mirror_shuffle_active(table_id: u32) -> bool {
    mirror_registry().with_mirror(table_id, || new_mirror(table_id), |m| {
        Ok(m.table.shuffle_state().pending_mask != 0)
    }).unwrap_or(false)
}

/// mirror 手牌是否仍在进行（reveal/betting/showdown 任一活跃）。
pub fn mirror_hand_active(table_id: u32) -> bool {
    mirror_registry().with_mirror(table_id, || new_mirror(table_id), |m| {
        Ok(m.table.hand_phase != poker_l1::vm::contracts::texas_poker::types::HandPhase::Waiting
            || m.table.shuffle_state().pending_mask != 0
            || m.table.reveal_token_state().is_some())
    }).unwrap_or(false)
}

/// mirror 中该地址座位的 total_bet。
pub fn mirror_seat_bet(table_id: u32, addr: poker_l1::Address) -> Option<u64> {
    mirror_registry().with_mirror(table_id, || new_mirror(table_id), |m| {
        let Some(seat) = m.seat_index_of(addr) else { return Ok(None) };
        Ok(m.table.seats.get(seat as usize).map(|s| s.total_bet()))
    }).ok().flatten()
}

/// mirror 状态快照（调试用）。
pub fn mirror_state_snapshot(table_id: u32) -> Option<String> {
    mirror_registry().with_mirror(table_id, || new_mirror(table_id), |m| {
        Ok(Some(format!(
            "hand={} phase={:?} shuffle_pending={} reveal_active={} turn={:?} tasks={}",
            m.table.hand_id,
            m.table.hand_phase,
            m.table.shuffle_state().pending_mask,
            m.table.reveal_token_state().is_some(),
            m.table.current_turn_option(),
            m.tasks.len(),
        )))
    }).ok().flatten()
}

/// mirror 中该地址的座位号。
pub fn mirror_my_seat(table_id: u32, addr: poker_l1::Address) -> Option<u8> {
    mirror_registry().with_mirror(table_id, || new_mirror(table_id), |m| {
        Ok(m.seat_index_of(addr))
    }).ok().flatten()
}

/// mirror 是否处于 ShowdownDisplay 且展示期已过。
pub fn mirror_showdown_display_expired(table_id: u32) -> bool {
    mirror_registry().with_mirror(table_id, || new_mirror(table_id), |m| {
        use poker_l1::vm::contracts::texas_poker::types::HandPhase;
        // ShowdownDisplay 的 deadline 在 phase 内携带；仅按阶段推进（bot 轮询频率足够）
        Ok(matches!(m.table.hand_phase, HandPhase::ShowdownDisplay { .. }))
    }).unwrap_or(false)
}

/// mirror advance_deadline（ShowdownDisplay 派奖 / 下注超时推进）。
pub fn mirror_advance_deadline(table_id: u32) -> Result<(), String> {
    mirror_registry().with_mirror(table_id, || new_mirror(table_id), |m| {
        m.advance_deadline()
    })
}
