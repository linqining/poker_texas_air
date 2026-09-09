//! 手牌证明事实记录（单一状态架构）。
//!
//! 职责只剩两件：
//! 1. **HandStart 快照**（deck 终局时刻的参与者/公钥/所有权证明/deck）——
//!    实时 VM 镜像（`shadow::hand_start`）的开局引导输入，以及结算时
//!    钱包重映射与 snip36 动作签名材料的参与者来源；
//! 2. **游戏层对账事实**（终局投入快照、逐笔派奖、台费）——结算时
//!    `cross_check_snapshot` / `cross_check_deltas` 的比对基准。
//!
//! 历史上的"已接受命令日志"（HandCommand 流 + 结算时 `build_from_log`
//! 重放）已随单一状态重构删除：VM 状态只存在一份，就是实时镜像——
//! 每个接受点同步 dispatch，结算直接取用，不再有第二份重放表示。

// 别名约定：zgame poker_protocol → ptx 类型桥（与 mirror.rs 相同）。
use poker_protocol as ptx_protocol;
pub use ptx_protocol::crypto::types::ECPoint as PtxECPoint;
pub use ptx_protocol::crypto::ElGamalCiphertext as PtxElGamalCiphertext;

use crate::pokergame::table::Table;

/// HandStart 快照：deck 终局时刻的手牌静态事实（全部在盲注扣除前采集）。
#[derive(Debug, Clone)]
pub struct HandStartData {
    /// 本手 id——开局时分配（`next_hand_id`），动作签名挑战域与结算
    /// 记账共用同一值；结算侧不再另行分配。
    pub hand_id: u32,
    /// 按游戏座位号升序的参与者（与 VM DealHole 升序座位规范对齐）。
    pub participants: Vec<HandParticipant>,
    /// 按参与者序列中按钮的序号（VM post_blinds 据此对齐盲注位）。
    pub button_rank: u8,
    /// 小盲注额（大盲 = 2×）。
    pub small_blind: u64,
    /// 终局 deck（52 张，游戏层与 VM 逐字节同源——方案A 注入）。
    pub deck: Vec<PtxElGamalCiphertext>,
}

/// 一名参与者（开局引导输入：join 重放 + 结算记账户头）。
#[derive(Debug, Clone)]
pub struct HandParticipant {
    /// 游戏座位号（动作日志条目按它映射到本结构的 pk）。
    pub seat: u32,
    /// 钱包 felt（hex，全精度——结算记账户头）。
    pub wallet: String,
    /// 玩家 pk hex（游戏层座位标识）。
    pub pk_hex: String,
    /// mental-poker ElGamal 公钥（ptx ECPoint）。
    pub pk: PtxECPoint,
    /// pk 所有权证明（80 字节序列化，join_table 验证）。
    pub pk_ownership_proof: Vec<u8>,
    /// 手牌开始时（盲注前）的游戏层 stack——跨手结转的真相，
    /// 取代入座时的原始 buy_in（2026-09-04 hand 2 根因修复）。
    pub stack: u64,
}

/// 每手证明事实（挂在游戏 Table 上，`serde(skip)`）。
#[derive(Debug, Clone, Default)]
pub struct HandProofLog {
    /// HandStart 快照（deck 终局时写入；None = 本手未开局，无可证明结算）。
    pub start: Option<HandStartData>,
    /// 本手终局投入快照（wallet → total_bet）——派彩前采集。
    /// `win_hand`（seat.rs）派彩时会清零赢家自己的 `total_bet`，而
    /// `take_settle_input` 在派彩后执行：不快照则摊牌手的对账恒为
    /// "vm 累计 vs game 0" 必拒（2026-09-07 线上两手复现）。
    pub final_total_bets: Option<Vec<(String, u64)>>,
    /// 本手派奖记录（wallet → 净得金额，含边池/主池多次累加）——
    /// 派奖接受点（win_hand 调用处）采集。与 final_total_bets 一起
    /// 构成游戏层净输赢对账基准：game_delta = Σpayouts − final_total_bet。
    pub payouts: Vec<(String, u64)>,
}

impl HandProofLog {
    /// 测试夹具：仅含开局 hand_id 的日志（动作签名域 v2 的验证前置）。
    #[cfg(test)]
    pub fn with_hand_start_for_test(hand_id: u32) -> Self {
        Self {
            start: Some(HandStartData {
                hand_id,
                participants: Vec::new(),
                button_rank: 0,
                small_blind: 10,
                deck: Vec::new(),
            }),
            final_total_bets: None,
            payouts: Vec::new(),
        }
    }
}

/// SIT_DOWN/JOIN 时的 pk 所有权证明缓冲：(table_id, wallet) → (pk_hex, proof)。
/// 仅是 socket 层与下一次 HandStart 之间的交接缓冲，不是状态账本
/// （上一手未入局的残留会被 HandStart 的"参与者过滤"自然淘汰）。
static JOIN_BUFFER: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<(u32, String), (String, Vec<u8>)>>,
> = std::sync::OnceLock::new();

fn join_buffer() -> &'static std::sync::Mutex<std::collections::HashMap<(u32, String), (String, Vec<u8>)>> {
    JOIN_BUFFER.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// SIT_DOWN / join 成功后记录 pk 所有权证明（下一手 HandStart 消费）。
pub fn record_join(table_id: u32, wallet: &str, pk_hex: &str, proof_bytes: Vec<u8>) {
    if let Ok(mut g) = join_buffer().lock() {
        g.insert((table_id, wallet.to_string()), (pk_hex.to_string(), proof_bytes));
    }
}

/// deck 终局（advance_shuffle 完成、盲注未扣）时采集 HandStart 快照。
/// 任何参与者缺 join 证明 → 本手不记录（结算时显式跳过并告警），
/// 与旧 mirror_begin_reveal 的放弃语义一致，绝不阻塞牌局。
/// 每桌单调递增的 hand_id。种子取 unix 秒：服务器重启后仍满足链上
/// register_aggregate 的 first_hand_id 严格递增校验。
static HAND_ID_SEQ: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<u32, u32>>> =
    std::sync::OnceLock::new();

pub(crate) fn next_hand_id(table_id: u32) -> u32 {
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

pub fn record_hand_start(table: &mut Table) {
    let table_id = table.summary.id;
    let sb = table.summary.min_bet.max(1);
    let deck = match super::mirror::conv::ciphertexts(&table.mental_poker_game.deck_encrypted) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!("[prove-log] table {table_id} deck conv failed: {e} — hand unprovable");
            table.hand_proof_log = HandProofLog::default();
            return;
        }
    };

    let joins = join_buffer().lock().ok();
    let mut plan: Vec<(u32, HandParticipant)> = Vec::new();
    let mut missing_proof = false;
    for (seat_id, seat) in table.seats() {
        let Some(player) = seat.player.as_ref() else { continue };
        if seat.sitting_out || seat.is_waiting {
            continue;
        }
        let Some((pk_hex, proof)) = joins.as_ref().and_then(|j| {
            j.get(&(table_id, player.wallet_address.0.clone())).cloned()
        }) else {
            tracing::warn!(
                "[prove-log] table {table_id} seat {seat_id} has no buffered join proof — hand unprovable"
            );
            missing_proof = true;
            break;
        };
        let pk = match poker_protocol::z_poker::convert::hex_to_ecpoint(&pk_hex)
            .map(|zp| super::mirror::conv::ec_point(&poker_protocol::crypto::types::ECPoint(zp)))
        {
            Ok(Ok(p)) => p,
            _ => {
                tracing::warn!("[prove-log] table {table_id} seat {seat_id} pk conv failed — hand unprovable");
                missing_proof = true;
                break;
            }
        };
        plan.push((seat_id, HandParticipant {
            seat: seat_id,
            wallet: player.wallet_address.0.clone(),
            pk_hex,
            pk,
            pk_ownership_proof: proof,
            // 盲注未扣：seat.stack 即本手开始真相（跨手结转，含此前输赢）
            stack: seat.stack,
        }));
    }
    if missing_proof {
        table.hand_proof_log = HandProofLog::default();
        return;
    }
    // 与旧 mirror_begin_reveal 相同：按游戏座位号升序（VM DealHole 升序
    // 座位规范，保证 deck index → 玩家映射逐字节一致），button 取其在
    // 参与者序列中的序号。
    plan.sort_by_key(|(seat_id, _)| *seat_id);
    if plan.len() < 2 {
        // 与 MIN_START_NUM 一致：不足 2 人无手牌
        table.hand_proof_log = HandProofLog::default();
        return;
    }
    let button_rank = table
        .button()
        .and_then(|b| plan.iter().position(|(seat_id, _)| *seat_id == b))
        .unwrap_or(0) as u8;

    table.hand_proof_log = HandProofLog {
        start: Some(HandStartData {
            hand_id: table.current_hand_id,
            participants: plan.into_iter().map(|(_, p)| p).collect(),
            button_rank,
            small_blind: sb,
            deck,
        }),
        final_total_bets: None,
        payouts: Vec::new(),
    };
    // 实时 VM 镜像开局（单一状态表示的起点；镜像随桌挂载）。
    if let Some(start) = table.hand_proof_log.start.as_ref() {
        table.live_mirror = crate::starknet::shadow::bootstrap(table_id, start);
    }
}

/// 派彩前快照终局投入（摊牌/fold-win 两条终局路径各调用一次；重复调用
/// 以首次为准——首次才是派彩前语义）。
pub fn record_final_bets(table: &mut Table) {
    if table.hand_proof_log.start.is_none() {
        return;
    }
    if table.hand_proof_log.final_total_bets.is_some() {
        return;
    }
    let bets = table
        .seats()
        .iter()
        .filter_map(|(_, s)| {
            s.player
                .as_ref()
                .map(|p| (p.wallet_address.0.clone(), s.total_bet))
        })
        .collect();
    table.hand_proof_log.final_total_bets = Some(bets);
}

/// 派奖接受点（determine_winner_by_ids / end_without_showdown 的
/// win_hand 调用处；边池+主池多次派奖累加）。金额为净得（已扣台费）。
pub fn record_payout(table: &mut Table, wallet: &str, amount: u64) {
    let log = &mut table.hand_proof_log;
    if log.start.is_none() {
        return;
    }
    log.payouts.push((wallet.to_string(), amount));
}

/// 结算输入：HandStart 快照 + 游戏层终局事实（对账基准）。
pub struct HandSettleInput {
    pub table_id: u32,
    /// HandStart 快照（非 Optional：None 时 take_settle_input 直接返回 None）。
    pub start: HandStartData,
    /// 游戏层事实（on_hand_complete 时刻）：summary.rake_collected。
    pub rake_collected: u64,
    /// 每座位的本手总投入（wallet hex → total_bet）。
    pub total_bets: Vec<(String, u64)>,
    /// 本手派奖（wallet hex → 累计净得，净输赢对账的另一半）。
    pub payouts: Vec<(String, u64)>,
    /// 已亮公共牌数。
    pub board_len: usize,
    /// 本手动作日志哈希（#18 Phase C 切片 1 起 = Poseidon 吸收链根，
    /// 32 字节大端）——settlement digest 吸收链尾词 + v2 公开段尾词。
    pub action_log_digest: [u8; 32],
    /// 本手动作日志词条（Phase C 切片 1）：电路按 64 槽 × 5 词重放整链的
    /// 见证输入；超上限的日志在结算构建时拒绝。
    pub action_log: Vec<crate::pokergame::actions::ActionLogEntry>,
}

/// on_hand_complete 时从游戏层提取结算输入（锁内仅克隆，重活全部在锁外）。
pub fn take_settle_input(table: &Table) -> Option<HandSettleInput> {
    let start = table.hand_proof_log.start.clone()?;
    // 优先用派彩前快照（终局投入语义，与实时 VM 镜像对账）；无快照（异常
    // 路径/旧手）回退实时读取。
    let total_bets = table
        .hand_proof_log
        .final_total_bets
        .clone()
        .unwrap_or_else(|| {
            table
                .seats()
                .iter()
                .filter_map(|(_, s)| {
                    s.player
                        .as_ref()
                        .map(|p| (p.wallet_address.0.clone(), s.total_bet))
                })
                .collect()
        });
    // 与 pot.rs 审计日志同窗口（hand_log_start 起的本手动作）。
    let window = &table.action_log[table.hand_log_start.min(table.action_log.len())..];
    let action_log_digest = crate::pokergame::actions::action_log_digest_felt(window).to_bytes_be();
    let action_log = window.to_vec();
    Some(HandSettleInput {
        table_id: table.summary.id,
        start,
        rake_collected: table.summary.rake_collected,
        total_bets,
        payouts: table.hand_proof_log.payouts.clone(),
        board_len: table.mental_poker_game.list_revealed_community_cards().len(),
        action_log_digest,
        action_log,
    })
}
