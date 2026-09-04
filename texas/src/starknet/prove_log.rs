//! 手牌证明输入记录（Phase 2，TODO #20）。
//!
//! 取代常驻 TableMirror（第二本账）：游戏层在**接受动作的同一条代码路径**
//! 上把已验证输入追加进每手 [`HandProofLog`]（join 缓冲 → HandStart 快照 →
//! reveal/下注/强制弃牌命令）。结算时 `hooks::on_hand_complete` 把日志克隆
//! 出锁，由构建器（mirror.rs 的 TableMirror）**一次性**重放出 ProveTask 链
//! 与 pre-payout 快照——VM 不再是持久同步副本，失步类 bug（2026-09-04
//! hand 2 未结算的 insufficient-stack 根因）整类消失。
//!
//! 记录纪律（与旧 mirror 单点派发相同）：
//! - 只在游戏层**接受**动作后记录（非法输入到不了这里）；
//! - reveal 令牌按 (pk, 令牌集) 去重（客户端幂等重试不重复记录）；
//! - auto 代打（超时 fold/check/call）与手动动作走同一 accept 点，天然覆盖。

use poker_texas_air::prove_task::ProveTask;
// 别名约定与 mirror.rs 相同：zgame poker_protocol → ptx 类型桥。
use poker_protocol as ptx_protocol;
pub use ptx_protocol::crypto::types::ECPoint as PtxECPoint;
pub use ptx_protocol::crypto::ElGamalCiphertext as PtxElGamalCiphertext;

use crate::pokergame::table::Table;

/// 单条已接受的手牌命令（重放输入）。
#[derive(Debug, Clone)]
pub enum HandCommand {
    /// 玩家揭牌令牌（DealHole / flop / turn / river / showdown 同一通道）。
    RevealTokens {
        /// 玩家 pk（游戏层座位标识，hex）。
        pk_hex: String,
        /// 客户端原始令牌（转换在构建时进行，与旧 mirror 接受点等价）。
        tokens: Vec<poker_protocol::z_poker::protocol::RevealToken>,
    },
    /// 下注动作（含 auto 代打——同一 accept 点）。
    Bet {
        pk_hex: String,
        /// "fold" | "check" | "call" | "raise"。
        action: &'static str,
        /// raise 语义：加注后本轮总下注额。
        total_bet: Option<u64>,
    },
    /// 手牌进行中玩家被移除（超时踢出/离桌）的强制弃牌。
    ForceFold { wallet: String },
}

/// HandStart 快照：deck 终局时刻的手牌静态事实（全部在盲注扣除前采集）。
#[derive(Debug, Clone)]
pub struct HandStartData {
    /// 按游戏座位号升序的参与者（与 VM DealHole 升序座位规范对齐）。
    pub participants: Vec<HandParticipant>,
    /// 按参与者序列中按钮的序号（VM post_blinds 据此对齐盲注位）。
    pub button_rank: u8,
    /// 小盲注额（大盲 = 2×）。
    pub small_blind: u64,
    /// 终局 deck（52 张，游戏层与 VM 逐字节同源——方案A 注入）。
    pub deck: Vec<PtxElGamalCiphertext>,
}

/// 一名参与者（join 重放输入）。
#[derive(Debug, Clone)]
pub struct HandParticipant {
    /// 钱包 felt（hex，全精度——结算记账户头）。
    pub wallet: String,
    /// 玩家 pk hex（游戏层座位标识；命令按它匹配座位）。
    pub pk_hex: String,
    /// mental-poker ElGamal 公钥（ptx ECPoint）。
    pub pk: PtxECPoint,
    /// pk 所有权证明（80 字节序列化，join_table 验证）。
    pub pk_ownership_proof: Vec<u8>,
    /// 手牌开始时（盲注前）的游戏层 stack——跨手结转的真相，
    /// 取代入座时的原始 buy_in（2026-09-04 hand 2 根因修复）。
    pub stack: u64,
}

/// 每手证明输入日志（挂在游戏 Table 上，`serde(skip)`）。
#[derive(Debug, Clone, Default)]
pub struct HandProofLog {
    /// HandStart 快照（deck 终局时写入；None = 本手未开局，无可证明结算）。
    pub start: Option<HandStartData>,
    /// 已接受命令（时序即重放序）。
    pub commands: Vec<HandCommand>,
    /// reveal 去重键（pk + 令牌集哈希）——客户端幂等重试不重复记录。
    seen_reveals: std::collections::HashSet<u64>,
}

impl HandProofLog {
    fn hash_reveal(pk_hex: &str, tokens: &[poker_protocol::z_poker::protocol::RevealToken]) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        pk_hex.hash(&mut h);
        for t in tokens {
            // RevealToken 未实现 Hash/Borsh：Debug 表示足以做去重键。
            format!("{t:?}").hash(&mut h);
        }
        h.finish()
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
            participants: plan.into_iter().map(|(_, p)| p).collect(),
            button_rank,
            small_blind: sb,
            deck,
        }),
        commands: Vec::new(),
        seen_reveals: std::collections::HashSet::new(),
    };
}

/// reveal 令牌接受点（submit_reveal_tokens_for_pk 成功后）。
pub fn record_reveal(table: &mut Table, pk_hex: &str, tokens: &[poker_protocol::z_poker::protocol::RevealToken]) {
    if tokens.is_empty() {
        return;
    }
    let log = &mut table.hand_proof_log;
    if log.start.is_none() {
        return; // 未开局（如重建桌后的迟到提交）
    }
    let key = HandProofLog::hash_reveal(pk_hex, tokens);
    if !log.seen_reveals.insert(key) {
        return; // 幂等重试
    }
    log.commands.push(HandCommand::RevealTokens {
        pk_hex: pk_hex.to_string(),
        tokens: tokens.to_vec(),
    });
}

/// 下注动作接受点（betting.rs 各 handle_* 成功后；auto 代打同一路径）。
pub fn record_bet(table: &mut Table, pk_hex: &str, action: &'static str, total_bet: Option<u64>) {
    let log = &mut table.hand_proof_log;
    if log.start.is_none() {
        return;
    }
    log.commands.push(HandCommand::Bet {
        pk_hex: pk_hex.to_string(),
        action,
        total_bet,
    });
}

/// 手牌进行中移除玩家的强制弃牌接受点。
pub fn record_force_fold(table: &mut Table, wallet: &str) {
    let log = &mut table.hand_proof_log;
    if log.start.is_none() {
        return;
    }
    log.commands.push(HandCommand::ForceFold {
        wallet: wallet.to_string(),
    });
}

/// 结算输入：日志克隆 + 游戏层终局事实（对账基准）。
pub struct HandSettleInput {
    pub table_id: u32,
    pub log: HandProofLog,
    /// 游戏层事实（on_hand_complete 时刻）：summary.rake_collected。
    pub rake_collected: u64,
    /// 每座位的本手总投入（wallet hex → total_bet）。
    pub total_bets: Vec<(String, u64)>,
    /// 已亮公共牌数。
    pub board_len: usize,
}

/// on_hand_complete 时从游戏层提取结算输入（锁内仅克隆，重活全部在锁外）。
pub fn take_settle_input(table: &Table) -> Option<HandSettleInput> {
    if table.hand_proof_log.start.is_none() {
        return None;
    }
    let total_bets = table
        .seats()
        .iter()
        .filter_map(|(_, s)| {
            s.player
                .as_ref()
                .map(|p| (p.wallet_address.0.clone(), s.total_bet))
        })
        .collect();
    Some(HandSettleInput {
        table_id: table.summary.id,
        log: table.hand_proof_log.clone(),
        rake_collected: table.summary.rake_collected,
        total_bets,
        board_len: table.mental_poker_game.list_revealed_community_cards().len(),
    })
}

/// 类型再导出：构建产物（mirror TableMirror）与 ProveTask 同源。
pub type BuiltMirror = super::mirror::TableMirror;

/// 便于构建器复用：ProveTask 再导出（本模块 doc 提及）。
pub type ProofTask = ProveTask;
