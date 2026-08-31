//! 牌局镜像：把 WS 牌局操作同步 dispatch 到 poker_l1 的 TexasPokerTable VM，
//! 收集每手牌的 ProveTask，供结算时生成证明链与 Starknet calldata。
//!
//! 镜像是**从动副本**：权威状态仍由 pokergame/ 的本地状态机维护（驱动 WS 广播），
//! 镜像只把等价操作喂给 poker_l1 VM。两者输入相同（前端提交的证明与动作），
//! 因此结算时镜像表的 seats/total_bet/pot 与真实牌局一致。
//!
//! 类型桥接：服务端现有代码把前端 JSON 解析为 zgame poker_protocol（0.2.0）类型；
//! poker_l1 使用 poker_texas_air 内的 poker_protocol（0.1.0）类型。两份副本的
//! crypto/proofs 结构逐字节一致（构建期 diff 验证），通过 borsh roundtrip 转换。

use borsh::{BorshDeserialize, BorshSerialize};
use poker_l1::object_model::ObjectID;
use poker_l1::signature::TaggedPubkey;
use poker_l1::vm::contracts::dispatch::DispatchContext;
use poker_l1::vm::contracts::texas_poker::dispatch::{self as texas_dispatch};
use poker_l1::vm::contracts::texas_poker::dispatch::{
    RaiseArgs, SeatIndexArgs, SubmitReconstructDeckArgs, SubmitRevealTokensArgs,
    SubmitShuffleV2Args,
};
use poker_l1::vm::contracts::texas_poker::types::{CipherDeck, SeatMask, ShuffleState, TexasPokerTable};
use poker_texas_air::prove_task::{DispatchOutput, ProveTask};
// 别名：源仓库里 ptx_protocol 是 poker_protocol 的重命名依赖；迁入工作区后
// cargo 不允许同一路径依赖出现两次，这里用 use 别名等价替代。
use poker_protocol as ptx_protocol;
// 公开 re-export：e2e 测试与上层 hook 复用这些类型别名。
pub use ptx_protocol::crypto::types::ECPoint as PtxECPoint;
pub use ptx_protocol::crypto::ElGamalCiphertext as PtxElGamalCiphertext;
pub use ptx_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof as PtxRevealTokenProof;
use ptx_protocol::zk_shuffle::reconstruction::{ReconstructProofV3 as PtxReconstructProofV3, ReconstructionV3Statement as PtxReconstructionV3Statement};
pub use ptx_protocol::zk_shuffle::ShuffleProof as PtxShuffleProof;
pub use ptx_protocol::crypto::DefaultCurve as PtxCurve;


/// 单桌镜像。生命周期：建桌 → 每手 start → 操作 → 结算 → 下一手。
#[derive(Clone)]
pub struct TableMirror {
    pub table: TexasPokerTable,
    /// 当前手牌收集的证明任务（每手结算后清空）。
    pub tasks: Vec<ProveTask>,
    /// 派奖前快照（board/pot/total_bet 完整），供 SettleHandCalldata 构建。
    /// 在 showdown 展示期结束、advance_deadline 派奖之前调用 [`mark_pre_settlement`]。
    pub pre_settlement: Option<TexasPokerTable>,
    /// 本 mirror 的 table_id 种子（hand_binding 的 table_id 分量）。
    pub table_seed: u64,
    /// 服务器 caller 地址（镜像内管理操作如 advance_deadline 的 caller）。
    caller: poker_l1::Address,
    block_height: u64,
    /// 抽水参数（begin_reveal_hand 时写入镜像桌面）。
    pub rake_bps: u16,
    pub rake_cap: u64,
}

impl TableMirror {
    /// 建桌。`table_id_seed` 用于派生确定性的镜像对象 ID。
    pub fn new(
        table_id_seed: u64,
        name: &str,
        creator: poker_l1::Address,
        max_players: u8,
        small_blind: u64,
        big_blind: u64,
        caller: poker_l1::Address,
    ) -> Self {
        let table = TexasPokerTable::new(
            ObjectID::new([0x5A; 20], table_id_seed),
            name.to_string(),
            creator,
            max_players,
            small_blind,
            big_blind,
        );
        Self {
            table,
            table_seed: table_id_seed,
            tasks: Vec::new(),
            pre_settlement: None,
            caller,
            block_height: 1,
            rake_bps: poker_l1::vm::contracts::texas_poker::constants::DEFAULT_RAKE_BPS,
            rake_cap: poker_l1::vm::contracts::texas_poker::constants::DEFAULT_RAKE_CAP,
        }
    }

    /// 派奖前打快照（showdown reveal 完成、advance_deadline 之前调用）。
    pub fn mark_pre_settlement(&mut self) {
        self.pre_settlement = Some(self.table.clone());
    }

    fn context(&self, caller: poker_l1::Address) -> DispatchContext {
        DispatchContext {
            caller,
            caller_pubkey: TaggedPubkey {
                tag: 0,
                raw: vec![0xA4; 32],
            },
            chain_id: 377,
            block_height: self.block_height,
            block_timestamp: now_ms(),
        }
    }

    /// dispatch 一个动作并收集产出的 ProveTask。
    pub fn apply(
        &mut self,
        caller: poker_l1::Address,
        selector: &[u8; 32],
        args: Vec<u8>,
    ) -> Result<(), String> {
        self.block_height += 1;
        let ctx = self.context(caller);
        let result = texas_dispatch::dispatch(&ctx, &mut self.table, selector, &args)
            .map_err(|e| format!("mirror dispatch failed: {e}"))?;
        let output: DispatchOutput = borsh::from_slice(&result.return_value)
            .map_err(|e| format!("mirror dispatch output decode failed: {e}"))?;
        if let Some(task) = output.prove_task {
            self.tasks.push(task);
        }
        Ok(())
    }

    /// 玩家入座（对应 SIT_DOWN_V2 的 join 步骤）。
    ///
    /// `player` 为玩家 Starknet 地址（20 字节），`pk` 为其 mental-poker ElGamal 公钥
    /// （与前端 pkHex 同源），`pk_ownership_proof` 为 80 字节 Schnorr 证明。
    pub fn join(
        &mut self,
        player: poker_l1::Address,
        buy_in_chips: u64,
        pk: PtxECPoint,
        pk_ownership_proof: Vec<u8>,
    ) -> Result<(), String> {
        use poker_l1::vm::contracts::texas_poker::dispatch::JoinTableArgs;
        let args = borsh::to_vec(&JoinTableArgs {
            player,
            buy_in: buy_in_chips,
            pk,
            pk_ownership_proof,
        })
        .map_err(|e| format!("encode join args: {e}"))?;
        self.apply(player, &texas_dispatch::selectors::join_table(), args)
    }

    /// 方案A 注入式开局：把游戏层**已终局**（全部客户端洗牌已验证、底牌已发）的
    /// deck 原样注入 VM，并让 VM 直接进入 DealHole reveal 窗口。
    ///
    /// `plan` 为按游戏座位号升序排列的参与座位（与 VM DealHole 的升序座位规范
    /// 对齐，保证 deck index → 玩家映射逐字节一致）；`button_rank` 是游戏层按钮
    /// 在该序列中的序号。此调用发生在任何 dispatch 之前，不产生 ProveTask，
    /// 后续 reveal/bet 任务在该注入状态上连续（满足 MethodBatch 状态连续性）。
    pub fn begin_reveal_hand(
        &mut self,
        deck: Vec<PtxElGamalCiphertext>,
        plan: &[(poker_l1::Address, u64, PtxECPoint, Vec<u8>)],
        button_rank: u8,
        hand_id: u32,
    ) -> Result<(), String> {
        // 全新手状态（TableMirror 由调用方刚构造）：清上一手残留，保证
        // deck 注入点是干净 canonical 状态。
        self.pre_settlement = None;
        self.tasks.clear();
        self.table.community_cards.clear();
        self.table.pot = 0;
        self.table.hand_id = hand_id;

        // join：按升序座位计划重放（VM find_empty_seat 顺序填座 →
        // mirror 座位 rank == 游戏座位 rank）。
        for (player, buy_in, pk, proof) in plan {
            self.join(*player, *buy_in, pk.clone(), proof.clone())
                .map_err(|e| format!("begin_reveal join: {e}"))?;
        }
        if self.table.seats.iter().all(|s| seat_player_addr(s).is_none()) {
            return Err("begin_reveal: no joined seats".into());
        }
        // join_table 产生的座位是 Waiting（等待大盲）状态；VM 原生流程由
        // start_hand 的 promote_waiting_for_big_blind 提升，注入式开局跳过
        // start_hand，这里等价执行"全新桌全体 Waiting 座位同时入局"规则，
        // 使 DealHole 的 active 座位集合与游戏层参与者一致。
        for seat in self.table.seats.iter_mut() {
            seat.promote_waiting();
        }

        // button 对齐：游戏层按钮在参与座位中的 rank（VM post_blinds 据此
        // 计算盲注位置，与游戏层盲注玩家保持一致）。
        self.table.button = button_rank.min(self.table.seats.len().saturating_sub(1) as u8);

        // 抽水规则：到手牌进入翻后（flop 及以后，即出现公共牌的争夺底池）才抽，
        // 翻前结束（无人跟注的 uncontested 底池）不抽。VM 结算的硬性不变量
        // `uncontested pot must not be raked` 天然满足前半条；这里启用百分比
        // 模式使"到翻后的争夺底池"按 bps 抽水（有单手 cap）。
        self.table.rake_mode = poker_l1::vm::contracts::texas_poker::constants::RAKE_MODE_PERCENTAGE;
        self.table.rake_bps = self.rake_bps;
        self.table.rake_cap = self.rake_cap;

        // deck 注入 + contributor 全量 + 直接进入 DealHole：
        // pending_mask = 0（游戏层洗牌已在注入前完成，VM 跳过洗牌阶段），
        // advance_shuffle 触发 ShuffleComplete → start_preflop_reveal_phase →
        // 按 VM 规范（升序座位，每人 2 张）创建 DealHole reveal 窗口。
        let cards: [PtxElGamalCiphertext; 52] = deck
            .try_into()
            .map_err(|_| "mirror deck must contain exactly 52 cards".to_string())?;
        self.table.deck_state.encrypted = CipherDeck::Active(Box::new(cards));
        self.table.deck_state.cards_dealt = 0;
        self.table.deck_state.owner_readable_hole_cards.clear();
        let mut contributor_mask: SeatMask = 0;
        for idx in 0..self.table.seats.len().min(16) {
            if seat_player_addr(&self.table.seats[idx]).is_some() {
                contributor_mask |= 1u16 << idx;
            }
        }
        self.table.deck_state.contributor_mask = contributor_mask;
        self.table
            .enter_initial_shuffling(
                ShuffleState {
                    pending_mask: 0,
                    completed_mask: 0,
                },
                now_ms(),
            )
            .map_err(|e| format!("mirror enter_initial_shuffling failed: {e}"))?;
        // 规范化推进：武装 deadline + 驱动 ShuffleComplete → DealHole，
        // 与 dispatch 后的 canonical 归一化保持一致。
        let mut events = Vec::new();
        poker_l1::vm::contracts::texas_poker::state_machine::normalize_until_blocked(
            &mut self.table,
            now_ms(),
            &mut events,
        )
        .map_err(|e| format!("mirror normalize after deck injection: {e}"))?;
        if self.table.reveal_token_state().is_none() {
            return Err("begin_reveal: DealHole reveal window did not start".into());
        }
        Ok(())
    }

    /// 当前 DealHole/Board/Showdown reveal 窗口中该座位待提交的密文
    /// （canonical 顺序）。调用方据此把客户端提交的 token 集合重排成
    /// VM 要求的 canonical 顺序（全有或全无）。
    pub fn pending_reveal_ciphertexts(&self, seat_index: u8) -> Result<Vec<PtxElGamalCiphertext>, String> {
        let Some(state) = self.table.reveal_token_state() else {
            return Err("reveal phase is NONE".into());
        };
        let mut out = Vec::new();
        for a in &state.assignments {
            if a.pending_mask & (1u16 << seat_index) != 0 {
                // showdown：验证目标是 ledger 保存的完整密文（与客户端生成
                // 证明所用密文逐字节一致）；其他阶段用当前 deck 密文。
                let ct = if self.table.reveal_phase()
                    == poker_l1::vm::contracts::texas_poker::constants::REVEAL_PHASE_SHOWDOWN
                {
                    let poker_l1::vm::contracts::texas_poker::types::RevealTarget::Hole {
                        seat_index: owner,
                        card_slot,
                    } = a.target
                    else {
                        return Err("showdown assignment must target hole".into());
                    };
                    self.table
                        .deck_state
                        .owner_readable_hole_cards
                        .get(owner, card_slot)
                        .map(|p| p.full_ciphertext)
                        .ok_or_else(|| "showdown partial ledger missing".to_string())?
                } else {
                    *self
                        .table
                        .deck_state
                        .encrypted
                        .get(a.encrypted_card_index as usize)
                        .ok_or_else(|| "reveal card index out of range".to_string())?
                };
                out.push(ct);
            }
        }
        Ok(out)
    }

    /// 玩家洗牌提交（对应 WS `SHUFFLE_SUBMIT`）。
    pub fn submit_shuffle(
        &mut self,
        seat_index: u8,
        output_cards: Vec<PtxElGamalCiphertext>,
        shuffle_proof: PtxShuffleProof,
    ) -> Result<(), String> {
        let caller = self.seat_player(seat_index)?;
        let args = borsh::to_vec(&SubmitShuffleV2Args {
            seat_index,
            output_cards,
            shuffle_proof,
        })
        .map_err(|e| format!("encode shuffle args: {e}"))?;
        self.apply(caller, &texas_dispatch::selectors::submit_shuffle_v2(), args)
    }

    /// 玩家揭牌令牌提交。
    pub fn submit_reveal_tokens(
        &mut self,
        seat_index: u8,
        reveal_tokens: Vec<PtxECPoint>,
        proofs: Vec<PtxRevealTokenProof<PtxCurve>>,
    ) -> Result<(), String> {
        let caller = self.seat_player(seat_index)?;
        let args = borsh::to_vec(&SubmitRevealTokensArgs {
            seat_index,
            reveal_tokens,
            proofs,
        })
        .map_err(|e| format!("encode reveal args: {e}"))?;
        self.apply(caller, &texas_dispatch::selectors::submit_player_reveal_tokens(), args)
    }

    /// 牌组重构提交（失败牌补救路径；镜像尽力跟随）。
    pub fn submit_reconstruct(
        &mut self,
        seat_index: u8,
        statement: PtxReconstructionV3Statement<PtxCurve>,
        proof: PtxReconstructProofV3<PtxCurve>,
    ) -> Result<(), String> {
        let caller = self.seat_player(seat_index)?;
        let args = borsh::to_vec(&SubmitReconstructDeckArgs {
            seat_index,
            statement,
            proof,
        })
        .map_err(|e| format!("encode reconstruct args: {e}"))?;
        self.apply(caller, &texas_dispatch::selectors::submit_reconstruct_deck(), args)
    }

    pub fn fold(&mut self, seat_index: u8) -> Result<(), String> {
        let caller = self.seat_player(seat_index)?;
        let args = borsh::to_vec(&SeatIndexArgs { seat_index }).map_err(|e| e.to_string())?;
        self.apply(caller, &texas_dispatch::selectors::fold(), args)
    }

    pub fn check(&mut self, seat_index: u8) -> Result<(), String> {
        let caller = self.seat_player(seat_index)?;
        let args = borsh::to_vec(&SeatIndexArgs { seat_index }).map_err(|e| e.to_string())?;
        self.apply(caller, &texas_dispatch::selectors::check(), args)
    }

    pub fn call(&mut self, seat_index: u8) -> Result<(), String> {
        let caller = self.seat_player(seat_index)?;
        let args = borsh::to_vec(&SeatIndexArgs { seat_index }).map_err(|e| e.to_string())?;
        self.apply(caller, &texas_dispatch::selectors::call(), args)
    }

    /// 加注。`total_bet` 是加注后本轮总下注额（与 WS RAISE 语义一致）。
    pub fn raise(&mut self, seat_index: u8, total_bet: u64) -> Result<(), String> {
        let caller = self.seat_player(seat_index)?;
        let args = borsh::to_vec(&RaiseArgs {
            seat_index,
            total_bet,
        })
        .map_err(|e| e.to_string())?;
        self.apply(caller, &texas_dispatch::selectors::raise(), args)
    }

    /// 超时强制推进（game_loop tick 驱动）。
    pub fn advance_deadline(&mut self) -> Result<(), String> {
        // ShowdownDisplay 派奖前打快照：此刻摊牌 reveal 已完成（seat.hand 已物化
        // 两张明文牌），board/pot/total_bet 仍完整——正是 SettleHandCalldata 需要的
        // pre-payout 表。派奖后 board 复位、pot 清零，无法再派生 settlement plan。
        if matches!(
            self.table.hand_phase,
            poker_l1::vm::contracts::texas_poker::types::HandPhase::ShowdownDisplay { .. }
        ) {
            self.mark_pre_settlement();
        }
        self.apply(self.caller, &texas_dispatch::selectors::advance_deadline(), Vec::new())
    }





    /// 当前镜像牌组（52 张，poker_l1 类型）。
    pub fn deck(&self) -> Vec<PtxElGamalCiphertext> {
        self.table.deck_state.encrypted.to_vec()
    }

    /// 按玩家地址查镜像座位号。
    pub fn seat_index_of(&self, player: poker_l1::Address) -> Option<u8> {
        self.table
            .seats
            .iter()
            .position(|s| seat_player_addr(s) == Some(player))
            .map(|i| i as u8)
    }

    fn seat_player(&self, seat_index: u8) -> Result<poker_l1::Address, String> {
        self.table
            .seats
            .get(seat_index as usize)
            .and_then(seat_player_addr)
            .ok_or_else(|| format!("mirror seat {seat_index} has no player"))
    }

    /// 手牌是否已收集到至少一个证明任务（有任务才有可结算的证明链）。
    pub fn has_provable_activity(&self) -> bool {
        !self.tasks.is_empty()
    }

    /// 从 Starknet felt 地址派生 poker_l1 地址（32 字节大端取低 20 字节）。
    pub fn addr_from_starknet(felt_hex: &str) -> Option<poker_l1::Address> {
        let felt = super::chain::parse_felt(felt_hex)?;
        let bytes = felt.to_bytes_be();
        Some(bytes[12..32].try_into().expect("20 bytes"))
    }
}

/// 从座位提取玩家地址（settle_hand 参与者来源）。
pub fn seat_player_addr(seat: &poker_l1::vm::contracts::texas_poker::types::Seat) -> Option<poker_l1::Address> {
    use poker_l1::vm::contracts::texas_poker::types::Seat;
    match seat {
        Seat::Playing { playing } => Some(playing.occupied.player),
        Seat::Waiting { occupied } => Some(occupied.player),
        Seat::DepartedThisHand { player, .. } => Some(*player),
        Seat::Vacant { .. } => None,
    }
}

/// zgame poker_protocol → ptx poker_protocol 的 borsh roundtrip 转换。
/// 两份副本结构一致（构建期 diff 校验），转换仅跨 crate 类型边界。
pub mod conv {
    use super::*;

    pub fn ciphertext(
        ct: &poker_protocol::crypto::ElGamalCiphertext,
    ) -> Result<PtxElGamalCiphertext, String> {
        let bytes = borsh::to_vec(ct).map_err(|e| e.to_string())?;
        borsh::from_slice(&bytes).map_err(|e| format!("ciphertext borsh bridge: {e}"))
    }

    pub fn ciphertexts(
        cts: &[poker_protocol::crypto::ElGamalCiphertext],
    ) -> Result<Vec<PtxElGamalCiphertext>, String> {
        cts.iter().map(ciphertext).collect()
    }

    pub fn shuffle_proof(
        proof: &poker_protocol::zk_shuffle::ShuffleProof,
    ) -> Result<PtxShuffleProof, String> {
        let bytes = borsh::to_vec(proof).map_err(|e| e.to_string())?;
        borsh::from_slice(&bytes).map_err(|e| format!("shuffle proof borsh bridge: {e}"))
    }

    pub fn ec_point(p: &poker_protocol::crypto::types::ECPoint) -> Result<PtxECPoint, String> {
        let bytes = borsh::to_vec(p).map_err(|e| e.to_string())?;
        borsh::from_slice(&bytes).map_err(|e| format!("ec point borsh bridge: {e}"))
    }

    pub fn reveal_token_proof(
        proof: &poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof<poker_protocol::crypto::DefaultCurve>,
    ) -> Result<PtxRevealTokenProof<PtxCurve>, String> {
        let bytes = borsh::to_vec(proof).map_err(|e| e.to_string())?;
        borsh::from_slice(&bytes).map_err(|e| format!("reveal token proof borsh bridge: {e}"))
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 全局镜像注册表：table_id → TableMirror。
/// SocketState 持有；所有访问都短暂持锁（dispatch 是同步 CPU 操作）。
#[derive(Default)]
pub struct MirrorRegistry {
    mirrors: std::sync::Mutex<std::collections::HashMap<u32, TableMirror>>,
}

impl MirrorRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// 获取或创建桌镜像。`create` 仅在首次访问时调用；`f` 在持锁状态下执行。
    pub fn with_mirror<F, R>(
        &self,
        table_id: u32,
        create: impl FnOnce() -> TableMirror,
        f: F,
    ) -> Result<R, String>
    where
        F: FnOnce(&mut TableMirror) -> Result<R, String>,
    {
        let mut guards = self.mirrors.lock().map_err(|e| e.to_string())?;
        let mirror = guards.entry(table_id).or_insert_with(create);
        f(mirror)
    }

    /// 用新构造的 mirror 替换该桌现有实例（仅限手牌边界的
    /// mirror_begin_reveal 调用；手牌进行中禁止替换）。
    pub fn install(&self, table_id: u32, mirror: TableMirror) {
        if let Ok(mut guards) = self.mirrors.lock() {
            guards.insert(table_id, mirror);
        }
    }

}
