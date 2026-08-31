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
pub struct TableMirror {
    pub table: TexasPokerTable,
    /// 当前手牌收集的证明任务（每手结算后清空）。
    pub tasks: Vec<ProveTask>,
    /// 待应用 join（下一手 begin_hand 前批量 dispatch join_table）。
    pub pending_joins: Vec<(poker_l1::Address, u64, PtxECPoint, Vec<u8>)>,
    /// 派奖前快照（board/pot/total_bet 完整），供 SettleHandCalldata 构建。
    /// 在 showdown 展示期结束、advance_deadline 派奖之前调用 [`mark_pre_settlement`]。
    pub pre_settlement: Option<TexasPokerTable>,
    /// 本 mirror 的 table_id 种子（hand_binding 的 table_id 分量）。
    pub table_seed: u64,
    /// 服务器 caller 地址（镜像内管理操作如 advance_deadline 的 caller）。
    caller: poker_l1::Address,
    block_height: u64,
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
            pending_joins: Vec::new(),
            pre_settlement: None,
            caller,
            block_height: 1,
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
    fn apply(
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

    /// 设置初始加密牌组并进入洗牌阶段（每手开始时调用）。
    ///
    /// `deck` 为服务端 deck.rs 维护的 52 张加密牌（zgame 类型，经 borsh 转换），
    /// `pending_mask` 的每一位对应一个需要洗牌的座位。
    pub fn start_hand(
        &mut self,
        deck: Vec<PtxElGamalCiphertext>,
        pending_mask: SeatMask,
        contributor_mask: SeatMask,
    ) -> Result<(), String> {
        // 新一手开始：上一手的结算快照失效（settle_hand 若未跑也不能跨手复用）。
        self.pre_settlement = None;
        let cards: [PtxElGamalCiphertext; 52] = deck
            .try_into()
            .map_err(|_| "mirror deck must contain exactly 52 cards".to_string())?;
        self.table.deck_state.encrypted =
            CipherDeck::Active(Box::new(cards));
        self.table.deck_state.contributor_mask = contributor_mask;
        self.table
            .enter_initial_shuffling(
                ShuffleState {
                    pending_mask,
                    completed_mask: 0,
                },
                now_ms(),
            )
            .map_err(|e| format!("mirror enter_initial_shuffling failed: {e}"))?;
        self.tasks.clear();
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

    /// 用服务端真实的初始牌组覆写镜像牌组。
    ///
    /// start_hand 内部生成的 sk=0 牌组与 zgame 服务器 MentalPokerGame 生成的
    /// 聚合密钥牌组在密钥层上不同；客户端洗牌证明是针对后者生成的，
    /// 因此 begin_hand 之后、首个洗牌提交之前调用此方法对齐输入
    /// （与 poker_texas_air 官方 e2e 测试的手工 deck 注入方式一致）。
    pub fn set_deck(&mut self, deck: Vec<PtxElGamalCiphertext>) -> Result<(), String> {
        let cards: [PtxElGamalCiphertext; 52] = deck
            .try_into()
            .map_err(|_| "mirror deck must contain exactly 52 cards".to_string())?;
        self.table.deck_state.encrypted = CipherDeck::Active(Box::new(cards));
        Ok(())
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

    /// 缓冲一个 join（等待 begin_hand 应用）。
    pub fn buffer_join(&mut self, player: poker_l1::Address, buy_in: u64, pk: PtxECPoint, proof: Vec<u8>) {
        self.pending_joins.push((player, buy_in, pk, proof));
    }


    /// mirror 自治初始洗牌：对当前 sk=0 牌组，按 poker_l1 的 shuffler 轮转，
    /// 为每个已 join 座位生成真实 BG 洗牌证明并 dispatch（产 dual-proof 任务）。
    pub fn autonomous_initial_shuffle(&mut self) -> Result<(), String> {
        use poker_protocol::crypto::DefaultCurve;
        use poker_protocol::crypto::curve::{Curve, CurveScalar};
        use poker_protocol::zk_shuffle::transcript_ext::{CryptoTranscript, FiatShamirTranscript};
        use rand::rngs::OsRng;

        // 派生各座位 pk（mirror table 的座位 pk）
        let mut rounds = 0;
        loop {
            let seat_index = self.table.shuffle_state().derived_current_shuffler();
            if seat_index == u8::MAX || self.table.shuffle_state().pending_mask == 0 {
                break;
            }
            if rounds > 9 {
                return Err("too many shuffle rounds".into());
            }
            rounds += 1;
            let Some(seat_pk) = self.table.seats[seat_index as usize].pk().copied() else {
                return Err(format!("seat {seat_index} has no pk"));
            };
            let agg_pk = self
                .table
                .derived_aggregated_pk()
                .map_err(|e| format!("agg pk: {e}"))?
                .map(|p| p.0)
                .unwrap_or_else(|| <DefaultCurve as Curve>::base_g());

            // 输入 = mirror 当前 deck（zgame 类型），输出 = 真实重加密+置换
            let input: Vec<poker_protocol::crypto::ElGamalCiphertext> = self
                .table
                .deck_state
                .encrypted
                .to_vec()
                .iter()
                .map(|ct| poker_protocol::crypto::ElGamalCiphertext { c1: ct.c1, c2: ct.c2 })
                .collect();
            let n = input.len();
            let mut permutation: Vec<usize> = (0..n).collect();
            for i in (1..n).rev() {
                let j = rand::Rng::gen_range(&mut rand::thread_rng(), 0..=i);
                permutation.swap(i, j);
            }
            let rerandomizers: Vec<_> = (0..n)
                .map(|_| <DefaultCurve as Curve>::Scalar::random(&mut OsRng))
                .collect();
            let output: Vec<_> = (0..n)
                .map(|i| input[permutation[i]].re_encrypt(&agg_pk, &rerandomizers[i]))
                .collect();
            let proof = poker_protocol::zk_shuffle::ShuffleProof::prove(
                &input,
                &output,
                &permutation,
                &rerandomizers,
                &agg_pk,
                &mut OsRng,
                &mut FiatShamirTranscript::new(b"zk_shuffle_proof_v2"),
            )
            .map_err(|e| format!("autonomous shuffle prove: {e}"))?;

            let out_ptx = conv::ciphertexts(&output)?;
            let proof_ptx = conv::shuffle_proof(&proof)?;
            self.submit_shuffle(seat_index, out_ptx, proof_ptx)
                .map_err(|e| format!("autonomous shuffle dispatch: {e}"))?;
        }
        Ok(())
    }

    /// 开局（对应服务端 start_preflop_shuffle）：应用缓冲 joins 后 dispatch start_hand。
    /// poker_l1 的 start_hand 内部生成 52 张 sk=0 初始加密牌组并进入洗牌阶段。
    pub fn begin_hand(&mut self, creator: poker_l1::Address) -> Result<(), String> {
        // 应用缓冲 joins（poker_l1 join_table 仅允许 Waiting，洗牌期入座延迟至此）
        let joins = std::mem::take(&mut self.pending_joins);
        for (player, buy_in, pk, proof) in joins {
            self.join(player, buy_in, pk, proof)
                .map_err(|e| format!("buffered join: {e}"))?;
        }
        self.apply(creator, &texas_dispatch::selectors::start_hand(), Vec::new())
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

    /// 丢弃该桌 mirror 状态并在全新实例上执行 `f`。
    /// 用于 mirror 卡死在中间态（超时/弃牌把 round_state 停在非 Waiting）、
    /// begin_hand 永久失败的自愈。
    pub fn with_fresh_mirror<F, R>(
        &self,
        table_id: u32,
        create: impl FnOnce() -> TableMirror,
        f: F,
    ) -> Result<R, String>
    where
        F: FnOnce(&mut TableMirror) -> Result<R, String>,
    {
        let mut guards = self.mirrors.lock().map_err(|e| e.to_string())?;
        guards.remove(&table_id);
        let mirror = guards.entry(table_id).or_insert_with(create);
        f(mirror)
    }
}
