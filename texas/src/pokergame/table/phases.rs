use super::*;
use crate::pokergame::game_state::{PlayerRevealAssignment, RevealPhase, RevealTokenState, ShufflePhase};
use poker_protocol::crypto::ElGamalCiphertext;

impl Table {
    /// 对齐 Move do_start_hand（table.move:850-870）：
    /// 仅 move_button + start_preflop_shuffle + advance_shuffle。
    /// 不在此处发牌（deal_preflop），发牌在洗牌完成后由 on_before_preflop_shuffle_complete 执行，
    /// 与 Move 一致（Move 的 deal_preflop 在 start_preflop_reveal_phase 中）。
    /// 盲注和下注轮在 on_reveal_complete(HandReveal) 中通过 set_blinds + init_turn + start_betting_round(true) 创建。
    pub fn start_hand(&mut self) {
        if self.round_state() != RoundState::Waiting{
            return;
        }
        if self.active_players().len() < MIN_START_NUM as usize{
            return;
        }

        // move_button
        self.move_button();

        // 初始化洗牌状态（对齐 Move start_preflop_shuffle + Rust 特有的玩家登记/清理）
        self.start_preflop_shuffle();

        // 推进洗牌流程（对齐 Move advance_shuffle）
        self.advance_shuffle();
    }

    /// 对齐 Move move_button（table.move:2028-2040）：
    /// 从当前 button+1 开始找下一个 occupied 座位。
    pub fn move_button(&mut self) {
        let max = self.max_players();
        let cur = self.button().unwrap_or(0);
        let mut next = cur + 1;
        for _ in 0..max {
            if next > max {
                next = 1;
            }
            if self.seats().contains_key(&next) {
                self.set_button(Some(next));
                return;
            }
            next += 1;
        }
    }

    /// 对齐 Move start_preflop_shuffle（table.move:845-848）：
    /// 设置 phase=BeforePreflop + 初始化 pending_players。
    /// Rust 额外做玩家登记/清理（remove_inactive_players/register_waiting_players/clear_waiting_flags），
    /// 这些在 Move 中由 join/leave 时维护，Rust 在此统一处理。
    pub fn start_preflop_shuffle(&mut self) {
        // Rust 特有：清理不活跃玩家、登记 waiting 玩家、清除 waiting 标记
        let already_completed: std::collections::HashSet<GamePkHex> =
            self.shuffle_state.completed_players.iter().cloned().collect();
        self.remove_inactive_players();
        self.register_waiting_players();
        self.clear_waiting_flags();

        // 对齐 Move start_preflop_shuffle：pending_players = 未完成洗牌的活跃玩家
        self.init_pending_players(&already_completed);

        // 对齐 Move：phase = BeforePreflop
        self.shuffle_state.phase = ShufflePhase::BeforePreflop;
        self.shuffle_state.timeout_seconds = 45;

        // Starknet 镜像：批量应用缓冲 join + poker_l1 start_hand
        crate::starknet::hooks::mirror_begin_hand(self);
    }

    /// 对齐 Move：BeforePreflop 洗牌完成后发牌（在 advance_shuffle 中调用）。
    /// 等价于原 start_hand 的发牌部分：reset board/pot/bets + unfold + deal_preflop。
    pub fn on_before_preflop_shuffle_complete(&mut self) {
        self.summary.went_to_showdown = false;
        self.reset_board_and_pot();
        self.reset_bets_and_actions();
        self.unfold_players();
        self.summary.history = vec![];
        if self.active_players().len() > 1 {
            self.deal_preflop();
            self.summary.hand_over = false;
        }

        self.update_history();
    }

    pub fn unfold_players(&mut self) {
        for seat in self.local_seats.values_mut() {
            seat.folded = seat.sitting_out;
            seat.total_bet = 0;
        }
    }

    pub fn init_turn(&mut self) {
        let active = self.active_players();
        let new_turn = if active.len() <= 3 {
            self.button()
        } else {
            self.next_active_player(self.button().unwrap_or(1), 3)
        };
        self.set_turn(new_turn);
    }

    /// 对齐 Move post_blinds：发布盲注 + 设置首行动作（current_turn）。
    /// 非 heads-up: 首行动作 = BB 后第一个活跃玩家（UTG）
    /// heads-up: 首行动作 = SB/Button
    pub fn set_blinds(&mut self) {
        let is_heads_up = self.active_players().len() == 2;
        let button = self.button().unwrap_or(1);

        let sb = if is_heads_up {
            Some(button)
        } else {
            self.next_active_player(button, 1)
        };
        self.set_small_blind(sb);
        let bb = if is_heads_up {
            self.next_active_player(button, 1)
        } else {
            self.next_active_player(button, 2)
        };
        self.set_big_blind(bb);

        let mut sb_amount: u64 = 0;
        let mut bb_amount: u64 = 0;

        if let Some(sb) = self.small_blind() {
            if let Some(seat) = self.local_seats.get_mut(&sb) {
                let actual_sb = seat.place_blind(self.summary.min_bet);
                sb_amount = actual_sb;
            }
        }
        if let Some(bb) = self.big_blind() {
            if let Some(seat) = self.local_seats.get_mut(&bb) {
                let actual_bb = seat.place_blind(self.summary.min_bet * 2);
                bb_amount = actual_bb;
            }
        }

        self.set_pot(self.pot() + sb_amount + bb_amount);
        self.summary.call_amount = Some(self.summary.min_bet * 2);
        self.set_min_raise(self.summary.min_bet * 2); // = big_blind; minimum re-raise equals the big blind

        // 对齐 Move post_blinds：设置首行动作
        // C5 修复扩展：盲注后可能全员 all-in，需要检查是否有可行动玩家
        if self.has_actionable_player() {
            let first_to_act = if is_heads_up {
                // heads-up: SB/Button 先行动，但 SB 可能已 all-in
                let sb_all_in = self.seats().get(&sb.unwrap_or(button))
                    .map_or(true, |s| s.stack == 0);
                if sb_all_in {
                    // SB all-in，找下一个可行动玩家（BB 或更远）
                    self.next_unfolded_player(sb.unwrap_or(button), 1)
                } else {
                    sb
                }
            } else {
                // 非 heads-up: BB 后第一个活跃玩家
                self.next_unfolded_player(bb.unwrap_or(button), 1)
            };
            self.set_turn(first_to_act);
        } else {
            // 全员 all-in，不设置 turn，start_betting_round 会跳过下注轮
            self.set_turn(None);
        }
    }

    /// Set blinds using on-chain values (from BlindsPosted event).
    /// Unlike set_blinds which calculates positions/amounts, this directly
    /// uses the values from the chain event. Used when BlindsPosted event
    /// drives the off-chain state.
    pub fn set_blinds_from_chain(
        &mut self,
        sb_seat: u64,
        bb_seat: u64,
        sb_amount: u64,
        bb_amount: u64,
        first_to_act: u64,
    ) {
        // Post small blind
        let mut sb_actual: u64 = 0;
        if let Some(seat) = self.local_seats.get_mut(&(sb_seat as u32)) {
            let sb_amt = std::cmp::min(sb_amount, seat.stack);
            sb_actual = seat.place_blind(sb_amt);
        }
        self.add_to_pot(sb_actual);

        // Post big blind
        let mut bb_actual: u64 = 0;
        if let Some(seat) = self.local_seats.get_mut(&(bb_seat as u32)) {
            let bb_amt = std::cmp::min(bb_amount, seat.stack);
            bb_actual = seat.place_blind(bb_amt);
        }
        self.add_to_pot(bb_actual);

        // Set betting state from chain values.
        // 对齐 set_blinds：call_amount = bb_amount，min_raise = bb_amount
        self.summary.call_amount = Some(bb_amount);
        self.set_min_raise(bb_amount);
        self.set_turn(Some(first_to_act as u32));
    }

    pub fn deal_preflop(&mut self) {
        let max = self.max_players();
        let button = self.button().unwrap_or(1);
        let order: Vec<u32> = (button..=max).chain(1..button).collect();

        for _ in 0..2 {
            for &seat_id in &order {
                let is_turn = self.turn() == Some(seat_id);
                if let Some(seat) = self.local_seats.get_mut(&seat_id) {
                    if let Some(player) = &seat.player{
                        if !seat.sitting_out {
                            tracing::info!("player {} is not sitting out,deal to {}", player.name, seat_id);
                            if let Err(e) = self.mental_poker_game.deal_to_player(&player.pk_hex.clone(), 1) {
                                tracing::error!("[deal_preflop] deal_to_player failed for player {} seat {}: {:?}", player.name, seat_id, e);
                            }
                            seat.turn = is_turn;
                        }else{
                            tracing::info!("player {} is sitting out,no deal", player.name);
                        }
                    }
                }
            }
        }
    }

    pub fn deal_flop(&mut self) {
        self.mental_poker_game.deal_community_cards_encrypted(3);
    }

    pub fn deal_turn_or_river(&mut self) {
        self.mental_poker_game.deal_community_cards_encrypted(1);
    }

    /// 为解密失败的玩家重新发牌（不验证 plaintext，信任客户端报告）
    /// 返回重新发的牌索引列表
    pub fn redeal_cards_for_player(&mut self, player_pk: &GamePkHex, failed_indices: Vec<usize>) -> Result<Vec<usize>, String> {
        if !self.mental_poker_game.players.contains_key(&**player_pk) {
            return Err("Player not found".to_string());
        }

        let mut redealt = Vec::new();
        for idx in failed_indices {
            match self.mental_poker_game.redeal_to_player_unchecked(&**player_pk, idx) {
                Ok(_) => {
                    tracing::info!("Redealt card at index {} for player {}", idx, player_pk);
                    redealt.push(idx);
                }
                Err(e) => {
                    tracing::warn!("Redeal failed for player {} index {}: {:?}", player_pk, idx, e);
                }
            }
        }

        Ok(redealt)
    }

    /// 启动 redeal reveal 阶段，为重新发的牌收集所有玩家的 reveal token
    /// 不改变 round_state，保持 PreFlop，通过 reveal_token_state 追踪 redeal 进度
    pub fn start_redeal_reveal_phase(&mut self, redealt_player_pk: &GamePkHex, _redealt_indices: Vec<usize>) {
        if self.reveal_token_state.is_active() {
            return;
        }

        let player_pks = self.mental_poker_game.players.keys().cloned().collect::<Vec<String>>();
        let mut player_assignments = HashMap::new();

        // 只需要为重新发牌的玩家收集 reveal token，其他玩家需要为新牌生成 token
        if let Some(player) = self.mental_poker_game.players.get(&**redealt_player_pk) {
            let redealt_cards: Vec<ElGamalCiphertext> = player.hand_encrypted.iter()
                .map(|c| c.encrypted_card.clone())
                .collect();
            for pk in &player_pks {
                if pk == &**redealt_player_pk { continue; }
                player_assignments.insert(GamePkHex::new(pk.clone()), PlayerRevealAssignment {
                    hand_card: redealt_cards.clone(),
                    community_card: vec![],
                });
            }
        }

        self.reveal_token_state = RevealTokenState {
            phase: RevealPhase::RedealReveal,
            current_card_index: 0,
            total_cards_per_player: 2,
            total_community_cards: 0,
            timeout_start: Some(std::time::Instant::now()),
            timeout_seconds: 45,
            completed_players: Vec::new(),
            pending_players: player_pks.iter()
                .filter(|pk| *pk != &**redealt_player_pk)
                .map(|pk| GamePkHex::new(pk.clone()))
                .collect(),
            player_assignments,
        };

        tracing::info!("[REDEAL] Redeal reveal phase started for player {}, {} pending",
            redealt_player_pk, self.reveal_token_state.pending_players.len());
    }

    // 相当于原来的deal_next_street
    pub fn advance_to_next_phase(&mut self) {
        // 对齐 Move advance_round：仅重置下注 + 推进阶段，不计算边池。
        // 边池仅在 showdown 时由 on_reveal_complete(ShowdownReveal) → calculate_side_pots 计算。
        self.reset_bets_and_actions();
        match self.round_state() {
            RoundState::PreFlop => {
                // deal three community card
                self.deal_flop();
                // start reveal community card
                self.transition_to(RoundState::Flop);
                self.start_community_reveal_phase();
            }
            RoundState::Flop => {
                self.deal_turn_or_river();
                self.transition_to(RoundState::Turn);
                self.start_community_reveal_phase();
            }
            RoundState::Turn => {
                self.deal_turn_or_river();
                self.transition_to(RoundState::River);
                self.start_community_reveal_phase();
            }
            RoundState::River => {
                self.transition_to(RoundState::Showdown);
                self.start_showdown_reveal_phase();
            }
            _ => {
                tracing::warn!("[advance_to_next_phase] unexpected round state: {:?}", self.round_state());
            }
        }
        self.update_history();
    }
}
