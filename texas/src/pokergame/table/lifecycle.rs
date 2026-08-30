use super::*;

impl Table {
    pub fn end_hand(&mut self) {
        self.clear_seat_turns();
        self.summary.hand_over = true;
        self.clear_seat_hands();
        self.transition_to(RoundState::Waiting);
        self.set_hand_complete_at(now_ms());
        self.sit_out_felted_players();
    }

    pub fn sit_out_felted_players(&mut self) {
        for seat in self.local_seats.values_mut() {
            if seat.stack == 0 {
                seat.sitting_out = true;
            }
        }
    }

    pub fn end_without_showdown(&mut self) {
        // 对齐 Move end_without_showdown：将剩余唯一未弃牌玩家判为赢家，获得全部底池。
        // Rust 中下注已通过 add_to_pot 累积到 self.pot，无需再调用 collect_bets_to_pot（否则双重计算）。
        let unfolded = self.unfolded_players();
        if let Some(winner) = unfolded.first() {
            // Total win includes main pot + all side pots
            let total_win = self.pot() + self.summary.side_pots.iter().map(|sp| sp.amount).sum::<u64>();
            let winner_id = winner.id;
            let player_name = winner.player.as_ref().map(|p| p.name.clone()).unwrap_or_default();
            if let Some(seat) = self.local_seats.get_mut(&winner_id) {
                seat.win_hand(total_win);
            }
            self.summary.win_messages.push(format!("{} wins ${:.2}", player_name, total_win));
        }
        self.end_hand();
    }

    pub fn reset_empty_table(&mut self) {
        self.set_button(None);
        self.set_turn(None);
        self.summary.hand_over = true;
        self.summary.went_to_showdown = false;
        self.mental_poker_game.reset();
        self.reset_board_and_pot();
        self.clear_win_messages();
        self.clear_seats();
        self.pk_to_seat.clear();
    }

    pub fn reset_board_and_pot(&mut self) {
        self.set_pot(0);
        self.summary.side_pots = vec![];
    }

    pub fn clear_seats(&mut self) {
        self.local_seats.clear();
    }

    pub fn clear_seat_hands(&mut self) {
        for seat in self.local_seats.values_mut() {
            seat.hand.clear();
        }
    }

    pub fn clear_seat_turns(&mut self) {
        for seat in self.local_seats.values_mut() {
            seat.turn = false;
        }
    }

    pub fn clear_win_messages(&mut self) {
        self.summary.win_messages = vec![];
    }

    pub fn reset_bets_and_actions(&mut self) {
        for seat in self.local_seats.values_mut() {
            seat.bet = 0;
            seat.checked = false;
            seat.last_action = None;
            seat.has_acted = false;
        }
        self.summary.call_amount = None;
        self.set_min_raise(self.summary.min_bet * 2);
        if let Some(ref mut betting) = self.betting_round {
            betting.reset();
        }
    }

    pub fn reset_for_next_hand(&mut self) {
        // 对齐 Move reset_for_next_hand：
        // 1. 重置所有 seat 的手牌状态
        for seat in self.local_seats.values_mut() {
            seat.hand.clear();
            seat.bet = 0;
            seat.total_bet = 0;
            seat.folded = seat.sitting_out; // sitting_out 玩家保持 folded
            seat.has_acted = false;
            seat.left_during_hand = false;
            seat.refunded = false;
        }

        // 2. 清理破产玩家（stack == 0）— 对齐 Move 中 reset_seat + emit PlayerLeft
        let broke_seats: Vec<u32> = self.seats().iter()
            .filter(|(_, s)| s.stack == 0)
            .map(|(id, _)| *id)
            .collect();
        for seat_id in &broke_seats {
            if let Some(seat) = self.seats().get(seat_id) {
                if let Some(player) = &seat.player {
                    tracing::info!("[reset_for_next_hand] Player {} left (broke)", player.pk_hex);
                }
            }
            self.local_seats.remove(seat_id);
        }

        // 3. 清理 pk_to_seat 中已移除的玩家
        let active_seat_pks: std::collections::HashSet<GamePkHex> = self.seats().values()
            .filter_map(|s| s.player.as_ref().map(|p| p.pk_hex.clone()))
            .collect();
        self.pk_to_seat.retain(|pk, _| active_seat_pks.contains(pk));
        self.local_players.retain(|pk, _| active_seat_pks.contains(pk));

        // 4. 重置牌桌状态
        self.transition_to(RoundState::Waiting);
        self.set_pot(0);
        self.summary.side_pots = vec![];
        self.summary.call_amount = None;
        self.betting_round = None;
        self.set_turn(None);
        self.summary.hand_over = true;

        // 5. 重置时间戳
        self.set_hand_complete_at(0);
        self.set_betting_started_at(0);
        self.set_ready_at(0);
        self.set_showdown_at(0);

        // 6. 清理消息和状态机
        self.clear_win_messages();
        self.shuffle_state.reset();
        self.reveal_token_state.reset();
        self.reconstruct_state.reset();
        self.mental_poker_game.reset();

        // 7. summary.crypto / summary.state 缓存不再清理
        //    accessor 已改为从 mental_poker_game 读取（单一真理之源），
        //    清理 summary 缓存无意义且有害（sync_table_state 会立即从链上覆写）。
    }

    /// 镜像 Move refund_all_bets：退还所有玩家本手牌的下注。
    /// - 在座玩家（未 left_during_hand）：total_bet 退到 stack
    /// - 已离开玩家（left_during_hand）：total_bet 退款（记日志，实际退款由链上事件处理）
    /// 清空所有 bet/total_bet，清空底池。
    pub fn refund_all_bets(&mut self) {
        for seat in self.local_seats.values_mut() {
            if !seat.refunded && seat.total_bet > 0 {
                if !seat.left_during_hand {
                    // 在座玩家：退到 stack
                    seat.stack += seat.total_bet;
                } else {
                    // 已离开玩家：记日志（Move 中发 PlayerRefund 事件，链下处理实际退款）
                    if let Some(player) = &seat.player {
                        tracing::info!("[refund_all_bets] Refund {} chips to left player {}",
                            seat.total_bet, player.pk_hex);
                    }
                }
                seat.refunded = true;
            }
            seat.bet = 0;
            seat.total_bet = 0;
        }
        self.set_pot(0);
        self.summary.side_pots.clear();
    }
}
