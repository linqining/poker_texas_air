use super::*;

impl Table {
    pub fn handle_fold(&mut self, pk: &GamePkHex) -> Option<ActionResult> {
        let seat = self.find_player_by_pk(pk)?;
        let seat_id = seat.id;
        let player_name = seat.player.as_ref().map(|p| p.name.clone()).unwrap_or_default();
        if let Some(ref betting) = self.betting_round {
            if betting.validate_fold(&seat).is_err() {
                return None;
            }
        }
        if let Some(seat) = self.local_seats.get_mut(&seat_id) {
            seat.fold();
            // seat.fold() 已设置 has_acted = true，对齐 Move: acted_this_round = true
        }
        if let Some(ref mut betting) = self.betting_round {
            betting.update_after_fold();
        }
        // 对齐 Move do_fold: 重置 betting_started_at = 0，为下一玩家准备
        // （Move 中设为 0，由 tick 重新设置；Rust 直接设为 now_ms 等效）
        self.set_betting_started_at(now_ms());
        Some(ActionResult { seat_id, message: format!("{} folds", player_name) })
    }

    pub fn handle_call(&mut self, pk: &GamePkHex) -> Option<ActionResult> {
        let seat = self.find_player_by_pk(pk)?;
        let seat_id = seat.id;
        let player_name = seat.player.as_ref().map(|p| p.name.clone()).unwrap_or_default();
        let call_amount = self.summary.call_amount?;
        let added_to_pot = if call_amount > seat.stack + seat.bet { seat.stack } else { call_amount - seat.bet };
        if let Some(ref betting) = self.betting_round {
            if betting.validate_call(&seat).is_err() {
                return None;
            }
        }
        if let Some(seat) = self.local_seats.get_mut(&seat_id) {
            seat.call_raise(call_amount);
        }
        if let Some(ref mut betting) = self.betting_round {
            betting.update_after_call();
        }
        self.add_to_pot(added_to_pot);
        // 对齐 handle_fold：重置下注计时，为下一玩家准备
        self.set_betting_started_at(now_ms());
        Some(ActionResult { seat_id, message: format!("{} calls ${:.2}", player_name, added_to_pot) })
    }

    pub fn handle_check(&mut self, pk: &GamePkHex) -> Option<ActionResult> {
        let seat = self.find_player_by_pk(pk)?;
        let seat_id = seat.id;
        let player_name = seat.player.as_ref().map(|p| p.name.clone()).unwrap_or_default();
        if let Some(ref betting) = self.betting_round {
            if betting.validate_check(&seat).is_err() {
                return None;
            }
        }
        if let Some(seat) = self.local_seats.get_mut(&seat_id) {
            seat.check();
        }
        if let Some(ref mut betting) = self.betting_round {
            betting.update_after_check();
        }
        // 对齐 handle_fold：重置下注计时，为下一玩家准备
        self.set_betting_started_at(now_ms());
        Some(ActionResult { seat_id, message: format!("{} checks", player_name) })
    }

    pub fn handle_raise(&mut self, pk: &GamePkHex, amount: u64) -> Option<ActionResult> {
        let seat = self.find_player_by_pk(pk)?;
        let seat_id = seat.id;
        let player_name = seat.player.as_ref().map(|p| p.name.clone()).unwrap_or_default();
        let seat_bet = seat.bet;
        let seat_stack = seat.stack;

        // 对齐 Move process_raise：校验筹码充足，all-in 允许低于 min_raise
        let (raise_amount, is_all_in, qualifies_full_raise) = if let Some(ref betting) = self.betting_round {
            let raise_amount = amount.saturating_sub(betting.current_bet());
            if betting.validate_raise(&seat, raise_amount).is_err() {
                return None;
            }
            let needed = amount.saturating_sub(seat_bet);
            let is_all_in = needed == seat_stack && seat_stack > 0;
            // all-in 时仅当 raise_amount >= min_raise 才算完整加注（重新打开行动权）
            let qualifies = !is_all_in || raise_amount >= betting.min_raise();
            (raise_amount, is_all_in, qualifies)
        } else {
            (0, false, true)
        };

        let added_to_pot = amount.saturating_sub(seat_bet);
        if let Some(seat) = self.local_seats.get_mut(&seat_id) {
            seat.raise(amount);
        }
        if let Some(ref mut betting) = self.betting_round {
            betting.update_after_raise(amount, seat_id, is_all_in);
        }
        self.add_to_pot(added_to_pot);
        self.summary.call_amount = Some(amount);
        // 对齐 Move process_raise：仅完整加注才更新 min_raise（短 all-in 不更新）
        // Move 中 min_raise = raise_amount（纯增量），不是 amount + raise_amount
        if qualifies_full_raise {
            self.set_min_raise(raise_amount);
        }
        // 修复：仅完整加注（重新打开行动权）才重置其他玩家的 has_acted。
        // 短 all-in（raise_amount < min_raise）不重新打开行动权，不应重置，
        // 否则已行动玩家会被迫再次行动（表现为"连续行动两次"）。
        if qualifies_full_raise {
            for seat in self.local_seats.values_mut() {
                if seat.id != seat_id && !seat.folded && !seat.sitting_out && seat.stack > 0 {
                    seat.has_acted = false;
                }
            }
        }
        // 对齐 handle_fold：重置下注计时，为下一玩家准备
        self.set_betting_started_at(now_ms());
        Some(ActionResult { seat_id, message: format!("{} raises to ${:.2}", player_name, amount) })
    }

    /// 对齐 Move：Move 中没有独立的 all_in 入口函数，all-in 在 call/raise 内部自然处理。
    /// 此处根据玩家 total_bet (bet+stack) 与 call_amount 的比较，路由到 handle_raise 或 handle_call。
    pub fn handle_allin(&mut self, pk: &GamePkHex) -> Option<ActionResult> {
        let seat = self.find_player_by_pk(pk)?;
        let stack = seat.stack;
        let bet = seat.bet;
        let call_amount = self.summary.call_amount.unwrap_or(0);

        if stack == 0 {
            return None; // nothing to all-in
        }

        let total_bet = bet + stack;
        if total_bet > call_amount {
            // All-in raise：对齐 Move raise，process_raise 会处理 all-in 逻辑
            self.handle_raise(pk, total_bet)
        } else {
            // All-in call：对齐 Move call，process_call 会 cap at stack
            self.handle_call(pk)
        }
    }

    pub fn add_to_pot(&mut self, amount: u64) {
        // New bets always go to self.pot, never to existing side_pots (B4 fix).
        // side_pots are only populated by calculate_side_pots() at end of round.
        self.set_pot(self.pot() + amount);
    }

    pub fn is_betting_round_complete(&self) -> bool {
        // 对齐 Move is_betting_complete：过滤 occupied && !folded && !all_in && !is_waiting
        // Rust 中 stack == 0 等价于 Move 的 all_in
        let active: Vec<&Seat> = self.local_seats.values()
            .filter(|s| !s.folded && !s.sitting_out && !s.is_waiting && s.stack > 0)
            .collect();
        if active.is_empty() {
            return true;
        }
        // Every active player must have acted at least once this round.
        // This prevents the BB's option from being skipped and ensures
        // that folds don't cause premature round completion.
        if active.iter().any(|s| !s.has_acted) {
            return false;
        }
        // All active players must have matched the current bet (or are all-in).
        if let Some(ref betting) = self.betting_round {
            let current_bet = betting.current_bet();
            for seat in &active {
                if seat.bet < current_bet {
                    return false;
                }
            }
        }
        true
    }

    pub fn players_all_in_this_turn(&self) -> Vec<&Seat> {
        self.local_seats.values()
            .filter(|s| !s.folded && s.bet > 0 && s.stack == 0)
            .collect()
    }

    pub fn check_betting_timeout(&mut self, timeout_secs: u64) -> Option<ActionResult> {
        // 对齐 Move：使用 summary.state.betting_started_at (u64 ms) 替代 Option<Instant>
        let timeout_start = self.betting_started_at();
        if timeout_start == 0 {
            return None;
        }
        let elapsed_ms = now_ms().saturating_sub(timeout_start);
        if elapsed_ms / 1000 < timeout_secs {
            return None;
        }
        let turn_seat_id = self.turn()?;
        // Extract only the needed info to avoid cloning the entire Seat
        let (folded, sitting_out, stack, pk_hex) = {
            let seat = self.local_seats.get(&turn_seat_id)?;
            (
                seat.folded,
                seat.sitting_out,
                seat.stack,
                seat.player.as_ref().map(|p| p.pk_hex.clone()),
            )
        };
        if folded || sitting_out || stack == 0 {
            // Turn is on a player who can't act — skip them and advance turn.
            // Return a special marker so the caller knows to re-advance.
            self.set_turn(self.next_unfolded_player(turn_seat_id, 1));
            self.set_betting_started_at(now_ms());
            let current_turn = self.turn();
            for i in 1..=self.max_players() {
                if let Some(seat) = self.local_seats.get_mut(&i) {
                    seat.turn = current_turn == Some(i);
                }
            }
            return None;
        }
        // 对齐 Move on_betting_timeout：超时一律 fold（Move 中不区分 needs_to_call）
        let pk = pk_hex?;
        self.handle_fold(&pk)
    }
}
