use crate::pokergame::seat::Seat;

#[derive(Debug, Clone)]
pub struct BettingRound {
    current_bet: u64,
    min_raise: u64,
    big_blind: u64,
    last_raiser_seat_id: Option<u32>,
    actions_taken: usize,
}

impl BettingRound {
    pub fn new(big_blind: u64) -> Self {
        Self {
            current_bet: 0,
            min_raise: big_blind,
            big_blind,
            last_raiser_seat_id: None,
            actions_taken: 0,
        }
    }

    pub fn new_preflop(big_blind: u64) -> Self {
        Self {
            current_bet: big_blind,
            min_raise: big_blind,
            big_blind,
            last_raiser_seat_id: None,
            actions_taken: 0,
        }
    }

    pub fn current_bet(&self) -> u64 {
        self.current_bet
    }

    pub fn min_raise(&self) -> u64 {
        self.min_raise
    }

    pub fn get_actions_taken(&self) -> usize {
        self.actions_taken
    }

    pub fn validate_fold(&self, _seat: &Seat) -> Result<(), String> {
        Ok(())
    }

    pub fn validate_check(&self, seat: &Seat) -> Result<(), String> {
        let chips_to_call = self.current_bet.saturating_sub(seat.bet);
        if chips_to_call > 0 {
            return Err(format!("cannot check: must call {} or fold", chips_to_call));
        }
        Ok(())
    }

    pub fn validate_call(&self, seat: &Seat) -> Result<(), String> {
        let chips_to_call = self.current_bet.saturating_sub(seat.bet);
        if chips_to_call == 0 {
            return Err("nothing to call - use check instead".to_string());
        }
        Ok(())
    }

    /// 对齐 Move process_raise：all-in（needed == stack）允许低于 min_raise（短 all-in），
    /// 仅非 all-in 时强制 min_raise 检查。
    pub fn validate_raise(&self, seat: &Seat, raise_amount: u64) -> Result<(), String> {
        let chips_to_call = self.current_bet.saturating_sub(seat.bet);
        let needed = chips_to_call + raise_amount;
        if needed > seat.stack {
            return Err(format!(
                "not enough chips: need {}, have {}",
                needed,
                seat.stack
            ));
        }
        let is_all_in = needed == seat.stack && seat.stack > 0;
        if !is_all_in && raise_amount < self.min_raise {
            return Err(format!(
                "minimum raise is {}, got {}",
                self.min_raise, raise_amount
            ));
        }
        Ok(())
    }



    /// G7 修复：使用 has_acted 而非 actions_taken 判断是否所有玩家都已行动。
    /// actions_taken 仅是计数器，无法反映每个玩家是否都行动过（如玩家加入/离开、
    /// 加注后重置等场景下计数会失真）。has_acted 在每次行动后置 true，在加注后
    /// 由调用方重置其他玩家，能准确反映"本轮是否所有人都行动过"。
    pub fn is_complete(&self, seats: &[&Seat]) -> bool {
        let active_players: Vec<&&Seat> = seats
            .iter()
            .filter(|s| !s.folded && !s.sitting_out && s.stack > 0)
            .collect();

        if active_players.is_empty() {
            return true;
        }
        // 所有活跃玩家都必须已行动过
        if !active_players.iter().all(|s| s.has_acted) {
            return false;
        }
        // 且所有活跃玩家的下注都等于当前下注（或已 all-in）
        active_players.iter().all(|s| s.bet == self.current_bet || s.stack == 0)
    }

    /// 对齐 Move process_raise：all-in 时仅当 raise_amount >= min_raise 才更新
    /// min_raise 和 last_raiser_seat_id（重新打开行动权）；短 all-in 不更新。
    /// 非 all-in 时始终更新（调用方已通过 validate_raise 保证 raise_amount >= min_raise）。
    pub fn update_after_raise(&mut self, total_bet: u64, seat_id: u32, is_all_in: bool) {
        let raise_amount = total_bet.saturating_sub(self.current_bet);
        if is_all_in {
            if raise_amount >= self.min_raise {
                self.min_raise = raise_amount;
                self.last_raiser_seat_id = Some(seat_id);
            }
            // 短 all-in（raise_amount < min_raise）：不更新 min_raise 和 last_raiser
        } else {
            self.min_raise = raise_amount;
            self.last_raiser_seat_id = Some(seat_id);
        }
        self.current_bet = total_bet;
        self.actions_taken += 1;
    }

    pub fn update_after_call(&mut self) {
        self.actions_taken += 1;
    }

    pub fn update_after_check(&mut self) {
        self.actions_taken += 1;
    }

    pub fn update_after_fold(&mut self) {
        self.actions_taken += 1;
    }

    pub fn reset(&mut self) {
        self.current_bet = 0;
        self.min_raise = self.big_blind;
        self.last_raiser_seat_id = None;
        self.actions_taken = 0;
    }

    pub fn available_actions(&self, seat: &Seat) -> Vec<String> {
        if seat.folded || seat.sitting_out || seat.stack == 0 {
            return Vec::new();
        }
        let chips_to_call = self.current_bet.saturating_sub(seat.bet);
        let mut actions = Vec::new();
        actions.push("fold".to_string());
        if chips_to_call == 0 {
            actions.push("check".to_string());
        } else {
            actions.push("call".to_string());
        }
        // 对齐 Move can_raise：stack > to_call 即可 raise（含短 all-in）
        if seat.stack > chips_to_call {
            actions.push("raise".to_string());
        }
        actions
    }
}
