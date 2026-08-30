use super::*;
use crate::pokergame::hand_rank::{vin_card_to_eval_card, EvalCard, HandRank};
use crate::pokergame::evaluator::best_hand;

impl Table {
    /// 对齐 Move side_pot::calculate_side_pots：使用 total_bet（累积下注）计算边池。
    /// 仅在 showdown 时调用一次（由 on_reveal_complete(ShowdownReveal) 触发）。
    /// self.pot 保持不变（已包含所有下注），self.side_pots 填充边池列表，
    /// main_pot() = pot - sum(side_pots) 即主池金额。
    pub fn calculate_side_pots(&mut self) {
        // 清空旧 side_pots（对齐 Move: 每次重新计算）
        self.summary.side_pots.clear();

        // 收集所有有下注的玩家 (seat_id, total_bet, folded, all_in)
        // all_in = stack == 0 && total_bet > 0（对齐 Move: stack 耗尽即 all-in）
        let mut player_bets: Vec<(u32, u64, bool, bool)> = self.seats().values()
            .filter(|s| s.total_bet > 0)
            .map(|s| (s.id, s.total_bet, s.folded, s.stack == 0))
            .collect();

        if player_bets.is_empty() {
            return;
        }

        // 收集所有 all-in 的下注额（去重），对齐 Move collect_all_in_bets
        let mut all_in_bets: Vec<u64> = player_bets.iter()
            .filter(|(_, _, _, all_in)| *all_in)
            .map(|(_, bet, _, _)| *bet)
            .collect();
        all_in_bets.sort_unstable();
        all_in_bets.dedup();

        // 没有 all-in 玩家 → 无边池，全部归主池
        if all_in_bets.is_empty() {
            return;
        }

        // 按层级计算边池，对齐 Move calculate_side_pots
        let n = player_bets.len();
        let mut prev_level: u64 = 0;
        let mut side_pots: Vec<SidePot> = Vec::new();

        for &level in &all_in_bets {
            if level <= prev_level { continue; }

            let mut pot_amount: u64 = 0;
            let mut eligible: Vec<u32> = Vec::new();
            for j in 0..n {
                let (seat_id, bet, folded, _) = player_bets[j];
                if bet > prev_level {
                    let contribution = if bet < level { bet - prev_level } else { level - prev_level };
                    pot_amount += contribution;
                    if !folded {
                        eligible.push(seat_id);
                    }
                }
            }
            if pot_amount > 0 {
                side_pots.push(SidePot { amount: pot_amount, players: eligible });
            }
            prev_level = level;
        }

        // 最外层（超出最大 all-in 的部分），对齐 Move
        let mut outer_amount: u64 = 0;
        let mut outer_eligible: Vec<u32> = Vec::new();
        for j in 0..n {
            let (seat_id, bet, folded, _) = player_bets[j];
            if bet > prev_level {
                outer_amount += bet - prev_level;
                if !folded {
                    outer_eligible.push(seat_id);
                }
            }
        }
        if outer_amount > 0 {
            side_pots.push(SidePot { amount: outer_amount, players: outer_eligible });
        }

        // M-A3 修复：最后一个边池 eligible 为空时，合并到上一个有 eligible 的层级
        if !side_pots.is_empty() {
            let last_idx = side_pots.len() - 1;
            if side_pots[last_idx].players.is_empty() && side_pots[last_idx].amount > 0 {
                let merge_amount = side_pots[last_idx].amount;
                side_pots.pop();
                if !side_pots.is_empty() {
                    // 找到最后一个有 eligible 的层级
                    let mut merge_idx = 0;
                    for k in (0..side_pots.len()).rev() {
                        if !side_pots[k].players.is_empty() {
                            merge_idx = k;
                            break;
                        }
                    }
                    side_pots[merge_idx].amount += merge_amount;
                } else {
                    // 所有层级 eligible 都为空，放回（由调用方处理）
                    side_pots.push(SidePot { amount: merge_amount, players: Vec::new() });
                }
            }
        }

        // 第一个边池 = 主池（对齐 Move: first.amount = main_pot），其余 = 边池。
        // Rust 中 self.pot 已包含所有下注，main_pot() = pot - sum(side_pots) 即主池。
        // 所以第一个边池不放入 self.side_pots，仅保留其余。
        if side_pots.len() > 1 {
            self.summary.side_pots = side_pots[1..].to_vec();
        }
    }



    pub fn determine_side_pot_winners(&mut self) {
        if self.summary.side_pots.is_empty() { return; }
        // Collect (amount, eligible_ids) pairs first to avoid cloning side_pots
        let pot_info: Vec<(u64, Vec<u32>)> = self.summary.side_pots.iter()
            .map(|sp| {
                let eligible: Vec<u32> = sp.players.iter()
                    .filter(|id| self.seats().get(id).map_or(false, |s| !s.folded))
                    .copied()
                    .collect();
                (sp.amount, eligible)
            })
            .collect();
        for (amount, eligible_ids) in pot_info {
            if eligible_ids.is_empty() { continue; }
            self.determine_winner_by_ids(amount, &eligible_ids);
        }
    }

    pub fn determine_main_pot_winner(&mut self) {
        let unfolded_ids: Vec<u32> = self.seats().values()
            .filter(|s| !s.folded)
            .map(|s| s.id)
            .collect();
        // 对齐 Move settle_hand: 使用 main_pot（= pot - sum(side_pots)），而非整个 pot
        self.determine_winner_by_ids(self.main_pot(), &unfolded_ids);
        self.summary.went_to_showdown = true;
        // 注意：round_state 已在 advance_to_next_phase(River) 中设为 Showdown，无需再 transition_to
        self.set_showdown_at(now_ms());
    }

    pub fn finish_showdown(&mut self) {
        self.clear_seat_turns();
        self.summary.hand_over = true;
        self.transition_to(RoundState::Waiting);
        self.set_hand_complete_at(now_ms());
        self.sit_out_felted_players();

        // Starknet 结算：镜像手牌 prove → outer aggregate → register/settle 上链
        // （dev 模式只生成 calldata 并记日志）。失败不影响链下记账。
        crate::starknet::hooks::on_hand_complete(self.summary.id);
    }

    /// 镜像 Move settle_hand：Showdown 展示超时后分配底池并重置牌桌。
    /// 先 calculate_side_pots(total_bet) 再分配 side pot 和 main pot 给赢家，最后 finish_showdown。
    pub fn settle_hand(&mut self) {
        self.calculate_side_pots();
        self.determine_side_pot_winners();
        self.determine_main_pot_winner();
        self.finish_showdown();
    }

    pub fn evaluate_player_hands(&self) -> Vec<(u32, HandRank)> {
        let mut results = Vec::new();
        let (player_revealed_map, comm_revealed_cards) = self.mental_poker_game.list_revealed_cards();
        if comm_revealed_cards.len() < 5 { return results; }
        tracing::info!("comm_revealed_cards: {:?}", comm_revealed_cards);
        for seat in self.seats().values() {
            let seat_player = match seat.player.as_ref() {
                Some(p) => p,
                None => continue,
            };
            let revealed_cards = match player_revealed_map.get(&seat_player.pk_hex.0){
                Some(rc) => rc,
                None => continue,
            };

            if !seat.folded && !seat.sitting_out && revealed_cards.len() >= 2 {
                let mut eval_cards: Vec<EvalCard> = Vec::new();
                for card in revealed_cards {
                    if let Some(ec) = vin_card_to_eval_card(card.suit.short_name_lower(), card.rank.symbol()) {
                        eval_cards.push(ec);
                    }
                }
                for card in &comm_revealed_cards {
                    if let Some(ec) = vin_card_to_eval_card(card.suit.short_name_lower(), card.rank.symbol()) {
                        eval_cards.push(ec);
                    }
                }
                tracing::info!("evaluate_player_hands eval_cards: {:?}", eval_cards);
                if eval_cards.len() >= 5 {
                    if let Some((hand_rank, _)) = best_hand(&eval_cards) {
                        results.push((seat.id, hand_rank));
                    }
                }
            }
        }
        results.sort_by(|a, b| b.1.cmp(&a.1));
        results
    }

    pub fn determine_winner_by_ids(&mut self, amount: u64, eligible_ids: &[u32]) {
        if eligible_ids.is_empty() { return; }
        if eligible_ids.len() == 1 {
            let winner_id = eligible_ids[0];
            let win_amount = amount;
            if let Some(seat) = self.local_seats.get_mut(&winner_id) {
                let player_name = seat.player.as_ref().map(|p| p.name.clone()).unwrap_or_default();
                seat.win_hand(win_amount);
                if win_amount > 0 {
                    self.summary.win_messages.push(format!("{} wins ${:.2}", player_name, win_amount));
                }
            }
            self.update_history();
            return;
        }
        let hand_results = self.evaluate_player_hands();
        let eligible_results: Vec<(u32, HandRank)> = hand_results
            .into_iter()
            .filter(|(id, _)| eligible_ids.contains(id))
            .collect();
        if eligible_results.is_empty() {
            // F5 fix: No reveal cards available — split evenly among all eligible
            // instead of silently dropping the pot.
            let win_amount = amount / eligible_ids.len() as u64;
            let remainder = amount % eligible_ids.len() as u64;
            for (idx, winner_id) in eligible_ids.iter().enumerate() {
                let extra = if idx < remainder as usize { 1 } else { 0 };
                if let Some(seat) = self.local_seats.get_mut(winner_id) {
                    let player_name = seat.player.as_ref().map(|p| p.name.clone()).unwrap_or_default();
                    seat.win_hand(win_amount + extra);
                    if win_amount + extra > 0 {
                        self.summary.win_messages.push(format!("{} wins ${:.2}", player_name, win_amount + extra));
                    }
                }
            }
            self.update_history();
            return;
        }
        let best_rank = &eligible_results[0].1;
        let winners: Vec<u32> = eligible_results
            .iter()
            .filter(|(_, rank)| rank == best_rank)
            .map(|(id, _)| *id)
            .collect();
        let win_amount = amount / winners.len() as u64;
        let remainder = amount % winners.len() as u64;
        for (idx, winner_id) in winners.iter().enumerate() {
            let extra = if idx < remainder as usize { 1 } else { 0 };
            if let Some(seat) = self.local_seats.get_mut(winner_id) {
                let player_name = seat.player.as_ref().map(|p| p.name.clone()).unwrap_or_default();
                seat.win_hand(win_amount + extra);
                if win_amount + extra > 0 {
                    self.summary.win_messages.push(format!("{} wins ${:.2} with {}", player_name, win_amount + extra, best_rank.name()));
                }
            }
        }
        self.update_history();
    }
}
