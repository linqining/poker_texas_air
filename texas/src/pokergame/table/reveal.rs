use super::*;

impl Table {
    pub fn start_preflop_reveal_phase(&mut self) {
        if self.reveal_token_state.is_active(){
            return;
        }
        let player_pks: Vec<GamePkHex> = self.mental_poker_game.players.keys()
            .map(|k| GamePkHex::new(k.clone()))
            .collect();
        let mut player_assignments = HashMap::new();
        for pk in &player_pks {
            let mut hand_cards = Vec::new();
            for (other_pk, state) in &self.mental_poker_game.players {
                if pk.0 == *other_pk { continue; }
                for card in &state.hand_encrypted {
                    hand_cards.push(card.encrypted_card.clone());
                }
            }
            player_assignments.insert(pk.clone(), PlayerRevealAssignment {
                hand_card: hand_cards,
                community_card: vec![],
            });
        }

        self.reveal_token_state = RevealTokenState {
            phase: RevealPhase::HandReveal,
            current_card_index: 0,
            total_cards_per_player: 2,
            total_community_cards: 5,
            timeout_start: Some(std::time::Instant::now()),
            timeout_seconds: 45,
            completed_players: Vec::new(),
            pending_players: player_pks.clone(),
            player_assignments,
        };
        tracing::info!("[REVEAL-TOKEN] Hand reveal phase started for {} players",
            player_pks.len());
    }

    pub fn start_community_reveal_phase(&mut self) {
        if self.reveal_token_state.is_active() {
            tracing::error!("[start_community_reveal_phase] Reveal phase already active");
            return;
        }

        let player_pks: Vec<GamePkHex> = self.mental_poker_game.players.keys()
            .map(|k| GamePkHex::new(k.clone()))
            .collect();

        let unreveal_cards = self.mental_poker_game.list_unreveal_community_cards_encrypted();
        let community_cards: Vec<ElGamalCiphertext> = unreveal_cards.iter().map(|c| c.encrypted_card.clone()).collect();
        let mut player_assignments = HashMap::new();
        for pk in &player_pks {
            player_assignments.insert(pk.clone(), PlayerRevealAssignment {
                hand_card: vec![],
                community_card: community_cards.clone(),
            });
        }

        self.reveal_token_state = RevealTokenState {
            phase: RevealPhase::CommunityReveal,
            current_card_index: 0,
            // G6 修复：community reveal 阶段不揭示玩家手牌，total_cards_per_player 应为 0
            total_cards_per_player: 0,
            total_community_cards: self.mental_poker_game.community_cards_encrypted.len(),
            timeout_start: Some(std::time::Instant::now()),
            timeout_seconds: 45,
            completed_players: Vec::new(),
            pending_players: player_pks.clone(),
            player_assignments,
        };
        tracing::info!("[REVEAL-TOKEN] Community reveal phase started for {} players ({} community cards)",
            player_pks.len(), self.mental_poker_game.community_cards_encrypted.len());
    }

    pub fn start_showdown_reveal_phase(&mut self) {
        if self.reveal_token_state.is_active() {
            tracing::error!("[start_hand_card_reveal_phase] Reveal phase already active");
            return;
        }
        // F4 fix: only include players who are actually in the mental poker game,
        // so pending_players stays consistent with player_assignments.
        let player_pks: Vec<GamePkHex> = self.seats().values()
            .filter(|s| !s.folded )
            .filter_map(|s| s.player.as_ref().map(|p| p.pk_hex.clone()))
            .filter(|pk| self.mental_poker_game.players.contains_key(pk.as_str()))
            .collect();
        let mut player_assignments = HashMap::new();
        for seat in self.seats().values() {
            if seat.folded { continue; }
            if let Some(player) = &seat.player {
                if let Some(men_player) = self.mental_poker_game.players.get(player.pk_hex.as_str()) {
                    let hand_cards = men_player.hand_encrypted.iter().map(|f| f.encrypted_card.clone()).collect();
                    player_assignments.insert(player.pk_hex.clone(), PlayerRevealAssignment {
                        hand_card: hand_cards,
                        community_card: vec![],
                    });
                }
            }
        }
        self.reveal_token_state = RevealTokenState {
            phase: RevealPhase::ShowdownReveal,
            current_card_index: 0,
            total_cards_per_player: 2,
            total_community_cards: self.mental_poker_game.community_cards_encrypted.len(),
            timeout_start: Some(std::time::Instant::now()),
            timeout_seconds: 45,
            completed_players: Vec::new(),
            pending_players: player_pks,
            player_assignments,
        };
        tracing::info!("[REVEAL-TOKEN] Hand card reveal (showdown) phase started");
    }

    pub fn mark_player_reveal_complete(&mut self, player_pk: &GamePkHex) -> bool {
        if !self.reveal_token_state.is_active() { return false; }
        if !self.reveal_token_state.pending_players.iter().any(|p| p == player_pk) { return false; }

        self.reveal_token_state.completed_players.push(player_pk.clone());
        self.reveal_token_state.pending_players.retain(|p| p != player_pk);

        tracing::info!("[REVEAL-TOKEN] Player {} completed {} phase, remaining: {}",
            player_pk, self.reveal_token_state.phase,
            self.reveal_token_state.pending_players.len());

        if self.reveal_token_state.pending_players.is_empty() {
            self.on_reveal_complete();
            return true;
        }
        false
    }

    /// 镜像 Move on_reveal_complete：所有 pending 玩家完成后的状态转换
    pub fn on_reveal_complete(&mut self) {
        if !self.reveal_token_state.is_active() {
            return;
        }
        if !self.reveal_token_state.pending_players.is_empty() {
            return;
        }

        let phase = self.reveal_token_state.phase;
        self.reveal_token_state.reset();

        match phase {
            RevealPhase::None => {
                // 不应到达（is_active 已检查），防御性处理
                tracing::warn!("[on_reveal_complete] reached with None phase");
            }
            RevealPhase::HandReveal => {
                // 翻牌前手牌揭牌完成 → 进入 PreFlop 下注轮
                // 对齐 Move check_reveal_phase_complete: post_blinds THEN start_betting_round(true)
                // set_blinds 已包含首行动作设置（对齐 Move post_blinds），无需再调用 init_turn
                self.set_blinds();
                self.start_betting_round(true);
            }
            RevealPhase::CommunityReveal => {
                // 公共牌揭牌完成 → 进入对应下注轮
                self.start_betting_round(false);
            }
            RevealPhase::ShowdownReveal => {
                // 摊牌揭牌完成 → 判定赢家
                // 对齐 Move settle_hand: 先 calculate_side_pots(total_bet) 再分配
                self.calculate_side_pots();
                self.determine_side_pot_winners();
                self.determine_main_pot_winner();
            }
            RevealPhase::RedealReveal => {
                // 重新发牌揭牌完成，保持当前 round_state 不变
                tracing::info!("[on_reveal_complete] Redeal reveal complete, round_state stays {:?}", self.round_state());
            }
        }

        // 仅在下注轮开始时同步 seat.turn（ShowdownReveal 后无行动者，不需要同步）
        if phase != RevealPhase::ShowdownReveal {
            let current_turn = self.turn();
            for i in 1..=self.max_players() {
                if let Some(seat) = self.local_seats.get_mut(&i) {
                    seat.turn = current_turn == Some(i);
                }
            }
        }
        tracing::info!("[REVEAL-TOKEN] All reveal phases complete, switch round state to {:?}", self.round_state());
        // 通知前端 reveal 完成
        self.emit_event(crate::pokergame::table::events::TableEvent::TableUpdated {
            message: None,
        });
    }

    /// 镜像 Move on_reveal_timeout：处理揭牌超时
    pub fn on_reveal_timeout(&mut self) {
        if !self.reveal_token_state.is_active() {
            return;
        }
        let timed_out_pks = self.reveal_token_state.pending_players.clone();
        tracing::warn!("[REVEAL-TOKEN] Timeout for players: {:?}", timed_out_pks);

        let is_preflop = self.round_state() == RoundState::PreFlop;

        // 对齐 Move clear_reveal_timeout_player：踢出所有超时玩家
        // kick_player_internal 会处理退款/pot/状态清理，可能触发 reset_for_next_hand
        for pk in &timed_out_pks {
            self.remove_player_by_pk(pk);
        }

        // kick 可能已触发 reset_for_next_hand（活跃玩家不足）
        if self.round_state() == RoundState::Waiting {
            return;
        }

        let active_count = self.active_players().len();

        if is_preflop {
            // PreFlop reveal 超时：重开整手
            if active_count == 0 {
                self.refund_all_bets();
                self.reset_for_next_hand();
                return;
            }
            if active_count == 1 {
                self.end_without_showdown();
                return;
            }
            // 退还未被踢玩家的筹码，重开整手
            self.refund_all_bets();
            self.reset_for_next_hand();
        } else {
            // 其他阶段超时：启动 reconstruct
            if active_count == 0 {
                self.refund_all_bets();
                self.reset_for_next_hand();
                return;
            }
            if active_count == 1 {
                self.end_without_showdown();
                return;
            }
            // 启动 reconstruct
            let _ = self.start_reconstruct();
        }
    }

    /// 镜像 Move start_betting_round：启动下注轮。
    /// 对齐 Move: 创建 BettingRound + 重置 acted_this_round + 设置首行动作。
    pub fn start_betting_round(&mut self, is_preflop: bool) {
        // C5 修复扩展到 preflop：当所有活跃玩家已 all-in 时，跳过下注轮。
        // preflop 时盲注已下，若全员 all-in 则无人可行动，直接推进。
        // postflop 同理：find_next_active_seat 在全员 all-in 时会返回 None，需先检查。
        if !self.has_actionable_player() {
            self.betting_round = None;
            self.advance_to_next_phase();
            return;
        }

        if is_preflop {
            // PreFlop: 盲注已由调用方发布（set_blinds），bet 保留盲注金额。
            // 仅重置 has_acted（对齐 Move: seat.acted_this_round = false）
            for seat in self.local_seats.values_mut() {
                seat.has_acted = false;
            }
            self.betting_round = Some(crate::pokergame::betting::BettingRound::new_preflop(self.summary.min_bet * 2));
            // preflop 的 current_turn 已由 set_blinds 设置，无需再设
        } else {
            // PostFlop: 重置下注 + 创建下注轮（对齐 Move: seat.bet = 0, acted_this_round = false）
            self.reset_bets_and_actions();
            self.betting_round = Some(crate::pokergame::betting::BettingRound::new(self.summary.min_bet * 2));

            // 对齐 Move start_betting_round: 设置 postflop 首行动作
            let first = self.next_unfolded_player(self.button().unwrap_or(1), 1);
            self.set_turn(first);
        }
        self.set_betting_started_at(now_ms());
    }

    /// 对齐 Move has_actionable_player：是否存在可行动的玩家（非 fold、非 all-in、非 waiting）
    pub fn has_actionable_player(&self) -> bool {
        self.seats().values().any(|s| {
            !s.folded && !s.sitting_out && !s.is_waiting && s.stack > 0
        })
    }

    pub fn check_reveal_timeout(&mut self) -> Option<Vec<GamePkHex>> {
        if !self.reveal_token_state.is_active() {
            return None;
        }
        let timeout_start = match self.reveal_token_state.timeout_start {
            Some(t) => t,
            None => return None,
        };
        if timeout_start.elapsed().as_secs() >= self.reveal_token_state.timeout_seconds {
            if self.reveal_token_state.pending_players.is_empty() {
                return None;
            }
            let time_out_pks = self.reveal_token_state.pending_players.clone();
            self.reveal_token_state.reset();
            tracing::info!("[REVEAL-TOKEN] timeout {:?} players, clear reveal state", time_out_pks.len());
            return Some(time_out_pks);
        }
        None
    }

    pub fn submit_player_reveal_tokens(
        &mut self,
        player_pk: &GamePkHex,
        tokens: Vec<poker_protocol::z_poker::protocol::RevealToken>,
    ) -> Result<(), String> {
        if !self.reveal_token_state.is_active() {
            return Err("Reveal token phase not active".to_string());
        }
        if !self.reveal_token_state.pending_players.iter().any(|p| p == player_pk) {
            return Err("Player already submitted or not pending".to_string());
        }

        let assign = match self.reveal_token_state.player_assignments.get(player_pk) {
            Some(a) => a,
            None => return Err(format!("No assignment found for player {}", player_pk)),
        };
        tracing::info!("[REVEAL-TOKEN] Player {} submitted token ({}) num {:?}",
            player_pk, self.reveal_token_state.phase, tokens.len());

        for token in tokens {
            let cards = match self.reveal_token_state.phase {
                RevealPhase::None => {
                    return Err("Reveal token phase not active".to_string());
                }
                RevealPhase::HandReveal => &assign.hand_card,
                RevealPhase::CommunityReveal => &assign.community_card,
                RevealPhase::ShowdownReveal => &assign.hand_card,
                RevealPhase::RedealReveal => &assign.hand_card,
            };
            if !cards.iter().any(|pct| pct == &token.encrypted_card) {
                return Err(format!("Invalid token in {} phase", self.reveal_token_state.phase));
            }
            if let Err(e) = self.mental_poker_game.submit_reveal_token(token.clone(), player_pk) {
                tracing::error!("[REVEAL-TOKEN] Token submission failed: {:?}", e);
                return Err(format!("Token submission failed: {:?}", e));
            }
        }
        Ok(())
    }

    pub fn get_reveal_token_public_state(&self) -> Option<RevealTokenPublicState> {
        if self.reveal_token_state.is_active() {
            Some(RevealTokenPublicState {
                phase: self.reveal_token_state.phase.to_string(),
                completed_players: self.reveal_token_state.completed_players.clone(),
                pending_players: self.reveal_token_state.pending_players.clone(),
                player_assignments: self.reveal_token_state.player_assignments.clone(),
            })
        } else {
            None
        }
    }
}

// ============================================================
// P0.2 不变量回归（Plan D）：reveal 编排必须满足的协议不变量。
//
// 服务器是 reveal 调度者。若（有意或回归）把玩家自己的手牌密文
// 放进该玩家在非 ShowdownReveal 阶段的 assignment，客户端会交出
// 自己的解密份额，服务器即可集齐 N 份解密底牌——这是
// "no admin can peek at cards" 的唯一主动攻击面（见
// docs/starknet-plan-d-stark-curve.md §0.2）。以下测试把它钉死：
// - HandReveal / CommunityReveal：assignment 不得包含 assignee 自己
//   的 hand_encrypted；
// - ShowdownReveal：assignment 必须恰好是自己的 hand_encrypted。
// 客户端侧对应守卫见 client/src/context/game/useCryptoOperations.ts
// 的 revealOwnCardGuard。
// ============================================================
#[cfg(test)]
mod reveal_invariant_tests {
    use super::*;
    use crate::pokergame::player::{GamePkHex, GamePlayer, WalletAddress};

    fn make_test_table() -> Table {
        Table::new(7, "invariant".to_string(), 100, 6, String::new())
    }

    /// 注册一个玩家到 mental_poker_game（真实 PKOwnership 证明）并入座。
    fn register_and_seat(table: &mut Table, idx: u64) -> String {
        use poker_protocol::crypto::curve::{Curve, CurveScalar};
        use poker_protocol::z_poker::PKOwnershipProof;

        let sk = <poker_protocol::crypto::DefaultCurve as Curve>::Scalar::random(&mut rand_core::OsRng);
        let pk = <poker_protocol::crypto::DefaultCurve as Curve>::base_g() * sk;
        let proof = PKOwnershipProof::prove(&sk, &pk, &mut rand_core::OsRng);
        let pk_hex = format!("{:064x}", idx);
        table
            .mental_poker_game
            .register_player(pk_hex.clone(), pk, proof);
        let player = GamePlayer {
            name: format!("p{idx}"),
            bankroll: 1000,
            pk_hex: GamePkHex::new(pk_hex.clone()),
            readable_hands: vec![],
            wallet_address: WalletAddress(format!("0xwallet{idx}")),
        };
        table.sit_player(player, idx as u32, 1000, false);
        // Seat::new 默认 folded=true（生产由开局流程清除）；测试直接清位，
        // 使 start_showdown_reveal_phase 的 !s.folded 过滤能看到这些座位。
        if let Some(seat) = table.local_seats.get_mut(&(idx as u32)) {
            seat.folded = false;
        }
        pk_hex
    }

    fn deal_hands(table: &mut Table) {
        for pk in table.mental_poker_game.players.keys().cloned().collect::<Vec<_>>() {
            table
                .mental_poker_game
                .deal_to_player(&pk, 2)
                .expect("deal to registered player");
        }
    }

    fn own_hand_ciphers(table: &Table, pk_hex: &str) -> Vec<String> {
        table
            .mental_poker_game
            .players
            .get(pk_hex)
            .map(|p| {
                p.hand_encrypted
                    .iter()
                    .map(|c| hex_ct(&c.encrypted_card))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn hex_ct(ct: &poker_protocol::crypto::ElGamalCiphertext) -> String {
        let mut s = String::new();
        s.push_str(&hex_bytes(ct.c1.compress().as_ref()));
        s.push_str(&hex_bytes(ct.c2.compress().as_ref()));
        s
    }

    fn hex_bytes(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// HandReveal（preflop）：assignment 不得包含 assignee 自己的手牌。
    #[test]
    fn hand_reveal_assignment_excludes_own_hand_cards() {
        let mut table = make_test_table();
        let pks: Vec<String> = (1..=3).map(|i| register_and_seat(&mut table, i)).collect();
        deal_hands(&mut table);
        assert!(
            table
                .mental_poker_game
                .players
                .values()
                .all(|p| !p.hand_encrypted.is_empty()),
            "fixture: every player must hold dealt cards"
        );

        table.start_preflop_reveal_phase();
        let state = table.reveal_token_state.clone();
        assert_eq!(state.phase, RevealPhase::HandReveal);

        for pk_hex in &pks {
            let assignment = state
                .player_assignments
                .get(&GamePkHex::new(pk_hex.clone()))
                .expect("every seated player gets an assignment");
            let own = own_hand_ciphers(&table, pk_hex);
            assert!(!own.is_empty());
            for card in &assignment.hand_card {
                assert!(
                    !own.contains(&hex_ct(card)),
                    "P0.2 invariant violated: own hand card leaked into own \
                     HandReveal assignment for {pk_hex} — a client following \
                     this assignment would surrender its decryption share"
                );
            }
        }
    }

    /// CommunityReveal：assignment 只含公共牌，不得混入任何玩家手牌。
    #[test]
    fn community_reveal_assignment_contains_only_community_cards() {
        let mut table = make_test_table();
        let pks: Vec<String> = (1..=3).map(|i| register_and_seat(&mut table, i)).collect();
        deal_hands(&mut table);
        table.mental_poker_game.deal_community_cards_encrypted(5);

        table.start_community_reveal_phase();
        let state = table.reveal_token_state.clone();
        assert_eq!(state.phase, RevealPhase::CommunityReveal);

        for pk_hex in &pks {
            let assignment = state
                .player_assignments
                .get(&GamePkHex::new(pk_hex.clone()))
                .expect("assignment for every player");
            let own = own_hand_ciphers(&table, pk_hex);
            for card in &assignment.hand_card {
                assert!(
                    !own.contains(&hex_ct(card)),
                    "P0.2 invariant violated: own hand card leaked into \
                     CommunityReveal assignment for {pk_hex}"
                );
            }
        }
    }

    /// ShowdownReveal：assignment 必须恰好等于自己的 hand_encrypted
    /// （持有者此刻交出自己的份额，卡牌公开——唯一允许的自身出份额阶段）。
    #[test]
    fn showdown_reveal_assignment_is_exactly_own_hand() {
        let mut table = make_test_table();
        let pks: Vec<String> = (1..=3).map(|i| register_and_seat(&mut table, i)).collect();
        deal_hands(&mut table);

        table.start_showdown_reveal_phase();
        let state = table.reveal_token_state.clone();
        assert_eq!(state.phase, RevealPhase::ShowdownReveal);

        for pk_hex in &pks {
            let assignment = state
                .player_assignments
                .get(&GamePkHex::new(pk_hex.clone()))
                .expect("showdown assignment for every seated player");
            let own = own_hand_ciphers(&table, pk_hex);
            assert_eq!(
                assignment.hand_card.len(),
                own.len(),
                "showdown assignment must cover exactly the own hand"
            );
            for card in &assignment.hand_card {
                assert!(
                    own.contains(&hex_ct(card)),
                    "showdown assignment must only contain own hand cards"
                );
            }
        }
    }
}
