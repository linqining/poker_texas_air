use super::*;
use crate::pokergame::game_state::ShufflePhase;
use rand::rngs::OsRng;

impl Table {
    pub fn start_reconstruct(&mut self) -> Result<(), String> {
        if self.reconstruct_state.is_active {
            return Err("Reconstruct already in progress".to_string());
        }
        self.reconstruct_state.is_active = true;
        self.reconstruct_state.timeout_start = Some(std::time::Instant::now());
        self.reconstruct_state.timeout_seconds = 10;
        self.reconstruct_state.completed_players.clear();
        self.reconstruct_state.pending_players = self.mental_poker_game.players.keys()
            .map(|k| GamePkHex::new(k.clone()))
            .collect();
        self.reconstruct_state.cards = self.mental_poker_game.deck_plaintext.clone();
        let mut rng = OsRng;
        self.reconstruct_state.coefficient = Scalar::random(&mut rng);
        self.reconstruct_state.player_readable_cards.clear();
        let player_readable_cards = self.mental_poker_game.get_player_readable_tokens();
        for (pk, cards) in player_readable_cards {
            self.reconstruct_state.player_readable_cards.insert(GamePkHex::new(pk.clone()), PlayerReadableCard{readable_cards: cards});
        }
        self.reconstruct_state.player_deck.clear();
        tracing::info!("[RECONSTRUCT] Reconstruct initiated for player {}", self.reconstruct_state.pending_players.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(","));
        // 通知前端 reconstruct 阶段已开始
        self.emit_event(crate::pokergame::table::events::TableEvent::ReconstructNotice);
        Ok(())
    }

    pub fn check_reconstruct_timeout(&mut self) -> Option<Vec<GamePkHex>> {
        if !self.reconstruct_state.is_active {
            return None;
        }
        let timeout_start = match self.reconstruct_state.timeout_start {
            Some(t) => t,
            None => return None,
        };

        if timeout_start.elapsed().as_secs() >= self.reconstruct_state.timeout_seconds {
            // 移除未提交 deck 的玩家
            let mut not_submitted = Vec::new();
            for player_pk in self.reconstruct_state.pending_players.iter() {
                not_submitted.push(player_pk.clone());
            }
            tracing::warn!("[RECONSTRUCT] Reconstruct timeout for players: {:?}",
                not_submitted.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(","));
            for player_pk in &not_submitted {
                self.remove_player_by_pk(player_pk);
            }
            self.reconstruct_state.reset();
            return Some(not_submitted);
        }
        None
    }

    pub fn execute_reconstruct_if_completed(&mut self) -> bool {
        if !self.reconstruct_state.is_active {
            return false;
        }
        // D1 fix: use pending_players.is_empty() instead of
        // completed_players.len() >= pending_players.len(), which is always
        // true when pending is empty but also true in other wrong cases.
        if self.reconstruct_state.pending_players.is_empty() {
            tracing::info!("[RECONSTRUCT] Executing reconstruct for players: {:?}",
                self.reconstruct_state.completed_players);
            self.on_complete_reconstruct();
            return true;
        }
        false
    }

    pub fn submit_reconstruct_deck(
        &mut self,
        player_pk_hex: &GamePkHex,
        output_cards: Vec<ElGamalCiphertextJson>,
        swap_cards: Vec<ElGamalCiphertextJson>,
        proof: ReconstructProofJson,
    ) -> Result<bool, String> {
        if !self.reconstruct_state.is_active {
            return Err("Reconstruct not active".to_string());
        }
        if !self.reconstruct_state.pending_players.contains(player_pk_hex) {
            return Err("Not found player".to_string());
        }

        let player = self.mental_poker_game.players.get(&**player_pk_hex)
            .map(|p| p.pk)
            .ok_or("Player not found in mental poker game")?;

        let output_cards = output_cards.iter()
            .map(|c| c.to_ciphertext())
            .collect::<Result<Vec<_>, _>>()?;
        let swap_cards = swap_cards.iter()
            .map(|c| c.to_ciphertext())
            .collect::<Result<Vec<_>, _>>()?;
        let proof = proof.to_proof()?;
        let user_readable_cards = match self.reconstruct_state.player_readable_cards.get(player_pk_hex) {
            Some(c) => c,
            None => return Err("Player not found in reconstruct state".to_string()),
        };
        let mut transcript = poker_protocol::zk_shuffle::transcript_ext::FiatShamirTranscript::new(
            poker_protocol::zk_shuffle::reconstruction::RECONSTRUCTION_PROOF_LABEL,
        );
        if proof.verify(&self.reconstruct_state.cards, &output_cards,
        &swap_cards, &user_readable_cards.readable_cards,
        &player, &mut transcript).is_err(){
            return Err("Invalid reconstruct proof".to_string());
        }

        self.reconstruct_state.player_deck.insert(player_pk_hex.clone(), output_cards);
        self.reconstruct_state.pending_players.retain(|p| p != player_pk_hex);
        self.reconstruct_state.completed_players.push(player_pk_hex.clone());
        let is_all_complete = self.reconstruct_state.pending_players.len()==0;
        // 移除原来的重建 deck 逻辑，由 execute_reconstruct_if_completed → on_complete_reconstruct 处理
        Ok(is_all_complete)
    }

    /// 镜像 Move on_complete_reconstruct：reconstruct 完成后重建牌组并重新洗牌
    pub fn on_complete_reconstruct(&mut self) {
        // 重建牌组（从 player_deck 构建）
        let init_deck = self.mental_poker_game.deck_plaintext.clone();
        let deck_len = init_deck.len();
        let mut reconstruct_deck = init_deck.iter().map(|c| ElGamalCiphertext {
            c1: EcPoint::identity(),
            c2: c.clone(),
        }).collect::<Vec<_>>();
        for (_, deck) in self.reconstruct_state.player_deck.iter() {
            for (i, card) in deck.iter().enumerate() {
                if i < deck_len {
                    reconstruct_deck[i].c1 = reconstruct_deck[i].c1 + card.c1;
                    reconstruct_deck[i].c2 = reconstruct_deck[i].c2 + card.c2 - init_deck[i];
                }
            }
        }
        self.mental_poker_game.deck_encrypted = reconstruct_deck;

        // 仅重置状态字段，保留 player_deck 供后续 on_reconstruct_shuffle_failed 重建牌组使用。
        // 下次 start_reconstruct 会清空 player_deck，此处无需清空。
        self.reconstruct_state.is_active = false;
        self.reconstruct_state.timeout_start = None;
        self.reconstruct_state.completed_players.clear();
        self.reconstruct_state.pending_players.clear();
        self.reconstruct_state.cards.clear();
        self.reconstruct_state.coefficient = Scalar::zero();
        self.reconstruct_state.player_readable_cards.clear();

        // 进入洗牌阶段（RECONSTRUCT phase，对齐 Move shuffle_phase_reconstruct）
        self.shuffle_state.phase = ShufflePhase::Reconstruct;
        self.shuffle_state.pending_players = self.mental_poker_game.players.keys()
            .map(|k| GamePkHex::new(k.clone()))
            .collect();
        self.shuffle_state.completed_players.clear();
        self.shuffle_state.current_player_pk = None;

        // 推进洗牌
        self.advance_shuffle();

        // 通知前端 reconstruct 完成
        self.emit_event(crate::pokergame::table::events::TableEvent::TableUpdated {
            message: None,
        });
    }

    /// 镜像 Move on_reconstruct_timeout：处理 reconstruct 超时
    pub fn on_reconstruct_timeout(&mut self) {
        if !self.reconstruct_state.is_active {
            return;
        }
        let pending_pks = self.reconstruct_state.pending_players.clone();
        tracing::warn!("[RECONSTRUCT] Timeout for players: {:?}", pending_pks);

        // 对齐 Move：kick all pending players（kick_player_internal 会处理退款/pot/状态清理）
        for pk in &pending_pks {
            self.remove_player_by_pk(pk);
        }

        let active_count = self.active_players().len();

        // 对齐 Move：没有活跃玩家 → refund + reset
        if active_count == 0 {
            self.refund_all_bets();
            self.reset_for_next_hand();
            return;
        }

        // 对齐 Move：只剩一人 → end_without_showdown
        if active_count == 1 {
            self.end_without_showdown();
            return;
        }

        // 对齐 Move：kick 可能已触发 reset_for_next_hand（活跃玩家不足）
        if self.round_state() == RoundState::Waiting {
            return;
        }

        // 对齐 Move：不清空 reconstruct_state，保留已提交的 player_decks 供 on_complete_reconstruct 重建牌组
        // 重置 pending_players（已全部 kick），保留 completed_players 和 player_deck
        self.reconstruct_state.is_active = false;
        self.reconstruct_state.timeout_start = None;
        self.reconstruct_state.pending_players.clear();

        // 调用 on_complete_reconstruct 用已提交的 deck 重建牌组
        self.on_complete_reconstruct();
    }

    pub fn get_reconstruct_public_state(&self) -> Option<ReconstructPublicState> {
        if self.reconstruct_state.is_active {
            Some(ReconstructPublicState {
                is_active: true,
                completed_players: self.reconstruct_state.completed_players.clone(),
                pending_players: self.reconstruct_state.pending_players.clone(),
                cards: self.reconstruct_state.cards.iter().map(|c| ecpoint_to_hex(c)).collect(),
                coefficient_hex: scalar_to_hex(&self.reconstruct_state.coefficient),
                player_readable_cards: self.reconstruct_state.player_readable_cards.iter().map(|(k, v)| {
                    (k.clone(), PlayerReadableCardJson {
                        readable_cards: v.readable_cards.iter().map(ElGamalCiphertextJson::from_ciphertext).collect(),
                    })
                }).collect(),
            })
        } else {
            None
        }
    }
}
