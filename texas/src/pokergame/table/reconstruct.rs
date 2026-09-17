use super::*;
use crate::pokergame::game_state::ShufflePhase;
use poker_protocol::crypto::DefaultCurve;
use poker_protocol::transcript_domains::{
    RECONSTRUCTION_CONTEXT_DIGEST_DOMAIN, RECONSTRUCTION_PRIOR_STATE_DIGEST_DOMAIN,
};
use poker_protocol::zk_shuffle::reconstruction::{ReconstructProof, ReconstructionStatement};

impl Table {
    /// reconstruction 上下文摘要：绑定 table id / hand id / 曲线域。
    /// 域与材料布局镜像 poker_l1 `utils::reconstruction_v3_context_digest`。
    fn reconstruction_context_digest(&self) -> [u8; 32] {
        let mut material = Vec::with_capacity(96);
        material.extend_from_slice(RECONSTRUCTION_CONTEXT_DIGEST_DOMAIN);
        material.extend_from_slice(&self.summary.id.to_le_bytes());
        material.extend_from_slice(&self.current_hand_id.to_le_bytes());
        material.extend_from_slice(b"stark-curve-v1");
        poker_protocol::poseidon_bytes_digest(&material)
    }

    /// 玩家 prior-state 摘要：吸收其上一轮 residual carriers 与桌台密钥状态。
    /// 服务端重算（不信任客户端自报），域镜像 poker_l1
    /// `utils::reconstruction_v3_prior_state_digest`。
    fn reconstruction_prior_state_digest(
        &self,
        player_pk: &EcPoint,
        epoch: u64,
        aggregate_pk: &EcPoint,
        residual_carriers: &[ElGamalCiphertext],
    ) -> [u8; 32] {
        let mut material = Vec::new();
        material.extend_from_slice(RECONSTRUCTION_PRIOR_STATE_DIGEST_DOMAIN);
        material.extend_from_slice(&self.summary.id.to_le_bytes());
        material.extend_from_slice(&self.current_hand_id.to_le_bytes());
        material.extend_from_slice(player_pk.compress().as_ref());
        material.extend_from_slice(&epoch.to_le_bytes());
        material.extend_from_slice(aggregate_pk.compress().as_ref());
        material.extend_from_slice(&(residual_carriers.len() as u32).to_le_bytes());
        for (slot, carrier) in residual_carriers.iter().enumerate() {
            material.extend_from_slice(&(slot as u32).to_le_bytes());
            material.extend_from_slice(carrier.c1.compress().as_ref());
            material.extend_from_slice(carrier.c2.compress().as_ref());
        }
        poker_protocol::poseidon_bytes_digest(&material)
    }

    pub fn start_reconstruct(&mut self) -> Result<(), String> {
        if self.reconstruct_state.is_active {
            return Err("Reconstruct already in progress".to_string());
        }
        // epoch 跨手单调递增（ReconstructState::reset 不清零）
        self.reconstruct_state.reconstruction_epoch += 1;
        let epoch = self.reconstruct_state.reconstruction_epoch;
        self.reconstruct_state.context_digest = self.reconstruction_context_digest();
        self.reconstruct_state.timeout_start = Some(std::time::Instant::now());
        self.reconstruct_state.timeout_seconds = 10;
        self.reconstruct_state.completed_players.clear();
        self.reconstruct_state.pending_players = self.mental_poker_game.players.keys()
            .map(|k| GamePkHex::new(k.clone()))
            .collect();
        self.reconstruct_state.cards = self.mental_poker_game.deck_plaintext.clone();
        self.reconstruct_state.player_residual_carriers.clear();
        self.reconstruct_state.prior_state_digests.clear();
        let aggregate_pk = self.mental_poker_game.key_manager.get_aggregated_pk();
        let player_residual_carriers = self.mental_poker_game.get_player_residual_carriers();
        for (pk, carriers) in player_residual_carriers {
            let pk_point = hex_to_ecpoint(&pk)?;
            let digest = self.reconstruction_prior_state_digest(
                &pk_point,
                epoch,
                &aggregate_pk,
                &carriers,
            );
            self.reconstruct_state.player_residual_carriers.insert(
                GamePkHex::new(pk.clone()),
                PlayerResidualCarriers { residual_carriers: carriers },
            );
            self.reconstruct_state
                .prior_state_digests
                .insert(GamePkHex::new(pk), digest);
        }
        self.reconstruct_state.player_deck.clear();
        tracing::info!("[RECONSTRUCT] Reconstruct initiated for players {} (epoch {})", self.reconstruct_state.pending_players.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(","), epoch);
        // 通知前端 reconstruct 阶段已开始
        self.emit_event(crate::pokergame::table::events::TableEvent::ReconstructNotice);
        Ok(())
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
        statement: ReconstructionStatement<DefaultCurve>,
        proof: ReconstructProof<DefaultCurve>,
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

        // statement 必须绑定服务端权威状态：statement 摘要字段一律服务端重算，
        // 客户端仅提供证明本体。
        let expected_carriers = self.reconstruct_state.player_residual_carriers
            .get(player_pk_hex)
            .ok_or("Player not found in reconstruct state")?;
        let expected_prior = self.reconstruct_state.prior_state_digests
            .get(player_pk_hex)
            .ok_or("Player not found in reconstruct state")?;
        if statement.version
            != poker_protocol::zk_shuffle::reconstruction::RECONSTRUCTION_PROOF_VERSION
        {
            return Err("Unsupported reconstruction statement version".to_string());
        }
        if statement.owner_pk != player {
            return Err("Statement owner key mismatch".to_string());
        }
        if statement.aggregate_pk != self.mental_poker_game.key_manager.get_aggregated_pk() {
            return Err("Statement aggregate key mismatch".to_string());
        }
        if statement.cards != self.reconstruct_state.cards {
            return Err("Statement card points mismatch".to_string());
        }
        if statement.residual_carriers != expected_carriers.residual_carriers {
            return Err("Statement residual carriers mismatch".to_string());
        }
        if statement.reconstruction_epoch != self.reconstruct_state.reconstruction_epoch {
            return Err("Statement epoch mismatch".to_string());
        }
        if statement.context_digest != self.reconstruct_state.context_digest {
            return Err("Statement context digest mismatch".to_string());
        }
        if statement.prior_state_digest != *expected_prior {
            return Err("Statement prior state digest mismatch".to_string());
        }
        statement
            .validate()
            .map_err(|e| format!("Invalid reconstruction statement: {e}"))?;

        let mut transcript = poker_protocol::zk_shuffle::transcript_ext::PoseidonFeltTranscript::new_domain(
            poker_protocol::transcript_domains::RECONSTRUCT_POSEIDON,
        );
        proof
            .verify(&statement, &mut transcript)
            .map_err(|e| format!("Invalid reconstruct proof: {e}"))?;

        self.reconstruct_state
            .player_deck
            .insert(player_pk_hex.clone(), statement.contributions);
        self.reconstruct_state.pending_players.retain(|p| p != player_pk_hex);
        self.reconstruct_state.completed_players.push(player_pk_hex.clone());
        let is_all_complete = self.reconstruct_state.pending_players.len()==0;
        // 移除原来的重建 deck 逻辑，由 execute_reconstruct_if_completed → on_complete_reconstruct 处理
        Ok(is_all_complete)
    }

    /// 镜像 Move on_complete_reconstruct：reconstruct 完成后重建牌组并重新洗牌。
    ///
    /// 新协议：从 canonical base deck（公牌点 × 聚合钥）出发，同态叠加每个
    /// 已验证玩家的 contributions。
    pub fn on_complete_reconstruct(&mut self) {
        let init_deck = self.mental_poker_game.deck_plaintext.clone();
        let aggregate_pk = self.mental_poker_game.key_manager.get_aggregated_pk();
        let mut deck = match poker_protocol::zk_shuffle::reconstruction::canonical_base_deck(
            &init_deck,
            &aggregate_pk,
        ) {
            Ok(deck) => deck,
            Err(e) => {
                tracing::error!("[RECONSTRUCT] canonical base deck failed: {e}");
                return;
            }
        };
        for (_, contributions) in self.reconstruct_state.player_deck.iter() {
            match poker_protocol::zk_shuffle::reconstruction::apply_reconstruction_contributions(
                &deck,
                contributions,
            ) {
                Ok(next) => deck = next,
                Err(e) => {
                    tracing::error!("[RECONSTRUCT] apply contributions failed: {e}");
                    return;
                }
            }
        }
        self.mental_poker_game.deck_encrypted = deck;
        // 重建 + 全员重洗后的 deck 是全新发牌序列：发牌游标归零，
        // 此后 deal/redeal 从新 deck 位置 0 起步（z_poker todo 收口）。
        self.mental_poker_game.note_deck_reconstructed();

        // 仅重置状态字段，保留 player_deck 供后续 on_reconstruct_shuffle_failed 重建牌组使用。
        // 下次 start_reconstruct 会清空 player_deck，此处无需清空。
        self.reconstruct_state.is_active = false;
        self.reconstruct_state.timeout_start = None;
        self.reconstruct_state.completed_players.clear();
        self.reconstruct_state.pending_players.clear();
        self.reconstruct_state.cards.clear();
        self.reconstruct_state.player_residual_carriers.clear();

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
                aggregate_pk: ecpoint_to_hex(&self.mental_poker_game.key_manager.get_aggregated_pk()),
                context_digest: hex::encode(self.reconstruct_state.context_digest),
                reconstruction_epoch: self.reconstruct_state.reconstruction_epoch,
                prior_state_digests: self.reconstruct_state.prior_state_digests.iter()
                    .map(|(k, v)| (k.clone(), hex::encode(v)))
                    .collect(),
                player_residual_carriers: self.reconstruct_state.player_residual_carriers.iter().map(|(k, v)| {
                    (k.clone(), PlayerResidualCarriersJson {
                        residual_carriers: v.residual_carriers.iter().map(ElGamalCiphertextJson::from_ciphertext).collect(),
                    })
                }).collect(),
            })
        } else {
            None
        }
    }
}
