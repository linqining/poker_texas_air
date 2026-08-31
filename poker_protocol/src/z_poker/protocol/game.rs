use crate::crypto::{
    encrypt_batch, DefaultCurve, EcPoint, ElGamalCiphertext, Plaintext, Scalar, BASE_G, N_CARDS,
};
use crate::z_poker::convert::hex_to_ecpoint;
use crate::zk_shuffle::error::VerificationError;
use crate::zk_shuffle::reveal_token_proof::{RevealTokenProof, REVEAL_TOKEN_PROOF_LABEL};
// 兼容 Move 合约：生产代码使用 FiatShamirTranscript（SHA3-256），
// 而非 FiatShamirTranscript（STROBE），因为 Move 合约使用 SHA3-256 状态机。
use super::expel::{ExpelRecord, ExpelSessionPhase, ExpelStateResponse, ExpelSummary};
use super::rounds::ShuffleRound;
use super::types::{
    DealResult, GameConfig, PlayerEncryptedCard, PlayerState, RevealState, RevealToken,
    RevealTokenSimple,
};
use crate::crypto::curve::{Curve, CurvePoint, CurveScalar};
use crate::z_poker::card::{standard_deck, PlayingCard};
use crate::z_poker::key_manager::KeyManager;
use crate::zk_shuffle::transcript_ext::{CryptoTranscript, FiatShamirTranscript};
#[cfg(not(feature = "stark-curve"))]
use blstrs::G1Projective;
use rand_core::OsRng;
use std::collections::HashMap;

/// Derive 52 deterministic, independent EcPoints as card plaintexts.
///
/// Uses BLS12-381 hash_to_g1 with label "texas_poker/card/{i}".
/// DST 对齐 poker_l1 VM 的 `generate_plaintext_cards`（BLS_G1_DST）——
/// 方案A 的 deck 同源要求：游戏层与 VM 必须共享同一规范明文域，
/// 否则注入 VM 的 deck 在解密时无法 canonical-match。
#[cfg(not(feature = "stark-curve"))]
pub fn new_plain_text() -> Vec<Plaintext> {
    const BLS_DST: &[u8] = b"POKER_L1_BLS12381G1_XMD:SHA-256_SSWU_RO_";
    (0..N_CARDS)
        .map(|i| {
            let label = format!("texas_poker/card/{}", i);
            G1Projective::hash_to_curve(label.as_bytes(), BLS_DST, b"")
        })
        .collect()
}

/// Plan D：STARK 曲线世界的明文牌 = DefaultCurve::hash_to_curve
/// （poseidon try-and-increment，与本仓库主协议一致）。
#[cfg(feature = "stark-curve")]
pub fn new_plain_text() -> Vec<Plaintext> {
    (0..N_CARDS)
        .map(|i| {
            let label = format!("texas_poker/card/{}", i);
            <DefaultCurve as Curve>::hash_to_curve(label.as_bytes())
        })
        .collect()
}

#[derive(Debug)]
pub struct MentalPokerGame {
    pub config: GameConfig,
    pub key_manager: KeyManager,
    pub players: HashMap<String, PlayerState>,
    pub deck_plaintext: Vec<Plaintext>,
    pub deck_encrypted: Vec<ElGamalCiphertext>,
    pub shuffle_rounds: Vec<ShuffleRound>,
    pub deal_results: Vec<DealResult>,
    pub community_cards_encrypted: Vec<PlayerEncryptedCard>,
    pub community_cards: Vec<Option<RevealToken>>,
    pub revealed_cards: HashMap<usize, Plaintext>,
    pub expelled_players: Vec<String>,
    pub expel_records: Vec<ExpelRecord>,
    pub entrusted_sk: HashMap<String, Scalar>,
}

impl MentalPokerGame {
    pub fn new(config: GameConfig) -> Self {
        let n_community = config.community_cards;
        let deck_plaintext = new_plain_text();
        let initial_encrypt_deck = deck_plaintext
            .iter()
            .map(|c| ElGamalCiphertext {
                c1: *BASE_G,
                c2: *c,
            })
            .collect();
        Self {
            config,
            key_manager: KeyManager::new(),
            players: HashMap::new(),
            deck_plaintext: deck_plaintext,
            deck_encrypted: initial_encrypt_deck,
            shuffle_rounds: vec![],
            deal_results: vec![],
            community_cards_encrypted: vec![],
            community_cards: vec![None; n_community],
            revealed_cards: HashMap::new(),
            expelled_players: vec![],
            expel_records: vec![],
            entrusted_sk: HashMap::new(),
        }
    }

    pub fn reset(&mut self) {
        // 初始牌组 (G, m + agg)：把当前注册玩家的聚合钥层预置进 c2。
        //
        // 为什么必须 + agg：SHUFFLE_SUBMIT 路径没有 mask 步骤（纯重加密），
        // 若初始 c2 = m，则 shuffle-only 手牌的 deck = m + (s−1)·agg，
        // reveal 的 token 和只消掉 s·agg，解出 m − agg ≠ 任何规范明文
        // ——表现为"第一手正常、第二手起手牌/公共牌全部无法解密显示"。
        // 预置 +agg 后 deck = m + s·agg 恒成立（s = c1 标量），token 和
        // 恰好消去聚合层。s·G = c1 从 1 起步（c1 = G），与 join 路径一致。
        let agg = self.key_manager.get_aggregated_pk();
        let initial_encrypt_deck = self
            .deck_plaintext
            .iter()
            .map(|c| ElGamalCiphertext {
                c1: *BASE_G,
                c2: *c + agg,
            })
            .collect();
        self.deck_encrypted = initial_encrypt_deck;
        self.shuffle_rounds.clear();
        self.deal_results.clear();
        self.community_cards_encrypted.clear();
        self.community_cards.clear();
        self.revealed_cards.clear();
        self.expelled_players.clear();
        self.expel_records.clear();
        self.entrusted_sk.clear();
        for (_, p) in self.players.iter_mut() {
            p.hand_encrypted.clear();
        }
    }

    pub fn register_player(
        &mut self,
        pk_hex: String,
        pk: EcPoint,
        proof: crate::z_poker::key_manager::PKOwnershipProof,
    ) -> &PlayerState {
        self.key_manager
            .register_player(pk, proof)
            .expect("register should succeed");
        let state = PlayerState {
            pk_hex: pk_hex.clone(),
            pk,
            hand_encrypted: vec![],
        };
        let pk_hex_ref = pk_hex.clone();
        self.players.insert(pk_hex, state);
        self.players.get(&pk_hex_ref).unwrap()
    }

    pub fn list_unreveal_community_cards_encrypted(&self) -> Vec<PlayerEncryptedCard> {
        self.community_cards_encrypted
            .iter()
            .filter(|c| c.playing_card.is_none())
            .map(|c| c.clone())
            .collect()
    }

    pub fn list_revealed_cards(&self) -> (HashMap<String, Vec<PlayingCard>>, Vec<PlayingCard>) {
        let mut player_revealed_map = HashMap::new();
        let comm_revealed_cards = self
            .community_cards_encrypted
            .iter()
            .filter(|c| c.playing_card.is_some())
            .map(|c| c.playing_card.unwrap())
            .collect();
        for (pk, p) in self.players.iter() {
            let revealed_cards = p
                .hand_encrypted
                .iter()
                .filter(|c| c.playing_card.is_some())
                .map(|c| c.playing_card.unwrap())
                .collect();
            player_revealed_map.insert(pk.clone(), revealed_cards);
        }
        (player_revealed_map, comm_revealed_cards)
    }

    pub fn list_revealed_community_cards(&self) -> Vec<PlayingCard> {
        let comm_revealed_cards = self
            .community_cards_encrypted
            .iter()
            .filter(|c| c.playing_card.is_some())
            .map(|c| c.playing_card.unwrap())
            .collect();
        comm_revealed_cards
    }

    pub fn leave_player(&mut self, player_pk: &str) -> Result<(), VerificationError> {
        if !self.players.contains_key(player_pk) {
            return Err(VerificationError::EntryNotFound);
        }
        if let Some(_p) = self.players.remove(player_pk) {
            self.deal_results.retain(|dr| dr.player_pk != player_pk);
            self.expelled_players.push(player_pk.to_string());
            self.key_manager.remove_player(player_pk.to_string());
        }
        Ok(())
    }

    pub fn encrypt_deck(&mut self) {
        let mut rng = OsRng;
        self.deck_encrypted = encrypt_batch(
            &self.deck_plaintext,
            &self.key_manager.get_aggregated_pk(),
            &mut rng,
        );
    }

    pub fn submit_shuffle(
        &mut self,
        player_pk: &str,
        round: ShuffleRound,
    ) -> Result<(), VerificationError> {
        if !self.players.contains_key(player_pk) {
            return Err(VerificationError::PlayerNotFound);
        }

        let mut transcript = FiatShamirTranscript::new(b"zk_shuffle_proof_v2");
        if !round.verify(&self.key_manager.get_aggregated_pk(), &mut transcript) {
            return Err(VerificationError::ProofVerificationFailed);
        }

        self.deck_encrypted = round.output_cards.clone();
        self.shuffle_rounds.push(round);
        Ok(())
    }

    pub fn deal_to_player(&mut self, player_pk: &str, n: usize) -> Result<(), VerificationError> {
        let pending_players: Vec<EcPoint> = self.players.values().map(|p| p.pk).collect::<Vec<_>>();

        let player = self
            .players
            .get_mut(player_pk)
            .ok_or(VerificationError::PlayerNotFound)?;

        // 每名玩家每手牌的底牌数量硬上限（德扑 = 2）。任何重复发牌路径
        // （双重 advance、洗牌后重发等）到这里都会被拒绝，防止手牌无限增长。
        if player.hand_encrypted.len() + n > self.config.cards_per_player {
            return Err(VerificationError::TooManyCardsReplaced);
        }

        let pk_hex = player.pk_hex.clone();
        let mut card_index =
            Self::get_current_deal_num(&self.deal_results, &self.community_cards_encrypted);
        if card_index + n > self.deck_encrypted.len() {
            return Err(VerificationError::TooManyCardsReplaced);
        }
        let mut player_encrypted_cards = Vec::with_capacity(n);
        let mut encrypted_cards = Vec::with_capacity(n);
        for _ in 0..n {
            player_encrypted_cards.push(PlayerEncryptedCard {
                card_index: card_index as u32,
                encrypted_card: self.deck_encrypted[card_index].clone(),
                reveal_state: RevealState {
                    pending_players: pending_players.clone(),
                    reveal_tokens: Vec::new(),
                },
                playing_card: None,
            });
            encrypted_cards.push(self.deck_encrypted[card_index].clone());
            card_index += 1;
        }
        player.hand_encrypted.extend(player_encrypted_cards);
        self.deal_results.push(DealResult {
            player_pk: pk_hex,
            encrypted_cards,
        });
        Ok(())
    }

    // 获取已发牌数量
    fn get_current_deal_num(
        deal_results: &[DealResult],
        community_cards_encrypted: &[PlayerEncryptedCard],
    ) -> usize {
        let mut deal_idx = 0;
        for dr in deal_results {
            deal_idx += dr.encrypted_cards.len();
        }
        deal_idx += community_cards_encrypted.len();
        deal_idx
    }

    pub fn deal_community_cards_encrypted(&mut self, n: usize) -> Vec<ElGamalCiphertext> {
        let mut encrypted_cards = Vec::with_capacity(n);
        let pending_players = self
            .players
            .values()
            .map(|p| p.pk.clone())
            .collect::<Vec<_>>();
        // 公共牌总数硬上限（德扑 = 5）。超出的部分截断（而非报错），保证
        // 双重推进等异常路径不会产生多于 5 张的公共牌。
        let remaining = self.config.community_cards.saturating_sub(self.community_cards_encrypted.len());
        let n = n.min(remaining);
        if n == 0 {
            tracing::warn!(
                "[deal_community] community cards capped at {} — ignoring extra deal request",
                self.config.community_cards
            );
            return encrypted_cards;
        }
        let deal_num =
            Self::get_current_deal_num(&self.deal_results, &self.community_cards_encrypted);
        for num in 0..n {
            let curr_idx = deal_num + num;
            let encrypt_card = self.deck_encrypted[curr_idx].clone();
            encrypted_cards.push(encrypt_card.clone());
            self.community_cards_encrypted.push(PlayerEncryptedCard {
                card_index: curr_idx as u32,
                encrypted_card: encrypt_card.clone(),
                reveal_state: RevealState {
                    pending_players: pending_players.clone(),
                    reveal_tokens: Vec::new(),
                },
                playing_card: None,
            });
        }
        encrypted_cards
    }

    pub fn get_hand_encrypted(&self, player_pk: &str) -> Option<&[PlayerEncryptedCard]> {
        self.players
            .get(player_pk)
            .map(|p| p.hand_encrypted.as_slice())
    }

    pub fn get_hand_plaintext(
        &self,
        player_pk: &str,
    ) -> Result<Vec<PlayingCard>, VerificationError> {
        let player = self
            .players
            .get(player_pk)
            .ok_or(VerificationError::EntryNotFound)?;
        let plaintexts: Vec<Plaintext> = player
            .hand_encrypted
            .iter()
            .filter(|card| card.reveal_state.pending_players.is_empty())
            .map(|card| {
                let mut reveal_tokens = EcPoint::identity();
                for token in &card.reveal_state.reveal_tokens {
                    reveal_tokens = reveal_tokens + token.reveal_token;
                }
                card.encrypted_card.c2 - reveal_tokens
            })
            .collect();
        let mut ret = Vec::new();
        for plaintext in plaintexts {
            let playing_cards: Option<PlayingCard> =
                Self::plaintext_to_playingcard_static(&self.deck_plaintext, &plaintext);
            if let Some(card) = playing_cards {
                ret.push(card);
            }
        }
        Ok(ret)
    }

    pub fn aggregated_pk(&self) -> EcPoint {
        self.key_manager.get_aggregated_pk()
    }

    pub fn submit_reveal_token(
        &mut self,
        token: RevealToken,
        player_pk: &str,
    ) -> Result<(), VerificationError> {
        let valid = self.verify_reveal_token(&token, player_pk)?;
        if !valid {
            return Err(VerificationError::InvalidRevealToken);
        }
        let pk_point =
            hex_to_ecpoint(player_pk).map_err(|_| VerificationError::InvalidPublicKey)?;
        for (_pk, state) in self.players.iter_mut() {
            for card in state.hand_encrypted.iter_mut() {
                if card.reveal_state.pending_players.is_empty() {
                    continue;
                }
                if card.encrypted_card == token.encrypted_card {
                    card.reveal_state.reveal_tokens.push(RevealTokenSimple {
                        proof: token.proof,
                        reveal_token: token.reveal_token,
                        user_public_key: token.proof.user_public_key,
                    });
                    card.reveal_state
                        .pending_players
                        .retain(|p| *p != token.proof.user_public_key);
                    if card.reveal_state.pending_players.is_empty() {
                        let plain_text = card.encrypted_card.c2
                            - card
                                .reveal_state
                                .reveal_tokens
                                .iter()
                                .map(|t| t.reveal_token)
                                .sum::<EcPoint>();
                        let playing_card = Self::plaintext_to_playingcard_static(
                            &self.deck_plaintext,
                            &plain_text,
                        );
                        card.playing_card = playing_card;
                    }
                }
            }
        }
        for card in self.community_cards_encrypted.iter_mut() {
            if card.reveal_state.pending_players.is_empty() {
                continue;
            }
            let encrypt_card = card.encrypted_card.clone();
            if encrypt_card == token.encrypted_card {
                tracing::info!("[submit_reveal_token]  match {} found", card.card_index);
                card.reveal_state.reveal_tokens.push(RevealTokenSimple {
                    proof: token.proof,
                    reveal_token: token.reveal_token,
                    user_public_key: token.proof.user_public_key,
                });
                card.reveal_state.pending_players.retain(|p| *p != pk_point);
                if card.reveal_state.pending_players.is_empty() {
                    let plain_text = card.encrypted_card.c2
                        - card
                            .reveal_state
                            .reveal_tokens
                            .iter()
                            .map(|t| t.reveal_token)
                            .sum::<EcPoint>();
                    let playing_card =
                        Self::plaintext_to_playingcard_static(&self.deck_plaintext, &plain_text);
                    if playing_card.is_none() {
                        // 诊断：物化失败 = 解密明文不在规范域（deck 不变量破坏）
                        tracing::error!(
                            "[submit_reveal_token] card {} materialize FAILED: plain={:?} c1={:?}",
                            card.card_index,
                            hex::encode(plain_text.compress().as_ref()).get(..24).unwrap_or(""),
                            hex::encode(card.encrypted_card.c1.compress().as_ref()).get(..24).unwrap_or("")
                        );
                    }
                    card.playing_card = playing_card;
                }
            }
        }
        Ok(())
    }

    pub fn verify_reveal_token(
        &self,
        token: &RevealToken,
        player_pk: &str,
    ) -> Result<bool, VerificationError> {
        let player = self
            .players
            .get(player_pk)
            .ok_or(VerificationError::EntryNotFound)?;

        if token.proof.user_public_key != player.pk {
            return Ok(false);
        }

        token
            .proof
            .verify(
                &token.encrypted_card,
                &token.reveal_token,
                &token.user_public_key,
                &mut FiatShamirTranscript::new(REVEAL_TOKEN_PROOF_LABEL),
            )
            .map(|_| true)
            .map_err(|_| VerificationError::ProofVerificationFailed)
    }

    pub fn submit_community_reveal(
        &mut self,
        token: RevealToken,
        comm_index: usize,
        revealer_pk: &str,
    ) -> Result<(), VerificationError> {
        if comm_index >= self.config.community_cards {
            return Err(VerificationError::LengthMismatch);
        }
        let offset = self.config.num_players * self.config.cards_per_player;
        let deck_index = offset + comm_index;

        let _valid = self.verify_community_reveal(&token, revealer_pk)?;
        let revealed_plaintext = token.encrypted_card.c2 - token.reveal_token;
        self.community_cards[comm_index] = Some(token.clone());
        self.revealed_cards.insert(deck_index, revealed_plaintext);
        Ok(())
    }

    pub fn verify_community_reveal(
        &self,
        token: &RevealToken,
        revealer_pk: &str,
    ) -> Result<bool, VerificationError> {
        let revealer = self
            .players
            .get(revealer_pk)
            .ok_or(VerificationError::EntryNotFound)?;

        if token.proof.user_public_key != revealer.pk {
            return Ok(false);
        }

        token
            .proof
            .verify(
                &token.encrypted_card,
                &token.reveal_token,
                &token.user_public_key,
                &mut FiatShamirTranscript::new(REVEAL_TOKEN_PROOF_LABEL),
            )
            .map(|_| true)
            .map_err(|_| VerificationError::ProofVerificationFailed)
    }

    pub fn is_valid_deck_plaintext(&self, pt: &Plaintext) -> bool {
        self.deck_plaintext.iter().any(|dpt| dpt == pt)
    }

    pub fn redeal_to_player(
        &mut self,
        player_pk: &str,
        hand_index: usize,
        current_pt: Plaintext,
    ) -> Result<ElGamalCiphertext, VerificationError> {
        self.redeal_inner(
            player_pk,
            hand_index,
            Some(current_pt),
            true,
            VerificationError::EntryNotFound,
        )
    }

    /// 重新发牌（不验证 plaintext），用于客户端报告解密失败的场景
    pub fn redeal_to_player_unchecked(
        &mut self,
        player_pk: &str,
        hand_index: usize,
    ) -> Result<ElGamalCiphertext, VerificationError> {
        self.redeal_inner(
            player_pk,
            hand_index,
            None,
            false,
            VerificationError::PlayerNotFound,
        )
    }

    /// Unified redeal implementation shared by `redeal_to_player` and
    /// `redeal_to_player_unchecked`.
    ///
    /// - `current_pt`: when `Some`, the plaintext to validate (safe variant).
    ///   `None` skips the plaintext validation gate (unchecked variant).
    /// - `validate`: when `true`, runs the `is_valid_deck_plaintext` gate.
    /// - `not_found_err`: error variant returned when `player_pk` is absent
    ///   (preserves the per-caller error variant).
    fn redeal_inner(
        &mut self,
        player_pk: &str,
        hand_index: usize,
        current_pt: Option<Plaintext>,
        validate: bool,
        not_found_err: VerificationError,
    ) -> Result<ElGamalCiphertext, VerificationError> {
        let player = self.players.get(player_pk).ok_or(not_found_err)?;

        if hand_index >= player.hand_encrypted.len() {
            return Err(VerificationError::LengthMismatch);
        }

        if validate {
            if let Some(pt) = &current_pt {
                if self.is_valid_deck_plaintext(pt) {
                    return Err(VerificationError::ProofVerificationFailed);
                }
            }
        }
        // todo reconstruct deck后 deal index 需要重置
        let deal_num =
            Self::get_current_deal_num(&self.deal_results, &self.community_cards_encrypted);
        if deal_num >= self.deck_encrypted.len() {
            return Err(VerificationError::TooManyCardsReplaced);
        }

        let redeal_ct = self.deck_encrypted[deal_num].clone();

        // 维护 deal_num：记录新的发牌结果
        self.deal_results.push(DealResult {
            player_pk: player_pk.to_string(),
            encrypted_cards: vec![redeal_ct.clone()],
        });

        // 替换玩家手牌中失败的牌，重置 reveal_state
        let pending_players: Vec<EcPoint> = self.players.values().map(|p| p.pk).collect();
        if let Some(player) = self.players.get_mut(player_pk) {
            player.hand_encrypted[hand_index] = PlayerEncryptedCard {
                card_index: deal_num as u32,
                encrypted_card: redeal_ct.clone(),
                reveal_state: RevealState {
                    pending_players,
                    reveal_tokens: Vec::new(),
                },
                playing_card: None,
            };
        }

        Ok(redeal_ct)
    }

    fn plaintext_to_playingcard_static(
        deck_plaintext: &[Plaintext],
        pt: &Plaintext,
    ) -> Option<PlayingCard> {
        let position = deck_plaintext.iter().position(|dpt| dpt == pt);
        let standard_deck = standard_deck();
        if let Some(index) = position {
            return Some(standard_deck[index]);
        }
        None
    }

    pub fn get_game_state_summary(&self) -> String {
        format!(
            "MentalPokerGame( players={}, shuffles={}, dealt={}, community_revealed={}/{}, expelled={}, entrusted={})",
            self.players.len(),
            self.shuffle_rounds.len(),
            self.deal_results.len(),
            self.community_cards.iter().filter(|x| x.is_some()).count(),
            self.config.community_cards,
            self.expelled_players.len(),
            self.entrusted_sk.len(),
        )
    }

    pub fn entrust_player(
        &mut self,
        player_pk: &str,
        sk: &Scalar,
    ) -> Result<(), VerificationError> {
        let player = self
            .players
            .get(player_pk)
            .ok_or(VerificationError::EntryNotFound)?;

        let claimed_pk = *BASE_G * sk;
        if claimed_pk != player.pk {
            return Err(VerificationError::EntryNotFound);
        }

        self.entrusted_sk.insert(player_pk.to_string(), *sk);
        Ok(())
    }

    pub fn is_entrusted(&self, player_pk: &str) -> bool {
        self.entrusted_sk.contains_key(player_pk)
    }

    pub fn get_entrusted_sk(&self, player_pk: &str) -> Option<&Scalar> {
        self.entrusted_sk.get(player_pk)
    }

    // 只能给离开了游戏的玩家调用
    pub fn proxy_shuffle_for(&mut self, player_pk: &str) -> Result<(), VerificationError> {
        if !self.players.contains_key(player_pk) {
            return Err(VerificationError::EntryNotFound);
        }

        let agg_pk = self.key_manager.get_aggregated_pk();
        let mut rng = OsRng;
        let mut transcript = FiatShamirTranscript::new(b"poker_protocol_force_shuffle");

        let round = ShuffleRound::execute(&self.deck_encrypted, &agg_pk, &mut transcript, &mut rng);

        let mut transcript = FiatShamirTranscript::new(b"poker_protocol_force_shuffle");
        if !round.verify(&agg_pk, &mut transcript) {
            return Err(VerificationError::ProofVerificationFailed);
        }

        self.deck_encrypted = round.output_cards.clone();
        self.shuffle_rounds.push(round);
        Ok(())
    }

    pub fn proxy_reveal_card_for(
        &mut self,
        player_pk: &str,
        card_index: usize,
    ) -> Result<RevealToken, VerificationError> {
        let sk = self
            .entrusted_sk
            .get(player_pk)
            .ok_or(VerificationError::EntryNotFound)?
            .clone();

        let player = self
            .players
            .get(player_pk)
            .ok_or(VerificationError::EntryNotFound)?;

        let hand = &player.hand_encrypted;
        if card_index >= hand.len() {
            return Err(VerificationError::LengthMismatch);
        }

        let player_card = hand[card_index].clone();
        let reveal_token = player_card.encrypted_card.gen_reveal_token(&sk);
        let mut transcript = FiatShamirTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        let proof = RevealTokenProof::<DefaultCurve>::prove(
            &sk,
            &player.pk,
            &player_card.encrypted_card,
            &reveal_token,
            &mut OsRng,
            &mut transcript,
        );

        Ok(RevealToken {
            user_public_key: player.pk,
            encrypted_card: player_card.encrypted_card,
            proof,
            reveal_token,
        })
    }

    pub fn proxy_reveal_community_for(
        &mut self,
        player_pk: &str,
        comm_plaintext: Plaintext,
    ) -> Result<RevealToken, VerificationError> {
        let sk = self
            .entrusted_sk
            .get(player_pk)
            .ok_or(VerificationError::EntryNotFound)?
            .clone();

        let player = self
            .players
            .get(player_pk)
            .ok_or(VerificationError::EntryNotFound)?;

        let ct_for_self =
            ElGamalCiphertext::encrypt(&comm_plaintext, &player.pk, &Scalar::random(&mut OsRng));
        let reveal_token = ct_for_self.gen_reveal_token(&sk);
        let mut transcript = FiatShamirTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        let proof = RevealTokenProof::<DefaultCurve>::prove(
            &sk,
            &player.pk,
            &ct_for_self,
            &reveal_token,
            &mut OsRng,
            &mut transcript,
        );

        Ok(RevealToken {
            user_public_key: player.pk,
            encrypted_card: ct_for_self,
            proof,
            reveal_token,
        })
    }

    pub fn revoke_entrustment(&mut self, player_pk: &str) -> bool {
        self.entrusted_sk.remove(player_pk).is_some()
    }

    pub fn expel_phase_name(phase: &Option<ExpelSessionPhase>) -> &'static str {
        match phase {
            None => "None",
            Some(ExpelSessionPhase::Initiated) => "Initiated",
            Some(ExpelSessionPhase::Collecting) => "Collecting",
            Some(ExpelSessionPhase::Finalized) => "Finalized",
        }
    }
}

impl MentalPokerGame {
    pub fn init_expel_deck(&mut self) -> Vec<ElGamalCiphertext> {
        let mut init_deck_cpy: Vec<ElGamalCiphertext> =
            vec![ElGamalCiphertext::new_placeholder_card(); N_CARDS];
        let agg_pk = self.aggregated_pk();
        let mut rng = OsRng;
        init_deck_cpy
            .iter_mut()
            .map(|x| x.re_encrypt(&agg_pk, &Scalar::random(&mut rng)))
            .collect::<Vec<_>>()
    }

    pub fn finalize_expel_session(
        &mut self,
        target_player_pk: &str,
    ) -> Result<ExpelSummary, VerificationError> {
        if !self
            .expelled_players
            .contains(&target_player_pk.to_string())
        {
            return Err(VerificationError::EntryNotFound);
        }

        let active_player_pks: Vec<String> = self
            .players
            .keys()
            .filter(|pk| *pk != target_player_pk && !self.expelled_players.contains(*pk))
            .cloned()
            .collect();

        let mut redealt_count = 0usize;
        for player_pk in &active_player_pks {
            if let Some(hand_data) = self.get_hand_encrypted(player_pk) {
                let hand_vec = hand_data.to_vec();
                for idx in 0..hand_vec.len() {
                    let pt = match self.peek_card_after_expel(player_pk, idx) {
                        Ok(pt) => pt,
                        Err(_) => continue,
                    };
                    if !self.is_valid_deck_plaintext(&pt) {
                        if self.redeal_to_player(player_pk, idx, pt).is_ok() {
                            redealt_count += 1;
                        }
                    }
                }
            }
        }

        let summary = ExpelSummary {
            expelled_player_pk: target_player_pk.to_string(),
            remaining_players: active_player_pks.len(),
            proofs_accepted: self
                .expel_records
                .iter()
                .filter(|r| r.expelled_player_pk == *target_player_pk)
                .count(),
            cards_redealt: redealt_count,
            deck_size: self.deck_encrypted.len(),
            community_revealed: self.community_cards.iter().filter(|x| x.is_some()).count(),
        };

        Ok(summary)
    }

    pub fn peek_card_after_expel(
        &self,
        player_pk: &str,
        card_index: usize,
    ) -> Result<Plaintext, VerificationError> {
        let hand = self
            .get_hand_encrypted(player_pk)
            .ok_or(VerificationError::EntryNotFound)?;
        if card_index >= hand.len() {
            return Err(VerificationError::LengthMismatch);
        }
        let ct = &hand[card_index];
        let player = self
            .players
            .get(player_pk)
            .ok_or(VerificationError::EntryNotFound)?;
        let active_sk_entries: Vec<Scalar> = self
            .players
            .values()
            .filter_map(|p| {
                if p.pk_hex == *player_pk {
                    return None;
                }
                if self.expelled_players.contains(&p.pk_hex) {
                    return None;
                }
                self.entrusted_sk.get(&p.pk_hex).cloned()
            })
            .collect();

        let mut token_sum = EcPoint::identity();

        for sk in &active_sk_entries {
            let token = ct.encrypted_card.gen_reveal_token(sk);
            token_sum = token_sum + token;
        }

        Ok(ct.encrypted_card.c2 - token_sum)
    }

    pub fn get_expel_state(&self) -> ExpelStateResponse {
        ExpelStateResponse {
            expelled_players: self.expelled_players.clone(),
            expel_records_count: self.expel_records.len(),
            active_players: self.players.keys().cloned().collect(),
            can_continue: self.players.len() > self.expelled_players.len()
                && self.expelled_players.len() > 0,
        }
    }

    pub fn is_player_active(&self, player_pk: &str) -> bool {
        self.players.contains_key(player_pk)
            && !self.expelled_players.contains(&player_pk.to_string())
    }

    pub fn force_expel_player(
        &mut self,
        target_player_pk: &str,
    ) -> Result<ExpelSummary, VerificationError> {
        let hand = self
            .get_hand_encrypted(target_player_pk)
            .ok_or(VerificationError::EntryNotFound)?
            .to_vec();

        if hand.is_empty() {
            return Err(VerificationError::EntryNotFound);
        }

        let player = self
            .players
            .get(target_player_pk)
            .ok_or(VerificationError::EntryNotFound)?;

        let player_pk_val = player.pk;

        let agg_pk = self.key_manager.get_aggregated_pk();
        let mut expelled_positions: Vec<usize> = Vec::new();
        let mut expelled_plaintexts: Vec<Plaintext> = Vec::new();

        for ct in &hand {
            let mut token_sum = EcPoint::identity();
            for (_pk, sk_entry) in &self.entrusted_sk {
                let token = ct.encrypted_card.gen_reveal_token(sk_entry);
                token_sum = token_sum + token;
            }
            let decrypted = ct.encrypted_card.c2 - token_sum;

            if let Some(pos) = self.deck_plaintext.iter().position(|pt| *pt == decrypted) {
                expelled_positions.push(pos);
                expelled_plaintexts.push(decrypted);
            }
        }

        if expelled_positions.is_empty() {
            return Err(VerificationError::EntryNotFound);
        }

        let all_r_new: Vec<Scalar> = (0..N_CARDS).map(|_| Scalar::random(&mut OsRng)).collect();
        let placeholder = ElGamalCiphertext::new_placeholder_card();
        let output_cards: Vec<ElGamalCiphertext> = self
            .deck_plaintext
            .iter()
            .enumerate()
            .map(|(i, _pt)| {
                if expelled_positions.contains(&i) {
                    placeholder.re_encrypt(&agg_pk, &all_r_new[i])
                } else {
                    ElGamalCiphertext::encrypt(&self.deck_plaintext[i], &agg_pk, &all_r_new[i])
                }
            })
            .collect();

        self.deck_encrypted = output_cards.clone();
        self.expelled_players.push(target_player_pk.to_string());
        self.key_manager.remove_player(target_player_pk.to_string());

        if let Some(p) = self.players.get_mut(target_player_pk) {
            p.hand_encrypted.clear();
        }

        self.deal_results
            .retain(|dr| dr.player_pk != target_player_pk);

        let active_player_pks: Vec<String> = self
            .players
            .keys()
            .filter(|pk| *pk != target_player_pk && !self.expelled_players.contains(*pk))
            .cloned()
            .collect();

        let mut redealt_count = 0usize;
        for player_pk in &active_player_pks {
            if let Some(hand_data) = self.get_hand_encrypted(player_pk) {
                let hand_vec = hand_data.to_vec();
                for idx in 0..hand_vec.len() {
                    let pt = match self.peek_card_after_expel(&player_pk, idx) {
                        Ok(pt) => pt,
                        Err(_) => continue,
                    };
                    if !self.is_valid_deck_plaintext(&pt) {
                        if self.redeal_to_player(&player_pk, idx, pt).is_ok() {
                            redealt_count += 1;
                        }
                    }
                }
            }
        }

        let summary = ExpelSummary {
            expelled_player_pk: target_player_pk.to_string(),
            remaining_players: active_player_pks.len(),
            proofs_accepted: 1,
            cards_redealt: redealt_count,
            deck_size: self.deck_encrypted.len(),
            community_revealed: self.community_cards.iter().filter(|x| x.is_some()).count(),
        };

        Ok(summary)
    }

    pub fn verify_all_pk_proofs(&self) -> bool {
        self.key_manager.verify_all_proofs()
    }

    pub fn get_all_reveal_tokens_for_card(&self, card_ct: &ElGamalCiphertext) -> Vec<RevealToken> {
        self.players
            .keys()
            .filter_map(|pk| {
                if self.entrusted_sk.contains_key(pk) {
                    let sk = &self.entrusted_sk[pk];
                    let pk_val = &self.players[pk].pk;
                    let reveal_token = card_ct.gen_reveal_token(sk);
                    let mut transcript = FiatShamirTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
                    let proof = RevealTokenProof::<DefaultCurve>::prove(
                        sk,
                        pk_val,
                        card_ct,
                        &reveal_token,
                        &mut OsRng,
                        &mut transcript,
                    );
                    Some(RevealToken {
                        user_public_key: *pk_val,
                        encrypted_card: card_ct.clone(),
                        proof,
                        reveal_token,
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    // 用户可解出的tokan
    pub fn get_player_readable_tokens(&self) -> HashMap<String, Vec<ElGamalCiphertext>> {
        let mut player_map = HashMap::new();
        for (player_pk, player) in self.players.clone() {
            let mut player_readable_cards = Vec::with_capacity(player.hand_encrypted.len());
            for ct in &player.hand_encrypted {
                if let Some(readable_card) = ct.get_readable_card(player.pk.clone()) {
                    player_readable_cards.push(readable_card);
                }
            }
            player_map.insert(player_pk.clone(), player_readable_cards);
        }
        player_map
    }

    pub fn unmask_card(
        &self,
        card_ct: &ElGamalCiphertext,
        tokens: &[RevealToken],
    ) -> Result<Plaintext, VerificationError> {
        super::client::ClientPlayer::distributed_decrypt_from_tokens(card_ct, tokens)
    }

    pub fn compute_aggregate_key_from_pks(pks: &[EcPoint]) -> EcPoint {
        pks.iter().fold(EcPoint::identity(), |agg, pk| agg + pk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{DefaultCurve, ElGamalCiphertext, Scalar};
    use crate::z_poker::protocol::ClientPlayer;
    use crate::zk_shuffle::reveal_token_proof::RevealTokenProof;
    use crate::zk_shuffle::transcript_ext::{CryptoTranscript, FiatShamirTranscript};
    use rand_core::OsRng;

    /// Verify that `submit_reveal_token` returns `InvalidPublicKey` error
    /// instead of panicking when `player_pk` is a malformed hex string.
    #[test]
    fn test_submit_reveal_token_malformed_pk_returns_error() {
        let mut game = MentalPokerGame::new(GameConfig::default());
        let player = ClientPlayer::new();

        // Insert a player whose map key (pk_hex) is a malformed hex string.
        // The pk field holds a valid EcPoint so that verify_reveal_token passes,
        // but hex_to_ecpoint(player_pk) will fail on the malformed string.
        let malformed_pk_hex = "not_a_valid_hex_string".to_string();
        let state = PlayerState {
            pk_hex: malformed_pk_hex.clone(),
            pk: player.pk,
            hand_encrypted: vec![],
        };
        game.players.insert(malformed_pk_hex.clone(), state);

        // Build a valid encrypted card, reveal token, and proof.
        let pt = new_plain_text()[0];
        let r = Scalar::random(&mut OsRng);
        let encrypted_card = ElGamalCiphertext::encrypt(&pt, &player.pk, &r);
        let reveal_token = encrypted_card.gen_reveal_token(&player.sk);

        let mut transcript = FiatShamirTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        let proof = RevealTokenProof::<DefaultCurve>::prove(
            &player.sk,
            &player.pk,
            &encrypted_card,
            &reveal_token,
            &mut OsRng,
            &mut transcript,
        );

        let token = RevealToken {
            encrypted_card,
            proof,
            reveal_token,
            user_public_key: player.pk,
        };

        // Should return Err(InvalidPublicKey) instead of panicking.
        let result = game.submit_reveal_token(token, &malformed_pk_hex);
        assert!(
            matches!(result, Err(VerificationError::InvalidPublicKey)),
            "Expected Err(InvalidPublicKey), got {:?}",
            result
        );
    }
}
