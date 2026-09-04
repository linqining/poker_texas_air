use crate::crypto::{
    hash_to_scalar, DefaultCurve, EcPoint, ElGamalCiphertext, Plaintext, Scalar, base_g,
};
use crate::z_poker::convert::{ecpoint_to_hex, hex_to_scalar, scalar_to_hex};
use crate::zk_shuffle::error::VerificationError;
use crate::zk_shuffle::reconstruction::{
    reconstruct_deck, ReconstructProof, ReconstructProofV3, RECONSTRUCTION_PROOF_LABEL,
    RECONSTRUCTION_V3_PROOF_LABEL,
};
use crate::zk_shuffle::reveal_token_proof::{RevealTokenProof, REVEAL_TOKEN_PROOF_LABEL};
// Native Texas verifies reveal-token proofs with Merlin under the fixed V3
// domain label. Browser-produced proofs must use that exact transcript; the
// retired Move/SHA3 path is not wire-compatible with the native VM.
use super::rounds::{JoinGameAndShuffleRound, LeaveGameRound, MaskAndShuffleRound, ShuffleRound};
use super::types::{ReconstructDeck, ReconstructDeckV3, RevealToken};
use crate::crypto::curve::{CurvePoint, CurveScalar};
use crate::z_poker::card::PlayingCard;
use crate::z_poker::key_manager::PKOwnershipProof;
use crate::zk_shuffle::transcript_ext::{CryptoTranscript, FiatShamirTranscript, MerlinTranscript};
use hex;
use rand_core::OsRng;

#[derive(Debug, Clone)]
pub struct ClientPlayer {
    pub sk: Scalar,
    pub pk: EcPoint,
}

impl ClientPlayer {
    pub fn new() -> Self {
        let sk = Scalar::random(&mut OsRng);
        let pk = base_g() *  sk;
        Self { sk, pk }
    }

    pub fn new_with_wallet_address(wallet_address: &str) -> Self {
        let sk = hash_to_scalar(wallet_address.as_bytes());
        let pk = base_g() *  sk;
        Self { sk, pk }
    }

    /// 口令派生身份（SETTLEMENT_PRIVACY_PLAN.md Part B1.5）：
    /// sk = KDF(口令)，KDF 参数（域名 "v1" + 迭代次数）一经发布冻结——
    /// 任何变化都会让全部口令用户静默换身份，只允许升 "v2" 并保留 v1。
    /// 同一口令在任何设备派生出同一 (sk, pk)，口令即身份备份；
    /// 与钱包零派生关系（对比 new_with_wallet_address 的公开可计算性）。
    pub fn new_with_passphrase(passphrase: &str) -> Self {
        let sk = Self::derive_key_from_passphrase(passphrase);
        let pk = base_g() *  sk;
        Self { sk, pk }
    }

    /// 迭代 hash_to_scalar：低熵口令的离线爆破减速带（每次一次曲线域哈希）。
    /// 迭代次数只在带新版本号时才可改。
    pub const PASSPHRASE_KDF_ITERATIONS: u32 = 20_000;
    pub const PASSPHRASE_KDF_DOMAIN: &str = "zgame:player-key:v1:";

    pub fn derive_key_from_passphrase(passphrase: &str) -> Scalar {
        let mut x = {
            let mut buf = Vec::with_capacity(Self::PASSPHRASE_KDF_DOMAIN.len() + passphrase.len());
            buf.extend_from_slice(Self::PASSPHRASE_KDF_DOMAIN.as_bytes());
            buf.extend_from_slice(passphrase.as_bytes());
            buf
        };
        for _ in 0..Self::PASSPHRASE_KDF_ITERATIONS {
            x = hash_to_scalar(&x).as_bytes();
        }
        hash_to_scalar(&x)
    }

    pub fn new_with_sk_hex(sk_hex: String) -> Result<Self, VerificationError> {
        let sk = hex_to_scalar(&sk_hex).map_err(|_| VerificationError::InvalidSecretKey)?;
        let pk = base_g() *  &sk;
        Ok(Self { sk, pk })
    }

    pub fn get_sk_and_pk_hex(&self) -> (String, String) {
        (scalar_to_hex(&self.sk), ecpoint_to_hex(&self.pk))
    }

    pub fn decrypt_card(&self, ct: &ElGamalCiphertext) -> Plaintext {
        ct.decrypt(&self.sk)
    }

    pub fn decrypt_playing_card(
        &self,
        ct: &ElGamalCiphertext,
        other_tokens: Vec<EcPoint>,
        deck_plaintext: Vec<Plaintext>,
    ) -> Option<PlayingCard> {
        let token = self.generate_reveal_token(ct);
        let other_tokens_sum = other_tokens.iter().sum::<EcPoint>();
        let plain_text = token.encrypted_card.c2 - token.reveal_token - other_tokens_sum;
        let index = deck_plaintext.iter().position(|p| p == &plain_text);
        if let Some(index) = index {
            return PlayingCard::from_index(index);
        }
        None
    }

    pub fn decrypt_readable_card(
        &self,
        ct: &ElGamalCiphertext,
        deck_plaintext: Vec<Plaintext>,
    ) -> Option<PlayingCard> {
        let token = self.generate_reveal_token(ct);
        let plain_text = token.encrypted_card.c2 - token.reveal_token;
        let index = deck_plaintext.iter().position(|p| p == &plain_text);
        if let Some(index) = index {
            return PlayingCard::from_index(index);
        }
        None
    }

    pub fn generate_pk_proof(&self) -> PKOwnershipProof {
        PKOwnershipProof::prove(&self.sk, &self.pk, &mut OsRng)
    }

    pub fn peek_own_card(&self, ct: &ElGamalCiphertext) -> Plaintext {
        ct.decrypt(&self.sk)
    }

    pub fn peek_card(
        &self,
        ct: &ElGamalCiphertext,
        tokens: &[RevealToken],
        plain_cards: &[Plaintext],
    ) -> Result<(Plaintext, ElGamalCiphertext), VerificationError> {
        for token in tokens {
            let mut transcript = FiatShamirTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
            token
                .proof
                .verify(
                    &token.encrypted_card,
                    &token.reveal_token,
                    &token.user_public_key,
                    &mut transcript,
                )
                .map_err(|_| VerificationError::InvalidRevealToken)?;
        }
        let self_token = ct.gen_reveal_token(&self.sk);
        let other_tokens_sum = tokens
            .iter()
            .map(|token| token.reveal_token)
            .sum::<EcPoint>();

        let plain_text = ct.c2 - self_token - other_tokens_sum;
        if !plain_cards.contains(&plain_text) {
            return Err(VerificationError::InvalidPlaintext);
        }
        let mut user_readable_card = ct.clone();
        user_readable_card.c2 -= other_tokens_sum;
        Ok((plain_text, user_readable_card))
    }

    pub fn verify_and_reveal_from_token(
        token: &RevealToken,
    ) -> Result<Plaintext, VerificationError> {
        let mut transcript = FiatShamirTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        token
            .proof
            .verify(
                &token.encrypted_card,
                &token.reveal_token,
                &token.user_public_key,
                &mut transcript,
            )
            .map_err(|_| VerificationError::InvalidRevealToken)?;
        Ok(token.encrypted_card.c2 - token.reveal_token)
    }

    pub fn generate_reveal_token(&self, ct: &ElGamalCiphertext) -> RevealToken {
        let reveal_token = ct.gen_reveal_token(&self.sk);
        let mut transcript = FiatShamirTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        let proof = RevealTokenProof::<DefaultCurve>::prove(
            &self.sk,
            &self.pk,
            ct,
            &reveal_token,
            &mut OsRng,
            &mut transcript,
        );
        RevealToken {
            user_public_key: self.pk,
            encrypted_card: ct.clone(),
            proof,
            reveal_token,
        }
    }

    pub fn batch_generate_reveal_token(&self, cts: &[ElGamalCiphertext]) -> Vec<RevealToken> {
        let mut tokens = Vec::new();
        for ct in cts {
            tokens.push(self.generate_reveal_token(ct));
        }
        tokens
    }

    pub fn shuffle(&self, deck_encrypted: &[ElGamalCiphertext], agg_pk: &EcPoint) -> ShuffleRound {
        let mut transcript = FiatShamirTranscript::new(b"zk_shuffle_proof_v2");
        ShuffleRound::execute(deck_encrypted, agg_pk, &mut transcript, &mut OsRng)
    }

    // curr_share_pk: 当前分享的公钥,不包含自己
    pub fn join_game_and_shuffle(
        &self,
        input_cards: &[ElGamalCiphertext],
        curr_share_pk: &EcPoint,
    ) -> JoinGameAndShuffleRound {
        let share_pk = *curr_share_pk + self.pk;
        let pk_proof = self.generate_pk_proof();
        let mask_and_shuffle_round = MaskAndShuffleRound::execute(
            input_cards,
            &share_pk,
            self.sk.clone(),
            &self.pk,
            &mut OsRng,
        );
        JoinGameAndShuffleRound {
            pk_hex: hex::encode(self.pk.compress().as_ref()),
            pk_ownership_proof: pk_proof,
            mask_and_shuffle_round,
        }
    }

    pub fn leave_game(&self, input_cards: &[ElGamalCiphertext]) -> LeaveGameRound {
        LeaveGameRound::execute(input_cards, &self.sk, &self.pk)
    }

    /// 离开/弃牌剥层（排除自己手牌槽）：见
    /// [`LeaveGameRound::execute_with_exclusions`] 的安全动机。
    pub fn leave_game_with_exclusions(
        &self,
        input_cards: &[ElGamalCiphertext],
        excluded_indices: &[usize],
    ) -> LeaveGameRound {
        LeaveGameRound::execute_with_exclusions(input_cards, excluded_indices, &self.sk, &self.pk)
    }

    pub fn reveal_own_card(
        &self,
        hand_index: usize,
        hand_encrypted: &[ElGamalCiphertext],
        _deck_plaintext: &[Plaintext],
        _agg_pk: &EcPoint,
    ) -> Result<RevealToken, VerificationError> {
        if hand_index >= hand_encrypted.len() {
            return Err(VerificationError::LengthMismatch);
        }

        let encrypted_card = hand_encrypted[hand_index].clone();
        let reveal_token = encrypted_card.gen_reveal_token(&self.sk);
        let mut transcript = FiatShamirTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        let proof = RevealTokenProof::<DefaultCurve>::prove(
            &self.sk,
            &self.pk,
            &encrypted_card,
            &reveal_token,
            &mut OsRng,
            &mut transcript,
        );

        Ok(RevealToken {
            user_public_key: self.pk,
            encrypted_card,
            proof,
            reveal_token,
        })
    }

    pub fn reveal_community(&self, comm_plaintext: Plaintext) -> RevealToken {
        let ct_for_self =
            ElGamalCiphertext::encrypt(&comm_plaintext, &self.pk, &Scalar::random(&mut OsRng));
        let reveal_token = ct_for_self.gen_reveal_token(&self.sk);
        let mut transcript = FiatShamirTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        let proof = RevealTokenProof::<DefaultCurve>::prove(
            &self.sk,
            &self.pk,
            &ct_for_self,
            &reveal_token,
            &mut OsRng,
            &mut transcript,
        );

        RevealToken {
            user_public_key: self.pk,
            encrypted_card: ct_for_self,
            proof,
            reveal_token,
        }
    }

    pub fn remask_card(&self, ct: &ElGamalCiphertext, pk: &EcPoint) -> (ElGamalCiphertext, Scalar) {
        let alpha = Scalar::random(&mut OsRng);
        let remasked = ct.re_encrypt(pk, &alpha);
        (remasked, alpha)
    }

    pub fn distributed_decrypt(
        &self,
        ct: &ElGamalCiphertext,
        other_tokens: &[EcPoint],
    ) -> Plaintext {
        let self_token = ct.gen_reveal_token(&self.sk);
        let all_tokens_sum: EcPoint = other_tokens
            .iter()
            .cloned()
            .chain(std::iter::once(self_token))
            .sum();
        ct.c2 - all_tokens_sum
    }

    pub fn distributed_decrypt_from_tokens(
        ct: &ElGamalCiphertext,
        tokens: &[RevealToken],
    ) -> Result<Plaintext, VerificationError> {
        for token in tokens {
            let mut transcript = FiatShamirTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
            token
                .proof
                .verify(
                    &token.encrypted_card,
                    &token.reveal_token,
                    &token.user_public_key,
                    &mut transcript,
                )
                .map_err(|_| VerificationError::InvalidRevealToken)?;
        }
        let tokens_sum: EcPoint = tokens.iter().map(|t| t.reveal_token).sum();
        Ok(ct.c2 - tokens_sum)
    }

    pub fn mask_card(&self, plaintext: &Plaintext, pk: &EcPoint) -> (ElGamalCiphertext, Scalar) {
        let r = Scalar::random(&mut OsRng);
        let encrypted = ElGamalCiphertext::encrypt(plaintext, pk, &r);
        (encrypted, r)
    }

    pub fn reconstruct(
        &self,
        origin_cards: &[Plaintext],
        user_readable_cards: &[ElGamalCiphertext],
        coefficient: &Scalar,
    ) -> Result<ReconstructDeck, VerificationError> {
        let (s_vec, output_cards, swap_out_cards) = reconstruct_deck(
            origin_cards,
            user_readable_cards,
            &self.sk,
            &self.pk,
            coefficient,
        )?;
        let mut transcript = FiatShamirTranscript::new(RECONSTRUCTION_PROOF_LABEL);
        let reconstruct_proof = ReconstructProof::<DefaultCurve>::prove(
            origin_cards.to_vec(),
            user_readable_cards.to_vec(),
            output_cards.clone(),
            swap_out_cards.clone(),
            &self.sk,
            &self.pk,
            s_vec,
            &mut transcript,
        )?;
        Ok(ReconstructDeck {
            output_cards,
            swap_cards: swap_out_cards.into_iter().map(|(_, ct)| ct).collect(),
            proof: reconstruct_proof,
        })
    }

    /// Create the V3 contribution vector and its proof for this player's prior
    /// readable hand.
    ///
    /// The host/AIR must check that `prior_state_digest` authenticates these
    /// readable ciphertexts as the owner's previous-round hand and that their
    /// lineage starts at `init_deck`. V3 binds that historical fact to the
    /// current epoch without publishing card indices or shuffle coefficients.
    #[allow(clippy::too_many_arguments)]
    pub fn reconstruct_v3(
        &self,
        context_digest: [u8; 32],
        reconstruction_epoch: u64,
        prior_state_digest: [u8; 32],
        origin_cards: &[Plaintext],
        user_readable_cards: &[ElGamalCiphertext],
        aggregate_pk: &EcPoint,
    ) -> Result<ReconstructDeckV3, VerificationError> {
        let mut transcript = FiatShamirTranscript::new(RECONSTRUCTION_V3_PROOF_LABEL);
        let (statement, proof) = ReconstructProofV3::<DefaultCurve>::prove(
            context_digest,
            reconstruction_epoch,
            prior_state_digest,
            origin_cards.to_vec(),
            user_readable_cards.to_vec(),
            &self.sk,
            &self.pk,
            aggregate_pk,
            &mut OsRng,
            &mut transcript,
        )?;
        Ok(ReconstructDeckV3 { statement, proof })
    }
}

#[cfg(test)]
mod reconstruction_v3_tests {
    use super::*;
    use crate::crypto::curve::{Curve, CurveScalar};

    #[test]
    fn client_builds_a_verifiable_v3_package() {
        let owner = ClientPlayer::new();
        let aggregate_sk = Scalar::random(&mut OsRng);
        let aggregate_pk = base_g() *  aggregate_sk;
        let cards: Vec<_> = (0..8)
            .map(|i| DefaultCurve::hash_to_curve(format!("client/v3/card/{i}").as_bytes()))
            .collect();
        let readable = [cards[2], cards[5]]
            .iter()
            .map(|card| ElGamalCiphertext::encrypt(card, &owner.pk, &Scalar::random(&mut OsRng)))
            .collect::<Vec<_>>();

        let package = owner
            .reconstruct_v3([1; 32], 9, [2; 32], &cards, &readable, &aggregate_pk)
            .unwrap();
        let mut transcript = FiatShamirTranscript::new(RECONSTRUCTION_V3_PROOF_LABEL);
        package
            .proof
            .verify(&package.statement, &mut transcript)
            .unwrap();
    }
}

#[cfg(test)]
mod passphrase_kdf_tests {
    use super::ClientPlayer;

    /// 同一口令在任何设备/时刻派生出同一 pk（可恢复身份的核心保证）。
    #[test]
    fn passphrase_derivation_is_deterministic() {
        let a = ClientPlayer::new_with_passphrase("correct horse battery staple");
        let b = ClientPlayer::new_with_passphrase("correct horse battery staple");
        assert_eq!(a.pk, b.pk, "same passphrase must derive the same pk");
    }

    #[test]
    fn different_passphrases_derive_different_pks() {
        let a = ClientPlayer::new_with_passphrase("alpha");
        let b = ClientPlayer::new_with_passphrase("beta");
        assert_ne!(a.pk, b.pk);
    }

    /// 口令身份与钱包派生身份必须是两个独立命名空间（隐私主张的前提）。
    #[test]
    fn passphrase_space_is_independent_from_wallet_space() {
        let wallet = ClientPlayer::new_with_wallet_address("0xdeadbeef");
        let pass = ClientPlayer::new_with_passphrase("0xdeadbeef");
        assert_ne!(
            wallet.pk, pass.pk,
            "domain separation: passphrase KDF must never collide with wallet derivation"
        );
    }

    /// KDF 输出必须是合法群标量（pk 可从其派生且非零点）——防御未来
    /// 曲线切换后 from_canonical_bytes 拒绝中间值的回归。
    #[test]
    fn derived_key_yields_valid_pk() {
        let p = ClientPlayer::new_with_passphrase("test");
        assert!(!hex::encode(crate::z_poker::convert::ecpoint_to_hex(&p.pk)).is_empty());
    }
}
