mod client;
mod expel;
mod game;
mod game_action;
mod rounds;
mod types;

// Re-export all public items so the public API remains unchanged
pub use client::ClientPlayer;
pub use expel::{ExpelRecord, ExpelSessionPhase, ExpelStateResponse, ExpelSummary};
pub use game_action::{sign_game_action, verify_game_action_hex, action_msg_bytes};
pub use game::MentalPokerGame;
pub use rounds::{JoinGameAndShuffleRound, LeaveGameRound, MaskAndShuffleRound, ShuffleRound};
pub use types::{
    DealResult, GameConfig, GamePhase, PlayerEncryptedCard, PlayerState, ReconstructDeck,
    ReconstructDeckV3, RevealState, RevealToken, RevealTokenSimple,
};

// Re-export new_plain_text for external use (e.g., testnet verify tests)
pub use game::new_plain_text;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::curve::{Curve, CurvePoint, CurveScalar};
    use crate::crypto::{DefaultCurve, EcPoint, ElGamalCiphertext, Scalar, BASE_G, N_CARDS};
    use crate::zk_shuffle::reveal_token_proof::RevealTokenProof;
    use crate::zk_shuffle::reveal_token_proof::{
        ExpelHandState, RevealTokenAndProof, REVEAL_TOKEN_PROOF_LABEL,
    };
    use crate::zk_shuffle::transcript_ext::{
        CryptoTranscript, FiatShamirTranscript, MerlinTranscript,
    };
    use rand_core::OsRng;

    fn create_test_player() -> ClientPlayer {
        ClientPlayer::new()
    }

    fn create_test_expel_hand_state(
        player: &ClientPlayer,
        agg_pk: &EcPoint,
        card_indices: &[usize],
    ) -> Vec<ExpelHandState<DefaultCurve>> {
        card_indices
            .iter()
            .map(|&idx| {
                let pt = new_plain_text()[idx];
                let r = Scalar::random(&mut OsRng);
                let encrypted_card = ElGamalCiphertext::encrypt(&pt, agg_pk, &r);

                let reveal_token = encrypted_card.gen_reveal_token(&player.sk);
                let mut transcript = MerlinTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
                let proof = RevealTokenProof::<DefaultCurve>::prove(
                    &player.sk,
                    &player.pk,
                    &encrypted_card,
                    &reveal_token,
                    &mut OsRng,
                    &mut transcript,
                );

                let token_and_proof = RevealTokenAndProof::<DefaultCurve> {
                    reveal_token,
                    proof,
                };

                ExpelHandState::<DefaultCurve> {
                    hand_encrypted: encrypted_card,
                    reveal_tokens: vec![token_and_proof],
                }
            })
            .collect()
    }

    #[test]
    fn test_reveal_token_generation_and_verification() {
        let player = create_test_player();
        let agg_pk = player.pk;

        let pt = new_plain_text()[0];
        let r = Scalar::random(&mut OsRng);
        let encrypted_card = ElGamalCiphertext::encrypt(&pt, &agg_pk, &r);

        let reveal_token = encrypted_card.gen_reveal_token(&player.sk);
        let mut transcript = MerlinTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        let proof = RevealTokenProof::<DefaultCurve>::prove(
            &player.sk,
            &player.pk,
            &encrypted_card,
            &reveal_token,
            &mut OsRng,
            &mut transcript,
        );

        let mut transcript = MerlinTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        let verify_result =
            proof.verify(&encrypted_card, &reveal_token, &player.pk, &mut transcript);
        assert!(
            verify_result.is_ok(),
            "Proof should verify: {:?}",
            verify_result
        );

        let decrypted = encrypted_card.c2 - reveal_token;
        assert_eq!(decrypted, pt, "Should decrypt to original plaintext");
    }

    // ========== ShuffleRound tests ==========

    /// Helper: 生成 N_CARDS 张加密牌（无 placeholder）
    fn make_full_encrypted_cards(pk: &EcPoint) -> Vec<ElGamalCiphertext> {
        new_plain_text()
            .iter()
            .map(|pt| ElGamalCiphertext::encrypt(pt, pk, &Scalar::random(&mut OsRng)))
            .collect()
    }

    /// Helper: 比较两个 EcPoint 集合是否包含相同的点（不考虑顺序）
    fn assert_same_point_set(a: &[EcPoint], b: &[EcPoint]) {
        let mut a_compressed: Vec<_> = a.iter().map(|p| p.compress().as_ref().to_vec()).collect();
        let mut b_compressed: Vec<_> = b.iter().map(|p| p.compress().as_ref().to_vec()).collect();
        a_compressed.sort();
        b_compressed.sort();
        assert_eq!(a_compressed, b_compressed);
    }

    #[test]
    fn test_shuffle_round_execute_and_verify() {
        let sk = Scalar::random(&mut OsRng);
        let pk = *BASE_G * sk;
        let input = make_full_encrypted_cards(&pk);

        let mut transcript = MerlinTranscript::new(b"test_shuffle_round");
        let round = ShuffleRound::execute(&input, &pk, &mut transcript, &mut OsRng);

        // verify 应通过
        let mut transcript = MerlinTranscript::new(b"test_shuffle_round");
        assert!(
            round.verify(&pk, &mut transcript),
            "honest shuffle round should verify"
        );

        // output 牌数应等于 input
        assert_eq!(round.output_cards.len(), crate::crypto::N_CARDS);
        assert_eq!(round.input_cards.len(), crate::crypto::N_CARDS);

        // output 应是 input 的重加密+排列，解密后明文集合应相同
        let input_pts: Vec<EcPoint> = input.iter().map(|ct| ct.decrypt(&sk)).collect();
        let output_pts: Vec<EcPoint> = round
            .output_cards
            .iter()
            .map(|ct| ct.decrypt(&sk))
            .collect();
        assert_same_point_set(&input_pts, &output_pts);
    }

    #[test]
    fn test_shuffle_round_wrong_pk_fails() {
        let sk = Scalar::random(&mut OsRng);
        let pk = *BASE_G * sk;
        let input = make_full_encrypted_cards(&pk);

        let mut transcript = MerlinTranscript::new(b"test_shuffle_round_wrong_pk");
        let round = ShuffleRound::execute(&input, &pk, &mut transcript, &mut OsRng);

        let wrong_sk = Scalar::random(&mut OsRng);
        let wrong_pk = *BASE_G * wrong_sk;
        let mut transcript = MerlinTranscript::new(b"test_shuffle_round_wrong_pk");
        assert!(
            !round.verify(&wrong_pk, &mut transcript),
            "verify with wrong pk should fail"
        );
    }

    #[test]
    fn test_shuffle_round_tampered_output_fails() {
        let sk = Scalar::random(&mut OsRng);
        let pk = *BASE_G * sk;
        let input = make_full_encrypted_cards(&pk);

        let mut transcript = MerlinTranscript::new(b"test_shuffle_round_tampered");
        let mut round = ShuffleRound::execute(&input, &pk, &mut transcript, &mut OsRng);

        // 篡改 output[0]
        round.output_cards[0] = round.output_cards[0].re_encrypt(&pk, &Scalar::random(&mut OsRng));
        let mut transcript = MerlinTranscript::new(b"test_shuffle_round_tampered");
        assert!(
            !round.verify(&pk, &mut transcript),
            "tampered output should fail verify"
        );
    }

    #[test]
    fn test_shuffle_round_tampered_input_fails() {
        let sk = Scalar::random(&mut OsRng);
        let pk = *BASE_G * sk;
        let input = make_full_encrypted_cards(&pk);

        let mut transcript = MerlinTranscript::new(b"test_shuffle_round_tampered_input");
        let round = ShuffleRound::execute(&input, &pk, &mut transcript, &mut OsRng);

        // 篡改 input[1]
        let mut tampered_input = input.clone();
        tampered_input[1] = ElGamalCiphertext::encrypt(
            &(*BASE_G * Scalar::from_u64(99u64)),
            &pk,
            &Scalar::random(&mut OsRng),
        );
        let tampered_round = ShuffleRound {
            input_cards: tampered_input,
            output_cards: round.output_cards.clone(),
            proof: round.proof,
        };
        let mut transcript = MerlinTranscript::new(b"test_shuffle_round_tampered_input");
        assert!(
            !tampered_round.verify(&pk, &mut transcript),
            "tampered input should fail verify"
        );
    }

    #[test]
    fn test_shuffle_round_deterministic_permutation() {
        // 多次 execute 应产生不同排列（概率极高）
        let sk = Scalar::random(&mut OsRng);
        let pk = *BASE_G * sk;
        let input = make_full_encrypted_cards(&pk);

        let mut transcript1 = MerlinTranscript::new(b"test_shuffle_round_det1");
        let round1 = ShuffleRound::execute(&input, &pk, &mut transcript1, &mut OsRng);
        let mut transcript2 = MerlinTranscript::new(b"test_shuffle_round_det2");
        let round2 = ShuffleRound::execute(&input, &pk, &mut transcript2, &mut OsRng);

        // 两次 output 的 c1 不应完全相同（随机排列+随机重加密）
        let same = round1
            .output_cards
            .iter()
            .zip(round2.output_cards.iter())
            .all(|(a, b)| a.c1 == b.c1);
        assert!(
            !same,
            "two shuffles should produce different outputs with overwhelming probability"
        );
    }

    #[test]
    fn test_mask_and_shuffle_round_execute_and_verify() {
        let player_sk = Scalar::random(&mut OsRng);
        let player_pk = *BASE_G * player_sk;
        let agg_sk = Scalar::random(&mut OsRng);
        let agg_pk = *BASE_G * agg_sk;
        let share_pk = agg_pk + player_pk;

        let input = make_full_encrypted_cards(&share_pk);
        let round =
            MaskAndShuffleRound::execute(&input, &share_pk, player_sk, &player_pk, &mut OsRng);

        // 验证时需要按与 prove 相同的顺序重建 transcript 状态：
        // 1. 先验证 remask_proof（吸收 remask 数据到 transcript）
        // 2. 再验证 shuffle_proof（在 remask 数据之后继续吸收 shuffle 数据）

        // 兼容 Move 合约：验证时使用与 prove 相同的 FiatShamirTranscript 和协议名
        // remask proof 应通过
        let mut transcript = FiatShamirTranscript::new(b"zk_mask_shuffle_proof_v2");
        assert!(
            round
                .remask_proof
                .verify(&input, &round.mask_cards, &player_pk, &mut transcript),
            "remask proof should verify"
        );

        // shuffle proof 应通过（使用同一个 transcript，状态已包含 remask 数据）
        assert!(
            round
                .proof
                .verify(
                    &round.mask_cards,
                    &round.output_cards,
                    &share_pk,
                    &mut transcript,
                )
                .is_ok(),
            "shuffle proof should verify"
        );

        // output 牌数应等于 input
        assert_eq!(round.output_cards.len(), crate::crypto::N_CARDS);
        assert_eq!(round.mask_cards.len(), crate::crypto::N_CARDS);
    }

    #[test]
    fn test_new_plain_text() {
        let plain_text = new_plain_text();
        println!("{:?}", plain_text);
    }
}
