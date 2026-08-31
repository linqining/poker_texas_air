//! Starknet 接入端到端测试（cargo test -p texas e2e_starknet）。
//!
//! 方案A（MIRROR_UNIFICATION_PLAN.md）对拍基线：
//! 1. 以**游戏层真实流程**构造牌局——两个客户端用 zgame poker_protocol
//!    （与前端 wasm 同源代码）执行 join_game_and_shuffle，deck 链由客户端洗牌驱动；
//! 2. 游戏层发完底牌后（deck 终局），把 deck **原样注入** mirror VM
//!    （`begin_reveal_hand`），断言 deck 逐字节一致；
//! 3. 客户端对游戏层密文生成的 reveal token（含摊牌阶段对**完整密文**的证明）
//!    必须被 VM 的 reveal 窗口逐个接受（DealHole / Board / ShowdownOwner）；
//! 4. 下注推进到 river（board == 5）→ 结算（derive_settlement_plan）→
//!    证明（Orchestrator + outer aggregate）→ Starknet calldata
//!    （register_aggregate / settle_hand）。
//!
//! 洗牌在 VM 中不再重放（方案A：deck 同源注入），因此证明链由
//! reveal-token 任务构成——这正是玩家实际参与的那副牌。

use poker_l1::signature::TaggedPubkey;
use poker_protocol::crypto::{DefaultCurve};
use poker_protocol::crypto::curve::{Curve, CurveScalar};
use poker_protocol::zk_shuffle::transcript_ext::CryptoTranscript as _CT;
use rand::rngs::OsRng;

use super::mirror::TableMirror;
use poker_protocol::z_poker::protocol::{ClientPlayer, MentalPokerGame};

type ZgCt = poker_protocol::crypto::ElGamalCiphertext;

/// 模拟游戏层两名客户端 join_game_and_shuffle 入座（服务器验证语义与
/// `Table::join_player_and_shuffle` 一致：proof verify → register → deck := output）。
fn game_layer_join(
    game: &mut MentalPokerGame,
    player: &ClientPlayer,
) {
    let agg_prev = game.key_manager.get_aggregated_pk();
    let round = player.join_game_and_shuffle(&game.deck_encrypted, &agg_prev);
    let ms = &round.mask_and_shuffle_round;
    // 服务器侧验证（与 join_player_and_shuffle 相同的两步证明校验）
    let mut transcript = poker_protocol::zk_shuffle::transcript_ext::FiatShamirTranscript::new(
        b"zk_mask_shuffle_proof_v2",
    );
    let input_cards: Vec<ZgCt> = game.deck_encrypted.clone();
    assert!(
        ms.remask_proof.verify(
            &input_cards,
            &ms.mask_cards,
            &player.pk,
            &mut transcript,
        ),
        "remask proof must verify"
    );
    let share_pk = agg_prev + player.pk;
    assert!(
        ms.proof.verify(
            &ms.mask_cards,
            &ms.output_cards,
            &share_pk,
            &mut transcript,
        )
        .is_ok(),
        "join shuffle proof must verify"
    );
    game.register_player(hex_pk(&player.pk), player.pk, round.pk_ownership_proof);
    game.deck_encrypted = ms.output_cards.clone();
}

/// 完整链路测试：游戏层 join×2 → 发底牌 → deck 注入 mirror →
/// reveal ×(DealHole/Board/Showdown) → 下注 → 结算 → calldata。
/// 牌力完全平分（awards==total_bets）时换随机密钥重打，最多 20 次。
#[test]
fn e2e_starknet_buyin_play_settle_calldata() {
    for attempt in 0..20 {
        match play_full_hand() {
            Ok(()) => {
                eprintln!("[attempt {attempt}] full hand settled + calldata OK");
                return;
            }
            Err(e) if e.contains("split pot") => {
                eprintln!("[attempt {attempt}] split pot, retrying");
            }
            Err(e) => panic!("hand play failed: {e}"),
        }
    }
    panic!("all 20 attempts produced split pots");
}

fn play_full_hand() -> Result<(), String> {
    let creator: poker_l1::Address = [0xC0; 20];
    let p1: poker_l1::Address = [0x11; 20];
    let p2: poker_l1::Address = [0x22; 20];

    // 客户端（真实 scalar 密钥，与 wasm ClientPlayer 同一代码）。
    let sk1 = <DefaultCurve as Curve>::Scalar::random(&mut OsRng);
    let sk2 = <DefaultCurve as Curve>::Scalar::random(&mut OsRng);
    let client1 = ClientPlayer { sk: sk1.clone(), pk: <DefaultCurve as Curve>::base_g() * &sk1 };
    let client2 = ClientPlayer { sk: sk2.clone(), pk: <DefaultCurve as Curve>::base_g() * &sk2 };

    // ---- 游戏层：两名客户端先后 join_game_and_shuffle（deck 由客户端驱动）----
    let mut game = MentalPokerGame::new(poker_protocol::z_poker::GameConfig {
        num_players: 2,
        cards_per_player: 2,
        community_cards: 5,
    });
    game_layer_join(&mut game, &client1);
    game_layer_join(&mut game, &client2);

    // ---- 游戏层发底牌（升序座位 ×2，对齐 deal_preflop 的 VM 规范顺序）----
    let pk_hex1 = hex_pk(&client1.pk);
    let pk_hex2 = hex_pk(&client2.pk);
    for _ in 0..2 {
        game.deal_to_player(&pk_hex1, 1).map_err(|e| format!("deal p1: {e:?}"))?;
        game.deal_to_player(&pk_hex2, 1).map_err(|e| format!("deal p2: {e:?}"))?;
    }
    // 此刻 deck 终局（后续 street 不再改写整副 deck）
    let game_deck: Vec<ZgCt> = game.deck_encrypted.clone();

    // ---- 方案A：deck 原样注入全新 mirror VM，VM 直接进入 DealHole ----
    use poker_l1::vm::contracts::texas_poker::utils::create_pk_ownership_proof;
    let zpk1 = super::mirror::conv::ec_point(&poker_protocol::crypto::types::ECPoint(client1.pk)).unwrap();
    let zpk2 = super::mirror::conv::ec_point(&poker_protocol::crypto::types::ECPoint(client2.pk)).unwrap();
    let proof1 = create_pk_ownership_proof(&sk1, &<DefaultCurve as Curve>::Scalar::random(&mut OsRng))
        .expect("proof p1");
    let proof2 = create_pk_ownership_proof(&sk2, &<DefaultCurve as Curve>::Scalar::random(&mut OsRng))
        .expect("proof p2");
    let plan = vec![
        (p1, 1000u64, zpk1, proof1),
        (p2, 1000u64, zpk2, proof2),
    ];
    let mut mirror = TableMirror::new(1, "e2e", creator, 4, 10, 20, creator);
    mirror
        .begin_reveal_hand(
            super::mirror::conv::ciphertexts(&game_deck).expect("deck bridge"),
            &plan,
            0,
            7,
        )
        .map_err(|e| format!("begin_reveal_hand: {e}"))?;

    // 对拍断言（B0 核心）：注入后 mirror deck 与游戏层 deck 逐字节一致。
    assert_eq!(
        mirror.deck(),
        super::mirror::conv::ciphertexts(&game_deck).unwrap(),
        "mirror deck must byte-match the game deck after injection"
    );

    // ---- reveal / betting 交替推进到 river ----
    // 客户端语义：每个玩家对"待揭示密文"生成 token = sk·c1 + Schnorr 证明
    // （证明绑定完整密文——包括摊牌阶段，与真实客户端一致）。
    use poker_protocol::zk_shuffle::transcript_ext::FiatShamirTranscript as FsT;
    use poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof as ZgRevealProof;

    let clients: [&ClientPlayer; 2] = [&client1, &client2];
    for _step in 0..64 {
        if mirror.table.reveal_token_state().is_some() {
            // pending 座位中编号最小者提交其全部 pending assignments（canonical 顺序）
            let reveal_state = mirror.table.reveal_token_state().unwrap();
            let min_pending_seat = reveal_state.assignments.iter()
                .filter(|a| !a.is_ready())
                .filter_map(|a| (0u8..2).find(|s| a.pending_mask() & (1u16 << s) != 0))
                .min();
            let Some(seat) = min_pending_seat else { break };
            let client = clients[seat as usize];
            // canonical 目标密文（showdown 为 ledger 保存的完整密文）
            let targets = mirror
                .pending_reveal_ciphertexts(seat)
                .map_err(|e| format!("pending targets: {e}"))?;
            let mut tokens = Vec::new();
            let mut proofs = Vec::new();
            for target in &targets {
                let ct = super::mirror::conv::ciphertexts(std::slice::from_ref(
                    &poker_protocol::crypto::ElGamalCiphertext { c1: target.c1, c2: target.c2 },
                ))
                .expect("ct bridge")
                .remove(0);
                let token = ct.gen_reveal_token(&client.sk);
                let proof = ZgRevealProof::prove(
                    &client.sk, &client.pk, &ct, &token, &mut OsRng,
                    &mut FsT::new(b"reveal_token_proof_v3"),
                );
                tokens.push(super::mirror::conv::ec_point(&poker_protocol::crypto::types::ECPoint(token)).unwrap());
                proofs.push(super::mirror::conv::reveal_token_proof(&proof).unwrap());
            }
            mirror
                .submit_reveal_tokens(seat, tokens, proofs)
                .map_err(|e| format!("seat {seat} reveal submit failed: {e}"))?;
            continue;
        }
        if let Some(actor) = mirror.table.current_turn_option() {
            let other = 1u8 - actor;
            let facing_bet = mirror.table.seats[actor as usize].total_bet()
                < mirror.table.seats[other as usize].total_bet();
            if facing_bet {
                mirror.call(actor).map_err(|e| format!("call: {e}"))?;
            } else {
                mirror.check(actor).map_err(|e| format!("check: {e}"))?;
            }
            continue;
        }
        // 既无 reveal 也无下注轮：若已到河牌则结束
        if mirror.table.community_cards.to_vec().len() == 5 {
            break;
        }
        panic!("stuck: no reveal, no betting turn, board {} cards",
            mirror.table.community_cards.to_vec().len());
    }

    assert_eq!(mirror.table.community_cards.to_vec().len(), 5, "board should reach river");
    assert!(
        mirror.has_provable_activity(),
        "reveal tasks must form the provable activity of this hand"
    );

    // 平分检测（须在派奖前：派奖后 board 复位无法 derive）
    let plan_check = poker_l1::vm::contracts::texas_poker::settlement::derive_settlement_plan(&mirror.table)
        .map_err(|e| format!("plan: {e}"))?;
    let all_zero_delta = mirror.table.seats.iter().enumerate().all(|(i, s)| {
        plan_check.awards.get(i).copied().unwrap_or(0) as i128 == s.total_bet() as i128
    });
    if all_zero_delta {
        return Err("split pot".into());
    }

    // 派奖前打快照（board/pot/total_bet 完整），供 SettleHandCalldata 使用
    mirror.mark_pre_settlement();

    // showdown 展示期后由 advance_deadline 驱动派奖归一化（对齐 zgame tick）
    std::thread::sleep(std::time::Duration::from_secs(4));
    mirror.advance_deadline().map_err(|e| format!("advance: {e}"))?;

    // ---- 结算：分池 + 证明 + calldata ----
    let settlement = super::submit::settle_hand(&mirror, Some(creator))
        .map_err(|e| format!("settlement: {e}"))?;

    assert_eq!(settlement.hand_id, 7, "hand_id must come from the injected counter");
    assert!(!settlement.register_calldata.is_empty());
    assert!(!settlement.settle_calldata.is_empty());
    assert!(settlement.settle_calldata.len() >= 6);
    assert_ne!(settlement.aggregate_digest, [0u8; 32]);

    // ---- Hand-batch（PokerDualSettlement）：hand_binding + hand-bound 认可批次 ----
    // P2.1 后服务器不持有认可密钥：测试在 host 侧生成密钥并铸造（角色
    // 等价于客户端 wasm endorsement_mint），再走客户端构建路径。
    let binding = super::dual_settle::prepare_handbatch_binding(&mirror, &settlement)?;
    let endorsements: Vec<super::dual_settle::ClientEndorsement> = settlement
        .players_remapped
        .iter()
        .map(|_p| {
            let sk = <super::dual_settle::Sc as CurveScalar>::random(&mut rand::rngs::OsRng);
            let pk = <poker_protocol::crypto::curve::StarkCurve as Curve>::base_g() * sk;
            let e = super::dual_settle::mint_endorsement(&sk, &pk, &binding.hand_id_bytes);
            super::dual_settle::ClientEndorsement { pk: e.pk, r: e.r, s: e.s }
        })
        .collect();
    let dual = super::dual_settle::build_dual_settlement_from_client(&mirror, &settlement, &endorsements)
        .map_err(|e| format!("dapv build: {e}"))?;
    assert_ne!(dual.hand_binding, starknet_ff::FieldElement::ZERO);
    assert_eq!(dual.batch_words.len(), 5 + 5 * settlement.players_remapped.len());
    assert_eq!(dual.register_calldata.len(), 6);
    let expect_len = 1 + 1 + 32 + 1
        + 1 + settlement.players_remapped.len()
        + 1 + settlement.deltas.len()
        + 1 + dual.batch_words.len();
    assert_eq!(dual.settle_calldata.len(), expect_len);
    assert_ne!(dual.proved.p_batch_commitment, starknet_ff::FieldElement::ZERO);
    assert_eq!(dual.proved.register_calldata.len(), 8);
    assert_eq!(
        dual.proved.settle_calldata.len(),
        expect_len - (1 + dual.batch_words.len()) + 2
    );

    // 宿主折叠 parity（链上 fold_and_check 的同构镜像）
    let hb_bytes = dual.hand_binding.to_bytes_be();
    let terms =
        super::dual_settle::parse_batch_terms(&hb_bytes, &dual.batch_words)
            .expect("parse honest batch");
    assert!(
        super::dual_settle::host_fold_is_identity(&hb_bytes, &terms),
        "honest batch must fold to L == O"
    );
    let mut wrong = hb_bytes;
    wrong[0] ^= 1;
    let wrong_terms = super::dual_settle::parse_batch_terms(&wrong, &dual.batch_words)
        .expect("parse under replayed domain");
    assert!(
        !super::dual_settle::host_fold_is_identity(&wrong, &wrong_terms),
        "cross-hand replay must fold to non-zero L"
    );
    Ok(())
}

fn hex_pk(pk: &poker_protocol::crypto::EcPoint) -> String {
    poker_protocol::z_poker::convert::ecpoint_to_hex(pk)
}

/// 注入前缀对拍：join×2 → 发底牌 → deck 注入 → 翻牌前 hole reveal 全部通过 →
/// 下注轮开启；全程断言 mirror deck 与游戏层 deck 逐字节一致。
#[test]
fn e2e_starknet_prefix_join_inject_reveal_betting() {
    let creator: poker_l1::Address = [0xC0; 20];
    let p1: poker_l1::Address = [0x11; 20];
    let p2: poker_l1::Address = [0x22; 20];
    let sk1 = <DefaultCurve as Curve>::Scalar::random(&mut OsRng);
    let sk2 = <DefaultCurve as Curve>::Scalar::random(&mut OsRng);
    let client1 = ClientPlayer { sk: sk1.clone(), pk: <DefaultCurve as Curve>::base_g() * &sk1 };
    let client2 = ClientPlayer { sk: sk2.clone(), pk: <DefaultCurve as Curve>::base_g() * &sk2 };

    let mut game = MentalPokerGame::new(poker_protocol::z_poker::GameConfig {
        num_players: 2,
        cards_per_player: 2,
        community_cards: 5,
    });
    game_layer_join(&mut game, &client1);
    game_layer_join(&mut game, &client2);
    let pk_hex1 = hex_pk(&client1.pk);
    let pk_hex2 = hex_pk(&client2.pk);
    for _ in 0..2 {
        game.deal_to_player(&pk_hex1, 1).expect("deal p1");
        game.deal_to_player(&pk_hex2, 1).expect("deal p2");
    }
    let game_deck: Vec<ZgCt> = game.deck_encrypted.clone();

    use poker_l1::vm::contracts::texas_poker::utils::create_pk_ownership_proof;
    let zpk1 = super::mirror::conv::ec_point(&poker_protocol::crypto::types::ECPoint(client1.pk)).unwrap();
    let zpk2 = super::mirror::conv::ec_point(&poker_protocol::crypto::types::ECPoint(client2.pk)).unwrap();
    let proof1 = create_pk_ownership_proof(&sk1, &<DefaultCurve as Curve>::Scalar::random(&mut OsRng)).unwrap();
    let proof2 = create_pk_ownership_proof(&sk2, &<DefaultCurve as Curve>::Scalar::random(&mut OsRng)).unwrap();
    let plan = vec![(p1, 1000u64, zpk1, proof1), (p2, 1000u64, zpk2, proof2)];
    let mut mirror = TableMirror::new(1, "e2e-prefix", creator, 4, 10, 20, creator);
    mirror
        .begin_reveal_hand(super::mirror::conv::ciphertexts(&game_deck).unwrap(), &plan, 0, 1)
        .expect("inject");

    assert_eq!(
        mirror.deck(),
        super::mirror::conv::ciphertexts(&game_deck).unwrap(),
        "deck parity after injection"
    );

    // hole reveal ×2（客户端 token 基于游戏层密文生成）
    use poker_protocol::zk_shuffle::transcript_ext::FiatShamirTranscript as FsT;
    use poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof as ZgRevealProof;
    let clients: [&ClientPlayer; 2] = [&client1, &client2];
    loop {
        let Some(rs) = mirror.table.reveal_token_state() else { break };
        let Some(seat) = rs.assignments.iter().filter(|a| !a.is_ready())
            .filter_map(|a| (0u8..2).find(|s| a.pending_mask() & (1u16 << s) != 0))
            .min() else { break };
        let client = clients[seat as usize];
        let targets = mirror.pending_reveal_ciphertexts(seat).expect("targets");
        let mut tokens = Vec::new();
        let mut proofs = Vec::new();
        for target in &targets {
            let ct = poker_protocol::crypto::ElGamalCiphertext { c1: target.c1, c2: target.c2 };
            let token = ct.gen_reveal_token(&client.sk);
            tokens.push(super::mirror::conv::ec_point(&poker_protocol::crypto::types::ECPoint(token)).unwrap());
            proofs.push(super::mirror::conv::reveal_token_proof(
                &ZgRevealProof::prove(&client.sk, &client.pk, &ct, &token, &mut OsRng,
                    &mut FsT::new(b"reveal_token_proof_v3"))).unwrap());
        }
        mirror.submit_reveal_tokens(seat, tokens, proofs).expect("hole reveal");
    }
    assert!(mirror.table.current_turn_option().is_some(), "betting round should start");
}

// ============================================================
// 方案A 实况对拍：走真实 Table 路径（join_player_and_shuffle →
// start_shuffle → mirror_begin_reveal），断言游戏层 reveal
// assignment 密文与 mirror VM pending 目标逐字节一致。
// 复现线上 "reveal set does not cover vm assignments byte-wise"。
// ============================================================
#[tokio::test]
async fn live_flow_assignments_match_mirror_targets() {
    use crate::config::Config;
    use crate::models::Database;
    use crate::pokergame::game_state::{MaskAndShuffleRoundJson, PkProofJson};
    use crate::pokergame::player::{GamePkHex, Player, WalletAddress};
    use crate::pokergame::table::Table;
    use crate::socket::SocketState;
    use crate::starknet::hooks;

    fn ec_hex(p: &poker_protocol::crypto::EcPoint) -> String {
        poker_protocol::z_poker::convert::ecpoint_to_hex(p)
    }
    fn sc_hex(s: &poker_protocol::crypto::Scalar) -> String {
        poker_protocol::z_poker::convert::scalar_to_hex(s)
    }
    fn shuffle_proof_json(proof: &poker_protocol::zk_shuffle::ShuffleProof) -> serde_json::Value {
        use poker_protocol::zk_shuffle::versioned::VersionedShuffleProof;
        match proof {
            VersionedShuffleProof::BayerGrothV2(p) => {
                let m = &p.multi_exponentiation;
                let pr = &p.product;
                serde_json::json!({
                    "version": 2,
                    "proof": {
                        "c_permutation_hex": ec_hex(&p.c_permutation),
                        "c_permuted_powers_hex": ec_hex(&p.c_permuted_powers),
                        "multi_exponentiation": {
                            "c_alpha_hex": ec_hex(&m.c_alpha),
                            "c_beta_hex": ec_hex(&m.c_beta),
                            "ciphertext_0": {"c1_hex": ec_hex(&m.ciphertext_0.c1), "c2_hex": ec_hex(&m.ciphertext_0.c2)},
                            "ciphertext_1": {"c1_hex": ec_hex(&m.ciphertext_1.c1), "c2_hex": ec_hex(&m.ciphertext_1.c2)},
                            "alpha_response_hex": m.alpha_response.iter().map(sc_hex).collect::<Vec<_>>(),
                            "commitment_response_hex": sc_hex(&m.commitment_response),
                            "beta_hex": sc_hex(&m.beta),
                            "beta_blinding_response_hex": sc_hex(&m.beta_blinding_response),
                            "rerandomization_response_hex": sc_hex(&m.rerandomization_response),
                        },
                        "product": {
                            "c_d_hex": ec_hex(&pr.c_d),
                            "c_delta_hex": ec_hex(&pr.c_delta),
                            "c_capital_delta_hex": ec_hex(&pr.c_capital_delta),
                            "a_response_hex": pr.a_response.iter().map(sc_hex).collect::<Vec<_>>(),
                            "b_response_hex": pr.b_response.iter().map(sc_hex).collect::<Vec<_>>(),
                            "r_response_hex": sc_hex(&pr.r_response),
                            "s_response_hex": sc_hex(&pr.s_response),
                        },
                    }
                })
            }
            VersionedShuffleProof::LegacyV1(_) => serde_json::Value::Null,
        }
    }
    fn join_payload(player: &ClientPlayer, deck: &[poker_protocol::crypto::ElGamalCiphertext], agg_pk: &poker_protocol::crypto::EcPoint)
        -> (PkProofJson, MaskAndShuffleRoundJson, String)
    {
        use serde_json::json;
        let round = player.join_game_and_shuffle(deck, agg_pk);
        let ms = &round.mask_and_shuffle_round;
        let ct_json = |ct: &poker_protocol::crypto::ElGamalCiphertext| {
            json!({"c1_hex": ec_hex(&ct.c1), "c2_hex": ec_hex(&ct.c2)})
        };
        let ct_vec_json = |cts: &[poker_protocol::crypto::ElGamalCiphertext]| {
            serde_json::Value::Array(cts.iter().map(ct_json).collect())
        };
        let mask_and_shuffle: MaskAndShuffleRoundJson = serde_json::from_value(json!({
            "mask_cards": ct_vec_json(&ms.mask_cards),
            "output_cards": ct_vec_json(&ms.output_cards),
            "remask_proof": {
                "per_card_commitments_hex": ms.remask_proof.per_card_commitments.iter().map(ec_hex).collect::<Vec<_>>(),
                "commitment_pk_hex": ec_hex(&ms.remask_proof.commitment_pk),
                "response_hex": sc_hex(&ms.remask_proof.response),
                "nonce_hex": sc_hex(&ms.remask_proof.nonce),
            },
            "shuffle_proof": shuffle_proof_json(&ms.proof),
        })).expect("mask and shuffle json");
        let pk_proof: PkProofJson = serde_json::from_value(json!({
            "commitment_hex": ec_hex(&round.pk_ownership_proof.commitment),
            "response_hex": sc_hex(&round.pk_ownership_proof.response),
        })).expect("pk proof json");
        (pk_proof, mask_and_shuffle, ec_hex(&player.pk))
    }

    // Rust 2024 下 set_var 是 unsafe；测试进程独占环境，直接包 unsafe
    unsafe { std::env::set_var("JWT_SECRET", "test-secret") };
    let state = std::sync::Arc::new(SocketState::new(
        Database::new(),
        std::collections::HashMap::new(),
        Config::from_env(),
    ));
    {
        let mut gs = state.state.write().await;
        gs.tables.insert(1, Table::new(1, "Table 1".to_string(), 10000, 9, String::new()));
    }

    // 与线上一致：bot 先入座 seat 2，浏览器用户后入座 seat 1
    let wallets = ["0xba7f00d", "0x6e37d33462f7319261396d7d7f669d147e40cdef91c6a8305cfde771805c782"];
    let seat_ids = [2u32, 1u32];
    let mut pks = Vec::new();
    for (i, wallet) in wallets.iter().enumerate() {
        let player = ClientPlayer::new_with_wallet_address(wallet);
        let (pk_proof, round, pk_hex) = {
            let gs = state.state.read().await;
            let table = gs.tables.get(&1).unwrap();
            let deck = table.mental_poker_game.deck_encrypted.clone();
            let agg = poker_protocol::crypto::EcPoint::from(table.mental_poker_game.key_manager.get_aggregated_pk());
            join_payload(&player, &deck, &agg)
        };
        let p = Player {
            socket_id: format!("sock-{i}"),
            id: format!("wallet:{wallet}"),
            name: format!("p{i}"),
            bankroll: 0,
            wallet_address: WalletAddress(wallet.to_string()),
        };
        let res = state
            .join_player_and_shuffle(1, p, player.pk.clone(), pk_proof, round, seat_ids[i], 1000)
            .await;
        assert!(res.is_ok(), "join {i} failed: {res:?}");
        pks.push((pk_hex, player));
    }

    // 开局（对齐 game_loop：ready 倒计时后 start_shuffle）
    {
        let mut gs = state.state.write().await;
        let table = gs.tables.get_mut(&1).unwrap();
        table.start_shuffle();
    }

    hooks::mirror_registry();
    let gs = state.state.read().await;
    let table = gs.tables.get(&1).unwrap();
    assert!(table.reveal_token_state.is_active(), "preflop reveal must be active");
    let assignments = table.reveal_token_state.player_assignments.clone();
    assert_eq!(assignments.len(), 2, "two players get assignments");

    for (pk_hex, _player) in &pks {
        let key = GamePkHex::new(pk_hex.clone());
        let wallet = table.players().get(&key).unwrap().0.clone();
        let addr = TableMirror::addr_from_starknet(&wallet).unwrap();
        let assignment = assignments.get(&key).expect("assignment for player");
        let targets = hooks::mirror_registry()
            .with_mirror(1, || TableMirror::new(1, "t", [0xC0; 20], 9, 50, 100, [0xC0; 20]), |m| {
                let Some(seat) = m.seat_index_of(addr) else { return Err("no seat".into()) };
                m.pending_reveal_ciphertexts(seat)
            })
            .expect("mirror reachable");
        assert_eq!(
            targets.len(),
            assignment.hand_card.len(),
            "target/assignment size mismatch"
        );
        for card in &assignment.hand_card {
            let hit = targets.iter().any(|t| t.c1 == card.c1 && t.c2 == card.c2);
            assert!(hit, "assignment card not byte-matched in mirror targets");
        }
    }
}
