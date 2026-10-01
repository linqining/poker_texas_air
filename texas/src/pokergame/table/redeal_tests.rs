//! Reconstruction 后 identity card 的换牌（redeal）+ reveal token 重触发流程测试。
//!
//! 场景（用户核对点，参考实现 texas_poker_move table.move::submit_player_reveal_tokens
//! 的 identity_card_indices → emit_identity_redeal → redeal assignments）：
//! reconstruct 重建 deck 后重洗，重洗会把"死槽"（解出非规范明文 = identity 的牌）
//! 随机打散进新 deck（poker_protocol note_deck_reconstructed 已知边界）——持有者
//! 本地解密失败 → 客户端 REDEAL_REQUEST → 服务端换牌 → RedealReveal 阶段重新
//! 收集 reveal token → 牌局继续。
//!
//! 本模块钉住两层事实：
//! 1. 换牌编排（redeal_cards_for_player + start_redeal_reveal_phase + 协议层
//!    redeal_to_player_unchecked 的新纪元游标语义）是实现的；
//! 2. **已知缺口**：RedealReveal 阶段的 token 走 Table::submit_player_reveal_tokens
//!    会被权威门拒绝——VM（poker_l1）没有 redeal 窗口（Betting 相位下
//!    pending_reveal_ciphertexts 报 "reveal phase is NONE"），无镜像时 fail-closed
//!    同样拒绝。换牌后的 re-reveal 因此无法经权威路径完成，45s 超时后退款重开。
//!    修复门禁（让 VM 学习 RedealReveal，或对 RedealReveal 豁免 VM 门）后，
//!    把下面的 expect_err 断言翻转为 expect。

use super::*;
use crate::pokergame::player::{GamePkHex, GamePlayer, WalletAddress};
use poker_protocol::crypto::EcPoint;
use poker_protocol::crypto::curve::CurvePoint;
use poker_protocol::z_poker::protocol::{ClientPlayer, RevealToken, ShuffleRound};
use poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof;
use poker_protocol::zk_shuffle::transcript_ext::PoseidonFeltTranscript;
use rand_core::OsRng;

struct RedealPlayer {
    pk_hex: GamePkHex,
    client: ClientPlayer,
}

fn seat_players(table: &mut Table, n: u64) -> Vec<RedealPlayer> {
    let mut players = Vec::new();
    for idx in 1..=n {
        let client = ClientPlayer::new();
        let proof = client.generate_pk_proof();
        let pk_hex = poker_protocol::z_poker::convert::ecpoint_to_hex(&client.pk);
        // record_join：record_hand_start 采集 HandStart 快照、挂载实时 VM 镜像的前置
        //（真实流程由 join_table 写入；测试直连写同一缓冲）。
        crate::starknet::prove_log::record_join(
            table.summary.id,
            &format!("0x{:064x}", idx),
            &pk_hex,
            crate::relayer::proof_bytes::serialize_pk_ownership_proof(&proof),
            None,
        );
        table
            .mental_poker_game
            .register_player(pk_hex.clone(), client.pk, proof);
        let player = GamePlayer {
            name: format!("p{idx}"),
            bankroll: 100000,
            pk_hex: GamePkHex::new(pk_hex.clone()),
            readable_hands: vec![],
            wallet_address: WalletAddress(format!("0x{:064x}", idx)),
        };
        table.sit_player(player, idx as u32, 100000, false);
        if let Some(seat) = table.local_seats.get_mut(&(idx as u32)) {
            seat.folded = false;
        }
        players.push(RedealPlayer { pk_hex: GamePkHex::new(pk_hex), client });
    }
    players
}

fn submit_real_shuffle(table: &mut Table, player: &RedealPlayer) {
    assert_eq!(table.shuffle_state.current_player_pk, Some(player.pk_hex.clone()));
    let deck = table.mental_poker_game.deck_encrypted.clone();
    let agg_pk = table.mental_poker_game.key_manager.get_aggregated_pk();
    let mut transcript = PoseidonFeltTranscript::new_domain(
        poker_protocol::transcript_domains::SHUFFLE_V2_POSEIDON,
    );
    let round = ShuffleRound::execute_random(&deck, &agg_pk, &mut transcript, &mut OsRng)
        .expect("random shuffle round");
    table
        .mental_poker_game
        .submit_shuffle(&player.pk_hex, round)
        .expect("real shuffle proof must verify");
    table.shuffle_state.completed_players.push(player.pk_hex.clone());
    table.shuffle_state.pending_players.retain(|p| p != &player.pk_hex);
    if let Some(next) = table.shuffle_state.pending_players.first().cloned() {
        table.set_current_shuffler(next);
    }
}

/// 为一名玩家按其 assignment 生成全部 reveal token（真实 RevealTokenProof）。
fn build_assignment_tokens(
    player: &RedealPlayer,
    cards: &[ElGamalCiphertext],
) -> Vec<RevealToken> {
    let mut tokens = Vec::new();
    for ct in cards {
        let token = ct.gen_reveal_token(&player.client.sk);
        let proof = RevealTokenProof::prove(
            &player.client.sk,
            &player.client.pk,
            ct,
            &token,
            &mut OsRng,
            &mut PoseidonFeltTranscript::new_domain(
                poker_protocol::transcript_domains::REVEAL_TOKEN_V3_POSEIDON,
            ),
        );
        tokens.push(RevealToken {
            encrypted_card: ct.clone(),
            proof,
            reveal_token: token,
            user_public_key: player.client.pk,
        });
    }
    tokens
}

/// 把一名玩家指定槽位的底牌密文改写为"持有者解出 identity"的死槽：
/// c2 := Σ_{他人已交 token} + c1·sk_owner。持有者视角
/// plaintext = c2 − Σ_{他人 token} − c1·sk_owner = identity（不在 deck 明文域）。
/// 服务端 hole 卡物化要求 pending 全清（牌主永不交 own token），故该破坏
/// 只对持有者可见——与线上"客户端解密失败 → REDEAL_REQUEST"的发现路径一致。
fn corrupt_to_identity_slot(table: &mut Table, owner: &RedealPlayer, slot: usize) {
    let (sum_tokens, own, c1) = {
        let card = &table
            .mental_poker_game
            .players
            .get(&**owner.pk_hex)
            .expect("owner registered")
            .hand_encrypted[slot];
        (
            card.reveal_state
                .reveal_tokens
                .iter()
                .map(|t| t.reveal_token.clone())
                .sum::<EcPoint>(),
            card.encrypted_card.gen_reveal_token(&owner.client.sk),
            card.encrypted_card.c1.clone(),
        )
    };
    let card = &mut table
        .mental_poker_game
        .players
        .get_mut(&**owner.pk_hex)
        .expect("owner registered")
        .hand_encrypted[slot];
    card.encrypted_card.c2 = sum_tokens + own;
    card.encrypted_card.c1 = c1;
    card.playing_card = None;
}

/// E2E（真实洗牌 + 实时 VM 镜像）：HandReveal 完成后持有者解出 identity 死槽 →
/// REDEAL_REQUEST → 换牌（从 deck 游标取新牌、reveal_state 全量重置）→
/// RedealReveal 阶段重新收集他人 token。
///
/// 同时钉住两个当前缺口（修复后翻转断言）：
/// 1. 权威门拒绝 RedealReveal token（VM 无 redeal 窗口）；
/// 2. 绕门提交时，未换的旧牌上他人 token 重复累加（协议层无按-player 去重），
///    摊牌物化明文必错 → materialization_broken 中止退款。
#[test]
fn redeal_e2e_identity_card_triggers_redeal_and_reveal_restart() {
    let mut table = Table::new(990_201, "redeal-e2e".to_string(), 10000, 9, String::new());
    let players = seat_players(&mut table, 3);
    let p1 = &players[0];
    let p2 = &players[1];
    let p3 = &players[2];

    table.mental_poker_game.encrypt_deck();
    table.start_hand();
    while table.shuffle_state.is_active() && !table.shuffle_state.pending_players.is_empty() {
        let current = table.shuffle_state.current_player_pk.clone().expect("shuffler set");
        let player = players.iter().find(|p| p.pk_hex == current).expect("seated shuffler");
        submit_real_shuffle(&mut table, player);
    }
    table.advance_shuffle();
    assert_eq!(table.round_state(), RoundState::PreFlop);
    assert_eq!(table.reveal_token_state.phase, RevealPhase::HandReveal);

    // ---- HandReveal：他人交 token（经权威路径，VM DealHole 窗口接受） ----
    let pending: Vec<GamePkHex> = table.reveal_token_state.pending_players.clone();
    for pk_hex in &pending {
        let player = players.iter().find(|p| &p.pk_hex == pk_hex).unwrap();
        let cards = table
            .reveal_token_state
            .player_assignments
            .get(pk_hex)
            .cloned()
            .expect("assignment")
            .hand_card;
        let tokens = build_assignment_tokens(player, &cards);
        table
            .submit_player_reveal_tokens(pk_hex, tokens)
            .unwrap_or_else(|e| panic!("HandReveal token submit failed: {e}"));
        table.mark_player_reveal_complete(pk_hex);
    }
    assert!(!table.reveal_token_state.is_active(), "HandReveal complete");

    // 持有者解密在破坏前必须成功（fixture 自检，对齐 run_full_hand 的锚点）。
    let holders = table.mental_poker_game.get_player_residual_carriers();
    for p in &players {
        let rcs = holders.get(&**p.pk_hex).expect("readable cards");
        assert_eq!(rcs.len(), 2);
        for rc in rcs.iter() {
            let own = rc.gen_reveal_token(&p.client.sk);
            assert!(table.mental_poker_game.deck_plaintext.contains(&(rc.c2 - own)));
        }
    }

    // ---- p1 的 0 号底牌成为 identity 死槽（持有者解密失败） ----
    corrupt_to_identity_slot(&mut table, p1, 0);
    let holders = table.mental_poker_game.get_player_residual_carriers();
    let rc0 = &holders.get(&**p1.pk_hex).unwrap()[0];
    let own0 = rc0.gen_reveal_token(&p1.client.sk);
    assert!(
        (rc0.c2 - own0).is_identity(),
        "fixture: holder decrypt must yield identity for the dead slot"
    );

    // ---- 客户端 REDEAL_REQUEST → WS handler 同款编排：换牌 + 重触发 reveal ----
    let redealt = table
        .redeal_cards_for_player(&p1.pk_hex, vec![0])
        .expect("redeal ok");
    assert_eq!(redealt, vec![0]);
    {
        let hand = &table.mental_poker_game.players.get(&**p1.pk_hex).unwrap().hand_encrypted;
        assert_eq!(hand[0].card_index, 6, "redeal 从 deck 游标（3 人 × 2 张）取新牌");
        assert_eq!(
            hand[0].encrypted_card,
            table.mental_poker_game.deck_encrypted[6],
            "换入的牌就是 deck 游标位的新密文"
        );
        assert_eq!(
            hand[0].reveal_state.pending_players.len(),
            3,
            "换牌后 reveal_state 全量重置：所有活跃玩家（含牌主）都待交 token"
        );
        assert!(hand[0].reveal_state.reveal_tokens.is_empty());
        assert!(hand[0].playing_card.is_none());
    }
    table.start_redeal_reveal_phase(&p1.pk_hex, redealt.clone());
    assert_eq!(table.reveal_token_state.phase, RevealPhase::RedealReveal);
    assert_eq!(table.round_state(), RoundState::PreFlop, "redeal 不改变 round_state");
    let p2_pk = p2.pk_hex.clone();
    let p3_pk = p3.pk_hex.clone();
    assert!(table.reveal_token_state.pending_players.contains(&p2_pk));
    assert!(table.reveal_token_state.pending_players.contains(&p3_pk));
    assert!(!table.reveal_token_state.pending_players.contains(&p1.pk_hex));
    assert!(
        !table.reveal_token_state.player_assignments.contains_key(&p1.pk_hex),
        "牌主不为换牌交 token（他人交齐后牌主本地解密）"
    );
    let new_ct = table.mental_poker_game.players.get(&**p1.pk_hex).unwrap().hand_encrypted[0]
        .encrypted_card
        .clone();
    for pk in [&p2_pk, &p3_pk] {
        let assign = &table.reveal_token_state.player_assignments[pk];
        assert_eq!(assign.hand_card.len(), 2, "assignment 覆盖 p1 全部两张底牌");
        assert!(assign.hand_card.iter().any(|c| *c == new_ct));
    }

    // ---- 已知缺口 1：权威门拒绝 RedealReveal token ----
    // VM（poker_l1）没有 RedealReveal 窗口：HandReveal 消化后已 normalize 进
    // Betting 相位，pending_reveal_ciphertexts 直接报 "reveal phase is NONE"。
    // 修复门禁后把 expect_err 翻转为 expect，并删掉下方协议级旁路。
    let tokens_p2 = {
        let cards = table.reveal_token_state.player_assignments[&p2_pk].hand_card.clone();
        build_assignment_tokens(p2, &cards)
    };
    let gate_err = table
        .submit_player_reveal_tokens(&p2_pk, tokens_p2.clone())
        .expect_err("known gap: authority gate must reject RedealReveal tokens");
    assert!(
        gate_err.contains("reveal rejected by VM"),
        "unexpected rejection reason: {gate_err}"
    );

    // ---- 门修复后的预期路径（协议级旁路）：p2/p3 为换牌重交 token ----
    for (pk, player) in [(&p2_pk, p2), (&p3_pk, p3)] {
        let cards = table.reveal_token_state.player_assignments[pk].hand_card.clone();
        for token in build_assignment_tokens(player, &cards) {
            table
                .mental_poker_game
                .submit_reveal_token(token, &**pk)
                .unwrap_or_else(|e| panic!("protocol token submit failed: {e:?}"));
        }
        table.mark_player_reveal_complete(pk);
    }
    assert!(!table.reveal_token_state.is_active(), "RedealReveal complete");

    // ---- 已知缺口 2：未换的旧牌 token 重复累加（特征化，修复去重后改断言） ----
    {
        let hand = &table.mental_poker_game.players.get(&**p1.pk_hex).unwrap().hand_encrypted;
        assert_eq!(
            hand[1].reveal_state.reveal_tokens.len(),
            4,
            "旧牌上 p2/p3 的 HandReveal token 被 RedealReveal 重复累加（无按-player 去重）\
             ——摊牌物化明文必错，最终 materialization_broken 中止退款"
        );
        assert_eq!(hand[1].reveal_state.pending_players.len(), 1);
        assert_eq!(hand[0].reveal_state.reveal_tokens.len(), 2, "换的新牌每人一份");
        assert_eq!(hand[0].reveal_state.pending_players.len(), 1, "只剩牌主待本地解密");
    }

    // ---- RedealReveal 完成后牌局继续：round_state 保持，下注轮仍可行动 ----
    let turn_seat = table.turn().expect("betting turn preserved after redeal reveal");
    let turn_pk = table
        .local_seats
        .get(&turn_seat)
        .expect("turn seat")
        .player
        .as_ref()
        .expect("occupied")
        .pk_hex
        .clone();
    let actor = players.iter().find(|p| p.pk_hex == turn_pk).expect("turn player");
    let others_max = table
        .local_seats
        .values()
        .filter(|s| s.id != turn_seat && !s.folded && s.player.is_some())
        .map(|s| s.total_bet)
        .max()
        .unwrap_or(0);
    let my_bet = table.local_seats.get(&turn_seat).map(|s| s.total_bet).unwrap_or(0);
    if my_bet < others_max {
        assert!(table.handle_call(&turn_pk).is_some(), "betting must continue");
    } else {
        assert!(table.handle_check(&turn_pk).is_some(), "betting must continue");
    }
    let _ = actor;
}

/// Reconstruction 纪元游标语义：note_deck_reconstructed 归零发牌游标后，
/// redeal 从新 deck 的未消费位置 0 取牌（未归零则取 6）；换牌后
/// start_redeal_reveal_phase 的 assignment / pending 形态正确。
#[test]
fn redeal_after_deck_reconstruction_pulls_from_new_era_cursor() {
    let mut table = Table::new(990_202, "redeal-cursor".to_string(), 10000, 9, String::new());
    // 仅协议层注册（本测试不驱动 VM/权威路径，无需 join 证明）。
    let mut clients = Vec::new();
    for _idx in 1..=3 {
        let client = ClientPlayer::new();
        let proof = client.generate_pk_proof();
        let pk_hex = poker_protocol::z_poker::convert::ecpoint_to_hex(&client.pk);
        table
            .mental_poker_game
            .register_player(pk_hex.clone(), client.pk, proof);
        clients.push((pk_hex, client));
    }
    table.mental_poker_game.encrypt_deck();

    // 旧纪元：每人 2 张（deck 位置 0..5 已消费）。
    for (pk_hex, _) in &clients {
        table
            .mental_poker_game
            .deal_to_player(pk_hex, 2)
            .expect("era-0 deal");
    }
    // reconstruct 完成：deck 重建 + 全员重洗（这里只换掉位置 0 模拟重洗后的新密文）
    // + 宿主 note_deck_reconstructed 归零游标。
    let reshuffled0 = ElGamalCiphertext {
        c1: EcPoint::identity(),
        c2: table.mental_poker_game.deck_encrypted[0].c2,
    };
    table.mental_poker_game.deck_encrypted[0] = reshuffled0.clone();
    table.mental_poker_game.note_deck_reconstructed();

    // 持有者报告 identity 死槽 → 换牌：新纪元第一张未消费牌 = deck[0]。
    let (p1, p2, p3) = (
        clients[0].0.clone(),
        clients[1].0.clone(),
        clients[2].0.clone(),
    );
    let redealt = table
        .redeal_cards_for_player(&GamePkHex::new(p1.clone()), vec![0])
        .expect("redeal ok");
    assert_eq!(redealt, vec![0]);
    {
        let hand = &table.mental_poker_game.players.get(&p1).unwrap().hand_encrypted;
        assert_eq!(hand[0].card_index, 0, "新纪元游标从 0 起步（未 note 则为 6）");
        assert_eq!(hand[0].encrypted_card, reshuffled0, "换入重洗后新 deck 位置 0 的牌");
        assert_eq!(hand[0].reveal_state.pending_players.len(), 3);
        assert!(hand[0].reveal_state.reveal_tokens.is_empty());
    }

    // 重触发 reveal token：RedealReveal 形态不变量。
    table.start_redeal_reveal_phase(&GamePkHex::new(p1.clone()), redealt);
    assert_eq!(table.reveal_token_state.phase, RevealPhase::RedealReveal);
    let pending = &table.reveal_token_state.pending_players;
    assert_eq!(pending.len(), 2);
    assert!(pending.contains(&GamePkHex::new(p2.clone())));
    assert!(pending.contains(&GamePkHex::new(p3.clone())));
    assert!(!pending.contains(&GamePkHex::new(p1.clone())));
    let hand = &table.mental_poker_game.players.get(&p1).unwrap().hand_encrypted;
    for pk in [&p2, &p3] {
        let assign = &table.reveal_token_state.player_assignments[&GamePkHex::new(pk.clone())];
        assert_eq!(assign.hand_card.len(), 2);
        assert!(assign.hand_card.iter().any(|c| *c == hand[0].encrypted_card));
        assert!(assign.hand_card.iter().any(|c| *c == hand[1].encrypted_card));
    }
    assert!(!table.reveal_token_state.player_assignments.contains_key(&GamePkHex::new(p1)));
}
