//! 完整一手牌全流程测试（Plan D 验收补全）。
//!
//! N 个玩家（9 人满桌 / 2 人最低），StarkCurve（DefaultCurve）：
//! 每人各洗一次（真实 Bayer-Groth V2 证明逐个验证）→ 发两张手牌 →
//! 翻牌前 HandReveal（他人 token + 持有者本地解密）→ 下注轮（check/
//! call 推进）→ 翻牌/转牌/河牌 CommunityReveal → 摊牌 ShowdownReveal
//!（各自交出自己的份额）→ 边池/主池判胜 → 手牌评估。
//!
//! 这覆盖真实对局需要的全部 reveal token 形态（他人手牌、公共牌、
//! 自己手牌），此前测试只覆盖认可批次（用户指出的缺口）。

use super::*;
use crate::pokergame::player::{GamePkHex, GamePlayer, WalletAddress};
use poker_protocol::crypto::curve::{Curve, CurveScalar};
use poker_protocol::crypto::{DefaultCurve, Scalar};
use poker_protocol::z_poker::protocol::ClientPlayer;
use poker_protocol::z_poker::protocol::ShuffleRound;
use poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof;
use poker_protocol::zk_shuffle::transcript_ext::{CryptoTranscript, FiatShamirTranscript};
use rand_core::OsRng;

struct Player {
    pk_hex: GamePkHex,
    client: ClientPlayer,
}

/// 满手向量生成状态：捕获流程中每个真实 reveal token（含提交者与密文）。
struct CapturedReveal {
    pk: EcPoint,
    sk: Scalar,
    ct: ElGamalCiphertext,
    token: EcPoint,
}

fn seat_players(table: &mut Table, n: u64) -> Vec<Player> {
    let mut players = Vec::new();
    for idx in 1..=n {
        let client = ClientPlayer::new();
        let proof = client.generate_pk_proof();
        // pk_hex = pk 点的十六进制（与真实客户端 get_pk_hex 一致；
        // submit_reveal_token 会从它反解点做校验）。
        let pk_hex = poker_protocol::z_poker::convert::ecpoint_to_hex(&client.pk);
        table
            .mental_poker_game
            .register_player(pk_hex.clone(), client.pk, proof);
        let player = GamePlayer {
            name: format!("p{idx}"),
            bankroll: 100000,
            pk_hex: GamePkHex::new(pk_hex.clone()),
            readable_hands: vec![],
            wallet_address: WalletAddress(format!("0xwallet{idx}")),
        };
        table.sit_player(player, idx as u32, 100000, false);
        if let Some(seat) = table.local_seats.get_mut(&(idx as u32)) {
            seat.folded = false;
        }
        players.push(Player { pk_hex: GamePkHex::new(pk_hex), client });
    }
    players
}

/// 用真实证明提交一次洗牌（与 submit_verified_shuffle 同验证强度：
/// mental_poker_game.submit_shuffle 内部跑 BG V2 Fiat-Shamir 验证）。
fn submit_real_shuffle(table: &mut Table, player: &Player) {
    assert_eq!(
        table.shuffle_state.current_player_pk,
        Some(player.pk_hex.clone()),
        "shuffle turn must be {}",
        player.pk_hex
    );
    let deck = table.mental_poker_game.deck_encrypted.clone();
    let agg_pk = table.mental_poker_game.key_manager.get_aggregated_pk();
    let mut transcript = FiatShamirTranscript::new(b"zk_shuffle_proof_v2");
    let round = ShuffleRound::execute(&deck, &agg_pk, &mut transcript, &mut OsRng);
    table
        .mental_poker_game
        .submit_shuffle(&player.pk_hex, round)
        .expect("real shuffle proof must verify");
    table.shuffle_state.completed_players.push(player.pk_hex.clone());
    table
        .shuffle_state
        .pending_players
        .retain(|p| p != &player.pk_hex);
    if let Some(next) = table.shuffle_state.pending_players.first().cloned() {
        let next = next.clone();
        table.set_current_shuffler(next);
    }
}

/// 推进当前 reveal 阶段：每个 pending 玩家对其 assignment 的全部卡出
/// 真实 token（RevealTokenProof），提交后阶段完成时触发 on_reveal_complete。
fn drive_reveal_phase(table: &mut Table, players: &[Player]) -> RevealPhase {
    drive_reveal_phase_capture(table, players, &mut None)
}

fn drive_reveal_phase_capture(
    table: &mut Table,
    players: &[Player],
    capture: &mut Option<&mut Vec<CapturedReveal>>,
) -> RevealPhase {
    assert!(
        table.reveal_token_state.is_active(),
        "reveal phase must be active to drive"
    );
    let phase = table.reveal_token_state.phase;
    // 快照 pending 列表（submit 中会原地修改）。
    let pending: Vec<GamePkHex> = table.reveal_token_state.pending_players.clone();
    for pk_hex in pending {
        let player = players
            .iter()
            .find(|p| p.pk_hex == pk_hex)
            .expect("pending player must be seated");
        let assign = table
            .reveal_token_state
            .player_assignments
            .get(&pk_hex)
            .cloned()
            .expect("assignment for pending player");
        let cards: Vec<ElGamalCiphertext> = match phase {
            RevealPhase::HandReveal | RevealPhase::RedealReveal | RevealPhase::ShowdownReveal => assign.hand_card,
            RevealPhase::CommunityReveal => assign.community_card,
            RevealPhase::None => unreachable!(),
        };
        let mut tokens = Vec::new();
        for ct in cards {
            let token = ct.gen_reveal_token(&player.client.sk);
            if let Some(cap) = capture.as_deref_mut() {
                cap.push(CapturedReveal {
                    pk: player.client.pk,
                    sk: player.client.sk,
                    ct: ct.clone(),
                    token,
                });
            }
            let proof = RevealTokenProof::prove(
                &player.client.sk,
                &player.client.pk,
                &ct,
                &token,
                &mut OsRng,
                &mut FiatShamirTranscript::new(b"reveal_token_proof_v3"),
            );
            tokens.push(poker_protocol::z_poker::protocol::RevealToken {
                encrypted_card: ct,
                proof,
                reveal_token: token,
                user_public_key: player.client.pk,
            });
        }
        table
            .submit_player_reveal_tokens(&pk_hex, tokens)
            .unwrap_or_else(|e| panic!("{phase:?} token submit failed for {pk_hex}: {e}"));
        // WS handler 同款收尾：登记完成并在最后一人时触发 on_reveal_complete。
        table.mark_player_reveal_complete(&pk_hex);
    }
    assert!(
        !table.reveal_token_state.is_active(),
        "reveal phase must complete after all submissions"
    );
    phase
}

/// 当前行动者 check（无人下注时）或 call（面对下注时），随后镜像
/// game_loop::handle_turn_advance 的推进逻辑（无 socket 层）。
fn act_and_advance(table: &mut Table, players: &[Player]) {
    let turn_seat = table
        .turn()
        .expect("betting must have a current turn");
    let turn_pk = {
        let seat = table.local_seats.get(&turn_seat).expect("turn seat");
        seat.player.as_ref().expect("seat occupied").pk_hex.clone()
    };
    let player = players.iter().find(|p| p.pk_hex == turn_pk).expect("turn player");

    let others_max_bet = table
        .local_seats
        .values()
        .filter(|s| s.id != turn_seat && !s.folded && s.player.is_some())
        .map(|s| s.total_bet)
        .max()
        .unwrap_or(0);
    let my_bet = table.local_seats.get(&turn_seat).map(|s| s.total_bet).unwrap_or(0);
    if my_bet < others_max_bet {
        table.handle_call(&player.pk_hex).expect("call");
    } else {
        table.handle_check(&player.pk_hex);
    }

    // handle_turn_advance 的纯表镜像
    if table.unfolded_players().len() <= 1 {
        table.end_without_showdown();
    } else if table.is_betting_round_complete() {
        table.advance_to_next_phase();
    } else {
        let last = table.turn().unwrap_or(1);
        table.set_turn(table.next_unfolded_player(last, 1));
    }
}

fn run_full_hand(n: u64) {
    // limit=10000 -> min_bet=50 (limit/200)，盲注 50/100 实际入池；
    // 否则奖池恒 0、win_messages 不产生（determine 仅在奖池>0 时写消息）。
    let mut table = Table::new(9, "full-flow".to_string(), 10000, 9, String::new());
    let players = seat_players(&mut table, n);

    // 在全量聚合公钥下重加密明文牌组（真实对局由 join 掩码层完成同样
    // 的事：把初始牌组拉进正确的密钥谱系；初始牌组在空聚合密钥=恒等元
    // 下加密，直接叠加洗牌层会破坏 Σsk·c1 = c2 − m 的可解性）。
    table.mental_poker_game.encrypt_deck();

    // ---- 开局 + 每人洗一次 ----
    table.start_hand();
    assert!(table.shuffle_state.is_active(), "shuffle phase active");
    let mut shuffled = 0;
    while table.shuffle_state.is_active() && !table.shuffle_state.pending_players.is_empty() {
        let current = table
            .shuffle_state
            .current_player_pk
            .clone()
            .expect("current shuffler set");
        let player = players
            .iter()
            .find(|p| p.pk_hex == current)
            .expect("current shuffler seated");
        submit_real_shuffle(&mut table, player);
        shuffled += 1;
    }
    assert_eq!(shuffled, n as usize, "every player shuffles exactly once");
    table.advance_shuffle();
    assert!(
        !table.shuffle_state.is_active(),
        "shuffle phase closed after all players"
    );
    assert_eq!(table.round_state(), RoundState::PreFlop, "preflop after shuffle");

    // ---- 发牌 + 翻牌前手牌 reveal（他人 token → 持有者本地解密） ----
    for p in &players {
        let hand = table
            .mental_poker_game
            .get_hand_encrypted(&p.pk_hex)
            .expect("dealt hand");
        assert_eq!(hand.len(), 2, "two hole cards per player");
    }
    assert_eq!(table.reveal_token_state.phase, RevealPhase::HandReveal);
    drive_reveal_phase(&mut table, &players);

    // 持有者本地解密（真实客户端流程）：HandReveal 后服务器把
    // readable_cards（c2 − 他人份额）发给持有者，持有者补自己的份额
    // （sk·c1）得到明文——服务器全程看不到明文。
    let readable_map = table.mental_poker_game.get_player_readable_tokens();
    for p in &players {
        let rcs = readable_map
            .get(&*p.pk_hex)
            .expect("holder has readable cards after HandReveal");
        assert_eq!(rcs.len(), 2, "two readable hole cards for {}", p.pk_hex);
        for rc in rcs {
            let own_token = rc.gen_reveal_token(&p.client.sk);
            let plaintext = rc.c2 - own_token;
            assert!(
                table.mental_poker_game.deck_plaintext.contains(&plaintext),
                "holder-decrypted card must be a deck plaintext ({})",
                p.pk_hex
            );
        }
    }

    // ---- 四条街：reveal → betting，直到摊牌 ----
    let mut steps = 0;
    loop {
        steps += 1;
        assert!(steps < 400, "game did not terminate (stuck)");

        if table.reveal_token_state.is_active() {
            let phase_done = drive_reveal_phase(&mut table, &players);
            if phase_done == RevealPhase::ShowdownReveal {
                // 生产路径：摊牌展示后 settle_hand 判定赢家 + 收尾
                //（hand_over、回 Waiting）。
                table.settle_hand();
                break;
            }
            continue;
        }
        if table.summary.hand_over || table.round_state() == RoundState::Waiting {
            break;
        }
        if table.turn().is_some() {
            eprintln!("[step {steps}] state={:?} turn={:?} acted={:?} win={:?} hand_over={}",
                table.round_state(), table.turn(),
                table.local_seats.values().map(|s| (s.id, s.has_acted)).collect::<Vec<_>>(),
                table.summary.win_messages, table.summary.hand_over);
            act_and_advance(&mut table, &players);
            continue;
        }
        // 既无 reveal 也无行动权（摊牌判定后）——退出
        break;
    }

    // ---- 终局断言 ----
    let board = table.mental_poker_game.list_revealed_community_cards();
    assert_eq!(board.len(), 5, "board reaches river (5 community cards)");
    assert!(
        table.summary.went_to_showdown,
        "check/call line goes to showdown"
    );
    assert!(
        !table.summary.win_messages.is_empty(),
        "winner determined with messages"
    );
    // 摊牌后所有未弃牌玩家的手牌均已公开（playing_card 已解出）。
    for p in &players {
        let revealed = table
            .mental_poker_game
            .players
            .get(&*p.pk_hex)
            .map(|ps| ps.hand_encrypted.iter().filter(|c| c.playing_card.is_some()).count())
            .unwrap_or(0);
        assert_eq!(revealed, 2, "showdown publishes every live hand ({})", p.pk_hex);
    }
    assert_eq!(
        table.mental_poker_game.shuffle_rounds.len(),
        n as usize,
        "N real shuffle rounds recorded"
    );
}

#[test]
fn full_hand_2_players_everyone_shuffles_and_reveals() {
    run_full_hand(2);
}

#[test]
fn full_hand_9_players_everyone_shuffles_and_reveals() {
    run_full_hand(9);
}

// ============================================================
// 满手 Hand-batch 批次向量生成（可折叠 reveal 纪元）：
// cargo +nightly test -p texas print_full_hand_batch -- --ignored --nocapture
//
// 跑完整一手（真实洗牌/reveal 流量），捕获全部 reveal token，为每个
// token 铸造可折叠证明（t1 = ω·G, t2 = ω·c1, s = ω + c·sk，c =
// handbatch_reveal_challenge——与合约 reveal_equations 复刻同式），连同
// N 条 ownership 认可组成满手批次，host_fold_check 通过后打印
// Cairo 测试向量。
// ============================================================
#[cfg(test)]
mod full_hand_vector_gen {
    use super::*;
    use crate::starknet::dual_settle::{HandBatchEquation, host_fold_check, parse_batch_terms};

    #[test]
    #[ignore = "vector generator: prints cairo literal"]
    fn print_full_hand_batch() {
        print_full_hand_batch_n(2, "full_hand_n2");
        print_full_hand_batch_n(9, "full_hand_n9");
    }

    fn print_full_hand_batch_n(n: u64, label: &str) {
        use poker_protocol::crypto::curve::{Curve, CurveScalar};
        let mut table = Table::new(9, "full-flow".to_string(), 10000, 9, String::new());
        let players = seat_players(&mut table, n);
        table.mental_poker_game.encrypt_deck();
        table.start_hand();
        while table.shuffle_state.is_active() && !table.shuffle_state.pending_players.is_empty() {
            let current = table.shuffle_state.current_player_pk.clone().unwrap();
            let player = players.iter().find(|p| p.pk_hex == current).unwrap();
            submit_real_shuffle(&mut table, player);
        }
        table.advance_shuffle();

        // 捕获全部 reveal token
        let mut captured: Vec<CapturedReveal> = Vec::new();
        drive_reveal_phase_capture(&mut table, &players, &mut Some(&mut captured));
        let mut steps = 0;
        loop {
            steps += 1;
            assert!(steps < 400);
            if table.reveal_token_state.is_active() {
                let phase_done = drive_reveal_phase_capture(&mut table, &players, &mut Some(&mut captured));
                if phase_done == RevealPhase::ShowdownReveal {
                    table.settle_hand();
                    break;
                }
                continue;
            }
            if table.summary.hand_over || table.round_state() == RoundState::Waiting {
                break;
            }
            if table.turn().is_some() {
                act_and_advance(&mut table, &players);
                continue;
            }
            break;
        }

        // hand_binding：用确定性值（与 ownership 向量同源方式）
        let mut hand_binding = [0x5Bu8; 32];
        hand_binding[0] = 0x02;

        // ---- ownership 认可（确定性 sk，同 print_stark_batch_vector）----
        use poker_protocol::crypto::curve::StarkCurve;
        type SSC = <StarkCurve as Curve>::Scalar;
        type SPT = <StarkCurve as Curve>::Point;
        let g_stark: SPT = <StarkCurve as Curve>::base_g();
        // 满手含 leave：一条 leave（2 卡：1 剥层 + 1 防亮牌排除槽）
        let mut words: Vec<[u8; 32]> = vec![
            u256_word_pub(n),
            u256_word_pub(0), // n_shuffle（BG 桶待链上 CK/MSM）
            u256_word_pub(captured.len() as u64),
            u256_word_pub(1), // n_leave
        ];
        let mut equations: Vec<HandBatchEquation> = Vec::new();
        for i in 0..n {
            use poker_protocol::crypto::curve::CurveScalar;
            let sk = <crate::starknet::dual_settle::Sc as CurveScalar>::from_u64(7000 + i);
            let pk = g_stark * sk;
            let e = crate::starknet::dual_settle::mint_endorsement(&sk, &pk, &hand_binding);
            let (pk_x, pk_y) = crate::starknet::dual_settle::point_xy(&e.pk);
            let (r_x, r_y) = crate::starknet::dual_settle::point_xy(&e.r);
            let mut s_w = [0u8; 32];
            s_w.copy_from_slice(&e.s.as_bytes());
            words.push(pk_x); words.push(pk_y); words.push(r_x); words.push(r_y); words.push(s_w);
            equations.push(HandBatchEquation::Ownership { s: e.s, pk: e.pk, r: e.r });
        }

        // ---- 可折叠 reveal 证明（StarkCurve，计数/相位来自真实流量）----
        // texas 构建当前在 legacy-bls 下，流程捕获的点是 BLS——gas 成本
        // 只由方程数量与点运算决定（曲线局部），故按真实计数在 StarkCurve
        // 上以同构语句铸造：ct_j 在聚合公钥下加密、token = sk_j·c1_j、
        // 两联方程与 reveal_token_proof 同形（挑战换 dapv 式）。
        let n_reveals = captured.len();
        for j in 0..n_reveals {
            let sk_j: SSC = <SSC as CurveScalar>::random(&mut OsRng);
            let pk_j: SPT = g_stark * sk_j;
            // 确定性密文（在 pk_j 下）与 token
            let msg = <StarkCurve as Curve>::hash_to_curve(
                format!("full-hand-fold/reveal-{j}").as_bytes(),
            );
            let r_j: SSC = <SSC as CurveScalar>::random(&mut OsRng);
            let ct_j = poker_protocol::crypto::ElGamalCiphertextGeneric::<StarkCurve>::encrypt(
                &msg, &pk_j, &r_j,
            );
            let token_j = ct_j.c1 * sk_j;
            // 可折叠证明
            let omega: SSC = <SSC as CurveScalar>::random(&mut OsRng);
            let t1 = g_stark * omega;
            let t2 = ct_j.c1 * omega;
            let nonce: SSC = <SSC as CurveScalar>::random(&mut OsRng);
            let c = poker_protocol_core::stark_curve::handbatch_reveal_challenge(
                &hand_binding, &pk_j, &ct_j.c1, &ct_j.c2, &token_j, &t1, &t2, &nonce,
            );
            let s = omega + c * sk_j;
            let (pk_x, pk_y) = crate::starknet::dual_settle::point_xy(&pk_j);
            let (c1x, c1y) = crate::starknet::dual_settle::point_xy(&ct_j.c1);
            let (c2x, c2y) = crate::starknet::dual_settle::point_xy(&ct_j.c2);
            let (tx, ty) = crate::starknet::dual_settle::point_xy(&token_j);
            let (t1x, t1y) = crate::starknet::dual_settle::point_xy(&t1);
            let (t2x, t2y) = crate::starknet::dual_settle::point_xy(&t2);
            let mut n_w = [0u8; 32];
            n_w.copy_from_slice(&{
                use poker_protocol::crypto::curve::CurveScalar as _;
                nonce.as_bytes()
            });
            let mut s_w = [0u8; 32];
            s_w.copy_from_slice(&{
                use poker_protocol::crypto::curve::CurveScalar as _;
                s.as_bytes()
            });
            for w in [pk_x, pk_y, c1x, c1y, c2x, c2y, tx, ty, t1x, t1y, t2x, t2y, n_w, s_w] {
                words.push(w);
            }
            equations.push(HandBatchEquation::Reveal {
                s, pk: pk_j, c1: ct_j.c1, c2: ct_j.c2,
                token: token_j, t1, t2, nonce,
            });
        }

        // ---- leave 条目（仅剥层子集）----
        // 排除槽（自己手牌，in==out）的 DLEq 方程数学上不可满足（a_i 在
        // 挑战前绑定）——防亮牌设计使然。Hand-batch 的 leave 方程集 = 剥层子集
        //（与客户端 execute_with_exclusions 的子集 DLEq 同构）；排除槽的
        // "原样保留"断言由游戏层执行（leave_player_with_proof 强校验）。
        {
            let lsk: SSC = <SSC as CurveScalar>::random(&mut OsRng);
            let l_pk: SPT = g_stark * lsk;
            let omega_l: SSC = <SSC as CurveScalar>::random(&mut OsRng);
            let cpk: SPT = g_stark * omega_l;
            let nonce_l: SSC = <SSC as CurveScalar>::random(&mut OsRng);
            // 一张剥层卡（确定性密文）
            let mut cards_v: Vec<crate::starknet::dual_settle::LeaveCardPts> = Vec::new();
            for j in 0..1u64 {
                let msg = <StarkCurve as Curve>::hash_to_curve(
                    format!("full-hand-fold/leave-card-{j}").as_bytes(),
                );
                let r: SSC = <SSC as CurveScalar>::random(&mut OsRng);
                let ct = poker_protocol::crypto::ElGamalCiphertextGeneric::<StarkCurve>::encrypt(
                    &msg, &l_pk, &r,
                );
                // 剥层：out_c2 = in_c2 − sk·c1（d2 = sk·in_c1 非恒等）
                let out_ct = poker_protocol::crypto::ElGamalCiphertextGeneric::<StarkCurve> {
                    c1: ct.c1,
                    c2: ct.c2 - ct.c1 * lsk,
                };
                let d2 = ct.c2 - out_ct.c2;
                let a = ct.c1 * omega_l;
                let _ = d2;
                cards_v.push(crate::starknet::dual_settle::LeaveCardPts {
                    in_c1: ct.c1,
                    in_c2: ct.c2,
                    out_c1: out_ct.c1,
                    out_c2: out_ct.c2,
                    a,
                });
            }
            let card_words: Vec<poker_protocol_core::stark_curve::HandLeaveCardWords> = cards_v
                .iter()
                .map(|c| poker_protocol_core::stark_curve::HandLeaveCardWords {
                    in_c1: c.in_c1,
                    in_c2: c.in_c2,
                    out_c1: c.out_c1,
                    out_c2: c.out_c2,
                    a: c.a,
                })
                .collect();
            let c = poker_protocol_core::stark_curve::handbatch_leave_challenge(
                &hand_binding, &l_pk, &cpk, &nonce_l, &card_words,
            );
            let s_l = omega_l + c * lsk;
            // 词：[n=1, pk 2, cpk 2, nonce, s, in_c1 2n, in_c2 2n, out_c1 2n, out_c2 2n, a 2n]
            words.push(u256_word_pub(1));
            let (x, y) = crate::starknet::dual_settle::point_xy(&l_pk);
            words.push(x); words.push(y);
            let (x, y) = crate::starknet::dual_settle::point_xy(&cpk);
            words.push(x); words.push(y);
            let mut nb = [0u8; 32]; nb.copy_from_slice(&nonce_l.as_bytes()); words.push(nb);
            let mut sb = [0u8; 32]; sb.copy_from_slice(&s_l.as_bytes()); words.push(sb);
            for c in &cards_v { let (x, y) = crate::starknet::dual_settle::point_xy(&c.in_c1); words.push(x); words.push(y); }
            for c in &cards_v { let (x, y) = crate::starknet::dual_settle::point_xy(&c.in_c2); words.push(x); words.push(y); }
            for c in &cards_v { let (x, y) = crate::starknet::dual_settle::point_xy(&c.out_c1); words.push(x); words.push(y); }
            for c in &cards_v { let (x, y) = crate::starknet::dual_settle::point_xy(&c.out_c2); words.push(x); words.push(y); }
            for c in &cards_v { let (x, y) = crate::starknet::dual_settle::point_xy(&c.a); words.push(x); words.push(y); }
            equations.push(HandBatchEquation::Leave { s: s_l, pk: l_pk, cpk, nonce: nonce_l, cards: cards_v });
        }

        // host parity 自检
        let parsed = parse_batch_terms(&hand_binding, &words).expect("parse full-hand batch");
        assert_eq!(
            parsed.len(),
            (n as usize) + captured.len() + 1,
            "equation count: n_own + n_reveal + 1 leave"
        );
        assert!(host_fold_check(&hand_binding, &parsed), "full-hand batch must fold to identity");

        // 打印 Cairo 向量
        println!("// {label}: captured {} reveals, {} words", captured.len(), words.len());
        println!("// {label}: payload:");
        println!("        array![");
        for w in &words {
            println!("            0x{},", hex::encode(w));
        }
        println!("        ]");
    }

    fn u256_word_pub(v: u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[24..].copy_from_slice(&v.to_be_bytes());
        out
    }
}

// ============================================================
// 开局统一基线重建回归（2026-09-03 双真人物化失败修复）：
// start_preflop_shuffle 必须无条件把牌组重建为 (G, m + 当前 agg) 基线、
// 清空 completed、全员 pending —— 已注册玩家的密钥层由 +agg 预置包含，
// 开局洗牌统一纯 shuffle（明文保持、公钥恒 agg，物化闭环）。
// 该语义同时天然清除孤儿密钥层（洗牌期买入者掉线，份额永久缺失）与
// 上一手残留层，无需单独的孤儿检测分支。
// ============================================================
#[cfg(test)]
mod hand_start_baseline_tests {
    use super::*;
    use crate::pokergame::game_state::ShufflePhase;

    fn agg_baseline_deck(table: &Table) -> Vec<ElGamalCiphertext> {
        let agg = table.mental_poker_game.key_manager.get_aggregated_pk();
        table
            .mental_poker_game
            .deck_plaintext
            .iter()
            .map(|p| ElGamalCiphertext { c1: poker_protocol::crypto::base_g(), c2: *p + agg })
            .collect()
    }

    fn deck_is_baseline(table: &Table) -> bool {
        let d = &table.mental_poker_game.deck_encrypted;
        d.len() == table.mental_poker_game.deck_plaintext.len()
            && d.iter().zip(agg_baseline_deck(table).iter()).all(|(a, b)| a == b)
    }

    /// 开局（无论上一手留下什么牌组/洗牌状态）必须重建基线 + 全员 pending。
    #[test]
    fn hand_start_rebuilds_baseline_and_repends_everyone() {
        let mut table = Table::new(9, "baseline".to_string(), 10000, 9, String::new());
        let players = seat_players(&mut table, 2);
        // 上一手遗留：牌组带真实洗牌层、completed 非空
        table.start_preflop_shuffle();
        for p in &players {
            table.set_current_shuffler(p.pk_hex.clone());
            submit_real_shuffle(&mut table, p);
        }
        assert!(!deck_is_baseline(&table), "deck must carry contributed layers pre-reset");
        assert_eq!(table.shuffle_state.completed_players.len(), 2);

        table.shuffle_state.phase = ShufflePhase::None; // 模拟上一手结束
        table.start_preflop_shuffle(); // 新一手开局

        assert!(deck_is_baseline(&table), "deck must reset to (G, m+agg)");
        assert!(table.shuffle_state.completed_players.is_empty(),
            "completed layers are void with the deck");
        let mut pending: Vec<String> = table
            .shuffle_state
            .pending_players
            .iter()
            .map(|p| p.0.clone())
            .collect();
        pending.sort();
        let mut expected: Vec<String> = players.iter().map(|p| p.pk_hex.0.clone()).collect();
        expected.sort();
        assert_eq!(pending, expected, "every player re-shuffles");
        assert_eq!(table.shuffle_state.phase, ShufflePhase::BeforePreflop);
    }

    /// 洗牌期买入者掉线（孤儿层）：开局重置后其注册被移除、基线只含剩余
    /// 玩家的 agg —— 孤儿份额问题随基线重建消失。
    #[test]
    fn hand_start_orphan_layer_dissolves_into_baseline() {
        let mut table = Table::new(9, "orphan".to_string(), 10000, 9, String::new());
        let players = seat_players(&mut table, 2);
        table.start_preflop_shuffle();
        for p in &players {
            table.set_current_shuffler(p.pk_hex.clone());
            submit_real_shuffle(&mut table, p);
        }
        let orphan = players[0].pk_hex.clone();
        let survivor = players[1].pk_hex.clone();
        table.stand_player_by_pk(&orphan);
        table.shuffle_state.phase = ShufflePhase::None;
        table.start_preflop_shuffle();

        assert!(deck_is_baseline(&table), "baseline rebuilt without the orphan's layer");
        assert_eq!(table.shuffle_state.pending_players, vec![survivor],
            "only the remaining player re-shuffles");
        assert!(!table.mental_poker_game.players.contains_key(orphan.to_string().as_str()));
    }
}
