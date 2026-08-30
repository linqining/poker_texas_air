//! 离开/弃牌剥层排除集（防亮牌 bug 修复）的协议层回归。
//!
//! 安全不变量：剥层输出公开 `input.c2 − output.c2 = sk·c1`（= 离开者对
//! 每张牌的 reveal token）。玩家自己的手牌槽必须原样保留——否则其余
//! 玩家串谋（合计 N−1 份 token + 公开的这份）即可解密已弃牌者的底牌。

use poker_protocol::crypto::curve::{Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric};
use poker_protocol::crypto::{DefaultCurve, EcPoint, Scalar};
use poker_protocol::z_poker::protocol::ClientPlayer;
use poker_protocol::z_poker::protocol::LeaveGameRound;
use poker_protocol::zk_shuffle::transcript_ext::{CryptoTranscript, FiatShamirTranscript};
use rand_core::OsRng;

type Ct = ElGamalCiphertextGeneric<DefaultCurve>;

fn deck_with_hole(n_cards: usize, hole_slots: &[usize]) -> (Vec<Ct>, Vec<EcPoint>) {
    // 模拟发牌后的牌组：hole_slots 是某玩家的两张手牌槽位。
    let sk = <DefaultCurve as Curve>::Scalar::random(&mut OsRng);
    let pk = <DefaultCurve as Curve>::base_g() * sk;
    let mut cts = Vec::with_capacity(n_cards);
    let mut plaintexts = Vec::with_capacity(n_cards);
    for i in 0..n_cards {
        let m = <DefaultCurve as Curve>::hash_to_curve(format!("leave-excl/card-{i}").as_bytes());
        let r = <DefaultCurve as Curve>::Scalar::random(&mut OsRng);
        cts.push(Ct::encrypt(&m, &pk, &r));
        plaintexts.push(m);
    }
    let _ = hole_slots;
    (cts, plaintexts)
}

#[test]
fn leave_excludes_own_hole_slots() {
    let (deck, _) = deck_with_hole(52, &[3, 17]);
    let leaver = ClientPlayer::new();

    let round = leaver.leave_game_with_exclusions(&deck, &[3, 17]);

    // 排除槽：原样保留（sk·c1 不泄露）
    for &i in &[3usize, 17] {
        assert_eq!(round.output_cards[i].c1, round.input_cards[i].c1, "c1 unchanged at hole slot {i}");
        assert_eq!(round.output_cards[i].c2, round.input_cards[i].c2, "c2 unchanged at hole slot {i}");
    }
    // 其余槽：已剥层（c2 改变，且差值 = sk·c1 公开可算）
    let mut stripped = 0;
    for i in 0..52 {
        if ![3, 17].contains(&i) {
            assert_ne!(round.output_cards[i].c2, round.input_cards[i].c2, "slot {i} must be stripped");
            stripped += 1;
        }
    }
    assert_eq!(stripped, 50, "exactly 50 cards stripped");
}

#[test]
fn leave_exclusion_dleq_verifies_over_subdeck() {
    let (deck, _) = deck_with_hole(52, &[0, 1]);
    let leaver = ClientPlayer::new();

    let round = leaver.leave_game_with_exclusions(&deck, &[0, 1]);

    // 验证方：切片 + 同 transcript 验证（与 texas leave_player_with_proof 同构）
    let excluded = [0usize, 1];
    let sub_input: Vec<Ct> = round.input_cards.iter().enumerate()
        .filter(|(i, _)| !excluded.contains(i))
        .map(|(_, ct)| ct.clone())
        .collect();
    let sub_output: Vec<Ct> = round.output_cards.iter().enumerate()
        .filter(|(i, _)| !excluded.contains(i))
        .map(|(_, ct)| ct.clone())
        .collect();
    let mut transcript = FiatShamirTranscript::new(b"zk_leave_proof_v1");
    assert!(
        round.leave_proof.verify(&sub_input, &sub_output, &leaver.pk, &mut transcript),
        "DLEq over the stripped subdeck must verify"
    );
}

#[test]
fn leave_exclusion_anti_reveal_invariant() {
    // 核心不变量：排除槽的 token（sk·c1）在输出中不可推导。
    let (deck, plaintexts) = deck_with_hole(52, &[5, 30]);
    let leaver = ClientPlayer::new();
    let round = leaver.leave_game_with_exclusions(&deck, &[5, 30]);

    // 攻击者视角：仅凭（输入牌组、输出牌组、其余玩家的 token）尝试解密
    // slot 5 的明文。剥层牌可解（差值即离开者 token）；排除牌不可。
    let hole_ct_in = round.input_cards[5].clone();
    let hole_ct_out = round.output_cards[5].clone();
    let leaked_token = hole_ct_in.c2 - hole_ct_out.c2; // 公开可算的 sk·c1
    let zero = <<DefaultCurve as Curve>::Point as CurvePoint>::identity();
    assert!(leaked_token == zero, "excluded slot leaks NO reveal token");

    // 对照：剥层槽的差值非零（token 公开——这是 leave 的语义本身）
    let stripped_in = round.input_cards[6].clone();
    let stripped_out = round.output_cards[6].clone();
    assert!(stripped_in.c2 - stripped_out.c2 != zero, "stripped slot does expose the token (by design)");

    // 且被剥层槽在「已知全部 sk 的聚合视角」下仍解出正确明文（协议正确性）
    // ——用 encrypt 时的同一 pk 退化验证：c2 − (c2−out) = out 对应明文层剥离。
    let _ = plaintexts; // 明文校验在 full_hand_flow 测试中由 reveal 流程覆盖
}

#[test]
fn leave_without_exclusions_still_works_and_full_deck_leaks() {
    // 兼容路径：空排除集 = 旧行为（全牌剥层），证明可验证。
    // 该测试钉住「不排除就泄露」的事实——服务端强校验依赖它拒绝旧客户端。
    let (deck, _) = deck_with_hole(8, &[]);
    let leaver = ClientPlayer::new();
    let round = leaver.leave_game(&deck);
    let mut transcript = FiatShamirTranscript::new(b"zk_leave_proof_v1");
    assert!(
        round.leave_proof.verify(&round.input_cards, &round.output_cards, &leaver.pk, &mut transcript),
        "legacy full-strip leave must still verify (service-side rejects it when hole slots exist)"
    );
    for i in 0..8 {
        assert_ne!(round.output_cards[i].c2, round.input_cards[i].c2, "full strip changes every card");
    }
}

#[test]
fn tampered_excluded_slot_rejected_by_subdeck_dleq() {
    // 篡改排除槽（声称保留却剥了层）：等值校验在服务端抓——这里验证
    // DLEq 侧的稳健性：把排除槽混进子集验证必须失败（证明不覆盖它）。
    let (deck, _) = deck_with_hole(8, &[2]);
    let leaver = ClientPlayer::new();
    let round = leaver.leave_game_with_exclusions(&deck, &[2]);

    // 若验证方错误地把全部牌送进 DLEq（不排除），必须验证失败。
    let mut transcript = FiatShamirTranscript::new(b"zk_leave_proof_v1");
    assert!(
        !round.leave_proof.verify(&round.input_cards, &round.output_cards, &leaver.pk, &mut transcript),
        "DLEq must NOT verify when the un-stripped excluded slot is mixed in"
    );
}
