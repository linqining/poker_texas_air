//! Starknet 接入端到端测试（cargo test -p texas e2e_starknet）：
//! 买入（join_table）→ 开局（start_hand）→ 真实洗牌证明 ×2 → 下注（raise/fold）
//! → 结算（derive_settlement_plan）→ 证明（Orchestrator + outer aggregate）
//! → Starknet calldata（register_aggregate / settle_hand）。
//!
//! 洗牌证明用 zgame poker_protocol（与前端 wasm 同源代码）真实生成，
//! 检验 poker_l1 dispatch 能否接受真实客户端证明——这是前后端证明协议对齐的
//! 核心集成事实。

use poker_l1::signature::TaggedPubkey;
use poker_protocol::crypto::{DefaultCurve};
use poker_protocol::crypto::curve::{Curve, ElGamalCiphertextGeneric};
use poker_protocol::zk_shuffle::ShuffleProof;
use poker_protocol::zk_shuffle::transcript_ext::{CryptoTranscript, FiatShamirTranscript};
use rand::rngs::OsRng;
use poker_protocol::crypto::curve::CurveScalar;

use super::mirror::TableMirror;

type ZgCt = poker_protocol::crypto::ElGamalCiphertext;

fn real_shuffle(
    input: &[ZgCt],
    aggregate_pk: &<DefaultCurve as Curve>::Point,
) -> (Vec<ZgCt>, ShuffleProof) {
    let n = input.len();
    // 真实随机置换（确定性置换会让每手牌局完全相同）
    let mut permutation: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        let j = rand::Rng::gen_range(&mut rand::thread_rng(), 0..=i);
        permutation.swap(i, j);
    }
    let rerandomizers: Vec<_> = (0..n)
        .map(|_| <DefaultCurve as Curve>::Scalar::random(&mut OsRng))
        .collect();
    let output: Vec<_> = (0..n)
        .map(|i| input[permutation[i]].re_encrypt(aggregate_pk, &rerandomizers[i]))
        .collect();
    let proof = ShuffleProof::prove(
        input,
        &output,
        &permutation,
        &rerandomizers,
        aggregate_pk,
        &mut OsRng,
        &mut FiatShamirTranscript::new(b"zk_shuffle_proof_v2"),
    )
    .expect("Bayer--Groth proof should build");
    (output, proof)
}

/// 把 ptx 密文（c1/c2: G1Projective）桥接为 zgame 密文（borsh roundtrip）。
fn to_zg_ct(ct: &super::mirror::PtxElGamalCiphertext) -> ZgCt {
    // 两份 poker_protocol 副本共享同一 blstrs G1Projective（Cargo 统一版本），
    // c1/c2 是裸点，直接字段拷贝即可。
    ZgCt { c1: ct.c1, c2: ct.c2 }
}

/// 把 zgame 密文列表桥接回 ptx 密文（borsh roundtrip）。
fn to_ptx_cts(cts: &[ZgCt]) -> Vec<super::mirror::PtxElGamalCiphertext> {
    super::mirror::conv::ciphertexts(cts).expect("borsh bridge")
}

/// 完整链路测试：买入 → 开局 → 真实洗牌 → 揭牌 → 下注 → 结算 → calldata。
///
/// 当前状态：已验证到「翻牌前 hole reveal 通过 + 下注轮开启」。
/// 剩余问题：flop 街 reveal 解密报 "decrypted plaintext is not a canonical
/// Texas Poker card"——需要核对 poker_l1 多街 reveal 的 card_index/密文谱系
/// （hole 用 live deck 已通过，flop 用同一 deck 失败，疑似 deal 时密文迁移）。
/// 修复该谱系后取消 #[ignore] 即可驱动完整结算断言。
/// 牌力完全平分（awards==total_bets）时换随机密钥重打，最多 5 次。
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

    // 玩家 mental-poker 密钥（真实 scalar）。
    let sk1 = <DefaultCurve as Curve>::Scalar::random(&mut OsRng);
    let sk2 = <DefaultCurve as Curve>::Scalar::random(&mut OsRng);
    let pk1 = <DefaultCurve as Curve>::base_g() * sk1;
    let pk2 = <DefaultCurve as Curve>::base_g() * sk2;
    let aggregate = pk1 + pk2;

    let mut mirror = TableMirror::new(1, "e2e", creator, 4, 10, 20, creator);

    // ---- 买入：join_table（buy_in 计入 stack，真实 Schnorr 所有权证明）----
    use poker_l1::vm::contracts::texas_poker::utils::create_pk_ownership_proof;
    let zpk1 = super::mirror::conv::ec_point(&poker_protocol::crypto::types::ECPoint(pk1)).unwrap();
    let zpk2 = super::mirror::conv::ec_point(&poker_protocol::crypto::types::ECPoint(pk2)).unwrap();
    let nonce1 = <DefaultCurve as Curve>::Scalar::random(&mut OsRng);
    let nonce2 = <DefaultCurve as Curve>::Scalar::random(&mut OsRng);
    let proof1 = create_pk_ownership_proof(&sk1, &nonce1).expect("proof p1");
    let proof2 = create_pk_ownership_proof(&sk2, &nonce2).expect("proof p2");
    mirror.join(p1, 1000, zpk1, proof1).expect("join p1");
    mirror.join(p2, 1000, zpk2, proof2).expect("join p2");
    assert_eq!(mirror.seat_index_of(p1), Some(0));
    assert_eq!(mirror.seat_index_of(p2), Some(1));

    // ---- 开局：start_hand（盲注 + sk=0 牌组 + 进入洗牌阶段）----
    mirror.begin_hand(creator).expect("start_hand");

    // ---- 洗牌 ×2（真实 Bayer-Groth 证明，前端 wasm 同一代码）----
    // 与真实客户端一致：首洗输入即 start_hand 的 sk=0 牌组 (G, m)，各玩家在
    // 聚合钥下重加密（c1 含 +1·G 项，这是 reveal token = sk·c1 求和能解密
    // 到明文的关键）。poker_l1 会在验证后自动注入洗牌者公钥层，所以 p2 的
    // 输入含 p1 的层。
    let seeded: Vec<ZgCt> = mirror.deck().iter().map(to_zg_ct).collect();
    let (out1, proof1) = real_shuffle(&seeded, &aggregate);
    mirror
        .submit_shuffle(0, to_ptx_cts(&out1), super::mirror::conv::shuffle_proof(&proof1).unwrap())
        .expect("p1 shuffle dispatch + verify");

    let deck_after_p1: Vec<ZgCt> = mirror.deck().iter().map(to_zg_ct).collect();
    let (out2, proof2) = real_shuffle(&deck_after_p1, &aggregate);
    mirror
        .submit_shuffle(1, to_ptx_cts(&out2), super::mirror::conv::shuffle_proof(&proof2).unwrap())
        .expect("p2 shuffle dispatch + verify");
    assert!(mirror.has_provable_activity(), "shuffles must emit prove tasks");

    // 洗牌后牌组快照：reveal token 必须基于提交时的密文（后续 street 可能改写 deck）
    let deck_snapshot: Vec<ZgCt> = mirror.deck().iter().map(to_zg_ct).collect();

    // ---- 推进：reveal 阶段与下注轮交替，直到公共牌到河牌 ----
    // 与真实协议一致：shuffle → 翻牌前 reveal → preflop 下注 → flop reveal →
    // flop 下注 → ... → river。reveal 每个玩家对全部 pending assignment 提交
    // token = sk·c1 + Schnorr 证明（与真实客户端同一证明代码）。
    use poker_protocol::crypto::curve::CurveScalar;
    use poker_protocol::zk_shuffle::transcript_ext::MerlinTranscript;
    use poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof as ZgRevealProof;

    let sks: [<DefaultCurve as Curve>::Scalar; 2] = [sk1, sk2];
    for _step in 0..64 {
        if mirror.table.reveal_token_state().is_some() {
            // reveal 阶段：pending 座位中编号最小者提交其全部 pending assignments
            let reveal_state = mirror.table.reveal_token_state().unwrap();
            let min_pending_seat = reveal_state.assignments.iter()
                .filter(|a| !a.is_ready())
                .filter_map(|a| (0u8..2).find(|s| a.pending_mask() & (1u16 << s) != 0))
                .min();
            let Some(seat) = min_pending_seat else { break };
            let ais: Vec<usize> = reveal_state.assignments.iter().enumerate()
                .filter(|(_, a)| a.pending_mask() & (1u16 << seat) != 0)
                .map(|(ai, _)| ai)
                .collect();
            let sk = sks[seat as usize];
            let pk = <DefaultCurve as Curve>::base_g() * sk;
            // showdown 阶段用 owner 账本的部分密文（非 owner 层已剥离），
            // 其余阶段用当前牌组快照密文——与 poker_l1 验证端谱系一致。
            let is_showdown = mirror.table.reveal_phase()
                == poker_l1::vm::contracts::texas_poker::constants::REVEAL_PHASE_SHOWDOWN;
            let mut tokens = Vec::new();
            let mut proofs = Vec::new();
            for ai in &ais {
                let assignment = &mirror.table.reveal_assignments()[*ai];
                let ct = if is_showdown {
                    let poker_l1::vm::contracts::texas_poker::types::RevealTarget::Hole {
                        seat_index: owner,
                        card_slot,
                    } = assignment.target
                    else {
                        panic!("showdown assignment must target a hole slot");
                    };
                    let partial = mirror
                        .table
                        .deck_state
                        .owner_readable_hole_cards
                        .get(owner, card_slot)
                        .expect("showdown ledger partial must exist");
                    to_zg_ct(&partial.ciphertext)
                } else {
                    deck_snapshot[assignment.encrypted_card_index as usize].clone()
                };
                let token = ct.gen_reveal_token(&sk);
                let proof = ZgRevealProof::prove(
                    &sk, &pk, &ct, &token, &mut OsRng,
                    &mut MerlinTranscript::new(b"reveal_token_proof_v3"),
                );
                tokens.push(super::mirror::conv::ec_point(&poker_protocol::crypto::types::ECPoint(token)).unwrap());
                proofs.push(super::mirror::conv::reveal_token_proof(&proof).unwrap());
            }
            mirror
                .submit_reveal_tokens(seat, tokens, proofs)
                .unwrap_or_else(|e| panic!("seat {seat} reveal submit failed: {e}"));
            continue;
        }
        if let Some(actor) = mirror.table.current_turn_option() {
            let other = 1u8 - actor;
            let facing_bet = mirror.table.seats[actor as usize].total_bet()
                < mirror.table.seats[other as usize].total_bet();
            if facing_bet {
                mirror.call(actor).expect("call");
            } else {
                mirror.check(actor).expect("check");
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

    // 平分检测（须在派奖前：派奖后 board 复位无法 derive）
    let plan_check = poker_l1::vm::contracts::texas_poker::settlement::derive_settlement_plan(&mirror.table)
        .map_err(|e| format!("plan: {e}"))?;
    let all_zero_delta = mirror.table.seats.iter().enumerate().all(|(i, s)| {
        plan_check.awards.get(i).copied().unwrap_or(0) as i128 == s.total_bet() as i128
    });
    if all_zero_delta {
        eprintln!("[debug] awards={:?} winner_mask={} total_bets={:?} hands={:?}",
            plan_check.awards, plan_check.winner_mask,
            mirror.table.seats.iter().map(|s| s.total_bet()).collect::<Vec<_>>(),
            mirror.table.seats.iter().map(|s| s.hand().map(|h| h.to_vec())).collect::<Vec<_>>());
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

    assert_eq!(settlement.hand_id, 1);
    assert!(!settlement.register_calldata.is_empty());
    assert!(!settlement.settle_calldata.is_empty());
    // settle_calldata 布局：digest(hi, lo) + hand_id + players.len + ... + deltas.len + ...
    assert!(settlement.settle_calldata.len() >= 6);
    // 零和：deltas felts 之和按模意义应为 0（由 SettleHandCalldata 零和校验保证）。
    // 聚合摘要非零。
    assert_ne!(settlement.aggregate_digest, [0u8; 32]);

    // ---- Hand-batch（PokerDualSettlement）：hand_binding + hand-bound 认可批次 ----
    // P2.1 后服务器不持有认可密钥：测试在 host 侧生成密钥并铸造（角色
    // 等价于客户端 wasm endorsement_mint），再走客户端构建路径。
    use poker_protocol::crypto::curve::{Curve, CurvePoint};
    let binding = super::dual_settle::prepare_handbatch_binding(&mirror, &settlement)?;
    // gas 压缩版：挑战域 = hand_binding 本身（felt 直通 Poseidon），无 keccak。
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
    // register_hand calldata：binding + settlement_digest + g_attestation
    // + 3 个零的期望桶计数尾部（新兼容字段，零 = 链上不约束）。
    assert_eq!(dual.register_calldata.len(), 6);
    // settle calldata 布局：binding + [32, bytes…] + hand_id + [n, players…] + [n, deltas…] + [m, felt×m]
    // （_stark 入口 Span<felt252> 单 felt/词）
    let expect_len = 1 + 1 + 32 + 1
        + 1 + settlement.players_remapped.len()
        + 1 + settlement.deltas.len()
        + 1 + dual.batch_words.len();
    assert_eq!(dual.settle_calldata.len(), expect_len);
    // proved 工件：承诺存在、register 8 词、settle calldata 无 p_batch
    // （同前缀，但去掉了 [m, felt×m] 尾巴，只补承诺+词数两个词）。
    assert_ne!(dual.proved.p_batch_commitment, starknet_ff::FieldElement::ZERO);
    assert_eq!(dual.proved.register_calldata.len(), 8);
    assert_eq!(
        dual.proved.settle_calldata.len(),
        expect_len - (1 + dual.batch_words.len()) + 2
    );

    // 宿主折叠 parity（链上 fold_and_check 的同构镜像）：本手通过；
    // 跨手（翻转 binding 首字节）按链上视角——用错误域重放挑战后折叠——
    // 必须拒绝（L2 hand 绑定；§8 引理：对诚实残差换 ρ 折叠恒为零，
    // 防重放靠的是挑战域错位，不是 ρ 本身）。
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


/// 已验证前缀：买入（真实 Schnorr 证明）→ start_hand → 真实 Bayer-Groth 洗牌
/// 证明在 poker_l1 dispatch 下验证通过 → 翻牌前 hole reveal 通过 → 下注轮开启。
/// 这是前后端证明协议对齐（zgame poker_protocol ↔ poker_texas_air）的核心集成事实。
#[test]
fn e2e_starknet_prefix_join_shuffle_reveal_betting() {
    // 与完整测试相同的前置（最多到第一次下注行动前）
    let creator: poker_l1::Address = [0xC0; 20];
    let p1: poker_l1::Address = [0x11; 20];
    let p2: poker_l1::Address = [0x22; 20];
    let sk1 = <DefaultCurve as Curve>::Scalar::random(&mut OsRng);
    let sk2 = <DefaultCurve as Curve>::Scalar::random(&mut OsRng);
    let pk1 = <DefaultCurve as Curve>::base_g() * sk1;
    let pk2 = <DefaultCurve as Curve>::base_g() * sk2;
    let aggregate = pk1 + pk2;

    let mut mirror = TableMirror::new(1, "e2e-prefix", creator, 4, 10, 20, creator);
    use poker_l1::vm::contracts::texas_poker::utils::create_pk_ownership_proof;
    use poker_protocol::crypto::curve::CurveScalar;
    let zpk1 = super::mirror::conv::ec_point(&poker_protocol::crypto::types::ECPoint(pk1)).unwrap();
    let zpk2 = super::mirror::conv::ec_point(&poker_protocol::crypto::types::ECPoint(pk2)).unwrap();
    let proof1 = create_pk_ownership_proof(&sk1, &<DefaultCurve as Curve>::Scalar::random(&mut OsRng)).unwrap();
    let proof2 = create_pk_ownership_proof(&sk2, &<DefaultCurve as Curve>::Scalar::random(&mut OsRng)).unwrap();
    mirror.join(p1, 1000, zpk1, proof1).expect("join p1");
    mirror.join(p2, 1000, zpk2, proof2).expect("join p2");
    mirror.begin_hand(creator).expect("start_hand");

    let seeded: Vec<ZgCt> = mirror.deck().iter().map(to_zg_ct).collect();

    let (out1, prf1) = real_shuffle(&seeded, &aggregate);
    mirror.submit_shuffle(0, to_ptx_cts(&out1), super::mirror::conv::shuffle_proof(&prf1).unwrap()).expect("p1 shuffle");
    let deck_after_p1: Vec<ZgCt> = mirror.deck().iter().map(to_zg_ct).collect();
    let (out2, prf2) = real_shuffle(&deck_after_p1, &aggregate);
    mirror.submit_shuffle(1, to_ptx_cts(&out2), super::mirror::conv::shuffle_proof(&prf2).unwrap()).expect("p2 shuffle");

    // hole reveal ×2 玩家
    use poker_protocol::zk_shuffle::transcript_ext::MerlinTranscript;
    use poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof as ZgRevealProof;
    let sks = [sk1, sk2];
    loop {
        let Some(rs) = mirror.table.reveal_token_state() else { break };
        let Some(seat) = rs.assignments.iter().filter(|a| !a.is_ready())
            .filter_map(|a| (0u8..2).find(|s| a.pending_mask() & (1u16 << s) != 0))
            .min() else { break };
        let ais: Vec<usize> = rs.assignments.iter().enumerate()
            .filter(|(_, a)| a.pending_mask() & (1u16 << seat) != 0)
            .map(|(ai, _)| ai).collect();
        let sk = sks[seat as usize];
        let pk = <DefaultCurve as Curve>::base_g() * sk;
        let mut tokens = Vec::new();
        let mut proofs = Vec::new();
        for ai in &ais {
            let ci = mirror.table.reveal_assignments()[*ai].encrypted_card_index as usize;
            let ct = to_zg_ct(&mirror.deck()[ci]);
            let token = ct.gen_reveal_token(&sk);
            tokens.push(super::mirror::conv::ec_point(&poker_protocol::crypto::types::ECPoint(token)).unwrap());
            proofs.push(super::mirror::conv::reveal_token_proof(
                &ZgRevealProof::prove(&sk, &pk, &ct, &token, &mut OsRng,
                    &mut MerlinTranscript::new(b"reveal_token_proof_v3"))).unwrap());
        }
        mirror.submit_reveal_tokens(seat, tokens, proofs).expect("hole reveal");
    }
    assert!(mirror.table.current_turn_option().is_some(), "betting round should start");
}
