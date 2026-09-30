//! fold 批测试（FoldDesign v2 **生产形状**：fold_batch.cairo 并 98 词 settle
//! wire + foldagg.rs 镜像）。
//!
//! 测试清单（T 编号沿用设计，负例名后缀 `_attack_*` 防回归语义漂移）：
//! - T1 正例（heavy）：2/5/8 人诚实聚合，K=8 手批 → 出证 verified +
//!   17 词段形状（[acc]++语句段++[roster_digest]）双 parity +
//!   `--check-only` 独立复验（P5 completeness 的电路级兑现）；
//! - T2 z̄+1 篡改 → 电路 panic 无证明（heavy；forge0_bad 方向已确认可行）；
//! - T3 跨手重放 (R̄,z̄) → 电路 panic（c 含 hand_binding）；
//! - T4 改性：host-parity 断言（公式漂移检测，**对 soundness 零证明力**
//!   ——soundness 闭合点在 roster_registry，T9/T10）；
//! - T5 伪造 prev_acc → 出证后 parity 门拒（recurse.rs:485-499 同款，heavy）；
//! - T6 off-curve / 恒等点 → 电路 panic（满阶依据：n 素 / cofactor=1 /
//!   无 2-torsion，审方 F-1 实测）；
//! - T7 perf（heavy）：K=1/8/32/64 @ P=8 生产形状 steps/RSS 扫描。验收线
//!   （fold-spec §3 诚实边界）：K=1 总量 ≤ combined 每手 12,160 + keyagg
//!   批固定层 1,628；批量边际 ≤ combined 每手 12,160（steps 轴底线——生产
//!   fold ≈11.3k/手估算 = keyagg 1,628 + 结算边际 9,405 + 签名层，结构性
//!   收益在单批单证/fact 密度 64×，不在 steps）；批 ≤ 2^20 桶；
//! - T8 KAT：BDN 域标签 / μ / M_h 真槽 / c / cm_digest 逐 felt 钉死（缺口 4
//!   + Q-2：cm_digest 8 词压缩十六进制钉值随生产版落库）；
//! - T9 forge0（heavy，_attack_A1）：wire pks 换攻击者钥 + 攻击者自签 →
//!   电路算术自洽照样出证，**断言点 = 出证后 host parity 门拒**
//!   （roster_digest ≠ 注册锚；生产对应 roster_registry 对照 segment[16]）；
//! - T10 agg1_forge（heavy，_attack_A2）：整组换 roster / n=1 同理门拒；
//! - T11/T12（heavy）：T9/T10 的 z̄+1 正控——电路对非签名的拒绝路径活跃，
//!   防「负例因电路坏而假阳性」。
//!
//! 运行（heavy 依赖 prove-hand 二进制）：
//!   cargo test -p hand-verify-native                       # 单测（T4/T8 + host 负例）
//!   cargo test --release -p hand-verify-native \
//!     --test fold_batch_test -- --ignored --nocapture      # 全量真跑
//!   FOLD_PERF_ONLY=64 cargo test --release -p hand-verify-native \
//!     --test fold_batch_test t7 -- --ignored --nocapture   # 单档 perf（配 /usr/bin/time -l 采 RSS）

#![allow(non_snake_case)] // 测试名带 _attack_T9 等攻击标签后缀（防回归语义漂移）

use std::path::PathBuf;

use starknet_crypto::{poseidon_hash_many, Felt};

use hand_verify_native::combined::{action_log_domain, build_settle_statement, segment_magic};
use hand_verify_native::foldagg::{
    aggregate_nonces, aggregate_sign, build_batch_wire, challenge_raw, claim_word,
    cm_digest_from_wire, ec_order_felt, expected_public_output, fold_acc, host_verify_batch,
    key_coeff_raw, mint_fold_hands, mint_roster_sks, msg_digest, nonce_commit, prove_fold_batch,
    prove_fold_batch_unchecked, roster_digest, roster_pks_from_sks, verify_equation, FOLD_SEGMENT_LEN,
    FOLD_ROSTER_INDEX, HAND_BLOCK_WORDS, KEYAGG_STEPS_ANCHOR, COMBINED_PER_HAND_STEPS,
    SETTLE_WORDS, NonceCommit,
};
use hand_verify_native::recurse::write_prod_params;

// ---------------------------------------------------------------------------
// 公共 fixture
// ---------------------------------------------------------------------------

const KAT_SEED: u64 = 0xFA17;

fn out_dir(tag: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("output/fold-batch-test")
        .join(tag);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

fn det(seed: u64, i: u64) -> Felt {
    poseidon_hash_many(&[Felt::from(seed), Felt::from(i), Felt::from(0xF01Du64)])
}

/// 铸一条确定性诚实 settle wire（98 词，settlement_stmt 布局；指定
/// hand_binding；空动作日志、双席零和）——KAT 与攻击负例共用的槽词来源。
fn settle_wire(hand_id: u64, hb: Felt, seed: u64) -> Vec<Felt> {
    let players: Vec<Felt> = (0..2u64).map(|i| det(seed, 50 + i) + Felt::ONE).collect();
    let deltas: Vec<i128> = vec![1_000_000, -1_000_000];
    let cms: Vec<Felt> = (0..8u64).map(|i| det(seed, 60 + i)).collect();
    let ald = poseidon_hash_many(&[action_log_domain()]);
    build_settle_statement(hand_id, hb, &players, &deltas, &cms, ald, &[])
        .expect("settle statement must build")
        .wire_words()
}

/// 诚实批：P 人 roster + K 手（确定性），返回 (roster_pks, hands, anchor)。
fn honest_batch(players: usize, k_hands: usize, seed: u64) -> (
    Vec<(Felt, Felt)>,
    Vec<hand_verify_native::foldagg::AggregatedHand>,
    hand_verify_native::foldagg::RosterAnchor,
) {
    let sks = mint_roster_sks(players, seed);
    let pks = roster_pks_from_sks(&sks);
    let hand_seeds: Vec<u64> = (0..k_hands as u64).map(|i| seed * 1000 + i).collect();
    let hands = mint_fold_hands(&pks, &hand_seeds, seed).expect("honest mint");
    let anchor = expected_public_output(Felt::ZERO, &pks, &hands);
    (pks, hands, anchor)
}

/// canonical_small 参数（L1 批量终证腿钉扎参数集——与基线对比同口径）。
fn canonical_params() -> Option<PathBuf> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root")
        .join("proving-tool/params/canonical_small.json");
    p.exists().then_some(p)
}

// ---------------------------------------------------------------------------
// T4 —— host-parity 断言（改性：切片无注册面；对 soundness 零证明力）
// ---------------------------------------------------------------------------

/// **T4（改性，_attack_T4）**：foldagg 公式层自洽——roster_digest 输出 ==
/// H(pks) 且 P̄ == keyagg(pks)。**注明：这是 host 公式对拍，只检测公式/实现
/// 漂移，对 soundness 零证明力**——「wire pks == 注册 pks」的闭合点在生产
/// roster_registry（合约对照 segment[16]），切片负例见 T9/T10。
#[test]
fn t4_host_parity_roster_digest_and_pbar_attack_T4() {
    let (pks, hands, anchor) = honest_batch(5, 3, KAT_SEED);
    // roster_digest == H(pks)（独立内联重算，双路径一致）
    let mut words = vec![hand_verify_native::foldagg::roster_label(), Felt::from(5u64)];
    for (x, y) in &pks {
        words.push(*x);
        words.push(*y);
    }
    assert_eq!(anchor.roster_digest, poseidon_hash_many(&words));
    assert_eq!(anchor.roster_digest, roster_digest(&pks));
    // P̄ == keyagg(pks)：每手 c 都由同一 P̄ 签出（aggregate_sign 内部一次），
    // host 直验全过即 P̄ 公式与签名方程自洽
    host_verify_batch(&pks, &hands).expect("host parity");
    // 换任意一席 pk → roster_digest 必变（公式绑定性）
    let mut pks2 = pks.clone();
    pks2[0] = roster_pks_from_sks(&[det(KAT_SEED, 999)])[0];
    assert_ne!(roster_digest(&pks2), anchor.roster_digest);
}

// ---------------------------------------------------------------------------
// T8 —— KAT：BDN 域标签 / μ / M_h 真槽 / c / cm_digest 逐 felt 钉死
// ---------------------------------------------------------------------------

/// 固定 2 人 KAT fixture 的公式值（与 fold_batch.cairo 逐 felt parity 的
/// 期望侧；十六进制钉死防域分离/换序回归）。生产形状：M_h 真槽取自
/// settle wire——m1 = wire[1]（registered_digest，由语句 digest 公式定）、
/// m2 = wire[2]（n_expected = 2）、cm_digest = poseidon(wire[28..=35])
/// （8 词 c0..c7 压缩，Q-2）。
fn kat_fixture() -> (Vec<(Felt, Felt)>, hand_verify_native::foldagg::AggregatedHand) {
    let sks = vec![det(KAT_SEED, 0), det(KAT_SEED, 1)];
    let ws = vec![det(KAT_SEED, 100), det(KAT_SEED, 101)];
    let hb = det(KAT_SEED, 7);
    let settle = settle_wire(1, hb, KAT_SEED);
    let agg = aggregate_sign(&sks, &ws, &settle).expect("kat mint");
    let pks = roster_pks_from_sks(&sks);
    (pks, agg)
}

#[test]
fn t8_kat_labels_mu_mh_c_pinned_attack_T8() {
    let (pks, agg) = kat_fixture();
    // 域标签逐字节（ASCII short-string felt，与 Cairo '...' 字面量同编码）
    let ascii = |s: &str| {
        let b = s.as_bytes();
        let mut buf = [0u8; 32];
        buf[32 - b.len()..].copy_from_slice(b);
        Felt::from_bytes_be(&buf)
    };
    assert_eq!(hand_verify_native::foldagg::keyagg_label(), ascii("poker/fold-batch/keyagg.v1"));
    assert_eq!(hand_verify_native::foldagg::roster_label(), ascii("poker/fold-batch/roster.v1"));
    assert_eq!(hand_verify_native::foldagg::m_label(), ascii("poker/fold-batch/msg.v1"));
    assert_eq!(hand_verify_native::foldagg::sig_label(), ascii("poker/fold-batch/sig.v1"));
    assert_eq!(hand_verify_native::foldagg::claim_label(), ascii("poker/fold-batch/claim.v1"));

    // μ_0 / roster_digest —— 字节钉死（poseidon_hash_many 出口）
    let mu0 = key_coeff_raw(2, pks[0].0, pks[0].1);
    assert_eq!(
        mu0,
        Felt::from_hex(KAT_MU0).expect("kat mu0"),
        "μ_0 drifted: keyagg domain shape changed"
    );
    assert_eq!(
        agg.roster_digest,
        Felt::from_hex(KAT_ROSTER_DIGEST).expect("kat rd"),
        "roster_digest drifted"
    );

    // M_h 真槽（D2）：m1 = wire[1]、m2 = wire[2]、cm_digest = poseidon(wire[28..=35])
    let m1 = agg.hand.m1();
    let m2 = agg.hand.m2();
    let cm_digest = agg.hand.cm_digest();
    assert_eq!(
        m1,
        Felt::from_hex(KAT_M1).expect("kat m1"),
        "m1 slot drifted: registered_digest (wire[1]) formula changed"
    );
    assert_eq!(m2, Felt::from(2u64), "m2 slot must be wire[2] n_expected");
    assert_eq!(
        cm_digest,
        Felt::from_hex(KAT_CM_DIGEST).expect("kat cm_digest"),
        "cm_digest drifted: 8-word c0..c7 compression (wire[28..=35]) changed"
    );
    // 两路径一致：独立内联重算 cm_digest 与 FoldHand 派生同值
    assert_eq!(cm_digest, cm_digest_from_wire(&agg.hand.settle));
    let m_h = msg_digest(agg.hand.hand_binding(), m1, m2, cm_digest, agg.roster_digest);
    assert_eq!(m_h, agg.m_h, "host M_h two-path mismatch");
    assert_eq!(
        agg.m_h,
        Felt::from_hex(KAT_MH).expect("kat M_h"),
        "M_h drifted: message slot shape changed"
    );
    assert_eq!(
        agg.c,
        Felt::from_hex(KAT_C).expect("kat c"),
        "challenge c drifted"
    );
    // c 为 raw felt（poseidon 出口，不显式 mod n——群阶自动归约纪律，
    // 与电路 add_mul 同出口；verify_equation 的 host 侧同样 raw 进 EC）。
    let _ = ec_order_felt();
}

// KAT 钉值（固定 fixture：seed 0xFA17、2 人 roster、settle wire 由
// settle_wire(1, det(0xFA17,7), 0xFA17) 派生；改动 = 域分离/换序/槽位漂移，
// T8 必红）。KAT_MU0/KAT_ROSTER_DIGEST 沿用切片轮钉值（roster 侧公式与
// fixture 未变）；M_h 真槽/8 词 cm 压缩随生产版重钉（Q-2）：
const KAT_MU0: &str = "0340622f9a217eb20b2b9351112177337faa294eb02c0fb5035bfd3e8ac17ce6";
const KAT_ROSTER_DIGEST: &str = "04ac85cd07aebad095fef54ed9a8456effe0e05f56e6b30f074fbfc0a65817ce";
const KAT_M1: &str = "0579bd25d99b3c011f316568bd440da7f44fec8460b62e4caef2a675672241fc";
const KAT_CM_DIGEST: &str = "07329cda3409da1dd910e55e83172d7b929e1abde6fb73eaf316201ebf89af5d";
const KAT_MH: &str = "441193921bf8aa1ee109e51a3941b27d4fc40495132ba3caf4e82d393f898db";
const KAT_C: &str = "4c1d844328471adac952b0a3b5b5feb422b54f3f9368584311a447eba0b7020";

// ---------------------------------------------------------------------------
// host 负例（公式层，不需要 prove-hand——门禁常跑）
// ---------------------------------------------------------------------------

/// **T2 host 面**：z̄+1 → RESIDUAL_NOT_IDENTITY（电路 panic 的 host 对偶）。
#[test]
fn t2_host_zbar_plus_one_rejects_attack_T2() {
    let (_pks, agg) = kat_fixture();
    let err = verify_equation(agg.pbar, agg.hand.rbar, agg.c, agg.hand.zbar + Felt::ONE)
        .expect_err("z̄+1 must fail");
    assert_eq!(err, "RESIDUAL_NOT_IDENTITY");
}

/// **T3 host 面**：跨手重放 (R̄,z̄) → 换 hand_binding 改 c → 拒。
#[test]
fn t3_host_cross_hand_replay_rejects_attack_T3() {
    let (pks, hands, _anchor) = honest_batch(2, 2, KAT_SEED + 1);
    let h1 = &hands[0];
    let hb2 = hands[1].hand.hand_binding();
    // 用 h1 的 (R̄,z̄) + h2 的 binding 重算 c：必不闭合
    let pbar = hand_verify_native::foldagg::agg_pubkey(&pks).expect("pbar");
    let m_h2 = msg_digest(hb2, h1.hand.m1(), h1.hand.m2(), h1.hand.cm_digest(), h1.roster_digest);
    let c_replay = challenge_raw(hb2, m_h2, pbar, h1.hand.rbar);
    assert_ne!(c_replay, h1.c, "challenge must bind hand_binding");
    let err = verify_equation(pbar, h1.hand.rbar, c_replay, h1.hand.zbar).expect_err("replay");
    assert_eq!(err, "RESIDUAL_NOT_IDENTITY");
    // claim 绑定：不同 binding 的 M_h 必得不同 claim
    assert_ne!(claim_word(h1.hand.hand_binding(), h1.m_h), claim_word(hb2, m_h2));
}

/// **T6 host 面**：off-curve / 恒等点 fail-closed（满阶依据：n 素 /
/// cofactor=1 / 无 2-torsion，审方 F-1 实测——on-curve + 非恒等即满阶，
/// 电路 panic 标签与之逐字对应）。
#[test]
fn t6_host_off_curve_and_identity_fail_closed_attack_T6() {
    let g = hand_verify_native::curve::Point::generator();
    let (gx, gy) = g.to_affine().unwrap();
    // off-curve R̄
    let err = verify_equation((gx, gy), (gx, gy + Felt::ONE), Felt::ONE, Felt::ONE)
        .expect_err("off-curve R̄");
    assert_eq!(err, "RBAR_OFF_CURVE");
    // 恒等 P̄（(0,0) 编码：x=y=0 不在曲线上——用 from_affine=None 判恒等）
    let err = verify_equation((Felt::ZERO, Felt::ZERO), (gx, gy), Felt::ONE, Felt::ONE)
        .expect_err("identity-encoded P̄");
    assert!(err.contains("OFF_CURVE") || err.contains("IDENTITY"), "err: {err}");
    // z̄ 出域（≥ n）
    let err = verify_equation((gx, gy), (gx, gy), Felt::ONE, ec_order_felt())
        .expect_err("z̄ ≥ n");
    assert_eq!(err, "ZBAR_OUT_OF_RANGE");
}

/// **BDN 三轮镜像**：nonce 承诺 roundtrip + 篡改 R 揭露（NONCE_COMMIT_MISMATCH）。
#[test]
fn bdn_three_round_nonce_commitment_mirror() {
    let ws = vec![det(KAT_SEED, 300), det(KAT_SEED, 301), det(KAT_SEED, 302)];
    let commits: Vec<NonceCommit> = ws.iter().map(|w| nonce_commit(*w)).collect();
    let rbar = aggregate_nonces(&commits).expect("round2");
    // R̄ == Σ w_i·G（独立重算）
    let g = hand_verify_native::curve::Point::generator();
    let mut expect = hand_verify_native::curve::Point::identity();
    for w in &ws {
        expect = expect + g.mul(*w);
    }
    assert_eq!(Some(rbar), expect.to_affine());
    // 篡改揭出的 R → 承诺验证 fail-closed
    let mut bad = commits.clone();
    bad[1].r = (bad[1].r.0 + Felt::ONE, bad[1].r.1);
    let err = aggregate_nonces(&bad).expect_err("commit mismatch");
    assert_eq!(err, "NONCE_COMMIT_MISMATCH");
}

/// wire 形状：build_batch_wire 词数 = 2 + 2P + 101K，每手块 = settle 98 词
/// + (R̄x, R̄y, z̄)（电路头注释同布局；槽位锚逐位检查）。
#[test]
fn wire_layout_matches_circuit_contract() {
    let (pks, hands, _anchor) = honest_batch(3, 4, KAT_SEED + 2);
    let wire = build_batch_wire(&pks, &hands.iter().map(|h| h.hand.clone()).collect::<Vec<_>>());
    assert_eq!(wire.len(), 2 + 2 * 3 + HAND_BLOCK_WORDS * 4);
    assert_eq!(wire[0], Felt::from(3u64)); // P
    assert_eq!(wire[1 + 2 * 3], Felt::from(4u64)); // K
    for (j, h) in hands.iter().enumerate() {
        let base = 2 + 2 * 3 + HAND_BLOCK_WORDS * j;
        // settle 98 词原样摊平（hand_id@0、registered_digest@1、
        // n_expected@2、hand_binding@3、cm 槽@28..=35……）
        assert_eq!(&wire[base..base + SETTLE_WORDS], h.hand.settle.as_slice());
        assert_eq!(wire[base + 3], h.hand.hand_binding());
        // 签名见证紧跟 settle wire
        assert_eq!(wire[base + SETTLE_WORDS], h.hand.rbar.0);
        assert_eq!(wire[base + SETTLE_WORDS + 1], h.hand.rbar.1);
        assert_eq!(wire[base + SETTLE_WORDS + 2], h.hand.zbar);
    }
}

/// M_h 真槽对拍：m1/m2/cm_digest 从 settle wire 槽位派生（D2）——
/// m2（n_expected=2）≠ roster 人数（3）即证槽语义独立于 roster 规模。
#[test]
fn mh_slots_derive_from_settle_wire() {
    let (pks, hands, _anchor) = honest_batch(3, 1, KAT_SEED + 4);
    let h = &hands[0];
    assert_eq!(pks.len(), 3);
    assert_eq!(h.hand.m1(), h.hand.settle[1], "m1 must be wire[1] registered_digest");
    assert_eq!(h.hand.m2(), h.hand.settle[2], "m2 must be wire[2] n_expected");
    assert_ne!(h.hand.m2(), Felt::from(pks.len() as u64), "m2 ≠ roster size（槽语义独立）");
    assert_eq!(h.hand.cm_digest(), cm_digest_from_wire(&h.hand.settle));
    // 篡改任一 cm 槽词 → cm_digest 必变 → M_h 必变（共签消息绑定）
    let mut tampered = h.hand.settle.clone();
    tampered[SETTLE_CM_SLOT] = tampered[SETTLE_CM_SLOT] + Felt::ONE;
    assert_ne!(cm_digest_from_wire(&tampered), h.hand.cm_digest());
    let mh2 = msg_digest(h.hand.hand_binding(), h.hand.m1(), h.hand.m2(), cm_digest_from_wire(&tampered), h.roster_digest);
    assert_ne!(mh2, h.m_h);
}

/// cm 槽起点（settle wire[28..=35]，settlement_stmt.cairo :194 布局）。
const SETTLE_CM_SLOT: usize = 28;

/// acc 链公式对拍：expected acc == fold_acc(0, claims)（两路径一致）。
#[test]
fn acc_chain_formula_parity() {
    let (pks, hands, anchor) = honest_batch(2, 5, KAT_SEED + 3);
    let claims: Vec<Felt> = hands.iter().map(|h| h.claim).collect();
    assert_eq!(anchor.expected_acc, fold_acc(Felt::ZERO, &claims));
    // 链推进：换 prev_acc 必改期望输出（T5 门的形式依据）
    let anchor2 = expected_public_output(Felt::ONE, &pks, &hands);
    assert_ne!(anchor2.expected_acc, anchor.expected_acc);
}

// ---------------------------------------------------------------------------
// heavy：真 prove-hand 电路跑（#[ignore]；--release -- --ignored --nocapture）
// ---------------------------------------------------------------------------

/// **T1 正例**：2/5/8 人诚实聚合，K=8 手批 → verified + 17 词段形状
/// （[acc]++语句段(15)++[roster_digest]）双 parity + 独立复验。bench 表列
/// = steps / trace rows / EC_OP / poseidon / prove ms / total ms / proof B。
#[test]
#[ignore]
fn t1_honest_fold_batch_roundtrip() {
    let params = canonical_params();
    for players in [2usize, 5, 8] {
        let (pks, hands, anchor) = honest_batch(players, 8, KAT_SEED + players as u64);
        let t = std::time::Instant::now();
        let outcome = prove_fold_batch(
            Felt::ZERO,
            &pks,
            &hands,
            &anchor,
            &out_dir(&format!("t1-p{players}-k8")),
            params.as_deref(),
        )
        .expect("honest fold batch must prove");
        let wall = t.elapsed();
        assert!(outcome.ec_ops > 0, "EC must ride EC_OP in the cairo trace");
        assert!(outcome.cairo_acc == anchor.expected_acc);
        assert!(outcome.cairo_roster_digest == anchor.roster_digest);
        // 生产段形状（D1）：K 段 × 17 词；acc@0 与 roster_digest@16 批常量
        // 同值；MAGIC@1 = 'SP2M_OK'（combined 信封同位）
        assert_eq!(outcome.segments.len(), 8);
        for seg in &outcome.segments {
            assert_eq!(seg.len(), FOLD_SEGMENT_LEN);
            assert_eq!(seg[0], anchor.expected_acc);
            assert_eq!(seg[1], segment_magic(), "segment[1] must be MAGIC 'SP2M_OK'");
            assert_eq!(seg[FOLD_ROSTER_INDEX], anchor.roster_digest);
        }
        println!(
            "| T1 P={players} K=8 | steps {} | trace_rows(padded) {} | EC_OP {} | poseidon {} | \
             total {} ms (compile {} / run {} / prove {}) | reverify {} ms | proof {} B |",
            outcome.steps,
            outcome.steps.next_power_of_two(),
            outcome.ec_ops,
            outcome.poseidon_ops,
            outcome.total_ms,
            outcome.cairo_compile_ms,
            outcome.cairo_run_ms,
            outcome.cairo_prove_ms,
            outcome.check_verify_ms,
            outcome.proof_bytes,
        );
        assert!(wall.as_secs() < 120, "order-of-magnitude regression: {wall:?}");
    }
}

/// **T2**：篡改 z̄+1 → 电路 panic → 无证明（无 proof.json 产出）。
#[test]
#[ignore]
fn t2_zbar_plus_one_panics_no_proof_attack_T2() {
    let (pks, hands, _anchor) = honest_batch(2, 2, KAT_SEED + 10);
    let mut wire_hands: Vec<hand_verify_native::foldagg::FoldHand> =
        hands.iter().map(|h| h.hand.clone()).collect();
    wire_hands[1].zbar = wire_hands[1].zbar + Felt::ONE;
    let dir = out_dir("t2-zbar-plus-one");
    let err = prove_fold_batch_unchecked(Felt::ZERO, &pks, &wire_hands, &dir, None)
        .expect_err("tampered z̄ must not prove");
    assert!(err.contains("circuit rejected"), "unexpected: {err}");
    assert!(!dir.join("proof.json").exists(), "panic must leave no proof");
}

/// **T3**：跨手重放——手 2 携手 1 的 (R̄,z̄)（settle wire 不同 → binding
/// 不同）→ 电路 panic。
#[test]
#[ignore]
fn t3_cross_hand_replay_panics_attack_T3() {
    let (pks, hands, _anchor) = honest_batch(2, 2, KAT_SEED + 11);
    let replayed = hand_verify_native::foldagg::FoldHand {
        settle: hands[1].hand.settle.clone(),
        rbar: hands[0].hand.rbar,
        zbar: hands[0].hand.zbar,
    };
    let wire_hands = vec![hands[0].hand.clone(), replayed];
    let dir = out_dir("t3-cross-hand-replay");
    let err = prove_fold_batch_unchecked(Felt::ZERO, &pks, &wire_hands, &dir, None)
        .expect_err("cross-hand replay must not prove");
    assert!(err.contains("circuit rejected"), "unexpected: {err}");
}

/// **T5**：伪造 prev_acc → 电路照常出证，公开 acc 偏离注册链期望 → parity 门拒
/// （recurse.rs:485-499 同款；acc 门 = 链状态的切片消费面）。
#[test]
#[ignore]
fn t5_forged_prev_acc_parity_gate_rejects_attack_T5() {
    let params = canonical_params();
    let (pks, hands, anchor) = honest_batch(2, 2, KAT_SEED + 12);
    let forged_prev = Felt::ONE; // 诚实链 prev = 0
    let err = prove_fold_batch(
        forged_prev,
        &pks,
        &hands,
        &anchor,
        &out_dir("t5-forged-prev"),
        params.as_deref(),
    )
    .expect_err("forged prev_acc must be caught");
    assert!(err.contains("acc parity failure"), "unexpected: {err}");
}

/// **T6**：off-curve / 恒等 roster 点 → 电路 panic（fail-closed）。
#[test]
#[ignore]
fn t6_off_curve_pk_panics_attack_T6() {
    let (pks, hands, _anchor) = honest_batch(2, 1, KAT_SEED + 13);
    let (gx, gy) = hand_verify_native::curve::Point::generator().to_affine().unwrap();
    // (a) off-curve pk（y+1）
    let mut off = pks.clone();
    off[1] = (off[1].0, off[1].1 + Felt::ONE);
    let dir = out_dir("t6-off-curve");
    let err = prove_fold_batch_unchecked(
        Felt::ZERO,
        &off,
        &hands.iter().map(|h| h.hand.clone()).collect::<Vec<_>>(),
        &dir,
        None,
    )
    .expect_err("off-curve pk must panic");
    assert!(err.contains("circuit rejected"), "unexpected: {err}");
    // (b) 恒等编码 pk：(0, 0)
    let mut ident = pks.clone();
    ident[1] = (Felt::ZERO, Felt::ZERO);
    let dir = out_dir("t6-identity-pk");
    let err = prove_fold_batch_unchecked(
        Felt::ZERO,
        &ident,
        &hands.iter().map(|h| h.hand.clone()).collect::<Vec<_>>(),
        &dir,
        None,
    )
    .expect_err("identity pk must panic");
    assert!(err.contains("circuit rejected"), "unexpected: {err}");
    let _ = (gx, gy);
}

/// **T9（_attack_A1，forge0 复现形状）**：wire pks 全换攻击者钥、攻击者对
/// 自己 roster 诚实自签（settle wire/槽词与诚实手相同——攻「签名身份」不攻
/// 消息）→ 电路算术自洽**照样出证**（证明 wire pks 在电路内仍自由——这就是
/// 修复 1 第 3 步把 roster_digest 推成公开输出词的原因）；断言点 = 出证后
/// host parity 门拒（cairo roster_digest ≠ 注册锚）。生产对应 = 合约
/// roster_registry 对照 segment[16]（H1 单射）。
#[test]
#[ignore]
fn t9_forge0_attacker_roster_parity_gate_rejects_attack_A1() {
    let params = canonical_params();
    // 注册面（host 模拟）：诚实 2 人 roster 的锚
    let (_hpks, hhands, anchor) = honest_batch(2, 1, KAT_SEED + 20);
    // 攻击者：整批换钥 + 自签（同一 settle wire——攻「签名身份」不攻消息）
    let attacker_sks = vec![det(KAT_SEED, 777), det(KAT_SEED, 778)];
    let apks = roster_pks_from_sks(&attacker_sks);
    let ws = vec![det(KAT_SEED, 779), det(KAT_SEED, 780)];
    let forged =
        aggregate_sign(&attacker_sks, &ws, &hhands[0].hand.settle).expect("attacker self-sign");
    // 电路必须接受（攻击者的聚合签名对自己的 roster 成立）
    let dir = out_dir("t9-forge0");
    let proved = prove_fold_batch(
        Felt::ZERO,
        &apks,
        &[forged.clone()],
        // 锚仍是诚实 roster 的注册值——攻击者的 roster_digest 对照不上
        &anchor,
        &dir,
        params.as_deref(),
    );
    let err = proved.expect_err("attacker roster must be caught by the parity gate");
    assert!(
        err.contains("roster digest parity failure"),
        "unexpected failure mode: {err}"
    );
}

/// **T10（_attack_A2，agg1_forge 形状）**：整组换 roster（n=1 单钥）+
/// 自签 → 同 T9，出证后 parity 门拒。
#[test]
#[ignore]
fn t10_agg1_forge_swapped_roster_rejected_attack_A2() {
    let params = canonical_params();
    let (_hpks, hhands, anchor) = honest_batch(2, 1, KAT_SEED + 21);
    let attacker_sks = vec![det(KAT_SEED, 887)];
    let apks = roster_pks_from_sks(&attacker_sks);
    let ws = vec![det(KAT_SEED, 888)];
    let forged =
        aggregate_sign(&attacker_sks, &ws, &hhands[0].hand.settle).expect("attacker self-sign");
    let err = prove_fold_batch(
        Felt::ZERO,
        &apks,
        &[forged],
        &anchor,
        &out_dir("t10-agg1-forge"),
        params.as_deref(),
    )
    .expect_err("swapped roster must be caught");
    assert!(err.contains("roster digest parity failure"), "unexpected: {err}");
}

/// **T11（T9 正控，_attack_A1）**：攻击者 roster + z̄+1 → 电路 panic——
/// 确认「电路残差非恒等」这条保险对非签名活跃（防 T9 因电路坏而假阳性）。
#[test]
#[ignore]
fn t11_forged_roster_zbar_plus_one_panics_attack_A1_control() {
    let attacker_sks = vec![det(KAT_SEED, 777), det(KAT_SEED, 778)];
    let apks = roster_pks_from_sks(&attacker_sks);
    let ws = vec![det(KAT_SEED, 779), det(KAT_SEED, 780)];
    let hb = det(KAT_SEED, 20);
    let settle = settle_wire(11, hb, KAT_SEED + 30);
    let mut forged = aggregate_sign(&attacker_sks, &ws, &settle).expect("attacker self-sign");
    forged.hand.zbar = forged.hand.zbar + Felt::ONE;
    let dir = out_dir("t11-forge-zbar-plus-one");
    let err = prove_fold_batch_unchecked(Felt::ZERO, &apks, &[forged.hand], &dir, None)
        .expect_err("z̄+1 on forged roster must panic");
    assert!(err.contains("circuit rejected"), "unexpected: {err}");
}

/// **T12（T10 正控，_attack_A2）**：n=1 换 roster + z̄+1 → 电路 panic。
#[test]
#[ignore]
fn t12_swapped_roster_zbar_plus_one_panics_attack_A2_control() {
    let attacker_sks = vec![det(KAT_SEED, 887)];
    let apks = roster_pks_from_sks(&attacker_sks);
    let ws = vec![det(KAT_SEED, 888)];
    let hb = det(KAT_SEED, 30);
    let settle = settle_wire(12, hb, KAT_SEED + 31);
    let mut forged = aggregate_sign(&attacker_sks, &ws, &settle).expect("attacker self-sign");
    forged.hand.zbar = forged.hand.zbar + Felt::ONE;
    let dir = out_dir("t12-n1-zbar-plus-one");
    let err = prove_fold_batch_unchecked(Felt::ZERO, &apks, &[forged.hand], &dir, None)
        .expect_err("z̄+1 on n=1 roster must panic");
    assert!(err.contains("circuit rejected"), "unexpected: {err}");
}

/// **T7 perf**：K=1/8/32/64 @ P=8，生产形状 steps + 耗时扫描（RSS 由外层
/// `/usr/bin/time -l` 采集）。验收线（生产形状，提案 §3.1 诚实边界）：
/// K=1 总量 ≤ combined 每手 12,160 + keyagg 批固定层 1,628（一批只付一次）；
/// 批量边际 ≤ combined 每手 12,160（steps 轴底线——生产 fold ≈11.3k/手
/// 估算 = keyagg 1,628 + 结算边际 9,405 + 签名层；结构性收益在单批单证/
/// fact 密度 64×，不在 steps）；批 ≤ 2^20 桶。`FOLD_PERF_ONLY=<K>` 只跑
/// 单档（分档采 RSS 用）。
#[test]
#[ignore]
fn t7_perf_sweep_steps_gate() {
    let players = 8usize;
    let pks = roster_pks_from_sks(&mint_roster_sks(players, KAT_SEED + 42));
    let sizes: &[usize] = if let Ok(only) = std::env::var("FOLD_PERF_ONLY") {
        &[only.parse().expect("FOLD_PERF_ONLY must be a number")]
    } else {
        &[1, 8, 32, 64]
    };
    let params = canonical_params();
    println!("| P | K | wire | steps | rows(2^) | EC_OP | poseidon | prove ms | total ms | proof B | per-hand |");
    println!("|---|---|------|-------|----------|-------|----------|----------|----------|---------|----------|");
    let mut step_rows: Vec<(usize, u64)> = Vec::with_capacity(sizes.len());
    for &k in sizes {
        let hand_seeds: Vec<u64> = (0..k as u64).map(|i| KAT_SEED * 100 + i).collect();
        let hands = mint_fold_hands(&pks, &hand_seeds, KAT_SEED + 42).expect("mint");
        let anchor = expected_public_output(Felt::ZERO, &pks, &hands);
        let outcome = prove_fold_batch(
            Felt::ZERO,
            &pks,
            &hands,
            &anchor,
            &out_dir(&format!("t7-k{k}")),
            params.as_deref(),
        )
        .expect("perf run must prove");
        println!(
            "| {} | {} | {} | {} | 2^{} | {} | {} | {} | {} | {} | {} |",
            players,
            k,
            outcome.wire_words,
            outcome.steps,
            outcome.steps.next_power_of_two().ilog2(),
            outcome.ec_ops,
            outcome.poseidon_ops,
            outcome.cairo_prove_ms,
            outcome.total_ms,
            outcome.proof_bytes,
            outcome.steps / k as u64,
        );
        step_rows.push((k, outcome.steps));
    }
    // 验收线（生产形状）：K=1（keyagg 批固定层 + 1 手）与批量边际都不得
    // 劣于 combined 每手整证口径
    let k1 = step_rows.iter().find(|(k, _)| *k == 1).map(|(_, s)| *s);
    if let Some(s1) = k1 {
        assert!(
            s1 <= COMBINED_PER_HAND_STEPS + KEYAGG_STEPS_ANCHOR,
            "K=1 (keyagg + 1 hand) steps {s1} > combined per-hand {COMBINED_PER_HAND_STEPS} + keyagg anchor {KEYAGG_STEPS_ANCHOR}"
        );
        for &(k, s) in &step_rows {
            if k > 1 {
                let marginal = (s - s1) / (k as u64 - 1);
                assert!(
                    marginal <= COMBINED_PER_HAND_STEPS,
                    "per-hand marginal {marginal} > combined per-hand {COMBINED_PER_HAND_STEPS} at K={k}"
                );
            }
        }
    }
    for &(_, s) in &step_rows {
        assert!(s <= (1u64 << 20), "batch steps {s} exceed the 2^20 bucket");
    }
}

/// prod 参数辅助复用检查（recurse 的 write_prod_params 在本切片可用作快速档）。
#[test]
fn prod_params_helper_writable() {
    let dir = out_dir("params-prod");
    let p = write_prod_params(&dir).expect("params");
    assert!(p.exists());
}
