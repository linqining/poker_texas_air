//! fold/combined 双跑对拍（规格 out/fold-spec.md §5/D5）——同一 settle 语料
//! 双吃：combined 腿逐手 16 词信封、fold 腿一批 K 手 17 词段，跨腿对拍。
//!
//! 两个形态（形态按规格 D5，本文件承载两档）：
//!
//! 1. **轻量 host 对拍**（默认门禁，`fold_combined_parity_same_settle_corpus_host`）：
//!    不出证——两腿各走 host 期望侧，同一 98 词 wire 单一来源：
//!    - combined 腿：诚实 action 任务 `host_fold_tasks` 直验折叠出 acc 链，
//!      信封 = `[acc] ++ expected_segment(15)`（combined.cairo 输出同形）；
//!    - fold 腿：生产 D2 真槽映射（m1←wire[1]、m2←wire[2]、hand_binding←wire[3]、
//!      cm_digest←poseidon(wire[28..=35])）→ claim → 批终 acc =
//!      `fold_acc(prev, claims)`（批级，Q-1）→ 段 = `[批终 acc] ++
//!      expected_segment(15) ++ [roster_digest]`（D1 布局）；
//!    - 断言 = D5 机器化 3a（跨腿 word 1..=15 逐词相等）/ 3b（fold 批 acc
//!      两路径一致）/ 3c（slot 16 == roster 注册面锚）+ D2 槽位钉死 + D2a
//!      ald 传递绑定演示。**对 soundness 零证明力**（T4 语义：只钉公式/
//!      映射/布局漂移；「wire pks == 注册 pks」的闭合点在生产 roster_registry
//!      合约对照，fold_batch_test T9/T10 与合约负例臂承载）。
//!
//! 2. **heavy 出证腿**（`#[ignore]`，`t13_fold_combined_parity_heavy_prove_roundtrip`，
//!    D5.1–3/5 全形）：combined 腿逐手 `prove_combined_layer`（其内部 acc/
//!    segment 双 parity 门即该腿既有机器核对，D5.2）、fold 腿 `prove_fold_batch`
//!    一次吃 8 手（其内部「出证后」roster/acc/段 parity 门 + `--check-only`
//!    独立复验即 D5.5 门序纪律与 D5.3d）；断言 = fold 段 word 1..=15 ==
//!    combined 输出 word 1..=15（跨腿主对拍）+ 逐链 acc/roster 锚出证后对照。
//!
//! **明确不断言**（D5.4）：combined chain_acc == fold acc。两链 claim 公式
//! 不同源——combined claim = poseidon([hand_binding, payload_digest, 桶计数…])
//! 无域标签（combined.cairo claim_preimage）；fold claim = poseidon([CLAIM_LABEL,
//! hand_binding, M_h])（fold_batch.cairo:152）。两条 acc 链是**有意的两个
//! 对象**：parity 只做逐链 host 重算一致 + 跨腿结算词一致，无跨链 acc 比较。
//!
//! 运行（heavy 依赖 prove-hand 二进制）：
//!   cargo test -p hand-verify-native --test fold_parity_test            # 轻量（默认门禁）
//!   cargo test --release -p hand-verify-native \
//!     --test fold_parity_test -- --ignored --nocapture                  # heavy（与 T1 同形态）
//!
//! D5.6 的合约层负例臂（未注册 roster / 16 词段 / 错哈希 fact / 重放）属
//! PokerDualSettlement 测试区（snforge），不在本 host 文件承载。

use std::path::PathBuf;

use starknet_crypto::{poseidon_hash_many, Felt};

use hand_verify_native::combined::{
    acc_fold, action_log_domain, build_settle_statement, host_verify, prove_combined_layer,
    segment_magic, SettleStatement, GENESIS,
};
use hand_verify_native::foldagg::{
    aggregate_sign, claim_word, cm_digest_from_wire, expected_public_output, fold_acc,
    mint_roster_sks, msg_digest, parse_settle_wire, prove_fold_batch, roster_digest,
    roster_pks_from_sks, AggregatedHand, FOLD_ROSTER_INDEX, FOLD_SEGMENT_LEN, SETTLE_CM_START,
    SETTLE_CM_WORDS, SETTLE_WORDS,
};
use hand_verify_native::mint::mint_hand;
use hand_verify_native::recurse::{hand_binding as task_binding, host_fold_tasks, RecurseTask};

// ---------------------------------------------------------------------------
// 公共 fixture：一张 8 人 roster × 8 手，同一 settle 语料双吃（D5.1）
// ---------------------------------------------------------------------------

const PARITY_SEED: u64 = 0x9A17;
const N_PLAYERS: usize = 8;
const K_HANDS: usize = 8;

fn det(seed: u64, i: u64) -> Felt {
    poseidon_hash_many(&[Felt::from(seed), Felt::from(i), Felt::from(0xF01Du64)])
}

/// 一手对拍语料：一条 settle 语句 + 其 98 词 wire（两腿单一来源）+ 该手的
/// 诚实 action 任务（combined 腿 claims 来源；binding 与 settle 一致）。
struct HandCorpus {
    hb: Felt,
    settle: SettleStatement,
    wire: Vec<Felt>,
    tasks: Vec<RecurseTask>,
}

/// 铸对拍语料：8 席全参与零和（席 0/1 赢、席 2..7 均摊输）、空动作日志
/// （count=0 → ald = poseidon([DOMAIN])，与 combined_test/fold T1 已证语料
/// 同形）、赢家承诺非零。`wire = settle.wire_words()` 即 fold 腿的
/// FoldHand.settle 与 combined 腿语句的共同源。
///
/// **为何语料不带非空动作日志**：log 词在电路内有语义校验（settlement_stmt
/// 「LOG_OVER_202BIT」/action ∈ {FOLD,CHECK,CALL,RAISE}/auto-legality 规则），
/// 且 host `expected_segment` 的链根公式（combined.rs:127-131 折 entry 双词）
/// 与电路重放（settlement_stmt.cairo:118 只折 log 词）在 count>0 时不同式——
/// 该分歧属 combined/settlement_stmt 两侧的既有面，不在本对拍修复范围；
/// 空日志（count=0）两式同归 poseidon([DOMAIN])，语料取此已证形状。
fn build_corpus() -> Vec<HandCorpus> {
    (0..K_HANDS as u64)
        .map(|h| {
            let hb = task_binding(PARITY_SEED * 1000 + h);
            let players: Vec<Felt> =
                (0..8u64).map(|i| det(PARITY_SEED + h, 10 + i) + Felt::ONE).collect();
            let unit = 100 * (h as i128 + 1);
            let deltas: Vec<i128> =
                vec![4 * unit, 2 * unit, -unit, -unit, -unit, -unit, -unit, -unit];
            let commitments: Vec<Felt> =
                (0..8u64).map(|i| det(PARITY_SEED + h, 30 + i)).collect();
            let ald = poseidon_hash_many(&[action_log_domain()]);
            let settle = build_settle_statement(
                500 + h,
                hb,
                &players,
                &deltas,
                &commitments,
                ald,
                &[],
            )
            .expect("honest settle statement");
            let wire = settle.wire_words();
            let tasks: Vec<RecurseTask> = (0..1u64)
                .map(|_| RecurseTask {
                    hand_binding: hb,
                    payload: mint_hand(hb, 2, 1, 0, 0, 0, PARITY_SEED + h),
                })
                .collect();
            HandCorpus { hb, settle, wire, tasks }
        })
        .collect()
}

fn out_dir(tag: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("output/fold-parity-test")
        .join(tag);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

/// canonical_small 参数（L1 批量终证腿钉扎参数集；与 fold_batch_test T1 同口径）。
fn canonical_params() -> Option<PathBuf> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("repo root")
        .join("proving-tool/params/canonical_small.json");
    p.exists().then_some(p)
}

// ---------------------------------------------------------------------------
// 轻量 host 对拍（默认门禁；T4 语义——公式/映射/布局漂移检测，零证明力）
// ---------------------------------------------------------------------------

/// **轻量 D5 host 形**：同一 98 词 settle wire 双吃——combined 腿（诚实任务
/// acc 链 + 16 词信封）vs fold 腿（D2 真槽映射 claims + 批终 acc + 17 词段）。
/// 断言：D5 3a 跨腿 word 1..=15 逐词相等、3b fold 批 acc 两路径一致、3c
/// slot 16 == roster 锚（批常量）、D2 槽位钉死（含 K-4 的 8 词 cm 压缩）、
/// D2a ald 传递绑定演示。
#[test]
fn fold_combined_parity_same_settle_corpus_host() {
    let hands = build_corpus();
    let sks = mint_roster_sks(N_PLAYERS, PARITY_SEED);
    let pks = roster_pks_from_sks(&sks);
    let roster_d = roster_digest(&pks);

    // ---- combined 腿（host 期望侧）：逐手 acc 链 + 16 词信封 ----
    let mut prev_acc = GENESIS;
    let mut envelopes: Vec<Vec<Felt>> = Vec::with_capacity(K_HANDS);
    let mut combined_claims: Vec<Felt> = Vec::with_capacity(K_HANDS);
    for (h, hc) in hands.iter().enumerate() {
        let acc = host_fold_tasks(&hc.tasks, prev_acc).expect("combined acc chain");
        // 两路径：claim 词独立重算（host 直验 → RecurseTask::claim → 折叠）
        let report = host_verify(hc.hb, &hc.tasks[0].payload).expect("host verify");
        let claim = hc.tasks[0].claim(&report);
        assert_eq!(
            acc,
            acc_fold(prev_acc, &[claim]),
            "hand {h}: combined acc 两路径一致（host_fold_tasks vs 手工折叠）"
        );
        combined_claims.push(claim);
        let segment = hc.settle.expected_segment().expect("expected segment");
        assert_eq!(segment.len(), 15);
        let mut env = Vec::with_capacity(16);
        env.push(acc);
        env.extend_from_slice(&segment);
        envelopes.push(env);
        prev_acc = acc;
    }

    // ---- fold 腿（host 期望侧）：D2 真槽映射 → claim → 批终 acc → 17 词段 ----
    let mut fold_claims: Vec<Felt> = Vec::with_capacity(K_HANDS);
    for (h, hc) in hands.iter().enumerate() {
        let w = &hc.wire;
        assert_eq!(w.len(), SETTLE_WORDS, "hand {h}: settle wire 98 词");
        // D2 槽位钉死（settlement_stmt.cairo 布局）：wire[1]=registered_digest、
        // wire[2]=n_expected、wire[3]=hand_binding、wire[28..=35]=c0..c7、
        // wire[36]=ald。
        assert_eq!(w[1], hc.settle.registered_digest, "hand {h}: wire[1] = registered_digest");
        assert_eq!(w[2], Felt::from(hc.settle.n_expected), "hand {h}: wire[2] = n_expected");
        assert_eq!(w[3], hc.hb, "hand {h}: wire[3] = hand_binding");
        assert_eq!(
            &w[SETTLE_CM_START..SETTLE_CM_START + SETTLE_CM_WORDS],
            &hc.settle.commitments[..],
            "hand {h}: wire[28..=35] = c0..c7（8 词，K-4）"
        );
        assert_eq!(w[36], hc.settle.action_log_digest, "hand {h}: wire[36] = ald");
        // cm_digest 是 8 词压缩（D2/K-4）——与切片 2 词占位压缩必不同值。
        let cm8 = cm_digest_from_wire(w);
        assert_eq!(
            cm8,
            poseidon_hash_many(&w[SETTLE_CM_START..SETTLE_CM_START + SETTLE_CM_WORDS]),
            "hand {h}: cm_digest = poseidon(wire[28..=35]) 内联一致"
        );
        assert_ne!(
            cm8,
            poseidon_hash_many(&w[SETTLE_CM_START..SETTLE_CM_START + 2]),
            "hand {h}: 8 词压缩 ≠ 切片 2 词占位（K-4 修复面）"
        );
        // M_h 三自由槽（D2）：m1←wire[1]、m2←wire[2]（不是 roster 人数占位）、
        // hand_binding←wire[3]；roster_digest 为电路内自算值（host = 注册面锚）。
        let m_h = msg_digest(w[3], w[1], w[2], cm8, roster_d);
        fold_claims.push(claim_word(w[3], m_h));
        // m2 槽活性：m2 = wire[2]（本手非零结算人数 8）≠ roster 人数占位
        // 语义混用面（8 人 roster 恰好同为 8——用另一手人数差异钉：语料全部
        // 8 参与本钉不动，改由 D2a 演示承担槽活性）。
        assert_eq!(w[2], Felt::from(8u64), "hand {h}: n_expected = 8（全席参与）");
    }
    let batch_acc = fold_acc(GENESIS, &fold_claims);
    // 3b：批终 acc 独立内联重算（poseidon([prev] ++ claims)）。
    let mut acc_in = vec![GENESIS];
    acc_in.extend_from_slice(&fold_claims);
    assert_eq!(
        batch_acc,
        poseidon_hash_many(&acc_in),
        "fold 批终 acc 两路径一致（fold_acc vs 内联 poseidon）"
    );

    // fold 17 词段装配（D1 布局）：语句段走 foldagg 自有 wire→statement
    // 解析路径（parse_settle_wire），非直接复用 combined 侧语句对象。
    let mut fold_segments: Vec<Vec<Felt>> = Vec::with_capacity(K_HANDS);
    for hc in &hands {
        let reparsed = parse_settle_wire(&hc.wire).expect("wire → statement round trip");
        let segment = reparsed.expected_segment().expect("reparsed segment");
        let mut seg = Vec::with_capacity(FOLD_SEGMENT_LEN);
        seg.push(batch_acc); // slot 0：批终 acc（Q-1，一批同值）
        seg.extend_from_slice(&segment); // word 1..=15
        seg.push(roster_d); // slot 16：roster 批常量（D1a）
        assert_eq!(seg.len(), FOLD_SEGMENT_LEN);
        fold_segments.push(seg);
    }

    // ---- D5 断言 ----
    // 3a 跨腿主对拍：fold 段 word 1..=15 == combined 信封 word 1..=15
    // （两侧同源 settlement_statement(settle)——等值才有「同账」意义）。
    for h in 0..K_HANDS {
        assert_eq!(
            fold_segments[h][1..FOLD_ROSTER_INDEX],
            envelopes[h][1..16],
            "hand {h}: fold seg words 1..=15 must equal combined envelope words 1..=15"
        );
        assert_eq!(fold_segments[h][1], segment_magic(), "hand {h}: 段首 MAGIC 锚");
    }
    // 3c roster 门：slot 16 批常量 == 注册面锚 == H(pks)。
    for (h, seg) in fold_segments.iter().enumerate() {
        assert_eq!(seg[FOLD_ROSTER_INDEX], roster_d, "hand {h}: slot 16 roster 批常量");
    }
    assert_eq!(roster_d, roster_digest(&pks), "roster 锚 == H(pks)");
    // D1 布局形状：combined 信封 16 词、fold 段 17 词（唯一新增 slot 16）。
    assert_eq!(envelopes[0].len(), 16);
    assert_eq!(fold_segments[0].len(), FOLD_SEGMENT_LEN);

    // D2a ald 传递绑定演示：改 ald 必改 registered_digest（=wire[1]=m1∈M_h）
    // 必改 claim 必改批 acc——ald 不是 M_h 独立槽，但其改动无法绕过 M_h。
    // st2 携一条合法 CALL 动作日志（log 词 = 电路 log_w 编码的 ASCII 'CALL'，
    // auto=0 ⇒ legality=0 合法；链根取电路重放式 poseidon([DOMAIN, log_w])）。
    // 仅取 expected_digest（ald 参与折叠），不调 expected_segment——
    // count>0 的链根公式 host/电路分歧见 build_corpus 注释。
    {
        let hc = &hands[0];
        let log_call = Felt::from_hex("0x43414c4c").expect("ASCII 'CALL'"); // settlement_stmt W_CALL
        let ald2 = poseidon_hash_many(&[action_log_domain(), log_call]);
        let players: Vec<Felt> =
            (0..8u64).map(|i| det(PARITY_SEED, 10 + i) + Felt::ONE).collect();
        let unit = 100i128;
        let deltas = vec![4 * unit, 2 * unit, -unit, -unit, -unit, -unit, -unit, -unit];
        let commitments: Vec<Felt> =
            (0..8u64).map(|i| det(PARITY_SEED, 30 + i)).collect();
        let st2 = build_settle_statement(
            500,
            hc.hb,
            &players,
            &deltas,
            &commitments,
            ald2,
            &[[log_call, Felt::ZERO]],
        )
        .expect("alternate-ald statement");
        assert_ne!(
            st2.expected_digest(),
            hc.settle.expected_digest(),
            "改 ald 必改 expected_digest（= wire[1] = m1 ∈ M_h，D2a）"
        );
        let m_h2 = msg_digest(
            hc.hb,
            st2.expected_digest(),
            Felt::from(8u64),
            cm_digest_from_wire(&hc.wire),
            roster_d,
        );
        assert_ne!(
            claim_word(hc.hb, m_h2),
            fold_claims[0],
            "改 ald 经 m1 必改 claim（传递绑定闭合，D2a）"
        );
    }

    // 两链 claim 公式不同源（D5.4 公式面）：同手两链 claim 词必不同——
    // combined claim 无域标签、fold claim 带 CLAIM_LABEL + M_h。
    for h in 0..K_HANDS {
        assert_ne!(
            combined_claims[h],
            fold_claims[h],
            "hand {h}: 两链 claim 词不同源（不同 preimage）"
        );
    }
    // D5.4：**无** combined acc vs fold acc 的比较断言——两条 acc 链是有意
    // 的两个对象（见模块注释），parity 只做逐链重算一致 + 跨腿结算词一致。
}

// ---------------------------------------------------------------------------
// heavy 出证腿（#[ignore]；D5.1–3/5 全形；与 T1 同运行形态）
// ---------------------------------------------------------------------------

/// **T13（heavy，D5 全形）**：同一 8 手语料双腿真出证——combined 腿逐手
/// `prove_combined_layer`（内部 acc/segment 双 parity 门 + `--check-only`，
/// D5.2）、fold 腿 `prove_fold_batch` 一次吃 8 手（内部「出证后」roster/acc/
/// 段三重 parity 门 + `--check-only` 独立复验，D5.3d/5 门序纪律）。断言 =
/// fold 段 word 1..=15 == combined 输出 word 1..=15（跨腿主对拍）+ 逐链
/// acc/roster 锚出证后对照。**不断言两链 acc 跨等**（D5.4）。
#[test]
#[ignore]
fn t13_fold_combined_parity_heavy_prove_roundtrip() {
    let params = canonical_params();
    let hands = build_corpus();
    let sks = mint_roster_sks(N_PLAYERS, PARITY_SEED);
    let pks = roster_pks_from_sks(&sks);
    let roster_d = roster_digest(&pks);
    let magic = segment_magic();

    // ---- combined 腿：逐手真出证（16 词信封 = [acc] ++ segment 15）----
    let mut prev_acc = GENESIS;
    let mut combined_envelopes: Vec<Vec<Felt>> = Vec::with_capacity(K_HANDS);
    for (h, hc) in hands.iter().enumerate() {
        let outcome = prove_combined_layer(
            &hc.tasks,
            &hc.settle,
            prev_acc,
            &out_dir(&format!("t13-combined-h{h}")),
            params.as_deref(),
        )
        .expect("combined leg must prove");
        // 从 MAGIC 锚定信封（runner 可能在输出前部有回显词，同
        // prove_combined_layer 内部定位法）。
        let mp = outcome
            .public_output
            .iter()
            .position(|w| *w == magic)
            .expect("MAGIC in combined public output");
        assert!(mp >= 1, "public output has no room for acc before MAGIC");
        let envelope: Vec<Felt> = outcome.public_output[mp - 1..mp + 15].to_vec();
        assert_eq!(envelope.len(), 16);
        combined_envelopes.push(envelope);
        prev_acc = outcome.cairo_acc;
    }

    // ---- fold 腿：8 手一批真出证（K×17 词段）----
    let mut agg_hands: Vec<AggregatedHand> = Vec::with_capacity(K_HANDS);
    for (h, hc) in hands.iter().enumerate() {
        let ws: Vec<Felt> =
            (0..N_PLAYERS as u64).map(|i| det(PARITY_SEED + h as u64, 200 + i)).collect();
        let agg = aggregate_sign(&sks, &ws, &hc.wire).expect("honest aggregate");
        // host 公式两路径：AggregatedHand.claim == 轻量映射重算（同 wire）。
        let w = &hc.wire;
        let m_h = msg_digest(w[3], w[1], w[2], cm_digest_from_wire(w), roster_d);
        assert_eq!(
            agg.claim,
            claim_word(w[3], m_h),
            "hand {h}: fold claim 两路径一致（aggregate_sign vs D2 映射重算）"
        );
        agg_hands.push(agg);
    }
    // 注册面锚（host 切片模拟）：批终 acc = fold_acc(prev, claims)、
    // roster_digest = H(pks)。**先出证、后对照**的门序由 prove_fold_batch
    // 内部承载（foldagg.rs 门序注释：电路对 wire pks 自由，锚对照在出证后）。
    let anchor = expected_public_output(GENESIS, &pks, &agg_hands);
    assert_eq!(anchor.roster_digest, roster_d);
    let fold_outcome = prove_fold_batch(
        GENESIS,
        &pks,
        &agg_hands,
        &anchor,
        &out_dir("t13-fold-k8"),
        params.as_deref(),
    )
    .expect("fold leg must prove");
    assert_eq!(fold_outcome.segments.len(), K_HANDS);

    // ---- D5 断言（全部出证后）----
    println!(
        "| leg | hands | steps | EC_OP | poseidon | prove ms | total ms | reverify ms | proof B |"
    );
    println!("|---|---|---|---|---|---|---|---|---|");
    println!(
        "| combined | 1×{} | - | - | - | - | - | - | - |（逐手出证见 output/fold-parity-test/t13-combined-h*）|",
        K_HANDS
    );
    println!(
        "| fold | {} | {} | {} | {} | {} | {} | {} | {} |",
        K_HANDS,
        fold_outcome.steps,
        fold_outcome.ec_ops,
        fold_outcome.poseidon_ops,
        fold_outcome.cairo_prove_ms,
        fold_outcome.total_ms,
        fold_outcome.check_verify_ms,
        fold_outcome.proof_bytes,
    );
    for h in 0..K_HANDS {
        let seg = &fold_outcome.segments[h];
        assert_eq!(seg.len(), FOLD_SEGMENT_LEN, "hand {h}: 17 词段");
        // 3a 跨腿主对拍：同一 settle 语料，两腿结算词零漂移。
        assert_eq!(
            seg[1..FOLD_ROSTER_INDEX],
            combined_envelopes[h][1..16],
            "hand {h}: fold seg words 1..=15 must equal combined output words 1..=15（跨腿主对拍）"
        );
        // 3c roster 门（出证后对照注册面锚；prove_fold_batch 内部已门，此处
        // 复述为对拍记录）。
        assert_eq!(seg[FOLD_ROSTER_INDEX], anchor.roster_digest, "hand {h}: slot 16 roster 锚");
        // 3b acc 门（批终 acc 一批同值；prove_fold_batch 内部已门，复述记录）。
        assert_eq!(seg[0], anchor.expected_acc, "hand {h}: slot 0 批终 acc 锚");
    }
    // 批终 acc 批常量（Q-1）：K 段 slot 0 全同值。
    let first_acc = fold_outcome.segments[0][0];
    assert!(fold_outcome.segments.iter().all(|s| s[0] == first_acc));
    // D5.4：无 combined chain acc vs fold 批 acc 的跨链比较——两条 acc 链
    // 是有意的两个对象（claim 公式不同源，见模块注释）。
}
