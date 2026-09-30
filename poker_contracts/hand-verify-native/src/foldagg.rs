//! foldagg — `cairo/src/fold_batch.cairo` 的 host 侧：BDN 手级聚合铸造/验证
//! 镜像 + 批 wire 构造 + prove-hand 出证驱动（FoldDesign v2 最小切片）。
//!
//! 与 `combined.rs`（每手合并信封）的分工：fold 批把**同一张牌桌**的 K 手
//! 折成一份证明——roster/keyagg 每批一次、每手只剩 3 次 poseidon + 单方程
//! EC 检查 + z̄ 范围检查，公开输出 2 词 `[acc, roster_digest]`。
//!
//! 公式与电路逐 felt parity（T8 KAT 钉死）：
//! - roster_digest = poseidon([roster_label, n] ++ (pkx, pky)×n)
//! - μ_i = poseidon([keyagg_label, n, pkx, pky])（BDN/CCS'06 系数，raw felt
//!   交 `Point::mul`——与 Cairo `add_mul` 同纪律，群阶自动归约 mod n）
//! - P̄ = Σ μ_i·pk_i
//! - M_h = poseidon([m_label, hand_binding, m1, m2, cm_digest, roster_digest])
//!   （m1/m2/cm_digest = 生产 settle wire[1]/[2]/cm 覆盖槽的切片占位——
//!   修复 2/4：registered_digest、n_expected、认领承诺全进共签消息）
//! - c = poseidon([sig_label, hand_binding, M_h, P̄x, P̄y, R̄x, R̄y])（raw）
//! - z̄ = Σ(w_i + c·μ_i·sk_i) mod n（铸侧）；验证方程 z̄·G − c·P̄ − R̄ == O
//! - claim_i = poseidon([claim_label, hand_binding, M_h])；
//!   acc = poseidon([prev_acc] ++ claims)
//!
//! BDN 三轮（nonce 承诺，抗 Drijvers 式并发会话的最低配置，risk-4）：
//! round1 各签名者对 nonce 承诺 t_i = poseidon([nonce_label, R_i 坐标])；
//! round2 全承诺到齐后揭 R_i，R̄ = Σ R_i；round3 用 c 出部分签名 z_i。
//! 承诺不进最终方程（协议面），公式面与单轮镜像一致。
//!
//! 纪律：坐标域 F_P / 标量域 Z_n 分离（与 curve.rs 同）；host 直验
//! fail-closed；parity 门在出证**之后**（roster_registry 对照面的切片模拟，
//! 见 prove_fold_batch 的门序注释）。

use std::path::{Path, PathBuf};
use std::time::Instant;

use starknet_crypto::{poseidon_hash_many, Felt};

use poker_protocol_core::curve::CurveScalar;
use poker_protocol_core::stark_curve::StarkScalar;

use crate::curve::Point;
use crate::handbatch::ascii_felt_pub;

// ---------------------------------------------------------------------------
// 域标签（与 fold_batch.cairo 常量逐字节一致）
// ---------------------------------------------------------------------------

pub fn keyagg_label() -> Felt {
    ascii_felt_pub("poker/fold-batch/keyagg.v1")
}

pub fn roster_label() -> Felt {
    ascii_felt_pub("poker/fold-batch/roster.v1")
}

pub fn m_label() -> Felt {
    ascii_felt_pub("poker/fold-batch/msg.v1")
}

pub fn sig_label() -> Felt {
    ascii_felt_pub("poker/fold-batch/sig.v1")
}

pub fn claim_label() -> Felt {
    ascii_felt_pub("poker/fold-batch/claim.v1")
}

pub fn nonce_label() -> Felt {
    ascii_felt_pub("poker/fold-batch/nonce.v1")
}

/// 群阶 n 的 felt 形（z̄ 范围检查的 host 侧）。
pub fn ec_order_felt() -> Felt {
    Felt::from_bytes_be(&poker_protocol_core::stark_curve::ec_order_bytes_be())
}

fn to_scalar(f: Felt) -> StarkScalar {
    <StarkScalar as CurveScalar>::from_bytes_mod_order(&f.to_bytes_be())
}

fn scalar_to_felt(s: StarkScalar) -> Felt {
    Felt::from_bytes_be(&s.to_bytes_be())
}

// ---------------------------------------------------------------------------
// 公式层（与 fold_batch.cairo 逐 felt parity）
// ---------------------------------------------------------------------------

/// roster_digest = poseidon([roster_label, n] ++ pks)。
pub fn roster_digest(pks: &[(Felt, Felt)]) -> Felt {
    let mut words = Vec::with_capacity(2 + 2 * pks.len());
    words.push(roster_label());
    words.push(Felt::from(pks.len() as u64));
    for (x, y) in pks {
        words.push(*x);
        words.push(*y);
    }
    poseidon_hash_many(&words)
}

/// μ 的 raw felt（poseidon 出口，不显式 mod n——与电路同出口）。
pub fn key_coeff_raw(n_players: usize, pkx: Felt, pky: Felt) -> Felt {
    poseidon_hash_many(&[keyagg_label(), Felt::from(n_players as u64), pkx, pky])
}

/// 聚合公钥 P̄ = Σ μ_i·pk_i（真实曲线；坐标/恒等由调用侧 fail-closed）。
pub fn agg_pubkey(pks: &[(Felt, Felt)]) -> Result<(Felt, Felt), String> {
    let mut acc = Point::identity();
    for (x, y) in pks {
        let pk = Point::from_affine(*x, *y).ok_or("agg_pubkey: pk off-curve")?;
        if pk.is_identity() {
            return Err("agg_pubkey: identity pk".into());
        }
        acc = acc + pk.mul(key_coeff_raw(pks.len(), *x, *y));
    }
    acc.to_affine().ok_or_else(|| "agg_pubkey: P̄ is identity (RO fixed point?)".to_string())
}

/// M_h = poseidon([m_label, hand_binding, m1, m2, cm_digest, roster_digest])。
#[allow(clippy::too_many_arguments)]
pub fn msg_digest(
    hand_binding: Felt,
    m1: Felt,
    m2: Felt,
    cm_digest: Felt,
    roster_d: Felt,
) -> Felt {
    poseidon_hash_many(&[m_label(), hand_binding, m1, m2, cm_digest, roster_d])
}

/// c = poseidon([sig_label, hand_binding, M_h, P̄x, P̄y, R̄x, R̄y])（raw felt）。
pub fn challenge_raw(
    hand_binding: Felt,
    m_h: Felt,
    pbar: (Felt, Felt),
    rbar: (Felt, Felt),
) -> Felt {
    poseidon_hash_many(&[
        sig_label(),
        hand_binding,
        m_h,
        pbar.0,
        pbar.1,
        rbar.0,
        rbar.1,
    ])
}

/// claim_i = poseidon([claim_label, hand_binding, M_h])。
pub fn claim_word(hand_binding: Felt, m_h: Felt) -> Felt {
    poseidon_hash_many(&[claim_label(), hand_binding, m_h])
}

/// acc = poseidon([prev_acc] ++ claims)（与 recurse::fold_accumulator 同公式）。
pub fn fold_acc(prev_acc: Felt, claims: &[Felt]) -> Felt {
    let mut words = Vec::with_capacity(claims.len() + 1);
    words.push(prev_acc);
    words.extend_from_slice(claims);
    poseidon_hash_many(&words)
}

// ---------------------------------------------------------------------------
// 验证方程（fold_batch.cairo 第 5 步的 host 形态，fail-closed 全检）
// ---------------------------------------------------------------------------

/// 单方程 host 直验：与电路同序——满阶编码检查 → z̄<n → 残差 == 恒等。
/// 返回 Err 的文案即电路对应 panic 标签（parity 的负向面）。
pub fn verify_equation(
    pbar: (Felt, Felt),
    rbar: (Felt, Felt),
    c_raw: Felt,
    zbar: Felt,
) -> Result<(), String> {
    let p = Point::from_affine(pbar.0, pbar.1).ok_or("PK_OFF_CURVE (P̄)")?;
    if p.is_identity() {
        return Err("PBAR_IS_IDENTITY".into());
    }
    let r = Point::from_affine(rbar.0, rbar.1).ok_or("RBAR_OFF_CURVE")?;
    if r.is_identity() {
        return Err("RBAR_IS_IDENTITY".into());
    }
    if zbar >= ec_order_felt() {
        return Err("ZBAR_OUT_OF_RANGE".into());
    }
    // z̄·G − c·P̄ − R̄ == O（raw-felt 乘法纪律：群阶自动归约）
    let residual = Point::generator().mul(zbar) - p.mul(c_raw) - r;
    if !residual.is_identity() {
        return Err("RESIDUAL_NOT_IDENTITY".into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// BDN 三轮铸造镜像（round1 nonce 承诺 → round2 揭 R_i → round3 部分签名）
// ---------------------------------------------------------------------------

/// 一手折叠加法语句的 wire 槽（fold_batch.cairo per-hand 7 词的 host 形状）。
///
/// m1/m2/cm_digest：生产形状 = settle wire[1]（registered_digest）、wire[2]
/// （n_expected）、cm_digest = poseidon(c0..c7 槽)（修复 2/4）；切片不含
/// 98 词 settle wire，host 铸造时以确定性派生词占位——**槽语义与占位值
/// 都在共签消息里**（改性即破签名），这是切片对修复 2/4 的可测承载。
#[derive(Debug, Clone)]
pub struct FoldHand {
    pub hand_binding: Felt,
    pub m1: Felt,
    pub m2: Felt,
    pub cm_digest: Felt,
    pub rbar: (Felt, Felt),
    pub zbar: Felt,
}

/// round1：nonce 承诺 t = poseidon([nonce_label, R 坐标])（承诺先行）。
#[derive(Debug, Clone)]
pub struct NonceCommit {
    pub t: Felt,
    /// round2 才揭的 nonce 点 R = w·G。
    pub r: (Felt, Felt),
}

pub fn nonce_commit(w: Felt) -> NonceCommit {
    let (rx, ry) = Point::generator().mul(w).to_affine().expect("w·G affine");
    NonceCommit { t: poseidon_hash_many(&[nonce_label(), rx, ry]), r: (rx, ry) }
}

/// round2：全承诺到齐后聚合 nonce 点 R̄ = Σ R_i（承诺验证是协议面纪律）。
pub fn aggregate_nonces(commits: &[NonceCommit]) -> Result<(Felt, Felt), String> {
    let mut acc = Point::identity();
    for c in commits {
        // 承诺绑定：揭出的 R_i 必须重出同一 t_i（防 Drijvers 式换 nonce）
        let t = poseidon_hash_many(&[nonce_label(), c.r.0, c.r.1]);
        if t != c.t {
            return Err("NONCE_COMMIT_MISMATCH".into());
        }
        let r = Point::from_affine(c.r.0, c.r.1).ok_or("nonce R off-curve")?;
        acc = acc + r;
    }
    acc.to_affine().ok_or_else(|| "R̄ is identity".to_string())
}

/// round3：部分签名 z_i = w_i + c·μ_i·sk_i (mod n)。
pub fn partial_sig(
    sk: Felt,
    w: Felt,
    c_raw: Felt,
    mu_raw: Felt,
) -> StarkScalar {
    to_scalar(w) + to_scalar(c_raw) * (to_scalar(mu_raw) * to_scalar(sk))
}

/// 批注册面锚（切片 = host 模拟 roster_registry；生产 = 合约对照 segment[16]）。
#[derive(Debug, Clone)]
pub struct RosterAnchor {
    pub roster_digest: Felt,
    pub expected_acc: Felt,
}

/// 一手聚合的完整宿主结果（铸造 + 公式重算的期望值来源）。
#[derive(Debug, Clone)]
pub struct AggregatedHand {
    pub hand: FoldHand,
    pub roster_digest: Felt,
    pub pbar: (Felt, Felt),
    pub m_h: Felt,
    pub c: Felt,
    pub claim: Felt,
}

/// BDN 三轮诚实聚合（host 镜像）：roster pks 由 sks 派生，m1/m2/cm_digest
/// 为调用方给定的槽词。铸侧全走标量域（mod n），验证侧走 raw-felt EC——
/// 与「电路读 wire、群阶自动归约」逐 felt 对齐。
#[allow(clippy::too_many_arguments)]
pub fn aggregate_sign(
    sks: &[Felt],
    ws: &[Felt],
    hand_binding: Felt,
    m1: Felt,
    m2: Felt,
    cm_digest: Felt,
) -> Result<AggregatedHand, String> {
    if sks.len() != ws.len() || sks.is_empty() {
        return Err("aggregate_sign: sks/ws length mismatch or empty".into());
    }
    let g = Point::generator();
    let pks: Vec<(Felt, Felt)> = sks
        .iter()
        .map(|sk| g.mul(*sk).to_affine().expect("sk·G affine"))
        .collect();
    let rd = roster_digest(&pks);
    let pbar = agg_pubkey(&pks)?;

    // BDN 三轮
    let commits: Vec<NonceCommit> = ws.iter().map(|w| nonce_commit(*w)).collect();
    let rbar = aggregate_nonces(&commits)?;
    let m_h = msg_digest(hand_binding, m1, m2, cm_digest, rd);
    let c = challenge_raw(hand_binding, m_h, pbar, rbar);

    let n = pks.len();
    let mut zbar = <StarkScalar as CurveScalar>::zero();
    for (i, sk) in sks.iter().enumerate() {
        let mu = key_coeff_raw(n, pks[i].0, pks[i].1);
        zbar = zbar + partial_sig(*sk, ws[i], c, mu);
    }

    Ok(AggregatedHand {
        hand: FoldHand { hand_binding, m1, m2, cm_digest, rbar, zbar: scalar_to_felt(zbar) },
        roster_digest: rd,
        pbar,
        m_h,
        c,
        claim: claim_word(hand_binding, m_h),
    })
}

/// 批的期望公开输出（parity 门期望侧）：
/// acc = fold_acc(prev, claims)，roster_digest = H(wire pks)。
/// （T4 改性：这是 host-parity 断言，对 soundness **零证明力**——它只钉
/// 公式漂移；「pks == 注册 pks」的 soundness 闭合点在生产 roster_registry，
/// 切片负例 T9/T10 走 prove 后 parity 门拒绝。）
pub fn expected_public_output(
    prev_acc: Felt,
    roster_pks: &[(Felt, Felt)],
    hands: &[AggregatedHand],
) -> RosterAnchor {
    let rd = roster_digest(roster_pks);
    let claims: Vec<Felt> = hands.iter().map(|h| h.claim).collect();
    RosterAnchor { roster_digest: rd, expected_acc: fold_acc(prev_acc, &claims) }
}

/// host 直验一批（fail-closed 预检；公式层与电路同序）。
pub fn host_verify_batch(
    roster_pks: &[(Felt, Felt)],
    hands: &[AggregatedHand],
) -> Result<(), String> {
    for (x, y) in roster_pks {
        let pk = Point::from_affine(*x, *y).ok_or("roster pk off-curve")?;
        if pk.is_identity() {
            return Err("roster pk is identity".into());
        }
    }
    let rd = roster_digest(roster_pks);
    let pbar = agg_pubkey(roster_pks)?;
    for h in hands {
        if h.roster_digest != rd {
            return Err("hand roster_digest mismatch".into());
        }
        verify_equation(pbar, h.hand.rbar, h.c, h.hand.zbar)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// wire 摊平 + prove-hand 驱动（recurse.rs:218-322 模式）
// ---------------------------------------------------------------------------

/// batch wire：`[P, (pkx,pky)×P, K, (hand_binding, m1, m2, cm_digest,
/// R̄x, R̄y, z̄)×K]`（fold_batch.cairo 头注释同布局）。
pub fn build_batch_wire(roster_pks: &[(Felt, Felt)], hands: &[FoldHand]) -> Vec<Felt> {
    let mut w = Vec::with_capacity(2 + 2 * roster_pks.len() + 7 * hands.len());
    w.push(Felt::from(roster_pks.len() as u64));
    for (x, y) in roster_pks {
        w.push(*x);
        w.push(*y);
    }
    w.push(Felt::from(hands.len() as u64));
    for h in hands {
        w.push(h.hand_binding);
        w.push(h.m1);
        w.push(h.m2);
        w.push(h.cm_digest);
        w.push(h.rbar.0);
        w.push(h.rbar.1);
        w.push(h.zbar);
    }
    w
}

fn felt_hex(f: Felt) -> String {
    format!("0x{}", f.to_bytes_be().iter().map(|b| format!("{b:02x}")).collect::<String>())
}

fn cairo_fold_src() -> PathBuf {
    std::env::var("HAND_VERIFY_FOLD_SRC").map(PathBuf::from).unwrap_or_else(|_| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("cairo/src/fold_batch.cairo")
    })
}

fn prove_hand_bin() -> PathBuf {
    std::env::var("HAND_VERIFY_PROVE_HAND").map(PathBuf::from).unwrap_or_else(|_| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("crate lives inside the repo")
            .join("proving-tool/target/release/prove-hand")
    })
}

/// 写 inputs.json（`[prev_acc, span_len] ++ batch wire`，hex felt 数组）。
pub fn write_inputs(
    prev_acc: Felt,
    roster_pks: &[(Felt, Felt)],
    hands: &[FoldHand],
    out_dir: &Path,
) -> Result<PathBuf, String> {
    let wire = build_batch_wire(roster_pks, hands);
    let mut arr = vec![felt_hex(prev_acc)];
    arr.push(format!("0x{:x}", wire.len()));
    arr.extend(wire.iter().map(|w| felt_hex(*w)));
    let path = out_dir.join("inputs.json");
    std::fs::write(&path, serde_json::to_string(&arr).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    Ok(path)
}

/// 一次出证的结果（recurse::LayerOutcome 的 fold 批对应物 + RSS 采集钩子）。
#[derive(Debug, Clone)]
pub struct FoldOutcome {
    pub n_players: usize,
    pub n_hands: usize,
    pub wire_words: usize,
    pub cairo_acc: Felt,
    pub cairo_roster_digest: Felt,
    pub expected_acc: Felt,
    pub expected_roster_digest: Felt,
    pub total_ms: u128,
    pub cairo_prove_ms: u64,
    pub cairo_run_ms: u64,
    pub cairo_compile_ms: u64,
    pub steps: u64,
    pub ec_ops: u64,
    pub poseidon_ops: u64,
    pub program_hash: Felt,
    pub proof_bytes: usize,
    pub check_verify_ms: u128,
    pub out_dir: PathBuf,
}

/// 每手 steps 边际的验收线（T7：1,628 实测锚 + 范围检查余量）。
pub const PER_HAND_STEPS_GATE: u64 = 2_200;

fn spawn_prove_hand(
    inputs_path: &Path,
    out_dir: &Path,
    params_path: Option<&Path>,
) -> Result<(std::process::Output, u128), String> {
    let mut cmd = std::process::Command::new(prove_hand_bin());
    cmd.arg("--program")
        .arg(cairo_fold_src())
        .arg("--inputs")
        .arg(inputs_path)
        .arg("--out-dir")
        .arg(out_dir);
    if let Ok(corelib) = std::env::var("HAND_VERIFY_CORELIB") {
        cmd.arg("--corelib").arg(corelib);
    }
    if let Some(params) = params_path {
        cmd.arg("--params").arg(params);
    }
    let t = Instant::now();
    let output = cmd.output().map_err(|e| format!("spawn prove-hand: {e}"))?;
    Ok((output, t.elapsed().as_millis()))
}

fn parse_summary(out_dir: &Path) -> Result<serde_json::Value, String> {
    serde_json::from_str(
        &std::fs::read_to_string(out_dir.join("summary.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| format!("parse summary.json: {e}"))
}

/// 未经 host 门禁的裸出证（负例专用：让 prove-hand 直接命中电路 panic）。
pub fn prove_fold_batch_unchecked(
    prev_acc: Felt,
    roster_pks: &[(Felt, Felt)],
    hands: &[FoldHand],
    out_dir: &Path,
    params_path: Option<&Path>,
) -> Result<(), String> {
    std::fs::create_dir_all(out_dir).map_err(|e| e.to_string())?;
    if !prove_hand_bin().exists() {
        return Err(format!(
            "prove-hand binary not found at {} (build: cd proving-tool && cargo build --release)",
            prove_hand_bin().display()
        ));
    }
    let inputs_path = write_inputs(prev_acc, roster_pks, hands, out_dir)?;
    let (output, _ms) = spawn_prove_hand(&inputs_path, out_dir, params_path)?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "prove-hand failed (circuit rejected): {}",
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

/// 出证一批 fold 语句并过双 parity 门（T1 主路径）。
///
/// 门序（对 A1/A2 的诚实承载——电路内 wire pks 仍自由，soundness 闭合点
/// 在消费面）：先出证（电路只保证算术一致 + 单方程成立），后对照注册面
/// 锚（`anchor` = RosterAnchor；切片 = host 重算，生产 = roster_registry）。
/// `cairo_roster_digest != anchor.roster_digest` ⇒ 换 roster 攻击被拒
/// （T9/T10）；`cairo_acc != anchor.expected_acc` ⇒ acc 链绑定被拒（T5）。
/// 最后 `--check-only` 独立复验证明文件。
pub fn prove_fold_batch(
    prev_acc: Felt,
    roster_pks: &[(Felt, Felt)],
    hands: &[AggregatedHand],
    anchor: &RosterAnchor,
    out_dir: &Path,
    params_path: Option<&Path>,
) -> Result<FoldOutcome, String> {
    std::fs::create_dir_all(out_dir).map_err(|e| e.to_string())?;
    if !prove_hand_bin().exists() {
        return Err(format!(
            "prove-hand binary not found at {} (build: cd proving-tool && cargo build --release)",
            prove_hand_bin().display()
        ));
    }
    // host 直验（fail-closed 预检——只验公式面，不做注册面预判，注册面
    // 对照必须在出证之后看 cairo 输出）。
    host_verify_batch(roster_pks, hands)?;

    let fold_hands: Vec<FoldHand> = hands.iter().map(|h| h.hand.clone()).collect();
    let wire_words = build_batch_wire(roster_pks, &fold_hands).len();
    let inputs_path = write_inputs(prev_acc, roster_pks, &fold_hands, out_dir)?;
    let (output, total_ms) = spawn_prove_hand(&inputs_path, out_dir, params_path)?;
    if !output.status.success() {
        return Err(format!(
            "prove-hand failed (batch rejected): {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let summary = parse_summary(out_dir)?;
    if !summary["verified"].as_bool().unwrap_or(false) {
        return Err("cairo proof did not verify".into());
    }
    let public: Vec<Felt> = summary["public"]["output"]
        .as_array()
        .ok_or("public output missing")?
        .iter()
        .map(|v| {
            let s = v.as_str().ok_or("public word not hex string")?;
            Felt::from_hex(s.trim_start_matches("0x")).map_err(|e| format!("parse felt: {e:?}"))
        })
        .collect::<Result<_, _>>()?;
    // runner 把 Array 返回序列化为 [len, ...elements]（forge0 单词返回 =
    // ["0x1","0x1"] 实证）——取 [2, acc, roster_digest]。
    if public.len() != 3 || public[0] != Felt::from(2u64) {
        return Err(format!(
            "expected [2, acc, roster_digest] public words, got {} words",
            public.len()
        ));
    }
    let (cairo_acc, cairo_rd) = (public[1], public[2]);

    // ---- parity 门（注册面切片模拟，出证后对照）----
    if cairo_rd != anchor.roster_digest {
        return Err(format!(
            "roster digest parity failure (unregistered roster): cairo 0x{:x} != registered 0x{:x}",
            cairo_rd, anchor.roster_digest
        ));
    }
    if cairo_acc != anchor.expected_acc {
        return Err(format!(
            "acc parity failure: cairo 0x{:x} != host 0x{:x}",
            cairo_acc, anchor.expected_acc
        ));
    }

    // ---- --check-only 独立复验 ----
    let proof_path = out_dir.join("proof.json");
    let t = Instant::now();
    let ck = std::process::Command::new(prove_hand_bin())
        .arg("--check-only")
        .arg("--proof")
        .arg(&proof_path)
        .output()
        .map_err(|e| format!("spawn prove-hand check-only: {e}"))?;
    if !ck.status.success() {
        return Err(format!(
            "standalone re-verify failed: {}",
            String::from_utf8_lossy(&ck.stderr).trim()
        ));
    }
    let check_verify_ms = t.elapsed().as_millis();

    let timings = &summary["timings_ms"];
    let outcome = FoldOutcome {
        n_players: roster_pks.len(),
        n_hands: hands.len(),
        wire_words,
        cairo_acc,
        cairo_roster_digest: cairo_rd,
        expected_acc: anchor.expected_acc,
        expected_roster_digest: anchor.roster_digest,
        total_ms,
        cairo_prove_ms: timings["prove"].as_u64().unwrap_or(0),
        cairo_run_ms: timings["run_witness"].as_u64().unwrap_or(0),
        cairo_compile_ms: timings["compile"].as_u64().unwrap_or(0),
        steps: summary["execution"]["steps"].as_u64().unwrap_or(0),
        ec_ops: summary["execution"]["builtin_instance_counter"]["ec_op_builtin"]
            .as_u64()
            .unwrap_or(0),
        poseidon_ops: summary["execution"]["builtin_instance_counter"]["poseidon_builtin"]
            .as_u64()
            .unwrap_or(0),
        program_hash: summary["public"]["program_hash"]
            .as_str()
            .and_then(|h| Felt::from_hex(h).ok())
            .ok_or("program hash missing")?,
        proof_bytes: std::fs::metadata(&proof_path).map(|m| m.len() as usize).unwrap_or(0),
        check_verify_ms,
        out_dir: out_dir.to_path_buf(),
    };
    Ok(outcome)
}

// ---------------------------------------------------------------------------
// 确定性铸造（测试/基准语料；无 rand 依赖）
// ---------------------------------------------------------------------------

fn det_felt(seed: u64, i: u64) -> Felt {
    poseidon_hash_many(&[Felt::from(seed), Felt::from(i), Felt::from(0xF01Du64)])
}

/// 铸一张 n 人确定性 roster（sk 派生自 seed）。
pub fn mint_roster_sks(n: usize, seed: u64) -> Vec<Felt> {
    (0..n as u64).map(|i| det_felt(seed, i)).collect()
}

/// 铸一张 n 人 roster 的公钥坐标。
pub fn roster_pks_from_sks(sks: &[Felt]) -> Vec<(Felt, Felt)> {
    let g = Point::generator();
    sks.iter().map(|sk| g.mul(*sk).to_affine().expect("sk·G affine")).collect()
}

/// 铸一张 K 手 × n 人诚实 fold 批（slot 词确定性派生；BDN nonce 从 seed 链）。
pub fn mint_fold_hands(
    roster_pks: &[(Felt, Felt)],
    hand_seeds: &[u64],
    seed: u64,
) -> Result<Vec<AggregatedHand>, String> {
    let sks = mint_roster_sks(roster_pks.len(), seed);
    let mut hands = Vec::with_capacity(hand_seeds.len());
    for (k, hs) in hand_seeds.iter().enumerate() {
        let hb = poseidon_hash_many(&[Felt::from(*hs), Felt::from(0xF01D_u64)]);
        let m1 = poseidon_hash_many(&[hb, Felt::from(k as u64), Felt::from(0xD16Du64)]);
        let m2 = Felt::from(roster_pks.len() as u64); // n_expected 槽语义
        let cm0 = poseidon_hash_many(&[hb, det_felt(seed, 900 + k as u64)]);
        let cm1 = poseidon_hash_many(&[hb, det_felt(seed, 950 + k as u64)]);
        let cm_digest = poseidon_hash_many(&[cm0, cm1]); // c0..c7 槽的切片压缩
        let ws: Vec<Felt> = (0..roster_pks.len() as u64)
            .map(|i| det_felt(*hs, 100 + i))
            .collect();
        hands.push(aggregate_sign(&sks, &ws, hb, m1, m2, cm_digest)?);
    }
    Ok(hands)
}
