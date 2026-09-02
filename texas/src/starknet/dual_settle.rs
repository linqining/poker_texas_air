//! Hand-batch（Dual-layer Attested Proof Verification，双层证明结算）+ G 层
//! 链上结算（`PokerDualSettlement`）。
//!
//! 术语说明：Hand-batch 是本项目内部命名，指"两层证明的结算验证"——
//! **P 层**（Player 侧：每座位 hand-bound Schnorr 认可，链上 ρ 折叠）
//! + **G 层**（Game 侧：canonical STARK 聚合摘要注册）。对外表述
//! 建议使用标准描述："ρ-folded Schnorr ownership endorsement batch
//! + host-verified STARK attestation"。
//!
//! 完整设计文档在外部结算 workspace：
//! `/Users/mac/projects/poker_texas_air/{DUAL_PROOF_PROTOCOL.md,
//! DAPV_SOUNDNESS.md}`（v2.8；含 hand_batch.cairo 的 Cairo 侧规范）。
//! 概要：
//! - **P 层**：每座位一条 hand-bound secp256k1 Schnorr 认可（ownership
//!   endorsement），全部残差方程在链上以 ρ 折叠成单点校验
//!   `L = Σ ρⁱ·Lᵢ == O`（`dual/hand_batch.cairo`；secp256k1 点经 OS 级
//!   secp mul syscall / corelib 验证，非 EC_OP builtin——后者仅限
//!   STARK 曲线）；
//! - **G 层**：Phase 1 = host 验证的 canonical STARK（orchestrator 的
//!   verified outer aggregate），其摘要经 `register_hand` 注册
//!   （`g_attestation`），公开输入承诺统一进 `hand_binding`。
//!
//! 绑定链（防跨手/跨层拼装）：
//! 1. `hand_binding` = Poseidon(table_id, hand_id, players, deck 承诺,
//!    reveal 承诺, state roots, settlement_digest)——注册后单次使用；
//! 2. Hand-batch 批次的 transcript 域与 ρ 都从 `hand_binding` 字节派生
//!   （链上 `bytes_to_felt(hand_id_bytes) == hand_binding` 强校验），
//!   且 ownership 挑战前置该域（§9-L2）：他手铸造的认可在本手折叠必
//!   非零；
//! 3. `settlement_digest` 在链上按 (hand_id, players, deltas) 重算并与
//!   注册值精确比对——证明无法为别的支付方案背书。
//!
//! 本运行时的现实边界（如实记录）：
//! - 游戏协议本体（poker_l1 镜像）运行在 BLS12-381 上，其洗牌/reveal
//!   语句是 BLS 点。链上 EC 支持分三档：EC_OP builtin 仅限 STARK 曲线
//!   （原生，最便宜）；secp256k1/r1 经 OS 级 mul syscall（中档）；BLS12-381
//!   无原生支持（需 Garaga 纯 Cairo 模拟，最贵）——所以 BLS 点的
//!   reveal/fold 残差暂不能进本手批次（载荷格式已支持）。
//!   迁移目标见 docs/starknet-plan-d-stark-curve.md：协议本体迁 STARK
//!   曲线（EC_OP 原生，是全残差批次唯一可负担的路线）；secp256k1 保留
//!   为 EVM ecrecover 互操作备选。当前批次仍承载每座位的 hand-bound
//!   所有权认可（secp256k1）。
//! - 认可密钥目前由服务器在入座时生成托管（bot 路径与 WS 路径都汇入
//!   `register_seat_wallet`）。生产形态：认可私钥由玩家钱包/客户端
//!   持有，结算时经签名请求铸造（与游戏密钥同分布）。

use poker_protocol_core::{Curve, CurvePoint, CurveScalar, StarkCurve};
use starknet::accounts::{Account, ExecutionEncoding};
use starknet::core::types::{Call, Felt};
use starknet::core::utils::starknet_keccak;
use starknet_ff::FieldElement as Ff;

use poker_texas_air::hand_binding::{compute_hand_binding, HandBindingInput};
use poker_texas_air::starknet_settlement::AggregateDigestFelts;

use super::config::SettleMode;
use super::mirror::TableMirror;
use super::submit::{ff_to_felt, i128_to_ff, HandSettlement};

pub type Sc = <StarkCurve as Curve>::Scalar;
pub type Pt = <StarkCurve as Curve>::Point;

/// 客户端提交的成品认可（P2.1：私钥在玩家客户端，服务器只中继）。
#[derive(Debug, Clone)]
pub struct ClientEndorsement {
    pub pk: Pt,
    pub r: Pt,
    pub s: Sc,
}

/// wallet → hand_id → 客户端铸造的认可。由 `register_client_endorsement`
/// 填充；结算时 hooks 优先取用，齐全则跳过服务器铸造路径。
static CLIENT_ENDORSEMENTS: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<String, std::collections::HashMap<u32, ClientEndorsement>>>,
> = std::sync::OnceLock::new();

/// 客户端提交其铸造的认可（hand-bound）。点坐标做 on-curve 校验，
/// 标量做域校验；重复提交同一 (wallet, hand_id) 覆盖（幂等）。
/// 生产形态：请求须附钱包签名（session key / typed-data）证明身份；
/// 当前过渡实现信任 WS 会话钱包标识（见 hooks 的 wallet 来源）。
pub fn register_client_endorsement(
    wallet: &str,
    hand_id: u32,
    pk_x_hex: &str,
    pk_y_hex: &str,
    r_x_hex: &str,
    r_y_hex: &str,
    s_hex: &str,
) -> Result<(), String> {
    fn parse_point(x_hex: &str, y_hex: &str) -> Result<Pt, String> {
        let x = hex::decode(x_hex).map_err(|e| format!("x hex: {e}"))?;
        let y = hex::decode(y_hex).map_err(|e| format!("y hex: {e}"))?;
        if x.len() != 32 || y.len() != 32 {
            return Err("point coordinates must be 32 bytes".into());
        }
        let mut xb = [0u8; 32];
        xb.copy_from_slice(&x);
        let mut yb = [0u8; 32];
        yb.copy_from_slice(&y);
        point_from_words(&xb, &yb).ok_or_else(|| "point not on curve".into())
    }
    let pk = parse_point(pk_x_hex, pk_y_hex)?;
    let r = parse_point(r_x_hex, r_y_hex)?;
    let mut s_bytes = [0u8; 32];
    let s_raw = hex::decode(s_hex).map_err(|e| format!("s hex: {e}"))?;
    if s_raw.len() != 32 {
        return Err("s must be 32 bytes".into());
    }
    s_bytes.copy_from_slice(&s_raw);
    let s = Sc::from_canonical_bytes(&s_bytes).ok_or("s out of range")?;

    let registry = CLIENT_ENDORSEMENTS.get_or_init(|| std::sync::Mutex::new(Default::default()));
    registry
        .lock()
        .unwrap_or_else(|e| e.into_inner()) // 锁污染不连锁 panic（audit M1）
        .entry(wallet.to_string())
        .or_default()
        .insert(hand_id, ClientEndorsement { pk, r, s });
    Ok(())
}

/// 进程内 bot 认可注册（bot 无 WS 会话，由服务器代持认可私钥后本地铸造；
/// 与 `register_client_endorsement` 等价，只是免去 hex 往返）。
pub fn register_client_endorsement_raw(wallet: &str, hand_id: u32, e: Endorsement) {
    let registry = CLIENT_ENDORSEMENTS.get_or_init(|| std::sync::Mutex::new(Default::default()));
    registry
        .lock()
        .unwrap_or_else(|e| e.into_inner()) // 锁污染不连锁 panic（audit M1）
        .entry(wallet.to_string())
        .or_default()
        .insert(hand_id, ClientEndorsement { pk: e.pk, r: e.r, s: e.s });
}

/// 取客户端已提交的认可（结算聚合用）；缺失返回 None。
pub fn take_client_endorsements(
    wallets: &[Ff],
    hand_id: u32,
) -> Option<Vec<ClientEndorsement>> {
    let registry = CLIENT_ENDORSEMENTS.get()?;
    let guard = registry.lock().unwrap_or_else(|e| e.into_inner()); // 锁污染不连锁 panic（audit M1）
    let mut out = Vec::with_capacity(wallets.len());
    for w in wallets {
        let key = format!("{w:#x}");
        let entry = match guard.get(&key).map(|m| m.get(&hand_id)) {
            Some(Some(e)) => e.clone(),
            _ => {
                tracing::info!(
                    "[starknet-settle] take: MISSING endorsement wallet={key} hand={hand_id} (registry has {} wallets)",
                    guard.len()
                );
                return None;
            }
        };
        out.push(entry);
    }
    Some(out)
}

/// 取（首次则生成并托管）钱包的 secp256k1 认可密钥对。
///
/// hand_batch 的域分离标签与认可工件（P2.1 后服务器不持有任何认可
/// 私钥；`mint_endorsement`/`Endorsement` 仅存于测试与向量生成，生产
/// 铸造在客户端 client-wasm `endorsement_mint`，公式逐字节一致）。

/// hand_batch.cairo 的域分离标签（逐字节对齐，勿改）。
const HAND_PROTO_DOMAIN: &[u8] = b"poker/hand-batch/proto";
const RHO_DOMAIN: &[u8] = b"poker/hand-batch/v1";

/// 一条 hand-bound 所有权认可：pk = sk·G，s = w + c·sk，
/// c = H(domain ‖ G ‖ pk ‖ R)，R = w·G。
#[derive(Debug, Clone)]
pub struct Endorsement {
    pub pk: Pt,
    pub r: Pt,
    pub s: Sc,
}

/// keccak256("poker/hand-batch/proto" ‖ hand_id)——与 Cairo 端
/// `hand_transcript_domain` 逐字节一致（digest 原始字节序）。
fn hand_transcript_domain(hand_id: &[u8; 32]) -> [u8; 32] {
    use sha3::Digest;
    let mut h = sha3::Keccak256::new();
    h.update(HAND_PROTO_DOMAIN);
    h.update(hand_id);
    h.finalize().into()
}

/// 铸造 hand-bound 认可。
///
/// 生产用途限定：仅供**服务器自己托管的测试玩家（dev_bot）**在进程内铸造——
/// 真实客户端的认可私钥保持在浏览器（client-wasm `endorsement_mint`），
/// 服务器不持有、也无法调用此函数代铸。
pub fn mint_endorsement(
    sk: &Sc,
    pk: &Pt,
    hand_binding: &[u8; 32],
) -> Endorsement {
    use rand_core::{CryptoRng, RngCore};
    let mut rng = rand::rngs::OsRng;
    let g = StarkCurve::base_g();
    loop {
        let w = <Sc as CurveScalar>::random(&mut rng);
        if w == <Sc as CurveScalar>::zero() {
            continue;
        }
        let r = g * w;
        if r.is_identity() {
            continue;
        }
        // gas 压缩版挑战：felt 直通 Poseidon（core 规范实现，与 Cairo/wasm
        // 复刻同式；取代 keccak 域 + 32B 压缩编码的字节流形态）。
        let c = poker_protocol_core::stark_curve::handbatch_endorsement_challenge(
            hand_binding, &g, pk, &r,
        );
        return Endorsement { pk: *pk, r, s: w + c * *sk };
    }
}

/// 仿射 (x, y) 各 32 字节大端（payload 字布局）。STARK 曲线坐标即
/// felt252，字直通 Cairo 合约，无 u256↔felt 换算。
pub fn point_xy(p: &Pt) -> ([u8; 32], [u8; 32]) {
    // audit M2：恒等点不再 panic（panic 会杀死 game_loop task 冻结牌桌），
    // 改为全零坐标——下游 Cairo EC 验证会自然拒绝该批认可（交易 revert，
    // 走既有有界重试/放弃路径），服务端日志可观测。
    match p.to_affine_parts() {
        Some((x, y)) => (x.to_bytes_be(), y.to_bytes_be()),
        None => {
            tracing::error!("point_xy: identity point encoded as zero words (will be rejected downstream)");
            ([0u8; 32], [0u8; 32])
        }
    }
}

fn scalar_be(s: &Sc) -> [u8; 32] {
    let v = <Sc as CurveScalar>::as_bytes(s);
    v.as_slice().try_into().expect("32-byte scalar")
}

/// Hand-batch 一次结算的全部工件。
pub struct DualSettlement {
    pub hand_binding: Ff,
    pub g_attestation: Ff,
    pub hand_id: u32,
    /// hand_batch 载荷（u256 字，大端 32 字节表示）。
    pub batch_words: Vec<[u8; 32]>,
    /// Linear（默认）路径 calldata：`register_hand`（含 3 个零的期望
    /// 桶计数尾部）+ `verify_and_settle_dapv`（p_batch 全文上链）。
    /// 永远构建——也是 proved 模式回退的目标。
    pub register_calldata: Vec<Felt>,
    pub settle_calldata: Vec<Felt>,
    /// Proved 路径工件（总是构建，成本仅一次 Poseidon + 两个 Vec；
    /// 是否使用由 `STARKNET_SETTLE_MODE` 在提交时决定）。
    pub proved: ProvedSettlement,
}

/// Proved 模式的上链工件：p_batch 不进 calldata，settle 只携带承诺。
#[derive(Debug, Clone)]
pub struct ProvedSettlement {
    /// `poseidon(hand_binding, poseidon(p_batch words))`——注册与结算
    /// 两侧都必须精确等于该值，把 attested batch 绑定到注册的那一个。
    pub p_batch_commitment: Ff,
    /// p_batch 词数（与承诺一起注册/比对）。
    pub p_batch_len: usize,
    /// `register_hand_proved` calldata：
    /// [hand_binding, settlement_digest, g_attestation, commitment,
    ///  batch_len, exp_reveal, exp_leave, exp_recon]（期望计数暂为零 =
    /// 链上不约束，由 prover 线下校验）。
    pub register_calldata: Vec<Felt>,
    /// `verify_and_settle_dapv_proved` calldata：
    /// [hand_binding, 32, hand_id_bytes…, hand_id, n, players…, n,
    /// deltas…, commitment, batch_len]——无 p_batch。
    pub settle_calldata: Vec<Felt>,
}

/// 递给外部 prover 的 workload（也是 JSON 导出文件的 schema）。
#[derive(Debug, Clone)]
pub struct ProverWorkload {
    pub hand_binding: Ff,
    pub hand_id: u32,
    pub batch_words: Vec<[u8; 32]>,
    pub p_batch_commitment: Ff,
}

/// 外部 prover 对 workload 的 attestation。
#[derive(Debug, Clone)]
pub struct ProverAttestation {
    /// prover 实际验证过的承诺——必须与 workload 的承诺逐字节相等
    /// 才接受（否则视为 prover 故障，回退 linear）。
    pub p_batch_commitment: Ff,
}

/// `p_batch_commitment = poseidon(hand_binding, poseidon(p_batch words))`。
///
/// 每个载荷词是 STARK 曲线坐标/标量（< 域模），32 字节大端可直接作
/// felt 进 Poseidon；任何超域词直接报错（这类批次本就无法以 felt 形态
/// 上链，线性路径同样会拒）。
pub fn compute_p_batch_commitment(
    hand_binding: Ff,
    batch_words: &[[u8; 32]],
) -> Result<Ff, String> {
    let mut inner: Vec<Ff> = Vec::with_capacity(batch_words.len());
    for w in batch_words {
        inner.push(
            Ff::from_bytes_be(w)
                .map_err(|_| "dapv: batch word not in felt252 range".to_string())?,
        );
    }
    Ok(starknet_crypto::poseidon_hash_many(&[
        hand_binding,
        starknet_crypto::poseidon_hash_many(&inner),
    ]))
}

/// 外部 batch-prover 客户端 seam：服务器**绝不**进程内跑 prover——只把
/// workload 提交给 `STARKNET_PROVER_URL` 指向的服务并接收 attestation。
/// 在独立 prover 工具（STARK fact-registry / SNIP-36 verifier 落地前的
/// 临时形态）存在之前，唯一实现 [`HttpBatchProver`] 是必然报错的存根：
/// proved 模式因此总是回退 linear（保持暗跑可观测：workload JSON 仍导出）。
pub trait BatchProver: Send + Sync {
    /// 返回 prover 对该 workload 的 attestation；**任何**错误都由调用
    /// 方视为"回退 linear"。
    fn request_attestation<'a>(
        &'a self,
        workload: &'a ProverWorkload,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ProverAttestation, String>> + Send + 'a>,
    >;
}

/// prover attestation 等待上限：超时即回退 linear（结算绝不因 prover
/// 阻塞超过 30s）。
pub const PROVER_ATTEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// `STARKNET_PROVER_URL` 的 HTTP prover 客户端——**存根**。
///
/// 真实客户端（提交 workload → 轮询/等待 → 拿回 attestation）在独立
/// prover CLI/服务存在后实现；当前无条件报错，使 proved 模式确定性地
/// 回退 linear。没有真实端点被请求。
pub struct HttpBatchProver {
    pub url: Option<String>,
}

impl HttpBatchProver {
    pub fn new(url: Option<String>) -> Self {
        Self { url }
    }
}

impl BatchProver for HttpBatchProver {
    fn request_attestation<'a>(
        &'a self,
        _workload: &'a ProverWorkload,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<ProverAttestation, String>> + Send + 'a>,
    > {
        let url = self.url.clone();
        Box::pin(async move {
            Err(format!(
                "batch prover client not implemented (STARKNET_PROVER_URL={url:?}) — \
                 proved mode stays dark until the standalone prover tool exists"
            ))
        })
    }
}

/// proved 模式下把 workload 导出到 `<dir>/hand-{hand_id}-{binding:#x}.json`
/// （best-effort：目录创建/写入失败只告警，绝不阻塞结算）。这是未来
/// 独立 prover CLI 消费的文件，也让 proved 模式在暗跑期可观测/可 dry-run。
pub fn export_prover_workload(
    dual: &DualSettlement,
    dir: &std::path::Path,
) -> Option<std::path::PathBuf> {
    let path = dir.join(format!("hand-{}-{:#x}.json", dual.hand_id, dual.hand_binding));
    let doc = serde_json::json!({
        "hand_binding": format!("{:#x}", dual.hand_binding),
        "hand_id": dual.hand_id,
        "batch_words": dual.batch_words.iter()
            .map(|w| hex::encode(w))
            .collect::<Vec<_>>(),
        "p_batch_commitment": format!("{:#x}", dual.proved.p_batch_commitment),
        "p_batch_len": dual.proved.p_batch_len,
    });
    let result = std::fs::create_dir_all(dir)
        .and_then(|_| std::fs::write(&path, serde_json::to_vec_pretty(&doc).unwrap_or_default()));
    match result {
        Ok(()) => {
            tracing::info!(
                "[dapv-proved] workload exported: {} ({} words, commitment {:#x})",
                path.display(),
                dual.proved.p_batch_len,
                dual.proved.p_batch_commitment
            );
            Some(path)
        }
        Err(e) => {
            tracing::warn!("[dapv-proved] workload export failed (non-fatal): {e}");
            None
        }
    }
}

/// proved 模式的提交决策：尝试 prover attestation，**任何**错误/超时/
/// 承诺不匹配都回退 [`SettleMode::Linear`]。结算绝不因 prover 阻塞。
pub async fn resolve_settle_mode_with_prover(
    prover: &dyn BatchProver,
    workload: &ProverWorkload,
) -> SettleMode {
    match tokio::time::timeout(PROVER_ATTEST_TIMEOUT, prover.request_attestation(workload)).await {
        Ok(Ok(att)) if att.p_batch_commitment == workload.p_batch_commitment => {
            SettleMode::Proved
        }
        Ok(Ok(att)) => {
            tracing::warn!(
                "[dapv-proved] prover attestation commitment mismatch (att {:#x} != workload {:#x}) — falling back to linear",
                att.p_batch_commitment,
                workload.p_batch_commitment
            );
            SettleMode::Linear
        }
        Ok(Err(e)) => {
            tracing::warn!("[dapv-proved] prover attestation failed, falling back to linear: {e}");
            SettleMode::Linear
        }
        Err(_) => {
            tracing::warn!(
                "[dapv-proved] prover attestation timed out after {:?}, falling back to linear",
                PROVER_ATTEST_TIMEOUT
            );
            SettleMode::Linear
        }
    }
}

/// reveal 承诺的域分隔标签：keccak256("zgame.dapv.reveal_commit.v2")。
fn handbatch_reveal_commit_label() -> Ff {
    // starknet_keccak 返回 starknet 的 Felt 类型；转字节后经 Ff 重建
    //（keccak 输出 < 2^250 < Fp 模，expect 无风险）。
    let felt = starknet_keccak("zgame.dapv.reveal_commit.v2".as_bytes());
    Ff::from_bytes_be(&felt.to_bytes_be()).expect("keccak output is a valid felt")
}

/// 任意字节串 → 31 字节大端块逐 felt（每块 < 2^248 < 域模，无截断风险）。
fn bytes_as_felts(bytes: &[u8]) -> Vec<Ff> {
    bytes
        .chunks(31)
        .map(|chunk| {
            let mut buf = [0u8; 32];
            buf[32 - chunk.len()..].copy_from_slice(chunk);
            Ff::from_bytes_be(&buf).expect("31-byte chunk is below the field modulus")
        })
        .collect()
}

/// 32 字节 → felt（清高 5 位保证 < 域模；仅用于承诺类字段，非安全性输入）。
fn bytes_to_field(b: &[u8; 32]) -> Ff {
    let mut out = *b;
    out[0] &= 0x07;
    Ff::from_bytes_be(&out).expect("top-3-bits-cleared 32 bytes always fit felt252")
}

/// 构造 Hand-batch 结算：hand_binding + g_attestation + 认可批次 + calldata。
///
/// `endorsement_keys` 与 `settlement.players_remapped` 同序（每参与者一条
/// (sk, pk)），在内部用 hand 域铸造认可。提交前在宿主侧做与链上完全
/// 一致的 ρ 折叠 parity 检查（L == O），本地不过直接报错，不上链浪费 gas。
/// 内部构建（接受认可生产回调）：客户端路径传成品认可；服务器铸造
/// 路径传 mint 闭包。hand_binding 派生需要先于认可铸造（挑战域）。
/// Hand-batch 结算第一阶段产物（P2.1）：hand_binding 及其 32B 大端字节。
/// 认可铸造以此为挑战域，客户端 mint 前必须拿到它。
#[derive(Debug, Clone)]
pub struct HandBatchBinding {
    pub hand_binding: Ff,
    pub hand_id_bytes: [u8; 32],
}

/// 提前派生 hand_binding（不依赖任何认可——绑定链只含 deck 承诺、
/// reveal 承诺、状态根、结算摘要）。`build_dual_settlement_with` 内部
/// 复用同一确定性计算，两处结果逐字节一致。
pub fn prepare_handbatch_binding(
    mirror: &TableMirror,
    settlement: &HandSettlement,
) -> Result<HandBatchBinding, String> {
    let pre_table = mirror
        .pre_settlement
        .as_ref()
        .unwrap_or(&mirror.table);
    let deck_commit = poker_texas_air::deck_commitment::deck_commitment(pre_table);
    let reveal_commitment = {
        let deck_bytes = borsh::to_vec(&pre_table.deck_state.encrypted)
            .map_err(|e| format!("dapv: deck encode: {e}"))?;
        let mut input = vec![handbatch_reveal_commit_label()];
        input.push(Ff::from(deck_bytes.len() as u64));
        input.extend(bytes_as_felts(&deck_bytes));
        let digest_bytes = settlement.aggregate_digest.to_vec();
        input.push(Ff::from(digest_bytes.len() as u64));
        input.extend(bytes_as_felts(&digest_bytes));
        starknet_crypto::poseidon_hash_many(&input)
    };
    let hand_binding = compute_hand_binding(&HandBindingInput {
        table_id: mirror.table_seed,
        hand_id: u64::from(settlement.hand_id),
        players: settlement.players_remapped.clone(),
        deck_commitments: vec![poker_texas_air::state_root::u64_to_field(deck_commit)],
        reveal_commitment,
        state_root_pre: bytes_to_field(&settlement.pre_state_root),
        state_root_post: bytes_to_field(&settlement.post_state_root),
        settlement_digest: settlement.settlement_digest,
    })
    .map_err(|e| format!("dapv: hand_binding: {e}"))?;
    Ok(HandBatchBinding {
        hand_id_bytes: hand_binding.to_bytes_be(),
        hand_binding,
    })
}

fn build_dual_settlement_with(
    mirror: &TableMirror,
    settlement: &HandSettlement,
    produce: &dyn Fn(&[u8; 32], &[Ff]) -> Result<Vec<Endorsement>, String>,
) -> Result<DualSettlement, String> {
    let pre_table = mirror
        .pre_settlement
        .as_ref()
        .unwrap_or(&mirror.table);

    // ---- 1. hand_binding（复用 prepare_handbatch_binding 的确定性派生）----
    let binding = prepare_handbatch_binding(mirror, settlement)?;
    let hand_id_bytes = binding.hand_id_bytes;
    let hand_binding = binding.hand_binding;
    let endorsements = produce(&hand_id_bytes, &settlement.players_remapped)?;
    let batch_words = assemble_batch(&endorsements, &[]);

    // ---- 3. 宿主侧 ρ 折叠 parity（Horner，与 Cairo fold_and_check 同构）----
    let equations = parse_batch_terms(&hand_id_bytes, &batch_words)
        .ok_or("dapv: batch reparse failed (internal)")?;
    if !host_fold_check(&hand_id_bytes, &equations) {
        return Err(
            "dapv: host fold parity failed (L != O) — batch would be rejected on-chain".into(),
        );
    }

    // ---- 4. g_attestation：G（外部聚合）+ 状态根的 Poseidon 承诺 ----
    let agg = AggregateDigestFelts::split(&settlement.aggregate_digest)
        .map_err(|e| format!("dapv: aggregate split: {e}"))?;
    let pre = AggregateDigestFelts::split(&settlement.pre_state_root)
        .map_err(|e| format!("dapv: pre root split: {e}"))?;
    let post = AggregateDigestFelts::split(&settlement.post_state_root)
        .map_err(|e| format!("dapv: post root split: {e}"))?;
    let g_attestation = starknet_crypto::poseidon_hash_many(&[
        hand_binding,
        settlement.settlement_digest,
        agg.hi,
        agg.lo,
        pre.hi,
        pre.lo,
        post.hi,
        post.lo,
    ]);

    // ---- 5. calldata（linear + proved 两套都构建；提交时按模式选用）----
    let hb_felt = ff_to_felt(hand_binding);
    // register_hand(hand_binding, settlement_digest, g_attestation,
    // exp_reveal, exp_leave, exp_recon)：期望桶计数暂全零（= 链上不约束；
    // 与合约侧"零 = 无约束"的兼容语义一致）。
    let register_calldata = vec![
        hb_felt,
        ff_to_felt(settlement.settlement_digest),
        ff_to_felt(g_attestation),
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
    ];

    let mut settle_calldata = Vec::with_capacity(6 + 32 + 4 * settlement.players_remapped.len());
    settle_calldata.push(hb_felt);
    // hand_id_bytes: Span<u8> = [len, items...]
    settle_calldata.push(Felt::from(32u64));
    for b in hand_id_bytes {
        settle_calldata.push(Felt::from(u64::from(b)));
    }
    settle_calldata.push(Felt::from(u64::from(settlement.hand_id)));
    // players: Span<ContractAddress>
    settle_calldata.push(Felt::from(settlement.players_remapped.len() as u64));
    for p in &settlement.players_remapped {
        settle_calldata.push(ff_to_felt(*p));
    }
    // deltas: Span<i128>（负数取模补，与合约 from_felt_signed_i128 对齐）。
    // 单位与 legacy 路径一致：vault 以 wei 记账，这里放大为 wei，
    // 与 register 的 settlement_digest（同样按 wei 计算）保持一致。
    const DAPV_WEI_PER_CHIP: i128 = 100_000_000_000_000;
    settle_calldata.push(Felt::from(settlement.deltas.len() as u64));
    for d in &settlement.deltas {
        let wei = d
            .checked_mul(DAPV_WEI_PER_CHIP)
            .ok_or("delta wei overflow")?;
        settle_calldata.push(ff_to_felt(i128_to_ff(wei)));
    }
    // p_batch: Span<felt252> —— 每字单 felt（STARK 曲线基域 == felt252，
    // 点坐标/标量词天然在域内；越界词在此报错不上链）。提交入口为
    // verify_and_settle_dapv_stark——旧 `verify_and_settle_dapv` 收
    // Span<u256> 并走 secp 变体 verify_hand_batch，与 STARK 背书不匹配。
    settle_calldata.push(Felt::from(batch_words.len() as u64));
    for w in &batch_words {
        settle_calldata.push(ff_to_felt(
            Ff::from_bytes_be(w)
                .map_err(|_| "dapv: batch word not in felt252 range".to_string())?,
        ));
    }

    // ---- 6. proved 工件：p_batch 承诺 + 无 p_batch 的 register/settle ----
    let p_batch_commitment = compute_p_batch_commitment(hand_binding, &batch_words)?;
    let p_batch_len_felt = Felt::from(batch_words.len() as u64);
    let proved_register_calldata = vec![
        hb_felt,
        ff_to_felt(settlement.settlement_digest),
        ff_to_felt(g_attestation),
        ff_to_felt(p_batch_commitment),
        p_batch_len_felt,
        // 期望桶计数（reveal/leave/recon）：链上不校验 proved 载荷（词都
        // 不上链），注册值供外部 prover 线下比对——暂全零（无约束）。
        Felt::ZERO,
        Felt::ZERO,
        Felt::ZERO,
    ];
    let mut proved_settle_calldata = Vec::with_capacity(6 + 32 + 2 * settlement.players_remapped.len());
    proved_settle_calldata.push(hb_felt);
    proved_settle_calldata.push(Felt::from(32u64));
    for b in hand_id_bytes {
        proved_settle_calldata.push(Felt::from(u64::from(b)));
    }
    proved_settle_calldata.push(Felt::from(u64::from(settlement.hand_id)));
    proved_settle_calldata.push(Felt::from(settlement.players_remapped.len() as u64));
    for p in &settlement.players_remapped {
        proved_settle_calldata.push(ff_to_felt(*p));
    }
    proved_settle_calldata.push(Felt::from(settlement.deltas.len() as u64));
    for d in &settlement.deltas {
        let wei = d
            .checked_mul(DAPV_WEI_PER_CHIP)
            .ok_or("delta wei overflow")?;
        proved_settle_calldata.push(ff_to_felt(i128_to_ff(wei)));
    }
    // 无 p_batch：只有承诺 + 词数。
    proved_settle_calldata.push(ff_to_felt(p_batch_commitment));
    proved_settle_calldata.push(p_batch_len_felt);
    let proved = ProvedSettlement {
        p_batch_commitment,
        p_batch_len: batch_words.len(),
        register_calldata: proved_register_calldata,
        settle_calldata: proved_settle_calldata,
    };

    Ok(DualSettlement {
        hand_binding,
        g_attestation,
        hand_id: settlement.hand_id,
        batch_words,
        register_calldata,
        settle_calldata,
        proved,
    })
}

/// ρ 折叠宿主 parity（Horner 版，A 优化）：与 Cairo 端
/// hand_batch_stark.cairo::fold_and_check 同构。
///
/// 结构：方程内点 `eq_i = s_i·G − c_i·pk_i − R_i`（负项用**点取反**表达，
/// −c·pk ≡ c·(−pk)，规避 felt 域取反 ≠ −c mod n 的陷阱），随后
/// Horner 折叠 `L = ρ·(ρ·(…(ρ·eq_N + eq_{N−1})…) + eq_1)`。
/// host 用归约后的 c/ρ（Z_n 标量），Cairo 用原始 poseidon felt 作标量
/// ——EC 标量乘对 m 与 m mod n 同结果（群阶），两侧同点。
pub fn host_fold_check(hand_id_bytes: &[u8; 32], equations: &[HandBatchEquation]) -> bool {
    if equations.is_empty() {
        return false;
    }
    let g = StarkCurve::base_g();

    // 展开全部方程内点 + ρ 词（ownership 1 点/方程，reveal 2 点/方程）。
    let mut eq_points: Vec<Pt> = Vec::new();
    let mut all_words = Vec::new();
    for e in equations {
        // BG 的两条标量校验是精确等式（不是概率性折叠）：失败必须立即
        // 拒绝（与 Cairo verify 直接 return false 同构）。
        if let HandBatchEquation::Shuffle { input, output, pk, proof } = e {
            let eqs = bg_shuffle_fold_equations(input, output, pk, proof);
            if !eqs.scalar_check_1 || !eqs.scalar_check_2 {
                return false;
            }
        }
        let (pts, words) = e.points_and_words(hand_id_bytes, &g);
        eq_points.extend(pts);
        all_words.push(words);
    }
    let rho = poker_protocol_core::stark_curve::handbatch_rho(hand_id_bytes, &all_words);

    // Horner：L = ρ·(ρ·(…(ρ·eq_N + eq_{N−1})…) + eq_1)
    let mut acc = eq_points[eq_points.len() - 1];
    for eq in eq_points[..eq_points.len() - 1].iter().rev() {
        acc = acc * rho + *eq;
    }
    acc.is_identity()
}

/// [`host_fold_check`] 的语义别名（测试/诊断用）。
pub fn host_fold_is_identity(hand_id_bytes: &[u8; 32], equations: &[HandBatchEquation]) -> bool {
    host_fold_check(hand_id_bytes, equations)
}

/// 一条参与 Hand-batch 折叠的方程（host 表示）。
#[derive(Debug, Clone)]
pub enum HandBatchEquation {
    /// s·G − c·pk − R = O（c = handbatch_endorsement_challenge）
    Ownership { s: Sc, pk: Pt, r: Pt },
    /// reveal 两联方程（c = handbatch_reveal_challenge）：
    ///   eq1: s·G − t1 − c·pk = O
    ///   eq2: s·c1 − t2 − c·token = O
    Reveal {
        s: Sc,
        pk: Pt,
        c1: Pt,
        c2: Pt,
        token: Pt,
        t1: Pt,
        t2: Pt,
        nonce: Sc,
    },
    /// leave/remask 批量 DLEQ（c = handbatch_leave_challenge）：
    ///   eq0:  s·G − cpk − c·pk = O
    ///   eq_i: s·in_c1ᵢ − aᵢ − c·d2ᵢ = O（d2ᵢ = in_c2ᵢ − out_c2ᵢ）
    Leave {
        s: Sc,
        pk: Pt,
        cpk: Pt,
        nonce: Sc,
        cards: Vec<LeaveCardPts>,
    },
    /// reconstruct CP-DLEQ 两联方程（c = handbatch_reconstruct_challenge）：
    ///   eq1: s·G1 − A − c·P1 = O
    ///   eq2: s·G2 − B − c·P2 = O
    /// wire 词序（13 词/条）：[g1 2, g2 2, p1 2, p2 2, A 2, B 2, s]。
    Reconstruct {
        s: Sc,
        g1: Pt,
        g2: Pt,
        p1: Pt,
        p2: Pt,
        a: Pt,
        b: Pt,
    },
    /// Bayer–Groth V2 洗牌（kind=5）：经 [`bg_shuffle_fold_equations`] 分解为
    /// 6 条线性方程（E1a, E1b, E3, E4a, E4b, E-batched——E2/E5/E6 已按
    /// E2/E5/E6 分开验证）+ 2 条标量校验。每条方程一个 ρ 词组
    /// （s=c=0——语句已由 BG transcript 自身整体绑定，ρ 只需记录"按序折
    /// 叠"），与 Cairo 端 bg_stark.cairo::bg_equation_words 同构。wire 词序
    /// （11n+31 词/条）：[n, input 4n, output 4n, pk 2, 承诺 22, 响应 3n+6]。
    Shuffle {
        input: Vec<poker_protocol_core::StarkElGamalCiphertext>,
        output: Vec<poker_protocol_core::StarkElGamalCiphertext>,
        pk: Pt,
        proof: Box<BayerGrothShuffleProof<StarkCurve>>,
    },
}

/// leave 每卡公开点。
#[derive(Debug, Clone)]
pub struct LeaveCardPts {
    pub in_c1: Pt,
    pub in_c2: Pt,
    pub out_c1: Pt,
    pub out_c2: Pt,
    pub a: Pt,
}

impl HandBatchEquation {
    /// 展开为（方程内点，ρ 词 (kind, s, c)）。
    fn points_and_words(
        &self,
        hand_binding: &[u8; 32],
        g: &Pt,
    ) -> (Vec<Pt>, poker_protocol_core::stark_curve::HandBatchEquationWords) {
        use poker_protocol_core::stark_curve::HandBatchEquationWords;
        match self {
            HandBatchEquation::Ownership { s, pk, r } => {
                let c = poker_protocol_core::stark_curve::handbatch_endorsement_challenge(
                    hand_binding, g, pk, r,
                );
                let eq = *g * *s + (-*pk) * c + (-*r);
                let mut s_w = [0u8; 32];
                s_w.copy_from_slice(&s.as_bytes());
                let mut c_w = [0u8; 32];
                c_w.copy_from_slice(&c.as_bytes());
                (vec![eq], HandBatchEquationWords { kind: 1, s: s_w, c: c_w })
            }
            HandBatchEquation::Reveal { s, pk, c1, c2, token, t1, t2, nonce } => {
                let c = poker_protocol_core::stark_curve::handbatch_reveal_challenge(
                    hand_binding, pk, c1, c2, token, t1, t2, nonce,
                );
                let eq1 = *g * *s + (-*pk) * c + (-*t1);
                let eq2 = *c1 * *s + (-*token) * c + (-*t2);
                let mut s_w = [0u8; 32];
                s_w.copy_from_slice(&s.as_bytes());
                let mut c_w = [0u8; 32];
                c_w.copy_from_slice(&c.as_bytes());
                (vec![eq1, eq2], HandBatchEquationWords { kind: 2, s: s_w, c: c_w })
            }
            HandBatchEquation::Leave { s, pk, cpk, nonce, cards } => {
                let card_words: Vec<poker_protocol_core::stark_curve::HandLeaveCardWords> = cards
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
                    hand_binding, pk, cpk, nonce, &card_words,
                );
                let mut pts = vec![*g * *s + (-*cpk) + (-*pk) * c];
                for card in cards {
                    let d2 = card.in_c2 - card.out_c2;
                    pts.push(card.in_c1 * *s + (-card.a) + (-d2) * c);
                }
                let mut s_w = [0u8; 32];
                s_w.copy_from_slice(&s.as_bytes());
                let mut c_w = [0u8; 32];
                c_w.copy_from_slice(&c.as_bytes());
                (pts, HandBatchEquationWords { kind: 3, s: s_w, c: c_w })
            }
            HandBatchEquation::Reconstruct { s, g1, g2, p1, p2, a, b } => {
                let c = poker_protocol_core::stark_curve::handbatch_reconstruct_challenge(
                    hand_binding, g1, g2, p1, p2, a, b,
                );
                let eq1 = *g1 * *s + (-*a) + (-*p1) * c;
                let eq2 = *g2 * *s + (-*b) + (-*p2) * c;
                let mut s_w = [0u8; 32];
                s_w.copy_from_slice(&s.as_bytes());
                let mut c_w = [0u8; 32];
                c_w.copy_from_slice(&c.as_bytes());
                (vec![eq1, eq2], HandBatchEquationWords { kind: 4, s: s_w, c: c_w })
            }
            HandBatchEquation::Shuffle { input, output, pk, proof } => {
                let eqs = bg_shuffle_fold_equations(input, output, pk, proof);
                let zero_w = [0u8; 32];
                // 每条 BG 方程一个残差点 + 一个 kind=5 ρ 词组（与 Cairo
                // hand_batch_stark 的 shuffle 桶折叠粒度一致）。
                let pts = eqs.equations.iter().map(|eq| linear_residual(eq)).collect();
                (pts, HandBatchEquationWords { kind: 5, s: zero_w, c: zero_w })
            }
        }
    }
}

/// 组装 hand_batch 载荷（P 层批次）。规范头（5 词）：
/// `[n_own, n_shuffle, n_reveal, n_leave, n_recon]`；随后按序：
/// - own：`(pk_x, pk_y, r_x, r_y, s) × n_own`（5 词/条）
/// - shuffle：BG 桶槽位（见 parse_batch_terms，暂拒）
/// - reveal：`(pk 2, c1 2, c2 2, token 2, t1 2, t2 2, nonce, s) × n_reveal`
///   （14 词/条）
/// - leave：每条 `[n, pk 2, cpk 2, nonce, s, in_c1 2n, in_c2 2n, out_c1 2n,
///   out_c2 2n, a 2n]`
/// - recon：`(g1 2, g2 2, p1 2, p2 2, A 2, B 2, s) × n_recon`（13 词/条）
fn assemble_batch(endorsements: &[Endorsement], recon: &[HandBatchEquation]) -> Vec<[u8; 32]> {
    let recon_terms: Vec<&HandBatchEquation> = recon
        .iter()
        .filter(|e| matches!(e, HandBatchEquation::Reconstruct { .. }))
        .collect();
    // 规范头（5 词）：[n_own, n_shuffle, n_reveal, n_leave, n_recon]
    let mut batch_words: Vec<[u8; 32]> =
        Vec::with_capacity(5 + 5 * endorsements.len() + 13 * recon_terms.len());
    batch_words.push(u256_word(endorsements.len() as u64));
    batch_words.push(u256_word(0));
    batch_words.push(u256_word(0));
    batch_words.push(u256_word(0));
    batch_words.push(u256_word(recon_terms.len() as u64));
    for e in endorsements {
        let (pk_x, pk_y) = point_xy(&e.pk);
        let (r_x, r_y) = point_xy(&e.r);
        batch_words.push(pk_x);
        batch_words.push(pk_y);
        batch_words.push(r_x);
        batch_words.push(r_y);
        batch_words.push(scalar_be(&e.s));
    }
    for term in recon_terms {
        if let HandBatchEquation::Reconstruct { s, g1, g2, p1, p2, a, b } = term {
            for p in [g1, g2, p1, p2, a, b] {
                let (x, y) = point_xy(p);
                batch_words.push(x);
                batch_words.push(y);
            }
            batch_words.push(scalar_be(s));
        }
    }
    batch_words
}

/// P2.1 客户端认可路径：用玩家客户端铸造并提交的成品认可构建结算，
/// 服务器全程不接触认可私钥。数量必须与参与者一致。
pub fn build_dual_settlement_from_client(
    mirror: &TableMirror,
    settlement: &HandSettlement,
    client_endorsements: &[ClientEndorsement],
) -> Result<DualSettlement, String> {
    if client_endorsements.len() != settlement.players_remapped.len() {
        return Err(format!(
            "dapv: client endorsement count {} != participants {}",
            client_endorsements.len(),
            settlement.players_remapped.len()
        ));
    }
    let endorsements: Vec<Endorsement> = client_endorsements
        .iter()
        .map(|c| Endorsement { pk: c.pk, r: c.r, s: c.s })
        .collect();
    // 与服务器铸造路径完全相同的构建（hand_binding/g_attestation/calldata）
    build_dual_settlement_with(mirror, settlement, &|_hb, _players| Ok(endorsements.clone()))
}

/// 解析 hand_batch 载荷为折叠项（与 Cairo 端 ownership_terms 同构；
/// 当前批次只含 ownership）。跨手重放检测与篡改检测的测试入口。
pub fn parse_batch_terms(hand_binding: &[u8; 32], batch_words: &[[u8; 32]]) -> Option<Vec<HandBatchEquation>> {
    // 规范头（5 词，Hand-batch v2.8 方程序序）：[n_own, n_shuffle, n_reveal, n_leave, n_recon]
    if batch_words.len() < 5 {
        return None;
    }
    let n_own = word_low_u64(&batch_words[0])? as usize;
    let n_shuffle = word_low_u64(&batch_words[1])? as usize;
    let n_reveal = word_low_u64(&batch_words[2])? as usize;
    let n_leave = word_low_u64(&batch_words[3])? as usize;
    let n_recon = word_low_u64(&batch_words[4])? as usize;
    if batch_words.len() < 5 + 5 * n_own + 14 * n_reveal + 13 * n_recon {
        return None;
    }
    let mut equations = Vec::with_capacity(n_own + n_reveal + n_leave + n_recon);
    for i in 0..n_own {
        let base = 5 + 5 * i;
        let pk = point_from_words(&batch_words[base], &batch_words[base + 1])?;
        let r = point_from_words(&batch_words[base + 2], &batch_words[base + 3])?;
        let s = scalar_from_word(&batch_words[base + 4])?;
        equations.push(HandBatchEquation::Ownership { s, pk, r });
    }
    // shuffle 桶（kind=5）：每条 [n, input 4n, output 4n, pk 2, 承诺 22,
    // 响应 3n+6] = 11n+31 词。重建 BayerGrothShuffleProof 后交
    // bg_shuffle_fold_equations 分解（挑战由 transcript 重放重算）。
    let mut cursor = 5 + 5 * n_own;
    for _ in 0..n_shuffle {
        if batch_words.len() < cursor + 1 {
            return None;
        }
        let n = word_low_u64(&batch_words[cursor])? as usize;
        if n == 0 {
            return None;
        }
        let bucket_len = 11 * n + 31;
        if batch_words.len() < cursor + bucket_len {
            return None;
        }
        let w = &batch_words[cursor..cursor + bucket_len];
        let mut o = 1usize;
        let mut ct_n = |o: &mut usize| -> Option<poker_protocol_core::StarkElGamalCiphertext> {
            let c1 = point_from_words(&w[*o], &w[*o + 1])?;
            let c2 = point_from_words(&w[*o + 2], &w[*o + 3])?;
            *o += 4;
            Some(poker_protocol_core::StarkElGamalCiphertext { c1, c2 })
        };
        let mut input = Vec::with_capacity(n);
        for _ in 0..n {
            input.push(ct_n(&mut o)?);
        }
        let mut output = Vec::with_capacity(n);
        for _ in 0..n {
            output.push(ct_n(&mut o)?);
        }
        let pk = point_from_words(&w[o], &w[o + 1])?;
        o += 2;
        let pt_n = |o: &mut usize| -> Option<Pt> {
            let p = point_from_words(&w[*o], &w[*o + 1])?;
            *o += 2;
            Some(p)
        };
        let sc_n = |o: &mut usize| -> Option<Sc> {
            let s = scalar_from_word(&w[*o])?;
            *o += 1;
            Some(s)
        };
        let c_permutation = pt_n(&mut o)?;
        let c_permuted_powers = pt_n(&mut o)?;
        let c_alpha = pt_n(&mut o)?;
        let c_beta = pt_n(&mut o)?;
        let ciphertext_0 = ct_n(&mut o)?;
        let ciphertext_1 = ct_n(&mut o)?;
        let c_d = pt_n(&mut o)?;
        let c_delta = pt_n(&mut o)?;
        let c_capital_delta = pt_n(&mut o)?;
        let mut alpha_response = Vec::with_capacity(n);
        for _ in 0..n {
            alpha_response.push(sc_n(&mut o)?);
        }
        let commitment_response = sc_n(&mut o)?;
        let beta = sc_n(&mut o)?;
        let beta_blinding_response = sc_n(&mut o)?;
        let rerandomization_response = sc_n(&mut o)?;
        let mut a_response = Vec::with_capacity(n);
        for _ in 0..n {
            a_response.push(sc_n(&mut o)?);
        }
        let mut b_response = Vec::with_capacity(n);
        for _ in 0..n {
            b_response.push(sc_n(&mut o)?);
        }
        let r_response = sc_n(&mut o)?;
        let s_response = sc_n(&mut o)?;
        debug_assert_eq!(o, bucket_len);
        equations.push(HandBatchEquation::Shuffle {
            input,
            output,
            pk,
            proof: Box::new(BayerGrothShuffleProof {
                c_permutation,
                c_permuted_powers,
                multi_exponentiation: MultiExponentiationArgument {
                    c_alpha,
                    c_beta,
                    ciphertext_0,
                    ciphertext_1,
                    alpha_response,
                    commitment_response,
                    beta,
                    beta_blinding_response,
                    rerandomization_response,
                },
                product: ProductArgument {
                    c_d,
                    c_delta,
                    c_capital_delta,
                    a_response,
                    b_response,
                    r_response,
                    s_response,
                },
            }),
        });
        cursor += bucket_len;
    }
    // reveal 词布局（与 secp 变体同构）：
    // [pk 2, c1 2, c2 2, token 2, t1 2, t2 2, nonce, s] = 14 词/条。
    for _ in 0..n_reveal {
        let pk = point_from_words(&batch_words[cursor], &batch_words[cursor + 1])?;
        let c1 = point_from_words(&batch_words[cursor + 2], &batch_words[cursor + 3])?;
        let c2 = point_from_words(&batch_words[cursor + 4], &batch_words[cursor + 5])?;
        let token = point_from_words(&batch_words[cursor + 6], &batch_words[cursor + 7])?;
        let t1 = point_from_words(&batch_words[cursor + 8], &batch_words[cursor + 9])?;
        let t2 = point_from_words(&batch_words[cursor + 10], &batch_words[cursor + 11])?;
        let nonce = scalar_from_word(&batch_words[cursor + 12])?;
        let s = scalar_from_word(&batch_words[cursor + 13])?;
        equations.push(HandBatchEquation::Reveal { s, pk, c1, c2, token, t1, t2, nonce });
        cursor += 14;
    }
    for _ in 0..n_leave {
        // [n, pk 2, cpk 2, nonce, s, in_c1 2n, in_c2 2n, out_c1 2n, out_c2 2n, a 2n]
        let n_cards = word_low_u64(&batch_words[cursor])? as usize;
        if batch_words.len() < cursor + 7 + 10 * n_cards {
            return None;
        }
        let pk = point_from_words(&batch_words[cursor + 1], &batch_words[cursor + 2])?;
        let cpk = point_from_words(&batch_words[cursor + 3], &batch_words[cursor + 4])?;
        let nonce = scalar_from_word(&batch_words[cursor + 5])?;
        let s = scalar_from_word(&batch_words[cursor + 6])?;
        let base = cursor + 7;
        let mut cards = Vec::with_capacity(n_cards);
        for i in 0..n_cards {
            let o = base + 2 * i;
            let in_c1 = point_from_words(&batch_words[o], &batch_words[o + 1])?;
            let in_c2 = point_from_words(&batch_words[base + 2 * n_cards + 2 * i], &batch_words[base + 2 * n_cards + 2 * i + 1])?;
            let out_c1 = point_from_words(&batch_words[base + 4 * n_cards + 2 * i], &batch_words[base + 4 * n_cards + 2 * i + 1])?;
            let out_c2 = point_from_words(&batch_words[base + 6 * n_cards + 2 * i], &batch_words[base + 6 * n_cards + 2 * i + 1])?;
            let a = point_from_words(&batch_words[base + 8 * n_cards + 2 * i], &batch_words[base + 8 * n_cards + 2 * i + 1])?;
            cards.push(LeaveCardPts { in_c1, in_c2, out_c1, out_c2, a });
        }
        equations.push(HandBatchEquation::Leave { s, pk, cpk, nonce, cards });
        cursor += 7 + 10 * n_cards;
    }
    // recon 词布局：[g1 2, g2 2, p1 2, p2 2, A 2, B 2, s] = 13 词/条。
    for _ in 0..n_recon {
        let g1 = point_from_words(&batch_words[cursor], &batch_words[cursor + 1])?;
        let g2 = point_from_words(&batch_words[cursor + 2], &batch_words[cursor + 3])?;
        let p1 = point_from_words(&batch_words[cursor + 4], &batch_words[cursor + 5])?;
        let p2 = point_from_words(&batch_words[cursor + 6], &batch_words[cursor + 7])?;
        let a = point_from_words(&batch_words[cursor + 8], &batch_words[cursor + 9])?;
        let b = point_from_words(&batch_words[cursor + 10], &batch_words[cursor + 11])?;
        let s = scalar_from_word(&batch_words[cursor + 12])?;
        equations.push(HandBatchEquation::Reconstruct { s, g1, g2, p1, p2, a, b });
        cursor += 13;
    }
    Some(equations)
}

fn word_low_u64(w: &[u8; 32]) -> Option<u64> {
    if w[..24].iter().any(|b| *b != 0) {
        return None;
    }
    let mut tail = [0u8; 8];
    tail.copy_from_slice(&w[24..]);
    Some(u64::from_be_bytes(tail))
}

fn point_from_words(x: &[u8; 32], y: &[u8; 32]) -> Option<Pt> {
    // types-core Felt 与 Pt（StarkPoint）内部域一致；BETA 来自
    // starknet-curve 0.6（同 types-core 0.2 类型实例）。
    use starknet_curve::curve_params::BETA;
    use starknet_types_core::felt::Felt;
    let px = Felt::from_bytes_be(x);
    let py = Felt::from_bytes_be(y);
    // 恶意载荷可能给出不在曲线上的 (x, y)：折叠数学只在真曲线上成立，
    // 解析时必须验证曲线方程 y² = x³ + x + β（STARK 曲线，a=1）。
    if py * py != px * px * px + px + BETA {
        return None;
    }
    Some(Pt::from_affine_parts(px, py))
}

fn scalar_from_word(w: &[u8; 32]) -> Option<Sc> {
    <Sc as CurveScalar>::from_canonical_bytes(w)
}

fn u256_word(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&v.to_be_bytes());
    out
}

/// 提交 Hand-batch 结算。按 `STARKNET_SETTLE_MODE` 分流：
///
/// - `Linear`（默认）：`register_hand` + `verify_and_settle_dapv`
///   （p_batch 全文上链）——与引入 settle-mode 之前的行为一致。
/// - `Proved`：先导出 workload JSON（prover CLI 的输入，best-effort），
///   再尝试外部 prover attestation（当前为必然报错的存根）；**任何**
///   错误/超时自动回退 linear 路径（复用同一份 batch_words/calldata，
///   结算绝不因 prover 阻塞）。attestation 成功且承诺匹配时才走
///   `register_hand_proved` + `verify_and_settle_dapv_proved`。
///
/// 返回 (register_tx, settle_tx)。
/// Part A Phase 1：检查所有赢家是否已在 vault 注册 payout commitment。
/// 任一未注册 → 私有结算入口缺前置，回退 legacy（不卡结算）。
async fn winners_registered(players_remapped: &[Ff], deltas: &[i128]) -> bool {
    let Some(chain) = super::chain() else {
        return false;
    };
    let Some(vault_addr) = super::chain::parse_felt(&chain.config.vault_address) else {
        return false;
    };
    let selector = starknet_keccak(b"payout_commitment");
    for (i, p) in players_remapped.iter().enumerate() {
        // 只有赢家（delta > 0）需要 payout commitment——输家走公开扣款。
        let Some(d) = deltas.get(i) else { return false };
        if *d <= 0 {
            continue;
        }
        match chain
            .call_contract(vault_addr, selector, vec![ff_to_felt(*p)])
            .await
        {
            Ok(felts) => {
                let registered = felts.first().map(|f| *f != Felt::ZERO).unwrap_or(false);
                if !registered {
                    tracing::info!(
                        "[starknet-settle] winner {p:#x} has no payout commitment — legacy settle"
                    );
                    return false;
                }
            }
            Err(e) => {
                tracing::warn!("[starknet-settle] payout_commitment query failed: {e}");
                return false;
            }
        }
    }
    true
}

pub async fn submit_dual_settlement(
    dual: &DualSettlement,
    dual_address: &str,
    players_remapped: &[Ff],
    deltas: &[i128],
) -> Result<(String, String), String> {
    let chain = super::chain().ok_or("starknet chain not initialized")?;
    let contract = super::chain::parse_felt(dual_address)
        .ok_or("invalid dual settlement contract address")?;
    let operator = chain.operator().await.ok_or("operator account unavailable")?;

    // 模式决策（proved → 尝试 prover → 失败回退 linear）。
    let mode = if chain.config.settle_mode == SettleMode::Proved {
        export_prover_workload(dual, std::path::Path::new(&chain.config.prover_work_dir));
        let prover = HttpBatchProver::new(chain.config.prover_url.clone());
        let workload = ProverWorkload {
            hand_binding: dual.hand_binding,
            hand_id: dual.hand_id,
            batch_words: dual.batch_words.clone(),
            p_batch_commitment: dual.proved.p_batch_commitment,
        };
        let resolved = resolve_settle_mode_with_prover(&prover, &workload).await;
        if resolved == SettleMode::Proved {
            tracing::info!(
                "[dapv-proved] table settling via proved entry (commitment {:#x}, {} words)",
                dual.proved.p_batch_commitment,
                dual.proved.p_batch_len
            );
        }
        resolved
    } else {
        SettleMode::Linear
    };

    // Part A Phase 1：STARKNET_SETTLE_PRIVATE=true 时走隐私结算入口
    // （赢家派奖进认领托管而非公开 chip 余额；输家仍公开扣款）。
    // 前置条件：所有赢家已在 vault 注册 payout commitment——未齐则自动
    // 回退 legacy 入口（下一手再试），绝不因缺注册而卡死结算。
    let settle_private = std::env::var("STARKNET_SETTLE_PRIVATE")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);
    let use_private =
        settle_private && winners_registered(players_remapped, deltas).await;

    let (register_selector, register_calldata, settle_selector, settle_calldata) =
        match mode {
            SettleMode::Proved => (
                "register_hand_proved",
                dual.proved.register_calldata.clone(),
                "verify_and_settle_dapv_proved",
                dual.proved.settle_calldata.clone(),
            ),
            SettleMode::Linear => (
                "register_hand",
                dual.register_calldata.clone(),
                if use_private {
                    "verify_and_settle_dapv_stark_private"
                } else {
                    "verify_and_settle_dapv_stark"
                },
                dual.settle_calldata.clone(),
            ),
        };

    let register_hash = match operator
        .execute_v3(vec![Call {
            to: contract,
            selector: starknet_keccak(register_selector.as_bytes()),
            calldata: register_calldata,
        }])
        .send()
        .await
    {
        Ok(r) => format!("{:#x}", r.transaction_hash),
        Err(e) => {
            let text = format!("{e}");
            // 幂等重放：本手 binding 已注册（此前某次尝试已成功）。
            if text.contains("already registered") || text.contains("Binding already") {
                "already-registered".to_string()
            } else {
                return Err(format!("{register_selector} submit failed: {e}"));
            }
        }
    };

    // settle 断言 binding 已注册；两笔交易存在包含时差——轮询等注册可见
    // 再提交 settle（hand_binding view 的第三位 = registered 标记）。
    {
        use starknet::providers::Provider;
        let selector = starknet_keccak("hand_binding".as_bytes());
        let binding_felt = super::chain::parse_felt(&format!("{:#x}", dual.hand_binding))
            .ok_or("invalid hand binding felt")?;
        let mut visible = false;
        for _ in 0..45 {
            if let Ok(felts) = chain
                .call_contract(contract, selector, vec![binding_felt])
                .await
            {
                if felts.get(2).map(|f| *f == Felt::ONE).unwrap_or(false) {
                    visible = true;
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
        }
        if !visible {
            return Err("hand_binding registration not visible on-chain within 45s".into());
        }
    }

    let settle_hash = operator
        .execute_v3(vec![Call {
            to: contract,
            selector: starknet_keccak(settle_selector.as_bytes()),
            calldata: settle_calldata,
        }])
        .send()
        .await
        .map_err(|e| format!("{settle_selector} submit failed: {e}"))?;

    Ok((
        register_hash,
        format!("{:#x}", settle_hash.transaction_hash),
    ))
}

#[allow(dead_code)]
fn _ensure_imports() {
    // 保持 ExecutionEncoding 引用（operator 类型由 chain 模块决定）。
    let _ = ExecutionEncoding::New;
}

// ============================================================
// Plan D P2：BG 洗牌可折叠方程（felt 直通 Poseidon transcript 纪元）
//
// 给定一条在 PoseidonFeltTranscript 上证明的诚实
// BayerGrothShuffleProof<StarkCurve>，把 verify() 的全部点校验分解为
// 纯线性方程（每条 = Σ scalar_i · point_i = O，负系数表达减项）+ 两条
// 纯标量校验。Cairo 端只需：重放 transcript 取挑战 → 从公开词重建
// 方程组 → ρ 折叠单点校验。
// ============================================================

/// BG 承诺密钥（与 poker-protocol-bg/src/proof.rs::CommitmentKey 同派生：
/// h = hash_to_curve("poker/bg12/v2/H")，CK_i =
/// hash_to_curve("poker/bg12/v2/G/{n}/{i}")）——公开词，Cairo 端作为
/// 常量钉死（见 /tmp/bgvectors/ck_n52.txt）。
pub struct BgCommitmentKey {
    pub h: Pt,
    pub generators: Vec<Pt>,
}

impl BgCommitmentKey {
    pub fn derive(n: usize) -> BgCommitmentKey {
        let h = <StarkCurve as Curve>::hash_to_curve(b"poker/bg12/v2/H");
        let generators = (0..n)
            .map(|i| <StarkCurve as Curve>::hash_to_curve(format!("poker/bg12/v2/G/{n}/{i}").as_bytes()))
            .collect();
        BgCommitmentKey { h, generators }
    }
}

/// 一条线性点方程：Σ (scalar_i · point_i) = O（负 scalar 表减项）。
pub type LinearTerms = Vec<(Sc, Pt)>;

/// 方程残差（lhs 求和；诚实证明 = 恒等点 O）。
pub fn linear_residual(terms: &LinearTerms) -> Pt {
    terms
        .iter()
        .map(|(s, p)| *p * *s)
        .fold(<Pt as CurvePoint>::identity(), |acc, t| acc + t)
}

/// BG 方程组 + 派生挑战 + 两条标量校验的公开中间量。
pub struct BgShuffleEquations {
    pub ck: BgCommitmentKey,
    /// transcript 派生挑战：x（powers）、y、z、e（mexp）、q（product）。
    pub powers_challenge: Sc,
    pub product_y: Sc,
    pub product_z: Sc,
    pub mexp_challenge: Sc,
    pub product_challenge: Sc,
    /// E1（2 条）+ E2 + E3 + E4（2 条）+ E5 + E6，共 8 条线性方程
    ///（顺序：E1a, E1b, E2, E3, E4a, E4b, E5, E6）。
    pub equations: Vec<LinearTerms>,
    /// 标量校验 1：b_response[0] == a_response[0]。
    pub scalar_check_1: bool,
    /// 标量校验 2：b_response[n−1] == q·Π_{i=1..n}(y·i + x^i − z)。
    pub scalar_check_2: bool,
}

use poker_protocol::zk_shuffle::bayer_groth::{
    BayerGrothShuffleProof, MultiExponentiationArgument, ProductArgument,
};

/// BG 验证 transcript 上的非零挑战（与 proof.rs::challenge_nonzero 同
/// 重采样语义；poseidon 输出为零的概率 ≈ 2^-251，循环仅为语义对齐）。
fn challenge_nonzero_stark(
    transcript: &mut poker_protocol_core::PoseidonFeltTranscript,
    label: &[u8],
) -> Sc {
    use poker_protocol_core::CryptoTranscript as _;
    let mut challenge = transcript.challenge::<StarkCurve>(label).scalar;
    let mut counter = 0u32;
    while challenge == <Sc as CurveScalar>::zero() {
        transcript.append_message(b"bg12_zero_challenge_retry", &counter.to_le_bytes());
        challenge = transcript.challenge::<StarkCurve>(label).scalar;
        counter = counter.wrapping_add(1);
    }
    challenge
}

/// 从公开词重放 BG 验证 transcript（与 poker-protocol-bg/src/proof.rs
/// verify() 的 append 顺序逐字节一致），返回五个挑战
/// (x=powers, y, z, e=mexp, q=product)。
pub fn bg_replay_challenges(
    input: &[poker_protocol_core::StarkElGamalCiphertext],
    output: &[poker_protocol_core::StarkElGamalCiphertext],
    pk: &Pt,
    proof: &BayerGrothShuffleProof<StarkCurve>,
    transcript: &mut poker_protocol_core::PoseidonFeltTranscript,
) -> (Sc, Sc, Sc, Sc, Sc) {
    use poker_protocol_core::CryptoTranscript as _;
    let mexp = &proof.multi_exponentiation;

    transcript.append_message(b"bg12_protocol", b"poker/bayer-groth-shuffle/v2");
    transcript.append_message(b"bg12_deck_size", &(input.len() as u64).to_le_bytes());
    transcript.append_point::<StarkCurve>(b"bg12_public_key", pk);
    for (label, cts) in [(b"input" as &[u8], input), (b"output" as &[u8], output)] {
        for ct in cts {
            transcript.append_message(b"bg12_ciphertext_label", label);
            transcript.append_point::<StarkCurve>(b"bg12_ciphertext_c1", &ct.c1);
            transcript.append_point::<StarkCurve>(b"bg12_ciphertext_c2", &ct.c2);
        }
    }
    transcript.append_point::<StarkCurve>(b"bg12_c_permutation", &proof.c_permutation);
    let x = challenge_nonzero_stark(transcript, b"bg12_powers_challenge");
    transcript.append_point::<StarkCurve>(b"bg12_c_permuted_powers", &proof.c_permuted_powers);
    let y = challenge_nonzero_stark(transcript, b"bg12_product_y");
    let z = challenge_nonzero_stark(transcript, b"bg12_product_z");

    transcript.append_point::<StarkCurve>(b"bg12_mexp_c_alpha", &mexp.c_alpha);
    transcript.append_point::<StarkCurve>(b"bg12_mexp_c_beta", &mexp.c_beta);
    for (label, ct) in [(b"mexp_0", &mexp.ciphertext_0), (b"mexp_1", &mexp.ciphertext_1)] {
        transcript.append_message(b"bg12_ciphertext_label", label);
        transcript.append_point::<StarkCurve>(b"bg12_ciphertext_c1", &ct.c1);
        transcript.append_point::<StarkCurve>(b"bg12_ciphertext_c2", &ct.c2);
    }
    let e = challenge_nonzero_stark(transcript, b"bg12_mexp_challenge");

    let product = &proof.product;
    transcript.append_point::<StarkCurve>(b"bg12_product_c_d", &product.c_d);
    transcript.append_point::<StarkCurve>(b"bg12_product_c_delta", &product.c_delta);
    transcript.append_point::<StarkCurve>(b"bg12_product_c_capital_delta", &product.c_capital_delta);
    let q = challenge_nonzero_stark(transcript, b"bg12_product_challenge");

    (x, y, z, e, q)
}

/// 把一条（诚实或待检的）BG 证明分解为线性方程组 + 标量校验。
///
/// 方程（均以残差 Σ scalar·point = O 表达，符号从 proof.rs verify()
/// 的 lhs−rhs 逐条推出）：
/// - E1（2 条）：msm(input, x^i) − ciphertext_1 = O（c1 与 c2 各一条）
/// - E2：e·c_permuted_powers + c_alpha − vc(alpha_resp, commit_resp)
/// - E3：c_beta − G·beta − CK_h·beta_blinding_response = O
/// - E4（2 条）：ciphertext_0 + e·ciphertext_1 − (G·τ +
///   msm(output, alpha_response)) = O（c1 侧）；c2 侧再 − G·beta − pk·τ
/// - E5：c_d + q·(y·c_perm + c_ppow) − q·z·S − vc(a_resp, r_resp)，
///   其中 c_minus_z = Σ(−z)·CK_i 因式为均匀标量 −z 乘 S = Σ CK_i
///   （CK 钉死常量，S 由程序内 52 次点加预计算，代数恒等）
/// - E6：c_delta + q·c_capital_delta − vc(recurrence, s_resp)，
///   recurrence_i = q·b_{i+1} − b_i·a_{i+1}（i<n−1），
///   recurrence_{n−1} = 0
///
/// 注意：E2/E5/E6 **不做** λ-批量合并（历史教训，见函数体内注释）：
/// 共享 λ 等价于检验裸和 E2+E5+E6，可被分量相消攻破；独立 λ 在
/// Cairo 成本模型下（fr_mul ≈ 12× EC 点乘）反而净亏。
pub fn bg_shuffle_fold_equations(
    input: &[poker_protocol_core::StarkElGamalCiphertext],
    output: &[poker_protocol_core::StarkElGamalCiphertext],
    pk: &Pt,
    proof: &BayerGrothShuffleProof<StarkCurve>,
) -> BgShuffleEquations {
    let n = input.len();
    let ck = BgCommitmentKey::derive(n);
    let mut tr = poker_protocol_core::PoseidonFeltTranscript::new_bg_fold();
    let (x, y, z, e, q) = bg_replay_challenges(input, output, pk, proof, &mut tr);
    let mexp = &proof.multi_exponentiation;
    let product = &proof.product;
    let g = StarkCurve::base_g();
    let one = <Sc as CurveScalar>::one();

    // 公开幂 x^1..x^n
    let mut powers = Vec::with_capacity(n);
    let mut cur = x;
    for _ in 0..n {
        powers.push(cur);
        cur = cur * x;
    }

    // S = Σ_i CK_i（均匀标量因式化的基；CK 为钉死常量，S 程序内
    // 52 次点加预计算，Rust/Cairo 一致）。
    let s_sum = ck
        .generators
        .iter()
        .fold(<Pt as CurvePoint>::identity(), |acc, p| acc + *p);

    let mut equations: Vec<LinearTerms> = Vec::with_capacity(8);

    // E1：Σ x^{i+1}·input_i − ciphertext_1 = O（c1 / c2）
    for side in [0usize, 1] {
        let mut terms: LinearTerms = input
            .iter()
            .zip(powers.iter())
            .map(|(ct, p)| {
                let pt = if side == 0 { ct.c1 } else { ct.c2 };
                (*p, pt)
            })
            .collect();
        terms.push((-one, if side == 0 { mexp.ciphertext_1.c1 } else { mexp.ciphertext_1.c2 }));
        equations.push(terms);
    }

    // E3：c_beta − G·beta − CK_h·beta_blinding_response = O
    equations.push(vec![
        (one, mexp.c_beta),
        (-mexp.beta, g),
        (-mexp.beta_blinding_response, ck.h),
    ]);

    // E4：ct0 + e·ct1 − (G·τ + Σ alpha_resp_i·output_i) = O
    //     ct0.c2 + e·ct1.c2 − (G·beta + pk·τ + Σ alpha_resp_i·output_i.c2) = O
    {
        let mut terms = vec![
            (one, mexp.ciphertext_0.c1),
            (e, mexp.ciphertext_1.c1),
            (-mexp.rerandomization_response, g),
        ];
        for (resp, ct) in mexp.alpha_response.iter().zip(output.iter()) {
            terms.push((-resp, ct.c1));
        }
        equations.push(terms);

        let mut terms = vec![
            (one, mexp.ciphertext_0.c2),
            (e, mexp.ciphertext_1.c2),
            (-mexp.beta, g),
            (-mexp.rerandomization_response, *pk),
        ];
        for (resp, ct) in mexp.alpha_response.iter().zip(output.iter()) {
            terms.push((-resp, ct.c2));
        }
        equations.push(terms);
    }

    // E2/E5/E6 **分开**验证（不做 λ-批量合并）。两个原因，写在这里
    // 防止将来重蹈：
    // 1. Soundness：共享单一 λ 的合并等价于检验 E2+E5+E6 = O——
    //    α_response/a_response 等都是证明者自由选取的公开词，E2/E5
    //    对它们线性，取 E2 残差 = P、E5 残差 = −P 即可精确相消；
    //    小指数批量验证需**独立**随机指数（λ₂,λ₅,λ₆）才成立。
    // 2. 成本：Cairo VM 里 mod-n 标量乘（fr_mul，u256 无 mul-mod
    //    builtin）每元素数千 step，而 EC 点乘走 EC_OP builtin
    //    ≈ 162 step——独立 λ 每元素 3 次 fr_mul，省下的 EC 点乘
    //    远 cover 不住（实测 λ 合并 +17% step-gas）。
    // E2：e·c_permuted_powers + c_alpha − vc(alpha_resp, commit_resp)
    equations.push({
        let mut terms: LinearTerms = mexp
            .alpha_response
            .iter()
            .zip(ck.generators.iter())
            .map(|(a, ck_i)| (-*a, *ck_i))
            .collect();
        terms.push((e, proof.c_permuted_powers));
        terms.push((one, mexp.c_alpha));
        terms.push((-mexp.commitment_response, ck.h));
        terms
    });
    // E5：c_d + q·(y·c_perm + c_ppow) − q·z·S − vc(a_resp, r_resp)。
    // 均匀标量因式化：c_minus_z = Σ(−z)·CK_i = −z·S（S = Σ CK_i，
    // 52 次点加预计算，代数恒等）。
    equations.push({
        let mut terms: LinearTerms = product
            .a_response
            .iter()
            .zip(ck.generators.iter())
            .map(|(a, ck_i)| (-*a, *ck_i))
            .collect();
        terms.push((one, product.c_d));
        terms.push((q * y, proof.c_permutation));
        terms.push((q, proof.c_permuted_powers));
        terms.push((-(q * z), s_sum));
        terms.push((-product.r_response, ck.h));
        terms
    });
    // E6：c_delta + q·c_capital_delta − vc(recurrence, s_resp)
    equations.push({
        // recurrence_i = q·b_{i+1} − b_i·a_{i+1}（i < n−1），否则 0
        let mut recurrence = vec![<Sc as CurveScalar>::zero(); n];
        for i in 0..n.saturating_sub(1) {
            recurrence[i] = q * product.b_response[i + 1]
                - product.b_response[i] * product.a_response[i + 1];
        }
        let mut terms: LinearTerms = recurrence
            .iter()
            .zip(ck.generators.iter())
            .map(|(r, ck_i)| (-*r, *ck_i))
            .collect();
        terms.push((one, product.c_delta));
        terms.push((q, product.c_capital_delta));
        terms.push((-product.s_response, ck.h));
        terms
    });

    // 标量校验 2：b_response[n−1] == q·Π_{i=1..n}(y·i + x^i − z)
    let expected_product = powers
        .iter()
        .enumerate()
        .map(|(i, &xp)| y * <Sc as CurveScalar>::from_u64(i as u64 + 1) + xp - z)
        .fold(one, |acc, v| acc * v);

    BgShuffleEquations {
        ck,
        powers_challenge: x,
        product_y: y,
        product_z: z,
        mexp_challenge: e,
        product_challenge: q,
        equations,
        scalar_check_1: product.b_response[0] == product.a_response[0],
        scalar_check_2: product.b_response[n - 1] == q * expected_product,
    }
}

/// 线性方程组的 ρ 折叠宿主 parity（与 host_fold_check 同 Horner 结构；
/// BG 方程 kind=5 词绑定）。诚实方程组残差逐条为恒等，折叠亦必为恒等。
pub fn host_fold_check_linear(hand_binding: &[u8; 32], equations: &[LinearTerms]) -> bool {
    if equations.is_empty() {
        return false;
    }
    let residuals: Vec<Pt> = equations.iter().map(linear_residual).collect();
    let words: Vec<poker_protocol_core::stark_curve::HandBatchEquationWords> = equations
        .iter()
        .map(|_| poker_protocol_core::stark_curve::HandBatchEquationWords {
            kind: 5,
            s: [0u8; 32],
            c: [0u8; 32],
        })
        .collect();
    let rho = poker_protocol_core::stark_curve::handbatch_rho(hand_binding, &words);
    let mut acc = residuals[residuals.len() - 1];
    for eq in residuals[..residuals.len() - 1].iter().rev() {
        acc = acc * rho + *eq;
    }
    acc.is_identity()
}
#[cfg(test)]
mod stark_endorsement_tests {
    use super::*;
    use rand_core::{CryptoRng, RngCore};

    fn random_scalar() -> Sc {
        <Sc as CurveScalar>::random(&mut rand::rngs::OsRng)
    }

    fn mint_batch(hand_id_bytes: [u8; 32], count: usize) -> Vec<[u8; 32]> {
        let mut words = vec![
            u256_word(count as u64),
            u256_word(0),
            u256_word(0),
            u256_word(0),
            u256_word(0),
        ];
        for _ in 0..count {
            let sk = random_scalar();
            let pk = StarkCurve::base_g() * sk;
            let endorsement = mint_endorsement(&sk, &pk, &hand_id_bytes);
            let (pk_x, pk_y) = point_xy(&endorsement.pk);
            let (r_x, r_y) = point_xy(&endorsement.r);
            words.push(pk_x);
            words.push(pk_y);
            words.push(r_x);
            words.push(r_y);
            words.push(scalar_be(&endorsement.s));
        }
        words
    }

    #[test]
    fn stark_endorsement_batch_folds_to_identity() {
        let hand_id = [0x42u8; 32];
        let words = mint_batch(hand_id, 3);
        let equations = parse_batch_terms(&hand_id, &words).expect("well-formed batch parses");
        assert_eq!(equations.len(), 3, "3 ownership equations");
        assert!(
            host_fold_check(&hand_id, &equations),
            "honest batch must fold to the identity point (Horner)"
        );
    }

    #[test]
    fn tampered_scalar_breaks_fold() {
        let hand_id = [0x43u8; 32];
        let mut words = mint_batch(hand_id, 2);
        // 篡改最后一个认可标量：s += 1
        let last = words.len() - 1;
        let mut s = words[last];
        let one = {
            let mut b = [0u8; 32];
            b[31] = 1;
            b
        };
        for i in (0..32).rev() {
            let (sum, carry) = (s[i] as u16 + one[i] as u16, s[i] as u16 + one[i] as u16);
            let _ = sum;
            let _ = carry;
            break;
        }
        // 直接逐字节加一（小端进位简化：仅最低字节 +1，溢出忽略——测试用）
        s[31] = s[31].wrapping_add(1);
        words[last] = s;
        let terms = parse_batch_terms(&hand_id, &words).expect("shape still parses");
        assert!(
            !host_fold_check(&hand_id, &terms),
            "a tampered endorsement scalar must not fold to identity"
        );
    }

    #[test]
    fn cross_hand_replay_is_rejected() {
        // hand A 域铸造的认可批次，放进 hand B 的解析域：挑战 c 因域分离
        // 而不同，折叠必非恒等（§9-L2 hand-bound 语义）。
        let hand_a = [0xAAu8; 32];
        let hand_b = [0xBBu8; 32];
        let words = mint_batch(hand_a, 2);
        let terms = parse_batch_terms(&hand_b, &words).expect("shape parses under any domain");
        assert!(
            !host_fold_check(&hand_b, &terms),
            "endorsements minted for hand A must not fold under hand B's domain"
        );
    }

    #[test]
    fn off_curve_payload_point_is_rejected() {
        // 非曲线 (x, y)：y 取一个大概率不满足 y² = x³ + x + β 的值
        let x = starknet_types_core::felt::Felt::from(7u64);
        let bad_y = starknet_types_core::felt::Felt::from(7u64);
        assert!(
            point_from_words(&x.to_bytes_be(), &bad_y.to_bytes_be()).is_none(),
            "off-curve payload coordinates must be rejected at parse time"
        );
        // 曲线上的点必须接受
        let pk = StarkCurve::base_g() * random_scalar();
        let (gx, gy) = point_xy(&pk);
        assert!(point_from_words(&gx, &gy).is_some(), "on-curve point accepted");
    }

    #[test]
    fn reveal_commitment_label_and_felt_chunks_are_stable() {
        // 域分隔标签确定性
        let l1 = handbatch_reveal_commit_label();
        let l2 = handbatch_reveal_commit_label();
        assert_eq!(l1, l2);
        // 31 字节分块：65 字节 → 3 块（31+31+3），无截断
        let bytes: Vec<u8> = (0..65u8).collect();
        let felts = bytes_as_felts(&bytes);
        assert_eq!(felts.len(), 3);
        // 确定性
        assert_eq!(bytes_as_felts(&bytes), felts);
    }
}

#[cfg(test)]
mod stark_vector_gen {
    use super::*;

    /// 生成 hand_batch_stark.cairo 的测试向量（运行：
    /// cargo +nightly test -p texas print_stark_batch_vector -- --ignored --nocapture）
    #[test]
    #[ignore = "vector generator: prints cairo literal"]
    fn print_stark_batch_vector() {
        print_stark_batch_vector_n(2, "print_stark_batch_vector_n2");
        print_stark_batch_vector_n(4, "print_stark_batch_vector_n4");
    }

    fn print_stark_batch_vector_n(n: usize, label: &str) {
        // 首字节压到 < 0x08：hand_binding 是合法 felt（真实场景恒为
        // Poseidon 输出 < 2^251，天然满足；合成向量显式满足以免
        // host/合约对超域值的归约解释分叉）。
        let mut hand_id = [0x5Bu8; 32];
        hand_id[0] = 0x02;
        let mut words = vec![
            u256_word(n as u64),
            u256_word(0),
            u256_word(0),
            u256_word(0),
            u256_word(0),
        ];
        for i in 0..n as u64 {
            let sk = <Sc as CurveScalar>::from_u64(100 + i);
            let pk = StarkCurve::base_g() * sk;
            let e = mint_endorsement(&sk, &pk, &hand_id);
            let (pk_x, pk_y) = point_xy(&e.pk);
            let (r_x, r_y) = point_xy(&e.r);
            words.push(pk_x);
            words.push(pk_y);
            words.push(r_x);
            words.push(r_y);
            words.push(scalar_be(&e.s));
        }
        let terms = parse_batch_terms(&hand_id, &words).expect("parse");
        assert!(host_fold_check(&hand_id, &terms), "vector must fold");
        // hand_binding 的 felt 表示（Cairo 端测试直接引用）
        let binding_felt = bytes_to_field(&hand_id);
        println!("// {label}: hand_binding felt: {binding_felt:#x}");
        println!("// {label}: hand_id (32B):");
        print_cairo_u8_array(&hand_id);
        println!("// {label}: payload ({} felt252 words):", words.len());
        print_cairo_felt_array(&words);
    }

    /// leave-only 最小向量（隔离对照 host/Cairo）。
    #[test]
    #[ignore = "vector generator: leave-only"]
    fn print_leave_only() {
        use poker_protocol::crypto::curve::StarkCurve;
        type SSC = <StarkCurve as Curve>::Scalar;
        let mut hand_binding = [0x5Bu8; 32];
        hand_binding[0] = 0x02;
        let g = StarkCurve::base_g();
        let lsk = <Sc as CurveScalar>::from_u64(9001);
        let l_pk = g * lsk;
        let omega = <Sc as CurveScalar>::from_u64(9002);
        let cpk = g * omega;
        let nonce = <Sc as CurveScalar>::from_u64(9003);
        // 1 张剥层卡（确定性）
        let msg = <StarkCurve as Curve>::hash_to_curve(b"leave-only/card-0");
        let r = <Sc as CurveScalar>::from_u64(9004);
        let ct = poker_protocol::crypto::ElGamalCiphertextGeneric::<StarkCurve>::encrypt(&msg, &l_pk, &r);
        let out_ct = poker_protocol::crypto::ElGamalCiphertextGeneric::<StarkCurve> {
            c1: ct.c1,
            c2: ct.c2 - ct.c1 * lsk,
        };
        let a = ct.c1 * omega;
        let cards = vec![super::super::dual_settle::LeaveCardPts {
            in_c1: ct.c1, in_c2: ct.c2, out_c1: out_ct.c1, out_c2: out_ct.c2, a,
        }];
        let card_words: Vec<poker_protocol_core::stark_curve::HandLeaveCardWords> = cards
            .iter()
            .map(|c| poker_protocol_core::stark_curve::HandLeaveCardWords {
                in_c1: c.in_c1, in_c2: c.in_c2, out_c1: c.out_c1, out_c2: c.out_c2, a: c.a,
            })
            .collect();
        let c = poker_protocol_core::stark_curve::handbatch_leave_challenge(
            &hand_binding, &l_pk, &cpk, &nonce, &card_words,
        );
        let s = omega + c * lsk;
        println!("// leave-only host c = 0x{}", {
            let b = c.as_bytes();
            b.iter().map(|x| format!("{x:02x}")).collect::<String>()
        });
        let mut words = vec![
            u256_word(0),
            u256_word(0),
            u256_word(0),
            u256_word(1),
            u256_word(0),
        ];
        words.push(u256_word(1));
        let (x, y) = point_xy(&l_pk); words.push(x); words.push(y);
        let (x, y) = point_xy(&cpk); words.push(x); words.push(y);
        let mut nb = [0u8; 32]; nb.copy_from_slice(&nonce.as_bytes()); words.push(nb);
        let mut sb = [0u8; 32]; sb.copy_from_slice(&s.as_bytes()); words.push(sb);
        let (x, y) = point_xy(&ct.c1); words.push(x); words.push(y);
        let (x, y) = point_xy(&ct.c2); words.push(x); words.push(y);
        let (x, y) = point_xy(&out_ct.c1); words.push(x); words.push(y);
        let (x, y) = point_xy(&out_ct.c2); words.push(x); words.push(y);
        let (x, y) = point_xy(&a); words.push(x); words.push(y);
        let parsed = parse_batch_terms(&hand_binding, &words).expect("parse");
        assert!(host_fold_check(&hand_binding, &parsed), "leave-only must fold");
        println!("// leave-only payload ({} words):", words.len());
        println!("        array![");
        for w in &words { println!("            0x{},", hex::encode(w)); }
        println!("        ]");
    }

    fn print_cairo_u8_array(bytes: &[u8]) {
        println!("        array![");
        for chunk in bytes.chunks(12) {
            let items: Vec<String> = chunk.iter().map(|b| format!("0x{b:02x}")).collect();
            println!("            {},", items.join(", "));
        }
        println!("        ]");
    }

    fn print_cairo_felt_array(words: &[[u8; 32]]) {
        println!("        array![");
        for w in words {
            println!("            0x{},", hex::encode(w));
        }
        println!("        ]");
    }
}

// ============================================================
// Plan D P2 测试：reconstruct 折叠 + BG 线性方程组 + /tmp/bgvectors
// ============================================================
#[cfg(test)]
mod bg_fold_tests {
    use super::*;
    use poker_protocol_core::{CryptoTranscript, PoseidonFeltTranscript};
    use poker_protocol::zk_shuffle::bayer_groth::{
    BayerGrothShuffleProof, MultiExponentiationArgument, ProductArgument,
};
    use rand_core::{CryptoRng, RngCore};

    type Ct = poker_protocol_core::StarkElGamalCiphertext;

    fn random_scalar() -> Sc {
        <Sc as CurveScalar>::random(&mut rand::rngs::OsRng)
    }

    fn test_binding() -> [u8; 32] {
        let mut b = [0x5Bu8; 32];
        b[0] = 0x02; // felt 合法域
        b
    }

    // ---- reconstruct (CP-DLEQ) ----

    /// 诚实 CP-DLEQ reconstruct：P1 = s·G1、P2 = s·G2，
    /// resp = w + c·s（c = handbatch_reconstruct_challenge）。
    fn mint_reconstruct() -> HandBatchEquation {
        let s = random_scalar();
        let g1 = StarkCurve::base_g();
        let g2 = <StarkCurve as Curve>::base_h();
        let p1 = g1 * s;
        let p2 = g2 * s;
        let w = random_scalar();
        let a = g1 * w;
        let b = g2 * w;
        let c = poker_protocol_core::stark_curve::handbatch_reconstruct_challenge(
            &test_binding(), &g1, &g2, &p1, &p2, &a, &b,
        );
        let resp = w + c * s;
        HandBatchEquation::Reconstruct { s: resp, g1, g2, p1, p2, a, b }
    }

    #[test]
    fn honest_reconstruct_folds() {
        let hb = test_binding();
        let eqs = [mint_reconstruct()];
        assert!(host_fold_check(&hb, &eqs), "honest CP-DLEQ must fold to identity");
    }

    #[test]
    fn tampered_reconstruct_fails() {
        let hb = test_binding();
        let eq = mint_reconstruct();
        let tampered = match eq {
            HandBatchEquation::Reconstruct { s, g1, g2, p1, p2, a, b } => {
                HandBatchEquation::Reconstruct { s: s + <Sc as CurveScalar>::one(), g1, g2, p1, p2, a, b }
            }
            _ => unreachable!(),
        };
        assert!(
            !host_fold_check(&hb, &[tampered]),
            "bumped response scalar must break the fold"
        );
    }

    // ---- BG shuffle over PoseidonFeltTranscript ----

    fn shuffle_instance(n: usize) -> (Vec<Ct>, Vec<Ct>, Pt, Vec<usize>, Vec<Sc>) {
        let sk = random_scalar();
        let pk = StarkCurve::base_g() * sk;
        let input: Vec<Ct> = (0..n)
            .map(|_| {
                let msg = <Pt as CurvePoint>::random(&mut rand::rngs::OsRng);
                Ct::encrypt(&msg, &pk, &random_scalar())
            })
            .collect();
        // 确定性双射（step 与 n 互素）
        let step = 7;
        let permutation: Vec<usize> = (0..n).map(|i| (i * step + 3) % n).collect();
        let rerandomizers: Vec<Sc> = (0..n).map(|_| random_scalar()).collect();
        let output: Vec<Ct> = (0..n)
            .map(|i| input[permutation[i]].re_encrypt(&pk, &rerandomizers[i]))
            .collect();
        (input, output, pk, permutation, rerandomizers)
    }

    #[test]
    fn honest_bg_shuffle_folds() {
        let n = 52;
        let (input, output, pk, permutation, rerandomizers) = shuffle_instance(n);
        let mut tr = PoseidonFeltTranscript::new_bg_fold();
        let proof = BayerGrothShuffleProof::<StarkCurve>::prove(
            &input, &output, &permutation, &rerandomizers, &pk, &mut rand::rngs::OsRng, &mut tr,
        )
        .expect("honest BG prove");

        // 参照系：BG verify() 在同一 transcript 类型上通过
        proof
            .verify(&input, &output, &pk, &mut PoseidonFeltTranscript::new_bg_fold())
            .expect("BG verify over PoseidonFeltTranscript");

        let eqs = bg_shuffle_fold_equations(&input, &output, &pk, &proof);
        assert_eq!(eqs.equations.len(), 8, "E1x2 + E2 + E3 + E4x2 + E5 + E6");
        assert!(eqs.scalar_check_1, "b[0] == a[0]");
        assert!(eqs.scalar_check_2, "b[n-1] == q * prod");
        for (i, eq) in eqs.equations.iter().enumerate() {
            assert!(linear_residual(eq).is_identity(), "equation {i} residual");
        }
        assert!(
            host_fold_check_linear(&test_binding(), &eqs.equations),
            "BG equation set must fold to identity"
        );
    }

    #[test]
    fn tampered_bg_shuffle_fails() {
        let n = 16;
        let (input, output, pk, permutation, rerandomizers) = shuffle_instance(n);
        let mut tr = PoseidonFeltTranscript::new_bg_fold();
        let proof = BayerGrothShuffleProof::<StarkCurve>::prove(
            &input, &output, &permutation, &rerandomizers, &pk, &mut rand::rngs::OsRng, &mut tr,
        )
        .expect("honest BG prove");

        // 篡改 1：证明词（beta += 1）→ E3/E4c2 破
        let mut bad = proof.clone();
        bad.multi_exponentiation.beta = bad.multi_exponentiation.beta + <Sc as CurveScalar>::one();
        let eqs = bg_shuffle_fold_equations(&input, &output, &pk, &bad);
        let any_bad = eqs.equations.iter().any(|e| !linear_residual(e).is_identity())
            || !eqs.scalar_check_1
            || !eqs.scalar_check_2;
        assert!(any_bad, "tampered beta must break the equation set");

        // 篡改 2：交换两条输出密文 → E4 破
        let mut swapped = output.clone();
        swapped.swap(0, 1);
        let eqs = bg_shuffle_fold_equations(&input, &swapped, &pk, &proof);
        assert!(
            eqs.equations.iter().any(|e| !linear_residual(e).is_identity()),
            "swapped outputs must break the equation set"
        );
    }

    // ---- /tmp/bgvectors 机器可读向量 ----

    /// /tmp/bgvectors/bg_shuffle.txt 重放一致性：x y z e q 与向量尾部
    /// 逐词一致。
    /// 向量文件缺失时跳过（仅本地/生成环境存在）。
    #[test]
    fn bgvectors_transcript_replay_matches_file() {
        let Ok(text) = std::fs::read_to_string("/tmp/bgvectors/bg_shuffle.txt") else {
            return;
        };
        let mut words: Vec<[u8; 32]> = Vec::new();
        for line in text.lines() {
            let l = line.trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            let mut b = [0u8; 32];
            b.copy_from_slice(&hex::decode(l).expect("hex word"));
            words.push(b);
        }
        let n = word_low_u64(&words[1]).expect("n") as usize;
        assert_eq!(n, 52);
        let b = &words[2..]; // after hand_binding + n: input 4n, output 4n, pk 2, comm 22, resp 3n+6, chal 6
        let mut o = 0usize;
        let mut ct_n = |o: &mut usize| -> Ct {
            let c1 = point_from_words(&b[*o], &b[*o + 1]).expect("c1");
            let c2 = point_from_words(&b[*o + 2], &b[*o + 3]).expect("c2");
            *o += 4;
            Ct { c1, c2 }
        };
        let input: Vec<Ct> = (0..n).map(|_| ct_n(&mut o)).collect();
        let output: Vec<Ct> = (0..n).map(|_| ct_n(&mut o)).collect();
        let pk = point_from_words(&b[o], &b[o + 1]).expect("pk");
        o += 2;
        let pt_n = |o: &mut usize| -> Pt {
            let p = point_from_words(&b[*o], &b[*o + 1]).expect("point");
            *o += 2;
            p
        };
        let sc_n = |o: &mut usize| -> Sc {
            let s = scalar_from_word(&b[*o]).expect("scalar");
            *o += 1;
            s
        };
        let c_permutation = pt_n(&mut o);
        let c_permuted_powers = pt_n(&mut o);
        let c_alpha = pt_n(&mut o);
        let c_beta = pt_n(&mut o);
        let ciphertext_0 = ct_n(&mut o);
        let ciphertext_1 = ct_n(&mut o);
        let c_d = pt_n(&mut o);
        let c_delta = pt_n(&mut o);
        let c_capital_delta = pt_n(&mut o);
        let alpha_response: Vec<Sc> = (0..n).map(|_| sc_n(&mut o)).collect();
        let commitment_response = sc_n(&mut o);
        let beta = sc_n(&mut o);
        let beta_blinding_response = sc_n(&mut o);
        let rerandomization_response = sc_n(&mut o);
        let a_response: Vec<Sc> = (0..n).map(|_| sc_n(&mut o)).collect();
        let b_response: Vec<Sc> = (0..n).map(|_| sc_n(&mut o)).collect();
        let r_response = sc_n(&mut o);
        let s_response = sc_n(&mut o);
        let proof = BayerGrothShuffleProof::<StarkCurve> {
            c_permutation,
            c_permuted_powers,
            multi_exponentiation: MultiExponentiationArgument {
                c_alpha,
                c_beta,
                ciphertext_0,
                ciphertext_1,
                alpha_response,
                commitment_response,
                beta,
                beta_blinding_response,
                rerandomization_response,
            },
            product: ProductArgument {
                c_d,
                c_delta,
                c_capital_delta,
                a_response,
                b_response,
                r_response,
                s_response,
            },
        };
        let eqs = bg_shuffle_fold_equations(&input, &output, &pk, &proof);
        let derived = [
            eqs.powers_challenge,
            eqs.product_y,
            eqs.product_z,
            eqs.mexp_challenge,
            eqs.product_challenge,
        ];
        // 末尾 5 词 = x y z e q（历史 λ 向量多 1 词时忽略尾部）
        let tail = &b[o..];
        let cmp_n = tail.len().min(derived.len());
        for i in 0..cmp_n {
            let mut w = [0u8; 32];
            w.copy_from_slice(&derived[i].as_bytes());
            assert_eq!(w, tail[i], "challenge word {i} mismatch");
        }
        // 分解后的方程组在该向量上仍须全零
        assert!(eqs.scalar_check_1 && eqs.scalar_check_2);
        assert!(
            eqs.equations.iter().all(|e| linear_residual(e).is_identity()),
            "pinned vector residuals"
        );
    }

    fn hex_line(w: &[u8; 32]) -> String {
        hex::encode(w)
    }

    fn point_words(p: &Pt) -> [[u8; 32]; 2] {
        let (x, y) = point_xy(p);
        [x, y]
    }

    fn scalar_word(s: &Sc) -> [u8; 32] {
        let mut b = [0u8; 32];
        b.copy_from_slice(&s.as_bytes());
        b
    }

    /// 生成 Cairo 端复刻所需的全部向量（运行：
    /// cargo +nightly test -p texas bg_vectors -- --nocapture）。
    #[test]
    fn bg_vectors() {
        let dir = std::path::Path::new("/tmp/bgvectors");
        std::fs::create_dir_all(dir).expect("mkdir /tmp/bgvectors");
        let hb = test_binding();

        // ---- 1. CK n=52（h + 52 generators，Cairo 常量钉死）----
        let ck = BgCommitmentKey::derive(52);
        let mut out = String::from(
            "# BG commitment key, n=52, STARK curve affine (x, y) hex words\n\
             # line order: h_x, h_y, G0_x, G0_y, ..., G51_x, G51_y (53 points)\n\
             # derivation: h = hash_to_curve(\"poker/bg12/v2/H\"), Gi = hash_to_curve(\"poker/bg12/v2/G/52/i\")\n",
        );
        for p in std::iter::once(&ck.h).chain(ck.generators.iter()) {
            for w in point_words(p) {
                out.push_str(&hex_line(&w));
                out.push('\n');
            }
        }
        std::fs::write(dir.join("ck_n52.txt"), out).expect("write ck_n52.txt");

        // ---- 2. CP-DLEQ reconstruct 向量 ----
        // wire 格式（recon 桶，每条 13 词，顺序）：
        //   [g1_x g1_y g2_x g2_y p1_x p1_y p2_x p2_y A_x A_y B_x B_y s]
        // 挑战 c = handbatch_reconstruct_challenge(hand_binding, ...) 链上重算；
        // 方程：s·g1 − A − c·p1 = O；s·g2 − B − c·p2 = O。
        let recon = mint_reconstruct();
        let (r_s, r_g1, r_g2, r_p1, r_p2, r_a, r_b) = match recon {
            HandBatchEquation::Reconstruct { s, g1, g2, p1, p2, a, b } => (s, g1, g2, p1, p2, a, b),
            _ => unreachable!(),
        };
        assert!(host_fold_check(&hb, &[HandBatchEquation::Reconstruct {
            s: r_s, g1: r_g1, g2: r_g2, p1: r_p1, p2: r_p2, a: r_a, b: r_b,
        }]));
        let mut out = String::from(
            "# CP-DLEQ reconstruct vector (foldable epoch, kind=4)\n\
             # word 0: hand_binding (32B BE)\n\
             # words 1..=13 (hex, one per line): g1_x g1_y g2_x g2_y p1_x p1_y p2_x p2_y A_x A_y B_x B_y s\n\
             # equations: s*g1 - A - c*p1 = O ; s*g2 - B - c*p2 = O\n\
             # c = poseidon([\"poker/reconstruct-fold/v1\", hand_binding, g1,g2,p1,p2,A,B]) mod n\n",
        );
        out.push_str(&hex_line(&hb));
        out.push('\n');
        for p in [&r_g1, &r_g2, &r_p1, &r_p2, &r_a, &r_b] {
            for w in point_words(p) {
                out.push_str(&hex_line(&w));
                out.push('\n');
            }
        }
        out.push_str(&hex_line(&scalar_word(&r_s)));
        out.push('\n');
        std::fs::write(dir.join("cp_recon.txt"), out).expect("write cp_recon.txt");

        // ---- 3. BG shuffle 向量（n=52）----
        // wire 格式（BG 桶，hex felt252 词每行一词，段序）：
        //   hand_binding (1)
        //   n (1)
        //   input  n*4: (c1_x c1_y c2_x c2_y)*n
        //   output n*4: (c1_x c1_y c2_x c2_y)*n
        //   pk (2)
        //   proof commitments (22): c_permutation(2) c_permuted_powers(2)
        //     c_alpha(2) c_beta(2) ct0(4) ct1(4) c_d(2) c_delta(2) c_capital_delta(2)
        //   proof responses (3n+6): alpha_response(n) commitment_response beta
        //     beta_blinding_response rerandomization_response a_response(n)
        //     b_response(n) r_response s_response
        //   derived challenges (5): x y z e q（Cairo 由 transcript 重放重算比对）
        let n = 52;
        let (input, output, pk, permutation, rerandomizers) = shuffle_instance(n);
        let mut tr = PoseidonFeltTranscript::new_bg_fold();
        let proof = BayerGrothShuffleProof::<StarkCurve>::prove(
            &input, &output, &permutation, &rerandomizers, &pk, &mut rand::rngs::OsRng, &mut tr,
        )
        .expect("honest BG prove");
        proof
            .verify(&input, &output, &pk, &mut PoseidonFeltTranscript::new_bg_fold())
            .expect("BG verify");
        let eqs = bg_shuffle_fold_equations(&input, &output, &pk, &proof);
        assert!(eqs.scalar_check_1 && eqs.scalar_check_2);
        assert!(host_fold_check_linear(&hb, &eqs.equations));

        let mut out = String::from(
            "# BG shuffle vector (foldable epoch), n=52, STARK curve\n\
             # hex felt252 words, one per line; section markers below\n\
             # Cairo recomputes x,y,z,e,q by replaying PoseidonFeltTranscript over:\n\
             #   protocol, deck_size, pk, input cts, output cts, c_permutation,\n\
             #   ->x, c_permuted_powers, ->y, ->z, c_alpha, c_beta, ct0, ct1,\n\
             #   ->e, c_d, c_delta, c_capital_delta, ->q\n",
        );
        out.push_str("# hand_binding\n");
        out.push_str(&hex_line(&hb));
        out.push('\n');
        out.push_str("# n\n");
        out.push_str(&hex_line(&u256_word(n as u64)));
        out.push('\n');
        out.push_str("# input ciphertexts (n*4)\n");
        for ct in &input {
            for p in [&ct.c1, &ct.c2] {
                for w in point_words(p) {
                    out.push_str(&hex_line(&w));
                    out.push('\n');
                }
            }
        }
        out.push_str("# output ciphertexts (n*4)\n");
        for ct in &output {
            for p in [&ct.c1, &ct.c2] {
                for w in point_words(p) {
                    out.push_str(&hex_line(&w));
                    out.push('\n');
                }
            }
        }
        out.push_str("# pk (2)\n");
        for w in point_words(&pk) {
            out.push_str(&hex_line(&w));
            out.push('\n');
        }
        out.push_str("# proof commitments (22)\n");
        let mexp = &proof.multi_exponentiation;
        let product = &proof.product;
        for p in [
            &proof.c_permutation,
            &proof.c_permuted_powers,
            &mexp.c_alpha,
            &mexp.c_beta,
            &mexp.ciphertext_0.c1,
            &mexp.ciphertext_0.c2,
            &mexp.ciphertext_1.c1,
            &mexp.ciphertext_1.c2,
            &product.c_d,
            &product.c_delta,
            &product.c_capital_delta,
        ] {
            for w in point_words(p) {
                out.push_str(&hex_line(&w));
                out.push('\n');
            }
        }
        out.push_str("# proof responses (3n+6)\n");
        for s in mexp.alpha_response.iter()
            .chain(std::iter::once(&mexp.commitment_response))
            .chain(std::iter::once(&mexp.beta))
            .chain(std::iter::once(&mexp.beta_blinding_response))
            .chain(std::iter::once(&mexp.rerandomization_response))
            .chain(product.a_response.iter())
            .chain(product.b_response.iter())
            .chain(std::iter::once(&product.r_response))
            .chain(std::iter::once(&product.s_response))
        {
            out.push_str(&hex_line(&scalar_word(s)));
            out.push('\n');
        }
        out.push_str("# derived challenges x y z e q (transcript replay)\n");
        for s in [
            &eqs.powers_challenge,
            &eqs.product_y,
            &eqs.product_z,
            &eqs.mexp_challenge,
            &eqs.product_challenge,
        ] {
            out.push_str(&hex_line(&scalar_word(s)));
            out.push('\n');
        }
        std::fs::write(dir.join("bg_shuffle.txt"), out).expect("write bg_shuffle.txt");

        // ---- 4. 全桶载荷（own+reveal+leave+recon host 可折叠；shuffle 桶
        //         词序同 bg_shuffle.txt 去掉 hand_binding 行——当前
        //         parse_batch_terms 仍拒 n_shuffle>0，词序为 part-2 目标）----
        let mut words: Vec<[u8; 32]> = vec![
            u256_word(1), // n_own
            u256_word(1), // n_shuffle
            u256_word(1), // n_reveal
            u256_word(1), // n_leave
            u256_word(1), // n_recon
        ];
        // own 桶
        let sk = random_scalar();
        let pk_own = StarkCurve::base_g() * sk;
        let e = mint_endorsement(&sk, &pk_own, &hb);
        for w in point_words(&e.pk).into_iter().chain(point_words(&e.r)) {
            words.push(w);
        }
        words.push(scalar_be(&e.s));
        // shuffle 桶（n + input + output + pk + 22 + 3n+6）
        words.push(u256_word(n as u64));
        for ct in input.iter().chain(output.iter()) {
            for p in [&ct.c1, &ct.c2] {
                for w in point_words(p) {
                    words.push(w);
                }
            }
        }
        for w in point_words(&pk) {
            words.push(w);
        }
        for p in [
            &proof.c_permutation,
            &proof.c_permuted_powers,
            &mexp.c_alpha,
            &mexp.c_beta,
            &mexp.ciphertext_0.c1,
            &mexp.ciphertext_0.c2,
            &mexp.ciphertext_1.c1,
            &mexp.ciphertext_1.c2,
            &product.c_d,
            &product.c_delta,
            &product.c_capital_delta,
        ] {
            for w in point_words(p) {
                words.push(w);
            }
        }
        for s in mexp.alpha_response.iter()
            .chain(std::iter::once(&mexp.commitment_response))
            .chain(std::iter::once(&mexp.beta))
            .chain(std::iter::once(&mexp.beta_blinding_response))
            .chain(std::iter::once(&mexp.rerandomization_response))
            .chain(product.a_response.iter())
            .chain(product.b_response.iter())
            .chain(std::iter::once(&product.r_response))
            .chain(std::iter::once(&product.s_response))
        {
            words.push(scalar_word(s));
        }
        // reveal 桶（14 词）
        let r_sk = random_scalar();
        let r_pk = StarkCurve::base_g() * r_sk;
        let msg = <StarkCurve as Curve>::hash_to_curve(b"bgvectors/reveal/card-0");
        let r_r = random_scalar();
        let ct = Ct::encrypt(&msg, &r_pk, &r_r);
        let token = ct.c1 * r_sk;
        let w_nonce = random_scalar();
        let (t1, t2) = (StarkCurve::base_g() * w_nonce, ct.c1 * w_nonce);
        let c_reveal = poker_protocol_core::stark_curve::handbatch_reveal_challenge(
            &hb, &r_pk, &ct.c1, &ct.c2, &token, &t1, &t2, &w_nonce,
        );
        let s_reveal = w_nonce + c_reveal * r_sk;
        for p in [&r_pk, &ct.c1, &ct.c2, &token, &t1, &t2] {
            for w in point_words(p) {
                words.push(w);
            }
        }
        words.push(scalar_word(&w_nonce));
        words.push(scalar_word(&s_reveal));
        // leave 桶（1 卡）
        let l_sk = random_scalar();
        let l_pk = StarkCurve::base_g() * l_sk;
        let omega = random_scalar();
        let l_cpk = StarkCurve::base_g() * omega;
        let l_nonce = random_scalar();
        let l_msg = <StarkCurve as Curve>::hash_to_curve(b"bgvectors/leave/card-0");
        let l_r = random_scalar();
        let l_ct = Ct::encrypt(&l_msg, &l_pk, &l_r);
        let l_out = Ct { c1: l_ct.c1, c2: l_ct.c2 - l_ct.c1 * l_sk };
        let l_a = l_ct.c1 * omega;
        let card_words = vec![poker_protocol_core::stark_curve::HandLeaveCardWords {
            in_c1: l_ct.c1, in_c2: l_ct.c2, out_c1: l_out.c1, out_c2: l_out.c2, a: l_a,
        }];
        let c_leave = poker_protocol_core::stark_curve::handbatch_leave_challenge(
            &hb, &l_pk, &l_cpk, &l_nonce, &card_words,
        );
        let s_leave = omega + c_leave * l_sk;
        words.push(u256_word(1));
        for w in point_words(&l_pk).into_iter().chain(point_words(&l_cpk)) {
            words.push(w);
        }
        words.push(scalar_word(&l_nonce));
        words.push(scalar_word(&s_leave));
        for p in [&l_ct.c1, &l_ct.c2, &l_out.c1, &l_out.c2, &l_a] {
            for w in point_words(p) {
                words.push(w);
            }
        }
        // recon 桶（13 词）
        for p in [&r_g1, &r_g2, &r_p1, &r_p2, &r_a, &r_b] {
            for w in point_words(p) {
                words.push(w);
            }
        }
        words.push(scalar_word(&r_s));

        // host parity：完整 5 桶载荷（含 shuffle）必须解析并折叠——
        // 与 Cairo 端 verify_hand_batch_stark 双跑一致。
        let equations = parse_batch_terms(&hb, &words).expect("5-bucket payload parses");
        assert_eq!(equations.len(), 5);
        assert!(host_fold_check(&hb, &equations), "5-bucket payload folds");

        // 篡改：shuffle 桶里的 beta 词 +1 → 折叠/标量校验必须破。
        // beta 位于 shuffle 桶响应段：1 + 8n + 2 + 22 + n(alpha) + 1。
        let beta_idx = 10 + 1 + 8 * n + 2 + 22 + n + 1;
        let mut bad = words.clone();
        let mut beta_b = bad[beta_idx];
        beta_b[31] = beta_b[31].wrapping_add(1);
        bad[beta_idx] = beta_b;
        let bad_eqs = match parse_batch_terms(&hb, &bad) {
            Some(e) => e,
            None => return, // 解析即拒（beta 非规范）也算正确拒绝
        };
        assert!(
            !host_fold_check(&hb, &bad_eqs),
            "tampered shuffle beta must break the fold"
        );

        let mut out = String::from(
            "# full hand-batch payload, all 5 buckets non-zero (n=52 shuffle)\n\
             # header (5 words): n_own n_shuffle n_reveal n_leave n_recon\n\
             # bucket order: own(5*no) shuffle(n+8n+2+22+3n+6) reveal(14*nr)\n\
             #   leave(7+10n_cards each) recon(13*nrc)\n\
             # shuffle bucket layout: [n, input 4n, output 4n, pk 2,\n\
             #   commitments 22, responses 3n+6]; challenges recomputed by\n\
             #   PoseidonFeltTranscript replay (same order as bg_shuffle.txt\n\
             #   minus hand_binding).\n",
        );
        out.push_str(&hex_line(&hb));
        out.push('\n');
        for w in &words {
            out.push_str(&hex_line(w));
            out.push('\n');
        }
        std::fs::write(dir.join("payload_full.txt"), out).expect("write payload_full.txt");
    }
}

// ============================================================
// Settle-mode（linear 默认 / proved 建而未启）测试
// ============================================================
#[cfg(test)]
mod settle_mode_tests {
    use super::*;
    use poker_l1::vm::contracts::texas_poker::settlement::{
        SettlementPlan, SettlementRunoutSchedule, SETTLEMENT_SEATS,
    };
    use rand_core::CryptoRng;

    fn random_scalar() -> Sc {
        <Sc as CurveScalar>::random(&mut rand::rngs::OsRng)
    }

    // ---- 1. 模式解析默认 ----

    #[test]
    fn settle_mode_parsing_defaults_to_linear() {
        assert_eq!(SettleMode::default(), SettleMode::Linear);
        for raw in ["", "linear", "Linear", "LINEAR", "auto", "garbage", "0"] {
            assert_eq!(SettleMode::parse(raw), SettleMode::Linear, "raw={raw:?}");
        }
        for raw in ["proved", "Proved", "PROVED", " proved "] {
            assert_eq!(SettleMode::parse(raw), SettleMode::Proved, "raw={raw:?}");
        }
    }

    // ---- 2. p_batch 承诺 ----

    fn words_fixture() -> Vec<[u8; 32]> {
        // 规范头 + 10 个合成词（无需是曲线点——承诺只是 Poseidon；首字节
        // 压到 0x02 保证 < 域模，其余字节承载差异）。
        let mut w = vec![u256_word(2), u256_word(0), u256_word(0), u256_word(0), u256_word(0)];
        for i in 0u8..10 {
            let mut word = [0u8; 32];
            word[0] = 0x02;
            word[1] = i;
            word[31] = i.wrapping_add(1);
            w.push(word);
        }
        w
    }

    #[test]
    fn p_batch_commitment_is_deterministic_and_binding() {
        let hb = Ff::from(0x5Bu64);
        let words = words_fixture();
        let c1 = compute_p_batch_commitment(hb, &words).expect("commitment");
        let c2 = compute_p_batch_commitment(hb, &words).expect("commitment");
        assert_eq!(c1, c2, "deterministic");
        assert_ne!(c1, Ff::ZERO, "non-trivial");
        // 绑定 hand_binding
        let other_hb = compute_p_batch_commitment(hb + Ff::ONE, &words).expect("commitment");
        assert_ne!(c1, other_hb, "binding must change with hand_binding");
        // 绑定 batch 词
        let mut tampered = words.clone();
        tampered[6][31] ^= 1;
        let c3 = compute_p_batch_commitment(hb, &tampered).expect("commitment");
        assert_ne!(c1, c3, "commitment must change with batch words");
        // 超域词（≥ 域模）必须报错，而不是截断
        let mut bad = vec![u256_word(0); 2];
        bad[1][0] = 0xFF; // 远超 felt 域
        assert!(
            compute_p_batch_commitment(hb, &bad).is_err(),
            "out-of-range word must error"
        );
    }

    // ---- 3. calldata 形态：linear 黄金布局 + proved 无 p_batch ----

    fn synthetic_settlement() -> HandSettlement {
        let mut awards = [0u64; SETTLEMENT_SEATS];
        awards[0] = 200;
        HandSettlement {
            hand_id: 3,
            plan: SettlementPlan {
                version: 2,
                schedule: SettlementRunoutSchedule::Single,
                gross_pot: 200,
                rake: 0,
                total_awards: 200,
                winner_mask: 0b0001,
                awards,
                pots: vec![],
            },
            register_calldata: vec![],
            settle_calldata: vec![],
            aggregate_digest: [7u8; 32],
            players_remapped: vec![Ff::from(0x1111u64), Ff::from(0x2222u64)],
            deltas: vec![100, -100],
            settlement_digest: Ff::from(123456789u64),
            pre_state_root: [1u8; 32],
            post_state_root: [2u8; 32],
        }
    }

    fn build_test_dual() -> DualSettlement {
        let mirror = TableMirror::new(7, "test", [0xAA; 20], 9, 10, 20, [0xAA; 20]);
        let settlement = synthetic_settlement();
        let binding = prepare_handbatch_binding(&mirror, &settlement).expect("binding");
        let endorsements: Vec<ClientEndorsement> = (0..2)
            .map(|_| {
                let sk = random_scalar();
                let pk = StarkCurve::base_g() * sk;
                let e = mint_endorsement(&sk, &pk, &binding.hand_id_bytes);
                ClientEndorsement { pk: e.pk, r: e.r, s: e.s }
            })
            .collect();
        build_dual_settlement_from_client(&mirror, &settlement, &endorsements).expect("dual build")
    }

    #[test]
    fn linear_calldata_matches_golden_layout() {
        let dual = build_test_dual();
        let settlement = synthetic_settlement();
        let hb_felt = ff_to_felt(dual.hand_binding);

        // register：[binding, digest, g_attestation, 0, 0, 0]（兼容新字段）。
        assert_eq!(dual.register_calldata.len(), 6);
        assert_eq!(dual.register_calldata[0], hb_felt);
        assert_eq!(dual.register_calldata[1], ff_to_felt(settlement.settlement_digest));
        assert_eq!(dual.register_calldata[2], ff_to_felt(dual.g_attestation));
        for tail in &dual.register_calldata[3..6] {
            assert_eq!(*tail, Felt::ZERO, "expected-count tail must default to zero");
        }

        // settle：binding + [32, bytes…] + hand_id + [n, players…] +
        // [n, deltas…] + [m, felt×m]（_stark 入口的 Span<felt252> 单
        // felt 打包；曾为 secp 入口的 (low, high) 双 felt，已修正）。
        let expect_len = 1 + 1 + 32 + 1
            + 1 + settlement.players_remapped.len()
            + 1 + settlement.deltas.len()
            + 1 + dual.batch_words.len();
        assert_eq!(dual.settle_calldata.len(), expect_len);
        assert_eq!(dual.settle_calldata[0], hb_felt);
        assert_eq!(dual.settle_calldata[1], Felt::from(32u64));
        assert_eq!(dual.settle_calldata[34], Felt::from(u64::from(settlement.hand_id)));
        assert_eq!(
            dual.settle_calldata[35],
            Felt::from(settlement.players_remapped.len() as u64)
        );
        assert_eq!(
            dual.settle_calldata[35 + 1 + settlement.players_remapped.len()],
            Felt::from(settlement.deltas.len() as u64)
        );
        let words_len_at = 35 + 1 + settlement.players_remapped.len() + 1 + settlement.deltas.len();
        assert_eq!(
            dual.settle_calldata[words_len_at],
            Felt::from(dual.batch_words.len() as u64)
        );
        // 首个 u256 词的 (low, high) 双 felt 形态保持。
        let w0 = dual.batch_words[0];
        assert_eq!(
            dual.settle_calldata[words_len_at + 1],
            Felt::from(u128::from_be_bytes(w0[16..32].try_into().unwrap()))
        );
        assert_eq!(
            dual.settle_calldata[words_len_at + 2],
            Felt::from(u128::from_be_bytes(w0[..16].try_into().unwrap()))
        );
    }

    #[test]
    fn proved_calldata_carries_commitment_and_no_batch() {
        let dual = build_test_dual();
        let settlement = synthetic_settlement();
        let hb_felt = ff_to_felt(dual.hand_binding);
        let commitment =
            compute_p_batch_commitment(dual.hand_binding, &dual.batch_words).expect("commitment");

        // register_hand_proved：[binding, digest, g_att, commitment, len, 0,0,0]。
        let pr = &dual.proved.register_calldata;
        assert_eq!(pr.len(), 8);
        assert_eq!(pr[0], hb_felt);
        assert_eq!(pr[1], ff_to_felt(settlement.settlement_digest));
        assert_eq!(pr[2], ff_to_felt(dual.g_attestation));
        assert_eq!(pr[3], ff_to_felt(commitment), "registered commitment");
        assert_eq!(pr[4], Felt::from(dual.batch_words.len() as u64));
        assert_eq!(pr[5], Felt::ZERO);
        assert_eq!(pr[6], Felt::ZERO);
        assert_eq!(pr[7], Felt::ZERO);

        // verify_and_settle_dapv_proved：与 linear 同前缀（binding、bytes、
        // hand_id、players、deltas），尾部是 [commitment, len]——**无 p_batch**。
        let ps = &dual.proved.settle_calldata;
        let prefix_len = 1 + 1 + 32 + 1
            + 1 + settlement.players_remapped.len()
            + 1 + settlement.deltas.len();
        assert_eq!(ps.len(), prefix_len + 2, "proved settle = prefix + commitment + len");
        assert_eq!(ps[..prefix_len], dual.settle_calldata[..prefix_len], "shared prefix");
        assert_eq!(ps[prefix_len], ff_to_felt(commitment));
        assert_eq!(ps[prefix_len + 1], Felt::from(dual.batch_words.len() as u64));
        // 承诺与结构字段一致
        assert_eq!(dual.proved.p_batch_commitment, commitment);
        assert_eq!(dual.proved.p_batch_len, dual.batch_words.len());
    }

    // ---- 4. prover 存根与回退 ----

    struct OkProver {
        commitment: Ff,
    }
    impl BatchProver for OkProver {
        fn request_attestation<'a>(
            &'a self,
            _workload: &'a ProverWorkload,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<ProverAttestation, String>> + Send + 'a>,
        > {
            let c = self.commitment;
            Box::pin(async move { Ok(ProverAttestation { p_batch_commitment: c }) })
        }
    }

    fn test_workload() -> ProverWorkload {
        ProverWorkload {
            hand_binding: Ff::from(0x5Bu64),
            hand_id: 1,
            batch_words: words_fixture(),
            p_batch_commitment: Ff::from(0xC0FFEEu64),
        }
    }

    #[tokio::test]
    async fn prover_stub_error_falls_back_to_linear() {
        for url in [None, Some("http://127.0.0.1:9/v1/attest".to_string())] {
            let prover = HttpBatchProver::new(url);
            let err = prover.request_attestation(&test_workload()).await.expect_err("stub must error");
            assert!(err.contains("not implemented"), "stub error text: {err}");
            assert_eq!(
                resolve_settle_mode_with_prover(&prover, &test_workload()).await,
                SettleMode::Linear,
                "any stub error must resolve to linear"
            );
        }
    }

    #[tokio::test]
    async fn prover_attestation_decides_mode() {
        let workload = test_workload();
        // 承诺匹配 → proved。
        let ok = OkProver { commitment: workload.p_batch_commitment };
        assert_eq!(
            resolve_settle_mode_with_prover(&ok, &workload).await,
            SettleMode::Proved
        );
        // 承诺不匹配 → linear（prover 故障视同失败）。
        let bad = OkProver { commitment: workload.p_batch_commitment + Ff::ONE };
        assert_eq!(
            resolve_settle_mode_with_prover(&bad, &workload).await,
            SettleMode::Linear
        );
    }

    // ---- 5. workload JSON 导出 ----

    #[test]
    fn prover_workload_export_writes_consumable_json() {
        let dual = build_test_dual();
        let dir = std::env::temp_dir().join(format!("zgame-prover-test-{}", std::process::id()));
        let path = export_prover_workload(&dual, &dir).expect("export succeeds");

        let text = std::fs::read_to_string(&path).expect("read back");
        let doc: serde_json::Value = serde_json::from_str(&text).expect("valid json");
        assert_eq!(doc["hand_binding"], format!("{:#x}", dual.hand_binding).as_str());
        assert_eq!(doc["hand_id"], serde_json::json!(dual.hand_id));
        assert_eq!(doc["p_batch_len"], serde_json::json!(dual.batch_words.len()));
        assert_eq!(
            doc["p_batch_commitment"],
            format!("{:#x}", dual.proved.p_batch_commitment).as_str()
        );
        let words = doc["batch_words"].as_array().expect("words array");
        assert_eq!(words.len(), dual.batch_words.len());
        assert_eq!(words[0], hex::encode(dual.batch_words[0]).as_str());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
