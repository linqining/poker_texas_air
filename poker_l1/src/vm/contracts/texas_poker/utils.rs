//! poker_protocol 适配层 —— 吸收 crypto/ 与 poker_protocol 的 API 差异。
//!
//! 本模块在删除 `crypto/` 目录后，提供以下能力：
//!
//! - **G1/Scalar 自由函数**：`parse_g1`/`serialize_g1`/`g1_add`/`g1_sub`/`g1_mul`/`hash_to_scalar`
//!   等（curve-generic 门面，`DefaultCurve` = StarkCurve——Plan D，blst 已移除）
//! - **ElGamal 操作**：`encrypt`/`decrypt`/`gen_reveal_token`/`remask`/`add_pk_to_c2` 等
//!   包装 `ElGamalCiphertextGeneric<DefaultCurve>` 方法
//! - **Transcript 工厂**：shuffle V2、legacy reconstruction 与 production reconstruction V3
//!   使用各自固定的 Move-compatible SHA3 transcript domain
//! - **ZK skip 回退**：`verify_or_skip` 保留 dev chain 友好的跳过逻辑
//! - **PK 所有权证明**：`create_pk_ownership_proof` / `verify_pk_ownership` 保留 80 字节
//!   Schnorr 自定义格式
//!   （poker_protocol 的 `GeneralizedSchnorrProof` 是不同格式，不替换）
//!
//! # 字节序约定
//!
//! - 曲线点压缩：32 字节（Stark 曲线，`CurvePoint::compress`）
//! - Scalar：32 字节大端序（`CurveScalar::as_bytes`，仅接受 canonical 值）
//! - `hash_to_scalar`/`hash_to_curve` 委托 core Stark 后端（Poseidon 域）

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use poker_protocol::crypto::curve::{Curve, CurvePoint, CurveScalar};

use poker_protocol::crypto::types::{DefaultCurve, ElGamalCiphertext};

// Plan D（2026-09-05）：曲线类型统一收敛到 `DefaultCurve`（= StarkCurve）。
// 保留历史别名 `G1Projective`/`BlsScalar` 以最小化移植面——实际为 Stark 点/标量。
pub type G1Projective = <DefaultCurve as Curve>::Point;
pub type BlsScalar = <DefaultCurve as Curve>::Scalar;
use poker_protocol::zk_shuffle::transcript_ext::{
    CryptoTranscript, FiatShamirTranscript, MerlinTranscript,
};

use crate::error::{PokerL1Error, PokerL1Result};

/// Whether crate-internal unit tests may bypass expensive Mental Poker verification.
///
/// This is deliberately a compile-time property rather than persisted table state. Integration
/// tests and every production build link `poker_l1` without `cfg(test)`, so they always return
/// `false` and execute the real verifier.
#[must_use]
pub const fn test_only_crypto_skip() -> bool {
    cfg!(test)
}

// ========== 常量 ==========

/// 曲线点压缩字节长度（Stark 曲线，32 字节）。
pub const G1_COMPRESSED_SIZE: usize = 32;

/// Scalar bytes 长度（32 字节，大端序）。
pub const SCALAR_SIZE: usize = 32;

/// 扑克牌数量。
pub const N_CARDS: usize = 52;

// ========== Transcript 工厂 ==========

/// 创建洗牌证明的 Transcript。
#[must_use]
pub fn new_shuffle_transcript() -> FiatShamirTranscript {
    FiatShamirTranscript::new(b"zk_shuffle_proof_v2")
}

/// 创建重掩码证明的 Transcript。
#[must_use]
pub fn new_remask_transcript() -> MerlinTranscript {
    MerlinTranscript::new(b"zk_remask_proof_v1")
}

/// 创建离场证明的 Transcript。
#[must_use]
pub fn new_leave_transcript() -> MerlinTranscript {
    MerlinTranscript::new(b"zk_leave_proof_v1")
}

/// Create the legacy reconstruction transcript.
///
/// Production `submit_reconstruct_deck` uses
/// [`new_reconstruct_v3_transcript`]. This constructor remains available for
/// decoding and auditing historical V2 artifacts.
#[must_use]
pub fn new_reconstruct_transcript() -> FiatShamirTranscript {
    FiatShamirTranscript::new(
        poker_protocol::zk_shuffle::reconstruction::RECONSTRUCTION_PROOF_LABEL,
    )
}

/// Create the Fiat--Shamir transcript used by reconstruction V3.
#[must_use]
pub fn new_reconstruct_v3_transcript() -> FiatShamirTranscript {
    FiatShamirTranscript::new(
        poker_protocol::zk_shuffle::reconstruction::RECONSTRUCTION_V3_PROOF_LABEL,
    )
}

/// Return the previous-round owner-readable ciphertexts authenticated by the
/// current table state, preserving canonical hole-slot order (slot 0, then slot 1).
///
/// These records arise only after reveal-token processing of cards drawn from
/// the shuffled `init_deck` lineage. Their deck indices do not reveal the
/// hidden canonical plaintext-card mapping.
#[must_use]
pub fn reconstruction_v3_user_readable_cards(
    table: &super::types::TexasPokerTable,
    seat_index: u8,
) -> Vec<ElGamalCiphertext> {
    table
        .deck_state
        .owner_readable_hole_cards
        .iter_for_seat(seat_index)
        .map(|(_, card)| card.ciphertext)
        .collect()
}

/// Derive the application/domain digest required by reconstruction V3.
///
/// The proof statement separately binds keys and card points; this digest
/// prevents cross-table, cross-hand, or cross-curve replay.
#[must_use]
pub fn reconstruction_v3_context_digest(table: &super::types::TexasPokerTable) -> [u8; 32] {
    let mut material = Vec::with_capacity(96);
    material.extend_from_slice(b"zchain.texas_poker.reconstruction_v3.context.v1");
    material.extend_from_slice(&table.id.to_bytes());
    material.extend_from_slice(&table.hand_id.to_le_bytes());
    material.extend_from_slice(b"stark-curve-v1");
    blake2b_256(&material)
}

/// Digest the authenticated prior owner-readable hand and its init-deck
/// lineage for reconstruction V3.
///
/// This value is recomputed by VM replay and the AIR precompile adapter. It is
/// not accepted from the prover. The full pre-state root in the call context
/// additionally commits to the rest of the table state.
pub fn reconstruction_v3_prior_state_digest(
    table: &super::types::TexasPokerTable,
    seat_index: u8,
) -> PokerL1Result<[u8; 32]> {
    let aggregate_pk = table.derived_aggregated_pk()?.ok_or_else(|| {
        PokerL1Error::Serialization(
            "reconstruction V3 prior state requires aggregate public key".into(),
        )
    })?;
    let mut material = Vec::new();
    material.extend_from_slice(b"zchain.texas_poker.reconstruction_v3.prior_state.v2");
    material.extend_from_slice(&table.id.to_bytes());
    material.extend_from_slice(&table.hand_id.to_le_bytes());
    material.push(seat_index);
    let reconstruct_epoch_ms = table.reconstruct_epoch_ms().ok_or_else(|| {
        PokerL1Error::Serialization(
            "reconstruction V3 prior state requires an active reconstruct epoch".into(),
        )
    })?;
    material.extend_from_slice(&reconstruct_epoch_ms.to_le_bytes());
    material.extend_from_slice(aggregate_pk.0.compress().as_ref());
    let plaintext_cards = generate_plaintext_cards();
    material.extend_from_slice(&(plaintext_cards.len() as u32).to_le_bytes());
    for card in &plaintext_cards {
        material.extend_from_slice(card.compress().as_ref());
    }

    let readable_records = table
        .deck_state
        .owner_readable_hole_cards
        .iter_for_seat(seat_index)
        .collect::<Vec<_>>();
    if readable_records.is_empty() {
        return Err(PokerL1Error::Serialization(
            "reconstruction V3 requires an authenticated previous-round readable hand".into(),
        ));
    }
    material.extend_from_slice(&(readable_records.len() as u32).to_le_bytes());
    for (card_slot, card) in readable_records {
        material.push(card_slot);
        material.push(card.encrypted_card_index);
        let ciphertext = &card.ciphertext;
        material.extend_from_slice(ciphertext.c1.compress().as_ref());
        material.extend_from_slice(ciphertext.c2.compress().as_ref());
    }
    Ok(blake2b_256(&material))
}

fn blake2b_256(payload: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("32 <= 64");
    Update::update(&mut hasher, &(payload.len() as u64).to_le_bytes());
    Update::update(&mut hasher, payload);
    let mut digest = [0u8; 32];
    hasher.finalize_variable(&mut digest).expect("32 <= 64");
    digest
}

// ========== ZK skip 回退 ==========

/// dev chain 友好的 ZK skip 回退。
///
/// 若 `should_skip` 为 true，直接返回 true（跳过 ZK 验证）；
/// 否则调用 `verify_fn` 执行实际验证。
pub fn verify_or_skip<F>(should_skip: bool, verify_fn: F) -> PokerL1Result<bool>
where
    F: FnOnce() -> PokerL1Result<bool>,
{
    if should_skip {
        return Ok(true);
    }
    verify_fn()
}

// ========== G1/Scalar 序列化与反序列化 ==========

/// 反序列化压缩曲线点（32 字节，Stark）。
pub fn parse_g1(bytes: &[u8]) -> PokerL1Result<G1Projective> {
    if bytes.len() != G1_COMPRESSED_SIZE {
        return Err(PokerL1Error::InvalidCurvePoint(format!(
            "compressed point size mismatch: {} != {}",
            bytes.len(),
            G1_COMPRESSED_SIZE
        )));
    }
    CurvePoint::from_compressed(bytes)
        .ok_or(PokerL1Error::InvalidCurvePoint("point not on curve".into()))
}

/// 序列化曲线点为压缩字节（32 字节）。
pub fn serialize_g1(point: &G1Projective) -> [u8; G1_COMPRESSED_SIZE] {
    let mut out = [0u8; G1_COMPRESSED_SIZE];
    out.copy_from_slice(CurvePoint::compress(point).as_ref());
    out
}

/// 反序列化 Scalar（32 字节，大端序）。
pub fn parse_scalar(bytes: &[u8]) -> PokerL1Result<BlsScalar> {
    if bytes.len() != SCALAR_SIZE {
        return Err(PokerL1Error::InvalidCurveScalar(format!(
            "scalar size mismatch: {} != {}",
            bytes.len(),
            SCALAR_SIZE
        )));
    }
    let mut arr = [0u8; SCALAR_SIZE];
    arr.copy_from_slice(bytes);
    <BlsScalar as CurveScalar>::from_canonical_bytes(&arr)
        .ok_or_else(|| PokerL1Error::InvalidCurveScalar("non-canonical scalar".to_string()))
}

/// 序列化 Scalar 为 32 字节大端序。
pub fn serialize_scalar(s: &BlsScalar) -> [u8; SCALAR_SIZE] {
    let mut out = [0u8; SCALAR_SIZE];
    out.copy_from_slice(&CurveScalar::as_bytes(s));
    out
}

// ========== 标量构造与运算 ==========

/// 标量零元。
pub fn scalar_zero() -> BlsScalar {
    <BlsScalar as CurveScalar>::zero()
}

/// 标量单位元。
pub fn scalar_one() -> BlsScalar {
    <BlsScalar as CurveScalar>::one()
}

/// 从 u64 构造标量。
pub fn scalar_from_u64(x: u64) -> BlsScalar {
    <BlsScalar as CurveScalar>::from_u64(x)
}

/// 标量加法。
pub fn scalar_add(a: &BlsScalar, b: &BlsScalar) -> BlsScalar {
    a + b
}

/// 标量减法。
pub fn scalar_sub(a: &BlsScalar, b: &BlsScalar) -> BlsScalar {
    a - b
}

/// 标量乘法。
pub fn scalar_mul(a: &BlsScalar, b: &BlsScalar) -> BlsScalar {
    a * b
}

/// 标量取负。
pub fn scalar_neg(a: &BlsScalar) -> BlsScalar {
    -a
}

/// 标量求逆（若为零返回零）。
pub fn scalar_inv(a: &BlsScalar) -> BlsScalar {
    // core StarkScalar::invert 对零值返回零（非 CtOption）。
    CurveScalar::invert(a)
}

// ========== 哈希到标量 / Hash-to-curve ==========

/// 将任意数据哈希为曲线标量。
///
/// Plan D：委托 `DefaultCurve::hash_to_scalar`（Stark 曲线 = Poseidon 归约，
/// 与 z_poker 客户端同源——挑战派生逐字节一致的前提）。
pub fn hash_to_scalar(data: &[u8]) -> PokerL1Result<BlsScalar> {
    Ok(<DefaultCurve as Curve>::hash_to_scalar(data))
}

/// Hash-to-curve（Stark 曲线 = Poseidon try-and-increment，与 z_poker
/// `new_plain_text` 同一域：`texas_poker/card/{i}` 明文牌派生同源）。
pub fn hash_to_g1(msg: &[u8]) -> G1Projective {
    <DefaultCurve as Curve>::hash_to_curve(msg)
}

/// 生成 52 张确定性明文牌点。
///
/// 对 `i = 0..52`：`hash_to_g1("texas_poker/card/{i}")`
pub fn generate_plaintext_cards() -> Vec<G1Projective> {
    (0..N_CARDS)
        .map(|i| {
            let label = format!("texas_poker/card/{i}");
            hash_to_g1(label.as_bytes())
        })
        .collect()
}

/// 派生独立基点 H：`hash_to_g1("texas_poker_independent_base_H")`。
pub fn base_h() -> G1Projective {
    hash_to_g1(b"texas_poker_independent_base_H")
}

/// 从密文 c1*sk 与 c2*sk 派生标量（m6 长度前缀防歧义编码）。
pub fn derive_scalar_from_card_and_sk(c1_sk: &[u8], c2_sk: &[u8]) -> PokerL1Result<BlsScalar> {
    let mut data = Vec::with_capacity(8 + c1_sk.len() + c2_sk.len());
    data.extend_from_slice(&(c1_sk.len() as u32).to_le_bytes());
    data.extend_from_slice(c1_sk);
    data.extend_from_slice(&(c2_sk.len() as u32).to_le_bytes());
    data.extend_from_slice(c2_sk);
    hash_to_scalar(&data)
}

/// 从密文 (c1, c2) 与公钥 pk 派生标量（m6 长度前缀防歧义编码）。
pub fn derive_scalar_from_card_and_pk(c1: &[u8], c2: &[u8], pk: &[u8]) -> PokerL1Result<BlsScalar> {
    let mut data = Vec::with_capacity(12 + c1.len() + c2.len() + pk.len());
    data.extend_from_slice(&(c1.len() as u32).to_le_bytes());
    data.extend_from_slice(c1);
    data.extend_from_slice(&(c2.len() as u32).to_le_bytes());
    data.extend_from_slice(c2);
    data.extend_from_slice(&(pk.len() as u32).to_le_bytes());
    data.extend_from_slice(pk);
    hash_to_scalar(&data)
}

// ========== G1 辅助 ==========

/// G1 生成元。
pub fn g1_generator() -> G1Projective {
    <DefaultCurve as Curve>::base_g()
}

/// G1 单位元。
pub fn g1_identity() -> G1Projective {
    <G1Projective as CurvePoint>::identity()
}

/// G1 点相等比较。
pub fn g1_equal(a: &G1Projective, b: &G1Projective) -> bool {
    a == b
}

/// 判断 G1 点是否为单位元。
pub fn g1_is_identity(p: &G1Projective) -> bool {
    p.is_identity().into()
}

/// G1 标量乘法。
pub fn g1_mul(s: &BlsScalar, p: &G1Projective) -> G1Projective {
    p * s
}

/// G1 点加法。
pub fn g1_add(a: &G1Projective, b: &G1Projective) -> G1Projective {
    a + b
}

/// G1 点减法。
pub fn g1_sub(a: &G1Projective, b: &G1Projective) -> G1Projective {
    a - b
}

/// 多标量乘法（MSM）：`Σ scalars[i] * points[i]`。
pub fn g1_msm(scalars: &[BlsScalar], points: &[G1Projective]) -> PokerL1Result<G1Projective> {
    if scalars.len() != points.len() {
        return Err(PokerL1Error::Serialization(format!(
            "g1_msm length mismatch: scalars={} points={}",
            scalars.len(),
            points.len()
        )));
    }
    let mut result = G1Projective::identity();
    for (s, p) in scalars.iter().zip(points.iter()) {
        result += p * s;
    }
    Ok(result)
}

/// DLEq 验证：检查 `s * g == commitment + c * pk`。
pub fn verify_dleq(
    g: &G1Projective,
    pk: &G1Projective,
    commitment: &G1Projective,
    s: &BlsScalar,
    c: &BlsScalar,
) -> bool {
    let lhs = g * s;
    let pk_c = pk * c;
    let rhs = commitment + pk_c;
    g1_equal(&lhs, &rhs)
}

// ========== u64 → ASCII ==========

/// u64 转 ASCII 字节表示（十进制字符串的字节序列）。
pub fn u64_to_ascii(n: u64) -> Vec<u8> {
    if n == 0 {
        return vec![b'0'];
    }
    let mut digits = Vec::new();
    let mut val = n;
    while val > 0 {
        let digit = (val % 10) as u8;
        digits.push(digit + b'0');
        val /= 10;
    }
    digits.reverse();
    digits
}

// ========== ElGamal 操作（包装 ElGamalCiphertextGeneric 方法） ==========

/// ElGamal 加密：`c1 = r·G, c2 = M + r·pk`。
pub fn encrypt(plaintext: &G1Projective, pk: &G1Projective, r: &BlsScalar) -> ElGamalCiphertext {
    ElGamalCiphertext::encrypt(plaintext, pk, r)
}

/// 重加密：`c1 += r·G, c2 += r·pk`。
pub fn re_encrypt(ct: &ElGamalCiphertext, pk: &G1Projective, r: &BlsScalar) -> ElGamalCiphertext {
    ct.re_encrypt(pk, r)
}

/// 解密：`M = c2 - sk·c1`。
pub fn decrypt(ct: &ElGamalCiphertext, sk: &BlsScalar) -> G1Projective {
    ct.decrypt(sk)
}

/// 生成揭牌令牌：`token = sk · c1`。
pub fn gen_reveal_token(ct: &ElGamalCiphertext, sk: &BlsScalar) -> G1Projective {
    ct.gen_reveal_token(sk)
}

/// Remask：`c2 += sk · c1`（c1 不变）。c1 必须非 identity。
///
/// # Errors
/// 当 c1 为 identity 点时返回 `Serialization` 错误。
pub fn remask(ct: &ElGamalCiphertext, sk: &BlsScalar) -> PokerL1Result<ElGamalCiphertext> {
    if g1_is_identity(&ct.c1) {
        return Err(PokerL1Error::Serialization(
            "c1 is identity point, cannot remask".to_string(),
        ));
    }
    Ok(ct.remask(sk))
}

/// shuffle_v2 链上注入 player_pk 贡献：`c2 += player_pk`（c1 不变）。
pub fn add_pk_to_c2(ct: &ElGamalCiphertext, player_pk: &G1Projective) -> ElGamalCiphertext {
    ElGamalCiphertext {
        c1: ct.c1,
        c2: g1_add(&ct.c2, player_pk),
    }
}

/// 批量加密：对每张明文用对应的随机数加密。
pub fn encrypt_batch(
    plaintexts: &[G1Projective],
    pk: &G1Projective,
    randoms: &[BlsScalar],
) -> Vec<ElGamalCiphertext> {
    plaintexts
        .iter()
        .zip(randoms.iter())
        .map(|(m, r)| encrypt(m, pk, r))
        .collect()
}

/// 批量 remask：每张密文都用同一个 sk remask。
pub fn remask_batch(
    ciphertexts: &[ElGamalCiphertext],
    sk: &BlsScalar,
) -> PokerL1Result<Vec<ElGamalCiphertext>> {
    ciphertexts.iter().map(|ct| remask(ct, sk)).collect()
}

/// 提取所有 c1 点。
pub fn extract_c1s(ciphertexts: &[ElGamalCiphertext]) -> Vec<G1Projective> {
    ciphertexts.iter().map(|ct| ct.c1).collect()
}

/// 提取所有 c2 点。
pub fn extract_c2s(ciphertexts: &[ElGamalCiphertext]) -> Vec<G1Projective> {
    ciphertexts.iter().map(|ct| ct.c2).collect()
}

// ========== PK 所有权证明（80 字节 Schnorr，自定义格式保留） ==========

/// Create a PK-ownership proof for `pk = G * secret_key` using caller-supplied nonce entropy.
///
/// Production callers must sample a fresh unpredictable non-zero `nonce` for every proof.
/// Accepting the nonce explicitly keeps RNG policy outside consensus code while sharing the exact
/// transcript encoding with [`verify_pk_ownership`].
pub fn create_pk_ownership_proof(
    secret_key: &BlsScalar,
    nonce: &BlsScalar,
) -> PokerL1Result<Vec<u8>> {
    let zero = <BlsScalar as CurveScalar>::zero();
    if *secret_key == zero || *nonce == zero {
        return Err(PokerL1Error::Serialization(
            "PK ownership secret key and nonce must be non-zero".into(),
        ));
    }
    let generator = g1_generator();
    let pk = generator * secret_key;
    let commitment = generator * nonce;
    let generator_bytes = serialize_g1(&generator);
    let pk_bytes = serialize_g1(&pk);
    let commitment_bytes = serialize_g1(&commitment);
    let mut challenge_input = Vec::with_capacity(G1_COMPRESSED_SIZE * 3);
    challenge_input.extend_from_slice(&generator_bytes);
    challenge_input.extend_from_slice(&pk_bytes);
    challenge_input.extend_from_slice(&commitment_bytes);
    let challenge = hash_to_scalar(&challenge_input)?;
    let response = nonce + challenge * secret_key;
    let mut proof = Vec::with_capacity(G1_COMPRESSED_SIZE + SCALAR_SIZE);
    proof.extend_from_slice(&commitment_bytes);
    proof.extend_from_slice(&serialize_scalar(&response));
    Ok(proof)
}

/// 验证 PK 所有权证明（Schnorr proof of knowledge of sk where pk = G · sk）。
///
/// `proof_bytes` 格式：commitment (32 bytes point) + response (32 bytes scalar) = 64 bytes
///
/// 挑战派生：`challenge = hash_to_scalar(G_bytes || pk_bytes || commitment_bytes)`
/// （M-D12 修复：使用 `hash_to_scalar` 替代原始 SHA2-256，清除高位确保 < 曲线阶）
///
/// 验证等式：`G · response == commitment + pk · challenge`
pub fn verify_pk_ownership(pk: &G1Projective, proof_bytes: &[u8]) -> bool {
    // M-D11 修复：拒绝恒等元公钥
    if g1_is_identity(pk) {
        return false;
    }
    // 检查长度: 32 (commitment) + 32 (response) = 64
    if proof_bytes.len() != G1_COMPRESSED_SIZE + SCALAR_SIZE {
        return false;
    }

    let g = g1_generator();
    let pk_bytes = serialize_g1(pk);
    let g_bytes = serialize_g1(&g);

    // 反序列化 commitment 和 response
    let commitment_bytes = &proof_bytes[0..G1_COMPRESSED_SIZE];
    let response_bytes = &proof_bytes[G1_COMPRESSED_SIZE..];

    let commitment = match parse_g1(commitment_bytes) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let response = match parse_scalar(response_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // 拒绝恒等元 commitment
    if g1_is_identity(&commitment) {
        return false;
    }

    // M-D12 修复：使用 hash_to_scalar 派生挑战
    // challenge = hash_to_scalar(G_bytes || pk_bytes || commitment_bytes)
    let mut hash_input =
        Vec::with_capacity(g_bytes.len() + pk_bytes.len() + commitment_bytes.len());
    hash_input.extend_from_slice(&g_bytes);
    hash_input.extend_from_slice(&pk_bytes);
    hash_input.extend_from_slice(commitment_bytes);
    let challenge = match hash_to_scalar(&hash_input) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // 验证: G * response == commitment + pk * challenge
    verify_dleq(&g, pk, &commitment, &response, &challenge)
}

// ========== 单元测试 ==========

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_g1_roundtrip() {
        let p = g1_generator();
        let bytes = serialize_g1(&p);
        let recovered = parse_g1(&bytes).unwrap();
        assert!(g1_equal(&p, &recovered));
    }

    #[test]
    fn test_scalar_roundtrip() {
        let s = scalar_from_u64(123_456_789);
        let bytes = serialize_scalar(&s);
        let recovered = parse_scalar(&bytes).unwrap();
        assert_eq!(s, recovered);
    }

    #[test]
    fn test_hash_to_scalar_deterministic() {
        let s1 = hash_to_scalar(b"hello").unwrap();
        let s2 = hash_to_scalar(b"hello").unwrap();
        assert_eq!(s1, s2);
        let s3 = hash_to_scalar(b"world").unwrap();
        assert_ne!(s1, s3);
    }

    #[test]
    fn test_generate_plaintext_cards_count() {
        let cards = generate_plaintext_cards();
        assert_eq!(cards.len(), N_CARDS);
        for c in &cards {
            assert!(!g1_is_identity(c));
        }
    }

    #[test]
    fn test_generate_plaintext_cards_deterministic() {
        let cards1 = generate_plaintext_cards();
        let cards2 = generate_plaintext_cards();
        for (a, b) in cards1.iter().zip(cards2.iter()) {
            assert!(g1_equal(a, b));
        }
    }

    #[test]
    fn test_g1_msm() {
        let points = vec![g1_generator(), hash_to_g1(b"point2")];
        let scalars = vec![scalar_from_u64(2), scalar_from_u64(3)];
        let msm = g1_msm(&scalars, &points).unwrap();
        let manual = g1_add(
            &g1_mul(&scalars[0], &points[0]),
            &g1_mul(&scalars[1], &points[1]),
        );
        assert!(g1_equal(&msm, &manual));
    }

    #[test]
    fn test_verify_dleq_honest() {
        // 诚实证明：s = r + c * sk, commitment = r * G, pk = sk * G
        let sk = scalar_from_u64(42);
        let r = scalar_from_u64(99);
        let g = g1_generator();
        let pk = g * sk;
        let commitment = g * r;
        let c = scalar_from_u64(7);
        let s = r + c * sk;
        assert!(verify_dleq(&g, &pk, &commitment, &s, &c));
    }

    #[test]
    fn test_verify_dleq_dishonest() {
        let sk = scalar_from_u64(42);
        let g = g1_generator();
        let pk = g * sk;
        let commitment = g * scalar_from_u64(99);
        let c = scalar_from_u64(7);
        let s = scalar_from_u64(0);
        assert!(!verify_dleq(&g, &pk, &commitment, &s, &c));
    }

    #[test]
    fn test_u64_to_ascii() {
        assert_eq!(u64_to_ascii(0), vec![b'0']);
        assert_eq!(u64_to_ascii(9), vec![b'9']);
        assert_eq!(u64_to_ascii(10), vec![b'1', b'0']);
        assert_eq!(u64_to_ascii(123), vec![b'1', b'2', b'3']);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let sk = scalar_from_u64(123_456);
        let pk = g1_generator() * sk;
        let plaintext = hash_to_g1(b"card_0");
        let r = scalar_from_u64(999);
        let ct = encrypt(&plaintext, &pk, &r);
        let recovered = decrypt(&ct, &sk);
        assert!(g1_equal(&plaintext, &recovered));
    }

    #[test]
    fn test_re_encrypt_preserves_decryption() {
        let sk = scalar_from_u64(123_456);
        let pk = g1_generator() * sk;
        let plaintext = hash_to_g1(b"card_1");
        let r1 = scalar_from_u64(11);
        let r2 = scalar_from_u64(22);
        let ct1 = encrypt(&plaintext, &pk, &r1);
        let ct2 = re_encrypt(&ct1, &pk, &r2);
        let recovered = decrypt(&ct2, &sk);
        assert!(g1_equal(&plaintext, &recovered));
    }

    #[test]
    fn test_reveal_token_partial_decrypt() {
        let sk = scalar_from_u64(123_456);
        let pk = g1_generator() * sk;
        let plaintext = hash_to_g1(b"card_2");
        let r = scalar_from_u64(7);
        let ct = encrypt(&plaintext, &pk, &r);
        let token = gen_reveal_token(&ct, &sk);
        // c2 - token == plaintext（因为 token = sk*c1 = sk*r*G = r*pk）
        let recovered = g1_sub(&ct.c2, &token);
        assert!(g1_equal(&plaintext, &recovered));
    }

    #[test]
    fn test_remask_changes_ciphertext() {
        let sk = scalar_from_u64(123_456);
        let pk = g1_generator() * sk;
        let plaintext = hash_to_g1(b"card_3");
        let r = scalar_from_u64(7);
        let ct = encrypt(&plaintext, &pk, &r);
        let sk2 = scalar_from_u64(555);
        let ct2 = remask(&ct, &sk2).unwrap();
        // c1 不变
        assert!(g1_equal(&ct.c1, &ct2.c1));
        // c2 变了
        assert!(!g1_equal(&ct.c2, &ct2.c2));
        // 用原 sk + 新 sk2 能解密（因为 c2 += sk2*c1，所以 M = c2 - (sk+sk2)*c1）
        let combined_sk = sk + sk2;
        let recovered = decrypt(&ct2, &combined_sk);
        assert!(g1_equal(&plaintext, &recovered));
    }

    #[test]
    fn test_remask_identity_c1_fails() {
        let ct = ElGamalCiphertext::new_placeholder_card();
        let sk = scalar_from_u64(1);
        assert!(remask(&ct, &sk).is_err());
    }

    #[test]
    fn test_add_pk_to_c2() {
        let sk = scalar_from_u64(123_456);
        let pk = g1_generator() * sk;
        let plaintext = hash_to_g1(b"card_4");
        let r = scalar_from_u64(7);
        let ct = encrypt(&plaintext, &pk, &r);
        // player_pk = sk2 * G
        let sk2 = scalar_from_u64(888);
        let player_pk = g1_generator() * sk2;
        let ct2 = add_pk_to_c2(&ct, &player_pk);
        // c1 不变
        assert!(g1_equal(&ct.c1, &ct2.c1));
        // c2 变了
        assert!(!g1_equal(&ct.c2, &ct2.c2));
        // c2 - player_pk 应等于原 c2
        let recovered_c2 = g1_sub(&ct2.c2, &player_pk);
        assert!(g1_equal(&recovered_c2, &ct.c2));
    }

    #[test]
    fn test_verify_pk_ownership_valid() {
        use rand::SeedableRng;
        use rand::rngs::StdRng;
        let mut rng = StdRng::seed_from_u64(42);
        let sk = scalar_from_u64(123_456);
        let pk = g1_generator() * sk;
        let g = g1_generator();

        // 链下构造 proof: commitment = G · omega, response = omega + challenge · sk
        let omega = <BlsScalar as CurveScalar>::random(&mut rng);
        let commitment = g * omega;

        // challenge = hash_to_scalar(G || pk || commitment)
        let g_bytes = serialize_g1(&g);
        let pk_bytes = serialize_g1(&pk);
        let comm_bytes = serialize_g1(&commitment);
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(&g_bytes);
        hash_input.extend_from_slice(&pk_bytes);
        hash_input.extend_from_slice(&comm_bytes);
        let challenge = hash_to_scalar(&hash_input).unwrap();

        let response = omega + challenge * sk;

        let mut proof_bytes = Vec::with_capacity(80);
        proof_bytes.extend_from_slice(&comm_bytes);
        proof_bytes.extend_from_slice(&serialize_scalar(&response));

        assert!(verify_pk_ownership(&pk, &proof_bytes));
    }

    #[test]
    fn test_verify_pk_ownership_wrong_length_rejected() {
        let pk = g1_generator() * scalar_from_u64(123);
        let short_proof = vec![0u8; 79];
        assert!(!verify_pk_ownership(&pk, &short_proof));
    }

    #[test]
    fn test_verify_pk_ownership_identity_pk_rejected() {
        let identity = g1_identity();
        let proof = vec![0u8; 80];
        assert!(!verify_pk_ownership(&identity, &proof));
    }

    #[test]
    fn test_verify_or_skip_skip_mode() {
        // skip=true：应直接返回 Ok(true)，不调用 closure。
        let result = verify_or_skip(true, || panic!("closure should not be called in skip mode"));
        assert!(result.unwrap());
    }

    #[test]
    fn test_verify_or_skip_no_skip_returns_closure_value() {
        // skip=false：应调用 closure 并返回其结果。
        let ok_true = verify_or_skip(false, || Ok(true));
        assert!(ok_true.unwrap());

        let ok_false: PokerL1Result<bool> = verify_or_skip(false, || Ok(false));
        assert!(!ok_false.unwrap());

        // closure 返回 Err 时应透传。
        let err: PokerL1Result<bool> = verify_or_skip(false, || {
            Err(PokerL1Error::Serialization(
                "simulated verify failure".into(),
            ))
        });
        assert!(err.is_err());
    }
}
