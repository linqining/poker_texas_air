//! 链上合约 verify 方法端到端测试
//!
//! 本模块通过 `sui_devInspectTransactionBlock` 调用测试网上已发布的 Move 合约
//! (`0x9cdd1d17521d526e8a22e6fcb7ad3815575fbdda4eb5a32116b85f604c193a76`)
//! 中的各个 verify 方法，验证 Rust 端生成的真实证明能被 Move 合约正确验证。
//!
//! # 运行方式
//!
//! 所有测试标记为 `#[ignore]`（需要网络访问），运行方式：
//! ```sh
//! cargo test --package poker_protocol --test move_verify_tests --nocapture --ignored
//! ```
//!
//! # 测试覆盖
//!
//! | 测试函数 | Move verify 方法 | 对应 Rust 证明 |
//! |---------|-----------------|---------------|
//! | `test_verify_pk_ownership_on_testnet` | `zk_verifier::verify_pk_ownership` | `PKOwnershipProof` |
//! | `test_verify_shuffle_on_testnet` | `zk_verifier::verify_shuffle` | `ZKShuffleProof` |
//! | `test_verify_remask_on_testnet` | `zk_verifier::verify_remask` | `DLEqProof<RemaskKind>` |
//! | `test_verify_leave_on_testnet` | `zk_verifier::verify_leave` | `DLEqProof<LeaveKind>` |
//! | `test_verify_reveal_token_on_testnet` | `zk_verifier::verify_reveal_token` | `RevealTokenProof` |
//! | `test_verify_reconstruct_on_testnet` | `zk_verifier::verify_reconstruct` | `ReconstructProof` |

use base64::Engine;
use poker_protocol::crypto::{
    DefaultCurve, EcPoint, ElGamalCiphertext, Scalar,
};
use poker_protocol::crypto::curve::{Curve, CurvePoint, CurveScalar};
use poker_protocol::zk_shuffle::dleq_proof::{DLEqProof, RemaskKind, LeaveKind};
use poker_protocol::zk_shuffle::generalized_schnorr_proof::GeneralizedSchnorrProof;
use poker_protocol::zk_shuffle::shuffle_proof::ZKShuffleProof;
use poker_protocol::z_poker::PKOwnershipProof;

#[cfg(feature = "sui-sdk")]
use group::Group;
#[cfg(feature = "sui-sdk")]
use poker_protocol::zk_shuffle::reconstruction::{
    ChaumPedersenDLEQProof,
};
#[cfg(feature = "sui-sdk")]
use poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof;
#[cfg(feature = "sui-sdk")]
use poker_protocol::zk_shuffle::transcript_ext::{CryptoTranscript, FiatShamirTranscript};
#[cfg(feature = "sui-sdk")]
use poker_protocol::z_poker::protocol::new_plain_text;
#[cfg(feature = "sui-sdk")]
use rand::rngs::OsRng;
#[cfg(feature = "sui-sdk")]
use sui_sdk_types::{
    Address, Argument, Command, Identifier, Input, MoveCall, ProgrammableTransaction,
    TransactionKind,
};

// ============================================================================
// 常量
// ============================================================================

/// 测试网已发布的 texas_poker_move 合约包 ID
/// （第四版：g1_msm 使用 g1_mul 循环 + deserialize_g1_points 函数）
#[cfg(feature = "sui-sdk")]
const PACKAGE_ID: &str = "0x9cdd1d17521d526e8a22e6fcb7ad3815575fbdda4eb5a32116b85f604c193a76";



/// ElGamal 密文字节数（c1:48 + c2:48）
const CIPHERTEXT_SIZE: usize = 96;

// ============================================================================
// 序列化辅助函数
// ============================================================================

/// 将 G1 点序列化为 48 字节压缩格式
fn g1_to_bytes(p: &EcPoint) -> Vec<u8> {
    p.compress().as_ref().to_vec()
}

/// 将标量序列化为 32 字节
fn scalar_to_bytes(s: &Scalar) -> Vec<u8> {
    s.as_bytes()
}

/// 将 ElGamal 密文序列化为 96 字节（c1:48 + c2:48）
fn ciphertext_to_bytes(ct: &ElGamalCiphertext) -> Vec<u8> {
    let mut buf = Vec::with_capacity(CIPHERTEXT_SIZE);
    buf.extend_from_slice(&g1_to_bytes(&ct.c1));
    buf.extend_from_slice(&g1_to_bytes(&ct.c2));
    buf
}

/// 将密文数组序列化为 flat bytes
fn ciphertexts_to_bytes(cts: &[ElGamalCiphertext]) -> Vec<u8> {
    cts.iter().flat_map(ciphertext_to_bytes).collect()
}

/// 将 u16 以小端序写入 buffer
fn append_u16_le(buf: &mut Vec<u8>, val: u16) {
    buf.push((val & 0xFF) as u8);
    buf.push(((val >> 8) & 0xFF) as u8);
}

/// 序列化 GeneralizedSchnorrProof 为 Move 合约期望的字节格式
/// 格式: commitment(48) + u16(count) + count*scalar(32)
fn serialize_schnorr_proof(proof: &GeneralizedSchnorrProof<DefaultCurve>) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&g1_to_bytes(&proof.commitment));
    let count = proof.responses.len() as u16;
    append_u16_le(&mut buf, count);
    for resp in &proof.responses {
        buf.extend_from_slice(&scalar_to_bytes(resp));
    }
    buf
}

/// 序列化 ZKShuffleProof 为 Move 合约期望的字节格式
/// 格式: sum_c1(48) + sum_c2(48) + nonce(32) + 3*schnorr_proof
fn serialize_shuffle_proof(proof: &ZKShuffleProof<DefaultCurve>) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&g1_to_bytes(&proof.sum_c1_commit));
    buf.extend_from_slice(&g1_to_bytes(&proof.sum_c2_commit));
    buf.extend_from_slice(&scalar_to_bytes(&proof.nonce));
    buf.extend_from_slice(&serialize_schnorr_proof(&proof.combined_schnorr_proof));
    buf.extend_from_slice(&serialize_schnorr_proof(&proof.sum_c1_schnorr_proof));
    buf.extend_from_slice(&serialize_schnorr_proof(&proof.sum_c2_schnorr_proof));
    buf
}

/// 序列化 DLEqProof (RemaskProof/LeaveProof) 为 Move 合约期望的字节格式
/// 格式: u16(count) + count*G1(48) + commitment_pk(48) + response(32) + nonce(32)
fn serialize_dleq_proof<C: Curve, K: poker_protocol::zk_shuffle::dleq_proof::DLEqProofKind<C>>(
    proof: &DLEqProof<C, K>,
) -> Vec<u8> {
    let mut buf = Vec::new();
    let count = proof.per_card_commitments.len() as u16;
    append_u16_le(&mut buf, count);
    for c in &proof.per_card_commitments {
        buf.extend_from_slice(&c.compress().as_ref());
    }
    buf.extend_from_slice(&proof.commitment_pk.compress().as_ref());
    buf.extend_from_slice(&proof.response.as_bytes());
    buf.extend_from_slice(&proof.nonce.as_bytes());
    buf
}

/// 序列化 RevealTokenProof 为 Move 合约期望的字节格式
/// 格式: user_pk(48) + t1(48) + t2(48) + response_s(32) + nonce(32)
/// M4 修复：包含 nonce 字段（对齐 Move reveal_token_proof.move）
#[cfg(feature = "sui-sdk")]
fn serialize_reveal_token_proof(proof: &RevealTokenProof<DefaultCurve>) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&g1_to_bytes(&proof.user_public_key));
    buf.extend_from_slice(&g1_to_bytes(&proof.commitment_t1));
    buf.extend_from_slice(&g1_to_bytes(&proof.commitment_t2));
    buf.extend_from_slice(&scalar_to_bytes(&proof.response_s));
    buf.extend_from_slice(&scalar_to_bytes(&proof.nonce));
    buf
}

/// 序列化 ChaumPedersenDLEQProof 为字节
/// 格式: commitment_a(48) + commitment_b(48) + response(32)
#[cfg(feature = "sui-sdk")]
fn serialize_chaum_pedersen(proof: &ChaumPedersenDLEQProof<DefaultCurve>) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&g1_to_bytes(&proof.commitment_a));
    buf.extend_from_slice(&g1_to_bytes(&proof.commitment_b));
    buf.extend_from_slice(&scalar_to_bytes(&proof.response));
    buf
}

// ============================================================================
// PTB 构建辅助函数（仅 sui-sdk feature 需要）
// ============================================================================

#[cfg(feature = "sui-sdk")]
fn parse_address(s: &str) -> Result<Address, String> {
    s.parse::<Address>()
        .map_err(|e| format!("invalid address '{}': {}", s, e))
}

#[cfg(feature = "sui-sdk")]
fn bcs_encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, String> {
    bcs::to_bytes(value).map_err(|e| format!("BCS serialization failed: {}", e))
}

/// 创建 Pure 输入（BCS 编码的 vector<u8>）
#[cfg(feature = "sui-sdk")]
fn pure_bytes(bytes: Vec<u8>) -> Input {
    Input::Pure(bcs_encode(&bytes).expect("BCS encode vector<u8> should not fail"))
}

/// 创建 Pure 输入（直接传入原始字节，不做 BCS 编码）
/// 用于当 Input::Pure 的内容已经是 BCS 编码的 Move 值时
#[cfg(feature = "sui-sdk")]
#[allow(dead_code)]
fn pure_raw(bytes: Vec<u8>) -> Input {
    Input::Pure(bytes)
}

/// 将 ProgrammableTransaction 序列化为 base64 编码的 TransactionKind
#[cfg(feature = "sui-sdk")]
fn serialize_tx_kind(pt: ProgrammableTransaction) -> Result<String, String> {
    let tx_kind = TransactionKind::ProgrammableTransaction(pt);
    let bytes = bcs::to_bytes(&tx_kind)
        .map_err(|e| format!("TransactionKind BCS serialization failed: {}", e))?;
    let engine = base64::engine::general_purpose::STANDARD;
    Ok(engine.encode(&bytes))
}

// ============================================================================
// 公共 API：JSON → Move 合约字节格式
//
// 供 client-wasm 调用。解析 JSON 后构造 Rust 结构体，
// 复用上方已有的 serialize_* 函数，确保编码格式一致。
// ============================================================================

/// hex → EcPoint (48 bytes compressed)
fn hex_to_ecpoint(hex_str: &str) -> Result<EcPoint, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
    if bytes.len() != 48 {
        return Err(format!("EC point must be 48 bytes, got {}", bytes.len()));
    }
    <EcPoint as CurvePoint>::from_compressed(&bytes)
        .ok_or_else(|| "Invalid EC point".to_string())
}

/// hex → Scalar (32 bytes)
fn hex_to_scalar(hex_str: &str) -> Result<Scalar, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("Invalid hex: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("Scalar must be 32 bytes, got {}", bytes.len()));
    }
    Ok(<Scalar as CurveScalar>::from_bytes_mod_order(&bytes))
}

/// JSON Value → ElGamalCiphertext
fn json_value_to_ct(val: &serde_json::Value) -> Result<ElGamalCiphertext, String> {
    Ok(ElGamalCiphertext {
        c1: hex_to_ecpoint(val["c1_hex"].as_str().ok_or("missing c1_hex")?)?,
        c2: hex_to_ecpoint(val["c2_hex"].as_str().ok_or("missing c2_hex")?)?,
    })
}

/// JSON 字符串 → Vec<ElGamalCiphertext>
fn json_to_ct_vec(json_str: &str) -> Result<Vec<ElGamalCiphertext>, String> {
    let arr: Vec<serde_json::Value> = serde_json::from_str(json_str)
        .map_err(|e| format!("JSON parse error: {}", e))?;
    arr.iter().map(json_value_to_ct).collect()
}

/// JSON Value → GeneralizedSchnorrProof<DefaultCurve>
fn json_to_schnorr_proof(
    val: &serde_json::Value,
) -> Result<GeneralizedSchnorrProof<DefaultCurve>, String> {
    let commitment = hex_to_ecpoint(
        val["commitment_hex"].as_str().ok_or("missing commitment_hex")?,
    )?;
    let responses_arr = val["responses_hex"]
        .as_array()
        .ok_or("missing responses_hex array")?;
    let responses: Vec<Scalar> = responses_arr
        .iter()
        .map(|r| hex_to_scalar(r.as_str().ok_or("response must be string")?))
        .collect::<Result<_, _>>()?;
    Ok(GeneralizedSchnorrProof { commitment, responses })
}

/// JSON Value → ZKShuffleProof<DefaultCurve>
fn json_to_shuffle_proof(
    val: &serde_json::Value,
) -> Result<ZKShuffleProof<DefaultCurve>, String> {
    Ok(ZKShuffleProof {
        sum_c1_commit: hex_to_ecpoint(
            val["sum_c1_commit_hex"].as_str().ok_or("missing sum_c1_commit_hex")?,
        )?,
        sum_c2_commit: hex_to_ecpoint(
            val["sum_c2_commit_hex"].as_str().ok_or("missing sum_c2_commit_hex")?,
        )?,
        combined_schnorr_proof: json_to_schnorr_proof(&val["combined_schnorr_proof"])?,
        sum_c1_schnorr_proof: json_to_schnorr_proof(&val["sum_c1_schnorr_proof"])?,
        sum_c2_schnorr_proof: json_to_schnorr_proof(&val["sum_c2_schnorr_proof"])?,
        nonce: hex_to_scalar(val["nonce_hex"].as_str().ok_or("missing nonce_hex")?)?,
    })
}

/// JSON Value → DLEqProof<DefaultCurve, K>
fn json_to_dleq_proof<K: poker_protocol::zk_shuffle::dleq_proof::DLEqProofKind<DefaultCurve>>(
    val: &serde_json::Value,
) -> Result<DLEqProof<DefaultCurve, K>, String> {
    let commitments_arr = val["per_card_commitments_hex"]
        .as_array()
        .ok_or("missing per_card_commitments_hex")?;
    let per_card_commitments: Vec<EcPoint> = commitments_arr
        .iter()
        .map(|c| hex_to_ecpoint(c.as_str().ok_or("commitment must be string")?))
        .collect::<Result<_, _>>()?;
    let commitment_pk = hex_to_ecpoint(
        val["commitment_pk_hex"].as_str().ok_or("missing commitment_pk_hex")?,
    )?;
    let response = hex_to_scalar(
        val["response_hex"].as_str().ok_or("missing response_hex")?,
    )?;
    let nonce = hex_to_scalar(
        val["nonce_hex"].as_str().ok_or("missing nonce_hex")?,
    )?;
    Ok(DLEqProof::from_parts(
        per_card_commitments,
        commitment_pk,
        response,
        nonce,
    ))
}

/// 序列化 pk（G1 compressed 48 bytes）为 Move 合约期望的字节格式。
///
/// 输入: pk_hex (48 bytes hex)
/// 输出: 48 bytes
pub fn serialize_pk_to_move_bytes(pk_hex: &str) -> Result<Vec<u8>, String> {
    let pk = hex_to_ecpoint(pk_hex)?;
    Ok(g1_to_bytes(&pk))
}

/// 序列化 pk_ownership_proof 为 Move 合约期望的字节格式。
///
/// 输入 JSON: {"commitment_hex":"...","response_hex":"..."}
/// 输出: commitment(48) + response(32) = 80 bytes
pub fn serialize_pk_ownership_proof_to_move_bytes(proof_json: &str) -> Result<Vec<u8>, String> {
    let val: serde_json::Value = serde_json::from_str(proof_json)
        .map_err(|e| format!("JSON parse error: {}", e))?;
    let proof = PKOwnershipProof {
        commitment: hex_to_ecpoint(
            val["commitment_hex"].as_str().ok_or("missing commitment_hex")?,
        )?,
        response: hex_to_scalar(
            val["response_hex"].as_str().ok_or("missing response_hex")?,
        )?,
    };
    let mut buf = Vec::new();
    buf.extend_from_slice(&g1_to_bytes(&proof.commitment));
    buf.extend_from_slice(&scalar_to_bytes(&proof.response));
    Ok(buf)
}

/// 序列化 ElGamalCiphertext 数组为 Move 合约期望的 flat bytes 格式。
///
/// 输入 JSON: [{"c1_hex":"...","c2_hex":"..."}, ...]
/// 输出: flat c1(48) + c2(48) per card = 96*N bytes
pub fn serialize_ciphertexts_to_move_bytes(cts_json: &str) -> Result<Vec<u8>, String> {
    let cts = json_to_ct_vec(cts_json)?;
    Ok(ciphertexts_to_bytes(&cts))
}

/// 序列化 RemaskProof 为 Move 合约期望的字节格式。
///
/// 输入 JSON: {"per_card_commitments_hex":["...",...],"commitment_pk_hex":"...","response_hex":"...","nonce_hex":"..."}
/// 输出: u16(count) + count*48(per_card_commitments) + 48(commitment_pk) + 32(response) + 32(nonce)
pub fn serialize_remask_proof_to_move_bytes(proof_json: &str) -> Result<Vec<u8>, String> {
    let val: serde_json::Value = serde_json::from_str(proof_json)
        .map_err(|e| format!("JSON parse error: {}", e))?;
    let proof: DLEqProof<DefaultCurve, RemaskKind> = json_to_dleq_proof(&val)?;
    Ok(serialize_dleq_proof(&proof))
}

/// 序列化 ShuffleProof 为 Move 合约期望的字节格式。
///
/// 输入 JSON: {"sum_c1_commit_hex":"...","sum_c2_commit_hex":"...","combined_schnorr_proof":{...},"sum_c1_schnorr_proof":{...},"sum_c2_schnorr_proof":{...},"nonce_hex":"..."}
/// 输出: 48(sum_c1_commit) + 48(sum_c2_commit) + 32(nonce) + 3*schnorr_proof
///   schnorr_proof: 48(commitment) + u16(count) + count*32(responses)
pub fn serialize_shuffle_proof_to_move_bytes(proof_json: &str) -> Result<Vec<u8>, String> {
    let _: serde_json::Value = serde_json::from_str(proof_json)
        .map_err(|e| format!("JSON parse error: {}", e))?;
    Err("shuffle proof serialization is disabled until the Bayer-Groth V2 precompile verifier is connected".to_string())
}

/// 序列化 LeaveProof 为 Move 合约期望的字节格式（与 RemaskProof 格式相同）。
///
/// 输入 JSON: {"per_card_commitments_hex":["...",...],"commitment_pk_hex":"...","response_hex":"...","nonce_hex":"..."}
/// 输出: u16(count) + count*48 + 48 + 32 + 32
pub fn serialize_leave_proof_to_move_bytes(proof_json: &str) -> Result<Vec<u8>, String> {
    let val: serde_json::Value = serde_json::from_str(proof_json)
        .map_err(|e| format!("JSON parse error: {}", e))?;
    let proof: DLEqProof<DefaultCurve, LeaveKind> = json_to_dleq_proof(&val)?;
    Ok(serialize_dleq_proof(&proof))
}

/// join_game_and_shuffle 序列化结果（base64 编码的各字段）
#[derive(serde::Serialize)]
pub struct JoinAndShuffleBytes {
    pub pk: String,
    pub pk_ownership_proof: String,
    pub output_cards: String,
    pub remask_proof_bytes: String,
    pub shuffle_proof_bytes: String,
}

/// 一次性将 join_game_and_shuffle 的完整结果转换为 Move 合约期望的字节格式。
///
/// 输入: join_game_and_shuffle 返回的 JSON 字符串
/// 输出: JoinAndShuffleBytes 包含 5 个 base64 编码的字段:
///   - pk: base64(48 bytes)
///   - pk_ownership_proof: base64(80 bytes)
///   - output_cards: base64(96*N bytes)
///   - remask_proof_bytes: base64(...)
///   - shuffle_proof_bytes: base64(...)
pub fn serialize_join_and_shuffle_to_move_bytes(
    join_result_json: &str,
) -> Result<JoinAndShuffleBytes, String> {
    let val: serde_json::Value = serde_json::from_str(join_result_json)
        .map_err(|e| format!("JSON parse error: {}", e))?;

    let pk_hex = val["pk_hex"].as_str().ok_or("missing pk_hex")?;
    let pk_bytes = serialize_pk_to_move_bytes(pk_hex)?;

    let pk_ownership_proof_json = serde_json::to_string(&val["pk_ownership_proof"])
        .map_err(|e| format!("Serialize error: {}", e))?;
    let pk_ownership_proof_bytes =
        serialize_pk_ownership_proof_to_move_bytes(&pk_ownership_proof_json)?;

    let mask_and_shuffle = &val["mask_and_shuffle_round"];
    let output_cards_json = serde_json::to_string(&mask_and_shuffle["output_cards"])
        .map_err(|e| format!("Serialize error: {}", e))?;
    let output_cards_bytes = serialize_ciphertexts_to_move_bytes(&output_cards_json)?;

    let remask_proof_json = serde_json::to_string(&mask_and_shuffle["remask_proof"])
        .map_err(|e| format!("Serialize error: {}", e))?;
    let remask_proof_bytes = serialize_remask_proof_to_move_bytes(&remask_proof_json)?;

    let shuffle_proof_json = serde_json::to_string(&mask_and_shuffle["shuffle_proof"])
        .map_err(|e| format!("Serialize error: {}", e))?;
    let shuffle_proof_bytes = serialize_shuffle_proof_to_move_bytes(&shuffle_proof_json)?;

    let engine = base64::engine::general_purpose::STANDARD;
    Ok(JoinAndShuffleBytes {
        pk: engine.encode(&pk_bytes),
        pk_ownership_proof: engine.encode(&pk_ownership_proof_bytes),
        output_cards: engine.encode(&output_cards_bytes),
        remask_proof_bytes: engine.encode(&remask_proof_bytes),
        shuffle_proof_bytes: engine.encode(&shuffle_proof_bytes),
    })
}
