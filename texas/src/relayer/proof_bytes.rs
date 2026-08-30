//! Proof serialization helpers for the `texas_poker_move` contract.
//!
//! These functions convert Rust crypto proof types to the byte format expected
//! by the Move contract's `zk_verifier` / `table_serialization` modules.
//!
//! Extracted from `move_verify_tests.rs` so they can be reused by socket
//! handlers when building on-chain PTBs for shuffle / reconstruct / reveal /
//! join_and_shuffle actions.

use poker_protocol::crypto::{DefaultCurve, EcPoint, ElGamalCiphertext, Scalar};
use poker_protocol::crypto::curve::{Curve, CurvePoint, CurveScalar};
use poker_protocol::zk_shuffle::dleq_proof::DLEqProof;
use poker_protocol::zk_shuffle::generalized_schnorr_proof::GeneralizedSchnorrProof;
use poker_protocol::zk_shuffle::reconstruction::{
    ChaumPedersenDLEQProof, ReconstructProof,
};
use poker_protocol::zk_shuffle::reveal_token_proof::RevealTokenProof;
use poker_protocol::zk_shuffle::ShuffleProof;
use poker_protocol::z_poker::key_manager::PKOwnershipProof;

// ============================================================================
// Constants
// ============================================================================

/// G1 compressed point size (BLS12-381 G1 compressed)
const G1_POINT_SIZE: usize = 48;

/// BLS scalar size
const SCALAR_SIZE: usize = 32;

/// ElGamal ciphertext size (c1:48 + c2:48)
const CIPHERTEXT_SIZE: usize = 96;

// ============================================================================
// Serialization helpers
// ============================================================================

/// 将 G1 点序列化为 48 字节压缩格式
pub fn g1_to_bytes(p: &EcPoint) -> Vec<u8> {
    p.compress().as_ref().to_vec()
}

/// 将标量序列化为 32 字节
pub fn scalar_to_bytes(s: &Scalar) -> Vec<u8> {
    s.as_bytes()
}

/// 将 ElGamal 密文序列化为 96 字节（c1:48 + c2:48）
pub fn ciphertext_to_bytes(ct: &ElGamalCiphertext) -> Vec<u8> {
    let mut buf = Vec::with_capacity(CIPHERTEXT_SIZE);
    buf.extend_from_slice(&g1_to_bytes(&ct.c1));
    buf.extend_from_slice(&g1_to_bytes(&ct.c2));
    buf
}

/// 将密文数组序列化为 flat bytes
pub fn ciphertexts_to_bytes(cts: &[ElGamalCiphertext]) -> Vec<u8> {
    cts.iter().flat_map(ciphertext_to_bytes).collect()
}

/// 将 u16 以小端序写入 buffer
pub fn append_u16_le(buf: &mut Vec<u8>, val: u16) {
    buf.push((val & 0xFF) as u8);
    buf.push(((val >> 8) & 0xFF) as u8);
}

/// 序列化 GeneralizedSchnorrProof 为 Move 合约期望的字节格式
/// 格式: commitment(48) + u16(count) + count*scalar(32)
pub fn serialize_schnorr_proof(proof: &GeneralizedSchnorrProof<DefaultCurve>) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&g1_to_bytes(&proof.commitment));
    let count = proof.responses.len() as u16;
    append_u16_le(&mut buf, count);
    for resp in &proof.responses {
        buf.extend_from_slice(&scalar_to_bytes(resp));
    }
    buf
}

/// Phase 0 fail-closed boundary. The deployed Move entry point only understands
/// the known-unsound V1 layout, while production now emits Bayer--Groth V2.
/// Do not submit either variant until the shuffle V2 precompile verifier is wired.
pub fn serialize_shuffle_proof(_proof: &ShuffleProof) -> Result<Vec<u8>, String> {
    Err("shuffle V2 precompile verifier is not connected; legacy V1 submission is disabled".to_string())
}

/// 序列化 DLEqProof (RemaskProof/LeaveProof) 为 Move 合约期望的字节格式
/// 格式: u16(count) + count*G1(48) + commitment_pk(48) + response(32) + nonce(32)
pub fn serialize_dleq_proof<C: Curve, K: poker_protocol::zk_shuffle::dleq_proof::DLEqProofKind<C>>(
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
/// 格式: user_pk(48) + t1(48) + t2(48) + response_s(32) + nonce(32) = 208 bytes
/// 对齐 Move `table_serialization::deserialize_reveal_token_proof`（M4 修复：含 nonce 字段）
pub fn serialize_reveal_token_proof(proof: &RevealTokenProof<DefaultCurve>) -> Vec<u8> {
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
pub fn serialize_chaum_pedersen(proof: &ChaumPedersenDLEQProof<DefaultCurve>) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&g1_to_bytes(&proof.commitment_a));
    buf.extend_from_slice(&g1_to_bytes(&proof.commitment_b));
    buf.extend_from_slice(&scalar_to_bytes(&proof.response));
    buf
}

/// Reconstruction V2 requires the Bayer--Groth precompile wire format. The
/// deployed Move verifier only understands the retired aggregate V1 proof, so
/// submissions must fail closed until that precompile route is connected.
pub fn serialize_reconstruct_proof(
    _proof: &ReconstructProof<DefaultCurve>,
) -> Result<Vec<u8>, String> {
    Err(
        "reconstruction V2 precompile verifier is not connected; legacy V1 submission is disabled"
            .to_string(),
    )
}

/// 序列化 PKOwnershipProof 为 Move 合约期望的字节格式
/// 格式: commitment(48) + response(32) = 80 bytes
pub fn serialize_pk_ownership_proof(proof: &PKOwnershipProof) -> Vec<u8> {
    let mut buf = Vec::with_capacity(80);
    buf.extend_from_slice(&g1_to_bytes(&proof.commitment));
    buf.extend_from_slice(&scalar_to_bytes(&proof.response));
    buf
}

/// Helper: 将 pk (EcPoint) 序列化为 48 字节压缩格式。
/// 等价于 `g1_to_bytes`，提供语义更明确的别名。
pub fn pk_to_bytes(pk: &EcPoint) -> Vec<u8> {
    g1_to_bytes(pk)
}

// Suppress unused-import warnings for constants re-exported via type aliases.
#[allow(dead_code)]
const _G1_POINT_SIZE: usize = G1_POINT_SIZE;
#[allow(dead_code)]
const _SCALAR_SIZE: usize = SCALAR_SIZE;
