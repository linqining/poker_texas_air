//! poker_l1 集成测试公共辅助 — 跨测试文件共享的构造函数与工具。
//!
//! 沿用 poker_zkvm `tests/common/mod.rs` 模式：`#![allow(dead_code)]`
//! 因为不同测试文件仅使用本模块的部分函数。

#![allow(dead_code)]

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use ed25519_dalek::{SigningKey, VerifyingKey};
use poker_l1::account::derive_address;
use poker_l1::block::{Block, BlockHeader};
use poker_l1::consensus::{DagCommitCertificate, DagVertex};
use poker_l1::signature::tagged_pubkey::encode_tag;
use poker_l1::signature::{CURRENT_VERSION, SignatureScheme, TaggedPubkey};
use poker_l1::transaction::{Gas, RouteHint, Transaction, TxLane};
use poker_l1::{Address, ChainId, DEFAULT_CHAIN_ID, Hash};
use secp256k1::Secp256k1;
use secp256k1::rand::rngs::OsRng;

// ===========================================================================
// Tagged Pubkey 构造
// ===========================================================================

/// 构造 secp256k1 v1 tagged pubkey（raw = 33 字节 `byte` 填充，结构合法但非真实密钥）。
pub fn make_tagged_pubkey_secp(byte: u8) -> TaggedPubkey {
    TaggedPubkey {
        tag: encode_tag(SignatureScheme::Secp256k1, CURRENT_VERSION),
        raw: vec![byte; 33],
    }
}

/// 构造 ed25519 v1 tagged pubkey（raw = 32 字节 `byte` 填充，结构合法但非真实密钥）。
pub fn make_tagged_pubkey_ed25519(byte: u8) -> TaggedPubkey {
    TaggedPubkey {
        tag: encode_tag(SignatureScheme::Ed25519, CURRENT_VERSION),
        raw: vec![byte; 32],
    }
}

// ===========================================================================
// 真实密钥对生成（用于签名往返 proptest）
// ===========================================================================

/// 生成真实 secp256k1 密钥对（返回 secret_key, public_key, tagged_pubkey）。
pub fn make_real_secp_keypair() -> (secp256k1::SecretKey, secp256k1::PublicKey, TaggedPubkey) {
    let secp = Secp256k1::new();
    let mut rng = OsRng;
    let (secret_key, public_key) = secp.generate_keypair(&mut rng);
    let compressed = public_key.serialize();
    let tagged = TaggedPubkey::new(
        SignatureScheme::Secp256k1,
        CURRENT_VERSION,
        compressed.to_vec(),
    )
    .expect("构造 tagged pubkey 不应失败");
    (secret_key, public_key, tagged)
}

/// 生成真实 ed25519 密钥对（返回 signing_key, verifying_key, tagged_pubkey）。
pub fn make_real_ed25519_keypair() -> (SigningKey, VerifyingKey, TaggedPubkey) {
    let mut rng = OsRng;
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = VerifyingKey::from(&signing_key);
    let tagged = TaggedPubkey::new(
        SignatureScheme::Ed25519,
        CURRENT_VERSION,
        verifying_key.to_bytes().to_vec(),
    )
    .expect("构造 tagged pubkey 不应失败");
    (signing_key, verifying_key, tagged)
}

// ===========================================================================
// Block / DagVertex / CommitCert 构造
// ===========================================================================

/// 构造最小合法 `DagCommitCertificate`（1 签名者，空 vertex_hash_list）。
pub fn dummy_commit_cert() -> DagCommitCertificate {
    DagCommitCertificate {
        epoch: 1,
        commit_round: 1,
        prev_commit_hash: [0u8; 32],
        epoch_transition: None,
        vertex_hash_list: vec![],
        round_attendance_bitmap: vec![0xFF],
        state_root: [0u8; 32],
        account_root: [0u8; 32],
        public_tx_root: [0u8; 32],
        gameturn_tx_root: [0u8; 32],
        signature_list: vec![vec![0u8; 65]],
        signer_bitmap: vec![0xFF],
    }
}

/// 构造 `Block`（timestamp_ms = height * 1000，空 tx 列表）。
pub fn make_block(height: u64, prev_hash: Hash) -> Block {
    let header = BlockHeader {
        height,
        timestamp_ms: height * 1000,
        prev_hash,
        state_root: [0u8; 32],
        account_root: [0u8; 32],
        public_tx_root: [0u8; 32],
        gameturn_tx_root: [0u8; 32],
        dag_commit_certificate: dummy_commit_cert(),
    };
    Block::new(header, vec![], vec![])
}

/// 构造 `DagVertex`（空 tx_list / parent_hashes，65 字节零签名）。
pub fn make_dag_vertex(epoch: u64, round: u64) -> DagVertex {
    DagVertex {
        epoch,
        round,
        author_pubkey: make_tagged_pubkey_secp(0x02),
        tx_list: vec![],
        parent_hashes: vec![],
        author_sig: vec![0u8; 65],
    }
}

// ===========================================================================
// Transaction 构造
// ===========================================================================

/// 构造最小合法 `Transaction`（空 inputs/outputs，65 字节零签名，Public 通道）。
#[allow(clippy::too_many_arguments)]
pub fn make_tx(
    tagged_pubkey: TaggedPubkey,
    chain_id: ChainId,
    nonce: u64,
    gameturn_nonce: Option<u64>,
    is_fallback: bool,
    lane: TxLane,
) -> Transaction {
    Transaction {
        inputs: vec![],
        outputs: vec![],
        contract_call: None,
        tagged_pubkey,
        signature: vec![0u8; 65],
        gas: Gas::zero(),
        lane_hint: lane,
        route_hint: RouteHint::AnyValidator,
        chain_id,
        nonce,
        gameturn_nonce,
        is_fallback,
    }
}

// ===========================================================================
// 哈希工具
// ===========================================================================

/// blake2b_256 摘要工具（32 字节输出）。
pub fn blake2b_256(data: &[u8]) -> Hash {
    let mut h = Blake2bVar::new(32).expect("32 <= 64");
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).expect("32 <= 64");
    out
}

// ===========================================================================
// Address 工具
// ===========================================================================

/// 从字节构造 20 字节地址（测试用，非真实派生）。
pub fn make_address(byte: u8) -> Address {
    [byte; 20]
}

/// 默认 chain_id（"pok1"）。
pub const fn default_chain_id() -> ChainId {
    DEFAULT_CHAIN_ID
}

/// 从 tagged pubkey 派生地址（re-export account::derive_address 便于测试）。
pub fn address_of(tp: &TaggedPubkey) -> Address {
    derive_address(tp)
}
