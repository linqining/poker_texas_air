//! Phase 7 端到端测试共享辅助函数。
//!
//! 提供真实密钥签名、游戏状态构造、DAG vertex 构造等辅助函数，
//! 供 `phase7_integration.rs` 各测试模块共享。

use ed25519_dalek::{Signer, SigningKey};
use poker_l1::block::{Block, BlockHeader};
use poker_l1::consensus::{DagCommitCertificate, DagVertex, Epoch, ValidatorEntry, ValidatorSet};
use poker_l1::signature::TaggedPubkey;
use poker_l1::signature::tagged_pubkey::{CURRENT_VERSION, SignatureScheme, encode_tag};
use poker_l1::transaction::{Gas, RouteHint, Transaction, TxLane};
use poker_l1::vm::contracts::settle::RakeConfig;
use poker_l1::vm::contracts::types::{
    ExecutionMode, GameContract, GamePhase, HandState, PlayerStack, RakeConfigRef,
};
use poker_l1::{Address, BlockHeight, ChainId, Hash};
use secp256k1::rand::rngs::OsRng;
use secp256k1::{Message, Secp256k1};

// ===== 地址与 pubkey 辅助 =====

/// 构造占位 tagged pubkey（secp256k1 scheme，不对应真实密钥）。
#[must_use]
pub fn dummy_tagged_pubkey(byte: u8) -> TaggedPubkey {
    let mut raw = vec![byte];
    raw.extend_from_slice(&[0x02u8; 32]);
    TaggedPubkey {
        tag: encode_tag(SignatureScheme::Secp256k1, CURRENT_VERSION),
        raw,
    }
}

/// 构造占位地址。
#[must_use]
pub fn make_addr(byte: u8) -> Address {
    [byte; 20]
}

/// 构造 ObjectID。
#[must_use]
pub fn make_game_id(addr_byte: u8, nonce: u64) -> poker_l1::object_model::ObjectID {
    poker_l1::object_model::ObjectID::new([addr_byte; 20], nonce)
}

// ===== 真实密钥对生成与签名 =====

/// 生成真实 secp256k1 密钥对。
///
/// 返回 `(secret_key, public_key, tagged_pubkey)`。
pub fn real_secp_keypair() -> (secp256k1::SecretKey, secp256k1::PublicKey, TaggedPubkey) {
    let secp = Secp256k1::new();
    let mut rng = OsRng;
    let (secret, public) = secp.generate_keypair(&mut rng);
    let compressed = public.serialize();
    let tagged = TaggedPubkey::new(
        SignatureScheme::Secp256k1,
        CURRENT_VERSION,
        compressed.to_vec(),
    )
    .expect("构造 tagged pubkey 不应失败");
    (secret, public, tagged)
}

/// 生成真实 ed25519 密钥对。
///
/// 返回 `(signing_key, tagged_pubkey)`。
pub fn real_ed25519_keypair() -> (SigningKey, TaggedPubkey) {
    let sk = SigningKey::generate(&mut OsRng);
    let pk_bytes = sk.verifying_key().to_bytes();
    let tagged = TaggedPubkey::new(SignatureScheme::Ed25519, CURRENT_VERSION, pk_bytes.to_vec())
        .expect("构造 ed25519 tagged pubkey 不应失败");
    (sk, tagged)
}

/// 用 secp256k1 密钥对消息哈希签名（65 字节 compact recoverable: r||s||v）。
pub fn sign_secp(secret: &secp256k1::SecretKey, msg_hash: &Hash) -> Vec<u8> {
    let secp = Secp256k1::new();
    let msg = Message::from_digest_slice(msg_hash).expect("msg_hash 必须是 32 字节");
    let sig = secp.sign_ecdsa_recoverable(&msg, secret);
    let (recovery_id, compact) = sig.serialize_compact();
    let mut sig_bytes = compact.to_vec();
    sig_bytes.push(recovery_id.to_i32() as u8);
    sig_bytes
}

/// 用 ed25519 密钥对消息哈希签名（64 字节）。
pub fn sign_ed25519(sk: &SigningKey, msg_hash: &Hash) -> Vec<u8> {
    sk.sign(msg_hash).to_vec()
}

// ===== Block / Vertex / Certificate 辅助 =====

/// 构造全零 DagCommitCertificate（用于占位 block）。
#[must_use]
pub fn dummy_commit_certificate() -> DagCommitCertificate {
    DagCommitCertificate {
        epoch: 0,
        commit_round: 0,
        prev_commit_hash: [0u8; 32],
        epoch_transition: None,
        vertex_hash_list: vec![],
        round_attendance_bitmap: vec![],
        state_root: [0u8; 32],
        account_root: [0u8; 32],
        public_tx_root: [0u8; 32],
        gameturn_tx_root: [0u8; 32],
        signature_list: vec![],
        signer_bitmap: vec![],
    }
}

/// 构造占位 block。
#[must_use]
pub fn dummy_block(height: u64) -> Block {
    Block::new(
        BlockHeader {
            height,
            timestamp_ms: height * 1000,
            prev_hash: [0u8; 32],
            state_root: [0u8; 32],
            account_root: [0u8; 32],
            public_tx_root: [0u8; 32],
            gameturn_tx_root: [0u8; 32],
            dag_commit_certificate: dummy_commit_certificate(),
        },
        vec![],
        vec![],
    )
}

/// 构造占位 DAG vertex。
#[must_use]
pub fn make_vertex(epoch: Epoch, round: u64, author: TaggedPubkey) -> DagVertex {
    DagVertex {
        epoch,
        round,
        author_pubkey: author,
        tx_list: vec![],
        parent_hashes: vec![],
        author_sig: vec![0u8; 65],
    }
}

// ===== Transaction 辅助 =====

/// 构造 Public tx（非游戏，正常计费 gas）。
#[must_use]
pub fn make_public_tx(signer: TaggedPubkey, nonce: u64, chain_id: ChainId) -> Transaction {
    Transaction {
        inputs: vec![],
        outputs: vec![],
        contract_call: None,
        tagged_pubkey: signer,
        signature: vec![0u8; 65],
        gas: Gas::new(1000, 1),
        lane_hint: TxLane::Public,
        route_hint: RouteHint::AnyValidator,
        chain_id,
        nonce,
        gameturn_nonce: None,
        is_fallback: false,
    }
}

/// 构造 GameTurn tx（免 gas，AssignedValidator 路由）。
#[must_use]
pub fn make_gameturn_tx(
    signer: TaggedPubkey,
    gameturn_nonce: u64,
    chain_id: ChainId,
) -> Transaction {
    Transaction {
        inputs: vec![],
        outputs: vec![],
        contract_call: None,
        tagged_pubkey: signer,
        signature: vec![0u8; 65],
        gas: Gas::zero(),
        lane_hint: TxLane::GameTurn,
        route_hint: RouteHint::AssignedValidator,
        chain_id,
        nonce: 0,
        gameturn_nonce: Some(gameturn_nonce),
        is_fallback: false,
    }
}

/// 构造 ForceSync tx（非游戏，正常计费 gas）。
#[must_use]
pub fn make_forcesync_tx(signer: TaggedPubkey, nonce: u64, chain_id: ChainId) -> Transaction {
    Transaction {
        inputs: vec![],
        outputs: vec![],
        contract_call: None,
        tagged_pubkey: signer,
        signature: vec![0u8; 65],
        gas: Gas::new(1000, 1),
        lane_hint: TxLane::ForceSync,
        route_hint: RouteHint::AnyValidator,
        chain_id,
        nonce,
        gameturn_nonce: None,
        is_fallback: false,
    }
}

// ===== Game 状态辅助 =====

/// 构造 RakeConfigRef。
#[must_use]
pub fn make_rake_config_ref() -> RakeConfigRef {
    RakeConfigRef {
        rake_rate_bps: 500, // 5%
        rake_cap: 1000,
        rake_recipient: make_addr(0x00),
    }
}

/// 构造 RakeConfig。
#[must_use]
pub fn make_rake_config() -> RakeConfig {
    RakeConfig {
        rake_rate_bps: 500,
        rake_cap: 1000,
        rake_recipient: make_addr(0x00),
    }
}

/// 构造 OnChain 模式 GameContract。
#[must_use]
#[allow(dead_code)] // 保留供未来测试使用
pub fn make_onchain_game(last_action_height: BlockHeight) -> GameContract {
    let mut game = GameContract::new(
        make_game_id(0x01, 1),
        make_addr(0x01),
        dummy_tagged_pubkey(0xFF),
        ExecutionMode::OnChain,
        make_rake_config_ref(),
        30, // turn_timeout_blocks
    );
    game.last_action_height = last_action_height;
    game
}

/// 构造 OffChain 模式 GameContract。
#[must_use]
pub fn make_offchain_game(last_action_height: BlockHeight) -> GameContract {
    let mut game = GameContract::new(
        make_game_id(0x02, 1),
        make_addr(0x02),
        dummy_tagged_pubkey(0xFE),
        ExecutionMode::OffChain,
        make_rake_config_ref(),
        30,
    );
    game.last_action_height = last_action_height;
    game
}

/// 构造含 checkpoint 的 Game（用于 OffChain 恢复测试）。
#[must_use]
pub fn make_game_with_checkpoint(last_action_height: BlockHeight) -> GameContract {
    let mut game = make_offchain_game(last_action_height);
    game.last_checkpoint_state_hash = Some([0xAB; 32]);
    game.last_commitment = Some([0x11; 32]);
    game
}

/// 构造含 2 个未 fold 玩家的 HandState。
#[must_use]
pub fn make_hand_state(bb_addr: Address, last_action_height: BlockHeight) -> HandState {
    HandState {
        phase: GamePhase::Preflop,
        pot: 100,
        current_bet: 20,
        big_blind_amount: 20,
        small_blind_amount: 10,
        raise_count: 0,
        bet_count: 0,
        current_turn: bb_addr,
        players: vec![
            PlayerStack {
                address: bb_addr,
                contributed: 20,
                folded: false,
                is_big_blind: true,
                is_small_blind: false,
                is_button: false,
            },
            PlayerStack {
                address: [0x20; 20],
                contributed: 10,
                folded: false,
                is_big_blind: false,
                is_small_blind: true,
                is_button: true,
            },
        ],
        last_action_height,
        hand_start_height: last_action_height,
    }
}

/// 构造含 hand 的 Game（用于 force_advance / settle 测试）。
#[must_use]
pub fn make_game_with_hand(last_action_height: BlockHeight) -> GameContract {
    let mut game = make_game_with_checkpoint(last_action_height);
    game.current_hand = Some(make_hand_state(make_addr(0x10), last_action_height));
    game
}

// ===== ValidatorSet 辅助 =====

/// 构造 N 个 validator 的 ValidatorSet（全部 Active 状态）。
#[must_use]
pub fn make_validator_set(count: usize) -> ValidatorSet {
    let validators: Vec<ValidatorEntry> = (0..count)
        .map(|i| {
            let mut entry = ValidatorEntry::new(
                dummy_tagged_pubkey(0x10 + i as u8),
                [0u8; 33], // vrf_pubkey 占位
                100_000,   // stake
                0,         // bonding_until_height = 0（已过 bonding 期）
            );
            // 设为 Active
            entry.status = poker_l1::consensus::ValidatorStatus::Active;
            entry
        })
        .collect();
    let mut set = ValidatorSet {
        epoch: 1,
        validators,
        validator_set_hash: [0u8; 32],
        epoch_randomness: [0u8; 32],
        prev_epoch_randomness: [0u8; 32],
        genesis_chain_randomness: [0u8; 32],
    };
    set.validator_set_hash = set.compute_hash();
    set
}

// ===== 签名 tx 构造 =====

/// 构造已签名的 Public tx（用 secp256k1 真实签名）。
pub fn signed_public_tx_secp(
    secret: &secp256k1::SecretKey,
    tagged: &TaggedPubkey,
    nonce: u64,
    chain_id: ChainId,
) -> Transaction {
    let mut tx = make_public_tx(tagged.clone(), nonce, chain_id);
    let signing_hash = tx.signing_hash();
    tx.signature = sign_secp(secret, &signing_hash);
    tx
}

/// 构造已签名的 Public tx（用 ed25519 真实签名）。
pub fn signed_public_tx_ed25519(
    sk: &SigningKey,
    tagged: &TaggedPubkey,
    nonce: u64,
    chain_id: ChainId,
) -> Transaction {
    let mut tx = make_public_tx(tagged.clone(), nonce, chain_id);
    let signing_hash = tx.signing_hash();
    tx.signature = sign_ed25519(sk, &signing_hash);
    tx
}
