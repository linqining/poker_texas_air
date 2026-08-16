//! OfflineState commitment + checkout/checkin tx（Task 21 — SubTask 21.1 / 21.2 / 21.3 / 21.4）。
//!
//! 严格遵循 spec.md L527–553 + L655–669（FROZEN 2026-06-27）：
//! - **SubTask 21.1**：`OfflineState { game_id, version, state_root, participants, nonce, execution_mode }`
//! - **SubTask 21.2**：Checkout tx — 仅当 `execution_mode = OffChain` 时开局后触发
//! - **SubTask 21.3**：Checkin tx — 验证证明，应用 delta，解锁
//! - **SubTask 21.4**：OnChain 模式跳过 checkout
//!
//! ## OfflineState commitment
//!
//! spec.md L547：Game 对象状态被快照为 `OfflineState` commitment 存入链上，
//! owner 标记为 `ChannelOwner`。
//!
//! ## Checkin 流程
//!
//! spec.md L665–669：玩家提交 `(π, Δ, new_commitment, ack_chain)` 作为 checkin 结算交易；
//! 该交易走 Public 通道排序（路由到任意 validator）；链上 verifier 验证 π，
//! 通过后应用 Δ 更新 Game 对象，解锁 checkout 锁定。

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::Hash;
use crate::error::PokerL1Error;
use crate::object_model::ObjectID;
use crate::signature::TaggedPubkey;

use super::ack_chain::AckEntry;
use super::zk_verifier::{ZkVerifierRegistry, ZkVerifyResult};

/// OfflineState commitment 格式（SubTask 21.1）。
///
/// spec.md L527–553：仅 OffChain 模式 Game 对象维护此 commitment。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineState {
    /// Game 对象 ID。
    pub game_id: ObjectID,
    /// 版本号（每次 checkout/checkin 递增）。
    pub version: u64,
    /// 状态根（Sparse Merkle Root）。
    pub state_root: Hash,
    /// 参与者 tagged pubkey 列表（活跃玩家）。
    pub participants: Vec<TaggedPubkey>,
    /// per-game nonce（防重放）。
    pub nonce: u64,
    /// 执行模式（OnChain / OffChain）。
    pub execution_mode: ExecutionMode,
}

/// 执行模式（与 vm::contracts::types::ExecutionMode 一致，但本模块独立定义避免循环依赖）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionMode {
    /// 链上模式：所有步骤直接走链上 GameTurn 通道，无 checkout/checkin（SubTask 21.4）。
    OnChain,
    /// 链下模式：开局后触发 checkout，结算时触发 checkin（SubTask 21.2 / 21.3）。
    OffChain,
}

impl OfflineState {
    /// 计算 commitment = `blake2b_256(game_id || version || state_root || participants || nonce || execution_mode)`。
    pub fn commitment(&self) -> Hash {
        let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32) 初始化不应失败");
        hasher.update(&self.game_id.to_bytes());
        hasher.update(&self.version.to_be_bytes());
        hasher.update(&self.state_root);
        for p in &self.participants {
            hasher.update(&p.to_bytes());
        }
        hasher.update(&self.nonce.to_be_bytes());
        let mode_byte: u8 = match self.execution_mode {
            ExecutionMode::OnChain => 0x00,
            ExecutionMode::OffChain => 0x01,
        };
        hasher.update(&[mode_byte]);
        let mut out = [0u8; 32];
        hasher
            .finalize_variable(&mut out)
            .expect("Blake2bVar finalize 不应失败");
        out
    }

    /// 是否应触发 checkout（SubTask 21.2 + 21.4）。
    ///
    /// 仅当 `execution_mode = OffChain` 时返回 true。
    pub fn should_checkout(&self) -> bool {
        self.execution_mode == ExecutionMode::OffChain
    }
}

/// Checkout tx（SubTask 21.2）。
///
/// 仅当 `execution_mode = OffChain` 时新一手牌开局后触发。
/// Game 对象状态被快照为 OfflineState commitment 存入链上。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckoutTx {
    /// Game 对象 ID。
    pub game_id: ObjectID,
    /// checkout 时的 OfflineState。
    pub state: OfflineState,
}

/// Checkin tx（SubTask 21.3）。
///
/// spec.md L665–669：玩家提交 `(π, Δ, new_commitment, ack_chain)` 作为 checkin 结算交易。
///
/// 完整 checkin tx 签名域（R5-M6 + v1.2 SubTask 11.2.3 BREAKING）：
/// `hash(chain_id || proof_kind || game_id || π_hash || state_delta_hash || new_commitment || ack_chain_hash)`
#[derive(Debug, Clone)]
pub struct CheckinTx {
    /// Game 对象 ID。
    pub game_id: ObjectID,
    /// ZK proof（π）字节。
    pub proof: Vec<u8>,
    /// 状态增量（Δ）。
    pub state_delta: Vec<u8>,
    /// 新 commitment（结算后状态）。
    pub new_commitment: Hash,
    /// ack_chain（所有正常 checkpoint ack 的聚合）。
    pub ack_chain: Vec<AckEntry>,
    /// scheme_id（Hypernova / Groth16 / IPA）。
    pub scheme_id: u32,
    /// proof_kind（v1.2 SubTask 11.2.3 — 与 `scheme_id` 双向映射，作为 1-byte 前缀进入 `signing_hash`）。
    pub proof_kind: super::zk_verifier::ProofKind,
    /// 是否基于 partial_checkin 衔接（SEC2-M8）。
    pub has_partial_checkin: bool,
    /// H-6 修复：折叠步数（由 prover 提供，进入 ZkPublicIo 而非硬编码）。
    pub folded_step_count: u32,
    /// H-6 修复：被跳过的 checkpoint 段数（由 prover 提供）。
    pub skip_count: u32,
    /// H-6 修复：段间连续性证明（由 prover 提供）。
    pub segment_continuity_proof: Vec<u8>,
}

impl CheckinTx {
    /// 计算 state_delta_hash = `blake2b_256(state_delta)`。
    pub fn state_delta_hash(&self) -> Hash {
        let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32) 不应失败");
        hasher.update(&self.state_delta);
        let mut out = [0u8; 32];
        hasher
            .finalize_variable(&mut out)
            .expect("Blake2bVar finalize 不应失败");
        out
    }

    /// 计算 proof_hash = `blake2b_256(proof)`。
    pub fn proof_hash(&self) -> Hash {
        let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32) 不应失败");
        hasher.update(&self.proof);
        let mut out = [0u8; 32];
        hasher
            .finalize_variable(&mut out)
            .expect("Blake2bVar finalize 不应失败");
        out
    }

    /// 计算 ack_chain_hash = `MerkleRoot(ack_chain)`（NEW-M5）。
    pub fn ack_chain_hash(&self) -> Hash {
        super::ack_chain::compute_ack_chain_hash(&self.ack_chain)
    }

    /// 计算 checkin tx 签名域哈希（R5-M6 + v1.2 SubTask 11.2.3 BREAKING）。
    ///
    /// `hash(chain_id || proof_kind || game_id || π_hash || state_delta_hash || new_commitment || ack_chain_hash)`
    ///
    /// `proof_kind` 作为 1-byte 前缀插入 `chain_id` 之后 — **BREAKING**：破坏旧签名，
    /// 升级时所有在途 `CheckinTx` 须在 `PRODUCTION_GRACE_BLOCKS` 内重提交或失效。
    pub fn signing_hash(&self, chain_id: crate::ChainId) -> Hash {
        let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32) 不应失败");
        hasher.update(&chain_id.to_be_bytes());
        hasher.update(&[self.proof_kind.to_byte()]); // v1.2 BREAKING — proof_kind 前缀
        hasher.update(&self.game_id.to_bytes());
        hasher.update(&self.proof_hash());
        hasher.update(&self.state_delta_hash());
        hasher.update(&self.new_commitment);
        hasher.update(&self.ack_chain_hash());
        let mut out = [0u8; 32];
        hasher
            .finalize_variable(&mut out)
            .expect("Blake2bVar finalize 不应失败");
        out
    }
}

/// Partial checkin tx（SubTask 28.7a — π_partial）。
///
/// spec.md L713–717：折叠中断恢复 + NEW-M6/M5 修复。
#[derive(Debug, Clone)]
pub struct PartialCheckinTx {
    /// Game 对象 ID。
    pub game_id: ObjectID,
    /// π_partial 字节。
    pub proof_partial: Vec<u8>,
    /// 已折叠步数 N。
    pub folded_step_count: u32,
    /// 中间状态承诺。
    pub intermediate_commitment: Hash,
    /// 前 N 个 ack 的链。
    pub ack_chain_partial: Vec<AckEntry>,
    /// scheme_id。
    pub scheme_id: u32,
    /// proof_kind（v1.2 SubTask 11.2.6 — 与 `scheme_id` 双向映射，序列化策略与 `CheckinTx` 一致）。
    pub proof_kind: super::zk_verifier::ProofKind,
}

impl PartialCheckinTx {
    /// 计算 π_partial hash。
    pub fn proof_partial_hash(&self) -> Hash {
        let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32) 不应失败");
        hasher.update(&self.proof_partial);
        let mut out = [0u8; 32];
        hasher
            .finalize_variable(&mut out)
            .expect("Blake2bVar finalize 不应失败");
        out
    }

    /// 计算 ack_chain_partial_hash（R5-M5：与 ack_chain_hash 完全相同构造）。
    pub fn ack_chain_partial_hash(&self) -> Hash {
        super::ack_chain::compute_ack_chain_partial_hash(&self.ack_chain_partial)
    }

    /// 计算 partial_checkin tx 签名域哈希（R5-M6 + v1.2 SubTask 11.2.6 BREAKING）。
    ///
    /// `hash(chain_id || proof_kind || game_id || π_partial_hash || folded_step_count || intermediate_commitment || ack_chain_partial_hash)`
    ///
    /// `proof_kind` 作为 1-byte 前缀插入 `chain_id` 之后 — 序列化策略与 `CheckinTx` 一致（**BREAKING**）。
    pub fn signing_hash(&self, chain_id: crate::ChainId) -> Hash {
        let mut hasher = Blake2bVar::new(32).expect("Blake2bVar(32) 不应失败");
        hasher.update(&chain_id.to_be_bytes());
        hasher.update(&[self.proof_kind.to_byte()]); // v1.2 BREAKING — proof_kind 前缀
        hasher.update(&self.game_id.to_bytes());
        hasher.update(&self.proof_partial_hash());
        hasher.update(&self.folded_step_count.to_be_bytes());
        hasher.update(&self.intermediate_commitment);
        hasher.update(&self.ack_chain_partial_hash());
        let mut out = [0u8; 32];
        hasher
            .finalize_variable(&mut out)
            .expect("Blake2bVar finalize 不应失败");
        out
    }
}

/// Last partial fold 记录（SubTask 28.7a — `last_partial_fold`）。
///
/// 链上记录此锚点用于 partial_checkin 与完整 checkin 衔接。
/// 需 `Serialize/Deserialize` 因存储于 `GameContract` 对象内（BCS 序列化）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct LastPartialFold {
    /// 中间状态承诺。
    pub intermediate_commitment: Hash,
    /// 已折叠步数 N。
    pub folded_step_count: u32,
    /// π_partial hash。
    pub proof_partial_hash: Hash,
    /// ack_chain[0..N] 的哈希。
    pub ack_chain_partial_hash: Hash,
}

/// 执行 checkout（SubTask 21.2 + 21.4）。
///
/// - `execution_mode = OnChain` → 跳过 checkout，返回 None
/// - `execution_mode = OffChain` → 计算 commitment，返回 Some(OfflineState)
pub fn execute_checkout(state: &OfflineState) -> Option<Hash> {
    if !state.should_checkout() {
        return None;
    }
    Some(state.commitment())
}

/// 执行 checkin（SubTask 21.3 + v1.2 SubTask 11.2.4/11.2.5）。
///
/// spec.md L665–669：
/// 1. 链上 verifier 验证 π（含 ack_chain_hash + skip_count + segment_continuity_proof 校验）
/// 2. 通过后应用 Δ 更新 Game 对象
/// 3. 解锁 checkout 锁定
///
/// v1.2 SubTask 11.2.4：按 `scheme_id` 分派 verifier；`proof_kind` 与 `scheme_id` 不一致返回 `ProofKindMismatch`。
/// v1.2 SubTask 11.2.5（v1.4 Min3-004 修正）：grace 期签名形式分派由 verifier 内部
/// `verify_with_context` 实现（`SignatureFormMismatch` 兜底）。
///
/// # 参数
/// - `tx`：checkin tx
/// - `registry`：ZK verifier registry
/// - `chain_id`：chain_id
/// - `last_partial_fold`：若 has_partial_checkin=true，须提供
/// - `max_skip_segments`：skip_count 上限（默认 3）
/// - `max_ack_chain_length`：ack_chain 长度上限（默认 1000）
/// - `ctx`：grace period + M2-003/004 所需的链上状态上下文（v1.2 SubTask 11.2.4）
/// - `checkout_commitment`：checkout 时锚定的链上 commitment（H6 修复 — 无 partial fold 时作为 initial_commitment）
#[allow(clippy::too_many_arguments)] // 8 参数均为 spec 要求的安全校验参数
pub fn execute_checkin(
    tx: &CheckinTx,
    registry: &ZkVerifierRegistry,
    chain_id: crate::ChainId,
    last_partial_fold: Option<&LastPartialFold>,
    max_skip_segments: u32,
    max_ack_chain_length: u32,
    ctx: &super::zk_verifier::ZkVerifyContext<'_>,
    checkout_commitment: Hash,
) -> Result<ZkVerifyResult, PokerL1Error> {
    // SEC2-M4：ack_chain 长度校验
    // M-13 修复：在 usize 域比较，避免 64-bit 平台 `as u32` 截断绕过上限检查
    if tx.ack_chain.len() > max_ack_chain_length as usize {
        let actual_u32 = u32::try_from(tx.ack_chain.len()).unwrap_or(u32::MAX);
        return Err(PokerL1Error::AckChainLengthExceeded {
            actual: actual_u32,
            limit: max_ack_chain_length,
        });
    }

    // v1.2 SubTask 11.2.4：proof_kind 与 scheme_id 一致性校验
    let expected_kind =
        super::zk_verifier::ProofKind::from_scheme_id(tx.scheme_id).ok_or_else(|| {
            PokerL1Error::ProofKindMismatch {
                declared: tx.proof_kind.to_byte(),
                actual: tx.scheme_id as u8,
            }
        })?;
    if expected_kind != tx.proof_kind {
        return Err(PokerL1Error::ProofKindMismatch {
            declared: tx.proof_kind.to_byte(),
            actual: tx.scheme_id as u8,
        });
    }

    // 构造 public_io（H-6 修复：使用 tx 提供的实际值而非硬编码）
    let ack_chain_hash = tx.ack_chain_hash();
    let state_delta_hash = tx.state_delta_hash();
    let public_io = super::zk_verifier::ZkPublicIo {
        initial_commitment: last_partial_fold
            .map(|p| p.intermediate_commitment)
            .unwrap_or(checkout_commitment), // H6 修复：无 partial 时使用 checkout commitment
        final_commitment: tx.new_commitment,
        state_delta_hash,
        ack_chain_hash,
        fold_step_count: tx.folded_step_count,
        skip_count: tx.skip_count,
        segment_continuity_proof: tx.segment_continuity_proof.clone(),
    };

    // SEC2-M8：has_partial_checkin 一致性校验
    if tx.has_partial_checkin {
        let p = last_partial_fold.ok_or_else(|| {
            PokerL1Error::PartialCheckinMismatch(
                "has_partial_checkin=true 但 last_partial_fold 不存在".to_string(),
            )
        })?;
        // H4 修复 + NEW-M6：ack_chain[0..N] 哈希校验
        // 须比较 partial hash（前 N 条目的哈希），而非完整 ack_chain hash
        let n = p.folded_step_count as usize;
        if tx.ack_chain.len() < n {
            return Err(PokerL1Error::PartialCheckinMismatch(format!(
                "ack_chain length {} < folded_step_count {}",
                tx.ack_chain.len(),
                n
            )));
        }
        let expected_partial_hash =
            super::ack_chain::compute_ack_chain_partial_hash(&tx.ack_chain[..n]);
        if p.ack_chain_partial_hash != expected_partial_hash {
            return Err(PokerL1Error::PartialCheckinMismatch(
                "ack_chain_partial_hash 不匹配".to_string(),
            ));
        }
    } else if last_partial_fold.is_some() {
        // has_partial_checkin=false 但链上有 last_partial_fold → 拒绝
        return Err(PokerL1Error::PartialCheckinFlagMismatch {
            declared: false,
            actual_state: true,
        });
    }

    // zk_verify（v1.2 SubTask 11.2.4 — 带 grace period 上下文）。Do not expose a
    // boolean result that a caller could forget to check: check-in is a state-unlocking action,
    // so a disabled or rejecting verifier is an execution error.
    let result = registry.zk_verify_with_context(
        chain_id,
        tx.scheme_id,
        &tx.proof,
        &public_io,
        max_skip_segments,
        max_ack_chain_length,
        ctx,
    )?;
    if !result.verified {
        return Err(PokerL1Error::InvalidZkProofFormat(
            "checkin proof verification failed".to_string(),
        ));
    }
    Ok(result)
}

/// 处理 partial_checkin tx（SubTask 28.7a + Phase 8 M2-003 + v1.2 SubTask 11.2.4/11.2.6）。
///
/// 返回更新后的 `LastPartialFold`。
///
/// # 校验
/// - `folded_step_count` 严格大于上一次记录（SEC-H1）
/// - 链上 verifier 验证 π_partial（Stub 状态下仅校验格式）
/// - **v1.3 M2-003**：`last_partial_fold.proof_partial_hash` 链上不可变约束
///   - 首次设置（`proof_partial_hash == None`）允许
///   - 幂等重提交（整个 `PartialCheckinTx` 内容幂等）允许
///   - 覆盖已有值返回 `PartialFoldHashImmutable` 错误
/// - **v1.4 Min3-003**：幂等重提交范围 = 整个 `PartialCheckinTx` 内容幂等
///   （`proof_partial_hash` + `intermediate_commitment` + `ack_chain_partial` 全部相等）
/// - **v1.2 SubTask 11.2.4**：`proof_kind` 与 `scheme_id` 一致性校验（不一致返回 `ProofKindMismatch`）
/// - **v1.2 SubTask 11.2.6**：`proof_kind` 字段进入 `signing_hash`（BREAKING）
///
/// # 参数
/// - `ctx`：grace period + M2-003/004 所需的链上状态上下文（v1.2 SubTask 11.2.4）
#[allow(clippy::too_many_arguments)] // 9 参数均为 spec 要求的安全校验参数
pub fn execute_partial_checkin(
    tx: &PartialCheckinTx,
    registry: &ZkVerifierRegistry,
    chain_id: crate::ChainId,
    last_partial_fold: Option<&LastPartialFold>,
    partial_checkin_count: u32,
    max_partial_checkin_count: u32,
    max_skip_segments: u32,
    max_ack_chain_length: u32,
    ctx: &super::zk_verifier::ZkVerifyContext<'_>,
) -> Result<LastPartialFold, PokerL1Error> {
    // v1.2 SubTask 11.2.4：proof_kind 与 scheme_id 一致性校验（先于其他校验，提前失败）
    let expected_kind =
        super::zk_verifier::ProofKind::from_scheme_id(tx.scheme_id).ok_or_else(|| {
            PokerL1Error::ProofKindMismatch {
                declared: tx.proof_kind.to_byte(),
                actual: tx.scheme_id as u8,
            }
        })?;
    if expected_kind != tx.proof_kind {
        return Err(PokerL1Error::ProofKindMismatch {
            declared: tx.proof_kind.to_byte(),
            actual: tx.scheme_id as u8,
        });
    }

    // SEC-H1：提交次数上限
    if partial_checkin_count >= max_partial_checkin_count {
        return Err(PokerL1Error::PartialCheckinLimitExceeded {
            actual: partial_checkin_count,
            limit: max_partial_checkin_count,
        });
    }

    // v1.3 M2-003 + v1.4 Min3-003：proof_partial_hash 链上不可变 + 幂等重提交范围校验
    // 注：幂等重提交校验须在进度校验之前，因幂等重提交时 folded_step_count 相等
    if let Some(prev) = last_partial_fold {
        let tx_proof_partial_hash = tx.proof_partial_hash();
        if prev.proof_partial_hash == tx_proof_partial_hash {
            // proof_partial_hash 匹配 — 须为整个 PartialCheckinTx 内容幂等（Min3-003）
            if prev.intermediate_commitment == tx.intermediate_commitment
                && prev.ack_chain_partial_hash == tx.ack_chain_partial_hash()
                && prev.folded_step_count == tx.folded_step_count
            {
                // 完全幂等重提交 — 允许，返回链上已存值
                return Ok(prev.clone());
            }
            // proof_partial_hash 匹配但其他字段不一致 — 视为覆盖，拒绝（Min3-003）
        }
        // proof_partial_hash 不匹配或匹配但非幂等 — 均视为覆盖，拒绝（M2-003 + Min3-003）
        // spec：last_partial_fold.proof_partial_hash 一旦写入即冻结，
        // 后续 PartialCheckinTx 不允许覆盖已存的 proof_partial_hash 字段
        return Err(PokerL1Error::PartialFoldHashImmutable);
    }

    // SEC-H1：进度校验（仅首次设置时执行，因 prev 已在上方处理）
    if let Some(prev) = last_partial_fold
        && tx.folded_step_count <= prev.folded_step_count
    {
        return Err(PokerL1Error::NoProgressPartialCheckin {
            new_count: tx.folded_step_count,
            last_recorded: prev.folded_step_count,
        });
    }

    // 构造 public_io（与最终 π 相同的边界格式，fold_step_count = N，final_commitment = intermediate_commitment）
    let public_io = super::zk_verifier::ZkPublicIo {
        initial_commitment: last_partial_fold
            .map(|p| p.intermediate_commitment)
            .unwrap_or(tx.intermediate_commitment),
        final_commitment: tx.intermediate_commitment,
        state_delta_hash: [0u8; 32], // partial_checkin 不应用 Δ
        ack_chain_hash: tx.ack_chain_partial_hash(),
        fold_step_count: tx.folded_step_count,
        skip_count: 0,
        segment_continuity_proof: Vec::new(),
    };

    // zk_verify π_partial（v1.2 SubTask 11.2.4 — 带 grace period 上下文）
    let result = registry.zk_verify_with_context(
        chain_id,
        tx.scheme_id,
        &tx.proof_partial,
        &public_io,
        max_skip_segments,
        max_ack_chain_length,
        ctx,
    )?;

    if !result.verified {
        return Err(PokerL1Error::InvalidZkProofFormat(
            "partial_checkin proof 验证失败".to_string(),
        ));
    }

    // 记录 last_partial_fold（首次设置 proof_partial_hash）
    Ok(LastPartialFold {
        intermediate_commitment: tx.intermediate_commitment,
        folded_step_count: tx.folded_step_count,
        proof_partial_hash: tx.proof_partial_hash(),
        ack_chain_partial_hash: tx.ack_chain_partial_hash(),
    })
}

/// 检查 verifier_status 是否允许 OffChain checkout（NEW-C1）。
///
/// `Stub` 状态在所有网络拒绝 OffChain checkout。
pub fn check_offchain_allowed(
    registry: &ZkVerifierRegistry,
    chain_id: crate::ChainId,
    is_mainnet: bool,
) -> Result<(), PokerL1Error> {
    let status = registry.verifier_status(chain_id);
    if !status.allows_offchain(chain_id, is_mainnet) {
        return Err(PokerL1Error::OffChainDisabledOnMainnet);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::offline::ack_chain::AckEntry;
    use crate::offline::zk_verifier::{
        ProofKind, SCHEME_STWO, SCHEME_ZKSHUFFLE, VerifierStatus, ZkVerifyContext,
        register_groth16_stub_verifier, register_ipa_stub_verifier,
        register_test_only_stwo_stub_verifier, register_zkshuffle_stub_verifier,
    };
    use crate::offline::{DEFAULT_MAX_ACK_CHAIN_LENGTH, DEFAULT_MAX_PARTIAL_CHECKIN_COUNT};

    /// 构造默认 ZkVerifyContext（切换前 + Zkvm 新签名）— 既有 scheme_id=1 测试用。
    fn make_default_ctx() -> ZkVerifyContext<'static> {
        ZkVerifyContext {
            current_height: 0,
            production_switch_height: 0, // 切换前
            grace_blocks: 7200,
            last_partial_proof_hash: None,
            uses_new_signature: true, // Zkvm 期望新签名
        }
    }

    fn make_offline_state(mode: ExecutionMode) -> OfflineState {
        OfflineState {
            game_id: ObjectID::new([0x01; 20], 1),
            version: 1,
            state_root: [0x42; 32],
            participants: vec![TaggedPubkey {
                tag: 0x01,
                raw: vec![0xAA; 33],
            }],
            nonce: 0,
            execution_mode: mode,
        }
    }

    fn make_ack_entry(seq: u64) -> AckEntry {
        AckEntry {
            chain_id: crate::DEFAULT_CHAIN_ID,
            epoch: 1,
            game_id: ObjectID::new([0x01; 20], 1),
            current_turn: [0x02; 20],
            state_hash: [0x42; 32],
            checkpoint_seq: seq,
            participant: TaggedPubkey {
                tag: 0x01,
                raw: vec![0xAA; 33],
            },
            participant_signature: vec![0xBB; 64],
        }
    }

    fn make_registry_with_all_verifiers() -> ZkVerifierRegistry {
        let mut registry = ZkVerifierRegistry::new();
        register_test_only_stwo_stub_verifier(&mut registry);
        register_groth16_stub_verifier(&mut registry);
        register_ipa_stub_verifier(&mut registry);
        registry
    }

    #[test]
    fn test_offline_state_commitment_deterministic() {
        let s1 = make_offline_state(ExecutionMode::OffChain);
        let s2 = make_offline_state(ExecutionMode::OffChain);
        assert_eq!(s1.commitment(), s2.commitment());
    }

    #[test]
    fn test_offline_state_commitment_differs_on_mode() {
        let s_onchain = make_offline_state(ExecutionMode::OnChain);
        let s_offchain = make_offline_state(ExecutionMode::OffChain);
        assert_ne!(s_onchain.commitment(), s_offchain.commitment());
    }

    #[test]
    fn test_offline_state_commitment_differs_on_version() {
        let s1 = make_offline_state(ExecutionMode::OffChain);
        let mut s2 = s1.clone();
        s2.version = 2;
        assert_ne!(s1.commitment(), s2.commitment());
    }

    #[test]
    fn test_should_checkout_offchain() {
        let s = make_offline_state(ExecutionMode::OffChain);
        assert!(s.should_checkout());
    }

    #[test]
    fn test_should_not_checkout_onchain() {
        let s = make_offline_state(ExecutionMode::OnChain);
        assert!(!s.should_checkout());
    }

    #[test]
    fn test_execute_checkout_offchain() {
        let s = make_offline_state(ExecutionMode::OffChain);
        let result = execute_checkout(&s);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), s.commitment());
    }

    #[test]
    fn test_execute_checkout_onchain_skipped() {
        // SubTask 21.4：OnChain 模式跳过 checkout
        let s = make_offline_state(ExecutionMode::OnChain);
        let result = execute_checkout(&s);
        assert!(result.is_none());
    }

    #[test]
    fn test_checkin_tx_signing_hash_deterministic() {
        let tx = CheckinTx {
            game_id: ObjectID::new([0x01; 20], 1),
            proof: vec![0xAA; 64],
            state_delta: vec![0xBB; 32],
            new_commitment: [0xCC; 32],
            ack_chain: vec![make_ack_entry(1)],
            scheme_id: 1,
            proof_kind: ProofKind::Zkvm,
            has_partial_checkin: false,
            folded_step_count: 1,
            skip_count: 0,
            segment_continuity_proof: Vec::new(),
        };

        let h1 = tx.signing_hash(crate::DEFAULT_CHAIN_ID);
        let h2 = tx.signing_hash(crate::DEFAULT_CHAIN_ID);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_checkin_tx_signing_hash_differs_on_proof() {
        let mut tx = CheckinTx {
            game_id: ObjectID::new([0x01; 20], 1),
            proof: vec![0xAA; 64],
            state_delta: vec![0xBB; 32],
            new_commitment: [0xCC; 32],
            ack_chain: vec![make_ack_entry(1)],
            scheme_id: 1,
            proof_kind: ProofKind::Zkvm,
            has_partial_checkin: false,
            folded_step_count: 1,
            skip_count: 0,
            segment_continuity_proof: Vec::new(),
        };

        let h1 = tx.signing_hash(crate::DEFAULT_CHAIN_ID);
        tx.proof[0] ^= 0xFF;
        let h2 = tx.signing_hash(crate::DEFAULT_CHAIN_ID);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_checkin_ack_chain_hash_matches_ack_chain_module() {
        let ack_chain = vec![make_ack_entry(1), make_ack_entry(2)];
        let tx = CheckinTx {
            game_id: ObjectID::new([0x01; 20], 1),
            proof: vec![0xAA; 64],
            state_delta: vec![0xBB; 32],
            new_commitment: [0xCC; 32],
            ack_chain: ack_chain.clone(),
            scheme_id: 1,
            proof_kind: ProofKind::Zkvm,
            has_partial_checkin: false,
            folded_step_count: 1,
            skip_count: 0,
            segment_continuity_proof: Vec::new(),
        };

        let expected = super::super::ack_chain::compute_ack_chain_hash(&ack_chain);
        assert_eq!(tx.ack_chain_hash(), expected);
    }

    #[test]
    fn test_execute_checkin_offchain_disabled_on_mainnet_stub() {
        // NEW-C1：Stub + mainnet → 拒绝
        let registry = make_registry_with_all_verifiers();
        let result = check_offchain_allowed(&registry, crate::DEFAULT_CHAIN_ID, true);
        assert!(matches!(
            result,
            Err(PokerL1Error::OffChainDisabledOnMainnet)
        ));
    }

    #[test]
    fn test_execute_checkin_offchain_disabled_on_testnet_stub() {
        // Stub is disabled on every network; testnet no longer treats format checks as proofs.
        let registry = make_registry_with_all_verifiers();
        let result = check_offchain_allowed(&registry, crate::DEFAULT_CHAIN_ID, false);
        assert!(matches!(
            result,
            Err(PokerL1Error::OffChainDisabledOnMainnet)
        ));
    }

    #[test]
    fn test_execute_checkin_offchain_allowed_on_mainnet_production() {
        // NEW-C1：Production + mainnet → 允许
        let mut registry = make_registry_with_all_verifiers();
        registry.set_verifier_status(crate::DEFAULT_CHAIN_ID, VerifierStatus::Production);
        let result = check_offchain_allowed(&registry, crate::DEFAULT_CHAIN_ID, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_execute_checkin_success_requires_production_status() {
        let registry = make_registry_with_all_verifiers();
        registry.set_verifier_status(crate::DEFAULT_CHAIN_ID, VerifierStatus::Production);
        let tx = CheckinTx {
            game_id: ObjectID::new([0x01; 20], 1),
            proof: vec![0xAA; 64],
            state_delta: vec![0xBB; 32],
            new_commitment: [0xCC; 32],
            ack_chain: vec![make_ack_entry(1)],
            scheme_id: 1, // Hypernova
            proof_kind: ProofKind::Zkvm,
            has_partial_checkin: false,
            folded_step_count: 1,
            skip_count: 0,
            segment_continuity_proof: Vec::new(),
        };

        let result = execute_checkin(
            &tx,
            &registry,
            crate::DEFAULT_CHAIN_ID,
            None,
            3,
            DEFAULT_MAX_ACK_CHAIN_LENGTH,
            &make_default_ctx(),
            [0xDD; 32], // H6: checkout_commitment ≠ new_commitment
        )
        .expect("checkin 应成功");

        assert!(result.verified);
        assert_eq!(result.verifier_status, VerifierStatus::Production);
    }

    #[test]
    fn test_execute_checkin_ack_chain_too_long() {
        let registry = make_registry_with_all_verifiers();
        let ack_chain: Vec<AckEntry> = (0..1001).map(make_ack_entry).collect();
        let tx = CheckinTx {
            game_id: ObjectID::new([0x01; 20], 1),
            proof: vec![0xAA; 64],
            state_delta: vec![0xBB; 32],
            new_commitment: [0xCC; 32],
            ack_chain,
            scheme_id: 1,
            proof_kind: ProofKind::Zkvm,
            has_partial_checkin: false,
            folded_step_count: 1,
            skip_count: 0,
            segment_continuity_proof: Vec::new(),
        };

        let result = execute_checkin(
            &tx,
            &registry,
            crate::DEFAULT_CHAIN_ID,
            None,
            3,
            DEFAULT_MAX_ACK_CHAIN_LENGTH,
            &make_default_ctx(),
            [0xDD; 32], // H6: checkout_commitment
        );
        assert!(matches!(
            result,
            Err(PokerL1Error::AckChainLengthExceeded { .. })
        ));
    }

    #[test]
    fn test_execute_checkin_has_partial_but_no_last_partial_fold() {
        let registry = make_registry_with_all_verifiers();
        let tx = CheckinTx {
            game_id: ObjectID::new([0x01; 20], 1),
            proof: vec![0xAA; 64],
            state_delta: vec![0xBB; 32],
            new_commitment: [0xCC; 32],
            ack_chain: vec![make_ack_entry(1)],
            scheme_id: 1,
            proof_kind: ProofKind::Zkvm,
            has_partial_checkin: true,
            folded_step_count: 1,
            skip_count: 0,
            segment_continuity_proof: Vec::new(),
        };

        let result = execute_checkin(
            &tx,
            &registry,
            crate::DEFAULT_CHAIN_ID,
            None,
            3,
            DEFAULT_MAX_ACK_CHAIN_LENGTH,
            &make_default_ctx(),
            [0xDD; 32], // H6: checkout_commitment
        );
        assert!(matches!(
            result,
            Err(PokerL1Error::PartialCheckinMismatch(_))
        ));
    }

    #[test]
    fn test_execute_checkin_no_partial_but_has_last_partial_fold() {
        let registry = make_registry_with_all_verifiers();
        let tx = CheckinTx {
            game_id: ObjectID::new([0x01; 20], 1),
            proof: vec![0xAA; 64],
            state_delta: vec![0xBB; 32],
            new_commitment: [0xCC; 32],
            ack_chain: vec![make_ack_entry(1)],
            scheme_id: 1,
            proof_kind: ProofKind::Zkvm,
            has_partial_checkin: false,
            folded_step_count: 1,
            skip_count: 0,
            segment_continuity_proof: Vec::new(),
        };

        let last_partial_fold = LastPartialFold {
            intermediate_commitment: [0xDD; 32],
            folded_step_count: 5,
            proof_partial_hash: [0xEE; 32],
            ack_chain_partial_hash: [0xFF; 32],
        };

        let result = execute_checkin(
            &tx,
            &registry,
            crate::DEFAULT_CHAIN_ID,
            Some(&last_partial_fold),
            3,
            DEFAULT_MAX_ACK_CHAIN_LENGTH,
            &make_default_ctx(),
            [0xDD; 32], // H6: checkout_commitment（有 partial fold 时不使用）
        );
        assert!(matches!(
            result,
            Err(PokerL1Error::PartialCheckinFlagMismatch { .. })
        ));
    }

    #[test]
    fn test_partial_checkin_tx_signing_hash_deterministic() {
        let tx = PartialCheckinTx {
            game_id: ObjectID::new([0x01; 20], 1),
            proof_partial: vec![0xAA; 64],
            folded_step_count: 5,
            intermediate_commitment: [0xBB; 32],
            ack_chain_partial: vec![make_ack_entry(1)],
            scheme_id: 1,
            proof_kind: ProofKind::Zkvm,
        };

        let h1 = tx.signing_hash(crate::DEFAULT_CHAIN_ID);
        let h2 = tx.signing_hash(crate::DEFAULT_CHAIN_ID);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_execute_partial_checkin_success() {
        let registry = make_registry_with_all_verifiers();
        registry.set_verifier_status(crate::DEFAULT_CHAIN_ID, VerifierStatus::Production);
        let tx = PartialCheckinTx {
            game_id: ObjectID::new([0x01; 20], 1),
            proof_partial: vec![0xAA; 64],
            folded_step_count: 5,
            intermediate_commitment: [0xBB; 32],
            ack_chain_partial: vec![make_ack_entry(1)],
            scheme_id: 1,
            proof_kind: ProofKind::Zkvm,
        };

        let result = execute_partial_checkin(
            &tx,
            &registry,
            crate::DEFAULT_CHAIN_ID,
            None,
            0,
            DEFAULT_MAX_PARTIAL_CHECKIN_COUNT,
            3,
            DEFAULT_MAX_ACK_CHAIN_LENGTH,
            &make_default_ctx(),
        )
        .expect("partial_checkin 应成功");

        assert_eq!(result.folded_step_count, 5);
        assert_eq!(result.intermediate_commitment, [0xBB; 32]);
        assert_eq!(result.ack_chain_partial_hash, tx.ack_chain_partial_hash());
    }

    #[test]
    fn test_execute_partial_checkin_no_progress() {
        // Phase 8 M2-003 修正：proof_partial_hash 不匹配时优先返回 PartialFoldHashImmutable
        // （M2-003 不可变约束比 SEC-H1 进度校验更严格）
        let registry = make_registry_with_all_verifiers();
        let last = LastPartialFold {
            intermediate_commitment: [0xBB; 32],
            folded_step_count: 5,
            proof_partial_hash: [0xAA; 32],
            ack_chain_partial_hash: [0xCC; 32],
        };
        let tx = PartialCheckinTx {
            game_id: ObjectID::new([0x01; 20], 1),
            proof_partial: vec![0xAA; 64], // hash 不匹配 [0xAA; 32]
            folded_step_count: 5,          // 不大于上一次
            intermediate_commitment: [0xBB; 32],
            ack_chain_partial: vec![make_ack_entry(1)],
            scheme_id: 1,
            proof_kind: ProofKind::Zkvm,
        };

        let result = execute_partial_checkin(
            &tx,
            &registry,
            crate::DEFAULT_CHAIN_ID,
            Some(&last),
            1,
            DEFAULT_MAX_PARTIAL_CHECKIN_COUNT,
            3,
            DEFAULT_MAX_ACK_CHAIN_LENGTH,
            &make_default_ctx(),
        );
        // M2-003：proof_partial_hash 不匹配 → PartialFoldHashImmutable（优先于 NoProgressPartialCheckin）
        assert!(matches!(
            result,
            Err(PokerL1Error::PartialFoldHashImmutable)
        ));
    }

    #[test]
    fn test_execute_partial_checkin_limit_exceeded() {
        let registry = make_registry_with_all_verifiers();
        let tx = PartialCheckinTx {
            game_id: ObjectID::new([0x01; 20], 1),
            proof_partial: vec![0xAA; 64],
            folded_step_count: 5,
            intermediate_commitment: [0xBB; 32],
            ack_chain_partial: vec![make_ack_entry(1)],
            scheme_id: 1,
            proof_kind: ProofKind::Zkvm,
        };

        let result = execute_partial_checkin(
            &tx,
            &registry,
            crate::DEFAULT_CHAIN_ID,
            None,
            DEFAULT_MAX_PARTIAL_CHECKIN_COUNT, // 已达上限
            DEFAULT_MAX_PARTIAL_CHECKIN_COUNT,
            3,
            DEFAULT_MAX_ACK_CHAIN_LENGTH,
            &make_default_ctx(),
        );
        assert!(matches!(
            result,
            Err(PokerL1Error::PartialCheckinLimitExceeded { .. })
        ));
    }

    // ===== SubTask 11.2.7：proof_kind 一致性集成测试 =====

    /// SubTask 11.2.7：scheme_id=1 + proof_kind=Zkvm + 合法 proof → 通过。
    ///
    /// 验证 `execute_checkin` 在 proof_kind 与 scheme_id 一致且 verifier 已启用时分派成功。
    #[test]
    fn test_execute_checkin_zkvm_proof_kind_consistency() {
        let registry = make_registry_with_all_verifiers();
        registry.set_verifier_status(crate::DEFAULT_CHAIN_ID, VerifierStatus::Production);
        let tx = CheckinTx {
            game_id: ObjectID::new([0x01; 20], 1),
            proof: vec![0xAA; 64],
            state_delta: vec![0xBB; 32],
            new_commitment: [0xCC; 32],
            ack_chain: vec![make_ack_entry(1)],
            scheme_id: SCHEME_STWO,
            proof_kind: ProofKind::Zkvm,
            has_partial_checkin: false,
            folded_step_count: 1,
            skip_count: 0,
            segment_continuity_proof: Vec::new(),
        };

        let result = execute_checkin(
            &tx,
            &registry,
            crate::DEFAULT_CHAIN_ID,
            None,
            3,
            DEFAULT_MAX_ACK_CHAIN_LENGTH,
            &make_default_ctx(),
            [0xDD; 32], // H6: checkout_commitment ≠ new_commitment
        )
        .expect("scheme_id=1 + proof_kind=Zkvm 一致时应成功");

        assert!(
            result.verified,
            "Production test verifier should accept the fixture"
        );
        assert_eq!(result.scheme_id, SCHEME_STWO);
        assert_eq!(result.verifier_status, VerifierStatus::Production);
    }

    /// Legacy ZkShuffle remains fail closed during the former grace period while status is Stub.
    #[test]
    fn test_execute_checkin_zkshuffle_proof_kind_consistency() {
        let mut registry = make_registry_with_all_verifiers();
        register_zkshuffle_stub_verifier(&mut registry);

        let tx = CheckinTx {
            game_id: ObjectID::new([0x01; 20], 1),
            proof: vec![0xAA; 64],
            state_delta: vec![0xBB; 32],
            new_commitment: [0xCC; 32],
            ack_chain: vec![make_ack_entry(1)],
            scheme_id: SCHEME_ZKSHUFFLE,
            proof_kind: ProofKind::ZkShuffle,
            has_partial_checkin: false,
            folded_step_count: 1,
            skip_count: 0,
            segment_continuity_proof: Vec::new(),
        };

        // grace 期 ctx：uses_new_signature=false（ZkShuffle 旧签名），
        // last_partial_proof_hash 须匹配 tx.proof_hash()（M2-003）
        let proof_hash = tx.proof_hash();
        let ctx = ZkVerifyContext {
            current_height: 100,
            production_switch_height: 100,
            grace_blocks: 7200,
            last_partial_proof_hash: Some(&proof_hash),
            uses_new_signature: false,
        };

        let result = execute_checkin(
            &tx,
            &registry,
            crate::DEFAULT_CHAIN_ID,
            None,
            3,
            DEFAULT_MAX_ACK_CHAIN_LENGTH,
            &ctx,
            [0xDD; 32], // H6: checkout_commitment ≠ new_commitment
        );

        assert!(matches!(result, Err(PokerL1Error::InvalidZkProofFormat(_))));
    }

    // ===== SubTask 11.2.8：proof_kind 健壮性负测试 =====

    /// SubTask 11.2.8：scheme_id=1 + proof_kind=ZkShuffle → ProofKindMismatch。
    ///
    /// 验证 `execute_checkin` 在 proof_kind 与 scheme_id 不一致时拒绝执行，
    /// 防止攻击者通过操纵 proof_kind 字段绕过签名形式校验（M2-004）。
    #[test]
    fn test_execute_checkin_proof_kind_mismatch() {
        let registry = make_registry_with_all_verifiers();
        let tx = CheckinTx {
            game_id: ObjectID::new([0x01; 20], 1),
            proof: vec![0xAA; 64],
            state_delta: vec![0xBB; 32],
            new_commitment: [0xCC; 32],
            ack_chain: vec![make_ack_entry(1)],
            scheme_id: SCHEME_STWO,
            proof_kind: ProofKind::ZkShuffle,
            has_partial_checkin: false,
            folded_step_count: 1,
            skip_count: 0,
            segment_continuity_proof: Vec::new(),
        };

        let result = execute_checkin(
            &tx,
            &registry,
            crate::DEFAULT_CHAIN_ID,
            None,
            3,
            DEFAULT_MAX_ACK_CHAIN_LENGTH,
            &make_default_ctx(),
            [0xDD; 32], // H6: checkout_commitment
        );

        assert!(
            matches!(result, Err(PokerL1Error::ProofKindMismatch { .. })),
            "scheme_id=1 + proof_kind=ZkShuffle 不一致应返回 ProofKindMismatch"
        );
    }

    /// SubTask 11.2.8：scheme_id=99（未知）→ ProofKindMismatch。
    ///
    /// 验证 `execute_checkin` 在 scheme_id 无法映射到任何 ProofKind 时拒绝执行，
    /// 防止未知 scheme_id 绕过 proof_kind 一致性校验。
    #[test]
    fn test_execute_checkin_unknown_scheme_id() {
        let registry = make_registry_with_all_verifiers();
        let tx = CheckinTx {
            game_id: ObjectID::new([0x01; 20], 1),
            proof: vec![0xAA; 64],
            state_delta: vec![0xBB; 32],
            new_commitment: [0xCC; 32],
            ack_chain: vec![make_ack_entry(1)],
            scheme_id: 99,
            proof_kind: ProofKind::Zkvm,
            has_partial_checkin: false,
            folded_step_count: 1,
            skip_count: 0,
            segment_continuity_proof: Vec::new(),
        };

        let result = execute_checkin(
            &tx,
            &registry,
            crate::DEFAULT_CHAIN_ID,
            None,
            3,
            DEFAULT_MAX_ACK_CHAIN_LENGTH,
            &make_default_ctx(),
            [0xDD; 32], // H6: checkout_commitment
        );

        assert!(
            matches!(result, Err(PokerL1Error::ProofKindMismatch { .. })),
            "未知 scheme_id=99 应返回 ProofKindMismatch"
        );
    }

    /// SubTask 11.2.8：proof_kind 作为 1-byte 前缀进入 `signing_hash` — 同一 tx
    /// 仅 proof_kind 不同 → signing_hash 不同。
    ///
    /// 验证 v1.2 BREAKING 变更：proof_kind 前缀确实影响了签名域哈希，
    /// 防止旧签名被复用到不同 proof_kind 的 tx 上（签名域隔离）。
    #[test]
    fn test_checkin_tx_signing_hash_includes_proof_kind() {
        let base_tx = CheckinTx {
            game_id: ObjectID::new([0x01; 20], 1),
            proof: vec![0xAA; 64],
            state_delta: vec![0xBB; 32],
            new_commitment: [0xCC; 32],
            ack_chain: vec![make_ack_entry(1)],
            scheme_id: SCHEME_STWO,
            proof_kind: ProofKind::Zkvm,
            has_partial_checkin: false,
            folded_step_count: 1,
            skip_count: 0,
            segment_continuity_proof: Vec::new(),
        };

        let hash_zkvm = base_tx.signing_hash(crate::DEFAULT_CHAIN_ID);

        let mut zkshuffle_tx = base_tx;
        zkshuffle_tx.proof_kind = ProofKind::ZkShuffle;
        let hash_zkshuffle = zkshuffle_tx.signing_hash(crate::DEFAULT_CHAIN_ID);

        assert_ne!(
            hash_zkvm, hash_zkshuffle,
            "不同 proof_kind 应产生不同 signing_hash（proof_kind 作为 1-byte 前缀）"
        );
    }
}
