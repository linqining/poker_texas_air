//! ZK Verifier trait 与热插拔注册表（Task 22 — SubTask 22.1 / 22.2 + NEW-C1）。
//!
//! 严格遵循 spec.md L493–525 + L853–857（FROZEN 2026-06-27）：
//! - **ZkVerifier trait**：统一接口，支持 Hypernova / Groth16 / IPA 三种 scheme
//! - **ZkVerifierRegistry**：热插拔注册表，节点升级新增 verifier 无需重编译已部署合约
//! - **verifier_status 治理开关**（NEW-C1）：per-`chain_id`，`Stub` → `Production` 须治理 90% quorum + `parameter_delay_blocks` timelock
//! - **zk_verify(scheme_id, proof, public_io) -> bool** 通用 syscall 入口

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use crate::Hash;
use crate::error::PokerL1Error;

/// ZK 证明 scheme 标识符（u32，与 syscall 接口一致）。
pub type SchemeId = u32;

/// Stwo scheme_id（v2 Stwo Circle-STARK 递归证明；历史名 Hypernova，已废弃）。
pub const SCHEME_STWO: SchemeId = 1;
/// VM `zk_verify` 可接收的最大 proof/envelope 字节数。
///
/// Texas recursive STWO 的真实 E2E 会断言当前 envelope 不超过该共识边界。
pub const MAX_ZK_PROOF_BYTES: usize = 256 * 1024;
/// Groth16 scheme_id（spec.md L505）。
pub const SCHEME_GROTH16: SchemeId = 2;
/// IPA scheme_id（spec.md L511）。
pub const SCHEME_IPA: SchemeId = 3;
/// ZkShuffle scheme_id（v1.2 spec.md L766 — `ProofKind::ZkShuffle → SCHEME_ZKSHUFFLE`）。
///
/// grace 期后 `scheme_id=4` 走既有 ZkShuffle Production verifier（非 stub）。
pub const SCHEME_ZKSHUFFLE: SchemeId = 4;

/// Proof kind（v1.2 spec.md L765-767 — 与 `scheme_id` 双向映射）。
///
/// M2-004 修复：单个 CheckinTx 同一时刻仅有一种合法签名形式（由 `scheme_id` 决定）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofKind {
    /// ZkShuffle 旧 proof（对应 `SCHEME_ZKSHUFFLE = 4`）。
    ///
    /// grace 期内走 stub 路径，签名形式为旧签名（无 `proof_kind` 字段）。
    ZkShuffle,
    /// Zkvm 新 proof（对应 `SCHEME_STWO = 1`）。
    ///
    /// 强制走 Production 路径，签名形式为新签名（含 `proof_kind` 字段）。
    Zkvm,
}

impl ProofKind {
    /// 由 `scheme_id` 反推期望的 `ProofKind`（spec.md L768）。
    ///
    /// v2 已使用 Stwo 替代 Hypernova，但保持向后兼容。
    #[must_use]
    pub const fn from_scheme_id(scheme_id: SchemeId) -> Option<Self> {
        match scheme_id {
            SCHEME_ZKSHUFFLE => Some(Self::ZkShuffle),
            SCHEME_STWO => Some(Self::Zkvm),
            _ => None,
        }
    }

    /// 是否为新签名形式（含 `proof_kind` 字段）— M2-004。
    ///
    /// - `ZkShuffle` → 旧签名（无 `proof_kind` 字段）
    /// - `Zkvm` → 新签名（含 `proof_kind` 字段，使用 Stwo 递归证明）
    #[must_use]
    pub const fn expects_new_signature(self) -> bool {
        matches!(self, Self::Zkvm)
    }

    /// 转为 1-byte 表示（用于 `signing_hash` 序列化，SubTask 11.2.3）。
    ///
    /// - `ZkShuffle` → 4（`SCHEME_ZKSHUFFLE`）
    /// - `Zkvm` → 1（`SCHEME_STWO`）
    #[must_use]
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::ZkShuffle => SCHEME_ZKSHUFFLE as u8,
            Self::Zkvm => SCHEME_STWO as u8,
        }
    }
}

/// ZK 验证上下文（Phase 8 — v1.2 双通道 grace period + M2-003/004 所需的链上状态）。
///
/// `HypernovaVerifier::verify_with_context` 接收此上下文以实现：
/// - **grace period 双通道**：根据 `production_switch_height` + `current_height` 判定是否在 grace 期内
/// - **M2-003**：`last_partial_fold.proof_partial_hash` 链上不可变校验
/// - **M2-004**：签名形式与 `scheme_id` 一致性校验
#[derive(Debug, Clone, Default)]
pub struct ZkVerifyContext<'a> {
    /// 当前 block height（用于判定 grace 期是否结束）。
    pub current_height: u64,
    /// `production_switch_height`（治理切换时写入；0 表示尚未切换）。
    pub production_switch_height: u64,
    /// `PRODUCTION_GRACE_BLOCKS` 常量（默认 7200；测试可覆盖）。
    pub grace_blocks: u64,
    /// 链上已存的 `last_partial_fold.proof_partial_hash`（M2-003 校验用）。
    ///
    /// `None` 表示尚未写入；`Some(hash)` 表示已写入且不可变。
    /// grace 期内 `proof_kind = ZkShuffle` 的 stub 路径要求 `proof_hash` 匹配此值。
    pub last_partial_proof_hash: Option<&'a crate::Hash>,
    /// 是否使用新签名形式（含 `proof_kind` 字段）— M2-004。
    ///
    /// 由调用方根据 CheckinTx 签名结构判定后传入。
    pub uses_new_signature: bool,
}

impl<'a> ZkVerifyContext<'a> {
    /// 是否处于 grace 期内（`production_switch_height > 0` 且
    /// `current_height <= production_switch_height + grace_blocks`）。
    #[must_use]
    pub const fn in_grace_period(&self) -> bool {
        self.production_switch_height > 0
            && self.current_height
                <= self
                    .production_switch_height
                    .saturating_add(self.grace_blocks)
    }

    /// grace 期是否已结束（`production_switch_height > 0` 且
    /// `current_height > production_switch_height + grace_blocks`）。
    #[must_use]
    pub const fn grace_period_ended(&self) -> bool {
        self.production_switch_height > 0
            && self.current_height
                > self
                    .production_switch_height
                    .saturating_add(self.grace_blocks)
    }
}

/// Verifier 状态（NEW-C1，spec.md L853–857）。
///
/// - `Stub`：验证器尚未启用，所有 proof 均 fail closed
/// - `Production`：完整验证
///
/// 升级须治理 90% quorum + `parameter_delay_blocks` timelock 双重保护。
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
)]
pub enum VerifierStatus {
    /// Stub 状态：验证器未启用，任何网络均不得据此接受 proof 或进入 OffChain。
    Stub,
    /// Production 状态：完整 ZK 验证。
    Production,
}

impl VerifierStatus {
    /// 是否允许 OffChain checkout（NEW-C1）。
    ///
    /// `Stub` 状态在所有网络拒绝 OffChain checkout。测试必须显式安装真实 verifier
    /// 并切换到 `Production`，不能再把格式校验当作密码学验证。
    pub fn allows_offchain(self, chain_id: crate::ChainId, is_mainnet: bool) -> bool {
        let _ = (chain_id, is_mainnet);
        matches!(self, Self::Production)
    }
}

/// ZK 证明的 public_io 边界（O15 修复 — spec.md L521–525）。
///
/// 所有 ZK scheme 的最终 π 都须包含此边界。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZkPublicIo {
    /// 折叠起点状态承诺。
    pub initial_commitment: Hash,
    /// 折叠终点状态承诺（== checkin tx 的 new_commitment）。
    pub final_commitment: Hash,
    /// 状态增量哈希（用于 challenge_delta 比对，NEW-H4：不可逆）。
    pub state_delta_hash: Hash,
    /// 所有 checkpoint ack 的聚合哈希（MerkleRoot，仅正常 checkpoint 聚合）。
    pub ack_chain_hash: Hash,
    /// 折叠步数，上限 1000（O15）。
    pub fold_step_count: u32,
    /// 被跳过的 checkpoint 段数（默认上限 3，SubTask 27.11）。
    pub skip_count: u32,
    /// 段间连续性证明（R5-H6：verify_segment_chain 校验）。
    pub segment_continuity_proof: Vec<u8>,
}

impl ZkPublicIo {
    /// 校验 public_io 边界完整性（O15 + SEC2-M4 + SubTask 27.11）。
    ///
    /// - `fold_step_count <= 1000`（O15）
    /// - `skip_count <= max_skip_segments`（默认 3）
    /// - `ack_chain_length <= max_ack_chain_length`（默认 1000，由调用方传入或使用默认值）
    pub const fn validate(
        &self,
        max_skip_segments: u32,
        max_ack_chain_length: u32,
    ) -> Result<(), PokerL1Error> {
        use crate::offline::MAX_FOLD_STEP_COUNT;

        if self.fold_step_count > MAX_FOLD_STEP_COUNT {
            return Err(PokerL1Error::FoldStepCountExceeded {
                actual: self.fold_step_count,
                limit: MAX_FOLD_STEP_COUNT,
            });
        }
        if self.skip_count > max_skip_segments {
            return Err(PokerL1Error::SkipCountExceeded {
                actual: self.skip_count,
                limit: max_skip_segments,
            });
        }
        let _ = max_ack_chain_length; // ack_chain_length 由 ack_chain 模块自行校验
        Ok(())
    }

    /// 序列化为字节（用于 proof hash 计算 + syscall 传输）。
    ///
    /// 布局：
    /// ```text
    /// | 偏移 | 长度 | 字段                       |
    /// |------|------|----------------------------|
    /// | 0    | 32   | initial_commitment         |
    /// | 32   | 32   | final_commitment           |
    /// | 64   | 32   | state_delta_hash           |
    /// | 96   | 32   | ack_chain_hash             |
    /// | 128  | 4    | fold_step_count (BE u32)   |
    /// | 132  | 4    | skip_count (BE u32)        |
    /// | 136  | 变长 | segment_continuity_proof   |
    /// ```
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 * 4 + 4 + 4 + self.segment_continuity_proof.len());
        out.extend_from_slice(&self.initial_commitment);
        out.extend_from_slice(&self.final_commitment);
        out.extend_from_slice(&self.state_delta_hash);
        out.extend_from_slice(&self.ack_chain_hash);
        out.extend_from_slice(&self.fold_step_count.to_be_bytes());
        out.extend_from_slice(&self.skip_count.to_be_bytes());
        out.extend_from_slice(&self.segment_continuity_proof);
        out
    }

    /// 最小字节数（不含变长 `segment_continuity_proof`）。
    pub const MIN_BYTES: usize = 32 * 4 + 4 + 4;

    /// 从字节反序列化（[`to_bytes`] 的逆操作）。
    ///
    /// 返回 `None` 当输入长度不足或字段非法。
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < Self::MIN_BYTES {
            return None;
        }
        let mut initial_commitment = [0u8; 32];
        initial_commitment.copy_from_slice(&bytes[..32]);
        let mut final_commitment = [0u8; 32];
        final_commitment.copy_from_slice(&bytes[32..64]);
        let mut state_delta_hash = [0u8; 32];
        state_delta_hash.copy_from_slice(&bytes[64..96]);
        let mut ack_chain_hash = [0u8; 32];
        ack_chain_hash.copy_from_slice(&bytes[96..128]);
        let fold_step_count = u32::from_be_bytes([bytes[128], bytes[129], bytes[130], bytes[131]]);
        let skip_count = u32::from_be_bytes([bytes[132], bytes[133], bytes[134], bytes[135]]);
        let segment_continuity_proof = bytes[136..].to_vec();
        Some(Self {
            initial_commitment,
            final_commitment,
            state_delta_hash,
            ack_chain_hash,
            fold_step_count,
            skip_count,
            segment_continuity_proof,
        })
    }
}

/// ZK 证明验证结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZkVerifyResult {
    /// 是否验证通过。
    pub verified: bool,
    /// Verifier 状态（Stub / Production）。
    pub verifier_status: VerifierStatus,
    /// scheme_id。
    pub scheme_id: SchemeId,
}

/// ZK Verifier trait — 统一接口（SubTask 22.1）。
///
/// 每个 scheme（Hypernova / Groth16 / IPA）实现此 trait，
/// 注册到 [`ZkVerifierRegistry`] 后即可通过 `zk_verify` syscall 调用。
pub trait ZkVerifier: Send + Sync {
    /// scheme_id（SCHEME_STWO / SCHEME_GROTH16 / SCHEME_IPA）。
    fn scheme_id(&self) -> SchemeId;

    /// 验证 ZK proof。
    ///
    /// # 参数
    /// - `proof`：proof 字节
    /// - `public_io`：public_io 边界
    /// - `status`：当前 verifier 状态（Stub 必须 fail closed）
    ///
    /// # 返回
    /// `true` 当且仅当 Production verifier 完整验证 proof 合法。
    fn verify(
        &self,
        proof: &[u8],
        public_io: &ZkPublicIo,
        status: VerifierStatus,
    ) -> Result<bool, PokerL1Error>;

    /// 带 grace period 上下文的验证（Phase 8 SubTask 8.2.3-8.2.7）。
    ///
    /// 默认实现委托到 [`verify`](Self::verify)，不参与 grace period 双通道。
    /// Hypernova verifier 覆写此方法以实现：
    /// - grace 期内 `proof_kind = ZkShuffle` 旧 proof 走 stub 路径（须匹配 `proof_partial_hash`）
    /// - grace 期内 `proof_kind = Zkvm` 新 proof 强制 Production 路径
    /// - grace 期结束后所有 proof 强制 Production 路径
    /// - M2-004 签名形式与 `scheme_id` 一致性校验
    ///
    /// # 参数
    /// - `ctx`：grace period + M2-003/004 所需的链上状态上下文
    fn verify_with_context(
        &self,
        proof: &[u8],
        public_io: &ZkPublicIo,
        status: VerifierStatus,
        ctx: &ZkVerifyContext<'_>,
    ) -> Result<bool, PokerL1Error> {
        let _ = ctx;
        self.verify(proof, public_io, status)
    }

    /// 校验 proof 格式（不实际验证）。
    ///
    /// Stub 状态下仅调用此方法。
    fn validate_proof_format(&self, proof: &[u8]) -> Result<(), PokerL1Error>;
}

/// ZK Verifier 热插拔注册表（SubTask 22.1）。
///
/// 节点升级新增 verifier 时，只需实现 [`ZkVerifier`] trait 并注册到此 registry，
/// 无需重新编译已部署合约（spec.md L515–519）。
#[derive(Clone, Default)]
pub struct ZkVerifierRegistry {
    /// scheme_id → verifier 实例。
    verifiers: BTreeMap<SchemeId, Arc<dyn ZkVerifier>>,
    /// per-chain_id verifier_status（NEW-C1）。
    statuses: Arc<RwLock<BTreeMap<crate::ChainId, VerifierStatus>>>,
}

/// Stub verifier — 仅供 crate 内测试构造边界场景。
///
/// 生产代码必须由 Texas 自有电路注册经过审计的 verifier；此类型不能进入生产构建。
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct StubVerifier {
    scheme_id: SchemeId,
}

#[cfg(test)]
impl StubVerifier {
    #[must_use]
    pub const fn new(scheme_id: SchemeId) -> Self {
        Self { scheme_id }
    }
}

#[cfg(test)]
impl ZkVerifier for StubVerifier {
    fn scheme_id(&self) -> SchemeId {
        self.scheme_id
    }

    fn verify(
        &self,
        proof: &[u8],
        _public_io: &ZkPublicIo,
        _status: VerifierStatus,
    ) -> Result<bool, PokerL1Error> {
        Ok(!proof.is_empty())
    }

    fn validate_proof_format(&self, proof: &[u8]) -> Result<(), PokerL1Error> {
        if proof.is_empty() {
            return Err(PokerL1Error::InvalidZkProofFormat(
                "proof 不能为空".to_string(),
            ));
        }
        Ok(())
    }
}

/// 注册 ZkShuffle scheme 的测试 stub；不会进入生产构建。
#[cfg(test)]
pub(crate) fn register_zkshuffle_stub_verifier(registry: &mut ZkVerifierRegistry) {
    registry.register(Arc::new(StubVerifier::new(SCHEME_ZKSHUFFLE)));
}

/// 注册 Groth16 scheme 的测试 stub；不会进入生产构建。
#[cfg(test)]
pub(crate) fn register_groth16_stub_verifier(registry: &mut ZkVerifierRegistry) {
    registry.register(Arc::new(StubVerifier::new(SCHEME_GROTH16)));
}

/// 注册 IPA scheme 的测试 stub；不会进入生产构建。
#[cfg(test)]
pub(crate) fn register_ipa_stub_verifier(registry: &mut ZkVerifierRegistry) {
    registry.register(Arc::new(StubVerifier::new(SCHEME_IPA)));
}

impl std::fmt::Debug for ZkVerifierRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let statuses = self
            .statuses
            .read()
            .unwrap_or_else(|error| error.into_inner());
        f.debug_struct("ZkVerifierRegistry")
            .field(
                "registered_schemes",
                &self.verifiers.keys().collect::<Vec<_>>(),
            )
            .field("statuses", &*statuses)
            .finish()
    }
}

impl ZkVerifierRegistry {
    /// 创建空 registry。
    pub fn new() -> Self {
        Self::default()
    }

    /// 注册 verifier（热插拔）。
    pub fn register(&mut self, verifier: Arc<dyn ZkVerifier>) {
        let scheme_id = verifier.scheme_id();
        self.verifiers.insert(scheme_id, verifier);
    }

    /// 注销 verifier。
    pub fn unregister(&mut self, scheme_id: SchemeId) -> Option<Arc<dyn ZkVerifier>> {
        self.verifiers.remove(&scheme_id)
    }

    /// 查询 verifier。
    pub fn get(&self, scheme_id: SchemeId) -> Option<&Arc<dyn ZkVerifier>> {
        self.verifiers.get(&scheme_id)
    }

    /// Whether a verifier implementation is registered for one scheme.
    ///
    /// This deliberately answers only implementation availability, not whether the scheme is
    /// governance-enabled.  Callers that need to admit a proof must still use
    /// [`Self::zk_verify`], which applies the authenticated [`VerifierStatus`] gate.
    #[must_use]
    pub fn has_verifier(&self, scheme_id: SchemeId) -> bool {
        self.verifiers.contains_key(&scheme_id)
    }

    /// 列出所有已注册 scheme_id。
    pub fn registered_schemes(&self) -> Vec<SchemeId> {
        self.verifiers.keys().copied().collect()
    }

    /// Test-only local status override.
    ///
    /// Production status changes are derived exclusively from the immutable governance
    /// singleton. Keeping this capability crate-private prevents an RPC/application caller with
    /// a registry handle from enabling proof acceptance outside a consensus transition.
    pub(crate) fn set_verifier_status(&self, chain_id: crate::ChainId, status: VerifierStatus) {
        self.statuses
            .write()
            .unwrap_or_else(|error| error.into_inner())
            .insert(chain_id, status);
    }

    /// Replace the runtime status view with the statuses from authenticated governance state.
    ///
    /// Registry clones share this status control plane, so a governance update becomes visible to
    /// RPC, block production, block replay, and VM syscall environments without rebuilding the
    /// registered verifier implementations.
    pub(crate) fn synchronize_governance_statuses(
        &self,
        governance: &crate::governance::GovernanceState,
    ) {
        let mut statuses = self
            .statuses
            .write()
            .unwrap_or_else(|error| error.into_inner());
        statuses.clear();
        statuses.extend(
            governance
                .verifier_statuses
                .iter()
                .map(|(chain_id, status)| (*chain_id, *status)),
        );
    }

    /// 查询 per-chain_id verifier_status（NEW-C1）。
    ///
    /// 未设置时默认 `Stub`（NEW-C1：初始 Stub）。
    pub fn verifier_status(&self, chain_id: crate::ChainId) -> VerifierStatus {
        self.statuses
            .read()
            .unwrap_or_else(|error| error.into_inner())
            .get(&chain_id)
            .copied()
            .unwrap_or(VerifierStatus::Stub)
    }

    /// 通用 `zk_verify(scheme_id, proof, public_io) -> bool` 入口（SubTask 22.2）。
    ///
    /// 步骤：
    /// 1. 查找 verifier（未注册返回 `ZkVerifierNotRegistered`）
    /// 2. 查询 `verifier_status`（per-chain_id）
    /// 3. 校验 public_io 边界（O15 + SubTask 27.11）
    /// 4. Stub 状态强制返回 `verified=false`；Production 才调用 verifier
    pub fn zk_verify(
        &self,
        chain_id: crate::ChainId,
        scheme_id: SchemeId,
        proof: &[u8],
        public_io: &ZkPublicIo,
        max_skip_segments: u32,
        max_ack_chain_length: u32,
    ) -> Result<ZkVerifyResult, PokerL1Error> {
        let verifier = self
            .verifiers
            .get(&scheme_id)
            .ok_or(PokerL1Error::ZkVerifierNotRegistered(scheme_id))?;

        let status = self.verifier_status(chain_id);

        // 校验 public_io 边界（O15 + SubTask 27.11）
        public_io.validate(max_skip_segments, max_ack_chain_length)?;

        // 校验 proof 格式（无论 Stub/Production 都校验）
        verifier.validate_proof_format(proof)?;

        // Registry owns the status gate. Even a mistakenly registered verifier cannot turn a
        // disabled/Stub scheme into an accepting MVP path.
        let verified = match status {
            VerifierStatus::Stub => false,
            VerifierStatus::Production => verifier.verify(proof, public_io, status)?,
        };

        Ok(ZkVerifyResult {
            verified,
            verifier_status: status,
            scheme_id,
        })
    }

    /// 带 grace period 上下文的 `zk_verify` 入口（Phase 8 SubTask 8.2.3-8.2.7）。
    ///
    /// 与 [`zk_verify`](Self::zk_verify) 的差异：
    /// - 委托到 `verifier.verify_with_context`，传入 `ZkVerifyContext`
    /// - Hypernova verifier 据此实现 grace period 双通道 + M2-003/004 校验
    ///
    /// # 参数
    /// - `ctx`：grace period + M2-003/004 所需的链上状态上下文
    #[allow(clippy::too_many_arguments)] // 8 参数均为 spec 要求的安全校验参数
    pub fn zk_verify_with_context(
        &self,
        chain_id: crate::ChainId,
        scheme_id: SchemeId,
        proof: &[u8],
        public_io: &ZkPublicIo,
        max_skip_segments: u32,
        max_ack_chain_length: u32,
        ctx: &ZkVerifyContext<'_>,
    ) -> Result<ZkVerifyResult, PokerL1Error> {
        let verifier = self
            .verifiers
            .get(&scheme_id)
            .ok_or(PokerL1Error::ZkVerifierNotRegistered(scheme_id))?;

        let status = self.verifier_status(chain_id);

        // 校验 public_io 边界（O15 + SubTask 27.11）
        public_io.validate(max_skip_segments, max_ack_chain_length)?;

        // 校验 proof 格式（无论 Stub/Production 都校验）
        verifier.validate_proof_format(proof)?;

        // 验证 proof（带 context）
        let verified = match status {
            VerifierStatus::Stub => false,
            VerifierStatus::Production => {
                verifier.verify_with_context(proof, public_io, status, ctx)?
            }
        };

        Ok(ZkVerifyResult {
            verified,
            verifier_status: status,
            scheme_id,
        })
    }
}

/// 为不关注证明格式的上层单元测试注册 scheme 1 stub。
///
/// Texas 生产节点不会调用此 helper；实际 verifier 必须由 Texas AIR crate 在审计完成后注册。
#[cfg(test)]
pub(crate) fn register_test_only_stwo_stub_verifier(registry: &mut ZkVerifierRegistry) {
    #[allow(deprecated)]
    registry.register(Arc::new(StubVerifier::new(SCHEME_STWO)));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::offline::MAX_FOLD_STEP_COUNT;

    /// 用于测试的 stub verifier — 仅校验 proof 非空。
    struct StubVerifier {
        scheme_id: SchemeId,
    }

    impl ZkVerifier for StubVerifier {
        fn scheme_id(&self) -> SchemeId {
            self.scheme_id
        }

        fn verify(
            &self,
            proof: &[u8],
            _public_io: &ZkPublicIo,
            _status: VerifierStatus,
        ) -> Result<bool, PokerL1Error> {
            Ok(!proof.is_empty())
        }

        fn validate_proof_format(&self, proof: &[u8]) -> Result<(), PokerL1Error> {
            if proof.is_empty() {
                return Err(PokerL1Error::InvalidZkProofFormat(
                    "proof 不能为空".to_string(),
                ));
            }
            Ok(())
        }
    }

    fn make_public_io(fold_step_count: u32, skip_count: u32) -> ZkPublicIo {
        ZkPublicIo {
            initial_commitment: [0x01; 32],
            final_commitment: [0x02; 32],
            state_delta_hash: [0x03; 32],
            ack_chain_hash: [0x04; 32],
            fold_step_count,
            skip_count,
            segment_continuity_proof: Vec::new(),
        }
    }

    #[test]
    fn test_register_and_lookup() {
        let mut registry = ZkVerifierRegistry::new();
        let verifier = Arc::new(StubVerifier { scheme_id: 99 });
        registry.register(verifier);

        assert!(registry.get(99).is_some());
        assert!(registry.get(98).is_none());
        assert_eq!(registry.registered_schemes(), vec![99]);
    }

    #[test]
    fn test_unregister() {
        let mut registry = ZkVerifierRegistry::new();
        registry.register(Arc::new(StubVerifier { scheme_id: 99 }));
        assert!(registry.unregister(99).is_some());
        assert!(registry.get(99).is_none());
    }

    #[test]
    fn test_default_verifier_status_is_stub() {
        let registry = ZkVerifierRegistry::new();
        assert_eq!(
            registry.verifier_status(crate::DEFAULT_CHAIN_ID),
            VerifierStatus::Stub
        );
    }

    #[test]
    fn test_set_verifier_status() {
        let mut registry = ZkVerifierRegistry::new();
        registry.set_verifier_status(crate::DEFAULT_CHAIN_ID, VerifierStatus::Production);
        assert_eq!(
            registry.verifier_status(crate::DEFAULT_CHAIN_ID),
            VerifierStatus::Production
        );
    }

    #[test]
    fn test_zk_verify_unregistered_scheme() {
        let registry = ZkVerifierRegistry::new();
        let public_io = make_public_io(1, 0);
        let result = registry.zk_verify(crate::DEFAULT_CHAIN_ID, 999, &[0x01], &public_io, 3, 1000);
        assert!(matches!(
            result,
            Err(PokerL1Error::ZkVerifierNotRegistered(999))
        ));
    }

    #[test]
    fn test_zk_verify_invalid_proof_format() {
        let mut registry = ZkVerifierRegistry::new();
        registry.register(Arc::new(StubVerifier { scheme_id: 99 }));
        let public_io = make_public_io(1, 0);
        let result = registry.zk_verify(crate::DEFAULT_CHAIN_ID, 99, &[], &public_io, 3, 1000);
        assert!(matches!(result, Err(PokerL1Error::InvalidZkProofFormat(_))));
    }

    #[test]
    fn test_reserved_texas_scheme_is_unregistered_by_default() {
        let registry = ZkVerifierRegistry::new();
        let public_io = make_public_io(1, 0);

        let result = registry.zk_verify(
            crate::DEFAULT_CHAIN_ID,
            SCHEME_STWO,
            &[0xAA; 64],
            &public_io,
            3,
            1000,
        );

        assert!(matches!(
            result,
            Err(PokerL1Error::ZkVerifierNotRegistered(SCHEME_STWO))
        ));
    }

    #[test]
    fn test_zk_verify_fold_step_count_exceeded() {
        let mut registry = ZkVerifierRegistry::new();
        registry.register(Arc::new(StubVerifier { scheme_id: 99 }));
        let public_io = make_public_io(MAX_FOLD_STEP_COUNT + 1, 0);
        let result = registry.zk_verify(crate::DEFAULT_CHAIN_ID, 99, &[0x01], &public_io, 3, 1000);
        assert!(matches!(
            result,
            Err(PokerL1Error::FoldStepCountExceeded { .. })
        ));
    }

    #[test]
    fn test_zk_verify_skip_count_exceeded() {
        let mut registry = ZkVerifierRegistry::new();
        registry.register(Arc::new(StubVerifier { scheme_id: 99 }));
        let public_io = make_public_io(1, 10);
        let result = registry.zk_verify(crate::DEFAULT_CHAIN_ID, 99, &[0x01], &public_io, 3, 1000);
        assert!(matches!(
            result,
            Err(PokerL1Error::SkipCountExceeded { .. })
        ));
    }

    #[test]
    fn test_zk_verify_stub_status_fails_closed_even_if_verifier_would_accept() {
        let mut registry = ZkVerifierRegistry::new();
        registry.register(Arc::new(StubVerifier { scheme_id: 99 }));
        let public_io = make_public_io(1, 0);
        let result = registry
            .zk_verify(crate::DEFAULT_CHAIN_ID, 99, &[0x01], &public_io, 3, 1000)
            .expect("disabled verifier should return a fail-closed result");
        assert!(!result.verified);
        assert_eq!(result.verifier_status, VerifierStatus::Stub);
        assert_eq!(result.scheme_id, 99);
    }

    #[test]
    fn test_verifier_status_allows_offchain() {
        // Stub 在任意网络都拒绝，避免测试网格式检查被误当作有效证明。
        assert!(!VerifierStatus::Stub.allows_offchain(crate::DEFAULT_CHAIN_ID, true));
        assert!(!VerifierStatus::Stub.allows_offchain(crate::DEFAULT_CHAIN_ID, false));
        // Production + mainnet → 允许
        assert!(VerifierStatus::Production.allows_offchain(crate::DEFAULT_CHAIN_ID, true));
    }

    #[test]
    fn test_public_io_validate_at_boundaries() {
        // fold_step_count = 1000 应通过（边界）
        let pi = make_public_io(MAX_FOLD_STEP_COUNT, 0);
        assert!(pi.validate(3, 1000).is_ok());
        // fold_step_count = 1001 应失败
        let pi = make_public_io(MAX_FOLD_STEP_COUNT + 1, 0);
        assert!(pi.validate(3, 1000).is_err());
        // skip_count = 3 应通过（边界）
        let pi = make_public_io(1, 3);
        assert!(pi.validate(3, 1000).is_ok());
        // skip_count = 4 应失败
        let pi = make_public_io(1, 4);
        assert!(pi.validate(3, 1000).is_err());
    }

    #[test]
    fn test_public_io_to_bytes_deterministic() {
        let pi1 = make_public_io(5, 2);
        let pi2 = make_public_io(5, 2);
        assert_eq!(pi1.to_bytes(), pi2.to_bytes());

        let pi3 = make_public_io(6, 2);
        assert_ne!(pi1.to_bytes(), pi3.to_bytes());
    }
}
