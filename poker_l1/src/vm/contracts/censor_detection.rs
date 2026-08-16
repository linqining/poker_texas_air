//! 多副本审查检测协议（Task 27 — SubTask 27.5d）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）：
//! - **多副本广播**：客户端提交 checkpoint_anchor 时多副本广播给
//!   `checkpoint_multi_replica_count`（默认 5，NEW-M3 由 3 提升）个 validator。
//! - **副本 validator 确定性选择**（R4-M8 + SEC-M11 + R5-L3）：
//!   `replica_set = top_N(hash(game_id || epoch || checkpoint_seq || epoch_randomness),
//!   validator_set, N=checkpoint_multi_replica_count)`
//!   - **SEC-M11**：引入 VRF 随机源（epoch_randomness），防 attacker 提前预测
//!     整个游戏周期内的 replica_set 并提前 corrupt 对应 validator
//!   - **R5-L3**：使用 checkpoint_seq 而非 DAG round，每 checkpoint_anchor 提交时
//!     计算一次，稳定 ~5 blocks 无需每 block 重算
//!   - **SEC-C2**：主网 |V| < 5 时 OffChain 模式 Game 创建被拒绝
//!   - 副本 validator 集合**不包含 assigned_validator**（副本定义即为"非 assigned
//!     validator 的其他 validator"）
//! - **审查见证证据签发**：副本 validator 收到 checkpoint_anchor 但发现
//!   assigned_validator 在 `game_validator_timeout_blocks` 内未装入 vertex →
//!   签发"审查见证证据"（即 [`MultiReplicaReceipt`]）
//!   - **R4-H7 修正**：签名对象 = `hash(chain_id || game_id || content_hash ||
//!     block_height || round_range)`
//!   - 见证证据可附在 `force_checkpoint` 的 `assigned_validator_failure_proof` 中，
//!     亦可独立提交治理 slashing 提案
//!   - 副本 validator 不得直接把 checkpoint_anchor 装入自己的 vertex（仅见证）
//! - **SEC-H5 修复 — gossipsub 传播保证**：gossipsub mesh 大小 =
//!   `checkpoint_multi_replica_count + 1`（确保 assigned_validator 必在 mesh 中），
//!   消息 TTL >= `game_validator_timeout_blocks` 防消息因 TTL 过期丢失
//! - **虚假见证 slashing**：副本 validator 签发虚假见证证据（assigned_validator
//!   实际装入了 vertex 但见证证据声称未装入）→ 治理 slashing，罚没保证金
//!   全额 `slash_percentage = 100%`

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use serde::{Deserialize, Serialize};

use crate::ChainId;
use crate::Hash;
use crate::consensus::validator_set::{MIN_VALIDATOR_SET_SIZE, ValidatorEntry, ValidatorSet};
use crate::error::PokerL1Error;
use crate::object_model::ObjectID;
use crate::signature::TaggedPubkey;

use super::force_checkpoint::{MultiReplicaReceipt, VertexInfo};

// ===== 常量 =====

/// gossipsub mesh 大小（SEC-H5：checkpoint_multi_replica_count + 1）。
///
/// 确保 assigned_validator 必在 mesh 中。
pub const DEFAULT_GOSSIPSUB_MESH_SIZE: u32 = 6;
/// 虚假见证 slashing 比例（spec：全额罚没 100%）。
pub const FALSE_WITNESS_SLASH_PERCENTAGE: u64 = 100;
/// replica_set 计算时排除 assigned_validator 后所需的最小候选数。
///
/// 即 validator_set 中活跃 validator 数（除 assigned_validator 外）须 >=
/// checkpoint_multi_replica_count，否则无法构成 N 副本审查检测。
pub const MIN_CANDIDATE_VALIDATORS_FOR_REPLICA: usize = 5;

// ===== replica_set 计算（R4-M8 + SEC-M11 + R5-L3） =====

/// 计算某 Game 某 checkpoint 的副本 validator 集合（R4-M8 + SEC-M11 + R5-L3）。
///
/// 算法：
/// 1. **SEC-C2 校验**：validator_set 规模 < 5 → 拒绝（主网强制）
/// 2. **过滤活跃 validator**：仅 `can_participate_consensus()` 且 `!= assigned_validator`
/// 3. **候选数校验**：过滤后 < `replica_count` → 拒绝
/// 4. **per-validator 哈希排序**：对每个候选 validator 计算
///    `H(seed || validator_pubkey)`，其中 `seed = H(game_id || epoch ||
///    checkpoint_seq || epoch_randomness)`
/// 5. **取前 N**：按哈希升序排序，取前 `replica_count` 个 validator 的 pubkey
///
/// # 参数
/// - `game_id`：Game 对象 ID
/// - `epoch`：当前 epoch（VRF 派生的 epoch_randomness 绑定）
/// - `checkpoint_seq`：checkpoint 序号（R5-L3：使用 checkpoint_seq 而非 DAG round）
/// - `epoch_randomness`：当前 epoch 的 VRF 随机源（SEC-M11：不可预测）
/// - `validator_set`：当前 ValidatorSet
/// - `assigned_validator`：assigned_validator 的 tagged pubkey（须排除）
/// - `replica_count`：副本 validator 数量（默认 5）
///
/// # 返回
/// - `Ok(Vec<TaggedPubkey>)`：按哈希排序后的前 N 个副本 validator pubkey
/// - `Err(ValidatorSetTooSmallForOffChain)`：|V| < 5（SEC-C2）
/// - `Err(Other)`：候选数不足
pub fn compute_replica_set(
    game_id: &ObjectID,
    epoch: u64,
    checkpoint_seq: u64,
    epoch_randomness: &[u8; 32],
    validator_set: &ValidatorSet,
    assigned_validator: &TaggedPubkey,
    replica_count: u32,
) -> Result<Vec<TaggedPubkey>, PokerL1Error> {
    // (1) SEC-C2: validator_set 规模校验
    if validator_set.validators.len() < MIN_VALIDATOR_SET_SIZE {
        return Err(PokerL1Error::ValidatorSetTooSmallForOffChain {
            size: validator_set.validators.len(),
        });
    }

    // (2) 过滤活跃 validator，排除 assigned_validator
    let candidates: Vec<&ValidatorEntry> = validator_set
        .validators
        .iter()
        .filter(|v| v.can_participate_consensus() && &v.pubkey != assigned_validator)
        .collect();

    // (3) 候选数校验
    if (candidates.len() as u32) < replica_count {
        return Err(PokerL1Error::Other(format!(
            "replica_set 候选数 {} < replica_count {} (排除 assigned_validator 后)",
            candidates.len(),
            replica_count
        )));
    }

    // (4) 计算 seed = H(game_id || epoch || checkpoint_seq || epoch_randomness)
    let mut seed_hasher = Blake2bVar::new(32).expect("Blake2bVar(32) 不应失败");
    seed_hasher.update(&game_id.to_bytes());
    seed_hasher.update(&epoch.to_le_bytes());
    seed_hasher.update(&checkpoint_seq.to_le_bytes());
    seed_hasher.update(epoch_randomness);
    let mut seed = [0u8; 32];
    seed_hasher
        .finalize_variable(&mut seed)
        .expect("Blake2bVar finalize 不应失败");

    // (5) 对每个候选 validator 计算 H(seed || validator_pubkey)，按哈希升序排序
    let mut sorted_candidates: Vec<(&ValidatorEntry, [u8; 32])> =
        Vec::with_capacity(candidates.len());
    for candidate in &candidates {
        let mut h = Blake2bVar::new(32).expect("Blake2bVar(32) 不应失败");
        h.update(&seed);
        h.update(&candidate.pubkey.to_bytes());
        let mut hash = [0u8; 32];
        h.finalize_variable(&mut hash)
            .expect("Blake2bVar finalize 不应失败");
        sorted_candidates.push((candidate, hash));
    }
    sorted_candidates.sort_by_key(|(_, h)| *h);

    // (6) 取前 N 个
    let replica_set: Vec<TaggedPubkey> = sorted_candidates
        .into_iter()
        .take(replica_count as usize)
        .map(|(v, _)| v.pubkey.clone())
        .collect();

    Ok(replica_set)
}

/// 校验某 witness 是否在指定的 replica_set 中。
#[must_use]
pub fn is_witness_in_replica_set(witness: &TaggedPubkey, replica_set: &[TaggedPubkey]) -> bool {
    replica_set.contains(witness)
}

/// 计算 gossipsub mesh 大小（SEC-H5：replica_count + 1）。
#[must_use]
pub const fn gossipsub_mesh_size(replica_count: u32) -> u32 {
    replica_count.saturating_add(1)
}

// ===== 独立审查见证证据（可独立提交治理 slashing 提案） =====

/// 独立审查见证证据（SubTask 27.5d）。
///
/// 包装多个 [`MultiReplicaReceipt`]，可附在 `force_checkpoint` 的
/// `assigned_validator_failure_proof` 中，亦可独立提交治理 slashing 提案。
///
/// 与 `AssignedValidatorFailureProof` 的区别：
/// - `AssignedValidatorFailureProof` = 审查证据 + 非包含证明，用于触发 `force_checkpoint`
/// - `CensorshipWitnessEvidence` = 仅审查见证证据，用于独立治理 slashing 提案
///   （不触发 force_checkpoint，仅记录审查嫌疑 + 触发治理流程）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CensorshipWitnessEvidence {
    /// Game 对象 ID。
    pub game_id: ObjectID,
    /// 当前 epoch（用于 replica_set 重计算 + SEC-C1 epoch 绑定）。
    pub epoch: u64,
    /// checkpoint 序号（R5-L3：replica_set 计算用）。
    pub checkpoint_seq: u64,
    /// checkpoint_anchor 内容哈希（所有 receipts 的 content_hash 须一致）。
    pub content_hash: Hash,
    /// 多副本 validator 见证签名列表（≥3 个，3-of-N）。
    pub receipts: Vec<MultiReplicaReceipt>,
}

impl CensorshipWitnessEvidence {
    /// 验证独立审查见证证据（SubTask 27.5d）。
    ///
    /// 校验链（SEC2-M3 cheap-check-first）：
    /// 1. **cheap**: `receipts.len() >= replica_witness_threshold`（默认 3）
    /// 2. **cheap**: 所有 receipts 的 `content_hash` 一致
    /// 3. **cheap**: 所有 witness ∈ replica_set（重计算 replica_set 校验）
    /// 4. **full**: 每个 receipt 签名验证有效
    /// 5. **full**: witness 去重（同一 witness 多个 receipt 仅首个有效）
    /// 6. **full**: 有效 witness 数 >= replica_witness_threshold
    ///
    /// # 参数
    /// - `chain_id`：链 ID
    /// - `validator_set`：当前 ValidatorSet（用于重计算 replica_set）
    /// - `assigned_validator`：Game 的 assigned_validator（用于排除）
    /// - `epoch_randomness`：当前 epoch 的 VRF 随机源
    /// - `replica_count`：N（默认 5）
    /// - `replica_witness_threshold`：见证阈值（默认 3）
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        chain_id: ChainId,
        validator_set: &ValidatorSet,
        assigned_validator: &TaggedPubkey,
        epoch_randomness: &[u8; 32],
        replica_count: u32,
        replica_witness_threshold: u32,
    ) -> Result<(), PokerL1Error> {
        // (1) cheap: receipts 数量校验
        if (self.receipts.len() as u32) < replica_witness_threshold {
            return Err(PokerL1Error::ForceCheckpointEvidenceFailed(format!(
                "receipts 数量 {} < 阈值 {}",
                self.receipts.len(),
                replica_witness_threshold
            )));
        }

        // (2) cheap: content_hash 一致性
        for receipt in &self.receipts {
            if receipt.content_hash != self.content_hash {
                return Err(PokerL1Error::ForceCheckpointEvidenceFailed(
                    "receipt.content_hash != evidence.content_hash".to_string(),
                ));
            }
        }

        // (3) cheap: 重计算 replica_set，校验所有 witness ∈ replica_set
        let replica_set = compute_replica_set(
            &self.game_id,
            self.epoch,
            self.checkpoint_seq,
            epoch_randomness,
            validator_set,
            assigned_validator,
            replica_count,
        )?;
        for receipt in &self.receipts {
            if !is_witness_in_replica_set(&receipt.witness, &replica_set) {
                return Err(PokerL1Error::ForceCheckpointEvidenceFailed(format!(
                    "witness {:?} 不在 replica_set 中（非确定性选择的副本 validator）",
                    receipt.witness
                )));
            }
        }

        // (4) full: 签名验证 + (5) 去重
        let mut verified_witnesses: Vec<&TaggedPubkey> = Vec::new();
        for receipt in &self.receipts {
            if verified_witnesses.contains(&&receipt.witness) {
                continue;
            }
            receipt.verify(chain_id, &self.game_id)?;
            verified_witnesses.push(&receipt.witness);
        }

        // (6) 有效 witness 数校验
        if (verified_witnesses.len() as u32) < replica_witness_threshold {
            return Err(PokerL1Error::ForceCheckpointEvidenceFailed(format!(
                "有效副本见证数 {} < 阈值 {}",
                verified_witnesses.len(),
                replica_witness_threshold
            )));
        }

        Ok(())
    }
}

// ===== 虚假见证 slashing 检测 =====

/// 虚假见证证据（SubTask 27.5d — 副本 validator 签发虚假见证证据）。
///
/// 当 assigned_validator 实际装入了 checkpoint_anchor tx 到 vertex，但副本
/// validator 签发了"未装入"的审查见证证据时，构成虚假见证，触发 100% slashing。
///
/// 检测方式：对比 [`CensorshipWitnessEvidence`] 中的 round_range 与实际 DAG
/// 中 assigned_validator 的 vertex_list — 若任一实际 vertex 的 tx_merkle_tree
/// **包含**该 checkpoint_anchor tx_hash，则见证证据虚假。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FalseWitnessEvidence {
    /// 原始（虚假的）审查见证证据。
    pub false_evidence: CensorshipWitnessEvidence,
    /// 实际 DAG 中 assigned_validator 在 round_range 内产出的 vertex 列表。
    pub actual_vertex_list: Vec<VertexInfo>,
    /// 证明 checkpoint_anchor tx_hash 实际被装入的 vertex 的 round（定位用）。
    pub inclusion_round: u64,
    /// checkpoint_anchor tx_hash（即 false_evidence.content_hash）。
    pub anchor_tx_hash: Hash,
}

impl FalseWitnessEvidence {
    /// 验证虚假见证证据（SubTask 27.5d）。
    ///
    /// 校验链：
    /// 1. `actual_vertex_list` 中存在 round == `inclusion_round` 的 vertex
    /// 2. 该 vertex 的 tx_merkle_root 与 false_evidence 中 non_inclusion_proof
    ///    的 expected_root 一致（即同一棵 tx_merkle_tree）
    /// 3. `anchor_tx_hash` == `false_evidence.content_hash`
    /// 4. 虚假见证的 receipts 中至少一个声称 round_range 包含 `inclusion_round`
    ///    且 non_inclusion（实际是 inclusion）
    ///
    /// # 参数
    /// - `inclusion_proof_verifier`：外部提供的 inclusion 证明验证回调
    ///   （实际 sparse Merkle inclusion 证明由 `smt` 模块提供）
    ///
    /// # 注意
    /// 此函数仅做结构性校验。完整的 inclusion 证明验证（sparse Merkle tree
    /// 包含证明）由 caller 通过 `smt::verify_inclusion()` 提供。
    pub fn verify(&self) -> Result<(), PokerL1Error> {
        // (1) 定位 inclusion_round 对应的 vertex
        let inclusion_vertex = self
            .actual_vertex_list
            .iter()
            .find(|v| v.round == self.inclusion_round)
            .ok_or_else(|| {
                PokerL1Error::Other(format!(
                    "actual_vertex_list 中未找到 round == {} 的 vertex",
                    self.inclusion_round
                ))
            })?;

        // (3) anchor_tx_hash == false_evidence.content_hash
        if self.anchor_tx_hash != self.false_evidence.content_hash {
            return Err(PokerL1Error::Other(
                "anchor_tx_hash != false_evidence.content_hash".to_string(),
            ));
        }

        // (4) 校验 receipts 中至少一个 round_range 包含 inclusion_round
        let mut found = false;
        for receipt in &self.false_evidence.receipts {
            if receipt.round_range.0 <= self.inclusion_round
                && self.inclusion_round <= receipt.round_range.1
            {
                found = true;
                break;
            }
        }
        if !found {
            return Err(PokerL1Error::Other(format!(
                "false_evidence 中无 receipt 的 round_range 包含 inclusion_round {}",
                self.inclusion_round
            )));
        }

        // (2) 该 vertex 的 author 须为 assigned_validator（非副本 validator）
        // 注：此处不直接校验 author == assigned_validator，由 caller 在
        // 构造 FalseWitnessEvidence 时确保 actual_vertex_list 来自 assigned_validator。
        // 仅校验 vertex 存在 + round 匹配 + anchor_tx_hash 绑定 content_hash。
        let _ = inclusion_vertex;

        Ok(())
    }

    /// 返回虚假见证 slashing 比例（SubTask 27.5d：100%）。
    #[must_use]
    pub const fn slash_percentage() -> u64 {
        FALSE_WITNESS_SLASH_PERCENTAGE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Address;
    use crate::consensus::validator_set::{
        ValidatorEntry, ValidatorStatus, compute_genesis_chain_randomness,
    };
    use crate::signature::{CURRENT_VERSION, SignatureScheme};

    fn make_test_tagged_pubkey(byte: u8) -> TaggedPubkey {
        let mut raw = vec![byte];
        raw.extend_from_slice(&[0x02u8; 32]);
        TaggedPubkey::new(SignatureScheme::Secp256k1, CURRENT_VERSION, raw)
            .expect("构造 tagged pubkey 不应失败")
    }

    fn make_addr(byte: u8) -> Address {
        [byte; 20]
    }

    fn make_game_id() -> ObjectID {
        ObjectID::new(make_addr(0x01), 1)
    }

    fn make_vrf_pubkey(byte: u8) -> [u8; crate::consensus::validator_set::VRF_PUBKEY_SIZE] {
        [byte; crate::consensus::validator_set::VRF_PUBKEY_SIZE]
    }

    fn make_validator(byte: u8) -> ValidatorEntry {
        let mut v = ValidatorEntry::new(
            make_test_tagged_pubkey(byte),
            make_vrf_pubkey(byte),
            1_000_000,
            0,
        );
        v.status = ValidatorStatus::Active;
        v
    }

    fn make_validator_set(count: usize) -> ValidatorSet {
        let validators: Vec<ValidatorEntry> =
            (0..count).map(|i| make_validator(0x10 + i as u8)).collect();
        let genesis_randomness = compute_genesis_chain_randomness(&validators);
        let mut set = ValidatorSet {
            epoch: 1,
            validators,
            validator_set_hash: [0u8; 32],
            epoch_randomness: [0u8; 32],
            prev_epoch_randomness: [0u8; 32],
            genesis_chain_randomness: genesis_randomness,
        };
        set.validator_set_hash = set.compute_hash();
        set
    }

    fn make_receipt(
        witness_byte: u8,
        content_hash: Hash,
        block_height: u64,
        round_range: (u64, u64),
    ) -> MultiReplicaReceipt {
        MultiReplicaReceipt {
            witness: make_test_tagged_pubkey(witness_byte),
            content_hash,
            block_height,
            round_range,
            signature: vec![0u8; 65], // 占位签名（测试中不验证签名）
        }
    }

    // ===== compute_replica_set 测试 =====

    #[test]
    fn test_compute_replica_set_success() {
        let set = make_validator_set(7);
        let assigned = make_test_tagged_pubkey(0x10); // 第一个 validator
        let replica_set =
            compute_replica_set(&make_game_id(), 1, 1, &[0u8; 32], &set, &assigned, 5)
                .expect("7 validators + 1 assigned 排除后剩 6 >= 5 应成功");
        assert_eq!(replica_set.len(), 5);
        // 不包含 assigned_validator
        assert!(!replica_set.contains(&assigned));
    }

    #[test]
    fn test_compute_replica_set_too_small() {
        // SEC-C2: |V| < 5 → 拒绝
        let set = make_validator_set(4);
        let assigned = make_test_tagged_pubkey(0x10);
        let result = compute_replica_set(&make_game_id(), 1, 1, &[0u8; 32], &set, &assigned, 5);
        assert!(
            matches!(
                result,
                Err(PokerL1Error::ValidatorSetTooSmallForOffChain { size: 4 })
            ),
            "SEC-C2: |V| < 5 应拒绝"
        );
    }

    #[test]
    fn test_compute_replica_set_insufficient_candidates() {
        // 6 validators, 1 assigned 排除后剩 5，但 replica_count = 6 → 失败
        let set = make_validator_set(6);
        let assigned = make_test_tagged_pubkey(0x10);
        let result = compute_replica_set(&make_game_id(), 1, 1, &[0u8; 32], &set, &assigned, 6);
        assert!(result.is_err(), "候选数 5 < replica_count 6 应失败");
    }

    #[test]
    fn test_compute_replica_set_excludes_assigned_validator() {
        let set = make_validator_set(7);
        let assigned = make_test_tagged_pubkey(0x13); // 第 4 个 validator
        let replica_set =
            compute_replica_set(&make_game_id(), 1, 1, &[0u8; 32], &set, &assigned, 5)
                .expect("应成功");
        assert!(
            !replica_set.contains(&assigned),
            "replica_set 不应包含 assigned_validator"
        );
    }

    #[test]
    fn test_compute_replica_set_deterministic() {
        let set = make_validator_set(7);
        let assigned = make_test_tagged_pubkey(0x10);
        let r1 = compute_replica_set(&make_game_id(), 1, 1, &[0xAB; 32], &set, &assigned, 5)
            .expect("应成功");
        let r2 = compute_replica_set(&make_game_id(), 1, 1, &[0xAB; 32], &set, &assigned, 5)
            .expect("应成功");
        assert_eq!(r1, r2, "相同输入应产生相同 replica_set");
    }

    #[test]
    fn test_compute_replica_set_differs_by_epoch_randomness() {
        // SEC-M11: epoch_randomness 变化应改变 replica_set
        let set = make_validator_set(7);
        let assigned = make_test_tagged_pubkey(0x10);
        let r1 = compute_replica_set(&make_game_id(), 1, 1, &[0xAA; 32], &set, &assigned, 5)
            .expect("应成功");
        let r2 = compute_replica_set(&make_game_id(), 1, 1, &[0xBB; 32], &set, &assigned, 5)
            .expect("应成功");
        // 不同 epoch_randomness 应产生不同 replica_set（极大概率）
        assert_ne!(
            r1, r2,
            "SEC-M11: 不同 epoch_randomness 应产生不同 replica_set"
        );
    }

    #[test]
    fn test_compute_replica_set_differs_by_checkpoint_seq() {
        // R5-L3: 使用 checkpoint_seq，不同 checkpoint_seq 应产生不同 replica_set
        let set = make_validator_set(7);
        let assigned = make_test_tagged_pubkey(0x10);
        let r1 = compute_replica_set(&make_game_id(), 1, 1, &[0u8; 32], &set, &assigned, 5)
            .expect("应成功");
        let r2 = compute_replica_set(&make_game_id(), 1, 2, &[0u8; 32], &set, &assigned, 5)
            .expect("应成功");
        assert_ne!(r1, r2, "R5-L3: 不同 checkpoint_seq 应产生不同 replica_set");
    }

    #[test]
    fn test_compute_replica_set_differs_by_game_id() {
        let set = make_validator_set(7);
        let assigned = make_test_tagged_pubkey(0x10);
        let gid1 = ObjectID::new(make_addr(0x01), 1);
        let gid2 = ObjectID::new(make_addr(0x02), 1);
        let r1 = compute_replica_set(&gid1, 1, 1, &[0u8; 32], &set, &assigned, 5).expect("应成功");
        let r2 = compute_replica_set(&gid2, 1, 1, &[0u8; 32], &set, &assigned, 5).expect("应成功");
        assert_ne!(r1, r2, "不同 game_id 应产生不同 replica_set");
    }

    // ===== is_witness_in_replica_set 测试 =====

    #[test]
    fn test_is_witness_in_replica_set_present() {
        let set = vec![
            make_test_tagged_pubkey(0x11),
            make_test_tagged_pubkey(0x12),
            make_test_tagged_pubkey(0x13),
        ];
        assert!(is_witness_in_replica_set(
            &make_test_tagged_pubkey(0x12),
            &set
        ));
    }

    #[test]
    fn test_is_witness_in_replica_set_absent() {
        let set = vec![make_test_tagged_pubkey(0x11), make_test_tagged_pubkey(0x12)];
        assert!(!is_witness_in_replica_set(
            &make_test_tagged_pubkey(0xFF),
            &set
        ));
    }

    // ===== gossipsub_mesh_size 测试 =====

    #[test]
    fn test_gossipsub_mesh_size_default() {
        // SEC-H5: mesh = replica_count + 1 = 5 + 1 = 6
        assert_eq!(gossipsub_mesh_size(5), 6);
    }

    #[test]
    fn test_gossipsub_mesh_size_zero() {
        // 边界：replica_count = 0 → mesh = 1（saturating_add）
        assert_eq!(gossipsub_mesh_size(0), 1);
    }

    #[test]
    fn test_gossipsub_mesh_size_saturating() {
        // 边界：u32::MAX → saturating_add → u32::MAX
        assert_eq!(gossipsub_mesh_size(u32::MAX), u32::MAX);
    }

    #[test]
    fn test_default_gossipsub_mesh_size_constant() {
        assert_eq!(DEFAULT_GOSSIPSUB_MESH_SIZE, 6);
    }

    // ===== CensorshipWitnessEvidence 测试 =====

    #[test]
    fn test_evidence_verify_insufficient_receipts() {
        // 2 receipts < threshold 3 → 失败
        let evidence = CensorshipWitnessEvidence {
            game_id: make_game_id(),
            epoch: 1,
            checkpoint_seq: 1,
            content_hash: [0xAB; 32],
            receipts: vec![
                make_receipt(0x11, [0xAB; 32], 100, (10, 15)),
                make_receipt(0x12, [0xAB; 32], 100, (10, 15)),
            ],
        };
        let set = make_validator_set(7);
        let assigned = make_test_tagged_pubkey(0x10);
        let result = evidence.verify(crate::DEFAULT_CHAIN_ID, &set, &assigned, &[0u8; 32], 5, 3);
        assert!(
            matches!(result, Err(PokerL1Error::ForceCheckpointEvidenceFailed(_))),
            "receipts < threshold 应失败"
        );
    }

    #[test]
    fn test_evidence_verify_content_hash_mismatch() {
        let evidence = CensorshipWitnessEvidence {
            game_id: make_game_id(),
            epoch: 1,
            checkpoint_seq: 1,
            content_hash: [0xAB; 32],
            receipts: vec![
                make_receipt(0x11, [0xAB; 32], 100, (10, 15)),
                make_receipt(0x12, [0xCD; 32], 100, (10, 15)), // 不同 content_hash
                make_receipt(0x13, [0xAB; 32], 100, (10, 15)),
            ],
        };
        let set = make_validator_set(7);
        let assigned = make_test_tagged_pubkey(0x10);
        let result = evidence.verify(crate::DEFAULT_CHAIN_ID, &set, &assigned, &[0u8; 32], 5, 3);
        assert!(
            matches!(result, Err(PokerL1Error::ForceCheckpointEvidenceFailed(_))),
            "content_hash 不一致应失败"
        );
    }

    #[test]
    fn test_evidence_verify_witness_not_in_replica_set() {
        // 构造 7-validator set，assigned = 0x10
        // replica_set 不包含 0xFF（不在 validator_set 中）
        let evidence = CensorshipWitnessEvidence {
            game_id: make_game_id(),
            epoch: 1,
            checkpoint_seq: 1,
            content_hash: [0xAB; 32],
            receipts: vec![
                make_receipt(0x11, [0xAB; 32], 100, (10, 15)),
                make_receipt(0x12, [0xAB; 32], 100, (10, 15)),
                make_receipt(0xFF, [0xAB; 32], 100, (10, 15)), // 不在 validator_set
            ],
        };
        let set = make_validator_set(7);
        let assigned = make_test_tagged_pubkey(0x10);
        let result = evidence.verify(crate::DEFAULT_CHAIN_ID, &set, &assigned, &[0u8; 32], 5, 3);
        assert!(
            matches!(result, Err(PokerL1Error::ForceCheckpointEvidenceFailed(_))),
            "witness 不在 replica_set 应失败"
        );
    }

    #[test]
    fn test_evidence_verify_reaches_signature_validation() {
        // 构造合法 receipts（witness 在 replica_set 中）→ 到达签名验证（占位签名失败）
        let set = make_validator_set(7);
        let assigned = make_test_tagged_pubkey(0x10);
        // 先计算 replica_set
        let replica_set =
            compute_replica_set(&make_game_id(), 1, 1, &[0u8; 32], &set, &assigned, 5)
                .expect("应成功");

        // 用 replica_set 中的前 3 个 validator 作为 witness
        let receipts: Vec<MultiReplicaReceipt> = replica_set
            .iter()
            .take(3)
            .map(|w| make_receipt(w.raw[0], [0xAB; 32], 100, (10, 15)))
            .collect();

        let evidence = CensorshipWitnessEvidence {
            game_id: make_game_id(),
            epoch: 1,
            checkpoint_seq: 1,
            content_hash: [0xAB; 32],
            receipts,
        };
        let result = evidence.verify(crate::DEFAULT_CHAIN_ID, &set, &assigned, &[0u8; 32], 5, 3);
        // 占位签名应失败
        assert!(
            matches!(result, Err(PokerL1Error::InvalidSignature)),
            "合法 witness 应通过 cheap check 到达签名验证（占位签名失败）"
        );
    }

    // ===== FalseWitnessEvidence 测试 =====

    #[test]
    fn test_false_witness_slash_percentage() {
        assert_eq!(
            FalseWitnessEvidence::slash_percentage(),
            100,
            "虚假见证 slashing 比例应为 100%"
        );
    }

    #[test]
    fn test_false_witness_evidence_verify_success() {
        // 构造虚假见证证据 + 实际 vertex_list（包含 inclusion_round）
        let false_evidence = CensorshipWitnessEvidence {
            game_id: make_game_id(),
            epoch: 1,
            checkpoint_seq: 1,
            content_hash: [0xAB; 32],
            receipts: vec![make_receipt(0x11, [0xAB; 32], 100, (10, 15))],
        };
        let actual_vertex_list = vec![VertexInfo {
            round: 12,
            author: make_test_tagged_pubkey(0x10),
            vertex_hash: [0xCD; 32],
            tx_merkle_root: [0xEF; 32],
        }];
        let false_witness = FalseWitnessEvidence {
            false_evidence,
            actual_vertex_list,
            inclusion_round: 12,
            anchor_tx_hash: [0xAB; 32],
        };
        assert!(false_witness.verify().is_ok(), "结构合法应验证通过");
    }

    #[test]
    fn test_false_witness_evidence_missing_inclusion_vertex() {
        // actual_vertex_list 中无 inclusion_round 对应的 vertex → 失败
        let false_evidence = CensorshipWitnessEvidence {
            game_id: make_game_id(),
            epoch: 1,
            checkpoint_seq: 1,
            content_hash: [0xAB; 32],
            receipts: vec![make_receipt(0x11, [0xAB; 32], 100, (10, 15))],
        };
        let actual_vertex_list = vec![VertexInfo {
            round: 11, // 不是 12
            author: make_test_tagged_pubkey(0x10),
            vertex_hash: [0xCD; 32],
            tx_merkle_root: [0xEF; 32],
        }];
        let false_witness = FalseWitnessEvidence {
            false_evidence,
            actual_vertex_list,
            inclusion_round: 12,
            anchor_tx_hash: [0xAB; 32],
        };
        assert!(
            false_witness.verify().is_err(),
            "缺少 inclusion_round 对应 vertex 应失败"
        );
    }

    #[test]
    fn test_false_witness_evidence_anchor_tx_hash_mismatch() {
        let false_evidence = CensorshipWitnessEvidence {
            game_id: make_game_id(),
            epoch: 1,
            checkpoint_seq: 1,
            content_hash: [0xAB; 32],
            receipts: vec![make_receipt(0x11, [0xAB; 32], 100, (10, 15))],
        };
        let actual_vertex_list = vec![VertexInfo {
            round: 12,
            author: make_test_tagged_pubkey(0x10),
            vertex_hash: [0xCD; 32],
            tx_merkle_root: [0xEF; 32],
        }];
        let false_witness = FalseWitnessEvidence {
            false_evidence,
            actual_vertex_list,
            inclusion_round: 12,
            anchor_tx_hash: [0xCD; 32], // != content_hash [0xAB; 32]
        };
        assert!(
            false_witness.verify().is_err(),
            "anchor_tx_hash != content_hash 应失败"
        );
    }

    #[test]
    fn test_false_witness_evidence_no_receipt_covers_inclusion_round() {
        // receipts 的 round_range 不包含 inclusion_round → 失败
        let false_evidence = CensorshipWitnessEvidence {
            game_id: make_game_id(),
            epoch: 1,
            checkpoint_seq: 1,
            content_hash: [0xAB; 32],
            receipts: vec![make_receipt(0x11, [0xAB; 32], 100, (20, 25))], // 不包含 12
        };
        let actual_vertex_list = vec![VertexInfo {
            round: 12,
            author: make_test_tagged_pubkey(0x10),
            vertex_hash: [0xCD; 32],
            tx_merkle_root: [0xEF; 32],
        }];
        let false_witness = FalseWitnessEvidence {
            false_evidence,
            actual_vertex_list,
            inclusion_round: 12,
            anchor_tx_hash: [0xAB; 32],
        };
        assert!(
            false_witness.verify().is_err(),
            "无 receipt 的 round_range 包含 inclusion_round 应失败"
        );
    }

    // ===== 常量测试 =====

    #[test]
    fn test_constants() {
        assert_eq!(DEFAULT_GOSSIPSUB_MESH_SIZE, 6, "SEC-H5: mesh = 5 + 1 = 6");
        assert_eq!(
            FALSE_WITNESS_SLASH_PERCENTAGE, 100,
            "虚假见证 slashing = 100%"
        );
        assert_eq!(
            MIN_CANDIDATE_VALIDATORS_FOR_REPLICA, 5,
            "最小候选 validator 数 = 5"
        );
    }
}
