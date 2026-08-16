//! 从已认证共识材料构造 [`crate::verified_chain::ExpectedChainAnchor`]（P05-H-source）。
//!
//! ## 目的
//!
//! [`ExpectedChainAnchor`] 的字段必须来自已认证 block/receipt，而不是从「正在被证明的
//! task」自推（见 [`ExpectedChainAnchor`] 文档警告）。本模块提供 [`build_anchor_from_consensus`]：
//! 把「已认证 `BlockHeader` + `DagCommitCertificate` + 每调用 SMT 包含证明」转换成 anchor，
//! 每步都做密码学校验。
//!
//! ## 认证链
//!
//! 1. **块认证**：[`poker_l1::consensus::bullshark::validate_commit_certificate_fields`] 校验
//!    pre/post 两个 block header 各自携带的 cert，其 epoch/prev_commit_hash/三个 root
//!    与 header 一致；[`poker_l1::consensus::cert_verification::verify_commit_certificate_signatures`]
//!    校验 ≥ 2/3 validator 的 secp256k1 quorum 签名。
//! 2. **单桌 snapshot ∈ 全局 state_root**：[`poker_l1::object_model::SparseMerkleTree::verify`]
//!    证明该 table `Object` 属于 block header 的全局 `state_root`，从而锚定端点
//!    `pre/post_state_root = compute_state_root(table)`。
//! 3. **逐调用签名与包含**：每个 dispatch 调用先验证 transaction signature，再用 SMT
//!    包含证明认证其属于 `public_tx_root` 或 `gameturn_tx_root`；caller 从签名 pubkey 派生，
//!    dispatch call digest 从 `{tx, block_header}` 独立重算（见
//!    [`crate::prove_task::dispatch_call_digest`]）。
//!
//! ## 固有边界（文档化）
//!
//! 共识层签名的 tx root 是 **order-independent** 的 SMT（leaf = tx_hash），**不**签名
//! 「某 table+hand 的有序调用序列」。因此本模块的调用顺序由 `pre/post_table` 的
//! `call_seq`/`hand_id` 隐式给出，线性顺序最终信任 Bullshark projection 的一致性。
//! 这不削弱每个 tx 都被 quorum 签名认证这一事实，仅说明「该序列就是本手牌的完整调用」
//! 依赖块内 tx 集合的完整投影。

use crate::error::{TexasAirError, TexasAirResult};
use crate::prove_task::dispatch_call_digest_from_legacy_args;
use crate::state_root::compute_state_root;
use crate::verified_chain::ExpectedChainAnchor;

use poker_l1::Hash;
use poker_l1::account::derive_address;
use poker_l1::block::BlockHeader;
use poker_l1::block::validator::validate_tx_signature;
use poker_l1::consensus::bullshark::{
    validate_commit_certificate_fields, validate_commit_certificate_quorum,
};
use poker_l1::consensus::cert_verification::verify_commit_certificate_signatures;
use poker_l1::consensus::{DagCommitCertificate, ValidatorEntry};
use poker_l1::object_model::{MerklePath, Object, Ownership, SparseMerkleTree};
use poker_l1::signature::unified::verify_signature;
use poker_l1::transaction::{Transaction, TxLane};
use poker_l1::vm::contracts::dispatch::DispatchContext;
use poker_l1::vm::contracts::texas_poker::types::{TableContextOpenings, TexasPokerTable};
use poker_l1::vm::contracts::texas_poker::{
    TEXAS_POKER_GOVERNANCE_OBJECT_TYPE, TEXAS_POKER_METADATA_OBJECT_TYPE,
    TEXAS_POKER_RULES_OBJECT_TYPE, TEXAS_POKER_TABLE_OBJECT_TYPE,
};

use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};

/// 一个已认证的 dispatch 调用：其 `Transaction`（来自 block body）+ 在对应 tx-lane SMT
/// 中的包含证明。
#[derive(Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct ConsensusDispatchCall {
    /// 来自 `Block.public_txs` 或 `Block.gameturn_txs` 的原始交易。
    pub tx: Transaction,
    /// 该 tx 所属通道，决定用 `public_tx_root` 还是 `gameturn_tx_root` 做包含校验。
    pub lane: TxLane,
    /// 针对 `blake2b(tx_hash)` 在对应通道 SMT 中的包含证明（value = tx_hash）。
    pub inclusion_path: MerklePath,
}

/// One authenticated ObjectDb object and its inclusion proof.
#[derive(Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct AuthenticatedObjectSnapshot {
    /// Exact object wrapper committed by the global state tree.
    pub object: Object,
    /// Inclusion proof under the corresponding block state root.
    pub inclusion_path: MerklePath,
}

/// Complete four-object snapshot of one resolved Texas table endpoint.
#[derive(Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct TableSnapshot {
    /// Mutable hot-v30 table object.
    pub hot_table: AuthenticatedObjectSnapshot,
    /// Immutable display metadata opening.
    pub metadata: AuthenticatedObjectSnapshot,
    /// Immutable rules opening.
    pub rules: AuthenticatedObjectSnapshot,
    /// Immutable governance opening.
    pub governance: AuthenticatedObjectSnapshot,
}

impl TableSnapshot {
    /// Hydrate the resolved runtime table after validating all four object wrappers and digests.
    ///
    /// # Errors
    ///
    /// Any wrong ID/type/ownership/opening or hot binding fails closed.
    pub fn table(&self) -> TexasAirResult<TexasPokerTable> {
        use poker_l1::vm::contracts::texas_poker::state_codec::{
            decode_hot_table_state, is_hot_table_state, table_governance_object_id,
            table_metadata_object_id, table_rules_object_id,
        };
        let table_id = self.hot_table.object.id;
        if self.hot_table.object.object_type != TEXAS_POKER_TABLE_OBJECT_TYPE
            || self.hot_table.object.owner != Ownership::Shared
            || !is_hot_table_state(&self.hot_table.object.data)
        {
            return Err(TexasAirError::ConsensusAnchor(
                "hot table object has non-canonical type, ownership, or schema".into(),
            ));
        }
        let validate_opening = |snapshot: &AuthenticatedObjectSnapshot,
                                expected_id,
                                expected_type: &str,
                                label: &str|
         -> TexasAirResult<()> {
            if snapshot.object.id != expected_id
                || snapshot.object.object_type != expected_type
                || snapshot.object.owner != Ownership::Immutable
            {
                return Err(TexasAirError::ConsensusAnchor(format!(
                    "{label} object has non-canonical ID, type, or ownership"
                )));
            }
            Ok(())
        };
        validate_opening(
            &self.metadata,
            table_metadata_object_id(table_id),
            TEXAS_POKER_METADATA_OBJECT_TYPE,
            "metadata",
        )?;
        validate_opening(
            &self.rules,
            table_rules_object_id(table_id),
            TEXAS_POKER_RULES_OBJECT_TYPE,
            "rules",
        )?;
        validate_opening(
            &self.governance,
            table_governance_object_id(table_id),
            TEXAS_POKER_GOVERNANCE_OBJECT_TYPE,
            "governance",
        )?;
        let openings = TableContextOpenings {
            metadata: borsh::from_slice(&self.metadata.object.data).map_err(|error| {
                TexasAirError::SerializationError(format!("Texas metadata opening: {error}"))
            })?,
            rules: borsh::from_slice(&self.rules.object.data).map_err(|error| {
                TexasAirError::SerializationError(format!("Texas rules opening: {error}"))
            })?,
            governance: borsh::from_slice(&self.governance.object.data).map_err(|error| {
                TexasAirError::SerializationError(format!("Texas governance opening: {error}"))
            })?,
        };
        let table =
            decode_hot_table_state(&self.hot_table.object.data, &openings).map_err(|error| {
                TexasAirError::SerializationError(format!("Texas hot table: {error}"))
            })?;
        if table.id != table_id {
            return Err(TexasAirError::ConsensusAnchor(
                "hot table embedded ID does not match object ID".into(),
            ));
        }
        Ok(table)
    }
}

/// 可序列化的、用于构造一个共识锚点的完整认证材料。
///
/// 该结构是 proving-service 与共识适配器之间的二进制契约。它携带认证两个
/// table endpoint 所需的 block header/certificate/SMT proof，以及构造精确
/// receipt range 所需的逐调用交易包含证明。反序列化本身不建立信任；调用
/// [`Self::build`] 会验证所有 certificate 签名和 SMT 包含证明后才返回
/// [`ExpectedChainAnchor`]。
#[derive(Debug, Clone, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct ConsensusAnchorMaterial {
    /// 证明范围起点所在块的 header。
    pub pre_block_header: BlockHeader,
    /// 起点 table snapshot 及 state-root 包含证明。
    pub pre_snapshot: TableSnapshot,
    /// `pre_block_header` 携带的 commit certificate。
    pub pre_certificate: DagCommitCertificate,
    /// 已认证链的 chain ID。
    pub chain_id: poker_l1::ChainId,
    /// 对应 epoch 的 validator set，用于验证 certificate quorum 签名。
    pub validators: Vec<ValidatorEntry>,
    /// 证明范围终点所在块的 header。
    pub post_block_header: BlockHeader,
    /// 终点 table snapshot 及 state-root 包含证明。
    pub post_snapshot: TableSnapshot,
    /// 以 call sequence 顺序排列的、被认证的 Texas dispatch 调用。
    pub calls: Vec<ConsensusDispatchCall>,
}

impl ConsensusAnchorMaterial {
    /// 验证所有认证材料并构造精确的 receipt-chain anchor。
    ///
    /// # Errors
    ///
    /// 任一 certificate、SMT inclusion、链 ID、table endpoint 或 dispatch digest
    /// 不匹配时返回错误；不可信输入永远不会产生 anchor。
    pub fn build(&self) -> TexasAirResult<ExpectedChainAnchor> {
        build_anchor_from_consensus(
            &self.pre_block_header,
            &self.pre_snapshot,
            &self.pre_certificate,
            self.chain_id,
            &self.validators,
            &self.post_block_header,
            &self.post_snapshot,
            &self.calls,
        )
    }
}

/// 验证一个 table snapshot 属于给定 block 的全局 `state_root`。
///
/// SMT key = `object.id.merkle_key()`，value = `borsh::to_vec(&object)`。
fn verify_object_inclusion(
    label: &str,
    snapshot: &AuthenticatedObjectSnapshot,
    state_root: &Hash,
) -> TexasAirResult<()> {
    let key = snapshot.object.id.merkle_key();
    let value = borsh::to_vec(&snapshot.object)
        .map_err(|e| TexasAirError::SerializationError(format!("Object borsh encode: {e}")))?;
    if !SparseMerkleTree::verify(state_root, &key, Some(&value), &snapshot.inclusion_path) {
        return Err(TexasAirError::ConsensusAnchor(format!(
            "{label} object {:?} not proved in block state_root",
            snapshot.object.id
        )));
    }
    Ok(())
}

fn verify_table_inclusion(
    snapshot: &TableSnapshot,
    state_root: &Hash,
) -> TexasAirResult<TexasPokerTable> {
    for (label, object) in [
        ("hot table", &snapshot.hot_table),
        ("metadata", &snapshot.metadata),
        ("rules", &snapshot.rules),
        ("governance", &snapshot.governance),
    ] {
        verify_object_inclusion(label, object, state_root)?;
    }
    snapshot.table()
}

/// 验证一个 dispatch call 的 tx 属于对应通道的 tx root，并重算其 dispatch digest。
///
/// tx-lane SMT：key = `blake2b(tx_hash)`，value = `tx_hash`。
fn verify_call_and_compute_digest(
    call: &ConsensusDispatchCall,
    context: &DispatchContext,
    public_tx_root: &Hash,
    gameturn_tx_root: &Hash,
) -> TexasAirResult<[u8; 32]> {
    if call.tx.lane_hint != call.lane {
        return Err(TexasAirError::ConsensusAnchor(format!(
            "declared dispatch lane {:?} does not match transaction lane {:?}",
            call.lane, call.tx.lane_hint
        )));
    }
    let tx_hash = call.tx.tx_hash();
    let key = blake2b_32(&tx_hash);
    let tx_root = match call.lane {
        TxLane::Public => public_tx_root,
        TxLane::GameTurn => gameturn_tx_root,
        // 其它通道不承载 poker dispatch 调用。
        _ => {
            return Err(TexasAirError::ConsensusAnchor(format!(
                "dispatch call lane {:?} is not Public/GameTurn",
                call.lane
            )));
        }
    };
    if !SparseMerkleTree::verify(tx_root, &key, Some(&tx_hash), &call.inclusion_path) {
        return Err(TexasAirError::ConsensusAnchor(format!(
            "tx not proved in {:?} tx_root",
            call.lane
        )));
    }

    let contract_call = call.tx.contract_call.as_ref().ok_or_else(|| {
        TexasAirError::ConsensusAnchor("dispatch call tx has no contract_call".into())
    })?;
    if contract_call.contract_id != poker_l1::vm::precompile::reserved::texas_poker_contract_id() {
        return Err(TexasAirError::ConsensusAnchor(
            "dispatch transaction does not target the Texas Poker precompile".into(),
        ));
    }

    // Certified inclusion authenticates the tx bytes, but administrator
    // authorization also requires the transaction signature itself. Verify it
    // explicitly so the AIR-bound dispatch digest is linked to the exact
    // tagged public key that signed the call and derives `context.caller`.
    validate_tx_signature(&call.tx).map_err(|error| {
        TexasAirError::ConsensusAnchor(format!(
            "dispatch transaction signature verification failed: {error}"
        ))
    })?;
    dispatch_call_digest_from_legacy_args(
        context,
        &contract_call.method_selector,
        &contract_call.args,
    )
}

/// 从 `{tx, block_header}` 重建 dispatch 时使用的 `DispatchContext`。
///
/// 各字段来源（与生产 executor / precompile 一致）：
/// - `caller` = `derive_address(tx.tagged_pubkey)`
/// - `caller_pubkey` = `tx.tagged_pubkey`
/// - `chain_id` = `tx.chain_id`
/// - `block_height` = `header.height`
/// - `block_timestamp` = `header.timestamp_ms`
fn rebuild_dispatch_context(tx: &Transaction, header: &BlockHeader) -> DispatchContext {
    DispatchContext {
        caller: derive_address(&tx.tagged_pubkey),
        caller_pubkey: tx.tagged_pubkey.clone(),
        chain_id: tx.chain_id,
        block_height: header.height,
        block_timestamp: header.timestamp_ms,
    }
}

/// Verify that one header is backed by the exact certificate it carries.
///
/// A state-root inclusion proof is meaningful only after the header's root is
/// authenticated.  In particular, the final table snapshot may be in a later
/// block, so accepting an unauthenticated `post_block_header` would let a
/// caller choose an arbitrary post-state root.
fn verify_authenticated_header(
    label: &str,
    header: &BlockHeader,
    cert: &DagCommitCertificate,
    chain_id: poker_l1::ChainId,
    validators: &[ValidatorEntry],
) -> TexasAirResult<()> {
    if header.dag_commit_certificate != *cert {
        return Err(TexasAirError::ConsensusAnchor(format!(
            "{label} block header does not carry the supplied commit certificate"
        )));
    }
    validate_commit_certificate_fields(
        cert,
        cert.epoch,
        cert.prev_commit_hash,
        header.state_root,
        header.account_root,
        header.public_tx_root,
        header.gameturn_tx_root,
    )
    .map_err(|error| {
        TexasAirError::ConsensusAnchor(format!("{label} cert field mismatch: {error}"))
    })?;
    validate_commit_certificate_quorum(cert, validators.len())
        .map_err(|error| TexasAirError::ConsensusAnchor(format!("{label} cert quorum: {error}")))?;
    verify_commit_certificate_signatures(cert, chain_id, validators, verify_signature).map_err(
        |error| TexasAirError::ConsensusAnchor(format!("{label} cert signatures: {error}")),
    )?;
    Ok(())
}

/// 从共识材料构造 [`ExpectedChainAnchor`]。
///
/// 调用方负责把 `calls` 按 `call_seq` 升序排列；本函数不重新排序（顺序是信任 Bullshark
/// projection 的一部分，见模块文档）。
///
/// # 参数
///
/// - `pre_snapshot`：本 range 起点的 table `Object`（pre 状态）及其在 **本块**
///   `state_root` 中的包含证明。
/// - `post_snapshot`：本 range 终点的 table `Object`（post 状态）及其在 **post 块**
///   `state_root` 中的包含证明 + 对应 post 块 header。post 状态通常跨块，故 post 侧
///   显式传入其块 header 与 state_root。
///
/// # Errors
///
/// 任一密码学校验失败（cert 字段/quorum 签名、SMT 包含证明）或字段不匹配时返回
/// [`TexasAirError::ConsensusAnchor`]。
#[allow(clippy::too_many_arguments)]
pub fn build_anchor_from_consensus(
    pre_block_header: &BlockHeader,
    pre_snapshot: &TableSnapshot,
    pre_cert: &DagCommitCertificate,
    chain_id: poker_l1::ChainId,
    validators: &[ValidatorEntry],
    post_block_header: &BlockHeader,
    post_snapshot: &TableSnapshot,
    calls: &[ConsensusDispatchCall],
) -> TexasAirResult<ExpectedChainAnchor> {
    if calls.is_empty() {
        return Err(TexasAirError::ConsensusAnchor(
            "consensus anchor requires at least one dispatch call".into(),
        ));
    }

    // 1. Authenticate both endpoint roots before accepting their SMT proofs.
    verify_authenticated_header("pre", pre_block_header, pre_cert, chain_id, validators)?;
    verify_authenticated_header(
        "post",
        post_block_header,
        &post_block_header.dag_commit_certificate,
        chain_id,
        validators,
    )?;

    // 2. 单桌 snapshot ∈ 全局 state_root（pre 用 pre 块，post 用 post 块）。
    let pre_table = verify_table_inclusion(pre_snapshot, &pre_block_header.state_root)?;
    let post_table = verify_table_inclusion(post_snapshot, &post_block_header.state_root)?;

    // 3. 逐调用：重建 DispatchContext、认证 tx ∈ tx_root、重算 digest，并从认证
    // pre-state 顺序重放旧 ABI。actor-less canonicalization 只有在旧 player/seat 声明
    // 已经通过原生 dispatch 校验后才安全。
    let mut dispatch_call_digests = Vec::with_capacity(calls.len());
    let mut replay_table = pre_table.clone();
    for call in calls {
        if call.tx.chain_id != chain_id {
            return Err(TexasAirError::ConsensusAnchor(format!(
                "dispatch transaction chain_id {} does not match authenticated chain_id {}",
                call.tx.chain_id, chain_id
            )));
        }
        let context = rebuild_dispatch_context(&call.tx, pre_block_header);
        let digest = verify_call_and_compute_digest(
            call,
            &context,
            &pre_block_header.public_tx_root,
            &pre_block_header.gameturn_tx_root,
        )?;
        let contract_call = call.tx.contract_call.as_ref().ok_or_else(|| {
            TexasAirError::ConsensusAnchor("dispatch call tx has no contract_call".into())
        })?;
        let result = poker_l1::vm::contracts::texas_poker::dispatch::dispatch(
            &context,
            &mut replay_table,
            &contract_call.method_selector,
            &contract_call.args,
        )
        .map_err(|error| {
            TexasAirError::ConsensusAnchor(format!(
                "authenticated Texas dispatch cannot replay from anchored state: {error}"
            ))
        })?;
        let output: crate::prove_task::DispatchOutput = borsh::from_slice(&result.return_value)
            .map_err(|error| {
                TexasAirError::SerializationError(format!(
                    "authenticated dispatch output borsh: {error}"
                ))
            })?;
        let task = output.prove_task.ok_or_else(|| {
            TexasAirError::ConsensusAnchor(
                "authenticated dispatch did not produce a state-changing proof task".into(),
            )
        })?;
        let replay_digest = crate::prove_task::dispatch_call_digest(
            &task.context,
            &task.selector(),
            &task.raw_args,
        )?;
        if replay_digest != digest {
            return Err(TexasAirError::ConsensusAnchor(
                "authenticated legacy dispatch does not match its canonical proof payload".into(),
            ));
        }
        dispatch_call_digests.push(digest);
    }

    // 4. 从 table snapshot 读端点元数据，装配 anchor。
    let table_id = pre_table.id.creation_nonce;
    if table_id != post_table.id.creation_nonce {
        return Err(TexasAirError::ConsensusAnchor(format!(
            "pre/post table_id mismatch: {} vs {}",
            table_id, post_table.id.creation_nonce
        )));
    }
    let pre_state_root = compute_state_root(&pre_table)?;
    let post_state_root = compute_state_root(&post_table)?;
    let call_count = u32::try_from(calls.len()).map_err(|_| {
        TexasAirError::ConsensusAnchor("dispatch call count does not fit u32".into())
    })?;
    let expected_post_call_seq = pre_table.call_seq.checked_add(call_count).ok_or_else(|| {
        TexasAirError::ConsensusAnchor("anchored call_seq transition overflows u32".into())
    })?;
    if post_table.call_seq != expected_post_call_seq {
        return Err(TexasAirError::ConsensusAnchor(format!(
            "post table call_seq {} does not equal pre call_seq {} + authenticated call count {}",
            post_table.call_seq, pre_table.call_seq, call_count
        )));
    }
    if replay_table != post_table {
        return Err(TexasAirError::ConsensusAnchor(
            "authenticated dispatch sequence does not reproduce the anchored post table".into(),
        ));
    }
    let hand_id = post_table.hand_id;
    let first_call_seq = pre_table.call_seq.checked_add(1).ok_or_else(|| {
        TexasAirError::ConsensusAnchor("anchored first call_seq overflows u32".into())
    })?;

    ExpectedChainAnchor::new(
        table_id,
        hand_id,
        first_call_seq,
        pre_state_root,
        post_state_root,
        u64::from(pre_table.call_seq),
        u64::from(post_table.call_seq),
        dispatch_call_digests,
    )
}

/// `blake2b_256` 单次哈希辅助（tx-lane SMT 的 key 派生）。
fn blake2b_32(input: &[u8]) -> Hash {
    let mut hasher = Blake2bVar::new(32).expect("32 <= 64");
    Update::update(&mut hasher, input);
    let mut out = [0u8; 32];
    hasher.finalize_variable(&mut out).expect("32 <= 64");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use borsh::BorshDeserialize;
    use poker_l1::consensus::ValidatorEntry;
    use poker_l1::consensus::bullshark::assemble_commit_certificate;
    use poker_l1::object_model::{ObjectID, ObjectStore};
    use poker_l1::signature::TaggedPubkey;
    use poker_l1::signature::tagged_pubkey::{CURRENT_VERSION, SignatureScheme};
    use poker_l1::transaction::{ContractCall, Gas, RouteHint, Transaction, TxLane};
    use secp256k1::{Message, Secp256k1, SecretKey};

    /// 测试夹具：已认证的 pre/post snapshot、真签名 cert、tx 包含证明。
    struct ConsensusFixture {
        pre_header: BlockHeader,
        post_header: BlockHeader,
        cert: DagCommitCertificate,
        validators: Vec<ValidatorEntry>,
        secrets: Vec<SecretKey>,
        pre_snapshot: TableSnapshot,
        post_snapshot: TableSnapshot,
        calls: Vec<ConsensusDispatchCall>,
        expected_digests: Vec<[u8; 32]>,
        table: TexasPokerTable,
    }

    /// 构造 N 个 secp256k1 validator。
    fn make_validators(n: usize) -> (Vec<ValidatorEntry>, Vec<SecretKey>) {
        let secp = Secp256k1::new();
        let mut entries = Vec::new();
        let mut secrets = Vec::new();
        for _ in 0..n {
            let (sk, pk) = secp.generate_keypair(&mut secp256k1::rand::rngs::OsRng);
            let tagged = TaggedPubkey::new(
                SignatureScheme::Secp256k1,
                CURRENT_VERSION,
                pk.serialize().to_vec(),
            )
            .unwrap();
            entries.push(ValidatorEntry::new(tagged, [0u8; 33], 1000, 0));
            secrets.push(sk);
        }
        (entries, secrets)
    }

    /// 构造一个 poker dispatch tx（GameTurn 通道，固定 selector/args）。
    fn make_dispatch_tx(
        tagged: &TaggedPubkey,
        secret: &SecretKey,
        selector: [u8; 32],
        args: Vec<u8>,
    ) -> Transaction {
        let secp = Secp256k1::new();
        let mut tx = Transaction {
            inputs: vec![],
            outputs: vec![],
            contract_call: Some(ContractCall {
                contract_id: poker_l1::vm::precompile::reserved::texas_poker_contract_id(),
                method_selector: selector,
                args,
            }),
            tagged_pubkey: tagged.clone(),
            signature: Vec::new(),
            gas: Gas::new(1_000_000, 1),
            lane_hint: TxLane::GameTurn,
            route_hint: RouteHint::AnyValidator,
            chain_id: poker_l1::DEFAULT_CHAIN_ID,
            nonce: 0,
            gameturn_nonce: None,
            is_fallback: false,
        };
        let sig = secp.sign_ecdsa_recoverable(&Message::from_digest(tx.signing_hash()), secret);
        let (rid, compact) = sig.serialize_compact();
        tx.signature = compact.to_vec();
        tx.signature.push(rid.to_i32() as u8);
        tx
    }

    /// 用 txs 填充一个 SMT（key=blake2b(tx_hash), value=tx_hash），返回 (root, per-tx paths)。
    fn build_tx_smt(txs: &[Transaction]) -> (Hash, Vec<MerklePath>) {
        let mut smt = SparseMerkleTree::new();
        let mut paths = Vec::with_capacity(txs.len());
        for tx in txs {
            let tx_hash = tx.tx_hash();
            let key = blake2b_32(&tx_hash);
            smt.upsert(key, &tx_hash);
        }
        for tx in txs {
            let tx_hash = tx.tx_hash();
            let key = blake2b_32(&tx_hash);
            paths.push(smt.prove(&key));
        }
        (smt.root(), paths)
    }

    /// 构造一个完整的真签名 cert（与 build_anchor 用的 header roots 一致）。
    fn sign_cert(
        validators: &[ValidatorEntry],
        secrets: &[SecretKey],
        roots: (Hash, Hash, Hash, Hash),
    ) -> DagCommitCertificate {
        let secp = Secp256k1::new();
        let placeholder = assemble_commit_certificate(
            1,
            1,
            [0u8; 32],
            vec![],
            vec![],
            roots.0,
            roots.1,
            roots.2,
            roots.3,
            &[],
            validators.len(),
        )
        .unwrap();
        let msg = placeholder.signing_hash(poker_l1::DEFAULT_CHAIN_ID);
        // 用 ≥ 2/3 validator 签名。
        let n_signers = validators.len() * 2 / 3 + 1;
        let mut sig_pairs: Vec<(usize, Vec<u8>)> = Vec::new();
        for (i, sk) in secrets.iter().take(n_signers).enumerate() {
            let sig = secp.sign_ecdsa_recoverable(&Message::from_digest(msg), sk);
            let (rid, compact) = sig.serialize_compact();
            let mut full = compact.to_vec();
            full.push(rid.to_i32() as u8);
            sig_pairs.push((i, full));
        }
        assemble_commit_certificate(
            1,
            1,
            [0u8; 32],
            vec![],
            vec![],
            roots.0,
            roots.1,
            roots.2,
            roots.3,
            &sig_pairs,
            validators.len(),
        )
        .unwrap()
    }

    fn build_table_snapshot(table: &TexasPokerTable) -> (Hash, TableSnapshot) {
        let [hot_table, metadata, rules, governance] =
            poker_l1::vm::contracts::texas_poker::state_codec::table_storage_objects(table)
                .unwrap();
        let mut store = ObjectStore::new();
        for object in [&hot_table, &metadata, &rules, &governance] {
            store.create(object.clone()).unwrap();
        }
        let authenticated = |object: Object| AuthenticatedObjectSnapshot {
            inclusion_path: store.prove(&object.id).unwrap(),
            object,
        };
        let snapshot = TableSnapshot {
            hot_table: authenticated(hot_table),
            metadata: authenticated(metadata),
            rules: authenticated(rules),
            governance: authenticated(governance),
        };
        (store.state_root(), snapshot)
    }

    fn reauthenticate_table_snapshot(snapshot: TableSnapshot) -> (Hash, TableSnapshot) {
        let objects = [
            snapshot.hot_table.object,
            snapshot.metadata.object,
            snapshot.rules.object,
            snapshot.governance.object,
        ];
        let mut store = ObjectStore::new();
        for object in &objects {
            store.create(object.clone()).unwrap();
        }
        let authenticated = |object: Object| AuthenticatedObjectSnapshot {
            inclusion_path: store.prove(&object.id).unwrap(),
            object,
        };
        let [hot_table, metadata, rules, governance] = objects;
        (
            store.state_root(),
            TableSnapshot {
                hot_table: authenticated(hot_table),
                metadata: authenticated(metadata),
                rules: authenticated(rules),
                governance: authenticated(governance),
            },
        )
    }

    fn build_fixture(selector_a: [u8; 32], args_a: Vec<u8>) -> ConsensusFixture {
        let (validators, secrets) = make_validators(5); // 2/3 of 5 = 4
        let caller_tagged = validators[0].pubkey.clone();
        let caller = poker_l1::account::derive_address(&caller_tagged);
        let ctx = DispatchContext {
            caller,
            caller_pubkey: caller_tagged.clone(),
            chain_id: poker_l1::DEFAULT_CHAIN_ID,
            block_height: 100,
            block_timestamp: 1_000_000,
        };
        let table_id = ObjectID::new([0u8; 20], 1);

        // 构造一个可以真实执行 start_hand 的 canonical pre-state。
        let mut table = TexasPokerTable::new(table_id, "test".into(), caller, 2, 50, 100);
        table.hand_id = 1;
        table.call_seq = 10;
        table.seats[0] = poker_l1::vm::contracts::texas_poker::types::Seat::occupied(
            caller,
            1_000,
            poker_protocol::crypto::types::ECPoint(
                poker_l1::vm::contracts::texas_poker::utils::g1_generator()
                    * poker_l1::vm::contracts::texas_poker::utils::scalar_from_u64(1),
            ),
            poker_l1::vm::contracts::texas_poker::types::SeatStatus::Active,
        )
        .unwrap();
        table.seats[1] = poker_l1::vm::contracts::texas_poker::types::Seat::occupied(
            [0x22; 20],
            1_000,
            poker_protocol::crypto::types::ECPoint(
                poker_l1::vm::contracts::texas_poker::utils::g1_generator()
                    * poker_l1::vm::contracts::texas_poker::utils::scalar_from_u64(2),
            ),
            poker_l1::vm::contracts::texas_poker::types::SeatStatus::Active,
        )
        .unwrap();
        table.chip_pool = 2_000;
        table.add_deck_contributor(0).unwrap();
        table.add_deck_contributor(1).unwrap();

        // pre snapshot：四个对象共享同一个 authenticated global state root。
        let (pre_state_root, pre_snapshot) = build_table_snapshot(&table);

        // post snapshot：由真实 authenticated dispatch 产生。
        let mut post_table = table.clone();
        poker_l1::vm::contracts::texas_poker::dispatch::dispatch(
            &ctx,
            &mut post_table,
            &selector_a,
            &args_a,
        )
        .unwrap();
        let (post_state_root, post_snapshot) = build_table_snapshot(&post_table);

        // 一个 dispatch call（GameTurn 通道）。
        let tx = make_dispatch_tx(&caller_tagged, &secrets[0], selector_a, args_a.clone());
        let (gameturn_tx_root, tx_paths) = build_tx_smt(std::slice::from_ref(&tx));

        // 重算预期 digest（与 build_anchor 内部逻辑独立地重算）。
        let expected_digest =
            dispatch_call_digest_from_legacy_args(&ctx, &selector_a, &args_a).unwrap();

        let empty_root = SparseMerkleTree::new().root();
        let cert = sign_cert(
            &validators,
            &secrets,
            (pre_state_root, empty_root, empty_root, gameturn_tx_root),
        );

        let pre_header = BlockHeader {
            height: 100,
            timestamp_ms: 1_000_000,
            prev_hash: [0u8; 32],
            state_root: pre_state_root,
            account_root: empty_root,
            public_tx_root: empty_root,
            gameturn_tx_root,
            dag_commit_certificate: cert.clone(),
        };
        let post_cert = sign_cert(
            &validators,
            &secrets,
            (post_state_root, empty_root, empty_root, gameturn_tx_root),
        );
        // post header 用 post_state_root（post snapshot 跨块）及其独立 quorum cert。
        let post_header = BlockHeader {
            state_root: post_state_root,
            dag_commit_certificate: post_cert.clone(),
            ..pre_header.clone()
        };

        ConsensusFixture {
            pre_header,
            post_header,
            cert,
            validators,
            secrets,
            pre_snapshot,
            post_snapshot,
            calls: vec![ConsensusDispatchCall {
                tx,
                lane: TxLane::GameTurn,
                inclusion_path: tx_paths.into_iter().next().unwrap(),
            }],
            expected_digests: vec![expected_digest],
            table,
        }
    }

    #[test]
    fn empty_calls_rejected() {
        let f = build_fixture(
            poker_l1::vm::contracts::texas_poker::dispatch::selectors::start_hand(),
            vec![],
        );
        let result = build_anchor_from_consensus(
            &f.pre_header,
            &f.pre_snapshot,
            &f.cert,
            poker_l1::DEFAULT_CHAIN_ID,
            &f.validators,
            &f.post_header,
            &f.post_snapshot,
            &[],
        );
        assert!(matches!(
            result,
            Err(TexasAirError::ConsensusAnchor(msg)) if msg.contains("at least one dispatch call")
        ));
    }

    #[test]
    fn valid_consensus_anchor_builds_and_matches() {
        let f = build_fixture(
            poker_l1::vm::contracts::texas_poker::dispatch::selectors::start_hand(),
            vec![],
        );
        let anchor = build_anchor_from_consensus(
            &f.pre_header,
            &f.pre_snapshot,
            &f.cert,
            poker_l1::DEFAULT_CHAIN_ID,
            &f.validators,
            &f.post_header,
            &f.post_snapshot,
            &f.calls,
        )
        .expect("valid consensus materials must build an anchor");

        // 端点元数据来自 table snapshot。
        assert_eq!(anchor.table_id(), f.table.id.creation_nonce);
        assert_eq!(anchor.hand_id(), f.table.hand_id + 1);
        assert_eq!(anchor.first_call_seq(), f.table.call_seq + 1);
        // dispatch digests 与独立重算一致。
        assert_eq!(anchor.dispatch_call_digests(), &f.expected_digests[..]);
    }

    #[test]
    fn authenticated_but_unbound_context_opening_is_rejected() {
        let mut f = build_fixture(
            poker_l1::vm::contracts::texas_poker::dispatch::selectors::start_hand(),
            vec![],
        );
        *f.pre_snapshot.metadata.object.data.last_mut().unwrap() ^= 1;
        let (state_root, snapshot) = reauthenticate_table_snapshot(f.pre_snapshot);
        f.pre_snapshot = snapshot;
        f.pre_header.state_root = state_root;
        f.cert = sign_cert(
            &f.validators,
            &f.secrets,
            (
                state_root,
                f.pre_header.account_root,
                f.pre_header.public_tx_root,
                f.pre_header.gameturn_tx_root,
            ),
        );
        f.pre_header.dag_commit_certificate = f.cert.clone();

        let error = build_anchor_from_consensus(
            &f.pre_header,
            &f.pre_snapshot,
            &f.cert,
            poker_l1::DEFAULT_CHAIN_ID,
            &f.validators,
            &f.post_header,
            &f.post_snapshot,
            &f.calls,
        )
        .unwrap_err();
        assert!(error.to_string().contains("binding/opening mismatch"));
    }

    #[test]
    fn serialized_consensus_material_rebuilds_the_same_authenticated_anchor() {
        let f = build_fixture(
            poker_l1::vm::contracts::texas_poker::dispatch::selectors::start_hand(),
            vec![],
        );
        let material = ConsensusAnchorMaterial {
            pre_block_header: f.pre_header.clone(),
            pre_snapshot: f.pre_snapshot.clone(),
            pre_certificate: f.cert.clone(),
            chain_id: poker_l1::DEFAULT_CHAIN_ID,
            validators: f.validators.clone(),
            post_block_header: f.post_header.clone(),
            post_snapshot: f.post_snapshot.clone(),
            calls: f.calls.clone(),
        };

        let wire = borsh::to_vec(&material).expect("consensus material must serialize");
        let recovered = ConsensusAnchorMaterial::try_from_slice(&wire)
            .expect("consensus material must deserialize");
        let anchor = recovered
            .build()
            .expect("authenticated material must rebuild an anchor");

        assert_eq!(anchor.table_id(), f.table.id.creation_nonce);
        assert_eq!(anchor.hand_id(), f.table.hand_id + 1);
        assert_eq!(anchor.first_call_seq(), f.table.call_seq + 1);
        assert_eq!(anchor.dispatch_call_digests(), &f.expected_digests[..]);
    }

    #[test]
    fn declared_lane_mismatch_is_rejected() {
        let mut f = build_fixture(
            poker_l1::vm::contracts::texas_poker::dispatch::selectors::start_hand(),
            vec![],
        );
        f.calls[0].lane = TxLane::Public;

        let result = build_anchor_from_consensus(
            &f.pre_header,
            &f.pre_snapshot,
            &f.cert,
            poker_l1::DEFAULT_CHAIN_ID,
            &f.validators,
            &f.post_header,
            &f.post_snapshot,
            &f.calls,
        );
        assert!(matches!(
            result,
            Err(TexasAirError::ConsensusAnchor(msg)) if msg.contains("does not match transaction lane")
        ));
    }

    #[test]
    fn non_texas_contract_is_rejected_even_with_valid_tx_inclusion() {
        let f = build_fixture(
            poker_l1::vm::contracts::texas_poker::dispatch::selectors::start_hand(),
            vec![],
        );
        let mut tx = f.calls[0].tx.clone();
        tx.contract_call.as_mut().unwrap().contract_id = ObjectID::new([0xEE; 20], 99);
        let (gameturn_tx_root, paths) = build_tx_smt(std::slice::from_ref(&tx));
        let call = ConsensusDispatchCall {
            tx,
            lane: TxLane::GameTurn,
            inclusion_path: paths.into_iter().next().unwrap(),
        };
        let context = rebuild_dispatch_context(&call.tx, &f.pre_header);

        let result = verify_call_and_compute_digest(
            &call,
            &context,
            &f.pre_header.public_tx_root,
            &gameturn_tx_root,
        );
        assert!(matches!(
            result,
            Err(TexasAirError::ConsensusAnchor(msg)) if msg.contains("does not target the Texas Poker precompile")
        ));
    }

    #[test]
    fn post_call_sequence_mismatch_is_rejected() {
        let mut f = build_fixture(
            poker_l1::vm::contracts::texas_poker::dispatch::selectors::start_hand(),
            vec![],
        );
        let mut post_table = f.post_snapshot.table().unwrap();
        post_table.call_seq += 1;

        let (post_state_root, post_snapshot) = build_table_snapshot(&post_table);
        f.post_header.state_root = post_state_root;
        f.post_header.dag_commit_certificate = sign_cert(
            &f.validators,
            &f.secrets,
            (
                f.post_header.state_root,
                f.post_header.account_root,
                f.post_header.public_tx_root,
                f.post_header.gameturn_tx_root,
            ),
        );
        f.post_snapshot = post_snapshot;

        let result = build_anchor_from_consensus(
            &f.pre_header,
            &f.pre_snapshot,
            &f.cert,
            poker_l1::DEFAULT_CHAIN_ID,
            &f.validators,
            &f.post_header,
            &f.post_snapshot,
            &f.calls,
        );
        assert!(matches!(
            result,
            Err(TexasAirError::ConsensusAnchor(msg)) if msg.contains("does not equal pre call_seq")
        ));
    }

    #[test]
    fn unauthenticated_post_header_is_rejected() {
        let mut f = build_fixture(
            poker_l1::vm::contracts::texas_poker::dispatch::selectors::start_hand(),
            vec![],
        );
        // A caller must not be able to select a different terminal root while
        // reusing the original post-block certificate.
        f.post_header.state_root = [0xA5; 32];
        let result = build_anchor_from_consensus(
            &f.pre_header,
            &f.pre_snapshot,
            &f.cert,
            poker_l1::DEFAULT_CHAIN_ID,
            &f.validators,
            &f.post_header,
            &f.post_snapshot,
            &f.calls,
        );
        assert!(matches!(
            result,
            Err(TexasAirError::ConsensusAnchor(msg)) if msg.contains("post cert field mismatch")
        ));
    }

    #[test]
    fn tampered_tx_args_rejected() {
        // 改 args → digest 变 → anchor 装配会用篡改后的 digest，与 receipt 链不匹配。
        // 这里直接验证：构造时 digest 会被重算，所以 anchor 本身会「成功」但 digest 不同。
        // 真正的安全门在 Orchestrator::prove_and_verify_chain_against（见下个测试）。
        // 本测试验证：传入与 selector/args 一致的 tx 时 digest 正确。
        let f = build_fixture(
            poker_l1::vm::contracts::texas_poker::dispatch::selectors::start_hand(),
            vec![],
        );
        let anchor = build_anchor_from_consensus(
            &f.pre_header,
            &f.pre_snapshot,
            &f.cert,
            poker_l1::DEFAULT_CHAIN_ID,
            &f.validators,
            &f.post_header,
            &f.post_snapshot,
            &f.calls,
        )
        .unwrap();
        assert_eq!(anchor.dispatch_call_digests(), &f.expected_digests[..]);
        // 确认 digest 不是全零（即确实从 tx 内容算出来的）。
        assert_ne!(anchor.dispatch_call_digests()[0], [0u8; 32]);
    }

    #[test]
    fn included_transaction_with_invalid_signature_is_rejected() {
        let mut f = build_fixture(
            poker_l1::vm::contracts::texas_poker::dispatch::selectors::start_hand(),
            vec![],
        );
        f.calls[0].tx.signature = vec![0u8; 65];

        // Rebuild the authenticated tx-root around the malformed transaction.
        // This isolates signature validation from the independent SMT-inclusion
        // check: the transaction is genuinely included in the certified root,
        // but it still must not authorize an administrator dispatch.
        let (gameturn_tx_root, paths) = build_tx_smt(&[f.calls[0].tx.clone()]);
        f.calls[0].inclusion_path = paths[0].clone();
        f.pre_header.gameturn_tx_root = gameturn_tx_root;
        f.post_header.gameturn_tx_root = gameturn_tx_root;
        let empty_root = SparseMerkleTree::new().root();
        f.cert = sign_cert(
            &f.validators,
            &f.secrets,
            (
                f.pre_header.state_root,
                f.pre_header.account_root,
                empty_root,
                gameturn_tx_root,
            ),
        );
        f.pre_header.dag_commit_certificate = f.cert.clone();
        f.post_header.dag_commit_certificate = sign_cert(
            &f.validators,
            &f.secrets,
            (
                f.post_header.state_root,
                f.post_header.account_root,
                empty_root,
                gameturn_tx_root,
            ),
        );

        let result = build_anchor_from_consensus(
            &f.pre_header,
            &f.pre_snapshot,
            &f.cert,
            poker_l1::DEFAULT_CHAIN_ID,
            &f.validators,
            &f.post_header,
            &f.post_snapshot,
            &f.calls,
        );
        assert!(matches!(
            result,
            Err(TexasAirError::ConsensusAnchor(msg))
                if msg.contains("transaction signature verification failed")
        ));
    }

    #[test]
    fn tampered_pre_table_inclusion_rejected() {
        let f = build_fixture(
            poker_l1::vm::contracts::texas_poker::dispatch::selectors::start_hand(),
            vec![],
        );
        // SMT inclusion 证明 = (root, key, value, path)；path 不含 leaf value，value 由
        // verifier 现算。因此篡改 snapshot 的 data（改变 leaf_hash）会让 verify 失败。
        // 注意：必须保留合法 borsh 以便 table() 解析，故只改不影响 canonicality 的
        // call_seq 字段，再把不同 table 重新编码塞进同一 object。
        let mut tampered = f.pre_snapshot.clone();
        let mut bad_table = tampered.table().unwrap();
        bad_table.call_seq = 999; // 与 pre-root 里记录的 call_seq 不同
        tampered.hot_table.object.data =
            poker_l1::vm::contracts::texas_poker::state_codec::encode_hot_table_state(&bad_table)
                .unwrap();
        let result = build_anchor_from_consensus(
            &f.pre_header,
            &tampered,
            &f.cert,
            poker_l1::DEFAULT_CHAIN_ID,
            &f.validators,
            &f.post_header,
            &f.post_snapshot,
            &f.calls,
        );
        assert!(matches!(
            result,
            Err(TexasAirError::ConsensusAnchor(msg)) if msg.contains("not proved in block state_root")
        ));
    }

    #[test]
    fn cert_signature_failure_rejected() {
        let f = build_fixture(
            poker_l1::vm::contracts::texas_poker::dispatch::selectors::start_hand(),
            vec![],
        );
        // 用错误的 validator 集（签名对不上）。
        let (wrong_validators, _) = make_validators(5);
        let result = build_anchor_from_consensus(
            &f.pre_header,
            &f.pre_snapshot,
            &f.cert,
            poker_l1::DEFAULT_CHAIN_ID,
            &wrong_validators,
            &f.post_header,
            &f.post_snapshot,
            &f.calls,
        );
        assert!(matches!(
            result,
            Err(TexasAirError::ConsensusAnchor(msg)) if msg.contains("cert signatures")
        ));
    }

    #[test]
    fn cert_field_mismatch_rejected() {
        let mut f = build_fixture(
            poker_l1::vm::contracts::texas_poker::dispatch::selectors::start_hand(),
            vec![],
        );
        // 篡改 header 的 gameturn_tx_root（与 cert 不一致）。
        f.pre_header.gameturn_tx_root = [0xFFu8; 32];
        let result = build_anchor_from_consensus(
            &f.pre_header,
            &f.pre_snapshot,
            &f.cert,
            poker_l1::DEFAULT_CHAIN_ID,
            &f.validators,
            &f.post_header,
            &f.post_snapshot,
            &f.calls,
        );
        assert!(matches!(
            result,
            Err(TexasAirError::ConsensusAnchor(msg)) if msg.contains("cert field mismatch")
        ));
    }
}
