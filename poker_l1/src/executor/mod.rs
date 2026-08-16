//! 交易执行引擎（P0 修复 — C-3：state_root 接入交易执行）。
//!
//! 参考 `solana_rbpf` 执行模型（加载 → 验证 → metering 执行 → 状态提交），
//! 将 block 内 tx 按通道路由执行并提交状态变更：
//!
//! - **Public / ForceSync 通道**：account nonce 校验 + gas 计费（`apply_public_tx`）。
//!   `contract_call` 优先路由至预编译合约（[`PrecompileRegistry`]），未注册则走 rBPF
//!   [`execute_contract`]；`outputs` 直接创建对象。
//! - **GameTurn / CheckpointAnchor 通道**（gas-free lane）：必须配 gas-free 预编译合约
//!   （`Precompile::is_gas_free() == true`）。executor 强制 lane-contract 一致性：
//!   gas-free lane 调用非 gas-free 合约 → 直接拒绝（防免费 gas 滥用 DoS）。
//!   gas-free 调用经 [`PrecompileRegistry::execute`] 直接派发，不经 rBPF VM。
//!
//! # 安全设计
//!
//! - **lane-contract 一致性**：gas-free lane（GameTurn / CheckpointAnchor）必须配
//!   gas-free precompile；不一致直接拒绝（防止构造 `lane=GameTurn` + 普通 rBPF 合约
//!   绕过账户/nonce/余额检查 + 获得无限 gas 的 DoS 攻击）。
//! - 执行前重跑完整校验链（limits / chain_id / 签名 / nonce），纵深防御：
//!   即使 RPC / P2P 入口校验被绕过，执行层仍拒绝非法 tx。
//! - rBPF 合约状态提交**全有或全无**：先在内存中校验所有待写对象
//!   （存在性 + 所有权 + 大小），全部通过后才落 `ObjectDb`；任一失败则
//!   整个 tx 状态不变。
//! - 通过 admission 校验后才进入执行的 tx 即使失败，也会记录确定性的 resource gas；
//!   Public / ForceSync 交易同时推进 account nonce，并按链上 fee policy 扣除失败 gas。
//!   签名、chain-id、nonce 等 admission 失败仍保持零费用且不改变状态。
//! - 创建对象校验 `ObjectID.creator_address == caller`，防止冒名创建。
//! - block 级 gas 累计超过 `block_gas_limit` 的 tx 跳过执行（状态不变）。
//!
//! # 确定性
//!
//! 同一组有序 tx + 同一初始状态 → 同一 `state_root`。出块方与验证方
//! 均通过 [`execute_block`] 得出 `state_root` 并比对（P0-2 接入）。

use crate::account::{
    Account, AccountStore, apply_public_tx_with_fee, derive_address, validate_public_tx,
};
use crate::block::validator::{validate_tx_chain_id, validate_tx_signature};
use crate::consensus::validator_set::replace_persisted_validator_set;
use crate::consensus::{
    SlashingConfig, VALIDATOR_UNBONDING_DELAY_BLOCKS, ValidatorSet, ValidatorSystemCall,
};
use crate::economics::{
    burn_escrowed_native, consume_native_coin_selection, create_native_coin_output,
    select_owned_native_coins, transfer_native_coins,
};
use crate::error::{PokerL1Error, PokerL1Result};
use crate::governance::{
    GovernanceSystemCall, PrecompileGovernanceSystemCall, ValidatorBondEscrow,
    ValidatorBondGovernanceSystemCall, ValidatorKeyRotationSystemCall,
    decode_governance_state_object, read_validator_bond_escrow, replace_persisted_governance_state,
    write_validator_bond_escrow,
};
use crate::object_model::{Object, ObjectID, Ownership};
use crate::offline::zk_verifier::ZkVerifierRegistry;
use crate::storage::{ObjectBackend, ObjectDb, TransactionalObjectBackend};
use crate::transaction::{Transaction, TxLane, validate_tx_limits};

/// 原生 UTXO 转账参数。
///
/// Wallets place the sender's selected native coin IDs in `Transaction.inputs`. Execution deletes
/// those immutable UTXOs and creates an exact recipient output plus deterministic sender change.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    borsh::BorshSerialize,
    borsh::BorshDeserialize,
)]
pub struct TransferArgs {
    /// 接收方地址。
    pub recipient: Address,
    /// 转账金额。
    pub amount: u64,
}

/// Resolve a signature key from historical evidence to the currently staked validator identity.
///
/// Evidence itself is verified against its embedded (possibly old) key first.  This mapping is
/// only for locating the escrow which remains slashable after an epoch-bound key rotation.
fn resolve_slashing_validator_key<B: ObjectBackend>(
    object_db: &B,
    chain_id: ChainId,
    evidence_key: &crate::signature::TaggedPubkey,
) -> PokerL1Result<crate::signature::TaggedPubkey> {
    Ok(
        crate::consensus::read_validator_key_history(object_db, chain_id)?
            .map(|(history, _)| history.resolve_current(evidence_key))
            .transpose()?
            .unwrap_or_else(|| evidence_key.clone()),
    )
}

/// Execute one consensus validator-state transition inside a transaction-local ObjectDb child.
///
/// This function intentionally has no Node reference.  Everything it needs is either signed by
/// the caller, derived from the block environment, or read from the immutable ValidatorSet system
/// object in `object_db`.  Consequently block production and replay use exactly the same path.
fn execute_validator_system_call<B: ObjectBackend>(
    env: &ExecutionEnvironment,
    tx: &Transaction,
    object_db: &mut B,
    _caller: Address,
    command: ValidatorSystemCall,
) -> PokerL1Result<Vec<ObjectID>> {
    let snapshot = env.validator_set_snapshot.as_ref().ok_or_else(|| {
        PokerL1Error::Other(
            "validator system calls require a candidate ValidatorSet snapshot".into(),
        )
    })?;
    let mut set = snapshot.lock().unwrap_or_else(|error| error.into_inner());
    let current = set.clone();
    let mut next = current.clone();
    let mut created = Vec::new();

    match command {
        ValidatorSystemCall::Bond { .. } => {
            // Validator signatures currently carry one vote each, rather than a stake-weighted
            // vote.  Accepting arbitrary bonded identities under that model lets one party split
            // a small balance into many registrations and obtain a certificate quorum.  Until a
            // stake-weighted validator-set transition is itself governed and committed on chain,
            // production membership is the immutable genesis allowlist.  Do not leave a
            // seemingly economic `Bond` call as an accidental Sybil-admission path.
            //
            // This is intentionally an execution-time rejection (rather than relying on the
            // RPC/P2P admission path), so every block replay enforces the same rule.  Existing
            // validators may still unbond and valid equivocation evidence may still slash them.
            return Err(PokerL1Error::Other(
                "permissionless validator bonding is disabled: validator membership is the genesis allowlist until stake-weighted governance is activated".into(),
            ));
        }
        ValidatorSystemCall::BeginUnbonding => {
            if !tx.inputs.is_empty() {
                return Err(PokerL1Error::Other(
                    "begin-unbonding must not consume coin inputs".into(),
                ));
            }
            let deadline = env
                .block_height
                .checked_add(VALIDATOR_UNBONDING_DELAY_BLOCKS)
                .ok_or_else(|| {
                    PokerL1Error::Other("validator unbonding deadline overflow".into())
                })?;
            next.start_unbonding(&tx.tagged_pubkey, deadline)?;
        }
        ValidatorSystemCall::DestroyVrfKey => {
            if !tx.inputs.is_empty() {
                return Err(PokerL1Error::Other(
                    "destroy-vrf-key must not consume coin inputs".into(),
                ));
            }
            next.mark_vrf_key_destroyed(&tx.tagged_pubkey)?;
        }
        ValidatorSystemCall::CompleteUnbonding { validator } => {
            if !tx.inputs.is_empty() {
                return Err(PokerL1Error::Other(
                    "complete-unbonding must not consume coin inputs".into(),
                ));
            }
            let refund = next
                .find_validator(&validator)
                .ok_or_else(|| PokerL1Error::ValidatorNotInSet(validator.clone()))?
                .stake;
            next.finalize_unbonding(&validator, env.block_height)?;
            if refund > 0 {
                let owner = derive_address(&validator);
                created.push(create_native_coin_output(
                    object_db,
                    owner,
                    refund,
                    &tx.tx_hash(),
                    0,
                )?);
                let retired = next
                    .find_validator_mut(&validator)
                    .ok_or_else(|| PokerL1Error::ValidatorNotInSet(validator.clone()))?;
                retired.stake = 0;
            }
        }
        ValidatorSystemCall::SlashVertexEquivocation { evidence } => {
            if !tx.inputs.is_empty() {
                return Err(PokerL1Error::Other(
                    "slashing evidence must not consume coin inputs".into(),
                ));
            }
            if evidence.chain_id != env.chain_id {
                return Err(PokerL1Error::Other(
                    "slashing evidence chain-id mismatch".into(),
                ));
            }
            evidence.validate()?;
            let slash_target =
                resolve_slashing_validator_key(object_db, env.chain_id, &evidence.author)?;
            let result = crate::consensus::apply_slashing(
                &mut next,
                &slash_target,
                evidence.to_reason(),
                &SlashingConfig::default(),
            )?;
            burn_escrowed_native(object_db, result.slash_amount)?;
        }
        ValidatorSystemCall::SlashCommitCertificateEquivocation { evidence } => {
            if !tx.inputs.is_empty() {
                return Err(PokerL1Error::Other(
                    "slashing evidence must not consume coin inputs".into(),
                ));
            }
            if evidence.chain_id != env.chain_id {
                return Err(PokerL1Error::Other(
                    "slashing evidence chain-id mismatch".into(),
                ));
            }
            evidence.validate()?;
            let slash_target =
                resolve_slashing_validator_key(object_db, env.chain_id, &evidence.author)?;
            let result = crate::consensus::apply_slashing(
                &mut next,
                &slash_target,
                evidence.to_reason(),
                &SlashingConfig::default(),
            )?;
            burn_escrowed_native(object_db, result.slash_amount)?;
        }
    }

    next.validator_set_hash = next.compute_hash();
    replace_persisted_validator_set(object_db, env.chain_id, &current, &next)?;
    *set = next;
    Ok(created)
}

/// Execute one consensus governance transition inside a transaction-local ObjectDb child.
///
/// The governance singleton is always read from the transaction's object backend, never from a
/// node-local cache. This keeps block production, replay, and snapshot recovery on exactly the
/// same authoritative state transition.
fn execute_governance_system_call<B: ObjectBackend>(
    env: &ExecutionEnvironment,
    tx: &Transaction,
    object_db: &mut B,
    command: GovernanceSystemCall,
) -> PokerL1Result<()> {
    let validator_snapshot = env.validator_set_snapshot.as_ref().ok_or_else(|| {
        PokerL1Error::Other(
            "governance system calls require a candidate ValidatorSet snapshot".into(),
        )
    })?;
    let validator_set = validator_snapshot
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let caller_is_active = validator_set
        .find_validator(&tx.tagged_pubkey)
        .is_some_and(|validator| validator.can_participate_consensus());
    if !caller_is_active {
        return Err(PokerL1Error::ValidatorNotInSet(tx.tagged_pubkey.clone()));
    }
    let validator_count = validator_set.validators.len();
    let current_validator_set = validator_set.clone();
    drop(validator_set);

    let object = object_db.read(&crate::governance::GOVERNANCE_STATE_OBJECT_ID)?;
    let current = decode_governance_state_object(&object, env.chain_id)?;
    let mut next = current.clone();
    match command {
        GovernanceSystemCall::CreateParameterProposal {
            param,
            new_value,
            target_chain_id,
        } => {
            next.create_parameter_proposal(
                param,
                new_value,
                target_chain_id,
                tx.tagged_pubkey.clone(),
                env.block_height,
                env.chain_id,
            )?;
        }
        GovernanceSystemCall::CreateFeePolicyProposal { policy } => {
            next.create_fee_policy_proposal(policy, tx.tagged_pubkey.clone(), env.block_height)?;
        }
        GovernanceSystemCall::CreateValidatorSetUpdateProposal {
            additions,
            removals,
            effective_epoch,
        } => {
            // A validator addition must be backed by NativeCoin inputs and remain accounted for
            // while it is waiting for the target epoch.  The current governance wire format has
            // no escrow/input commitment, so accepting `additions` here would create a proposal
            // whose later epoch transition necessarily violates native-supply reconciliation.
            // Reject it at admission until the versioned bond-escrow transaction is implemented;
            // removals remain supported and continue through the existing unbonding path.
            if !additions.is_empty() {
                return Err(PokerL1Error::Other(
                    "validator additions are disabled until a NativeCoin-backed governance bond escrow is available"
                        .into(),
                ));
            }
            next.create_validator_set_update_proposal(
                &current_validator_set,
                additions,
                removals,
                effective_epoch,
                tx.tagged_pubkey.clone(),
                env.block_height,
            )?;
        }
        GovernanceSystemCall::Vote {
            proposal_id,
            approve,
        } => next.vote(
            proposal_id,
            tx.tagged_pubkey.clone(),
            approve,
            env.block_height,
        )?,
        GovernanceSystemCall::FinalizeVoting { proposal_id } => {
            next.finalize_voting(proposal_id, validator_count, env.block_height)?;
        }
        GovernanceSystemCall::ExecuteProposal { proposal_id } => {
            let fee_policy_change =
                next.proposals
                    .get(&proposal_id)
                    .and_then(|proposal| match &proposal.kind {
                        crate::governance::ProposalKind::FeePolicyChange { policy } => {
                            Some(*policy)
                        }
                        _ => None,
                    });
            let precompile_change =
                next.proposals
                    .get(&proposal_id)
                    .and_then(|proposal| match &proposal.kind {
                        crate::governance::ProposalKind::PrecompileUpgrade {
                            precompile_id,
                            new_version,
                        } => Some((*precompile_id, Some(*new_version), None)),
                        crate::governance::ProposalKind::PrecompileStatusChange {
                            precompile_id,
                            status,
                        } => Some((*precompile_id, None, Some(*status))),
                        _ => None,
                    });
            next.execute_proposal(proposal_id, env.block_height)?;
            if let Some(policy) = fee_policy_change {
                let fee_object = object_db.read(&crate::economics::FEE_POLICY_OBJECT_ID)?;
                crate::economics::decode_fee_policy(&fee_object, env.chain_id)?;
                let next_version = fee_object.version.checked_add(1).ok_or_else(|| {
                    PokerL1Error::Other("FeePolicy object version overflow".into())
                })?;
                object_db.replace_system_object(crate::economics::fee_policy_object(
                    env.chain_id,
                    policy,
                    next_version,
                )?)?;
            }
            if let Some((precompile_id, pending_version, status)) = precompile_change {
                let registry = env.precompile_registry.as_ref().ok_or_else(|| {
                    PokerL1Error::Other(
                        "precompile governance execution requires the node native registry".into(),
                    )
                })?;
                let (mut precompile_state, previous_version) =
                    crate::vm::precompile::read_precompile_governance_state(
                        object_db,
                        env.chain_id,
                    )?;
                if let Some(new_version) = pending_version {
                    if !registry.has_implementation(precompile_id, new_version) {
                        return Err(PokerL1Error::Other(format!(
                            "node lacks precompile {precompile_id:?} version {new_version} approved by governance"
                        )));
                    }
                    let activation_height = env.block_height.checked_add(1).ok_or_else(|| {
                        PokerL1Error::Other("precompile activation height overflow".into())
                    })?;
                    precompile_state.schedule_upgrade(
                        precompile_id,
                        new_version,
                        activation_height,
                    )?;
                }
                if let Some(status) = status {
                    precompile_state.set_status(precompile_id, status)?;
                }
                crate::vm::precompile::replace_precompile_governance_state(
                    object_db,
                    &precompile_state,
                    previous_version,
                )?;
            }
        }
    }
    replace_persisted_governance_state(object_db, env.chain_id, &current, &next)
}

/// Create a native-precompile governance proposal after verifying that the release is available
/// in this protocol binary and that the target is already a committed system precompile.
fn execute_precompile_governance_system_call<B: ObjectBackend>(
    env: &ExecutionEnvironment,
    tx: &Transaction,
    object_db: &mut B,
    command: PrecompileGovernanceSystemCall,
) -> PokerL1Result<()> {
    let validator_snapshot = env.validator_set_snapshot.as_ref().ok_or_else(|| {
        PokerL1Error::Other(
            "precompile governance calls require a candidate ValidatorSet snapshot".into(),
        )
    })?;
    let validator_set = validator_snapshot
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if !validator_set
        .find_validator(&tx.tagged_pubkey)
        .is_some_and(|validator| validator.can_participate_consensus())
    {
        return Err(PokerL1Error::ValidatorNotInSet(tx.tagged_pubkey.clone()));
    }
    drop(validator_set);

    let governance_object = object_db.read(&crate::governance::GOVERNANCE_STATE_OBJECT_ID)?;
    let current_governance = decode_governance_state_object(&governance_object, env.chain_id)?;
    let (precompile_state, _) =
        crate::vm::precompile::read_precompile_governance_state(object_db, env.chain_id)?;
    let registry = env.precompile_registry.as_ref().ok_or_else(|| {
        PokerL1Error::Other("precompile governance calls require the node native registry".into())
    })?;
    let mut next_governance = current_governance.clone();
    match command {
        PrecompileGovernanceSystemCall::CreateUpgradeProposal {
            precompile_id,
            new_version,
        } => {
            let activation = precompile_state.activation(precompile_id)?;
            if new_version <= activation.active_version
                || !registry.has_implementation(precompile_id, new_version)
            {
                return Err(PokerL1Error::Other(format!(
                    "precompile release {precompile_id:?} version {new_version} is not a newer local implementation"
                )));
            }
            next_governance.create_precompile_upgrade_proposal(
                precompile_id,
                new_version,
                tx.tagged_pubkey.clone(),
                env.block_height,
            )?;
        }
        PrecompileGovernanceSystemCall::CreateStatusProposal {
            precompile_id,
            status,
        } => {
            precompile_state.activation(precompile_id)?;
            next_governance.create_precompile_status_proposal(
                precompile_id,
                status,
                tx.tagged_pubkey.clone(),
                env.block_height,
            )?;
        }
    }
    replace_persisted_governance_state(
        object_db,
        env.chain_id,
        &current_governance,
        &next_governance,
    )
}

/// Execute the versioned, NativeCoin-backed validator-admission governance wire.
///
/// The legacy governance contract intentionally continues to reject coin inputs and validator
/// additions.  This separate path is the only one that can create pending admission escrow, so
/// an epoch transition can prove that every new `ValidatorEntry::stake` was removed from a live
/// UTXO before it becomes consensus weight.
fn execute_validator_bond_governance_system_call<B: ObjectBackend>(
    env: &ExecutionEnvironment,
    tx: &Transaction,
    object_db: &mut B,
    caller: Address,
    command: ValidatorBondGovernanceSystemCall,
) -> PokerL1Result<Vec<ObjectID>> {
    let validator_snapshot = env.validator_set_snapshot.as_ref().ok_or_else(|| {
        PokerL1Error::Other(
            "validator-bond governance calls require a candidate ValidatorSet snapshot".into(),
        )
    })?;
    let validator_set = validator_snapshot
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let current_validator_set = validator_set.clone();
    drop(validator_set);

    let governance_object = object_db.read(&crate::governance::GOVERNANCE_STATE_OBJECT_ID)?;
    let current_governance = decode_governance_state_object(&governance_object, env.chain_id)?;
    let mut created = Vec::new();

    match command {
        ValidatorBondGovernanceSystemCall::CreateBondedValidatorSetUpdateProposal {
            additions,
            removals,
            effective_epoch,
        } => {
            if !current_validator_set
                .find_validator(&tx.tagged_pubkey)
                .is_some_and(|validator| validator.can_participate_consensus())
            {
                return Err(PokerL1Error::ValidatorNotInSet(tx.tagged_pubkey.clone()));
            }
            if additions.is_empty() {
                return Err(PokerL1Error::Other(
                    "bonded validator-set proposal requires at least one addition".into(),
                ));
            }
            let required = additions.iter().try_fold(0u64, |total, addition| {
                total.checked_add(addition.stake).ok_or_else(|| {
                    PokerL1Error::Other("validator admission bond total overflow".into())
                })
            })?;
            let selection = select_owned_native_coins(object_db, &tx.inputs, caller, required)?;

            let mut next_governance = current_governance.clone();
            let proposal_id = next_governance.create_validator_set_update_proposal(
                &current_validator_set,
                additions.clone(),
                removals,
                effective_epoch,
                tx.tagged_pubkey.clone(),
                env.block_height,
            )?;
            let (mut escrow, previous_version) =
                read_validator_bond_escrow(object_db, env.chain_id)?
                    .unwrap_or_else(|| (ValidatorBondEscrow::default(), 0));
            // `0` is also the first valid persisted version.  Keep creation and replacement
            // distinct so a fresh chain never mistakes an absent object for version zero.
            let escrow_was_present = object_db
                .read(&crate::governance::VALIDATOR_BOND_ESCROW_OBJECT_ID)
                .is_ok();
            escrow.insert_proposal(proposal_id, &additions, caller)?;

            // The difference between selected inputs and their deterministic change output is
            // now represented only by this consensus singleton.  Supply reconciliation includes
            // it until `release_activated` moves the exact same amount into ValidatorSet stake.
            if let Some(change) = consume_native_coin_selection(
                object_db,
                &selection,
                caller,
                required,
                &tx.tx_hash(),
                0,
            )? {
                created.push(change);
            }
            replace_persisted_governance_state(
                object_db,
                env.chain_id,
                &current_governance,
                &next_governance,
            )?;
            write_validator_bond_escrow(
                object_db,
                env.chain_id,
                escrow_was_present.then_some(previous_version),
                &escrow,
            )?;
        }
        ValidatorBondGovernanceSystemCall::ClaimRejectedValidatorBondRefund { proposal_id } => {
            if !tx.inputs.is_empty() {
                return Err(PokerL1Error::Other(
                    "validator bond refund must not consume coin inputs".into(),
                ));
            }
            let proposal = current_governance
                .proposals
                .get(&proposal_id)
                .ok_or_else(|| {
                    PokerL1Error::Other(format!("unknown validator bond proposal {proposal_id}"))
                })?;
            let (mut escrow, previous_version) =
                read_validator_bond_escrow(object_db, env.chain_id)?.ok_or_else(|| {
                    PokerL1Error::Other("validator bond escrow is not initialized".into())
                })?;
            let refund = escrow.claim_refund(proposal_id, caller, proposal.status)?;
            let refund_coin =
                create_native_coin_output(object_db, caller, refund, &tx.tx_hash(), 0)?;
            created.push(refund_coin);
            write_validator_bond_escrow(object_db, env.chain_id, Some(previous_version), &escrow)?;
        }
    }
    Ok(created)
}

/// Create an authenticated, governance-approved validator key-rotation proposal.
///
/// This path accepts no caller-selected old key: the signed transaction identity is the key being
/// replaced.  Actual replacement is deferred to the certificate epoch-transition path, after the
/// transition certificate has been validated with the old validator set.
fn execute_validator_key_rotation_system_call<B: ObjectBackend>(
    env: &ExecutionEnvironment,
    tx: &Transaction,
    object_db: &mut B,
    command: ValidatorKeyRotationSystemCall,
) -> PokerL1Result<()> {
    let validator_snapshot = env.validator_set_snapshot.as_ref().ok_or_else(|| {
        PokerL1Error::Other(
            "validator key-rotation calls require a candidate ValidatorSet snapshot".into(),
        )
    })?;
    let validator_set = validator_snapshot
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let old_validator = validator_set
        .find_validator(&tx.tagged_pubkey)
        .ok_or_else(|| PokerL1Error::ValidatorNotInSet(tx.tagged_pubkey.clone()))?;
    if !old_validator.can_participate_consensus() {
        return Err(PokerL1Error::Other(
            "only an active validator may propose a consensus-key rotation".into(),
        ));
    }
    let current_set = validator_set.clone();
    drop(validator_set);

    let ValidatorKeyRotationSystemCall::CreateKeyRotationProposal { new_pubkey } = command;
    // Validate both Borsh-decoded tagged-key structure and collision against the committed set.
    crate::signature::TaggedPubkey::from_bytes(&new_pubkey.to_bytes())?;
    if current_set.find_validator(&new_pubkey).is_some() {
        return Err(PokerL1Error::Other(
            "validator key rotation new public key already belongs to a validator".into(),
        ));
    }
    let object = object_db.read(&crate::governance::GOVERNANCE_STATE_OBJECT_ID)?;
    let current_governance = decode_governance_state_object(&object, env.chain_id)?;
    let mut next_governance = current_governance.clone();
    next_governance.create_key_rotation_proposal(
        tx.tagged_pubkey.clone(),
        new_pubkey,
        tx.tagged_pubkey.clone(),
        env.block_height,
    )?;
    replace_persisted_governance_state(
        object_db,
        env.chain_id,
        &current_governance,
        &next_governance,
    )
}
use crate::vm::context::{PokerL1Context, TxContext};
use crate::vm::gas_table::{BLOCK_GAS_LIMIT, MAX_OBJECT_SIZE, TX_GAS_LIMIT};
use crate::vm::{ContractObject, PrecompileRegistry, execute_contract, load_contract_bytecode};
use crate::{Address, BlockHeight, ChainId, Hash, TimestampMs};
use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

/// Re-export the consensus-committed fee policy at the historical executor path.
pub use crate::economics::FeePolicy;

#[cfg(test)]
mod parallel_tests;
pub mod schedule;
pub mod write_capture;

/// 执行环境（block 级上下文）。
#[derive(Debug, Clone)]
pub struct ExecutionEnvironment {
    /// 网络 chain_id（SEC-L4）。
    pub chain_id: ChainId,
    /// 当前 block height。
    pub block_height: BlockHeight,
    /// 当前 block timestamp（毫秒）。
    pub block_timestamp: TimestampMs,
    /// block gas 上限（默认 [`BLOCK_GAS_LIMIT`] = 50M）。
    pub block_gas_limit: u64,
    /// ZK verifier 注册表（合约内 `zk_verify` syscall 使用；`None` 时该 syscall 报错）。
    pub zk_verifier: Option<ZkVerifierRegistry>,
    /// 预编译合约注册表（用于路由预编译合约调用）。
    pub precompile_registry: Option<Arc<PrecompileRegistry>>,
    /// Bridge registry store（缺口 #9：bridge_verify 铸币路径用）。
    ///
    /// `None` 时 bridge contract_call 被拒绝（节点未配置桥）。生产节点注入持久化 store。
    pub bridge_registry_store: Option<Arc<crate::storage::BridgeRegistryStore>>,
    /// Isolated bridge nonce state for the candidate block currently being executed.
    ///
    /// Bridge verification consumes a replay-protection nonce.  It must never mutate the live
    /// registry while an object/account transaction can still fail, so production block paths
    /// inject a snapshot created by [`crate::storage::BridgeRegistryStore::create_snapshot`].
    /// A bridge call without this snapshot fails closed.
    pub bridge_registry_snapshot: Option<Arc<Mutex<crate::storage::BridgeRegistrySnapshot>>>,
    /// Isolated ValidatorSet for one candidate block.
    ///
    /// Validator system calls update this clone and replace the corresponding immutable system
    /// object in the same object transaction.  The node installs the clone only after the block
    /// journal has made all stores durable.
    pub validator_set_snapshot: Option<Arc<Mutex<ValidatorSet>>>,
    /// 出块 proposer 地址（用于执行上下文和后续证明/统计，不产生货币奖励）。
    pub proposer: Option<Address>,
    /// Chain-wide resource-credit policy. This does not disable gas metering.
    pub fee_policy: FeePolicy,
}

impl ExecutionEnvironment {
    /// 创建执行环境（使用默认 block gas limit）。
    #[must_use]
    pub fn new(chain_id: ChainId, block_height: BlockHeight, block_timestamp: TimestampMs) -> Self {
        Self {
            chain_id,
            block_height,
            block_timestamp,
            block_gas_limit: BLOCK_GAS_LIMIT,
            zk_verifier: None,
            precompile_registry: None,
            bridge_registry_store: None,
            bridge_registry_snapshot: None,
            validator_set_snapshot: None,
            proposer: None,
            fee_policy: FeePolicy::Free,
        }
    }

    /// Select the resource-credit policy while preserving compute metering.
    #[must_use]
    pub const fn with_fee_policy(mut self, fee_policy: FeePolicy) -> Self {
        self.fee_policy = fee_policy;
        self
    }

    /// 注入 ZK verifier 注册表（builder 模式）。
    #[must_use]
    pub fn with_zk_verifier(mut self, registry: ZkVerifierRegistry) -> Self {
        self.zk_verifier = Some(registry);
        self
    }

    /// 注入预编译合约注册表（builder 模式）。
    #[must_use]
    pub fn with_precompile_registry(mut self, registry: PrecompileRegistry) -> Self {
        self.precompile_registry = Some(Arc::new(registry));
        self
    }

    /// 注入预编译合约注册表（Arc 共享，builder 模式）。
    ///
    /// 与 [`Self::with_precompile_registry`] 的区别：直接接受 `Arc<PrecompileRegistry>`，
    /// 适合 `Node` 持有共享 registry、每个 block 执行时 clone Arc 引用而非重建注册表。
    #[must_use]
    pub fn with_precompile_registry_arc(mut self, registry: Arc<PrecompileRegistry>) -> Self {
        self.precompile_registry = Some(registry);
        self
    }

    /// 注入 Bridge registry store（缺口 #9：bridge 铸币路径）。
    #[must_use]
    pub fn with_bridge_registry_store(
        mut self,
        store: Arc<crate::storage::BridgeRegistryStore>,
    ) -> Self {
        self.bridge_registry_store = Some(store);
        self
    }

    /// Inject the isolated bridge state for one candidate block.
    #[must_use]
    pub fn with_bridge_registry_snapshot(
        mut self,
        snapshot: Arc<Mutex<crate::storage::BridgeRegistrySnapshot>>,
    ) -> Self {
        self.bridge_registry_snapshot = Some(snapshot);
        self
    }

    /// Inject the candidate block's validator-set snapshot.
    #[must_use]
    pub fn with_validator_set_snapshot(mut self, snapshot: Arc<Mutex<ValidatorSet>>) -> Self {
        self.validator_set_snapshot = Some(snapshot);
        self
    }

    /// 注入出块 proposer 地址。
    #[must_use]
    pub fn with_proposer(mut self, proposer: Address) -> Self {
        self.proposer = Some(proposer);
        self
    }

    /// 覆盖 block gas limit（测试用）。
    #[must_use]
    pub const fn with_block_gas_limit(mut self, limit: u64) -> Self {
        self.block_gas_limit = limit;
        self
    }
}

/// 单笔 tx 执行回执。
#[derive(Debug, Clone)]
pub struct TxReceipt {
    /// tx 哈希（`signing_hash`，含 chain_id 域）。
    pub tx_hash: Hash,
    /// tx 通道。
    pub lane: TxLane,
    /// 是否执行成功（状态变更仅在 success=true 时提交）。
    pub success: bool,
    /// 失败原因（success=false 时为 `Some`）。
    pub error: Option<String>,
    /// 实际消耗的 block resource gas。GameTurn 可免 caller fee，但 host-native
    /// precompile work 仍会计入此字段。
    pub gas_used: u64,
    /// 实际消耗的不可转让 resource credits；默认免收费时为 0。
    pub fee_charged: u64,
    /// 本 tx 创建的对象 ID。
    pub created_objects: Vec<ObjectID>,
    /// 本 tx 修改的对象 ID。
    pub modified_objects: Vec<ObjectID>,
}

impl TxReceipt {
    /// 构造 admission 失败回执（无 gas、无状态变更）。
    fn failure(tx: &Transaction, err: &PokerL1Error) -> Self {
        Self::failure_with_gas(tx, err, 0, 0)
    }

    /// 构造已进入执行阶段的失败回执。
    fn failure_with_gas(
        tx: &Transaction,
        err: &PokerL1Error,
        gas_used: u64,
        fee_charged: u64,
    ) -> Self {
        Self {
            tx_hash: tx.signing_hash(),
            lane: tx.lane_hint,
            success: false,
            error: Some(err.to_string()),
            gas_used,
            fee_charged,
            created_objects: Vec::new(),
            modified_objects: Vec::new(),
        }
    }
}

/// Block 执行结果。
#[derive(Debug, Clone)]
pub struct BlockExecutionOutcome {
    /// 每笔 tx 的回执（与输入顺序一致）。
    pub receipts: Vec<TxReceipt>,
    /// 执行全部 tx 后的全局状态根（ObjectDb SMT root）。
    pub state_root: Hash,
    /// Deterministic commitment of AccountStore (balances, resource credits and replay nonces).
    pub account_root: Hash,
    /// block 累计消耗的 resource gas。所有通过 admission 并实际执行的交易都会计入，
    /// 包括失败交易和免 caller fee 的 GameTurn / CheckpointAnchor native precompile。
    pub total_gas_used: u64,
}

/// 执行单笔 tx（骨架版，P0-1）。
///
/// 失败语义：admission 失败返回零 gas、零状态变更回执；已进入执行阶段后失败时，
/// 合约对象状态回滚，但仍记录实际 block resource gas。Public / ForceSync 还会推进
/// account nonce，并按 [`FeePolicy`] 结算 caller fee；gas-free lane 不推进 account
/// nonce、也不扣 caller fee。本函数本身不返回 `Err`，所有执行级错误都转化为回执，
/// 保证 block 内后续 tx 继续执行。
///
/// # 参数
///
/// - `env`：执行环境（chain_id / height / timestamp / gas limit / ZK registry）
/// - `tx`：待执行交易
/// - `object_db`：对象数据库（直接可变引用，由调用方持有锁）
/// - `account_store`：账户存储
pub fn execute_tx<B: TransactionalObjectBackend>(
    env: &ExecutionEnvironment,
    tx: &Transaction,
    object_db: &mut B,
    account_store: &mut AccountStore,
) -> TxReceipt {
    // Execute all object and account mutations against private child state.  In particular, do
    // not let a late error (for example a duplicate explicit output after a precompile changed a
    // table) escape into the parent state.
    let mut object_transaction = object_db.begin_transaction();
    let mut account_transaction = account_store.create_snapshot();
    // A bridge verification may have consumed its staged nonce before a later tx operation
    // (for example an explicit-output collision) fails. Preserve and restore the entire staged
    // registry on every transaction failure; the live RocksDB registry remains untouched until
    // Node::put_block commits the completed candidate block.
    let bridge_before = env.bridge_registry_snapshot.as_ref().map(|snapshot| {
        snapshot
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    });
    let validator_set_before = env.validator_set_snapshot.as_ref().map(|snapshot| {
        snapshot
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    });
    let restore_bridge = || {
        if let (Some(snapshot), Some(before)) = (&env.bridge_registry_snapshot, &bridge_before) {
            *snapshot.lock().unwrap_or_else(|error| error.into_inner()) = before.clone();
        }
    };
    let restore_validator_set = || {
        if let (Some(snapshot), Some(before)) = (&env.validator_set_snapshot, &validator_set_before)
        {
            *snapshot.lock().unwrap_or_else(|error| error.into_inner()) = before.clone();
        }
    };
    match execute_tx_inner(env, tx, &mut object_transaction, &mut account_transaction) {
        Ok(receipt) => {
            // ObjectDb commits its child as one WriteBatch.  For an outer ObjectDbSnapshot this
            // only merges into the block candidate; durable cross-store coordination is owned by
            // Node::put_block, which commits the completed block transition.
            if let Err(error) = object_db.commit_transaction(object_transaction) {
                restore_bridge();
                restore_validator_set();
                return settle_failed_tx(env, tx, &error, account_store);
            }
            if let Err(error) = account_store.apply_snapshot(account_transaction) {
                // A persistent AccountStore failure is a node-level storage fault.  The block
                // commit journal handles recovery for production nodes; preserve deterministic
                // failure settlement for in-memory callers here.
                restore_bridge();
                restore_validator_set();
                return settle_failed_tx(env, tx, &error, account_store);
            }
            receipt
        }
        Err(err) => {
            restore_bridge();
            restore_validator_set();
            settle_failed_tx(env, tx, &err, account_store)
        }
    }
}

/// Return the deterministic resource cost of a call before executing it.
fn estimated_call_gas(env: &ExecutionEnvironment, tx: &Transaction) -> u64 {
    let Some(call) = &tx.contract_call else {
        return crate::vm::gas_table::GAS_FAILED_TX_BASE;
    };
    if let Some(registry) = &env.precompile_registry
        && registry.is_precompile(call.contract_id)
        && let Ok(cost) = registry.gas_cost(call.contract_id, &call.method_selector, &call.args)
    {
        return cost.max(crate::vm::gas_table::GAS_FAILED_TX_BASE);
    }
    crate::vm::gas_table::GAS_FAILED_TX_BASE.saturating_add(call.args.len() as u64)
}

/// Persisted replay counter for a gas-free GameTurn lane transaction.
///
/// GameTurn transactions intentionally do not use the legacy account nonce.  They still need a
/// consensus-visible counter, however, otherwise a previously signed action can be replayed after
/// the table returns to a compatible state.  The counter lives in ObjectDb so it is covered by the
/// same SMT root as the table mutation.  The deterministic ID is derived from the contract/game
/// object and caller, making the counter per-game/per-player without changing the hot-table schema.
const GAMETURN_NONCE_OBJECT_TYPE: &str = "System::GameTurnNonceV1";
const GAMETURN_NONCE_DOMAIN: &[u8] = b"zchain.gameturn_nonce.v1";

fn gameturn_nonce_object_id(tx: &Transaction) -> PokerL1Result<ObjectID> {
    let caller = derive_address(&tx.tagged_pubkey);
    let contract_id = tx
        .contract_call
        .as_ref()
        .ok_or_else(|| PokerL1Error::Other("GameTurn tx requires a contract call".into()))?
        .contract_id;
    let mut hasher = Blake2bVar::new(32).expect("32 <= 64");
    hasher.update(GAMETURN_NONCE_DOMAIN);
    hasher.update(&contract_id.to_bytes());
    hasher.update(&caller);
    let mut digest = [0u8; 32];
    hasher.finalize_variable(&mut digest).expect("32 <= 64");

    let mut creator = [0u8; 20];
    creator.copy_from_slice(&digest[..20]);
    let mut nonce_bytes = [0u8; 8];
    nonce_bytes.copy_from_slice(&digest[20..28]);
    Ok(ObjectID::new(creator, u64::from_le_bytes(nonce_bytes)))
}

fn read_gameturn_nonce<B: ObjectBackend>(
    object_db: &B,
    tx: &Transaction,
) -> PokerL1Result<(ObjectID, u64)> {
    let id = gameturn_nonce_object_id(tx)?;
    match object_db.read(&id) {
        Ok(object) => {
            if object.object_type != GAMETURN_NONCE_OBJECT_TYPE || object.owner != Ownership::Shared
            {
                return Err(PokerL1Error::Other(
                    "GameTurn nonce object has a non-canonical type or owner".into(),
                ));
            }
            let nonce = borsh::from_slice::<u64>(&object.data).map_err(|error| {
                PokerL1Error::Serialization(format!("GameTurn nonce object: {error}"))
            })?;
            Ok((id, nonce))
        }
        Err(PokerL1Error::ObjectNotFound(_)) => Ok((id, 0)),
        Err(error) => Err(error),
    }
}

fn advance_gameturn_nonce<B: ObjectBackend>(
    object_db: &mut B,
    tx: &Transaction,
    id: ObjectID,
    expected: u64,
) -> PokerL1Result<()> {
    let next = expected
        .checked_add(1)
        .ok_or_else(|| PokerL1Error::Other("GameTurn nonce overflow".into()))?;
    let data = borsh::to_vec(&next)?;
    match object_db.read(&id) {
        Ok(object) => {
            if object.object_type != GAMETURN_NONCE_OBJECT_TYPE || object.owner != Ownership::Shared
            {
                return Err(PokerL1Error::Other(
                    "GameTurn nonce object has a non-canonical type or owner".into(),
                ));
            }
            let caller = derive_address(&tx.tagged_pubkey);
            object_db.update(&id, &caller, data)
        }
        Err(PokerL1Error::ObjectNotFound(_)) => object_db.create(Object::new(
            id,
            Ownership::Shared,
            GAMETURN_NONCE_OBJECT_TYPE,
            data,
            None,
        )),
        Err(error) => Err(error),
    }
}

/// Conservative block-gas reservation used before a transaction starts executing.
///
/// Public/ForceSync transactions reserve their signed budget; gas-free lanes reserve the
/// deterministic native precompile cost. Successful and chargeable failed executions are
/// guaranteed not to exceed this value.
fn block_gas_reservation(env: &ExecutionEnvironment, tx: &Transaction) -> u64 {
    if matches!(tx.lane_hint, TxLane::GameTurn | TxLane::CheckpointAnchor) {
        estimated_call_gas(env, tx)
    } else {
        tx.gas.budget.min(TX_GAS_LIMIT)
    }
}

/// Re-run only admission checks to decide whether an execution failure is chargeable.
fn failure_passed_admission(
    env: &ExecutionEnvironment,
    tx: &Transaction,
    account_store: &AccountStore,
) -> bool {
    if validate_tx_limits(tx).is_err()
        || validate_tx_chain_id(tx, env.chain_id).is_err()
        || validate_tx_signature(tx).is_err()
    {
        return false;
    }
    let is_gameturn_lane = tx.lane_hint == TxLane::GameTurn;
    let is_checkpoint_anchor = tx.lane_hint == TxLane::CheckpointAnchor;
    let target_is_gas_free = match (&tx.contract_call, &env.precompile_registry) {
        (Some(call), Some(registry)) if registry.is_precompile(call.contract_id) => {
            registry.is_gas_free(call.contract_id)
        }
        _ => false,
    };
    if is_gameturn_lane {
        return target_is_gas_free;
    }
    let caller = derive_address(&tx.tagged_pubkey);
    account_store.get(&caller).is_some_and(|account| {
        validate_public_tx(account, tx, env.chain_id).is_ok()
            && (is_checkpoint_anchor
                || env.fee_policy == FeePolicy::Free
                || account.balance >= tx.gas.budget)
    })
}

/// Charge deterministic failure resources while preserving object-state rollback semantics.
fn settle_failed_tx(
    env: &ExecutionEnvironment,
    tx: &Transaction,
    err: &PokerL1Error,
    account_store: &mut AccountStore,
) -> TxReceipt {
    if !failure_passed_admission(env, tx, account_store) {
        return TxReceipt::failure(tx, err);
    }

    let estimated = estimated_call_gas(env, tx);
    let observed = match err {
        PokerL1Error::OutOfGas { used, .. } => *used,
        _ => 0,
    };
    let is_gameturn_lane = tx.lane_hint == TxLane::GameTurn;
    let is_checkpoint_anchor = tx.lane_hint == TxLane::CheckpointAnchor;
    let is_gas_free_lane = is_gameturn_lane || is_checkpoint_anchor;
    let gas_used = if is_gas_free_lane {
        estimated.max(observed)
    } else {
        estimated.max(observed).min(tx.gas.budget)
    };
    if is_gameturn_lane {
        return TxReceipt::failure_with_gas(tx, err, gas_used, 0);
    }

    let caller = derive_address(&tx.tagged_pubkey);
    let fee_charged = if is_checkpoint_anchor {
        0
    } else {
        env.fee_policy.caller_fee(gas_used)
    };
    let Some(account) = account_store.get_mut(&caller) else {
        return TxReceipt::failure(tx, err);
    };
    if is_checkpoint_anchor {
        account.increment_nonce();
    } else if apply_public_tx_with_fee(account, tx, gas_used, fee_charged).is_err() {
        return TxReceipt::failure(tx, err);
    }
    TxReceipt::failure_with_gas(tx, err, gas_used, fee_charged)
}

/// Execute one signed, ordinary (non-emergency) contract-upgrade system call.
///
/// The state object is committed through `replace_system_object`, so a transaction-local snapshot
/// carries it through block replay, state-root validation, and the durable ObjectDb batch.  It is
/// deliberately not a process-local `ContractRegistry` cache.
fn execute_contract_upgrade_system_call<B: ObjectBackend>(
    env: &ExecutionEnvironment,
    object_db: &mut B,
    caller: Address,
    command: crate::vm::ContractUpgradeSystemCall,
) -> PokerL1Result<(Vec<ObjectID>, Vec<ObjectID>)> {
    use crate::vm::contract::{
        CONTRACT_TYPE, ContractUpgradeState, contract_upgrade_state_id,
        contract_upgrade_state_object, decode_contract_object,
        decode_contract_upgrade_state_object,
    };

    let contract_id = match &command {
        crate::vm::ContractUpgradeSystemCall::Initiate { contract_id, .. }
        | crate::vm::ContractUpgradeSystemCall::Cancel { contract_id }
        | crate::vm::ContractUpgradeSystemCall::Dispute { contract_id } => *contract_id,
    };
    let contract_object = object_db.read(&contract_id).map_err(|error| match error {
        PokerL1Error::ObjectNotFound(_) => PokerL1Error::ContractNotFound(contract_id),
        other => other,
    })?;
    if contract_object.object_type != CONTRACT_TYPE {
        return Err(PokerL1Error::ContractNotFound(contract_id));
    }
    let contract = decode_contract_object(&contract_object)?;
    if !contract.is_active {
        return Err(PokerL1Error::ContractNotFound(contract_id));
    }
    // The timelock is a consensus parameter, never a binary-local default.  All validators read
    // the same GovernanceState from the transaction snapshot, so a governance update changes the
    // next upgrade deterministically during replay and after restart.
    let governance_object = object_db.read(&crate::governance::GOVERNANCE_STATE_OBJECT_ID)?;
    let governance =
        crate::governance::decode_governance_state_object(&governance_object, env.chain_id)?;
    let upgrade_config = crate::vm::UpgradeConfig {
        upgrade_delay_blocks: governance.params.parameter_delay_blocks,
        ..crate::vm::UpgradeConfig::default()
    };

    let state_id = contract_upgrade_state_id(env.chain_id, contract_id);
    let existing = object_db.read(&state_id).ok();
    let (mut record, state_version, was_persisted) = match existing {
        Some(object) => {
            let state = decode_contract_upgrade_state_object(&object, env.chain_id)?;
            (state, object.version, true)
        }
        None => (
            ContractUpgradeState::new(
                env.chain_id,
                contract_id,
                contract.deployer,
                contract.deployed_at_height,
            ),
            0,
            false,
        ),
    };

    match command {
        crate::vm::ContractUpgradeSystemCall::Initiate { new_bytecode, .. } => {
            crate::vm::initiate_persisted_upgrade(
                &mut record,
                &contract,
                &upgrade_config,
                caller,
                new_bytecode,
                env.block_height,
            )?;
        }
        crate::vm::ContractUpgradeSystemCall::Cancel { .. } => {
            crate::vm::cancel_persisted_upgrade(&mut record, caller)?;
        }
        crate::vm::ContractUpgradeSystemCall::Dispute { .. } => {
            crate::vm::dispute_persisted_upgrade(&mut record)?;
        }
    }

    let next_version = if was_persisted {
        state_version.checked_add(1).ok_or_else(|| {
            PokerL1Error::Other("contract upgrade state object version overflow".into())
        })?
    } else {
        0
    };
    let object = contract_upgrade_state_object(&record, next_version)?;
    if was_persisted {
        object_db.replace_system_object(object)?;
        Ok((Vec::new(), vec![state_id]))
    } else {
        object_db.system_create(object)?;
        Ok((vec![state_id], Vec::new()))
    }
}

/// `execute_tx` 内部实现（错误向上传播，由外层转为失败回执）。
fn execute_tx_inner<B: ObjectBackend>(
    env: &ExecutionEnvironment,
    tx: &Transaction,
    object_db: &mut B,
    account_store: &mut AccountStore,
) -> PokerL1Result<TxReceipt> {
    let caller = derive_address(&tx.tagged_pubkey);
    let is_gameturn_lane = tx.lane_hint == TxLane::GameTurn;
    // GameTurn 使用独立的 per-game nonce；CheckpointAnchor 虽然免 caller fee，仍使用账户
    // nonce，因此必须取得账户视图。
    let account_view: Option<&mut crate::account::Account> = if is_gameturn_lane {
        None
    } else {
        Some(account_store.get_mut(&caller).ok_or_else(|| {
            PokerL1Error::Other(format!("account not found for caller {caller:?}"))
        })?)
    };
    execute_tx_on_view_inner(env, tx, object_db, account_view)
}

/// 在单个账户视图上执行 tx 的内部实现（供串行与并行执行器共用）。
///
/// 与 [`execute_tx_inner`] 的区别：账户以 `Option<&mut Account>` 传入，而非整个
/// [`AccountStore`]。这使并行执行器可为每个 worker 提供独立的账户快照副本，
/// 波次结束后按序 merge 回主 [`AccountStore`]。
///
/// - `account_view = Some(acc)`：非 gas-free lane，需 nonce/余额预检 + 结算。
/// - `account_view = None`：gas-free lane（GameTurn / CheckpointAnchor），不触碰账户。
fn execute_tx_on_view_inner<B: ObjectBackend>(
    env: &ExecutionEnvironment,
    tx: &Transaction,
    object_db: &mut B,
    account_view: Option<&mut crate::account::Account>,
) -> PokerL1Result<TxReceipt> {
    // ===== 1. 防御性重校验（limits / chain_id / 签名）=====
    validate_tx_limits(tx)?;
    validate_tx_chain_id(tx, env.chain_id)?;
    validate_tx_signature(tx)?;

    let caller = derive_address(&tx.tagged_pubkey);
    let is_gameturn_lane = tx.lane_hint == TxLane::GameTurn;
    let is_checkpoint_anchor = tx.lane_hint == TxLane::CheckpointAnchor;
    let is_gas_free_lane = is_gameturn_lane || is_checkpoint_anchor;

    // ===== 2. 解析目标合约的 gas-free 属性 =====
    //
    // gas-free 与否由 `Precompile::is_gas_free()` 决定（注册时声明），而非 tx lane。
    // 未注册合约 / 无 contract_call → 一律视为非 gas-free（按 Public 计费）。
    let target_is_gas_free: bool = match (&tx.contract_call, &env.precompile_registry) {
        (Some(call), Some(registry)) if registry.is_precompile(call.contract_id) => {
            registry.is_gas_free(call.contract_id)
        }
        _ => false,
    };

    // ===== 3. 安全校验：gas-free lane 必须配 gas-free 预编译合约 =====
    //
    // 防止构造 `lane_hint = GameTurn` + 普通 rBPF 合约的恶意 tx：
    // 旧实现会跳过账户/nonce/余额预检 + 给予 gas_limit = u64::MAX + 不扣费不推进 nonce，
    // 即免费无限 gas DoS + 绕过 nonce 重放保护。
    if is_gas_free_lane && !target_is_gas_free {
        let contract_id_str = tx
            .contract_call
            .as_ref()
            .map(|c| format!("{:?}", c.contract_id))
            .unwrap_or_else(|| "None".to_string());
        return Err(PokerL1Error::Other(format!(
            "gas-free lane {:?} requires gas-free precompile contract; \
             got contract_id={contract_id_str}, target_is_gas_free={}",
            tx.lane_hint, target_is_gas_free,
        )));
    }

    // GameTurn replay protection is part of production execution.  The counter is keyed by the
    // target game/table contract and the authenticated caller, and is committed in ObjectDb.
    let gameturn_nonce = if is_gameturn_lane {
        let (id, expected) = read_gameturn_nonce(object_db, tx)?;
        crate::account::validate_gameturn_tx(expected, tx, env.chain_id)?;
        Some((id, expected))
    } else {
        None
    };

    // ===== 4. 账户与 nonce / 余额预检（仅非 gas-free lane 需要）=====
    //
    // gas 策略跟随 lane 而非合约属性（Assumption 3）：
    // - gas-free lane（GameTurn/CheckpointAnchor）+ gas-free precompile → 免预检
    // - 非 gas-free lane（Public/ForceSync）+ 任意合约 → 需预检
    //   （包括调 gas-free precompile 的情况：按 Public 计费、推进 nonce）
    if is_gameturn_lane {
        // The GameTurn nonce was checked above; no AccountStore access is required.
    } else if is_checkpoint_anchor {
        let account = account_view.as_ref().ok_or_else(|| {
            PokerL1Error::Other(format!("account not found for caller {caller:?}"))
        })?;
        validate_public_tx(account, tx, env.chain_id)?;
    } else {
        let account = account_view.as_ref().ok_or_else(|| {
            PokerL1Error::Other(format!("account not found for caller {caller:?}"))
        })?;
        validate_public_tx(account, tx, env.chain_id)?;
        // Charged mode reserves the signed budget. Free mode still validates nonce and budget
        // during execution but deliberately does not depend on legacy Account.balance.
        if env.fee_policy == FeePolicy::Charged && account.balance < tx.gas.budget {
            return Err(PokerL1Error::InsufficientBalance {
                needed: tx.gas.budget,
                has: account.balance,
            });
        }
    }

    // ===== 5. 分通道执行 =====
    let mut all_created: Vec<ObjectID> = Vec::new();
    let mut all_modified: Vec<ObjectID> = Vec::new();
    let mut gas_used: u64 = 0;
    if let Some(call) = &tx.contract_call {
        // 缺口 #9：Bridge 铸币路径特判（在预编译/rBPF 之前）。
        //
        // bridge contract_id 的调用不走 Precompile trait（因 bridge 需访问有状态的
        // BridgeRegistry + 铸币 + nonce 持久化，超出 trait 的 ObjectBackend 签名）。
        // executor 直接：解码 BridgeVerifyTx → bridge_verify → 铸 wrapped Object → 落 nonce。
        if call.contract_id == crate::vm::precompile::reserved::bridge_contract_id() {
            if tx.lane_hint != TxLane::Public {
                return Err(PokerL1Error::Other(
                    "bridge calls must use the signed Public lane".to_string(),
                ));
            }
            let bridge_snapshot = env
                .bridge_registry_snapshot
                .as_ref()
                .ok_or_else(|| PokerL1Error::BridgeVerifyNotAuthorized)?;
            let mut bridge_replay_changed = false;
            if call.method_selector == [0u8; 32] {
                let bridge_tx: crate::bridge::BridgeVerifyTx = borsh::from_slice(&call.args)
                    .map_err(|e| {
                        PokerL1Error::Other(format!("bridge_verify: invalid args encoding: {e}"))
                    })?;
                // bridge_verify 只可变更候选块的 isolated registry。Node::put_block 会在
                // ObjectDb / AccountStore 都 durable 后，把相同 nonce 通过 journal 原子补齐。
                let outcome = {
                    let mut snapshot = bridge_snapshot
                        .lock()
                        .unwrap_or_else(|error| error.into_inner());
                    crate::bridge::bridge_verify(
                        snapshot.registry_mut(),
                        &bridge_tx,
                        env.chain_id,
                        true,
                    )?
                };
                // The transaction hash itself is collision-resistant and deterministically
                // available to every replayer.  Fold all 256 bits into the 64-bit ObjectID nonce
                // instead of exposing a deliberately controllable low-32-bit collision domain.
                let creation_nonce = u64::from_le_bytes(tx.tx_hash()[..8].try_into().unwrap());
                let wrapped_id =
                    crate::bridge::mint_wrapped_object(&outcome, object_db, creation_nonce)?;
                all_created.push(wrapped_id);
                bridge_replay_changed = true;
            } else if call.method_selector
                == crate::vm::precompile::reserved::bridge_burn_selector()
            {
                if tx.inputs.len() != 1 {
                    return Err(PokerL1Error::BurnProofInvalid(
                        "bridge burn must consume exactly one wrapped input".to_string(),
                    ));
                }
                let burn: crate::bridge::BridgeBurnTx =
                    borsh::from_slice(&call.args).map_err(|e| {
                        PokerL1Error::Other(format!("bridge burn: invalid args encoding: {e}"))
                    })?;
                if tx.inputs[0] != burn.wrapped_object_id {
                    return Err(PokerL1Error::BurnProofInvalid(
                        "bridge burn input does not match request".to_string(),
                    ));
                }
                let mut snapshot = bridge_snapshot
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                crate::bridge::burn_wrapped_object(
                    snapshot.registry_mut(),
                    object_db,
                    caller,
                    &burn,
                    env.chain_id,
                    tx.tx_hash(),
                )?;
                bridge_replay_changed = true;
            } else if call.method_selector
                == crate::vm::precompile::reserved::bridge_config_selector()
            {
                if !tx.inputs.is_empty() || !tx.outputs.is_empty() {
                    return Err(PokerL1Error::Other(
                        "bridge configuration update must not contain inputs or outputs"
                            .to_string(),
                    ));
                }
                let update: crate::bridge::BridgeConfigUpdate = borsh::from_slice(&call.args)
                    .map_err(|error| {
                        PokerL1Error::Other(format!(
                            "bridge configuration update: invalid args encoding: {error}"
                        ))
                    })?;
                let current_object =
                    object_db.read(&crate::bridge::BRIDGE_REGISTRY_CONFIG_OBJECT_ID)?;
                let current = crate::bridge::decode_bridge_registry_config_object(
                    &current_object,
                    env.chain_id,
                )?;
                let validator_snapshot = env.validator_set_snapshot.as_ref().ok_or_else(|| {
                    PokerL1Error::Other(
                        "bridge configuration updates require a ValidatorSet snapshot".to_string(),
                    )
                })?;
                let active_validators = validator_snapshot
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .validators
                    .iter()
                    .filter(|validator| validator.can_participate_consensus())
                    .map(|validator| validator.pubkey.clone())
                    .collect();
                crate::bridge::validate_bridge_config_update(
                    &update,
                    &current,
                    current_object.version,
                    &active_validators,
                    env.chain_id,
                )?;
                let next_version = current_object.version.checked_add(1).ok_or_else(|| {
                    PokerL1Error::Other("bridge configuration version overflow".to_string())
                })?;
                object_db.replace_system_object(crate::bridge::bridge_registry_config_object(
                    &update.next_config,
                    next_version,
                )?)?;
                // Deposits later in the same serial bridge block must observe this committed
                // configuration rather than the block-start snapshot.
                bridge_snapshot
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .registry_mut()
                    .replace_slots(update.next_config.slots.clone());
            } else {
                return Err(PokerL1Error::Other(
                    "unknown bridge method selector".to_string(),
                ));
            }
            if bridge_replay_changed {
                let replay_object =
                    object_db.read(&crate::bridge::BRIDGE_REPLAY_STATE_OBJECT_ID)?;
                crate::bridge::decode_bridge_replay_state_object(&replay_object, env.chain_id)?;
                let (nonce_root, deposit_nonce_count, burn_nonce_count) = bridge_snapshot
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .registry_mut()
                    .replay_commitment();
                let state = crate::bridge::BridgeReplayState {
                    chain_id: env.chain_id,
                    nonce_root,
                    deposit_nonce_count,
                    burn_nonce_count,
                };
                let next_version = replay_object.version.checked_add(1).ok_or_else(|| {
                    PokerL1Error::Other("bridge replay state version overflow".to_string())
                })?;
                object_db.replace_system_object(crate::bridge::bridge_replay_state_object(
                    &state,
                    next_version,
                )?)?;
            }
            // bridge 调用不经 rBPF，gas_used 保持 0；步骤 6 仍按 Public lane 扣费 + 推进 nonce。
        } else if call.contract_id
            == crate::vm::precompile::reserved::validator_system_contract_id()
        {
            if tx.lane_hint != TxLane::Public {
                return Err(PokerL1Error::Other(
                    "validator system calls must use the signed Public lane".into(),
                ));
            }
            if call.method_selector != [0u8; 32] {
                return Err(PokerL1Error::Other(
                    "validator system calls require the canonical zero selector".into(),
                ));
            }
            if !tx.outputs.is_empty() {
                return Err(PokerL1Error::Other(
                    "validator system outputs are executor-derived; explicit outputs are forbidden"
                        .into(),
                ));
            }
            let command: ValidatorSystemCall = borsh::from_slice(&call.args).map_err(|error| {
                PokerL1Error::Other(format!("invalid validator system call encoding: {error}"))
            })?;
            all_created.extend(execute_validator_system_call(
                env, tx, object_db, caller, command,
            )?);
        } else if call.contract_id
            == crate::vm::precompile::reserved::governance_system_contract_id()
        {
            if tx.lane_hint != TxLane::Public {
                return Err(PokerL1Error::Other(
                    "governance system calls must use the signed Public lane".into(),
                ));
            }
            if call.method_selector != [0u8; 32] {
                return Err(PokerL1Error::Other(
                    "governance system calls require the canonical zero selector".into(),
                ));
            }
            if !tx.inputs.is_empty() || !tx.outputs.is_empty() {
                return Err(PokerL1Error::Other(
                    "governance system calls must not contain coin inputs or explicit outputs"
                        .into(),
                ));
            }
            let command: GovernanceSystemCall = borsh::from_slice(&call.args).map_err(|error| {
                PokerL1Error::Other(format!("invalid governance system call encoding: {error}"))
            })?;
            execute_governance_system_call(env, tx, object_db, command)?;
        } else if call.contract_id
            == crate::vm::precompile::reserved::validator_bond_governance_system_contract_id()
        {
            if tx.lane_hint != TxLane::Public {
                return Err(PokerL1Error::Other(
                    "validator-bond governance calls must use the signed Public lane".into(),
                ));
            }
            if call.method_selector != [0u8; 32] {
                return Err(PokerL1Error::Other(
                    "validator-bond governance calls require the canonical zero selector".into(),
                ));
            }
            if !tx.outputs.is_empty() {
                return Err(PokerL1Error::Other(
                    "validator-bond governance outputs are executor-derived; explicit outputs are forbidden"
                        .into(),
                ));
            }
            let command: ValidatorBondGovernanceSystemCall = borsh::from_slice(&call.args)
                .map_err(|error| {
                    PokerL1Error::Other(format!(
                        "invalid validator-bond governance call encoding: {error}"
                    ))
                })?;
            all_created.extend(execute_validator_bond_governance_system_call(
                env, tx, object_db, caller, command,
            )?);
        } else if call.contract_id
            == crate::vm::precompile::reserved::validator_key_rotation_system_contract_id()
        {
            if tx.lane_hint != TxLane::Public {
                return Err(PokerL1Error::Other(
                    "validator key-rotation calls must use the signed Public lane".into(),
                ));
            }
            if call.method_selector != [0u8; 32] {
                return Err(PokerL1Error::Other(
                    "validator key-rotation calls require the canonical zero selector".into(),
                ));
            }
            if !tx.inputs.is_empty() || !tx.outputs.is_empty() {
                return Err(PokerL1Error::Other(
                    "validator key-rotation calls must not contain coin inputs or explicit outputs"
                        .into(),
                ));
            }
            let command: ValidatorKeyRotationSystemCall =
                borsh::from_slice(&call.args).map_err(|error| {
                    PokerL1Error::Other(format!(
                        "invalid validator key-rotation call encoding: {error}"
                    ))
                })?;
            execute_validator_key_rotation_system_call(env, tx, object_db, command)?;
        } else if call.contract_id
            == crate::vm::precompile::reserved::contract_upgrade_system_contract_id()
        {
            if tx.lane_hint != TxLane::Public {
                return Err(PokerL1Error::Other(
                    "contract upgrade calls must use the signed Public lane".into(),
                ));
            }
            if call.method_selector != [0u8; 32] {
                return Err(PokerL1Error::Other(
                    "contract upgrade calls require the canonical zero selector".into(),
                ));
            }
            if !tx.inputs.is_empty() || !tx.outputs.is_empty() {
                return Err(PokerL1Error::Other(
                    "contract upgrade calls must not contain coin inputs or explicit outputs"
                        .into(),
                ));
            }
            let command: crate::vm::ContractUpgradeSystemCall = borsh::from_slice(&call.args)
                .map_err(|error| {
                    PokerL1Error::Other(format!(
                        "invalid contract upgrade system call encoding: {error}"
                    ))
                })?;
            let (created, modified) =
                execute_contract_upgrade_system_call(env, object_db, caller, command)?;
            all_created.extend(created);
            all_modified.extend(modified);
        } else if call.contract_id
            == crate::vm::precompile::reserved::precompile_governance_system_contract_id()
        {
            if tx.lane_hint != TxLane::Public {
                return Err(PokerL1Error::Other(
                    "precompile governance calls must use the signed Public lane".into(),
                ));
            }
            if call.method_selector != [0u8; 32] {
                return Err(PokerL1Error::Other(
                    "precompile governance calls require the canonical zero selector".into(),
                ));
            }
            if !tx.inputs.is_empty() || !tx.outputs.is_empty() {
                return Err(PokerL1Error::Other(
                    "precompile governance calls must not contain coin inputs or explicit outputs"
                        .into(),
                ));
            }
            let command: PrecompileGovernanceSystemCall =
                borsh::from_slice(&call.args).map_err(|error| {
                    PokerL1Error::Other(format!(
                        "invalid precompile governance call encoding: {error}"
                    ))
                })?;
            execute_precompile_governance_system_call(env, tx, object_db, command)?;
        } else if call.contract_id == crate::vm::precompile::reserved::transfer_contract_id() {
            // Native transfer: selected immutable UTXOs become recipient payment + sender change.
            if !tx.outputs.is_empty() {
                return Err(PokerL1Error::Other(
                    "native transfer outputs are executor-derived; explicit tx.outputs are forbidden"
                        .into(),
                ));
            }
            let args: TransferArgs = borsh::from_slice(&call.args).map_err(|e| {
                PokerL1Error::Other(format!("transfer: invalid args encoding: {e}"))
            })?;
            if args.amount == 0 {
                return Err(PokerL1Error::Other(
                    "transfer: amount must be > 0".to_string(),
                ));
            }
            let selection = select_owned_native_coins(object_db, &tx.inputs, caller, args.amount)?;
            let (recipient_output, change_output) = transfer_native_coins(
                object_db,
                &selection,
                caller,
                args.recipient,
                args.amount,
                &tx.tx_hash(),
            )?;
            all_created.push(recipient_output);
            if let Some(change_output) = change_output {
                all_created.push(change_output);
            }
            // 转账不经 rBPF，gas_used 保持 0；步骤 6 仍按 Public lane 扣费 + 推进 nonce。
        } else if let Some(registry) = &env.precompile_registry {
            // 优先检查预编译合约注册表（参考以太坊预编译合约设计）
            if registry.is_precompile(call.contract_id) {
                let precompile_gas = registry.active_gas_cost(
                    call.contract_id,
                    &call.method_selector,
                    &call.args,
                    &*object_db,
                    env.chain_id,
                )?;
                if !is_gas_free_lane && precompile_gas > tx.gas.budget {
                    return Err(PokerL1Error::OutOfGas {
                        used: precompile_gas,
                        limit: tx.gas.budget,
                    });
                }
                let precompile_env = crate::vm::precompile::ExecutionEnvironment {
                    chain_id: env.chain_id,
                    block_height: env.block_height,
                    block_timestamp: env.block_timestamp,
                    tx_inputs: tx.inputs.clone(),
                    tx_hash: tx.tx_hash(),
                };
                let selector: [u8; 32] = call.method_selector;
                let dispatch_result = registry.execute(
                    call.contract_id,
                    &caller,
                    &tx.tagged_pubkey,
                    &selector,
                    &call.args,
                    &precompile_env,
                    &mut *object_db,
                )?;
                all_created.extend(dispatch_result.created_objects);
                all_modified.extend(dispatch_result.modified_objects);
                // Native precompiles bypass rBPF instruction metering, so their deterministic
                // host resource cost is supplied by the precompile implementation.
                gas_used = precompile_gas;
            } else {
                // 非预编译合约，走 rBPF 执行
                let (created, modified, used) =
                    execute_contract_call(env, tx, &caller, call, object_db)?;
                all_created.extend(created);
                all_modified.extend(modified);
                gas_used = used;
            }
        } else {
            // 无预编译注册表，所有合约调用走 rBPF
            let (created, modified, used) =
                execute_contract_call(env, tx, &caller, call, object_db)?;
            all_created.extend(created);
            all_modified.extend(modified);
            gas_used = used;
        }
    }
    // 注：原 `else if is_gameturn` fail-closed 分支已被步骤 3 的 lane-contract
    // 一致性校验覆盖：gas-free lane 无 contract_call 时直接在步骤 3 被拒绝。

    // tx.outputs 直接创建（与 contract_call 创建的对象并列）。
    let outputs_created = apply_tx_outputs(env, tx, &caller, object_db)?;
    all_created.extend(outputs_created);

    // ===== 6. 账户 / GameTurn nonce 结算 =====
    //
    // GameTurn 成功后推进独立的 per-game/per-player nonce；CheckpointAnchor 免 caller fee
    // 但仍推进账户 nonce；Public/ForceSync 同时扣费（按策略）并推进账户 nonce。
    let fee_charged = if is_gameturn_lane {
        if let Some((id, expected)) = gameturn_nonce {
            advance_gameturn_nonce(object_db, tx, id, expected)?;
        }
        0u64
    } else {
        let account = account_view
            .ok_or_else(|| PokerL1Error::Other("account disappeared mid-execution".into()))?;
        let fee_charged = if is_checkpoint_anchor {
            0
        } else {
            env.fee_policy.caller_fee(gas_used)
        };
        if is_checkpoint_anchor {
            account.increment_nonce();
        } else {
            apply_public_tx_with_fee(account, tx, gas_used, fee_charged)?;
        }
        fee_charged
    };

    Ok(TxReceipt {
        tx_hash: tx.signing_hash(),
        lane: tx.lane_hint,
        success: true,
        error: None,
        gas_used,
        fee_charged,
        created_objects: all_created,
        modified_objects: all_modified,
    })
}

/// 执行 rBPF 合约调用并提交状态（全有或全无）。
///
/// 返回 `(created_objects, modified_objects, gas_used)`。
fn execute_contract_call<B: ObjectBackend>(
    env: &ExecutionEnvironment,
    tx: &Transaction,
    caller: &crate::Address,
    call: &crate::transaction::ContractCall,
    object_db: &mut B,
) -> PokerL1Result<(Vec<ObjectID>, Vec<ObjectID>, u64)> {
    // 1. Read and validate the executor-owned contract representation.
    //
    // Do not deserialize `data` directly here.  A caller can create an ordinary mutable object
    // whose payload happens to decode as ContractObject; treating that object as executable code
    // would bypass the immutable Contract object path and its upgrade timelock.
    let contract_obj = object_db.read(&call.contract_id).map_err(|e| match e {
        PokerL1Error::ObjectNotFound(_) => PokerL1Error::ContractNotFound(call.contract_id),
        other => other,
    })?;
    let contract =
        crate::vm::contract::decode_contract_object(&contract_obj).map_err(
            |error| match error {
                PokerL1Error::Other(_) => PokerL1Error::ContractNotFound(call.contract_id),
                other => other,
            },
        )?;
    if !contract.is_active {
        return Err(PokerL1Error::OldVersionNotCallable {
            contract_id: call.contract_id,
            version: contract.version,
        });
    }

    // 2. 加载 + RequisiteVerifier 验证字节码（IMPL-SEC-4：(1)）
    let loaded = load_contract_bytecode(&contract.bytecode, call.contract_id, contract.version)?;

    // 3. 构造执行上下文（gas_limit 按 tx.gas.budget，上限 TX_GAS_LIMIT）
    //
    // 注：gas-free precompile 已在 `execute_tx_inner` 步骤 5 走 `registry.execute`
    // 分支派发，不会进入此函数。进入此函数的 tx 一律按 Public 计费。
    // （`u64::MAX` 不再用于表示免 gas；`PokerL1Context::new` 内部会把超过
    // `TX_GAS_LIMIT` 的 gas_limit 钳制到 `TX_GAS_LIMIT`，防止 CPU DoS。）
    let gas_limit = tx.gas.budget.min(TX_GAS_LIMIT);
    let tx_ctx = TxContext {
        caller: *caller,
        caller_pubkey: tx.tagged_pubkey.clone(),
        chain_id: env.chain_id,
        nonce: tx.nonce,
        block_height: env.block_height,
        block_timestamp: env.block_timestamp,
    };
    let mut ctx = PokerL1Context::new(tx_ctx, gas_limit);
    if let Some(registry) = &env.zk_verifier {
        ctx = ctx.with_zk_verifier(registry.clone());
    }

    // 4. 预加载输入对象到 object_cache（contract_id 不预载，防止合约改写自身字节码对象）
    for id in &tx.inputs {
        let obj = object_db.read(id)?; // ObjectNotFound 直接失败
        ctx.object_cache.insert(*id, obj.data);
    }

    // 5. 执行（input = method_selector || args，合约自行解析）
    let mut input = Vec::with_capacity(call.method_selector.len() + call.args.len());
    input.extend_from_slice(&call.method_selector);
    input.extend_from_slice(&call.args);
    let result = execute_contract(&loaded, &mut ctx, &input)?;

    // 6. 全有或全无提交：先校验全部待写对象，再落库
    commit_object_cache(object_db, caller, &ctx)?;

    Ok((
        result.created_objects,
        result.modified_objects,
        result.gas_used,
    ))
}

/// 将合约执行后的 `object_cache` 提交到 `ObjectDb`（全有或全无）。
///
/// 阶段 1（只读校验）：所有待更新对象必须存在、caller 可写、数据 ≤ 64KB；
/// 所有待创建对象必须不存在（防碰撞）。
/// 阶段 2（写入）：校验全部通过后才落库。
fn commit_object_cache<B: ObjectBackend>(
    object_db: &mut B,
    caller: &crate::Address,
    ctx: &PokerL1Context,
) -> PokerL1Result<()> {
    // ----- 阶段 1：只读校验 -----
    for (id, data) in &ctx.object_cache {
        if data.len() > MAX_OBJECT_SIZE {
            return Err(PokerL1Error::ObjectTooLarge {
                actual: data.len(),
                limit: MAX_OBJECT_SIZE,
            });
        }
        if ctx.created_objects.contains(id) {
            if object_db.read(id).is_ok() {
                return Err(PokerL1Error::ObjectIDCollision(*id));
            }
        } else {
            let existing = object_db.read(id)?;
            if !existing.can_write(caller) {
                return Err(PokerL1Error::NotOwner(*id));
            }
        }
    }

    // ----- 阶段 2：写入 -----
    for (id, data) in &ctx.object_cache {
        if ctx.created_objects.contains(id) {
            let object = Object::new(
                *id,
                Ownership::AddressOwned { owner: *caller },
                "Generic",
                data.clone(),
                None,
            );
            object_db.create(object)?;
        } else {
            object_db.update(id, caller, data.clone())?;
        }
    }
    Ok(())
}

/// 创建 `tx.outputs` 中的对象。
///
/// 校验：creator 必须等于 caller（防冒名创建）、data ≤ 64KB、无 ID 碰撞。
/// 返回创建的对象 ID 列表。
fn apply_tx_outputs<B: ObjectBackend>(
    env: &ExecutionEnvironment,
    tx: &Transaction,
    caller: &crate::Address,
    object_db: &mut B,
) -> PokerL1Result<Vec<ObjectID>> {
    use crate::object_model::Ownership;
    use crate::vm::contract::{
        ContractObject, ContractUpgradeState, contract_object, contract_upgrade_state_id,
        contract_upgrade_state_object, decode_contract_object,
    };

    let output_ids: HashSet<ObjectID> = tx.outputs.iter().map(|object| object.id).collect();
    let mut reserved_companion_ids = HashSet::new();

    // 只读预检（全有或全无）
    for obj in &tx.outputs {
        if crate::economics::is_reserved_economic_object(obj) {
            return Err(PokerL1Error::Other(
                "native ZCN economic objects may only be created by treasury/escrow system paths"
                    .into(),
            ));
        }
        if obj.id.creator_address != *caller {
            return Err(PokerL1Error::Other(format!(
                "output object creator {:?} != caller {:?}",
                obj.id.creator_address, caller
            )));
        }
        if obj.data.len() > MAX_OBJECT_SIZE {
            return Err(PokerL1Error::ObjectTooLarge {
                actual: obj.data.len(),
                limit: MAX_OBJECT_SIZE,
            });
        }
        if object_db.read(&obj.id).is_ok() {
            return Err(PokerL1Error::ObjectIDCollision(obj.id));
        }
        if crate::vm::contract::is_contract_upgrade_state_object(obj) {
            return Err(PokerL1Error::Other(
                "ContractUpgradeState objects are executor-created companions, not transaction outputs"
                    .into(),
            ));
        }
        if crate::vm::contract::is_contract_object(obj) {
            if tx.lane_hint != TxLane::Public {
                return Err(PokerL1Error::Other(
                    "contract deployment must use the signed Public lane".into(),
                ));
            }
            if !matches!(obj.owner, Ownership::Immutable) || obj.version != 0 {
                return Err(PokerL1Error::Other(
                    "new contract output must be immutable and have object version zero".into(),
                ));
            }
            let contract: ContractObject = decode_contract_object(obj)?;
            if contract.deployer != *caller
                || contract.contract_id.creator_address != *caller
                || contract.version != 1
                || !contract.is_active
                || contract.deployed_at_height != env.block_height
            {
                return Err(PokerL1Error::Other(
                    "contract deployment metadata is not bound to the signed caller and block"
                        .into(),
                ));
            }
            let companion_id = contract_upgrade_state_id(env.chain_id, contract.contract_id);
            if output_ids.contains(&companion_id)
                || !reserved_companion_ids.insert(companion_id)
                || object_db.read(&companion_id).is_ok()
            {
                return Err(PokerL1Error::ObjectIDCollision(companion_id));
            }
        }
    }

    let mut created = Vec::with_capacity(tx.outputs.len() * 2);
    for obj in &tx.outputs {
        if crate::vm::contract::is_contract_object(obj) {
            let contract: ContractObject = decode_contract_object(obj)?;
            // Reconstruct before storing so the executor, rather than user-selected Object
            // metadata, defines the durable immutable contract representation.
            object_db.create_contract_object(contract_object(&contract, 0)?)?;
            created.push(obj.id);
            let state = ContractUpgradeState::new(
                env.chain_id,
                contract.contract_id,
                *caller,
                env.block_height,
            );
            let companion = contract_upgrade_state_object(&state, 0)?;
            object_db.system_create(companion.clone())?;
            created.push(companion.id);
        } else {
            object_db.create(obj.clone())?;
            created.push(obj.id);
        }
    }
    Ok(created)
}

/// 执行一个 block 的有序 tx 序列，返回回执与执行后状态根。
///
/// - 逐笔执行，失败 tx 仅记录回执，不中断后续 tx。
/// - block gas 累计（`receipt.gas_used`）超过 `env.block_gas_limit` 后，
///   后续 tx 跳过执行（回执标记 `OutOfGas`）。免 caller fee 的 native precompile
///   仍消耗 block resource gas。
/// - 返回的 `state_root` 为全部 tx 执行后的 `ObjectDb` SMT root。
///
/// # block-level gas 判定说明
///
/// Public/rBPF 调用以 signed budget 作为执行前 reservation；native precompile 使用其
/// deterministic `gas_cost`。这保证 fee-free GameTurn 也不能绕过 block resource limit。
pub fn execute_block(
    env: &ExecutionEnvironment,
    txs: &[Transaction],
    object_db: &mut ObjectDb,
    account_store: &mut AccountStore,
) -> BlockExecutionOutcome {
    // The shared staged bridge registry is intentionally serial.  Its nonce set is outside the
    // ObjectDb read/write scheduler, so parallel execution could otherwise observe and consume
    // the same nonce nondeterministically.
    if env.bridge_registry_snapshot.is_some()
        || env.validator_set_snapshot.is_some()
        || txs.iter().any(|tx| {
            tx.contract_call.as_ref().is_some_and(|call| {
                call.contract_id == crate::vm::precompile::reserved::validator_system_contract_id()
                    || call.contract_id
                        == crate::vm::precompile::reserved::governance_system_contract_id()
                    || call.contract_id
                        == crate::vm::precompile::reserved::contract_upgrade_system_contract_id()
                    || call.contract_id
                        == crate::vm::precompile::reserved::precompile_governance_system_contract_id()
            })
        })
    {
        execute_block_serial(env, txs, object_db, account_store)
    } else {
        execute_block_parallel(env, txs, object_db, account_store)
    }
}

/// 波次化并行执行（核心实现）。
///
/// 流程：
/// 1. **prepare（可并发）**：估计每笔 tx 的读写集（`schedule::estimate_rwset`）。
/// 2. **wave 划分**：`schedule::plan_waves` 按读写集把 tx 分为若干波次，
///    波次内 tx 两两读写集不相交（可安全并发）。
/// 3. **波次内并发执行**：每个 worker 拿共享 `&ObjectDb` 构造私有
///    [`write_capture::WriteCaptureBackend`]，并在该 caller 的账户快照副本上执行
///    （`execute_tx_on_view_inner`）。读走共享 `&ObjectDb`，写进私有 log。
/// 4. **波次间串行 merge**：按 tx_index 升序把写日志回放主 ObjectDb + 应用账户增量。
/// 5. **block gas 限**：与串行版同一逻辑，在 merge 阶段按序累计，超限 tx 标记 OutOfGas。
///
/// # 确定性
///
/// 波次划分仅依赖 (rwset, tx_index)；波次内结果按 tx_index 升序 merge；
/// 故与 [`execute_block_serial`] 产生相同 state_root。
///
/// # Soundness
///
/// 波次内 tx 读写集两两不相交（由 `plan_waves` 保证），故 worker 间无共享可变状态：
/// 读走共享 `&ObjectDb`（`&self`，可并发），写进各自私有 log。波次间串行 merge，
/// 下一波次基于已 merge 的状态执行——与串行语义等价。
fn execute_block_parallel(
    env: &ExecutionEnvironment,
    txs: &[Transaction],
    object_db: &mut ObjectDb,
    account_store: &mut AccountStore,
) -> BlockExecutionOutcome {
    use crate::executor::write_capture::ObjectWriteLog;
    use rayon::prelude::*;

    // 空 block 快路径
    if txs.is_empty() {
        return BlockExecutionOutcome {
            receipts: Vec::new(),
            state_root: object_db.state_root(),
            account_root: account_store.state_root(),
            total_gas_used: 0,
        };
    }

    // ----- 1. prepare：估计读写集 -----
    let registry_ref = env.precompile_registry.as_ref();
    let rwsets: Vec<_> = (0..txs.len())
        .map(|i| {
            crate::executor::schedule::estimate_rwset(&txs[i], registry_ref.map(|r| r.as_ref()))
        })
        .collect();

    // ----- 2. 波次划分 -----
    let waves = crate::executor::schedule::plan_waves(&rwsets);

    let mut receipts: Vec<Option<TxReceipt>> = (0..txs.len()).map(|_| None).collect();
    let mut total_gas: u64 = 0;

    for wave in waves {
        // ---- 3a. 预取本波次所有 caller 的账户快照 ----
        // 主线程串行读 account_store（&mut 不可跨线程），各 worker 用快照副本。
        let snapshots: HashMap<crate::Address, Account> = wave
            .iter()
            .filter_map(|&idx| {
                let tx = &txs[idx];
                if matches!(tx.lane_hint, TxLane::GameTurn | TxLane::CheckpointAnchor) {
                    None
                } else {
                    let caller = derive_address(&tx.tagged_pubkey);
                    account_store.get(&caller).map(|a| (caller, a.clone()))
                }
            })
            .collect();

        // A wave may need multiple execution batches. Each batch reserves a prefix of the
        // remaining txs whose worst-case gas fits. After their actual gas is known, deferred txs
        // are reconsidered. This preserves serial admission semantics while ensuring a tx is
        // never sent to a worker before block-gas admission.
        let mut pending = wave;
        while !pending.is_empty() {
            let mut batch_indices = Vec::new();
            let mut batch_order = Vec::new();
            let mut reserved_gas = 0u64;
            let mut consumed = 0usize;

            for &idx in &pending {
                let reservation = block_gas_reservation(env, &txs[idx]);
                if total_gas.saturating_add(reservation) > env.block_gas_limit {
                    // This tx cannot become admissible after earlier txs consume more gas. Keep
                    // it in the ordered merge plan, but do not execute it.
                    batch_order.push((idx, false));
                    consumed += 1;
                    continue;
                }
                if total_gas
                    .saturating_add(reserved_gas)
                    .saturating_add(reservation)
                    > env.block_gas_limit
                {
                    // Actual gas from the current batch may be lower than its reservation. Stop
                    // here and reconsider this ordered suffix after merging the batch.
                    break;
                }
                reserved_gas = reserved_gas.saturating_add(reservation);
                batch_indices.push(idx);
                batch_order.push((idx, true));
                consumed += 1;
            }

            debug_assert!(
                consumed > 0,
                "the first individually admissible tx must fit an empty batch"
            );
            let deferred = pending.split_off(consumed);

            // ---- 3b. Admitted batch executes concurrently ----
            // shared_db is refreshed after every merge batch. Transactions in the same original
            // wave are disjoint, so prior batch writes cannot invalidate their snapshots.
            let shared_db: &ObjectDb = &*object_db;
            let batch_outcomes: Vec<(usize, PokerL1Result<(TxReceipt, ObjectWriteLog)>)> =
                batch_indices
                    .par_iter()
                    .map(|&idx| {
                        let tx = &txs[idx];
                        let result = run_one_tx(env, tx, shared_db, &snapshots);
                        (idx, result)
                    })
                    .collect();
            let mut outcome_by_index: HashMap<usize, PokerL1Result<(TxReceipt, ObjectWriteLog)>> =
                batch_outcomes.into_iter().collect();

            // ---- 4. Ordered merge, including pre-admission rejections ----
            for (idx, admitted) in batch_order {
                let tx = &txs[idx];
                if !admitted {
                    receipts[idx] = Some(TxReceipt::failure(
                        tx,
                        &PokerL1Error::OutOfGas {
                            used: total_gas,
                            limit: env.block_gas_limit,
                        },
                    ));
                    continue;
                }
                let result = outcome_by_index
                    .remove(&idx)
                    .expect("every admitted tx must produce one worker outcome");
                let needs_gas =
                    !matches!(tx.lane_hint, TxLane::GameTurn | TxLane::CheckpointAnchor);

                // 执行结果：成功则 merge；通过 admission 后的失败结算 resource gas，
                // Public/ForceSync 同时推进 nonce 并按 fee policy 扣费。
                let (receipt, log) = match result {
                    Ok(v) => v,
                    Err(e) => {
                        let receipt = settle_failed_tx(env, tx, &e, account_store);
                        if needs_gas {
                            let caller = derive_address(&tx.tagged_pubkey);
                            let _ = account_store.flush(&caller);
                        }
                        total_gas = total_gas.saturating_add(receipt.gas_used);
                        receipts[idx] = Some(receipt);
                        continue;
                    }
                };

                // 回放写日志到主 ObjectDb（capture 阶段已校验，主库再校验一次）
                if let Err(e) = log.apply_to(object_db) {
                    let receipt = settle_failed_tx(env, tx, &e, account_store);
                    if needs_gas {
                        let caller = derive_address(&tx.tagged_pubkey);
                        let _ = account_store.flush(&caller);
                    }
                    total_gas = total_gas.saturating_add(receipt.gas_used);
                    receipts[idx] = Some(receipt);
                    continue;
                }

                // 应用账户增量（扣费 + nonce 推进）到主 account_store
                if needs_gas {
                    let caller = derive_address(&tx.tagged_pubkey);
                    if let Some(acc) = account_store.get_mut(&caller) {
                        // 快照已成功通过 apply_public_tx，此处重放相同增量，必然成功；
                        // 失败则视为内部不一致（记失败回执，状态已 merge 不可回滚）。
                        if let Err(e) =
                            apply_public_tx_with_fee(acc, tx, receipt.gas_used, receipt.fee_charged)
                        {
                            receipts[idx] = Some(TxReceipt::failure(tx, &e));
                            continue;
                        }
                    }
                    // 缺口 #8：get_mut 变更后显式落盘（持久化模式下；内存模式 no-op）。
                    if let Err(e) = account_store.flush(&caller) {
                        receipts[idx] = Some(TxReceipt::failure(tx, &e));
                        continue;
                    }
                }

                total_gas = total_gas.saturating_add(receipt.gas_used);

                receipts[idx] = Some(receipt);
            }

            debug_assert!(outcome_by_index.is_empty());
            pending = deferred;
        }
    }

    let receipts: Vec<TxReceipt> = receipts
        .into_iter()
        .map(|o| o.expect("所有 idx 已填充"))
        .collect();

    BlockExecutionOutcome {
        receipts,
        state_root: object_db.state_root(),
        account_root: account_store.state_root(),
        total_gas_used: total_gas,
    }
}

/// 在共享 ObjectDb + 账户快照上执行单笔 tx（波次内 worker 调用）。
///
/// - 读走 [`WriteCaptureBackend`]（先查私有 log，再委托共享 `&ObjectDb`）。
/// - 写进私有 [`ObjectWriteLog`]（返回给主线程 merge）。
/// - 账户操作在快照副本上做（成功后由主线程在主 account_store 重放相同增量）。
fn run_one_tx(
    env: &ExecutionEnvironment,
    tx: &Transaction,
    shared_db: &ObjectDb,
    snapshots: &HashMap<crate::Address, Account>,
) -> PokerL1Result<(TxReceipt, crate::executor::write_capture::ObjectWriteLog)> {
    use crate::executor::write_capture::WriteCaptureBackend;
    let caller = derive_address(&tx.tagged_pubkey);
    let is_gas_free_lane = matches!(tx.lane_hint, TxLane::GameTurn | TxLane::CheckpointAnchor);

    // capture 后端：读委托 shared_db，写进私有 log
    let mut cap = WriteCaptureBackend::new(shared_db);
    // 账户快照副本（非 gas-free lane 需要：nonce/余额校验 + 结算）
    let mut account_view: Option<Account> = if is_gas_free_lane {
        None
    } else {
        snapshots.get(&caller).cloned()
    };

    let receipt = execute_tx_on_view_inner(env, tx, &mut cap, account_view.as_mut())?;
    let log = cap.into_log();
    Ok((receipt, log))
}

/// 串行执行（回归基准 / 降级 fallback）。
///
/// 这是并行执行器改造前的原 `execute_block` 实现，逐笔执行、单一 state_root。
/// 保留用于：
/// - 并行执行器的等价性回归测试（`execute_block_parallel` 必须产生相同 state_root）；
/// - 并行路径运行时复核失败时的 tx 降级重跑；
/// - Snapshot（`ObjectDbSnapshot`）等非 `ObjectDb` 后端的执行。
///
/// 语义与并行版完全等价：同一组有序 tx + 同一初始状态 → 同一 state_root。
pub fn execute_block_serial<B: TransactionalObjectBackend>(
    env: &ExecutionEnvironment,
    txs: &[Transaction],
    object_db: &mut B,
    account_store: &mut AccountStore,
) -> BlockExecutionOutcome {
    let mut receipts = Vec::with_capacity(txs.len());
    let mut total_gas: u64 = 0;

    for tx in txs {
        let needs_gas = !matches!(tx.lane_hint, TxLane::GameTurn | TxLane::CheckpointAnchor);
        let reservation = block_gas_reservation(env, tx);
        if total_gas.saturating_add(reservation) > env.block_gas_limit {
            receipts.push(TxReceipt::failure(
                tx,
                &PokerL1Error::OutOfGas {
                    used: total_gas,
                    limit: env.block_gas_limit,
                },
            ));
            continue;
        }
        let receipt = execute_tx(env, tx, object_db, account_store);
        // 缺口 #8：串行执行路径下，gas-lane tx 的账户变更（扣费 + nonce）需显式落盘。
        if needs_gas {
            let caller = derive_address(&tx.tagged_pubkey);
            if let Err(e) = account_store.flush(&caller) {
                receipts.push(TxReceipt::failure(tx, &e));
                continue;
            }
        }
        total_gas = total_gas.saturating_add(receipt.gas_used);
        receipts.push(receipt);
    }

    BlockExecutionOutcome {
        receipts,
        state_root: object_db.state_root(),
        account_root: account_store.state_root(),
        total_gas_used: total_gas,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DEFAULT_CHAIN_ID;
    use crate::account::Account;
    use crate::consensus::ValidatorStatus;
    use crate::object_model::{Object, Ownership};
    use crate::signature::TaggedPubkey;
    use crate::signature::tagged_pubkey::{SignatureScheme, encode_tag};
    use crate::transaction::{ContractCall, Gas, RouteHint, TxRequest};
    use crate::vm::precompile::{
        DispatchResult, ExecutionEnvironment as PrecompileEnv, Precompile,
    };
    use rand::rngs::OsRng;
    use secp256k1::{Message, Secp256k1};
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // ===== 测试辅助：最小 ELF 构造 =====

    /// BPF `mov64 r0, 0` 指令（8 字节）。
    const BPF_MOV0: [u8; 8] = [0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    /// BPF `exit` 指令（8 字节）。
    const BPF_EXIT: [u8; 8] = [0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    /// 构造 `n` 条 `mov64 r0, 0` + `exit` 的 BPF 程序。
    fn make_program(n_movs: usize) -> Vec<u8> {
        let mut text = Vec::with_capacity((n_movs + 1) * 8);
        for _ in 0..n_movs {
            text.extend_from_slice(&BPF_MOV0);
        }
        text.extend_from_slice(&BPF_EXIT);
        text
    }

    /// 手工构造最小合法 ELF64（EM_BPF / ET_DYN / SBPF V1），
    /// 含 `.text`（BPF 指令）与 `.shstrtab` 两个 section。
    ///
    /// 布局：`[ELF header 64B][.text][.shstrtab][3 × section header 64B]`。
    /// SBPF V1 要求 `.text` 的 `sh_addr == sh_offset`（`reject_broken_elfs`），
    /// 且 `e_entry` 落在 `.text` 的 vm_range 内（取 offset 0）。
    fn build_test_elf(text: &[u8]) -> Vec<u8> {
        const EHDR_SIZE: usize = 64;
        const SHDR_SIZE: usize = 64;
        const EM_BPF: u16 = 247;
        const ET_DYN: u16 = 3;
        const SHT_PROGBITS: u32 = 1;
        const SHT_STRTAB: u32 = 3;
        const SHF_ALLOC_EXEC: u64 = 0x2 | 0x4;

        let shstrtab: &[u8] = b"\0.text\0.shstrtab\0";
        let text_off = EHDR_SIZE as u64;
        let strtab_off = text_off + text.len() as u64;
        // section header 表起始必须按 align_of::<Elf64Shdr>()=8 对齐（解析器硬校验）
        let shoff = (strtab_off + shstrtab.len() as u64).next_multiple_of(8);

        let mut elf = Vec::with_capacity(shoff as usize + 3 * SHDR_SIZE);

        // ---- ELF header ----
        elf.extend_from_slice(&[0x7F, b'E', b'L', b'F']); // magic
        elf.push(2); // EI_CLASS = ELFCLASS64
        elf.push(1); // EI_DATA = ELFDATA2LSB
        elf.push(1); // EI_VERSION
        elf.push(0); // EI_OSABI = ELFOSABI_NONE
        elf.extend_from_slice(&[0u8; 8]); // EI_ABIVERSION + EI_PAD
        elf.extend_from_slice(&ET_DYN.to_le_bytes()); // e_type
        elf.extend_from_slice(&EM_BPF.to_le_bytes()); // e_machine
        elf.extend_from_slice(&1u32.to_le_bytes()); // e_version
        elf.extend_from_slice(&text_off.to_le_bytes()); // e_entry = .text 起始
        elf.extend_from_slice(&0u64.to_le_bytes()); // e_phoff（无 program header）
        elf.extend_from_slice(&shoff.to_le_bytes()); // e_shoff
        elf.extend_from_slice(&0u32.to_le_bytes()); // e_flags = 0（SBPF V1）
        elf.extend_from_slice(&(EHDR_SIZE as u16).to_le_bytes()); // e_ehsize
        // e_phentsize：解析器要求恒等于 sizeof(Elf64Phdr)=56（即使 e_phnum=0）
        elf.extend_from_slice(&56u16.to_le_bytes());
        elf.extend_from_slice(&0u16.to_le_bytes()); // e_phnum
        elf.extend_from_slice(&(SHDR_SIZE as u16).to_le_bytes()); // e_shentsize
        elf.extend_from_slice(&3u16.to_le_bytes()); // e_shnum
        elf.extend_from_slice(&2u16.to_le_bytes()); // e_shstrndx

        // ---- .text ----
        elf.extend_from_slice(text);
        // ---- .shstrtab ----
        elf.extend_from_slice(shstrtab);
        // ---- 填充至 8 字节对齐 ----
        elf.resize(shoff as usize, 0);

        // ---- section header [0]：NULL ----
        elf.extend_from_slice(&[0u8; SHDR_SIZE]);
        // ---- section header [1]：.text ----
        elf.extend_from_slice(&1u32.to_le_bytes()); // sh_name = ".text"
        elf.extend_from_slice(&SHT_PROGBITS.to_le_bytes());
        elf.extend_from_slice(&SHF_ALLOC_EXEC.to_le_bytes());
        elf.extend_from_slice(&text_off.to_le_bytes()); // sh_addr == sh_offset（V1 硬约束）
        elf.extend_from_slice(&text_off.to_le_bytes()); // sh_offset
        elf.extend_from_slice(&(text.len() as u64).to_le_bytes()); // sh_size
        elf.extend_from_slice(&0u32.to_le_bytes()); // sh_link
        elf.extend_from_slice(&0u32.to_le_bytes()); // sh_info
        elf.extend_from_slice(&8u64.to_le_bytes()); // sh_addralign
        elf.extend_from_slice(&0u64.to_le_bytes()); // sh_entsize
        // ---- section header [2]：.shstrtab ----
        elf.extend_from_slice(&7u32.to_le_bytes()); // sh_name = ".shstrtab"
        elf.extend_from_slice(&SHT_STRTAB.to_le_bytes());
        elf.extend_from_slice(&0u64.to_le_bytes()); // sh_flags
        elf.extend_from_slice(&0u64.to_le_bytes()); // sh_addr
        elf.extend_from_slice(&strtab_off.to_le_bytes()); // sh_offset
        elf.extend_from_slice(&(shstrtab.len() as u64).to_le_bytes()); // sh_size
        elf.extend_from_slice(&0u32.to_le_bytes());
        elf.extend_from_slice(&0u32.to_le_bytes());
        elf.extend_from_slice(&1u64.to_le_bytes()); // sh_addralign
        elf.extend_from_slice(&0u64.to_le_bytes());

        elf
    }

    // ===== 测试辅助：签名者与交易构造 =====

    /// secp256k1 测试签名者。
    struct TestSigner {
        sk: secp256k1::SecretKey,
        pk: secp256k1::PublicKey,
    }

    impl TestSigner {
        fn new() -> Self {
            let secp = Secp256k1::new();
            let (sk, pk) = secp.generate_keypair(&mut OsRng);
            Self { sk, pk }
        }

        fn tagged_pubkey(&self) -> TaggedPubkey {
            TaggedPubkey {
                tag: encode_tag(SignatureScheme::Secp256k1, 1),
                raw: self.pk.serialize().to_vec(),
            }
        }

        fn address(&self) -> crate::Address {
            derive_address(&self.tagged_pubkey())
        }

        fn sign(&self, req: TxRequest) -> Transaction {
            let hash = req.signing_hash();
            let signature = self.sign_hash(hash);
            req.into_transaction(self.tagged_pubkey(), signature)
        }

        fn sign_hash(&self, hash: crate::Hash) -> Vec<u8> {
            let secp = Secp256k1::new();
            let sig = secp.sign_ecdsa_recoverable(&Message::from_digest(hash), &self.sk);
            let (rid, compact) = sig.serialize_compact();
            let mut full_sig = compact.to_vec();
            full_sig.push(rid.to_i32() as u8);
            full_sig
        }
    }

    /// 构造默认 Public 通道 TxRequest（budget=1_000_000, price=1）。
    fn public_request(nonce: u64) -> TxRequest {
        TxRequest {
            inputs: vec![],
            outputs: vec![],
            contract_call: None,
            gas: Gas::new(1_000_000, 1),
            lane_hint: TxLane::Public,
            route_hint: RouteHint::AnyValidator,
            chain_id: DEFAULT_CHAIN_ID,
            nonce,
            gameturn_nonce: None,
            is_fallback: false,
        }
    }

    fn governance_system_tx(
        signer: &TestSigner,
        nonce: u64,
        command: GovernanceSystemCall,
    ) -> Transaction {
        let mut request = public_request(nonce);
        request.contract_call = Some(ContractCall {
            contract_id: crate::vm::precompile::reserved::governance_system_contract_id(),
            method_selector: [0; 32],
            args: borsh::to_vec(&command).unwrap(),
        });
        signer.sign(request)
    }

    /// 构造受签名保护的合约升级系统调用。
    fn contract_upgrade_system_tx(
        signer: &TestSigner,
        nonce: u64,
        command: crate::vm::ContractUpgradeSystemCall,
    ) -> Transaction {
        let mut request = public_request(nonce);
        request.contract_call = Some(ContractCall {
            contract_id: crate::vm::precompile::reserved::contract_upgrade_system_contract_id(),
            method_selector: [0; 32],
            args: borsh::to_vec(&command).unwrap(),
        });
        signer.sign(request)
    }

    /// 构造受签名保护的原生预编译治理调用。
    fn precompile_governance_system_tx(
        signer: &TestSigner,
        nonce: u64,
        command: PrecompileGovernanceSystemCall,
    ) -> Transaction {
        let mut request = public_request(nonce);
        request.contract_call = Some(ContractCall {
            contract_id: crate::vm::precompile::reserved::precompile_governance_system_contract_id(
            ),
            method_selector: [0; 32],
            args: borsh::to_vec(&command).unwrap(),
        });
        signer.sign(request)
    }

    /// 构造 GameTurn 通道 TxRequest（免 gas）。
    fn gameturn_request() -> TxRequest {
        TxRequest {
            inputs: vec![],
            outputs: vec![],
            contract_call: None,
            gas: Gas::zero(),
            lane_hint: TxLane::GameTurn,
            route_hint: RouteHint::AssignedValidator,
            chain_id: DEFAULT_CHAIN_ID,
            nonce: 0,
            gameturn_nonce: Some(0),
            is_fallback: false,
        }
    }

    /// 构造归属 `owner` 的输出对象。
    fn make_output(owner: crate::Address, creation_nonce: u64, data: &[u8]) -> Object {
        Object::new(
            ObjectID::new(owner, creation_nonce),
            Ownership::AddressOwned { owner },
            "TestOutput",
            data.to_vec(),
            None,
        )
    }

    /// 部署测试合约（以对象形式写入 ObjectDb），返回 contract_id。
    fn deploy_contract(
        object_db: &mut ObjectDb,
        caller: crate::Address,
        bytecode: Vec<u8>,
        creation_nonce: u64,
        is_active: bool,
    ) -> ObjectID {
        let contract_id = ObjectID::new(caller, creation_nonce);
        let mut contract = ContractObject::new(contract_id, 1, bytecode, caller, 0);
        contract.is_active = is_active;
        let obj =
            crate::vm::contract::contract_object(&contract, 0).expect("构造受保护 Contract 对象");
        object_db
            .create_contract_object(obj)
            .expect("通过受保护路径写入合约对象");
        contract_id
    }

    fn make_env() -> ExecutionEnvironment {
        ExecutionEnvironment::new(DEFAULT_CHAIN_ID, 100, 1_000_000)
            .with_fee_policy(FeePolicy::Charged)
    }

    // ===== 测试辅助：gas-free 预编译合约 stub =====

    /// 简化的 gas-free 预编译合约 stub（用于 executor gas 策略测试）。
    ///
    /// 不依赖完整 `GameContract` 状态，`call()` 返回空 `DispatchResult`，
    /// 仅用于验证 executor 的 lane-contract 一致性校验与 gas 策略。
    struct GasFreeTestPrecompile {
        id: ObjectID,
        fixed_gas: Option<u64>,
        failure: Option<&'static str>,
        calls: Option<Arc<AtomicUsize>>,
    }

    /// Minimal versioned native implementation used to exercise consensus precompile releases.
    struct VersionedNoopPrecompile {
        id: ObjectID,
        version: u32,
    }

    impl Precompile for VersionedNoopPrecompile {
        fn id(&self) -> ObjectID {
            self.id
        }

        fn version(&self) -> u32 {
            self.version
        }

        fn call(
            &self,
            _caller: &crate::Address,
            _caller_pubkey: &TaggedPubkey,
            _method_selector: &[u8; 32],
            _args: &[u8],
            _env: &PrecompileEnv,
            _object_db: &mut dyn ObjectBackend,
        ) -> PokerL1Result<DispatchResult> {
            Ok(DispatchResult::empty())
        }
    }

    impl GasFreeTestPrecompile {
        fn new(id: ObjectID) -> Arc<dyn Precompile> {
            Arc::new(Self {
                id,
                fixed_gas: None,
                failure: None,
                calls: None,
            })
        }

        fn failing(id: ObjectID, fixed_gas: u64, calls: Arc<AtomicUsize>) -> Arc<dyn Precompile> {
            Arc::new(Self {
                id,
                fixed_gas: Some(fixed_gas),
                failure: Some("synthetic native crypto proof verification failed"),
                calls: Some(calls),
            })
        }
    }

    impl Precompile for GasFreeTestPrecompile {
        fn id(&self) -> ObjectID {
            self.id
        }

        fn version(&self) -> u32 {
            1
        }

        fn call(
            &self,
            _caller: &crate::Address,
            _caller_pubkey: &TaggedPubkey,
            _method_selector: &[u8; 32],
            _args: &[u8],
            _env: &PrecompileEnv,
            _object_db: &mut dyn ObjectBackend,
        ) -> PokerL1Result<DispatchResult> {
            if let Some(calls) = &self.calls {
                calls.fetch_add(1, Ordering::SeqCst);
            }
            if let Some(message) = self.failure {
                return Err(PokerL1Error::Other(message.into()));
            }
            Ok(DispatchResult::empty())
        }

        fn gas_cost(&self, _method_selector: &[u8; 32], args: &[u8]) -> u64 {
            self.fixed_gas
                .unwrap_or_else(|| crate::vm::gas_table::precompile_gas(args.len() as u64))
        }

        fn is_gas_free(&self) -> bool {
            true
        }
    }

    /// Test-only precompile that makes an observable object mutation before returning success.
    /// A later transaction-level error must discard this mutation with the rest of the tx.
    struct MutatingTestPrecompile {
        id: ObjectID,
        target: ObjectID,
    }

    impl Precompile for MutatingTestPrecompile {
        fn id(&self) -> ObjectID {
            self.id
        }

        fn version(&self) -> u32 {
            1
        }

        fn call(
            &self,
            caller: &crate::Address,
            _caller_pubkey: &TaggedPubkey,
            _method_selector: &[u8; 32],
            _args: &[u8],
            _env: &PrecompileEnv,
            object_db: &mut dyn ObjectBackend,
        ) -> PokerL1Result<DispatchResult> {
            object_db.update(&self.target, caller, b"mutated-before-late-error".to_vec())?;
            Ok(DispatchResult {
                created_objects: vec![],
                modified_objects: vec![self.target],
                read_objects: vec![self.target],
                return_value: vec![],
            })
        }

        fn is_gas_free(&self) -> bool {
            true
        }
    }

    /// 构造带 GasFreeTestPrecompile 注册的 PrecompileRegistry。
    ///
    /// `gas_free_id` 为注册的预编译合约 ObjectID（免 gas）。
    fn make_registry_with_gas_free_precompile(gas_free_id: ObjectID) -> PrecompileRegistry {
        let mut registry = PrecompileRegistry::new();
        registry.register(GasFreeTestPrecompile::new(gas_free_id));
        registry
    }

    /// 构造注入 GasFreeTestPrecompile 的执行环境。
    fn make_gas_free_env(gas_free_id: ObjectID) -> ExecutionEnvironment {
        let registry = make_registry_with_gas_free_precompile(gas_free_id);
        make_env().with_precompile_registry(registry)
    }

    fn make_failing_gas_free_env(
        gas_free_id: ObjectID,
        fixed_gas: u64,
        calls: Arc<AtomicUsize>,
    ) -> ExecutionEnvironment {
        let mut registry = PrecompileRegistry::new();
        registry.register(GasFreeTestPrecompile::failing(
            gas_free_id,
            fixed_gas,
            calls,
        ));
        make_env().with_precompile_registry(registry)
    }

    /// 基础 fixture：空 ObjectDb + 含 signer 账户（balance=1_000_000）的 AccountStore。
    struct Fixture {
        object_db: ObjectDb,
        account_store: AccountStore,
        signer: TestSigner,
        initial_root: crate::Hash,
    }

    impl Fixture {
        fn new() -> Self {
            let object_db = ObjectDb::open_inmemory().expect("打开内存 ObjectDb");
            let mut account_store = AccountStore::new();
            let signer = TestSigner::new();
            let account = Account::new(signer.tagged_pubkey(), 1_000_000);
            account_store.create(account).expect("创建账户");
            let initial_root = object_db.state_root();
            Self {
                object_db,
                account_store,
                signer,
                initial_root,
            }
        }

        fn caller(&self) -> crate::Address {
            self.signer.address()
        }

        fn account(&self) -> &Account {
            self.account_store
                .get(&self.caller())
                .expect("账户必须存在")
        }
    }

    fn empty_validator_set() -> ValidatorSet {
        let genesis_randomness = crate::consensus::compute_genesis_chain_randomness(&[]);
        let mut set = ValidatorSet {
            epoch: 0,
            validators: vec![],
            validator_set_hash: [0u8; 32],
            epoch_randomness: genesis_randomness,
            prev_epoch_randomness: [0u8; 32],
            genesis_chain_randomness: genesis_randomness,
        };
        set.validator_set_hash = set.compute_hash();
        set
    }

    fn active_validator_entry(signer: &TestSigner) -> crate::consensus::ValidatorEntry {
        let mut entry = crate::consensus::ValidatorEntry::new(
            signer.tagged_pubkey(),
            signer.pk.serialize(),
            0,
            0,
        );
        entry.status = ValidatorStatus::Active;
        entry
    }

    fn validator_set_with_active_signers(signers: &[&TestSigner]) -> ValidatorSet {
        let validators = signers
            .iter()
            .map(|signer| active_validator_entry(signer))
            .collect::<Vec<_>>();
        let genesis_randomness = crate::consensus::compute_genesis_chain_randomness(&validators);
        let mut set = ValidatorSet {
            epoch: 0,
            validators,
            validator_set_hash: [0u8; 32],
            epoch_randomness: genesis_randomness,
            prev_epoch_randomness: [0u8; 32],
            genesis_chain_randomness: genesis_randomness,
        };
        set.validator_set_hash = set.compute_hash();
        set
    }

    fn install_bridge_system_state(
        fx: &mut Fixture,
        config: &crate::bridge::BridgeRegistryConfig,
        validators: &ValidatorSet,
    ) {
        crate::economics::genesis_mint_with_system_objects(
            &mut fx.object_db,
            DEFAULT_CHAIN_ID,
            &[],
            vec![
                crate::consensus::validator_set::validator_set_object(
                    DEFAULT_CHAIN_ID,
                    validators,
                    0,
                )
                .expect("validator set system object"),
                crate::bridge::bridge_registry_config_object(config, 0)
                    .expect("bridge config system object"),
                crate::bridge::bridge_replay_state_object(
                    &crate::bridge::BridgeReplayState::empty(DEFAULT_CHAIN_ID),
                    0,
                )
                .expect("bridge replay system object"),
            ],
        )
        .expect("install bridge system state");
    }

    fn install_governance_system_state(fx: &mut Fixture, validators: &ValidatorSet) {
        install_governance_system_state_with_alloc(fx, validators, &[]);
    }

    fn install_governance_system_state_with_alloc(
        fx: &mut Fixture,
        validators: &ValidatorSet,
        allocs: &[(crate::Address, u64)],
    ) {
        crate::economics::genesis_mint_with_system_objects(
            &mut fx.object_db,
            DEFAULT_CHAIN_ID,
            allocs,
            vec![
                crate::consensus::validator_set::validator_set_object(
                    DEFAULT_CHAIN_ID,
                    validators,
                    0,
                )
                .expect("validator set system object"),
                crate::governance::governance_state_object(
                    DEFAULT_CHAIN_ID,
                    &crate::governance::GovernanceState::new(),
                    0,
                )
                .expect("governance state system object"),
                crate::economics::fee_policy_object(DEFAULT_CHAIN_ID, FeePolicy::Free, 0)
                    .expect("fee policy system object"),
            ],
        )
        .expect("install governance system state");
    }

    #[test]
    fn governance_system_call_requires_active_validator_and_persists_proposal() {
        let mut fx = Fixture::new();
        let validators = validator_set_with_active_signers(&[&fx.signer]);
        install_governance_system_state(&mut fx, &validators);
        let validator_snapshot = Arc::new(Mutex::new(validators));
        let env = make_env()
            .with_fee_policy(FeePolicy::Free)
            .with_validator_set_snapshot(Arc::clone(&validator_snapshot));

        let mut request = public_request(0);
        request.contract_call = Some(ContractCall {
            contract_id: crate::vm::precompile::reserved::governance_system_contract_id(),
            method_selector: [0; 32],
            args: borsh::to_vec(&GovernanceSystemCall::CreateParameterProposal {
                param: crate::governance::ParamName::MaxIntervalMs,
                new_value: 3_000,
                target_chain_id: DEFAULT_CHAIN_ID,
            })
            .unwrap(),
        });
        let receipt = execute_tx(
            &env,
            &fx.signer.sign(request),
            &mut fx.object_db,
            &mut fx.account_store,
        );
        assert!(
            receipt.success,
            "governance proposal failed: {:?}",
            receipt.error
        );
        let state = crate::governance::decode_governance_state_object(
            &fx.object_db
                .read(&crate::governance::GOVERNANCE_STATE_OBJECT_ID)
                .unwrap(),
            DEFAULT_CHAIN_ID,
        )
        .unwrap();
        assert_eq!(state.next_proposal_id, 2);
        assert_eq!(state.proposals[&1].proposer, fx.signer.tagged_pubkey());
        assert_eq!(
            fx.object_db
                .version_of(&crate::governance::GOVERNANCE_STATE_OBJECT_ID)
                .unwrap(),
            1
        );

        let outsider = TestSigner::new();
        fx.account_store
            .create(Account::new(outsider.tagged_pubkey(), 1_000_000))
            .unwrap();
        let mut unauthorized = public_request(0);
        unauthorized.contract_call = Some(ContractCall {
            contract_id: crate::vm::precompile::reserved::governance_system_contract_id(),
            method_selector: [0; 32],
            args: borsh::to_vec(&GovernanceSystemCall::CreateParameterProposal {
                param: crate::governance::ParamName::MaxIntervalMs,
                new_value: 4_000,
                target_chain_id: DEFAULT_CHAIN_ID,
            })
            .unwrap(),
        });
        let receipt = execute_tx(
            &env,
            &outsider.sign(unauthorized),
            &mut fx.object_db,
            &mut fx.account_store,
        );
        assert!(!receipt.success, "non-validator governance call must fail");
        let state = crate::governance::decode_governance_state_object(
            &fx.object_db
                .read(&crate::governance::GOVERNANCE_STATE_OBJECT_ID)
                .unwrap(),
            DEFAULT_CHAIN_ID,
        )
        .unwrap();
        assert_eq!(state.next_proposal_id, 2);
    }

    #[test]
    fn governance_validator_addition_rejects_unfunded_wire_path() {
        let mut fx = Fixture::new();
        let validators = validator_set_with_active_signers(&[&fx.signer]);
        install_governance_system_state(&mut fx, &validators);
        let validator_snapshot = Arc::new(Mutex::new(validators));
        let env = make_env()
            .with_fee_policy(FeePolicy::Free)
            .with_validator_set_snapshot(Arc::clone(&validator_snapshot));

        let candidate = TestSigner::new();
        let addition = crate::governance::ValidatorAddition {
            pubkey: candidate.tagged_pubkey(),
            vrf_pubkey: candidate.pk.serialize(),
            stake: 1_000,
        };
        let mut request = public_request(0);
        request.contract_call = Some(ContractCall {
            contract_id: crate::vm::precompile::reserved::governance_system_contract_id(),
            method_selector: [0; 32],
            args: borsh::to_vec(&GovernanceSystemCall::CreateValidatorSetUpdateProposal {
                additions: vec![addition],
                removals: vec![],
                effective_epoch: 1,
            })
            .unwrap(),
        });
        let receipt = execute_tx(
            &env,
            &fx.signer.sign(request),
            &mut fx.object_db,
            &mut fx.account_store,
        );
        assert!(!receipt.success);
        assert!(
            receipt
                .error
                .as_deref()
                .is_some_and(|error| error.contains("bond escrow"))
        );
        let state = crate::governance::decode_governance_state_object(
            &fx.object_db
                .read(&crate::governance::GOVERNANCE_STATE_OBJECT_ID)
                .unwrap(),
            DEFAULT_CHAIN_ID,
        )
        .unwrap();
        assert_eq!(state.next_proposal_id, 1);
    }

    #[test]
    fn bonded_validator_governance_v2_locks_native_coin_and_persists_exact_escrow() {
        let mut fx = Fixture::new();
        let validator_b = TestSigner::new();
        let validator_c = TestSigner::new();
        let validator_d = TestSigner::new();
        let validator_e = TestSigner::new();
        let validators = validator_set_with_active_signers(&[
            &fx.signer,
            &validator_b,
            &validator_c,
            &validator_d,
            &validator_e,
        ]);
        let caller = fx.caller();
        install_governance_system_state_with_alloc(&mut fx, &validators, &[(caller, 1_000)]);
        let input = crate::economics::list_owned_native_coins(&fx.object_db, caller).unwrap()[0].id;
        let validator_snapshot = Arc::new(Mutex::new(validators));
        let env = make_env()
            .with_fee_policy(FeePolicy::Free)
            .with_validator_set_snapshot(Arc::clone(&validator_snapshot));
        let candidate = TestSigner::new();
        let addition = crate::governance::ValidatorAddition {
            pubkey: candidate.tagged_pubkey(),
            vrf_pubkey: candidate.pk.serialize(),
            stake: 300,
        };
        let mut request = public_request(0);
        request.inputs = vec![input];
        request.contract_call = Some(ContractCall {
            contract_id:
                crate::vm::precompile::reserved::validator_bond_governance_system_contract_id(),
            method_selector: [0; 32],
            args: borsh::to_vec(
                &ValidatorBondGovernanceSystemCall::CreateBondedValidatorSetUpdateProposal {
                    additions: vec![addition.clone()],
                    removals: vec![],
                    effective_epoch: 1,
                },
            )
            .unwrap(),
        });
        let receipt = execute_tx(
            &env,
            &fx.signer.sign(request),
            &mut fx.object_db,
            &mut fx.account_store,
        );
        assert!(
            receipt.success,
            "bonded proposal failed: {:?}",
            receipt.error
        );
        assert_eq!(
            crate::economics::native_coin_balance(&fx.object_db, caller).unwrap(),
            700
        );
        let escrow = crate::governance::read_validator_bond_escrow(&fx.object_db, DEFAULT_CHAIN_ID)
            .unwrap()
            .expect("bonded proposal must create escrow")
            .0;
        escrow.validate_activation(1, &[addition]).unwrap();
        assert_eq!(escrow.total_amount().unwrap(), 300);
        // The locked amount is a custody domain, not a mint or burn.
        crate::economics::reconcile_native_supply(&fx.object_db, 300).unwrap();
    }

    #[test]
    fn validator_key_rotation_wire_binds_old_key_to_signed_caller() {
        let mut fx = Fixture::new();
        let validators = validator_set_with_active_signers(&[&fx.signer]);
        install_governance_system_state(&mut fx, &validators);
        let validator_snapshot = Arc::new(Mutex::new(validators));
        let env = make_env()
            .with_fee_policy(FeePolicy::Free)
            .with_validator_set_snapshot(Arc::clone(&validator_snapshot));
        let replacement = TestSigner::new().tagged_pubkey();
        let mut request = public_request(0);
        request.contract_call = Some(ContractCall {
            contract_id: crate::vm::precompile::reserved::validator_key_rotation_system_contract_id(
            ),
            method_selector: [0; 32],
            args: borsh::to_vec(&ValidatorKeyRotationSystemCall::CreateKeyRotationProposal {
                new_pubkey: replacement.clone(),
            })
            .unwrap(),
        });
        let receipt = execute_tx(
            &env,
            &fx.signer.sign(request),
            &mut fx.object_db,
            &mut fx.account_store,
        );
        assert!(
            receipt.success,
            "key rotation proposal failed: {:?}",
            receipt.error
        );
        let governance = crate::governance::decode_governance_state_object(
            &fx.object_db
                .read(&crate::governance::GOVERNANCE_STATE_OBJECT_ID)
                .unwrap(),
            DEFAULT_CHAIN_ID,
        )
        .unwrap();
        assert!(matches!(
            &governance.proposals[&1].kind,
            crate::governance::ProposalKind::KeyRotation {
                old_pubkey,
                new_pubkey,
                ..
            } if old_pubkey == &fx.signer.tagged_pubkey() && new_pubkey == &replacement
        ));
    }

    #[test]
    fn governed_fee_policy_replacement_requires_vote_and_timelock() {
        let mut fx = Fixture::new();
        let validators = validator_set_with_active_signers(&[&fx.signer]);
        install_governance_system_state(&mut fx, &validators);
        let validator_snapshot = Arc::new(Mutex::new(validators));
        let env_at = |height| {
            ExecutionEnvironment::new(DEFAULT_CHAIN_ID, height, 1_000_000)
                .with_fee_policy(FeePolicy::Free)
                .with_validator_set_snapshot(Arc::clone(&validator_snapshot))
        };
        let created = execute_tx(
            &env_at(100),
            &governance_system_tx(
                &fx.signer,
                0,
                GovernanceSystemCall::CreateFeePolicyProposal {
                    policy: FeePolicy::Charged,
                },
            ),
            &mut fx.object_db,
            &mut fx.account_store,
        );
        assert!(
            created.success,
            "fee policy proposal failed: {:?}",
            created.error
        );
        let voted = execute_tx(
            &env_at(1_100),
            &governance_system_tx(
                &fx.signer,
                1,
                GovernanceSystemCall::Vote {
                    proposal_id: 1,
                    approve: true,
                },
            ),
            &mut fx.object_db,
            &mut fx.account_store,
        );
        assert!(voted.success, "fee policy vote failed: {:?}", voted.error);
        let finalized = execute_tx(
            &env_at(1_100),
            &governance_system_tx(
                &fx.signer,
                2,
                GovernanceSystemCall::FinalizeVoting { proposal_id: 1 },
            ),
            &mut fx.object_db,
            &mut fx.account_store,
        );
        assert!(
            finalized.success,
            "fee policy finalization failed: {:?}",
            finalized.error
        );
        let premature = execute_tx(
            &env_at(3_099),
            &governance_system_tx(
                &fx.signer,
                3,
                GovernanceSystemCall::ExecuteProposal { proposal_id: 1 },
            ),
            &mut fx.object_db,
            &mut fx.account_store,
        );
        assert!(!premature.success, "fee policy timelock must be enforced");
        let executed = execute_tx(
            &env_at(3_100),
            &governance_system_tx(
                &fx.signer,
                4,
                GovernanceSystemCall::ExecuteProposal { proposal_id: 1 },
            ),
            &mut fx.object_db,
            &mut fx.account_store,
        );
        assert!(
            executed.success,
            "fee policy execution failed: {:?}",
            executed.error
        );
        assert_eq!(
            crate::economics::decode_fee_policy(
                &fx.object_db
                    .read(&crate::economics::FEE_POLICY_OBJECT_ID)
                    .unwrap(),
                DEFAULT_CHAIN_ID,
            )
            .unwrap(),
            FeePolicy::Charged
        );
        assert_eq!(
            fx.object_db
                .version_of(&crate::economics::FEE_POLICY_OBJECT_ID)
                .unwrap(),
            1
        );
    }

    #[test]
    fn bridge_config_deposit_and_burn_execute_atomically_with_replay_state() {
        let mut fx = Fixture::new();
        let validator_b = TestSigner::new();
        let validator_c = TestSigner::new();
        let validator_set =
            validator_set_with_active_signers(&[&fx.signer, &validator_b, &validator_c]);
        let current_config = crate::bridge::BridgeRegistryConfig::empty(DEFAULT_CHAIN_ID);
        install_bridge_system_state(&mut fx, &current_config, &validator_set);

        let bridge_store = crate::storage::BridgeRegistryStore::open_inmemory().unwrap();
        let bridge_snapshot = Arc::new(Mutex::new(
            bridge_store.create_snapshot_with_config(&current_config),
        ));
        let validator_snapshot = Arc::new(Mutex::new(validator_set));
        let env = make_env()
            .with_fee_policy(FeePolicy::Free)
            .with_bridge_registry_snapshot(Arc::clone(&bridge_snapshot))
            .with_validator_set_snapshot(Arc::clone(&validator_snapshot));

        let bridge_validator = fx.signer.tagged_pubkey();
        let slot = crate::bridge::BridgeValidatorSlot::new(
            0xAA55,
            BTreeSet::from([bridge_validator.clone()]),
        );
        let next_config = crate::bridge::BridgeRegistryConfig {
            chain_id: DEFAULT_CHAIN_ID,
            slots: BTreeMap::from([(slot.source_chain_id, slot)]),
        };
        let mut config_update = crate::bridge::BridgeConfigUpdate {
            expected_version: 0,
            expected_config_hash: current_config.commitment_hash(),
            next_config: next_config.clone(),
            signatures: Vec::new(),
        };
        let update_message = config_update.message_hash();
        config_update.signatures = vec![
            crate::bridge::BridgeConfigSignature {
                validator: fx.signer.tagged_pubkey(),
                signature: fx.signer.sign_hash(update_message),
            },
            crate::bridge::BridgeConfigSignature {
                validator: validator_b.tagged_pubkey(),
                signature: validator_b.sign_hash(update_message),
            },
            crate::bridge::BridgeConfigSignature {
                validator: validator_c.tagged_pubkey(),
                signature: validator_c.sign_hash(update_message),
            },
        ];
        let mut update_request = public_request(0);
        update_request.contract_call = Some(ContractCall {
            contract_id: crate::vm::precompile::reserved::bridge_contract_id(),
            method_selector: crate::vm::precompile::reserved::bridge_config_selector(),
            args: borsh::to_vec(&config_update).unwrap(),
        });
        let update_receipt = execute_tx(
            &env,
            &fx.signer.sign(update_request),
            &mut fx.object_db,
            &mut fx.account_store,
        );
        assert!(
            update_receipt.success,
            "bridge configuration update failed: {:?}",
            update_receipt.error
        );
        let persisted_config = crate::bridge::decode_bridge_registry_config_object(
            &fx.object_db
                .read(&crate::bridge::BRIDGE_REGISTRY_CONFIG_OBJECT_ID)
                .unwrap(),
            DEFAULT_CHAIN_ID,
        )
        .unwrap();
        assert_eq!(persisted_config, next_config);
        assert_eq!(
            fx.object_db
                .version_of(&crate::bridge::BRIDGE_REGISTRY_CONFIG_OBJECT_ID)
                .unwrap(),
            1
        );

        let deposit = crate::bridge::BridgeDeposit {
            nonce: 9,
            source_chain_id: 0xAA55,
            dest_chain_id: DEFAULT_CHAIN_ID,
            asset: [0xA5; 32],
            amount: 700,
            recipient: fx.caller(),
            source_tx_hash: [0x5A; 32],
        };
        let deposit_message = deposit.message_hash();
        let bridge_tx = crate::bridge::BridgeVerifyTx {
            deposit,
            validator_signatures: vec![crate::bridge::BridgeValidatorSig {
                validator: bridge_validator,
                signature: fx.signer.sign_hash(deposit_message),
            }],
            recipient_sig: fx.signer.sign_hash(deposit_message),
            recipient_pubkey: fx.signer.tagged_pubkey(),
            preferred_relayer: None,
        };
        let mut deposit_request = public_request(1);
        deposit_request.contract_call = Some(ContractCall {
            contract_id: crate::vm::precompile::reserved::bridge_contract_id(),
            method_selector: [0; 32],
            args: borsh::to_vec(&bridge_tx).unwrap(),
        });
        let deposit_receipt = execute_tx(
            &env,
            &fx.signer.sign(deposit_request),
            &mut fx.object_db,
            &mut fx.account_store,
        );
        assert!(
            deposit_receipt.success,
            "bridge deposit failed: {:?}",
            deposit_receipt.error
        );
        let wrapped_id = *deposit_receipt
            .created_objects
            .first()
            .expect("bridge deposit must mint exactly one wrapped object");

        // A malformed burn must not consume the wrapped object, nonce, or replay singleton.
        let mut malformed_request = public_request(2);
        malformed_request.inputs = vec![wrapped_id];
        malformed_request.contract_call = Some(ContractCall {
            contract_id: crate::vm::precompile::reserved::bridge_contract_id(),
            method_selector: crate::vm::precompile::reserved::bridge_burn_selector(),
            args: borsh::to_vec(&crate::bridge::BridgeBurnTx {
                wrapped_object_id: ObjectID::new(fx.caller(), 0xDEAD),
                burn_nonce: 14,
                source_chain_id: 0xAA55,
                recipient: [0x11; 20],
            })
            .unwrap(),
        });
        let malformed_receipt = execute_tx(
            &env,
            &fx.signer.sign(malformed_request),
            &mut fx.object_db,
            &mut fx.account_store,
        );
        assert!(!malformed_receipt.success);
        assert!(fx.object_db.read(&wrapped_id).is_ok());
        assert!(
            !bridge_snapshot
                .lock()
                .unwrap()
                .registry_mut()
                .is_burn_nonce_consumed(DEFAULT_CHAIN_ID, 14)
        );
        assert_eq!(
            fx.object_db
                .version_of(&crate::bridge::BRIDGE_REPLAY_STATE_OBJECT_ID)
                .unwrap(),
            1,
            "failed burn must restore the staged replay-state update"
        );

        let mut burn_request = public_request(3);
        burn_request.inputs = vec![wrapped_id];
        burn_request.contract_call = Some(ContractCall {
            contract_id: crate::vm::precompile::reserved::bridge_contract_id(),
            method_selector: crate::vm::precompile::reserved::bridge_burn_selector(),
            args: borsh::to_vec(&crate::bridge::BridgeBurnTx {
                wrapped_object_id: wrapped_id,
                burn_nonce: 14,
                source_chain_id: 0xAA55,
                recipient: [0x11; 20],
            })
            .unwrap(),
        });
        let burn_receipt = execute_tx(
            &env,
            &fx.signer.sign(burn_request),
            &mut fx.object_db,
            &mut fx.account_store,
        );
        assert!(
            burn_receipt.success,
            "bridge burn failed: {:?}",
            burn_receipt.error
        );
        assert!(fx.object_db.read(&wrapped_id).is_err());
        let mut staged_registry = bridge_snapshot.lock().unwrap().clone();
        let replay = crate::bridge::decode_bridge_replay_state_object(
            &fx.object_db
                .read(&crate::bridge::BRIDGE_REPLAY_STATE_OBJECT_ID)
                .unwrap(),
            DEFAULT_CHAIN_ID,
        )
        .unwrap();
        assert!(replay.matches_registry(staged_registry.registry_mut()));
        assert_eq!(replay.deposit_nonce_count, 1);
        assert_eq!(replay.burn_nonce_count, 1);
        assert_eq!(
            fx.account().nonce,
            4,
            "the rejected signed Public transaction consumes its account nonce by design"
        );
    }

    #[test]
    fn permissionless_validator_bond_is_rejected_without_mutating_validator_state() {
        let mut fx = Fixture::new();
        let caller = fx.caller();
        let initial_set = empty_validator_set();
        crate::economics::genesis_mint_with_system_objects(
            &mut fx.object_db,
            DEFAULT_CHAIN_ID,
            &[(caller, 1_000)],
            vec![
                crate::consensus::validator_set::validator_set_object(
                    DEFAULT_CHAIN_ID,
                    &initial_set,
                    0,
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let coin_id = fx
            .object_db
            .iter()
            .find(|object| crate::economics::is_native_coin_object(object))
            .expect("genesis coin exists")
            .id;
        let entry = crate::consensus::ValidatorEntry::new(
            fx.signer.tagged_pubkey(),
            [0x42; crate::consensus::VRF_PUBKEY_SIZE],
            600,
            0,
        );
        let mut request = public_request(0);
        request.inputs = vec![coin_id];
        request.contract_call = Some(ContractCall {
            contract_id: crate::vm::precompile::reserved::validator_system_contract_id(),
            method_selector: [0; 32],
            args: borsh::to_vec(&ValidatorSystemCall::Bond {
                entry: entry.clone(),
            })
            .unwrap(),
        });
        let tx = fx.signer.sign(request);
        let staged_set = Arc::new(Mutex::new(initial_set.clone()));
        let env = make_env().with_validator_set_snapshot(Arc::clone(&staged_set));

        let root_before = fx.object_db.state_root();
        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);
        assert!(!receipt.success, "permissionless bond must be rejected");
        assert!(receipt
            .error
            .as_deref()
            .is_some_and(|error| error.contains("permissionless validator bonding is disabled")));
        let actual = staged_set.lock().unwrap().clone();
        assert_eq!(
            actual, initial_set,
            "failed bond must not change the active set"
        );
        let persisted = crate::consensus::validator_set::decode_validator_set_object(
            &fx.object_db
                .read(&crate::consensus::validator_set::VALIDATOR_SET_OBJECT_ID)
                .unwrap(),
            DEFAULT_CHAIN_ID,
        )
        .unwrap();
        assert_eq!(
            persisted, initial_set,
            "state root must retain the genesis allowlist"
        );
        assert_eq!(fx.object_db.state_root(), root_before);
        assert!(
            fx.object_db.read(&coin_id).is_ok(),
            "bond input remains spendable"
        );
        crate::economics::reconcile_native_supply(&fx.object_db, 0).unwrap();
    }

    /// 断言状态未变（state_root 与账户 nonce/balance 均不变）。
    fn assert_state_unchanged(fx: &Fixture, nonce_before: u64, balance_before: u64) {
        assert_eq!(
            fx.object_db.state_root(),
            fx.initial_root,
            "失败 tx 不得改变 state_root"
        );
        let account = fx.account_store.get(&fx.caller());
        if let Some(acc) = account {
            assert_eq!(acc.nonce, nonce_before, "失败 tx 不得推进 nonce");
            assert_eq!(acc.balance, balance_before, "失败 tx 不得扣费");
        }
    }

    fn assert_failed_execution_settled(
        fx: &Fixture,
        receipt: &TxReceipt,
        nonce_before: u64,
        balance_before: u64,
    ) {
        assert!(!receipt.success);
        assert!(
            receipt.gas_used > 0,
            "已进入执行阶段的失败必须计 resource gas"
        );
        assert_eq!(fx.account().nonce, nonce_before + 1);
        assert_eq!(
            fx.account().balance,
            balance_before - receipt.fee_charged,
            "失败执行只结算 receipt 声明的 resource fee"
        );
    }

    // ===== execute_tx 正向路径 =====

    #[test]
    fn test_execute_tx_outputs_success() {
        let mut fx = Fixture::new();
        let env = make_env();
        let caller = fx.caller();

        let mut req = public_request(0);
        req.outputs = vec![
            make_output(caller, 0, b"obj0"),
            make_output(caller, 1, b"obj1"),
        ];
        let tx = fx.signer.sign(req);
        let expected_hash = tx.signing_hash();

        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);

        assert!(receipt.success, "应执行成功: {:?}", receipt.error);
        assert_eq!(receipt.tx_hash, expected_hash);
        assert_eq!(receipt.lane, TxLane::Public);
        assert_eq!(receipt.gas_used, 0, "无合约调用时 gas_used 为 0");
        assert_eq!(receipt.fee_charged, 0);
        assert_eq!(receipt.created_objects.len(), 2);
        assert!(receipt.error.is_none());

        // 对象已创建且 state_root 改变
        assert_ne!(fx.object_db.state_root(), fx.initial_root);
        for id in &receipt.created_objects {
            fx.object_db.read(id).expect("对象应已创建");
        }
        // nonce 推进
        assert_eq!(fx.account().nonce, 1);
        assert_eq!(fx.account().balance, 1_000_000);
    }

    #[test]
    fn test_execute_tx_contract_call_success() {
        let mut fx = Fixture::new();
        let env = make_env();
        let caller = fx.caller();
        let elf = build_test_elf(&make_program(1)); // mov r0,0; exit
        let contract_id = deploy_contract(&mut fx.object_db, caller, elf, 100, true);
        let root_after_deploy = fx.object_db.state_root();

        let mut req = public_request(0);
        req.contract_call = Some(ContractCall {
            contract_id,
            method_selector: [0u8; 32],
            args: vec![],
        });
        let tx = fx.signer.sign(req);

        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);

        assert!(receipt.success, "应执行成功: {:?}", receipt.error);
        assert!(
            receipt.gas_used >= 2,
            "至少消耗 mov+exit 两条指令 gas: {}",
            receipt.gas_used
        );
        assert_eq!(receipt.fee_charged, receipt.gas_used);
        // 余额扣费 + nonce 推进
        assert_eq!(fx.account().balance, 1_000_000 - receipt.gas_used);
        assert_eq!(fx.account().nonce, 1);
        // 空 object_cache → 无状态变更
        assert_eq!(fx.object_db.state_root(), root_after_deploy);
    }

    #[test]
    fn test_execute_tx_rejects_mutable_object_disguised_as_contract() {
        let mut fx = Fixture::new();
        let env = make_env();
        let caller = fx.caller();
        let contract_id = ObjectID::new(caller, 101);
        let forged_contract = ContractObject::new(
            contract_id,
            1,
            build_test_elf(&make_program(1)),
            caller,
            env.block_height,
        );

        // This object deliberately has a valid ContractObject payload but is an ordinary,
        // address-owned object.  Before the execution entrypoint performed structural
        // validation, it was accepted as executable bytecode and could later be mutated through
        // generic object syscalls.
        fx.object_db
            .create(Object::new(
                contract_id,
                Ownership::AddressOwned { owner: caller },
                "Generic",
                borsh::to_vec(&forged_contract).unwrap(),
                None,
            ))
            .unwrap();
        let root_before_call = fx.object_db.state_root();

        let mut req = public_request(0);
        req.contract_call = Some(ContractCall {
            contract_id,
            method_selector: [0u8; 32],
            args: vec![],
        });
        let receipt = execute_tx(
            &env,
            &fx.signer.sign(req),
            &mut fx.object_db,
            &mut fx.account_store,
        );

        assert!(!receipt.success, "non-Contract object must never execute");
        assert_eq!(
            fx.object_db.state_root(),
            root_before_call,
            "rejected forged contract call must not mutate object state"
        );
    }

    #[test]
    fn precompile_upgrade_proposal_is_consensus_persisted_and_release_pinned() {
        let mut fx = Fixture::new();
        let validators = validator_set_with_active_signers(&[&fx.signer]);
        install_governance_system_state(&mut fx, &validators);
        let current_governance = crate::governance::decode_governance_state_object(
            &fx.object_db
                .read(&crate::governance::GOVERNANCE_STATE_OBJECT_ID)
                .unwrap(),
            DEFAULT_CHAIN_ID,
        )
        .unwrap();
        let mut fast_governance = current_governance.clone();
        fast_governance.params.voting_period_blocks = 0;
        fast_governance.params.parameter_delay_blocks = 0;
        crate::governance::replace_persisted_governance_state(
            &mut fx.object_db,
            DEFAULT_CHAIN_ID,
            &current_governance,
            &fast_governance,
        )
        .unwrap();
        let validator_snapshot = Arc::new(Mutex::new(validators));
        let precompile_id = ObjectID::new([0xEE; 20], 91);
        let mut registry = PrecompileRegistry::new_consensus();
        registry.register(Arc::new(VersionedNoopPrecompile {
            id: precompile_id,
            version: 1,
        }));
        registry.register(Arc::new(VersionedNoopPrecompile {
            id: precompile_id,
            version: 2,
        }));
        let state = crate::vm::precompile::PrecompileGovernanceState::from_active_versions(
            DEFAULT_CHAIN_ID,
            [(precompile_id, 1)],
        )
        .unwrap();
        fx.object_db
            .system_create(
                crate::vm::precompile::precompile_governance_state_object(&state, 0).unwrap(),
            )
            .unwrap();
        let env = make_env()
            .with_fee_policy(FeePolicy::Free)
            .with_validator_set_snapshot(validator_snapshot)
            .with_precompile_registry(registry);

        let receipt = execute_tx(
            &env,
            &precompile_governance_system_tx(
                &fx.signer,
                0,
                PrecompileGovernanceSystemCall::CreateUpgradeProposal {
                    precompile_id,
                    new_version: 2,
                },
            ),
            &mut fx.object_db,
            &mut fx.account_store,
        );
        assert!(
            receipt.success,
            "precompile proposal failed: {:?}",
            receipt.error
        );
        let governance = crate::governance::decode_governance_state_object(
            &fx.object_db
                .read(&crate::governance::GOVERNANCE_STATE_OBJECT_ID)
                .unwrap(),
            DEFAULT_CHAIN_ID,
        )
        .unwrap();
        assert!(matches!(
            governance.proposals.get(&1).map(|proposal| &proposal.kind),
            Some(crate::governance::ProposalKind::PrecompileUpgrade {
                precompile_id: id,
                new_version: 2,
            }) if *id == precompile_id
        ));

        // A version the node did not compile is rejected before it can become a governance
        // commitment, so validators cannot later disagree about which native code is selected.
        let root_before = fx.object_db.state_root();
        let rejected = execute_tx(
            &env,
            &precompile_governance_system_tx(
                &fx.signer,
                1,
                PrecompileGovernanceSystemCall::CreateUpgradeProposal {
                    precompile_id,
                    new_version: 3,
                },
            ),
            &mut fx.object_db,
            &mut fx.account_store,
        );
        assert!(!rejected.success);
        assert_eq!(fx.object_db.state_root(), root_before);

        for (nonce, command) in [
            (
                2,
                GovernanceSystemCall::Vote {
                    proposal_id: 1,
                    approve: true,
                },
            ),
            (3, GovernanceSystemCall::FinalizeVoting { proposal_id: 1 }),
            (4, GovernanceSystemCall::ExecuteProposal { proposal_id: 1 }),
        ] {
            let receipt = execute_tx(
                &env,
                &governance_system_tx(&fx.signer, nonce, command),
                &mut fx.object_db,
                &mut fx.account_store,
            );
            assert!(
                receipt.success,
                "governance lifecycle failed: {:?}",
                receipt.error
            );
        }
        let (pending, _) = crate::vm::precompile::read_precompile_governance_state(
            &fx.object_db,
            DEFAULT_CHAIN_ID,
        )
        .unwrap();
        assert!(matches!(
            pending.activation(precompile_id).unwrap().pending,
            Some(crate::vm::PendingPrecompileUpgrade {
                version: 2,
                activate_at_height: 101,
            })
        ));
        let mut before_due = fx.object_db.create_snapshot();
        assert!(
            crate::vm::activate_due_precompile_upgrades(&mut before_due, DEFAULT_CHAIN_ID, 100,)
                .unwrap()
                .is_empty()
        );
        before_due.apply_to(&mut fx.object_db).unwrap();
        let mut due = fx.object_db.create_snapshot();
        assert_eq!(
            crate::vm::activate_due_precompile_upgrades(&mut due, DEFAULT_CHAIN_ID, 101).unwrap(),
            vec![precompile_id]
        );
        due.apply_to(&mut fx.object_db).unwrap();
        let (active, _) = crate::vm::precompile::read_precompile_governance_state(
            &fx.object_db,
            DEFAULT_CHAIN_ID,
        )
        .unwrap();
        assert_eq!(active.activation(precompile_id).unwrap().active_version, 2);
    }

    #[test]
    fn contract_deployment_and_timelocked_upgrade_are_consensus_persisted() {
        let mut fx = Fixture::new();
        let validators = empty_validator_set();
        install_governance_system_state(&mut fx, &validators);
        let env = make_env().with_fee_policy(FeePolicy::Free);
        let caller = fx.caller();
        let contract_id = ObjectID::new(caller, 102);
        let original_bytecode = build_test_elf(&make_program(1));
        let deployed = ContractObject::new(
            contract_id,
            1,
            original_bytecode.clone(),
            caller,
            env.block_height,
        );

        // A user may propose a deployment, but the executor reconstructs and creates the
        // protected immutable code object plus its reserved upgrade-state companion atomically.
        let mut deploy_request = public_request(0);
        deploy_request.outputs = vec![crate::vm::contract::contract_object(&deployed, 0).unwrap()];
        let deploy = execute_tx(
            &env,
            &fx.signer.sign(deploy_request),
            &mut fx.object_db,
            &mut fx.account_store,
        );
        assert!(deploy.success, "deployment failed: {:?}", deploy.error);
        let state_id =
            crate::vm::contract::contract_upgrade_state_id(DEFAULT_CHAIN_ID, contract_id);
        assert_eq!(deploy.created_objects, vec![contract_id, state_id]);
        let stored_contract = fx.object_db.read(&contract_id).unwrap();
        assert!(matches!(stored_contract.owner, Ownership::Immutable));
        assert_eq!(
            crate::vm::contract::decode_contract_object(&stored_contract)
                .unwrap()
                .bytecode,
            original_bytecode
        );
        let persisted_state = crate::vm::contract::decode_contract_upgrade_state_object(
            &fx.object_db.read(&state_id).unwrap(),
            DEFAULT_CHAIN_ID,
        )
        .unwrap();
        assert_eq!(persisted_state.state, crate::vm::UpgradeState::Idle);

        // Generic mutation APIs cannot alter, transfer, or delete deployed bytecode.
        assert!(
            fx.object_db
                .update(&contract_id, &caller, b"tamper".to_vec())
                .is_err()
        );
        assert!(
            fx.object_db
                .transfer(&contract_id, &caller, [0xA5; 20])
                .is_err()
        );
        assert!(fx.object_db.delete(&contract_id).is_err());

        let upgraded_bytecode = build_test_elf(&make_program(2));
        let initiate = execute_tx(
            &env,
            &contract_upgrade_system_tx(
                &fx.signer,
                1,
                crate::vm::ContractUpgradeSystemCall::Initiate {
                    contract_id,
                    new_bytecode: upgraded_bytecode.clone(),
                },
            ),
            &mut fx.object_db,
            &mut fx.account_store,
        );
        assert!(initiate.success, "initiate failed: {:?}", initiate.error);
        assert_eq!(initiate.modified_objects, vec![state_id]);
        let pending = crate::vm::contract::decode_contract_upgrade_state_object(
            &fx.object_db.read(&state_id).unwrap(),
            DEFAULT_CHAIN_ID,
        )
        .unwrap();
        assert!(matches!(
            pending.state,
            crate::vm::UpgradeState::Pending {
                new_version: 2,
                activate_at_height: 2_100,
                ..
            }
        ));

        let outsider = TestSigner::new();
        fx.account_store
            .create(Account::new(outsider.tagged_pubkey(), 1_000_000))
            .unwrap();
        let root_before_unauthorized = fx.object_db.state_root();
        let unauthorized = execute_tx(
            &env,
            &contract_upgrade_system_tx(
                &outsider,
                0,
                crate::vm::ContractUpgradeSystemCall::Cancel { contract_id },
            ),
            &mut fx.object_db,
            &mut fx.account_store,
        );
        assert!(
            !unauthorized.success,
            "non-holder must not control an upgrade"
        );
        assert_eq!(fx.object_db.state_root(), root_before_unauthorized);

        let mut before_due = fx.object_db.create_snapshot();
        assert!(
            crate::vm::activate_due_persisted_upgrades(&mut before_due, 2_099)
                .unwrap()
                .is_empty()
        );
        before_due.apply_to(&mut fx.object_db).unwrap();
        assert_eq!(
            crate::vm::contract::decode_contract_object(&fx.object_db.read(&contract_id).unwrap())
                .unwrap()
                .version,
            1
        );

        let mut due = fx.object_db.create_snapshot();
        assert_eq!(
            crate::vm::activate_due_persisted_upgrades(&mut due, 2_100).unwrap(),
            vec![contract_id]
        );
        due.apply_to(&mut fx.object_db).unwrap();
        let activated =
            crate::vm::contract::decode_contract_object(&fx.object_db.read(&contract_id).unwrap())
                .unwrap();
        assert_eq!(activated.version, 2);
        assert_eq!(activated.bytecode, upgraded_bytecode);
        assert_eq!(
            crate::vm::contract::decode_contract_upgrade_state_object(
                &fx.object_db.read(&state_id).unwrap(),
                DEFAULT_CHAIN_ID,
            )
            .unwrap()
            .state,
            crate::vm::UpgradeState::Idle
        );
    }

    #[test]
    fn free_fee_policy_meters_compute_without_requiring_or_debiting_balance() {
        let mut fx = Fixture::new();
        let caller = fx.caller();
        let elf = build_test_elf(&make_program(1));
        let contract_id = deploy_contract(&mut fx.object_db, caller, elf, 100, true);
        fx.account_store.get_mut(&caller).unwrap().balance = 0;

        let proposer_signer = TestSigner::new();
        let proposer = proposer_signer.address();
        fx.account_store
            .create(Account::new(proposer_signer.tagged_pubkey(), 0))
            .unwrap();
        let env = make_env()
            .with_fee_policy(FeePolicy::Free)
            .with_proposer(proposer);
        let mut req = public_request(0);
        req.contract_call = Some(ContractCall {
            contract_id,
            method_selector: [0u8; 32],
            args: vec![],
        });
        let tx = fx.signer.sign(req);

        let outcome = execute_block(&env, &[tx], &mut fx.object_db, &mut fx.account_store);
        let receipt = &outcome.receipts[0];
        assert!(receipt.success, "free-fee tx failed: {:?}", receipt.error);
        assert!(receipt.gas_used > 0, "compute must still be metered");
        assert_eq!(receipt.fee_charged, 0);
        assert_eq!(outcome.total_gas_used, receipt.gas_used);
        assert_eq!(fx.account().balance, 0);
        assert_eq!(
            fx.account().nonce,
            1,
            "free-fee public tx still advances nonce"
        );
        assert_eq!(
            fx.account_store.get(&proposer).unwrap().balance,
            0,
            "metered compute and free-fee execution must not mint proposer revenue"
        );
    }

    #[test]
    fn execution_environment_defaults_to_free_resource_policy() {
        assert_eq!(
            ExecutionEnvironment::new(DEFAULT_CHAIN_ID, 1, 1).fee_policy,
            FeePolicy::Free
        );
    }

    #[test]
    fn test_execute_tx_gameturn_contract_call_gas_free() {
        // 重构后：gas-free lane（GameTurn）+ gas-free precompile → 免 gas 执行。
        // 必须注入 PrecompileRegistry + gas-free precompile，否则被 lane-contract
        // 一致性校验拒绝。
        let mut fx = Fixture::new();
        // 注册一个 gas-free precompile（用保留命名空间外的地址避免冲突）
        let gas_free_id = ObjectID::new([0xFE; 20], 200);
        let env = make_gas_free_env(gas_free_id);

        let mut req = gameturn_request();
        req.contract_call = Some(ContractCall {
            contract_id: gas_free_id,
            method_selector: [0u8; 32],
            args: vec![],
        });
        let tx = fx.signer.sign(req);

        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);

        assert!(
            receipt.success,
            "GameTurn + gas-free precompile 应成功: {:?}",
            receipt.error
        );
        assert_eq!(
            receipt.gas_used,
            crate::vm::gas_table::GAS_PRECOMPILE_BASE,
            "GameTurn 免 caller fee，但 native work 计入 block gas"
        );
        assert_eq!(receipt.fee_charged, 0);
        // 账户不被触碰（gas-free lane 不走 account nonce）
        assert_eq!(fx.account().nonce, 0);
        assert_eq!(fx.account().balance, 1_000_000);
    }

    #[test]
    fn failed_tx_discards_precompile_mutation_before_late_output_error() {
        let mut fx = Fixture::new();
        let caller = fx.caller();
        let target = make_output(caller, 777, b"original");
        fx.object_db.create(target.clone()).unwrap();
        let root_before = fx.object_db.state_root();

        let precompile_id = ObjectID::new([0xED; 20], 778);
        let mut registry = PrecompileRegistry::new();
        registry.register(Arc::new(MutatingTestPrecompile {
            id: precompile_id,
            target: target.id,
        }));
        let env = make_env().with_precompile_registry(registry);

        let mut request = gameturn_request();
        request.contract_call = Some(ContractCall {
            contract_id: precompile_id,
            method_selector: [0; 32],
            args: vec![],
        });
        // The explicit output collides only after the precompile has mutated `target`.
        request.outputs = vec![target.clone()];
        let tx = fx.signer.sign(request);

        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);

        assert!(
            !receipt.success,
            "late output collision must fail the transaction"
        );
        assert_eq!(fx.object_db.state_root(), root_before);
        assert_eq!(fx.object_db.read(&target.id).unwrap().data, b"original");
        assert_eq!(
            fx.account().nonce,
            0,
            "failed GameTurn must not touch account nonce"
        );
    }

    #[test]
    fn test_execute_tx_gameturn_without_contract_call_rejected() {
        // 重构后：gas-free lane（GameTurn）无 contract_call 直接被拒绝
        // （lane-contract 一致性校验：gas-free lane 必须配 gas-free precompile）。
        let mut fx = Fixture::new();
        let env = make_env();
        let (nonce0, bal0) = (fx.account().nonce, fx.account().balance);

        let tx = fx.signer.sign(gameturn_request());
        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);

        assert!(!receipt.success, "gas-free lane 无 contract_call 应被拒绝");
        assert!(
            receipt
                .error
                .as_deref()
                .is_some_and(|e| e.contains("gas-free lane")),
            "错误应说明 gas-free lane 一致性校验失败: {:?}",
            receipt.error
        );
        assert_state_unchanged(&fx, nonce0, bal0);
    }

    // ===== execute_tx 反向路径：防御性重校验 =====

    #[test]
    fn test_execute_tx_wrong_chain_id() {
        let mut fx = Fixture::new();
        let env = make_env();
        let (nonce0, bal0) = (fx.account().nonce, fx.account().balance);

        let mut req = public_request(0);
        req.chain_id = DEFAULT_CHAIN_ID + 1;
        let tx = fx.signer.sign(req);

        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);
        assert!(!receipt.success);
        assert!(
            receipt
                .error
                .as_deref()
                .is_some_and(|e| e.contains("chain_id") || e.contains("chain id")),
            "错误应为 WrongChainId: {:?}",
            receipt.error
        );
        assert_state_unchanged(&fx, nonce0, bal0);
    }

    #[test]
    fn test_execute_tx_invalid_signature() {
        let mut fx = Fixture::new();
        let env = make_env();
        let (nonce0, bal0) = (fx.account().nonce, fx.account().balance);

        let mut tx = fx.signer.sign(public_request(0));
        tx.signature[0] ^= 0x01; // 篡改签名

        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);
        assert!(!receipt.success);
        assert_state_unchanged(&fx, nonce0, bal0);
    }

    #[test]
    fn test_execute_tx_nonce_too_high() {
        let mut fx = Fixture::new();
        let env = make_env();
        let (nonce0, bal0) = (fx.account().nonce, fx.account().balance);

        let tx = fx.signer.sign(public_request(5)); // account.nonce = 0
        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);

        assert!(!receipt.success);
        assert!(
            receipt
                .error
                .as_deref()
                .is_some_and(|e| e.contains("nonce")),
            "错误应为 nonce 不匹配: {:?}",
            receipt.error
        );
        assert_state_unchanged(&fx, nonce0, bal0);
    }

    #[test]
    fn test_execute_tx_nonce_replay_rejected() {
        let mut fx = Fixture::new();
        let env = make_env();
        let caller = fx.caller();

        let mut req = public_request(0);
        req.outputs = vec![make_output(caller, 0, b"obj0")];
        let tx = fx.signer.sign(req);

        // 第一次执行成功
        let r1 = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);
        assert!(r1.success);
        let root_after_first = fx.object_db.state_root();

        // 重放同一 tx → NonceTooLow
        let r2 = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);
        assert!(!r2.success, "重放 tx 必须被拒绝");
        assert_eq!(
            fx.object_db.state_root(),
            root_after_first,
            "重放失败后状态不变"
        );
        assert_eq!(fx.account().nonce, 1);
    }

    #[test]
    fn test_execute_tx_insufficient_balance() {
        let mut fx = Fixture::new();
        let env = make_env();
        let (nonce0, bal0) = (fx.account().nonce, fx.account().balance);

        let mut req = public_request(0);
        req.gas = Gas::new(2_000_000, 1); // budget > balance(1_000_000)
        let tx = fx.signer.sign(req);

        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);
        assert!(!receipt.success);
        assert!(
            receipt
                .error
                .as_deref()
                .is_some_and(|e| e.contains("balance") || e.contains("insufficient")),
            "错误应为余额不足: {:?}",
            receipt.error
        );
        assert_state_unchanged(&fx, nonce0, bal0);
    }

    #[test]
    fn test_execute_tx_account_not_found() {
        let object_db = ObjectDb::open_inmemory().expect("打开内存 ObjectDb");
        let mut object_db = object_db;
        let mut account_store = AccountStore::new(); // 空账户库
        let env = make_env();
        let signer = TestSigner::new();
        let initial_root = object_db.state_root();

        let tx = signer.sign(public_request(0));
        let receipt = execute_tx(&env, &tx, &mut object_db, &mut account_store);

        assert!(!receipt.success);
        assert!(
            receipt
                .error
                .as_deref()
                .is_some_and(|e| e.contains("account not found")),
            "错误应为账户不存在: {:?}",
            receipt.error
        );
        assert_eq!(object_db.state_root(), initial_root);
    }

    // ===== execute_tx 反向路径：合约调用 =====

    #[test]
    fn test_execute_tx_contract_not_found() {
        let mut fx = Fixture::new();
        let env = make_env();
        let (nonce0, bal0) = (fx.account().nonce, fx.account().balance);

        let mut req = public_request(0);
        req.contract_call = Some(ContractCall {
            contract_id: ObjectID::new(fx.caller(), 999), // 不存在
            method_selector: [0u8; 32],
            args: vec![],
        });
        let tx = fx.signer.sign(req);

        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);
        assert!(!receipt.success);
        assert!(
            receipt
                .error
                .as_deref()
                .is_some_and(|e| e.contains("contract not found")),
            "错误应为 ContractNotFound: {:?}",
            receipt.error
        );
        assert_failed_execution_settled(&fx, &receipt, nonce0, bal0);
    }

    #[test]
    fn test_execute_tx_invalid_contract_bytecode() {
        let mut fx = Fixture::new();
        let env = make_env();
        let caller = fx.caller();
        // 部署垃圾字节码合约
        let contract_id = deploy_contract(
            &mut fx.object_db,
            caller,
            vec![0xDE, 0xAD, 0xBE, 0xEF],
            100,
            true,
        );
        let root_after_deploy = fx.object_db.state_root();

        let mut req = public_request(0);
        req.contract_call = Some(ContractCall {
            contract_id,
            method_selector: [0u8; 32],
            args: vec![],
        });
        let tx = fx.signer.sign(req);

        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);
        assert!(!receipt.success);
        assert!(
            receipt
                .error
                .as_deref()
                .is_some_and(|e| e.contains("bytecode") || e.contains("ELF")),
            "错误应为 InvalidBytecode: {:?}",
            receipt.error
        );
        // 部署后的 root 不变（执行无效果）
        assert_eq!(fx.object_db.state_root(), root_after_deploy);
        assert_eq!(
            fx.account().nonce,
            1,
            "合法 Public tx 的执行失败仍推进 nonce"
        );
    }

    #[test]
    fn test_execute_tx_inactive_contract_rejected() {
        let mut fx = Fixture::new();
        let env = make_env();
        let caller = fx.caller();
        let elf = build_test_elf(&make_program(1));
        let contract_id = deploy_contract(&mut fx.object_db, caller, elf, 100, false); // is_active=false

        let mut req = public_request(0);
        req.contract_call = Some(ContractCall {
            contract_id,
            method_selector: [0u8; 32],
            args: vec![],
        });
        let tx = fx.signer.sign(req);

        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);
        assert!(!receipt.success);
        assert!(
            receipt
                .error
                .as_deref()
                .is_some_and(|e| e.contains("no longer callable")),
            "错误应为 OldVersionNotCallable: {:?}",
            receipt.error
        );
        assert_eq!(fx.account().nonce, 1);
    }

    #[test]
    fn test_execute_tx_input_object_not_found() {
        let mut fx = Fixture::new();
        let env = make_env();
        let caller = fx.caller();
        let elf = build_test_elf(&make_program(1));
        let contract_id = deploy_contract(&mut fx.object_db, caller, elf, 100, true);
        let root_after_deploy = fx.object_db.state_root();

        let mut req = public_request(0);
        req.inputs = vec![ObjectID::new(caller, 999)]; // 输入对象不存在
        req.contract_call = Some(ContractCall {
            contract_id,
            method_selector: [0u8; 32],
            args: vec![],
        });
        let tx = fx.signer.sign(req);

        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);
        assert!(!receipt.success);
        assert!(
            receipt
                .error
                .as_deref()
                .is_some_and(|e| e.contains("object not found")),
            "错误应为 ObjectNotFound: {:?}",
            receipt.error
        );
        assert_eq!(fx.object_db.state_root(), root_after_deploy);
        assert_eq!(fx.account().nonce, 1);
    }

    #[test]
    fn test_execute_tx_out_of_gas() {
        let mut fx = Fixture::new();
        let env = make_env();
        let caller = fx.caller();
        // 101 条指令的程序，budget=10 → 第 11 条指令处 gas 耗尽
        let elf = build_test_elf(&make_program(100));
        let contract_id = deploy_contract(&mut fx.object_db, caller, elf, 100, true);
        let root_after_deploy = fx.object_db.state_root();

        let mut req = public_request(0);
        req.gas = Gas::new(10, 1);
        req.contract_call = Some(ContractCall {
            contract_id,
            method_selector: [0u8; 32],
            args: vec![],
        });
        let tx = fx.signer.sign(req);

        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);
        assert!(!receipt.success);
        assert!(
            receipt
                .error
                .as_deref()
                .is_some_and(|e| e.contains("out of gas")),
            "错误应为 OutOfGas: {:?}",
            receipt.error
        );
        assert_eq!(receipt.gas_used, 10, "失败 tx 消耗其已执行的 gas budget");
        assert_eq!(receipt.fee_charged, 10);
        // 合约对象状态回滚；账户 nonce/资源费仍结算，阻止免费重放。
        assert_eq!(fx.object_db.state_root(), root_after_deploy);
        assert_eq!(fx.account().nonce, 1);
        assert_eq!(fx.account().balance, 1_000_000 - 10);
    }

    // ===== execute_tx 反向路径：outputs 创建 =====

    #[test]
    fn test_execute_tx_output_creator_mismatch() {
        let mut fx = Fixture::new();
        let env = make_env();
        let (nonce0, bal0) = (fx.account().nonce, fx.account().balance);

        let mut req = public_request(0);
        // 输出对象 creator 是别人 → 冒名创建
        req.outputs = vec![make_output([0xAA; 20], 0, b"forged")];
        let tx = fx.signer.sign(req);

        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);
        assert!(!receipt.success);
        assert!(
            receipt
                .error
                .as_deref()
                .is_some_and(|e| e.contains("creator")),
            "错误应为 creator 不匹配: {:?}",
            receipt.error
        );
        assert_failed_execution_settled(&fx, &receipt, nonce0, bal0);
    }

    #[test]
    fn test_execute_tx_output_id_collision_atomic() {
        let mut fx = Fixture::new();
        let env = make_env();
        let caller = fx.caller();

        // 预创建对象（将与第二个输出碰撞）
        let collision_id = ObjectID::new(caller, 42);
        fx.object_db
            .create(make_output(caller, 42, b"existing"))
            .expect("预创建对象");
        let root_after_pre = fx.object_db.state_root();

        let mut req = public_request(0);
        req.outputs = vec![
            make_output(caller, 0, b"new_obj"),   // 本可成功
            make_output(caller, 42, b"collides"), // 碰撞
        ];
        let tx = fx.signer.sign(req);

        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);
        assert!(!receipt.success);
        // 全有或全无：第一个对象也不得创建
        assert!(
            fx.object_db.read(&ObjectID::new(caller, 0)).is_err(),
            "碰撞时整个 tx 不得产生任何对象"
        );
        // 已有对象数据未被覆盖
        let existing = fx.object_db.read(&collision_id).expect("已有对象仍在");
        assert_eq!(existing.data, b"existing");
        assert_eq!(fx.object_db.state_root(), root_after_pre);
        assert_eq!(fx.account().nonce, 1);
    }

    #[test]
    fn test_execute_tx_output_too_large() {
        let mut fx = Fixture::new();
        let env = make_env();
        let (nonce0, bal0) = (fx.account().nonce, fx.account().balance);
        let caller = fx.caller();

        let mut req = public_request(0);
        req.outputs = vec![make_output(caller, 0, &vec![0u8; MAX_OBJECT_SIZE + 1])];
        let tx = fx.signer.sign(req);

        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);
        assert!(!receipt.success);
        assert!(
            receipt
                .error
                .as_deref()
                .is_some_and(|e| e.contains("too large")),
            "错误应为 ObjectTooLarge: {:?}",
            receipt.error
        );
        assert_failed_execution_settled(&fx, &receipt, nonce0, bal0);
    }

    // ===== execute_block =====

    #[test]
    fn test_execute_block_mixed_txs() {
        let mut fx = Fixture::new();
        let env = make_env();
        let caller = fx.caller();
        let elf = build_test_elf(&make_program(1));
        let contract_id = deploy_contract(&mut fx.object_db, caller, elf, 100, true);

        // tx1：outputs 创建（成功）
        let mut req1 = public_request(0);
        req1.outputs = vec![make_output(caller, 0, b"obj0")];
        let tx1 = fx.signer.sign(req1);

        // tx2：合约调用（成功，消耗 gas）
        let mut req2 = public_request(1);
        req2.contract_call = Some(ContractCall {
            contract_id,
            method_selector: [0u8; 32],
            args: vec![],
        });
        let tx2 = fx.signer.sign(req2);

        // tx3：签名被篡改（失败）
        let mut tx3 = fx.signer.sign(public_request(2));
        tx3.signature[0] ^= 0x01;

        let outcome = execute_block(
            &env,
            &[tx1, tx2, tx3],
            &mut fx.object_db,
            &mut fx.account_store,
        );

        assert_eq!(outcome.receipts.len(), 3);
        assert!(outcome.receipts[0].success);
        assert!(outcome.receipts[1].success);
        assert!(!outcome.receipts[2].success, "篡改签名的 tx 应失败");

        // block gas 仅累计成功且需 gas 的 tx
        assert_eq!(outcome.total_gas_used, outcome.receipts[1].gas_used);
        assert!(outcome.total_gas_used > 0);

        // state_root 与 ObjectDb 一致；仅成功 tx 的变更可见
        assert_eq!(outcome.state_root, fx.object_db.state_root());
        fx.object_db
            .read(&ObjectID::new(caller, 0))
            .expect("tx1 的对象应存在");
        // nonce 仅被成功 tx 推进两次
        assert_eq!(fx.account().nonce, 2);
    }

    #[test]
    fn test_execute_block_gas_limit_skips_public_not_gameturn() {
        let mut fx = Fixture::new();
        // block_gas_limit=100：tx1(budget=60) 执行，tx2(budget=99) 超出跳过
        // 注入 gas-free precompile registry：tx3 走 gas-free lane + gas-free precompile
        let gas_free_id = ObjectID::new([0xFE; 20], 200);
        let env = make_gas_free_env(gas_free_id).with_block_gas_limit(100);
        let caller = fx.caller();
        let elf = build_test_elf(&make_program(1));
        let contract_id = deploy_contract(&mut fx.object_db, caller, elf, 100, true);

        let mut req1 = public_request(0);
        req1.gas = Gas::new(60, 1);
        req1.contract_call = Some(ContractCall {
            contract_id,
            method_selector: [0u8; 32],
            args: vec![],
        });
        let tx1 = fx.signer.sign(req1);

        let mut req2 = public_request(1);
        req2.gas = Gas::new(99, 1);
        req2.contract_call = Some(ContractCall {
            contract_id,
            method_selector: [1u8; 32],
            args: vec![],
        });
        let tx2 = fx.signer.sign(req2);

        // GameTurn tx 免 caller fee，但 native work 仍受 block resource limit 约束。
        let mut req3 = gameturn_request();
        req3.contract_call = Some(ContractCall {
            contract_id: gas_free_id,
            method_selector: [2u8; 32],
            args: vec![],
        });
        let tx3 = fx.signer.sign(req3);

        let outcome = execute_block(
            &env,
            &[tx1, tx2, tx3],
            &mut fx.object_db,
            &mut fx.account_store,
        );

        assert_eq!(outcome.receipts.len(), 3);
        assert!(outcome.receipts[0].success, "tx1 应执行成功");
        assert!(
            !outcome.receipts[1].success,
            "tx2 应被 block gas limit 跳过"
        );
        assert!(
            outcome.receipts[1]
                .error
                .as_deref()
                .is_some_and(|e| e.contains("out of gas")),
            "tx2 错误应为 OutOfGas: {:?}",
            outcome.receipts[1].error
        );
        assert!(!outcome.receipts[2].success);
        assert!(
            outcome.receipts[2]
                .error
                .as_deref()
                .is_some_and(|error| error.contains("out of gas"))
        );
        assert_eq!(outcome.receipts[2].gas_used, 0);
        // block gas 仅含 tx1 的消耗
        assert_eq!(outcome.total_gas_used, outcome.receipts[0].gas_used);
        // tx2 未推进 nonce：tx1 一次 + tx3 不走 account nonce
        assert_eq!(fx.account().nonce, 1);
    }

    #[test]
    fn test_execute_block_deterministic_state_root() {
        // 同一 signer + 同一 tx 序列 + 两个全新状态 → 相同 state_root
        let signer = TestSigner::new();
        let caller = signer.address();
        let elf = build_test_elf(&make_program(2));

        let run = || {
            let mut object_db = ObjectDb::open_inmemory().expect("打开内存 ObjectDb");
            let mut account_store = AccountStore::new();
            account_store
                .create(Account::new(signer.tagged_pubkey(), 1_000_000))
                .expect("创建账户");
            let contract_id = deploy_contract(&mut object_db, caller, elf.clone(), 100, true);

            let mut req1 = public_request(0);
            req1.outputs = vec![make_output(caller, 0, b"obj0")];
            let tx1 = signer.sign(req1);

            let mut req2 = public_request(1);
            req2.contract_call = Some(ContractCall {
                contract_id,
                method_selector: [0u8; 32],
                args: vec![1, 2, 3],
            });
            let tx2 = signer.sign(req2);

            let env = make_env();
            execute_block(&env, &[tx1, tx2], &mut object_db, &mut account_store)
        };

        let outcome1 = run();
        let outcome2 = run();

        assert_eq!(
            outcome1.state_root, outcome2.state_root,
            "相同输入必须产生相同 state_root（出块/验证确定性）"
        );
        assert_eq!(outcome1.total_gas_used, outcome2.total_gas_used);
        assert!(outcome1.receipts.iter().all(|r| r.success));
    }

    #[test]
    fn test_execute_block_empty() {
        let mut fx = Fixture::new();
        let env = make_env();
        let outcome = execute_block(&env, &[], &mut fx.object_db, &mut fx.account_store);

        assert!(outcome.receipts.is_empty());
        assert_eq!(outcome.total_gas_used, 0);
        assert_eq!(outcome.state_root, fx.initial_root, "空 block 状态根不变");
    }

    // ===== 重构新增：lane-contract 一致性 + 非对称 gas 策略测试 =====

    #[test]
    fn test_gas_free_lane_with_gas_free_precompile_succeeds() {
        // lane=GameTurn + gas-free precompile → 执行成功，计 block gas，
        // 不扣 caller fee、不推进 account nonce。
        let mut fx = Fixture::new();
        let gas_free_id = ObjectID::new([0xFE; 20], 200);
        let env = make_gas_free_env(gas_free_id);

        let mut req = gameturn_request();
        req.contract_call = Some(ContractCall {
            contract_id: gas_free_id,
            method_selector: [0u8; 32],
            args: vec![],
        });
        let tx = fx.signer.sign(req);

        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);

        assert!(receipt.success, "应执行成功: {:?}", receipt.error);
        assert_eq!(receipt.gas_used, crate::vm::gas_table::GAS_PRECOMPILE_BASE);
        assert_eq!(receipt.fee_charged, 0, "gas-free lane 不扣费");
        assert_eq!(fx.account().nonce, 0, "gas-free lane 不推进 nonce");
        assert_eq!(fx.account().balance, 1_000_000, "gas-free lane 不扣余额");
    }

    #[test]
    fn test_gameturn_replay_rejected_by_objectdb_nonce() {
        let mut fx = Fixture::new();
        let gas_free_id = ObjectID::new([0xFE; 20], 200);
        let env = make_gas_free_env(gas_free_id);

        let mut req = gameturn_request();
        req.contract_call = Some(ContractCall {
            contract_id: gas_free_id,
            method_selector: [0u8; 32],
            args: vec![],
        });
        let tx = fx.signer.sign(req);

        let first = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);
        assert!(first.success, "首笔 GameTurn 应成功: {:?}", first.error);
        let second = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);
        assert!(!second.success, "重放的 GameTurn 必须失败");
        assert!(
            second
                .error
                .as_deref()
                .is_some_and(|error| error.contains("nonce")),
            "unexpected replay error: {:?}",
            second.error
        );
        assert_eq!(
            fx.account().nonce,
            0,
            "GameTurn 不应推进 legacy account nonce"
        );
    }

    #[test]
    fn failed_gas_free_crypto_precompile_consumes_block_gas_without_caller_fee() {
        let mut fx = Fixture::new();
        let gas_free_id = ObjectID::new([0xFC; 20], 201);
        let native_crypto_gas = crate::vm::gas_table::GAS_STWO_VERIFY + 123;
        let calls = Arc::new(AtomicUsize::new(0));
        let env = make_failing_gas_free_env(gas_free_id, native_crypto_gas, calls.clone());
        let initial_root = fx.object_db.state_root();
        let initial_nonce = fx.account().nonce;
        let initial_balance = fx.account().balance;

        let mut req = gameturn_request();
        req.contract_call = Some(ContractCall {
            contract_id: gas_free_id,
            method_selector: [0xA5; 32],
            args: vec![7; 64],
        });
        let tx = fx.signer.sign(req);

        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);

        assert!(!receipt.success);
        assert!(
            receipt
                .error
                .as_deref()
                .is_some_and(|error| error.contains("crypto proof"))
        );
        assert_eq!(receipt.gas_used, native_crypto_gas);
        assert_eq!(receipt.fee_charged, 0);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(fx.object_db.state_root(), initial_root);
        assert_eq!(fx.account().nonce, initial_nonce);
        assert_eq!(fx.account().balance, initial_balance);
    }

    #[test]
    fn parallel_block_admission_skips_over_limit_native_crypto_before_execution() {
        let mut fx = Fixture::new();
        let gas_free_id = ObjectID::new([0xFB; 20], 202);
        let native_crypto_gas = crate::vm::gas_table::GAS_STWO_VERIFY;
        let calls = Arc::new(AtomicUsize::new(0));
        let env = make_failing_gas_free_env(gas_free_id, native_crypto_gas, calls.clone())
            .with_block_gas_limit(native_crypto_gas);

        let make_tx = |selector: u8| {
            let mut req = gameturn_request();
            req.contract_call = Some(ContractCall {
                contract_id: gas_free_id,
                method_selector: [selector; 32],
                args: vec![selector; 32],
            });
            fx.signer.sign(req)
        };
        let txs = [make_tx(1), make_tx(2)];

        let outcome = execute_block(&env, &txs, &mut fx.object_db, &mut fx.account_store);

        assert!(
            !outcome.receipts[0].success,
            "first native verifier call fails after execution"
        );
        assert_eq!(outcome.receipts[0].gas_used, native_crypto_gas);
        assert!(!outcome.receipts[1].success);
        assert_eq!(outcome.receipts[1].gas_used, 0);
        assert!(
            outcome.receipts[1]
                .error
                .as_deref()
                .is_some_and(|error| error.contains("out of gas"))
        );
        assert_eq!(outcome.total_gas_used, native_crypto_gas);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "over-limit proof must never reach host verifier"
        );
    }

    #[test]
    fn test_gas_free_lane_with_non_gas_free_contract_rejected() {
        // 核心安全测试：lane=GameTurn + 普通 rBPF 合约 → 拒绝执行（防免费 gas DoS）。
        let mut fx = Fixture::new();
        let caller = fx.caller();
        let env = make_env(); // 无 precompile registry
        let elf = build_test_elf(&make_program(1));
        let contract_id = deploy_contract(&mut fx.object_db, caller, elf, 100, true);

        let (nonce0, bal0) = (fx.account().nonce, fx.account().balance);
        let mut req = gameturn_request();
        req.contract_call = Some(ContractCall {
            contract_id,
            method_selector: [0u8; 32],
            args: vec![],
        });
        let tx = fx.signer.sign(req);

        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);

        assert!(!receipt.success, "gas-free lane + 非免 gas 合约必须被拒绝");
        assert!(
            receipt
                .error
                .as_deref()
                .is_some_and(|e| e.contains("gas-free lane")),
            "错误应说明 gas-free lane 一致性校验失败: {:?}",
            receipt.error
        );
        // 状态不变（账户未触碰、state_root 不变）
        assert_eq!(fx.account().nonce, nonce0);
        assert_eq!(fx.account().balance, bal0);
    }

    #[test]
    fn test_gas_free_lane_with_unregistered_contract_rejected() {
        // lane=GameTurn + 未注册 ObjectID → 拒绝执行。
        let mut fx = Fixture::new();
        let gas_free_id = ObjectID::new([0xFE; 20], 200);
        let env = make_gas_free_env(gas_free_id); // 仅注册了 gas_free_id
        let unregistered_id = ObjectID::new([0xFD; 20], 999);

        let (nonce0, bal0) = (fx.account().nonce, fx.account().balance);
        let mut req = gameturn_request();
        req.contract_call = Some(ContractCall {
            contract_id: unregistered_id,
            method_selector: [0u8; 32],
            args: vec![],
        });
        let tx = fx.signer.sign(req);

        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);

        assert!(!receipt.success, "gas-free lane + 未注册合约必须被拒绝");
        assert!(
            receipt
                .error
                .as_deref()
                .is_some_and(|e| e.contains("gas-free lane")),
            "错误应说明 gas-free lane 一致性校验失败: {:?}",
            receipt.error
        );
        assert_eq!(fx.account().nonce, nonce0);
        assert_eq!(fx.account().balance, bal0);
    }

    #[test]
    fn test_public_lane_with_gas_free_precompile_charges_nonce() {
        // lane=Public + gas-free precompile → 执行成功，按 native resource gas 计费并推进 nonce。
        // 验证非对称策略：gas 策略跟随 lane 而非合约属性（Assumption 3）。
        let mut fx = Fixture::new();
        let gas_free_id = ObjectID::new([0xFE; 20], 200);
        let env = make_gas_free_env(gas_free_id);

        let mut req = public_request(0);
        req.contract_call = Some(ContractCall {
            contract_id: gas_free_id,
            method_selector: [0u8; 32],
            args: vec![],
        });
        let tx = fx.signer.sign(req);

        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);

        assert!(
            receipt.success,
            "Public lane + gas-free precompile 应成功: {:?}",
            receipt.error
        );
        assert_eq!(receipt.gas_used, crate::vm::gas_table::GAS_PRECOMPILE_BASE);
        assert_eq!(receipt.fee_charged, receipt.gas_used);
        // 但 Public lane 推进 nonce（重放保护）
        assert_eq!(fx.account().nonce, 1, "Public lane 必须推进 nonce");
        assert_eq!(fx.account().balance, 1_000_000 - receipt.fee_charged);
    }

    #[test]
    fn test_checkpoint_anchor_lane_with_gas_free_precompile_succeeds() {
        // lane=CheckpointAnchor + gas-free precompile → 免 caller fee，但计 block gas。
        let mut fx = Fixture::new();
        let gas_free_id = ObjectID::new([0xFE; 20], 200);
        let env = make_gas_free_env(gas_free_id);

        let mut req = gameturn_request();
        req.lane_hint = TxLane::CheckpointAnchor;
        req.route_hint = RouteHint::AssignedValidator;
        req.contract_call = Some(ContractCall {
            contract_id: gas_free_id,
            method_selector: [0u8; 32],
            args: vec![],
        });
        let tx = fx.signer.sign(req);

        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);

        assert!(
            receipt.success,
            "CheckpointAnchor + gas-free precompile 应成功: {:?}",
            receipt.error
        );
        assert_eq!(receipt.gas_used, crate::vm::gas_table::GAS_PRECOMPILE_BASE);
        assert_eq!(receipt.fee_charged, 0);
        assert_eq!(
            fx.account().nonce,
            1,
            "CheckpointAnchor 使用 account nonce 防重放"
        );
        assert_eq!(fx.account().balance, 1_000_000);
    }

    #[test]
    fn test_gas_free_lane_without_registry_rejected() {
        // 无 precompile registry 时，gas-free lane 任意 contract_call 都被拒绝。
        let mut fx = Fixture::new();
        let caller = fx.caller();
        let env = make_env(); // 无 precompile_registry
        let elf = build_test_elf(&make_program(1));
        let contract_id = deploy_contract(&mut fx.object_db, caller, elf, 100, true);

        let (nonce0, bal0) = (fx.account().nonce, fx.account().balance);
        let mut req = gameturn_request();
        req.contract_call = Some(ContractCall {
            contract_id,
            method_selector: [0u8; 32],
            args: vec![],
        });
        let tx = fx.signer.sign(req);

        let receipt = execute_tx(&env, &tx, &mut fx.object_db, &mut fx.account_store);

        assert!(!receipt.success, "无 registry 时 gas-free lane 必须被拒绝");
        assert!(
            receipt
                .error
                .as_deref()
                .is_some_and(|e| e.contains("gas-free lane")),
            "错误应说明 gas-free lane 一致性校验失败: {:?}",
            receipt.error
        );
        assert_eq!(fx.account().nonce, nonce0);
        assert_eq!(fx.account().balance, bal0);
    }

    // ===== resource metering 与 proposer 不铸币 =====

    #[test]
    fn charged_resource_credits_are_not_transferred_to_proposer() {
        let mut fx = Fixture::new();
        let caller = fx.caller();
        // 部署一个合约（供调用产生 gas）。
        let elf = build_test_elf(&make_program(1));
        let contract_id = deploy_contract(&mut fx.object_db, caller, elf, 100, true);

        // proposer 账户：独立 tagged pubkey，初始余额 0。
        let proposer_signer = TestSigner::new();
        let proposer_addr = proposer_signer.address();
        fx.account_store
            .create(Account::new(proposer_signer.tagged_pubkey(), 0))
            .expect("创建 proposer 账户");

        let env = make_env().with_proposer(proposer_addr);
        let mut req = public_request(0);
        req.gas = Gas::new(1_000_000, 1);
        req.contract_call = Some(ContractCall {
            contract_id,
            method_selector: [0u8; 32],
            args: vec![],
        });
        let tx = fx.signer.sign(req);
        let caller_bal_before = fx.account().balance;

        let outcome = execute_block(&env, &[tx], &mut fx.object_db, &mut fx.account_store);

        assert!(outcome.total_gas_used > 0, "合约调用应产生 gas 消耗，got 0");
        let proposer_bal_after = fx
            .account_store
            .get(&proposer_addr)
            .expect("proposer 账户应存在")
            .balance;
        assert_eq!(
            proposer_bal_after, 0,
            "resource credits are non-transferable and proposer rewards must not mint ZCN"
        );
        // Explicit Charged mode still consumes the caller's legacy resource credits.
        let caller_bal_after = fx.account().balance;
        assert_eq!(
            caller_bal_before - caller_bal_after,
            outcome.total_gas_used,
            "caller resource-credit debit must equal metered gas"
        );
    }

    #[test]
    fn charged_resource_credits_are_consumed_without_a_proposer() {
        let mut fx = Fixture::new();
        let caller = fx.caller();
        let elf = build_test_elf(&make_program(1));
        let contract_id = deploy_contract(&mut fx.object_db, caller, elf, 100, true);
        let env = make_env(); // 无 proposer
        let mut req = public_request(0);
        req.gas = Gas::new(1_000_000, 1);
        req.contract_call = Some(ContractCall {
            contract_id,
            method_selector: [0u8; 32],
            args: vec![],
        });
        let tx = fx.signer.sign(req);
        let caller_bal_before = fx.account().balance;

        let outcome = execute_block(&env, &[tx], &mut fx.object_db, &mut fx.account_store);
        assert!(outcome.total_gas_used > 0, "合约调用应产生 gas");
        let caller_bal_after = fx.account().balance;
        // gas 从 caller 扣除（烧毁），无 proposer 收到。
        assert_eq!(caller_bal_before - caller_bal_after, outcome.total_gas_used);
    }

    #[test]
    fn empty_block_does_not_mint_proposer_reward() {
        let mut fx = Fixture::new();
        let proposer_signer = TestSigner::new();
        let proposer_addr = proposer_signer.address();
        fx.account_store
            .create(Account::new(proposer_signer.tagged_pubkey(), 0))
            .expect("创建 proposer 账户");

        let env = make_env().with_proposer(proposer_addr);
        let outcome = execute_block(&env, &[], &mut fx.object_db, &mut fx.account_store);
        assert_eq!(outcome.total_gas_used, 0, "空 block 无 gas");
        let proposer_bal = fx.account_store.get(&proposer_addr).unwrap().balance;
        assert_eq!(
            proposer_bal, 0,
            "empty blocks must not mint value outside TreasuryCap"
        );
    }

    // ===== 缺口 #4-M1：原生转账测试 =====

    #[test]
    fn native_transfer_consumes_utxo_and_creates_recipient_plus_change() {
        let mut fx = Fixture::new();
        let caller = fx.caller();
        let caller_bal_before = fx.account().balance;

        // recipient 账户（独立 TestSigner，初始余额 0）。
        let recipient_signer = TestSigner::new();
        let recipient_addr = recipient_signer.address();
        fx.account_store
            .create(Account::new(recipient_signer.tagged_pubkey(), 0))
            .unwrap();

        let input = crate::economics::native_coin_object(caller, 120_000, 77).unwrap();
        fx.object_db.create(input.clone()).unwrap();

        // 构造转账 tx：transfer contract_call。
        let transfer_amount = 100_000u64;
        let mut req = public_request(0);
        req.inputs = vec![input.id];
        req.contract_call = Some(ContractCall {
            contract_id: crate::vm::precompile::reserved::transfer_contract_id(),
            method_selector: [0u8; 32],
            args: borsh::to_vec(&TransferArgs {
                recipient: recipient_addr,
                amount: transfer_amount,
            })
            .unwrap(),
        });
        let tx = fx.signer.sign(req);

        let env = make_env();
        let outcome = execute_block(&env, &[tx], &mut fx.object_db, &mut fx.account_store);
        assert!(outcome.receipts[0].success, "转账应成功");
        assert!(
            fx.object_db.read(&input.id).is_err(),
            "input UTXO must be spent"
        );
        assert_eq!(
            crate::economics::native_coin_balance(&fx.object_db, recipient_addr).unwrap(),
            transfer_amount
        );
        assert_eq!(
            crate::economics::native_coin_balance(&fx.object_db, caller).unwrap(),
            20_000
        );
        assert_eq!(fx.account().balance, caller_bal_before);
        assert_eq!(
            fx.account_store.get(&recipient_addr).unwrap().balance,
            0,
            "recipient Account metadata must not carry ZCN"
        );
    }

    #[test]
    fn native_transfer_rejects_insufficient_utxo_value_atomically() {
        let mut fx = Fixture::new();
        let caller = fx.caller();
        let account_balance_before = fx.account().balance;
        let input = crate::economics::native_coin_object(caller, 10, 78).unwrap();
        fx.object_db.create(input.clone()).unwrap();

        let recipient_signer = TestSigner::new();
        let recipient_addr = recipient_signer.address();
        fx.account_store
            .create(Account::new(recipient_signer.tagged_pubkey(), 0))
            .unwrap();

        let mut req = public_request(0);
        req.inputs = vec![input.id];
        req.contract_call = Some(ContractCall {
            contract_id: crate::vm::precompile::reserved::transfer_contract_id(),
            method_selector: [0u8; 32],
            args: borsh::to_vec(&TransferArgs {
                recipient: recipient_addr,
                amount: 100,
            })
            .unwrap(),
        });
        let tx = fx.signer.sign(req);

        let env = make_env();
        let outcome = execute_block(&env, &[tx], &mut fx.object_db, &mut fx.account_store);
        assert!(!outcome.receipts[0].success, "UTXO value不足转账应失败");
        assert_eq!(
            fx.account().balance,
            account_balance_before - outcome.receipts[0].fee_charged
        );
        assert_eq!(fx.account().nonce, 1);
        assert!(
            fx.object_db.read(&input.id).is_ok(),
            "failed spend keeps input"
        );
        assert_eq!(
            crate::economics::native_coin_balance(&fx.object_db, caller).unwrap(),
            10
        );
        assert_eq!(
            crate::economics::native_coin_balance(&fx.object_db, recipient_addr).unwrap(),
            0,
            "failed transfer creates no recipient UTXO"
        );
    }

    #[test]
    fn native_transfer_rejects_explicit_outputs_before_spending_inputs() {
        let mut fx = Fixture::new();
        let caller = fx.caller();
        let recipient = [0x55; 20];
        let input = crate::economics::native_coin_object(caller, 100, 79).unwrap();
        fx.object_db.create(input.clone()).unwrap();

        let mut req = public_request(0);
        req.inputs = vec![input.id];
        req.outputs = vec![make_output(caller, 999, b"unexpected")];
        req.contract_call = Some(ContractCall {
            contract_id: crate::vm::precompile::reserved::transfer_contract_id(),
            method_selector: [0u8; 32],
            args: borsh::to_vec(&TransferArgs {
                recipient,
                amount: 60,
            })
            .unwrap(),
        });
        let tx = fx.signer.sign(req);

        let receipt = execute_tx(&make_env(), &tx, &mut fx.object_db, &mut fx.account_store);
        assert!(!receipt.success);
        assert!(fx.object_db.read(&input.id).is_ok());
        assert_eq!(
            crate::economics::native_coin_balance(&fx.object_db, caller).unwrap(),
            100
        );
        assert_eq!(
            crate::economics::native_coin_balance(&fx.object_db, recipient).unwrap(),
            0
        );
        assert_eq!(fx.account().nonce, 1);
        assert!(receipt.gas_used > 0);
    }
}
