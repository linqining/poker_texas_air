//! 结算与上链：一手牌结束后
//! 1. `derive_settlement_plan` 计算分池 / rake / awards（poker_l1 内置）
//! 2. `Orchestrator::prove_and_verify_chain` 把本手 ProveTask 证成 receipt 链
//! 3. `prove_outer_aggregate` + `verify_outer_aggregate` 产出已验证聚合
//! 4. 组装 `register_aggregate` / `settle_hand` 的 Cairo calldata
//! 5. 操作员账户提交到 PokerSettlement 合约（配置齐备时）
//!
//! dev 模式（未配置 settlement 合约/操作员）只生成 calldata 并记日志，
//! 保证无链环境可以跑完整流程（证明生成照常执行）。

use poker_l1::vm::contracts::texas_poker::settlement::{derive_settlement_plan, SettlementPlan};
use poker_texas_air::outer_aggregate::{prove_outer_aggregate, verify_outer_aggregate, VerifiedOuterAggregate};
use poker_texas_air::orchestrator::Orchestrator;
use poker_texas_air::starknet_settlement::{
    AggregateDigestFelts, RegisterAggregateCalldata, SettleHandCalldata,
};
use starknet::accounts::{Account, ExecutionEncoder};
use starknet::core::types::{Call, Felt};
use starknet::core::utils::starknet_keccak;
use starknet_ff::FieldElement as Ff;

use super::mirror::TableMirror;

/// starknet-ff (0.3) FieldElement → starknet (0.13) Felt 的别名。
/// 两者均为 32 字节大端模元素，逐字节拷贝即可。
fn scale_felt(f: Ff) -> Felt {
    ff_to_felt(f)
}

/// 一手牌的完整结算产物。
pub struct HandSettlement {
    pub hand_id: u32,
    pub plan: SettlementPlan,
    /// `register_aggregate` calldata（felts，对齐 Cairo 合约 ABI）。
    pub register_calldata: Vec<Felt>,
    /// `settle_hand` calldata（felts，对齐 Cairo 合约 ABI，双 felt digest 形式）。
    pub settle_calldata: Vec<Felt>,
    /// 聚合摘要（32 字节大端）。
    pub aggregate_digest: [u8; 32],
    /// 重映射后的参与者（真实钱包 felt，settle 顺序）——Hand-batch 路径复用。
    pub players_remapped: Vec<Ff>,
    /// 与 players 对应的净输赢（零和）。
    pub deltas: Vec<i128>,
    /// 重映射后的 Poseidon 结算摘要（register root / Hand-batch 路径共用）。
    pub settlement_digest: Ff,
    /// G 链首 receipt 的 pre state root（hand_binding 输入）。
    pub pre_state_root: [u8; 32],
    /// G 链末 receipt 的 post state root（hand_binding 输入）。
    pub post_state_root: [u8; 32],
}

/// 结算镜像中当前手牌：证明 + 分池 + calldata。
///
/// 同步执行（prove 约 2 秒/hand），调用方应放在 `tokio::task::spawn_blocking` 里。
pub fn settle_hand(
    mirror: &TableMirror,
    rake_recipient: Option<poker_l1::Address>,
) -> Result<HandSettlement, String> {
    if mirror.tasks.is_empty() {
        return Err("mirror has no prove tasks for this hand".into());
    }
    // 只证明当前手的任务，且只聚合首个连续的 dual-proof 任务段：
    // outer aggregate 仅支持 4 种密码学动作（shuffle/reconstruct/fold_with_proof/
    // reveal tokens）；join/start_hand/下注等由 VerifiedChain 的 method proofs 覆盖，
    // 若混入会把聚合 receipt 链截断（state-root 不连续）。
    let hand_id = mirror.table.hand_id;
    use poker_texas_air::method_kind::MethodKind;
    let is_dual = |k: &MethodKind| {
        matches!(
            k,
            MethodKind::SubmitShuffleV2
                | MethodKind::SubmitPlayerRevealTokens
                | MethodKind::SubmitReconstructDeck
                | MethodKind::FoldWithProof
        )
    };
    let mut tasks: Vec<poker_texas_air::prove_task::ProveTask> = Vec::new();
    let mut seen_dual = false;
    for t in mirror.tasks.iter().filter(|t| t.hand_id == hand_id) {
        if is_dual(&t.method_kind) {
            tasks.push(t.clone());
            seen_dual = true;
        } else if seen_dual {
            break; // 第一个非 dual 任务结束聚合窗口
        }
    }
    if tasks.is_empty() {
        return Err(format!("mirror has no dual-proof tasks for hand {hand_id}"));
    }
    let tasks = &tasks;

    // 0. 派奖前快照优先：VM 在 advance_deadline 时已派奖（pot 清零、board 复位），
    //    而 settle_hand 需要 pre-payout 状态（board 5 张、pot、total_bet）。
    let settle_table = mirror
        .pre_settlement
        .as_ref()
        .unwrap_or(&mirror.table);

    // 1. 分池 / rake / awards（库内计算，含零和校验）。
    let plan = derive_settlement_plan(settle_table)
        .map_err(|e| format!("derive_settlement_plan failed: {e}"))?;

    // 2. 证明链（receipt chain）。
    let _chain = Orchestrator::prove_and_verify_chain(tasks)
        .map_err(|e| format!("prove_and_verify_chain failed: {e}"))?;

    // 3. outer aggregate：证明 + 验证，产出可信任的聚合工件。
    let bundle = prove_outer_aggregate(tasks)
        .map_err(|e| format!("prove_outer_aggregate failed: {e}"))?;
    let verified: VerifiedOuterAggregate = verify_outer_aggregate(tasks, &bundle)
        .map_err(|e| format!("verify_outer_aggregate failed: {e}"))?;
    let digest = verified.aggregate_digest();

    // 4. Cairo calldata。
    let settle = SettleHandCalldata::new(digest, hand_id, settle_table, &plan, rake_recipient)
        .map_err(|e| format!("SettleHandCalldata::new failed: {e}"))?;

    // 4.5 参与者地址重映射：mirror 座位只存钱包 felt 的低 160 位（poker_l1
    //     Address 为 20 字节），而 vault 余额以完整钱包 felt 为键。上链前把
    //     players 重映射回真实钱包地址，并按同一映射重算 settlement digest——
    //     合约 settle_hand 会用 calldata 的 players 重算 Poseidon 承诺并与
    //     register_aggregate 写入的 root 精确比对。
    let remaps = super::hooks::seat_wallet_remaps();
    let remap_player = |p: Ff| -> Ff {
        let p_felt = ff_to_felt(p);
        let truncated: [u8; 20] = p_felt.to_bytes_be()[12..32]
            .try_into()
            .expect("32-byte felt tail is 20 bytes");
        remaps
            .iter()
            .find(|(addr, _)| *addr == truncated)
            .map(|(_, wallet)| {
                let w = super::chain::parse_felt(wallet).unwrap_or(p_felt);
                felt_to_ff(&w)
            })
            .unwrap_or(p)
    };
    let players_remapped: Vec<Ff> = settle.players().iter().map(|p| remap_player(*p)).collect();
    let mut digest_fields: Vec<Ff> = vec![Ff::from(u64::from(settle.hand_id()))];
    for (p, d) in players_remapped.iter().zip(settle.deltas().iter()) {
        digest_fields.push(*p);
        let magnitude = u64::try_from(d.unsigned_abs()).map_err(|_| "delta magnitude overflow")?;
        if *d >= 0 {
            digest_fields.push(Ff::from(1u64));
        } else {
            digest_fields.push(Ff::from(0u64));
        }
        digest_fields.push(Ff::from(magnitude));
    }
    let settlement_digest = starknet_crypto::poseidon_hash_many(&digest_fields);

    // register_aggregate：本手一个 aggregate，settlement root 取重映射后的 digest。
    let register = RegisterAggregateCalldata::new(
        std::slice::from_ref(&verified),
        hand_id,
        hand_id,
        vec![settlement_digest],
    )
    .map_err(|e| format!("RegisterAggregateCalldata::new failed: {e}"))?;

    let register_calldata = register.to_felts().iter().map(|f| ff_to_felt(*f)).collect();
    let settle_calldata = build_settle_calldata(digest, &settle, &players_remapped);

    // G 链首尾 state root（hand_binding 的输入）：首 receipt 的 pre、
    // 末 receipt 的 post。
    let receipts = verified.chain().receipts();
    let pre_state_root = receipts
        .first()
        .ok_or("verified chain has no receipts")?
        .pre_state_root()
        .bytes();
    let post_state_root = receipts
        .last()
        .expect("non-empty checked above")
        .post_state_root()
        .bytes();

    Ok(HandSettlement {
        hand_id,
        plan,
        register_calldata,
        settle_calldata,
        aggregate_digest: digest,
        players_remapped,
        deltas: settle.deltas().to_vec(),
        settlement_digest,
        pre_state_root,
        post_state_root,
    })
}

/// `settle_hand(aggregate_digest: (felt252, felt252), hand_id: u64,
///               players: Span<ContractAddress>, deltas: Span<i128>)` 的 calldata。
///
/// 合约使用双 felt digest；Rust builder 的 `to_felts()` 是单 felt 旧格式，
/// 这里按当前合约 ABI 手工组装。`players` 为重映射后的真实钱包地址。
fn build_settle_calldata(digest: [u8; 32], settle: &SettleHandCalldata, players: &[Ff]) -> Vec<Felt> {
    let felts = AggregateDigestFelts::split(&digest).expect("32-byte digest always splits");
    let mut out = Vec::with_capacity(4 + players.len() * 2);
    out.push(scale_felt(felts.hi));
    out.push(scale_felt(felts.lo));
    out.push(Felt::from(settle.hand_id()));
    out.push(Felt::from(players.len() as u64));
    out.extend(players.iter().map(|p| scale_felt(*p)));
    out.push(Felt::from(settle.deltas().len() as u64));
    out.extend(settle.deltas().iter().map(|d| scale_felt(i128_to_ff(*d))));
    out
}

/// 把结算产物提交到链上。返回交易哈希（register, settle）。
pub async fn submit_settlement(
    settlement: &HandSettlement,
    settlement_address: &str,
) -> Result<(String, String), String> {
    let chain = super::chain().ok_or("starknet chain not initialized")?;
    let contract = super::chain::parse_felt(settlement_address)
        .ok_or("invalid settlement contract address")?;
    let operator = chain.operator().await.ok_or("operator account unavailable")?;

    let register_call = Call {
        to: contract,
        selector: starknet_keccak("register_aggregate".as_bytes()),
        calldata: settlement.register_calldata.clone(),
    };
    let settle_call = Call {
        to: contract,
        selector: starknet_keccak("settle_hand".as_bytes()),
        calldata: settlement.settle_calldata.clone(),
    };

    let register_hash = operator
        .execute_v3(vec![register_call])
        .send()
        .await
        .map_err(|e| format!("register_aggregate submit failed: {e}"))?;

    let settle_hash = operator
        .execute_v3(vec![settle_call])
        .send()
        .await
        .map_err(|e| format!("settle_hand submit failed: {e}"))?;

    Ok((
        format!("{:#x}", register_hash.transaction_hash),
        format!("{:#x}", settle_hash.transaction_hash),
    ))
}

/// starknet-ff (0.3) FieldElement → starknet (0.13) Felt。两者均为 32 字节大端。
pub fn ff_to_felt(f: Ff) -> Felt {
    Felt::from_bytes_be(&f.to_bytes_be())
}

/// starknet (0.13) Felt → starknet-ff (0.3) FieldElement。
pub fn felt_to_ff(f: &Felt) -> Ff {
    Ff::from_bytes_be(&f.to_bytes_be()).expect("any 32-byte value is a canonical felt252")
}

/// i128 → starknet-ff（负数取模补，与合约 `from_felt_signed_i128` 对齐；
/// poker_texas_air::starknet_settlement::i128_to_felt 为私有，这里按同一语义实现）。
pub fn i128_to_ff(value: i128) -> Ff {
    if value >= 0 {
        Ff::from(value.unsigned_abs())
    } else {
        -Ff::from(value.unsigned_abs())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn i128_felt_roundtrip_semantics() {
        let pos = i128_to_ff(42);
        assert_eq!(pos, Ff::from(42_u64));
        let neg = i128_to_ff(-42);
        // -42 mod P ≈ P - 42，非零且与 +42 不同。
        assert_ne!(neg, Ff::from(42_u64));
        assert_ne!(neg, Ff::ZERO);
    }
}
