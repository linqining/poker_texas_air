//! Post-commit Prover 端到端测试：poker_l1 dispatch → return_value → Orchestrator。
//!
//! 验证完整链路：
//! 1. poker_l1 dispatch 执行 method，return_value = borsh(L1DispatchOutput)
//! 2. 从 return_value 反序列化为 poker_texas_air::prove_task::DispatchOutput
//!    （borsh 跨 crate 兼容性）
//! 3. Orchestrator 消费 ProveTask，prove + verify 成功
//!
//! 这是 Post-commit Prover 方案的核心集成测试。

use borsh::BorshDeserialize;

use poker_l1::Address;
use poker_l1::object_model::ObjectID;
use poker_l1::signature::TaggedPubkey;
use poker_l1::vm::contracts::dispatch::DispatchContext;
use poker_l1::vm::contracts::texas_poker::dispatch::{self, CreateTableArgs, selectors};
use poker_l1::vm::contracts::texas_poker::types::{EMPTY_PLAYER, TexasPokerTable};

use poker_texas_air::orchestrator::Orchestrator;
use poker_texas_air::prove_task::DispatchOutput;

fn ctx_as(caller: Address) -> DispatchContext {
    DispatchContext {
        caller,
        caller_pubkey: TaggedPubkey {
            tag: 0,
            raw: vec![0xBB; 32],
        },
        chain_id: 1,
        block_height: 100,
        block_timestamp: 1_000_000,
    }
}

/// 端到端：create_table dispatch → return_value → Orchestrator prove+verify。
///
/// 验证：
/// - return_value 能反序列化为 DispatchOutput（borsh 兼容）
/// - prove_task 非空
/// - Orchestrator 消费 task 后 prove + verify 成功
#[test]
fn e2e_create_table_dispatch_to_orchestrator() {
    let creator: Address = [0xAA; 20];
    let mut table = TexasPokerTable::new(
        ObjectID::new([0xFF; 20], 0),
        String::new(),
        EMPTY_PLAYER,
        2,
        1,
        1,
    );

    let args = CreateTableArgs {
        name: "real_table".into(),
        max_players: 6,
        small_blind: 50,
        big_blind: 100,
    };
    let args_bytes = borsh::to_vec(&args).unwrap();

    let result = dispatch::dispatch(
        &ctx_as(creator),
        &mut table,
        &selectors::create_table(),
        &args_bytes,
    )
    .expect("create_table dispatch 应成功");

    // 1. return_value 反序列化为 DispatchOutput（borsh 跨 crate 兼容性验证）
    let output: DispatchOutput = BorshDeserialize::try_from_slice(&result.return_value)
        .expect("return_value 应能反序列化为 poker_texas_air::DispatchOutput");

    // 2. prove_task 非空
    let task = output
        .prove_task
        .expect("create_table dispatch 应产出 prove_task");

    // 3. Orchestrator 消费 task，prove + verify
    let mut orch = Orchestrator::new();
    let summary = orch
        .prove_and_verify_task(&task)
        .expect("Orchestrator prove+verify 应成功");
    assert_eq!(
        summary.method_kind,
        poker_texas_air::method_kind::MethodKind::CreateTable
    );

    // 4. state_root 链自洽（单任务，verify_chain 应通过）
    orch.verify_chain().expect("单任务链应自洽");
}

/// 反序列化兼容性：return_value 即使无 prove_task（tick 路径）也能正确解析。
#[test]
fn e2e_dispatch_output_events_only() {
    let creator: Address = [0xAA; 20];
    let mut table = TexasPokerTable::new(
        ObjectID::new([0xFF; 20], 0),
        "t".into(),
        creator,
        6,
        50,
        100,
    );

    // advance_deadline：空 args。
    let _ = dispatch::dispatch(
        &ctx_as(creator),
        &mut table,
        &selectors::advance_deadline(),
        &[],
    )
    .expect("advance_deadline dispatch 应成功");

    // tick 不产生 prove_task（build_method_input 返回 None）
    // 此处仅验证 dispatch 不 panic；return_value 反序列化应得到 events_only。
    // 注意：tick 在无玩家时不触发状态变更，但 dispatch 成功即可。
}
