//! `create_table` 方法的 trace 生成器。
//!
//! 从 [`CreateTableInput`] + pre/post state 直接构造 trace（不经 RV32IM 执行）。

use crate::airs::lifecycle::create_table::{CreateTableAir, CreateTableInput, CreateTableRow};
use crate::error::TexasAirResult;
use crate::state_root::{StateRoot, compute_state_root, state_root_to_air_limbs};
use crate::trace_gen::MethodTrace;
use crate::trace_gen::generic_trace::SINGLE_METHOD_LOG_SIZE;

/// `create_table` trace 生成器输出。
#[derive(Debug, Clone)]
pub struct CreateTableTrace {
    /// 业务 trace 数据。
    pub trace: MethodTrace,
    /// 配套的 AIR 公开输入。
    pub air: CreateTableAir,
}

/// 生成 `create_table` trace。
///
/// # 参数
/// - `input`: create_table 输入参数
/// - `pre_table`: 调用前的 TexasPokerTable
/// - `post_table`: 调用后的 TexasPokerTable（执行 `TexasPokerTable::new` + `bump_version` 后）
/// - `table_id`: 表台 ID
/// - `hand_id`: 手牌序号
/// - `call_seq`: 调用序号
///
/// # 返回
/// `CreateTableTrace`，含 trace 数据与 AIR 公开输入。
///
/// # Errors
///
/// 当 state_root 计算失败或 trace 写入失败时返回错误。
pub fn gen_create_table_trace(
    input: CreateTableInput,
    pre_table: &poker_l1::vm::contracts::texas_poker::types::TexasPokerTable,
    post_table: &poker_l1::vm::contracts::texas_poker::types::TexasPokerTable,
    table_id: u64,
    hand_id: u32,
    call_seq: u32,
) -> TexasAirResult<CreateTableTrace> {
    // 1. 计算 pre/post state_root
    let pre_root: StateRoot = compute_state_root(pre_table)?;
    let post_root: StateRoot = compute_state_root(post_table)?;

    // 2. 选择 log_size
    // create_table 是单步操作，使用经基准验证的 256-row low-latency profile，
    // 因此把同一 active statement 复制到全部行，避免未绑定 first-row selector。
    let log_size = SINGLE_METHOD_LOG_SIZE;

    // 3. 构造 active 行
    let active_row = CreateTableRow::active(
        &input,
        state_root_to_air_limbs(pre_root),
        state_root_to_air_limbs(post_root),
        table_id,
        hand_id,
        call_seq,
        u64::from(pre_table.call_seq),
        u64::from(post_table.call_seq),
    );

    // 4. 构造 trace
    let mut trace = MethodTrace::new(log_size, CreateTableAir::num_columns());
    let padding_row = CreateTableRow::padding();
    trace.write_active_with_padding(&active_row.to_vec(), &padding_row.to_vec())?;

    // 5. 构造 AIR
    let air = CreateTableAir::new(
        log_size,
        input,
        state_root_to_air_limbs(pre_root),
        state_root_to_air_limbs(post_root),
        table_id,
        hand_id,
        call_seq,
        u64::from(pre_table.call_seq),
        u64::from(post_table.call_seq),
    );

    Ok(CreateTableTrace { trace, air })
}
