//! 错误类型定义。

use thiserror::Error;

/// `poker_texas_air` 主错误类型。
#[derive(Debug, Error)]
pub enum TexasAirError {
    /// 业务规约违反（pre/post state 不匹配、字段非法值等）。
    #[error("业务规约违反: {0}")]
    SpecViolation(String),

    /// State root 计算失败（Poseidon252 哈希失败）。
    #[error("State root 计算失败: {0}")]
    StateRootError(String),

    /// Merkle 树构造/验证失败。
    #[error("Merkle 树错误: {0}")]
    MerkleError(String),

    /// AIR 约束不满足（soundness 检查失败）。
    #[error("AIR 约束不满足: {0}")]
    ConstraintUnsatisfied(String),

    /// Trace 生成失败。
    #[error("Trace 生成失败: {0}")]
    TraceGenError(String),

    /// Stwo prover 内部错误。
    #[error("Stwo prover 错误: {0}")]
    StwoProverError(String),

    /// 递归证明失败。
    #[error("递归证明错误: {0}")]
    RecursionError(String),

    /// Descriptor-only Aggregator 未验证子 proof，生产入口默认禁用。
    #[error(
        "不可信聚合已禁用: descriptor-only Aggregator 未在电路内验证子 proof；只能使用显式测试入口"
    )]
    UntrustedAggregationDisabled,

    /// 下注动作触发了当前 AIR 尚未建模的收池、轮次推进或结算分支。
    ///
    /// 生产 prover 必须 fail-closed；不能拿只描述 mid-round seat update 的 AIR
    /// 去证明完整的 end-of-round VM transition。
    #[error("下注转移未覆盖（fail-closed）: {0}")]
    UnsupportedBettingTransition(String),

    /// 序列化/反序列化失败。
    #[error("序列化错误: {0}")]
    SerializationError(String),

    /// 未实现（C 档密码学方法 AIR 在阶段 4 实现）。
    #[error("未实现: {0}")]
    NotImplemented(String),

    /// 共识来源锚定失败（P05-H-source）：cert 校验、SMT 包含证明或单桌 snapshot
    /// 绑定未通过。
    #[error("consensus anchor: {0}")]
    ConsensusAnchor(String),
}

/// 主 Result 类型别名。
pub type TexasAirResult<T> = Result<T, TexasAirError>;
