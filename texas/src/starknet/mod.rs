//! Starknet 接入层：链配置、RPC 客户端、钱包认证、STRK20 买入、实时 VM 镜像、
//! 证明生成与结算上链。
//!
//! 模块地图（按职责）：
//! - 实时镜像与对账事实
//!   - [`shadow`]：实时 VM 镜像（**权威入口**）——每个接受点同步 dispatch
//!     的单一 VM 状态，结算直接取用其 ProveTask 链与 pre-payout 快照
//!   - [`mirror`]：VM 机械层——`TableMirror` dispatch 包装、开局引导、
//!     zgame ↔ ptx 类型的 borsh 桥
//!   - [`prove_log`]：手牌对账事实记录（HandStart 快照、终局投入、派奖）
//! - 结算编排与提交
//!   - [`hooks`]：结算编排（游戏层结束钩子 → 证明 → 提交 → 锁账续钟）
//!   - [`lock`]：vault 会话钥核验（P1-2 会话委托）与在局筹码锁定/释放
//!   - [`submit`]：legacy 结算（register_aggregate / settle_hand calldata + 提交）
//!   - [`dual_settle`]：DAPV 双证明结算路径
//!   - [`recursion_prover`] / [`settlement_prover`]：证明生成
//!     （SNIP-36 递归信封 / settlement 电路）
//! - 基础设施
//!   - [`config`]：环境变量配置（RPC、操作员账户、合约地址）
//!   - [`chain`]：全局 `StarknetChain` 单例（provider + 操作员账户）及
//!     felt 解析 / selector / hex 公共辅助
//!   - [`auth`]：Starknet 钱包签名验证（isValidSignature 视图调用）
//!   - [`chips`]：vault 筹码余额 / 买入交易回执校验
//!   - [`paymaster`]：Plan C paymaster 中继（paymaster_* JSON-RPC 透传）

pub mod auth;
pub mod chain;
pub mod chips;
#[cfg(test)]
mod e2e_tests;
pub mod config;
pub mod dual_settle;
pub mod recursion_prover;
pub mod hooks;
pub mod lock;
pub mod mirror;
pub mod paymaster;
pub mod prove_log;
pub mod settlement_prover;
pub mod shadow;
pub mod submit;
/// 桌台注册表锚定（PokerTableRegistry：合约分配 id + Open→Closed 生命周期）。
pub mod table_registry;

pub use chain::StarknetChain;
pub use config::StarknetConfig;

use std::sync::OnceLock;

static CHAIN: OnceLock<StarknetChain> = OnceLock::new();

/// 初始化全局链客户端（main.rs 启动时调用一次）。
pub fn init(config: StarknetConfig) -> &'static StarknetChain {
    let chain = StarknetChain::new(config);
    let _ = CHAIN.set(chain);
    chain_ref()
}

/// 获取全局链客户端。未初始化时返回 None 的兜底句柄（dev 模式下也可以工作）。
pub fn chain() -> Option<&'static StarknetChain> {
    CHAIN.get()
}

fn chain_ref() -> &'static StarknetChain {
    CHAIN.get().expect("StarknetChain not initialized")
}
