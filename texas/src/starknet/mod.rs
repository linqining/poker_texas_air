//! Starknet 接入层：链配置、RPC 客户端、钱包认证、STRK20 买入、牌局镜像证明与结算上链。
//!
//! 模块结构：
//! - [`config`]：环境变量配置（RPC、操作员账户、合约地址）
//! - [`chain`]：全局 `StarknetChain` 单例（provider + 操作员账户）
//! - [`auth`]：Starknet 钱包签名验证（isValidSignature 视图调用）
//! - [`chips`]：STRK20 余额 / vault 筹码余额 / 买入交易回执校验
//! - [`paymaster`]：Plan C paymaster 中继（paymaster_* JSON-RPC 透传 + API key 服务端注入）
//! - [`mirror`]：牌局镜像 —— 把 WS 牌局操作同步 dispatch 到 poker_l1 VM 收集 ProveTask
//! - [`submit`]：一手结束后 prove → outer aggregate → Cairo calldata → 上链提交

pub mod auth;
pub mod chain;
pub mod chips;
#[cfg(test)]
mod e2e_tests;
pub mod config;
pub mod dual_settle;
pub mod hooks;
pub mod lock;
pub mod mirror;
pub mod paymaster;
pub mod settlement_prover;
pub mod submit;

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
