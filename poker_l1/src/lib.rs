//! poker_l1 — Poker L1 区块链核心库
//!
//! 模块结构按 spec.md (FROZEN 2026-06-27) 组织：
//! - [`object_model`]：对象模型（Object / ObjectID / Ownership / ObjectStore + Sparse Merkle Tree）
//! - [`signature`]：多曲线钱包签名（tagged pubkey / secp256k1 / ed25519）
//! - [`account`]：账户身份、nonce 与可选不可转让 resource credits
//! - [`economics`]：NativeCoin UTXO、TreasuryCap、合约与 staking escrow 守恒
//! - [`transaction`]：交易结构
//! - [`block`]：区块结构
//! - [`consensus`]：DAG vertex / commit certificate / Bullshark / ECVRF / slashing
//! - [`storage`]：链存储（BlockStore / ObjectStore / DagVertexStore / BridgeRegistryStore，RocksDB）
//! - [`vm`]：rBPF VM 与 syscalls（合约执行 + precompile）
//!
//! 以下模块已为实质实现（非 stub）：
//! - [`network`]：P2P 传输抽象（NetworkTransport trait + TcpTransport + gossip / compact block relay 类型）
//! - [`bridge`]：跨链桥（bridge_verify / wrapped-asset 铸币 / nonce 持久化）
//! - [`governance`]：治理（proposals / timelock / quorum / 参数治理 / key rotation）
//! - [`node`]：节点（4 角色 / NodeConfig / CLI / 集成存储）
//! - [`executor`]：交易执行引擎（串行 + 波次化并行 + 默认免 Gas 的 resource metering）
//! - [`offline`]：链下 ZK 验证器注册（Stwo / Groth16 / IPA scheme 抽象）
//! - [`rpc`]：JSON-RPC 2.0 接口
//! - [`sync`]：Fast/Snap 同步；[`indexer`]：链上索引/事件订阅
//! - [`crypto_precompiles`]：BLS12-381 等密码学预编译（部分实现）
//!
//! # 安全说明
//!
//! 全库 `deny(unsafe_code)`；唯一例外是 [`vm`] 模块（`allow(unsafe_code)`），
//! 因为 `solana_rbpf` 的 syscall 注册机制需要裸指针交互（`*mut EbpfVm<C>`）。
//! 所有 unsafe 操作封装在 `vm` 模块内，附安全不变式注释。

#![deny(unsafe_code)]
#![deny(rust_2021_compatibility)]
#![warn(missing_docs)]
#![warn(clippy::all, clippy::nursery)]

pub mod account;
pub mod block;
pub mod bridge;
pub mod consensus;
pub mod crypto_precompiles;
pub mod economics;
pub mod error;
pub mod executor;
pub mod genesis;
pub mod governance;
pub mod indexer;
pub mod metrics;
pub mod network;
pub mod node;
pub mod object_model;
pub mod offline;
pub mod rpc;
pub mod signature;
pub mod storage;
pub mod sync;
pub mod transaction;
pub mod vm;
pub mod wallet;

/// 网络标识（chain_id）类型。spec 中 chain_id 用于跨链重放保护（M10 / SEC-L4）。
pub type ChainId = u64;

/// 区块高度类型。
pub type BlockHeight = u64;

/// 毫秒级时间戳。
pub type TimestampMs = u64;

/// 玩家地址（20 字节，由 blake2b_256(tagged_pubkey)[0..20] 派生）。
pub type Address = [u8; 20];

/// 32 字节哈希（blake2b_256 输出）。
pub type Hash = [u8; 32];

/// Genesis 默认 chain_id；testnet=0x70_6f_6b_31（"pok1"）。生产网络由 genesis 配置。
pub const DEFAULT_CHAIN_ID: ChainId = 0x706F_6B31;
