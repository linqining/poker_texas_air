//! Starknet 环境配置。
//!
//! 所有地址留空时进入 dev 模式（跳过链上校验/提交，仅记账 + 生成 calldata），
//! 保证本地无 RPC 也能跑完整牌局流程。

/// 1 STRK = 10^18 wei，1 STRK = 1000 chips → 1 chip = 10^15 wei。
/// pSTRK/swap 已下线，筹码直接锚定原生 STRK。
pub const WEI_PER_CHIP: u128 = 1_000_000_000_000_000;

/// Hand-batch（DAPV）上链形态（`STARKNET_SETTLE_MODE`）：
///
/// - `Linear`（默认）：现状行为——p_batch 全文上链，链上做 ρ 折叠校验。
///   除非显式配置，什么都不变。
/// - `Proved`：p_batch 不上链；register/settle 换用 proved 入口
///   （`register_hand_proved` / `verify_and_settle_dapv_proved`），settle
///   只携带 `p_batch_commitment = poseidon(hand_binding,
///   poseidon(p_batch words))`。链上接受条件 = 调用者在合约 prover
///   白名单内（临时 prover-attestation 模型）。服务器侧需外部 prover
///   出具 attestation——当前 HTTP 客户端是必然报错的存根，所以 proved
///   模式实际总是自动回退 linear（结算绝不因 prover 阻塞）。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SettleMode {
    #[default]
    Linear,
    Proved,
}

impl SettleMode {
    /// 大小写不敏感解析；未设置/未知值一律回到 Linear（默认路径，
    /// 行为与改造前逐字节一致）。
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "proved" => SettleMode::Proved,
            _ => SettleMode::Linear,
        }
    }
}

#[derive(Clone, Debug)]
pub struct StarknetConfig {
    /// JSON-RPC 端点（如 https://starknet-sepolia-rpc.publicnode.com）。
    pub rpc_url: String,
    /// 结算操作员账户地址（调用 register_aggregate / settle_hand 的 prover）。
    pub operator_address: String,
    /// 操作员签名私钥（hex，含或不含 0x 前缀均可）。
    pub operator_private_key: String,
    /// PokerVault 合约地址。留空跳过筹码余额/买入校验。
    pub vault_address: String,
    /// PokerSettlement 合约地址。留空只生成 calldata 不提交交易。
    pub settlement_address: String,
    /// PokerDualSettlement 合约地址（Hand-batch 路径：P 层 ρ 折叠残差链上验证）。
    /// 留空时 Hand-batch 路径不可用。
    pub dual_settlement_address: String,
    /// 结算模式：`dapv`（仅 DAPV，失败报错）| `legacy`（仅 register_aggregate/
    /// settle_hand）| `auto`（优先 DAPV，任一步失败自动回退 legacy）。
    /// 2026-09-06 起固定为 `legacy`（见 `from_env`）：结算期收集 endorsement
    /// 的 liveness 缺口在开局期铸造（DAPV §9 L2 注册期语义）落地前不可接受。
    pub settlement_mode: String,
    /// Hand-batch 上链形态（`STARKNET_SETTLE_MODE`，默认 Linear）。
    pub settle_mode: SettleMode,
    /// DAPV settle 上链入口（`STARKNET_DAPV_SETTLE_ENTRY`）：
    /// `v2`（默认）= `verify_and_settle_dapv_stark_private_v2`——零明文结算，
    /// fact-registry 单证明锚（settlement_private 电路），**可随时回退的
    /// 稳定入口**；`proved_private` = `verify_and_settle_dapv_proved_private`
    /// ——hand_verify + stark verify 双 fact 认证（P2-M4，dual v4）；
    /// `snip36` = `verify_and_settle_dapv_stark_private_v3`——SNIP-36
    /// proof_facts 优先 + fact-registry 降级双门（**合约侧随 cairo ≥2.12
    /// 迁移上链后生效**，选中现网会 revert，属预期）。未知值一律回退 v2。
    pub dapv_settle_entry: String,
    /// 外部 batch-prover 服务端点（`STARKNET_PROVER_URL`）。proved 模式的
    /// attestation 来源；服务器只提交 workload、接收 attestation，绝不
    /// 进程内跑 prover。当前 HTTP 客户端为存根（必然报错 → 回退 linear），
    /// 变量先解析存储，待 prover 工具落地后启用。
    pub prover_url: Option<String>,
    /// proved 模式 workload JSON 导出目录（`STARKNET_PROVER_WORK_DIR`，
    /// 默认 `/tmp/zgame-prover`）——未来独立 prover CLI 消费的输入文件。
    pub prover_work_dir: String,
    /// true = 钱包签名必须通过 isValidSignature 链上验证；false = dev 模式放行。
    pub auth_strict: bool,
    /// 平台 treasury 地址（抽水接收方，`STARKNET_TREASURY_ADDRESS`）。
    /// 留空回退 operator 地址。
    pub treasury_address: String,
    /// PokerTableRegistry 合约地址（`STARKNET_TABLE_REGISTRY_ADDRESS`）。
    /// 留空 = 纯链下模式（不建链上桌台锚点）。
    pub table_registry_address: String,
    // 抽水参数不在本结构：链上/链下同一来源
    // `crate::pokergame::rake::rake_params`（STARKNET_RAKE_BPS/CAP）。
}

impl StarknetConfig {
    pub fn from_env() -> Self {
        Self {
            rpc_url: std::env::var("STARKNET_RPC_URL").unwrap_or_default(),
            operator_address: std::env::var("STARKNET_OPERATOR_ADDRESS").unwrap_or_default(),
            operator_private_key: std::env::var("STARKNET_OPERATOR_PRIVATE_KEY").unwrap_or_default(),
            vault_address: std::env::var("STARKNET_VAULT_ADDRESS").unwrap_or_default(),
            settlement_address: std::env::var("STARKNET_SETTLEMENT_ADDRESS").unwrap_or_default(),
            dual_settlement_address: std::env::var("STARKNET_DUAL_SETTLEMENT_ADDRESS").unwrap_or_default(),
            // 2026-09-06：endorsement 收集通道删除后 DAPV 旧模式（dapv/auto）
            // 的前提已不存在，但动作签名（zgame.action-sig.v3）已成为每手
            // 必然的参与背书材料——`snip36` 模式据此启用：牌局结束异步出
            // 递归证明（action-sig 批次）后提交。除 snip36 外仍钉 legacy
            // （v2 结算不启动证明）。
            settlement_mode: {
                let requested = std::env::var("STARKNET_SETTLEMENT_MODE").unwrap_or_default();
                match requested.trim() {
                    "snip36" => "snip36".to_string(),
                    other => {
                        if !other.is_empty() && other != "legacy" {
                            eprintln!(
                                "[starknet-config] STARKNET_SETTLEMENT_MODE={other} ignored — \
                                 pinned to legacy (available: legacy | snip36)"
                            );
                        }
                        "legacy".to_string()
                    }
                }
            },
            settle_mode: SettleMode::parse(
                &std::env::var("STARKNET_SETTLE_MODE").unwrap_or_default(),
            ),
            dapv_settle_entry: std::env::var("STARKNET_DAPV_SETTLE_ENTRY").unwrap_or_default(),
            prover_url: std::env::var("STARKNET_PROVER_URL")
                .ok()
                .filter(|s| !s.trim().is_empty()),
            prover_work_dir: std::env::var("STARKNET_PROVER_WORK_DIR")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "/tmp/zgame-prover".to_string()),
            auth_strict: std::env::var("STARKNET_AUTH_STRICT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(false),
            treasury_address: std::env::var("STARKNET_TREASURY_ADDRESS").unwrap_or_default(),
            table_registry_address: std::env::var("STARKNET_TABLE_REGISTRY_ADDRESS")
                .unwrap_or_default(),
        }
    }

    /// RPC 是否可用（决定买入校验/上链提交是否真正执行）。
    pub fn rpc_enabled(&self) -> bool {
        !self.rpc_url.is_empty()
    }

    /// 桌台注册表是否启用（`STARKNET_TABLE_REGISTRY_ADDRESS` 配置即开启）。
    /// 开启后：建桌写注册表拿合约分配 id、关桌写链、开局前可读回状态；
    /// 未开启 = 纯链下模式（table_id 用服务端本地分配，行为不变）。
    pub fn table_registry_enabled(&self) -> bool {
        !self.table_registry_address.is_empty()
    }

    /// 是否启用 snip36 递归证明结算模式（牌局结束异步证明后提交；
    /// 非 snip36 模式（v2/legacy）不启动任何证明进程）。
    pub fn settlement_mode_snip36(&self) -> bool {
        self.settlement_mode.trim() == "snip36"
    }

    /// 归一化的 settle 入口值（trim 后；空/未知 → "v2"）。
    pub fn dapv_settle_entry(&self) -> &str {
        match self.dapv_settle_entry.trim() {
            "proved_private" => "proved_private",
            "snip36" => "snip36",
            _ => "v2",
        }
    }

    /// 结算上链是否可用（需要 RPC + settlement 合约 + 操作员密钥）。
    pub fn settlement_enabled(&self) -> bool {
        self.rpc_enabled()
            && !self.settlement_address.is_empty()
            && !self.operator_address.is_empty()
            && !self.operator_private_key.is_empty()
    }
}

#[cfg(test)]
mod wei_tests {
    /// 2026-09-04 回归：结算腿（submit.rs / dual_settle.rs 的 deltas 放大）
    /// 与买入记账（client WEI_PER_CHIP 同值）必须用同一常量。曾出现局部
    /// 定义 1e14 与全局 1e15 差 10 倍 → 链上余额与游戏输赢每手漂移 9/10。
    /// 客户端对应 client/src/starknet/config.ts（1 chip = 1e15 wei = 0.001 STRK）。
    #[test]
    fn wei_per_chip_is_locked_to_client_parity() {
        assert_eq!(super::WEI_PER_CHIP, 1_000_000_000_000_000u128);
    }
}
