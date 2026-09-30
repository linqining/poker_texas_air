//! poster 运营配置——**不绑任何现状 env**（STARKNET_* 是 texas 的面；
//! poster 用 TEXAS_POSTER_* 自有命名空间，避免与游戏服务器共用进程环境
//! 语义）。

use std::path::PathBuf;
use std::time::Duration;

use starknet_txmgr::TxManagerConfig;
use starknet_types_core::felt::Felt;

/// Monad 工件落盘目录 env（跨仓工件：zchain 侧 monad_settlementd
/// `--mode settle` 经 `--settle-inbox` 从此目录消费 MonadProofEnvelope；
/// 消费方界定见 monad.rs 模块文档）。
pub const ENV_MONAD_SPOOL_DIR: &str = "TEXAS_MONAD_SPOOL_DIR";

/// cadence（op-batcher max-channel-duration 式触发节奏）。
#[derive(Debug, Clone)]
pub struct CadenceConfig {
    /// 批手数上限 K（政策上限 64——stark-recursion/src/chain.rs:63
    /// MAX_HANDS_PER_LEAF；且批尺寸须为 2 的幂，chain.rs:165-175 校验）。
    pub max_batch_hands: usize,
    /// 攒批时间窗（最老候选等待超过此时长即触发——不满 max 也发）。
    pub max_wait_secs: u64,
    /// 触发下限（时间窗到期也至少攒够这么多手才成批；1 = 单手可成批）。
    pub min_batch_hands: usize,
}

impl Default for CadenceConfig {
    fn default() -> Self {
        Self {
            max_batch_hands: 64,
            max_wait_secs: 300,
            min_batch_hands: 1,
        }
    }
}

/// fold 攒批开关（poster 运营配置；现状无 fold env——`SettleMode` 仅
/// {Linear, Proved}，`texas/src/starknet/config.rs:24-39`）。
#[derive(Debug, Clone)]
pub struct FoldConfig {
    pub enabled: bool,
    /// program_hash 对拍锚（prove-batch.sh:51 EXPECTED_PH 同值）。
    pub expected_program_hash: String,
    /// prove-batch.sh 脚本路径（两阶段腿入口）。
    pub script: PathBuf,
    /// 基础手输入 JSON（prove-batch.sh 用法：`<K> <base> <out> [acc]`）。
    pub base_input: PathBuf,
    /// 出证工作目录。
    pub work_dir: PathBuf,
    /// 出证有界重试。
    pub max_proof_attempts: u32,
}

impl Default for FoldConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            // prove-batch.sh:51 的钉扎值（9 人桌 2026-09-30 迁移后）。
            expected_program_hash:
                "0x03977925c8f46d896d04f4b76c18874e0f9a05a4c860f0de56236518e9faf74d".into(),
            script: PathBuf::from("../proving-tool/prove-batch.sh"),
            base_input: PathBuf::new(),
            work_dir: PathBuf::from("/tmp/zgame-batch-poster"),
            max_proof_attempts: 3,
        }
    }
}

/// poster 配置。
#[derive(Debug, Clone)]
pub struct PosterConfig {
    /// settle-queue WAL 路径（只读）。
    pub queue_wal: PathBuf,
    /// poster sidecar 目录（独占写）。
    pub sidecar_dir: PathBuf,
    /// Monad 工件落盘目录（env TEXAS_MONAD_SPOOL_DIR）。
    pub monad_spool_dir: PathBuf,
    /// 操作员账户（nonce 租约主体）。
    pub operator_account: Felt,
    /// PokerSettlement（legacy 两笔 + settlement_digest 可见性 view）。
    pub legacy_settlement: Felt,
    /// PokerDualSettlement（dual 两笔 + fold 批入口）。
    pub dual_settlement: Felt,
    pub cadence: CadenceConfig,
    pub fold: FoldConfig,
    /// Dual 腿投递重试上限（耗尽 → 投递期死信 → 等 texas 降级）。
    pub dual_max_attempts: u32,
    /// Legacy 腿投递重试上限（耗尽 → 终态死信，停发观察）。
    pub legacy_max_attempts: u32,
    /// daemon 轮询间隔。
    pub poll_interval: Duration,
    /// 交易管理层配置。
    pub txmgr: TxManagerConfig,
    /// 可见性轮询策略（Legacy register 腿；txmgr 层）。
    pub visible: starknet_txmgr::VisiblePolicy,
}

impl PosterConfig {
    /// 从 env 装配（运营配置；全部有缺省，dev 空值即全零地址）。
    pub fn from_env() -> Self {
        let fold = FoldConfig::default();
        Self {
            queue_wal: env_path("TEXAS_POSTER_QUEUE_WAL", "settle-queue/queue.jsonl"),
            sidecar_dir: env_path("TEXAS_POSTER_SIDECAR_DIR", "poster-sidecar"),
            monad_spool_dir: std::env::var(ENV_MONAD_SPOOL_DIR)
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("poster-sidecar/monad-spool")),
            operator_account: env_felt("TEXAS_POSTER_OPERATOR").unwrap_or_default(),
            legacy_settlement: env_felt("TEXAS_POSTER_LEGACY_SETTLEMENT").unwrap_or_default(),
            dual_settlement: env_felt("TEXAS_POSTER_DUAL_SETTLEMENT").unwrap_or_default(),
            cadence: CadenceConfig {
                max_batch_hands: std::env::var("TEXAS_POSTER_MAX_BATCH_HANDS")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(64),
                max_wait_secs: std::env::var("TEXAS_POSTER_MAX_WAIT_SECS")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(300),
                min_batch_hands: 1,
            },
            fold: FoldConfig {
                enabled: std::env::var("TEXAS_POSTER_FOLD_ENABLED")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false),
                script: env_path(
                    "TEXAS_POSTER_PROVE_SCRIPT",
                    "../proving-tool/prove-batch.sh",
                ),
                base_input: env_path(
                    "TEXAS_POSTER_PROVE_BASE_INPUT",
                    &fold.base_input.to_string_lossy(),
                ),
                work_dir: env_path(
                    "TEXAS_POSTER_PROVE_WORK_DIR",
                    &fold.work_dir.to_string_lossy(),
                ),
                ..fold
            },
            dual_max_attempts: 8,
            legacy_max_attempts: 8,
            poll_interval: Duration::from_secs(3),
            txmgr: TxManagerConfig::default(),
            visible: starknet_txmgr::VisiblePolicy::default(),
        }
    }

    /// K 政策校验（构造期 fail-closed：批上限不得超过
    /// stark_recursion::chain::MAX_HANDS_PER_LEAF 且 ≥1）。
    pub fn validate(&self) -> Result<(), String> {
        let cap = stark_recursion::chain::MAX_HANDS_PER_LEAF;
        if self.cadence.max_batch_hands == 0 || self.cadence.max_batch_hands > cap {
            return Err(format!(
                "max_batch_hands {} 越界（1..={cap}，chain.rs:63 政策）",
                self.cadence.max_batch_hands
            ));
        }
        if self.cadence.min_batch_hands < 1
            || self.cadence.min_batch_hands > self.cadence.max_batch_hands
        {
            return Err("min_batch_hands 须在 1..=max_batch_hands".into());
        }
        Ok(())
    }
}

fn env_path(name: &str, default: &str) -> PathBuf {
    std::env::var(name)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(default))
}

fn env_felt(name: &str) -> Option<Felt> {
    std::env::var(name).ok().and_then(|s| parse_felt_hex(&s))
}

/// hex（0x 前缀可选）→ Felt。
pub fn parse_felt_hex(s: &str) -> Option<Felt> {
    Felt::from_hex(s.trim().trim_start_matches("0x")).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// K 政策校验：上限 64（chain.rs:63），越界 fail-closed。
    #[test]
    fn cadence_bounds_enforced() {
        let mut cfg = PosterConfig {
            queue_wal: PathBuf::new(),
            sidecar_dir: PathBuf::new(),
            monad_spool_dir: PathBuf::new(),
            operator_account: Felt::default(),
            legacy_settlement: Felt::default(),
            dual_settlement: Felt::default(),
            cadence: CadenceConfig::default(),
            fold: FoldConfig::default(),
            dual_max_attempts: 8,
            legacy_max_attempts: 8,
            poll_interval: Duration::from_secs(1),
            txmgr: TxManagerConfig::default(),
            visible: starknet_txmgr::VisiblePolicy::default(),
        };
        assert!(cfg.validate().is_ok());
        cfg.cadence.max_batch_hands = 65;
        assert!(cfg.validate().is_err(), "K=65 > MAX_HANDS_PER_LEAF=64");
        cfg.cadence.max_batch_hands = 0;
        assert!(cfg.validate().is_err());
    }
}
