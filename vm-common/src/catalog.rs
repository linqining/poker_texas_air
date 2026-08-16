//! PrecompileCatalog — 跨 VM 预编译可用性目录（Phase 5）。
//!
//! 合约开发者单一入口：通过此目录查询某个预编译在 L1 / zkvm 的可用性、
//! gas 策略、ID 与调用方式，无需阅读两个 VM 的源码。
//!
//! # 设计
//!
//! 本模块是**只读目录**，不参与运行时分派。条目在编译期硬编码，
//! 反映 `poker_l1/src/vm/contracts/` 与 `poker_zkvm/src/precompiles/` 的实际实现。
//!
//! # 用法
//!
//! ```ignore
//! use vm_common::catalog::PrecompileCatalog;
//! let catalog = PrecompileCatalog::default_catalog();
//! let entry = catalog.find("sha256").expect("sha256 应存在");
//! assert!(entry.l1_available);
//! assert!(entry.zkvm_available);
//! ```

use crate::precompile::precompile_id_from_name;

/// 预编译类别。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrecompileCategory {
    /// 哈希函数（sha256/keccak256/blake2b_256/poseidon）。
    Hash,
    /// 签名验证（ecdsa/ed25519）。
    Signature,
    /// 配对 / 椭圆曲线运算（BLS12-381/BN254）。
    Pairing,
    /// 业务合约（游戏逻辑：gameturn/settle/forfeit 等）。
    Business,
    /// ZK 证明验证（Stwo/Groth16/IPA）。
    ZkProof,
    /// 其他。
    Other,
}

/// 预编译可用性条目。
///
/// 描述单个预编译在两个 VM 中的可用性、gas 策略与稳定 ID。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogEntry {
    /// 预编译名称（如 `"sha256"`, `"gameturn"`）。
    pub name: &'static str,
    /// 类别。
    pub category: PrecompileCategory,
    /// poker_l1 是否可用。
    pub l1_available: bool,
    /// poker_zkvm 是否可用。
    pub zkvm_available: bool,
    /// 是否 gas-free（GameTurn/CheckpointAnchor lane）。
    pub is_gas_free: bool,
    /// 稳定 ID（`[u8; 32]`，0xFF 前缀，由 [`precompile_id_from_name`] 生成）。
    pub id_bytes: [u8; 32],
    /// 简短描述。
    pub description: &'static str,
}

/// 跨 VM 预编译目录。
///
/// 通过 [`PrecompileCatalog::default_catalog`] 创建包含所有已知预编译的目录。
#[derive(Debug, Default)]
pub struct PrecompileCatalog {
    /// 所有条目。
    entries: Vec<CatalogEntry>,
}

impl PrecompileCatalog {
    /// 创建包含所有已知预编译的目录。
    ///
    /// 条目反映 `poker_l1/src/vm/contracts/` 与 `poker_zkvm/src/precompiles/` 的实际实现。
    #[must_use]
    pub fn default_catalog() -> Self {
        let mut entries = Vec::new();

        // ===== 哈希函数（跨 VM 共享）=====
        for &(name, desc) in &[
            ("sha256", "SHA-256 哈希"),
            ("keccak256", "Keccak-256 哈希（Ethereum 风格）"),
            ("blake2b_256", "Blake2b-256 哈希"),
            ("poseidon", "Poseidon 哈希（ZK 友好）"),
        ] {
            entries.push(CatalogEntry {
                name,
                category: PrecompileCategory::Hash,
                l1_available: true,
                zkvm_available: true,
                is_gas_free: false,
                id_bytes: precompile_id_from_name(name),
                description: desc,
            });
        }

        // ===== 签名验证 =====
        for &(name, l1, zk, desc) in &[
            (
                "ecdsa_secp256k1",
                true,
                false,
                "ECDSA secp256k1 签名验证（poker_l1）",
            ),
            ("ed25519", true, true, "Ed25519 签名验证（跨 VM）"),
            ("ecdsa_verify", false, true, "ECDSA 验签电路（zkvm 专用）"),
        ] {
            entries.push(CatalogEntry {
                name,
                category: PrecompileCategory::Signature,
                l1_available: l1,
                zkvm_available: zk,
                is_gas_free: false,
                id_bytes: precompile_id_from_name(name),
                description: desc,
            });
        }

        // ===== 配对 / 椭圆曲线 =====
        for &(name, l1, zk, desc) in &[
            (
                "bls12_381_pairing",
                true,
                false,
                "BLS12-381 配对检查（poker_l1 blstrs）",
            ),
            (
                "bn254_pairing",
                false,
                true,
                "BN254 配对检查（zkvm ark-bn254）",
            ),
            ("bn254_ops", false, true, "BN254 椭圆曲线运算（zkvm）"),
        ] {
            entries.push(CatalogEntry {
                name,
                category: PrecompileCategory::Pairing,
                l1_available: l1,
                zkvm_available: zk,
                is_gas_free: false,
                id_bytes: precompile_id_from_name(name),
                description: desc,
            });
        }

        // ===== 业务合约（仅 L1）=====
        // gas-free lane: gameturn + checkpoint_anchor
        for &(name, gas_free, desc) in &[
            ("gameturn", true, "游戏回合（gas-free lane，GameTurn 通道）"),
            (
                "checkpoint_anchor",
                true,
                "检查点锚定（gas-free lane，Game 通道）",
            ),
            ("force_advance", false, "强制推进"),
            ("force_settle", false, "强制结算"),
            ("force_checkin", false, "强制签到"),
            ("settle", false, "结算"),
            ("revert", false, "回退"),
            ("hand_started", false, "手牌开始"),
            ("ack_protocol", false, "确认协议"),
            ("forfeit", false, "弃牌"),
            ("censor_detection", false, "审查检测"),
            ("delegated_escape", false, "委托逃生"),
            ("force_checkpoint", false, "强制检查点"),
            ("challenge_delta", false, "挑战增量"),
            ("checkpoint_skip", false, "检查点跳过"),
            ("request_da", false, "请求 DA"),
            ("checkin", false, "签到（Public 通道，正常 gas 计费）"),
        ] {
            entries.push(CatalogEntry {
                name,
                category: PrecompileCategory::Business,
                l1_available: true,
                zkvm_available: false,
                is_gas_free: gas_free,
                id_bytes: precompile_id_from_name(name),
                description: desc,
            });
        }

        // ===== ZK 证明（跨 VM）=====
        entries.push(CatalogEntry {
            name: "zk_verify",
            category: PrecompileCategory::ZkProof,
            l1_available: true,
            zkvm_available: true,
            is_gas_free: false,
            id_bytes: precompile_id_from_name("zk_verify"),
            description: "ZK 证明验证（Stwo/Groth16/IPA）",
        });

        Self { entries }
    }

    /// 按名称查找预编译条目。
    #[must_use]
    pub fn find(&self, name: &str) -> Option<&CatalogEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    /// 列出所有在两个 VM 都可用的预编译。
    pub fn cross_vm_available(&self) -> impl Iterator<Item = &CatalogEntry> {
        self.entries
            .iter()
            .filter(|e| e.l1_available && e.zkvm_available)
    }

    /// 列出所有 gas-free 预编译（GameTurn/CheckpointAnchor lane）。
    pub fn gas_free(&self) -> impl Iterator<Item = &CatalogEntry> {
        self.entries.iter().filter(|e| e.is_gas_free)
    }

    /// 按类别筛选预编译。
    pub fn by_category(&self, cat: PrecompileCategory) -> impl Iterator<Item = &CatalogEntry> {
        self.entries.iter().filter(move |e| e.category == cat)
    }

    /// 返回条目总数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 返回所有条目的迭代器。
    pub fn iter(&self) -> impl Iterator<Item = &CatalogEntry> {
        self.entries.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::precompile::PRECOMPILE_PREFIX;

    #[test]
    fn test_catalog_default_not_empty() {
        let c = PrecompileCatalog::default_catalog();
        assert!(!c.is_empty());
        // 4 hashes + 3 signatures + 3 pairings + 17 business + 1 zk = 28
        assert_eq!(c.len(), 28, "应有 28 个条目");
    }

    #[test]
    fn test_find_sha256() {
        let c = PrecompileCatalog::default_catalog();
        let e = c.find("sha256").expect("sha256 应存在");
        assert!(e.l1_available, "sha256 应在 L1 可用");
        assert!(e.zkvm_available, "sha256 应在 zkvm 可用");
        assert!(!e.is_gas_free, "sha256 不应免 gas");
        assert_eq!(e.category, PrecompileCategory::Hash);
    }

    #[test]
    fn test_find_gameturn_gas_free() {
        let c = PrecompileCatalog::default_catalog();
        let e = c.find("gameturn").expect("gameturn 应存在");
        assert!(e.l1_available, "gameturn 应在 L1 可用");
        assert!(!e.zkvm_available, "gameturn 不应在 zkvm 可用");
        assert!(e.is_gas_free, "gameturn 应免 gas");
        assert_eq!(e.category, PrecompileCategory::Business);
    }

    #[test]
    fn test_find_checkpoint_anchor_gas_free() {
        let c = PrecompileCatalog::default_catalog();
        let e = c
            .find("checkpoint_anchor")
            .expect("checkpoint_anchor 应存在");
        assert!(e.l1_available);
        assert!(e.is_gas_free, "checkpoint_anchor 应免 gas");
    }

    #[test]
    fn test_cross_vm_available_includes_hashes() {
        let c = PrecompileCatalog::default_catalog();
        let names: Vec<_> = c.cross_vm_available().map(|e| e.name).collect();
        assert!(names.contains(&"sha256"));
        assert!(names.contains(&"keccak256"));
        assert!(names.contains(&"ed25519"));
        assert!(names.contains(&"zk_verify"));
        // 业务合约不应在跨 VM 列表中
        assert!(!names.contains(&"gameturn"));
    }

    #[test]
    fn test_gas_free_lane() {
        let c = PrecompileCatalog::default_catalog();
        let gas_free: Vec<_> = c.gas_free().map(|e| e.name).collect();
        assert!(gas_free.contains(&"gameturn"));
        assert!(gas_free.contains(&"checkpoint_anchor"));
        assert_eq!(gas_free.len(), 2, "应只有 2 个 gas-free 预编译");
    }

    #[test]
    fn test_by_category_business() {
        let c = PrecompileCatalog::default_catalog();
        let business: Vec<_> = c.by_category(PrecompileCategory::Business).collect();
        assert_eq!(business.len(), 17, "应有 17 个业务合约");
    }

    #[test]
    fn test_by_category_hash() {
        let c = PrecompileCatalog::default_catalog();
        let hashes: Vec<_> = c.by_category(PrecompileCategory::Hash).collect();
        assert_eq!(hashes.len(), 4, "应有 4 个哈希函数");
    }

    #[test]
    fn test_by_category_zkproof() {
        let c = PrecompileCatalog::default_catalog();
        let zk: Vec<_> = c.by_category(PrecompileCategory::ZkProof).collect();
        assert_eq!(zk.len(), 1, "应有 1 个 ZK 证明预编译");
        assert_eq!(zk[0].name, "zk_verify");
    }

    #[test]
    fn test_id_bytes_stable() {
        let c = PrecompileCatalog::default_catalog();
        let e = c.find("sha256").unwrap();
        assert_eq!(e.id_bytes[0], PRECOMPILE_PREFIX, "ID 首字节应为 0xFF");
        // 验证与 precompile_id_from_name 一致
        assert_eq!(e.id_bytes, precompile_id_from_name("sha256"));
    }

    #[test]
    fn test_id_bytes_unique() {
        let c = PrecompileCatalog::default_catalog();
        let mut seen = std::collections::HashSet::new();
        for entry in c.iter() {
            assert!(
                seen.insert(entry.id_bytes),
                "名称 {} 生成了重复 ID",
                entry.name
            );
        }
    }

    #[test]
    fn test_find_nonexistent() {
        let c = PrecompileCatalog::default_catalog();
        assert!(c.find("nonexistent").is_none());
        assert!(c.find("").is_none());
    }

    #[test]
    fn test_default_trait() {
        let c = PrecompileCatalog::default();
        assert!(c.is_empty());
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn test_poseidon_zkvm_only_hash() {
        let c = PrecompileCatalog::default_catalog();
        let e = c.find("poseidon").unwrap();
        // poseidon 跨 VM 可用（L1 通过 crypto_precompiles，zkvm 通过 precompiles/poseidon）
        assert!(e.l1_available);
        assert!(e.zkvm_available, "poseidon 应在 zkvm 可用");
        assert_eq!(e.category, PrecompileCategory::Hash);
    }
}
