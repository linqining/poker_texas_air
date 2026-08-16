//! 预编译合约共享类型与元数据接口（Phase 2 迁移）。
//!
//! # 设计目标
//!
//! - 定义跨 VM 共享的预编译合约元数据接口（`PrecompileMetadata`）
//! - 共享 `PrecompileStatus` 枚举（治理门控状态）
//! - 不依赖 poker_l1 的 `ObjectID`/`ObjectDb`/`PokerL1Error` 等类型
//! - 为 zkvm `PrecompileCircuit` 提供 adapter 桥接基础
//!
//! # 架构
//!
//! ```text
//! vm_common::precompile::PrecompileMetadata (trait, 字节级接口)
//!     ▲
//!     │ impl
//!     │
//!     ├── poker_l1::vm::precompile::Precompile (完整接口，含 ObjectID/ObjectDb)
//!     │   └── 17 个业务合约（零修改）
//!     │
//!     └── poker_zkvm::precompiles::adapter::PrecompileCircuitAdapter
//!         └── 包装 9 个 PrecompileCircuit（poseidon/sha256/ecdsa/...）
//! ```
//!
//! # 为什么不统一 Precompile trait
//!
//! poker_l1 的 `Precompile::call()` 依赖 `ObjectID`/`Address`/`TaggedPubkey`/`ObjectDb`/
//! `PokerL1Error` 等 poker_l1 专有类型。将这些类型迁入 vm-common 会破坏"vm-common 不含
//! ISA 语义"原则，使 vm-common 成为 god-crate。使用关联类型抽象则会导致 17 个业务合约
//! 需要修改 impl 签名，破坏"零修改"承诺。
//!
//! **务实决策**：vm-common 仅定义元数据接口（`PrecompileMetadata`），poker_l1 保留完整
//! `Precompile` trait（零修改），zkvm 通过 adapter 实现元数据接口。完整的跨 VM `call()`
//! 统一推迟到有具体业务需求时再实现。

/// 预编译合约状态（治理门控）。
///
/// - `Stub`：测试网可用，主网受限
/// - `Production`：完整功能，主网可用
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrecompileStatus {
    /// Stub 状态：测试网可用，主网拒绝某些操作。
    Stub,
    /// Production 状态：完整功能。
    Production,
}

impl PrecompileStatus {
    /// 是否允许主网使用。
    #[must_use]
    pub fn allows_mainnet(self) -> bool {
        matches!(self, Self::Production)
    }
}

/// 预编译合约版本信息（使用 u64 避免 BlockHeight 类型依赖）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrecompileVersion {
    /// 当前活跃版本号。
    pub active_version: u32,
    /// 待激活版本（timelock 等待中）。
    pub pending_version: Option<u32>,
    /// 待激活版本的激活高度（timelock 到期高度）。
    pub activation_height: Option<u64>,
}

impl Default for PrecompileVersion {
    fn default() -> Self {
        Self {
            active_version: 1,
            pending_version: None,
            activation_height: None,
        }
    }
}

/// 预编译合约元数据接口（跨 VM 共享）。
///
/// 这是预编译合约的**最小**共享接口，仅包含元数据方法。
/// 不含 `call()` 方法（因 `call()` 依赖各 VM 专有类型）。
///
/// # 用途
///
/// - zkvm `PrecompileCircuit` 通过 `PrecompileCircuitAdapter` 实现此接口
/// - poker_l1 `Precompile` trait 可通过 blanket impl 或手动 impl 复用
/// - 跨 VM 注册表可基于此接口管理元数据
///
/// # ID 格式
///
/// 使用 `[u8; 32]` 字节数组作为 ID，避免依赖 `ObjectID` 类型。
/// poker_l1 的 `ObjectID` 可通过序列化转换为此格式。
pub trait PrecompileMetadata: Send + Sync {
    /// 预编译合约的唯一标识符（32 字节）。
    fn id_bytes(&self) -> [u8; 32];

    /// 预编译合约名称（用于日志与调试）。
    fn name(&self) -> &str;

    /// 当前版本号。
    fn version(&self) -> u32 {
        1
    }

    /// 校验方法选择器是否属于此预编译合约。
    ///
    /// 默认实现返回 true（允许任意选择器），子类可覆写以实现更严格的校验。
    fn supports_selector(&self, _selector: &[u8; 32]) -> bool {
        true
    }

    /// 该预编译合约是否免 gas。
    ///
    /// 默认 `false`：普通预编译合约仍按 tx gas 策略计费。
    /// GameTurn/CheckpointAnchor lane 的预编译合约应返回 `true`。
    fn is_gas_free(&self) -> bool {
        false
    }
}

/// 预编译合约命名空间保留地址前缀。
///
/// 参考以太坊预编译合约地址（0x01-0x09），使用 0xFF 前缀标识预编译合约。
pub const PRECOMPILE_PREFIX: u8 = 0xFF;

/// 生成预编译合约 ID 字节数组（从名称哈希）。
///
/// 用于 zkvm 电路 adapter 生成稳定的 ID。
///
/// # 算法
///
/// 1. 使用 `DefaultHasher`（SipHash-1-0-3）对名称哈希
/// 2. 第 0 字节固定为 `PRECOMPILE_PREFIX`（0xFF）
/// 3. 第 1-8 字节为哈希值的 LE 编码
/// 4. 第 9-31 字节为 0（保留扩展空间）
///
/// # 稳定性
///
/// 同一进程内对同一名称生成的 ID 相同。不同名称生成的 ID 不同（碰撞概率极低）。
/// 跨进程稳定性由 poker_l1 `ObjectID` 序列化保证（adapter 仅用于运行时元数据查询）。
#[must_use]
pub fn precompile_id_from_name(name: &str) -> [u8; 32] {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    name.hash(&mut hasher);
    let hash = hasher.finish();

    let mut id = [0u8; 32];
    id[0] = PRECOMPILE_PREFIX;
    id[1..9].copy_from_slice(&hash.to_le_bytes());
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_precompile_status_allows_mainnet() {
        assert!(!PrecompileStatus::Stub.allows_mainnet());
        assert!(PrecompileStatus::Production.allows_mainnet());
    }

    #[test]
    fn test_precompile_version_default() {
        let v = PrecompileVersion::default();
        assert_eq!(v.active_version, 1);
        assert_eq!(v.pending_version, None);
        assert_eq!(v.activation_height, None);
    }

    #[test]
    fn test_precompile_id_from_name_stable() {
        let id1 = precompile_id_from_name("poseidon");
        let id2 = precompile_id_from_name("poseidon");
        assert_eq!(id1, id2, "相同名称应生成相同 ID");

        let id3 = precompile_id_from_name("sha256");
        assert_ne!(id1, id3, "不同名称应生成不同 ID");

        // 验证前缀
        assert_eq!(id1[0], PRECOMPILE_PREFIX);
        assert_eq!(id3[0], PRECOMPILE_PREFIX);
    }

    #[test]
    fn test_precompile_id_from_name_uniqueness() {
        let names = ["poseidon", "sha256", "ecdsa", "keccak256", "ed25519"];
        let mut seen = std::collections::HashSet::new();
        for name in &names {
            let id = precompile_id_from_name(name);
            assert!(seen.insert(id), "名称 {name} 生成了重复 ID");
        }
    }

    /// 测试用 PrecompileMetadata 实现。
    struct TestPrecompile {
        id: [u8; 32],
        name: &'static str,
        gas_free: bool,
    }

    impl PrecompileMetadata for TestPrecompile {
        fn id_bytes(&self) -> [u8; 32] {
            self.id
        }
        fn name(&self) -> &str {
            self.name
        }
        fn is_gas_free(&self) -> bool {
            self.gas_free
        }
    }

    #[test]
    fn test_precompile_metadata_trait() {
        let p = TestPrecompile {
            id: precompile_id_from_name("test"),
            name: "test",
            gas_free: false,
        };
        assert_eq!(p.id_bytes()[0], PRECOMPILE_PREFIX);
        assert_eq!(p.name(), "test");
        assert_eq!(p.version(), 1); // 默认值
        assert!(p.supports_selector(&[0u8; 32])); // 默认值
        assert!(!p.is_gas_free());
    }

    #[test]
    fn test_precompile_metadata_gas_free_override() {
        // GameTurn 场景：is_gas_free 应可被覆写为 true
        let p = TestPrecompile {
            id: precompile_id_from_name("gameturn"),
            name: "gameturn",
            gas_free: true,
        };
        assert_eq!(p.name(), "gameturn");
        assert_eq!(p.id_bytes()[0], PRECOMPILE_PREFIX);
        assert!(p.is_gas_free(), "GameTurn 预编译应免 gas");
    }

    #[test]
    fn test_precompile_metadata_gas_free_default() {
        // 默认 is_gas_free = false（普通预编译按 tx gas 计费）
        let p = TestPrecompile {
            id: precompile_id_from_name("normal"),
            name: "normal",
            gas_free: false,
        };
        assert!(!p.is_gas_free(), "普通预编译应按 tx gas 计费");
    }
}
