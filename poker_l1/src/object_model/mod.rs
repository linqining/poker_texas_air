//! 对象模型（Object-Centric State）— Task 2 实现。
//!
//! 模块组成：
//! - [`id`]：ObjectID（NEW-L4 修复）
//! - [`ownership`]：Ownership 枚举（AddressOwned / Shared / Immutable / ChannelOwner）
//! - [`object`]：Object 结构（id / version / owner / type / data / assigned_validator）+ BCS + content-hash
//! - [`smt`]：Sparse Merkle Tree（IMPL-SEC-3 修复）
//! - [`store`]：ObjectStore（内存版 + SMT backing）

pub mod id;
pub mod object;
pub mod ownership;
pub mod smt;
pub mod store;

pub use id::ObjectID;
pub use object::{Object, ObjectData, ObjectType, Version};
pub use ownership::Ownership;
pub use smt::{
    MerklePath, SparseMerkleTree, TREE_DEPTH, empty_hashes, empty_leaf_hash, internal_hash,
    leaf_hash,
};
pub use store::ObjectStore;
