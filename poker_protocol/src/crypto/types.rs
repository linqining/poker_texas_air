//! Default curve type aliases and shared crypto utilities.
//!
//! Change `DefaultCurve` to switch the entire project to a different curve.
//! All downstream modules reference types through these aliases.

use std::hash::{Hash, Hasher};

#[cfg(feature = "stark-curve")]
use crate::crypto::curve::StarkCurve;
use crate::crypto::curve::{Curve, CurvePoint, ElGamalCiphertextGeneric};
#[cfg(not(feature = "stark-curve"))]
use crate::crypto::curve::Bls12381Curve;

/// The default curve used by the project.
/// Plan D 落地（2026-09-05）：Stark 曲线唯一世界，blst legacy 已移除。
pub type DefaultCurve = StarkCurve;

pub const N_CARDS: usize = 52;

// ============================================================
// Type aliases derived from DefaultCurve
// ============================================================

pub type EcPoint = <DefaultCurve as Curve>::Point;
pub type Scalar = <DefaultCurve as Curve>::Scalar;
pub type Plaintext = EcPoint;
pub type ElGamalCiphertext = ElGamalCiphertextGeneric<DefaultCurve>;

// ============================================================
// ECPoint wrapper for HashMap keys
// ============================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ECPoint(pub EcPoint);

impl Hash for ECPoint {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.compress().as_ref().hash(state);
    }
}

impl std::ops::Deref for ECPoint {
    type Target = EcPoint;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ECPoint {
    pub fn from_inner(point: EcPoint) -> Self {
        Self(point)
    }

    pub fn into_inner(self) -> EcPoint {
        self.0
    }

    pub fn to_affine(&self) -> <EcPoint as CurvePoint>::Compressed {
        self.0.compress()
    }
}

// ============================================================
// ECScalar wrapper — Borsh 友好的 Scalar newtype
// ============================================================
//
// 与 `ECPoint` 对偶：`Scalar`（= `<DefaultCurve as Curve>::Scalar`）
// 是外部曲线类型，无法直接 impl `BorshSerialize`/`BorshDeserialize`
// （orphan rule），使用本地 newtype 包装。
// 使用本地 newtype `ECScalar(BlsScalar)` 包装，borsh_impls.rs 中
// impl Borsh 序列化为 32 字节大端序（与 Move 兼容）。
//
// 字节布局：与 `borsh_impls::write_scalar` 一致（32B 大端序）。

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ECScalar(pub Scalar);

impl std::ops::Deref for ECScalar {
    type Target = Scalar;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ECScalar {
    pub fn from_inner(scalar: Scalar) -> Self {
        Self(scalar)
    }

    pub fn into_inner(self) -> Scalar {
        self.0
    }
}



// ============================================================
// Utility functions
// ============================================================

pub fn hash_to_scalar(digest: &[u8]) -> Scalar {
    DefaultCurve::hash_to_scalar(digest)
}

/// 兼容 Move 合约 bls_scalar::derive_scalar_from_card_and_sk：
/// 输入 c1*sk 和 c2*sk 的压缩字节，直接拼接后 hash_to_scalar。
/// 无域名分隔符前缀，无 SHA-256 预哈希（Move 端只有一层 SHA3-256）。
pub fn derive_scalar_from_card_and_sk(user_card: &ElGamalCiphertext, user_sk: &Scalar) -> Scalar {
    let c1_sk = user_card.c1 * user_sk;
    let c2_sk = user_card.c2 * user_sk;
    let mut data = c1_sk.compress().as_ref().to_vec();
    data.extend_from_slice(c2_sk.compress().as_ref());
    hash_to_scalar(&data)
}

/// 兼容 Move 合约 bls_scalar::derive_scalar_from_card_and_pk：
/// 输入 c1、c2、pk 的压缩字节，直接拼接后 hash_to_scalar。
/// 无域名分隔符前缀，无 SHA-256 预哈希（Move 端只有一层 SHA3-256）。
pub fn derive_scalar_from_card_and_pk(user_card: &ElGamalCiphertext, user_pk: &EcPoint) -> Scalar {
    let mut data = user_card.c1.compress().as_ref().to_vec();
    data.extend_from_slice(user_card.c2.compress().as_ref());
    data.extend_from_slice(user_pk.compress().as_ref());
    hash_to_scalar(&data)
}

/// 聚合公钥基点（原 lazy_static；Stark base_g 为纯计算，直接函数化）。
pub fn base_g() -> EcPoint {
    DefaultCurve::base_g()
}
