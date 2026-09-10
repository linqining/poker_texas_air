//! Borsh codecs for Stark curve points and scalars（单一权威实现）。
//!
//! 编码规范（持久化/线上格式，字节布局冻结）：
//! - 点 = 32 字节压缩（`CurvePoint::compress`：x 大端 + 首字节 0x80 位
//!   记 y 奇偶，全零 = 恒等元）；
//! - 标量 = 32 字节大端（`CurveScalar::as_bytes` / `from_canonical_bytes`，
//!   Move 兼容）。
//!
//! 反序列化 fail-closed：非规范标量（≥ 群阶）与非曲线点编码一律拒绝。
//! 2026-09-10：proofs / bg / poker_protocol 三处近似拷贝收敛到本文件
//! （字节布局不变；错误文案以 proofs 份现行为准）——防"client-wasm
//! 48 字节事故"类漂移重演。

use crate::curve::{CurvePoint, CurveScalar};
use crate::stark_curve::{StarkCurve, StarkPoint, StarkScalar};
use crate::ElGamalCiphertextGeneric;
use borsh::{BorshDeserialize, BorshSerialize};

/// Stark 压缩点字节数。
pub const STARK_POINT_COMPRESSED_LEN: usize = 32;
/// Stark 标量字节数（大端序，Move 兼容）。
pub const STARK_SCALAR_LEN: usize = 32;

/// 写 32B 压缩点。
#[inline]
pub fn write_stark_point<W: borsh::io::Write>(
    p: &StarkPoint,
    w: &mut W,
) -> borsh::io::Result<()> {
    let bytes = CurvePoint::compress(p);
    w.write_all(bytes.as_ref())
}

/// 读 32B 压缩点。on-curve 校验：`from_compressed` 对非曲线编码
/// （含 x ≥ 2^251 的非规范范围）返回 None，此处转 InvalidData。
#[inline]
pub fn read_stark_point<R: borsh::io::Read>(r: &mut R) -> borsh::io::Result<StarkPoint> {
    let mut bytes = [0u8; STARK_POINT_COMPRESSED_LEN];
    r.read_exact(&mut bytes)?;
    CurvePoint::from_compressed(&bytes).ok_or_else(|| {
        borsh::io::Error::new(
            borsh::io::ErrorKind::InvalidData,
            "invalid compressed curve point",
        )
    })
}

/// 写 32B 大端标量。
#[inline]
pub fn write_stark_scalar<W: borsh::io::Write>(
    s: &StarkScalar,
    w: &mut W,
) -> borsh::io::Result<()> {
    let bytes = CurveScalar::as_bytes(s);
    w.write_all(&bytes)
}

/// 读 32B 大端标量。非规范编码（≥ 群阶）拒绝：对攻击者控制的值取模
/// 会使线上格式可塑（malleable）。
#[inline]
pub fn read_stark_scalar<R: borsh::io::Read>(r: &mut R) -> borsh::io::Result<StarkScalar> {
    let mut bytes = [0u8; STARK_SCALAR_LEN];
    r.read_exact(&mut bytes)?;
    CurveScalar::from_canonical_bytes(&bytes).ok_or_else(|| {
        borsh::io::Error::new(
            borsh::io::ErrorKind::InvalidData,
            "non-canonical curve scalar",
        )
    })
}

impl BorshSerialize for ElGamalCiphertextGeneric<StarkCurve> {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        write_stark_point(&self.c1, writer)?;
        write_stark_point(&self.c2, writer)
    }
}

impl BorshDeserialize for ElGamalCiphertextGeneric<StarkCurve> {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let c1 = read_stark_point(reader)?;
        let c2 = read_stark_point(reader)?;
        Ok(Self { c1, c2 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::Curve;

    /// 标量字节布局 KAT：from_u64(42) 必须编码为 31 个零后缀 0x2a
    /// （32B 大端）。
    #[test]
    fn scalar_layout_is_32_byte_big_endian() {
        let mut buf = Vec::new();
        write_stark_scalar(&StarkScalar::from_u64(42), &mut buf).unwrap();
        let mut expected = [0u8; 32];
        expected[31] = 42;
        assert_eq!(buf, expected);
        let mut cursor = std::io::Cursor::new(buf);
        assert_eq!(read_stark_scalar(&mut cursor).unwrap(), StarkScalar::from_u64(42));
    }

    /// 点字节布局 KAT：恒等元 = 全零 32B；生成元压缩 roundtrip。
    #[test]
    fn point_layout_roundtrip_and_identity_is_zero() {
        let identity = <StarkPoint as CurvePoint>::identity();
        let mut buf = Vec::new();
        write_stark_point(&identity, &mut buf).unwrap();
        assert_eq!(buf.len(), STARK_POINT_COMPRESSED_LEN);
        assert!(buf.iter().all(|b| *b == 0));

        let g = <StarkCurve as Curve>::base_g();
        buf.clear();
        write_stark_point(&g, &mut buf).unwrap();
        assert_eq!(buf.len(), STARK_POINT_COMPRESSED_LEN);
        let mut cursor = std::io::Cursor::new(&buf);
        assert_eq!(read_stark_point(&mut cursor).unwrap(), g);
    }

    /// 非规范标量（= 群阶）必须被拒绝。
    #[test]
    fn scalar_decoder_rejects_noncanonical_encoding() {
        let mut cursor = std::io::Cursor::new(crate::stark_curve::ec_order_bytes_be());
        assert!(read_stark_scalar(&mut cursor).is_err());
    }

    /// 非曲线点编码（随机 32B 大概率不在曲线上 / 首字节高位组合非法）
    /// 必须被拒绝；长度不足必须是 IO 错误。
    #[test]
    fn point_decoder_rejects_invalid_and_short_input() {
        let not_on_curve = [0xffu8; 32]; // 首字节低 7 位 > 0x07 → 非规范范围
        let mut cursor = std::io::Cursor::new(not_on_curve);
        assert!(read_stark_point(&mut cursor).is_err());

        let short = [0u8; 31];
        let mut cursor = std::io::Cursor::new(short);
        assert!(read_stark_point(&mut cursor).is_err());
    }
}
