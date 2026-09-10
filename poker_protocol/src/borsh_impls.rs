//! Borsh encodings for the facade-local wrapper types (`ECPoint`/`ECScalar`).
//!
//! 编码核心收敛到 poker-protocol-core（2026-09-10，单一权威）：
//! 点 = `CurvePoint::compress()`（Stark 曲线 32 字节压缩）；标量 =
//! 32 字节大端（`CurveScalar::as_bytes`/`from_canonical_bytes`）。
//! 旧 48 字节 BLS G1 压缩编码已随 blst 移除（2026-09-05，不考虑兼容）。
//! 此前反序列化以"压缩一次 base_g"动态求点长度——恒为 32，现直接使用
//! core 的定长读取（行为等价：32B 压缩点）。

#![cfg(feature = "borsh")]

use borsh::{BorshDeserialize, BorshSerialize};
use poker_protocol_core::{read_stark_point, read_stark_scalar, write_stark_point, write_stark_scalar};

use crate::crypto::types::{ECPoint, ECScalar};

impl BorshSerialize for ECPoint {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        write_stark_point(&self.0, writer)
    }
}

impl BorshDeserialize for ECPoint {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        Ok(Self(read_stark_point(reader)?))
    }
}

impl BorshSerialize for ECScalar {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        write_stark_scalar(&self.0, writer)
    }
}

impl BorshDeserialize for ECScalar {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        Ok(Self(read_stark_scalar(reader)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::curve::{Curve, CurveScalar};
    use crate::crypto::types::DefaultCurve as CurveT;

    #[test]
    fn facade_wrappers_roundtrip() {
        let point = ECPoint(<CurveT as Curve>::base_g());
        let point_bytes = borsh::to_vec(&point).unwrap();
        assert_eq!(point_bytes.len(), 32, "stark compressed point is 32 bytes");
        assert_eq!(borsh::from_slice::<ECPoint>(&point_bytes).unwrap(), point);

        let scalar = ECScalar(<CurveT as Curve>::Scalar::from_u64(42));
        let scalar_bytes = borsh::to_vec(&scalar).unwrap();
        assert_eq!(borsh::from_slice::<ECScalar>(&scalar_bytes).unwrap(), scalar);
    }
}
