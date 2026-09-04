//! Borsh encodings for the facade-local wrapper types (`ECPoint`/`ECScalar`).
//!
//! 编码：点 = `CurvePoint::compress()`（Stark 曲线 32 字节压缩）；标量 =
//! 32 字节大端（`CurveScalar::as_bytes`/`from_canonical_bytes`）。
//! 旧 48 字节 BLS G1 压缩编码已随 blst 移除（2026-09-05，不考虑兼容）。

#![cfg(feature = "borsh")]

use borsh::{BorshDeserialize, BorshSerialize};

use crate::crypto::curve::{Curve, CurvePoint, CurveScalar};
use crate::crypto::types::{DefaultCurve, ECPoint, ECScalar};

type Point = <DefaultCurve as Curve>::Point;
type Scalar = <DefaultCurve as Curve>::Scalar;

impl BorshSerialize for ECPoint {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        let bytes = self.0.compress();
        writer.write_all(bytes.as_ref())
    }
}

impl BorshDeserialize for ECPoint {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        // 压缩点定长：以生成元压缩长度为准（32）。
        let len = {
            let g = <DefaultCurve as Curve>::base_g();
            g.compress().as_ref().len()
        };
        let mut bytes = vec![0u8; len];
        reader.read_exact(&mut bytes)?;
        let point = Point::from_compressed(&bytes).ok_or_else(|| {
            borsh::io::Error::new(borsh::io::ErrorKind::InvalidData, "invalid compressed point")
        })?;
        Ok(Self(point))
    }
}

impl BorshSerialize for ECScalar {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        writer.write_all(&CurveScalar::as_bytes(&self.0))
    }
}

impl BorshDeserialize for ECScalar {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let mut bytes = [0u8; 32];
        reader.read_exact(&mut bytes)?;
        let scalar = <Scalar as CurveScalar>::from_canonical_bytes(&bytes).ok_or_else(|| {
            borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "non-canonical curve scalar",
            )
        })?;
        Ok(Self(scalar))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
