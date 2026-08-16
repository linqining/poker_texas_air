//! Borsh encodings for facade-local BLS12-381 wrapper types.
//!
//! Proof encodings live in `poker-protocol-proofs`, alongside the proof
//! types. Keeping only local newtypes here avoids orphan-rule violations.

#![cfg(feature = "borsh")]

use blstrs::{G1Projective, Scalar as BlsScalar};
use borsh::{BorshDeserialize, BorshSerialize};
use group::GroupEncoding;

use crate::crypto::curve::CurveScalar;
use crate::crypto::types::{ECPoint, ECScalar};

const G1_COMPRESSED_LEN: usize = 48;
const SCALAR_LEN: usize = 32;

fn write_point<W: borsh::io::Write>(point: &G1Projective, writer: &mut W) -> borsh::io::Result<()> {
    let bytes = <G1Projective as GroupEncoding>::to_bytes(point);
    writer.write_all(bytes.as_ref())
}

fn read_point<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<G1Projective> {
    let mut bytes = [0u8; G1_COMPRESSED_LEN];
    reader.read_exact(&mut bytes)?;
    let point = G1Projective::from_compressed(&bytes);
    Option::<G1Projective>::from(point).ok_or_else(|| {
        borsh::io::Error::new(
            borsh::io::ErrorKind::InvalidData,
            "invalid G1 compressed bytes",
        )
    })
}

fn write_scalar<W: borsh::io::Write>(scalar: &BlsScalar, writer: &mut W) -> borsh::io::Result<()> {
    writer.write_all(&<BlsScalar as CurveScalar>::as_bytes(scalar))
}

fn read_scalar<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<BlsScalar> {
    let mut bytes = [0u8; SCALAR_LEN];
    reader.read_exact(&mut bytes)?;
    <BlsScalar as CurveScalar>::from_canonical_bytes(&bytes).ok_or_else(|| {
        borsh::io::Error::new(
            borsh::io::ErrorKind::InvalidData,
            "non-canonical BLS12-381 scalar",
        )
    })
}

impl BorshSerialize for ECPoint {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        write_point(&self.0, writer)
    }
}

impl BorshDeserialize for ECPoint {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        Ok(Self(read_point(reader)?))
    }
}

impl BorshSerialize for ECScalar {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        write_scalar(&self.0, writer)
    }
}

impl BorshDeserialize for ECScalar {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        Ok(Self(read_scalar(reader)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::curve::{Bls12381Curve, Curve};

    #[test]
    fn facade_wrappers_roundtrip() {
        let point = ECPoint(Bls12381Curve::base_g());
        let point_bytes = borsh::to_vec(&point).unwrap();
        assert_eq!(borsh::from_slice::<ECPoint>(&point_bytes).unwrap(), point);

        let scalar = ECScalar(<BlsScalar as CurveScalar>::from_u64(42));
        let scalar_bytes = borsh::to_vec(&scalar).unwrap();
        assert_eq!(
            borsh::from_slice::<ECScalar>(&scalar_bytes).unwrap(),
            scalar
        );
    }

    #[test]
    fn scalar_decoder_rejects_noncanonical_encoding() {
        const MODULUS_BE: [u8; 32] = [
            0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1,
            0xd8, 0x05, 0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x01,
        ];
        let mut cursor = std::io::Cursor::new(MODULUS_BE);
        assert!(read_scalar(&mut cursor).is_err());
    }
}
