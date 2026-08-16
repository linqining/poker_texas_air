use crate::{Bls12381Curve, Curve, CurvePoint, ElGamalCiphertextGeneric};
use borsh::{BorshDeserialize, BorshSerialize};

const G1_COMPRESSED_LEN: usize = 48;

impl BorshSerialize for ElGamalCiphertextGeneric<Bls12381Curve> {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        writer.write_all(self.c1.compress().as_ref())?;
        writer.write_all(self.c2.compress().as_ref())
    }
}

impl BorshDeserialize for ElGamalCiphertextGeneric<Bls12381Curve> {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let c1 = read_point(reader)?;
        let c2 = read_point(reader)?;
        Ok(Self { c1, c2 })
    }
}

fn read_point<R: borsh::io::Read>(
    reader: &mut R,
) -> borsh::io::Result<<Bls12381Curve as Curve>::Point> {
    let mut encoded = [0u8; G1_COMPRESSED_LEN];
    reader.read_exact(&mut encoded)?;
    <<Bls12381Curve as Curve>::Point as CurvePoint>::from_compressed(&encoded).ok_or_else(|| {
        borsh::io::Error::new(
            borsh::io::ErrorKind::InvalidData,
            "invalid BLS12-381 G1 compressed point",
        )
    })
}
