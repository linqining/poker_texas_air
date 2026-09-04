use crate::{Curve, CurvePoint, ElGamalCiphertextGeneric, StarkCurve};
use borsh::{BorshDeserialize, BorshSerialize};

const POINT_COMPRESSED_LEN: usize = 32;

impl BorshSerialize for ElGamalCiphertextGeneric<StarkCurve> {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        writer.write_all(self.c1.compress().as_ref())?;
        writer.write_all(self.c2.compress().as_ref())
    }
}

impl BorshDeserialize for ElGamalCiphertextGeneric<StarkCurve> {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let c1 = read_point(reader)?;
        let c2 = read_point(reader)?;
        Ok(Self { c1, c2 })
    }
}

fn read_point<R: borsh::io::Read>(
    reader: &mut R,
) -> borsh::io::Result<<StarkCurve as Curve>::Point> {
    let mut encoded = [0u8; POINT_COMPRESSED_LEN];
    reader.read_exact(&mut encoded)?;
    <<StarkCurve as Curve>::Point as CurvePoint>::from_compressed(&encoded).ok_or_else(|| {
        borsh::io::Error::new(
            borsh::io::ErrorKind::InvalidData,
            "invalid Stark curve compressed point",
        )
    })
}
