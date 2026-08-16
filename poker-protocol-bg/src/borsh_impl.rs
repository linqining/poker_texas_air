use crate::{BayerGrothShuffleProof, MultiExponentiationArgument, ProductArgument};
use borsh::{BorshDeserialize, BorshSerialize};
use poker_protocol_core::{
    Bls12381Curve, Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric,
};

const POINT_LEN: usize = 48;
const SCALAR_LEN: usize = 32;
const MAX_SHUFFLE_DECK_SIZE: usize = 1024;

type Point = <Bls12381Curve as Curve>::Point;
type Scalar = <Bls12381Curve as Curve>::Scalar;

fn write_point<W: borsh::io::Write>(point: &Point, writer: &mut W) -> borsh::io::Result<()> {
    writer.write_all(point.compress().as_ref())
}

fn read_point<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Point> {
    let mut encoded = [0u8; POINT_LEN];
    reader.read_exact(&mut encoded)?;
    <Point as CurvePoint>::from_compressed(&encoded)
        .ok_or_else(|| borsh::io::Error::new(borsh::io::ErrorKind::InvalidData, "invalid G1 point"))
}

fn write_scalar<W: borsh::io::Write>(scalar: &Scalar, writer: &mut W) -> borsh::io::Result<()> {
    writer.write_all(&scalar.as_bytes())
}

fn read_scalar<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Scalar> {
    let mut encoded = [0u8; SCALAR_LEN];
    reader.read_exact(&mut encoded)?;
    Scalar::from_canonical_bytes(&encoded).ok_or_else(|| {
        borsh::io::Error::new(borsh::io::ErrorKind::InvalidData, "non-canonical scalar")
    })
}

fn write_scalar_vec<W: borsh::io::Write>(
    values: &[Scalar],
    writer: &mut W,
) -> borsh::io::Result<()> {
    let len = u32::try_from(values.len()).map_err(|_| {
        borsh::io::Error::new(
            borsh::io::ErrorKind::InvalidData,
            "response vector too long",
        )
    })?;
    writer.write_all(&len.to_le_bytes())?;
    for value in values {
        write_scalar(value, writer)?;
    }
    Ok(())
}

fn read_scalar_vec<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Vec<Scalar>> {
    let mut encoded_len = [0u8; 4];
    reader.read_exact(&mut encoded_len)?;
    let len = u32::from_le_bytes(encoded_len) as usize;
    if !(2..=MAX_SHUFFLE_DECK_SIZE).contains(&len) {
        return Err(borsh::io::Error::new(
            borsh::io::ErrorKind::InvalidData,
            "invalid Bayer-Groth response vector length",
        ));
    }
    (0..len).map(|_| read_scalar(reader)).collect()
}

impl BorshSerialize for MultiExponentiationArgument<Bls12381Curve> {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        write_point(&self.c_alpha, writer)?;
        write_point(&self.c_beta, writer)?;
        BorshSerialize::serialize(&self.ciphertext_0, writer)?;
        BorshSerialize::serialize(&self.ciphertext_1, writer)?;
        write_scalar_vec(&self.alpha_response, writer)?;
        write_scalar(&self.commitment_response, writer)?;
        write_scalar(&self.beta, writer)?;
        write_scalar(&self.beta_blinding_response, writer)?;
        write_scalar(&self.rerandomization_response, writer)
    }
}

impl BorshDeserialize for MultiExponentiationArgument<Bls12381Curve> {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        Ok(Self {
            c_alpha: read_point(reader)?,
            c_beta: read_point(reader)?,
            ciphertext_0: ElGamalCiphertextGeneric::deserialize_reader(reader)?,
            ciphertext_1: ElGamalCiphertextGeneric::deserialize_reader(reader)?,
            alpha_response: read_scalar_vec(reader)?,
            commitment_response: read_scalar(reader)?,
            beta: read_scalar(reader)?,
            beta_blinding_response: read_scalar(reader)?,
            rerandomization_response: read_scalar(reader)?,
        })
    }
}

impl BorshSerialize for ProductArgument<Bls12381Curve> {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        write_point(&self.c_d, writer)?;
        write_point(&self.c_delta, writer)?;
        write_point(&self.c_capital_delta, writer)?;
        write_scalar_vec(&self.a_response, writer)?;
        write_scalar_vec(&self.b_response, writer)?;
        write_scalar(&self.r_response, writer)?;
        write_scalar(&self.s_response, writer)
    }
}

impl BorshDeserialize for ProductArgument<Bls12381Curve> {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let c_d = read_point(reader)?;
        let c_delta = read_point(reader)?;
        let c_capital_delta = read_point(reader)?;
        let a_response = read_scalar_vec(reader)?;
        let b_response = read_scalar_vec(reader)?;
        if a_response.len() != b_response.len() {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "mismatched Bayer-Groth product response lengths",
            ));
        }
        Ok(Self {
            c_d,
            c_delta,
            c_capital_delta,
            a_response,
            b_response,
            r_response: read_scalar(reader)?,
            s_response: read_scalar(reader)?,
        })
    }
}

impl BorshSerialize for BayerGrothShuffleProof<Bls12381Curve> {
    fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
        write_point(&self.c_permutation, writer)?;
        write_point(&self.c_permuted_powers, writer)?;
        BorshSerialize::serialize(&self.multi_exponentiation, writer)?;
        BorshSerialize::serialize(&self.product, writer)
    }
}

impl BorshDeserialize for BayerGrothShuffleProof<Bls12381Curve> {
    fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
        let c_permutation = read_point(reader)?;
        let c_permuted_powers = read_point(reader)?;
        let multi_exponentiation = MultiExponentiationArgument::deserialize_reader(reader)?;
        let product = ProductArgument::deserialize_reader(reader)?;
        let n = multi_exponentiation.alpha_response.len();
        if product.a_response.len() != n || product.b_response.len() != n {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "mismatched Bayer-Groth proof response lengths",
            ));
        }
        Ok(Self {
            c_permutation,
            c_permuted_powers,
            multi_exponentiation,
            product,
        })
    }
}
