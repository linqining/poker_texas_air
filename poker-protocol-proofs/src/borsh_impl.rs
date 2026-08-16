//! Borsh encodings for the complete BLS12-381 proof suite.

#![cfg(feature = "borsh")]

use blstrs::{G1Projective, Scalar as BlsScalar};
use borsh::{BorshDeserialize, BorshSerialize};
use group::GroupEncoding;
use poker_protocol_bg::BayerGrothShuffleProof;
use poker_protocol_core::{Bls12381Curve, CurveScalar, ElGamalCiphertextGeneric};

use crate::dleq_proof::{DLEqProof, LeaveKind, RemaskKind};
use crate::generalized_schnorr_proof::GeneralizedSchnorrProof;
use crate::reconstruction::{
    ChaumPedersenDLEQProof, CrossKeyNegationProof, OrderedEncryptionProof, ReconstructProof,
    ReconstructProofV3, ReconstructionDLEQProof, ReconstructionV3Statement,
    SlotContributionOrProof, SwapOutCardProof, RECONSTRUCTION_PROOF_VERSION,
    RECONSTRUCTION_V3_PROOF_VERSION,
};
use crate::reveal_token_proof::RevealTokenProof;
use crate::shuffle_proof::ZKShuffleProof;
use crate::versioned::{
    VersionedShuffleProof, BAYER_GROTH_SHUFFLE_PROOF_VERSION, LEGACY_SHUFFLE_PROOF_VERSION,
};

// ============================================================
// 内部辅助函数：定长字节读写
// ============================================================

/// G1 压缩点字节数（BLS12-381 G1）。
const G1_COMPRESSED_LEN: usize = 48;
/// BLS 标量字节数（大端序，Move 兼容）。
const SCALAR_LEN: usize = 32;
const MAX_RECONSTRUCTION_DECK_SIZE: usize = 1024;

#[inline]
fn write_point<W: borsh::io::Write>(p: &G1Projective, w: &mut W) -> borsh::io::Result<()> {
    let bytes = <G1Projective as GroupEncoding>::to_bytes(p);
    w.write_all(bytes.as_ref())
}

#[inline]
fn read_point<R: borsh::io::Read>(r: &mut R) -> borsh::io::Result<G1Projective> {
    let mut bytes = [0u8; G1_COMPRESSED_LEN];
    r.read_exact(&mut bytes)?;
    let ct = G1Projective::from_compressed(&bytes);
    if bool::from(ct.is_some()) {
        Ok(ct.unwrap())
    } else {
        Err(borsh::io::Error::new(
            borsh::io::ErrorKind::InvalidData,
            "invalid G1 compressed bytes",
        ))
    }
}

#[inline]
fn write_scalar<W: borsh::io::Write>(s: &BlsScalar, w: &mut W) -> borsh::io::Result<()> {
    // CurveScalar::as_bytes() → to_bytes_be() → 32 字节大端序（Move 兼容）
    let bytes = <BlsScalar as CurveScalar>::as_bytes(s);
    w.write_all(&bytes)
}

#[inline]
fn read_scalar<R: borsh::io::Read>(r: &mut R) -> borsh::io::Result<BlsScalar> {
    let mut bytes = [0u8; SCALAR_LEN];
    r.read_exact(&mut bytes)?;
    // Proof encodings must be canonical. Reducing an attacker-controlled
    // non-canonical value modulo q would make the wire format malleable.
    let scalar = BlsScalar::from_bytes_be(&bytes);
    if bool::from(scalar.is_some()) {
        Ok(scalar.unwrap())
    } else {
        Err(borsh::io::Error::new(
            borsh::io::ErrorKind::InvalidData,
            "non-canonical BLS12-381 scalar",
        ))
    }
}

#[inline]
fn write_point_vec<W: borsh::io::Write>(v: &[G1Projective], w: &mut W) -> borsh::io::Result<()> {
    let len = v.len() as u32;
    w.write_all(&len.to_le_bytes())?;
    for p in v {
        write_point(p, w)?;
    }
    Ok(())
}

#[inline]
fn read_point_vec<R: borsh::io::Read>(r: &mut R) -> borsh::io::Result<Vec<G1Projective>> {
    let mut len_bytes = [0u8; 4];
    r.read_exact(&mut len_bytes)?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(read_point(r)?);
    }
    Ok(out)
}

#[inline]
fn write_scalar_vec<W: borsh::io::Write>(v: &[BlsScalar], w: &mut W) -> borsh::io::Result<()> {
    let len = v.len() as u32;
    w.write_all(&len.to_le_bytes())?;
    for s in v {
        write_scalar(s, w)?;
    }
    Ok(())
}

#[inline]
fn read_scalar_vec<R: borsh::io::Read>(r: &mut R) -> borsh::io::Result<Vec<BlsScalar>> {
    let mut len_bytes = [0u8; 4];
    r.read_exact(&mut len_bytes)?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        out.push(read_scalar(r)?);
    }
    Ok(out)
}

// ============================================================
// GeneralizedSchnorrProof<Bls12381Curve>
// ============================================================

impl BorshSerialize for GeneralizedSchnorrProof<Bls12381Curve> {
    fn serialize<W: borsh::io::Write>(&self, w: &mut W) -> borsh::io::Result<()> {
        write_point(&self.commitment, w)?;
        write_scalar_vec(&self.responses, w)?;
        Ok(())
    }
}

impl BorshDeserialize for GeneralizedSchnorrProof<Bls12381Curve> {
    fn deserialize_reader<R: borsh::io::Read>(r: &mut R) -> borsh::io::Result<Self> {
        let commitment = read_point(r)?;
        let responses = read_scalar_vec(r)?;
        Ok(Self {
            commitment,
            responses,
        })
    }
}

// ============================================================
// ZKShuffleProof<Bls12381Curve> (= ShuffleProof)
// ============================================================

impl BorshSerialize for ZKShuffleProof<Bls12381Curve> {
    fn serialize<W: borsh::io::Write>(&self, w: &mut W) -> borsh::io::Result<()> {
        write_point(&self.sum_c1_commit, w)?;
        write_point(&self.sum_c2_commit, w)?;
        BorshSerialize::serialize(&self.combined_schnorr_proof, w)?;
        BorshSerialize::serialize(&self.sum_c1_schnorr_proof, w)?;
        BorshSerialize::serialize(&self.sum_c2_schnorr_proof, w)?;
        write_scalar(&self.nonce, w)?;
        Ok(())
    }
}

impl BorshDeserialize for ZKShuffleProof<Bls12381Curve> {
    fn deserialize_reader<R: borsh::io::Read>(r: &mut R) -> borsh::io::Result<Self> {
        let sum_c1_commit = read_point(r)?;
        let sum_c2_commit = read_point(r)?;
        let combined_schnorr_proof = BorshDeserialize::deserialize_reader(r)?;
        let sum_c1_schnorr_proof = BorshDeserialize::deserialize_reader(r)?;
        let sum_c2_schnorr_proof = BorshDeserialize::deserialize_reader(r)?;
        let nonce = read_scalar(r)?;
        Ok(Self {
            sum_c1_commit,
            sum_c2_commit,
            combined_schnorr_proof,
            sum_c1_schnorr_proof,
            sum_c2_schnorr_proof,
            nonce,
        })
    }
}

// ============================================================
// Bayer--Groth V2 and versioned shuffle proofs
// ============================================================

impl BorshSerialize for VersionedShuffleProof<Bls12381Curve> {
    fn serialize<W: borsh::io::Write>(&self, w: &mut W) -> borsh::io::Result<()> {
        match self {
            Self::LegacyV1(proof) => {
                w.write_all(&[LEGACY_SHUFFLE_PROOF_VERSION])?;
                BorshSerialize::serialize(proof, w)
            }
            Self::BayerGrothV2(proof) => {
                w.write_all(&[BAYER_GROTH_SHUFFLE_PROOF_VERSION])?;
                BorshSerialize::serialize(proof, w)
            }
        }
    }
}

impl BorshDeserialize for VersionedShuffleProof<Bls12381Curve> {
    fn deserialize_reader<R: borsh::io::Read>(r: &mut R) -> borsh::io::Result<Self> {
        let mut version = [0u8; 1];
        r.read_exact(&mut version)?;
        match version[0] {
            LEGACY_SHUFFLE_PROOF_VERSION => {
                Ok(Self::LegacyV1(BorshDeserialize::deserialize_reader(r)?))
            }
            BAYER_GROTH_SHUFFLE_PROOF_VERSION => {
                Ok(Self::BayerGrothV2(BorshDeserialize::deserialize_reader(r)?))
            }
            _ => Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "unsupported shuffle proof version",
            )),
        }
    }
}

// ============================================================
// DLEqProof<Bls12381Curve, K>（RemaskProof / LeaveProof）
// ============================================================
//
// PhantomData<K> 不参与序列化。

impl BorshSerialize for DLEqProof<Bls12381Curve, RemaskKind> {
    fn serialize<W: borsh::io::Write>(&self, w: &mut W) -> borsh::io::Result<()> {
        write_point_vec(&self.per_card_commitments, w)?;
        write_point(&self.commitment_pk, w)?;
        write_scalar(&self.response, w)?;
        write_scalar(&self.nonce, w)?;
        Ok(())
    }
}

impl BorshDeserialize for DLEqProof<Bls12381Curve, RemaskKind> {
    fn deserialize_reader<R: borsh::io::Read>(r: &mut R) -> borsh::io::Result<Self> {
        let per_card_commitments = read_point_vec(r)?;
        let commitment_pk = read_point(r)?;
        let response = read_scalar(r)?;
        let nonce = read_scalar(r)?;
        Ok(DLEqProof::from_parts(
            per_card_commitments,
            commitment_pk,
            response,
            nonce,
        ))
    }
}

impl BorshSerialize for DLEqProof<Bls12381Curve, LeaveKind> {
    fn serialize<W: borsh::io::Write>(&self, w: &mut W) -> borsh::io::Result<()> {
        write_point_vec(&self.per_card_commitments, w)?;
        write_point(&self.commitment_pk, w)?;
        write_scalar(&self.response, w)?;
        write_scalar(&self.nonce, w)?;
        Ok(())
    }
}

impl BorshDeserialize for DLEqProof<Bls12381Curve, LeaveKind> {
    fn deserialize_reader<R: borsh::io::Read>(r: &mut R) -> borsh::io::Result<Self> {
        let per_card_commitments = read_point_vec(r)?;
        let commitment_pk = read_point(r)?;
        let response = read_scalar(r)?;
        let nonce = read_scalar(r)?;
        Ok(DLEqProof::from_parts(
            per_card_commitments,
            commitment_pk,
            response,
            nonce,
        ))
    }
}

// ============================================================
// RevealTokenProof<Bls12381Curve>
// ============================================================

impl BorshSerialize for RevealTokenProof<Bls12381Curve> {
    fn serialize<W: borsh::io::Write>(&self, w: &mut W) -> borsh::io::Result<()> {
        write_point(&self.user_public_key, w)?;
        write_point(&self.commitment_t1, w)?;
        write_point(&self.commitment_t2, w)?;
        write_scalar(&self.response_s, w)?;
        write_scalar(&self.nonce, w)?;
        Ok(())
    }
}

impl BorshDeserialize for RevealTokenProof<Bls12381Curve> {
    fn deserialize_reader<R: borsh::io::Read>(r: &mut R) -> borsh::io::Result<Self> {
        let user_public_key = read_point(r)?;
        let commitment_t1 = read_point(r)?;
        let commitment_t2 = read_point(r)?;
        let response_s = read_scalar(r)?;
        let nonce = read_scalar(r)?;
        Ok(Self {
            user_public_key,
            commitment_t1,
            commitment_t2,
            response_s,
            nonce,
        })
    }
}

// ============================================================
// ChaumPedersenDLEQProof<Bls12381Curve>
// ============================================================

impl BorshSerialize for ChaumPedersenDLEQProof<Bls12381Curve> {
    fn serialize<W: borsh::io::Write>(&self, w: &mut W) -> borsh::io::Result<()> {
        write_point(&self.commitment_a, w)?;
        write_point(&self.commitment_b, w)?;
        write_scalar(&self.response, w)?;
        Ok(())
    }
}

impl BorshDeserialize for ChaumPedersenDLEQProof<Bls12381Curve> {
    fn deserialize_reader<R: borsh::io::Read>(r: &mut R) -> borsh::io::Result<Self> {
        let commitment_a = read_point(r)?;
        let commitment_b = read_point(r)?;
        let response = read_scalar(r)?;
        Ok(Self {
            commitment_a,
            commitment_b,
            response,
        })
    }
}

// ============================================================
// ReconstructionDLEQProof<Bls12381Curve>
// ============================================================

impl BorshSerialize for ReconstructionDLEQProof<Bls12381Curve> {
    fn serialize<W: borsh::io::Write>(&self, w: &mut W) -> borsh::io::Result<()> {
        write_point(&self.commitment, w)?;
        write_scalar(&self.response, w)?;
        write_scalar(&self.nonce, w)?;
        Ok(())
    }
}

impl BorshDeserialize for ReconstructionDLEQProof<Bls12381Curve> {
    fn deserialize_reader<R: borsh::io::Read>(r: &mut R) -> borsh::io::Result<Self> {
        let commitment = read_point(r)?;
        let response = read_scalar(r)?;
        let nonce = read_scalar(r)?;
        Ok(Self {
            commitment,
            response,
            nonce,
        })
    }
}

// ============================================================
// SwapOutCardProof<Bls12381Curve>
// ============================================================

impl BorshSerialize for SwapOutCardProof<Bls12381Curve> {
    fn serialize<W: borsh::io::Write>(&self, w: &mut W) -> borsh::io::Result<()> {
        BorshSerialize::serialize(&self.user_readable_card, w)?;
        BorshSerialize::serialize(&self.swap_out_card, w)?;
        BorshSerialize::serialize(&self.chaum_pedersen_proof, w)?;
        Ok(())
    }
}

impl BorshDeserialize for SwapOutCardProof<Bls12381Curve> {
    fn deserialize_reader<R: borsh::io::Read>(r: &mut R) -> borsh::io::Result<Self> {
        let user_readable_card = BorshDeserialize::deserialize_reader(r)?;
        let swap_out_card = BorshDeserialize::deserialize_reader(r)?;
        let chaum_pedersen_proof = BorshDeserialize::deserialize_reader(r)?;
        Ok(Self {
            user_readable_card,
            swap_out_card,
            chaum_pedersen_proof,
        })
    }
}

// ============================================================
// ReconstructProof<Bls12381Curve>
// ============================================================

fn write_reconstruction_len<W: borsh::io::Write>(
    len: usize,
    min: usize,
    w: &mut W,
) -> borsh::io::Result<()> {
    if !(min..=MAX_RECONSTRUCTION_DECK_SIZE).contains(&len) {
        return Err(borsh::io::Error::new(
            borsh::io::ErrorKind::InvalidData,
            "invalid reconstruction vector length",
        ));
    }
    let len = u32::try_from(len).map_err(|_| {
        borsh::io::Error::new(
            borsh::io::ErrorKind::InvalidData,
            "reconstruction vector too long",
        )
    })?;
    w.write_all(&len.to_le_bytes())
}

fn read_reconstruction_len<R: borsh::io::Read>(r: &mut R, min: usize) -> borsh::io::Result<usize> {
    let mut len_bytes = [0u8; 4];
    r.read_exact(&mut len_bytes)?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    if !(min..=MAX_RECONSTRUCTION_DECK_SIZE).contains(&len) {
        return Err(borsh::io::Error::new(
            borsh::io::ErrorKind::InvalidData,
            "invalid reconstruction vector length",
        ));
    }
    Ok(len)
}

impl BorshSerialize for OrderedEncryptionProof<Bls12381Curve> {
    fn serialize<W: borsh::io::Write>(&self, w: &mut W) -> borsh::io::Result<()> {
        let n = self.responses.len();
        if self.commitment_g.len() != n || self.commitment_pk.len() != n {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "mismatched ordered encryption proof lengths",
            ));
        }
        write_reconstruction_len(n, 2, w)?;
        for point in &self.commitment_g {
            write_point(point, w)?;
        }
        for point in &self.commitment_pk {
            write_point(point, w)?;
        }
        for response in &self.responses {
            write_scalar(response, w)?;
        }
        Ok(())
    }
}

impl BorshDeserialize for OrderedEncryptionProof<Bls12381Curve> {
    fn deserialize_reader<R: borsh::io::Read>(r: &mut R) -> borsh::io::Result<Self> {
        let n = read_reconstruction_len(r, 2)?;
        let commitment_g = (0..n).map(|_| read_point(r)).collect::<Result<_, _>>()?;
        let commitment_pk = (0..n).map(|_| read_point(r)).collect::<Result<_, _>>()?;
        let responses = (0..n).map(|_| read_scalar(r)).collect::<Result<_, _>>()?;
        Ok(Self {
            commitment_g,
            commitment_pk,
            responses,
        })
    }
}

impl BorshSerialize for ReconstructProof<Bls12381Curve> {
    fn serialize<W: borsh::io::Write>(&self, w: &mut W) -> borsh::io::Result<()> {
        w.write_all(&[RECONSTRUCTION_PROOF_VERSION])?;
        write_reconstruction_len(self.swap_out_cards_proofs.len(), 1, w)?;
        for p in &self.swap_out_cards_proofs {
            BorshSerialize::serialize(p, w)?;
        }
        write_reconstruction_len(self.padded_swap_cards.len(), 2, w)?;
        for ciphertext in &self.padded_swap_cards {
            BorshSerialize::serialize(ciphertext, w)?;
        }
        BorshSerialize::serialize(&self.padded_swap_shuffle_proof, w)?;
        BorshSerialize::serialize(&self.ordered_encryption_proof, w)?;
        Ok(())
    }
}

impl BorshDeserialize for ReconstructProof<Bls12381Curve> {
    fn deserialize_reader<R: borsh::io::Read>(r: &mut R) -> borsh::io::Result<Self> {
        let mut version = [0u8; 1];
        r.read_exact(&mut version)?;
        if version[0] != RECONSTRUCTION_PROOF_VERSION {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "unsupported reconstruction proof version",
            ));
        }
        let swap_len = read_reconstruction_len(r, 1)?;
        let swap_out_cards_proofs = (0..swap_len)
            .map(|_| BorshDeserialize::deserialize_reader(r))
            .collect::<Result<Vec<_>, _>>()?;
        let n = read_reconstruction_len(r, 2)?;
        if swap_len > n {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "more swap cards than reconstruction slots",
            ));
        }
        let padded_swap_cards = (0..n)
            .map(|_| BorshDeserialize::deserialize_reader(r))
            .collect::<Result<Vec<ElGamalCiphertextGeneric<Bls12381Curve>>, _>>()?;
        let padded_swap_shuffle_proof =
            BayerGrothShuffleProof::<Bls12381Curve>::deserialize_reader(r)?;
        if padded_swap_shuffle_proof
            .multi_exponentiation
            .alpha_response
            .len()
            != n
        {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "Bayer-Groth proof length does not match reconstruction deck",
            ));
        }
        let ordered_encryption_proof =
            OrderedEncryptionProof::<Bls12381Curve>::deserialize_reader(r)?;
        if ordered_encryption_proof.responses.len() != n {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "ordered proof length does not match reconstruction deck",
            ));
        }
        Ok(Self {
            swap_out_cards_proofs,
            padded_swap_cards,
            padded_swap_shuffle_proof,
            ordered_encryption_proof,
        })
    }
}

// ============================================================
// Reconstruction V3 statement and proof package
// ============================================================

impl BorshSerialize for CrossKeyNegationProof<Bls12381Curve> {
    fn serialize<W: borsh::io::Write>(&self, w: &mut W) -> borsh::io::Result<()> {
        write_point(&self.commitment_owner_key, w)?;
        write_point(&self.commitment_contribution_c1, w)?;
        write_point(&self.commitment_joint_c2, w)?;
        write_scalar(&self.response_owner_sk, w)?;
        write_scalar(&self.response_contribution_randomness, w)
    }
}

impl BorshDeserialize for CrossKeyNegationProof<Bls12381Curve> {
    fn deserialize_reader<R: borsh::io::Read>(r: &mut R) -> borsh::io::Result<Self> {
        Ok(Self {
            commitment_owner_key: read_point(r)?,
            commitment_contribution_c1: read_point(r)?,
            commitment_joint_c2: read_point(r)?,
            response_owner_sk: read_scalar(r)?,
            response_contribution_randomness: read_scalar(r)?,
        })
    }
}

impl BorshSerialize for SlotContributionOrProof<Bls12381Curve> {
    fn serialize<W: borsh::io::Write>(&self, w: &mut W) -> borsh::io::Result<()> {
        for point in &self.commitment_g {
            write_point(point, w)?;
        }
        for point in &self.commitment_pk {
            write_point(point, w)?;
        }
        for challenge in &self.challenges {
            write_scalar(challenge, w)?;
        }
        for response in &self.responses {
            write_scalar(response, w)?;
        }
        Ok(())
    }
}

impl BorshDeserialize for SlotContributionOrProof<Bls12381Curve> {
    fn deserialize_reader<R: borsh::io::Read>(r: &mut R) -> borsh::io::Result<Self> {
        Ok(Self {
            commitment_g: [read_point(r)?, read_point(r)?],
            commitment_pk: [read_point(r)?, read_point(r)?],
            challenges: [read_scalar(r)?, read_scalar(r)?],
            responses: [read_scalar(r)?, read_scalar(r)?],
        })
    }
}

impl BorshSerialize for ReconstructionV3Statement<Bls12381Curve> {
    fn serialize<W: borsh::io::Write>(&self, w: &mut W) -> borsh::io::Result<()> {
        if self.version != RECONSTRUCTION_V3_PROOF_VERSION
            || self.cards.len() != self.contributions.len()
            || self.user_readable_cards.len() > self.cards.len()
        {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "invalid reconstruction V3 statement shape",
            ));
        }
        w.write_all(&[self.version])?;
        w.write_all(&self.context_digest)?;
        w.write_all(&self.reconstruction_epoch.to_le_bytes())?;
        w.write_all(&self.prior_state_digest)?;
        write_point(&self.aggregate_pk, w)?;
        write_point(&self.owner_pk, w)?;

        write_reconstruction_len(self.cards.len(), 2, w)?;
        for card in &self.cards {
            write_point(card, w)?;
        }
        write_reconstruction_len(self.user_readable_cards.len(), 1, w)?;
        for ciphertext in &self.user_readable_cards {
            BorshSerialize::serialize(ciphertext, w)?;
        }
        // Contributions have exactly the canonical card count, so no second
        // attacker-controlled length is necessary on the wire.
        for ciphertext in &self.contributions {
            BorshSerialize::serialize(ciphertext, w)?;
        }
        Ok(())
    }
}

impl BorshDeserialize for ReconstructionV3Statement<Bls12381Curve> {
    fn deserialize_reader<R: borsh::io::Read>(r: &mut R) -> borsh::io::Result<Self> {
        let mut version = [0u8; 1];
        r.read_exact(&mut version)?;
        if version[0] != RECONSTRUCTION_V3_PROOF_VERSION {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "unsupported reconstruction V3 statement version",
            ));
        }
        let mut context_digest = [0u8; 32];
        r.read_exact(&mut context_digest)?;
        let mut epoch_bytes = [0u8; 8];
        r.read_exact(&mut epoch_bytes)?;
        let reconstruction_epoch = u64::from_le_bytes(epoch_bytes);
        let mut prior_state_digest = [0u8; 32];
        r.read_exact(&mut prior_state_digest)?;
        let aggregate_pk = read_point(r)?;
        let owner_pk = read_point(r)?;

        let n = read_reconstruction_len(r, 2)?;
        let cards = (0..n).map(|_| read_point(r)).collect::<Result<_, _>>()?;
        let k = read_reconstruction_len(r, 1)?;
        if k > n {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "more readable cards than reconstruction slots",
            ));
        }
        let user_readable_cards = (0..k)
            .map(|_| BorshDeserialize::deserialize_reader(r))
            .collect::<Result<Vec<ElGamalCiphertextGeneric<Bls12381Curve>>, _>>()?;
        let contributions = (0..n)
            .map(|_| BorshDeserialize::deserialize_reader(r))
            .collect::<Result<Vec<ElGamalCiphertextGeneric<Bls12381Curve>>, _>>()?;
        let statement = Self {
            version: version[0],
            context_digest,
            reconstruction_epoch,
            prior_state_digest,
            aggregate_pk,
            owner_pk,
            cards,
            user_readable_cards,
            contributions,
        };
        statement.validate().map_err(|_| {
            borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "invalid reconstruction V3 statement",
            )
        })?;
        Ok(statement)
    }
}

impl BorshSerialize for ReconstructProofV3<Bls12381Curve> {
    fn serialize<W: borsh::io::Write>(&self, w: &mut W) -> borsh::io::Result<()> {
        let k = self.negative_contributions.len();
        let n = self.slot_membership_proofs.len();
        if self.cross_key_proofs.len() != k || k == 0 || k > n {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "invalid reconstruction V3 proof shape",
            ));
        }
        w.write_all(&[RECONSTRUCTION_V3_PROOF_VERSION])?;
        write_reconstruction_len(k, 1, w)?;
        for ciphertext in &self.negative_contributions {
            BorshSerialize::serialize(ciphertext, w)?;
        }
        for proof in &self.cross_key_proofs {
            BorshSerialize::serialize(proof, w)?;
        }
        BorshSerialize::serialize(&self.contribution_shuffle_proof, w)?;
        write_reconstruction_len(n, 2, w)?;
        for proof in &self.slot_membership_proofs {
            BorshSerialize::serialize(proof, w)?;
        }
        Ok(())
    }
}

impl BorshDeserialize for ReconstructProofV3<Bls12381Curve> {
    fn deserialize_reader<R: borsh::io::Read>(r: &mut R) -> borsh::io::Result<Self> {
        let mut version = [0u8; 1];
        r.read_exact(&mut version)?;
        if version[0] != RECONSTRUCTION_V3_PROOF_VERSION {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "unsupported reconstruction V3 proof version",
            ));
        }
        let k = read_reconstruction_len(r, 1)?;
        let negative_contributions = (0..k)
            .map(|_| BorshDeserialize::deserialize_reader(r))
            .collect::<Result<Vec<ElGamalCiphertextGeneric<Bls12381Curve>>, _>>(
        )?;
        let cross_key_proofs = (0..k)
            .map(|_| BorshDeserialize::deserialize_reader(r))
            .collect::<Result<Vec<CrossKeyNegationProof<Bls12381Curve>>, _>>()?;
        let contribution_shuffle_proof =
            BayerGrothShuffleProof::<Bls12381Curve>::deserialize_reader(r)?;
        let n = read_reconstruction_len(r, 2)?;
        if k > n
            || contribution_shuffle_proof
                .multi_exponentiation
                .alpha_response
                .len()
                != n
        {
            return Err(borsh::io::Error::new(
                borsh::io::ErrorKind::InvalidData,
                "reconstruction V3 proof vector lengths disagree",
            ));
        }
        let slot_membership_proofs = (0..n)
            .map(|_| BorshDeserialize::deserialize_reader(r))
            .collect::<Result<Vec<SlotContributionOrProof<Bls12381Curve>>, _>>(
        )?;
        Ok(Self {
            negative_contributions,
            cross_key_proofs,
            contribution_shuffle_proof,
            slot_membership_proofs,
        })
    }
}

// ============================================================
// 测试
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reconstruction::reconstruct_deck;
    use crate::transcript_ext::{CryptoTranscript, FiatShamirTranscript};
    use poker_protocol_core::{Curve, CurvePoint, ElGamalCiphertextGeneric};
    use rand_core::OsRng;

    #[test]
    fn elgamal_ciphertext_borsh_roundtrip() {
        let sk = <BlsScalar as CurveScalar>::random(&mut OsRng);
        let pk = <G1Projective as CurvePoint>::identity() + <Bls12381Curve as Curve>::base_g() * sk;
        let plaintext = <Bls12381Curve as Curve>::base_h();
        let r = <BlsScalar as CurveScalar>::random(&mut OsRng);
        let ct = ElGamalCiphertextGeneric::<Bls12381Curve>::encrypt(&plaintext, &pk, &r);

        let bytes = borsh::to_vec(&ct).unwrap();
        assert_eq!(bytes.len(), 2 * G1_COMPRESSED_LEN);
        let recovered: ElGamalCiphertextGeneric<Bls12381Curve> = borsh::from_slice(&bytes).unwrap();
        assert_eq!(ct, recovered);
    }

    #[test]
    fn generalized_schnorr_borsh_roundtrip() {
        let commitment = <Bls12381Curve as Curve>::base_g();
        let responses = vec![
            <BlsScalar as CurveScalar>::random(&mut OsRng),
            <BlsScalar as CurveScalar>::random(&mut OsRng),
        ];
        let proof = GeneralizedSchnorrProof::<Bls12381Curve> {
            commitment,
            responses,
        };

        let bytes = borsh::to_vec(&proof).unwrap();
        let recovered: GeneralizedSchnorrProof<Bls12381Curve> = borsh::from_slice(&bytes).unwrap();
        assert_eq!(proof.commitment, recovered.commitment);
        assert_eq!(proof.responses.len(), recovered.responses.len());
    }

    #[test]
    fn reveal_token_proof_borsh_roundtrip() {
        let proof = RevealTokenProof::<Bls12381Curve> {
            user_public_key: <Bls12381Curve as Curve>::base_g(),
            commitment_t1: <Bls12381Curve as Curve>::base_h(),
            commitment_t2: <Bls12381Curve as Curve>::base_g(),
            response_s: <BlsScalar as CurveScalar>::random(&mut OsRng),
            nonce: <BlsScalar as CurveScalar>::random(&mut OsRng),
        };
        let bytes = borsh::to_vec(&proof).unwrap();
        let recovered: RevealTokenProof<Bls12381Curve> = borsh::from_slice(&bytes).unwrap();
        // RevealTokenProof 未 derive PartialEq，逐字段比较
        assert_eq!(proof.user_public_key, recovered.user_public_key);
        assert_eq!(proof.commitment_t1, recovered.commitment_t1);
        assert_eq!(proof.commitment_t2, recovered.commitment_t2);
        assert_eq!(proof.response_s, recovered.response_s);
        assert_eq!(proof.nonce, recovered.nonce);
    }

    #[test]
    fn versioned_bayer_groth_borsh_roundtrip_and_verify() {
        let n = 8;
        let secret_key = <BlsScalar as CurveScalar>::random(&mut OsRng);
        let public_key = <Bls12381Curve as Curve>::base_g() * secret_key;
        let input: Vec<_> = (0..n)
            .map(|i| {
                let message = <Bls12381Curve as Curve>::hash_to_curve(
                    format!("borsh/bg12/card/{i}").as_bytes(),
                );
                let randomness = <BlsScalar as CurveScalar>::random(&mut OsRng);
                ElGamalCiphertextGeneric::<Bls12381Curve>::encrypt(
                    &message,
                    &public_key,
                    &randomness,
                )
            })
            .collect();
        let permutation = vec![3, 0, 7, 1, 6, 2, 5, 4];
        let rerandomizers: Vec<_> = (0..n)
            .map(|_| <BlsScalar as CurveScalar>::random(&mut OsRng))
            .collect();
        let output: Vec<_> = (0..n)
            .map(|i| input[permutation[i]].re_encrypt(&public_key, &rerandomizers[i]))
            .collect();
        let proof = VersionedShuffleProof::<Bls12381Curve>::prove(
            &input,
            &output,
            &permutation,
            &rerandomizers,
            &public_key,
            &mut OsRng,
            &mut FiatShamirTranscript::new(b"borsh-bg12-v2"),
        )
        .unwrap();

        let bytes = borsh::to_vec(&proof).unwrap();
        assert_eq!(bytes[0], BAYER_GROTH_SHUFFLE_PROOF_VERSION);
        let recovered: VersionedShuffleProof<Bls12381Curve> = borsh::from_slice(&bytes).unwrap();
        assert_eq!(recovered.version(), BAYER_GROTH_SHUFFLE_PROOF_VERSION);
        assert!(recovered
            .verify(
                &input,
                &output,
                &public_key,
                &mut FiatShamirTranscript::new(b"borsh-bg12-v2"),
            )
            .is_ok());
    }

    #[test]
    fn versioned_shuffle_rejects_unknown_version() {
        let result = borsh::from_slice::<VersionedShuffleProof<Bls12381Curve>>(&[99]);
        assert!(result.is_err());
    }

    #[test]
    fn reconstruction_v2_borsh_roundtrip_and_verify() {
        let cards = (0..8)
            .map(|i| {
                <Bls12381Curve as Curve>::hash_to_curve(
                    format!("borsh/reconstruction/card/{i}").as_bytes(),
                )
            })
            .collect::<Vec<_>>();
        let user_sk = <BlsScalar as CurveScalar>::from_u64(73);
        let user_pk = <Bls12381Curve as Curve>::base_g() * user_sk;
        let user_readable_cards = [1usize, 6]
            .iter()
            .enumerate()
            .map(|(i, index)| {
                ElGamalCiphertextGeneric::<Bls12381Curve>::encrypt(
                    &cards[*index],
                    &user_pk,
                    &<BlsScalar as CurveScalar>::from_u64(1000 + i as u64),
                )
            })
            .collect::<Vec<_>>();
        let (s_vec, output_cards, swap_out_cards) = reconstruct_deck::<Bls12381Curve>(
            &cards,
            &user_readable_cards,
            &user_sk,
            &user_pk,
            &<BlsScalar as CurveScalar>::from_u64(7),
        )
        .unwrap();
        let proof = ReconstructProof::<Bls12381Curve>::prove(
            cards.clone(),
            user_readable_cards.clone(),
            output_cards.clone(),
            swap_out_cards.clone(),
            &user_sk,
            &user_pk,
            s_vec,
            &mut FiatShamirTranscript::new(b"borsh-reconstruction-v2"),
        )
        .unwrap();

        let bytes = borsh::to_vec(&proof).unwrap();
        assert_eq!(bytes[0], RECONSTRUCTION_PROOF_VERSION);
        let recovered: ReconstructProof<Bls12381Curve> = borsh::from_slice(&bytes).unwrap();
        let swap_ciphertexts = swap_out_cards
            .iter()
            .map(|(_, ciphertext)| ciphertext.clone())
            .collect::<Vec<_>>();
        recovered
            .verify(
                &cards,
                &output_cards,
                &swap_ciphertexts,
                &user_readable_cards,
                &user_pk,
                &mut FiatShamirTranscript::new(b"borsh-reconstruction-v2"),
            )
            .unwrap();
    }

    #[test]
    fn reconstruction_v2_borsh_rejects_unknown_version_and_huge_length() {
        assert!(borsh::from_slice::<ReconstructProof<Bls12381Curve>>(&[99]).is_err());

        let mut malicious = vec![RECONSTRUCTION_PROOF_VERSION];
        malicious.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(borsh::from_slice::<ReconstructProof<Bls12381Curve>>(&malicious).is_err());
    }

    #[test]
    fn reconstruction_v3_statement_and_proof_borsh_roundtrip() {
        let cards = (0..8)
            .map(|i| {
                <Bls12381Curve as Curve>::hash_to_curve(
                    format!("borsh/reconstruction/v3/card/{i}").as_bytes(),
                )
            })
            .collect::<Vec<_>>();
        let owner_sk = <BlsScalar as CurveScalar>::from_u64(73);
        let other_sk = <BlsScalar as CurveScalar>::from_u64(29);
        let aggregate_sk = owner_sk + other_sk;
        let owner_pk = <Bls12381Curve as Curve>::base_g() * owner_sk;
        let aggregate_pk = <Bls12381Curve as Curve>::base_g() * aggregate_sk;
        let readable_cards = [1usize, 6]
            .iter()
            .enumerate()
            .map(|(i, index)| {
                ElGamalCiphertextGeneric::<Bls12381Curve>::encrypt(
                    &cards[*index],
                    &owner_pk,
                    &<BlsScalar as CurveScalar>::from_u64(2000 + i as u64),
                )
            })
            .collect::<Vec<_>>();

        let (statement, proof) = ReconstructProofV3::<Bls12381Curve>::prove(
            [3u8; 32],
            12,
            [4u8; 32],
            cards,
            readable_cards,
            &owner_sk,
            &owner_pk,
            &aggregate_pk,
            &mut OsRng,
            &mut FiatShamirTranscript::new(b"borsh-reconstruction-v3"),
        )
        .unwrap();

        let statement_bytes = borsh::to_vec(&statement).unwrap();
        let proof_bytes = borsh::to_vec(&proof).unwrap();
        assert_eq!(statement_bytes[0], RECONSTRUCTION_V3_PROOF_VERSION);
        assert_eq!(proof_bytes[0], RECONSTRUCTION_V3_PROOF_VERSION);

        let recovered_statement: ReconstructionV3Statement<Bls12381Curve> =
            borsh::from_slice(&statement_bytes).unwrap();
        let recovered_proof: ReconstructProofV3<Bls12381Curve> =
            borsh::from_slice(&proof_bytes).unwrap();
        recovered_proof
            .verify(
                &recovered_statement,
                &mut FiatShamirTranscript::new(b"borsh-reconstruction-v3"),
            )
            .unwrap();
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
