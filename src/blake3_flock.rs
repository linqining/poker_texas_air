//! BLAKE3 binary-field (flock) hash-proving backend.
//!
//! The hash layer's digests and proofs move from the M31 Blake2b lookup
//! stack to the vendored flock prover (`third_party/flock`, BLAKE3
//! Merkle-fork).  Two statement shapes exist, both rooted in one BLAKE3
//! compression `compress(cv, m, counter, blen, flags)`:
//!
//! - **Preimage statements** (`digest = blake3_chain_digest(message)`): a
//!   padded length-bound chain of compressions from the public IV to the
//!   public `cv_last == digest`.  Proved with flock's chain statement
//!   (`cv_{i+1} = compress(cv_i, m_i)`), with the message bytes absorbed
//!   into the Fiat–Shamir transcript so the witness message blocks are
//!   bound to the public statement.
//! - **SMT path statements** (256 × 64-byte node messages plus one leaf):
//!   proved with flock's Merkle-path statement, which algebraically binds
//!   the public leaf, the public root, and the public direction bits (the
//!   key).  Sibling halves stay witness — the (leaf, root) binding rests on
//!   BLAKE3 compression preimage resistance, which is exactly the security
//!   the statement needs.
//!
//! Splice protection is unchanged: the archive carries the exact ordered
//! statement list, and the trait's `verify_statements` rejects any splice,
//! reorder, or substitution before backend verification runs.

#![allow(missing_docs)]

use crate::error::{TexasAirError, TexasAirResult};
use crate::hash_prover::{ArchivedHashProof, Blake2bStatement, HashProofProvider};
use flock_core::challenger::Challenger as _;
use flock_core::challenger::FsChallenger;
use flock_prover::r1cs_hashes::blake3::{
    BLAKE3_IV, Blake3Setup, Compression, blake3_compress, cv_to_phys_bits,
};

/// Fiat–Shamir domain for preimage-chain proofs.
pub const FLOCK_CHAIN_DOMAIN: &[u8] = b"zchain.texas.flock-chain.v1";
/// Fiat–Shamir domain for Merkle-path proofs.
pub const FLOCK_MERKLE_DOMAIN: &[u8] = b"zchain.texas.flock-merkle.v1";

/// Minimum chain length: the smallest registered Ligerito security config
/// is m = 22 (k_log = 14), i.e. 256 blocks.  The chain prove cost is fixed
/// overhead dominated, so padding small preimages up to 256 steps is free.
const MIN_CHAIN_STEPS: usize = 256;

fn words32(bytes: &[u8; 32]) -> [u32; 8] {
    let mut out = [0u32; 8];
    for w in 0..8 {
        out[w] = u32::from_le_bytes(bytes[w * 4..w * 4 + 4].try_into().unwrap());
    }
    out
}

fn bytes32(words: &[u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for w in 0..8 {
        out[w * 4..w * 4 + 4].copy_from_slice(&words[w].to_le_bytes());
    }
    out
}

fn words64(bytes: &[u8; 64]) -> [u32; 16] {
    let mut out = [0u32; 16];
    for w in 0..16 {
        out[w] = u32::from_le_bytes(bytes[w * 4..w * 4 + 4].try_into().unwrap());
    }
    out
}

/// One BLAKE3 compression over exactly 64 bytes, output the low chaining
/// value.  This is the node hash of the SMT layer.
#[must_use]
pub fn blake3_hash64(message: &[u8; 64]) -> [u8; 32] {
    let state = blake3_compress(&BLAKE3_IV, &words64(message), 0, 64, 0);
    let mut out = [0u32; 8];
    out.copy_from_slice(&state[0..8]);
    bytes32(&out)
}

/// The exact compression sequence of the padded length-bound chain for one
/// preimage: `ceil(len/64)` chunk blocks, one length block (LE `u64` length
/// in the first word), zero-padded to the step floor.  Chaining values
/// thread block-to-block (`cv_{i+1} = out_lo(compress(cv_i, m_i))`), which
/// is exactly the relation the flock chain statement proves.
#[must_use]
pub fn blake3_chain_blocks(message: &[u8]) -> Vec<Compression> {
    let n_chunks = message.len().div_ceil(64);
    let steps = MIN_CHAIN_STEPS.max(n_chunks.saturating_add(1).next_power_of_two());
    let mut blocks: Vec<Compression> = Vec::with_capacity(steps.max(n_chunks + 1));
    let mut cv = BLAKE3_IV;
    let mut push = |cv: [u32; 8],
                    block: [u8; 64],
                    blen: u32,
                    blocks: &mut Vec<Compression>| {
        let m = words64(&block);
        let state = blake3_compress(&cv, &m, 0, blen, 0);
        let mut lo = [0u32; 8];
        lo.copy_from_slice(&state[0..8]);
        blocks.push((cv, m, 0u64, blen, 0u32));
        lo
    };
    for chunk in 0..n_chunks {
        let mut block = [0u8; 64];
        let hi = (64 * (chunk + 1)).min(message.len());
        block[..hi - 64 * chunk].copy_from_slice(&message[64 * chunk..hi]);
        let blen = (hi - 64 * chunk) as u32;
        cv = push(cv, block, blen, &mut blocks);
    }
    let mut len_block = [0u8; 64];
    len_block[..8].copy_from_slice(&(message.len() as u64).to_le_bytes());
    cv = push(cv, len_block, 64, &mut blocks);
    while blocks.len() < steps {
        cv = push(cv, [0u8; 64], 0, &mut blocks);
    }
    blocks
}

/// The digest of a preimage statement: the terminal chaining value of
/// [`blake3_chain_blocks`].  Native evaluation is prover-side only; the
/// verify path authenticates it through the flock chain proof.
#[must_use]
pub fn blake3_chain_digest(message: &[u8]) -> [u8; 32] {
    let blocks = blake3_chain_blocks(message);
    let last = blocks.last().expect("chain is never empty");
    let state = blake3_compress(&last.0, &last.1, last.2, last.3, last.4);
    let mut lo = [0u32; 8];
    lo.copy_from_slice(&state[0..8]);
    bytes32(&lo)
}

/// A proved preimage chain.
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct ArchivedFlockChain {
    /// Index range [start, end) of the covered statement (always one).
    pub index: u32,
    pub cv_0: [u8; 32],
    pub cv_last: [u8; 32],
    /// bincode(flock Commitment + ChainProofLigerito).
    pub bundle: Vec<u8>,
}

/// A proved Merkle path run.
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct ArchivedFlockMerkle {
    /// Index range [start, end) of the covered statements (leaf + parents).
    pub start: u32,
    pub len: u32,
    pub leaf: [u8; 32],
    pub root: [u8; 32],
    pub b_bits: Vec<u8>,
    /// bincode(flock Commitment + MerklePathProofLigerito).
    pub bundle: Vec<u8>,
}

/// The flock backend archive: covered statements plus their proofs.
#[derive(Debug, Clone, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct ArchivedFlockHashesProof {
    pub statements: Vec<Blake2bStatement>,
    pub chains: Vec<ArchivedFlockChain>,
    pub merkles: Vec<ArchivedFlockMerkle>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ChainBundle {
    commitment: flock_core::pcs::Commitment,
    proof: flock_prover::r1cs_hashes::chain_common::ChainProofLigerito,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct MerkleBundle {
    commitment: flock_core::pcs::Commitment,
    proof: flock_prover::r1cs_hashes::merkle_path_common::MerklePathProofLigerito,
}

fn pack_chain(
    commitment: &flock_core::pcs::Commitment,
    proof: &flock_prover::r1cs_hashes::chain_common::ChainProofLigerito,
) -> TexasAirResult<Vec<u8>> {
    bincode::serialize(&ChainBundle {
        commitment: commitment.clone(),
        proof: proof.clone(),
    })
    .map_err(|e| TexasAirError::SerializationError(e.to_string()))
}

fn unpack_chain(bytes: &[u8]) -> TexasAirResult<ChainBundle> {
    bincode::deserialize(bytes).map_err(|e| TexasAirError::SerializationError(e.to_string()))
}

fn pack_merkle(
    commitment: &flock_core::pcs::Commitment,
    proof: &flock_prover::r1cs_hashes::merkle_path_common::MerklePathProofLigerito,
) -> TexasAirResult<Vec<u8>> {
    bincode::serialize(&MerkleBundle {
        commitment: commitment.clone(),
        proof: proof.clone(),
    })
    .map_err(|e| TexasAirError::SerializationError(e.to_string()))
}

fn unpack_merkle(bytes: &[u8]) -> TexasAirResult<MerkleBundle> {
    bincode::deserialize(bytes).map_err(|e| TexasAirError::SerializationError(e.to_string()))
}

/// Absorb a statement tag into a Fiat–Shamir transcript so that witness
/// message blocks cannot be swapped for a different statement's preimage.
fn absorb_statement<Ch: flock_core::challenger::Challenger>(ch: &mut Ch, statement: &Blake2bStatement) {
    ch.observe_bytes(&(statement.message.len() as u64).to_le_bytes());
    ch.observe_bytes(&statement.message);
    ch.observe_bytes(&statement.digest);
}

/// One Merkle path run recognized inside an ordered statement list: the leaf
/// statement plus the parent statements, each message containing the
/// previous digest as one 32-byte half.
struct PathRun {
    start: usize,
    len: usize,
    b_bits: Vec<bool>,
}

/// Detect the Merkle run starting at `start`, if any.  A run requires ≥ 2
/// statements (leaf + parents), every message exactly 64 bytes, and each
/// parent message containing the previous digest as one half.  Returns the
/// run length and the derived direction bits.
fn recognize_path_run(statements: &[Blake2bStatement], start: usize) -> Option<PathRun> {
    if start >= statements.len() || statements[start].message.len() != 64 {
        return None;
    }
    let mut b_bits = Vec::new();
    let mut len = 1usize;
    while start + len < statements.len() {
        let prev = statements[start + len - 1].digest;
        let msg = statements[start + len].message.as_slice();
        if msg.len() != 64 {
            break;
        }
        let left = &msg[..32];
        let right = &msg[32..];
        if left == prev {
            b_bits.push(false);
        } else if right == prev {
            b_bits.push(true);
        } else {
            break;
        }
        len += 1;
    }
    if len < 2 {
        return None;
    }
    Some(PathRun { start, len, b_bits })
}

/// The binary-field flock backend.
#[derive(Debug, Clone, Copy, Default)]
pub struct FlockProvider;

impl HashProofProvider for FlockProvider {
    fn prove_statements(
        &self,
        statements: &[Blake2bStatement],
    ) -> TexasAirResult<ArchivedHashProof> {
        if statements.is_empty() {
            return Err(TexasAirError::SpecViolation(
                "hash proof batch must not be empty".into(),
            ));
        }
        // Witness generation over the padded chain/merkle schedules uses
        // deep stacks (and nested rayon workers) in debug builds; run it
        // inside a dedicated large-stack thread pool so callers on default
        // test/rayon stacks never overflow.
        let statements = statements.to_vec();
        flock_pool().install(|| prove_statements_on_stack(&statements))
    }

    fn verify_proof(&self, proof: &ArchivedHashProof) -> TexasAirResult<()> {
        let ArchivedHashProof::Flock(inner) = proof else {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "proof was not produced by the flock backend".into(),
            ));
        };
        // Re-derive the segmentation from the covered statements; it must
        // reproduce the archived chain/merkle layout exactly.
        let mut chains = inner.chains.iter();
        let mut merkles = inner.merkles.iter();
        let mut i = 0usize;
        while i < inner.statements.len() {
            if let Some(run) = recognize_path_run(&inner.statements, i) {
                let archived = merkles.next().ok_or_else(|| {
                    TexasAirError::ConstraintUnsatisfied(
                        "flock proof is missing a merkle-path sub-proof".into(),
                    )
                })?;
                if archived.start as usize != run.start
                    || archived.len as usize != run.len
                    || archived.b_bits.len() != run.b_bits.len()
                    || archived
                        .b_bits
                        .iter()
                        .zip(run.b_bits.iter())
                        .any(|(a, b)| (*a == 1) != *b)
                {
                    return Err(TexasAirError::ConstraintUnsatisfied(
                        "flock merkle sub-proof is detached from its statements".into(),
                    ));
                }
                verify_merkle_run(&inner.statements, &run, archived)?;
                i += run.len;
                continue;
            }
            let archived = chains.next().ok_or_else(|| {
                TexasAirError::ConstraintUnsatisfied(
                    "flock proof is missing a chain sub-proof".into(),
                )
            })?;
            if archived.index as usize != i {
                return Err(TexasAirError::ConstraintUnsatisfied(
                    "flock chain sub-proof index does not match the statement order".into(),
                ));
            }
            verify_chain_statement(&inner.statements[i], archived)?;
            i += 1;
        }
        if chains.next().is_some() || merkles.next().is_some() {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "flock proof carries sub-proofs beyond the covered statements".into(),
            ));
        }
        Ok(())
    }
}

static FLOCK_POOL: std::sync::OnceLock<rayon::ThreadPool> = std::sync::OnceLock::new();

fn flock_pool() -> &'static rayon::ThreadPool {
    FLOCK_POOL.get_or_init(|| {
        rayon::ThreadPoolBuilder::new()
            .stack_size(64 * 1024 * 1024)
            .build()
            .expect("flock prover thread pool builds")
    })
}

fn prove_statements_on_stack(
    statements: &[Blake2bStatement],
) -> TexasAirResult<ArchivedHashProof> {
    let mut chains = Vec::new();
    let mut merkles = Vec::new();
    let mut i = 0usize;
    while i < statements.len() {
        if let Some(run) = recognize_path_run(statements, i) {
            merkles.push(prove_merkle_run(statements, &run)?);
            i += run.len;
            continue;
        }
        chains.push(prove_chain_statement(&statements[i], i as u32)?);
        i += 1;
    }
    Ok(ArchivedHashProof::Flock(ArchivedFlockHashesProof {
        statements: statements.to_vec(),
        chains,
        merkles,
    }))
}

fn prove_chain_statement(
    statement: &Blake2bStatement,
    index: u32,
) -> TexasAirResult<ArchivedFlockChain> {
    let blocks = blake3_chain_blocks(&statement.message);
    let mut cv = BLAKE3_IV;
    for (_, m, counter, blen, flags) in &blocks {
        let state = blake3_compress(&cv, m, *counter, *blen, *flags);
        let mut lo = [0u32; 8];
        lo.copy_from_slice(&state[0..8]);
        cv = lo;
    }
    let cv_last = bytes32(&cv);
    if cv_last != statement.digest {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "preimage statement digest does not match the blake3 chain".into(),
        ));
    }
    let setup = Blake3Setup::with_profile(
        blocks.len(),
        flock_core::pcs::ligerito::LigeritoProfile::Slim,
    );
    let mut ch = FsChallenger::new(FLOCK_CHAIN_DOMAIN);
    absorb_statement(&mut ch, statement);
    let (proof, commitment) = setup.prove_chain(&blocks, &mut ch);
    Ok(ArchivedFlockChain {
        index,
        cv_0: bytes32(&BLAKE3_IV),
        cv_last,
        bundle: pack_chain(&commitment, &proof)?,
    })
}

fn verify_chain_statement(
    statement: &Blake2bStatement,
    archived: &ArchivedFlockChain,
) -> TexasAirResult<()> {
    if archived.cv_0 != bytes32(&BLAKE3_IV) {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "flock chain sub-proof has an unexpected initial chaining value".into(),
        ));
    }
    let steps = blake3_chain_blocks(&statement.message).len();
    let bundle = unpack_chain(&archived.bundle)?;
    let setup = Blake3Setup::with_profile(
        steps,
        flock_core::pcs::ligerito::LigeritoProfile::Slim,
    );
    let mut ch = FsChallenger::new(FLOCK_CHAIN_DOMAIN);
    absorb_statement(&mut ch, statement);
    setup
        .verify_chain(
            &bundle.commitment,
            &bundle.proof,
            &words32(&archived.cv_0),
            &words32(&archived.cv_last),
            &mut ch,
        )
        .map_err(|e| {
            TexasAirError::ConstraintUnsatisfied(format!("flock chain proof rejected: {e:?}"))
        })
}

fn prove_merkle_run(
    statements: &[Blake2bStatement],
    run: &PathRun,
) -> TexasAirResult<ArchivedFlockMerkle> {
    let nodes = run.len - 1;
    if !nodes.is_power_of_two() || nodes < MIN_CHAIN_STEPS {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "merkle-path statement runs must be a leaf plus a power-of-two ≥ 8 parents".into(),
        ));
    }
    let mut compressions: Vec<Compression> = Vec::with_capacity(nodes);
    for offset in 1..run.len {
        let statement = &statements[run.start + offset];
        let msg: [u8; 64] = statement.message.as_slice().try_into().map_err(|_| {
            TexasAirError::ConstraintUnsatisfied("merkle node message must be 64 bytes".into())
        })?;
        let digest = blake3_hash64(&msg);
        if digest != statement.digest {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "merkle node statement digest does not match the blake3 compression".into(),
            ));
        }
        compressions.push((BLAKE3_IV, words64(&msg), 0u64, 64u32, 0u32));
    }
    let leaf = statements[run.start].digest;
    let root = statements[run.start + run.len - 1].digest;
    let setup = Blake3Setup::with_profile(
        nodes,
        flock_core::pcs::ligerito::LigeritoProfile::Slim,
    );
    let mut ch = FsChallenger::new(FLOCK_MERKLE_DOMAIN);
    absorb_statement(&mut ch, &statements[run.start]);
    ch.observe_bytes(&root);
    let (proof, commitment) = setup.prove_merkle_path(&compressions, &run.b_bits, &mut ch);
    Ok(ArchivedFlockMerkle {
        start: run.start as u32,
        len: run.len as u32,
        leaf,
        root,
        b_bits: run.b_bits.iter().map(|b| *b as u8).collect(),
        bundle: pack_merkle(&commitment, &proof)?,
    })
}

fn verify_merkle_run(
    statements: &[Blake2bStatement],
    run: &PathRun,
    archived: &ArchivedFlockMerkle,
) -> TexasAirResult<()> {
    if archived.leaf != statements[run.start].digest
        || archived.root != statements[run.start + run.len - 1].digest
    {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "flock merkle sub-proof endpoints do not match its statements".into(),
        ));
    }
    let nodes = run.len - 1;
    let bundle = unpack_merkle(&archived.bundle)?;
    let setup = Blake3Setup::with_profile(
        nodes,
        flock_core::pcs::ligerito::LigeritoProfile::Slim,
    );
    let b_bits: Vec<bool> = run.b_bits.clone();
    let mut ch = FsChallenger::new(FLOCK_MERKLE_DOMAIN);
    absorb_statement(&mut ch, &statements[run.start]);
    ch.observe_bytes(&archived.root);
    setup
        .verify_merkle_path(
            &bundle.commitment,
            &bundle.proof,
            &words32(&archived.leaf),
            &words32(&archived.root),
            &b_bits,
            &mut ch,
        )
        .map_err(|e| {
            TexasAirError::ConstraintUnsatisfied(format!("flock merkle proof rejected: {e:?}"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_digest_is_length_bound() {
        let a = blake3_chain_digest(&[1u8; 64]);
        let b = blake3_chain_digest(&[1u8; 128]);
        let padded = {
            let mut m = vec![1u8; 64];
            m.extend_from_slice(&[0u8; 64]);
            blake3_chain_digest(&m)
        };
        assert_ne!(a, b);
        assert_ne!(a, padded);
        assert_eq!(blake3_chain_digest(&[7u8; 65]), blake3_chain_digest(&[7u8; 65]));
    }

    #[test]
    fn preimage_statements_prove_and_verify() {
        let statements = vec![
            Blake2bStatement::new(b"zchain.texas.rules.v2".to_vec(), blake3_chain_digest(b"zchain.texas.rules.v2")),
            Blake2bStatement::new(vec![9u8; 200], blake3_chain_digest(&[9u8; 200])),
        ];
        let proof = FlockProvider.prove_statements(&statements).expect("proof");
        FlockProvider.verify_statements(&proof, &statements).expect("verify");

        // Wrong digest fails at prove; splices fail at verify.
        let mut wrong = statements.clone();
        wrong[1].digest[0] ^= 1;
        assert!(FlockProvider.prove_statements(&wrong).is_err());
        assert!(FlockProvider.verify_statements(&proof, &wrong).is_err());
    }

    #[test]
    fn merkle_run_proves_and_verify_rejects_endpoint_tamper() {
        // A depth-256 synthetic SMT-style path: leaf = H1(key||value), parents
        // = H1(left||right) with one half the previous digest.
        let key = [3u8; 32];
        let value = [5u8; 32];
        let mut node = blake3_hash64(&{
            let mut m = [0u8; 64];
            m[..32].copy_from_slice(&key);
            m[32..].copy_from_slice(&value);
            m
        });
        let mut statements = vec![Blake2bStatement::new(
            {
                let mut m = [0u8; 64];
                m[..32].copy_from_slice(&key);
                m[32..].copy_from_slice(&value);
                m.to_vec()
            },
            node,
        )];
        for height in 0..256 {
            let mut sibling = [0u8; 32];
            sibling[0] = height as u8;
            let bit = height % 2 == 1;
            let mut msg = [0u8; 64];
            if bit {
                msg[..32].copy_from_slice(&sibling);
                msg[32..].copy_from_slice(&node);
            } else {
                msg[..32].copy_from_slice(&node);
                msg[32..].copy_from_slice(&sibling);
            }
            node = blake3_hash64(&msg);
            statements.push(Blake2bStatement::new(msg.to_vec(), node));
        }
        let proof = FlockProvider.prove_statements(&statements).expect("proof");
        FlockProvider
            .verify_statements(&proof, &statements)
            .expect("verify");

        // A different root in the last statement must fail closed.
        let mut tampered = statements.clone();
        let last = tampered.len() - 1;
        tampered[last].digest[0] ^= 1;
        assert!(FlockProvider.verify_statements(&proof, &tampered).is_err());
    }
}

#[cfg(test)]
mod mixed_tests {
    use super::*;
    use crate::smt_statements::{smt_path_statements, synthetic_smt_witness};

    #[test]
    fn mixed_chain_then_merkle_segments_correctly() {
        let chains: Vec<Blake2bStatement> = vec![
            Blake2bStatement::new(
                b"zchain.texas.rules.v2".to_vec(),
                blake3_chain_digest(b"zchain.texas.rules.v2"),
            ),
            Blake2bStatement::new(vec![7u8; 300], blake3_chain_digest(&[7u8; 300])),
            Blake2bStatement::new(vec![8u8; 300], blake3_chain_digest(&[8u8; 300])),
        ];
        let witness = synthetic_smt_witness(0x5a, [0x11; 32], [0x22; 32]);
        let mut statements = chains;
        statements.extend(smt_path_statements(&witness).expect("path"));
        let proof = FlockProvider.prove_statements(&statements).expect("proof");
        FlockProvider.verify_statements(&proof, &statements).expect("verify");
    }
}
