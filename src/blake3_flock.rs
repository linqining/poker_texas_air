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
use flock_prover::r1cs_hashes::blake3::{BLAKE3_IV, Blake3Setup, Compression, blake3_compress};
use rayon::prelude::*;

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
    blake3_chain_blocks_with_cv(message).0
}

/// Number of chain steps for a message of the given length: a pure function
/// of the padded schedule above, shared by prove and verify so the two sides
/// cannot drift apart.
fn chain_steps(message_len: usize) -> usize {
    let n_chunks = message_len.div_ceil(64);
    MIN_CHAIN_STEPS.max(n_chunks.saturating_add(1).next_power_of_two())
}

/// [`blake3_chain_blocks`] plus the terminal chaining value it already
/// computes, so prove paths need not re-compress the block vector.
fn blake3_chain_blocks_with_cv(message: &[u8]) -> (Vec<Compression>, [u32; 8]) {
    let n_chunks = message.len().div_ceil(64);
    let steps = chain_steps(message.len());
    let mut blocks: Vec<Compression> = Vec::with_capacity(steps.max(n_chunks + 1));
    let mut cv = BLAKE3_IV;
    let mut push = |cv: [u32; 8], block: [u8; 64], blen: u32, blocks: &mut Vec<Compression>| {
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
    (blocks, cv)
}

/// The digest of a preimage statement: the terminal chaining value of the
/// padded chain.  Computed streaming — each block's compression already
/// yields the next chaining value, so the last one is the digest and no
/// block vector is materialized.  Native evaluation is prover-side only; the
/// verify path authenticates it through the flock chain proof.
#[must_use]
pub fn blake3_chain_digest(message: &[u8]) -> [u8; 32] {
    let n_chunks = message.len().div_ceil(64);
    let steps = chain_steps(message.len());
    let mut cv = BLAKE3_IV;
    let mut advance = |cv: [u32; 8], block: [u8; 64], blen: u32| {
        let state = blake3_compress(&cv, &words64(&block), 0, blen, 0);
        let mut lo = [0u32; 8];
        lo.copy_from_slice(&state[0..8]);
        lo
    };
    for chunk in 0..n_chunks {
        let mut block = [0u8; 64];
        let hi = (64 * (chunk + 1)).min(message.len());
        block[..hi - 64 * chunk].copy_from_slice(&message[64 * chunk..hi]);
        cv = advance(cv, block, (hi - 64 * chunk) as u32);
    }
    let mut len_block = [0u8; 64];
    len_block[..8].copy_from_slice(&(message.len() as u64).to_le_bytes());
    cv = advance(cv, len_block, 64);
    for _ in n_chunks + 1..steps {
        cv = advance(cv, [0u8; 64], 0);
    }
    bytes32(&cv)
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
fn absorb_statement<Ch: flock_core::challenger::Challenger>(
    ch: &mut Ch,
    statement: &Blake2bStatement,
) {
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
        // test/rayon stacks never overflow.  `install` is synchronous, so
        // the closure borrows the caller's slice directly — no deep copy of
        // the statement messages before entering the pool.
        flock_pool().install(|| prove_statements_on_stack(statements))
    }

    fn verify_proof(&self, proof: &ArchivedHashProof) -> TexasAirResult<()> {
        let ArchivedHashProof::Flock(inner) = proof else {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "proof was not produced by the flock backend".into(),
            ));
        };
        verify_flock_archive(inner)
    }
}

/// Borrow-checked flock verify path.  Lets callers (e.g. `canonical_rake_opening`,
/// `canonical_state_hash`, `state_root_binding`) avoid the per-statement
/// `Vec<u8>` clone that the trait-object route would otherwise pay on the
/// `ArchivedFlockHashesProof` archive.
pub fn verify_flock_archive(inner: &ArchivedFlockHashesProof) -> TexasAirResult<()> {
    // Re-derive the segmentation from the covered statements; it must
    // reproduce the archived chain/merkle layout exactly.  Each sub-proof
    // verifies against its own Fiat–Shamir challenger seeded from the
    // domain plus its statement bytes, so the sub-proofs are mutually
    // independent and verify in parallel (each pays a fixed Ligerito
    // channel/FRI cost; see prove_statements_on_stack).  The result is
    // fail-closed in segment order regardless of scheduling: the first
    // failing segment by index is the reported error.
    flock_pool().install(|| {
        let segments = segment_statements(&inner.statements)?;
        let mut chains = inner.chains.iter();
        let mut merkles = inner.merkles.iter();
        let mut next_chain = || {
            chains.next().ok_or_else(|| {
                TexasAirError::ConstraintUnsatisfied(
                    "flock proof is missing a chain sub-proof".into(),
                )
            })
        };
        let mut next_merkle = || {
            merkles.next().ok_or_else(|| {
                TexasAirError::ConstraintUnsatisfied(
                    "flock proof is missing a merkle-path sub-proof".into(),
                )
            })
        };
        let statements = &inner.statements;
        // Pair each segment with its archived sub-proof (serial, keeps
        // the archive layout check identical), then verify in parallel.
        let mut jobs = Vec::with_capacity(segments.len());
        let mut i = 0usize;
        let mut seg_idx = 0usize;
        while i < statements.len() {
            let seg = &segments[seg_idx];
            match seg {
                Segment::Chain { start: _ } => {
                    let archived = next_chain()?;
                    if archived.index as usize != i {
                        return Err(TexasAirError::ConstraintUnsatisfied(
                            "flock chain sub-proof index does not match the statement order".into(),
                        ));
                    }
                    jobs.push(Job::Chain(&statements[i], archived));
                    i += 1;
                }
                Segment::Merkle { run } => {
                    let archived = next_merkle()?;
                    let run: &PathRun = run;
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
                    jobs.push(Job::Merkle(statements, run, archived));
                    i += run.len;
                }
            }
            seg_idx += 1;
        }
        if chains.next().is_some() || merkles.next().is_some() {
            return Err(TexasAirError::ConstraintUnsatisfied(
                "flock proof carries sub-proofs beyond the covered statements".into(),
            ));
        }
        let results: Vec<TexasAirResult<()>> = jobs
            .into_par_iter()
            .map(|job| match job {
                Job::Chain(statement, archived) => verify_chain_statement(statement, archived),
                Job::Merkle(statements, run, archived) => {
                    verify_merkle_run(statements, run, archived)
                }
            })
            .collect();
        results.into_iter().find(|r| r.is_err()).unwrap_or(Ok(()))
    })
}

static FLOCK_POOL: std::sync::OnceLock<rayon::ThreadPool> = std::sync::OnceLock::new();

/// Cached [`Blake3Setup`] per block count.  Building a setup runs the
/// one-time CSC fold-circuit build (a pass over ~21M nonzeros) plus prover
/// scratch prewarm; that cost is per `BlockR1cs` instance, so constructing a
/// fresh setup per sub-proof pays it once per statement on both prove and
/// verify.  All real bundles use n_blocks = 256 (chains are padded to
/// [`MIN_CHAIN_STEPS`], Merkle runs are depth-256), which hits the cache.
type SetupCache = std::collections::HashMap<usize, std::sync::Arc<Blake3Setup>>;

static SETUP_CACHE: std::sync::OnceLock<std::sync::Mutex<SetupCache>> = std::sync::OnceLock::new();

fn blake3_setup(n_blocks: usize) -> std::sync::Arc<Blake3Setup> {
    let cache = SETUP_CACHE.get_or_init(|| std::sync::Mutex::new(SetupCache::new()));
    {
        let guard = cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(setup) = guard.get(&n_blocks) {
            return std::sync::Arc::clone(setup);
        }
    }

    // The CSC circuit construction is intentionally outside the mutex: a cold
    // setup may be expensive, and unrelated block counts must not wait for it.
    let setup = std::sync::Arc::new(Blake3Setup::with_profile(
        n_blocks,
        flock_core::pcs::ligerito::LigeritoProfile::Slim,
    ));
    let mut guard = cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(existing) = guard.get(&n_blocks) {
        return std::sync::Arc::clone(existing);
    }
    guard.insert(n_blocks, std::sync::Arc::clone(&setup));
    setup
}

fn flock_pool() -> &'static rayon::ThreadPool {
    FLOCK_POOL.get_or_init(|| {
        rayon::ThreadPoolBuilder::new()
            .stack_size(64 * 1024 * 1024)
            .build()
            .expect("flock prover thread pool builds")
    })
}

/// The segmentation of an ordered statement list into sub-proof units: one
/// preimage chain per lone statement, one run per recognized Merkle path.
enum Segment {
    Chain { start: usize },
    Merkle { run: PathRun },
}

/// A sub-proof verify job: statement slice plus the archived sub-proof it
/// must authenticate against.
enum Job<'a> {
    Chain(&'a Blake2bStatement, &'a ArchivedFlockChain),
    Merkle(&'a [Blake2bStatement], &'a PathRun, &'a ArchivedFlockMerkle),
}

/// Split an ordered statement list into chain/merkle segments.  Pure
/// recognition (no proving), shared by prove and verify so the two sides
/// cannot drift apart.
fn segment_statements(statements: &[Blake2bStatement]) -> TexasAirResult<Vec<Segment>> {
    let mut segments = Vec::new();
    let mut i = 0usize;
    while i < statements.len() {
        if let Some(run) = recognize_path_run(statements, i) {
            i += run.len;
            segments.push(Segment::Merkle { run });
            continue;
        }
        segments.push(Segment::Chain { start: i });
        i += 1;
    }
    Ok(segments)
}

fn prove_statements_on_stack(statements: &[Blake2bStatement]) -> TexasAirResult<ArchivedHashProof> {
    // Every sub-proof runs its own Ligerito instance with an independent
    // Fiat–Shamir challenger (fresh transcript seeded from the domain plus
    // this statement's bytes), so the ~fixed per-instance cost
    // (channel/PoW/FRI) is paid once per sub-proof and the sub-proofs are
    // parallel-safe with no shared transcript ordering.  Prove them on the
    // dedicated flock pool: wall clock drops from `n_subproofs x fixed` to
    // ~`fixed` when cores are available.
    let segments = segment_statements(statements)?;
    enum Sub {
        Chain(ArchivedFlockChain),
        Merkle(ArchivedFlockMerkle),
    }
    let subs: Vec<TexasAirResult<Sub>> = segments
        .into_par_iter()
        .map(|seg| match seg {
            Segment::Chain { start } => {
                prove_chain_statement(&statements[start], start as u32).map(Sub::Chain)
            }
            Segment::Merkle { run } => prove_merkle_run(statements, &run).map(Sub::Merkle),
        })
        .collect();
    let mut chains = Vec::new();
    let mut merkles = Vec::new();
    for sub in subs {
        match sub? {
            Sub::Chain(c) => chains.push(c),
            Sub::Merkle(m) => merkles.push(m),
        }
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
    let (blocks, cv) = blake3_chain_blocks_with_cv(&statement.message);
    let cv_last = bytes32(&cv);
    if cv_last != statement.digest {
        return Err(TexasAirError::ConstraintUnsatisfied(
            "preimage statement digest does not match the blake3 chain".into(),
        ));
    }
    let setup = blake3_setup(blocks.len());
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
    let steps = chain_steps(statement.message.len());
    let bundle = unpack_chain(&archived.bundle)?;
    let setup = blake3_setup(steps);
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
    let setup = blake3_setup(nodes);
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
    let setup = blake3_setup(nodes);
    let b_bits = run.b_bits.as_slice();
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
        assert_eq!(
            blake3_chain_digest(&[7u8; 65]),
            blake3_chain_digest(&[7u8; 65])
        );
    }

    #[test]
    fn preimage_statements_prove_and_verify() {
        let statements = vec![
            Blake2bStatement::new(
                b"zchain.texas.rules.v2".to_vec(),
                blake3_chain_digest(b"zchain.texas.rules.v2"),
            ),
            Blake2bStatement::new(vec![9u8; 200], blake3_chain_digest(&[9u8; 200])),
        ];
        let proof = FlockProvider.prove_statements(&statements).expect("proof");
        FlockProvider
            .verify_statements(&proof, &statements)
            .expect("verify");

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
        FlockProvider
            .verify_statements(&proof, &statements)
            .expect("verify");
    }
}
