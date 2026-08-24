//! Transferable stage-4 host-verified outer-aggregate precompile.
//!
//! This module closes the safe non-recursive stage-4 path.  A package carries
//! the exact [`ProveTask`] values, the stage-4 [`OuterAggregateBundle`], and a
//! final Stwo proof binding a verifier-issued native receipt.  Verification:
//!
//! 1. compares the request's anchor with an independently authenticated anchor;
//! 2. replays and verifies every stage-3 child in O(N) time;
//! 3. checks the complete receipt chain against that anchor;
//! 4. recomputes full-width request, anchor, aggregate, and receipt digests; and
//! 5. verifies the final Stwo AIR that binds those exact digests.
//!
//! This is a circuit-facing precompile boundary, not recursive compression.
//! The verifier still performs O(N) native child verification before accepting
//! the final AIR proof.

use bincode::Options;
use blake2::Blake2bVar;
use blake2::digest::{Update, VariableOutput};
use borsh::BorshDeserialize;
use starknet_ff::FieldElement;
use stwo::core::channel::{Channel, Poseidon252Channel};
use stwo::core::fields::m31::M31;
use stwo::core::pcs::CommitmentSchemeVerifier;
use stwo::core::proof::StarkProof;
use stwo::core::vcs_lifted::poseidon252_merkle::{
    Poseidon252MerkleChannel, Poseidon252MerkleHasher,
};
use stwo::core::verifier::{VerificationError, verify};
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::pcs::CommitmentSchemeProver;
use stwo::prover::{ProvingError, prove};
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
};

use crate::dual_proof::MAX_STARK_PROOF_BYTES;
use crate::error::{TexasAirError, TexasAirResult};
use crate::outer_aggregate::{
    MAX_OUTER_AGGREGATE_BYTES, MAX_OUTER_CHILDREN, MIN_OUTER_CHILDREN, OuterAggregateBundle,
    VerifiedOuterAggregate, prove_outer_aggregate, verify_outer_aggregate,
};
use crate::precompile_binding::{DIGEST_LIMBS, digest_to_m31_limbs};
use crate::prove_task::ProveTask;
use crate::state_root::StateRoot;
use crate::trace_gen::generic_trace::{SINGLE_METHOD_LOG_SIZE, gen_method_trace};
use crate::verified_chain::ExpectedChainAnchor;

/// Wire magic for the canonical outer-precompile request.
pub const OUTER_PRECOMPILE_REQUEST_MAGIC: [u8; 8] = *b"ZPOPRE04";
/// Wire magic for the transferable outer-precompile proof package.
pub const OUTER_PRECOMPILE_PROOF_MAGIC: [u8; 8] = *b"ZPOPRF04";
/// Wire magic for the canonical authenticated range encoding.
pub const OUTER_PRECOMPILE_ANCHOR_MAGIC: [u8; 8] = *b"ZPANCH01";
/// Current request and proof-envelope ABI version.
pub const OUTER_PRECOMPILE_ABI_VERSION: u8 = 1;
/// Circuit-visible selector for host-verified outer aggregation.
pub const OUTER_PRECOMPILE_ID: u8 = 4;
/// Native backend identity for O(N) VM/crypto/Stwo child replay.
pub const OUTER_PRECOMPILE_BACKEND_ID: u8 = 1;
/// Maximum canonical Borsh size accepted for one task.
pub const MAX_OUTER_TASK_BYTES: usize = 16 * 1024 * 1024;
/// Maximum total encoded outer-precompile request size.
pub const MAX_OUTER_PRECOMPILE_REQUEST_BYTES: usize = 512 * 1024 * 1024;
/// Maximum total encoded proof package size.
pub const MAX_OUTER_PRECOMPILE_PROOF_BYTES: usize =
    MAX_OUTER_PRECOMPILE_REQUEST_BYTES + MAX_STARK_PROOF_BYTES + 24;

const REQUEST_HEADER_LEN: usize = 24;
const PACKAGE_HEADER_LEN: usize = 20;
const ANCHOR_HEADER_LEN: usize = 112;

/// Canonical request replayed by the outer-aggregate native precompile.
#[derive(Debug, Clone)]
pub struct OuterAggregatePrecompileRequest {
    tasks: Vec<ProveTask>,
    bundle: OuterAggregateBundle,
    anchor: ExpectedChainAnchor,
}

impl OuterAggregatePrecompileRequest {
    /// Construct a request. Cryptographic and chain verification is performed
    /// by [`verify_outer_precompile_request`].
    #[must_use]
    pub fn new(
        tasks: Vec<ProveTask>,
        bundle: OuterAggregateBundle,
        anchor: ExpectedChainAnchor,
    ) -> Self {
        Self {
            tasks,
            bundle,
            anchor,
        }
    }

    /// Ordered trusted-task candidates carried for independent VM replay.
    #[must_use]
    pub fn tasks(&self) -> &[ProveTask] {
        &self.tasks
    }

    /// Stage-4 aggregate bundle carried by the request.
    #[must_use]
    pub const fn bundle(&self) -> &OuterAggregateBundle {
        &self.bundle
    }

    /// Anchor claimed by the request. It is not trusted until compared with an
    /// independently authenticated expected anchor.
    #[must_use]
    pub const fn anchor(&self) -> &ExpectedChainAnchor {
        &self.anchor
    }

    /// Encode the request with strict length-prefixed canonical components.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid counts, oversized components, or encoding
    /// failure.
    pub fn encode(&self) -> TexasAirResult<Vec<u8>> {
        encode_request(&self.tasks, &self.bundle, &self.anchor)
    }

    /// Strictly decode a canonical request.
    ///
    /// # Errors
    ///
    /// Rejects unknown versions or flags, invalid lengths, malformed tasks,
    /// count mismatches, and trailing bytes.
    pub fn decode(bytes: &[u8]) -> TexasAirResult<Self> {
        if bytes.len() < REQUEST_HEADER_LEN {
            return Err(wire_error("outer precompile request header is truncated"));
        }
        if bytes.len() > MAX_OUTER_PRECOMPILE_REQUEST_BYTES {
            return Err(wire_error(
                "outer precompile request exceeds total size limit",
            ));
        }
        if bytes[..8] != OUTER_PRECOMPILE_REQUEST_MAGIC {
            return Err(wire_error("outer precompile request magic mismatch"));
        }
        if bytes[8] != OUTER_PRECOMPILE_ABI_VERSION {
            return Err(wire_error(format!(
                "unsupported outer precompile request version {}",
                bytes[8]
            )));
        }
        if bytes[9] != 0 || bytes[10..12] != [0, 0] {
            return Err(wire_error(
                "outer precompile request flags/reserved are non-zero",
            ));
        }
        let task_count = read_u32(bytes, 12)? as usize;
        validate_task_count(task_count)?;
        let anchor_len = read_u32(bytes, 16)? as usize;
        let bundle_len = read_u32(bytes, 20)? as usize;
        if anchor_len < ANCHOR_HEADER_LEN
            || bundle_len == 0
            || bundle_len > MAX_OUTER_AGGREGATE_BYTES
        {
            return Err(wire_error("outer precompile component length is invalid"));
        }
        let anchor_end = REQUEST_HEADER_LEN
            .checked_add(anchor_len)
            .ok_or_else(|| wire_error("outer anchor end overflow"))?;
        let bundle_end = anchor_end
            .checked_add(bundle_len)
            .ok_or_else(|| wire_error("outer bundle end overflow"))?;
        if bundle_end > bytes.len() {
            return Err(wire_error("outer precompile fixed payload is truncated"));
        }
        let anchor = decode_anchor(&bytes[REQUEST_HEADER_LEN..anchor_end])?;
        let bundle = OuterAggregateBundle::decode(&bytes[anchor_end..bundle_end])?;
        if bundle.children().len() != task_count {
            return Err(wire_error("outer precompile task/child count mismatch"));
        }

        let mut cursor = bundle_end;
        let mut tasks = Vec::with_capacity(task_count);
        for index in 0..task_count {
            let len_end = cursor
                .checked_add(4)
                .ok_or_else(|| wire_error("outer task length offset overflow"))?;
            if len_end > bytes.len() {
                return Err(wire_error(format!(
                    "outer task {index} length is truncated"
                )));
            }
            let task_len = u32::from_le_bytes(
                bytes[cursor..len_end]
                    .try_into()
                    .expect("fixed task length slice"),
            ) as usize;
            if task_len == 0 || task_len > MAX_OUTER_TASK_BYTES {
                return Err(wire_error(format!("outer task {index} length is invalid")));
            }
            let task_end = len_end
                .checked_add(task_len)
                .ok_or_else(|| wire_error("outer task end overflow"))?;
            if task_end > bytes.len() {
                return Err(wire_error(format!(
                    "outer task {index} payload is truncated"
                )));
            }
            let task = ProveTask::try_from_slice(&bytes[len_end..task_end])
                .map_err(|error| wire_error(format!("outer task {index} borsh decode: {error}")))?;
            tasks.push(task);
            cursor = task_end;
        }
        if cursor != bytes.len() {
            return Err(wire_error(
                "outer precompile request contains trailing bytes",
            ));
        }
        Ok(Self {
            tasks,
            bundle,
            anchor,
        })
    }
}

/// Full-width AIR projection of an accepted outer-precompile call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OuterAggregateAirBinding {
    /// Precompile selector.
    pub precompile_id: u8,
    /// Request ABI version.
    pub abi_version: u8,
    /// Native verification backend identity.
    pub backend_id: u8,
    /// Exact number of verified stage-3 children.
    pub child_count: u32,
    /// Full aggregate semantic digest.
    pub aggregate_digest: [M31; DIGEST_LIMBS],
    /// Full canonical authenticated-anchor digest.
    pub anchor_digest: [M31; DIGEST_LIMBS],
    /// Full canonical request digest.
    pub request_digest: [M31; DIGEST_LIMBS],
    /// Full verifier-issued receipt digest.
    pub receipt_digest: [M31; DIGEST_LIMBS],
}

/// Native-verifier binding for an accepted outer-precompile request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OuterAggregateCallBinding {
    request_digest: [u8; 32],
    aggregate_digest: [u8; 32],
    anchor_digest: [u8; 32],
    receipt_digest: [u8; 32],
    child_count: u32,
}

impl OuterAggregateCallBinding {
    /// Full request digest.
    #[must_use]
    pub const fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }

    /// Full aggregate semantic digest.
    #[must_use]
    pub const fn aggregate_digest(&self) -> [u8; 32] {
        self.aggregate_digest
    }

    /// Full canonical anchor digest.
    #[must_use]
    pub const fn anchor_digest(&self) -> [u8; 32] {
        self.anchor_digest
    }

    /// Full verifier-issued receipt digest.
    #[must_use]
    pub const fn receipt_digest(&self) -> [u8; 32] {
        self.receipt_digest
    }

    /// Number of child packages independently verified by the native backend.
    #[must_use]
    pub const fn child_count(&self) -> u32 {
        self.child_count
    }

    /// Convert every 256-bit digest into exact sixteen-u16 AIR limbs.
    #[must_use]
    pub fn air_binding(&self) -> OuterAggregateAirBinding {
        OuterAggregateAirBinding {
            precompile_id: OUTER_PRECOMPILE_ID,
            abi_version: OUTER_PRECOMPILE_ABI_VERSION,
            backend_id: OUTER_PRECOMPILE_BACKEND_ID,
            child_count: self.child_count,
            aggregate_digest: digest_to_m31_limbs(self.aggregate_digest),
            anchor_digest: digest_to_m31_limbs(self.anchor_digest),
            request_digest: digest_to_m31_limbs(self.request_digest),
            receipt_digest: digest_to_m31_limbs(self.receipt_digest),
        }
    }
}

/// Result of native verification before the final AIR is checked.
#[derive(Debug, Clone)]
pub struct VerifiedOuterAggregateCall {
    verified_aggregate: VerifiedOuterAggregate,
    binding: OuterAggregateCallBinding,
}

impl VerifiedOuterAggregateCall {
    /// Verified child receipt chain and semantic aggregate digest.
    #[must_use]
    pub const fn verified_aggregate(&self) -> &VerifiedOuterAggregate {
        &self.verified_aggregate
    }

    /// Verifier-issued precompile binding.
    #[must_use]
    pub const fn binding(&self) -> &OuterAggregateCallBinding {
        &self.binding
    }
}

/// Verify the complete request with the native O(N) backend.
///
/// `expected_anchor` must come from authenticated consensus material. The
/// request-carried copy is compared byte-for-byte before it is used.
///
/// # Errors
///
/// Returns an error for anchor substitution, any invalid child proof or crypto
/// request, chain discontinuity, or digest/metadata mismatch.
pub fn verify_outer_precompile_request(
    request: &OuterAggregatePrecompileRequest,
    expected_anchor: &ExpectedChainAnchor,
) -> TexasAirResult<VerifiedOuterAggregateCall> {
    let carried_anchor = encode_anchor(&request.anchor)?;
    let expected_anchor_bytes = encode_anchor(expected_anchor)?;
    if carried_anchor != expected_anchor_bytes {
        return Err(TexasAirError::RecursionError(
            "outer precompile request anchor differs from authenticated anchor".into(),
        ));
    }
    let verified_aggregate = verify_outer_aggregate(&request.tasks, &request.bundle)?;
    verified_aggregate.verify_against_anchor(expected_anchor)?;

    let request_bytes = request.encode()?;
    let binding = outer_call_binding(
        verified_aggregate.aggregate_digest(),
        &carried_anchor,
        &request_bytes,
        request.tasks.len(),
    )?;
    Ok(VerifiedOuterAggregateCall {
        verified_aggregate,
        binding,
    })
}

/// Canonical request encoding shared by the request object and the prove path.
///
/// Produces byte-identical output to [`OuterAggregatePrecompileRequest::encode`]
/// without requiring an owned copy of the tasks.
///
/// # Errors
///
/// Returns an error for invalid counts, oversized components, or encoding
/// failure.
fn encode_request(
    tasks: &[ProveTask],
    bundle: &OuterAggregateBundle,
    anchor: &ExpectedChainAnchor,
) -> TexasAirResult<Vec<u8>> {
    validate_task_count(tasks.len())?;
    if tasks.len() != bundle.children().len() {
        return Err(wire_error("outer precompile task/child count mismatch"));
    }
    let anchor_bytes = encode_anchor(anchor)?;
    let bundle_bytes = bundle.encode()?;
    if bundle_bytes.len() > MAX_OUTER_AGGREGATE_BYTES {
        return Err(wire_error("outer aggregate exceeds request limit"));
    }
    let mut task_bytes = Vec::with_capacity(tasks.len());
    let mut total_len = REQUEST_HEADER_LEN
        .checked_add(anchor_bytes.len())
        .and_then(|value| value.checked_add(bundle_bytes.len()))
        .ok_or_else(|| wire_error("outer precompile request length overflow"))?;
    for task in tasks {
        let encoded = borsh::to_vec(task)
            .map_err(|error| wire_error(format!("outer task borsh encode: {error}")))?;
        if encoded.is_empty() || encoded.len() > MAX_OUTER_TASK_BYTES {
            return Err(wire_error("outer task size is outside the accepted range"));
        }
        total_len = total_len
            .checked_add(4)
            .and_then(|value| value.checked_add(encoded.len()))
            .ok_or_else(|| wire_error("outer precompile task length overflow"))?;
        task_bytes.push(encoded);
    }
    if total_len > MAX_OUTER_PRECOMPILE_REQUEST_BYTES {
        return Err(wire_error(
            "outer precompile request exceeds total size limit",
        ));
    }

    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(&OUTER_PRECOMPILE_REQUEST_MAGIC);
    out.extend_from_slice(&[OUTER_PRECOMPILE_ABI_VERSION, 0]);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(tasks.len() as u32).to_le_bytes());
    out.extend_from_slice(&(anchor_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&(bundle_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&anchor_bytes);
    out.extend_from_slice(&bundle_bytes);
    for task in task_bytes {
        out.extend_from_slice(&(task.len() as u32).to_le_bytes());
        out.extend_from_slice(&task);
    }
    debug_assert_eq!(out.len(), total_len);
    Ok(out)
}

/// Derive the native precompile binding from accepted verification material.
///
/// `anchor_bytes` must be the canonical encoding of the accepted anchor and
/// `request_bytes` the canonical encoding of the accepted request, so digest
/// inputs are identical to [`verify_outer_precompile_request`].
///
/// # Errors
///
/// Returns an error if the child count exceeds u32.
fn outer_call_binding(
    aggregate_digest: [u8; 32],
    anchor_bytes: &[u8],
    request_bytes: &[u8],
    child_count: usize,
) -> TexasAirResult<OuterAggregateCallBinding> {
    let child_count = u32::try_from(child_count)
        .map_err(|_| wire_error("outer precompile child count exceeds u32"))?;
    let request_digest = hash256(b"zchain.poker.outer_precompile.request.v1", request_bytes);
    let anchor_digest = hash256(b"zchain.poker.outer_precompile.anchor.v1", anchor_bytes);
    let mut receipt = Vec::with_capacity(4 + 4 + 32 * 3);
    receipt.extend_from_slice(&[
        OUTER_PRECOMPILE_ID,
        OUTER_PRECOMPILE_ABI_VERSION,
        OUTER_PRECOMPILE_BACKEND_ID,
        1,
    ]);
    receipt.extend_from_slice(&child_count.to_le_bytes());
    receipt.extend_from_slice(&request_digest);
    receipt.extend_from_slice(&aggregate_digest);
    receipt.extend_from_slice(&anchor_digest);
    let receipt_digest = hash256(b"zchain.poker.outer_precompile.receipt.v1", &receipt);
    Ok(OuterAggregateCallBinding {
        request_digest,
        aggregate_digest,
        anchor_digest,
        receipt_digest,
        child_count,
    })
}

/// Column layout for the final outer-precompile AIR.
pub mod cols {
    use super::DIGEST_LIMBS;

    /// Precompile selector column.
    pub const PRECOMPILE_ID: usize = 0;
    /// ABI version column.
    pub const ABI_VERSION: usize = 1;
    /// Native backend identity column.
    pub const BACKEND_ID: usize = 2;
    /// Exact child-count column.
    pub const CHILD_COUNT: usize = 3;
    /// Aggregate digest base column.
    pub const AGGREGATE_DIGEST_BASE: usize = 4;
    /// Anchor digest base column.
    pub const ANCHOR_DIGEST_BASE: usize = AGGREGATE_DIGEST_BASE + DIGEST_LIMBS;
    /// Request digest base column.
    pub const REQUEST_DIGEST_BASE: usize = ANCHOR_DIGEST_BASE + DIGEST_LIMBS;
    /// Receipt digest base column.
    pub const RECEIPT_DIGEST_BASE: usize = REQUEST_DIGEST_BASE + DIGEST_LIMBS;
    /// Total original-trace column count.
    pub const NUM_COLUMNS: usize = RECEIPT_DIGEST_BASE + DIGEST_LIMBS;
}

/// Final AIR statement binding an accepted host-verified aggregate call.
#[derive(Debug, Clone)]
pub struct OuterAggregatePrecompileAir {
    /// Trace log size.
    pub log_size: u32,
    /// Verifier-issued full-width binding.
    pub binding: OuterAggregateAirBinding,
}

impl OuterAggregatePrecompileAir {
    /// Number of original-trace columns.
    #[must_use]
    pub const fn num_columns() -> usize {
        cols::NUM_COLUMNS
    }

    fn mix_into<C: Channel>(&self, channel: &mut C) {
        channel.mix_u32s(&[
            0x5a50_4f34,
            self.binding.precompile_id.into(),
            self.binding.abi_version.into(),
            self.binding.backend_id.into(),
            self.binding.child_count,
        ]);
        for digest in [
            self.binding.aggregate_digest,
            self.binding.anchor_digest,
            self.binding.request_digest,
            self.binding.receipt_digest,
        ] {
            channel.mix_u32s(&digest.map(|limb| limb.0));
        }
    }
}

impl FrameworkEval for OuterAggregatePrecompileAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let precompile_id = eval.next_trace_mask();
        let abi_version = eval.next_trace_mask();
        let backend_id = eval.next_trace_mask();
        let child_count = eval.next_trace_mask();
        let aggregate_digest: Vec<_> = (0..DIGEST_LIMBS).map(|_| eval.next_trace_mask()).collect();
        let anchor_digest: Vec<_> = (0..DIGEST_LIMBS).map(|_| eval.next_trace_mask()).collect();
        let request_digest: Vec<_> = (0..DIGEST_LIMBS).map(|_| eval.next_trace_mask()).collect();
        let receipt_digest: Vec<_> = (0..DIGEST_LIMBS).map(|_| eval.next_trace_mask()).collect();

        let expected_precompile: E::F = M31::from(u32::from(self.binding.precompile_id)).into();
        let expected_abi: E::F = M31::from(u32::from(self.binding.abi_version)).into();
        let expected_backend: E::F = M31::from(u32::from(self.binding.backend_id)).into();
        let expected_count: E::F = M31::from(self.binding.child_count).into();
        eval.add_constraint(precompile_id - expected_precompile);
        eval.add_constraint(abi_version - expected_abi);
        eval.add_constraint(backend_id - expected_backend);
        eval.add_constraint(child_count - expected_count);
        for i in 0..DIGEST_LIMBS {
            let expected_aggregate: E::F = self.binding.aggregate_digest[i].into();
            let expected_anchor: E::F = self.binding.anchor_digest[i].into();
            let expected_request: E::F = self.binding.request_digest[i].into();
            let expected_receipt: E::F = self.binding.receipt_digest[i].into();
            eval.add_constraint(aggregate_digest[i].clone() - expected_aggregate);
            eval.add_constraint(anchor_digest[i].clone() - expected_anchor);
            eval.add_constraint(request_digest[i].clone() - expected_request);
            eval.add_constraint(receipt_digest[i].clone() - expected_receipt);
        }
        eval
    }
}

/// Canonical trace row for [`OuterAggregatePrecompileAir`].
#[derive(Debug, Clone)]
pub struct OuterAggregatePrecompileRow {
    values: Vec<M31>,
}

impl OuterAggregatePrecompileRow {
    /// Construct the unique verifier-bound row from a native receipt.
    #[must_use]
    pub fn new(binding: &OuterAggregateAirBinding) -> Self {
        let mut values = Vec::with_capacity(cols::NUM_COLUMNS);
        values.push(M31::from(u32::from(binding.precompile_id)));
        values.push(M31::from(u32::from(binding.abi_version)));
        values.push(M31::from(u32::from(binding.backend_id)));
        values.push(M31::from(binding.child_count));
        values.extend_from_slice(&binding.aggregate_digest);
        values.extend_from_slice(&binding.anchor_digest);
        values.extend_from_slice(&binding.request_digest);
        values.extend_from_slice(&binding.receipt_digest);
        debug_assert_eq!(values.len(), cols::NUM_COLUMNS);
        Self { values }
    }

    /// Row values in trace-column order.
    #[must_use]
    pub fn to_vec(&self) -> Vec<M31> {
        self.values.clone()
    }
}

/// Transferable package containing the canonical request and final AIR proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostVerifiedOuterAggregateProof {
    request_bytes: Vec<u8>,
    stark_proof_bytes: Vec<u8>,
}

impl HostVerifiedOuterAggregateProof {
    /// Canonical outer-precompile request bytes.
    #[must_use]
    pub fn request_bytes(&self) -> &[u8] {
        &self.request_bytes
    }

    /// Serialized final Stwo proof bytes.
    #[must_use]
    pub fn stark_proof_bytes(&self) -> &[u8] {
        &self.stark_proof_bytes
    }

    /// Encode the proof package with strict fixed-width lengths.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty or oversized component.
    pub fn encode(&self) -> TexasAirResult<Vec<u8>> {
        validate_package_lengths(self.request_bytes.len(), self.stark_proof_bytes.len())?;
        let mut out = Vec::with_capacity(
            PACKAGE_HEADER_LEN + self.request_bytes.len() + self.stark_proof_bytes.len(),
        );
        out.extend_from_slice(&OUTER_PRECOMPILE_PROOF_MAGIC);
        out.extend_from_slice(&[OUTER_PRECOMPILE_ABI_VERSION, 0]);
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(self.request_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.stark_proof_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.request_bytes);
        out.extend_from_slice(&self.stark_proof_bytes);
        Ok(out)
    }

    /// Strictly decode a proof package.
    ///
    /// # Errors
    ///
    /// Rejects unknown versions/flags, invalid sizes, truncation, malformed
    /// requests, and trailing data.
    pub fn decode(bytes: &[u8]) -> TexasAirResult<Self> {
        if bytes.len() < PACKAGE_HEADER_LEN || bytes.len() > MAX_OUTER_PRECOMPILE_PROOF_BYTES {
            return Err(wire_error("outer precompile proof package size is invalid"));
        }
        if bytes[..8] != OUTER_PRECOMPILE_PROOF_MAGIC {
            return Err(wire_error("outer precompile proof magic mismatch"));
        }
        if bytes[8] != OUTER_PRECOMPILE_ABI_VERSION {
            return Err(wire_error("unsupported outer precompile proof version"));
        }
        if bytes[9] != 0 || bytes[10..12] != [0, 0] {
            return Err(wire_error(
                "outer precompile proof flags/reserved are non-zero",
            ));
        }
        let request_len = read_u32(bytes, 12)? as usize;
        let proof_len = read_u32(bytes, 16)? as usize;
        validate_package_lengths(request_len, proof_len)?;
        let expected_len = PACKAGE_HEADER_LEN
            .checked_add(request_len)
            .and_then(|value| value.checked_add(proof_len))
            .ok_or_else(|| wire_error("outer precompile proof length overflow"))?;
        if expected_len != bytes.len() {
            return Err(wire_error("outer precompile proof length mismatch"));
        }
        let request_end = PACKAGE_HEADER_LEN + request_len;
        let request_bytes = bytes[PACKAGE_HEADER_LEN..request_end].to_vec();
        let _ = OuterAggregatePrecompileRequest::decode(&request_bytes)?;
        Ok(Self {
            request_bytes,
            stark_proof_bytes: bytes[request_end..].to_vec(),
        })
    }
}

/// Acceptance artifact issued only after native O(N) replay and final AIR
/// verification both succeed.
#[derive(Debug, Clone)]
pub struct VerifiedHostOuterAggregateProof {
    binding: OuterAggregateCallBinding,
    table_id: u64,
    hand_id: u32,
    first_call_seq: u32,
    child_count: u32,
    pre_state_root: StateRoot,
    post_state_root: StateRoot,
    pre_version: u64,
    post_version: u64,
}

impl VerifiedHostOuterAggregateProof {
    /// Native precompile binding accepted by the final AIR.
    #[must_use]
    pub const fn binding(&self) -> &OuterAggregateCallBinding {
        &self.binding
    }

    /// Table identifier authenticated by the external anchor.
    #[must_use]
    pub const fn table_id(&self) -> u64 {
        self.table_id
    }

    /// Hand identifier authenticated by the external anchor.
    #[must_use]
    pub const fn hand_id(&self) -> u32 {
        self.hand_id
    }

    /// First call sequence in the accepted range.
    #[must_use]
    pub const fn first_call_seq(&self) -> u32 {
        self.first_call_seq
    }

    /// Number of accepted child calls.
    #[must_use]
    pub const fn child_count(&self) -> u32 {
        self.child_count
    }

    /// Anchored range-start state root.
    #[must_use]
    pub const fn pre_state_root(&self) -> StateRoot {
        self.pre_state_root
    }

    /// Anchored range-end state root.
    #[must_use]
    pub const fn post_state_root(&self) -> StateRoot {
        self.post_state_root
    }

    /// Anchored range-start state version.
    #[must_use]
    pub const fn pre_version(&self) -> u64 {
        self.pre_version
    }

    /// Anchored range-end state version.
    #[must_use]
    pub const fn post_version(&self) -> u64 {
        self.post_version
    }
}

/// Generate child dual proofs, aggregate them, and issue the final precompile
/// package.
///
/// # Errors
///
/// Returns an error if child proving, native re-verification, anchor checking,
/// final AIR proving, or serialization fails.
pub fn prove_host_verified_outer_aggregate(
    tasks: &[ProveTask],
    anchor: &ExpectedChainAnchor,
) -> TexasAirResult<HostVerifiedOuterAggregateProof> {
    let bundle = prove_outer_aggregate(tasks)?;
    prove_host_verified_outer_aggregate_from_bundle(tasks, bundle, anchor)
}

/// Issue the final precompile package from an existing stage-4 bundle.
///
/// # Errors
///
/// Returns an error unless the supplied bundle independently verifies against
/// every task and the authenticated anchor.
pub fn prove_host_verified_outer_aggregate_from_bundle(
    tasks: &[ProveTask],
    bundle: OuterAggregateBundle,
    anchor: &ExpectedChainAnchor,
) -> TexasAirResult<HostVerifiedOuterAggregateProof> {
    // The bundle is an externally supplied in-memory object of unknown
    // provenance, so full O(N) child verification is a required trust boundary
    // and is intentionally kept. Only redundant canonical re-encodings of
    // already in-memory material are avoided: the request bytes are encoded
    // once and reused for both the request digest and the package payload,
    // without deep-copying the tasks or round-tripping the anchor.
    let verified = verify_outer_aggregate(tasks, &bundle)?;
    verified.verify_against_anchor(anchor)?;
    let anchor_bytes = encode_anchor(anchor)?;
    let request_bytes = encode_request(tasks, &bundle, anchor)?;
    let binding = outer_call_binding(
        verified.aggregate_digest(),
        &anchor_bytes,
        &request_bytes,
        tasks.len(),
    )?;
    let air = OuterAggregatePrecompileAir {
        log_size: SINGLE_METHOD_LOG_SIZE,
        binding: binding.air_binding(),
    };
    let row = OuterAggregatePrecompileRow::new(&air.binding).to_vec();
    let trace = gen_method_trace(cols::NUM_COLUMNS, &row, &row)?;
    let stark_proof = prove_outer_air(&trace, &air)?;
    let stark_proof_bytes = bincode_options()
        .serialize(&stark_proof)
        .map_err(|error| wire_error(format!("outer AIR proof serialization: {error}")))?;
    // Enforce the same transport size bounds as `encode` without re-copying
    // the request bytes into another full package buffer.
    validate_package_lengths(request_bytes.len(), stark_proof_bytes.len())?;
    Ok(HostVerifiedOuterAggregateProof {
        request_bytes,
        stark_proof_bytes,
    })
}

/// Verify the complete transferable stage-4 precompile package.
///
/// The caller must supply an independently authenticated anchor. Verification
/// remains O(N) because every child VM transition, poker proof, and Stwo method
/// proof is replayed before the final AIR proof is accepted.
///
/// # Errors
///
/// Returns an error for any malformed field, substituted anchor/request,
/// invalid child, discontinuous chain, receipt mismatch, or invalid final AIR.
pub fn verify_host_verified_outer_aggregate(
    package: &HostVerifiedOuterAggregateProof,
    expected_anchor: &ExpectedChainAnchor,
) -> TexasAirResult<VerifiedHostOuterAggregateProof> {
    validate_package_lengths(package.request_bytes.len(), package.stark_proof_bytes.len())?;
    let request = OuterAggregatePrecompileRequest::decode(&package.request_bytes)?;
    let verified = verify_outer_precompile_request(&request, expected_anchor)?;
    let air = OuterAggregatePrecompileAir {
        log_size: SINGLE_METHOD_LOG_SIZE,
        binding: verified.binding.air_binding(),
    };
    let stark_proof = decode_stark(&package.stark_proof_bytes)?;
    verify_outer_air(stark_proof, &air)?;
    Ok(VerifiedHostOuterAggregateProof {
        binding: verified.binding,
        table_id: expected_anchor.table_id(),
        hand_id: expected_anchor.hand_id(),
        first_call_seq: expected_anchor.first_call_seq(),
        child_count: u32::try_from(expected_anchor.dispatch_call_digests().len())
            .map_err(|_| wire_error("outer anchor child count exceeds u32"))?,
        pre_state_root: expected_anchor.pre_state_root(),
        post_state_root: expected_anchor.post_state_root(),
        pre_version: expected_anchor.pre_version(),
        post_version: expected_anchor.post_version(),
    })
}

fn prove_outer_air(
    trace: &crate::trace_gen::MethodTrace,
    air: &OuterAggregatePrecompileAir,
) -> TexasAirResult<StarkProof<Poseidon252MerkleHasher>> {
    let config = crate::prover_context::protocol_pcs_config();
    let twiddles =
        crate::prover_context::simd_twiddles(trace.log_size + config.fri_config.log_blowup_factor);
    let mut channel = Poseidon252Channel::default();
    air.mix_into(&mut channel);
    let mut commitment_scheme =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::with_memory_pool(
            config,
            &twiddles,
            crate::prover_context::simd_base_column_pool(),
        );
    {
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(vec![]);
        tree_builder.commit(&mut channel);
    }
    {
        let mut tree_builder = commitment_scheme.tree_builder();
        tree_builder.extend_evals(trace.to_evaluations());
        tree_builder.commit(&mut channel);
    }
    let mut allocator = TraceLocationAllocator::default();
    let component = FrameworkComponent::new(
        &mut allocator,
        air.clone(),
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    prove(&[&component], &mut channel, commitment_scheme)
        .map_err(|error: ProvingError| TexasAirError::StwoProverError(error.to_string()))
}

fn verify_outer_air(
    stark_proof: StarkProof<Poseidon252MerkleHasher>,
    air: &OuterAggregatePrecompileAir,
) -> TexasAirResult<()> {
    let config = crate::prover_context::protocol_pcs_config();
    let mut channel = Poseidon252Channel::default();
    air.mix_into(&mut channel);
    let mut commitment_scheme = CommitmentSchemeVerifier::<Poseidon252MerkleChannel>::new(config);
    let preprocessed_commitment = *stark_proof.commitments.first().ok_or_else(|| {
        TexasAirError::StwoProverError("outer AIR proof misses preprocessed commitment".into())
    })?;
    commitment_scheme.commit(preprocessed_commitment, &[], &mut channel);
    let trace_commitment = *stark_proof.commitments.get(1).ok_or_else(|| {
        TexasAirError::StwoProverError("outer AIR proof misses trace commitment".into())
    })?;
    commitment_scheme.commit(
        trace_commitment,
        &vec![air.log_size; cols::NUM_COLUMNS],
        &mut channel,
    );
    let mut allocator = TraceLocationAllocator::default();
    let component = FrameworkComponent::new(
        &mut allocator,
        air.clone(),
        stwo::core::fields::qm31::SecureField::from(0u32),
    );
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verify(
            &[&component],
            &mut channel,
            &mut commitment_scheme,
            stark_proof,
        )
    }))
    .map_err(|_| {
        TexasAirError::ConstraintUnsatisfied(
            "malformed outer AIR proof caused the backend verifier to abort".into(),
        )
    })?
    .map_err(|error: VerificationError| TexasAirError::ConstraintUnsatisfied(error.to_string()))
}

fn encode_anchor(anchor: &ExpectedChainAnchor) -> TexasAirResult<Vec<u8>> {
    let count = u32::try_from(anchor.dispatch_call_digests().len())
        .map_err(|_| wire_error("outer anchor digest count exceeds u32"))?;
    if count == 0 {
        return Err(wire_error("outer anchor must not be empty"));
    }
    let mut out = Vec::with_capacity(ANCHOR_HEADER_LEN + count as usize * 32);
    out.extend_from_slice(&OUTER_PRECOMPILE_ANCHOR_MAGIC);
    out.extend_from_slice(&[OUTER_PRECOMPILE_ABI_VERSION, 0]);
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&anchor.table_id().to_le_bytes());
    out.extend_from_slice(&anchor.hand_id().to_le_bytes());
    out.extend_from_slice(&anchor.first_call_seq().to_le_bytes());
    out.extend_from_slice(&anchor.pre_version().to_le_bytes());
    out.extend_from_slice(&anchor.post_version().to_le_bytes());
    out.extend_from_slice(&anchor.pre_state_root().bytes());
    out.extend_from_slice(&anchor.post_state_root().bytes());
    debug_assert_eq!(out.len(), ANCHOR_HEADER_LEN);
    for digest in anchor.dispatch_call_digests() {
        out.extend_from_slice(digest);
    }
    Ok(out)
}

fn decode_anchor(bytes: &[u8]) -> TexasAirResult<ExpectedChainAnchor> {
    if bytes.len() < ANCHOR_HEADER_LEN || bytes[..8] != OUTER_PRECOMPILE_ANCHOR_MAGIC {
        return Err(wire_error("outer anchor header or magic is invalid"));
    }
    if bytes[8] != OUTER_PRECOMPILE_ABI_VERSION || bytes[9] != 0 || bytes[10..12] != [0, 0] {
        return Err(wire_error(
            "outer anchor version/flags/reserved are invalid",
        ));
    }
    let count = read_u32(bytes, 12)? as usize;
    validate_task_count(count)?;
    let expected_len = ANCHOR_HEADER_LEN
        .checked_add(
            count
                .checked_mul(32)
                .ok_or_else(|| wire_error("anchor length overflow"))?,
        )
        .ok_or_else(|| wire_error("anchor length overflow"))?;
    if bytes.len() != expected_len {
        return Err(wire_error("outer anchor length mismatch"));
    }
    let table_id = read_u64(bytes, 16)?;
    let hand_id = read_u32(bytes, 24)?;
    let first_call_seq = read_u32(bytes, 28)?;
    let pre_version = read_u64(bytes, 32)?;
    let post_version = read_u64(bytes, 40)?;
    let pre_state_root = decode_root(&bytes[48..80])?;
    let post_state_root = decode_root(&bytes[80..112])?;
    let dispatch_call_digests = bytes[112..]
        .chunks_exact(32)
        .map(|chunk| chunk.try_into().expect("fixed digest chunk"))
        .collect();
    ExpectedChainAnchor::new(
        table_id,
        hand_id,
        first_call_seq,
        pre_state_root,
        post_state_root,
        pre_version,
        post_version,
        dispatch_call_digests,
    )
}

fn decode_root(bytes: &[u8]) -> TexasAirResult<StateRoot> {
    let root_bytes: &[u8; 32] = bytes
        .try_into()
        .map_err(|_| wire_error("state root must contain 32 bytes"))?;
    Ok(StateRoot::from_bytes(*root_bytes))
}

fn validate_task_count(count: usize) -> TexasAirResult<()> {
    if !(MIN_OUTER_CHILDREN..=MAX_OUTER_CHILDREN).contains(&count) {
        return Err(wire_error(format!(
            "outer precompile task count {count} is outside {MIN_OUTER_CHILDREN}..={MAX_OUTER_CHILDREN}"
        )));
    }
    Ok(())
}

fn validate_package_lengths(request_len: usize, proof_len: usize) -> TexasAirResult<()> {
    if request_len == 0 || request_len > MAX_OUTER_PRECOMPILE_REQUEST_BYTES {
        return Err(wire_error("outer precompile request length is invalid"));
    }
    if proof_len == 0 || proof_len > MAX_STARK_PROOF_BYTES {
        return Err(wire_error("outer precompile Stwo proof length is invalid"));
    }
    Ok(())
}

fn decode_stark(bytes: &[u8]) -> TexasAirResult<StarkProof<Poseidon252MerkleHasher>> {
    if bytes.is_empty() || bytes.len() > MAX_STARK_PROOF_BYTES {
        return Err(wire_error("outer AIR proof size is invalid"));
    }
    bincode_options()
        .reject_trailing_bytes()
        .deserialize(bytes)
        .map_err(|error| wire_error(format!("outer AIR proof decoding: {error}")))
}

fn bincode_options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_STARK_PROOF_BYTES as u64)
}

fn read_u32(bytes: &[u8], offset: usize) -> TexasAirResult<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| wire_error("u32 offset overflow"))?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| wire_error("u32 field is truncated"))?;
    Ok(u32::from_le_bytes(
        slice.try_into().expect("fixed u32 slice"),
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> TexasAirResult<u64> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| wire_error("u64 offset overflow"))?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| wire_error("u64 field is truncated"))?;
    Ok(u64::from_le_bytes(
        slice.try_into().expect("fixed u64 slice"),
    ))
}

fn hash256(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("32 <= 64");
    hasher.update(domain);
    hasher.update(&(payload.len() as u64).to_le_bytes());
    hasher.update(payload);
    let mut digest = [0u8; 32];
    hasher.finalize_variable(&mut digest).expect("32 <= 64");
    digest
}

fn wire_error(message: impl Into<String>) -> TexasAirError {
    TexasAirError::SerializationError(message.into())
}
