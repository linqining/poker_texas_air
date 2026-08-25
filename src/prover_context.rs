//! Process-local immutable data shared by independent Stwo proofs.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock, RwLock};

use stwo::core::fri::FriConfig;
use stwo::core::pcs::PcsConfig;
use stwo::core::poly::circle::CanonicCoset;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::mempool::BaseColumnPool;
use stwo::prover::poly::circle::PolyOps;
use stwo::prover::poly::twiddles::TwiddleTree;

const MAX_CACHED_DOMAINS: usize = 4;

type TwiddleCache = BTreeMap<u32, Arc<TwiddleTree<SimdBackend>>>;

static TWIDDLE_CACHE: OnceLock<RwLock<TwiddleCache>> = OnceLock::new();
static BASE_COLUMN_POOL: OnceLock<BaseColumnPool<SimdBackend>> = OnceLock::new();

/// Canonical PCS profile for every production Texas AIR proof.
///
/// This is deliberately equivalent to Stwo 2.3's current default: 10 PoW
/// bits plus 30 FRI bits (`log_blowup_factor = 1`, `n_queries = 30`). Keeping
/// it local prevents an upstream default change from silently changing proof
/// compatibility or soundness. Alternative equal-security FRI configurations
/// must be benchmarked and adopted here atomically by prover and verifier.
pub(crate) fn protocol_pcs_config() -> PcsConfig {
    PcsConfig {
        pow_bits: 10,
        fri_config: FriConfig::new(0, 1, 30, 1),
        lifting_log_size: None,
    }
}

/// Return process-local reusable LDE column storage.
///
/// The pool contains only temporary base-field buffers. Commitment generation
/// overwrites each buffer before it is read, so reuse cannot carry witness or
/// Fiat--Shamir state between independent proofs. The underlying pool is
/// concurrent and is safe for Rayon proof workers.
pub(crate) fn simd_base_column_pool() -> &'static BaseColumnPool<SimdBackend> {
    BASE_COLUMN_POOL.get_or_init(BaseColumnPool::new)
}

/// Return immutable SIMD twiddles for a PCS evaluation domain.
///
/// Twiddles depend only on the domain, never on the trace, AIR, public
/// inputs, or Fiat--Shamir channel. Keeping a small process-local cache is
/// therefore safe across independent proofs while avoiding repeated setup on
/// the latency-sensitive single-method path.
pub(crate) fn simd_twiddles(domain_log_size: u32) -> Arc<TwiddleTree<SimdBackend>> {
    let cache = TWIDDLE_CACHE.get_or_init(|| RwLock::new(BTreeMap::new()));
    if let Some(twiddles) = cache
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&domain_log_size)
    {
        return Arc::clone(twiddles);
    }

    {
        let cache = cache
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(twiddles) = cache.get(&domain_log_size) {
            return Arc::clone(twiddles);
        }
    }

    // Precomputation is deliberately outside the write lock. Different cold
    // domains must not block readers or serialize one another unnecessarily.
    let twiddles = Arc::new(SimdBackend::precompute_twiddles(
        CanonicCoset::new(domain_log_size).half_coset(),
    ));
    let mut cache = cache
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(existing) = cache.get(&domain_log_size) {
        return Arc::clone(existing);
    }
    if cache.len() < MAX_CACHED_DOMAINS {
        cache.insert(domain_log_size, Arc::clone(&twiddles));
    }
    twiddles
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_pcs_profile_stays_at_forty_bits() {
        assert_eq!(protocol_pcs_config().security_bits(), 40);
    }
}
