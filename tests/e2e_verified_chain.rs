//! External regression for the descriptor-only aggregation production gate.
//!
//! Receipt issuance and chain construction are intentionally crate-private;
//! their continuity invariants are tested inside `verified_chain.rs`, while
//! public callers can only inspect a chain returned by the Orchestrator.

use poker_texas_air::aggregator_air::ChildDescriptor;
use poker_texas_air::aggregator_prover::prove_aggregator;
use poker_texas_air::error::TexasAirError;
use poker_texas_air::method_kind::MethodKind;

#[test]
fn descriptor_only_summary_remains_fail_closed() {
    let first = ChildDescriptor {
        pre_state_root: [stwo::core::fields::m31::M31::from(1u32); 4],
        post_state_root: [stwo::core::fields::m31::M31::from(2u32); 4],
        call_seq: 1,
        method_kind: MethodKind::Fold,
    };
    let second = ChildDescriptor {
        pre_state_root: [stwo::core::fields::m31::M31::from(2u32); 4],
        post_state_root: [stwo::core::fields::m31::M31::from(3u32); 4],
        call_seq: 2,
        method_kind: MethodKind::Check,
    };

    assert!(matches!(
        prove_aggregator(vec![first, second]),
        Err(TexasAirError::UntrustedAggregationDisabled)
    ));
}
