//! Cairo-route recursion envelope test (form-③) — the recursive proof chain
//! plus its negative corpus.
//!
//! Heavy (each prove spawns the real Cairo pipeline, ~5–20 s per layer):
//! `#[ignore]`-gated. Run with:
//!   cargo test --release --test recurse_test -- --ignored --nocapture
//! Requires the prove-hand binary (built once):
//!   cd proving-tool && cargo build --release
//! The binary location can be overridden with HAND_VERIFY_PROVE_HAND.
#![cfg(not(debug_assertions))]

use std::path::PathBuf;

use hand_verify_native::air::KindCounts;
use hand_verify_native::recurse::{
    self, fold_accumulator, host_fold_tasks, mint_tasks, prove_layer, write_prod_params,
    GENESIS_ACC,
};

fn two_player() -> KindCounts {
    KindCounts { n_own: 2, n_reveal: 18, n_leave: 1, n_recon: 1 }
}

fn out_dir(tag: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("output/recurse-test").join(tag);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

/// One honest envelope layer: the Cairo program's public accumulator must
/// equal the host-side fold (formula parity), and the proof must re-verify
/// standalone.
#[test]
#[ignore]
fn recursion_single_layer_parity() {
    let params = write_prod_params(&out_dir("params")).expect("params");
    let tasks = mint_tasks(two_player(), 2, 2, 1501);
    let expected = host_fold_tasks(&tasks, GENESIS_ACC).expect("host fold");
    let outcome =
        prove_layer(GENESIS_ACC, &tasks, expected, &out_dir("single"), Some(&params))
            .expect("envelope layer");
    assert_eq!(outcome.cairo_acc, expected, "parity gate");
    assert!(outcome.ec_ops > 0, "EC must be in the cairo trace");
    assert!(outcome.proof_bytes > 0);
}

/// The recursion chain: layer 1 consumes layer 0's public accumulator as its
/// prev_acc; the final public output equals the host-side chain fold.
#[test]
#[ignore]
fn recursion_chain_two_layers() {
    let params = write_prod_params(&out_dir("params")).expect("params");
    let report =
        recurse::run_recursion(two_player(), 2, 2, 2, 1511, &out_dir("chain"), Some(&params))
            .expect("recursion chain");
    assert_eq!(report.layers.len(), 2);
    // Layer 1's prev_acc is layer 0's public output (the chain is real).
    assert_eq!(report.layers[1].prev_acc, report.layers[0].cairo_acc);
    // And the final accumulator matches the host-side chain fold.
    assert_eq!(report.layers[1].cairo_acc, report.host_chain_acc);
    // Genesis anchor: layer 0 starts from the shared constant.
    assert_eq!(report.layers[0].prev_acc, GENESIS_ACC);
}

/// Tampered task (ownership s +1) must panic inside the envelope — the batch
/// produces no proof at all (fail-closed).
#[test]
#[ignore]
fn recursion_rejects_tampered_task() {
    let params = write_prod_params(&out_dir("params")).expect("params");
    recurse::run_negative_tampered_task(two_player(), 1521, &out_dir("neg-tampered"), Some(&params))
        .expect("tampered batch must be rejected");
}

/// A forged prev_acc (cross-layer splice) proves successfully against ITS OWN
/// input, but its public accumulator diverges from the honest chain fold —
/// the parity gate must reject it.
#[test]
#[ignore]
fn recursion_rejects_forged_prev_acc() {
    let params = write_prod_params(&out_dir("params")).expect("params");
    recurse::run_negative_wrong_prev(two_player(), 1522, &out_dir("neg-prev"), Some(&params))
        .expect("forged prev_acc must be caught");
}

/// The accumulator fold is order- and content-sensitive (sanity on the host
/// mirror itself, cheap — no proving involved).
#[test]
fn recursion_fold_accumulator_sensitivity() {
    // Wire felt（starknet-ff）边界；poseidon 内核是 starknet-crypto 0.8 的
    // types-core Felt——经字节桥后同一值（golden vectors 钉死跨版本一致）。
    use starknet_ff::FieldElement as Felt;
    let a = Felt::from(11u32);
    let b = Felt::from(22u32);
    assert_ne!(fold_accumulator(GENESIS_ACC, &[a, b]), fold_accumulator(GENESIS_ACC, &[b, a]));
    assert_ne!(fold_accumulator(GENESIS_ACC, &[a]), fold_accumulator(a, &[GENESIS_ACC]));
    // The empty batch folds to poseidon([prev_acc]) on both sides — the host
    // mirror matches the Cairo formula even at degenerate inputs.
    let genesis_core =
        starknet_crypto::Felt::from_bytes_be(&GENESIS_ACC.to_bytes_be());
    let empty = starknet_crypto::poseidon_hash_many(&[genesis_core]);
    assert_eq!(
        fold_accumulator(GENESIS_ACC, &[]).to_bytes_be(),
        empty.to_bytes_be()
    );
}
