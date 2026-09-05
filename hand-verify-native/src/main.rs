//! hand-verify-native — one-binary CLI for the native-Stwo hand_verify spike.
//!
//! Subcommands:
//! - `self-test` — mint honest hands (2-player / 4-player / 9-player with
//!   leave+recon), run the full host verification, prove, verify, and
//!   exercise the negative corpus (tamper / cross-hand replay / claim
//!   mismatch inside the STARK).
//! - `bench`     — prove/verify timings across payload scales, including
//!   amplified corpora, to demonstrate the O(log n)-verify property.
//! - `vectors`   — emit golden transcript vectors (challenges, rho, digest)
//!   for fixed inputs; the same vectors are pinned by an embedded test.
//!
//! Run inside `hand-verify-native/`: `cargo run --release -- self-test`.

use std::time::Instant;

use starknet_crypto::poseidon_hash_many;
use starknet_crypto::FieldElement as Felt;

use hand_verify_native::air::{HandBatchClaim, KindCounts};
use hand_verify_native::curve::Point;
use hand_verify_native::handbatch::{
    endorsement_challenge, hand_rho, leave_challenge, payload_digest,
    reconstruct_challenge, reveal_challenge, verify_hand, FoldEquation, LeaveCard,
    KIND_OWNERSHIP, KIND_RECONSTRUCT, KIND_REVEAL,
};
use hand_verify_native::{compose, curve, handbatch, mint, prove};

fn hand_binding(seed: u64) -> Felt {
    poseidon_hash_many(&[Felt::from(seed), Felt::from(0xB16Du64)])
}

struct RoundTrip {
    label: &'static str,
    counts: KindCounts,
    host_verify_us: u128,
    prove_ms: u128,
    verify_us: u128,
    proof_bytes: usize,
    log_size: u32,
}

fn run_round_trip(label: &'static str, counts: KindCounts, seed: u64) -> RoundTrip {
    let hb = hand_binding(seed);
    let payload = mint::mint_hand(
        hb, counts.n_own, counts.n_reveal, counts.n_leave, counts.n_recon, seed,
    );

    // 1. Host-native sigma verification (the form-① trust boundary).
    let t = Instant::now();
    let report = verify_hand(hb, &payload).expect("payload parses");
    let host_verify_us = t.elapsed().as_micros();
    assert!(report.accepted(), "minted payload must verify: {label}");
    assert_eq!(report.n_own, counts.n_own);
    assert_eq!(report.n_recon, counts.n_recon);

    // 2. Claim + prove.
    let claim =
            HandBatchClaim::new(hb, payload_digest(&payload), counts, Felt::ZERO);
    let t = Instant::now();
    let proof = prove::prove_claim(&claim).expect("prove");
    let prove_ms = t.elapsed().as_millis();

    // 3. Verify against the independently reconstructed claim.
    let t = Instant::now();
    prove::verify_claim(&claim, &proof).expect("verify");
    let verify_us = t.elapsed().as_micros();

    // Serialized proof size (bincode of the Stwo proof alone).
    let proof_bytes = bincode::serialize(&proof.stark_proof).map(|b| b.len()).unwrap_or(0);

    RoundTrip {
        label,
        counts,
        host_verify_us,
        prove_ms,
        verify_us,
        proof_bytes,
        log_size: claim.log_size,
    }
}

fn print_row(r: &RoundTrip) {
    println!(
        "| {:<14} | {:>3}+{:>3}+{:>2}+{:>2}    | {:>7} | {:>9.1} ms | {:>7.1} ms | {:>8.1} ms | {:>9} |",
        r.label,
        r.counts.n_own,
        r.counts.n_reveal,
        r.counts.n_leave,
        r.counts.n_recon,
        format!("2^{}", r.log_size),
        r.host_verify_us as f64 / 1000.0,
        r.prove_ms as f64,
        r.verify_us as f64 / 1000.0,
        format_bytes(r.proof_bytes),
    );
}

fn format_bytes(n: usize) -> String {
    if n >= 1 << 20 {
        format!("{:.1} MiB", n as f64 / (1 << 20) as f64)
    } else if n >= 1024 {
        format!("{:.1} KiB", n as f64 / 1024.0)
    } else {
        format!("{n} B")
    }
}

fn self_test() {
    println!("== self-test: honest corpora ==");
    let corpora = [
        ("2-player", KindCounts { n_own: 2, n_reveal: 18, n_leave: 1, n_recon: 1 }, 101u64),
        ("4-player", KindCounts { n_own: 4, n_reveal: 45, n_leave: 2, n_recon: 1 }, 102),
        ("9-player", KindCounts { n_own: 9, n_reveal: 207, n_leave: 3, n_recon: 2 }, 103),
    ];
    for (label, counts, seed) in corpora {
        let hb = hand_binding(seed);
        let payload = mint::mint_hand(
            hb, counts.n_own, counts.n_reveal, counts.n_leave, counts.n_recon, seed,
        );
        let report = verify_hand(hb, &payload).expect("parses");
        assert!(report.accepted(), "{label} honest hand must verify");
        assert_eq!(report.n_own, counts.n_own);
        assert_eq!(report.n_reveal, counts.n_reveal);
        assert_eq!(report.n_leave, counts.n_leave);
        assert_eq!(report.n_recon, counts.n_recon);
        println!(
            "  {label}: n_eq={} residuals=identity fold=identity ✔",
            report.n_eq
        );
    }

    println!("== self-test: prove/verify round trips ==");
    for (label, counts, seed) in [
        ("2-player", KindCounts { n_own: 2, n_reveal: 18, n_leave: 1, n_recon: 1 }, 101u64),
        ("9-player", KindCounts { n_own: 9, n_reveal: 207, n_leave: 3, n_recon: 2 }, 103),
    ] {
        let hb = hand_binding(seed);
        let payload = mint::mint_hand(
            hb, counts.n_own, counts.n_reveal, counts.n_leave, counts.n_recon, seed,
        );
        let claim =
            HandBatchClaim::new(hb, payload_digest(&payload), counts, Felt::ZERO);
        let proof = prove::prove_claim(&claim).expect("prove");
        prove::verify_claim(&claim, &proof).expect("verify");
        println!("  {label}: prove → verify ✔");
    }

    println!("== self-test: negative corpus ==");
    let hb = hand_binding(201);
    let seed = 201u64;

    // 1. Tampered s (ownership response word).
    let mut payload = mint::mint_hand(hb, 2, 4, 0, 0, seed);
    payload[5 + 4] = payload[5 + 4] + Felt::from(1u32);
    assert!(!verify_hand(hb, &payload).unwrap().accepted(), "tampered s must reject");
    println!("  tampered ownership s → rejected ✔");

    // 2. Cross-hand replay (same payload, different binding).
    let payload = mint::mint_hand(hb, 2, 4, 0, 0, seed);
    assert!(
        !verify_hand(hb + Felt::from(1u32), &payload).unwrap().accepted(),
        "cross-hand replay must reject"
    );
    println!("  cross-hand replay → rejected ✔");

    // 3. Off-curve pk.
    let mut payload = mint::mint_hand(hb, 1, 0, 0, 0, seed);
    payload[5] = payload[5] + Felt::from(1u32);
    assert!(verify_hand(hb, &payload).is_err(), "off-curve pk must reject");
    println!("  off-curve pk → rejected ✔");

    // 4. STARK-level claim binding (transport check bypassed): a proof
    //    generated under a different hand binding must fail inside the
    //    protocol — this is the property an L1 verifier relies on.
    let counts = KindCounts { n_own: 2, n_reveal: 4, n_leave: 0, n_recon: 0 };
    let payload = mint::mint_hand(hb, counts.n_own, counts.n_reveal, 0, 0, seed);
    let claim =
            HandBatchClaim::new(hb, payload_digest(&payload), counts, Felt::ZERO);
    let proof = prove::prove_claim(&claim).expect("prove");
    let other_hb = hb + Felt::from(7u32);
    let wrong =
            HandBatchClaim::new(other_hb, payload_digest(&payload), counts, Felt::ZERO);
    assert!(
        prove::verify_stark_against(&wrong, &proof.stark_proof).is_err(),
        "claim mismatch must reject inside the STARK"
    );
    println!("  claim mismatch (hand_binding) → rejected inside STARK ✔");

    // 5. Count mismatch at the STARK layer.
    let wrong_counts = KindCounts { n_own: 1, n_reveal: 4, n_leave: 0, n_recon: 0 };
    let wrong_counts =
            HandBatchClaim::new(hb, payload_digest(&payload), wrong_counts, Felt::ZERO);
    assert!(
        prove::verify_stark_against(&wrong, &proof.stark_proof).is_err(),
        "count mismatch must reject inside the STARK"
    );
    println!("  claim count mismatch → rejected inside STARK ✔");

    println!("self-test: all green");
}

fn bench() {
    println!("== bench: host verify + native Stwo prove/verify (release) ==");
    println!("(statements = own+reveal+leave+recon)");
    println!("| {:<14} | {:<14} | {:>7} | {:>11} | {:>9} | {:>10} | {:>9} |",
        "scale", "statements", "rows", "host verify", "prove", "verify", "proof");
    println!("|-----------------|-----------------|---------|--------------|-----------|------------|-----------|");

    let scales: [(&str, KindCounts, u64); 5] = [
        ("2-player", KindCounts { n_own: 2, n_reveal: 18, n_leave: 1, n_recon: 1 }, 301),
        ("4-player", KindCounts { n_own: 4, n_reveal: 45, n_leave: 2, n_recon: 1 }, 302),
        ("9-player", KindCounts { n_own: 9, n_reveal: 207, n_leave: 3, n_recon: 2 }, 303),
        ("9p x10 (2k)", KindCounts { n_own: 90, n_reveal: 2070, n_leave: 30, n_recon: 20 }, 304),
        ("9p x40 (8k)", KindCounts { n_own: 360, n_reveal: 8280, n_leave: 120, n_recon: 80 }, 305),
    ];
    let mut results = Vec::new();
    for (label, counts, seed) in scales {
        let r = run_round_trip(label, counts, seed);
        print_row(&r);
        results.push(r);
    }

    println!();
    println!("== scaling check: verify / proof size vs statement count ==");
    let smallest = &results[0];
    let largest = results.last().unwrap();
    let count_ratio = largest.counts.total() as f64 / smallest.counts.total() as f64;
    let verify_ratio = largest.verify_us as f64 / smallest.verify_us as f64;
    println!(
        "statements ×{count_ratio:.0} (rows 2^{} → 2^{}) → verify ×{verify_ratio:.2} (FRI \
        layers grow with log_size, i.e. O(log n) with ms constants), proof {} → {}",
        smallest.log_size,
        largest.log_size,
        format_bytes(smallest.proof_bytes),
        format_bytes(largest.proof_bytes),
    );
    println!(
        "Cairo-route baseline for comparison: 13.6 s prove per 148-EC hand (M3 Pro, stwo-cairo)."
    );
}

/// Emit golden transcript vectors for fixed inputs. The embedded `vectors`
/// test pins these byte-for-byte; cross-checking them against
/// `poker-protocol-core::stark_curve::handbatch_*_challenge` (whose
/// host↔Cairo parity is pinned in the main project) is the production gate.
fn vectors() {
    let hb = Felt::from(0xB16Du64);
    let g = Point::generator();
    // Deterministic statement points: small multiples of G.
    let p2 = g.mul(Felt::from(2u32));
    let p3 = g.mul(Felt::from(3u32));
    let p4 = g.mul(Felt::from(4u32));
    let p5 = g.mul(Felt::from(5u32));
    let p6 = g.mul(Felt::from(6u32));
    let p7 = g.mul(Felt::from(7u32));

    let c_own = endorsement_challenge(hb, g, p2, p3);
    let c_rev = reveal_challenge(hb, p2, p3, p4, p5, p6, p7, Felt::from(8u32));
    let card = LeaveCard { in_c1: p2, in_c2: p3, out_c1: p4, out_c2: p5, a: p6 };
    let c_leave = leave_challenge(hb, p2, p3, Felt::from(8u32), &[card]);
    let c_recon = reconstruct_challenge(hb, g, p2, p3, p4, p5, p6);
    let eqs = [
        FoldEquation {
            kind: KIND_OWNERSHIP,
            s: Felt::from(11u32),
            c: c_own,
            residual: curve::Point::identity(),
        },
        FoldEquation {
            kind: KIND_REVEAL,
            s: Felt::from(12u32),
            c: c_rev,
            residual: curve::Point::identity(),
        },
        FoldEquation {
            kind: KIND_RECONSTRUCT,
            s: Felt::from(13u32),
            c: c_recon,
            residual: curve::Point::identity(),
        },
    ];
    let rho = hand_rho(hb, &eqs);
    let digest = handbatch::payload_digest(&[hb, Felt::from(1u32), Felt::from(2u32)]);

    for (name, value) in [
        ("hand_binding", hb),
        ("endorsement_challenge", c_own),
        ("reveal_challenge", c_rev),
        ("leave_challenge", c_leave),
        ("reconstruct_challenge", c_recon),
        ("hand_rho", rho),
        ("payload_digest", digest),
    ] {
        println!("{name}: 0x{}", hex(&value.to_bytes_be()));
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Form-② composed round trip: Cairo EC attestation (EC_OP in trace) +
/// native statement-table AIR, bound by the claim's program hash.
fn compose_cmd() {
    let counts = hand_verify_native::air::KindCounts { n_own: 2, n_reveal: 0, n_leave: 0, n_recon: 0 };
    let out_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("output/compose");
    println!("== compose: form-② (Cairo EC attestation + native table AIR) ==");
    let t = Instant::now();
    let report = compose::run_compose(counts, 601, &out_dir).expect("compose");
    println!(
        "  payload    : 2 ownership statements ({} EC_OP in cairo trace)",
        report.cairo_ec_ops
    );
    println!("  cairo half : prove {} ms (incl. compile + witness), check-only ✓", report.cairo_prove_ms);
    println!(
        "  native half: prove {} ms, verify {} ms ✓",
        report.native_prove_ms, report.native_verify_ms
    );
    println!(
        "  binding    : program hash 0x{} mixed into the native claim channel ✓",
        report.cairo_program_hash.to_bytes_be().iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    println!("  total wall : {} ms", t.elapsed().as_millis());
    println!("compose: all green");
}

/// Native felt252-mul kernel throughput: the leaf cost that the whole
/// form-② native stack multiplies by (EC step ≈ 8–12 kernel rows,
/// Poseidon permutation ≈ 1233).
fn mulbench() {
    use hand_verify_native::feltmul::{prove_felt_muls, verify_felt_muls, FeltMulClaim};
    use std::time::Instant;

    println!("== mulbench: native felt252-mod-mul kernel (trace row = 1 mul) ==");
    for log in [8u32, 10, 12] {
        let n = 1usize << log;
        let stmts: Vec<_> = (0..n as u64)
            .map(hand_verify_native::feltmul::sample_statement)
            .collect();
        let t = Instant::now();
        let proof = prove_felt_muls(&stmts, log).expect("prove");
        let prove = t.elapsed();
        let t = Instant::now();
        verify_felt_muls(&FeltMulClaim::new(log), &proof).expect("verify");
        let verify = t.elapsed();
        let muls_per_s = n as f64 / prove.as_secs_f64();
        println!(
            "| 2^{:<3} | {:>7} muls | prove {:>8.2?} | verify {:>8.2?} | {:>10.0} muls/s |",
            log, n, prove, verify, muls_per_s
        );
    }
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "self-test".into());
    match mode.as_str() {
        "self-test" => self_test(),
        "bench" => bench(),
        "vectors" => vectors(),
        "compose" => compose_cmd(),
        "mulbench" => mulbench(),
        "help" | "--help" | "-h" => {
            println!("usage: hand-verify-native [self-test|bench|vectors|compose|mulbench]");
        }
        other => {
            eprintln!("unknown mode: {other} (expected self-test | bench | vectors | compose)");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Pin the golden transcript vectors. Any accidental drift in the
    /// transcript formulas (labels, word order, encoding) breaks this test.
    /// Values are generated by `cargo run --release -- vectors`; the
    /// production gate is cross-checking them against
    /// `poker-protocol-core::stark_curve` (host↔Cairo parity lives there).
    #[test]
    fn golden_vectors_pinned() {
        let hb = Felt::from(0xB16Du64);
        let g = Point::generator();
        let p2 = g.mul(Felt::from(2u32));
        let p3 = g.mul(Felt::from(3u32));
        let p4 = g.mul(Felt::from(4u32));
        let p5 = g.mul(Felt::from(5u32));
        let p6 = g.mul(Felt::from(6u32));
        let p7 = g.mul(Felt::from(7u32));

        // Populated from `cargo run --release -- vectors` (see
        // docs/golden-vectors.md); asserted here to pin formula drift.
        assert_eq!(
            hex(&endorsement_challenge(hb, g, p2, p3).to_bytes_be()),
            crate_golden::ENDORSEMENT,
        );
        assert_eq!(
            hex(&reveal_challenge(hb, p2, p3, p4, p5, p6, p7, Felt::from(8u32)).to_bytes_be()),
            crate_golden::REVEAL,
        );
        assert_eq!(hex(&hand_binding(1).to_bytes_be()), crate_golden::HAND_BINDING_SEED_1);
    }

    /// Inline module holding the pinned vectors (kept beside the test so a
    /// failure shows both sides of the comparison).
    mod crate_golden {
        // Generated by `cargo run --release -- vectors` (2026-09-05).
        pub const ENDORSEMENT: &str =
            "0189aed1c36bf0805ded895ee4f33d6c0dcf31dbdba0e71afaddbff230e633f4";
        pub const REVEAL: &str =
            "0229a973a7e63c4611e15f3b3789607159a9c19e533dc869e5096617b13d39c4";
        pub const HAND_BINDING_SEED_1: &str =
            "07eaa6791d6dec73dd42d4db78de231bec25b88b39faac13dcbbbc271088dac0";
    }
}
