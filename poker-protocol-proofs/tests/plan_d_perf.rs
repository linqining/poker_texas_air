//! Plan D P3 性能指标测试（criterion 不引入；std::time 计时）。
//!
//! 运行：`cargo test -p poker-protocol-core --test plan_d_perf -- --ignored --nocapture`
//!
//! 指标用途：
//! 1. STARK 曲线原生运算吞吐 → P1.4 全残差批次的 EC_OP 链上预算推演；
//! 2. 52 卡洗牌证明 prove/verify 时延 → direct-Sigma 热路径容量；
//! 3. host_fold_check N 项时延 → 每手 EC_OP 折叠项上限的依据；
//! 4. 电路重执行 / Nova folding 的成本模型输入（单点乘、多标量乘基线）。

use poker_protocol_core::{
    ec_encrypt_batch_generic, Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric, StarkCurve,
};
use poker_protocol_proofs::shuffle_proof::ZKShuffleProof;
use poker_protocol_proofs::transcript_ext::{CryptoTranscript, MerlinTranscript};
use rand::seq::SliceRandom;
use rand_core::OsRng;
use std::time::Instant;

type C = StarkCurve;
type Ct = ElGamalCiphertextGeneric<C>;

fn scalar(v: u64) -> <C as Curve>::Scalar {
    <C as Curve>::Scalar::from_u64(v)
}

fn random_point() -> <C as Curve>::Point {
    <C as Curve>::base_g() * <C as Curve>::Scalar::random(&mut OsRng)
}

fn median_us(samples: &[u128]) -> u128 {
    let mut s = samples.to_vec();
    s.sort();
    s[s.len() / 2]
}

#[test]
#[ignore = "perf metrics: run with --ignored"]
fn perf_scalar_mul_throughput() {
    let p = random_point();
    let s = scalar(0x1234_5678_9abc_def0);
    // 预热
    for _ in 0..20 {
        let _ = p * s;
    }
    const N: usize = 400;
    let start = Instant::now();
    for _ in 0..N {
        let _ = p * s;
    }
    let total_us = start.elapsed().as_micros();
    let per_op_us = total_us / N as u128;
    println!("[perf] 标量乘（double-and-add，251 bit）：{per_op_us} µs/op（{N} 次，共 {total_us} µs）");
    assert!(per_op_us < 20_000, "scalar mul must stay sub-20ms for gameplay use");
}

#[test]
#[ignore = "perf metrics: run with --ignored"]
fn perf_vartime_multiscalar_52() {
    let scalars: Vec<_> = (0..52).map(|_| <C as Curve>::Scalar::random(&mut OsRng)).collect();
    let points: Vec<_> = (0..52).map(|_| random_point()).collect();
    // 预热
    let _ = stark_vartime(&scalars, &points);
    const N: usize = 50;
    let mut samples = Vec::with_capacity(N);
    for _ in 0..N {
        let start = Instant::now();
        let _ = stark_vartime(&scalars, &points);
        samples.push(start.elapsed().as_micros());
    }
    println!("[perf] 52 项 vartime_multiscalar_mul：中位 {} µs", median_us(&samples));
}

fn stark_vartime(
    scalars: &[<C as Curve>::Scalar],
    points: &[<C as Curve>::Point],
) -> <C as Curve>::Point {
    <_ as CurvePoint>::vartime_multiscalar_mul(scalars, points)
}

#[test]
#[ignore = "perf metrics: run with --ignored"]
fn perf_shuffle_52_prove_verify() {
    let sk = <C as Curve>::Scalar::random(&mut OsRng);
    let pk = <C as Curve>::base_g() * sk;
    let msgs: Vec<_> = (0..52).map(|i| <C as Curve>::base_g() * scalar(i as u64 + 1)).collect();
    let input = ec_encrypt_batch_generic::<C>(&msgs, &pk, &mut OsRng);
    let mut permute: Vec<usize> = (0..52).collect();
    permute.shuffle(&mut OsRng);
    let r_values: Vec<_> = (0..52).map(|_| <C as Curve>::Scalar::random(&mut OsRng)).collect();
    let output: Vec<Ct> = (0..52)
        .map(|j| input[permute[j]].re_encrypt(&pk, &r_values[j]))
        .collect();

    let start = Instant::now();
    let proof = ZKShuffleProof::<C>::prove(
        &input,
        &output,
        &permute,
        &r_values,
        &pk,
        &mut OsRng,
        &mut MerlinTranscript::new(b"perf-shuffle"),
    )
    .expect("honest proof");
    let prove_us = start.elapsed().as_micros();

    let start = Instant::now();
    proof
        .verify(&input, &output, &pk, &mut MerlinTranscript::new(b"perf-shuffle"))
        .expect("verify");
    let verify_us = start.elapsed().as_micros();

    println!("[perf] ZKShuffleProof 52 卡：prove {prove_us} µs，verify {verify_us} µs");
}

#[test]
#[ignore = "perf metrics: run with --ignored"]
fn perf_batch_encrypt_52() {
    let pk = random_point();
    let msgs: Vec<_> = (0..52).map(|i| <C as Curve>::base_g() * scalar(i as u64 + 1)).collect();
    let start = Instant::now();
    let _ = ec_encrypt_batch_generic::<C>(&msgs, &pk, &mut OsRng);
    println!("[perf] 52 卡批量 ElGamal 加密（含 52 次标量乘）：{} µs", start.elapsed().as_micros());
}

#[test]
#[ignore = "perf metrics: run with --ignored"]
fn perf_hand_batch_fold_9p_full_residual_budget() {
    // 9 人桌全残差批次预算：9 × (52×3 + 7×2) ≈ 1540 项（保守取 1540）
    // 每项 2 次标量乘（ρ 幂 + 点乘）——链上 EC_OP 折叠的 host 模拟。
    let scalars: Vec<_> = (0..1540).map(|i| scalar((i % 61 + 1) as u64)).collect();
    let points: Vec<_> = (0..1540).map(|_| random_point()).collect();
    let start = Instant::now();
    let _ = stark_vartime(&scalars, &points);
    println!(
        "[perf] 1540 项 host 折叠模拟（9 人桌全残差）：{} µs —— 链上 EC_OP 版本按 builtin 单步估算",
        start.elapsed().as_micros()
    );
}

#[test]
#[ignore = "perf metrics: run with --ignored"]
fn perf_hash_to_scalar_and_curve() {
    const N: usize = 500;
    let start = Instant::now();
    for i in 0..N {
        let _ = <C as Curve>::hash_to_scalar(format!("perf-h2s-{i}").as_bytes());
    }
    println!(
        "[perf] hash_to_scalar（Poseidon）：{} µs/op",
        start.elapsed().as_micros() / N as u128
    );

    let start = Instant::now();
    for i in 0..N {
        let _ = <C as Curve>::hash_to_curve(format!("perf-h2c-{i}").as_bytes());
    }
    println!(
        "[perf] hash_to_curve（try-and-increment + sqrt）：{} µs/op",
        start.elapsed().as_micros() / N as u128
    );
}
