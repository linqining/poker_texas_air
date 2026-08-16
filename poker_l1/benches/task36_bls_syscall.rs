//! Task 36.2: BLS12-381 syscall 单次延迟（含子群检查）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）+ tasks.md Task 36 SubTask 36.2：
//! 测量各 BLS12-381 预编译 syscall 的单次延迟，含 G1/G2 子群检查开销。
//!
//! 覆盖的预编译：
//! - bls_g1_add / bls_g1_mul / bls_g1_neg（G1 操作 + 子群检查）
//! - bls_g2_add / bls_g2_mul / bls_g2_neg（G2 操作 + 子群检查）
//! - bls_pairing_check（4 输入子群检查 + pairing 验证，worst-case gas=5000）
//! - bls_miller_loop / bls_final_exp（拆分 pairing）
//! - bls_hash_to_g1 / bls_hash_to_g2（RFC 9380 hash-to-curve）

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use poker_l1::crypto_precompiles::bls::{
    bls_final_exp, bls_g1_add, bls_g1_mul, bls_g1_neg, bls_g2_add, bls_g2_mul, bls_g2_neg,
    bls_hash_to_g1, bls_hash_to_g2, bls_miller_loop, bls_pairing_check,
};

// ===== 测试数据准备 =====

/// 生成有效的 G1 点（通过 hash_to_g1）。
fn gen_g1_point(msg: &[u8]) -> Vec<u8> {
    bls_hash_to_g1(msg).expect("hash_to_g1 应成功").to_vec()
}

/// 生成有效的 G2 点（通过 hash_to_g2）。
fn gen_g2_point(msg: &[u8]) -> Vec<u8> {
    bls_hash_to_g2(msg).expect("hash_to_g2 应成功").to_vec()
}

/// 生成有效 scalar（32 字节大端）。
fn gen_scalar(byte: u8) -> Vec<u8> {
    let mut s = vec![0u8; 32];
    s[31] = byte; // 小 scalar，避免无穷远点
    s
}

// ===== G1 操作基准 =====

fn bench_g1_add(c: &mut Criterion) {
    let a = gen_g1_point(b"bench_g1_a");
    let b = gen_g1_point(b"bench_g1_b");

    c.bench_function("bls_g1_add", |bencher| {
        bencher.iter(|| {
            let result = bls_g1_add(black_box(&a), black_box(&b)).expect("g1_add");
            black_box(result);
        });
    });
}

fn bench_g1_mul(c: &mut Criterion) {
    let point = gen_g1_point(b"bench_g1_mul");
    let scalar = gen_scalar(42);

    c.bench_function("bls_g1_mul", |bencher| {
        bencher.iter(|| {
            let result = bls_g1_mul(black_box(&point), black_box(&scalar)).expect("g1_mul");
            black_box(result);
        });
    });
}

fn bench_g1_neg(c: &mut Criterion) {
    let point = gen_g1_point(b"bench_g1_neg");

    c.bench_function("bls_g1_neg", |bencher| {
        bencher.iter(|| {
            let result = bls_g1_neg(black_box(&point)).expect("g1_neg");
            black_box(result);
        });
    });
}

// ===== G2 操作基准 =====

fn bench_g2_add(c: &mut Criterion) {
    let a = gen_g2_point(b"bench_g2_a");
    let b = gen_g2_point(b"bench_g2_b");

    c.bench_function("bls_g2_add", |bencher| {
        bencher.iter(|| {
            let result = bls_g2_add(black_box(&a), black_box(&b)).expect("g2_add");
            black_box(result);
        });
    });
}

fn bench_g2_mul(c: &mut Criterion) {
    let point = gen_g2_point(b"bench_g2_mul");
    let scalar = gen_scalar(42);

    c.bench_function("bls_g2_mul", |bencher| {
        bencher.iter(|| {
            let result = bls_g2_mul(black_box(&point), black_box(&scalar)).expect("g2_mul");
            black_box(result);
        });
    });
}

fn bench_g2_neg(c: &mut Criterion) {
    let point = gen_g2_point(b"bench_g2_neg");

    c.bench_function("bls_g2_neg", |bencher| {
        bencher.iter(|| {
            let result = bls_g2_neg(black_box(&point)).expect("g2_neg");
            black_box(result);
        });
    });
}

// ===== Pairing 基准（最重操作）=====

fn bench_pairing_check(c: &mut Criterion) {
    let a_g1 = gen_g1_point(b"pairing_a");
    let b_g2 = gen_g2_point(b"pairing_b");
    let c_g1 = gen_g1_point(b"pairing_c");
    let d_g2 = gen_g2_point(b"pairing_d");

    c.bench_function("bls_pairing_check", |bencher| {
        bencher.iter(|| {
            let result = bls_pairing_check(
                black_box(&a_g1),
                black_box(&b_g2),
                black_box(&c_g1),
                black_box(&d_g2),
            )
            .expect("pairing_check");
            black_box(result);
        });
    });
}

fn bench_miller_loop(c: &mut Criterion) {
    let a_g1 = gen_g1_point(b"miller_a");
    let b_g2 = gen_g2_point(b"miller_b");

    c.bench_function("bls_miller_loop", |bencher| {
        bencher.iter(|| {
            let result = bls_miller_loop(black_box(&a_g1), black_box(&b_g2)).expect("miller_loop");
            black_box(result);
        });
    });
}

fn bench_final_exp(c: &mut Criterion) {
    let a_g1 = gen_g1_point(b"fexp_a");
    let b_g2 = gen_g2_point(b"fexp_b");
    let gt = bls_miller_loop(&a_g1, &b_g2).expect("miller_loop for final_exp setup");

    c.bench_function("bls_final_exp", |bencher| {
        bencher.iter(|| {
            let result = bls_final_exp(black_box(&gt)).expect("final_exp");
            black_box(result);
        });
    });
}

// ===== Hash-to-curve 基准（RFC 9380）=====

fn bench_hash_to_g1(c: &mut Criterion) {
    let msg = b"benchmark_hash_to_g1_message";

    c.bench_function("bls_hash_to_g1", |bencher| {
        bencher.iter(|| {
            let result = bls_hash_to_g1(black_box(msg)).expect("hash_to_g1");
            black_box(result);
        });
    });
}

fn bench_hash_to_g2(c: &mut Criterion) {
    let msg = b"benchmark_hash_to_g2_message";

    c.bench_function("bls_hash_to_g2", |bencher| {
        bencher.iter(|| {
            let result = bls_hash_to_g2(black_box(msg)).expect("hash_to_g2");
            black_box(result);
        });
    });
}

criterion_group!(
    benches,
    bench_g1_add,
    bench_g1_mul,
    bench_g1_neg,
    bench_g2_add,
    bench_g2_mul,
    bench_g2_neg,
    bench_pairing_check,
    bench_miller_loop,
    bench_final_exp,
    bench_hash_to_g1,
    bench_hash_to_g2,
);
criterion_main!(benches);
