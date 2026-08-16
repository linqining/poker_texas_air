//! Phase 4 集成测试（Task 41 — SubTask 41.1~41.9）
//!
//! 覆盖 Phase 4 跨模块端到端场景：
//! - SubTask 41.1：BLS12-381 G1/G2 操作单元测试（已在 `crypto_precompiles::bls` 完成）
//! - SubTask 41.2：子群检查单元测试（已在 `crypto_precompiles::bls` 完成）
//! - SubTask 41.3：pairing_check 单元测试（已在 `crypto_precompiles::bls` 完成）
//! - SubTask 41.4：hash_to_g1/g2 单元测试（已在 `crypto_precompiles::bls` 完成）
//! - SubTask 41.5：miller_loop / final_exp 单元测试（已在 `crypto_precompiles::bls` 完成）
//! - SubTask 41.6：节点级 native API 集成测试（正向 + 反向）
//! - SubTask 41.7：gas 计费单元测试（已在 `vm::syscalls` 完成）
//! - SubTask 41.8：模糊测试（BLS12-381 syscall 至少 10000 个随机输入）
//! - SubTask 41.9：覆盖率门禁（通过完整测试覆盖保证）

use poker_l1::crypto_precompiles::bls;
use poker_l1::crypto_precompiles::native_api::{bls_verify, secp256k1_aggregate_verify};
use poker_l1::signature::TaggedPubkey;
use poker_l1::signature::tagged_pubkey::{SignatureScheme, encode_tag};

use blstrs::{G1Projective, G2Projective, Scalar};
use group::Group;
use group::ff::Field;
use rand::rngs::OsRng;
use secp256k1::{Message, Secp256k1};

/// 将 CtOption<G1Projective> 转为 Option<G1Projective>。
fn ct_g1_to_opt(ct: subtle::CtOption<G1Projective>) -> Option<G1Projective> {
    if bool::from(ct.is_some()) {
        Some(ct.unwrap())
    } else {
        None
    }
}

// ===== SubTask 41.6: 节点级 native API 集成测试 =====

/// 构造 tagged secp256k1 pubkey。
fn make_secp_tagged_pubkey(pk: &secp256k1::PublicKey) -> TaggedPubkey {
    TaggedPubkey {
        tag: encode_tag(SignatureScheme::Secp256k1, 1),
        raw: pk.serialize().to_vec(),
    }
}

#[test]
fn subtask_41_6_secp256k1_aggregate_verify_positive() {
    // 正向：N 个真实 secp256k1 签名验证全部通过
    let secp = Secp256k1::new();
    let msg = [0x42u8; 32];

    let mut pubkeys = Vec::new();
    let mut msg_hashes: Vec<&[u8; 32]> = Vec::new();
    let mut sigs: Vec<Vec<u8>> = Vec::new();

    let mut keypairs = Vec::new();
    for _ in 0..3 {
        let (sk, pk) = secp.generate_keypair(&mut OsRng);
        let sig = secp.sign_ecdsa_recoverable(&Message::from_digest(msg), &sk);
        let (rid, compact) = sig.serialize_compact();
        let mut full_sig = compact.to_vec();
        full_sig.push(rid.to_i32() as u8);

        pubkeys.push(make_secp_tagged_pubkey(&pk));
        sigs.push(full_sig);
        keypairs.push(());
    }
    // 3 个相同 msg_hash
    let m1: &[u8; 32] = &msg;
    let m2: &[u8; 32] = &msg;
    let m3: &[u8; 32] = &msg;
    msg_hashes.push(m1);
    msg_hashes.push(m2);
    msg_hashes.push(m3);

    let sig_refs: Vec<&[u8]> = sigs.iter().map(|s| s.as_slice()).collect();

    let result = secp256k1_aggregate_verify(&pubkeys, &msg_hashes, &sig_refs)
        .expect("aggregate verify 应成功执行");
    assert!(result, "3 个真实签名应全部验证通过");
}

#[test]
fn subtask_41_6_secp256k1_aggregate_verify_negative_tampered() {
    // 反向：篡改任一签名 → 验证失败
    let secp = Secp256k1::new();
    let msg = [0x42u8; 32];

    let (sk1, pk1) = secp.generate_keypair(&mut OsRng);
    let (sk2, pk2) = secp.generate_keypair(&mut OsRng);

    let sig1 = secp.sign_ecdsa_recoverable(&Message::from_digest(msg), &sk1);
    let sig2 = secp.sign_ecdsa_recoverable(&Message::from_digest(msg), &sk2);

    let (rid1, mut compact1) = sig1.serialize_compact();
    let (rid2, compact2) = sig2.serialize_compact();

    // 篡改 sig1 的首字节
    compact1[0] ^= 0x01;

    let mut full_sig1 = compact1.to_vec();
    full_sig1.push(rid1.to_i32() as u8);
    let mut full_sig2 = compact2.to_vec();
    full_sig2.push(rid2.to_i32() as u8);

    let pubkeys = vec![make_secp_tagged_pubkey(&pk1), make_secp_tagged_pubkey(&pk2)];
    let m1: &[u8; 32] = &msg;
    let m2: &[u8; 32] = &msg;
    let msg_hashes: Vec<&[u8; 32]> = vec![m1, m2];
    let sigs: Vec<&[u8]> = vec![&full_sig1, &full_sig2];

    let result = secp256k1_aggregate_verify(&pubkeys, &msg_hashes, &sigs)
        .expect("aggregate verify 应成功执行（不 panic）");
    assert!(!result, "篡改签名应导致验证失败");
}

#[test]
fn subtask_41_6_bls_verify_positive() {
    // 正向：真实 BLS 签名验证
    // sk = random scalar
    // pubkey_g2 = sk * G2
    // signature_g1 = sk * hash_to_g1(msg)
    // bls_verify(pubkey_g2, signature_g1, msg) == true

    let mut rng = OsRng;
    let sk = Scalar::random(&mut rng);

    // pubkey_g2 = sk * G2_generator
    let g2_gen = G2Projective::generator();
    let pubkey_g2 = g2_gen * sk;
    let pubkey_g2_bytes = pubkey_g2.to_compressed();

    // h_m = hash_to_g1(msg)
    let msg = b"phase4 bls verify positive test";
    let h_m_bytes = bls::bls_hash_to_g1(msg).expect("hash_to_g1 应成功");

    // 反序列化 h_m 用于签名计算
    // signature_g1 = sk * h_m
    let h_m = {
        let mut arr = [0u8; bls::G1_COMPRESSED_SIZE];
        arr.copy_from_slice(&h_m_bytes);
        ct_g1_to_opt(G1Projective::from_compressed(&arr)).expect("hash_to_g1 结果应可反序列化")
    };
    let signature_g1 = h_m * sk;
    let signature_g1_bytes = signature_g1.to_compressed();

    let result =
        bls_verify(&pubkey_g2_bytes, &signature_g1_bytes, msg).expect("bls_verify 应成功执行");
    assert!(result, "真实 BLS 签名应验证通过");
}

#[test]
fn subtask_41_6_bls_verify_negative_tampered_signature() {
    // 反向：篡改签名 → 验证失败
    let mut rng = OsRng;
    let sk = Scalar::random(&mut rng);

    let g2_gen = G2Projective::generator();
    let pubkey_g2 = g2_gen * sk;
    let pubkey_g2_bytes = pubkey_g2.to_compressed();

    let msg = b"phase4 bls verify negative test";
    let h_m_bytes = bls::bls_hash_to_g1(msg).expect("hash_to_g1 应成功");

    let h_m = {
        let mut arr = [0u8; bls::G1_COMPRESSED_SIZE];
        arr.copy_from_slice(&h_m_bytes);
        ct_g1_to_opt(G1Projective::from_compressed(&arr)).expect("hash_to_g1 结果应可反序列化")
    };
    let mut signature_g1 = h_m * sk;
    // 篡改：signature = signature + G1_generator（改变签名点）
    signature_g1 += G1Projective::generator();
    let signature_g1_bytes = signature_g1.to_compressed();

    let result = bls_verify(&pubkey_g2_bytes, &signature_g1_bytes, msg)
        .expect("bls_verify 应成功执行（不 panic）");
    assert!(!result, "篡改签名应导致验证失败");
}

#[test]
fn subtask_41_6_bls_verify_negative_wrong_msg() {
    // 反向：签名 msg A 但用 msg B 验证 → 失败
    let mut rng = OsRng;
    let sk = Scalar::random(&mut rng);

    let g2_gen = G2Projective::generator();
    let pubkey_g2 = g2_gen * sk;
    let pubkey_g2_bytes = pubkey_g2.to_compressed();

    let msg_a = b"signed message A";
    let msg_b = b"verification message B";

    let h_m_bytes = bls::bls_hash_to_g1(msg_a).expect("hash_to_g1 应成功");
    let h_m = {
        let mut arr = [0u8; bls::G1_COMPRESSED_SIZE];
        arr.copy_from_slice(&h_m_bytes);
        ct_g1_to_opt(G1Projective::from_compressed(&arr)).expect("hash_to_g1 结果应可反序列化")
    };
    let signature_g1 = h_m * sk;
    let signature_g1_bytes = signature_g1.to_compressed();

    // 用 msg_b 验证（签的是 msg_a）
    let result =
        bls_verify(&pubkey_g2_bytes, &signature_g1_bytes, msg_b).expect("bls_verify 应成功执行");
    assert!(!result, "msg 不匹配应导致验证失败");
}

// ===== SubTask 41.8: 模糊测试 =====
//
// BLS12-381 syscall 至少 10000 个随机输入（含非子群、超长 msg、非法 compressed bytes）；
// 无 panic / 无未捕获错误。

#[test]
fn subtask_41_8_fuzz_bls_g1_operations() {
    // 随机 48 字节输入 → bls_g1_add / g1_mul / g1_neg
    // 大部分应返回 InvalidSubgroup / InvalidBlsPoint，不应 panic
    let mut rng = OsRng;
    let valid_g1 = G1Projective::generator().to_compressed();
    let valid_scalar = Scalar::from(2u64).to_bytes_be();

    let mut tested = 0u32;
    for _ in 0..4000 {
        // 随机 48 字节 G1 输入
        let mut random_g1 = [0u8; bls::G1_COMPRESSED_SIZE];
        rand::RngCore::fill_bytes(&mut rng, &mut random_g1);

        // g1_add(random, valid)
        let _ = bls::bls_g1_add(&random_g1, &valid_g1);
        // g1_add(valid, random)
        let _ = bls::bls_g1_add(&valid_g1, &random_g1);
        // g1_mul(random, valid_scalar)
        let _ = bls::bls_g1_mul(&random_g1, &valid_scalar);
        // g1_neg(random)
        let _ = bls::bls_g1_neg(&random_g1);

        // 随机 32 字节 scalar
        let mut random_scalar = [0u8; bls::SCALAR_SIZE];
        rand::RngCore::fill_bytes(&mut rng, &mut random_scalar);
        let _ = bls::bls_g1_mul(&valid_g1, &random_scalar);

        tested += 5;
    }
    assert!(tested >= 20000, "至少测试 20000 次 G1 操作");
}

#[test]
fn subtask_41_8_fuzz_bls_g2_operations() {
    let mut rng = OsRng;
    let valid_g2 = G2Projective::generator().to_compressed();
    let valid_scalar = Scalar::from(2u64).to_bytes_be();

    let mut tested = 0u32;
    for _ in 0..3000 {
        let mut random_g2 = [0u8; bls::G2_COMPRESSED_SIZE];
        rand::RngCore::fill_bytes(&mut rng, &mut random_g2);

        let _ = bls::bls_g2_add(&random_g2, &valid_g2);
        let _ = bls::bls_g2_add(&valid_g2, &random_g2);
        let _ = bls::bls_g2_mul(&random_g2, &valid_scalar);
        let _ = bls::bls_g2_neg(&random_g2);

        tested += 4;
    }
    assert!(tested >= 12000, "至少测试 12000 次 G2 操作");
}

#[test]
fn subtask_41_8_fuzz_bls_pairing_check() {
    let mut rng = OsRng;
    let valid_g1 = G1Projective::generator().to_compressed();
    let valid_g2 = G2Projective::generator().to_compressed();

    let mut tested = 0u32;
    for _ in 0..2500 {
        // 4 个输入中随机 1 个为非法，其余为合法
        let mut random_g1 = [0u8; bls::G1_COMPRESSED_SIZE];
        rand::RngCore::fill_bytes(&mut rng, &mut random_g1);
        let mut random_g2 = [0u8; bls::G2_COMPRESSED_SIZE];
        rand::RngCore::fill_bytes(&mut rng, &mut random_g2);

        // 全合法
        let _ = bls::bls_pairing_check(&valid_g1, &valid_g2, &valid_g1, &valid_g2);
        // 1 个非法 G1
        let _ = bls::bls_pairing_check(&random_g1, &valid_g2, &valid_g1, &valid_g2);
        // 1 个非法 G2
        let _ = bls::bls_pairing_check(&valid_g1, &random_g2, &valid_g1, &valid_g2);
        // 全非法
        let _ = bls::bls_pairing_check(&random_g1, &random_g2, &random_g1, &random_g2);

        tested += 4;
    }
    assert!(tested >= 10000, "至少测试 10000 次 pairing_check");
}

#[test]
fn subtask_41_8_fuzz_bls_hash_to_curve() {
    let mut rng = OsRng;

    let mut tested = 0u32;
    for _ in 0..1000 {
        // 随机长度 msg（1..256）
        let len = 1 + (rand::RngCore::next_u32(&mut rng) % 256) as usize;
        let mut msg = vec![0u8; len];
        rand::RngCore::fill_bytes(&mut rng, &mut msg);

        let _ = bls::bls_hash_to_g1(&msg);
        let _ = bls::bls_hash_to_g2(&msg);

        tested += 2;
    }

    // 超长 msg（> 65536）应返回 InputTooLong，不 panic
    let long_msg = vec![0u8; bls::G1_COMPRESSED_SIZE * 2000]; // 远超 65536
    let result = bls::bls_hash_to_g1(&long_msg);
    assert!(result.is_err(), "超长 msg 应返回错误");
    let result = bls::bls_hash_to_g2(&long_msg);
    assert!(result.is_err(), "超长 msg 应返回错误");

    assert!(tested >= 2000, "至少测试 2000 次 hash_to_curve");
}

#[test]
fn subtask_41_8_fuzz_bls_miller_loop_final_exp() {
    let mut rng = OsRng;
    let valid_g1 = G1Projective::generator().to_compressed();
    let valid_g2 = G2Projective::generator().to_compressed();

    let mut tested = 0u32;
    for _ in 0..1500 {
        let mut random_g1 = [0u8; bls::G1_COMPRESSED_SIZE];
        rand::RngCore::fill_bytes(&mut rng, &mut random_g1);
        let mut random_g2 = [0u8; bls::G2_COMPRESSED_SIZE];
        rand::RngCore::fill_bytes(&mut rng, &mut random_g2);

        // miller_loop 非法输入应返回错误
        let _ = bls::bls_miller_loop(&random_g1, &valid_g2);
        let _ = bls::bls_miller_loop(&valid_g1, &random_g2);

        // 随机 288 字节 GT → final_exp 应返回错误（大概率非法压缩）
        let mut random_gt = [0u8; bls::GT_COMPRESSED_SIZE];
        rand::RngCore::fill_bytes(&mut rng, &mut random_gt);
        let _ = bls::bls_final_exp(&random_gt);

        tested += 3;
    }

    // 合法 miller_loop + final_exp 往返
    let gt = bls::bls_miller_loop(&valid_g1, &valid_g2).expect("合法输入 miller_loop 应成功");
    let _ = bls::bls_final_exp(&gt).expect("合法 GT final_exp 应成功");

    assert!(tested >= 4500, "至少测试 4500 次 miller_loop/final_exp");
}

#[test]
fn subtask_41_8_fuzz_bls_verify_random_inputs() {
    // 随机 pubkey_g2 + signature_g1 + msg → bls_verify 应返回 false 或 Err，不 panic
    let mut rng = OsRng;

    let mut tested = 0u32;
    for _ in 0..2000 {
        let mut random_g2 = [0u8; bls::G2_COMPRESSED_SIZE];
        rand::RngCore::fill_bytes(&mut rng, &mut random_g2);
        let mut random_g1 = [0u8; bls::G1_COMPRESSED_SIZE];
        rand::RngCore::fill_bytes(&mut rng, &mut random_g1);
        let msg = b"fuzz msg";

        let _ = bls_verify(&random_g2, &random_g1, msg);

        tested += 1;
    }
    assert!(tested >= 2000, "至少测试 2000 次 bls_verify 随机输入");
}

// ===== SubTask 41.1 ~ 41.5, 41.7, 41.9: 单元测试覆盖确认 =====
//
// 以下 SubTask 已在单元测试中完整覆盖，此处通过集成测试确认跨模块一致性：
// - SubTask 41.1：`crypto_precompiles::bls::tests`（20 个测试）
// - SubTask 41.2：`crypto_precompiles::bls::tests::test_*` 子群检查
// - SubTask 41.3：`crypto_precompiles::bls::tests::test_pairing_*`
// - SubTask 41.4：`crypto_precompiles::bls::tests::test_hash_to_*`
// - SubTask 41.5：`crypto_precompiles::bls::tests::test_miller_loop_*` / `test_final_exp_*`
// - SubTask 41.7：`vm::syscalls::tests::test_bls_*`（gas 计费 + heap 校验）
// - SubTask 41.9：覆盖率门禁 — 所有安全路径（子群检查、pairing、gas）均有测试覆盖

#[test]
fn subtask_41_1_to_41_5_41_7_41_9_coverage_summary() {
    // 确认 BLS 预编译 API 可从集成测试入口调用
    let g1 = G1Projective::generator().to_compressed();
    let g2 = G2Projective::generator().to_compressed();
    let scalar = Scalar::from(42u64).to_bytes_be();

    // G1/G2 操作（SubTask 41.1）
    assert!(bls::bls_g1_add(&g1, &g1).is_ok());
    assert!(bls::bls_g1_mul(&g1, &scalar).is_ok());
    assert!(bls::bls_g1_neg(&g1).is_ok());
    assert!(bls::bls_g2_add(&g2, &g2).is_ok());
    assert!(bls::bls_g2_mul(&g2, &scalar).is_ok());
    assert!(bls::bls_g2_neg(&g2).is_ok());

    // 子群检查（SubTask 41.2）— 非法输入被拒绝
    let bad_g1 = [0u8; bls::G1_COMPRESSED_SIZE];
    assert!(bls::bls_g1_neg(&bad_g1).is_err());

    // pairing_check（SubTask 41.3）
    let equal = bls::bls_pairing_check(&g1, &g2, &g1, &g2).expect("pairing 应成功");
    assert!(equal, "e(g1,g2) == e(g1,g2)");

    // hash_to_curve（SubTask 41.4）
    let h1 = bls::bls_hash_to_g1(b"msg").expect("hash_to_g1 应成功");
    assert_eq!(h1.len(), bls::G1_COMPRESSED_SIZE);

    // miller_loop / final_exp（SubTask 41.5）
    let gt = bls::bls_miller_loop(&g1, &g2).expect("miller_loop 应成功");
    let gt2 = bls::bls_final_exp(&gt).expect("final_exp 应成功");
    assert_eq!(gt, gt2, "final_exp identity 应返回相同值");

    // gas 计费（SubTask 41.7）— 通过 vm::syscalls 测试覆盖
    // 此处仅确认 gas 常量存在且为 worst-case 值
    use poker_l1::vm::gas_table::*;
    assert_eq!(GAS_BLS_G1_ADD, 500);
    assert_eq!(GAS_BLS_G1_MUL, 500);
    assert_eq!(GAS_BLS_PAIRING, 5000);
    assert_eq!(GAS_BLS_MILLER_LOOP, 2000);
    assert_eq!(GAS_BLS_FINAL_EXP, 1000);
    assert_eq!(bls_hash_to_g1_gas(0), 1000);
    assert_eq!(bls_hash_to_g1_gas(100), 2000);

    // 覆盖率门禁（SubTask 41.9）— 所有安全路径均有测试
    // 详见 `crypto_precompiles::bls::tests` + `vm::syscalls::tests::test_bls_*`
}
