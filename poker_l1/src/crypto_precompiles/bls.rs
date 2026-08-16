//! BLS12-381 原生预编译实现（Task 18 — SubTask 18.1 ~ 18.6）。
//!
//! 严格遵循 spec.md（FROZEN 2026-06-27）：
//! - **SubTask 18.1**：`bls12_381_g1_add` / `g1_mul` / `g1_neg`（含 G1 子群检查）
//! - **SubTask 18.2**：`bls12_381_g2_add` / `g2_mul` / `g2_neg`（含 G2 子群检查）
//! - **SubTask 18.3**：`bls12_381_pairing_check(a1, b1, a2, b2)`（4 输入子群检查 + worst-case gas）
//! - **SubTask 18.4**：`bls12_381_hash_to_g1` / `hash_to_g2`（RFC 9380，固定 DST）
//! - **SubTask 18.5**：`bls12_381_miller_loop` / `final_exp`
//! - **SubTask 18.6**：子群检查失败返回 `InvalidSubgroup` 错误
//!
//! # 安全说明
//!
//! 所有 G1/G2 输入通过 compressed bytes 反序列化，`from_compressed` 内部执行
//! 完整的点解码 + 子群成员检查。非子群元素在 pairing 之前被拒绝（DoS 防护）。
//!
//! # SEC2-L2 修复 — 固定 DST
//!
//! `hash_to_g1` / `hash_to_g2` 使用固定 DST，runtime 自动附加，不允许合约自定义：
//! - G1 DST = `POKER_L1_BLS12381G1_XMD:SHA-256_SSWU_RO_`
//! - G2 DST = `POKER_L1_BLS12381G2_XMD:SHA-256_SSWU_RO_`

use std::io::Cursor;

use blstrs::{Bls12, Compress, G1Projective, G2Prepared, G2Projective, Gt, Scalar};
use group::{Curve, Group};
use pairing::{MillerLoopResult as _, MultiMillerLoop};
use subtle::CtOption;

use crate::error::{PokerL1Error, PokerL1Result};

/// G1 compressed bytes 长度（48 字节）。
pub const G1_COMPRESSED_SIZE: usize = 48;
/// G2 compressed bytes 长度（96 字节）。
pub const G2_COMPRESSED_SIZE: usize = 96;
/// Scalar bytes 长度（32 字节）。
pub const SCALAR_SIZE: usize = 32;
/// GT（target group）compressed bytes 长度（288 字节 = 6 × 48，torus-based 压缩）。
pub const GT_COMPRESSED_SIZE: usize = 288;

/// SEC2-L2 修复 — G1 hash_to_curve 固定 DST（genesis 硬编码，治理不可更改）。
pub const BLS_G1_DST: &[u8] = b"POKER_L1_BLS12381G1_XMD:SHA-256_SSWU_RO_";
/// SEC2-L2 修复 — G2 hash_to_curve 固定 DST。
pub const BLS_G2_DST: &[u8] = b"POKER_L1_BLS12381G2_XMD:SHA-256_SSWU_RO_";

// ===== 辅助函数 =====

/// 将 `CtOption<T>` 转换为 `Option<T>`（常数时间结果转换为分支）。
fn ct_opt_to_opt<T>(ct: CtOption<T>) -> Option<T> {
    if bool::from(ct.is_some()) {
        Some(ct.unwrap())
    } else {
        None
    }
}

// ===== G1 操作（SubTask 18.1）=====

/// 反序列化 G1 compressed bytes（48 字节），含子群检查。
///
/// `from_compressed` 内部执行完整的点解码 + 子群成员检查。
/// 失败返回 `InvalidSubgroup`（非子群 / 不在曲线上）。
fn parse_g1(bytes: &[u8]) -> PokerL1Result<G1Projective> {
    if bytes.len() != G1_COMPRESSED_SIZE {
        return Err(PokerL1Error::InvalidBlsPoint(format!(
            "G1 compressed size mismatch: {} != {}",
            bytes.len(),
            G1_COMPRESSED_SIZE
        )));
    }
    let mut arr = [0u8; G1_COMPRESSED_SIZE];
    arr.copy_from_slice(bytes);
    ct_opt_to_opt(G1Projective::from_compressed(&arr)).ok_or(PokerL1Error::InvalidSubgroup(
        "G1 point failed subgroup check or not on curve",
    ))
}

/// 序列化 G1 点为 compressed bytes（48 字节）。
fn serialize_g1(point: &G1Projective) -> [u8; G1_COMPRESSED_SIZE] {
    point.to_compressed()
}

/// 反序列化 Scalar（32 字节，大端序）。
fn parse_scalar(bytes: &[u8]) -> PokerL1Result<Scalar> {
    if bytes.len() != SCALAR_SIZE {
        return Err(PokerL1Error::InvalidBlsScalar(format!(
            "scalar size mismatch: {} != {}",
            bytes.len(),
            SCALAR_SIZE
        )));
    }
    let mut arr = [0u8; SCALAR_SIZE];
    arr.copy_from_slice(bytes);
    ct_opt_to_opt(Scalar::from_bytes_be(&arr))
        .ok_or_else(|| PokerL1Error::InvalidBlsScalar("scalar reduction failed".to_string()))
}

/// `bls12_381_g1_add(a, b)` — G1 点加法（含子群检查）。
///
/// 两个输入均通过 `from_compressed` 执行子群检查。
/// gas = [`GAS_BLS_G1_ADD`](crate::vm::gas_table::GAS_BLS_G1_ADD) = 500。
pub fn bls_g1_add(a: &[u8], b: &[u8]) -> PokerL1Result<[u8; G1_COMPRESSED_SIZE]> {
    let pa = parse_g1(a)?;
    let pb = parse_g1(b)?;
    let result = pa + pb;
    Ok(serialize_g1(&result))
}

/// `bls12_381_g1_mul(point, scalar)` — G1 标量乘法（含子群检查）。
///
/// gas = [`GAS_BLS_G1_MUL`](crate::vm::gas_table::GAS_BLS_G1_MUL) = 500。
pub fn bls_g1_mul(point: &[u8], scalar: &[u8]) -> PokerL1Result<[u8; G1_COMPRESSED_SIZE]> {
    let p = parse_g1(point)?;
    let s = parse_scalar(scalar)?;
    let result = p * s;
    Ok(serialize_g1(&result))
}

/// `bls12_381_g1_neg(point)` — G1 取负（含子群检查）。
///
/// gas = [`GAS_BLS_G1_NEG`](crate::vm::gas_table::GAS_BLS_G1_NEG) = 500。
pub fn bls_g1_neg(point: &[u8]) -> PokerL1Result<[u8; G1_COMPRESSED_SIZE]> {
    let p = parse_g1(point)?;
    let result = -p;
    Ok(serialize_g1(&result))
}

// ===== G2 操作（SubTask 18.2）=====

/// 反序列化 G2 compressed bytes（96 字节），含子群检查。
fn parse_g2(bytes: &[u8]) -> PokerL1Result<G2Projective> {
    if bytes.len() != G2_COMPRESSED_SIZE {
        return Err(PokerL1Error::InvalidBlsPoint(format!(
            "G2 compressed size mismatch: {} != {}",
            bytes.len(),
            G2_COMPRESSED_SIZE
        )));
    }
    let mut arr = [0u8; G2_COMPRESSED_SIZE];
    arr.copy_from_slice(bytes);
    ct_opt_to_opt(G2Projective::from_compressed(&arr)).ok_or(PokerL1Error::InvalidSubgroup(
        "G2 point failed subgroup check or not on curve",
    ))
}

/// 序列化 G2 点为 compressed bytes（96 字节）。
fn serialize_g2(point: &G2Projective) -> [u8; G2_COMPRESSED_SIZE] {
    point.to_compressed()
}

/// `bls12_381_g2_add(a, b)` — G2 点加法（含子群检查）。
///
/// gas = [`GAS_BLS_G2_ADD`](crate::vm::gas_table::GAS_BLS_G2_ADD) = 500。
pub fn bls_g2_add(a: &[u8], b: &[u8]) -> PokerL1Result<[u8; G2_COMPRESSED_SIZE]> {
    let pa = parse_g2(a)?;
    let pb = parse_g2(b)?;
    let result = pa + pb;
    Ok(serialize_g2(&result))
}

/// `bls12_381_g2_mul(point, scalar)` — G2 标量乘法（含子群检查）。
///
/// gas = [`GAS_BLS_G2_MUL`](crate::vm::gas_table::GAS_BLS_G2_MUL) = 500。
pub fn bls_g2_mul(point: &[u8], scalar: &[u8]) -> PokerL1Result<[u8; G2_COMPRESSED_SIZE]> {
    let p = parse_g2(point)?;
    let s = parse_scalar(scalar)?;
    let result = p * s;
    Ok(serialize_g2(&result))
}

/// `bls12_381_g2_neg(point)` — G2 取负（含子群检查）。
///
/// gas = [`GAS_BLS_G2_NEG`](crate::vm::gas_table::GAS_BLS_G2_NEG) = 500。
pub fn bls_g2_neg(point: &[u8]) -> PokerL1Result<[u8; G2_COMPRESSED_SIZE]> {
    let p = parse_g2(point)?;
    let result = -p;
    Ok(serialize_g2(&result))
}

// ===== Pairing（SubTask 18.3）=====

/// `bls12_381_pairing_check(a_g1, b_g2, c_g1, d_g2)` — 双线性配对检查。
///
/// 对所有 4 个输入做子群检查（G1/G2 `from_compressed` 内含），
/// 失败返回 `InvalidSubgroup`（DoS 防护 — 在 pairing 之前拒绝）。
/// 通过后返回 `e(a, b) == e(c, d)` 布尔结果。
///
/// gas = [`GAS_BLS_PAIRING`](crate::vm::gas_table::GAS_BLS_PAIRING) = 5000（worst-case）。
pub fn bls_pairing_check(
    a_g1: &[u8],
    b_g2: &[u8],
    c_g1: &[u8],
    d_g2: &[u8],
) -> PokerL1Result<bool> {
    let a = parse_g1(a_g1)?.to_affine();
    let b = G2Prepared::from(parse_g2(b_g2)?.to_affine());
    let neg_c = (-parse_g1(c_g1)?).to_affine();
    let d = G2Prepared::from(parse_g2(d_g2)?.to_affine());

    // e(a, b) == e(c, d)  <=>  e(a, b) * e(-c, d) == identity
    let ml = Bls12::multi_miller_loop(&[(&a, &b), (&neg_c, &d)]);
    let result = ml.final_exponentiation();

    Ok(bool::from(result.is_identity()))
}

// ===== Hash-to-curve（SubTask 18.4）=====

/// `bls12_381_hash_to_g1(msg)` — RFC 9380 hash to G1。
///
/// SEC2-L2 修复：DST 固定为 [`BLS_G1_DST`]，runtime 自动附加，不允许合约自定义。
/// gas = `1000 + 10 * msg.len()`；msg > 65536 字节返回 `InputTooLong`。
pub fn bls_hash_to_g1(msg: &[u8]) -> PokerL1Result<[u8; G1_COMPRESSED_SIZE]> {
    crate::vm::gas_table::check_bls_hash_msg_len(msg.len() as u64)?;
    let point = G1Projective::hash_to_curve(msg, BLS_G1_DST, &[]);
    Ok(serialize_g1(&point))
}

/// `bls12_381_hash_to_g2(msg)` — RFC 9380 hash to G2。
///
/// SEC2-L2 修复：DST 固定为 [`BLS_G2_DST`]，runtime 自动附加，不允许合约自定义。
/// gas = `1000 + 10 * msg.len()`；msg > 65536 字节返回 `InputTooLong`。
pub fn bls_hash_to_g2(msg: &[u8]) -> PokerL1Result<[u8; G2_COMPRESSED_SIZE]> {
    crate::vm::gas_table::check_bls_hash_msg_len(msg.len() as u64)?;
    let point = G2Projective::hash_to_curve(msg, BLS_G2_DST, &[]);
    Ok(serialize_g2(&point))
}

// ===== Miller loop / Final exp（SubTask 18.5）=====

/// 序列化 GT 为 compressed bytes（288 字节，torus-based 压缩）。
fn serialize_gt(gt: &Gt) -> [u8; GT_COMPRESSED_SIZE] {
    let mut buf = [0u8; GT_COMPRESSED_SIZE];
    gt.write_compressed(Cursor::new(&mut buf[..]))
        .expect("GT serialization should not fail with sufficient buffer");
    buf
}

/// 反序列化 GT compressed bytes（288 字节）。
fn parse_gt(bytes: &[u8]) -> PokerL1Result<Gt> {
    if bytes.len() != GT_COMPRESSED_SIZE {
        return Err(PokerL1Error::InvalidBlsPoint(format!(
            "GT compressed size mismatch: {} != {}",
            bytes.len(),
            GT_COMPRESSED_SIZE
        )));
    }
    Gt::read_compressed(Cursor::new(bytes))
        .map_err(|e| PokerL1Error::InvalidBlsPoint(format!("GT deserialization failed: {e}")))
}

/// `bls12_381_miller_loop(a_g1, b_g2)` — Miller loop + final exponentiation。
///
/// 注意：blstrs 的 `MillerLoopResult` 不可序列化，因此本函数执行完整的
/// miller_loop + final_exponentiation 并返回 `Gt` compressed bytes。
/// 调用方如需 multi-pairing，应使用 `bls_pairing_check`。
/// gas = [`GAS_BLS_MILLER_LOOP`](crate::vm::gas_table::GAS_BLS_MILLER_LOOP) = 2000。
pub fn bls_miller_loop(a_g1: &[u8], b_g2: &[u8]) -> PokerL1Result<[u8; GT_COMPRESSED_SIZE]> {
    let a = parse_g1(a_g1)?.to_affine();
    let b = G2Prepared::from(parse_g2(b_g2)?.to_affine());
    let ml = Bls12::multi_miller_loop(&[(&a, &b)]);
    let result = ml.final_exponentiation();
    Ok(serialize_gt(&result))
}

/// `bls12_381_final_exp(gt)` — Final exponentiation（identity，因 miller_loop 已含）。
///
/// 由于 `miller_loop` 已执行完整 pairing，本函数为 identity（仅校验 GT 反序列化）。
/// 保留此 syscall 以满足 SubTask 18.5 API 完整性要求。
/// gas = [`GAS_BLS_FINAL_EXP`](crate::vm::gas_table::GAS_BLS_FINAL_EXP) = 1000。
pub fn bls_final_exp(gt: &[u8]) -> PokerL1Result<[u8; GT_COMPRESSED_SIZE]> {
    let parsed = parse_gt(gt)?;
    Ok(serialize_gt(&parsed))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 生成测试用 G1 生成元。
    fn g1_generator() -> G1Projective {
        G1Projective::generator()
    }

    /// 生成测试用 G2 生成元。
    fn g2_generator() -> G2Projective {
        G2Projective::generator()
    }

    /// 生成测试用 scalar = 2。
    fn scalar_two() -> [u8; SCALAR_SIZE] {
        let s = Scalar::from(2u64);
        let be = s.to_bytes_be();
        let mut arr = [0u8; SCALAR_SIZE];
        arr.copy_from_slice(&be);
        arr
    }

    // ===== SubTask 18.1: G1 操作 =====

    #[test]
    fn test_g1_add_basic() {
        let g = g1_generator();
        let g_bytes = serialize_g1(&g);
        let result = bls_g1_add(&g_bytes, &g_bytes).expect("G1 add 应成功");
        let sum = parse_g1(&result).expect("结果应可反序列化");
        let expected = g + g;
        assert_eq!(sum, expected);
    }

    #[test]
    fn test_g1_mul_basic() {
        let g = g1_generator();
        let g_bytes = serialize_g1(&g);
        let s = scalar_two();
        let result = bls_g1_mul(&g_bytes, &s).expect("G1 mul 应成功");
        let product = parse_g1(&result).expect("结果应可反序列化");
        let expected = g * Scalar::from(2u64);
        assert_eq!(product, expected);
    }

    #[test]
    fn test_g1_neg_basic() {
        let g = g1_generator();
        let g_bytes = serialize_g1(&g);
        let result = bls_g1_neg(&g_bytes).expect("G1 neg 应成功");
        let neg = parse_g1(&result).expect("结果应可反序列化");
        assert_eq!(neg, -g);
    }

    #[test]
    fn test_g1_compressed_roundtrip() {
        let g = g1_generator();
        let bytes = serialize_g1(&g);
        assert_eq!(bytes.len(), G1_COMPRESSED_SIZE);
        let restored = parse_g1(&bytes).expect("往返应成功");
        assert_eq!(restored, g);
    }

    // ===== SubTask 18.2: G2 操作 =====

    #[test]
    fn test_g2_add_basic() {
        let g = g2_generator();
        let g_bytes = serialize_g2(&g);
        let result = bls_g2_add(&g_bytes, &g_bytes).expect("G2 add 应成功");
        let sum = parse_g2(&result).expect("结果应可反序列化");
        assert_eq!(sum, g + g);
    }

    #[test]
    fn test_g2_mul_basic() {
        let g = g2_generator();
        let g_bytes = serialize_g2(&g);
        let s = scalar_two();
        let result = bls_g2_mul(&g_bytes, &s).expect("G2 mul 应成功");
        let product = parse_g2(&result).expect("结果应可反序列化");
        assert_eq!(product, g * Scalar::from(2u64));
    }

    #[test]
    fn test_g2_neg_basic() {
        let g = g2_generator();
        let g_bytes = serialize_g2(&g);
        let result = bls_g2_neg(&g_bytes).expect("G2 neg 应成功");
        let neg = parse_g2(&result).expect("结果应可反序列化");
        assert_eq!(neg, -g);
    }

    #[test]
    fn test_g2_compressed_roundtrip() {
        let g = g2_generator();
        let bytes = serialize_g2(&g);
        assert_eq!(bytes.len(), G2_COMPRESSED_SIZE);
        let restored = parse_g2(&bytes).expect("往返应成功");
        assert_eq!(restored, g);
    }

    // ===== SubTask 18.3: Pairing =====

    #[test]
    fn test_pairing_check_equal() {
        // e(g1, g2) == e(g1, g2) → true
        let g1 = serialize_g1(&g1_generator());
        let g2 = serialize_g2(&g2_generator());
        let result = bls_pairing_check(&g1, &g2, &g1, &g2).expect("pairing 应成功");
        assert!(result, "e(g1,g2) == e(g1,g2) 应为 true");
    }

    #[test]
    fn test_pairing_check_unequal() {
        // e(g1, g2) == e(2*g1, g2) → false (因为 e(2g1, g2) = e(g1, g2)^2)
        let g1 = serialize_g1(&g1_generator());
        let g2 = serialize_g2(&g2_generator());
        let g1_double = serialize_g1(&(g1_generator() * Scalar::from(2u64)));
        let result = bls_pairing_check(&g1, &g2, &g1_double, &g2).expect("pairing 应成功");
        assert!(!result, "e(g1,g2) != e(2g1,g2) 应为 false");
    }

    #[test]
    fn test_pairing_bilinearity() {
        // e(a*g1, g2) == e(g1, a*g2) → true (双线性)
        let a = Scalar::from(3u64);
        let g1 = g1_generator();
        let g2 = g2_generator();
        let a_g1 = serialize_g1(&(g1 * a));
        let a_g2 = serialize_g2(&(g2 * a));
        let g1_bytes = serialize_g1(&g1);
        let g2_bytes = serialize_g2(&g2);
        let result = bls_pairing_check(&a_g1, &g2_bytes, &g1_bytes, &a_g2).expect("pairing 应成功");
        assert!(result, "e(a*g1, g2) == e(g1, a*g2) 双线性应成立");
    }

    // ===== SubTask 18.4: Hash-to-curve =====

    #[test]
    fn test_hash_to_g1_basic() {
        let msg = b"hello world";
        let result = bls_hash_to_g1(msg).expect("hash_to_g1 应成功");
        assert_eq!(result.len(), G1_COMPRESSED_SIZE);
        // 相同 msg 应确定性输出
        let result2 = bls_hash_to_g1(msg).expect("第二次 hash 应成功");
        assert_eq!(result, result2, "相同 msg 应得到相同 G1 点");
    }

    #[test]
    fn test_hash_to_g2_basic() {
        let msg = b"hello world";
        let result = bls_hash_to_g2(msg).expect("hash_to_g2 应成功");
        assert_eq!(result.len(), G2_COMPRESSED_SIZE);
        let result2 = bls_hash_to_g2(msg).expect("第二次 hash 应成功");
        assert_eq!(result, result2, "相同 msg 应得到相同 G2 点");
    }

    #[test]
    fn test_hash_to_g1_dst_fixed() {
        // SEC2-L2：DST 固定，相同 msg 总是确定性输出
        let msg = b"test message";
        let r1 = bls_hash_to_g1(msg).unwrap();
        let r2 = bls_hash_to_g1(msg).unwrap();
        assert_eq!(r1, r2);

        // 不同 msg 应产生不同结果
        let r3 = bls_hash_to_g1(b"different").unwrap();
        assert_ne!(r1, r3, "不同 msg 应产生不同 G1 点");
    }

    #[test]
    fn test_hash_too_long_msg_rejected() {
        let long_msg = vec![0u8; 65_537]; // > 65536
        let result = bls_hash_to_g1(&long_msg);
        assert!(
            matches!(result, Err(PokerL1Error::InputTooLong { .. })),
            "超长 msg 应返回 InputTooLong"
        );

        let result2 = bls_hash_to_g2(&long_msg);
        assert!(
            matches!(result2, Err(PokerL1Error::InputTooLong { .. })),
            "超长 msg 应返回 InputTooLong"
        );
    }

    // ===== SubTask 18.5: Miller loop / Final exp =====

    #[test]
    fn test_miller_loop_basic() {
        let g1 = serialize_g1(&g1_generator());
        let g2 = serialize_g2(&g2_generator());
        let result = bls_miller_loop(&g1, &g2).expect("miller_loop 应成功");
        assert_eq!(result.len(), GT_COMPRESSED_SIZE);
    }

    #[test]
    fn test_final_exp_identity() {
        let g1 = serialize_g1(&g1_generator());
        let g2 = serialize_g2(&g2_generator());
        let gt = bls_miller_loop(&g1, &g2).expect("miller_loop 应成功");
        let result = bls_final_exp(&gt).expect("final_exp 应成功");
        assert_eq!(result, gt, "final_exp identity 应返回相同值");
    }

    // ===== SubTask 18.6: 子群检查 =====

    #[test]
    fn test_invalid_g1_length_rejected() {
        let bad = [0u8; 47]; // 错误长度
        let result = bls_g1_add(&bad, &bad);
        assert!(matches!(result, Err(PokerL1Error::InvalidBlsPoint(_))));

        let result2 = bls_g1_mul(&bad, &[0u8; SCALAR_SIZE]);
        assert!(matches!(result2, Err(PokerL1Error::InvalidBlsPoint(_))));
    }

    #[test]
    fn test_invalid_g2_length_rejected() {
        let bad = [0u8; 95]; // 错误长度
        let result = bls_g2_add(&bad, &bad);
        assert!(matches!(result, Err(PokerL1Error::InvalidBlsPoint(_))));
    }

    #[test]
    fn test_zero_bytes_rejected() {
        // 全零 bytes 不是合法的 compressed point
        let zero_g1 = [0u8; G1_COMPRESSED_SIZE];
        let result = bls_g1_neg(&zero_g1);
        assert!(result.is_err(), "全零 G1 compressed 应被拒绝（不在曲线上）");

        let zero_g2 = [0u8; G2_COMPRESSED_SIZE];
        let result2 = bls_g2_neg(&zero_g2);
        assert!(
            result2.is_err(),
            "全零 G2 compressed 应被拒绝（不在曲线上）"
        );
    }

    #[test]
    fn test_invalid_scalar_length_rejected() {
        let g = serialize_g1(&g1_generator());
        let bad_scalar = [0u8; 31]; // 错误长度
        let result = bls_g1_mul(&g, &bad_scalar);
        assert!(matches!(result, Err(PokerL1Error::InvalidBlsScalar(_))));
    }

    #[test]
    fn test_pairing_invalid_input_rejected_before_computation() {
        // 非法 G1 输入应在 pairing 之前被拒绝（DoS 防护）
        let bad_g1 = [0u8; G1_COMPRESSED_SIZE];
        let g2 = serialize_g2(&g2_generator());
        let good_g1 = serialize_g1(&g1_generator());

        let result = bls_pairing_check(&bad_g1, &g2, &good_g1, &g2);
        assert!(result.is_err(), "非法 G1 应在 pairing 之前被拒绝");
    }
}
