//! 真实 ECVRF-secp256k1-SHA256-TAI prover / verifier（缺口 #2 — IMPL-SEC-2）。
//!
//! 替换 [`super::validator_set::StubVrfVerifier`]（仅测试用）。基于 `vrf` crate 的
//! `SECP256K1_SHA256_TAI` 实现（draft-irtf-cfrg-vrf-05），后端为 OpenSSL。
//!
//! # proof 布局
//!
//! 规范 proof = `gamma_33B || c_16B || s_32B` = 81 字节（见 [`super::validator_set::VRF_PROOF_SIZE`]）。
//! [`VrfProof::to_bytes`] / [`VrfProof::from_bytes`] 产出与此完全一致的字节序列，
//! 故本模块直接把 `VrfProof` 序列化为 81 字节交给 `vrf` crate 的 `prove` / `verify`。
//!
//! # 密钥
//!
//! - VRF secret key：32 字节 secp256k1 标量（big-endian），由 validator 启动时加载。
//! - VRF public key：33 字节 compressed secp256k1 point，存于 [`ValidatorEntry::vrf_pubkey`]。
//!
//! `vrf` crate 的 `prove`/`verify` 接受 `&[u8]` 形式的 secret/public key（见
//! `vrf::VRF<&[u8], &[u8]>` impl）。secret key 传入 32 字节；public key 传入 33 字节
//! compressed point。`vrf` crate 内部用 OpenSSL `ECPoint::from_bytes` 解析。
//!
//! [`ValidatorEntry::vrf_pubkey`]: super::validator_set::ValidatorEntry::vrf_pubkey

use vrf::VRF;
use vrf::openssl::{CipherSuite, ECVRF};

use super::validator_set::{
    VRF_OUTPUT_SIZE, VRF_PROOF_SIZE, VRF_PUBKEY_SIZE, VrfProof, VrfVerifier,
};
use crate::error::{PokerL1Error, PokerL1Result};

/// VRF secret key 长度（secp256k1 标量 = 32 字节 big-endian）。
pub const VRF_SECRET_KEY_SIZE: usize = 32;

/// 真实 ECVRF-secp256k1-SHA256-TAI 验证器（生产用，替换 [`StubVrfVerifier`]）。
///
/// 无内部状态（`vrf::openssl::ECVRF` 每次调用 `from_slice` 构造），可自由 clone / Send + Sync。
///
/// [`StubVrfVerifier`]: super::validator_set::StubVrfVerifier
#[derive(Debug, Default, Clone, Copy)]
pub struct Secp256k1VrfVerifier;

impl Secp256k1VrfVerifier {
    /// 创建验证器。
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// 构造 ECVRF 引擎（SECP256K1_SHA256_TAI）。
    ///
    /// `ECVRF` 不实现 `Clone` / `Send`，故每次验证按需构造（开销可忽略，仅建 OpenSSL 上下文）。
    fn engine() -> PokerL1Result<ECVRF> {
        ECVRF::from_suite(CipherSuite::SECP256K1_SHA256_TAI)
            .map_err(|e| PokerL1Error::Other(format!("ECVRF engine init failed: {e}")))
    }
}

impl VrfVerifier for Secp256k1VrfVerifier {
    fn verify(
        &self,
        vrf_pubkey: &[u8; VRF_PUBKEY_SIZE],
        input: &[u8; VRF_OUTPUT_SIZE],
        proof: &VrfProof,
    ) -> PokerL1Result<[u8; VRF_OUTPUT_SIZE]> {
        let mut engine = Self::engine()?;
        // proof 序列化为 81 字节规范布局，交给 vrf crate 验证。
        let pi = proof.to_bytes();
        // vrf crate 的 verify(public_key=&[u8], pi=&[u8], alpha=&[u8]) -> Result<Vec<u8>, Error>。
        // 返回值即 VRF hash output（gamma_to_hash，32 字节 SHA-256）。
        let output_vec = engine
            .verify(vrf_pubkey.as_slice(), pi.as_slice(), input.as_slice())
            .map_err(|e| PokerL1Error::InvalidVrfProof(format!("ECVRF verify failed: {e}")))?;
        if output_vec.len() != VRF_OUTPUT_SIZE {
            return Err(PokerL1Error::InvalidVrfProof(format!(
                "ECVRF output length {} != expected {}",
                output_vec.len(),
                VRF_OUTPUT_SIZE
            )));
        }
        let mut out = [0u8; VRF_OUTPUT_SIZE];
        out.copy_from_slice(&output_vec);
        Ok(out)
    }
}

/// VRF prover（生成 proof）。validator 启动时用自身 VRF secret key 构造。
///
/// 与 [`Secp256k1VrfVerifier`] 对称：prover 持 32 字节 secret key，对 VRF input 生成
/// 81 字节 proof，供后续经 `submit_epoch_vrf_proof` 提交。
#[derive(Debug, Clone)]
pub struct Secp256k1VrfProver {
    /// 32 字节 secp256k1 secret key（big-endian 标量）。
    secret_key: [u8; VRF_SECRET_KEY_SIZE],
}

impl Secp256k1VrfProver {
    /// 从 32 字节 secret key 构造 prover。
    pub fn from_secret_bytes(secret_key: &[u8; VRF_SECRET_KEY_SIZE]) -> Self {
        Self {
            secret_key: *secret_key,
        }
    }

    /// 生成 VRF proof + random output（给定 VRF input）。
    ///
    /// 返回 `(proof, output)`：proof 为 81 字节规范布局的 [`VrfProof`]，
    /// output 为 32 字节 random output（与验证方 `verify` 返回值一致）。
    pub fn prove(
        &self,
        input: &[u8; VRF_OUTPUT_SIZE],
    ) -> PokerL1Result<(VrfProof, [u8; VRF_OUTPUT_SIZE])> {
        let mut engine = Secp256k1VrfVerifier::engine()?;
        let pi_vec = engine
            .prove(self.secret_key.as_slice(), input.as_slice())
            .map_err(|e| PokerL1Error::InvalidVrfProof(format!("ECVRF prove failed: {e}")))?;
        if pi_vec.len() != VRF_PROOF_SIZE {
            return Err(PokerL1Error::InvalidVrfProof(format!(
                "ECVRF proof length {} != expected {}",
                pi_vec.len(),
                VRF_PROOF_SIZE
            )));
        }
        let proof = VrfProof::from_bytes(&pi_vec)?;
        // 用 proof_to_hash 重新推导 output，确保与验证方一致（而非信任 prover 内部状态）。
        let output_vec = engine
            .proof_to_hash(pi_vec.as_slice())
            .map_err(|e| PokerL1Error::InvalidVrfProof(format!("proof_to_hash failed: {e}")))?;
        if output_vec.len() != VRF_OUTPUT_SIZE {
            return Err(PokerL1Error::InvalidVrfProof(format!(
                "ECVRF output length {} != expected {}",
                output_vec.len(),
                VRF_OUTPUT_SIZE
            )));
        }
        let mut output = [0u8; VRF_OUTPUT_SIZE];
        output.copy_from_slice(&output_vec);
        Ok((proof, output))
    }

    /// 从 secret key 派生 VRF public key（33 字节 compressed secp256k1）。
    ///
    /// 供 validator 启动时从 secret key 计算 `ValidatorEntry.vrf_pubkey`。
    pub fn derive_public_key(&self) -> PokerL1Result<[u8; VRF_PUBKEY_SIZE]> {
        let mut engine = Secp256k1VrfVerifier::engine()?;
        // vrf crate 提供 derive_public_key(secret_key) -> Vec<u8>（compressed point）。
        let pk_vec = engine
            .derive_public_key(self.secret_key.as_slice())
            .map_err(|e| PokerL1Error::InvalidVrfProof(format!("derive_public_key failed: {e}")))?;
        if pk_vec.len() != VRF_PUBKEY_SIZE {
            return Err(PokerL1Error::InvalidVrfProof(format!(
                "derived pubkey length {} != expected {}",
                pk_vec.len(),
                VRF_PUBKEY_SIZE
            )));
        }
        let mut pk = [0u8; VRF_PUBKEY_SIZE];
        pk.copy_from_slice(&pk_vec);
        Ok(pk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::validator_set::{VRF_PUBKEY_SIZE, compute_vrf_input, compute_vrf_output};

    /// 生成一对 (prover, pubkey) 用于测试。
    fn make_keypair(seed: u8) -> (Secp256k1VrfProver, [u8; VRF_PUBKEY_SIZE]) {
        let secret = [seed; VRF_SECRET_KEY_SIZE];
        let prover = Secp256k1VrfProver::from_secret_bytes(&secret);
        let pubkey = prover.derive_public_key().expect("derive pubkey");
        (prover, pubkey)
    }

    #[test]
    fn prover_verifier_roundtrip_valid() {
        // 端到端：prover 生成 → verifier 验证 → output 一致。
        let (prover, pubkey) = make_keypair(0x42);
        let prev_random = [0xAA; 32];
        let input = compute_vrf_input(crate::DEFAULT_CHAIN_ID, 1, &prev_random);

        let (proof, prover_output) = prover.prove(&input).expect("prove");
        let verifier = Secp256k1VrfVerifier::new();
        let verifier_output = verifier
            .verify(&pubkey, &input, &proof)
            .expect("verify 应通过");

        // 关键不变量：prover 与 verifier 得到相同的 random output。
        assert_eq!(
            prover_output, verifier_output,
            "prover 与 verifier 的 output 必须一致"
        );
        // output 不应等于 input（非 stub 行为）。
        assert_ne!(verifier_output, input, "真实 VRF output 不应等于 input");
    }

    #[test]
    fn verifier_rejects_wrong_pubkey() {
        // 用 prover A 的 pubkey 验证 → 应失败（pubkey 不匹配）。
        let (prover_a, _pubkey_a) = make_keypair(0x11);
        let (_prover_b, pubkey_b) = make_keypair(0x22);
        let input = compute_vrf_input(crate::DEFAULT_CHAIN_ID, 1, &[0xBB; 32]);
        let (proof, _) = prover_a.prove(&input).expect("prove A");

        let verifier = Secp256k1VrfVerifier::new();
        let err = verifier.verify(&pubkey_b, &input, &proof).unwrap_err();
        assert!(
            matches!(err, PokerL1Error::InvalidVrfProof(_)),
            "用错误 pubkey 验证应失败: {err:?}"
        );
    }

    #[test]
    fn verifier_rejects_wrong_input() {
        // proof 绑定 input，换 input 验证应失败。
        let (prover, pubkey) = make_keypair(0x33);
        let input_a = compute_vrf_input(crate::DEFAULT_CHAIN_ID, 1, &[0xCC; 32]);
        let input_b = compute_vrf_input(crate::DEFAULT_CHAIN_ID, 2, &[0xCC; 32]);
        let (proof, _) = prover.prove(&input_a).expect("prove");

        let verifier = Secp256k1VrfVerifier::new();
        let err = verifier.verify(&pubkey, &input_b, &proof).unwrap_err();
        assert!(
            matches!(err, PokerL1Error::InvalidVrfProof(_)),
            "用错误 input 验证应失败: {err:?}"
        );
    }

    #[test]
    fn proof_is_81_bytes() {
        // 回归：proof 规范布局 = 81 字节（缺口 #2 修正自旧 97 字节）。
        let (prover, _pubkey) = make_keypair(0x44);
        let input = compute_vrf_input(crate::DEFAULT_CHAIN_ID, 1, &[0xDD; 32]);
        let (proof, _) = prover.prove(&input).expect("prove");
        assert_eq!(proof.to_bytes().len(), VRF_PROOF_SIZE);
        assert_eq!(VRF_PROOF_SIZE, 81);
    }

    #[test]
    fn output_differs_for_different_inputs() {
        // 不同 input → 不同 output（VRF 随机性）。
        let (prover, pubkey) = make_keypair(0x55);
        let input1 = compute_vrf_input(crate::DEFAULT_CHAIN_ID, 1, &[0; 32]);
        let input2 = compute_vrf_input(crate::DEFAULT_CHAIN_ID, 2, &[0; 32]);
        let (proof1, _) = prover.prove(&input1).expect("prove1");
        let (proof2, _) = prover.prove(&input2).expect("prove2");

        let verifier = Secp256k1VrfVerifier::new();
        let out1 = verifier.verify(&pubkey, &input1, &proof1).unwrap();
        let out2 = verifier.verify(&pubkey, &input2, &proof2).unwrap();
        assert_ne!(out1, out2, "不同 input 应产生不同 output");
    }

    #[test]
    fn output_does_not_match_legacy_compute_vrf_output() {
        // 文档性回归：真实 ECVRF output（gamma_to_hash）与旧 placeholder
        // compute_vrf_output（自定义 blake2b）不同。确认两者分离，避免误用。
        let (prover, pubkey) = make_keypair(0x66);
        let input = compute_vrf_input(crate::DEFAULT_CHAIN_ID, 1, &[0xEE; 32]);
        let (proof, real_output) = prover.prove(&input).expect("prove");
        let legacy = compute_vrf_output(&pubkey, &input, &proof.gamma);
        assert_ne!(
            real_output, legacy,
            "真实 ECVRF output 与旧 placeholder 派生必须不同"
        );
    }
}
