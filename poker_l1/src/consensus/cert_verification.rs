//! Commit certificate 签名验证（P05-H-source）。
//!
//! 现有 [`super::bullshark::validate_commit_certificate_quorum`] 仅校验
//! `signer_bitmap` 置位数是否 ≥ 2/3，不验证 secp256k1 签名本身。本模块补全这一缺口：
//! [`verify_commit_certificate_signatures`] 把 `signer_bitmap` 的置位（升序）与
//! `signature_list` 紧凑对应，逐签名用调用方提供的验证闭包校验，并去重防同一 validator
//! 多签刷 quorum。
//!
//! 镜像 [`crate::network::verify_light_client_header`] 的去重 + quorum + 逐签名模式，
//! 适配 `DagCommitCertificate` 的 `bitmap + 签名列表` 布局。

use std::collections::BTreeSet;

use super::DagCommitCertificate;
use super::validator_set::ValidatorEntry;
use crate::error::{PokerL1Error, PokerL1Result};
use crate::signature::TaggedPubkey;
use crate::{BlockHeight, ChainId, Hash, TimestampMs};

/// 校验 `DagCommitCertificate` 的 secp256k1 quorum 签名。
///
/// 步骤：
/// 1. 复用 [`super::bullshark::validate_commit_certificate_quorum`] 校验置位数 ≥ 2/3。
/// 2. 把 `signer_bitmap` 的置位（升序）与 `signature_list` 紧凑对应：置位数必须等于
///    `signature_list.len()`，否则返回 [`PokerL1Error::CommitCertSignatureBitmapMismatch`]。
/// 3. 对每个 `(validator_pubkey, sig, signing_hash)` 调用 `verify_fn`；任一失败返回
///    [`PokerL1Error::InvalidCommitCertificateSignature`]。
/// 4. 用 [`BTreeSet`] 去重 validator 索引，防同一 validator 多签刷 quorum。
///
/// # 参数
///
/// - `cert`：待验证的 commit certificate。
/// - `chain_id`：链 ID（进入 `signing_hash`）。
/// - `validators`：当前 validator 集，`signer_bitmap` 的 bit `i` 对应 `validators[i]`。
///   传入切片以避免强依赖 `ValidatorSet` 全结构。
/// - `verify_fn`：签名验证闭包，签名通过返回 `Ok(())`。生产路径传
///   [`crate::signature::unified::verify_signature`]。
///
/// # Errors
///
/// - [`PokerL1Error::InsufficientQuorum`]：置位数 < 2/3。
/// - [`PokerL1Error::CommitCertSignatureBitmapMismatch`]：置位数 ≠ `signature_list.len()`。
/// - [`PokerL1Error::DuplicateCommitCertificateSigner`]：同一 validator 索引出现多次。
/// - [`PokerL1Error::InvalidCommitCertificateSignature`]：某签名验证失败。
/// - 索引越界返回带上下文的 `InvalidCommitCertificateSignature`。
pub fn verify_commit_certificate_signatures(
    cert: &DagCommitCertificate,
    chain_id: ChainId,
    validators: &[ValidatorEntry],
    verify_fn: impl Fn(&TaggedPubkey, &[u8], &[u8; 32]) -> PokerL1Result<()>,
) -> PokerL1Result<()> {
    let validator_pubkeys: Vec<TaggedPubkey> = validators
        .iter()
        .map(|entry| entry.pubkey.clone())
        .collect();
    verify_commit_certificate_pubkey_signatures(cert, chain_id, &validator_pubkeys, verify_fn)
}

/// Strictly verify a certificate against the canonical bitmap-indexed pubkey list.
///
/// Unlike the legacy block-validator implementation, this enumerates every set bit before
/// accepting the certificate. A bit beyond `validator_pubkeys.len()` is therefore rejected and
/// cannot inflate quorum without a corresponding validator signature.
pub fn verify_commit_certificate_pubkey_signatures(
    cert: &DagCommitCertificate,
    chain_id: ChainId,
    validator_pubkeys: &[TaggedPubkey],
    verify_fn: impl Fn(&TaggedPubkey, &[u8], &[u8; 32]) -> PokerL1Result<()>,
) -> PokerL1Result<()> {
    let msg_hash = cert.signing_hash(chain_id);
    verify_commit_certificate_pubkey_signatures_with_hash(
        cert,
        validator_pubkeys,
        msg_hash,
        verify_fn,
    )
}

/// Verify a production certificate whose signatures bind the complete block-header position.
pub fn verify_commit_certificate_pubkey_signatures_for_header(
    cert: &DagCommitCertificate,
    chain_id: ChainId,
    height: BlockHeight,
    timestamp_ms: TimestampMs,
    prev_hash: Hash,
    validator_pubkeys: &[TaggedPubkey],
    verify_fn: impl Fn(&TaggedPubkey, &[u8], &[u8; 32]) -> PokerL1Result<()>,
) -> PokerL1Result<()> {
    let msg_hash = cert.signing_hash_for_header(chain_id, height, timestamp_ms, prev_hash);
    verify_commit_certificate_pubkey_signatures_with_hash(
        cert,
        validator_pubkeys,
        msg_hash,
        verify_fn,
    )
}

fn verify_commit_certificate_pubkey_signatures_with_hash(
    cert: &DagCommitCertificate,
    validator_pubkeys: &[TaggedPubkey],
    msg_hash: Hash,
    verify_fn: impl Fn(&TaggedPubkey, &[u8], &[u8; 32]) -> PokerL1Result<()>,
) -> PokerL1Result<()> {
    // 1. 复用现有 2/3 计数校验。
    super::bullshark::validate_commit_certificate_quorum(cert, validator_pubkeys.len())?;

    // 2. signer_bitmap 置位（升序）必须与 signature_list 紧凑对应。
    let signer_indices: Vec<usize> = bitmap_set_bits(&cert.signer_bitmap);
    if signer_indices.len() != cert.signature_list.len() {
        return Err(PokerL1Error::CommitCertSignatureBitmapMismatch {
            bitmap_count: signer_indices.len(),
            sig_count: cert.signature_list.len(),
        });
    }

    // 3. 逐签名验证 + 去重。
    let mut seen: BTreeSet<usize> = BTreeSet::new();
    for (list_pos, &validator_idx) in signer_indices.iter().enumerate() {
        // 索引越界：bitmap 引用了不存在的 validator。归并为签名验证失败以便上层统一处理。
        let validator_pubkey = validator_pubkeys.get(validator_idx).ok_or(
            PokerL1Error::InvalidCommitCertificateSignature {
                signer_idx: validator_idx,
            },
        )?;

        // 去重：同一 validator 索引不得出现两次。
        if !seen.insert(validator_idx) {
            return Err(PokerL1Error::DuplicateCommitCertificateSigner {
                signer_idx: validator_idx,
            });
        }

        let sig = &cert.signature_list[list_pos];
        verify_fn(validator_pubkey, sig, &msg_hash).map_err(|_| {
            PokerL1Error::InvalidCommitCertificateSignature {
                signer_idx: validator_idx,
            }
        })?;
    }

    Ok(())
}

/// 升序枚举 `bitmap` 中所有置位的 bit 索引。
///
/// `bitmap` 按小端字节序解释：字节 `b` 的第 `i` 位对应全局索引 `b * 8 + i`。
/// 与 [`DagCommitCertificate::signer_count`] 的计数口径一致。
fn bitmap_set_bits(bitmap: &[u8]) -> Vec<usize> {
    let mut indices = Vec::new();
    for (byte_idx, &byte) in bitmap.iter().enumerate() {
        let mut bits = byte;
        while bits != 0 {
            // 最低置位位的局部偏移。
            let bit_offset = bits.trailing_zeros() as usize;
            indices.push(byte_idx * 8 + bit_offset);
            // 清除该位。
            bits &= bits - 1;
        }
    }
    indices
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Hash;
    use crate::consensus::DagCommitCertificate;
    use crate::consensus::bullshark::assemble_commit_certificate;
    use crate::signature::tagged_pubkey::{SignatureScheme, TaggedPubkey};
    use crate::signature::{ed25519_scheme, secp256k1_scheme};
    use secp256k1::{Message, Secp256k1, SecretKey};
    use std::collections::BTreeMap;

    /// 构造 N 个 secp256k1 validator（全部 Active）。
    fn make_validators(n: usize) -> (Vec<ValidatorEntry>, Vec<SecretKey>) {
        let secp = Secp256k1::new();
        let mut entries = Vec::new();
        let mut secrets = Vec::new();
        for _ in 0..n {
            let (sk, pk) = secp.generate_keypair(&mut rand::rngs::OsRng);
            let tagged = TaggedPubkey::new(
                SignatureScheme::Secp256k1,
                crate::signature::tagged_pubkey::CURRENT_VERSION,
                pk.serialize().to_vec(),
            )
            .unwrap();
            // VRF pubkey 字段对本测试无关，填零。
            entries.push(ValidatorEntry::new(tagged, [0u8; 33], 1000, 0));
            secrets.push(sk);
        }
        (entries, secrets)
    }

    /// 构造一个 cert，由 `signer_secrets` 中每个 key 对 `signing_hash(chain_id)` 签名。
    ///
    /// 签名格式与生产一致：`sign_ecdsa_recoverable` → `r||s||v`（65 字节，v ∈ {0,1}），
    /// 即 [`crate::signature::secp256k1_scheme::SECP256K1_SIG_LEN`] 要求的格式。
    fn make_signed_cert(
        validators: &[ValidatorEntry],
        signer_secrets: &[(usize, SecretKey)],
        roots: (Hash, Hash, Hash),
        chain_id: ChainId,
    ) -> DagCommitCertificate {
        let secp = Secp256k1::new();
        // 用给定 roots 构造一个临时 cert 仅用于算 signing_hash。
        let placeholder = assemble_commit_certificate(
            1,
            1,
            [0u8; 32],
            vec![],
            vec![],
            roots.0,
            [0u8; 32],
            roots.1,
            roots.2,
            &[],
            validators.len(),
        )
        .unwrap();
        let msg = placeholder.signing_hash(chain_id);
        let mut sigs: BTreeMap<usize, Vec<u8>> = BTreeMap::new();
        for &(idx, ref sk) in signer_secrets {
            let sig = secp.sign_ecdsa_recoverable(&Message::from_digest(msg), sk);
            let (rid, compact) = sig.serialize_compact();
            let mut full = compact.to_vec();
            full.push(rid.to_i32() as u8);
            sigs.insert(idx, full);
        }
        let sig_pairs: Vec<(usize, Vec<u8>)> = sigs.into_iter().collect();
        assemble_commit_certificate(
            1,
            1,
            [0u8; 32],
            vec![],
            vec![],
            roots.0,
            [0u8; 32],
            roots.1,
            roots.2,
            &sig_pairs,
            validators.len(),
        )
        .unwrap()
    }

    /// 构造绑定完整 block-header 位置的生产证书。
    fn make_header_bound_signed_cert(
        validators: &[ValidatorEntry],
        signer_secrets: &[(usize, SecretKey)],
        roots: (Hash, Hash, Hash),
        chain_id: ChainId,
        height: BlockHeight,
        timestamp_ms: TimestampMs,
        prev_hash: Hash,
    ) -> DagCommitCertificate {
        let secp = Secp256k1::new();
        let placeholder = assemble_commit_certificate(
            1,
            1,
            [0u8; 32],
            vec![],
            vec![],
            roots.0,
            [0u8; 32],
            roots.1,
            roots.2,
            &[],
            validators.len(),
        )
        .unwrap();
        let msg = placeholder.signing_hash_for_header(chain_id, height, timestamp_ms, prev_hash);
        let mut sigs: BTreeMap<usize, Vec<u8>> = BTreeMap::new();
        for &(idx, ref sk) in signer_secrets {
            let sig = secp.sign_ecdsa_recoverable(&Message::from_digest(msg), sk);
            let (rid, compact) = sig.serialize_compact();
            let mut full = compact.to_vec();
            full.push(rid.to_i32() as u8);
            sigs.insert(idx, full);
        }
        let sig_pairs: Vec<(usize, Vec<u8>)> = sigs.into_iter().collect();
        assemble_commit_certificate(
            1,
            1,
            [0u8; 32],
            vec![],
            vec![],
            roots.0,
            [0u8; 32],
            roots.1,
            roots.2,
            &sig_pairs,
            validators.len(),
        )
        .unwrap()
    }

    #[test]
    fn header_bound_certificate_rejects_header_transplant() {
        let (validators, secrets) = make_validators(5); // quorum = 4
        let signer_secrets: Vec<(usize, SecretKey)> = (0..4).map(|i| (i, secrets[i])).collect();
        let chain_id = crate::DEFAULT_CHAIN_ID;
        let height = 42;
        let timestamp_ms = 123_456;
        let prev_hash = [0xA5; 32];
        let cert = make_header_bound_signed_cert(
            &validators,
            &signer_secrets,
            ([1u8; 32], [2u8; 32], [3u8; 32]),
            chain_id,
            height,
            timestamp_ms,
            prev_hash,
        );

        let verify = |height, timestamp_ms, prev_hash| {
            verify_commit_certificate_pubkey_signatures_for_header(
                &cert,
                chain_id,
                height,
                timestamp_ms,
                prev_hash,
                &validators
                    .iter()
                    .map(|entry| entry.pubkey.clone())
                    .collect::<Vec<_>>(),
                secp256k1_scheme::verify,
            )
        };

        assert!(verify(height, timestamp_ms, prev_hash).is_ok());
        assert!(verify(height + 1, timestamp_ms, prev_hash).is_err());
        assert!(verify(height, timestamp_ms + 1, prev_hash).is_err());
        assert!(verify(height, timestamp_ms, [0x5A; 32]).is_err());
    }

    #[test]
    fn valid_quorum_signatures_pass() {
        let (validators, secrets) = make_validators(5); // 2/3 of 5 = 4
        let signer_secrets: Vec<(usize, SecretKey)> = (0..4).map(|i| (i, secrets[i])).collect();
        let cert = make_signed_cert(
            &validators,
            &signer_secrets,
            ([1u8; 32], [2u8; 32], [3u8; 32]),
            crate::DEFAULT_CHAIN_ID,
        );
        assert!(
            verify_commit_certificate_signatures(
                &cert,
                crate::DEFAULT_CHAIN_ID,
                &validators,
                secp256k1_scheme::verify,
            )
            .is_ok()
        );
    }

    #[test]
    fn insufficient_quorum_fails() {
        let (validators, secrets) = make_validators(6); // 2/3 of 6 = 4
        let signer_secrets: Vec<(usize, SecretKey)> = (0..3).map(|i| (i, secrets[i])).collect(); // only 3 < 4
        let cert = make_signed_cert(
            &validators,
            &signer_secrets,
            ([1u8; 32], [2u8; 32], [3u8; 32]),
            crate::DEFAULT_CHAIN_ID,
        );
        assert!(matches!(
            verify_commit_certificate_signatures(
                &cert,
                crate::DEFAULT_CHAIN_ID,
                &validators,
                secp256k1_scheme::verify,
            ),
            Err(PokerL1Error::InsufficientQuorum { .. })
        ));
    }

    #[test]
    fn wrong_message_hash_fails() {
        let (validators, secrets) = make_validators(5);
        let signer_secrets: Vec<(usize, SecretKey)> = (0..4).map(|i| (i, secrets[i])).collect();
        // 签名用 DEFAULT_CHAIN_ID，但验证用不同 chain_id → signing_hash 不同。
        let cert = make_signed_cert(
            &validators,
            &signer_secrets,
            ([1u8; 32], [2u8; 32], [3u8; 32]),
            crate::DEFAULT_CHAIN_ID,
        );
        assert!(matches!(
            verify_commit_certificate_signatures(
                &cert,
                0xDEAD_BEEF,
                &validators,
                secp256k1_scheme::verify,
            ),
            Err(PokerL1Error::InvalidCommitCertificateSignature { .. })
        ));
    }

    #[test]
    fn bitmap_signature_list_length_mismatch_fails() {
        let (validators, secrets) = make_validators(5);
        let signer_secrets: Vec<(usize, SecretKey)> = (0..4).map(|i| (i, secrets[i])).collect();
        let mut cert = make_signed_cert(
            &validators,
            &signer_secrets,
            ([1u8; 32], [2u8; 32], [3u8; 32]),
            crate::DEFAULT_CHAIN_ID,
        );
        // 人为多塞一个签名 → bitmap 置位数(4) != signature_list.len()(5)。
        cert.signature_list.push(vec![0u8; 64]);
        assert!(matches!(
            verify_commit_certificate_signatures(
                &cert,
                crate::DEFAULT_CHAIN_ID,
                &validators,
                secp256k1_scheme::verify,
            ),
            Err(PokerL1Error::CommitCertSignatureBitmapMismatch { .. })
        ));
    }

    #[test]
    fn bitmap_set_bits_is_ascending_and_complete() {
        // 第 0、3 位（byte 0）、第 9 位（byte 1 bit 1）、第 23 位（byte 2 bit 7）。
        let bitmap = [0b0000_1001u8, 0b0000_0010, 0b1000_0000];
        assert_eq!(bitmap_set_bits(&bitmap), vec![0, 3, 9, 23]);
    }

    #[test]
    fn wrong_scheme_verify_fn_rejects() {
        // 用 ed25519 verify 闭包验证 secp256k1 签名必须失败。
        let (validators, secrets) = make_validators(5);
        let signer_secrets: Vec<(usize, SecretKey)> = (0..4).map(|i| (i, secrets[i])).collect();
        let cert = make_signed_cert(
            &validators,
            &signer_secrets,
            ([1u8; 32], [2u8; 32], [3u8; 32]),
            crate::DEFAULT_CHAIN_ID,
        );
        assert!(matches!(
            verify_commit_certificate_signatures(
                &cert,
                crate::DEFAULT_CHAIN_ID,
                &validators,
                ed25519_scheme::verify,
            ),
            Err(PokerL1Error::InvalidCommitCertificateSignature { .. })
        ));
    }
}
