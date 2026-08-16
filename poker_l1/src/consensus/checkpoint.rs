//! 检查点与归档（缺口 #9：Checkpoint & Archive）。
//!
//! 周期性生成不可逆检查点（finality gadget 保证），使新节点可从最近检查点
//! 而非 genesis 开始 Fast Sync；pruned 节点仅保留检查点之后的完整状态。
//!
//! # 检查点结构
//!
//! 检查点包含：`height` + `block_hash` + `state_root` + 2/3+ validator 签名。
//! 一旦 2/3+ validator 签名背书，该 height 之前的所有区块不可逆转（finalized）。

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::BlockHeight;
use crate::Hash;
use crate::consensus::Epoch;
use crate::error::{PokerL1Error, PokerL1Result};
use crate::signature::TaggedPubkey;
use crate::signature::unified::verify_signature;

/// 检查点生成间隔（每 10,000 区块生成一个检查点）。
pub const CHECKPOINT_INTERVAL: u64 = 10_000;

/// 检查点证书（缺口 #9）。
///
/// 由 ≥2/3 validator 签名背书的不可逆转检查点。一旦形成，该 height 之前的
/// 所有区块被视为 finalized，pruned 节点可安全丢弃更早的数据。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct CheckpointCertificate {
    /// 检查点对应的区块高度。
    pub height: BlockHeight,
    /// 该高度的 block_hash。
    pub block_hash: Hash,
    /// 该高度的 state_root。
    pub state_root: Hash,
    /// 当前 epoch。
    pub epoch: Epoch,
    /// 参与签名的 validator pubkeys。
    pub signer_pubkeys: Vec<TaggedPubkey>,
    /// 对应的 secp256k1 签名列表。
    pub signatures: Vec<Vec<u8>>,
}

impl CheckpointCertificate {
    /// 计算检查点的签名对象哈希（所有 validator 对此哈希签名）。
    ///
    /// `blake2b_256(CHECKPOINT_DOMAIN || height || block_hash || state_root || epoch)`
    #[must_use]
    pub fn signing_hash(&self) -> Hash {
        use blake2::Blake2bVar;
        use blake2::digest::{Update, VariableOutput};
        const CHECKPOINT_DOMAIN: u8 = 0x43; // 'C' for Checkpoint
        let mut h = Blake2bVar::new(32).expect("32 <= 64");
        h.update(&[CHECKPOINT_DOMAIN]);
        h.update(&self.height.to_le_bytes());
        h.update(&self.block_hash);
        h.update(&self.state_root);
        h.update(&self.epoch.to_le_bytes());
        let mut out = [0u8; 32];
        h.finalize_variable(&mut out).expect("32 <= 64");
        out
    }

    /// 签名者数量。
    #[must_use]
    pub fn signer_count(&self) -> usize {
        self.signatures.len()
    }

    /// 校验检查点证书（缺口 #9）。
    ///
    /// 校验项：
    /// 1. signer_pubkeys 与 signatures 长度一致
    /// 2. 签名者数量 ≥ required_quorum（2/3）
    /// 3. 每个签名对 `signing_hash` 有效（pubkey 验证）
    /// 4. 无重复签名者
    pub fn validate(&self, validators: &[TaggedPubkey]) -> PokerL1Result<()> {
        // 1. 长度一致
        if self.signer_pubkeys.len() != self.signatures.len() {
            return Err(PokerL1Error::Other(format!(
                "checkpoint: signer_pubkeys len {} != signatures len {}",
                self.signer_pubkeys.len(),
                self.signatures.len()
            )));
        }
        // 2. quorum
        let members: std::collections::BTreeSet<TaggedPubkey> =
            validators.iter().cloned().collect();
        if members.is_empty() || members.len() != validators.len() {
            return Err(PokerL1Error::Other(
                "checkpoint validator set is empty or contains duplicate members".into(),
            ));
        }
        let required = crate::consensus::required_quorum(members.len());
        if self.signer_count() < required {
            return Err(PokerL1Error::InsufficientQuorum {
                actual: self.signer_count(),
                required,
            });
        }
        // 3 + 4. 逐签名验证 + 去重
        let msg_hash = self.signing_hash();
        let mut seen = std::collections::BTreeSet::new();
        for (pk, sig) in self.signer_pubkeys.iter().zip(self.signatures.iter()) {
            if !members.contains(pk) {
                return Err(PokerL1Error::Other(
                    "checkpoint signer is not in the finalized ValidatorSet".into(),
                ));
            }
            let pk_bytes = pk.to_bytes();
            if !seen.insert(pk_bytes.clone()) {
                return Err(PokerL1Error::Other(format!(
                    "checkpoint: duplicate signer {:?}",
                    pk
                )));
            }
            verify_signature(pk, sig, &msg_hash).map_err(|_| {
                PokerL1Error::Other("checkpoint: signature verification failed".to_string())
            })?;
        }
        Ok(())
    }
}

/// 判断给定高度是否应生成检查点（每 CHECKPOINT_INTERVAL 区块一次）。
#[must_use]
pub fn should_create_checkpoint(height: BlockHeight) -> bool {
    height > 0 && height % CHECKPOINT_INTERVAL == 0
}

/// 构造检查点证书的签名对象（供 validator 签名）。
///
/// 返回 `signing_hash`，validator 用 secp256k1 对此哈希签名后填入 `CheckpointCertificate.signatures`。
#[must_use]
pub fn checkpoint_signing_hash(
    height: BlockHeight,
    block_hash: Hash,
    state_root: Hash,
    epoch: Epoch,
) -> Hash {
    let cert = CheckpointCertificate {
        height,
        block_hash,
        state_root,
        epoch,
        signer_pubkeys: vec![],
        signatures: vec![],
    };
    cert.signing_hash()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::validator_set::ValidatorEntry;
    use crate::signature::tagged_pubkey::{SignatureScheme, encode_tag};

    fn make_real_keypair(seed: u8) -> (secp256k1::SecretKey, TaggedPubkey) {
        let secp = secp256k1::Secp256k1::new();
        let mut secret_bytes = [0u8; 32];
        for (i, b) in secret_bytes.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8);
        }
        let secret = loop {
            match secp256k1::SecretKey::from_slice(&secret_bytes) {
                Ok(s) => break s,
                Err(_) => secret_bytes[31] = secret_bytes[31].wrapping_add(1),
            }
        };
        let public = secp256k1::PublicKey::from_secret_key(&secp, &secret);
        let tagged = TaggedPubkey::new(
            SignatureScheme::Secp256k1,
            crate::signature::CURRENT_VERSION,
            public.serialize().to_vec(),
        )
        .expect("tagged pubkey");
        (secret, tagged)
    }

    fn sign_hash(secret: &secp256k1::SecretKey, msg_hash: &[u8; 32]) -> Vec<u8> {
        let secp = secp256k1::Secp256k1::new();
        let msg = secp256k1::Message::from_digest(*msg_hash);
        let sig = secp.sign_ecdsa_recoverable(&msg, secret);
        let (recovery_id, compact) = sig.serialize_compact();
        let mut full = compact.to_vec();
        full.push(recovery_id.to_i32() as u8);
        full
    }

    #[test]
    fn checkpoint_interval_detection() {
        assert!(!should_create_checkpoint(0));
        assert!(!should_create_checkpoint(1));
        assert!(!should_create_checkpoint(9999));
        assert!(should_create_checkpoint(10000));
        assert!(should_create_checkpoint(20000));
        assert!(!should_create_checkpoint(15000));
    }

    #[test]
    fn checkpoint_validate_with_real_signatures() {
        // 3 validator，2/3 quorum = 3（required_quorum(3)=3），全签。
        let chain_epoch = 1u64;
        let block_hash = [0xAA; 32];
        let state_root = [0xBB; 32];
        let height = 10_000u64;
        let signing_hash = checkpoint_signing_hash(height, block_hash, state_root, chain_epoch);

        let keys: Vec<_> = (0..3).map(|i| make_real_keypair(0x10 + i)).collect();
        let sigs: Vec<Vec<u8>> = keys
            .iter()
            .map(|(sk, _)| sign_hash(sk, &signing_hash))
            .collect();
        let pubkeys: Vec<TaggedPubkey> = keys.iter().map(|(_, pk)| pk.clone()).collect();

        let cert = CheckpointCertificate {
            height,
            block_hash,
            state_root,
            epoch: chain_epoch,
            signer_pubkeys: pubkeys,
            signatures: sigs,
        };
        cert.validate(&cert.signer_pubkeys)
            .expect("3/3 签名应通过 validate");
    }

    #[test]
    fn checkpoint_rejects_insufficient_quorum() {
        // 5 validator，需 4 签名，仅给 3 → 拒绝。
        let signing_hash = checkpoint_signing_hash(10_000, [0xAA; 32], [0xBB; 32], 1);
        let keys: Vec<_> = (0..3).map(|i| make_real_keypair(0x20 + i)).collect();
        let sigs: Vec<Vec<u8>> = keys
            .iter()
            .map(|(sk, _)| sign_hash(sk, &signing_hash))
            .collect();
        let pubkeys: Vec<TaggedPubkey> = keys.iter().map(|(_, pk)| pk.clone()).collect();
        let cert = CheckpointCertificate {
            height: 10_000,
            block_hash: [0xAA; 32],
            state_root: [0xBB; 32],
            epoch: 1,
            signer_pubkeys: pubkeys,
            signatures: sigs,
        };
        let mut validators = cert.signer_pubkeys.clone();
        validators.extend((0..2).map(|i| make_real_keypair(0x50 + i).1));
        let err = cert.validate(&validators).unwrap_err();
        assert!(matches!(err, PokerL1Error::InsufficientQuorum { .. }));
    }

    #[test]
    fn checkpoint_rejects_duplicate_signer() {
        // 5 validator（required_quorum(5)=4），提供 4 个签名（其中 1 个重复）→
        // 通过 quorum 检查（4>=4），但在逐签名验证时检测到重复。
        let signing_hash = checkpoint_signing_hash(10_000, [0xAA; 32], [0xBB; 32], 1);
        let keys: Vec<_> = (0..3).map(|i| make_real_keypair(0x30 + i)).collect();
        let sigs: Vec<Vec<u8>> = keys
            .iter()
            .map(|(sk, _)| sign_hash(sk, &signing_hash))
            .collect();
        let pubkeys: Vec<TaggedPubkey> = keys.iter().map(|(_, pk)| pk.clone()).collect();
        // 3 个不同 + 1 个重复（复制第 0 个）→ 共 4 个签名
        let cert = CheckpointCertificate {
            height: 10_000,
            block_hash: [0xAA; 32],
            state_root: [0xBB; 32],
            epoch: 1,
            signer_pubkeys: {
                let mut p = pubkeys.clone();
                p.push(pubkeys[0].clone()); // 重复第 0 个
                p
            },
            signatures: {
                let mut s = sigs.clone();
                s.push(sigs[0].clone()); // 重复第 0 个签名
                s
            },
        };
        let mut validators = pubkeys;
        validators.extend((0..2).map(|i| make_real_keypair(0x60 + i).1));
        let err = cert.validate(&validators).unwrap_err();
        assert!(
            matches!(err, PokerL1Error::Other(_)),
            "应检测到重复签名者: {err:?}"
        );
    }

    #[test]
    fn checkpoint_bcs_roundtrip() {
        let signing_hash = checkpoint_signing_hash(10_000, [0xAA; 32], [0xBB; 32], 1);
        let (sk, pk) = make_real_keypair(0x40);
        let sig = sign_hash(&sk, &signing_hash);
        let cert = CheckpointCertificate {
            height: 10_000,
            block_hash: [0xAA; 32],
            state_root: [0xBB; 32],
            epoch: 1,
            signer_pubkeys: vec![pk],
            signatures: vec![sig],
        };
        let bytes = borsh::to_vec(&cert).unwrap();
        let recovered: CheckpointCertificate = borsh::from_slice(&bytes).unwrap();
        assert_eq!(cert, recovered);
    }
}
