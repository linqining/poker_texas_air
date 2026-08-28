pub use poker_protocol_core::{Challenge, CryptoTranscript};
use poker_protocol_core::{Curve, CurvePoint, CurveScalar};
use sha3::Digest;
use std::collections::HashMap;
use std::sync::Mutex;

// ========== Label interning cache ==========
//
// `merlin::Transcript` 要求 label 为 `&'static [u8]`，而我们对外暴露的
// `CryptoTranscript` trait 接受 `&[u8]`。直接 `Box::leak` 会在每次调用时
// 泄漏内存（长跑服务下持续增长）。这里用一个全局缓存把每个唯一的 label
// 只 leak 一次，后续相同 label 复用同一份 `&'static [u8]`。
lazy_static::lazy_static! {
    static ref LABEL_CACHE: Mutex<HashMap<Vec<u8>, &'static [u8]>> = Mutex::new(HashMap::new());
}

/// 将任意 `&[u8]` label 转为 `&'static [u8]`，相同内容只 leak 一次。
fn intern_label(label: &[u8]) -> &'static [u8] {
    let mut cache = LABEL_CACHE.lock().expect("LABEL_CACHE poisoned");
    if let Some(static_label) = cache.get(label) {
        return *static_label;
    }
    let static_label: &'static [u8] = Box::leak(label.to_vec().into_boxed_slice());
    cache.insert(label.to_vec(), static_label);
    static_label
}

// ========== MerlinTranscript (wraps merlin::Transcript) ==========

/// Wrapper around `merlin::Transcript` implementing `CryptoTranscript`.
/// 仅用于离线测试，不兼容 Move 合约。
pub struct MerlinTranscript {
    inner: merlin::Transcript,
}

impl std::fmt::Debug for MerlinTranscript {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MerlinTranscript").finish_non_exhaustive()
    }
}

impl CryptoTranscript for MerlinTranscript {
    fn new(protocol_name: &[u8]) -> Self {
        // merlin::Transcript::new 要求 &'static [u8]；通过 intern_label 复用，
        // 相同 protocol_name 只 leak 一次，避免长跑服务内存持续增长。
        let static_name: &'static [u8] = intern_label(protocol_name);
        MerlinTranscript {
            inner: merlin::Transcript::new(static_name),
        }
    }

    fn append_message(&mut self, label: &[u8], message: &[u8]) {
        // merlin::Transcript::append_message 要求 &'static [u8] label；
        // 通过 intern_label 复用，相同 label 只 leak 一次。
        let static_label: &'static [u8] = intern_label(label);
        self.inner.append_message(static_label, message);
    }

    fn challenge_bytes(&mut self, label: &[u8], dest: &mut [u8]) {
        let static_label: &'static [u8] = intern_label(label);
        self.inner.challenge_bytes(static_label, dest);
    }

    fn append_point<C: Curve>(&mut self, label: &[u8], point: &C::Point) {
        let static_label: &'static [u8] = intern_label(label);
        self.inner
            .append_message(static_label, point.compress().as_ref());
    }

    fn append_scalar<C: Curve>(&mut self, label: &[u8], scalar: &C::Scalar) {
        let static_label: &'static [u8] = intern_label(label);
        self.inner.append_message(static_label, &scalar.as_bytes());
    }

    fn challenge<C: Curve>(&mut self, label: &[u8]) -> Challenge<C> {
        let mut buf = [0u8; 64];
        let static_label: &'static [u8] = intern_label(label);
        self.inner.challenge_bytes(static_label, &mut buf);
        let scalar = C::Scalar::from_bytes_mod_order_wide(&buf);
        Challenge { scalar }
    }
}

// ========== FiatShamirTranscript (SHA3-256, matches Move contract) ==========

/// Fiat-Shamir Transcript using SHA3-256, matching the Move contract implementation.
///
/// 状态机：state = SHA3-256(current_state || len_label[4字节LE] || label || len_msg[4字节LE] || message)
/// 与 Move 合约 bls_transcript.move 完全兼容（含 M-P13 长度前缀修复）。
///
/// challenge 标量生成使用 Curve::hash_to_scalar（清位法），
/// 而非 from_bytes_mod_order（模约简），与 Move 端一致。
#[derive(Debug)]
pub struct FiatShamirTranscript {
    state: Vec<u8>,
}

impl CryptoTranscript for FiatShamirTranscript {
    fn new(protocol_name: &[u8]) -> Self {
        // 兼容 Move 合约 bls_transcript::new：
        // state = SHA3-256(protocol_name)
        let state = sha3::Sha3_256::digest(protocol_name).to_vec();
        FiatShamirTranscript { state }
    }

    fn append_message(&mut self, label: &[u8], message: &[u8]) {
        // 兼容 Move 合约 bls_transcript::append_message (M-P13)：
        // state = SHA3-256(state || len_label[4字节LE] || label || len_msg[4字节LE] || message)
        // Move 端在 label 和 message 前分别添加 4 字节小端长度前缀，
        // 防止长度扩展攻击和歧义编码。
        let mut data = self.state.clone();
        let label_len = label.len() as u32;
        data.extend_from_slice(&label_len.to_le_bytes());
        data.extend_from_slice(label);
        let msg_len = message.len() as u32;
        data.extend_from_slice(&msg_len.to_le_bytes());
        data.extend_from_slice(message);
        self.state = sha3::Sha3_256::digest(&data).to_vec();
    }

    fn challenge_bytes(&mut self, label: &[u8], dest: &mut [u8]) {
        // 兼容旧接口：先追加 "challenge" 消息，再取状态哈希字节。
        // 注意：此方法不与 Move 直接对应，仅用于兼容旧调用方。
        // 新代码应使用 challenge() 或 challenge_vec()。
        self.append_message(label, b"challenge");
        let hash = sha3::Sha3_256::digest(&self.state);
        let copy_len = dest.len().min(hash.len());
        dest[..copy_len].copy_from_slice(&hash[..copy_len]);
    }

    fn append_point<C: Curve>(&mut self, label: &[u8], point: &C::Point) {
        let point_bytes = point.compress();
        self.append_message(label, point_bytes.as_ref());
    }

    fn append_scalar<C: Curve>(&mut self, label: &[u8], scalar: &C::Scalar) {
        self.append_message(label, &scalar.as_bytes());
    }

    fn challenge<C: Curve>(&mut self, label: &[u8]) -> Challenge<C> {
        // 兼容 Move 合约 bls_transcript::challenge：
        // 1. append_message(label, b"challenge")
        // 2. hash_to_scalar(state) — 使用清位法
        self.append_message(label, b"challenge");
        let scalar = C::hash_to_scalar(&self.state);
        Challenge { scalar }
    }
}


/// Keccak-256 Fiat–Shamir transcript (v2.3 secp256k1 direct-sigma route).
///
/// Identical state machine to [`FiatShamirTranscript`] —
/// `state = Keccak256(state || u32le(len) || label || u32le(len) || msg)`,
/// challenge = hash_to_scalar(state) — with the compression function swapped
/// to legacy Keccak-256 (0x01 padding) so the on-chain Cairo verifier replays
/// it with Starknet's native keccak builtin at near-zero cost.
#[derive(Debug)]
pub struct KeccakTranscript {
    state: Vec<u8>,
}

impl KeccakTranscript {
    /// Debug accessor: the raw transcript state (vector-generator tooling).
    pub fn state_bytes(&self) -> &[u8] {
        &self.state
    }
}

impl CryptoTranscript for KeccakTranscript {
    fn new(protocol_name: &[u8]) -> Self {
        let state = sha3::Keccak256::digest(protocol_name).to_vec();
        KeccakTranscript { state }
    }

    fn append_message(&mut self, label: &[u8], message: &[u8]) {
        let mut data = self.state.clone();
        data.extend_from_slice(&(label.len() as u32).to_le_bytes());
        data.extend_from_slice(label);
        data.extend_from_slice(&(message.len() as u32).to_le_bytes());
        data.extend_from_slice(message);
        self.state = sha3::Keccak256::digest(&data).to_vec();
    }

    fn challenge_bytes(&mut self, label: &[u8], dest: &mut [u8]) {
        self.append_message(label, b"challenge");
        let hash = sha3::Keccak256::digest(&self.state);
        let copy_len = dest.len().min(hash.len());
        dest[..copy_len].copy_from_slice(&hash[..copy_len]);
    }

    fn append_point<C: Curve>(&mut self, label: &[u8], point: &C::Point) {
        let point_bytes = point.compress();
        self.append_message(label, point_bytes.as_ref());
    }

    fn append_scalar<C: Curve>(&mut self, label: &[u8], scalar: &C::Scalar) {
        self.append_message(label, &scalar.as_bytes());
    }

    fn challenge<C: Curve>(&mut self, label: &[u8]) -> Challenge<C> {
        self.append_message(label, b"challenge");
        let scalar = C::hash_to_scalar(&self.state);
        Challenge { scalar }
    }
}
