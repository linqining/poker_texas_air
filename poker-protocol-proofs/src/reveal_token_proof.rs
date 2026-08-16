//! Reveal-token Chaum--Pedersen proof.
//!
//! For ciphertext `ct = (rG, m + r*pk)`, the player publishes
//! `token = sk * ct.c1`. The statement is `(expected_pk, ct, token)` and the
//! witness is the registered non-zero `sk`. The two equations are
//! `pk = sk*G` and `token = sk*ct.c1`; the response is shared, so the token is
//! bound to the same key as the registered public key.
//!
//! The verifier checks ciphertext validity, key equality with `expected_pk`,
//! non-identity token/commitments and both equations. Subtracting the token
//! from `ct.c2` is an external state-machine action. The interactive protocol
//! is perfectly complete, specially sound and perfectly HVZK; the Rust proof
//! is Fiat--Shamir with an explicit nonce and fixed legacy-compatible labels.

use crate::transcript_ext::CryptoTranscript;
use poker_protocol_core::{Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric};
use rand_core::{CryptoRng, RngCore};

/// Fiat-Shamir transcript label for `RevealTokenProof`.
///
/// This label MUST match the Move contract's `reveal_token_proof` domain separator
/// exactly. A typo here would silently break proof verification. All call sites
/// that construct a transcript for `RevealTokenProof::prove` / `verify` MUST use
/// this constant instead of inlining the byte string.
pub const REVEAL_TOKEN_PROOF_LABEL: &[u8] = b"reveal_token_proof_v3";

#[derive(Debug, Clone, Copy)]
pub struct RevealTokenProof<C: Curve> {
    pub user_public_key: C::Point,
    pub commitment_t1: C::Point,
    pub commitment_t2: C::Point,
    pub response_s: C::Scalar,
    /// Nonce included in the Fiat--Shamir transcript.
    pub nonce: C::Scalar,
}

#[derive(Debug, Clone, Copy)]
pub struct RevealTokenAndProof<C: Curve> {
    pub reveal_token: C::Point,
    pub proof: RevealTokenProof<C>,
}

#[derive(Debug, Clone)]
pub struct ExpelHandState<C: Curve> {
    pub hand_encrypted: ElGamalCiphertextGeneric<C>,
    pub reveal_tokens: Vec<RevealTokenAndProof<C>>,
}

#[derive(Debug, Clone)]
pub enum RevealProofError {
    InvalidProof,
    InvalidElGamalStructure,
}

impl<C: Curve> RevealTokenProof<C> {
    pub fn try_prove(
        sk: &C::Scalar,
        user_pk: &C::Point,
        encrypted_card: &ElGamalCiphertextGeneric<C>,
        reveal_token: &C::Point,
        rng: &mut (impl CryptoRng + RngCore),
        transcript: &mut impl CryptoTranscript,
    ) -> Result<Self, RevealProofError> {
        if *sk == C::Scalar::zero() || user_pk.is_identity() || *user_pk != C::base_g() * *sk {
            return Err(RevealProofError::InvalidProof);
        }
        if !encrypted_card.is_valid() {
            return Err(RevealProofError::InvalidElGamalStructure);
        }
        if reveal_token.is_identity() || *reveal_token != encrypted_card.c1 * *sk {
            return Err(RevealProofError::InvalidProof);
        }

        let (omega, t1, t2) = loop {
            let omega = C::Scalar::random(rng);
            if omega == C::Scalar::zero() {
                continue;
            }
            let t1 = C::base_g() * omega;
            let t2 = encrypted_card.c1 * omega;
            if !t1.is_identity() && !t2.is_identity() {
                break (omega, t1, t2);
            }
        };
        // The nonce preserves the established wire challenge schedule.
        let nonce = C::Scalar::random(rng);

        let challenge = Self::compute_challenge(
            user_pk,
            encrypted_card,
            reveal_token,
            &t1,
            &t2,
            &nonce,
            transcript,
        );

        let response_s = omega + challenge * *sk;

        Ok(RevealTokenProof {
            user_public_key: *user_pk,
            commitment_t1: t1,
            commitment_t2: t2,
            response_s,
            nonce,
        })
    }

    /// Backward-compatible wrapper. New protocol code should call
    /// [`Self::try_prove`] so malformed statements are returned as errors.
    pub fn prove(
        sk: &C::Scalar,
        user_pk: &C::Point,
        encrypted_card: &ElGamalCiphertextGeneric<C>,
        reveal_token: &C::Point,
        rng: &mut (impl CryptoRng + RngCore),
        transcript: &mut impl CryptoTranscript,
    ) -> Self {
        Self::try_prove(sk, user_pk, encrypted_card, reveal_token, rng, transcript)
            .expect("RevealTokenProof::prove received an invalid witness or statement")
    }

    pub fn verify(
        &self,
        encrypted_card: &ElGamalCiphertextGeneric<C>,
        reveal_token: &C::Point,
        expected_pk: &C::Point,
        transcript: &mut impl CryptoTranscript,
    ) -> Result<(), RevealProofError> {
        if !encrypted_card.is_valid() {
            return Err(RevealProofError::InvalidElGamalStructure);
        }

        if expected_pk.is_identity() || self.user_public_key.is_identity() {
            return Err(RevealProofError::InvalidProof);
        }

        // An identity token would encode a trivial statement.
        if reveal_token.is_identity() {
            return Err(RevealProofError::InvalidProof);
        }

        // Bind the proof-carried key to the authenticated registered key.
        if self.user_public_key != *expected_pk {
            return Err(RevealProofError::InvalidProof);
        }

        // Strict wire validation rejects identity commitments.
        if self.commitment_t1.is_identity() || self.commitment_t2.is_identity() {
            return Err(RevealProofError::InvalidProof);
        }

        let expected_c = Self::compute_challenge(
            &self.user_public_key,
            encrypted_card,
            reveal_token,
            &self.commitment_t1,
            &self.commitment_t2,
            &self.nonce,
            transcript,
        );

        let lhs_g = C::base_g() * self.response_s;
        let rhs_g = self.commitment_t1 + self.user_public_key * expected_c;
        if lhs_g != rhs_g {
            return Err(RevealProofError::InvalidProof);
        }

        let lhs_ct = encrypted_card.c1 * self.response_s;
        let rhs_ct = self.commitment_t2 + *reveal_token * expected_c;
        if lhs_ct != rhs_ct {
            return Err(RevealProofError::InvalidProof);
        }
        Ok(())
    }

    fn compute_challenge(
        pk: &C::Point,
        encrypted_card: &ElGamalCiphertextGeneric<C>,
        reveal_token: &C::Point,
        t1: &C::Point,
        t2: &C::Point,
        nonce: &C::Scalar,
        transcript: &mut impl CryptoTranscript,
    ) -> C::Scalar {
        // Field order is consensus-sensitive and must match every verifier.
        transcript.append_scalar::<C>(b"reveal_token_nonce", nonce);
        transcript.append_point::<C>(b"pk", pk);
        transcript.append_point::<C>(b"c1", &encrypted_card.c1);
        transcript.append_point::<C>(b"c2", &encrypted_card.c2);
        transcript.append_point::<C>(b"reveal_token", reveal_token);
        transcript.append_point::<C>(b"t1", t1);
        transcript.append_point::<C>(b"t2", t2);
        // The short challenge label is retained for wire compatibility.
        transcript.challenge::<C>(b"challenge").scalar
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transcript_ext::{CryptoTranscript, MerlinTranscript};
    use poker_protocol_core::RistrettoCurve;

    type C = RistrettoCurve;
    type ElGamalCiphertext = ElGamalCiphertextGeneric<C>;

    fn setup() -> (<C as Curve>::Scalar, <C as Curve>::Point) {
        let sk = <C as Curve>::Scalar::random(&mut rand_core::OsRng);
        (sk, C::base_g() * sk)
    }

    #[test]
    fn test_reveal_token_and_proof_valid() {
        let (sk, pk) = setup();
        let pt = C::base_g() + C::base_h();
        let r = <C as Curve>::Scalar::random(&mut rand_core::OsRng);
        let ct = ElGamalCiphertext::encrypt(&pt, &pk, &r);

        let reveal_token = ct.gen_reveal_token(&sk);
        assert_eq!(
            ct.c2 - reveal_token,
            pt,
            "token should decrypt to plaintext"
        );

        let mut transcript = MerlinTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        let proof = RevealTokenProof::<C>::prove(
            &sk,
            &pk,
            &ct,
            &reveal_token,
            &mut rand_core::OsRng,
            &mut transcript,
        );
        let mut transcript = MerlinTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        assert!(
            proof
                .verify(&ct, &reveal_token, &pk, &mut transcript)
                .is_ok(),
            "Valid proof should pass"
        );
    }

    #[test]
    fn test_wrong_sk_fails() {
        let (_sk, pk) = setup();
        let wrong_sk = <C as Curve>::Scalar::random(&mut rand_core::OsRng);
        let pt = C::base_g() + C::base_h();
        let r = <C as Curve>::Scalar::random(&mut rand_core::OsRng);
        let ct = ElGamalCiphertext::encrypt(&pt, &pk, &r);

        let wrong_token = ct.gen_reveal_token(&wrong_sk);
        let mut transcript = MerlinTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        assert!(
            RevealTokenProof::<C>::try_prove(
                &wrong_sk,
                &pk,
                &ct,
                &wrong_token,
                &mut rand_core::OsRng,
                &mut transcript,
            )
            .is_err(),
            "Wrong SK must be rejected before proof generation"
        );
    }

    #[test]
    fn test_plaintext_binding_is_caller_responsibility() {
        let (sk, pk) = setup();
        let real_pt = C::base_g() + C::base_h();
        let r = <C as Curve>::Scalar::random(&mut rand_core::OsRng);
        let ct = ElGamalCiphertext::encrypt(&real_pt, &pk, &r);

        let reveal_token = ct.gen_reveal_token(&sk);
        let mut transcript = MerlinTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        let proof = RevealTokenProof::<C>::prove(
            &sk,
            &pk,
            &ct,
            &reveal_token,
            &mut rand_core::OsRng,
            &mut transcript,
        );

        let mut transcript = MerlinTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        assert!(
            proof
                .verify(&ct, &reveal_token, &pk, &mut transcript)
                .is_ok(),
            "DLEq proof valid regardless of plaintext"
        );
        let computed_pt = ct.c2 - reveal_token;
        assert_eq!(
            computed_pt, real_pt,
            "Caller must verify c2 - token == expected plaintext"
        );
    }

    #[test]
    fn test_token_cannot_transfer_to_different_ct() {
        let (sk, pk) = setup();
        let pt = C::base_g() + C::base_h();
        let r1 = <C as Curve>::Scalar::random(&mut rand_core::OsRng);
        let ct1 = ElGamalCiphertext::encrypt(&pt, &pk, &r1);
        let r2 = <C as Curve>::Scalar::random(&mut rand_core::OsRng);
        let ct2 = ElGamalCiphertext::encrypt(&pt, &pk, &r2);

        let token1 = ct1.gen_reveal_token(&sk);
        let mut transcript = MerlinTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        let proof = RevealTokenProof::<C>::prove(
            &sk,
            &pk,
            &ct1,
            &token1,
            &mut rand_core::OsRng,
            &mut transcript,
        );

        let mut transcript = MerlinTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        assert!(
            proof.verify(&ct2, &token1, &pk, &mut transcript).is_err(),
            "Token for ct1 invalid on ct2"
        );
    }

    /// SECURITY VERIFICATION: is_valid() now correctly uses && (not ||)
    ///
    /// PREVIOUS BUG (FIXED): The old `is_valid()` in elgamal.rs used `||`:
    ///   pub fn is_valid(&self) -> bool {
    ///       !self.c1.is_identity() || !self.c2.is_identity()
    ///   }
    /// This allowed c1 = identity with c2 ≠ identity.
    ///
    /// CURRENT FIX: `is_valid()` in curve.rs now correctly uses `&&`:
    ///   pub fn is_valid(&self) -> bool {
    ///       !self.c1.is_identity() && !self.c2.is_identity()
    ///   }
    /// This means c1=identity ciphertexts are rejected BEFORE the DLEq check.
    ///
    /// NOTE: crypto/elgamal.rs STILL has the `||` bug in its legacy `is_valid()`.
    #[test]
    fn test_forgery_reveal_token_identity_c1_bypass() {
        let (_sk, pk) = setup();

        // Create a ciphertext with c1 = identity, c2 = some non-identity point
        let fake_plaintext = C::base_g() * <C as Curve>::Scalar::from_u64(999u64);
        let malicious_ct = ElGamalCiphertext {
            c1: <C as Curve>::Point::identity(),
            c2: fake_plaintext, // arbitrary c2, NOT an encryption of this value
        };

        // is_valid() now REJECTS c1=identity (using &&)
        assert!(
            !malicious_ct.is_valid(),
            "FIXED: is_valid() correctly rejects c1=identity with &&"
        );
    }

    #[test]
    fn test_reveal_token_equals_c1_times_sk() {
        let (sk, _pk) = setup();
        let pk = C::base_g() * sk;
        let pt = C::base_h();
        let r = <C as Curve>::Scalar::random(&mut rand_core::OsRng);
        let ct = ElGamalCiphertext::encrypt(&pt, &pk, &r);

        let token = ct.gen_reveal_token(&sk);
        let expected = ct.c1 * sk;
        assert_eq!(token, expected, "reveal_token must equal c1*sk");

        let decrypted = ct.c2 - token;
        assert_eq!(decrypted, pt, "c2 - token must equal plaintext");
    }

    // ===== FORGERY TESTS =====

    /// FIXED: verify() now accepts expected_pk and validates proof.user_public_key == expected_pk.
    /// 攻击者用自己的 sk' 生成证明，但 verify() 现在会拒绝，因为 proof.user_public_key != expected_pk。
    #[test]
    fn test_forgery_wrong_user_pk_now_detected() {
        // 真实用户的密钥对
        let (real_sk, real_pk) = setup();

        // 攻击者的密钥对
        let attacker_sk = <C as Curve>::Scalar::random(&mut rand_core::OsRng);
        let attacker_pk = C::base_g() * attacker_sk;

        // 用真实 pk 加密的牌
        let pt = C::base_g() + C::base_h();
        let r = <C as Curve>::Scalar::random(&mut rand_core::OsRng);
        let ct = ElGamalCiphertext::encrypt(&pt, &real_pk, &r);

        // 攻击者用 attacker_sk 计算 token = c1 * attacker_sk
        let attacker_token = ct.gen_reveal_token(&attacker_sk);

        // 攻击者用 attacker_sk 生成证明
        let mut transcript = MerlinTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        let proof = RevealTokenProof::<C>::prove(
            &attacker_sk,
            &attacker_pk,
            &ct,
            &attacker_token,
            &mut rand_core::OsRng,
            &mut transcript,
        );

        // 修复后: verify() 需要传入 expected_pk，并验证 proof.user_public_key == expected_pk
        // 用 real_pk 验证会失败，因为 proof.user_public_key = attacker_pk ≠ real_pk
        let mut transcript = MerlinTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        assert!(
            proof
                .verify(&ct, &attacker_token, &real_pk, &mut transcript)
                .is_err(),
            "FIXED: proof with wrong pk is now rejected when expected_pk is provided"
        );

        // 用 attacker_pk 验证会成功（但调用方应该使用 real_pk）
        let mut transcript = MerlinTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        assert!(
            proof
                .verify(&ct, &attacker_token, &attacker_pk, &mut transcript)
                .is_ok(),
            "proof passes when expected_pk matches attacker_pk"
        );

        // 解密结果错误: c2 - attacker_token = M + real_pk*r - attacker_pk*r
        let wrong_decrypted = ct.c2 - attacker_token;
        assert_ne!(
            wrong_decrypted, pt,
            "Decryption with attacker's token gives wrong plaintext"
        );

        // 攻击者构造完全伪造的密文
        let forged_ct = ElGamalCiphertext {
            c1: ct.c1,
            c2: pt + attacker_pk * r,
        };

        let forged_token = forged_ct.gen_reveal_token(&attacker_sk);
        let mut transcript = MerlinTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        let forged_proof = RevealTokenProof::<C>::prove(
            &attacker_sk,
            &attacker_pk,
            &forged_ct,
            &forged_token,
            &mut rand_core::OsRng,
            &mut transcript,
        );

        // 修复后: 需要传入 expected_pk，伪造证明会被拒绝（如果调用方使用 real_pk）
        let mut transcript = MerlinTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        assert!(
            forged_proof
                .verify(&forged_ct, &forged_token, &real_pk, &mut transcript)
                .is_err(),
            "FIXED: forged proof rejected when expected_pk is real_pk"
        );
    }

    /// FIXED: verify() now requires expected_pk. 完全伪造攻击现在被阻止，
    /// 因为调用方必须传入 expected_pk，且 verify() 会验证 proof.user_public_key == expected_pk。
    /// 调用方仍需验证: c2 - token == expected_plaintext
    #[test]
    fn test_forgery_full_fabrication_blocked() {
        // 攻击者生成任意密钥对
        let attacker_sk = <C as Curve>::Scalar::random(&mut rand_core::OsRng);
        let attacker_pk = C::base_g() * attacker_sk;

        // 真实用户的公钥
        let (real_sk, real_pk) = setup();

        // 攻击者构造任意密文和 token
        let arbitrary_pt = C::base_h() * <C as Curve>::Scalar::from_u64(777u64);
        let r = <C as Curve>::Scalar::random(&mut rand_core::OsRng);
        let ct = ElGamalCiphertext::encrypt(&arbitrary_pt, &attacker_pk, &r);
        let token = ct.gen_reveal_token(&attacker_sk);

        // 攻击者生成证明
        let mut transcript = MerlinTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        let proof = RevealTokenProof::<C>::prove(
            &attacker_sk,
            &attacker_pk,
            &ct,
            &token,
            &mut rand_core::OsRng,
            &mut transcript,
        );

        // 修复后: 如果调用方使用 real_pk 作为 expected_pk，伪造证明会被拒绝
        let mut transcript = MerlinTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        assert!(
            proof
                .verify(&ct, &token, &real_pk, &mut transcript)
                .is_err(),
            "FIXED: fabricated proof rejected when expected_pk doesn't match"
        );

        // 如果调用方错误地使用 attacker_pk，证明会通过（调用方责任）
        let mut transcript = MerlinTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        assert!(
            proof
                .verify(&ct, &token, &attacker_pk, &mut transcript)
                .is_ok(),
            "proof passes when expected_pk matches attacker_pk (caller responsibility)"
        );

        // 解密正确
        let decrypted = ct.c2 - token;
        assert_eq!(
            decrypted, arbitrary_pt,
            "Fabricated proof decrypts to attacker's chosen plaintext"
        );

        // 调用方仍需验证: c2 - token == expected_plaintext
        // 以及: proof.user_public_key == expected_pk（现在由 verify() 强制执行）
    }
}
