use crate::crypto::{DefaultCurve, EcPoint, ElGamalCiphertext, Scalar, N_CARDS};
use crate::zk_shuffle::error::VerificationError;
use crate::zk_shuffle::leave_proof::{leave_ciphertext, LeaveProof};
use crate::zk_shuffle::remask_proof::{remask_ciphertext, RemaskProof};
use crate::zk_shuffle::ShuffleProof;
// 2026-09 Poseidon epoch：生产证明统一 PoseidonFeltTranscript +
// transcript_domains 生产域（旧 Move/SHA3 域停发）。
use crate::crypto::curve::CurveScalar;
use crate::z_poker::key_manager::PKOwnershipProof;
use crate::zk_shuffle::transcript_ext::{CryptoTranscript, PoseidonFeltTranscript};
use rand_core::{CryptoRng, OsRng, RngCore};

/// 校验调用方提供的洗牌置换是 `0..N_CARDS` 的双射（fail-closed）。
///
/// 洗牌置换是用户/客户端的洗牌决定权（mental poker 核心），属于外部
/// 输入：非双射的置换既无法成证也会破坏牌组完整性，必须在入口拒绝。
fn validate_permutation(permute: &[usize; N_CARDS]) -> Result<(), VerificationError> {
    let mut seen = [false; N_CARDS];
    for &p in permute.iter() {
        if p >= N_CARDS || seen[p] {
            return Err(VerificationError::InvalidPermutation);
        }
        seen[p] = true;
    }
    Ok(())
}

/// 本地 CSPRNG 生成随机置换（代理洗牌/自随机流程专用）。
fn random_permutation(rng: &mut (impl RngCore + CryptoRng)) -> [usize; N_CARDS] {
    let mut arr: Vec<usize> = (0..N_CARDS).collect();
    use rand::seq::SliceRandom;
    arr.shuffle(rng);
    let mut fixed = [0usize; N_CARDS];
    fixed.copy_from_slice(&arr);
    fixed
}

#[derive(Debug)]
pub struct ShuffleRound {
    pub input_cards: Vec<ElGamalCiphertext>,
    pub output_cards: Vec<ElGamalCiphertext>,
    pub proof: ShuffleProof,
}

impl ShuffleRound {
    /// 执行一轮**用户洗牌**：置换由调用方传入。
    ///
    /// mental poker 的核心是每个玩家用自己的秘密置换洗牌——库不再代生成
    /// （原 todo "用户传入permute，核心是用户洗牌"）。置换是外部输入，
    /// 非双射 fail-closed 拒绝；重加密盲化因子与证明仍由 `rng` 供给。
    pub fn execute(
        input_cards: &[ElGamalCiphertext],
        share_pk: &EcPoint,
        permute: [usize; N_CARDS],
        transcript: &mut impl CryptoTranscript,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self, VerificationError> {
        validate_permutation(&permute)?;

        let mut r_values = Vec::with_capacity(N_CARDS);
        let mut output = Vec::with_capacity(N_CARDS);

        for j in 0..N_CARDS {
            let r_j = Scalar::random(&mut *rng);
            r_values.push(r_j);
            let i = permute[j];
            output.push(input_cards[i].re_encrypt(share_pk, &r_j));
        }

        let proof = ShuffleProof::prove(
            input_cards,
            &output,
            &permute,
            &r_values,
            share_pk,
            &mut *rng,
            transcript,
        )
        .expect("shuffle prove failed: identity base point in input cards");

        Ok(ShuffleRound {
            input_cards: input_cards.to_vec(),
            output_cards: output,
            proof,
        })
    }

    /// 代理/自随机洗牌：置换由本地 CSPRNG 生成。
    ///
    /// 仅限服务端受托流程（如 `proxy_shuffle_for` 为离场玩家代洗）——
    /// 玩家自己的洗牌必须走 [`ShuffleRound::execute`] 传入自己的置换。
    pub fn execute_random(
        input_cards: &[ElGamalCiphertext],
        share_pk: &EcPoint,
        transcript: &mut impl CryptoTranscript,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self, VerificationError> {
        let permute = random_permutation(rng);
        Self::execute(input_cards, share_pk, permute, transcript, rng)
    }

    pub fn verify(&self, share_pk: &EcPoint, transcript: &mut impl CryptoTranscript) -> bool {
        self.proof
            .verify(&self.input_cards, &self.output_cards, share_pk, transcript)
            .is_ok()
    }
}

// 中途加入并洗牌的牌局
#[derive(Debug)]
pub struct JoinGameAndShuffleRound {
    pub pk_hex: String,
    pub pk_ownership_proof: PKOwnershipProof,
    pub mask_and_shuffle_round: MaskAndShuffleRound,
}

// 中途加入并洗牌的牌局
#[derive(Debug)]
pub struct MaskAndShuffleRound {
    pub mask_cards: Vec<ElGamalCiphertext>,
    pub output_cards: Vec<ElGamalCiphertext>,
    pub proof: ShuffleProof,
    pub remask_proof: RemaskProof<DefaultCurve>,
}

impl MaskAndShuffleRound {
    pub fn execute(
        input_cards: &[ElGamalCiphertext],
        share_pk: &EcPoint,
        player_sk: Scalar,
        player_pk: &EcPoint,
        permute: [usize; N_CARDS],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Self, VerificationError> {
        // 创建共享 transcript，绑定 remask_proof 和 shuffle_proof
        let mut transcript = PoseidonFeltTranscript::new_domain(crate::transcript_domains::MASK_SHUFFLE_V2_POSEIDON);

        let mut mask_cards: Vec<ElGamalCiphertext> = vec![];
        for i in 0..input_cards.len() {
            let remask_card = remask_ciphertext(&input_cards[i], &player_sk, player_pk, rng)
                .expect("remask_ciphertext failed: c1 is identity (should not happen for valid encrypted cards)");
            mask_cards.push(remask_card);
        }
        let remask_proof = RemaskProof::<DefaultCurve>::prove(
            input_cards,
            &mask_cards,
            &player_sk,
            player_pk,
            &mut transcript,
        );
        let shuffle_round =
            ShuffleRound::execute(&mask_cards, share_pk, permute, &mut transcript, rng)?;
        Ok(Self {
            mask_cards,
            output_cards: shuffle_round.output_cards,
            proof: shuffle_round.proof,
            remask_proof,
        })
    }
}

// 离开牌局：生成 leave 密文和 LeaveProof
#[derive(Debug)]
pub struct LeaveGameRound {
    pub input_cards: Vec<ElGamalCiphertext>,
    pub output_cards: Vec<ElGamalCiphertext>,
    pub leave_proof: LeaveProof<DefaultCurve>,
}

impl LeaveGameRound {
    pub fn execute(
        input_cards: &[ElGamalCiphertext],
        player_sk: &Scalar,
        player_pk: &EcPoint,
    ) -> Self {
        let mut rng = OsRng;
        let output_cards: Vec<ElGamalCiphertext> = input_cards
            .iter()
            .map(|ct| leave_ciphertext(ct, player_sk, player_pk, &mut rng).unwrap())
            .collect();

        let mut transcript = PoseidonFeltTranscript::new_domain(crate::transcript_domains::LEAVE_POSEIDON_V2);
        let leave_proof = LeaveProof::<DefaultCurve>::prove(
            input_cards,
            &output_cards,
            player_sk,
            player_pk,
            &mut transcript,
        );

        Self {
            input_cards: input_cards.to_vec(),
            output_cards,
            leave_proof,
        }
    }

    /// 离开/弃牌剥层，**排除指定牌槽**（玩家自己的手牌）。
    ///
    /// 安全动机：剥层输出公开即公开 `sk·c1`（= 该玩家对这些牌的
    /// reveal token，任何人都可从 input.c2 − output.c2 算出）。若不排除
    /// 自己的手牌，其余玩家串谋（合计 N−1 份 token）即可解密已弃牌
    /// 玩家的底牌——违反扑克规则。排除槽的输出 = 输入原样（层保留，
    /// token 不泄露）；这些牌在规则上是死牌，永远无需解密。
    ///
    /// DLEq 证明覆盖**剥层子集**（非排除槽的 input/output 切片），
    /// transcript 绑定切片本身；排除槽由验证方从自己的状态推导
    /// （发牌记录公开），不信任离开者的声明。
    pub fn execute_with_exclusions(
        input_cards: &[ElGamalCiphertext],
        excluded_indices: &[usize],
        player_sk: &Scalar,
        player_pk: &EcPoint,
    ) -> Self {
        let mut rng = OsRng;
        let output_cards: Vec<ElGamalCiphertext> = input_cards
            .iter()
            .enumerate()
            .map(|(i, ct)| {
                if excluded_indices.contains(&i) {
                    // 排除槽：原样保留（不剥层、不泄露 token）。
                    ct.clone()
                } else {
                    leave_ciphertext(ct, player_sk, player_pk, &mut rng).unwrap()
                }
            })
            .collect();

        // DLEq 只覆盖剥层子集。
        let sub_input: Vec<ElGamalCiphertext> = input_cards
            .iter()
            .enumerate()
            .filter(|(i, _)| !excluded_indices.contains(i))
            .map(|(_, ct)| ct.clone())
            .collect();
        let sub_output: Vec<ElGamalCiphertext> = output_cards
            .iter()
            .enumerate()
            .filter(|(i, _)| !excluded_indices.contains(i))
            .map(|(_, ct)| ct.clone())
            .collect();

        let mut transcript = PoseidonFeltTranscript::new_domain(crate::transcript_domains::LEAVE_POSEIDON_V2);
        let leave_proof = LeaveProof::<DefaultCurve>::prove(
            &sub_input,
            &sub_output,
            player_sk,
            player_pk,
            &mut transcript,
        );

        Self {
            input_cards: input_cards.to_vec(),
            output_cards,
            leave_proof,
        }
    }
}
