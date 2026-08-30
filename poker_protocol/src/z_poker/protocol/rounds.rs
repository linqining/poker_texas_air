use crate::crypto::{DefaultCurve, EcPoint, ElGamalCiphertext, Scalar, N_CARDS};
use crate::zk_shuffle::leave_proof::{leave_ciphertext, LeaveProof};
use crate::zk_shuffle::remask_proof::{remask_ciphertext, RemaskProof};
use crate::zk_shuffle::ShuffleProof;
// 兼容 Move 合约：生产代码使用 FiatShamirTranscript（SHA3-256），
// 而非 FiatShamirTranscript（STROBE），因为 Move 合约使用 SHA3-256 状态机。
use crate::crypto::curve::CurveScalar;
use crate::z_poker::key_manager::PKOwnershipProof;
use crate::zk_shuffle::transcript_ext::{CryptoTranscript, FiatShamirTranscript};
use rand_core::{CryptoRng, OsRng, RngCore};

#[derive(Debug)]
pub struct ShuffleRound {
    pub input_cards: Vec<ElGamalCiphertext>,
    pub output_cards: Vec<ElGamalCiphertext>,
    pub proof: ShuffleProof,
}

impl ShuffleRound {
    pub fn execute(
        input_cards: &[ElGamalCiphertext],
        share_pk: &EcPoint,
        transcript: &mut impl CryptoTranscript,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Self {
        //todo 用户传入permute，核心是用户洗牌
        let permute: [usize; N_CARDS] = {
            let mut arr: Vec<usize> = (0..N_CARDS).collect();
            use rand::seq::SliceRandom;
            arr.shuffle(rng);
            let mut fixed = [0usize; N_CARDS];
            fixed.copy_from_slice(&arr);
            fixed
        };

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

        ShuffleRound {
            input_cards: input_cards.to_vec(),
            output_cards: output,
            proof,
        }
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
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Self {
        // 创建共享 transcript，绑定 remask_proof 和 shuffle_proof
        let mut transcript = FiatShamirTranscript::new(b"zk_mask_shuffle_proof_v2");

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
        let shuffle_round = ShuffleRound::execute(&mask_cards, share_pk, &mut transcript, rng);
        Self {
            mask_cards,
            output_cards: shuffle_round.output_cards,
            proof: shuffle_round.proof,
            remask_proof,
        }
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

        let mut transcript = FiatShamirTranscript::new(b"zk_leave_proof_v1");
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

        let mut transcript = FiatShamirTranscript::new(b"zk_leave_proof_v1");
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
