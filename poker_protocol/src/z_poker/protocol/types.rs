use crate::crypto::{DefaultCurve, EcPoint, ElGamalCiphertext, PublicKey};
use crate::z_poker::card::PlayingCard;
use crate::zk_shuffle::reconstruction::{
    ReconstructProof, ReconstructProofV3, ReconstructionV3Statement,
};
use crate::zk_shuffle::reveal_token_proof::{RevealTokenProof, REVEAL_TOKEN_PROOF_LABEL};
use crate::zk_shuffle::transcript_ext::{CryptoTranscript, MerlinTranscript};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GamePhase {
    Setup,
    Shuffling,
    Dealing,
    Playing,
    Reveal,
    Finished,
}

#[derive(Debug, Clone)]
pub struct GameConfig {
    pub num_players: usize,
    pub cards_per_player: usize,
    pub community_cards: usize,
}

impl Default for GameConfig {
    fn default() -> Self {
        Self {
            num_players: 9,
            cards_per_player: 2,
            community_cards: 5,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PlayerEncryptedCard {
    pub card_index: u32,
    pub encrypted_card: ElGamalCiphertext,
    pub reveal_state: RevealState,
    pub playing_card: Option<PlayingCard>,
}

impl PlayerEncryptedCard {
    pub(crate) fn get_readable_card(&self, user_pk: PublicKey) -> Option<ElGamalCiphertext> {
        if self.reveal_state.pending_players.contains(&user_pk)
            && self.reveal_state.pending_players.len() == 1
        {
            let sum_token: EcPoint = self
                .reveal_state
                .reveal_tokens
                .iter()
                .map(|t| t.reveal_token)
                .sum();
            let mut readable_card = self.encrypted_card.clone();
            readable_card.c2 -= sum_token;
            Some(readable_card)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
pub struct DealResult {
    pub player_pk: String,
    pub encrypted_cards: Vec<ElGamalCiphertext>,
}

#[derive(Debug, Clone)]
pub struct RevealToken {
    pub encrypted_card: ElGamalCiphertext,
    pub proof: RevealTokenProof<DefaultCurve>,
    pub reveal_token: EcPoint,
    pub user_public_key: PublicKey,
}

impl RevealToken {
    pub(crate) fn is_ok(&self) -> bool {
        let mut transcript = MerlinTranscript::new(REVEAL_TOKEN_PROOF_LABEL);
        self.proof
            .verify(
                &self.encrypted_card,
                &self.reveal_token,
                &self.user_public_key,
                &mut transcript,
            )
            .is_ok()
    }
}

#[derive(Debug)]
pub struct ReconstructDeck {
    pub output_cards: Vec<ElGamalCiphertext>,
    pub swap_cards: Vec<ElGamalCiphertext>,
    pub proof: ReconstructProof<DefaultCurve>,
}

/// V3 reconstruction result sent as one statement/proof pair.
///
/// Unlike V2, it has no public swap list or coefficient responses. The hidden
/// readable-to-slot mapping exists only as the Bayer--Groth prover witness.
#[derive(Debug)]
pub struct ReconstructDeckV3 {
    pub statement: ReconstructionV3Statement<DefaultCurve>,
    pub proof: ReconstructProofV3<DefaultCurve>,
}

#[derive(Debug, Clone)]
pub struct RevealTokenSimple {
    pub proof: RevealTokenProof<DefaultCurve>,
    pub reveal_token: EcPoint,
    pub user_public_key: PublicKey,
}

#[derive(Debug, Clone)]
pub struct RevealState {
    pub pending_players: Vec<PublicKey>,       // 待亮牌的玩家
    pub reveal_tokens: Vec<RevealTokenSimple>, // 每个玩家的reveal_token
}

//todo user flod, add is_leave state
#[derive(Debug, Clone)]
pub struct PlayerState {
    pub pk_hex: String,
    pub pk: PublicKey,
    pub hand_encrypted: Vec<PlayerEncryptedCard>,
}
