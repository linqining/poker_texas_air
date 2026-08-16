use crate::crypto::{EcPoint, ElGamalCiphertext};

#[derive(Debug)]
pub struct ExpelRecord {
    pub expelled_player_pk: String,
    pub output_cards: Vec<ElGamalCiphertext>,
    pub expelled_card_positions: Vec<usize>,
    pub user_cards: Vec<ElGamalCiphertext>,
    pub agg_pk_at_proof_time: EcPoint,
    pub departed_player_pk: EcPoint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpelSessionPhase {
    Initiated,
    Collecting,
    Finalized,
}

#[derive(Debug, Clone)]
pub struct ExpelSummary {
    pub expelled_player_pk: String,
    pub remaining_players: usize,
    pub proofs_accepted: usize,
    pub cards_redealt: usize,
    pub deck_size: usize,
    pub community_revealed: usize,
}

#[derive(Debug, Clone)]
pub struct ExpelStateResponse {
    pub expelled_players: Vec<String>,
    pub expel_records_count: usize,
    pub active_players: Vec<String>,
    pub can_continue: bool,
}
