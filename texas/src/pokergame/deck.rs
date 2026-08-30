use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use poker_protocol::z_poker::{PlayingCard};

use crate::pokergame::game_state::ElGamalCiphertextJson;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Card {
    pub suit: String,
    pub rank: String,
}

impl Card {
    pub fn from_playing_card(card: &PlayingCard) -> Self {
        Self { suit: card.suit.short_name_lower().to_string(),  rank: card.rank.to_string() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deck {
    pub cards: Vec<Card>,
}

impl Deck {
    pub fn new() -> Self {
        let suits = vec!["s", "h", "d", "c"];
        let ranks = vec!["A", "K", "Q", "J", "10", "9", "8", "7", "6", "5", "4", "3", "2"];
        let mut cards: Vec<Card> = Vec::new();
        for suit in &suits {
            for rank in &ranks {
                cards.push(Card { suit: suit.to_string(), rank: rank.to_string() });
            }
        }
        let mut rng = rand::thread_rng();
        for _ in 0..8 {
            cards.shuffle(&mut rng);
        }
        Self { cards }
    }


}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedDeck {
    pub cards: Vec<ElGamalCiphertextJson>,
}