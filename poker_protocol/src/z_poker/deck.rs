use std::collections::VecDeque;

use super::card::{standard_deck, PlayingCard, Rank, Suit};

#[derive(Debug, Clone)]
pub struct Deck {
    cards: VecDeque<PlayingCard>,
}

impl Deck {
    pub fn new_standard() -> Self {
        let cards = standard_deck().into();
        Self { cards }
    }

    pub fn from_cards(cards: Vec<PlayingCard>) -> Self {
        Self {
            cards: cards.into(),
        }
    }

    pub fn len(&self) -> usize {
        self.cards.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cards.is_empty()
    }

    pub fn get(&self, index: usize) -> Option<&PlayingCard> {
        self.cards.get(index)
    }

    pub fn cards(&self) -> Vec<PlayingCard> {
        self.cards.iter().copied().collect()
    }

    pub fn into_cards(self) -> Vec<PlayingCard> {
        self.cards.into()
    }

    pub fn shuffle<R: rand::Rng + ?Sized>(&mut self, rng: &mut R) {
        use rand::seq::SliceRandom;
        self.cards.make_contiguous().shuffle(rng);
    }

    pub fn deal(&mut self, count: usize) -> Option<Vec<PlayingCard>> {
        if self.cards.len() < count {
            return None;
        }
        Some(self.cards.drain(..count).collect())
    }

    pub fn deal_one(&mut self) -> Option<PlayingCard> {
        self.cards.pop_front()
    }

    pub fn push(&mut self, card: PlayingCard) {
        self.cards.push_back(card);
    }

    pub fn extend<I>(&mut self, cards: I)
    where
        I: IntoIterator<Item = PlayingCard>,
    {
        self.cards.extend(cards);
    }

    pub fn remove(&mut self, index: usize) -> Option<PlayingCard> {
        if index < self.cards.len() {
            self.cards.remove(index)
        } else {
            None
        }
    }

    pub fn find_by_rank_suit(&self, rank: Rank, suit: Suit) -> Option<usize> {
        self.cards
            .iter()
            .position(|c| c.rank == rank && c.suit == suit)
    }

    pub fn filter_by_suit(&self, suit: Suit) -> Vec<&PlayingCard> {
        self.cards.iter().filter(|c| c.suit == suit).collect()
    }

    pub fn filter_by_rank(&self, rank: Rank) -> Vec<&PlayingCard> {
        self.cards.iter().filter(|c| c.rank == rank).collect()
    }
}

impl Default for Deck {
    fn default() -> Self {
        Self::new_standard()
    }
}

impl IntoIterator for Deck {
    type Item = PlayingCard;
    type IntoIter = std::collections::vec_deque::IntoIter<PlayingCard>;

    fn into_iter(self) -> Self::IntoIter {
        self.cards.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::z_poker::card::STANDARD_DECK_SIZE;
    use rand;

    #[test]
    fn test_new_standard_52() {
        let deck = Deck::new_standard();
        assert_eq!(deck.len(), STANDARD_DECK_SIZE);
    }

    #[test]
    fn test_deal() {
        let mut deck = Deck::new_standard();
        let hand = deck.deal(5);
        assert!(hand.is_some());
        assert_eq!(hand.unwrap().len(), 5);
        assert_eq!(deck.len(), 47);
    }

    #[test]
    fn test_deal_too_many() {
        let mut deck = Deck::new_standard();
        assert!(deck.deal(53).is_none());
        assert_eq!(deck.len(), STANDARD_DECK_SIZE);
    }

    #[test]
    fn test_deal_one() {
        let mut deck = Deck::new_standard();
        for _ in 0..STANDARD_DECK_SIZE {
            assert!(deck.deal_one().is_some());
        }
        assert!(deck.deal_one().is_none());
        assert!(deck.is_empty());
    }

    #[test]
    fn test_shuffle_preserves_count() {
        let mut deck = Deck::new_standard();
        let original_len = deck.len();
        let mut rng = rand::thread_rng();
        deck.shuffle(&mut rng);
        assert_eq!(deck.len(), original_len);
    }

    #[test]
    fn test_filter_by_suit() {
        let deck = Deck::new_standard();
        let clubs = deck.filter_by_suit(Suit::Club);
        assert_eq!(clubs.len(), 13);
        for &c in &clubs {
            assert_eq!(c.suit, Suit::Club);
        }
    }

    #[test]
    fn test_into_iter() {
        let deck = Deck::new_standard();
        let count = deck.into_iter().count();
        assert_eq!(count, STANDARD_DECK_SIZE);
    }
}
