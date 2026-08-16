use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Suit {
    Club,
    Diamond,
    Heart,
    Spade,
}

impl Suit {
    pub const ALL: [Self; 4] = [Self::Club, Self::Diamond, Self::Heart, Self::Spade];

    pub fn symbol(&self) -> &'static str {
        match self {
            Self::Club => "\u{2663}",
            Self::Diamond => "\u{2666}",
            Self::Heart => "\u{2665}",
            Self::Spade => "\u{2660}",
        }
    }

    pub fn short_name(&self) -> &'static str {
        match self {
            Self::Club => "C",
            Self::Diamond => "D",
            Self::Heart => "H",
            Self::Spade => "S",
        }
    }

    pub fn short_name_lower(&self) -> &'static str {
        match self {
            Self::Club => "c",
            Self::Diamond => "d",
            Self::Heart => "h",
            Self::Spade => "s",
        }
    }

    pub fn is_red(&self) -> bool {
        matches!(self, Self::Diamond | Self::Heart)
    }

    pub fn is_black(&self) -> bool {
        !self.is_red()
    }

    pub fn from_index(i: usize) -> Option<Self> {
        Self::ALL.get(i).copied()
    }
}

impl fmt::Display for Suit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.symbol())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Rank {
    Two = 2,
    Three = 3,
    Four = 4,
    Five = 5,
    Six = 6,
    Seven = 7,
    Eight = 8,
    Nine = 9,
    Ten = 10,
    Jack = 11,
    Queen = 12,
    King = 13,
    Ace = 14,
}

impl Rank {
    pub const ALL: [Self; 13] = [
        Self::Two,
        Self::Three,
        Self::Four,
        Self::Five,
        Self::Six,
        Self::Seven,
        Self::Eight,
        Self::Nine,
        Self::Ten,
        Self::Jack,
        Self::Queen,
        Self::King,
        Self::Ace,
    ];

    pub fn symbol(&self) -> &'static str {
        match self {
            Self::Two => "2",
            Self::Three => "3",
            Self::Four => "4",
            Self::Five => "5",
            Self::Six => "6",
            Self::Seven => "7",
            Self::Eight => "8",
            Self::Nine => "9",
            Self::Ten => "10",
            Self::Jack => "J",
            Self::Queen => "Q",
            Self::King => "K",
            Self::Ace => "A",
        }
    }

    pub fn numeric_value(&self) -> u8 {
        *self as u8
    }

    pub fn is_face_card(&self) -> bool {
        matches!(self, Self::Jack | Self::Queen | Self::King)
    }

    pub fn is_ace(&self) -> bool {
        matches!(self, Self::Ace)
    }

    pub fn from_index(i: usize) -> Option<Self> {
        Self::ALL.get(i).copied()
    }
}

impl fmt::Display for Rank {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.symbol())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PlayingCard {
    pub rank: Rank,
    pub suit: Suit,
}

impl PlayingCard {
    pub fn new(rank: Rank, suit: Suit) -> Self {
        Self { rank, suit }
    }

    pub fn id(&self) -> usize {
        (self.rank.numeric_value() as usize - 2) + (self.suit_index() * 13)
    }

    fn suit_index(&self) -> usize {
        match self.suit {
            Suit::Club => 0,
            Suit::Diamond => 1,
            Suit::Heart => 2,
            Suit::Spade => 3,
        }
    }

    pub fn from_id(id: usize) -> Option<Self> {
        if id >= 52 {
            return None;
        }
        let rank_idx = id % 13;
        let suit_idx = id / 13;
        let rank = Rank::from_index(rank_idx)?;
        let suit = Suit::from_index(suit_idx)?;
        Some(Self { rank, suit })
    }

    pub fn from_index(index: usize) -> Option<Self> {
        Self::from_id(index)
    }
}

impl fmt::Display for PlayingCard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.suit.short_name_lower(), self.rank.symbol())
    }
}

pub const STANDARD_DECK_SIZE: usize = 52;

pub fn standard_deck() -> Vec<PlayingCard> {
    let mut deck = Vec::with_capacity(STANDARD_DECK_SIZE);
    for &suit in &Suit::ALL {
        for &rank in &Rank::ALL {
            deck.push(PlayingCard::new(rank, suit));
        }
    }
    deck
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_deck_has_52_cards() {
        let deck = standard_deck();
        assert_eq!(deck.len(), STANDARD_DECK_SIZE);
    }

    #[test]
    fn test_standard_deck_no_duplicates() {
        use std::collections::HashSet;
        let deck = standard_deck();
        let unique: HashSet<PlayingCard> = deck.iter().copied().collect();
        assert_eq!(unique.len(), STANDARD_DECK_SIZE);
    }

    #[test]
    fn test_standard_deck_covers_all_combinations() {
        let deck = standard_deck();
        for &suit in &Suit::ALL {
            for &rank in &Rank::ALL {
                assert!(
                    deck.iter().any(|c| c.rank == rank && c.suit == suit),
                    "Missing {}{}",
                    rank,
                    suit
                );
            }
        }
    }

    #[test]
    fn test_playing_card_id_roundtrip() {
        let deck = standard_deck();
        for card in &deck {
            let id = card.id();
            let restored = PlayingCard::from_id(id);
            assert_eq!(restored, Some(*card), "Roundtrip failed for {}", card);
        }
    }

    #[test]
    fn test_suit_properties() {
        assert!(!Suit::Club.is_red());
        assert!(Suit::Club.is_black());
        assert!(Suit::Diamond.is_red());
        assert!(!Suit::Diamond.is_black());
        assert!(Suit::Heart.is_red());
        assert!(!Suit::Heart.is_black());
        assert!(!Suit::Spade.is_red());
        assert!(Suit::Spade.is_black());
    }

    #[test]
    fn test_rank_ordering() {
        assert!(Rank::Two < Rank::Three);
        assert!(Rank::Ten < Rank::Jack);
        assert!(Rank::Jack < Rank::Queen);
        assert!(Rank::Queen < Rank::King);
        assert!(Rank::King < Rank::Ace);
    }
}
