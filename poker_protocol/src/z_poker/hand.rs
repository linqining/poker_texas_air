use super::card::{PlayingCard, Rank, Suit};
use std::cmp::Ordering;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HandRank {
    HighCard = 1,
    OnePair = 2,
    TwoPair = 3,
    ThreeOfAKind = 4,
    Straight = 5,
    Flush = 6,
    FullHouse = 7,
    FourOfAKind = 8,
    StraightFlush = 9,
    RoyalFlush = 10,
}

impl fmt::Display for HandRank {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HighCard => write!(f, "High Card"),
            Self::OnePair => write!(f, "One Pair"),
            Self::TwoPair => write!(f, "Two Pair"),
            Self::ThreeOfAKind => write!(f, "Three of a Kind"),
            Self::Straight => write!(f, "Straight"),
            Self::Flush => write!(f, "Flush"),
            Self::FullHouse => write!(f, "Full House"),
            Self::FourOfAKind => write!(f, "Four of a Kind"),
            Self::StraightFlush => write!(f, "Straight Flush"),
            Self::RoyalFlush => write!(f, "Royal Flush"),
        }
    }
}

use std::fmt;

#[derive(Debug, Clone)]
pub struct PokerHand {
    pub cards: Vec<PlayingCard>,
    pub rank: HandRank,
    pub kickers: Vec<Rank>,
}

impl PokerHand {
    pub fn new(cards: Vec<PlayingCard>) -> Option<Self> {
        if !(5..=7).contains(&cards.len()) {
            return None;
        }
        let mut sorted_cards = cards.clone();
        sorted_cards.sort_by(|a, b| b.rank.cmp(&a.rank));
        let evaluator = HandEvaluator::evaluate(&sorted_cards)?;
        Some(Self {
            cards: sorted_cards,
            rank: evaluator.0,
            kickers: evaluator.1,
        })
    }

    pub fn cmp_hands(&self, other: &Self) -> Ordering {
        match self.rank.cmp(&other.rank) {
            Ordering::Equal => {
                for (a, b) in self.kickers.iter().zip(other.kickers.iter()) {
                    match a.cmp(b) {
                        Ordering::Equal => continue,
                        ord => return ord,
                    }
                }
                Ordering::Equal
            }
            ord => ord,
        }
    }

    pub fn beats(&self, other: &Self) -> bool {
        matches!(self.cmp_hands(other), Ordering::Greater)
    }
}

impl fmt::Display for PokerHand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cards_str: Vec<String> = self.cards.iter().map(|c| format!("{}", c)).collect();
        write!(f, "[{}] {} ({})", cards_str.join(" "), self.rank, {
            let kicker_str: Vec<String> = self.kickers.iter().map(|r| format!("{}", r)).collect();
            kicker_str.join(",")
        })
    }
}

pub struct HandEvaluator;

impl HandEvaluator {
    /// Evaluate a hand of 5, 6, or 7 cards and return the best hand rank with kickers.
    pub fn evaluate(cards: &[PlayingCard]) -> Option<(HandRank, Vec<Rank>)> {
        if cards.len() < 5 {
            return None;
        }
        if cards.len() == 5 {
            return Self::evaluate_five(cards);
        }
        // For 6 or 7 cards, enumerate all C(n,5) combinations and return the best
        Self::best_five_from_n(cards)
    }

    /// Evaluate exactly 5 cards (must be pre-sorted by rank descending).
    fn evaluate_five(cards: &[PlayingCard]) -> Option<(HandRank, Vec<Rank>)> {
        if cards.len() != 5 {
            return None;
        }
        let ranks: Vec<Rank> = cards.iter().map(|c| c.rank).collect();
        let suits: Vec<Suit> = cards.iter().map(|c| c.suit).collect();

        let flush_result = Self::check_flush(&suits, &ranks);
        let straight_high = Self::straight_high_card(&ranks);

        if flush_result.is_some() && straight_high.is_some() {
            let high = straight_high.unwrap();
            if high == Rank::Ace {
                return Some((HandRank::RoyalFlush, vec![high]));
            }
            return Some((HandRank::StraightFlush, vec![high]));
        }

        if let Some(flush_ranks) = flush_result {
            return Some((HandRank::Flush, flush_ranks));
        }

        if let Some(high) = straight_high {
            return Some((HandRank::Straight, vec![high]));
        }

        let counts = Self::count_ranks(&ranks);
        let mut count_vec: Vec<(usize, Rank)> = counts
            .into_iter()
            .map(|(rank, count)| (count, rank))
            .collect();
        count_vec.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));

        match count_vec[0].0 {
            4 => Some((HandRank::FourOfAKind, vec![count_vec[0].1, count_vec[1].1])),
            3 => {
                if count_vec.len() > 1 && count_vec[1].0 >= 2 {
                    Some((HandRank::FullHouse, vec![count_vec[0].1, count_vec[1].1]))
                } else {
                    Some((
                        HandRank::ThreeOfAKind,
                        vec![
                            count_vec[0].1,
                            count_vec.get(1).map(|c| c.1).unwrap_or(Rank::Two),
                            count_vec.get(2).map(|c| c.1).unwrap_or(Rank::Two),
                        ],
                    ))
                }
            }
            2 => {
                if count_vec.len() > 1 && count_vec[1].0 == 2 {
                    Some((HandRank::TwoPair, vec![count_vec[0].1, count_vec[1].1]))
                } else {
                    Some((
                        HandRank::OnePair,
                        vec![
                            count_vec[0].1,
                            count_vec.get(1).map(|c| c.1).unwrap_or(Rank::Two),
                            count_vec.get(2).map(|c| c.1).unwrap_or(Rank::Two),
                            count_vec.get(3).map(|c| c.1).unwrap_or(Rank::Two),
                        ],
                    ))
                }
            }
            _ => Some((HandRank::HighCard, ranks)),
        }
    }

    /// Enumerate all C(n,5) combinations from n cards and return the best hand.
    fn best_five_from_n(cards: &[PlayingCard]) -> Option<(HandRank, Vec<Rank>)> {
        let n = cards.len();
        if n < 5 {
            return None;
        }

        let mut best: Option<(HandRank, Vec<Rank>)> = None;

        // Generate all combinations of 5 cards from n using bitmask approach
        // For n <= 7, at most C(7,5) = 21 combinations
        let combo_count = choose(n, 5);
        for mask in 0..combo_count {
            let combo = nth_combination(cards, 5, mask);
            let mut sorted = combo;
            sorted.sort_by(|a, b| b.rank.cmp(&a.rank));
            if let Some(result) = Self::evaluate_five(&sorted) {
                if best.is_none()
                    || compare_hands(&result, best.as_ref().unwrap()) == Ordering::Greater
                {
                    best = Some(result);
                }
            }
        }

        best
    }

    /// Check if all 5 cards share the same suit. Returns the ranks if flush.
    fn check_flush(suits: &[Suit], ranks: &[Rank]) -> Option<Vec<Rank>> {
        if suits.len() != 5 {
            return None;
        }
        let first = suits[0];
        if suits.iter().all(|&s| s == first) {
            Some(ranks.to_vec())
        } else {
            None
        }
    }

    /// Check if 5 cards form a straight. Returns the high card of the straight if so.
    /// For a wheel (A-2-3-4-5), returns Five as the high card.
    fn straight_high_card(ranks: &[Rank]) -> Option<Rank> {
        if ranks.len() != 5 {
            return None;
        }
        // Check for duplicates
        for i in 0..5 {
            for j in (i + 1)..5 {
                if ranks[i] == ranks[j] {
                    return None;
                }
            }
        }
        let high = ranks[0].numeric_value();
        let low = ranks[4].numeric_value();
        if high - low == 4 {
            return Some(ranks[0]);
        }
        // Wheel straight: A-2-3-4-5 (sorted descending: A,5,4,3,2)
        if ranks[0] == Rank::Ace && ranks[1] == Rank::Five {
            return Some(Rank::Five);
        }
        None
    }

    fn count_ranks(ranks: &[Rank]) -> std::collections::HashMap<Rank, usize> {
        let mut map = std::collections::HashMap::new();
        for &r in ranks {
            *map.entry(r).or_insert(0) += 1;
        }
        map
    }
}

/// Compare two (HandRank, Vec<Rank>) results, returning the Ordering.
fn compare_hands(a: &(HandRank, Vec<Rank>), b: &(HandRank, Vec<Rank>)) -> Ordering {
    match a.0.cmp(&b.0) {
        Ordering::Equal => {
            for (ra, rb) in a.1.iter().zip(b.1.iter()) {
                match ra.cmp(rb) {
                    Ordering::Equal => continue,
                    ord => return ord,
                }
            }
            Ordering::Equal
        }
        ord => ord,
    }
}

/// Compute binomial coefficient C(n, k).
fn choose(n: usize, k: usize) -> usize {
    if k > n {
        return 0;
    }
    if k == 0 || k == n {
        return 1;
    }
    let k = k.min(n - k);
    let mut result = 1usize;
    for i in 0..k {
        result = result * (n - i) / (i + 1);
    }
    result
}

/// Return the `mask`-th combination of `k` items from `items` (in lexicographic order).
fn nth_combination<T: Clone>(items: &[T], k: usize, mask: usize) -> Vec<T> {
    let n = items.len();
    let mut result = Vec::with_capacity(k);
    let mut remaining = mask;
    let mut start = 0;
    for i in 0..k {
        // For position i, try each candidate starting from `start`
        for j in start..=n - (k - i) {
            let count = choose(n - j - 1, k - i - 1);
            if remaining < count {
                result.push(items[j].clone());
                start = j + 1;
                break;
            }
            remaining -= count;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_high_card() {
        let cards = vec![
            PlayingCard::new(Rank::Two, Suit::Club),
            PlayingCard::new(Rank::Five, Suit::Diamond),
            PlayingCard::new(Rank::Seven, Suit::Heart),
            PlayingCard::new(Rank::Nine, Suit::Spade),
            PlayingCard::new(Rank::King, Suit::Club),
        ];
        let hand = PokerHand::new(cards);
        assert!(hand.is_some());
        let h = hand.unwrap();
        assert_eq!(h.rank, HandRank::HighCard);
    }

    #[test]
    fn test_royal_flush() {
        let cards = vec![
            PlayingCard::new(Rank::Ace, Suit::Spade),
            PlayingCard::new(Rank::King, Suit::Spade),
            PlayingCard::new(Rank::Queen, Suit::Spade),
            PlayingCard::new(Rank::Jack, Suit::Spade),
            PlayingCard::new(Rank::Ten, Suit::Spade),
        ];
        let hand = PokerHand::new(cards);
        assert!(hand.is_some());
        let h = hand.unwrap();
        assert_eq!(h.rank, HandRank::RoyalFlush);
    }

    #[test]
    fn test_four_of_a_kind() {
        let cards = vec![
            PlayingCard::new(Rank::Ace, Suit::Club),
            PlayingCard::new(Rank::Ace, Suit::Diamond),
            PlayingCard::new(Rank::Ace, Suit::Heart),
            PlayingCard::new(Rank::Ace, Suit::Spade),
            PlayingCard::new(Rank::King, Suit::Club),
        ];
        let hand = PokerHand::new(cards);
        assert!(hand.is_some());
        let h = hand.unwrap();
        assert_eq!(h.rank, HandRank::FourOfAKind);
    }

    #[test]
    fn test_hand_comparison() {
        let royal = vec![
            PlayingCard::new(Rank::Ace, Suit::Spade),
            PlayingCard::new(Rank::King, Suit::Spade),
            PlayingCard::new(Rank::Queen, Suit::Spade),
            PlayingCard::new(Rank::Jack, Suit::Spade),
            PlayingCard::new(Rank::Ten, Suit::Spade),
        ];
        let pair = vec![
            PlayingCard::new(Rank::Two, Suit::Club),
            PlayingCard::new(Rank::Two, Suit::Diamond),
            PlayingCard::new(Rank::Three, Suit::Heart),
            PlayingCard::new(Rank::Four, Suit::Spade),
            PlayingCard::new(Rank::Five, Suit::Club),
        ];

        let h1 = PokerHand::new(royal).unwrap();
        let h2 = PokerHand::new(pair).unwrap();
        assert!(h1.beats(&h2));
    }

    #[test]
    fn test_less_than_5_cards_returns_none() {
        let cards = vec![
            PlayingCard::new(Rank::Ace, Suit::Spade),
            PlayingCard::new(Rank::King, Suit::Spade),
            PlayingCard::new(Rank::Queen, Suit::Spade),
            PlayingCard::new(Rank::Jack, Suit::Spade),
        ];
        assert!(PokerHand::new(cards).is_none());
    }

    // === 7-card hand evaluation tests ===

    #[test]
    fn test_seven_card_flush() {
        // 7 cards with 5 hearts forming a flush
        let cards = vec![
            PlayingCard::new(Rank::Ace, Suit::Heart),
            PlayingCard::new(Rank::King, Suit::Heart),
            PlayingCard::new(Rank::Queen, Suit::Heart),
            PlayingCard::new(Rank::Jack, Suit::Heart),
            PlayingCard::new(Rank::Nine, Suit::Heart),
            PlayingCard::new(Rank::Two, Suit::Club),
            PlayingCard::new(Rank::Three, Suit::Diamond),
        ];
        let hand = PokerHand::new(cards).unwrap();
        assert_eq!(hand.rank, HandRank::Flush);
        // Kickers should be the best 5 flush cards: A,K,Q,J,9
        assert_eq!(
            hand.kickers,
            vec![Rank::Ace, Rank::King, Rank::Queen, Rank::Jack, Rank::Nine]
        );
    }

    #[test]
    fn test_seven_card_straight() {
        // 7 cards containing a straight 9-K
        let cards = vec![
            PlayingCard::new(Rank::King, Suit::Club),
            PlayingCard::new(Rank::Queen, Suit::Diamond),
            PlayingCard::new(Rank::Jack, Suit::Heart),
            PlayingCard::new(Rank::Ten, Suit::Spade),
            PlayingCard::new(Rank::Nine, Suit::Club),
            PlayingCard::new(Rank::Two, Suit::Heart),
            PlayingCard::new(Rank::Three, Suit::Diamond),
        ];
        let hand = PokerHand::new(cards).unwrap();
        assert_eq!(hand.rank, HandRank::Straight);
        assert_eq!(hand.kickers, vec![Rank::King]);
    }

    #[test]
    fn test_seven_card_full_house() {
        // 7 cards: three Aces and two Kings form a full house
        let cards = vec![
            PlayingCard::new(Rank::Ace, Suit::Club),
            PlayingCard::new(Rank::Ace, Suit::Diamond),
            PlayingCard::new(Rank::Ace, Suit::Heart),
            PlayingCard::new(Rank::King, Suit::Club),
            PlayingCard::new(Rank::King, Suit::Diamond),
            PlayingCard::new(Rank::Two, Suit::Heart),
            PlayingCard::new(Rank::Three, Suit::Spade),
        ];
        let hand = PokerHand::new(cards).unwrap();
        assert_eq!(hand.rank, HandRank::FullHouse);
        assert_eq!(hand.kickers, vec![Rank::Ace, Rank::King]);
    }

    #[test]
    fn test_seven_card_full_house_over_trips() {
        // 7 cards: three Aces, two Kings, two Queens -> best is full house Aces over Kings
        let cards = vec![
            PlayingCard::new(Rank::Ace, Suit::Club),
            PlayingCard::new(Rank::Ace, Suit::Diamond),
            PlayingCard::new(Rank::Ace, Suit::Heart),
            PlayingCard::new(Rank::King, Suit::Club),
            PlayingCard::new(Rank::King, Suit::Diamond),
            PlayingCard::new(Rank::Queen, Suit::Heart),
            PlayingCard::new(Rank::Queen, Suit::Spade),
        ];
        let hand = PokerHand::new(cards).unwrap();
        assert_eq!(hand.rank, HandRank::FullHouse);
        assert_eq!(hand.kickers, vec![Rank::Ace, Rank::King]);
    }

    #[test]
    fn test_seven_card_straight_flush() {
        // 7 cards with a straight flush in spades: 9-K of spades
        let cards = vec![
            PlayingCard::new(Rank::King, Suit::Spade),
            PlayingCard::new(Rank::Queen, Suit::Spade),
            PlayingCard::new(Rank::Jack, Suit::Spade),
            PlayingCard::new(Rank::Ten, Suit::Spade),
            PlayingCard::new(Rank::Nine, Suit::Spade),
            PlayingCard::new(Rank::King, Suit::Heart),
            PlayingCard::new(Rank::Two, Suit::Club),
        ];
        let hand = PokerHand::new(cards).unwrap();
        assert_eq!(hand.rank, HandRank::StraightFlush);
        assert_eq!(hand.kickers, vec![Rank::King]);
    }

    #[test]
    fn test_seven_card_four_of_a_kind() {
        // 7 cards with four Aces
        let cards = vec![
            PlayingCard::new(Rank::Ace, Suit::Club),
            PlayingCard::new(Rank::Ace, Suit::Diamond),
            PlayingCard::new(Rank::Ace, Suit::Heart),
            PlayingCard::new(Rank::Ace, Suit::Spade),
            PlayingCard::new(Rank::King, Suit::Club),
            PlayingCard::new(Rank::Two, Suit::Heart),
            PlayingCard::new(Rank::Three, Suit::Diamond),
        ];
        let hand = PokerHand::new(cards).unwrap();
        assert_eq!(hand.rank, HandRank::FourOfAKind);
        assert_eq!(hand.kickers, vec![Rank::Ace, Rank::King]);
    }

    #[test]
    fn test_seven_card_two_pair() {
        // 7 cards with two pairs but no better hand
        let cards = vec![
            PlayingCard::new(Rank::Ace, Suit::Club),
            PlayingCard::new(Rank::Ace, Suit::Diamond),
            PlayingCard::new(Rank::King, Suit::Club),
            PlayingCard::new(Rank::King, Suit::Diamond),
            PlayingCard::new(Rank::Nine, Suit::Heart),
            PlayingCard::new(Rank::Two, Suit::Spade),
            PlayingCard::new(Rank::Three, Suit::Club),
        ];
        let hand = PokerHand::new(cards).unwrap();
        assert_eq!(hand.rank, HandRank::TwoPair);
    }

    #[test]
    fn test_seven_card_wheel_straight() {
        // 7 cards with A-2-3-4-5 straight (wheel)
        let cards = vec![
            PlayingCard::new(Rank::Ace, Suit::Club),
            PlayingCard::new(Rank::Five, Suit::Diamond),
            PlayingCard::new(Rank::Four, Suit::Heart),
            PlayingCard::new(Rank::Three, Suit::Spade),
            PlayingCard::new(Rank::Two, Suit::Club),
            PlayingCard::new(Rank::King, Suit::Heart),
            PlayingCard::new(Rank::Queen, Suit::Diamond),
        ];
        let hand = PokerHand::new(cards).unwrap();
        assert_eq!(hand.rank, HandRank::Straight);
        // Wheel straight: high card is 5 (Ace plays low)
        assert_eq!(hand.kickers, vec![Rank::Five]);
    }

    #[test]
    fn test_six_card_flush() {
        // 6 cards with 5 hearts forming a flush
        let cards = vec![
            PlayingCard::new(Rank::Ace, Suit::Heart),
            PlayingCard::new(Rank::King, Suit::Heart),
            PlayingCard::new(Rank::Queen, Suit::Heart),
            PlayingCard::new(Rank::Jack, Suit::Heart),
            PlayingCard::new(Rank::Nine, Suit::Heart),
            PlayingCard::new(Rank::Two, Suit::Club),
        ];
        let hand = PokerHand::new(cards).unwrap();
        assert_eq!(hand.rank, HandRank::Flush);
    }

    #[test]
    fn test_seven_card_best_flush_over_straight() {
        // 7 cards where both a straight and flush are possible, flush wins
        let cards = vec![
            PlayingCard::new(Rank::Ace, Suit::Heart),
            PlayingCard::new(Rank::King, Suit::Heart),
            PlayingCard::new(Rank::Queen, Suit::Heart),
            PlayingCard::new(Rank::Jack, Suit::Heart),
            PlayingCard::new(Rank::Nine, Suit::Heart),
            PlayingCard::new(Rank::Ten, Suit::Club),
            PlayingCard::new(Rank::Eight, Suit::Diamond),
        ];
        let hand = PokerHand::new(cards).unwrap();
        assert_eq!(hand.rank, HandRank::Flush);
    }

    #[test]
    fn test_choose_function() {
        assert_eq!(choose(7, 5), 21);
        assert_eq!(choose(6, 5), 6);
        assert_eq!(choose(5, 5), 1);
        assert_eq!(choose(7, 3), 35);
    }

    #[test]
    fn test_nth_combination_covers_all() {
        let cards: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7];
        let count = choose(7, 5);
        let mut all_combos: Vec<Vec<u8>> =
            (0..count).map(|i| nth_combination(&cards, 5, i)).collect();
        // Sort for deterministic comparison
        all_combos.sort();
        // There should be exactly 21 unique combinations
        assert_eq!(all_combos.len(), 21);
        // First combo should be [1,2,3,4,5]
        assert_eq!(all_combos[0], vec![1, 2, 3, 4, 5]);
        // Last combo should be [3,4,5,6,7]
        assert_eq!(all_combos[20], vec![3, 4, 5, 6, 7]);
    }
}
