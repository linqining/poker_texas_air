//! Texas Poker 牌的数据结构（移植自 `texas_poker_move/sources/card.move`）。
//!
//! # 花色编码差异
//!
//! 注意：原 Move 合约存在两套花色编码：
//! - `Card`（table.move 用）：SPADES=0, HEARTS=1, DIAMONDS=2, CLUBS=3
//! - `PlayingCard`（Mental Poker 解密后映射用）：Club=0, Diamond=1, Heart=2, Spade=3
//!
//! 本模块同时提供两套常量，并在 `playing_card_to_card` 中处理映射。

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::ops::Deref;

// ===== Card 花色常量（table.move 编码）=====

pub const SPADES: u8 = 0;
pub const HEARTS: u8 = 1;
pub const DIAMONDS: u8 = 2;
pub const CLUBS: u8 = 3;

// ===== Card 点数常量 =====

pub const TWO: u8 = 2;
pub const THREE: u8 = 3;
pub const FOUR: u8 = 4;
pub const FIVE: u8 = 5;
pub const SIX: u8 = 6;
pub const SEVEN: u8 = 7;
pub const EIGHT: u8 = 8;
pub const NINE: u8 = 9;
pub const TEN: u8 = 10;
pub const JACK: u8 = 11;
pub const QUEEN: u8 = 12;
pub const KING: u8 = 13;
pub const ACE: u8 = 14;

/// Canonical card identifier (`0..=51`).
///
/// The persisted representation is exactly one byte. Suit and rank are deterministic views:
/// `suit = id / 13`, `rank = id % 13 + 2`. Values outside `0..52` are transient invalid
/// sentinels and are rejected by canonical table validation.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
#[serde(transparent)]
pub struct Card(u8);

impl Card {
    /// Canonical padding value used by fixed-capacity card containers.
    pub const PADDING: Self = Self(u8::MAX);

    /// 构造新牌。
    #[must_use]
    pub const fn new(suit: u8, rank: u8) -> Self {
        if suit <= CLUBS && rank >= TWO && rank <= ACE {
            Self(suit * 13 + (rank - TWO))
        } else if suit <= CLUBS && rank == 0 {
            // Transient evaluator-only padding. Canonical state rejects these values.
            Self(52 + suit)
        } else {
            Self::PADDING
        }
    }

    /// 校验牌的合法性。
    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.0 < 52
    }

    /// 转为 0..51 索引（suit * 13 + (rank - 2)）。
    #[must_use]
    pub const fn to_index(self) -> u8 {
        self.0
    }

    /// 从 0..51 索引构造牌。
    #[must_use]
    pub const fn from_index(idx: u8) -> Self {
        Self(idx)
    }

    /// Return the table-encoding suit (`0..=3`) or `u8::MAX` for a generic invalid sentinel.
    #[must_use]
    pub const fn suit(self) -> u8 {
        if self.0 < 52 {
            self.0 / 13
        } else if self.0 < 56 {
            self.0 - 52
        } else {
            u8::MAX
        }
    }

    /// Return the rank (`2..=14`) or zero for a transient invalid/padding card.
    #[must_use]
    pub const fn rank(self) -> u8 {
        if self.0 < 52 { (self.0 % 13) + TWO } else { 0 }
    }

    /// 花色名称。
    #[must_use]
    pub fn suit_name(&self) -> &'static str {
        match self.suit() {
            SPADES => "♠",
            HEARTS => "♥",
            DIAMONDS => "♦",
            CLUBS => "♣",
            _ => "?",
        }
    }

    /// 点数名称。
    #[must_use]
    pub fn rank_name(&self) -> &'static str {
        match self.rank() {
            TWO => "2",
            THREE => "3",
            FOUR => "4",
            FIVE => "5",
            SIX => "6",
            SEVEN => "7",
            EIGHT => "8",
            NINE => "9",
            TEN => "10",
            JACK => "J",
            QUEEN => "Q",
            KING => "K",
            ACE => "A",
            _ => "?",
        }
    }

    /// 显示字符串（如 "A♠"）。
    #[must_use]
    pub fn display(&self) -> String {
        format!("{}{}", self.rank_name(), self.suit_name())
    }
}

impl Default for Card {
    fn default() -> Self {
        Self::PADDING
    }
}

impl std::fmt::Display for Card {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display())
    }
}

// ===== PlayingCard（Mental Poker 解密后映射用）=====

/// Mental Poker 解密后的牌结构（花色编码与 `Card` 不同）。
///
/// 与 Move `PlayingCard` struct 一致：
/// - rank: 2-14
/// - suit: 0=Club, 1=Diamond, 2=Heart, 3=Spade
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct PlayingCard {
    pub rank: u8,
    pub suit: u8,
}

impl PlayingCard {
    /// 构造新 PlayingCard。
    #[must_use]
    pub const fn new(rank: u8, suit: u8) -> Self {
        Self { rank, suit }
    }

    /// 将 PlayingCard 转为 Card（处理花色编码差异）。
    ///
    /// 映射规则（与 table.move:254-262 一致）：
    /// - PlayingCard Club(0)    → Card CLUBS(3)
    /// - PlayingCard Diamond(1) → Card DIAMONDS(2)
    /// - PlayingCard Heart(2)   → Card HEARTS(1)
    /// - PlayingCard Spade(3)   → Card SPADES(0)
    #[must_use]
    pub fn to_card(&self) -> Card {
        let card_suit = match self.suit {
            0 => CLUBS,
            1 => DIAMONDS,
            2 => HEARTS,
            3 => SPADES,
            _ => CLUBS, // 不应发生
        };
        Card::new(card_suit, self.rank)
    }
}

/// Fixed-capacity canonical two-card hand.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct HoleCards {
    len: u8,
    cards: [Card; 2],
}

impl HoleCards {
    /// Empty hand with canonical padding.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            len: 0,
            cards: [Card::PADDING; 2],
        }
    }

    /// Number of live cards.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Whether the hand is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Live cards in dealing order.
    #[must_use]
    pub fn as_slice(&self) -> &[Card] {
        &self.cards[..self.len()]
    }

    /// Append one valid card, rejecting a third card.
    pub fn try_push(&mut self, card: Card) -> Result<(), &'static str> {
        if !card.is_valid() {
            return Err("hole card id is outside 0..52");
        }
        if self.len() >= self.cards.len() {
            return Err("hole cards exceed capacity 2");
        }
        self.cards[self.len()] = card;
        self.len += 1;
        Ok(())
    }

    /// Remove all cards and restore canonical padding.
    pub fn clear(&mut self) {
        *self = Self::empty();
    }

    /// Validate length, cards and unused padding.
    pub fn validate_canonical(&self) -> Result<(), &'static str> {
        if self.len() > self.cards.len() {
            return Err("hole-card length exceeds capacity 2");
        }
        if self.as_slice().iter().any(|card| !card.is_valid()) {
            return Err("hole cards contain an invalid card id");
        }
        if self.cards[self.len()..]
            .iter()
            .any(|card| *card != Card::PADDING)
        {
            return Err("hole cards contain non-canonical padding");
        }
        Ok(())
    }
}

impl Default for HoleCards {
    fn default() -> Self {
        Self::empty()
    }
}

impl Deref for HoleCards {
    type Target = [Card];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<'a> IntoIterator for &'a HoleCards {
    type Item = &'a Card;
    type IntoIter = std::slice::Iter<'a, Card>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}

impl TryFrom<Vec<Card>> for HoleCards {
    type Error = &'static str;

    fn try_from(cards: Vec<Card>) -> Result<Self, Self::Error> {
        let mut result = Self::empty();
        for card in cards {
            result.try_push(card)?;
        }
        Ok(result)
    }
}

impl From<[Card; 2]> for HoleCards {
    fn from(cards: [Card; 2]) -> Self {
        Self { len: 2, cards }
    }
}

impl PartialEq<Vec<Card>> for HoleCards {
    fn eq(&self, other: &Vec<Card>) -> bool {
        self.as_slice() == other.as_slice()
    }
}

/// Fixed-capacity canonical public-board or runout-suffix cards.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BoardCards {
    len: u8,
    cards: [Card; 5],
}

impl BoardCards {
    /// Empty board with canonical padding.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            len: 0,
            cards: [Card::PADDING; 5],
        }
    }

    /// Number of live cards.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len as usize
    }

    /// Whether the board is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Live cards in dealing order.
    #[must_use]
    pub fn as_slice(&self) -> &[Card] {
        &self.cards[..self.len()]
    }

    /// Append one valid card, rejecting a sixth card.
    pub fn try_push(&mut self, card: Card) -> Result<(), &'static str> {
        if !card.is_valid() {
            return Err("board card id is outside 0..52");
        }
        if self.len() >= self.cards.len() {
            return Err("board cards exceed capacity 5");
        }
        self.cards[self.len()] = card;
        self.len += 1;
        Ok(())
    }

    /// Remove all cards and restore canonical padding.
    pub fn clear(&mut self) {
        *self = Self::empty();
    }

    /// Convert the live prefix to a vector for event and settlement boundaries.
    #[must_use]
    pub fn to_vec(&self) -> Vec<Card> {
        self.as_slice().to_vec()
    }

    /// Validate length, cards and unused padding.
    pub fn validate_canonical(&self) -> Result<(), &'static str> {
        if self.len() > self.cards.len() {
            return Err("board length exceeds capacity 5");
        }
        if self.as_slice().iter().any(|card| !card.is_valid()) {
            return Err("board contains an invalid card id");
        }
        if self.cards[self.len()..]
            .iter()
            .any(|card| *card != Card::PADDING)
        {
            return Err("board contains non-canonical padding");
        }
        Ok(())
    }
}

impl Default for BoardCards {
    fn default() -> Self {
        Self::empty()
    }
}

impl Deref for BoardCards {
    type Target = [Card];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<'a> IntoIterator for &'a BoardCards {
    type Item = &'a Card;
    type IntoIter = std::slice::Iter<'a, Card>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}

impl TryFrom<Vec<Card>> for BoardCards {
    type Error = &'static str;

    fn try_from(cards: Vec<Card>) -> Result<Self, Self::Error> {
        let mut result = Self::empty();
        for card in cards {
            result.try_push(card)?;
        }
        Ok(result)
    }
}

impl PartialEq<Vec<Card>> for BoardCards {
    fn eq(&self, other: &Vec<Card>) -> bool {
        self.as_slice() == other.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_card_valid() {
        assert!(Card::new(SPADES, ACE).is_valid());
        assert!(Card::new(CLUBS, TWO).is_valid());
        assert!(!Card::new(4, ACE).is_valid()); // 非法花色
        assert!(!Card::new(SPADES, 1).is_valid()); // 非法点数
        assert!(!Card::new(SPADES, 15).is_valid()); // 非法点数
    }

    #[test]
    fn test_card_index_roundtrip() {
        for idx in 0..52 {
            let card = Card::from_index(idx);
            assert_eq!(card.to_index(), idx);
            assert!(card.is_valid());
        }
    }

    #[test]
    fn test_card_display() {
        assert_eq!(Card::new(SPADES, ACE).display(), "A♠");
        assert_eq!(Card::new(HEARTS, KING).display(), "K♥");
        assert_eq!(Card::new(DIAMONDS, TEN).display(), "10♦");
        assert_eq!(Card::new(CLUBS, TWO).display(), "2♣");
    }

    #[test]
    fn test_playing_card_to_card_mapping() {
        // PlayingCard Club(0) → Card CLUBS(3)
        assert_eq!(PlayingCard::new(ACE, 0).to_card(), Card::new(CLUBS, ACE));
        // PlayingCard Diamond(1) → Card DIAMONDS(2)
        assert_eq!(
            PlayingCard::new(KING, 1).to_card(),
            Card::new(DIAMONDS, KING)
        );
        // PlayingCard Heart(2) → Card HEARTS(1)
        assert_eq!(
            PlayingCard::new(QUEEN, 2).to_card(),
            Card::new(HEARTS, QUEEN)
        );
        // PlayingCard Spade(3) → Card SPADES(0)
        assert_eq!(PlayingCard::new(JACK, 3).to_card(), Card::new(SPADES, JACK));
    }
}
