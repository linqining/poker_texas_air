//! Texas Poker 手牌评估（7 选 5 最佳手牌）。
//!
//! # 电路友好设计
//!
//! - [`HandRank`] 用定长 `kickers: [u8; 5]`（非 Vec），电路里是固定 5 字节。
//! - 直接实现 `Ord`（category 优先，kickers 字典序），删除 Move 风格的
//!   `compare`/`compare_kickers` 三态转换。
//! - `evaluate_best` 统一处理 5..=7 张牌（C(n,5) 组合枚举），<5 张用 0 填充。
//!   删除占位牌补齐路径（避免重复牌污染评估）。

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use super::card::Card;

// ===== 牌型常量 =====

pub const HIGH_CARD: u8 = 0;
pub const ONE_PAIR: u8 = 1;
pub const TWO_PAIR: u8 = 2;
pub const THREE_OF_A_KIND: u8 = 3;
pub const STRAIGHT: u8 = 4;
pub const FLUSH: u8 = 5;
pub const FULL_HOUSE: u8 = 6;
pub const FOUR_OF_A_KIND: u8 = 7;
pub const STRAIGHT_FLUSH: u8 = 8;
pub const ROYAL_FLUSH: u8 = 9;

/// 手牌评估结果。
///
/// - `category`: 牌型（0-9）
/// - `kickers`: tiebreaker 点数列表（定长 5，降序，不足位补 0）
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
pub struct HandRank {
    pub category: u8,
    pub kickers: [u8; 5],
}

impl HandRank {
    /// 构造新 HandRank，kickers 不足 5 位用 0 填充。
    #[must_use]
    pub fn new(category: u8, kickers: &[u8]) -> Self {
        let mut k = [0u8; 5];
        for (i, &val) in kickers.iter().take(5).enumerate() {
            k[i] = val;
        }
        Self {
            category,
            kickers: k,
        }
    }

    /// 牌型名称。
    #[must_use]
    pub fn category_name(&self) -> &'static str {
        match self.category {
            HIGH_CARD => "High Card",
            ONE_PAIR => "One Pair",
            TWO_PAIR => "Two Pair",
            THREE_OF_A_KIND => "Three of a Kind",
            STRAIGHT => "Straight",
            FLUSH => "Flush",
            FULL_HOUSE => "Full House",
            FOUR_OF_A_KIND => "Four of a Kind",
            STRAIGHT_FLUSH => "Straight Flush",
            ROYAL_FLUSH => "Royal Flush",
            _ => "Unknown",
        }
    }
}

impl std::fmt::Display for HandRank {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.category_name())
    }
}

/// 直接字典序比较：category 优先，其次 kickers 降序逐位比较。
///
/// kickers 已保证降序排列（由 evaluate_five 保证），故 `[u8;5]` 的自然 Ord
/// 恰好对应"降序逐位比较"，无需自定义 compare_kickers。
impl Ord for HandRank {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.category
            .cmp(&other.category)
            .then_with(|| self.kickers.cmp(&other.kickers))
    }
}

impl PartialOrd for HandRank {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// 从 n 张牌（5..=7）中选出最佳 5 张组合；<5 张时先 0 填充到 5 张再评估。
///
/// - 7 张：枚举 C(7,5)=21 种组合。
/// - 5/6 张：枚举 C(n,5) 组合。
/// - <5 张：用点数 0 填充（0 < 任何合法点数 2..14，不影响牌型判定）。
#[must_use]
pub fn evaluate_best(cards: &[Card]) -> HandRank {
    if cards.len() < 5 {
        // 不足 5 张：用 rank=0（不计入 counts）、花色递增的占位牌填充到 5 张。
        // rank=0 保证不构成对子/顺子；花色递增保证不构成同花。
        let mut padded = cards.to_vec();
        let mut next_suit = 0u8;
        while padded.len() < 5 {
            padded.push(Card::new(next_suit, 0));
            next_suit = next_suit.wrapping_add(1);
        }
        return evaluate_five(&[padded[0], padded[1], padded[2], padded[3], padded[4]]);
    }
    let n = cards.len();
    let mut best = HandRank::new(HIGH_CARD, &[0; 5]);
    // 枚举所有 C(n,5) 组合。n==7 时为 21 组（电路里硬编码展开）。
    for i in 0..n {
        for j in (i + 1)..n {
            for k in (j + 1)..n {
                for l in (k + 1)..n {
                    for m in (l + 1)..n {
                        let five = [cards[i], cards[j], cards[k], cards[l], cards[m]];
                        let rank = evaluate_five(&five);
                        if rank > best {
                            best = rank;
                        }
                    }
                }
            }
        }
    }
    best
}

/// 校验无重复牌（调试用）。
fn assert_no_duplicates(cards: &[Card]) {
    use std::collections::HashSet;
    let set: HashSet<_> = cards.iter().map(|card| card.to_index()).collect();
    debug_assert_eq!(set.len(), cards.len(), "牌组中存在重复牌");
}

/// 评估 5 张牌（核心算法）。
fn evaluate_five(cards: &[Card; 5]) -> HandRank {
    let c0 = cards[0];
    let c1 = cards[1];
    let c2 = cards[2];
    let c3 = cards[3];
    let c4 = cards[4];
    let all = [c0, c1, c2, c3, c4];

    // 1. counts[13]（索引 0=点数2, 12=点数14）
    let mut counts = [0u8; 13];
    for c in &all {
        if c.rank() >= 2 && c.rank() <= 14 {
            counts[(c.rank() - 2) as usize] += 1;
        }
    }

    // 2. 同花检测
    let is_flush = c0.suit() == c1.suit()
        && c1.suit() == c2.suit()
        && c2.suit() == c3.suit()
        && c3.suit() == c4.suit();

    // 3. 点数降序排序
    let mut ranks = [c0.rank(), c1.rank(), c2.rank(), c3.rank(), c4.rank()];
    ranks.sort_unstable_by(|a, b| b.cmp(a));

    // 4. 顺子检测（返回顺子最高点数）
    let straight = straight_high(&ranks);

    // 5. 相同点数组（按 count 降序、rank 降序）。
    // 末尾用 (0,0) 填充到至少 5 个元素，保证后续 groups[1..4] 访问安全
    //（0 值的 count=0，不会匹配任何牌型条件，仅占位）。
    let mut groups: Vec<(u8, u8)> = (0..13u8)
        .map(|i| (counts[i as usize], i + 2))
        .filter(|(c, _)| *c > 0)
        .collect();
    groups.sort_unstable_by(|a, b| b.cmp(a));
    while groups.len() < 5 {
        groups.push((0, 0));
    }

    // 6. 优先级判断（从高到低）

    // 同花顺 / 皇家同花顺
    if is_flush {
        if let Some(high) = straight {
            if high == 14 {
                return HandRank::new(ROYAL_FLUSH, &[14]);
            }
            return HandRank::new(STRAIGHT_FLUSH, &[high]);
        }
    }

    // 四条
    if groups[0].0 == 4 {
        return HandRank::new(FOUR_OF_A_KIND, &[groups[0].1, groups[1].1]);
    }

    // 葫芦
    if groups[0].0 == 3 && groups[1].0 >= 2 {
        return HandRank::new(FULL_HOUSE, &[groups[0].1, groups[1].1]);
    }

    // 同花
    if is_flush {
        return HandRank::new(FLUSH, &ranks);
    }

    // 顺子
    if let Some(high) = straight {
        return HandRank::new(STRAIGHT, &[high]);
    }

    // 三条
    if groups[0].0 == 3 {
        // groups[1..] 已按 (count,rank) 降序，rank 天然降序，直接取前 2
        let k = [groups[0].1, groups[1].1, groups[2].1];
        return HandRank::new(THREE_OF_A_KIND, &k);
    }

    // 两对
    if groups[0].0 == 2 && groups[1].0 == 2 {
        let (hi, lo) = if groups[0].1 > groups[1].1 {
            (groups[0].1, groups[1].1)
        } else {
            (groups[1].1, groups[0].1)
        };
        return HandRank::new(TWO_PAIR, &[hi, lo, groups[2].1]);
    }

    // 一对
    if groups[0].0 == 2 {
        // groups[1..] rank 已降序，取前 3 作为 kicker
        let k = [groups[0].1, groups[1].1, groups[2].1, groups[3].1];
        return HandRank::new(ONE_PAIR, &k);
    }

    // 高牌
    HandRank::new(HIGH_CARD, &ranks)
}

/// 检测顺子，返回最高点数（A-2-3-4-5 wheel 返回 5）。非顺子返回 None。
fn straight_high(ranks_desc: &[u8; 5]) -> Option<u8> {
    // wheel: A-2-3-4-5（排序后 [14,5,4,3,2]）
    if *ranks_desc == [14, 5, 4, 3, 2] {
        return Some(5);
    }
    // 普通顺子：5 张连续递减
    let consecutive = (0..4).all(|i| ranks_desc[i] == ranks_desc[i + 1] + 1);
    if consecutive {
        Some(ranks_desc[0])
    } else {
        None
    }
}

/// 从多个玩家中找出赢家（返回 seat_index 列表，平局多人）。
#[must_use]
pub fn find_winners(hands: &[(u8, Vec<Card>)]) -> Vec<u8> {
    assert!(!hands.is_empty(), "find_winners 要求至少 1 个玩家");
    let mut best_rank = HandRank::new(HIGH_CARD, &[0; 5]);
    let mut best_seats: Vec<u8> = Vec::new();

    for (seat, cards) in hands {
        let rank = evaluate_best(cards);
        match rank.cmp(&best_rank) {
            std::cmp::Ordering::Greater => {
                best_rank = rank;
                best_seats.clear();
                best_seats.push(*seat);
            }
            std::cmp::Ordering::Equal => {
                best_seats.push(*seat);
            }
            std::cmp::Ordering::Less => {}
        }
    }
    best_seats
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::contracts::texas_poker::card::*;

    fn card(suit: u8, rank: u8) -> Card {
        Card::new(suit, rank)
    }

    fn make_seven(cards: [Card; 7]) -> Vec<Card> {
        cards.to_vec()
    }

    #[test]
    fn test_royal_flush() {
        let seven = make_seven([
            card(SPADES, ACE),
            card(SPADES, KING),
            card(SPADES, QUEEN),
            card(SPADES, JACK),
            card(SPADES, TEN),
            card(HEARTS, TWO),
            card(CLUBS, THREE),
        ]);
        let rank = evaluate_best(&seven);
        assert_eq!(rank.category, ROYAL_FLUSH);
        assert_eq!(rank.kickers, [14, 0, 0, 0, 0]);
    }

    #[test]
    fn test_straight_flush_wheel() {
        let seven = make_seven([
            card(SPADES, ACE),
            card(SPADES, TWO),
            card(SPADES, THREE),
            card(SPADES, FOUR),
            card(SPADES, FIVE),
            card(HEARTS, KING),
            card(CLUBS, QUEEN),
        ]);
        let rank = evaluate_best(&seven);
        assert_eq!(rank.category, STRAIGHT_FLUSH);
        assert_eq!(rank.kickers, [5, 0, 0, 0, 0]);
    }

    #[test]
    fn test_four_of_a_kind() {
        let seven = make_seven([
            card(SPADES, KING),
            card(HEARTS, KING),
            card(DIAMONDS, KING),
            card(CLUBS, KING),
            card(SPADES, TWO),
            card(HEARTS, THREE),
            card(CLUBS, FOUR),
        ]);
        let rank = evaluate_best(&seven);
        assert_eq!(rank.category, FOUR_OF_A_KIND);
        assert_eq!(rank.kickers, [13, 4, 0, 0, 0]);
    }

    #[test]
    fn test_full_house() {
        let seven = make_seven([
            card(SPADES, QUEEN),
            card(HEARTS, QUEEN),
            card(DIAMONDS, QUEEN),
            card(CLUBS, JACK),
            card(SPADES, JACK),
            card(HEARTS, TWO),
            card(CLUBS, THREE),
        ]);
        let rank = evaluate_best(&seven);
        assert_eq!(rank.category, FULL_HOUSE);
        assert_eq!(rank.kickers, [12, 11, 0, 0, 0]);
    }

    #[test]
    fn test_flush() {
        let seven = make_seven([
            card(SPADES, ACE),
            card(SPADES, KING),
            card(SPADES, JACK),
            card(SPADES, NINE),
            card(SPADES, SEVEN),
            card(HEARTS, TWO),
            card(CLUBS, THREE),
        ]);
        let rank = evaluate_best(&seven);
        assert_eq!(rank.category, FLUSH);
    }

    #[test]
    fn test_straight() {
        let seven = make_seven([
            card(SPADES, TEN),
            card(HEARTS, NINE),
            card(DIAMONDS, EIGHT),
            card(CLUBS, SEVEN),
            card(SPADES, SIX),
            card(HEARTS, TWO),
            card(CLUBS, THREE),
        ]);
        let rank = evaluate_best(&seven);
        assert_eq!(rank.category, STRAIGHT);
        assert_eq!(rank.kickers, [10, 0, 0, 0, 0]);
    }

    #[test]
    fn test_straight_wheel() {
        let seven = make_seven([
            card(SPADES, ACE),
            card(HEARTS, TWO),
            card(DIAMONDS, THREE),
            card(CLUBS, FOUR),
            card(SPADES, FIVE),
            card(HEARTS, KING),
            card(CLUBS, QUEEN),
        ]);
        let rank = evaluate_best(&seven);
        assert_eq!(rank.category, STRAIGHT);
        assert_eq!(rank.kickers, [5, 0, 0, 0, 0]);
    }

    #[test]
    fn test_three_of_a_kind() {
        let seven = make_seven([
            card(SPADES, SEVEN),
            card(HEARTS, SEVEN),
            card(DIAMONDS, SEVEN),
            card(CLUBS, KING),
            card(SPADES, QUEEN),
            card(HEARTS, TWO),
            card(CLUBS, THREE),
        ]);
        let rank = evaluate_best(&seven);
        assert_eq!(rank.category, THREE_OF_A_KIND);
        assert_eq!(rank.kickers, [7, 13, 12, 0, 0]);
    }

    #[test]
    fn test_two_pair() {
        let seven = make_seven([
            card(SPADES, JACK),
            card(HEARTS, JACK),
            card(DIAMONDS, FOUR),
            card(CLUBS, FOUR),
            card(SPADES, ACE),
            card(HEARTS, TWO),
            card(CLUBS, THREE),
        ]);
        let rank = evaluate_best(&seven);
        assert_eq!(rank.category, TWO_PAIR);
        assert_eq!(rank.kickers, [11, 4, 14, 0, 0]);
    }

    #[test]
    fn test_one_pair() {
        let seven = make_seven([
            card(SPADES, ACE),
            card(HEARTS, ACE),
            card(DIAMONDS, KING),
            card(CLUBS, QUEEN),
            card(SPADES, JACK),
            card(HEARTS, TWO),
            card(CLUBS, THREE),
        ]);
        let rank = evaluate_best(&seven);
        assert_eq!(rank.category, ONE_PAIR);
        assert_eq!(rank.kickers, [14, 13, 12, 11, 0]);
    }

    #[test]
    fn test_high_card() {
        let seven = make_seven([
            card(SPADES, ACE),
            card(HEARTS, KING),
            card(DIAMONDS, JACK),
            card(CLUBS, NINE),
            card(SPADES, FIVE),
            card(HEARTS, THREE),
            card(CLUBS, TWO),
        ]);
        let rank = evaluate_best(&seven);
        assert_eq!(rank.category, HIGH_CARD);
    }

    #[test]
    fn test_compare() {
        let pair = HandRank::new(ONE_PAIR, &[14, 13, 12, 11]);
        let two_pair = HandRank::new(TWO_PAIR, &[11, 4, 14]);

        assert!(two_pair > pair);
        assert!(pair < two_pair);
        assert_eq!(pair, HandRank::new(ONE_PAIR, &[14, 13, 12, 11]));

        // 同 category 比较 kickers
        let pair_high = HandRank::new(ONE_PAIR, &[14, 13, 12, 11]);
        let pair_low = HandRank::new(ONE_PAIR, &[13, 12, 11, 10]);
        assert!(pair_high > pair_low);
    }

    #[test]
    fn test_find_winners_single() {
        let p1 = (
            0u8,
            make_seven([
                card(SPADES, ACE),
                card(SPADES, KING),
                card(SPADES, QUEEN),
                card(SPADES, JACK),
                card(SPADES, TEN),
                card(HEARTS, TWO),
                card(CLUBS, THREE),
            ]),
        );
        let p2 = (
            1u8,
            make_seven([
                card(HEARTS, TWO),
                card(HEARTS, THREE),
                card(HEARTS, FOUR),
                card(HEARTS, FIVE),
                card(HEARTS, SIX),
                card(CLUBS, KING),
                card(SPADES, QUEEN),
            ]),
        );
        let winners = find_winners(&[p1, p2]);
        assert_eq!(winners, vec![0]);
    }

    #[test]
    fn test_find_winners_tie() {
        let p1 = (
            0u8,
            make_seven([
                card(SPADES, ACE),
                card(HEARTS, ACE),
                card(DIAMONDS, KING),
                card(CLUBS, KING),
                card(SPADES, QUEEN),
                card(HEARTS, TWO),
                card(CLUBS, THREE),
            ]),
        );
        let p2 = (
            1u8,
            make_seven([
                card(DIAMONDS, ACE),
                card(CLUBS, ACE),
                card(SPADES, KING),
                card(HEARTS, KING),
                card(DIAMONDS, QUEEN),
                card(CLUBS, TWO),
                card(SPADES, THREE),
            ]),
        );
        let winners = find_winners(&[p1, p2]);
        assert_eq!(winners.len(), 2);
        assert!(winners.contains(&0));
        assert!(winners.contains(&1));
    }

    #[test]
    fn test_evaluate_best_partial_fewer_cards() {
        // 2 张牌：HIGH_CARD
        let two = vec![card(SPADES, ACE), card(HEARTS, KING)];
        let rank = evaluate_best(&two);
        assert_eq!(rank.category, HIGH_CARD);
        assert_eq!(rank.kickers[0], 14);

        // 0 张牌：HIGH_CARD，kickers 全 0
        let none: Vec<Card> = vec![];
        let rank = evaluate_best(&none);
        assert_eq!(rank.category, HIGH_CARD);
    }
}
