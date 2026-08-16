//! Texas Poker 模块单元测试 — 覆盖核心游戏逻辑。

use poker_l1::Address;
use poker_l1::signature::TaggedPubkey;
use poker_l1::vm::contracts::texas_poker::{
    betting::{BettingError, BettingRound},
    card::{
        ACE, CLUBS, Card, DIAMONDS, EIGHT, FIVE, FOUR, HEARTS, JACK, KING, NINE, PlayingCard,
        QUEEN, SEVEN, SIX, SPADES, TEN, THREE, TWO,
    },
    constants::{
        ACTION_CALL, ACTION_CHECK, ACTION_FOLD, ACTION_RAISE, ANTE_MODE_BBA, ANTE_MODE_NONE,
        ANTE_MODE_NORMAL, MAX_PLAYERS, MAX_TOTAL_BET, MIN_PLAYERS_TO_START, RAKE_MODE_NONE,
        RAKE_MODE_PERCENTAGE, ROUND_FLOP, ROUND_PREFLOP, ROUND_RIVER, ROUND_SHOWDOWN, ROUND_TURN,
        ROUND_WAITING, SHUFFLE_PHASE_NONE,
    },
    hand_evaluator::{
        FLUSH, FOUR_OF_A_KIND, FULL_HOUSE, HIGH_CARD, HandRank, ONE_PAIR, ROYAL_FLUSH, STRAIGHT,
        STRAIGHT_FLUSH, THREE_OF_A_KIND, TWO_PAIR, evaluate_best, find_winners,
    },
    side_pot::{SidePot, SidePotError, calculate_side_pots},
    types::{
        ReconstructState, RevealPurpose, RevealTokenState, Seat, SeatStatus, ShuffleState,
        seat_mask_remove,
    },
};

// ===========================================================================
// 1. card.rs — 扑克牌类型与操作
// ===========================================================================

#[test]
fn test_card_from_index_standard_range() {
    for i in 0..52 {
        let card = Card::from_index(i);
        assert_eq!(card.to_index(), i, "Card::from_index({i}) roundtrip failed");
    }
}

#[test]
fn test_card_from_index_boundary_zero() {
    let card = Card::from_index(0);
    assert_eq!(card.suit(), SPADES);
    assert_eq!(card.rank(), TWO);
    assert_eq!(card.to_index(), 0);
}

#[test]
fn test_card_from_index_boundary_max() {
    let card = Card::from_index(51);
    assert_eq!(card.suit(), CLUBS);
    assert_eq!(card.rank(), ACE);
    assert_eq!(card.to_index(), 51);
}

#[test]
fn test_card_is_valid() {
    assert!(Card::new(SPADES, ACE).is_valid());
    assert!(Card::new(CLUBS, TWO).is_valid());
    assert!(!Card::new(4, ACE).is_valid()); // 非法花色
    assert!(!Card::new(SPADES, 1).is_valid()); // 非法点数
    assert!(!Card::new(SPADES, 15).is_valid()); // 非法点数
}

#[test]
fn test_card_display_format() {
    assert_eq!(Card::new(SPADES, TWO).display(), "2♠");
    assert_eq!(Card::new(SPADES, ACE).display(), "A♠");
    assert_eq!(Card::new(DIAMONDS, TWO).display(), "2♦");
    assert_eq!(Card::new(HEARTS, ACE).display(), "A♥");
    assert_eq!(Card::new(CLUBS, TWO).display(), "2♣");
}

#[test]
fn test_card_borsh_roundtrip() {
    for i in 0..52 {
        let card = Card::from_index(i);
        let bytes = borsh::to_vec(&card).unwrap();
        let decoded = borsh::from_slice(&bytes).unwrap();
        assert_eq!(card, decoded);
    }
}

#[test]
fn test_playing_card_to_card_mapping() {
    // PlayingCard Club(0) → Card CLUBS(3)
    assert_eq!(PlayingCard::new(ACE, 0).to_card(), Card::new(CLUBS, ACE));
    // PlayingCard Diamond(1) → Card DIAMONDS(2)
    assert_eq!(PlayingCard::new(ACE, 1).to_card(), Card::new(DIAMONDS, ACE));
    // PlayingCard Heart(2) → Card HEARTS(1)
    assert_eq!(PlayingCard::new(ACE, 2).to_card(), Card::new(HEARTS, ACE));
    // PlayingCard Spade(3) → Card SPADES(0)
    assert_eq!(PlayingCard::new(ACE, 3).to_card(), Card::new(SPADES, ACE));
}

#[test]
fn test_playing_card_borsh_roundtrip() {
    let pc = PlayingCard::new(ACE, SPADES);
    let bytes = borsh::to_vec(&pc).unwrap();
    let decoded = borsh::from_slice(&bytes).unwrap();
    assert_eq!(pc, decoded);
}

// ===== card.rs 补充边缘场景 =====

#[test]
fn test_card_suit_name_invalid_suit() {
    let card = Card::new(4, ACE);
    assert_eq!(card.suit_name(), "?");
}

#[test]
fn test_card_rank_name_invalid_rank() {
    let card = Card::new(SPADES, 1);
    assert_eq!(card.rank_name(), "?");
    let card = Card::new(SPADES, 15);
    assert_eq!(card.rank_name(), "?");
}

#[test]
fn test_card_display_invalid_card() {
    let card = Card::new(4, 1);
    assert_eq!(card.display(), "??");
}

#[test]
fn test_card_all_suit_names() {
    assert_eq!(Card::new(SPADES, ACE).suit_name(), "♠");
    assert_eq!(Card::new(HEARTS, ACE).suit_name(), "♥");
    assert_eq!(Card::new(DIAMONDS, ACE).suit_name(), "♦");
    assert_eq!(Card::new(CLUBS, ACE).suit_name(), "♣");
}

#[test]
fn test_card_all_rank_names() {
    let ranks = [
        (TWO, "2"),
        (THREE, "3"),
        (FOUR, "4"),
        (FIVE, "5"),
        (SIX, "6"),
        (SEVEN, "7"),
        (EIGHT, "8"),
        (NINE, "9"),
        (TEN, "10"),
        (JACK, "J"),
        (QUEEN, "Q"),
        (KING, "K"),
        (ACE, "A"),
    ];
    for (rank, expected) in ranks {
        assert_eq!(Card::new(SPADES, rank).rank_name(), expected);
    }
}

#[test]
fn test_playing_card_invalid_suit_defaults_to_clubs() {
    // PlayingCard 非法 suit 时 to_card 默认返回 CLUBS
    let pc = PlayingCard::new(ACE, 4);
    let card = pc.to_card();
    assert_eq!(card.suit(), CLUBS);
    assert_eq!(card.rank(), ACE);
}

#[test]
fn test_card_display_trait() {
    let card = Card::new(SPADES, ACE);
    assert_eq!(format!("{}", card), "A♠");
}

#[test]
fn test_card_new_const() {
    let card = Card::new(SPADES, ACE);
    assert_eq!(card.suit(), SPADES);
    assert_eq!(card.rank(), ACE);
}

#[test]
fn test_playing_card_new_const() {
    let pc = PlayingCard::new(ACE, 0);
    assert_eq!(pc.rank, ACE);
    assert_eq!(pc.suit, 0);
}

// ===========================================================================
// 2. constants.rs — 常量与位掩码
// ===========================================================================

#[test]
fn test_constants_player_limits() {
    assert!(MIN_PLAYERS_TO_START >= 2);
    assert!(MAX_PLAYERS >= MIN_PLAYERS_TO_START);
}

#[test]
fn test_constants_action_masks_unique() {
    assert!((ACTION_FOLD & ACTION_CHECK) == 0);
    assert!((ACTION_FOLD & ACTION_CALL) == 0);
    assert!((ACTION_FOLD & ACTION_RAISE) == 0);
    assert!((ACTION_CHECK & ACTION_CALL) == 0);
    assert!((ACTION_CHECK & ACTION_RAISE) == 0);
    assert!((ACTION_CALL & ACTION_RAISE) == 0);
}

#[test]
fn test_constants_round_state_order() {
    assert!(ROUND_WAITING < ROUND_PREFLOP);
    assert!(ROUND_PREFLOP < ROUND_FLOP);
    assert!(ROUND_FLOP < ROUND_TURN);
    assert!(ROUND_TURN < ROUND_RIVER);
    assert!(ROUND_RIVER < ROUND_SHOWDOWN);
}

// ===========================================================================
// 3. types.rs — 核心类型
// ===========================================================================

#[test]
fn test_seat_status_default() {
    let status = SeatStatus::default();
    assert_eq!(status, SeatStatus::Empty);
}

// ===========================================================================
// 4. betting.rs — 下注轮状态与规则
// ===========================================================================

#[test]
fn test_betting_round_new_preflop() {
    let round = BettingRound::new(10, 10); // big_blind=10, current_bet=10
    assert_eq!(round.current_bet, 10);
    assert_eq!(round.min_raise, 10);
}

#[test]
fn test_betting_round_new_postflop() {
    let round = BettingRound::new(10, 0); // big_blind=10, current_bet=0
    assert_eq!(round.current_bet, 0);
    assert_eq!(round.min_raise, 10);
}

#[test]
fn test_betting_round_chips_to_call() {
    let round = BettingRound::new(10, 10);
    assert_eq!(round.chips_to_call(0), 10);
    assert_eq!(round.chips_to_call(5), 5);
    assert_eq!(round.chips_to_call(10), 0);
    assert_eq!(round.chips_to_call(20), 0);
}

#[test]
fn test_betting_round_can_check() {
    let round = BettingRound::new(10, 10);
    assert!(!round.can_check(0));
    assert!(round.can_check(10));
}

#[test]
fn test_betting_round_can_call() {
    let round = BettingRound::new(10, 10);
    assert!(round.can_call(0, 100)); // 需要跟注且有筹码
    assert!(!round.can_call(10, 100)); // 无需跟注
    assert!(!round.can_call(0, 0)); // 无筹码
}

#[test]
fn test_betting_round_can_raise() {
    let round = BettingRound::new(10, 10);
    assert!(round.can_raise(0, 100)); // stack > chips_to_call
    assert!(round.can_raise(0, 11)); // 刚好能加注
    assert!(!round.can_raise(0, 10)); // 只能 all-in call
    assert!(!round.can_raise(10, 0)); // 无筹码
}

#[test]
fn test_betting_round_available_actions() {
    let round = BettingRound::new(10, 10);

    // 需要跟注，有足够筹码
    let actions = round.available_actions(0, 100);
    assert!(actions & ACTION_FOLD != 0);
    assert!(actions & ACTION_CALL != 0);
    assert!(actions & ACTION_RAISE != 0);
    assert!(actions & ACTION_CHECK == 0);

    // 已跟注，有筹码
    let actions = round.available_actions(10, 100);
    assert!(actions & ACTION_FOLD != 0);
    assert!(actions & ACTION_CHECK != 0);
    assert!(actions & ACTION_RAISE != 0);
    assert!(actions & ACTION_CALL == 0);

    // 需要跟注，但筹码不够加注
    let actions = round.available_actions(0, 10);
    assert!(actions & ACTION_FOLD != 0);
    assert!(actions & ACTION_CALL != 0);
    assert!(actions & ACTION_RAISE == 0);
    assert!(actions & ACTION_CHECK == 0);
}

#[test]
fn test_betting_round_process_call() {
    let round = BettingRound::new(10, 10);
    assert_eq!(round.process_call(0, 100), 10); // 正常跟注
    assert_eq!(round.process_call(0, 5), 5); // all-in 跟注
    assert_eq!(round.process_call(10, 100), 0); // 无需跟注
}

#[test]
fn test_betting_round_process_raise_normal() {
    let mut round = BettingRound::new(10, 10);
    let needed = round.process_raise(30, 0, 100).unwrap();
    assert_eq!(needed, 30);
    assert_eq!(round.current_bet, 30);
    assert_eq!(round.min_raise, 20); // 30-10=20
}

#[test]
fn test_betting_round_process_raise_all_in() {
    let mut round = BettingRound::new(10, 10);
    let needed = round.process_raise(30, 0, 30).unwrap();
    assert_eq!(needed, 30);
    assert_eq!(round.min_raise, 20);
}

#[test]
fn test_betting_round_process_raise_short_all_in() {
    let mut round = BettingRound::new(10, 10);
    round.process_raise(30, 0, 100).unwrap(); // min_raise = 20
    // 短 all-in：raise_amount=10 < min_raise=20
    let needed = round.process_raise(40, 0, 40).unwrap();
    assert_eq!(needed, 40);
    assert_eq!(round.min_raise, 20); // 不更新
    assert_eq!(round.current_bet, 40);
}

#[test]
fn test_betting_round_process_raise_below_min_rejected() {
    let mut round = BettingRound::new(10, 10);
    assert!(matches!(
        round.process_raise(15, 0, 100),
        Err(BettingError::InvalidRaiseAmount)
    ));
}

#[test]
fn test_betting_round_process_raise_below_current_bet_rejected() {
    let mut round = BettingRound::new(10, 10);
    assert!(matches!(
        round.process_raise(5, 0, 100),
        Err(BettingError::InvalidRaiseAmount)
    ));
}

#[test]
fn test_betting_round_process_raise_insufficient_stack() {
    let mut round = BettingRound::new(10, 10);
    assert!(matches!(
        round.process_raise(100, 0, 50),
        Err(BettingError::CannotRaise)
    ));
}

#[test]
fn test_betting_round_borsh_roundtrip() {
    let round = BettingRound::new(10, 10);
    let bytes = borsh::to_vec(&round).unwrap();
    let decoded = borsh::from_slice(&bytes).unwrap();
    assert_eq!(round, decoded);
}

// ===== betting.rs 补充边缘场景 =====

#[test]
fn test_betting_round_can_raise_exact_minimum() {
    let round = BettingRound::new(10, 10);
    // stack = chips_to_call + 1 = 11, 刚好可以 raise min_raise=10
    assert!(round.can_raise(0, 11));
    // stack = chips_to_call = 10, 只能 all-in call
    assert!(!round.can_raise(0, 10));
}

#[test]
fn test_betting_round_process_raise_equal_to_current_rejected() {
    let mut round = BettingRound::new(10, 10);
    // total_bet == current_bet 应被拒绝
    assert!(matches!(
        round.process_raise(10, 0, 100),
        Err(BettingError::InvalidRaiseAmount)
    ));
}

#[test]
fn test_betting_round_process_raise_equal_to_seat_bet_rejected() {
    let mut round = BettingRound::new(10, 10);
    // total_bet == seat_bet 应被拒绝
    assert!(matches!(
        round.process_raise(5, 5, 100),
        Err(BettingError::InvalidRaiseAmount)
    ));
}

#[test]
fn test_betting_round_process_call_zero_stack() {
    let round = BettingRound::new(10, 10);
    assert_eq!(round.process_call(0, 0), 0);
}

#[test]
fn test_betting_round_chips_to_call_seat_bet_exceeds_current() {
    let round = BettingRound::new(10, 10);
    // seat_bet > current_bet 时 saturating_sub 返回 0
    assert_eq!(round.chips_to_call(20), 0);
}

#[test]
fn test_betting_round_available_actions_all_in_player() {
    let round = BettingRound::new(10, 10);
    // all-in 玩家（stack=0）：只能 fold
    let actions = round.available_actions(0, 0);
    assert!(actions & ACTION_FOLD != 0);
    assert!(actions & ACTION_CALL == 0);
    assert!(actions & ACTION_RAISE == 0);
    assert!(actions & ACTION_CHECK == 0);
}

#[test]
fn test_betting_round_available_actions_already_all_in_equal_bet() {
    let round = BettingRound::new(10, 10);
    // 已 all-in 且 bet == current_bet：可以 check（因为 chips_to_call == 0）
    // 但在实际游戏中 all-in 玩家不应再有行动权
    let actions = round.available_actions(10, 0);
    assert!(actions & ACTION_FOLD != 0);
    // 注意：can_check 只看 chips_to_call，不看 stack，所以 all-in 且已跟注时可以 check
    assert!(actions & ACTION_CHECK != 0);
    assert!(actions & ACTION_CALL == 0);
    assert!(actions & ACTION_RAISE == 0);
}

#[test]
fn test_betting_round_min_raise_after_multiple_raises() {
    let mut round = BettingRound::new(10, 10);
    // 第一次加注：10 → 30，min_raise=20
    round.process_raise(30, 0, 1000).unwrap();
    assert_eq!(round.min_raise, 20);
    // 第二次加注：30 → 70，min_raise=40
    round.process_raise(70, 0, 1000).unwrap();
    assert_eq!(round.min_raise, 40);
    assert_eq!(round.current_bet, 70);
}

#[test]
fn test_betting_round_short_all_in_does_not_increase_min_raise() {
    let mut round = BettingRound::new(10, 10);
    // 正常加注到 30，min_raise=20
    round.process_raise(30, 0, 1000).unwrap();
    assert_eq!(round.min_raise, 20);
    // 短 all-in 到 45（raise=15 < min_raise=20）
    round.process_raise(45, 0, 45).unwrap();
    // min_raise 保持 20 不变
    assert_eq!(round.min_raise, 20);
    assert_eq!(round.current_bet, 45);
}

#[test]
fn test_betting_round_can_call_zero_chips_needed_zero_stack() {
    let round = BettingRound::new(10, 10);
    // 不需要跟注且没筹码 → 不能 call
    assert!(!round.can_call(10, 0));
}

#[test]
fn test_betting_error_display() {
    assert_eq!(
        format!("{}", BettingError::InvalidRaiseAmount),
        "invalid raise amount"
    );
    assert_eq!(
        format!("{}", BettingError::CannotRaise),
        "cannot raise: insufficient stack"
    );
    assert_eq!(
        format!("{}", BettingError::NotPlayerTurn),
        "not player's turn"
    );
    assert_eq!(
        format!("{}", BettingError::PlayerInactive),
        "player folded or all-in"
    );
}

// ===========================================================================
// 5. hand_evaluator.rs — 手牌评估
// ===========================================================================

fn make_cards(ints: &[u8]) -> Vec<Card> {
    ints.iter().map(|&i| Card::from_index(i)).collect()
}

#[test]
fn test_hand_rank_category_name() {
    let hr = HandRank::new(HIGH_CARD, &[]);
    assert_eq!(hr.category_name(), "High Card");
    let hr = HandRank::new(ONE_PAIR, &[]);
    assert_eq!(hr.category_name(), "One Pair");
    let hr = HandRank::new(TWO_PAIR, &[]);
    assert_eq!(hr.category_name(), "Two Pair");
    let hr = HandRank::new(THREE_OF_A_KIND, &[]);
    assert_eq!(hr.category_name(), "Three of a Kind");
    let hr = HandRank::new(STRAIGHT, &[]);
    assert_eq!(hr.category_name(), "Straight");
    let hr = HandRank::new(FLUSH, &[]);
    assert_eq!(hr.category_name(), "Flush");
    let hr = HandRank::new(FULL_HOUSE, &[]);
    assert_eq!(hr.category_name(), "Full House");
    let hr = HandRank::new(FOUR_OF_A_KIND, &[]);
    assert_eq!(hr.category_name(), "Four of a Kind");
    let hr = HandRank::new(STRAIGHT_FLUSH, &[]);
    assert_eq!(hr.category_name(), "Straight Flush");
    let hr = HandRank::new(ROYAL_FLUSH, &[]);
    assert_eq!(hr.category_name(), "Royal Flush");
}

#[test]
fn test_hand_rank_display() {
    let hr = HandRank::new(ROYAL_FLUSH, &[]);
    assert_eq!(format!("{}", hr), "Royal Flush");
}

#[test]
fn test_hand_rank_ordering() {
    let high_card = HandRank::new(HIGH_CARD, &[ACE]);
    let one_pair = HandRank::new(ONE_PAIR, &[ACE]);
    let two_pair = HandRank::new(TWO_PAIR, &[ACE]);
    let three_of_a_kind = HandRank::new(THREE_OF_A_KIND, &[ACE]);
    let straight = HandRank::new(STRAIGHT, &[ACE]);
    let flush = HandRank::new(FLUSH, &[ACE]);
    let full_house = HandRank::new(FULL_HOUSE, &[ACE]);
    let four_of_a_kind = HandRank::new(FOUR_OF_A_KIND, &[ACE]);
    let straight_flush = HandRank::new(STRAIGHT_FLUSH, &[ACE]);
    let royal_flush = HandRank::new(ROYAL_FLUSH, &[]);

    assert!(high_card < one_pair);
    assert!(one_pair < two_pair);
    assert!(two_pair < three_of_a_kind);
    assert!(three_of_a_kind < straight);
    assert!(straight < flush);
    assert!(flush < full_house);
    assert!(full_house < four_of_a_kind);
    assert!(four_of_a_kind < straight_flush);
    assert!(straight_flush < royal_flush);
}

#[test]
fn test_find_winners_two_players_tie() {
    let player1 = make_cards(&[0, 1]); // 2♠ 3♠
    let player2 = make_cards(&[13, 14]); // 2♦ 3♦

    let winners = find_winners(&[(0, player1), (1, player2)]);
    assert_eq!(winners.len(), 2);
    assert!(winners.contains(&0));
    assert!(winners.contains(&1));
}

#[test]
fn test_find_winners_two_players_one_wins() {
    let player1 = make_cards(&[12, 25]); // A♠ A♥ (一对A)
    let player2 = make_cards(&[0, 13]); // 2♠ 2♦ (一对2)

    let winners = find_winners(&[(0, player1), (1, player2)]);
    assert_eq!(winners.len(), 1);
    assert!(winners.contains(&0));
}

#[test]
fn test_find_winners_three_players_one_winner() {
    let player1 = make_cards(&[0, 1]); // 2♠ 3♠
    let player2 = make_cards(&[12, 25]); // A♠ A♥ (一对A)
    let player3 = make_cards(&[2, 3]); // 4♠ 5♠

    let winners = find_winners(&[(0, player1), (1, player2), (2, player3)]);
    assert_eq!(winners.len(), 1);
    assert!(winners.contains(&1));
}

// ===== hand_evaluator.rs 补充边缘场景 =====

#[test]
fn test_hand_rank_category_name_unknown() {
    let hr = HandRank::new(100, &[]);
    assert_eq!(hr.category_name(), "Unknown");
}

#[test]
fn test_hand_rank_kickers_padding() {
    // kickers 不足 5 位应补 0
    let hr = HandRank::new(ONE_PAIR, &[14, 13]);
    assert_eq!(hr.kickers, [14, 13, 0, 0, 0]);

    // kickers 超过 5 位应截断
    let hr = HandRank::new(HIGH_CARD, &[14, 13, 12, 11, 10, 9]);
    assert_eq!(hr.kickers, [14, 13, 12, 11, 10]);
}

#[test]
fn test_hand_rank_eq_and_ord() {
    let a = HandRank::new(ONE_PAIR, &[14, 13, 12, 11]);
    let b = HandRank::new(ONE_PAIR, &[14, 13, 12, 11]);
    assert_eq!(a, b);
    assert!(a <= b);
    assert!(a >= b);

    let c = HandRank::new(ONE_PAIR, &[14, 13, 12, 10]);
    assert!(a > c);
    assert!(c < a);
}

#[test]
fn test_evaluate_best_five_cards() {
    // 5张同花色 → 同花
    let cards = make_cards(&[0, 1, 2, 3, 5]); // 2♠ 3♠ 4♠ 5♠ 7♠
    let rank = evaluate_best(&cards);
    assert_eq!(rank.category, FLUSH);
}

#[test]
fn test_evaluate_best_six_cards() {
    // 6张同花色 → 选5张最大的同花
    let cards = make_cards(&[0, 1, 2, 3, 5, 7]); // 都是 ♠
    let rank = evaluate_best(&cards);
    assert_eq!(rank.category, FLUSH);
}

#[test]
fn test_evaluate_best_zero_cards() {
    let cards: Vec<Card> = vec![];
    let rank = evaluate_best(&cards);
    assert_eq!(rank.category, HIGH_CARD);
    assert_eq!(rank.kickers, [0, 0, 0, 0, 0]);
}

#[test]
fn test_evaluate_best_one_card() {
    let cards = make_cards(&[12]); // A♠
    let rank = evaluate_best(&cards);
    assert_eq!(rank.category, HIGH_CARD);
    assert_eq!(rank.kickers[0], ACE);
}

#[test]
fn test_evaluate_best_four_cards() {
    // 4张不同花色的牌：补齐到5张，补齐牌 rank=0 且花色与现有不构成同花
    let cards = vec![
        Card::new(SPADES, ACE),
        Card::new(HEARTS, KING),
        Card::new(DIAMONDS, QUEEN),
        Card::new(CLUBS, JACK),
    ];
    let rank = evaluate_best(&cards);
    assert_eq!(rank.category, HIGH_CARD);
    assert_eq!(rank.kickers[0], ACE);
}

#[test]
fn test_straight_wheel_a2345() {
    // A-2-3-4-5 wheel 顺子，high=5
    let cards = vec![
        Card::new(SPADES, ACE),
        Card::new(HEARTS, TWO),
        Card::new(DIAMONDS, THREE),
        Card::new(CLUBS, FOUR),
        Card::new(SPADES, FIVE),
        Card::new(HEARTS, KING),
        Card::new(DIAMONDS, QUEEN),
    ];
    let rank = evaluate_best(&cards);
    assert_eq!(rank.category, STRAIGHT);
    assert_eq!(rank.kickers[0], 5);
}

#[test]
fn test_straight_flush_wheel() {
    // 同花顺 wheel: A-2-3-4-5 of same suit
    let cards = vec![
        Card::new(SPADES, ACE),
        Card::new(SPADES, TWO),
        Card::new(SPADES, THREE),
        Card::new(SPADES, FOUR),
        Card::new(SPADES, FIVE),
        Card::new(HEARTS, KING),
        Card::new(DIAMONDS, QUEEN),
    ];
    let rank = evaluate_best(&cards);
    assert_eq!(rank.category, STRAIGHT_FLUSH);
    assert_eq!(rank.kickers[0], 5);
}

#[test]
fn test_royal_flush_is_not_straight_flush() {
    // 皇家同花顺
    let cards = make_cards(&[
        8,  // 10♠
        9,  // J♠
        10, // Q♠
        11, // K♠
        12, // A♠
        0,  // 2♠
        13, // 2♥
    ]);
    let rank = evaluate_best(&cards);
    assert_eq!(rank.category, ROYAL_FLUSH);
    assert!(rank > HandRank::new(STRAIGHT_FLUSH, &[14]));
}

#[test]
fn test_full_house_three_pairs_pick_best() {
    // 有三个对子，选最大的两对
    let cards = vec![
        Card::new(SPADES, ACE),
        Card::new(HEARTS, ACE),
        Card::new(DIAMONDS, KING),
        Card::new(CLUBS, KING),
        Card::new(SPADES, QUEEN),
        Card::new(HEARTS, QUEEN),
        Card::new(DIAMONDS, JACK),
    ];
    let rank = evaluate_best(&cards);
    // 应该是两对（高对 A + 低对 K），不是葫芦
    assert_eq!(rank.category, TWO_PAIR);
    assert_eq!(rank.kickers[0], ACE);
    assert_eq!(rank.kickers[1], KING);
}

#[test]
fn test_four_of_a_kind_kicker() {
    // 四条带 kicker
    let cards = vec![
        Card::new(SPADES, KING),
        Card::new(HEARTS, KING),
        Card::new(DIAMONDS, KING),
        Card::new(CLUBS, KING),
        Card::new(SPADES, ACE),
        Card::new(HEARTS, TWO),
        Card::new(DIAMONDS, THREE),
    ];
    let rank = evaluate_best(&cards);
    assert_eq!(rank.category, FOUR_OF_A_KIND);
    assert_eq!(rank.kickers[0], KING);
    assert_eq!(rank.kickers[1], ACE); // kicker 是 A
}

#[test]
fn test_flush_beats_straight() {
    let flush = HandRank::new(FLUSH, &[ACE, KING, QUEEN, JACK, NINE]);
    let straight = HandRank::new(STRAIGHT, &[10]);
    assert!(flush > straight);
}

#[test]
fn test_find_winners_single_player() {
    let player1 = make_cards(&[12, 25]); // 一对A
    let winners = find_winners(&[(0, player1)]);
    assert_eq!(winners, vec![0]);
}

#[test]
fn test_find_winners_three_way_tie() {
    let p1 = make_cards(&[0, 13]); // 2♠ 2♦ (一对2)
    let p2 = make_cards(&[1, 14]); // 3♠ 3♦ (一对3)
    let p3 = make_cards(&[2, 15]); // 4♠ 4♦ (一对4)

    // 三个都是一对，p3 赢
    let winners = find_winners(&[(0, p1), (1, p2), (2, p3)]);
    assert_eq!(winners.len(), 1);
    assert_eq!(winners[0], 2);
}

#[test]
fn test_high_card_compare_kickers() {
    // 高牌比较，比较所有 5 张 kicker
    let a = HandRank::new(HIGH_CARD, &[ACE, KING, QUEEN, JACK, NINE]);
    let b = HandRank::new(HIGH_CARD, &[ACE, KING, QUEEN, JACK, TEN]);
    assert!(b > a);
}

#[test]
fn test_one_pair_kicker_comparison() {
    // 一对相同，比较 kicker
    let a = HandRank::new(ONE_PAIR, &[ACE, KING, QUEEN, JACK]);
    let b = HandRank::new(ONE_PAIR, &[ACE, KING, QUEEN, TEN]);
    assert!(a > b);
}

// ========== hand_evaluator.rs 补充边缘场景 ==========

#[test]
fn test_four_of_a_kind_beats_full_house() {
    // 四条 > 葫芦
    let four_cards = vec![
        Card::new(SPADES, ACE),
        Card::new(HEARTS, ACE),
        Card::new(DIAMONDS, ACE),
        Card::new(CLUBS, ACE),
        Card::new(SPADES, KING),
    ];
    let full_house_cards = vec![
        Card::new(SPADES, ACE),
        Card::new(HEARTS, ACE),
        Card::new(DIAMONDS, ACE),
        Card::new(CLUBS, KING),
        Card::new(SPADES, KING),
    ];
    let four_rank = evaluate_best(&four_cards);
    let full_house_rank = evaluate_best(&full_house_cards);
    assert_eq!(four_rank.category, FOUR_OF_A_KIND);
    assert_eq!(full_house_rank.category, FULL_HOUSE);
    assert!(four_rank > full_house_rank);
}

#[test]
fn test_four_of_a_kind_kicker_comparison() {
    // 四条相同，比较 kicker
    let a = vec![
        Card::new(SPADES, ACE),
        Card::new(HEARTS, ACE),
        Card::new(DIAMONDS, ACE),
        Card::new(CLUBS, ACE),
        Card::new(SPADES, KING), // kicker: K
    ];
    let b = vec![
        Card::new(SPADES, ACE),
        Card::new(HEARTS, ACE),
        Card::new(DIAMONDS, ACE),
        Card::new(CLUBS, ACE),
        Card::new(SPADES, QUEEN), // kicker: Q
    ];
    let rank_a = evaluate_best(&a);
    let rank_b = evaluate_best(&b);
    assert!(rank_a > rank_b);
}

#[test]
fn test_full_house_kicker_comparison() {
    // 葫芦相同，比较 kicker
    let a = vec![
        Card::new(SPADES, ACE),
        Card::new(HEARTS, ACE),
        Card::new(DIAMONDS, ACE),
        Card::new(CLUBS, KING),
        Card::new(SPADES, KING),
    ];
    let b = vec![
        Card::new(SPADES, ACE),
        Card::new(HEARTS, ACE),
        Card::new(DIAMONDS, ACE),
        Card::new(CLUBS, QUEEN),
        Card::new(SPADES, QUEEN),
    ];
    let rank_a = evaluate_best(&a);
    let rank_b = evaluate_best(&b);
    assert!(rank_a > rank_b);
}

#[test]
fn test_straight_high_card_comparison() {
    // 顺子比较高牌
    let high = vec![
        Card::new(SPADES, ACE),
        Card::new(HEARTS, KING),
        Card::new(DIAMONDS, QUEEN),
        Card::new(CLUBS, JACK),
        Card::new(SPADES, TEN),
    ];
    let low = vec![
        Card::new(SPADES, KING),
        Card::new(HEARTS, QUEEN),
        Card::new(DIAMONDS, JACK),
        Card::new(CLUBS, TEN),
        Card::new(SPADES, NINE),
    ];
    let rank_high = evaluate_best(&high);
    let rank_low = evaluate_best(&low);
    assert!(rank_high > rank_low);
}

#[test]
fn test_flush_high_card_comparison() {
    // 同花比较高牌（确保不会形成顺子）
    // A-K-Q-9-7 不是顺子（缺少J和10），K-Q-J-8-6 不是顺子（缺少10和9）
    let high = vec![
        Card::new(SPADES, ACE),   // 14
        Card::new(SPADES, KING),  // 13
        Card::new(SPADES, QUEEN), // 12
        Card::new(SPADES, NINE),  // 9
        Card::new(SPADES, SEVEN), // 7
    ];
    let low = vec![
        Card::new(SPADES, KING),  // 13
        Card::new(SPADES, QUEEN), // 12
        Card::new(SPADES, JACK),  // 11
        Card::new(SPADES, EIGHT), // 8
        Card::new(SPADES, SIX),   // 6
    ];
    let rank_high = evaluate_best(&high);
    let rank_low = evaluate_best(&low);
    assert_eq!(rank_high.category, FLUSH);
    assert_eq!(rank_low.category, FLUSH);
    // 高同花应该大于低同花
    assert!(rank_high > rank_low);
}

#[test]
fn test_three_of_a_kind_kicker_comparison() {
    // 三条比较 kicker
    let a = vec![
        Card::new(SPADES, ACE),
        Card::new(HEARTS, ACE),
        Card::new(DIAMONDS, ACE),
        Card::new(CLUBS, KING),
        Card::new(SPADES, QUEEN),
    ];
    let b = vec![
        Card::new(SPADES, ACE),
        Card::new(HEARTS, ACE),
        Card::new(DIAMONDS, ACE),
        Card::new(CLUBS, KING),
        Card::new(SPADES, JACK),
    ];
    let rank_a = evaluate_best(&a);
    let rank_b = evaluate_best(&b);
    assert!(rank_a > rank_b);
}

#[test]
fn test_evaluate_best_seven_cards_straight_flush() {
    // 7张牌中选出同花顺
    let cards = vec![
        Card::new(SPADES, ACE),
        Card::new(SPADES, KING),
        Card::new(SPADES, QUEEN),
        Card::new(SPADES, JACK),
        Card::new(SPADES, TEN),
        Card::new(HEARTS, TWO),
        Card::new(DIAMONDS, THREE),
    ];
    let rank = evaluate_best(&cards);
    assert_eq!(rank.category, ROYAL_FLUSH);
}

#[test]
fn test_evaluate_best_seven_cards_multiple_options() {
    // 7张牌同时有顺子和同花，但不是同花顺
    let cards = vec![
        Card::new(SPADES, ACE),
        Card::new(SPADES, KING),
        Card::new(SPADES, QUEEN),
        Card::new(SPADES, JACK),
        Card::new(SPADES, NINE), // 同花（缺10）
        Card::new(HEARTS, TEN),  // 顺子 A-K-Q-J-10
        Card::new(DIAMONDS, TWO),
    ];
    let rank = evaluate_best(&cards);
    // 同花 > 顺子，应该选同花
    assert_eq!(rank.category, FLUSH);
}

#[test]
fn test_find_winners_empty() {
    // 空玩家列表：find_winners 要求至少 1 个玩家
    // 实际使用中不会出现这种情况，但测试函数行为
    let result = std::panic::catch_unwind(|| find_winners(&[]));
    assert!(result.is_err());
}

#[test]
fn test_find_winners_two_way_tie() {
    // 两个玩家平局
    let p1 = make_cards(&[12, 25]); // 一对A
    let p2 = make_cards(&[12, 38]); // 一对A
    let winners = find_winners(&[(0, p1), (1, p2)]);
    assert_eq!(winners.len(), 2);
    assert!(winners.contains(&0));
    assert!(winners.contains(&1));
}

#[test]
fn test_find_winners_all_players_folded() {
    // 所有玩家都fold了（空牌组）
    let p1: Vec<Card> = vec![];
    let p2: Vec<Card> = vec![];
    let winners = find_winners(&[(0, p1), (1, p2)]);
    // 空牌组都是 HIGH_CARD 且 kickers 全为 0，平局
    assert_eq!(winners.len(), 2);
}

#[test]
fn test_hand_rank_equality() {
    // 相同牌型和 kicker 相等
    let a = HandRank::new(ONE_PAIR, &[ACE, KING, QUEEN, JACK]);
    let b = HandRank::new(ONE_PAIR, &[ACE, KING, QUEEN, JACK]);
    assert_eq!(a, b);
    assert!(!(a > b));
    assert!(!(a < b));
}

#[test]
fn test_hand_rank_different_categories() {
    // 不同牌型比较
    let high_card = HandRank::new(HIGH_CARD, &[ACE, KING, QUEEN, JACK, TEN]);
    let one_pair = HandRank::new(ONE_PAIR, &[2, 2, 2, 2, 2]); // 一对2
    assert!(one_pair > high_card);

    let two_pair = HandRank::new(TWO_PAIR, &[2, 2, 2, 2, 2]);
    assert!(two_pair > one_pair);

    let three = HandRank::new(THREE_OF_A_KIND, &[2, 2, 2, 2, 2]);
    assert!(three > two_pair);

    let straight = HandRank::new(STRAIGHT, &[5, 0, 0, 0, 0]); // wheel
    assert!(straight > three);

    let flush = HandRank::new(FLUSH, &[2, 2, 2, 2, 2]);
    assert!(flush > straight);

    let full_house = HandRank::new(FULL_HOUSE, &[2, 2, 2]);
    assert!(full_house > flush);

    let four = HandRank::new(FOUR_OF_A_KIND, &[2, 2]);
    assert!(four > full_house);

    let straight_flush = HandRank::new(STRAIGHT_FLUSH, &[5, 0, 0, 0, 0]);
    assert!(straight_flush > four);

    let royal = HandRank::new(ROYAL_FLUSH, &[0, 0, 0, 0, 0]);
    assert!(royal > straight_flush);
}

#[test]
fn test_two_pair_high_pair_comparison() {
    // 两对：先比高对
    let a = HandRank::new(TWO_PAIR, &[ACE, KING, QUEEN]);
    let b = HandRank::new(TWO_PAIR, &[KING, QUEEN, JACK]);
    assert!(a > b);
}

#[test]
fn test_two_pair_low_pair_comparison() {
    // 两对：高对相同，比低对
    let a = HandRank::new(TWO_PAIR, &[ACE, QUEEN, KING]);
    let b = HandRank::new(TWO_PAIR, &[ACE, KING, QUEEN]);
    // 排序后高对都是 A，低对应该是 K vs Q
    // 注意：kickers 是按 hi, lo, kicker 排列的
    assert_eq!(a.kickers[0], ACE);
    assert_eq!(b.kickers[0], ACE);
    // 测试两对的实际评估
    let cards_a = vec![
        Card::new(SPADES, ACE),
        Card::new(HEARTS, ACE),
        Card::new(DIAMONDS, KING),
        Card::new(CLUBS, KING),
        Card::new(SPADES, QUEEN),
    ];
    let cards_b = vec![
        Card::new(SPADES, ACE),
        Card::new(HEARTS, ACE),
        Card::new(DIAMONDS, QUEEN),
        Card::new(CLUBS, QUEEN),
        Card::new(SPADES, KING),
    ];
    let rank_a = evaluate_best(&cards_a);
    let rank_b = evaluate_best(&cards_b);
    assert_eq!(rank_a.category, TWO_PAIR);
    assert_eq!(rank_b.category, TWO_PAIR);
    // A 对 K 对 > A 对 Q 对
    assert!(rank_a > rank_b);
}

// ===========================================================================
// 6. side_pot.rs — 边池结算
// ===========================================================================

#[test]
fn test_side_pot_new() {
    let pot = SidePot::new(100, 0b0011);
    assert_eq!(pot.amount, 100);
    assert_eq!(pot.eligible_seats, 0b0011);
}

#[test]
fn test_side_pot_is_eligible() {
    let pot = SidePot::new(100, 0b0101);
    assert!(pot.is_eligible(0));
    assert!(!pot.is_eligible(1));
    assert!(pot.is_eligible(2));
    assert!(!pot.is_eligible(3));
}

#[test]
fn test_side_pot_borsh_roundtrip() {
    let pot = SidePot::new(150, 0b1011);
    let bytes = borsh::to_vec(&pot).unwrap();
    let decoded = borsh::from_slice(&bytes).unwrap();
    assert_eq!(pot, decoded);
}

#[test]
fn test_calculate_side_pots_no_all_in() {
    let bets = vec![100, 100];
    let folded = vec![false, false];
    let all_in = vec![false, false];
    let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
    assert_eq!(result.pots.len(), 1);
    assert_eq!(result.pots[0].amount, 200);
    assert_eq!(result.pots[0].eligible_seats, 0b0011);
    assert_eq!(result.total(), 200);
}

#[test]
fn test_calculate_side_pots_single_all_in() {
    let bets = vec![50, 100];
    let folded = vec![false, false];
    let all_in = vec![true, false];
    let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
    assert_eq!(result.pots.len(), 2);
    assert_eq!(result.pots[0].amount, 100);
    assert_eq!(result.pots[0].eligible_seats, 0b0011);
    assert_eq!(result.pots[1].amount, 50);
    assert_eq!(result.pots[1].eligible_seats, 0b0010);
    assert_eq!(result.total(), 150);
}

#[test]
fn test_calculate_side_pots_three_players_two_all_in() {
    let bets = vec![50, 100, 100];
    let folded = vec![false, false, false];
    let all_in = vec![true, true, false];
    let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
    assert_eq!(result.pots.len(), 2);
    assert_eq!(result.pots[0].amount, 150);
    assert_eq!(result.pots[0].eligible_seats, 0b0111);
    assert_eq!(result.pots[1].amount, 100);
    assert_eq!(result.pots[1].eligible_seats, 0b0110);
    assert_eq!(result.total(), 250);
}

#[test]
fn test_calculate_side_pots_folded_player_ineligible() {
    let bets = vec![30, 100, 100];
    let folded = vec![true, false, false];
    let all_in = vec![false, true, false];
    let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
    assert_eq!(result.pots.len(), 1);
    assert_eq!(result.pots[0].amount, 230);
    assert_eq!(result.pots[0].eligible_seats, 0b0110);
}

#[test]
fn test_calculate_side_pots_all_folded() {
    let bets = vec![50, 100, 150];
    let folded = vec![true, true, true];
    let all_in = vec![false, false, false];
    let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
    assert_eq!(result.pots.len(), 1);
    assert_eq!(result.pots[0].amount, 300);
    assert_eq!(result.pots[0].eligible_seats, 0);
}

#[test]
fn test_calculate_side_pots_empty_eligible_merge() {
    let bets = vec![50, 200, 200];
    let folded = vec![false, true, true];
    let all_in = vec![true, false, false];
    let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
    assert_eq!(result.pots.len(), 1);
    assert_eq!(result.pots[0].amount, 450);
}

#[test]
fn test_calculate_side_pots_length_mismatch() {
    let bets = vec![100, 100];
    let folded = vec![false];
    let all_in = vec![false, false];
    let result = calculate_side_pots(&bets, &folded, &all_in);
    assert!(matches!(result, Err(SidePotError::LengthMismatch)));
}

#[test]
fn test_calculate_side_pots_bet_overflow() {
    let bets = vec![MAX_TOTAL_BET, 1];
    let folded = vec![false, false];
    let all_in = vec![false, false];
    let result = calculate_side_pots(&bets, &folded, &all_in);
    assert!(matches!(result, Err(SidePotError::BetOverflow)));
}

#[test]
fn test_calculate_side_pots_four_players_multiple_all_in() {
    let bets = vec![20, 50, 80, 100];
    let folded = vec![false, false, false, false];
    let all_in = vec![true, true, true, false];
    let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();

    assert_eq!(result.pots.len(), 4);
    assert_eq!(result.pots[0].amount, 80);
    assert_eq!(result.pots[1].amount, 90);
    assert_eq!(result.pots[2].amount, 60);
    assert_eq!(result.pots[3].amount, 20);
    assert_eq!(result.total(), 250);
}

// ===== side_pot.rs 补充边缘场景 =====

#[test]
fn test_side_pot_error_display() {
    assert_eq!(
        format!("{}", SidePotError::BetOverflow),
        "total bets exceed MAX_TOTAL_BET, possible overflow"
    );
    assert_eq!(
        format!("{}", SidePotError::LengthMismatch),
        "bets/folded/all_in vectors must have same length"
    );
}

#[test]
fn test_side_pot_result_total_matches_sum() {
    let bets = vec![50, 100, 150];
    let folded = vec![false, false, false];
    let all_in = vec![true, true, false];
    let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();

    let sum: u64 = result.pots.iter().map(|p| p.amount).sum();
    assert_eq!(result.total(), sum);
    assert_eq!(result.total(), 300);
}

#[test]
fn test_calculate_side_pots_max_players_limit() {
    // 超过 MAX_PLAYERS 应该返回 LengthMismatch
    let bets = vec![100; 10];
    let folded = vec![false; 10];
    let all_in = vec![false; 10];
    let result = calculate_side_pots(&bets, &folded, &all_in);
    assert!(matches!(result, Err(SidePotError::LengthMismatch)));
}

#[test]
fn test_calculate_side_pots_single_player() {
    let bets = vec![100];
    let folded = vec![false];
    let all_in = vec![true];
    let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
    assert_eq!(result.pots.len(), 1);
    assert_eq!(result.pots[0].amount, 100);
    assert!(result.pots[0].is_eligible(0));
}

#[test]
fn test_calculate_side_pots_zero_bet_all_in() {
    // all-in 但 bet=0：不应作为 level
    let bets = vec![0, 100];
    let folded = vec![false, false];
    let all_in = vec![true, false];
    let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
    assert_eq!(result.pots.len(), 1);
    assert_eq!(result.pots[0].amount, 100);
}

#[test]
fn test_calculate_side_pots_all_same_all_in_level() {
    // 所有玩家 all-in 且金额相同
    let bets = vec![100, 100, 100];
    let folded = vec![false, false, false];
    let all_in = vec![true, true, true];
    let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
    assert_eq!(result.pots.len(), 1);
    assert_eq!(result.pots[0].amount, 300);
    assert_eq!(result.pots[0].eligible_seats, 0b0111);
}

#[test]
fn test_side_pot_is_eligible_boundary() {
    let pot = SidePot::new(100, 0xFFFF);
    assert!(pot.is_eligible(0));
    assert!(pot.is_eligible(15));
    // seat 在 0-15 范围内正常工作
}

#[test]
#[should_panic(expected = "shift left with overflow")]
fn test_side_pot_is_eligible_seat_over_15_panics() {
    // seat >= 16 时位运算会溢出（u16 最多 16 位）
    // 在实际使用中 seat 由 MAX_PLAYERS 限制为 0-8，不会触发
    let pot = SidePot::new(100, 0xFFFF);
    let _ = pot.is_eligible(16);
}

#[test]
fn test_calculate_side_pots_side_pot_result_clone() {
    let bets = vec![50, 100];
    let folded = vec![false, false];
    let all_in = vec![true, false];
    let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
    let cloned = result.clone();
    assert_eq!(result.pots.len(), cloned.pots.len());
    assert_eq!(result.total(), cloned.total());
}

#[test]
fn test_calculate_side_pots_all_in_folded_only() {
    // 只有 all-in 且 folded 的玩家贡献
    let bets = vec![50, 100];
    let folded = vec![true, true];
    let all_in = vec![true, false];
    let result = calculate_side_pots(&bets, &folded, &all_in).unwrap();
    // 全员 fold，只有一个 pot，eligible=0
    assert_eq!(result.pots.len(), 1);
    assert_eq!(result.pots[0].amount, 150);
    assert_eq!(result.pots[0].eligible_seats, 0);
}

// ===========================================================================
// 7. state_machine.rs — 状态机与游戏逻辑
// ===========================================================================

use blstrs::G1Projective;
use group::Group;
use poker_l1::vm::contracts::texas_poker::{
    events::{KickCause, TexasPokerEvent},
    state_machine,
    types::TexasPokerTable,
};
use poker_protocol::crypto::types::ECPoint;

fn dummy_table(name: &str, max_players: u8) -> TexasPokerTable {
    let id = poker_l1::object_model::ObjectID::new([0xFF; 20], 0);
    // creator 设为 [0x01;20]，与 make_dispatch_context().caller 一致，
    // 使需要 creator 权限的管理类测试天然通过。
    TexasPokerTable::new(id, name.into(), [0x01; 20], max_players, 50, 100)
}

fn occupy_seat(table: &mut TexasPokerTable, seat_idx: u8, player: [u8; 20], stack: u64) {
    let mut seat = Seat::occupied(
        player,
        stack,
        ECPoint(G1Projective::generator()),
        SeatStatus::Active,
    )
    .unwrap();
    seat.set_time_bank_ms(300_000);
    table.seats[seat_idx as usize] = seat;
}

fn enter_betting_fixture(
    table: &mut TexasPokerTable,
    street: u8,
    round: BettingRound,
    current_turn: u8,
) {
    table
        .enter_betting(street, round, current_turn, 1_000)
        .unwrap();
}

// ========== 状态谓词 ==========

#[test]
fn test_state_predicates_can_join_state() {
    let mut table = dummy_table("test", 6);
    assert!(state_machine::can_join_state(&table));

    enter_betting_fixture(&mut table, ROUND_PREFLOP, BettingRound::new(100, 0), 0);
    assert!(!state_machine::can_join_state(&table));
}

#[test]
fn test_state_predicates_can_leave_state() {
    let mut table = dummy_table("test", 6);
    assert!(state_machine::can_leave_state(&table));

    enter_betting_fixture(&mut table, ROUND_FLOP, BettingRound::new(100, 0), 0);
    assert!(!state_machine::can_leave_state(&table));
}

#[test]
fn test_state_predicates_is_betting_round() {
    let mut table = dummy_table("test", 6);
    assert!(!state_machine::is_betting_round(&table));

    enter_betting_fixture(&mut table, ROUND_PREFLOP, BettingRound::new(100, 100), 0);
    assert!(state_machine::is_betting_round(&table));

    table.enter_showdown_display(0);
    assert!(!state_machine::is_betting_round(&table));
}

#[test]
fn test_state_predicates_is_playing() {
    let mut table = dummy_table("test", 6);
    assert!(!state_machine::is_playing(&table));

    enter_betting_fixture(&mut table, ROUND_PREFLOP, BettingRound::new(100, 0), 0);
    assert!(state_machine::is_playing(&table));
}

#[test]
fn test_state_predicates_is_player_turn() {
    let mut table = dummy_table("test", 6);
    enter_betting_fixture(&mut table, ROUND_PREFLOP, BettingRound::new(100, 0), 2);

    assert!(state_machine::is_player_turn(&table, 2));
    assert!(!state_machine::is_player_turn(&table, 3));
}

#[test]
fn test_state_predicates_is_in_mask() {
    let mask = 0b10_1010;
    assert!(state_machine::is_in_mask(mask, 3));
    assert!(!state_machine::is_in_mask(mask, 2));
}

// ========== 座位辅助函数 ==========

#[test]
fn test_seat_helpers_count_active_players() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    occupy_seat(&mut table, 2, [0x03; 20], 1000);

    assert_eq!(state_machine::count_active_players(&table.seats), 3);

    table.seats[1].set_status(SeatStatus::Folded);
    assert_eq!(state_machine::count_active_players(&table.seats), 2);

    table.seats[2].set_status(SeatStatus::Waiting);
    assert_eq!(state_machine::count_active_players(&table.seats), 1);
}

#[test]
fn test_seat_helpers_count_active_occupied() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);

    assert_eq!(state_machine::count_active_occupied(&table.seats), 2);

    table.seats[1].set_status(SeatStatus::Folded);
    assert_eq!(state_machine::count_active_occupied(&table.seats), 2);

    table.seats[1].set_status(SeatStatus::Waiting);
    assert_eq!(state_machine::count_active_occupied(&table.seats), 1);
}

#[test]
fn test_seat_helpers_get_active_seat_indices() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 2, [0x02; 20], 1000);

    let indices = state_machine::get_active_seat_indices(&table.seats);
    assert_eq!(indices, vec![0, 2]);
}

#[test]
fn test_seat_helpers_find_next_active_seat() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    occupy_seat(&mut table, 2, [0x03; 20], 1000);
    table.seats[0].set_status(SeatStatus::Folded);

    // 环形查找：从 seat 0 开始找下一个，跳过 folded 的 seat 0，找到 seat 1
    assert_eq!(
        state_machine::find_next_active_seat(&table.seats, 0, 4),
        Some(1)
    );
    // 从 seat 1 开始找下一个，找到 seat 2
    assert_eq!(
        state_machine::find_next_active_seat(&table.seats, 1, 4),
        Some(2)
    );
    // 从 seat 2 开始找下一个，绕回找到 seat 1（seat 0 已 folded）
    assert_eq!(
        state_machine::find_next_active_seat(&table.seats, 2, 4),
        Some(1)
    );

    // 所有玩家都 folded 时返回 None
    table.seats[1].set_status(SeatStatus::Folded);
    table.seats[2].set_status(SeatStatus::Folded);
    assert_eq!(
        state_machine::find_next_active_seat(&table.seats, 0, 4),
        None
    );
}

#[test]
fn test_seat_helpers_find_next_participating_seat() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 2, [0x02; 20], 1000);

    assert_eq!(
        state_machine::find_next_participating_seat(&table.seats, 0, 4),
        Some(2)
    );
}

#[test]
fn test_seat_helpers_has_actionable_player() {
    let mut table = dummy_table("test", 4);
    assert!(!state_machine::has_actionable_player(&table.seats));

    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    assert!(state_machine::has_actionable_player(&table.seats));

    table.seats[0].set_status(SeatStatus::Folded);
    assert!(!state_machine::has_actionable_player(&table.seats));
}

// ========== 下注动作 ==========

#[test]
fn test_apply_fold_not_betting_round() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    table.enter_waiting();

    let mut events = vec![];
    let result = state_machine::apply_fold(&mut table, 0, &mut events);
    assert!(matches!(result, Err(_)));
}

#[test]
fn test_apply_fold_not_players_turn() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    enter_betting_fixture(&mut table, ROUND_PREFLOP, BettingRound::new(100, 100), 1);

    let mut events = vec![];
    let result = state_machine::apply_fold(&mut table, 0, &mut events);
    assert!(matches!(result, Err(_)));
}

#[test]
fn test_apply_fold_success() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    occupy_seat(&mut table, 2, [0x03; 20], 1000);
    enter_betting_fixture(&mut table, ROUND_PREFLOP, BettingRound::new(100, 100), 0);

    let mut events = vec![];
    let result = state_machine::apply_fold(&mut table, 0, &mut events);
    assert!(result.is_ok());
    assert!(table.seats[0].is_folded());
}

#[test]
fn test_apply_check_not_betting_round() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);

    let mut events = vec![];
    let result = state_machine::apply_check(&mut table, 0, &mut events);
    assert!(matches!(result, Err(_)));
}

#[test]
fn test_apply_check_bet_below_current() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    enter_betting_fixture(&mut table, ROUND_PREFLOP, BettingRound::new(100, 100), 0);

    let mut events = vec![];
    let result = state_machine::apply_check(&mut table, 0, &mut events);
    assert!(matches!(result, Err(_)));
}

#[test]
fn test_apply_check_success() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    enter_betting_fixture(&mut table, ROUND_FLOP, BettingRound::new(100, 0), 0);

    let mut events = vec![];
    let result = state_machine::apply_check(&mut table, 0, &mut events);
    assert!(result.is_ok());
    assert!(table.seat_acted_this_round(0));
    assert_eq!(table.current_turn(), 1);
}

#[test]
fn test_apply_call_not_betting_round() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);

    let mut events = vec![];
    let result = state_machine::apply_call(&mut table, 0, &mut events);
    assert!(matches!(result, Err(_)));
}

#[test]
fn test_apply_call_success() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    enter_betting_fixture(&mut table, ROUND_PREFLOP, BettingRound::new(100, 100), 0);

    let mut events = vec![];
    let result = state_machine::apply_call(&mut table, 0, &mut events);
    assert!(result.is_ok());
    assert_eq!(table.seats[0].bet(), 100);
    assert_eq!(table.seats[0].stack(), 900);
}

#[test]
fn test_apply_call_all_in() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 50);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    enter_betting_fixture(&mut table, ROUND_PREFLOP, BettingRound::new(100, 100), 0);

    let mut events = vec![];
    let result = state_machine::apply_call(&mut table, 0, &mut events);
    assert!(result.is_ok());
    assert_eq!(table.seats[0].stack(), 0);
    assert!(table.seats[0].is_all_in());
}

#[test]
fn test_apply_raise_not_betting_round() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);

    let mut events = vec![];
    let result = state_machine::apply_raise(&mut table, 0, 200, &mut events);
    assert!(matches!(result, Err(_)));
}

#[test]
fn test_apply_raise_success() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    enter_betting_fixture(&mut table, ROUND_PREFLOP, BettingRound::new(100, 100), 0);

    let mut events = vec![];
    let result = state_machine::apply_raise(&mut table, 0, 300, &mut events);
    assert!(result.is_ok());
    assert_eq!(table.seats[0].bet(), 300);
    assert_eq!(table.seats[0].stack(), 700);
}

#[test]
fn test_apply_raise_all_in() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 500);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    enter_betting_fixture(&mut table, ROUND_PREFLOP, BettingRound::new(100, 100), 0);

    let mut events = vec![];
    let result = state_machine::apply_raise(&mut table, 0, 500, &mut events);
    assert!(result.is_ok());
    assert_eq!(table.seats[0].stack(), 0);
    assert!(table.seats[0].is_all_in());
}

#[test]
fn test_apply_raise_resets_other_players() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    enter_betting_fixture(&mut table, ROUND_PREFLOP, BettingRound::new(100, 100), 0);
    table.set_seat_acted_this_round(1, true);

    let mut events = vec![];
    let result = state_machine::apply_raise(&mut table, 0, 300, &mut events);
    assert!(result.is_ok());
    assert!(!table.seat_acted_this_round(1));
}

// ========== 结算与重置 ==========

#[test]
fn test_reset_for_next_hand_clears_state() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 500);
    occupy_seat(&mut table, 1, [0x02; 20], 500);
    table.pot = 1000;
    table.community_cards = vec![Card::new(0, 14), Card::new(1, 13)].try_into().unwrap();
    table.enter_showdown_display(0);

    let mut events = vec![];
    let result = state_machine::reset_for_next_hand(&mut table, &mut events);
    assert!(result.is_ok());

    assert_eq!(table.round_state(), ROUND_WAITING);
    assert_eq!(table.pot, 0);
    assert!(table.community_cards.is_empty());
    assert!(table.betting_round().is_none());
    assert!(table.current_turn_option().is_none());
}

#[test]
fn test_reset_for_next_hand_merges_pending_addon() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 500);
    table.seats[0].set_pending_addon(1000).unwrap();
    table.chip_pool = 1500;

    let mut events = vec![];
    let result = state_machine::reset_for_next_hand(&mut table, &mut events);
    assert!(result.is_ok());

    assert_eq!(table.seats[0].stack(), 1500);
    assert_eq!(table.seats[0].pending_addon(), 0);
}

#[test]
fn test_reset_for_next_hand_refills_time_bank() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 500);
    table.seats[0].set_time_bank_ms(0);

    let mut events = vec![];
    let result = state_machine::reset_for_next_hand(&mut table, &mut events);
    assert!(result.is_ok());

    assert!(table.seats[0].time_bank_ms() > 0);
}

// ========== 盲注定位（通过 start_hand 间接测试） ==========

// ========== kick_player_internal ==========

#[test]
fn test_kick_player_internal_refunds_stack() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 500);
    table.chip_pool = 500;

    let mut events = vec![];
    state_machine::kick_player_internal(&mut table, 0, KickCause::Timeout, &mut events).unwrap();

    assert!(!table.seats[0].is_occupied());
    assert_eq!(table.chip_pool, 0);
}

// ========== state_machine.rs 补充边缘场景 ==========

#[test]
fn test_is_playing_different_phases() {
    let mut table = dummy_table("test", 4);
    // 初始状态：不在游戏中
    assert!(!state_machine::is_playing(&table));

    // round_state 非 WAITING
    enter_betting_fixture(&mut table, ROUND_PREFLOP, BettingRound::new(100, 0), 0);
    assert!(state_machine::is_playing(&table));

    // 回到 WAITING，但 shuffle phase 非 NONE
    table
        .enter_initial_shuffling(
            ShuffleState {
                pending_mask: 1,
                completed_mask: 0,
            },
            0,
        )
        .unwrap();
    assert!(state_machine::is_playing(&table));

    // shuffle 结束，但 reveal phase 非 NONE
    table
        .enter_revealing(
            ROUND_FLOP,
            RevealTokenState {
                purpose: RevealPurpose::Board,
                assignments: vec![],
            },
            0,
        )
        .unwrap();
    assert!(state_machine::is_playing(&table));

    // reveal 结束，但 reconstruct 非 NONE
    table
        .enter_reconstructing(
            ROUND_FLOP,
            ReconstructState {
                pending_mask: 1,
                accumulated_deck: None,
            },
            RevealTokenState {
                purpose: RevealPurpose::Board,
                assignments: vec![],
            },
            0,
        )
        .unwrap();
    assert!(state_machine::is_playing(&table));
}

#[test]
fn test_find_next_active_seat_all_in_filtered() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    occupy_seat(&mut table, 2, [0x03; 20], 1000);

    // seat 1 all-in，应被跳过
    table.seats[1].set_status(SeatStatus::AllIn);
    assert_eq!(
        state_machine::find_next_active_seat(&table.seats, 0, 4),
        Some(2)
    );
    assert_eq!(
        state_machine::find_next_active_seat(&table.seats, 2, 4),
        Some(0)
    );
}

#[test]
fn test_find_next_participating_seat_includes_folded_and_all_in() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    occupy_seat(&mut table, 2, [0x03; 20], 1000);

    // find_next_participating_seat 不过滤 folded / all_in
    table.seats[1].set_status(SeatStatus::Folded);
    table.seats[2].set_status(SeatStatus::AllIn);
    assert_eq!(
        state_machine::find_next_participating_seat(&table.seats, 0, 4),
        Some(1)
    );
    assert_eq!(
        state_machine::find_next_participating_seat(&table.seats, 1, 4),
        Some(2)
    );
}

#[test]
fn test_is_pk_registered() {
    let mut table = dummy_table("test", 4);
    let pk1 = G1Projective::generator();
    let pk2 = G1Projective::identity();

    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    table.seats[0].occupied_mut().unwrap().pk = ECPoint(pk1);

    assert!(state_machine::is_pk_registered(&table.seats, &pk1));
    assert!(!state_machine::is_pk_registered(&table.seats, &pk2));
}

#[test]
fn test_get_pending_seat_indices_filters_completed() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    occupy_seat(&mut table, 2, [0x03; 20], 1000);

    let completed_mask = 0b0101;
    let pending_mask = state_machine::get_pending_seat_mask(completed_mask, &table.seats);
    assert_eq!(pending_mask, 0b0010);
}

#[test]
fn test_remove_from_pending_existing() {
    let mut mask = 0b1111;
    seat_mask_remove(&mut mask, 1);
    assert_eq!(mask.count_ones(), 3);
    assert!(!state_machine::is_in_mask(mask, 1));
}

#[test]
fn test_remove_from_pending_non_existing() {
    let mut mask = 0b0111;
    // 移除不存在的值，不应报错
    seat_mask_remove(&mut mask, 5);
    assert_eq!(mask, 0b0111);
}

#[test]
fn test_collect_rake_none_mode() {
    let mut table = dummy_table("test", 4);
    table.rake_mode = RAKE_MODE_NONE;
    table.pot = 1000;

    let rake =
        state_machine::collect_rake(&mut table).expect("none-mode rake collection should succeed");
    assert_eq!(rake, 0);
    assert_eq!(table.pot, 1000);
}

#[test]
fn test_collect_rake_percentage_below_cap() {
    let mut table = dummy_table("test", 4);
    table.rake_mode = RAKE_MODE_PERCENTAGE;
    table.rake_bps = 500; // 5%
    table.rake_cap = 100;
    table.pot = 1000;
    table.chip_pool = 1000;

    let rake = state_machine::collect_rake(&mut table)
        .expect("percentage rake collection below cap should succeed");
    assert_eq!(rake, 50); // 1000 * 5% = 50
    assert_eq!(table.pot, 950);
    assert_eq!(1000 - table.pot, 50);
}

#[test]
fn test_collect_rake_percentage_at_cap() {
    let mut table = dummy_table("test", 4);
    table.rake_mode = RAKE_MODE_PERCENTAGE;
    table.rake_bps = 500; // 5%
    table.rake_cap = 30;
    table.pot = 1000;
    table.chip_pool = 1000;

    let rake = state_machine::collect_rake(&mut table)
        .expect("percentage rake collection at cap should succeed");
    assert_eq!(rake, 30); // capped at 30
    assert_eq!(table.pot, 970);
}

#[test]
fn test_collect_rake_zero_pot() {
    let mut table = dummy_table("test", 4);
    table.rake_mode = RAKE_MODE_PERCENTAGE;
    table.rake_bps = 500;
    table.rake_cap = 100;
    table.pot = 0;

    let rake =
        state_machine::collect_rake(&mut table).expect("zero-pot rake collection should succeed");
    assert_eq!(rake, 0);
    assert_eq!(table.pot, 0);
}

#[test]
fn test_collect_ante_none_mode() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    table.ante_mode = ANTE_MODE_NONE;
    table.ante_amount = 10;

    let mut events = vec![];
    state_machine::collect_ante(&mut table, 0, &mut events).unwrap();
    assert_eq!(table.seats[0].stack(), 1000); // 未扣
    assert_eq!(table.pot, 0);
}

#[test]
fn test_collect_ante_normal_mode() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    table.ante_mode = ANTE_MODE_NORMAL;
    table.ante_amount = 10;

    let mut events = vec![];
    state_machine::collect_ante(&mut table, 0, &mut events).unwrap();

    assert_eq!(table.seats[0].stack(), 990);
    assert_eq!(table.seats[1].stack(), 990);
    assert_eq!(table.pot, 20);
    // Antes are dead money: they increase total_bet and pot, but do not reduce
    // the amount still owed in the current betting round.
    assert_eq!(table.seats[0].bet(), 0);
    assert_eq!(table.seats[0].total_bet(), 10);
}

#[test]
fn test_collect_ante_bba_mode() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    table.ante_mode = ANTE_MODE_BBA;
    table.ante_amount = 10;

    let mut events = vec![];
    state_machine::collect_ante(&mut table, 1, &mut events).unwrap(); // BB 是 seat 1

    assert_eq!(table.seats[0].stack(), 1000); // 非 BB 不扣
    assert_eq!(table.seats[1].stack(), 990); // BB 扣
    assert_eq!(table.pot, 10);
}

#[test]
fn test_collect_ante_all_in_on_zero_stack() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 5); // 只有 5 筹码
    table.ante_mode = ANTE_MODE_NORMAL;
    table.ante_amount = 10;

    let mut events = vec![];
    state_machine::collect_ante(&mut table, 0, &mut events).unwrap();

    assert_eq!(table.seats[0].stack(), 0);
    assert!(table.seats[0].is_all_in());
    // A short-stack ante is still dead money and therefore does not enter bet.
    assert_eq!(table.seats[0].bet(), 0);
    assert_eq!(table.pot, 5);
}

#[test]
fn test_set_initial_encrypted_deck() {
    let mut table = dummy_table("test", 4);
    let result = state_machine::set_initial_encrypted_deck(&mut table);
    assert!(result.is_ok());
    assert_eq!(table.deck_state.encrypted.len(), 52);
    assert_eq!(utils::generate_plaintext_cards().len(), 52);
    assert_eq!(table.deck_state.cards_dealt, 0);
    assert!(table.deck_state.owner_readable_hole_cards.is_empty());
}

// ========== state_machine.rs 补充边缘场景 — 状态谓词 ==========

#[test]
fn test_count_active_players_empty_table() {
    let table = dummy_table("test", 4);
    assert_eq!(state_machine::count_active_players(&table.seats), 0);
}

#[test]
fn test_count_active_players_with_waiting() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    table.seats[1].set_status(SeatStatus::Waiting);

    assert_eq!(state_machine::count_active_players(&table.seats), 1);
}

#[test]
fn test_count_active_players_with_folded_and_all_in() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    occupy_seat(&mut table, 2, [0x03; 20], 1000);
    table.seats[1].set_status(SeatStatus::Folded);
    table.seats[2].set_status(SeatStatus::AllIn);

    // count_active_players 不过滤 all-in，只过滤 folded/waiting
    // seat 0: active, seat 1: folded(excluded), seat 2: all-in(included)
    assert_eq!(state_machine::count_active_players(&table.seats), 2);
}

#[test]
fn test_count_active_occupied_includes_folded() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    table.seats[1].set_status(SeatStatus::Folded);

    assert_eq!(state_machine::count_active_occupied(&table.seats), 2);
}

#[test]
fn test_get_active_seat_indices_empty() {
    let table = dummy_table("test", 4);
    assert!(state_machine::get_active_seat_indices(&table.seats).is_empty());
}

#[test]
fn test_get_active_seat_indices_excludes_waiting() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    table.seats[1].set_status(SeatStatus::Waiting);

    let indices = state_machine::get_active_seat_indices(&table.seats);
    assert_eq!(indices, vec![0]);
}

#[test]
fn test_find_next_active_seat_all_folded() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    table.seats[0].set_status(SeatStatus::Folded);
    table.seats[1].set_status(SeatStatus::Folded);

    assert_eq!(
        state_machine::find_next_active_seat(&table.seats, 0, 4),
        None
    );
}

#[test]
fn test_find_next_active_seat_wraps_around() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 3, [0x03; 20], 1000);

    assert_eq!(
        state_machine::find_next_active_seat(&table.seats, 0, 4),
        Some(3)
    );
    assert_eq!(
        state_machine::find_next_active_seat(&table.seats, 3, 4),
        Some(0)
    );
}

// ========== state_machine.rs 补充边缘场景 — apply_raise ==========

#[test]
fn test_apply_raise_minimum_raise() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    enter_betting_fixture(&mut table, ROUND_PREFLOP, BettingRound::new(100, 100), 0); // current_bet=100, min_raise=100

    let mut events = vec![];
    // 从 0 raise 到 200（最小 raise），需要投入 200
    let result = state_machine::apply_raise(&mut table, 0, 200, &mut events);
    assert!(result.is_ok());
    assert_eq!(table.seats[0].bet(), 200);
    assert_eq!(table.seats[0].stack(), 800); // 1000 - 200 = 800
    assert_eq!(table.betting_round().unwrap().current_bet, 200);
}

#[test]
fn test_apply_raise_below_minimum() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    enter_betting_fixture(&mut table, ROUND_PREFLOP, BettingRound::new(100, 100), 0);

    let mut events = vec![];
    // raise 到 150，低于最小 raise（需要到 200）
    let result = state_machine::apply_raise(&mut table, 0, 150, &mut events);
    assert!(result.is_err());
}

#[test]
fn test_apply_raise_not_players_turn() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    enter_betting_fixture(&mut table, ROUND_PREFLOP, BettingRound::new(100, 100), 0); // seat 0 的回合

    let mut events = vec![];
    // seat 1 尝试 raise（不是他的回合）
    let result = state_machine::apply_raise(&mut table, 1, 200, &mut events);
    assert!(result.is_err());
}

#[test]
fn test_apply_raise_raises_minimum_after_all_in() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 150);
    enter_betting_fixture(&mut table, ROUND_PREFLOP, BettingRound::new(100, 100), 1);

    let mut events = vec![];
    // seat 1 all-in raise 到 150
    // raise_amount = 50，小于 min_raise=100，所以 min_raise 不更新
    state_machine::apply_raise(&mut table, 1, 150, &mut events).unwrap();
    assert_eq!(table.betting_round().unwrap().current_bet, 150);
    assert_eq!(table.betting_round().unwrap().min_raise, 100); // 短 all-in 不更新 min_raise

    // seat 0 需要 raise 到 250（150+100）
    table.set_betting_turn(0).unwrap();
    events.clear();
    let result = state_machine::apply_raise(&mut table, 0, 250, &mut events);
    assert!(result.is_ok());
}

// ========== state_machine.rs 补充边缘场景 — 多步集成测试 ==========

#[test]
fn test_betting_round_complete_two_players() {
    let mut table = dummy_table("test", 2);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    enter_betting_fixture(&mut table, ROUND_PREFLOP, BettingRound::new(100, 100), 0); // BB = 100

    // seat 1 是 BB，已下注 100
    table.seats[1].set_bet(100).unwrap();
    table.seats[1].set_total_bet(100).unwrap();
    table.seats[1].set_stack(900).unwrap();

    let mut events = vec![];

    // seat 0 calls（跟注 100）
    state_machine::apply_call(&mut table, 0, &mut events).unwrap();
    assert_eq!(table.seats[0].bet(), 100);
    assert_eq!(table.seats[0].stack(), 900);

    // seat 1 checks（已跟注，无需行动）
    table.set_betting_turn(1).unwrap();
    events.clear();
    state_machine::apply_check(&mut table, 1, &mut events).unwrap();

    // 此时应该推进到下一回合（flop）
    // 由于 apply_check 会调用 advance_turn，最终会触发 advance_round
    assert_eq!(table.round_state(), ROUND_FLOP);
}

#[test]
fn test_raise_resets_other_players_acted() {
    let mut table = dummy_table("test", 3);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    occupy_seat(&mut table, 2, [0x03; 20], 1000);
    enter_betting_fixture(&mut table, ROUND_PREFLOP, BettingRound::new(100, 100), 0);

    let mut events = vec![];

    // seat 0 calls
    state_machine::apply_call(&mut table, 0, &mut events).unwrap();
    assert!(table.seat_acted_this_round(0));

    // seat 1 calls
    table.set_betting_turn(1).unwrap();
    state_machine::apply_call(&mut table, 1, &mut events).unwrap();
    assert!(table.seat_acted_this_round(1));

    // seat 2 raises
    table.set_betting_turn(2).unwrap();
    state_machine::apply_raise(&mut table, 2, 200, &mut events).unwrap();

    // seat 0 和 seat 1 的 acted_this_round 应该被重置
    assert!(!table.seat_acted_this_round(0));
    assert!(!table.seat_acted_this_round(1));
}

// ========== state_machine.rs 补充边缘场景 — tick 与超时处理 ==========

#[test]
fn test_consume_time_bank_normal() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    table.seats[0].set_time_bank_ms(30000);

    let mut events = vec![];
    let result = state_machine::consume_time_bank(&mut table, 0, 10000, &mut events);
    assert!(result.is_ok());
    assert_eq!(table.seats[0].time_bank_ms(), 20000);
}

#[test]
fn test_consume_time_bank_seat_out_of_range() {
    let mut table = dummy_table("test", 4);
    let mut events = vec![];
    let result = state_machine::consume_time_bank(&mut table, 4, 1000, &mut events);
    assert!(result.is_err());
}

#[test]
fn test_consume_time_bank_not_occupied() {
    let mut table = dummy_table("test", 4);
    let mut events = vec![];
    let result = state_machine::consume_time_bank(&mut table, 0, 1000, &mut events);
    assert!(result.is_err());
}

#[test]
fn test_consume_time_bank_insufficient() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    table.seats[0].set_time_bank_ms(5000);

    let mut events = vec![];
    let result = state_machine::consume_time_bank(&mut table, 0, 10000, &mut events);
    assert!(result.is_err());
}

#[test]
fn test_tick_waiting_requires_explicit_start_hand() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    // 2个玩家 >= MIN_PLAYERS_TO_START
    assert_eq!(table.round_state(), ROUND_WAITING);

    let mut events = vec![];
    let result = state_machine::advance_deadline(&mut table, 1_000_000, &mut events);
    assert!(result.is_ok());
    // WAITING is command-blocked, not deadline-blocked.
    assert_eq!(table.round_state(), ROUND_WAITING);
    assert_eq!(table.shuffle_phase(), SHUFFLE_PHASE_NONE);

    state_machine::start_hand(&mut table, &mut events).unwrap();
    assert_ne!(table.shuffle_phase(), SHUFFLE_PHASE_NONE);
}

#[test]
fn test_tick_betting_timeout_with_time_bank() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    enter_betting_fixture(&mut table, ROUND_PREFLOP, BettingRound::new(100, 100), 0);
    table.arm_betting_deadline(1_000_000).unwrap();
    table.timeout_config.betting_timeout_ms = 30000;
    table.seats[0].set_time_bank_ms(30000);

    let mut events = vec![];
    // 超时但有 time_bank，应该消耗 time_bank 而不是 fold
    let result = state_machine::advance_deadline(&mut table, 1_030_000, &mut events);
    assert!(result.is_ok());
    assert_eq!(table.seats[0].time_bank_ms(), 0);
    assert!(!table.seats[0].is_folded());
    // betting_started_at 应该被延长
    assert!(table.betting_deadline_ms().unwrap().unwrap() > 1_030_000);
}

#[test]
fn test_tick_betting_timeout_triggers_fold() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    occupy_seat(&mut table, 2, [0x03; 20], 1000); // 第三个玩家，防止立即结束
    enter_betting_fixture(&mut table, ROUND_PREFLOP, BettingRound::new(100, 100), 0);
    table.arm_betting_deadline(1_000_000).unwrap();
    table.timeout_config.betting_timeout_ms = 30000;
    table.seats[0].set_time_bank_ms(0); // 没有 time_bank

    let mut events = vec![];
    // 超时且没有 time_bank，应该 fold
    let result = state_machine::advance_deadline(&mut table, 1_030_001, &mut events);
    assert!(result.is_ok());
    // on_betting_timeout 应该 fold 玩家
    assert!(table.seats[0].is_folded());
}

#[test]
fn test_tick_showdown_settles_hand() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 900);
    occupy_seat(&mut table, 1, [0x02; 20], 900);
    table.seats[0]
        .set_hand([Card::new(0, 14), Card::new(1, 14)].into())
        .unwrap();
    table.seats[1]
        .set_hand([Card::new(2, 13), Card::new(3, 13)].into())
        .unwrap();
    table.seats[0].set_total_bet(100).unwrap();
    table.seats[1].set_total_bet(100).unwrap();
    table.community_cards = vec![
        Card::new(0, 2),
        Card::new(1, 3),
        Card::new(2, 4),
        Card::new(3, 8),
        Card::new(0, 9),
    ]
    .try_into()
    .unwrap();
    table.enter_showdown_display(1_000_000);
    table.pot = 200;
    table.chip_pool = 2_000;

    let mut events = vec![];
    // showdown 时间到，应该结算
    let result = state_machine::advance_deadline(&mut table, 1_000_001, &mut events);
    assert!(result.is_ok(), "showdown settlement failed: {result:?}");
    assert_eq!(table.round_state(), ROUND_WAITING);
    assert_eq!(table.pot, 0);
}

#[test]
fn test_start_hand_min_players_fails() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    // 只有1个玩家，不够开始游戏
    let mut events = vec![];
    let result = state_machine::start_hand(&mut table, &mut events);
    assert!(result.is_err());
}

#[test]
fn test_start_hand_success() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    // 2个玩家 >= MIN_PLAYERS_TO_START
    let mut events = vec![];
    let result = state_machine::start_hand(&mut table, &mut events);
    assert!(result.is_ok());
    assert_ne!(table.shuffle_phase(), SHUFFLE_PHASE_NONE);
}

// ========== state_machine.rs 补充边缘场景 — apply_fold_internal 修复测试 ==========

#[test]
fn test_apply_fold_internal_betting_round() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    occupy_seat(&mut table, 2, [0x03; 20], 1000); // 第三个玩家，防止立即结束
    enter_betting_fixture(&mut table, ROUND_PREFLOP, BettingRound::new(100, 100), 0);

    let mut events = vec![];
    let result = state_machine::apply_fold_internal(&mut table, 0, 0, &mut events);
    assert!(result.is_ok());
    assert!(table.seats[0].is_folded());
}

#[test]
fn test_apply_fold_internal_not_betting_round() {
    let mut table = dummy_table("test", 2);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    table.enter_waiting(); // 不在 betting round

    let mut events = vec![];
    let result = state_machine::apply_fold_internal(&mut table, 0, 0, &mut events);
    assert!(result.is_err());
}

#[test]
fn test_apply_fold_internal_already_folded() {
    let mut table = dummy_table("test", 2);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    enter_betting_fixture(&mut table, ROUND_PREFLOP, BettingRound::new(100, 100), 0);
    table.seats[0].set_status(SeatStatus::Folded);

    let mut events = vec![];
    let result = state_machine::apply_fold_internal(&mut table, 0, 0, &mut events);
    assert!(result.is_err());
}

// ========== state_machine.rs 补充边缘场景 — apply_bet / apply_addon / apply_rebuy ==========

#[test]
fn test_apply_bet_postflop_success() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    enter_betting_fixture(&mut table, ROUND_FLOP, BettingRound::new(100, 0), 0); // big_blind=100, current_bet=0

    let mut events = vec![];
    let result = state_machine::apply_bet(&mut table, 0, 100, &mut events);
    assert!(result.is_ok());
    assert_eq!(table.seats[0].bet(), 100);
}

#[test]
fn test_apply_bet_not_betting_round() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    table.enter_waiting();

    let mut events = vec![];
    let result = state_machine::apply_bet(&mut table, 0, 100, &mut events);
    assert!(result.is_err());
}

#[test]
fn test_apply_bet_not_players_turn() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    enter_betting_fixture(&mut table, ROUND_FLOP, BettingRound::new(100, 0), 1); // seat 1 的回合

    let mut events = vec![];
    let result = state_machine::apply_bet(&mut table, 0, 100, &mut events);
    assert!(result.is_err());
}

#[test]
fn test_apply_bet_amount_zero() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    enter_betting_fixture(&mut table, ROUND_FLOP, BettingRound::new(100, 0), 0);

    let mut events = vec![];
    let result = state_machine::apply_bet(&mut table, 0, 0, &mut events);
    assert!(result.is_err());
}

#[test]
fn test_apply_bet_not_allowed_in_preflop() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    enter_betting_fixture(&mut table, ROUND_PREFLOP, BettingRound::new(100, 100), 0);

    let mut events = vec![];
    let result = state_machine::apply_bet(&mut table, 0, 100, &mut events);
    assert!(result.is_err());
}

#[test]
fn test_apply_bet_should_use_call_raise() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    enter_betting_fixture(&mut table, ROUND_FLOP, BettingRound::new(100, 100), 0); // big_blind=100, current_bet=100
    table.seats[0].set_bet(0).unwrap(); // seat 0 还没跟注

    let mut events = vec![];
    let result = state_machine::apply_bet(&mut table, 0, 100, &mut events);
    assert!(result.is_err()); // current_bet > seat_bet，应使用 call/raise
}

#[test]
fn test_apply_addon_success() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);

    let mut events = vec![];
    let result = state_machine::apply_addon(&mut table, 0, 500, &mut events);
    assert!(result.is_ok());
    assert_eq!(table.seats[0].pending_addon(), 500);
    assert_eq!(table.seats[0].stack(), 1000); // stack 不变
    assert_eq!(
        table.seats.iter().map(Seat::pending_addon).sum::<u64>(),
        500
    );
}

#[test]
fn test_apply_addon_seat_out_of_range() {
    let mut table = dummy_table("test", 4);
    let mut events = vec![];
    let result = state_machine::apply_addon(&mut table, 4, 500, &mut events);
    assert!(result.is_err());
}

#[test]
fn test_apply_addon_not_occupied() {
    let mut table = dummy_table("test", 4);
    let mut events = vec![];
    let result = state_machine::apply_addon(&mut table, 0, 500, &mut events);
    assert!(result.is_err());
}

#[test]
fn test_apply_addon_amount_zero() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);

    let mut events = vec![];
    let result = state_machine::apply_addon(&mut table, 0, 0, &mut events);
    assert!(result.is_err());
}

#[test]
fn test_apply_rebuy_success() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);

    let mut events = vec![];
    let result = state_machine::apply_rebuy(&mut table, 0, 500, &mut events);
    assert!(result.is_ok());
    assert_eq!(table.seats[0].stack(), 1500); // stack 立即增加
    assert_eq!(table.chip_pool, 500);
    assert_eq!(table.seats.iter().map(Seat::pending_addon).sum::<u64>(), 0);
}

#[test]
fn test_apply_rebuy_seat_out_of_range() {
    let mut table = dummy_table("test", 4);
    let mut events = vec![];
    let result = state_machine::apply_rebuy(&mut table, 4, 500, &mut events);
    assert!(result.is_err());
}

#[test]
fn test_apply_rebuy_not_occupied() {
    let mut table = dummy_table("test", 4);
    let mut events = vec![];
    let result = state_machine::apply_rebuy(&mut table, 0, 500, &mut events);
    assert!(result.is_err());
}

#[test]
fn test_apply_rebuy_amount_zero() {
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);

    let mut events = vec![];
    let result = state_machine::apply_rebuy(&mut table, 0, 0, &mut events);
    assert!(result.is_err());
}

// ===========================================================================
// 8. dispatch.rs — 路由与参数校验
// ===========================================================================

use poker_l1::vm::contracts::dispatch::DispatchContext;
use poker_l1::vm::contracts::texas_poker::{
    dispatch,
    dispatch::{
        AddonArgs, BetArgs, CreateTableArgs, JoinTableArgs, LeaveTableArgs, RaiseArgs, RebuyArgs,
        SeatIndexArgs, selectors,
    },
    utils,
};

fn make_dispatch_context() -> DispatchContext {
    DispatchContext {
        // caller = [0x01;20]，与多数 addon/rebuy/下注测试里 occupy_seat 的 player 一致，
        // 使 P0-2 权限校验（caller == seat.player）天然通过。
        // join_table 测试（player=[0x11]/[0x22]）用 make_dispatch_context_as 显式传 caller。
        caller: [0x01; 20],
        caller_pubkey: TaggedPubkey {
            tag: 0,
            raw: vec![0xBB; 32],
        },
        chain_id: 1,
        block_height: 100,
        block_timestamp: 1_000_000,
    }
}

/// 构造指定 caller 的 dispatch context（P0-2 权限校验后，join/leave 等动作类
/// 方法要求 caller == seat.player，测试需用对应玩家的 context）。
fn make_dispatch_context_as(caller: Address) -> DispatchContext {
    let mut ctx = make_dispatch_context();
    ctx.caller = caller;
    ctx
}

// ========== selector 测试 ==========

#[test]
fn test_dispatch_selectors_deterministic() {
    let h1 = selectors::create_table();
    let h2 = dispatch::compute_method_selector("create_table");
    assert_eq!(h1, h2);
}

#[test]
fn test_dispatch_selectors_all_unique() {
    let sels = selectors::all();
    assert_eq!(sels.len(), 19);
    for i in 0..sels.len() {
        for j in (i + 1)..sels.len() {
            assert_ne!(sels[i], sels[j]);
        }
    }
}

// ========== create_table 参数校验 ==========

#[test]
fn test_dispatch_create_table_rejects_zero_big_blind() {
    let ctx = make_dispatch_context();
    let mut table = dummy_table("test", 4);
    let args = CreateTableArgs {
        name: "bad".into(),
        max_players: 6,
        small_blind: 50,
        big_blind: 0,
    };
    let args_bytes = borsh::to_vec(&args).unwrap();
    let result = dispatch::dispatch(&ctx, &mut table, &selectors::create_table(), &args_bytes);
    assert!(result.is_err());
}

#[test]
fn test_dispatch_create_table_rejects_small_blind_greater_than_big_blind() {
    let ctx = make_dispatch_context();
    let mut table = dummy_table("test", 4);
    let args = CreateTableArgs {
        name: "bad".into(),
        max_players: 6,
        small_blind: 100,
        big_blind: 50,
    };
    let args_bytes = borsh::to_vec(&args).unwrap();
    let result = dispatch::dispatch(&ctx, &mut table, &selectors::create_table(), &args_bytes);
    assert!(result.is_err());
}

#[test]
fn test_dispatch_create_table_rejects_max_players_too_small() {
    let ctx = make_dispatch_context();
    let mut table = dummy_table("test", 4);
    let args = CreateTableArgs {
        name: "bad".into(),
        max_players: 1,
        small_blind: 50,
        big_blind: 100,
    };
    let args_bytes = borsh::to_vec(&args).unwrap();
    let result = dispatch::dispatch(&ctx, &mut table, &selectors::create_table(), &args_bytes);
    assert!(result.is_err());
}

// ========== join_table 参数校验 ==========

#[test]
fn test_dispatch_join_table_rejects_non_waiting_state() {
    let ctx = make_dispatch_context_as([0x11; 20]);
    let mut table = dummy_table("test", 4);
    enter_betting_fixture(&mut table, ROUND_PREFLOP, BettingRound::new(100, 0), 0);

    let args = JoinTableArgs::with_key(
        [0x11; 20],
        1000,
        utils::scalar_from_u64(11),
        utils::scalar_from_u64(101),
    )
    .unwrap();
    let args_bytes = borsh::to_vec(&args).unwrap();
    let result = dispatch::dispatch(&ctx, &mut table, &selectors::join_table(), &args_bytes);
    assert!(result.is_err());
}

#[test]
fn test_dispatch_join_table_rejects_buy_in_less_than_big_blind() {
    let ctx = make_dispatch_context_as([0x11; 20]);
    let mut table = dummy_table("test", 4);
    table.big_blind = 100;

    let args = JoinTableArgs::with_key(
        [0x11; 20],
        50,
        utils::scalar_from_u64(11),
        utils::scalar_from_u64(102),
    )
    .unwrap();
    let args_bytes = borsh::to_vec(&args).unwrap();
    let result = dispatch::dispatch(&ctx, &mut table, &selectors::join_table(), &args_bytes);
    assert!(result.is_err());
}

#[test]
fn test_dispatch_join_table_rejects_duplicate_pk() {
    let ctx = make_dispatch_context_as([0x11; 20]);
    let mut table = dummy_table("test", 4);

    let args1 = JoinTableArgs::with_key(
        [0x11; 20],
        1000,
        utils::scalar_from_u64(11),
        utils::scalar_from_u64(103),
    )
    .unwrap();
    dispatch::dispatch(
        &ctx,
        &mut table,
        &selectors::join_table(),
        &borsh::to_vec(&args1).unwrap(),
    )
    .unwrap();

    let args2 = JoinTableArgs::with_key(
        [0x22; 20],
        1000,
        utils::scalar_from_u64(11),
        utils::scalar_from_u64(104),
    )
    .unwrap();
    // P0-2：args2 用 player=[0x22] 自己的 ctx，确保测的是 duplicate pk 而非权限错。
    let ctx_p2 = make_dispatch_context_as([0x22; 20]);
    let result = dispatch::dispatch(
        &ctx_p2,
        &mut table,
        &selectors::join_table(),
        &borsh::to_vec(&args2).unwrap(),
    );
    assert!(result.is_err());
}

// ========== leave_table 参数校验 ==========

#[test]
fn test_dispatch_leave_table_rejects_non_waiting_state() {
    let ctx = make_dispatch_context_as([0x11; 20]);
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x11; 20], 1000);
    enter_betting_fixture(&mut table, ROUND_PREFLOP, BettingRound::new(100, 0), 0);

    let args = LeaveTableArgs { seat_index: 0 };
    let args_bytes = borsh::to_vec(&args).unwrap();
    let result = dispatch::dispatch(&ctx, &mut table, &selectors::leave_table(), &args_bytes);
    assert!(result.is_err());
}

#[test]
fn test_dispatch_leave_table_rejects_empty_seat() {
    let ctx = make_dispatch_context_as([0x11; 20]);
    let mut table = dummy_table("test", 4);

    let args = LeaveTableArgs { seat_index: 0 };
    let args_bytes = borsh::to_vec(&args).unwrap();
    let result = dispatch::dispatch(&ctx, &mut table, &selectors::leave_table(), &args_bytes);
    assert!(result.is_err());
}

#[test]
fn test_dispatch_leave_table_rejects_invalid_seat_index() {
    let ctx = make_dispatch_context_as([0x11; 20]);
    let mut table = dummy_table("test", 4);

    let args = LeaveTableArgs { seat_index: 10 };
    let args_bytes = borsh::to_vec(&args).unwrap();
    let result = dispatch::dispatch(&ctx, &mut table, &selectors::leave_table(), &args_bytes);
    assert!(result.is_err());
}

// ========== addon/rebuy 测试 ==========

#[test]
fn test_dispatch_addon_accumulates_pending() {
    let ctx = make_dispatch_context();
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 500);

    let args = AddonArgs {
        seat_index: 0,
        amount: 1000,
    };
    let args_bytes = borsh::to_vec(&args).unwrap();
    let result = dispatch::dispatch(&ctx, &mut table, &selectors::addon(), &args_bytes);
    assert!(result.is_ok());

    assert_eq!(table.seats[0].pending_addon(), 1000);
    assert_eq!(table.seats[0].stack(), 500);
}

#[test]
fn test_dispatch_addon_rejects_invalid_seat() {
    let ctx = make_dispatch_context();
    let mut table = dummy_table("test", 4);

    let args = AddonArgs {
        seat_index: 0,
        amount: 1000,
    };
    let args_bytes = borsh::to_vec(&args).unwrap();
    let result = dispatch::dispatch(&ctx, &mut table, &selectors::addon(), &args_bytes);
    assert!(result.is_err());
}

#[test]
fn test_dispatch_rebuy_increases_stack_immediately() {
    let ctx = make_dispatch_context();
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 500);

    let args = RebuyArgs {
        seat_index: 0,
        amount: 1000,
    };
    let args_bytes = borsh::to_vec(&args).unwrap();
    let result = dispatch::dispatch(&ctx, &mut table, &selectors::rebuy(), &args_bytes);
    assert!(result.is_ok());

    assert_eq!(table.seats[0].stack(), 1500);
    assert_eq!(table.seats[0].pending_addon(), 0);
}

#[test]
fn test_dispatch_rebuy_rejects_invalid_seat() {
    let ctx = make_dispatch_context();
    let mut table = dummy_table("test", 4);

    let args = RebuyArgs {
        seat_index: 0,
        amount: 1000,
    };
    let args_bytes = borsh::to_vec(&args).unwrap();
    let result = dispatch::dispatch(&ctx, &mut table, &selectors::rebuy(), &args_bytes);
    assert!(result.is_err());
}

// ========== 下注动作路由测试 ==========

#[test]
fn test_dispatch_fold_route() {
    let ctx = make_dispatch_context();
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    occupy_seat(&mut table, 2, [0x03; 20], 1000);
    enter_betting_fixture(&mut table, ROUND_PREFLOP, BettingRound::new(100, 100), 0);

    let args = SeatIndexArgs { seat_index: 0 };
    let args_bytes = borsh::to_vec(&args).unwrap();
    let result = dispatch::dispatch(&ctx, &mut table, &selectors::fold(), &args_bytes);
    assert!(result.is_ok());
    assert!(table.seats[0].is_folded());
}

#[test]
fn test_dispatch_check_route() {
    let ctx = make_dispatch_context();
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    enter_betting_fixture(&mut table, ROUND_FLOP, BettingRound::new(100, 0), 0);

    let args = SeatIndexArgs { seat_index: 0 };
    let args_bytes = borsh::to_vec(&args).unwrap();
    let result = dispatch::dispatch(&ctx, &mut table, &selectors::check(), &args_bytes);
    assert!(result.is_ok());
}

#[test]
fn test_dispatch_call_route() {
    let ctx = make_dispatch_context();
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    enter_betting_fixture(&mut table, ROUND_PREFLOP, BettingRound::new(100, 100), 0);

    let args = SeatIndexArgs { seat_index: 0 };
    let args_bytes = borsh::to_vec(&args).unwrap();
    let result = dispatch::dispatch(&ctx, &mut table, &selectors::call(), &args_bytes);
    assert!(result.is_ok());
    assert_eq!(table.seats[0].bet(), 100);
}

#[test]
fn test_dispatch_raise_route() {
    let ctx = make_dispatch_context();
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    enter_betting_fixture(&mut table, ROUND_PREFLOP, BettingRound::new(100, 100), 0);

    let args = RaiseArgs {
        seat_index: 0,
        total_bet: 300,
    };
    let args_bytes = borsh::to_vec(&args).unwrap();
    let result = dispatch::dispatch(&ctx, &mut table, &selectors::raise(), &args_bytes);
    assert!(result.is_ok());
    assert_eq!(table.seats[0].bet(), 300);
}

#[test]
fn test_dispatch_bet_route() {
    let ctx = make_dispatch_context();
    let mut table = dummy_table("test", 4);
    occupy_seat(&mut table, 0, [0x01; 20], 1000);
    occupy_seat(&mut table, 1, [0x02; 20], 1000);
    enter_betting_fixture(&mut table, ROUND_FLOP, BettingRound::new(100, 0), 0);

    let args = BetArgs {
        seat_index: 0,
        amount: 200,
    };
    let args_bytes = borsh::to_vec(&args).unwrap();
    let result = dispatch::dispatch(&ctx, &mut table, &selectors::bet(), &args_bytes);
    assert!(result.is_ok());
    assert_eq!(table.seats[0].bet(), 200);
}

// ========== 未知方法测试 ==========

#[test]
fn test_dispatch_unknown_method() {
    let ctx = make_dispatch_context();
    let mut table = dummy_table("test", 4);
    let unknown_selector = [0xFE; 32];
    let result = dispatch::dispatch(&ctx, &mut table, &unknown_selector, &[]);
    assert!(matches!(
        result,
        Err(poker_l1::error::PokerL1Error::UnknownContractMethod { .. })
    ));
}

// ========== dispatch.rs 补充边缘场景 ==========

#[test]
fn test_dispatch_create_table_max_players_at_limit() {
    let ctx = make_dispatch_context();
    let mut table = dummy_table("test", 9); // MAX_PLAYERS = 9
    let args = CreateTableArgs {
        name: "ok".into(),
        max_players: 9,
        small_blind: 50,
        big_blind: 100,
    };
    let args_bytes = borsh::to_vec(&args).unwrap();
    let result = dispatch::dispatch(&ctx, &mut table, &selectors::create_table(), &args_bytes);
    // max_players = MAX_PLAYERS 应该可以
    assert!(result.is_ok());
}

#[test]
fn test_dispatch_create_table_max_players_over_limit() {
    let ctx = make_dispatch_context();
    let mut table = dummy_table("test", 9);
    let args = CreateTableArgs {
        name: "bad".into(),
        max_players: 10,
        small_blind: 50,
        big_blind: 100,
    };
    let args_bytes = borsh::to_vec(&args).unwrap();
    let result = dispatch::dispatch(&ctx, &mut table, &selectors::create_table(), &args_bytes);
    assert!(result.is_err());
}

#[test]
fn test_dispatch_advance_deadline_uses_consensus_timestamp_without_payload() {
    let ctx = make_dispatch_context();
    let mut table = dummy_table("test", 4);
    let result = dispatch::dispatch(&ctx, &mut table, &selectors::advance_deadline(), &[]);
    assert!(result.is_ok());
}

#[test]
fn test_dispatch_join_table_rejects_seat_full() {
    let ctx = make_dispatch_context_as([0x11; 20]);
    let mut table = dummy_table("test", 2); // 只有2个座位

    // 加入第一个玩家
    let args1 = JoinTableArgs::with_key(
        [0x11; 20],
        1000,
        utils::scalar_from_u64(1),
        utils::scalar_from_u64(201),
    )
    .unwrap();
    dispatch::dispatch(
        &ctx,
        &mut table,
        &selectors::join_table(),
        &borsh::to_vec(&args1).unwrap(),
    )
    .unwrap();

    // 加入第二个玩家（P0-2：须用 player=[0x22] 自己的 ctx）
    let args2 = JoinTableArgs::with_key(
        [0x22; 20],
        1000,
        utils::scalar_from_u64(2),
        utils::scalar_from_u64(202),
    )
    .unwrap();
    let ctx_p2 = make_dispatch_context_as([0x22; 20]);
    dispatch::dispatch(
        &ctx_p2,
        &mut table,
        &selectors::join_table(),
        &borsh::to_vec(&args2).unwrap(),
    )
    .unwrap();

    // 加入第三个玩家（满员）
    let args3 = JoinTableArgs::with_key(
        [0x33; 20],
        1000,
        utils::scalar_from_u64(3),
        utils::scalar_from_u64(203),
    )
    .unwrap();
    let ctx_p3 = make_dispatch_context_as([0x33; 20]);
    let result = dispatch::dispatch(
        &ctx_p3,
        &mut table,
        &selectors::join_table(),
        &borsh::to_vec(&args3).unwrap(),
    );
    assert!(result.is_err());
}

// ===========================================================================
// 9. types.rs — 数据类型与状态
// ===========================================================================

#[test]
fn test_seat_empty_default() {
    let seat = Seat::empty();
    assert!(!seat.is_occupied());
    assert_eq!(seat.status(), SeatStatus::Empty);
    assert_eq!(seat.stack(), 0);
    assert_eq!(seat.bet(), 0);
    assert_eq!(seat.total_bet(), 0);
    assert!(!seat.is_folded());
    assert!(!seat.is_all_in());
}

#[test]
fn test_seat_status_active() {
    let seat = Seat::occupied(
        [0x01; 20],
        1000,
        ECPoint(G1Projective::generator()),
        SeatStatus::Active,
    )
    .unwrap();
    assert_eq!(seat.status(), SeatStatus::Active);
    assert!(seat.is_occupied());
    assert_eq!(seat.stack(), 1000);
}

#[test]
fn test_seat_status_folded() {
    let mut seat = Seat::occupied(
        [0x01; 20],
        1000,
        ECPoint(G1Projective::generator()),
        SeatStatus::Active,
    )
    .unwrap();
    seat.set_status(SeatStatus::Folded);
    assert_eq!(seat.status(), SeatStatus::Folded);
}

#[test]
fn test_seat_status_all_in() {
    let mut seat = Seat::occupied(
        [0x01; 20],
        0,
        ECPoint(G1Projective::generator()),
        SeatStatus::Active,
    )
    .unwrap();
    seat.set_status(SeatStatus::AllIn);
    assert_eq!(seat.status(), SeatStatus::AllIn);
}

#[test]
fn test_seat_status_waiting() {
    let seat = Seat::occupied(
        [0x01; 20],
        1000,
        ECPoint(G1Projective::generator()),
        SeatStatus::Waiting,
    )
    .unwrap();
    assert_eq!(seat.status(), SeatStatus::Waiting);
    // is_waiting 的座位仍算 occupied（有玩家但等下一局）
    assert!(seat.is_occupied());
}

#[test]
fn test_seat_status_left_during_hand() {
    let mut seat = Seat::occupied(
        [0x01; 20],
        1000,
        ECPoint(G1Projective::generator()),
        SeatStatus::Active,
    )
    .unwrap();
    seat.set_status(SeatStatus::Out);
    assert_eq!(seat.status(), SeatStatus::Out);
    assert!(!seat.is_occupied());
    assert!(seat.has_left_hand());
    assert_eq!(seat.player(), [0x01; 20]);
}

#[test]
fn test_seat_status_is_mutually_exclusive() {
    let mut seat = Seat::occupied(
        [0x01; 20],
        1000,
        ECPoint(G1Projective::generator()),
        SeatStatus::Active,
    )
    .unwrap();
    seat.set_status(SeatStatus::Folded);
    assert_eq!(seat.status(), SeatStatus::Folded);
    assert!(seat.is_folded());
    assert!(!seat.is_all_in());
    assert!(!seat.is_waiting());
}

#[test]
fn test_seat_borsh_roundtrip() {
    let mut seat = Seat::occupied(
        [0xAB; 20],
        5000,
        ECPoint(G1Projective::generator()),
        SeatStatus::Active,
    )
    .unwrap();
    seat.set_status(SeatStatus::Folded);

    let bytes = borsh::to_vec(&seat).unwrap();
    let decoded: Seat = borsh::from_slice(&bytes).unwrap();
    assert_eq!(decoded.player(), seat.player());
    assert_eq!(decoded.stack(), seat.stack());
    assert_eq!(decoded.status(), seat.status());
}

// ===========================================================================
// 10. utils.rs — 工具函数
// ===========================================================================

#[test]
fn test_utils_g1_generator_not_identity() {
    let g = utils::g1_generator();
    assert!(!utils::g1_is_identity(&g));
}

#[test]
fn test_utils_g1_identity_is_identity() {
    let id = utils::g1_identity();
    assert!(utils::g1_is_identity(&id));
}

#[test]
fn test_utils_g1_add_sub_inverse() {
    let g = utils::g1_generator();
    let g2 = utils::g1_add(&g, &g);
    let result = utils::g1_sub(&g2, &g);
    assert!(utils::g1_equal(&result, &g));
}

#[test]
fn test_utils_scalar_add_commutative() {
    let a = utils::scalar_from_u64(42);
    let b = utils::scalar_from_u64(100);
    let sum1 = utils::scalar_add(&a, &b);
    let sum2 = utils::scalar_add(&b, &a);
    assert!(bool::from(sum1 == sum2));
}

#[test]
fn test_utils_scalar_from_u64() {
    let s = utils::scalar_from_u64(42);
    let expected = utils::scalar_add(&utils::scalar_one(), &utils::scalar_from_u64(41));
    assert!(bool::from(s == expected));
}

#[test]
fn test_utils_u64_to_ascii() {
    assert_eq!(utils::u64_to_ascii(0), b"0");
    assert_eq!(utils::u64_to_ascii(42), b"42");
    assert_eq!(utils::u64_to_ascii(12345), b"12345");
    assert_eq!(
        utils::u64_to_ascii(u64::MAX / 1000),
        (u64::MAX / 1000).to_string().as_bytes()
    );
}

#[test]
fn test_utils_generate_plaintext_cards_count() {
    let cards = utils::generate_plaintext_cards();
    assert_eq!(cards.len(), 52);
}

#[test]
fn test_utils_hash_to_scalar_deterministic() {
    let data = b"test data";
    let h1 = utils::hash_to_scalar(data).unwrap();
    let h2 = utils::hash_to_scalar(data).unwrap();
    assert!(bool::from(h1 == h2));
}

#[test]
fn test_utils_hash_to_g1_deterministic() {
    let msg = b"test message";
    let p1 = utils::hash_to_g1(msg);
    let p2 = utils::hash_to_g1(msg);
    assert!(utils::g1_equal(&p1, &p2));
}

#[test]
fn test_utils_encrypt_decrypt_roundtrip() {
    let sk = utils::scalar_from_u64(123);
    let pk_computed = utils::g1_mul(&sk, &utils::g1_generator());
    let plaintext = utils::hash_to_g1(b"plaintext");
    let r = utils::scalar_from_u64(456);

    let ct = utils::encrypt(&plaintext, &pk_computed, &r);
    let decrypted = utils::decrypt(&ct, &sk);
    assert!(utils::g1_equal(&decrypted, &plaintext));
}

#[test]
fn test_utils_extract_c1s_c2s() {
    let pk = utils::g1_generator();
    let r = utils::scalar_from_u64(1);
    let p1 = utils::hash_to_g1(b"card1");
    let p2 = utils::hash_to_g1(b"card2");

    let cts = vec![utils::encrypt(&p1, &pk, &r), utils::encrypt(&p2, &pk, &r)];

    let c1s = utils::extract_c1s(&cts);
    let c2s = utils::extract_c2s(&cts);
    assert_eq!(c1s.len(), 2);
    assert_eq!(c2s.len(), 2);
}

// ===========================================================================
// 11. constants.rs — 常量验证
// ===========================================================================

#[test]
fn test_constants_round_order() {
    // 验证轮次顺序
    assert!(ROUND_WAITING < ROUND_PREFLOP);
    assert!(ROUND_PREFLOP < ROUND_FLOP);
    assert!(ROUND_FLOP < ROUND_TURN);
    assert!(ROUND_TURN < ROUND_RIVER);
    assert!(ROUND_RIVER < ROUND_SHOWDOWN);
}

#[test]
fn test_constants_action_flags_unique() {
    // 验证 action flag 使用不同的 bit
    assert_eq!(ACTION_FOLD, 1);
    assert_eq!(ACTION_CHECK, 2);
    assert_eq!(ACTION_CALL, 4);
    assert_eq!(ACTION_RAISE, 8);
    // 每个 flag 都是唯一的 bit
    assert!(ACTION_FOLD & ACTION_CHECK == 0);
    assert!(ACTION_FOLD & ACTION_CALL == 0);
    assert!(ACTION_FOLD & ACTION_RAISE == 0);
    assert!(ACTION_CHECK & ACTION_CALL == 0);
    assert!(ACTION_CHECK & ACTION_RAISE == 0);
    assert!(ACTION_CALL & ACTION_RAISE == 0);
}

#[test]
fn test_constants_min_players_constraint() {
    assert!(MIN_PLAYERS_TO_START >= 2);
    assert!(MIN_PLAYERS_TO_START <= MAX_PLAYERS);
}

#[test]
fn test_constants_max_total_bet_positive() {
    assert!(MAX_TOTAL_BET > 0);
}

// ===========================================================================
// 12. events.rs — 事件类型
// ===========================================================================

#[test]
fn test_event_serde_roundtrip() {
    use serde_json;
    let event = TexasPokerEvent::PlayerJoined {
        table_id: poker_l1::object_model::ObjectID::new([0xFF; 20], 0),
        seat_index: 0,
        player: [0x01; 20],
        buy_in: 1000,
        is_waiting: false,
        active_count_after: 1,
    };
    let json = serde_json::to_string(&event).unwrap();
    let decoded: TexasPokerEvent = serde_json::from_str(&json).unwrap();
    match (&event, &decoded) {
        (
            TexasPokerEvent::PlayerJoined { buy_in: b1, .. },
            TexasPokerEvent::PlayerJoined { buy_in: b2, .. },
        ) => {
            assert_eq!(b1, b2);
        }
        _ => panic!("event type mismatch"),
    }
}
