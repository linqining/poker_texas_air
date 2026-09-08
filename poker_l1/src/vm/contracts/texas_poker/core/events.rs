//! Texas Poker 事件定义（移植自 `texas_poker_move/sources/table_events.move`）。
//!
//! 将所有 40+ 种事件统一为 `TexasPokerEvent` 枚举，Borsh 序列化后由预编译合约
//! 通过 `emit_event` syscall 写入事件日志（链下索引）。
//!
//! 事件分类（与 Move 端一致）：
//! 1. 牌桌生命周期：TableCreated / PlayerJoined / PlayerLeft / LeaveRequested
//! 2. 手牌生命周期：HandStarted / BlindsPosted / BettingRoundStarted / RoundAdvanced /
//!    PotCollected / WinnerAwarded / HandSettled / HandEndedWithoutShowdown / HandReset
//! 3. 下注操作：PlayerFolded / PlayerChecked / PlayerCalled / PlayerRaised / PlayerAllIn
//! 4. 洗牌协议：ShuffleVerified / ShuffleTurn / ShuffleComplete / ShuffleTimeout
//! 5. 揭示协议：RevealPhase / RevealTokenSubmitted / RevealPhaseComplete / RevealTimeout /
//!    CardIsIdentity / IdentityRedeal / RedealRequested / CommunityCardRevealed /
//!    ShowdownHoleCardsRevealed
//! 6. 重构协议：ReconstructInitiated / ReconstructDeckSubmitted / ReconstructComplete /
//!    ReconstructTimeout
//! 7. 玩家管理：PlayerKicked / PlayerRefund
//! 8. 配置与牌组重建：TimeoutConfigUpdated / DeckRebuilt / CurrentTurnChanged

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::Address;
use crate::object_model::ObjectID;

// ========== 退款类型常量 ==========
pub const REFUND_TYPE_STACK_ONLY: u8 = 0;
pub const REFUND_TYPE_STACK_AND_BET: u8 = 1;
pub const REFUND_TYPE_BET_ONLY: u8 = 2;

/// Canonical source of a player removal.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum KickCause {
    /// A protocol deadline expired.
    Timeout = 0,
    /// The table administrator explicitly removed the player.
    Admin = 1,
    /// Reconstruction did not complete before its deadline.
    ReconstructTimeout = 2,
}

// ========== 重置原因常量 ==========
pub const RESET_REASON_TIMEOUT: u8 = 0;
pub const RESET_REASON_KICK: u8 = 1;
pub const RESET_REASON_RECONSTRUCT_FAIL: u8 = 2;
pub const RESET_REASON_LAST_PLAYER_STANDING: u8 = 3;
pub const RESET_REASON_STATE_INCONSISTENT: u8 = 4;

// ========== 弃牌原因常量 ==========
pub const FOLD_REASON_MANUAL: u8 = 0;
pub const FOLD_REASON_AUTO_TIMEOUT: u8 = 1;
pub const FOLD_REASON_FORCE_ADMIN: u8 = 2;

// ========== 牌组重建原因常量 ==========
pub const DECK_REBUILT_REASON_SHUFFLE_TIMEOUT: u8 = 0;
pub const DECK_REBUILT_REASON_RECONSTRUCT_COMPLETE: u8 = 1;

// ========== 触发动作常量（PlayerAllIn）==========
pub const TRIGGER_ACTION_CALL_ALL_IN: u8 = 0;
pub const TRIGGER_ACTION_RAISE_ALL_IN: u8 = 1;

// ========== pot_type 常量（WinnerAwarded）==========
pub const POT_TYPE_MAIN: u8 = 0;
pub const POT_TYPE_SIDE: u8 = 1;

/// Texas Poker 事件枚举（所有变体 copy + drop，Borsh 友好）。
///
/// 镜像 `table_events.move` 的所有 struct，统一为 enum 便于在
/// `dispatch` 阶段收集 `Vec<TexasPokerEvent>` 后批量 emit。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum TexasPokerEvent {
    // ========== 1. 牌桌生命周期 ==========
    TableCreated {
        table_id: ObjectID,
        name: String,
    },
    PlayerJoined {
        table_id: ObjectID,
        seat_index: u8,
        player: Address,
        buy_in: u64,
        is_waiting: bool,
        active_count_after: u64,
    },
    PlayerLeft {
        table_id: ObjectID,
        seat_index: u8,
        player: Address,
    },
    /// 玩家显式设置「本手结束后离场」意图。
    ///
    /// 由 `set_leave_after_hand` 方法在标志实际变化时发出。
    /// 实际离场（退款 + 座位清空）在下一手 `reset_for_next_hand` 时触发，
    /// 届时另发 `PlayerRefund` + `PlayerLeft`。
    LeaveRequested {
        table_id: ObjectID,
        seat_index: u8,
        player: Address,
        /// 显式目标值（true=已预约下局离场，false=取消预约）。
        want_leave: bool,
    },

    // ========== 2. 手牌生命周期 ==========
    HandStarted {
        table_id: ObjectID,
        button: u8,
        small_blind: u64,
        big_blind: u64,
        participants: Vec<u8>,
    },
    BlindsPosted {
        table_id: ObjectID,
        sb_seat: u8,
        bb_seat: u8,
        sb_amount: u64,
        bb_amount: u64,
        first_to_act: u8,
    },
    BettingRoundStarted {
        table_id: ObjectID,
        round_state: u8,
        current_bet: u64,
        min_raise: u64,
        first_to_act: u8,
        pot_before: u64,
    },
    RoundAdvanced {
        table_id: ObjectID,
        from_round: u8,
        to_round: u8,
        pot: u64,
        community_cards_count: u64,
    },
    PotCollected {
        table_id: ObjectID,
        round_state: u8,
        pot_after: u64,
        collected_from_seats: Vec<u8>,
    },
    WinnerAwarded {
        table_id: ObjectID,
        seat_index: u8,
        player: Address,
        amount: u64,
        /// 0=main_pot, 1=side_pot
        pot_type: u8,
        /// 最佳牌型（None=无摊牌直接获胜）
        hand_rank: Option<u8>,
    },
    HandSettled {
        table_id: ObjectID,
        pot: u64,
        winners: Vec<u8>,
    },
    HandEndedWithoutShowdown {
        table_id: ObjectID,
        winner_seat: u8,
        winner_player: Address,
        pot: u64,
    },
    HandReset {
        table_id: ObjectID,
        reason: u8,
        round_state: u8,
    },

    // ========== 3. 下注操作 ==========
    PlayerFolded {
        table_id: ObjectID,
        seat_index: u8,
        /// 0=manual, 1=auto_timeout, 2=force_admin
        reason: u8,
        round_state: u8,
    },
    PlayerChecked {
        table_id: ObjectID,
        seat_index: u8,
        round_state: u8,
    },
    PlayerCalled {
        table_id: ObjectID,
        seat_index: u8,
        call_delta: u64,
        round_state: u8,
    },
    PlayerRaised {
        table_id: ObjectID,
        seat_index: u8,
        raise_delta: u64,
        total_bet: u64,
        round_state: u8,
    },
    PlayerAllIn {
        table_id: ObjectID,
        seat_index: u8,
        /// 0=call_all_in, 1=raise_all_in
        trigger_action: u8,
        amount: u64,
        round_state: u8,
    },

    // ========== 4. 洗牌协议 ==========
    ShuffleVerified {
        table_id: ObjectID,
        seat_index: u8,
        player: Address,
    },
    ShuffleTurn {
        table_id: ObjectID,
        seat_index: u8,
        pending_count: u64,
        completed_count: u64,
    },
    ShuffleComplete {
        table_id: ObjectID,
        phase: u8,
        participant_count: u64,
        deck_size: u64,
    },
    ShuffleTimeout {
        table_id: ObjectID,
        seat_index: u8,
        phase: u8,
        started_at: u64,
        timeout_ms: u64,
    },

    // ========== 5. 揭示协议 ==========
    RevealPhase {
        table_id: ObjectID,
        phase: u8,
    },
    RevealTokenSubmitted {
        table_id: ObjectID,
        seat_index: u8,
        card_index: u8,
        phase: u8,
    },
    RevealPhaseComplete {
        table_id: ObjectID,
        phase: u8,
    },
    RevealTimeout {
        table_id: ObjectID,
        phase: u8,
        pending_players: Vec<u8>,
    },
    CardIsIdentity {
        table_id: ObjectID,
        card_index: u8,
        assignment_index: u8,
        phase: u8,
    },
    IdentityRedeal {
        table_id: ObjectID,
        identity_card_indices: Vec<u8>,
        redeal_count: u64,
        phase: u8,
    },
    RedealRequested {
        table_id: ObjectID,
        seat_index: u8,
        card_indices: Vec<u8>,
    },
    CommunityCardRevealed {
        table_id: ObjectID,
        phase: u8,
        card_indices: Vec<u8>,
        card_ranks: Vec<u8>,
        card_suits: Vec<u8>,
    },
    ShowdownHoleCardsRevealed {
        table_id: ObjectID,
        seat_index: u8,
        player: Address,
        card_indices: Vec<u8>,
        card_ranks: Vec<u8>,
        card_suits: Vec<u8>,
    },

    // ========== 6. 重构协议 ==========
    ReconstructInitiated {
        table_id: ObjectID,
        expected_players: Vec<u8>,
        round_state: u8,
    },
    ReconstructDeckSubmitted {
        table_id: ObjectID,
        seat_index: u8,
    },
    ReconstructComplete {
        table_id: ObjectID,
    },
    ReconstructTimeout {
        table_id: ObjectID,
        pending_players: Vec<u8>,
    },

    // ========== 7. 玩家管理 ==========
    PlayerKicked {
        table_id: ObjectID,
        seat_index: u8,
        player: Address,
        reason: KickCause,
    },
    PlayerRefund {
        table_id: ObjectID,
        seat_index: u8,
        player: Address,
        amount: u64,
        refund_type: u8,
    },

    // ========== 8. 配置与牌组重建 ==========
    TimeoutConfigUpdated {
        table_id: ObjectID,
        betting_timeout_ms: u64,
        shuffle_timeout_ms: u64,
        reveal_timeout_ms: u64,
        reconstruct_timeout_ms: u64,
        showdown_display_ms: u64,
    },
    DeckRebuilt {
        table_id: ObjectID,
        reason: u8,
        deck_size: u64,
    },
    CurrentTurnChanged {
        table_id: ObjectID,
        old_turn: Option<u8>,
        new_turn: Option<u8>,
        round_state: u8,
    },

    // ========== 9. Addon / Rebuy ==========
    /// 玩家发起 addon（下一手生效）。
    AddonRequested {
        table_id: ObjectID,
        seat_index: u8,
        player: Address,
        amount: u64,
        pending_after: u64,
    },
    /// addon 在 `reset_for_next_hand` 合并到 stack 时触发。
    AddonCredited {
        table_id: ObjectID,
        seat_index: u8,
        player: Address,
        amount: u64,
        stack_after: u64,
    },
    /// 玩家 rebuy（立即生效，仅 MTT 早期/特殊规则）。
    RebuyProcessed {
        table_id: ObjectID,
        seat_index: u8,
        player: Address,
        amount: u64,
        stack_after: u64,
    },

    // ========== 10. Bet 动作 ==========
    /// 玩家主动下注（postflop 第一个下注者）。
    PlayerBet {
        table_id: ObjectID,
        seat_index: u8,
        amount: u64,
        round_state: u8,
    },

    // ========== 11. Time Bank ==========
    /// 玩家 Time Bank 被消耗（超时续命）。
    TimeBankConsumed {
        table_id: ObjectID,
        seat_index: u8,
        consumed_ms: u64,
        remaining_ms: u64,
    },

    // ========== 12. Ante ==========
    /// Ante 被投注（start_hand 时）。
    AntePosted {
        table_id: ObjectID,
        seat_index: u8,
        amount: u64,
        ante_mode: u8,
    },

    // ========== 13. Rake ==========
    /// Rake 被抽水（settle 时）。
    RakeCollected {
        table_id: ObjectID,
        pot_before: u64,
        rake_amount: u64,
        pot_after: u64,
        rake_mode: u8,
    },

    // ========== 14. Run It Twice ==========
    /// Run It Twice 被触发（all-in 后）。
    RunItTwiceTriggered {
        table_id: ObjectID,
        board1_cards: u8, // 牌数
        board2_cards: u8,
    },

    // ========== 15. Canonical settlement plan ==========
    /// The state machine derived and atomically applied a canonical settlement plan.
    ///
    /// The digest commits to every pot layer, runout amount, eligible/winner mask, hand rank,
    /// per-seat award, rake allocation, and odd-chip decision.
    SettlementPlanCommitted {
        /// Settled table.
        table_id: ObjectID,
        /// Domain-separated digest of the canonical Borsh settlement plan v2.
        plan_digest: [u8; 32],
        /// Number of independent runouts (`1` or `2`).
        runout_count: u8,
        /// Total wager amount before rake.
        gross_pot: u64,
        /// Total rake removed from table custody.
        rake: u64,
        /// Total amount awarded to seats.
        total_awards: u64,
    },
}

/// 将事件追加到事件日志（链下索引友好）。
///
/// 镜像 Move `event::emit(...)`：仅追加，不返回值。
/// 调用方在 `dispatch` 中收集所有事件后，由 Precompile::call 批量 emit。
pub fn emit_event(events: &mut Vec<TexasPokerEvent>, evt: TexasPokerEvent) {
    events.push(evt);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_table_id() -> ObjectID {
        ObjectID::new([0xFF; 20], 0)
    }

    #[test]
    fn test_event_borsh_roundtrip_table_created() {
        let evt = TexasPokerEvent::TableCreated {
            table_id: dummy_table_id(),
            name: "test-table".to_string(),
        };
        let bytes = borsh::to_vec(&evt).unwrap();
        let recovered: TexasPokerEvent = borsh::from_slice(&bytes).unwrap();
        assert_eq!(evt, recovered);
    }

    #[test]
    fn test_event_borsh_roundtrip_player_joined() {
        let evt = TexasPokerEvent::PlayerJoined {
            table_id: dummy_table_id(),
            seat_index: 3,
            player: [0xAB; 20],
            buy_in: 1_000_000,
            is_waiting: false,
            active_count_after: 4,
        };
        let bytes = borsh::to_vec(&evt).unwrap();
        let recovered: TexasPokerEvent = borsh::from_slice(&bytes).unwrap();
        assert_eq!(evt, recovered);
    }

    #[test]
    fn test_event_borsh_roundtrip_hand_started() {
        let evt = TexasPokerEvent::HandStarted {
            table_id: dummy_table_id(),
            button: 0,
            small_blind: 50,
            big_blind: 100,
            participants: vec![0, 1, 2, 3],
        };
        let bytes = borsh::to_vec(&evt).unwrap();
        let recovered: TexasPokerEvent = borsh::from_slice(&bytes).unwrap();
        assert_eq!(evt, recovered);
    }

    #[test]
    fn test_event_borsh_roundtrip_community_card_revealed() {
        let evt = TexasPokerEvent::CommunityCardRevealed {
            table_id: dummy_table_id(),
            phase: 3, // flop
            card_indices: vec![0, 1, 2],
            card_ranks: vec![14, 13, 7], // A, K, 7
            card_suits: vec![0, 1, 2],   // spade, heart, diamond
        };
        let bytes = borsh::to_vec(&evt).unwrap();
        let recovered: TexasPokerEvent = borsh::from_slice(&bytes).unwrap();
        assert_eq!(evt, recovered);
    }

    #[test]
    fn test_event_borsh_roundtrip_current_turn_changed() {
        let evt = TexasPokerEvent::CurrentTurnChanged {
            table_id: dummy_table_id(),
            old_turn: Some(0),
            new_turn: Some(1),
            round_state: 2, // preflop
        };
        let bytes = borsh::to_vec(&evt).unwrap();
        let recovered: TexasPokerEvent = borsh::from_slice(&bytes).unwrap();
        assert_eq!(evt, recovered);
    }

    #[test]
    fn test_event_borsh_roundtrip_current_turn_changed_none() {
        let evt = TexasPokerEvent::CurrentTurnChanged {
            table_id: dummy_table_id(),
            old_turn: Some(2),
            new_turn: None,
            round_state: 6, // showdown
        };
        let bytes = borsh::to_vec(&evt).unwrap();
        let recovered: TexasPokerEvent = borsh::from_slice(&bytes).unwrap();
        assert_eq!(evt, recovered);
    }

    #[test]
    fn test_emit_event_appends() {
        let mut events: Vec<TexasPokerEvent> = vec![];
        emit_event(
            &mut events,
            TexasPokerEvent::TableCreated {
                table_id: dummy_table_id(),
                name: "t1".to_string(),
            },
        );
        emit_event(
            &mut events,
            TexasPokerEvent::PlayerJoined {
                table_id: dummy_table_id(),
                seat_index: 0,
                player: [0; 20],
                buy_in: 1000,
                is_waiting: false,
                active_count_after: 1,
            },
        );
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0], TexasPokerEvent::TableCreated { .. }));
        assert!(matches!(events[1], TexasPokerEvent::PlayerJoined { .. }));
    }

    #[test]
    fn test_constants_match_move() {
        // 验证常量值与 Move 端一致
        assert_eq!(REFUND_TYPE_STACK_ONLY, 0);
        assert_eq!(REFUND_TYPE_STACK_AND_BET, 1);
        assert_eq!(REFUND_TYPE_BET_ONLY, 2);

        assert_eq!(KickCause::Timeout as u8, 0);
        assert_eq!(KickCause::Admin as u8, 1);
        assert_eq!(KickCause::ReconstructTimeout as u8, 2);

        assert_eq!(RESET_REASON_TIMEOUT, 0);
        assert_eq!(RESET_REASON_KICK, 1);
        assert_eq!(RESET_REASON_RECONSTRUCT_FAIL, 2);
        assert_eq!(RESET_REASON_LAST_PLAYER_STANDING, 3);
        assert_eq!(RESET_REASON_STATE_INCONSISTENT, 4);

        assert_eq!(FOLD_REASON_MANUAL, 0);
        assert_eq!(FOLD_REASON_AUTO_TIMEOUT, 1);
        assert_eq!(FOLD_REASON_FORCE_ADMIN, 2);

        assert_eq!(DECK_REBUILT_REASON_SHUFFLE_TIMEOUT, 0);
        assert_eq!(DECK_REBUILT_REASON_RECONSTRUCT_COMPLETE, 1);

        assert_eq!(TRIGGER_ACTION_CALL_ALL_IN, 0);
        assert_eq!(TRIGGER_ACTION_RAISE_ALL_IN, 1);

        assert_eq!(POT_TYPE_MAIN, 0);
        assert_eq!(POT_TYPE_SIDE, 1);
    }

    #[test]
    fn test_all_variants_borsh_serializable() {
        // 烟雾测试：枚举每个分支的 Borsh 序列化至少不 panic。
        // 覆盖所有 40 个变体，确保 derive(Serialize, Deserialize) 正确。
        let table_id = dummy_table_id();
        let samples: Vec<TexasPokerEvent> = vec![
            TexasPokerEvent::TableCreated {
                table_id,
                name: "x".into(),
            },
            TexasPokerEvent::PlayerJoined {
                table_id,
                seat_index: 0,
                player: [0; 20],
                buy_in: 0,
                is_waiting: false,
                active_count_after: 0,
            },
            TexasPokerEvent::PlayerLeft {
                table_id,
                seat_index: 0,
                player: [0; 20],
            },
            TexasPokerEvent::LeaveRequested {
                table_id,
                seat_index: 0,
                player: [0; 20],
                want_leave: true,
            },
            TexasPokerEvent::HandStarted {
                table_id,
                button: 0,
                small_blind: 0,
                big_blind: 0,
                participants: vec![],
            },
            TexasPokerEvent::BlindsPosted {
                table_id,
                sb_seat: 0,
                bb_seat: 1,
                sb_amount: 0,
                bb_amount: 0,
                first_to_act: 0,
            },
            TexasPokerEvent::BettingRoundStarted {
                table_id,
                round_state: 0,
                current_bet: 0,
                min_raise: 0,
                first_to_act: 0,
                pot_before: 0,
            },
            TexasPokerEvent::RoundAdvanced {
                table_id,
                from_round: 0,
                to_round: 0,
                pot: 0,
                community_cards_count: 0,
            },
            TexasPokerEvent::PotCollected {
                table_id,
                round_state: 0,
                pot_after: 0,
                collected_from_seats: vec![],
            },
            TexasPokerEvent::WinnerAwarded {
                table_id,
                seat_index: 0,
                player: [0; 20],
                amount: 0,
                pot_type: 0,
                hand_rank: None,
            },
            TexasPokerEvent::HandSettled {
                table_id,
                pot: 0,
                winners: vec![],
            },
            TexasPokerEvent::HandEndedWithoutShowdown {
                table_id,
                winner_seat: 0,
                winner_player: [0; 20],
                pot: 0,
            },
            TexasPokerEvent::HandReset {
                table_id,
                reason: 0,
                round_state: 0,
            },
            TexasPokerEvent::PlayerFolded {
                table_id,
                seat_index: 0,
                reason: 0,
                round_state: 0,
            },
            TexasPokerEvent::PlayerChecked {
                table_id,
                seat_index: 0,
                round_state: 0,
            },
            TexasPokerEvent::PlayerCalled {
                table_id,
                seat_index: 0,
                call_delta: 0,
                round_state: 0,
            },
            TexasPokerEvent::PlayerRaised {
                table_id,
                seat_index: 0,
                raise_delta: 0,
                total_bet: 0,
                round_state: 0,
            },
            TexasPokerEvent::PlayerAllIn {
                table_id,
                seat_index: 0,
                trigger_action: 0,
                amount: 0,
                round_state: 0,
            },
            TexasPokerEvent::ShuffleVerified {
                table_id,
                seat_index: 0,
                player: [0; 20],
            },
            TexasPokerEvent::ShuffleTurn {
                table_id,
                seat_index: 0,
                pending_count: 0,
                completed_count: 0,
            },
            TexasPokerEvent::ShuffleComplete {
                table_id,
                phase: 0,
                participant_count: 0,
                deck_size: 0,
            },
            TexasPokerEvent::ShuffleTimeout {
                table_id,
                seat_index: 0,
                phase: 0,
                started_at: 0,
                timeout_ms: 0,
            },
            TexasPokerEvent::RevealPhase { table_id, phase: 0 },
            TexasPokerEvent::RevealTokenSubmitted {
                table_id,
                seat_index: 0,
                card_index: 0,
                phase: 0,
            },
            TexasPokerEvent::RevealPhaseComplete { table_id, phase: 0 },
            TexasPokerEvent::RevealTimeout {
                table_id,
                phase: 0,
                pending_players: vec![],
            },
            TexasPokerEvent::CardIsIdentity {
                table_id,
                card_index: 0,
                assignment_index: 0,
                phase: 0,
            },
            TexasPokerEvent::IdentityRedeal {
                table_id,
                identity_card_indices: vec![],
                redeal_count: 0,
                phase: 0,
            },
            TexasPokerEvent::RedealRequested {
                table_id,
                seat_index: 0,
                card_indices: vec![],
            },
            TexasPokerEvent::CommunityCardRevealed {
                table_id,
                phase: 0,
                card_indices: vec![],
                card_ranks: vec![],
                card_suits: vec![],
            },
            TexasPokerEvent::ShowdownHoleCardsRevealed {
                table_id,
                seat_index: 0,
                player: [0; 20],
                card_indices: vec![],
                card_ranks: vec![],
                card_suits: vec![],
            },
            TexasPokerEvent::ReconstructInitiated {
                table_id,
                expected_players: vec![],
                round_state: 0,
            },
            TexasPokerEvent::ReconstructDeckSubmitted {
                table_id,
                seat_index: 0,
            },
            TexasPokerEvent::ReconstructComplete { table_id },
            TexasPokerEvent::ReconstructTimeout {
                table_id,
                pending_players: vec![],
            },
            TexasPokerEvent::PlayerKicked {
                table_id,
                seat_index: 0,
                player: [0; 20],
                reason: KickCause::Timeout,
            },
            TexasPokerEvent::PlayerRefund {
                table_id,
                seat_index: 0,
                player: [0; 20],
                amount: 0,
                refund_type: 0,
            },
            TexasPokerEvent::TimeoutConfigUpdated {
                table_id,
                betting_timeout_ms: 0,
                shuffle_timeout_ms: 0,
                reveal_timeout_ms: 0,
                reconstruct_timeout_ms: 0,
                showdown_display_ms: 0,
            },
            TexasPokerEvent::DeckRebuilt {
                table_id,
                reason: 0,
                deck_size: 0,
            },
            TexasPokerEvent::CurrentTurnChanged {
                table_id,
                old_turn: None,
                new_turn: None,
                round_state: 0,
            },
            TexasPokerEvent::AddonRequested {
                table_id,
                seat_index: 0,
                player: [0; 20],
                amount: 0,
                pending_after: 0,
            },
            TexasPokerEvent::AddonCredited {
                table_id,
                seat_index: 0,
                player: [0; 20],
                amount: 0,
                stack_after: 0,
            },
            TexasPokerEvent::RebuyProcessed {
                table_id,
                seat_index: 0,
                player: [0; 20],
                amount: 0,
                stack_after: 0,
            },
            TexasPokerEvent::PlayerBet {
                table_id,
                seat_index: 0,
                amount: 0,
                round_state: 0,
            },
            TexasPokerEvent::TimeBankConsumed {
                table_id,
                seat_index: 0,
                consumed_ms: 0,
                remaining_ms: 0,
            },
            TexasPokerEvent::AntePosted {
                table_id,
                seat_index: 0,
                amount: 0,
                ante_mode: 0,
            },
            TexasPokerEvent::RakeCollected {
                table_id,
                pot_before: 0,
                rake_amount: 0,
                pot_after: 0,
                rake_mode: 0,
            },
            TexasPokerEvent::RunItTwiceTriggered {
                table_id,
                board1_cards: 0,
                board2_cards: 0,
            },
            TexasPokerEvent::SettlementPlanCommitted {
                table_id,
                plan_digest: [0; 32],
                runout_count: 1,
                gross_pot: 0,
                rake: 0,
                total_awards: 0,
            },
        ];

        for evt in &samples {
            let bytes = borsh::to_vec(evt).expect("Borsh serialize 失败");
            let _recovered: TexasPokerEvent =
                borsh::from_slice(&bytes).expect("Borsh deserialize 失败");
        }
        // 验证样本数量（49 个变体）
        assert_eq!(samples.len(), 49, "事件变体数应为 49");
    }
}
