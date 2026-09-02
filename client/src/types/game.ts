// 游戏相关类型定义

export type RoundStateType =
  | 'waiting'
  | 'shuffling'
  | 'shuffleComplete'
  | 'preFlopReveal'
  | 'preFlop'
  | 'flopReveal'
  | 'flop'
  | 'turnReveal'
  | 'turn'
  | 'riverReveal'
  | 'river'
  | 'showdownReveal'
  | 'showdown'
  | 'handComplete';

export const RoundState = {
  Waiting: 'waiting',
  Shuffling: 'shuffling',
  ShuffleComplete: 'shuffleComplete',
  PreFlopReveal: 'preFlopReveal',
  PreFlop: 'preFlop',
  FlopReveal: 'flopReveal',
  Flop: 'flop',
  TurnReveal: 'turnReveal',
  Turn: 'turn',
  RiverReveal: 'riverReveal',
  River: 'river',
  ShowdownReveal: 'showdownReveal',
  Showdown: 'showdown',
  HandComplete: 'handComplete',
} as const;

export interface Card {
  suit: string;
  rank: string;
}

export interface Player {
  socketId: string;
  pkHex: string;
  name: string;
  chips: number;
  sittingOut: boolean;
}

export interface Seat {
  id: number;
  player: Player | null;
  hand: Card[];
  turn: boolean;
  chips: number;
  bet: number;
  sittingOut: boolean;
  stack: number;
  lastAction: string | null;
  /** 玩家是否已 fold（与后端 ClientSeat.folded 对齐，camelCase 序列化） */
  folded?: boolean;
}

export interface ShuffleState {
  is_active: boolean;
  current_player_pk: string;
  deck_encrypted: string[][];
  aggregate_pk: string;
  completed_players: string[];
  pending_players: string[];
  /** 当前洗牌者是否需补自身密钥层（waiting 入座玩家）——true 时走 join_game_and_shuffle。 */
  needs_join_layer?: boolean;
  /** 聚合公钥减去当前洗牌者公钥（join_game_and_shuffle 的 curr_share_pk）。 */
  share_pk?: string;
}

export interface RevealTokenState {
  phase?: string;
  pending_players?: string[];
  completed_players?: string[];
  player_assignments: Record<
    string,
    {
      hand_cards?: Array<{ encrypted_card: string }>;
      community_cards?: Array<{ encrypted_card: string }>;
      hand_card?: Array<{ encrypted_card: string }>;
      community_card?: Array<{ encrypted_card: string }>;
    }
  >;
}

/** 服务器快照中的 reconstruct 状态（字段与 RECONSTRUCT_NOTICE 一致，snake_case）。 */
export interface ReconstructState {
  is_active: boolean;
  completed_players: string[];
  pending_players: string[];
  cards: string[];
  coefficient_hex: string;
  player_readable_cards?: Record<string, {
    readable_cards: unknown[];
  }>;
}

export interface SidePot {
  amount: number;
}

export interface Table {
  id: string;
  /** Optional chain-side table id. Not used by the client in the Starknet flow
   * (per-hand poker actions are off-chain through the game server), but kept
   * so downstream code can still reference it when wired up. */
  chainTableId?: string;
  seats: Record<number, Seat>;
  roundState: RoundStateType;
  shuffleState: ShuffleState | null;
  revealTokenState: RevealTokenState | null;
  reconstructState?: ReconstructState | null;
  deck?: {
    cards: string[][];
  };
  pot: number;
  currentBet: number;
  minBuyIn: number;
  maxBuyIn: number;
  bigBlind: number;
  smallBlind: number;
  dealerSeatId: number;
  limit: number;
  minBet: number;
  minRaise: number;
  button: number;
  callAmount: number;
  handOver: boolean;
  mainPot: number;
  sidePots: SidePot[];
  players: Player[];
  board: Card[];
  wentToShowdown: boolean;
  winMessages: string[];
  /** 本手已收台费（摊牌结算时按链上口径收取，0 = 未抽水） */
  rakeCollected: number;
}

export interface GameMessage {
  text: string;
  timestamp: number;
}

export interface GameContextType {
  messages: GameMessage[];
  currentTable: Table | null;
  isPlayerSeated: boolean;
  seatId: number | null;
  shuffleLoading: boolean;
  revealLoading: boolean;
  decryptedHandCards: string[];
  communityCards: Card[];
  kickNotification: string | null;
  cryptoEvents: CryptoEvent[];
  leaveDeferred: boolean;
  setLeaveDeferred: (value: boolean) => void;
  /** 当玩家在手牌进行中且未 fold 时点击离开，置为 true 以触发确认弹窗（Task 7 渲染弹窗） */
  showFoldLeaveConfirm: boolean;
  /** 用户确认 fold 并离开：调用 fold() 后进入 deferred leave 流程 */
  confirmFoldLeave: (shouldNavigate?: boolean, pkHex?: string) => void;
  /** 用户取消 fold 并离开 */
  cancelFoldLeave: () => void;
  /** 用户在 deferred banner 上取消离开：中断进行中的 performDeferredLeave */
  cancelDeferredLeave: () => void;
  joinTable: (tableId: number, pkHex: string) => void;
  leaveTable: (shouldNavigate?: boolean, pkHex?: string, fireAndForget?: boolean) => Promise<void>;
  sitDown: (tableId: string, seatId: number, amount: number) => Promise<void>;
  standUp: () => Promise<void>;
  addMessage: (message: string) => void;
  fold: () => void;
  check: () => void;
  call: () => void;
  raise: (amount: number) => void;
  rebuy: (tableId: string, seatId: number, amount: number) => void;
  sittingOut: () => void;
  sittingIn: () => void;
  expelInitiate: (tableId: string, targetPlayerPk: string) => void;
  clearKickNotification: () => void;
  isActionLoading: boolean;
  startActionLoading: () => void;
}

// ===== ZK 密码学事件（用于可视化面板） =====
export type CryptoEventType = 'shuffle' | 'remask' | 'reveal_token' | 'leave' | 'reconstruct';

export interface CryptoEvent {
  type: 'crypto_event';
  event_type: CryptoEventType;
  player_pk: string;
  card_index: number | null;
  tx_digest: string | null;
  verified: boolean;
  timestamp: number;
  message?: string;
}
