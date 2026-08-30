import type { Card, ShuffleState, Table } from '../../types/game';
import { logger } from '../../helpers/logger';

export interface ShuffleNoticeData {
  tableId: string;
  shuffleState: ShuffleState;
}

export interface ShuffleResult {
  output_cards: string[][];
  shuffle_proof: unknown;
}

export interface ShuffleHandleResult {
  tableId: string;
  gameId: string;
  pkHex: string | null;
  shuffleResult: ShuffleResult;
}

export interface RevealNoticeData {
  table_id: string;
  phase: string;
  pending_players: string[];
  player_assignments?: Record<string, {
    hand_cards?: Array<{ encrypted_card: string } | string>;
    community_cards?: Array<{ encrypted_card: string } | string>;
    hand_card?: Array<{ encrypted_card: string } | string>;
    community_card?: Array<{ encrypted_card: string } | string>;
  }>;
}

export interface HandRevealResultData {
  tableId: string;
  playerPk: string;
  readableCards: unknown[];
  deckPlaintext: unknown;
}

export interface CommunityRevealResultData {
  tableId: string;
  communityCards: Card[];
}

export interface ReconstructNoticeData {
  table_id: string;
  completed_players: string[];
  pending_players: string[];
  cards: unknown[];
  coefficient_hex: string;
  player_readable_cards?: Record<string, {
    readable_cards: unknown[];
  }>;
}

export interface TableUpdatedPayload {
  table: Table;
  message?: string;
  from?: string;
}

export interface TableJoinedPayload {
  table: Table;
  message?: string;
  from?: string;
}

export interface TableLeftPayload {
  tables: unknown[];
  tableId: string;
  reason?: string;
}

export interface ReconstructSubmitPayload {
  table_id: string;
  pk_hex: string;
  output_cards: string[][];
  swap_cards: string[][];
  proof: string;
}

export interface HandRevealReturn {
  failedCards: unknown[];
  playerPk: string;
  failedCardIndices?: number[];
}

export interface ReconstructResult {
  output_cards: string[][];
  swap_cards: string[][];
  proof: string;
}

export interface JoinAndShuffleResult {
  mask_and_shuffle_round: {
    mask_cards: unknown;
    output_cards: unknown;
    remask_proof: unknown;
    shuffle_proof: unknown;
  };
  pk_ownership_proof: unknown;
}

export function wrapCryptoOp<T>(op: () => T, name: string): T {
  try {
    return op();
  } catch (e) {
    logger.error(`[Crypto] ${name} failed:`, e);
    throw e;
  }
}

/**
 * Parse a WASM result that may be returned as a JSON string or as an
 * already-deserialized object. Centralizes the
 * `typeof result === 'string' ? JSON.parse(result) : result` pattern.
 */
export function parseWasmResult<T>(result: string | T): T {
  return typeof result === 'string' ? JSON.parse(result) : result;
}
