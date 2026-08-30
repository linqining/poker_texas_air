import httpClient from '../helpers/httpClient';
import type { AxiosError, AxiosRequestConfig } from 'axios';

export interface GameConfig {
  num_players: number;
  cards_per_player: number;
  community_cards: number;
  small_blind: number;
  big_blind: number;
  starting_chips: number;
}

export interface PlayerPublicInfo {
  id: string;
  name: string;
  player_pk: string;
  chips: number;
  current_bet: number;
  folded: boolean;
  card_count: number;
  cards?: (string | null)[];
}

export interface ShuffleState {
  is_active: boolean;
  current_player_pk: string | null;
  completed_players: string[];
  pending_players: string[];
  shuffle_round: number;
  deck_encrypted: ElGamalCiphertextJson[];
}

export interface RevealTokenState {
  is_active: boolean;
  phase: string;
  current_card_index: number;
  total_cards_per_player: number;
  total_community_cards: number;
  completed_players: string[];
  pending_players: string[];
  player_assignments: Record<string, PlayerRevealAssignment>;
}

export interface PlayerRevealAssignment {
  hand_cards: CardEncryptedInfo[];
  community_cards: CardEncryptedInfo[];
}

export interface CardEncryptedInfo {
  card_index: number;
  encrypted_card: ElGamalCiphertextJson;
}

export interface RevealTokenProofJson {
  commitment_t1_hex: string;
  commitment_t2_hex: string;
  response_s_hex: string;
}

export interface SubmitRevealToken {
  card_index: number;
  encrypted_card: ElGamalCiphertextJson;
  reveal_token_proof: RevealTokenProofJson;
  reveal_token_hex: string;
}

export interface SubmitRevealTokenRequest {
  pk_hex: string;
  reveal_tokens: SubmitRevealToken[];
}

export interface GameState {
  game_id: string;
  config: GameConfig;
  phase: string;
  players: PlayerPublicInfo[];
  pot: number;
  current_player_index: number | null;
  community_cards_revealed: number;
  community_cards?: (string | null)[];
  deck_size: number;
  winner: string | null;
  shuffle_state?: ShuffleState | null;
  reveal_token_state?: RevealTokenState | null;
  aggregate_pk?: string;
}

export interface PlayerKeys {
  player_pk: string;
  sk: string;
  pk: string;
}

export interface PKOwnershipProofJson {
  commitment_hex: string;
  response_hex: string;
}

export interface ElGamalCiphertextJson {
  c1_hex: string;
  c2_hex: string;
  c3_hex: string;
}

export interface ShuffleProofJson {
  zk_consistency: ZKConsistencyProofJson;
  triple_dleq: TripleDLEqProofJson;
  product_arg: ProductArgumentV2Json;
  global_challenge_hex: string;
  nonce_hex: string;
}

export interface ZKConsistencyProofJson {
  d1_hex: string;
  d2_hex: string;
  a_g_hex: string;
  a_pk_hex: string;
  s_hex: string;
}

export interface TripleDLEqProofJson {
  a_g_hex: string;
  a_pk_hex: string;
  a_h_hex: string;
  s_hex: string;
}

export interface ProductArgumentV2Json {
  a_hex: string;
  b_hex: string;
  c_hex: string;
  d_hex: string;
  s_hex: string;
  t_hex: string;
}

export interface RemaskProofJson {
  a_hex: string;
  b_hex: string;
  sum_c1_hex: string;
  sum_d2_hex: string;
  s_hex: string;
  nonce_hex: string;
}

export interface LeaveProofJson {
  per_card_commitments_hex: string[];
  commitment_pk_hex: string;
  response_hex: string;
  nonce_hex: string;
}

export interface LeaveGameRoundJson {
  input_cards: ElGamalCiphertextJson[];
  output_cards: ElGamalCiphertextJson[];
  leave_proof: LeaveProofJson;
}

export interface MaskAndShuffleRoundJson {
  player_pk: string;
  mask_cards: ElGamalCiphertextJson[];
  remask_proof: RemaskProofJson;
  output_cards: ElGamalCiphertextJson[];
  shuffle_proof: ShuffleProofJson;
}

export interface ShuffleRoundJson {
  player_pk: string;
  shuffle_round: number;
  output_cards: ElGamalCiphertextJson[];
  proof: ShuffleProofJson;
}

export interface KeypairResponse {
  sk_hex: string;
  pk_hex: string;
  pk_proof: PKOwnershipProofJson;
}

class ApiClient {
  private async request<T>(path: string, options?: RequestInit): Promise<T> {
    try {
      const config: AxiosRequestConfig = {
        method: (options?.method || 'GET') as AxiosRequestConfig['method'],
        url: path,
        data: options?.body,
        headers: options?.headers as Record<string, string> | undefined,
      };
      const res = await httpClient(config);
      return res.data;
    } catch (err) {
      const axiosErr = err as AxiosError<{ error?: string }>;
      const errorData = axiosErr.response?.data;
      throw new Error(errorData?.error || `HTTP ${axiosErr.response?.status ?? 'unknown'}`);
    }
  }

  async getConfig(): Promise<GameConfig> {
    return this.request<GameConfig>('/config');
  }

  async createGame(config?: Partial<GameConfig>): Promise<{ game_id: string; config: GameConfig }> {
    return this.request('/games', {
      method: 'POST',
      body: JSON.stringify({ config: config || {} }),
    });
  }

  async listGames(): Promise<GameState[]> {
    return this.request('/games');
  }

  async getGame(gameId: string): Promise<GameState> {
    return this.request(`/games/${gameId}`);
  }

  async deleteGame(gameId: string): Promise<void> {
    return this.request(`/games/${gameId}`, { method: 'DELETE' });
  }

  async joinGame(gameId: string, name: string, pkHex: string, pkProof: PKOwnershipProofJson): Promise<{ player: PlayerKeys & { id: string; name: string; chips: number }; message: string }> {
    return this.request(`/games/${gameId}/join`, {
      method: 'POST',
      body: JSON.stringify({ name, pk_hex: pkHex, pk_proof: pkProof }),
    });
  }

  async joinGameAndShuffle(
    gameId: string,
    name: string,
    pkHex: string,
    pkProof: PKOwnershipProofJson,
    maskAndShuffleRound: MaskAndShuffleRoundJson,
  ): Promise<{ player: { id: string; name: string; chips: number }; message: string }> {
    return this.request(`/games/${gameId}/join-game-and-shuffle`, {
      method: 'POST',
      body: JSON.stringify({
        name,
        pk_hex: pkHex,
        pk_proof: pkProof,
        mask_and_shuffle_round: maskAndShuffleRound,
      }),
    });
  }

  async startShuffle(gameId: string): Promise<{ message: string; phase: string }> {
    return this.request(`/games/${gameId}/start`, { method: 'POST' });
  }

  async submitShuffle(gameId: string, shuffleRound: ShuffleRoundJson): Promise<{ message: string; shuffles_received: number; total_players: number }> {
    return this.request(`/games/${gameId}/shuffle`, {
      method: 'POST',
      body: JSON.stringify({ shuffle_round: shuffleRound }),
    });
  }

  async dealCards(gameId: string): Promise<{ message: string; phase: string; players_dealt: number }> {
    return this.request(`/games/${gameId}/deal`, { method: 'POST' });
  }

  async revealCard(gameId: string, playerPk: string, cardIndex: number): Promise<{ message: string }> {
    return this.request(`/games/${gameId}/reveal/card`, {
      method: 'POST',
      body: JSON.stringify({ player_pk: playerPk, card_index: cardIndex }),
    });
  }

  async revealCommunityCard(gameId: string): Promise<{ message: string; revealed: number; total: number }> {
    return this.request(`/games/${gameId}/reveal/community`, { method: 'POST' });
  }

  async showdown(gameId: string): Promise<{ message: string; winner: string | null; is_finished: boolean; phase: string }> {
    return this.request(`/games/${gameId}/showdown`, { method: 'POST' });
  }

  async performAction(
    gameId: string,
    playerPk: string,
    action: 'fold' | 'call' | 'raise' | 'check' | 'all_in',
    amount?: number
  ): Promise<GameState> {
    return this.request(`/games/${gameId}/action`, {
      method: 'POST',
      body: JSON.stringify({ player_pk: playerPk, action, amount }),
    });
  }

  async nextRound(gameId: string): Promise<{ message: string; community_revealed: number; pot: number }> {
    return this.request(`/games/${gameId}/next-round`, { method: 'POST' });
  }

  async submitRevealToken(gameId: string, req: SubmitRevealTokenRequest): Promise<{ message: string; player_pk: string; results: Array<{ card_index: number; status?: string; error?: string }>; phase: string; reveal_phase_complete: boolean }> {
    return this.request(`/games/${gameId}/reveal-token`, {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }
}

export const api = new ApiClient();
export default api;
