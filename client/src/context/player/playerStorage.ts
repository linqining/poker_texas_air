// Typed wrapper around localStorage for player-related keys.
// Centralizes the raw 'sk' / 'pk' / 'player_name' / 'last_game_id' string keys
// so they are defined in exactly one place.

const STORAGE_KEYS = {
  SK: 'sk',
  PK: 'pk',
  PLAYER_NAME: 'player_name',
  LAST_GAME_ID: 'last_game_id',
} as const;

export const PlayerStorage = {
  getSk(): string | null {
    return localStorage.getItem(STORAGE_KEYS.SK);
  },
  setSk(sk: string): void {
    localStorage.setItem(STORAGE_KEYS.SK, sk);
  },

  getPk(): string | null {
    return localStorage.getItem(STORAGE_KEYS.PK);
  },
  setPk(pk: string): void {
    localStorage.setItem(STORAGE_KEYS.PK, pk);
  },

  getPlayerName(): string | null {
    return localStorage.getItem(STORAGE_KEYS.PLAYER_NAME);
  },
  setPlayerName(name: string): void {
    localStorage.setItem(STORAGE_KEYS.PLAYER_NAME, name);
  },

  getLastGameId(): string | null {
    return localStorage.getItem(STORAGE_KEYS.LAST_GAME_ID);
  },
  setLastGameId(gid: string): void {
    localStorage.setItem(STORAGE_KEYS.LAST_GAME_ID, gid);
  },
  clearLastGameId(): void {
    localStorage.removeItem(STORAGE_KEYS.LAST_GAME_ID);
  },

  clearAll(): void {
    localStorage.removeItem(STORAGE_KEYS.SK);
    localStorage.removeItem(STORAGE_KEYS.PK);
    localStorage.removeItem(STORAGE_KEYS.PLAYER_NAME);
    localStorage.removeItem(STORAGE_KEYS.LAST_GAME_ID);
  },
};
