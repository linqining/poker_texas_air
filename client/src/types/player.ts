// 玩家密钥相关类型
import type { WasmClientPlayer } from '@linqining/client-wasm';

export interface PlayerContextType {
  playerKeys: WasmClientPlayer | null;
  pkProof: PkProofData | null;
  pkHex: string | null;
  skHex: string | null;
  gameId: string | null;
  playerName: string | null;
  wasmReady: boolean;
  setPlayerKeys: (
    keys: WasmClientPlayer,
    proof: PkProofData,
    gid: string,
    name: string,
  ) => void;
  clearPlayerKeys: () => void;
  getPlayerKeys: () => WasmClientPlayer | null;
  restoreSession: () => boolean;
}

export interface PkProofData {
  commitment: string;
  response: string;
  nonce: string;
}
