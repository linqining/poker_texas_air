import React, { createContext, useState, useCallback, useEffect, useRef, useContext } from 'react';
import { PlayerContextType, PkProofData } from '../../types/player';
import init, { WasmClientPlayer } from '@linqining/client-wasm';
import wasmUrl from '@linqining/client-wasm/client_wasm_bg.wasm?url';
import authContext from '../auth/authContext';
import { logger } from '../../helpers/logger';
import { PlayerStorage } from './playerStorage';

const PlayerContext = createContext<PlayerContextType | undefined>(undefined);

let wasmInitialized = false;
let wasmInitPromise: Promise<void> | null = null;

export async function ensureWasmReady() {
  if (wasmInitialized) return;

  if (!wasmInitPromise) {
    wasmInitPromise = (async () => {
      await init({ module_or_path: wasmUrl });
      wasmInitialized = true;
      // Functional self-check: derives a real keypair + ownership proof.
      // Any protocol/curve breakage surfaces here, in the browser console.
      const selfTest = new WasmClientPlayer('wasm-selftest');
      const proof = selfTest.generate_pk_proof();
      const ok = typeof proof === 'string' ? JSON.parse(proof) : proof;
      if (!ok) throw new Error('pk proof self-test produced no output');
      logger.log('[wasm] ready — self-test pk:', selfTest.get_pk_hex().slice(0, 16) + '…');
    })();
  }

  await wasmInitPromise;
}

function parsePkProof(proofVal: unknown): PkProofData {
  if (typeof proofVal === 'string') {
    return JSON.parse(proofVal);
  }
  return proofVal as PkProofData;
}

const PlayerProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { walletAddress } = useContext(authContext)!;
  const [playerKeys, setPlayerKeysState] = useState<WasmClientPlayer | null>(null);
  const [pkProof, setPkProof] = useState<PkProofData | null>(null);
  const [pkHex, setPkHex] = useState<string | null>(null);
  const [skHex, setSkHex] = useState<string | null>(null);
  const [gameId, setGameId] = useState<string | null>(null);
  const [playerName, setPlayerName] = useState<string | null>(null);
  const [wasmReady, setWasmReady] = useState(false);
  const keysRef = useRef<WasmClientPlayer | null>(null);
  const restoreSessionRef = useRef<(() => boolean) | null>(null);
  const getPlayerKeysRef = useRef<(() => WasmClientPlayer | null) | null>(null);
  const prevWalletRef = useRef<string | null>(null);

  useEffect(() => {
    ensureWasmReady().then(() => {
      setWasmReady(true);
      if (restoreSessionRef.current) {
        const restored = restoreSessionRef.current();
        if (!restored && getPlayerKeysRef.current) {
          getPlayerKeysRef.current();
        }
      }
    }).catch((e: unknown) => {
      logger.error('[PlayerContext] Failed to initialize WASM:', e);
    });
  }, []);

  const setPlayerKeys = useCallback((keys: WasmClientPlayer, proof: PkProofData, gid: string, name: string) => {
    const pk = keys.get_pk_hex();
    const sk = keys.get_sk_hex();

    logger.log('[PlayerContext] Storing player keys');
    logger.log('[PlayerContext]   - Game ID:', gid);
    logger.log('[PlayerContext]   - Player name:', name);

    keysRef.current = keys;
    setPlayerKeysState(keys);
    setPkProof(parsePkProof(proof));
    setPkHex(pk);
    setSkHex(sk);
    setGameId(gid);
    setPlayerName(name);

    PlayerStorage.setSk(sk);
    PlayerStorage.setPk(pk);
    PlayerStorage.setPlayerName(name);
    PlayerStorage.setLastGameId(gid);
  }, []);

  const clearPlayerKeys = useCallback(() => {
    PlayerStorage.clearAll();

    keysRef.current = null;
    setPlayerKeysState(null);
    setPkProof(null);
    setPkHex(null);
    setSkHex(null);
    setGameId(null);
    setPlayerName(null);

    logger.log('[PlayerContext] Cleared all player data');
  }, []);

  const getPlayerKeys = useCallback((): WasmClientPlayer | null => {
    if (keysRef.current) {
      return keysRef.current;
    }

    if (!wasmInitialized) {
      logger.error('[PlayerContext] WASM not initialized');
      return null;
    }

    const storedSk = PlayerStorage.getSk();
    if (!storedSk) {
      logger.warn('[PlayerContext] No SK found in storage, generating new keys from wallet address');
      if (!walletAddress) {
        logger.error('[PlayerContext] No wallet address available, cannot generate keys');
        return null;
      }
      const newKeys = WasmClientPlayer.new_with_wallet_address(walletAddress);
      const sk = newKeys.get_sk_hex();
      const pk = newKeys.get_pk_hex();
      PlayerStorage.setSk(sk);
      PlayerStorage.setPk(pk);
      const restoredProof = parsePkProof(newKeys.generate_pk_proof());
      setPlayerKeys(newKeys, restoredProof, "", pk);
      return newKeys;
    }

    try {
      logger.log('[PlayerContext] Reconstructing player keys from SK...', storedSk);
      const reconstructedKeys = WasmClientPlayer.from_sk(storedSk);
      const restoredProof = parsePkProof(reconstructedKeys.generate_pk_proof());
      const pk = reconstructedKeys.get_pk_hex();
      const savedName = PlayerStorage.getPlayerName() || '';
      const savedGameId = PlayerStorage.getLastGameId() || '';
      setPlayerKeys(reconstructedKeys, restoredProof, savedGameId, savedName);
      logger.log('[PlayerContext] Successfully reconstructed player keys');
      return reconstructedKeys;
    } catch (e) {
      logger.error('[PlayerContext] Failed to reconstruct player keys:', e);
      return null;
    }
  }, [setPlayerKeys]);

  const restoreSession = useCallback((): boolean => {
    const savedGameId = PlayerStorage.getLastGameId();
    const savedSk = PlayerStorage.getSk();
    const savedName = PlayerStorage.getPlayerName();

    if (!savedSk) {
      return false;
    }

    if (keysRef.current) return true;

    if (!wasmInitialized) {
      logger.error('[PlayerContext] WASM not initialized');
      return false;
    }

    try {
      logger.log('[PlayerContext] Restoring player session from storage...');
      const restoredKeys = WasmClientPlayer.from_sk(savedSk);
      const restoredProof = parsePkProof(restoredKeys.generate_pk_proof());

      setPlayerKeys(restoredKeys, restoredProof, savedGameId || '', savedName || '');
      logger.log('[PlayerContext] Player session restored successfully!');
      return true;
    } catch (e) {
      logger.error('[PlayerContext] Failed to restore player session:', e);
      PlayerStorage.clearLastGameId();
      return false;
    }
  }, [setPlayerKeys]);

  useEffect(() => {
    restoreSessionRef.current = restoreSession;
    getPlayerKeysRef.current = getPlayerKeys;
  }, [restoreSession, getPlayerKeys]);

  // 钱包地址变化时，重新生成密钥（与钱包一一对应）
  useEffect(() => {
    if (!wasmReady || !walletAddress) return;
    // 首次或钱包未变化时跳过
    if (prevWalletRef.current === walletAddress) return;
    const prevWallet = prevWalletRef.current;
    prevWalletRef.current = walletAddress;

    // 非首次切换钱包：清除旧密钥，用新钱包地址生成
    if (prevWallet !== null) {
      logger.log('[PlayerContext] Wallet address changed, regenerating keys');
      clearPlayerKeys();
      const newKeys = WasmClientPlayer.new_with_wallet_address(walletAddress);
      const sk = newKeys.get_sk_hex();
      const pk = newKeys.get_pk_hex();
      PlayerStorage.setSk(sk);
      PlayerStorage.setPk(pk);
      const proof = parsePkProof(newKeys.generate_pk_proof());
      setPlayerKeys(newKeys, proof, "", pk);
    }
  }, [walletAddress, wasmReady, clearPlayerKeys, setPlayerKeys]);

  useEffect(() => {
    logger.log('[PlayerContext] Context updated:', {
      hasKeys: !!playerKeys,
      gameId,
      playerName,
      wasmReady,
    });
  }, [playerKeys, gameId, playerName, wasmReady]);

  return (
    <PlayerContext.Provider
      value={{
        playerKeys,
        pkProof,
        pkHex,
        skHex,
        gameId,
        playerName,
        wasmReady,
        setPlayerKeys,
        clearPlayerKeys,
        getPlayerKeys,
        restoreSession,
      }}
    >
      {children}
    </PlayerContext.Provider>
  );
};

export { PlayerContext };
export default PlayerProvider;
