import { useEffect, useRef } from 'react';
import type { Dispatch, MutableRefObject, SetStateAction } from 'react';
import type { Socket } from 'socket.io-client';
import type { Card, CryptoEvent, GameMessage, Table } from '../../types/game';
import {
  TABLE_JOINED,
  TABLE_LEFT,
  TABLE_UPDATED,
  LEAVE_DEFERRED,
  SHUFFLE_NOTICE,
  SHUFFLE_SUBMIT,
  RECONSTRUCT_NOTICE,
  RECONSTRUCT_SUBMIT,
  RECONSTRUCT_RESULT,
  REVEAL_NOTICE,
  HAND_REVEAL_RESULT,
  COMMUNITY_REVEAL_RESULT,
  REDEAL_NOTICE,
  REDEAL_RESULT,
  REDEAL_REQUEST,
  CRYPTO_EVENT,
} from '../../pokergame/actions';
import {
  ShuffleNoticeData,
  RevealNoticeData,
  HandRevealResultData,
  CommunityRevealResultData,
  ReconstructNoticeData,
  ReconstructSubmitPayload,
  TableUpdatedPayload,
  TableJoinedPayload,
  TableLeftPayload,
  HandRevealReturn,
  ShuffleHandleResult,
} from './gameInternal';
import { logger } from '../../helpers/logger';
import { useContext } from 'react';
import authContext from '../auth/authContext';
import { ENDORSEMENT_REQUEST, ENDORSEMENT_SUBMIT } from '../../pokergame/actions';
import { mintEndorsement } from './endorsementClient';

export interface UseGameSocketParams {
  socket: Socket | null;
  addMessage: (message: string) => void;
  currentTableRef: MutableRefObject<Table | null>;
  setCurrentTable: (table: Table | null) => void;
  setMessages: Dispatch<SetStateAction<GameMessage[]>>;
  setDecryptedHandCards: Dispatch<SetStateAction<string[]>>;
  setCommunityCards: Dispatch<SetStateAction<Card[]>>;
  setKickNotification: (notification: string | null) => void;
  setCryptoEvents: Dispatch<SetStateAction<CryptoEvent[]>>;
  setLeaveDeferred: Dispatch<SetStateAction<boolean>>;
  isUnmountingRef: MutableRefObject<boolean>;
  pkHex: string | null;
  leaveTable: (shouldNavigate?: boolean, pkHex?: string, fireAndForget?: boolean) => Promise<void>;
  handleShuffleNotice: (data: ShuffleNoticeData) => Promise<ShuffleHandleResult | null>;
  handleRevealNotice: (data: RevealNoticeData) => Promise<void>;
  handleReconstructNotice: (data: ReconstructNoticeData) => Promise<ReconstructSubmitPayload | void>;
  handleHandRevealResult: (data: HandRevealResultData) => HandRevealReturn | null;
  handleCommunityRevealResult: (data: CommunityRevealResultData) => void;
  resetRevealDedup: () => void;
  stopActionLoading: () => void;
}

function translateKickReason(reason: string): string {
  const lower = reason.toLowerCase();
  let core: string;
  if (lower.includes('shuffle')) {
    core = 'shuffle 超时';
  } else if (lower.includes('reveal')) {
    core = 'reveal 超时';
  } else if (lower.includes('reconstruct')) {
    core = 'reconstruct 超时';
  } else {
    core = reason;
  }
  return `你因 ${core} 被移出牌桌`;
}

const BETTING_ACTIONS = new Set(['fold', 'check', 'call', 'raise']);

export const useGameSocket = (params: UseGameSocketParams): void => {
  const {
    socket,
    addMessage,
    currentTableRef,
    setCurrentTable,
    setMessages,
    setDecryptedHandCards,
    setCommunityCards,
    setKickNotification,
    setCryptoEvents,
    setLeaveDeferred,
    isUnmountingRef,
    pkHex,
    leaveTable,
    handleShuffleNotice,
    handleRevealNotice,
    handleReconstructNotice,
    handleHandRevealResult,
    handleCommunityRevealResult,
    resetRevealDedup,
    stopActionLoading,
  } = params;
  const { walletAddress } = useContext(authContext)!;

  useEffect(() => {
    // StrictMode dev 双挂载会把 isUnmountingRef 置 true 且无人复位，导致
    // 之后每次依赖变化（服务端 TABLE_UPDATED 广播）的 cleanup 都误发
    // STAND_UP，玩家在牌局中被服务端反复移座。effect 重新激活即视为挂载。
    isUnmountingRef.current = false;
    const onUnload = () => leaveTable(false, pkHex || undefined, true);
    window.addEventListener('unload', onUnload);
    window.addEventListener('close', onUnload);

    if (socket) {
      (window as unknown as Record<string, unknown>).__sockDebug = {
        reg: Date.now(),
        sid: (socket as unknown as { id?: string }).id ?? null,
      };
      socket.on(TABLE_UPDATED, ({ table, message, from }: TableUpdatedPayload) => {
        (window as unknown as Record<string, unknown>).__sockDebug = {
          ...(window as unknown as Record<string, unknown>).__sockDebug as object,
          tu: Date.now(),
          phase: (table as { roundState?: string }).roundState,
        };
        logger.log(TABLE_UPDATED, table, message, from);
        if (table.roundState === 'waiting') {
          setDecryptedHandCards([]);
          resetRevealDedup();
        }
        setCurrentTable(table);
        logger.log("table updated:", table);
        message && addMessage(message);

        // Fallback reveal trigger for missed REVEAL_NOTICE
        const revealState = table.revealTokenState;
        const revealPhase = revealState?.phase;
        const isPhaseActive = revealPhase && revealPhase !== 'None' && revealPhase !== '';
        if (revealState && isPhaseActive && pkHex && revealState.pending_players?.includes(pkHex)
            && !revealState.completed_players?.includes(pkHex)) {
          logger.log('[Reveal] TABLE_UPDATED fallback: player in pending, phase=' + revealPhase + ', triggering handleRevealNotice');
          handleRevealNotice({
            table_id: table.id,
            phase: revealPhase,
            pending_players: revealState.pending_players,
            player_assignments: revealState.player_assignments,
          });
        }
      });

      // Plan D P2.1：Hand-batch 认可收集——服务器每手结算时广播请求，
      // 本地 wasm 铸造后交回成品（私钥不出客户端）。wasm pkg 未包含
      // 认可导出时 mintEndorsement 返回 null，静默跳过（Hand-batch 结算
      // 由服务器超时降级，legacy 结算不受影响）。
      socket.on(ENDORSEMENT_REQUEST, async (data: { tableId: number; handId: number; handBindingHex: string }) => {
        logger.log('[ENDORSEMENT_REQUEST]', data);
        const submission = await mintEndorsement(data.handBindingHex);
        if (!submission) {
          logger.warn('[ENDORSEMENT_REQUEST] wasm endorsement capability unavailable — skipping');
          return;
        }
        socket.emit(ENDORSEMENT_SUBMIT, {
          wallet: walletAddress,
          tableId: data.tableId,
          handId: data.handId,
          ...submission,
        });
        logger.log('[ENDORSEMENT_REQUEST] submitted client-minted endorsement for hand', data.handId);
      });

      socket.on(TABLE_JOINED, ({ table, message, from }: TableJoinedPayload) => {
        logger.log(TABLE_JOINED, table, message, from);
        logger.log("table joined:", table);
        setCurrentTable(table);
      });

      socket.on(TABLE_LEFT, ({ tables, tableId, reason }: TableLeftPayload) => {
        logger.log(TABLE_LEFT, tables, tableId, reason);
        setCurrentTable(null);
        setMessages([]);
        setDecryptedHandCards([]);
        setCommunityCards([]);
        setLeaveDeferred(false);
        if (reason && reason.trim()) {
          setKickNotification(translateKickReason(reason));
        }
      });

      socket.on(LEAVE_DEFERRED, (payload: { tableId: number; reason: string }) => {
        logger.log(LEAVE_DEFERRED, payload);
        setLeaveDeferred(true);
      });

      socket.on(SHUFFLE_NOTICE, async (data: ShuffleNoticeData) => {
        setCommunityCards([]);
        setDecryptedHandCards([]);
        resetRevealDedup();
        const result = await handleShuffleNotice(data);
        if (result) {
          logger.log('SHUFFLE_NOTICE shuffle proof', result.shuffleResult.shuffle_proof);
          socket.emit(SHUFFLE_SUBMIT, {
            table_id: result.tableId,
            pk_hex: result.pkHex,
            output_cards: result.shuffleResult.output_cards,
            shuffle_proof: result.shuffleResult.shuffle_proof,
          });
          logger.log(SHUFFLE_SUBMIT, result);
          addMessage(`Shuffle submitted (${result.shuffleResult.output_cards.length} cards)`);
        }
      });

      socket.on(REVEAL_NOTICE, (data: RevealNoticeData) => {
        handleRevealNotice(data);
      });

      socket.on(RECONSTRUCT_NOTICE, async (data: ReconstructNoticeData) => {
        const result = await handleReconstructNotice(data);
        if (result) {
          socket.emit(RECONSTRUCT_SUBMIT, result);
        }
      });

      socket.on(RECONSTRUCT_RESULT, (data: { expelled?: boolean }) => {
        logger.log(RECONSTRUCT_RESULT, data);
        if (data?.expelled) {
          addMessage('Player expelled by vote');
        } else {
          addMessage('construct vote timed out');
        }
      });

      socket.on(HAND_REVEAL_RESULT, (data: HandRevealResultData) => {
        const redealInfo = handleHandRevealResult(data);
        if (redealInfo) {
          socket.emit(REDEAL_REQUEST, {
            tableId: currentTableRef.current?.id,
            playerPk: redealInfo.playerPk,
            failedCardIndices: redealInfo.failedCardIndices,
          });
          addMessage(`Requesting redeal for ${redealInfo.failedCardIndices?.length || 0} failed cards...`);
        }
      });

      socket.on(COMMUNITY_REVEAL_RESULT, (data: CommunityRevealResultData) => {
        handleCommunityRevealResult(data);
      });

      socket.on(REDEAL_NOTICE, (data: RevealNoticeData) => {
        logger.log(REDEAL_NOTICE, data);
        handleRevealNotice(data);
      });

      socket.on(REDEAL_RESULT, (data: HandRevealResultData) => {
        const redealInfo = handleHandRevealResult(data);
        if (redealInfo) {
          addMessage(`Redeal decryption still failed for ${redealInfo.failedCardIndices?.length || 0} cards`);
        } else {
          addMessage('Redeal successful, new cards decrypted');
        }
      });

      socket.on(CRYPTO_EVENT, (data: CryptoEvent) => {
        logger.log(CRYPTO_EVENT, data);
        setCryptoEvents((prev) => {
          const next = [...prev, data];
          return next.length > 100 ? next.slice(next.length - 100) : next;
        });
      });

      // Per-hand poker actions (fold/check/call/raise) flow client-side
      // through the connected Starknet wallet via useAccount() / useSendTransaction.
      // There is no longer a server-pushed ACTION_SIGNING_REQUEST event —
      // chip operations and per-hand actions go through starknet-react hooks
      // directly from the action caller. This keeps the protocol uniform with
      // any future AVNU paymaster or Cartridge controller integration.

      // Global error handling for server-sent errors (e.g. SIT_DOWN_V2 deck
      // out of sync). For betting action errors, close the loading overlay
      // so the player can act again.
      socket.on('error', (data: { msg?: string; action?: string; table_id?: string }) => {
        logger.error('[Socket error]', data);
        if (data?.action && BETTING_ACTIONS.has(data.action)) {
          stopActionLoading();
        }
        if (data?.msg) {
          addMessage(data.msg);
        }
      });
    }
    return () => {
      window.removeEventListener('unload', onUnload);
      window.removeEventListener('close', onUnload);
      socket?.off(TABLE_UPDATED);
      socket?.off(TABLE_JOINED);
      socket?.off(TABLE_LEFT);
      socket?.off(LEAVE_DEFERRED);
      socket?.off(SHUFFLE_NOTICE);
      socket?.off(REVEAL_NOTICE);
      socket?.off(RECONSTRUCT_NOTICE);
      socket?.off(RECONSTRUCT_RESULT);
      socket?.off(HAND_REVEAL_RESULT);
      socket?.off(COMMUNITY_REVEAL_RESULT);
      socket?.off(REDEAL_NOTICE);
      socket?.off(REDEAL_RESULT);
      socket?.off(CRYPTO_EVENT);
      socket?.off('error');
      if (isUnmountingRef.current) {
        leaveTable(true, pkHex || undefined, true);
      }
    };
  }, [socket, handleShuffleNotice, handleRevealNotice, handleReconstructNotice, handleHandRevealResult, handleCommunityRevealResult, resetRevealDedup, stopActionLoading, addMessage, currentTableRef, leaveTable, pkHex, setCommunityCards, setCryptoEvents, setCurrentTable, setDecryptedHandCards, setKickNotification, setLeaveDeferred, setMessages, isUnmountingRef]);
};