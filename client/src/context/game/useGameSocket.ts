import { useEffect, useRef } from 'react';
import type { Dispatch, MutableRefObject, SetStateAction } from 'react';
import type { Socket } from 'socket.io-client';
import type { Card, CryptoEvent, GameMessage, Table, ShuffleState } from '../../types/game';
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
import { useContentContext } from '../content/contentContext';
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
  const { getLocalizedString } = useContentContext();

  // TABLE_UPDATED shuffle fallback 去重：同一 shuffle 轮（phase + 已完成人数）
  // 只补交一次，防止重复广播触发重复洗牌提交。
  const shuffleFallbackDoneRef = useRef<{ phase: string; completed: number } | null>(null);
  // TABLE_UPDATED reconstruct fallback 去重：同一 reconstruct 轮（coefficient + pending 数）只补交一次。
  const reconstructFallbackKeyRef = useRef<string | null>(null);

  const endorsedHandIdsRef = useRef<Set<number>>(new Set());
  useEffect(() => {
    // StrictMode dev 双挂载会把 isUnmountingRef 置 true 且无人复位，导致
    // 之后每次依赖变化（服务端 TABLE_UPDATED 广播）的 cleanup 都误发
    // STAND_UP，玩家在牌局中被服务端反复移座。effect 重新激活即视为挂载。
    isUnmountingRef.current = false;
    // pagehide 取代已废弃的 unload（ unload 在移动端/前进后退缓存下不可靠，
    // pagehide 是标准替代，导航与关页都会触发；'close' 并非 window 事件）
    const onUnload = () => leaveTable(false, pkHex || undefined, true);
    window.addEventListener('pagehide', onUnload);

    if (socket) {
      (window as unknown as Record<string, unknown>).__sockDebug = {
        reg: Date.now(),
        sid: (socket as unknown as { id?: string }).id ?? null,
      };
      // 围观者/重连者的房间状态同步（SETTLEMENT_PRIVACY_PLAN.md 修复项）：
      // 公共牌、亮牌清理、winMessage 都以服务器 TABLE_UPDATED 为准补齐——
      // 仅靠事件流（COMMUNITY_REVEAL_RESULT 等）会让中途进桌的围观者看不到。
      const lastWinMessagesRef = { current: [] as string[] };
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
        // 手结束（结算/弃牌胜）即清理桌上已亮手牌
        if (table.handOver) {
          setDecryptedHandCards([]);
        }
        // 公共牌以服务器 board 为准同步（错过 reveal 事件的围观者由此补上）
        if (Array.isArray(table.board)) {
          setCommunityCards(table.board as Card[]);
        }
        // winMessage 保持显示直到新一手开始（waiting 之后的新手牌清空）
        const winMsgs = (table as { winMessages?: string[] }).winMessages;
        if (Array.isArray(winMsgs) && winMsgs.length > 0) {
          lastWinMessagesRef.current = winMsgs;
        } else if (
          lastWinMessagesRef.current.length > 0 &&
          table.roundState !== 'waiting' && table.roundState !== 'showdown'
        ) {
          lastWinMessagesRef.current = [];
        }
        if (lastWinMessagesRef.current.length > 0 && !(winMsgs?.length)) {
          (table as { winMessages?: string[] }).winMessages = lastWinMessagesRef.current;
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

        // Fallback reconstruct trigger for missed RECONSTRUCT_NOTICE：
        // 快照 reconstructState 与 RECONSTRUCT_NOTICE 字段一致，轮到我时直接补做。
        const reconstructState = table.reconstructState;
        if (reconstructState && reconstructState.is_active && pkHex
            && Array.isArray(reconstructState.pending_players)
            && reconstructState.pending_players.includes(pkHex)) {
          const recKey = `${reconstructState.coefficient_hex}#${reconstructState.pending_players.length}`;
          if (reconstructFallbackKeyRef.current !== recKey) {
            logger.log('[Reconstruct] TABLE_UPDATED fallback: player in pending, triggering handleReconstructNotice');
            void (async () => {
              const result = await handleReconstructNotice({
                table_id: table.id,
                completed_players: reconstructState.completed_players,
                pending_players: reconstructState.pending_players,
                cards: reconstructState.cards,
                coefficient_hex: reconstructState.coefficient_hex,
                player_readable_cards: reconstructState.player_readable_cards,
              });
              if (result) {
                reconstructFallbackKeyRef.current = recKey;
                socket?.emit(RECONSTRUCT_SUBMIT, result);
              }
            })();
          }
        }

        // Fallback shuffle trigger for missed SHUFFLE_NOTICE（刷新/重连恢复）：
        // 快照的 shuffleState 与 SHUFFLE_NOTICE 携带同样的 current_player_pk /
        // deck_encrypted / aggregate_pk，轮到我洗牌时直接补做。失败（返回 null）
        // 不记 dedup，下一次 TABLE_UPDATED 会重试。
        const shuffleState = table.shuffleState as (ShuffleState & { phase?: string }) | null;
        if (shuffleState && shuffleState.current_player_pk && pkHex
            && shuffleState.current_player_pk === pkHex) {
          const completedCount = Array.isArray(shuffleState.completed_players)
            ? shuffleState.completed_players.length : 0;
          const done = shuffleFallbackDoneRef.current;
          if (!done || done.phase !== (shuffleState.phase || '') || done.completed !== completedCount) {
            logger.log('[Shuffle] TABLE_UPDATED fallback: it is my turn (phase=' + shuffleState.phase + '), triggering handleShuffleNotice');
            void (async () => {
              const result = await handleShuffleNotice({
                tableId: String(table.id),
                shuffleState: shuffleState as ShuffleState,
              });
              if (result) {
                shuffleFallbackDoneRef.current = { phase: shuffleState.phase || '', completed: completedCount };
                socket?.emit(SHUFFLE_SUBMIT, {
                  table_id: Number(result.tableId),
                  pk_hex: result.pkHex,
                  output_cards: result.shuffleResult.output_cards,
                  shuffle_proof: result.shuffleResult.shuffle_proof ?? undefined,
                  mask_and_shuffle_round: result.maskAndShuffleRound ?? undefined,
                });
                addMessage(`Shuffle submitted (${result.shuffleResult.output_cards.length} cards)`);
              }
            })();
          }
        }
      });

      // Plan D P2.1：Hand-batch 认可收集——服务器每手结算时广播请求，
      // 本地 wasm 铸造后交回成品（私钥不出客户端）。wasm pkg 未包含
      // 认可导出时 mintEndorsement 返回 null，静默跳过（Hand-batch 结算
      // 由服务器超时降级，legacy 结算不受影响）。
      // 同一手只铸造/提交一次：服务器 DAPV 重投会重播请求（每 3.5s 一次），
      // 无去重会导致浏览器反复做 wasm 铸造把页面卡死。
      const endorsedHandIds = endorsedHandIdsRef.current;
      socket.on(ENDORSEMENT_REQUEST, async (data: { tableId: number; handId: number; handBindingHex: string }) => {
        logger.log('[ENDORSEMENT_REQUEST]', data);
        if (endorsedHandIds.has(data.handId)) {
          logger.log('[ENDORSEMENT_REQUEST] already endorsed hand', data.handId);
          return;
        }
        endorsedHandIds.add(data.handId);
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
        // 围观者首次进桌：公共牌/上一手结果从初始快照补齐
        if (Array.isArray(table.board)) {
          setCommunityCards(table.board as Card[]);
        }
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
            table_id: Number(result.tableId),
            pk_hex: result.pkHex,
            output_cards: result.shuffleResult.output_cards,
            shuffle_proof: result.shuffleResult.shuffle_proof ?? undefined,
            mask_and_shuffle_round: result.maskAndShuffleRound ?? undefined,
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
      socket.on('error', (data: { code?: string; key?: string; msg?: string; detail?: string; action?: string; table_id?: string }) => {
        // 良性幂等：同一玩家重复提交 reveal token（同账号多浏览器/双触发竞态）
        // 被服务器拒绝属正常现象，首次提交已生效，不作为错误展示。
        if (data?.msg && data.msg.includes('already submitted or not pending')) {
          logger.log('[Socket error] benign duplicate reveal submit:', data.msg);
          return;
        }
        if (data?.code && data.code === 'REVEAL_DUPLICATE') {
          logger.log('[Socket error] benign duplicate reveal submit (code)');
          return;
        }
        // 开发者视角：完整结构化信息进 console（code/detail 用于排障）
        logger.error('[Socket error]', data);
        if (data?.action && BETTING_ACTIONS.has(data.action)) {
          stopActionLoading();
        }
        // i18n：payload.key = locale 文件的稳定键（socket_error_<CODE>）；
        // 本地化缺失时回退服务端 msg，再回退通用文案
        let friendly: string | undefined;
        if (data?.key) {
          const localized = getLocalizedString(data.key);
          if (localized !== data.key) friendly = localized;
        }
        if (!friendly) friendly = data?.msg || '操作失败，请稍候重试';
        addMessage(friendly);
      });
    }
    return () => {
      window.removeEventListener('pagehide', onUnload);
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
}
