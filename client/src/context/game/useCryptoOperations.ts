import { useCallback, useRef } from 'react';
import type { Dispatch, MutableRefObject, SetStateAction } from 'react';
import type { Socket } from 'socket.io-client';
import type { WasmClientPlayer } from '@linqining/client-wasm';
import { guardRevealAssignment, recordOwnCards } from './revealOwnCardGuard';
import { recordOwnHoleCiphertexts } from './ownHoleCards';
import type { Card, Table } from '../../types/game';
import type { SubmitRevealToken } from '../../api/secretPokerClient';
import {
  SHUFFLE_NOTICE,
  SHUFFLE_SUBMIT,
  REVEAL_NOTICE,
  REVEAL_SUBMIT,
  RECONSTRUCT_NOTICE,
  HAND_REVEAL_RESULT,
  COMMUNITY_REVEAL_RESULT,
} from '../../pokergame/actions';
import {
  ShuffleNoticeData,
  ShuffleResult,
  ShuffleHandleResult,
  RevealNoticeData,
  HandRevealResultData,
  HandRevealReturn,
  CommunityRevealResultData,
  ReconstructNoticeData,
  ReconstructSubmitPayload,
  ReconstructResult,
  wrapCryptoOp,
  parseWasmResult,
} from './gameInternal';
import { logger } from '../../helpers/logger';
import { PlayerStorage } from '../player/playerStorage';

export interface UseCryptoOperationsParams {
  socket: Socket | null;
  playerKeys: WasmClientPlayer | null;
  pkHex: string | null;
  getPlayerKeys: () => WasmClientPlayer | null;
  addMessage: (message: string) => void;
  currentTableRef: MutableRefObject<Table | null>;
  setShuffleLoading: (value: boolean) => void;
  setRevealLoading: (value: boolean) => void;
  setDecryptedHandCards: Dispatch<SetStateAction<string[]>>;
  setCommunityCards: Dispatch<SetStateAction<Card[]>>;
  shuffleLoadingRef: MutableRefObject<boolean>;
  revealLoadingRef: MutableRefObject<boolean>;
}

export interface UseCryptoOperationsReturn {
  handleShuffleNotice: (data: ShuffleNoticeData) => Promise<ShuffleHandleResult | null>;
  handleRevealNotice: (data: RevealNoticeData) => Promise<void>;
  handleHandRevealResult: (data: HandRevealResultData) => HandRevealReturn | null;
  handleCommunityRevealResult: (data: CommunityRevealResultData) => void;
  handleReconstructNotice: (data: ReconstructNoticeData) => Promise<ReconstructSubmitPayload | void>;
  resetRevealDedup: () => void;
}

export const useCryptoOperations = (
  params: UseCryptoOperationsParams,
): UseCryptoOperationsReturn => {
  const {
    socket,
    playerKeys,
    pkHex,
    getPlayerKeys,
    addMessage,
    currentTableRef,
    setShuffleLoading,
    setRevealLoading,
    setDecryptedHandCards,
    setCommunityCards,
    shuffleLoadingRef,
    revealLoadingRef,
  } = params;

  // Resolves the current player keys from state or storage. Returns null when
  // no keys are available — callers keep their existing early-return behavior.
  const getRequiredKeys = useCallback((): WasmClientPlayer | null => {
    return playerKeys || getPlayerKeys();
  }, [playerKeys, getPlayerKeys]);

  // 防止同一 reveal phase 的重复 REVEAL_NOTICE 导致重复提交。
  // revealLoadingRef 仅防并发，emit 后立即重置无法阻止同一阶段的顺序重复提交。
  // 此 ref 记录已提交的 phase + 时间戳，30 秒窗口内同 phase 的重复通知直接跳过。
  // 注意：每手牌的 preflop reveal phase 都是 "HandReveal"，跨手牌时需通过 resetRevealDedup 清除。
  const revealSubmittedRef = useRef<{ phase: string; ts: number } | null>(null);

  const resetRevealDedup = useCallback(() => {
    if (revealSubmittedRef.current) {
      logger.log('[Reveal] resetRevealDedup: clearing previous dedup state', revealSubmittedRef.current);
      revealSubmittedRef.current = null;
    }
  }, []);

  const handleShuffleNotice = useCallback(async (data: ShuffleNoticeData): Promise<ShuffleHandleResult | null> => {
    logger.log(SHUFFLE_NOTICE, data);
    const { tableId, shuffleState } = data;

    const keys = getRequiredKeys();
    if (!keys) {
      logger.warn('[Shuffle] No player keys available');
      return null;
    }
    logger.log('[SHUFFLE_NOTICE] Current player:', pkHex, keys);
    if (shuffleState.current_player_pk !== pkHex) {
      logger.log('[Shuffle] Not my turn, waiting...');
      return null;
    }

    if (shuffleLoadingRef.current) {
      logger.log('[Shuffle] Already processing a shuffle');
      return null;
    }

    const deckEncrypted = shuffleState.deck_encrypted;
    const aggregatePk = shuffleState.aggregate_pk;

    if (!deckEncrypted || deckEncrypted.length === 0) {
      logger.warn('[Shuffle] No deck_encrypted in shuffle state');
      return null;
    }
    if (!aggregatePk) {
      logger.warn('[Shuffle] No aggregate_pk');
      return null;
    }

    shuffleLoadingRef.current = true;
    setShuffleLoading(true);

    try {
      const deckJson = JSON.stringify(deckEncrypted);
      const shuffleResult = wrapCryptoOp(() => {
        const result = keys.shuffle(deckJson, aggregatePk);
        if (!result) throw new Error('Shuffle returned null');
        return parseWasmResult<ShuffleResult>(result);
      }, 'shuffle');

      if (!shuffleResult.output_cards || !Array.isArray(shuffleResult.output_cards)) {
        throw new Error('Invalid shuffle result: missing output_cards');
      }

      const gameId = String(tableId);
      logger.log(SHUFFLE_SUBMIT, { gameId, pkHex, cardCount: shuffleResult.output_cards.length });

      return {
        tableId,
        gameId,
        pkHex,
        shuffleResult,
      };
    } catch (e) {
      const err = e as Error;
      logger.error('[Shuffle] Failed:', e);
      addMessage(`Shuffle failed: ${err.message || e}`);
      return null;
    } finally {
      shuffleLoadingRef.current = false;
      setShuffleLoading(false);
    }
  }, [getRequiredKeys, pkHex, addMessage]);

  const handleRevealNotice = useCallback(async (data: RevealNoticeData): Promise<void> => {
    logger.log(REVEAL_NOTICE, data);
    const { table_id, phase, pending_players, player_assignments } = data;

    const keys = getRequiredKeys();
    if (!keys) {
      logger.warn('[Reveal] No player keys available');
      return;
    }

    if (!pending_players || !pending_players.includes(pkHex!)) {
      logger.log('[Reveal] Not my turn for reveal');
      return;
    }

    if (revealLoadingRef.current) {
      logger.log('[Reveal] Already processing reveal tokens');
      return;
    }

    // 防止同一阶段的重复 REVEAL_NOTICE 导致重复提交（30 秒窗口）。
    // 竞态修复：REVEAL_NOTICE 与 TABLE_UPDATED fallback 会在同一广播批次内
    // 并发触发本 handler，若在提交成功后才写 dedup（旧实现），两次调用都会
    // 通过检查 → 第二次提交被服务器拒为 "already submitted or not pending"。
    // 这里在进入时立即占坑（先写 ts 再做后续异步工作）。
    const now = Date.now();
    const lastSubmit = revealSubmittedRef.current;
    if (lastSubmit && lastSubmit.phase === phase && now - lastSubmit.ts < 30_000) {
      logger.warn(`[Reveal] DEDUP SKIP: phase=${phase} last_ts=${lastSubmit.ts} now=${now} elapsed=${now - lastSubmit.ts}ms < 30000ms — if this is a NEW hand, resetRevealDedup should have been called`);
      return;
    }
    if (lastSubmit) {
      logger.log(`[Reveal] DEDUP PASS: phase=${phase} last_phase=${lastSubmit.phase} elapsed=${now - lastSubmit.ts}ms`);
    }
    revealSubmittedRef.current = { phase, ts: now };

    const assignments = player_assignments || currentTableRef.current?.revealTokenState?.player_assignments;
    if (!assignments) {
      logger.warn('[Reveal] No player assignments available');
      return;
    }

    const myAssignment = assignments[pkHex!];
    if (!myAssignment) {
      logger.warn('[Reveal] No assignment found for my pk');
      return;
    }

    let cardsForPhase: unknown[] = [];
    const handCards = myAssignment.hand_cards || myAssignment.hand_card;
    let rawHandCards: unknown[] = [];
    if (handCards) {
      rawHandCards = handCards.map((c: { encrypted_card?: string } | string) =>
        typeof c === 'string' ? c : c.encrypted_card || c
      );
      cardsForPhase = [...rawHandCards];
    }
    const communityCards = myAssignment.community_cards || myAssignment.community_card;
    if (communityCards && communityCards.length > 0) {
      for (const cc of communityCards) {
        cardsForPhase.push(typeof cc === 'string' ? cc : cc.encrypted_card || cc);
      }
    }

    if (cardsForPhase.length === 0) {
      logger.warn('[Reveal] No cards assigned');
      return;
    }

    // P0.1/P0.4 reveal 编排守卫（Plan D）：非 ShowdownReveal 阶段，
    // assignment 中的手牌卡命中自有手牌 marker（HAND_REVEAL_RESULT 建立
    // 的 c1 锚点）即拒绝出 token —— 阻断恶意服务器借客户端之手集齐
    // N 份解密份额的主动偷看路径。无锚点时保守拒绝手牌类 assignment。
    const rawCommunityCards: unknown[] = (communityCards || []).map(
      (cc: { encrypted_card?: string } | string) => (typeof cc === 'string' ? cc : cc.encrypted_card || cc)
    );
    const guard = guardRevealAssignment(rawHandCards, rawCommunityCards, phase);
    if (guard.blocked.length > 0) {
      logger.error(
        `[Reveal] GUARD: ${guard.blocked.length} card(s) in my ${phase} assignment match MY OWN hole cards — ` +
          `refusing to surrender decryption shares for them. Server orchestration is hostile or buggy.`
      );
      addMessage(
        `安全守卫：检测到 ${phase} 编排中混入你自己的手牌，已拒绝出 ${guard.blocked.length} 个 token（防偷看保护）`
      );
    }
    if (guard.conservativelyBlocked) {
      logger.warn(
        `[Reveal] GUARD: no own-card anchors established yet (no HAND_REVEAL_RESULT) — ` +
          `conservatively refusing hand-card tokens for phase=${phase}`
      );
      addMessage(`安全守卫：未建立手牌锚点，保守拒绝 ${phase} 的手牌 token 提交`);
    }
    cardsForPhase = guard.allowed;

    if (cardsForPhase.length === 0) {
      logger.warn('[Reveal] All cards blocked by guard; nothing to submit');
      return;
    }

    revealLoadingRef.current = true;
    setRevealLoading(true);

    try {
      const cardJson = JSON.stringify(cardsForPhase);
      const tokens = wrapCryptoOp(() => {
        const tokensRaw = keys.batch_generate_reveal_token(cardJson);
        if (!tokensRaw) throw new Error('batch_generate_reveal_token returned null');
        const parsed = parseWasmResult<unknown[]>(tokensRaw);
        if (!Array.isArray(parsed) || parsed.length === 0) {
          throw new Error('Invalid or empty tokens returned');
        }
        return parsed;
      }, 'batchGenerateRevealToken');

      socket?.emit(REVEAL_SUBMIT, {
        tableId: Number(table_id),
        pkHex: pkHex!,
        revealTokens: tokens as SubmitRevealToken[],
      });
      revealSubmittedRef.current = { phase, ts: Date.now() };
      logger.log('[Reveal] Submitted tokens:', { gameId: table_id, pkHex, tokens });

      addMessage(`Reveal ${phase}: ${tokens.length} tokens submitted`);
    } catch (e) {
      const err = e as Error;
      logger.error('[Reveal] Failed:', e);
      addMessage(`Reveal token failed: ${err.message || e}`);
    } finally {
      revealLoadingRef.current = false;
      setRevealLoading(false);
    }
  }, [socket, getRequiredKeys, pkHex, addMessage]);

  const handleHandRevealResult = useCallback((data: HandRevealResultData): HandRevealReturn | null => {
    logger.log(HAND_REVEAL_RESULT, data);
    const { tableId, playerPk, readableCards, deckPlaintext } = data;

    if (!readableCards || !Array.isArray(readableCards) || readableCards.length === 0) {
      logger.warn('[HandReveal] No readable cards in payload');
      return null;
    }

    const keys = getRequiredKeys();
    if (!keys) {
      logger.warn('[HandReveal] No player keys available for decryption');
      return null;
    }

    const currentPkHex = pkHex || PlayerStorage.getPk();
    if (playerPk !== currentPkHex) {
      logger.warn('[HandReveal] playerPk mismatch, ignoring:', { playerPk, currentPkHex });
      return null;
    }
    // 底牌数量硬上限（德扑 = 2）。服务端异常路径若下发多于 2 张，只取前 2 张
    // 并告警，防止"手牌不限"透出到 UI。
    const MAX_HOLE_CARDS = 2;
    const cappedCards = readableCards.length > MAX_HOLE_CARDS ? readableCards.slice(0, MAX_HOLE_CARDS) : readableCards;
    if (cappedCards.length !== readableCards.length) {
      logger.error(`[HandReveal] payload carried ${readableCards.length} hole cards (max ${MAX_HOLE_CARDS}) — capped`);
    }
    const decFailedCards: unknown[] = [];
    const decrypted: string[] = [];
    for (let i = 0; i < cappedCards.length; i++) {
      const card = cappedCards[i];
      const ctJson = JSON.stringify(card);
      const deckPlaintextJson = JSON.stringify(deckPlaintext);
      try {
        const result = wrapCryptoOp(() => {
          logger.log('[HandReveal] Decrypting card:', ctJson);
          const decryptedStr = keys.decrypt_readable_card(ctJson, deckPlaintextJson);
          if (!decryptedStr) throw new Error('decrypt_readable_card returned null');
          return decryptedStr;
        }, 'decrypt_readable_card');
        logger.log('[HandReveal] Decrypted card:', result);
        decrypted.push(result);
      } catch (e) {
        decFailedCards.push(card);
        const err = e as Error;
        logger.error('[HandReveal] Decryption failed:', e);
        addMessage(`Hand reveal decryption failed: ${err.message || e}`);
        continue;
      }
    }
    if (decFailedCards.length > 0) {
      addMessage(`Hand reveal decryption failed for ${decFailedCards.length} cards`);
      return { failedCards: decFailedCards, playerPk: currentPkHex };
    } else {
      // P0.1 锚点建立：这些密文确认是自己的手牌，记录 marker 供 reveal
      // 编排守卫比对（非 ShowdownReveal 阶段拒绝为自己的手牌出 token）。
      const markerCount = recordOwnCards(readableCards);
      if (markerCount > 0) {
        logger.log(`[HandReveal] Recorded ${markerCount} own-card guard marker(s)`);
      }
      // 离开/弃牌剥层排除集的锚点（c1 不变，见 ownHoleCards.ts）。
      recordOwnHoleCiphertexts(readableCards);
      setDecryptedHandCards(decrypted);
      addMessage(`Hand revealed: ${decrypted.length} cards decrypted`);
      return null;
    }
  }, [getRequiredKeys, pkHex, addMessage]);

  const handleCommunityRevealResult = useCallback((data: CommunityRevealResultData): void => {
    logger.log(COMMUNITY_REVEAL_RESULT, data);
    const { tableId, communityCards: cards } = data;

    if (!cards || !Array.isArray(cards) || cards.length === 0) {
      logger.warn('[CommunityReveal] No community cards in payload');
      return;
    }

    // 公共牌数量硬上限（德扑 = 5）。服务端异常路径若下发多于 5 张，只取前 5 张
    // 并告警，防止"公共牌不限"透出到 UI。
    const MAX_COMMUNITY_CARDS = 5;
    const capped = cards.length > MAX_COMMUNITY_CARDS ? cards.slice(0, MAX_COMMUNITY_CARDS) : cards;
    if (capped.length !== cards.length) {
      logger.error(`[CommunityReveal] payload carried ${cards.length} community cards (max ${MAX_COMMUNITY_CARDS}) — capped`);
    }

    setCommunityCards(capped);
    addMessage(`Community cards revealed: ${capped.length} cards`);
  }, [addMessage]);

  const handleReconstructNotice = useCallback(async (data: ReconstructNoticeData): Promise<ReconstructSubmitPayload | void> => {
    logger.log(RECONSTRUCT_NOTICE, data);
    const { table_id, completed_players, pending_players, cards, coefficient_hex, player_readable_cards } = data;
    const keys = getRequiredKeys();
    if (!keys) {
      logger.warn('[Reconstruct] No player keys available for decryption');
      return;
    }

    if (!pending_players || !pending_players.includes(pkHex!)) {
      logger.log('[Reconstruct] Not my turn for reconstruct');
      return;
    }

    const myReadableCards = player_readable_cards?.[pkHex!];
    if (!myReadableCards || !myReadableCards.readable_cards || myReadableCards.readable_cards.length === 0) {
      logger.warn('[Reconstruct] No readable cards assigned for my pk');
      return;
    }

    try {
      const originCardsJson = JSON.stringify(cards);
      const userReadableCardsJson = JSON.stringify(myReadableCards.readable_cards);

      const result = wrapCryptoOp(() => {
        const resultRaw = keys.reconstruct(originCardsJson, userReadableCardsJson, coefficient_hex);
        if (!resultRaw) throw new Error('reconstruct returned null');
        return parseWasmResult<ReconstructResult>(resultRaw);
      }, 'reconstruct');

      logger.log('RECONSTRUCT_NOTICE shuffle proof', result);
      logger.log('[Reconstruct] Result:', result);
      addMessage(`Reconstruct submitted`);
      return {
        table_id,
        pk_hex: pkHex,
        output_cards: result.output_cards,
        swap_cards: result.swap_cards,
        proof: result.proof,
      } as ReconstructSubmitPayload;
    } catch (e) {
      const err = e as Error;
      logger.error('[Reconstruct] Failed:', e);
      addMessage(`Reconstruct failed: ${err.message || e}`);
    }
  }, [getRequiredKeys, pkHex, addMessage]);

  return {
    handleShuffleNotice,
    handleRevealNotice,
    handleHandRevealResult,
    handleCommunityRevealResult,
    handleReconstructNotice,
    resetRevealDedup,
  };
};
