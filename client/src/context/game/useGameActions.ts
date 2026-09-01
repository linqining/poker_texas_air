import { useContext, useEffect, useRef, useState, type MutableRefObject } from 'react';
import type { NavigateFunction } from 'react-router-dom';
import type { Socket } from 'socket.io-client';
import { extractC1, ownHoleC1Set } from './ownHoleCards';
import type { WasmClientPlayer } from '@linqining/client-wasm';
import {
  CALL,
  CHECK,
  FOLD,
  JOIN_TABLE,
  LEAVE_TABLE,
  RAISE,
  REBUY,
  SIT_DOWN_V2,
  STAND_UP,
  SITTING_OUT,
  SITTING_IN,
  RECONSTRUCT_INITIATE,
  TABLE_UPDATED,
} from '../../pokergame/actions';
import { getToken } from '../../helpers/getToken';
import httpClient from '../../helpers/httpClient';
import type { Table, Seat } from '../../types/game';
import { RoundState } from '../../types/game';
import { TableUpdatedPayload, wrapCryptoOp } from './gameInternal';
import authContext from '../../context/auth/authContext';
import { logger } from '../../helpers/logger';
import { STAND_UP_TIMEOUT_MS } from '../../clientConfig';
import { useAccount } from '@starknet-react/core';
import { submitBuyIn } from '../../starknet/starknetGameActions';
import { activeAccount } from '../../starknet/devAccount';

export interface UseGameActionsParams {
  socket: Socket | null;
  navigate: NavigateFunction;
  playerKeys: WasmClientPlayer | null;
  pkHex: string | null;
  getPlayerKeys: () => WasmClientPlayer | null;
  addMessage: (message: string) => void;
  currentTableRef: MutableRefObject<Table | null>;
  /** 当前 table 状态（来自 React state，用于在 useEffect 中响应 roundState 变化） */
  currentTable: Table | null;
  seatId: number | null;
  isPlayerSeated: boolean;
  /** 后端因手牌进行中而推迟离桌时（LEAVE_DEFERRED 事件）置为 true */
  leaveDeferred: boolean;
  setLeaveDeferred: (value: boolean) => void;
  authMethod: string | null;
}

export interface UseGameActionsReturn {
  joinTable: (tableId: number, pkHex: string) => void;
  leaveTable: (shouldNavigate?: boolean, pkHex?: string, fireAndForget?: boolean) => Promise<void>;
  sitDown: (tableId: string, seatId: number, amount: number) => Promise<void>;
  rebuy: (tableId: string, seatId: number, amount: number) => void;
  standUp: () => Promise<void>;
  fold: () => void;
  check: () => void;
  call: () => void;
  raise: (amount: number) => void;
  sittingOut: () => void;
  sittingIn: () => void;
  expelInitiate: (tableId: string, targetPlayerPk: string) => void;
  /** 当玩家在手牌进行中且未 fold 时点击离开，置为 true 以触发确认弹窗（Task 7 渲染弹窗） */
  showFoldLeaveConfirm: boolean;
  /** 用户确认 fold 并离开：调用 fold() 后进入 deferred leave 流程 */
  confirmFoldLeave: (shouldNavigate?: boolean, pkHex?: string) => void;
  /** 用户取消 fold 并离开 */
  cancelFoldLeave: () => void;
  /** 用户在 deferred banner 上取消离开：中断进行中的 performDeferredLeave */
  cancelDeferredLeave: () => void;
}

export const useGameActions = (params: UseGameActionsParams): UseGameActionsReturn => {
  const {
    socket,
    navigate,
    playerKeys,
    pkHex,
    getPlayerKeys,
    addMessage,
    currentTableRef,
    currentTable,
    seatId,
    isPlayerSeated,
    leaveDeferred,
    setLeaveDeferred,
  } = params;

  const { walletAddress } = useContext(authContext)!;
  const connected = useAccount();
  // dev 直签账户（VITE_DEV_ACCOUNT_*，testnet 联调）优先于连接的钱包
  const account = activeAccount(connected.account);

  /**
   * 当玩家在手牌进行中且未 fold 时点击离开，置为 true 以触发确认弹窗。
   * Task 7 负责渲染弹窗；本 hook 只暴露状态和 confirm/cancel 处理函数。
   */
  const [showFoldLeaveConfirm, setShowFoldLeaveConfirm] = useState(false);
  // 保存触发确认弹窗时的 leaveTable 调用参数，供 confirmFoldLeave 使用
  const pendingLeaveParamsRef = useRef<{ shouldNavigate: boolean; pkHex?: string }>({
    shouldNavigate: true,
  });
  // 防止 performDeferredLeave 并发执行
  const deferredLeaveInFlightRef = useRef(false);
  // 捕获进入 deferred leave 流程时的原始 tableId / pkHex / 取消标志。
  // 必须使用 ref 而非 currentTableRef：用户可能在 Waiting 到来前导航离开并加入新表，
  // 此时 currentTableRef.current 指向新表，会对错误的表执行 standUp + LEAVE_TABLE。
  const deferredLeaveCtxRef = useRef<{
    tableId: number | string | null;
    pkHex: string;
    cancelled: boolean;
  }>({ tableId: null, pkHex: '', cancelled: false });

  // 进入 deferred leave 流程：捕获原始 tableId/pkHex 并设置 leaveDeferred
  const enterDeferredLeave = (
    tableId: number | string | null,
    pkHexToUse: string,
    shouldNavigate: boolean,
  ) => {
    deferredLeaveCtxRef.current = {
      tableId,
      pkHex: pkHexToUse,
      cancelled: false,
    };
    setLeaveDeferred(true);
    if (shouldNavigate) navigate('/');
  };

  // 用户在 deferred banner 上点击"取消离开"：置位 cancelled 以中断进行中的 performDeferredLeave
  const cancelDeferredLeave = () => {
    deferredLeaveCtxRef.current.cancelled = true;
    setLeaveDeferred(false);
  };

  const joinTable = (tableId: number, pk: string) => {
    logger.log(JOIN_TABLE, { tableId, pkHex: pk });
    socket?.emit(JOIN_TABLE, { tableId, pkHex: pk });
  };

  const leaveTable = async (shouldNavigate = true, pk?: string, fireAndForget = false) => {
    const table = currentTableRef.current;
    const tableId = table?.id;
    const roundState = table?.roundState;
    const mySeat = seatId != null && table?.seats ? table.seats[seatId] : null;
    const isFolded = !!(mySeat && mySeat.folded);

    // fireAndForget: 页面卸载，无法等待异步流程。
    // 已入座 → emit STAND_UP 标记 sitting_out；观察者 → emit LEAVE_TABLE 让后端清理。
    if (fireAndForget) {
      if (tableId != null) {
        if (isPlayerSeated) {
          socket?.emit(STAND_UP, { tableId, pkHex: pk || null, leaveRound: null });
        } else {
          socket?.emit(LEAVE_TABLE, { tableId, pkHex: pk || '' });
        }
      }
      return;
    }

    // 没有 table 或未入座：直接 emit LEAVE_TABLE + navigate
    if (!table || !tableId || !isPlayerSeated) {
      if (tableId != null) {
        socket?.emit(LEAVE_TABLE, { tableId, pkHex: pk || '' });
      }
      setLeaveDeferred(false);
      if (shouldNavigate) navigate('/');
      return;
    }

    // Waiting: 立即离桌
    if (roundState === RoundState.Waiting) {
      try {
        await standUp();
      } catch (e) {
        const err = e as Error;
        logger.error('[leaveTable] standUp failed:', e);
        addMessage(`Failed to leave table: ${err.message || e}`);
        return;
      }
      socket?.emit(LEAVE_TABLE, { tableId, pkHex: pk || '' });
      setLeaveDeferred(false);
      if (shouldNavigate) navigate('/');
      return;
    }

    // 已 fold 或 Showdown（手牌即将结束）：进入 deferred leave 流程，
    // 等待 roundState 回到 Waiting 后再真正离桌。
    if (isFolded || roundState === RoundState.Showdown) {
      socket?.emit(STAND_UP, { tableId, pkHex: pk || null, leaveRound: null });
      enterDeferredLeave(tableId, pk || '', shouldNavigate);
      return;
    }

    // 手牌进行中且未 fold：触发确认弹窗（Task 7 渲染弹窗）
    // 用户确认后调用 confirmFoldLeave -> fold() + deferred 路径
    pendingLeaveParamsRef.current = { shouldNavigate, pkHex: pk };
    setShowFoldLeaveConfirm(true);
    return;
  };

  /**
   * 当 roundState 转为 Waiting 且 leaveDeferred == true 时执行真正的离桌操作。
   * 使用 deferredLeaveCtxRef 中捕获的原始 tableId/pkHex，避免用户换桌后离错表；
   * 在 await standUp() 前后检查 cancelled 标志，支持 banner 取消中断。
   */
  const performDeferredLeave = async () => {
    if (deferredLeaveInFlightRef.current) return;
    const ctx = deferredLeaveCtxRef.current;
    if (!ctx.tableId) {
      setLeaveDeferred(false);
      return;
    }
    deferredLeaveInFlightRef.current = true;
    try {
      await standUp();
      // await 期间用户可能点了 banner "取消离开"，此时不应继续 emit LEAVE_TABLE
      if (deferredLeaveCtxRef.current.cancelled) {
        return;
      }
      socket?.emit(LEAVE_TABLE, { tableId: ctx.tableId, pkHex: ctx.pkHex || '' });
      setLeaveDeferred(false);
    } catch (e) {
      logger.error('[performDeferredLeave] failed:', e);
      addMessage(`Failed to complete leave: ${(e as Error).message || e}`);
      setLeaveDeferred(false);
    } finally {
      deferredLeaveInFlightRef.current = false;
    }
  };

  /**
   * 监听 leaveDeferred + currentTable.roundState：
   * 当 leaveDeferred == true 且 roundState == Waiting 时，执行 deferred leave。
   */
  useEffect(() => {
    if (!leaveDeferred) return;
    const roundState = currentTable?.roundState;
    if (roundState === RoundState.Waiting) {
      performDeferredLeave();
    }
  }, [leaveDeferred, currentTable]); // eslint-disable-line react-hooks/exhaustive-deps

  /**
   * 用户在确认弹窗中点击"确认 fold 并离开"。
   * 调用 fold() 后进入 deferred leave 流程（与已 fold 路径相同）。
   */
  const confirmFoldLeave = (shouldNavigate = true, pkHexArg?: string) => {
    setShowFoldLeaveConfirm(false);
    const table = currentTableRef.current;
    const tableId = table?.id;
    const usePkHex = pkHexArg ?? pkHex ?? '';
    if (!tableId) {
      setLeaveDeferred(false);
      return;
    }
    // 先 fold（后端会更新 seat.folded = true）
    fold();
    // 标记 sitting_out + deferred leave
    socket?.emit(STAND_UP, { tableId, pkHex: usePkHex || null, leaveRound: null });
    enterDeferredLeave(tableId, usePkHex, shouldNavigate);
  };

  /**
   * 用户在确认弹窗中点击"取消"：仅清除弹窗状态，不执行任何离桌操作。
   */
  const cancelFoldLeave = () => {
    setShowFoldLeaveConfirm(false);
    pendingLeaveParamsRef.current = { shouldNavigate: true };
  };

  const sitDown = async (tableId: string, seatIdNum: number, amount: number) => {
    const keys = playerKeys || getPlayerKeys();
    if (!keys) {
      logger.error('[SitDown] No player keys available');
      addMessage('Cannot sit down: no player keys');
      return;
    }
    if (!pkHex) {
      logger.error('[SitDown] No pkHex available');
      addMessage('Cannot sit down: no public key');
      return;
    }
    if (!currentTableRef.current) {
      logger.error('[SitDown] No current table');
      addMessage('Cannot sit down: no table data');
      return;
    }
    const token = getToken();
    if (!token) {
      logger.error('[SitDown] No auth token available');
      addMessage('Cannot sit down: please connect your wallet first');
      return;
    }
    if (!walletAddress) {
      logger.error('[SitDown] No wallet connected');
      addMessage('Cannot sit down: no wallet connected');
      return;
    }
    if (!account) {
      logger.error('[SitDown] No Starknet account available');
      addMessage('Cannot sit down: no Starknet account');
      return;
    }

    // ----- Starknet 买入（一次性）：私密路径优先（Plan B），公开路径回退 -----
    addMessage('Submitting the STRK20 buy-in...');
    const depositResult = await submitBuyIn(account, amount);
    if (!depositResult.success) {
      const failMsg = depositResult.error || 'Buy-in deposit failed';
      logger.error('[SitDown] vault.deposit failed:', failMsg);
      addMessage(`Sit down failed: ${failMsg}`);
      return;
    }
    logger.log('[SitDown] PokerVault deposit tx:', depositResult.hash);

    // ----- 入座（带重试）：bots 无限循环手牌时 deck 每 ~20s 变更一层，
    // 新玩家取牌组→生成证明→提交的间隙可能撞上变更（Invalid remask proof）。
    // 服务器把 join 失败经 error 事件回传，客户端据此自动重取牌组重试。
    const MAX_ATTEMPTS = 3;
    let depositTxHashUsed = depositResult.hash;
    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      // 每次尝试重新拉取最新 table/deck 状态
      let table = currentTableRef.current;
      try {
        const resp = await httpClient.get<Table>(`/tables/${tableId}`);
        if (resp.data) table = resp.data;
      } catch (e) {
        logger.warn('[SitDown] failed to fetch fresh table state, using local cache:', e);
      }
      const deckEncrypted = table.shuffleState?.deck_encrypted || table.deck?.cards;
      if (!deckEncrypted || deckEncrypted.length === 0) {
        logger.error('[SitDown] No deck_encrypted available');
        addMessage('Cannot sit down: no encrypted deck');
        return;
      }
      // 入座统一走 plain join（对齐 texas_poker_move main 的 join 语义）：
      // 仅提交 pk ownership proof，不动牌组——牌局中替换牌组会让在场玩家
      // 解不出手牌。玩家以 waiting 身份入座，reset_for_next_hand 后在下一手
      // 参与 start_preflop_shuffle 洗牌轮（SHUFFLE_NOTICE 流程既有实现）。
      // deck 竞态与 Invalid remask proof 由此彻底消除。
      let pkProof: unknown;
      try {
        const proofRaw = wrapCryptoOp(() => keys.generate_pk_proof(), 'generate_pk_proof') as string | object;
        pkProof = typeof proofRaw === 'string' ? JSON.parse(proofRaw) : proofRaw;
      } catch (e) {
        const err = e as Error;
        logger.error('[SitDown] pk proof generation failed:', err);
        addMessage(`Sit down failed: ${err.message || err}`);
        return;
      }

      // 提交并在窗口期内监听服务器回传的入座失败（deck 竞态可重试）。
      // 无错误回执即视为入座已受理（与既往乐观行为一致）。
      const outcome = await new Promise<{ failed: boolean; msg: string; retryable?: boolean } | null>((resolve) => {
        let settled = false;
        const onErr = (data: { msg?: string; action?: string; retryable?: boolean }) => {
          if (data?.action !== 'sit_down' || settled) return;
          settled = true;
          socket?.off('error', onErr);
          resolve({ failed: true, msg: data.msg ?? 'sit down rejected', retryable: data.retryable });
        };
        socket?.on('error', onErr);
        socket?.emit(SIT_DOWN_V2, {
          token,
          tableId,
          seatId: seatIdNum,
          amount,
          pkHex,
          pkProof,
          depositTxHash: depositTxHashUsed,
        });
        setTimeout(() => {
          if (!settled) {
            settled = true;
            socket?.off('error', onErr);
            resolve(null);
          }
        }, 6000);
      });

      if (outcome === null) {
        addMessage('Joined table and shuffled successfully');
        logger.log('[SitDown] join accepted (no error within window)');
        return;
      }
      const busyRetry = /洗牌|牌局进行中/.test(outcome.msg);
      if (!busyRetry && !/remask|shuffle|c1|deck|mismatch/i.test(outcome.msg)) {
        addMessage(`Sit down failed: ${outcome.msg}`);
        logger.error('[SitDown] join rejected:', outcome.msg);
        return;
      }
      logger.warn(`[SitDown] join deferred (attempt ${attempt}/${MAX_ATTEMPTS}): ${outcome.msg} — retrying`);
      addMessage(`桌面忙，正在自动重试入座（${attempt}/${MAX_ATTEMPTS}）…`);
      await new Promise((r) => setTimeout(r, 3000));
    }
  };

  const rebuy = (tableId: string, seatIdNum: number, amount: number) => {
    socket?.emit(REBUY, { tableId, seatId: seatIdNum, amount });
  };

  const standUp = async () => {
    if (!currentTableRef.current) return;
    const table = currentTableRef.current;

    const keys = playerKeys || getPlayerKeys();
    if (!keys) {
      logger.error('[StandUp] No player keys available');
      return;
    }

    const deckEncrypted = table.shuffleState?.deck_encrypted || table.deck?.cards;

    // 没有 deck（例如从未洗牌的座位）：直接走简单 stand up
    if (!deckEncrypted || deckEncrypted.length === 0) {
      logger.warn('[StandUp] No deck_encrypted, falling back to simple stand up');
      socket?.emit(STAND_UP, { tableId: table.id, pkHex, leaveRound: null });
      return;
    }

    // Starknet 模式：离桌证明走 socket 由后端验证（per-hand 操作全部离链，
    // 链上只涉及 PokerVault 的筹码出入）。
    let outputCardsJson: string;
    let leaveProofJson: string;
    let inputCards: unknown;
    try {
      const deckEncryptedJson = JSON.stringify(deckEncrypted);
      // Bug 修复（离开不亮牌）：剥层会公开 sk·c1（= 自己对各牌的 reveal
      // token），必须排除自己手牌的槽位。通过手牌密文 c1（reveal 生命周期
      // 不变）与牌组密文 c1 匹配定位槽位。验证方从发牌状态推导同一集合。
      const myHoleC1s = ownHoleC1Set();
      const excludedIndices: number[] = deckEncrypted
        .map((card: unknown, idx: number) => {
          const c1 = extractC1(card);
          return c1 && myHoleC1s.has(c1) ? idx : -1;
        })
        .filter((i: number) => i >= 0);
      const leaveResult = wrapCryptoOp(() => {
        const result = keys.leave_game(deckEncryptedJson, JSON.stringify(excludedIndices));
        if (!result) throw new Error('leave_game returned null');
        return typeof result === 'string' ? JSON.parse(result) : result;
      }, 'leave_game') as { input_cards: unknown; output_cards: unknown; leave_proof: unknown };

      inputCards = leaveResult.input_cards;
      outputCardsJson = JSON.stringify(leaveResult.output_cards);
      leaveProofJson = JSON.stringify(leaveResult.leave_proof);
    } catch (e) {
      const err = e as Error;
      logger.error('[StandUp] leave_game failed:', e);
      throw err;
    }

    await new Promise<void>((resolve, reject) => {
      let settled = false;

      const cleanup = () => {
        clearTimeout(timer);
        socket?.off(TABLE_UPDATED, onTableUpdated);
        socket?.off('error', onError);
      };

      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        cleanup();
        logger.warn('[StandUp] Timed out waiting for server response');
        reject(new Error('Stand up timed out waiting for server response'));
      }, STAND_UP_TIMEOUT_MS);

      // Server removes player and broadcasts TABLE_UPDATED
      const onTableUpdated = (data: TableUpdatedPayload) => {
        if (!data?.table) return;
        // Check if this player is no longer seated
        const stillSeated = pkHex
          ? Object.values(data.table.seats || {}).some(
              (seat: Seat) => seat.player?.pkHex === pkHex,
            )
          : false;
        if (!stillSeated) {
          if (settled) return;
          settled = true;
          cleanup();
          logger.log('[StandUp] Leave confirmed via TABLE_UPDATED');
          resolve();
        }
      };

      // Server emits error event on proof verification failure
      const onError = (data: { action?: string; msg?: string }) => {
        if (data?.action !== 'leave_with_proof_verified') return;
        if (settled) return;
        settled = true;
        cleanup();
        reject(new Error(data?.msg || 'Stand up failed on server'));
      };

      socket?.on(TABLE_UPDATED, onTableUpdated);
      socket?.on('error', onError);

      socket?.emit(STAND_UP, {
        tableId: table.id,
        pkHex,
        leaveRound: {
          input_cards: inputCards,
          output_cards: JSON.parse(outputCardsJson),
          leave_proof: JSON.parse(leaveProofJson),
        },
      });
    });
  };

  const fold = () => {
    currentTableRef &&
      currentTableRef.current &&
      socket?.emit(FOLD, currentTableRef.current.id);
  };

  const check = () => {
    currentTableRef &&
      currentTableRef.current &&
      socket?.emit(CHECK, currentTableRef.current.id);
  };

  const call = () => {
    currentTableRef &&
      currentTableRef.current &&
      socket?.emit(CALL, currentTableRef.current.id);
  };

  const raise = (amount: number) => {
    currentTableRef &&
      currentTableRef.current &&
      socket?.emit(RAISE, { tableId: currentTableRef.current.id, amount });
  };

  const sittingOut = () => {
    currentTableRef &&
      currentTableRef.current &&
      seatId != null &&
      socket?.emit(SITTING_OUT, { tableId: currentTableRef.current.id, seatId });
  };

  const sittingIn = () => {
    currentTableRef &&
      currentTableRef.current &&
      seatId != null &&
      socket?.emit(SITTING_IN, { tableId: currentTableRef.current.id, seatId });
  };

  const expelInitiate = (tableId: string, targetPlayerPk: string) => {
    socket?.emit(RECONSTRUCT_INITIATE, { tableId, targetPlayerPk });
  };

  return {
    joinTable,
    leaveTable,
    sitDown,
    rebuy,
    standUp,
    fold,
    check,
    call,
    raise,
    sittingOut,
    sittingIn,
    expelInitiate,
    showFoldLeaveConfirm,
    confirmFoldLeave,
    cancelFoldLeave,
    cancelDeferredLeave,
  };
};