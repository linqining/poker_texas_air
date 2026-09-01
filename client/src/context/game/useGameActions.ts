import { useContext, useEffect, useRef, useState, type MutableRefObject } from 'react';
import type { NavigateFunction } from 'react-router-dom';
import type { Socket } from 'socket.io-client';
import { compute_aggregate_key } from '@linqining/client-wasm';
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
import { JoinAndShuffleResult, TableUpdatedPayload, wrapCryptoOp } from './gameInternal';
import authContext from '../../context/auth/authContext';
import { logger } from '../../helpers/logger';
import { STAND_UP_TIMEOUT_MS } from '../../clientConfig';
import { useAccount } from '@starknet-react/core';
import { submitBuyIn } from '../../starknet/starknetGameActions';
import { activeAccount } from '../../starknet/devAccount';
import { initGameController } from '../../starknet/cartridge';

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

    const localTable = currentTableRef.current;
    if (!localTable) {
      logger.error('[SitDown] No current table');
      addMessage('Cannot sit down: no table data');
      return;
    }

    try {
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

      // 从服务器拉取最新的 table 状态，确保 deck_encrypted 与服务器同步
      // （localTable 可能在其他玩家 shuffle 完成前就已缓存，导致 c1 mismatch）
      let table = localTable;
      try {
        const resp = await httpClient.get<Table>(`/tables/${tableId}`);
        if (resp.data) {
          table = resp.data;
          logger.log('[SitDown] fetched fresh table state from server, deck cards:',
            table.deck?.cards?.length ?? 0, 'shuffleState deck:',
            table.shuffleState?.deck_encrypted?.length ?? 0);
        }
      } catch (e) {
        logger.warn('[SitDown] failed to fetch fresh table state, using local cache:', e);
      }

      const deckEncrypted = table.shuffleState?.deck_encrypted || table.deck?.cards;
      if (!deckEncrypted || deckEncrypted.length === 0) {
        logger.error('[SitDown] No deck_encrypted available');
        addMessage('Cannot sit down: no encrypted deck');
        return;
      }

      const pkHexes = (Object.values(table.seats) || [])
        .filter((p: Seat) => p.player && p.player.pkHex && p.player.pkHex !== pkHex)
        .map((p: Seat) => p.player!.pkHex);
      const pkHexesJson = JSON.stringify(pkHexes);
      const aggPkHex = compute_aggregate_key(pkHexesJson);

      const deckEncryptedJson = JSON.stringify(deckEncrypted);
      logger.log('SIT_DOWN_V2', tableId, seatIdNum, amount, pkHex, aggPkHex);
      const joinResultRaw = wrapCryptoOp(() => {
        const result = keys.join_game_and_shuffle(deckEncryptedJson, aggPkHex);
        if (!result) throw new Error('join_game_and_shuffle returned null');
        return result;
      }, 'join_game_and_shuffle') as string | object;
      const joinResult = typeof joinResultRaw === 'string' ? JSON.parse(joinResultRaw) : joinResultRaw as JoinAndShuffleResult;

      const maskAndShuffleRound = {
        mask_cards: joinResult.mask_and_shuffle_round.mask_cards,
        output_cards: joinResult.mask_and_shuffle_round.output_cards,
        remask_proof: joinResult.mask_and_shuffle_round.remask_proof,
        shuffle_proof: joinResult.mask_and_shuffle_round.shuffle_proof,
      };
      const pkProof = joinResult.pk_ownership_proof;
      logger.log('SIT_DOWN_V2', tableId, seatIdNum, amount, pkHex, pkProof, maskAndShuffleRound, keys.get_pk_hex(), getToken());

      // ----- Starknet 买入：私密路径优先（Plan B），公开路径回退 -----
      // 私密：STRK20 隐私池私密交易内由 anonymizer.deposit_for 给玩家记账，
      // 链上看不到付款人；公开：approve（幂等）+ deposit 经 paymaster 中继
      // 或 session 直签（Plan C）。depositTxHash 私密买入时可为空 —— 服务端
      // 以 vault.chip_balance 为权威校验。
      addMessage('Submitting the STRK20 buy-in...');
      const depositResult = await submitBuyIn(account, amount);
      if (!depositResult.success) {
        const failMsg = depositResult.error || 'Buy-in deposit failed';
        logger.error('[SitDown] vault.deposit failed:', failMsg);
        addMessage(`Sit down failed: ${failMsg}`);
        return;
      }
      logger.log('[SitDown] PokerVault deposit tx:', depositResult.hash);

      // 买入成功：自动初始化 Cartridge 游戏交互会话（session key，弹一次
      // 登录后静默）。不阻塞 SIT_DOWN_V2——初始化与入座并行。
      initGameController().catch(() => undefined);

      // 买入成功后通知 game server：后端校验 remask proof 并让玩家入座。
      socket?.emit(SIT_DOWN_V2, {
        token,
        tableId,
        seatId: seatIdNum,
        amount,
        pkHex,
        pkProof,
        maskAndShuffleRound,
        depositTxHash: depositResult.hash,
      });
      addMessage('Joined table and shuffled successfully');
    } catch (e) {
      const err = e as Error;
      logger.error('[SitDown] join_and_shuffle failed:', e);
      addMessage(`Sit down failed: ${err.message || e}`);
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