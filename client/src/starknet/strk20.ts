// STRK20 隐私领取（SETTLEMENT_PRIVACY_PLAN.md Part C3 / C5）。
//
// 「领取奖励」两条路径，均通过连接的钱包（Ready / Cartridge）执行：
//
// - 私密领取（首选）：STRK20 Wallet API 两动作模式（transfer amount=OPEN
//   + invoke PokerVaultAnonymizer.privacy_withdraw）。池先把用户屏蔽余额
//   里的 STRK 划给 helper，helper 按额烧毁 vault 筹码，再把等额 STRK 以
//   open note 记回（note owner 隐藏）→ 链上看不出是谁领走了奖励。
//   前提：钱包支持 Wallet API ≥0.10.3（Ready 是官方测试基线），且用户
//   池内屏蔽余额 ≥ 领取额（conservation 在池内闭环）。
// - 公开出金（回退）：vault.withdraw 直提钱包，边缘公开但功能等价。
//
// 能力探测按官方指引只用 `supportedWalletApi` 版本查询（≥0.10.3），绝不
// 用 strk20Balances 之类的数据调用做探测——那会触发钱包授权弹窗。

import { starknetConfig } from './config';
import { getProvider } from './contracts';
import { logger } from '../helpers/logger';
import type { TxResult } from './starknetGameActions';

const PAYOUT_SECRET_KEY = 'poker.payoutSecret';

/** 读取（或首次生成）本地 payout secret（capability，永不上报）。 */
export function getPayoutSecret(): string | null {
  let secret = localStorage.getItem(PAYOUT_SECRET_KEY);
  if (!secret) {
    const bytes = new Uint8Array(31);
    crypto.getRandomValues(bytes);
    bytes[0] = bytes[0] & 0x0f; // 保证 < 2^251（felt 合法域）
    secret =
      '0x' +
      [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
    localStorage.setItem(PAYOUT_SECRET_KEY, secret);
    logger.log('[strk20] payout secret generated');
  }
  return secret;
}

/** Wallet API 最低版本（STRK20 私密交易 + viewing key 体系）。 */
export const STRK20_WALLET_API_MIN = '0.10.3';

interface Strk20CapableAccount {
  strk20InvokeTransaction?: (actions: unknown[]) => Promise<{ transaction_hash: string }>;
  strk20Balances?: (tokens: string[]) => Promise<Array<{ token: string; balance: bigint }>>;
  supportedWalletApi?: (wallet?: unknown) => Promise<string[]>;
  execute?: (calls: unknown) => Promise<{ transaction_hash: string }>;
  address?: string;
}

/**
 * 获取注入的 STN-1 钱包对象（Ready 安装时即 window.starknet）。
 * STRK20 Wallet API 的私密交易必须经钱包对象（wallet.request）走
 * SNIP-36 证明管线——WalletAccount（starknet-react 连接产物）没有该表面。
 */
export function getInjectedStarknetWallet(): unknown {
  // Ready（argentX）注入的 EIP-6963 命名空间是 starknet_argentX /
  // starknet_ready（starknet-react ensureWallet 同款发现方式），legacy
  // window.starknet 作为兜底。
  const w = globalThis as unknown as Record<string, unknown>;
  return w.starknet_argentX ?? w.starknet_ready ?? w.starknet ?? null;
}

/**
 * 探测连接钱包是否具备 STRK20 私密交易能力（Wallet API ≥ 0.10.3）。
 * 依次探测：注入钱包对象（supportedWalletApi 版本查询，官方推荐方式）→
 * WalletAccountV6 方法存在性。绝不用数据类调用做探测（会触发授权弹窗）。
 */
export async function detectStrk20Support(account: unknown): Promise<boolean> {
  // 探测挂起保护：Ready 等注入代理在扩展锁定时 request 可能不响应
  const withTimeout = <T>(p: Promise<T>, ms = 5000): Promise<T> =>
    Promise.race([
      p,
      new Promise<T>((_, rej) => setTimeout(() => rej(new Error('probe timeout')), ms)),
    ]);
  const wallet = getInjectedStarknetWallet();
  if (wallet) {
    try {
      const { walletV6 } = await import('starknet');
      const versions = (await withTimeout(
        walletV6.supportedWalletApi(wallet as never) as Promise<string[]>,
      )) as string[];
      if (
        (versions ?? []).some(
          (v) => typeof v === 'string' && compareVersions(v, STRK20_WALLET_API_MIN) >= 0,
        )
      ) {
        return true;
      }
    } catch (e) {
      logger.warn('[strk20] wallet supportedWalletApi probe failed:', e);
    }
  }
  const acct = account as Strk20CapableAccount | null | undefined;
  if (acct && typeof acct.strk20InvokeTransaction === 'function') return true;
  if (acct && typeof acct.supportedWalletApi === 'function') {
    try {
      const versions = await acct.supportedWalletApi();
      return (versions ?? []).some(
        (v) => typeof v === 'string' && compareVersions(v, STRK20_WALLET_API_MIN) >= 0,
      );
    } catch (e) {
      logger.warn('[strk20] account supportedWalletApi probe failed:', e);
    }
  }
  return false;
}

/** 简单语义化版本比较（'0.10.3' vs '0.9.2' 等；非数字段按 0 处理）。 */
export function compareVersions(a: string, b: string): number {
  const pa = a.replace(/[^0-9.]/g, '').split('.').map((n) => parseInt(n, 10) || 0);
  const pb = b.replace(/[^0-9.]/g, '').split('.').map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i += 1) {
    const diff = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

/** 查询池内屏蔽余额（钱包会弹授权，仅在用户主动查看余额时调用）。 */
export async function getShieldedBalance(
  account: unknown,
  tokenAddress: string,
): Promise<bigint | null> {
  const wallet = getInjectedStarknetWallet();
  const acct = account as Strk20CapableAccount | null;
  if (!wallet || !acct?.strk20Balances) return null;
  try {
    let entries: Array<{ token: string; balance: string | bigint }>;
    if (typeof acct.strk20Balances === 'function') {
      entries = (await acct.strk20Balances([tokenAddress])) as Array<{
        token: string;
        balance: string | bigint;
      }>;
    } else {
      const { walletV6 } = await import('starknet');
      entries = (await walletV6.strk20Balances(wallet as never, [
        tokenAddress,
      ])) as Array<{ token: string; balance: string | bigint }>;
    }
    const norm = tokenAddress.toLowerCase();
    const hit = entries.find((e) => BigInt(e.token ?? 0n) === BigInt(tokenAddress));
    return hit ? BigInt(hit.balance) : 0n;
  } catch (e) {
    logger.warn('[strk20] shielded balance query failed:', e);
    return null;
  }
}

export interface ClaimRewardsArgs {
  /** 领取额（token wei，u256 上限内）。 */
  amountWei: bigint;
}

/**
 * 私密领取奖励（Ready/STRK20 两动作，单笔原子交易）：
 *   1. transfer amount="OPEN" → 开一张 open note（金额在执行时填入）；
 *   2. invoke privacy_withdraw(player, amount(u256), ${openNoteIds[0]})。
 * 池 → helper → 烧筹码 → open note，全在一笔池证明交易里；提交 envelope
 * 与 note owner 都不指向玩家。
 */
export async function claimRewardsPrivate(
  account: unknown,
  args: ClaimRewardsArgs,
): Promise<TxResult> {
  const wallet = getInjectedStarknetWallet();
  const { anonymizerAddress } = starknetConfig.privacy;
  const acct = account as Strk20CapableAccount | null;
  const hasWalletSurface = !!wallet && typeof (wallet as any).request === 'function';
  const hasAccountSurface = !!acct?.strk20InvokeTransaction && !!acct.address;
  if (!hasWalletSurface && !hasAccountSurface) {
    return { hash: '', success: false, error: 'Wallet does not support STRK20 private transactions' };
  }
  if (!acct?.address) {
    return { hash: '', success: false, error: 'Connected account address unavailable' };
  }
  if (!anonymizerAddress) {
    return { hash: '', success: false, error: 'PokerVaultAnonymizer address not configured' };
  }
  const amount = args.amountWei;
  if (amount <= 0n) {
    return { hash: '', success: false, error: 'Amount must be positive' };
  }
  const lo = (amount & 0xffffffffffffffffffffffffffffffffn).toString();
  const hi = (amount >> 128n).toString();
  const player = acct.address;
  const actions = [
    {
      type: 'transfer',
      token: starknetConfig.strk20Address,
      amount: 'OPEN',
      recipient: player,
    },
    {
      type: 'invoke',
      contract: anonymizerAddress,
      // calldata 顺序必须与 privacy_withdraw(player, amount:u256,
      // recipient_note_id) 完全一致；${openNoteIds[0]} 由钱包解析为
      // 上面 OPEN transfer 创建的 note。
      calldata: [player, lo, hi, '${openNoteIds[0]}'],
    },
  ];
  try {
    // 官方路径：walletV6.strk20InvokeTransaction(wallet, actions) —— SNIP-36
    // 证明与费用动作都在扩展内生成；回退 features 路径（等价形状）。
    let hash = '';
    if (wallet) {
      const { walletV6 } = await import('starknet');
      const res = await walletV6.strk20InvokeTransaction(wallet as never, actions as never);
      hash = res.transaction_hash ?? '';
    }
    if (!hash && typeof acct.strk20InvokeTransaction === 'function') {
      hash = (await acct.strk20InvokeTransaction(actions)).transaction_hash;
    }
    if (!hash && wallet) {
      const features = (wallet as any).features?.['starknet:walletApi'];
      if (!features?.request) throw new Error('wallet api feature unavailable');
      const res = (await features.request({
        type: 'wallet_strk20InvokeTransaction',
        params: { actions },
      })) as { transaction_hash?: string };
      hash = res.transaction_hash ?? '';
    }
    if (!hash) return { hash: '', success: false, error: 'wallet returned empty tx hash' };
    logger.log('[strk20] private claim submitted:', hash);
    return { hash, success: true };
  } catch (err) {
    logger.error('[strk20] private claim failed:', err);
    return { hash: '', success: false, error: String(err) };
  }
}

/**
 * 公开出金回退：vault.withdraw 直提钱包地址（边缘公开）。
 * Cartridge session policy 已预授权 withdraw；Ready 会弹一次确认。
 */
export async function claimRewardsPublic(
  account: unknown,
  args: ClaimRewardsArgs,
): Promise<TxResult> {
  const acct = account as Strk20CapableAccount | null;
  if (!acct?.execute || !acct.address) {
    return { hash: '', success: false, error: 'Wallet account unavailable' };
  }
  const { pokerVaultAddress } = starknetConfig;
  if (!pokerVaultAddress) {
    return { hash: '', success: false, error: 'PokerVault address not configured' };
  }
  const amount = args.amountWei;
  if (amount <= 0n) {
    return { hash: '', success: false, error: 'Amount must be positive' };
  }
  const lo = (amount & 0xffffffffffffffffffffffffffffffffn).toString();
  const hi = (amount >> 128n).toString();
  try {
    const res = await acct.execute({
      contractAddress: pokerVaultAddress,
      entrypoint: 'withdraw',
      calldata: [lo, hi],
    });
    const hash = res.transaction_hash;
    // 出金到账以交易落地为准；中继提交（paymaster）时哈希可能延迟可见。
    getProvider()
      .waitForTransaction(hash)
      .catch(() => logger.warn('[strk20] public withdraw receipt not visible yet:', hash));
    return { hash, success: true };
  } catch (err) {
    logger.error('[strk20] public withdraw failed:', err);
    return { hash: '', success: false, error: String(err) };
  }
}

/**
 * Part A Phase 1：注册赔付承诺（vault.register_payout_commitment）。
 * commitment = poseidon(secret)，secret 本地生成/保存——链上只见承诺。
 * 注册后，赢家在该手结算时即可从认领托管私密领取。
 * 返回 'registered'（已有）/ 'tx'（已提交注册交易）。
 */
/**
 * 查询玩家是否已在 vault 注册 payout commitment（链上真值）。
 * 返回 commitment 的 felt 值（0 = 未注册）。
 */
export async function getRegisteredPayoutCommitment(
  account: unknown,
): Promise<string | null> {
  const acct = account as { address?: string } | null;
  if (!acct?.address) return null;
  const { pokerVaultAddress } = starknetConfig;
  if (!pokerVaultAddress) return null;
  try {
    const s = await import('starknet');
    const provider = getProvider();
    const selector = '0x' + s.hash.starknetKeccak('payout_commitment').toString(16);
    const res = await provider.callContract({
      contractAddress: pokerVaultAddress,
      entrypoint: 'payout_commitment',
      calldata: [acct.address],
    });
    const v = BigInt(res[0] ?? 0);
    return v !== 0n ? '0x' + v.toString(16) : null;
  } catch (e) {
    logger.warn('[strk20] payout_commitment read failed:', e);
    return null;
  }
}

export async function ensurePayoutCommitment(account: unknown): Promise<
  { status: 'registered' | 'tx' } | { status: 'error'; error: string }
> {
  const acct = account as {
    address?: string;
    execute?: (calls: unknown) => Promise<{ transaction_hash: string }>;
  } | null;
  if (!acct?.execute || !acct.address) {
    return { status: 'error', error: 'wallet account unavailable' };
  }
  const { pokerVaultAddress } = starknetConfig;
  if (!pokerVaultAddress) {
    return { status: 'error', error: 'PokerVault address not configured' };
  }
  const secret = getPayoutSecret();
  if (!secret) return { status: 'error', error: 'cannot generate payout secret' };
  // 与合约 corelib Poseidon 同规范（单元素 H(x)）
  const s = await import('starknet');
  const commitment: string = '0x' + BigInt(
    s.hash.computePoseidonHashOnElements([secret]),
  ).toString(16);
  // 已注册则无需重复上链
  const provider = getProvider();
  const selector = await (async () => {
    const k = (s as unknown as { hash: { starknetKeccak: (n: string) => bigint } }).hash;
    return k ? k.starknetKeccak('payout_commitment') : null;
  })();
  if (selector) {
    try {
      const res = await (provider as unknown as {
        callContract: (c: unknown) => Promise<{ result: string[] }>;
      }).callContract({
        contractAddress: pokerVaultAddress,
        entryPointSelector: '0x' + selector.toString(16),
        calldata: [acct.address],
      });
      if (res.result?.[0] && BigInt(res.result[0]) !== 0n) {
        return { status: 'registered' };
      }
    } catch (e) {
      logger.warn('[strk20] payout_commitment read failed (continuing to register):', e);
    }
  }
  const res = await acct.execute({
    contractAddress: pokerVaultAddress,
    entrypoint: 'register_payout_commitment',
    calldata: [commitment],
  });
  logger.log('[strk20] payout commitment registered, tx:', res.transaction_hash);
  return { status: 'tx' };
}
