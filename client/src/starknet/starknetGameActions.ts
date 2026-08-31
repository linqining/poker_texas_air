// Starknet game actions for the zgame frontend.
//
// In the Starknet world the
// client only needs to talk to two contracts for chip operations:
//   1. STRK20 (canonical Sepolia STRK) — approve the vault to pull STRK
//   2. PokerVault — deposit (pulls STRK via transferFrom, credits chips 1:1)
//                   and withdraw (sends STRK back to the player)
//
// Per-hand poker actions (fold/check/call/raise) stay off-chain through the
// existing zgame/texas game server. The on-chain surface is exclusively the
// chip economy.
//
// Plan C: 写操作统一经 submitCalls() 提交 —— paymaster 中继优先（链上发送者
// 与用户地址解耦），失败自动回退 session key 直签。

import { Account, Contract, RpcProvider, BlockTag, type Abi, cairo, uint256, type AccountInterface, type Call } from 'starknet';
import { STRK20_ABI, POKER_VAULT_ABI } from './abis';
import { starknetConfig, WEI_PER_CHIP } from './config';
import { POKER_VAULT_ANONYMIZER_ABI } from './abis';
import { getProvider } from './contracts';
import { submitCalls } from './paymaster';
import { buyInPrivately, isPrivateBuyInConfigured } from './privacyBuyIn';
import { logger } from '../helpers/logger';

export interface TxResult {
  /** Starknet transaction hash (hex 0x... string). */
  hash: string;
  success: boolean;
  error?: string;
}

function getStrk20Write(account: AccountInterface): Contract {
  return new Contract({
    abi: STRK20_ABI as Abi,
    address: starknetConfig.strk20Address,
    providerOrAccount: account,
  });
}

function getPokerVaultWrite(account: AccountInterface): Contract {
  if (!starknetConfig.pokerVaultAddress) {
    throw new Error(
      'PokerVault address is not configured. Set VITE_POKER_VAULT_ADDRESS.',
    );
  }
  return new Contract({
    abi: POKER_VAULT_ABI as Abi,
    address: starknetConfig.pokerVaultAddress,
    providerOrAccount: account,
  });
}

export async function getStrkBalance(address: string): Promise<bigint> {
  try {
    const contract = new Contract({
      abi: STRK20_ABI as Abi,
      address: starknetConfig.strk20Address,
      providerOrAccount: getProvider(),
    });
    const raw = await contract.balance_of(address);
    return uint256.uint256ToBN(raw);
  } catch (err) {
    logger.error('[starknet] getStrkBalance failed:', err);
    return 0n;
  }
}

export async function getChipBalance(address: string): Promise<bigint> {
  if (!starknetConfig.pokerVaultAddress) return 0n;
  try {
    const contract = new Contract({
      abi: POKER_VAULT_ABI as Abi,
      address: starknetConfig.pokerVaultAddress,
      providerOrAccount: getProvider(),
    });
    const raw = await contract.chip_balance(address);
    return uint256.uint256ToBN(raw);
  } catch (err) {
    logger.error('[starknet] getChipBalance failed:', err);
    return 0n;
  }
}

export async function getStrkAllowance(owner: string): Promise<bigint> {
  if (!starknetConfig.pokerVaultAddress) return 0n;
  try {
    const contract = new Contract({
      abi: STRK20_ABI as Abi,
      address: starknetConfig.strk20Address,
      providerOrAccount: getProvider(),
    });
    const raw = await contract.allowance(owner, starknetConfig.pokerVaultAddress);
    return uint256.uint256ToBN(raw);
  } catch (err) {
    logger.error('[starknet] getStrkAllowance failed:', err);
    return 0n;
  }
}

export async function approveStrkForVault(
  account: AccountInterface,
  amountWei: bigint,
): Promise<TxResult> {
  const owner = account.address;
  const existing = await getStrkAllowance(owner);
  if (existing >= amountWei) {
    logger.log('[starknet] existing STRK allowance covers amount, skipping approve');
    return { hash: '', success: true };
  }
  try {
    const strk = getStrk20Write(account);
    const call = strk.populate('approve', [
      starknetConfig.pokerVaultAddress,
      cairo.uint256(amountWei),
    ]);
    return await submitCalls(account, [call]);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.error('[starknet] approve failed:', msg);
    return { hash: '', success: false, error: msg };
  }
}

export function chipsToWei(chips: number): bigint {
  return BigInt(chips) * WEI_PER_CHIP;
}

/**
 * 统一买入入口（Plan B 优先，公开路径回退）：
 * 1. 私密买入（VITE_PRIVACY_BUYIN_ENABLED 且配置就绪）：STRK20 隐私池私密
 *    交易内由 PokerVaultAnonymizer.deposit_for 给玩家记账 —— 链上看不到付款人；
 *    失败/不可用时自动回退。
 * 2. 公开路径：approve（如需）+ deposit 经 paymaster 中继或 session 直签。
 *
 * 返回的 hash 私密买入时是私密交易哈希（或空 —— 服务端以 chip_balance 为权威）。
 */
export async function submitBuyIn(
  account: AccountInterface,
  chipAmount: number,
): Promise<TxResult> {
  if (isPrivateBuyInConfigured()) {
    const priv = await buyInPrivately(account, chipsToWei(chipAmount));
    if (priv.success) {
      return { hash: priv.hash, success: true };
    }
    logger.warn('[starknet] private buy-in failed; falling back to public path:', priv.error);
  }
  return depositForBuyIn(account, chipAmount);
}

export async function depositForBuyIn(
  account: AccountInterface,
  chipAmount: number,
): Promise<TxResult> {
  const wei = chipsToWei(chipAmount);
  try {
    // approve（如需）+ deposit 合并为一次提交：中继路径只占用一次 paymaster
    // 通道；直签路径 session policy 对两个 entrypoint 均静默放行。
    const calls: Call[] = [];
    const existing = await getStrkAllowance(account.address);
    if (existing < wei) {
      calls.push(
        getStrk20Write(account).populate('approve', [
          starknetConfig.pokerVaultAddress,
          cairo.uint256(wei),
        ]),
      );
    }
    calls.push(getPokerVaultWrite(account).populate('deposit', [cairo.uint256(wei)]));
    return await submitCalls(account, calls);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.error('[starknet] build deposit calls failed:', msg);
    return { hash: '', success: false, error: msg };
  }
}

export async function withdrawFromVault(
  account: AccountInterface,
  chipAmount: number,
): Promise<TxResult> {
  const wei = chipsToWei(chipAmount);
  try {
    // Plan D P2.2 (unshield)：私密出金开启时，筹码烧毁经 anonymizer 的
    // privacy_withdraw 完成（池内 STRK 守恒，出金 note 由池私密派发，
    // 玩家筹码账户与出金地址的关联被池切断）。请求经 POST 提交到
    // proving/pool 后端做私密交易组装——这里只发起出金意图。
    if (isUnshieldEnabled()) {
      return await withdrawViaPrivacyPool(account, wei);
    }
    const vault = getPokerVaultWrite(account);
    const call = vault.populate('withdraw', [cairo.uint256(wei)]);
    return await submitCalls(account, [call]);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.error('[starknet] vault.withdraw failed:', msg);
    return { hash: '', success: false, error: msg };
  }
}

/** VITE_UNSHIELD_ENABLED：私密出金开关（合约三件套部署齐备后开启）。 */
function isUnshieldEnabled(): boolean {
  return starknetConfig.privacy.unshieldEnabled;
}

/**
 * 私密出金意图提交：调 anonymizer 的 privacy_withdraw 需要在池的私密
 * 交易（InvokeExternal）内执行——与买入的 privacy_invoke 同机制，由
 * STRK20 钱包/SDK 的私密交易组装器发起。此处通过 STRK20 钱包 API
 * （privacyBuyIn 的同源通道）构建调用；未配置或钱包不支持时回退
 * 公开 withdraw，调用方提示用户隐私降级。
 */
async function withdrawViaPrivacyPool(
  account: AccountInterface,
  wei: bigint,
): Promise<TxResult> {
  const anonymizerAddress = starknetConfig.privacy.anonymizerAddress;
  if (!anonymizerAddress) {
    logger.warn('[starknet] unshield enabled but anonymizer address missing — public withdraw');
    const vault = getPokerVaultWrite(account);
    const call = vault.populate('withdraw', [cairo.uint256(wei)]);
    return await submitCalls(account, [call]);
  }
  try {
    const anonymizer = new Contract({
      abi: POKER_VAULT_ANONYMIZER_ABI as Abi,
      address: anonymizerAddress,
      providerOrAccount: account,
    });
    const noteId = Date.now(); // 出金 note 的客户端盐（池侧再混排）
    const call = anonymizer.populate('privacy_withdraw', [
      account.address,
      cairo.uint256(wei),
      noteId,
    ]);
    return await submitCalls(account, [call]);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.error('[starknet] privacy_withdraw failed:', msg);
    return { hash: '', success: false, error: msg };
  }
}
// ===== PokerSwap：固定 1 STRK = 1000 pSTRK 兑换 =====

const POKER_SWAP_ABI = [
  {
    name: 'PokerSwap',
    type: 'struct abi',
    items: [],
  },
  {
    type: 'function',
    name: 'swap',
    inputs: [{ name: 'strk_amount', type: 'core::integer::u256' }],
    outputs: [],
    state_mutability: 'external',
  },
  {
    type: 'function',
    name: 'fund_pstrk',
    inputs: [{ name: 'amount', type: 'core::integer::u256' }],
    outputs: [],
    state_mutability: 'external',
  },
] as const;

const STRK_ERC20_ABI = [
  {
    type: 'function',
    name: 'approve',
    inputs: [
      { name: 'spender', type: 'core::starknet::contract_address::ContractAddress' },
      { name: 'amount', type: 'core::integer::u256' },
    ],
    outputs: [{ type: 'core::bool' }],
    state_mutability: 'external',
  },
  {
    type: 'function',
    name: 'balance_of',
    inputs: [{ name: 'account', type: 'core::starknet::contract_address::ContractAddress' }],
    outputs: [{ type: 'core::integer::u256' }],
    state_mutability: 'view',
  },
] as const;

/** 规范 STRK 地址（mainnet/Sepolia/devnet 一致，与 PokerSwap 合约内一致）。 */
export const CANONICAL_STRK_ADDRESS =
  '0x4718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d';

export type SwapDirection = 'strk-to-pstrk' | 'pstrk-to-strk';

/** 兑换入口是否可用（配置了 PokerSwap 地址）。 */
export function isSwapConfigured(): boolean {
  return !!starknetConfig.swapAddress;
}

/**
 * devnet 浏览器联调用直签账户（可选，fallback）：VITE_DEV_ACCOUNT_ADDRESS +
 * VITE_DEV_ACCOUNT_PRIVATE_KEY 配置后，在没有任何钱包连接时，兑换交易用该
 * 账户直接签名提交到当前 RPC。有连接账户（Cartridge Controller）时不使用。
 */
export function getDevSwapAccount(): AccountInterface | null {
  const addr = import.meta.env.VITE_DEV_ACCOUNT_ADDRESS as string | undefined;
  const pk = import.meta.env.VITE_DEV_ACCOUNT_PRIVATE_KEY as string | undefined;
  if (!addr || !pk) return null;
  // devnet 的交易停留在 pre-confirmed 状态；默认 latest 读 nonce 会拿到旧值
  // （52: Invalid transaction nonce），与 starknet-privacy demo 一致改用
  // PRE_CONFIRMED 作为 provider 默认块。
  const provider = new RpcProvider({
    nodeUrl: import.meta.env.VITE_STARKNET_RPC_URL as string,
    blockIdentifier: BlockTag.PRE_CONFIRMED,
  });
  return new Account({ provider, address: addr, signer: pk });
}

/**
 * 双向固定汇率兑换（1 STRK = 1000 pSTRK）。直接构造 Call（不经 ABI 解析）：
 * - strk-to-pstrk：approve 规范 STRK → swap_strk_to_pstrk；
 * - pstrk-to-strk：approve pSTRK → swap_pstrk_to_strk（数量需整除 0.001）。
 * 完成后调用方需自行刷新余额。
 */
export async function swapTokens(
  account: AccountInterface,
  direction: SwapDirection,
  amountWei: bigint,
): Promise<TxResult> {
  if (!isSwapConfigured()) {
    return { hash: '', success: false, error: 'PokerSwap address not configured' };
  }
  if (direction === 'pstrk-to-strk' && amountWei % BigInt(SWAP_RATE) !== 0n) {
    return { hash: '', success: false, error: 'pSTRK 数量需为 0.001 的整数倍' };
  }
  try {
    const amount = uint256.bnToUint256(amountWei);
    const amountWords = [amount.low.toString(), amount.high.toString()];
    const swapAddress = starknetConfig.swapAddress;

    const approveCall: Call =
      direction === 'strk-to-pstrk'
        ? {
            contractAddress: CANONICAL_STRK_ADDRESS,
            entrypoint: 'approve',
            calldata: [swapAddress, ...amountWords],
          }
        : {
            contractAddress: starknetConfig.strk20Address,
            entrypoint: 'approve',
            calldata: [swapAddress, ...amountWords],
          };
    const swapCall: Call = {
      contractAddress: swapAddress,
      entrypoint:
        direction === 'strk-to-pstrk' ? 'swap_strk_to_pstrk' : 'swap_pstrk_to_strk',
      calldata: amountWords,
    };

    // 先 approve 再 swap：两笔独立交易（保证 nonce 顺序）。
    // 优先走连接的钱包（Cartridge Controller，session key 免弹窗）；
    // 无连接账户时才回退 dev 直签。dev 路径显式管理 nonce
    // （pre-confirmed 状态下自动 nonce 会读到过期值）。
    const devSigner = getDevSwapAccount();
    const signer = account ?? devSigner;
    const exec = signer as never as {
      execute: (c: Call, d?: { nonce?: string }) => Promise<{ transaction_hash: string }>;
    };

    if (!account && devSigner) {
      const nonce = await (devSigner as never as { getNonce: () => Promise<string> }).getNonce();
      const next = (BigInt(nonce) + 1n).toString();
      const r1 = await exec.execute(approveCall, { nonce });
      // 等 approve 落地再发 swap：公共 RPC 的 pre_confirmed 不一定立刻包含
      // 刚提交的交易，swap 的 estimateFee 模拟会因 allowance=0 revert。
      await getProvider().waitForTransaction(r1.transaction_hash);
      const r2 = await exec.execute(swapCall, { nonce: next });
      await getProvider().waitForTransaction(r2.transaction_hash);
      return { hash: r2.transaction_hash, success: true };
    }

    const r1 = await exec.execute(approveCall);
    await getProvider().waitForTransaction(r1.transaction_hash);
    const r2 = await exec.execute(swapCall);
    await getProvider().waitForTransaction(r2.transaction_hash);

    return { hash: r2.transaction_hash, success: true };
  } catch (err) {
    logger.error('[starknet] swapTokens failed:', err);
    return { hash: '', success: false, error: String(err) };
  }
}

/** 1 STRK = 1000 pSTRK。 */
export const SWAP_RATE = 1000;

/** 查询原生 STRK 余额（规范 fee token，用于兑换页展示）。 */
export async function getNativeStrkBalance(address: string): Promise<bigint> {
  try {
    const contract = new Contract({
      abi: STRK_ERC20_ABI as Abi,
      address: CANONICAL_STRK_ADDRESS,
      providerOrAccount: getProvider(),
    });
    const raw = await contract.balance_of(address);
    return uint256.uint256ToBN(raw);
  } catch (err) {
    logger.error('[starknet] getNativeStrkBalance failed:', err);
    return 0n;
  }
}

/** 查询 pSTRK 余额（PokerToken，同 getStrkBalance，语义别名）。 */
export async function getPstrkBalance(address: string): Promise<bigint> {
  return getStrkBalance(address);
}
