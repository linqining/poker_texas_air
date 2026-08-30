// dev/testnet 浏览器联调直签账户（可选配置）。
//
// VITE_DEV_ACCOUNT_ADDRESS + VITE_DEV_ACCOUNT_PRIVATE_KEY 配置后，前端把该
// 账户当作"已连接钱包"：登录签名（SNIP-12 typed data）、兑换、买入、提现
// 全部用该账户直接签名提交到当前 RPC —— 无需 Cartridge 弹窗即可在浏览器里
// 真实跑通全流程（参考 starkware-libs/starknet-privacy demo 的 plain
// Account 用法）。生产环境不配置这两个变量，全部回退连接的钱包。
//
// provider 默认块用 PRE_CONFIRMED：测试网/本地节点交易在 accepted 前停留
// pre-confirmed，latest 读 nonce 会拿到过期值（52: Invalid transaction
// nonce）。Sepolia 公共 RPC（publicnode）同样支持 pre_confirmed。

import { Account, RpcProvider, BlockTag, type AccountInterface } from 'starknet';

let cachedAccount: Account | null = null;

export function isDevAccountConfigured(): boolean {
  const addr = import.meta.env.VITE_DEV_ACCOUNT_ADDRESS as string | undefined;
  const pk = import.meta.env.VITE_DEV_ACCOUNT_PRIVATE_KEY as string | undefined;
  return !!addr && !!pk;
}

export function getDevAccountAddress(): string | null {
  if (!isDevAccountConfigured()) return null;
  return (import.meta.env.VITE_DEV_ACCOUNT_ADDRESS as string).toLowerCase();
}

export function getDevAccount(): Account | null {
  if (!isDevAccountConfigured()) return null;
  if (!cachedAccount) {
    cachedAccount = new Account({
      provider: new RpcProvider({
        nodeUrl: import.meta.env.VITE_STARKNET_RPC_URL as string,
        blockIdentifier: BlockTag.PRE_CONFIRMED,
      }),
      address: import.meta.env.VITE_DEV_ACCOUNT_ADDRESS as string,
      signer: import.meta.env.VITE_DEV_ACCOUNT_PRIVATE_KEY as string,
    });
  }
  return cachedAccount;
}

/**
 * 活跃账户 = dev 直签账户（配置时）优先，否则连接的钱包账户。
 * hook 形态见 hooks/useActiveAccount.ts。
 */
export function activeAddress(connected: string | null | undefined): string | null {
  return getDevAccountAddress() ?? (connected ?? null);
}

export function activeAccount(connected: AccountInterface | null | undefined): AccountInterface | null {
  return getDevAccount() ?? (connected ?? null);
}
