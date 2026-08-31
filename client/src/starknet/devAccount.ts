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
 * 活跃账户解析（对齐 Cartridge 官方集成模型：Controller 是内嵌 iframe 的
 * passkey 智能钱包，无需浏览器插件；每个浏览器 profile 持有自己的 keychain
 * 账户，多账号联调 = 每个浏览器各自连接自己的 Controller 账户）。
 *
 * 连接的钱包（Cartridge Controller）**优先**——游戏身份必须跟随真实连接的
 * 账户，否则第二个浏览器永远拿不到自己的身份。dev 直签账户只在没有任何
 * 钱包连接时兜底（离线/本地联调）。
 * hook 形态见 hooks/useActiveAccount.ts。
 */
export function activeAddress(connected: string | null | undefined): string | null {
  return (connected ?? null) ?? getDevAccountAddress();
}

export function activeAccount(connected: AccountInterface | null | undefined): AccountInterface | null {
  return (connected ?? null) ?? getDevAccount();
}
