// Cartridge Controller integration — session keys so on-chain actions
// (approve / deposit / withdraw for buy-in and cash-out) do NOT prompt the
// wallet on every action.
//
// How it works: the Controller is a passkey-based smart wallet. At connect
// time the user approves a set of session policies (contract → entrypoints).
// Executing those entrypoints through the connected account is authorized by
// the session key client-side — no popup. Anything outside the policies
// (e.g. a one-time login signature) still prompts.
//
// starknet-react v5 has no first-class Cartridge connector, so we adapt the
// wallet-standard object (`ControllerConnector.asWalletStandard()`) to the
// `Connector` interface ourselves. The account handed to the app is
// starknet's `WalletAccount`, which routes execute/sign through the
// controller — session-authorized calls resolve silently.

import {
  Connector,
  ConnectorNotConnectedError,
  ConnectorNotFoundError,
  UserRejectedRequestError,
} from '@starknet-react/core';

/** Local structural equivalents of the connector-internal types. */
type ConnectorData = { account?: string; chainId?: bigint };
type ConnectorIcon = { dark: string; light: string };
import { ControllerConnector } from '@cartridge/connector';
import { FeeSource } from '@cartridge/controller';
import { WalletAccount, constants, type AccountInterface, type ProviderInterface } from 'starknet';
import { starknetConfig } from './config';

/** The wallet-standard object shape we rely on. The concrete type comes from
 * @starknet-io/get-starknet-core (a transitive dep); we duck-type it so our
 * direct imports stay minimal.
 *
 * The STN-1 wallet standard keeps capabilities in `features`:
 * - `standard:events` → { on, off }
 * - `starknet:walletApi` → { request } */
interface ControllerWallet {
  name: string;
  features: Record<string, unknown>;
}
function walletApi(wallet: ControllerWallet): {
  request(call: { type: string; params?: unknown }): Promise<unknown>;
} {
  const api = wallet.features['starknet:walletApi'] as {
    request(call: { type: string; params?: unknown }): Promise<unknown>;
  };
  if (!api?.request) throw new ConnectorNotConnectedError();
  return api;
}
/** WalletAccount（starknet v10）期待 wallet.request 直挂在对象上，而 STN-1
 * 钱包标准把 request 收在 features['starknet:walletApi'] 里——包一层兼容。 */
function withFlatRequestApi(
  wallet: Parameters<typeof WalletAccount.connect>[1],
): Parameters<typeof WalletAccount.connect>[1] {
  const duck = wallet as unknown as ControllerWallet;
  const flat = Object.assign(
    Object.create(Object.getPrototypeOf(wallet) ?? Object.prototype),
    wallet,
  ) as {
    request?: unknown;
    on?: unknown;
    off?: unknown;
  };
  if (typeof flat.request !== 'function') {
    flat.request = (call: { type: string; params?: unknown }) =>
      walletApi(duck).request(call);
  }
  if (typeof flat.on !== 'function') {
    const ev = () =>
      walletEvents(duck) as unknown as {
        on(event: string, handler: (...args: never[]) => void): void;
        off(event: string, handler: (...args: never[]) => void): void;
      };
    flat.on = (event: string, handler: (...args: never[]) => void) =>
      ev().on(event, handler);
    flat.off = (event: string, handler: (...args: never[]) => void) =>
      ev().off(event, handler);
  }
  return flat as Parameters<typeof WalletAccount.connect>[1];
}

function walletEvents(wallet: ControllerWallet): {
  on(event: string, handler: (...args: never[]) => void): void;
} {
  const events = wallet.features['standard:events'] as {
    on(event: string, handler: (...args: never[]) => void): void;
  };
  if (!events?.on) throw new ConnectorNotConnectedError();
  return events;
}

type SessionPolicies = ConstructorParameters<typeof ControllerConnector>[0] extends
  | { policies?: infer P }
  | undefined
  ? P
  : never;

// Session chain: Cartridge-hosted RPC for the default chain. Custom chains
// are possible but session infra (paymaster / keychain) lives on Cartridge.
const SESSION_RPC_URL =
  import.meta.env.VITE_CARTRIDGE_RPC_URL || 'https://api.cartridge.gg/x/starknet/sepolia';

function buildController(): ControllerConnector {
  const policies: NonNullable<SessionPolicies> = {
    contracts: {},
  };
  const contractPolicies = policies.contracts as Record<
    string,
    { methods: { entrypoint: string; description?: string }[] }
  >;

  if (starknetConfig.strk20Address) {
    contractPolicies[starknetConfig.strk20Address] = {
      methods: [
        { entrypoint: 'approve', description: 'Approve the vault to pull tokens for buy-in' },
      ],
    };
  }
  if (starknetConfig.pokerVaultAddress) {
    contractPolicies[starknetConfig.pokerVaultAddress] = {
      methods: [
        { entrypoint: 'deposit', description: 'Buy in chips (STRK → chips)' },
        { entrypoint: 'withdraw', description: 'Cash out chips (chips → STRK)' },
      ],
    };
  }
  if (starknetConfig.pokerSettlementAddress) {
    contractPolicies[starknetConfig.pokerSettlementAddress] = {
      methods: [
        { entrypoint: 'hand_settled' },
        { entrypoint: 'settlement_digest' },
      ],
    };
  }

  const options: ConstructorParameters<typeof ControllerConnector>[0] = {
    chains: [{ rpcUrl: SESSION_RPC_URL }],
    defaultChainId: constants.StarknetChainId.SN_SEPOLIA,
    policies,
    propagateSessionErrors: true,
    // Controller accounts pay fees from Cartridge credits or the AVNU
    // paymaster — self-held STRK is not a controller fee source. Default to
    // credits; the paymaster is AVNU's public service (flaky outside mainnet).
    feeSource: FeeSource.CREDITS,
  };
  return new ControllerConnector(options);
}

const controller = buildController();

/**
 * starknet-react Connector backed by the Cartridge Controller.
 * Mirrors the InjectedConnector flow, but the "injected wallet" is the
 * controller's wallet-standard object instead of a window global.
 */
export class CartridgeConnector extends Connector {
  private _wallet?: ControllerWallet;

  constructor() {
    super();
    this._wallet = controller.asWalletStandard() as unknown as ControllerWallet;
  }

  get id(): string {
    return 'controller';
  }

  get name(): string {
    return 'Cartridge (Session Keys)';
  }

  get icon(): ConnectorIcon {
    // Minimal inline glyph; the controller iframe supplies branded UI itself.
    const svg =
      '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="8" fill="#12141d"/><text x="16" y="22" font-family="monospace" font-size="18" fill="#ff7a00" text-anchor="middle">C</text></svg>';
    const b64 = btoa(svg);
    return {
      dark: `data:image/svg+xml;base64,${b64}`,
      light: `data:image/svg+xml;base64,${b64}`,
    };
  }

  available(): boolean {
    return this._wallet !== undefined;
  }

  async chainId(): Promise<bigint> {
    if (!this._wallet) throw new ConnectorNotConnectedError();
    // The session is pinned to defaultChainId at build time; the controller
    // wallet-standard surface does not expose starknet_chainId.
    return BigInt(constants.StarknetChainId.SN_SEPOLIA);
  }

  async ready(): Promise<boolean> {
    if (!this._wallet) return false;
    try {
      const permissions = (await walletApi(this._wallet).request({
        type: 'wallet_getPermissions',
      })) as string[];
      return permissions?.includes('accounts') ?? false;
    } catch {
      return false;
    }
  }

  async account(provider: ProviderInterface): Promise<AccountInterface> {
    if (!this._wallet) throw new ConnectorNotConnectedError();
    return WalletAccount.connect(
      provider,
      withFlatRequestApi(
        controller.asWalletStandard() as unknown as Parameters<
          typeof WalletAccount.connect
        >[1],
      ),
    );
  }

  async connect(_args?: { chainIdHint?: bigint }): Promise<ConnectorData> {
    if (!this._wallet) throw new ConnectorNotFoundError();
    walletEvents(this._wallet).on('accountsChanged', (accounts?: string[]) => {
      if (!accounts?.length) {
        this.emit('disconnect');
      } else {
        const account = accounts[0];
        this.chainId()
          .then((chainId) => this.emit('change', { account, chainId }))
          .catch(() => this.emit('change', { account }));
      }
    });
    walletEvents(this._wallet).on(
      'networkChanged',
      (chainIdHex?: string, accounts?: string[]) => {
        if (chainIdHex) {
          this.emit('change', {
            chainId: BigInt(chainIdHex),
            account: accounts?.[0],
          });
        } else {
          this.emit('change', {});
        }
      },
    );
    const accounts = (await walletApi(this._wallet).request({
      type: 'wallet_requestAccounts',
    })) as string[] | undefined;
    if (!accounts?.length) throw new UserRejectedRequestError();
    const chainId = await this.chainId();
    this.emit('connect', { account: accounts[0], chainId });
    return { account: accounts[0], chainId };
  }

  async disconnect(): Promise<void> {
    await controller.disconnect();
    this.emit('disconnect');
  }

  // The wallet-standard request surface is generic over the RPC message map;
  // rather than re-importing that peer's types we narrow through `never[]`
  // and let each call site assert its expected result type.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async request(call: { type: string; params?: unknown }): Promise<any> {
    if (!this._wallet) throw new ConnectorNotConnectedError();
    return walletApi(this._wallet).request(call);
  }

  /** Expose the underlying controller for session/profile management. */
  get sessionController(): ControllerConnector {
    return controller;
  }
}

export const cartridgeConnector = new CartridgeConnector();

// ---------------------------------------------------------------------------
// 游戏交互会话（SETTLEMENT_PRIVACY_PLAN.md Part C：钱包角色分工）
//
// Ready 承担登录验证、买入扣款、swap、私密领取；Cartridge 只在买入成功后
// 由应用自动初始化，作为游戏交互的签名会话（session key 免弹窗）。
// 每个 page 会话只初始化一次：首次弹出 controller 登录/创建（用户完成一次
// passkey），之后 keychain 会话静默复用。用户关闭弹窗则跳过，下笔买入再试。
// ---------------------------------------------------------------------------

let gameControllerInit = false;

export function isGameControllerReady(): boolean {
  return gameControllerInit;
}

export async function initGameController(): Promise<boolean> {
  if (gameControllerInit) return true;
  gameControllerInit = true;
  try {
    // ControllerConnector.connect：keychain 已有会话时静默返回；否则弹出
    // controller 登录/创建 UI（用户完成一次即可）。
    await controller.connect();
    return true;
  } catch (e) {
    // eslint-disable-next-line no-console
    console.warn('[cartridge] game controller init skipped:', e);
    gameControllerInit = false;
    return false;
  }
}
