import { useEffect, useState, useCallback } from 'react';
import httpClient from '../helpers/httpClient';
import setAuthToken from '../helpers/setAuthToken';
import { getToken } from '../helpers/getToken';
import { useGlobalContext } from '../context/global/globalContext';
import { useAccount, useDisconnect } from '@starknet-react/core';
import { getStrkBalance } from '../starknet/starknetGameActions';
import { starknetConfig } from '../starknet/config';
import { activeAccount, activeAddress } from '../starknet/devAccount';
import type { AuthMethod } from '../context/auth/authContext';
import { logger } from '../helpers/logger';

interface UseAuthReturn {
  isLoggedIn: boolean;
  logout: () => void;
  loadUser: (token: string) => Promise<void>;
  walletAddress: string | null;
  disconnectWallet: () => void;
  authMethod: AuthMethod;
}

/** Typed-data domain for the login message (SNIP-12 revision 1). */
const LOGIN_DOMAIN = {
  name: 'zgame',
  version: '1',
  chainId: starknetConfig.chainId,
  revision: '1',
};

const useAuth = (): UseAuthReturn => {
  const token = getToken();
  if (token) setAuthToken(token);

  const {
    setId,
    setIsLoading,
    setUserName,
    setEmail,
    setChipsAmount,
    setStrkBalance,
  } = useGlobalContext();

  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [walletAddress, setWalletAddress] = useState<string | null>(
    localStorage.getItem('walletAddress')
  );
  const [authMethod, setAuthMethod] = useState<AuthMethod>(
    (localStorage.getItem('authMethod') as AuthMethod) || null
  );

  const { address: connectedAddress, account: connectedAccount } = useAccount();
  // Cartridge 文档模型：登出必须 disconnect Controller（断开 keychain 会话），
  // 否则连接仍在、自动重登立即登回同一账号，永远换不了用户。
  const { disconnect: disconnectConnector } = useDisconnect();
  // dev 直签账户（VITE_DEV_ACCOUNT_*，testnet 联调）优先于连接的钱包：
  // 登录签名、余额读取、游戏身份都用它，无需钱包弹窗。
  const address = activeAddress(connectedAddress);
  const account = activeAccount(connectedAccount);

  useEffect(() => {
    let cancelled = false;
    const init = async () => {
      setIsLoading(true);
      const storedToken = getToken();
      if (!storedToken) {
        localStorage.removeItem('walletAddress');
        localStorage.removeItem('authMethod');
        setWalletAddress(null);
        setAuthMethod(null);
      }
      if (storedToken) await loadUser(storedToken);
      if (!cancelled) setIsLoading(false);
    };
    init();
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Sync wallet address from starknet-react
  useEffect(() => {
    if (address) {
      setWalletAddress(address);
      localStorage.setItem('walletAddress', address);
    } else {
      setWalletAddress(null);
      localStorage.removeItem('walletAddress');
    }
  }, [address]);

  // Refresh STRK balance whenever the address changes
  useEffect(() => {
    if (!address) {
      setStrkBalance(null);
      return;
    }
    let cancelled = false;
    (async () => {
      const bal = await getStrkBalance(address);
      if (!cancelled) setStrkBalance(bal);
    })();
    return () => { cancelled = true; };
  }, [address, setStrkBalance]);

  // 会话过期统一处理：httpClient 在 401 时派发 zgame:session-expired，
  // 这里清理前端登录态（等同 logout，但不调后端——后端已不认识这个 token）。
  useEffect(() => {
    const onSessionExpired = () => {
      logger.warn('[Auth] session expired — clearing login state');
      localStorage.removeItem('token');
      localStorage.removeItem('walletAddress');
      localStorage.removeItem('authMethod');
      setWalletAddress(null);
      setAuthToken(null);
      setIsLoggedIn(false);
      setId(null);
      setUserName(null);
      setEmail(null);
      setChipsAmount(null);
      setStrkBalance(null);
      setAuthMethod(null);
    };
    window.addEventListener('zgame:session-expired', onSessionExpired);
    return () => window.removeEventListener('zgame:session-expired', onSessionExpired);
  }, [setId, setUserName, setEmail, setChipsAmount, setStrkBalance]);

  // Auto-authenticate with the backend after wallet connection
  useEffect(() => {
    if (address && !isLoggedIn && account) {
      const storedToken = getToken();
      if (!storedToken) {
        authenticateWithWallet(address, account).catch((e) =>
          logger.error('[Auth] wallet auth failed:', e)
        );
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [address, isLoggedIn, account]);

  const authenticateWithWallet = async (
    addr: string,
    acct: NonNullable<typeof account>,
  ): Promise<void> => {
    setIsLoading(true);
    try {
      // SNIP-12 rev1 typed message: 服务端需要 messageHash 做 isValidSignature 验证。
      // 约束来自 Cartridge controller wasm 内嵌的 starknet-core 严格解析：
      // - domain 类型名必须是 "StarknetDomain"（小写 net）且带 revision 字段；
      // - 只支持 felt/shortstring/ContractAddress/timestamp 等内置类型（无 ByteArray）；
      // - 每个字段值必须能编码成单个 felt（不能放长文本）。
      // 服务端只校验 (address, messageHash, signature)，不解析 message 内容。
      const message = `zgame-login:${addr}:${Date.now()}`;
      const typedDataObj = {
        domain: LOGIN_DOMAIN,
        types: {
          StarknetDomain: [
            { name: 'name', type: 'shortstring' },
            { name: 'version', type: 'shortstring' },
            { name: 'chainId', type: 'shortstring' },
            { name: 'revision', type: 'shortstring' },
          ],
          Message: [
            { name: 'action', type: 'shortstring' },
            { name: 'address', type: 'ContractAddress' },
            { name: 'timestamp', type: 'timestamp' },
          ],
        },
        primaryType: 'Message',
        message: {
          action: 'zgame-login',
          address: addr,
          timestamp: Math.floor(Date.now() / 1000),
        },
      };
      const signature = await acct.signMessage(typedDataObj);
      const typedDataMod = await import('starknet');
      const messageHash = typedDataMod.typedData.getMessageHash(typedDataObj, addr);
      // plain Account（dev 直签）的 signMessage / getMessageHash 返回 bigint，
      // axios 的 JSON 序列化无法处理 bigint（同步抛
      // "Do not know how to serialize a BigInt"）——统一转成 felt 字符串。
      const signatureFelts = Array.isArray(signature)
        ? signature.map((s) => String(s))
        : [String(signature)];

      const res = await httpClient.post('/auth/wallet', {
        address: addr,
        messageHash: String(messageHash),
        signature: signatureFelts,
        message,
      });

      const backendToken = res.data.token;
      if (backendToken) {
        localStorage.setItem('token', backendToken);
        setAuthToken(backendToken);
        await loadUser(backendToken);
        setAuthMethod('wallet');
        localStorage.setItem('authMethod', 'wallet');
      }
    } catch (error) {
      logger.error('[Auth] Wallet authentication failed:', error);
    }
    setIsLoading(false);
  };

  const loadUser = async (token: string): Promise<void> => {
    try {
      const res = await httpClient.get('/auth');
      const { _id, name, address: userAddress, chipsAmount } = res.data;
      setIsLoggedIn(true);
      setId(_id);
      setUserName(name);
      if (userAddress) {
        setWalletAddress(userAddress);
        localStorage.setItem('walletAddress', userAddress);
      }
      setChipsAmount(chipsAmount ?? 0);
    } catch (error) {
      // 登录会话已失效（401 token 无效 / 404 服务端重启清空了会话用户）：
      // 彻底清理前端登录态。但只在失败的 token 仍是当前存储 token 时清理——
      // 若自动重登已换发新 token（竞态），旧 token 的迟到失败必须忽略，
      // 否则会把新登录态清掉（Sign In 闪退）。
      const status = (error as { response?: { status?: number } })?.response?.status;
      const failedToken = getToken();
      if (failedToken !== token) {
        logger.warn('loadUser failed for a stale token — ignoring (already re-authenticated)');
        return;
      }
      logger.warn('loadUser failed (status=%s) — clearing login state:', status, error);
      localStorage.removeItem('token');
      localStorage.removeItem('walletAddress');
      localStorage.removeItem('authMethod');
      setAuthToken(null);
      setIsLoggedIn(false);
      setWalletAddress(null);
      setAuthMethod(null);
      setId(null);
      setUserName(null);
      setChipsAmount(null);
    }
  };

  const logout = useCallback((): void => {
    localStorage.removeItem('token');
    localStorage.removeItem('walletAddress');
    localStorage.removeItem('authMethod');
    setIsLoggedIn(false);
    setId(null);
    setUserName(null);
    setEmail(null);
    setChipsAmount(null);
    setStrkBalance(null);
    setAuthMethod(null);
  }, [setId, setUserName, setEmail, setChipsAmount, setStrkBalance]);

  const disconnectWallet = useCallback((): void => {
    const storedToken = getToken();
    if (storedToken) {
      httpClient.post('/auth/wallet/logout', {}).catch((err) => {
        logger.error('wallet_logout backend call failed:', err);
      });
    }
    // 先断开 Cartridge Controller 连接（passkey 会话失效），再清应用态。
    // 否则连接的 address 仍存在，自动重登 effect 会立刻登回同一账号。
    try {
      disconnectConnector();
    } catch (err) {
      logger.warn('connector disconnect failed:', err);
    }
    setWalletAddress(null);
    logout();
  }, [logout, disconnectConnector]);

  return {
    isLoggedIn,
    logout,
    loadUser,
    walletAddress,
    disconnectWallet,
    authMethod,
  };
};

export default useAuth;