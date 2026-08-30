import { useEffect, useState, useCallback } from 'react';
import httpClient from '../helpers/httpClient';
import setAuthToken from '../helpers/setAuthToken';
import { getToken } from '../helpers/getToken';
import { useGlobalContext } from '../context/global/globalContext';
import { useAccount } from '@starknet-react/core';
import { getStrkBalance } from '../starknet/starknetGameActions';
import { starknetConfig } from '../starknet/config';
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

/** Typed-data domain for the login message (SNIP-12). */
const LOGIN_DOMAIN = {
  name: 'zgame',
  version: '1',
  chainId: starknetConfig.chainId,
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

  const { address, account } = useAccount();

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
      const message = `zgame-login:${addr}:${Date.now()}`;
      // SNIP-12 typed message: 服务端需要 messageHash 做 isValidSignature 验证。
      const typedDataObj = {
        domain: LOGIN_DOMAIN,
        types: {
          StarkNetDomain: [
            { name: 'name', type: 'shortstring' },
            { name: 'version', type: 'shortstring' },
            { name: 'chainId', type: 'shortstring' },
          ],
          Message: [
            { name: 'contents', type: 'string' },
          ],
        },
        primaryType: 'Message',
        message: { contents: message },
      };
      const signature = await acct.signMessage(typedDataObj);
      const typedDataMod = await import('starknet');
      const messageHash = typedDataMod.typedData.getMessageHash(typedDataObj, addr);

      const res = await httpClient.post('/auth/wallet', {
        address: addr,
        messageHash,
        signature,
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
      localStorage.removeItem('token');
      logger.error('loadUser failed:', error);
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
    setWalletAddress(null);
    logout();
  }, [logout]);

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