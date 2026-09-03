// 临时 UI 验证 harness（不进入生产路径，验证后删除）：
// 挂载真实 ClaimRewardsModal，配合 claim-harness.html 的假钱包/RPC 拦截，
// 验证三种注册状态渲染与折叠摘要展开交互。交易已被 html 层拦截，安全。
import React from 'react';
import { createRoot } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  StarknetConfig,
  jsonRpcProvider,
  injected,
  starkscan,
  useConnect,
} from '@starknet-react/core';
import { sepolia, mainnet } from '@starknet-react/chains';
import { ThemeProvider } from 'styled-components';
import theme from '../styles/theme';
import GlobalStyles from '../styles/Global';
import authContext from '../context/auth/authContext';
import ClaimModal from '../components/modals/ClaimRewardsModal';

const queryClient = new QueryClient();

const RPC_URLS: Record<string, string> = {
  [sepolia.id.toString()]: 'https://starknet-sepolia-rpc.publicnode.com',
  [mainnet.id.toString()]: 'https://starknet-rpc.publicnode.com',
};

const provider = jsonRpcProvider({
  rpc: (chain) => {
    const url = RPC_URLS[chain.id.toString()];
    return url ? { nodeUrl: url } : null;
  },
});

const chains = [sepolia, mainnet];
const connectors = [injected({ id: 'ready' }), injected({ id: 'argentX' })];

const mockAddr =
  ((window as unknown as { __MOCK_ADDR?: string }).__MOCK_ADDR ?? '').toLowerCase();

/** 挂载后立即静默连接 mock 钱包，让 useAccount 拿到 account */
const AutoConnect: React.FC = () => {
  const { connectAsync } = useConnect();
  React.useEffect(() => {
    const connector = connectors.find((c) => c.id === 'ready');
    if (!connector) return;
    connectAsync({ connector }).catch((e) => {
      // 连接失败也继续渲染：弹窗会停在「检测中」，便于发现回归
      console.error('[harness] mock connect failed:', e);
    });
  }, [connectAsync]);
  return null;
};

const Harness: React.FC = () => {
  const [open, setOpen] = React.useState(true);
  return (
    <QueryClientProvider client={queryClient}>
      <StarknetConfig
        chains={chains}
        provider={provider}
        connectors={connectors}
        explorer={starkscan}
      >
        <ThemeProvider theme={theme}>
          <GlobalStyles />
          <AutoConnect />
          <authContext.Provider
            value={{
              isLoggedIn: true,
              logout: () => {},
              loadUser: async () => {},
              walletAddress: mockAddr || null,
              disconnectWallet: () => {},
              authMethod: 'wallet',
            }}
          >
            <div style={{ maxWidth: 430, margin: '1.5rem auto', padding: '0 0.5rem' }}>
              <ClaimModal isOpen={open} chipsAmount={5000} onClose={() => setOpen(false)} />
              {open ? null : (
                <button type="button" onClick={() => setOpen(true)}>重新打开</button>
              )}
            </div>
          </authContext.Provider>
        </ThemeProvider>
      </StarknetConfig>
    </QueryClientProvider>
  );
};

createRoot(document.getElementById('root')!).render(<Harness />);
