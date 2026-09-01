import React from 'react';
import GlobalState from './global/GlobalState';
import AuthProvider from './auth/AuthProvider';
import LocaProvider from './localization/LocaProvider';
import ContentProvider from './content/ContentProvider';
import ModalProvider from './modal/ModalProvider';
import { ThemeProvider } from 'styled-components';
import theme from '../styles/theme';
import Normalize from '../styles/Normalize';
import GlobalStyles from '../styles/Global';
import { BrowserRouter } from 'react-router-dom';
import OfflineProvider from './offline/OfflineProvider';
import WebSocketProvider from './websocket/WebsocketProvider';
import PlayerProvider from './player/PlayerContext';
import GameState from './game/GameState';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import {
  StarknetConfig,
  starkscan,
  jsonRpcProvider,
  injected,
} from '@starknet-react/core';
import { cartridgeConnector } from '../starknet/cartridge';
import { sepolia, mainnet } from '@starknet-react/chains';

const queryClient = new QueryClient();

// Connector list（SETTLEMENT_PRIVACY_PLAN.md Part C：Ready 为首选钱包）：
// - Ready Wallet（注入钱包，STRK20 Wallet API 的官方测试基线）排最前：
//   登录验证、swap 兑换、买入扣款、私密领取奖励全部走 Ready——买入必须
//   扣用户 Ready 钱包里的钱。Ready 的注入 id 历史上是 'argentX'，改版后
//   可能注册 'ready'——两个都挂，LoginModal 按 available() 过滤并保持
//   本顺序（Ready 在前）。
// - Cartridge Controller（passkey smart wallet，session keys 免弹窗）仅作
//   备选，排在 Ready 之后；starknet-react autoConnect 优先重连上次使用
//   的连接器，首次连接时 UI 按 connectors 顺序展示 → Ready 优先。
const connectors = [
  injected({ id: 'argentX' }),
  injected({ id: 'ready' }),
  cartridgeConnector,
];

// Per-chain RPC endpoints (public Blast endpoints; override by editing here).
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

interface ProvidersProps {
  children: React.ReactNode;
}

const Providers: React.FC<ProvidersProps> = ({ children }) => (
  <BrowserRouter future={{ v7_relativeSplatPath: true, v7_startTransition: true }}>
    <QueryClientProvider client={queryClient}>
      <StarknetConfig
        chains={chains}
        provider={provider}
        connectors={connectors}
        explorer={starkscan}
      >
        <ThemeProvider theme={theme}>
          <GlobalState>
            <LocaProvider>
              <ContentProvider>
                <AuthProvider>
                  <ModalProvider>
                    <OfflineProvider>
                      <WebSocketProvider>
                        <PlayerProvider>
                          <GameState>
                            <Normalize />
                            <GlobalStyles />
                            {children}
                          </GameState>
                        </PlayerProvider>
                      </WebSocketProvider>
                    </OfflineProvider>
                  </ModalProvider>
                </AuthProvider>
              </ContentProvider>
            </LocaProvider>
          </GlobalState>
        </ThemeProvider>
      </StarknetConfig>
    </QueryClientProvider>
  </BrowserRouter>
);

export default Providers;