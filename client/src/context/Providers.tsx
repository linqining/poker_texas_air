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
import { MotionConfig } from 'framer-motion';
import {
  StarknetConfig,
  starkscan,
  jsonRpcProvider,
  injected,
} from '@starknet-react/core';
import { sepolia, mainnet } from '@starknet-react/chains';

const queryClient = new QueryClient();

// Connector list（SETTLEMENT_PRIVACY_PLAN.md Part C：Ready 唯一钱包）：
// Ready Wallet（注入钱包，STRK20 Wallet API 的官方测试基线）承担登录验证、
// swap 兑换、买入扣款、私密领取奖励。Ready 的注入 id 历史上是 'argentX'，
// 改版后可能注册 'ready'——两个都挂，LoginModal 按 available() 过滤。
// Cartridge 已整体移除：其 #controller 覆盖层曾拦截全页点击、买入后强制
// 弹初始化窗；游戏交互签名由 plain join + 服务器会话承担，无需 session key。
const connectors = [
  injected({ id: 'argentX' }),
  injected({ id: 'ready' }),
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
        autoConnect
      >
        <ThemeProvider theme={theme}>
          {/* reducedMotion="user"：跟随系统 prefers-reduced-motion，
              framer-motion 自动只保留 opacity 类过渡、跳过 transform 动画 */}
          <MotionConfig reducedMotion="user">
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
          </MotionConfig>
        </ThemeProvider>
      </StarknetConfig>
    </QueryClientProvider>
  </BrowserRouter>
);

export default Providers;