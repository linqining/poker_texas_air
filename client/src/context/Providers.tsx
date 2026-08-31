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
} from '@starknet-react/core';
import { cartridgeConnector } from '../starknet/cartridge';
import { sepolia, mainnet } from '@starknet-react/chains';

const queryClient = new QueryClient();

// Connector list. 仅保留 Cartridge Controller：passkey smart wallet with
// session keys — approve/deposit/withdraw run without per-action popups.
// （ArgentX/Braavos 注入钱包按产品决策下线。）
const connectors = [cartridgeConnector];

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