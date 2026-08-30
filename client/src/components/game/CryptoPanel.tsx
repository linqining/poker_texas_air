import React from 'react';
import styled from 'styled-components';
import { Shield, ChevronDown, ChevronUp } from 'lucide-react';
import CryptoEventStream from '../crypto/CryptoEventStream';
import NarrationOverlay from '../crypto/NarrationOverlay';
import { useContentContext } from '../../context/content/contentContext';
import type { CryptoEvent, Table } from '../../types/game';

interface CryptoPanelProps {
  cryptoEvents: CryptoEvent[];
  currentTable: Table | null;
  showCryptoPanel: boolean;
  onToggle: () => void;
}

// ZK 密码学事件浮动面板（可收起，位于右上角，不遮挡牌桌核心区域）
const PanelContainer = styled.div`
  position: fixed;
  top: 1rem;
  right: 1rem;
  z-index: 900;
  max-width: 320px;
  width: calc(100vw - 2rem);
  pointer-events: auto;
`;

const ToggleButton = styled.button<{ $expanded: boolean }>`
  display: flex;
  align-items: center;
  gap: 0.4rem;
  width: 100%;
  justify-content: space-between;
  background: ${({ $expanded }) =>
    $expanded ? 'rgba(15, 23, 42, 0.92)' : 'rgba(59, 130, 246, 0.92)'};
  color: #fff;
  border: none;
  border-radius: ${({ $expanded }) => ($expanded ? '8px 8px 0 0' : '8px')};
  padding: 0.45rem 0.7rem;
  font-size: 0.72rem;
  font-weight: 700;
  cursor: pointer;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.2);
  font-family: 'JetBrains Mono', monospace;
`;

const ToggleLabel = styled.span`
  display: flex;
  align-items: center;
  gap: 0.35rem;
`;

const EventCountBadge = styled.span`
  background: rgba(255, 255, 255, 0.25);
  border-radius: 10px;
  padding: 0 0.4rem;
  font-size: 0.62rem;
`;

const PanelContent = styled.div`
  background: rgba(255, 255, 255, 0.97);
  border-radius: 0 0 8px 8px;
  padding: 0.5rem;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
  max-height: 40vh;
  overflow-y: auto;
  overscroll-behavior: contain;
  display: flex;
  flex-direction: column;
  gap: 0.4rem;
`;

export const CryptoPanel: React.FC<CryptoPanelProps> = ({
  cryptoEvents,
  currentTable,
  showCryptoPanel,
  onToggle,
}) => {
  const { getLocalizedString } = useContentContext();

  return (
    <PanelContainer>
      {/* 折叠/展开切换按钮 */}
      <ToggleButton
        $expanded={showCryptoPanel}
        onClick={onToggle}
      >
        <ToggleLabel>
          <Shield size={13} />
          {getLocalizedString('play_zk-crypto-events')}
          {cryptoEvents.length > 0 && (
            <EventCountBadge>{cryptoEvents.length}</EventCountBadge>
          )}
        </ToggleLabel>
        {showCryptoPanel ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
      </ToggleButton>

      {/* 展开后的面板内容 */}
      {showCryptoPanel && (
        <PanelContent>
          {/* 当前阶段叙事（一行简短文案） */}
          {currentTable && (
            <NarrationOverlay
              phase={currentTable.roundState}
              cryptoEventCount={cryptoEvents.length}
            />
          )}
          {/* 紧凑版密码学事件流 */}
          <CryptoEventStream events={cryptoEvents} compact compactMaxItems={6} />
        </PanelContent>
      )}
    </PanelContainer>
  );
};
