import React from 'react';
import styled from 'styled-components';
import { Shield, ChevronDown, ChevronUp, CheckCircle2, XCircle, Clock } from 'lucide-react';
import CryptoEventStream from '../crypto/CryptoEventStream';
import NarrationOverlay from '../crypto/NarrationOverlay';
import { useContentContext } from '../../context/content/contentContext';
import type { CryptoEvent, Table, SettlementReceipt } from '../../types/game';

interface CryptoPanelProps {
  cryptoEvents: CryptoEvent[];
  currentTable: Table | null;
  showCryptoPanel: boolean;
  onToggle: () => void;
  /** D4 结算终局回执（handId → 最新；T4「已上链结算」印章实时数据源） */
  settlementReceipts?: Record<number, SettlementReceipt>;
}

// ZK 密码学事件浮动面板（可收起，位于右上角，不遮挡牌桌核心区域）
const PanelContainer = styled.div`
  position: fixed;
  top: 7.6rem;
  right: 0.8rem;
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
  background: ${({ $expanded }) => ($expanded ? '#14130f' : '#15507f')};
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

const SettlementStamp = styled.div<{ $status: 'settled' | 'refused' | 'failed' }>`
  display: flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.4rem 0.55rem;
  border-radius: 6px;
  font-size: 0.7rem;
  font-family: 'JetBrains Mono', monospace;
  border: 1px solid
    ${({ $status }) =>
      $status === 'settled' ? 'rgba(16,185,129,0.45)' : 'rgba(239,68,68,0.45)'};
  background: ${({ $status }) =>
    $status === 'settled' ? 'rgba(16,185,129,0.08)' : 'rgba(239,68,68,0.08)'};
  color: ${({ $status }) => ($status === 'settled' ? '#047857' : '#b91c1c')};
  flex-wrap: wrap;
`;

const StampMeta = styled.span`
  color: #64748b;
  font-size: 0.66rem;
`;

export const CryptoPanel: React.FC<CryptoPanelProps> = ({
  cryptoEvents,
  currentTable,
  showCryptoPanel,
  onToggle,
  settlementReceipts,
}) => {
  const { getLocalizedString } = useContentContext();
  // 洗牌层总数 N = 在座非 sitting_out 人数（洗牌发生在开局，此时无人弃牌）
  const shuffleParticipants = currentTable
    ? Object.values(currentTable.seats).filter((s) => s?.player && !s.sittingOut)
        .length || undefined
    : undefined;

  // D4/T4：当前手的最新结算回执（ClientTable.handId 对齐；无回执 = 待上链）
  const currentSettlement =
    settlementReceipts && currentTable?.handId
      ? settlementReceipts[currentTable.handId]
      : Object.values(settlementReceipts ?? {}).slice(-1)[0];

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
          {/* D4/T4：结算印章（settled/refused/failed 三态；无回执 = 待上链不渲染） */}
          {currentSettlement && (
            <SettlementStamp $status={currentSettlement.status}>
              {currentSettlement.status === 'settled' ? (
                <CheckCircle2 size={13} style={{ flexShrink: 0 }} />
              ) : (
                <XCircle size={13} style={{ flexShrink: 0 }} />
              )}
              <strong>
                {getLocalizedString(
                  currentSettlement.status === 'settled'
                    ? 'settlement_settled-stamp'
                    : currentSettlement.status === 'refused'
                      ? 'settlement_refused-stamp'
                      : 'settlement_failed-stamp',
                )}
              </strong>
              <StampMeta>
                hand #{currentSettlement.handSeq ?? currentSettlement.handId} ·{' '}
                {currentSettlement.exit}
              </StampMeta>
              {currentSettlement.blockNumber != null && (
                <StampMeta>
                  <Clock size={10} style={{ verticalAlign: -1, marginRight: 2 }} />
                  #{currentSettlement.blockNumber.toLocaleString()}
                </StampMeta>
              )}
              {currentSettlement.gasFee && <StampMeta>{currentSettlement.gasFee}</StampMeta>}
              {currentSettlement.reason && (
                <StampMeta style={{ flexBasis: '100%' }}>{currentSettlement.reason}</StampMeta>
              )}
            </SettlementStamp>
          )}
          {/* 紧凑版密码学事件流 */}
          <CryptoEventStream
            events={cryptoEvents}
            compact
            compactMaxItems={6}
            shuffleParticipants={shuffleParticipants}
          />
        </PanelContent>
      )}
    </PanelContainer>
  );
};
