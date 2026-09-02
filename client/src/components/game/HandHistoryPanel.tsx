import React, { useCallback, useEffect, useState } from 'react';
import styled, { useTheme } from 'styled-components';
import ModalShell from '../modals/ModalShell';
import Text from '../typography/Text';
import Button from '../buttons/Button';
import PokerCard from './PokerCard';
import { api, type HandHistoryRecord } from '../../api/secretPokerClient';
import { useContentContext } from '../../context/content/contentContext';
import { useLocaContext } from '../../context/localization/locaContext';

interface HandHistoryPanelProps {
  /** 桌号；null 时面板不渲染 */
  tableId: number | null;
  visible: boolean;
  onClose: () => void;
}

const List = styled.ul`
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
`;

const HandRow = styled.li`
  border: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  border-radius: ${({ theme }) => theme.radius.md};
  padding: 0.6rem 0.75rem;
  cursor: pointer;
  background: transparent;
  transition: background 0.15s ease;
  &:hover {
    background: rgba(255, 255, 255, 0.04);
  }
`;

const HandRowHeader = styled.div`
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 0.5rem;
  font-size: 0.85rem;
  color: ${({ theme }) => theme.colors.fontColorDark};
`;

const HandMeta = styled.span`
  color: ${({ theme }) => theme.colors.mutedText};
  font-size: 0.75rem;
  white-space: nowrap;
`;

const Badge = styled.span<{ $showdown: boolean }>`
  font-size: 0.7rem;
  padding: 0.1rem 0.45rem;
  border-radius: ${({ theme }) => theme.radius.pill};
  border: 1px solid
    ${({ $showdown, theme }) => ($showdown ? theme.colors.borderSubtle : 'transparent')};
  background: ${({ $showdown }) => ($showdown ? 'transparent' : 'rgba(255,255,255,0.06)')};
  color: ${({ theme }) => theme.colors.mutedText};
  white-space: nowrap;
`;

const BoardRow = styled.div`
  display: flex;
  gap: 0.25rem;
  margin-top: 0.5rem;
  flex-wrap: wrap;
`;

const WinLine = styled.div`
  margin-top: 0.35rem;
  font-size: 0.8rem;
  color: ${({ theme }) => theme.colors.fontColorDark};
`;

const DetailGrid = styled.div`
  margin-top: 0.5rem;
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(140px, 1fr));
  gap: 0.35rem 0.75rem;
  font-size: 0.78rem;
  color: ${({ theme }) => theme.colors.mutedText};
`;

const EmptyState = styled(Text)`
  text-align: center;
  padding: 1.5rem 0;
`;

const formatChips = (n: number) => `$${Number(n || 0).toFixed(2)}`;

const formatTime = (ms: number, lang: string) => {
  try {
    return new Date(ms).toLocaleString(lang === 'zh' ? 'zh-CN' : 'en-US', {
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return '';
  }
};

/**
 * 牌局记录看板（P0-2）：拉取 `/api/tables/:id/history` 最近手牌记录，
 * 行内展开公共牌/座位明细。数据来自服务器内存存储（每桌 ≤100 条，新→旧）。
 */
const HandHistoryPanel: React.FC<HandHistoryPanelProps> = ({ tableId, visible, onClose }) => {
  const theme = useTheme();
  const { getLocalizedString } = useContentContext();
  const { lang } = useLocaContext();
  const [records, setRecords] = useState<HandHistoryRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<number | null>(null);

  const load = useCallback(async () => {
    if (tableId == null) return;
    setLoading(true);
    setError(null);
    try {
      setRecords(await api.getHandHistory(tableId));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [tableId]);

  useEffect(() => {
    if (visible) {
      setExpanded(null);
      void load();
    }
  }, [visible, load]);

  if (!visible) return null;

  const labels = {
    title: getLocalizedString('game_history-title'),
    hand: getLocalizedString('game_history-hand-lbl'),
    pot: getLocalizedString('game_history-pot-lbl'),
    rake: getLocalizedString('game_rake-collected_lbl'),
    showdown: getLocalizedString('game_history-showdown-badge'),
    fold: getLocalizedString('game_history-fold-badge'),
    empty: getLocalizedString('game_history-empty'),
    refresh: getLocalizedString('game_history-refresh'),
  };

  return (
    <ModalShell
      width="lg"
      ariaLabel={labels.title}
      onBackdropClick={onClose}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <h2
          style={{
            margin: 0,
            fontFamily: theme.fonts.fontFamilySansSerif,
            fontSize: '1.3rem',
            fontWeight: 700,
            color: theme.colors.fontColorDark,
          }}
        >
          {labels.title}
        </h2>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <Button variant="secondary" small onClick={() => void load()} disabled={loading}>
            {labels.refresh}
          </Button>
          <Button variant="secondary" small onClick={onClose}>
            ✕
          </Button>
        </div>
      </div>

      {error && (
        <Text style={{ color: theme.colors.danger ?? '#ff6b6b' }}>{error}</Text>
      )}
      {loading && records.length === 0 && <Text textAlign="center">…</Text>}
      {!loading && !error && records.length === 0 && <EmptyState>{labels.empty}</EmptyState>}

      <List>
        {records.map((r) => {
          const isOpen = expanded === r.handSeq;
          return (
            <HandRow
              key={r.handSeq}
              onClick={() => setExpanded(isOpen ? null : r.handSeq)}
            >
              <HandRowHeader>
                <span>
                  {labels.hand} #{r.handSeq} · {labels.pot} {formatChips(r.grossPot)}
                  {r.rakeCollected > 0 && ` · ${labels.rake} ${formatChips(r.rakeCollected)}`}
                </span>
                <span style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                  <HandMeta>{formatTime(r.handOverAt, lang)}</HandMeta>
                  <Badge $showdown={r.wentToShowdown}>
                    {r.wentToShowdown ? labels.showdown : labels.fold}
                  </Badge>
                </span>
              </HandRowHeader>
              {r.winMessages.slice(0, isOpen ? undefined : 1).map((m, i) => (
                <WinLine key={i}>{m}</WinLine>
              ))}
              {isOpen && (
                <>
                  {r.board.length > 0 && (
                    <BoardRow>
                      {r.board.map((c, i) => (
                        <PokerCard key={i} card={c} width="2rem" />
                      ))}
                    </BoardRow>
                  )}
                  <DetailGrid>
                    {Object.entries(r.seats).map(([seatId, s]) => (
                      <span key={seatId}>
                        #{seatId} {s.player?.username || s.player?.id?.slice(0, 10) || '—'} ·{' '}
                        {labels.pot} {formatChips(s.stack)}
                      </span>
                    ))}
                  </DetailGrid>
                </>
              )}
            </HandRow>
          );
        })}
      </List>
    </ModalShell>
  );
};

export default HandHistoryPanel;
