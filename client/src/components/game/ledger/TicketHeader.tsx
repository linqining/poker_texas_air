import React from 'react';
import styled from 'styled-components';
import { Table } from '../../../types/game';

/**
 * 票据抬头（design/table .tb-hd）：桌名 + 手数 + 盲注/最小加注/上限/链上锚点。
 * 底部齿孔线（perforation）为票据共同特征。
 */
const Wrap = styled.header`
  flex: none;
  display: flex;
  align-items: flex-start;
  gap: 14px;
  padding: 10px 22px 12px;
  background: ${({ theme }) => theme.colors.lightestBg};
  position: relative;
  &::after {
    content: '';
    position: absolute;
    left: 0;
    right: 0;
    bottom: 0;
    height: 1px;
    background: ${({ theme }) => theme.colors.borderMuted};
  }
`;

const Kind = styled.div`
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-size: 9.5px;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  color: ${({ theme }) => theme.colors.softerText};
`;

const Title = styled.div`
  font-size: 17px;
  font-weight: 700;
  letter-spacing: 0.01em;
  margin-top: 2px;
  display: flex;
  align-items: baseline;
  gap: 9px;
  flex-wrap: wrap;
`;

const Hand = styled.span`
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-variant-numeric: tabular-nums;
  font-size: 11px;
  font-weight: 500;
  color: ${({ theme }) => theme.colors.softerText};
  letter-spacing: 0.06em;
`;

const Right = styled.div`
  margin-left: auto;
  display: flex;
  align-items: center;
  gap: 7px;
  flex: none;
  padding-top: 4px;
  flex-wrap: wrap;
  justify-content: flex-end;
`;

const Net = styled.span`
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-variant-numeric: tabular-nums;
  font-size: 10.5px;
  color: ${({ theme }) => theme.colors.mutedText};
  border: 1px solid ${({ theme }) => theme.colors.borderMuted};
  border-radius: 2px;
  padding: 2px 7px;
  background: ${({ theme }) => theme.colors.lightestBg};
  white-space: nowrap;
`;

const fmt = (n: number) => new Intl.NumberFormat().format(n);

interface TicketHeaderProps {
  table: Table;
  /** 状态注（如「等待开盘」「轮到我行动」） */
  statusNote?: string;
}

export const TicketHeader: React.FC<TicketHeaderProps> = ({ table, statusNote }) => {
  const name = table.name || table.id;
  return (
    <Wrap>
      <div style={{ minWidth: 0 }}>
        <Kind>Texas Hold'em · No Limit · 5 seats</Kind>
        <Title>
          {name}
          <Hand>
            HAND #{table.handId ?? '—'}
            {statusNote ? ` · ${statusNote}` : ''}
          </Hand>
        </Title>
      </div>
      <Right>
        <Net>
          盲注 {fmt(table.smallBlind)} / {fmt(table.bigBlind)}
        </Net>
        {!!table.minRaise && <Net>最小加注 {fmt(table.minRaise)}</Net>}
        <Net>最小买入 {fmt(table.minBuyIn)}</Net>
        <Net>上限 {fmt(table.maxBuyIn)}</Net>
      </Right>
    </Wrap>
  );
};

export default TicketHeader;
