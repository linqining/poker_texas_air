import React, { useContext, useEffect, useState } from 'react';
import styled from 'styled-components';
import contentContext from '../../../context/content/contentContext';
import gameContext from '../../../context/game/gameContext';
import { Table } from '../../../types/game';
import { fontMono } from '../../../styles/theme';
import { PaperCard } from './PaperCard';

/**
 * 座位条目卡（design/table .seat-cd）：账目条目而非圆形头像。
 * 在座 = 方形纸卡（头像块 + 名 + 等宽余量右对齐 + 状态章 + 线性计时 + 注单引线）；
 * 空置 = 虚线待填行 + 行内「入座」。已弃牌保留在账页上（划销 + 虚线框）。
 */

const SeatWrap = styled.div<{ $turn: boolean; $folded: boolean }>`
  position: relative;
  width: clamp(150px, 18vw, 200px);
  max-width: 100%;
  opacity: ${({ $folded }) => ($folded ? 0.55 : 1)};
`;

const Card = styled.div<{ $turn: boolean; $folded: boolean }>`
  background: ${({ $folded, theme }) => ($folded ? 'transparent' : theme.colors.lightestBg)};
  border: 1px
    ${({ $folded, $turn, theme }) =>
      $folded ? `dashed 1px ${theme.colors.borderMuted}` : `solid 1px ${$turn ? theme.colors.fontColorDark : theme.colors.borderSubtle}`};
  border-radius: 3px;
  box-shadow: ${({ $folded, theme }) => ($folded ? 'none' : theme.other.cardDropShadow)};
  padding: 8px 10px;
  display: grid;
  grid-template-columns: 30px 1fr auto;
  gap: 9px;
  align-items: center;
  position: relative;
  ${({ $turn, theme }) =>
    $turn
      ? `&::before {
          content: '';
          position: absolute;
          left: -1px;
          top: -1px;
          bottom: -1px;
          width: 3px;
          background: ${theme.colors.warning};
        }`
      : ''}
`;

const Tag = styled.span`
  position: absolute;
  top: -9px;
  left: 9px;
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-size: 8.5px;
  letter-spacing: 0.1em;
  color: ${({ theme }) => theme.colors.softerText};
  background: ${({ theme }) => theme.colors.lightBg};
  padding: 0 4px;
  white-space: nowrap;
`;

const Avatar = styled.div`
  width: 30px;
  height: 30px;
  border-radius: 2px;
  flex: none;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 700;
  font-size: 12px;
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  background: ${({ theme }) => theme.colors.fontColorDark};
  color: ${({ theme }) => theme.colors.fontColorLight};
`;

const NameCol = styled.div<{ $folded: boolean }>`
  min-width: 0;
  b {
    display: block;
    font-size: 12.5px;
    font-weight: 600;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    ${({ $folded }) => ($folded ? 'text-decoration: line-through; text-decoration-thickness: 1px;' : '')}
  }
`;

const Stack = styled.span`
  display: flex;
  align-items: baseline;
  gap: 4px;
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-variant-numeric: tabular-nums;
  font-size: 13px;
  font-weight: 600;
  color: ${({ theme }) => theme.colors.fontColorDark};
  white-space: nowrap;
  margin-top: 1px;
`;

const StatusChip = styled.span<{ $tone: 'default' | 'felt' | 'amb' | 'bad' }>`
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-size: 9px;
  letter-spacing: 0.06em;
  padding: 1.5px 6px;
  border: 1px solid ${({ theme }) => theme.colors.borderMuted};
  border-radius: 2px;
  white-space: nowrap;
  font-weight: 500;
  align-self: center;
  ${({ $tone, theme }) => {
    const map = {
      default: '',
      felt: `color: ${theme.colors.success}; border-color: rgba(11,107,69,.4); background: rgba(11,107,69,.06);`,
      amb: `color: ${theme.colors.warning}; border-color: rgba(130,85,16,.4); background: rgba(130,85,16,.06);`,
      bad: `color: ${theme.colors.danger}; border-color: rgba(168,50,38,.4); background: rgba(168,50,38,.06);`,
    } as const;
    return map[$tone];
  }}
`;

const TimerRow = styled.div`
  margin-top: 5px;
  display: flex;
  align-items: center;
  gap: 7px;
  .num {
    font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
    font-variant-numeric: tabular-nums;
    font-size: 10px;
    color: ${({ theme }) => theme.colors.warning};
    font-weight: 600;
    letter-spacing: 0.04em;
  }
`;

const Meter = styled.div`
  flex: 1;
  height: 4px;
  background: ${({ theme }) => theme.colors.darkBg};
  border: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  border-radius: 1px;
  overflow: hidden;
  i {
    display: block;
    height: 100%;
    background: ${({ theme }) => theme.colors.warning};
  }
`;

const BetLine = styled.div`
  display: flex;
  align-items: baseline;
  gap: 6px;
  padding: 5px 6px 0;
  font-size: 10.5px;
  color: ${({ theme }) => theme.colors.mutedText};
  .lead {
    flex: 1;
    border-bottom: 1px dotted ${({ theme }) => theme.colors.borderMuted};
    transform: translateY(-3px);
    min-width: 14px;
  }
  .amt {
    font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
    font-variant-numeric: tabular-nums;
    font-weight: 600;
    color: ${({ theme }) => theme.colors.fontColorDark};
    font-size: 12px;
  }
  .amt.allin {
    color: ${({ theme }) => theme.colors.danger};
  }
  .amt.dim {
    font-weight: 400;
    color: ${({ theme }) => theme.colors.softerText};
  }
`;

// 摊牌亮牌（design T4 .seat-hand）：服务端在 showdown 广播所有未弃牌
// 座位的明牌（ClientSeat.hand），两张小牌交叠置于座卡下沿、牌型行之上。
const SeatHand = styled.div`
  margin-top: 5px;
  display: flex;
  align-items: flex-start;
`;

const VacantCard = styled(Card)`
  display: block;
  background: transparent;
  border: 1px dashed ${({ theme }) => theme.colors.borderMuted};
  box-shadow: none;
  padding: 11px 10px;
  text-align: center;
`;

const VacLabel = styled.div`
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-size: 8.5px;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  color: ${({ theme }) => theme.colors.softerText};
`;

const SitButton = styled.button`
  margin-top: 7px;
  height: 28px;
  padding: 0 14px;
  font-size: 12px;
  font-weight: 600;
  border: 1px solid ${({ theme }) => theme.colors.fontColorDark};
  border-radius: 3px;
  background: transparent;
  color: ${({ theme }) => theme.colors.fontColorDark};
  cursor: pointer;
  &:hover {
    background: ${({ theme }) => theme.colors.fontColorDark};
    color: ${({ theme }) => theme.colors.fontColorLight};
  }
`;

const fmt = (n: number) => new Intl.NumberFormat().format(n);

/** 线性回合计时（T-XX 等宽读数 + 细条），绑定服务端截止时间。 */
export const SeatTimer: React.FC<{ deadline: number; totalMs: number }> = ({ deadline, totalMs }) => {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const iv = setInterval(() => setNow(Date.now()), 250);
    return () => clearInterval(iv);
  }, [deadline]);
  const total = totalMs > 0 ? totalMs : 15000;
  const remaining = Math.max(deadline - now, 0);
  const frac = Math.min(remaining / total, 1);
  /* 读数按 total 钳制：客户端时钟偏差不应显示出比配置更长的剩余时间 */
  const secs = Math.ceil(Math.min(remaining, total) / 1000);
  return (
    <TimerRow>
      <span className="num">T-{String(secs).padStart(2, '0')}</span>
      <Meter>
        <i style={{ width: `${frac * 100}%` }} />
      </Meter>
    </TimerRow>
  );
};

export interface SeatEntryProps {
  table: Table;
  seatNumber: number;
  /** 角色标注（小盲/大盲；null 不显示） */
  blindLabel?: string | null;
  /** 空位点击入座（父级打开 T5 买入单据弹窗） */
  onSitDown?: (seatNumber: number) => void;
  /** 观战模式：空位不显示入座钮 */
  canSit?: boolean;
  /** 摊牌胜者信息（本手结束 + WINNER 座位时回填账目行）；金额缺失显示 — */
  winnerInfo?: { rank: string; amount: number | null } | null;
  /** 摊牌牌型（T4「三条 K」行：showdownHandRanks 广播的各家 rank，明牌不下发） */
  showdownRank?: string | null;
}

export const SeatEntry: React.FC<SeatEntryProps> = ({
  table,
  seatNumber,
  blindLabel,
  onSitDown,
  canSit,
  winnerInfo,
  showdownRank,
}) => {
  const { getLocalizedString } = useContext(contentContext)!;
  const { seatId } = useContext(gameContext)!;
  const seat = table.seats[seatNumber];
  const seatTag = `SEAT ${seatNumber}${blindLabel ? ` · ${blindLabel}` : ''}`;
  const seatNo = seatNumber.toString();

  if (!seat || !seat.player) {
    return (
      <SeatWrap $turn={false} $folded={false}>
        <VacantCard $turn={false} $folded={false}>
          <Tag>{seatTag}</Tag>
          <VacLabel>空置 Vacant</VacLabel>
          {canSit && (
            <div style={{ marginTop: 7 }}>
              <SitButton onClick={() => onSitDown?.(seatNumber)}>
                {getLocalizedString('game_sitdown-btn')}
              </SitButton>
            </div>
          )}
        </VacantCard>
      </SeatWrap>
    );
  }

  // 服务端 Seat::new 以 folded=true 作为「未参与本手」哨兵：刚买入/等待
  // 入局的座位也带 folded=true，但从未行动过（lastAction 为空）。真正
  // 弃牌必然经过 fold() → lastAction='fold'。据此区分：
  // - 等待入局（isWaiting 或 folded 且无行动记录）→ 「等待下一手」章
  // - 真弃牌 / 全下 / sitting out → 弃牌章（划销样式）
  const waitingToEnter =
    !!seat.isWaiting || (!!seat.folded && !seat.lastAction && !seat.sittingOut);
  const folded = !waitingToEnter && (!!seat.folded || !!seat.sittingOut);
  const allIn = !folded && seat.stack === 0;
  const acting = !!seat.turn && !table.handOver;
  const isHero = seatId === seat.id;

  const tone: 'default' | 'felt' | 'amb' | 'bad' = folded
    ? 'bad'
    : acting
      ? 'amb'
      : allIn
        ? 'bad'
        : seat.lastAction
          ? 'felt'
          : 'default';
  const statusText = folded
    ? getLocalizedString('game_seat-folded-lbl')
    : waitingToEnter
      ? getLocalizedString('game_seat-waiting-lbl')
      : acting
        ? getLocalizedString('game_seat-acting-lbl')
        : allIn
          ? getLocalizedString('game_ui_all-in')
          : seat.lastAction
            ? getLocalizedString('game_seat-acted-lbl')
            : getLocalizedString('game_seat-online-lbl');

  const name = seat.player.name || seat.player.pkHex.slice(0, 10);
  const initials = name.slice(0, 2).toUpperCase();

  // T4 亮牌：摊牌后服务端对未弃牌座位下发明牌（ClientSeat.hand）。
  // 弃牌座位底牌不公开（设计稿 sbar-note「弃牌 2 家底牌不公开」）。
  const revealedCards =
    table.handOver && !folded && Array.isArray(seat.hand) ? seat.hand.slice(0, 2) : [];

  const deadline =
    table.bettingStartedAt && table.bettingTimeoutMs
      ? table.bettingStartedAt + table.bettingTimeoutMs
      : null;

  return (
    <SeatWrap $turn={acting} $folded={folded}>
      <Card $turn={acting} $folded={folded}>
        <Tag>
          {seatTag}
          {isHero ? ' · 你' : ''}
        </Tag>
        <Avatar>{initials}</Avatar>
        <NameCol $folded={folded}>
          <b>{name}</b>
          <Stack>{fmt(seat.stack)}</Stack>
        </NameCol>
        <StatusChip $tone={tone}>{statusText}</StatusChip>
      </Card>
      {revealedCards.length >= 2 && (
        <SeatHand>
          {revealedCards.map((c, i) => (
            <span key={i} style={{ marginLeft: i > 0 ? -11 : 0 }}>
              <PaperCard card={c} small />
            </span>
          ))}
        </SeatHand>
      )}
      {acting && deadline && (
        <SeatTimer deadline={deadline} totalMs={table.bettingTimeoutMs ?? 15000} />
      )}
      {!folded && seat.lastAction !== 'WINNER' && (seat.bet > 0 || seat.lastAction) && (
        <BetLine>
          <span style={{ fontFamily: fontMono }}>{seat.lastAction ?? '下注'}</span>
          <span className="lead" />
          <span className={`amt ${allIn ? 'allin' : ''}`}>{seat.bet > 0 ? fmt(seat.bet) : '—'}</span>
        </BetLine>
      )}
      {folded && seat.bet > 0 && (
        <BetLine>
          <span style={{ fontFamily: fontMono }}>弃牌</span>
          <span className="lead" />
          <span className="amt dim">—</span>
        </BetLine>
      )}
      {seat.lastAction === 'WINNER' && table.handOver && (
        <BetLine>
          <span style={{ fontFamily: fontMono }}>
            {winnerInfo ? `${winnerInfo.rank}` : 'WINNER'}
          </span>
          <span className="lead" />
          <span className="amt">
            {winnerInfo?.amount != null ? `+${fmt(winnerInfo.amount)}` : '—'}
          </span>
        </BetLine>
      )}
      {table.handOver && seat.lastAction !== 'WINNER' && !folded && showdownRank && (
        <BetLine>
          <span style={{ fontFamily: fontMono }}>{showdownRank}</span>
          <span className="lead" />
          <span className="amt dim">—</span>
        </BetLine>
      )}
      <span data-seat={seatNo} style={{ display: 'none' }} />
    </SeatWrap>
  );
};

export default SeatEntry;
