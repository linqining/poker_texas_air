import React, { useContext, useEffect, useMemo, useState } from 'react';
import styled from 'styled-components';
import { ShieldCheck } from 'lucide-react';
import contentContext from '../../../context/content/contentContext';
import gameContext from '../../../context/game/gameContext';
import authContext from '../../../context/auth/authContext';
import globalContext from '../../../context/global/globalContext';
import { Table } from '../../../types/game';
import TicketHeader from './TicketHeader';
import StreetRail, { currentStreetIndex } from './StreetRail';
import PotBlock from './PotBlock';
import SeatEntry, { SeatTimer } from './SeatEntry';
import PaperCard from './PaperCard';
import { blindRoles, toCallAmount, potOdds } from '../../../helpers/tableDerived';
import { evaluateBestHand, rankLabel } from '../../../helpers/handEval';
import { fontMono } from '../../../styles/theme';

/**
 * 牌桌账簿主布局（design/table T1–T4）：
 * 票据抬头 → 街段栏 → 毡面（账格纸面：对手座位压上沿 + 公共牌 + 彩池合计 + 消息条）
 * → 页脚（玩家本人英雄卡 + 行动区）。
 */

const Root = styled.div`
  display: flex;
  flex-direction: column;
  flex: 1;
  min-height: 100dvh;
  background: ${({ theme }) => theme.colors.lightBg};
  color: ${({ theme }) => theme.colors.fontColorDark};
  text-align: left;
`;

const StreetBar = styled.div`
  flex: none;
  display: flex;
  align-items: center;
  gap: 18px;
  padding: 10px 22px;
  border-top: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  border-bottom: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  background: ${({ theme }) => theme.colors.lightBg};
  flex-wrap: wrap;
`;

const Chip = styled.span<{ $tone?: 'amb' | 'play' | 'default' }>`
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-size: 9.5px;
  letter-spacing: 0.09em;
  text-transform: uppercase;
  padding: 1.5px 6px;
  border: 1px solid ${({ theme }) => theme.colors.borderMuted};
  border-radius: 2px;
  color: ${({ theme }) => theme.colors.mutedText};
  background: ${({ theme }) => theme.colors.lightestBg};
  white-space: nowrap;
  font-weight: 500;
  ${({ $tone, theme }) => {
    if ($tone === 'amb')
      return `color: ${theme.colors.warning}; border-color: rgba(130,85,16,.4); background: rgba(130,85,16,.06); font-weight: 600;`;
    if ($tone === 'play')
      return `color: ${theme.colors.info}; border-color: rgba(21,80,127,.4); background: rgba(21,80,127,.06);`;
    return '';
  }}
`;

const BarNote = styled.span`
  margin-left: auto;
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  justify-content: flex-end;
`;

const FeltBody = styled.div`
  position: relative;
  flex: 1;
  min-height: 0;
`;

const Felt = styled.div`
  position: absolute;
  left: 12px;
  right: 12px;
  top: 8px;
  bottom: 8px;
  background: ${({ theme }) => theme.colors.surfaceMutedPlain};
  /* 账簿牌桌：椭圆毡面（design/table .felt 大圆角胶囊语言） */
  border-radius: 50%;
  &::before {
    content: '';
    position: absolute;
    inset: 0;
    border: 1px solid ${({ theme }) => theme.colors.borderMuted};
    border-radius: 50%;
  }
  &::after {
    content: '';
    position: absolute;
    inset: 6px;
    border: 1px solid ${({ theme }) => theme.colors.borderSubtle};
    border-radius: 50%;
    background: repeating-linear-gradient(
      180deg,
      transparent 0 25px,
      rgba(20, 19, 15, 0.045) 25px 26px
    );
  }
`;

const FeltTag = styled.span`
  position: absolute;
  left: 50%;
  top: 10px;
  transform: translateX(-50%);
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-size: 8.5px;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  color: ${({ theme }) => theme.colors.softerText};
  opacity: 0.7;
  white-space: nowrap;
  z-index: 1;
`;

const SeatsRail = styled.div`
  position: absolute;
  left: 50%;
  top: 36px;
  transform: translateX(-50%);
  display: flex;
  gap: 10px;
  z-index: 3;
  flex-wrap: wrap;
  justify-content: center;
  /* 显式宽度：绝对定位 + left:50% 时 shrink-to-fit 只剩右半幅，会错误折行 */
  width: min(96%, 1180px);
`;

const CenterStack = styled.div`
  position: absolute;
  left: 50%;
  top: 46%;
  transform: translate(-50%, -50%);
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 10px;
  z-index: 2;
`;

const BoardRow = styled.div`
  display: flex;
  gap: 7px;
  align-items: flex-start;
  justify-content: center;
`;

const BoardLabel = styled.div`
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-size: 8.5px;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  color: ${({ theme }) => theme.colors.softerText};
  display: flex;
  align-items: center;
  gap: 6px;
  white-space: nowrap;
  justify-content: center;
`;

const MsgStrip = styled.div`
  position: absolute;
  left: 50%;
  transform: translateX(-50%);
  bottom: 12px;
  display: flex;
  gap: 8px;
  flex-direction: column;
  align-items: center;
  z-index: 3;
  max-width: 94%;
`;

const Msg = styled.div<{ $ok?: boolean }>`
  background: ${({ theme }) => theme.colors.lightestBg};
  border: 1px solid ${({ theme }) => theme.colors.borderMuted};
  border-left: 3px solid ${({ $ok, theme }) => ($ok ? theme.colors.success : theme.colors.mutedText)};
  border-radius: 3px;
  padding: 6px 13px;
  font-size: 12px;
  color: ${({ theme, $ok }) => ($ok ? theme.colors.fontColorDark : theme.colors.mutedText)};
  box-shadow: ${({ theme }) => theme.other.cardDropShadow};
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 100%;
  b,
  .num {
    font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
    font-variant-numeric: tabular-nums;
    font-weight: 600;
    color: ${({ theme }) => theme.colors.fontColorDark};
  }
`;

const Watermark = styled.span`
  position: absolute;
  left: 22px;
  bottom: 10px;
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-size: 8px;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: ${({ theme }) => theme.colors.softerText};
  opacity: 0.55;
  pointer-events: none;
`;

const Footer = styled.footer`
  flex: none;
  background: ${({ theme }) => theme.colors.lightestBg};
  border-top: 1px solid ${({ theme }) => theme.colors.fontColorDark};
  padding: 12px 22px 14px;
  display: flex;
  align-items: center;
  gap: 20px;
  position: relative;
  flex-wrap: wrap;
`;

const HeroCard = styled.div<{ $accent?: 'felt' | 'ink' }>`
  width: 280px;
  flex: none;
  border: 1px solid ${({ $accent, theme }) => ($accent === 'felt' ? theme.colors.success : theme.colors.borderSubtle)};
  background: ${({ $accent, theme }) => ($accent === 'felt' ? 'rgba(11,107,69,.08)' : theme.colors.lightestBg)};
  border-radius: 3px;
  padding: 9px 11px;
`;

const HeroTop = styled.div`
  display: flex;
  align-items: center;
  gap: 8px;
  b {
    font-size: 12.5px;
    font-weight: 600;
    font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
    font-variant-numeric: tabular-nums;
  }
`;

const HeroAv = styled.div`
  width: 26px;
  height: 26px;
  border-radius: 2px;
  background: ${({ theme }) => theme.colors.fontColorDark};
  color: ${({ theme }) => theme.colors.fontColorLight};
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 10px;
  font-weight: 700;
  flex: none;
`;

const HeroHand = styled.div`
  display: flex;
  align-items: center;
  gap: 0;
  margin-top: 7px;
  .note {
    font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
    font-variant-numeric: tabular-nums;
    font-size: 10px;
    color: ${({ theme }) => theme.colors.success};
    font-weight: 600;
    margin-left: 9px;
  }
`;

const HeroSeal = styled.span`
  margin-left: auto;
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
  font-size: 9px;
  letter-spacing: 0.13em;
  text-transform: uppercase;
  padding: 3px 7px;
  border: 1.5px solid currentColor;
  border-radius: 2px;
  transform: rotate(-4deg);
  font-weight: 600;
  color: ${({ theme }) => theme.colors.success};
`;

const FootNote = styled.div`
  flex: 1;
  min-width: 220px;
  border: 1px solid ${({ theme }) => theme.colors.borderSubtle};
  border-left: 3px solid ${({ theme }) => theme.colors.softerText};
  border-radius: 3px;
  background: ${({ theme }) => theme.colors.lightestBg};
  font-size: 11.5px;
  color: ${({ theme }) => theme.colors.mutedText};
  padding: 10px 12px;
  line-height: 1.55;
  b {
    font-family: ${({ theme }) => theme.fonts.fontFamilySansSerif};
    font-variant-numeric: tabular-nums;
    color: ${({ theme }) => theme.colors.fontColorDark};
  }
`;

const fmt = (n: number) => new Intl.NumberFormat().format(n);

const streetNote = (rs: string): string => {
  const map: Record<string, string> = {
    waiting: '等待开盘',
    shuffling: '洗牌中',
    shuffleComplete: '洗牌完成',
    preFlopReveal: '翻前开牌',
    preFlop: '翻牌前下注',
    flopReveal: '翻牌开牌',
    flop: '翻牌圈',
    turnReveal: '转牌开牌',
    turn: '转牌圈',
    riverReveal: '河牌开牌',
    river: '河牌圈',
    showdownReveal: '摊牌开牌',
    showdown: '摊牌',
    handComplete: '本手结束',
  };
  return map[rs] ?? rs;
};

export interface PlayLedgerProps {
  table: Table;
  communityCards: { suit: string; rank: string }[];
  decryptedHandCards: string[];
  lastMessage: string | null;
  onSitDown: (seatNumber: number) => void;
  canSit: boolean;
  /** 页脚右侧动作区（GameUI 或等待提示），由 Play 装配 */
  actionSlot?: React.ReactNode;
  /** 街段栏右侧工具钮（离桌 / 牌局记录 / 凭证），由 Play 装配 */
  toolbar?: React.ReactNode;
  onOpenReceipt: () => void;
}

export const PlayLedger: React.FC<PlayLedgerProps> = ({
  table,
  communityCards,
  decryptedHandCards,
  lastMessage,
  onSitDown,
  canSit,
  actionSlot,
  toolbar,
  onOpenReceipt,
}) => {
  const { getLocalizedString } = useContext(contentContext)!;
  const { seatId } = useContext(gameContext)!;
  const { walletAddress } = useContext(authContext)!;
  const { chipsAmount } = useContext(globalContext)!;

  const roles = blindRoles(table);
  const heroSeat = seatId != null ? table.seats[seatId] : null;
  const heroHand = useMemo(
    () =>
      decryptedHandCards.map((cardStr) => ({
        suit: cardStr.slice(0, 1),
        rank: cardStr.slice(1),
      })),
    [decryptedHandCards],
  );

  // 对手席位：除英雄座外按座位号取前 4；未入座时取前 4（SEAT 5 由英雄位呈现）
  const railSeats = useMemo(() => {
    // 服务端 seats 只序列化在座座位——空位固定渲染为虚线待填行。
    // 未入座：5 席全上栏；已入座：4 个对手上栏，本人座位于页脚英雄卡。
    const all = [1, 2, 3, 4, 5];
    const withoutHero = heroSeat ? all.filter((n) => n !== seatId) : all;
    return withoutHero.slice(0, heroSeat ? 4 : 5);
  }, [heroSeat, seatId]);

  // 自己手牌牌型标注（公共牌齐才可评）
  const heroEval = useMemo(() => {
    if (!heroSeat) return null;
    const cards = [...heroSeat.hand, ...communityCards];
    return evaluateBestHand(cards);
  }, [heroSeat, communityCards]);

  const boardCount = communityCards.length || table.board.length || 0;
  const streetIdx = currentStreetIndex(table);
  const activeCount = Object.values(table.seats).filter(
    (s) => s?.player && !s.folded && !s.sittingOut,
  ).length;

  const statusNote = table.handOver
    ? getLocalizedString('game_state-info_wait')
    : streetNote(table.roundState);

  const toCall = seatId != null ? toCallAmount(table, seatId) : 0;
  const odds = seatId != null ? potOdds(table, seatId) : null;
  const heroStack = heroSeat?.stack ?? 0;
  const heroInvested = heroSeat?.totalBet ?? 0;

  return (
    <Root>
      <TicketHeader table={table} statusNote={statusNote} />

      <StreetBar>
        <StreetRail table={table} />
        <BarNote>
          {toolbar}
          <Chip $tone={table.handOver ? 'default' : 'play'}>
            roundState · {table.roundState}
          </Chip>
          {!table.handOver && (
            <Chip>
              在座 {activeCount} / 5
            </Chip>
          )}
          {toCall > 0 && !table.handOver && (
            <Chip>
              待跟 <b style={{ fontFamily: fontMono }}>{fmt(toCall)}</b>
              {odds != null ? ` · 赔率 ${odds} : 1` : ''}
            </Chip>
          )}
        </BarNote>
      </StreetBar>

      <FeltBody>
        <Felt />
        <FeltTag>公共区 · COMMON — 不归属任何玩家</FeltTag>

        <SeatsRail>
          {railSeats.map((n) => {
            // 胜者账目行回填（T4）：牌型来自 showdownHandRanks，金额从
            // winMessages 首条解析（"X wins $200 with Two Pair"）
            const rank = table.showdownHandRanks?.find((h) => h.seat === n)?.rank;
            const isWinnerSeat =
              table.handOver && table.seats[n]?.lastAction === 'WINNER';
            const winAmount = (() => {
              if (!isWinnerSeat) return null;
              const msg = table.winMessages?.[0] ?? '';
              const m = msg.match(/\$([\d,]+)/);
              return m ? Number(m[1].replace(/,/g, '')) : null;
            })();
            return (
            <SeatEntry
              key={n}
              table={table}
              seatNumber={n}
              winnerInfo={isWinnerSeat && rank ? { rank, amount: winAmount } : null}
              showdownRank={table.handOver ? (rank ?? null) : null}
              blindLabel={roles[n] === 'sb' ? getLocalizedString('game_seat-sb-lbl') : roles[n] === 'bb' ? getLocalizedString('game_seat-bb-lbl') : null}
              onSitDown={onSitDown}
              canSit={canSit}
            />
            );
          })}
        </SeatsRail>

        <CenterStack>
          <div>
            <BoardLabel>
              公共牌 {boardCount} / 5 · {boardCount === 0 ? '未发' : '已上链开牌'}
            </BoardLabel>
            <div style={{ height: 5 }} />
            <BoardRow>
              {[0, 1, 2, 3, 4].map((i) =>
                i < boardCount ? (
                  <PaperCard
                    key={i}
                    card={communityCards[i] ?? table.board[i]}
                  />
                ) : (
                  <PaperCard key={i} sealedIndex={i + 1} />
                ),
              )}
            </BoardRow>
          </div>
          <PotBlock table={table} />
        </CenterStack>

        <MsgStrip>
          {table.winMessages && table.winMessages.length > 0 && (
            <Msg $ok>{table.winMessages[table.winMessages.length - 1]}</Msg>
          )}
          {lastMessage && <Msg>{lastMessage}</Msg>}
          {table.handOver && (
            <Msg>
              <button
                onClick={onOpenReceipt}
                style={{
                  font: 'inherit',
                  border: 'none',
                  background: 'none',
                  cursor: 'pointer',
                  textDecoration: 'underline',
                  color: 'inherit',
                  padding: 0,
                }}
              >
                查看本手凭证 →
              </button>
            </Msg>
          )}
        </MsgStrip>

        <Watermark>
          zchain · appchain texas · hand #{table.handId ?? '—'}
        </Watermark>
      </FeltBody>

      <Footer>
        {heroSeat ? (
          <HeroCard $accent={table.handOver ? 'felt' : undefined}>
            <HeroTop>
              <HeroAv>你</HeroAv>
              <b>{walletAddress ? `${walletAddress.slice(0, 6)}…${walletAddress.slice(-4)}` : '—'}</b>
              <span style={{ fontFamily: fontMono, fontWeight: 600 }}>{fmt(heroStack)}</span>
              {table.handOver && (
                <HeroSeal>
                  <ShieldCheck size={11} strokeWidth={2} /> 已结算
                </HeroSeal>
              )}
            </HeroTop>
            {/* 轮到自己行动：与对手座位同款 T-XX 倒计时（绑定服务端截止） */}
            {heroSeat?.turn && !table.handOver && table.bettingStartedAt && table.bettingTimeoutMs ? (
              <SeatTimer
                deadline={table.bettingStartedAt + table.bettingTimeoutMs}
                totalMs={table.bettingTimeoutMs}
              />
            ) : null}
            <HeroHand>
              {heroHand.map((c, i) => (
                <span key={i} style={{ marginLeft: i > 0 ? -11 : 0 }}>
                  <PaperCard card={c} small />
                </span>
              ))}
              {heroEval && (
                <span className="note">
                  {getLocalizedString(heroEval.i18nKey)}
                  {heroEval.category === 'flush' || heroEval.category === 'royal-flush'
                    ? ''
                    : ` ${rankLabel(heroEval.mainRank)}`}
                </span>
              )}
            </HeroHand>
          </HeroCard>
        ) : (
          <HeroCard>
            <HeroTop>
              <HeroAv>?</HeroAv>
              <span style={{ fontSize: 12, color: '#5f5b50' }}>
                {canSit
                  ? `${getLocalizedString('game_sitdown-prompt')}`
                  : '观战模式 · SPECTATOR'}
              </span>
            </HeroTop>
            <div style={{ fontSize: 11, color: '#5f5b50', marginTop: 6 }}>
              {walletAddress ? (
                <>
                  已登录钱包{' '}
                  <span style={{ fontFamily: fontMono }}>
                    {walletAddress.slice(0, 6)}…{walletAddress.slice(-4)}
                  </span>
                  {` · 可用 ${fmt(chipsAmount ?? 0)} 筹码`}
                </>
              ) : (
                '连接钱包后可入座参与'
              )}
            </div>
          </HeroCard>
        )}

        {actionSlot ?? (
          <FootNote>
            {heroSeat ? (
              table.handOver ? (
                <>
                  本手已结算。你本手投入 <b>{fmt(heroInvested)}</b>，台费{' '}
                  <b>{fmt(table.rakeCollected)}</b>（{table.rakeBps ? `${table.rakeBps / 100}%，上限 ${fmt(table.rakeCap ?? 0)}` : '本场免台费'}）。
                </>
              ) : (
                <>
                  等待他人行动。你已投入 <b>{fmt(heroInvested)}</b>
                  {toCall > 0 && (
                    <>
                      ，当前需跟 <b>{fmt(toCall)}</b>
                    </>
                  )}
                  ；超时将自动弃牌。
                </>
              )
            ) : (
              <>
                入座即按盲注结构锁定买入，<b>{fmt(table.minBuyIn)} – {fmt(table.maxBuyIn)}</b>{' '}
                步进 <b>1,000</b>；筹码由链上 vault 入账，余量与每一手结算都以等宽数字记账。
              </>
            )}
          </FootNote>
        )}
      </Footer>
    </Root>
  );
};

export default PlayLedger;
