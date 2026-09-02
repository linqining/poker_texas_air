import React, { useContext, useEffect, useState } from 'react';
import ReactDOM from 'react-dom';
import { useTheme } from 'styled-components';
import Container from '../components/layout/Container';
import Button from '../components/buttons/Button';
import ModalShell from '../components/modals/ModalShell';
import gameContext from '../context/game/gameContext';
import socketContext from '../context/websocket/socketContext';

import PokerTable from '../components/game/PokerTable';
import { RotateDevicePrompt } from '../components/game/RotateDevicePrompt';
import { PositionedUISlot } from '../components/game/PositionedUISlot';
import { PokerTableWrapper } from '../components/game/PokerTableWrapper';
import { Seat } from '../components/game/Seat';
import Text from '../components/typography/Text';
import { useModalContext } from '../context/modal/modalContext';
import { useNavigate } from 'react-router-dom';
import { TableInfoWrapper } from '../components/game/TableInfoWrapper';
import { InfoPill } from '../components/game/InfoPill';
import { GameUI } from '../components/game/GameUI';
import { GameStateInfo } from '../components/game/GameStateInfo';
import PokerCard from '../components/game/PokerCard';
import { useContentContext } from '../context/content/contentContext';
import { PlayerContext } from '../context/player/PlayerContext';
import Loader from '../components/loading/Loader';
import { logger } from '../helpers/logger';
import { useTableJoin } from '../hooks/useTableJoin';
import { CryptoPanel } from '../components/game/CryptoPanel';
import { KickNotification } from '../components/game/KickNotification';
import HandHistoryPanel from '../components/game/HandHistoryPanel';
import { ActionLoadingOverlay, LeavingOverlay, LeaveDeferredBanner } from './Play.styles';


// 5 个座位的绝对定位布局，用于 .map() 渲染，避免重复的 PositionedUISlot + Seat 块
interface SeatLayout {
  seatNumber: number;
  top?: string;
  bottom?: string;
  left?: string;
  right?: string;
  scale: string;
  origin: string;
}
const SEAT_LAYOUTS: SeatLayout[] = [
  { seatNumber: 1, top: '-5%', left: '0', scale: '0.55', origin: 'top left' },
  { seatNumber: 2, top: '-5%', scale: '0.55', origin: 'top center' },
  { seatNumber: 3, top: '-5%', right: '2%', scale: '0.55', origin: 'top right' },
  { seatNumber: 4, bottom: '15%', right: '2%', scale: '0.55', origin: 'bottom right' },
  { seatNumber: 5, bottom: '15%', left: '0', scale: '0.55', origin: 'bottom left' },
];

const Play: React.FC = () => {
  const navigate = useNavigate();
  const theme = useTheme();
  const { socket, isConnected } = useContext(socketContext)!;
  const { openModal } = useModalContext();
  const {
    messages,
    currentTable,
    communityCards,
    isPlayerSeated,
    seatId,
    joinTable,
    leaveTable,
    sitDown,
    fold,
    check,
    call,
    raise,
    kickNotification,
    clearKickNotification,
    cryptoEvents,
    isActionLoading,
    startActionLoading,
    leaveDeferred,
    showFoldLeaveConfirm,
    confirmFoldLeave,
    cancelFoldLeave,
    cancelDeferredLeave,
    sittingIn,
  } = useContext(gameContext)!;
  const { getLocalizedString } = useContentContext();
  const { pkHex } = useContext(PlayerContext)!;

  const [bet, setBet] = useState(0);
  const [isLeaving, setIsLeaving] = useState(false);
  // ZK 密码学事件面板开关（默认收起，避免遮挡牌桌核心区域）
  const [showCryptoPanel, setShowCryptoPanel] = useState(false);
  // 牌局记录看板开关（P0-2）
  const [showHistoryPanel, setShowHistoryPanel] = useState(false);

  /**
   * Portrait detection: supplements the CSS-only <RotateDevicePrompt /> with
   * a runtime check so we can degrade the rendered tree to a minimal stub
   * when the user is in portrait. The CSS prompt is still the primary
   * deterrent (full-screen overlay), but this hook lets us short-circuit
   * the seat/socket join logic in the rare case the overlay is dismissed
   * (e.g. via DevTools) — preventing the table from running in an
   * unusable layout.
   */
  const [isPortrait, setIsPortrait] = useState<boolean>(() => {
    if (typeof window === 'undefined') return false;
    return window.matchMedia('(orientation: portrait)').matches;
  });

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const mql = window.matchMedia('(orientation: portrait)');
    const onChange = (e: MediaQueryListEvent) => setIsPortrait(e.matches);
    // matchMedia.addEventListener is the modern API; addListener is the
    // Safari < 14 fallback. Both are no-ops if already registered.
    if (mql.addEventListener) mql.addEventListener('change', onChange);
    else mql.addListener(onChange);
    return () => {
      if (mql.removeEventListener) mql.removeEventListener('change', onChange);
      else mql.removeListener(onChange);
    };
  }, []);

  useTableJoin({
    socket,
    isConnected,
    pkHex,
    currentTable,
    joinTable,
    leaveTable,
    openModal,
    navigate,
    getLocalizedString,
  });

  useEffect(() => {
    if (currentTable && seatId != null && currentTable.seats && currentTable.seats[seatId]) {
      const seatBet = currentTable.seats[seatId].bet || 0;
      const currentBet = currentTable.currentBet || 0;
      setBet(Math.max(currentBet - seatBet, 0));
    }
  }, [currentTable, seatId]);

  const wrappedFold = () => {
    startActionLoading();
    fold();
  };
  const wrappedCheck = () => {
    startActionLoading();
    check();
  };
  const wrappedCall = () => {
    startActionLoading();
    call();
  };
  const wrappedRaise = (amount: number) => {
    startActionLoading();
    raise(amount);
  };

  // Waiting for socket connection
  if (!socket) {
    return (
      <Container fullHeight contentCenteredMobile>
        <Loader />
        <Text textAlign="center" style={{ marginTop: '1rem' }}>
          {getLocalizedString('play_connecting')}
        </Text>
      </Container>
    );
  }

  // Socket exists but disconnected - show reconnecting overlay
  if (!isConnected) {
    return (
      <Container fullHeight contentCenteredMobile>
        <Loader />
        <Text textAlign="center" style={{ marginTop: '1rem' }}>
          {getLocalizedString('play_reconnecting')}
        </Text>
      </Container>
    );
  }

  // Portrait: the table is designed for landscape. The CSS-only
  // <RotateDevicePrompt /> is the primary deterrent; here we add a
  // runtime short-circuit so that the socket/table logic does not
  // continue to consume server resources / set state for a viewport
  // the user is not actually playing on. The prompt itself remains
  // rendered above the empty stub below.
  if (isPortrait) {
    return (
      <>
        <Container fullHeight contentCenteredMobile>
          <Text textAlign="center">
            {getLocalizedString('game_rotate-device-prompt')}
          </Text>
        </Container>
        <RotateDevicePrompt />
      </>
    );
  }

  return (
    <>
      {isLeaving && (
        <LeavingOverlay>
          <Loader />
          <Text textAlign="center" style={{ marginTop: '1rem', color: '#fff' }}>
            {getLocalizedString('play_leaving') || '正在离开牌桌...'}
          </Text>
        </LeavingOverlay>
      )}
      {isActionLoading && (
        <ActionLoadingOverlay>
          <Loader />
          <Text textAlign="center" style={{ marginTop: '1rem', color: '#fff' }}>
            {getLocalizedString('play_action-signing') || '等待签名确认...'}
          </Text>
        </ActionLoadingOverlay>
      )}
      <KickNotification
        kickNotification={kickNotification}
        clearKickNotification={clearKickNotification}
      />
      {showFoldLeaveConfirm &&
        ReactDOM.createPortal(
          <ModalShell
            width="sm"
            role="alertdialog"
            ariaLabel={getLocalizedString('leave_confirm-title')}
            onBackdropClick={cancelFoldLeave}
          >
            <h2
              style={{
                margin: 0,
                fontFamily: theme.fonts.fontFamilySansSerif,
                fontSize: '1.4rem',
                fontWeight: 700,
                color: theme.colors.fontColorDark,
                textAlign: 'center',
              }}
            >
              {getLocalizedString('leave_confirm-title')}
            </h2>
            <Text textAlign="center" style={{ color: theme.colors.mutedText }}>
              {getLocalizedString('leave_confirm-message')}
            </Text>
            <div
              style={{
                display: 'flex',
                gap: '0.75rem',
                justifyContent: 'center',
                marginTop: '0.5rem',
              }}
            >
              <Button
                variant="secondary"
                small
                onClick={cancelFoldLeave}
              >
                {getLocalizedString('leave_confirm-cancel')}
              </Button>
              <Button
                variant="danger"
                small
                onClick={() => confirmFoldLeave(true, pkHex || undefined)}
              >
                {getLocalizedString('leave_confirm-fold')}
              </Button>
            </div>
          </ModalShell>,
          document.getElementById('modal') as HTMLElement,
        )}
      <CryptoPanel
        cryptoEvents={cryptoEvents}
        currentTable={currentTable}
        showCryptoPanel={showCryptoPanel}
        onToggle={() => setShowCryptoPanel((v) => !v)}
      />
      {currentTable &&
        ReactDOM.createPortal(
          <HandHistoryPanel
            tableId={Number(currentTable.id)}
            visible={showHistoryPanel}
            onClose={() => setShowHistoryPanel(false)}
          />,
          document.getElementById('modal') as HTMLElement,
        )}
      <RotateDevicePrompt />
      <Container fullHeight>
        {leaveDeferred && (
          <LeaveDeferredBanner role="status" aria-live="polite">
            <span>{getLocalizedString('leave_deferred-banner')}</span>
            <Button
              variant="secondary"
              small
              onClick={() => {
                // Re-join the table: 先中断 deferred leave（cancelled=true），
                // 再 emit SITTING_IN 让后端清除 sitting_out 标记。
                cancelDeferredLeave();
                sittingIn();
              }}
            >
              {getLocalizedString('leave_deferred-cancel')}
            </Button>
          </LeaveDeferredBanner>
        )}
        {currentTable && (
          <>
            <PositionedUISlot
              bottom="2vh"
              left="1.5rem"
              scale="0.65"
              style={{ zIndex: '50', display: 'flex', gap: '0.5rem' }}
            >
              <Button small secondary onClick={async () => {
                if (isLeaving) return;
                setIsLeaving(true);
                try {
                  await leaveTable(true, pkHex || undefined);
                } catch (e) {
                  logger.error('[Play] leaveTable failed:', e);
                  setIsLeaving(false);
                }
              }} disabled={isLeaving}>
                {isLeaving ? getLocalizedString('play_leaving') || '离开中...' : getLocalizedString('game_leave-table-btn')}
              </Button>
              <Button
                small
                secondary
                onClick={() => setShowHistoryPanel(true)}
                aria-label={getLocalizedString('game_history-open-btn')}
              >
                {getLocalizedString('game_history-open-btn')}
              </Button>
            </PositionedUISlot>
            {!isPlayerSeated && (
              <PositionedUISlot
                bottom="1.5vh"
                right="1.5rem"
                scale="0.65"
                style={{ pointerEvents: 'none', zIndex: '50' }}
                origin="bottom right"
              >
                <TableInfoWrapper>
                  <Text textAlign="right">
                    <strong>{currentTable.id}</strong> |{' '}
                    <strong>
                      {getLocalizedString('game_info_limit-lbl')}:{' '}
                    </strong>
                    {new Intl.NumberFormat(
                      document.documentElement.lang,
                    ).format(currentTable.minBuyIn)}{' '}
                    |{' '}
                    <strong>
                      {getLocalizedString('game_info_blinds-lbl')}:{' '}
                    </strong>
                    {new Intl.NumberFormat(
                      document.documentElement.lang,
                    ).format(currentTable.smallBlind)}{' '}
                    /{' '}
                    {new Intl.NumberFormat(
                      document.documentElement.lang,
                    ).format(currentTable.bigBlind)}
                  </Text>
                </TableInfoWrapper>
              </PositionedUISlot>
            )}
          </>
        )}
        <PokerTableWrapper>
          <PokerTable />
          {currentTable && (
            <>
              {SEAT_LAYOUTS.map((layout) => (
                <PositionedUISlot
                  key={layout.seatNumber}
                  top={layout.top}
                  bottom={layout.bottom}
                  left={layout.left}
                  right={layout.right}
                  scale={layout.scale}
                  origin={layout.origin}
                >
                  <Seat
                    seatNumber={layout.seatNumber}
                    currentTable={currentTable}
                    isPlayerSeated={isPlayerSeated}
                    sitDown={sitDown}
                  />
                </PositionedUISlot>
              ))}
              <PositionedUISlot
                width="100%"
                origin="center center"
                scale="0.60"
                style={{
                  display: 'flex',
                  textAlign: 'center',
                  justifyContent: 'center',
                  alignItems: 'center',
                }}
              >
                {communityCards && communityCards.length > 0 && (
                  <>
                    {communityCards.map((card, index) => (
                      <PokerCard key={index} card={card} />
                    ))}
                  </>
                )}
              </PositionedUISlot>
              <PositionedUISlot bottom="8%" scale="0.60" origin="bottom center">
                {messages && messages.length > 0 && (
                  <>
                    <InfoPill>{messages[messages.length - 1].text}</InfoPill>
                    {!isPlayerSeated && (
                      <InfoPill>{getLocalizedString('game_sitdown-prompt')}</InfoPill>
                    )}
                    {currentTable.winMessages && currentTable.winMessages.length > 0 && (
                      <InfoPill>
                        {currentTable.winMessages[currentTable.winMessages.length - 1]}
                      </InfoPill>
                    )}
                    {!!currentTable.rakeCollected && (
                      <InfoPill>
                        {`${getLocalizedString('game_rake-collected_lbl')}: $${Number(currentTable.rakeCollected).toFixed(2)}`}
                      </InfoPill>
                    )}
                  </>
                )}
              </PositionedUISlot>
              <PositionedUISlot
                bottom="25%"
                scale="0.60"
                origin="center center"
              >
                {(!currentTable.winMessages || currentTable.winMessages.length === 0) && (
                  <GameStateInfo currentTable={currentTable} communityCards={communityCards} />
                )}
              </PositionedUISlot>
            </>
          )}
        </PokerTableWrapper>

        {currentTable &&
          isPlayerSeated &&
          seatId != null &&
          currentTable.seats[seatId] &&
          currentTable.seats[seatId].turn && (
            <GameUI
              currentTable={currentTable}
              seatId={seatId}
              bet={bet}
              setBet={setBet}
              raise={wrappedRaise}
              fold={wrappedFold}
              check={wrappedCheck}
              call={wrappedCall}
              isActionLoading={isActionLoading}
            />
          )}
      </Container>
    </>
  );
};

export default Play;
