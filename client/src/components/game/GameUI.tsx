import React, { useContext } from 'react';
import contentContext from '../../context/content/contentContext';
import Button from '../buttons/Button';
import { BetSlider } from './BetSlider';
import { UIWrapper } from './UIWrapper';
import { Table } from '../../types/game';

interface GameUIProps {
  currentTable: Table;
  seatId: number;
  bet: number;
  setBet: (bet: number) => void;
  raise: (amount: number) => void;
  fold: () => void;
  check: () => void;
  call: () => void;
  isActionLoading?: boolean;
}

export const GameUI: React.FC<GameUIProps> = ({
  currentTable,
  seatId,
  bet,
  setBet,
  raise,
  fold,
  check,
  call,
  isActionLoading = false,
}) => {
  const { getLocalizedString } = useContext(contentContext)!;

  return (
    <UIWrapper>
      <BetSlider
        currentTable={currentTable}
        seatId={seatId}
        bet={bet}
        setBet={setBet}
      />
      <Button small disabled={isActionLoading} onClick={() => raise(bet + currentTable.seats[seatId].bet)}>
        {getLocalizedString('game_ui_bet')} {bet}
      </Button>
      <Button small secondary disabled={isActionLoading} onClick={fold}>
        {getLocalizedString('game_ui_fold')}
      </Button>
      <Button
        small
        secondary
        disabled={
          isActionLoading ||
          (currentTable.callAmount !== currentTable.seats[seatId].bet &&
          currentTable.callAmount > 0)
        }
        onClick={check}
      >
        {getLocalizedString('game_ui_check')}
      </Button>
      <Button
        small
        disabled={
          isActionLoading ||
          currentTable.callAmount === 0 ||
          currentTable.seats[seatId].bet >= currentTable.callAmount
        }
        onClick={call}
      >
        {getLocalizedString('game_ui_call')}{' '}
        {currentTable.callAmount &&
        currentTable.seats[seatId].bet < currentTable.callAmount &&
        currentTable.callAmount <= currentTable.seats[seatId].stack
          ? currentTable.callAmount - currentTable.seats[seatId].bet
          : ''}
      </Button>
      <Button
        small
        disabled={isActionLoading}
        onClick={() => {
          const totalPossible =
            currentTable.seats[seatId].stack + currentTable.seats[seatId].bet;
          if (totalPossible <= currentTable.callAmount) {
            call();
          } else {
            raise(totalPossible);
          }
        }}
      >
        {getLocalizedString('game_ui_all-in')} (
        {currentTable.seats[seatId].stack})
      </Button>
    </UIWrapper>
  );
};
