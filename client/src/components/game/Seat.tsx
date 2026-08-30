import React, { useCallback, useContext, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { AnimatePresence, motion } from 'framer-motion';
import Button from '../buttons/Button';
import modalContext from '../../context/modal/modalContext';
import globalContext from '../../context/global/globalContext';
import { ButtonGroup } from '../forms/ButtonGroup';
import { Form } from '../forms/Form';
import { FormGroup } from '../forms/FormGroup';
import { Input } from '../forms/Input';
import gameContext from '../../context/game/gameContext';
import { PositionedUISlot } from './PositionedUISlot';
import { InfoPill } from './InfoPill';
import PokerCard from './PokerCard';
import ChipsAmountPill from './ChipsAmountPill';
import ColoredText from '../typography/ColoredText';
import Text from '../typography/Text';
import PokerChip from '../icons/PokerChip';
import { OccupiedSeat } from './OccupiedSeat';
import { Hand } from './Hand';
import { NameTag } from './NameTag';
import { PlayerName } from './PlayerName';
import contentContext from '../../context/content/contentContext';
import Markdown from 'react-markdown';
import DealerButton from '../icons/DealerButton';
import styled from 'styled-components';
import { Table } from '../../types/game';
import authContext from '../../context/auth/authContext';
import { EmptySeat } from './seatStyles';
import { getStrkBalance } from '../../starknet/starknetGameActions';
import { CHIPS_PER_STRK, STRK_DECIMALS } from '../../starknet/config';
import { logger } from '../../helpers/logger';

const StyledSeat = styled.div`
  width: 200px;
  height: 200px;
  display: flex;
  justify-content: center;
  align-items: center;
`;

const BuyinInfo = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  margin-bottom: 0.75rem;
  padding: 0.75rem 1rem;
  background: ${({ theme }) => theme.colors.brandSuiBlueAlpha08};
  border: 1px solid ${({ theme }) => theme.colors.brandSuiBlueAlpha20};
  border-radius: ${({ theme }) => theme.radius.md};
  font-size: 0.85rem;
  color: ${({ theme }) => theme.colors.fontColorDarkLighter};
`;

const BuyinInfoRow = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 0.5rem;

  img {
    width: 16px;
    height: 16px;
    vertical-align: middle;
    margin-right: 0.25rem;
  }
`;

const ExchangeRate = styled.div`
  font-size: 0.75rem;
  color: ${({ theme }) => theme.colors.softText};
  text-align: center;
  padding-top: 0.25rem;
  border-top: 1px dashed rgba(148, 163, 184, 0.3);
`;

// 与 Modal 底部按钮（ModalButton 紫色渐变）保持视觉一致
const ConfirmButton = styled(Button)`
  background: ${({ theme }) => theme.colors.brandGradient} !important;
  color: ${({ theme }) => theme.colors.lightestBg} !important;
  border: none !important;
  border-radius: ${({ theme }) => theme.radius.md} !important;
  font-weight: 600 !important;
  padding: 0.65rem 2rem !important;
  box-shadow: 0 4px 20px rgba(102, 126, 234, 0.25) !important;
  transition:
    box-shadow 0.35s ${({ theme }) => theme.easing.easeOutCubic},
    transform 0.35s ${({ theme }) => theme.easing.easeOutCubic} !important;

  &:hover:not(:disabled) {
    box-shadow: 0 6px 24px rgba(102, 126, 234, 0.35) !important;
    transform: translateY(-1px);
  }
`;

// Faucet 按钮：次要样式（描边），与确认/取消按钮区分
const FaucetButton = styled.button`
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.4rem;
  width: 100%;
  padding: 0.55rem 1rem;
  border-radius: ${({ theme }) => theme.radius.md};
  border: 1px dashed ${({ theme }) => theme.colors.brandSuiBlueAlpha20};
  background: ${({ theme }) => theme.colors.brandSuiBlueAlpha08};
  color: ${({ theme }) => theme.colors.brandSuiBlue};
  font-size: 0.85rem;
  font-weight: 500;
  cursor: pointer;
  transition:
    background-color 0.2s ease,
    border-color 0.2s ease,
    opacity 0.2s ease;
  /* Apple HIG: 44x44 touch target on mobile */
  min-height: 44px;

  img {
    width: 16px;
    height: 16px;
  }

  &:hover:not(:disabled) {
    background: ${({ theme }) => theme.colors.brandSuiBlueAlpha08};
    border-color: ${({ theme }) => theme.colors.brandSuiBlue};
    opacity: 0.95;
  }

  &:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
`;

interface SeatProps {
  currentTable: Table;
  seatNumber: number;
  isPlayerSeated: boolean;
  sitDown: (tableId: string, seatId: number, amount: number) => Promise<void>;
}

export const Seat: React.FC<SeatProps> = ({ currentTable, seatNumber, isPlayerSeated, sitDown }) => {
  const { openModal, closeModal } = useContext(modalContext)!;
  const navigate = useNavigate();
  const { chipsAmount } = useContext(globalContext)!;
  const { standUp, seatId, rebuy } = useContext(gameContext)!;
  const { getLocalizedString } = useContext(contentContext)!;
  const { isLoggedIn, walletAddress } = useContext(authContext)!;
  const hasWallet = !!walletAddress;

  // Read the player's STRK balance from Starknet Sepolia. Re-fetched when the
  // wallet address changes and after a faucet claim.
  const [strkBalanceWei, setStrkBalanceWei] = useState<bigint>(0n);

  const fetchBalance = useCallback(async () => {
    if (!walletAddress) {
      setStrkBalanceWei(0n);
      return;
    }
    try {
      const bal = await getStrkBalance(walletAddress);
      setStrkBalanceWei(bal);
    } catch (err) {
      logger.error('[Seat] fetch STRK balance failed:', err);
    }
  }, [walletAddress]);

  useEffect(() => {
    fetchBalance();
  }, [fetchBalance]);

  const seat = currentTable.seats[seatNumber];
  // limit 在链上同步场景可能为 0（链上 BCS 不含此字段），回退到 bigBlind * 100
  const maxBuyin = 5000;
  const minBuyIn = Math.max(currentTable.minBet * 2 * 10, 1000);
  const BUYIN_STEP = 1000;

  // 1 STRK = 10_000 chips → 1 chip = 0.0001 STRK
  const strkBalanceInStrk =
    Number(strkBalanceWei / BigInt(10) ** BigInt(STRK_DECIMALS)) +
    Number(strkBalanceWei % BigInt(10) ** BigInt(STRK_DECIMALS)) /
      10 ** STRK_DECIMALS;
  const availableChips = chipsAmount ?? 0;

  // 兑换指定筹码需要的 STRK 数量
  const strkCostForChips = (chips: number): number => chips / CHIPS_PER_STRK;

  // 格式化钱包地址用于显示（前6位...后4位）
  const shortAddress = walletAddress
    ? `${walletAddress.slice(0, 6)}...${walletAddress.slice(-4)}`
    : '';

  // Faucet 请求状态
  const [faucetLoading, setFaucetLoading] = useState(false);
  const [faucetMsg, setFaucetMsg] = useState<string | null>(null);

  // Faucet: Starknet Sepolia STRK has no SDK-style programmatic faucet the way
  // Sui does, so we open the official Starknet Sepolia STRK faucet in a new
  // tab and ask the user to paste their address.
  const handleFaucetRequest = async () => {
    if (!walletAddress || faucetLoading) return;
    setFaucetLoading(true);
    setFaucetMsg(null);
    try {
      const faucetUrl = `https://starknet-faucet.vercel.app/?address=${encodeURIComponent(walletAddress)}`;
      window.open(faucetUrl, '_blank', 'noopener,noreferrer');
      setFaucetMsg(getLocalizedString('seat_claim-success'));
      // Refresh balance after a short delay to pick up the faucet transfer.
      setTimeout(() => {
        fetchBalance();
        setFaucetMsg(null);
      }, 5000);
    } catch (err: any) {
      const msg = err?.message || String(err);
      setFaucetMsg(`${getLocalizedString('seat_claim-failed-prefix')}: ${msg}`);
      openModal(
        () => <Text textAlign="center">{msg}</Text>,
        getLocalizedString('seat_claim-failed-title'),
        getLocalizedString('seat_claim-failed-ok'),
      );
    } finally {
      setFaucetLoading(false);
    }
  };

  // Debug: log hand cards for the current player's seat
  if (seat && seatId !== null && seat.id === seatId) {
    logger.log('[Seat] seatNumber:', seatNumber, 'seatId:', seatId, 'hand:', seat.hand);
  }

  useEffect(() => {
    if (
      currentTable &&
      isPlayerSeated &&
      seat &&
      seat.id === seatId &&
      seat.stack === 0 &&
      seat.sittingOut
    ) {
      if (availableChips <= minBuyIn || availableChips === 0) {
        standUp().catch(e => logger.error('[Seat] standUp failed:', e));
      } else {
        // 打开 rebuy 弹窗前刷新余额，确保显示最新 STRK 余额
        fetchBalance();
        openModal(
          () => (
            <Form
              onSubmit={(e) => {
                e.preventDefault();

                const amount = +(document.getElementById('amount') as HTMLInputElement).value;

                if (
                  amount &&
                  amount >= minBuyIn &&
                  amount % BUYIN_STEP === 0 &&
                  amount <= availableChips &&
                  amount <= maxBuyin
                ) {
                  rebuy(currentTable.id, seatNumber, parseInt(String(amount)));
                  closeModal();
                }
              }}
            >
              <BuyinInfo>
                <BuyinInfoRow>
                  <span>{getLocalizedString('seat_wallet-address-label')}</span>
                  <strong>{shortAddress || '-'}</strong>
                </BuyinInfoRow>
                <BuyinInfoRow>
                  <span><img src="/strk-logo.svg" alt={getLocalizedString('seat_strk-logo-alt')} />{getLocalizedString('seat_strk-balance-label')}</span>
                  <strong>{strkBalanceInStrk.toLocaleString(undefined, { maximumFractionDigits: 4 })} STRK</strong>
                </BuyinInfoRow>
                <BuyinInfoRow>
                  <span>{getLocalizedString('seat_redeemable-chips-label')}</span>
                  <strong>{availableChips.toLocaleString()}</strong>
                </BuyinInfoRow>
                <BuyinInfoRow>
                  <span>{getLocalizedString('seat_conversion-cost-label')}</span>
                  <strong>{strkCostForChips(minBuyIn).toLocaleString(undefined, { maximumFractionDigits: 4 })} STRK</strong>
                </BuyinInfoRow>
                <ExchangeRate>{getLocalizedString('seat_exchange-rate-label').replace('{rate}', CHIPS_PER_STRK.toLocaleString())}</ExchangeRate>
              </BuyinInfo>
              <FormGroup>
                <Input
                  id="amount"
                  type="number"
                  inputMode="numeric"
                  pattern="[0-9]*"
                  min={minBuyIn}
                  max={availableChips <= maxBuyin ? availableChips : maxBuyin}
                  step={BUYIN_STEP}
                  defaultValue={minBuyIn}
                />
              </FormGroup>
              <ButtonGroup>
                <ConfirmButton primary type="submit" fullWidth>
                  {getLocalizedString('game_rebuy-modal_confirm')}
                </ConfirmButton>
                <FaucetButton
                  type="button"
                  onClick={handleFaucetRequest}
                  disabled={faucetLoading || !walletAddress}
                >
                  <img src="/strk-logo.svg" alt={getLocalizedString('seat_strk-logo-alt')} />
                  {faucetLoading ? getLocalizedString('seat_claiming-btn') : getLocalizedString('seat_claim-faucet-btn')}
                </FaucetButton>
                {faucetMsg && (
                  <Text textAlign="center" style={{ fontSize: '0.8rem' }}>
                    {faucetMsg}
                  </Text>
                )}
              </ButtonGroup>
            </Form>
          ),
          getLocalizedString('game_rebuy-modal_header'),
          getLocalizedString('game_rebuy-modal_cancel'),
          () => {
            standUp().catch(e => logger.error('[Seat] standUp failed:', e));
            closeModal();
          },
          () => {
            standUp().catch(e => logger.error('[Seat] standUp failed:', e));
            closeModal();
          },
        );
      }
    }
    // eslint-disable-next-line
  }, [currentTable]);

  return (
    <StyledSeat>
      <AnimatePresence mode="wait">
        {!seat ? (
          <motion.div
            key="empty"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.3 }}
            style={{
              display: 'flex',
              justifyContent: 'center',
              alignItems: 'center',
            }}
          >
            {!isPlayerSeated ? (
              <Button
                small
                onClick={() => {
                  if (!isLoggedIn && !hasWallet) {
                    openModal(
                      () => <Text textAlign="center">{getLocalizedString('game_login-required_text')}</Text>,
                      getLocalizedString('login_page-header_txt'),
                      getLocalizedString('navbar-login_btn'),
                      () => {
                        closeModal();
                        navigate('/', { state: { showLogin: true } });
                      },
                    );
                    return;
                  }
                  // 打开 buyin 弹窗前刷新余额，确保显示最新 STRK 余额
                  fetchBalance();
                  openModal(
                    () => (
                      <Form
                        onSubmit={(e) => {
                          e.preventDefault();

                          const amount = +(document.getElementById('amount') as HTMLInputElement).value;

                          if (
                            amount &&
                            amount >= minBuyIn &&
                            amount % BUYIN_STEP === 0 &&
                            amount <= availableChips &&
                            amount <= maxBuyin
                          ) {
                            sitDown(
                              currentTable.id,
                              seatNumber,
                              parseInt(String(amount)),
                            );
                            closeModal();
                          }
                        }}
                      >
                        <BuyinInfo>
                          <BuyinInfoRow>
                            <span>{getLocalizedString('seat_wallet-address-label')}</span>
                            <strong>{shortAddress || '-'}</strong>
                          </BuyinInfoRow>
<BuyinInfoRow>
                          <span><img src="/strk-logo.svg" alt={getLocalizedString('seat_strk-logo-alt')} />{getLocalizedString('seat_strk-balance-label')}</span>
                          <strong>{strkBalanceInStrk.toLocaleString(undefined, { maximumFractionDigits: 4 })} STRK</strong>
                        </BuyinInfoRow>
                          <BuyinInfoRow>
                            <span>{getLocalizedString('seat_redeemable-chips-label')}</span>
                            <strong>{availableChips.toLocaleString()}</strong>
                          </BuyinInfoRow>
                          <BuyinInfoRow>
                            <span>{getLocalizedString('seat_conversion-cost-label')}</span>
                            <strong>{strkCostForChips(minBuyIn).toLocaleString(undefined, { maximumFractionDigits: 4 })} STRK</strong>
                          </BuyinInfoRow>
                          <ExchangeRate>{getLocalizedString('seat_exchange-rate-label').replace('{rate}', CHIPS_PER_STRK.toLocaleString())}</ExchangeRate>
                        </BuyinInfo>
                        <FormGroup>
                          <Input
                            id="amount"
                            type="number"
                            inputMode="numeric"
                            pattern="[0-9]*"
                            min={minBuyIn}
                            max={availableChips <= maxBuyin ? availableChips : maxBuyin}
                            defaultValue={minBuyIn}
                          />
                        </FormGroup>
                        <ButtonGroup>
                          <ConfirmButton primary type="submit" fullWidth>
                            {getLocalizedString('game_buyin-modal_confirm')}
                          </ConfirmButton>
                          <FaucetButton
                            type="button"
                            onClick={handleFaucetRequest}
                            disabled={faucetLoading || !walletAddress}
                          >
                            <img src="/strk-logo.svg" alt={getLocalizedString('seat_strk-logo-alt')} />
                            {faucetLoading ? getLocalizedString('seat_claiming-btn') : getLocalizedString('seat_claim-faucet-btn')}
                          </FaucetButton>
                          {faucetMsg && (
                            <Text textAlign="center" style={{ fontSize: '0.8rem' }}>
                              {faucetMsg}
                            </Text>
                          )}
                        </ButtonGroup>
                      </Form>
                    ),
                    getLocalizedString('game_buyin-modal_header'),
                    getLocalizedString('game_buyin-modal_cancel'),
                  );
                }}
              >
                {getLocalizedString('game_sitdown-btn')}
              </Button>
            ) : (
              <EmptySeat>
                <Markdown>{getLocalizedString('game_table_empty-seat')}</Markdown>
              </EmptySeat>
            )}
          </motion.div>
        ) : (
          <motion.div
            key="occupied"
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{
              opacity: 1,
              scale: 1,
              transition: { duration: 0.3, ease: 'easeOut' },
            }}
            exit={{ opacity: 0, transition: { duration: 0.3, ease: 'easeIn' } }}
            style={{
              position: 'absolute',
              display: 'flex',
              textAlign: 'center',
              justifyContent: 'center',
              alignItems: 'center',
              transformOrigin: 'center center',
              backfaceVisibility: 'hidden',
              WebkitBackfaceVisibility: 'hidden',
            }}
          >
            <PositionedUISlot top="-6.25rem" left="-75px" origin="top center">
              <NameTag>
                <ColoredText primary textAlign="center">
                  <PlayerName name={seat.player!.name} />
                  <br />
                  {seat.stack && (
                    <ColoredText secondary>
                      <PokerChip width="15" height="15" />{' '}
                      {new Intl.NumberFormat(
                        document.documentElement.lang,
                      ).format(seat.stack)}
                    </ColoredText>
                  )}
                </ColoredText>
              </NameTag>
            </PositionedUISlot>
            <PositionedUISlot>
              <OccupiedSeat seatNumber={seatNumber} hasTurn={seat.turn} />
            </PositionedUISlot>
            <PositionedUISlot
              left="4vh"
              style={{
                display: 'flex',
                textAlign: 'center',
                justifyContent: 'center',
                alignItems: 'center',
              }}
              origin="center right"
            >
              <Hand>
                {seat.hand &&
                  seat.hand.map((card, index) => (
                    <PokerCard
                      key={index}
                      card={card}
                      width="5vw"
                      maxWidth="60px"
                      minWidth="30px"
                    />
                  ))}
              </Hand>
            </PositionedUISlot>

            {currentTable.button === seatNumber && (
              <PositionedUISlot
                right="35px"
                origin="center left"
                style={{ zIndex: '55' }}
              >
                <DealerButton />
              </PositionedUISlot>
            )}

            <PositionedUISlot
              top="6vh"
              style={{ minWidth: '150px', zIndex: '55' }}
              origin="bottom center"
            >
              <ChipsAmountPill chipsAmount={seat.bet} />
              {!currentTable.handOver && seat.lastAction && (
                <InfoPill>{seat.lastAction}</InfoPill>
              )}
            </PositionedUISlot>
          </motion.div>
        )}
      </AnimatePresence>
    </StyledSeat>
  );
};
