import React, { useContext, useEffect, useState } from 'react';
import ReactDOM from 'react-dom';
import { useTheme } from 'styled-components';
import LogoWithText from '../logo/LogoWithText';
import Logo from '../logo/LogoIcon';
import Container from '../layout/Container';
import styled from 'styled-components';
import { Link, useNavigate } from 'react-router-dom';
import Hider from '../layout/Hider';
import Button from '../buttons/Button';
import HamburgerButton from '../buttons/HamburgerButton';
import Spacer from '../layout/Spacer';
import contentContext from '../../context/content/contentContext';
import authContext from '../../context/auth/authContext';
import { useAccount } from '@starknet-react/core';
import { activeAccount } from '../../starknet/devAccount';
import { useGlobalContext } from '../../context/global/globalContext';
import { STRK_DECIMALS } from '../../starknet/config';
import ModalShell from '../modals/ModalShell';
import { Form } from '../forms/Form';
import { FormGroup } from '../forms/FormGroup';
import { Input } from '../forms/Input';
import { ButtonGroup } from '../forms/ButtonGroup';
import Text from '../typography/Text';
import {
  getNativeStrkBalance,
  getPstrkBalance,
  isSwapConfigured,
  swapTokens,
  type SwapDirection,
} from '../../starknet/starknetGameActions';
import { getProvider } from '../../starknet/contracts';
import { Contract, type Abi, uint256 } from 'starknet';

interface NavbarProps {
  loggedIn: boolean;
  chipsAmount: number | null;
  openNavMenu: () => void;
  onSignIn?: () => void;
  onLogout?: () => void;
  className?: string;
  variant?: 'light' | 'dark';
}

const StyledNav = styled.nav`
  padding: 1rem 0;
  position: absolute;
  z-index: ${({ theme }) => theme.zIndex.nav};
  width: 100%;
  transition: background-color 0.4s ease;
  background-color: ${({ theme }) => theme.colors.lightestBg};
  border-bottom: 1px solid ${({ theme }) => theme.colors.borderSubtle};
`;

const ChipAmount = styled.div`
  color: #4DA2FF;
  font-family: 'JetBrains Mono', monospace;
  font-weight: 600;
  font-size: 0.95rem;
  padding: 0.4rem 0.75rem;
  background: rgba(77, 162, 255, 0.12);
  border: 1px solid rgba(77, 162, 255, 0.25);
  border-radius: 8px;
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;

  img {
    width: 18px;
    height: 18px;
  }
`;

const StyledHamburgerButton = styled(HamburgerButton)`
  .hamburger-line {
    background-color: ${({ theme }) => theme.colors.fontColorDark};
  }
`;

const LoginButton = styled(Button)`
  background: linear-gradient(135deg, ${({ theme }) => theme.colors.secondaryCta}, #764ba2);
  color: ${({ theme }) => theme.colors.lightestBg};
  border: none;
  box-shadow: 0 4px 20px rgba(102, 126, 234, 0.25);
  &:hover {
    transform: translateY(-3px);
    box-shadow: 0 12px 35px rgba(102, 126, 234, 0.45);
  }
`;

const LogoutButton = styled(Button)`
  background: rgba(241, 245, 249, 0.8);
  color: #475569;
  border: 1px solid rgba(226, 232, 240, 0.9);
  box-shadow: none;
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.85rem;
  min-width: auto;

  &:hover {
    transform: translateY(-3px);
    border-color: rgba(239, 68, 68, 0.4);
    color: #ef4444;
    background: rgba(239, 68, 68, 0.06);
    box-shadow: 0 8px 25px rgba(239, 68, 68, 0.15);
  }
`;

const LogoutAddrDot = styled.span`
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: #22c55e;
  flex-shrink: 0;
`;

/** 兑换弹窗信息行样式（与 Seat 买入弹窗一致）。 */
const SwapInfo = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  margin-bottom: 0.75rem;
`;
const SwapInfoRow = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 0.9rem;
  color: ${({ theme }) => theme.colors.mutedText};
  strong {
    color: ${({ theme }) => theme.colors.fontColorDark};
    font-family: 'JetBrains Mono', monospace;
  }
`;
const SwapRate = styled.div`
  text-align: center;
  font-size: 0.8rem;
  color: #16a34a;
  font-family: 'JetBrains Mono', monospace;
  margin-bottom: 0.5rem;
`;

/** 兑换方向切换 tab。 */
const DirectionTab = styled.button<{ $active?: boolean }>`
  flex: 1;
  padding: 0.45rem 0.5rem;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.82rem;
  border-radius: 8px;
  border: 1px solid ${({ $active }) => ($active ? 'rgba(77, 162, 255, 0.6)' : 'rgba(226, 232, 240, 0.9)')};
  background: ${({ $active }) => ($active ? 'rgba(77, 162, 255, 0.14)' : 'rgba(241, 245, 249, 0.8)')};
  color: ${({ $active }) => ($active ? '#1d4ed8' : '#64748b')};
  cursor: pointer;
  &:disabled {
    opacity: 0.6;
  }
`;

/** 1 STRK = 1000 pSTRK 固定汇率兑换入口（PokerSwap）。 */
const SwapButton = styled(Button)`
  background: rgba(34, 197, 94, 0.1);
  color: #16a34a;
  border: 1px solid rgba(34, 197, 94, 0.35);
  box-shadow: none;
  display: inline-flex;
  align-items: center;
  gap: 0.3rem;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.85rem;
  min-width: auto;

  &:hover {
    transform: translateY(-2px);
    background: rgba(34, 197, 94, 0.18);
    box-shadow: 0 6px 20px rgba(34, 197, 94, 0.2);
  }
  &:disabled {
    opacity: 0.55;
    transform: none;
  }
`;

const Navbar: React.FC<NavbarProps> = ({
  loggedIn,
  chipsAmount,
  openNavMenu,
  onSignIn,
  onLogout,
  className,
}) => {
  const theme = useTheme();
  const { getLocalizedString } = useContext(contentContext)!;
  const { walletAddress } = useContext(authContext)!;
  const { strkBalance, setStrkBalance } = useGlobalContext();
  const connected = useAccount();
  // dev 直签账户（VITE_DEV_ACCOUNT_*，testnet 联调）优先于连接的钱包
  const account = activeAccount(connected.account);
  const navigate = useNavigate();
  const [showSwap, setShowSwap] = useState(false);
  const [swapPending, setSwapPending] = useState(false);
  const [swapDone, setSwapDone] = useState<{ hash: string } | null>(null);
  const [swapError, setSwapError] = useState('');
  const [nativeStrk, setNativeStrk] = useState<bigint | null>(null);
  const [direction, setDirection] = useState<SwapDirection>('strk-to-pstrk');

  const shortAddress = walletAddress
    ? `${walletAddress.slice(0, 6)}...${walletAddress.slice(-4)}`
    : '';

  const strkDisplay = (() => {
    if (strkBalance === null) return '0';
    const whole = strkBalance / BigInt(10) ** BigInt(STRK_DECIMALS);
    const frac = strkBalance % BigInt(10) ** BigInt(STRK_DECIMALS);
    const fracStr = frac.toString().padStart(STRK_DECIMALS, '0').slice(0, 4).replace(/0+$/, '');
    return fracStr.length > 0 ? `${whole.toString()}.${fracStr}` : whole.toString();
  })();

  const handleSignIn = () => {
    if (onSignIn) {
      onSignIn();
    } else {
      navigate('/');
    }
  };

  // 打开兑换弹窗时拉取两侧余额
  useEffect(() => {
    if (showSwap && walletAddress) {
      getNativeStrkBalance(walletAddress).then(setNativeStrk);
      getPstrkBalance(walletAddress).then(setStrkBalance);
    }
  }, [showSwap, walletAddress]);

  const closeSwapModal = () => {
    setShowSwap(false);
    setSwapPending(false);
    setSwapDone(null);
    setSwapError('');
  };

  const handleSwapSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!account || swapPending) return;
    const amount = parseFloat((document.getElementById('swap-amount') as HTMLInputElement)?.value ?? '');
    if (!Number.isFinite(amount) || amount <= 0) return;
    const wei = BigInt(Math.round(amount * 1e18));
    setSwapPending(true);
    setSwapError('');
    const res = await swapTokens(account, direction, wei);
    setSwapPending(false);
    if (res.success) {
      setSwapDone({ hash: res.hash });
      if (walletAddress) {
        setStrkBalance(await getPstrkBalance(walletAddress));
        setNativeStrk(await getNativeStrkBalance(walletAddress));
      }
    } else {
      setSwapError(res.error || 'swap failed');
    }
  };

  if (!loggedIn) {
    return (
      <StyledNav className={className}>
        <Container contentCenteredMobile>
          <Link to="/">
            <LogoWithText />
          </Link>
          <Spacer>
            <LoginButton onClick={handleSignIn}>
              {getLocalizedString('navbar-signin_btn')}
            </LoginButton>
          </Spacer>
        </Container>
      </StyledNav>
    );
  }

  return (
    <StyledNav className={className}>
      <Container>
        <Link to="/">
          <Hider hideOnMobile>
            <LogoWithText />
          </Hider>
          <Hider hideOnDesktop>
            <Logo />
          </Hider>
        </Link>
        <Spacer>
          <ChipAmount title={`${getLocalizedString('seat_strk-balance-label')}: ${strkBalance?.toString() ?? '0'} wei`}>
            <img src="/strk-logo.svg" alt={getLocalizedString('seat_strk-logo-alt')} />
            {strkDisplay} pSTRK
          </ChipAmount>
          {isSwapConfigured() && (
            <SwapButton onClick={() => setShowSwap(true)} title="固定 1 STRK = 1000 pSTRK">
              ⇄ 兑换
            </SwapButton>
          )}
          <LogoutButton onClick={onLogout} title={walletAddress || ''}>
            <LogoutAddrDot />
            {shortAddress || getLocalizedString('navmenu-logout_btn')}
          </LogoutButton>
          <StyledHamburgerButton clickHandler={openNavMenu} />
        </Spacer>
      </Container>
      {showSwap &&
        ReactDOM.createPortal(
          <ModalShell
            width="sm"
            role="dialog"
            ariaLabel="兑换 STRK 为 pSTRK"
            onBackdropClick={swapPending ? undefined : closeSwapModal}
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
              兑换 {direction === 'strk-to-pstrk' ? 'STRK → pSTRK' : 'pSTRK → STRK'}
            </h2>
            <SwapInfo>
              <SwapInfoRow>
                <span>钱包</span>
                <strong>{shortAddress || '-'}</strong>
              </SwapInfoRow>
              <SwapInfoRow>
                <span>STRK 余额</span>
                <strong>{nativeStrk === null ? '…' : `${(Number(nativeStrk) / 1e18).toFixed(4)}`}</strong>
              </SwapInfoRow>
              <SwapInfoRow>
                <span>pSTRK 余额</span>
                <strong>{strkDisplay}</strong>
              </SwapInfoRow>
            </SwapInfo>
            <SwapInfo>
              <ButtonGroup>
                <DirectionTab
                  type="button"
                  $active={direction === 'strk-to-pstrk'}
                  onClick={() => !swapPending && setDirection('strk-to-pstrk')}
                >
                  STRK → pSTRK
                </DirectionTab>
                <DirectionTab
                  type="button"
                  $active={direction === 'pstrk-to-strk'}
                  onClick={() => !swapPending && setDirection('pstrk-to-strk')}
                >
                  pSTRK → STRK
                </DirectionTab>
              </ButtonGroup>
            </SwapInfo>
            <SwapRate>固定汇率 1 STRK = 1000 pSTRK</SwapRate>
            {swapDone ? (
              <>
                <Text textAlign="center" style={{ color: '#16a34a' }}>
                  兑换成功 ✓
                </Text>
                <Text
                  textAlign="center"
                  style={{ fontSize: '0.75rem', wordBreak: 'break-all', color: theme.colors.mutedText }}
                >
                  tx: {swapDone.hash}
                </Text>
                <ButtonGroup>
                  <Button variant="secondary" small onClick={closeSwapModal} fullWidth>
                    关闭
                  </Button>
                </ButtonGroup>
              </>
            ) : (
              <Form onSubmit={handleSwapSubmit}>
                <FormGroup>
                  <Input
                    id="swap-amount"
                    type="number"
                    inputMode="decimal"
                    min={0}
                    step={direction === 'pstrk-to-strk' ? '0.001' : 'any'}
                    placeholder={direction === 'strk-to-pstrk' ? '输入 STRK 数量' : '输入 pSTRK 数量（0.001 整数倍）'}
                    disabled={swapPending}
                    autoFocus
                  />
                </FormGroup>
                {swapError && (
                  <Text
                    textAlign="center"
                    style={{ fontSize: '0.8rem', color: '#ef4444', wordBreak: 'break-all' }}
                  >
                    {swapError}
                  </Text>
                )}
                <ButtonGroup>
                  <Button variant="secondary" small type="button" onClick={closeSwapModal} disabled={swapPending}>
                    取消
                  </Button>
                  <Button primary small type="submit" disabled={swapPending}>
                    {swapPending ? '兑换中…' : `确认兑换 ${direction === 'strk-to-pstrk' ? 'pSTRK' : 'STRK'}`}
                  </Button>
                </ButtonGroup>
              </Form>
            )}
          </ModalShell>,
          document.getElementById('modal') as HTMLElement,
        )}
    </StyledNav>
  );
};

export default Navbar;