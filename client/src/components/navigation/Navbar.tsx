import React, { useContext, useState } from 'react';
import styled from 'styled-components';
import LogoWithText from '../logo/LogoWithText';
import Logo from '../logo/LogoIcon';
import Container from '../layout/Container';
import { Link, useNavigate } from 'react-router-dom';
import Hider from '../layout/Hider';
import Button from '../buttons/Button';
import HamburgerButton from '../buttons/HamburgerButton';
import Spacer from '../layout/Spacer';
import contentContext from '../../context/content/contentContext';
import authContext from '../../context/auth/authContext';
import { useGlobalContext } from '../../context/global/globalContext';
import { STRK_DECIMALS } from '../../starknet/config';
import ClaimRewardsModal from '../modals/ClaimRewardsModal';
import WalletPill from './WalletPill';
import AccountMenu from './AccountMenu';

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

/** bigint wei → STRK 十进制字符串；maxFrac 控制小数位（展示 4 位，tooltip 全精度） */
const formatStrk = (raw: bigint, maxFrac: number): string => {
  const scale = BigInt(10) ** BigInt(STRK_DECIMALS);
  const whole = raw / scale;
  const frac = (raw % scale)
    .toString()
    .padStart(STRK_DECIMALS, '0')
    .slice(0, maxFrac)
    .replace(/0+$/, '');
  return frac ? `${whole}.${frac}` : whole.toString();
};

const Navbar: React.FC<NavbarProps> = ({
  loggedIn,
  chipsAmount,
  openNavMenu,
  onSignIn,
  onLogout,
  className,
}) => {
  const { getLocalizedString } = useContext(contentContext)!;
  const { walletAddress } = useContext(authContext)!;
  const { strkBalance } = useGlobalContext();
  const navigate = useNavigate();
  const [showClaim, setShowClaim] = useState(false);

  // 余额统一由 useAuth 拉取并写入全局 strkBalance（此前 Navbar 重复拉过一次）
  const strkDisplay = strkBalance === null ? null : formatStrk(strkBalance, 4);
  const strkFull = strkBalance === null ? '' : formatStrk(strkBalance, STRK_DECIMALS);
  const balanceLabel = getLocalizedString('seat_strk-balance-label');
  const balanceTitle =
    strkBalance === null ? balanceLabel : `${balanceLabel}: ${strkFull} STRK`;

  const handleSignIn = () => {
    if (onSignIn) {
      onSignIn();
    } else {
      navigate('/');
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
          <WalletPill
            balance={strkDisplay}
            balanceTitle={balanceTitle}
            logoAlt={getLocalizedString('seat_strk-logo-alt')}
            claimLabel={getLocalizedString('navbar-claim_btn')}
            claimTitle={getLocalizedString('navbar-claim_tip')}
            hasClaimable={(chipsAmount ?? 0) > 0}
            onClaim={() => setShowClaim(true)}
          />
          {walletAddress && (
            <AccountMenu
              address={walletAddress}
              copyLabel={getLocalizedString('navbar-copy-address')}
              copiedLabel={getLocalizedString('navbar-copied')}
              logoutLabel={getLocalizedString('navmenu-logout_btn')}
              onLogout={onLogout}
            />
          )}
          <StyledHamburgerButton clickHandler={openNavMenu} />
        </Spacer>
      </Container>
      {showClaim && (
        <ClaimRewardsModal
          isOpen={showClaim}
          chipsAmount={chipsAmount}
          onClose={() => setShowClaim(false)}
        />
      )}
    </StyledNav>
  );
};

export default Navbar;
