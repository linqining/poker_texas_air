import React, { useContext } from 'react';
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
import { useGlobalContext } from '../../context/global/globalContext';
import { STRK_DECIMALS } from '../../starknet/config';

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
            {strkDisplay} STRK
          </ChipAmount>
          <LogoutButton onClick={onLogout} title={walletAddress || ''}>
            <LogoutAddrDot />
            {shortAddress || getLocalizedString('navmenu-logout_btn')}
          </LogoutButton>
          <StyledHamburgerButton clickHandler={openNavMenu} />
        </Spacer>
      </Container>
    </StyledNav>
  );
};

export default Navbar;