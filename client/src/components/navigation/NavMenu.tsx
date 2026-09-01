import React, { useContext } from 'react';
import styled from 'styled-components';
import CloseButton from '../buttons/CloseButton';
import Button from '../buttons/Button';
import Text from '../typography/Text';
import ColoredText from '../typography/ColoredText';
import { PlayerName } from '../game/PlayerName';
import ChipsAmount from '../user/ChipsAmount';
import { Link } from 'react-router-dom';
import lobbyIcon from '../../assets/icons/lobby-icon.svg';
import userIcon from '../../assets/icons/user-icon.svg';
import contentContext from '../../context/content/contentContext';
import globalContext from '../../context/global/globalContext';
import LanguageSwitcher from './LanguageSwitcher';
import PlayerKeyPanel from './PlayerKeyPanel';

const NavMenuWrapper = styled.div`
  position: fixed;
  display: flex;
  justify-content: center;
  align-items: center;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  z-index: ${({ theme }) => theme.zIndex.drawer};
  background-color: rgba(0, 0, 0, 0.15);
  backdrop-filter: blur(4px);
  -webkit-backdrop-filter: blur(4px);
  overscroll-behavior: contain;
`;

const StyledNavMenu = styled.div`
  position: fixed;
  display: flex;
  flex-direction: column;
  top: 0;
  right: 0;
  width: 320px;
  height: 100%;
  background: rgba(255, 255, 255, 0.95);
  border-left: 1px solid rgba(226, 232, 240, 0.9);
  box-shadow: -8px 0 40px rgba(0, 0, 0, 0.08);
  overflow: hidden;

  @media screen and (max-width: 400px) {
    width: 85vw;
  }
`;

const MenuHeader = styled.div`
  padding: 1rem 1.25rem 0;
  justify-self: flex-start;
`;

const MenuItem = styled(Link)`
  display: flex;
  padding: 0.85rem 1.25rem;
  justify-content: space-between;
  align-items: center;
  width: 100%;
  text-align: right;
  font-family: 'Inter', -apple-system, sans-serif;
  color: ${({ theme }) => theme.colors.fontColorDark} !important;
  border-bottom: 1px solid rgba(226, 232, 240, 0.6);
  background-color: transparent !important;
  font-size: 0.95rem;
  font-weight: 500;
  text-decoration: none;
  transition:
    background-color 0.2s ease,
    color 0.2s ease,
    border-left-color 0.2s ease;

  img {
    opacity: 0.6;
    transition: opacity 0.2s ease;
  }

  &:hover {
    background-color: rgba(102, 126, 234, 0.08) !important;
    color: ${({ theme }) => theme.colors.secondaryCta} !important;

    img {
      opacity: 1;
    }
  }

  &:focus {
    outline: none;
    border-left: 3px solid ${({ theme }) => theme.colors.secondaryCta};
  }
`;

const MenuBody = styled.div`
  overflow-y: auto;
  overscroll-behavior: contain;
  margin-top: 0.5rem;

  &::-webkit-scrollbar {
    width: 0.4rem;
  }

  &::-webkit-scrollbar-track {
    background: transparent;
  }

  &::-webkit-scrollbar-thumb {
    background: rgba(203, 213, 225, 0.6);
    border-radius: 4px;
  }
`;

const MenuFooter = styled.div`
  padding: 1rem 1.25rem;
  margin: auto 0 0 0;
  border-top: 1px solid rgba(226, 232, 240, 0.6);
`;

/* Single source of truth for nav menu icon dimensions. The audit (P1-47)
   flagged that the prior version set both HTML width="22" AND an inline
   `style={{ width: '22px' }}` for every menu icon — the inline style won
   but duplicated the literal. Centralize here. */
const MenuIcon = styled.img`
  width: 22px;
  height: 22px;
  flex-shrink: 0;
`;

const HorizontalWrapper = styled.div`
  display: flex;
  margin: 1.5rem auto;
  justify-content: space-between;
  align-items: center;
  gap: 0.75rem;

  ${Button} {
    min-width: 6.5rem;
    background: linear-gradient(135deg, ${({ theme }) => theme.colors.secondaryCta}, #764ba2) !important;
    color: ${({ theme }) => theme.colors.lightestBg} !important;
    border: none !important;
    border-radius: 10px !important;
    box-shadow: 0 2px 12px rgba(102, 126, 234, 0.2) !important;
  }
`;

const SalutationText = styled(Text)`
  font-family: 'Inter', -apple-system, sans-serif;
  font-size: 1.25rem;
  font-weight: 700;
  color: ${({ theme }) => theme.colors.fontColorDark};
  letter-spacing: -0.02em;

  ${ColoredText} {
    background: linear-gradient(135deg, ${({ theme }) => theme.colors.secondaryCta}, #764ba2);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
  }
`;

const OnlineText = styled(Text)`
  font-family: 'Inter', -apple-system, sans-serif;
  font-size: 0.85rem;
  color: #64748b;
  margin-top: 0.25rem;

  ${ColoredText} {
    color: #10b981;
    font-weight: 600;
  }
`;

const IconWrapper = styled.div`
  position: absolute;
  top: 0.75rem;
  right: 0.75rem;

  button {
    color: #64748b !important;

    &:hover {
      color: ${({ theme }) => theme.colors.fontColorDark} !important;
    }
  }
`;

interface NavMenuProps {
  onClose: () => void;
  userName: string | null;
  chipsAmount: number | null;
  lang?: string;
  setLang?: React.Dispatch<React.SetStateAction<string>>;
  openModal: (
    children: () => React.ReactNode,
    headingText: string,
    btnText: string,
    btnCallBack?: () => void,
    onCloseCallBack?: () => void,
  ) => void;
}

const NavMenu: React.FC<NavMenuProps> = ({
  onClose,
  userName,
  chipsAmount,
  openModal,
}) => {
  const { players } = useContext(globalContext)!;
  const { getLocalizedString } = useContext(contentContext)!;

  const openShopModal = () =>
    openModal(
      () => (
        <Text textAlign="center">
            {getLocalizedString('shop-coming_soon-modal_text')}
          </Text>
      ),
      getLocalizedString('shop-coming_soon-modal_heading'),
      getLocalizedString('shop-coming_soon-modal_btn_text'),
    );

  return (
    <NavMenuWrapper
      id="wrapper"
      onClick={(e) => {
        if ((e.target as HTMLElement).id === 'wrapper') {
          onClose();
        }
      }}
    >
      <StyledNavMenu>
        <IconWrapper>
          <CloseButton clickHandler={onClose} autoFocus />
        </IconWrapper>
        <MenuHeader>
          <SalutationText textAlign="left">
            {getLocalizedString('main_page-salutation')}
            <br />
            <ColoredText><PlayerName name={userName} />!</ColoredText>
          </SalutationText>
          {players && (
            <OnlineText textAlign="left">
              {getLocalizedString('game_online-lbl')} <ColoredText>{players.length}</ColoredText>
            </OnlineText>
          )}
          <HorizontalWrapper>
            <ChipsAmount
              chipsAmount={chipsAmount ?? 0}
              clickHandler={openShopModal}
            />
            <Button onClick={openShopModal} small primary>
              {getLocalizedString('shop-coming_soon-modal_heading')}
            </Button>
          </HorizontalWrapper>
        </MenuHeader>
        <MenuBody>
          <MenuItem
            to="/"
            onClick={() => {
              onClose();
            }}
          >
            {getLocalizedString('navmenu-menu_item-lobby_txt')}
            <MenuIcon
              src={lobbyIcon}
              alt={getLocalizedString('navbar_lobby-alt')}
            />
          </MenuItem>
          <MenuItem
            to="/dashboard"
            onClick={() => {
              onClose();
            }}
          >
            {getLocalizedString('navmenu-menu_item-dashboard_txt')}
            <MenuIcon
              src={userIcon}
              alt={getLocalizedString('navbar_dashboard-alt')}
            />
          </MenuItem>

        </MenuBody>
        <PlayerKeyPanel />
        <MenuFooter>
          <LanguageSwitcher />
        </MenuFooter>
      </StyledNavMenu>
    </NavMenuWrapper>
  );
};

export default NavMenu;
