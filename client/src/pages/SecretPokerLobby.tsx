import { useContext } from 'react';
import { useNavigate } from 'react-router-dom';
import styled from 'styled-components';
import jackImg from '../assets/img/jack-rounded-img@2x.png';
import kingImg from '../assets/img/king-rounded-img@2x.png';
import queenImg from '../assets/img/queen-rounded-img@2x.png';
import queen2Img from '../assets/img/queen2-rounded-img@2x.png';
import { useGlobalContext } from '../context/global/globalContext';
import { useContentContext } from '../context/content/contentContext';
import { useModalContext } from '../context/modal/modalContext';
import authContext from '../context/auth/authContext';
import Text from '../components/typography/Text';
import { PlayerName } from '../components/game/PlayerName';
import UnclaimedFundsBanner from '../components/funds/UnclaimedFundsBanner';

/* ===== Styled Components ===== */

const PageWrapper = styled.div`
  min-height: 100dvh;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: flex-end;
  background: ${({ theme }) => theme.colors.fontColorLight};
  padding: 5rem 1.5rem 2rem;

  @media screen and (max-width: 468px) {
    padding: 4.5rem 1rem 2rem;
  }

  @media screen and (max-width: 900px) and (max-height: 450px) and (orientation: landscape) {
    justify-content: center;
  }
`;

const WelcomeHeading = styled.h2`
  font-family: 'Inter', -apple-system, sans-serif;
  font-size: 1.6rem;
  font-weight: 700;
  text-align: center;
  color: ${({ theme }) => theme.colors.fontColorDark};
  margin: 2rem auto;
  letter-spacing: -0.02em;

  span {
    background: linear-gradient(135deg, ${({ theme }) => theme.colors.secondaryCta}, #764ba2);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
  }

  @media screen and (max-width: 468px) {
    font-size: 1.3rem;
  }

  @media screen and (max-width: 900px) and (max-height: 450px) and (orientation: landscape) {
    display: none;
  }
`;

const MenuGrid = styled.div`
  margin: 0 0 auto 0;
  display: grid;
  justify-content: center;
  align-content: center;
  grid-template-columns: repeat(2, minmax(250px, auto));
  grid-template-rows: repeat(2, minmax(250px, auto));
  grid-gap: 1.5rem;
  max-width: 600px;

  @media screen and (max-width: 900px) and (max-height: 450px) and (orientation: landscape) {
    grid-template-columns: repeat(4, 140px);
    grid-template-rows: repeat(1, minmax(140px, auto));
    grid-gap: 1rem;
  }

  @media screen and (max-width: 590px) and (max-height: 420px) and (orientation: landscape) {
    grid-template-columns: repeat(4, 120px);
    grid-template-rows: repeat(1, minmax(120px, auto));
    grid-gap: 1rem;
  }

  @media screen and (max-width: 468px) {
    grid-template-columns: repeat(1, auto);
    grid-template-rows: repeat(4, auto);
    grid-gap: 1rem;
  }
`;

/* button 而非 div onClick：键盘/读屏用户也能进入游戏（WCAG 2.1.1）。
   reset 浏览器默认按钮样式以保持原视觉。 */
const MenuCard = styled.button`
  appearance: none;
  display: flex;
  flex-direction: column;
  justify-content: flex-start;
  align-items: center;
  text-align: center;
  font-family: inherit;
  cursor: pointer;
  background: rgba(255, 255, 255, 0.85);
  border: 1px solid rgba(226, 232, 240, 0.9);
  border-radius: 16px;
  padding: 1.5rem 2rem;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.06);
  transition:
    border-color 0.35s cubic-bezier(0.22, 1, 0.36, 1),
    transform 0.35s cubic-bezier(0.22, 1, 0.36, 1),
    box-shadow 0.35s cubic-bezier(0.22, 1, 0.36, 1);

  &,
  & > * {
    user-select: none;
    -moz-user-select: none;
    -khtml-user-select: none;
    -webkit-user-select: none;
    -o-user-select: none;
  }

  &:hover {
    border-color: rgba(102, 126, 234, 0.4);
    transform: translateY(-3px);
    box-shadow: 0 12px 40px rgba(0, 0, 0, 0.08);
  }

  h3 {
    font-family: 'Inter', -apple-system, sans-serif;
    font-size: 1rem;
    font-weight: 700;
    color: ${({ theme }) => theme.colors.secondaryCta};
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin: 0;
    word-wrap: break-word;
  }

  img {
    margin: 1rem;
    width: 75%;
    max-width: 170px;
    height: auto;
    opacity: 0.9;
  }

  @media screen and (min-width: 648px) {
    font-size: 3rem;
  }

  @media screen and (max-width: 648px) {
    padding: 0.5rem;
  }

  @media screen and (max-width: 468px) {
    flex-direction: row;
    justify-content: space-between;
    border-radius: 90px 40px 40px 90px;
    padding: 0 1rem 0 0;

    h3 {
      text-align: right;
      margin: 0 1rem;
      font-size: 0.9rem;
    }

    img {
      max-width: 80px;
      margin: 0;
    }
  }
`;

/* ===== Component ===== */

export default function Lobby() {
  const navigate = useNavigate();
  const { userName } = useGlobalContext();
  const { getLocalizedString } = useContentContext();
  const { openModal, closeModal } = useModalContext();
  const { isLoggedIn, walletAddress } = useContext(authContext)!;
  const hasWallet = !!walletAddress;

  const requireAuthAndNavigate = () => {
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
    navigate('/play');
  };

  return (
    <PageWrapper>
      <UnclaimedFundsBanner />
      <WelcomeHeading>
        {getLocalizedString('main_page-salutation')}{' '}
        <span><PlayerName name={userName ?? getLocalizedString('main_page-guest-name')} />!</span>
      </WelcomeHeading>

      <MenuGrid>
        <MenuCard type="button" onClick={requireAuthAndNavigate}>
          <img src={kingImg} alt={getLocalizedString('lobby_join-table-alt')} width={196} height={210} loading="lazy" />
          <h3>{getLocalizedString('main_page-join_table').toUpperCase()}</h3>
        </MenuCard>

        <MenuCard type="button" onClick={requireAuthAndNavigate}>
          <img src={queen2Img} alt={getLocalizedString('lobby_quick-game-alt')} width={196} height={206} loading="lazy" />
          <h3>{getLocalizedString('main_page-quick_game').toUpperCase()}</h3>
        </MenuCard>

        <MenuCard
          type="button"
          onClick={() => {
            openModal(
              () => (
                <Text textAlign="center">
                  {getLocalizedString('main_page-modal_text')}
                </Text>
              ),
              getLocalizedString('main_page-modal_heading'),
              getLocalizedString('main_page-modal_button_text'),
            );
          }}
        >
          <img src={jackImg} alt={getLocalizedString('lobby_shop-alt')} />
          <h3>{getLocalizedString('main_page-open_shop').toUpperCase()}</h3>
        </MenuCard>

        <MenuCard type="button" onClick={() => navigate('/game-rules')}>
          <img src={queenImg} alt={getLocalizedString('lobby_rules-alt')} width={196} height={206} loading="lazy" />
          <h3>{getLocalizedString('main_page-open_rules').toUpperCase()}</h3>
        </MenuCard>
      </MenuGrid>
    </PageWrapper>
  );
}
