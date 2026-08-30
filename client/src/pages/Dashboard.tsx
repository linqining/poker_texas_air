import React, { useContext } from 'react';
import { Link } from 'react-router-dom';
import Button from '../components/buttons/Button';
import { Input } from '../components/forms/Input';
import styled from 'styled-components';
import LogoWithText from '../components/logo/LogoWithText';
import { useGlobalContext } from '../context/global/globalContext';
import { useContentContext } from '../context/content/contentContext';

const PageWrapper = styled.div`
  min-height: 100dvh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: #f1f5f9;
  padding: 2rem;
`;

const DashboardCard = styled.div`
  width: 100%;
  max-width: 600px;
  background: rgba(255, 255, 255, 0.85);
  border: 1px solid rgba(226, 232, 240, 0.9);
  border-radius: 20px;
  padding: 2.5rem 2rem;
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
`;

const LogoWrapper = styled.div`
  display: flex;
  justify-content: center;
  margin-bottom: 2rem;
`;

const FormTitle = styled.h2`
  font-family: 'Inter', -apple-system, sans-serif;
  font-size: 1.5rem;
  font-weight: 700;
  text-align: center;
  color: ${({ theme }) => theme.colors.fontColorDark};
  margin-bottom: 2rem;
  letter-spacing: -0.02em;
`;

const Wrapper = styled.div`
  display: grid;
  grid-template-columns: 1fr 1fr;
  grid-gap: 1.25rem;
  margin-bottom: 1.5rem;

  @media screen and (max-width: 624px) {
    display: flex;
    flex-direction: column;
    gap: 1.25rem;
  }
`;

const FormGroup = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
`;

const StyledLabel = styled.label`
  font-size: 0.85rem;
  color: #475569;
  font-weight: 500;
`;

const StyledInput = styled(Input)`
  background: ${({ theme }) => theme.colors.lightestBg} !important;
  border: 1px solid rgba(203, 213, 225, 0.8) !important;
  border-radius: 10px !important;
  color: ${({ theme }) => theme.colors.fontColorDark} !important;
  height: 44px;
  font-size: 1rem;

  &:focus {
    border-color: ${({ theme }) => theme.colors.secondaryCta} !important;
    box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.15);
  }
`;

const ActionButton = styled(Button)`
  background: linear-gradient(135deg, ${({ theme }) => theme.colors.secondaryCta}, #764ba2) !important;
  color: ${({ theme }) => theme.colors.lightestBg} !important;
  border: none !important;
  border-radius: 10px !important;
  font-weight: 600 !important;
  height: 40px;
  box-shadow: 0 2px 12px rgba(102, 126, 234, 0.2) !important;
  transition:
    box-shadow 0.3s ease,
    transform 0.3s ease !important;

  &:hover:not(:disabled) {
    box-shadow: 0 4px 20px rgba(102, 126, 234, 0.35) !important;
    transform: translateY(-1px);
  }
`;

const DangerButton = styled(Button)`
  background: rgba(241, 245, 249, 0.8) !important;
  color: #64748b !important;
  border: 1px solid rgba(203, 213, 225, 0.8) !important;
  border-radius: 10px !important;
  font-weight: 500 !important;
  height: 40px;
  transition:
    border-color 0.25s ease,
    color 0.25s ease,
    background-color 0.25s ease !important;

  &:hover {
    border-color: rgba(226, 232, 240, 0.9) !important;
    color: #ef4444 !important;
    background: rgba(241, 245, 249, 1) !important;
  }
`;

const BackButton = styled(Button)`
  background: transparent !important;
  color: #64748b !important;
  border: 1px solid rgba(203, 213, 225, 0.8) !important;
  border-radius: 10px !important;
  font-weight: 500 !important;
  height: 40px;
  transition:
    border-color 0.25s ease,
    color 0.25s ease !important;

  &:hover {
    border-color: rgba(102, 126, 234, 0.4) !important;
    color: ${({ theme }) => theme.colors.secondaryCta} !important;
  }
`;

const FullWidthGroup = styled.div`
  grid-column: 1 / -1;
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
`;

const Dashboard: React.FC = () => {
  const { getLocalizedString } = useContentContext();
  const { userName, email } = useGlobalContext();

  return (
    <PageWrapper>
      <DashboardCard>
        <LogoWrapper>
          <LogoWithText />
        </LogoWrapper>
        <FormTitle>{getLocalizedString('dashboard-heading_txt')}</FormTitle>
        <Wrapper>
          <FormGroup>
            <StyledLabel>{getLocalizedString('dashboard-nickname_lbl_txt')}</StyledLabel>
            <StyledInput value={userName ?? ''} readOnly />
            <ActionButton primary>
              {getLocalizedString('dashboard-nickname_btn_txt')}
            </ActionButton>
          </FormGroup>
          <FormGroup>
            <StyledLabel>{getLocalizedString('dashboard-email_lbl_txt')}</StyledLabel>
            <StyledInput type="email" value={email ?? ''} readOnly />
            <ActionButton primary>
              {getLocalizedString('dashboard-email_btn_txt')}
            </ActionButton>
          </FormGroup>
          <FullWidthGroup>
            <ActionButton primary>
              {getLocalizedString('dashboard-reset_pw_btn_text')}
            </ActionButton>
            <DangerButton>
              {getLocalizedString('dashboard-delete_acct_btn_text')}
            </DangerButton>
          </FullWidthGroup>
          <FullWidthGroup>
            <BackButton as={Link} to="/">
              {getLocalizedString('static_page-back_btn_txt')}
            </BackButton>
          </FullWidthGroup>
        </Wrapper>
      </DashboardCard>
    </PageWrapper>
  );
};

export default Dashboard;
