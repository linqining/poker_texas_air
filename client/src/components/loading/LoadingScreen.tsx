import React from 'react';
import styled, { keyframes } from 'styled-components';
import Loader from './Loader';

const fadeIn = keyframes`
  from { opacity: 0; }
  to { opacity: 1; }
`;

const StyledLoadingScreen = styled.div`
  width: 100%;
  min-height: 100dvh;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
  overflow: hidden;
  background: ${({ theme }) => theme.colors.fontColorLight};
  animation: ${fadeIn} 0.3s ease-out;

  &::before {
    content: '';
    position: absolute;
    inset: 0;
    background:
      radial-gradient(circle at 30% 40%, rgba(102, 126, 234, 0.12) 0%, transparent 50%),
      radial-gradient(circle at 70% 60%, rgba(118, 75, 162, 0.12) 0%, transparent 50%),
      radial-gradient(circle at 50% 80%, rgba(6, 182, 212, 0.08) 0%, transparent 40%);
    pointer-events: none;
  }

  &::after {
    content: '';
    position: absolute;
    inset: 0;
    background-image:
      linear-gradient(rgba(0, 0, 0, 0.04) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0, 0, 0, 0.04) 1px, transparent 1px);
    background-size: 60px 60px;
    pointer-events: none;
    mask-image: radial-gradient(ellipse at center, black 0%, transparent 70%);
    -webkit-mask-image: radial-gradient(ellipse at center, black 0%, transparent 70%);
  }
`;

const LoadingScreen: React.FC = () => (
  <StyledLoadingScreen>
    <Loader />
  </StyledLoadingScreen>
);

export default LoadingScreen;
