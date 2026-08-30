import styled from 'styled-components';

export const Select = styled.select`
  height: 40px;
  overflow: hidden;
  padding: 0 0.5rem;
  text-align: right;
  font-size: 1.1rem;
  border: none;
  border-radius: calc(
    ${({ theme }) => theme.other.stdBorderRadius} - 1.25rem
  );
  background-color: ${({ theme }) => theme.colors.playingCardBgLighter};
  border-color: ${({ theme }) => theme.colors.secondaryCta};
  color: ${({ theme }) => theme.colors.primaryCta};
  width: 100%;

  &:focus {
    outline: none;
    border-width: 3px;
    border-color: ${({ theme }) => theme.colors.primaryCta};
  }
`;
