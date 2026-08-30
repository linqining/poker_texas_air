import styled from 'styled-components';
import { responsiveScale } from './responsiveScale';

export const UIWrapper = styled.div`
  position: fixed;
  bottom: calc(1vh + env(safe-area-inset-bottom, 0px));
  right: calc(1vh + env(safe-area-inset-right, 0px));
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  grid-gap: 0.5rem;
  background-color: ${({ theme }) => theme.colors.goldChipAlpha80};
  box-shadow: 10px 10px 30px rgba(0, 0, 0, 0.1);
  border-radius: ${({ theme }) => theme.other.stdBorderRadius};
  padding: 1rem;
  transform-origin: bottom right;
  -webkit-backface-visibility: hidden;
  backface-visibility: hidden;
  /* Avoid overscroll chaining from the floating HUD into the page */
  overscroll-behavior: contain;

  ${responsiveScale(0.5)}

  /* Hide on narrow portrait phones: the chip tray is the primary
     in-game control and the HUD would steal touch real-estate. */
  @media screen and (max-width: 479px) and (orientation: portrait) {
    display: none;
  }
`;
