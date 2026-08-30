import { createGlobalStyle } from 'styled-components';

const GlobalStyles = createGlobalStyle`
  :root {
    box-sizing: border-box;
    font-size: ${(props) => props.theme.fonts.fontSizeRoot};
  }

  *,
  *::before,
  *::after {
    margin: 0;
    padding: 0;
    scrollbar-width: thin;
    scrollbar-color: ${(props) => props.theme.colors.secondaryCta} ${(props) =>
  props.theme.colors.lightBg};
    box-sizing: inherit;
  }

  /* Use :focus-visible (keyboard-only) so touch users don't get rings.
     iOS / Android still get visual focus via :focus-visible when an
     external keyboard / assistive switch is connected. */
  *:focus-visible {
    outline: 2px solid ${(props) => props.theme.colors.primaryCta};
    outline-offset: 2px;
  }

  *::-webkit-scrollbar {
    width: 0.75rem;
    transition: background-color ${(props) => props.theme.timing.base} ${(props) =>
  props.theme.easing.easeStandard};
  }

  *::-webkit-scrollbar-track {
    background: ${(props) => props.theme.colors.lightBg};
  }

  *::-webkit-scrollbar-thumb {
    background-color: ${(props) => props.theme.colors.secondaryCta};
    border-radius: ${(props) => props.theme.radius.pill};
  }

  *::-webkit-scrollbar-thumb:hover {
    background-color: ${(props) => props.theme.colors.primaryCta};
  }

  ::-moz-selection {
    background: ${(props) => props.theme.colors.primaryCta};
    color: #ffffff;
  }

  ::selection {
    background: ${(props) => props.theme.colors.primaryCta};
    color: #ffffff;
  }

  html {
    /* Prevent rubber-band scroll chaining and accidental pull-to-refresh */
    overscroll-behavior-y: contain;
    /* Better touch behavior on iOS */
    -webkit-text-size-adjust: 100%;
    /* Document-level scroll snap. Set on <html> so it covers the entire
       page (any <body> child) and works in tandem with
       scroll-snap-align: start on per-section targets. This keeps
       native page-level scrolling instead of trapping it inside a
       nested overflow:auto island (which on some browsers never
       receives the wheel/touch gesture). */
    scroll-snap-type: y proximity;
    scroll-behavior: smooth;
  }

  body {
    background-color: ${(props) => props.theme.colors.lightestBg};
    color: ${(props) => props.theme.colors.fontColorDark};
    font-family: ${(props) => props.theme.fonts.fontFamilySansSerif};
    line-height: ${(props) => props.theme.fonts.fontLineHeight};
    font-weight: 400;
    /* Prevent horizontal scroll bleed when fixed positioned UI overflows */
    overflow-x: hidden;
    /* Better touch behavior — disable double-tap zoom and other gestures */
    touch-action: manipulation;
    /* Safe area support (iPhone notch) */
    padding-top: ${(props) => props.theme.other.safeAreaTop};
    padding-bottom: ${(props) => props.theme.other.safeAreaBottom};
    padding-left: ${(props) => props.theme.other.safeAreaLeft};
    padding-right: ${(props) => props.theme.other.safeAreaRight};
  }

  hr {
    background-color: ${(props) => props.theme.colors.darkBg};
    height: 1px;
  }

  a {
    text-decoration: none;
    color: ${(props) => props.theme.colors.primaryCta};
    font-weight: bold;

    &:visited {
      color: ${(props) => props.theme.colors.primaryCta};
    }

    &:hover {
      color: ${(props) => props.theme.colors.primaryCtaDarker};
    }

    &:active {
      color: ${(props) => props.theme.colors.primaryCtaDarker};
    }
  }

  h1,
  h2,
  h3,
  h4,
  h5,
  h5 {
    font-family: ${(props) => props.theme.fonts.fontFamilySerif};
    font-weight: 400;
    margin-bottom: 1.5rem;
  }

  h1,
  .h1 {
    font-size: ${(props) => props.theme.fonts.fontSizeH1};
  }

  h2,
  .h2 {
    font-size: ${(props) => props.theme.fonts.fontSizeH2};
  }

  h3,
  .h3 {
    font-size: ${(props) => props.theme.fonts.fontSizeH3};
  }

  h4,
  .h4 {
    font-size: ${(props) => props.theme.fonts.fontSizeH4};
  }

  h5,
  .h5 {
    font-size: ${(props) => props.theme.fonts.fontSizeH5};
  }

  h6,
  .h6 {
    font-size: ${(props) => props.theme.fonts.fontSizeH6};
  }

  p {
    font-family: ${(props) => props.theme.fonts.fontFamilySansSerif};
    font-size: ${(props) => props.theme.fonts.fontSizeParagraph};
    font-weight: 400;
    line-height: ${(props) => props.theme.fonts.fontLineHeight};
    margin-bottom: 1rem;
  }

  input,
  textarea,
  button,
  div,
  select,
  a {
    -webkit-tap-highlight-color: rgba(0,0,0,0);
  }

  img {
    max-width: 100%;
  }

  @media screen and (max-width: 1023px) {
    :root {
      font-size: ${(props) => props.theme.fonts.fontSizeRootMobile};
    }
  }
`;

export default GlobalStyles;
