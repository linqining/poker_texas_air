import 'styled-components';

interface ThemeColors {
  // === Primary Brand Colors ===
  primaryCta: string;
  primaryCtaDarker: string;
  secondaryCta: string;
  secondaryCtaDarker: string;
  secondaryCtaDarkest: string;

  // === Brand Purple (formerly hardcoded #764ba2) ===
  brandPurple: string;
  brandPurpleHover: string;
  brandPurpleLight: string;
  brandPurpleRgb: string; // '118, 75, 162' (for rgba())
  brandPurpleAlpha04: string; // rgba(118,75,162,0.04)
  brandPurpleAlpha10: string; // rgba(118,75,162,0.10)
  brandPurpleAlpha15: string; // rgba(118,75,162,0.15)
  brandGradient: string;
  brandGradientHover: string;

  // === Brand Indigo (secondary CTA #667eea) ===
  brandIndigo: string;     // #667eea
  brandIndigoRgb: string;  // '102, 126, 234' (for rgba())
  brandIndigoAlpha06: string; // rgba(102,126,234,0.06)
  brandIndigoAlpha10: string; // rgba(102,126,234,0.10)
  brandIndigoAlpha12: string; // rgba(102,126,234,0.12)
  brandIndigoAlpha15: string; // rgba(102,126,234,0.15)
  brandIndigoAlpha20: string; // rgba(102,126,234,0.20)
  brandIndigoAlpha25: string; // rgba(102,126,234,0.25)
  brandIndigoAlpha35: string; // rgba(102,126,234,0.35)

  // === Brand Blue ===
  brandBlue: string;
  brandBlueAlpha08: string;
  brandBlueAlpha20: string;

  // === Backgrounds ===
  darkBg: string;
  lightBg: string;
  lightestBg: string;

  // === Font Colors ===
  fontColorLight: string;
  fontColorDark: string;
  fontColorDarkLighter: string;
  mutedText: string;       // #475569
  softText: string;        // #64748b
  softerText: string;      // #94a3b8

  // === Surfaces (glass / muted) ===
  surfaceGlass: string;    // rgba(255,255,255,0.95)
  surfaceMuted: string;    // rgba(241,245,249,0.8)
  surfaceSubtle: string;   // rgba(241,245,249,0.9)
  surfaceMutedPlain: string; // #f1f5f9
  surfaceMutedPlainRgb: string; // '241, 245, 249' (for rgba())

  // === Borders ===
  borderSubtle: string;    // rgba(226,232,240,0.9)
  borderSubtleRgb: string; // '226, 232, 240'
  borderMuted: string;     // rgba(203,213,225,0.8)
  borderMutedRgb: string;  // '203, 213, 225'

  // === Status Colors ===
  success: string;         // #10b981
  successStrong: string;   // #059669
  successAlpha06: string;  // rgba(16,185,129,0.06)
  successAlpha12: string;  // rgba(16,185,129,0.12)
  successAlpha20: string;  // rgba(16,185,129,0.20)
  danger: string;          // #ef4444
  dangerStrong: string;    // #dc2626
  dangerLighter: string;   // hsl(0,100%,56%) — legacy
  dangerBase: string;      // hsl(0,100%,46%) — legacy
  dangerAlpha06: string;   // rgba(239,68,68,0.06)
  dangerAlpha95: string;   // rgba(239,68,68,0.95)
  warning: string;         // #f59e0b
  warningDark: string;     // #b45309
  gold: string;            // #ffd700
  goldDarker: string;      // #d4a843
  goldChip: string;        // #f7f2dc (chip background)
  goldChipAlpha80: string; // rgba(247,242,220,0.8) (empty seat)
  info: string;            // #3b82f6
  infoCyan: string;        // #06b6d4

  // === Other legacy ===
  playingCardBg: string;
  playingCardBgLighter: string;
  goldenColorDarker: string;
  goldenColor: string;
  dangerColorLighter: string;
  dangerColor: string;

  // === Pill (chip) colors ===
  pillDark: string;        // #282215
  pillDarkText: string;    // #fffefc
  pillBorder: string;      // #5b96b5
  pillBackgroundLight: string; // #245069

  // === Disabled ===
  disabled: string;        // rgba(0,0,0,0.3) — used for greyed state
  disabledText: string;    // #94a3b8

  // === Tooltip ===
  tooltipBg: string;       // #1e293b
  tooltipText: string;     // #f8fafc
}

interface ThemeFonts {
  fontFamilySerif: string;
  fontFamilySansSerif: string;
  fontLineHeight: string;
  fontSizeRoot: string;
  fontSizeRootMobile: string;
  fontSizeH1: string;
  fontSizeH2: string;
  fontSizeH3: string;
  fontSizeH4: string;
  fontSizeH5: string;
  fontSizeH6: string;
  fontSizeParagraph: string;
}

interface ThemeRadius {
  pill: string;
  xxl: string;
  xl: string;
  lg: string;
  md: string;
  sm: string;
  xs: string;
  xxs: string;
}

interface ThemeFontSize {
  xxs: string;
  xs: string;
  sm: string;
  base: string;
  md: string;
  lg: string;
  xl: string;
  '2xl': string;
}

interface ThemeTiming {
  fast: string;
  base: string;
  slow: string;
  emphasis: string;
  critical: string;
}

interface ThemeEasing {
  easeOutCubic: string;
  easeStandard: string;
}

interface ThemeZIndex {
  base: number;        // 0
  hidden: number;      // -1
  watermark: number;   // -99
  backdrop: number;    // 100
  nav: number;         // 300
  overlay: number;     // 400
  modal: number;       // 500
  drawer: number;      // 600
  popover: number;     // 700
  toast: number;       // 800
  loading: number;     // 900
  critical: number;    // 1000
}

interface ThemeBreakpoints {
  sm: number;          // 480
  md: number;          // 768
  lg: number;          // 1024
  xl: number;          // 1280
  /** 媒体查询字符串（min-width） */
  up: { sm: string; md: string; lg: string; xl: string };
  /** 媒体查询字符串（max-width） */
  down: { sm: string; md: string; lg: string; xl: string };
}

interface ThemeOther {
  stdBorderRadius: string;
  cardDropShadow: string;
  navMenuDropShadow: string;
  /** iOS safe-area helpers */
  safeAreaTop: string;
  safeAreaBottom: string;
  safeAreaLeft: string;
  safeAreaRight: string;
}

export interface Theme {
  colors: ThemeColors;
  fonts: ThemeFonts;
  radius: ThemeRadius;
  fontSize: ThemeFontSize;
  timing: ThemeTiming;
  easing: ThemeEasing;
  zIndex: ThemeZIndex;
  breakpoints: ThemeBreakpoints;
  other: ThemeOther;
}

declare module 'styled-components' {
  // eslint-disable-next-line @typescript-eslint/no-empty-interface
  export interface DefaultTheme extends Theme {}
}

const up = (bp: number) => `@media (min-width: ${bp}px)`;
const down = (bp: number) => `@media (max-width: ${bp - 1}px)`;

const theme: Theme = {
  // Colors
  colors: {
    // Primary Brand Colors
    primaryCta: '#4f46e5',
    primaryCtaDarker: '#4338ca',
    secondaryCta: '#667eea',
    secondaryCtaDarker: '#5a67d8',
    secondaryCtaDarkest: '#4f46e5',
    // Brand Purple
    brandPurple: '#764ba2',
    brandPurpleHover: '#8559ad',
    brandPurpleLight: '#a78bdb',
    brandPurpleRgb: '118, 75, 162',
    brandPurpleAlpha04: 'rgba(118, 75, 162, 0.04)',
    brandPurpleAlpha10: 'rgba(118, 75, 162, 0.10)',
    brandPurpleAlpha15: 'rgba(118, 75, 162, 0.15)',
    brandGradient: 'linear-gradient(135deg, #667eea, #764ba2)',
    brandGradientHover: 'linear-gradient(135deg, #7b8ff0, #8559ad)',
    // Brand Indigo
    brandIndigo: '#667eea',
    brandIndigoRgb: '102, 126, 234',
    brandIndigoAlpha06: 'rgba(102, 126, 234, 0.06)',
    brandIndigoAlpha10: 'rgba(102, 126, 234, 0.10)',
    brandIndigoAlpha12: 'rgba(102, 126, 234, 0.12)',
    brandIndigoAlpha15: 'rgba(102, 126, 234, 0.15)',
    brandIndigoAlpha20: 'rgba(102, 126, 234, 0.20)',
    brandIndigoAlpha25: 'rgba(102, 126, 234, 0.25)',
    brandIndigoAlpha35: 'rgba(102, 126, 234, 0.35)',
    // Brand Blue
    brandBlue: '#4DA2FF',
    brandBlueAlpha08: 'rgba(77, 162, 255, 0.08)',
    brandBlueAlpha20: 'rgba(77, 162, 255, 0.20)',
    // Backgrounds
    darkBg: '#e2e8f0',
    lightBg: '#f1f5f9',
    lightestBg: '#ffffff',
    // Font Colors
    fontColorLight: '#f8fafc',
    fontColorDark: '#0f172a',
    fontColorDarkLighter: '#334155',
    mutedText: '#475569',
    softText: '#64748b',
    softerText: '#94a3b8',
    // Surfaces
    surfaceGlass: 'rgba(255, 255, 255, 0.95)',
    surfaceMuted: 'rgba(241, 245, 249, 0.8)',
    surfaceSubtle: 'rgba(241, 245, 249, 0.9)',
    surfaceMutedPlain: '#f1f5f9',
    surfaceMutedPlainRgb: '241, 245, 249',
    // Borders
    borderSubtle: 'rgba(226, 232, 240, 0.9)',
    borderSubtleRgb: '226, 232, 240',
    borderMuted: 'rgba(203, 213, 225, 0.8)',
    borderMutedRgb: '203, 213, 225',
    // Status Colors
    success: '#10b981',
    successStrong: '#059669',
    successAlpha06: 'rgba(16, 185, 129, 0.06)',
    successAlpha12: 'rgba(16, 185, 129, 0.12)',
    successAlpha20: 'rgba(16, 185, 129, 0.20)',
    danger: '#ef4444',
    dangerStrong: '#dc2626',
    dangerLighter: 'hsl(0, 100%, 56%)',
    dangerBase: 'hsl(0, 100%, 46%)',
    dangerAlpha06: 'rgba(239, 68, 68, 0.06)',
    dangerAlpha95: 'rgba(239, 68, 68, 0.95)',
    warning: '#f59e0b',
    warningDark: '#b45309',
    gold: '#ffd700',
    goldDarker: '#d4a843',
    goldChip: '#f7f2dc',
    goldChipAlpha80: 'rgba(247, 242, 220, 0.8)',
    info: '#3b82f6',
    infoCyan: '#06b6d4',
    // Other legacy
    playingCardBg: '#f8fafc',
    playingCardBgLighter: '#ffffff',
    goldenColorDarker: '#d4a843',
    goldenColor: '#e2b84d',
    dangerColorLighter: 'hsl(0, 100%, 56%)',
    dangerColor: 'hsl(0, 100%, 46%)',
    // Pill (chip) colors
    pillDark: '#282215',
    pillDarkText: '#fffefc',
    pillBorder: '#5b96b5',
    pillBackgroundLight: '#245069',
    // Disabled
    disabled: 'rgba(0, 0, 0, 0.3)',
    disabledText: '#94a3b8',
    // Tooltip
    tooltipBg: '#1e293b',
    tooltipText: '#f8fafc',
  },
  // Fonts
  fonts: {
    fontFamilySerif: "'Playfair Display', serif",
    fontFamilySansSerif: "'Roboto', sans-serif",
    // Use clamp() so portrait phones don't blow up H1
    fontLineHeight: '1.4',
    fontSizeRoot: '1em',
    fontSizeRootMobile: '0.9em',
    fontSizeH1: 'clamp(1.6rem, 4.5vmin + 1rem, 2.5rem)',
    fontSizeH2: 'clamp(1.4rem, 4vmin + 0.9rem, 2.1rem)',
    fontSizeH3: 'clamp(1.25rem, 3.5vmin + 0.85rem, 1.85rem)',
    fontSizeH4: 'clamp(1.15rem, 3vmin + 0.8rem, 1.6rem)',
    fontSizeH5: 'clamp(1.05rem, 2.5vmin + 0.75rem, 1.4rem)',
    fontSizeH6: 'clamp(1rem, 2vmin + 0.7rem, 1.2rem)',
    fontSizeParagraph: '1.2rem',
  },
  // Radius scale (used by Modal, Cards, Buttons, Chips)
  radius: {
    pill: '999px',
    xxl: '2rem',
    xl: '20px',
    lg: '16px',
    md: '12px',
    sm: '10px',
    xs: '8px',
    xxs: '6px',
  },
  // Font size scale
  fontSize: {
    xxs: '0.7rem',
    xs: '0.75rem',
    sm: '0.85rem',
    base: '1rem',
    md: '1.1rem',
    lg: '1.3rem',
    xl: '1.5rem',
    '2xl': '1.6rem',
  },
  // Animation timing tokens
  timing: {
    fast: '0.2s',
    base: '0.3s',
    slow: '0.4s',
    emphasis: '0.6s',
    critical: '1s',
  },
  // Easing curves
  easing: {
    easeOutCubic: 'cubic-bezier(0.22, 1, 0.36, 1)',
    easeStandard: 'ease',
  },
  // Z-index scale
  zIndex: {
    base: 0,
    hidden: -1,
    watermark: -99,
    backdrop: 100,
    nav: 300,
    overlay: 400,
    modal: 500,
    drawer: 600,
    popover: 700,
    toast: 800,
    loading: 900,
    critical: 1000,
  },
  // Breakpoints
  breakpoints: {
    sm: 480,
    md: 768,
    lg: 1024,
    xl: 1280,
    up: {
      sm: up(480),
      md: up(768),
      lg: up(1024),
      xl: up(1280),
    },
    down: {
      sm: down(480),
      md: down(768),
      lg: down(1024),
      xl: down(1280),
    },
  },
  // Other styles
  other: {
    stdBorderRadius: '2rem',
    cardDropShadow: '0 8px 30px rgba(0, 0, 0, 0.06)',
    navMenuDropShadow: '-10px 0px 30px rgba(0, 0, 0, 0.06)',
    safeAreaTop: 'env(safe-area-inset-top, 0px)',
    safeAreaBottom: 'env(safe-area-inset-bottom, 0px)',
    safeAreaLeft: 'env(safe-area-inset-left, 0px)',
    safeAreaRight: 'env(safe-area-inset-right, 0px)',
  },
};

export default theme;
