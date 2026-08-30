interface Config {
  isProduction: boolean;
  contentfulSpaceId: string | undefined;
  contentfulAccessToken: string | undefined;
  googleAnalyticsTrackingId: string | undefined;
  socketURI: string;
}

const config: Config = {
  isProduction: import.meta.env.PROD,
  contentfulSpaceId: import.meta.env.VITE_CONTENTFUL_SPACE_ID,
  contentfulAccessToken: import.meta.env.VITE_CONTENTFUL_ACCESS_TOKEN,
  googleAnalyticsTrackingId: import.meta.env.VITE_GOOGLE_ANALYTICS_TRACKING_ID,
  socketURI: import.meta.env.PROD
    ? import.meta.env.VITE_SERVER_URI
    : `http://${window.location.hostname}:9001/`,
};

export default config;

// ========== 游戏相关命名常量 ==========
// 1 chip = 100_000 wei of STRK (1 STRK = 10^18 wei, 1 STRK = 10_000 chips → 1 chip = 10^14 wei)
export const WEI_PER_CHIP = 100_000n;
// StandUp（离开牌桌）等待服务器响应的超时时间
export const STAND_UP_TIMEOUT_MS = 60_000;
// 进入 /play 后若 currentTable 一直为空，重试 join 的最大次数
export const MAX_JOIN_RETRIES = 3;
// 玩家操作（raise/call/fold/check/all-in）loading overlay 的超时兜底时间
export const ACTION_LOADING_TIMEOUT_MS = 30_000;
// join 重试之间的延迟
export const JOIN_RETRY_DELAY_MS = 1500;
// 踢出通知自动消失时间
export const KICK_NOTIFICATION_DISMISS_MS = 5000;
