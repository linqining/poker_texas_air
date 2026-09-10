import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

// 游戏服务器地址（vite 代理目标）：GAME_SERVER_URL 环境变量可覆盖
// （scripts/dev.sh 用 PORT=xxxx 拉起时同步导出）；默认本地 9001。
const gameServer = process.env.GAME_SERVER_URL ?? 'http://127.0.0.1:9001';

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    proxy: {
      '/api': gameServer,
      '/socket.io': {
        target: gameServer,
        ws: true,
      },
    },
  },
  assetsInclude: ['**/*.wasm'],
});
