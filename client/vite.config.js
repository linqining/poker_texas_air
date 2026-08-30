import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';
export default defineConfig({
    plugins: [react()],
    resolve: {
        alias: {
            '@': path.resolve(__dirname, './src'),
        },
    },
    server: {
        proxy: {
            '/api': 'http://127.0.0.1:9001',
            '/socket.io': {
                target: 'http://127.0.0.1:9001',
                ws: true,
            },
        },
    },
    assetsInclude: ['**/*.wasm'],
});
