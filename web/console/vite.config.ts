// Vite config for the Fortik console. The production bundle is written into
// internal/console/dist, where the Go binary embeds it (go:embed) and serves
// it at "/". In development, `npm run dev` proxies the API and auth routes to
// a local `fortik serve` on 127.0.0.1:8080 so session cookies stay same-origin.
import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

const api = 'http://127.0.0.1:8080';

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: '../../internal/console/dist',
    emptyOutDir: true,
    sourcemap: false,
    assetsDir: 'assets',
  },
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    proxy: {
      // Host/Origin are kept as the dev server's (changeOrigin false): the
      // API's dev-login origin check compares Origin with Host.
      '/v1': { target: api, changeOrigin: false },
      '/auth': { target: api, changeOrigin: false },
    },
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    css: false,
  },
});
