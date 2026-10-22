import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig(({ command }) => ({
  plugins: [react()],
  base: '/static/v2/',
  // The router basename differs between the Go-served build (/admin/v2) and
  // `vite dev` (/static/v2, Vite's base). Injecting it as a constant keeps the
  // mode check in the build config instead of the app source.
  define: {
    __FWMON_BASE__: JSON.stringify(command === 'serve' ? '/static/v2' : '/admin/v2'),
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  // Dev-only: `npm run dev` serves the SPA at /static/v2/ (Vite's base), so the
  // API calls the app makes to /admin/** have to reach the Go binary. Without
  // this every fetch 404s against Vite itself and manual QA is impossible
  // without rebuilding the bundle on each change.
  server: {
    proxy: {
      '/admin': {
        target: process.env.FWMON_API_URL || 'http://localhost:8080',
        changeOrigin: false,
      },
    },
  },
  build: {
    outDir: path.resolve(__dirname, '../cmd/api/static/v2'),
    emptyOutDir: true,
    sourcemap: false,
    cssCodeSplit: false,
    rollupOptions: {
      input: path.resolve(__dirname, 'src/main.tsx'),
      output: {
        entryFileNames: 'v2.js',
        chunkFileNames: 'chunks/[name].[hash].js',
        manualChunks: {
          vendor: ['react', 'react-dom', 'react-router'],
          query: ['@tanstack/react-query', '@tanstack/react-table'],
          icons: ['lucide-react'],
        },
        assetFileNames: (assetInfo) => {
          if (assetInfo.names && assetInfo.names.some((n) => n.endsWith('.css'))) {
            return 'v2.css';
          }
          return 'assets/[name].[hash][extname]';
        },
      },
    },
  },
}));
