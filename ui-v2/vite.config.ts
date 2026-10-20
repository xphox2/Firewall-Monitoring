import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  plugins: [react()],
  base: '/static/v2/',
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
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
        chunkFileNames: 'chunks/[name].js',
        manualChunks: {
          vendor: ['react', 'react-dom', 'react-router'],
          query: ['@tanstack/react-query', '@tanstack/react-table'],
          icons: ['lucide-react'],
        },
        assetFileNames: (assetInfo) => {
          if (assetInfo.names && assetInfo.names.some((n) => n.endsWith('.css'))) {
            return 'v2.css';
          }
          return 'assets/[name][extname]';
        },
      },
    },
  },
});
