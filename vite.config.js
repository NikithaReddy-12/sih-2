import { defineConfig } from 'vite';

const api = 'http://127.0.0.1:8000';

export default defineConfig({
  server: {
    proxy: {
      '/api': api,
      '/health': api,
    },
  },
  preview: {
    proxy: {
      '/api': api,
      '/health': api,
    },
  },
});
