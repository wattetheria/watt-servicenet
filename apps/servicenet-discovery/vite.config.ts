import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': '/src',
    },
  },
  server: {
    host: '0.0.0.0',
    port: 5174,
    proxy: {
      '/api/servicenet': {
        target: process.env.SERVICENET_API_URL ?? 'http://127.0.0.1:8042',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/servicenet/, ''),
      },
    },
  },
})
