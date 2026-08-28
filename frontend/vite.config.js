import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import path from 'path'

// 开发环境代理到统一后端（backend/main.py，端口 8001）
const BACKEND = 'http://127.0.0.1:8001'

export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src'),
    },
  },
  server: {
    port: 5173,
    host: true,
    proxy: {
      // SDLC 业务 API
      '/api': {
        target: BACKEND,
        changeOrigin: true,
      },
      // AI 威胁建模子应用 API（精确匹配 /threat/api，避免拦截 /threat-modeling 前端路由）
      '/threat/api': {
        target: BACKEND,
        changeOrigin: true,
      },
    },
  },
  build: {
    chunkSizeWarningLimit: 1500,
    cssMinify: false,
    minify: false,
    outDir: 'dist',
  },
})
