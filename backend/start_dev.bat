@echo off
REM ============================================
REM SDLC 安全平台 - 本地开发启动脚本
REM 用途：开发环境启动后端（端口 8001，前端 Vite 代理到 8001）
REM 用法：双击运行，或在 backend 目录下执行 .\start_dev.bat
REM 端口对齐：frontend/vite.config.js 中的 BACKEND = http://127.0.0.1:8001
REM ============================================

REM 切到脚本所在目录（不依赖绝对路径）
cd /d "%~dp0"

REM 必填：JWT 签名密钥（生产请用 openssl rand -hex 32 生成）
set SECRET_KEY=dev-secret-key-for-local-testing-only-32chars

REM CORS 白名单：本地 Vite(5173) + 后端自身(8001)
set CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:8001,http://localhost:8001

REM 数据库：使用相对路径，便于跨机器
set DATABASE_URL=sqlite:///./security_platform.db

REM 启动
REM 使用统一入口 main.py（同时挂载 SDLC 业务子应用 + /threat AI 威胁建模 + Vue3 前端 SPA）
REM 单独的 app.app_entry:app 不会挂载威胁建模，会导致 /threat/api/* 全部 404
uvicorn main:app --host 127.0.0.1 --port 8001 --reload --no-use-colors
