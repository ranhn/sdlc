# ============================================
# VeSync SDLC 安全平台 - 统一后端镜像
# 多阶段构建：先用 Node 构建 Vue3 前端，再运行 FastAPI 后端
# ============================================

# ---- 阶段 1：构建前端 ----
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY frontend/ .
RUN npm run build

# ---- 阶段 2：运行后端 ----
FROM python:3.12-slim
WORKDIR /app

# Python 依赖
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir uvicorn[standard]

# 后端代码
COPY backend/ ./backend/

# 前端构建产物（与 main.py 的 FRONTEND_DIST 路径保持一致）
COPY --from=frontend-builder /app/frontend/dist ./backend/static_new

# 工作目录必须为 backend（main.py 在其中）
WORKDIR /app/backend

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
