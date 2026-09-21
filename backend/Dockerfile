# ============================================
# VeSync SDLC 安全平台 - 统一后端镜像
# 多阶段构建：先用 Node 构建 Vue3 前端，再运行 FastAPI 后端
# ============================================

# ---- 阶段 1：构建前端 ----
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json* ./
# BuildKit 缓存挂载：npm 下载缓存留在构建缓存里（不写进镜像层）
RUN --mount=type=cache,target=/root/.npm \
    npm install --no-audit --no-fund
COPY frontend/ .
RUN npm run build

# ---- 阶段 2：运行后端 ----
# 注意：不要用浮动 tag。python:3.12-slim 上游一重新发布，下面 COPY/RUN 的层缓存
# 会全部失效、依赖要从 PyPI 全量重下（实测一次构建 380s 主要耗在这）。
# 需要锁版本时在构建机上取一次 digest 贴上来：
#   docker image inspect python:3.12-slim --format '{{index .RepoDigests 0}}'
FROM python:3.12-slim
WORKDIR /app

# Python 依赖
# BuildKit 缓存挂载：pip 下载缓存留在构建缓存里、不写进镜像层（体积不变）。
# 层缓存失效也能离线装包，几秒完成，不必再按带宽全量下载。
COPY backend/requirements.txt ./requirements.txt
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install -r requirements.txt \
    && pip install "uvicorn[standard]"

# 中文字体：Word 报告里的数据流图（后端 PIL 渲染）依赖它。
# slim 镜像默认**没有任何字体**，缺字体时导出的图会"只有框线、没有文字"，
# 而且过去是静默的（修完才加的日志）—— 排查一次很费劲，这里一次性装好。
# 体积：fonts-noto-cjk 约 90MB；只想要小体积可换成 fonts-wqy-zenhei（约 5MB），
# 两者路径都已在 dfd_renderer.font_candidates 里。
RUN apt-get update \
    && apt-get install -y --no-install-recommends fonts-noto-cjk fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

# 后端代码
COPY backend/ ./backend/

# 前端构建产物（与 main.py 的 FRONTEND_DIST 路径保持一致）
COPY --from=frontend-builder /app/frontend/dist ./backend/static_new

# 工作目录必须为 backend（main.py 在其中）
WORKDIR /app/backend

EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
