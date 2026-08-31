# ============================================
# VeSync SDLC 安全平台 - Nginx 镜像
# 多阶段构建：先用 Node 构建 Vue3 前端，再镜像到 nginx
# 原因：单阶段 COPY frontend/dist 会因宿主机没有 dist 目录而失败
# 注意：docker-compose 里 build context = 项目根，所以所有路径相对项目根
# ============================================

# ---- 阶段 1：构建前端 ----
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY frontend/ .
RUN npm run build

# ---- 阶段 2：nginx ----
FROM nginx:1.25-alpine

# 复制自定义配置（路径相对项目根 context）
COPY nginx/nginx.conf /etc/nginx/nginx.conf

# 从前端构建阶段拷贝产物
COPY --from=frontend-builder /app/frontend/dist /usr/share/nginx/html

# 创建 SSL 证书目录
RUN mkdir -p /etc/nginx/ssl /var/www/certbot

# 暴露端口
EXPOSE 80 443

CMD ["nginx", "-g", "daemon off;"]
