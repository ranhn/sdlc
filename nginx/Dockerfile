# ============================================
# VeSync SDLC 安全平台 - Nginx 镜像
# 多阶段构建：先用 Node 构建 Vue3 前端，再镜像到 nginx
# 同时在 nginx 阶段生成自签 SSL 证书（生产请挂载真实证书覆盖）
# 注意：docker-compose 里 build context = 项目根，所有路径相对项目根
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

# 安装 openssl 用于生成自签证书
RUN apk add --no-cache openssl

# 复制自定义配置（路径相对项目根 context）
COPY nginx/nginx.conf /etc/nginx/nginx.conf

# 从前端构建阶段拷贝产物
COPY --from=frontend-builder /app/frontend/dist /usr/share/nginx/html

# 生成自签证书（如挂载了真实证书会覆盖此文件）
# 浏览器会报警告；生产请把证书放到 nginx/ssl/ 目录挂载进来
RUN mkdir -p /etc/nginx/ssl /var/www/certbot && \
    openssl req -x509 -nodes -days 3650 \
        -newkey rsa:2048 \
        -keyout /etc/nginx/ssl/privkey.pem \
        -out /etc/nginx/ssl/fullchain.pem \
        -subj "/CN=localhost" 2>/dev/null

# 暴露端口
EXPOSE 80 443

CMD ["nginx", "-g", "daemon off;"]
