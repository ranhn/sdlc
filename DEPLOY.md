# SDLC 安全平台 - 部署指南

## 架构

```
┌─────────────┐     HTTPS (443)      ┌─────────────┐
│   浏览器    │ ◄──────────────────► │   Nginx     │
└─────────────┘   HTTP (80) → HTTPS   │  (反向代理) │
                                       └──────┬──────┘
                                              │ HTTP (8000)
                                              ▼
                                       ┌─────────────┐
                                       │  FastAPI    │
                                       │  (后端 API) │
                                       └──────┬──────┘
                                              │
                                              ▼
                                       ┌─────────────┐
                                       │   SQLite    │
                                       │   uploads/  │
                                       └─────────────┘
```

## 部署步骤

### 1. 准备服务器

```bash
# 安装 Docker
curl -fsSL https://get.docker.com | sh
systemctl start docker
systemctl enable docker

# 安装 Docker Compose（如果未自带）
apt install docker-compose-plugin  # Debian/Ubuntu
```

### 2. 上传代码

```bash
# 方式 1：git clone
git clone <repo> /opt/sdlc-platform
cd /opt/sdlc-platform

# 方式 2：scp 上传
scp -r sdlc-platform/ user@server:/opt/
```

### 3. 配置环境变量

```bash
cp .env.example .env
nano .env
```

**必填项**：
```bash
# 生成强随机密钥
SECRET_KEY=$(openssl rand -hex 32)

# CORS 白名单（填实际域名）
CORS_ORIGINS=https://sdlc.yourcompany.com

# 域名
DOMAIN=sdlc.yourcompany.com
```

### 4. 构建前端

```bash
cd frontend
npm install
npm run build
cd ..
```

### 5. 启动服务

```bash
docker compose up -d --build
docker compose ps  # 查看状态
docker compose logs -f  # 查看日志
```

### 6. 配置 HTTPS（Let's Encrypt）

#### 方式 A：宿主机 certbot（推荐）

```bash
# 安装 certbot
apt install certbot

# 申请证书（需先停止 Nginx 80 端口，或用 standalone 模式）
certbot certonly --standalone -d sdlc.yourcompany.com

# 证书会放在 /etc/letsencrypt/live/sdlc.yourcompany.com/
# 复制到 nginx/ssl 目录
mkdir -p nginx/ssl
cp /etc/letsencrypt/live/sdlc.yourcompany.com/fullchain.pem nginx/ssl/
cp /etc/letsencrypt/live/sdlc.yourcompany.com/privkey.pem nginx/ssl/

# 重启 Nginx
docker compose restart nginx
```

#### 方式 B：自动续期

```bash
# 编辑 crontab
crontab -e

# 每月 1 号凌晨 3 点续期 + 复制到 nginx/ssl + 重启
0 3 1 * * certbot renew --quiet && cp /etc/letsencrypt/live/sdlc.yourcompany.com/fullchain.pem /opt/sdlc-platform/nginx/ssl/ && cp /etc/letsencrypt/live/sdlc.yourcompany.com/privkey.pem /opt/sdlc-platform/nginx/ssl/ && cd /opt/sdlc-platform && docker compose restart nginx
```

### 7. 配置防火墙

```bash
# 开放 80 和 443
ufw allow 80/tcp
ufw allow 443/tcp

# 关闭 8000（不再需要外部访问）
# ufw deny 8000
```

### 8. 验证

```bash
# HTTP 应跳转到 HTTPS
curl -I http://sdlc.yourcompany.com

# HTTPS 应正常响应
curl -I https://sdlc.yourcompany.com

# API 健康检查
curl https://sdlc.yourcompany.com/api/health
```

## 日常运维

### 查看日志

```bash
# 应用日志
docker compose logs -f sdlc

# Nginx 访问日志
tail -f nginx/logs/access.log

# Nginx 错误日志
tail -f nginx/logs/error.log
```

### 重启服务

```bash
docker compose restart
```

### 更新代码

```bash
git pull
cd frontend && npm run build && cd ..
docker compose up -d --build
```

### 备份

```bash
# 手动备份
./backup.sh

# 恢复
./restore.sh
```

详见 [BACKUP.md](BACKUP.md)。

## 故障排查

### 502 Bad Gateway

```bash
# 检查后端是否启动
docker compose ps
docker compose logs sdlc

# 检查网络
docker network inspect sdlc-platform_sdlc-net
```

### 证书过期

```bash
# 查看证书到期时间
openssl x509 -in nginx/ssl/fullchain.pem -noout -dates

# 手动续期
certbot renew
cp /etc/letsencrypt/live/<domain>/fullchain.pem nginx/ssl/
cp /etc/letsencrypt/live/<domain>/privkey.pem nginx/ssl/
docker compose restart nginx
```

### 磁盘空间不足

```bash
# 查看 Docker 占用的空间
docker system df

# 清理无用镜像
docker image prune -a

# 清理旧备份
find backups/ -name "*.tar.gz" -mtime +30 -delete
```

## 性能调优

### Nginx

```nginx
# nginx.conf 中调整
worker_processes auto;  # 自动按 CPU 核心数
worker_connections 2048;
```

### FastAPI

```bash
# docker-compose.yml 中调整
command: uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

### 数据库

生产环境建议从 SQLite 切换到 PostgreSQL：

```bash
# .env
DATABASE_URL=postgresql://user:pass@postgres:5432/sdlc_platform
```

并在 docker-compose.yml 中加 postgres 服务。
