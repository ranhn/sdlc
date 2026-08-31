# SDLC 安全平台 - 部署指南

## 架构

```
┌─────────────┐     HTTPS (443)      ┌─────────────┐
│   浏览器    │ ◄──────────────────► │   Nginx     │
└─────────────┘   HTTP (80) → HTTPS   │  HTTPS终结  │
                                       │  静态托管   │
                                       └──┬──────┬───┘
                                          │      │ 反代 /api/* /threat/*
                                          ▼      ▼
                                    ┌─────────────────┐
                                    │     FastAPI     │
                                    │  (业务 API +    │
                                    │  Vue3 SPA +     │
                                    │  /threat 子应用)│
                                    └────────┬────────┘
                                             │
                                             ▼
                                    ┌─────────────────┐
                                    │ sdlc_db         │
                                    │ sdlc_uploads    │  (named volumes)
                                    └─────────────────┘
```

## 数据持久化

| 卷名 | 挂载点（容器内） | 内容 | 备份建议 |
|---|---|---|---|
| `sdlc_db` | `/app/backend/data` | SQLite 数据库 | 每日 |
| `sdlc_uploads` | `/app/backend/uploads` | 用户上传的附件 | 每日 |

> ⚠️ **重要**：本项目**只挂数据子目录**，不再整目录挂载 `backend/`。这避免 Docker named volume 在首次启动后"冻结"代码导致 `update.sh` 看似成功但代码不生效。

## 首次部署（5 分钟）

```bash
# 1. 在目标服务器（root 权限）执行
bash <(curl -fsSL https://raw.githubusercontent.com/ranhn/sdlc/main/deploy.sh)

# 或先下载再执行
curl -fsSL https://raw.githubusercontent.com/ranhn/sdlc/main/deploy.sh -o deploy.sh
bash deploy.sh
```

`deploy.sh` 会自动完成：
1. 安装 Docker（如未装）
2. 克隆代码到 `/opt/sdlc-platform`
3. 生成 `.env`（含强随机 `SECRET_KEY`）
4. 开放 80/443 防火墙
5. 构建并启动
6. 等待健康检查通过

部署完**立即做**：
- [ ] **修改默认密码** `admin / admin123`（登录后"个人中心 → 修改密码"）
- [ ] 检查 `.env` 中 `CORS_ORIGINS` 和 `DOMAIN` 是否符合实际环境
- [ ] 申请 HTTPS 证书（见下）

## 后续更新

```bash
cd /opt/sdlc-platform
./update.sh
```

`update.sh` 会自动：
1. `git pull` 拉取最新代码
2. `docker compose up -d --build` 重新构建并启动
3. 健康检查通过即完成

> 💡 数据库结构和数据**不会被破坏**（代码在 image 里、数据在 volume 里）。

## 数据备份

### 手动备份

```bash
./backup.sh
# 默认备份到 /backup/sdlc/sdlc-YYYYMMDD-HHMMSS.tar.gz
# 自动保留 30 天

./backup.sh /data/backups   # 自定义备份目录
```

### 定时备份（推荐）

```bash
crontab -e
# 每天凌晨 2 点备份
0 2 * * * cd /opt/sdlc-platform && ./backup.sh >> /var/log/sdlc-backup.log 2>&1
```

### 恢复

```bash
./restore.sh /backup/sdlc/sdlc-20260831-120000.tar.gz
# 按提示输入 yes 确认
```

## HTTPS 配置

### 方式 A：Let's Encrypt（推荐，**外网域名**）

```bash
# 1. 安装 certbot
apt install certbot

# 2. 申请证书（首次需临时停止 Nginx 占用的 80，或用 standalone 模式）
certbot certonly --standalone -d sdlc.yourcompany.com

# 3. 复制到项目
mkdir -p nginx/ssl
cp /etc/letsencrypt/live/sdlc.yourcompany.com/fullchain.pem nginx/ssl/
cp /etc/letsencrypt/live/sdlc.yourcompany.com/privkey.pem nginx/ssl/

# 4. 重启 Nginx
docker compose restart nginx
```

### 方式 B：内网自签证书

```bash
mkdir -p nginx/ssl
openssl req -x509 -nodes -days 3650 \
  -newkey rsa:2048 \
  -keyout nginx/ssl/privkey.pem \
  -out nginx/ssl/fullchain.pem \
  -subj "/CN=sdlc.yourcompany.com"
docker compose restart nginx
```

### 自动续期

```bash
crontab -e
# 每月 1 号凌晨 3 点续期
0 3 1 * * certbot renew --quiet && cp /etc/letsencrypt/live/sdlc.yourcompany.com/fullchain.pem /opt/sdlc-platform/nginx/ssl/ && cp /etc/letsencrypt/live/sdlc.yourcompany.com/privkey.pem /opt/sdlc-platform/nginx/ssl/ && cd /opt/sdlc-platform && docker compose restart nginx
```

## 环境变量（.env）

| 变量 | 必填 | 说明 |
|---|---|---|
| `SECRET_KEY` | ✅ | JWT 签名密钥，**至少 32 位随机** |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | - | Token 过期分钟，默认 720 (12h) |
| `CORS_ORIGINS` | ✅ | 允许的前端域名，逗号分隔 |
| `DOMAIN` | ✅ | 访问域名 |
| `DATABASE_URL` | - | 默认 `sqlite:///./data/security_platform.db` |
| `MAX_UPLOAD_SIZE_MB` | - | 上传文件大小上限，默认 50 |
| `LLM_BASE_URL` / `LLM_API_KEY` / `LLM_MODEL` | - | 威胁建模 AI 配置 |
| `FEISHU_APP_ID` / `FEISHU_APP_SECRET` | - | 飞书用户同步 |

## 故障排查

### 健康检查不通过

```bash
cd /opt/sdlc-platform
docker compose ps           # 看服务状态
docker compose logs sdlc    # 后端日志
docker compose logs nginx   # 反代日志
tail -100 nginx/logs/error.log
```

### 502 Bad Gateway

```bash
# 后端没起来
docker compose ps sdlc
docker compose logs sdlc --tail=200

# 网络问题
docker network inspect sdlc-platform_sdlc-net
```

### 升级后代码不生效（历史问题，已修复）

- **原因**：旧版 docker-compose 用 `sdlc_data:/app/backend` 整目录挂载，named volume 首次启动后"冻结"代码。
- **现状**：当前已改为只挂 `sdlc_db` / `sdlc_uploads` 子目录，`update.sh` 会正确更新。
- **如果从旧版本升级**：手动删旧卷 `docker volume rm sdlc-platform_sdlc_data`（**会丢数据，请先备份！**）

### 证书过期

```bash
openssl x509 -in nginx/ssl/fullchain.pem -noout -dates
certbot renew
cp /etc/letsencrypt/live/<domain>/fullchain.pem nginx/ssl/
cp /etc/letsencrypt/live/<domain>/privkey.pem nginx/ssl/
docker compose restart nginx
```

### 磁盘空间不足

```bash
docker system df                       # 占用总览
docker image prune -a                  # 清理无用镜像
docker volume prune                    # 清理无用卷（⚠️ 会丢数据）
find /backup/sdlc -mtime +30 -delete  # 清理旧备份
```

## 性能调优

```yaml
# docker-compose.yml 中调整后端 workers
services:
  sdlc:
    command: uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
```

数据库生产建议从 SQLite 切到 PostgreSQL：

```bash
# 1. .env 中改为
DATABASE_URL=postgresql://user:pass@postgres:5432/sdlc_platform

# 2. docker-compose.yml 中加 postgres 服务
# 3. 启动后端自动建表（Base.metadata.create_all）
```
