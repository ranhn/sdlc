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
./backup.sh        # 生产建议先备份（出问题可 restore 回去）
./update.sh
```

`update.sh` 会自动：
1. `git fetch` + `git reset --hard <远端分支>` 对齐代码（**会覆盖仓库内的本地改动**，
   所以别在服务器上直接改仓库文件；`.env` / `backups/` / `data/` 不受影响）
2. `docker compose up -d --build` 重新构建并启动
3. 健康检查通过即完成

> 💡 数据库结构和数据**不会被破坏**（代码在 image 里、数据在 volume 里）。
> ⏱ 重建容器会有 **1~3 分钟中断**，生产建议低峰期执行。

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

# 4. 让 Nginx 用上证书（首次要 --force-recreate：新加的卷挂载 restart 不生效）
docker compose up -d --force-recreate nginx
```

### 方式 B：内网自签证书

```bash
mkdir -p nginx/ssl
openssl req -x509 -nodes -days 825 \
  -newkey rsa:2048 \
  -keyout nginx/ssl/privkey.pem \
  -out nginx/ssl/fullchain.pem \
  -subj "/C=CN/O=Company/CN=sdlc.yourcompany.com" \
  -addext "subjectAltName=DNS:sdlc.yourcompany.com"   # 必须带 SAN，否则浏览器报"域名不匹配"
docker compose up -d --force-recreate nginx
```
> 自签只解决"加密"，浏览器仍会提示不受信任（同事首次访问要点「继续访问」）；
> 想让内部同事零告警：把 `fullchain.pem` 作为受信任根证书装到各机器，或让 IT 用域策略下发。

### 方式 C：内网域名 + 公司内部 CA 证书（内网访问推荐）

内网域名（如 `sdlc.yourcompany.com` 只在内网解析）**申请不到公网 CA 证书**（Let's Encrypt
需要公网可验证）；正规做法是让 IT 用**公司内部 CA** 签发一张该域名的服务器证书：

```bash
# 向 IT/运维申请：CN/SAN = sdlc.yourcompany.com，取回 fullchain.pem + privkey.pem
mkdir -p /opt/sdlc-platform/nginx/ssl
# 把两个 pem 放进去，然后：
cd /opt/sdlc-platform
vim docker-compose.yml     # 取消 nginx 服务下 `- ./nginx/ssl:/etc/nginx/ssl:ro` 的注释
docker compose up -d --force-recreate nginx
```
同事机器只要信任公司根 CA（域内一般已下发），访问就**完全没有告警**。

> ⚠️ 两个容易踩的点：
> ① 端口要对内网可达 —— 本机确认 `ss -lntp | grep :443` 有 docker-proxy 监听；
>    若走运维侧的反向代理/内网防火墙，需请运维放行到本机 443。
> ② 改了 `docker-compose.yml` 的挂载必须用 `--force-recreate`（`restart` 不会重新套用卷配置，
>    现象是"证书放好了页面还是旧证书自签告警"）。

> 🔀 **80 会强制跳 443**（Nginx 默认行为），只留三条走明文：
> `/.well-known/acme-challenge/`（证书续期）、`/nginx-health`（容器健康检查）、
> `/api/health`（`update.sh` 与外部监控）—— 这三条一跳转就"看起来健康"但实际没验到后端。
> 其余路径（含 SPA、`/api/*`、`/threat/*`）一律 `301 → https://<你访问的域名><原路径>`。
>
> ⚠️ 如果贵司运维的代理是「**TLS 终止 + 回源到本机 80**」（而不是 TLS 透传到 443），
> 这个跳转会形成"浏览器 https → 代理 → 本机 80 → 301 → 循环"。这种情况请告诉开发，
> 改用 `X-Forwarded-Proto` 判据（代理已终结 TLS 时不再跳）。**建议先与运维确认代理方式。**

> 💡 暂不建议加 HSTS：证书还是自签时，HSTS 会让浏览器**无法再点「继续访问」**（只能清站点数据），
> 等真证书装好、验证一段时间后再考虑。

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
| `FEISHU_NOTIFY` | - | 飞书指派通知开关，默认 `1`；设 `0` 关闭。需开通 `im:message:send_as_bot` 权限 + 启用「机器人」应用能力并发布版本 |
| `PUBLIC_BASE_URL` | - | 飞书通知深链/按钮用的**对外地址**（如 `https://sdlc.vesync.cn`）。不配则取操作人访问地址，可能内网不可达。改完必须 `docker compose up -d --force-recreate sdlc`（env_file 在容器创建时固化，`restart` 不生效） |
| `FEISHU_DEFAULT_PASSWORD` | - | 飞书同步账号的初始密码（默认 `Aa123456`）。仅作用于从没登录过的账号，指派通知会随卡片发给本人，首登强制改密 |
| `FEISHU_SYNC_WEEKLY` | - | 飞书通讯录**每周定时同步**开关，默认开。与手动同步共用同一份实现和同一把锁；"本周已同步过"（含手动）不再重复跑；漏跑会自动补 |
| `FEISHU_SYNC_WEEKDAY` / `FEISHU_SYNC_HOUR` | - | 定时同步的星期几（ISO 1=周一）与小时数（**北京时间**），默认 `1` / `8` = 每周一 08:00 |
| `LOG_LEVEL` | - | 应用日志级别，默认 `INFO`。`INFO` 会记录「飞书通知已发送/失败」「飞书同步: …停用 N」等排查线索；`DEBUG` 细查 / `WARNING` 降噪 |
| `COMPLIANCE_REGIONS` | - | 威胁建模报告「合规影响面」启用哪些法规地区，默认 `US,EU`；需要境内条目写成 `US,EU,CN` |

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
