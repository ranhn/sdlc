# SDLC 安全平台 - 备份策略

## 概述

| 脚本 | 用途 |
|---|---|
| `backup.sh` | 自动备份数据库和附件 |
| `restore.sh` | 从备份恢复数据 |

## 快速开始

### 手动备份

```bash
# 默认备份到 ./backups/，保留 30 天
./backup.sh

# 自定义备份目录
BACKUP_DIR=/data/backup ./backup.sh

# 只保留 7 天
KEEP_DAYS=7 ./backup.sh
```

### 手动恢复

```bash
# 列出所有备份
./restore.sh

# 恢复指定备份
./restore.sh sdlc_backup_20260828_020000.tar.gz

# 恢复最新备份
./restore.sh latest
```

## 定时备份（推荐）

### 方式 1：crontab（宿主机）

```bash
# 编辑 crontab
crontab -e

# 每天凌晨 2 点备份，保留 30 天
0 2 * * * /opt/sdlc-platform/backup.sh >> /var/log/sdlc-backup.log 2>&1
```

### 方式 2：Docker 内置 cron（推荐）

在 `docker-compose.yml` 中加一个 cron 容器：

```yaml
  sdlc-backup:
    image: alpine:3.19
    container_name: sdlc-backup
    restart: unless-stopped
    volumes:
      - ./:/app
      - ./backups:/app/backups
    entrypoint: /bin/sh
    command:
      - -c
      - |
        echo "0 2 * * * /app/backup.sh >> /var/log/sdlc-backup.log 2>&1" > /etc/crontabs/root
        crond -f -L /var/log/sdlc-backup.log
```

## 数据源路径

| 部署方式 | 数据库路径 | 附件路径 |
|---|---|---|
| **宿主机直接跑** | `./backend/security_platform.db` | `./backend/uploads/` |
| **Docker 容器内** | `/app/backend/security_platform.db` | `/app/backend/uploads/` |

可通过环境变量覆盖：
```bash
DB_PATH=/custom/path/db.sqlite ./backup.sh
UPLOADS_PATH=/custom/uploads ./backup.sh
```

## 异地备份（可选）

### 阿里云 OSS

编辑 `backup.sh` 末尾的 OSS 上传段：
```bash
if [[ -n "$${OSS_BUCKET:-}" ]]; then
    ossutil cp "$${BACKUP_FILE}" "oss://$${OSS_BUCKET}/sdlc-backups/"
fi
```

### 腾讯云 COS

```bash
coscli cp "${BACKUP_FILE}" "cos://${COS_BUCKET}-${APP_ID}/sdlc-backups/"
```

## 监控建议

备份失败的告警（可选）：

```bash
# backup.sh 末尾加：
if [[ $$? -ne 0 ]]; then
    curl -X POST "https://api.dingtalk.com/robot/send?access_token=XXX" \
        -H "Content-Type: application/json" \
        -d '{"msgtype":"text","text":{"content":"SDLC 备份失败！"}}'
fi
```

## 容量估算

| 数据量 | 单次备份大小 | 30 天累计 |
|---|---|---|
| 100 用户 + 1000 漏洞 | ~50 MB | ~1.5 GB |
| 500 用户 + 5000 漏洞 | ~200 MB | ~6 GB |
| 1000 用户 + 10000 漏洞 | ~500 MB | ~15 GB |

## 测试恢复

**重要**：每月至少演练一次恢复流程，确保备份可用。

```bash
# 1. 找个测试环境
# 2. 把备份文件拷过去
scp sdlc_backup_*.tar.gz test-server:/tmp/

# 3. 恢复
./restore.sh /tmp/sdlc_backup_*.tar.gz

# 4. 验证数据完整性
sqlite3 security_platform.db "SELECT COUNT(*) FROM sys_user;"
ls uploads/ | wc -l
```
