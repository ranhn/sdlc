#!/bin/bash
# ============================================
# VeSync SDLC 安全平台 - 数据恢复
# 用法：./restore.sh <backup.tar.gz>
#
# 预期包结构（与 backup.sh 配套）：
#   sdlc-XXX.tar.gz
#   ├── data/        → 还原到 sdlc_db volume
#   └── uploads/     → 还原到 sdlc_uploads volume
# ============================================
set -euo pipefail

cd "$(dirname "$0")"
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'
warn() { echo -e "${YELLOW}$*${NC}"; }
log() { echo -e "${GREEN}$*${NC}"; }

BACKUP_FILE="${1:?用法: $0 <backup.tar.gz>}"
[ -f "$BACKUP_FILE" ] || { echo "❌ 文件不存在: $BACKUP_FILE"; exit 1; }

# 验证包结构
log "验证备份包结构..."
if ! tar -tzf "$BACKUP_FILE" 2>/dev/null | head -20 | grep -qE '(^|/)data/?($|-)|(^|/)uploads/?($|-)'; then
    echo "❌ 备份包结构异常：包内应包含 data/ 或 uploads/ 目录"
    echo "实际顶层:"
    tar -tzf "$BACKUP_FILE" 2>/dev/null | head -5
    exit 1
fi

warn "⚠️  即将从 $BACKUP_FILE 恢复数据"
warn "    现有数据会被覆盖！"
read -p "确认恢复？(输入 yes 继续) " ans
[ "$ans" = "yes" ] || { echo "已取消"; exit 0; }

# 停后端（保留 nginx）
log "停止后端服务"
docker compose stop sdlc

# 清空数据卷
log "清空现有数据卷"
docker run --rm \
    -v sdlc-platform_sdlc_db:/data \
    -v sdlc-platform_sdlc_uploads:/uploads \
    alpine:3.18 sh -c "rm -rf /data/* /uploads/*"

# 解压备份（包顶层 data/ + uploads/ 对应 mount 点 /data + /uploads）
log "解压备份到数据卷"
docker run --rm \
    -v sdlc-platform_sdlc_db:/data \
    -v sdlc-platform_sdlc_uploads:/uploads \
    -v "$(dirname "$BACKUP_FILE")":/backup:ro \
    alpine:3.18 sh -c "tar xzf /backup/$(basename "$BACKUP_FILE")"

# 重启
log "重启服务"
docker compose up -d

# 健康检查
log "等待健康检查..."
for i in $(seq 1 20); do
    sleep 2
    if curl -sf http://localhost/api/health >/dev/null 2>&1; then
        log "✅ 恢复完成"
        exit 0
    fi
done
warn "❌ 健康检查未通过，请 docker compose logs --tail=200"
exit 1
