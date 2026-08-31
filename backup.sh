#!/bin/bash
# ============================================
# VeSync SDLC 安全平台 - 数据备份
# 用法：./backup.sh [备份目录]
# 默认备份到 /backup/sdlc
# 自动保留最近 30 天
# ============================================
set -e

cd "$(dirname "$0")"
GREEN='\033[0;32m'
NC='\033[0m'
log() { echo -e "${GREEN}[$(date +%H:%M:%S)]${NC} $*"; }

BACKUP_DIR="${1:-/backup/sdlc}"
mkdir -p "$BACKUP_DIR"
STAMP="$(date +%Y%m%d-%H%M%S)"
FILE="$BACKUP_DIR/sdlc-${STAMP}.tar.gz"

log "备份数据库 + 上传文件 -> $FILE"
docker run --rm \
  -v sdlc-platform_sdlc_db:/data:ro \
  -v sdlc-platform_sdlc_uploads:/uploads:ro \
  -v "$BACKUP_DIR":/backup \
  alpine:latest \
  tar czf /backup/$(basename "$FILE") data uploads

# 清理 30 天前的备份
DELETED=$(find "$BACKUP_DIR" -name "sdlc-*.tar.gz" -mtime +30 -delete -print | wc -l)
log "✅ 备份完成: $FILE"
[ "$DELETED" -gt 0 ] && log "已清理 $DELETED 个 30 天前的旧备份"
