#!/bin/bash
# ============================================
# VeSync SDLC 安全平台 - 数据备份
# 用法：./backup.sh [备份目录]
# 默认备份到 ./backups/
# 自动保留最近 30 天
#
# 关键改进：
#  1. SQLite 在线热备（python sqlite3.backup API）→ 杜绝半写状态
#  2. 默认路径改 ./backups/ → 跟随项目目录，不丢到主机根目录
#  3. alpine 固定 3.18 → 避免 latest 漂移
#
# 包结构（与 restore.sh 兼容）：
#   sdlc-XXX.tar.gz
#   ├── data/                 # → 还原到 sdlc_db volume
#   │   ├── security_platform.db   (热备一致快照)
#   │   ├── llm_cache.sqlite
#   │   └── attachments/
#   └── uploads/              # → 还原到 sdlc_uploads volume
# ============================================
set -euo pipefail

cd "$(dirname "$0")"
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
log() { echo -e "${GREEN}[$(date +%H:%M:%S)]${NC} $*"; }
warn() { echo -e "${YELLOW}[$(date +%H:%M:%S)]${NC} $*"; }

# 默认备份目录：项目内的 backups/（跟随项目，避免丢到主机根目录）
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BACKUP_DIR="${1:-$SCRIPT_DIR/backups}"
mkdir -p "$BACKUP_DIR"
STAMP="$(date +%Y%m%d-%H%M%S)"
HOT_BACKUP_BN=".hot_backup_${STAMP}.db"
DB_TAR="$BACKUP_DIR/sdlc_db-${STAMP}.tar.gz"
UP_TAR="$BACKUP_DIR/sdlc_uploads-${STAMP}.tar.gz"
FINAL="$BACKUP_DIR/sdlc-${STAMP}.tar.gz"

log "备份目录: $BACKUP_DIR"
log "本次时间戳: $STAMP"

# ==================================================
# 步骤 1/4：SQLite 在线热备
# 必须在 sdlc 容器内用 Python sqlite3.backup() 拿一致快照。
# 直接 tar 半写状态会导致 restore 后数据库打不开（高风险）。
# ==================================================
log "[1/4] SQLite 在线热备（sdlc 容器内）"
if ! docker compose exec -T sdlc python -c "
import sqlite3, os
src = sqlite3.connect('/app/backend/data/security_platform.db')
dst = sqlite3.connect('/app/backend/data/${HOT_BACKUP_BN}')
with dst:
    src.backup(dst)
src.close()
dst.close()
print('  热备完成, size =', os.path.getsize('/app/backend/data/${HOT_BACKUP_BN}'), 'bytes')
"; then
    warn "❌ SQLite 热备失败，中止备份"
    exit 1
fi

# ==================================================
# 步骤 2/4：打包 sdlc_db volume
# 用热备 .db 替代原 .db（保证一致性）
# 同时打包 llm_cache.sqlite 和 attachments/
# ==================================================
log "[2/4] 打包 sdlc_db volume (主库 + LLM缓存 + 威胁建模附件)"
docker run --rm \
    -v sdlc-platform_sdlc_db:/data:ro \
    -v "$BACKUP_DIR":/backup \
    alpine:3.18 sh -c "
        set -e
        WORK=/tmp/stage
        rm -rf \$WORK && mkdir -p \$WORK/data
        cp /data/${HOT_BACKUP_BN} \$WORK/data/security_platform.db
        [ -f /data/llm_cache.sqlite ] && cp /data/llm_cache.sqlite \$WORK/data/ || echo '  (llm_cache 跳过)'
        [ -d /data/attachments ] && cp -r /data/attachments \$WORK/data/ || echo '  (attachments 跳过)'
        tar czf /backup/$(basename "$DB_TAR") -C \$WORK data
        echo '  sdlc_db packaged'
    "

# ==================================================
# 步骤 3/4：打包 sdlc_uploads volume（培训资料）
# ==================================================
log "[3/4] 打包 sdlc_uploads volume (培训资料)"
docker run --rm \
    -v sdlc-platform_sdlc_uploads:/uploads:ro \
    -v "$BACKUP_DIR":/backup \
    alpine:3.18 \
    tar czf /backup/$(basename "$UP_TAR") -C /uploads .

# ==================================================
# 步骤 4/4：合并成单个 sdlc-XXX.tar.gz（与 restore.sh 兼容）
# ==================================================
log "[4/4] 合并成总包"
docker run --rm \
    -v "$BACKUP_DIR":/backup:ro \
    alpine:3.18 sh -c "
        set -e
        WORK=/tmp/final
        rm -rf \$WORK && mkdir -p \$WORK
        tar xzf /backup/$(basename "$DB_TAR") -C \$WORK
        mkdir -p \$WORK/uploads
        tar xzf /backup/$(basename "$UP_TAR") -C \$WORK/uploads
        tar czf /backup/$(basename "$FINAL") -C \$WORK .
    "
rm -f "$DB_TAR" "$UP_TAR"

# 清理 sdlc 容器内残留的临时热备文件
docker compose exec -T sdlc rm -f "/app/backend/data/${HOT_BACKUP_BN}" || true

# 清理 30 天前的旧备份
DELETED=$(find "$BACKUP_DIR" -name "sdlc-*.tar.gz" -mtime +30 -delete -print | wc -l)
[ "$DELETED" -gt 0 ] && log "已清理 $DELETED 个 30 天前的旧备份"

log "✅ 备份完成: $FINAL"
ls -lh "$FINAL"
log "包内容预览（前 20 条）:"
tar -tzf "$FINAL" 2>/dev/null | head -20
echo "  ... (共 $(tar -tzf "$FINAL" 2>/dev/null | wc -l) 个条目)"
