#!/usr/bin/env bash
# ============================================
# SDLC 安全平台 - 自动备份脚本
# 备份内容：SQLite 数据库 + uploads 目录
# 保留策略：默认保留 30 天，可通过 KEEP_DAYS 调整
# 用法：
#   ./backup.sh                          # 默认备份到 ./backups/
#   BACKUP_DIR=/data/backup ./backup.sh  # 自定义备份目录
#   KEEP_DAYS=7 ./backup.sh              # 只保留 7 天
# 建议：crontab -e 添加 0 2 * * * /opt/sdlc-platform/backup.sh
# ============================================
set -euo pipefail

# ---- 配置 ----
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="${BACKUP_DIR:-${SCRIPT_DIR}/backups}"
KEEP_DAYS="${KEEP_DAYS:-30}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
DATE_LABEL="$(date +%Y-%m-%d_%H:%M:%S)"

# 数据源路径（容器内或宿主机）
# 容器内：/app/backend/security_platform.db 和 /app/backend/uploads
# 宿主机：./backend/security_platform.db 和 ./backend/uploads
DB_PATH="${DB_PATH:-${SCRIPT_DIR}/backend/security_platform.db}"
UPLOADS_PATH="${UPLOADS_PATH:-${SCRIPT_DIR}/backend/uploads}"

# 备份文件名
BACKUP_FILE="${BACKUP_DIR}/sdlc_backup_${TIMESTAMP}.tar.gz"

# ---- 颜色输出 ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[$(date +%H:%M:%S)]${NC} $*"; }
warn() { echo -e "${YELLOW}[$(date +%H:%M:%S)]${NC} $*"; }
err()  { echo -e "${RED}[$(date +%H:%M:%S)]${NC} $*" >&2; }

# ---- 前置检查 ----
mkdir -p "${BACKUP_DIR}"

if [[ ! -f "${DB_PATH}" ]]; then
    err "数据库文件不存在：${DB_PATH}"
    err "请通过 DB_PATH 环境变量指定正确路径"
    exit 1
fi

# ---- 备份 ----
log "开始备份：${DATE_LABEL}"
log "  数据库：${DB_PATH}"
log "  附件：${UPLOADS_PATH}"
log "  输出：${BACKUP_FILE}"

# 使用 tar 打包（数据库 + 附件）
# 注意：tar 不会锁库，备份期间建议低峰期；或先 sqlite3 .backup 命令
TAR_PATHS=("${DB_PATH}")
if [[ -d "${UPLOADS_PATH}" ]]; then
    TAR_PATHS+=("${UPLOADS_PATH}")
fi

# 切换到父目录，让压缩包内路径相对化
PARENT_DIR="$(dirname "${DB_PATH}")"
tar -czf "${BACKUP_FILE}" \
    -C "${PARENT_DIR}" \
    --exclude='*.pyc' \
    --exclude='__pycache__' \
    --exclude='.git' \
    $(basename "${DB_PATH}") \
    $([[ -d "${UPLOADS_PATH}" ]] && echo "$(basename "${UPLOADS_PATH}")") \
    2>/dev/null || {
        # 兼容写法：上面 $(...) 在某些 shell 下可能为空导致 tar 报错
        tar -czf "${BACKUP_FILE}" \
            -C "${PARENT_DIR}" \
            --exclude='*.pyc' \
            --exclude='__pycache__' \
            "$(basename "${DB_PATH}")"
    }

if [[ ! -s "${BACKUP_FILE}" ]]; then
    err "备份文件生成失败或为空"
    exit 1
fi

BACKUP_SIZE="$(du -h "${BACKUP_FILE}" | cut -f1)"
log "备份完成：${BACKUP_FILE} (${BACKUP_SIZE})"

# ---- 清理旧备份 ----
DELETED=$(find "${BACKUP_DIR}" -name "sdlc_backup_*.tar.gz" -mtime +${KEEP_DAYS} -delete -print | wc -l)
if [[ "${DELETED}" -gt 0 ]]; then
    log "已清理 ${DELETED} 个超过 ${KEEP_DAYS} 天的旧备份"
fi

# ---- 统计 ----
TOTAL=$(find "${BACKUP_DIR}" -name "sdlc_backup_*.tar.gz" | wc -l)
TOTAL_SIZE=$(du -sh "${BACKUP_DIR}" | cut -f1)
log "当前备份目录共 ${TOTAL} 个文件，占用 ${TOTAL_SIZE}"

# ---- 可选：上传到云存储 ----
# 取消注释并填入配置即可启用
# if [[ -n "${OSS_BUCKET:-}" ]]; then
#     log "上传到 OSS..."
#     ossutil cp "${BACKUP_FILE}" "oss://${OSS_BUCKET}/sdlc-backups/" || warn "OSS 上传失败"
# fi

log "全部完成 ✓"
