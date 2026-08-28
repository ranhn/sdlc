#!/usr/bin/env bash
# SDLC 安全平台 - 恢复脚本
# 用法：
#   ./restore.sh                                    # 列出所有可用备份
#   ./restore.sh sdlc_backup_20260828_020000.tar.gz # 恢复指定备份
#   ./restore.sh latest                             # 恢复最新备份
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKUP_DIR="${BACKUP_DIR:-${SCRIPT_DIR}/backups}"
DB_PATH="${DB_PATH:-${SCRIPT_DIR}/backend/security_platform.db}"
UPLOADS_PATH="${UPLOADS_PATH:-${SCRIPT_DIR}/backend/uploads}"
PARENT_DIR="$(dirname "${DB_PATH}")"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[$(date +%H:%M:%S)]${NC} $*"; }
warn() { echo -e "${YELLOW}[$(date +%H:%M:%S)]${NC} $*"; }
err()  { echo -e "${RED}[$(date +%H:%M:%S)]${NC} $*" >&2; }

# 列出备份
list_backups() {
    echo "可用备份："
    ls -lh "${BACKUP_DIR}"/sdlc_backup_*.tar.gz 2>/dev/null || { err "无备份文件"; exit 1; }
}

# 选择备份
SELECTED="${1:-}"
if [[ -z "${SELECTED}" ]]; then
    list_backups
    echo
    read -rp "请输入备份文件名（或 Ctrl+C 退出）: " SELECTED
fi

if [[ "${SELECTED}" == "latest" ]]; then
    SELECTED="$(ls -t "${BACKUP_DIR}"/sdlc_backup_*.tar.gz 2>/dev/null | head -1)"
    [[ -z "${SELECTED}" ]] && { err "无备份文件"; exit 1; }
    log "选择最新备份：$(basename "${SELECTED}")"
fi

if [[ ! -f "${SELECTED}" ]]; then
    SELECTED="${BACKUP_DIR}/${SELECTED}"
fi

if [[ ! -f "${SELECTED}" ]]; then
    err "备份文件不存在：${SELECTED}"
    exit 1
fi

# 确认
warn "即将从 $(basename "${SELECTED}") 恢复数据"
warn "  数据库：${DB_PATH}"
warn "  附件：${UPLOADS_PATH}"
read -rp "确认恢复？现有数据将被覆盖！(yes/no): " CONFIRM
[[ "${CONFIRM}" == "yes" ]] || { log "已取消"; exit 0; }

# 备份当前数据（防止恢复失败）
if [[ -f "${DB_PATH}" ]]; then
    cp "${DB_PATH}" "${DB_PATH}.pre-restore.$(date +%Y%m%d_%H%M%S)"
    warn "已备份当前数据库到 ${DB_PATH}.pre-restore.*"
fi

# 解压
log "解压备份..."
tar -xzf "${SELECTED}" -C "${PARENT_DIR}"
log "恢复完成 ✓"
log "请重启服务：docker compose restart sdlc"
