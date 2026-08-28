#!/usr/bin/env bash
# ============================================
# SDLC 安全平台 - 磁盘清理脚本
# 清理内容：
#   - threat/data/results  超过 7  天的分析结果 JSON
#   - threat/data/attachments 超过 30 天的附件
#   - backend/uploads      超过 90 天的上传文件
#   - logs/*.log           超过 30 天的旧日志
#   - threat/data/llm_cache.sqlite 中超过 30 天的缓存记录
#
# 用法：
#   ./cleanup.sh                        # 预览（dry-run）
#   CLEANUP_FORCE=1 ./cleanup.sh        # 实际清理
#   ./cleanup.sh --force                # 同上（兼容写法）
#
# 建议 crontab（每周日凌晨 3 点）：
#   0 3 * * 0 /opt/sdlc-platform/cleanup.sh >> /opt/sdlc-platform/logs/cleanup.log 2>&1
# ============================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${SCRIPT_DIR}"
LOGS_DIR="${PROJECT_DIR}/logs"
mkdir -p "${LOGS_DIR}"

# ---- 解析参数 ----
FORCE=0
for arg in "$@"; do
    case "${arg}" in
        --force|-f) FORCE=1 ;;
        --help|-h)
            sed -n '2,20p' "$0"
            exit 0
            ;;
        *) echo "未知参数: ${arg}（使用 --force 实际执行）"; exit 1 ;;
    esac
done
[[ "${CLEANUP_FORCE:-0}" == "1" ]] && FORCE=1

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[$(date +%Y-%m-%d\ %H:%M:%S)]${NC} $*"; }
warn() { echo -e "${YELLOW}[$(date +%Y-%m-%d\ %H:%M:%S)]${NC} $*"; }
err()  { echo -e "${RED}[$(date +%Y-%m-%d\ %H:%M:%S)]${NC} $*" >&2; }

# 通用清理函数：按修改时间清理目录下文件
cleanup_dir() {
    local dir="$1"
    local days="$2"
    local pattern="$3"
    local label="$4"

    if [[ ! -d "${dir}" ]]; then
        return
    fi

    local files
    files=$(find "${dir}" -type f -name "${pattern}" -mtime +${days} 2>/dev/null || true)
    if [[ -z "${files}" ]]; then
        return
    fi

    local count=0
    while IFS= read -r f; do
        if [[ "${FORCE}" -eq 1 ]]; then
            rm -f "$f" && count=$((count + 1))
        else
            count=$((count + 1))
        fi
    done <<< "${files}"

    if [[ ${count} -gt 0 ]]; then
        if [[ "${FORCE}" -eq 1 ]]; then
            log "  [${label}] 已清理 ${count} 个文件 (超过 ${days} 天)"
        else
            log "  [${label}] 将清理 ${count} 个文件 (超过 ${days} 天) [dry-run]"
        fi
    fi
}

# ---- 主体 ----
if [[ "${FORCE}" -eq 1 ]]; then
    log "开始磁盘清理（实际执行）"
else
    log "开始磁盘清理（dry-run 模式，未实际删除）"
    warn "确认无误后使用 --force 或 CLEANUP_FORCE=1 实际执行"
fi

# 1. 威胁建模结果（7 天）
cleanup_dir "${PROJECT_DIR}/backend/threat/data/results"     7  "*.json"      "results"

# 2. 威胁建模附件（30 天）
cleanup_dir "${PROJECT_DIR}/backend/threat/data/attachments" 30 "*"           "attachments"

# 3. 上传文件（90 天）
cleanup_dir "${PROJECT_DIR}/backend/uploads"                 90 "*"           "uploads"

# 4. 旧日志（30 天，保留当周日志）
cleanup_dir "${LOGS_DIR}"                                    30 "*.log.*"     "logs.old"
cleanup_dir "${LOGS_DIR}"                                    30 "*.log.gz"    "logs.gz"

# 5. LLM 缓存 SQLite 清理
CACHE_DB="${PROJECT_DIR}/backend/threat/data/llm_cache.sqlite"
if [[ -f "${CACHE_DB}" ]]; then
    log "  [llm_cache] $(du -h "${CACHE_DB}" | cut -f1)"
    if [[ "${FORCE}" -eq 1 ]]; then
        if command -v python3 >/dev/null 2>&1; then
            python3 "${PROJECT_DIR}/scripts/cleanup_cache.py" --days 30 \
                || warn "LLM 缓存清理失败，请手动检查"
        else
            warn "未找到 python3，跳过 LLM 缓存清理"
        fi
    else
        log "  [llm_cache] 将清理 SQLite 中超过 30 天的记录 [dry-run]"
    fi
fi

# 6. 显示清理后磁盘使用
log "清理后磁盘使用："
df -h "${PROJECT_DIR}" | awk 'NR==1 || NR==2'

if [[ "${FORCE}" -ne 1 ]]; then
    warn "本次为 dry-run 模式，文件未被实际删除"
    warn "实际清理请运行: $0 --force"
fi

log "清理完成 ✓"
