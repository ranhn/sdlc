#!/usr/bin/env bash
# ============================================
# SDLC 安全平台 - 健康检查 + 邮件告警
# 检查项：HTTP / 数据库 / 磁盘 / 进程
# 失败时调用 scripts/alert.py 发送邮件
#
# 用法：
#   ./healthcheck.sh                          # 手动执行
#   crontab -e 添加：
#     */5 * * * * /opt/sdlc-platform/healthcheck.sh >> /opt/sdlc-platform/logs/healthcheck.log 2>&1
#
# 邮件配置（首次部署必须设置环境变量，推荐写入 /opt/sdlc-platform/.env.monitor）：
#   SMTP_HOST=mail.vesync.com
#   SMTP_PORT=25
#   SMTP_FROM=sdlc-platform@vesync.com
# ============================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${SCRIPT_DIR}"

# ---- 加载监控专用环境变量（如有）----
# shellcheck disable=SC1091
[[ -f "${PROJECT_DIR}/.env.monitor" ]] && source "${PROJECT_DIR}/.env.monitor"

# ---- 配置 ----
HEALTH_URL="${HEALTH_URL:-http://localhost:8000/api/health}"
DB_PATH="${DB_PATH:-${PROJECT_DIR}/backend/security_platform.db}"
ALERT_EMAIL="${ALERT_EMAIL:-ning.ran@vesync.com}"
ALERT_LOG="${PROJECT_DIR}/logs/healthcheck_alert.log"
ALERT_PY="${PROJECT_DIR}/scripts/alert.py"
TMP_RESULT="$(mktemp /tmp/sdlc_healthcheck.XXXXXX.txt)"
trap 'rm -f "${TMP_RESULT}"' EXIT

mkdir -p "$(dirname "${ALERT_LOG}")"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[$(date +%Y-%m-%d\ %H:%M:%S)]${NC} $*"; }
warn() { echo -e "${YELLOW}[$(date +%Y-%m-%d\ %H:%M:%S)]${NC} $*"; }
err()  { echo -e "${RED}[$(date +%Y-%m-%d\ %H:%M:%S)]${NC} $*" >&2; }

ISSUES=()

# 1. HTTP 健康检查
log "检查 HTTP: ${HEALTH_URL}"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "${HEALTH_URL}" 2>/dev/null || echo "000")
if [[ "${HTTP_CODE}" != "200" ]]; then
    ISSUES+=("HTTP 健康检查失败 (HTTP ${HTTP_CODE}, URL: ${HEALTH_URL})")
fi

# 2. 数据库文件存在且非空
log "检查数据库: ${DB_PATH}"
if [[ ! -s "${DB_PATH}" ]]; then
    ISSUES+=("数据库文件不存在或为空: ${DB_PATH}")
fi

# 3. 磁盘使用率 >= 90%
log "检查磁盘使用率"
DISK_USAGE=$(df -P "${PROJECT_DIR}" 2>/dev/null | awk 'NR==2 {gsub(/%/,"",$5); print $5}')
if [[ -n "${DISK_USAGE}" ]] && [[ "${DISK_USAGE}" =~ ^[0-9]+$ ]] && [[ "${DISK_USAGE}" -ge 90 ]]; then
    ISSUES+=("磁盘使用率过高: ${DISK_USAGE}%")
fi

# 4. 服务进程检查（Docker 或直接进程）
log "检查服务进程"
SERVICE_OK=0
if command -v docker >/dev/null 2>&1; then
    if docker ps --filter "name=sdlc-api" --filter "status=running" --format "{{.Names}}" 2>/dev/null | grep -q sdlc-api; then
        SERVICE_OK=1
    fi
fi
if [[ "${SERVICE_OK}" -eq 0 ]]; then
    # 退回到进程检查（非容器或容器命令不可用）
    if pgrep -af "uvicorn.*app.app_entry:app" >/dev/null 2>&1 \
       || pgrep -af "uvicorn.*app.main:app" >/dev/null 2>&1; then
        SERVICE_OK=1
    fi
fi
if [[ "${SERVICE_OK}" -eq 0 ]]; then
    ISSUES+=("SDLC 服务进程未运行")
fi

# ---- 结论 ----
if [[ ${#ISSUES[@]} -eq 0 ]]; then
    log "✓ 健康检查通过"
    exit 0
fi

# ---- 失败处理 ----
err "✗ 健康检查失败（${#ISSUES[@]} 项）"
for issue in "${ISSUES[@]}"; do
    err "  - ${issue}"
done

# 写告警日志
echo "[$(date +%Y-%m-%d\ %H:%M:%S)] FAIL (${#ISSUES[@]}): ${ISSUES[*]}" >> "${ALERT_LOG}"

# 写告警内容文件
cat > "${TMP_RESULT}" <<EOF
告警时间：$(date +%Y-%m-%d\ %H:%M:%S)
服务器：$(hostname)
项目目录：${PROJECT_DIR}
问题列表：
$(printf '  - %s\n' "${ISSUES[@]}")

排查建议：
  1. 查看服务状态：docker compose ps
  2. 查看日志：tail -100 ${PROJECT_DIR}/server_err.log
  3. 重启服务：cd ${PROJECT_DIR} && docker compose restart sdlc
EOF

# 发送邮件告警
if [[ -f "${ALERT_PY}" ]] && command -v python3 >/dev/null 2>&1; then
    log "发送告警邮件至 ${ALERT_EMAIL}"
    # 只导出已显式设置的 SMTP 变量，未设置的让 alert.py 用内置默认值
    SMTP_ENV=()
    [[ -n "${SMTP_HOST:-}"     ]] && SMTP_ENV+=(SMTP_HOST="${SMTP_HOST}")
    [[ -n "${SMTP_PORT:-}"     ]] && SMTP_ENV+=(SMTP_PORT="${SMTP_PORT}")
    [[ -n "${SMTP_FROM:-}"     ]] && SMTP_ENV+=(SMTP_FROM="${SMTP_FROM}")
    [[ -n "${SMTP_USER:-}"     ]] && SMTP_ENV+=(SMTP_USER="${SMTP_USER}")
    [[ -n "${SMTP_PASSWORD:-}" ]] && SMTP_ENV+=(SMTP_PASSWORD="${SMTP_PASSWORD}")
    ALERT_LOG="${ALERT_LOG}" \
        env "${SMTP_ENV[@]}" python3 "${ALERT_PY}" "${TMP_RESULT}" "${ALERT_EMAIL}" \
        || warn "邮件发送过程异常（已写入告警日志 ${ALERT_LOG}）"
else
    warn "未找到 ${ALERT_PY} 或 python3，跳过邮件告警"
fi

exit 1
