#!/bin/bash
# ============================================
# VeSync SDLC 安全平台 - 一键更新
# 用法：在项目根目录执行 ./update.sh
# 流程：git pull -> docker compose up -d --build -> 健康检查
# ============================================
set -e

cd "$(dirname "$0")"
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
log() { echo -e "${GREEN}[$(date +%H:%M:%S)]${NC} $*"; }
warn() { echo -e "${YELLOW}[$(date +%H:%M:%S)] ⚠️  $*${NC}"; }

# ---- 1. 拉取最新代码 ----
log "拉取远端最新代码..."
git fetch origin

# 提示新提交
NEW=$(git log --oneline HEAD..origin/main 2>/dev/null | wc -l)
if [ "$NEW" -gt 0 ]; then
  log "发现 $NEW 个新提交："
  git log --oneline HEAD..origin/main | sed 's/^/    /'
else
  log "无新提交（HEAD 已对齐 origin/main）"
fi

# 强制对齐到远端（保留 .env / backups / data 等运行时文件）
git reset --hard origin/main

# ---- 2. 重新构建并启动 ----
log "重新构建并启动服务..."
docker compose up -d --build

# ---- 3. 健康检查 ----
log "等待健康检查..."
for i in {1..30}; do
  sleep 2
  if curl -sf http://localhost/api/health >/dev/null 2>&1; then
    log "✅ 更新完成"
    echo "    版本: $(git log -1 --oneline)"
    echo "    时间: $(date '+%F %T')"
    exit 0
  fi
done
warn "❌ 健康检查未通过"
warn "请执行: docker compose logs --tail=200"
exit 1
