#!/bin/bash
# ============================================
# SDLC 平台 - 双仓库推送脚本 (Linux/macOS)
# 同时推送到 GitHub (HTTPS + PAT) 和 GitLab (SSH)
#
# 用法：
#   ./scripts/push-all.sh                    推送当前分支
#   ./scripts/push-all.sh feature-xxx        推送当前分支到 feature-xxx
#   ./scripts/push-all.sh HEAD~3..HEAD       推送指定范围
# ============================================

set -e

if [ -z "$GITHUB_TOKEN" ]; then
    echo "[错误] 未设置 GITHUB_TOKEN 环境变量"
    echo "请运行: export GITHUB_TOKEN=ghp_xxxxx"
    exit 1
fi

# 切到仓库根目录
cd "$(dirname "$0")/.."

RANGE="${*:-HEAD}"

echo "=== [1/2] 推送到 GitHub ==="
GIT_TERMINAL_PROMPT=0 git push "https://ranhn:${GITHUB_TOKEN}@github.com/ranhn/sdlc.git" $RANGE

echo
echo "=== [2/2] 推送到 GitLab ==="
git push gitlab $RANGE

echo
echo "=== 完成 ==="
