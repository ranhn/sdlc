#!/bin/bash
# ============================================
# VeSync SDLC 安全平台 - 一键初始化部署
# 用法：bash deploy.sh
# 适用：Ubuntu/Debian/CentOS 等 systemd 系列
# ============================================
set -e

APP_DIR="${1:-/opt/sdlc-platform}"
REPO_URL="${REPO_URL:-https://github.com/ranhn/sdlc.git}"
BRANCH="${BRANCH:-main}"
DOMAIN="${DOMAIN:-$(hostname -f)}"

# ---- 颜色 ----
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[$(date +%H:%M:%S)]${NC} $*"; }
warn() { echo -e "${YELLOW}[$(date +%H:%M:%S)] ⚠️  $*${NC}"; }

# ---- 1. 安装 docker ----
if ! command -v docker >/dev/null 2>&1; then
  log "未检测到 docker，正在安装..."
  curl -fsSL https://get.docker.com | bash
  systemctl enable --now docker
  log "docker 安装完成"
fi
if ! docker compose version >/dev/null 2>&1; then
  warn "未检测到 docker compose plugin"
  apt install -y docker-compose-plugin || yum install -y docker-compose-plugin
fi

# ---- 2. 拉取代码 ----
if [ ! -d "$APP_DIR" ]; then
  log "克隆仓库 $REPO_URL -> $APP_DIR"
  git clone -b "$BRANCH" "$REPO_URL" "$APP_DIR"
fi
cd "$APP_DIR"
log "拉取最新代码"
git fetch origin
git reset --hard "origin/$BRANCH"

# ---- 3. 生成 .env ----
if [ ! -f .env ]; then
  log "生成 .env（请检查 CORS_ORIGINS 与 DOMAIN）"
  SECRET=$(openssl rand -hex 32)
  cat > .env <<EOF
# === 安全 ===
SECRET_KEY=${SECRET}
ACCESS_TOKEN_EXPIRE_MINUTES=720

# === CORS 白名单（生产请改为 https://${DOMAIN}） ===
CORS_ORIGINS=http://${DOMAIN},https://${DOMAIN},http://localhost,https://localhost

# === 域名 ===
DOMAIN=${DOMAIN}

# === 数据库（默认 SQLite，落入 data/ 子目录由 sdlc_db 卷持久化） ===
DATABASE_URL=sqlite:///./data/security_platform.db

# === 上传限制 ===
MAX_UPLOAD_SIZE_MB=50

# === LLM / 飞书（可选） ===
# THREAT_API_TOKEN=
# LLM_BASE_URL=https://api.openai.com/v1
# LLM_API_KEY=
# LLM_MODEL=gpt-4o
# FEISHU_APP_ID=
# FEISHU_APP_SECRET=
EOF
  warn "已生成 .env，请立即检查 CORS_ORIGINS / DOMAIN / LLM_API_KEY 后再继续"
  read -p "继续启动？(yes/no) " ans
  [ "$ans" = "yes" ] || { echo "已退出，请修改 .env 后重跑 deploy.sh"; exit 0; }
fi

# ---- 4. 防火墙 ----
if command -v firewall-cmd >/dev/null 2>&1; then
  log "开放 80/443 端口"
  firewall-cmd --permanent --add-service=http
  firewall-cmd --permanent --add-service=https
  firewall-cmd --reload
fi
if command -v ufw >/dev/null 2>&1; then
  ufw allow 80/tcp
  ufw allow 443/tcp
fi

# ---- 5. 构建并启动 ----
log "构建镜像（首次约 3-5 分钟）"
docker compose build
log "启动服务"
docker compose up -d

# ---- 6. 健康检查 ----
log "等待健康检查..."
for i in {1..30}; do
  sleep 2
  if curl -sf http://localhost/api/health >/dev/null 2>&1; then
    log "✅ 部署完成"
    echo
    echo "访问地址: http://${DOMAIN}/"
    echo "默认账号: admin / admin123（⚠️  请立即修改）"
    echo "更新方式: cd ${APP_DIR} && ./update.sh"
    echo "备份方式: cd ${APP_DIR} && ./backup.sh"
    exit 0
  fi
done
warn "❌ 健康检查未通过，请执行: cd $APP_DIR && docker compose logs --tail=200"
exit 1
