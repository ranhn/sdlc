"""统一 SDLC 安全平台入口。

整合：
- SDLC 业务后端（app.app_entry.app）：工作台/漏洞/基线/扫描/培训/人员等
- AI 威胁建模后端（threat.app.api.router.app）：挂载到 /threat 前缀
- Vue3 前端构建产物（frontend/dist）：托管为 SPA 静态站点

生产部署：只需运行本文件，即可对外提供单端口完整的前后端服务。
"""
# 网络时钟：必须最先 import（启动时立即 NTP 校准）。
# 业务侧用 from app.utils import network_clock as nc
# 调 nc.now() / nc.utcnow() / nc.epoch() 即得真实网络时间。
from app.utils import network_clock  # noqa: F401

import os

from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.app_entry import app as sdlc_app  # 业务子应用（含建表、播种、业务 router）
from threat.app.api.router import app as threat_app

# 复用 SDLC 宿主应用
from app.utils import network_clock as nc
app = sdlc_app

# 移除宿主 app 上已挂载的旧原生前端静态目录（避免与 Vue3 前端冲突）
STATIC_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "app", "static",
)
app.router.routes[:] = [r for r in app.router.routes if getattr(r, "name", "") != "static"]

# ---- 托管 Vue3 前端构建产物（SPA，需 history 回退）----
FRONTEND_DIST = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "static_new",
)

# /threat-modeling 是前端路由，必须精确返回 SPA index.html，
# 否则会被下面的 /threat 子应用前缀匹配拦截导致 404。
# 该路由需在 app.mount("/threat", ...) 之前注册。
@app.get("/threat-modeling", include_in_schema=False)
async def threat_modeling_page():
    index_path = os.path.join(FRONTEND_DIST, "index.html")
    if os.path.isfile(index_path):
        return FileResponse(index_path)
    return {
        "message": "前端尚未构建。请先执行：cd frontend && npm install && npm run build",
    }

# ---- 挂载 AI 威胁建模子应用（前端通过 /threat/api/* 访问）----
app.mount("/threat", threat_app)


class SPAStaticFiles(StaticFiles):
    """支持 Vue Router history 模式回退到 index.html。"""

    async def get_response(self, path: str, scope):
        response = await super().get_response(path, scope)
        if response.status_code == 404:
            response = await super().get_response("index.html", scope)
        return response


# 托管上传文件目录
UPLOADS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
if os.path.isdir(UPLOADS_DIR):
    app.mount("/uploads", StaticFiles(directory=UPLOADS_DIR), name="uploads")

if os.path.isdir(FRONTEND_DIST):
    app.mount("/", SPAStaticFiles(directory=FRONTEND_DIST, html=True), name="frontend")
else:
    @app.get("/")
    def not_built():
        return {
            "message": "前端尚未构建。请先执行：cd frontend && npm install && npm run build",
        }
