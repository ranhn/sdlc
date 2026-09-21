"""飞书开放平台 - 用户同步路由。

通过飞书自建应用的 App ID / App Secret 获取 tenant_access_token，
拉取企业内成员列表，按 open_id 去重写入本地 User 表。

安全约束：
- 仅 admin 角色可调用
- App Secret 仅在服务端使用，不返回给前端
- 同步产生的用户密码随机生成，首次登录后强制改密
"""
import asyncio
import json
import logging
import os
import re
import secrets
import threading
import time
from datetime import datetime
from typing import Any, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Department, Role, User
from ..security import get_current_user, hash_password, write_operation_log

from app.utils import network_clock as nc

# 本地 dev 直接用 uvicorn 起服务时，环境变量可能是在"填好 .env 之前"注入的
# （进程启动早于配置），表现为点「从飞书同步」提示"飞书配置未启用"。
# 这里在 import 阶段兜底读一次仓库根 .env —— 代码改动触发 reload 后即刻生效，不用重启服务。
# 已有环境变量优先（load_dotenv 默认不覆盖），所以 docker/生产不受影响。
try:
    from pathlib import Path as _Path

    from dotenv import load_dotenv

    load_dotenv(_Path(__file__).resolve().parents[3] / ".env")
except Exception:  # noqa: BLE001  —— 缺 dotenv 也不该影响服务启动
    pass

router = APIRouter(prefix="/api/admin/feishu", tags=["飞书同步"])

FEISHU_BASE = "https://open.feishu.cn/open-apis"

logger = logging.getLogger(__name__)

# 并发度：公司有 400+ 部门，而这个接口**只返回部门直属成员**（实测
# /users/find_by_department 也一样，没有"含子部门"的省事写法），所以必须逐个部门拉。
# 串行实测 400 个部门要 333s（每次调用约 0.83s，大头是每请求新建连接的 TLS 握手），
# 同步接口会一直挂到前端超时。这里复用同一个连接池 + 有界并发把耗时压到 20~30s。
# 取值偏保守（6）：通讯录接口有频控，宁可慢一点也别被限流。
FEISHU_CONCURRENCY = 6

_HTTP_CLIENT: httpx.AsyncClient | None = None
# 记住这个客户端是在哪个事件循环里建的（见 _client 说明：跨循环复用必崩）
_HTTP_CLIENT_LOOP: Any = None


def _client() -> httpx.AsyncClient:
    """复用同一个 AsyncClient（连接池），但**必须绑定当前事件循环**。

    为什么要判断循环：httpx.AsyncClient 的连接池与创建它的事件循环绑定，跨循环复用会抛
    ``RuntimeError: Event loop is closed``（在关闭的循环上 call_soon / 关连接）。

    这不是理论风险，是实测事故：飞书通知原先在**临时线程**里用 ``asyncio.run`` 发，
    它第一次创建了这个共享客户端 → 客户端绑在"通知线程"的循环上（很快就关闭）→
    之后**主事件循环里的通讯录同步**复用它，于是"从飞书同步"必失败
    （时间线：通知功能上线当天，同步开始 100% 失败；此前一直正常）。

    现在按循环缓存：循环变了（新线程 / asyncio.run 新建 / 测试里连续 run）就重建客户端，
    既保留同循环内复用连接池的收益，又不会跨循环踩雷。
    """
    global _HTTP_CLIENT, _HTTP_CLIENT_LOOP
    try:
        loop: Any = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if _HTTP_CLIENT is None or _HTTP_CLIENT.is_closed or _HTTP_CLIENT_LOOP is not loop:
        if _HTTP_CLIENT is not None and not _HTTP_CLIENT.is_closed:
            # 旧客户端的连接绑在已失效的循环上，关闭动作本身也可能抛错 —— 忽略即可
            try:
                asyncio.ensure_future(_HTTP_CLIENT.aclose())
            except Exception:  # noqa: BLE001
                pass
        _HTTP_CLIENT = httpx.AsyncClient(
            timeout=20,
            limits=httpx.Limits(max_connections=FEISHU_CONCURRENCY * 2,
                                max_keepalive_connections=FEISHU_CONCURRENCY * 2),
        )
        _HTTP_CLIENT_LOOP = loop
    return _HTTP_CLIENT


# ===================== 配置读取 =====================

def _get_config():
    """读取飞书配置 + 部门映射 + 默认角色。"""
    app_id = os.getenv("FEISHU_APP_ID", "").strip()
    app_secret = os.getenv("FEISHU_APP_SECRET", "").strip()
    default_role_id_raw = os.getenv("FEISHU_DEFAULT_ROLE_ID", "").strip()
    dept_map_raw = os.getenv("FEISHU_DEPT_MAP_JSON", "").strip()
    default_dept_id_raw = os.getenv("FEISHU_DEFAULT_DEPT_ID", "").strip()

    dept_map = {}
    if dept_map_raw:
        try:
            dept_map = json.loads(dept_map_raw)
        except json.JSONDecodeError:
            dept_map = {}

    default_role_id = int(default_role_id_raw) if default_role_id_raw.isdigit() else None
    default_dept_id = int(default_dept_id_raw) if default_dept_id_raw.isdigit() else None

    return {
        "app_id": app_id,
        "app_secret": app_secret,
        "default_role_id": default_role_id,
        "default_dept_id": default_dept_id,
        "dept_map": dept_map,
    }


# ===================== 初始密码 =====================

# 飞书同步账号的初始密码（可用 FEISHU_DEFAULT_PASSWORD 覆盖）。
#
# 为什么是"固定默认口令"而不是每人一个随机值：库里的 password_hash 是**单向**的，
# 改密之后连管理员也拿不到明文 —— 所以"把账号密码发给本人"这件事只有一种实现路径：
# 把密码设成一个**双方都知道的值**。历史行为是随机口令且从不下发，结果是那些从没登录过的
# 同事手里**根本没有可用的密码**（他自己不知道、我们也取不出来）。
#
# 三个护栏（缺一不可）：
#   1) 只作用于 must_change_password=True 的账号 —— 即"从没改过密码、没人成功登录过"。
#      已改过密码的账号一律不碰，否则等于把在职同事锁在门外；
#   2) 首次登录**强制改密**：登录接口返回 must_change_password，前端弹窗不放行，
#      改完清标记（changing 后本模块再也发不出这个口令，因为库里没有明文）；
#   3) 只在**单聊**里发给本人，不写进日志明文、不进群。
DEFAULT_INITIAL_PASSWORD = "Aa123456"


def default_password() -> str:
    """初始密码口径：FEISHU_DEFAULT_PASSWORD 优先，未配置用 DEFAULT_INITIAL_PASSWORD。

    公开（非下划线）是因为管理端"重置密码"入口也要用它 —— 两处必须同源，
    否则同步建号的口令与管理员重置出来的口令会不一致，通知里发的就成假的了。
    """
    return os.getenv("FEISHU_DEFAULT_PASSWORD", "").strip() or DEFAULT_INITIAL_PASSWORD


def initial_password_for(user) -> Optional[str]:
    """这个账号**现在能拿到的初始密码**；拿不到（不该发）返回 None。

    两种返回 None 的情况，理由不同：
      · 已改过密码（must_change_password=False）→ 明文只在他脑子里，我们发不出来，
        更不该替他重置；
      · 手工创建的账号（没有 feishu_open_id）→ 它的初始密码是管理员设的（管理员知道），
        给它发"默认口令"反而是错的：那个口令根本不是它的密码。
    只有"飞书同步来的 + 从没改过密码"的账号，初始口令才由本模块统一指定。
    """
    if not getattr(user, "must_change_password", False):
        return None
    if not (getattr(user, "feishu_open_id", "") or "").strip():
        return None
    return default_password()


# ===================== 卡片构件（消息卡片 1.0） =====================
#
# ⚠️ 实测结论：**本环境（租户/客户端）不支持卡片 JSON 2.0**。同一时段用最小样例对照过：
#     · 2.0（`{"schema":"2.0","header":{...},"body":{"elements":[...]}}`）→ 飞书把整卡降级成
#       `{"tag":"img",...}` + "请升级至最新版本客户端，以查看内容"，**正文全丢**；
#     · 1.0（顶层 elements + div/lark_md）→ 正常解析渲染。
#   （两次都是 code=0，所以"接口成功"不代表"客户端看得见"——验收必须看 message 的渲染体。）
#   因此全项目统一用 **1.0**。等客户端全线升级后再切 2.0，那时能多拿到三样东西：
#   header 的 subtitle（副标题）、column_set（真列布局）、primary_filled（实心按钮）。
#
# 1.0 下把版式做紧的两个要点：
#   1) 并列信息走 `div.fields` + `is_short`（飞书自动排两列），不要多个 div 堆叠；
#   2) **标签与值写在同一行**（`**等级**：高危`）—— 用 `\n` 拆成两行会被当成两个段落，
#      段间距会把卡片撑得又空又散（这是上一版截图里最刺眼的问题）。

def fields_div(*cells: str) -> dict:
    """两列网格：`fields` + `is_short`（飞书按两列排；给 4 段即 2×2）。"""
    return {
        "tag": "div",
        "fields": [{"is_short": True, "text": {"tag": "lark_md", "content": c}}
                   for c in cells],
    }


def text_div(content: str) -> dict:
    """一段 markdown 文本（1.0 的正文元素）。"""
    return {"tag": "div", "text": {"tag": "lark_md", "content": content}}


def primary_button(label: str, url: str) -> dict:
    """跳转按钮（1.0：action + button.url）。"""
    return {"tag": "action", "actions": [{
        "tag": "button",
        "text": {"tag": "lark_md", "content": label},
        "type": "primary",
        "url": url,
    }]}


def note_div(content: str) -> dict:
    """底部灰色小字。"""
    return {"tag": "note", "elements": [{"tag": "lark_md", "content": content}]}


def credentials_div(username: str, password: str) -> dict:
    """「账号 / 初始密码」两列 —— 漏洞指派卡与管理端重置卡**共用同一版式**。"""
    return fields_div(f"**账号**：`{username}`", f"**初始密码**：`{password}`")


def credentials_card(username: str, password: str, base_url: str, *,
                     reason: str | None = None) -> dict:
    """「账号 + 初始口令」卡片：管理端「重置密码」后私信本人（与漏洞指派卡同一套观感）。"""
    elements: list[dict] = [
        text_div(reason or "你的账号已初始化，请用下面的凭据登录"),
        credentials_div(username, password),
    ]
    if base_url:
        elements += [{"tag": "hr"},
                     primary_button("打开登录页", f"{base_url.rstrip('/')}/login")]
    elements.append(note_div("首次登录会强制要求修改密码"))
    return {
        "config": {"wide_screen_mode": True},
        "header": {"template": "indigo",
                   "title": {"tag": "plain_text", "content": "账号初始化"}},
        "elements": elements,
    }


# ===================== 飞书 API 调用 =====================

async def _get_tenant_token(app_id: str, app_secret: str) -> str:
    """获取 tenant_access_token。"""
    url = f"{FEISHU_BASE}/auth/v3/tenant_access_token/internal"
    r = await _client().post(url, json={"app_id": app_id, "app_secret": app_secret})
    data = r.json()
    if data.get("code") != 0:
        raise HTTPException(status_code=502, detail=f"飞书鉴权失败：{data.get('msg', 'unknown')}")
    return data["tenant_access_token"]


# ===================== 单聊消息下发（漏洞指派通知） =====================
#
# 为什么放在这个模块：App 凭证读取（_get_config）、httpx 连接池（_client）、
# tenant_access_token 解析都在这里，复用同一套配置与客户端即可，不必再写第二份
# "飞书调用"实现（本项目对同一件事的两份实现很敏感）。
#
# ⚠️ 需要在飞书开放平台「权限管理」里开通并**发布版本**后才生效：
#     · im:message:send_as_bot —— 以应用身份发送单聊消息（本段用的就是它）
#     · **「应用能力」里必须启用「机器人」** —— 漏了这一步，权限勾对了、凭证也没问题，
#       发送仍然固定返回 code=230006 "Bot ability is not activated."（已实测确认）
#     · 接收人必须在应用的「可用范围」内 —— 否则返回 **230013
#       "Bot has NO availability to this user."**（实测踩过：给自己发完全正常，
#       发给不在可用范围的同事全部失败）；**改完可用范围必须发布新版本才生效**。
#   发消息与通讯录同步是两套独立权限：只有 contact:* 是发不出去的。
#   常见返回码的人话映射见下面的 FEISHU_SEND_ERROR_HINTS / explain_send_error。
#   想确认到底卡在哪一步，可直接跑 tests 之外的自检：取 token → 发一条给自己，
#   打印飞书原始返回（排查顺序：连通性 → 鉴权 → open_id → 机器人能力 → 可用范围）。
#
# 为什么单独做 token 缓存（同步逻辑里是每次直取）：通讯录同步一次只取一次 token，
# 而"按人发消息"是持续发生的高频动作 —— 每条都换 token 既慢又容易撞飞书频控。
# tenant_access_token 有效期 7200s，这里留 5 分钟安全边界。
# 常见发送失败返回码 → 人话。日志与"重置密码"的页面回报都拼这一段，
# 否则管理员只看到一串数字，得去翻文档才知道该改哪里。
FEISHU_SEND_ERROR_HINTS = {
    230002: "接收人不在应用可用范围",
    230006: "应用未启用「机器人」能力：飞书后台 → 应用能力 → 机器人",
    230013: "机器人对该用户不可用：应用「可用范围」不含此人（改完需发布新版本才生效）",
    230020: "触发飞书频控，稍后重试",
    99991672: "权限未开通、或开通后没发布版本（im:message:send_as_bot）",
}


def explain_send_error(code: Any, msg: Any) -> str:
    """把飞书返回码翻成一句人话（未知码原样返回，绝不编造解释）。"""
    base = f"飞书发消息失败：code={code} {msg}"
    try:
        hint = FEISHU_SEND_ERROR_HINTS.get(int(code))
    except (TypeError, ValueError):
        hint = None
    return f"{base}（{hint}）" if hint else base


_TOKEN_CACHE: dict[str, Any] = {"value": "", "expire_at": 0.0}


def notify_enabled() -> bool:
    """是否启用飞书消息通知。

    两个条件同时满足才发：① 配了 App 凭证（没配就是没接入，静默跳过）；
    ② 没有被 FEISHU_NOTIFY=0/false 显式关掉（出问题时的应急开关，不用改代码）。
    """
    raw = str(os.getenv("FEISHU_NOTIFY", "1")).strip().lower()
    if raw in ("0", "false", "no", "off"):
        return False
    cfg = _get_config()
    return bool(cfg["app_id"] and cfg["app_secret"])


async def _tenant_token_cached() -> str:
    """带缓存地取 tenant_access_token（见上方说明）。"""
    cfg = _get_config()
    app_id, app_secret = cfg["app_id"], cfg["app_secret"]
    if not app_id or not app_secret:
        raise HTTPException(status_code=400,
                            detail="飞书配置未启用（缺少 FEISHU_APP_ID / FEISHU_APP_SECRET）")
    now = time.time()
    if _TOKEN_CACHE["value"] and now < float(_TOKEN_CACHE["expire_at"]):
        return str(_TOKEN_CACHE["value"])
    url = f"{FEISHU_BASE}/auth/v3/tenant_access_token/internal"
    r = await _client().post(url, json={"app_id": app_id, "app_secret": app_secret})
    data = r.json()
    if data.get("code") != 0:
        raise HTTPException(status_code=502, detail=f"飞书鉴权失败：{data.get('msg', 'unknown')}")
    _TOKEN_CACHE["value"] = data["tenant_access_token"]
    _TOKEN_CACHE["expire_at"] = now + max(60, int(data.get("expire", 7200)) - 300)
    return str(_TOKEN_CACHE["value"])


def _sync_client() -> httpx.Client:
    """发消息专用的一次性同步客户端（**不复用** _client() 那个连接池）。

    为什么不复用：_client() 里的 AsyncClient 是给通讯录同步用的，它跑在 uvicorn 的
    事件循环里；而通知/密码推送是在**临时线程**里发的 —— AsyncClient 绑定事件循环，
    跨循环复用会在连接回收时偶发 "Event loop is closed"。消息量极小（一次一两条），
    短连接的开销可以忽略，换来的是"任何线程里都能安全发"。
    """
    return httpx.Client(timeout=20)


def _sync_tenant_token() -> str:
    """同步版取 token（与异步版**共用同一个 _TOKEN_CACHE** —— 缓存的是数据，与事件循环无关）。"""
    cfg = _get_config()
    app_id, app_secret = cfg["app_id"], cfg["app_secret"]
    if not app_id or not app_secret:
        raise HTTPException(status_code=400,
                            detail="飞书配置未启用（缺少 FEISHU_APP_ID / FEISHU_APP_SECRET）")
    now = time.time()
    if _TOKEN_CACHE["value"] and now < float(_TOKEN_CACHE["expire_at"]):
        return str(_TOKEN_CACHE["value"])
    with _sync_client() as c:
        r = c.post(f"{FEISHU_BASE}/auth/v3/tenant_access_token/internal",
                   json={"app_id": app_id, "app_secret": app_secret})
    data = r.json()
    if data.get("code") != 0:
        raise HTTPException(status_code=502, detail=f"飞书鉴权失败：{data.get('msg', 'unknown')}")
    _TOKEN_CACHE["value"] = data["tenant_access_token"]
    _TOKEN_CACHE["expire_at"] = now + max(60, int(data.get("expire", 7200)) - 300)
    return str(_TOKEN_CACHE["value"])


def send_and_wait(receive_id: str, msg_type: str, content: Any) -> dict:
    """**同步**发一条消息并返回飞书结果；失败抛 HTTPException（含飞书返回码）。

    msg_type：``text`` 纯文本 / ``interactive`` 消息卡片（content 传卡片 dict）。
    content 收 dict、在这里统一字符串化 —— 飞书要求 content 是**字符串化的 JSON**
    （不是对象），漏了这层会报 code=230001 invalid content。

    给"管理员当面对着一个人操作"的场景用（重置密码）：他要的是**确定答案**
    （发出去了没 / 失败原因是什么），所以这里等结果并把错误抛回去，而不是丢后台线程。
    """
    token = _sync_tenant_token()
    with _sync_client() as c:
        r = c.post(
            f"{FEISHU_BASE}/im/v1/messages",
            # receive_id_type 必须与 receive_id 的**内容**一致：本地存的是 open_id
            # （User.feishu_open_id，同步时用 user_id_type=open_id 拉的）
            params={"receive_id_type": "open_id"},
            headers={"Authorization": f"Bearer {token}"},
            json={"receive_id": receive_id, "msg_type": msg_type,
                  "content": json.dumps(content, ensure_ascii=False)},
        )
    data = r.json()
    if data.get("code") != 0:
        raise HTTPException(
            status_code=502,
            detail=explain_send_error(data.get("code"), data.get("msg")),
        )
    return data.get("data") or {}


def send_in_background(receive_id: str, msg_type: str, content: Any, *, tag: str = "") -> None:
    """在后台线程里发一条消息：**不阻塞调用方，失败也不影响调用方的业务动作**。

    全项目**唯一的发送出口** —— 调用点同步、可被测试替换（线上真发发生在线程里）。

    为什么是线程而不是 BackgroundTasks / 把端点改成 async：
      · 调用方（漏洞指派/创建/编辑）都是**同步端点**（同步 SQLAlchemy Session），
        改成 async 会把阻塞的 DB 调用搬进事件循环；
      · 飞书这一跳可能慢、可能被限流、权限没开时会直接失败 —— 这些都不该让
        "指派负责人"这个业务动作变慢或失败。
    失败只写 WARNING 日志（含飞书返回码，直接对上排查手册）：
      230006 = 没启用「机器人」应用能力（权限勾了也会卡在这）；
      230002 = 接收人不在可用范围；99991672 = 权限未开通/未发布版本。
    """
    if not receive_id or not content:
        return
    label = f"（{tag}）" if tag else ""

    def _run() -> None:
        try:
            send_and_wait(receive_id, msg_type, content)
            logger.info("飞书通知已发送%s → %s", label, receive_id)
        except Exception as exc:  # noqa: BLE001 —— 后台线程里的任何失败都不能冒泡
            logger.warning("飞书通知发送失败%s → %s：%s", label, receive_id, exc)

    threading.Thread(target=_run, daemon=True, name="feishu-notify").start()


def send_text_in_background(receive_id: str, text: str, *, tag: str = "") -> None:
    """纯文本发送（自检脚本、临时通知用）。业务通知请用 send_in_background 发卡片。"""
    if not text:
        return
    send_in_background(receive_id, "text", {"text": text}, tag=tag)


async def _list_feishu_dept_users(token: str, department_id: str, page_size: int = 50) -> list:
    """拉取某飞书部门下的所有用户（自动翻页）。"""
    url = f"{FEISHU_BASE}/contact/v3/users"
    headers = {"Authorization": f"Bearer {token}"}
    users = []
    page_token = ""
    while True:
        params = {
            "department_id": department_id,
            # 关键：部门 ID 用的是 departments 接口返回的 open_department_id，
            # 这里必须同步声明 department_id_type，否则飞书按 department_id 解析
            # 这个 `od-xxx`，匹配不到部门 → code=0 但 items 为空（表现为"同步成功 0 人"）。
            "department_id_type": "open_department_id",
            "page_size": str(page_size),
            "user_id_type": "open_id",
        }
        if page_token:
            params["page_token"] = page_token
        r = await _client().get(url, headers=headers, params=params)
        data = r.json()
        if data.get("code") != 0:
            raise HTTPException(status_code=502, detail=f"拉取飞书用户失败：{data.get('msg')}")
        users.extend(data.get("data", {}).get("items", []) or [])
        if not data.get("data", {}).get("has_more"):
            break
        page_token = data["data"].get("page_token", "")
        if not page_token:
            break
    return users


async def _list_feishu_sub_depts(token: str, parent_id: str, page_size: int = 50) -> list:
    """拉取某部门的**直接子部门**（自动翻页）。parent_id="0" 表示一级部门。"""
    url = f"{FEISHU_BASE}/contact/v3/departments"
    headers = {"Authorization": f"Bearer {token}"}
    items: list = []
    page_token = ""
    while True:
        params = {
            "parent_department_id": parent_id,
            "department_id_type": "open_department_id",
            "page_size": str(page_size),
        }
        if page_token:
            params["page_token"] = page_token
        r = await _client().get(url, headers=headers, params=params)
        data = r.json()
        if data.get("code") != 0:
            raise HTTPException(status_code=502, detail=f"拉取飞书部门失败：{data.get('msg')}")
        payload = data.get("data", {}) or {}
        items.extend(payload.get("items", []) or [])
        if not payload.get("has_more"):
            break
        page_token = payload.get("page_token", "")
        if not page_token:
            break
    return items


async def _collect_feishu_dept_tree(token: str) -> list[dict]:
    """BFS 收集**全公司部门树**（含层级），按层序返回。

    为什么必须遍历整棵树，而不是只取一级部门：
      1. `/contact/v3/users` 返回的是部门的**直属成员**，只看一级部门会漏掉全部
         子部门同事 —— 表现为"同步成功，但人数明显偏少"，且很难一眼看出；
      2. 部门树落库后，人员的部门归属可以直接按 `open_department_id` 自动匹配，
         不必再依赖人工维护的 FEISHU_DEPT_MAP_JSON（那玩意部门一多必然漏配）。

    性能：按"层"并发拉子部门（实测公司 420 个部门 5 层，串行要 5 分钟以上）。
    同一层内用 `asyncio.gather` 保持结果顺序 = 部门原始顺序，所以整棵树仍然**确定性有序**。
    """
    sem = asyncio.Semaphore(FEISHU_CONCURRENCY)

    async def children_of(parent: str) -> list[dict]:
        async with sem:
            try:
                return await _list_feishu_sub_depts(token, parent)
            except HTTPException:
                # 单个部门拉不动（范围外/频控）不该让整棵树失败，跳过它的子部门
                return []

    tree: list[dict] = []
    level_nodes: list[tuple[dict, Optional[str], int]] = [
        (d, None, 1) for d in await children_of("0")
    ]
    while level_nodes:
        this_level: list[tuple[str, int]] = []
        for raw, parent, level in level_nodes:
            odid = (raw or {}).get("open_department_id")
            if not odid:
                continue
            tree.append(
                {
                    "open_department_id": odid,
                    "name": (raw.get("name") or "").strip(),
                    "parent_open_id": parent,
                    "level": level,
                }
            )
            this_level.append((odid, level))
        if not this_level:
            break
        fetched = await asyncio.gather(*[children_of(odid) for odid, _ in this_level])
        level_nodes = [
            (child, odid, level + 1)
            for (odid, level), kids in zip(this_level, fetched)
            for child in kids
        ]
    return tree


# ===================== 同步逻辑 =====================

def _upsert_departments(db: Session, tree: list[dict]) -> dict:
    """把飞书部门树写进本地部门表，返回 `{飞书 open_department_id: 本地部门 id}`。

    匹配顺序（**保证不产生重复部门**）：
      1. 本地已有同 `feishu_open_dept_id` → 复用（只更新）；
      2. 否则本地已有**同名**部门且它还没绑定别的飞书部门 → 认领它并补上飞书 id。
         这一步是关键：seed 出来的"研发部/安全部/测试部/产品部"就是这么对应的，
         不认领就会撞 `sys_department.name` 唯一约束（或插出一堆重复部门）；
      3. 都没有 → 新建；同名已被别人占用时用"名称(2)"这类后缀避让。

    父子关系在第二趟统一回填 —— 父部门可能本趟才刚建出来。
    """
    mapping: dict[str, int] = {}
    created = matched = 0
    for node in tree:
        odid = node["open_department_id"]
        name = node["name"] or odid
        dept = db.query(Department).filter(Department.feishu_open_dept_id == odid).first()
        if dept is None:
            by_name = db.query(Department).filter(Department.name == name).first()
            # 同名但已绑定**另一个**飞书部门（不同分支下的同名部门）→ 不能认领，
            # 否则两个飞书部门会挤进同一条记录、互相覆盖 feishu_open_dept_id
            if by_name is not None and by_name.feishu_open_dept_id in (None, odid):
                dept = by_name
        if dept is None:
            final_name = name
            seq = 1
            while db.query(Department).filter(Department.name == final_name).first() is not None:
                seq += 1
                final_name = f"{name}({seq})"
            dept = Department(name=final_name, feishu_open_dept_id=odid)
            db.add(dept)
            db.flush()   # 需要拿到本地 id 才能回填父子关系
            created += 1
        else:
            dept.feishu_open_dept_id = odid
            matched += 1
        mapping[odid] = dept.id

    for node in tree:
        odid = node["open_department_id"]
        parent_local = mapping.get(node.get("parent_open_id") or "")
        if parent_local and parent_local != mapping.get(odid):
            dept = db.get(Department, mapping[odid])
            if dept is not None:
                dept.parent_id = parent_local
    db.flush()
    return {"mapping": mapping, "created": created, "matched": matched}


_CJK_RE = re.compile(r"[\u4e00-\u9fff]+")

# 人员统一归属到第几级部门（实测 1601 人的直属部门横跨 1~5 级，不归一就没法按部门看）
# 选 2 的依据：二级部门 104 个、平均 15.4 人（粒度像"部门"，且「研发部/测试部」这类
# 名字能和现有部门对上）；三级 257 个、平均 6.2 人（更像小组），且 290 人会因层级不足
# 混进更浅一级，口径不干净。可用 FEISHU_DEPT_LEVEL 覆盖。
DEFAULT_DEPT_LEVEL = 2


def _split_name(full: str) -> tuple[str, str]:
    """把飞书 `name` 拆成 (英文名, 中文名)。

    飞书把中英文名拼在同一个字段（"Tracy.Yang 杨翠"），而 `en_name` 实测为空
    （1601 人里 0 个有值），所以只能自己拆：连续汉字段 = 中文名，其余 = 英文名。
    三种形态都覆盖："Tracy.Yang 杨翠" / "John Villanueva"（纯英文）/ "梁俊"（纯中文）。
    """
    full = (full or "").strip()
    cn = "".join(_CJK_RE.findall(full))
    en = _CJK_RE.sub("", full)
    # 挖掉中文后可能留下孤立的括号/分隔符（"Tracy(杨翠)" → "Tracy( )"）
    en = re.sub(r"[()（）/|、,，]+", " ", en)
    en = " ".join(en.split()).strip(" .·-_")
    return en, cn


def _normalize_dept_map(tree: list[dict], level: int) -> tuple[dict[str, dict], dict[str, str]]:
    """把部门树压到第 `level` 级，返回 (要落库的部门, {任意部门 id → 归一后的部门 id})。

    为什么要归一：人员的**直属部门**层级是不齐的（实测 1 级 29 人 / 2 级 261 / 3 级 869 /
    4 级 422 / 5 级 20），不归一的话同一个业务部门会散成好几条，人员列表也没法按部门看。
    层级不足 `level` 的（直接挂在一级部门下的那 29 人）归到它实际所在的最深一级 ——
    宁可口径略浅，也不给它凭空造一个不存在的上级。
    """
    by_id = {n["open_department_id"]: n for n in tree}

    def chain(dept_id: str) -> list[dict]:
        out: list[dict] = []
        cur = by_id.get(dept_id)
        while cur:
            out.append(cur)
            parent = cur.get("parent_open_id")
            cur = by_id.get(parent) if parent else None
        return list(reversed(out))

    keep: dict[str, dict] = {}
    mapping: dict[str, str] = {}
    for node in tree:
        dept_id = node["open_department_id"]
        chain_ids = chain(dept_id)
        target = chain_ids[min(level, len(chain_ids)) - 1] if chain_ids else node
        mapping[dept_id] = target["open_department_id"]
        keep.setdefault(target["open_department_id"], {
            "open_department_id": target["open_department_id"],
            "name": target["name"],
            # 只落这一层：上层不落库，新增用户时的部门下拉才是干净的 104 项
            "parent_open_id": None,
            "level": target.get("level"),
        })
    return keep, mapping


def _derive_username(en_name: str, email: Optional[str], open_id: str,
                     taken: set[str]) -> str:
    """用户名 = 英文名（产品要求：列表里不再单独展示英文名，用户名就是它）。

    取名顺序：英文名 → 邮箱前缀（12 人没有英文名）→ fs_<open_id 尾 8>（兜底）。
    冲突处理：重名时追加序号（实测飞书侧只有 1 组重名 Ada.Wang），并且用**小写**比对 ——
    登录接口在精确匹配失败后会退化成不区分大小写匹配，所以 Bob 与 bob 视作同一个名字。
    """
    base = (en_name or "").strip()
    if not base and email and "@" in email:
        base = email.split("@", 1)[0]
    base = re.sub(r"\s+", "", base) or _gen_username("fs", open_id)
    base = base[:40]                     # 给序号留出空间，username 列是 50 字符
    candidate, seq = base, 1
    while candidate.lower() in taken:
        seq += 1
        candidate = f"{base}{seq}"
    taken.add(candidate.lower())
    return candidate


def _pick_dept_id(
    feishu_dept_ids: list,
    dept_map: dict,
    fs_dept_map: dict,
    default_dept_id: Optional[int],
) -> Optional[int]:
    """从飞书部门 ID 列表里匹配本地部门 id。

    优先级：人工映射（FEISHU_DEPT_MAP_JSON，保留为覆盖手段）> 飞书部门树自动落库的
    映射 > 默认部门。人的 `department_ids[0]` 通常是主部门，故按列表顺序取第一个能
    匹配上的。

    映射值容错：`FEISHU_DEPT_MAP_JSON` 是人手写的环境变量，写错（"1 " / 空串 /
    非数字）不该让整次同步 500，跳过继续匹配下一项即可。
    """
    for source in (dept_map, fs_dept_map):
        for fid in feishu_dept_ids or []:
            raw = source.get(str(fid))
            if raw is None or raw == "":
                continue
            try:
                return int(raw)
            except (TypeError, ValueError):
                continue
    return default_dept_id


def _gen_username(prefix: str, open_id: str) -> str:
    """生成不超过 50 字符的 username。"""
    suffix = open_id[-8:] if open_id else secrets.token_hex(4)
    return f"{prefix}_{suffix}"[:50]


class FeishuConfigOut(BaseModel):
    enabled: bool
    default_role_id: Optional[int]
    default_dept_id: Optional[int]
    dept_map_keys: list


class FeishuSyncResult(BaseModel):
    total: int
    created: int
    updated: int
    skipped: int
    failed: int
    details: list
    # 部门树同步情况：飞书部门会自动落库并按 open_department_id 匹配本地部门。
    # 这三个数字用来判断"人员归属对不对" —— 部门没建出来，人就会全落默认部门。
    dept_total: int = 0
    dept_created: int = 0
    dept_matched: int = 0
    # 本轮飞书里已不存在 → 被停用的本地账号数（离职/移出部门）
    deactivated: int = 0
    # 与手工账号合并的人数（手工账号挂上飞书 id、飞书那条重复记录软删除）
    merged: int = 0
    # 用户名由 fs_xxxx 改成英文名的账号数（只改从没登录过的账号）
    renamed: int = 0


@router.get("/config", response_model=FeishuConfigOut)
def get_config(current: User = Depends(get_current_user)):
    """查看飞书同步配置状态（不返回敏感字段）。"""
    if current.role is None or current.role.code != "admin":
        raise HTTPException(status_code=403, detail="仅超级管理员可操作")
    cfg = _get_config()
    return FeishuConfigOut(
        enabled=bool(cfg["app_id"] and cfg["app_secret"]),
        default_role_id=cfg["default_role_id"],
        default_dept_id=cfg["default_dept_id"],
        dept_map_keys=list(cfg["dept_map"].keys()),
    )


@router.post("/sync", response_model=FeishuSyncResult)
async def sync_users(db: Session = Depends(get_db), current: User = Depends(get_current_user)):
    """从飞书拉取用户并同步到本地。"""
    if current.role is None or current.role.code != "admin":
        raise HTTPException(status_code=403, detail="仅超级管理员可操作")
    cfg = _get_config()
    if not (cfg["app_id"] and cfg["app_secret"]):
        raise HTTPException(status_code=400, detail="飞书配置未启用（FEISHU_APP_ID / FEISHU_APP_SECRET）")

    # 默认角色兜底：所有同步进来的用户都是「普通权限」（FEISHU_DEFAULT_ROLE_ID 可覆盖）
    default_role_id = cfg["default_role_id"]
    if not default_role_id:
        # ⚠️ 这里踩过一次线上坑：seed 出来的「普通权限」角色 code 是 **user**，而下面兜底
        # 创建用的 code 是 employee —— 只按 code=employee 查会查不到，接着再插一条同名
        # 角色就撞 sys_role.name 唯一约束，整次同步直接 500（按钮点了没反应）。
        # 所以：code 兼容 user/employee，再按名字兜底（名字含改名前后的两种），最后才创建。
        emp_role = (
            db.query(Role).filter(Role.code.in_(("employee", "user"))).first()
            or db.query(Role).filter(Role.name.in_(("普通权限", "普通员工"))).first()
        )
        if not emp_role:
            emp_role = Role(name="普通权限", code="employee", description="飞书同步默认角色")
            db.add(emp_role)
            db.commit()
            db.refresh(emp_role)
        default_role_id = emp_role.id

    # 默认部门兜底：取第一个
    default_dept_id = cfg["default_dept_id"]
    if not default_dept_id:
        first_dept = db.query(Department).first()
        if first_dept:
            default_dept_id = first_dept.id

    token = await _get_tenant_token(cfg["app_id"], cfg["app_secret"])

    # 1) 先同步部门树：人员的部门归属依赖它（部门没落库 → 人全落默认部门）
    dept_tree = await _collect_feishu_dept_tree(token)
    # 归一到固定层级（默认第 2 级）后再落库，人员一律挂到这一层
    dept_level = int(os.getenv("FEISHU_DEPT_LEVEL", "") or DEFAULT_DEPT_LEVEL)
    keep_depts, dept_norm = (
        _normalize_dept_map(dept_tree, dept_level)
        if dept_tree else ({}, {})
    )
    dept_sync = (
        _upsert_departments(db, list(keep_depts.values()))
        if keep_depts
        else {"mapping": {}, "created": 0, "matched": 0}
    )
    fs_dept_map: dict = dept_sync["mapping"]

    result = FeishuSyncResult(
        total=0, created=0, updated=0, skipped=0, failed=0, details=[],
        dept_total=len(keep_depts),
        dept_created=dept_sync["created"],
        dept_matched=dept_sync["matched"],
    )
    seen_open_ids: set = set()

    # 已同步过的账号预加载成字典：1600 人逐个 SELECT 太浪费，后面停用判断也复用这份数据
    existing_by_open_id: dict[str, User] = {
        u.feishu_open_id: u
        for u in db.query(User)
        .filter(User.feishu_open_id.isnot(None), User.is_deleted == False)  # noqa: E712
        .all()
    }
    # 已被占用的用户名（含手工账号），用于给新用户/改名用户挑一个不撞的名字
    taken_usernames: set[str] = {
        (u.username or "").lower() for u in db.query(User).all()
    }

    # 新建账号的初始密码：**整批共用一个哈希**（口令口径见 DEFAULT_INITIAL_PASSWORD 说明）。
    # 为什么不给每人单独哈希：bcrypt 单次实测 186ms，1600 个新用户就是 ~300s 纯 CPU，
    # 而且它是同步调用、会**阻塞事件循环**（同步期间整个后端含健康检查都无响应）。
    batch_pwd_hash = hash_password(default_password())
    aligned_password = 0   # 顺带把"从没登录过的老账号"对齐到默认口令，最后写进操作日志

    # 2) 逐个部门拉**直属**用户：只取一级部门会漏掉全部子部门同事
    target_depts = [n["open_department_id"] for n in dept_tree] or ["0"]

    # 并发拉取各部门用户（串行 400+ 个部门实测 333s，前端会等到超时）。
    # `gather` 保持顺序 = target_depts 顺序，所以写库顺序仍然确定。
    sem = asyncio.Semaphore(FEISHU_CONCURRENCY)

    async def _fetch_dept(dept_id: str) -> tuple[str, list, Optional[str]]:
        async with sem:
            try:
                return dept_id, await _list_feishu_dept_users(token, dept_id), None
            except HTTPException as e:
                return dept_id, [], str(e.detail)

    fetched_depts = await asyncio.gather(*[_fetch_dept(fid) for fid in target_depts])

    # 一个人可能同时挂在多个部门（跨部门/兼任）——先把"他在哪些部门出现过"汇总起来，
    # 每人只留一条记录，部门取**归一后层级最深**的那个（最具体、最接近他实际所在的团队）；
    # 同层级时取 BFS 先遇到的（一级部门优先），保证结果确定、可复现。
    dept_hits: dict[str, list[str]] = {}
    for fid, fs_users, err in fetched_depts:
        if err:
            continue
        for fu in fs_users:
            oid = fu.get("open_id")
            if oid:
                dept_hits.setdefault(oid, []).append(fid)

    def _most_specific_dept(candidates: list[str]) -> str:
        best, best_level = candidates[0], -1
        for raw in candidates:
            target = dept_norm.get(str(raw), str(raw))
            level = (keep_depts.get(target) or {}).get("level") or 0
            if level > best_level:
                best, best_level = target, level
        return best

    # 1.5) 同一人两条记录：**手工建的账号**（无 feishu_open_id）+ 飞书同步出来的账号。
    #      合并规则刻意保守：只在"中文名在飞书侧唯一"时才认（同名多人绝不自动并，
    #      宁可不并也不能错误合并两个人的账号与漏洞数据）。
    #      合并动作可回滚：手工账号挂上飞书 open_id（保留其 id/用户名/密码，能继续登录），
    #      飞书那条重复记录软删除（is_deleted=True，列表不再显示）。
    cn_to_open_ids: dict[str, list[str]] = {}
    for fid, fs_users, err in fetched_depts:
        if err:
            continue
        for fu in fs_users:
            oid = fu.get("open_id")
            if not oid:
                continue
            _en, cn = _split_name(fu.get("name") or "")
            if cn and oid not in cn_to_open_ids.setdefault(cn, []):
                cn_to_open_ids[cn].append(oid)

    for local in db.query(User).filter(
        User.feishu_open_id.is_(None), User.is_deleted == False,  # noqa: E712
    ).all():
        oids = cn_to_open_ids.get((local.full_name or "").strip()) or []
        if len(oids) != 1:
            continue
        oid = oids[0]
        dup = existing_by_open_id.get(oid)
        if dup is not None and dup.id == local.id:
            continue
        if dup is not None:
            dup.is_deleted = True          # 飞书那条重复记录 → 软删除
        # ⚠️ 必须把 open_id 真正写到手工账号上（只改内存映射的话，下次同步还会再建一个重复账号）
        local.feishu_open_id = oid
        existing_by_open_id[oid] = local   # 之后按这个手工账号更新（保留其用户名/密码）
        result.merged += 1

    for fid, fs_users, err in fetched_depts:
        if err:
            result.failed += 1
            result.details.append({"dept": fid, "error": err})
            continue
        for fu in fs_users:
            open_id = fu.get("open_id")
            if not open_id or open_id in seen_open_ids:
                continue
            seen_open_ids.add(open_id)
            result.total += 1
            try:
                # 飞书 name = "Tracy.Yang 杨翠"（中英文拼一起），拆成英文名 / 中文名两列；
                # full_name 优先存中文名，没有中文名（270 人）时用英文名兜底，避免空名字。
                en_name, cn_name = _split_name(fu.get("name") or "")
                name = cn_name or en_name or "未命名"
                email = fu.get("email") or None
                # 「部门直属用户列表」实测**不返回** department_ids 字段（飞书只回
                # open_id/name/email/employee_no/avatar 等）。若不兜底，所有人的
                # department_ids 都是空 → 全部落到"默认部门"，部门同步等于白做。
                # 兜底依据：我们本来就是**按部门逐个拉**的，`fid` 就是这个人的归属；
                # 同一人出现在多个部门时按 BFS 顺序取第一个（一级部门优先 ≈ 主部门）。
                # 再统一归一到指定层级（默认二级），保证全公司口径一致。
                # 他挂过的所有部门 → 取最具体的一个（见 _most_specific_dept 说明）
                fs_dept_ids = fu.get("department_ids") or dept_hits.get(open_id, [fid])
                normalized = [_most_specific_dept([str(x) for x in fs_dept_ids])]
                dept_id = _pick_dept_id(
                    normalized, cfg["dept_map"], fs_dept_map, default_dept_id
                )
                username = _gen_username("fs", open_id)

                existing = existing_by_open_id.get(open_id)
                now = nc.utcnow()
                if existing:
                    existing.full_name = name
                    existing.en_name = en_name or None
                    existing.email = email or existing.email
                    existing.department_id = dept_id or existing.department_id
                    existing.last_synced_at = now
                    # 初始口令对齐：历史同步建号用的是**随机且从不下发**的口令，从没登录过的
                    # 同事手里等于没有可用密码（指派通知里也就发不出账号密码）。这里把这类账号
                    # 对齐成默认口令 —— 判定口径与"改名"一致：must_change_password=True
                    # （从没改过密码、没人成功用它登录过）。已改密的账号一律不碰。
                    if existing.must_change_password:
                        existing.password_hash = batch_pwd_hash
                        aligned_password += 1
                    # 用户名改成英文名（产品要求：列表不再单独展示英文名，用户名就是它）。
                    # 只改**自动生成且从没登录过**的账号：username 仍是 fs_<open_id 尾8>
                    # 且 must_change_password=True（说明没改过密码、没人用这个账号登录过）。
                    # 管理员手工改过用户名、或已登录过的账号一律不动，避免把人锁在外面。
                    if existing.must_change_password and existing.username == _gen_username("fs", open_id):
                        taken_usernames.discard((existing.username or "").lower())
                        new_username = _derive_username(en_name, email, open_id, taken_usernames)
                        if new_username != existing.username:
                            existing.username = new_username
                            result.renamed += 1
                    existing.is_active = True
                    result.updated += 1
                else:
                    # 邮箱缺失时**留空**，不再用手机号拼 `{mobile}@feishu.local` 假邮箱：
                    # 假地址会跟着用户进通讯录和通知链路，告警/邮件发到不存在的地址，
                    # 比"没有邮箱"更难排查。已开通 contact:user.email:readonly，
                    # 正常情况都能读到真实邮箱；为空说明该员工未填或未授权该字段。
                    # 用户名 = 英文名（重名时加序号；没英文名的用邮箱前缀兜底）
                    username = _derive_username(en_name, email, open_id, taken_usernames)
                    # 初始密码只哈希一次、整批共用（见上方 batch_pwd_hash 说明），
                    # 并且首次登录强制改密
                    user = User(
                        username=username,
                        password_hash=batch_pwd_hash,
                        full_name=name,
                        en_name=en_name or None,
                        email=email,
                        role_id=default_role_id,      # 角色：默认普通权限（FEISHU_DEFAULT_ROLE_ID 可覆盖）
                        department_id=dept_id,
                        is_active=True,
                        feishu_open_id=open_id,
                        last_synced_at=now,
                        must_change_password=True,  # 飞书同步用户首次登录必须改密
                    )
                    db.add(user)
                    result.created += 1
            except Exception as e:
                result.failed += 1
                result.details.append({"open_id": open_id, "error": str(e)})

    # 3) 状态：本轮飞书里**没再出现**的人 → 停用（离职、或被移出所有可见部门）。
    #    飞书接口不返回 status 字段（部门列表和单用户接口都实测过），所以只能用
    #    "这次还在不在"来推导 —— 这也正是通讯录同步的常规做法。
    #    两道安全阀，避免"范围被收窄/某次大面积失败"把整库人误停用：
    #      ① 本次有任何部门拉取失败 → 直接跳过（宁可不停用，也不能误停）；
    #      ② 本轮拉到的人数不到库内飞书用户的 50% → 跳过（疑似范围异常）。
    feishu_accounts = list(existing_by_open_id.values())   # 复用前面预加载的字典
    if result.failed == 0 and seen_open_ids and len(seen_open_ids) * 2 >= len(feishu_accounts):
        for u in feishu_accounts:
            if u.feishu_open_id not in seen_open_ids and u.is_active:
                u.is_active = False
                result.deactivated += 1
    elif feishu_accounts:
        result.details.append({
            "skipped_deactivate": f"本轮 {len(seen_open_ids)} 人 / 库内 {len(feishu_accounts)} 人"
                                  f"（失败部门 {result.failed} 个）→ 不执行停用",
        })

    db.commit()
    write_operation_log(
        db, current, "feishu_sync", "admin",
        f"飞书同步: 部门 {result.dept_total} 个（新建 {result.dept_created} / 匹配 {result.dept_matched}）, "
        f"用户 总数 {result.total}, 新建 {result.created}, 更新 {result.updated}, "
        f"改名 {result.renamed}, 合并手工账号 {result.merged}, "
        f"初始口令对齐 {aligned_password}, "
        f"停用 {result.deactivated}, 失败 {result.failed}",
    )
    return result
