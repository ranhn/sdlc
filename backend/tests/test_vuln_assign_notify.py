"""漏洞指派 · 飞书通知回归测试。

用法（在 backend 目录下）：
    python tests/test_vuln_assign_notify.py

为什么要有它：指派通知是**发出去就收不回**的动作 —— 发错人、重复轰炸、或因为飞书侧
报错把"指派"本身搞失败，代价都比没有通知大。这组测试把"什么时候发、发给谁、发什么、
什么时候一律不发、发失败会怎样"逐条钉住。

测试**不发真实请求**：把 feishu.send_text_in_background（唯一的发送出口）换成本地记录
函数。这也顺带固化了设计：通知的发送出口只有一个，且调用点同步、可被替换 —— 真发是
在线程里进行的（见 feishu.send_text_in_background 的说明）。
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI                            # noqa: E402
from fastapi.testclient import TestClient              # noqa: E402
from sqlalchemy import create_engine                   # noqa: E402
from sqlalchemy.orm import sessionmaker                # noqa: E402
from sqlalchemy.pool import StaticPool                 # noqa: E402

import app.routers.feishu as feishu                    # noqa: E402
from app.database import Base, get_db                  # noqa: E402
from app.models import AssetSystem, Role, User, Vuln, VulnFlow   # noqa: E402
from app.routers import vulns as vulns_router          # noqa: E402
from app.security import get_current_user              # noqa: E402

# 模块导入时的原函数：_setup() 会把它换成 lambda（每个用例都从"通知可用"开始），
# 测开关本身时必须用这个原函数，否则测到的是替身。
_ORIG_NOTIFY_ENABLED = feishu.notify_enabled

CURRENT: dict = {}
SENT: list[dict] = []


def _capture(receive_id, msg_type, content, *, tag=""):
    """发送函数替身：只记录（收件人、消息类型、内容、标签），不做任何网络调用。"""
    SENT.append({"to": receive_id, "msg_type": msg_type, "content": content, "tag": tag})


def _card_text(card) -> str:
    """把卡片 JSON 里所有文案拍平成一个字符串，便于按关键字断言（不绑死段落结构）。"""
    out: list[str] = []

    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "content" and isinstance(v, str):
                    out.append(v)
                else:
                    walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(card)
    return "\n".join(out)


def _card_links(card) -> list[str]:
    """收集卡片里所有按钮的跳转地址。

    同时认两种写法：卡片 2.0 用 ``behaviors[].default_url``，1.0 是按钮上直接给 ``url``。
    两种都收，是为了"以后回退版本"不至于让测试全红。
    """
    links: list[str] = []

    def walk(node):
        if isinstance(node, dict):
            if node.get("tag") == "button":
                if node.get("url"):
                    links.append(node["url"])
                for b in node.get("behaviors") or []:
                    if isinstance(b, dict) and b.get("default_url"):
                        links.append(b["default_url"])
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(card)
    return links


def _setup():
    engine = create_engine("sqlite:///:memory:",
                           connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    admin_role = Role(name="超级管理员", code="admin")
    dev_role = Role(name="研发人员", code="dev")
    db.add_all([admin_role, dev_role])
    db.flush()
    db.add(AssetSystem(name="官网门户", description="回归测试用"))
    db.add(User(username="admin", password_hash="x", full_name="管理员", role_id=admin_role.id))
    # dev1/dev3 是飞书同步来的（有 open_id），dev2 是手工建号（没有 open_id）
    # dev1：飞书同步来、**从没登录过**（must_change_password=True）→ 通知里要带初始口令
    db.add(User(username="dev1", password_hash="x", full_name="研发小王",
                role_id=dev_role.id, feishu_open_id="ou_dev1", must_change_password=True))
    db.add(User(username="dev2", password_hash="x", full_name="手工账号",
                role_id=dev_role.id, feishu_open_id=None))
    db.add(User(username="dev3", password_hash="x", full_name="研发小李",
                role_id=dev_role.id, feishu_open_id="ou_dev3"))
    db.commit()

    api = FastAPI()
    api.include_router(vulns_router.router)
    api.dependency_overrides[get_db] = lambda: db
    api.dependency_overrides[get_current_user] = lambda: CURRENT["user"]

    # 每个用例都从"通知已启用 + 发送被记录"开始（开关本身另有专门用例）
    SENT.clear()
    feishu.notify_enabled = lambda: True
    feishu.send_in_background = _capture
    return db, TestClient(api)


def _users(db):
    def one(name):
        return db.query(User).filter(User.username == name).first()
    return one("admin"), one("dev1"), one("dev2"), one("dev3")


def _new_vuln(client, *, assignee_id=None, severity="high", system_id=None) -> int:
    payload = {
        "title": "测试漏洞：指派通知",
        "severity": severity,
        "description": "回归测试用",
        "api_endpoint": "/api/test/notify",
    }
    if assignee_id is not None:
        payload["assignee_id"] = assignee_id
    if system_id is not None:
        payload["system_id"] = system_id
    r = client.post("/api/vulns", json=payload)
    assert r.status_code in (200, 201), r.text
    return r.json()["id"]


def _assign(client, vid: int, uid: int):
    return client.post(f"/api/vulns/{vid}/assign", json={"assignee_id": uid})


# ============ 该发的时候要发，且内容可用 ============
def test_assign_sends_feishu_message_to_new_assignee():
    """指派接口 → 新负责人收到 1 条消息，收件人是他的 open_id，正文含关键信息与深链。"""
    db, client = _setup()
    admin, dev1, _, _ = _users(db)
    system = db.query(AssetSystem).first()
    CURRENT["user"] = admin
    vid = _new_vuln(client, system_id=system.id)

    r = _assign(client, vid, dev1.id)
    assert r.status_code == 200, r.text
    assert len(SENT) == 1, f"应发 1 条，实际 {len(SENT)}：{SENT}"
    msg = SENT[0]
    assert msg["to"] == "ou_dev1", f"收件人应是负责人的 open_id：{msg}"
    # 通知是**消息卡片**（等级配色标题 + 两列网格 + 主按钮），不是纯文本
    assert msg["msg_type"] == "interactive", f"指派通知应发卡片：{msg['msg_type']}"
    card = msg["content"]
    # 关键：**不带 schema 2.0** —— 实测本环境不支持 2.0（会被降级成"请升级客户端"占位），
    # 发出去看不见。这条断言就是为了防止以后有人"顺手升级"成 2.0。
    assert "schema" not in card, "卡片 2.0 在本环境渲染不出来，请保持 1.0（见 feishu.py 说明）"
    title = card["header"]["title"]["content"]
    assert "漏洞指派" in title and "高危" in title, title   # SEV_ZH 口径（与报告/页面一致）
    assert card["header"]["template"] == "orange", "高危应是橙色标题（与前端严重度配色一致）"
    text = _card_text(card)
    assert "测试漏洞：指派通知" in text, text
    assert "官网门户" in text, text
    assert "待确认" in text, text
    assert "管理员" in text, text                           # 谁派的
    # 主按钮直达修复页：与 CSV/Word 导出的 ?id= 语义一致（只断言路径，域名随部署环境变）
    links = _card_links(card)
    assert links and f"/vulnerabilities/fix?id={vid}" in links[0], links


def test_create_with_assignee_sends():
    """提交时就填了「修复负责人」→ 也要通知（这是最常见的"指定负责人"入口）。"""
    db, client = _setup()
    admin, dev1, _, _ = _users(db)
    CURRENT["user"] = admin
    vid = _new_vuln(client, assignee_id=dev1.id)
    assert len(SENT) == 1, f"提交时指定负责人应发 1 条，实际 {len(SENT)}"
    assert SENT[0]["to"] == "ou_dev1"
    # 时间线也要有这条提交记录（与通知同一条件，便于"他到底通没通知"对账）
    assert db.query(VulnFlow).filter(VulnFlow.vuln_id == vid).count() == 1


def test_edit_that_changes_assignee_sends_once():
    """编辑表单里改负责人 = 一次指派 → 发 1 条；再编辑别的字段不再重复发。"""
    db, client = _setup()
    admin, dev1, _, _ = _users(db)
    CURRENT["user"] = admin
    vid = _new_vuln(client)
    assert SENT == []

    r = client.patch(f"/api/vulns/{vid}", json={"assignee_id": dev1.id})
    assert r.status_code == 200, r.text
    assert len(SENT) == 1, f"编辑改负责人应发 1 条，实际 {len(SENT)}"

    # 只改标题（不含 assignee_id）→ 不再发
    assert client.patch(f"/api/vulns/{vid}", json={"title": "改个标题"}).status_code == 200
    assert len(SENT) == 1, f"没动负责人不该再发：{SENT}"


def test_transfer_by_assignee_sends_to_new_owner():
    """修复人转派（上一轮新开的入口）→ 通知**新**负责人，而不是原负责人。"""
    db, client = _setup()
    admin, dev1, _, dev3 = _users(db)
    CURRENT["user"] = admin
    vid = _new_vuln(client, assignee_id=dev1.id)
    SENT.clear()                       # 忽略创建时那一条

    CURRENT["user"] = dev1             # 负责人本人转派给 dev3
    r = _assign(client, vid, dev3.id)
    assert r.status_code == 200, r.text
    assert [m["to"] for m in SENT] == ["ou_dev3"], SENT


# ============ 不该发的时候一条都不能发 ============
def test_reassign_to_same_person_does_not_send_again():
    """重复指派同一个人不再打扰他（与"时间线只在换人时记一条"同一口径）。"""
    db, client = _setup()
    admin, dev1, _, _ = _users(db)
    CURRENT["user"] = admin
    vid = _new_vuln(client)
    assert _assign(client, vid, dev1.id).status_code == 200
    assert _assign(client, vid, dev1.id).status_code == 200
    assert len(SENT) == 1, f"同一人不该重复通知：{SENT}"


def test_unassign_does_not_send():
    """取消指派（负责人清空）不发 —— 没有收件人，也不该 @ 任何人。"""
    db, client = _setup()
    admin, dev1, _, _ = _users(db)
    CURRENT["user"] = admin
    vid = _new_vuln(client, assignee_id=dev1.id)
    SENT.clear()

    r = client.patch(f"/api/vulns/{vid}", json={"assignee_id": None})
    assert r.status_code == 200, r.text
    assert SENT == [], f"取消指派不该发通知：{SENT}"
    # 但"取消指派"这件事仍要留痕（通知与留痕是两回事）
    last = db.query(VulnFlow).filter(VulnFlow.vuln_id == vid) \
        .order_by(VulnFlow.created_at.desc()).first()
    assert "取消指派" in (last.comment or ""), last.comment


def test_assignee_without_open_id_is_skipped():
    """负责人是手工账号（无 feishu_open_id）→ 跳过发送，但指派本身必须成功。"""
    db, client = _setup()
    admin, _, dev2, _ = _users(db)
    CURRENT["user"] = admin
    vid = _new_vuln(client)
    r = _assign(client, vid, dev2.id)
    assert r.status_code == 200, f"没有 open_id 不该影响指派：{r.text}"
    assert SENT == [], f"无 open_id 不应调用发送：{SENT}"
    db.expire_all()
    assert db.get(Vuln, vid).assignee_id == dev2.id, "指派没生效"


def test_notify_disabled_by_switch():
    """FEISHU_NOTIFY=0（应急开关）→ 一条都不发，指派照样成功。"""
    db, client = _setup()
    admin, dev1, _, _ = _users(db)
    feishu.notify_enabled = lambda: False
    CURRENT["user"] = admin
    vid = _new_vuln(client)
    assert _assign(client, vid, dev1.id).status_code == 200
    assert SENT == [], SENT


# ============ 初始账号密码：只在"从没登录过"的账号上出现 ============
def test_card_carries_credentials_for_never_logged_in_assignee():
    """从没登录过的飞书账号：卡片里要给出账号 + 初始口令 + 首登必改提示。

    否则等于把人派了活却不给他进门的钥匙（历史同步的随机口令从不下发，他根本没有密码）。
    """
    db, client = _setup()
    admin, dev1, _, _ = _users(db)
    CURRENT["user"] = admin
    vid = _new_vuln(client)

    assert _assign(client, vid, dev1.id).status_code == 200
    text = _card_text(SENT[0]["content"])
    assert "初始密码" in text, text
    assert "Aa123456" in text, text
    assert "dev1" in text, text                    # 账号（用户名）也要给
    assert "强制要求修改密码" in text, text         # 首登必改的提示
    assert dev1.username == "dev1"


def test_card_has_no_credentials_for_user_who_changed_password():
    """**已改过密码的账号绝不出现在口令**（这是本功能最要紧的一条）。

    库里只有哈希、明文只在本人脑子里：一旦给在用账号发"初始口令"，轻则误导他按默认值登录，
    重则等于泄露一个可猜的口令。判定只认 must_change_password，这里把它钉死。
    """
    db, client = _setup()
    admin, _, _, dev3 = _users(db)      # dev3：已改过密码（must_change_password=False）
    assert dev3.must_change_password is False
    CURRENT["user"] = admin
    vid = _new_vuln(client)

    assert _assign(client, vid, dev3.id).status_code == 200
    text = _card_text(SENT[0]["content"])
    assert "初始密码" not in text, f"不该给已改密的账号发口令：{text}"
    assert "Aa123456" not in text, text


# ============ 通知失败不能波及业务 ============
def test_feishu_failure_does_not_break_assign():
    """飞书侧抛错（挂了/限流/权限没开）时，指派仍必须 200 且落库留痕。

    这是设计的底线：通知是"尽力而为"的附加动作，不能反过来决定指派成不成功。
    """
    db, client = _setup()
    admin, dev1, _, _ = _users(db)

    def _boom(receive_id, msg_type, content, *, tag=""):
        raise RuntimeError("模拟飞书 502")

    feishu.send_in_background = _boom
    CURRENT["user"] = admin
    vid = _new_vuln(client)
    r = _assign(client, vid, dev1.id)
    assert r.status_code == 200, r.text
    db.expire_all()
    assert db.get(Vuln, vid).assignee_id == dev1.id, "指派没生效"
    # 时间线应有两步：提交（创建时）+ 指派。通知失败不该吃掉指派这一步。
    flows = db.query(VulnFlow).filter(VulnFlow.vuln_id == vid).all()
    assert len(flows) == 2, f"应有「提交」「指派」两条流转记录，实际 {len(flows)}"
    # 指派不改状态（from == to，见 _assign_change_text 说明）；首次指派文案是「指派负责人：X」
    assign_flow = [f for f in flows if f.from_status == f.to_status]
    assert assign_flow and "指派负责人" in (assign_flow[0].comment or ""), \
        f"指派没留痕：{[f.comment for f in flows]}"


def test_notification_link_prefers_public_base_url():
    """配了 PUBLIC_BASE_URL 就用它 —— 通知的读者是**另一个人**，必须给他点得开的地址。

    没配时取"操作人此刻访问的地址"（与 CSV/Word 导出同一套 _resolve_base_url）。那个口径
    对导出是对的（文件由操作人自己下载），但通知不行：操作人在本机/内网操作时，收件人收到
    的是 127.0.0.1 这类打不开的链接（实测踩过）。
    """
    db, client = _setup()
    admin, dev1, _, _ = _users(db)
    CURRENT["user"] = admin
    vid = _new_vuln(client)

    saved = os.environ.get("PUBLIC_BASE_URL")
    try:
        # 故意带尾部斜杠：拼接时不能出现 //vulnerabilities
        os.environ["PUBLIC_BASE_URL"] = "https://sdlc.example.com/"
        assert _assign(client, vid, dev1.id).status_code == 200
        links = _card_links(SENT[0]["content"])
        # 尾部斜杠不能拼出 https://sdlc.example.com//vulnerabilities/...
        assert links == [f"https://sdlc.example.com/vulnerabilities/fix?id={vid}"], links
    finally:
        if saved is None:
            os.environ.pop("PUBLIC_BASE_URL", None)
        else:
            os.environ["PUBLIC_BASE_URL"] = saved


def test_notify_enabled_reads_config_and_switch():
    """开关口径：没配 App 凭证 = 没接入 → 静默不发；配了且未被关掉 → 发。"""
    keys = ("FEISHU_APP_ID", "FEISHU_APP_SECRET", "FEISHU_NOTIFY")
    saved = {k: os.environ.get(k) for k in keys}
    try:
        os.environ["FEISHU_APP_ID"] = ""
        os.environ["FEISHU_APP_SECRET"] = ""
        os.environ.pop("FEISHU_NOTIFY", None)
        assert _ORIG_NOTIFY_ENABLED() is False, "没配凭证也不该尝试发送"

        os.environ["FEISHU_APP_ID"] = "cli_xxx"
        os.environ["FEISHU_APP_SECRET"] = "secret_xxx"
        assert _ORIG_NOTIFY_ENABLED() is True

        for off in ("0", "false", "no", "off", "FALSE"):
            os.environ["FEISHU_NOTIFY"] = off
            assert _ORIG_NOTIFY_ENABLED() is False, f"FEISHU_NOTIFY={off} 应关闭通知"
    finally:
        for k, val in saved.items():
            if val is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = val


# ============ 运行器 ============
def _main() -> int:
    cases = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in cases:
        try:
            fn()
            print(f"  PASS  {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL  {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"  ERROR {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(cases) - failed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_main())
