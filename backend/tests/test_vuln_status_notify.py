"""漏洞**状态流转**飞书通知回归测试（确认 / 驳回 / 修复完成 / 复测通过 / 关闭）。

用法（在 backend 目录下）：
    python tests/test_vuln_status_notify.py

背景（用户原始诉求）：漏洞被驳回后，提单人完全不知道"为什么没了" —— 驳回应带原因通知他；
顺着这条线，把"之后需要谁动起来"的流转也一起通知了，但**刻意不发**每一小步（噪音）。

这组测试钉住四件事：
  1. 该发的动作发、不该发的（start_fix）一条都不发；
  2. 收件人口径：确认/驳回/修复完成 → 提单人；复测通过/关闭 → 提单人 + 负责人；
  3. 三类"一律不发"：操作人本人、无 open_id 的手工账号、FEISHU_NOTIFY=0；
  4. 通知失败（飞书挂了）绝不能反过来把状态流转搞失败。

测试不发真实请求：把 feishu.send_in_background（唯一发送出口）换成本地记录函数
（与 test_vuln_assign_notify.py 同一套做法）。
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

CURRENT: dict = {}
SENT: list[dict] = []


def _capture(receive_id, msg_type, content, *, tag=""):
    SENT.append({"to": receive_id, "msg_type": msg_type, "content": content, "tag": tag})


def _card_text(card) -> str:
    """把卡片里所有文案拍平成字符串，便于按关键字断言（不绑死段落结构）。"""
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
    roles = {}
    for name, code in (("超级管理员", "admin"), ("安全专家", "secops"),
                       ("研发人员", "dev"), ("测试人员", "tester")):
        r = Role(name=name, code=code)
        db.add(r)
        roles[code] = r
    db.flush()
    db.add(AssetSystem(name="VeSync APP", description="回归测试用"))
    db.add(User(username="admin", password_hash="x", full_name="管理员",
                role_id=roles["admin"].id, feishu_open_id="ou_admin"))
    # sec1 = 安全专家（多数用例里的**提单人**，有 open_id → 收得到通知）
    db.add(User(username="sec1", password_hash="x", full_name="安全小张",
                role_id=roles["secops"].id, feishu_open_id="ou_sec1"))
    # dev1 = 研发（负责人，有 open_id）
    db.add(User(username="dev1", password_hash="x", full_name="研发小王",
                role_id=roles["dev"].id, feishu_open_id="ou_dev1"))
    # manual1 = 手工账号（**没有 open_id** → 通知必须跳过而不是报错）
    db.add(User(username="manual1", password_hash="x", full_name="手工账号",
                role_id=roles["secops"].id, feishu_open_id=None))
    db.add(User(username="tester1", password_hash="x", full_name="测试小李",
                role_id=roles["tester"].id, feishu_open_id="ou_tester1"))
    db.commit()

    api = FastAPI()
    api.include_router(vulns_router.router)
    api.dependency_overrides[get_db] = lambda: db
    api.dependency_overrides[get_current_user] = lambda: CURRENT["user"]

    SENT.clear()
    feishu.notify_enabled = lambda: True
    feishu.send_in_background = _capture
    return db, TestClient(api)


def _u(db, name):
    return db.query(User).filter(User.username == name).first()


def _new_vuln(client, *, assignee_id=None) -> int:
    payload = {
        "title": "测试漏洞：流转通知",
        "severity": "high",
        "description": "回归测试用",
        "api_endpoint": "/api/test/flow-notify",
        "system_id": 1,
    }
    if assignee_id is not None:
        payload["assignee_id"] = assignee_id
    r = client.post("/api/vulns", json=payload)
    assert r.status_code in (200, 201), r.text
    return r.json()["id"]


def _action(client, vid, action, comment=None):
    body = {"comment": comment} if comment else {}
    return client.post(f"/api/vulns/{vid}/action/{action}", json=body)


def _to_retest(client, vid, *, fixer):
    """推进到「待复测」：确认 → 开始修复 → 修复完成（fixer 必须是能改状态的研发/专家）。"""
    CURRENT["user"] = fixer
    assert _action(client, vid, "confirm").status_code == 200
    assert _action(client, vid, "start_fix").status_code == 200
    assert _action(client, vid, "finish_fix", "已按修复建议修改并自测通过").status_code == 200


# ============ 驳回：提单人必须拿到原因 ============
def test_reject_notifies_reporter_with_reason():
    """驳回 → 提单人收到卡片，**原因必须在卡片里**（这是本功能存在的理由）。"""
    db, client = _setup()
    admin, sec1 = _u(db, "admin"), _u(db, "sec1")
    CURRENT["user"] = sec1                     # 提单人 = 安全专家 sec1
    vid = _new_vuln(client)
    SENT.clear()

    CURRENT["user"] = admin                    # 由管理员驳回（操作人 != 提单人）
    r = client.post(f"/api/vulns/{vid}/reject", json={"reason": "误报：该接口已有鉴权与审计"})
    assert r.status_code == 200, r.text
    assert [m["to"] for m in SENT] == ["ou_sec1"], SENT

    msg = SENT[0]
    assert msg["msg_type"] == "interactive", msg["msg_type"]
    card = msg["content"]
    assert "schema" not in card, "卡片 2.0 在本环境渲染不出来，保持 1.0"
    assert "驳回" in card["header"]["title"]["content"], card["header"]
    assert card["header"]["template"] == "red", "驳回用红色标题"
    text = _card_text(card)
    assert "误报：该接口已有鉴权与审计" in text, text      # ← 原因
    assert "已驳回" in text, text                          # 当前状态
    assert "管理员" in text, text                          # 谁驳回的
    links = _card_links(card)
    assert links and f"/vulnerabilities/fix?id={vid}" in links[0], links


def test_reject_by_reporter_himself_sends_nothing():
    """提单人自己驳回（有权限）→ 不给自己发通知。"""
    db, client = _setup()
    sec1 = _u(db, "sec1")
    CURRENT["user"] = sec1
    vid = _new_vuln(client)
    SENT.clear()

    r = client.post(f"/api/vulns/{vid}/reject", json={"reason": "自己提的误报"})
    assert r.status_code == 200, r.text
    assert SENT == [], f"操作人本人不该被通知：{SENT}"


def test_reject_notifies_once_when_reporter_is_manual_account():
    """提单人是手工账号（无 open_id）→ 跳过发送，但驳回本身必须成功。"""
    db, client = _setup()
    admin = _u(db, "admin")
    CURRENT["user"] = _u(db, "manual1")
    vid = _new_vuln(client)
    SENT.clear()

    CURRENT["user"] = admin
    r = client.post(f"/api/vulns/{vid}/reject", json={"reason": "环境问题"})
    assert r.status_code == 200, f"没有 open_id 不该影响驳回：{r.text}"
    assert SENT == [], f"无 open_id 不应调用发送：{SENT}"
    db.expire_all()
    assert db.get(Vuln, vid).status == "rejected", "驳回没生效"


# ============ 确认 / 修复完成 / 复测通过 / 关闭 ============
def test_confirm_notifies_reporter():
    """确认受理 → 提单人收到「漏洞已受理」。"""
    db, client = _setup()
    admin, sec1 = _u(db, "admin"), _u(db, "sec1")
    CURRENT["user"] = sec1
    vid = _new_vuln(client)
    SENT.clear()

    CURRENT["user"] = admin
    assert _action(client, vid, "confirm", "已复现，进入修复").status_code == 200
    assert [m["to"] for m in SENT] == ["ou_sec1"], SENT
    card = SENT[0]["content"]
    assert "已受理" in card["header"]["title"]["content"], card["header"]
    text = _card_text(card)
    assert "已复现，进入修复" in text, text      # 操作备注也要带上


def test_start_fix_sends_nothing():
    """开始修复**刻意不发**：提单人不需要知道每一小步，发了就是噪音。"""
    db, client = _setup()
    admin, sec1 = _u(db, "admin"), _u(db, "sec1")
    CURRENT["user"] = sec1
    vid = _new_vuln(client, assignee_id=_u(db, "dev1").id)
    CURRENT["user"] = admin
    assert _action(client, vid, "confirm").status_code == 200
    SENT.clear()

    assert _action(client, vid, "start_fix").status_code == 200
    assert SENT == [], f"start_fix 不该通知：{SENT}"


def test_finish_fix_notifies_reporter_only():
    """修复完成 → 提单人（去复核/复测），**不打扰负责人**（是他自己点的）。"""
    db, client = _setup()
    admin, sec1, dev1 = _u(db, "admin"), _u(db, "sec1"), _u(db, "dev1")
    CURRENT["user"] = sec1
    vid = _new_vuln(client, assignee_id=dev1.id)
    CURRENT["user"] = admin
    assert _action(client, vid, "confirm").status_code == 200
    CURRENT["user"] = dev1
    assert _action(client, vid, "start_fix").status_code == 200
    SENT.clear()

    assert _action(client, vid, "finish_fix", "已修复").status_code == 200
    assert [m["to"] for m in SENT] == ["ou_sec1"], f"应只通知提单人：{SENT}"
    card = SENT[0]["content"]
    assert "待复测" in card["header"]["title"]["content"], card["header"]
    assert "待复测" in _card_text(card), _card_text(card)      # 当前状态也跟着变


def test_pass_retest_notifies_reporter_and_assignee():
    """复测通过 → 提单人 + 负责人各 1 条（闭环）。"""
    db, client = _setup()
    admin, sec1, dev1, tester = (_u(db, "admin"), _u(db, "sec1"),
                                 _u(db, "dev1"), _u(db, "tester1"))
    CURRENT["user"] = sec1
    vid = _new_vuln(client, assignee_id=dev1.id)
    CURRENT["user"] = admin
    _to_retest(client, vid, fixer=admin)
    SENT.clear()

    CURRENT["user"] = tester
    assert _action(client, vid, "pass_retest", "复测通过").status_code == 200
    assert sorted(m["to"] for m in SENT) == ["ou_dev1", "ou_sec1"], SENT
    assert all(m["msg_type"] == "interactive" for m in SENT), SENT


def test_pass_retest_dedupes_when_reporter_is_assignee():
    """提单人 == 负责人（自己提自己修）→ 同一条消息只发一次，不重复轰炸。"""
    db, client = _setup()
    admin, sec1, tester = _u(db, "admin"), _u(db, "sec1"), _u(db, "tester1")
    CURRENT["user"] = sec1
    vid = _new_vuln(client, assignee_id=sec1.id)
    CURRENT["user"] = admin
    _to_retest(client, vid, fixer=admin)
    SENT.clear()

    CURRENT["user"] = tester
    assert _action(client, vid, "pass_retest").status_code == 200
    assert [m["to"] for m in SENT] == ["ou_sec1"], f"同一人应收 1 条：{SENT}"


def test_close_notifies_reporter_and_assignee():
    """关闭 → 提单人 + 负责人（收尾闭环）。"""
    db, client = _setup()
    admin, sec1, dev1, tester = (_u(db, "admin"), _u(db, "sec1"),
                                 _u(db, "dev1"), _u(db, "tester1"))
    CURRENT["user"] = sec1
    vid = _new_vuln(client, assignee_id=dev1.id)
    CURRENT["user"] = admin
    _to_retest(client, vid, fixer=admin)
    CURRENT["user"] = tester
    assert _action(client, vid, "pass_retest").status_code == 200
    SENT.clear()

    CURRENT["user"] = admin
    assert _action(client, vid, "close").status_code == 200
    assert sorted(m["to"] for m in SENT) == ["ou_dev1", "ou_sec1"], SENT
    assert "已关闭" in _card_text(SENT[0]["content"]), _card_text(SENT[0]["content"])


# ============ 复测不通过（打回重修） ============
def test_fail_retest_bounces_back_and_notifies_both_with_reason():
    """复测不通过 → 状态回到「修复中」，负责人 + 提单人各 1 条，**原因是独立正文块**。"""
    db, client = _setup()
    admin, sec1, dev1, tester = (_u(db, "admin"), _u(db, "sec1"),
                                 _u(db, "dev1"), _u(db, "tester1"))
    CURRENT["user"] = sec1
    vid = _new_vuln(client, assignee_id=dev1.id)
    CURRENT["user"] = admin
    _to_retest(client, vid, fixer=admin)
    SENT.clear()

    CURRENT["user"] = tester
    r = _action(client, vid, "fail_retest", "仍可越权读取他人数据")
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "fixing", f"应打回修复中：{r.json().get('status')}"
    assert sorted(m["to"] for m in SENT) == ["ou_dev1", "ou_sec1"], SENT

    card = next(m["content"] for m in SENT if m["to"] == "ou_dev1")
    assert "复测不通过" in card["header"]["title"]["content"], card["header"]
    assert card["header"]["template"] == "orange", "需要人立刻行动 → 橙色（非绿色的通过）"
    text = _card_text(card)
    assert "复测不通过原因" in text, text          # 原因块有自己的标签，不混进「备注」
    assert "仍可越权读取他人数据" in text, text
    assert "修复中" in text, text                  # 当前状态跟着变
    assert "测试小李" in text, text                # 谁判的不通过


def test_fail_retest_by_fixer_is_rejected():
    """修复人**不能自己判"没通过"** —— 那等于绕过复测环节；必须由复测方（专家/测试）判定。"""
    db, client = _setup()
    admin, dev1 = _u(db, "admin"), _u(db, "dev1")
    CURRENT["user"] = admin
    vid = _new_vuln(client, assignee_id=dev1.id)
    _to_retest(client, vid, fixer=admin)
    SENT.clear()

    CURRENT["user"] = dev1
    r = _action(client, vid, "fail_retest", "我觉得没修好")
    assert r.status_code == 403, f"研发不该能判复测不通过：{r.status_code} {r.text}"
    assert SENT == [], SENT
    db.expire_all()
    assert db.get(Vuln, vid).status == "retest", "状态不该被改动"


def test_fail_retest_by_reporter_himself_notifies_assignee_only():
    """提单人自己复测判不通过（他是安全专家）→ 只通知负责人，不给自己发。"""
    db, client = _setup()
    admin, sec1, dev1 = _u(db, "admin"), _u(db, "sec1"), _u(db, "dev1")
    CURRENT["user"] = sec1                      # 提单人 = sec1
    vid = _new_vuln(client, assignee_id=dev1.id)
    CURRENT["user"] = admin
    _to_retest(client, vid, fixer=admin)
    SENT.clear()

    CURRENT["user"] = sec1                      # 由提单人本人复测并判不通过
    assert _action(client, vid, "fail_retest", "未覆盖该分支").status_code == 200
    assert [m["to"] for m in SENT] == ["ou_dev1"], f"只该通知负责人：{SENT}"


# ============ 不该发 / 失败兜底 ============
def test_notify_disabled_by_switch():
    """FEISHU_NOTIFY=0（应急开关）→ 一条都不发，流转照样成功。"""
    db, client = _setup()
    admin, sec1 = _u(db, "admin"), _u(db, "sec1")
    feishu.notify_enabled = lambda: False
    CURRENT["user"] = sec1
    vid = _new_vuln(client)
    SENT.clear()

    CURRENT["user"] = admin
    assert client.post(f"/api/vulns/{vid}/reject", json={"reason": "x"}).status_code == 200
    assert SENT == [], SENT


def test_feishu_failure_does_not_break_transition():
    """飞书发送抛错时必须吞掉：状态、流转记录、审计日志一个都不能少。"""
    db, client = _setup()
    admin, sec1 = _u(db, "admin"), _u(db, "sec1")
    CURRENT["user"] = sec1
    vid = _new_vuln(client)
    SENT.clear()

    def _boom(receive_id, msg_type, content, *, tag=""):
        raise RuntimeError("模拟飞书 502")

    feishu.send_in_background = _boom
    CURRENT["user"] = admin
    assert client.post(f"/api/vulns/{vid}/reject", json={"reason": "误报"}).status_code == 200
    db.expire_all()
    v = db.get(Vuln, vid)
    assert v.status == "rejected", "驳回没生效"
    assert v.rejection_reason == "误报", "驳回原因没落库"
    flows = db.query(VulnFlow).filter(VulnFlow.vuln_id == vid).all()
    assert any("驳回" in (f.comment or "") for f in flows), [f.comment for f in flows]


def test_notification_link_prefers_public_base_url():
    """通知的读者是**另一个人**：配了 PUBLIC_BASE_URL 就必须用它（否则他点不开）。"""
    db, client = _setup()
    admin, sec1 = _u(db, "admin"), _u(db, "sec1")
    CURRENT["user"] = sec1
    vid = _new_vuln(client)
    SENT.clear()

    saved = os.environ.get("PUBLIC_BASE_URL")
    try:
        os.environ["PUBLIC_BASE_URL"] = "https://sdlc.vesync.cn/"     # 故意带尾斜杠
        CURRENT["user"] = admin
        assert _action(client, vid, "confirm").status_code == 200
        links = _card_links(SENT[0]["content"])
        assert links == [f"https://sdlc.vesync.cn/vulnerabilities/fix?id={vid}"], links
    finally:
        if saved is None:
            os.environ.pop("PUBLIC_BASE_URL", None)
        else:
            os.environ["PUBLIC_BASE_URL"] = saved


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
