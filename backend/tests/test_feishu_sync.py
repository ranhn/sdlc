"""飞书同步 · 部门树落库与人员部门归属 回归测试。

用法（在 backend 目录下）：
    python -m pytest tests/test_feishu_sync.py -v
    python tests/test_feishu_sync.py          # 无 pytest 时直接跑

为什么要有它（这几条都是"联调时才发现、且现象很隐蔽"的坑）：
  1. `/contact/v3/users` 只返回部门的**直属成员** —— 不递归遍历部门树，就会漏掉
     全部子部门同事，现象是"同步成功、但人数明显偏少"，光看结果数字很难定位；
  2. 部门落库必须**认领** seed 出来的同名部门（`sys_department.name` 是唯一约束），
     否则要么插重复部门，要么直接抛 IntegrityError 让整次同步失败；
  3. 不同分支的同名部门（两个"研发部"）不能挤进同一条本地记录，否则会互相覆盖
     `feishu_open_dept_id`，第二天同步又把人员归属改错；
  4. 人员部门归属的优先级必须是：人工映射（FEISHU_DEPT_MAP_JSON）> 飞书自动映射
     > 默认部门 —— 人工映射是运维用来"纠偏"的，不能被自动映射顶掉。
"""

from __future__ import annotations

import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app.database import Base  # noqa: E402
from app.models import Department, Role, User  # noqa: E402
from app.routers import feishu  # noqa: E402


# ============ 飞书返回的假数据（三层部门树） ============
#
#   研发中心(od-rnd)
#     ├─ 后端组(od-be)
#     │    └─ 支付小组(od-pay)     ← 第三层，只取一级部门就会漏掉它的人
#     └─ 前端组(od-fe)
#   安全部(od-sec)                  ← 与 seed 部门同名，必须认领
#
_CHILDREN = {
    "0": [
        {"open_department_id": "od-rnd", "name": "研发中心"},
        {"open_department_id": "od-sec", "name": "安全部"},
    ],
    "od-rnd": [
        {"open_department_id": "od-be", "name": "后端组"},
        {"open_department_id": "od-fe", "name": "前端组"},
    ],
    "od-be": [{"open_department_id": "od-pay", "name": "支付小组"}],
    "od-pay": [],
    "od-fe": [],
    "od-sec": [],
}

_USERS = {
    "od-rnd": [{"open_id": "ou_rnd_1", "name": "研发老大", "department_ids": ["od-rnd"]}],
    "od-be": [
        {"open_id": "ou_be_1", "name": "后端甲", "department_ids": ["od-be"]},
        {"open_id": "ou_be_2", "name": "后端乙", "department_ids": ["od-be", "od-rnd"]},
    ],
    "od-pay": [{"open_id": "ou_pay_1", "name": "支付丙", "department_ids": ["od-pay"]}],
    "od-fe": [{"open_id": "ou_fe_1", "name": "前端丁", "department_ids": ["od-fe"]}],
    "od-sec": [{"open_id": "ou_sec_1", "name": "安全戊", "department_ids": ["od-sec"]}],
}


def _fake_list_sub_depts(token: str, parent_id: str, page_size: int = 50):
    return _CHILDREN.get(parent_id, [])


async def _fake_list_sub_depts_async(token: str, parent_id: str, page_size: int = 50):
    return _fake_list_sub_depts(token, parent_id)


def _make_db():
    """内存库 + 建表，模拟现网"已有 seed 部门"的起点。"""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    # seed 出来的部门（没有飞书 id）——同名认领逻辑要认的就是它们
    db.add_all([Department(name="研发部"), Department(name="安全部"), Department(name="测试部")])
    db.commit()
    return db


# ============ 用例 ============

def test_collect_dept_tree_covers_all_levels():
    """三层部门树必须全部收集到，且父链正确（漏一层就漏一批人）。"""
    feishu._list_feishu_sub_depts = _fake_list_sub_depts_async
    tree = asyncio.run(feishu._collect_feishu_dept_tree("token"))
    ids = [n["open_department_id"] for n in tree]
    assert ids == ["od-rnd", "od-sec", "od-be", "od-fe", "od-pay"], ids

    by_id = {n["open_department_id"]: n for n in tree}
    assert by_id["od-pay"]["parent_open_id"] == "od-be"
    assert by_id["od-pay"]["level"] == 3
    assert by_id["od-rnd"]["parent_open_id"] is None

    # 目标部门 = 树里所有部门 → 每个部门都拉到人，去重后 6 人（含子部门的 3 人）
    fetched = {}
    for node in tree:
        for u in _USERS.get(node["open_department_id"], []):
            fetched[u["open_id"]] = u
    assert len(fetched) == 6, fetched


def test_upsert_reuses_seeded_department_by_name():
    """同名部门要认领（补飞书 id），不能新建重复记录，也不能撞唯一约束。"""
    db = _make_db()
    tree = [
        {"open_department_id": "od-sec", "name": "安全部", "parent_open_id": None, "level": 1},
        {"open_department_id": "od-new", "name": "数据平台部", "parent_open_id": None, "level": 1},
    ]
    res = feishu._upsert_departments(db, tree)
    db.commit()

    assert res["created"] == 1 and res["matched"] == 1, res
    sec = db.query(Department).filter(Department.name == "安全部").all()
    assert len(sec) == 1, "同名部门被插成了两条"
    assert sec[0].feishu_open_dept_id == "od-sec"
    assert res["mapping"]["od-new"] == db.query(Department).filter(
        Department.name == "数据平台部"
    ).first().id
    # 认领后本地部门总数 = 原 3 个 + 新建 1 个
    assert db.query(Department).count() == 4


def test_upsert_links_parent_and_is_idempotent():
    """父子关系要回填；同输入再跑一次不能产生新部门（幂等）。"""
    db = _make_db()
    tree = [
        {"open_department_id": "od-rnd", "name": "研发中心", "parent_open_id": None, "level": 1},
        {"open_department_id": "od-be", "name": "后端组", "parent_open_id": "od-rnd", "level": 2},
    ]
    first = feishu._upsert_departments(db, tree)
    db.commit()
    be = db.get(Department, first["mapping"]["od-be"])
    assert be.parent_id == first["mapping"]["od-rnd"]

    second = feishu._upsert_departments(db, tree)
    db.commit()
    assert second["created"] == 0, "第二次同步又建了部门（不幂等）"
    assert db.query(Department).count() == 5  # 3 seed + 2


def test_same_name_different_feishu_dept_does_not_collide():
    """不同分支的同名部门：各自独立成行，不能互相覆盖 feishu_open_dept_id。"""
    db = _make_db()
    tree = [
        {"open_department_id": "od-d1", "name": "研发中心", "parent_open_id": None, "level": 1},
        {"open_department_id": "od-d2", "name": "研发中心", "parent_open_id": None, "level": 1},
    ]
    res = feishu._upsert_departments(db, tree)
    db.commit()

    assert res["mapping"]["od-d1"] != res["mapping"]["od-d2"], res
    a = db.get(Department, res["mapping"]["od-d1"])
    b = db.get(Department, res["mapping"]["od-d2"])
    assert {a.feishu_open_dept_id, b.feishu_open_dept_id} == {"od-d1", "od-d2"}
    assert a.name == "研发中心" and b.name != "研发中心"  # 后者用后缀避让唯一约束


def test_split_name_handles_all_three_shapes():
    """飞书 name 把中英文拼在一起，且 en_name 字段为空 —— 三种形态都要拆对。"""
    assert feishu._split_name("Tracy.Yang 杨翠") == ("Tracy.Yang", "杨翠")
    assert feishu._split_name("John Villanueva") == ("John Villanueva", "")   # 纯英文名
    assert feishu._split_name("梁俊") == ("", "梁俊")                          # 纯中文名
    assert feishu._split_name("Tracy(杨翠)") == ("Tracy", "杨翠")             # 括号包中文
    assert feishu._split_name("") == ("", "")


def test_normalize_dept_map_collapses_to_target_level():
    """部门归一到指定层级：深层归到第 2 级，不到 2 级的保留自己（不凭空造上级）。"""
    tree = [
        {"open_department_id": "od-l1", "name": "一级部", "parent_open_id": None, "level": 1},
        {"open_department_id": "od-l2a", "name": "二级A", "parent_open_id": "od-l1", "level": 2},
        {"open_department_id": "od-l3a", "name": "三级A", "parent_open_id": "od-l2a", "level": 3},
        {"open_department_id": "od-l3b", "name": "三级B", "parent_open_id": "od-l2a", "level": 3},
        {"open_department_id": "od-l4", "name": "四级C", "parent_open_id": "od-l3b", "level": 4},
        {"open_department_id": "od-l2b", "name": "二级B", "parent_open_id": "od-l1", "level": 2},
    ]
    keep, mapping = feishu._normalize_dept_map(tree, 2)
    # 三级/四级都被归到二级；一级部**要保留** —— 层级不足二级的人（真实数据里有 29 人）
    # 必须有个归属，否则他们会掉进"默认部门"，口径又乱了
    assert set(keep) == {"od-l1", "od-l2a", "od-l2b"}, keep
    assert mapping["od-l1"] == "od-l1"
    assert mapping["od-l3a"] == "od-l2a"
    assert mapping["od-l3b"] == "od-l2a"
    assert mapping["od-l4"] == "od-l2a"                 # 第四层也归到二级
    assert [d["name"] for d in keep.values()] == ["一级部", "二级A", "二级B"]   # 顺序确定
    assert all(d["parent_open_id"] is None for d in keep.values())   # 归一后不再保留上层


def test_derive_username_uses_english_name_then_falls_back():
    """用户名 = 英文名；重名（大小写不敏感）加序号；没英文名退回邮箱前缀 / fs_ 兜底。"""
    taken = {"tracy.yang"}          # 登录接口对用户名是不区分大小写的，所以 Bob 与 bob 视为同名
    assert feishu._derive_username("Tracy.Yang", None, "ou_1", taken) == "Tracy.Yang2"
    assert feishu._derive_username("John Villanueva", None, "ou_2", taken) == "JohnVillanueva"
    assert feishu._derive_username("", "li.hua@x.com", "ou_3", taken) == "li.hua"
    assert feishu._derive_username("", None, "ou_abcdefgh", taken) == "fs_abcdefgh"
    # 连续重名继续加序号，且都写进 taken（同一次同步里不会互相撞）
    assert feishu._derive_username("Tracy.Yang", None, "ou_4", taken) == "Tracy.Yang3"


def test_sync_renames_auto_username_to_english_name():
    """上次同步生成的 fs_xxx 用户名 → 本次改成英文名（账号没登录过才改）。"""
    db = _make_db()
    admin = _wire_sync(db, {"od-sec": [{"open_id": "ou_tracy", "name": "Tracy.Yang 杨翠"}]})
    role = db.query(Role).first()
    db.add(User(username="fs_ou_tracy", password_hash="x", full_name="杨翠", role_id=role.id,
                feishu_open_id="ou_tracy", is_active=True, must_change_password=True))
    db.commit()

    res = asyncio.run(feishu.sync_users(db=db, current=admin))
    assert res.renamed == 1, res
    u = db.query(User).filter(User.feishu_open_id == "ou_tracy").first()
    assert u.username == "Tracy.Yang", u.username


def test_sync_does_not_rename_account_that_has_logged_in():
    """已登录过（改过密码）的账号不改名 —— 否则可能把人锁在外面。"""
    db = _make_db()
    admin = _wire_sync(db, {"od-sec": [{"open_id": "ou_tracy", "name": "Tracy.Yang 杨翠"}]})
    role = db.query(Role).first()
    db.add(User(username="fs_ou_tracy", password_hash="x", full_name="杨翠", role_id=role.id,
                feishu_open_id="ou_tracy", is_active=True, must_change_password=False))
    db.commit()

    res = asyncio.run(feishu.sync_users(db=db, current=admin))
    assert res.renamed == 0, res
    assert db.query(User).filter(User.feishu_open_id == "ou_tracy").first().username == "fs_ou_tracy"


def test_sync_merges_manual_account_with_feishu_user():
    """同一个人两条记录（手工建的 + 飞书同步的）：保留手工账号，飞书那条软删除。

    真实场景：冉海南/胡汉文/许智双/江晓蕾 4 个人既有手工账号、又被飞书同步进来一份。
    """
    db = _make_db()
    admin = _wire_sync(db, {"od-sec": [{"open_id": "ou_ran", "name": "Ning.Ran 冉海南"}]})
    role = db.query(Role).first()
    manual = User(username="Ning.Ran", password_hash="x", full_name="冉海南", role_id=role.id,
                  is_active=True)                       # 手工账号：无 feishu_open_id
    dup = User(username="fs_ou_ran", password_hash="x", full_name="冉海南", role_id=role.id,
               feishu_open_id="ou_ran", is_active=True, must_change_password=True)
    db.add_all([manual, dup])
    db.commit()
    manual_id = manual.id

    res = asyncio.run(feishu.sync_users(db=db, current=admin))
    db.expire_all()
    manual = db.get(User, manual_id)
    dup = db.query(User).filter(User.username == "fs_ou_ran").first()

    assert res.merged == 1 and res.created == 0, res
    assert manual.feishu_open_id == "ou_ran", "手工账号没挂上飞书标识"
    assert manual.username == "Ning.Ran", "手工账号的用户名被改掉了"
    assert manual.must_change_password is False, "不该给已有账号加'首次登录改密'"
    assert dup.is_deleted is True, "飞书那条重复记录没软删除"


def test_sync_does_not_merge_when_name_is_ambiguous():
    """同名多人时绝不自动合并（宁可不并，也不能把两个人的账号/漏洞数据混在一起）。"""
    db = _make_db()
    admin = _wire_sync(db, {"od-sec": [
        {"open_id": "ou_a", "name": "Zhang.San 张三"},
        {"open_id": "ou_b", "name": "Zhang.San 张三"},
    ]})
    role = db.query(Role).first()
    db.add(User(username="zhangsan", password_hash="x", full_name="张三", role_id=role.id,
                is_active=True))
    db.commit()

    res = asyncio.run(feishu.sync_users(db=db, current=admin))
    assert res.merged == 0, res
    assert db.query(User).filter(User.username == "zhangsan").first().feishu_open_id is None


def test_pick_dept_priority():
    """归属优先级：人工映射 > 飞书自动映射 > 默认部门。"""
    manual = {"od-be": 7}
    auto = {"od-be": 8, "od-rnd": 9}
    # 人工映射优先（运维纠偏不能被自动映射顶掉）
    assert feishu._pick_dept_id(["od-be", "od-rnd"], manual, auto, 1) == 7
    # 人工没配 → 用飞书树落库的结果，且按 department_ids 顺序取第一个命中的
    assert feishu._pick_dept_id(["od-unknown", "od-rnd"], {}, auto, 1) == 9
    # 都匹配不上 → 默认部门
    assert feishu._pick_dept_id(["od-unknown"], {}, auto, 1) == 1
    assert feishu._pick_dept_id([], {}, auto, 1) == 1
    # 人工映射写了脏值（非数字）时不抛异常，跳过它继续用飞书自动映射
    assert feishu._pick_dept_id(["od-be"], {"od-be": "x"}, auto, 1) == 8
    # 人工映射写了空串同理
    assert feishu._pick_dept_id(["od-be"], {"od-be": ""}, auto, 1) == 8


# ============ 端到端：真实 sync_users 循环 ============

def _make_admin(db):
    role = Role(name="超级管理员", code="admin")
    db.add(role)
    db.flush()
    admin = User(username="admin", password_hash="x", full_name="管理员", role_id=role.id)
    db.add(admin)
    db.commit()
    return admin


def _wire_sync(db, dept_users: dict, tree: list | None = None):
    """把 sync_users 依赖的网络调用换成假数据（不碰真实飞书）。"""
    os.environ["FEISHU_APP_ID"] = "cli_test"
    os.environ["FEISHU_APP_SECRET"] = "secret_test"
    os.environ["FEISHU_DEFAULT_DEPT_ID"] = ""
    os.environ["FEISHU_DEPT_MAP_JSON"] = ""
    os.environ.pop("FEISHU_DEPT_LEVEL", None)

    async def fake_token(app_id, app_secret):
        return "t-test"

    async def fake_tree(token):
        return tree if tree is not None else [
            {"open_department_id": "od-rnd", "name": "研发中心", "parent_open_id": None, "level": 1},
            {"open_department_id": "od-sec", "name": "安全部", "parent_open_id": None, "level": 1},
        ]

    async def fake_users(token, dept_id, page_size=50):
        return dept_users.get(dept_id, [])

    feishu._get_tenant_token = fake_token
    feishu._collect_feishu_dept_tree = fake_tree
    feishu._list_feishu_dept_users = fake_users
    return _make_admin(db)


def _dept_name(db, open_id):
    u = db.query(User).filter(User.feishu_open_id == open_id).first()
    return db.get(Department, u.department_id).name if u and u.department_id else None


def test_sync_lands_users_in_their_departments_without_department_ids():
    """实测坑：部门直属用户列表**不返回** department_ids —— 人必须落到正确部门。

    真实返回里没有 department_ids 字段，如果只认这个字段再回退"默认部门"，
    整批人会全挤进默认部门（本用例里默认部门是 seed 的「研发部」），部门树同步等于白做。
    """
    db = _make_db()
    admin = _wire_sync(db, {
        "od-rnd": [{"open_id": "ou_1", "name": "研发甲", "email": "a@x.com"}],
        "od-sec": [{"open_id": "ou_2", "name": "安全乙", "email": "b@x.com"}],
    })
    res = asyncio.run(feishu.sync_users(db=db, current=admin))

    assert res.total == 2 and res.created == 2, res
    assert res.dept_total == 2 and res.dept_created == 1, res   # 研发中心新建、安全部认领 seed
    assert _dept_name(db, "ou_1") == "研发中心", _dept_name(db, "ou_1")
    assert _dept_name(db, "ou_2") == "安全部", f"{_dept_name(db, 'ou_2')}（落到默认部门了？）"
    # 姓名/邮箱/工号落库
    u1 = db.query(User).filter(User.feishu_open_id == "ou_1").first()
    assert u1.full_name == "研发甲" and u1.email == "a@x.com"


def test_sync_dedups_user_across_departments_and_is_idempotent():
    """同一人挂多个部门：只同步一条，且按 BFS 顺序取第一个部门；重复同步不产生新数据。"""
    db = _make_db()
    admin = _wire_sync(db, {
        "od-rnd": [{"open_id": "ou_9", "name": "跨部门丙"}],
        "od-sec": [{"open_id": "ou_9", "name": "跨部门丙"}],
    })
    first = asyncio.run(feishu.sync_users(db=db, current=admin))
    assert first.total == 1 and first.created == 1, first
    assert _dept_name(db, "ou_9") == "研发中心", _dept_name(db, "ou_9")

    second = asyncio.run(feishu.sync_users(db=db, current=admin))
    assert second.total == 1 and second.created == 0 and second.updated == 1, second
    assert second.dept_created == 0, "第二次同步又建了部门（不幂等）"
    assert db.query(User).filter(User.feishu_open_id == "ou_9").count() == 1


def test_sync_picks_most_specific_department_for_multi_dept_user():
    """同属多个部门：只同步一条，部门取"归一后最具体"的那个（而不是先遍历到的）。

    真实场景：有人既挂在一级部门、又挂在某个二级部门下 —— 应该展示更具体的那个，
    否则他的部门会显示成一级部门，跟同事不在同一个分组里。
    """
    tree = [
        {"open_department_id": "od-rnd", "name": "研发中心", "parent_open_id": None, "level": 1},
        {"open_department_id": "od-be", "name": "后端组", "parent_open_id": "od-rnd", "level": 2},
    ]
    db = _make_db()
    admin = _wire_sync(db, {
        "od-rnd": [{"open_id": "ou_m", "name": "张三"}],     # 一级部门也挂了他
        "od-be": [{"open_id": "ou_m", "name": "张三"}],      # 二级部门才是"主部门"
    }, tree=tree)

    res = asyncio.run(feishu.sync_users(db=db, current=admin))
    assert res.total == 1 and res.created == 1, res
    assert db.query(User).filter(User.feishu_open_id == "ou_m").count() == 1, "同一个人被导入了两条"
    assert _dept_name(db, "ou_m") == "后端组", f"归到了 {_dept_name(db, 'ou_m')}"


def test_sync_reuses_seeded_employee_role_instead_of_crashing():
    """真实库踩到的坑：seed 的「普通权限」code 是 user，而兜底创建用 employee。

    只按 code=employee 查会查不到 → 再插一条同名角色 → 撞 sys_role.name
    唯一约束 → 整次同步 500（表现就是"点了同步没反应"）。
    """
    db = _make_db()
    db.add(Role(name="普通权限", code="user", description="seed 角色"))
    db.commit()
    admin = _wire_sync(db, {"od-sec": [{"open_id": "ou_a", "name": "张三"}]})

    res = asyncio.run(feishu.sync_users(db=db, current=admin))
    assert res.created == 1 and res.failed == 0, res
    u = db.query(User).filter(User.feishu_open_id == "ou_a").first()
    assert db.get(Role, u.role_id).code == "user", "没有复用现成的普通权限角色"
    assert db.query(Role).filter(Role.code == "employee").count() == 0, "多插了一条角色"


def test_sync_matches_default_role_by_name_across_rename():
    """默认角色按名字兜底时，改名前后的两种名字都要认。

    背景：user 角色的显示名 2026-09 从「普通员工」改成「普通权限」（code 不变）。
    兜底链路是 code(user/employee) → 名字 → 新建；若老库里默认角色的 code 两者都不是，
    就只能靠名字匹配 —— 这时只认新名会让老库匹配失败，进而新建同名角色撞唯一约束、
    整次同步 500。所以名字匹配要同时认新旧两种。
    """
    db = _make_db()
    db.add(Role(name="普通员工", code="staff", description="旧名 + 非标准 code"))
    db.commit()
    admin = _wire_sync(db, {"od-sec": [{"open_id": "ou_old", "name": "旧名用户"}]})

    res = asyncio.run(feishu.sync_users(db=db, current=admin))
    assert res.created == 1 and res.failed == 0, res
    u = db.query(User).filter(User.feishu_open_id == "ou_old").first()
    assert db.get(Role, u.role_id).name == "普通员工", "没按（旧的）名称匹配到默认角色"
    assert db.query(Role).filter(Role.code == "employee").count() == 0, "又新建了一条角色"


def test_sync_deactivates_users_missing_from_feishu():
    """状态靠"本轮还在不在"推导：飞书里没了 → 停用本地账号（离职/移出部门）。"""
    db = _make_db()
    admin = _wire_sync(db, {"od-sec": [{"open_id": "ou_keep", "name": "张留 张留"}]})
    role = db.query(Role).first()
    db.add_all([
        User(username="fs_keep", password_hash="x", full_name="张留", role_id=role.id,
             feishu_open_id="ou_keep", is_active=True),
        User(username="fs_gone", password_hash="x", full_name="已离职", role_id=role.id,
             feishu_open_id="ou_gone", is_active=True),
    ])
    db.commit()

    res = asyncio.run(feishu.sync_users(db=db, current=admin))
    assert res.deactivated == 1, res
    assert db.query(User).filter(User.username == "fs_gone").first().is_active is False
    assert db.query(User).filter(User.username == "fs_keep").first().is_active is True


def test_sync_skips_deactivation_when_fetch_looks_truncated():
    """安全阀：库内有 3 个飞书账号、本轮只拉到 1 个 → 疑似范围被收窄，不执行停用。"""
    db = _make_db()
    admin = _wire_sync(db, {"od-sec": [{"open_id": "ou_1", "name": "只拉到一个"}]})
    role = db.query(Role).first()
    db.add_all([
        User(username="fs_x", password_hash="x", full_name="甲", role_id=role.id,
             feishu_open_id="ou_1", is_active=True),
        User(username="fs_y", password_hash="x", full_name="乙", role_id=role.id,
             feishu_open_id="ou_2", is_active=True),
        User(username="fs_z", password_hash="x", full_name="丙", role_id=role.id,
             feishu_open_id="ou_3", is_active=True),
    ])
    db.commit()

    res = asyncio.run(feishu.sync_users(db=db, current=admin))
    assert res.deactivated == 0, res
    assert db.query(User).filter(User.username == "fs_y").first().is_active is True
    assert any("skipped_deactivate" in d for d in res.details), res.details


# ============ 运行器 ============

def _main():
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
