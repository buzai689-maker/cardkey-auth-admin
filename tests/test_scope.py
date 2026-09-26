"""Operator (子账号) accounts are confined to the applications assigned to them:
card generation, card/device management, dashboard, logs and the app list all
filter by that assignment; super admins are unrestricted."""
import os
import re
from pathlib import Path

os.environ["DATABASE_URL"] = "sqlite:///./data/test_scope.db"
os.environ["SECRET_KEY"] = "test-scope-key"

for _s in ("", "-wal", "-shm"):
    _p = Path("data/test_scope.db" + _s)
    if _p.exists():
        _p.unlink()

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app import crypto  # noqa: E402
from app.database import SessionLocal, engine, init_db  # noqa: E402
from app.main import app, bootstrap_admin  # noqa: E402
from app.models import Admin, Application, AuditLog, AuthLog, Card, Device  # noqa: E402
from app.services import applications as app_svc  # noqa: E402
from app.services import settings as ss  # noqa: E402
from app.services.cards import find_or_create_time_type, generate_cards  # noqa: E402

init_db()
bootstrap_admin()
ss.refresh_cache()
crypto.ensure_keys()

OP_USER, OP_PWD = "op1", "op1-secret"


def _login(username, password):
    c = TestClient(app)
    r = c.post(
        "/admin/login",
        data={"username": username, "password": password},
        follow_redirects=False,
    )
    assert r.status_code == 303 and r.headers["location"] == "/admin", r.text
    return c


def _card(app_id, prefix):
    db = SessionLocal()
    try:
        t = find_or_create_time_type(db, 30, False, 2)
        _, cards = generate_cards(db, t, 1, application_id=app_id, prefix=prefix, length=10)
        return cards[0].id, cards[0].code
    finally:
        db.close()


def _device(card_id, device_id):
    db = SessionLocal()
    try:
        d = Device(card_id=card_id, device_id=device_id, status="active")
        db.add(d)
        db.commit()
        return d.id
    finally:
        db.close()


def _card_status(card_id):
    db = SessionLocal()
    try:
        return db.get(Card, card_id).status
    finally:
        db.close()


def _device_status(dev_id):
    db = SessionLocal()
    try:
        return db.get(Device, dev_id).status
    finally:
        db.close()


@pytest.fixture(scope="module")
def ctx():
    db = SessionLocal()
    app_a = app_svc.create_application(db, "AlphaApp")
    app_b = app_svc.create_application(db, "BetaApp")
    c = {
        "a_id": app_a.id,
        "a_key": app_a.app_key,
        "b_id": app_b.id,
        "b_key": app_b.app_key,
        "b_payload": app_b.payload_key_b64,
    }
    db.close()

    c["a_card_id"], c["a_code"] = _card(c["a_id"], "AAA-")
    c["b_card_id"], c["b_code"] = _card(c["b_id"], "BBB-")
    c["legacy_card_id"], c["legacy_code"] = _card(None, "OLD-")
    c["a_dev_id"] = _device(c["a_card_id"], "MACHINE-ALPHA")
    c["b_dev_id"] = _device(c["b_card_id"], "MACHINE-BETA")

    super_c = _login("admin", "admin888")
    # super creates the operator through the real form, granting AlphaApp only
    r = super_c.post(
        "/admin/admins/create",
        data={"username": OP_USER, "password": OP_PWD, "role": "operator", "app_ids": [c["a_id"]]},
        follow_redirects=False,
    )
    assert r.status_code == 303, r.text
    db = SessionLocal()
    op = db.query(Admin).filter_by(username=OP_USER).first()
    c["op_id"] = op.id
    assert [a.id for a in op.applications] == [c["a_id"]]
    db.close()

    c["super"] = super_c
    c["op"] = _login(OP_USER, OP_PWD)
    return c


def test_admins_page_shows_assignment(ctx):
    html = ctx["super"].get("/admin/admins").text
    assert "AlphaApp" in html
    assert f'action="/admin/admins/{ctx["op_id"]}/apps"' in html


def test_generate_page_lists_only_assigned_apps(ctx):
    html = ctx["op"].get("/admin/cards/generate").text
    assert ctx["a_key"] in html
    assert ctx["b_key"] not in html
    # super still sees every app
    html = ctx["super"].get("/admin/cards/generate").text
    assert ctx["a_key"] in html and ctx["b_key"] in html


def test_generate_for_foreign_app_is_forbidden_and_audited(ctx):
    db = SessionLocal()
    before = db.query(Card).filter_by(application_id=ctx["b_id"]).count()
    db.close()

    r = ctx["op"].post(
        "/admin/cards/generate",
        data={"application_id": ctx["b_id"], "days": 30, "max_devices": 1, "count": 3},
        follow_redirects=False,
    )
    assert r.status_code == 403
    assert "无权" in r.text  # styled 403 page, not raw JSON

    db = SessionLocal()
    assert db.query(Card).filter_by(application_id=ctx["b_id"]).count() == before
    denied = (
        db.query(AuditLog)
        .filter_by(action="access.denied", admin_id=ctx["op_id"], target=ctx["b_key"])
        .first()
    )
    assert denied is not None
    db.close()


def test_generate_for_own_app_works(ctx):
    r = ctx["op"].post(
        "/admin/cards/generate",
        data={"application_id": ctx["a_id"], "days": 7, "max_devices": 1, "count": 2, "prefix": "OPGEN-"},
        follow_redirects=False,
    )
    assert r.status_code == 303, r.text
    db = SessionLocal()
    made = db.query(Card).filter(Card.code.like("OPGEN-%")).all()
    assert len(made) == 2
    assert all(c.application_id == ctx["a_id"] and c.created_by == OP_USER for c in made)
    db.close()


def test_card_list_and_export_are_scoped(ctx):
    html = ctx["op"].get("/admin/cards").text
    assert ctx["a_code"] in html
    assert ctx["b_code"] not in html
    assert ctx["legacy_code"] not in html  # unassigned legacy cards: super only

    # explicitly asking for the other app's cards yields nothing
    html = ctx["op"].get(f"/admin/cards?application_id={ctx['b_id']}").text
    assert ctx["b_code"] not in html

    codes = ctx["op"].get("/admin/cards/export").text.split()
    assert ctx["a_code"] in codes and ctx["b_code"] not in codes and ctx["legacy_code"] not in codes

    html = ctx["super"].get("/admin/cards").text
    assert ctx["a_code"] in html and ctx["b_code"] in html and ctx["legacy_code"] in html


def test_card_detail_and_actions_are_scoped(ctx):
    op = ctx["op"]
    assert op.get(f"/admin/cards/{ctx['a_card_id']}").status_code == 200
    assert op.get(f"/admin/cards/{ctx['b_card_id']}").status_code == 403
    assert op.get(f"/admin/cards/{ctx['legacy_card_id']}").status_code == 403

    for action in ("ban", "unban", "reset", "unbind-devices", "delete"):
        r = op.post(f"/admin/cards/{ctx['b_card_id']}/{action}", follow_redirects=False)
        assert r.status_code == 403, action
    r = op.post(
        f"/admin/cards/{ctx['b_card_id']}/edit",
        data={"remark": "x", "max_devices": 5, "extend_minutes": 0},
        follow_redirects=False,
    )
    assert r.status_code == 403
    assert _card_status(ctx["b_card_id"]) == "unused"

    r = op.post(f"/admin/cards/{ctx['a_card_id']}/ban", follow_redirects=False)
    assert r.status_code == 303
    assert _card_status(ctx["a_card_id"]) == "banned"


def test_devices_are_scoped(ctx):
    op = ctx["op"]
    html = op.get("/admin/devices").text
    assert "MACHINE-ALPHA" in html
    assert "MACHINE-BETA" not in html
    # searching by the other app's card code must not leak it either
    html = op.get(f"/admin/devices?q={ctx['b_code']}").text
    assert "MACHINE-BETA" not in html

    r = op.post(f"/admin/devices/{ctx['b_dev_id']}/unbind", follow_redirects=False)
    assert r.status_code == 403
    assert _device_status(ctx["b_dev_id"]) == "active"
    r = op.post(
        f"/admin/devices/{ctx['b_dev_id']}/edit",
        data={"device_name": "hacked"},
        follow_redirects=False,
    )
    assert r.status_code == 403
    r = op.post(f"/admin/devices/{ctx['b_dev_id']}/delete", follow_redirects=False)
    assert r.status_code == 403

    r = op.post(f"/admin/devices/{ctx['a_dev_id']}/unbind", follow_redirects=False)
    assert r.status_code == 303
    assert _device_status(ctx["a_dev_id"]) == "unbound"


def test_dashboard_is_scoped(ctx):
    html = ctx["op"].get("/admin").text
    assert html.count('class="stat"') == 6
    nums = [int(n) for n in re.findall(r'<div class="n">(\d+)</div>', html)]
    db = SessionLocal()
    a_total = db.query(Card).filter_by(application_id=ctx["a_id"]).count()
    all_total = db.query(Card).count()
    db.close()
    assert nums[0] == a_total < all_total
    assert ctx["a_code"] in html
    assert ctx["b_code"] not in html

    html = ctx["super"].get("/admin").text
    nums = [int(n) for n in re.findall(r'<div class="n">(\d+)</div>', html)]
    assert nums[0] == all_total


def test_logs_are_scoped(ctx):
    db = SessionLocal()
    db.add_all(
        [
            AuthLog(code=ctx["a_code"], device_id="MACHINE-ALPHA", action="verify", success=True),
            AuthLog(code=ctx["b_code"], device_id="MACHINE-BETA", action="verify", success=True),
        ]
    )
    db.commit()
    db.close()

    html = ctx["op"].get("/admin/logs?tab=auth").text
    assert ctx["a_code"] in html and ctx["b_code"] not in html
    # audit tab: only the operator's own actions (super's admin.create is hidden)
    html = ctx["op"].get("/admin/logs?tab=audit").text
    assert "card.ban" in html and "admin.create" not in html

    html = ctx["super"].get("/admin/logs?tab=auth").text
    assert ctx["a_code"] in html and ctx["b_code"] in html
    html = ctx["super"].get("/admin/logs?tab=audit").text
    assert "admin.create" in html and "access.denied" in html


def test_applications_page_is_readonly_and_scoped_for_operators(ctx):
    op = ctx["op"]
    r = op.get("/admin/applications")
    assert r.status_code == 200
    assert ctx["a_key"] in r.text and ctx["b_key"] not in r.text
    assert "新建应用" not in r.text and "轮换密钥" not in r.text

    assert op.post("/admin/applications/create", data={"name": "Evil"}, follow_redirects=False).status_code == 403
    for action in ("toggle", "rotate-key", "delete"):
        for app_id in (ctx["a_id"], ctx["b_id"]):
            r = op.post(f"/admin/applications/{app_id}/{action}", follow_redirects=False)
            assert r.status_code == 403, (action, app_id)

    db = SessionLocal()
    assert db.get(Application, ctx["b_id"]).payload_key_b64 == ctx["b_payload"]
    assert db.query(Application).filter_by(name="Evil").count() == 0
    db.close()

    html = ctx["super"].get("/admin/applications").text
    assert "新建应用" in html and OP_USER in html  # 授权子账号 column


def test_operator_cannot_manage_admins(ctx):
    op = ctx["op"]
    assert op.get("/admin/admins").status_code == 403
    r = op.post(
        f"/admin/admins/{ctx['op_id']}/apps",
        data={"app_ids": [ctx["a_id"], ctx["b_id"]]},
        follow_redirects=False,
    )
    assert r.status_code == 403
    assert ctx["b_key"] not in op.get("/admin/cards/generate").text


def test_super_reassigns_apps_and_it_takes_effect_immediately(ctx):
    sup, op = ctx["super"], ctx["op"]
    r = sup.post(
        f"/admin/admins/{ctx['op_id']}/apps",
        data={"app_ids": [ctx["a_id"], ctx["b_id"]]},
        follow_redirects=False,
    )
    assert r.status_code == 303
    html = op.get("/admin/cards/generate").text
    assert ctx["a_key"] in html and ctx["b_key"] in html
    assert op.get(f"/admin/cards/{ctx['b_card_id']}").status_code == 200

    # revoke everything -> operator sees nothing and gets the "not assigned" hint
    r = sup.post(f"/admin/admins/{ctx['op_id']}/apps", data={}, follow_redirects=False)
    assert r.status_code == 303
    html = op.get("/admin/cards/generate").text
    assert ctx["a_key"] not in html and "尚未分配" in html
    assert op.get(f"/admin/cards/{ctx['a_card_id']}").status_code == 403
    assert ctx["a_code"] not in op.get("/admin/cards").text
    assert "MACHINE-ALPHA" not in op.get("/admin/devices").text

    # super assigning apps to a super is a no-op
    r = sup.post("/admin/admins/1/apps", data={"app_ids": [ctx["a_id"]]}, follow_redirects=False)
    assert r.status_code == 303
    with engine.connect() as conn:
        n = conn.execute(text("SELECT count(*) FROM admin_applications WHERE admin_id=1")).scalar()
    assert n == 0


def test_deleting_admin_or_app_removes_assignment_rows(ctx):
    sup = ctx["super"]
    db = SessionLocal()
    app_c = app_svc.create_application(db, "GammaApp")
    c_id = app_c.id
    db.close()
    r = sup.post(
        "/admin/admins/create",
        data={"username": "op2", "password": "pw", "role": "operator", "app_ids": [c_id]},
        follow_redirects=False,
    )
    assert r.status_code == 303
    db = SessionLocal()
    op2_id = db.query(Admin).filter_by(username="op2").first().id
    db.close()

    def rows(where):
        with engine.connect() as conn:
            return conn.execute(text(f"SELECT count(*) FROM admin_applications WHERE {where}")).scalar()

    assert rows(f"admin_id={op2_id}") == 1
    assert sup.post(f"/admin/admins/{op2_id}/delete", follow_redirects=False).status_code == 303
    assert rows(f"admin_id={op2_id}") == 0

    # and the other direction: deleting an (empty) application drops its grants
    r = sup.post(
        f"/admin/admins/{ctx['op_id']}/apps", data={"app_ids": [c_id]}, follow_redirects=False
    )
    assert r.status_code == 303
    assert rows(f"application_id={c_id}") == 1
    assert sup.post(f"/admin/applications/{c_id}/delete", follow_redirects=False).status_code == 303
    assert rows(f"application_id={c_id}") == 0
