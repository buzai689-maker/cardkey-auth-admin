import os
from pathlib import Path

os.environ["DATABASE_URL"] = "sqlite:///./data/test_app.db"
os.environ["SECRET_KEY"] = "test-secret-key"

# Start each run from a clean test database.
for suffix in ("", "-wal", "-shm"):
    p = Path("data/test_app.db" + suffix)
    if p.exists():
        p.unlink()

from fastapi.testclient import TestClient  # noqa: E402

from app import crypto  # noqa: E402
from app.database import SessionLocal, init_db  # noqa: E402
from app.main import app, bootstrap_admin  # noqa: E402
from app.models import CardType  # noqa: E402
from app.services import settings as settings_svc  # noqa: E402
from app.services.cards import generate_cards  # noqa: E402

from tests import secure_util  # noqa: E402

init_db()
bootstrap_admin()
settings_svc.refresh_cache()
crypto.ensure_keys()
client = TestClient(app)


def _make_card(name="test-day", max_devices=1):
    db = SessionLocal()
    try:
        t = db.query(CardType).filter_by(name=name).first()
        if not t:
            t = CardType(
                name=name, kind="time", duration_minutes=1440, max_devices=max_devices
            )
            db.add(t)
            db.commit()
        _, cards = generate_cards(db, t, 1, prefix="T-", length=10)
        return cards[0].code
    finally:
        db.close()


def test_admin_login_and_dashboard():
    r = client.post(
        "/admin/login",
        data={"username": "admin", "password": "admin888"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    r2 = client.get("/admin")
    assert r2.status_code == 200
    assert "仪表盘" in r2.text


def test_activate_verify_and_device_limit():
    code = _make_card()
    body = secure_util.call(client, "activate", {"code": code, "device_id": "MACHINE-A"})
    assert body["success"] is True, body
    assert body["data"]["status"] == "active"

    body = secure_util.call(client, "verify", {"code": code, "device_id": "MACHINE-A"})
    assert body["success"] is True

    # max_devices == 1 -> second machine rejected
    body = secure_util.call(client, "activate", {"code": code, "device_id": "MACHINE-B"})
    assert body["success"] is False


def test_verify_rejects_unbound_device():
    code = _make_card()
    secure_util.call(client, "activate", {"code": code, "device_id": "DEV-1"})
    body = secure_util.call(client, "verify", {"code": code, "device_id": "DEV-2"})
    assert body["success"] is False


def test_activate_unknown_card():
    body = secure_util.call(client, "activate", {"code": "NOPE-XXXX", "device_id": "X"})
    assert body["success"] is False


def test_plaintext_endpoints_are_gone():
    # only /secure remains — the old plaintext routes must 404
    assert client.post("/api/v1/activate", json={"code": "x", "device_id": "y"}).status_code == 404
    assert client.post("/api/v1/verify", json={"code": "x", "device_id": "y"}).status_code == 404
    assert client.post("/api/v1/heartbeat", json={"code": "x", "device_id": "y", "nonce": "z"}).status_code == 404
