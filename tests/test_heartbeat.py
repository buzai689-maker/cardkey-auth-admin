import base64
import os
from datetime import datetime, timedelta
from pathlib import Path

os.environ["DATABASE_URL"] = "sqlite:///./data/test_hb.db"
os.environ["SECRET_KEY"] = "test-hb-key"

for s in ("", "-wal", "-shm"):
    p = Path("data/test_hb.db" + s)
    if p.exists():
        p.unlink()

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import crypto  # noqa: E402
from app.database import SessionLocal, init_db  # noqa: E402
from app.main import app, bootstrap_admin  # noqa: E402
from app.models import Card  # noqa: E402
from app.services import applications as app_svc  # noqa: E402
from app.services import settings as ss  # noqa: E402
from app.services.cards import find_or_create_time_type, generate_cards, set_status  # noqa: E402

init_db()
bootstrap_admin()
ss.refresh_cache()
crypto.ensure_keys()
client = TestClient(app)
PUB = crypto.server_public_key_b64()


def _make_active_card(device_id="HB-DEV"):
    db = SessionLocal()
    try:
        appx = app_svc.create_application(db, "HBApp")
        t = find_or_create_time_type(db, 30, False, 1)
        _, cards = generate_cards(db, t, 1, application_id=appx.id, prefix="HB-", length=10)
        code = cards[0].code
    finally:
        db.close()
    client.post("/api/v1/activate", json={"code": code, "device_id": device_id})
    return code


def _beat(code, device_id="HB-DEV"):
    nonce = base64.b64encode(os.urandom(16)).decode()
    resp = client.post(
        "/api/v1/heartbeat",
        json={"code": code, "device_id": device_id, "nonce": nonce},
    ).json()
    return nonce, resp


def test_heartbeat_valid_is_signed():
    code = _make_active_card()
    nonce, resp = _beat(code)
    assert resp["success"] is True
    obj = crypto.verify_body(resp, PUB, crypto.HEARTBEAT_AAD)  # raises if forged
    assert obj["valid"] is True
    assert obj["nonce"] == nonce
    assert obj["status"] == "active"


def test_ban_takes_effect_on_next_beat():
    code = _make_active_card()
    assert _beat(code)[1]["success"] is True
    db = SessionLocal()
    try:
        card = db.query(Card).filter_by(code=code).first()
        set_status(db, card, "banned")
    finally:
        db.close()
    # revocation bites immediately on the next heartbeat
    assert _beat(code)[1]["success"] is False


def test_expiry_takes_effect_on_next_beat():
    code = _make_active_card()
    db = SessionLocal()
    try:
        card = db.query(Card).filter_by(code=code).first()
        card.expires_at = datetime.now() - timedelta(minutes=1)
        db.commit()
    finally:
        db.close()
    assert _beat(code)[1]["success"] is False


def test_tampered_heartbeat_rejected():
    code = _make_active_card()
    _, resp = _beat(code)
    resp["body"] = resp["body"].replace('"valid":true', '"valid":true ')  # mutate
    with pytest.raises(Exception):
        crypto.verify_body(resp, PUB, crypto.HEARTBEAT_AAD)
