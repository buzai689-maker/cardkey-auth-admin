import base64
import os
from pathlib import Path

os.environ["DATABASE_URL"] = "sqlite:///./data/test_apps.db"
os.environ["SECRET_KEY"] = "test-apps-key"

for s in ("", "-wal", "-shm"):
    p = Path("data/test_apps.db" + s)
    if p.exists():
        p.unlink()

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import crypto  # noqa: E402
from app.database import SessionLocal, init_db  # noqa: E402
from app.main import app, bootstrap_admin  # noqa: E402
from app.services import applications as app_svc  # noqa: E402
from app.services import settings as ss  # noqa: E402
from app.services.cards import find_or_create_time_type, generate_cards  # noqa: E402

from tests import secure_util  # noqa: E402

init_db()
bootstrap_admin()
ss.refresh_cache()
crypto.ensure_keys()
client = TestClient(app)


def _session(code, device_id, app_key=""):
    priv = X25519PrivateKey.generate()
    pub_b64 = base64.b64encode(
        priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    nonce = base64.b64encode(os.urandom(16)).decode()
    body = {"code": code, "device_id": device_id, "client_pub": pub_b64, "nonce": nonce}
    if app_key:
        body["app_key"] = app_key
    return priv, nonce, secure_util.call(client, "session", body)


def _make_card(app_id):
    db = SessionLocal()
    try:
        t = find_or_create_time_type(db, 30, False, 2)
        _, cards = generate_cards(db, t, 1, application_id=app_id, prefix="T-", length=10)
        return cards[0].code
    finally:
        db.close()


def test_per_app_payload_key_isolation():
    db = SessionLocal()
    app_a = app_svc.create_application(db, "AppA")
    app_b = app_svc.create_application(db, "AppB")
    id_a, id_b = app_a.id, app_b.id
    key_a, key_b = app_svc.payload_key_bytes(app_a), app_svc.payload_key_bytes(app_b)
    app_a_key = app_a.app_key
    db.close()

    assert key_a != key_b

    server_pub = crypto.server_public_key_b64()
    code_a, code_b = _make_card(id_a), _make_card(id_b)

    priv, nonce, resp = _session(code_a, "DEV-A")
    assert resp["success"], resp
    k_a, card = crypto.open_session_response(resp, priv, nonce, server_pub)
    assert k_a == key_a
    assert card["app"] == app_a_key

    priv, nonce, resp = _session(code_b, "DEV-B")
    k_b, _ = crypto.open_session_response(resp, priv, nonce, server_pub)
    assert k_b == key_b
    assert k_a != k_b


def test_app_key_crosscheck_rejected():
    db = SessionLocal()
    app_x = app_svc.create_application(db, "AppX")
    id_x = app_x.id
    db.close()
    code = _make_card(id_x)
    _, _, resp = _session(code, "DEV-X", app_key="not-the-right-app")
    assert resp["success"] is False
