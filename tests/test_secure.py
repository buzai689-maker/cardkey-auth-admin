import base64
import json
import os
from pathlib import Path

os.environ["DATABASE_URL"] = "sqlite:///./data/test_secure.db"
os.environ["SECRET_KEY"] = "test-secure-key"

for s in ("", "-wal", "-shm"):
    p = Path("data/test_secure.db" + s)
    if p.exists():
        p.unlink()

from fastapi.testclient import TestClient  # noqa: E402

from app import crypto  # noqa: E402
from app.database import SessionLocal, init_db  # noqa: E402
from app.main import app, bootstrap_admin  # noqa: E402
from app.services import applications as app_svc  # noqa: E402
from app.services import settings as ss  # noqa: E402
from app.services.cards import find_or_create_time_type, generate_cards  # noqa: E402

init_db()
bootstrap_admin()
ss.refresh_cache()
crypto.ensure_keys()
client = TestClient(app)
ENC = crypto.server_enc_public_key_b64()
SIGN = crypto.server_public_key_b64()


def _secure(op, fields):
    inner = dict(fields)
    inner["op"] = op
    env, k = crypto.seal_request(json.dumps(inner).encode(), ENC)
    reply = client.post("/api/v1/secure", json=env).json()
    return env, k, reply


def _make_card(device_id=None):
    db = SessionLocal()
    try:
        a = app_svc.create_application(db, "SecApp")
        t = find_or_create_time_type(db, 30, False, 1)
        _, c = generate_cards(db, t, 1, application_id=a.id, prefix="S-", length=10)
        return c[0].code
    finally:
        db.close()


def test_secure_activate_roundtrip():
    code = _make_card()
    env, k, reply = _secure("activate", {"code": code, "device_id": "SEC-1"})
    assert "ct" in reply and "epk" not in reply  # sealed reply {n, ct}
    out = json.loads(crypto.open_reply(reply, k))
    assert out["success"] is True
    assert out["data"]["status"] == "active"


def test_card_code_never_in_plaintext_envelope():
    code = _make_card()
    env, _, _ = _secure("verify", {"code": code, "device_id": "SEC-2"})
    assert code not in json.dumps(env)  # code is ciphertext on the wire


def test_tampered_envelope_rejected():
    code = _make_card()
    inner = {"op": "activate", "code": code, "device_id": "SEC-3"}
    env, _ = crypto.seal_request(json.dumps(inner).encode(), ENC)
    ct = bytearray(base64.b64decode(env["ct"]))
    ct[0] ^= 0x01
    env["ct"] = base64.b64encode(bytes(ct)).decode()
    reply = client.post("/api/v1/secure", json=env).json()
    assert reply.get("error") == "bad_envelope"


def test_secure_heartbeat_is_signed_and_randomized():
    code = _make_card()
    _secure("activate", {"code": code, "device_id": "SEC-4"})
    nonce = base64.b64encode(os.urandom(16)).decode()
    _, k, reply = _secure("heartbeat", {"code": code, "device_id": "SEC-4", "nonce": nonce})
    out = json.loads(crypto.open_reply(reply, k))
    assert out["success"] is True
    obj = crypto.verify_body(out, SIGN, crypto.HEARTBEAT_AAD)  # raises if forged
    assert obj["valid"] is True
    assert obj["nonce"] == nonce
    assert 10 <= int(obj["next"]) <= 3600
