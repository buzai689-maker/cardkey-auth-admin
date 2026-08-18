import base64
import json
import os
import time
from pathlib import Path

os.environ.setdefault("DATABASE_URL", "sqlite:///./data/test_crypto.db")
for s in ("", "-wal", "-shm"):
    p = Path("data/test_crypto.db" + s)
    if p.exists():
        p.unlink()

import pytest  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402

from app import crypto  # noqa: E402


def _client_kx():
    priv = X25519PrivateKey.generate()
    pub_b64 = base64.b64encode(
        priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    nonce_b64 = base64.b64encode(os.urandom(16)).decode()
    return priv, pub_b64, nonce_b64


def test_payload_roundtrip():
    key = os.urandom(32)
    data = b"protected core bytes " * 100
    blob = crypto.encrypt_payload(data, key)
    assert blob != data
    assert crypto.decrypt_payload(blob, key) == data


def test_session_delivers_payload_key():
    crypto.ensure_keys()
    priv, pub_b64, nonce_b64 = _client_kx()
    card = {"status": "active", "expires_at": None, "type": "30天·2设备"}
    resp = crypto.build_session_response(pub_b64, nonce_b64, card, int(time.time()))
    k, card_out = crypto.open_session_response(
        resp, priv, nonce_b64, crypto.server_public_key_b64()
    )
    assert k == crypto.payload_key()
    assert card_out["status"] == "active"


def test_tampered_body_rejected():
    priv, pub_b64, nonce_b64 = _client_kx()
    resp = crypto.build_session_response(pub_b64, nonce_b64, {"a": 1}, 0)
    bad = dict(resp)
    bad["body"] = resp["body"].replace('"a":1', '"a":2')
    with pytest.raises(Exception):
        crypto.open_session_response(bad, priv, nonce_b64, crypto.server_public_key_b64())


def test_wrong_server_pubkey_rejected():
    priv, pub_b64, nonce_b64 = _client_kx()
    resp = crypto.build_session_response(pub_b64, nonce_b64, {"a": 1}, 0)
    other = base64.b64encode(
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    with pytest.raises(Exception):
        crypto.open_session_response(resp, priv, nonce_b64, other)


def test_replayed_nonce_rejected():
    priv, pub_b64, nonce_b64 = _client_kx()
    resp = crypto.build_session_response(pub_b64, nonce_b64, {"a": 1}, 0)
    # client presents a different nonce than the one echoed/signed -> reject
    other_nonce = base64.b64encode(os.urandom(16)).decode()
    with pytest.raises(Exception):
        crypto.open_session_response(
            resp, priv, other_nonce, crypto.server_public_key_b64()
        )
