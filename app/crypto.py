"""Authenticated key-exchange + payload protection for the client SDK.

Wire goal: deliver the payload key K_payload to the client ONLY after a valid
card + bound device, in a way that survives the client controlling the network
and the TLS layer (self-installed CA / mitmproxy). Achieved with an app-layer
handshake:

  client --(X25519 client_pub, nonce, code, device_id)--> server
  server: ECDH(server_eph, client_pub) -> HKDF -> session_key
          wrap K_payload under session_key (AES-GCM)
          sign the whole response body with the server's static Ed25519 key
  client: verify Ed25519 sig (pinned pub) -> ECDH -> session_key -> unwrap K_payload

Patching the client's "success" branch yields nothing: K_payload is not in the
binary, and the signature/ECDH cannot be forged without the server keys.
"""
from __future__ import annotations

import base64
import json
import os
import struct
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from .config import BASE_DIR

KEYS_DIR = BASE_DIR / "data" / "keys"
SESSION_INFO = b"kmauth-session-v1"
SESSION_AAD = b"kmauth-session-v1"
PAYLOAD_AAD = b"kmauth-payload-v1"
PAYLOAD_MAGIC = b"KMENC1\x00"


# --------------------------------------------------------------------------- #
# base64 / framing helpers (client re-implements these in its own language)    #
# --------------------------------------------------------------------------- #
def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64d(text: str) -> bytes:
    return base64.b64decode(text)


def frame(*chunks) -> bytes:
    """Length-prefixed concatenation so a signed transcript is unambiguous."""
    out = bytearray()
    for c in chunks:
        if isinstance(c, str):
            c = c.encode()
        out += struct.pack(">I", len(c)) + c
    return bytes(out)


def _hkdf(shared: bytes, salt: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt, info=SESSION_INFO
    ).derive(shared)


def _raw_pub(pub) -> bytes:
    return pub.public_bytes(Encoding.Raw, PublicFormat.Raw)


# --------------------------------------------------------------------------- #
# server key material (generated on first use, kept under data/keys)           #
# --------------------------------------------------------------------------- #
def ensure_keys() -> None:
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    ed = KEYS_DIR / "ed25519_priv.key"
    if not ed.exists():
        k = Ed25519PrivateKey.generate()
        ed.write_bytes(
            k.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        )
    pk = KEYS_DIR / "payload.key"
    if not pk.exists():
        pk.write_bytes(os.urandom(32))
    for p in (ed, pk):
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass


def server_signing_key() -> Ed25519PrivateKey:
    ensure_keys()
    return Ed25519PrivateKey.from_private_bytes(
        (KEYS_DIR / "ed25519_priv.key").read_bytes()
    )


def server_public_key_b64() -> str:
    return b64e(_raw_pub(server_signing_key().public_key()))


def payload_key() -> bytes:
    ensure_keys()
    return (KEYS_DIR / "payload.key").read_bytes()


# --------------------------------------------------------------------------- #
# server: build a signed session response that delivers K_payload              #
# --------------------------------------------------------------------------- #
def build_session_response(
    client_pub_b64: str,
    client_nonce_b64: str,
    card_data: dict,
    ts: int,
    key: bytes | None = None,
) -> dict:
    """`key` is the per-application K_payload to deliver; falls back to the
    global payload key for legacy single-app cards."""
    client_pub_raw = b64d(client_pub_b64)
    client_pub = X25519PublicKey.from_public_bytes(client_pub_raw)

    server_eph = X25519PrivateKey.generate()
    shared = server_eph.exchange(client_pub)

    cn = b64d(client_nonce_b64)
    sn = os.urandom(16)
    session_key = _hkdf(shared, salt=cn + sn)

    k_payload = key if key is not None else payload_key()
    gcm_nonce = os.urandom(12)
    wrapped = AESGCM(session_key).encrypt(gcm_nonce, k_payload, SESSION_AAD)

    body_obj = {
        "v": 1,
        "ts": ts,
        "client_nonce": client_nonce_b64,
        "server_pub": b64e(_raw_pub(server_eph.public_key())),
        "server_nonce": b64e(sn),
        "gcm_nonce": b64e(gcm_nonce),
        "wrapped_key": b64e(wrapped),
        "card": card_data,
    }
    body = json.dumps(body_obj, sort_keys=True, separators=(",", ":"))
    transcript = frame(SESSION_AAD, client_pub_raw, cn, body.encode())
    sig = server_signing_key().sign(transcript)
    return {"body": body, "sig": b64e(sig)}


# --------------------------------------------------------------------------- #
# client: verify signature, run ECDH, unwrap K_payload                         #
# --------------------------------------------------------------------------- #
def open_session_response(
    resp: dict,
    client_priv: X25519PrivateKey,
    client_nonce_b64: str,
    server_static_pub_b64: str,
) -> tuple[bytes, dict]:
    body = resp["body"]
    sig = b64d(resp["sig"])
    client_pub_raw = _raw_pub(client_priv.public_key())
    cn = b64d(client_nonce_b64)

    transcript = frame(SESSION_AAD, client_pub_raw, cn, body.encode())
    # raises InvalidSignature if forged / tampered
    Ed25519PublicKey.from_public_bytes(b64d(server_static_pub_b64)).verify(
        sig, transcript
    )

    obj = json.loads(body)
    if obj.get("client_nonce") != client_nonce_b64:
        raise ValueError("nonce mismatch (possible replay)")

    server_eph_pub = X25519PublicKey.from_public_bytes(b64d(obj["server_pub"]))
    shared = client_priv.exchange(server_eph_pub)
    sn = b64d(obj["server_nonce"])
    session_key = _hkdf(shared, salt=cn + sn)

    k_payload = AESGCM(session_key).decrypt(
        b64d(obj["gcm_nonce"]), b64d(obj["wrapped_key"]), SESSION_AAD
    )
    return k_payload, obj["card"]


# --------------------------------------------------------------------------- #
# payload container: encrypt the protected core with K_payload                 #
# --------------------------------------------------------------------------- #
def encrypt_payload(data: bytes, key: bytes) -> bytes:
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, data, PAYLOAD_AAD)
    return PAYLOAD_MAGIC + nonce + ct


def decrypt_payload(blob: bytes, key: bytes) -> bytes:
    if not blob.startswith(PAYLOAD_MAGIC):
        raise ValueError("bad payload container magic")
    body = blob[len(PAYLOAD_MAGIC):]
    nonce, ct = body[:12], body[12:]
    return AESGCM(key).decrypt(nonce, ct, PAYLOAD_AAD)
