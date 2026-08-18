"""Reference client for the card-key network authorization.

Flow per launch:
  1. compute a stable machine code (device_id) from hardware
  2. X25519 ephemeral keypair + nonce
  3. POST /api/v1/session {code, device_id, client_pub, nonce}
  4. verify the server's Ed25519 signature (pinned public key)
  5. ECDH -> session key -> unwrap K_payload
  6. decrypt the shipped core.enc in memory with K_payload and run it

The crypto is language-agnostic (see README "客户端协议"); a real C/C++/C#/Delphi
client reimplements steps 2-6. This Python version reuses app.crypto for brevity.

    python -m examples.client --code DAY-XXXX-XXXX-XXXX
    python -m examples.client --code DAY-... --server http://127.0.0.1:8000 --core examples/core.enc
"""
import argparse
import base64
import hashlib
import json
import os
import platform
import subprocess
import urllib.request
import uuid

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app import crypto

# Pin the server key here in production (paste the /api/v1/pubkey value). When
# empty this demo fetches it once over the wire — which a MITM could swap, so a
# shipped client MUST hardcode it.
PINNED_SERVER_PUB = ""


def machine_code() -> str:
    """Stable hardware fingerprint. Windows: MachineGuid + CPU id + MAC."""
    parts: list[str] = []
    try:
        import winreg

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography"
        ) as k:
            parts.append(winreg.QueryValueEx(k, "MachineGuid")[0])
    except Exception:
        pass
    if platform.system() == "Windows":
        try:
            out = subprocess.run(
                ["wmic", "cpu", "get", "ProcessorId"],
                capture_output=True, text=True, timeout=5,
            ).stdout
            rows = [r.strip() for r in out.splitlines() if r.strip()]
            if len(rows) >= 2:
                parts.append(rows[1])
        except Exception:
            pass
    parts.append(str(uuid.getnode()))  # MAC-derived
    raw = "|".join(p for p in parts if p) or platform.platform()
    return hashlib.sha256(raw.encode()).hexdigest()[:32].upper()


def _post(url: str, obj: dict) -> dict:
    data = json.dumps(obj).encode()
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode())


def _get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=10) as r:
        return json.loads(r.read().decode())


def run(code: str, server: str, core_path: str, app_key: str = "") -> int:
    server = server.rstrip("/")
    device_id = machine_code()
    print(f"[*] device_id = {device_id}")

    server_pub = PINNED_SERVER_PUB or _get(f"{server}/api/v1/pubkey")["public_key"]

    client_priv = X25519PrivateKey.generate()
    client_pub_b64 = base64.b64encode(
        client_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    nonce_b64 = base64.b64encode(os.urandom(16)).decode()

    req = {
        "code": code,
        "device_id": device_id,
        "client_pub": client_pub_b64,
        "nonce": nonce_b64,
    }
    if app_key:
        req["app_key"] = app_key  # optional: server rejects if card belongs elsewhere
    resp = _post(f"{server}/api/v1/session", req)
    if not resp.get("success"):
        print(f"[!] authorization failed: {resp.get('message')}")
        return 1

    try:
        k_payload, card = crypto.open_session_response(
            resp, client_priv, nonce_b64, server_pub
        )
    except Exception as e:  # InvalidSignature / nonce mismatch / decrypt error
        print(f"[!] handshake verification failed: {e!r}")
        return 1

    print(f"[+] authorized: {json.dumps(card, ensure_ascii=False)}")
    print(f"[+] K_payload delivered ({len(k_payload)} bytes)")

    if not os.path.exists(core_path):
        print(f"[i] no protected core at {core_path}; run tools/protect.py to make one.")
        return 0
    blob = open(core_path, "rb").read()
    try:
        core = crypto.decrypt_payload(blob, k_payload)
    except Exception:
        # wrong K_payload — e.g. this card belongs to a different application
        print("[!] core decryption failed — card does not match this software.")
        return 1
    print(f"[+] core.enc decrypted in memory ({len(core)} bytes), executing:\n")
    exec(compile(core, core_path, "exec"), {"__name__": "__protected__"})
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--code", required=True, help="card key")
    ap.add_argument("--server", default="http://127.0.0.1:8000")
    ap.add_argument("--core", default="examples/core.enc")
    ap.add_argument("--app", default="", help="optional app_key cross-check")
    args = ap.parse_args()
    raise SystemExit(run(args.code, args.server, args.core, args.app))
