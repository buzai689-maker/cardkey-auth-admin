"""Reference client for the card-key network authorization.

Every call goes through the sealed-box transport (/api/v1/secure): the inner
{op, code, device_id, ...} is X25519-ECDH-encrypted to the server's static key,
so the card code never appears in plaintext on the wire (independent of TLS).

Flow per launch:
  1. machine code (device_id) from hardware
  2. fetch + pin server keys (Ed25519 sign, X25519 box)
  3. op=session  -> unwrap K_payload -> decrypt core.enc -> run
  4. op=heartbeat every server-chosen (randomized) delay; fail-closed on trouble

The crypto is language-agnostic (see README); a real C/C++/C#/Delphi client
reimplements it. This Python version reuses app.crypto for brevity.

    python -m examples.client --code DAY-XXXX-XXXX-XXXX
    python -m examples.client --code DAY-... --beats 6 --interval 2
"""
import argparse
import base64
import hashlib
import json
import os
import platform
import subprocess
import time
import urllib.request
import uuid

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app import crypto

# Pin the server keys here in production (paste /api/v1/pubkey values). When
# empty this demo fetches them once — which a MITM could swap, so a shipped
# client MUST hardcode both.
PINNED_SERVER_PUB = ""      # Ed25519 signature key
PINNED_SERVER_ENC_PUB = ""  # X25519 sealed-box key


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
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode())


def _get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=10) as r:
        return json.loads(r.read().decode())


def secure_call(server: str, enc_pub: str, op: str, fields: dict) -> dict:
    """Wrap {op, **fields} in a sealed box, POST /secure, open the sealed reply."""
    inner = dict(fields)
    inner["op"] = op
    env, k_s2c = crypto.seal_request(json.dumps(inner).encode(), enc_pub)
    reply = _post(f"{server}/api/v1/secure", env)
    if "ct" not in reply:
        raise RuntimeError(f"secure transport error: {reply}")
    return json.loads(crypto.open_reply(reply, k_s2c))


def heartbeat_once(server, code, device_id, sign_pub, enc_pub):
    """One signed beat over the box. Fail-closed: any error -> (False, reason)."""
    nonce = base64.b64encode(os.urandom(16)).decode()
    try:
        resp = secure_call(server, enc_pub, "heartbeat", {"code": code, "device_id": device_id, "nonce": nonce})
    except Exception as e:
        return False, f"network: {e}"
    if not resp.get("success"):
        return False, resp.get("message", "invalid")
    try:
        obj = crypto.verify_body(resp, sign_pub, crypto.HEARTBEAT_AAD)
    except Exception:
        return False, "signature invalid"
    if obj.get("nonce") != nonce:
        return False, "nonce mismatch"
    if abs(int(time.time()) - int(obj.get("ts", 0))) > 120:
        return False, "stale timestamp"
    if not obj.get("valid"):
        return False, "not valid"
    return True, obj


def run(code: str, server: str, core_path: str, app_key: str = "", beats: int = 0, interval: int = 0) -> int:
    server = server.rstrip("/")
    device_id = machine_code()
    print(f"[*] device_id = {device_id}")

    keys = _get(f"{server}/api/v1/pubkey")
    sign_pub = PINNED_SERVER_PUB or keys["public_key"]
    enc_pub = PINNED_SERVER_ENC_PUB or keys["enc_public_key"]

    client_priv = X25519PrivateKey.generate()
    client_pub_b64 = base64.b64encode(
        client_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    nonce_b64 = base64.b64encode(os.urandom(16)).decode()

    fields = {"code": code, "device_id": device_id, "client_pub": client_pub_b64, "nonce": nonce_b64}
    if app_key:
        fields["app_key"] = app_key
    resp = secure_call(server, enc_pub, "session", fields)
    if not resp.get("success"):
        print(f"[!] authorization failed: {resp.get('message')}")
        return 1

    try:
        k_payload, card = crypto.open_session_response(resp, client_priv, nonce_b64, sign_pub)
    except Exception as e:
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
        print("[!] core decryption failed — card does not match this software.")
        return 1
    print(f"[+] core.enc decrypted in memory ({len(core)} bytes), executing:\n")
    exec(compile(core, core_path, "exec"), {"__name__": "__protected__"})

    # heartbeat: re-validate on a server-chosen randomized cadence so ban /
    # unbind / expiry stop the app mid-run. A real client runs this in a thread.
    if beats:
        every = interval or int(card.get("heartbeat") or 60)
        print(f"\n[hb] heartbeat (randomized cadence, fail-closed):")
        for i in range(beats):
            time.sleep(every)
            ok, info = heartbeat_once(server, code, device_id, sign_pub, enc_pub)
            if not ok:
                print(f"[hb] beat {i + 1}: INVALID -> {info} — 停止运行")
                return 2
            every = interval or int(info.get("next") or every)
            print(f"[hb] beat {i + 1}: valid (status={info.get('status')}, next in {every}s)")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--code", required=True, help="card key")
    ap.add_argument("--server", default="http://127.0.0.1:8000")
    ap.add_argument("--core", default="examples/core.enc")
    ap.add_argument("--app", default="", help="optional app_key cross-check")
    ap.add_argument("--beats", type=int, default=0, help="heartbeat rounds after launch (demo)")
    ap.add_argument("--interval", type=int, default=0, help="override heartbeat seconds (0=server)")
    args = ap.parse_args()
    raise SystemExit(run(args.code, args.server, args.core, args.app, args.beats, args.interval))
