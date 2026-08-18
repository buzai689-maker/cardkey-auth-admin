"""Encrypt/decrypt a software's protected core with that app's K_payload.

Each application has its own key, so you pick the app by its app_key:

    python -m tools.protect list-apps
    python -m tools.protect encrypt --app myapp-ab12cd core.py core.enc
    python -m tools.protect decrypt --app myapp-ab12cd core.enc /tmp/core.py
    python -m tools.protect keyinfo --app myapp-ab12cd
"""
import argparse
import hashlib
import sys

from app import crypto
from app.database import SessionLocal, init_db
from app.models import Application
from app.services import applications as app_svc


def _resolve_key(app_key: str) -> bytes:
    init_db()
    db = SessionLocal()
    try:
        app = app_svc.get_by_key(db, app_key)
        if not app:
            avail = [f"{a.app_key}  ({a.name})" for a in db.query(Application).all()]
            listing = "\n  ".join(avail) if avail else "(none — create one in 应用)"
            raise SystemExit(f"app_key '{app_key}' not found. available:\n  {listing}")
        return app_svc.payload_key_bytes(app)
    finally:
        db.close()


def cmd_encrypt(args) -> int:
    key = _resolve_key(args.app)
    data = open(args.src, "rb").read()
    blob = crypto.encrypt_payload(data, key)
    open(args.dst, "wb").write(blob)
    print(f"encrypted {len(data)} -> {len(blob)} bytes  [{args.app}]  {args.src} -> {args.dst}")
    return 0


def cmd_decrypt(args) -> int:
    key = _resolve_key(args.app)
    blob = open(args.src, "rb").read()
    data = crypto.decrypt_payload(blob, key)
    open(args.dst, "wb").write(data)
    print(f"decrypted {len(blob)} -> {len(data)} bytes  [{args.app}]  {args.src} -> {args.dst}")
    return 0


def cmd_keyinfo(args) -> int:
    key = _resolve_key(args.app)
    print("app_key          :", args.app)
    print("K_payload sha256 :", hashlib.sha256(key).hexdigest())
    print("server pubkey    :", crypto.server_public_key_b64())
    print("(embed the server pubkey in the client for signature pinning)")
    return 0


def cmd_listapps(_args) -> int:
    init_db()
    db = SessionLocal()
    try:
        apps = db.query(Application).order_by(Application.id).all()
        if not apps:
            print("(no applications — create one in the 应用 page)")
        for a in apps:
            state = "active" if a.is_active else "disabled"
            print(f"{a.app_key:28} {state:9} cards={app_svc.card_count(db, a):<5} {a.name}")
    finally:
        db.close()
    return 0


def main(argv) -> int:
    ap = argparse.ArgumentParser(prog="tools.protect")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("encrypt")
    p.add_argument("--app", required=True)
    p.add_argument("src")
    p.add_argument("dst")
    p.set_defaults(fn=cmd_encrypt)

    p = sub.add_parser("decrypt")
    p.add_argument("--app", required=True)
    p.add_argument("src")
    p.add_argument("dst")
    p.set_defaults(fn=cmd_decrypt)

    p = sub.add_parser("keyinfo")
    p.add_argument("--app", required=True)
    p.set_defaults(fn=cmd_keyinfo)

    p = sub.add_parser("list-apps")
    p.set_defaults(fn=cmd_listapps)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
