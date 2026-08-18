import base64
import hashlib
import os
import re
import secrets

from ..models import Application, Card


def _slug(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return s[:24] or "app"


def gen_app_key(db, name: str) -> str:
    base = _slug(name)
    for _ in range(50):
        cand = f"{base}-{secrets.token_hex(3)}"
        if not db.query(Application.id).filter_by(app_key=cand).first():
            return cand
    return f"app-{secrets.token_hex(6)}"


def create_application(db, name: str, remark: str = "") -> Application:
    name = name.strip() or "未命名应用"
    app = Application(
        name=name,
        app_key=gen_app_key(db, name),
        payload_key_b64=base64.b64encode(os.urandom(32)).decode(),
        remark=remark.strip(),
    )
    db.add(app)
    db.commit()
    return app


def get_by_key(db, app_key: str) -> Application | None:
    return db.query(Application).filter_by(app_key=app_key).first()


def payload_key_bytes(app: Application) -> bytes:
    return base64.b64decode(app.payload_key_b64)


def key_fingerprint(app: Application) -> str:
    return hashlib.sha256(payload_key_bytes(app)).hexdigest()[:16]


def rotate_key(db, app: Application) -> None:
    """New K_payload. Invalidates payloads already encrypted with the old key —
    they must be re-encrypted and redistributed."""
    app.payload_key_b64 = base64.b64encode(os.urandom(32)).decode()
    db.commit()


def card_count(db, app: Application) -> int:
    return db.query(Card).filter_by(application_id=app.id).count()
