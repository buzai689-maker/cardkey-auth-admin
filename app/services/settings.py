from ..database import SessionLocal
from ..models import Setting

DEFAULTS = {
    "site_name": "卡密授权管理后台",
    "notice": "",
    # allow the client verification API to self-unbind a device
    "allow_self_unbind": "0",
    # activate auto-binds the calling device_id (else only pre-bound devices pass)
    "auto_bind_on_activate": "1",
}

_cache: dict | None = None


def _load(db) -> dict:
    rows = {s.key: s.value for s in db.query(Setting).all()}
    merged = dict(DEFAULTS)
    merged.update(rows)
    return merged


def refresh_cache() -> dict:
    global _cache
    db = SessionLocal()
    try:
        _cache = _load(db)
    finally:
        db.close()
    return _cache


def get_settings() -> dict:
    if _cache is None:
        return refresh_cache()
    return _cache


def get(key: str, default: str = "") -> str:
    return get_settings().get(key, default)


def set_many(db, data: dict) -> None:
    for k, v in data.items():
        row = db.get(Setting, k)
        if row:
            row.value = str(v)
        else:
            db.add(Setting(key=k, value=str(v)))
    db.commit()
    refresh_cache()
