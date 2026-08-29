import json
import secrets
import time

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import crypto
from ..database import get_db
from ..services import applications as app_svc
from ..services import settings as settings_svc
from ..services import verify as verify_svc

router = APIRouter(prefix="/api/v1", tags=["client-api"])


class SecureIn(BaseModel):
    epk: str  # base64 client ephemeral X25519 public key
    n: str  # base64 nonce
    ct: str  # base64 AES-GCM ciphertext of the inner {op, ...} request


def _s(d: dict, key: str) -> str:
    return (d.get(key) or "").strip()


def _next_interval() -> int:
    """A fresh random heartbeat delay in [min,max] seconds, chosen per beat so
    the client holds no fixed interval constant to pattern-match / patch."""
    try:
        lo = max(10, int(settings_svc.get("heartbeat_min", "45")))
        hi = max(lo, int(settings_svc.get("heartbeat_max", "90")))
    except (TypeError, ValueError):
        lo, hi = 45, 90
    return lo + secrets.randbelow(hi - lo + 1)


def _card_payload(card):
    return {
        "status": card.effective_status,
        "app": card.application.app_key if card.application else None,
        "heartbeat": _next_interval(),  # seconds until the client's first beat
        "type": card.type.name if card.type else None,
        "activated_at": card.activated_at.isoformat() if card.activated_at else None,
        "expires_at": card.expires_at.isoformat() if card.expires_at else None,
        "max_devices": card.max_devices,
        "bound_devices": card.bound_count,
        "remaining_count": card.remaining_count,
    }


# --------------------------------------------------------------------------- #
# operation handlers — invoked only through the encrypted /secure transport    #
# --------------------------------------------------------------------------- #
def _do_activate(db, request, d):
    ok, msg, card = verify_svc.activate(
        db, request, _s(d, "code"), _s(d, "device_id"), _s(d, "device_name")
    )
    return {"success": ok, "message": msg, "data": _card_payload(card) if (ok and card) else None}


def _do_verify(db, request, d):
    ok, msg, card = verify_svc.verify(db, request, _s(d, "code"), _s(d, "device_id"))
    return {"success": ok, "message": msg, "data": _card_payload(card) if (ok and card) else None}


def _do_unbind(db, request, d):
    ok, msg, _ = verify_svc.self_unbind(db, request, _s(d, "code"), _s(d, "device_id"))
    return {"success": ok, "message": msg}


def _do_heartbeat(db, request, d):
    ok, msg, card = verify_svc.verify(
        db, request, _s(d, "code"), _s(d, "device_id"),
        action="heartbeat", log_success=False,
    )
    if not ok or card is None:
        return {"success": False, "message": msg}
    obj = {
        "v": 1,
        "ts": int(time.time()),
        "nonce": d.get("nonce", ""),
        "valid": True,
        "status": card.effective_status,
        "expires_at": card.expires_at.isoformat() if card.expires_at else None,
        "next": _next_interval(),  # signed: when to beat again (randomized)
    }
    return {"success": True, "message": "ok", **crypto.sign_body(obj)}


def _do_session(db, request, d):
    ok, msg, card = verify_svc.activate(
        db, request, _s(d, "code"), _s(d, "device_id"), _s(d, "device_name")
    )
    if not ok or card is None:
        return {"success": False, "message": msg}
    key = None
    if card.application_id:
        app = card.application
        if not app or not app.is_active:
            return {"success": False, "message": "应用未启用"}
        if d.get("app_key") and d.get("app_key") != app.app_key:
            return {"success": False, "message": "卡与应用不匹配"}
        key = app_svc.payload_key_bytes(app)
    try:
        session = crypto.build_session_response(
            _s(d, "client_pub"), _s(d, "nonce"), _card_payload(card), int(time.time()), key
        )
    except Exception:
        return {"success": False, "message": "握手参数无效"}
    return {"success": True, "message": "ok", **session}


_OPS = {
    "activate": _do_activate,
    "verify": _do_verify,
    "unbind": _do_unbind,
    "heartbeat": _do_heartbeat,
    "session": _do_session,
}


# --------------------------------------------------------------------------- #
# the ONLY client entrypoint: every op wrapped in a sealed box (no plaintext)  #
# --------------------------------------------------------------------------- #
@router.post("/secure")
def api_secure(request: Request, env: SecureIn, db: Session = Depends(get_db)):
    """Open a sealed-box request {epk,n,ct} carrying an inner {op, ...}, run it,
    and return the sealed reply. The card code etc. never appear in plaintext.

    ops: activate | verify | unbind | heartbeat | session (see README)."""
    try:
        pt, k_s2c = crypto.open_envelope(env.model_dump())
        inner = json.loads(pt)
    except Exception:
        return {"error": "bad_envelope"}
    handler = _OPS.get(inner.get("op"))
    result = handler(db, request, inner) if handler else {"success": False, "message": "unknown op"}
    return crypto.seal_reply(json.dumps(result).encode(), k_s2c)


@router.get("/pubkey")
def api_pubkey():
    """Server public keys to pin/embed in the client: Ed25519 for signature
    verification, X25519 for the sealed-box encrypted transport."""
    return {
        "alg": "ed25519",
        "public_key": crypto.server_public_key_b64(),
        "enc_alg": "x25519",
        "enc_public_key": crypto.server_enc_public_key_b64(),
    }
