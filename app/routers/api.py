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


class ActivateIn(BaseModel):
    code: str
    device_id: str
    device_name: str | None = ""


class VerifyIn(BaseModel):
    code: str
    device_id: str


class HeartbeatIn(BaseModel):
    code: str
    device_id: str
    nonce: str  # base64 client nonce, fresh per beat


class SessionIn(BaseModel):
    code: str
    device_id: str
    client_pub: str  # base64 raw X25519 public key
    nonce: str  # base64 client nonce
    device_name: str | None = ""
    app_key: str | None = ""  # optional: cross-check the card belongs to this app


def _heartbeat_interval() -> int:
    try:
        return max(10, int(settings_svc.get("heartbeat_interval", "60")))
    except (TypeError, ValueError):
        return 60


def _card_payload(card):
    return {
        "status": card.effective_status,
        "app": card.application.app_key if card.application else None,
        "heartbeat": _heartbeat_interval(),
        "type": card.type.name if card.type else None,
        "activated_at": card.activated_at.isoformat() if card.activated_at else None,
        "expires_at": card.expires_at.isoformat() if card.expires_at else None,
        "max_devices": card.max_devices,
        "bound_devices": card.bound_count,
        "remaining_count": card.remaining_count,
    }


@router.post("/activate")
def api_activate(request: Request, body: ActivateIn, db: Session = Depends(get_db)):
    ok, msg, card = verify_svc.activate(
        db, request, body.code.strip(), body.device_id.strip(), (body.device_name or "").strip()
    )
    return {
        "success": ok,
        "message": msg,
        "data": _card_payload(card) if (ok and card) else None,
    }


@router.post("/verify")
def api_verify(request: Request, body: VerifyIn, db: Session = Depends(get_db)):
    ok, msg, card = verify_svc.verify(
        db, request, body.code.strip(), body.device_id.strip()
    )
    return {
        "success": ok,
        "message": msg,
        "data": _card_payload(card) if (ok and card) else None,
    }


@router.post("/unbind")
def api_unbind(request: Request, body: VerifyIn, db: Session = Depends(get_db)):
    ok, msg, _ = verify_svc.self_unbind(
        db, request, body.code.strip(), body.device_id.strip()
    )
    return {"success": ok, "message": msg}


@router.post("/heartbeat")
def api_heartbeat(request: Request, body: HeartbeatIn, db: Session = Depends(get_db)):
    """Signed liveness check. Re-validates the card every beat so ban / unbind /
    expiry take effect mid-session. Returns {success, body, sig} on valid — the
    client must verify the signature + echoed nonce and fail closed otherwise."""
    ok, msg, card = verify_svc.verify(
        db,
        request,
        body.code.strip(),
        body.device_id.strip(),
        action="heartbeat",
        log_success=False,
    )
    if not ok or card is None:
        return {"success": False, "message": msg}
    obj = {
        "v": 1,
        "ts": int(time.time()),
        "nonce": body.nonce,
        "valid": True,
        "status": card.effective_status,
        "expires_at": card.expires_at.isoformat() if card.expires_at else None,
        "heartbeat": _heartbeat_interval(),
    }
    return {"success": True, "message": "ok", **crypto.sign_body(obj)}


@router.get("/pubkey")
def api_pubkey():
    """Server static Ed25519 public key. Pin/embed this in the client."""
    return {"alg": "ed25519", "public_key": crypto.server_public_key_b64()}


@router.post("/session")
def api_session(request: Request, body: SessionIn, db: Session = Depends(get_db)):
    """Authenticate + bind, then deliver K_payload over a signed ECDH channel.

    Same auth/bind semantics as /activate; on success returns {body, sig} where
    body carries the wrapped payload key and card status, signed by the server.
    """
    ok, msg, card = verify_svc.activate(
        db, request, body.code.strip(), body.device_id.strip(), (body.device_name or "").strip()
    )
    if not ok or card is None:
        return {"success": False, "message": msg}

    # resolve which app's K_payload to deliver (per-app isolation)
    key = None
    if card.application_id:
        app = card.application
        if not app or not app.is_active:
            return {"success": False, "message": "应用未启用"}
        if body.app_key and body.app_key != app.app_key:
            return {"success": False, "message": "卡与应用不匹配"}
        key = app_svc.payload_key_bytes(app)

    try:
        session = crypto.build_session_response(
            body.client_pub, body.nonce, _card_payload(card), int(time.time()), key
        )
    except Exception:
        return {"success": False, "message": "握手参数无效"}
    return {"success": True, "message": "ok", **session}
