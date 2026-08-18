from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..database import get_db
from ..services import verify as verify_svc

router = APIRouter(prefix="/api/v1", tags=["client-api"])


class ActivateIn(BaseModel):
    code: str
    device_id: str
    device_name: str | None = ""


class VerifyIn(BaseModel):
    code: str
    device_id: str


def _card_payload(card):
    return {
        "status": card.effective_status,
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
