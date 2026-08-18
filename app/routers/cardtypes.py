from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import get_current_admin
from ..models import Admin, Card, CardType
from ..services.audit import log_action
from ..templating import flash, render
from ..utils import to_int

router = APIRouter(prefix="/admin/card-types")


@router.get("")
def list_types(
    request: Request,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    types = db.query(CardType).order_by(CardType.id.desc()).all()
    counts = {
        t.id: db.query(Card).filter_by(type_id=t.id).count() for t in types
    }
    return render(
        request, "admin/cardtypes.html", active="cardtypes", types=types, counts=counts
    )


@router.post("/create")
def create_type(
    request: Request,
    name: str = Form(...),
    kind: str = Form("time"),
    value: int = Form(0),
    unit: str = Form("day"),
    max_devices: int = Form(1),
    is_permanent: str = Form(""),
    remark: str = Form(""),
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    permanent = kind == "time" and bool(is_permanent)
    duration = 0
    total = 0
    if kind == "count":
        total = max(0, to_int(value))
    elif not permanent:
        mult = {"minute": 1, "hour": 60, "day": 1440}.get(unit, 1440)
        duration = max(0, to_int(value)) * mult

    t = CardType(
        name=name.strip() or "未命名",
        kind="count" if kind == "count" else "time",
        duration_minutes=duration,
        is_permanent=permanent,
        total_count=total,
        max_devices=max(1, to_int(max_devices, 1)),
        remark=remark.strip(),
    )
    db.add(t)
    db.commit()
    log_action(db, request, "card_type.create", t.id, f"{t.name} / {t.duration_label}")
    flash(request, f"卡类型「{t.name}」已创建", "ok")
    return RedirectResponse("/admin/card-types", status_code=303)


@router.post("/{type_id}/toggle")
def toggle_type(
    type_id: int,
    request: Request,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    t = db.get(CardType, type_id)
    if t:
        t.is_active = not t.is_active
        db.commit()
        log_action(db, request, "card_type.toggle", t.id, f"is_active={t.is_active}")
    return RedirectResponse("/admin/card-types", status_code=303)


@router.post("/{type_id}/delete")
def delete_type(
    type_id: int,
    request: Request,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    t = db.get(CardType, type_id)
    if not t:
        return RedirectResponse("/admin/card-types", status_code=303)
    if db.query(Card).filter_by(type_id=type_id).count() > 0:
        flash(request, "该类型下仍有卡密,无法删除", "danger")
        return RedirectResponse("/admin/card-types", status_code=303)
    db.delete(t)
    db.commit()
    log_action(db, request, "card_type.delete", type_id, t.name)
    flash(request, "卡类型已删除", "ok")
    return RedirectResponse("/admin/card-types", status_code=303)
