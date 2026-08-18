from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import PlainTextResponse, RedirectResponse
from sqlalchemy.orm import Session, joinedload

from ..database import get_db
from ..deps import get_current_admin
from ..models import Admin, Card, CardType
from ..services import cards as card_svc
from ..services.audit import log_action
from ..templating import flash, render
from ..utils import paginate, to_int

router = APIRouter(prefix="/admin/cards")


def _base_query(db, status, type_id, batch, q):
    query = db.query(Card).options(joinedload(Card.type))
    if status:
        query = query.filter(Card.status == status)
    if type_id:
        query = query.filter(Card.type_id == type_id)
    if batch:
        query = query.filter(Card.batch_no == batch)
    if q:
        query = query.filter(Card.code.like(f"%{q}%"))
    return query.order_by(Card.id.desc())


@router.get("")
def list_cards(
    request: Request,
    page: int = 1,
    status: str = "",
    type_id: int = 0,
    batch: str = "",
    q: str = "",
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    query = _base_query(db, status, type_id, batch, q.strip())
    items, pg = paginate(query, page, per_page=20)
    types = db.query(CardType).order_by(CardType.id.desc()).all()
    return render(
        request,
        "admin/cards.html",
        active="cards",
        cards=items,
        pg=pg,
        types=types,
        f={"status": status, "type_id": type_id, "batch": batch, "q": q},
    )


@router.get("/generate")
def generate_form(
    request: Request,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    return render(request, "admin/cards_generate.html", active="generate")


@router.post("/generate")
def generate_do(
    request: Request,
    days: int = Form(30),
    is_permanent: str = Form(""),
    max_devices: int = Form(1),
    count: int = Form(...),
    prefix: str = Form(""),
    length: int = Form(16),
    group_size: int = Form(0),
    remark: str = Form(""),
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    permanent = bool(is_permanent)
    days = max(0, to_int(days))
    max_devices = max(1, min(to_int(max_devices, 1), 99))
    count = max(1, min(to_int(count, 1), 5000))
    length = max(4, min(to_int(length, 16), 64))

    ct = card_svc.find_or_create_time_type(db, days, permanent, max_devices)
    batch, created = card_svc.generate_cards(
        db,
        ct,
        count,
        prefix=prefix.strip(),
        length=length,
        group_size=to_int(group_size),
        created_by=admin.username,
        remark=remark.strip(),
    )
    span = "永久" if permanent else f"{days}天"
    log_action(db, request, "card.generate", batch, f"{span}/{max_devices}设备 x{len(created)}")
    flash(
        request,
        f"已生成 {len(created)} 张卡密 · {span} · 授权 {max_devices} 台 (批次 {batch})",
        "ok",
    )
    return RedirectResponse(f"/admin/cards?batch={batch}", status_code=303)


@router.get("/export", response_class=PlainTextResponse)
def export_cards(
    request: Request,
    status: str = "",
    type_id: int = 0,
    batch: str = "",
    q: str = "",
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    query = _base_query(db, status, type_id, batch, q.strip())
    codes = [c.code for c in query.limit(20000).all()]
    fname = f"cards_{batch or 'all'}.txt"
    return PlainTextResponse(
        "\n".join(codes),
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


@router.get("/{card_id}")
def card_detail(
    card_id: int,
    request: Request,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    card = (
        db.query(Card)
        .options(joinedload(Card.type), joinedload(Card.devices))
        .filter_by(id=card_id)
        .first()
    )
    if not card:
        flash(request, "卡密不存在", "danger")
        return RedirectResponse("/admin/cards", status_code=303)
    devices = sorted(card.devices, key=lambda d: d.id, reverse=True)
    return render(
        request, "admin/card_detail.html", active="cards", card=card, devices=devices
    )


@router.post("/{card_id}/edit")
def card_edit(
    card_id: int,
    request: Request,
    remark: str = Form(""),
    max_devices: int = Form(1),
    extend_minutes: int = Form(0),
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    card = db.get(Card, card_id)
    if not card:
        flash(request, "卡密不存在", "danger")
        return RedirectResponse("/admin/cards", status_code=303)
    card.remark = remark.strip()
    card.max_devices = max(1, to_int(max_devices, 1))
    extend = to_int(extend_minutes)
    if extend:
        card_svc.extend_expiry(db, card, extend)
    db.commit()
    log_action(db, request, "card.edit", card.code, f"max_devices={card.max_devices},extend={extend}")
    flash(request, "卡密已更新", "ok")
    return RedirectResponse(f"/admin/cards/{card_id}", status_code=303)


@router.post("/{card_id}/ban")
def card_ban(
    card_id: int,
    request: Request,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    card = db.get(Card, card_id)
    if card:
        card_svc.set_status(db, card, "banned")
        log_action(db, request, "card.ban", card.code)
        flash(request, "卡密已封禁", "ok")
    return RedirectResponse(f"/admin/cards/{card_id}", status_code=303)


@router.post("/{card_id}/unban")
def card_unban(
    card_id: int,
    request: Request,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    card = db.get(Card, card_id)
    if card:
        # restore to active if it was ever activated, else unused
        card_svc.set_status(db, card, "active" if card.activated_at else "unused")
        log_action(db, request, "card.unban", card.code)
        flash(request, "卡密已解封", "ok")
    return RedirectResponse(f"/admin/cards/{card_id}", status_code=303)


@router.post("/{card_id}/reset")
def card_reset(
    card_id: int,
    request: Request,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    card = db.get(Card, card_id)
    if card:
        card_svc.reset_card(db, card)
        log_action(db, request, "card.reset", card.code, "解绑全部设备并重置")
        flash(request, "卡密已重置(解绑全部设备)", "ok")
    return RedirectResponse(f"/admin/cards/{card_id}", status_code=303)


@router.post("/{card_id}/unbind-devices")
def card_unbind_devices(
    card_id: int,
    request: Request,
    back: str = Form(""),
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    """Unbind all devices of a card WITHOUT resetting its status/expiry."""
    card = db.get(Card, card_id)
    if card:
        n = card_svc.unbind_all_devices(db, card)
        log_action(db, request, "card.unbind_all", card.code, f"unbound={n}")
        flash(request, f"已解绑 {n} 台设备", "ok" if n else "info")
    return RedirectResponse(back or f"/admin/cards/{card_id}", status_code=303)


@router.post("/{card_id}/delete")
def card_delete(
    card_id: int,
    request: Request,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    card = db.get(Card, card_id)
    if card:
        code = card.code
        db.delete(card)
        db.commit()
        log_action(db, request, "card.delete", code)
        flash(request, "卡密已删除", "ok")
    return RedirectResponse("/admin/cards", status_code=303)
