from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import PlainTextResponse, RedirectResponse
from sqlalchemy.orm import Session, joinedload

from ..database import get_db
from ..deps import get_current_admin
from ..models import Admin, Application, Card, CardType
from ..services import cards as card_svc
from ..services import scope
from ..services.audit import log_action
from ..templating import flash, render
from ..utils import paginate, to_int

router = APIRouter(prefix="/admin/cards")


def _base_query(db, admin, status, type_id, batch, q, application_id=0, creator=""):
    query = db.query(Card).options(joinedload(Card.type), joinedload(Card.application))
    # operators only ever see their own cards within the applications assigned to them
    query = scope.scope_cards(query, admin)
    if creator:
        query = query.filter(Card.created_by == creator)
    if application_id:
        query = query.filter(Card.application_id == application_id)
    if status:
        query = query.filter(Card.status == status)
    if type_id:
        query = query.filter(Card.type_id == type_id)
    if batch:
        query = query.filter(Card.batch_no == batch)
    if q:
        query = query.filter(Card.code.like(f"%{q}%"))
    return query.order_by(Card.id.desc())


def _load_card(db, request, admin, card_id, *options):
    """Fetch a card the admin may act on.

    Returns None when the card does not exist; audit-logs and raises 403 when
    it is outside the admin's scope (other application, or issued by someone
    else in the case of an operator).
    """
    query = db.query(Card).filter_by(id=card_id)
    if options:
        query = query.options(*options)
    card = query.first()
    if card and not scope.can_access_card(admin, card):
        scope.forbid(db, request, card.code, f"card_id={card.id}")
    return card


@router.get("")
def list_cards(
    request: Request,
    page: int = 1,
    status: str = "",
    type_id: int = 0,
    application_id: int = 0,
    batch: str = "",
    q: str = "",
    creator: str = "",
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    creator = creator.strip()
    query = _base_query(db, admin, status, type_id, batch, q.strip(), application_id, creator)
    items, pg = paginate(query, page, per_page=20)
    types = db.query(CardType).order_by(CardType.id.desc()).all()
    apps = scope.visible_apps(db, admin)
    # super admins can filter by who issued the cards (owner vs. each agent)
    creators = []
    if scope.is_super(admin):
        creators = sorted(v for (v,) in db.query(Card.created_by).distinct().all() if v)
    return render(
        request,
        "admin/cards.html",
        active="cards",
        cards=items,
        pg=pg,
        types=types,
        apps=apps,
        creators=creators,
        f={
            "status": status,
            "type_id": type_id,
            "application_id": application_id,
            "batch": batch,
            "q": q,
            "creator": creator,
        },
    )


@router.get("/generate")
def generate_form(
    request: Request,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    apps = scope.visible_apps(db, admin, active_only=True)
    return render(request, "admin/cards_generate.html", active="generate", apps=apps)


@router.post("/generate")
def generate_do(
    request: Request,
    application_id: int = Form(...),
    days: int = Form(30),
    is_permanent: str = Form(""),
    max_devices: int = Form(1),
    count: int = Form(...),
    prefix: str = Form(""),
    length: int = Form(16),
    group_size: int = Form(4),
    remark: str = Form(""),
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    app = db.get(Application, to_int(application_id))
    if not app:
        flash(request, "请先选择所属应用", "danger")
        return RedirectResponse("/admin/cards/generate", status_code=303)
    if not scope.can_access_app(admin, app.id):
        # the form never offers this app to the operator; this is a forged request
        scope.forbid(db, request, app.app_key, "card.generate")

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
        application_id=app.id,
        prefix=prefix.strip(),
        length=length,
        group_size=to_int(group_size),
        created_by=admin.username,  # ownership: operators only ever see their own cards
        remark=remark.strip(),
    )
    span = "永久" if permanent else f"{days}天"
    log_action(
        db, request, "card.generate", batch, f"{app.name}/{span}/{max_devices}设备 x{len(created)}"
    )
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
    application_id: int = 0,
    batch: str = "",
    q: str = "",
    creator: str = "",
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    query = _base_query(
        db, admin, status, type_id, batch, q.strip(), application_id, creator.strip()
    )
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
    card = _load_card(
        db,
        request,
        admin,
        card_id,
        joinedload(Card.type),
        joinedload(Card.application),
        joinedload(Card.devices),
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
    card = _load_card(db, request, admin, card_id)
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
    card = _load_card(db, request, admin, card_id)
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
    card = _load_card(db, request, admin, card_id)
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
    card = _load_card(db, request, admin, card_id)
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
    card = _load_card(db, request, admin, card_id)
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
    card = _load_card(db, request, admin, card_id)
    if card:
        code = card.code
        db.delete(card)
        db.commit()
        log_action(db, request, "card.delete", code)
        flash(request, "卡密已删除", "ok")
    return RedirectResponse("/admin/cards", status_code=303)
