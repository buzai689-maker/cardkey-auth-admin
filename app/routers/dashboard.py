from datetime import datetime

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload

from ..database import get_db
from ..deps import get_current_admin
from ..models import Admin, AuthLog, Card, Device
from ..services import scope
from ..templating import render

router = APIRouter()


@router.get("/admin")
def dashboard(
    request: Request,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    # None for super admins; otherwise restricts everything to the operator's apps
    card_crit = scope.card_criterion(admin)
    log_crit = scope.authlog_criterion(admin)

    def count(model, *filters):
        q = db.query(func.count(model.id))
        for f in filters:
            if f is not None:
                q = q.filter(f)
        return q.scalar() or 0

    device_q = (
        db.query(func.count(Device.id))
        .join(Card, Device.card_id == Card.id)
        .filter(Device.status == "active")
    )
    if card_crit is not None:
        device_q = device_q.filter(card_crit)

    today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    stats = {
        "total": count(Card, card_crit),
        "unused": count(Card, card_crit, Card.status == "unused"),
        "active": count(Card, card_crit, Card.status == "active"),
        "banned": count(Card, card_crit, Card.status == "banned"),
        "devices": device_q.scalar() or 0,
        "today_activate": count(
            AuthLog,
            log_crit,
            AuthLog.action == "activate",
            AuthLog.success.is_(True),
            AuthLog.created_at >= today,
        ),
    }
    recent_cards = (
        scope.scope_cards(db.query(Card).options(joinedload(Card.type)), admin)
        .order_by(Card.id.desc())
        .limit(8)
        .all()
    )
    logs_q = db.query(AuthLog)
    if log_crit is not None:
        logs_q = logs_q.filter(log_crit)
    recent_logs = logs_q.order_by(AuthLog.id.desc()).limit(10).all()
    return render(
        request,
        "admin/dashboard.html",
        active="dashboard",
        stats=stats,
        recent_cards=recent_cards,
        recent_logs=recent_logs,
    )
