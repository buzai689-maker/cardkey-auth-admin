from datetime import datetime

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func
from sqlalchemy.orm import Session, joinedload

from ..database import get_db
from ..deps import get_current_admin
from ..models import Admin, AuthLog, Card, Device
from ..templating import render

router = APIRouter()


@router.get("/admin")
def dashboard(
    request: Request,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    def count(model, *filters):
        q = db.query(func.count(model.id))
        for f in filters:
            q = q.filter(f)
        return q.scalar() or 0

    today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    stats = {
        "total": count(Card),
        "unused": count(Card, Card.status == "unused"),
        "active": count(Card, Card.status == "active"),
        "banned": count(Card, Card.status == "banned"),
        "devices": count(Device, Device.status == "active"),
        "today_activate": count(
            AuthLog,
            AuthLog.action == "activate",
            AuthLog.success.is_(True),
            AuthLog.created_at >= today,
        ),
    }
    recent_cards = (
        db.query(Card)
        .options(joinedload(Card.type))
        .order_by(Card.id.desc())
        .limit(8)
        .all()
    )
    recent_logs = db.query(AuthLog).order_by(AuthLog.id.desc()).limit(10).all()
    return render(
        request,
        "admin/dashboard.html",
        active="dashboard",
        stats=stats,
        recent_cards=recent_cards,
        recent_logs=recent_logs,
    )
