from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import get_current_admin
from ..models import Admin, AuditLog, AuthLog
from ..services import scope
from ..templating import render
from ..utils import paginate

router = APIRouter(prefix="/admin/logs")


@router.get("")
def logs(
    request: Request,
    tab: str = "auth",
    page: int = 1,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    tab = "audit" if tab == "audit" else "auth"
    if tab == "auth":
        # operators: only verification events of cards in their applications
        query = db.query(AuthLog)
        crit = scope.authlog_criterion(admin)
        if crit is not None:
            query = query.filter(crit)
        query = query.order_by(AuthLog.id.desc())
    else:
        # operators: only their own backend actions
        query = db.query(AuditLog)
        if admin.role != "super":
            query = query.filter(AuditLog.admin_id == admin.id)
        query = query.order_by(AuditLog.id.desc())
    items, pg = paginate(query, page, per_page=30)
    return render(
        request, "admin/logs.html", active="logs", tab=tab, items=items, pg=pg
    )
