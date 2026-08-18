from ..models import AuditLog
from ..utils import client_ip


def log_action(db, request, action: str, target: str = "", detail: str = "") -> None:
    admin = getattr(request.state, "admin", None)
    db.add(
        AuditLog(
            admin_id=getattr(admin, "id", None),
            admin_name=getattr(admin, "username", ""),
            action=action,
            target=str(target),
            detail=detail,
            ip=client_ip(request),
        )
    )
    db.commit()
