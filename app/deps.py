from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .database import get_db
from .models import Admin


class AuthRequired(Exception):
    """Raised by admin dependencies when there is no valid session."""


def get_current_admin(request: Request, db: Session = Depends(get_db)) -> Admin:
    aid = request.session.get("admin_id")
    if not aid:
        raise AuthRequired()
    admin = db.get(Admin, aid)
    if not admin or not admin.is_active:
        request.session.pop("admin_id", None)
        raise AuthRequired()
    request.state.admin = admin
    return admin


def require_super(admin: Admin = Depends(get_current_admin)) -> Admin:
    if admin.role != "super":
        raise HTTPException(status_code=403, detail="需要超级管理员权限")
    return admin
