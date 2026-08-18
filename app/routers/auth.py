from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Admin
from ..security import verify_password
from ..services.audit import log_action
from ..templating import flash, render
from ..utils import client_ip, now

router = APIRouter()


@router.get("/admin/login")
def login_page(request: Request):
    if request.session.get("admin_id"):
        return RedirectResponse("/admin", status_code=303)
    return render(request, "login.html")


@router.post("/admin/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    admin = db.query(Admin).filter_by(username=username).first()
    if not admin or not admin.is_active or not verify_password(password, admin.password_hash):
        flash(request, "用户名或密码错误", "danger")
        return RedirectResponse("/admin/login", status_code=303)

    request.session["admin_id"] = admin.id
    request.state.admin = admin
    admin.last_login_at = now()
    admin.last_login_ip = client_ip(request)
    db.commit()
    log_action(db, request, "login", admin.username, "登录成功")
    flash(request, f"欢迎回来,{admin.username}", "ok")
    return RedirectResponse("/admin", status_code=303)


@router.get("/admin/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/admin/login", status_code=303)
