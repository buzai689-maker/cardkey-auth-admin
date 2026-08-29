from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from ..database import get_db
from ..deps import get_current_admin, require_super
from ..models import Admin
from ..security import hash_password
from ..services import settings as settings_svc
from ..services.audit import log_action
from ..templating import flash, render

router = APIRouter(prefix="/admin")


# ------------------------- 站点设置 -------------------------
@router.get("/settings")
def settings_page(
    request: Request,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    return render(
        request, "admin/settings.html", active="settings", cfg=settings_svc.get_settings()
    )


@router.post("/settings")
def settings_save(
    request: Request,
    site_name: str = Form(""),
    notice: str = Form(""),
    allow_self_unbind: str = Form(""),
    auto_bind_on_activate: str = Form(""),
    heartbeat_interval: int = Form(60),
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    try:
        hb = max(10, min(int(heartbeat_interval), 3600))
    except (TypeError, ValueError):
        hb = 60
    settings_svc.set_many(
        db,
        {
            "site_name": site_name.strip() or "卡密授权管理后台",
            "notice": notice.strip(),
            "allow_self_unbind": "1" if allow_self_unbind else "0",
            "auto_bind_on_activate": "1" if auto_bind_on_activate else "0",
            "heartbeat_interval": str(hb),
        },
    )
    log_action(db, request, "settings.save", "settings")
    flash(request, "设置已保存", "ok")
    return RedirectResponse("/admin/settings", status_code=303)


# ------------------------- 管理员管理 (super only) -------------------------
@router.get("/admins")
def admins_page(
    request: Request,
    admin: Admin = Depends(require_super),
    db: Session = Depends(get_db),
):
    admins = db.query(Admin).order_by(Admin.id).all()
    return render(request, "admin/admins.html", active="admins", admins=admins)


@router.post("/admins/create")
def admin_create(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form("operator"),
    admin: Admin = Depends(require_super),
    db: Session = Depends(get_db),
):
    username = username.strip()
    if not username or not password:
        flash(request, "用户名和密码必填", "danger")
        return RedirectResponse("/admin/admins", status_code=303)
    if db.query(Admin).filter_by(username=username).first():
        flash(request, "用户名已存在", "danger")
        return RedirectResponse("/admin/admins", status_code=303)
    db.add(
        Admin(
            username=username,
            password_hash=hash_password(password),
            role="super" if role == "super" else "operator",
        )
    )
    db.commit()
    log_action(db, request, "admin.create", username, role)
    flash(request, f"管理员「{username}」已创建", "ok")
    return RedirectResponse("/admin/admins", status_code=303)


@router.post("/admins/{admin_id}/reset-pwd")
def admin_reset_pwd(
    admin_id: int,
    request: Request,
    password: str = Form(...),
    admin: Admin = Depends(require_super),
    db: Session = Depends(get_db),
):
    target = db.get(Admin, admin_id)
    if target and password:
        target.password_hash = hash_password(password)
        db.commit()
        log_action(db, request, "admin.reset_pwd", target.username)
        flash(request, "密码已重置", "ok")
    return RedirectResponse("/admin/admins", status_code=303)


@router.post("/admins/{admin_id}/toggle")
def admin_toggle(
    admin_id: int,
    request: Request,
    admin: Admin = Depends(require_super),
    db: Session = Depends(get_db),
):
    target = db.get(Admin, admin_id)
    if target and target.id != admin.id:
        target.is_active = not target.is_active
        db.commit()
        log_action(db, request, "admin.toggle", target.username, f"is_active={target.is_active}")
    else:
        flash(request, "不能停用当前登录账号", "danger")
    return RedirectResponse("/admin/admins", status_code=303)


@router.post("/admins/{admin_id}/delete")
def admin_delete(
    admin_id: int,
    request: Request,
    admin: Admin = Depends(require_super),
    db: Session = Depends(get_db),
):
    target = db.get(Admin, admin_id)
    if target and target.id != admin.id:
        name = target.username
        db.delete(target)
        db.commit()
        log_action(db, request, "admin.delete", name)
        flash(request, "管理员已删除", "ok")
    else:
        flash(request, "不能删除当前登录账号", "danger")
    return RedirectResponse("/admin/admins", status_code=303)
