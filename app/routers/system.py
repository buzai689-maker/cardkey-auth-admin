from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session, selectinload

from ..database import get_db
from ..deps import get_current_admin, require_super
from ..models import Admin, Application
from ..security import hash_password
from ..services import settings as settings_svc
from ..services.audit import log_action
from ..templating import flash, render
from ..utils import to_int

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
    heartbeat_min: int = Form(45),
    heartbeat_max: int = Form(90),
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    def _clamp(v, default):
        try:
            return max(10, min(int(v), 3600))
        except (TypeError, ValueError):
            return default

    hb_min = _clamp(heartbeat_min, 45)
    hb_max = _clamp(heartbeat_max, 90)
    if hb_max < hb_min:
        hb_max = hb_min
    settings_svc.set_many(
        db,
        {
            "site_name": site_name.strip() or "卡密授权管理后台",
            "notice": notice.strip(),
            "allow_self_unbind": "1" if allow_self_unbind else "0",
            "auto_bind_on_activate": "1" if auto_bind_on_activate else "0",
            "heartbeat_min": str(hb_min),
            "heartbeat_max": str(hb_max),
        },
    )
    log_action(db, request, "settings.save", "settings")
    flash(request, "设置已保存", "ok")
    return RedirectResponse("/admin/settings", status_code=303)


# ------------------------- 管理员管理 (super only) -------------------------
def _pick_apps(db, app_ids) -> list[Application]:
    """Resolve the app_ids checkboxes of the admin forms to Application rows."""
    ids = {to_int(i) for i in app_ids} - {0}
    if not ids:
        return []
    return db.query(Application).filter(Application.id.in_(sorted(ids))).all()


@router.get("/admins")
def admins_page(
    request: Request,
    admin: Admin = Depends(require_super),
    db: Session = Depends(get_db),
):
    admins = (
        db.query(Admin)
        .options(selectinload(Admin.applications))
        .order_by(Admin.id)
        .all()
    )
    apps = db.query(Application).order_by(Application.id.desc()).all()
    return render(request, "admin/admins.html", active="admins", admins=admins, apps=apps)


@router.post("/admins/create")
def admin_create(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form("operator"),
    app_ids: list[int] = Form([]),
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
    role = "super" if role == "super" else "operator"
    target = Admin(username=username, password_hash=hash_password(password), role=role)
    if role == "operator":
        # a sub-account only gets the applications ticked on the form
        target.applications = _pick_apps(db, app_ids)
    db.add(target)
    db.commit()
    if role == "super":
        detail = "super"
    else:
        detail = "operator apps=" + (",".join(a.app_key for a in target.applications) or "-")
    log_action(db, request, "admin.create", username, detail)
    flash(request, f"管理员「{username}」已创建", "ok")
    return RedirectResponse("/admin/admins", status_code=303)


@router.post("/admins/{admin_id}/apps")
def admin_set_apps(
    admin_id: int,
    request: Request,
    app_ids: list[int] = Form([]),
    admin: Admin = Depends(require_super),
    db: Session = Depends(get_db),
):
    """Replace the set of applications an operator may work with."""
    target = db.get(Admin, admin_id)
    if not target:
        flash(request, "管理员不存在", "danger")
        return RedirectResponse("/admin/admins", status_code=303)
    if target.role == "super":
        flash(request, "超级管理员拥有全部应用,无需分配", "info")
        return RedirectResponse("/admin/admins", status_code=303)
    target.applications = _pick_apps(db, app_ids)
    db.commit()
    names = ", ".join(a.name for a in target.applications) or "无"
    log_action(
        db,
        request,
        "admin.apps",
        target.username,
        ",".join(a.app_key for a in target.applications) or "-",
    )
    flash(request, f"「{target.username}」可用应用已更新: {names}", "ok")
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
