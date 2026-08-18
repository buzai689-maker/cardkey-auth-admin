from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from .. import crypto
from ..database import get_db
from ..deps import get_current_admin
from ..models import Admin, Application
from ..services import applications as app_svc
from ..services.audit import log_action
from ..templating import flash, render

router = APIRouter(prefix="/admin/applications")


@router.get("")
def list_apps(
    request: Request,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    apps = db.query(Application).order_by(Application.id.desc()).all()
    counts = {a.id: app_svc.card_count(db, a) for a in apps}
    fps = {a.id: app_svc.key_fingerprint(a) for a in apps}
    return render(
        request,
        "admin/applications.html",
        active="applications",
        apps=apps,
        counts=counts,
        fps=fps,
        server_pubkey=crypto.server_public_key_b64(),
    )


@router.post("/create")
def create_app(
    request: Request,
    name: str = Form(...),
    remark: str = Form(""),
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    app = app_svc.create_application(db, name, remark)
    log_action(db, request, "app.create", app.app_key, app.name)
    flash(request, f"应用「{app.name}」已创建 (app_key: {app.app_key})", "ok")
    return RedirectResponse("/admin/applications", status_code=303)


@router.post("/{app_id}/toggle")
def toggle_app(
    app_id: int,
    request: Request,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    app = db.get(Application, app_id)
    if app:
        app.is_active = not app.is_active
        db.commit()
        log_action(db, request, "app.toggle", app.app_key, f"is_active={app.is_active}")
    return RedirectResponse("/admin/applications", status_code=303)


@router.post("/{app_id}/rotate-key")
def rotate_app_key(
    app_id: int,
    request: Request,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    app = db.get(Application, app_id)
    if app:
        app_svc.rotate_key(db, app)
        log_action(db, request, "app.rotate_key", app.app_key)
        flash(request, "K_payload 已轮换,请重新加密并分发该应用的核心", "info")
    return RedirectResponse("/admin/applications", status_code=303)


@router.post("/{app_id}/delete")
def delete_app(
    app_id: int,
    request: Request,
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    app = db.get(Application, app_id)
    if not app:
        return RedirectResponse("/admin/applications", status_code=303)
    if app_svc.card_count(db, app) > 0:
        flash(request, "该应用下仍有卡密,无法删除", "danger")
        return RedirectResponse("/admin/applications", status_code=303)
    key = app.app_key
    db.delete(app)
    db.commit()
    log_action(db, request, "app.delete", key)
    flash(request, "应用已删除", "ok")
    return RedirectResponse("/admin/applications", status_code=303)
