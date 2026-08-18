from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session, joinedload

from ..database import get_db
from ..deps import get_current_admin
from ..models import Admin, Card, Device
from ..services import devices as dev_svc
from ..services.audit import log_action
from ..templating import flash, render
from ..utils import paginate

router = APIRouter(prefix="/admin/devices")


@router.get("")
def list_devices(
    request: Request,
    page: int = 1,
    status: str = "",
    q: str = "",
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    query = db.query(Device).options(joinedload(Device.card))
    if status:
        query = query.filter(Device.status == status)
    q = q.strip()
    if q:
        query = query.join(Card, Device.card_id == Card.id).filter(
            (Device.device_id.like(f"%{q}%")) | (Card.code.like(f"%{q}%"))
        )
    query = query.order_by(Device.id.desc())
    items, pg = paginate(query, page, per_page=20)
    return render(
        request,
        "admin/devices.html",
        active="devices",
        devices=items,
        pg=pg,
        f={"status": status, "q": q},
    )


@router.post("/{device_id}/edit")
def edit_device(
    device_id: int,
    request: Request,
    device_name: str = Form(""),
    remark: str = Form(""),
    new_device_id: str = Form(""),
    back: str = Form(""),
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    dev = db.get(Device, device_id)
    if not dev:
        flash(request, "设备不存在", "danger")
        return RedirectResponse(back or "/admin/devices", status_code=303)
    dev_svc.edit(
        db,
        dev,
        device_name=device_name.strip(),
        remark=remark.strip(),
        device_id=new_device_id.strip() or None,
    )
    log_action(db, request, "device.edit", dev.device_id, f"card_id={dev.card_id}")
    flash(request, "设备信息已更新", "ok")
    return RedirectResponse(back or "/admin/devices", status_code=303)


@router.post("/{device_id}/unbind")
def unbind_device(
    device_id: int,
    request: Request,
    back: str = Form(""),
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    dev = db.get(Device, device_id)
    if not dev:
        flash(request, "设备不存在", "danger")
        return RedirectResponse(back or "/admin/devices", status_code=303)
    if dev.status != "active":
        flash(request, "该设备已是解绑状态", "info")
        return RedirectResponse(back or "/admin/devices", status_code=303)
    dev_svc.unbind(db, dev)
    log_action(db, request, "device.unbind", dev.device_id, f"card_id={dev.card_id}")
    flash(request, "设备已解绑", "ok")
    return RedirectResponse(back or "/admin/devices", status_code=303)


@router.post("/{device_id}/delete")
def delete_device(
    device_id: int,
    request: Request,
    back: str = Form(""),
    admin: Admin = Depends(get_current_admin),
    db: Session = Depends(get_db),
):
    dev = db.get(Device, device_id)
    if dev:
        did = dev.device_id
        db.delete(dev)
        db.commit()
        log_action(db, request, "device.delete", did)
        flash(request, "设备记录已删除", "ok")
    return RedirectResponse(back or "/admin/devices", status_code=303)
