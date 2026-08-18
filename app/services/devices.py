from datetime import datetime

from ..models import Device


def unbind(db, device: Device) -> None:
    device.status = "unbound"
    device.unbound_at = datetime.now()
    db.commit()


def edit(
    db,
    device: Device,
    device_name: str | None = None,
    remark: str | None = None,
    device_id: str | None = None,
) -> None:
    if device_name is not None:
        device.device_name = device_name
    if remark is not None:
        device.remark = remark
    if device_id is not None and device_id.strip():
        # 换绑: repoint this binding to a new machine code
        device.device_id = device_id.strip()
    db.commit()
