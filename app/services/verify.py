from datetime import datetime, timedelta

from ..models import AuthLog, Card, Device
from ..utils import client_ip
from . import settings as settings_svc


def _log(db, request, code, device_id, action, success, message) -> None:
    db.add(
        AuthLog(
            code=code or "",
            device_id=device_id or "",
            action=action,
            success=success,
            message=message,
            ip=client_ip(request),
        )
    )
    db.commit()


def _compute_expiry(card: Card):
    t = card.type
    if t.kind == "time" and not t.is_permanent and t.duration_minutes > 0:
        return datetime.now() + timedelta(minutes=t.duration_minutes)
    return None  # permanent time card or count card


def _find_card(db, code: str) -> Card | None:
    return db.query(Card).filter_by(code=code).first()


def activate(db, request, code: str, device_id: str, device_name: str = ""):
    """First-use activation + device binding. Returns (ok, message, card)."""
    card = _find_card(db, code)
    if not card:
        _log(db, request, code, device_id, "activate", False, "card not found")
        return False, "卡密不存在", None
    if not device_id:
        _log(db, request, code, device_id, "activate", False, "no device_id")
        return False, "缺少设备标识", None
    if card.status == "banned":
        _log(db, request, code, device_id, "activate", False, "banned")
        return False, "卡密已封禁", None
    if card.effective_status == "expired":
        _log(db, request, code, device_id, "activate", False, "expired")
        return False, "卡密已过期", None

    dev = (
        db.query(Device)
        .filter_by(card_id=card.id, device_id=device_id, status="active")
        .first()
    )
    if not dev:
        if settings_svc.get("auto_bind_on_activate", "1") != "1":
            _log(db, request, code, device_id, "activate", False, "device not bound")
            return False, "设备未绑定,请联系管理员", None
        active_bindings = [d for d in card.devices if d.status == "active"]
        if len(active_bindings) >= card.max_devices:
            _log(db, request, code, device_id, "activate", False, "device limit")
            return False, "设备数已达上限", None
        dev = Device(
            device_id=device_id,
            device_name=device_name,
            ip=client_ip(request),
            status="active",
            last_active_at=datetime.now(),
        )
        # append to the relationship (not bare db.add) so card.bound_count is
        # fresh in the same request that returns the newly bound device.
        card.devices.append(dev)
    else:
        dev.last_active_at = datetime.now()
        if device_name:
            dev.device_name = device_name

    if card.status == "unused":
        card.status = "active"
        card.activated_at = datetime.now()
        card.expires_at = _compute_expiry(card)

    db.commit()
    _log(db, request, code, device_id, "activate", True, "ok")
    return True, "激活成功", card


def verify(db, request, code: str, device_id: str, *, action: str = "verify", log_success: bool = True):
    """Validity check for an already-bound device (login / heartbeat).

    `action` labels the AuthLog entry; `log_success` can be turned off so a
    frequent heartbeat only records failures (revoked/expired/unbound) instead
    of flooding the log with successes.
    """
    card = _find_card(db, code)
    if not card:
        _log(db, request, code, device_id, action, False, "card not found")
        return False, "卡密不存在", None
    if card.status == "banned":
        _log(db, request, code, device_id, action, False, "banned")
        return False, "卡密已封禁", None
    eff = card.effective_status
    if eff == "expired":
        _log(db, request, code, device_id, action, False, "expired")
        return False, "卡密已过期", None
    if eff == "used_up":
        _log(db, request, code, device_id, action, False, "used up")
        return False, "点数已用尽", None
    if eff == "unused":
        _log(db, request, code, device_id, action, False, "not activated")
        return False, "卡密尚未激活", None

    dev = (
        db.query(Device)
        .filter_by(card_id=card.id, device_id=device_id, status="active")
        .first()
    )
    if not dev:
        _log(db, request, code, device_id, action, False, "device not bound")
        return False, "设备未绑定", None

    dev.last_active_at = datetime.now()
    db.commit()
    if log_success:
        _log(db, request, code, device_id, action, True, "ok")
    return True, "验证通过", card


def self_unbind(db, request, code: str, device_id: str):
    """Client-initiated unbind, gated by the allow_self_unbind setting."""
    if settings_svc.get("allow_self_unbind", "0") != "1":
        _log(db, request, code, device_id, "unbind", False, "self-unbind disabled")
        return False, "未开放自助解绑", None
    card = _find_card(db, code)
    if not card:
        _log(db, request, code, device_id, "unbind", False, "card not found")
        return False, "卡密不存在", None
    dev = (
        db.query(Device)
        .filter_by(card_id=card.id, device_id=device_id, status="active")
        .first()
    )
    if not dev:
        _log(db, request, code, device_id, "unbind", False, "device not bound")
        return False, "设备未绑定", None
    dev.status = "unbound"
    dev.unbound_at = datetime.now()
    db.commit()
    _log(db, request, code, device_id, "unbind", True, "ok")
    return True, "解绑成功", card
