"""Per-application visibility for admin accounts.

Super admins see everything. Operators (子账号) only see the applications
assigned to them on the 管理员 page — and, transitively, only the cards,
devices and logs that belong to those applications. Legacy cards with no
application are visible to super admins only.
"""
from fastapi import HTTPException
from sqlalchemy import false, select

from ..models import Admin, Application, AuthLog, Card
from .audit import log_action


def allowed_app_ids(admin: Admin) -> set[int] | None:
    """Application ids the admin may touch. None means unrestricted (super)."""
    if admin.role == "super":
        return None
    return {a.id for a in admin.applications}


def can_access_app(admin: Admin, app_id: int | None) -> bool:
    ids = allowed_app_ids(admin)
    if ids is None:
        return True
    return app_id is not None and app_id in ids


def can_access_card(admin: Admin, card: Card) -> bool:
    return can_access_app(admin, card.application_id)


def card_criterion(admin: Admin):
    """SQL filter restricting Card rows to the admin's applications.

    Returns None when no restriction applies; a criterion that matches nothing
    when the operator has no application assigned yet.
    """
    ids = allowed_app_ids(admin)
    if ids is None:
        return None
    if not ids:
        return false()
    return Card.application_id.in_(sorted(ids))


def authlog_criterion(admin: Admin):
    """AuthLog rows whose card belongs to one of the admin's applications."""
    crit = card_criterion(admin)
    if crit is None:
        return None
    return AuthLog.code.in_(select(Card.code).where(crit))


def scope_cards(query, admin: Admin):
    """Apply card_criterion() to a Query that selects from (or joins) Card."""
    crit = card_criterion(admin)
    return query if crit is None else query.filter(crit)


def visible_apps(db, admin: Admin, active_only: bool = False) -> list[Application]:
    q = db.query(Application)
    if active_only:
        q = q.filter_by(is_active=True)
    ids = allowed_app_ids(admin)
    if ids is not None:
        if not ids:
            return []
        q = q.filter(Application.id.in_(sorted(ids)))
    return q.order_by(Application.id.desc()).all()


def forbid(db, request, target: str = "", detail: str = "") -> None:
    """Audit-log a cross-application attempt, then abort with 403."""
    log_action(db, request, "access.denied", target, detail)
    raise HTTPException(status_code=403, detail="无权访问该应用的数据")
