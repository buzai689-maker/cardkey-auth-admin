from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


class AuthLog(Base):
    """Client-side verification API events (activate / verify / unbind)."""

    __tablename__ = "auth_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(64), default="", index=True)
    device_id: Mapped[str] = mapped_column(String(128), default="")
    action: Mapped[str] = mapped_column(String(32), default="")
    success: Mapped[bool] = mapped_column(Boolean, default=False)
    message: Mapped[str] = mapped_column(String(255), default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), index=True
    )


class AuditLog(Base):
    """Admin backend action trail."""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    admin_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    admin_name: Mapped[str] = mapped_column(String(64), default="")
    action: Mapped[str] = mapped_column(String(64), default="")
    target: Mapped[str] = mapped_column(String(128), default="")
    detail: Mapped[str] = mapped_column(String(512), default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), index=True
    )
