from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..database import Base


class Device(Base):
    """A hardware/device binding of a card (device_id == 机器码)."""

    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(primary_key=True)
    card_id: Mapped[int] = mapped_column(ForeignKey("cards.id"))
    device_id: Mapped[str] = mapped_column(String(128), index=True)
    device_name: Mapped[str] = mapped_column(String(128), default="")
    status: Mapped[str] = mapped_column(String(16), default="active")  # active | unbound
    ip: Mapped[str] = mapped_column(String(64), default="")
    remark: Mapped[str] = mapped_column(String(255), default="")
    bound_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    last_active_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    unbound_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    card: Mapped["Card"] = relationship(back_populates="devices")
