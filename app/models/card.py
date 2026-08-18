from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..database import Base


class CardType(Base):
    """A card template: 天卡/周卡/月卡/永久 (time) or 点卡 (count)."""

    __tablename__ = "card_types"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(16), default="time")  # time | count
    duration_minutes: Mapped[int] = mapped_column(Integer, default=0)
    is_permanent: Mapped[bool] = mapped_column(Boolean, default=False)
    total_count: Mapped[int] = mapped_column(Integer, default=0)  # for kind == count
    max_devices: Mapped[int] = mapped_column(Integer, default=1)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    remark: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    cards: Mapped[list["Card"]] = relationship(back_populates="type")

    @property
    def duration_label(self) -> str:
        if self.kind == "count":
            return f"{self.total_count} 次"
        if self.is_permanent:
            return "永久"
        m = self.duration_minutes
        if m % 1440 == 0:
            return f"{m // 1440} 天"
        if m % 60 == 0:
            return f"{m // 60} 小时"
        return f"{m} 分钟"


class Card(Base):
    __tablename__ = "cards"

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    type_id: Mapped[int] = mapped_column(ForeignKey("card_types.id"))
    # which software this card belongs to (nullable for legacy single-app cards)
    application_id: Mapped[int | None] = mapped_column(
        ForeignKey("applications.id"), nullable=True, index=True
    )
    # stored status: unused | active | banned  (expired/used_up are derived)
    status: Mapped[str] = mapped_column(String(16), default="unused", index=True)
    max_devices: Mapped[int] = mapped_column(Integer, default=1)
    remaining_count: Mapped[int] = mapped_column(Integer, default=0)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    batch_no: Mapped[str] = mapped_column(String(32), default="", index=True)
    remark: Mapped[str] = mapped_column(String(255), default="")
    created_by: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    type: Mapped["CardType"] = relationship(back_populates="cards")
    application: Mapped["Application | None"] = relationship(back_populates="cards")
    devices: Mapped[list["Device"]] = relationship(
        back_populates="card", cascade="all, delete-orphan"
    )

    @property
    def bound_count(self) -> int:
        return sum(1 for d in self.devices if d.status == "active")

    @property
    def effective_status(self) -> str:
        if self.status in ("banned", "unused"):
            return self.status
        # status == active
        if self.expires_at and datetime.now() >= self.expires_at:
            return "expired"
        if (
            self.type
            and self.type.kind == "count"
            and self.activated_at
            and self.remaining_count <= 0
        ):
            return "used_up"
        return "active"
