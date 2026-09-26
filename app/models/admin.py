from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, Table, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..database import Base

# Which applications an operator account may work with. Super admins are not
# listed here — they implicitly own every application.
admin_applications = Table(
    "admin_applications",
    Base.metadata,
    Column("admin_id", ForeignKey("admins.id", ondelete="CASCADE"), primary_key=True),
    Column(
        "application_id",
        ForeignKey("applications.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


class Admin(Base):
    __tablename__ = "admins"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    nickname: Mapped[str] = mapped_column(String(64), default="")
    role: Mapped[str] = mapped_column(String(16), default="operator")  # super | operator
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_login_ip: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    # Applications this operator is allowed to see / issue cards for.
    applications: Mapped[list["Application"]] = relationship(
        secondary=admin_applications, back_populates="admins"
    )

    @property
    def is_super(self) -> bool:
        return self.role == "super"
