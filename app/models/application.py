from datetime import datetime

from sqlalchemy import Boolean, DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..database import Base


class Application(Base):
    """A protected software product. Each app has an isolated card pool and its
    own K_payload, so a card issued for app A cannot unlock app B."""

    __tablename__ = "applications"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128))
    app_key: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    # base64 of 32 random bytes — this app's K_payload (server-side secret)
    payload_key_b64: Mapped[str] = mapped_column(String(64))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    remark: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    cards: Mapped[list["Card"]] = relationship(back_populates="application")
