import uuid
from datetime import datetime
from sqlalchemy import Boolean, DateTime, String, Text, func, true
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base

class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    nickname: Mapped[str | None] = mapped_column(String(64), nullable=True)
    bio: Mapped[str | None] = mapped_column(String(160), nullable=True)
    status_text: Mapped[str | None] = mapped_column(String(48), nullable=True)
    accent_color: Mapped[str | None] = mapped_column(String(7), nullable=True)
    profile_visibility: Mapped[str | None] = mapped_column(String(16), nullable=True)
    discoverable_by_username: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=true())
    share_read_receipts: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=true())
    share_typing_indicators: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=true())
    avatar_data_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    cover_data_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    email: Mapped[str | None] = mapped_column(String(254), unique=True, nullable=True)
    email_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    phone_e164: Mapped[str | None] = mapped_column(String(20), unique=True, nullable=True)
    phone_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    devices = relationship("Device", back_populates="user", cascade="all, delete-orphan")
