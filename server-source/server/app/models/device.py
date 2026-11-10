import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class Device(Base):
    __tablename__ = "devices"

    device_id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    identity_public_key: Mapped[str] = mapped_column(Text, nullable=False)
    device_public_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    device_key_signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Public-only X25519 key used to wrap secret-chat content keys for this
    # device. The corresponding private key never leaves the client.
    secret_gate_public_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    secret_gate_key_signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Candidate keys are never exposed as trusted keys until the device is approved.
    pending_identity_public_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    pending_device_public_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    pending_device_key_signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    # The PIN-derived key is wrapped with an auth-only master-secret mask.
    # API nodes may read devices but cannot recover the challenge key.
    arduino_pin_key_wrapped: Mapped[str | None] = mapped_column(String(64), nullable=True)
    device_name: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="approved")
    session_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    key_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user = relationship("User", back_populates="devices")
