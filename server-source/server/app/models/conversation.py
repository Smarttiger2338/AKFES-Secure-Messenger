import uuid
from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class Conversation(Base):
    __tablename__ = "conversations"
    __table_args__ = (
        CheckConstraint("status IN ('pending','accepted','rejected','blocked')", name='ck_conversations_status'),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    type: Mapped[str] = mapped_column(String(16), nullable=False, default="direct")
    direct_key: Mapped[str | None] = mapped_column(String(64), nullable=True, unique=True, index=True)
    title: Mapped[str | None] = mapped_column(String(80), nullable=True)
    server_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("community_servers.id", ondelete="CASCADE"), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="accepted", server_default="accepted")
    requested_by_user_id: Mapped[str | None] = mapped_column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    members = relationship("ConversationMember", back_populates="conversation", cascade="all, delete-orphan")
    messages = relationship("Message", back_populates="conversation", cascade="all, delete-orphan")


class ConversationMember(Base):
    __tablename__ = "conversation_members"

    conversation_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("conversations.id", ondelete="CASCADE"), primary_key=True
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    joined_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    pinned: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    muted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    archived: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    last_read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    role: Mapped[str] = mapped_column(String(16), nullable=False, default="member", server_default="member")

    conversation = relationship("Conversation", back_populates="members")
