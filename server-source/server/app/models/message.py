import uuid
from datetime import datetime
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base

class Message(Base):
    __tablename__='messages'
    __table_args__=(UniqueConstraint('conversation_id','sender_device_id','recipient_device_id','ratchet_session_id','message_number',name='uq_message_ratchet_number_v4'),)
    id:Mapped[str]=mapped_column(String(36),primary_key=True,default=lambda:str(uuid.uuid4()))
    logical_message_id:Mapped[str]=mapped_column(String(36),nullable=False,default=lambda:str(uuid.uuid4()),index=True)
    conversation_id:Mapped[str]=mapped_column(String(36),ForeignKey('conversations.id',ondelete='CASCADE'),nullable=False,index=True)
    sender_device_id:Mapped[str]=mapped_column(String(36),ForeignKey('devices.device_id'),nullable=False,index=True)
    recipient_device_id:Mapped[str|None]=mapped_column(String(36),ForeignKey('devices.device_id'),nullable=True,index=True)
    ciphertext:Mapped[str]=mapped_column(Text,nullable=False)
    nonce:Mapped[str]=mapped_column(Text,nullable=False)
    e2ee_version:Mapped[int]=mapped_column(Integer,nullable=False,default=4)
    signed_prekey_id:Mapped[int|None]=mapped_column(Integer,nullable=True)
    one_time_prekey_id:Mapped[int|None]=mapped_column(Integer,nullable=True)
    message_number:Mapped[int|None]=mapped_column(Integer,nullable=True)
    ratchet_session_id:Mapped[str|None]=mapped_column(String(64),nullable=True,index=True)
    ephemeral_public_key:Mapped[str|None]=mapped_column(String(64),nullable=True)
    message_type:Mapped[str]=mapped_column(String(32),nullable=False,default='text')
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),server_default=func.now(),index=True)
    conversation=relationship('Conversation',back_populates='messages')
