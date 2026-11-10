from datetime import datetime
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base

class PreKey(Base):
    __tablename__='prekeys'
    __table_args__=(UniqueConstraint('device_id','prekey_id',name='uq_prekey_device_id'),)
    id:Mapped[int]=mapped_column(Integer,primary_key=True,autoincrement=True)
    device_id:Mapped[str]=mapped_column(String(36),ForeignKey('devices.device_id',ondelete='CASCADE'),nullable=False,index=True)
    prekey_id:Mapped[int]=mapped_column(Integer,nullable=False)
    public_key:Mapped[str]=mapped_column(Text,nullable=False)
    signature:Mapped[str|None]=mapped_column(Text,nullable=True)
    kind:Mapped[str]=mapped_column(String(16),nullable=False,default='one_time')
    used:Mapped[bool]=mapped_column(Boolean,default=False,index=True)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),server_default=func.now(),index=True)

class PreKeyClaimLease(Base):
    __tablename__='prekey_claim_leases'
    __table_args__=(UniqueConstraint('requester_device_id','target_device_id',name='uq_prekey_claim_pair'),)
    id:Mapped[int]=mapped_column(Integer,primary_key=True,autoincrement=True)
    requester_device_id:Mapped[str]=mapped_column(String(36),ForeignKey('devices.device_id',ondelete='CASCADE'),nullable=False,index=True)
    target_device_id:Mapped[str]=mapped_column(String(36),ForeignKey('devices.device_id',ondelete='CASCADE'),nullable=False,index=True)
    prekey_id:Mapped[int]=mapped_column(Integer,nullable=False)
    expires_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),nullable=False,index=True)
    created_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),server_default=func.now())
