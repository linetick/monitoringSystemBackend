from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from .database import Base
from .roles import UserRole

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default=UserRole.LIMITED.value)
    is_active = Column(Boolean, nullable=False, default=True)
    audit_logs = relationship("AuditLog", back_populates="user")

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    user_id = Column(Integer, ForeignKey("users.id"))
    username = Column(String) # Дублируем имя на случай удаления юзера
    action = Column(String)   # CREATE, DELETE, KILL_PROCESS, etc.
    object_name = Column(String) # PID, Username, etc.
    ip_address = Column(String)
    details = Column(Text, nullable=True)
    
    user = relationship("User", back_populates="audit_logs")
