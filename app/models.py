from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from .database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_admin = Column(Boolean, default=False)
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