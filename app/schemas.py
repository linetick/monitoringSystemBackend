from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List
from datetime import datetime

# --- Auth ---
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class UserLogin(BaseModel):
    username: str
    password: str

# --- Users ---
class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    is_admin: bool = False

class UserCreate(UserBase):
    password: str = Field(..., min_length=6, description="Password must be at least 6 characters")

class UserUpdate(BaseModel):
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    password: Optional[str] = Field(None, min_length=6)
    is_admin: Optional[bool] = None

class UserResponse(UserBase):
    id: int
    is_active: bool = True

    class Config:
        orm_mode = True

# --- Processes ---
class ProcessInfo(BaseModel):
    pid: int
    name: str
    cpu: float
    mem: float
    status: str
    owner: str

class ProcessAction(BaseModel):
    action: str = Field(..., pattern="^(kill|kill_tree|priority)$")
    priority: Optional[int] = Field(None, ge=-20, le=19)
    confirm: bool = Field(..., description="Must be true to confirm action")

# --- Metrics ---
class ServerMetrics(BaseModel):
    hostname: str
    cpu_percent: float
    mem_percent: float
    disk_percent: float
    last_update: float
    status: str
    alerts: List[str]

# --- Audit ---
class AuditLogResponse(BaseModel):
    id: int
    timestamp: datetime
    username: str
    action: str
    object_name: str
    ip_address: str
    details: Optional[str] = None

    class Config:
        orm_mode = True