from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field, root_validator, validator

from .roles import UserRole

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
    role: UserRole = UserRole.LIMITED

    @validator("username")
    def normalize_username(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("username must not be empty")
        if any(character.isspace() for character in normalized):
            raise ValueError("username must not contain whitespace")
        return normalized

class UserCreate(UserBase):
    password: str = Field(..., min_length=6, description="Password must be at least 6 characters")
    is_active: bool = True

class UserUpdate(BaseModel):
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    password: Optional[str] = Field(None, min_length=6)
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None

    @validator("username")
    def normalize_optional_username(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        normalized = value.strip()
        if not normalized:
            raise ValueError("username must not be empty")
        if any(character.isspace() for character in normalized):
            raise ValueError("username must not contain whitespace")
        return normalized

class UserResponse(UserBase):
    id: int
    is_active: bool
    created_at: datetime
    updated_at: datetime

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

    @root_validator
    def validate_priority_for_action(cls, values):
        action = values.get("action")
        priority = values.get("priority")

        if action == "priority" and priority is None:
            raise ValueError("priority is required when action='priority'")
        if action in {"kill", "kill_tree"} and priority is not None:
            raise ValueError("priority is only allowed when action='priority'")
        return values


class ProcessActionResult(BaseModel):
    status: str
    message: str
    pid: int
    action: str
    process_name: str
    affected_pids: List[int]
    previous_priority: Optional[int] = None
    current_priority: Optional[int] = None

# --- Metrics ---
class ServerMetrics(BaseModel):
    hostname: str
    cpu_percent: float
    mem_percent: float
    disk_percent: float
    last_update: datetime
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
