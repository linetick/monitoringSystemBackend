from datetime import timedelta
from typing import List

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from . import auth, database, models, system
from .schemas import (
    AuditLogResponse,
    ProcessAction,
    ProcessActionResult,
    ProcessInfo,
    ServerMetrics,
    Token,
    UserCreate,
    UserResponse,
)
from .dependencies import get_current_user, get_current_admin_user

app = FastAPI(title="Server Monitoring System")

# --- Вспомогательная функция аудита ---
def log_action(db: Session, user: models.User, action: str, obj: str, ip: str, details: str = None):
    db.add(models.AuditLog(
        user_id=user.id,
        username=user.username,
        action=action,
        object_name=obj,
        ip_address=ip,
        details=details
    ))
    db.commit()

# --- Auth ---
@app.post("/token", response_model=Token)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(database.get_db)
):
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user",
        )
    access_token_expires = timedelta(minutes=auth.settings.access_token_expire_minutes)
    access_token = auth.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=UserResponse)
def read_users_me(current_user: models.User = Depends(get_current_user)):
    return current_user

# --- Metrics ---
@app.get("/metrics", response_model=ServerMetrics)
def get_metrics(current_user: models.User = Depends(get_current_user)):
    return system.get_server_metrics()

# --- Processes ---
@app.get("/processes", response_model=List[ProcessInfo])
def list_processes(
    filter_name: str = None,
    sort_by: str = "pid",
    current_user: models.User = Depends(get_current_user)
):
    return system.get_processes(filter_name, sort_by)

@app.post("/processes/{pid}", response_model=ProcessActionResult)
def control_process(
    pid: int,
    action_data: ProcessAction,
    request: Request,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_admin_user)
):
    if not action_data.confirm:
        raise HTTPException(status_code=400, detail="Confirmation required")
    
    client_ip = request.client.host
    try:
        result = system.manage_process(pid, action_data.action, action_data.priority)
        details = [
            f"action={result['action']}",
            f"process_name={result['process_name']}",
            f"affected_pids={','.join(map(str, result['affected_pids']))}",
        ]
        if result.get("previous_priority") is not None:
            details.append(f"previous_priority={result['previous_priority']}")
        if result.get("current_priority") is not None:
            details.append(f"current_priority={result['current_priority']}")
        log_action(db, current_user, "PROCESS_CONTROL", str(pid), client_ip, "; ".join(details))
        return result
    except HTTPException as exc:
        error_details = [f"action={action_data.action}", f"error={exc.detail}"]
        if action_data.priority is not None:
            error_details.append(f"priority={action_data.priority}")
        log_action(
            db,
            current_user,
            "PROCESS_CONTROL_FAILED",
            str(pid),
            client_ip,
            "; ".join(error_details),
        )
        raise
    except Exception as e:
        error_details = [f"action={action_data.action}", f"error={str(e)}"]
        if action_data.priority is not None:
            error_details.append(f"priority={action_data.priority}")
        log_action(
            db,
            current_user,
            "PROCESS_CONTROL_FAILED",
            str(pid),
            client_ip,
            "; ".join(error_details),
        )
        raise HTTPException(status_code=500, detail=str(e))

# --- User Management ---
@app.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(
    user: UserCreate,
    request: Request,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_admin_user)
):
    if db.query(models.User).filter(models.User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already registered")
    
    hashed_password = auth.get_password_hash(user.password)
    db_user = models.User(
        username=user.username,
        hashed_password=hashed_password,
        is_active=user.is_active,
        role=user.role.value,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    log_action(db, current_user, "CREATE_USER", user.username, request.client.host)
    return db_user

@app.get("/users", response_model=List[UserResponse])
def read_users(
    skip: int = 0, limit: int = 100,
    current_user: models.User = Depends(get_current_admin_user),
    db: Session = Depends(database.get_db)
):
    users = db.query(models.User).offset(skip).limit(limit).all()
    return users

@app.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    request: Request,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_admin_user)
):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    
    db.delete(user)
    db.commit()
    log_action(db, current_user, "DELETE_USER", user.username, request.client.host)
    return {"status": "success"}

# --- Audit ---
@app.get("/audit", response_model=List[AuditLogResponse])
def get_audit_log(
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_admin_user)
):
    logs = db.query(models.AuditLog).order_by(models.AuditLog.timestamp.desc()).limit(100).all()
    return logs
