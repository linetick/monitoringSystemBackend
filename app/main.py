from datetime import timedelta
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from . import auth, database, models, system
from .roles import UserRole
from .config import settings
from .schemas import (
    AuditLogResponse,
    ProcessAction,
    ProcessActionResult,
    ProcessInfo,
    ProcessSortField,
    ServerMetrics,
    SortDirection,
    Token,
    UserCreate,
    UserResponse,
    UserUpdate,
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


def get_user_or_404(db: Session, user_id: int) -> models.User:
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


def ensure_username_available(db: Session, username: str, exclude_user_id: int = None) -> None:
    query = db.query(models.User).filter(models.User.username == username)
    if exclude_user_id is not None:
        query = query.filter(models.User.id != exclude_user_id)
    if query.first():
        raise HTTPException(status_code=400, detail="Username already registered")


def build_user_audit_details(user: models.User) -> str:
    return f"username={user.username}; role={user.role}; is_active={user.is_active}"

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
    response: Response,
    filter_name: Optional[str] = Query(None, min_length=1, max_length=255),
    sort_by: ProcessSortField = ProcessSortField.PID,
    sort_direction: SortDirection = SortDirection.ASC,
    skip: int = Query(0, ge=0),
    limit: int = Query(
        settings.processes_default_limit,
        ge=1,
        le=settings.processes_max_limit,
    ),
    current_user: models.User = Depends(get_current_user)
):
    processes, total = system.get_processes(
        filter_name=filter_name,
        sort_by=sort_by.value,
        sort_direction=sort_direction.value,
        skip=skip,
        limit=limit,
    )
    response.headers["X-Total-Count"] = str(total)
    response.headers["X-Page-Skip"] = str(skip)
    response.headers["X-Page-Limit"] = str(limit)
    response.headers["X-Sort-By"] = sort_by.value
    response.headers["X-Sort-Direction"] = sort_direction.value
    return processes

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
    ensure_username_available(db, user.username)
    
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
    
    log_action(
        db,
        current_user,
        "CREATE_USER",
        user.username,
        request.client.host,
        build_user_audit_details(db_user),
    )
    return db_user

@app.get("/users", response_model=List[UserResponse])
def read_users(
    skip: int = 0, limit: int = 100,
    current_user: models.User = Depends(get_current_admin_user),
    db: Session = Depends(database.get_db)
):
    users = db.query(models.User).offset(skip).limit(limit).all()
    return users


@app.put("/users/{user_id}", response_model=UserResponse)
def update_user(
    user_id: int,
    user_update: UserUpdate,
    request: Request,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_admin_user),
):
    db_user = get_user_or_404(db, user_id)

    changed_fields = []

    if user_update.username is not None and user_update.username != db_user.username:
        ensure_username_available(db, user_update.username, exclude_user_id=db_user.id)
        db_user.username = user_update.username
        changed_fields.append(f"username={db_user.username}")

    if user_update.password is not None:
        db_user.hashed_password = auth.get_password_hash(user_update.password)
        changed_fields.append("password=updated")

    if user_update.role is not None:
        new_role = user_update.role.value
        if db_user.id == current_user.id and new_role != UserRole.ADMIN.value:
            raise HTTPException(status_code=400, detail="Cannot remove your own admin role")
        if new_role != db_user.role:
            db_user.role = new_role
            changed_fields.append(f"role={db_user.role}")

    if user_update.is_active is not None:
        if db_user.id == current_user.id and not user_update.is_active:
            raise HTTPException(status_code=400, detail="Cannot deactivate yourself")
        if user_update.is_active != db_user.is_active:
            db_user.is_active = user_update.is_active
            changed_fields.append(f"is_active={db_user.is_active}")

    if not changed_fields:
        raise HTTPException(status_code=400, detail="No changes provided")

    db.commit()
    db.refresh(db_user)

    log_action(
        db,
        current_user,
        "UPDATE_USER",
        db_user.username,
        request.client.host,
        "; ".join(changed_fields),
    )
    return db_user

@app.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    request: Request,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_admin_user)
):
    user = get_user_or_404(db, user_id)
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    
    deleted_username = user.username
    deleted_details = build_user_audit_details(user)
    db.delete(user)
    db.commit()
    log_action(
        db,
        current_user,
        "DELETE_USER",
        deleted_username,
        request.client.host,
        deleted_details,
    )
    return {"status": "success"}

# --- Audit ---
@app.get("/audit", response_model=List[AuditLogResponse])
def get_audit_log(
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_admin_user)
):
    logs = db.query(models.AuditLog).order_by(models.AuditLog.timestamp.desc()).limit(100).all()
    return logs
