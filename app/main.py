import csv
import json
from datetime import datetime, timedelta, timezone
from io import StringIO
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import StreamingResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from . import auth, database, models, system
from .audit import create_audit_entry, create_user_audit_entry
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
    create_user_audit_entry(
        db,
        user=user,
        action=action,
        object_name=obj,
        ip_address=ip,
        details=details,
    )


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


def build_audit_query(
    db: Session,
    username: str = None,
    action: str = None,
    object_name: str = None,
    ip_address: str = None,
    date_from: datetime = None,
    date_to: datetime = None,
):
    query = db.query(models.AuditLog)

    if username:
        query = query.filter(models.AuditLog.username.ilike(f"%{username.strip()}%"))
    if action:
        query = query.filter(models.AuditLog.action.ilike(f"%{action.strip()}%"))
    if object_name:
        query = query.filter(models.AuditLog.object_name.ilike(f"%{object_name.strip()}%"))
    if ip_address:
        query = query.filter(models.AuditLog.ip_address.ilike(f"%{ip_address.strip()}%"))
    if date_from:
        query = query.filter(models.AuditLog.timestamp >= date_from)
    if date_to:
        query = query.filter(models.AuditLog.timestamp <= date_to)

    return query.order_by(models.AuditLog.timestamp.desc())


def build_audit_filter_details(
    username: str = None,
    action: str = None,
    object_name: str = None,
    ip_address: str = None,
    date_from: datetime = None,
    date_to: datetime = None,
    limit: int = None,
    export_format: str = None,
) -> str:
    details = []
    if username:
        details.append(f"username={username}")
    if action:
        details.append(f"action={action}")
    if object_name:
        details.append(f"object_name={object_name}")
    if ip_address:
        details.append(f"ip_address={ip_address}")
    if date_from:
        details.append(f"date_from={date_from.isoformat()}")
    if date_to:
        details.append(f"date_to={date_to.isoformat()}")
    if limit is not None:
        details.append(f"limit={limit}")
    if export_format:
        details.append(f"format={export_format}")
    return "; ".join(details) if details else "no_filters"

# --- Auth ---
@app.post("/token", response_model=Token)
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(database.get_db)
):
    user = db.query(models.User).filter(models.User.username == form_data.username).first()
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        create_audit_entry(
            db,
            action="LOGIN_FAILED",
            object_name="/token",
            ip_address=request.client.host if request.client else None,
            username=form_data.username,
            details="reason=invalid_credentials",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        create_audit_entry(
            db,
            action="LOGIN_FAILED",
            object_name="/token",
            ip_address=request.client.host if request.client else None,
            username=user.username,
            user_id=user.id,
            details="reason=inactive_user",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user",
        )
    access_token_expires = timedelta(minutes=auth.settings.access_token_expire_minutes)
    access_token = auth.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    log_action(
        db,
        user,
        "LOGIN_SUCCESS",
        "/token",
        request.client.host if request.client else None,
        "token_type=bearer",
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=UserResponse)
def read_users_me(current_user: models.User = Depends(get_current_user)):
    return current_user


@app.post("/logout")
def logout(
    request: Request,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_user),
):
    log_action(
        db,
        current_user,
        "LOGOUT",
        "/logout",
        request.client.host if request.client else None,
        "mode=client_side_logout",
    )
    return {"status": "success", "message": "Logged out"}

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
    db.query(models.AuditLog).filter(models.AuditLog.user_id == user.id).update(
        {models.AuditLog.user_id: None},
        synchronize_session=False,
    )
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
    username: str = None,
    action: str = None,
    object_name: str = None,
    ip_address: str = None,
    date_from: datetime = None,
    date_to: datetime = None,
    limit: int = Query(100, ge=1, le=1000),
    request: Request = None,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_admin_user)
):
    logs = build_audit_query(
        db,
        username=username,
        action=action,
        object_name=object_name,
        ip_address=ip_address,
        date_from=date_from,
        date_to=date_to,
    ).limit(limit).all()
    if request is not None:
        log_action(
            db,
            current_user,
            "AUDIT_VIEW",
            "/audit",
            request.client.host if request.client else None,
            build_audit_filter_details(
                username=username,
                action=action,
                object_name=object_name,
                ip_address=ip_address,
                date_from=date_from,
                date_to=date_to,
                limit=limit,
            ),
        )
    return logs


@app.get("/audit/export")
def export_audit_log(
    format: str = Query("csv", regex="^(csv|json)$"),
    username: str = None,
    action: str = None,
    object_name: str = None,
    ip_address: str = None,
    date_from: datetime = None,
    date_to: datetime = None,
    limit: int = Query(1000, ge=1, le=5000),
    request: Request = None,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(get_current_admin_user),
):
    logs = build_audit_query(
        db,
        username=username,
        action=action,
        object_name=object_name,
        ip_address=ip_address,
        date_from=date_from,
        date_to=date_to,
    ).limit(limit).all()

    filename_suffix = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filter_details = build_audit_filter_details(
        username=username,
        action=action,
        object_name=object_name,
        ip_address=ip_address,
        date_from=date_from,
        date_to=date_to,
        limit=limit,
        export_format=format,
    )
    if request is not None:
        log_action(
            db,
            current_user,
            "AUDIT_EXPORT",
            "/audit/export",
            request.client.host if request.client else None,
            filter_details,
        )

    if format == "json":
        payload = jsonable_encoder([AuditLogResponse.from_orm(log) for log in logs])
        buffer = StringIO()
        buffer.write(json.dumps(payload, ensure_ascii=False, indent=2))
        buffer.seek(0)
        return StreamingResponse(
            buffer,
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="audit_logs_{filename_suffix}.json"'
            },
        )

    buffer = StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["id", "timestamp", "username", "action", "object_name", "ip_address", "details"])
    for log in logs:
        writer.writerow([
            log.id,
            log.timestamp.isoformat(),
            log.username,
            log.action,
            log.object_name,
            log.ip_address,
            log.details or "",
        ])
    buffer.seek(0)
    return StreamingResponse(
        buffer,
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="audit_logs_{filename_suffix}.csv"'
        },
    )
