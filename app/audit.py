from typing import Optional

from sqlalchemy.orm import Session

from . import models


def create_audit_entry(
    db: Session,
    *,
    action: str,
    object_name: str,
    ip_address: Optional[str],
    username: str,
    user_id: Optional[int] = None,
    details: Optional[str] = None,
) -> models.AuditLog:
    entry = models.AuditLog(
        user_id=user_id,
        username=username,
        action=action,
        object_name=object_name,
        ip_address=ip_address or "unknown",
        details=details,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


def create_user_audit_entry(
    db: Session,
    *,
    user: models.User,
    action: str,
    object_name: str,
    ip_address: Optional[str],
    details: Optional[str] = None,
) -> models.AuditLog:
    return create_audit_entry(
        db,
        action=action,
        object_name=object_name,
        ip_address=ip_address,
        username=user.username,
        user_id=user.id,
        details=details,
    )


def safe_create_audit_entry(
    db: Session,
    *,
    action: str,
    object_name: str,
    ip_address: Optional[str],
    username: str,
    user_id: Optional[int] = None,
    details: Optional[str] = None,
) -> None:
    try:
        create_audit_entry(
            db,
            action=action,
            object_name=object_name,
            ip_address=ip_address,
            username=username,
            user_id=user_id,
            details=details,
        )
    except Exception:
        db.rollback()
