"""Ensure audit_logs.user_id uses ON DELETE SET NULL."""

from alembic import op
import sqlalchemy as sa


revision = "20260313_0003"
down_revision = "20260313_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    if "users" not in tables or "audit_logs" not in tables:
        return

    foreign_keys = inspector.get_foreign_keys("audit_logs")
    user_foreign_keys = [
        foreign_key
        for foreign_key in foreign_keys
        if foreign_key.get("referred_table") == "users"
        and foreign_key.get("constrained_columns") == ["user_id"]
    ]

    has_expected_fk = any(
        (foreign_key.get("options") or {}).get("ondelete") == "SET NULL"
        for foreign_key in user_foreign_keys
    )
    if has_expected_fk:
        return

    for foreign_key in user_foreign_keys:
        if foreign_key.get("name"):
            op.drop_constraint(foreign_key["name"], "audit_logs", type_="foreignkey")

    op.create_foreign_key(
        "fk_audit_logs_user_id",
        "audit_logs",
        "users",
        ["user_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    if "users" not in tables or "audit_logs" not in tables:
        return

    foreign_keys = inspector.get_foreign_keys("audit_logs")
    for foreign_key in foreign_keys:
        if foreign_key.get("referred_table") == "users" and foreign_key.get("constrained_columns") == ["user_id"]:
            if foreign_key.get("name"):
                op.drop_constraint(foreign_key["name"], "audit_logs", type_="foreignkey")

    op.create_foreign_key(
        "audit_logs_user_id_fkey",
        "audit_logs",
        "users",
        ["user_id"],
        ["id"],
    )
