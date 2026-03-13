"""Add explicit user roles and bootstrap schema with Alembic."""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "20260313_0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _table_names(bind) -> set[str]:
    inspector = sa.inspect(bind)
    return set(inspector.get_table_names())


def _column_names(bind, table_name: str) -> set[str]:
    inspector = sa.inspect(bind)
    return {column["name"] for column in inspector.get_columns(table_name)}


def _index_names(bind, table_name: str) -> set[str]:
    inspector = sa.inspect(bind)
    return {index["name"] for index in inspector.get_indexes(table_name)}


def _unique_constraint_names(bind, table_name: str) -> set[str]:
    inspector = sa.inspect(bind)
    return {constraint["name"] for constraint in inspector.get_unique_constraints(table_name)}


def upgrade() -> None:
    bind = op.get_bind()
    table_names = _table_names(bind)

    if "users" not in table_names:
        op.create_table(
            "users",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("username", sa.String(length=50), nullable=False),
            sa.Column("hashed_password", sa.String(length=255), nullable=False),
            sa.Column("role", sa.String(length=20), nullable=False, server_default="limited"),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.CheckConstraint("role IN ('admin', 'limited')", name="ck_users_role"),
        )
    else:
        user_columns = _column_names(bind, "users")

        if "role" not in user_columns:
            op.add_column(
                "users",
                sa.Column("role", sa.String(length=20), nullable=True, server_default="limited"),
            )

        refreshed_columns = _column_names(bind, "users")
        if "is_admin" in refreshed_columns:
            op.execute(
                sa.text(
                    "UPDATE users "
                    "SET role = CASE WHEN is_admin THEN 'admin' ELSE 'limited' END "
                    "WHERE role IS NULL OR role = 'limited'"
                )
            )
            op.drop_column("users", "is_admin")

        if "is_active" not in refreshed_columns:
            op.add_column(
                "users",
                sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
            )

        op.alter_column("users", "role", existing_type=sa.String(length=20), nullable=False)

    if "audit_logs" not in table_names:
        op.create_table(
            "audit_logs",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("timestamp", sa.DateTime(), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
            sa.Column("user_id", sa.Integer(), nullable=True),
            sa.Column("username", sa.String(length=50), nullable=False),
            sa.Column("action", sa.String(length=64), nullable=False),
            sa.Column("object_name", sa.String(length=128), nullable=False),
            sa.Column("ip_address", sa.String(length=45), nullable=False),
            sa.Column("details", sa.Text(), nullable=True),
            sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        )

    user_indexes = _index_names(bind, "users")
    user_unique_constraints = _unique_constraint_names(bind, "users")
    if "ix_users_username" not in user_indexes and "uq_users_username" not in user_unique_constraints:
        op.create_index("ix_users_username", "users", ["username"], unique=True)

    audit_indexes = _index_names(bind, "audit_logs")
    if "idx_audit_logs_timestamp" not in audit_indexes:
        op.create_index("idx_audit_logs_timestamp", "audit_logs", ["timestamp"], unique=False)
    if "idx_audit_logs_user_id" not in audit_indexes:
        op.create_index("idx_audit_logs_user_id", "audit_logs", ["user_id"], unique=False)
    if "idx_audit_logs_username" not in audit_indexes:
        op.create_index("idx_audit_logs_username", "audit_logs", ["username"], unique=False)
    if "idx_audit_logs_action" not in audit_indexes:
        op.create_index("idx_audit_logs_action", "audit_logs", ["action"], unique=False)


def downgrade() -> None:
    bind = op.get_bind()
    table_names = _table_names(bind)
    if "users" in table_names:
        user_columns = _column_names(bind, "users")
        if "is_admin" not in user_columns:
            op.add_column(
                "users",
                sa.Column("is_admin", sa.Boolean(), nullable=False, server_default=sa.false()),
            )
            op.execute(
                sa.text(
                    "UPDATE users SET is_admin = CASE WHEN role = 'admin' THEN TRUE ELSE FALSE END"
                )
            )
        if "role" in _column_names(bind, "users"):
            op.drop_column("users", "role")
