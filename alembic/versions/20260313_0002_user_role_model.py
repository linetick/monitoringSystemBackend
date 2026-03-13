"""Replace is_admin with explicit user roles."""

from alembic import op
import sqlalchemy as sa


revision = "20260313_0002"
down_revision = "20260313_0001"
branch_labels = None
depends_on = None


def _check_constraint_names(bind, table_name: str) -> set[str]:
    inspector = sa.inspect(bind)
    return {constraint["name"] for constraint in inspector.get_check_constraints(table_name)}


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "users" not in inspector.get_table_names():
        return

    user_columns = {column["name"] for column in inspector.get_columns("users")}
    if "role" not in user_columns:
        op.add_column(
            "users",
            sa.Column(
                "role",
                sa.String(length=20),
                nullable=True,
                server_default=sa.text("'limited'"),
            ),
        )
        user_columns.add("role")

    if "is_admin" in user_columns:
        op.execute(
            """
            UPDATE users
            SET role = CASE WHEN is_admin THEN 'admin' ELSE 'limited' END
            WHERE role IS NULL OR role = 'limited';
            """
        )
        op.drop_column("users", "is_admin")
    else:
        op.execute("UPDATE users SET role = 'limited' WHERE role IS NULL;")

    op.alter_column(
        "users",
        "role",
        existing_type=sa.String(length=20),
        nullable=False,
        server_default=sa.text("'limited'"),
    )

    if "ck_users_role" not in _check_constraint_names(bind, "users"):
        op.create_check_constraint(
            "ck_users_role",
            "users",
            "role IN ('admin', 'limited')",
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "users" not in inspector.get_table_names():
        return

    user_columns = {column["name"] for column in inspector.get_columns("users")}
    if "is_admin" not in user_columns:
        op.add_column(
            "users",
            sa.Column(
                "is_admin",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("FALSE"),
            ),
        )
        op.execute(
            """
            UPDATE users
            SET is_admin = CASE WHEN role = 'admin' THEN TRUE ELSE FALSE END;
            """
        )

    if "ck_users_role" in _check_constraint_names(bind, "users"):
        op.drop_constraint("ck_users_role", "users", type_="check")

    if "role" in {column["name"] for column in inspector.get_columns("users")}:
        op.drop_column("users", "role")
