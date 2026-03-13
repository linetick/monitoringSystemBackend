"""Initial schema for users and audit logs."""

from alembic import op
import sqlalchemy as sa


revision = "20260313_0001"
down_revision = None
branch_labels = None
depends_on = None


def _index_exists(indexes, target_name, columns=None):
    for index in indexes:
        if index["name"] == target_name:
            return True
        if columns and index.get("column_names") == columns:
            return True
    return False


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    op.execute(
        """
        CREATE OR REPLACE FUNCTION set_updated_at()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = CURRENT_TIMESTAMP;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )

    if "users" not in tables:
        op.create_table(
            "users",
            sa.Column("id", sa.Integer(), sa.Identity(), primary_key=True),
            sa.Column("username", sa.String(length=50), nullable=False),
            sa.Column("hashed_password", sa.String(length=255), nullable=False),
            sa.Column("is_admin", sa.Boolean(), nullable=False, server_default=sa.text("FALSE")),
            sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("TRUE")),
            sa.Column(
                "created_at",
                sa.DateTime(),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.UniqueConstraint("username", name="uq_users_username"),
        )
        op.create_index("idx_users_username", "users", ["username"], unique=False)
        op.create_index("idx_users_is_active", "users", ["is_active"], unique=False)
    else:
        user_columns = {column["name"] for column in inspector.get_columns("users")}
        user_indexes = inspector.get_indexes("users")
        user_uniques = inspector.get_unique_constraints("users")
        has_username_unique = any(
            constraint.get("column_names") == ["username"] for constraint in user_uniques
        ) or _index_exists(user_indexes, "ix_users_username", ["username"])

        if "is_active" not in user_columns:
            op.add_column(
                "users",
                sa.Column(
                    "is_active",
                    sa.Boolean(),
                    nullable=False,
                    server_default=sa.text("TRUE"),
                ),
            )
        if "created_at" not in user_columns:
            op.add_column(
                "users",
                sa.Column(
                    "created_at",
                    sa.DateTime(),
                    nullable=False,
                    server_default=sa.text("CURRENT_TIMESTAMP"),
                ),
            )
        if "updated_at" not in user_columns:
            op.add_column(
                "users",
                sa.Column(
                    "updated_at",
                    sa.DateTime(),
                    nullable=False,
                    server_default=sa.text("CURRENT_TIMESTAMP"),
                ),
            )

        op.execute("UPDATE users SET is_admin = FALSE WHERE is_admin IS NULL;")
        op.execute("UPDATE users SET is_active = TRUE WHERE is_active IS NULL;")
        op.execute("UPDATE users SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL;")
        op.execute("UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL;")

        op.alter_column(
            "users",
            "username",
            existing_type=sa.String(),
            type_=sa.String(length=50),
            nullable=False,
        )
        op.alter_column(
            "users",
            "hashed_password",
            existing_type=sa.String(),
            type_=sa.String(length=255),
            nullable=False,
        )
        op.alter_column(
            "users",
            "is_admin",
            existing_type=sa.Boolean(),
            nullable=False,
            server_default=sa.text("FALSE"),
        )
        op.alter_column(
            "users",
            "is_active",
            existing_type=sa.Boolean(),
            nullable=False,
            server_default=sa.text("TRUE"),
        )
        op.alter_column(
            "users",
            "created_at",
            existing_type=sa.DateTime(),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        )
        op.alter_column(
            "users",
            "updated_at",
            existing_type=sa.DateTime(),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        )

        if not has_username_unique:
            op.create_unique_constraint("uq_users_username", "users", ["username"])
        if not _index_exists(user_indexes, "idx_users_is_active", ["is_active"]):
            op.create_index("idx_users_is_active", "users", ["is_active"], unique=False)

    if "audit_logs" not in tables:
        op.create_table(
            "audit_logs",
            sa.Column("id", sa.Integer(), sa.Identity(), primary_key=True),
            sa.Column(
                "timestamp",
                sa.DateTime(),
                nullable=False,
                server_default=sa.text("CURRENT_TIMESTAMP"),
            ),
            sa.Column("user_id", sa.Integer(), nullable=True),
            sa.Column("username", sa.String(length=50), nullable=False),
            sa.Column("action", sa.String(length=64), nullable=False),
            sa.Column("object_name", sa.String(length=128), nullable=False),
            sa.Column("ip_address", sa.String(length=45), nullable=False),
            sa.Column("details", sa.Text(), nullable=True),
            sa.ForeignKeyConstraint(
                ["user_id"],
                ["users.id"],
                name="fk_audit_logs_user_id",
                ondelete="SET NULL",
            ),
        )
        op.create_index("idx_audit_logs_timestamp", "audit_logs", ["timestamp"], unique=False)
        op.create_index("idx_audit_logs_user_id", "audit_logs", ["user_id"], unique=False)
        op.create_index("idx_audit_logs_username", "audit_logs", ["username"], unique=False)
        op.create_index("idx_audit_logs_action", "audit_logs", ["action"], unique=False)
    else:
        audit_columns = {column["name"] for column in inspector.get_columns("audit_logs")}
        audit_indexes = inspector.get_indexes("audit_logs")

        op.execute("UPDATE audit_logs SET timestamp = CURRENT_TIMESTAMP WHERE timestamp IS NULL;")
        op.alter_column(
            "audit_logs",
            "timestamp",
            existing_type=sa.DateTime(),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        )
        op.alter_column(
            "audit_logs",
            "username",
            existing_type=sa.String(),
            type_=sa.String(length=50),
            nullable=False,
        )
        op.alter_column(
            "audit_logs",
            "action",
            existing_type=sa.String(),
            type_=sa.String(length=64),
            nullable=False,
        )
        op.alter_column(
            "audit_logs",
            "object_name",
            existing_type=sa.String(),
            type_=sa.String(length=128),
            nullable=False,
        )
        op.alter_column(
            "audit_logs",
            "ip_address",
            existing_type=sa.String(),
            type_=sa.String(length=45),
            nullable=False,
        )
        if "details" not in audit_columns:
            op.add_column("audit_logs", sa.Column("details", sa.Text(), nullable=True))
        if not _index_exists(audit_indexes, "idx_audit_logs_timestamp", ["timestamp"]):
            op.create_index("idx_audit_logs_timestamp", "audit_logs", ["timestamp"], unique=False)
        if not _index_exists(audit_indexes, "idx_audit_logs_user_id", ["user_id"]):
            op.create_index("idx_audit_logs_user_id", "audit_logs", ["user_id"], unique=False)
        if not _index_exists(audit_indexes, "idx_audit_logs_username", ["username"]):
            op.create_index("idx_audit_logs_username", "audit_logs", ["username"], unique=False)
        if not _index_exists(audit_indexes, "idx_audit_logs_action", ["action"]):
            op.create_index("idx_audit_logs_action", "audit_logs", ["action"], unique=False)

    op.execute(
        """
        DROP TRIGGER IF EXISTS trg_users_set_updated_at ON users;
        CREATE TRIGGER trg_users_set_updated_at
        BEFORE UPDATE ON users
        FOR EACH ROW
        EXECUTE FUNCTION set_updated_at();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_users_set_updated_at ON users;")
    op.drop_index("idx_audit_logs_action", table_name="audit_logs")
    op.drop_index("idx_audit_logs_username", table_name="audit_logs")
    op.drop_index("idx_audit_logs_user_id", table_name="audit_logs")
    op.drop_index("idx_audit_logs_timestamp", table_name="audit_logs")
    op.drop_table("audit_logs")
    op.drop_index("idx_users_is_active", table_name="users")
    op.drop_index("idx_users_username", table_name="users")
    op.drop_table("users")
    op.execute("DROP FUNCTION IF EXISTS set_updated_at();")
