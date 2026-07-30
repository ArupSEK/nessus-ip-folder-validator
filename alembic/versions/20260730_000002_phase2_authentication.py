"""phase2 authentication foundation

Revision ID: 20260730_000002
Revises: 20260730_000001
Create Date: 2026-07-30
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20260730_000002"
down_revision = "20260730_000001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "roles",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=100), nullable=False, unique=True),
        sa.Column("description", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "permissions",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("code", sa.String(length=100), nullable=False, unique=True),
        sa.Column("description", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "users",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("username", sa.String(length=150), nullable=False, unique=True),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("is_superuser", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("failed_login_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "role_permissions",
        sa.Column("role_id", sa.String(length=36), sa.ForeignKey("roles.id"), primary_key=True),
        sa.Column("permission_id", sa.String(length=36), sa.ForeignKey("permissions.id"), primary_key=True),
    )
    op.create_table(
        "user_roles",
        sa.Column("user_id", sa.String(length=36), sa.ForeignKey("users.id"), primary_key=True),
        sa.Column("role_id", sa.String(length=36), sa.ForeignKey("roles.id"), primary_key=True),
    )
    op.create_table(
        "user_sessions",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("user_id", sa.String(length=36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("session_token_hash", sa.String(length=128), nullable=False, unique=True),
        sa.Column("csrf_token", sa.String(length=128), nullable=False),
        sa.Column("ip_address", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("user_agent", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "password_reset_tokens",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("user_id", sa.String(length=36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("token_hash", sa.String(length=128), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("actor_user_id", sa.String(length=36), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("action", sa.String(length=120), nullable=False),
        sa.Column("object_type", sa.String(length=120), nullable=False, server_default=""),
        sa.Column("object_id", sa.String(length=120), nullable=False, server_default=""),
        sa.Column("object_name", sa.String(length=255), nullable=False, server_default=""),
        sa.Column("source_ip", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("result", sa.String(length=32), nullable=False, server_default="success"),
        sa.Column("justification", sa.Text(), nullable=False, server_default=""),
        sa.Column("previous_state", sa.Text(), nullable=False, server_default=""),
        sa.Column("new_state", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_users_username", "users", ["username"], unique=True)
    op.create_index("ix_permissions_code", "permissions", ["code"], unique=True)
    op.create_index("ix_user_sessions_user_id", "user_sessions", ["user_id"], unique=False)
    op.create_index("ix_password_reset_tokens_user_id", "password_reset_tokens", ["user_id"], unique=False)
    op.create_index("ix_audit_events_action", "audit_events", ["action"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_audit_events_action", table_name="audit_events")
    op.drop_index("ix_password_reset_tokens_user_id", table_name="password_reset_tokens")
    op.drop_index("ix_user_sessions_user_id", table_name="user_sessions")
    op.drop_index("ix_permissions_code", table_name="permissions")
    op.drop_index("ix_users_username", table_name="users")
    op.drop_table("audit_events")
    op.drop_table("password_reset_tokens")
    op.drop_table("user_sessions")
    op.drop_table("user_roles")
    op.drop_table("role_permissions")
    op.drop_table("users")
    op.drop_table("permissions")
    op.drop_table("roles")
