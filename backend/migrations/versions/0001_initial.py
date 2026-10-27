"""Начальная схема (базовый релиз)

Revision ID: 0001
Revises:
Create Date: 2026-10-26
"""
from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("login", sa.String(length=128), nullable=False),
        sa.Column("full_name", sa.String(length=256)),
        sa.Column("position", sa.String(length=256)),
        sa.Column("password_hash", sa.String(length=256), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("is_active", sa.Boolean()),
        sa.Column("created_at", sa.DateTime()),
    )
    op.create_index("ix_users_login", "users", ["login"], unique=True)

    op.create_table(
        "settings",
        sa.Column("key", sa.String(length=64), primary_key=True),
        sa.Column("value", sa.JSON(), nullable=False),
    )

    op.create_table(
        "projects",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=512), nullable=False),
        sa.Column("client_name", sa.String(length=512)),
        sa.Column("client_requisites", sa.Text()),
        sa.Column("object_description", sa.Text()),
        sa.Column("test_methods", sa.JSON()),
        sa.Column("work_types", sa.JSON()),
        sa.Column("period_from", sa.String(length=32)),
        sa.Column("period_to", sa.String(length=32)),
        sa.Column("tech_sites", sa.Text()),
        sa.Column("status", sa.String(length=32)),
        sa.Column("intruders", sa.JSON()),
        sa.Column("interfaces", sa.JSON()),
        sa.Column("threats", sa.JSON()),
        sa.Column("tools", sa.JSON()),
        sa.Column("executors", sa.JSON()),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id")),
        sa.Column("created_at", sa.DateTime()),
        sa.Column("updated_at", sa.DateTime()),
    )

    op.create_table(
        "project_members",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id", ondelete="CASCADE")),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id")),
    )

    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id", ondelete="CASCADE")),
        sa.Column("work_type", sa.String(length=32), nullable=False),
        sa.Column("order_index", sa.Integer()),
        sa.Column("title", sa.String(length=1024)),
        sa.Column("description", sa.Text()),
        sa.Column("scope", sa.Text()),
        sa.Column("tools", sa.String(length=1024)),
        sa.Column("detected_at", sa.String(length=64)),
        sa.Column("cvss_vector", sa.String(length=256)),
        sa.Column("intruder_models", sa.String(length=128)),
        sa.Column("availability", sa.String(length=32)),
        sa.Column("ease", sa.String(length=32)),
        sa.Column("fstec_k", sa.String(length=32)),
        sa.Column("fstec_l", sa.String(length=32)),
        sa.Column("fstec_p", sa.String(length=32)),
        sa.Column("fstec_e", sa.String(length=32)),
        sa.Column("fstec_h", sa.String(length=32)),
        sa.Column("poc", sa.Text()),
        sa.Column("exploitation_result", sa.Text()),
        sa.Column("recommendations", sa.Text()),
        sa.Column("created_at", sa.DateTime()),
        sa.Column("updated_at", sa.DateTime()),
    )

    op.create_table(
        "vuln_images",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("vuln_id", sa.Integer(), sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE")),
        sa.Column("filename", sa.String(length=512)),
        sa.Column("orig_name", sa.String(length=512)),
        sa.Column("caption", sa.String(length=1024)),
        sa.Column("block", sa.String(length=32)),
        sa.Column("order_index", sa.Integer()),
    )


def downgrade():
    op.drop_table("vuln_images")
    op.drop_table("vulnerabilities")
    op.drop_table("project_members")
    op.drop_table("projects")
    op.drop_table("settings")
    op.drop_index("ix_users_login", table_name="users")
    op.drop_table("users")
