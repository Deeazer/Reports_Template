"""ФИО пользователя, авторство изменений, журнал, социотехническое тестирование, OWASP

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-27

Идемпотентна: столбцы и таблицы создаются только если их ещё нет.
Существующее full_name раскладывается на фамилию, имя и отчество по пробелам.
"""
from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

USER_COLS = ("last_name", "first_name", "middle_name")


def _cols(table):
    return {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}


def _tables():
    return set(sa.inspect(op.get_bind()).get_table_names())


def _fk_users(name):
    return sa.Column(name, sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"))


def upgrade():
    bind = op.get_bind()
    cols = _cols("users")
    added = [c for c in USER_COLS if c not in cols]
    for name in added:
        op.add_column("users", sa.Column(name, sa.String(128), server_default=""))
    if added:
        rows = bind.execute(sa.text("SELECT id, full_name FROM users")).fetchall()
        for uid, full in rows:
            parts = (full or "").split()
            if len(parts) < 2:
                continue  # одно слово («Администратор») — не ФИО, оставляем как есть
            last, first, middle = (parts + ["", ""])[:3]
            if len(parts) > 3:
                middle = " ".join(parts[2:])
            bind.execute(sa.text("UPDATE users SET last_name=:l, first_name=:f, middle_name=:m WHERE id=:id"),
                         {"l": last, "f": first, "m": middle, "id": uid})

    cols = _cols("projects")
    if "social" not in cols:
        op.add_column("projects", sa.Column("social", sa.JSON()))
    if "updated_by" not in cols:
        op.add_column("projects", _fk_users("updated_by"))

    cols = _cols("vulnerabilities")
    for name in ("created_by", "updated_by"):
        if name not in cols:
            op.add_column("vulnerabilities", _fk_users(name))
    if "owasp" not in cols:
        op.add_column("vulnerabilities", sa.Column("owasp", sa.String(16), server_default=""))

    tables = _tables()
    if "project_images" not in tables:
        op.create_table(
            "project_images",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id", ondelete="CASCADE")),
            sa.Column("section", sa.String(128), nullable=False),
            sa.Column("filename", sa.String(512)),
            sa.Column("orig_name", sa.String(512)),
            sa.Column("caption", sa.String(1024), server_default=""),
            sa.Column("order_index", sa.Integer(), server_default="0"),
            sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL")),
            sa.Column("created_at", sa.DateTime()),
        )
    if "audit_log" not in tables:
        op.create_table(
            "audit_log",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("project_id", sa.Integer(), sa.ForeignKey("projects.id", ondelete="CASCADE"), index=True),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL")),
            sa.Column("user_name", sa.String(256), server_default=""),
            sa.Column("at", sa.DateTime(), index=True),
            sa.Column("entity", sa.String(32), nullable=False),
            sa.Column("entity_id", sa.Integer()),
            sa.Column("entity_title", sa.String(1024), server_default=""),
            sa.Column("action", sa.String(16), nullable=False),
            sa.Column("fields", sa.JSON()),
        )


def downgrade():
    tables = _tables()
    for t in ("audit_log", "project_images"):
        if t in tables:
            op.drop_table(t)
    cols = _cols("vulnerabilities")
    for name in ("owasp", "updated_by", "created_by"):
        if name in cols:
            op.drop_column("vulnerabilities", name)
    cols = _cols("projects")
    for name in ("updated_by", "social"):
        if name in cols:
            op.drop_column("projects", name)
    cols = _cols("users")
    for name in reversed(USER_COLS):
        if name in cols:
            op.drop_column("users", name)
