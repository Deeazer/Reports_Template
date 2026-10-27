"""Проект: границы исследования (Приложение 1), лист согласования, преимущества 1.4.x

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-27

Идемпотентна: столбцы добавляются только если их ещё нет.
"""
from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

COLUMNS = ("scope", "approvals", "security_notes")


def _existing_columns():
    bind = op.get_bind()
    return {c["name"] for c in sa.inspect(bind).get_columns("projects")}


def upgrade():
    cols = _existing_columns()
    for name in COLUMNS:
        if name not in cols:
            op.add_column("projects", sa.Column(name, sa.JSON()))


def downgrade():
    cols = _existing_columns()
    for name in reversed(COLUMNS):
        if name in cols:
            op.drop_column("projects", name)
