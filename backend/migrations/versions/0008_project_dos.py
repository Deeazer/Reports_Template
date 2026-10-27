"""Тестирование отказа в обслуживании: данные раздела в проекте

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-27

Идемпотентна: столбец добавляется только если его ещё нет.
"""
from alembic import op
import sqlalchemy as sa

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def _cols(table):
    return {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade():
    if "dos" not in _cols("projects"):
        op.add_column("projects", sa.Column("dos", sa.JSON()))


def downgrade():
    if "dos" in _cols("projects"):
        op.drop_column("projects", "dos")
