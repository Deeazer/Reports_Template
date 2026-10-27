"""Анализ защищённости беспроводных сетей: данные раздела в проекте

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-27

Идемпотентна: столбец добавляется только если его ещё нет.
"""
from alembic import op
import sqlalchemy as sa

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def _cols(table):
    return {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade():
    if "wireless" not in _cols("projects"):
        op.add_column("projects", sa.Column("wireless", sa.JSON()))


def downgrade():
    if "wireless" in _cols("projects"):
        op.drop_column("projects", "wireless")
