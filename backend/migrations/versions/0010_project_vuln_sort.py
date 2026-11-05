"""Режим сортировки уязвимостей по видам работ в проекте

Revision ID: 0010
Revises: 0009
Create Date: 2026-11-05

Идемпотентна: столбец добавляется только если его ещё нет.
"""
from alembic import op
import sqlalchemy as sa

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def _cols(table):
    return {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade():
    if "vuln_sort" not in _cols("projects"):
        op.add_column("projects", sa.Column("vuln_sort", sa.JSON()))


def downgrade():
    if "vuln_sort" in _cols("projects"):
        op.drop_column("projects", "vuln_sort")
