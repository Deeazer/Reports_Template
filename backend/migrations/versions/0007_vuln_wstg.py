"""Привязка уязвимостей к категориям OWASP WSTG (веб-приложения)

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-27

Идемпотентна: столбец добавляется только если его ещё нет.
"""
from alembic import op
import sqlalchemy as sa

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def _cols(table):
    return {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade():
    if "wstg" not in _cols("vulnerabilities"):
        op.add_column("vulnerabilities", sa.Column("wstg", sa.String(16), server_default=""))


def downgrade():
    if "wstg" in _cols("vulnerabilities"):
        op.drop_column("vulnerabilities", "wstg")
