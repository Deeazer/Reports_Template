"""Уязвимость: ссылки на угрозы БДУ и интерфейсы воздействия

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-26

Идемпотентна: столбцы добавляются только если их ещё нет (на случай БД,
где они уже появились через create_all прежней версии).
"""
from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def _existing_columns():
    bind = op.get_bind()
    return {c["name"] for c in sa.inspect(bind).get_columns("vulnerabilities")}


def upgrade():
    cols = _existing_columns()
    if "threat_codes" not in cols:
        op.add_column("vulnerabilities", sa.Column("threat_codes", sa.JSON()))
    if "interface_codes" not in cols:
        op.add_column("vulnerabilities", sa.Column("interface_codes", sa.JSON()))


def downgrade():
    cols = _existing_columns()
    if "interface_codes" in cols:
        op.drop_column("vulnerabilities", "interface_codes")
    if "threat_codes" in cols:
        op.drop_column("vulnerabilities", "threat_codes")
