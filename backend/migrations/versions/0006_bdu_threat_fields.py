"""Каталог угроз: интерфейсы, нарушители, свойства и последствия по данным БДУ

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-27

Заполняет пустые поля угроз (интерфейсы, нарушители, нарушаемые свойства,
последствия) в каталогах проектов и в каталоге по умолчанию по официальным
данным БДУ (thrlist.xlsx). Заполненные вручную значения не меняются.
"""
import json
from alembic import op
import sqlalchemy as sa
from app.refdata import complete_threats

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def _load(v):
    return json.loads(v) if isinstance(v, str) else v


def upgrade():
    bind = op.get_bind()
    for pid, threats in bind.execute(sa.text("SELECT id, threats FROM projects")).fetchall():
        threats = _load(threats) or []
        full = complete_threats(threats)
        if full != threats:
            bind.execute(sa.text("UPDATE projects SET threats = CAST(:t AS JSON) WHERE id = :id"),
                         {"t": json.dumps(full, ensure_ascii=False), "id": pid})
    row = bind.execute(sa.text("SELECT value FROM settings WHERE key = 'threats'")).fetchone()
    if row:
        threats = _load(row[0]) or []
        full = complete_threats(threats)
        if full != threats:
            bind.execute(sa.text("UPDATE settings SET value = CAST(:t AS JSON) WHERE key = 'threats'"),
                         {"t": json.dumps(full, ensure_ascii=False)})


def downgrade():
    pass  # заполненные значения не откатываются: их могли уже отредактировать
