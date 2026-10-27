"""Каталог угроз: дополнение всеми угрозами БДУ ФСТЭК России

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-27

Дополняет каталог угроз каждого проекта и сохранённый в настройках каталог
по умолчанию недостающими угрозами БДУ (по номеру УБИ). Существующие записи
и их коды не меняются, поэтому ссылки из уязвимостей сохраняются.
"""
import json
from alembic import op
import sqlalchemy as sa
from app.refdata import complete_threats

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def _load(v):
    return json.loads(v) if isinstance(v, str) else v


def upgrade():
    bind = op.get_bind()
    for pid, threats in bind.execute(sa.text("SELECT id, threats FROM projects")).fetchall():
        threats = _load(threats) or []
        full = complete_threats(threats)
        if len(full) != len(threats):
            bind.execute(sa.text("UPDATE projects SET threats = CAST(:t AS JSON) WHERE id = :id"),
                         {"t": json.dumps(full, ensure_ascii=False), "id": pid})
    row = bind.execute(sa.text("SELECT value FROM settings WHERE key = 'threats'")).fetchone()
    if row:
        threats = _load(row[0]) or []
        full = complete_threats(threats)
        if len(full) != len(threats):
            bind.execute(sa.text("UPDATE settings SET value = CAST(:t AS JSON) WHERE key = 'threats'"),
                         {"t": json.dumps(full, ensure_ascii=False)})


def downgrade():
    pass  # добавленные угрозы не удаляются: на них могут ссылаться уязвимости
