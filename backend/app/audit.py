"""Журнал изменений проекта.

Автосохранение в интерфейсе шлёт правки по одному полю, поэтому подряд идущие
изменения одного объекта одним пользователем объединяются в одну запись
(в пределах MERGE_WINDOW), а список изменённых полей накапливается.
"""
from datetime import datetime, timedelta
from . import models

MERGE_WINDOW = timedelta(minutes=10)


def log(db, user, project_id, entity, entity_id, action, title="", fields=None):
    fields = sorted(set(fields or []))
    now = datetime.utcnow()
    if action == "update":
        last = (db.query(models.AuditEntry)
                .filter_by(project_id=project_id)
                .order_by(models.AuditEntry.id.desc()).first())
        if (last and last.action in ("update", "create") and last.entity == entity
                and last.entity_id == entity_id and last.user_id == user.id
                and now - last.at < MERGE_WINDOW):
            if last.action == "update":
                last.fields = sorted(set(last.fields or []) | set(fields))
            last.at = now
            last.entity_title = title or last.entity_title
            return last
    e = models.AuditEntry(project_id=project_id, user_id=user.id, user_name=user.short_name,
                          at=now, entity=entity, entity_id=entity_id, entity_title=title or "",
                          action=action, fields=fields)
    db.add(e)
    return e


def entry_dict(e):
    return {"id": e.id, "at": e.at.isoformat() if e.at else None, "user_id": e.user_id,
            "user_name": e.user_name, "entity": e.entity, "entity_id": e.entity_id,
            "entity_title": e.entity_title, "action": e.action, "fields": e.fields or []}
