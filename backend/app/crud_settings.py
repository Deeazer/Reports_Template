from sqlalchemy.orm import Session
from . import models, refdata


def get_all_settings(db: Session) -> dict:
    rows = db.query(models.Setting).all()
    data = {r.key: r.value for r in rows}
    # значения по умолчанию, если в БД ещё нет
    for key, default in refdata.DEFAULT_SETTINGS.items():
        data.setdefault(key, default)
    return data


def get_setting(db: Session, key: str):
    row = db.get(models.Setting, key)
    if row:
        return row.value
    return refdata.DEFAULT_SETTINGS.get(key)


def set_setting(db: Session, key: str, value):
    row = db.get(models.Setting, key)
    if row:
        row.value = value
    else:
        db.add(models.Setting(key=key, value=value))
    db.commit()
    return value


def fstec_settings(db: Session):
    return get_setting(db, "fstec") or refdata.DEFAULT_SETTINGS["fstec"]
