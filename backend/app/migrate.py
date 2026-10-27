"""Применение миграций Alembic при старте приложения.

Поддерживает три случая:
- чистая БД: создаются все таблицы (upgrade head);
- БД, созданная до внедрения Alembic (есть таблицы, нет alembic_version):
  ставится «штамп» базовой ревизии 0001, затем применяются следующие;
- уже мигрированная БД: upgrade head ничего не делает.
"""
import os
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect
from .db import engine
from .config import DATABASE_URL

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _config() -> Config:
    cfg = Config(os.path.join(BASE_DIR, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(BASE_DIR, "migrations"))
    cfg.set_main_option("sqlalchemy.url", os.getenv("DATABASE_URL", DATABASE_URL))
    return cfg


def run_migrations():
    cfg = _config()
    insp = inspect(engine)
    has_version = insp.has_table("alembic_version")
    has_legacy = insp.has_table("users")
    if not has_version and has_legacy:
        # БД была создана прежней версией через create_all — помечаем её
        # базовой ревизией, чтобы следующие миграции добавили новые столбцы.
        command.stamp(cfg, "0001")
    command.upgrade(cfg, "head")
