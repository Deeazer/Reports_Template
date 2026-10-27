from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, ForeignKey, JSON, Boolean, Float
)
from sqlalchemy.orm import relationship
from .db import Base


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    login = Column(String(128), unique=True, nullable=False, index=True)
    full_name = Column(String(256), default="")
    position = Column(String(256), default="")
    password_hash = Column(String(256), nullable=False)
    role = Column(String(32), nullable=False, default="executor")  # admin | executor
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class Setting(Base):
    __tablename__ = "settings"
    key = Column(String(64), primary_key=True)
    value = Column(JSON, nullable=False)


class Project(Base):
    __tablename__ = "projects"
    id = Column(Integer, primary_key=True)
    name = Column(String(512), nullable=False)
    client_name = Column(String(512), default="")          # АО «...»
    client_requisites = Column(Text, default="")
    object_description = Column(Text, default="")          # 1.1
    test_methods = Column(JSON, default=list)              # ["black","grey"]
    work_types = Column(JSON, default=list)                # ["external","internal"]
    period_from = Column(String(32), default="")
    period_to = Column(String(32), default="")
    tech_sites = Column(Text, default="")                  # 1.3
    status = Column(String(32), default="draft")           # draft | in_progress | done
    # копии справочников на момент создания проекта (редактируемы в проекте)
    intruders = Column(JSON, default=list)
    interfaces = Column(JSON, default=list)
    threats = Column(JSON, default=list)
    tools = Column(JSON, default=list)
    executors = Column(JSON, default=list)                 # [{org,position,name}]
    # Приложение 1: {"ips": [{address, description}], "fqdns": [{name, description}],
    #                "segments": [{segment, purpose}]}
    scope = Column(JSON, default=dict)
    approvals = Column(JSON, default=list)                 # лист согласования [{side,org,position,name,date}]
    security_notes = Column(JSON, default=dict)            # 1.4.x: {work_type: {"advantages": [str]}}
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    vulns = relationship("Vulnerability", back_populates="project",
                         cascade="all, delete-orphan")
    members = relationship("ProjectMember", cascade="all, delete-orphan")


class ProjectMember(Base):
    """Доступ исполнителя к проекту (админ видит всё)."""
    __tablename__ = "project_members"
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"))
    user_id = Column(Integer, ForeignKey("users.id"))


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"))
    work_type = Column(String(32), nullable=False)         # external | internal
    order_index = Column(Integer, default=0)
    # ---- поля карточки (ввод) ----
    title = Column(String(1024), default="")
    description = Column(Text, default="")
    scope = Column(Text, default="")                       # Границы
    tools = Column(String(1024), default="")               # Инструменты
    detected_at = Column(String(64), default="")           # Время обнаружения
    cvss_vector = Column(String(256), default="")          # AV:N/AC:L/...
    intruder_models = Column(String(128), default="")      # Н1, Н2
    threat_codes = Column(JSON, default=list)              # ["У-01", ...] угрозы БДУ, реализуемые уязвимостью
    interface_codes = Column(JSON, default=list)           # ["И-01", ...] интерфейсы воздействия
    availability = Column(String(32), default="")          # для вероятности
    ease = Column(String(32), default="")                  # простота эксплуатации
    # показатели методики ФСТЭК (ключи из refdata)
    fstec_k = Column(String(32), default="")
    fstec_l = Column(String(32), default="")
    fstec_p = Column(String(32), default="")
    fstec_e = Column(String(32), default="")
    fstec_h = Column(String(32), default="")
    poc = Column(Text, default="")
    exploitation_result = Column(Text, default="")
    recommendations = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    project = relationship("Project", back_populates="vulns")
    images = relationship("VulnImage", back_populates="vuln",
                          cascade="all, delete-orphan", order_by="VulnImage.order_index")


class VulnImage(Base):
    __tablename__ = "vuln_images"
    id = Column(Integer, primary_key=True)
    vuln_id = Column(Integer, ForeignKey("vulnerabilities.id", ondelete="CASCADE"))
    filename = Column(String(512))                         # на диске
    orig_name = Column(String(512))
    caption = Column(String(1024), default="")             # «Рисунок X – ...»
    block = Column(String(32), default="poc")              # poc | result
    order_index = Column(Integer, default=0)

    vuln = relationship("Vulnerability", back_populates="images")
