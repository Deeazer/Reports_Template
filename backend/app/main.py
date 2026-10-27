import os
import time
import uuid
from datetime import datetime
from urllib.parse import quote
from fastapi import (FastAPI, Depends, HTTPException, status, UploadFile, File,
                     Form, Response, Body)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from sqlalchemy import text

from .db import Base, engine, get_db
from . import models, schemas, refdata, security, serializers, scoring, audit
from .crud_settings import get_all_settings, set_setting, fstec_settings
from .security import (current_user, require_admin, can_access_project,
                       hash_password, verify_password, create_token)
from .config import ADMIN_LOGIN, ADMIN_PASSWORD, UPLOAD_DIR
from .report import build_report

app = FastAPI(title="Генератор отчётов по пентесту", version="1.0")

app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
    allow_headers=["*"], allow_credentials=False,
)

os.makedirs(UPLOAD_DIR, exist_ok=True)


# --------------------------------------------------------------------------
# Инициализация БД + сид администратора (ждём поднятия postgres)
# --------------------------------------------------------------------------
@app.on_event("startup")
def startup():
    for attempt in range(30):
        try:
            with engine.connect() as c:
                c.execute(text("SELECT 1"))
            break
        except Exception:
            time.sleep(2)
    from .migrate import run_migrations
    run_migrations()
    from .db import SessionLocal
    db = SessionLocal()
    try:
        if not db.query(models.User).filter_by(login=ADMIN_LOGIN).first():
            db.add(models.User(login=ADMIN_LOGIN, full_name="Администратор",
                               password_hash=hash_password(ADMIN_PASSWORD), role="admin"))
            db.commit()
    finally:
        db.close()


@app.get("/api/health")
def health():
    return {"status": "ok"}


# --------------------------------------------------------------------------
# Auth
# --------------------------------------------------------------------------
@app.post("/api/auth/login", response_model=schemas.Token)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(models.User).filter_by(login=form.username).first()
    if not user or not verify_password(form.password, user.password_hash) or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Неверный логин или пароль")
    return schemas.Token(access_token=create_token(user), id=user.id, role=user.role,
                         full_name=user.short_name, login=user.login)


@app.get("/api/auth/me", response_model=schemas.UserOut)
def me(user: models.User = Depends(current_user)):
    return user


# --------------------------------------------------------------------------
# Users (админ)
# --------------------------------------------------------------------------
@app.get("/api/users", response_model=list[schemas.UserOut])
def list_users(db: Session = Depends(get_db), _: models.User = Depends(require_admin)):
    return db.query(models.User).order_by(models.User.id).all()


def _apply_name(u, last=None, first=None, middle=None, full=None):
    """Части ФИО задаются отдельно; full_name собирается из них.
    Если пришло только full_name (старый клиент), оно раскладывается по пробелам."""
    if last is None and first is None and middle is None and full is not None:
        parts = full.split()
        if len(parts) >= 2:
            last, first, middle = parts[0], parts[1], " ".join(parts[2:])
        else:
            u.last_name = u.first_name = u.middle_name = ""
            u.full_name = full.strip()
            return
    if last is not None: u.last_name = last.strip()
    if first is not None: u.first_name = first.strip()
    if middle is not None: u.middle_name = middle.strip()
    u.compose_full_name()


@app.post("/api/users", response_model=schemas.UserOut)
def create_user(data: schemas.UserCreate, db: Session = Depends(get_db),
                _: models.User = Depends(require_admin)):
    if db.query(models.User).filter_by(login=data.login).first():
        raise HTTPException(400, "Пользователь с таким логином уже существует")
    if data.role not in ("admin", "executor"):
        raise HTTPException(400, "Недопустимая роль")
    u = models.User(login=data.login, position=data.position,
                    role=data.role, password_hash=hash_password(data.password))
    has_parts = data.last_name or data.first_name or data.middle_name
    _apply_name(u, *( (data.last_name, data.first_name, data.middle_name, None) if has_parts
                      else (None, None, None, data.full_name)))
    if not u.full_name:
        raise HTTPException(400, "Укажите фамилию и имя пользователя")
    db.add(u); db.commit(); db.refresh(u)
    return u


@app.patch("/api/users/{uid}", response_model=schemas.UserOut)
def update_user(uid: int, data: schemas.UserUpdate, db: Session = Depends(get_db),
                _: models.User = Depends(require_admin)):
    u = db.get(models.User, uid)
    if not u:
        raise HTTPException(404, "Не найдено")
    if any(x is not None for x in (data.last_name, data.first_name, data.middle_name, data.full_name)):
        _apply_name(u, data.last_name, data.first_name, data.middle_name, data.full_name)
        if not u.full_name:
            raise HTTPException(400, "Укажите фамилию и имя пользователя")
    if data.position is not None: u.position = data.position
    if data.role is not None: u.role = data.role
    if data.is_active is not None: u.is_active = data.is_active
    if data.password: u.password_hash = hash_password(data.password)
    db.commit(); db.refresh(u)
    return u


@app.delete("/api/users/{uid}")
def delete_user(uid: int, db: Session = Depends(get_db),
                admin: models.User = Depends(require_admin)):
    u = db.get(models.User, uid)
    if not u:
        raise HTTPException(404, "Не найдено")
    if u.id == admin.id:
        raise HTTPException(400, "Нельзя удалить самого себя")
    # проекты пользователя остаются: снимаем назначения и авторство,
    # иначе внешние ключи не дадут удалить запись
    db.query(models.ProjectMember).filter_by(user_id=u.id).delete()
    db.query(models.Project).filter_by(created_by=u.id).update({"created_by": None})
    db.query(models.Project).filter_by(updated_by=u.id).update({"updated_by": None})
    db.query(models.Vulnerability).filter_by(created_by=u.id).update({"created_by": None})
    db.query(models.Vulnerability).filter_by(updated_by=u.id).update({"updated_by": None})
    db.query(models.ProjectImage).filter_by(created_by=u.id).update({"created_by": None})
    # в журнале остаётся снимок имени, ссылка на пользователя снимается
    db.query(models.AuditEntry).filter_by(user_id=u.id).update({"user_id": None})
    db.delete(u); db.commit()
    return {"ok": True}


# --------------------------------------------------------------------------
# Settings (чтение — любой авторизованный, запись — админ)
# --------------------------------------------------------------------------
@app.get("/api/settings")
def read_settings(db: Session = Depends(get_db), _: models.User = Depends(current_user)):
    data = get_all_settings(db)
    data.pop("bdu", None)   # перечень БДУ отдаётся отдельно (/api/bdu)
    return data


@app.put("/api/settings/{key}")
def write_setting(key: str, value: dict | list = Body(...), db: Session = Depends(get_db),
                  _: models.User = Depends(require_admin)):
    return {"key": key, "value": set_setting(db, key, value)}


def _bdu(db):
    """Перечень БДУ: загруженный администратором (thrlist.xlsx), иначе встроенный."""
    from .crud_settings import get_setting
    return get_setting(db, "bdu") or refdata.BDU


@app.get("/api/bdu")
def read_bdu(db: Session = Depends(get_db), _: models.User = Depends(current_user)):
    """Перечень угроз БДУ ФСТЭК России для подстановки наименований."""
    b = _bdu(db)
    return {"source": b.get("source"), "retrieved": b.get("retrieved"), "threats": b["threats"]}


@app.post("/api/settings/bdu-import")
def import_bdu(file: UploadFile = File(...), db: Session = Depends(get_db),
               admin: models.User = Depends(require_admin)):
    """Загрузка thrlist.xlsx с bdu.fstec.ru: обновляет перечень БДУ, дополняет каталог
    угроз по умолчанию и каталоги всех проектов (заполняются только пустые поля)."""
    from .bdu_import import parse_thrlist
    try:
        bdu = parse_thrlist(file.file.read())
    except Exception as e:
        raise HTTPException(400, f"Не удалось прочитать файл: {e}")
    set_setting(db, "bdu", bdu)
    settings = get_all_settings(db)
    set_setting(db, "threats", refdata.complete_threats(settings.get("threats"), bdu))
    changed = 0
    for p in db.query(models.Project):
        full = refdata.complete_threats(p.threats, bdu)
        if full != (p.threats or []):
            p.threats = full
            audit.log(db, admin, p.id, "project", p.id, "update", p.name, ["threats"])
            changed += 1
    db.commit()
    return {"ok": True, "threats": len(bdu["threats"]), "retrieved": bdu["retrieved"], "projects_updated": changed}


@app.get("/api/refdata")
def read_refdata(_: models.User = Depends(current_user)):
    """Справочники для форм (виды работ, методы, показатели ФСТЭК, уровни)."""
    return {
        "work_types": refdata.WORK_TYPES,
        "test_methods": refdata.TEST_METHODS,
        "severity_levels": refdata.SEVERITY_LEVELS,
        "levels3": refdata.LEVELS3,
        "risk_levels": refdata.RISK_LEVELS,
        "fstec": refdata.DEFAULT_SETTINGS["fstec"],
        "colors": refdata.COLORS,
        "cvss_metrics": _cvss_options(),
        "owasp_top10": refdata.OWASP_TOP10,
    }


def _cvss_options():
    return {
        "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
        "AC": {"L": "Low", "H": "High"},
        "PR": {"N": "None", "L": "Low", "H": "High"},
        "UI": {"N": "None", "R": "Required"},
        "S": {"U": "Unchanged", "C": "Changed"},
        "C": {"N": "None", "L": "Low", "H": "High"},
        "I": {"N": "None", "L": "Low", "H": "High"},
        "A": {"N": "None", "L": "Low", "H": "High"},
    }


# --------------------------------------------------------------------------
# Projects
# --------------------------------------------------------------------------
def _load_project(db, pid, user, need_write=False):
    p = db.get(models.Project, pid)
    if not p:
        raise HTTPException(404, "Проект не найден")
    if not can_access_project(db, user, p):
        raise HTTPException(403, "Нет доступа к проекту")
    return p


@app.get("/api/projects")
def list_projects(db: Session = Depends(get_db), user: models.User = Depends(current_user)):
    q = db.query(models.Project).order_by(models.Project.updated_at.desc())
    if user.role != "admin":
        ids = {m.project_id for m in db.query(models.ProjectMember).filter_by(user_id=user.id)}
        projects = [p for p in q if p.created_by == user.id or p.id in ids]
    else:
        projects = q.all()
    result = []
    for p in projects:
        d = serializers.project_dict(p, with_vulns=True, settings_fstec=fstec_settings(db))
        result.append({
            "id": d["id"], "name": d["name"], "client_name": d["client_name"],
            "work_types": d["work_types"], "status": d["status"],
            "updated_at": d["updated_at"], "vuln_count": len(d["vulns"]),
            "created_by": d["created_by"],
            "created_by_name": d["created_by_name"],
            "updated_by_name": d["updated_by_name"],
            "created_at": d["created_at"],
            "counts": d["summary"]["counts"],
        })
    return result


@app.post("/api/projects")
def create_project(data: schemas.ProjectCreate, db: Session = Depends(get_db),
                   user: models.User = Depends(current_user)):
    s = get_all_settings(db)
    work_types = refdata.enabled_work_types(data.work_types)
    if not work_types:
        raise HTTPException(400, "Выберите хотя бы один доступный вид работ")
    p = models.Project(
        name=data.name, client_name=data.client_name,
        work_types=work_types, test_methods=data.test_methods,
        tech_sites=refdata.DEFAULT_TECH_SITES,
        client_requisites="", created_by=user.id, updated_by=user.id,
        intruders=s.get("intruders", refdata.DEFAULT_INTRUDERS),
        # в проект копируются ВСЕ интерфейсы и весь каталог угроз;
        # интерфейсы редактируются вручную, актуальные угрозы (1.8.3)
        # формируются автоматически из уязвимостей, выбирающих угрозы каталога.
        interfaces=s.get("interfaces", refdata.DEFAULT_INTERFACES),
        threats=refdata.complete_threats(s.get("threats", refdata.DEFAULT_THREATS), _bdu(db)),
        tools=s.get("tools", refdata.DEFAULT_TOOLS),
        executors=[],
    )
    db.add(p); db.flush()
    audit.log(db, user, p.id, "project", p.id, "create", p.name)
    db.commit(); db.refresh(p)
    return serializers.project_dict(p, settings_fstec=fstec_settings(db))


@app.get("/api/projects/{pid}")
def get_project(pid: int, db: Session = Depends(get_db), user: models.User = Depends(current_user)):
    p = _load_project(db, pid, user)
    return serializers.project_dict(p, settings_fstec=fstec_settings(db))


@app.patch("/api/projects/{pid}")
def update_project(pid: int, data: schemas.ProjectUpdate, db: Session = Depends(get_db),
                   user: models.User = Depends(current_user)):
    p = _load_project(db, pid, user)
    payload = data.model_dump(exclude_unset=True)
    member_ids = payload.pop("member_ids", None)
    if "work_types" in payload:
        payload["work_types"] = refdata.enabled_work_types(payload["work_types"])
        if not payload["work_types"]:
            raise HTTPException(400, "Выберите хотя бы один доступный вид работ")
        added = set(payload["work_types"]) - set(p.work_types or [])
        if added and "interfaces" not in payload:
            payload["interfaces"] = _tag_interfaces(p.interfaces or [], added)
    changed = [k for k, v in payload.items() if getattr(p, k) != v]
    for k, v in payload.items():
        setattr(p, k, v)
    if member_ids is not None and (user.role == "admin" or p.created_by == user.id):
        old = {m.user_id for m in p.members}
        if old != set(member_ids):
            changed.append("member_ids")
        db.query(models.ProjectMember).filter_by(project_id=p.id).delete()
        for mid in member_ids:
            db.add(models.ProjectMember(project_id=p.id, user_id=mid))
    if changed:
        _touch(p, user)
        audit.log(db, user, p.id, "project", p.id, "update", p.name, changed)
    db.commit(); db.refresh(p)
    return serializers.project_dict(p, settings_fstec=fstec_settings(db))


def _tag_interfaces(interfaces, added_work_types):
    """При добавлении вида работ в проект отмечает его у интерфейсов проекта,
    которые относятся к нему в каталоге по умолчанию (по коду интерфейса)."""
    defaults = {i["code"]: set(i.get("work_types") or []) for i in refdata.DEFAULT_INTERFACES}
    out = []
    for i in interfaces:
        i = dict(i)
        wts = list(i.get("work_types") or [])
        for wt in added_work_types:
            if wt in defaults.get(i.get("code"), set()) and wt not in wts:
                wts.append(wt)
        if i.get("work_types") is not None or wts:
            i["work_types"] = wts
        out.append(i)
    return out


def _touch(p, user):
    """Отмечает, кто и когда последним менял проект (в том числе его уязвимости)."""
    p.updated_by = user.id
    p.updated_at = datetime.utcnow()


@app.post("/api/projects/{pid}/threats/complete")
def complete_project_threats(pid: int, db: Session = Depends(get_db),
                             user: models.User = Depends(current_user)):
    """Дополняет каталог угроз проекта всеми угрозами БДУ, которых в нём нет."""
    p = _load_project(db, pid, user)
    before = p.threats or []
    p.threats = refdata.complete_threats(before, _bdu(db))
    added = len(p.threats) - len(before)
    if p.threats != before:
        _touch(p, user)
        audit.log(db, user, p.id, "project", p.id, "update", p.name, ["threats"])
    db.commit(); db.refresh(p)
    out = serializers.project_dict(p, settings_fstec=fstec_settings(db))
    out["threats_added"] = added
    return out


@app.get("/api/projects/{pid}/history")
def project_history(pid: int, limit: int = 300, db: Session = Depends(get_db),
                    user: models.User = Depends(current_user)):
    _load_project(db, pid, user)
    q = (db.query(models.AuditEntry).filter_by(project_id=pid)
         .order_by(models.AuditEntry.at.desc(), models.AuditEntry.id.desc()).limit(min(limit, 1000)))
    return [audit.entry_dict(e) for e in q]


def _remove_upload_files(filenames):
    """Удаляет файлы скриншотов с диска (после удаления записей из БД)."""
    for fname in filenames:
        try:
            os.remove(os.path.join(UPLOAD_DIR, fname))
        except OSError:
            pass


@app.delete("/api/projects/{pid}")
def delete_project(pid: int, db: Session = Depends(get_db), user: models.User = Depends(current_user)):
    p = _load_project(db, pid, user)
    if user.role != "admin" and p.created_by != user.id:
        raise HTTPException(403, "Удалять проект может администратор или его создатель")
    files = [im.filename for v in p.vulns for im in v.images] + [im.filename for im in p.images]
    vulns = len(p.vulns)
    db.delete(p); db.commit()
    # файлы удаляются только после успешного удаления записей
    _remove_upload_files(files)
    return {"ok": True, "deleted": {"vulns": vulns, "images": len(files)}}


# --------------------------------------------------------------------------
# Vulnerabilities
# --------------------------------------------------------------------------
@app.post("/api/projects/{pid}/vulns")
def add_vuln(pid: int, data: schemas.VulnCreate, db: Session = Depends(get_db),
             user: models.User = Depends(current_user)):
    p = _load_project(db, pid, user)
    n = db.query(models.Vulnerability).filter_by(project_id=pid, work_type=data.work_type).count()
    v = models.Vulnerability(project_id=pid, order_index=n, created_by=user.id, updated_by=user.id,
                             **data.model_dump())
    db.add(v); db.flush()
    _touch(p, user)
    audit.log(db, user, pid, "vuln", v.id, "create", v.title)
    db.commit(); db.refresh(v)
    return serializers.vuln_dict(v, fstec_settings(db))


@app.patch("/api/vulns/{vid}")
def update_vuln(vid: int, data: schemas.VulnUpdate, db: Session = Depends(get_db),
                user: models.User = Depends(current_user)):
    v = db.get(models.Vulnerability, vid)
    if not v:
        raise HTTPException(404, "Уязвимость не найдена")
    p = _load_project(db, v.project_id, user)
    payload = data.model_dump(exclude_unset=True)
    changed = [k for k, val in payload.items() if getattr(v, k) != val]
    for k, val in payload.items():
        setattr(v, k, val)
    if changed:
        _vuln_changed(db, p, v, user, changed)
    db.commit(); db.refresh(v)
    out = serializers.vuln_dict(v, fstec_settings(db))
    out["auto_threat_codes"] = scoring.auto_threat_codes(out, v.project.threats or [])
    return out


def _vuln_changed(db, p, v, user, fields):
    v.updated_by = user.id
    v.updated_at = datetime.utcnow()
    _touch(p, user)
    audit.log(db, user, p.id, "vuln", v.id, "update", v.title, fields)


@app.delete("/api/vulns/{vid}")
def delete_vuln(vid: int, db: Session = Depends(get_db), user: models.User = Depends(current_user)):
    v = db.get(models.Vulnerability, vid)
    if not v:
        raise HTTPException(404, "Не найдено")
    p = _load_project(db, v.project_id, user)
    files = [im.filename for im in v.images]
    _touch(p, user)
    audit.log(db, user, p.id, "vuln", v.id, "delete", v.title)
    db.delete(v); db.commit()
    _remove_upload_files(files)
    return {"ok": True}


# --------------------------------------------------------------------------
# Images
# --------------------------------------------------------------------------
def _save_upload(file):
    ext = os.path.splitext(file.filename or "")[1].lower() or ".png"
    if ext not in (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"):
        raise HTTPException(400, "Недопустимый тип файла")
    fname = f"{uuid.uuid4().hex}{ext}"
    with open(os.path.join(UPLOAD_DIR, fname), "wb") as f:
        f.write(file.file.read())
    return fname


@app.post("/api/vulns/{vid}/images")
def upload_image(vid: int, block: str = Form("poc"), caption: str = Form(""),
                 file: UploadFile = File(...), db: Session = Depends(get_db),
                 user: models.User = Depends(current_user)):
    v = db.get(models.Vulnerability, vid)
    if not v:
        raise HTTPException(404, "Не найдено")
    p = _load_project(db, v.project_id, user)
    fname = _save_upload(file)
    n = db.query(models.VulnImage).filter_by(vuln_id=vid, block=block).count()
    im = models.VulnImage(vuln_id=vid, filename=fname, orig_name=file.filename,
                          caption=caption, block=block, order_index=n)
    db.add(im)
    _vuln_changed(db, p, v, user, ["images_" + block])
    db.commit(); db.refresh(im)
    return {"id": im.id, "caption": im.caption, "block": im.block,
            "order_index": im.order_index, "url": f"/api/images/{im.id}"}


@app.get("/api/images/{iid}")
def get_image(iid: int, db: Session = Depends(get_db)):
    im = db.get(models.VulnImage, iid)
    if not im:
        raise HTTPException(404, "Не найдено")
    path = os.path.join(UPLOAD_DIR, im.filename)
    if not os.path.exists(path):
        raise HTTPException(404, "Файл отсутствует")
    return FileResponse(path)


@app.patch("/api/images/{iid}")
def update_image(iid: int, caption: str = Form(None), order_index: int = Form(None),
                 db: Session = Depends(get_db), user: models.User = Depends(current_user)):
    im = db.get(models.VulnImage, iid)
    if not im:
        raise HTTPException(404, "Не найдено")
    v = db.get(models.Vulnerability, im.vuln_id)
    p = _load_project(db, v.project_id, user)
    if caption is not None: im.caption = caption
    if order_index is not None: im.order_index = order_index
    _vuln_changed(db, p, v, user, ["images_" + (im.block or "poc")])
    db.commit()
    return {"ok": True}


@app.delete("/api/images/{iid}")
def delete_image(iid: int, db: Session = Depends(get_db), user: models.User = Depends(current_user)):
    im = db.get(models.VulnImage, iid)
    if not im:
        raise HTTPException(404, "Не найдено")
    v = db.get(models.Vulnerability, im.vuln_id)
    p = _load_project(db, v.project_id, user)
    _vuln_changed(db, p, v, user, ["images_" + (im.block or "poc")])
    db.delete(im); db.commit()
    _remove_upload_files([im.filename])
    return {"ok": True}


# --------------------------------------------------------------------------
# Изображения разделов проекта (сценарии социотехнического тестирования)
# --------------------------------------------------------------------------
def _project_image_dict(im):
    return {"id": im.id, "section": im.section, "caption": im.caption,
            "order_index": im.order_index, "url": f"/api/project-images/{im.id}"}


@app.post("/api/projects/{pid}/images")
def upload_project_image(pid: int, section: str = Form(...), caption: str = Form(""),
                         file: UploadFile = File(...), db: Session = Depends(get_db),
                         user: models.User = Depends(current_user)):
    p = _load_project(db, pid, user)
    fname = _save_upload(file)
    n = db.query(models.ProjectImage).filter_by(project_id=pid, section=section).count()
    im = models.ProjectImage(project_id=pid, section=section, filename=fname, orig_name=file.filename,
                             caption=caption, order_index=n, created_by=user.id)
    db.add(im)
    _touch(p, user)
    audit.log(db, user, pid, "project", pid, "update", p.name, ["social_images"])
    db.commit(); db.refresh(im)
    return _project_image_dict(im)


@app.get("/api/project-images/{iid}")
def get_project_image(iid: int, db: Session = Depends(get_db)):
    im = db.get(models.ProjectImage, iid)
    path = os.path.join(UPLOAD_DIR, im.filename) if im else ""
    if not im or not os.path.exists(path):
        raise HTTPException(404, "Не найдено")
    return FileResponse(path)


@app.patch("/api/project-images/{iid}")
def update_project_image(iid: int, caption: str = Form(None), db: Session = Depends(get_db),
                         user: models.User = Depends(current_user)):
    im = db.get(models.ProjectImage, iid)
    if not im:
        raise HTTPException(404, "Не найдено")
    p = _load_project(db, im.project_id, user)
    if caption is not None:
        im.caption = caption
    _touch(p, user)
    audit.log(db, user, p.id, "project", p.id, "update", p.name, ["social_images"])
    db.commit()
    return {"ok": True}


@app.delete("/api/project-images/{iid}")
def delete_project_image(iid: int, db: Session = Depends(get_db), user: models.User = Depends(current_user)):
    im = db.get(models.ProjectImage, iid)
    if not im:
        raise HTTPException(404, "Не найдено")
    p = _load_project(db, im.project_id, user)
    _touch(p, user)
    audit.log(db, user, p.id, "project", p.id, "update", p.name, ["social_images"])
    db.delete(im); db.commit()
    _remove_upload_files([im.filename])
    return {"ok": True}


# --------------------------------------------------------------------------
# Генерация отчёта DOCX
# --------------------------------------------------------------------------
@app.get("/api/projects/{pid}/report")
def generate_report(pid: int, db: Session = Depends(get_db), user: models.User = Depends(current_user)):
    p = _load_project(db, pid, user)
    data = serializers.project_dict(p, settings_fstec=fstec_settings(db))
    settings = get_all_settings(db)
    # карта id изображения -> имя файла на диске (имена не отдаются в API)
    img_map = {im.id: im.filename
               for v in p.vulns for im in v.images}
    img_map.update({f"p{im.id}": im.filename for im in p.images})
    buffer = build_report(data, settings, UPLOAD_DIR, img_map)
    fname = f"Отчет_{(p.client_name or p.name or 'pentest')}".replace(" ", "_")[:80] + ".docx"
    headers = {"Content-Disposition": f"attachment; filename*=UTF-8''{quote(fname)}"}
    return StreamingResponse(
        buffer,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers=headers,
    )
