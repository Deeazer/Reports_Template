import os
import time
import uuid
from urllib.parse import quote
from fastapi import (FastAPI, Depends, HTTPException, status, UploadFile, File,
                     Form, Response)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from sqlalchemy import text

from .db import Base, engine, get_db
from . import models, schemas, refdata, security, serializers, scoring
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
    return schemas.Token(access_token=create_token(user), role=user.role,
                         full_name=user.full_name or user.login, login=user.login)


@app.get("/api/auth/me", response_model=schemas.UserOut)
def me(user: models.User = Depends(current_user)):
    return user


# --------------------------------------------------------------------------
# Users (админ)
# --------------------------------------------------------------------------
@app.get("/api/users", response_model=list[schemas.UserOut])
def list_users(db: Session = Depends(get_db), _: models.User = Depends(require_admin)):
    return db.query(models.User).order_by(models.User.id).all()


@app.post("/api/users", response_model=schemas.UserOut)
def create_user(data: schemas.UserCreate, db: Session = Depends(get_db),
                _: models.User = Depends(require_admin)):
    if db.query(models.User).filter_by(login=data.login).first():
        raise HTTPException(400, "Пользователь с таким логином уже существует")
    if data.role not in ("admin", "executor"):
        raise HTTPException(400, "Недопустимая роль")
    u = models.User(login=data.login, full_name=data.full_name, position=data.position,
                    role=data.role, password_hash=hash_password(data.password))
    db.add(u); db.commit(); db.refresh(u)
    return u


@app.patch("/api/users/{uid}", response_model=schemas.UserOut)
def update_user(uid: int, data: schemas.UserUpdate, db: Session = Depends(get_db),
                _: models.User = Depends(require_admin)):
    u = db.get(models.User, uid)
    if not u:
        raise HTTPException(404, "Не найдено")
    if data.full_name is not None: u.full_name = data.full_name
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
    db.delete(u); db.commit()
    return {"ok": True}


# --------------------------------------------------------------------------
# Settings (чтение — любой авторизованный, запись — админ)
# --------------------------------------------------------------------------
@app.get("/api/settings")
def read_settings(db: Session = Depends(get_db), _: models.User = Depends(current_user)):
    return get_all_settings(db)


@app.put("/api/settings/{key}")
def write_setting(key: str, value: dict | list, db: Session = Depends(get_db),
                  _: models.User = Depends(require_admin)):
    return {"key": key, "value": set_setting(db, key, value)}


_BDU = __import__("json").load(open(os.path.join(os.path.dirname(__file__), "bdu.json"), encoding="utf-8"))


@app.get("/api/bdu")
def read_bdu(_: models.User = Depends(current_user)):
    """Перечень угроз БДУ ФСТЭК России (УБИ.001–УБИ.227) для подстановки наименований."""
    return _BDU


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
        client_requisites="", created_by=user.id,
        intruders=s.get("intruders", refdata.DEFAULT_INTRUDERS),
        # в проект копируются ВСЕ интерфейсы и весь каталог угроз;
        # интерфейсы редактируются вручную, актуальные угрозы (1.8.3)
        # формируются автоматически из уязвимостей, выбирающих угрозы каталога.
        interfaces=s.get("interfaces", refdata.DEFAULT_INTERFACES),
        threats=s.get("threats", refdata.DEFAULT_THREATS),
        tools=s.get("tools", refdata.DEFAULT_TOOLS),
        executors=[],
    )
    db.add(p); db.commit(); db.refresh(p)
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
    for k, v in payload.items():
        setattr(p, k, v)
    if member_ids is not None and (user.role == "admin" or p.created_by == user.id):
        db.query(models.ProjectMember).filter_by(project_id=p.id).delete()
        for mid in member_ids:
            db.add(models.ProjectMember(project_id=p.id, user_id=mid))
    db.commit(); db.refresh(p)
    return serializers.project_dict(p, settings_fstec=fstec_settings(db))


@app.delete("/api/projects/{pid}")
def delete_project(pid: int, db: Session = Depends(get_db), user: models.User = Depends(current_user)):
    p = _load_project(db, pid, user)
    if user.role != "admin" and p.created_by != user.id:
        raise HTTPException(403, "Удалять проект может администратор или его создатель")
    db.delete(p); db.commit()
    return {"ok": True}


# --------------------------------------------------------------------------
# Vulnerabilities
# --------------------------------------------------------------------------
@app.post("/api/projects/{pid}/vulns")
def add_vuln(pid: int, data: schemas.VulnCreate, db: Session = Depends(get_db),
             user: models.User = Depends(current_user)):
    p = _load_project(db, pid, user)
    n = db.query(models.Vulnerability).filter_by(project_id=pid, work_type=data.work_type).count()
    v = models.Vulnerability(project_id=pid, order_index=n, **data.model_dump())
    db.add(v); db.commit(); db.refresh(v)
    return serializers.vuln_dict(v, fstec_settings(db))


@app.patch("/api/vulns/{vid}")
def update_vuln(vid: int, data: schemas.VulnUpdate, db: Session = Depends(get_db),
                user: models.User = Depends(current_user)):
    v = db.get(models.Vulnerability, vid)
    if not v:
        raise HTTPException(404, "Уязвимость не найдена")
    _load_project(db, v.project_id, user)
    for k, val in data.model_dump(exclude_unset=True).items():
        setattr(v, k, val)
    db.commit(); db.refresh(v)
    out = serializers.vuln_dict(v, fstec_settings(db))
    out["auto_threat_codes"] = scoring.auto_threat_codes(out, v.project.threats or [])
    return out


@app.delete("/api/vulns/{vid}")
def delete_vuln(vid: int, db: Session = Depends(get_db), user: models.User = Depends(current_user)):
    v = db.get(models.Vulnerability, vid)
    if not v:
        raise HTTPException(404, "Не найдено")
    _load_project(db, v.project_id, user)
    db.delete(v); db.commit()
    return {"ok": True}


# --------------------------------------------------------------------------
# Images
# --------------------------------------------------------------------------
@app.post("/api/vulns/{vid}/images")
def upload_image(vid: int, block: str = Form("poc"), caption: str = Form(""),
                 file: UploadFile = File(...), db: Session = Depends(get_db),
                 user: models.User = Depends(current_user)):
    v = db.get(models.Vulnerability, vid)
    if not v:
        raise HTTPException(404, "Не найдено")
    _load_project(db, v.project_id, user)
    ext = os.path.splitext(file.filename or "")[1].lower() or ".png"
    if ext not in (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"):
        raise HTTPException(400, "Недопустимый тип файла")
    fname = f"{uuid.uuid4().hex}{ext}"
    with open(os.path.join(UPLOAD_DIR, fname), "wb") as f:
        f.write(file.file.read())
    n = db.query(models.VulnImage).filter_by(vuln_id=vid, block=block).count()
    im = models.VulnImage(vuln_id=vid, filename=fname, orig_name=file.filename,
                          caption=caption, block=block, order_index=n)
    db.add(im); db.commit(); db.refresh(im)
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
    _load_project(db, v.project_id, user)
    if caption is not None: im.caption = caption
    if order_index is not None: im.order_index = order_index
    db.commit()
    return {"ok": True}


@app.delete("/api/images/{iid}")
def delete_image(iid: int, db: Session = Depends(get_db), user: models.User = Depends(current_user)):
    im = db.get(models.VulnImage, iid)
    if not im:
        raise HTTPException(404, "Не найдено")
    v = db.get(models.Vulnerability, im.vuln_id)
    _load_project(db, v.project_id, user)
    try:
        os.remove(os.path.join(UPLOAD_DIR, im.filename))
    except OSError:
        pass
    db.delete(im); db.commit()
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
    buffer = build_report(data, settings, UPLOAD_DIR, img_map)
    fname = f"Отчет_{(p.client_name or p.name or 'pentest')}".replace(" ", "_")[:80] + ".docx"
    headers = {"Content-Disposition": f"attachment; filename*=UTF-8''{quote(fname)}"}
    return StreamingResponse(
        buffer,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers=headers,
    )
