import datetime
import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from .config import JWT_SECRET, JWT_ALG, JWT_TTL_HOURS
from .db import get_db
from . import models

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except ValueError:
        return False


def create_token(user: "models.User") -> str:
    exp = datetime.datetime.utcnow() + datetime.timedelta(hours=JWT_TTL_HOURS)
    payload = {"sub": str(user.id), "role": user.role, "login": user.login, "exp": exp}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def current_user(token: str = Depends(oauth2_scheme),
                 db: Session = Depends(get_db)) -> "models.User":
    cred_err = HTTPException(status.HTTP_401_UNAUTHORIZED, "Недействительный токен",
                             headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        uid = int(payload["sub"])
    except (jwt.PyJWTError, KeyError, ValueError):
        raise cred_err
    user = db.get(models.User, uid)
    if not user or not user.is_active:
        raise cred_err
    return user


def require_admin(user: "models.User" = Depends(current_user)) -> "models.User":
    if user.role != "admin":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Требуются права администратора")
    return user


def can_access_project(db: Session, user: "models.User", project: "models.Project") -> bool:
    if user.role == "admin":
        return True
    if project.created_by == user.id:
        return True
    member = (db.query(models.ProjectMember)
              .filter_by(project_id=project.id, user_id=user.id).first())
    return member is not None
