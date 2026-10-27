import os

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg://pentest:pentest@db:5432/pentest",
)
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-in-production-please-32chars-min")
JWT_ALG = "HS256"
JWT_TTL_HOURS = int(os.getenv("JWT_TTL_HOURS", "12"))

ADMIN_LOGIN = os.getenv("ADMIN_LOGIN", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin")  # сменить при первом входе

UPLOAD_DIR = os.getenv("UPLOAD_DIR", "/data/uploads")
