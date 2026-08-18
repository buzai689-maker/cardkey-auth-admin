import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings:
    APP_NAME = os.getenv("APP_NAME", "卡密授权管理后台")
    # Session signing key. Override in production via env / .env.
    SECRET_KEY = os.getenv(
        "SECRET_KEY", "dev-insecure-secret-change-me-please-0123456789abcdef"
    )
    DATABASE_URL = os.getenv(
        "DATABASE_URL", f"sqlite:///{(BASE_DIR / 'data' / 'app.db').as_posix()}"
    )
    DEBUG = os.getenv("DEBUG", "1") == "1"
    SESSION_COOKIE = os.getenv("SESSION_COOKIE", "kmauth_session")
    PWD_ITERATIONS = int(os.getenv("PWD_ITERATIONS", "200000"))

    # First-run bootstrap super admin (only created when the admins table is empty).
    DEFAULT_ADMIN = os.getenv("DEFAULT_ADMIN", "admin")
    DEFAULT_ADMIN_PWD = os.getenv("DEFAULT_ADMIN_PWD", "admin888")

    PAGE_SIZE = int(os.getenv("PAGE_SIZE", "20"))


settings = Settings()
