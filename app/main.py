from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from .config import BASE_DIR, settings
from .database import SessionLocal, init_db
from .deps import AuthRequired
from .models import Admin
from .routers import api, applications, auth, cards, dashboard, devices, logs, system
from .security import hash_password
from .services import settings as settings_svc


def bootstrap_admin() -> None:
    """Create the first super admin when the admins table is empty."""
    db = SessionLocal()
    try:
        if not db.query(Admin.id).first():
            db.add(
                Admin(
                    username=settings.DEFAULT_ADMIN,
                    password_hash=hash_password(
                        settings.DEFAULT_ADMIN_PWD, settings.PWD_ITERATIONS
                    ),
                    nickname="超级管理员",
                    role="super",
                    is_active=True,
                )
            )
            db.commit()
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    bootstrap_admin()
    settings_svc.refresh_cache()
    from . import crypto

    crypto.ensure_keys()
    yield


app = FastAPI(title=settings.APP_NAME, debug=settings.DEBUG, lifespan=lifespan)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SECRET_KEY,
    session_cookie=settings.SESSION_COOKIE,
    same_site="lax",
    https_only=False,
)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "app" / "static")), name="static")


@app.exception_handler(AuthRequired)
async def _auth_required_handler(request: Request, exc: AuthRequired):
    # API callers get JSON 401; browser sessions are redirected to login.
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": "unauthorized"}, status_code=401)
    return RedirectResponse("/admin/login", status_code=303)


for r in (auth, dashboard, applications, cards, devices, logs, system, api):
    app.include_router(r.router)


@app.get("/")
def index():
    return RedirectResponse("/admin")
