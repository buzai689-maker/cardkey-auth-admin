from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import BASE_DIR, settings

_is_sqlite = settings.DATABASE_URL.startswith("sqlite")
if _is_sqlite:
    (BASE_DIR / "data").mkdir(parents=True, exist_ok=True)

connect_args = {"check_same_thread": False} if _is_sqlite else {}
engine = create_engine(
    settings.DATABASE_URL, connect_args=connect_args, echo=False, future=True
)

if _is_sqlite:

    @event.listens_for(engine, "connect")
    def _sqlite_pragma(dbapi_conn, _rec):  # noqa: ANN001
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA journal_mode=WAL")
        cur.close()


SessionLocal = sessionmaker(
    bind=engine, autoflush=False, autocommit=False, expire_on_commit=False
)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    from . import models  # noqa: F401  (register mappers)

    Base.metadata.create_all(engine)
