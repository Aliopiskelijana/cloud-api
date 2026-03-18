from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import NullPool

Base = declarative_base()

_engine = None
_SessionLocal = None


def _make_pg8000_url(url: str) -> str:
    """Ensure SQLAlchemy uses pg8000 (pure-Python) driver, not psycopg2."""
    for prefix in ("postgresql://", "postgres://"):
        if url.startswith(prefix):
            return "postgresql+pg8000://" + url[len(prefix):]
    return url


def init_db():
    global _engine, _SessionLocal
    if _engine is not None:
        return  # already initialised (warm invocation)
    from app.config import settings
    url = _make_pg8000_url(settings.database_url)
    _engine = create_engine(url, poolclass=NullPool)
    _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_engine)
    Base.metadata.create_all(bind=_engine)


def get_engine():
    return _engine


def get_db():
    if _SessionLocal is None:
        init_db()
    db = _SessionLocal()
    try:
        yield db
    finally:
        db.close()
