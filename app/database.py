from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import NullPool

Base = declarative_base()

_engine = None
_SessionLocal = None


def init_db():
    global _engine, _SessionLocal
    from app.config import settings
    _engine = create_engine(
        settings.database_url,
        poolclass=NullPool,
        connect_args={"connect_timeout": 10} if "postgresql" in settings.database_url else {},
    )
    _SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=_engine)


def get_engine():
    return _engine


def get_db():
    db = _SessionLocal()
    try:
        yield db
    finally:
        db.close()
