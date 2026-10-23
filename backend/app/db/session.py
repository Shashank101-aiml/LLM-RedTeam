"""
Database Engine, Session Local, and FastAPI Dependency.
"""

from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from app.core.config import settings

# SQLite configuration: check_same_thread=False allows multi-threaded test harnesses
connect_args = {"check_same_thread": False} if settings.SYNC_DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    settings.SYNC_DATABASE_URL,
    connect_args=connect_args,
    echo=settings.DEBUG,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """FastAPI request dependency yielding a managed database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Initializes database tables."""
    from app.db.base import Base
    import app.models  # noqa: F401 Ensure models are imported
    Base.metadata.create_all(bind=engine)
