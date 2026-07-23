"""Database engine, session factory, and declarative base.

SQLAlchemy 2.0 style. The engine is built from ``settings.database_url`` and
transparently supports both PostgreSQL (production) and SQLite (local/tests).
"""
from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.core.config import settings


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


def _engine_kwargs() -> dict:
    kwargs: dict = {"pool_pre_ping": True, "future": True}
    if settings.is_sqlite:
        # Allow cross-thread use for the eager/test path; ignore pooling knobs.
        kwargs["connect_args"] = {"check_same_thread": False}
        kwargs.pop("pool_pre_ping", None)
    return kwargs


engine = create_engine(settings.database_url, **_engine_kwargs())

SessionLocal = sessionmaker(
    bind=engine, autoflush=False, autocommit=False, expire_on_commit=False,
    class_=Session,
)


def get_session() -> Iterator[Session]:
    """FastAPI dependency yielding a scoped DB session."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def session_scope() -> Session:
    """Return a raw session for use outside the request lifecycle (workers)."""
    return SessionLocal()
