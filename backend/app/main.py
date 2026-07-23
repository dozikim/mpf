"""FastAPI application entrypoint.

Wires the v1 router, CORS for the Vite dev server, structured logging, and a
health endpoint. Tables are created on startup when running against SQLite
(dev/test) so the app is usable without an explicit Alembic run; Postgres
deployments run ``alembic upgrade head`` via docker-compose.
"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.logging import configure_logging, get_logger
from app.db.session import Base, engine

configure_logging()
log = get_logger("api")


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="MPF — Android APK reverse-engineering & static-analysis API",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(api_router, prefix=settings.api_prefix)

    @app.on_event("startup")
    def _startup() -> None:
        if settings.is_sqlite:
            Base.metadata.create_all(engine)
        log.info("%s v%s started (db=%s)", settings.app_name,
                 settings.app_version,
                 "sqlite" if settings.is_sqlite else "postgres")

    @app.get("/health", tags=["meta"])
    def health() -> dict:
        return {"status": "ok", "service": "mpf-api", "version": settings.app_version}

    return app


app = create_app()
