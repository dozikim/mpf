"""Application configuration.

All settings are read from the environment (prefix ``MPF_``) with sane
local-dev defaults so the app boots without a ``.env`` file. In production the
docker-compose stack injects ``MPF_DATABASE_URL`` / ``MPF_REDIS_URL`` /
``MPF_STORAGE_ROOT``.

The design goal (per the deployment decision) is: run against Postgres+Redis
when present, but degrade gracefully to SQLite + an eager in-process task
runner when they are not — so the backend and its test suite run anywhere.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Repo root is two levels up from this file: backend/app/core/config.py -> repo/
_REPO_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    """Typed application settings."""

    model_config = SettingsConfigDict(
        env_prefix="MPF_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- identity ---
    app_name: str = "MPF Analysis API"
    app_version: str = "2.0.0"
    environment: str = Field(default="development")

    # --- persistence ---
    # Default to a local SQLite file so `pytest`/`uvicorn` work with no services.
    database_url: str = Field(
        default=f"sqlite:///{_REPO_ROOT / 'backend' / 'mpf.db'}"
    )

    # --- redis / celery ---
    redis_url: str = Field(default="redis://localhost:6379/0")
    # When Redis/Celery are unavailable, run tasks eagerly in-process.
    celery_eager: bool = Field(default=False)

    # --- storage ---
    storage_root: Path = Field(default=_REPO_ROOT / "storage")

    # --- uploads ---
    max_upload_mb: int = Field(default=512)
    allowed_extensions: tuple[str, ...] = ("apk", "xapk", "apks")

    # --- caching ---
    cache_ttl_seconds: int = Field(default=300)

    # --- api ---
    api_prefix: str = "/api/v1"
    cors_origins: tuple[str, ...] = ("http://localhost:5173", "http://127.0.0.1:5173")

    # --- toolchain (absolute paths optional; falls back to PATH lookup) ---
    tool_apktool: str = "apktool"
    tool_jadx: str = "jadx"
    tool_aapt2: str = "aapt2"
    tool_apksigner: str = "apksigner"
    tool_dexdump: str = "dexdump"
    tool_strings: str = "strings"
    tool_keytool: str = "keytool"

    # Per-tool wall-clock budget (seconds) so a hostile APK can't hang a worker.
    tool_timeout_seconds: int = Field(default=1800)

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024

    @property
    def analyses_root(self) -> Path:
        return self.storage_root / "analyses"

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")


@lru_cache
def get_settings() -> Settings:
    """Return a process-wide cached Settings instance."""
    settings = Settings()
    settings.analyses_root.mkdir(parents=True, exist_ok=True)
    return settings


settings = get_settings()
