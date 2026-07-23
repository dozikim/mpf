"""Redis-backed response cache with a safe no-op fallback.

The API caches expensive derived responses (file trees, directory listings,
search results) keyed by analysis id. When Redis is unreachable the cache
degrades to a null implementation so the app keeps working (just uncached).
"""
from __future__ import annotations

import json
from typing import Any

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger("cache")

try:  # redis is optional at runtime
    import redis as _redis
except Exception:  # pragma: no cover
    _redis = None


class Cache:
    """Thin JSON cache over Redis with graceful degradation."""

    def __init__(self, url: str, ttl: int) -> None:
        self._ttl = ttl
        self._client = None
        if _redis is None:
            log.warning("redis library missing; cache disabled")
            return
        try:
            self._client = _redis.Redis.from_url(url, decode_responses=True)
            self._client.ping()
            log.info("cache connected: %s", url)
        except Exception as exc:  # noqa: BLE001
            log.warning("redis unavailable (%s); cache disabled", exc)
            self._client = None

    @property
    def enabled(self) -> bool:
        return self._client is not None

    def get(self, key: str) -> Any | None:
        if not self._client:
            return None
        try:
            raw = self._client.get(key)
            return json.loads(raw) if raw is not None else None
        except Exception:  # noqa: BLE001
            return None

    def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        if not self._client:
            return
        try:
            self._client.set(key, json.dumps(value, default=str),
                             ex=ttl or self._ttl)
        except Exception:  # noqa: BLE001
            pass

    def invalidate_prefix(self, prefix: str) -> None:
        """Delete every key under ``prefix`` (used when an analysis changes)."""
        if not self._client:
            return
        try:
            for key in self._client.scan_iter(match=f"{prefix}*"):
                self._client.delete(key)
        except Exception:  # noqa: BLE001
            pass


cache = Cache(settings.redis_url, settings.cache_ttl_seconds)
