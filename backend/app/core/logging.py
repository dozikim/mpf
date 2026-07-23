"""Structured logging setup.

A single ``configure_logging`` call installs a consistent formatter across the
API process and the Celery workers. ``get_logger`` returns namespaced loggers
(``mpf.pipeline.jadx`` etc.) so log lines are greppable per subsystem.
"""
from __future__ import annotations

import logging
import sys

_CONFIGURED = False

_FORMAT = "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"


def configure_logging(level: int = logging.INFO) -> None:
    """Install a stream handler on the root ``mpf`` logger (idempotent)."""
    global _CONFIGURED
    if _CONFIGURED:
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(_FORMAT))
    root = logging.getLogger("mpf")
    root.setLevel(level)
    root.addHandler(handler)
    root.propagate = False
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Return a logger under the ``mpf`` namespace."""
    configure_logging()
    return logging.getLogger(f"mpf.{name}")
