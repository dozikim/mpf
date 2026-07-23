"""Security primitives.

The file-browsing features expose decompiled artifacts on disk. Every path
that originates from a client (tree navigation, ``?path=`` query params, file
downloads) MUST be resolved through :func:`safe_join` so a crafted value such
as ``../../etc/passwd`` or an absolute path can never escape the analysis's
own storage directory.

Server filesystem paths are never returned to clients; the API only ever
exposes *relative* paths rooted at an analysis directory.
"""
from __future__ import annotations

from pathlib import Path


class PathTraversalError(ValueError):
    """Raised when a client-supplied path escapes its permitted base."""


def safe_join(base: Path, *parts: str) -> Path:
    """Resolve ``parts`` under ``base``, refusing any escape.

    Returns the resolved absolute path. Raises :class:`PathTraversalError` if
    the result would fall outside ``base`` (via ``..``, an absolute component,
    or a symlink pointing out of the tree).
    """
    base_resolved = base.resolve()
    # Reject absolute components and empty/whitespace segments up front.
    candidate = base_resolved
    for raw in parts:
        rel = (raw or "").strip().replace("\\", "/")
        # Strip a leading slash so callers can pass "/java/Foo.java" ergonomically.
        rel = rel.lstrip("/")
        if not rel:
            continue
        candidate = candidate / rel

    resolved = candidate.resolve()
    if resolved != base_resolved and base_resolved not in resolved.parents:
        raise PathTraversalError(
            f"resolved path escapes its permitted base: {parts!r}"
        )
    return resolved


def to_relative(base: Path, target: Path) -> str:
    """Return ``target`` as a POSIX relative path under ``base``.

    Used to build the client-facing path strings; never leaks the absolute
    server location.
    """
    return target.resolve().relative_to(base.resolve()).as_posix()
