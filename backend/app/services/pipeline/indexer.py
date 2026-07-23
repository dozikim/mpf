"""File indexer.

After decompilation, this walks each logical storage tree and yields metadata
records (relative path, size, extension, text/binary, line count, Monaco
language id) that get persisted as :class:`DecompiledFile` rows. The index is
what powers the file explorer, per-tree browsers, and global search without
touching the filesystem on every request.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

# Extension -> Monaco language identifier.
LANGUAGE_MAP = {
    ".java": "java", ".kt": "kotlin", ".smali": "smali", ".xml": "xml",
    ".json": "json", ".html": "html", ".htm": "html", ".js": "javascript",
    ".ts": "typescript", ".css": "css", ".txt": "plaintext", ".md": "markdown",
    ".properties": "properties", ".gradle": "groovy", ".yml": "yaml",
    ".yaml": "yaml", ".c": "c", ".cpp": "cpp", ".h": "cpp", ".py": "python",
    ".sh": "shell", ".sql": "sql", ".cfg": "ini", ".conf": "ini",
    ".pem": "plaintext", ".rsa": "plaintext", ".dsa": "plaintext",
}

TEXT_EXTS = set(LANGUAGE_MAP) | {".pro", ".map"}

# Extensions we treat as binary regardless (skip line counting).
BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".svg",
    ".so", ".dex", ".apk", ".jar", ".zip", ".ttf", ".otf", ".woff",
    ".woff2", ".mp3", ".mp4", ".ogg", ".wav", ".db", ".sqlite", ".sqlite3",
    ".arsc", ".bin", ".dat", ".keystore", ".jks",
}


@dataclass
class IndexedFile:
    tree: str
    rel_path: str          # relative to the analysis root
    name: str
    ext: str | None
    size: int
    is_text: bool
    lines: int | None
    language: str | None


def _count_lines(path: Path, cap_bytes: int = 5_000_000) -> int | None:
    """Count newlines up to a size cap (skip counting huge files)."""
    try:
        if path.stat().st_size > cap_bytes:
            return None
        with path.open("rb") as fh:
            return sum(chunk.count(b"\n") for chunk in iter(lambda: fh.read(1 << 16), b"")) + 1
    except OSError:
        return None


def index_tree(analysis_root: Path, tree: str, tree_dir: Path) -> Iterator[IndexedFile]:
    """Yield :class:`IndexedFile` records for every file under ``tree_dir``."""
    if not tree_dir.exists():
        return
    for path in tree_dir.rglob("*"):
        if not path.is_file():
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        ext = path.suffix.lower() or None
        is_text = ext in TEXT_EXTS or (ext not in BINARY_EXTS and size < 2_000_000
                                       and _looks_text(path))
        yield IndexedFile(
            tree=tree,
            rel_path=path.relative_to(analysis_root).as_posix(),
            name=path.name,
            ext=ext,
            size=size,
            is_text=is_text,
            lines=_count_lines(path) if is_text else None,
            language=LANGUAGE_MAP.get(ext or "", "plaintext" if is_text else None),
        )


def _looks_text(path: Path, sniff: int = 2048) -> bool:
    """Heuristic: no NUL byte in the first ``sniff`` bytes => text."""
    try:
        with path.open("rb") as fh:
            chunk = fh.read(sniff)
        return b"\x00" not in chunk
    except OSError:
        return False


def collect_package_paths(java_dir: Path, limit: int = 50_000) -> set[str]:
    """Derive dotted package prefixes from the decompiled Java/Smali layout.

    Used by the library detector. Returns directory paths converted to dotted
    packages (``a/b/c`` -> ``a.b.c``), bounded by ``limit`` for pathological APKs.
    """
    packages: set[str] = set()
    if not java_dir.exists():
        return packages
    count = 0
    for path in java_dir.rglob("*"):
        if path.is_dir():
            rel = path.relative_to(java_dir).as_posix()
            if rel:
                packages.add(rel.replace("/", "."))
                count += 1
                if count >= limit:
                    break
    return packages
