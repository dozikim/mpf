"""File-tree, content, and search services.

Bridges the on-disk artifact store and the DB file index to serve the browser
UI. All client-facing paths are relative and validated through
``safe_join`` so directory traversal is impossible.
"""
from __future__ import annotations

from pathlib import Path

from sqlalchemy.orm import Session

from app.core.security import PathTraversalError, safe_join
from app.models import (BehaviourFinding, CodeFinding, Component, DecompiledFile,
                        DomainIntel, Library, Permission, ReconFinding)
from app.repositories.repos import FileRepository
from app.schemas import FileContent, SearchHit, TreeNode
from app.services.storage import TREE_SUBDIRS, AnalysisStorage

# Files larger than this are streamed/truncated rather than returned whole.
MAX_INLINE_BYTES = 2_000_000


class FileService:
    def __init__(self, session: Session):
        self.session = session
        self.files = FileRepository(session)

    # -- lazy directory tree ------------------------------------------------
    def list_dir(self, analysis_id: str, tree: str, rel: str = "") -> list[TreeNode]:
        """Return the immediate children of a directory within a tree.

        Powers lazy tree expansion: one level at a time, cheap and virtualiz-
        able on the client.
        """
        storage = AnalysisStorage(analysis_id)
        base = storage.tree_dir(tree)
        target = safe_join(base, rel)
        if not target.exists() or not target.is_dir():
            return []

        nodes: list[TreeNode] = []
        for child in sorted(target.iterdir(),
                            key=lambda p: (p.is_file(), p.name.lower())):
            child_rel = child.relative_to(base).as_posix()
            if child.is_dir():
                nodes.append(TreeNode(
                    name=child.name, path=child_rel, is_dir=True,
                    has_children=any(child.iterdir()) if child.exists() else False,
                    children=None))
            else:
                record = self.files.by_path(
                    analysis_id, f"{TREE_SUBDIRS[tree]}/{child_rel}")
                nodes.append(TreeNode(
                    name=child.name, path=child_rel, is_dir=False,
                    size=child.stat().st_size,
                    language=record.language if record else None,
                    has_children=False))
        return nodes

    # -- file content -------------------------------------------------------
    def read_file(self, analysis_id: str, tree: str, rel: str) -> FileContent:
        storage = AnalysisStorage(analysis_id)
        base = storage.tree_dir(tree)
        target = safe_join(base, rel)
        if not target.exists() or not target.is_file():
            raise FileNotFoundError(rel)

        size = target.stat().st_size
        truncated = size > MAX_INLINE_BYTES
        raw = target.read_bytes()[:MAX_INLINE_BYTES] if truncated else target.read_bytes()
        text = raw.decode("utf-8", errors="replace")

        record = self.files.by_path(analysis_id, f"{TREE_SUBDIRS[tree]}/{rel}")
        return FileContent(
            path=rel, name=target.name, size=size,
            lines=text.count("\n") + 1,
            language=record.language if record else _guess_language(target.suffix),
            truncated=truncated, content=text)

    def resolve_disk_path(self, analysis_id: str, tree: str, rel: str) -> Path:
        """Return the validated absolute path for streaming/download."""
        base = AnalysisStorage(analysis_id).tree_dir(tree)
        target = safe_join(base, rel)
        if not target.exists() or not target.is_file():
            raise FileNotFoundError(rel)
        return target

    # -- search -------------------------------------------------------------
    def search_content(self, analysis_id: str, query: str, *,
                       trees: tuple[str, ...] | None = None,
                       max_hits: int = 500,
                       max_files: int = 20_000) -> list[SearchHit]:
        """Grep decompiled text for ``query`` (case-insensitive substring)."""
        if not query:
            return []
        needle = query.lower()
        storage = AnalysisStorage(analysis_id)
        hits: list[SearchHit] = []
        records = self.files.text_files(analysis_id, trees, limit=max_files)
        for rec in records:
            abs_path = safe_join(storage.root, rec.rel_path)
            try:
                with abs_path.open("r", encoding="utf-8", errors="replace") as fh:
                    for i, line in enumerate(fh, start=1):
                        if needle in line.lower():
                            hits.append(SearchHit(
                                tree=rec.tree,
                                path=_tree_relative(rec),
                                name=rec.name, line_number=i,
                                line=line.rstrip()[:400],
                                language=rec.language))
                            if len(hits) >= max_hits:
                                return hits
            except OSError:
                continue
        self._search_stored_results(analysis_id, needle, hits, max_hits)
        return hits

    def _search_stored_results(self, analysis_id: str, needle: str,
                               hits: list[SearchHit], max_hits: int) -> None:
        def add(path: str | None, line_no: int | None, title: str, preview: str) -> None:
            if len(hits) >= max_hits:
                return
            hits.append(SearchHit(
                tree="java" if path and path.endswith((".java", ".kt")) else "manifest",
                path=path or "AndroidManifest.xml",
                name=(Path(path).name if path else "stored-result"),
                line_number=line_no or 1,
                line=f"{title}: {preview}"[:400],
                language="java" if path and path.endswith((".java", ".kt")) else "plaintext"))

        for row in self.session.query(ReconFinding).filter(ReconFinding.analysis_id == analysis_id).limit(2000):
            hay = " ".join(str(x or "") for x in (row.kind, row.value, row.file_path, row.context)).lower()
            if needle in hay:
                add(row.file_path, row.line_number, row.kind, row.value)
        for row in self.session.query(CodeFinding).filter(CodeFinding.analysis_id == analysis_id).limit(2000):
            hay = " ".join(str(x or "") for x in (row.issue, row.description, row.category, row.evidence)).lower()
            if needle in hay:
                add(row.java_file, row.line_number, row.issue, row.description)
        for row in self.session.query(BehaviourFinding).filter(BehaviourFinding.analysis_id == analysis_id).limit(2000):
            hay = " ".join(str(x or "") for x in (row.name, row.description, row.java_file, row.evidence)).lower()
            if needle in hay:
                add(row.java_file, row.line_number, row.name, row.description)
        for row in self.session.query(DomainIntel).filter(DomainIntel.analysis_id == analysis_id).limit(2000):
            hay = " ".join(str(x or "") for x in (row.domain, row.resolved_ip, row.country, row.city, row.isp)).lower()
            if needle in hay:
                add(row.source_file, row.line_number, "domain", row.domain)
        for model, fields in ((Permission, ("name", "protection_level", "description")),
                              (Library, ("name", "category", "evidence")),
                              (Component, ("name", "kind", "permission", "risk_reason"))):
            for row in self.session.query(model).filter(model.analysis_id == analysis_id).limit(2000):
                values = [str(getattr(row, f, "") or "") for f in fields]
                if needle in " ".join(values).lower():
                    add(None, None, model.__name__, " | ".join(values))


def _tree_relative(rec: DecompiledFile) -> str:
    """Strip the tree's on-disk subdir prefix to get a tree-relative path."""
    prefix = TREE_SUBDIRS.get(rec.tree, "")
    rel = rec.rel_path
    if prefix and rel.startswith(prefix + "/"):
        return rel[len(prefix) + 1:]
    return rel


def _guess_language(suffix: str) -> str | None:
    from app.services.pipeline.indexer import LANGUAGE_MAP
    return LANGUAGE_MAP.get(suffix.lower())


__all__ = ["FileService", "PathTraversalError"]
