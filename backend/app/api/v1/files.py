"""File-browsing endpoints: per-tree trees, file content, download, search.

    GET /analysis/{id}/java              java tree root (lazy)
    GET /analysis/{id}/java/file         java file content
    GET /analysis/{id}/smali             smali tree root (lazy)
    GET /analysis/{id}/smali/file        smali file content
    GET /analysis/{id}/manifest          pretty AndroidManifest.xml
    GET /analysis/{id}/files             flat file index (paginated/filtered)
    GET /analysis/{id}/file              generic file content (tree + path)
    GET /analysis/{id}/download          stream a file for download
    GET /analysis/{id}/search            content search across trees
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.api.deps import db_session, pagination, require_analysis
from app.core.cache import cache
from app.core.security import PathTraversalError
from app.models import Analysis
from app.repositories.repos import FileRepository, ManifestRepository
from app.schemas import (FileContent, FileOut, Page, PageParams, SearchHit,
                        TreeNode)
from app.services.file_service import FileService
from app.services.storage import TREE_SUBDIRS, AnalysisStorage

router = APIRouter(prefix="/analysis", tags=["files"])


def _tree_root(session: Session, analysis_id: str, tree: str) -> list[TreeNode]:
    key = f"analysis:{analysis_id}:tree:{tree}:root"
    if (cached := cache.get(key)) is not None:
        return [TreeNode.model_validate(n) for n in cached]
    nodes = FileService(session).list_dir(analysis_id, tree, "")
    cache.set(key, [n.model_dump() for n in nodes])
    return nodes


def _read(session: Session, analysis_id: str, tree: str, path: str) -> FileContent:
    try:
        return FileService(session).read_file(analysis_id, tree, path)
    except FileNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "file not found")
    except PathTraversalError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid path")


# --- Java ---
@router.get("/{analysis_id}/java", response_model=list[TreeNode])
def java_tree(analysis: Analysis = Depends(require_analysis),
              session: Session = Depends(db_session)) -> list[TreeNode]:
    return _tree_root(session, analysis.id, "java")


@router.get("/{analysis_id}/java/file", response_model=FileContent)
def java_file(path: str = Query(...),
              analysis: Analysis = Depends(require_analysis),
              session: Session = Depends(db_session)) -> FileContent:
    return _read(session, analysis.id, "java", path)


# --- Smali ---
@router.get("/{analysis_id}/smali", response_model=list[TreeNode])
def smali_tree(analysis: Analysis = Depends(require_analysis),
               session: Session = Depends(db_session)) -> list[TreeNode]:
    return _tree_root(session, analysis.id, "smali")


@router.get("/{analysis_id}/smali/file", response_model=FileContent)
def smali_file(path: str = Query(...),
               analysis: Analysis = Depends(require_analysis),
               session: Session = Depends(db_session)) -> FileContent:
    return _read(session, analysis.id, "smali", path)


# --- Manifest ---
@router.get("/{analysis_id}/manifest", response_model=FileContent)
def manifest_file(analysis: Analysis = Depends(require_analysis),
                  session: Session = Depends(db_session)) -> FileContent:
    manifest = ManifestRepository(session).get(analysis.id)
    if manifest is None or not manifest.manifest_path:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "manifest not available")
    return _read(session, analysis.id, "manifest", "AndroidManifest.xml")


# --- generic flat file index ---
@router.get("/{analysis_id}/files", response_model=Page[FileOut])
def list_files(analysis: Analysis = Depends(require_analysis),
               tree: str | None = Query(None),
               ext: str | None = Query(None),
               params: PageParams = Depends(pagination),
               session: Session = Depends(db_session)) -> Page[FileOut]:
    repo = FileRepository(session)
    from app.models import DecompiledFile
    extra = []
    if tree:
        extra.append(DecompiledFile.tree == tree)
    if ext:
        extra.append(DecompiledFile.ext == ext)
    items, total = repo.paginate(
        analysis.id, page=params.page, page_size=params.page_size,
        search=params.search, sort=params.sort, order=params.order,
        extra_filters=extra)
    return Page(items=[FileOut.model_validate(f) for f in items],
                total=total, page=params.page, page_size=params.page_size)


# --- generic content + download ---
@router.get("/{analysis_id}/file", response_model=FileContent)
def generic_file(tree: str = Query(...), path: str = Query(...),
                 analysis: Analysis = Depends(require_analysis),
                 session: Session = Depends(db_session)) -> FileContent:
    if tree not in TREE_SUBDIRS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"unknown tree: {tree}")
    return _read(session, analysis.id, tree, path)


@router.get("/{analysis_id}/download")
def download_file(tree: str = Query(...), path: str = Query(...),
                  analysis: Analysis = Depends(require_analysis),
                  session: Session = Depends(db_session)) -> FileResponse:
    if tree not in TREE_SUBDIRS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"unknown tree: {tree}")
    try:
        disk = FileService(session).resolve_disk_path(analysis.id, tree, path)
    except FileNotFoundError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "file not found")
    except PathTraversalError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid path")
    return FileResponse(disk, filename=disk.name)


# --- content search ---
@router.get("/{analysis_id}/search", response_model=list[SearchHit])
def search(q: str = Query(..., min_length=1),
           trees: str | None = Query(None, description="comma-separated tree filter"),
           analysis: Analysis = Depends(require_analysis),
           session: Session = Depends(db_session)) -> list[SearchHit]:
    tree_tuple = tuple(t.strip() for t in trees.split(",")) if trees else None
    return FileService(session).search_content(analysis.id, q, trees=tree_tuple)
