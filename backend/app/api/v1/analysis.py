"""Analysis lifecycle & overview endpoints.

    POST   /analysis                 upload an APK -> creates + enqueues analysis
    GET    /analysis                 list analyses (paginated)
    GET    /analysis/{id}            analysis detail + aggregate counts
    GET    /analysis/{id}/status     lightweight progress poll
    DELETE /analysis/{id}            delete analysis + artifacts
    GET    /analysis/{id}/tree       lazy directory tree for a storage sub-tree
"""
from __future__ import annotations

import shutil

from fastapi import (APIRouter, Depends, File, HTTPException, Query, UploadFile,
                    status)
from sqlalchemy.orm import Session

from app.api.deps import db_session, pagination, require_analysis
from app.core.config import settings
from app.core.security import PathTraversalError
from app.models import Analysis
from app.repositories.repos import AnalysisRepository
from app.schemas import (AnalysisCreated, AnalysisDetail, AnalysisSummary, Page,
                        PageParams, TreeNode)
from app.services.file_service import FileService
from app.services.storage import TREE_SUBDIRS, AnalysisStorage
from app.workers.tasks import enqueue_analysis

router = APIRouter(prefix="/analysis", tags=["analysis"])


def _allowed(filename: str) -> bool:
    return "." in filename and \
        filename.rsplit(".", 1)[1].lower() in settings.allowed_extensions


@router.post("", response_model=AnalysisCreated, status_code=status.HTTP_201_CREATED)
async def create_analysis(
    file: UploadFile = File(...),
    session: Session = Depends(db_session),
) -> AnalysisCreated:
    """Upload an APK, persist it, and enqueue the decompilation pipeline."""
    if not file.filename or not _allowed(file.filename):
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "only .apk/.xapk/.apks files are accepted")

    repo = AnalysisRepository(session)
    analysis = repo.create(file_name=file.filename, storage_dir="")
    storage = AnalysisStorage(analysis.id).create()
    analysis.storage_dir = analysis.id
    session.commit()

    # Stream the upload to disk, enforcing the size cap.
    dest = storage.apk_dir / "app.apk"
    written = 0
    with dest.open("wb") as out:
        while chunk := await file.read(1 << 20):
            written += len(chunk)
            if written > settings.max_upload_bytes:
                out.close()
                shutil.rmtree(storage.root, ignore_errors=True)
                repo.delete(analysis)
                raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                    f"file exceeds {settings.max_upload_mb} MB limit")
            out.write(chunk)

    enqueue_analysis(analysis.id)
    return AnalysisCreated(id=analysis.id, status=analysis.status)


@router.get("", response_model=Page[AnalysisSummary])
def list_analyses(
    params: PageParams = Depends(pagination),
    session: Session = Depends(db_session),
) -> Page[AnalysisSummary]:
    repo = AnalysisRepository(session)
    items, total = repo.list(page=params.page, page_size=params.page_size,
                             search=params.search, sort=params.sort,
                             order=params.order)
    return Page(items=[AnalysisSummary.model_validate(a) for a in items],
                total=total, page=params.page, page_size=params.page_size)


@router.get("/{analysis_id}", response_model=AnalysisDetail)
def get_analysis(
    analysis: Analysis = Depends(require_analysis),
    session: Session = Depends(db_session),
) -> AnalysisDetail:
    detail = AnalysisDetail.model_validate(analysis)
    detail.counts = AnalysisRepository(session).counts(analysis.id)
    return detail


@router.get("/{analysis_id}/status")
def analysis_status(analysis: Analysis = Depends(require_analysis)) -> dict:
    return {
        "id": analysis.id,
        "status": analysis.status,
        "progress": analysis.progress,
        "current_stage": analysis.current_stage,
        "error": analysis.error,
    }


@router.delete("/{analysis_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_analysis(
    analysis: Analysis = Depends(require_analysis),
    session: Session = Depends(db_session),
) -> None:
    shutil.rmtree(AnalysisStorage(analysis.id).root, ignore_errors=True)
    AnalysisRepository(session).delete(analysis)


@router.get("/{analysis_id}/tree", response_model=list[TreeNode])
def get_tree(
    analysis: Analysis = Depends(require_analysis),
    tree: str = Query("java"),
    path: str = Query("", description="directory path within the tree"),
    session: Session = Depends(db_session),
) -> list[TreeNode]:
    """Return the immediate children of a directory (lazy expansion)."""
    if tree not in TREE_SUBDIRS:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"unknown tree: {tree}")
    try:
        return FileService(session).list_dir(analysis.id, tree, path)
    except PathTraversalError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid path")
