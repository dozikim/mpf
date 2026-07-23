"""Shared API dependencies.

Provides request-scoped DB sessions, the common pagination params, and an
``require_analysis`` dependency that 404s early if the analysis id is unknown —
so every per-analysis router can assume the row exists.
"""
from __future__ import annotations

from fastapi import Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.db.session import get_session
from app.models import Analysis
from app.repositories.repos import AnalysisRepository
from app.schemas import PageParams


def db_session() -> Session:  # re-export for router readability
    yield from get_session()


def pagination(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    search: str | None = Query(None),
    sort: str | None = Query(None),
    order: str = Query("asc", pattern="^(asc|desc)$"),
) -> PageParams:
    return PageParams(page=page, page_size=page_size, search=search,
                      sort=sort, order=order)


def require_analysis(
    analysis_id: str,
    session: Session = Depends(db_session),
) -> Analysis:
    analysis = AnalysisRepository(session).get(analysis_id)
    if analysis is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "analysis not found")
    return analysis
