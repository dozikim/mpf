"""Component & metadata endpoints.

    GET /analysis/{id}/activities
    GET /analysis/{id}/services
    GET /analysis/{id}/receivers
    GET /analysis/{id}/providers
    GET /analysis/{id}/libraries
    GET /analysis/{id}/permissions
    GET /analysis/{id}/sbom
    GET /analysis/{id}/manifest/summary   (parsed manifest metadata)
"""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import db_session, pagination, require_analysis
from app.models import Analysis
from app.repositories.repos import (ComponentRepository, LibraryRepository,
                                    ManifestRepository, PermissionRepository,
                                    SBOMRepository)
from app.schemas import (ComponentOut, LibraryOut, ManifestOut, Page,
                        PageParams, PermissionOut, SBOMOut)

router = APIRouter(prefix="/analysis", tags=["components"])


def _component_page(session: Session, analysis_id: str, kind: str,
                    params: PageParams) -> Page[ComponentOut]:
    repo = ComponentRepository(session)
    items, total = repo.for_kind(
        analysis_id, kind, page=params.page, page_size=params.page_size,
        search=params.search, sort=params.sort, order=params.order)
    out = []
    for c in items:
        model = ComponentOut.model_validate(c)
        if c.intent_filters:
            try:
                model.intent_filters = json.loads(c.intent_filters)
            except json.JSONDecodeError:
                model.intent_filters = None
        out.append(model)
    return Page(items=out, total=total, page=params.page,
                page_size=params.page_size)


@router.get("/{analysis_id}/activities", response_model=Page[ComponentOut])
def activities(analysis: Analysis = Depends(require_analysis),
               params: PageParams = Depends(pagination),
               session: Session = Depends(db_session)) -> Page[ComponentOut]:
    return _component_page(session, analysis.id, "activity", params)


@router.get("/{analysis_id}/services", response_model=Page[ComponentOut])
def services(analysis: Analysis = Depends(require_analysis),
             params: PageParams = Depends(pagination),
             session: Session = Depends(db_session)) -> Page[ComponentOut]:
    return _component_page(session, analysis.id, "service", params)


@router.get("/{analysis_id}/receivers", response_model=Page[ComponentOut])
def receivers(analysis: Analysis = Depends(require_analysis),
              params: PageParams = Depends(pagination),
              session: Session = Depends(db_session)) -> Page[ComponentOut]:
    return _component_page(session, analysis.id, "receiver", params)


@router.get("/{analysis_id}/providers", response_model=Page[ComponentOut])
def providers(analysis: Analysis = Depends(require_analysis),
              params: PageParams = Depends(pagination),
              session: Session = Depends(db_session)) -> Page[ComponentOut]:
    return _component_page(session, analysis.id, "provider", params)


@router.get("/{analysis_id}/libraries", response_model=Page[LibraryOut])
def libraries(analysis: Analysis = Depends(require_analysis),
              params: PageParams = Depends(pagination),
              session: Session = Depends(db_session)) -> Page[LibraryOut]:
    repo = LibraryRepository(session)
    items, total = repo.paginate(
        analysis.id, page=params.page, page_size=params.page_size,
        search=params.search, sort=params.sort, order=params.order)
    return Page(items=[LibraryOut.model_validate(x) for x in items],
                total=total, page=params.page, page_size=params.page_size)


@router.get("/{analysis_id}/permissions", response_model=Page[PermissionOut])
def permissions(analysis: Analysis = Depends(require_analysis),
                params: PageParams = Depends(pagination),
                session: Session = Depends(db_session)) -> Page[PermissionOut]:
    repo = PermissionRepository(session)
    items, total = repo.paginate(
        analysis.id, page=params.page, page_size=params.page_size,
        search=params.search, sort=params.sort, order=params.order)
    return Page(items=[PermissionOut.model_validate(x) for x in items],
                total=total, page=params.page, page_size=params.page_size)


@router.get("/{analysis_id}/sbom", response_model=Page[SBOMOut])
def sbom(analysis: Analysis = Depends(require_analysis),
         params: PageParams = Depends(pagination),
         session: Session = Depends(db_session)) -> Page[SBOMOut]:
    repo = SBOMRepository(session)
    items, total = repo.paginate(
        analysis.id, page=params.page, page_size=params.page_size,
        search=params.search, sort=params.sort, order=params.order)
    return Page(items=[SBOMOut.model_validate(x) for x in items],
                total=total, page=params.page, page_size=params.page_size)


@router.get("/{analysis_id}/manifest/summary", response_model=ManifestOut)
def manifest_summary(analysis: Analysis = Depends(require_analysis),
                     session: Session = Depends(db_session)) -> ManifestOut:
    manifest = ManifestRepository(session).get(analysis.id)
    if manifest is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "manifest not parsed")
    return ManifestOut.model_validate(manifest)
