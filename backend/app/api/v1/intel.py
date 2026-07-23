"""Security-intel endpoints: certificates, firebase, malware, recon.

    GET /analysis/{id}/certificates
    GET /analysis/{id}/firebase
    GET /analysis/{id}/malware
    GET /analysis/{id}/recon           (urls/domains/ips/emails/firebase from metadata.json)
"""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import db_session, pagination, require_analysis
from app.models import Analysis
from app.repositories.repos import (CertificateRepository, FirebaseRepository,
                                    MalwareRepository)
from app.schemas import (CertificateOut, FirebaseOut, MalwareOut, Page,
                        PageParams)
from app.services.storage import AnalysisStorage

router = APIRouter(prefix="/analysis", tags=["intel"])


@router.get("/{analysis_id}/certificates", response_model=list[CertificateOut])
def certificates(analysis: Analysis = Depends(require_analysis),
                 session: Session = Depends(db_session)) -> list[CertificateOut]:
    repo = CertificateRepository(session)
    return [CertificateOut.model_validate(c) for c in repo.all_for(analysis.id)]


@router.get("/{analysis_id}/firebase", response_model=Page[FirebaseOut])
def firebase(analysis: Analysis = Depends(require_analysis),
             params: PageParams = Depends(pagination),
             session: Session = Depends(db_session)) -> Page[FirebaseOut]:
    repo = FirebaseRepository(session)
    items, total = repo.paginate(
        analysis.id, page=params.page, page_size=params.page_size,
        search=params.search, sort=params.sort, order=params.order)
    return Page(items=[FirebaseOut.model_validate(x) for x in items],
                total=total, page=params.page, page_size=params.page_size)


@router.get("/{analysis_id}/malware", response_model=Page[MalwareOut])
def malware(analysis: Analysis = Depends(require_analysis),
            category: str | None = None,
            params: PageParams = Depends(pagination),
            session: Session = Depends(db_session)) -> Page[MalwareOut]:
    from app.models import MalwareFinding
    repo = MalwareRepository(session)
    extra = [MalwareFinding.category == category] if category else None
    items, total = repo.paginate(
        analysis.id, page=params.page, page_size=params.page_size,
        search=params.search, sort=params.sort, order=params.order,
        extra_filters=extra)
    return Page(items=[MalwareOut.model_validate(x) for x in items],
                total=total, page=params.page, page_size=params.page_size)


@router.get("/{analysis_id}/recon")
def recon(analysis: Analysis = Depends(require_analysis)) -> dict:
    """Return recon indicators captured in metadata.json (urls/ips/domains…)."""
    meta_path = AnalysisStorage(analysis.id).metadata_path
    if not meta_path.exists():
        return {"urls": [], "domains": [], "ips": [], "emails": [], "firebase": []}
    try:
        meta = json.loads(meta_path.read_text())
    except (json.JSONDecodeError, OSError):
        return {"urls": [], "domains": [], "ips": [], "emails": [], "firebase": []}
    return meta.get("recon", {})
