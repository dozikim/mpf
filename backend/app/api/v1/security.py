"""Stored security-analysis endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import db_session, pagination, require_analysis
from app.models import (AbusedPermission, Analysis, ApkidResult, BehaviourFinding,
                        CodeFinding, DomainIntel, ReconFinding)
from app.repositories.repos import (AbusedPermissionRepository, ApkidRepository,
                                    BehaviourRepository, CodeFindingRepository,
                                    DomainIntelRepository, ReconFindingRepository)
from app.schemas import (AbusedPermissionOut, ApkidOut, BehaviourOut,
                        CodeFindingOut, DomainIntelOut, MalwareLookupOut,
                        OverviewSecurityOut, Page, PageParams, ReconFindingOut)
from app.services.pipeline.static_scanner import overview_security

router = APIRouter(prefix="/analysis", tags=["security"])


def _report_urls(sha256: str | None) -> dict[str, str | None]:
    if not sha256:
        return {"virustotal": None, "triage": None, "hybrid_analysis": None, "metadefender": None}
    return {
        "virustotal": f"https://www.virustotal.com/gui/file/{sha256}",
        "triage": f"https://tria.ge/s?q={sha256}",
        "hybrid_analysis": f"https://www.hybrid-analysis.com/search?query={sha256}",
        "metadefender": f"https://metadefender.opswat.com/results/file/{sha256}/hash/overview",
    }


@router.get("/{analysis_id}/overview/security", response_model=OverviewSecurityOut)
def security_overview(analysis: Analysis = Depends(require_analysis),
                      session: Session = Depends(db_session)) -> OverviewSecurityOut:
    return OverviewSecurityOut.model_validate(overview_security(session, analysis))


@router.get("/{analysis_id}/malware/lookup", response_model=MalwareLookupOut)
def malware_lookup(analysis: Analysis = Depends(require_analysis)) -> MalwareLookupOut:
    return MalwareLookupOut(
        analysis_status=analysis.status,
        last_scan=analysis.completed_at,
        detection_ratio=None,
        hashes={"md5": analysis.md5, "sha1": analysis.sha1, "sha256": analysis.sha256},
        reports=_report_urls(analysis.sha256),
    )


@router.get("/{analysis_id}/apkid", response_model=Page[ApkidOut])
def apkid(analysis: Analysis = Depends(require_analysis),
          params: PageParams = Depends(pagination),
          session: Session = Depends(db_session)) -> Page[ApkidOut]:
    repo = ApkidRepository(session)
    items, total = repo.paginate(analysis.id, page=params.page, page_size=params.page_size,
                                 search=params.search, sort=params.sort, order=params.order)
    return Page(items=[ApkidOut.model_validate(x) for x in items],
                total=total, page=params.page, page_size=params.page_size)


@router.get("/{analysis_id}/behaviours", response_model=Page[BehaviourOut])
def behaviours(analysis: Analysis = Depends(require_analysis),
               params: PageParams = Depends(pagination),
               session: Session = Depends(db_session)) -> Page[BehaviourOut]:
    repo = BehaviourRepository(session)
    items, total = repo.paginate(analysis.id, page=params.page, page_size=params.page_size,
                                 search=params.search, sort=params.sort, order=params.order)
    return Page(items=[BehaviourOut.model_validate(x) for x in items],
                total=total, page=params.page, page_size=params.page_size)


@router.get("/{analysis_id}/abused-permissions", response_model=Page[AbusedPermissionOut])
def abused_permissions(analysis: Analysis = Depends(require_analysis),
                       category: str | None = Query(None),
                       params: PageParams = Depends(pagination),
                       session: Session = Depends(db_session)) -> Page[AbusedPermissionOut]:
    repo = AbusedPermissionRepository(session)
    extra = [AbusedPermission.category == category] if category else None
    items, total = repo.paginate(analysis.id, page=params.page, page_size=params.page_size,
                                 search=params.search, sort=params.sort, order=params.order,
                                 extra_filters=extra)
    return Page(items=[AbusedPermissionOut.model_validate(x) for x in items],
                total=total, page=params.page, page_size=params.page_size)


@router.get("/{analysis_id}/code-analysis", response_model=Page[CodeFindingOut])
def code_analysis(analysis: Analysis = Depends(require_analysis),
                  severity: str | None = Query(None),
                  params: PageParams = Depends(pagination),
                  session: Session = Depends(db_session)) -> Page[CodeFindingOut]:
    repo = CodeFindingRepository(session)
    extra = [CodeFinding.severity == severity] if severity else None
    items, total = repo.paginate(analysis.id, page=params.page, page_size=params.page_size,
                                 search=params.search, sort=params.sort, order=params.order,
                                 extra_filters=extra)
    return Page(items=[CodeFindingOut.model_validate(x) for x in items],
                total=total, page=params.page, page_size=params.page_size)


@router.get("/{analysis_id}/recon/findings", response_model=Page[ReconFindingOut])
def recon_findings(analysis: Analysis = Depends(require_analysis),
                   kind: str | None = Query(None),
                   params: PageParams = Depends(pagination),
                   session: Session = Depends(db_session)) -> Page[ReconFindingOut]:
    repo = ReconFindingRepository(session)
    extra = [ReconFinding.kind == kind] if kind else None
    items, total = repo.paginate(analysis.id, page=params.page, page_size=params.page_size,
                                 search=params.search, sort=params.sort, order=params.order,
                                 extra_filters=extra)
    return Page(items=[ReconFindingOut.model_validate(x) for x in items],
                total=total, page=params.page, page_size=params.page_size)


@router.get("/{analysis_id}/domains/intel", response_model=Page[DomainIntelOut])
def domains_intel(analysis: Analysis = Depends(require_analysis),
                  params: PageParams = Depends(pagination),
                  session: Session = Depends(db_session)) -> Page[DomainIntelOut]:
    repo = DomainIntelRepository(session)
    items, total = repo.paginate(analysis.id, page=params.page, page_size=params.page_size,
                                 search=params.search, sort=params.sort, order=params.order)
    return Page(items=[DomainIntelOut.model_validate(x) for x in items],
                total=total, page=params.page, page_size=params.page_size)
