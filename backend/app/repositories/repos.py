"""Concrete repositories for each model."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import (AbusedPermission, Analysis, AnalysisStatus, ApkidResult,
                        BehaviourFinding, Certificate, CodeFinding, Component,
                        DecompiledFile, DomainIntel, FirebaseRef, Library,
                        MalwareFinding, Manifest, Permission, ReconFinding,
                        Report, SBOMComponent)
from app.repositories.base import BaseRepository


class AnalysisRepository(BaseRepository[Analysis]):
    model = Analysis
    search_fields = ("file_name", "package_name", "app_name", "sha256")
    default_sort = "created_at"

    def create(self, *, file_name: str, storage_dir: str) -> Analysis:
        obj = Analysis(file_name=file_name, storage_dir=storage_dir,
                       status=AnalysisStatus.PENDING.value)
        self.session.add(obj)
        self.session.commit()
        self.session.refresh(obj)
        return obj

    def get(self, analysis_id: str) -> Analysis | None:
        return self.session.get(Analysis, analysis_id)

    def list(self, *, page: int, page_size: int, search: str | None,
             sort: str | None, order: str) -> tuple[list[Analysis], int]:
        stmt = select(Analysis)
        stmt = self._apply_search(stmt, search)
        total = self.count(stmt)
        stmt = self._apply_sort(stmt, sort, order)
        stmt = stmt.offset((page - 1) * page_size).limit(page_size)
        return list(self.session.scalars(stmt).all()), total

    def counts(self, analysis_id: str) -> dict[str, int]:
        """Aggregate child-row counts for the overview dashboard."""
        def n(model, *filters) -> int:
            stmt = select(func.count()).select_from(model).where(
                model.analysis_id == analysis_id)
            for f in filters:
                stmt = stmt.where(f)
            return self.session.scalar(stmt) or 0

        return {
            "activities": n(Component, Component.kind == "activity"),
            "services": n(Component, Component.kind == "service"),
            "receivers": n(Component, Component.kind == "receiver"),
            "providers": n(Component, Component.kind == "provider"),
            "permissions": n(Permission),
            "dangerous_permissions": n(Permission, Permission.is_dangerous.is_(True)),
            "libraries": n(Library),
            "certificates": n(Certificate),
            "firebase": n(FirebaseRef),
            "malware": n(MalwareFinding),
            "apkid": n(ApkidResult),
            "behaviours": n(BehaviourFinding),
            "abused_permissions": n(AbusedPermission),
            "code_findings": n(CodeFinding),
            "high_findings": n(CodeFinding, CodeFinding.severity == "HIGH"),
            "medium_findings": n(CodeFinding, CodeFinding.severity == "WARNING"),
            "low_findings": n(CodeFinding, CodeFinding.severity == "LOW"),
            "info_findings": n(CodeFinding, CodeFinding.severity == "INFO"),
            "domains": n(DomainIntel),
            "urls": n(ReconFinding, ReconFinding.kind == "url"),
            "emails": n(ReconFinding, ReconFinding.kind == "email"),
            "files": n(DecompiledFile),
            "java_files": n(DecompiledFile, DecompiledFile.tree == "java"),
            "smali_files": n(DecompiledFile, DecompiledFile.tree == "smali"),
            "native_libraries": n(DecompiledFile, DecompiledFile.tree == "native"),
        }

    def delete(self, analysis: Analysis) -> None:
        self.session.delete(analysis)
        self.session.commit()


class ComponentRepository(BaseRepository[Component]):
    model = Component
    search_fields = ("name", "permission")
    default_sort = "name"

    def for_kind(self, analysis_id: str, kind: str, **page) -> tuple[list[Component], int]:
        return self.paginate(analysis_id, extra_filters=[Component.kind == kind], **page)


class PermissionRepository(BaseRepository[Permission]):
    model = Permission
    search_fields = ("name", "protection_level")
    default_sort = "name"


class LibraryRepository(BaseRepository[Library]):
    model = Library
    search_fields = ("name", "category", "license")
    default_sort = "name"


class SBOMRepository(BaseRepository[SBOMComponent]):
    model = SBOMComponent
    search_fields = ("name", "kind", "license")
    default_sort = "name"


class CertificateRepository(BaseRepository[Certificate]):
    model = Certificate
    default_sort = "id"


class FirebaseRepository(BaseRepository[FirebaseRef]):
    model = FirebaseRef
    search_fields = ("url", "kind")
    default_sort = "url"


class MalwareRepository(BaseRepository[MalwareFinding]):
    model = MalwareFinding
    search_fields = ("title", "category", "evidence", "indicator")
    default_sort = "severity"


class ApkidRepository(BaseRepository[ApkidResult]):
    model = ApkidResult
    search_fields = ("category", "label", "value", "evidence", "file_path")
    default_sort = "category"


class BehaviourRepository(BaseRepository[BehaviourFinding]):
    model = BehaviourFinding
    search_fields = ("name", "description", "java_file", "method_name", "evidence")
    default_sort = "severity"


class AbusedPermissionRepository(BaseRepository[AbusedPermission]):
    model = AbusedPermission
    search_fields = ("permission", "category", "description", "dangerous_reason", "malware_usage", "files")
    default_sort = "risk_level"


class CodeFindingRepository(BaseRepository[CodeFinding]):
    model = CodeFinding
    search_fields = ("issue", "description", "java_file", "category", "recommendation", "evidence")
    default_sort = "severity"


class ReconFindingRepository(BaseRepository[ReconFinding]):
    model = ReconFinding
    search_fields = ("kind", "value", "file_path", "method_name", "context")
    default_sort = "value"


class DomainIntelRepository(BaseRepository[DomainIntel]):
    model = DomainIntel
    search_fields = ("domain", "resolved_ip", "country", "region", "city", "isp", "asn")
    default_sort = "domain"


class ManifestRepository(BaseRepository[Manifest]):
    model = Manifest

    def get(self, analysis_id: str) -> Manifest | None:
        return self.session.scalar(self._base_query(analysis_id))


class FileRepository(BaseRepository[DecompiledFile]):
    model = DecompiledFile
    search_fields = ("name", "rel_path")
    default_sort = "rel_path"

    def for_tree(self, analysis_id: str, tree: str, **page):
        return self.paginate(analysis_id,
                             extra_filters=[DecompiledFile.tree == tree], **page)

    def by_path(self, analysis_id: str, rel_path: str) -> DecompiledFile | None:
        return self.session.scalar(
            self._base_query(analysis_id).where(DecompiledFile.rel_path == rel_path))

    def text_files(self, analysis_id: str, trees: tuple[str, ...] | None = None,
                   limit: int = 50_000) -> list[DecompiledFile]:
        stmt = self._base_query(analysis_id).where(DecompiledFile.is_text.is_(True))
        if trees:
            stmt = stmt.where(DecompiledFile.tree.in_(trees))
        return list(self.session.scalars(stmt.limit(limit)).all())


class ReportRepository(BaseRepository[Report]):
    model = Report
    default_sort = "created_at"
