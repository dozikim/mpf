"""Pydantic v2 API schemas.

These are the wire contracts for the REST API. They intentionally never expose
absolute server paths — only relative, analysis-rooted paths.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# --------------------------------------------------------------------------- #
#  Generic pagination envelope
# --------------------------------------------------------------------------- #
class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int

    @property
    def pages(self) -> int:
        return (self.total + self.page_size - 1) // self.page_size if self.page_size else 0


class PageParams(BaseModel):
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=500)
    search: str | None = None
    sort: str | None = None
    order: str = Field(default="asc", pattern="^(asc|desc)$")


# --------------------------------------------------------------------------- #
#  Analysis
# --------------------------------------------------------------------------- #
class AnalysisSummary(ORMModel):
    id: str
    file_name: str
    file_size: int
    package_name: str | None
    app_name: str | None
    version_name: str | None
    status: str
    progress: int
    current_stage: str | None
    created_at: datetime
    completed_at: datetime | None


class AnalysisDetail(AnalysisSummary):
    md5: str | None
    sha1: str | None
    sha256: str | None
    version_code: str | None
    min_sdk: str | None
    target_sdk: str | None
    error: str | None
    # aggregate counts for the overview dashboard
    counts: dict[str, int] = Field(default_factory=dict)


class AnalysisCreated(BaseModel):
    id: str
    status: str


# --------------------------------------------------------------------------- #
#  Manifest & components
# --------------------------------------------------------------------------- #
class ManifestOut(ORMModel):
    package_name: str | None
    version_name: str | None
    version_code: str | None
    min_sdk: str | None
    target_sdk: str | None
    compile_sdk: str | None
    debuggable: bool
    allow_backup: bool
    uses_cleartext_traffic: bool | None
    network_security_config: str | None
    manifest_path: str | None


class ComponentOut(ORMModel):
    id: int
    kind: str
    name: str
    exported: bool
    enabled: bool
    permission: str | None
    authorities: str | None
    grant_uri_permissions: bool | None
    intent_filters: Any | None = None
    risk: str | None
    risk_reason: str | None


class PermissionOut(ORMModel):
    id: int
    name: str
    protection_level: str | None
    is_dangerous: bool
    is_custom: bool
    description: str | None


class LibraryOut(ORMModel):
    id: int
    name: str
    category: str | None
    version: str | None
    license: str | None
    risk: str | None
    evidence: str | None


class SBOMOut(ORMModel):
    id: int
    name: str
    kind: str | None
    version: str | None
    license: str | None
    purl: str | None
    file_path: str | None
    sha256: str | None


class CertificateOut(ORMModel):
    id: int
    subject: str | None
    issuer: str | None
    serial_number: str | None
    signature_algorithm: str | None
    sha1: str | None
    sha256: str | None
    valid_from: str | None
    valid_to: str | None
    scheme_v1: bool | None
    scheme_v2: bool | None
    scheme_v3: bool | None


class FirebaseOut(ORMModel):
    id: int
    url: str
    kind: str | None
    is_public: bool | None
    detail: str | None


class MalwareOut(ORMModel):
    id: int
    category: str
    title: str
    severity: str | None
    detail: str | None
    evidence: str | None
    indicator: str | None
    country: str | None
    latitude: float | None
    longitude: float | None


class MalwareLookupOut(BaseModel):
    analysis_status: str
    last_scan: datetime | None
    detection_ratio: str | None
    hashes: dict[str, str | None]
    reports: dict[str, str | None]


class ApkidOut(ORMModel):
    id: int
    category: str
    label: str
    value: str
    detected: bool
    severity: str | None
    file_path: str | None
    line_number: int | None
    evidence: str | None


class BehaviourOut(ORMModel):
    id: int
    name: str
    severity: str
    description: str
    java_file: str | None
    method_name: str | None
    line_number: int | None
    evidence: str | None


class AbusedPermissionOut(ORMModel):
    id: int
    permission: str
    category: str
    risk_level: str
    description: str | None
    dangerous_reason: str | None
    malware_usage: str | None
    used_in_code: bool
    files: str | None
    methods: str | None


class CodeFindingOut(ORMModel):
    id: int
    issue: str
    severity: str
    description: str
    cwe: str | None
    owasp: str | None
    masvs: str | None
    java_file: str | None
    line_number: int | None
    category: str
    recommendation: str | None
    status: str
    evidence: str | None


class ReconFindingOut(ORMModel):
    id: int
    kind: str
    value: str
    protocol: str | None
    indicator_type: str | None
    risk: str | None
    file_path: str | None
    line_number: int | None
    method_name: str | None
    context: str | None


class DomainIntelOut(ORMModel):
    id: int
    domain: str
    status: str
    resolved_ip: str | None
    country: str | None
    region: str | None
    city: str | None
    latitude: float | None
    longitude: float | None
    isp: str | None
    asn: str | None
    source_file: str | None
    line_number: int | None


class OverviewSecurityOut(BaseModel):
    security_score: int
    tracker_score: int
    overall_risk_level: str
    exported_components_count: int
    dangerous_permissions_count: int
    native_libraries_count: int
    detected_trackers: list[str]
    detected_third_party_sdks: list[str]
    malware_indicators: list[str]
    security_summary: list[str]
    static_analysis_summary: dict[str, int]


# --------------------------------------------------------------------------- #
#  Files & tree
# --------------------------------------------------------------------------- #
class FileOut(ORMModel):
    id: int
    tree: str
    rel_path: str
    name: str
    ext: str | None
    size: int
    is_text: bool
    lines: int | None
    language: str | None


class TreeNode(BaseModel):
    """A node in a lazily-loaded directory tree."""
    name: str
    path: str                      # relative path within the tree
    is_dir: bool
    size: int | None = None
    language: str | None = None
    children: list["TreeNode"] | None = None  # None => not yet loaded (lazy)
    has_children: bool = False


class FileContent(BaseModel):
    path: str
    name: str
    size: int
    lines: int | None
    language: str | None
    encoding: str = "utf-8"
    truncated: bool = False
    content: str


class SearchHit(BaseModel):
    tree: str
    path: str
    name: str
    line_number: int
    line: str
    language: str | None = None


TreeNode.model_rebuild()
