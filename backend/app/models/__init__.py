"""SQLAlchemy ORM models for the MPF analysis platform.

Design principles:
  * One ``Analysis`` aggregate root; every other table carries an
    ``analysis_id`` FK with ``ON DELETE CASCADE`` so removing an analysis
    tears down all derived rows.
  * The database stores **metadata only** — large decompiled artifacts live on
    disk under ``storage/analyses/{id}/`` and are referenced by relative path.
  * Enums are stored as plain strings for portability across Postgres/SQLite.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (BigInteger, Boolean, DateTime, Float, ForeignKey,
                        Index, Integer, String, Text, UniqueConstraint)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.session import Base


def _uuid() -> str:
    return uuid.uuid4().hex


def _now() -> datetime:
    return datetime.now(timezone.utc)


class AnalysisStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ComponentKind(str, enum.Enum):
    ACTIVITY = "activity"
    SERVICE = "service"
    RECEIVER = "receiver"
    PROVIDER = "provider"


# --------------------------------------------------------------------------- #
#  Aggregate root
# --------------------------------------------------------------------------- #
class Analysis(Base):
    """One APK submission and the state of its analysis run."""

    __tablename__ = "analyses"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)

    # Upload identity
    file_name: Mapped[str] = mapped_column(String(512))
    file_size: Mapped[int] = mapped_column(BigInteger, default=0)
    md5: Mapped[str | None] = mapped_column(String(32), index=True)
    sha1: Mapped[str | None] = mapped_column(String(40))
    sha256: Mapped[str | None] = mapped_column(String(64), index=True)

    # APK identity (from aapt2 badging / manifest)
    package_name: Mapped[str | None] = mapped_column(String(256), index=True)
    app_name: Mapped[str | None] = mapped_column(String(256))
    version_name: Mapped[str | None] = mapped_column(String(128))
    version_code: Mapped[str | None] = mapped_column(String(64))
    min_sdk: Mapped[str | None] = mapped_column(String(16))
    target_sdk: Mapped[str | None] = mapped_column(String(16))

    # Run state
    status: Mapped[str] = mapped_column(String(16), default=AnalysisStatus.PENDING.value,
                                        index=True)
    progress: Mapped[int] = mapped_column(Integer, default=0)  # 0..100
    current_stage: Mapped[str | None] = mapped_column(String(64))
    error: Mapped[str | None] = mapped_column(Text)

    # Storage
    storage_dir: Mapped[str] = mapped_column(String(512))  # relative to analyses_root

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now,
                                                 onupdate=_now)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Relationships (cascade delete-orphan; DB also enforces ON DELETE CASCADE)
    manifest: Mapped["Manifest"] = relationship(back_populates="analysis",
                                                uselist=False, cascade="all, delete-orphan")
    components: Mapped[list["Component"]] = relationship(back_populates="analysis",
                                                        cascade="all, delete-orphan")
    permissions: Mapped[list["Permission"]] = relationship(back_populates="analysis",
                                                          cascade="all, delete-orphan")
    libraries: Mapped[list["Library"]] = relationship(back_populates="analysis",
                                                      cascade="all, delete-orphan")
    sbom: Mapped[list["SBOMComponent"]] = relationship(back_populates="analysis",
                                                       cascade="all, delete-orphan")
    certificates: Mapped[list["Certificate"]] = relationship(back_populates="analysis",
                                                            cascade="all, delete-orphan")
    firebase: Mapped[list["FirebaseRef"]] = relationship(back_populates="analysis",
                                                        cascade="all, delete-orphan")
    malware: Mapped[list["MalwareFinding"]] = relationship(back_populates="analysis",
                                                          cascade="all, delete-orphan")
    apkid_results: Mapped[list["ApkidResult"]] = relationship(back_populates="analysis",
                                                              cascade="all, delete-orphan")
    behaviour_findings: Mapped[list["BehaviourFinding"]] = relationship(back_populates="analysis",
                                                                        cascade="all, delete-orphan")
    abused_permissions: Mapped[list["AbusedPermission"]] = relationship(back_populates="analysis",
                                                                       cascade="all, delete-orphan")
    code_findings: Mapped[list["CodeFinding"]] = relationship(back_populates="analysis",
                                                              cascade="all, delete-orphan")
    recon_findings: Mapped[list["ReconFinding"]] = relationship(back_populates="analysis",
                                                                cascade="all, delete-orphan")
    domain_intel: Mapped[list["DomainIntel"]] = relationship(back_populates="analysis",
                                                            cascade="all, delete-orphan")
    files: Mapped[list["DecompiledFile"]] = relationship(back_populates="analysis",
                                                        cascade="all, delete-orphan")
    reports: Mapped[list["Report"]] = relationship(back_populates="analysis",
                                                   cascade="all, delete-orphan")


# --------------------------------------------------------------------------- #
#  Manifest & components
# --------------------------------------------------------------------------- #
class Manifest(Base):
    """Parsed AndroidManifest.xml summary (one per analysis)."""

    __tablename__ = "manifests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True)

    package_name: Mapped[str | None] = mapped_column(String(256))
    version_name: Mapped[str | None] = mapped_column(String(128))
    version_code: Mapped[str | None] = mapped_column(String(64))
    min_sdk: Mapped[str | None] = mapped_column(String(16))
    target_sdk: Mapped[str | None] = mapped_column(String(16))
    compile_sdk: Mapped[str | None] = mapped_column(String(16))

    debuggable: Mapped[bool] = mapped_column(Boolean, default=False)
    allow_backup: Mapped[bool] = mapped_column(Boolean, default=True)
    uses_cleartext_traffic: Mapped[bool | None] = mapped_column(Boolean)
    network_security_config: Mapped[str | None] = mapped_column(String(512))

    # Path (relative) to the pretty-printed manifest on disk.
    manifest_path: Mapped[str | None] = mapped_column(String(512))

    analysis: Mapped["Analysis"] = relationship(back_populates="manifest")


class Component(Base):
    """An exported/declared Android component: activity/service/receiver/provider."""

    __tablename__ = "components"
    __table_args__ = (
        Index("ix_components_analysis_kind", "analysis_id", "kind"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True)

    kind: Mapped[str] = mapped_column(String(16))  # ComponentKind value
    name: Mapped[str] = mapped_column(String(512))
    exported: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    permission: Mapped[str | None] = mapped_column(String(512))
    # provider-specific
    authorities: Mapped[str | None] = mapped_column(String(512))
    grant_uri_permissions: Mapped[bool | None] = mapped_column(Boolean)
    # JSON-encoded list of intent-filter descriptors
    intent_filters: Mapped[str | None] = mapped_column(Text)
    # Heuristic risk classification: LOW/MEDIUM/HIGH/CRITICAL
    risk: Mapped[str | None] = mapped_column(String(16))
    risk_reason: Mapped[str | None] = mapped_column(Text)

    analysis: Mapped["Analysis"] = relationship(back_populates="components")


class Permission(Base):
    """A permission declared (or used) by the app."""

    __tablename__ = "permissions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True)

    name: Mapped[str] = mapped_column(String(256))
    protection_level: Mapped[str | None] = mapped_column(String(64))
    is_dangerous: Mapped[bool] = mapped_column(Boolean, default=False)
    is_custom: Mapped[bool] = mapped_column(Boolean, default=False)
    description: Mapped[str | None] = mapped_column(Text)

    analysis: Mapped["Analysis"] = relationship(back_populates="permissions")


# --------------------------------------------------------------------------- #
#  Libraries / SBOM
# --------------------------------------------------------------------------- #
class Library(Base):
    """A detected third-party framework/library (AndroidX, Firebase, …)."""

    __tablename__ = "libraries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True)

    name: Mapped[str] = mapped_column(String(256))
    category: Mapped[str | None] = mapped_column(String(64))  # e.g. "Networking"
    version: Mapped[str | None] = mapped_column(String(64))
    license: Mapped[str | None] = mapped_column(String(128))
    risk: Mapped[str | None] = mapped_column(String(16))
    evidence: Mapped[str | None] = mapped_column(Text)  # matched package/path

    analysis: Mapped["Analysis"] = relationship(back_populates="libraries")


class SBOMComponent(Base):
    """A software-bill-of-materials entry (native .so, jar, asset dep)."""

    __tablename__ = "sbom_components"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True)

    name: Mapped[str] = mapped_column(String(256))
    kind: Mapped[str | None] = mapped_column(String(64))  # native/jar/dex/asset
    version: Mapped[str | None] = mapped_column(String(64))
    license: Mapped[str | None] = mapped_column(String(128))
    purl: Mapped[str | None] = mapped_column(String(256))  # package URL
    file_path: Mapped[str | None] = mapped_column(String(512))
    sha256: Mapped[str | None] = mapped_column(String(64))

    analysis: Mapped["Analysis"] = relationship(back_populates="sbom")


# --------------------------------------------------------------------------- #
#  Certificates / Firebase / Malware
# --------------------------------------------------------------------------- #
class Certificate(Base):
    """Signing certificate extracted via apksigner/keytool."""

    __tablename__ = "certificates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True)

    subject: Mapped[str | None] = mapped_column(Text)
    issuer: Mapped[str | None] = mapped_column(Text)
    serial_number: Mapped[str | None] = mapped_column(String(128))
    signature_algorithm: Mapped[str | None] = mapped_column(String(128))
    sha1: Mapped[str | None] = mapped_column(String(64))
    sha256: Mapped[str | None] = mapped_column(String(128))
    valid_from: Mapped[str | None] = mapped_column(String(64))
    valid_to: Mapped[str | None] = mapped_column(String(64))
    scheme_v1: Mapped[bool | None] = mapped_column(Boolean)
    scheme_v2: Mapped[bool | None] = mapped_column(Boolean)
    scheme_v3: Mapped[bool | None] = mapped_column(Boolean)

    analysis: Mapped["Analysis"] = relationship(back_populates="certificates")


class FirebaseRef(Base):
    """A Firebase/Google-cloud endpoint referenced by the app."""

    __tablename__ = "firebase_refs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True)

    url: Mapped[str] = mapped_column(String(512))
    kind: Mapped[str | None] = mapped_column(String(64))  # database/storage/…
    is_public: Mapped[bool | None] = mapped_column(Boolean)  # open-DB check
    detail: Mapped[str | None] = mapped_column(Text)

    analysis: Mapped["Analysis"] = relationship(back_populates="firebase")


class MalwareFinding(Base):
    """A malware/behaviour signal: APKiD packer, abused permission, C2 host…"""

    __tablename__ = "malware_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True)

    category: Mapped[str] = mapped_column(String(64))  # apkid/behaviour/permission/domain
    title: Mapped[str] = mapped_column(String(256))
    severity: Mapped[str | None] = mapped_column(String(16))
    detail: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[str | None] = mapped_column(Text)
    # optional geo columns for "Server Locations"
    indicator: Mapped[str | None] = mapped_column(String(256))
    country: Mapped[str | None] = mapped_column(String(64))
    latitude: Mapped[float | None] = mapped_column(Float)
    longitude: Mapped[float | None] = mapped_column(Float)

    analysis: Mapped["Analysis"] = relationship(back_populates="malware")


class ApkidResult(Base):
    """Static APKiD-style technology and anti-analysis signature result."""

    __tablename__ = "apkid_results"
    __table_args__ = (
        Index("ix_apkid_analysis_category", "analysis_id", "category"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True)

    category: Mapped[str] = mapped_column(String(64))
    label: Mapped[str] = mapped_column(String(128))
    value: Mapped[str] = mapped_column(String(256))
    detected: Mapped[bool] = mapped_column(Boolean, default=True)
    severity: Mapped[str | None] = mapped_column(String(16))
    file_path: Mapped[str | None] = mapped_column(String(1024))
    line_number: Mapped[int | None] = mapped_column(Integer)
    evidence: Mapped[str | None] = mapped_column(Text)

    analysis: Mapped["Analysis"] = relationship(back_populates="apkid_results")


class BehaviourFinding(Base):
    """A statically detected behaviour with source location."""

    __tablename__ = "behaviour_findings"
    __table_args__ = (
        Index("ix_behaviour_analysis_name", "analysis_id", "name"),
        Index("ix_behaviour_analysis_severity", "analysis_id", "severity"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True)

    name: Mapped[str] = mapped_column(String(128))
    severity: Mapped[str] = mapped_column(String(16))
    description: Mapped[str] = mapped_column(Text)
    java_file: Mapped[str | None] = mapped_column(String(1024))
    method_name: Mapped[str | None] = mapped_column(String(256))
    line_number: Mapped[int | None] = mapped_column(Integer)
    evidence: Mapped[str | None] = mapped_column(Text)

    analysis: Mapped["Analysis"] = relationship(back_populates="behaviour_findings")


class AbusedPermission(Base):
    """Declared permission risk enriched with static code usage evidence."""

    __tablename__ = "abused_permissions"
    __table_args__ = (
        Index("ix_abused_permissions_analysis_category", "analysis_id", "category"),
        Index("ix_abused_permissions_analysis_risk", "analysis_id", "risk_level"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True)

    permission: Mapped[str] = mapped_column(String(256))
    category: Mapped[str] = mapped_column(String(64))
    risk_level: Mapped[str] = mapped_column(String(16))
    description: Mapped[str | None] = mapped_column(Text)
    dangerous_reason: Mapped[str | None] = mapped_column(Text)
    malware_usage: Mapped[str | None] = mapped_column(Text)
    used_in_code: Mapped[bool] = mapped_column(Boolean, default=False)
    files: Mapped[str | None] = mapped_column(Text)
    methods: Mapped[str | None] = mapped_column(Text)

    analysis: Mapped["Analysis"] = relationship(back_populates="abused_permissions")


class CodeFinding(Base):
    """Static code-analysis issue stored after upload-time scanning."""

    __tablename__ = "code_findings"
    __table_args__ = (
        Index("ix_code_findings_analysis_severity", "analysis_id", "severity"),
        Index("ix_code_findings_analysis_category", "analysis_id", "category"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True)

    issue: Mapped[str] = mapped_column(String(256))
    severity: Mapped[str] = mapped_column(String(16))
    description: Mapped[str] = mapped_column(Text)
    cwe: Mapped[str | None] = mapped_column(String(64))
    owasp: Mapped[str | None] = mapped_column(String(64))
    masvs: Mapped[str | None] = mapped_column(String(64))
    java_file: Mapped[str | None] = mapped_column(String(1024))
    line_number: Mapped[int | None] = mapped_column(Integer)
    category: Mapped[str] = mapped_column(String(128))
    recommendation: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(32), default="open")
    evidence: Mapped[str | None] = mapped_column(Text)

    analysis: Mapped["Analysis"] = relationship(back_populates="code_findings")


class ReconFinding(Base):
    """Recon indicator with source location and preview context."""

    __tablename__ = "recon_findings"
    __table_args__ = (
        Index("ix_recon_findings_analysis_kind", "analysis_id", "kind"),
        Index("ix_recon_findings_analysis_value", "analysis_id", "value"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True)

    kind: Mapped[str] = mapped_column(String(32))
    value: Mapped[str] = mapped_column(String(1024))
    protocol: Mapped[str | None] = mapped_column(String(32))
    indicator_type: Mapped[str | None] = mapped_column(String(64))
    risk: Mapped[str | None] = mapped_column(String(16))
    file_path: Mapped[str | None] = mapped_column(String(1024))
    line_number: Mapped[int | None] = mapped_column(Integer)
    method_name: Mapped[str | None] = mapped_column(String(256))
    context: Mapped[str | None] = mapped_column(Text)

    analysis: Mapped["Analysis"] = relationship(back_populates="recon_findings")


class DomainIntel(Base):
    """Domain/IP reputation and geolocation shell generated from extracted hosts."""

    __tablename__ = "domain_intel"
    __table_args__ = (
        Index("ix_domain_intel_analysis_domain", "analysis_id", "domain"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True)

    domain: Mapped[str] = mapped_column(String(512))
    status: Mapped[str] = mapped_column(String(32), default="extracted")
    resolved_ip: Mapped[str | None] = mapped_column(String(64))
    country: Mapped[str | None] = mapped_column(String(64))
    region: Mapped[str | None] = mapped_column(String(128))
    city: Mapped[str | None] = mapped_column(String(128))
    latitude: Mapped[float | None] = mapped_column(Float)
    longitude: Mapped[float | None] = mapped_column(Float)
    isp: Mapped[str | None] = mapped_column(String(256))
    asn: Mapped[str | None] = mapped_column(String(64))
    source_file: Mapped[str | None] = mapped_column(String(1024))
    line_number: Mapped[int | None] = mapped_column(Integer)

    analysis: Mapped["Analysis"] = relationship(back_populates="domain_intel")


# --------------------------------------------------------------------------- #
#  File index
# --------------------------------------------------------------------------- #
class DecompiledFile(Base):
    """An indexed file within the analysis storage tree.

    One row per file across all sub-trees (jadx/java, apktool/smali, resources,
    assets, native, …). Powers the file explorer, per-tree browsers, and search
    without walking the filesystem on every request.
    """

    __tablename__ = "decompiled_files"
    __table_args__ = (
        Index("ix_files_analysis_tree", "analysis_id", "tree"),
        UniqueConstraint("analysis_id", "rel_path", name="uq_file_path"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True)

    # Logical tree this file belongs to: java/smali/resources/manifest/assets/
    # native/databases/certificates/other
    tree: Mapped[str] = mapped_column(String(32), index=True)
    # Path relative to the analysis storage dir (client-facing, never absolute).
    rel_path: Mapped[str] = mapped_column(String(1024))
    name: Mapped[str] = mapped_column(String(512), index=True)
    ext: Mapped[str | None] = mapped_column(String(32), index=True)
    size: Mapped[int] = mapped_column(BigInteger, default=0)
    is_text: Mapped[bool] = mapped_column(Boolean, default=True)
    lines: Mapped[int | None] = mapped_column(Integer)
    language: Mapped[str | None] = mapped_column(String(32))  # monaco language id

    analysis: Mapped["Analysis"] = relationship(back_populates="files")


class Report(Base):
    """A generated report artifact (json/html/pdf)."""

    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[str] = mapped_column(
        ForeignKey("analyses.id", ondelete="CASCADE"), index=True)

    fmt: Mapped[str] = mapped_column(String(16))  # json/html/pdf
    file_path: Mapped[str] = mapped_column(String(512))
    size: Mapped[int] = mapped_column(BigInteger, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now)

    analysis: Mapped["Analysis"] = relationship(back_populates="reports")
