"""Permanent per-analysis storage layout.

Every analysis owns a directory tree under ``settings.analyses_root``::

    storage/analyses/{analysis_id}/
        apk/            original uploaded APK
        jadx/java/      decompiled Java sources
        apktool/
            smali/      disassembled smali
            resources/  decoded resources (res/)
            manifest/   pretty AndroidManifest.xml
        assets/         raw assets/
        native/         .so libraries
        databases/      bundled SQLite DBs
        certificates/   extracted signing certs
        reports/        generated json/html/pdf
        metadata.json   machine-readable run summary

This module centralises the layout so no other code hard-codes sub-paths, and
provides the ``tree -> subdir`` mapping the file browser relies on.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from app.core.config import settings

# Logical browser trees -> on-disk subdirectory (relative to the analysis dir).
TREE_SUBDIRS: dict[str, str] = {
    "java": "jadx/java",
    "smali": "apktool/smali",
    "resources": "apktool/resources",
    "manifest": "apktool/manifest",
    "assets": "assets",
    "native": "native",
    "databases": "databases",
    "certificates": "certificates",
    "apk": "apk",
}


@dataclass(frozen=True)
class AnalysisStorage:
    """Filesystem view of a single analysis's artifact tree."""

    analysis_id: str

    @property
    def root(self) -> Path:
        return settings.analyses_root / self.analysis_id

    # --- named sub-trees ---
    @property
    def apk_dir(self) -> Path:
        return self.root / "apk"

    @property
    def jadx_java_dir(self) -> Path:
        return self.root / "jadx" / "java"

    @property
    def smali_dir(self) -> Path:
        return self.root / "apktool" / "smali"

    @property
    def resources_dir(self) -> Path:
        return self.root / "apktool" / "resources"

    @property
    def manifest_dir(self) -> Path:
        return self.root / "apktool" / "manifest"

    @property
    def assets_dir(self) -> Path:
        return self.root / "assets"

    @property
    def native_dir(self) -> Path:
        return self.root / "native"

    @property
    def databases_dir(self) -> Path:
        return self.root / "databases"

    @property
    def certificates_dir(self) -> Path:
        return self.root / "certificates"

    @property
    def reports_dir(self) -> Path:
        return self.root / "reports"

    @property
    def metadata_path(self) -> Path:
        return self.root / "metadata.json"

    def tree_dir(self, tree: str) -> Path:
        """Return the base directory for a logical browser tree."""
        sub = TREE_SUBDIRS.get(tree)
        if sub is None:
            raise KeyError(f"unknown tree: {tree!r}")
        return self.root / sub

    def create(self) -> "AnalysisStorage":
        """Create the full directory skeleton (idempotent)."""
        for d in (self.apk_dir, self.jadx_java_dir, self.smali_dir,
                  self.resources_dir, self.manifest_dir, self.assets_dir,
                  self.native_dir, self.databases_dir, self.certificates_dir,
                  self.reports_dir):
            d.mkdir(parents=True, exist_ok=True)
        return self
