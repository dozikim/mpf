"""APK analysis pipeline orchestrator.

Runs the full decompilation + static-analysis workflow for one uploaded APK
and persists all derived metadata. Each stage updates the ``Analysis`` row's
``progress`` / ``current_stage`` so the UI can show live status, and every
stage is defensive: a failing/absent tool records a skip and the pipeline
continues rather than aborting the whole run.

Stages
------
 1. hashing        md5/sha1/sha256 of the APK
 2. aapt2 badging  package/version/sdk identity
 3. apktool        smali + resources + decoded manifest
 4. jadx           java sources
 5. manifest parse components / permissions -> DB
 6. libraries      framework detection -> DB
 7. certificates   apksigner/keytool -> DB
 8. natives/dbs    copy .so and .sqlite artifacts into their trees
 9. recon          urls/ips/domains/firebase/secrets -> DB
10. index          walk all trees -> DecompiledFile rows
11. metadata.json  machine-readable summary
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.models import (Analysis, AnalysisStatus, Certificate, Component,
                        DecompiledFile, FirebaseRef, Library, MalwareFinding,
                        Manifest, Permission, SBOMComponent)
from app.services.pipeline import (cert_extractor, indexer, library_detector,
                                   manifest_parser, recon_scanner, static_scanner)
from app.services.pipeline.tools import run_tool
from app.services.storage import AnalysisStorage

log = get_logger("pipeline")

_AAPT_PKG_RE = re.compile(r"package: name='([^']+)' versionCode='([^']*)' versionName='([^']*)'")
_AAPT_LABEL_RE = re.compile(r"application-label:'([^']*)'")
_AAPT_SDK_RE = re.compile(r"sdkVersion:'([^']*)'")
_AAPT_TARGET_RE = re.compile(r"targetSdkVersion:'([^']*)'")


class Pipeline:
    """Executes and persists a single analysis run."""

    def __init__(self, session: Session, analysis: Analysis):
        self.session = session
        self.analysis = analysis
        self.storage = AnalysisStorage(analysis.id)

    # -- progress helper ----------------------------------------------------
    def _stage(self, name: str, pct: int) -> None:
        self.analysis.current_stage = name
        self.analysis.progress = pct
        self.analysis.status = AnalysisStatus.RUNNING.value
        self.session.commit()
        log.info("[%s] stage=%s (%d%%)", self.analysis.id, name, pct)

    # -- entrypoint ---------------------------------------------------------
    def run(self) -> None:
        try:
            self.storage.create()
            self._stage("hashing", 5)
            self._hash_apk()

            self._stage("badging", 12)
            self._aapt_badging()

            self._stage("apktool", 30)
            self._run_apktool()

            self._stage("jadx", 55)
            self._run_jadx()

            self._stage("manifest", 65)
            self._parse_manifest()

            self._stage("libraries", 72)
            self._detect_libraries()

            self._stage("certificates", 78)
            self._extract_certs()

            self._stage("artifacts", 84)
            self._collect_binary_artifacts()

            self._stage("recon", 90)
            self._run_recon()

            self._stage("index", 94)
            self._index_files()

            self._stage("static-scans", 98)
            self._run_static_scans()

            self._write_metadata()
            self.analysis.status = AnalysisStatus.COMPLETED.value
            self.analysis.progress = 100
            self.analysis.current_stage = "done"
            self.analysis.completed_at = datetime.now(timezone.utc)
            self.session.commit()
            log.info("[%s] analysis complete", self.analysis.id)
        except Exception as exc:  # noqa: BLE001
            log.exception("[%s] pipeline failed", self.analysis.id)
            self.analysis.status = AnalysisStatus.FAILED.value
            self.analysis.error = str(exc)
            self.session.commit()
            raise

    # -- stages -------------------------------------------------------------
    @property
    def _apk_path(self) -> Path:
        return next(self.storage.apk_dir.glob("*"), self.storage.apk_dir / "app.apk")

    def _hash_apk(self) -> None:
        apk = self._apk_path
        md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
        with apk.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                md5.update(chunk); sha1.update(chunk); sha256.update(chunk)
        self.analysis.md5 = md5.hexdigest()
        self.analysis.sha1 = sha1.hexdigest()
        self.analysis.sha256 = sha256.hexdigest()
        self.analysis.file_size = apk.stat().st_size
        self.session.commit()

    def _aapt_badging(self) -> None:
        res = run_tool(settings.tool_aapt2, ["dump", "badging", str(self._apk_path)])
        if not res.ok:
            return
        out = res.stdout
        if m := _AAPT_PKG_RE.search(out):
            self.analysis.package_name = m.group(1)
            self.analysis.version_code = m.group(2)
            self.analysis.version_name = m.group(3)
        if m := _AAPT_LABEL_RE.search(out):
            self.analysis.app_name = m.group(1)
        if m := _AAPT_SDK_RE.search(out):
            self.analysis.min_sdk = m.group(1)
        if m := _AAPT_TARGET_RE.search(out):
            self.analysis.target_sdk = m.group(1)
        self.session.commit()

    def _run_apktool(self) -> None:
        # apktool decodes smali + resources + manifest into one output dir.
        out_dir = self.storage.root / "apktool" / "_decoded"
        if out_dir.exists():
            shutil.rmtree(out_dir, ignore_errors=True)
        run_tool(settings.tool_apktool,
                 ["d", "-f", "-o", str(out_dir), str(self._apk_path)])
        if not out_dir.exists():
            return
        # Relocate decoded pieces into the canonical layout.
        for smali_root in sorted(out_dir.glob("smali*")):
            dest = self.storage.smali_dir / smali_root.name
            _merge_move(smali_root, dest)
        res_dir = out_dir / "res"
        if res_dir.exists():
            _merge_move(res_dir, self.storage.resources_dir)
        manifest_src = out_dir / "AndroidManifest.xml"
        if manifest_src.exists():
            shutil.copy2(manifest_src, self.storage.manifest_dir / "AndroidManifest.xml")

    def _run_jadx(self) -> None:
        # jadx writes sources under <out>/sources; point it straight at java dir.
        out_dir = self.storage.root / "jadx"
        run_tool(settings.tool_jadx,
                 ["-d", str(out_dir), "--no-res", "-r",
                  "--output-format", "java", str(self._apk_path)])
        # jadx emits ./sources; normalise into jadx/java.
        sources = out_dir / "sources"
        if sources.exists():
            _merge_move(sources, self.storage.jadx_java_dir)

    def _parse_manifest(self) -> None:
        manifest_file = self.storage.manifest_dir / "AndroidManifest.xml"
        parsed = manifest_parser.parse_manifest(manifest_file)

        m = Manifest(
            analysis_id=self.analysis.id,
            package_name=parsed.package_name or self.analysis.package_name,
            version_name=parsed.version_name,
            version_code=parsed.version_code,
            min_sdk=parsed.min_sdk,
            target_sdk=parsed.target_sdk,
            compile_sdk=parsed.compile_sdk,
            debuggable=parsed.debuggable,
            allow_backup=parsed.allow_backup,
            uses_cleartext_traffic=parsed.uses_cleartext_traffic,
            network_security_config=parsed.network_security_config,
            manifest_path=("apktool/manifest/AndroidManifest.xml"
                           if manifest_file.exists() else None),
        )
        self.session.add(m)

        for perm in parsed.permissions:
            self.session.add(Permission(
                analysis_id=self.analysis.id, name=perm.name,
                protection_level=perm.protection_level,
                is_dangerous=perm.is_dangerous, is_custom=perm.is_custom))

        for comp in parsed.components:
            self.session.add(Component(
                analysis_id=self.analysis.id, kind=comp.kind, name=comp.name,
                exported=comp.exported, enabled=comp.enabled,
                permission=comp.permission, authorities=comp.authorities,
                grant_uri_permissions=comp.grant_uri_permissions,
                intent_filters=manifest_parser.intent_filters_json(comp),
                risk=comp.risk, risk_reason=comp.risk_reason))
        self.session.commit()

    def _detect_libraries(self) -> None:
        pkgs = indexer.collect_package_paths(self.storage.jadx_java_dir)
        pkgs |= indexer.collect_package_paths(self.storage.smali_dir)
        for lib in library_detector.detect_libraries(pkgs):
            self.session.add(Library(analysis_id=self.analysis.id, **lib))
        self.session.commit()

    def _extract_certs(self) -> None:
        result = cert_extractor.extract_signing(self._apk_path)
        if result.raw:
            (self.storage.certificates_dir / "apksigner.txt").write_text(result.raw)
        for c in result.certificates:
            self.session.add(Certificate(analysis_id=self.analysis.id, **vars(c)))
        self.session.commit()

    def _collect_binary_artifacts(self) -> None:
        """Copy native libs & SQLite DBs out of the APK into their trees."""
        try:
            zf = zipfile.ZipFile(self._apk_path)
        except (zipfile.BadZipFile, OSError):
            return
        with zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                name = info.filename
                lower = name.lower()
                dest: Path | None = None
                if lower.endswith(".so"):
                    dest = self.storage.native_dir / Path(name).name
                elif lower.endswith((".db", ".sqlite", ".sqlite3")):
                    dest = self.storage.databases_dir / Path(name).name
                elif lower.startswith("assets/"):
                    dest = self.storage.assets_dir / name[len("assets/"):]
                if dest is None:
                    continue
                try:
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(info) as src, dest.open("wb") as out:
                        shutil.copyfileobj(src, out)
                except (OSError, zipfile.BadZipFile):
                    continue

    def _run_recon(self) -> None:
        text_paths: list[Path] = []
        for base in (self.storage.jadx_java_dir, self.storage.smali_dir,
                     self.storage.resources_dir, self.storage.assets_dir):
            if base.exists():
                text_paths.extend(p for p in base.rglob("*")
                                  if p.is_file() and p.suffix.lower() in indexer.TEXT_EXTS)
        result = recon_scanner.scan_paths(text_paths)

        for url in sorted(result.firebase):
            self.session.add(FirebaseRef(
                analysis_id=self.analysis.id, url=url, kind="database"))

        # Persist secrets and abused permissions as malware/behaviour findings.
        for label, hits in result.secrets.items():
            for evidence in list(hits)[:20]:
                self.session.add(MalwareFinding(
                    analysis_id=self.analysis.id, category="secret",
                    title=f"Hardcoded {label}", severity="HIGH",
                    evidence=evidence))

        # Store recon indicators as JSON in metadata for the Recon pages.
        self._recon_summary = {
            "urls": sorted(result.urls)[:2000],
            "domains": sorted(result.domains)[:2000],
            "ips": sorted(result.ips)[:2000],
            "emails": sorted(result.emails)[:1000],
            "firebase": sorted(result.firebase)[:500],
        }
        self.session.commit()

    def _index_files(self) -> None:
        root = self.storage.root
        for tree in ("java", "smali", "resources", "manifest", "assets",
                     "native", "databases", "certificates"):
            tree_dir = self.storage.tree_dir(tree)
            for f in indexer.index_tree(root, tree, tree_dir):
                self.session.add(DecompiledFile(
                    analysis_id=self.analysis.id, tree=f.tree,
                    rel_path=f.rel_path, name=f.name, ext=f.ext, size=f.size,
                    is_text=f.is_text, lines=f.lines, language=f.language))
        self.session.commit()

    def _run_static_scans(self) -> None:
        static_scanner.run_static_scans(self.session, self.analysis)

    def _write_metadata(self) -> None:
        meta = {
            "analysis_id": self.analysis.id,
            "file_name": self.analysis.file_name,
            "package_name": self.analysis.package_name,
            "version_name": self.analysis.version_name,
            "version_code": self.analysis.version_code,
            "min_sdk": self.analysis.min_sdk,
            "target_sdk": self.analysis.target_sdk,
            "md5": self.analysis.md5,
            "sha256": self.analysis.sha256,
            "recon": getattr(self, "_recon_summary", {}),
            "generated": datetime.now(timezone.utc).isoformat(),
        }
        self.storage.metadata_path.write_text(json.dumps(meta, indent=2, default=str))


def _merge_move(src: Path, dest: Path) -> None:
    """Move ``src`` into ``dest``, merging directory trees."""
    dest.mkdir(parents=True, exist_ok=True)
    for item in src.iterdir():
        target = dest / item.name
        if item.is_dir():
            _merge_move(item, target)
        else:
            try:
                shutil.move(str(item), str(target))
            except (OSError, shutil.Error):
                pass
