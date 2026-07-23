"""Certificate & signature extraction.

Uses ``apksigner verify --print-certs`` when available (authoritative for the
v1/v2/v3 signing schemes), falling back to ``keytool -printcert -jarfile``.
Output is parsed into structured certificate records.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from app.core.config import settings
from app.services.pipeline.tools import run_tool, tool_available


@dataclass
class CertInfo:
    subject: str | None = None
    issuer: str | None = None
    serial_number: str | None = None
    signature_algorithm: str | None = None
    sha1: str | None = None
    sha256: str | None = None
    valid_from: str | None = None
    valid_to: str | None = None
    scheme_v1: bool | None = None
    scheme_v2: bool | None = None
    scheme_v3: bool | None = None


@dataclass
class SigningResult:
    certificates: list[CertInfo] = field(default_factory=list)
    raw: str = ""


_SHA256_RE = re.compile(r"SHA-256 digest:\s*([0-9a-fA-F]+)")
_SHA1_RE = re.compile(r"SHA-1 digest:\s*([0-9a-fA-F]+)")
_DN_RE = re.compile(r"certificate DN:\s*(.+)")


def extract_signing(apk_path: Path) -> SigningResult:
    """Extract signing certificate details from an APK."""
    result = SigningResult()

    if tool_available(settings.tool_apksigner):
        res = run_tool(settings.tool_apksigner,
                       ["verify", "--print-certs", "--verbose", str(apk_path)])
        result.raw = res.stdout + res.stderr
        if res.stdout:
            result.certificates = _parse_apksigner(res.stdout)
        return result

    if tool_available(settings.tool_keytool):
        res = run_tool(settings.tool_keytool,
                       ["-printcert", "-jarfile", str(apk_path)])
        result.raw = res.stdout + res.stderr
        if res.stdout:
            result.certificates = _parse_keytool(res.stdout)
    return result


def _parse_apksigner(text: str) -> list[CertInfo]:
    cert = CertInfo()
    for line in text.splitlines():
        line = line.strip()
        if m := _DN_RE.search(line):
            cert.subject = m.group(1).strip()
        elif m := _SHA256_RE.search(line):
            cert.sha256 = m.group(1)
        elif m := _SHA1_RE.search(line):
            cert.sha1 = m.group(1)
        elif line.startswith("Verified using v1 scheme"):
            cert.scheme_v1 = line.rstrip(".").endswith("true")
        elif line.startswith("Verified using v2 scheme"):
            cert.scheme_v2 = line.rstrip(".").endswith("true")
        elif line.startswith("Verified using v3 scheme"):
            cert.scheme_v3 = line.rstrip(".").endswith("true")
    return [cert] if any(vars(cert).values()) else []


def _parse_keytool(text: str) -> list[CertInfo]:
    cert = CertInfo()
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("Owner:"):
            cert.subject = line.split(":", 1)[1].strip()
        elif line.startswith("Issuer:"):
            cert.issuer = line.split(":", 1)[1].strip()
        elif line.startswith("Serial number:"):
            cert.serial_number = line.split(":", 1)[1].strip()
        elif line.startswith("Signature algorithm name:"):
            cert.signature_algorithm = line.split(":", 1)[1].strip()
        elif "SHA256:" in line:
            cert.sha256 = line.split("SHA256:", 1)[1].strip()
        elif "SHA1:" in line:
            cert.sha1 = line.split("SHA1:", 1)[1].strip()
    return [cert] if any(vars(cert).values()) else []
