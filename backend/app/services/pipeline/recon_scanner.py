"""Reconnaissance & secret scanner.

Greps the decompiled Java/Smali/resources text for network indicators (URLs,
domains, IPs), Firebase endpoints, and common hardcoded-secret patterns. Feeds
the Reconnaissance, Firebase and Malware pages. Bounded so a huge APK can't
blow up memory: files are streamed and matches are de-duplicated.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

URL_RE = re.compile(r"https?://[\w\-.]+(?::\d+)?(?:/[\w\-./%?=&#:+~]*)?", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
FIREBASE_RE = re.compile(r"https?://[\w\-]+\.(?:firebaseio\.com|firebasedatabase\.app|firebaseapp\.com|appspot\.com)[\w\-./]*", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[\w.+\-]+@[\w\-]+\.[\w.\-]+\b")

SECRET_PATTERNS = {
    "Google API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Slack Token": re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,48}"),
    "Private Key Block": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    "JWT": re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
}

_PRIVATE_IP_PREFIXES = ("10.", "192.168.", "127.", "0.")


@dataclass
class ReconResult:
    urls: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)
    emails: set[str] = field(default_factory=set)
    firebase: set[str] = field(default_factory=set)
    # secret label -> set of evidence strings
    secrets: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))


def _domain_of(url: str) -> str | None:
    m = re.match(r"https?://([^/:]+)", url, re.IGNORECASE)
    return m.group(1).lower() if m else None


def scan_text(text: str, result: ReconResult) -> None:
    for url in URL_RE.findall(text):
        result.urls.add(url)
        if dom := _domain_of(url):
            result.domains.add(dom)
    for ip in IP_RE.findall(text):
        if not ip.startswith(_PRIVATE_IP_PREFIXES):
            result.ips.add(ip)
    for fb in FIREBASE_RE.findall(text):
        result.firebase.add(fb)
    for em in EMAIL_RE.findall(text):
        result.emails.add(em)
    for label, pat in SECRET_PATTERNS.items():
        for m in pat.findall(text):
            result.secrets[label].add(m[:80] if isinstance(m, str) else str(m))


def scan_paths(paths: list[Path], *, max_files: int = 20_000,
               max_bytes_per_file: int = 3_000_000) -> ReconResult:
    """Scan a list of text files, bounded for safety."""
    result = ReconResult()
    for i, path in enumerate(paths):
        if i >= max_files:
            break
        try:
            if path.stat().st_size > max_bytes_per_file:
                continue
            text = path.read_text("utf-8", errors="replace")
        except OSError:
            continue
        scan_text(text, result)
    return result
