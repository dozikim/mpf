"""AndroidManifest.xml parser.

apktool decodes the binary manifest back to text XML. This module parses that
XML (safely, via defusedxml) into the structured records the DB and API need:
package metadata, permissions, and the four component kinds with their
exported/permission/intent-filter attributes plus a heuristic risk rating.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from defusedxml.ElementTree import parse as safe_parse

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

# Well-known dangerous permissions (subset of the Android "dangerous" group).
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
    "android.permission.READ_SMS", "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS", "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG", "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA", "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION", "android.permission.READ_PHONE_STATE",
    "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.CALL_PHONE", "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR", "android.permission.BODY_SENSORS",
    "android.permission.ACCESS_BACKGROUND_LOCATION", "android.permission.GET_ACCOUNTS",
}

TAG_TO_KIND = {
    "activity": "activity",
    "activity-alias": "activity",
    "service": "service",
    "receiver": "receiver",
    "provider": "provider",
}


@dataclass
class ParsedComponent:
    kind: str
    name: str
    exported: bool
    enabled: bool = True
    permission: str | None = None
    authorities: str | None = None
    grant_uri_permissions: bool | None = None
    intent_filters: list[dict[str, Any]] = field(default_factory=list)
    risk: str = "LOW"
    risk_reason: str | None = None


@dataclass
class ParsedPermission:
    name: str
    protection_level: str | None = None
    is_dangerous: bool = False
    is_custom: bool = False


@dataclass
class ParsedManifest:
    package_name: str | None = None
    version_name: str | None = None
    version_code: str | None = None
    min_sdk: str | None = None
    target_sdk: str | None = None
    compile_sdk: str | None = None
    debuggable: bool = False
    allow_backup: bool = True
    uses_cleartext_traffic: bool | None = None
    network_security_config: str | None = None
    permissions: list[ParsedPermission] = field(default_factory=list)
    components: list[ParsedComponent] = field(default_factory=list)


def _attr(el, name: str) -> str | None:
    return el.get(f"{ANDROID_NS}{name}")


def _as_bool(val: str | None, default: bool = False) -> bool:
    if val is None:
        return default
    return val.strip().lower() == "true"


def _classify_risk(comp: ParsedComponent) -> tuple[str, str]:
    """Heuristic risk for an exported component (mirrors MobSF intent)."""
    if not comp.exported:
        return "LOW", "Not exported"
    if comp.permission:
        return "MEDIUM", "Exported but permission-protected"
    if comp.intent_filters:
        return "HIGH", "Exported with intent-filters and no permission guard"
    return "MEDIUM", "Exported without permission"


def parse_manifest(manifest_path: Path) -> ParsedManifest:
    """Parse a decoded AndroidManifest.xml into a :class:`ParsedManifest`."""
    result = ParsedManifest()
    if not manifest_path.exists():
        return result

    tree = safe_parse(str(manifest_path))
    root = tree.getroot()

    result.package_name = root.get("package")
    result.version_name = _attr(root, "versionName")
    result.version_code = _attr(root, "versionCode")
    result.compile_sdk = _attr(root, "compileSdkVersion")

    uses_sdk = root.find("uses-sdk")
    if uses_sdk is not None:
        result.min_sdk = _attr(uses_sdk, "minSdkVersion")
        result.target_sdk = _attr(uses_sdk, "targetSdkVersion")

    app = root.find("application")
    if app is not None:
        result.debuggable = _as_bool(_attr(app, "debuggable"))
        result.allow_backup = _as_bool(_attr(app, "allowBackup"), default=True)
        cleartext = _attr(app, "usesCleartextTraffic")
        result.uses_cleartext_traffic = _as_bool(cleartext) if cleartext is not None else None
        result.network_security_config = _attr(app, "networkSecurityConfig")

    # Permissions (uses-permission + custom permission declarations)
    for el in root.findall("uses-permission") + root.findall("uses-permission-sdk-23"):
        name = _attr(el, "name")
        if not name:
            continue
        result.permissions.append(ParsedPermission(
            name=name,
            is_dangerous=name in DANGEROUS_PERMISSIONS,
            is_custom=not name.startswith("android.permission."),
        ))
    for el in root.findall("permission"):
        name = _attr(el, "name")
        if not name:
            continue
        result.permissions.append(ParsedPermission(
            name=name,
            protection_level=_attr(el, "protectionLevel"),
            is_custom=True,
        ))

    # Components
    if app is not None:
        for tag, kind in TAG_TO_KIND.items():
            for el in app.findall(tag):
                name = _attr(el, "name") or "(anonymous)"
                # Default exported semantics: true if it has intent-filters and
                # no explicit android:exported, per pre-S behaviour (MobSF-like).
                intent_filters = _parse_intent_filters(el)
                exported_attr = _attr(el, "exported")
                if exported_attr is not None:
                    exported = _as_bool(exported_attr)
                else:
                    exported = bool(intent_filters)
                comp = ParsedComponent(
                    kind=kind,
                    name=name,
                    exported=exported,
                    enabled=_as_bool(_attr(el, "enabled"), default=True),
                    permission=_attr(el, "permission"),
                    authorities=_attr(el, "authorities") if kind == "provider" else None,
                    grant_uri_permissions=(
                        _as_bool(_attr(el, "grantUriPermissions"))
                        if kind == "provider" else None),
                    intent_filters=intent_filters,
                )
                comp.risk, comp.risk_reason = _classify_risk(comp)
                result.components.append(comp)

    return result


def _parse_intent_filters(el) -> list[dict[str, Any]]:
    filters: list[dict[str, Any]] = []
    for f in el.findall("intent-filter"):
        entry = {
            "actions": [_attr(a, "name") for a in f.findall("action")],
            "categories": [_attr(c, "name") for c in f.findall("category")],
            "data": [
                {k: v for k, v in (
                    ("scheme", _attr(d, "scheme")),
                    ("host", _attr(d, "host")),
                    ("path", _attr(d, "path")),
                    ("mimeType", _attr(d, "mimeType")),
                ) if v}
                for d in f.findall("data")
            ],
        }
        filters.append(entry)
    return filters


def intent_filters_json(comp: ParsedComponent) -> str | None:
    return json.dumps(comp.intent_filters) if comp.intent_filters else None
