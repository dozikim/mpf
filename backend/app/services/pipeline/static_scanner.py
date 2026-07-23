"""Stored static-analysis scanners for source navigation powered pages."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.core.security import safe_join
from app.models import (AbusedPermission, Analysis, ApkidResult, BehaviourFinding,
                        CodeFinding, DecompiledFile, DomainIntel, Library,
                        MalwareFinding, Manifest, Permission, ReconFinding)
from app.repositories.repos import FileRepository
from app.services.pipeline.recon_scanner import EMAIL_RE, FIREBASE_RE, IP_RE, URL_RE
from app.services.storage import AnalysisStorage, TREE_SUBDIRS

METHOD_RE = re.compile(r"\b(?:public|private|protected|static|final|synchronized|native|abstract|\s)+[\w<>\[\], ?]+\s+(\w+)\s*\([^;]*\)\s*\{?")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|co|in|dev|app|cloud|api|xyz|info|biz)\b", re.IGNORECASE)

@dataclass(frozen=True)
class LineMatch:
    file_path: str
    line_number: int
    line: str
    method_name: str | None


BEHAVIOUR_RULES: tuple[dict, ...] = (
    {"name": "Reading Files", "severity": "LOW", "description": "Reads local files or streams.", "patterns": (r"FileInputStream\s*\(", r"\.read\s*\(", r"Files\.read")},
    {"name": "Writing Files", "severity": "WARNING", "description": "Writes data to local files or streams.", "patterns": (r"FileOutputStream\s*\(", r"\.write\s*\(", r"Files\.write")},
    {"name": "Deleting Files", "severity": "WARNING", "description": "Deletes files from local storage.", "patterns": (r"\.delete\s*\(", r"Files\.delete")},
    {"name": "Renaming Files", "severity": "LOW", "description": "Renames or moves files.", "patterns": (r"\.renameTo\s*\(", r"Files\.move")},
    {"name": "Creating Directories", "severity": "LOW", "description": "Creates directories on local storage.", "patterns": (r"\.mkdirs?\s*\(", r"Files\.createDirector")},
    {"name": "Reading Contacts", "severity": "HIGH", "description": "Accesses contacts content providers.", "patterns": (r"ContactsContract", r"READ_CONTACTS")},
    {"name": "Reading SMS", "severity": "HIGH", "description": "Reads SMS content or SMS permissions.", "patterns": (r"Telephony\.Sms", r"content://sms", r"READ_SMS")},
    {"name": "Sending SMS", "severity": "HIGH", "description": "Sends SMS messages.", "patterns": (r"SmsManager", r"SEND_SMS")},
    {"name": "Making Calls", "severity": "HIGH", "description": "Initiates phone calls.", "patterns": (r"ACTION_CALL", r"CALL_PHONE")},
    {"name": "Reading Call Logs", "severity": "HIGH", "description": "Reads call-log data.", "patterns": (r"CallLog", r"READ_CALL_LOG")},
    {"name": "Location Access", "severity": "WARNING", "description": "Uses Android location APIs.", "patterns": (r"LocationManager", r"FusedLocationProviderClient", r"ACCESS_FINE_LOCATION", r"ACCESS_COARSE_LOCATION")},
    {"name": "Camera Usage", "severity": "WARNING", "description": "Uses camera APIs or permission.", "patterns": (r"android\.hardware\.Camera", r"CameraManager", r"CAMERA")},
    {"name": "Microphone Usage", "severity": "WARNING", "description": "Uses audio recording APIs.", "patterns": (r"MediaRecorder", r"AudioRecord", r"RECORD_AUDIO")},
    {"name": "Clipboard Access", "severity": "WARNING", "description": "Reads or writes clipboard data.", "patterns": (r"ClipboardManager", r"ClipData")},
    {"name": "Bluetooth", "severity": "LOW", "description": "Uses Bluetooth APIs.", "patterns": (r"BluetoothAdapter", r"BLUETOOTH")},
    {"name": "WiFi", "severity": "LOW", "description": "Uses WiFi network APIs.", "patterns": (r"WifiManager", r"ACCESS_WIFI_STATE")},
    {"name": "NFC", "severity": "LOW", "description": "Uses NFC APIs.", "patterns": (r"NfcAdapter", r"android\.nfc")},
    {"name": "USB", "severity": "LOW", "description": "Uses USB host/device APIs.", "patterns": (r"UsbManager", r"android\.hardware\.usb")},
    {"name": "Accessibility Services", "severity": "HIGH", "description": "Uses accessibility service APIs.", "patterns": (r"AccessibilityService", r"BIND_ACCESSIBILITY_SERVICE")},
    {"name": "Overlay Windows", "severity": "HIGH", "description": "Requests or uses overlay window capability.", "patterns": (r"SYSTEM_ALERT_WINDOW", r"TYPE_APPLICATION_OVERLAY", r"canDrawOverlays")},
    {"name": "Notification Access", "severity": "WARNING", "description": "Accesses notification listener APIs.", "patterns": (r"NotificationListenerService", r"BIND_NOTIFICATION_LISTENER_SERVICE")},
    {"name": "Foreground Services", "severity": "LOW", "description": "Starts foreground services.", "patterns": (r"startForeground", r"FOREGROUND_SERVICE")},
    {"name": "Background Services", "severity": "LOW", "description": "Starts Android services in background contexts.", "patterns": (r"startService\s*\(", r"JobScheduler", r"WorkManager")},
    {"name": "Package Installation", "severity": "HIGH", "description": "Uses package installation APIs.", "patterns": (r"PackageInstaller", r"REQUEST_INSTALL_PACKAGES")},
    {"name": "Runtime Command Execution", "severity": "HIGH", "description": "Executes runtime commands.", "patterns": (r"Runtime\.getRuntime\(\)\.exec", r"ProcessBuilder")},
    {"name": "Shell Execution", "severity": "HIGH", "description": "Executes shell commands.", "patterns": (r"/system/bin/sh", r"su\b", r"sh -c")},
    {"name": "Reflection", "severity": "WARNING", "description": "Uses Java reflection APIs.", "patterns": (r"Class\.forName", r"getDeclaredMethod", r"java\.lang\.reflect")},
    {"name": "Dynamic Class Loading", "severity": "HIGH", "description": "Loads classes dynamically.", "patterns": (r"ClassLoader", r"loadClass\s*\(")},
    {"name": "DexClassLoader", "severity": "HIGH", "description": "Loads external dex bytecode.", "patterns": (r"DexClassLoader",)},
    {"name": "Native Code Loading", "severity": "WARNING", "description": "Loads native libraries at runtime.", "patterns": (r"System\.loadLibrary", r"System\.load\s*\(")},
    {"name": "SSL Pinning", "severity": "INFO", "description": "Uses certificate or public-key pinning APIs.", "patterns": (r"CertificatePinner", r"pinning", r"checkServerTrusted")},
    {"name": "Certificate Validation", "severity": "WARNING", "description": "Custom certificate validation logic is present.", "patterns": (r"X509TrustManager", r"TrustManager", r"HostnameVerifier")},
    {"name": "Root Detection", "severity": "INFO", "description": "Checks for rooted devices.", "patterns": (r"/system/xbin/su", r"test-keys", r"RootBeer", r"isDeviceRooted")},
    {"name": "Emulator Detection", "severity": "INFO", "description": "Checks for emulator indicators.", "patterns": (r"goldfish", r"ranchu", r"Build\.FINGERPRINT", r"Genymotion")},
    {"name": "Biometric APIs", "severity": "INFO", "description": "Uses Android biometric APIs.", "patterns": (r"BiometricPrompt", r"FingerprintManager")},
    {"name": "Crypto APIs", "severity": "INFO", "description": "Uses cryptographic APIs.", "patterns": (r"Cipher\.getInstance", r"MessageDigest", r"KeyStore")},
    {"name": "AES", "severity": "INFO", "description": "References AES cryptography.", "patterns": (r"AES",)},
    {"name": "RSA", "severity": "INFO", "description": "References RSA cryptography.", "patterns": (r"RSA",)},
    {"name": "DES", "severity": "HIGH", "description": "References DES cryptography.", "patterns": (r"DES", r"DESede")},
    {"name": "SHA", "severity": "INFO", "description": "References SHA hashing.", "patterns": (r"SHA-?\d*",)},
    {"name": "Base64", "severity": "INFO", "description": "Uses Base64 encoding or decoding.", "patterns": (r"Base64",)},
    {"name": "Network APIs", "severity": "INFO", "description": "Uses network APIs.", "patterns": (r"HttpURLConnection", r"URLConnection", r"Socket\s*\(")},
    {"name": "HTTP", "severity": "WARNING", "description": "References non-TLS HTTP endpoints.", "patterns": (r"http://",)},
    {"name": "HTTPS", "severity": "INFO", "description": "References TLS HTTPS endpoints.", "patterns": (r"https://",)},
    {"name": "Retrofit", "severity": "INFO", "description": "Uses Retrofit networking.", "patterns": (r"retrofit2", r"Retrofit\.Builder")},
    {"name": "OkHttp", "severity": "INFO", "description": "Uses OkHttp networking.", "patterns": (r"okhttp3", r"OkHttpClient")},
    {"name": "Volley", "severity": "INFO", "description": "Uses Android Volley networking.", "patterns": (r"com\.android\.volley", r"RequestQueue")},
    {"name": "Sockets", "severity": "WARNING", "description": "Uses raw socket APIs.", "patterns": (r"Socket\s*\(", r"ServerSocket")},
    {"name": "WebView Usage", "severity": "WARNING", "description": "Uses WebView APIs.", "patterns": (r"WebView", r"loadUrl\s*\(")},
    {"name": "SQLite", "severity": "INFO", "description": "Uses SQLite APIs.", "patterns": (r"SQLiteDatabase", r"SQLiteOpenHelper")},
    {"name": "Firebase", "severity": "INFO", "description": "Uses Firebase SDKs or endpoints.", "patterns": (r"firebase", r"Firebase")},
    {"name": "SharedPreferences", "severity": "INFO", "description": "Uses SharedPreferences storage.", "patterns": (r"SharedPreferences", r"getSharedPreferences")},
)

CODE_RULES: tuple[dict, ...] = (
    {"issue": "Hardcoded API Keys", "severity": "HIGH", "category": "Secrets", "description": "A probable API key is hardcoded in source.", "patterns": (r"AIza[0-9A-Za-z\-_]{35}", r"api[_-]?key\s*[=:]\s*[\"'][^\"']{12,}"), "cwe": "CWE-798", "owasp": "M9", "masvs": "MASVS-RESILIENCE", "recommendation": "Move secrets to a backend or protected runtime configuration."},
    {"issue": "Hardcoded Passwords", "severity": "HIGH", "category": "Secrets", "description": "A password-like literal is present in code.", "patterns": (r"password\s*[=:]\s*[\"'][^\"']{6,}", r"passwd\s*[=:]\s*[\"'][^\"']{6,}"), "cwe": "CWE-798", "owasp": "M9", "masvs": "MASVS-STORAGE", "recommendation": "Remove embedded credentials and rotate exposed values."},
    {"issue": "Hardcoded Tokens", "severity": "HIGH", "category": "Secrets", "description": "A token-like secret is hardcoded.", "patterns": (r"token\s*[=:]\s*[\"'][^\"']{16,}", r"bearer\s+[A-Za-z0-9._\-]{16,}"), "cwe": "CWE-798", "owasp": "M9", "masvs": "MASVS-STORAGE", "recommendation": "Keep tokens outside client binaries."},
    {"issue": "Hardcoded URLs", "severity": "INFO", "category": "Network", "description": "A URL is embedded in source.", "patterns": (r"https?://[\w\-.]+(?::\d+)?(?:/[\w\-./%?=&#:+~]*)?",), "cwe": None, "owasp": "M5", "masvs": "MASVS-NETWORK", "recommendation": "Review endpoints for exposure and environment leakage."},
    {"issue": "Hardcoded IPs", "severity": "WARNING", "category": "Network", "description": "A public IP literal is embedded in source.", "patterns": (IP_RE.pattern,), "cwe": None, "owasp": "M5", "masvs": "MASVS-NETWORK", "recommendation": "Use named hosts and review whether the IP is trusted."},
    {"issue": "Logging Sensitive Data", "severity": "WARNING", "category": "Logging", "description": "Logging APIs may expose sensitive data.", "patterns": (r"Log\.(?:d|e|i|v|w)\s*\(", r"System\.out\.print"), "cwe": "CWE-532", "owasp": "M9", "masvs": "MASVS-PRIVACY", "recommendation": "Remove sensitive logging from release builds."},
    {"issue": "Weak Random", "severity": "WARNING", "category": "Cryptography", "description": "Non-cryptographic randomness is used.", "patterns": (r"new\s+Random\s*\(", r"Math\.random\s*\("), "cwe": "CWE-338", "owasp": "M10", "masvs": "MASVS-CRYPTO", "recommendation": "Use SecureRandom for security decisions."},
    {"issue": "ECB Mode", "severity": "HIGH", "category": "Cryptography", "description": "ECB cipher mode is insecure for structured data.", "patterns": (r"/ECB/", r"ECB/PKCS"), "cwe": "CWE-327", "owasp": "M10", "masvs": "MASVS-CRYPTO", "recommendation": "Use authenticated encryption such as AES-GCM."},
    {"issue": "DES", "severity": "HIGH", "category": "Cryptography", "description": "DES/3DES is obsolete cryptography.", "patterns": (r"DESede", r"\bDES\b"), "cwe": "CWE-327", "owasp": "M10", "masvs": "MASVS-CRYPTO", "recommendation": "Replace DES with modern authenticated encryption."},
    {"issue": "MD5", "severity": "WARNING", "category": "Cryptography", "description": "MD5 is collision-prone.", "patterns": (r"MD5",), "cwe": "CWE-327", "owasp": "M10", "masvs": "MASVS-CRYPTO", "recommendation": "Use SHA-256 or stronger where hashing is required."},
    {"issue": "SHA1", "severity": "WARNING", "category": "Cryptography", "description": "SHA-1 is collision-prone.", "patterns": (r"SHA-?1",), "cwe": "CWE-327", "owasp": "M10", "masvs": "MASVS-CRYPTO", "recommendation": "Use SHA-256 or stronger where hashing is required."},
    {"issue": "Insecure SSL", "severity": "HIGH", "category": "Network", "description": "Custom trust logic may disable TLS validation.", "patterns": (r"TrustAll", r"ALLOW_ALL_HOSTNAME_VERIFIER", r"return\s+true\s*;"), "cwe": "CWE-295", "owasp": "M5", "masvs": "MASVS-NETWORK", "recommendation": "Use platform TLS validation and strict hostname checks."},
    {"issue": "HostnameVerifier", "severity": "HIGH", "category": "Network", "description": "Custom HostnameVerifier requires review.", "patterns": (r"HostnameVerifier",), "cwe": "CWE-297", "owasp": "M5", "masvs": "MASVS-NETWORK", "recommendation": "Avoid permissive hostname verification."},
    {"issue": "TrustManager", "severity": "HIGH", "category": "Network", "description": "Custom TrustManager requires review.", "patterns": (r"X509TrustManager", r"TrustManager"), "cwe": "CWE-295", "owasp": "M5", "masvs": "MASVS-NETWORK", "recommendation": "Do not trust arbitrary certificates."},
    {"issue": "WebView JavaScript Enabled", "severity": "WARNING", "category": "WebView", "description": "WebView JavaScript is enabled.", "patterns": (r"setJavaScriptEnabled\s*\(\s*true\s*\)",), "cwe": "CWE-749", "owasp": "M1", "masvs": "MASVS-PLATFORM", "recommendation": "Enable JavaScript only for trusted content."},
    {"issue": "Runtime.exec()", "severity": "HIGH", "category": "Command Execution", "description": "Runtime command execution is present.", "patterns": (r"Runtime\.getRuntime\(\)\.exec",), "cwe": "CWE-78", "owasp": "M7", "masvs": "MASVS-CODE", "recommendation": "Avoid shell command execution or strictly validate inputs."},
    {"issue": "DexClassLoader", "severity": "HIGH", "category": "Dynamic Loading", "description": "External dex loading is present.", "patterns": (r"DexClassLoader",), "cwe": "CWE-470", "owasp": "M8", "masvs": "MASVS-RESILIENCE", "recommendation": "Avoid loading untrusted code at runtime."},
    {"issue": "Reflection", "severity": "WARNING", "category": "Code Quality", "description": "Reflection is used.", "patterns": (r"Class\.forName", r"getDeclaredMethod", r"java\.lang\.reflect"), "cwe": "CWE-470", "owasp": "M7", "masvs": "MASVS-CODE", "recommendation": "Review reflection targets and input control."},
    {"issue": "WebView addJavascriptInterface", "severity": "HIGH", "category": "WebView", "description": "Java objects are exposed to WebView JavaScript.", "patterns": (r"addJavascriptInterface",), "cwe": "CWE-749", "owasp": "M1", "masvs": "MASVS-PLATFORM", "recommendation": "Expose only minimal interfaces to trusted origins."},
    {"issue": "External Storage Usage", "severity": "WARNING", "category": "Storage", "description": "External storage APIs are used.", "patterns": (r"getExternalStorage", r"Environment\.getExternalStorage"), "cwe": "CWE-922", "owasp": "M2", "masvs": "MASVS-STORAGE", "recommendation": "Store sensitive data in private app storage."},
    {"issue": "Clipboard Usage", "severity": "WARNING", "category": "Privacy", "description": "Clipboard APIs are used.", "patterns": (r"ClipboardManager", r"ClipData"), "cwe": "CWE-200", "owasp": "M2", "masvs": "MASVS-PRIVACY", "recommendation": "Avoid placing sensitive data on the clipboard."},
    {"issue": "Base64 Secrets", "severity": "WARNING", "category": "Secrets", "description": "Large Base64 literals may hide secrets.", "patterns": (r"[A-Za-z0-9+/]{40,}={0,2}",), "cwe": "CWE-798", "owasp": "M9", "masvs": "MASVS-STORAGE", "recommendation": "Review encoded literals and remove embedded secrets."},
    {"issue": "AWS Keys", "severity": "HIGH", "category": "Secrets", "description": "AWS access key pattern detected.", "patterns": (r"AKIA[0-9A-Z]{16}",), "cwe": "CWE-798", "owasp": "M9", "masvs": "MASVS-STORAGE", "recommendation": "Rotate the key and remove it from the app."},
    {"issue": "Private Keys", "severity": "HIGH", "category": "Secrets", "description": "Private key material appears in source.", "patterns": (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",), "cwe": "CWE-798", "owasp": "M9", "masvs": "MASVS-STORAGE", "recommendation": "Remove private keys from the client binary immediately."},
    {"issue": "JWT Secrets", "severity": "HIGH", "category": "Secrets", "description": "JWT-like token detected.", "patterns": (r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",), "cwe": "CWE-798", "owasp": "M9", "masvs": "MASVS-STORAGE", "recommendation": "Do not ship bearer tokens in mobile clients."},
)

TRACKER_NAMES = ("Firebase Analytics", "Google Analytics", "Facebook", "Adjust", "AppsFlyer", "Branch", "Crashlytics")

PERMISSION_INFO = {
    "android.permission.RECEIVE_BOOT_COMPLETED": ("Malware Permissions", "HIGH", "Starts when the device boots.", "Can provide persistence after reboot.", "Persistence, auto-start background agents."),
    "android.permission.SEND_SMS": ("Malware Permissions", "HIGH", "Allows sending SMS messages.", "Can cause fraud or exfiltrate via SMS.", "Premium SMS fraud and command channels."),
    "android.permission.READ_SMS": ("Malware Permissions", "HIGH", "Allows reading SMS messages.", "Can expose OTPs and private messages.", "OTP theft and account takeover."),
    "android.permission.READ_CONTACTS": ("Dangerous Permissions", "HIGH", "Allows reading contacts.", "Exposes personal address-book data.", "Contact harvesting and spam campaigns."),
    "android.permission.ACCESS_FINE_LOCATION": ("Dangerous Permissions", "WARNING", "Allows precise location access.", "Exposes physical movement and location.", "Tracking and targeted surveillance."),
    "android.permission.CAMERA": ("Dangerous Permissions", "WARNING", "Allows camera access.", "Can capture sensitive surroundings.", "Spyware capture workflows."),
    "android.permission.RECORD_AUDIO": ("Dangerous Permissions", "HIGH", "Allows microphone access.", "Can capture conversations.", "Audio surveillance."),
    "android.permission.SYSTEM_ALERT_WINDOW": ("Malware Permissions", "HIGH", "Allows drawing over other apps.", "Can support phishing overlays and tapjacking.", "Credential phishing overlays."),
    "android.permission.REQUEST_INSTALL_PACKAGES": ("Malware Permissions", "HIGH", "Allows requesting APK installation.", "Can sideload additional payloads.", "Dropper behaviour and staged installs."),
}


def run_static_scans(session: Session, analysis: Analysis) -> None:
    storage = AnalysisStorage(analysis.id)
    files = FileRepository(session).text_files(
        analysis.id,
        trees=("java", "smali", "resources", "manifest", "assets", "databases"),
        limit=30_000,
    )
    text_files = list(_iter_text_files(storage, files))
    _scan_recon(session, analysis.id, text_files)
    _scan_apkid(session, analysis, text_files)
    _scan_behaviours(session, analysis.id, text_files)
    _scan_code(session, analysis, text_files)
    _scan_permissions(session, analysis, text_files)
    _scan_domains(session, analysis.id)
    session.commit()


def _iter_text_files(storage: AnalysisStorage, records: list[DecompiledFile]):
    for rec in records:
        try:
            disk = safe_join(storage.tree_dir(rec.tree), _tree_relative(rec))
            if not disk.is_file() or disk.stat().st_size > 3_000_000:
                continue
            yield rec, disk.read_text("utf-8", errors="replace")
        except OSError:
            continue


def _tree_relative(rec: DecompiledFile) -> str:
    prefix = TREE_SUBDIRS.get(rec.tree, "")
    if rec.rel_path.startswith(prefix + "/"):
        return rec.rel_path[len(prefix) + 1:]
    return rec.rel_path


def _line_matches(text_files, patterns: tuple[str, ...], max_matches: int = 100) -> list[LineMatch]:
    compiled = [re.compile(p, re.IGNORECASE) for p in patterns]
    matches: list[LineMatch] = []
    for rec, text in text_files:
        method: str | None = None
        for i, line in enumerate(text.splitlines(), start=1):
            if m := METHOD_RE.search(line):
                method = m.group(1)
            if any(p.search(line) for p in compiled):
                matches.append(LineMatch(_tree_relative(rec), i, line.strip()[:500], method))
                if len(matches) >= max_matches:
                    return matches
    return matches


def _scan_recon(session: Session, analysis_id: str, text_files) -> None:
    seen: set[tuple[str, str, str, int]] = set()
    for rec, text in text_files:
        method: str | None = None
        for i, line in enumerate(text.splitlines(), start=1):
            if m := METHOD_RE.search(line):
                method = m.group(1)
            for kind, regex in (("url", URL_RE), ("email", EMAIL_RE), ("ip", IP_RE), ("firebase", FIREBASE_RE), ("domain", DOMAIN_RE)):
                for value in regex.findall(line):
                    value = value if isinstance(value, str) else str(value)
                    if kind == "domain" and "@" in value:
                        continue
                    key = (kind, value, _tree_relative(rec), i)
                    if key in seen or len(seen) > 8000:
                        continue
                    seen.add(key)
                    protocol = urlparse(value).scheme or None if kind == "url" else None
                    risk = "WARNING" if kind == "url" and value.lower().startswith("http://") else "INFO"
                    session.add(ReconFinding(
                        analysis_id=analysis_id, kind=kind, value=value,
                        protocol=protocol, indicator_type=_indicator_type(kind, value),
                        risk=risk, file_path=_tree_relative(rec), line_number=i,
                        method_name=method, context=line.strip()[:500]))


def _indicator_type(kind: str, value: str) -> str:
    if kind == "url":
        host = urlparse(value).hostname or ""
        return "cdn" if any(x in host for x in ("cloudfront", "akamai", "fastly", "cloudflare")) else "url"
    if kind == "domain":
        return "cdn" if any(x in value for x in ("cloudfront", "akamai", "fastly", "cloudflare")) else "hostname"
    return kind


def _scan_apkid(session: Session, analysis: Analysis, text_files) -> None:
    rules = (
        ("Compiler", "D8", (r"com/android/tools/r8", r"\.source \"D8"), "INFO"),
        ("Obfuscator", "ProGuard/R8", (r"proguard", r"mapping\.txt", r"a\.a\.a"), "WARNING"),
        ("Packer", "Known packer markers", (r"jiagu", r"bangcle", r"secneo", r"360jiagu"), "HIGH"),
        ("Protector", "Runtime protection", (r"DexGuard", r"Arxan", r"Promon", r"AppSealing"), "HIGH"),
        ("Anti VM", "Detected", (r"goldfish", r"ranchu", r"Genymotion", r"emulator"), "WARNING"),
        ("Anti Debug", "Detected", (r"Debug\.isDebuggerConnected", r"TracerPid", r"android/os/Debug"), "WARNING"),
        ("Anti Disassembly", "Detected", (r"anti.?tamper", r"integrity check", r"classes\.dex"), "WARNING"),
        ("Reflection", "Detected", (r"Class\.forName", r"java\.lang\.reflect"), "WARNING"),
        ("Kotlin Detection", "Kotlin", (r"kotlin/", r"kotlin\.", r"Metadata;"), "INFO"),
        ("Framework Detection", "Flutter", (r"io/flutter", r"FlutterActivity"), "INFO"),
        ("Framework Detection", "React Native", (r"com/facebook/react", r"ReactActivity"), "INFO"),
        ("Framework Detection", "Cordova", (r"org/apache/cordova", r"CordovaActivity"), "INFO"),
        ("Framework Detection", "Unity", (r"com/unity3d", r"UnityPlayer"), "INFO"),
        ("Framework Detection", "Xamarin", (r"mono/android", r"xamarin"), "INFO"),
        ("Encryption Libraries", "Detected", (r"BouncyCastle", r"SpongyCastle", r"javax\.crypto"), "INFO"),
        ("Interesting Strings", "Root/emulator strings", (r"/system/xbin/su", r"test-keys", r"frida"), "WARNING"),
    )
    for category, value, patterns, severity in rules:
        hits = _line_matches(text_files, patterns, max_matches=1)
        if hits:
            h = hits[0]
            session.add(ApkidResult(analysis_id=analysis.id, category=category,
                                    label=category, value=value, detected=True,
                                    severity=severity, file_path=h.file_path,
                                    line_number=h.line_number, evidence=h.line))
    multidex = len(list(AnalysisStorage(analysis.id).apk_dir.glob("*.apk"))) > 1
    native_count = sum(1 for _ in AnalysisStorage(analysis.id).native_dir.glob("*.so"))
    session.add(ApkidResult(analysis_id=analysis.id, category="Multidex",
                            label="Multidex", value="Detected" if multidex else "None",
                            detected=multidex, severity="INFO"))
    session.add(ApkidResult(analysis_id=analysis.id, category="Native Libraries",
                            label="Native Libraries", value=str(native_count),
                            detected=native_count > 0, severity="INFO"))


def _scan_behaviours(session: Session, analysis_id: str, text_files) -> None:
    for rule in BEHAVIOUR_RULES:
        for hit in _line_matches(text_files, rule["patterns"], max_matches=50):
            session.add(BehaviourFinding(
                analysis_id=analysis_id, name=rule["name"], severity=rule["severity"],
                description=rule["description"], java_file=hit.file_path,
                method_name=hit.method_name, line_number=hit.line_number,
                evidence=hit.line))


def _scan_code(session: Session, analysis: Analysis, text_files) -> None:
    for rule in CODE_RULES:
        for hit in _line_matches(text_files, rule["patterns"], max_matches=75):
            if rule["issue"] == "Hardcoded IPs" and hit.line.startswith(("10.", "192.168.", "127.", "0.")):
                continue
            session.add(CodeFinding(
                analysis_id=analysis.id, issue=rule["issue"], severity=rule["severity"],
                description=rule["description"], cwe=rule["cwe"], owasp=rule["owasp"],
                masvs=rule["masvs"], java_file=hit.file_path,
                line_number=hit.line_number, category=rule["category"],
                recommendation=rule["recommendation"], status="open", evidence=hit.line))
    manifest = session.query(Manifest).filter(Manifest.analysis_id == analysis.id).first()
    if manifest and manifest.debuggable:
        session.add(CodeFinding(
            analysis_id=analysis.id, issue="Debuggable Build", severity="HIGH",
            description="The APK manifest enables android:debuggable.", cwe="CWE-489",
            owasp="M8", masvs="MASVS-RESILIENCE", java_file="AndroidManifest.xml",
            line_number=None, category="Manifest", recommendation="Disable debuggable for release builds.",
            status="open", evidence="android:debuggable=true"))


def _scan_permissions(session: Session, analysis: Analysis, text_files) -> None:
    perms = session.query(Permission).filter(Permission.analysis_id == analysis.id).all()
    for perm in perms:
        default_category = "Dangerous Permissions" if perm.is_dangerous else "Normal Permissions"
        if perm.protection_level == "signature":
            default_category = "Signature Permissions"
        category, risk, desc, danger, usage = PERMISSION_INFO.get(
            perm.name,
            (default_category, "WARNING" if perm.is_dangerous else "INFO",
             perm.description or perm.name, "Review how the permission expands app access.",
             "Common abuse depends on surrounding code paths."),
        )
        token = perm.name.rsplit(".", 1)[-1]
        hits = _line_matches(text_files, (re.escape(perm.name), re.escape(token)), max_matches=20)
        files = sorted({h.file_path for h in hits})
        methods = sorted({h.method_name for h in hits if h.method_name})
        session.add(AbusedPermission(
            analysis_id=analysis.id, permission=perm.name, category=category,
            risk_level=risk, description=desc, dangerous_reason=danger,
            malware_usage=usage, used_in_code=bool(hits),
            files=json.dumps(files), methods=json.dumps(methods)))


def _scan_domains(session: Session, analysis_id: str) -> None:
    rows = session.query(ReconFinding).filter(
        ReconFinding.analysis_id == analysis_id,
        ReconFinding.kind.in_(("domain", "url", "firebase")),
    ).all()
    seen: set[str] = set()
    for row in rows:
        domain = urlparse(row.value).hostname if row.kind in ("url", "firebase") else row.value
        if not domain:
            continue
        domain = domain.lower()
        if domain in seen:
            continue
        seen.add(domain)
        session.add(DomainIntel(
            analysis_id=analysis_id, domain=domain, status="extracted",
            source_file=row.file_path, line_number=row.line_number))


def overview_security(session: Session, analysis: Analysis) -> dict:
    components = session.query(Analysis).get(analysis.id).components
    exported = sum(1 for c in components if c.exported)
    dangerous = session.query(Permission).filter(Permission.analysis_id == analysis.id,
                                                 Permission.is_dangerous.is_(True)).count()
    high = session.query(CodeFinding).filter(CodeFinding.analysis_id == analysis.id,
                                             CodeFinding.severity == "HIGH").count()
    warn = session.query(CodeFinding).filter(CodeFinding.analysis_id == analysis.id,
                                             CodeFinding.severity == "WARNING").count()
    info = session.query(CodeFinding).filter(CodeFinding.analysis_id == analysis.id,
                                             CodeFinding.severity == "INFO").count()
    native = session.query(DecompiledFile).filter(DecompiledFile.analysis_id == analysis.id,
                                                  DecompiledFile.tree == "native").count()
    libs = session.query(Library).filter(Library.analysis_id == analysis.id).all()
    trackers = [lib.name for lib in libs if any(t.lower() in lib.name.lower() for t in TRACKER_NAMES)]
    malware = session.query(MalwareFinding).filter(MalwareFinding.analysis_id == analysis.id).limit(20).all()
    penalty = min(100, high * 12 + warn * 5 + dangerous * 2 + exported * 2)
    score = max(0, 100 - penalty)
    tracker_score = max(0, 100 - len(trackers) * 15)
    risk = "LOW"
    if score < 40 or high >= 5:
        risk = "HIGH"
    elif score < 70 or high:
        risk = "MEDIUM"
    summary = []
    if high:
        summary.append(f"{high} high-severity code findings require review.")
    if dangerous:
        summary.append(f"{dangerous} dangerous permissions are declared.")
    if exported:
        summary.append(f"{exported} exported components increase the app attack surface.")
    if not summary:
        summary.append("No high-risk static indicators were detected by stored scans.")
    return {
        "security_score": score,
        "tracker_score": tracker_score,
        "overall_risk_level": risk,
        "exported_components_count": exported,
        "dangerous_permissions_count": dangerous,
        "native_libraries_count": native,
        "detected_trackers": trackers,
        "detected_third_party_sdks": [lib.name for lib in libs],
        "malware_indicators": [m.title for m in malware],
        "security_summary": summary,
        "static_analysis_summary": {"HIGH": high, "WARNING": warn, "LOW": 0, "INFO": info},
    }
