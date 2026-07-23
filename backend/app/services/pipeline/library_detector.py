"""Third-party library / framework detection.

Walks decompiled package paths (smali & java) and matches them against a
signature table to identify frameworks the way MobSF's "Libraries" view does:
AndroidX, Google Play Services, Firebase, Retrofit, OkHttp, Jetpack Compose,
Flutter, Cordova, React Native, Unity, Xamarin, and common utility libs.

Detection is path-prefix based, which is robust against obfuscation of *app*
code (framework packages are rarely renamed) and cheap to compute.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LibSignature:
    name: str
    category: str
    # Any of these package prefixes (dotted) marks a hit.
    prefixes: tuple[str, ...]
    risk: str = "LOW"
    license: str | None = None


SIGNATURES: tuple[LibSignature, ...] = (
    LibSignature("AndroidX", "Jetpack", ("androidx.",), license="Apache-2.0"),
    LibSignature("Android Support", "Jetpack", ("android.support.",), license="Apache-2.0"),
    LibSignature("Jetpack Compose", "UI", ("androidx.compose.",), license="Apache-2.0"),
    LibSignature("Google Play Services", "Google", ("com.google.android.gms.",), license="Proprietary"),
    LibSignature("Firebase", "Google", ("com.google.firebase.",), license="Proprietary"),
    LibSignature("Google Guava", "Utility", ("com.google.common.",), license="Apache-2.0"),
    LibSignature("Gson", "Serialization", ("com.google.gson.",), license="Apache-2.0"),
    LibSignature("Retrofit", "Networking", ("retrofit2.",), license="Apache-2.0"),
    LibSignature("OkHttp", "Networking", ("okhttp3.", "com.squareup.okhttp."), license="Apache-2.0"),
    LibSignature("Okio", "Networking", ("okio.",), license="Apache-2.0"),
    LibSignature("Glide", "Imaging", ("com.bumptech.glide.",), license="BSD/Apache-2.0"),
    LibSignature("Picasso", "Imaging", ("com.squareup.picasso.",), license="Apache-2.0"),
    LibSignature("Kotlin Stdlib", "Language", ("kotlin.", "kotlinx."), license="Apache-2.0"),
    LibSignature("RxJava", "Reactive", ("io.reactivex.", "rx."), license="Apache-2.0"),
    LibSignature("Dagger", "DI", ("dagger.",), license="Apache-2.0"),
    LibSignature("ButterKnife", "UI", ("butterknife.",), license="Apache-2.0"),
    LibSignature("EventBus", "Messaging", ("org.greenrobot.eventbus.",), license="Apache-2.0"),
    # Cross-platform runtimes — higher interest for RE.
    LibSignature("Flutter", "Cross-Platform", ("io.flutter.",), risk="MEDIUM", license="BSD-3"),
    LibSignature("React Native", "Cross-Platform", ("com.facebook.react.",), risk="MEDIUM", license="MIT"),
    LibSignature("Cordova", "Cross-Platform", ("org.apache.cordova.",), risk="MEDIUM", license="Apache-2.0"),
    LibSignature("Unity", "Game-Engine", ("com.unity3d.",), risk="MEDIUM", license="Proprietary"),
    LibSignature("Xamarin", "Cross-Platform", ("mono.", "md5"), risk="MEDIUM", license="MIT"),
    LibSignature("Cocos2d", "Game-Engine", ("org.cocos2dx.",), risk="MEDIUM", license="MIT"),
    # Ad / analytics SDKs — privacy-relevant.
    LibSignature("Facebook SDK", "Social", ("com.facebook.",), risk="MEDIUM", license="Proprietary"),
    LibSignature("AppsFlyer", "Analytics", ("com.appsflyer.",), risk="MEDIUM", license="Proprietary"),
    LibSignature("Crashlytics", "Analytics", ("com.crashlytics.", "com.google.firebase.crashlytics."), license="Proprietary"),
)


def detect_libraries(package_paths: set[str]) -> list[dict]:
    """Return detected libraries given a set of dotted package prefixes.

    ``package_paths`` is the set of directory-derived dotted packages present in
    the decompiled output (e.g. ``{"okhttp3.internal", "com.myapp.ui", …}``).
    """
    hits: dict[str, dict] = {}
    for sig in SIGNATURES:
        for pkg in package_paths:
            if any(pkg == p.rstrip(".") or pkg.startswith(p) for p in sig.prefixes):
                existing = hits.get(sig.name)
                if existing is None:
                    hits[sig.name] = {
                        "name": sig.name,
                        "category": sig.category,
                        "version": None,
                        "license": sig.license,
                        "risk": sig.risk,
                        "evidence": pkg,
                    }
                break
    return sorted(hits.values(), key=lambda h: h["name"].lower())
