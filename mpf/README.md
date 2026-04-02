# MPF – Mobile Penetration Testing Framework

**Version:** 2.0.0 | **OWASP-Aligned** | **Android Security Assessment Platform**

> B.Tech Final Year Research Project | Educational Use Only

---

## Overview

MPF is a comprehensive, **Metasploit-inspired** security validation platform for Android application security assessment. It addresses the critical fragmentation problem in mobile security testing by providing a unified framework combining:

- **Static Analysis** – APK decompilation and code scanning
- **Dynamic Analysis** – ADB-based runtime behaviour analysis
- **Exploit Modules** – 9 exploit modules for common Android vulnerabilities
- **Payload System** – 13 payload modules (simulation/evidence-only)
- **OWASP Compliance** – 100% Mobile Top 10 coverage with automated scoring
- **Attack Chain Reasoning** – Automated multi-step vulnerability correlation
- **Report Generation** – JSON, HTML, and PDF compliance reports

---

## Quick Start

```bash
# Prerequisites
# Ruby 2.7+, apktool, adb (Android Debug Bridge)

# Run the framework
ruby mpf.rb

# Inside the MPF CLI:
mpf > use exploits/android/webview_rce
mpf exploit(webview_rce) > set TARGET /path/to/app.apk
mpf exploit(webview_rce) > run

# Full analysis pipeline:
mpf > analyze /path/to/app.apk
mpf > report generate
```

---

## Directory Structure

```
mpf/
├── mpf.rb                      # Main entry point
├── core/
│   ├── framework.rb            # Module registry & orchestration
│   ├── session.rb              # Session state management
│   └── dispatcher.rb           # Module execution engine
├── engines/
│   ├── static_analyzer.rb      # 6-phase APK analysis engine
│   ├── owasp_engine.rb         # OWASP Mobile Top 10 compliance engine
│   └── chain_reasoner.rb       # Attack chain reasoning engine
├── modules/
│   ├── exploits/               # 9 exploit modules
│   │   ├── sql_injection.rb
│   │   ├── webview_rce.rb
│   │   ├── ipc_bypass.rb
│   │   ├── intent_hijacking.rb
│   │   ├── deeplink_injection.rb
│   │   ├── broadcast_receiver_exploit.rb
│   │   ├── clipboard_hijack.rb
│   │   ├── fragment_injection.rb
│   │   └── tapjacking.rb
│   ├── payloads/               # 13 payload modules
│   │   ├── data_exfiltration.rb
│   │   ├── reverse_shell.rb
│   │   ├── persistence_agent.rb
│   │   ├── keylogger.rb
│   │   ├── screen_capture.rb
│   │   ├── gps_tracker.rb
│   │   ├── contact_harvester.rb
│   │   ├── sms_interceptor.rb
│   │   ├── clipboard_spy.rb
│   │   ├── credential_stealer.rb
│   │   ├── token_extractor.rb
│   │   ├── log_injector.rb
│   │   └── broadcast_spoofer.rb
│   └── auxiliary/              # 2 auxiliary modules
│       ├── apk_info_scanner.rb
│       └── permission_analyzer.rb
├── reporters/
│   ├── json_reporter.rb        # JSON compliance report generator
│   └── html_reporter.rb        # Interactive HTML report generator
├── cli/
│   ├── banner.rb               # MPF ASCII banner
│   └── commander.rb            # REPL command processor
├── config/
│   └── owasp_rules.yml         # OWASP rules & compatibility matrix
├── docs/
│   └── USAGE.md                # Detailed usage documentation
├── reports/                    # Generated reports (JSON, HTML)
└── test_apps/                  # Sample vulnerable APK descriptors
```

---

## Module Inventory

### Exploit Modules (9)

| Module | OWASP | Severity |
|--------|-------|----------|
| sql_injection | M2, M7 | CRITICAL |
| webview_rce | M1, M7 | CRITICAL |
| ipc_bypass | M1 | HIGH |
| intent_hijacking | M1 | HIGH |
| deeplink_injection | M1, M7 | HIGH |
| broadcast_receiver_exploit | M1 | HIGH |
| fragment_injection | M1, M4 | HIGH |
| clipboard_hijack | M2 | MEDIUM |
| tapjacking | M1 | MEDIUM |

### Payload Modules (13)

| Module | OWASP | Severity |
|--------|-------|----------|
| data_exfiltration | M2 | CRITICAL |
| reverse_shell | M1 | CRITICAL |
| keylogger | M2, M4 | CRITICAL |
| sms_interceptor | M2 | CRITICAL |
| credential_stealer | M2, M4 | CRITICAL |
| persistence_agent | M8 | HIGH |
| contact_harvester | M2 | HIGH |
| token_extractor | M4, M5 | HIGH |
| screen_capture | M2 | HIGH |
| gps_tracker | M2 | MEDIUM |
| clipboard_spy | M2 | MEDIUM |
| log_injector | M7 | MEDIUM |
| broadcast_spoofer | M1 | MEDIUM |

### Auxiliary Modules (2)

| Module | Purpose |
|--------|---------|
| apk_info_scanner | APK metadata extraction |
| permission_analyzer | Permission risk analysis |

---

## OWASP Mobile Top 10 Coverage

| Category | Name | Covered |
|----------|------|---------|
| M1 | Improper Platform Usage | ✅ |
| M2 | Insecure Data Storage | ✅ |
| M3 | Insecure Communication | ✅ |
| M4 | Insecure Authentication | ✅ |
| M5 | Insufficient Cryptography | ✅ |
| M6 | Insecure Authorization | ✅ |
| M7 | Client Code Quality | ✅ |
| M8 | Code Tampering | ✅ |
| M9 | Reverse Engineering | ✅ |
| M10 | Extraneous Functionality | ✅ |

**Coverage: 100% (10/10)**

---

## CLI Commands

```
use <module>            Load an exploit, payload, or auxiliary module
set <OPTION> <value>    Set a module option
show [options|modules|payloads|auxiliary|all]
run / exploit           Execute the loaded module
analyze <apk>           Run full 6-phase analysis pipeline
report generate         Generate JSON + HTML compliance reports
search <term>           Search available modules
info                    Show info on current module
back                    Unload current module
help                    Show help
exit / quit             Exit MPF
```

---

## Framework Statistics

- **Lines of Code:** 8,000+ (production Ruby)
- **Total Modules:** 24
- **Detection Rules:** 26 (OWASP M1–M10)
- **Vulnerability Types:** 50+
- **Report Formats:** JSON, HTML, PDF
- **Android API Support:** 21–34 (Android 5.0 – 14.0)

---

## Experimental Results

| Application | Vulnerabilities | Detected | Rate |
|-------------|----------------|----------|------|
| DIVA | 13 | 13 | 100% |
| FakeBank | 8 | 8 | 100% |
| Hackway | 10 | 9 | 90% |

**Average Detection Rate: 96.7%**

---

## Safety & Ethics

All exploit and payload modules operate in **safe/simulation mode**:
- No persistent changes made to target systems
- Evidence collected only — no actual exploitation
- Full audit log maintained per session
- Designed for authorised security assessments only

> ⚠️ **LEGAL WARNING:** Use MPF only on applications you own or have explicit written authorisation to test. Unauthorised testing is illegal.

---

## Technology Stack

- **Language:** Ruby 2.7+
- **APK Decompilation:** apktool
- **Android Bridge:** ADB (Android Debug Bridge)
- **XML Parsing:** REXML (stdlib)
- **CLI Interface:** Readline (stdlib)
- **Report Formats:** JSON, HTML, PDF

---

## License

Educational and Research Use Only. See LICENSE file.

---

*MPF – Mobile Penetration Testing Framework v2.0.0 | B.Tech Final Year Project | March 2026*
