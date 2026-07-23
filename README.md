# MPF – Mobile Penetration Testing & Reverse-Engineering Framework

**Version:** 2.0.0 | **OWASP-Aligned** | **Android Security & Static Analysis Platform**

> Educational & Authorised Research Use Only

---

## Overview

**MPF (Mobile Penetration Testing Framework)** is an end-to-end security validation and reverse-engineering platform for Android applications. It bridges the gap between static analysis, runtime behaviour inspection, compliance auditing, and vulnerability validation by offering both a **modern web-based Reverse-Engineering IDE** and a **Metasploit-inspired CLI engine**.

### Dual Interface Architecture
1. **Web IDE & Full-Stack Platform**: A web application featuring decompilation pipelines, interactive file tree navigation, Monaco code editing, component analysis, domain intelligence, and compliance report generation.
2. **CLI Engine (`mpf/`)**: A command-line interface with 24 security modules for testing vulnerability mechanics, attack chains, and payload simulations.

---

## Key Features

- **Full-Stack Static Analysis IDE**:
  - **Decompilation Pipeline**: Multi-phase APK disassembly using Jadx and Apktool via asynchronous Celery background workers.
  - **Interactive File Explorer**: Full directory tree navigation with syntax highlighting powered by Monaco Editor.
  - **Component Inspector**: Deep analysis of Android Activities, Services, Broadcast Receivers, and Content Providers.
  - **Security & Compliance Dashboards**:
    - **Manifest & Permission Risk Analysis**: Identification of abused and dangerous permissions.
    - **APKID & Compiler Detection**: Detection of packers, obfuscators, and compilers.
    - **Certificate & Signing Inspector**: Analysis of signatures, keystore integrity, and certificate validity.
    - **Domain Intelligence & Firebase Check**: Discovery of embedded endpoints, misconfigured Firebase databases, and hardcoded secrets.
    - **Malware & Threat Lookup**: Automated lookup and risk scoring against known malware patterns.
    - **Software Bill of Materials (SBOM)**: Dependency tracking, library vulnerability detection, and licence auditing.

- **CLI Engine & Vulnerability Verification**:
  - **Exploit Modules (9)**: Simulators for WebViews, SQL injections, IPC bypasses, Intent hijacking, Tapjacking, etc.
  - **Payload Modules (13)**: Evidence-gathering payload simulation modules.
  - **OWASP Mobile Top 10 Coverage**: 100% mapping (M1–M10) with automated risk scoring.
  - **Attack Chain Reasoning**: Automated multi-step vulnerability correlation engine.
  - **Multi-Format Reporting**: Automated JSON, HTML, and PDF compliance report generation.

---

## Project Structure

```
mpf/
├── backend/                    # FastAPI backend & Celery worker service
│   ├── app/
│   │   ├── api/v1/             # REST API endpoints (analysis, security, files, intel)
│   │   ├── core/               # Configuration & logging settings
│   │   ├── db/                 # Database models & SQLAlchemy sessions
│   │   ├── services/           # Decompilation, parsing & security analysis engines
│   │   └── workers/            # Celery asynchronous task queues
│   ├── alembic/                # Database migration scripts
│   ├── Dockerfile              # Container definition for backend/worker
│   └── requirements.txt        # Python backend dependencies
├── frontend/                   # React + TypeScript + Vite Web IDE
│   ├── src/
│   │   ├── components/         # Navigation, layout, and UI components
│   │   ├── pages/              # Security analysis views & dashboards
│   │   └── api/                # API client hooks & query integration
│   ├── package.json            # Node dependencies & scripts
│   └── vite.config.ts          # Vite build configuration
├── mpf/                        # Metasploit-inspired CLI engine (Ruby)
│   ├── mpf.rb                  # Main CLI entrypoint
│   ├── core/                   # Framework engine & dispatcher
│   ├── engines/                # Static analyzer & OWASP engine
│   └── modules/                # Exploit, payload & auxiliary modules
├── storage/                    # Persistent artifact store for decompiled APKs
├── docker-compose.yml          # Multi-container orchestrator (Postgres, Redis, Backend, Worker)
├── install.sh                  # One-command dependency setup script
├── start.sh                    # All-in-one local launcher script
└── README.md                   # Project documentation
```

---

## Tech Stack

### Web Platform
- **Backend Framework**: FastAPI (Python 3.11+)
- **Async Task Broker**: Celery + Redis 7
- **Database**: PostgreSQL 16 (or SQLite for development)
- **ORMs & Migrations**: SQLAlchemy 2.0 + Alembic
- **Frontend Framework**: React 18, TypeScript, Vite
- **Code Viewer**: Monaco Editor (`@monaco-editor/react`)
- **State & Data Fetching**: TanStack React Query v5
- **Decompilation Tools**: Jadx, Apktool, `lxml`, `defusedxml`

### CLI Engine
- **Language**: Ruby 2.7+
- **CLI Interface**: Readline (stdlib)
- **Parsing**: REXML (stdlib)

---

## Quick Start

### 1. Web IDE & Full-Stack Platform Setup

#### Prerequisites
- Docker & Docker Compose
- Python 3.10+
- Node.js 18+ & npm

#### Automatic Installation & Launch
Run the installation script to prepare dependencies, start database containers, and run migrations:

```bash
# Clone the repository
git clone https://github.com/dozikim/mpf.git
cd mpf

# Install dependencies and setup environment
./install.sh

# Launch all services (Postgres, Redis, FastAPI, Celery, React Frontend)
./start.sh
```

Once started, access the interfaces at:
- **Web IDE (Frontend)**: [http://localhost:5173](http://localhost:5173)
- **Backend REST API**: [http://localhost:8000](http://localhost:8000)
- **Interactive Swagger Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)

#### Docker Compose Launch (Alternative)
You can also launch the full backend stack via Docker:

```bash
docker compose up --build -d
```

---

### 2. CLI Engine Setup (Legacy / Terminal Mode)

To run the interactive Metasploit-like CLI interface:

```bash
# Ensure Ruby 2.7+, apktool, and adb are installed
cd mpf

# Launch the interactive CLI
ruby mpf.rb

# Inside the MPF CLI shell:
mpf > analyze /path/to/target.apk
mpf > use exploits/android/webview_rce
mpf exploit(webview_rce) > set TARGET /path/to/target.apk
mpf exploit(webview_rce) > run
mpf > report generate
```

---

## Module Inventory & OWASP Alignment

### Exploit Modules (9)

| Module | OWASP Mapping | Severity | Description |
|--------|---------------|----------|-------------|
| `sql_injection` | M2, M7 | CRITICAL | Identifies vulnerable content providers and SQLite queries |
| `webview_rce` | M1, M7 | CRITICAL | Detects insecure `addJavascriptInterface` exposures |
| `ipc_bypass` | M1 | HIGH | Identifies unprotected exported components |
| `intent_hijacking` | M1 | HIGH | Tests implicit intent vulnerabilities |
| `deeplink_injection` | M1, M7 | HIGH | Evaluates unvalidated deep link schemes |
| `broadcast_receiver_exploit` | M1 | HIGH | Audits unprotected broadcast receivers |
| `fragment_injection` | M1, M4 | HIGH | Audits preference activity fragment injection |
| `clipboard_hijack` | M2 | MEDIUM | Detects sensitive data leaks to global clipboard |
| `tapjacking` | M1 | MEDIUM | Tests overlay vulnerability exposure |

### Payload Modules (13)

| Module | OWASP Mapping | Severity | Description |
|--------|---------------|----------|-------------|
| `data_exfiltration` | M2 | CRITICAL | Simulates sensitive data exfiltration |
| `reverse_shell` | M1 | CRITICAL | Terminal shell connectivity simulation |
| `keylogger` | M2, M4 | CRITICAL | Keystroke interception simulation |
| `sms_interceptor` | M2 | CRITICAL | SMS message capture simulation |
| `credential_stealer` | M2, M4 | CRITICAL | Account token/credential harvesting simulation |
| `persistence_agent` | M8 | HIGH | Boot receiver persistence verification |
| `contact_harvester` | M2 | HIGH | Address book exposure simulation |
| `token_extractor` | M4, M5 | HIGH | Auth token discovery in storage/logs |
| `screen_capture` | M2 | HIGH | Surface capture permission testing |
| `gps_tracker` | M2 | MEDIUM | Location tracking data access simulation |
| `clipboard_spy` | M2 | MEDIUM | Background clipboard read simulation |
| `log_injector` | M7 | MEDIUM | Logcat data pollution check |
| `broadcast_spoofer` | M1 | MEDIUM | System broadcast event spoofing test |

### OWASP Mobile Top 10 (100% Coverage)

| Category | Vulnerability Name | Status |
|----------|-------------------|--------|
| **M1** | Improper Platform Usage | ✅ Covered |
| **M2** | Insecure Data Storage | ✅ Covered |
| **M3** | Insecure Communication | ✅ Covered |
| **M4** | Insecure Authentication | ✅ Covered |
| **M5** | Insufficient Cryptography | ✅ Covered |
| **M6** | Insecure Authorization | ✅ Covered |
| **M7** | Client Code Quality | ✅ Covered |
| **M8** | Code Tampering | ✅ Covered |
| **M9** | Reverse Engineering | ✅ Covered |
| **M10** | Extraneous Functionality | ✅ Covered |

---

## Safety & Ethics

All modules within MPF run strictly in **simulation and audit mode**:
- **Non-Destructive**: No persistent unauthorized alterations to target systems.
- **Evidence-Driven**: Focuses on evidence collection, static pattern matching, and compliance validation.
- **Audit Logging**: Comprehensive activity logs maintained for session tracking.

> ⚠️ **LEGAL DISCLAIMER**: MPF is designed exclusively for educational purposes and authorized security assessments. Operating MPF against targets without prior written permission is illegal and strictly prohibited.

---

## License

Educational and Research Use Only. See the `LICENSE` file for details.

