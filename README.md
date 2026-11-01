# CYBERCORE v1.0.0-rc1 — Cybersecurity & Threat Intelligence Platform

CYBERCORE is a modern, enterprise-grade digital defense and cyber threat intelligence platform. Built on the **Obsidian Luxury** and **Arctic Glass** design system, it delivers real-time URL heuristic analysis, IP & domain reconnaissance, password exposure auditing, server-side binary and file inspection, cryptographic signature lookup, an AI security copilot, and crowdsourced community threat reporting.

---

## 🛡️ Core Capabilities

| Capability | Workstation Route | API Endpoint | Description |
| :--- | :--- | :--- | :--- |
| **URL Security Scanner** | `/security-tools/url-scanner` | `POST /api/v1/scan/`<br>`GET /api/v1/scan/{scan_id}` | Concurrent multi-engine URL inspection: SSL verification, DNS resolution, heuristic pattern analysis, Google Safe Browsing, and VirusTotal reputation with explicit SSRF mitigation. |
| **IP & Domain Intelligence** | `/security-tools/ip-domain-analyzer` | `POST /api/v1/ip-domain/analyze`<br>`GET /api/v1/ip-domain/{query}` | Technical reconnaissance for IPv4/IPv6 addresses and apex domains: A/AAAA, MX, NS, TXT apex records, DMARC/SPF checks, apex DKIM heuristic hint (`has_dkim_hint`, not selector-based RFC 6376 email verification), reverse DNS (PTR), and RDAP registration metadata. |
| **Password Breach Checker** | `/security-tools` (Module) | `GET /api/v1/password/range/{prefix}` | Privacy-preserving credential auditing using k-anonymity (SHA-1 prefix matching via Have I Been Pwned API). Raw passwords never leave browser memory. |
| **Cryptographic Hash Lookup** | `/security-tools/hash-lookup` | `POST /api/v1/files/hash-lookup` | Zero-knowledge binary reputation lookup across MD5, SHA-1, and SHA-256 digests. Accurately reports `UNASSESSED` when external telemetry is unconfigured. |
| **Binary & File Analyzer** | `/security-tools/file-analyzer` | `POST /api/v1/files/analyze` | Multipart binary file inspection: calculates SHA-256/SHA-1/MD5 on the fly, checks magic bytes to detect disguised file extensions (e.g. `invoice.pdf.exe`), and checks malware signatures with strict 25 MB streaming limits. |
| **Message Scam Analyzer** | `/security-tools/message-analyzer` | `POST /api/v1/messages/analyze` | Deterministic regex and pattern taxonomy engine analyzing phishing SMS (smishing), cryptocurrency drainers, courier delivery lures, urgency markers, and brand impersonation. Does not use black-box ML models. |
| **AI Security Assistant** | `/assistant` | `POST /api/v1/ai/chat`<br>`GET /api/v1/ai/suggestions` | Conversational cyber defense advisor supporting incident triage and mitigation recommendations. Connects to Gemini/OpenAI when API keys are configured; deterministically falls back to a security knowledge base without external keys. Does not execute shell commands or autonomous tools. |
| **Threat Intelligence & Community Reports** | `/threat-intelligence` | `GET /api/v1/dashboard/threat-feed`<br>`POST /api/v1/dashboard/report`<br>`GET /api/v1/dashboard/reports` | Curated threat advisories combined with a durable SQLite WAL-backed crowdsourced community reporting pipeline and authenticated moderation workflow. Note: Dashboard overview stats and recent scans are static demonstration fixtures. |
| **Browser Extension Shield** | `extension/` (Chrome MV3) | `http://localhost:8000/api/v1/scan/` | Client-side Manifest V3 browser extension providing real-time tab navigation scanning and malicious site blocking. |

---

## 🏗️ Architecture & Technology Stack

```
   ┌─────────────────────────────────────────────────────────────┐
   │                   CYBERCORE CLIENT TIERS                    │
   │                                                             │
   │   Next.js 14 Web Portal         Chrome MV3 Browser Shield   │
   │   (Obsidian / Arctic Glass)     (Background Service Worker) │
   └───────────────────────────────┬─────────────────────────────┘
                                   │ HTTPS / REST (X-Request-ID)
                                   ▼
   ┌─────────────────────────────────────────────────────────────┐
   │                    FASTAPI BACKEND ENGINE                   │
   │                                                             │
   │   SlowAPI Rate Limiter        Correlation & Latency Middleware│
   │   Trusted Proxy Header Guard  SSRF Blocklist & Input Filter │
   │                                                             │
   │   • /api/v1/scan/             • /api/v1/ip-domain/          │
   │   • /api/v1/files/            • /api/v1/messages/           │
   │   • /api/v1/password/         • /api/v1/dashboard/         │
   │   • /api/v1/ai/               • /api/health                 │
   └───────────────┬───────────────────────────────┬─────────────┘
                   │                               │
                   ▼                               ▼
   ┌───────────────────────────────┐ ┌───────────────────────────┐
   │   PERSISTENT STORAGE ENGINE   │ │  EXTERNAL INTEL PROVIDERS │
   │                               │ │                           │
   │   SQLite 3 with WAL Mode      │ │   • VirusTotal API        │
   │   PRAGMA busy_timeout = 10000 │ │   • Google Safe Browsing  │
   │   Hot Online Backup API       │ │   • Have I Been Pwned     │
   │   community_threat_reports    │ │   • RDAP / DNS Resolution │
   └───────────────────────────────┘ └───────────────────────────┘
```

- **Frontend:** Next.js 14 (App Router), React 18, TypeScript, Tailwind CSS, Lucide React, Geist Fonts.
- **Backend:** FastAPI, Python 3.11+, Pydantic v2, SlowAPI, Uvicorn (ASGI).
- **Storage:** SQLite3 with Write-Ahead Logging (`WAL`), online hot backup (`conn.backup()`), busy timeout.
- **Containerization:** Multi-stage Dockerfiles (`python:3.11-slim`, `node:20-alpine`), unprivileged non-root execution (`cybercore:10001`, `nextjs:1001`), Docker Compose production orchestration.

---

## 📂 Repository Structure

```
CYBERCORE-1/
├── backend/
│   ├── app/
│   │   ├── config.py             # Pydantic BaseSettings & environment validation
│   │   ├── main.py               # FastAPI application, correlation middleware, health
│   │   ├── limiter.py            # Centralized SlowAPI rate limiter
│   │   ├── models/               # Pydantic schemas (scan, messages, files)
│   │   ├── routers/              # API controllers (scan, files, password, ip_domain, dashboard, ai)
│   │   ├── services/             # Core security engines (dns_analyzer, file_analyzer, report_store)
│   │   └── utils/                # Security utilities (auth, validators, proxy extraction)
│   ├── backups/                  # Verified online database backup snapshots (.db)
│   ├── tests/                    # Comprehensive automated test suite (45 unit/regression tests)
│   ├── Dockerfile                # Multi-stage hardened backend Dockerfile
│   └── requirements.txt          # Production Python dependencies
├── frontend/
│   ├── src/
│   │   ├── app/                  # Next.js App Router routes (/, /security-tools, /assistant, etc.)
│   │   ├── components/           # UI components, layout, investigation cards, dashboard widgets
│   │   ├── lib/                  # ApiClient, HTTP service wrappers, formatters
│   │   └── types/                # Strict TypeScript API contracts
│   ├── tests/                    # Node.js test runner unit & integration tests
│   ├── Dockerfile                # Multi-stage hardened frontend Dockerfile
│   └── package.json              # Frontend scripts & dependencies
├── extension/                    # Manifest V3 Chrome Extension
│   ├── manifest.json             # Extension permissions & declarative configuration
│   ├── background.js             # Service worker handling navigation tab scans
│   ├── content.js                # In-page warning & banner injection
│   └── popup.html                # Quick status popup
├── docker-compose.production.yml # Production multi-container orchestration
├── .env.production.example       # Template for production secret configuration
├── start.sh                      # Unified launch script
├── ARCHITECTURE.md               # Complete architectural specifications
├── SECURITY.md                   # Security model, threat analysis & disclosure policy
└── RELEASE_NOTES.md              # Version changelog and feature inventory
```

---

## ⚙️ Environment Configuration

Copy `.env.production.example` to `backend/.env` for local configuration:

```bash
# Application Environment
APP_ENV=development
APP_PORT=8000
APP_HOST=0.0.0.0
APP_SECRET_KEY=dev_secret_key_change_in_production_min_32_chars

# Administrative Secret (Required for /dashboard/backup and /dashboard/reports moderation)
ADMIN_API_KEY=your_secure_admin_key_here

# Database Storage Location
DATABASE_PATH=cybercore.db

# Reverse Proxy Trusted IP List (Comma-separated CIDRs or IPs)
TRUSTED_PROXIES=127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12

# External Security APIs (Optional for local testing; returns UNASSESSED if omitted)
VIRUSTOTAL_API_KEY=
GOOGLE_SAFE_BROWSING_API_KEY=
HIBP_API_KEY=

# AI Assistant Provider (Optional: supports Gemini or OpenAI API keys; uses built-in knowledge base if omitted)
GEMINI_API_KEY=
OPENAI_API_KEY=
```

Frontend configuration in `frontend/.env.local`:
```bash
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000/api/v1
```

---

## 🚀 Installation & Running

### Option 1: Automated Script
```bash
./start.sh
```

### Option 2: Manual Development Mode

#### 1. Backend Service
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
- API Base URL: `http://localhost:8000/api/v1`
- Swagger Documentation (Dev Mode only): `http://localhost:8000/api/docs`
- Health Probe: `http://localhost:8000/api/health`

#### 2. Frontend Application
```bash
cd frontend
npm install
npm run dev
```
- Web Application: `http://localhost:3000`

#### 3. Browser Extension Setup
1. In Chrome or any Chromium browser (Arc, Brave, Edge), navigate to `chrome://extensions/`.
2. Toggle on **Developer mode** in the upper right.
3. Click **Load unpacked** and select the `extension/` directory.

---

## 🧪 Testing & Quality Assurance

### Run Backend Test Suite (45 Tests)
```bash
cd backend
.venv/bin/python -m unittest discover -s tests -p "test_*.py"
```
Covers:
- `test_hash_checker.py`: Hash length, hex validation, VirusTotal availability states.
- `test_threat_reports.py`: SQLite persistence, deduplication, report moderation.
- `test_regression.py`: Multipart uploads, spoofed extension detection, k-anonymity.
- `test_production_readiness.py`: Admin auth, SlowAPI rate limiting, trusted proxy anti-spoofing.
- `test_adversarial_security.py`: Concurrency WAL stress (10 threads), SSRF attacks, isolated restore.

### Run Frontend Tests, Lint & Build
```bash
# Run unit & API client tests
node --test frontend/tests/api-client.test.mjs

# Strict TypeScript validation
cd frontend && npm run typecheck

# ESLint audit
cd frontend && npm run lint

# Production compilation
cd frontend && npm run build
```

---

## ⚠️ Known Limitations & Operational Considerations

1. **Docker Runtime Verification (Host Storage Constraint):**
   - On the development workstation, Docker Desktop daemon encountered containment storage I/O errors due to the host macOS APFS container reaching 100% capacity (`124 MiB` available).
   - Docker container runtime validation is documented as **NOT TESTED** in the Phase 6/6.1 security reports.
   - For production Linux deployments, standard Docker Engine with >15 GB free space is required.
2. **External Intelligence Subsystems:**
   - When API keys for VirusTotal or Google Safe Browsing are not provisioned, CYBERCORE displays explicit `UNASSESSED` badges with `risk_score: null`. It **never** fabricates clean scores or reports missing intelligence as safe.
   - Have I Been Pwned queries use the public k-anonymity API without requiring a mandatory key.
   - **Shodan and AbuseIPDB are NOT IMPLEMENTED** in the current release. Previous documentation referencing them has been corrected.
3. **Email Security (DKIM):**
   - The IP & Domain intelligence engine checks for `v=dkim1` substring hints within apex domain TXT records (`has_dkim_hint`). It does **not** perform full RFC 6376 cryptographic DKIM selector verification, which requires specific message headers and selectors.
4. **Demonstration Fixtures vs. Live Data:**
   - The Overview dashboard metrics (`/dashboard/stats`) and recent scan cards (`/dashboard/recent`) are static demonstration fixtures.
   - Threat intelligence campaigns (`/dashboard/threat-feed`) are curated human reference advisories.
   - Community threat reports (`/dashboard/report`, `/dashboard/reports`) are live SQLite WAL-persisted records.
5. **Database Architecture:**
   - The bundled SQLite database is configured for single-node vertical workloads. For multi-node distributed container clusters (Kubernetes), transition to PostgreSQL via the abstraction layer in `report_store.py`.

---

## 📄 License & Attribution

Designed and engineered for enterprise cyber threat defense. All rights reserved.
