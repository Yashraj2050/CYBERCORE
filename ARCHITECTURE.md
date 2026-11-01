# CYBERCORE — SYSTEM ARCHITECTURE SPECIFICATION

**Document Version:** 1.0.0-rc1
**Target Platform:** CYBERCORE Cyber Threat Intelligence & Analysis
**Repository Path:** `/Users/yashrajdnyaneshwarkuyate/CYBERCORE-1`
**Classification:** Enterprise System Specification

---

## 1. System Overview

CYBERCORE is structured as a decoupled, multi-tier threat intelligence and digital security analysis platform. It combines a client-side Next.js 14 web application, a Manifest V3 browser extension shield, a hardened Python FastAPI backend, and an embedded high-performance SQLite database operating in Write-Ahead Logging (`WAL`) mode.

```
+-------------------------------------------------------------------------+
|                              CLIENT TIER                                |
|                                                                         |
|  +--------------------------------+  +--------------------------------+ |
|  |     Next.js 14 Web Portal      |  |   Manifest V3 Chrome Extension | |
|  |   • Obsidian Luxury Theme      |  |   • Background Service Worker  | |
|  |   • Monolithic Bento Matrix    |  |   • Real-Time Tab Interceptor  | |
|  |   • Zero File/Password Storage |  |   • In-Page Advisory Injection | |
|  +--------------------------------+  +--------------------------------+ |
+-----------------------------------▲-------------------------------------+
                                    │ HTTPS (X-Request-ID, Strict CORS)
+-----------------------------------▼-------------------------------------+
|                             ROUTING TIER                                |
|                                                                         |
|  +-------------------------------------------------------------------+  |
|  |  Operational Middleware Stack                                     |  |
|  |  • Correlation ID Middleware (X-Request-ID tracking)              |  |
|  |  • Latency Benchmark Middleware (X-Response-Time in ms)           |  |
|  |  • Reverse-Proxy IP Guard (Anti-spoofing via TRUSTED_PROXIES)     |  |
|  |  • SlowAPI Rate Limiting Bus (In-Memory sliding-window limiter)   |  |
|  |  • OWASP Security Headers (nosniff, DENY, strict-origin)          |  |
|  +-------------------------------------------------------------------+  |
+-----------------------------------▲-------------------------------------+
                                    │
+-----------------------------------▼-------------------------------------+
|                           CONTROLLER TIER                               |
|                                                                         |
|  +-------------------+  +-------------------+  +---------------------+  |
|  | scan.py           |  | ip_domain.py      |  | files.py            |  |
|  | URL threat triage |  | DNS & RDAP intel  |  | File/hash analysis  |  |
|  +-------------------+  +-------------------+  +---------------------+  |
|  +-------------------+  +-------------------+  +---------------------+  |
|  | password.py       |  | messages.py       |  | dashboard.py        |  |
|  | HIBP k-anonymity  |  | Scam regex engine |  | Telemetry & reports |  |
|  +-------------------+  +-------------------+  +---------------------+  |
|  +-------------------+  +-------------------+                           |
|  | ai_chat.py        |  | main.py (Health)  |                           |
|  | Security copilot  |  | /api/health probe |                           |
|  +-------------------+  +-------------------+                           |
+-----------------------------------▲-------------------------------------+
                                    │
+-----------------------------------▼-------------------------------------+
|                      SERVICE & ENGINE SUBSYSTEMS                        |
|                                                                         |
|  +-------------------+  +-------------------+  +---------------------+  |
|  | url_scanner.py    |  | dns_analyzer.py   |  | file_analyzer.py    |  |
|  | Concurrent triage |  | RDAP, DMARC, PTR  |  | Magic byte spoofing |  |
|  +-------------------+  +-------------------+  +---------------------+  |
|  +-------------------+  +-------------------+  +---------------------+  |
|  | message_analyzer  |  | report_store.py   |  | threat_intel.py     |  |
|  | Phishing patterns |  | SQLite WAL engine |  | VT & GSB connectors |  |
|  +-------------------+  +-------------------+  +---------------------+  |
+-----------------------------------▲-------------------------------------+
                                    │
+-----------------------------------▼-------------------------------------+
|                           DATA PERSISTENCE                              |
|                                                                         |
|  SQLite 3 (PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 10000;)     |
|  • community_threat_reports (Atomic deduplication, indexes, isolation)  |
|  • Online Hot Backup API (conn.backup() into /backend/backups/)         |
+-------------------------------------------------------------------------+
```

---

## 2. Frontend Architecture (Next.js 14 App Router)

### 2.1 Visual Identity & Design System
- **Theme:** Obsidian Luxury, Arctic Glass, and Monolithic Brutalism.
- **Palette:**
  - Base Background: `#090B0E` (Deep Obsidian).
  - Secondary Panel Surface: `#101318` (Surface Glass).
  - Primary Typography: `#F1F2F3` (Crisp Monospaced & Sans).
  - Muted Borders: `#262B33` (Subtle Gridlines).
  - Tactical Accent: `#B6C7D9` (Arctic Ice).
  - Severe Risk Indicators: `#E5484D` (Critical Threat), `#F76808` (High Risk).
  - Secure Indicators: `#30A46C` (Safe / Verified).
- **Navigation:** Top horizontal header with sticky positioning. No permanent left sidebar, maximizing analytical viewport width for complex multi-column telemetry.
- **Micro-Interactions:** Monolithic corner framing markers (`border-t-2 border-l-2`), tactile badges with status dots, and progress bars.

### 2.2 Client-Side Privacy Guarantees
- **Password Breach Checker:**
  - Computes `SHA-1` in browser memory via the native `crypto.subtle.digest` Web API.
  - Slices the first 5 characters (hash prefix) and sends ONLY that prefix to the API.
  - Suffix matching occurs entirely within the client's local browser memory. The full password is never transmitted or retained.
- **Binary Hash Checker:**
  - Client sends only the hex digest. The raw file is never transmitted for hash lookups.
- **Session Isolation:**
  - Recent investigations are preserved in browser `sessionStorage`, cleared upon tab closure, and never sent to cloud analytics trackers.

### 2.3 Modular Directory Hierarchy
```
frontend/src/
├── app/
│   ├── layout.tsx                     # Root layout, ThemeProvider, Topbar
│   ├── page.tsx                       # Main Dashboard & Telemetry Posture
│   ├── error.tsx / global-error.tsx   # Granular error boundary recovery
│   ├── not-found.tsx                  # Monolithic 404 handler
│   ├── assistant/page.tsx             # AI Security Assistant workstation
│   ├── threat-intelligence/page.tsx   # Curated feed & community reports
│   └── security-tools/
│       ├── page.tsx                   # Tools launchpad & password checker
│       ├── url-scanner/page.tsx       # Multi-engine URL investigation
│       ├── ip-domain-analyzer/page.tsx# DNS, RDAP, and host intelligence
│       ├── file-analyzer/page.tsx     # Multipart binary inspector
│       ├── hash-lookup/page.tsx       # Cryptographic signature checker
│       └── message-analyzer/page.tsx  # Phishing SMS & email parser
├── components/
│   ├── layout/                        # PageContainer, PageHeader, Navigation
│   ├── dashboard/                     # Metrics cards, recent activity, threat feed
│   ├── investigation/                 # Individual security tool modules
│   └── ui/                            # Atomic primitives (Button, Badge, Card)
├── lib/
│   └── api/
│       ├── client.ts                  # Axios-like Fetch wrapper with FormData fix
│       └── services/                  # Service contracts (scanner, ai, dashboard)
└── types/                             # TypeScript interfaces mirroring OpenAPI
```

---

## 3. Backend Architecture (FastAPI Engine)

### 3.1 Application Bootstrap & Lifespan
- **Entry Point:** `backend/app/main.py`.
- **Lifespan Manager:**
  - Validates environment variables (`APP_ENV`, `APP_SECRET_KEY`, `ADMIN_API_KEY`).
  - Probes SQLite database health (`report_store.check_health()`).
  - Initializes the SlowAPI rate limiter with custom IP resolver.
  - Registers correlation middleware and security headers.
  - Mounts routes under `/api/v1` namespace.

### 3.2 Request Lifecycle & Correlation
Every incoming HTTP request passes through:
1. **Correlation Middleware:**
   - Extracts `X-Request-ID` or generates a 16-hex unguessable identifier.
   - Attaches `request.state.request_id` for use in exception handlers.
2. **Reverse Proxy & Client IP Extraction:**
   - Invokes `get_client_ip(request)` (`backend/app/utils/security.py`).
   - If the immediate peer IP is in `TRUSTED_PROXIES`, checks `CF-Connecting-IP`, then `X-Forwarded-For`.
   - If untrusted, ignores forwarded headers to prevent spoofing.
3. **SlowAPI Rate Limiter:**
   - Evaluates client IP against endpoint-specific rate limits.
   - Emits HTTP 429 Too Many Requests upon limit exhaustion.
4. **Latency Measurement:**
   - Measures execution duration with `time.perf_counter()`.
   - Appends `X-Response-Time: X.XXms` to the outgoing response.
5. **Security Headers Injection:**
   - Appends `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block`, `Referrer-Policy: strict-origin-when-cross-origin`.

---

## 4. Database Architecture (SQLite 3 WAL)

### 4.1 Schema Definition
The database stores crowdsourced threat reports in `community_threat_reports`:

```sql
CREATE TABLE IF NOT EXISTS community_threat_reports (
    id TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    threat_type TEXT NOT NULL,
    description TEXT,
    source TEXT DEFAULT 'web',
    reporter_ref TEXT,
    client_ip TEXT,
    status TEXT DEFAULT 'PENDING_REVIEW',
    risk_classification TEXT DEFAULT 'UNASSESSED',
    reported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_threat_reports_url ON community_threat_reports(url);
CREATE INDEX IF NOT EXISTS idx_threat_reports_status ON community_threat_reports(status);
CREATE INDEX IF NOT EXISTS idx_threat_reports_reported_at ON community_threat_reports(reported_at);
```

### 4.2 Concurrency & Reliability
- **Write-Ahead Logging (WAL):** Enabled via `PRAGMA journal_mode = WAL;`. Readers and writers execute concurrently without blocking each other.
- **Busy Timeout:** Configured via `PRAGMA busy_timeout = 10000;` (10 seconds), eliminating database lock exceptions under concurrent load.
- **Deduplication:** Submissions within a rolling 24-hour window matching an existing normalized target return `DUPLICATE_ACKNOWLEDGED` without duplicating rows.
- **Online Hot Backup:** Implemented via Python's native SQLite Online Backup API (`source_conn.backup(dest_conn)`), generating point-in-time snapshots while the database is actively handling traffic.

---

## 5. Security & Isolation Architecture

### 5.1 Server-Side Request Forgery (SSRF) Mitigations
URL scan targets are sanitized through `validate_url()` and `validate_domain()`:
- **Blocked IP Ranges:**
  - Loopback: `127.0.0.0/8`, `::1`
  - Private Networks: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
  - Link-Local & Carrier-Grade NAT: `169.254.0.0/16`, `100.64.0.0/10`
  - Cloud Provider Metadata Services: `169.254.169.254` (AWS/GCP), `100.100.100.200` (Alibaba), `192.0.0.192` (Oracle)
- **Protocol Restrictions:** Only `http://` and `https://` schemes permitted. `file://`, `ftp://`, `gopher://`, and `ldap://` are rejected with HTTP 400.

### 5.2 Multipart Binary File Safety
- **Streaming Enforcement:** `POST /api/v1/files/analyze` reads incoming bytes in 64 KB chunks. If cumulative bytes exceed 25 MB (`26,214,400 bytes`), the connection is terminated with HTTP 413 Payload Too Large.
- **Zero Permanent Storage:** Uploaded binaries are analyzed entirely in ephemeral memory buffers. No binary files are stored on server disks.

### 5.3 Administrative Authorization
- Administrative operations (`POST /api/v1/dashboard/backup`, `PATCH /api/v1/dashboard/reports/{report_id}`) require `ADMIN_API_KEY`.
- Evaluated via `hmac.compare_digest` to prevent timing side-channel attacks.
- Accepts both `X-Admin-Key: <key>` and `Authorization: Bearer <key>`.

---

## 6. External Intelligence Integration Matrix

| Subsystem | External Provider | Status | Fallback Behavior When Unconfigured / Unreachable |
| :--- | :--- | :--- | :--- |
| **URL Threat Intelligence** | VirusTotal v3, Google Safe Browsing v4, URLhaus | Implemented | When all providers are unconfigured/unreachable and coverage <= 50% without heuristics, emits `risk_score: null` and category `INSUFFICIENT_EVIDENCE`. Confirmed external detections trigger an inviolable threat floor (`MALICIOUS`, score >= 85) that cannot be diluted by clean checks. |
| **Domain & Hash Reputation** | VirusTotal v3 API | Implemented | Returns `threat_level: "UNASSESSED"`, `risk_score: null`. Never reports unassessed targets as safe. |
| **Credential Exposure**| Have I Been Pwned API | Implemented | Returns HTTP 503 `SERVICE_UNAVAILABLE`. Frontend explicitly warns user that safety cannot be established. Free k-anonymity does not require a key. |
| **RDAP / Whois** | IANA / Verisign / RDAP.org | Implemented | Queries domain registrar or IP RDAP (`rdap.org/ip/{host}`); records `error` gracefully if unavailable. |
| **AI Assistant** | Gemini API / OpenAI | Implemented (Optional) | Falls back to deterministic rule-based security knowledge base when API keys are absent. Autonomous tool calling / shell execution is NOT IMPLEMENTED. |
| **Host Reconnaissance (Shodan)** | Shodan API | **NOT IMPLEMENTED** | Not integrated into CYBERCORE backend. Previous documentation claims corrected. |
| **IP Reputation (AbuseIPDB)** | AbuseIPDB API | **NOT IMPLEMENTED** | Not integrated into CYBERCORE backend. Previous documentation claims corrected. |

> [!NOTE]
> **Email Security (DKIM):** The DNS inspection engine checks for `v=dkim1` substring presence within apex domain TXT records (`has_dkim_hint`). It does **not** perform full RFC 6376 cryptographic DKIM selector verification, as that requires message headers and specific selectors (`<selector>._domainkey.<domain>`).

---

## 7. Deployment & Container Architecture

CYBERCORE defines production-ready multi-stage containers:

### 7.1 Backend Container
- **Base:** `python:3.11-slim`.
- **User:** Unprivileged system user `cybercore:10001`.
- **Mounts:** `/app/data` for persistent SQLite database; `/app/backups` for snapshots.
- **Healthcheck:** Invokes `GET /api/health` every 30s.

### 7.2 Frontend Container
- **Base:** `node:20-alpine`.
- **User:** Unprivileged system user `nextjs:1001`.
- **Build:** Next.js standalone server mode.

### 7.3 Multi-Container Production Topology
```yaml
services:
  backend:
    build: ./backend
    restart: always
    volumes:
      - cybercore_db_data:/data
      - ./backend/backups:/app/backups
    ports:
      - "8000:8000"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/api/health"]
    networks:
      - cybercore-net

  frontend:
    build: ./frontend
    restart: always
    ports:
      - "3000:3000"
    depends_on:
      backend:
        condition: service_healthy
    networks:
      - cybercore-net
```
