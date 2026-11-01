# CYBERCORE — SECURITY MODEL & RESPONSIBLE DISCLOSURE POLICY

**Security Policy Version:** 1.0.0-rc1
**Effective Date:** 2026-11-01
**Target Platform:** CYBERCORE Threat Intelligence Platform
**Repository:** `https://github.com/Yashraj2050/CYBERCORE`

---

## 1. Security Architecture Principles

CYBERCORE is engineered with defense-in-depth, zero-trust principles, and cryptographic privacy guarantees:

1. **Truthfulness in Security Verdicts & 7-Tier Classification Taxonomy:**
   Missing or unavailable intelligence is explicitly marked `INSUFFICIENT_EVIDENCE` or `UNASSESSED` with `risk_score: null`. CYBERCORE **never** returns `SAFE`, `CLEAN`, or `0` when external detection engines are offline or unconfigured. Risk assessments adhere to a calibrated 7-tier taxonomy: `CLEAN`, `LOW`, `SUSPICIOUS`, `HIGH`, `MALICIOUS`, `UNVERIFIED`, and `INSUFFICIENT_EVIDENCE`.
2. **Authoritative Threat Floor Precedence:**
   Confirmed detections from authoritative threat intelligence sources or compounding heuristic dropper vectors establish an inviolable threat floor (minimum score 85 for external threats, >= 75–80 for heuristic droppers). Authoritative threats are never diluted down into LOW or MODERATE risk by clean peripheral checks (such as valid SSL or empty redirect chains).
2. **Zero Knowledge by Design:**
   Raw passwords never leave the user's browser memory. Raw binary files are processed transiently in RAM and never stored on disk.
3. **Least Privilege Execution:**
   All containers run as unprivileged, dedicated non-root users (`cybercore:10001` and `nextjs:1001`). No privileged Docker flags or host socket mounts are permitted.
4. **Resilience to Abuse:**
   SlowAPI rate limiting is enforced on all endpoints with trusted proxy validation to prevent header spoofing.

---

## 2. Authentication & Authorization Boundaries

### 2.1 Public Endpoints
The following endpoints are accessible without authentication, protected by IP-based rate limiting:
- `POST /api/v1/scan/` (30 req/min)
- `GET /api/v1/scan/{scan_id}` (30 req/min)
- `POST /api/v1/ip-domain/analyze` (30 req/min)
- `GET /api/v1/password/range/{hash_prefix}` (60 req/min)
- `POST /api/v1/files/hash-lookup` (30 req/min)
- `POST /api/v1/files/analyze` (10 req/min)
- `POST /api/v1/messages/analyze` (30 req/min)
- `POST /api/v1/ai/chat` (15 req/min)
- `GET /api/v1/dashboard/stats` (Default limit)
- `GET /api/v1/dashboard/threat-feed` (Default limit)
- `POST /api/v1/dashboard/report` (5 req/min)
- `GET /api/v1/dashboard/reports` (Default limit)
- `GET /api/health` (Public health probe)

### 2.2 Administrative Endpoints
The following endpoints require `ADMIN_API_KEY` authentication:
- `POST /api/v1/dashboard/backup`: Triggers online hot SQLite backup snapshot.
- `PATCH /api/v1/dashboard/reports/{report_id}`: Moderates status and risk classification of community reports.

**Authentication Mechanism:**
- Evaluated via `hmac.compare_digest` (constant-time string comparison) against `settings.admin_api_key`.
- Accepted via either:
  - Header: `X-Admin-Key: <ADMIN_API_KEY>`
  - Header: `Authorization: Bearer <ADMIN_API_KEY>`
- Missing, empty, or invalid keys yield HTTP 401 Unauthorized or HTTP 403 Forbidden.
- Production startup raises an error if `APP_SECRET_KEY` is set to the default placeholder.

---

## 3. Threat Mitigations & Attack Surface Hardening

### 3.1 Server-Side Request Forgery (SSRF) Mitigations
URL scan targets are sanitized through `validate_url()` and `validate_domain()` before any network dispatch:
- **Blocked IP Ranges:**
  - Loopback: `127.0.0.0/8`, `::1`
  - Private Networks: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
  - Link-Local & Carrier-Grade NAT: `169.254.0.0/16`, `100.64.0.0/10`
  - Cloud Metadata Services:
    - `169.254.169.254` (AWS, Google Cloud, Azure)
    - `100.100.100.200` (Alibaba Cloud)
    - `192.0.0.192` (Oracle Cloud)
- **Protocol Enforcements:** Only `http://` and `https://` permitted. All alternative schemes (`file://`, `ftp://`, `gopher://`, `ldap://`) are rejected with HTTP 400 Bad Request.

### 3.2 Denial of Service (DoS) & Memory Exhaustion Mitigations
- **File Upload Streaming Limits:** Uploaded files are streamed in 64 KB buffers. If the stream exceeds 25 MB (`26,214,400 bytes`), the stream is terminated immediately with HTTP 413 Payload Too Large. Full files are never buffered into RAM simultaneously.
- **Message Content Limits:** Message text is bounded at 10,000 characters to prevent regex backtracking attacks.
- **Rate Limiting:** SlowAPI enforces per-minute thresholds per IP on every state-changing route.

### 3.3 Reverse-Proxy Client IP Spoofing Mitigations
The helper `get_client_ip()` in `app/utils/security.py` resolves the effective client IP:
- Evaluates `request.client.host` against `settings.trusted_proxies_list`.
- If the immediate connection does NOT originate from a trusted proxy (e.g. `127.0.0.1` or internal Docker network), all forward headers (`X-Forwarded-For`, `CF-Connecting-IP`, `X-Real-IP`) are strictly discarded.
- Untrusted clients cannot spoof arbitrary IPs to bypass rate limits.

### 3.4 Sensitive Data & Privacy Protection
- **Password Anonymity:** Only 5 hexadecimal characters of SHA-1 are sent across the wire. Raw passwords are never transmitted, logged, or cached.
- **Community Threat Reporter Anonymity:** While `reporter_ref` and reporter IP are stored in the database for abuse monitoring, `GET /api/v1/dashboard/reports` selects only public fields (`id, url, threat_type, description, source, reported_at, status, risk_classification`).
- **Telemetry Redaction:** The structured logging middleware records only request ID, client IP, method, route path, status code, and latency. Request bodies and authorization headers are never logged.

### 3.5 URL Threat Precedence & Dropper Detection Heuristics
- **Compounding Heuristic Droppers:** When a URL exhibits raw IP hosting (`IPv4`/`IPv6`), non-standard high port (`>1024`), executable/script payload paths (`.sh`, `.exe`, `.bin`, `.elf`, `.bat`, `.ps1`), and unencrypted HTTP transport, the heuristic engine triggers an automatic compounding dropper threat (score >= 80, `FindingType.CONFIRMED_THREAT`).
- **Honest Absence of Evidence Handling:** If external threat intelligence is unconfigured or unreachable and total subsystem coverage is <= 50% with zero heuristic flags, the engine emits `risk_score: null` and category `INSUFFICIENT_EVIDENCE`. CYBERCORE strictly forbids interpreting unreached security feeds as confirmation of innocence.

---

## 4. Known Security & Infrastructure Limitations

1. **Docker Runtime Verification:**
   - Docker container runtime verification is marked **NOT TESTED** in Phase 6/6.1 due to host workstation APFS disk saturation (124 MiB available). Static container security definitions are verified.
2. **Reverse Proxy Requirement:**
   - In production environments, CYBERCORE must be placed behind a TLS-terminating reverse proxy (Nginx, Traefik, Caddy, or Cloudflare) with `TRUSTED_PROXIES` configured to match the proxy's IP.
3. **Database Concurrency Limits:**
   - SQLite WAL mode is optimal for single-node deployments up to 1,000 req/sec. Multi-node distributed clustering requires PostgreSQL.
4. **External Threat Feeds Scope:**
   - VirusTotal and Google Safe Browsing require operational API keys to return reputation data; without keys, they safely return `UNASSESSED`.
   - Shodan and AbuseIPDB are **not implemented** in this release.
5. **DKIM Verification Scope:**
   - The IP/Domain analyzer performs an apex domain TXT string match for `v=dkim1` (`has_dkim_hint`). Full RFC 6376 cryptographic email signature verification requires email headers and selectors and is not performed at the domain level.

---

## 5. Vulnerability Disclosure Policy

If you discover a security vulnerability in CYBERCORE:
1. **Do not create public GitHub issues** detailing security defects.
2. Send an email with reproduction steps, affected endpoints, and impact assessment to:
   **security@cybercore.local** or contact the repository maintainers privately.
3. The maintenance team aims to acknowledge receipt within 48 hours and provide a remediation timeline within 7 days.
