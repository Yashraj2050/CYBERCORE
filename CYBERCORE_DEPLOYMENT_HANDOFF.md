# CYBERCORE Production Deployment Handoff Manual

**Canonical Repository:** `/Users/yashrajdnyaneshwarkuyate/CYBERCORE-1`
**GitHub Repository:** `https://github.com/Yashraj2050/CYBERCORE` (`main` branch)
**Target Production Architecture:**
* **Frontend:** Vercel (`Next.js 14 App Router`)
* **Backend:** Render (`Docker Web Service`, Python 3.12, Uvicorn, FastAPI)
* **Database:** Render Managed PostgreSQL 16
* **Edge & DNS:** Cloudflare (Edge Ingress, TLS Termination, Header Injection)

---

## 1. Environment Variables Configuration

### 1.1 Backend: Render Docker Web Service
Configure the following environment variables in the Render Dashboard under **Service $\rightarrow$ Environment**:

| Variable | Recommended / Required Value | Purpose & Sensitivity |
| :--- | :--- | :--- |
| `APP_ENV` | `production` | **Required.** Activates production security gates and refuses SQLite fallback. |
| `APP_HOST` | `0.0.0.0` | Container bind address. |
| `PORT` | `8000` | (Render sets `PORT` automatically; Uvicorn binds to `${PORT:-8000}`). |
| `APP_SECRET_KEY` | `<generate_32_byte_secret>` | Session signing and cryptographic operations. Generate via `openssl rand -hex 32`. |
| `ADMIN_API_KEY` | `<generate_secure_admin_key>` | **Required.** Authenticates administrative moderation and backup endpoints. |
| `DATABASE_URL` | `postgresql://<user>:<pass>@<render_host>/<db>` | **Required.** Internal Database URL of Render Managed PostgreSQL. |
| `INGRESS_SECRET` | `<generate_32_byte_hex_secret>` | **Required.** Authenticates forwarded client-IP headers from Cloudflare edge. |
| `TRUSTED_PROXIES` | `127.0.0.1,::1` | Fallback proxy IP whitelist for local development/testing. |
| `CORS_ORIGINS` | `https://your-frontend.vercel.app,https://yourdomain.com` | **Required.** Comma-separated list of permitted frontend origins. |
| `RATE_LIMIT_PER_MINUTE` | `30` | Default route rate limit per client IP. |
| `RATE_LIMIT_SCAN_PER_HOUR` | `100` | URL/File scan rate limit per client IP. |
| `MAX_FILE_SIZE_MB` | `32` | Maximum file upload size. |
| `AI_PROVIDER` | `gemini` | Primary AI analysis provider (`gemini` or `openai`). |
| `GEMINI_API_KEY` | `<your_gemini_api_key>` | API key for Gemini 1.5 Flash security analysis. |
| `VIRUSTOTAL_API_KEY` | `<your_virustotal_key>` | (Optional) External threat intelligence. |
| `GOOGLE_SAFE_BROWSING_API_KEY` | `<your_gsb_key>` | (Optional) URL reputation scanning. |
| `HIBP_API_KEY` | `<your_hibp_key>` | (Optional) HaveIBeenPwned credential breach checks. |
| `PHISHTANK_API_KEY` | `<your_phishtank_key>` | (Optional) PhishTank phishing database. |

### 1.2 Frontend: Vercel Web Application
Configure in Vercel Dashboard under **Project Settings $\rightarrow$ Environment Variables**:

| Variable | Required Value | Notes |
| :--- | :--- | :--- |
| `NEXT_PUBLIC_API_BASE_URL` | `https://api.yourdomain.com` (or Render public URL) | Base URL for backend API requests. |

> [!CAUTION]
> **NEVER** expose `INGRESS_SECRET` or `ADMIN_API_KEY` in Vercel or any `NEXT_PUBLIC_*` variable. Ingress authentication is strictly an edge-to-backend credential. The browser client must never possess or transmit it.

---

## 2. Cloudflare Edge Configuration (Transform Rules)

To authenticate forwarded client IP headers arriving at Render without trusting dynamic internal private IPs, configure a Request Header Modification rule in Cloudflare:

1. Log in to **Cloudflare Dashboard** $\rightarrow$ Select your domain.
2. Navigate to **Rules $\rightarrow$ Transform Rules $\rightarrow$ Modify Request Header**.
3. Click **Create rule**:
   * **Rule name:** `Inject CYBERCORE Ingress Secret`
   * **When incoming requests match:**
     * Field: `Hostname`
     * Operator: `equals`
     * Value: `api.yourdomain.com` (or the backend route)
   * **Then (Modify request header):**
     * Type: `Set static`
     * Header name: `X-CYBERCORE-Ingress-Secret`
     * Value: `<the_exact_value_of_INGRESS_SECRET_from_render>`
4. Click **Deploy**.

### How Header Trust Works:
* Cloudflare sets `CF-Connecting-IP` to the connecting client's verified IP and injects `X-CYBERCORE-Ingress-Secret`.
* When CYBERCORE receives the connection from Render's load balancer, `is_trusted_proxy_request()` verifies the secret via constant-time comparison (`secrets.compare_digest`).
* Upon successful authentication, `get_client_ip()` trusts `CF-Connecting-IP`, validates the IP format, and SlowAPI enforces rate limits against that real user IP.
* If a direct connection arrives without the secret (or with a forged/wrong secret), forward headers are completely ignored, and the rate limiter keys on the direct socket host.

---

## 3. Backend Start Command & Container Architecture

As defined in [`backend/Dockerfile`](file:///Users/yashrajdnyaneshwarkuyate/CYBERCORE-1/backend/Dockerfile#L46):

```dockerfile
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1"]
```

### Architectural Key Points:
* **Uvicorn Proxy-Header Processing is Disabled:** The `--proxy-headers` flag is omitted. Uvicorn does not mutate `scope["client"]` or attempt to parse unauthenticated forward headers.
* **Sole Authority:** The application's [`get_client_ip()`](file:///Users/yashrajdnyaneshwarkuyate/CYBERCORE-1/backend/app/utils/security.py#L89) function holds exclusive authority over client IP resolution and header trust.
* **Port Expansion:** Supports Render's dynamic `$PORT` environment variable with fallback to 8000.
* **Worker Count:** Single worker process (`--workers 1`), optimal for containerized workloads with async I/O.
* **Least Privilege:** Runs as non-root user `appuser` (UID 10001).

---

## 4. Database Configuration & Lifecycle

* **Database Engine:** Render Managed PostgreSQL 16.
* **Connection Lifecycle:**
  - Connection pooling implemented via `psycopg_pool.ConnectionPool` (2 min, 10 max connections).
  - Open on FastAPI startup (`lifespan`), gracefully closed on shutdown.
  - Connection timeout: 5.0 seconds. Statement timeout: 15.0 seconds.
* **Automatic Table Provisioning:**
  - Table `community_threat_reports` and indexes on `reported_at`, `category`, `status`, and `target_url` auto-initialize on startup if they do not exist.
* **Production Safety Gate:**
  - In `app_env=production`, missing or unconnectable `DATABASE_URL` raises a `RuntimeError` immediately on startup, refusing fallback to ephemeral SQLite storage.
* **Legacy Data Migration (Optional):**
  - If existing reports from local SQLite need migration:
    ```bash
    python backend/scripts/migrate_sqlite_to_postgres.py \
      --source backend/cybercore.db \
      --database-url "$DATABASE_URL"
    ```

---

## 5. Production Deployment Sequence

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Operator
    participant CF as Cloudflare
    participant PG as Render PostgreSQL
    participant Rnd as Render Web Service
    participant Vrc as Vercel Frontend

    Dev->>PG: 1. Provision Managed PostgreSQL 16 (obtain Internal DB URL)
    Dev->>Dev: 2. Generate INGRESS_SECRET (32-byte hex) & ADMIN_API_KEY
    Dev->>CF: 3. Configure Transform Rule: Set X-CYBERCORE-Ingress-Secret
    Dev->>Rnd: 4. Deploy Backend Web Service (set INGRESS_SECRET, DATABASE_URL, etc.)
    Rnd->>PG: Auto-connect pool & initialize schema
    Dev->>Rnd: 5. Smoke test: GET https://api.yourdomain.com/api/health
    Rnd-->>Dev: HTTP 200 {"status":"operational","database":"connected","engine":"postgresql"}
    Dev->>Vrc: 6. Deploy Frontend (set NEXT_PUBLIC_API_BASE_URL)
    Dev->>Vrc: 7. End-to-end verification via browser
```

1. **Phase 1: Database Provisioning**
   - In Render Dashboard, create a **New PostgreSQL** database.
   - Note the **Internal Database URL** (e.g. `postgresql://user:pass@dpg-xxxx-a:5432/cybercore`).
2. **Phase 2: Secrets Generation**
   - Generate high-entropy secrets locally:
     ```bash
     python3 -c "import secrets; print('INGRESS_SECRET=' + secrets.token_hex(32)); print('ADMIN_API_KEY=' + secrets.token_hex(32)); print('APP_SECRET_KEY=' + secrets.token_hex(32))"
     ```
3. **Phase 3: Cloudflare Transform Rule**
   - Create the Modify Request Header rule in Cloudflare as documented in Section 2.
4. **Phase 4: Render Web Service Deployment**
   - Create a **New Web Service** pointing to the GitHub repository (`main` branch).
   - Select **Docker** environment.
   - Enter all environment variables from Section 1.1.
   - Deploy.
5. **Phase 5: Verification & Smoke Testing**
   - Verify health: `curl -s https://api.yourdomain.com/api/health | jq .`
   - Verify response: `"status": "operational"`, `"database": "connected"`, `"engine": "postgresql"`.
6. **Phase 6: Vercel Frontend Deployment**
   - In Vercel, connect repository and configure root directory to `frontend`.
   - Set `NEXT_PUBLIC_API_BASE_URL=https://api.yourdomain.com`.
   - Trigger production deployment.
7. **Phase 7: End-to-End Operational Smoke Test**
   - Submit a threat URL from the Vercel UI.
   - Confirm it appears in the Community Reports list.
   - Verify rate limiting triggers gracefully if requested repeatedly.

---

## 6. Critical Security Distinction & Remaining Limitations

> [!IMPORTANT]
> **Client-IP Metadata Authentication vs. Origin Access Protection:**
>
> The `INGRESS_SECRET` mechanism authenticates **forwarded client-IP metadata** (`CF-Connecting-IP`, `X-Forwarded-For`). It guarantees that:
> 1. External clients connecting directly to the Render service cannot spoof their client IP to evade SlowAPI rate limits or poison logs.
> 2. Rogue or compromised workloads on Render's internal private mesh cannot forge client IPs.
>
> **However, this secret does NOT automatically block direct HTTP access to the Render origin.**
> Direct requests sent to `https://<service-name>.onrender.com` without Cloudflare will still be received by the container. They will be processed normally by public endpoints (e.g. `/api/health`, `/api/v1/scan`), but their client IP is attributed strictly to their **real direct socket IP** (preventing rate limit bypass).
>
> If complete origin cloaking (blocking direct HTTP access entirely) is required in the future, the operator may:
> * Implement **Cloudflare Authenticated Origin Pulls** using client certificate verification (mTLS).
> * Add an application admission middleware that rejects requests without the ingress secret header with `HTTP 403 Forbidden`.
> * Deploy the backend as a **Render Private Service** accessible solely through a dedicated ingress gateway.

---

## 7. Verification Summary

Prior to handoff, all regression and build suites were executed with 100% pass rates:
* **Backend Proxy Security Suite:** 31 / 31 passed (`backend/tests/test_proxy_security.py`).
* **Backend Adversarial Security Suite:** 14 / 14 passed (`backend/tests/test_adversarial_security.py`).
* **Backend Production Readiness Suite:** 10 / 10 passed (`backend/tests/test_production_readiness.py`).
* **Backend PostgreSQL Integration Suite:** 10 / 10 passed against local PostgreSQL 14 (`backend/tests/test_postgres_integration.py`).
* **Full Backend Discovery Suite:** 109 / 109 passed (`python -m unittest discover -s tests -p "test_*.py"`).
* **Frontend API Client Suite:** 3 / 3 passed (`node tests/api-client.test.mjs`).
* **Frontend Static Analysis:** `tsc --noEmit` and `next lint` passed with 0 errors and 0 warnings.
* **Frontend Production Build:** `next build` compiled all 16 static routes successfully.
* **Git Cleanliness:** `git diff --check` passed with 0 whitespace errors. Browser extension (`extension/`) has 0 changes.
