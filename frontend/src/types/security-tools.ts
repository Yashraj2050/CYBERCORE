/**
 * Security Tools Types matching verified FastAPI backend contracts.
 */

// 1. URL Scanner
export interface ScanRequest {
  url: string;
  source?: string;
}

export interface ScanResponse {
  scan_id: string;
  url: string;
  domain: string;
  risk_score: number;
  risk_category: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  confidence: "LOW" | "MEDIUM" | "HIGH";
  coverage_percent: number;
  components: Record<string, unknown>;
  unavailable_checks: string[];
  dns_details: Record<string, unknown>;
  whois_details: Record<string, unknown>;
  scanned_at: string;
  scan_duration_ms: number;
  recommended_actions: string[];
  from_cache: boolean;
}

// 3. IP / Domain Intelligence
export interface IpDomainRequest {
  query: string;
}

export interface IpDomainResponse {
  type: "ip" | "domain";
  target: string;
  ip_version?: number;
  is_global?: boolean;
  reverse_dns?: string | null;
  dns?: {
    ptr?: string;
    a_records?: string[];
    mx_records?: string[];
    ns_records?: string[];
    txt_records?: string[];
    has_spf?: boolean;
    has_dmarc?: boolean;
    has_dkim_hint?: boolean;
  };
  registration?: Record<string, unknown>;
  reputation?: {
    risk_score?: number;
    score?: number;
    verdict?: string;
    confidence?: string;
    notes?: string[];
    findings?: string[];
  };
}

// 4. File Security
export interface VirusTotalReputation {
  malicious?: number;
  suspicious?: number;
  undetected?: number;
  harmless?: number;
  total_engines?: number;
  reputation?: number;
  status?: string;
  message?: string;
}

export interface HashCheckRequest {
  hash_value: string;
  filename?: string | null;
}

export interface HashCheckResponse {
  hash: string;
  filename?: string | null;
  risk_score: number | null;
  threat_level: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "SAFE" | "UNASSESSED" | string;
  findings: string[];
  vt_reputation?: VirusTotalReputation | Record<string, unknown> | null;
}

export interface FileAnalyzeResponse {
  filename: string;
  file_size: number;
  md5: string;
  sha1: string;
  sha256: string;
  detected_mime: string;
  declared_extension: string;
  is_spoofed_extension: boolean;
  risk_score: number;
  threat_level: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "SAFE" | string;
  findings: string[];
  vt_reputation?: VirusTotalReputation | Record<string, unknown> | null;
}

export interface HashApiError {
  status: number;
  title: string;
  message: string;
  detail?: string;
  isInvalidFormat?: boolean;
  isTimeout?: boolean;
}

export interface FileApiError {
  status: number;
  title: string;
  message: string;
  detail?: string;
  isTooLarge?: boolean;
  isEmpty?: boolean;
  isTimeout?: boolean;
}

// 5. Password Breach Verifier (k-Anonymity)
export type PasswordBreachStatus =
  | "NOT FOUND IN BREACH CORPUS" // Hash suffix not matched in checked breach corpus
  | "CLEAN"                      // Legacy alias
  | "BREACHED"                   // Hash suffix matched in breach records
  | "SERVICE_UNAVAILABLE"        // HTTP 503: External HIBP service unreachable
  | "INVALID_INPUT"              // HTTP 422: Input is not a valid 5-char hex SHA-1 prefix
  | "ERROR";                     // Unexpected failure

export interface PasswordBreachResult {
  status: PasswordBreachStatus;
  prefix: string;
  matchCount?: number;
  message: string;
  detail?: string;
}

