/**
 * TypeScript Data Models for CYBERCORE Website URL Scanner
 * Strictly matches the live Python FastAPI contract for POST /api/v1/scan/.
 */

export interface ScanComponentDetail {
  score: number | null;
  confidence: "LOW" | "MEDIUM" | "HIGH" | "UNAVAILABLE" | string;
  finding_type:
    | "UNABLE_TO_VERIFY"
    | "NO_KNOWN_DETECTION"
    | "HEURISTIC_ASSESSMENT"
    | "SUSPICIOUS_INDICATOR"
    | "HEURISTIC_HIGH_RISK"
    | "CONFIRMED_THREAT"
    | "CRITICAL_THREAT"
    | string;
  details?: Record<string, unknown>;
  evidence?: string[];
}

export interface DnsDetails {
  a_records?: string[];
  mx_records?: string[];
  ns_records?: string[];
  txt_records?: string[];
  has_spf?: boolean;
  has_dmarc?: boolean;
  has_dkim_hint?: boolean;
  error?: string;
}

export interface WhoisDetails {
  error?: string;
  domain_age_days?: number | null;
  registrar?: string | null;
  registration_date?: string | null;
  expiration_date?: string | null;
  status?: string[];
  [key: string]: unknown;
}

export interface ScanComponents {
  threat_intelligence?: ScanComponentDetail;
  phishing_malware?: ScanComponentDetail;
  domain_reputation?: ScanComponentDetail;
  url_patterns?: ScanComponentDetail;
  ssl_tls?: ScanComponentDetail;
  redirect_analysis?: ScanComponentDetail;
  [key: string]: ScanComponentDetail | undefined;
}

export interface UrlScanResult {
  scan_id: string;
  url: string;
  domain: string;
  risk_score: number | null;
  risk_category:
    | "CLEAN"
    | "LOW_RISK"
    | "LOW"
    | "SUSPICIOUS"
    | "HIGH_RISK"
    | "HIGH"
    | "MALICIOUS"
    | "UNVERIFIED"
    | "INSUFFICIENT_EVIDENCE"
    | "MODERATE"
    | "CRITICAL"
    | string;
  confidence: "LOW" | "MEDIUM" | "HIGH" | "UNAVAILABLE" | string;
  coverage_percent: number;
  is_phishing: boolean | null;
  is_malware: boolean | null;
  phishing_status?: "CONFIRMED_PHISHING" | "SUSPECTED_PHISHING" | "NO_KNOWN_DETECTION" | "UNVERIFIED" | string;
  malware_status?: "CONFIRMED_MALWARE" | "SUSPECTED_MALWARE" | "NO_KNOWN_DETECTION" | "UNVERIFIED" | string;
  ssl_valid: boolean | null;
  components: ScanComponents;
  unavailable_checks: string[];
  dns_details: DnsDetails;
  whois_details: WhoisDetails;
  source: string;
  scanned_at: string;
  scan_duration_ms: number;
  recommended_actions: string[];
  from_cache: boolean;
}

export type ScanMode = "scan" | "lookup_id" | "lookup_domain";

export interface UrlScanRequest {
  url: string;
  source?: string;
}

export interface ScanApiError {
  status: number;
  message: string;
  isSsrf?: boolean;
  isTimeout?: boolean;
  isNotFound?: boolean;
  detail?: string;
}

