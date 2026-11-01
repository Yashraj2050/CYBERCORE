/**
 * CYBERCORE — IP & Domain Intelligence Types
 * Strict TypeScript types mirroring backend Pydantic models from:
 * backend/app/routers/ip_domain.py
 */

// ── IP Response Types ────────────────────────────────────────

export interface IpDnsDetails {
  ptr: string;
}

export interface IpReputation {
  risk_score: number;
  verdict: string;
  notes: string[];
}

export interface IpAnalysisResponse {
  type: "ip";
  target: string;
  ip_version: number; // 4 | 6
  is_global: boolean;
  reverse_dns: string | null;
  dns: IpDnsDetails;
  reputation: IpReputation;
  scanned_at?: string;
}

// ── Domain Response Types ────────────────────────────────────

export type DmarcStatus = "VALID" | "MISSING" | "MALFORMED" | "UNAVAILABLE";

export interface DomainDnsDetails {
  a_records: string[];
  mx_records: string[];
  ns_records: string[];
  txt_records: string[];
  has_spf: boolean;
  has_dmarc: boolean | null;
  has_dkim_hint: boolean;
  dmarc_record: string | null;
  dmarc_status: DmarcStatus | null;
}

export interface DomainRegistrationDetails {
  registration_date?: string | null;
  domain_age_days?: number | null;
  expiration_date?: string | null;
  last_updated?: string | null;
  status?: string[] | null;
  nameservers?: string[] | null;
  registrar?: string | null;
  error?: string | null;
}

export interface DomainReputation {
  score: number;
  confidence: string; // "HIGH" | "MEDIUM" | "LOW"
  findings: string[];
}

export interface DomainAnalysisResponse {
  type: "domain";
  target: string;
  dns: DomainDnsDetails;
  registration: DomainRegistrationDetails;
  reputation: DomainReputation;
  scanned_at?: string;
}

// ── Discriminated Union ──────────────────────────────────────

export type IpDomainResult = IpAnalysisResponse | DomainAnalysisResponse;

// ── Request Schema ───────────────────────────────────────────

export interface IpDomainRequest {
  query: string;
}

// ── Error Classification ─────────────────────────────────────

export interface IpDomainApiError {
  status?: number;
  title: string;
  message: string;
  detail?: string;
  isSecurityRestriction?: boolean;
  isTooShort?: boolean;
  isTooLong?: boolean;
  isTimeout?: boolean;
}

