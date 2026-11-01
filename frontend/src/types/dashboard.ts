/**
 * Backend Data Models for CYBERCORE Dashboard & Telemetry
 * Matches OpenAPI contract from Python FastAPI backend.
 */

export interface DashboardStats {
  safety_index: number;
  total_scans_today: number;
  threats_intercepted: number;
  phishing_campaigns_detected: number;
  malware_signatures_verified: number;
  extension_active_users: number;
  system_status: "OPERATIONAL" | "DEGRADED" | "OFFLINE" | string;
  protection_status: "ACTIVE_DEFENSE" | "MONITORING" | string;
  threat_level: "LOW" | "ELEVATED" | "HIGH" | "CRITICAL" | string;
}

export type ScanType = "URL" | "MESSAGE" | "FILE" | "IP" | "DOMAIN" | string;
export type RiskLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "SAFE" | string;

export interface RecentScanItem {
  id: string;
  target: string;
  type: ScanType;
  risk_score: number;
  risk_level: RiskLevel;
  verdict: string;
  timestamp: string;
}

export interface RecentActivityResponse {
  recent_scans: RecentScanItem[];
}

export interface ThreatFeedCampaign {
  title: string;
  severity: "CRITICAL" | "HIGH" | "MODERATE" | "LOW" | string;
  indicators: string[];
  recommendation: string;
}

export interface ThreatFeedResponse {
  active_campaigns: ThreatFeedCampaign[];
}

export interface HealthCheckResponse {
  status: string;
  service: string;
  version: string;
  environment: string;
  api_keys: {
    virustotal?: boolean;
    google_safe_browsing?: boolean;
    ai?: boolean;
    [key: string]: boolean | undefined;
  };
}

