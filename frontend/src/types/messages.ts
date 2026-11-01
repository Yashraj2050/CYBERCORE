/**
/**
 * TypeScript Data Models for CYBERCORE Message Phishing & Social Engineering Analyzer
 * Strictly maps to Python FastAPI schema in app/routers/messages.py.
 */

export interface MessageIndicator {
  type: "pattern_match" | "urls_detected" | "impersonation" | string;
  description: string;
  severity: number;
  scam_type?: string | null;
  matched_snippet?: string | null;
}

export interface MessageAnalyzeResult {
  risk_score: number;
  risk_level: "CRITICAL" | "HIGH_RISK" | "SUSPICIOUS" | "LOW_RISK" | "SAFE" | string;
  scam_type: string | null;
  indicators: MessageIndicator[];
  urls_found: string[];
  manipulation_tactics: string[];
  impersonation_targets: string[];
  recommended_actions: string[];
  message_hash: string;
  summary: string;
}

export type MessageAnalyzeResponse = MessageAnalyzeResult;

export interface MessageAnalyzeRequest {
  message?: string;
  text?: string;
  source?: "web" | "extension" | string;
}

export interface MessageApiError {
  status: number;
  message: string;
  detail?: string;
  isBlank?: boolean;
  isTooLong?: boolean;
  isTimeout?: boolean;
}
