/**
 * Centralized API configuration for CYBERCORE.
 * Communicates with the Python FastAPI backend over HTTPS.
 *
 * Environment Variable:
 * - NEXT_PUBLIC_API_BASE_URL: Absolute HTTPS URL to the FastAPI backend API root
 *   (e.g., https://api.cybercore.security/api/v1).
 *   MUST be configured in production hosting (e.g., Vercel Project Settings).
 *   In local development (NODE_ENV !== "production"), falls back to http://localhost:8000/api/v1.
 */

export interface ApiConfig {
  baseUrl: string;
  timeoutMs: number;
  headers: Record<string, string>;
}

const resolveBaseUrl = (): string => {
  const configuredUrl = process.env.NEXT_PUBLIC_API_BASE_URL;
  if (configuredUrl && configuredUrl.trim() !== "") {
    return configuredUrl.trim().replace(/\/+$/, "");
  }

  // Development-only fallback. In production, no localhost or hardcoded backend URL is assumed.
  if (process.env.NODE_ENV !== "production") {
    return "http://localhost:8000/api/v1";
  }

  return "";
};

export const apiConfig: ApiConfig = {
  baseUrl: resolveBaseUrl(),
  timeoutMs: 30000,
  headers: {
    "Content-Type": "application/json",
    Accept: "application/json",
  },
};
