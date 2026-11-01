/**
 * Centralized API configuration for CYBERCORE.
 * Communicates with the Python FastAPI backend.
 */

export interface ApiConfig {
  baseUrl: string;
  timeoutMs: number;
  headers: Record<string, string>;
}

export const apiConfig: ApiConfig = {
  baseUrl:
    process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000/api/v1",
  timeoutMs: 30000,
  headers: {
    "Content-Type": "application/json",
    Accept: "application/json",
  },
};

