import type { ApiErrorPayload } from "@/types/api";

/**
 * Standardized API Error for CYBERCORE network and HTTP failures.
 */
export class ApiError extends Error {
  readonly status: number;
  readonly statusText: string;
  readonly endpoint: string;
  readonly payload?: ApiErrorPayload;

  constructor(params: {
    message: string;
    status: number;
    statusText: string;
    endpoint: string;
    payload?: ApiErrorPayload;
  }) {
    super(params.message);
    this.name = "ApiError";
    this.status = params.status;
    this.statusText = params.statusText;
    this.endpoint = params.endpoint;
    this.payload = params.payload;

    // Restore prototype chain for instanceof checks
    Object.setPrototypeOf(this, ApiError.prototype);
  }

  /**
   * Extracts a human-readable message from FastAPI/standard error payloads.
   */
  static extractMessage(payload?: ApiErrorPayload, fallback = "An unexpected error occurred"): string {
    if (!payload) return fallback;

    if (typeof payload.detail === "string") {
      return payload.detail;
    }

    if (Array.isArray(payload.detail) && payload.detail.length > 0) {
      const first = payload.detail[0];
      if (typeof first === "object" && first !== null && "msg" in first) {
        return String((first as { msg: unknown }).msg);
      }
    }

    if (typeof payload.message === "string") {
      return payload.message;
    }

    return fallback;
  }
}

