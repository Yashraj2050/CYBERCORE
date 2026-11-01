import { apiClient } from "@/lib/api/client";
import { ApiError } from "@/lib/api/errors";
import type { UrlScanRequest, UrlScanResult, ScanApiError } from "@/types/scanner";

/**
 * Service for executing synchronous URL threat inspections against FastAPI.
 * Fully type-safe and maps HTTP error status codes into structured error classifications.
 */
export const scannerService = {
  /**
   * Dispatches a synchronous URL scan.
   * POST /api/v1/scan/
   */
  async scanUrl(request: UrlScanRequest): Promise<UrlScanResult> {
    try {
      const response = await apiClient.post<UrlScanResult>("/scan/", {
        url: request.url.trim(),
        source: request.source || "web",
      });
      return response.data;
    } catch (err) {
      throw this.classifyError(err);
    }
  },

  /**
   * Retrieves an existing cached scan by scan_id.
   * GET /api/v1/scan/{scan_id}
   */
  async getScanById(scanId: string): Promise<UrlScanResult> {
    try {
      const response = await apiClient.get<UrlScanResult>(`/scan/${encodeURIComponent(scanId)}`);
      return response.data;
    } catch (err) {
      throw this.classifyError(err);
    }
  },

  /**
   * Retrieves the most recent cached scan for a domain.
   * GET /api/v1/scan/domain/{domain}
   */
  async getScanByDomain(domain: string): Promise<UrlScanResult> {
    try {
      const response = await apiClient.get<UrlScanResult>(`/scan/domain/${encodeURIComponent(domain)}`);
      return response.data;
    } catch (err) {
      throw this.classifyError(err);
    }
  },

  /**
   * Normalizes network, HTTP, and SSRF errors into clean user-facing representations.
   */
  classifyError(err: unknown): ScanApiError {
    // If already classified, return directly
    if (
      typeof err === "object" &&
      err !== null &&
      "status" in err &&
      "message" in err &&
      ("isSsrf" in err || "isTimeout" in err || "detail" in err)
    ) {
      return err as ScanApiError;
    }

    if (err instanceof ApiError || (typeof err === "object" && err !== null && "status" in err && "payload" in err)) {
      const apiErr = err as ApiError;
      const rawDetail =
        typeof apiErr.payload === "object" && apiErr.payload !== null && "detail" in apiErr.payload
          ? (apiErr.payload as { detail: unknown }).detail
          : apiErr.message;

      let detailString = typeof rawDetail === "string" ? rawDetail : JSON.stringify(rawDetail);

      const isSsrf =
        apiErr.status === 400 &&
        (detailString.toLowerCase().includes("not allowed for security reasons") ||
          detailString.toLowerCase().includes("private ip ranges") ||
          detailString.toLowerCase().includes("loopback") ||
          detailString.toLowerCase().includes("reserved ip"));

      const isUnresolvable =
        apiErr.status === 400 && detailString.toLowerCase().includes("could not resolve hostname");

      let cleanMessage = apiErr.message;
      if (isSsrf) {
        cleanMessage = "Security Restriction: Target resolves to an internal, loopback, or reserved private IP address. SSRF defense engaged.";
      } else if (isUnresolvable) {
        cleanMessage = `DNS Resolution Failure: ${detailString}`;
      } else if (apiErr.status === 422) {
        cleanMessage = "URL Validation Error: The provided target structure was rejected by the inspection engine.";
      } else if (apiErr.status === 429) {
        cleanMessage = "Rate Limit Exceeded: 30 requests per minute quota reached. Please stand by.";
      } else if (apiErr.status >= 500) {
        cleanMessage = "Analysis Service Error: The inspection engine encountered an internal exception. Target could not be analyzed.";
      }

      return {
        status: apiErr.status,
        message: cleanMessage,
        isSsrf,
        detail: detailString,
      };
    }

    if (err instanceof Error) {
      const isTimeout = err.name === "AbortError" || err.message.toLowerCase().includes("timeout");
      return {
        status: isTimeout ? 408 : 0,
        message: isTimeout
          ? "Scan Request Timed Out: Inspection engine took longer than 30s to respond."
          : "Backend Bus Unavailable: Unable to reach FastAPI service at http://localhost:8000.",
        isTimeout,
        detail: err.message,
      };
    }

    return {
      status: 0,
      message: "An unknown execution error occurred during scan dispatch.",
    };
  },
};
