import { apiClient } from "@/lib/api/client";
import { ApiError } from "@/lib/api/errors";
import type { IpDomainRequest, IpDomainResult, IpDomainApiError } from "@/types/ip-domain";

/**
 * Service for communicating with FastAPI IP & Domain Intelligence endpoint:
 * POST /api/v1/ip-domain/analyze
 */
export const ipDomainService = {
  /**
   * Dispatches an IP address or domain name for technical intelligence inspection.
   */
  async analyze(request: IpDomainRequest): Promise<IpDomainResult> {
    try {
      const cleanQuery = request.query.trim();
      const response = await apiClient.post<IpDomainResult>("/ip-domain/analyze", {
        query: cleanQuery,
      });

      // Augment with client-side completion timestamp
      const data = response.data;
      data.scanned_at = new Date().toISOString();
      return data;
    } catch (err) {
      throw this.classifyError(err);
    }
  },

  /**
   * Normalizes network, validation, and HTTP errors into structured user-facing representations.
   */
  classifyError(err: unknown): IpDomainApiError {
    if (
      typeof err === "object" &&
      err !== null &&
      "title" in err &&
      "message" in err
    ) {
      return err as IpDomainApiError;
    }

    if (err instanceof ApiError || (typeof err === "object" && err !== null && "status" in err && "payload" in err)) {
      const apiErr = err as ApiError;
      const rawDetail =
        typeof apiErr.payload === "object" && apiErr.payload !== null && "detail" in apiErr.payload
          ? (apiErr.payload as { detail: unknown }).detail
          : apiErr.message;

      const detailString = typeof rawDetail === "string" ? rawDetail : JSON.stringify(rawDetail);
      const detailLower = detailString.toLowerCase();

      const isSecurityRestriction =
        apiErr.status === 400 &&
        (detailLower.includes("security restriction") ||
          detailLower.includes("private") ||
          detailLower.includes("loopback") ||
          detailLower.includes("reserved"));

      const isTooShort =
        apiErr.status === 422 &&
        (detailLower.includes("at least 2 characters") || detailLower.includes("string_too_short"));

      const isTooLong =
        apiErr.status === 422 &&
        (detailLower.includes("at most 253 characters") || detailLower.includes("string_too_long"));

      let cleanTitle = "Investigation Error";
      let cleanMessage = apiErr.message;

      if (isSecurityRestriction) {
        cleanTitle = "SSRF Security Restriction";
        cleanMessage = detailString;
      } else if (isTooShort) {
        cleanTitle = "Input Format Invalid";
        cleanMessage = "Query must be at least 2 characters in length (e.g., '1.1.1.1' or 'io.net').";
      } else if (isTooLong) {
        cleanTitle = "Input Length Exceeded";
        cleanMessage = "Domain or hostname exceeds maximum permitted length of 253 characters.";
      } else if (apiErr.status === 400) {
        cleanTitle = "Input Validation Failed";
        cleanMessage = detailString;
      } else if (apiErr.status >= 500) {
        cleanTitle = "Engine Error";
        cleanMessage = "The DNS and RDAP intelligence backend encountered an unexpected internal exception.";
      }

      return {
        status: apiErr.status,
        title: cleanTitle,
        message: cleanMessage,
        detail: detailString,
        isSecurityRestriction,
        isTooShort,
        isTooLong,
      };
    }

    if (err instanceof Error) {
      const isTimeout = err.name === "AbortError" || err.message.toLowerCase().includes("timeout");
      return {
        status: isTimeout ? 408 : 0,
        title: isTimeout ? "Request Timed Out" : "Backend Bus Unavailable",
        message: isTimeout
          ? "Network analysis timed out while awaiting external DNS or RDAP resolvers."
          : "Unable to establish socket connection with FastAPI backend at http://localhost:8000.",
        isTimeout,
        detail: err.message,
      };
    }

    return {
      status: 0,
      title: "Unknown Execution Error",
      message: "An unclassified exception occurred while executing target analysis.",
    };
  },
};

