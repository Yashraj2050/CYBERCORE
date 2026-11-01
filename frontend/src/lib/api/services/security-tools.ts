import { apiClient } from "@/lib/api/client";
import { apiConfig } from "@/config/api";
import type {
  ScanRequest,
  ScanResponse,
  IpDomainRequest,
  IpDomainResponse,
  HashCheckRequest,
  HashCheckResponse,
  PasswordBreachResult,
} from "@/types/security-tools";
import type { MessageAnalyzeRequest, MessageAnalyzeResponse } from "@/types/messages";

export const securityToolsService = {
  /**
   * Scans a URL with SSRF protection and multi-stage analysis.
   * POST /api/v1/scan/
   */
  async scanUrl(request: ScanRequest): Promise<ScanResponse> {
    const response = await apiClient.post<ScanResponse>("/scan/", request);
    return response.data;
  },

  /**
   * Analyzes text for phishing and social engineering indicators.
   * POST /api/v1/messages/analyze
   */
  async analyzeMessage(request: MessageAnalyzeRequest): Promise<MessageAnalyzeResponse> {
    const response = await apiClient.post<MessageAnalyzeResponse>("/messages/analyze", request);
    return response.data;
  },

  /**
   * Queries IP or domain intelligence (PTR, DNS, RDAP).
   * POST /api/v1/ip-domain/analyze
   */
  async analyzeIpDomain(request: IpDomainRequest): Promise<IpDomainResponse> {
    const response = await apiClient.post<IpDomainResponse>("/ip-domain/analyze", request);
    return response.data;
  },

  /**
   * Performs privacy-preserving hash check against known signatures.
   * POST /api/v1/files/check-hash
   */
  async checkHash(request: HashCheckRequest): Promise<HashCheckResponse> {
    const response = await apiClient.post<HashCheckResponse>("/files/check-hash", request);
    return response.data;
  },

  /**
   * Verifies password breach status using k-anonymity (5-hex SHA-1 prefix).
   * GET /api/v1/password/breached/{hash_prefix}
   *
   * Crucial Resilience Contract:
   * - 200 OK: Parses suffixes.
   * - 503 Service Unavailable: HIBP upstream down/unreachable. NEVER interpreted as clean.
   * - 422 Unprocessable Entity: Invalid prefix (must be 5 hex chars).
   * - Raw passwords never leave the client.
   */
  async checkPasswordBreach(hashPrefix: string): Promise<PasswordBreachResult> {
    const cleanPrefix = hashPrefix.trim().toUpperCase();

    // Client-side format validation (5 hex chars)
    if (!/^[0-9A-F]{5}$/.test(cleanPrefix)) {
      return {
        status: "INVALID_INPUT",
        prefix: cleanPrefix,
        message: "Prefix must be exactly 5 hexadecimal characters (k-anonymity SHA-1 prefix).",
      };
    }

    const baseUrl = apiConfig.baseUrl.replace(/\/$/, "");
    const url = `${baseUrl}/password/breached/${cleanPrefix}`;

    try {
      const response = await fetch(url, {
        method: "GET",
        headers: { Accept: "application/json" },
      });

      if (response.status === 503) {
        return {
          status: "SERVICE_UNAVAILABLE",
          prefix: cleanPrefix,
          message: "Breach database service is temporarily unavailable. Cannot verify breach status.",
          detail: "The upstream Have I Been Pwned API is unreachable. This does NOT indicate your password is safe.",
        };
      }

      if (response.status === 422) {
        return {
          status: "INVALID_INPUT",
          prefix: cleanPrefix,
          message: "The server rejected the prefix as invalid.",
        };
      }

      if (!response.ok) {
        return {
          status: "ERROR",
          prefix: cleanPrefix,
          message: `Breach verification failed with HTTP ${response.status}.`,
        };
      }

      const data = await response.json();
      return {
        status: "CLEAN",
        prefix: cleanPrefix,
        message: "Prefix successfully queried.",
        detail: JSON.stringify(data),
      };
    } catch (err) {
      return {
        status: "ERROR",
        prefix: cleanPrefix,
        message: err instanceof Error ? err.message : "Network failure while reaching breach gateway.",
      };
    }
  },
};

