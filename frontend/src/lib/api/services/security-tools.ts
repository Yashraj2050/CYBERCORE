import { apiClient } from "@/lib/api/client";
import { apiConfig } from "@/config/api";
import { ApiError } from "@/lib/api/errors";
import type {
  ScanRequest,
  ScanResponse,
  IpDomainRequest,
  IpDomainResponse,
  HashCheckRequest,
  HashCheckResponse,
  FileAnalyzeResponse,
  PasswordBreachResult,
  HashApiError,
  FileApiError,
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
    try {
      const response = await apiClient.post<HashCheckResponse>("/files/check-hash", {
        hash_value: request.hash_value.trim().toLowerCase(),
        filename: request.filename?.trim() || null,
      });
      return response.data;
    } catch (err) {
      throw this.classifyHashError(err);
    }
  },

  /**
   * Uploads and inspects a binary or document file for malware, disguised extensions,
   * and VirusTotal reputation (up to 25MB).
   * POST /api/v1/files/analyze
   */
  async analyzeFile(file: File): Promise<FileAnalyzeResponse> {
    try {
      const formData = new FormData();
      formData.append("file", file);
      const response = await apiClient.post<FileAnalyzeResponse>("/files/analyze", formData);
      return response.data;
    } catch (err) {
      throw this.classifyFileError(err);
    }
  },

  /**
   * Normalizes hash check errors into structured, user-facing representations.
   */
  classifyHashError(err: unknown): HashApiError {
    if (typeof err === "object" && err !== null && "title" in err && "message" in err) {
      return err as HashApiError;
    }

    if (err instanceof ApiError || (typeof err === "object" && err !== null && "status" in err && "payload" in err)) {
      const apiErr = err as ApiError;
      const rawDetail =
        typeof apiErr.payload === "object" && apiErr.payload !== null && "detail" in apiErr.payload
          ? (apiErr.payload as { detail: unknown }).detail
          : apiErr.message;

      const detailString = typeof rawDetail === "string" ? rawDetail : JSON.stringify(rawDetail);
      const detailLower = detailString.toLowerCase();

      const isInvalidFormat =
        apiErr.status === 400 ||
        (apiErr.status === 422 && (detailLower.includes("hexadecimal") || detailLower.includes("hash")));

      let cleanTitle = "Hash Lookup Error";
      let cleanMessage = apiErr.message;

      if (isInvalidFormat) {
        cleanTitle = "Invalid Hash Format";
        cleanMessage = "Must be a valid hexadecimal string of 32 (MD5), 40 (SHA-1), or 64 (SHA-256) characters.";
      } else if (apiErr.status === 422) {
        cleanTitle = "Input Length Error";
        cleanMessage = "Hash string must be between 32 and 64 characters.";
      } else if (apiErr.status >= 500) {
        cleanTitle = "Engine Error";
        cleanMessage = "The signature inspection engine encountered an internal exception.";
      }

      return {
        status: apiErr.status,
        title: cleanTitle,
        message: cleanMessage,
        detail: detailString,
        isInvalidFormat,
      };
    }

    if (err instanceof Error) {
      const isTimeout = err.name === "AbortError" || err.message.toLowerCase().includes("timeout");
      return {
        status: isTimeout ? 408 : 0,
        title: isTimeout ? "Request Timed Out" : "Backend Bus Unavailable",
        message: isTimeout
          ? "Signature lookup took longer than 30s to respond."
          : "Unable to establish socket connection with the FastAPI backend service.",
        isTimeout,
        detail: err.message,
      };
    }

    return {
      status: 0,
      title: "Unknown Error",
      message: "An unknown execution error occurred during hash lookup.",
    };
  },

  /**
   * Normalizes binary file upload errors into structured, user-facing representations.
   */
  classifyFileError(err: unknown): FileApiError {
    if (typeof err === "object" && err !== null && "title" in err && "message" in err) {
      return err as FileApiError;
    }

    if (err instanceof ApiError || (typeof err === "object" && err !== null && "status" in err && "payload" in err)) {
      const apiErr = err as ApiError;
      const rawDetail =
        typeof apiErr.payload === "object" && apiErr.payload !== null && "detail" in apiErr.payload
          ? (apiErr.payload as { detail: unknown }).detail
          : apiErr.message;

      const detailString = typeof rawDetail === "string" ? rawDetail : JSON.stringify(rawDetail);
      const detailLower = detailString.toLowerCase();

      const isTooLarge = apiErr.status === 413 || detailLower.includes("25mb") || detailLower.includes("exceeds");
      const isEmpty = detailLower.includes("must have a filename") || detailLower.includes("empty");

      let cleanTitle = "File Analysis Error";
      let cleanMessage = apiErr.message;

      if (isTooLarge) {
        cleanTitle = "File Size Exceeded";
        cleanMessage = "Uploaded file exceeds the maximum permitted size of 25MB.";
      } else if (isEmpty) {
        cleanTitle = "Invalid File Payload";
        cleanMessage = "The selected file is invalid or missing a valid filename.";
      } else if (apiErr.status === 422) {
        cleanTitle = "Upload Format Error";
        cleanMessage = "Server could not process multipart form upload.";
      } else if (apiErr.status >= 500) {
        cleanTitle = "Engine Error";
        cleanMessage = "The binary inspection engine encountered an internal exception.";
      }

      return {
        status: apiErr.status,
        title: cleanTitle,
        message: cleanMessage,
        detail: detailString,
        isTooLarge,
        isEmpty,
      };
    }

    if (err instanceof Error) {
      const isTimeout = err.name === "AbortError" || err.message.toLowerCase().includes("timeout");
      return {
        status: isTimeout ? 408 : 0,
        title: isTimeout ? "Request Timed Out" : "Backend Bus Unavailable",
        message: isTimeout
          ? "Binary inspection took longer than 30s to respond."
          : "Unable to establish socket connection with the FastAPI backend service.",
        isTimeout,
        detail: err.message,
      };
    }

    return {
      status: 0,
      title: "Unknown Error",
      message: "An unknown execution error occurred during file analysis.",
    };
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
        status: "NOT FOUND IN BREACH CORPUS",
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

