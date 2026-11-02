import { apiConfig } from "@/config/api";
import type { ApiResponse, HttpMethod, RequestOptions, ApiErrorPayload } from "@/types/api";
import { ApiError } from "./errors";

export class ApiClient {
  private readonly baseUrl: string;
  private readonly defaultHeaders: Record<string, string>;
  private readonly defaultTimeout: number;

  constructor(options?: {
    baseUrl?: string;
    headers?: Record<string, string>;
    timeoutMs?: number;
  }) {
    this.baseUrl = (options?.baseUrl || apiConfig.baseUrl).replace(/\/$/, "");
    this.defaultHeaders = {
      ...apiConfig.headers,
      ...options?.headers,
    };
    this.defaultTimeout = options?.timeoutMs || apiConfig.timeoutMs;
  }

  /**
   * Builds the fully qualified URL including query parameters.
   */
  private buildUrl(
    endpoint: string,
    params?: Record<string, string | number | boolean | undefined | null>
  ): string {
    if (!this.baseUrl) {
      throw new ApiError({
        message:
          "CYBERCORE API is unconfigured: Backend base URL is not set. Please configure NEXT_PUBLIC_API_BASE_URL.",
        status: 0,
        statusText: "Configuration Error",
        endpoint,
      });
    }

    const cleanEndpoint = endpoint.startsWith("/") ? endpoint : `/${endpoint}`;
    const url = new URL(`${this.baseUrl}${cleanEndpoint}`);

    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined && value !== null) {
          url.searchParams.append(key, String(value));
        }
      });
    }

    return url.toString();
  }

  /**
   * Core request dispatcher with timeout and standardized error handling.
   */
  async request<T>(
    endpoint: string,
    method: HttpMethod,
    options: RequestOptions = {}
  ): Promise<ApiResponse<T>> {
    const { params, body, headers, timeoutMs = this.defaultTimeout, token, ...customInit } = options;
    const url = this.buildUrl(endpoint, params);

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    const requestHeaders: Record<string, string> = {
      ...this.defaultHeaders,
      ...(headers as Record<string, string>),
    };

    if (token) {
      requestHeaders["Authorization"] = `Bearer ${token}`;
    }

    let serializedBody: BodyInit | undefined = undefined;
    if (body !== undefined) {
      if (typeof FormData !== "undefined" && body instanceof FormData) {
        serializedBody = body;
        // Let the runtime/browser compute the multipart boundary header automatically.
        // Strip all case variants of Content-Type (e.g. content-type, Content-Type, Content-type).
        Object.keys(requestHeaders).forEach((key) => {
          if (key.toLowerCase() === "content-type") {
            delete requestHeaders[key];
          }
        });
      } else if (typeof body === "string") {
        serializedBody = body;
      } else {
        serializedBody = JSON.stringify(body);
      }
    }

    try {
      const response = await fetch(url, {
        method,
        headers: requestHeaders,
        body: serializedBody,
        signal: controller.signal,
        ...customInit,
      });

      const contentType = response.headers.get("content-type") || "";
      const isJson = contentType.includes("application/json");

      let responseData: unknown = null;
      if (isJson) {
        try {
          responseData = await response.json();
        } catch {
          responseData = null;
        }
      } else {
        responseData = await response.text();
      }

      if (!response.ok) {
        const payload = (typeof responseData === "object" && responseData !== null
          ? responseData
          : { message: String(responseData || response.statusText) }) as ApiErrorPayload;

        throw new ApiError({
          message: ApiError.extractMessage(payload, `HTTP ${response.status}: ${response.statusText}`),
          status: response.status,
          statusText: response.statusText,
          endpoint,
          payload,
        });
      }

      return {
        data: responseData as T,
        status: response.status,
        headers: response.headers,
        ok: response.ok,
      };
    } catch (error) {
      if (error instanceof ApiError) {
        throw error;
      }

      if (error instanceof DOMException && error.name === "AbortError") {
        throw new ApiError({
          message: `Request timed out after ${timeoutMs}ms`,
          status: 408,
          statusText: "Request Timeout",
          endpoint,
        });
      }

      throw new ApiError({
        message: error instanceof Error ? error.message : "Network failure",
        status: 0,
        statusText: "Client Error",
        endpoint,
      });
    } finally {
      clearTimeout(timeoutId);
    }
  }

  // Convenient HTTP Verb Wrappers
  get<T>(endpoint: string, options?: RequestOptions): Promise<ApiResponse<T>> {
    return this.request<T>(endpoint, "GET", options);
  }

  post<T>(endpoint: string, body?: unknown, options?: RequestOptions): Promise<ApiResponse<T>> {
    return this.request<T>(endpoint, "POST", { ...options, body });
  }

  put<T>(endpoint: string, body?: unknown, options?: RequestOptions): Promise<ApiResponse<T>> {
    return this.request<T>(endpoint, "PUT", { ...options, body });
  }

  patch<T>(endpoint: string, body?: unknown, options?: RequestOptions): Promise<ApiResponse<T>> {
    return this.request<T>(endpoint, "PATCH", { ...options, body });
  }

  delete<T>(endpoint: string, options?: RequestOptions): Promise<ApiResponse<T>> {
    return this.request<T>(endpoint, "DELETE", options);
  }
}

/**
 * Singleton API client instance for application-wide reuse.
 */
export const apiClient = new ApiClient();

