/**
 * Core HTTP & API Client Types
 * Generic foundation for CYBERCORE - does not invent domain-specific schemas.
 */

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

export interface RequestOptions extends Omit<RequestInit, "method" | "body"> {
  params?: Record<string, string | number | boolean | undefined | null>;
  body?: unknown;
  timeoutMs?: number;
  token?: string;
}

export interface ApiResponse<T> {
  data: T;
  status: number;
  headers: Headers;
  ok: boolean;
}

export interface ApiErrorPayload {
  detail?: string | { message?: string; [key: string]: unknown }[];
  message?: string;
  code?: string;
  [key: string]: unknown;
}

