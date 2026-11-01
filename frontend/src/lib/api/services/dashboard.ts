import { apiClient } from "@/lib/api/client";
import type {
  DashboardStats,
  RecentActivityResponse,
  ThreatFeedResponse,
  HealthCheckResponse,
} from "@/types/dashboard";

/**
 * Service for fetching real-time telemetry from FastAPI backend.
 */
export const dashboardService = {
  /**
   * Retrieves aggregate security statistics and system protection status.
   * GET /api/v1/dashboard/stats
   */
  async getStats(): Promise<DashboardStats> {
    const response = await apiClient.get<DashboardStats>("/dashboard/stats");
    return response.data;
  },

  /**
   * Retrieves recent scan activity and detection verdicts.
   * GET /api/v1/dashboard/recent
   */
  async getRecentActivity(): Promise<RecentActivityResponse> {
    const response = await apiClient.get<RecentActivityResponse>("/dashboard/recent");
    return response.data;
  },

  /**
   * Retrieves curated threat intelligence highlights.
   * GET /api/v1/dashboard/threat-feed
   */
  async getThreatFeed(): Promise<ThreatFeedResponse> {
    const response = await apiClient.get<ThreatFeedResponse>("/dashboard/threat-feed");
    return response.data;
  },

  /**
   * Checks backend service health.
   * GET /api/health
   */
  async getHealth(): Promise<HealthCheckResponse> {
    // Health endpoint is mounted at /api/health directly
    const baseUrl = (process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000/api/v1")
      .replace(/\/v1\/?$/, "");
    const res = await fetch(`${baseUrl}/health`, {
      headers: { Accept: "application/json" },
      cache: "no-store",
    });
    if (!res.ok) {
      throw new Error(`Health check failed: HTTP ${res.status}`);
    }
    return res.json();
  },
};

