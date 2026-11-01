"use client";

import * as React from "react";
import Link from "next/link";
import {
  Shield,
  Activity,
  RefreshCw,
  SlidersHorizontal,
  Flame,
  ArrowUpRight,
  Terminal,
} from "lucide-react";
import { PageContainer } from "@/components/layout/page-container";
import { PageHeader } from "@/components/layout/page-header";
import { DashboardSummary } from "@/components/dashboard/dashboard-summary";
import { RecentInvestigations } from "@/components/dashboard/recent-investigations";
import { ThreatFeedCard } from "@/components/dashboard/threat-feed-card";
import { SecurityToolsShortcuts } from "@/components/dashboard/security-tools-shortcuts";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { dashboardService } from "@/lib/api/services/dashboard";
import type {
  DashboardStats,
  RecentScanItem,
  ThreatFeedCampaign,
} from "@/types/dashboard";

export default function OverviewDashboardPage() {
  const [stats, setStats] = React.useState<DashboardStats | null>(null);
  const [scans, setScans] = React.useState<RecentScanItem[]>([]);
  const [campaigns, setCampaigns] = React.useState<ThreatFeedCampaign[]>([]);

  const [loading, setLoading] = React.useState<boolean>(true);
  const [statsError, setStatsError] = React.useState<string | null>(null);
  const [recentError, setRecentError] = React.useState<string | null>(null);
  const [feedError, setFeedError] = React.useState<string | null>(null);

  const fetchDashboardData = React.useCallback(async () => {
    setLoading(true);
    setStatsError(null);
    setRecentError(null);
    setFeedError(null);

    // Concurrently fetch telemetry from verified FastAPI endpoints
    const [statsResult, recentResult, feedResult] = await Promise.allSettled([
      dashboardService.getStats(),
      dashboardService.getRecentActivity(),
      dashboardService.getThreatFeed(),
    ]);

    if (statsResult.status === "fulfilled") {
      setStats(statsResult.value);
    } else {
      setStatsError(
        statsResult.reason instanceof Error
          ? statsResult.reason.message
          : "FastAPI telemetry bus unavailable"
      );
    }

    if (recentResult.status === "fulfilled") {
      setScans(recentResult.value.recent_scans || []);
    } else {
      setRecentError(
        recentResult.reason instanceof Error
          ? recentResult.reason.message
          : "Recent scans feed offline"
      );
    }

    if (feedResult.status === "fulfilled") {
      setCampaigns(feedResult.value.active_campaigns || []);
    } else {
      setFeedError(
        feedResult.reason instanceof Error
          ? feedResult.reason.message
          : "Threat campaign feed offline"
      );
    }

    setLoading(false);
  }, []);

  React.useEffect(() => {
    fetchDashboardData();
  }, [fetchDashboardData]);

  const isConnected = Boolean(stats && !statsError);

  return (
    <PageContainer>
      {/* 1. Editorial Page Header */}
      <PageHeader
        editorialTag="GLOBAL TELEMETRY BUS // NODE-01"
        title="Security Posture & Threat Overview"
        description="Real-time protection posture and aggregate telemetry. Metric correlation across browser extension clients, recent investigation samples, and curated threat reference indicators."
        badge={
          <Badge
            variant={isConnected ? "secure" : "default"}
            radius="xs"
            dot
          >
            {isConnected ? `STATUS: ${stats?.system_status}` : "BUS: STANDBY"}
          </Badge>
        }
        actions={
          <div className="flex items-center gap-2">
            <Button
              variant="monolithic"
              size="sm"
              onClick={fetchDashboardData}
              disabled={loading}
              className="gap-1.5"
            >
              <RefreshCw
                className={`h-3 w-3 ${loading ? "animate-spin text-cyber-accent" : "text-cyber-text-dim"}`}
              />
              <span className="hidden sm:inline">REFRESH TELEMETRY</span>
            </Button>

            <Button variant="default" size="sm" asChild>
              <Link href="/security-tools/url-scanner">LAUNCH SCANNER</Link>
            </Button>
          </div>
        }
      />

      {/* 2. Primary Telemetry Metric Cards */}
      <DashboardSummary
        stats={stats}
        loading={loading}
        error={statsError}
        onRefresh={fetchDashboardData}
      />

      {/* 3. Asymmetric Bento Matrix: Recent Investigations + Threat Feed */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
        {/* Recent Investigations (8 cols on lg) */}
        <div className="lg:col-span-7 xl:col-span-8">
          <RecentInvestigations
            scans={scans}
            loading={loading}
            error={recentError}
          />
        </div>

        {/* Live Threat Feed (5 cols on lg) */}
        <div className="lg:col-span-5 xl:col-span-4">
          <ThreatFeedCard
            campaigns={campaigns}
            loading={loading}
            error={feedError}
          />
        </div>
      </div>

      {/* 4. Verified Security Tools Fast-Launchers */}
      <SecurityToolsShortcuts />
    </PageContainer>
  );
}
