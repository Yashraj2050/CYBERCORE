"use client";

import * as React from "react";
import Link from "next/link";
import {
  ShieldAlert,
  Search,
  Filter,
  FileText,
  Globe,
  MessageSquare,
  Clock,
  ArrowRight,
  RefreshCw,
} from "lucide-react";
import { PageContainer } from "@/components/layout/page-container";
import { PageHeader } from "@/components/layout/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { SearchField } from "@/components/ui/search-field";
import { dashboardService } from "@/lib/api/services/dashboard";
import type { RecentScanItem } from "@/types/dashboard";

const typeIcons: Record<string, React.ComponentType<{ className?: string }>> = {
  URL: Globe,
  MESSAGE: MessageSquare,
  FILE: FileText,
};

export default function InvestigationsPage() {
  const [scans, setScans] = React.useState<RecentScanItem[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);
  const [filterType, setFilterType] = React.useState<string>("ALL");
  const [searchQuery, setSearchQuery] = React.useState<string>("");

  const loadInvestigations = React.useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await dashboardService.getRecentActivity();
      setScans(data.recent_scans || []);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to load investigations"
      );
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    loadInvestigations();
  }, [loadInvestigations]);

  const filteredScans = React.useMemo(() => {
    return scans.filter((s) => {
      const matchesType = filterType === "ALL" || s.type === filterType;
      const q = searchQuery.toLowerCase().trim();
      const matchesQuery =
        !q ||
        s.target.toLowerCase().includes(q) ||
        s.verdict.toLowerCase().includes(q) ||
        s.risk_level.toLowerCase().includes(q);
      return matchesType && matchesQuery;
    });
  }, [scans, filterType, searchQuery]);

  return (
    <PageContainer>
      <PageHeader
        editorialTag="INCIDENT TRIAGE SAMPLES // REFERENCE ARCHIVE"
        title="Investigations"
        description="Sample audit trail, reference indicators of compromise (IOC), and triage verdicts across analyzed URLs, suspicious messages, and binary artifacts."
        badge={
          <Badge variant="monolithic" radius="xs">
            {scans.length} SAMPLE RECORDS
          </Badge>
        }
        actions={
          <Button
            variant="monolithic"
            size="sm"
            onClick={loadInvestigations}
            disabled={loading}
            className="gap-1.5"
          >
            <RefreshCw
              className={`h-3 w-3 ${loading ? "animate-spin text-cyber-accent" : "text-cyber-text-dim"}`}
            />
            <span>REFRESH</span>
          </Button>
        }
      />

      {/* Filter & Search Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 p-3 bg-cyber-bg-secondary border border-cyber-border rounded-xs">
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 sm:pb-0">
          {["ALL", "URL", "MESSAGE", "FILE"].map((t) => (
            <button
              key={t}
              type="button"
              onClick={() => setFilterType(t)}
              className={`px-2.5 py-1 text-[11px] font-mono tracking-tactical uppercase rounded-xs transition-colors ${
                filterType === t
                  ? "bg-cyber-bg-surface text-cyber-text-primary border border-cyber-border-strong font-semibold"
                  : "text-cyber-text-dim hover:text-cyber-text-secondary"
              }`}
            >
              {t}
            </button>
          ))}
        </div>

        <div className="w-full sm:max-w-xs">
          <SearchField
            placeholder="Filter target, verdict, severity..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            onClear={() => setSearchQuery("")}
            className="h-8 text-xs"
          />
        </div>
      </div>

      {/* Investigations Table / Feed */}
      <div className="glass-panel p-5 rounded-xs space-y-4 border border-cyber-border relative group">
        {/* Corner Monolithic Framing */}
        <span className="pointer-events-none absolute top-0 left-0 w-2 h-2 border-t-2 border-l-2 border-cyber-accent" />
        <span className="pointer-events-none absolute top-0 right-0 w-2 h-2 border-t-2 border-r-2 border-cyber-accent" />
        <span className="pointer-events-none absolute bottom-0 left-0 w-2 h-2 border-b-2 border-l-2 border-cyber-accent" />
        <span className="pointer-events-none absolute bottom-0 right-0 w-2 h-2 border-b-2 border-r-2 border-cyber-accent" />
        {loading ? (
          <div className="space-y-3 py-6">
            {[1, 2, 3, 4, 5].map((i) => (
              <div
                key={i}
                className="h-12 bg-cyber-bg-surface/50 rounded-xs animate-pulse"
              />
            ))}
          </div>
        ) : error ? (
          <div className="py-12 text-center text-xs font-mono text-cyber-threat-critical/80 space-y-2">
            <p>TELEMETRY OFFLINE: {error}</p>
            <Button size="xs" variant="outline" onClick={loadInvestigations}>
              Retry Connection
            </Button>
          </div>
        ) : filteredScans.length === 0 ? (
          <div className="py-12 text-center text-xs font-mono text-cyber-text-dim space-y-2">
            <p>No investigations match the selected filter criteria.</p>
            <button
              type="button"
              onClick={() => {
                setFilterType("ALL");
                setSearchQuery("");
              }}
              className="text-cyber-accent hover:underline text-[11px]"
            >
              Reset all filters
            </button>
          </div>
        ) : (
          <div className="divide-y divide-cyber-border/40">
            {filteredScans.map((scan) => {
              const Icon = typeIcons[scan.type] || Globe;
              const isCritical =
                scan.risk_level === "CRITICAL" || scan.risk_score >= 70;
              const isSafe = scan.risk_level === "SAFE" || scan.risk_score < 20;

              return (
                <div
                  key={scan.id}
                  className="py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs font-mono hover:bg-cyber-bg-surface/30 px-2 transition-colors"
                >
                  <div className="flex items-center gap-3 min-w-0 flex-1">
                    <div className="flex h-8 w-8 items-center justify-center border border-cyber-border bg-cyber-bg rounded-xs shrink-0">
                      <Icon className="h-4 w-4 text-cyber-text-dim" />
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] text-cyber-text-dim uppercase">
                          {scan.type}
                        </span>
                        <span className="text-cyber-text-primary font-medium truncate">
                          {scan.target}
                        </span>
                      </div>
                      <p className="text-[11px] text-cyber-text-secondary truncate mt-0.5">
                        {scan.verdict}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 shrink-0 self-end sm:self-auto">
                    <Badge
                      variant={isCritical ? "critical" : isSafe ? "secure" : "medium"}
                      radius="xs"
                      dot
                    >
                      {scan.risk_level} ({scan.risk_score})
                    </Badge>

                    <span className="text-[10px] text-cyber-text-dim">
                      {new Date(scan.timestamp).toLocaleString([], {
                        month: "short",
                        day: "2-digit",
                        hour: "2-digit",
                        minute: "2-digit",
                      })}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </PageContainer>
  );
}

